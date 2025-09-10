use alloy_primitives::{Address, B256, U256, keccak256};
use bytemuck::cast_slice;
use std::{
    fs,
    path::Path,
    str::FromStr,
    sync::{Arc, mpsc},
    thread,
    time::Instant,
};
use wgpu::util::DeviceExt;

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct GpuOutput {
    found: u32,
    _pad0: [u32; 3],
    salt_le: [u32; 4],
    addr_words: [u32; 5],
    _pad: [u32; 2],
    _pad_end: u32,
}

mod config;

fn load_creation_code_hex<P: AsRef<Path>>(p: P) -> Vec<u8> {
    let raw = fs::read_to_string(p).expect("failed to read creation code file");
    // Keep only hex characters; ignore 0x, quotes, commas, whitespace, etc.
    let filtered: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if filtered.is_empty() {
        panic!("creation code file contained no hex");
    }
    hex::decode(&filtered).expect("invalid hex in creation code file")
}

#[inline]
fn create2_address_from_hash(deployer: Address, salt: B256, init_code_hash: &[u8; 32]) -> Address {
    // preimage = 0xff || deployer(20) || salt(32) || keccak(init_code)(32)  => 85 bytes
    let mut preimage = [0u8; 85];
    preimage[0] = 0xff;
    preimage[1..21].copy_from_slice(deployer.as_slice());
    preimage[21..53].copy_from_slice(salt.as_slice());
    preimage[53..85].copy_from_slice(init_code_hash);

    let hash = keccak256(&preimage);
    Address::from_slice(&hash[12..32])
}

fn normalize_req(s: &str) -> String {
    let mut p = s.trim().to_lowercase();
    if let Some(rest) = p.strip_prefix("0x") {
        p = rest.to_string();
    }
    p
}

fn validate_req(mode: config::MatchMode, req: &str) {
    let ok_chars = req.chars().all(|c| c.is_ascii_hexdigit() || c == '.');
    if !ok_chars {
        panic!("REQUEST_PATTERN must contain only [0-9a-fA-F] and '.' (for Mask)");
    }
    match mode {
        config::MatchMode::Exact => {
            if req.len() != 40 {
                panic!("Exact mode requires a 40-hex-nibble address (no dots)");
            }
            if req.contains('.') {
                panic!("Exact mode does not allow '.' wildcards");
            }
        }
        config::MatchMode::Mask => {
            if req.len() != 40 {
                panic!("Mask mode requires a 40-char mask ('.' wildcards allowed)");
            }
        }
        // Prefix/Suffix/Contains: any length 1..=40, no dots.
        _ => {
            if req.is_empty() || req.len() > 40 {
                panic!("Pattern length must be between 1 and 40 nibbles");
            }
            if req.contains('.') {
                panic!("Prefix/Suffix/Contains do not use '.'; use Mask mode instead");
            }
        }
    }
}

#[inline]
fn address_matches(addr: Address, req: &str, mode: config::MatchMode) -> bool {
    let addr_hex = hex::encode(addr); // 40 lowercase hex
    match mode {
        config::MatchMode::Prefix => addr_hex.starts_with(req),
        config::MatchMode::Suffix => addr_hex.ends_with(req),
        config::MatchMode::Contains => addr_hex.contains(req),
        config::MatchMode::Exact => addr_hex == req,
        config::MatchMode::Mask => {
            // req is 40 chars of [0-9a-f or '.']
            addr_hex
                .bytes()
                .zip(req.bytes())
                .all(|(a, p)| p == b'.' || p == a)
        }
    }
}

fn parse_start_salt_u128(s: &str) -> u128 {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).expect("START_SALT hex parse failed (u128 max)")
    } else {
        t.parse::<u128>().expect("START_SALT decimal parse failed")
    }
}

fn hex_char_to_nibble(c: char) -> Option<u32> {
    match c {
        '0'..='9' => Some((c as u32) - ('0' as u32)),
        'a'..='f' => Some(10 + (c as u32 - 'a' as u32)),
        'A'..='F' => Some(10 + (c as u32 - 'A' as u32)),
        _ => None,
    }
}

fn req_to_prefix_nibbles(req: &str) -> (Vec<u32>, u32) {
    // Convert a hex string (no 0x) into nibble array (max 40).
    let mut nibbles = vec![0u32; 40];
    let mut count = 0u32;
    for (i, ch) in req.chars().enumerate() {
        if i >= 40 {
            break;
        }
        if let Some(v) = hex_char_to_nibble(ch) {
            nibbles[i] = v;
            count += 1;
        } else {
            break;
        }
    }
    (nibbles, count)
}

fn pack_le_words(bytes: &[u8]) -> Vec<u32> {
    assert!(bytes.len() % 4 == 0);
    let mut out = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks(4) {
        let w = (chunk[0] as u32)
            | ((chunk[1] as u32) << 8)
            | ((chunk[2] as u32) << 16)
            | ((chunk[3] as u32) << 24);
        out.push(w);
    }
    out
}

fn build_inputs_u32(
    base_salt: u128,
    pattern_nibbles: &[u32],
    pattern_mask: &[u32],
    pattern_len: u32,
    match_mode: u32,
    salts_per_invocation: u32,
    stride: u32,
    work_items: u32,
    deployer: Address,
    init_code_hash: &[u8; 32],
) -> Vec<u32> {
    // Layout must match WGSL `Inputs` struct (std430):
    // - base_salt: vec4<u32>
    // - pattern_len: u32
    // - match_mode: u32
    // - salts_per_invocation: u32
    // - stride: u32
    // - work_items: u32
    // - deployer_words: array<u32, 5>
    // - init_hash_words: array<u32, 8>
    // - pattern_nibbles: array<u32, 40>
    // - pattern_mask: array<u32, 40>
    let mut v: Vec<u32> = Vec::with_capacity(4 + 5 + 5 + 8 + 40 + 40);

    // base_salt (128-bit little-endian limbs)
    let s0 = (base_salt & 0xffff_ffff) as u32;
    let s1 = ((base_salt >> 32) & 0xffff_ffff) as u32;
    let s2 = ((base_salt >> 64) & 0xffff_ffff) as u32;
    let s3 = ((base_salt >> 96) & 0xffff_ffff) as u32;
    v.extend_from_slice(&[s0, s1, s2, s3]);

    // pattern_len, match_mode, salts_per_invocation, stride, work_items
    v.push(pattern_len);
    v.push(match_mode);
    v.push(salts_per_invocation);
    v.push(stride);
    v.push(work_items);

    // deployer (20 bytes) -> 5 little-endian u32 words
    let dep_bytes = deployer.as_slice();
    let dep_words = pack_le_words(dep_bytes);
    debug_assert_eq!(dep_words.len(), 5);
    v.extend_from_slice(&dep_words);

    // init_code_hash (32 bytes) -> 8 little-endian u32 words
    let hash_words = pack_le_words(init_code_hash);
    debug_assert_eq!(hash_words.len(), 8);
    v.extend_from_slice(&hash_words);

    // pattern_nibbles (40)
    let mut pattern = [0u32; 40];
    for (i, &n) in pattern_nibbles.iter().take(40).enumerate() {
        pattern[i] = n & 0x0f;
    }
    v.extend_from_slice(&pattern);

    // pattern_mask (40)
    let mut mask = [0u32; 40];
    for (i, &m) in pattern_mask.iter().take(40).enumerate() {
        mask[i] = m;
    }
    v.extend_from_slice(&mask);

    // Pad to 16-byte multiple (std430 struct size); u32 count must be multiple of 4.
    let rem = v.len() % 4;
    if rem != 0 {
        v.extend(std::iter::repeat(0u32).take(4 - rem));
    }

    v
}

fn gpu_try_prefix(
    req_no0x: &str,
    mode: config::MatchMode,
    deployer: Address,
    init_code_hash: &[u8; 32],
    base_salt: u128,
    work_items: u32,
) -> Option<(U256, Address)> {
    if work_items == 0 {
        return None;
    }

    // Build input payload
    // Convert request to pattern arrays based on mode
    let mut pattern_nibbles = vec![0u32; 40];
    let mut pattern_mask = vec![0u32; 40];
    let mut pattern_len: u32 = 0;
    match mode {
        config::MatchMode::Mask => {
            for (i, ch) in req_no0x.chars().take(40).enumerate() {
                if ch == '.' {
                    pattern_mask[i] = 1;
                } else if let Some(v) = hex_char_to_nibble(ch) {
                    pattern_nibbles[i] = v & 0x0f;
                }
            }
            pattern_len = 40;
        }
        config::MatchMode::Exact => {
            for (i, ch) in req_no0x.chars().take(40).enumerate() {
                if let Some(v) = hex_char_to_nibble(ch) {
                    pattern_nibbles[i] = v & 0x0f;
                }
            }
            pattern_len = 40;
        }
        _ => {
            for (i, ch) in req_no0x.chars().take(40).enumerate() {
                if let Some(v) = hex_char_to_nibble(ch) {
                    pattern_nibbles[i] = v & 0x0f;
                    pattern_len += 1;
                } else {
                    break;
                }
            }
        }
    }
    let match_mode_u32 = match mode {
        config::MatchMode::Prefix => 0,
        config::MatchMode::Suffix => 1,
        config::MatchMode::Contains => 2,
        config::MatchMode::Mask => 3,
        config::MatchMode::Exact => 4,
    } as u32;
    let salts_per_invocation: u32 = 1;
    let stride: u32 = work_items;
    let inputs_u32 = build_inputs_u32(
        base_salt,
        &pattern_nibbles,
        &pattern_mask,
        pattern_len,
        match_mode_u32,
        salts_per_invocation,
        stride,
        work_items,
        deployer,
        init_code_hash,
    );

    // WGPU setup (minimal)
    let instance = wgpu::Instance::default();
    let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        compatible_surface: None,
        force_fallback_adapter: false,
    }))
    .ok()?;

    let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
        label: Some("compute-device"),
        required_features: wgpu::Features::empty(),
        required_limits: wgpu::Limits::downlevel_defaults(),
        memory_hints: wgpu::MemoryHints::Performance,
        trace: wgpu::Trace::Off,
    }))
    .ok()?;

    // Buffers
    let in_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("inputs"),
        contents: cast_slice(&inputs_u32),
        usage: wgpu::BufferUsages::STORAGE,
    });

    let out_zero = GpuOutput {
        found: 0,
        _pad0: [0; 3],
        salt_le: [0; 4],
        addr_words: [0; 5],
        _pad: [0; 2],
        _pad_end: 0,
    };
    let out_storage_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("outputs-storage"),
        contents: bytemuck::bytes_of(&out_zero),
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
    });
    let read_buf = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("outputs-readback"),
        size: std::mem::size_of::<GpuOutput>() as u64,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });

    // Pipeline
    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("create2_search.wgsl"),
        source: wgpu::ShaderSource::Wgsl(include_str!("shaders/create2_search.wgsl").into()),
    });

    let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("compute-bgl"),
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("compute-pl"),
        bind_group_layouts: &[&bgl],
        push_constant_ranges: &[],
    });

    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("create2-search"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: Some("main"),
        compilation_options: wgpu::PipelineCompilationOptions::default(),
        cache: None,
    });

    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("compute-bg"),
        layout: &bgl,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: in_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: out_storage_buf.as_entire_binding(),
            },
        ],
    });

    // Dispatch
    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("compute-encoder"),
    });

    {
        let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("compute-pass"),
            timestamp_writes: None,
        });
        cpass.set_pipeline(&pipeline);
        cpass.set_bind_group(0, &bind_group, &[]);
        let wg_size = 256u32;
        let groups = (work_items + wg_size - 1) / wg_size;
        cpass.dispatch_workgroups(groups, 1, 1);
    }

    encoder.copy_buffer_to_buffer(
        &out_storage_buf,
        0,
        &read_buf,
        0,
        std::mem::size_of::<GpuOutput>() as u64,
    );
    queue.submit(Some(encoder.finish()));
    device.poll(wgpu::PollType::Wait).unwrap();

    // Read back
    let slice = read_buf.slice(..);
    let (tx_map, rx_map) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |res| {
        let _ = tx_map.send(res);
    });
    device.poll(wgpu::PollType::Wait).unwrap();
    if rx_map.recv().ok().and_then(|r| r.ok()).is_none() {
        return None;
    }
    let data = slice.get_mapped_range();
    let out: &GpuOutput = bytemuck::from_bytes(&data);

    let result = if out.found > 0 {
        let s0 = out.salt_le[0] as u128;
        let s1 = out.salt_le[1] as u128;
        let s2 = out.salt_le[2] as u128;
        let s3 = out.salt_le[3] as u128;
        let salt128 = s0 | (s1 << 32) | (s2 << 64) | (s3 << 96);
        let salt_u256 = U256::from(salt128);

        let mut addr_bytes = [0u8; 20];
        for i in 0..5 {
            let w = out.addr_words[i];
            let o = i * 4;
            addr_bytes[o + 0] = (w & 0xFF) as u8;
            addr_bytes[o + 1] = ((w >> 8) & 0xFF) as u8;
            addr_bytes[o + 2] = ((w >> 16) & 0xFF) as u8;
            addr_bytes[o + 3] = ((w >> 24) & 0xFF) as u8;
        }
        let addr = Address::from_slice(&addr_bytes);
        Some((salt_u256, addr))
    } else {
        None
    };

    drop(data);
    read_buf.unmap();

    result
}

fn main() {
    // --- Load config ---
    let deployer =
        Address::from_str(config::DEPLOYER).expect("invalid DEPLOYER in config.rs (address parse)");
    let init_code = load_creation_code_hex(config::CREATION_CODE_PATH);
    let init_code_hash = keccak256(&init_code); // PRECOMPUTE ONCE
    let init_code_hash = Arc::new(init_code_hash); // share to threads cheaply

    let raw_req = config::REQUEST_PATTERN;
    let mode = config::MATCH_MODE;

    // Normalize/validate pattern once
    let req = normalize_req(raw_req);
    validate_req(mode, &req);

    // --- Threading setup ---
    let default_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let num_threads = config::THREAD_OVERRIDE.unwrap_or(default_threads);
    let stride: u128 = num_threads as u128;
    let start_at: u128 = parse_start_salt_u128(config::START_SALT);

    let (tx, rx) = mpsc::channel::<(U256, Address)>();

    println!(
        "CREATE2 vanity search\
        \n- deployer: {}\
        \n- init_code: {} bytes\
        \n- init_code keccak256: 0x{}\
        \n- mode: {:?}\
        \n- request: {}\
        \n- threads: {}\
        \n- start_salt(dec): {}\
        \n- start_salt(hex32): 0x{:064x}",
        deployer,
        init_code.len(),
        hex::encode(init_code_hash.as_slice()), // ← fixed
        mode,
        raw_req,
        num_threads,
        start_at,
        U256::from(start_at),
    );

    // GPU loop (all modes): initialize WGPU once, keep dispatching chunks until a match is found.
    if matches!(
        mode,
        config::MatchMode::Prefix
            | config::MatchMode::Suffix
            | config::MatchMode::Contains
            | config::MatchMode::Mask
            | config::MatchMode::Exact
    ) {
        // Precompute pattern arrays and constants once on CPU
        let mut pattern_nibbles = vec![0u32; 40];
        let mut pattern_mask = vec![0u32; 40];
        let mut pattern_len: u32 = 0;
        match mode {
            config::MatchMode::Mask => {
                for (i, ch) in req.chars().take(40).enumerate() {
                    if ch == '.' {
                        pattern_mask[i] = 1;
                    } else if let Some(v) = hex_char_to_nibble(ch) {
                        pattern_nibbles[i] = v & 0x0f;
                    }
                }
                pattern_len = 40;
            }
            config::MatchMode::Exact => {
                for (i, ch) in req.chars().take(40).enumerate() {
                    if let Some(v) = hex_char_to_nibble(ch) {
                        pattern_nibbles[i] = v & 0x0f;
                    }
                }
                pattern_len = 40;
            }
            _ => {
                for (i, ch) in req.chars().take(40).enumerate() {
                    if let Some(v) = hex_char_to_nibble(ch) {
                        pattern_nibbles[i] = v & 0x0f;
                        pattern_len += 1;
                    } else {
                        break;
                    }
                }
            }
        }
        let match_mode_u32 = match mode {
            config::MatchMode::Prefix => 0,
            config::MatchMode::Suffix => 1,
            config::MatchMode::Contains => 2,
            config::MatchMode::Mask => 3,
            config::MatchMode::Exact => 4,
        } as u32;

        // WGPU setup (once)
        let instance = wgpu::Instance::default();
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))
        .expect("no suitable GPU adapter found");
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("compute-device"),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::downlevel_defaults(),
            memory_hints: wgpu::MemoryHints::Performance,
            trace: wgpu::Trace::Off,
        }))
        .expect("failed to create device");

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("create2_search.wgsl"),
            source: wgpu::ShaderSource::Wgsl(include_str!("shaders/create2_search.wgsl").into()),
        });

        let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("compute-bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("compute-pl"),
            bind_group_layouts: &[&bgl],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("create2-search"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });

        // Persistent output buffers
        let out_zero = GpuOutput {
            found: 0,
            _pad0: [0; 3],
            salt_le: [0; 4],
            addr_words: [0; 5],
            _pad: [0; 2],
            _pad_end: 0,
        };
        // Create batched output and readback buffers
        let batch = config::GPU_BATCH_DISPATCHES_OVERRIDE.unwrap_or(4);
        let mut out_storage_bufs: Vec<wgpu::Buffer> = Vec::with_capacity(batch as usize);
        let mut read_bufs: Vec<wgpu::Buffer> = Vec::with_capacity(batch as usize);
        for _ in 0..batch {
            let obuf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("outputs-storage"),
                contents: bytemuck::bytes_of(&out_zero),
                usage: wgpu::BufferUsages::STORAGE
                    | wgpu::BufferUsages::COPY_SRC
                    | wgpu::BufferUsages::COPY_DST,
            });
            let rbuf = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("outputs-readback"),
                size: std::mem::size_of::<GpuOutput>() as u64,
                usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
                mapped_at_creation: false,
            });
            out_storage_bufs.push(obuf);
            read_bufs.push(rbuf);
        }

        // Auto-tune work_items and salts_per_invocation based on adapter limits, with config overrides
        let (work_items, salts_per_invocation) = {
            let limits = adapter.limits();
            let wg_size = 256u32; // must match @workgroup_size in WGSL
            let auto_groups = limits.max_compute_workgroups_per_dimension.min(1_048_576); // keep groups reasonable
            let auto_work_items = auto_groups.saturating_mul(wg_size);
            let wi = config::GPU_WORK_ITEMS_OVERRIDE.unwrap_or(auto_work_items);
            let spi = config::GPU_SALTS_PER_INVOCATION_OVERRIDE.unwrap_or(8);
            (wi, spi)
        };
        let wg_size = 256u32;
        let groups = (work_items + wg_size - 1) / wg_size;

        // Each invocation tests 'salts_per_invocation' salts, stepping by 'stride' between each.
        // 'stride' must equal the total number of invocations in this dispatch (work_items).
        let stride: u32 = work_items;
        // Inputs/bind groups are created per-batch per-iteration to allow distinct base salts.

        // Map the read buffer per iteration (avoid keeping it mapped across submissions)

        let t0 = Instant::now();
        let mut chunks_scanned: u64 = 0;
        loop {
            // Advance base by the total salts covered per chunk: work_items * salts_per_invocation
            let base_chunk = start_at.wrapping_add(
                (chunks_scanned as u128) * (work_items as u128) * (salts_per_invocation as u128),
            );

            // Build inputs and bind groups for each batch item with distinct base_salt
            let mut in_bufs: Vec<wgpu::Buffer> = Vec::with_capacity(batch as usize);
            let mut bind_groups: Vec<wgpu::BindGroup> = Vec::with_capacity(batch as usize);
            for b in 0..batch {
                let base_b = base_chunk.wrapping_add(
                    (b as u128) * (work_items as u128) * (salts_per_invocation as u128),
                );
                let inputs_u32 = build_inputs_u32(
                    base_b,
                    &pattern_nibbles,
                    &pattern_mask,
                    pattern_len,
                    match_mode_u32,
                    salts_per_invocation,
                    stride,
                    work_items,
                    deployer,
                    &init_code_hash,
                );
                let inb = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                    label: Some("inputs"),
                    contents: cast_slice(&inputs_u32),
                    usage: wgpu::BufferUsages::STORAGE,
                });
                in_bufs.push(inb);
            }

            // Reset all output storage buffers
            for b in 0..batch {
                queue.write_buffer(
                    &out_storage_bufs[b as usize],
                    0,
                    bytemuck::bytes_of(&out_zero),
                );
            }

            // Create bind groups for this batch
            for b in 0..batch {
                let bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("compute-bg"),
                    layout: &bgl,
                    entries: &[
                        wgpu::BindGroupEntry {
                            binding: 0,
                            resource: in_bufs[b as usize].as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 1,
                            resource: out_storage_bufs[b as usize].as_entire_binding(),
                        },
                    ],
                });
                bind_groups.push(bg);
            }

            // Record commands for all batch dispatches
            let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("compute-encoder"),
            });
            {
                let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: Some("compute-pass"),
                    timestamp_writes: None,
                });
                cpass.set_pipeline(&pipeline);
                for b in 0..batch {
                    cpass.set_bind_group(0, &bind_groups[b as usize], &[]);
                    cpass.dispatch_workgroups(groups, 1, 1);
                }
            }
            // Copy outputs to readback buffers
            for b in 0..batch {
                encoder.copy_buffer_to_buffer(
                    &out_storage_bufs[b as usize],
                    0,
                    &read_bufs[b as usize],
                    0,
                    std::mem::size_of::<GpuOutput>() as u64,
                );
            }

            // Submit and wait
            queue.submit(Some(encoder.finish()));
            device.poll(wgpu::PollType::Wait).unwrap();

            // Map results for this batch and check for hit
            let mut result: Option<(U256, Address)> = None;
            for b in 0..batch {
                let slice = read_bufs[b as usize].slice(..);
                let (tx_map, rx_map) = std::sync::mpsc::channel();
                slice.map_async(wgpu::MapMode::Read, move |res| {
                    let _ = tx_map.send(res);
                });
                device.poll(wgpu::PollType::Wait).unwrap();
                if rx_map.recv().ok().and_then(|r| r.ok()).is_none() {
                    read_bufs[b as usize].unmap();
                    continue;
                }
                let data = slice.get_mapped_range();
                let out: &GpuOutput = bytemuck::from_bytes(&data);
                if out.found > 0 {
                    let s0 = out.salt_le[0] as u128;
                    let s1 = out.salt_le[1] as u128;
                    let s2 = out.salt_le[2] as u128;
                    let s3 = out.salt_le[3] as u128;
                    let salt128 = s0 | (s1 << 32) | (s2 << 64) | (s3 << 96);
                    let salt_u256 = U256::from(salt128);

                    let mut addr_bytes = [0u8; 20];
                    for i in 0..5 {
                        let w = out.addr_words[i];
                        let o = i * 4;
                        addr_bytes[o + 0] = (w & 0xFF) as u8;
                        addr_bytes[o + 1] = ((w >> 8) & 0xFF) as u8;
                        addr_bytes[o + 2] = ((w >> 16) & 0xFF) as u8;
                        addr_bytes[o + 3] = ((w >> 24) & 0xFF) as u8;
                    }
                    let addr = Address::from_slice(&addr_bytes);
                    result = Some((salt_u256, addr));
                    drop(data);
                    read_bufs[b as usize].unmap();
                    break;
                }
                drop(data);
                read_bufs[b as usize].unmap();
            }

            if let Some((salt, addr)) = result {
                println!();
                println!("=== RESULT ===");
                println!("Vanity address: 0x{}", hex::encode(addr));
                println!("Salt (decimal): {}", salt);
                println!("Salt (hex 32B): 0x{:064x}", U256::from(salt));
                println!("(GPU) Recompute to verify:");
                println!("create2(deployer, salt, keccak(init_code)) == above address ✔");
                return;
            }

            chunks_scanned = chunks_scanned.wrapping_add(1);
            if chunks_scanned % 100 == 0 {
                let salts_scanned = (chunks_scanned as u128) * (work_items as u128);
                eprintln!(
                    "GPU: scanned {} chunks (~{} salts) in {:.2}s",
                    chunks_scanned,
                    salts_scanned,
                    t0.elapsed().as_secs_f64()
                );
            }
        }
    }
    let start = Instant::now();

    for i in 0..num_threads {
        let tx = tx.clone();
        let init_code_hash = Arc::clone(&init_code_hash);
        let req = req.clone();

        thread::spawn(move || {
            let progress_every = config::PROGRESS_EVERY;
            let mut checked: u64 = 0;
            // start from offset + thread index
            let mut j: u128 = start_at.wrapping_add(i as u128);

            loop {
                let salt_u256 = U256::from(j);
                let salt_b256 = B256::from(salt_u256);

                let addr = create2_address_from_hash(deployer, salt_b256, &init_code_hash);

                if address_matches(addr, &req, mode) {
                    eprintln!(
                        "[FOUND] thread={} salt(dec)={} salt(hex)=0x{:064x} addr=0x{}",
                        i,
                        j,
                        j,
                        hex::encode(addr)
                    );
                    let _ = tx.send((salt_u256, addr));
                    break;
                }

                j = j.wrapping_add(stride); // advance by #threads
                checked = checked.wrapping_add(1);
                if checked % progress_every == 0 {
                    eprintln!("thread {}: checked ~{} salts", i, checked);
                }
            }
        });
    }

    // Wait for first hit, then print and exit.
    match rx.recv() {
        Ok((salt, addr)) => {
            let elapsed = start.elapsed().as_secs_f64();
            println!();
            println!("=== RESULT ===");
            println!("Vanity address: 0x{}", hex::encode(addr));
            println!("Salt (decimal): {}", salt);
            println!("Salt (hex 32B): 0x{:064x}", U256::from(salt));
            println!("Elapsed: {:.3}s", elapsed);
            println!("Recompute to verify:");
            println!("create2(deployer, salt, keccak(init_code)) == above address ✔");
        }
        Err(_) => eprintln!("all threads exited without a result (unexpected)"),
    }
}
