use alloy_primitives::{Address, B256, U256, keccak256};
use bytemuck::cast_slice;
use std::{
    env, fs,
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

mod benchmark;
mod config;

fn load_creation_code_hex<P: AsRef<Path>>(p: P) -> Vec<u8> {
    let raw = fs::read_to_string(p).expect("failed to read creation code file");
    let filtered: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if filtered.is_empty() {
        panic!("creation code file contained no hex");
    }
    hex::decode(&filtered).expect("invalid hex in creation code file")
}

#[inline]
fn create2_address_from_hash(deployer: Address, salt: B256, init_code_hash: &[u8; 32]) -> Address {
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
    let addr_hex = hex::encode(addr);
    match mode {
        config::MatchMode::Prefix => addr_hex.starts_with(req),
        config::MatchMode::Suffix => addr_hex.ends_with(req),
        config::MatchMode::Contains => addr_hex.contains(req),
        config::MatchMode::Exact => addr_hex == req,
        config::MatchMode::Mask => addr_hex
            .bytes()
            .zip(req.bytes())
            .all(|(a, p)| p == b'.' || p == a),
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
    let mut v: Vec<u32> = Vec::with_capacity(4 + 5 + 5 + 8 + 40 + 40);

    // base_salt (128-bit little-endian limbs)
    let s0 = (base_salt & 0xffff_ffff) as u32;
    let s1 = ((base_salt >> 32) & 0xffff_ffff) as u32;
    let s2 = ((base_salt >> 64) & 0xffff_ffff) as u32;
    let s3 = ((base_salt >> 96) & 0xffff_ffff) as u32;
    v.extend_from_slice(&[s0, s1, s2, s3]);

    v.push(pattern_len);
    v.push(match_mode);
    v.push(salts_per_invocation);
    v.push(stride);
    v.push(work_items);

    let dep_bytes = deployer.as_slice();
    let dep_words = pack_le_words(dep_bytes);
    debug_assert_eq!(dep_words.len(), 5);
    v.extend_from_slice(&dep_words);

    let hash_words = pack_le_words(init_code_hash);
    debug_assert_eq!(hash_words.len(), 8);
    v.extend_from_slice(&hash_words);

    let mut pattern = [0u32; 40];
    for (i, &n) in pattern_nibbles.iter().take(40).enumerate() {
        pattern[i] = n & 0x0f;
    }
    v.extend_from_slice(&pattern);

    let mut mask = [0u32; 40];
    for (i, &m) in pattern_mask.iter().take(40).enumerate() {
        mask[i] = m;
    }
    v.extend_from_slice(&mask);

    let rem = v.len() % 4;
    if rem != 0 {
        v.extend(std::iter::repeat(0u32).take(4 - rem));
    }

    v
}

// Optimized GPU context that persists across multiple dispatches
struct OptimizedGpuContext {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    output_buffers: Vec<wgpu::Buffer>,
    input_buffers: Vec<wgpu::Buffer>,
    bind_groups: Vec<wgpu::BindGroup>,
    staging_buffer: wgpu::Buffer,
    batch_size: usize,
    work_items: u32,
    workgroup_size: u32,
}

impl OptimizedGpuContext {
    async fn new(work_items: u32, batch_size: usize) -> Option<Self> {
        println!("Creating WGPU instance...");
        let instance = wgpu::Instance::default();

        println!("Requesting GPU adapter...");
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await;

        let adapter = match adapter {
            Ok(a) => {
                let info = a.get_info();
                println!("Found GPU adapter: {} ({:?})", info.name, info.backend);
                a
            }
            Err(e) => {
                println!("No suitable GPU adapter found: {}", e);
                return None;
            }
        };

        println!("Requesting GPU device...");
        let (device, queue) = match adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("compute-device"),
                required_features: wgpu::Features::empty(),
                required_limits: adapter.limits(),
                memory_hints: wgpu::MemoryHints::Performance,
                trace: wgpu::Trace::Off,
            })
            .await
        {
            Ok((d, q)) => {
                println!("GPU device created successfully");
                (d, q)
            }
            Err(e) => {
                println!("Failed to create GPU device: {}", e);
                return None;
            }
        };

        // Use optimized shader
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("create2_search.wgsl"),
            source: wgpu::ShaderSource::Wgsl(include_str!("shaders/create2_search.wgsl").into()),
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
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
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("create2-search-optimized"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });

        // Create persistent output and readback buffers
        let out_zero = GpuOutput {
            found: 0,
            _pad0: [0; 3],
            salt_le: [0; 4],
            addr_words: [0; 5],
            _pad: [0; 2],
            _pad_end: 0,
        };

        let mut output_buffers = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            let out_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("output-storage"),
                contents: bytemuck::bytes_of(&out_zero),
                usage: wgpu::BufferUsages::STORAGE
                    | wgpu::BufferUsages::COPY_SRC
                    | wgpu::BufferUsages::COPY_DST,
            });

            output_buffers.push(out_buf);
        }

        // Create a larger staging buffer for efficient transfers
        let staging_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging"),
            size: (batch_size * std::mem::size_of::<GpuOutput>()) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        // Optimize workgroup size for the GPU
        let workgroup_size = 256u32; // Most GPUs work well with 256

        Some(Self {
            device,
            queue,
            pipeline,
            bind_group_layout,
            output_buffers,
            input_buffers: Vec::new(),
            bind_groups: Vec::new(),
            staging_buffer,
            batch_size,
            work_items,
            workgroup_size,
        })
    }

    fn dispatch_batch(
        &mut self,
        inputs_batch: &[Vec<u32>],
        _salts_per_invocation: u32,
    ) -> Option<(U256, Address)> {
        assert_eq!(inputs_batch.len(), self.batch_size);

        // Reset output buffers
        let out_zero = GpuOutput {
            found: 0,
            _pad0: [0; 3],
            salt_le: [0; 4],
            addr_words: [0; 5],
            _pad: [0; 2],
            _pad_end: 0,
        };

        for buf in &self.output_buffers {
            self.queue
                .write_buffer(buf, 0, bytemuck::bytes_of(&out_zero));
        }

        // Lazily create input buffers and bind groups once, then reuse
        if self.input_buffers.is_empty() {
            for i in 0..self.batch_size {
                let size_bytes = (inputs_batch[i].len() * 4) as u64;
                let input_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("input"),
                    size: size_bytes,
                    usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                });

                let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("compute-bg"),
                    layout: &self.bind_group_layout,
                    entries: &[
                        wgpu::BindGroupEntry {
                            binding: 0,
                            resource: input_buf.as_entire_binding(),
                        },
                        wgpu::BindGroupEntry {
                            binding: 1,
                            resource: self.output_buffers[i].as_entire_binding(),
                        },
                    ],
                });

                self.input_buffers.push(input_buf);
                self.bind_groups.push(bind_group);
            }
        }
        // Update inputs via queue writes
        for (i, inputs) in inputs_batch.iter().enumerate() {
            self.queue
                .write_buffer(&self.input_buffers[i], 0, cast_slice(inputs));
        }

        // Record compute pass
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("compute-encoder"),
            });

        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("compute-pass"),
                timestamp_writes: None,
            });

            compute_pass.set_pipeline(&self.pipeline);

            let groups = (self.work_items + self.workgroup_size - 1) / self.workgroup_size;

            for bind_group in &self.bind_groups {
                compute_pass.set_bind_group(0, bind_group, &[]);
                compute_pass.dispatch_workgroups(groups, 1, 1);
            }
        }

        // Copy results to staging buffer for efficient readback
        let output_size = std::mem::size_of::<GpuOutput>() as u64;
        for (i, output_buf) in self.output_buffers.iter().enumerate() {
            encoder.copy_buffer_to_buffer(
                output_buf,
                0,
                &self.staging_buffer,
                (i as u64) * output_size,
                output_size,
            );
        }

        self.queue.submit(Some(encoder.finish()));
        self.device.poll(wgpu::PollType::Wait).unwrap();

        // Map staging buffer and check all results
        let staging_slice = self.staging_buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        staging_slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).ok();
        });
        self.device.poll(wgpu::PollType::Wait).unwrap();

        if rx.recv().ok().and_then(|r| r.ok()).is_none() {
            return None;
        }

        let mapped_data = staging_slice.get_mapped_range();

        // Check each batch result
        for i in 0..self.batch_size {
            let offset = i * std::mem::size_of::<GpuOutput>();
            let output: &GpuOutput = bytemuck::from_bytes(
                &mapped_data[offset..offset + std::mem::size_of::<GpuOutput>()],
            );

            if output.found > 0 {
                let s0 = output.salt_le[0] as u128;
                let s1 = output.salt_le[1] as u128;
                let s2 = output.salt_le[2] as u128;
                let s3 = output.salt_le[3] as u128;
                let salt128 = s0 | (s1 << 32) | (s2 << 64) | (s3 << 96);
                let salt_u256 = U256::from(salt128);

                let mut addr_bytes = [0u8; 20];
                for j in 0..5 {
                    let w = output.addr_words[j];
                    let base = j * 4;
                    addr_bytes[base] = (w & 0xFF) as u8;
                    addr_bytes[base + 1] = ((w >> 8) & 0xFF) as u8;
                    addr_bytes[base + 2] = ((w >> 16) & 0xFF) as u8;
                    addr_bytes[base + 3] = ((w >> 24) & 0xFF) as u8;
                }
                let addr = Address::from_slice(&addr_bytes);

                drop(mapped_data);
                self.staging_buffer.unmap();
                return Some((salt_u256, addr));
            }
        }

        drop(mapped_data);
        self.staging_buffer.unmap();
        None
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Check for benchmark argument
    if args.len() > 1 && args[1] == "--benchmark" {
        benchmark::run_comprehensive_benchmark();
        return;
    }
    let deployer =
        Address::from_str(config::DEPLOYER).expect("invalid DEPLOYER in config.rs (address parse)");
    let init_code = load_creation_code_hex(config::CREATION_CODE_PATH);
    let init_code_hash = keccak256(&init_code);
    let init_code_hash = Arc::new(init_code_hash);

    let raw_req = config::REQUEST_PATTERN;
    let mode = config::MATCH_MODE;

    let req = normalize_req(raw_req);
    validate_req(mode, &req);

    let start_at: u128 = parse_start_salt_u128(config::START_SALT);

    println!(
        "CREATE2 vanity search\
        \n- deployer: {}\
        \n- init_code: {} bytes\
        \n- init_code keccak256: 0x{}\
        \n- mode: {:?}\
        \n- request: {}\
        \n- start_salt(dec): {}\
        \n- start_salt(hex32): 0x{:064x}",
        deployer,
        init_code.len(),
        hex::encode(init_code_hash.as_slice()),
        mode,
        raw_req,
        start_at,
        U256::from(start_at),
    );

    // GPU optimization path
    if matches!(mode, config::MatchMode::Prefix) {
        // Precompute pattern arrays
        let mut pattern_nibbles = vec![0u32; 40];
        let pattern_mask = vec![0u32; 40];
        let mut pattern_len: u32 = 0;

        for (i, ch) in req.chars().take(40).enumerate() {
            if let Some(v) = hex_char_to_nibble(ch) {
                pattern_nibbles[i] = v & 0x0f;
                pattern_len += 1;
            } else {
                break;
            }
        }

        let match_mode_u32 = 0u32; // Prefix mode

        // Optimized GPU parameters
        let work_items = config::GPU_WORK_ITEMS_OVERRIDE.unwrap_or(1_048_576); // 1M work items
        let salts_per_invocation = config::GPU_SALTS_PER_INVOCATION_OVERRIDE.unwrap_or(16); // More salts per invocation
        let batch_size = config::GPU_BATCH_DISPATCHES_OVERRIDE.unwrap_or(8) as usize; // Larger batches

        // Create optimized GPU context
        println!(
            "Attempting to create GPU context with work_items={}, batch_size={}",
            work_items, batch_size
        );
        let gpu_context = pollster::block_on(OptimizedGpuContext::new(work_items, batch_size));

        if let Some(mut gpu_context) = gpu_context {
            println!("GPU context created successfully!");

            let stride = work_items;
            let t0 = Instant::now();
            let mut chunks_scanned: u64 = 0;

            loop {
                let base_chunk = start_at.wrapping_add(
                    (chunks_scanned as u128)
                        * (work_items as u128)
                        * (salts_per_invocation as u128)
                        * (batch_size as u128),
                );

                // Build input batch
                let mut inputs_batch = Vec::with_capacity(batch_size);
                for b in 0..batch_size {
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
                    inputs_batch.push(inputs_u32);
                }

                // Dispatch optimized batch
                if let Some((salt, addr)) =
                    gpu_context.dispatch_batch(&inputs_batch, salts_per_invocation)
                {
                    println!();
                    println!("=== RESULT (GPU) ===");
                    println!("Vanity address: 0x{}", hex::encode(addr));
                    println!("Salt (decimal): {}", salt);
                    println!("Salt (hex 32B): 0x{:064x}", U256::from(salt));
                    println!("Time elapsed: {:.2}s", t0.elapsed().as_secs_f64());
                    println!("Recompute to verify:");
                    println!("create2(deployer, salt, keccak(init_code)) == above address ✔");
                    return;
                }

                chunks_scanned = chunks_scanned.wrapping_add(1);
                if chunks_scanned % 10 == 0 {
                    // Report progress more frequently
                    let salts_scanned = (chunks_scanned as u128)
                        * (work_items as u128)
                        * (salts_per_invocation as u128)
                        * (batch_size as u128);
                    eprintln!(
                        "GPU: scanned {} batches (~{} salts) in {:.2}s | Rate: {:.0} MH/s",
                        chunks_scanned,
                        salts_scanned,
                        t0.elapsed().as_secs_f64(),
                        salts_scanned as f64 / t0.elapsed().as_secs_f64() / 1_000_000.0
                    );
                }
            }
        } else {
            println!("Failed to create GPU context, falling back to CPU");
        }
    }

    // CPU-only fallback for non-prefix modes or when GPU fails
    let default_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let num_threads = config::THREAD_OVERRIDE.unwrap_or(default_threads);
    let stride: u128 = num_threads as u128;

    println!("Using CPU-only implementation (threads: {})", num_threads);
    let (tx, rx) = mpsc::channel::<(U256, Address)>();
    let start = Instant::now();

    for i in 0..num_threads {
        let tx = tx.clone();
        let init_code_hash = Arc::clone(&init_code_hash);
        let req = req.clone();

        thread::spawn(move || {
            let progress_every = std::cmp::max(config::PROGRESS_EVERY / 10, 1u64);
            let mut checked: u64 = 0;
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

                j = j.wrapping_add(stride);
                checked = checked.wrapping_add(1);
                if checked % progress_every == 0 {
                    eprintln!("thread {}: checked ~{} salts", i, checked);
                }
            }
        });
    }

    match rx.recv() {
        Ok((salt, addr)) => {
            let elapsed = start.elapsed().as_secs_f64();
            println!();
            println!("=== RESULT (CPU) ===");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    #[ignore]
    fn optimized_gpu_prefix_test() {
        let req = "";
        let mode = config::MatchMode::Prefix;
        let deployer = Address::from_str(config::DEPLOYER).expect("invalid DEPLOYER");
        let init_code: Vec<u8> = Vec::new();
        let init_hash = keccak256(&init_code);
        let base: u128 = 0;
        let work_items: u32 = 256;
        let batch_size = 2;

        let gpu_context = pollster::block_on(OptimizedGpuContext::new(work_items, batch_size))
            .expect("GPU context creation failed");

        let pattern_nibbles = vec![0u32; 40];
        let pattern_mask = vec![0u32; 40];

        let mut inputs_batch = Vec::new();
        for i in 0..batch_size {
            let inputs_u32 = build_inputs_u32(
                base + (i as u128) * (work_items as u128),
                &pattern_nibbles,
                &pattern_mask,
                0u32,
                0u32,
                1u32,
                work_items,
                work_items,
                deployer,
                &init_hash,
            );
            inputs_batch.push(inputs_u32);
        }

        let result = gpu_context.dispatch_batch(&inputs_batch, 1);
        assert!(result.is_some(), "Should find a match with empty prefix");
    }
}
