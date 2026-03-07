use alloy_primitives::{Address, U256};
use metal::*;
use objc::rc::autoreleasepool;
use sha3::{Digest, Keccak256};
use std::{
    fs,
    mem,
    path::Path,
    str::FromStr,
    time::Instant,
};

mod config;

// ---------------------------------------------------------------------------
// Metal Shading Language kernel (compiled at runtime)
// ---------------------------------------------------------------------------
const MSL_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

// ---- Keccak-f[1600] round constants ----
constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL,
};

// Rotate left for 64-bit
static inline ulong rotl64(ulong x, uint n) {
    return (x << n) | (x >> (64u - n));
}

// Full Keccak-f[1600] permutation (24 rounds)
static void keccak_f1600(thread ulong* state) {
    ulong C[5];
    ulong D[5];
    ulong B[25];

    for (int round = 0; round < 24; round++) {
        // Theta
        C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        D[0] = C[4] ^ rotl64(C[1], 1);
        D[1] = C[0] ^ rotl64(C[2], 1);
        D[2] = C[1] ^ rotl64(C[3], 1);
        D[3] = C[2] ^ rotl64(C[4], 1);
        D[4] = C[3] ^ rotl64(C[0], 1);

        state[ 0] ^= D[0]; state[ 1] ^= D[1]; state[ 2] ^= D[2]; state[ 3] ^= D[3]; state[ 4] ^= D[4];
        state[ 5] ^= D[0]; state[ 6] ^= D[1]; state[ 7] ^= D[2]; state[ 8] ^= D[3]; state[ 9] ^= D[4];
        state[10] ^= D[0]; state[11] ^= D[1]; state[12] ^= D[2]; state[13] ^= D[3]; state[14] ^= D[4];
        state[15] ^= D[0]; state[16] ^= D[1]; state[17] ^= D[2]; state[18] ^= D[3]; state[19] ^= D[4];
        state[20] ^= D[0]; state[21] ^= D[1]; state[22] ^= D[2]; state[23] ^= D[3]; state[24] ^= D[4];

        // Rho + Pi (combined, fully unrolled)
        B[ 0] = state[ 0];
        B[10] = rotl64(state[ 1],  1);
        B[20] = rotl64(state[ 2], 62);
        B[ 5] = rotl64(state[ 3], 28);
        B[15] = rotl64(state[ 4], 27);
        B[16] = rotl64(state[ 5], 36);
        B[ 1] = rotl64(state[ 6], 44);
        B[11] = rotl64(state[ 7],  6);
        B[21] = rotl64(state[ 8], 55);
        B[ 6] = rotl64(state[ 9], 20);
        B[ 7] = rotl64(state[10],  3);
        B[17] = rotl64(state[11], 10);
        B[ 2] = rotl64(state[12], 43);
        B[12] = rotl64(state[13], 25);
        B[22] = rotl64(state[14], 39);
        B[23] = rotl64(state[15], 41);
        B[ 8] = rotl64(state[16], 45);
        B[18] = rotl64(state[17], 15);
        B[ 3] = rotl64(state[18], 21);
        B[13] = rotl64(state[19],  8);
        B[14] = rotl64(state[20], 18);
        B[24] = rotl64(state[21],  2);
        B[ 9] = rotl64(state[22], 61);
        B[19] = rotl64(state[23], 56);
        B[ 4] = rotl64(state[24], 14);

        // Chi
        for (int j = 0; j < 25; j += 5) {
            state[j+0] = B[j+0] ^ ((~B[j+1]) & B[j+2]);
            state[j+1] = B[j+1] ^ ((~B[j+2]) & B[j+3]);
            state[j+2] = B[j+2] ^ ((~B[j+3]) & B[j+4]);
            state[j+3] = B[j+3] ^ ((~B[j+4]) & B[j+0]);
            state[j+4] = B[j+4] ^ ((~B[j+0]) & B[j+1]);
        }

        // Iota
        state[0] ^= RC[round];
    }
}

// Read a little-endian u64 from byte array
static inline ulong read_le64(const thread uchar* p) {
    return  (ulong)p[0]        | ((ulong)p[1] <<  8)
          | ((ulong)p[2] << 16) | ((ulong)p[3] << 24)
          | ((ulong)p[4] << 32) | ((ulong)p[5] << 40)
          | ((ulong)p[6] << 48) | ((ulong)p[7] << 56);
}

// ---- GPU parameters (must match Rust #[repr(C)] struct) ----
struct GpuParams {
    ulong base_salt;         // 0
    uint  pattern_len;       // 8
    int   partial_nibble;    // 12
    uchar block_template[136]; // 16
    uchar pattern[20];        // 152
    uchar _pad[4];             // 172  -> total 176
};

struct GpuResult {
    atomic_uint found;       // 0
    uint  _pad;              // 4
    ulong salt;              // 8
    uchar address[20];       // 16
    uchar _pad2[4];          // 36  -> total 40
};

kernel void mine_create2(
    device const GpuParams& params [[buffer(0)]],
    device GpuResult&       result [[buffer(1)]],
    uint tid [[thread_position_in_grid]])
{
    // Early exit if another thread already found a match
    if (atomic_load_explicit(&result.found, memory_order_relaxed) != 0) {
        return;
    }

    // Compute salt for this thread
    ulong salt = params.base_salt + (ulong)tid;

    // Copy block template to thread-local memory
    uchar block[136];
    for (int i = 0; i < 136; i++) {
        block[i] = params.block_template[i];
    }

    // Write salt into block[45..53] (big-endian u64, lower 8 bytes of the 32-byte salt field)
    // Salt field in preimage is [21..53]. Upper 24 bytes are zero. u64 goes in [45..53].
    block[45] = (uchar)(salt >> 56);
    block[46] = (uchar)(salt >> 48);
    block[47] = (uchar)(salt >> 40);
    block[48] = (uchar)(salt >> 32);
    block[49] = (uchar)(salt >> 24);
    block[50] = (uchar)(salt >> 16);
    block[51] = (uchar)(salt >>  8);
    block[52] = (uchar)(salt);

    // Absorb block into keccak state (17 lanes, little-endian)
    ulong state[25] = {0};
    for (int i = 0; i < 17; i++) {
        state[i] = read_le64(&block[i * 8]);
    }

    // Keccak-f[1600]
    keccak_f1600(state);

    // Extract hash bytes 12..32 (the 20-byte address)
    // state[0] = hash[0..8], state[1] = hash[8..16], state[2] = hash[16..24], state[3] = hash[24..32]
    uchar addr[20];
    {
        ulong s1 = state[1];
        addr[0] = (uchar)(s1 >> 32);
        addr[1] = (uchar)(s1 >> 40);
        addr[2] = (uchar)(s1 >> 48);
        addr[3] = (uchar)(s1 >> 56);
    }
    {
        ulong s2 = state[2];
        for (int i = 0; i < 8; i++) {
            addr[4 + i] = (uchar)(s2 >> (i * 8));
        }
    }
    {
        ulong s3 = state[3];
        for (int i = 0; i < 8; i++) {
            addr[12 + i] = (uchar)(s3 >> (i * 8));
        }
    }

    // Check prefix match
    bool matched = true;
    for (uint i = 0; i < params.pattern_len; i++) {
        if (addr[i] != params.pattern[i]) {
            matched = false;
            break;
        }
    }

    // Check partial nibble
    if (matched && params.partial_nibble >= 0) {
        uchar high_nibble = addr[params.pattern_len] >> 4;
        if (high_nibble != (uchar)params.partial_nibble) {
            matched = false;
        }
    }

    if (matched) {
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(
                &result.found, &expected, 1u,
                memory_order_relaxed, memory_order_relaxed))
        {
            result.salt = salt;
            for (int i = 0; i < 20; i++) result.address[i] = addr[i];
        }
    }
}
"#;

// ---------------------------------------------------------------------------
// Rust-side structs (must match MSL layout exactly)
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone)]
struct GpuParams {
    base_salt: u64,
    pattern_len: u32,
    partial_nibble: i32,
    block_template: [u8; 136],
    pattern: [u8; 20],
    _pad: [u8; 4],
}

#[repr(C)]
#[derive(Clone)]
struct GpuResult {
    found: u32,
    _pad: u32,
    salt: u64,
    address: [u8; 20],
    _pad2: [u8; 4],
}

// ---------------------------------------------------------------------------
// Helpers (reused from main.rs / main_optimized.rs)
// ---------------------------------------------------------------------------
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn load_creation_code_hex<P: AsRef<Path>>(p: P) -> Vec<u8> {
    let raw = fs::read_to_string(p).expect("failed to read creation code file");
    let filtered: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if filtered.is_empty() {
        panic!("creation code file contained no hex");
    }
    hex::decode(&filtered).expect("invalid hex in creation code file")
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
        panic!("REQUEST_PATTERN must contain only [0-9a-fA-F] and '.'");
    }
    match mode {
        config::MatchMode::Exact => {
            if req.len() != 40 { panic!("Exact mode requires 40 hex nibbles"); }
            if req.contains('.') { panic!("Exact mode: no '.' wildcards"); }
        }
        config::MatchMode::Mask => {
            if req.len() != 40 { panic!("Mask mode requires 40-char mask"); }
        }
        _ => {
            if req.is_empty() || req.len() > 40 { panic!("Pattern: 1-40 nibbles"); }
            if req.contains('.') { panic!("Use Mask mode for '.' wildcards"); }
        }
    }
}

fn parse_pattern_bytes(hex_str: &str) -> (Vec<u8>, Option<u8>) {
    let full_bytes = hex_str.len() / 2;
    let has_partial = hex_str.len() % 2 == 1;
    let mut bytes = Vec::with_capacity(full_bytes);
    for i in 0..full_bytes {
        bytes.push(u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap());
    }
    let partial = if has_partial {
        Some(u8::from_str_radix(&hex_str[hex_str.len() - 1..], 16).unwrap())
    } else {
        None
    };
    (bytes, partial)
}

fn parse_start_salt_u128(s: &str) -> u128 {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).expect("START_SALT hex parse failed")
    } else {
        t.parse::<u128>().expect("START_SALT decimal parse failed")
    }
}

/// Build the pre-padded 136-byte Keccak block for CREATE2 preimage.
fn build_padded_block(deployer: &[u8; 20], init_code_hash: &[u8; 32]) -> [u8; 136] {
    let mut block = [0u8; 136];
    block[0] = 0xff;
    block[1..21].copy_from_slice(deployer);
    // block[21..53] = salt (zeroed, GPU kernel fills in per-thread)
    block[53..85].copy_from_slice(init_code_hash);
    // Ethereum Keccak-256 padding (raw Keccak, NOT SHA-3)
    block[85] = 0x01;
    block[135] |= 0x80;
    block
}

/// Verify GPU Keccak output matches CPU for a test salt.
fn verify_gpu_correctness(device: &Device, pipeline: &ComputePipelineState, params: &GpuParams) {
    let test_salt: u64 = 12345;

    // CPU reference: build preimage, hash, extract address
    let mut preimage = [0u8; 85];
    preimage.copy_from_slice(&params.block_template[..85]);
    // Write test salt (u64 BE) into preimage[45..53]
    preimage[45..53].copy_from_slice(&test_salt.to_be_bytes());
    let cpu_hash = keccak256(&preimage);
    let cpu_addr = &cpu_hash[12..32];

    // GPU: dispatch single thread with test salt
    let mut test_params = params.clone();
    test_params.base_salt = test_salt;

    let params_buf = device.new_buffer_with_data(
        &test_params as *const GpuParams as *const _,
        mem::size_of::<GpuParams>() as u64,
        MTLResourceOptions::StorageModeShared,
    );

    let result_buf = device.new_buffer(
        mem::size_of::<GpuResult>() as u64,
        MTLResourceOptions::StorageModeShared,
    );
    // Zero result
    unsafe {
        let ptr = result_buf.contents() as *mut GpuResult;
        *ptr = GpuResult {
            found: 0, _pad: 0, salt: 0,
            address: [0u8; 20], _pad2: [0u8; 4],
        };
    }

    // Set pattern to match "any" (pattern_len=0) so the kernel always "matches"
    // Actually, let's just run one thread and check the address manually
    // We need to temporarily set pattern to match the CPU result
    unsafe {
        let p = params_buf.contents() as *mut GpuParams;
        (*p).pattern_len = cpu_addr.len() as u32; // 20 bytes = exact match
        (&mut (*p).pattern)[..20].copy_from_slice(cpu_addr);
        (*p).partial_nibble = -1;
        (*p).base_salt = test_salt;
    }

    let command_queue = device.new_command_queue();

    autoreleasepool(|| {
        let cmd = command_queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        enc.set_buffer(0, Some(&params_buf), 0);
        enc.set_buffer(1, Some(&result_buf), 0);
        enc.dispatch_threads(
            MTLSize::new(1, 1, 1),
            MTLSize::new(1, 1, 1),
        );
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
    });

    let gpu_result = unsafe { &*(result_buf.contents() as *const GpuResult) };
    if gpu_result.found == 0 {
        panic!(
            "GPU verification FAILED: kernel did not find a match for test salt.\n\
             CPU address: 0x{}\n\
             This likely means the GPU Keccak-256 implementation is incorrect.",
            hex::encode(cpu_addr)
        );
    }
    if &gpu_result.address[..] != cpu_addr {
        panic!(
            "GPU verification FAILED: address mismatch!\n\
             CPU: 0x{}\n\
             GPU: 0x{}",
            hex::encode(cpu_addr),
            hex::encode(&gpu_result.address)
        );
    }
    println!("GPU Keccak-256 verification PASSED (test salt={}, addr=0x{})",
        test_salt, hex::encode(cpu_addr));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
fn main() {
    let deployer =
        Address::from_str(config::DEPLOYER).expect("invalid DEPLOYER address");
    let deployer_bytes: [u8; 20] = deployer.0.into();

    let init_code = load_creation_code_hex(config::CREATION_CODE_PATH);
    let init_code_hash = keccak256(&init_code);

    let mode = config::MATCH_MODE;
    let req = normalize_req(config::REQUEST_PATTERN);
    validate_req(mode, &req);

    if !matches!(mode, config::MatchMode::Prefix) {
        panic!("GPU miner currently supports Prefix mode only. \
                Use salt_miner or salt_miner_fast for other modes.");
    }

    let (pattern_bytes, partial_nibble) = parse_pattern_bytes(&req);
    let start_at: u128 = parse_start_salt_u128(config::START_SALT);
    if start_at > u64::MAX as u128 {
        panic!("GPU miner requires START_SALT to fit in u64");
    }

    // Build padded block template
    let block_template = build_padded_block(&deployer_bytes, &init_code_hash);

    // Prepare GPU params
    let mut gpu_params = GpuParams {
        base_salt: start_at as u64,
        pattern_len: pattern_bytes.len() as u32,
        partial_nibble: partial_nibble.map(|n| n as i32).unwrap_or(-1),
        block_template,
        pattern: [0u8; 20],
        _pad: [0u8; 4],
    };
    gpu_params.pattern[..pattern_bytes.len()].copy_from_slice(&pattern_bytes);

    // ---- Metal setup ----
    let device = Device::system_default().expect("No Metal GPU device found");
    println!("GPU: {}", device.name());

    let options = CompileOptions::new();
    let library = device
        .new_library_with_source(MSL_SOURCE, &options)
        .expect("Failed to compile Metal shader");

    let kernel = library
        .get_function("mine_create2", None)
        .expect("Kernel function 'mine_create2' not found");

    let pipeline = device
        .new_compute_pipeline_state_with_function(&kernel)
        .expect("Failed to create compute pipeline");

    let max_threads = pipeline.max_total_threads_per_threadgroup();
    let threadgroup_size = max_threads.min(256) as u64;

    println!(
        "CREATE2 vanity search (GPU)\
        \n- deployer: {}\
        \n- init_code: {} bytes\
        \n- init_code keccak256: 0x{}\
        \n- mode: {:?}\
        \n- request: {}\
        \n- max_threads_per_threadgroup: {}\
        \n- threadgroup_size: {}\
        \n- start_salt(dec): {}",
        deployer,
        init_code.len(),
        hex::encode(&init_code_hash),
        mode,
        config::REQUEST_PATTERN,
        max_threads,
        threadgroup_size,
        start_at,
    );

    // Verify GPU correctness before mining
    verify_gpu_correctness(&device, &pipeline, &gpu_params);

    // ---- Mining loop ----
    let batch_size: u64 = 1 << 22; // 4M candidates per GPU dispatch
    let mut current_salt: u64 = start_at as u64;
    let mut total_checked: u64 = 0;

    let command_queue = device.new_command_queue();

    let params_buf = device.new_buffer_with_data(
        &gpu_params as *const GpuParams as *const _,
        mem::size_of::<GpuParams>() as u64,
        MTLResourceOptions::StorageModeShared,
    );

    let result_buf = device.new_buffer(
        mem::size_of::<GpuResult>() as u64,
        MTLResourceOptions::StorageModeShared,
    );

    let start_time = Instant::now();

    println!("Mining with batch_size = {} ({:.1}M per dispatch)...",
        batch_size, batch_size as f64 / 1_000_000.0);

    loop {
        // Update base_salt in params buffer
        unsafe {
            let p = params_buf.contents() as *mut GpuParams;
            (*p).base_salt = current_salt;
        }

        // Reset result buffer
        unsafe {
            let r = result_buf.contents() as *mut GpuResult;
            (*r).found = 0;
            (*r).salt = 0;
        }

        // Dispatch GPU batch
        autoreleasepool(|| {
            let cmd = command_queue.new_command_buffer();
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(&pipeline);
            enc.set_buffer(0, Some(&params_buf), 0);
            enc.set_buffer(1, Some(&result_buf), 0);

            let grid = MTLSize::new(batch_size, 1, 1);
            let tg = MTLSize::new(threadgroup_size, 1, 1);
            enc.dispatch_threads(grid, tg);

            enc.end_encoding();
            cmd.commit();
            cmd.wait_until_completed();
        });

        total_checked += batch_size;

        // Check result
        let gpu_result = unsafe { &*(result_buf.contents() as *const GpuResult) };
        if gpu_result.found != 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let salt = gpu_result.salt;
            let addr = gpu_result.address;

            println!();
            println!("=== RESULT ===");
            println!("Vanity address: 0x{}", hex::encode(addr));
            println!("Salt (decimal): {}", salt);
            println!("Salt (hex 32B): 0x{:064x}", U256::from(salt));
            println!("Elapsed: {:.3}s", elapsed);
            println!("Total checked: {} ({:.1}M)", total_checked,
                total_checked as f64 / 1_000_000.0);
            println!("Throughput: {:.1}M hashes/sec",
                total_checked as f64 / elapsed / 1_000_000.0);

            // CPU verification
            let mut preimage = [0u8; 85];
            preimage.copy_from_slice(&block_template[..85]);
            preimage[45..53].copy_from_slice(&salt.to_be_bytes());
            let verify_hash = keccak256(&preimage);
            let verify_addr = &verify_hash[12..32];
            if verify_addr == &addr[..] {
                println!("CPU cross-verification: PASSED");
            } else {
                println!("CPU cross-verification: FAILED!");
                println!("  CPU addr: 0x{}", hex::encode(verify_addr));
                println!("  GPU addr: 0x{}", hex::encode(addr));
            }
            break;
        }

        // Progress
        if total_checked % (batch_size * 50) == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = total_checked as f64 / elapsed / 1_000_000.0;
            eprintln!(
                "GPU: checked ~{}M salts ({:.1}s, {:.1}M/s)",
                total_checked / 1_000_000,
                elapsed,
                rate,
            );
        }

        current_salt += batch_size;
    }
}
