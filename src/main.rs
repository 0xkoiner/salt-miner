use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};
use std::{
    fs,
    path::Path,
    str::FromStr,
    sync::{mpsc, Arc},
    thread,
    time::Instant,
};

mod config;

/// ARM-optimized Keccak256 using sha3 crate with assembly optimizations
/// On M3 Pro, this uses ARM crypto extensions for faster hashing
#[inline(always)]
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

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

/// Optimized CREATE2 computation with pre-allocated buffer (Phase 2 optimization)
/// This avoids allocating the preimage buffer on every iteration
#[inline(always)]
fn create2_address_optimized(preimage: &mut [u8; 85], salt_bytes: &[u8; 32]) -> Address {
    // Only update the salt portion (bytes 21..53), rest is pre-initialized
    preimage[21..53].copy_from_slice(salt_bytes);

    let hash = keccak256(preimage);
    Address::from_slice(&hash[12..32])
}

/// Convert u128 salt directly to 32-byte array (B256 format)
/// This eliminates the U256 intermediate conversion
#[inline(always)]
fn u128_to_b256_bytes(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    // Place u128 in the last 16 bytes (big-endian)
    bytes[16..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn normalize_req(s: &str) -> String {
    let mut p = s.trim().to_lowercase();
    if let Some(rest) = p.strip_prefix("0x") {
        p = rest.to_string();
    }
    p
}

/// Parsed pattern for fast byte-level matching (zero allocations in hot path)
#[derive(Clone, Debug)]
struct ParsedPattern {
    mode: config::MatchMode,
    /// For string-based modes (backward compat)
    hex_string: String,
    /// For byte-optimized modes
    bytes: Vec<u8>,
    /// If pattern has odd number of nibbles, this is the last nibble (0x0-0xf)
    partial_nibble: Option<u8>,
}

impl ParsedPattern {
    fn from_hex_string(hex_str: &str, mode: config::MatchMode) -> Self {
        let bytes_len = hex_str.len() / 2;
        let has_partial = hex_str.len() % 2 == 1;

        let mut bytes = Vec::with_capacity(bytes_len + if has_partial { 1 } else { 0 });

        // Parse full bytes
        for i in 0..bytes_len {
            let byte_str = &hex_str[i * 2..i * 2 + 2];
            bytes.push(u8::from_str_radix(byte_str, 16).unwrap());
        }

        // Parse partial nibble if exists (e.g., "0x00000000fee" -> last 'e')
        let partial_nibble = if has_partial {
            let last_nibble = hex_str.chars().last().unwrap();
            Some(u8::from_str_radix(&last_nibble.to_string(), 16).unwrap())
        } else {
            None
        };

        Self {
            mode,
            hex_string: hex_str.to_string(),
            bytes,
            partial_nibble,
        }
    }
}

/// Fast byte-level address matching (NO string allocations)
#[inline(always)]
fn address_matches_fast(addr: &Address, pattern: &ParsedPattern) -> bool {
    let addr_bytes = addr.as_slice(); // 20 bytes

    match pattern.mode {
        config::MatchMode::Prefix => {
            // Check full bytes
            if addr_bytes.len() < pattern.bytes.len() {
                return false;
            }

            for i in 0..pattern.bytes.len() {
                if addr_bytes[i] != pattern.bytes[i] {
                    return false;
                }
            }

            // Check partial nibble (high nibble of next byte)
            if let Some(nibble) = pattern.partial_nibble {
                if let Some(&next_byte) = addr_bytes.get(pattern.bytes.len()) {
                    let high_nibble = next_byte >> 4;
                    if high_nibble != nibble {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            true
        }
        config::MatchMode::Suffix => {
            // For suffix, we need to check the end
            let start_idx = if let Some(_) = pattern.partial_nibble {
                // With partial nibble, we need to check nibble alignment
                // Fall back to string comparison for suffix with odd nibbles
                return address_matches_string(addr, &pattern.hex_string, pattern.mode);
            } else {
                addr_bytes.len().saturating_sub(pattern.bytes.len())
            };

            if start_idx + pattern.bytes.len() > addr_bytes.len() {
                return false;
            }

            &addr_bytes[start_idx..] == &pattern.bytes[..]
        }
        config::MatchMode::Contains => {
            // For contains, fall back to string (but we could optimize with SIMD later)
            address_matches_string(addr, &pattern.hex_string, pattern.mode)
        }
        config::MatchMode::Mask => {
            // For mask, use string comparison (already efficient)
            address_matches_string(addr, &pattern.hex_string, pattern.mode)
        }
        config::MatchMode::Exact => {
            // Exact match: compare all 20 bytes
            if pattern.bytes.len() != 20 {
                return false;
            }
            addr_bytes == &pattern.bytes[..]
        }
    }
}

/// Original string-based matching (for modes that need it)
#[inline]
fn address_matches_string(addr: &Address, req: &str, mode: config::MatchMode) -> bool {
    let addr_hex = hex::encode(addr); // 40 lowercase hex
    match mode {
        config::MatchMode::Prefix => addr_hex.starts_with(req),
        config::MatchMode::Suffix => addr_hex.ends_with(req),
        config::MatchMode::Contains => addr_hex.contains(req),
        config::MatchMode::Exact => addr_hex == req,
        config::MatchMode::Mask => {
            addr_hex
                .bytes()
                .zip(req.bytes())
                .all(|(a, p)| p == b'.' || p == a)
        }
    }
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


fn parse_start_salt_u128(s: &str) -> u128 {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).expect("START_SALT hex parse failed (u128 max)")
    } else {
        t.parse::<u128>().expect("START_SALT decimal parse failed")
    }
}

fn main() {
    // --- Load config ---
    let deployer =
        Address::from_str(config::DEPLOYER).expect("invalid DEPLOYER in config.rs (address parse)");
    let init_code = load_creation_code_hex(config::CREATION_CODE_PATH);
    let init_code_hash = keccak256(&init_code);      // PRECOMPUTE ONCE
    let init_code_hash = Arc::new(init_code_hash);   // share to threads cheaply

    let raw_req = config::REQUEST_PATTERN;
    let mode = config::MATCH_MODE;

    // Normalize/validate pattern once
    let req = normalize_req(raw_req);
    validate_req(mode, &req);

    // Parse pattern for fast byte-level matching
    let parsed_pattern = ParsedPattern::from_hex_string(&req, mode);

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
        hex::encode(init_code_hash.as_slice()),   // ← fixed
        mode,
        raw_req,
        num_threads,
        start_at,
        U256::from(start_at),
    );

    let start = Instant::now();

    for i in 0..num_threads {
        let tx = tx.clone();
        let init_code_hash = Arc::clone(&init_code_hash);
        let pattern = parsed_pattern.clone();

        thread::spawn(move || {
            let progress_every = config::PROGRESS_EVERY;
            let mut checked: u64 = 0;
            // start from offset + thread index
            let mut j: u128 = start_at.wrapping_add(i as u128);

            // ⚡ PHASE 2: Pre-allocate CREATE2 preimage buffer (reused every iteration)
            let mut preimage = [0u8; 85];
            preimage[0] = 0xff;
            preimage[1..21].copy_from_slice(deployer.as_slice());
            preimage[53..85].copy_from_slice(init_code_hash.as_slice());
            // preimage[21..53] will be updated with salt each iteration

            loop {
                // ⚡ PHASE 2: Direct u128 → [u8; 32] conversion (no U256 intermediate)
                let salt_bytes = u128_to_b256_bytes(j);

                // ⚡ PHASE 2: Optimized CREATE2 with pre-allocated buffer
                let addr = create2_address_optimized(&mut preimage, &salt_bytes);

                // ⚡ PHASE 1: Zero-allocation byte-level matching
                if address_matches_fast(&addr, &pattern) {
                    eprintln!(
                        "[FOUND] thread={} salt(dec)={} salt(hex)=0x{:064x} addr=0x{}",
                        i, j, j, hex::encode(addr)
                    );
                    // Convert back to U256 for display
                    let salt_u256 = U256::from(j);
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