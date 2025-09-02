use alloy_primitives::{keccak256, Address, B256, U256};
use std::{
    fs,
    path::Path,
    str::FromStr,
    sync::{mpsc, Arc},
    thread,
    time::Instant,
};

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
                        i, j, j, hex::encode(addr)
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