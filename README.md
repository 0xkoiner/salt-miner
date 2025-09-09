```bash
         xxx          -*~*-             ===           +++        `  ___  '        _/7
        (o o)         (o o)            (o o)         (o o)      -  (O o)  -      (o o)
    ooO--(_)--Ooo-ooO--(_)--Ooo----ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo-

                                                    
                                                        
                        ▗▄▄▖ ▄   ▄      ▄▀▀▚▖▄   ▄ ▗▖ ▗▖ ▄▄▄  ▄ ▄▄▄▄  ▗▞▀▚▖ ▄▄▄ 
                        ▐▌ ▐▌█   █      █  ▐▌ ▀▄▀  ▐▌▗▞▘█   █ ▄ █   █ ▐▛▀▀▘█    
                        ▐▛▀▚▖ ▀▀▀█      █  ▐▌▄▀ ▀▄ ▐▛▚▖ ▀▄▄▄▀ █ █   █ ▝▚▄▄▖█    
                        ▐▙▄▞▘ ▄  █      ▀▄▄▞▘      ▐▌ ▐▌      █                 
                              ▀▀▀                                            


         xxx          -*~*-             ===           +++        `  ___  '        _/7
        (o o)         (o o)            (o o)         (o o)      -  (O o)  -      (o o)
    ooO--(_)--Ooo-ooO--(_)--Ooo----ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo-
```

<h1 align="center"> Salt Miner (CREATE2 Vanity Address) </h1>

Small, fast Rust tool to brute-force a salt for CREATE2 so your deployed contract address matches a vanity prefix/suffix/contains/mask/exact pattern.
Optimized for big init code (hashes keccak(init_code) once), multi-threaded, and supports resuming from an arbitrary global salt offset.

### Why this exists
For the canonical CREATE2 deployer (e.g. 0x4e59b4…956C) the deployed address is:
```rust
addr = keccak256(0xff ++ DEPLOYER ++ SALT ++ keccak256(INIT_CODE))[12..32]
```
If you know the exact INIT_CODE (creation code + ABI-encoded constructor args), you can search SALT until the address matches your desired pattern.


### Features
	•	Pattern modes: Prefix / Suffix / Contains / Mask (40-nibble with . wildcards) / Exact.
	•	Resume from salt: start from any global salt (START_SALT) to resume long scans.
	•	Multi-threaded: each thread walks a disjoint arithmetic progression (start + i, step = num_threads).
	•	Large init code friendly: precomputes keccak256(init_code) once; per-candidate work is a single 85-byte Keccak.
	•	Clean output: prints the init code hash, starting salt (dec & hex32), and progress per thread.

### Requirements
	•	Rust (stable)
	•	forge / cast (Foundry) for building the contract and encoding constructor args.

#### Contract Deployed wit Salt-Miner: 
***pub const REQUEST_PATTERN: &str = "0x0000fee";***
<br></br>
0x0000FEeaB9F73EAa49583aC15357a8673098D971

***pub const REQUEST_PATTERN: &str = "0x0000256";***
<br></br>

0x0000256A4eB4642E668CD371aeDE4b004295ad65

### Install & Run
```bash
# build
cargo build --release

# run
cargo run --release
```

### Project Layout
```bash
create2/
├─ Cargo.toml
└─ src/
   ├─ main.rs
   ├─ config.rs
   └─ creation_code.hex        # your INIT_CODE (creationCode + constructor args)
```

### Config (src/config.rs)
```
/// Canonical CREATE2 deployer (Solmate factory).
pub const DEPLOYER: &str = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/// Path to INIT_CODE hex file (no 0x; whitespace ok).
pub const CREATION_CODE_PATH: &str = "src/creation_code.hex";

#[derive(Clone, Copy, Debug)]
pub enum MatchMode { Prefix, Suffix, Contains, Mask, Exact }

/// Choose the matching strategy.
pub const MATCH_MODE: MatchMode = MatchMode::Prefix;

/// Pattern:
///  - Prefix/Suffix/Contains/Exact: hex like "0x00007702" (Exact requires 40 nibbles)
///  - Mask (40 chars): '.' are wildcards: "0x00007702................................"
pub const REQUEST_PATTERN: &str = "0x00007702";

/// Threads (None = all logical CPUs).
pub const THREAD_OVERRIDE: Option<usize> = None;

/// Log every N salts per thread.
pub const PROGRESS_EVERY: u64 = 50_000;

/// Global starting salt (decimal or 0x-hex) to support resume.
pub const START_SALT: &str = "0";
```

#### Examples
Prefix 0xba5efee… (nice for “base fee”):
```rust
pub const MATCH_MODE: MatchMode = MatchMode::Prefix;
pub const REQUEST_PATTERN: &str = "0xba5efee";
```

Suffix …00007702:
```rust
pub const MATCH_MODE: MatchMode = MatchMode::Suffix;
pub const REQUEST_PATTERN: &str = "0x00007702";
```

Contains …4337fee…:
```rust
pub const MATCH_MODE: MatchMode = MatchMode::Contains;
pub const REQUEST_PATTERN: &str = "0x4337fee";
```

Mask (exact positions; 40 nibbles, . wildcards):
```rust
pub const MATCH_MODE: MatchMode = MatchMode::Mask;
pub const REQUEST_PATTERN: &str = "0x00007702................................";
```

Exact (full 20-byte address, no wildcards):
```rust
pub const MATCH_MODE: MatchMode = MatchMode::Exact;
pub const REQUEST_PATTERN: &str = "0x00007702abcd0000000000000000000000000000";
```

### Resume from a specific salt
```rust
pub const START_SALT: &str = "4363250000"; // decimal
// or "0x000000000000000000000000000000000000000000000000000000010411e950"
```
The miner seeds each thread at START_SALT + thread_index and advances by num_threads.

Resuming math
If on a prior run (with the same num_threads) you saw:
```rust
thread X: checked ~N salts
```
then the next global starting salt is:
```rust
new START_SALT = old START_SALT + (N * num_threads)
```

(Use the smallest N printed across threads to avoid gaps.)

Keep num_threads the same when resuming for perfectly disjoint coverage.

### Performance notes
	•	Expected trials for an n-nibble prefix is 16ⁿ:
	•	6 nibbles ≈ 16,777,216
	•	7 nibbles ≈ 268,435,456
	•	8 nibbles ≈ 4,294,967,296
	•	Throughput scales with cores; the hot path is a single 85-byte Keccak per candidate.
	•	Init code size doesn’t matter per-iteration (we hash it once), only at startup.

### Verifying the result
When a hit is found the tool prints:
```bash
Vanity address: 0x...
Salt (decimal): N
Salt (hex 32B): 0x...
```

You can recompute independently:
```rust
// Pseudocode
addr = keccak256(0xff || deployer || salt || keccak256(init_code))[12..32]
```

Or with a quick script (Rust/JS/Foundry) using the same formula.


### Troubleshooting
	•	I got the wrong address.
99% of the time it’s the wrong bytes: you mined with runtime code instead of INIT_CODE, forgot to append constructor args, changed solc/optimizer/via-ir, or missed library linking.
	•	Large init code is slow.
The miner prehashes init code once; if you see slowness, you’re likely passing a non-hex file (placeholders) or not running --release.
	•	Progress looks like it starts from zero.
The thread i: checked ~N salts lines are per-thread counters. The absolute salt is START_SALT + i + N * num_threads.