// src/config.rs

/// Canonical CREATE2 deployer (Solmate/0xCE... factory-bytes style).
pub const DEPLOYER: &str = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/// Path to a file that contains the creation/init code as hex text (no need for 0x).
/// Any non-hex chars are ignored so comments/whitespace are fine.
pub const CREATION_CODE_PATH: &str = "sample/creation_code.hex";

/// How to interpret `REQUEST_PATTERN`.
#[derive(Clone, Copy, Debug)]
pub enum MatchMode {
    /// Address must start with `REQUEST_PATTERN` (after stripping optional 0x).
    Prefix,
    /// Address must end with `REQUEST_PATTERN`.
    Suffix,
    /// Address must contain `REQUEST_PATTERN` somewhere inside.
    Contains,
    /// Full 40-nibble mask with '.' wildcards, e.g.
    /// "00007702................................" (exact positions).
    Mask,
    /// Exact 40-nibble address (no wildcards).
    Exact,
}

/**
pub const MATCH_MODE: MatchMode = MatchMode::Prefix;
pub const REQUEST_PATTERN: &str = "0x00007702";

pub const MATCH_MODE: MatchMode = MatchMode::Contains;
pub const REQUEST_PATTERN: &str = "0x00007702";

pub const MATCH_MODE: MatchMode = MatchMode::Suffix;
pub const REQUEST_PATTERN: &str = "0x00007702";

pub const MATCH_MODE: MatchMode = MatchMode::Mask;
pub const REQUEST_PATTERN: &str = "0x00007702................................";

pub const MATCH_MODE: MatchMode = MatchMode::Exact;
pub const REQUEST_PATTERN: &str = "0x00007702abcd0000000000000000000000000000";
*/
/// Set the matching mode here.
pub const MATCH_MODE: MatchMode = MatchMode::Prefix;

/// The requested pattern:
/// - For Prefix/Suffix/Contains/Exact: put the hex you care about, e.g. "0x00007702"
///   (Exact requires full 40 nibbles).
/// - For Mask: provide a 40-char mask using [0-9a-f] and '.' wildcards,
///   e.g. "0x00007702................................"
pub const REQUEST_PATTERN: &str = "0xcafecafe";

/// Optional: set how many threads to use (None = use all logical CPUs).
pub const THREAD_OVERRIDE: Option<usize> = None;

/// GPU tuning (None = auto-tune based on adapter limits).
/// - GPU_WORK_ITEMS_OVERRIDE: total invocations per dispatch (workgroups * workgroup_size),
///   e.g. 1_048_576. If None, the program will auto-tune based on adapter limits.
/// - GPU_SALTS_PER_INVOCATION_OVERRIDE: how many salts each thread tests in-shader (1, 8, 16, 32...).
///   If None, the program will auto-tune a small integer based on device limits.
/// - GPU_BATCH_DISPATCHES_OVERRIDE: number of dispatches to issue before mapping results.
///   Higher values reduce CPU-GPU sync overhead (trade latency for throughput).
pub const GPU_WORK_ITEMS_OVERRIDE: Option<u32> = None;
pub const GPU_SALTS_PER_INVOCATION_OVERRIDE: Option<u32> = None;
pub const GPU_BATCH_DISPATCHES_OVERRIDE: Option<u32> = None;

/// Progress log interval per thread (every N salts checked).
pub const PROGRESS_EVERY: u64 = 50_000;

/// Global starting salt (offset) for the scan.
/// Accepts decimal: "0", "123456789"
/// or hex: "0x0000000000000000deadbeef"
/*
pub const START_SALT: &str = "4345600000";           // decimal
// or
pub const START_SALT: &str = "0x0000000103a1b2c3";   // hex (up to u128)
*/
pub const START_SALT: &str = "0";
