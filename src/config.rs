//! Optimized performance configuration for CREATE2 salt mining
//! Tune these values for your specific GPU and workload

use std::str::FromStr;

// Basic mining configuration
pub const DEPLOYER: &str = "0x4e59b44847b379578588920cA78FbF26c0B4956C"; // CREATE2 deployer
pub const CREATION_CODE_PATH: &str = "src/sample/creation_code.hex"; // Path to bytecode file
pub const REQUEST_PATTERN: &str = "00cafecafe"; // Pattern to search for
pub const START_SALT: &str = "0"; // Starting salt value

// Match mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MatchMode {
    Prefix,   // Match at the beginning
    Suffix,   // Match at the end
    Contains, // Match anywhere
    Mask,     // Use '.' wildcards
    Exact,    // Exact 40-character match
}

pub const MATCH_MODE: MatchMode = MatchMode::Prefix;

// CPU fallback settings
pub const THREAD_OVERRIDE: Option<usize> = None; // None = auto-detect
pub const PROGRESS_EVERY: u64 = 1_000_000; // Report progress every N salts

// GPU vs CPU optimization
pub const USE_SINGLE_CPU_THREAD_WITH_GPU: bool = true; // Use only 1 CPU thread when GPU is available

// GPU optimization settings
pub const GPU_WORK_ITEMS_OVERRIDE: Option<u32> = Some(524_288); // 512K work items (better for Apple GPUs)
pub const GPU_SALTS_PER_INVOCATION_OVERRIDE: Option<u32> = Some(8); // Fewer salts per thread (reduces register pressure)
pub const GPU_BATCH_DISPATCHES_OVERRIDE: Option<u32> = Some(4); // Smaller batch sizes (reduces driver overhead)
pub const GPU_WORKGROUP_SIZE_OVERRIDE: Option<u32> = Some(256); // Optimal for most GPUs

// Advanced GPU tuning parameters
pub const GPU_ENABLE_ASYNC_COMPUTE: bool = true; // Use async compute queues if available
pub const GPU_ENABLE_PERSISTENT_MAPPING: bool = true; // Keep buffers mapped for performance
pub const GPU_PREFER_INTEGRATED: bool = false; // Prefer discrete GPU over integrated

// Memory optimization
pub const GPU_STAGING_BUFFER_SIZE_MB: usize = 64; // Staging buffer size in MB
pub const GPU_MAX_CONCURRENT_DISPATCHES: usize = 4; // Limit concurrent dispatches

// Performance monitoring
pub const ENABLE_PERFORMANCE_COUNTERS: bool = true; // Enable detailed performance metrics
pub const PROGRESS_REPORT_INTERVAL_SEC: f64 = 2.0; // Report progress every N seconds

// Auto-tuning parameters
pub const AUTO_TUNE_WORK_ITEMS: bool = true; // Automatically tune work items based on GPU
pub const AUTO_TUNE_BATCH_SIZE: bool = true; // Automatically tune batch size
pub const BENCHMARK_DURATION_SEC: f64 = 5.0; // Duration for auto-tuning benchmark

// Validation settings
pub const VERIFY_GPU_RESULTS: bool = true; // Double-check GPU results on CPU
pub const EARLY_EXIT_ON_MATCH: bool = true; // Exit immediately when match found

// GPU-specific optimizations
pub struct GpuConfig {
    pub max_compute_units: Option<u32>,
    pub memory_bandwidth_gb_s: Option<f32>,
    pub l2_cache_size_mb: Option<u32>,
    pub preferred_workgroup_size: Option<u32>,
}

impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            max_compute_units: None,
            memory_bandwidth_gb_s: None,
            l2_cache_size_mb: None,
            preferred_workgroup_size: Some(256),
        }
    }
}

// GPU vendor-specific optimizations
#[derive(Debug, Clone, Copy)]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Apple,
    Unknown,
}

pub fn get_optimal_config_for_vendor(vendor: GpuVendor) -> GpuConfig {
    match vendor {
        GpuVendor::Nvidia => GpuConfig {
            max_compute_units: None, // Will be auto-detected
            memory_bandwidth_gb_s: None,
            l2_cache_size_mb: None,
            preferred_workgroup_size: Some(256), // NVIDIA GPUs typically prefer 256
        },
        GpuVendor::Amd => GpuConfig {
            max_compute_units: None,
            memory_bandwidth_gb_s: None,
            l2_cache_size_mb: None,
            preferred_workgroup_size: Some(256), // AMD RDNA also works well with 256
        },
        GpuVendor::Intel => GpuConfig {
            max_compute_units: None,
            memory_bandwidth_gb_s: None,
            l2_cache_size_mb: None,
            preferred_workgroup_size: Some(128), // Intel Arc prefers smaller workgroups
        },
        GpuVendor::Apple => GpuConfig {
            max_compute_units: None,
            memory_bandwidth_gb_s: None,
            l2_cache_size_mb: None,
            preferred_workgroup_size: Some(256), // Apple Silicon handles 256 well
        },
        GpuVendor::Unknown => GpuConfig::default(),
    }
}

// Performance presets
#[derive(Debug, Clone, Copy)]
pub enum PerformancePreset {
    Conservative, // Safe settings that work on most hardware
    Balanced,     // Good balance of performance and compatibility
    Aggressive,   // Maximum performance, may not work on all GPUs
}

pub fn get_config_for_preset(preset: PerformancePreset) -> (u32, u32, u32) {
    // Returns (work_items, salts_per_invocation, batch_size)
    match preset {
        PerformancePreset::Conservative => (524_288, 8, 4), // 512K, 8, 4
        PerformancePreset::Balanced => (1_048_576, 16, 8),  // 1M, 16, 8
        PerformancePreset::Aggressive => (4_194_304, 64, 16), // 4M, 64, 16
    }
}

// Runtime configuration that can be modified
pub struct RuntimeConfig {
    pub current_preset: PerformancePreset,
    pub work_items: u32,
    pub salts_per_invocation: u32,
    pub batch_size: u32,
    pub enable_auto_tuning: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        let preset = PerformancePreset::Balanced;
        let (work_items, salts_per_invocation, batch_size) = get_config_for_preset(preset);

        Self {
            current_preset: preset,
            work_items,
            salts_per_invocation,
            batch_size,
            enable_auto_tuning: AUTO_TUNE_WORK_ITEMS,
        }
    }
}

// Helper functions for configuration validation
pub fn validate_config() -> Result<(), String> {
    // Validate deployer address
    if alloy_primitives::Address::from_str(DEPLOYER).is_err() {
        return Err("Invalid DEPLOYER address".to_string());
    }

    // Validate pattern
    let pattern = REQUEST_PATTERN.trim().to_lowercase();
    let pattern = pattern.strip_prefix("0x").unwrap_or(&pattern);

    if pattern.is_empty() || pattern.len() > 40 {
        return Err("Pattern length must be 1-40 characters".to_string());
    }

    let valid_chars = pattern.chars().all(|c| c.is_ascii_hexdigit() || c == '.');
    if !valid_chars {
        return Err("Pattern contains invalid characters".to_string());
    }

    // Validate GPU settings
    if let Some(work_items) = GPU_WORK_ITEMS_OVERRIDE {
        if work_items == 0 || work_items > 16_777_216 {
            return Err("work_items must be between 1 and 16M".to_string());
        }
    }

    if let Some(salts_per_invocation) = GPU_SALTS_PER_INVOCATION_OVERRIDE {
        if salts_per_invocation == 0 || salts_per_invocation > 1024 {
            return Err("salts_per_invocation must be between 1 and 1024".to_string());
        }
    }

    Ok(())
}

// Performance estimation
pub fn estimate_performance(
    work_items: u32,
    salts_per_invocation: u32,
    batch_size: u32,
    gpu_compute_units: u32,
    gpu_clock_mhz: u32,
) -> f64 {
    // Very rough estimate of hashes per second
    let total_threads = work_items;
    let hashes_per_dispatch =
        total_threads as u64 * salts_per_invocation as u64 * batch_size as u64;

    // Assume each hash takes roughly 1000 GPU cycles (very rough estimate)
    let cycles_per_hash = 1000.0;
    let gpu_cycles_per_second = gpu_compute_units as f64 * gpu_clock_mhz as f64 * 1_000_000.0;
    let estimated_dispatches_per_second =
        gpu_cycles_per_second / (hashes_per_dispatch as f64 * cycles_per_hash);

    hashes_per_dispatch as f64 * estimated_dispatches_per_second
}
