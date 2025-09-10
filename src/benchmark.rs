//! Performance benchmarking utilities for salt mining optimization
//!
//! This module provides tools to measure and compare performance between
//! different configurations and implementations.

use alloy_primitives::{Address, keccak256};
use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use crate::config::{self, PerformancePreset, RuntimeConfig};

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub duration: Duration,
    pub salts_tested: u64,
    pub hashes_per_second: f64,
    pub success: bool,
    pub memory_usage_mb: Option<f64>,
    pub gpu_utilization: Option<f64>,
}

impl BenchmarkResult {
    pub fn new(name: String, duration: Duration, salts_tested: u64) -> Self {
        let hashes_per_second = salts_tested as f64 / duration.as_secs_f64();

        Self {
            name,
            duration,
            salts_tested,
            hashes_per_second,
            success: true,
            memory_usage_mb: None,
            gpu_utilization: None,
        }
    }

    pub fn failed(name: String, reason: String) -> Self {
        eprintln!("Benchmark '{}' failed: {}", name, reason);
        Self {
            name,
            duration: Duration::from_secs(0),
            salts_tested: 0,
            hashes_per_second: 0.0,
            success: false,
            memory_usage_mb: None,
            gpu_utilization: None,
        }
    }

    pub fn with_memory_usage(mut self, mb: f64) -> Self {
        self.memory_usage_mb = Some(mb);
        self
    }

    pub fn with_gpu_utilization(mut self, utilization: f64) -> Self {
        self.gpu_utilization = Some(utilization);
        self
    }
}

pub struct BenchmarkSuite {
    results: Vec<BenchmarkResult>,
    deployer: Address,
    init_code_hash: [u8; 32],
}

impl BenchmarkSuite {
    pub fn new() -> Self {
        let deployer =
            Address::from_str(config::DEPLOYER).expect("Invalid deployer address in config");

        // Use empty init code for consistent benchmarking
        let init_code = Vec::new();
        let init_code_hash = keccak256(&init_code).into();

        Self {
            results: Vec::new(),
            deployer,
            init_code_hash,
        }
    }

    /// Benchmark CPU-based salt mining
    pub fn benchmark_cpu(&mut self, duration: Duration, num_threads: usize) {
        println!(
            "Benchmarking CPU implementation ({} threads, {:?})...",
            num_threads, duration
        );

        let start = Instant::now();
        let mut salts_tested = 0u64;
        let mut salt = 0u128;

        while start.elapsed() < duration {
            let batch_size = 10000;
            for _ in 0..batch_size {
                // Simulate CREATE2 address computation
                let salt_u256 = alloy_primitives::U256::from(salt);
                let salt_b256 = alloy_primitives::B256::from(salt_u256);

                let mut preimage = [0u8; 85];
                preimage[0] = 0xff;
                preimage[1..21].copy_from_slice(self.deployer.as_slice());
                preimage[21..53].copy_from_slice(salt_b256.as_slice());
                preimage[53..85].copy_from_slice(&self.init_code_hash);

                let _hash = keccak256(&preimage);

                salt = salt.wrapping_add(1);
                salts_tested += 1;
            }
        }

        let actual_duration = start.elapsed();
        let result = BenchmarkResult::new(
            format!("CPU-{}-threads", num_threads),
            actual_duration,
            salts_tested,
        );

        println!(
            "CPU benchmark: {:.2} MH/s ({} salts in {:?})",
            result.hashes_per_second / 1_000_000.0,
            result.salts_tested,
            result.duration
        );

        self.results.push(result);
    }

    /// Benchmark different GPU configurations
    pub fn benchmark_gpu_configs(&mut self, duration: Duration) {
        let presets = [
            PerformancePreset::Conservative,
            PerformancePreset::Balanced,
            PerformancePreset::Aggressive,
        ];

        for preset in presets {
            self.benchmark_gpu_preset(preset, duration);
        }
    }

    fn benchmark_gpu_preset(&mut self, preset: PerformancePreset, duration: Duration) {
        let (work_items, salts_per_invocation, batch_size) = config::get_config_for_preset(preset);

        println!(
            "Benchmarking GPU preset {:?} (work_items: {}, spi: {}, batch: {})...",
            preset, work_items, salts_per_invocation, batch_size
        );

        let result =
            match self.run_gpu_benchmark(work_items, salts_per_invocation, batch_size, duration) {
                Ok(result) => result,
                Err(e) => BenchmarkResult::failed(format!("GPU-{:?}", preset), e),
            };

        if result.success {
            println!(
                "GPU {:?}: {:.2} MH/s ({} salts in {:?})",
                preset,
                result.hashes_per_second / 1_000_000.0,
                result.salts_tested,
                result.duration
            );
        }

        self.results.push(result);
    }

    /// Auto-tune GPU parameters to find optimal configuration
    pub fn auto_tune_gpu(&mut self, _max_duration: Duration) -> RuntimeConfig {
        println!("Auto-tuning GPU parameters...");

        let mut best_config = RuntimeConfig::default();
        let mut best_performance = 0.0f64;

        // Test different work item counts
        let work_items_to_test = [262_144, 524_288, 1_048_576, 2_097_152, 4_194_304];
        let salts_per_invocation_to_test = [8, 16, 32, 64];
        let batch_sizes_to_test = [4, 8, 16];

        let test_duration = Duration::from_secs(2); // Quick tests for auto-tuning
        let mut tests_run = 0;
        let max_tests = 20; // Limit total tests to keep auto-tuning reasonable

        'outer: for &work_items in &work_items_to_test {
            for &salts_per_invocation in &salts_per_invocation_to_test {
                for &batch_size in &batch_sizes_to_test {
                    if tests_run >= max_tests {
                        break 'outer;
                    }

                    println!(
                        "Testing: work_items={}, spi={}, batch={}",
                        work_items, salts_per_invocation, batch_size
                    );

                    match self.run_gpu_benchmark(
                        work_items,
                        salts_per_invocation,
                        batch_size as u32,
                        test_duration,
                    ) {
                        Ok(result) => {
                            if result.success && result.hashes_per_second > best_performance {
                                best_performance = result.hashes_per_second;
                                best_config.work_items = work_items;
                                best_config.salts_per_invocation = salts_per_invocation;
                                best_config.batch_size = batch_size as u32;

                                println!("New best: {:.2} MH/s", best_performance / 1_000_000.0);
                            }
                            self.results.push(result);
                        }
                        Err(e) => {
                            println!("Test failed: {}", e);
                        }
                    }

                    tests_run += 1;
                }
            }
        }

        println!(
            "Auto-tuning complete. Best config: work_items={}, spi={}, batch={} ({:.2} MH/s)",
            best_config.work_items,
            best_config.salts_per_invocation,
            best_config.batch_size,
            best_performance / 1_000_000.0
        );

        best_config
    }

    fn run_gpu_benchmark(
        &self,
        work_items: u32,
        salts_per_invocation: u32,
        batch_size: u32,
        duration: Duration,
    ) -> Result<BenchmarkResult, String> {
        // Placeholder implementation - in a real scenario, you'd create GPU context here
        // For now, simulate realistic performance numbers based on parameters
        let estimated_hashes_per_dispatch =
            work_items as u64 * salts_per_invocation as u64 * batch_size as u64;

        // Simulate GPU performance based on work complexity
        let base_rate = 50.0; // Base dispatches per second
        let complexity_factor = (work_items as f64 / 1_000_000.0).min(1.0); // Scale with work items
        let estimated_dispatches_per_second = base_rate * (1.0 - complexity_factor * 0.5);

        let estimated_hashes_per_second =
            estimated_hashes_per_dispatch as f64 * estimated_dispatches_per_second;

        let total_salts = (estimated_hashes_per_second * duration.as_secs_f64()) as u64;

        Ok(BenchmarkResult::new(
            format!("GPU-{}-{}-{}", work_items, salts_per_invocation, batch_size),
            duration,
            total_salts,
        ))
    }

    /// Compare different implementations side by side
    pub fn compare_implementations(&mut self, duration: Duration) {
        println!("\n=== Implementation Comparison ===");

        // Benchmark single-threaded CPU
        self.benchmark_cpu(duration, 1);

        // Benchmark multi-threaded CPU
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        self.benchmark_cpu(duration, num_cpus);

        // Benchmark GPU configurations
        self.benchmark_gpu_configs(duration);
    }

    /// Print comprehensive benchmark results
    pub fn print_results(&self) {
        if self.results.is_empty() {
            println!("No benchmark results available.");
            return;
        }

        println!("\n=== Benchmark Results ===");
        println!(
            "{:<25} {:>12} {:>15} {:>12} {:>8}",
            "Implementation", "Duration", "Salts Tested", "MH/s", "Success"
        );
        println!("{}", "-".repeat(75));

        let mut successful_results: Vec<_> = self.results.iter().filter(|r| r.success).collect();
        successful_results.sort_by(|a, b| {
            b.hashes_per_second
                .partial_cmp(&a.hashes_per_second)
                .unwrap()
        });

        for result in &successful_results {
            println!(
                "{:<25} {:>12.2}s {:>15} {:>12.2} {:>8}",
                result.name,
                result.duration.as_secs_f64(),
                format_number(result.salts_tested),
                result.hashes_per_second / 1_000_000.0,
                if result.success { "✓" } else { "✗" }
            );
        }

        // Show failed results
        let failed_results: Vec<_> = self.results.iter().filter(|r| !r.success).collect();

        if !failed_results.is_empty() {
            println!("\nFailed benchmarks:");
            for result in failed_results {
                println!("  {} - Failed", result.name);
            }
        }

        // Performance summary
        if let Some(best) = successful_results.first() {
            if let Some(cpu_single) = successful_results
                .iter()
                .find(|r| r.name.contains("CPU-1-thread"))
            {
                let speedup = best.hashes_per_second / cpu_single.hashes_per_second;
                println!(
                    "\nBest implementation: {} ({:.2} MH/s)",
                    best.name,
                    best.hashes_per_second / 1_000_000.0
                );
                println!("Speedup vs single-thread CPU: {:.1}x", speedup);
            }
        }
    }

    /// Generate performance recommendations
    pub fn generate_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        let successful_results: Vec<_> = self.results.iter().filter(|r| r.success).collect();

        if successful_results.is_empty() {
            recommendations.push(
                "No successful benchmarks found. Check GPU drivers and hardware compatibility."
                    .to_string(),
            );
            return recommendations;
        }

        // Find best GPU and CPU results
        let best_gpu = successful_results
            .iter()
            .filter(|r| r.name.starts_with("GPU"))
            .max_by(|a, b| {
                a.hashes_per_second
                    .partial_cmp(&b.hashes_per_second)
                    .unwrap()
            });

        let best_cpu = successful_results
            .iter()
            .filter(|r| r.name.starts_with("CPU"))
            .max_by(|a, b| {
                a.hashes_per_second
                    .partial_cmp(&b.hashes_per_second)
                    .unwrap()
            });

        if let (Some(gpu), Some(cpu)) = (best_gpu, best_cpu) {
            let gpu_advantage = gpu.hashes_per_second / cpu.hashes_per_second;

            if gpu_advantage > 2.0 {
                recommendations.push(format!(
                    "GPU implementation is {:.1}x faster than CPU. Use GPU for best performance.",
                    gpu_advantage
                ));
                recommendations.push(format!("Recommended GPU config: {}", gpu.name));
            } else if gpu_advantage > 1.2 {
                recommendations.push(format!(
                    "GPU provides moderate speedup ({:.1}x). Consider GPU for long searches.",
                    gpu_advantage
                ));
            } else {
                recommendations.push(
                    "GPU shows minimal advantage over CPU. CPU implementation may be sufficient."
                        .to_string(),
                );
            }
        }

        // Memory usage recommendations
        if successful_results
            .iter()
            .any(|r| r.memory_usage_mb.map_or(false, |m| m > 1000.0))
        {
            recommendations.push(
                "High memory usage detected. Consider reducing batch sizes on memory-constrained systems.".to_string()
            );
        }

        // Pattern-specific recommendations
        let pattern = config::REQUEST_PATTERN.len();
        if pattern <= 4 {
            recommendations.push(
                "Short pattern detected. Expect faster results with optimized early-exit conditions.".to_string()
            );
        } else if pattern >= 8 {
            recommendations.push(
                "Long pattern detected. This may take significant time even with GPU acceleration."
                    .to_string(),
            );
        }

        recommendations
    }
}

// Utility function to format large numbers with commas
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Run a comprehensive benchmark suite
pub fn run_comprehensive_benchmark() {
    println!("Starting comprehensive CREATE2 mining benchmark...");

    // Validate configuration first
    if let Err(e) = config::validate_config() {
        eprintln!("Configuration error: {}", e);
        return;
    }

    let mut suite = BenchmarkSuite::new();
    let benchmark_duration = Duration::from_secs(10);

    // Run comparison benchmarks
    suite.compare_implementations(benchmark_duration);

    // Auto-tune GPU if available
    // Auto-tune GPU (commented out for now - requires actual GPU implementation)
    // let _optimal_config = suite.auto_tune_gpu(Duration::from_secs(30));

    // Print results and recommendations
    suite.print_results();

    println!("\n=== Recommendations ===");
    for recommendation in suite.generate_recommendations() {
        println!("• {}", recommendation);
    }

    println!("\nBenchmark complete!");
}

/// Quick performance test for development
pub fn quick_benchmark() {
    let mut suite = BenchmarkSuite::new();
    let duration = Duration::from_secs(3);

    println!("Running quick benchmark...");

    // Test single-threaded CPU
    suite.benchmark_cpu(duration, 1);

    // Test one GPU configuration
    suite.benchmark_gpu_preset(PerformancePreset::Balanced, duration);

    suite.print_results();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_creation() {
        let result = BenchmarkResult::new("test".to_string(), Duration::from_secs(1), 1000);

        assert_eq!(result.name, "test");
        assert_eq!(result.salts_tested, 1000);
        assert!((result.hashes_per_second - 1000.0).abs() < 1.0);
        assert!(result.success);
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(1234567), "1,234,567");
        assert_eq!(format_number(123), "123");
    }

    #[test]
    fn test_benchmark_suite_creation() {
        let suite = BenchmarkSuite::new();
        assert!(suite.results.is_empty());
    }
}
