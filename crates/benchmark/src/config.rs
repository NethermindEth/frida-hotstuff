//! Configuration system for Frida and DeFrida benchmark experiments.
//!
//! This module provides a comprehensive configuration system that allows users to design
//! and customize benchmark experiments for both Frida and DeFrida protocols through YAML files.

use std::{fs, path::Path};

use frida_poc::winterfell::FriOptions;
use serde::{Deserialize, Serialize};

use crate::process::Benchmark;

/// Default configuration file name (relative to workspace root)
pub const CONFIG_FILE: &str = "benchmark_config.yaml";

/// Main configuration structure for the Frida and DeFrida benchmark suite.
///
/// This struct defines all parameters required to execute benchmarks of both
/// Frida and DeFrida across multiple dimensions: validator set sizes, data
/// matrix dimensions, and FRI cryptographic parameters.
///
/// # Configuration File Format
///
/// The configuration is loaded from a YAML file (`benchmark_config.yaml`) that
/// allows easy modification of benchmark parameters without recompiling.
///
/// # Benchmark Dimensions
///
/// The benchmark suite creates a Cartesian product of all configuration parameters:
/// - **Validator counts** × **Data sizes** × **FRI options** = Total test cases
/// - Example: 6 validator configs × 3 data sizes × 2 FRI configs = 36 test cases
///
/// # Performance Impact
///
/// Different combinations have varying computational requirements:
/// - **More validators**: Increased network complexity and consensus overhead
/// - **Larger data**: Higher memory usage and longer proof generation times
/// - **Different FRI params**: Trade-offs between proof size and computation time
///
/// # YAML Structure
///
/// ```yaml
/// num_of_validators: [3, 5, 10, 20, 50, 100]
/// data_sizes:
///   - height: 100
///     width: 100
/// fri_options:
///   - blowup_factor: 2
///     folding_factor: 2
///     max_remainder_degree: 1
/// output_files:
///   frida_benchmark: "results.txt"
///   defrida_benchmark: "defrida_results.txt"
/// ```
#[derive(Debug, Deserialize, Serialize)]
pub struct BenchmarkConfig {
    /// List of validator counts to test in the consensus protocol.
    ///
    /// Each value represents the number of validator nodes participating
    /// in the consensus protocol during benchmarking. Higher validator
    /// counts increase network complexity and communication overhead.
    ///
    pub num_of_validators: Vec<u32>,

    /// List of data matrix dimensions to benchmark.
    ///
    /// Each [`DataSize`] defines the height×width of data matrices used
    /// for FRI proof generation. Larger matrices require more memory
    /// and computation time but test scalability limits.
    pub data_sizes: Vec<DataSize>,

    /// List of FRI (Fast Reed-Solomon Interactive) parameter configurations.
    ///
    /// Each [`FriConfig`] defines cryptographic parameters that affect
    /// the trade-off between proof size, generation time, and verification time.
    /// Different configurations help identify optimal parameters for various use cases.
    pub fri_options: Vec<FriConfig>,

    /// File paths for benchmark output results.
    ///
    /// Specifies where benchmark results and performance metrics
    /// should be written for analysis.
    pub output_files: OutputFiles,
}

/// Data matrix dimensions for blob storage and FRI proof generation.
///
/// This struct defines the dimensions of a data matrix used to monitor and organize
/// blobs within the consensus protocol. The matrix structure allows efficient
/// organization and processing of blob data during benchmark operations.
///
/// # Matrix Structure
///
/// - **Each row represents a new blob** being processed
/// - **Width determines the data capacity per blob**
/// - **Height controls the total number of blobs that can be stored**
///
/// # Usage in Benchmarks
///
/// Different matrix sizes test various aspects of the system:
/// - **Small matrices** (e.g., 10×10): Quick tests, minimal memory usage
/// - **Medium matrices** (e.g., 100×100): Balanced performance testing
/// - **Large matrices** (e.g., 1000×1000): Stress testing, memory scalability
///
/// # Performance Impact
///
/// - **Larger height**: More blobs to process, increased memory usage
/// - **Larger width**: More data per blob, longer processing times
/// - **Total elements** (height × width): Affects FRI proof generation time
///
/// # YAML Configuration Example
///
/// ```yaml
/// data_sizes:
///   - height: 100    # 100 blobs (rows)
///     width: 50      # 50 data elements per blob
///   - height: 500    # 500 blobs (rows)  
///     width: 100     # 100 data elements per blob
/// ```
#[derive(Debug, Deserialize, Serialize)]
pub struct DataSize {
    /// Number of rows in the data matrix (number of blobs).
    ///
    /// Each row represents a new blob being processed in the system.
    /// Higher values allow testing with more blobs.
    pub height: usize,

    /// Number of columns in the data matrix (data elements per blob).
    ///
    /// Defines how much data each blob can contain. Larger widths
    /// allow more data per blob.
    pub width: usize,
}

/// Configuration for FRI (Fast Reed-Solomon Interactive) cryptographic parameters.
///
/// This struct defines the cryptographic parameters used in FRI proof generation,
/// which is a core component of the Frida consensus protocol. FRI is a cryptographic
/// protocol that enables efficient verification of Reed-Solomon codes through
/// interactive proofs.
///
/// # Parameter Trade-offs
///
/// These parameters control fundamental trade-offs in the cryptographic system:
/// - **Proof size** vs **Generation time** vs **Verification time**
/// - **Security level** vs **Performance**
/// - **Memory usage** vs **Computational efficiency**
///
/// # Parameter Relationships
///
/// The three parameters work together to define the FRI protocol behavior:
/// - `blowup_factor` affects the low-degree extension size
/// - `folding_factor` determines how much the polynomial degree is reduced per round
/// - `max_remainder_degree` sets the threshold for switching to direct verification
///
/// # Common Configurations
///
/// | Use Case | Blowup | Folding | Max Remainder | Trade-off |
/// |----------|--------|---------|---------------|-----------|
/// | Fast proof | 2 | 2 | 1 | Smaller proofs, faster generation |
/// | Secure | 8 | 2 | 1 | Larger proofs, higher security |
/// | Balanced | 4 | 4 | 2 | Moderate size and speed |
///
/// # YAML Configuration
///
/// ```yaml
/// fri_options:
///   - blowup_factor: 2           # Fast, smaller proofs
///     folding_factor: 2
///     max_remainder_degree: 1
///   - blowup_factor: 8           # More secure, larger proofs  
///     folding_factor: 2
///     max_remainder_degree: 1
/// ```
///
/// # Performance Impact
///
/// - **Higher blowup_factor**: Larger proofs but potentially better security
/// - **Higher folding_factor**: Fewer FRI rounds but larger per-round complexity
/// - **Higher max_remainder_degree**: Earlier termination but larger final proof
///
#[derive(Debug, Deserialize, Serialize)]
pub struct FriConfig {
    /// Low-Degree Extension (LDE) blowup factor.
    ///
    /// Controls the size of the low-degree extension used in the FRI protocol.
    /// A higher blowup factor increases the proof size but can provide better
    /// security guarantees and more efficient verification in some cases.
    ///
    /// Common values: `2`, `4`, `8`, `16`
    /// - `2`: Minimal overhead, fastest proof generation
    /// - `8`: Good security/performance balance  
    /// - `16`: Maximum security, larger proofs
    pub blowup_factor: usize,

    /// Polynomial degree reduction factor per FRI round.
    ///
    /// Determines how much the polynomial degree is reduced in each round
    /// of the FRI protocol. Higher values mean fewer rounds but more
    /// computation per round.
    ///
    /// Common values: `2`, `4`, `8`
    /// - `2`: More rounds, less computation per round
    /// - `4`: Balanced approach
    /// - `8`: Fewer rounds, more computation per round
    pub folding_factor: usize,

    /// Maximum polynomial degree before switching to direct verification.
    ///
    /// When the polynomial degree drops below this threshold, the FRI
    /// protocol switches from interactive reduction to direct verification
    /// of the remaining small polynomial.
    ///
    /// Common values: `1`, `2`, `4`
    /// - `1`: Minimize final proof component
    /// - `2`: Balanced termination
    /// - `4`: Earlier termination, larger final component
    pub max_remainder_degree: usize,
}

/// Configuration for benchmark result output file paths.
///
/// # YAML Configuration
///
/// ```yaml
/// output_files:
///   frida_benchmark: "results/frida-2024-01-15.txt"
///   defrida_benchmark: "results/defrida-2024-01-15.txt"
/// ```
///
/// # File Handling
///
/// - Files are created if they don't exist
/// - Existing files are **appended to**, allowing multiple benchmark runs
/// - Relative paths are resolved from the benchmark tool's working directory
///
#[derive(Debug, Deserialize, Serialize)]
pub struct OutputFiles {
    /// File path for Frida protocol benchmark results.
    ///
    /// Specifies where the Frida benchmark results should be written.
    pub frida_benchmark: String,

    /// File path for DeFrida protocol benchmark results.
    ///
    /// Specifies where the DeFrida benchmark results should be written.
    pub defrida_benchmark: String,
}

impl BenchmarkConfig {
    /// Load configuration from YAML file
    pub fn load() -> Self {
        let config_path = Path::new(CONFIG_FILE);
        if config_path.exists() {
            tracing::info!("Loading configuration from {:?}", config_path);
            let config_content =
                fs::read_to_string(&config_path).expect("Failed to read configuration file");
            serde_yml::from_str(&config_content).expect("Failed to parse configuration file")
        } else {
            panic!(
                "Configuration file {config_path:?} not found. Please create a benchmark_config.yaml file in the project root."
            )
        }
    }

    /// Create a Benchmark instance from this configuration
    pub fn to_benchmark(&self) -> Benchmark {
        let num_validators = self.num_of_validators.clone();

        let data_sizes = self
            .data_sizes
            .iter()
            .map(|ds| (ds.height, ds.width))
            .collect();

        let fri_options = self
            .fri_options
            .iter()
            .map(|fri| {
                FriOptions::new(
                    fri.blowup_factor,
                    fri.folding_factor,
                    fri.max_remainder_degree,
                )
            })
            .collect();

        Benchmark::new(&num_validators, &data_sizes, &fri_options)
    }
}
