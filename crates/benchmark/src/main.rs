//! # Frida and DeFrida Benchmark Tool
//!
//! A comprehensive benchmarking tool for evaluating both Frida and DeFrida performance
//! across different validator set sizes, data dimensions, and FRI configuration parameters.
//!
//! ## Overview
//!
//! This binary benchmarks both Frida and DeFrida by:
//! - Testing various validator configurations (3 to 100 validators)
//! - Evaluating different data sizes for cryptographic operations
//! - Measuring performance across multiple FRI (Fast Reed-Solomon Interactive) parameter sets
//! - Generating detailed performance reports with timing and proof size metrics
//! - Comparing performance characteristics between Frida and DeFrida implementations
//!
//! ## Output
//!
//! Results are written to:
//! - `logs/logging.log` - Detailed execution logs
//! - `results/frida-benchmark.txt` - Frida protocol benchmark results and metrics
//! - `results/defrida-benchmark.txt` - DeFrida protocol benchmark results and metrics
//! - Standard output - Real-time progress information
//!
//! ## Environment Variables
//!
//! - `RUST_LOG` - Controls logging verbosity (default: INFO)
//!   - Examples: `RUST_LOG=debug`, `RUST_LOG=trace`, `RUST_LOG=warn`

mod calculation;
mod config;
mod handlers;
mod node;
mod process;
mod reporting;

use std::{
    fs::{self, OpenOptions},
    path::Path,
};

use config::BenchmarkConfig;
use frida_app::{create_app as create_frida_app, network::mock_network as mock_network_frida_app};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, util::SubscriberInitExt};

/// Directory where log files are stored
const LOG_DIR: &str = "logs";

/// Name of the main log file
const LOG_FILE: &str = "logging.log";

/// Initializes application-wide structured logging with dual output streams.
///
/// Sets up a comprehensive logging system that writes to both file and console,
/// with configurable log levels and proper formatting for different output targets.
///
/// # Logging Configuration
///
/// - **File Output**: `logs/logging.log` (truncated on each run, no ANSI colors)
/// - **Console Output**: Standard output (with ANSI colors for readability)
/// - **Log Level**: Controlled by `RUST_LOG` environment variable (default: INFO)
///
/// # Environment Variables
///
/// The `RUST_LOG` environment variable controls verbosity.
///
/// # Returns
///
/// Returns a [`tracing_appender::non_blocking::WorkerGuard`] that **must** be kept alive
/// for the entire duration of the application. Dropping this guard will:
/// - Flush any remaining log messages
/// - Cleanly shut down the background writer thread
/// - Potentially lose unflushed log data
///
/// # Panics
///
/// Panics if:
/// - The log directory cannot be created
/// - The log file cannot be opened for writing
///
/// # Examples
///
/// ```no_run
/// let _guard = init_logging();
/// tracing::info!("Application started");
/// // Guard must remain in scope for logging to work
/// ```
fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    // Ensure the logs directory exists, creating it if necessary
    fs::create_dir_all(LOG_DIR)
        .unwrap_or_else(|err| panic!("Failed to create log directory '{LOG_DIR}': {err}"));

    // Create or truncate the log file for this run
    let log_path = Path::new(LOG_DIR).join(LOG_FILE);
    let file = OpenOptions::new()
        .create(true) // Create file if it doesn't exist
        .write(true) // Open for writing
        .truncate(true) // Clear existing content
        .open(&log_path)
        .unwrap_or_else(|err| panic!("Failed to open log file '{log_path:?}': {err}"));

    // Set up non-blocking file writer to prevent I/O from blocking the main thread
    let (non_blocking, guard) = tracing_appender::non_blocking(file);

    // Parse log level from environment or use INFO as default
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|lvl| lvl.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::INFO);

    // Configure file output layer (no ANSI escape codes for clean file output)
    let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false);

    // Configure console output layer (with ANSI colors for better readability)
    let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_ansi(true);

    // Initialize the global subscriber with both layers
    tracing_subscriber::registry()
        .with(file_layer.with_filter(level))
        .with(stdout_layer.with_filter(level))
        .init();

    guard
}

/// Main entry point for the Frida and DeFrida benchmark application.
///
/// # Benchmark Process
///
/// 1. **Initialization**: Sets up logging and loads configuration
/// 2. **Frida Testing**: Runs complete benchmark suite for Frida protocol
/// 3. **DeFrida Testing**: Runs complete benchmark suite for DeFrida protocol
/// 4. **Report Generation**: Writes detailed results to configured output files
fn main() {
    // Initialize logging system - guard must be kept alive throughout execution
    let guard = init_logging();

    tracing::info!("Starting Frida and DeFrida benchmark suite");

    // Load configuration from YAML file
    let config = BenchmarkConfig::load();
    tracing::info!("Configuration loaded successfully");
    tracing::info!("Validator counts: {:?}", config.num_of_validators);
    tracing::info!("Data sizes: {} configurations", config.data_sizes.len());
    tracing::info!("FRI options: {} configurations", config.fri_options.len());

    // Create parent directories if they don't exist. Check that that it can be
    // created instead of failing after the benchmark
    if let Some(parent) = Path::new(&config.output_files.frida_benchmark).parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("Failed to create output directory '{parent:?}': {err}"));
    }

    if let Some(parent) = Path::new(&config.output_files.defrida_benchmark).parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("Failed to create output directory '{parent:?}': {err}"));
    }

    // Execute Frida protocol benchmark
    for benchmark in config.benchmarks() {
        benchmark.start(
            |peers| mock_network_frida_app(peers.cloned()),
            create_frida_app,
            &config.output_files.frida_benchmark,
        );
        tracing::info!(
            "Frida benchmark completed, results written to {}",
            config.output_files.frida_benchmark
        );
    }

    // Execute DeFrida protocol benchmark
    for benchmark in config.benchmarks() {
        benchmark.start_defrida(
            |peers| mock_network_frida_app(peers.cloned()),
            &config.output_files.defrida_benchmark,
        );
        tracing::info!(
            "DeFrida benchmark completed, results written to {}",
            config.output_files.defrida_benchmark
        );
    }

    tracing::info!("All benchmarks completed successfully");

    // Explicitly drop the guard to ensure all logs are flushed before exit
    drop(guard);
}
