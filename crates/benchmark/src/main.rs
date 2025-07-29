mod benchmark_calculation;
mod benchmark_handlers;
mod benchmark_node;
mod benchmark_process;
mod benchmark_reporting;
mod benchmark_utils;

use std::{
    fs::{self, OpenOptions},
    path::Path,
};

use frida_app::{create_app as create_frida_app, network::mock_network as mock_network_frida_app};
use frida_poc::winterfell::FriOptions;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, util::SubscriberInitExt};

use crate::benchmark_process::Benchmark;

const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "logging.log";

/// Initialise application-wide logging.
///
/// * Logs are written to both `logs/logging.log` (file is recreated each run) and stdout.
/// * The log level can be configured via the standard `RUST_LOG` environment
///   variable (e.g. `RUST_LOG=debug`). If the variable is not set or cannot be
///   parsed, the default level is `INFO`.
/// * The returned [`WorkerGuard`] **must** be kept alive for as long as you
///   want logging to keep working; dropping it flushes any remaining messages
///   and cleanly shuts down the background writer thread.
fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    // Ensure the logs directory exists.
    fs::create_dir_all(LOG_DIR)
        .unwrap_or_else(|err| panic!("Failed to create log directory '{LOG_DIR}': {err}"));

    // Create the log file.
    let log_path = Path::new(LOG_DIR).join(LOG_FILE);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_path)
        .unwrap_or_else(|err| {
            panic!("Failed to open log file '{log_path:?}': {err}. Falling back to stdout logging.")
        });

    let (non_blocking, guard) = tracing_appender::non_blocking(file);

    // Honour RUST_LOG if present, otherwise default to INFO.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|lvl| lvl.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::INFO);

    // File layer (non-ANSI)
    let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false);

    // Stdout layer (ANSI colouring)
    let stdout_layer = fmt::layer().with_writer(std::io::stdout).with_ansi(true);

    tracing_subscriber::registry()
        .with(file_layer.with_filter(level))
        .with(stdout_layer.with_filter(level))
        .init();

    guard
}

fn main() {
    let guard = init_logging();
    let num_of_validators = vec![3, 5, 10, 20, 50, 100];
    let data_sizes = vec![(100, 100), (1000, 1000), (10_000, 10_000)];
    let fri_options = vec![FriOptions::new(2, 2, 1)];

    let frida_benchmark_file_path = "frida-benchmark.txt";
    let benchmark = Benchmark::new(&num_of_validators, &data_sizes, &fri_options);
    benchmark.start(
        |peers| mock_network_frida_app(peers.cloned()),
        create_frida_app,
        frida_benchmark_file_path,
    );

    let _defrida_benchmark_file_path = "defrida-benchmark.txt";
    // benchmark.start(
    //     |peers| mock_network_defrida_app(peers.cloned()),
    //     create_defrida_app,
    //     defrida_benchmark_file_path,
    // );

    drop(guard);
}
