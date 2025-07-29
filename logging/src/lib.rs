use std::{
    fs::{self, OpenOptions},
    path::Path,
};

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, util::SubscriberInitExt};

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
pub fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logging_writes_to_file() {
        // Initialise logger and keep guard alive for the scope of the test
        let guard = init_logging();

        // Emit a test message
        let test_message = "Hello, logging test!";
        tracing::info!("{test_message}");

        // Explicitly drop guard to flush logs
        drop(guard);

        // Verify that the log file exists and contains the message
        let log_path = std::path::Path::new(super::LOG_DIR).join(super::LOG_FILE);
        assert!(
            log_path.exists(),
            "Log file was not created: {:?}",
            log_path
        );

        let contents =
            std::fs::read_to_string(&log_path).expect("Failed to read log file contents");
        assert!(
            contents.contains(test_message),
            "Log file does not contain expected message"
        );
    }
}
