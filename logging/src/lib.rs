pub fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    use std::fs::{self, OpenOptions};

    // Create logs directory if it doesn't exist
    fs::create_dir_all("logs").unwrap();

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("logs/logging.log")
        .unwrap();

    let (non_blocking, guard) = tracing_appender::non_blocking(file);

    // Set up the subscriber using that writer
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .init();

    guard
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_init_logging() {
        let _guard = init_logging();

        tracing::info!("Hello, world!");

        // Keep guard alive until end of test
        drop(_guard);
    }
}
