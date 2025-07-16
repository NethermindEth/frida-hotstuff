pub mod benchmark_calculation;
pub mod benchmark_handlers;
pub mod benchmark_node;
pub mod benchmark_process;
pub mod benchmark_reporting;
pub mod benchmark_utils;

// Example usage of the benchmark handler
#[cfg(test)]
mod tests {
    use super::benchmark_handlers::BenchmarkHandler;

    #[test]
    fn test_benchmark_handler_usage() {
        // Create a new benchmark handler
        let handler = BenchmarkHandler::new();

        // After running your benchmark, you can access the timestamps:

        // Print a summary of all recorded timestamps
        handler.print_summary();

        // Get timestamps for a specific view
        if let Some(view_timestamps) = handler.get_benchmark_metrics(0) {
            println!("View 0 timestamps: {:?}", view_timestamps);
        }

        // Calculate timing bounds for a view
        if let Some(bounds) = handler.get_view_timing_bounds(0) {
            println!("View 0 timing bounds: {:?}", bounds);
        }

        // Calculate latency statistics for a specific event type
        if let Some(stats) = handler.calculate_latency_stats("propose") {
            println!("Propose event latency stats: {:?}", stats);
        }

        // Get all timestamps for all views
        let all_timestamps = handler.get_all_benchmark_metrics();
        println!("Total views recorded: {}", all_timestamps.len());
    }
}
