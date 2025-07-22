pub mod benchmark_calculation;
pub mod benchmark_handlers;
pub mod benchmark_node;
pub mod benchmark_process;
pub mod benchmark_reporting;
pub mod benchmark_utils;

// Example usage of the benchmark handler
#[cfg(test)]
mod tests {
    use frida_app::{create_app, network::mock_network};
    use frida_poc::winterfell::FriOptions;

    use crate::benchmark_process::Benchmark;

    #[test]
    #[ignore]
    fn test_benchmark_start() {
        let file_path = "test.txt";
        let num_of_validators = vec![50];
        let data_sizes = vec![(10_000, 10_000)];
        let fri_options = vec![FriOptions::new(2, 2, 1)];
        let benchmark = Benchmark::new(&num_of_validators, &data_sizes, &fri_options);
        benchmark.start(|peers| mock_network(peers.cloned()), create_app, file_path, false);
    }
}