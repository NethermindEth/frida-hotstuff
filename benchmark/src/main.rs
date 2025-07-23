use benchmark_framework::benchmark_process::Benchmark;
use frida_app::{create_app as create_frida_app, network::mock_network as mock_network_frida_app};
use frida_poc::winterfell::FriOptions;

fn main() {
    let frida_benchmark_file_path = "frida-benchmark.txt";
    let num_of_validators = vec![3, 5, 10, 20, 50, 100];
    let data_sizes = vec![(100, 100), (1000, 1000), (10_000, 10_000)];
    let fri_options = vec![FriOptions::new(2, 2, 1)];

    let benchmark = Benchmark::new(&num_of_validators, &data_sizes, &fri_options);
    benchmark.start(
        |peers| mock_network_frida_app(peers.cloned()),
        create_frida_app,
        frida_benchmark_file_path,
    );
}
