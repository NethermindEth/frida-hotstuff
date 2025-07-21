# :crab: deFrida hotstuff

## Frida and deFrida benchmarks using hotstuff
This repository contains the codebase to benchmark metrics between the implementation of Frida and DeFrida using Hotstuff. The codebase is separated into its own crates. The result of the benchmark will be recorded in its own `.txt` file

## Quickstart
The benchmark can be run by running
```
cargo run -p benchmark
```

This will run all the benchmarks for frida and defrida (current WIP) for a defined configurations
The results will be outputted to a txt file

To modify the configurations or output file name, refer to [Initiate the benchmark](#initiate-the-benchmark) to see how these can be modified


## Crate structure
The code is separated into its own crates for easy maintenence. Each crate having its own responsibility.

### benchmark-framework
Contains functionalities to carrying out the benchmarking process. Proving a generic function that allows the benchmark to be used in both frida and defrida.

### frida-app
Contains implementation of Frida using hotstuff

### defrida-app
*WIP*

### benchmark
The main benchmarking process. Utilizing `benchmark-framework` to benchmarking frida and defrida


## Benchmark
### Initiate the benchmark
In our benchmark, we are able to configure `data_size`, `num_of_validators` and `fri_options`
We are able to initiate the `Benchmark` struct with the above configurations and `start` the benchmark for frida and defrida app respectively

Initiate the `Benchmark` using desired configurations. We are able to pass in a vector of each configurations and our bencmark will run each of these combinations of configurations
Fri options consist of `blowup_factor`, `folding_factor`, and `remainder_max_degree`
eg.
```
 let num_of_validators = vec![3, 5, 10, 20, 50, 100];
 let data_sizes = vec![(100, 100), (1000, 1000), (10_000, 10_000)];
 let fri_options = vec![FriOptions::new(2, 2, 1)];

 let benchmark = Benchmark::new(&num_of_validators, &data_sizes, &fri_options);
```

### Start the benchmark
To start the benchmark for a specific application (eg. frida, or defrida), 
We will need to define a file path of which our benchmark report will be generated

We will need to provide a handler to create the network and also a handler that will initiate our hotstuff application

```
 benchmark.start(
        |peers| mock_network_frida_app(peers.cloned()),
        create_frida_app,
        frida_benchmark_file_path,
    );
```

Example of how the `create_network` and `create_app` handler


Example of create network handler
```
pub fn mock_network(peers: impl Iterator<Item = VerifyingKey>) -> Vec<NetworkStub> {
    let mut all_peers = HashMap::new();
    let peer_and_inboxes: Vec<(VerifyingKey, Receiver<(VerifyingKey, Message)>)> = peers
        .map(|peer| {
            let (sender, receiver) = mpsc::channel();
            all_peers.insert(peer, sender);

            (peer, receiver)
        })
        .collect();

    peer_and_inboxes
        .into_iter()
        .map(|(my_verifying_key, inbox)| NetworkStub {
            my_verifying_key,
            all_peers: all_peers.clone(),
            inbox: Arc::new(Mutex::new(inbox)),
        })
        .collect()
}
```

Example of create application handler
```
pub fn create_app(
    tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    fri_option: FriOptions,
    height: usize,
    width: usize,
) -> FridaApp {
    let prover_builder =
        FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(fri_option.clone());
    FridaApp::new(tx_queue, prover_builder, height, width)
}
```

The reason of which the factory function method is preferred here is so that it allows the network and application to have a more flexible initiation method, (ie. they do not need to implement the same `new` creation trait as the initiation can be defined in the factory function. This will allow each different application to have different initiation values )


## Benchmarking results
In our benchmark we measure for 
```
pub struct PhaseTimingAndProofSize {
    pub propose_block_time: BenchmarkTiming,
    pub send_proposal_time: BenchmarkTiming,
    pub validate_proposal_time: BenchmarkTiming,
    pub send_signed_proposal_time: BenchmarkTiming,
    pub validate_signature_time: BenchmarkTiming,
    pub proposal_proof_size: BenchmarkProofSize,
    pub receive_proposal_proof_size: BenchmarkProofSize,
}
```

Each of these will include the min, mean and max value


## Installation
If `frida-poc` cannot be installed, do follow [this guide here](https://docs.shipyard.rs/configuration/git-fetch-with-cli.html)




#  TODOs and Possible Improvements
1. Right now, the consensus of each node will run for 3 seconds, the result will be an aggregation and averaging from all the consensus rounds. Some simpler calculations that requires a much shorter processing time will end up having more consensus rounds. To allow for an averaging of a more consistent number of consensus round, it is better if we modify our benchmark to stop based on the number of consensus round rather that the time allocated to run the consensus

2. Defrida hasn't been integrated yet. We will work on integrating Defrida to allow a comparision between Frida and Defrida

3. Right now, Frida benchmarking uses a locally mock network, it is possible that we use a network that involves an actual p2p layer (eg. libp2p)
