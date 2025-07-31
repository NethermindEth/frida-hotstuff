use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use common::data::FridaTransaction;
use defrida_app::{
    ProofStatistics,
    app::DefridaApp,
    defrida_proof_calculation,
    network::{DefridaNetworkHandle, DefridaSideNetwork},
};
use frida_app::{frida_app::FridaApp, mem_db::MemDB};
use frida_poc::{
    frida_prover::FridaProverBuilder,
    winterfell::{Blake3_256, FriOptions, f128::BaseElement, rand_vector},
};
use hotstuff_rs::{
    networking::network::Network,
    replica::Configuration,
    types::{
        data_types::{BufferSize, ChainID, EpochLength, Power},
        update_sets::ValidatorSetUpdates,
        validator_set::{SigningKey, ValidatorSet, ValidatorSetState, VerifyingKey},
    },
};
use rand_core::OsRng;

use crate::{
    benchmark_calculation::PhaseTimingAndProofSize, benchmark_handlers::BenchmarkHandler,
    benchmark_node::BenchmarkNode, benchmark_reporting::generate_report,
    benchmark_utils::generate_test_data,
};

pub struct Benchmark<'a> {
    pub num_of_validators: &'a Vec<u32>,
    pub data_sizes: &'a Vec<(usize, usize)>,
    pub fri_options: &'a Vec<FriOptions>,
}

impl<'a> Benchmark<'a> {
    pub fn new(
        num_of_validators: &'a Vec<u32>,
        data_sizes: &'a Vec<(usize, usize)>,
        fri_options: &'a Vec<FriOptions>,
    ) -> Self {
        Self {
            num_of_validators,
            data_sizes,
            fri_options,
        }
    }

    // create_networks: pass in the network layer that will be used to connect the
    // validators
    pub fn start<F, G, N>(&self, create_networks: F, create_app: G, reporting_file_path: &str)
    where
        F: Fn(std::slice::Iter<VerifyingKey>) -> Vec<N>,
        G: Fn(Arc<Mutex<Vec<FridaTransaction>>>, FriOptions, usize, usize) -> FridaApp,
        N: Network + Send + Sync + 'static,
    {
        for num_of_validator in self.num_of_validators {
            for fri_option in self.fri_options {
                let mut height_width_phase_timings: Vec<(usize, usize, PhaseTimingAndProofSize)> =
                    vec![];

                for data_size in self.data_sizes {
                    // let fri_data = generate_test_data(data_size.0, data_size.1);
                    // Generate n replicas.
                    let mut csprg = OsRng {};
                    let keypairs: Vec<SigningKey> = (0..*num_of_validator)
                        .map(|_| SigningKey::generate(&mut csprg))
                        .collect();

                    // Create network conneting n number of replicas
                    let verifying_keys: Vec<VerifyingKey> =
                        keypairs.iter().map(|kp| kp.verifying_key()).collect();
                    let networks = create_networks(verifying_keys.iter());

                    let init_vs_updates = {
                        let mut vs_updates = ValidatorSetUpdates::new();
                        keypairs.iter().for_each(|kp| {
                            vs_updates.insert(kp.verifying_key(), Power::new(1));
                        });
                        vs_updates
                    };

                    let benchmark_handlers = BenchmarkHandler::new();

                    let live_nodes: Vec<BenchmarkNode<FridaApp, MemDB, N>> = keypairs
                        .into_iter()
                        .zip(networks)
                        .map(|(keypair, network)| {
                            let tx_queue = Arc::new(Mutex::new(Vec::new()));
                            let app = create_app(
                                tx_queue.clone(),
                                fri_option.clone(),
                                data_size.0,
                                data_size.1,
                            );
                            let configuration = Configuration::builder()
                                .me(keypair.clone())
                                .chain_id(ChainID::new(0))
                                .block_sync_request_limit(10)
                                .block_sync_server_advertise_time(Duration::new(10, 0))
                                .block_sync_response_timeout(Duration::new(3, 0))
                                .block_sync_blacklist_expiry_time(Duration::new(10, 0))
                                .block_sync_trigger_min_view_difference(2)
                                .block_sync_trigger_timeout(Duration::new(60, 0))
                                .progress_msg_buffer_capacity(BufferSize::new(1024))
                                .epoch_length(EpochLength::new(50))
                                // `max_view_time` must be **at least** 500 milliseconds, since
                                // `NumberApp`'s `produce_block` and
                                // `validate_block` each take a minimum of 250 milliseconds to
                                // complete.
                                .max_view_time(Duration::from_millis(2000))
                                .log_events(false)
                                .build();

                            let kv_store = MemDB::new();

                            BenchmarkNode::start_benchmark_node(
                                app,
                                network,
                                keypair,
                                configuration,
                                kv_store,
                                init_vs_updates.clone(),
                                &benchmark_handlers,
                                tx_queue,
                            )
                        })
                        .collect();

                    // live_nodes[0].submit_transaction(vec![fri_data.clone().into()]);
                    live_nodes[0].submit_transaction(vec![FridaTransaction::new(
                        Bytes::from_static(b"hellooooooooooooo"),
                    )]);

                    // TODO:
                    // to stop process after one transaction has been included into block?

                    std::thread::sleep(std::time::Duration::from_secs(20));

                    live_nodes.into_iter().for_each(|node| node.stop());

                    // get all metrics
                    let all_metrics = benchmark_handlers.get_all_benchmark_metrics();
                    // println!("all_metrics: {:?}", all_metrics);
                    // println!("end all metrics");
                    let phase_timing_proof_size =
                        PhaseTimingAndProofSize::get_min_max_mean_from_all_benchmark_metrics(
                            all_metrics,
                        );

                    println!("phase_timing_proof_size: {:?}", phase_timing_proof_size);
                    height_width_phase_timings.push((
                        data_size.0,
                        data_size.1,
                        phase_timing_proof_size,
                    ));
                }

                generate_report(
                    reporting_file_path,
                    *num_of_validator as u64,
                    fri_option.clone(),
                    height_width_phase_timings,
                    None,
                );
            }
        }
    }

    pub fn start_defrida<F, N>(&self, create_networks: F, reporting_file_path: &str)
    where
        F: Fn(std::slice::Iter<VerifyingKey>) -> Vec<N>,
        N: Network + Send + Sync + 'static,
    {
        for &num_of_validator in self.num_of_validators {
            for fri_option in self.fri_options {
                let mut height_width_phase_timings: Vec<(usize, usize, PhaseTimingAndProofSize)> =
                    vec![];
                let mut proof_statistics: Option<ProofStatistics> = None;

                for data_size in self.data_sizes {
                    let mut csprg = OsRng {};
                    let signing_keys: Vec<SigningKey> = (0..num_of_validator)
                        .map(|_| SigningKey::generate(&mut csprg))
                        .collect();
                    let verifying_keys: Vec<_> =
                        signing_keys.iter().map(|sk| sk.verifying_key()).collect();

                    // let hotstuff_network_stubs = mock_network(verifying_keys.iter().cloned());
                    let hotstuff_network_stubs = create_networks(verifying_keys.iter());
                    let (side_tx, side_rx) = std::sync::mpsc::channel();
                    let mut peer_txs = HashMap::new();
                    let mut node_rxs = HashMap::new();

                    for vk in &verifying_keys {
                        let (tx, rx) = std::sync::mpsc::channel();
                        peer_txs.insert(*vk, tx);
                        node_rxs.insert(*vk, Arc::new(Mutex::new(rx)));
                    }
                    let proof_store = DefridaSideNetwork::start(side_rx, peer_txs);

                    let tx_pool = Arc::new(Mutex::new(Vec::<FridaTransaction>::new()));
                    let total_queries = 7;

                    // Thread to continuously supply transactions
                    let pool_clone = tx_pool.clone();
                    let test_duration = Duration::from_secs(20);

                    let producer_handle = thread::spawn(move || {
                        let start = Instant::now();
                        while start.elapsed() < test_duration - Duration::from_secs(5) {
                            pool_clone
                                .lock()
                                .unwrap()
                                .push(FridaTransaction::new(rand_vector::<u8>(512).into()));
                            thread::sleep(Duration::from_millis(500));
                        }
                        println!("Transaction producer finished.");
                    });

                    let benchmark_handlers = BenchmarkHandler::new();

                    let mut lives_nodes = vec![];
                    for (i, sk) in signing_keys.into_iter().enumerate() {
                        let vk = verifying_keys[i];
                        let defrida_network_handle = DefridaNetworkHandle {
                            tx: side_tx.clone(),
                            rx: node_rxs.get(&vk).unwrap().clone(),
                        };
                        let prover_builder = FridaProverBuilder::<
                            BaseElement,
                            Blake3_256<BaseElement>,
                        >::new(fri_option.clone());
                        let app = DefridaApp::<MemDB>::new(
                            defrida_network_handle,
                            vk,
                            tx_pool.clone(),
                            prover_builder,
                            total_queries,
                            1000,
                            1000,
                        );

                        let configuration = Configuration::builder()
                            .me(sk.clone())
                            .chain_id(ChainID::new(0))
                            .block_sync_request_limit(10)
                            .block_sync_server_advertise_time(Duration::new(10, 0))
                            .block_sync_response_timeout(Duration::new(3, 0))
                            .block_sync_blacklist_expiry_time(Duration::new(10, 0))
                            .block_sync_trigger_min_view_difference(2)
                            .block_sync_trigger_timeout(Duration::new(60, 0))
                            .progress_msg_buffer_capacity(BufferSize::new(1024))
                            .epoch_length(EpochLength::new(50))
                            // `max_view_time` must be **at least** 500 milliseconds, since
                            // `NumberApp`'s `produce_block` and
                            // `validate_block` each take a minimum of 250 milliseconds to
                            // complete.
                            .max_view_time(Duration::from_millis(2000))
                            .log_events(false)
                            .build();

                        let kv_store = MemDB::new();
                        let mut vs_updates = ValidatorSetUpdates::new();
                        verifying_keys
                            .iter()
                            .for_each(|vk| vs_updates.insert(*vk, Power::new(1)));

                        let node = BenchmarkNode::start_benchmark_node(
                            app,
                            hotstuff_network_stubs[i].clone(),
                            sk,
                            configuration,
                            kv_store,
                            vs_updates.clone(),
                            &benchmark_handlers,
                            tx_pool.clone(),
                        );

                        lives_nodes.push(node);
                    }

                    std::thread::sleep(std::time::Duration::from_secs(20));

                    lives_nodes.into_iter().for_each(|node| node.stop());

                    // get all metrics
                    let all_metrics = benchmark_handlers.get_all_benchmark_metrics();
                    // println!("all_metrics: {:?}", all_metrics);
                    // println!("end all metrics");
                    let phase_timing_proof_size =
                        PhaseTimingAndProofSize::get_min_max_mean_from_all_benchmark_metrics(
                            all_metrics,
                        );

                    println!("phase_timing_proof_size: {:?}", phase_timing_proof_size);
                    height_width_phase_timings.push((
                        data_size.0,
                        data_size.1,
                        phase_timing_proof_size,
                    ));

                    let proof_store = proof_store.lock().unwrap();
                    proof_statistics = Some(defrida_proof_calculation(&proof_store));
                    println!("proof_statistics: {:?}", proof_statistics);
                }

                generate_report(
                    reporting_file_path,
                    num_of_validator as u64,
                    fri_option.clone(),
                    height_width_phase_timings,
                    proof_statistics,
                );
            }
        }
    }
}
