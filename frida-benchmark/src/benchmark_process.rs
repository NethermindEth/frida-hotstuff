use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use frida_app::frida_app::FridaApp;
use frida_app::mem_db::MemDB;
use frida_poc::{
    frida_prover::FridaProverBuilder,
    winterfell::{Blake3_256, FriOptions, f128::BaseElement},
};
use hotstuff_rs::{
    networking::network::Network,
    replica::Configuration,
    types::{
        data_types::{BufferSize, ChainID, EpochLength, Power},
        update_sets::ValidatorSetUpdates,
        validator_set::{SigningKey, VerifyingKey},
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

    // create_networks: pass in the network layer that will be used to connect the validators
    pub fn start<F, N>(&self, create_networks: F, reporting_file_path: &str)
    where
        F: Fn(std::slice::Iter<'_, VerifyingKey>) -> Vec<N>,
        N: Network + Send + Sync + 'static,
    {
        for num_of_validator in self.num_of_validators {
            for fri_option in self.fri_options {
                let mut height_width_phase_timings: Vec<(usize, usize, PhaseTimingAndProofSize)> =
                    vec![];

                for data_size in self.data_sizes {
                    let fri_data = generate_test_data(data_size.0, data_size.1);
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
                            let prover_builder =
                                FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(
                                    fri_option.clone(),
                                );
                            let tx_queue = Arc::new(Mutex::new(Vec::new()));
                            let app = FridaApp::new(
                                tx_queue.clone(),
                                prover_builder,
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
                                // `max_view_time` must be **at least** 500 milliseconds, since `NumberApp`'s `produce_block` and
                                // `validate_block` each take a minimum of 250 milliseconds to complete.
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
                    live_nodes[0].submit_transaction(vec![fri_data.clone().into()]);

                    // TODO:
                    // to stop process after one transaction has been included into block?

                    std::thread::sleep(std::time::Duration::from_secs(10));

                    // get all metrics
                    let all_metrics = benchmark_handlers.get_all_benchmark_metrics();
                    let phase_timing_proof_size =
                        PhaseTimingAndProofSize::get_min_max_mean_from_all_benchmark_metrics(
                            all_metrics,
                        );

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
                );
            }
        }
    }
}
