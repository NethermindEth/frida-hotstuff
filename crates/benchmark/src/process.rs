//! # Benchmark Process Execution
//!
//! This module provides the core execution logic for running individual Frida
//! and DeFrida protocol benchmarks. It handles the setup and coordination of
//! validator nodes, network connections, and performance measurement
//! collection.
//!
//! ## Overview
//!
//! The benchmark process follows these key phases:
//! 1. **Network Setup**: Generate validator keypairs and establish network connections
//! 2. **Node Initialization**: Create consensus nodes with specified configurations
//! 3. **Transaction Execution**: Submit transactions and allow consensus to process them
//! 4. **Metrics Collection**: Gather performance metrics from all nodes
//! 5. **Report Generation**: Analyze metrics and generate benchmark reports
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   Validator 1   │    │   Validator 2   │    │   Validator N   │
//! │  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
//! │  │ FridaApp  │  │    │  │ FridaApp  │  │    │  │ FridaApp  │  │
//! │  │ + MemDB   │  │    │  │ + MemDB   │  │    │  │ + MemDB   │  │
//! │  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//!          │                       │                       │
//!          └───────────────────────┼───────────────────────┘
//!                                  │
//!                    ┌─────────────────────────┐
//!                    │    Mock Network Layer   │
//!                    │   (In-Memory Channels)  │
//!                    └─────────────────────────┘
//! ```
//!
//! ## Performance Metrics
//!
//! The benchmark collects detailed timing and proof size metrics:
//! - **Proof Generation Time**: Time to create FRI proofs
//! - **Proof Verification Time**: Time to verify received proofs  
//! - **Proof Size**: Size of generated cryptographic proofs in bytes
//! - **Consensus Latency**: Time from transaction submission to block inclusion
//! - **Network Overhead**: Communication costs between validators

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use common::data::FridaTransaction;
use frida_app::{frida_app::FridaApp, mem_db::MemDB};
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
    benchmark_utils::generate_test_data, config::DataSize,
};

/// A single benchmark configuration executor for Frida and DeFrida.
///
/// This struct represents one specific benchmark test case with fixed parameters:
/// a specific number of validators, data matrix dimensions, and FRI cryptographic settings.
/// It coordinates the entire benchmark execution process from network setup to report generation.
///
/// ## Usage
///
/// Typically created via the [`crate::config::BenchmarkConfig::benchmarks()`] iterator rather than directly:
///
/// ```rust
/// use benchmark::config::BenchmarkConfig;
///
/// let config = BenchmarkConfig::load();
/// for benchmark in config.benchmarks() {
///     benchmark.start(create_networks, create_app, "results.txt");
/// }
/// ```
///
/// ## Performance Characteristics
///
/// The benchmark execution time scales with:
/// - **Validator Count**: O(n²) network complexity
/// - **Data Size**: O(h×w) for proof generation where h=height, w=width
/// - **FRI Parameters**: Logarithmic in blowup factor, linear in folding factor
pub struct Benchmark {
    /// Number of validator nodes participating in this benchmark.
    ///
    /// More validators increase network complexity and consensus overhead,
    /// allowing testing of scalability characteristics. Typical range: 3-100 validators.
    pub num_of_validators: u32,

    /// Data matrix dimensions for FRI proof operations.
    ///
    /// Defines the size of data matrices used for cryptographic proof generation
    /// and verification. Larger matrices test memory scalability and computational limits.
    pub data_sizes: DataSize,

    /// FRI cryptographic protocol parameters.
    ///
    /// Controls the cryptographic proof system configuration, affecting the trade-offs
    /// between proof size, generation time, and verification time.
    pub fri_options: FriOptions,
}

impl Benchmark {
    /// Creates a new benchmark configuration.
    ///
    /// # Parameters
    ///
    /// * `num_of_validators` - Number of consensus validators (must be ≥ 1)
    /// * `data_sizes` - Matrix dimensions for proof operations
    /// * `fri_options` - FRI cryptographic parameters
    ///
    /// # Examples
    ///
    /// ```rust
    /// use benchmark::{config::DataSize, process::Benchmark};
    /// use frida_poc::winterfell::FriOptions;
    ///
    /// let data_size = DataSize { height: 100, width: 100 };
    /// let fri_options = FriOptions::new(2, 2, 1);
    /// let benchmark = Benchmark::new(5, &data_size, &fri_options);
    /// ```
    pub fn new(num_of_validators: u32, data_sizes: &DataSize, fri_options: &FriOptions) -> Self {
        Self {
            num_of_validators,
            data_sizes: data_sizes.clone(),
            fri_options: fri_options.clone(),
        }
    }

    /// Executes a complete benchmark run with the configured parameters.
    ///
    /// This method orchestrates the entire benchmark process: network setup, validator
    /// initialization, transaction execution, metrics collection, and report generation.
    /// It represents a single data point in the benchmark results.
    ///
    /// ## Parameters
    ///
    /// * `create_networks` - Factory function for creating validator network instances
    /// * `create_app` - Factory function for creating FridaApp instances  
    /// * `reporting_file_path` - Path where benchmark results will be written
    ///
    /// ## Example Usage
    ///
    /// ```rust
    /// use frida_app::{create_app, network::mock_network};
    ///
    /// let benchmark = Benchmark::new(5, &data_size, &fri_options);
    /// benchmark.start(
    ///     |peers| mock_network(peers.cloned()),
    ///     create_app,
    ///     "results/benchmark-output.txt"
    /// );
    /// ```
    pub fn start<F, G, N>(&self, create_networks: F, create_app: G, reporting_file_path: &str)
    where
        F: Fn(std::slice::Iter<VerifyingKey>) -> Vec<N>,
        G: Fn(Arc<Mutex<Vec<FridaTransaction>>>, FriOptions, usize, usize) -> FridaApp,
        N: Network + Send + Sync + 'static,
    {
        // ═══════════════════════════════════════════════════════════════════════════════
        // Phase 1: Cryptographic Setup
        // ═══════════════════════════════════════════════════════════════════════════════
        // Generate cryptographic keypairs for each validator using a secure RNG
        let mut csprg = OsRng::default();
        let keypairs: Vec<SigningKey> = (0..self.num_of_validators)
            .map(|_| SigningKey::generate(&mut csprg))
            .collect();

        // ═══════════════════════════════════════════════════════════════════════════════
        // Phase 2: Network Initialization
        // ═══════════════════════════════════════════════════════════════════════════════
        // Extract public keys and create network connections between all validators
        let verifying_keys: Vec<VerifyingKey> =
            keypairs.iter().map(|kp| kp.verifying_key()).collect();
        let networks = create_networks(verifying_keys.iter());

        // ═══════════════════════════════════════════════════════════════════════════════
        // Phase 3: Validator Set Configuration
        // ═══════════════════════════════════════════════════════════════════════════════
        // Create initial validator set with equal voting power for all participants
        let init_vs_updates = {
            let mut vs_updates = ValidatorSetUpdates::new();
            keypairs.iter().for_each(|kp| {
                vs_updates.insert(kp.verifying_key(), Power::new(1));
            });
            vs_updates
        };

        // Initialize shared benchmark metrics collection handler
        let benchmark_handlers = BenchmarkHandler::new();

        // ═══════════════════════════════════════════════════════════════════════════════
        // Phase 4: Node Creation and Startup
        // ═══════════════════════════════════════════════════════════════════════════════
        // Create and start each validator node with proper configuration
        let live_nodes: Vec<BenchmarkNode<FridaApp, MemDB, N>> = keypairs
            .into_iter()
            .zip(networks)
            .map(|(keypair, network)| {
                // Create transaction queue for this validator
                let tx_queue = Arc::new(Mutex::new(Vec::new()));

                // Initialize FridaApp with configured data dimensions and FRI parameters
                let app = create_app(
                    tx_queue.clone(),
                    self.fri_options.clone(),
                    self.data_sizes.height,
                    self.data_sizes.width,
                );

                // Configure HotStuff consensus parameters
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
                    // View timeout must accommodate FRI proof generation time
                    // (minimum 500ms for basic operations, 2000ms provides safe margin)
                    .max_view_time(Duration::from_millis(2000))
                    .log_events(false) // Disable verbose logging for cleaner benchmark output
                    .build();

                // Initialize in-memory key-value store for each validator
                let kv_store = MemDB::new();

                // Start the benchmark node with metrics collection enabled
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

        // ═══════════════════════════════════════════════════════════════════════════════
        // Phase 5: Transaction Execution
        // ═══════════════════════════════════════════════════════════════════════════════
        // Submit a test transaction to the first validator to trigger consensus
        live_nodes[0].submit_transaction(vec![FridaTransaction::new(Bytes::from_static(
            b"hellooooooooooooo",
        ))]);

        // Allow sufficient time for transaction processing and consensus completion
        // This 20-second window accommodates:
        // - Transaction propagation across network
        // - FRI proof generation (computationally intensive)
        // - Consensus protocol rounds (propose, prepare, precommit, commit)
        // - Block finalization and storage
        std::thread::sleep(std::time::Duration::from_secs(20));

        // Gracefully stop all validator nodes
        live_nodes.into_iter().for_each(|node| node.stop());

        // ═══════════════════════════════════════════════════════════════════════════════
        // Phase 6: Metrics Analysis and Reporting
        // ═══════════════════════════════════════════════════════════════════════════════
        // Collect performance metrics from all validators
        let all_metrics = benchmark_handlers.get_all_benchmark_metrics();

        // Calculate statistical summaries (min, max, mean) for timing and proof sizes
        let phase_timing_proof_size =
            PhaseTimingAndProofSize::get_min_max_mean_from_all_benchmark_metrics(all_metrics);

        // Output performance summary to console for immediate feedback
        println!("phase_timing_proof_size: {:?}", phase_timing_proof_size);

        // FIXME: Change the generate_report function
        let height_width_phase_timings = vec![(
            self.data_sizes.height,
            self.data_sizes.width,
            phase_timing_proof_size,
        )];

        // Generate structured benchmark report and append to output file
        generate_report(
            reporting_file_path,
            self.num_of_validators as u64,
            self.fri_options.clone(),
            height_width_phase_timings,
        );
    }
}
