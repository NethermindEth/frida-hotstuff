use std::sync::{Arc, Mutex};

use frida_app::frida_app::FridaTransaction;
use hotstuff_rs::{
    app::App,
    block_tree::pluggables::KVStore,
    networking::network::Network,
    replica::{Configuration, Replica, ReplicaSpec},
    types::{
        update_sets::{AppStateUpdates, ValidatorSetUpdates, VerifyingKeyBytes},
        validator_set::{SigningKey, ValidatorSet, ValidatorSetState},
    },
};

use crate::benchmark_handlers::{self, BenchmarkHandler};

pub struct BenchmarkNode<A, K: KVStore, N> {
    _phantom: std::marker::PhantomData<(A, N)>,
    verifying_key: VerifyingKeyBytes,
    tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    replica: Replica<K>,
}

impl<A: App<K> + 'static, K: KVStore, N: Network + 'static> BenchmarkNode<A, K, N> {
    pub fn start_benchmark_node(
        app: A,
        network: N,
        keypair: SigningKey,
        replica_configuration: Configuration,
        kv_store: K,
        init_vs_updates: ValidatorSetUpdates,
        benchmark_handlers: &BenchmarkHandler,
        tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    ) -> Self {
        let verifying_key = keypair.verifying_key().to_bytes();

        let mut init_vs = ValidatorSet::new();
        init_vs.apply_updates(&init_vs_updates);
        let init_vs_state = ValidatorSetState::new(init_vs.clone(), init_vs, None, true);

        // Initialize with empty app state
        let init_as_updates = AppStateUpdates::new();
        Replica::initialize(kv_store.clone(), init_as_updates, init_vs_state);

        let replica = ReplicaSpec::builder()
            .app(app)
            .network(network)
            .kv_store(kv_store)
            .configuration(replica_configuration)
            .on_start_view(benchmark_handlers.start_view())
            .on_propose(benchmark_handlers.propose())
            .on_receive_proposal(benchmark_handlers.receive_proposal())
            .on_phase_vote(benchmark_handlers.phase_vote())
            .on_receive_phase_vote(benchmark_handlers.receive_phase_vote())
            .on_collect_pc(benchmark_handlers.collect_pc())
            .build()
            .start();

        Self {
            verifying_key,
            tx_queue,
            replica,
            _phantom: std::marker::PhantomData,
        }
    }
}
