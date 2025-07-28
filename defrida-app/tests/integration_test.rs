use benchmark_common::data::FridaTransaction;
use frida_poc::frida_prover::FridaProverBuilder;
use frida_poc::winterfell::{f128::BaseElement, Blake3_256, FriOptions};
use hotstuff_rs::replica::{Configuration, Replica, ReplicaSpec};
use hotstuff_rs::types::crypto_primitives::{SigningKey, VerifyingKey};
use hotstuff_rs::types::data_types::{BufferSize, ChainID, EpochLength, Power};
use hotstuff_rs::types::update_sets::{AppStateUpdates, ValidatorSetUpdates};
use hotstuff_rs::types::validator_set::{ValidatorSet, ValidatorSetState};
use rand_core::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use winter_rand_utils::rand_vector;

use defrida_app::app::DefridaApp;
use defrida_app::network::{DefridaNetworkHandle, DefridaNetworkMessage, DefridaSideNetwork};

mod common;
use common::mem_db::MemDB;
use common::network::mock_network;

#[test]
fn test_defrida_app_integration() {
    let num_nodes = 4;
    let mut csprg = OsRng {};
    let signing_keys: Vec<SigningKey> = (0..num_nodes)
        .map(|_| SigningKey::generate(&mut csprg))
        .collect();
    let verifying_keys: Vec<_> = signing_keys.iter().map(|sk| sk.verifying_key()).collect();

    let hotstuff_network_stubs = mock_network(verifying_keys.iter().cloned());
    let (side_tx, side_rx) = std::sync::mpsc::channel();
    let mut peer_txs = HashMap::new();
    let mut node_rxs = HashMap::new();

    for vk in &verifying_keys {
        let (tx, rx) = std::sync::mpsc::channel();
        peer_txs.insert(*vk, tx);
        node_rxs.insert(*vk, Arc::new(Mutex::new(rx)));
    }
    DefridaSideNetwork::start(side_rx, peer_txs);

    let tx_pool = Arc::new(Mutex::new(Vec::<FridaTransaction>::new()));
    let fri_options = FriOptions::new(4, 4, 16);
    let total_queries = 16;

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

    let mut replicas: Vec<Replica<MemDB>> = Vec::new();
    for (i, sk) in signing_keys.into_iter().enumerate() {
        let vk = verifying_keys[i];
        let defrida_network_handle = DefridaNetworkHandle {
            tx: side_tx.clone(),
            rx: node_rxs.get(&vk).unwrap().clone(),
        };
        let prover_builder =
            FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(fri_options.clone());
        let app = DefridaApp::new(
            defrida_network_handle,
            vk,
            tx_pool.clone(),
            prover_builder,
            total_queries,
            100,
            100,
        );

        let kv_store = MemDB::new();
        let mut vs_updates = ValidatorSetUpdates::new();
        verifying_keys
            .iter()
            .for_each(|vk| vs_updates.insert(*vk, Power::new(1)));
        let mut init_vs = ValidatorSet::new();
        init_vs.apply_updates(&vs_updates);
        let init_vs_state = ValidatorSetState::new(init_vs.clone(), init_vs, None, true);
        Replica::initialize(kv_store.clone(), AppStateUpdates::new(), init_vs_state);

        let config = Configuration::builder()
            .me(sk)
            .chain_id(ChainID::new(1))
            .block_sync_request_limit(10)
            .block_sync_server_advertise_time(Duration::from_secs(10))
            .block_sync_response_timeout(Duration::from_secs(5))
            .block_sync_blacklist_expiry_time(Duration::from_secs(10))
            .block_sync_trigger_min_view_difference(2)
            .block_sync_trigger_timeout(Duration::from_secs(60))
            .progress_msg_buffer_capacity(BufferSize::new(10 * 1024 * 1024))
            .epoch_length(EpochLength::new(5))
            .max_view_time(Duration::from_secs(10))
            .log_events(false)
            .build();

        let replica = ReplicaSpec::builder()
            .app(app)
            .network(hotstuff_network_stubs[i].clone())
            .kv_store(kv_store)
            .configuration(config)
            .build()
            .start();

        replicas.push(replica);
    }

    println!(
        "Consensus running for {} seconds...",
        test_duration.as_secs()
    );
    thread::sleep(test_duration);
    producer_handle.join().unwrap();
    println!("Checking results...");

    // Consensus progress checking
    let mut final_heights = Vec::new();
    let polling_deadline = Instant::now() + Duration::from_secs(10);
    let mut success = false;

    while Instant::now() < polling_deadline {
        let mut heights = Vec::new();
        for replica in &replicas {
            let snapshot = replica.block_tree_camera().snapshot();
            if let Some(block_hash) = snapshot.highest_committed_block().unwrap() {
                let height = snapshot.block_height(&block_hash).unwrap().unwrap();
                heights.push(height.int());
            } else {
                heights.push(0);
            }
        }

        let first_height = heights[0];
        if first_height > 0 && heights.iter().all(|&h| h == first_height) {
            println!(
                "✅ Success! All nodes are in sync at height {}.",
                first_height
            );
            final_heights = heights;
            success = true;
            break;
        }

        println!("Polling... current heights: {:?}", heights);
        thread::sleep(Duration::from_secs(1));
    }

    if !success {
        panic!("Nodes did not sync up! Final heights: {:?}", final_heights);
    }
}
