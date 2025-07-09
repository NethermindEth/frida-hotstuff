use bytes::Bytes;
use ed25519_dalek::SigningKey;
use hotstuff_rs::types::{data_types::Power, update_sets::ValidatorSetUpdates};
use rand_core::OsRng;

use crate::{
    frida_app::FridaTransaction,
    logging::log_with_context,
    test::{network::mock_network, node::Node},
};

#[test]
fn test_simple_frida_app() {
    let lde_blowup_e = 1;
    let folding_factor_e = 1;
    let max_remainder_degree = 1;

    // 1.1. Generate signing keys for 4 replicas.
    let mut csprg = OsRng {};
    let keypairs: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut csprg)).collect();

    // 1.2. Create a mock network connecting the 3 replicas.
    let network_stubs = mock_network(keypairs.iter().map(|kp| kp.verifying_key()));

    // 1.4. Initialize the validator set of the cluster to contain 4 replicas.
    let init_vs_updates = {
        let mut vs_updates = ValidatorSetUpdates::new();
        vs_updates.insert(keypairs[0].verifying_key(), Power::new(1));
        vs_updates.insert(keypairs[1].verifying_key(), Power::new(1));
        vs_updates.insert(keypairs[2].verifying_key(), Power::new(1));
        vs_updates
    };

    // 1.5. Simultaneously start the first 3 replicas.
    let live_nodes: Vec<Node> = keypairs
        .into_iter()
        .zip(network_stubs)
        .map(|(keypair, network)| {
            Node::new(
                keypair.clone(),
                network,
                lde_blowup_e,
                folding_factor_e,
                max_remainder_degree,
                init_vs_updates.clone(),
            )
        })
        .collect();

    log_with_context(
        None,
        "Submitting transactions to each of replica 0 and replica 1.",
    );
    live_nodes[0].send_transaction(vec![FridaTransaction::new(Bytes::from_static(
        b"1234567890",
    ))]);

    live_nodes[1].send_transaction(vec![FridaTransaction::new(Bytes::from_static(b"hello"))]);

    std::thread::sleep(std::time::Duration::from_secs(10));
}
