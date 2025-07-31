use std::{
    collections::HashMap,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex,
    },
    thread,
};

use hotstuff_rs::types::{
    crypto_primitives::VerifyingKey,
    data_types::{CryptoHash, ViewNumber},
};

use crate::defrida_proofs::DefridaProof;

// --- Logging Helper Functions ---
fn short_key(key: &VerifyingKey) -> String {
    let bytes = key.as_bytes();
    format!("{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2])
}

fn short_hash(hash: &CryptoHash) -> String {
    let bytes = hash.bytes();
    format!("{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2])
}

pub enum DefridaNetworkMessage {
    StoreProof(ViewNumber, CryptoHash, VerifyingKey, DefridaProof),
    RequestProof(ViewNumber, CryptoHash, VerifyingKey),
    ProofResponse(Option<DefridaProof>),
}

#[derive(Clone)]
pub struct DefridaNetworkHandle {
    pub tx: Sender<(VerifyingKey, DefridaNetworkMessage)>,
    pub rx: Arc<Mutex<Receiver<(VerifyingKey, DefridaNetworkMessage)>>>,
}

pub struct DefridaSideNetwork {
    rx: Receiver<(VerifyingKey, DefridaNetworkMessage)>,
    peers: HashMap<VerifyingKey, Sender<(VerifyingKey, DefridaNetworkMessage)>>,
    // The key is (ViewNumber, CryptoHash)
    proof_store: Arc<Mutex<HashMap<(ViewNumber, CryptoHash), HashMap<VerifyingKey, DefridaProof>>>>,
}

impl DefridaSideNetwork {
    pub fn start(
        rx: Receiver<(VerifyingKey, DefridaNetworkMessage)>,
        peers: HashMap<VerifyingKey, Sender<(VerifyingKey, DefridaNetworkMessage)>>,
    ) -> Arc<Mutex<HashMap<(ViewNumber, CryptoHash), HashMap<VerifyingKey, DefridaProof>>>> {
        let proof_store = Arc::new(Mutex::new(HashMap::new()));
        let proof_store_clone = proof_store.clone();
        thread::spawn(move || {
            let side = DefridaSideNetwork {
                rx,
                peers,
                proof_store: proof_store_clone,
            };
            side.run();
        });
        proof_store
    }

    fn run(&self) {
        loop {
            if let Ok((sender_vk, message)) = self.rx.recv() {
                match message {
                    DefridaNetworkMessage::StoreProof(view, data_hash, validator_vk, proof) => {
                        println!(
                            "[Side Network] Storing proof for view {} hash {}... from proposer {} for validator {}",
                            view.int(),
                            short_hash(&data_hash),
                            short_key(&sender_vk),
                            short_key(&validator_vk)
                        );
                        let mut store = self.proof_store.lock().unwrap();
                        store
                            .entry((view, data_hash))
                            .or_default()
                            .insert(validator_vk, proof);
                    }

                    DefridaNetworkMessage::RequestProof(view, data_hash, validator_vk) => {
                        println!(
                            "[Side Network] Received request for view {} hash {}... from validator {}",
                            view.int(),
                            short_hash(&data_hash),
                            short_key(&validator_vk)
                        );
                        let proof = {
                            let store = self.proof_store.lock().unwrap();
                            store
                                .get(&(view, data_hash))
                                .and_then(|s| s.get(&validator_vk).cloned())
                        };

                        if let Some(peer_tx) = self.peers.get(&sender_vk) {
                            let found_msg = if proof.is_some() {
                                "Found and sending"
                            } else {
                                "Proof not found for"
                            };
                            println!(
                                "[Side Network] {} proof to {}",
                                found_msg,
                                short_key(&sender_vk)
                            );
                            let _ = peer_tx
                                .send((sender_vk, DefridaNetworkMessage::ProofResponse(proof)));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
