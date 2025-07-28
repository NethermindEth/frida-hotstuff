use crate::defrida_proofs::{DefridaProof, ValidatorShare};
use hotstuff_rs::types::crypto_primitives::VerifyingKey;
use hotstuff_rs::types::data_types::{CryptoHash, ViewNumber};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

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
    StoreShare(ViewNumber, CryptoHash, VerifyingKey, ValidatorShare),
    RequestShare(ViewNumber, CryptoHash, VerifyingKey),
    ShareResponse(Option<ValidatorShare>),
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
    share_store:
        Arc<Mutex<HashMap<(ViewNumber, CryptoHash), HashMap<VerifyingKey, ValidatorShare>>>>,
    // The key is (ViewNumber, CryptoHash)
    proof_store: Arc<Mutex<HashMap<(ViewNumber, CryptoHash), HashMap<VerifyingKey, DefridaProof>>>>,
}

impl DefridaSideNetwork {
    pub fn start(
        rx: Receiver<(VerifyingKey, DefridaNetworkMessage)>,
        peers: HashMap<VerifyingKey, Sender<(VerifyingKey, DefridaNetworkMessage)>>,
    ) {
        let share_store = Arc::new(Mutex::new(HashMap::new()));
        let proof_store = Arc::new(Mutex::new(HashMap::new()));
        thread::spawn(move || {
            let side = DefridaSideNetwork {
                rx,
                peers,
                share_store,
                proof_store,
            };
            side.run();
        });
    }

    fn run(&self) {
        loop {
            if let Ok((sender_vk, message)) = self.rx.recv() {
                match message {
                    DefridaNetworkMessage::StoreShare(view, data_hash, validator_vk, share) => {
                        println!(
                            "[Side Network] Storing share for view {} hash {}... from proposer {} for validator {}",
                            view.int(), short_hash(&data_hash), short_key(&sender_vk), short_key(&validator_vk)
                        );
                        let mut store = self.share_store.lock().unwrap();
                        store
                            .entry((view, data_hash))
                            .or_default()
                            .insert(validator_vk, share);
                    }

                    DefridaNetworkMessage::StoreProof(view, data_hash, validator_vk, proof) => {
                        println!(
                            "[Side Network] Storing proof for view {} hash {}... from proposer {} for validator {}",
                            view.int(), short_hash(&data_hash), short_key(&sender_vk), short_key(&validator_vk)
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
                            view.int(), short_hash(&data_hash), short_key(&validator_vk)
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

                    DefridaNetworkMessage::RequestShare(view, data_hash, validator_vk) => {
                        println!(
                            "[Side Network] Received request for view {} hash {}... from validator {}",
                            view.int(), short_hash(&data_hash), short_key(&validator_vk)
                        );
                        let share = {
                            let store = self.share_store.lock().unwrap();
                            store
                                .get(&(view, data_hash))
                                .and_then(|s| s.get(&validator_vk).cloned())
                        };

                        if let Some(peer_tx) = self.peers.get(&sender_vk) {
                            let found_msg = if share.is_some() {
                                "Found and sending"
                            } else {
                                "Share not found for"
                            };
                            println!(
                                "[Side Network] {} share to {}",
                                found_msg,
                                short_key(&sender_vk)
                            );
                            let _ = peer_tx
                                .send((sender_vk, DefridaNetworkMessage::ShareResponse(share)));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
