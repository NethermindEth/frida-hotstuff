
use std::sync::{Arc, Mutex};
use hotstuff_rs::app::{
    App, ProduceBlockRequest, ProduceBlockResponse, ValidateBlockRequest, ValidateBlockResponse,
};
use hotstuff_rs::block_tree::pluggables::KVStore;
use hotstuff_rs::types::crypto_primitives::VerifyingKey;
use hotstuff_rs::types::data_types::{CryptoHash, Data, Datum};
use frida_poc::frida_prover::{FridaProverBuilder, ProverCommitment};
use frida_poc::winterfell::{
    f128::BaseElement, Blake3_256, ByteReader, Deserializable, DeserializationError,
    Serializable,
};
use winter_crypto::Hasher;
use winter_utils::ByteWriter;

use crate::defrida_proofs::{Proposer, Validator, ValidatorShare};
use crate::network::{DefridaNetworkHandle, DefridaNetworkMessage};

type Blake3 = Blake3_256<BaseElement>;

// --- Logging Helper Functions ---
fn short_key(key: &VerifyingKey) -> String {
    let bytes = key.as_bytes();
    format!("{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2])
}

fn short_hash(hash: &CryptoHash) -> String {
    let bytes = hash.bytes();
    format!("{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2])
}

#[derive(Clone)]
pub struct DefridaBlockData {
    pub commitment: ProverCommitment<Blake3>,
}

impl Serializable for DefridaBlockData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.commitment.write_into(target);
    }
}

impl Deserializable for DefridaBlockData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let commitment = ProverCommitment::<Blake3>::read_from(source)?;
        Ok(DefridaBlockData { commitment })
    }
}

pub struct DefridaApp<K: KVStore> {
    network_handle: DefridaNetworkHandle,
    my_verifying_key: VerifyingKey,
    tx_pool: Arc<Mutex<Vec<Vec<u8>>>>,
    prover_builder: FridaProverBuilder<BaseElement, Blake3>,
    total_queries: usize,
    _marker: std::marker::PhantomData<K>,
}

impl<K: KVStore> DefridaApp<K> {
    pub fn new(
        network_handle: DefridaNetworkHandle,
        my_verifying_key: VerifyingKey,
        tx_pool: Arc<Mutex<Vec<Vec<u8>>>>,
        prover_builder: FridaProverBuilder<BaseElement, Blake3>,
        total_queries: usize,
    ) -> Self {
        Self {
            network_handle,
            my_verifying_key,
            tx_pool,
            prover_builder,
            total_queries,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<K: KVStore + 'static> App<K> for DefridaApp<K> {
    fn produce_block(&mut self, request: ProduceBlockRequest<K>) -> ProduceBlockResponse {
        let data = self.tx_pool.lock().unwrap().pop().unwrap_or_default();

        if data.is_empty() {
            let empty_data_hash = CryptoHash::new(Blake3::hash(&[]).to_bytes().try_into().unwrap());
            return ProduceBlockResponse {
                data_hash: empty_data_hash,
                data: Data::new(vec![Datum::new(vec![])]),
                app_state_updates: None,
                validator_set_updates: None,
            };
        }

        println!("[Proposer {}] Producing block for data of size {}", short_key(&self.my_verifying_key), data.len());

        let proposer = Proposer::new(&data, self.prover_builder.options.clone()).unwrap();

        let validator_set = request.block_tree().validator_set().unwrap();
        let n_validators = validator_set.len();
        let artifacts = proposer.generate_artifacts(n_validators, self.total_queries);

        let block_data = DefridaBlockData {
            commitment: artifacts.commitment,
        };

        let serialized_block_data = block_data.to_bytes();
        let data_hash = CryptoHash::new(Blake3::hash(&serialized_block_data).to_bytes().try_into().unwrap());
        println!("[Proposer {}] Generated data hash: {}", short_key(&self.my_verifying_key), short_hash(&data_hash));

        // Distribute shares.
        for (i, share_option) in artifacts.validator_shares.into_iter().enumerate() {
            if let Some(share) = share_option {
                if let Some(validator_vk) = validator_set.validators().nth(i) {
                    self.network_handle
                        .tx
                        .send((
                            self.my_verifying_key,
                            DefridaNetworkMessage::StoreShare(data_hash, *validator_vk, share),
                        ))
                        .unwrap();
                }
            }
        }

        ProduceBlockResponse {
            data_hash,
            data: Data::new(vec![Datum::new(serialized_block_data)]),
            app_state_updates: None,
            validator_set_updates: None,
        }
    }

    fn validate_block(&mut self, request: ValidateBlockRequest<K>) -> ValidateBlockResponse {
        let proposed_block = request.proposed_block();
        let block_data_bytes = &proposed_block.data.vec()[0].bytes();

        if block_data_bytes.is_empty() {
            return ValidateBlockResponse::Valid {
                app_state_updates: None,
                validator_set_updates: None,
            };
        }

        let block_data = match DefridaBlockData::read_from_bytes(block_data_bytes) {
            Ok(data) => data,
            Err(_) => {
                println!("[Validator {}] ❌ FAILED to deserialize block data for hash: {}", short_key(&self.my_verifying_key), short_hash(&proposed_block.data_hash));
                return ValidateBlockResponse::Invalid;
            }
        };

        self.network_handle
            .tx
            .send((
                self.my_verifying_key,
                DefridaNetworkMessage::RequestShare(proposed_block.data_hash, self.my_verifying_key),
            ))
            .unwrap();

        match self.network_handle.rx.lock().unwrap().recv_timeout(std::time::Duration::from_secs(5)) {
            Ok((_, DefridaNetworkMessage::ShareResponse(Some(share)))) => {
                println!("[Validator {}] Received share for hash: {}", short_key(&self.my_verifying_key), short_hash(&proposed_block.data_hash));
                
                // Get options from the app's prover_builder.
                let options = self.prover_builder.options.clone();

                match Validator::verify_share(&block_data.commitment, &share, &options) {
                    Ok(_) => {
                        println!("[Validator {}] ✅ Share verification SUCCESSFUL for hash: {}", short_key(&self.my_verifying_key), short_hash(&proposed_block.data_hash));
                        ValidateBlockResponse::Valid {
                            app_state_updates: None,
                            validator_set_updates: None,
                        }
                    }
                    Err(e) => {
                        println!("[Validator {}] ❌ Share verification FAILED for hash: {}, Error: {:?}", short_key(&self.my_verifying_key), short_hash(&proposed_block.data_hash), e);
                        ValidateBlockResponse::Invalid
                    }
                }
            }
            Ok((_, DefridaNetworkMessage::ShareResponse(None))) => {
                println!("[Validator {}] ❌ Did not receive a share from network for block hash {}", short_key(&self.my_verifying_key), short_hash(&proposed_block.data_hash));
                ValidateBlockResponse::Invalid
            }
            Err(e) => {
                println!("[Validator {}] ❌ Error/Timeout receiving share from network: {:?} for block hash {}", short_key(&self.my_verifying_key), e, short_hash(&proposed_block.data_hash));
                ValidateBlockResponse::Invalid
            }
            _ => ValidateBlockResponse::Invalid,
        }
    }

    fn validate_block_for_sync(&mut self, request: ValidateBlockRequest<K>) -> ValidateBlockResponse {
        self.validate_block(request)
    }
}