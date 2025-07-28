use benchmark_common::blob_helper::{merge_blobs, YodaBlobData};
use benchmark_common::data::{FriData, FridaTransaction};
use frida_poc::frida_prover::{FridaProverBuilder, ProverCommitment};
use frida_poc::winterfell::{
    f128::BaseElement, Blake3_256, ByteReader, Deserializable, DeserializationError, Serializable,
};
use hotstuff_rs::app::{
    App, ProduceBlockRequest, ProduceBlockResponse, ValidateBlockRequest, ValidateBlockResponse,
};
use hotstuff_rs::block_tree::pluggables::KVStore;
use hotstuff_rs::types::crypto_primitives::VerifyingKey;
use hotstuff_rs::types::data_types::{CryptoHash, Data, Datum, ViewNumber};
use std::sync::{Arc, Mutex};
use winter_crypto::Hasher;
use winter_utils::ByteWriter;

use crate::defrida_proofs::{DefridaProver, Proposer, Validator};
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

pub struct DefridaBlockData {
    pub commitment: ProverCommitment<Blake3>,
    pub view: ViewNumber,
}

impl Clone for DefridaBlockData {
    fn clone(&self) -> Self {
        Self {
            commitment: ProverCommitment {
                roots: self.commitment.roots.clone(),
                domain_size: self.commitment.domain_size,
                poly_count: self.commitment.poly_count,
            },
            view: self.view,
        }
    }
}

impl Serializable for DefridaBlockData {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.commitment.write_into(target);
        target.write_u64(self.view.int());
    }
}

impl Deserializable for DefridaBlockData {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let commitment = ProverCommitment::<Blake3>::read_from(source)?;
        let view = ViewNumber::new(source.read_u64()?);
        Ok(DefridaBlockData { commitment, view })
    }
}

pub struct DefridaApp<K: KVStore> {
    network_handle: DefridaNetworkHandle,
    my_verifying_key: VerifyingKey,
    tx_pool: Arc<Mutex<Vec<FridaTransaction>>>,
    prover_builder: FridaProverBuilder<BaseElement, Blake3>,
    total_queries: usize,
    data_height: usize,
    data_width: usize,
    _marker: std::marker::PhantomData<K>,
}

impl<K: KVStore> DefridaApp<K> {
    pub fn new(
        network_handle: DefridaNetworkHandle,
        my_verifying_key: VerifyingKey,
        tx_pool: Arc<Mutex<Vec<FridaTransaction>>>,
        prover_builder: FridaProverBuilder<BaseElement, Blake3>,
        total_queries: usize,
        data_height: usize,
        data_width: usize,
    ) -> Self {
        Self {
            network_handle,
            my_verifying_key,
            tx_pool,
            prover_builder,
            total_queries,
            data_height,
            data_width,
            _marker: std::marker::PhantomData,
        }
    }

    // TODO: refactor this to reuse FridaApp also has the exact same function
    // read transaction from tx_queue
    // combine data into data structure
    fn create_fri_data(&self, transactions: &Vec<FridaTransaction>) -> FriData {
        let mut yoda_blob = vec![];
        for tx in transactions {
            yoda_blob.push(YodaBlobData::from_raw(tx.data.clone()).unwrap());
        }

        let merged_blob = merge_blobs(&yoda_blob);

        let mut fri_data = FriData::new(self.data_height, self.data_width);
        fri_data.arrange_blobs(&merged_blob);

        fri_data
    }
}

impl<K: KVStore + 'static> App<K> for DefridaApp<K> {
    fn produce_block(&mut self, request: ProduceBlockRequest<K>) -> ProduceBlockResponse {
        let mut tx_pool = self.tx_pool.lock().unwrap();
        let fri_data = self.create_fri_data(&tx_pool);
        // let commitment = self.create_commitment(&fri_data);

        // let data = self.tx_pool.lock().unwrap().pop().unwrap();
        let current_view = request.cur_view();

        let (commitment, _) = self
            .prover_builder
            .calculate_commitment_batch(&fri_data.data_list)
            .unwrap();

        let defrida_prover = DefridaProver::new(&self.prover_builder, &fri_data).unwrap();

        let validator_set = request.block_tree().validator_set().unwrap();
        let n_validators = validator_set.len();
        let validator_proofs = defrida_prover
            .prove(n_validators, self.total_queries)
            .unwrap();

        // if data.is_empty() {
        //     let empty_data_hash = CryptoHash::new(Blake3::hash(&[]).to_bytes().try_into().unwrap());
        //     return ProduceBlockResponse {
        //         data_hash: empty_data_hash,
        //         data: Data::new(vec![Datum::new(vec![])]),
        //         app_state_updates: None,
        //         validator_set_updates: None,
        //     };
        // }

        // fn create_commitment(&self, fri_data: &FriData) -> Commitment<Blake3_256<BaseElement>> {
        //     let num_queries = 1;
        //     let (commitment, _) = self
        //         .prover_builder
        //         .commit_batch(&fri_data.data_list, num_queries)
        //         .unwrap();

        //     commitment
        // }
        // let (commitment, prover) = prover_builder.commit_to_data(data)?;

        // let proposer = Proposer::new(&data, self.prover_builder.options.clone()).unwrap();

        // let validator_set = request.block_tree().validator_set().unwrap();
        // let n_validators = validator_set.len();
        // let (commitment, validator_shares) =
        //     proposer.generate_artifacts(n_validators, self.total_queries);

        let block_data = DefridaBlockData {
            commitment,
            view: current_view,
        };

        let serialized_block_data = block_data.to_bytes();
        let data_hash = CryptoHash::new(
            Blake3::hash(&serialized_block_data)
                .to_bytes()
                .try_into()
                .unwrap(),
        );
        println!(
            "[Proposer {}] Generated data hash: {}",
            short_key(&self.my_verifying_key),
            short_hash(&data_hash)
        );

        for (i, proof) in validator_proofs.into_iter() {
            if let Some(validator_vk) = validator_set.validators().nth(i) {
                self.network_handle
                    .tx
                    .send((
                        self.my_verifying_key,
                        DefridaNetworkMessage::StoreProof(
                            current_view,
                            data_hash,
                            *validator_vk,
                            proof,
                        ),
                    ))
                    .unwrap();
            }
        }

        // for (i, share_option) in validator_shares.into_iter().enumerate() {
        //     if let Some(share) = share_option {
        //         if let Some(validator_vk) = validator_set.validators().nth(i) {
        //             self.network_handle
        //                 .tx
        //                 .send((
        //                     self.my_verifying_key,
        //                     DefridaNetworkMessage::StoreShare(
        //                         current_view,
        //                         data_hash,
        //                         *validator_vk,
        //                         share,
        //                     ),
        //                 ))
        //                 .unwrap();
        //         }
        //     }
        // }

        tx_pool.clear();
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
            Err(_) => return ValidateBlockResponse::Invalid,
        };

        let proposal_view = block_data.view;
        println!(
            "[Validator {}] Validating block from view {} with hash: {}",
            short_key(&self.my_verifying_key),
            proposal_view.int(),
            short_hash(&proposed_block.data_hash)
        );

        // self.network_handle
        //     .tx
        //     .send((
        //         self.my_verifying_key,
        //         DefridaNetworkMessage::RequestShare(
        //             proposal_view,
        //             proposed_block.data_hash,
        //             self.my_verifying_key,
        //         ),
        //     ))
        //     .unwrap();

        self.network_handle
            .tx
            .send((
                self.my_verifying_key,
                DefridaNetworkMessage::RequestProof(
                    proposal_view,
                    proposed_block.data_hash,
                    self.my_verifying_key,
                ),
            ))
            .unwrap();

        match self
            .network_handle
            .rx
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(5))
        {
            Ok((_, DefridaNetworkMessage::ProofResponse(Some(proof)))) => {
                println!(
                    "[Validator {}] Received share for hash: {}",
                    short_key(&self.my_verifying_key),
                    short_hash(&proposed_block.data_hash)
                );

                let options = self.prover_builder.options.clone();
                match proof.verify(&block_data.commitment, &options) {
                    Ok(_) => {
                        println!(
                            "[Validator {}] ✅ Share verification SUCCESSFUL for hash: {}",
                            short_key(&self.my_verifying_key),
                            short_hash(&proposed_block.data_hash)
                        );
                        ValidateBlockResponse::Valid {
                            app_state_updates: None,
                            validator_set_updates: None,
                        }
                    }
                    Err(e) => ValidateBlockResponse::Invalid,
                }
            }
            Ok((_, DefridaNetworkMessage::ProofResponse(None))) => {
                println!(
                    "[Validator {}] ❌ Did not receive a proof for view {} hash {}",
                    short_key(&self.my_verifying_key),
                    proposal_view.int(),
                    short_hash(&proposed_block.data_hash)
                );
                ValidateBlockResponse::Invalid
            }
            Err(e) => {
                println!(
                    "[Validator {}] ❌ Error/Timeout receiving proof for view {} hash {}: {:?}",
                    short_key(&self.my_verifying_key),
                    proposal_view.int(),
                    short_hash(&proposed_block.data_hash),
                    e
                );
                ValidateBlockResponse::Invalid
            }
            _ => ValidateBlockResponse::Invalid,
        }

        // match self
        //     .network_handle
        //     .rx
        //     .lock()
        //     .unwrap()
        //     .recv_timeout(std::time::Duration::from_secs(5))
        // {
        //     Ok((_, DefridaNetworkMessage::ShareResponse(Some(share)))) => {
        //         println!(
        //             "[Validator {}] Received share for hash: {}",
        //             short_key(&self.my_verifying_key),
        //             short_hash(&proposed_block.data_hash)
        //         );

        //         let options = self.prover_builder.options.clone();
        //         match Validator::verify_share(&block_data.commitment, &share, &options) {
        //             Ok(_) => {
        //                 println!(
        //                     "[Validator {}] ✅ Share verification SUCCESSFUL for hash: {}",
        //                     short_key(&self.my_verifying_key),
        //                     short_hash(&proposed_block.data_hash)
        //                 );
        //                 ValidateBlockResponse::Valid {
        //                     app_state_updates: None,
        //                     validator_set_updates: None,
        //                 }
        //             }
        //             Err(e) => {
        //                 println!(
        //                     "[Validator {}] ❌ Share verification FAILED for hash: {}, Error: {:?}",
        //                     short_key(&self.my_verifying_key),
        //                     short_hash(&proposed_block.data_hash),
        //                     e
        //                 );
        //                 ValidateBlockResponse::Invalid
        //             }
        //         }
        //     }
        //     Ok((_, DefridaNetworkMessage::ShareResponse(None))) => {
        //         println!(
        //             "[Validator {}] ❌ Did not receive a share for view {} hash {}",
        //             short_key(&self.my_verifying_key),
        //             proposal_view.int(),
        //             short_hash(&proposed_block.data_hash)
        //         );
        //         ValidateBlockResponse::Invalid
        //     }
        //     Err(e) => {
        //         println!(
        //             "[Validator {}] ❌ Error/Timeout receiving share for view {} hash {}: {:?}",
        //             short_key(&self.my_verifying_key),
        //             proposal_view.int(),
        //             short_hash(&proposed_block.data_hash),
        //             e
        //         );
        //         ValidateBlockResponse::Invalid
        //     }
        //     _ => ValidateBlockResponse::Invalid,
        // }
    }

    fn validate_block_for_sync(
        &mut self,
        request: ValidateBlockRequest<K>,
    ) -> ValidateBlockResponse {
        self.validate_block(request)
    }
}
