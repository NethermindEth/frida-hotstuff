use std::sync::{Arc, Mutex};

use bytes::Bytes;
use frida_poc::{
    frida_prover::{Commitment, FridaProverBuilder},
    frida_verifier::das::FridaDasVerifier,
    winterfell::{Blake3_256, Serializable, f128::BaseElement},
};
use hotstuff_rs::{
    app::{App, ProduceBlockResponse, ValidateBlockResponse},
    types::{
        crypto_primitives::{CryptoHasher, Digest},
        data_types::{CryptoHash, Data, Datum},
    },
};
use winter_utils::Deserializable;

use crate::{
    blob_helper::{YodaBlobData, merge_blobs},
    frida::arrange_blobs,
    mem_db::MemDB,
};

pub type Blake3 = Blake3_256<BaseElement>;
pub type FridaHotstuffDasVerifier = FridaDasVerifier<BaseElement, Blake3, Blake3>;

pub struct FridaApp {
    tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    prover_builder: FridaProverBuilder<BaseElement, Blake3>,
}

pub struct FridaTransaction {
    data: Bytes,
}

impl App<MemDB> for FridaApp {
    fn produce_block(
        &mut self,
        _request: hotstuff_rs::app::ProduceBlockRequest<MemDB>, // no need to use this as we do not need to worry about the blockchain state
    ) -> ProduceBlockResponse {
        let mut tx_queue = self.tx_queue.lock().unwrap();
        let commitment = self.create_commitment(&tx_queue);
        let data = Data::new(vec![Datum::new(commitment.to_bytes())]);

        let data_hash = {
            let mut hasher = CryptoHasher::new();
            hasher.update(&data.vec()[0].bytes());
            let bytes = hasher.finalize().into();
            CryptoHash::new(bytes)
        };

        tx_queue.clear();

        ProduceBlockResponse {
            data_hash,
            data,
            app_state_updates: None, // no need to update any state as we only require validators to verify only
            validator_set_updates: None,
        }
    }

    fn validate_block(
        &mut self,
        request: hotstuff_rs::app::ValidateBlockRequest<MemDB>,
    ) -> ValidateBlockResponse {
        self.validate_block_for_sync(request)
    }

    fn validate_block_for_sync(
        &mut self,
        request: hotstuff_rs::app::ValidateBlockRequest<MemDB>,
    ) -> ValidateBlockResponse {
        let data = &request.proposed_block().data;
        let data_hash: CryptoHash = {
            let mut hasher = CryptoHasher::new();
            hasher.update(&data.vec()[0].bytes());
            let bytes = hasher.finalize().into();
            CryptoHash::new(bytes)
        };

        if request.proposed_block().data_hash != data_hash {
            ValidateBlockResponse::Invalid
        } else {
            let commitment =
                Commitment::<Blake3_256<BaseElement>>::read_from_bytes(&data.vec()[0].bytes())
                    .unwrap();

            // this new method aldy contains check for the valid commitment in the block header
            let result =
                FridaHotstuffDasVerifier::new(commitment, self.prover_builder.options.clone());

            match result {
                Ok(_) => ValidateBlockResponse::Valid {
                    app_state_updates: None,
                    validator_set_updates: None,
                },
                Err(_) => ValidateBlockResponse::Invalid,
            }
        }
    }
}

impl FridaApp {
    pub fn new(
        tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
        prover_builder: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>>,
    ) -> Self {
        Self {
            tx_queue,
            prover_builder,
        }
    }

    fn create_commitment(
        &self,
        transactions: &Vec<FridaTransaction>,
    ) -> Commitment<Blake3_256<BaseElement>> {
        // read transaction from tx_queue
        // combine data into data structure
        // create commitment (that include frida proof)

        let mut yoda_blob = vec![];
        for tx in transactions {
            yoda_blob.push(YodaBlobData::from_raw(tx.data.clone()).unwrap());
        }

        let merged_blob = merge_blobs(&yoda_blob);
        let fri_data = arrange_blobs(&merged_blob);

        let num_queries = 1;
        let (commitment, _) = self
            .prover_builder
            .commit_batch(&fri_data.data_list, num_queries)
            .unwrap();

        commitment
    }
}
