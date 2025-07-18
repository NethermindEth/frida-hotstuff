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
    frida::FriData,
    logging::log_with_context,
    mem_db::MemDB,
};

pub type Blake3 = Blake3_256<BaseElement>;
pub type FridaHotstuffDasVerifier = FridaDasVerifier<BaseElement, Blake3, Blake3>;

pub struct FridaApp {
    tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    prover_builder: FridaProverBuilder<BaseElement, Blake3>,
    data_height: usize,
    data_width: usize,
}

pub struct FridaTransaction {
    data: Bytes,
}

impl From<FriData> for FridaTransaction {
    fn from(value: FriData) -> Self {
        let data: Vec<u8> = value.into();
        Self {
            data: Bytes::from(data),
        }
    }
}

impl FridaTransaction {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl App<MemDB> for FridaApp {
    fn produce_block(
        &mut self,
        _request: hotstuff_rs::app::ProduceBlockRequest<MemDB>, // no need to use this as we do not need to worry about the blockchain state
    ) -> ProduceBlockResponse {
        let mut tx_queue = self.tx_queue.lock().unwrap();
        let fri_data = self.create_fri_data(&tx_queue);
        let commitment = self.create_commitment(&fri_data);
        let data = Data::new(vec![
            Datum::new(commitment.to_bytes()),
            Datum::new(fri_data.into()),
        ]);

        let data_hash = self.calculate_data_hash(&data);

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
        let data_hash = self.calculate_data_hash(&data);

        if request.proposed_block().data_hash != data_hash {
            ValidateBlockResponse::Invalid
        } else {
            let commitment =
                Commitment::<Blake3_256<BaseElement>>::read_from_bytes(&data.vec()[0].bytes())
                    .unwrap();

            let result = FridaDasVerifier::<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
            >::new(commitment, self.prover_builder.options.clone());
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
        data_height: usize,
        data_width: usize,
    ) -> Self {
        Self {
            tx_queue,
            prover_builder,
            data_height,
            data_width,
        }
    }

    fn calculate_data_hash(&self, data: &Data) -> CryptoHash {
        let mut hasher = CryptoHasher::new();
        hasher.update(&data.vec()[0].bytes());
        hasher.update(&data.vec()[1].bytes());
        let bytes = hasher.finalize().into();
        CryptoHash::new(bytes)
    }

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
        log_with_context(
            None,
            &format!("Fri data length: {:?}", fri_data.data_list.len()),
        );

        fri_data
    }

    // create commitment (that include frida proof)
    fn create_commitment(&self, fri_data: &FriData) -> Commitment<Blake3_256<BaseElement>> {
        let num_queries = 1;
        let (commitment, _) = self
            .prover_builder
            .commit_batch(&fri_data.data_list, num_queries)
            .unwrap();

        commitment
    }
}

#[cfg(test)]
mod tests {
    use frida_poc::winterfell::FriOptions;

    use super::*;

    #[test]
    fn test_create_commitment() {
        let lde_blowup_e = 1;
        let folding_factor_e = 1;
        let max_remainder_degree = 1;
        let lde_blowup = 1 << lde_blowup_e;
        let folding_factor = 1 << folding_factor_e;
        let data_height = 100;
        let data_width = 100;

        let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);
        let prover_builder =
            FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(options.clone());

        let tx_queue = Arc::new(Mutex::new(Vec::new()));
        let frida_app = FridaApp::new(tx_queue.clone(), prover_builder, data_height, data_width);
        let fri_data = frida_app.create_fri_data(&vec![FridaTransaction::new(Bytes::from_static(
            b"1234567890",
        ))]);
        let commitment = frida_app.create_commitment(&fri_data);
        println!("Commitment: {:?}", commitment);
    }
}
