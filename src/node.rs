use std::sync::{Arc, Mutex};

use frida_poc::{
    frida_prover::FridaProverBuilder,
    winterfell::{Blake3_256, FriOptions, f128::BaseElement},
};

use crate::frida_app::FridaTransaction;

pub struct Node {
    tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    prover: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>>,
}

impl Node {
    pub fn new(
        trace_length_e: i32,
        lde_blowup_e: i32,
        folding_factor_e: i32,
        max_remainder_degree: usize,
    ) -> Self {
        let trace_length = 1 << trace_length_e;
        let lde_blowup = 1 << lde_blowup_e;
        let folding_factor = 1 << folding_factor_e;

        let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);
        let prover_builder =
            FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(options.clone());

        let tx_queue = Arc::new(Mutex::new(Vec::new()));

        Self {
            tx_queue,
            prover: prover_builder,
        }
    }
}
