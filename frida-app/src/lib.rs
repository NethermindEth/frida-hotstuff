use std::sync::{Arc, Mutex};

use frida_poc::{
    frida_prover::FridaProverBuilder,
    winterfell::{Blake3_256, FriOptions, f128::BaseElement},
};

use crate::frida_app::{FridaApp, FridaTransaction};

pub mod frida_app;
pub mod logging;
pub mod mem_db;
pub mod network;

#[cfg(test)]
pub mod test;

pub fn create_app(
    tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    fri_option: FriOptions,
    height: usize,
    width: usize,
) -> FridaApp {
    let prover_builder =
        FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(fri_option.clone());
    FridaApp::new(tx_queue, prover_builder, height, width)
}
