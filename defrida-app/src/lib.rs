pub mod app;
pub mod defrida_proofs;
pub mod network;
pub mod errors;

// pub fn create_app(tx_queue: Arc<Mutex<Vec<FridaTransaction>>>, fri_option: FriOptions) {
//     let prover_builder =
//         FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(fri_option.clone());
// }
// pub fn create_app(
//     tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
//     fri_option: FriOptions,
//     height: usize,
//     width: usize,
// ) -> FridaApp {
//     let prover_builder =
//         FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(fri_option.clone());
//     FridaApp::new(tx_queue, prover_builder, height, width)
// }

// pub struct DefridaApp<K: KVStore> {
//     network_handle: DefridaNetworkHandle,
//     my_verifying_key: VerifyingKey,
//     tx_pool: Arc<Mutex<Vec<Vec<u8>>>>,
//     prover_builder: FridaProverBuilder<BaseElement, Blake3>,
//     total_queries: usize,
//     _marker: std::marker::PhantomData<K>,
// }

// impl<K: KVStore> DefridaApp<K> {
//     pub fn new(
//         network_handle: DefridaNetworkHandle,
//         my_verifying_key: VerifyingKey,
//         tx_pool: Arc<Mutex<Vec<Vec<u8>>>>,
//         prover_builder: FridaProverBuilder<BaseElement, Blake3>,
//         total_queries: usize,
//     ) -> Self {
//         Self {
//             network_handle,
//             my_verifying_key,
//             tx_pool,
//             prover_builder,
//             total_queries,
//             _marker: std::marker::PhantomData,
//         }
//     }
// }
