pub mod app;
pub mod defrida_proofs;
pub mod errors;
pub mod network;

use hotstuff_rs::types::data_types::ViewNumber;
use std::collections::HashMap;

pub struct ProofStatistics {
    pub min_proof_size: usize,
    pub max_proof_size: usize,
    pub mean_proof_size: usize,
    pub total_individual_proofs: usize,
    pub total_views: usize,
    pub total_size: usize,
    pub average_size_per_view: usize,
}

pub fn defrida_proof_calculation(
    proof_store: &HashMap<
        (ViewNumber, hotstuff_rs::types::data_types::CryptoHash),
        HashMap<
            hotstuff_rs::types::crypto_primitives::VerifyingKey,
            crate::defrida_proofs::DefridaProof,
        >,
    >,
) -> ProofStatistics {
    // Calculate total size of proofs for each view
    let mut view_sizes: HashMap<ViewNumber, usize> = HashMap::new();
    let mut min_proof_size = usize::MAX;
    let mut max_proof_size = 0;
    let mut total_individual_proofs = 0;
    let mut sum_individual_proof_sizes = 0;

    for ((view, _), proofs) in proof_store.iter() {
        let mut total_size = 0;
        for (_, proof) in proofs.iter() {
            // Calculate size of this proof - using a simpler approach
            let proof_size = std::mem::size_of_val(&proof.proof);
            let positions_size = proof.positions.len() * std::mem::size_of::<usize>();
            let evaluations_size = proof.evaluations.len()
                * std::mem::size_of::<frida_poc::winterfell::f128::BaseElement>();
            let total_proof_size = proof_size + positions_size + evaluations_size;

            // Track min and max individual proof sizes
            min_proof_size = min_proof_size.min(total_proof_size);
            max_proof_size = max_proof_size.max(total_proof_size);

            // Track sum for mean calculation
            sum_individual_proof_sizes += total_proof_size;
            total_individual_proofs += 1;

            total_size += total_proof_size;
        }

        view_sizes.insert(*view, total_size);
        println!(
            "View {}: Total proof size = {} bytes ({} proofs)",
            view.int(),
            total_size,
            proofs.len()
        );
    }

    // Calculate mean proof size across all views
    let mean_proof_size = if total_individual_proofs > 0 {
        sum_individual_proof_sizes / total_individual_proofs
    } else {
        0
    };

    // Calculate summary statistics
    let total_views = view_sizes.len();
    let total_size: usize = view_sizes.values().sum();
    let average_size_per_view = if total_views > 0 {
        total_size / total_views
    } else {
        0
    };

    // Handle case where no proofs were found
    let (min_proof_size, max_proof_size) = if min_proof_size != usize::MAX {
        (min_proof_size, max_proof_size)
    } else {
        (0, 0)
    };

    ProofStatistics {
        min_proof_size,
        max_proof_size,
        mean_proof_size,
        total_individual_proofs,
        total_views,
        total_size,
        average_size_per_view,
    }
}

// // Calculate mean proof size across all views
// let mean_proof_size = sum_individual_proof_sizes / total_individual_proofs;

// // Print summary
// let total_views = view_sizes.len();
// let total_size: usize = view_sizes.values().sum();
// println!("\nSummary:");
// println!("Total views: {}", total_views);
// println!("Total proof size across all views: {} bytes", total_size);
// if total_views > 0 {
//     println!(
//         "Average proof size per view: {} bytes",
//         total_size / total_views
//     );
// }
// if min_proof_size != usize::MAX {
//     println!("Minimum individual proof size: {} bytes", min_proof_size);
//     println!("Maximum individual proof size: {} bytes", max_proof_size);
//     println!("Mean individual proof size: {} bytes", mean_proof_size);
//     println!("Total individual proofs: {}", total_individual_proofs);
// }

// pub fn create_app(tx_queue: Arc<Mutex<Vec<FridaTransaction>>>, fri_option:
// FriOptions) {     let prover_builder =
//         FridaProverBuilder::<BaseElement,
// Blake3_256<BaseElement>>::new(fri_option.clone()); }
// pub fn create_app(
//     tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
//     fri_option: FriOptions,
//     height: usize,
//     width: usize,
// ) -> FridaApp {
//     let prover_builder =
//         FridaProverBuilder::<BaseElement,
// Blake3_256<BaseElement>>::new(fri_option.clone());
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
