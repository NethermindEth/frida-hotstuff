use std::collections::HashMap;

use hotstuff_rs::types::data_types::ViewNumber;

pub mod app;
pub mod defrida_proofs;
pub mod errors;
pub mod network;

#[derive(Debug, Clone, Copy)]
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
        HashMap<hotstuff_rs::types::crypto_primitives::VerifyingKey, defrida_proofs::DefridaProof>,
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
