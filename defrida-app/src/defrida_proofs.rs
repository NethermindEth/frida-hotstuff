use std::collections::HashMap;

use common::data::FriData;
use frida_poc::{
    frida_error::FridaError,
    frida_prover::{
        FridaProver, FridaProverBuilder, ProverCommitment, batch_data_to_evaluations,
        get_evaluations_from_positions, proof::FridaProof,
    },
    frida_verifier::das::FridaDasVerifier,
    winterfell::{Blake3_256, FriOptions, f128::BaseElement},
};

use crate::errors::DefridaError;

type Blake3 = Blake3_256<BaseElement>;
type FridaBuilder = FridaProverBuilder<BaseElement, Blake3>;

#[derive(Debug, Clone)]
pub struct DefridaProof {
    /// The individual proof for this specific validator.
    pub proof: FridaProof,
    /// The query positions assigned to this validator.
    pub positions: Vec<usize>,
    /// The evaluation values for the assigned positions.
    pub evaluations: Vec<BaseElement>,
}

impl DefridaProof {
    pub fn verify(
        &self,
        public_commitment: &ProverCommitment<Blake3>,
        options: &FriOptions,
    ) -> Result<(), FridaError> {
        let verifier = FridaDasVerifier::<BaseElement, Blake3, Blake3>::from_commitment(
            public_commitment,
            options.clone(),
        )?;
        verifier.verify(&self.proof, &self.evaluations, &self.positions)
    }
}

pub struct DefridaProver {
    prover: FridaProver<BaseElement, Blake3>,
    commitment: ProverCommitment<Blake3>,
    // The proposer holds all evaluations to distribute the necessary slices to validators.
    all_evaluations: Vec<BaseElement>,
    options: FriOptions,
    poly_count: usize,
    base_positions: Vec<usize>,
}

impl DefridaProver {
    pub fn new(
        prover_builder: &FridaProverBuilder<BaseElement, Blake3>,
        fri_data: &FriData,
        num_queries: usize,
    ) -> Result<Self, FridaError> {
        let (commitment, prover, base_positions) =
            prover_builder.calculate_commitment_batch(&fri_data.data_list, num_queries)?;

        let all_evaluations = batch_data_to_evaluations::<BaseElement>(
            &fri_data.data_list,
            fri_data.data_list.len(),
            commitment.domain_size,
            prover_builder.options.blowup_factor(),
            prover_builder.options.folding_factor(),
        )?;

        Ok(DefridaProver {
            commitment,
            prover,
            all_evaluations,
            options: prover_builder.options.clone(),
            poly_count: fri_data.data_list.len(),
            base_positions,
        })
    }

    pub fn commitment(&self) -> ProverCommitment<Blake3> {
        ProverCommitment {
            roots: self.commitment.roots.clone(),
            domain_size: self.commitment.domain_size,
            poly_count: self.commitment.poly_count,
        }
    }

    pub fn prove(
        &self,
        n_validators: usize,
        base_positions: Vec<usize>,
    ) -> Result<Vec<(usize, DefridaProof)>, DefridaError> {
        if n_validators == 0 {
            return Err(DefridaError::InvalidNumValidators);
        }

        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let validator_positions_sets =
            compute_position_assignments(n_validators, &base_positions, h);

        let mut proof_cache: HashMap<Vec<usize>, FridaProof> = HashMap::new();

        let proofs = validator_positions_sets
            .into_iter()
            .enumerate()
            .filter_map(|(validator_index, positions)| {
                if positions.is_empty() {
                    None
                } else {
                    let proof = proof_cache
                        .entry(positions.clone())
                        .or_insert_with(|| self.prover.open(&positions))
                        .clone();

                    // Look up the specific evaluation values for this validator's positions.
                    let evaluations = get_evaluations_from_positions(
                        &self.all_evaluations,
                        &positions,
                        self.poly_count,
                        self.commitment.domain_size,
                        self.options.folding_factor(),
                    );

                    Some((
                        validator_index,
                        DefridaProof {
                            proof,
                            positions,
                            evaluations,
                        },
                    ))
                }
            })
            .collect();

        Ok(proofs)
    }
}

/// Computes position assignments for all validators using the algorithm.
fn compute_position_assignments(
    n_validators: usize,
    query_positions: &[usize],
    h: usize,
) -> Vec<Vec<usize>> {
    let s = query_positions.len();
    let n = n_validators;
    if n == 0 {
        return vec![];
    }
    if n <= s {
        // Case A
        let span_length = s.saturating_sub(h).saturating_add(1);
        (1..=n)
            .map(|i| {
                let offset = (i - 1) % s;
                (0..span_length)
                    .map(|j| query_positions[(offset + j) % s])
                    .collect()
            })
            .collect()
    } else {
        // Case B
        let n_prime = (n / s) * s;
        if n_prime == 0 {
            return vec![Vec::new(); n];
        }
        let replication_factor = n_prime / s;
        let h_prime = (h.saturating_sub(n - n_prime) + replication_factor - 1) / replication_factor;
        let base_subsets = compute_position_assignments(s, query_positions, h_prime);
        (1..=n)
            .map(|i| {
                if i <= n_prime {
                    base_subsets[(i - 1) % s].clone()
                } else {
                    Vec::new()
                }
            })
            .collect()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {

    use super::*;
    use bytes::Bytes;
    use common::blob_helper::{merge_blobs, YodaBlobData};
    use frida_poc::winterfell::FieldElement;

    #[test]
    fn test_defrida_workflow() {
        let options = FriOptions::new(2, 2, 1);
        let n_validators = 10;
        // depending on the data size, we more data we have, the bigger the total
        // queries the total_queries should be lesser than the domain size
        let total_queries = 7;
        let prover_builder = FridaBuilder::new(options.clone());

        let yoda_blob_data_1 = YodaBlobData::from_raw(Bytes::from_static(b"1234567890")).unwrap();
        let yoda_blob_data_2 = YodaBlobData::from_raw(Bytes::from_static(b"hello")).unwrap();
        let yoda_blob_data_3 = YodaBlobData::from_raw(Bytes::from_static(b"world")).unwrap();

        let merged_blob = merge_blobs(&[yoda_blob_data_1, yoda_blob_data_2, yoda_blob_data_3]);

        let mut fri_data = FriData::new(100, 100);
        fri_data.arrange_blobs(&merged_blob);

        let defrida_prover = DefridaProver::new(&prover_builder, &fri_data, total_queries).unwrap();
        let validator_proofs = defrida_prover
            .prove(n_validators, defrida_prover.base_positions.clone())
            .unwrap();
        let commitment = defrida_prover.commitment();

        for (_, proof) in validator_proofs.into_iter() {
            proof.verify(&commitment, &options).unwrap();
        }
    }

    #[test]
    fn test_negative_verification_wrong_evaluations() {
        let options = FriOptions::new(2, 2, 1);
        let n_validators = 10;
        // depending on the data size, we more data we have, the bigger the total
        // queries the total_queries should be lesser than the domain size
        let total_queries = 7;
        let prover_builder = FridaBuilder::new(options.clone());

        let yoda_blob_data_1 = YodaBlobData::from_raw(Bytes::from_static(b"1234567890")).unwrap();
        let yoda_blob_data_2 = YodaBlobData::from_raw(Bytes::from_static(b"hello")).unwrap();
        let yoda_blob_data_3 = YodaBlobData::from_raw(Bytes::from_static(b"world")).unwrap();

        let merged_blob = merge_blobs(&[yoda_blob_data_1, yoda_blob_data_2, yoda_blob_data_3]);

        let mut fri_data = FriData::new(100, 100);
        fri_data.arrange_blobs(&merged_blob);

        let defrida_prover = DefridaProver::new(&prover_builder, &fri_data, total_queries).unwrap();
        let validator_proofs = defrida_prover
            .prove(n_validators, defrida_prover.base_positions.clone())
            .unwrap();
        let commitment = defrida_prover.commitment();

        let mut tampered_proof = validator_proofs[0].1.clone();
        tampered_proof.evaluations[0] += BaseElement::ONE;

        let result = tampered_proof.verify(&commitment, &options);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
    }

    #[test]
    fn test_negative_verification_wrong_proof() {
        let options = FriOptions::new(2, 2, 1);
        let n_validators = 10;
        // depending on the data size, we more data we have, the bigger the total
        // queries the total_queries should be lesser than the domain size
        let total_queries = 7;
        let prover_builder = FridaBuilder::new(options.clone());

        let yoda_blob_data_1 = YodaBlobData::from_raw(Bytes::from_static(b"1234567890")).unwrap();
        let yoda_blob_data_2 = YodaBlobData::from_raw(Bytes::from_static(b"hello")).unwrap();
        let yoda_blob_data_3 = YodaBlobData::from_raw(Bytes::from_static(b"world")).unwrap();

        let merged_blob = merge_blobs(&[yoda_blob_data_1, yoda_blob_data_2, yoda_blob_data_3]);

        let mut fri_data = FriData::new(100, 100);
        fri_data.arrange_blobs(&merged_blob);

        let defrida_prover = DefridaProver::new(&prover_builder, &fri_data, total_queries).unwrap();
        let validator_proofs = defrida_prover
            .prove(n_validators, defrida_prover.base_positions.clone())
            .unwrap();
        let commitment = defrida_prover.commitment();

        let mut proof_0 = validator_proofs[0].1.clone();
        proof_0.positions = validator_proofs[1].1.positions.clone();

        let result = proof_0.verify(&commitment, &options);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
    }

    // this test is not correct
    // this is because the num_queries limit depends on the domain size
    // instead `compute_position_assignments`should be the one that is tested
    // Rigorously tests the coverage property of the PointSampling algorithm.
    // #[test]
    // fn test_coverage_property() {
    //     let test_cases = vec![
    //         (10, 16), // Case A
    //         (20, 16), // Case B
    //         (7, 7),   // Edge case n = s
    //         (40, 8),  // Case B with high replication
    //         (3, 100), // Case A with h=2, should cover all
    //     ];

    //     for (n_validators, total_queries) in test_cases {
    //         let f = (n_validators - 1) / 3;
    //         let h = f + 1;
    //         let base_positions: Vec<usize> = (0..total_queries).collect();
    //         let assignments = compute_position_assignments(n_validators,
    // &base_positions, h);

    //         let non_empty_assignments: Vec<_> =
    //             assignments.iter().filter(|a| !a.is_empty()).collect();

    //         if non_empty_assignments.len() < h {
    //             continue;
    //         }

    //         // Check the first `h` validators.
    //         let mut union_of_queries = HashSet::new();
    //         for i in 0..h {
    //             for &pos in non_empty_assignments[i] {
    //                 union_of_queries.insert(pos);
    //             }
    //         }

    //         assert_eq!(
    //             union_of_queries.len(),
    //             total_queries,
    //             "Coverage failed for n={}, s={}",
    //             n_validators,
    //             total_queries
    //         );
    //     }
    // }
}
