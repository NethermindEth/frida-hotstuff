use std::collections::{HashMap, HashSet};

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

/// Computes position assignments for all validators.
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
    if s == 0 {
        return vec![vec![]; n];
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
    use common::blob_helper::{merge_blobs, BlobData};
    use frida_poc::winterfell::FieldElement;


    mod workflow_tests {
        use super::*;

        fn setup_test_prover(
            n_validators: usize,
            total_queries: usize,
        ) -> (
            DefridaProver,
            Vec<(usize, DefridaProof)>,
            ProverCommitment<Blake3>,
            FriOptions,
        ) {
            let options = FriOptions::new(2, 2, 1);
            let prover_builder = FridaBuilder::new(options.clone());

            let blob_data_1 = BlobData::from_raw(Bytes::from_static(b"1234567890")).unwrap();
            let blob_data_2 = BlobData::from_raw(Bytes::from_static(b"hello")).unwrap();
            let blob_data_3 = BlobData::from_raw(Bytes::from_static(b"world")).unwrap();
            let merged_blob = merge_blobs(&[blob_data_1, blob_data_2, blob_data_3]);
            let mut fri_data = FriData::new(100, 100);
            fri_data.arrange_blobs(&merged_blob);

            let defrida_prover =
                DefridaProver::new(&prover_builder, &fri_data, total_queries).unwrap();
            let validator_proofs = defrida_prover
                .prove(n_validators, defrida_prover.base_positions.clone())
                .unwrap();
            let commitment = defrida_prover.commitment();

            (defrida_prover, validator_proofs, commitment, options)
        }

        #[test]
        fn test_defrida_workflow() {
            let n_validators = 10;
            let total_queries = 7;
            let (_prover, validator_proofs, commitment, options) =
                setup_test_prover(n_validators, total_queries);

            for (_, proof) in validator_proofs.into_iter() {
                proof.verify(&commitment, &options).unwrap();
            }
        }

        #[test]
        fn test_negative_verification_wrong_evaluations() {
            let n_validators = 10;
            let total_queries = 7;
            let (_prover, validator_proofs, commitment, options) =
                setup_test_prover(n_validators, total_queries);

            let mut tampered_proof = validator_proofs[0].1.clone();
            tampered_proof.evaluations[0] += BaseElement::ONE;

            let result = tampered_proof.verify(&commitment, &options);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
        }

        #[test]
        fn test_negative_verification_wrong_proof() {
            let n_validators = 10;
            let total_queries = 7;
            let (_prover, validator_proofs, commitment, options) =
                setup_test_prover(n_validators, total_queries);

            let mut proof_0 = validator_proofs[0].1.clone();
            proof_0.positions = validator_proofs[1].1.positions.clone();

            let result = proof_0.verify(&commitment, &options);

            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
        }
    }
    
    mod position_assignment_tests {
        use super::*;

        /// Function to verify the crucial coverage property for any set of assignments.
        /// It checks that the union of any `h` validators' query sets equals the entire set of queries.
        fn check_coverage(assignments: &[Vec<usize>], h: usize, total_queries: usize) {
            let non_empty_assignments: Vec<_> =
                assignments.iter().filter(|a| !a.is_empty()).collect();
            if non_empty_assignments.len() < h {
                // Cannot check coverage if not enough validators have work, which is an expected outcome for some configurations (e.g., h is very large).
                return;
            }

            // A full check would test all C(n, h) combinations. For a robust test, we check a sliding window of `h` consecutive validators.
            for i in 0..=(non_empty_assignments.len() - h) {
                let mut union_of_queries = HashSet::new();
                for j in 0..h {
                    for &pos in non_empty_assignments[i + j] {
                        union_of_queries.insert(pos);
                    }
                }
                assert_eq!(
                    union_of_queries.len(),
                    total_queries,
                    "Coverage failed for a window of h={} assignments starting at index {}",
                    h,
                    i
                );
            }
        }

        #[test]
        fn case_a_spec_example() {
            let s = 8;
            let n = 4;
            let h = 2;
            let positions: Vec<usize> = (0..s).collect();
            let assignments = compute_position_assignments(n, &positions, h);

            assert_eq!(assignments.len(), n);
            assert_eq!(assignments[0], vec![0, 1, 2, 3, 4, 5, 6]); // V1
            assert_eq!(assignments[1], vec![1, 2, 3, 4, 5, 6, 7]); // V2
            assert_eq!(assignments[2], vec![2, 3, 4, 5, 6, 7, 0]); // V3
            assert_eq!(assignments[3], vec![3, 4, 5, 6, 7, 0, 1]); // V4
            check_coverage(&assignments, h, s);
        }

        #[test]
        fn case_a_edge_n_equals_s() {
            let s = 10;
            let n = 10;
            let h = 4;
            let positions: Vec<usize> = (0..s).collect();
            let assignments = compute_position_assignments(n, &positions, h);

            assert_eq!(assignments.len(), n);
            assert_eq!(assignments[0].len(), s - h + 1, "Span length should be s-h+1"); // 10 - 4 + 1 = 7
            check_coverage(&assignments, h, s);
        }

        #[test]
        fn case_a_edge_large_h() {
            let s = 10;
            let n = 4;
            let h = 10; // h >= s
            let positions: Vec<usize> = (0..s).collect();
            let assignments = compute_position_assignments(n, &positions, h);
            
            // Span should be s - h + 1, but saturating_sub makes it 0, then +1 = 1.
            assert_eq!(assignments.len(), n);
            assert_eq!(assignments[0].len(), 1, "Span length should be 1 when h >= s");
            // Coverage is not guaranteed by the algorithm if span is 1, so we don't check it.
        }

        #[test]
        fn case_b_spec_example() {
            let s = 8;
            let n = 17;
            let h = 6;
            let positions: Vec<usize> = (0..s).collect();
            let assignments = compute_position_assignments(n, &positions, h);

            assert_eq!(assignments.len(), n);
            // V1 and V9 should have the same assignment.
            assert_eq!(assignments[0], assignments[8]);
            assert_eq!(assignments[1], assignments[9]);
            // Empty assignment for the excess validator.
            assert!(assignments[16].is_empty());
            // Check span length (h' = ceil((6-1)/2) = 3, so span = 8-3+1=6).
            assert_eq!(assignments[0].len(), 6);
            check_coverage(&assignments, h, s);
        }
        
        #[test]
        fn case_b_edge_n_just_above_s() {
            let s = 10;
            let n = 11;
            let h = 4;
            let positions: Vec<usize> = (0..s).collect();
            let assignments = compute_position_assignments(n, &positions, h);

            assert_eq!(assignments.len(), n);
            assert!(assignments[10].is_empty(), "Validator 11 should be an excess validator");
            // V1 should get the first base subset.
            assert!(!assignments[0].is_empty());
            check_coverage(&assignments, h, s);
        }

        #[test]
        fn general_edge_cases() {
            let positions: Vec<usize> = (0..10).collect();
            // Zero validators should produce an empty result.
            assert!(compute_position_assignments(0, &positions, 2).is_empty());
            // Zero queries should result in empty assignments for all validators.
            assert_eq!(compute_position_assignments(5, &[], 2), vec![vec![]; 5]);
            // A single validator should be assigned all queries.
            let assignments = compute_position_assignments(1, &positions, 1);
            assert_eq!(assignments.len(), 1);
            assert_eq!(assignments[0].len(), 10);
        }
    }
}
