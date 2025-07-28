use benchmark_common::data::FriData;
use frida_poc::{
    frida_data::build_evaluations_from_data,
    frida_error::FridaError,
    frida_prover::{
        batch_data_to_evaluations, get_evaluations_from_positions, proof::FridaProof, FridaProver,
        FridaProverBuilder, ProverCommitment,
    },
    frida_verifier::das::FridaDasVerifier,
    winterfell::{
        f128::BaseElement, Blake3_256, ByteReader, Deserializable, DeserializationError,
        FriOptions, Serializable,
    },
};
use std::collections::HashMap;
use winter_utils::ByteWriter;

use crate::errors::DefridaError;

type Blake3 = Blake3_256<BaseElement>;
type FridaBuilder = FridaProverBuilder<BaseElement, Blake3>;

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

// --- Core Data Structures ---

/// The payload sent to a single validator. It contains the minimal information
/// needed to verify their share against the public commitment from the block header.
#[derive(Clone, Debug)]
pub struct ValidatorShare {
    /// The individual proof for this specific validator.
    pub proof: FridaProof,
    /// The query positions assigned to this validator.
    pub positions: Vec<usize>,
    /// The evaluation values for the assigned positions.
    pub evaluations: Vec<BaseElement>,
}

// --- Proposer API & Workflow ---

pub struct DefridaProver {
    prover: FridaProver<BaseElement, Blake3>,
    commitment: ProverCommitment<Blake3>,
    // The proposer holds all evaluations to distribute the necessary slices to validators.
    all_evaluations: Vec<BaseElement>,
    options: FriOptions,
    poly_count: usize,
}

impl DefridaProver {
    pub fn new(
        prover_builder: &FridaProverBuilder<BaseElement, Blake3>,
        fri_data: &FriData,
    ) -> Result<Self, FridaError> {
        let (commitment, prover) =
            prover_builder.calculate_commitment_batch(&fri_data.data_list)?;

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
        total_queries: usize,
    ) -> Result<Vec<(usize, DefridaProof)>, DefridaError> {
        if n_validators == 0 {
            return Err(DefridaError::InvalidNumValidators);
        }

        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let base_positions: Vec<usize> = (0..total_queries).collect();
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

pub struct Proposer {
    prover: FridaProver<BaseElement, Blake3>,
    commitment: ProverCommitment<Blake3>,
    // The proposer holds all evaluations to distribute the necessary slices to validators.
    all_evaluations: Vec<BaseElement>,
}

impl Proposer {
    /// Creates a new Proposer by committing to the given data.
    pub fn new(data: &[u8], options: FriOptions) -> Result<Self, FridaError> {
        let prover_builder = FridaBuilder::new(options.clone());
        let (commitment, prover) = prover_builder.calculate_commitment(data)?;

        // The proposer must calculate all evaluations once to distribute them to validators.
        let all_evaluations = build_evaluations_from_data::<BaseElement>(
            data,
            commitment.domain_size,
            options.blowup_factor(),
        )?;

        Ok(Proposer {
            prover,
            commitment,
            all_evaluations,
        })
    }

    /// Generates the public commitment and the set of ValidatorShare objects.
    pub fn generate_artifacts(
        &self,
        n_validators: usize,
        total_queries: usize,
    ) -> (ProverCommitment<Blake3>, Vec<Option<ValidatorShare>>) {
        if n_validators == 0 {
            return (
                ProverCommitment {
                    roots: self.commitment.roots.clone(),
                    domain_size: self.commitment.domain_size,
                    poly_count: self.commitment.poly_count,
                },
                vec![],
            );
        }

        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let base_positions: Vec<usize> = (0..total_queries).collect();
        let validator_positions_sets =
            compute_position_assignments(n_validators, &base_positions, h);

        let mut proof_cache: HashMap<Vec<usize>, FridaProof> = HashMap::new();

        let validator_shares = validator_positions_sets
            .into_iter()
            .map(|positions| {
                if positions.is_empty() {
                    None
                } else {
                    let proof = proof_cache
                        .entry(positions.clone())
                        .or_insert_with(|| self.prover.open(&positions))
                        .clone();

                    // Look up the specific evaluation values for this validator's positions.
                    let evaluations = positions.iter().map(|&p| self.all_evaluations[p]).collect();

                    Some(ValidatorShare {
                        proof,
                        positions,
                        evaluations,
                    })
                }
            })
            .collect();

        (
            ProverCommitment {
                roots: self.commitment.roots.clone(),
                domain_size: self.commitment.domain_size,
                poly_count: self.commitment.poly_count,
            },
            validator_shares,
        )
    }
}

// --- Validator API & Workflow ---

pub struct Validator;

impl Validator {
    /// Verifies a validator's share using the public commitment from the block header.
    pub fn verify_share(
        public_commitment: &ProverCommitment<Blake3>,
        share: &ValidatorShare,
        options: &FriOptions,
    ) -> Result<(), FridaError> {
        // 1. Initialize a verifier from the lightweight public commitment.
        let verifier = FridaDasVerifier::<BaseElement, Blake3, Blake3>::from_commitment(
            public_commitment,
            options.clone(),
        )?;

        // 2. Verify the proof using the positions and evaluations provided in the share.
        //    The validator does NOT need the full data block.
        verifier.verify(&share.proof, &share.evaluations, &share.positions)
    }
}

// --- Algorithm Implementation & Helpers ---

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

impl Serializable for ValidatorShare {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
        self.positions.write_into(target);
        self.evaluations.write_into(target);
    }
}

impl Deserializable for ValidatorShare {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = FridaProof::read_from(source)?;
        let positions = Vec::<usize>::read_from(source)?;
        let evaluations = Vec::<BaseElement>::read_from(source)?;
        Ok(ValidatorShare {
            proof,
            positions,
            evaluations,
        })
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use frida_poc::winterfell::rand_vector;
    use frida_poc::winterfell::FieldElement;

    /// Tests the full end-to-end workflow.
    #[test]
    fn test_defrida_workflow() {
        let data = rand_vector::<u8>(1024);
        let options = FriOptions::new(8, 4, 63);
        let n_validators = 10;
        let total_queries = 16;

        let proposer = Proposer::new(&data, options.clone()).unwrap();
        let (public_commitment, validator_shares) =
            proposer.generate_artifacts(n_validators, total_queries);

        // Each validator receives their share and verifies it against the public commitment.
        for share in validator_shares.into_iter().flatten() {
            let result = Validator::verify_share(&public_commitment, &share, &options);
            assert!(result.is_ok(), "Validator share verification failed");
        }
    }

    /// Tests the serialization and deserialization of ValidatorShare.
    #[test]
    fn test_validator_share_serialization() {
        let data = rand_vector::<u8>(256);
        let options = FriOptions::new(4, 2, 15);

        let proposer = Proposer::new(&data, options.clone()).unwrap();
        let (public_commitment, shares) = proposer.generate_artifacts(5, 8);
        let share = shares[0].clone().unwrap();

        let serialized_share = share.to_bytes();
        assert!(!serialized_share.is_empty());
        let deserialized_share = ValidatorShare::read_from_bytes(&serialized_share).unwrap();

        // Check that all fields were correctly deserialized.
        assert_eq!(share.positions, deserialized_share.positions);
        assert_eq!(share.evaluations, deserialized_share.evaluations);

        // Verify that the deserialized share is still valid against the original public commitment.
        let result = Validator::verify_share(&public_commitment, &deserialized_share, &options);
        assert!(result.is_ok(), "Verification of deserialized share failed");
    }

    /// Tests that verification fails if a validator receives a share with tampered evaluations.
    #[test]
    fn test_negative_verification_wrong_evaluations() {
        let data = rand_vector::<u8>(512);
        let options = FriOptions::new(4, 2, 15);

        let proposer = Proposer::new(&data, options.clone()).unwrap();
        let (public_commitment, shares) = proposer.generate_artifacts(5, 8);

        let mut tampered_share = shares[0].as_ref().unwrap().clone();
        // Tamper with the evaluation values.
        tampered_share.evaluations[0] += BaseElement::ONE;

        let result = Validator::verify_share(&public_commitment, &tampered_share, &options);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
    }

    /// Tests that verification fails if a proof for one validator is used with another's positions.
    #[test]
    fn test_negative_verification_wrong_proof() {
        let data = rand_vector::<u8>(512);
        let options = FriOptions::new(4, 2, 15);

        let proposer = Proposer::new(&data, options.clone()).unwrap();
        let (public_commitment, shares) = proposer.generate_artifacts(5, 8);

        // Take validator 0's proof and evaluations...
        let mut malicious_share = shares[0].as_ref().unwrap().clone();
        // ...but replace its positions with validator 1's positions.
        malicious_share.positions = shares[1].as_ref().unwrap().positions.clone();

        let result = Validator::verify_share(&public_commitment, &malicious_share, &options);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
    }

    /// Rigorously tests the coverage property of the PointSampling algorithm.
    #[test]
    fn test_coverage_property() {
        let test_cases = vec![
            (10, 16), // Case A
            (20, 16), // Case B
            (7, 7),   // Edge case n = s
            (40, 8),  // Case B with high replication
            (3, 100), // Case A with h=2, should cover all
        ];

        for (n_validators, total_queries) in test_cases {
            let f = (n_validators - 1) / 3;
            let h = f + 1;
            let base_positions: Vec<usize> = (0..total_queries).collect();
            let assignments = compute_position_assignments(n_validators, &base_positions, h);

            let non_empty_assignments: Vec<_> =
                assignments.iter().filter(|a| !a.is_empty()).collect();

            if non_empty_assignments.len() < h {
                continue;
            }

            // Check the first `h` validators.
            let mut union_of_queries = HashSet::new();
            for i in 0..h {
                for &pos in non_empty_assignments[i] {
                    union_of_queries.insert(pos);
                }
            }

            assert_eq!(
                union_of_queries.len(),
                total_queries,
                "Coverage failed for n={}, s={}",
                n_validators,
                total_queries
            );
        }
    }
}
