//! Implements the distributed data availability proof workflow using the `frida-poc` library.
//!
//! This module provides a high-level API for proposers and validators.

use frida_poc::{
    frida_data::build_evaluations_from_data,
    frida_error::FridaError,
    frida_prover::{proof::FridaProof, FridaProver, FridaProverBuilder, ProverCommitment},
    frida_verifier::das::FridaDasVerifier,
    winterfell::{
        f128::BaseElement, Blake3_256, ByteReader, Deserializable, DeserializationError,
        FriOptions, Hasher, Serializable,
    },
};

use winter_utils::ByteWriter;

use std::collections::{HashMap, HashSet};


type Blake3 = Blake3_256<BaseElement>;
type FridaBuilder = FridaProverBuilder<BaseElement, Blake3>;

// --- Core Data Structures ---

/// A self-contained share of the proof and data sent to a single validator.
#[derive(Clone, Debug)]
pub struct ValidatorShare {
    /// The public shared commitment.
    pub commitment: ProverCommitment<Blake3>,
    /// The individual proof for this specific validator.
    pub proof: FridaProof,
    /// The query positions assigned to this validator.
    pub positions: Vec<usize>,
    /// The full original data block.
    pub data: Vec<u8>,
}

// --- Proposer API & Workflow ---

pub struct Proposer {
    prover: FridaProver<BaseElement, Blake3>,
    commitment: ProverCommitment<Blake3>,
    data: Vec<u8>,
}

impl Proposer {
    /// Creates a new Proposer by committing to the given data.
    pub fn new(data: &[u8], options: FriOptions) -> Result<Self, FridaError> {
        let prover_builder = FridaBuilder::new(options);
        let (commitment, prover) = prover_builder.commit_to_data(data)?;
        Ok(Proposer {
            prover,
            commitment,
            data: data.to_vec(),
        })
    }

    /// Returns the public commitment.
    pub fn commitment(&self) -> &ProverCommitment<Blake3> {
        &self.commitment
    }

    /// Generates the set of `ValidatorShare` objects to be sent to each validator.
    ///
    /// This method implements proof caching to avoid re-generating proofs for validators
    /// that share the same set of query positions, which is common when n > s.
    pub fn generate_validator_shares(
        &self,
        n_validators: usize,
        total_queries: usize,
    ) -> Vec<Option<ValidatorShare>> {
        if n_validators == 0 {
            return vec![];
        }

        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let base_positions: Vec<usize> = (0..total_queries).collect();
        let validator_positions = compute_position_assignments(n_validators, &base_positions, h);

        let mut proof_cache: HashMap<Vec<usize>, FridaProof> = HashMap::new();

        validator_positions
            .into_iter()
            .map(|positions| {
                if positions.is_empty() {
                    None
                } else {
                    let proof = proof_cache
                        .entry(positions.clone())
                        .or_insert_with(|| self.prover.open(&positions))
                        .clone();

                    Some(ValidatorShare {
                        commitment: self.commitment.clone(),
                        proof,
                        positions,
                        data: self.data.clone(),
                    })
                }
            })
            .collect()
    }
}

// --- Validator API & Workflow ---

pub struct Validator;

impl Validator {
    /// Verifies a self-contained validator's proof share.
    pub fn verify_share(
        share: &ValidatorShare,
        options: &FriOptions,
    ) -> Result<(), FridaError> {
        // 1. Initialize a verifier from the public commitment in the share.
        let verifier = FridaDasVerifier::<BaseElement, Blake3, Blake3>::from_commitment(
            &share.commitment,
            options.clone(),
        )?;

        // 2. The validator derives the evaluation values for their specific positions from the data in the share.
        let all_evaluations = build_evaluations_from_data::<BaseElement>(
            &share.data,
            share.commitment.domain_size,
            options.blowup_factor(),
        )?;
        let validator_evaluations: Vec<BaseElement> = share
            .positions
            .iter()
            .map(|&p| all_evaluations[p])
            .collect();

        // 3. Verify the specific proof.
        verifier.verify(&share.proof, &validator_evaluations, &share.positions)
    }
}

// --- Algorithm Implementation & Helpers ---

/// Computes position assignments for all validators using the PointSampling algorithm.
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
        // Case A: n <= s
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
        // Case B: n > s
        let n_prime = (n / s) * s;
        if n_prime == 0 {
            return vec![Vec::new(); n];
        }
        let replication_factor = n_prime / s;
        let h_prime =
            (h.saturating_sub(n - n_prime) + replication_factor - 1) / replication_factor;
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
        self.commitment.write_into(target);
        self.proof.write_into(target);
        self.positions.write_into(target);
        // Also serialize the data length and the data itself
        target.write_u64(self.data.len() as u64);
        target.write_bytes(&self.data);
    }
}

impl Deserializable for ValidatorShare {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let commitment = ProverCommitment::<Blake3>::read_from(source)?;
        let proof = FridaProof::read_from(source)?;
        let positions = Vec::<usize>::read_from(source)?;
        // Also deserialize the data
        let data_len = source.read_u64()? as usize;
        let data = source.read_vec(data_len)?;

        Ok(ValidatorShare {
            commitment,
            proof,
            positions,
            data,
        })
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use frida_poc::winterfell::rand_vector;

    /// Tests the full end-to-end workflow using the Proposer/Validator APIs.
    #[test]
    fn test_proposer_validator_workflow() {
        let data = rand_vector::<u8>(1024);
        let options = FriOptions::new(8, 4, 63);
        let n_validators = 10;
        let total_queries = 16;

        let proposer = Proposer::new(&data, options.clone()).unwrap();
        let shares = proposer.generate_validator_shares(n_validators, total_queries);

        for share in shares.into_iter().flatten() {
            let result = Validator::verify_share(&share, &options);
            assert!(result.is_ok(), "Validator share verification failed");
        }
    }

    /// Tests the serialization and deserialization of the self-contained ValidatorShare.
    #[test]
    fn test_validator_share_serialization() {
        let data = rand_vector::<u8>(256);
        let options = FriOptions::new(4, 2, 15);

        let proposer = Proposer::new(&data, options.clone()).unwrap();
        let shares = proposer.generate_validator_shares(5, 8);
        let share = shares[0].clone().unwrap();

        // Serialize the share to bytes.
        let serialized_share = share.to_bytes();
        assert!(!serialized_share.is_empty());

        // Deserialize the share from bytes.
        let deserialized_share = ValidatorShare::read_from_bytes(&serialized_share).unwrap();
        
        // Check that the data was correctly deserialized
        assert_eq!(share.data, deserialized_share.data);

        // Verify that the deserialized share is still valid.
        let result = Validator::verify_share(&deserialized_share, &options);
        assert!(result.is_ok(), "Verification of deserialized share failed");
    }

    /// Tests that verification fails if a validator receives a share with tampered data.
    #[test]
    fn test_negative_verification_wrong_data() {
        let original_data = rand_vector::<u8>(512);
        let options = FriOptions::new(4, 2, 15);

        let proposer = Proposer::new(&original_data, options.clone()).unwrap();
        let shares = proposer.generate_validator_shares(5, 8);
        
        // Take a valid share and tamper with its data field.
        let mut tampered_share = shares[0].as_ref().unwrap().clone();
        tampered_share.data = rand_vector::<u8>(512); // Different data

        let result = Validator::verify_share(&tampered_share, &options);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
    }

    /// Tests that verification fails if a proof for one validator is used with another's positions.
    #[test]
    fn test_negative_verification_wrong_proof() {
        let data = rand_vector::<u8>(512);
        let options = FriOptions::new(4, 2, 15);

        let proposer = Proposer::new(&data, options.clone()).unwrap();
        let shares = proposer.generate_validator_shares(5, 8);
        
        // Take validator 0's share...
        let mut malicious_share = shares[0].as_ref().unwrap().clone();
        // ...but replace its positions with validator 1's positions.
        malicious_share.positions = shares[1].as_ref().unwrap().positions.clone();

        let result = Validator::verify_share(&malicious_share, &options);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FridaError::FailToVerify);
    }

    /// Tests the coverage property of the algorithm.
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

            let non_empty_assignments: Vec<_> = assignments.iter().filter(|a| !a.is_empty()).collect();

            if non_empty_assignments.len() < h {
                continue; // Cannot check coverage if not enough validators have work.
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
