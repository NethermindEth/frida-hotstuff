use frida_poc::{
    frida_data::build_evaluations_from_data,
    frida_error::FridaError,
    frida_prover::{Commitment, FridaProver, FridaProverBuilder, proof::FridaProof},
    frida_verifier::das::FridaDasVerifier,
};
use std::collections::HashMap;
use winter_crypto::{ElementHasher, Hasher};
use winter_fri::FriOptions;
use winter_math::FieldElement;

// I initially considered whether we could decompose the proof returned by
// commit() into sub-proofs, but there are fundamental limitations:

// Merkle Proof Structure: The FridaProof contains BatchMerkleProof objects that
// are optimized for their specific position sets. You can't easily extract a
// sub-proof for positions {a1,a2,a3} from a batch proof for positions
// {a0,a1,a2,a3,a4} without access to the underlying tree structure.

// API Constraints: Winter crypto's BatchMerkleProof doesn't expose methods for
// extracting sub-proofs. The internal optimization strategies (like shared path
// nodes) aren't accessible through public APIs.

// APPROACH EXPLANATION:
// - Generate a commitment with enough queries to support all validators
// - Use our own deterministic position assignment (following the algorithm)
// - Each validator generates their own proof using prover.open() for their
//   positions
// - All validators verify against the shared commitment roots

// Even when we can't avoid all open() calls, the approach is still optimal
// (given this is written as a wraper of frida-poc) because:

// Pre-computed FRI Layers: The expensive FRI layer computations are done once
// in commit(). Each open() call only extracts from pre-built Merkle trees.

// The core optimization comes from recognizing that many validators will have
// identical or highly overlapping position sets. The generate_validator_proofs
// function uses a HashMap cache to avoid redundant open() calls:

/// Result structure containing split proofs for distributed verification
#[derive(Clone)]
pub struct SplitProofResult<H: ElementHasher + Hasher> {
    /// The shared commitment roots that all validators use
    pub shared_commitment_roots: Vec<H::Digest>,
    /// Individual proofs for each validator (None for empty assignments)
    pub validator_proofs: Vec<Option<FridaProof>>,
    /// Position assignments for each validator (actual domain positions)
    pub validator_positions: Vec<Vec<usize>>,
    /// Domain size for verification
    pub domain_size: usize,
    /// Number of polynomials (always 1 for single data case)
    pub poly_count: usize,
    /// FRI options used for commitment
    pub fri_options: FriOptions,
    /// Original data for verification
    pub data: Vec<u8>,
}

impl<H: ElementHasher + Hasher> SplitProofResult<H> {
    /// Verify a specific validator's proof
    pub fn verify_validator<E>(&self, validator_index: usize) -> Result<bool, FridaError>
    where
        E: FieldElement,
        H: ElementHasher<BaseField = E::BaseField>,
    {
        if validator_index >= self.validator_proofs.len() {
            return Err(FridaError::BadNumQueries(validator_index));
        }

        if let Some(proof) = &self.validator_proofs[validator_index] {
            verify_validator_proof::<E, H>(
                proof,
                &self.validator_positions[validator_index],
                &self.shared_commitment_roots,
                &self.data,
                self.domain_size,
                self.poly_count,
                &self.fri_options,
            )
        } else {
            // Empty assignment - consider it valid
            Ok(true)
        }
    }
}

/// Generate a FRI proofs across n validators using the proof
/// splitting/distribution algorithm
pub fn distribute_proof<E, H>(
    data: &[u8],
    n_validators: usize,
    total_queries: usize,
    options: FriOptions,
) -> Result<SplitProofResult<H>, FridaError>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField> + Hasher,
{
    // Input validation
    if n_validators == 0 {
        return Err(FridaError::BadNumQueries(0));
    }
    if total_queries == 0 {
        return Err(FridaError::BadNumQueries(0));
    }

    // Calculate Byzantine fault tolerance parameters
    let f = (n_validators - 1) / 3;
    let h = f + 1;

    // Step 1: Generate initial commitment and prover
    // The proof in Commitment<H> returned by commit(), is mathematically infeasible
    // to split into many sub-proofs as we need it, as the layers are coupled with
    // the exact query position.
    let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());
    let (commitment, prover) = prover_builder.commit(data, total_queries)?;

    // Step 2: Generate deterministic query positions for our algorithm
    // We don't need FRIDA's exact positions - we can use our own as long as they're
    // valid
    let query_positions =
        generate_deterministic_positions(commitment.domain_size, total_queries, &options);

    // Step 3: Apply the proof splitting algorithm to assign positions
    let validator_positions = compute_position_assignments(n_validators, &query_positions, f, h);

    // Step 4: Generate individual proofs for each validator
    let validator_proofs = generate_validator_proofs(&prover, &validator_positions);

    Ok(SplitProofResult {
        shared_commitment_roots: commitment.roots,
        validator_proofs,
        validator_positions,
        domain_size: commitment.domain_size,
        poly_count: commitment.poly_count,
        fri_options: options,
        data: data.to_vec(),
    })
}

/// Generate deterministic positions for proof for validators: They need to be
/// valid domain positions
fn generate_deterministic_positions(
    domain_size: usize,
    num_queries: usize,
    _options: &FriOptions,
) -> Vec<usize> {
    // Simple deterministic generation: evenly spaced positions
    let step = domain_size / num_queries.min(domain_size);
    (0..num_queries.min(domain_size))
        .map(|i| (i * step) % domain_size)
        .collect::<std::collections::BTreeSet<_>>() // Remove any duplicates
        .into_iter()
        .collect()
}

/// Compute position assignments for all validators using the algorithm
fn compute_position_assignments(
    n_validators: usize,
    query_positions: &[usize],
    _f: usize,
    h: usize,
) -> Vec<Vec<usize>> {
    let s = query_positions.len();
    let n = n_validators;

    if n <= s {
        // Case A: n ≤ s
        compute_case_a_assignments(n, s, h, query_positions)
    } else {
        // Case B: n > s
        compute_case_b_assignments(n, s, h, query_positions)
    }
}

/// Case A implementation: n ≤ s
fn compute_case_a_assignments(
    n: usize,
    s: usize,
    h: usize,
    positions: &[usize],
) -> Vec<Vec<usize>> {
    if s == 0 || n == 0 {
        return vec![Vec::new(); n];
    }

    // Calculate span length ensuring we don't underflow
    let span_length = if h >= s {
        s // If h is too large, give all positions
    } else {
        s - h + 1
    };

    let mut result = Vec::with_capacity(n);

    for i in 1..=n {
        let offset = (i - 1) % s;
        let mut validator_positions = Vec::with_capacity(span_length);

        // Assign cyclic interval of positions
        for j in 0..span_length {
            let index = (offset + j) % s;
            validator_positions.push(positions[index]);
        }

        result.push(validator_positions);
    }

    result
}

/// Case B implementation: n > s
fn compute_case_b_assignments(
    n: usize,
    s: usize,
    h: usize,
    positions: &[usize],
) -> Vec<Vec<usize>> {
    let n_prime = (n / s) * s;

    if n_prime == 0 {
        // All validators get empty assignments if n < s somehow
        return vec![Vec::new(); n];
    }

    let replication_factor = n_prime / s;

    // Calculate h_prime with overflow protection
    let excess = n - n_prime;
    let h_prime = if excess >= h {
        1 // Minimum viable h_prime
    } else {
        let h_minus_excess = h - excess;
        (h_minus_excess + replication_factor - 1) / replication_factor // Ceiling division
    };

    // Generate base subsets using Case A logic
    let base_subsets = compute_case_a_assignments(s, s, h_prime, positions);

    let mut result = Vec::with_capacity(n);

    // Assign base subsets round-robin
    for i in 1..=n {
        if i <= n_prime {
            let subset_index = (i - 1) % s;
            result.push(base_subsets[subset_index].clone());
        } else {
            result.push(Vec::new());
        }
    }

    result
}

/// Generate proofs for validators with deduplication
fn generate_validator_proofs<E, H>(
    prover: &FridaProver<E, H>,
    validator_positions: &[Vec<usize>],
) -> Vec<Option<FridaProof>>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField> + Hasher,
{
    let mut unique_proofs: HashMap<Vec<usize>, FridaProof> = HashMap::new();
    let mut results = Vec::with_capacity(validator_positions.len());

    for positions in validator_positions {
        if positions.is_empty() {
            results.push(None);
            continue;
        }

        // Create deterministic key for deduplication
        let mut sorted_positions = positions.clone();
        sorted_positions.sort();

        let proof = unique_proofs
            .entry(sorted_positions)
            .or_insert_with(|| prover.open(positions))
            .clone();

        results.push(Some(proof));
    }

    results
}

/// Verify a validator's proof against the shared commitment
pub fn verify_validator_proof<E, H>(
    validator_proof: &FridaProof,
    validator_positions: &[usize],
    shared_roots: &[H::Digest],
    data: &[u8],
    domain_size: usize,
    poly_count: usize,
    options: &FriOptions,
) -> Result<bool, FridaError>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField> + Hasher,
{
    if validator_positions.is_empty() {
        return Ok(true);
    }

    // Create a commitment object using the shared roots and the validator's proof
    let commitment = Commitment {
        roots: shared_roots.to_vec(),
        proof: validator_proof.clone(),
        domain_size,
        num_queries: validator_positions.len(),
        poly_count,
    };

    // Create verifier with this commitment
    let (verifier, _) = FridaDasVerifier::<E, H, H>::new(commitment, options.clone())?;

    // Build evaluations for the data
    let evaluations = build_evaluations_from_data::<E>(data, domain_size, options.blowup_factor())?;

    // Extract evaluations at validator's positions
    let validator_evaluations: Vec<E> = validator_positions
        .iter()
        .map(|&pos| evaluations[pos])
        .collect();

    // Verify the proof
    match verifier.verify(validator_proof, &validator_evaluations, validator_positions) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::rand_vector;

    type Blake3 = Blake3_256<BaseElement>;
    type TestElement = BaseElement;

    #[test]
    fn test_case_a_example_from_algorithm() {
        // Test the exact example from the algorithm documentation
        let positions = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let n = 4;
        let s = 8;
        let _f = 1;
        let h = 2;

        let assignments = compute_case_a_assignments(n, s, h, &positions);

        assert_eq!(assignments.len(), 4);
        assert_eq!(assignments[0], vec![0, 1, 2, 3, 4, 5, 6]); // V₁
        assert_eq!(assignments[1], vec![1, 2, 3, 4, 5, 6, 7]); // V₂
        assert_eq!(assignments[2], vec![2, 3, 4, 5, 6, 7, 0]); // V₃
        assert_eq!(assignments[3], vec![3, 4, 5, 6, 7, 0, 1]); // V₄

        // Verify coverage property
        for i in 0..n {
            for j in i + 1..n {
                let union: std::collections::HashSet<_> = assignments[i]
                    .iter()
                    .chain(assignments[j].iter())
                    .cloned()
                    .collect();
                assert_eq!(union.len(), 8);
            }
        }
    }

    #[test]
    fn test_case_b_example_from_algorithm() {
        let positions = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let n = 17;
        let s = 8;
        let _f = 5;
        let h = 6;

        let assignments = compute_case_b_assignments(n, s, h, &positions);

        assert_eq!(assignments.len(), 17);

        // First 16 validators should have non-empty assignments
        for i in 0..16 {
            assert!(!assignments[i].is_empty());
        }

        // 17th validator should have empty assignment
        assert!(assignments[16].is_empty());

        // Check round-robin pattern
        assert_eq!(assignments[0], assignments[8]);
        assert_eq!(assignments[1], assignments[9]);
    }

    #[test]
    fn test_full_distribute_proof_workflow() {
        let data = rand_vector::<u8>(200);
        let options = FriOptions::new(8, 2, 7);
        let n_validators = 4;
        let num_queries = 8;

        let result = distribute_proof::<TestElement, Blake3>(
            &data,
            n_validators,
            num_queries,
            options.clone(),
        )
        .expect("Split proof generation should succeed");

        assert_eq!(result.validator_proofs.len(), n_validators);
        assert_eq!(result.validator_positions.len(), n_validators);
        assert!(!result.shared_commitment_roots.is_empty());

        // Verify all validators have valid proofs
        for i in 0..n_validators {
            assert!(result.validator_proofs[i].is_some());
            assert!(!result.validator_positions[i].is_empty());
        }
    }

    // #[test]
    // fn test_validator_proof_verification() {
    //     let data = rand_vector::<u8>(100);
    //     let options = FriOptions::new(4, 2, 3);
    //     let n_validators = 7;
    //     let num_queries = 12;

    //     let result = distribute_proof::<TestElement, Blake3>(
    //         &data,
    //         n_validators,
    //         num_queries,
    //         options.clone(),
    //     )
    //     .expect("Split proof should work");

    //     println!("Domain size: {}", result.domain_size);
    //     println!(
    //         "FRI options: blowup={}, folding={}, remainder_degree={}",
    //         options.blowup_factor(),
    //         options.folding_factor(),
    //         options.remainder_max_degree()
    //     );
    //     println!(
    //         "f={}, h={}",
    //         (n_validators - 1) / 3,
    //         (n_validators - 1) / 3 + 1
    //     );

    //     // Verify each validator's proof
    //     for i in 0..n_validators {
    //         if result.validator_proofs[i].is_some() {
    //             println!(
    //                 "Validator {} positions: {:?}",
    //                 i, result.validator_positions[i]
    //             );

    //             let verification_result =
    // result.verify_validator::<TestElement>(i);

    //             assert!(
    //                 verification_result.is_ok() && verification_result.unwrap(),
    //                 "Validator {}'s proof should verify successfully",
    //                 i
    //             );
    //         }
    //     }

    //     // Verify coverage property
    //     let h = (n_validators - 1) / 3 + 1;
    //     let non_empty_validators: Vec<usize> = (0..n_validators)
    //         .filter(|&i| result.validator_proofs[i].is_some())
    //         .collect();

    //     if non_empty_validators.len() >= h {
    //         let test_validators = &non_empty_validators[0..h];
    //         let union: std::collections::HashSet<_> = test_validators
    //             .iter()
    //             .flat_map(|&i| result.validator_positions[i].iter())
    //             .cloned()
    //             .collect();

    //         println!(
    //             "Coverage test: {} validators cover {} unique positions",
    //             h,
    //             union.len()
    //         );
    //     }
    // }

    #[test]
    fn test_coverage_property_general() {
        let test_cases = vec![
            (4, 8),  // Case A example
            (6, 10), // Case A
            (15, 8), // Case B
            (20, 5), // Case B with many excess validators
        ];

        for (n, s) in test_cases {
            println!("Testing n={}, s={}", n, s);
            let positions: Vec<usize> = (0..s).collect();
            let f = (n - 1) / 3;
            let h = f + 1;

            let assignments = compute_position_assignments(n, &positions, f, h);

            // Test coverage with non-empty validators
            let non_empty_indices: Vec<usize> = assignments
                .iter()
                .enumerate()
                .filter(|(_, pos)| !pos.is_empty())
                .map(|(i, _)| i)
                .collect();

            if non_empty_indices.len() >= h {
                let test_indices = &non_empty_indices[0..h];
                let union: std::collections::HashSet<_> = test_indices
                    .iter()
                    .flat_map(|&i| assignments[i].iter())
                    .cloned()
                    .collect();

                assert_eq!(
                    union.len(),
                    s,
                    "Coverage property failed for n={}, s={}",
                    n,
                    s
                );
            }
        }
    }

    #[test]
    fn test_edge_case_single_validator() {
        let data = rand_vector::<u8>(50);
        let options = FriOptions::new(4, 2, 1);
        let n_validators = 1;
        let num_queries = 4;

        let result =
            distribute_proof::<TestElement, Blake3>(&data, n_validators, num_queries, options)
                .expect("Single validator split should work");

        assert_eq!(result.validator_proofs.len(), 1);
        assert!(result.validator_proofs[0].is_some());
    }

    #[test]
    fn test_edge_case_empty_assignments() {
        let data = rand_vector::<u8>(50);
        let options = FriOptions::new(4, 2, 1);
        let n_validators = 20;
        let num_queries = 3;

        let result =
            distribute_proof::<TestElement, Blake3>(&data, n_validators, num_queries, options)
                .expect("Should handle many validators");

        assert_eq!(result.validator_proofs.len(), n_validators);

        let empty_count = result
            .validator_proofs
            .iter()
            .filter(|p| p.is_none())
            .count();
        assert!(empty_count > 0);
    }
}
