use crate::benchmark_calculation::PhaseTimingAndProofSize;
use frida_poc::winterfell::FriOptions;
use std::fs::File;
use std::io::Write;

pub fn generate_report(
    file_path: &str,
    num_validators: u64,
    fri_options: FriOptions,
    height_width_phase_timings_proof_sizes: Vec<(usize, usize, PhaseTimingAndProofSize)>,
) {
    let mut file = File::create(file_path).unwrap();
    writeln!(file, "Number of validators: {}", num_validators).unwrap();
    writeln!(
        file,
        "Folding factor: {:?}, Remainder max degree: {:?}, Blowup factor: {:?} ",
        fri_options.folding_factor(),
        fri_options.remainder_max_degree(),
        fri_options.blowup_factor()
    )
    .unwrap();

    writeln!(
        file,
        "\nData Size (height x width) | Propose Block Time (min/mean/max) | Send Proposal Time (min/mean/max) | Validate Proposal Time (min/mean/max) | Send Signed Proposal Time (min/mean/max) | Validate Signature Time (min/mean/max) | Proposal Proof Size (min/mean/max) | Receive Proposal Proof Size (min/mean/max)"
    )
    .unwrap();
    writeln!(file, "-------------------------------------------------").unwrap();
    for (height, width, timing_proof_size) in height_width_phase_timings_proof_sizes.iter() {
        writeln!(
            file,
            "{:4} x {:4} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} ",
            height,
            width,
            timing_proof_size.propose_block_time.min_time.unwrap(),
            timing_proof_size.propose_block_time.mean_time.unwrap(),
            timing_proof_size.propose_block_time.max_time.unwrap(),
            timing_proof_size.send_proposal_time.min_time.unwrap(),
            timing_proof_size.send_proposal_time.mean_time.unwrap(),
            timing_proof_size.send_proposal_time.max_time.unwrap(),
            timing_proof_size.validate_proposal_time.min_time.unwrap(),
            timing_proof_size.validate_proposal_time.mean_time.unwrap(),
            timing_proof_size.validate_proposal_time.max_time.unwrap(),
            timing_proof_size.send_signed_proposal_time.min_time.unwrap(),
            timing_proof_size.send_signed_proposal_time.mean_time.unwrap(),
            timing_proof_size.send_signed_proposal_time.max_time.unwrap(),
            timing_proof_size.validate_signature_time.min_time.unwrap(),
            timing_proof_size.validate_signature_time.mean_time.unwrap(),
            timing_proof_size.validate_signature_time.max_time.unwrap(),
            timing_proof_size.proposal_proof_size.min_proof_size.unwrap(),
            timing_proof_size.proposal_proof_size.mean_proof_size.unwrap(),
            timing_proof_size.proposal_proof_size.max_proof_size.unwrap(),
            timing_proof_size.receive_proposal_proof_size.min_proof_size.unwrap(),
            timing_proof_size.receive_proposal_proof_size.mean_proof_size.unwrap(),
            timing_proof_size.receive_proposal_proof_size.max_proof_size.unwrap()
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::benchmark_calculation::{BenchmarkProofSize, BenchmarkTiming};

    use super::*;

    #[test]
    #[ignore]
    fn test_generate_report() {
        let file_path = "test.txt";
        let num_validators = 10;
        let fri_options = FriOptions::new(8, 2, 1);
        let height_width_phase_timings_proof_sizes = vec![(
            10,
            10,
            PhaseTimingAndProofSize::new(
                BenchmarkTiming::new(10, 10, 10),
                BenchmarkTiming::new(10, 10, 10),
                BenchmarkTiming::new(10, 10, 10),
                BenchmarkTiming::new(10, 10, 10),
                BenchmarkTiming::new(10, 10, 10),
                BenchmarkProofSize::new(10, 10, 10),
                BenchmarkProofSize::new(10, 10, 10),
            ),
        )];

        generate_report(
            file_path,
            num_validators,
            fri_options,
            height_width_phase_timings_proof_sizes,
        );
    }
}
