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
            timing_proof_size.propose_block_time.min_time,
            timing_proof_size.propose_block_time.mean_time,
            timing_proof_size.propose_block_time.max_time,
            timing_proof_size.send_proposal_time.min_time,
            timing_proof_size.send_proposal_time.mean_time,
            timing_proof_size.send_proposal_time.max_time,
            timing_proof_size.validate_proposal_time.min_time,
            timing_proof_size.validate_proposal_time.mean_time,
            timing_proof_size.validate_proposal_time.max_time,
            timing_proof_size.send_signed_proposal_time.min_time,
            timing_proof_size.send_signed_proposal_time.mean_time,
            timing_proof_size.send_signed_proposal_time.max_time,
            timing_proof_size.validate_signature_time.min_time,
            timing_proof_size.validate_signature_time.mean_time,
            timing_proof_size.validate_signature_time.max_time,
            timing_proof_size.proposal_proof_size.min_proof_size,
            timing_proof_size.proposal_proof_size.mean_proof_size,
            timing_proof_size.proposal_proof_size.max_proof_size,
            timing_proof_size.receive_proposal_proof_size.min_proof_size,
            timing_proof_size.receive_proposal_proof_size.mean_proof_size,
            timing_proof_size.receive_proposal_proof_size.max_proof_size
        )
        .unwrap();
    }
}
