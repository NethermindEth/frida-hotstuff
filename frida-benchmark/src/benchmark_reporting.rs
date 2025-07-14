use crate::benchmark_calculation::PhaseTiming;
use frida_poc::winterfell::FriOptions;
use std::fs::File;
use std::io::Write;

pub fn generate_report(
    file_path: &str,
    num_validators: u64,
    fri_options: FriOptions,
    height_width_phase_timings: Vec<(usize, usize, PhaseTiming)>,
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
        "\nData Size (height x width) | Propose Block Time (min/mean/max) | Send Proposal Time (min/mean/max) | Validate Proposal Time (min/mean/max) | Send Signed Proposal Time (min/mean/max) | Validate Signature Time (min/mean/max)"
    )
    .unwrap();
    writeln!(file, "-------------------------------------------------").unwrap();
    for (height, width, timing) in height_width_phase_timings.iter() {
        writeln!(
            file,
            "{:4} x {:4} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} | {:6}/{:6}/{:6} ",
            height,
            width,
            timing.propose_block_time.min_time,
            timing.propose_block_time.mean_time,
            timing.propose_block_time.max_time,
            timing.send_proposal_time.min_time,
            timing.send_proposal_time.mean_time,
            timing.send_proposal_time.max_time,
            timing.validate_proposal_time.min_time,
            timing.validate_proposal_time.mean_time,
            timing.validate_proposal_time.max_time
        )
        .unwrap();
    }
}
