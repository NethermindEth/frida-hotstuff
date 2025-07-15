use std::collections::HashMap;

use crate::benchmark_handlers::ViewTimestamps;

pub fn compare_and_update_benchmark_timing(
    current_benchmark_timing: &mut BenchmarkTiming,
    new_benchmark_timing: BenchmarkTiming,
) {
    if current_benchmark_timing.min_time == 0 {
        current_benchmark_timing.min_time = new_benchmark_timing.min_time;
    } else {
        current_benchmark_timing.min_time = current_benchmark_timing
            .min_time
            .min(new_benchmark_timing.min_time);
    }
    if current_benchmark_timing.mean_time == 0 {
        current_benchmark_timing.mean_time = new_benchmark_timing.mean_time;
    } else {
        current_benchmark_timing.mean_time = current_benchmark_timing
            .mean_time
            .min(new_benchmark_timing.mean_time);
    }
    if current_benchmark_timing.max_time == 0 {
        current_benchmark_timing.max_time = new_benchmark_timing.max_time;
    } else {
        current_benchmark_timing.max_time = current_benchmark_timing
            .max_time
            .min(new_benchmark_timing.max_time);
    }
}

pub struct PhaseTiming {
    pub propose_block_time: BenchmarkTiming,
    pub send_proposal_time: BenchmarkTiming,
    pub validate_proposal_time: BenchmarkTiming,
    pub send_signed_proposal_time: BenchmarkTiming,
    pub validate_signature_time: BenchmarkTiming,
}

impl PhaseTiming {
    pub fn new(
        propose_block_time: BenchmarkTiming,
        send_proposal_time: BenchmarkTiming,
        validate_proposal_time: BenchmarkTiming,
        send_signed_proposal_time: BenchmarkTiming,
        validate_signature_time: BenchmarkTiming,
    ) -> Self {
        Self {
            propose_block_time,
            send_proposal_time,
            validate_proposal_time,
            send_signed_proposal_time,
            validate_signature_time,
        }
    }

    pub fn calculate_phase_timing(view_timestamp: ViewTimestamps) -> Self {
        let propose_block_time = BenchmarkTiming::calculate_timings(
            view_timestamp.start_view,
            view_timestamp.propose.clone(),
        );
        let send_proposal_time = BenchmarkTiming::calculate_timings(
            view_timestamp.propose,
            view_timestamp.receive_proposal.clone(),
        );
        let validate_proposal_time = BenchmarkTiming::calculate_timings(
            view_timestamp.receive_proposal,
            view_timestamp.phase_vote.clone(),
        );
        let send_signed_proposal_time = BenchmarkTiming::calculate_timings(
            view_timestamp.phase_vote,
            view_timestamp.receive_phase_vote.clone(),
        );

        let validate_signature_time = BenchmarkTiming::calculate_timings(
            view_timestamp.receive_phase_vote,
            view_timestamp.collect_pc,
        );

        Self::new(
            propose_block_time,
            send_proposal_time,
            validate_proposal_time,
            send_signed_proposal_time,
            validate_signature_time,
        )
    }

    pub fn get_min_max_mean_from_all_view_numbers(
        all_timestamps: HashMap<u64, ViewTimestamps>,
    ) -> Self {
        let mut propose_block_time = BenchmarkTiming::new(0, 0, 0);
        let mut send_proposal_time = BenchmarkTiming::new(0, 0, 0);
        let mut validate_proposal_time = BenchmarkTiming::new(0, 0, 0);
        let mut send_signed_proposal_time = BenchmarkTiming::new(0, 0, 0);
        let mut validate_signature_time = BenchmarkTiming::new(0, 0, 0);

        for (_, view_timestamps) in all_timestamps {
            let phase_timing = PhaseTiming::calculate_phase_timing(view_timestamps);

            // find the min, max, mean from all the different view numbers
            let current_propose_block_time = phase_timing.propose_block_time;
            let current_send_proposal_time = phase_timing.send_proposal_time;
            let current_validate_proposal_time = phase_timing.validate_proposal_time;
            let current_send_signed_proposal_time = phase_timing.send_signed_proposal_time;
            let current_validate_signature_time = phase_timing.validate_signature_time;

            compare_and_update_benchmark_timing(
                &mut propose_block_time,
                current_propose_block_time,
            );
            compare_and_update_benchmark_timing(
                &mut send_proposal_time,
                current_send_proposal_time,
            );
            compare_and_update_benchmark_timing(
                &mut validate_proposal_time,
                current_validate_proposal_time,
            );
            compare_and_update_benchmark_timing(
                &mut send_signed_proposal_time,
                current_send_signed_proposal_time,
            );
            compare_and_update_benchmark_timing(
                &mut validate_signature_time,
                current_validate_signature_time,
            );
        }

        Self::new(
            propose_block_time,
            send_proposal_time,
            validate_proposal_time,
            send_signed_proposal_time,
            validate_signature_time,
        )
    }
}

pub struct BenchmarkTiming {
    pub min_time: u64,
    pub mean_time: u64,
    pub max_time: u64,
}

impl BenchmarkTiming {
    pub fn new(min_time: u64, mean_time: u64, max_time: u64) -> Self {
        Self {
            min_time,
            mean_time,
            max_time,
        }
    }
    // ViewTimestamps
    pub fn calculate_timings(froms: Vec<u64>, tos: Vec<u64>) -> Self {
        let from_min = *froms.iter().min().unwrap();
        let from_max = *froms.iter().max().unwrap();
        let from_mean = froms.iter().sum::<u64>() / froms.len() as u64;

        let to_min = *tos.iter().min().unwrap();
        let to_max = *tos.iter().max().unwrap();
        let to_mean = tos.iter().sum::<u64>() / tos.len() as u64;

        Self::new(to_min - from_max, to_mean - from_mean, to_max - from_min)
    }
}
