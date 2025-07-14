use crate::benchmark_handlers::ViewTimestamps;

pub struct PhaseTiming {
    pub propose_block_time: BenchmarkTiming,
    pub send_proposal_time: BenchmarkTiming,
    pub validate_proposal_time: BenchmarkTiming,
    pub send_signed_proposal_time: BenchmarkTiming,
    pub validate_signature_time: BenchmarkTiming,
}

impl PhaseTiming {
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

        Self {
            propose_block_time,
            send_proposal_time,
            validate_proposal_time,
            send_signed_proposal_time,
            validate_signature_time,
        }
    }
}

pub struct BenchmarkTiming {
    pub min_time: u64,
    pub mean_time: u64,
    pub max_time: u64,
}

impl BenchmarkTiming {
    // ViewTimestamps
    pub fn calculate_timings(froms: Vec<u64>, tos: Vec<u64>) -> Self {
        let from_min = *froms.iter().min().unwrap();
        let from_max = *froms.iter().max().unwrap();
        let from_mean = froms.iter().sum::<u64>() / froms.len() as u64;

        let to_min = *tos.iter().min().unwrap();
        let to_max = *tos.iter().max().unwrap();
        let to_mean = tos.iter().sum::<u64>() / tos.len() as u64;

        Self {
            min_time: to_min - from_max,
            mean_time: to_mean - from_mean,
            max_time: to_max - from_min,
        }
    }
}
