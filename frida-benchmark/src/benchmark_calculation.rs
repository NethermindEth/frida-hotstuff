use std::collections::HashMap;

use crate::benchmark_handlers::BenchmarkMetrics;

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
        current_benchmark_timing.mean_time =
            (current_benchmark_timing.mean_time + new_benchmark_timing.mean_time) / 2;
    }
    current_benchmark_timing.max_time = current_benchmark_timing
        .max_time
        .max(new_benchmark_timing.max_time);
}

pub fn compare_and_update_benchmark_proof_size(
    current_benchmark_proof_size: &mut BenchmarkProofSize,
    new_benchmark_proof_size: BenchmarkProofSize,
) {
    if current_benchmark_proof_size.min_proof_size == 0 {
        current_benchmark_proof_size.min_proof_size = new_benchmark_proof_size.min_proof_size;
    } else {
        current_benchmark_proof_size.min_proof_size = current_benchmark_proof_size
            .min_proof_size
            .min(new_benchmark_proof_size.min_proof_size);
    }

    if current_benchmark_proof_size.mean_proof_size == 0 {
        current_benchmark_proof_size.mean_proof_size = new_benchmark_proof_size.mean_proof_size;
    } else {
        current_benchmark_proof_size.mean_proof_size = (current_benchmark_proof_size
            .mean_proof_size
            + new_benchmark_proof_size.mean_proof_size)
            / 2;
    }

    current_benchmark_proof_size.max_proof_size = current_benchmark_proof_size
        .max_proof_size
        .max(new_benchmark_proof_size.max_proof_size);
}

#[derive(Debug)]
pub struct PhaseTimingAndProofSize {
    pub propose_block_time: BenchmarkTiming,
    pub send_proposal_time: BenchmarkTiming,
    pub validate_proposal_time: BenchmarkTiming,
    pub send_signed_proposal_time: BenchmarkTiming,
    pub validate_signature_time: BenchmarkTiming,
    pub proposal_proof_size: BenchmarkProofSize,
    pub receive_proposal_proof_size: BenchmarkProofSize,
}

impl PhaseTimingAndProofSize {
    pub fn new(
        propose_block_time: BenchmarkTiming,
        send_proposal_time: BenchmarkTiming,
        validate_proposal_time: BenchmarkTiming,
        send_signed_proposal_time: BenchmarkTiming,
        validate_signature_time: BenchmarkTiming,
        proposal_proof_size: BenchmarkProofSize,
        receive_proposal_proof_size: BenchmarkProofSize,
    ) -> Self {
        Self {
            propose_block_time,
            send_proposal_time,
            validate_proposal_time,
            send_signed_proposal_time,
            validate_signature_time,
            proposal_proof_size,
            receive_proposal_proof_size,
        }
    }

    pub fn calculate_phase_timing_proof_size(metrics: BenchmarkMetrics) -> Self {
        let propose_block_time = BenchmarkTiming::calculate_timings(
            metrics.start_view_time,
            metrics.propose_time.clone(),
        );
        let send_proposal_time = BenchmarkTiming::calculate_timings(
            metrics.propose_time,
            metrics.receive_proposal_time.clone(),
        );
        let validate_proposal_time = BenchmarkTiming::calculate_timings(
            metrics.receive_proposal_time,
            metrics.phase_vote_time.clone(),
        );
        let send_signed_proposal_time = BenchmarkTiming::calculate_timings(
            metrics.phase_vote_time,
            metrics.receive_phase_vote_time.clone(),
        );

        let validate_signature_time = BenchmarkTiming::calculate_timings(
            metrics.receive_phase_vote_time,
            metrics.collect_pc_time,
        );

        let proposal_proof_size =
            BenchmarkProofSize::calculate_proof_size(metrics.proposal_proof_size);
        let receive_proposal_proof_size =
            BenchmarkProofSize::calculate_proof_size(metrics.receive_proposal_proof_size);

        Self::new(
            propose_block_time,
            send_proposal_time,
            validate_proposal_time,
            send_signed_proposal_time,
            validate_signature_time,
            proposal_proof_size,
            receive_proposal_proof_size,
        )
    }

    pub fn get_min_max_mean_from_all_benchmark_metrics(
        all_metrics: HashMap<u64, BenchmarkMetrics>,
    ) -> Self {
        let mut propose_block_time = BenchmarkTiming::new(0, 0, 0);
        let mut send_proposal_time = BenchmarkTiming::new(0, 0, 0);
        let mut validate_proposal_time = BenchmarkTiming::new(0, 0, 0);
        let mut send_signed_proposal_time = BenchmarkTiming::new(0, 0, 0);
        let mut validate_signature_time = BenchmarkTiming::new(0, 0, 0);
        let mut proposal_proof_size = BenchmarkProofSize::new(0, 0, 0);
        let mut receive_proposal_proof_size = BenchmarkProofSize::new(0, 0, 0);

        for (_, metrics) in all_metrics {
            let phase_timing_proof_size =
                PhaseTimingAndProofSize::calculate_phase_timing_proof_size(metrics);

            // find the min, max, mean from all the different view numbers
            let current_propose_block_time = phase_timing_proof_size.propose_block_time;
            let current_send_proposal_time = phase_timing_proof_size.send_proposal_time;
            let current_validate_proposal_time = phase_timing_proof_size.validate_proposal_time;
            let current_send_signed_proposal_time =
                phase_timing_proof_size.send_signed_proposal_time;
            let current_validate_signature_time = phase_timing_proof_size.validate_signature_time;
            let current_proposal_proof_size = phase_timing_proof_size.proposal_proof_size;
            let current_receive_proposal_proof_size =
                phase_timing_proof_size.receive_proposal_proof_size;

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

            compare_and_update_benchmark_proof_size(
                &mut proposal_proof_size,
                current_proposal_proof_size,
            );
            compare_and_update_benchmark_proof_size(
                &mut receive_proposal_proof_size,
                current_receive_proposal_proof_size,
            );
        }

        Self::new(
            propose_block_time,
            send_proposal_time,
            validate_proposal_time,
            send_signed_proposal_time,
            validate_signature_time,
            proposal_proof_size,
            receive_proposal_proof_size,
        )
    }
}

#[derive(Debug)]
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
        let from_min = if froms.is_empty() {
            0
        } else {
            *froms.iter().min().unwrap()
        };
        let from_max = if froms.is_empty() {
            0
        } else {
            *froms.iter().max().unwrap()
        };
        let from_mean = if froms.is_empty() {
            0
        } else {
            froms.iter().sum::<u64>() / froms.len() as u64
        };

        let to_min = if tos.is_empty() {
            0
        } else {
            *tos.iter().min().unwrap()
        };
        let to_max = if tos.is_empty() {
            0
        } else {
            *tos.iter().max().unwrap()
        };
        let to_mean = if tos.is_empty() {
            0
        } else {
            tos.iter().sum::<u64>() / tos.len() as u64
        };

        // min time : to_min - from_max
        Self::new(to_min - from_min, to_mean - from_mean, to_max - from_min)
    }
}

#[derive(Debug)]
pub struct BenchmarkProofSize {
    pub min_proof_size: usize,
    pub mean_proof_size: usize,
    pub max_proof_size: usize,
}

impl BenchmarkProofSize {
    pub fn new(min_proof_size: usize, mean_proof_size: usize, max_proof_size: usize) -> Self {
        Self {
            min_proof_size,
            mean_proof_size,
            max_proof_size,
        }
    }

    pub fn calculate_proof_size(proof_sizes: Vec<usize>) -> Self {
        let min_proof_size = if proof_sizes.is_empty() {
            0
        } else {
            *proof_sizes.iter().min().unwrap()
        };
        let mean_proof_size = if proof_sizes.is_empty() {
            0
        } else {
            proof_sizes.iter().sum::<usize>() / proof_sizes.len()
        };
        let max_proof_size = if proof_sizes.is_empty() {
            0
        } else {
            *proof_sizes.iter().max().unwrap()
        };
        Self::new(min_proof_size, mean_proof_size, max_proof_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_timing() {
        let froms = vec![1, 2, 3];
        let tos = vec![4, 5, 6];
        let benchmark_timing = BenchmarkTiming::calculate_timings(froms, tos);
        assert_eq!(benchmark_timing.min_time, 1);
        assert_eq!(benchmark_timing.mean_time, 3);
        assert_eq!(benchmark_timing.max_time, 5);
    }

    #[test]
    fn test_benchmark_proof_size() {
        let proof_sizes = vec![1, 2, 3];
        let benchmark_proof_size = BenchmarkProofSize::calculate_proof_size(proof_sizes);
        assert_eq!(benchmark_proof_size.min_proof_size, 1);
        assert_eq!(benchmark_proof_size.mean_proof_size, 2);
        assert_eq!(benchmark_proof_size.max_proof_size, 3);
    }

    #[test]
    fn test_compare_and_update_benchmark_timing() {
        let mut benchmark_timing = BenchmarkTiming::new(0, 0, 0);
        let new_benchmark_timing = BenchmarkTiming::new(1, 1, 1);

        compare_and_update_benchmark_timing(&mut benchmark_timing, new_benchmark_timing);

        assert_eq!(benchmark_timing.min_time, 1);
        assert_eq!(benchmark_timing.mean_time, 1);
        assert_eq!(benchmark_timing.max_time, 1);

        let new_benchmark_timing = BenchmarkTiming::new(2, 2, 2);
        compare_and_update_benchmark_timing(&mut benchmark_timing, new_benchmark_timing);

        assert_eq!(benchmark_timing.min_time, 1);
        assert_eq!(benchmark_timing.mean_time, 1);
        assert_eq!(benchmark_timing.max_time, 2);
    }

    #[test]
    fn test_compare_and_update_benchmark_proof_size() {
        let mut benchmark_proof_size = BenchmarkProofSize::new(0, 0, 0);
        let new_benchmark_proof_size = BenchmarkProofSize::new(1, 1, 1);

        compare_and_update_benchmark_proof_size(
            &mut benchmark_proof_size,
            new_benchmark_proof_size,
        );

        assert_eq!(benchmark_proof_size.min_proof_size, 1);
        assert_eq!(benchmark_proof_size.mean_proof_size, 1);
        assert_eq!(benchmark_proof_size.max_proof_size, 1);

        let new_benchmark_proof_size = BenchmarkProofSize::new(2, 2, 2);
        compare_and_update_benchmark_proof_size(
            &mut benchmark_proof_size,
            new_benchmark_proof_size,
        );

        assert_eq!(benchmark_proof_size.min_proof_size, 1);
        assert_eq!(benchmark_proof_size.mean_proof_size, 1);
        assert_eq!(benchmark_proof_size.max_proof_size, 2);
    }

    #[test]
    fn test_get_min_max_mean_from_all_benchmark_metrics() {
        let mut all_metrics = HashMap::new();
        all_metrics.insert(1, BenchmarkMetrics::new());
        all_metrics.insert(
            2,
            BenchmarkMetrics {
                start_view_time: vec![1, 2, 3],
                propose_time: vec![1, 2, 3],
                receive_proposal_time: vec![1, 2, 3],
                phase_vote_time: vec![1, 2, 3],
                receive_phase_vote_time: vec![1, 2, 3],
                collect_pc_time: vec![1, 2, 3],
                proposal_proof_size: vec![1, 2, 3],
                receive_proposal_proof_size: vec![1, 2, 3],
            },
        );

        let metrics =
            PhaseTimingAndProofSize::get_min_max_mean_from_all_benchmark_metrics(all_metrics);

        println!("{:?}", metrics);
    }
}
