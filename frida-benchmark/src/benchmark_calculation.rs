use std::collections::HashMap;

use crate::benchmark_handlers::BenchmarkMetrics;

pub fn compare_and_update_benchmark_timing(
    current_benchmark_timing: &mut BenchmarkTiming,
    new_benchmark_timing: BenchmarkTiming,
) {
    if let Some(min_time) = current_benchmark_timing.min_time {
        current_benchmark_timing.min_time =
            Some(min_time.min(new_benchmark_timing.min_time.unwrap()));
    } else {
        current_benchmark_timing.min_time = new_benchmark_timing.min_time;
    }

    if let Some(mean_time) = current_benchmark_timing.mean_time {
        current_benchmark_timing.mean_time =
            Some((mean_time + new_benchmark_timing.mean_time.unwrap()) / 2);
    } else {
        current_benchmark_timing.mean_time = new_benchmark_timing.mean_time;
    }

    if let Some(max_time) = current_benchmark_timing.max_time {
        current_benchmark_timing.max_time =
            Some(max_time.max(new_benchmark_timing.max_time.unwrap()));
    } else {
        current_benchmark_timing.max_time = new_benchmark_timing.max_time;
    }
}

pub fn compare_and_update_benchmark_proof_size(
    current_benchmark_proof_size: &mut BenchmarkProofSize,
    new_benchmark_proof_size: BenchmarkProofSize,
) {
    if let Some(min_proof_size) = current_benchmark_proof_size.min_proof_size {
        current_benchmark_proof_size.min_proof_size =
            Some(min_proof_size.min(new_benchmark_proof_size.min_proof_size.unwrap()));
    } else {
        current_benchmark_proof_size.min_proof_size = new_benchmark_proof_size.min_proof_size;
    }

    if let Some(mean_proof_size) = current_benchmark_proof_size.mean_proof_size {
        current_benchmark_proof_size.mean_proof_size =
            Some((mean_proof_size + new_benchmark_proof_size.mean_proof_size.unwrap()) / 2);
    } else {
        current_benchmark_proof_size.mean_proof_size = new_benchmark_proof_size.mean_proof_size;
    }

    if let Some(max_proof_size) = current_benchmark_proof_size.max_proof_size {
        current_benchmark_proof_size.max_proof_size =
            Some(max_proof_size.max(new_benchmark_proof_size.max_proof_size.unwrap()));
    } else {
        current_benchmark_proof_size.max_proof_size = new_benchmark_proof_size.max_proof_size;
    }
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
        println!("metrics: {:?}", metrics);

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
        let mut propose_block_time = BenchmarkTiming::new_empty();
        let mut send_proposal_time = BenchmarkTiming::new_empty();
        let mut validate_proposal_time = BenchmarkTiming::new_empty();
        let mut send_signed_proposal_time = BenchmarkTiming::new_empty();
        let mut validate_signature_time = BenchmarkTiming::new_empty();
        let mut proposal_proof_size = BenchmarkProofSize::new_empty();
        let mut receive_proposal_proof_size = BenchmarkProofSize::new_empty();

        for (_, metrics) in all_metrics {
            if metrics.if_any_empty() {
                break;
            }

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
    pub min_time: Option<u64>,
    pub mean_time: Option<u64>,
    pub max_time: Option<u64>,
}

impl BenchmarkTiming {
    pub fn new_empty() -> Self {
        Self {
            min_time: None,
            mean_time: None,
            max_time: None,
        }
    }

    pub fn new(min_time: u64, mean_time: u64, max_time: u64) -> Self {
        Self {
            min_time: Some(min_time),
            mean_time: Some(mean_time),
            max_time: Some(max_time),
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
        // but in consensus there could be the case where this substraction will cause an overflow
        println!("to_min: {:?}", to_min);
        println!("from_min: {:?}", from_min);
        println!("to_max: {:?}", to_max);
        println!("from_max: {:?}", from_max);
        println!("to_mean: {:?}", to_mean);
        println!("from_mean: {:?}", from_mean);

        let min = to_min - from_min;
        let mean = to_mean - from_mean;
        let max = to_max - from_min;
        Self::new(min, mean, max)
    }
}

#[derive(Debug)]
pub struct BenchmarkProofSize {
    pub min_proof_size: Option<usize>,
    pub mean_proof_size: Option<usize>,
    pub max_proof_size: Option<usize>,
}

impl BenchmarkProofSize {
    pub fn new_empty() -> Self {
        Self {
            min_proof_size: None,
            mean_proof_size: None,
            max_proof_size: None,
        }
    }

    pub fn new(min_proof_size: usize, mean_proof_size: usize, max_proof_size: usize) -> Self {
        Self {
            min_proof_size: Some(min_proof_size),
            mean_proof_size: Some(mean_proof_size),
            max_proof_size: Some(max_proof_size),
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
        assert_eq!(benchmark_timing.min_time.unwrap(), 3);
        assert_eq!(benchmark_timing.mean_time.unwrap(), 3);
        assert_eq!(benchmark_timing.max_time.unwrap(), 5);
    }

    #[test]
    fn test_benchmark_proof_size() {
        let proof_sizes = vec![1, 2, 3];
        let benchmark_proof_size = BenchmarkProofSize::calculate_proof_size(proof_sizes);
        assert_eq!(benchmark_proof_size.min_proof_size.unwrap(), 1);
        assert_eq!(benchmark_proof_size.mean_proof_size.unwrap(), 2);
        assert_eq!(benchmark_proof_size.max_proof_size.unwrap(), 3);
    }

    #[test]
    fn test_compare_and_update_benchmark_timing() {
        let mut benchmark_timing = BenchmarkTiming::new_empty();
        let new_benchmark_timing = BenchmarkTiming::new(1, 1, 1);

        compare_and_update_benchmark_timing(&mut benchmark_timing, new_benchmark_timing);

        assert_eq!(benchmark_timing.min_time.unwrap(), 1);
        assert_eq!(benchmark_timing.mean_time.unwrap(), 1);
        assert_eq!(benchmark_timing.max_time.unwrap(), 1);

        let new_benchmark_timing = BenchmarkTiming::new(2, 2, 2);
        compare_and_update_benchmark_timing(&mut benchmark_timing, new_benchmark_timing);

        assert_eq!(benchmark_timing.min_time.unwrap(), 1);
        assert_eq!(benchmark_timing.mean_time.unwrap(), 1);
        assert_eq!(benchmark_timing.max_time.unwrap(), 2);
    }

    #[test]
    fn test_compare_and_update_benchmark_proof_size() {
        let mut benchmark_proof_size = BenchmarkProofSize::new_empty();
        let new_benchmark_proof_size = BenchmarkProofSize::new(1, 1, 1);

        compare_and_update_benchmark_proof_size(
            &mut benchmark_proof_size,
            new_benchmark_proof_size,
        );

        assert_eq!(benchmark_proof_size.min_proof_size.unwrap(), 1);
        assert_eq!(benchmark_proof_size.mean_proof_size.unwrap(), 1);
        assert_eq!(benchmark_proof_size.max_proof_size.unwrap(), 1);

        let new_benchmark_proof_size = BenchmarkProofSize::new(2, 2, 2);
        compare_and_update_benchmark_proof_size(
            &mut benchmark_proof_size,
            new_benchmark_proof_size,
        );

        assert_eq!(benchmark_proof_size.min_proof_size.unwrap(), 1);
        assert_eq!(benchmark_proof_size.mean_proof_size.unwrap(), 1);
        assert_eq!(benchmark_proof_size.max_proof_size.unwrap(), 2);
    }

    #[test]
    fn test_calculate_phase_timing_proof_size() {
        let metrics = BenchmarkMetrics {
            start_view_time: vec![1, 2, 3],              // min: 1, mean: 2, max: 3
            propose_time: vec![4, 5, 6],                 // min: 4, mean: 5, max: 6
            receive_proposal_time: vec![8, 10, 23],      // min: 8, mean: 13, max: 23
            phase_vote_time: vec![24, 25, 26],           // min: 24, mean: 25, max: 26
            receive_phase_vote_time: vec![27, 28, 29],   // min: 27, mean: 28, max: 29
            collect_pc_time: vec![30, 31, 32],           // min: 30, mean: 31, max: 32
            proposal_proof_size: vec![33, 34, 35],       // min: 33, mean: 34, max: 35
            receive_proposal_proof_size: vec![8, 9, 10], // min: 8, mean: 9, max: 10
        };

        let phase_timing_proof_size =
            PhaseTimingAndProofSize::calculate_phase_timing_proof_size(metrics);

        {
            assert_eq!(
                phase_timing_proof_size.propose_block_time.min_time.unwrap(),
                3
            );
            assert_eq!(
                phase_timing_proof_size
                    .propose_block_time
                    .mean_time
                    .unwrap(),
                3
            );
            assert_eq!(
                phase_timing_proof_size.propose_block_time.max_time.unwrap(),
                5
            );
        }

        {
            assert_eq!(
                phase_timing_proof_size.send_proposal_time.min_time.unwrap(),
                4
            );
            assert_eq!(
                phase_timing_proof_size
                    .send_proposal_time
                    .mean_time
                    .unwrap(),
                8
            );
            assert_eq!(
                phase_timing_proof_size.send_proposal_time.max_time.unwrap(),
                19
            );
        }

        {
            assert_eq!(
                phase_timing_proof_size
                    .validate_proposal_time
                    .min_time
                    .unwrap(),
                16
            );
            assert_eq!(
                phase_timing_proof_size
                    .validate_proposal_time
                    .mean_time
                    .unwrap(),
                12
            );
            assert_eq!(
                phase_timing_proof_size
                    .validate_proposal_time
                    .max_time
                    .unwrap(),
                18
            );
        }

        {
            assert_eq!(
                phase_timing_proof_size
                    .send_signed_proposal_time
                    .min_time
                    .unwrap(),
                3
            );
            assert_eq!(
                phase_timing_proof_size
                    .send_signed_proposal_time
                    .mean_time
                    .unwrap(),
                3
            );
            assert_eq!(
                phase_timing_proof_size
                    .send_signed_proposal_time
                    .max_time
                    .unwrap(),
                5
            );
        }

        {
            assert_eq!(
                phase_timing_proof_size
                    .validate_signature_time
                    .min_time
                    .unwrap(),
                3
            );
            assert_eq!(
                phase_timing_proof_size
                    .validate_signature_time
                    .mean_time
                    .unwrap(),
                3
            );
            assert_eq!(
                phase_timing_proof_size
                    .validate_signature_time
                    .max_time
                    .unwrap(),
                5
            );
        }

        {
            assert_eq!(
                phase_timing_proof_size
                    .proposal_proof_size
                    .min_proof_size
                    .unwrap(),
                33
            );
            assert_eq!(
                phase_timing_proof_size
                    .proposal_proof_size
                    .mean_proof_size
                    .unwrap(),
                34
            );
            assert_eq!(
                phase_timing_proof_size
                    .proposal_proof_size
                    .max_proof_size
                    .unwrap(),
                35
            );
        }

        {
            assert_eq!(
                phase_timing_proof_size
                    .receive_proposal_proof_size
                    .min_proof_size
                    .unwrap(),
                8
            );
            assert_eq!(
                phase_timing_proof_size
                    .receive_proposal_proof_size
                    .mean_proof_size
                    .unwrap(),
                9
            );
            assert_eq!(
                phase_timing_proof_size
                    .receive_proposal_proof_size
                    .max_proof_size
                    .unwrap(),
                10
            );
        }
    }

    #[test]
    fn test_get_min_max_mean_from_all_benchmark_metrics() {
        let mut all_metrics = HashMap::new();
        all_metrics.insert(1, BenchmarkMetrics::new());
        all_metrics.insert(
            2,
            BenchmarkMetrics {
                start_view_time: vec![1, 2, 3],
                propose_time: vec![4, 5, 6],
                receive_proposal_time: vec![8, 10, 23],
                phase_vote_time: vec![24, 25, 26],
                receive_phase_vote_time: vec![27, 28, 29],
                collect_pc_time: vec![30, 31, 32],
                proposal_proof_size: vec![33, 34, 35],
                receive_proposal_proof_size: vec![8, 9, 10],
            },
        );

        let metrics =
            PhaseTimingAndProofSize::get_min_max_mean_from_all_benchmark_metrics(all_metrics);

        {
            assert_eq!(metrics.propose_block_time.min_time.unwrap(), 0);
            assert_eq!(metrics.propose_block_time.mean_time.unwrap(), 1);
            assert_eq!(metrics.propose_block_time.max_time.unwrap(), 5);
        }

        {
            assert_eq!(metrics.send_proposal_time.min_time.unwrap(), 0);
            assert_eq!(metrics.send_proposal_time.mean_time.unwrap(), 4);
            assert_eq!(metrics.send_proposal_time.max_time.unwrap(), 19);
        }

        {
            assert_eq!(metrics.validate_proposal_time.min_time.unwrap(), 0);
            assert_eq!(metrics.validate_proposal_time.mean_time.unwrap(), 6);
            assert_eq!(metrics.validate_proposal_time.max_time.unwrap(), 18);
        }

        {
            assert_eq!(metrics.send_signed_proposal_time.min_time.unwrap(), 0);
            assert_eq!(metrics.send_signed_proposal_time.mean_time.unwrap(), 1);
            assert_eq!(metrics.send_signed_proposal_time.max_time.unwrap(), 5);
        }

        {
            assert_eq!(metrics.validate_signature_time.min_time.unwrap(), 0);
            assert_eq!(metrics.validate_signature_time.mean_time.unwrap(), 1);
            assert_eq!(metrics.validate_signature_time.max_time.unwrap(), 5);
        }

        {
            assert_eq!(metrics.proposal_proof_size.min_proof_size.unwrap(), 0);
            assert_eq!(metrics.proposal_proof_size.mean_proof_size.unwrap(), 17);
            assert_eq!(metrics.proposal_proof_size.max_proof_size.unwrap(), 35);
        }

        {
            assert_eq!(
                metrics.receive_proposal_proof_size.min_proof_size.unwrap(),
                0
            );
            assert_eq!(
                metrics.receive_proposal_proof_size.mean_proof_size.unwrap(),
                4
            );
            assert_eq!(
                metrics.receive_proposal_proof_size.max_proof_size.unwrap(),
                10
            );
        }
    }
}
