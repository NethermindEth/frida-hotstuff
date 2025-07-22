use hotstuff_rs::events::{
    CollectPCEvent, PhaseVoteEvent, ProposeEvent, ReceivePhaseVoteEvent, ReceiveProposalEvent,
    StartViewEvent,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

// Use DashMap for lock-free concurrent access
use dashmap::DashMap;

#[derive(Clone)]
pub struct BenchmarkHandler {
    metrics: Arc<DashMap<u64, BenchmarkMetrics>>,
    is_log: bool,
}

#[derive(Debug, Clone)]
pub struct BenchmarkMetrics {
    pub start_view_time: Vec<u64>,
    pub propose_time: Vec<u64>,
    pub receive_proposal_time: Vec<u64>,
    pub phase_vote_time: Vec<u64>,
    pub receive_phase_vote_time: Vec<u64>,
    pub collect_pc_time: Vec<u64>,
    pub proposal_proof_size: Vec<usize>,
    pub receive_proposal_proof_size: Vec<usize>,
}

impl BenchmarkMetrics {
    pub fn new() -> Self {
        Self {
            start_view_time: Vec::new(),
            propose_time: Vec::new(),
            receive_proposal_time: Vec::new(),
            phase_vote_time: Vec::new(),
            receive_phase_vote_time: Vec::new(),
            collect_pc_time: Vec::new(),
            proposal_proof_size: Vec::new(),
            receive_proposal_proof_size: Vec::new(),
        }
    }

    pub fn if_any_empty(&self) -> bool {
        self.start_view_time.is_empty()
            || self.propose_time.is_empty()
            || self.receive_proposal_time.is_empty()
            || self.phase_vote_time.is_empty()
            || self.receive_phase_vote_time.is_empty()
            || self.collect_pc_time.is_empty()
    }
}

pub(crate) type HandlerPtr<T> = Box<dyn Fn(&T) + Send>;

impl BenchmarkHandler {
    pub fn new(is_log: bool) -> Self {
        Self {
            metrics: Arc::new(DashMap::new()),
            is_log,
        }
    }

    fn get_current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64
    }

    pub fn start_view(&self) -> HandlerPtr<StartViewEvent> {
        let metrics = self.metrics.clone();
        Box::new(move |event| {
            let view_key = event.view.int(); // Convert ViewNumber to string
            let timestamp = Self::get_current_timestamp();

            // Use entry API for atomic access
            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .start_view_time
                .push(timestamp);

            let count = metrics.get(&view_key).unwrap().start_view_time.len();
            
            println!(
                "[BENCHMARK] StartViewEvent recorded for view {} at timestamp {} (total: {})",
                view_key, timestamp, count
            );
        })
    }

    pub fn propose(&self) -> HandlerPtr<ProposeEvent> {
        let metrics = self.metrics.clone();
        Box::new(move |event| {
            let view_key = event.proposal.view.int(); // Convert ViewNumber to string
            let timestamp = Self::get_current_timestamp();

            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .propose_time
                .push(timestamp);

            let count = metrics.get(&view_key).unwrap().propose_time.len();
            println!(
                "[BENCHMARK] ProposeEvent recorded for view {} at timestamp {} (total: {})",
                view_key, timestamp, count
            );

            // calculate proof and commitment size
            let data = event.proposal.block.data.clone();
            let mut total_len = 0;
            for d in data.vec().iter() {
                total_len += d.bytes().len();
            }

            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .proposal_proof_size
                .push(total_len);
        })
    }

    pub fn receive_proposal(&self) -> HandlerPtr<ReceiveProposalEvent> {
        let metrics = self.metrics.clone();
        Box::new(move |event| {
            let view_key = event.proposal.view.int(); // Convert ViewNumber to string
            let timestamp = Self::get_current_timestamp();

            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .receive_proposal_time
                .push(timestamp);

            let count = metrics.get(&view_key).unwrap().receive_proposal_time.len();
            println!(
                "[BENCHMARK] ReceiveProposalEvent recorded for view {} at timestamp {} (total: {})",
                view_key, timestamp, count
            );

            // calculate proof and commitment size
            let data = event.proposal.block.data.clone();
            let mut total_len = 0;
            for d in data.vec().iter() {
                total_len += d.bytes().len();
            }

            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .receive_proposal_proof_size
                .push(total_len);
        })
    }

    pub fn phase_vote(&self) -> HandlerPtr<PhaseVoteEvent> {
        let metrics = self.metrics.clone();
        Box::new(move |event| {
            let view_key = event.vote.view.int(); // Convert ViewNumber to string
            let timestamp = Self::get_current_timestamp();

            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .phase_vote_time
                .push(timestamp);

            let count = metrics.get(&view_key).unwrap().phase_vote_time.len();
            println!(
                "[BENCHMARK] PhaseVoteEvent recorded for view {} at timestamp {} (total: {})",
                view_key, timestamp, count
            );
        })
    }

    pub fn receive_phase_vote(&self) -> HandlerPtr<ReceivePhaseVoteEvent> {
        let metrics = self.metrics.clone();
        Box::new(move |event| {
            let view_key = event.phase_vote.view.int(); // Convert ViewNumber to string
            let timestamp = Self::get_current_timestamp();

            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .receive_phase_vote_time
                .push(timestamp);

            let count = metrics
                .get(&view_key)
                .unwrap()
                .receive_phase_vote_time
                .len();
            println!(
                "[BENCHMARK] ReceivePhaseVoteEvent recorded for view {} at timestamp {} (total: {})",
                view_key, timestamp, count
            );
        })
    }

    pub fn collect_pc(&self) -> HandlerPtr<CollectPCEvent> {
        let metrics = self.metrics.clone();
        Box::new(move |event| {
            let view_key = event.phase_certificate.view.int(); // Convert ViewNumber to string
            let timestamp = Self::get_current_timestamp();

            metrics
                .entry(view_key)
                .or_insert_with(BenchmarkMetrics::new)
                .collect_pc_time
                .push(timestamp);

            let count = metrics.get(&view_key).unwrap().collect_pc_time.len();
            println!(
                "[BENCHMARK] CollectPCEvent recorded for view {} at timestamp {} (total: {})",
                view_key, timestamp, count
            );
        })
    }

    /// Get all recorded timestamps for a specific view
    pub fn get_benchmark_metrics(&self, view: u64) -> Option<BenchmarkMetrics> {
        self.metrics.get(&view).map(|entry| entry.clone())
    }

    /// Get all recorded timestamps for all views
    pub fn get_all_benchmark_metrics(&self) -> HashMap<u64, BenchmarkMetrics> {
        self.metrics
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Print a summary of all recorded timestamps
    pub fn print_summary(&self) {
        println!("\n=== BENCHMARK TIMESTAMPS SUMMARY ===");
        for entry in self.metrics.iter() {
            let view = entry.key();
            let view_ts = entry.value();

            println!("View {}:", view);
            if !view_ts.start_view_time.is_empty() {
                println!(
                    "  StartView: {} timestamps - {:?}",
                    view_ts.start_view_time.len(),
                    view_ts.start_view_time
                );
            }
            if !view_ts.propose_time.is_empty() {
                println!(
                    "  Propose: {} timestamps - {:?}",
                    view_ts.propose_time.len(),
                    view_ts.propose_time
                );
            }
            if !view_ts.receive_proposal_time.is_empty() {
                println!(
                    "  ReceiveProposal: {} timestamps - {:?}",
                    view_ts.receive_proposal_time.len(),
                    view_ts.receive_proposal_time
                );
            }
            if !view_ts.phase_vote_time.is_empty() {
                println!(
                    "  PhaseVote: {} timestamps - {:?}",
                    view_ts.phase_vote_time.len(),
                    view_ts.phase_vote_time
                );
            }
            if !view_ts.receive_phase_vote_time.is_empty() {
                println!(
                    "  ReceivePhaseVote: {} timestamps - {:?}",
                    view_ts.receive_phase_vote_time.len(),
                    view_ts.receive_phase_vote_time
                );
            }
            if !view_ts.collect_pc_time.is_empty() {
                println!(
                    "  CollectPC: {} timestamps - {:?}",
                    view_ts.collect_pc_time.len(),
                    view_ts.collect_pc_time
                );
            }
            println!();
        }
    }

    /// Calculate timing statistics for a specific view
    pub fn calculate_view_timing_stats(&self, view: u64) -> Option<ViewTimingStats> {
        let view_ts = self.get_benchmark_metrics(view)?;

        Some(ViewTimingStats {
            view,
            start_view_count: view_ts.start_view_time.len(),
            propose_count: view_ts.propose_time.len(),
            receive_proposal_count: view_ts.receive_proposal_time.len(),
            phase_vote_count: view_ts.phase_vote_time.len(),
            receive_phase_vote_count: view_ts.receive_phase_vote_time.len(),
            collect_pc_count: view_ts.collect_pc_time.len(),
            propose_timestamps: view_ts.propose_time,
            receive_proposal_timestamps: view_ts.receive_proposal_time,
            phase_vote_timestamps: view_ts.phase_vote_time,
            collect_pc_timestamps: view_ts.collect_pc_time,
        })
    }

    /// Get the earliest and latest timestamps for each event type in a view
    pub fn get_view_timing_bounds(&self, view: u64) -> Option<ViewTimingBounds> {
        let view_ts = self.get_benchmark_metrics(view)?;

        Some(ViewTimingBounds {
            view,
            start_view_bounds: if !view_ts.start_view_time.is_empty() {
                Some((
                    *view_ts.start_view_time.iter().min().unwrap(),
                    *view_ts.start_view_time.iter().max().unwrap(),
                ))
            } else {
                None
            },
            propose_bounds: if !view_ts.propose_time.is_empty() {
                Some((
                    *view_ts.propose_time.iter().min().unwrap(),
                    *view_ts.propose_time.iter().max().unwrap(),
                ))
            } else {
                None
            },
            receive_proposal_bounds: if !view_ts.receive_proposal_time.is_empty() {
                Some((
                    *view_ts.receive_proposal_time.iter().min().unwrap(),
                    *view_ts.receive_proposal_time.iter().max().unwrap(),
                ))
            } else {
                None
            },
            phase_vote_bounds: if !view_ts.phase_vote_time.is_empty() {
                Some((
                    *view_ts.phase_vote_time.iter().min().unwrap(),
                    *view_ts.phase_vote_time.iter().max().unwrap(),
                ))
            } else {
                None
            },
            receive_phase_vote_bounds: if !view_ts.receive_phase_vote_time.is_empty() {
                Some((
                    *view_ts.receive_phase_vote_time.iter().min().unwrap(),
                    *view_ts.receive_phase_vote_time.iter().max().unwrap(),
                ))
            } else {
                None
            },
            collect_pc_bounds: if !view_ts.collect_pc_time.is_empty() {
                Some((
                    *view_ts.collect_pc_time.iter().min().unwrap(),
                    *view_ts.collect_pc_time.iter().max().unwrap(),
                ))
            } else {
                None
            },
        })
    }

    /// Get all timestamps for a specific event type across all views
    pub fn get_all_timestamps_for_event_type(&self, event_type: &str) -> HashMap<u64, Vec<u64>> {
        let mut result = HashMap::new();

        for entry in self.metrics.iter() {
            let view = entry.key();
            let view_ts = entry.value();

            let timestamps = match event_type {
                "start_view" => &view_ts.start_view_time,
                "propose" => &view_ts.propose_time,
                "receive_proposal" => &view_ts.receive_proposal_time,
                "phase_vote" => &view_ts.phase_vote_time,
                "receive_phase_vote" => &view_ts.receive_phase_vote_time,
                "collect_pc" => &view_ts.collect_pc_time,
                _ => continue,
            };

            if !timestamps.is_empty() {
                result.insert(view.clone(), timestamps.clone());
            }
        }

        result
    }

    /// Calculate latency statistics for a specific event type across all views
    pub fn calculate_latency_stats(&self, event_type: &str) -> Option<LatencyStats> {
        let all_timestamps = self.get_all_timestamps_for_event_type(event_type);

        if all_timestamps.is_empty() {
            return None;
        }

        let mut all_times = Vec::new();
        for timestamps in all_timestamps.values() {
            all_times.extend(timestamps);
        }

        all_times.sort();

        let count = all_times.len();
        let min = all_times[0];
        let max = all_times[count - 1];
        let median = if count % 2 == 0 {
            (all_times[count / 2 - 1] + all_times[count / 2]) / 2
        } else {
            all_times[count / 2]
        };

        let sum: u64 = all_times.iter().sum();
        let mean = sum / count as u64;

        Some(LatencyStats {
            event_type: event_type.to_string(),
            count,
            min,
            max,
            mean,
            median,
            all_timestamps: all_times,
        })
    }
}

#[derive(Debug)]
pub struct ViewTimingStats {
    pub view: u64,
    pub start_view_count: usize,
    pub propose_count: usize,
    pub receive_proposal_count: usize,
    pub phase_vote_count: usize,
    pub receive_phase_vote_count: usize,
    pub collect_pc_count: usize,
    pub propose_timestamps: Vec<u64>,
    pub receive_proposal_timestamps: Vec<u64>,
    pub phase_vote_timestamps: Vec<u64>,
    pub collect_pc_timestamps: Vec<u64>,
}

#[derive(Debug)]
pub struct ViewTimingBounds {
    pub view: u64,
    pub start_view_bounds: Option<(u64, u64)>, // (earliest, latest)
    pub propose_bounds: Option<(u64, u64)>,
    pub receive_proposal_bounds: Option<(u64, u64)>,
    pub phase_vote_bounds: Option<(u64, u64)>,
    pub receive_phase_vote_bounds: Option<(u64, u64)>,
    pub collect_pc_bounds: Option<(u64, u64)>,
}

#[derive(Debug)]
pub struct LatencyStats {
    pub event_type: String,
    pub count: usize,
    pub min: u64,
    pub max: u64,
    pub mean: u64,
    pub median: u64,
    pub all_timestamps: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::BenchmarkHandler;
    use hotstuff_rs::{
        events::ProposeEvent,
        hotstuff::{messages::Proposal, types::PhaseCertificate},
        types::{
            block::Block,
            data_types::{BlockHeight, ChainID, CryptoHash, Data, Datum, ViewNumber},
        },
    };

    #[test]
    fn test_handler() {
        let benchmark_handler = BenchmarkHandler::new(false);

        // Get the propose handler
        let propose_handler = benchmark_handler.propose();

        // Create the required components for Block::new()
        let height = BlockHeight::new(1);
        let justify = PhaseCertificate::genesis_pc();
        let data_hash = CryptoHash::new([0u8; 32]);
        let data = Data::new(vec![Datum::new(vec![1, 2, 3, 4])]);
        let view_number = 2;
        let timestamp_now = SystemTime::now();

        let block = Block::new(height, justify, data_hash, data);

        let proposal = Proposal {
            chain_id: ChainID::new(1),
            view: ViewNumber::new(view_number),
            block,
        };

        let propose_event = ProposeEvent {
            proposal,
            timestamp: timestamp_now,
        };

        // Call the handler with the event
        propose_handler(&propose_event);

        // Verify the handler recorded the timestamp
        let timestamps = benchmark_handler.get_all_benchmark_metrics();
        assert!(!timestamps.is_empty());

        // Check that view 2 has a propose timestamp
        let view_2_timestamps = benchmark_handler.get_benchmark_metrics(view_number);
        assert!(view_2_timestamps.is_some());
        let view_2_ts = view_2_timestamps.unwrap();
        assert_eq!(
            view_2_ts.propose_time,
            vec![
                timestamp_now
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64
            ]
        );
    }
}
