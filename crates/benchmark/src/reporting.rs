//! # Benchmark Report Generation
//!
//! This module provides functionality to generate structured CSV benchmark reports from collected
//! performance metrics. It formats timing and proof size data into machine-readable CSV format
//! for analysis, visualization, and comparison using data analysis tools.
//!
//! ## Output Format
//!
//! The CSV output contains one row per benchmark run with columns for:
//! - **Configuration**: validator count, FRI parameters, data dimensions
//! - **Timing Metrics**: min/mean/max values for each consensus phase
//! - **Proof Sizes**: min/mean/max cryptographic proof sizes
//!
use std::{fs::OpenOptions, path::Path};

use csv::WriterBuilder;
use frida_poc::winterfell::FriOptions;
use serde::Serialize;

use crate::{
    calculation::PhaseTimingAndProofSize,
    config::{DataSize, FriConfig},
};

// Serde flatten doesn't work with csv
#[derive(Serialize)]
struct BenchmarkRecord {
    // Configuration parameters
    num_validators: u32,
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,

    // Data dimensions
    data_height: usize,
    data_width: usize,

    // Timing metrics - propose_block_time
    propose_block_time_min: Option<u64>,
    propose_block_time_mean: Option<u64>,
    propose_block_time_max: Option<u64>,

    // Timing metrics - send_proposal_time
    send_proposal_time_min: Option<u64>,
    send_proposal_time_mean: Option<u64>,
    send_proposal_time_max: Option<u64>,

    // Timing metrics - validate_proposal_time
    validate_proposal_time_min: Option<u64>,
    validate_proposal_time_mean: Option<u64>,
    validate_proposal_time_max: Option<u64>,

    // Timing metrics - send_signed_proposal_time
    send_signed_proposal_time_min: Option<u64>,
    send_signed_proposal_time_mean: Option<u64>,
    send_signed_proposal_time_max: Option<u64>,

    // Timing metrics - validate_signature_time
    validate_signature_time_min: Option<u64>,
    validate_signature_time_mean: Option<u64>,
    validate_signature_time_max: Option<u64>,

    // Proof size metrics - proposal_proof_size
    proposal_proof_size_min: Option<usize>,
    proposal_proof_size_mean: Option<usize>,
    proposal_proof_size_max: Option<usize>,

    // Proof size metrics - receive_proposal_proof_size
    receive_proposal_proof_size_min: Option<usize>,
    receive_proposal_proof_size_mean: Option<usize>,
    receive_proposal_proof_size_max: Option<usize>,
}

/// Generates a CSV benchmark report from collected performance metrics.
///
/// This function creates or appends to a CSV file containing structured benchmark results.
/// Each row represents one complete benchmark run with all configuration parameters and
/// performance measurements.
///
/// ## CSV Format
///
/// The output CSV includes headers and is compatible with data analysis tools:
/// - **Headers**: Descriptive column names for easy identification
/// - **Data Types**: Numeric values for timing (nanoseconds) and sizes (bytes)
/// - **Missing Values**: Empty cells for metrics that couldn't be measured
/// - **Append Mode**: Multiple benchmark runs accumulate in the same file
///
/// ## Parameters
///
/// * `num_validators` - Number of validators in this benchmark run
/// * `fri_options` - FRI cryptographic configuration parameters
/// * `height_width_phase_timings_proof_sizes` - Collected metrics per data size
///
/// ## Error Handling
///
/// This function panics on I/O errors (file creation, writing) as these indicate
/// configuration issues that should be resolved before running benchmarks.
pub fn generate_report(
    file_path: &str,
    num_validators: u32,
    fri_options: &FriOptions,
    data_size: &DataSize,
    height_width_phase_timings_proof_sizes: &PhaseTimingAndProofSize,
) {
    // Check if file exists to determine whether to write headers
    let file_exists = Path::new(file_path).exists();

    // Open file in append mode (create if it doesn't exist)
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Failed to create or open CSV file");

    // Create CSV writer with automatic headers
    let mut writer = WriterBuilder::new()
        .has_headers(!file_exists)
        .from_writer(file);

    // Convert FriOptions to FriConfig for serialization
    let fri_config = FriConfig {
        blowup_factor: fri_options.blowup_factor(),
        folding_factor: fri_options.folding_factor(),
        max_remainder_degree: fri_options.remainder_max_degree(),
    };

    // Create benchmark record with all data
    let benchmark_record = BenchmarkRecord {
        // Configuration parameters
        num_validators,
        blowup_factor: fri_config.blowup_factor,
        folding_factor: fri_config.folding_factor,
        max_remainder_degree: fri_config.max_remainder_degree,

        // Data dimensions
        data_height: data_size.height,
        data_width: data_size.width,

        // Timing metrics - propose_block_time
        propose_block_time_min: height_width_phase_timings_proof_sizes
            .propose_block_time
            .min_time,
        propose_block_time_mean: height_width_phase_timings_proof_sizes
            .propose_block_time
            .mean_time,
        propose_block_time_max: height_width_phase_timings_proof_sizes
            .propose_block_time
            .max_time,

        // Timing metrics - send_proposal_time
        send_proposal_time_min: height_width_phase_timings_proof_sizes
            .send_proposal_time
            .min_time,
        send_proposal_time_mean: height_width_phase_timings_proof_sizes
            .send_proposal_time
            .mean_time,
        send_proposal_time_max: height_width_phase_timings_proof_sizes
            .send_proposal_time
            .max_time,

        // Timing metrics - validate_proposal_time
        validate_proposal_time_min: height_width_phase_timings_proof_sizes
            .validate_proposal_time
            .min_time,
        validate_proposal_time_mean: height_width_phase_timings_proof_sizes
            .validate_proposal_time
            .mean_time,
        validate_proposal_time_max: height_width_phase_timings_proof_sizes
            .validate_proposal_time
            .max_time,

        // Timing metrics - send_signed_proposal_time
        send_signed_proposal_time_min: height_width_phase_timings_proof_sizes
            .send_signed_proposal_time
            .min_time,
        send_signed_proposal_time_mean: height_width_phase_timings_proof_sizes
            .send_signed_proposal_time
            .mean_time,
        send_signed_proposal_time_max: height_width_phase_timings_proof_sizes
            .send_signed_proposal_time
            .max_time,

        // Timing metrics - validate_signature_time
        validate_signature_time_min: height_width_phase_timings_proof_sizes
            .validate_signature_time
            .min_time,
        validate_signature_time_mean: height_width_phase_timings_proof_sizes
            .validate_signature_time
            .mean_time,
        validate_signature_time_max: height_width_phase_timings_proof_sizes
            .validate_signature_time
            .max_time,

        // Proof size metrics - proposal_proof_size
        proposal_proof_size_min: height_width_phase_timings_proof_sizes
            .proposal_proof_size
            .min_proof_size,
        proposal_proof_size_mean: height_width_phase_timings_proof_sizes
            .proposal_proof_size
            .mean_proof_size,
        proposal_proof_size_max: height_width_phase_timings_proof_sizes
            .proposal_proof_size
            .max_proof_size,

        // Proof size metrics - receive_proposal_proof_size
        receive_proposal_proof_size_min: height_width_phase_timings_proof_sizes
            .receive_proposal_proof_size
            .min_proof_size,
        receive_proposal_proof_size_mean: height_width_phase_timings_proof_sizes
            .receive_proposal_proof_size
            .mean_proof_size,
        receive_proposal_proof_size_max: height_width_phase_timings_proof_sizes
            .receive_proposal_proof_size
            .max_proof_size,
    };

    // Serialize the benchmark record to CSV
    writer
        .serialize(&benchmark_record)
        .expect("Failed to write CSV record");

    // Ensure all data is written to file
    writer.flush().expect("Failed to flush CSV writer");
}
