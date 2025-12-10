# Frida and DeFrida Hotstuff Benchmarks

## Overview
This repository contains a comprehensive benchmarking suite for evaluating the performance of both Frida and DeFrida implementations using the Hotstuff consensus protocol.

## 🚀 Quickstart
1. **Configure your experiment** by editing `benchmark_config.yaml` in the project root
2. **Run the benchmark**:
```bash
cargo run --release -p benchmark
```

This will execute the benchmarks for both Frida and DeFrida using the configured parameters. Results are automatically saved to the `results/` directory with detailed logs in `logs/`.

## 📁 Project Structure
The codebase is organized into focused crates for maintainability and modularity:

- **`crates/benchmark/`** - The main benchmarking binary that orchestrates the entire benchmarking process
- **`crates/common/`** - Shared utilities and data structures used across multiple crates  
- **`frida-app/`** - Complete implementation of the Frida protocol using Hotstuff consensus
- **`defrida-app/`** - Complete implementation of the DeFrida protocol using Hotstuff consensus


## ⚙️ Configuration

### YAML Configuration System
All benchmark parameters are configured through `benchmark_config.yaml` in the project root. This file serves as both configuration and documentation, explaining the impact of each parameter.

The benchmark creates a **matrix of tests** by computing the cartesian product of all configured parameters:
```
Total Tests = (validator counts) × (data sizes) × (FRI configurations)
```

### Configuration Parameters

#### **Validator Counts** (`num_of_validators`)
Number of validator nodes participating in consensus:
```yaml
num_of_validators:
  - 5
  - 10
  - 20
  - 50
  - 100
```

#### **Data Sizes** (`data_sizes`)
Dimensions of data matrices for cryptographic operations:
```yaml
data_sizes:
  - height: 100
    width: 100
  - height: 1000
    width: 1000
  - height: 10000
    width: 10000
```

#### **FRI Options** (`fri_options`)
Fast Reed-Solomon Interactive proof system parameters:
```yaml
fri_options:
  - blowup_factor: 2        # Low-Degree Extension multiplier
    folding_factor: 2       # Polynomial degree reduction per round
    max_remainder_degree: 1 # Direct verification threshold
```

#### **Output Files** (`output_files`)
Specify where benchmark results are written:
```yaml
output_files:
  frida_benchmark: "results/frida-benchmark.csv"
  defrida_benchmark: "results/defrida-benchmark.csv"
```

## 📊 Benchmark Output

### Output Files
Results are automatically organized into structured directories:
- **`results/frida-benchmark.csv`** - Frida protocol performance metrics
- **`results/defrida-benchmark.csv`** - DeFrida protocol performance metrics
- **`logs/logging.log`** - Detailed execution logs with timestamps

### Measured Metrics
Each benchmark captures comprehensive performance data:

```rust
pub struct PhaseTimingAndProofSize {
    pub propose_block_time: BenchmarkTiming,        // Block proposal timing
    pub send_proposal_time: BenchmarkTiming,        // Network transmission timing
    pub validate_proposal_time: BenchmarkTiming,    // Proposal validation timing
    pub send_signed_proposal_time: BenchmarkTiming, // Signature transmission timing
    pub validate_signature_time: BenchmarkTiming,   // Signature validation timing
    pub proposal_proof_size: BenchmarkProofSize,    // Cryptographic proof sizes
    pub receive_proposal_proof_size: BenchmarkProofSize, // Received proof sizes
}
```

Each timing and proof size metric includes **minimum**, **mean**, and **maximum** values across all consensus rounds for statistical analysis.

### Performance Analysis
The benchmark results enable comparative analysis between:
- **Frida vs DeFrida** performance characteristics
- **Scalability** across different validator set sizes
- **Memory impact** of varying data dimensions
- **Cryptographic trade-offs** between different FRI configurations

## 🛠️ Installation

### Prerequisites
- Rust toolchain (see `rust-toolchain.toml` for version)
- Git with proper SSH/HTTPS access

### Setup
```bash
git clone <repository-url>
cd frida-hotstuff
cargo build --release
```

If you encounter issues with `frida-poc` dependency, follow [this configuration guide](https://docs.shipyard.rs/configuration/git-fetch-with-cli.html).

## 🚧 Current Status & Future Work

### Completed Features ✅
- ✅ **YAML-based configuration system** for flexible experiment design
- ✅ **Frida protocol benchmarking** with comprehensive metrics
- ✅ **Structured logging and reporting** system
- ✅ **Multi-dimensional performance analysis** (validators, data size, FRI params)
- ✅ **DeFrida protocol integration** (framework ready, implementation in progress)
- ✅ **Enhanced statistical analysis** and visualization tools


### Future Improvements 🔮
1. **Consensus round-based termination** instead of time-based (for more consistent averaging)
2. **Real P2P networking layer** integration (e.g., libp2p) instead of mock networks

## License
The crates in this repository are licensed under the following licence.

* Apache 2.0 license ([LICENSE](./LICENSE)) is applied to all commits

## Would like to contribute?

see [Contributing](./CONTRIBUTING.md).
