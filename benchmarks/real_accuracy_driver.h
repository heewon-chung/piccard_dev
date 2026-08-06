#pragma once

#include <cstdint>
#include <string>

namespace piccard::bench {

// Parsed --mode=accuracy CLI arguments for bench_real_datasets (Work 5
// Sub-phase 5.3). Every field is mandatory on the command line; there are
// no defaults (normative plan §Phase 5, accuracy CLI).
struct RealAccuracyCliArgs {
    std::string dataset_manifest_path;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t max_pairs = 0;
    uint32_t accuracy_trials = 0;
    uint64_t root_seed = 0;
    std::string hash_randomness;
    std::string csv_path;
    std::string workload_manifest_out_path;
    std::string workload_rows_out_path;
};

// Runs the plaintext accuracy mode end to end: loads and strictly validates
// the processed dataset, derives the per-(pair, trial) workload, computes
// each row through the deployed sha256-random-ranking-poc-v1 MinHash
// estimator and its Plan-1 bias correction, and atomically writes the
// workload rows file, the workload manifest, and the accuracy CSV.
//
// Never constructs an FHE context or calls KeyGen: this translation unit
// (benchmarks/real_accuracy_driver.cpp) draws its #include set from a
// closed allowlist enforced by
// tests/scripts/test_real_dataset_pipeline.py's
// DriverIncludeAllowlistTest, so a transitive OpenFHE pull-in cannot slip
// past this boundary.
//
// Throws std::invalid_argument for a missing/malformed argument and
// std::runtime_error for any I/O or validation failure encountered while
// loading the dataset or writing outputs; the caller (bench_real_datasets)
// is responsible for catching and reporting these on stderr.
// Returns 0 on success.
int RunRealAccuracyMode(const RealAccuracyCliArgs& args);

}  // namespace piccard::bench
