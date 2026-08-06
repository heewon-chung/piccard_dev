#pragma once

#include <cstdint>
#include <string>

namespace piccard::bench {

// Parsed --mode=timing CLI arguments for bench_real_datasets (Work 5
// Sub-phase 5.4). Every field is mandatory on the command line; there are
// no defaults (normative plan §Phase 5, timing CLI). This header is
// deliberately FHE-header-free -- like real_accuracy_driver.h -- so
// bench_real_datasets.cpp (built unconditionally, see CMakeLists.txt) can
// include it regardless of whether OpenFHE is available at configure time.
// The two possible implementations of RunRealTimingMode below
// (benchmarks/real_timing_driver.cpp when OpenFHE is available,
// benchmarks/real_timing_driver_stub.cpp otherwise) are selected by
// CMakeLists.txt, never by a preprocessor branch inside this file or
// bench_real_datasets.cpp.
struct RealTimingCliArgs {
    std::string dataset_manifest_path;
    std::string profile_id;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t trials = 0;
    std::string timing_pair;  // only "median" is accepted
    uint64_t root_seed = 0;
    std::string csv_path;
    std::string workload_manifest_out_path;
};

// Runs the FHE timing mode end to end: loads and strictly validates the
// processed dataset, selects the pair whose combined bucketed set size is
// closest to the median combined bucketed set size (lexical pair_id
// tie-break), resolves the named Work-4 benchmark profile, runs one
// discarded warmup plus `trials` zero-based measured trials of the deployed
// one-hot MinHash BFV query protocol against a live BFV context built for
// that profile, and atomically writes the timing CSV and the timing
// workload manifest.
//
// Throws std::invalid_argument for a missing/malformed argument or an
// unknown profile, and std::runtime_error for any I/O, dataset-validation,
// or parameter-selection failure (including a profile whose calibration
// table lacks a feasible row for its exact security level -- this never
// falls back to a different security level). The caller (bench_real_datasets)
// is responsible for catching and reporting these on stderr.
// Returns 0 on success.
int RunRealTimingMode(const RealTimingCliArgs& args);

}  // namespace piccard::bench
