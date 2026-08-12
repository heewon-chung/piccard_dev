#pragma once

#include <cstdint>
#include <string>

namespace piccard::bench {

/** @brief Arguments for the plaintext held-out DBLP threshold experiment. */
struct RealThresholdCliArgs {
    std::string dataset_manifest_path;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t max_pairs = 0;
    uint32_t threshold_trials = 0;
    uint64_t root_seed = 0;
    std::string hash_randomness;
    std::string csv_path;
    std::string workload_manifest_out_path;
    std::string workload_rows_out_path;
};

/**
 * @brief Runs DBLP calibration/held-out threshold evaluation in plaintext.
 *
 * The driver accepts only the frozen DBLP-ACM variant and k=128,m=64.  It
 * writes a versioned evaluation CSV and two provenance-bound workload files.
 */
int RunRealThresholdMode(const RealThresholdCliArgs& args);

}  // namespace piccard::bench
