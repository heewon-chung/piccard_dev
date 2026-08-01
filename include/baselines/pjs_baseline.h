#pragma once

/**
 * @file pjs_baseline.h
 * @brief Common contract for private Jaccard similarity (PJS) baselines
 *
 * Piccard is compared against protocols built on different primitives (BFV,
 * AHE, and DH-based PSI-CA), so bench_comparison drives their query execution
 * through one cost interface. Security and reporting capability metadata are
 * deliberately not part of this engine API: benchmarks bind each concrete
 * implementation through the strict typed map in baseline_profile.h.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace piccard {
namespace baselines {

// Cost of a single PJS query, uniform across protocols. Phases that a given
// protocol does not have (e.g. no encrypt step) stay at 0.
struct QueryCost {
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_compute_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    size_t comm_bytes = 0;      // 2x upload + 1x result download
    size_t ct_size_bytes = 0;   // per-party upload

    double jaccard_estimate = 0.0;
};

// Implemented by each baseline protocol. Setup() covers one-time key/parameter
// generation and is excluded from per-query cost.
class PJSBaseline {
public:
    virtual ~PJSBaseline() = default;

    virtual const char* Name() const = 0;
    virtual void Setup() = 0;

    virtual QueryCost RunQuery(const std::vector<uint64_t>& set_x,
                               const std::vector<uint64_t>& set_y) = 0;
};

} // namespace baselines
} // namespace piccard
