#pragma once

#include "benchmark_estimator_provenance.h"
#include "raw_timing_schema.h"

#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
class DynamicPiccard;

namespace benchmark {

DynamicResult RunSingleOwnerRefresh(
    const DynamicPiccard& engine,
    const std::vector<uint64_t>& set_a,
    const std::vector<uint64_t>& set_b,
    uint32_t depth,
    uint64_t refresh_updates);

/**
 * @brief Execute the frozen one-owner refresh sequence repeatedly.
 *
 * This helper is used only by the opt-in paper/readiness producer path.  The
 * existing single-run API remains the Work-5 compatibility surface; each
 * returned row is one complete measured trial and no synthetic warmup is
 * inserted here because the dynamic_refresh producer contract is
 * WarmupPolicy::None.
 */
std::vector<DynamicResult> RunSingleOwnerRefreshTrials(
    const DynamicPiccard& engine,
    const std::vector<uint64_t>& set_a,
    const std::vector<uint64_t>& set_b,
    uint32_t depth,
    uint64_t refresh_updates,
    uint64_t measured_trials);

/**
 * @brief Build a canonical raw-timing sidecar for refresh trial rows.
 *
 * The refresh producer has no warmup.  The helper records every refresh phase
 * and the explicit total for every trial with one shared seed/cell identity,
 * leaving aggregate computation to the versioned raw-timing schema.
 */
RawTimingArtifact MakeDynamicRefreshTimingArtifact(
    const std::string& profile_id,
    const std::string& cell_id,
    uint64_t seed,
    const std::vector<DynamicResult>& measured_trials);

}  // namespace benchmark
}  // namespace piccard
