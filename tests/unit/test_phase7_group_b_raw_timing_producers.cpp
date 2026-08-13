// Compile-time contract probe for the Phase 7 Group B producer helpers.
//
// This file is intentionally not added to CMake: the readiness gate compiles
// it directly so producer ownership can be checked without running a FHE
// benchmark executable.

#include "dynamic_refresh_benchmark.h"

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace piccard::benchmark {
namespace {

void Phase7GroupBRefreshArtifactContract() {
    const std::vector<DynamicResult> measured;
    const RawTimingArtifact artifact = MakeDynamicRefreshTimingArtifact(
        "readiness-toy-v1", "refresh-updates-1", UINT64_C(7), measured);
    static_assert(std::is_same_v<decltype(artifact), const RawTimingArtifact>);
    (void)artifact;
}

void Phase7GroupBRefreshTrialContract(const DynamicPiccard& engine,
                                      const std::vector<uint64_t>& set_a,
                                      const std::vector<uint64_t>& set_b) {
    const auto rows = RunSingleOwnerRefreshTrials(
        engine, set_a, set_b, 5, UINT64_C(1), UINT64_C(1));
    (void)rows;
}

}  // namespace
}  // namespace piccard::benchmark
