#pragma once

#include "benchmark_estimator_provenance.h"

#include <cstdint>
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

}  // namespace benchmark
}  // namespace piccard
