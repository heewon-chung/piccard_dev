#pragma once

#include <cstdint>

namespace piccard {

struct DeletionSurvivalConfig {
    uint64_t set_size;
    uint32_t bottom_depth;
    uint32_t hash_count;
};

struct DeletionSurvivalSummary {
    uint64_t maximum_safe_deletions;
    long double expected_first_failure_time;
    long double expected_safe_deletions;
};

long double BottomExhaustionProbability(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions);
long double ExactDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions);
long double UnionBoundDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions);
DeletionSurvivalSummary AnalyzeDeletionSurvival(
    const DeletionSurvivalConfig& config, long double required_survival);

}  // namespace piccard
