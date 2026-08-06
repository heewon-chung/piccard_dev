#pragma once

#include "analysis/deletion_survival.h"

#include <cstdint>
#include <random>
#include <vector>

namespace piccard {

uint64_t UniformBelow(std::mt19937_64& generator, uint64_t bound);
uint64_t SampleFirstFailure(
    const DeletionSurvivalConfig& config, std::mt19937_64& generator);

struct DeletionMonteCarloResult {
    uint64_t trials;
    uint64_t seed;
    std::vector<uint64_t> failure_histogram;
    long double mean_first_failure_time;
    long double mean_safe_deletions;

    long double SurvivalAt(uint64_t completed_deletions) const;
    long double StandardErrorAt(uint64_t completed_deletions) const;
};

DeletionMonteCarloResult SimulateDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t trials, uint64_t seed);

}  // namespace piccard
