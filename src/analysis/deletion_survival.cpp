#include "analysis/deletion_survival.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace piccard {
namespace {

void Validate(const DeletionSurvivalConfig& config, uint64_t completed_deletions) {
    if (config.set_size == 0 || config.bottom_depth == 0 ||
        config.bottom_depth > config.set_size || config.hash_count == 0 ||
        completed_deletions > config.set_size) {
        throw std::invalid_argument("invalid deletion survival configuration");
    }
}

}  // namespace

long double BottomExhaustionProbability(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions) {
    Validate(config, completed_deletions);
    if (completed_deletions < config.bottom_depth) {
        return 0.0L;
    }

    long double ratio = 1.0L;
    for (uint32_t i = 0; i < config.bottom_depth; ++i) {
        ratio *= static_cast<long double>(completed_deletions - i) /
                 static_cast<long double>(config.set_size - i);
    }
    return ratio;
}

long double ExactDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions) {
    const long double q =
        BottomExhaustionProbability(config, completed_deletions);
    if (q == 1.0L) {
        return 0.0L;
    }
    return std::exp(static_cast<long double>(config.hash_count) *
                    std::log1p(-q));
}

long double UnionBoundDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions) {
    const long double q =
        BottomExhaustionProbability(config, completed_deletions);
    return std::max(0.0L, 1.0L - static_cast<long double>(config.hash_count) * q);
}

DeletionSurvivalSummary AnalyzeDeletionSurvival(
    const DeletionSurvivalConfig& config, long double required_survival) {
    Validate(config, 0);
    if (!std::isfinite(required_survival) || required_survival <= 0.0L ||
        required_survival > 1.0L) {
        throw std::invalid_argument("required survival must be finite and in (0, 1]");
    }

    uint64_t low = 0;
    uint64_t high = config.set_size;
    while (low < high) {
        const uint64_t candidate = low + (high - low + 1) / 2;
        if (ExactDeletionSurvival(config, candidate) >= required_survival) {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }

    long double first_failure = 0.0L;
    for (uint64_t completed_deletions = 0;
         completed_deletions < config.set_size; ++completed_deletions) {
        first_failure += ExactDeletionSurvival(config, completed_deletions);
    }
    const long double safe_deletions = first_failure - 1.0L;
    return {low, first_failure, safe_deletions};
}

}  // namespace piccard
