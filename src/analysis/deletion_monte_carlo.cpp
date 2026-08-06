#include "analysis/deletion_monte_carlo.h"

#include <cmath>
#include <limits>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace piccard {
namespace {

void ValidateConfig(const DeletionSurvivalConfig& config) {
    if (config.set_size == 0 || config.bottom_depth == 0 ||
        config.bottom_depth > config.set_size || config.hash_count == 0) {
        throw std::invalid_argument("invalid deletion survival configuration");
    }
}

void ValidateHistogramSize(const DeletionSurvivalConfig& config) {
    const size_t maximum_bins = std::vector<uint64_t>().max_size();
    if (config.set_size == std::numeric_limits<uint64_t>::max() ||
        config.set_size >= maximum_bins) {
        throw std::invalid_argument("set size cannot represent histogram bins");
    }
}

}  // namespace

uint64_t UniformBelow(std::mt19937_64& generator, uint64_t bound) {
    if (bound == 0) {
        throw std::invalid_argument("uniform bound must be positive");
    }
    const uint64_t cutoff = (-bound) % bound;
    uint64_t word = 0;
    do {
        word = generator();
    } while (word < cutoff);
    return word % bound;
}

uint64_t SampleFirstFailure(
    const DeletionSurvivalConfig& config, std::mt19937_64& generator) {
    ValidateConfig(config);
    uint64_t first_failure = config.set_size;
    for (uint32_t coordinate = 0; coordinate < config.hash_count; ++coordinate) {
        std::unordered_set<uint64_t> selected;
        selected.reserve(static_cast<size_t>(config.bottom_depth));
        const uint64_t first_j = config.set_size - config.bottom_depth + 1;
        for (uint64_t j = first_j;; ++j) {
            const uint64_t candidate = UniformBelow(generator, j) + 1;
            selected.insert(selected.find(candidate) != selected.end() ? j : candidate);
            if (j == config.set_size) {
                break;
            }
        }

        uint64_t coordinate_failure = 0;
        for (uint64_t position : selected) {
            if (position > coordinate_failure) {
                coordinate_failure = position;
            }
        }
        if (coordinate_failure < first_failure) {
            first_failure = coordinate_failure;
        }
    }
    return first_failure;
}

long double DeletionMonteCarloResult::SurvivalAt(
    uint64_t completed_deletions) const {
    if (trials == 0 || completed_deletions >= failure_histogram.size()) {
        return 0.0L;
    }
    uint64_t survivors = 0;
    for (uint64_t failure = completed_deletions + 1;
         failure < failure_histogram.size(); ++failure) {
        survivors += failure_histogram[failure];
    }
    return static_cast<long double>(survivors) / static_cast<long double>(trials);
}

long double DeletionMonteCarloResult::StandardErrorAt(
    uint64_t completed_deletions) const {
    if (trials == 0) {
        return 0.0L;
    }
    const long double survival = SurvivalAt(completed_deletions);
    return std::sqrt(survival * (1.0L - survival) /
                     static_cast<long double>(trials));
}

DeletionMonteCarloResult SimulateDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t trials, uint64_t seed) {
    ValidateConfig(config);
    if (trials == 0) {
        throw std::invalid_argument("trials must be positive");
    }
    ValidateHistogramSize(config);

    DeletionMonteCarloResult result{trials, seed,
                                    std::vector<uint64_t>(config.set_size + 1, 0),
                                    0.0L, 0.0L};
    std::mt19937_64 generator(seed);
    for (uint64_t trial = 0; trial < trials; ++trial) {
        const uint64_t failure = SampleFirstFailure(config, generator);
        ++result.failure_histogram[failure];
        result.mean_first_failure_time += static_cast<long double>(failure);
        result.mean_safe_deletions += static_cast<long double>(failure - 1);
    }
    result.mean_first_failure_time /= static_cast<long double>(trials);
    result.mean_safe_deletions /= static_cast<long double>(trials);
    return result;
}

}  // namespace piccard
