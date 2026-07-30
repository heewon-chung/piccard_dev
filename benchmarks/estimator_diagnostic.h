#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Exact reduced rational parsed from a decimal Jaccard grid point. */
struct ExactRational {
    uint64_t numerator = 0;
    uint64_t denominator = 1;
    std::string decimal = "0";
};

/** @brief Deterministically constructed equal-cardinality input sets. */
struct SetPair {
    std::vector<uint64_t> a;
    std::vector<uint64_t> b;
    uint64_t intersection_size = 0;
    double realized_jaccard = 0.0;
};

/** @brief Inputs shared by every point in an estimator diagnostic run. */
struct DiagnosticConfig {
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t set_size = 0;
    uint64_t trials = 0;
    uint64_t root_seed = 0;
    std::vector<ExactRational> jaccard_grid;
};

/** @brief Empirical error statistics for one estimator. */
struct EstimateStatistics {
    double mean = 0.0;
    double bias = 0.0;
    double mae = 0.0;
    std::optional<double> sample_sd;
    std::optional<double> standard_error;
};

/** @brief One reproducible CSV row for one requested Jaccard point. */
struct DiagnosticRow {
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t set_size = 0;
    ExactRational target_jaccard;
    double realized_jaccard = 0.0;
    uint64_t intersection_size = 0;
    uint64_t trials = 0;
    uint64_t root_seed = 0;
    EstimateStatistics raw_rank;
    EstimateStatistics bucket_match;
    EstimateStatistics corrected;
    double raw_bias_limit = 0.0;
    double corrected_bias_limit = 0.0;
    bool raw_passed = false;
    bool corrected_passed = false;
};

/** @brief Parse one unsigned exact decimal in the closed interval [0, 1]. */
ExactRational ParseJaccardPoint(const std::string& text);

/** @brief Parse a nonempty comma-separated exact-decimal Jaccard grid. */
std::vector<ExactRational> ParseJaccardGrid(const std::string& text);

/** @brief Validate the pure diagnostic configuration (one trial is allowed). */
void ValidateDiagnosticConfig(const DiagnosticConfig& config);

/** @brief Construct equal-size sets using the phase-pinned rounding rule. */
SetPair ConstructSetPair(uint64_t set_size, const ExactRational& target);

/** @brief Derive a domain-separated per-grid, per-trial MinHasher seed. */
uint64_t DeriveTrialSeed(uint64_t root_seed,
                         uint32_t grid_index,
                         uint64_t trial_index);

/** @brief Aggregate pure trial estimates around one realized Jaccard value. */
EstimateStatistics AggregateEstimates(const std::vector<double>& estimates,
                                      double realized_jaccard);

/** @brief Run and aggregate one deterministic empirical grid point. */
DiagnosticRow RunDiagnosticPoint(const DiagnosticConfig& config,
                                 const ExactRational& target,
                                 uint32_t grid_index);

/** @brief Serialize the stable diagnostic CSV header. */
std::string SerializeDiagnosticHeader();

/** @brief Serialize one diagnostic CSV row. */
std::string SerializeDiagnosticRow(const DiagnosticRow& row);

}  // namespace benchmark
}  // namespace piccard
