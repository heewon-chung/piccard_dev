#include "estimator_diagnostic.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using namespace piccard::benchmark;

namespace {

size_t CsvColumns(const std::string& line) {
    return static_cast<size_t>(std::count(line.begin(), line.end(), ',')) + 1;
}

DiagnosticConfig SmallConfig() {
    DiagnosticConfig config;
    config.k = 8;
    config.m = 16;
    config.set_size = 6;
    config.trials = 3;
    config.root_seed = 20260729;
    config.jaccard_grid = ParseJaccardGrid("0.5");
    return config;
}

void ExpectFinite(const EstimateStatistics& statistics) {
    EXPECT_TRUE(std::isfinite(statistics.mean));
    EXPECT_TRUE(std::isfinite(statistics.bias));
    EXPECT_TRUE(std::isfinite(statistics.mae));
    ASSERT_TRUE(statistics.sample_sd.has_value());
    EXPECT_TRUE(std::isfinite(*statistics.sample_sd));
    ASSERT_TRUE(statistics.standard_error.has_value());
    EXPECT_TRUE(std::isfinite(*statistics.standard_error));
}

}  // namespace

TEST(EstimatorDiagnostic, ConstructsExactRequestedJaccardSets) {
    const SetPair zero = ConstructSetPair(3, ParseJaccardPoint("0"));
    EXPECT_EQ(zero.a, (std::vector<uint64_t>{0, 1, 2}));
    EXPECT_EQ(zero.b, (std::vector<uint64_t>{3, 4, 5}));
    EXPECT_EQ(zero.intersection_size, 0u);
    EXPECT_DOUBLE_EQ(zero.realized_jaccard, 0.0);

    const SetPair half = ConstructSetPair(3, ParseJaccardPoint("0.5"));
    EXPECT_EQ(half.a, (std::vector<uint64_t>{0, 1, 2}));
    EXPECT_EQ(half.b, (std::vector<uint64_t>{0, 1, 3}));
    EXPECT_EQ(half.intersection_size, 2u);
    EXPECT_DOUBLE_EQ(half.realized_jaccard, 0.5);

    const SetPair one = ConstructSetPair(3, ParseJaccardPoint("1"));
    EXPECT_EQ(one.a, (std::vector<uint64_t>{0, 1, 2}));
    EXPECT_EQ(one.b, one.a);
    EXPECT_EQ(one.intersection_size, 3u);
    EXPECT_DOUBLE_EQ(one.realized_jaccard, 1.0);
}

TEST(EstimatorDiagnostic, DerivesPinnedTrialSeeds) {
    EXPECT_EQ(DeriveTrialSeed(20260729, 0, 0), 0x4233064eb10c5c9bULL);
    EXPECT_EQ(DeriveTrialSeed(20260729, 3, 7), 0x5c7c90995424145bULL);
    EXPECT_EQ(DeriveTrialSeed(20260729, 6, 9999),
              0xf4f5bd3387a71db3ULL);
}

TEST(EstimatorDiagnostic, AggregatesWithPinnedSampleDenominators) {
    const EstimateStatistics statistics =
        AggregateEstimates({0.0, 0.5, 1.0}, 0.5);
    EXPECT_DOUBLE_EQ(statistics.mean, 0.5);
    EXPECT_DOUBLE_EQ(statistics.bias, 0.0);
    EXPECT_DOUBLE_EQ(statistics.mae, 1.0 / 3.0);
    ASSERT_TRUE(statistics.sample_sd.has_value());
    EXPECT_DOUBLE_EQ(*statistics.sample_sd, 0.5);
    ASSERT_TRUE(statistics.standard_error.has_value());
    EXPECT_DOUBLE_EQ(*statistics.standard_error, 0.5 / std::sqrt(3.0));

    const EstimateStatistics singleton = AggregateEstimates({0.25}, 0.5);
    EXPECT_FALSE(singleton.sample_sd.has_value());
    EXPECT_FALSE(singleton.standard_error.has_value());
}

TEST(EstimatorDiagnostic, RepeatedInputsSerializeIdentically) {
    const DiagnosticConfig config = SmallConfig();
    const DiagnosticRow first =
        RunDiagnosticPoint(config, config.jaccard_grid.front(), 0);
    const DiagnosticRow second =
        RunDiagnosticPoint(config, config.jaccard_grid.front(), 0);

    EXPECT_EQ(SerializeDiagnosticRow(first), SerializeDiagnosticRow(second));
}

TEST(EstimatorDiagnostic, CsvSchemaMatchesAndStatisticsAreFinite) {
    const DiagnosticConfig config = SmallConfig();
    const DiagnosticRow row =
        RunDiagnosticPoint(config, config.jaccard_grid.front(), 0);

    EXPECT_EQ(CsvColumns(SerializeDiagnosticHeader()),
              CsvColumns(SerializeDiagnosticRow(row)));
    ExpectFinite(row.raw_rank);
    ExpectFinite(row.bucket_match);
    ExpectFinite(row.corrected);
    EXPECT_TRUE(std::isfinite(row.raw_bias_limit));
    EXPECT_TRUE(std::isfinite(row.corrected_bias_limit));
}

TEST(EstimatorDiagnostic, IdenticalSetsAreExactForEveryEstimator) {
    DiagnosticConfig config = SmallConfig();
    config.trials = 2;
    config.jaccard_grid = ParseJaccardGrid("1");

    const DiagnosticRow row =
        RunDiagnosticPoint(config, config.jaccard_grid.front(), 0);

    for (const EstimateStatistics* statistics :
         {&row.raw_rank, &row.bucket_match, &row.corrected}) {
        EXPECT_DOUBLE_EQ(statistics->mean, 1.0);
        EXPECT_DOUBLE_EQ(statistics->bias, 0.0);
        EXPECT_DOUBLE_EQ(statistics->mae, 0.0);
        ASSERT_TRUE(statistics->sample_sd.has_value());
        EXPECT_DOUBLE_EQ(*statistics->sample_sd, 0.0);
        ASSERT_TRUE(statistics->standard_error.has_value());
        EXPECT_DOUBLE_EQ(*statistics->standard_error, 0.0);
    }
}

TEST(EstimatorDiagnostic, RejectsInvalidConfigurationAndGridPoints) {
    DiagnosticConfig config = SmallConfig();

    config.k = 0;
    EXPECT_THROW(ValidateDiagnosticConfig(config), std::invalid_argument);
    config = SmallConfig();
    config.m = 1;
    EXPECT_THROW(ValidateDiagnosticConfig(config), std::invalid_argument);
    config = SmallConfig();
    config.set_size = 0;
    EXPECT_THROW(ValidateDiagnosticConfig(config), std::invalid_argument);
    config = SmallConfig();
    config.trials = 0;
    EXPECT_THROW(ValidateDiagnosticConfig(config), std::invalid_argument);

    EXPECT_THROW(ParseJaccardGrid(""), std::invalid_argument);
    EXPECT_THROW(ParseJaccardGrid("-0.1"), std::invalid_argument);
    EXPECT_THROW(ParseJaccardGrid("1.1"), std::invalid_argument);
    EXPECT_THROW(ParseJaccardGrid("0.25,,0.75"), std::invalid_argument);
}
