#include <gtest/gtest.h>

#include "analysis/deletion_monte_carlo.h"

#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>

using namespace piccard;

TEST(DeletionMonteCarloTest, UniformBelowUsesPortableRawWordRejection) {
    std::mt19937_64 raw(20260729);
    EXPECT_EQ(raw(), UINT64_C(0x13abed35ef7208d7));
    EXPECT_EQ(raw(), UINT64_C(0xa821398ce4959c44));
    EXPECT_EQ(raw(), UINT64_C(0x3ec9d6707639929d));
    EXPECT_EQ(raw(), UINT64_C(0xb2413cc1f3082f90));
    EXPECT_EQ(raw(), UINT64_C(0x2376e8e55d856132));
    EXPECT_EQ(raw(), UINT64_C(0xc3cb86fe4cb18180));

    std::mt19937_64 generator(20260729);
    EXPECT_EQ(UniformBelow(generator, 1), 0u);
    EXPECT_EQ(UniformBelow(generator, 2), 0u);
    EXPECT_EQ(UniformBelow(generator, 3), 2u);
    EXPECT_EQ(UniformBelow(generator, 10), 8u);
    EXPECT_EQ(UniformBelow(generator, 1024), 306u);
    EXPECT_EQ(UniformBelow(generator, 1000), 296u);
}

TEST(DeletionMonteCarloTest, OneTrialIsSeededAndUsesStrictTGreaterThanR) {
    const DeletionSurvivalConfig config{8, 2, 3};
    const auto first = SimulateDeletionSurvival(config, 1, 7);
    const auto second = SimulateDeletionSurvival(config, 1, 7);
    EXPECT_EQ(first.failure_histogram, second.failure_histogram);
    ASSERT_EQ(first.failure_histogram.size(), 9u);
    EXPECT_EQ(first.failure_histogram[3], 1u);
    EXPECT_EQ(std::accumulate(first.failure_histogram.begin(),
                              first.failure_histogram.end(), uint64_t{0}),
              1u);
    EXPECT_EQ(first.SurvivalAt(2), 1.0L);
    EXPECT_EQ(first.SurvivalAt(3), 0.0L);
    EXPECT_EQ(first.mean_first_failure_time, 3.0L);
    EXPECT_EQ(first.mean_safe_deletions, 2.0L);
}

TEST(DeletionMonteCarloTest, RejectsUnrepresentableHistogramSizeBeforeSampling) {
    const DeletionSurvivalConfig config{std::numeric_limits<uint64_t>::max(), 1, 1};
    EXPECT_THROW(SimulateDeletionSurvival(config, 1, 7), std::invalid_argument);
}
