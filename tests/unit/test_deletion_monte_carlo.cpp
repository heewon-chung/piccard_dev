#include <gtest/gtest.h>

#include "analysis/deletion_monte_carlo.h"
#include "analysis/deletion_survival.h"

#include <cmath>
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

// (n,d,k) = (1024,5,128) is the manuscript's fig:del-survival configuration.
// The Monte-Carlo survival estimate must agree with the exact curve
// Pr[r* > r] = (1 - C(r,d)/C(n,d))^k within sampling error at every plotted
// r, and must be distinguishable from the curve shifted by one deletion
// (Pr[r* > r+1]).  This is the evidence behind HANDOFF F7: the simulator in
// this repository has no one-step offset.
TEST(DeletionMonteCarloTest, PaperConfigurationTracksExactCurveWithoutOneStepShift) {
    const DeletionSurvivalConfig config{1024, 5, 128};
    const auto sim = SimulateDeletionSurvival(config, 400000, 20260902);
    for (uint64_t r = 0; r <= 520; r += 40) {
        const long double exact = ExactDeletionSurvival(config, r);
        const long double mc = sim.SurvivalAt(r);
        const long double se = sim.StandardErrorAt(r);
        EXPECT_LE(std::fabs(mc - exact), 4.0L * se) << "r=" << r;
    }
    // Mid-curve the one-step shift is ~1.4 percentage points, i.e. > 4 SE at
    // 400k trials: the estimate must sit above the shifted curve.
    for (uint64_t r : {280u, 320u, 360u, 400u}) {
        const long double shifted = ExactDeletionSurvival(config, r + 1);
        EXPECT_GT(sim.SurvivalAt(r) - shifted, 3.0L * sim.StandardErrorAt(r)) << "r=" << r;
    }
    const auto exact = AnalyzeDeletionSurvival(config, 0.99L);
    EXPECT_NEAR(static_cast<double>(exact.expected_first_failure_time), 357.745, 0.001);
    EXPECT_EQ(exact.maximum_safe_deletions, 156u);
    // E[r*] from simulation: 357.5331 at this seed; the "safe deletions"
    // expectation 356.745 must be excluded.
    EXPECT_GT(sim.mean_first_failure_time, 357.2L);
    EXPECT_LT(sim.mean_first_failure_time, 358.3L);
}
