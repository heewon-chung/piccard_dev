#include "noise_calibration_probe.h"

#include "util/params_calibration.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <random>

using namespace piccard;
using namespace piccard::std_evidence::calibration;

TEST(NoiseCalibrationProbe, PatternSeedsAreDomainSeparatedAndStable) {
    const uint64_t first = DerivePatternSeed(
        7, "onehot", 1024, 3, 40, Pattern::AllMatch);
    EXPECT_EQ(first, DerivePatternSeed(
                         7, "onehot", 1024, 3, 40, Pattern::AllMatch));
    EXPECT_NE(first, DerivePatternSeed(
                         7, "onehot", 1024, 3, 40, Pattern::NoMatch));
    EXPECT_NE(first, DerivePatternSeed(
                         7, "sqrt", 1024, 3, 40, Pattern::AllMatch));
    EXPECT_STREQ(PatternName(Pattern::Random), "random");
}

TEST(NoiseCalibrationProbe, SyntheticPatternsHaveExactRegimes) {
    for (const Pattern pattern : {Pattern::AllMatch, Pattern::NoMatch,
                                  Pattern::Random}) {
        std::mt19937_64 rng(DerivePatternSeed(
            7, "onehot", 1024, 3, 40, pattern));
        const auto [lhs, rhs] = MakeSignatures(pattern, 16, 16, rng);
        ASSERT_EQ(lhs.size(), 16u);
        ASSERT_EQ(rhs.size(), 16u);
        const int64_t matches = ExpectedMatches(lhs, rhs, 16);
        if (pattern == Pattern::AllMatch) EXPECT_EQ(matches, 16);
        if (pattern == Pattern::NoMatch) EXPECT_EQ(matches, 0);
        if (pattern == Pattern::Random) EXPECT_GE(matches, 0);
        if (pattern == Pattern::Random) EXPECT_LE(matches, 16);
    }
}

TEST(NoiseCalibrationProbe, BudgetUsesFrozenDiagnosticFormula) {
    const auto budget = ComputeBudget(
        56.1, 1024, 240.0, 65537, 40, UINT64_C(1) << 20, 8, 136.0);
    EXPECT_EQ(budget.eval_noise_bits, 57u);
    EXPECT_EQ(budget.query_stat_bits, 60u);
    EXPECT_EQ(budget.coefficient_stat_bits, 70u);
    EXPECT_EQ(budget.flood_noise_bits, 135u);
    EXPECT_EQ(budget.required_capacity_bits, 137u);
    EXPECT_DOUBLE_EQ(budget.log_q_over_t_bits,
                     240.0 - std::log2(65537.0));
    EXPECT_FALSE(budget.saturated);
    EXPECT_FALSE(budget.fits);

    const auto inclusive = ComputeBudget(1.0, 1024, 240.0, 65537, 40,
                                         UINT64_C(1) << 20, 8, 81.0);
    EXPECT_TRUE(inclusive.fits);
}

TEST(NoiseCalibrationProbe, ContextDescriptionUsesLiveMetadata) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();
    BFVContext context(params);
    context.InitializeContextOnly();

    const auto description = DescribeContext(context);
    EXPECT_EQ(description.metadata.context_fingerprint,
              context.ContextFingerprintHex());
    EXPECT_EQ(description.metadata.ordered_rns_moduli.size(),
              description.metadata.num_limbs);
    EXPECT_GT(description.modulus_q.ConvertToDouble(), 0.0);
    EXPECT_GT(description.log_delta_bits, 0.0);
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}
