#include <gtest/gtest.h>

#include "analysis/deletion_survival.h"

#include <stdexcept>

using namespace piccard;

TEST(DeletionSurvivalTest, SmallFixtureAndOffByOneSemanticsAreExact) {
    const DeletionSurvivalConfig one{5, 2, 1};
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(one, 2)),
                0.9, 1e-12);
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(one, 3)),
                0.7, 1e-12);
    const DeletionSurvivalConfig two{5, 2, 2};
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(two, 3)),
                0.49, 1e-12);

    const auto summary = AnalyzeDeletionSurvival(one, 0.7L);
    EXPECT_EQ(summary.maximum_safe_deletions, 3u);
    EXPECT_NEAR(static_cast<double>(summary.expected_first_failure_time),
                4.0, 1e-12);
    EXPECT_NEAR(static_cast<double>(summary.expected_safe_deletions),
                3.0, 1e-12);
}

TEST(DeletionSurvivalTest, DefaultPoCGoldensMatchExactAnalysis) {
    const DeletionSurvivalConfig config{1024, 5, 128};
    const auto summary = AnalyzeDeletionSurvival(config, 0.99L);
    EXPECT_EQ(summary.maximum_safe_deletions, 156u);
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(config, 156)),
                0.990106970136603, 1e-12);
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(config, 157)),
                0.989783196554901, 1e-12);
    EXPECT_NEAR(static_cast<double>(summary.expected_first_failure_time),
                357.745231932978, 1e-9);
    EXPECT_NEAR(static_cast<double>(summary.expected_safe_deletions),
                356.745231932978, 1e-9);
}

TEST(DeletionSurvivalTest, UnionBoundIsConservativeForSmallFixture) {
    const DeletionSurvivalConfig config{5, 2, 2};
    EXPECT_NEAR(static_cast<double>(UnionBoundDeletionSurvival(config, 3)),
                0.4, 1e-12);
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(config, 3)),
                0.49, 1e-12);
}

TEST(DeletionSurvivalTest, InvalidConfigurationAndDeletionCountAreRejected) {
    EXPECT_THROW(
        BottomExhaustionProbability(DeletionSurvivalConfig{5, 6, 1}, 0),
        std::invalid_argument);
    EXPECT_THROW(
        ExactDeletionSurvival(DeletionSurvivalConfig{5, 2, 1}, 6),
        std::invalid_argument);
}
