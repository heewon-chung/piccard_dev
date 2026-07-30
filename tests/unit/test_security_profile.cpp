#include "util/security_profile.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace piccard {
namespace {

TEST(CeilLog2, AcceptsEveryPositiveInteger) {
    EXPECT_EQ(CeilLog2(1), 0u);
    EXPECT_EQ(CeilLog2(2), 1u);
    EXPECT_EQ(CeilLog2(3), 2u);
    EXPECT_EQ(CeilLog2(5), 3u);
}

TEST(CeilLog2, RejectsZero) {
    EXPECT_THROW(CeilLog2(0), std::invalid_argument);
}

TEST(SanitizerProfile, DerivesExactTranscriptAndCoefficientTargets) {
    struct Case {
        uint32_t transcript_stat_bits;
        uint64_t max_queries;
        uint64_t realized_ring_dim;
        uint32_t expected_query_stat_bits;
        uint32_t expected_coefficient_stat_bits;
    };

    constexpr uint32_t kEvalNoiseBits = 100;
    constexpr uint32_t kFloodMarginBits = 8;
    const Case cases[] = {
        {40, 1, UINT64_C(8192), 40, 53},
        {40, UINT64_C(1) << 20, UINT64_C(8192), 60, 73},
        {64, UINT64_C(1) << 20, UINT64_C(16384), 84, 98},
        {128, UINT64_C(1) << 20, UINT64_C(32768), 148, 163},
    };

    for (const auto& test_case : cases) {
        const SanitizerProfile profile = DeriveSanitizerProfile(
            test_case.transcript_stat_bits,
            test_case.max_queries,
            test_case.realized_ring_dim,
            kEvalNoiseBits,
            kFloodMarginBits);

        EXPECT_EQ(profile.transcript_stat_bits,
                  test_case.transcript_stat_bits);
        EXPECT_EQ(profile.max_queries, test_case.max_queries);
        EXPECT_EQ(profile.realized_ring_dim, test_case.realized_ring_dim);
        EXPECT_EQ(profile.eval_noise_bits, kEvalNoiseBits);
        EXPECT_EQ(profile.flood_margin_bits, kFloodMarginBits);
        EXPECT_EQ(profile.query_adjustment_bits,
                  CeilLog2(test_case.max_queries));
        EXPECT_EQ(profile.coefficient_adjustment_bits,
                  CeilLog2(test_case.realized_ring_dim));
        EXPECT_EQ(profile.query_stat_bits,
                  test_case.expected_query_stat_bits);
        EXPECT_EQ(profile.coefficient_stat_bits,
                  test_case.expected_coefficient_stat_bits);
        EXPECT_EQ(profile.flood_noise_bits,
                  kEvalNoiseBits +
                      test_case.expected_coefficient_stat_bits +
                      kFloodMarginBits);
    }
}

TEST(SanitizerProfile, AcceptsNonPowerOfTwoQueryCount) {
    const SanitizerProfile profile =
        DeriveSanitizerProfile(40, 3, 8192, 100, 8);

    EXPECT_EQ(profile.query_adjustment_bits, 2u);
    EXPECT_EQ(profile.query_stat_bits, 42u);
    EXPECT_EQ(profile.coefficient_stat_bits, 55u);
    EXPECT_EQ(profile.flood_noise_bits, 163u);
}

TEST(SanitizerProfile, RejectsInvalidRingDimensions) {
    EXPECT_THROW(
        DeriveSanitizerProfile(40, 1, 0, 100, 8),
        std::invalid_argument);
    EXPECT_THROW(
        DeriveSanitizerProfile(40, 1, 8193, 100, 8),
        std::invalid_argument);
}

TEST(SanitizerProfile, EnforcesQueryCountBoundary) {
    constexpr uint64_t kMaxSupportedQueries = UINT64_C(1) << 63;

    EXPECT_THROW(
        DeriveSanitizerProfile(40, 0, 8192, 100, 8),
        std::invalid_argument);

    const SanitizerProfile boundary =
        DeriveSanitizerProfile(40, kMaxSupportedQueries, 8192, 100, 8);
    EXPECT_EQ(boundary.query_adjustment_bits, 63u);
    EXPECT_EQ(boundary.query_stat_bits, 103u);

    EXPECT_THROW(
        DeriveSanitizerProfile(
            40, kMaxSupportedQueries + 1, 8192, 100, 8),
        std::invalid_argument);
}

TEST(SanitizerProfile, RejectsUnsupportedTranscriptTargets) {
    EXPECT_THROW(
        DeriveSanitizerProfile(0, 1, 8192, 100, 8),
        std::invalid_argument);
    EXPECT_THROW(
        DeriveSanitizerProfile(41, 1, 8192, 100, 8),
        std::invalid_argument);
}

TEST(CheckedAddBits, ReportsQueryStatOverflow) {
    try {
        static_cast<void>(CheckedAddBits(
            std::numeric_limits<uint32_t>::max(),
            1,
            SanitizerProfileField::QueryStatBits));
        FAIL() << "Expected query-stat addition to overflow";
    } catch (const std::overflow_error& error) {
        EXPECT_NE(std::string(error.what()).find("query_stat_bits"),
                  std::string::npos);
    }
}

TEST(CheckedAddBits, ReportsCoefficientStatOverflow) {
    try {
        static_cast<void>(CheckedAddBits(
            std::numeric_limits<uint32_t>::max() - 1,
            2,
            SanitizerProfileField::CoefficientStatBits));
        FAIL() << "Expected coefficient-stat addition to overflow";
    } catch (const std::overflow_error& error) {
        EXPECT_NE(std::string(error.what()).find("coefficient_stat_bits"),
                  std::string::npos);
    }
}

TEST(CheckedAddBits, ReportsFloodNoiseOverflow) {
    try {
        static_cast<void>(CheckedAddBits(
            std::numeric_limits<uint32_t>::max() - 7,
            8,
            SanitizerProfileField::FloodNoiseBits));
        FAIL() << "Expected flood-noise addition to overflow";
    } catch (const std::overflow_error& error) {
        EXPECT_NE(std::string(error.what()).find("flood_noise_bits"),
                  std::string::npos);
    }
}

TEST(SanitizerProfile, ChecksFinalFloodNoiseAddition) {
    EXPECT_THROW(
        DeriveSanitizerProfile(
            40,
            1,
            8192,
            std::numeric_limits<uint32_t>::max() - 60,
            8),
        std::overflow_error);
}

}  // namespace
}  // namespace piccard
