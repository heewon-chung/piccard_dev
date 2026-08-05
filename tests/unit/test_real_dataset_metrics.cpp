#include "data/real_dataset_metrics.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using namespace piccard::data;

// ---------------------------------------------------------------------------
// ExactJaccard — sorted-unique uint64 feature-ID vectors.
// ---------------------------------------------------------------------------

TEST(ExactJaccardTest, BothEmptyIsZero) {
    EXPECT_DOUBLE_EQ(ExactJaccard({}, {}), 0.0);
}

TEST(ExactJaccardTest, OneEmptyIsZero) {
    EXPECT_DOUBLE_EQ(ExactJaccard({}, {1, 2, 3}), 0.0);
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2, 3}, {}), 0.0);
}

TEST(ExactJaccardTest, DisjointSetsIsZero) {
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2}, {3, 4}), 0.0);
}

TEST(ExactJaccardTest, IdenticalSetsIsOne) {
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2, 3}, {1, 2, 3}), 1.0);
}

TEST(ExactJaccardTest, PartialOverlapHandCalculated) {
    // {1,2,3} vs {2,3,4}: intersection={2,3} (2), union={1,2,3,4} (4).
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2, 3}, {2, 3, 4}), 0.5);
}

TEST(ExactJaccardTest, SubsetRelationshipHandCalculated) {
    // {1,2} subset of {1,2,3,4}: intersection=2, union=4.
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2}, {1, 2, 3, 4}), 0.5);
}

// ---------------------------------------------------------------------------
// FormatReal17 — must byte-match format_float() in
// scripts/prepare_real_datasets.py (shared golden table, Python side in
// tests/scripts/test_real_dataset_preprocess.py::FormattingGoldenTests).
// ---------------------------------------------------------------------------

namespace {
struct FormatVector {
    double input;
    const char* expected;
};

// Independently verified against scripts/prepare_real_datasets.py's
// format_float() before either side of this golden table was written; see
// FormattingGoldenTests in tests/scripts/test_real_dataset_preprocess.py for
// the byte-identical Python-side pin.
const std::vector<FormatVector>& FormatGoldenVectors() {
    static const std::vector<FormatVector> kVectors = {
        {0.0, "0"},
        {-0.0, "0"},
        {1.0, "1"},
        {-1.0, "-1"},
        {0.5, "0.5"},
        {-0.5, "-0.5"},
        {2.5, "2.5"},
        {7.5, "7.5"},
        {100.0, "100"},
        {-100.0, "-100"},
        {5.0, "5"},
        {42.0, "42"},
        {0.001, "0.001"},
        // Bucket boundaries (also exercised as JaccardBucketLabel inputs below).
        {0.1, "0.10000000000000001"},
        {0.3, "0.29999999999999999"},
        {0.6, "0.59999999999999998"},
        // Needs all 17 significant digits.
        {123456789.123456789, "123456789.12345679"},
        {0.6000000000000001, "0.60000000000000009"},
        {3.14159265358979, "3.14159265358979"},
        {1234567890123456.0, "1234567890123456"},
        {9999999999999998.0, "9999999999999998"},
        // Very small / very large magnitudes.
        {1e-300, "1e-300"},
        {1e300, "1.0000000000000001e+300"},
        {-1e300, "-1.0000000000000001e+300"},
        {1e-5, "1.0000000000000001e-05"},
        {1e16, "10000000000000000"},
        {1e17, "1e+17"},
        {1e-16, "9.9999999999999998e-17"},
        {1.7976931348623157e308, "1.7976931348623157e+308"},
        {2.2250738585072014e-308, "2.2250738585072014e-308"},
    };
    return kVectors;
}
}  // namespace

TEST(FormatReal17Test, MatchesSharedGoldenVectors) {
    for (const auto& v : FormatGoldenVectors()) {
        EXPECT_EQ(FormatReal17(v.input), v.expected) << "input=" << v.input;
    }
}

TEST(FormatReal17Test, RejectsNonFinite) {
    EXPECT_THROW(FormatReal17(std::numeric_limits<double>::quiet_NaN()), std::invalid_argument);
    EXPECT_THROW(FormatReal17(std::numeric_limits<double>::infinity()), std::invalid_argument);
    EXPECT_THROW(FormatReal17(-std::numeric_limits<double>::infinity()), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// JaccardBucketLabel — [0,.1)->b00_10, [.1,.3)->b10_30, [.3,.6)->b30_60,
// [.6,1]->b60_100. Upper endpoint 1 belongs to b60_100.
// ---------------------------------------------------------------------------

TEST(JaccardBucketLabelTest, LowerBucket) {
    EXPECT_STREQ(JaccardBucketLabel(0.0), "b00_10");
    EXPECT_STREQ(JaccardBucketLabel(0.099999), "b00_10");
}

TEST(JaccardBucketLabelTest, LowerBoundaryZeroPointOneIsExclusiveUpper) {
    EXPECT_STREQ(JaccardBucketLabel(0.1), "b10_30");
}

TEST(JaccardBucketLabelTest, MidBucket) {
    EXPECT_STREQ(JaccardBucketLabel(0.29999), "b10_30");
}

TEST(JaccardBucketLabelTest, BoundaryZeroPointThree) {
    EXPECT_STREQ(JaccardBucketLabel(0.3), "b30_60");
}

TEST(JaccardBucketLabelTest, UpperMidBucket) {
    EXPECT_STREQ(JaccardBucketLabel(0.59999), "b30_60");
}

TEST(JaccardBucketLabelTest, BoundaryZeroPointSix) {
    EXPECT_STREQ(JaccardBucketLabel(0.6), "b60_100");
}

TEST(JaccardBucketLabelTest, BoundaryOneBelongsToTopBucket) {
    EXPECT_STREQ(JaccardBucketLabel(1.0), "b60_100");
}

// ---------------------------------------------------------------------------
// Summarize — over finite abs errors.
// ---------------------------------------------------------------------------

TEST(SummarizeTest, EmptyInputHasZeroCount) {
    SummaryStats stats = Summarize({});
    EXPECT_EQ(stats.n, 0u);
}

TEST(SummarizeTest, SingleValueAllStatsEqualSoleValue) {
    SummaryStats stats = Summarize({0.25});
    EXPECT_EQ(stats.n, 1u);
    EXPECT_DOUBLE_EQ(stats.mae, 0.25);
    EXPECT_DOUBLE_EQ(stats.median, 0.25);
    EXPECT_DOUBLE_EQ(stats.p95, 0.25);
    EXPECT_DOUBLE_EQ(stats.max, 0.25);
}

TEST(SummarizeTest, GoldenTwoPairMedianIsMeanOfBothAndP95IsLargerNearestRank) {
    // Hand-calculated golden case (normative §Phase 5 RED): median of a
    // two-element set is the arithmetic mean of the two values; nearest-rank
    // P95 for n=2 is sorted[ceil(0.95*2)-1] = sorted[1], the larger value.
    SummaryStats stats = Summarize({0.3, 0.1});  // unsorted input on purpose
    EXPECT_EQ(stats.n, 2u);
    EXPECT_DOUBLE_EQ(stats.mae, 0.2);
    EXPECT_DOUBLE_EQ(stats.median, 0.2);
    EXPECT_DOUBLE_EQ(stats.p95, 0.3);
    EXPECT_DOUBLE_EQ(stats.max, 0.3);
    // sample_sd = sqrt(((0.1-0.2)^2 + (0.3-0.2)^2) / (2-1)) = sqrt(0.02).
    EXPECT_NEAR(stats.sample_sd, std::sqrt(0.02), 1e-12);
    // margin = 1.96 * sample_sd / sqrt(2) = 1.96 * 0.1 = 0.196 exactly
    // (sample_sd / sqrt(2) == 0.1 for this vector).
    EXPECT_NEAR(stats.ci95_low, 0.2 - 0.196, 1e-9);
    EXPECT_NEAR(stats.ci95_high, 0.2 + 0.196, 1e-9);
}

TEST(SummarizeTest, OddCountMedianIsCenterValue) {
    // n=5: sorted {0.1, 0.2, 0.3, 0.4, 0.5}; median is the center (0.3);
    // p95 = sorted[ceil(0.95*5)-1] = sorted[ceil(4.75)-1] = sorted[4] = 0.5.
    SummaryStats stats = Summarize({0.5, 0.1, 0.4, 0.2, 0.3});
    EXPECT_EQ(stats.n, 5u);
    EXPECT_DOUBLE_EQ(stats.median, 0.3);
    EXPECT_DOUBLE_EQ(stats.p95, 0.5);
    EXPECT_DOUBLE_EQ(stats.max, 0.5);
    EXPECT_NEAR(stats.mae, 0.3, 1e-12);
}

TEST(SummarizeTest, AsymmetricOddVectorPinsMedianDistinctFromMean) {
    // Asymmetric n=3: sorted {0.1, 0.1, 0.7}; median is the center value
    // (0.1) while the mean is 0.3 — a mean-as-median implementation fails.
    SummaryStats stats = Summarize({0.7, 0.1, 0.1});
    EXPECT_EQ(stats.n, 3u);
    EXPECT_DOUBLE_EQ(stats.median, 0.1);
    EXPECT_NEAR(stats.mae, 0.3, 1e-12);
    EXPECT_DOUBLE_EQ(stats.max, 0.7);
}

TEST(SummarizeTest, AsymmetricEvenVectorPinsMeanOfTwoCentersDistinctFromMean) {
    // Asymmetric n=4: sorted {0.1, 0.1, 0.2, 0.8}; median is the mean of the
    // two center values (0.1+0.2)/2 = 0.15 while the mean is 0.3.
    SummaryStats stats = Summarize({0.8, 0.1, 0.2, 0.1});
    EXPECT_EQ(stats.n, 4u);
    EXPECT_DOUBLE_EQ(stats.median, 0.15);
    EXPECT_NEAR(stats.mae, 0.3, 1e-12);
}

TEST(SummarizeTest, NearestRankP95DiffersFromMaxAtTwentyValues) {
    // n=20: for n < 20, ceil(0.95*n)-1 == n-1 makes p95 == max vacuously;
    // at n=20, p95 = sorted[ceil(19)-1] = sorted[18] while max = sorted[19].
    // Vector: 0.01..0.19 (19 values) plus an outlier 5.0.
    std::vector<double> values;
    for (int i = 1; i <= 19; ++i) values.push_back(i / 100.0);
    values.push_back(5.0);
    SummaryStats stats = Summarize(values);
    EXPECT_EQ(stats.n, 20u);
    EXPECT_NEAR(stats.p95, 0.19, 1e-12);
    EXPECT_DOUBLE_EQ(stats.max, 5.0);
    // median = (sorted[9] + sorted[10]) / 2 = (0.10 + 0.11) / 2 = 0.105;
    // mae = (sum(0.01..0.19) + 5.0) / 20 = (1.9 + 5.0) / 20 = 0.345.
    EXPECT_NEAR(stats.median, 0.105, 1e-12);
    EXPECT_NEAR(stats.mae, 0.345, 1e-12);
}
