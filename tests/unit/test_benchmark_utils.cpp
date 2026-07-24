// test_benchmark_utils.cpp — focused dispersion test for DispersionStats / ComputeDispersion
//
// This is the sole automated guard against a sample-vs-population SD error,
// which a 2-trial quick run cannot catch on its own.

#include "benchmark_utils.h"
#include <gtest/gtest.h>
#include <cmath>
#include <vector>

using namespace piccard::benchmark;

// ── Empty vector ─────────────────────────────────────────────────────

TEST(BenchmarkUtils, EmptyVector) {
    auto s = ComputeDispersion({});
    EXPECT_EQ(s.n, 0u);
    EXPECT_DOUBLE_EQ(s.mean,   0.0);
    EXPECT_DOUBLE_EQ(s.sd,    -1.0);   // sentinel: undefined
    EXPECT_DOUBLE_EQ(s.median, 0.0);
}

// ── Single element: sd sentinel ───────────────────────────────────────

TEST(BenchmarkUtils, SingleElement) {
    auto s = ComputeDispersion({5.0});
    EXPECT_EQ(s.n, 1u);
    EXPECT_DOUBLE_EQ(s.mean,   5.0);
    EXPECT_DOUBLE_EQ(s.sd,    -1.0);   // n < 2 sentinel
    EXPECT_DOUBLE_EQ(s.median, 5.0);
}

// ── Three elements: mean, sample SD, median ───────────────────────────
//   {2, 4, 6}: mean=4, sd=sqrt(8/2)=2 (sample n-1), median=4

TEST(BenchmarkUtils, ThreeElements) {
    auto s = ComputeDispersion({2.0, 4.0, 6.0});
    EXPECT_EQ(s.n, 3u);
    EXPECT_DOUBLE_EQ(s.mean, 4.0);
    EXPECT_NEAR(s.sd,        2.0, 1e-10);   // sample: sqrt((4+0+4)/2)
    EXPECT_DOUBLE_EQ(s.median, 4.0);
}

// ── Two elements: sample (n-1) vs population (n) discriminator ────────
//   {1, 5}: mean=3
//     population sd = sqrt(8/2) = 2.0
//     sample sd     = sqrt(8/1) = 2.828427...   ← must be this

TEST(BenchmarkUtils, SampleNotPopulationSd) {
    auto s = ComputeDispersion({1.0, 5.0});
    EXPECT_EQ(s.n, 2u);
    EXPECT_DOUBLE_EQ(s.mean,   3.0);
    EXPECT_NEAR(s.sd, std::sqrt(8.0), 1e-10);   // sample (n-1=1)
    EXPECT_DOUBLE_EQ(s.median, 3.0);             // mean of the two values
}

// ── Unsorted input: caller's vector must be unchanged (taken by value) ─

TEST(BenchmarkUtils, UnsortedInputCallerVectorUnchanged) {
    std::vector<double> v = {9.0, 1.0, 5.0};
    auto s = ComputeDispersion(v);
    // By-value copy: original order preserved
    ASSERT_EQ(v.size(), 3u);
    EXPECT_DOUBLE_EQ(v[0], 9.0);
    EXPECT_DOUBLE_EQ(v[1], 1.0);
    EXPECT_DOUBLE_EQ(v[2], 5.0);
    // Correct median of {1, 5, 9} = 5
    EXPECT_DOUBLE_EQ(s.median, 5.0);
    EXPECT_NEAR(s.mean, 5.0, 1e-10);
}
