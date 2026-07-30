// test_benchmark_utils.cpp — focused dispersion test for DispersionStats / ComputeDispersion
//
// This is the sole automated guard against a sample-vs-population SD error,
// which a 2-trial quick run cannot catch on its own.

#include "benchmark_utils.h"
#include "benchmark_estimator_provenance.h"
#include <gtest/gtest.h>
#include <cmath>
#include <set>
#include <stdexcept>
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

// ── HashTrialSeed: domain separation from set-generation seeds ────────
// Accuracy trials must draw the hash family independently of the sets. If the
// two seeds coincided for some (root, trial, overlap) the two draws would be
// correlated, so the separation is asserted, not assumed.

TEST(BenchmarkUtils, HashTrialSeedIsDeterministic) {
    EXPECT_EQ(HashTrialSeed(12345, 0, 0.3), HashTrialSeed(12345, 0, 0.3));
    EXPECT_EQ(HashTrialSeed(0, 7, 1.0), HashTrialSeed(0, 7, 1.0));
}

TEST(BenchmarkUtils, HashTrialSeedDiffersFromSetTrialSeed) {
    const double overlaps[] = {0.0, 0.1, 0.3, 0.5, 0.9, 1.0};
    for (uint64_t root : {0ULL, 1ULL, 42ULL, 999983ULL}) {
        for (size_t t = 0; t < 8; t++) {
            for (double o : overlaps) {
                EXPECT_NE(HashTrialSeed(root, t, o), TrialSeed(root, t, o))
                    << "root=" << root << " t=" << t << " overlap=" << o;
            }
        }
    }
}

TEST(BenchmarkUtils, HashTrialSeedVariesWithTrial) {
    std::set<uint64_t> seen;
    for (size_t t = 0; t < 64; t++) seen.insert(HashTrialSeed(42, t, 0.3));
    EXPECT_EQ(seen.size(), 64u) << "each trial must get its own hash seed";
}

TEST(BenchmarkUtils, HashTrialSeedVariesWithOverlap) {
    std::set<uint64_t> seen;
    for (int i = 0; i <= 10; i++) {
        seen.insert(HashTrialSeed(42, 3, static_cast<double>(i) / 10.0));
    }
    EXPECT_EQ(seen.size(), 11u) << "each overlap must get its own hash seed";
}

// The signature carries no k/m/n and no engine identity, which is exactly what
// lets a sweep and a sibling benchmark reuse one seed and stay paired.
TEST(BenchmarkUtils, HashTrialSeedIsReusableAcrossSweepsAndEngines) {
    const uint64_t expected = HashTrialSeed(2026, 5, 0.4);
    EXPECT_EQ(HashTrialSeed(2026, 5, 0.4), expected);
    EXPECT_EQ(HashTrialSeed(2026, 5, 0.4), expected);
}

// ── HashRandomness mode + CLI parsing ─────────────────────────────────

TEST(BenchmarkUtils, HashRandomnessNames) {
    EXPECT_STREQ(HashRandomnessName(HashRandomness::Resampled), "resampled");
    EXPECT_STREQ(HashRandomnessName(HashRandomness::Fixed), "fixed");
}

TEST(BenchmarkUtils, HashRandomnessDefaultsToResampled) {
    const char* argv[] = {"bench", "--seed=7"};
    auto cfg = BenchmarkConfig::ParseArgs(2, const_cast<char**>(argv));
    EXPECT_EQ(cfg.hash_randomness, HashRandomness::Resampled);
}

TEST(BenchmarkUtils, HashRandomnessParsesFixedAndResampled) {
    const char* argv_fixed[] = {"bench", "--seed=7", "--hash_randomness=fixed"};
    auto fixed = BenchmarkConfig::ParseArgs(3, const_cast<char**>(argv_fixed));
    EXPECT_EQ(fixed.hash_randomness, HashRandomness::Fixed);

    const char* argv_res[] = {"bench", "--seed=7",
                              "--hash_randomness=resampled"};
    auto res = BenchmarkConfig::ParseArgs(3, const_cast<char**>(argv_res));
    EXPECT_EQ(res.hash_randomness, HashRandomness::Resampled);
}

TEST(BenchmarkUtils, HashRandomnessRejectsUnknownValue) {
    const char* argv[] = {"bench", "--hash_randomness=sometimes"};
    EXPECT_THROW(BenchmarkConfig::ParseArgs(2, const_cast<char**>(argv)),
                 std::invalid_argument);
}

// The flag is optional: an invocation that predates it must still parse.
TEST(BenchmarkUtils, LegacyInvocationStillParses) {
    const char* argv[] = {"bench", "--k=64", "--m=16", "--mode=accuracy",
                          "--seed=7", "--trials=2"};
    auto cfg = BenchmarkConfig::ParseArgs(6, const_cast<char**>(argv));
    EXPECT_EQ(cfg.k, 64u);
    EXPECT_EQ(cfg.mode, "accuracy");
    EXPECT_EQ(cfg.seed, 7ULL);
    EXPECT_EQ(cfg.hash_randomness, HashRandomness::Resampled);
}

// A wrong model literal would make benchmark rows claim a different deployed
// estimator than the implementation actually uses.
TEST(BenchmarkUtils, EstimatorModelNamesAreStable) {
    EXPECT_STREQ(EstimatorModelName(
                     EstimatorModel::Sha256RandomRankingPocV1),
                 "sha256-random-ranking-poc-v1");
    EXPECT_STREQ(EstimatorModelName(EstimatorModel::NotApplicable),
                 "not-applicable");
}

// A serializer-side fallback would hide a missed row-construction assignment.
// Missing provenance must therefore be rejected rather than guessed.
TEST(BenchmarkUtils, BenchmarkSerializerRejectsMissingEstimatorModel) {
    BenchmarkResult row;
    row.label = "missing-provenance";
    EXPECT_THROW(SerializeBenchmarkRow(row), std::logic_error);
}
