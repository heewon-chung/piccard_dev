#include "benchmark_profile.h"
#include "benchmark_utils.h"

#include <gtest/gtest.h>

#include <array>
#include <stdexcept>
#include <string>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;

namespace {

BenchmarkConfig Parse(std::vector<std::string> args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) argv.push_back(arg.data());
    return BenchmarkConfig::ParseArgs(
        static_cast<int>(argv.size()), argv.data(), [] { return UINT64_C(7); });
}

std::vector<std::string> Keys(const std::vector<BenchmarkGridPoint>& points) {
    std::vector<std::string> keys;
    keys.reserve(points.size());
    for (const auto& point : points) keys.push_back(point.Key());
    return keys;
}

}  // namespace

TEST(BenchmarkProfile, ResolvesAllSevenExactProfiles) {
    struct Expected {
        const char* id;
        SecurityLevel security;
        uint32_t target_security_bits;
        uint32_t transcript_stat_bits;
        BenchmarkRunClass run_class;
        bool comparison_eligible;
    };
    const std::array<Expected, 7> expected = {{
        {"std128-t40-primary", SecurityLevel::STD128, 128, 40,
         BenchmarkRunClass::Primary, true},
        {"std192-t40-primary", SecurityLevel::STD192, 192, 40,
         BenchmarkRunClass::Primary, true},
        {"std128-t64-sensitivity", SecurityLevel::STD128, 128, 64,
         BenchmarkRunClass::Sensitivity, false},
        {"std192-t64-sensitivity", SecurityLevel::STD192, 192, 64,
         BenchmarkRunClass::Sensitivity, false},
        {"std128-t128-feasibility", SecurityLevel::STD128, 128, 128,
         BenchmarkRunClass::Feasibility, false},
        {"std192-t128-feasibility", SecurityLevel::STD192, 192, 128,
         BenchmarkRunClass::Feasibility, false},
        {"toy-smoke", SecurityLevel::TOY, 0, 40,
         BenchmarkRunClass::Smoke, false},
    }};

    for (const auto& want : expected) {
        const auto& got = ResolveBenchmarkProfile(want.id);
        EXPECT_EQ(got.id, want.id);
        EXPECT_EQ(got.security, want.security);
        EXPECT_EQ(got.target_security_bits, want.target_security_bits);
        EXPECT_EQ(got.transcript_stat_bits, want.transcript_stat_bits);
        EXPECT_EQ(got.max_queries, UINT64_C(1) << 20);
        EXPECT_EQ(got.query_adjustment_bits, 20u);
        EXPECT_EQ(got.run_class, want.run_class);
        EXPECT_EQ(got.comparison_eligible, want.comparison_eligible);
    }
}

TEST(BenchmarkProfile, FeasibilityProfilesCannotBecomePrimary) {
    for (const char* id : {"std128-t128-feasibility",
                           "std192-t128-feasibility"}) {
        const auto& profile = ResolveBenchmarkProfile(id);
        EXPECT_EQ(profile.run_class, BenchmarkRunClass::Feasibility);
        EXPECT_FALSE(profile.comparison_eligible);
        EXPECT_FALSE(profile.failure_is_blocking);
    }
}

TEST(BenchmarkProfile, UnknownProfileFailsClosed) {
    EXPECT_THROW(ResolveBenchmarkProfile("std128-t41-primary"),
                 std::invalid_argument);
}

TEST(BenchmarkProfile, MatchingOverridesAreAcceptedAndConflictsFail) {
    const auto matching = Parse({"bench", "--profile=std128-t40-primary",
                                 "--security=STD128",
                                 "--transcript_stat_bits=40",
                                 "--max_queries=1048576"});
    EXPECT_EQ(matching.profile.id, "std128-t40-primary");
    EXPECT_EQ(matching.security_level, SecurityLevel::STD128);

    for (const auto& conflict : std::vector<std::vector<std::string>>{
             {"bench", "--profile=std128-t40-primary", "--security=STD192"},
             {"bench", "--profile=std128-t40-primary",
              "--transcript_stat_bits=64"},
             {"bench", "--profile=std128-t40-primary", "--max_queries=17"},
         }) {
        EXPECT_THROW(Parse(conflict), std::invalid_argument);
    }
}

TEST(BenchmarkProfile, LegacyCliIsExplicitlyLegacy) {
    const auto config = Parse({"bench", "--seed=11"});
    EXPECT_EQ(config.profile.id, "legacy");
    EXPECT_EQ(config.profile.run_class, BenchmarkRunClass::Legacy);
    EXPECT_FALSE(config.profile.comparison_eligible);
}

TEST(BenchmarkProfile, TargetJaccardParsesExactEndpoints) {
    const auto zero = Parse({"bench", "--profile=toy-smoke",
                             "--evidence_point", "--target-jaccard=0.0"});
    const auto one = Parse({"bench", "--profile=toy-smoke",
                            "--evidence_point", "--target-jaccard=1.0"});
    EXPECT_DOUBLE_EQ(zero.target_jaccard, 0.0);
    EXPECT_DOUBLE_EQ(one.target_jaccard, 1.0);
    EXPECT_THROW(Parse({"bench", "--profile=toy-smoke",
                        "--evidence_point", "--target-jaccard=0.5junk"}),
                 std::invalid_argument);
}

TEST(BenchmarkProfile, EvidencePointIsExactlyTheSuppliedPoint) {
    const BenchmarkGridPoint supplied{"evidence", 128, 64, 1000, 0, 0.5};
    for (const char* id : {"std128-t64-sensitivity",
                           "std192-t64-sensitivity",
                           "std128-t128-feasibility",
                           "std192-t128-feasibility"}) {
        const auto points = ResolveBenchmarkGrid(
            ResolveBenchmarkProfile(id), BenchmarkProducer::Piccard,
            BenchmarkMode::Timing, true, supplied);
        ASSERT_EQ(points.size(), 1u);
        EXPECT_EQ(points.front().Key(), "evidence:k=128,m=64,n=1000,j=0.5");
    }
}

TEST(BenchmarkProfile, SensitivityAndFeasibilityRejectHiddenSweeps) {
    const BenchmarkGridPoint supplied{"evidence", 128, 64, 1000, 0, 0.5};
    EXPECT_THROW(
        ResolveBenchmarkGrid(ResolveBenchmarkProfile(
                                 "std128-t64-sensitivity"),
                             BenchmarkProducer::OneHotSqrt,
                             BenchmarkMode::Accuracy, false, supplied),
        std::invalid_argument);
    EXPECT_THROW(
        ResolveBenchmarkGrid(ResolveBenchmarkProfile(
                                 "std128-t128-feasibility"),
                             BenchmarkProducer::Piccard,
                             BenchmarkMode::Timing, false, supplied),
        std::invalid_argument);
}

TEST(BenchmarkProfile, PiccardPrimaryNativeGridIsExact) {
    const auto points = ResolveBenchmarkGrid(
        ResolveBenchmarkProfile("std128-t40-primary"),
        BenchmarkProducer::Piccard, BenchmarkMode::Timing, false, {});
    EXPECT_EQ(Keys(points), (std::vector<std::string>{
        "k:k=16,m=64,n=1000,j=0.5", "k:k=32,m=64,n=1000,j=0.5",
        "k:k=64,m=64,n=1000,j=0.5", "k:k=128,m=64,n=1000,j=0.5",
        "k:k=256,m=64,n=1000,j=0.5", "k:k=512,m=64,n=1000,j=0.5",
        "m:k=128,m=16,n=1000,j=0.5", "m:k=128,m=32,n=1000,j=0.5",
        "m:k=128,m=64,n=1000,j=0.5", "m:k=128,m=128,n=1000,j=0.5",
        "m:k=128,m=256,n=1000,j=0.5", "n:k=128,m=64,n=100,j=0.5",
        "n:k=128,m=64,n=1000,j=0.5", "n:k=128,m=64,n=10000,j=0.5",
        "n:k=128,m=64,n=100000,j=0.5"}));
}

TEST(BenchmarkProfile, OneHotNativeTimingAndAccuracyGridsAreExact) {
    const auto& profile = ResolveBenchmarkProfile("std192-t40-primary");
    EXPECT_EQ(Keys(ResolveBenchmarkGrid(profile, BenchmarkProducer::OneHotSqrt,
                                        BenchmarkMode::Timing, false, {})),
              (std::vector<std::string>{
                  "k:k=16,m=64,n=1000,j=0.5", "k:k=32,m=64,n=1000,j=0.5",
                  "k:k=64,m=64,n=1000,j=0.5", "k:k=128,m=64,n=1000,j=0.5",
                  "k:k=256,m=64,n=1000,j=0.5", "k:k=512,m=64,n=1000,j=0.5",
                  "m:k=128,m=4,n=1000,j=0.5", "m:k=128,m=16,n=1000,j=0.5",
                  "m:k=128,m=64,n=1000,j=0.5", "m:k=128,m=256,n=1000,j=0.5",
                  "n:k=128,m=64,n=100,j=0.5", "n:k=128,m=64,n=1000,j=0.5",
                  "n:k=128,m=64,n=10000,j=0.5", "n:k=128,m=64,n=100000,j=0.5"}));
    EXPECT_EQ(Keys(ResolveBenchmarkGrid(profile, BenchmarkProducer::OneHotSqrt,
                                        BenchmarkMode::Accuracy, false, {})),
              (std::vector<std::string>{
                  "j:k=128,m=64,n=1000,j=0", "j:k=128,m=64,n=1000,j=0.1",
                  "j:k=128,m=64,n=1000,j=0.2", "j:k=128,m=64,n=1000,j=0.3",
                  "j:k=128,m=64,n=1000,j=0.4", "j:k=128,m=64,n=1000,j=0.5",
                  "j:k=128,m=64,n=1000,j=0.6", "j:k=128,m=64,n=1000,j=0.7",
                  "j:k=128,m=64,n=1000,j=0.8", "j:k=128,m=64,n=1000,j=0.9",
                  "j:k=128,m=64,n=1000,j=1"}));
}

TEST(BenchmarkProfile, DynamicGridPreservesRequestedSetSize) {
    const auto points = ResolveBenchmarkGrid(
        ResolveBenchmarkProfile("std128-t40-primary"),
        BenchmarkProducer::Dynamic, BenchmarkMode::Timing, false, {});
    ASSERT_EQ(points.size(), 15u);
    EXPECT_EQ(points[0].set_size, 1000u);
    EXPECT_EQ(points[6].set_size, 1000u);
    EXPECT_EQ(points[12].set_size, 1000u);
}

TEST(BenchmarkProfile, DiagnosticGridsRemainPinned) {
    const auto& profile = ResolveBenchmarkProfile("toy-smoke");
    const auto crossover = ResolveBenchmarkGrid(
        profile, BenchmarkProducer::Crossover, BenchmarkMode::Timing,
        false, {});
    ASSERT_EQ(crossover.size(), 25u);
    EXPECT_EQ(crossover.front().Key(), "diagnostic:k=32,m=4,n=1000,j=0.5");
    EXPECT_EQ(crossover.back().Key(), "diagnostic:k=512,m=1024,n=1000,j=0.5");

    EXPECT_EQ(Keys(ResolveBenchmarkGrid(
                  profile, BenchmarkProducer::SqrtComparison,
                  BenchmarkMode::Timing, false, {})),
              (std::vector<std::string>{
                  "diagnostic:k=128,m=64,n=500,j=0.5",
                  "diagnostic:k=256,m=64,n=500,j=0.5",
                  "diagnostic:k=512,m=64,n=500,j=0.5",
                  "diagnostic:k=1024,m=64,n=500,j=0.5",
                  "diagnostic:k=128,m=256,n=500,j=0.5",
                  "diagnostic:k=128,m=1024,n=500,j=0.5"}));
}

TEST(BenchmarkProfile, CombinedExpandsToTimingAndAccuracyRows) {
    EXPECT_EQ(MeasurementKindsForMode(BenchmarkMode::Combined),
              (std::vector<BenchmarkMeasurementKind>{
                  BenchmarkMeasurementKind::FheTiming,
                  BenchmarkMeasurementKind::FheAccuracy}));
}

TEST(BenchmarkProfile, ReviewerComparisonGridIsExactlyTwoUniverses) {
    const auto points = ResolveBenchmarkGrid(
        ResolveBenchmarkProfile("std128-t40-primary"),
        BenchmarkProducer::Comparison, BenchmarkMode::Combined, false, {});
    ASSERT_EQ(points.size(), 2u);
    EXPECT_EQ(points[0].universe_size, 16384u);
    EXPECT_EQ(points[1].universe_size, 65536u);
    EXPECT_EQ(points[0].k, 128u);
    EXPECT_EQ(points[0].m, 64u);
    EXPECT_EQ(points[0].set_size, 1000u);
}

TEST(BenchmarkProfile, UnknownOptionsAreFatalAfterExtensionsAreDeclared) {
    const char* invalid[] = {"bench", "--profile=toy-smoke", "--typo=1"};
    EXPECT_THROW(RejectUnknownBenchmarkOptions(
                     3, const_cast<char**>(invalid)),
                 std::invalid_argument);

    const char* extension[] = {
        "bench", "--profile=toy-smoke", "--depth=5"};
    EXPECT_NO_THROW(RejectUnknownBenchmarkOptions(
        3, const_cast<char**>(extension), {"--depth="}));
}
