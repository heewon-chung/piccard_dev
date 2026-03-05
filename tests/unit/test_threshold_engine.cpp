#include <gtest/gtest.h>
#include "piccard/protocol/threshold_piccard.h"

using namespace piccard;

class ThresholdEngineTest : public ::testing::Test {
protected:
    void SetUpWithTau(uint32_t tau) {
        params.k = 16;   // Small k for fast polynomial evaluation
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.threshold_mode = true;
        params.threshold_tau = tau;
        params.Validate();

        engine = std::make_unique<ThresholdPiccard>(params);
        engine->KeyGen();
    }

    PiccardParams params;
    std::unique_ptr<ThresholdPiccard> engine;
};

TEST_F(ThresholdEngineTest, IdenticalSetsAboveThreshold) {
    // Identical sets: match_count = k = 16. Use tau = 10 (well below k).
    SetUpWithTau(10);

    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 50; i++) set.push_back(i);

    bool result = engine->Run(set, set);
    EXPECT_TRUE(result) << "Identical sets should exceed threshold tau=10";
}

TEST_F(ThresholdEngineTest, DisjointSetsBelowThreshold) {
    // Disjoint sets: match_count ≈ k/m = 2. Use tau = 8 (above expected collisions).
    SetUpWithTau(8);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 50; i++) {
        set_a.push_back(i);
        set_b.push_back(i + 100000);
    }

    bool result = engine->Run(set_a, set_b);
    EXPECT_FALSE(result) << "Disjoint sets should be below threshold tau=8";
}

TEST_F(ThresholdEngineTest, ThresholdAtK) {
    // tau = k: only identical sets pass (match_count must be exactly k)
    SetUpWithTau(16);

    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 50; i++) set.push_back(i);

    bool result_identical = engine->Run(set, set);
    EXPECT_TRUE(result_identical) << "Identical sets should pass tau=k";
}

TEST_F(ThresholdEngineTest, TauZeroAlwaysPasses) {
    // tau = 0: u(x) = 1 for all x in [0..k], so any sets pass
    SetUpWithTau(0);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 50; i++) {
        set_a.push_back(i);
        set_b.push_back(i + 100000);
    }

    RecordProperty("input_tau", 0);
    RecordProperty("input_sets", "disjoint ({0..49} vs {100000..100049})");
    RecordProperty("expected", "true (tau=0 always passes)");

    bool result = engine->Run(set_a, set_b);
    RecordProperty("output", result ? "true" : "false");

    EXPECT_TRUE(result) << "tau=0 should always pass regardless of similarity";
}

TEST_F(ThresholdEngineTest, TauOneWithOverlap) {
    // tau = 1: passes when match_count >= 1
    // 50% overlap ensures match_count >> 1 (expected ~6.7), so result is robust
    SetUpWithTau(1);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    RecordProperty("input_tau", 1);
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{50..149}");
    RecordProperty("input_overlap", "50/150 (J=1/3)");
    RecordProperty("expected_match_count", "~6.7");
    RecordProperty("expected", "true (6.7 >= 1)");

    bool result = engine->Run(set_a, set_b);
    RecordProperty("output", result ? "true" : "false");

    EXPECT_TRUE(result) << "50% overlap should easily pass tau=1";
}

TEST_F(ThresholdEngineTest, PartialOverlapAboveThreshold) {
    // 50% overlap: |A intersection B|=50, |A union B|=150, J=1/3
    // Expected v/k ~= J*(1-1/m) + 1/m = (1/3)*(7/8) + 1/8 ~= 0.417
    // Expected match_count ~= 0.417 * 16 ~= 6.7
    // tau = 4: should pass comfortably (6.7 >= 4)
    SetUpWithTau(4);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    RecordProperty("input_tau", 4);
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{50..149}");
    RecordProperty("input_overlap", "50/150 (J=1/3)");
    RecordProperty("expected_match_count", "~6.7");
    RecordProperty("expected", "true (6.7 >= 4)");

    bool result = engine->Run(set_a, set_b);
    RecordProperty("output", result ? "true" : "false");

    EXPECT_TRUE(result) << "50% overlap should pass tau=4 (expected match ~= 6.7)";
}

TEST_F(ThresholdEngineTest, HighThresholdRejectsPartialOverlap) {
    // 50% overlap: expected match_count ~= 6.7
    // tau = 14: well above expected match_count, should fail
    SetUpWithTau(14);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    RecordProperty("input_tau", 14);
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{50..149}");
    RecordProperty("input_overlap", "50/150 (J=1/3)");
    RecordProperty("expected_match_count", "~6.7");
    RecordProperty("expected", "false (6.7 < 14)");

    bool result = engine->Run(set_a, set_b);
    RecordProperty("output", result ? "true" : "false");

    EXPECT_FALSE(result) << "Partial overlap should fail tau=14 (match ~= 6.7 < 14)";
}

TEST_F(ThresholdEngineTest, SymmetryOfThreshold) {
    // Threshold decision should be symmetric: threshold(A,B) == threshold(B,A)
    SetUpWithTau(4);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 80; i++) set_a.push_back(i);
    for (uint64_t i = 30; i < 120; i++) set_b.push_back(i);

    RecordProperty("input_tau", 4);
    RecordProperty("input_set_a", "{0..79}");
    RecordProperty("input_set_b", "{30..119}");

    bool result_ab = engine->Run(set_a, set_b);
    bool result_ba = engine->Run(set_b, set_a);

    RecordProperty("output_threshold(A,B)", result_ab ? "true" : "false");
    RecordProperty("output_threshold(B,A)", result_ba ? "true" : "false");

    EXPECT_EQ(result_ab, result_ba) << "Threshold should be symmetric";
}
