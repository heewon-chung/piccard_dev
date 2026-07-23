#include <gtest/gtest.h>
#include "protocol/piccard.h"

#include <cmath>
#include <string>

using namespace piccard;

class PiccardE2ETest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 128;
        params.m = 64;
        params.security = SecurityLevel::TOY;
        params.Validate();

        engine = std::make_unique<Piccard>(params);
        engine->KeyGen();
    }

    static double ExactJaccard(const std::vector<uint64_t>& a,
                               const std::vector<uint64_t>& b) {
        std::set<uint64_t> sa(a.begin(), a.end());
        std::set<uint64_t> sb(b.begin(), b.end());
        size_t inter = 0;
        for (auto x : sa) {
            if (sb.count(x)) inter++;
        }
        size_t uni = sa.size() + sb.size() - inter;
        if (uni == 0) return 1.0;
        return static_cast<double>(inter) / static_cast<double>(uni);
    }

    PiccardParams params;
    std::unique_ptr<Piccard> engine;
};

TEST_F(PiccardE2ETest, IdenticalSets) {
    RecordProperty("input_k", 128);
    RecordProperty("input_m", 64);
    RecordProperty("input_set", "{0..199}");
    RecordProperty("expected_jaccard", "1.0");

    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 200; i++) set.push_back(i);

    auto result = engine->Run(set, set);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_NEAR(result.jaccard_estimate, 1.0, 0.01);
}

TEST_F(PiccardE2ETest, DisjointSets) {
    RecordProperty("input_k", 128);
    RecordProperty("input_m", 64);
    RecordProperty("input_set_a", "{0..199}");
    RecordProperty("input_set_b", "{100000..100199}");
    RecordProperty("expected_jaccard", "0.0");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 200; i++) {
        set_a.push_back(i);
        set_b.push_back(i + 100000);
    }

    auto result = engine->Run(set_a, set_b);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_NEAR(result.jaccard_estimate, 0.0, 0.1);
}

TEST_F(PiccardE2ETest, VaryingOverlap) {
    RecordProperty("input_k", 128);
    RecordProperty("input_m", 64);
    RecordProperty("input_set_size", 200);

    std::vector<double> overlap_fractions = {0.0, 0.25, 0.5, 0.75, 1.0};

    for (size_t idx = 0; idx < overlap_fractions.size(); idx++) {
        double frac = overlap_fractions[idx];
        size_t set_size = 200;
        size_t overlap = static_cast<size_t>(frac * set_size);

        std::vector<uint64_t> set_a, set_b;
        for (uint64_t i = 0; i < overlap; i++) {
            set_a.push_back(i);
            set_b.push_back(i);
        }
        for (uint64_t i = overlap; i < set_size; i++) {
            set_a.push_back(i + 1000000);
        }
        for (uint64_t i = overlap; i < set_size; i++) {
            set_b.push_back(i + 2000000);
        }

        double j_true = ExactJaccard(set_a, set_b);
        auto result = engine->Run(set_a, set_b);

        std::string prefix = "overlap_" + std::to_string(idx) + "_";
        RecordProperty(prefix + "fraction", std::to_string(frac));
        RecordProperty(prefix + "true_jaccard", std::to_string(j_true));
        RecordProperty(prefix + "match_count", std::to_string(result.match_count));
        RecordProperty(prefix + "jaccard_estimate", std::to_string(result.jaccard_estimate));
        RecordProperty(prefix + "error", std::to_string(std::abs(result.jaccard_estimate - j_true)));

        double tolerance = 0.15;
        EXPECT_NEAR(result.jaccard_estimate, j_true, tolerance)
            << "Overlap fraction: " << frac
            << ", true J: " << j_true
            << ", estimated J: " << result.jaccard_estimate;
    }
}

TEST_F(PiccardE2ETest, LargerSets) {
    RecordProperty("input_set_a", "{0..999}");
    RecordProperty("input_set_b", "{500..1499}");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 1000; i++) set_a.push_back(i);
    for (uint64_t i = 500; i < 1500; i++) set_b.push_back(i);

    double j_true = ExactJaccard(set_a, set_b);
    auto result = engine->Run(set_a, set_b);

    RecordProperty("true_jaccard", std::to_string(j_true));
    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));
    RecordProperty("output_error", std::to_string(std::abs(result.jaccard_estimate - j_true)));

    EXPECT_NEAR(result.jaccard_estimate, j_true, 0.15);
}

TEST_F(PiccardE2ETest, MatchCountBounds) {
    RecordProperty("input_set_a", "{1, 2, 3, 4, 5}");
    RecordProperty("input_set_b", "{6, 7, 8, 9, 10}");
    RecordProperty("expected_match_count_range", "[0, 128]");

    std::vector<uint64_t> set_a = {1, 2, 3, 4, 5};
    std::vector<uint64_t> set_b = {6, 7, 8, 9, 10};

    auto result = engine->Run(set_a, set_b);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_GE(result.match_count, 0);
    EXPECT_LE(result.match_count, static_cast<int64_t>(params.k));
}

TEST_F(PiccardE2ETest, Symmetry) {
    // J(A,B) must equal J(B,A) for the full pipeline
    RecordProperty("input_set_a", "{0..149}");
    RecordProperty("input_set_b", "{100..299}");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 150; i++) set_a.push_back(i);
    for (uint64_t i = 100; i < 300; i++) set_b.push_back(i);

    auto result_ab = engine->Run(set_a, set_b);
    auto result_ba = engine->Run(set_b, set_a);

    RecordProperty("output_J(A,B)_match", std::to_string(result_ab.match_count));
    RecordProperty("output_J(A,B)_estimate", std::to_string(result_ab.jaccard_estimate));
    RecordProperty("output_J(B,A)_match", std::to_string(result_ba.match_count));
    RecordProperty("output_J(B,A)_estimate", std::to_string(result_ba.jaccard_estimate));
    RecordProperty("true_jaccard", std::to_string(ExactJaccard(set_a, set_b)));

    EXPECT_EQ(result_ab.match_count, result_ba.match_count);
    EXPECT_DOUBLE_EQ(result_ab.jaccard_estimate, result_ba.jaccard_estimate);
}

TEST_F(PiccardE2ETest, SubsetRelationship) {
    // A ⊂ B: J(A,B) = |A|/|B|
    // A = {0..99}, B = {0..199}: J = 100/200 = 0.5
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{0..199}");
    RecordProperty("expected_jaccard", "0.5 (100/200)");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 0; i < 200; i++) set_b.push_back(i);

    double j_true = ExactJaccard(set_a, set_b);
    auto result = engine->Run(set_a, set_b);

    RecordProperty("output_true_jaccard", std::to_string(j_true));
    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));
    RecordProperty("output_error", std::to_string(std::abs(result.jaccard_estimate - j_true)));

    EXPECT_NEAR(result.jaccard_estimate, 0.5, 0.15);
}

TEST_F(PiccardE2ETest, SmallSets) {
    // Test with very small sets (edge case for MinHash)
    RecordProperty("input_set_a", "{1, 2, 3}");
    RecordProperty("input_set_b", "{2, 3, 4}");
    RecordProperty("expected_jaccard", "0.5 (2/4)");

    std::vector<uint64_t> set_a = {1, 2, 3};
    std::vector<uint64_t> set_b = {2, 3, 4};

    double j_true = ExactJaccard(set_a, set_b);
    auto result = engine->Run(set_a, set_b);

    RecordProperty("output_true_jaccard", std::to_string(j_true));
    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    // Wider tolerance for small sets (high variance with few elements)
    EXPECT_NEAR(result.jaccard_estimate, j_true, 0.3);
    EXPECT_GE(result.jaccard_estimate, 0.0);
    EXPECT_LE(result.jaccard_estimate, 1.0);
}

TEST_F(PiccardE2ETest, MonotonicallyIncreasingOverlap) {
    // As overlap increases, Jaccard estimate should generally increase
    RecordProperty("input_set_size", 200);
    RecordProperty("input_overlap_steps", "0, 50, 100, 150, 200");

    std::vector<uint64_t> set_a;
    for (uint64_t i = 0; i < 200; i++) set_a.push_back(i);

    double prev_j = -1.0;
    for (uint32_t overlap : {0u, 50u, 100u, 150u, 200u}) {
        std::vector<uint64_t> set_b;
        for (uint64_t i = 0; i < overlap; i++) set_b.push_back(i);
        for (uint64_t i = overlap; i < 200; i++) set_b.push_back(i + 1000000);

        auto result = engine->Run(set_a, set_b);

        std::string key = "overlap_" + std::to_string(overlap);
        RecordProperty(key + "_match_count", std::to_string(result.match_count));
        RecordProperty(key + "_jaccard", std::to_string(result.jaccard_estimate));
        RecordProperty(key + "_true_jaccard",
                       std::to_string(ExactJaccard(set_a, set_b)));

        if (prev_j >= 0.0) {
            EXPECT_GE(result.jaccard_estimate, prev_j - 0.05)
                << "Jaccard should generally increase with overlap="
                << overlap;
        }
        prev_j = result.jaccard_estimate;
    }
}
