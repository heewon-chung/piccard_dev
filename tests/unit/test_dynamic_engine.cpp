#include <gtest/gtest.h>
#include "piccard/protocol/dynamic_piccard.h"

#include <cmath>

using namespace piccard;

class DynamicEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 64;
        params.m = 16;
        params.security = SecurityLevel::TOY;
        params.bottom_depth = 5;
        params.Validate();

        engine = std::make_unique<DynamicPiccard>(params);
        engine->KeyGen();
    }

    PiccardParams params;
    std::unique_ptr<DynamicPiccard> engine;
};

TEST_F(DynamicEngineTest, MatchesBasicProtocol) {
    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    auto basic_result = engine->Run(set_a, set_b);

    auto bottom_a = engine->InitSet(set_a);
    auto bottom_b = engine->InitSet(set_b);
    auto dynamic_result = engine->Run(*bottom_a, *bottom_b);

    EXPECT_EQ(basic_result.match_count, dynamic_result.match_count);
    EXPECT_DOUBLE_EQ(basic_result.jaccard_estimate,
                     dynamic_result.jaccard_estimate);
}

TEST_F(DynamicEngineTest, IdenticalSets) {
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 50; i++) set.push_back(i);

    auto bottom_a = engine->InitSet(set);
    auto bottom_b = engine->InitSet(set);
    auto result = engine->Run(*bottom_a, *bottom_b);

    EXPECT_NEAR(result.jaccard_estimate, 1.0, 0.01);
}

TEST_F(DynamicEngineTest, InsertIncreasesOverlap) {
    std::vector<uint64_t> set_a = {1, 2, 3, 4, 5};
    std::vector<uint64_t> set_b = {6, 7, 8, 9, 10};

    auto bottom_a = engine->InitSet(set_a);
    auto bottom_b = engine->InitSet(set_b);
    auto result_before = engine->Run(*bottom_a, *bottom_b);

    // Insert shared elements into both sets
    for (uint64_t i = 100; i < 200; i++) {
        bottom_a->Insert(i);
        bottom_b->Insert(i);
    }
    auto result_after = engine->Run(*bottom_a, *bottom_b);

    // After adding many shared elements, similarity should increase
    EXPECT_GT(result_after.jaccard_estimate, result_before.jaccard_estimate);
}

TEST_F(DynamicEngineTest, DeleteReducesOverlap) {
    // Start with identical sets
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 200; i++) set.push_back(i);

    auto bottom_a = engine->InitSet(set);
    auto bottom_b = engine->InitSet(set);

    auto result_before = engine->Run(*bottom_a, *bottom_b);
    EXPECT_NEAR(result_before.jaccard_estimate, 1.0, 0.01);

    // Delete elements from set_a and insert different ones
    for (uint64_t i = 0; i < 50; i++) {
        bottom_a->Delete(i);
        bottom_a->Insert(i + 10000);
    }
    auto result_after = engine->Run(*bottom_a, *bottom_b);

    // Similarity should decrease
    EXPECT_LT(result_after.jaccard_estimate, result_before.jaccard_estimate);
}

TEST_F(DynamicEngineTest, Symmetry) {
    // J_dynamic(A,B) == J_dynamic(B,A)
    RecordProperty("input_set_a", "{0..79}");
    RecordProperty("input_set_b", "{30..119}");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 80; i++) set_a.push_back(i);
    for (uint64_t i = 30; i < 120; i++) set_b.push_back(i);

    auto bottom_a = engine->InitSet(set_a);
    auto bottom_b = engine->InitSet(set_b);

    auto result_ab = engine->Run(*bottom_a, *bottom_b);
    auto result_ba = engine->Run(*bottom_b, *bottom_a);

    RecordProperty("output_J(A,B)_match", std::to_string(result_ab.match_count));
    RecordProperty("output_J(A,B)_estimate", std::to_string(result_ab.jaccard_estimate));
    RecordProperty("output_J(B,A)_match", std::to_string(result_ba.match_count));
    RecordProperty("output_J(B,A)_estimate", std::to_string(result_ba.jaccard_estimate));

    EXPECT_EQ(result_ab.match_count, result_ba.match_count);
    EXPECT_DOUBLE_EQ(result_ab.jaccard_estimate, result_ba.jaccard_estimate);
}

TEST_F(DynamicEngineTest, InitPlusInsertMatchesFullInit) {
    // Creating bottom structure from {1..50} then inserting {51..100}
    // should match creating from {1..100}
    RecordProperty("input_init", "{1..50}");
    RecordProperty("input_inserts", "{51..100}");
    RecordProperty("input_full", "{1..100}");

    std::vector<uint64_t> init_set, full_set;
    for (uint64_t i = 1; i <= 50; i++) init_set.push_back(i);
    for (uint64_t i = 1; i <= 100; i++) full_set.push_back(i);

    auto bottom_inc = engine->InitSet(init_set);
    for (uint64_t i = 51; i <= 100; i++) bottom_inc->Insert(i);
    auto bottom_full = engine->InitSet(full_set);

    // Compare signatures
    auto sig_inc = bottom_inc->GetSignature();
    auto sig_full = bottom_full->GetSignature();

    uint32_t matching = 0;
    for (size_t i = 0; i < sig_inc.size(); i++) {
        if (sig_inc[i] == sig_full[i]) matching++;
    }

    RecordProperty("output_matching_sigs", static_cast<int>(matching));
    RecordProperty("output_total", static_cast<int>(sig_inc.size()));

    EXPECT_EQ(matching, sig_inc.size())
        << "Init+Insert should match full Init";
}

TEST_F(DynamicEngineTest, ManyMutationsStillProducesValidResult) {
    // Stress test: many inserts and deletes, result should still be in [0, 1]
    RecordProperty("input_initial", "{0..99}");
    RecordProperty("input_mutations", "insert 100..299, delete 0..99");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 0; i < 100; i++) set_b.push_back(i);

    auto bottom_a = engine->InitSet(set_a);
    auto bottom_b = engine->InitSet(set_b);

    // Mutate bottom_a: replace all elements with new ones
    for (uint64_t i = 0; i < 100; i++) bottom_a->Delete(i);
    for (uint64_t i = 100; i < 300; i++) bottom_a->Insert(i);

    auto result = engine->Run(*bottom_a, *bottom_b);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_GE(result.jaccard_estimate, 0.0);
    EXPECT_LE(result.jaccard_estimate, 1.0);
    // After replacing all elements in A, similarity with B should be low
    EXPECT_LT(result.jaccard_estimate, 0.3)
        << "Replacing all elements should yield low similarity";
}
