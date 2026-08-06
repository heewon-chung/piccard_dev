#include <gtest/gtest.h>
#include "protocol/dynamic_piccard.h"

#include <limits>
#include <stdexcept>

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

TEST_F(DynamicEngineTest, ExhaustedStructureRejectsEncryptionUntilReinitialized) {
    auto bottom = engine->InitSet({7});
    ASSERT_FALSE(bottom->RequiresRebuild());
    bottom->Delete(7);
    ASSERT_TRUE(bottom->RequiresRebuild());
    EXPECT_THROW(engine->Encrypt(*bottom), std::logic_error);
    EXPECT_THROW(bottom->Insert(8), std::logic_error);

    bottom->Initialize({8, 9});
    EXPECT_FALSE(bottom->RequiresRebuild());
    EXPECT_NO_THROW(engine->Encrypt(*bottom));
}

// ── Public CRS propagation (§"실행 중 재추출") ────────────────────────────────

// Same equivalence as MatchesBasicProtocol, but under a seed that is not the
// default 42, so a path that silently kept the old default would show up here.
TEST_F(DynamicEngineTest, MatchesBasicProtocolUnderCustomHashSeed) {
    PiccardParams custom = params;
    custom.hash_seed = 20260725ULL;
    custom.Validate();

    DynamicPiccard custom_engine(custom);
    custom_engine.KeyGen();
    ASSERT_EQ(custom_engine.GetParams().hash_seed, 20260725ULL);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    auto basic_result = custom_engine.Run(set_a, set_b);

    auto bottom_a = custom_engine.InitSet(set_a);
    auto bottom_b = custom_engine.InitSet(set_b);
    EXPECT_EQ(bottom_a->GetSeed(), 20260725ULL);
    EXPECT_EQ(bottom_b->GetSeed(), 20260725ULL);

    auto dynamic_result = custom_engine.Run(*bottom_a, *bottom_b);

    EXPECT_EQ(basic_result.match_count, dynamic_result.match_count);
    EXPECT_DOUBLE_EQ(basic_result.jaccard_estimate,
                     dynamic_result.jaccard_estimate);
}

TEST_F(DynamicEngineTest, CustomSeedStaticAndDynamicSignaturesMatchExactly) {
    constexpr uint64_t custom_seed = 20260729;
    PiccardParams custom = params;
    custom.hash_seed = custom_seed;
    custom.Validate();
    DynamicPiccard custom_engine(custom);
    custom_engine.KeyGen();
    const std::vector<uint64_t> set = {
        0,
        17,
        (1ULL << 63) + 5,
        std::numeric_limits<uint64_t>::max(),
        17,
    };
    const MinHasher reference(custom.k, custom.hash_range, custom_seed);

    const auto static_signature = custom_engine.ComputeSignature(set);
    const auto bottom = custom_engine.InitSet(set);

    EXPECT_EQ(custom_engine.GetParams().hash_seed, custom_seed);
    EXPECT_EQ(bottom->GetSeed(), custom_seed);
    EXPECT_EQ(static_signature, reference.ComputeSignature(set));
    EXPECT_EQ(bottom->GetSignature(), static_signature);
}

TEST_F(DynamicEngineTest, InitPlusInsertMatchesExactSetUnionState) {
    const std::vector<uint64_t> prefix = {
        0,
        17,
        std::numeric_limits<uint64_t>::max(),
    };
    const std::vector<uint64_t> suffix = {
        99,
        17,
        std::numeric_limits<uint64_t>::max(),
    };
    const std::vector<uint64_t> exact_union = {
        0,
        17,
        99,
        std::numeric_limits<uint64_t>::max(),
    };

    auto incremental = engine->InitSet(prefix);
    for (uint64_t element : suffix) {
        engine->Insert(*incremental, element);
    }
    const auto initialized_from_union = engine->InitSet(exact_union);

    EXPECT_EQ(incremental->GetSignature(),
              initialized_from_union->GetSignature());
    EXPECT_EQ(incremental->GetBottom(),
              initialized_from_union->GetBottom());
}

// A structure built under the previous CRS must be refused, not silently
// compared against one built under the new CRS.
TEST_F(DynamicEngineTest, RejectsBottomStructureFromPreviousCrs) {
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 60; i++) set.push_back(i);

    auto stale = engine->InitSet(set);
    ASSERT_EQ(stale->GetSeed(), params.hash_seed);

    engine->SetHashSeed(params.hash_seed + 1);
    auto fresh = engine->InitSet(set);
    ASSERT_NE(stale->GetSeed(), fresh->GetSeed());

    EXPECT_THROW(engine->Encrypt(*stale), std::invalid_argument);
    EXPECT_THROW(engine->Run(*stale, *fresh), std::invalid_argument);
    EXPECT_THROW(engine->Run(*fresh, *stale), std::invalid_argument);
    EXPECT_NO_THROW(engine->Run(*fresh, *fresh));
}

// Reseeding must change the hash family but leave the BFV context and keys
// alone -- that is what makes per-trial resampling affordable.
TEST_F(DynamicEngineTest, SetHashSeedChangesFamilyButKeepsCryptoContext) {
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 60; i++) set.push_back(i);

    const auto sig_before = engine->ComputeSignature(set);
    const uint32_t ring_before = engine->GetParams().ring_dim;
    const size_t slots_before = engine->GetBFVContext().GetSlotCount();

    engine->SetHashSeed(999983ULL);

    EXPECT_EQ(engine->GetParams().hash_seed, 999983ULL);
    EXPECT_NE(engine->ComputeSignature(set), sig_before);
    EXPECT_EQ(engine->GetParams().ring_dim, ring_before);
    EXPECT_EQ(engine->GetBFVContext().GetSlotCount(), slots_before);
}

// After reseeding, freshly built structures agree with the static path again.
TEST_F(DynamicEngineTest, StructuresBuiltAfterReseedMatchBasicProtocol) {
    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    engine->SetHashSeed(31337ULL);

    auto basic_result = engine->Run(set_a, set_b);
    auto bottom_a = engine->InitSet(set_a);
    auto bottom_b = engine->InitSet(set_b);
    auto dynamic_result = engine->Run(*bottom_a, *bottom_b);

    EXPECT_EQ(bottom_a->GetSeed(), 31337ULL);
    EXPECT_EQ(basic_result.match_count, dynamic_result.match_count);
    EXPECT_DOUBLE_EQ(basic_result.jaccard_estimate,
                     dynamic_result.jaccard_estimate);
}
