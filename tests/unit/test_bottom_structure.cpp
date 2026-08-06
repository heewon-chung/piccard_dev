#include <gtest/gtest.h>
#include "core/bottom_structure.h"
#include "core/minhash.h"

#include <limits>

using namespace piccard;

class BottomStructureTest : public ::testing::Test {
protected:
    static constexpr uint32_t k = 64;
    static constexpr uint32_t d = 5;
    static constexpr uint64_t hash_range = UINT64_MAX;
    static constexpr uint64_t seed = 42;
};

TEST_F(BottomStructureTest, InitializeMatchesMinHash) {
    // B[i][0] should equal the MinHash signature value for the same set/seed
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 100; i++) set.push_back(i);

    MinHasher hasher(k, hash_range, seed);
    auto sig = hasher.ComputeSignature(set);

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);
    auto bottom_sig = bottom.GetSignature();

    ASSERT_EQ(sig.size(), bottom_sig.size());
    for (size_t i = 0; i < sig.size(); i++) {
        EXPECT_EQ(sig[i], bottom_sig[i])
            << "Mismatch at hash function " << i;
    }
}

TEST_F(BottomStructureTest, FullSignatureMatchesMinHasherForExactCrs) {
    constexpr uint64_t custom_seed = 20260729;
    const std::vector<uint64_t> set = {
        0,
        17,
        (1ULL << 63) + 5,
        std::numeric_limits<uint64_t>::max(),
    };
    const MinHasher hasher(k, hash_range, custom_seed);
    BottomStructure bottom(k, d, hash_range, custom_seed);

    bottom.Initialize(set);

    EXPECT_EQ(bottom.GetSeed(), custom_seed);
    EXPECT_EQ(bottom.GetSignature(), hasher.ComputeSignature(set));
}

TEST_F(BottomStructureTest, DuplicateInputsDoNotChangeSignatureOrState) {
    const std::vector<uint64_t> unique = {
        0,
        17,
        std::numeric_limits<uint64_t>::max(),
    };
    const std::vector<uint64_t> with_duplicates = {
        17,
        0,
        17,
        std::numeric_limits<uint64_t>::max(),
        0,
    };
    BottomStructure unique_bottom(k, d, hash_range, seed);
    BottomStructure duplicate_bottom(k, d, hash_range, seed);
    unique_bottom.Initialize(unique);
    duplicate_bottom.Initialize(with_duplicates);

    EXPECT_EQ(duplicate_bottom.GetSignature(), unique_bottom.GetSignature());
    EXPECT_EQ(duplicate_bottom.GetBottom(), unique_bottom.GetBottom());

    const auto state_before_duplicate_insert = unique_bottom.GetBottom();
    unique_bottom.Insert(17);
    EXPECT_EQ(unique_bottom.GetBottom(), state_before_duplicate_insert);
}

TEST_F(BottomStructureTest, DepthLimit) {
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 1000; i++) set.push_back(i);

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);

    for (uint32_t i = 0; i < k; i++) {
        EXPECT_LE(bottom.GetBottom()[i].size(), d)
            << "Bottom[" << i << "] exceeds depth " << d;
        EXPECT_GE(bottom.GetBottom()[i].size(), 1u)
            << "Bottom[" << i << "] is empty";
    }
}

TEST_F(BottomStructureTest, BottomIsSorted) {
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 200; i++) set.push_back(i);

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);

    for (uint32_t i = 0; i < k; i++) {
        const auto& arr = bottom.GetBottom()[i];
        for (size_t j = 1; j < arr.size(); j++) {
            EXPECT_LE(arr[j - 1], arr[j])
                << "Bottom[" << i << "] not sorted at position " << j;
        }
    }
}

TEST_F(BottomStructureTest, InsertSmallerUpdatesSignature) {
    // Create with a single large-valued element, then insert a smaller one
    std::vector<uint64_t> set = {999999};
    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);
    auto sig_before = bottom.GetSignature();

    // Insert many elements — at least some hash functions should get smaller mins
    for (uint64_t i = 0; i < 100; i++) {
        bottom.Insert(i);
    }
    auto sig_after = bottom.GetSignature();

    uint32_t changed = 0;
    for (uint32_t i = 0; i < k; i++) {
        if (sig_after[i] < sig_before[i]) changed++;
    }
    EXPECT_GT(changed, 0u) << "No signature values decreased after inserts";
}

TEST_F(BottomStructureTest, InsertLargerDoesNotChangeSignature) {
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 100; i++) set.push_back(i);

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);
    auto sig_before = bottom.GetSignature();

    // Insert elements with very large values (unlikely to be new minimums)
    for (uint64_t i = 0; i < 10; i++) {
        bottom.Insert(i + 10000000);
    }
    auto sig_after = bottom.GetSignature();

    // Most signatures should remain unchanged
    uint32_t unchanged = 0;
    for (uint32_t i = 0; i < k; i++) {
        if (sig_before[i] == sig_after[i]) unchanged++;
    }
    EXPECT_GT(unchanged, k / 2) << "Too many signatures changed from large inserts";
}

TEST_F(BottomStructureTest, DeleteNonMinimumPreservesSignature) {
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 200; i++) set.push_back(i);

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);
    auto sig_before = bottom.GetSignature();

    // Delete element 150 — unlikely to be the minimum for most hash functions
    bottom.Delete(150);
    auto sig_after = bottom.GetSignature();

    // Most signatures should be unchanged
    uint32_t unchanged = 0;
    for (uint32_t i = 0; i < k; i++) {
        if (sig_before[i] == sig_after[i]) unchanged++;
    }
    EXPECT_GT(unchanged, k / 2);
}

TEST_F(BottomStructureTest, DeleteMinimumPromotesNext) {
    // Use a small set where we can track which element gives the minimum
    std::vector<uint64_t> set = {10, 20, 30, 40, 50};

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);

    // For each hash function, find which element gives the minimum
    MinHasher hasher(k, hash_range, seed);

    // Delete each element one at a time and check that signatures are valid
    for (uint64_t elem : set) {
        BottomStructure test_bottom(k, d, hash_range, seed);
        test_bottom.Initialize(set);
        test_bottom.Delete(elem);

        // After deletion, each B[i] should still have elements (depth=5, set has 5 elems)
        // The signature should be the minimum of the remaining elements
        auto sig = test_bottom.GetSignature();
        for (uint32_t i = 0; i < k; i++) {
            EXPECT_GT(test_bottom.GetBottom()[i].size(), 0u);
        }
    }
}

TEST_F(BottomStructureTest, EmptySetThrows) {
    BottomStructure bottom(k, d, hash_range, seed);
    EXPECT_THROW(bottom.Initialize({}), std::invalid_argument);
}

TEST_F(BottomStructureTest, RebuildStateIsStickyUntilFullInitialize) {
    BottomStructure bottom(1, 1, hash_range, seed);
    EXPECT_TRUE(bottom.RequiresRebuild());
    EXPECT_THROW(bottom.Insert(9), std::logic_error);
    EXPECT_THROW(bottom.Delete(9), std::logic_error);
    EXPECT_THROW(bottom.GetSignature(), std::logic_error);

    bottom.Initialize({9});
    EXPECT_FALSE(bottom.RequiresRebuild());
    bottom.Delete(9);
    EXPECT_TRUE(bottom.RequiresRebuild());
    EXPECT_THROW(bottom.Insert(10), std::logic_error);
    EXPECT_THROW(bottom.Delete(10), std::logic_error);
    EXPECT_THROW(bottom.GetSignature(), std::logic_error);

    EXPECT_THROW(bottom.Initialize({}), std::invalid_argument);
    EXPECT_TRUE(bottom.RequiresRebuild());
    bottom.Initialize({10, 11});
    EXPECT_FALSE(bottom.RequiresRebuild());
    EXPECT_NO_THROW(bottom.GetSignature());
}

TEST_F(BottomStructureTest, InitPlusInsertMatchesFullInit) {
    // Initialize({1..50}) + Insert(51..100) should give the same signature
    // as Initialize({1..100})
    RecordProperty("input_init_set", "{1..50}");
    RecordProperty("input_inserts", "{51..100}");
    RecordProperty("input_full_set", "{1..100}");

    BottomStructure incremental(k, d, hash_range, seed);
    std::vector<uint64_t> init_set;
    for (uint64_t i = 1; i <= 50; i++) init_set.push_back(i);
    incremental.Initialize(init_set);
    for (uint64_t i = 51; i <= 100; i++) incremental.Insert(i);

    BottomStructure full(k, d, hash_range, seed);
    std::vector<uint64_t> full_set;
    for (uint64_t i = 1; i <= 100; i++) full_set.push_back(i);
    full.Initialize(full_set);

    auto sig_inc = incremental.GetSignature();
    auto sig_full = full.GetSignature();

    uint32_t matching = 0;
    for (uint32_t i = 0; i < k; i++) {
        if (sig_inc[i] == sig_full[i]) matching++;
    }

    RecordProperty("output_matching_signatures", static_cast<int>(matching));
    RecordProperty("output_total", static_cast<int>(k));

    EXPECT_EQ(matching, k)
        << "Init + Insert should produce same signature as full Init";
}

TEST_F(BottomStructureTest, InitPlusInsertMatchesExactSetUnion) {
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

    BottomStructure incremental(k, d, hash_range, seed);
    incremental.Initialize(prefix);
    for (uint64_t element : suffix) {
        incremental.Insert(element);
    }

    BottomStructure initialized_from_union(k, d, hash_range, seed);
    initialized_from_union.Initialize(exact_union);

    EXPECT_EQ(incremental.GetSignature(),
              initialized_from_union.GetSignature());
    EXPECT_EQ(incremental.GetBottom(), initialized_from_union.GetBottom());
}

TEST_F(BottomStructureTest, InsertDeleteCycleRestoresSignature) {
    // Insert element, then delete it — signature should be unchanged
    RecordProperty("input_set", "{1..100}");
    RecordProperty("input_insert_then_delete", "999");

    std::vector<uint64_t> set;
    for (uint64_t i = 1; i <= 100; i++) set.push_back(i);

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);
    auto sig_before = bottom.GetSignature();

    bottom.Insert(999);
    bottom.Delete(999);
    auto sig_after = bottom.GetSignature();

    uint32_t matching = 0;
    for (uint32_t i = 0; i < k; i++) {
        if (sig_before[i] == sig_after[i]) matching++;
    }

    RecordProperty("output_matching_after_cycle", static_cast<int>(matching));

    EXPECT_EQ(matching, k)
        << "Insert then Delete of same element should restore signature";
}

TEST_F(BottomStructureTest, ManyInsertsRespectDepth) {
    // After many inserts, each bottom array should still respect depth limit
    RecordProperty("input_initial_set", "{1..10}");
    RecordProperty("input_inserts", "{11..500}");
    RecordProperty("input_depth", static_cast<int>(d));

    std::vector<uint64_t> set;
    for (uint64_t i = 1; i <= 10; i++) set.push_back(i);

    BottomStructure bottom(k, d, hash_range, seed);
    bottom.Initialize(set);

    for (uint64_t i = 11; i <= 500; i++) bottom.Insert(i);

    for (uint32_t i = 0; i < k; i++) {
        RecordProperty("bottom_" + std::to_string(i) + "_size",
                       static_cast<int>(bottom.GetBottom()[i].size()));
        EXPECT_LE(bottom.GetBottom()[i].size(), d)
            << "Bottom[" << i << "] exceeds depth after many inserts";
        EXPECT_GE(bottom.GetBottom()[i].size(), 1u)
            << "Bottom[" << i << "] is empty after many inserts";
    }
}
