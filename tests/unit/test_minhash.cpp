#include <gtest/gtest.h>
#include "core/minhash.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace piccard;

TEST(MinHasher, Determinism) {
    RecordProperty("input_k", 64);
    RecordProperty("input_seed", 123);
    RecordProperty("input_set", "{1, 2, 3, 4, 5}");

    MinHasher h1(64, UINT64_MAX, 123);
    MinHasher h2(64, UINT64_MAX, 123);

    std::vector<uint64_t> set = {1, 2, 3, 4, 5};
    auto sig1 = h1.ComputeSignature(set);
    auto sig2 = h2.ComputeSignature(set);

    RecordProperty("output_sig1_0", std::to_string(sig1[0]));
    RecordProperty("output_sig2_0", std::to_string(sig2[0]));
    RecordProperty("output_match", sig1 == sig2 ? "true" : "false");

    EXPECT_EQ(sig1, sig2);
}

TEST(MinHasher, IdenticalSets) {
    RecordProperty("input_k", 256);
    RecordProperty("input_set", "{10, 20, 30, 40, 50}");

    MinHasher hasher(256, UINT64_MAX, 42);

    std::vector<uint64_t> set = {10, 20, 30, 40, 50};
    auto sig_x = hasher.ComputeSignature(set);
    auto sig_y = hasher.ComputeSignature(set);

    double j = MinHasher::EstimateJaccard(sig_x, sig_y);
    RecordProperty("output_jaccard", std::to_string(j));

    EXPECT_DOUBLE_EQ(j, 1.0);
}

TEST(MinHasher, DisjointSets) {
    RecordProperty("input_k", 1000);
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{1000..1099}");

    MinHasher hasher(1000, UINT64_MAX, 42);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) {
        set_a.push_back(i);
        set_b.push_back(i + 1000);
    }

    auto sig_a = hasher.ComputeSignature(set_a);
    auto sig_b = hasher.ComputeSignature(set_b);

    double j = MinHasher::EstimateJaccard(sig_a, sig_b);
    RecordProperty("output_jaccard", std::to_string(j));
    RecordProperty("expected_jaccard", "0.0");

    EXPECT_LT(j, 0.05);
}

TEST(MinHasher, KnownOverlap) {
    RecordProperty("input_k", 2000);
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{50..149}");
    RecordProperty("expected_jaccard", "0.333333 (1/3)");

    MinHasher hasher(2000, UINT64_MAX, 42);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    auto sig_a = hasher.ComputeSignature(set_a);
    auto sig_b = hasher.ComputeSignature(set_b);

    double j = MinHasher::EstimateJaccard(sig_a, sig_b);
    RecordProperty("output_jaccard", std::to_string(j));
    RecordProperty("output_error", std::to_string(std::abs(j - 1.0 / 3.0)));

    // Expected: 1/3 ≈ 0.333. With k=2000, std dev ≈ 1/sqrt(k) ≈ 0.022
    // Allow 3 sigma (0.07) for statistical robustness
    EXPECT_NEAR(j, 1.0 / 3.0, 0.07);
}

TEST(MinHasher, SignatureLength) {
    uint32_t k = 128;
    RecordProperty("input_k", static_cast<int>(k));
    RecordProperty("input_set", "{1, 2, 3}");

    MinHasher hasher(k, UINT64_MAX, 42);

    std::vector<uint64_t> set = {1, 2, 3};
    auto sig = hasher.ComputeSignature(set);

    RecordProperty("output_sig_length", static_cast<int>(sig.size()));

    EXPECT_EQ(sig.size(), k);
}

TEST(MinHasher, EmptySetThrows) {
    RecordProperty("input_set", "{}");
    RecordProperty("expected_outcome", "throws std::invalid_argument");

    MinHasher hasher(64, UINT64_MAX, 42);
    std::vector<uint64_t> empty_set;

    EXPECT_THROW(hasher.ComputeSignature(empty_set), std::invalid_argument);
}

TEST(MinHasher, MismatchedSignaturesThrow) {
    RecordProperty("input_sig_a_length", 3);
    RecordProperty("input_sig_b_length", 2);
    RecordProperty("expected_outcome", "throws std::invalid_argument");

    std::vector<uint64_t> sig_a = {1, 2, 3};
    std::vector<uint64_t> sig_b = {1, 2};

    EXPECT_THROW(MinHasher::EstimateJaccard(sig_a, sig_b), std::invalid_argument);
}

TEST(MinHasher, ComputeElementHashesLength) {
    uint32_t k = 64;
    RecordProperty("input_k", static_cast<int>(k));
    RecordProperty("input_element", "12345");

    MinHasher hasher(k, UINT64_MAX, 42);
    auto hashes = hasher.ComputeElementHashes(12345);

    RecordProperty("output_hashes_length", static_cast<int>(hashes.size()));

    EXPECT_EQ(hashes.size(), k);
}

TEST(MinHasher, ComputeElementHashesDeterminism) {
    RecordProperty("input_k", 64);
    RecordProperty("input_seed", "42");
    RecordProperty("input_element", "999");

    MinHasher h1(64, UINT64_MAX, 42);
    MinHasher h2(64, UINT64_MAX, 42);

    auto hashes1 = h1.ComputeElementHashes(999);
    auto hashes2 = h2.ComputeElementHashes(999);

    RecordProperty("output_match", hashes1 == hashes2 ? "true" : "false");

    EXPECT_EQ(hashes1, hashes2);
}

TEST(MinHasher, ComputeElementHashesMatchesSingleElementSignature) {
    // For a single-element set {elem}, the signature should equal
    // the element's per-hash-function hashes (only one candidate per function)
    uint32_t k = 64;
    uint64_t elem = 42;
    RecordProperty("input_k", static_cast<int>(k));
    RecordProperty("input_element", "42");

    MinHasher hasher(k, UINT64_MAX, 123);

    auto hashes = hasher.ComputeElementHashes(elem);
    auto sig = hasher.ComputeSignature({elem});

    RecordProperty("output_hashes_eq_sig", hashes == sig ? "true" : "false");

    EXPECT_EQ(hashes, sig)
        << "Single-element signature should equal element hashes";
}

TEST(MinHasher, SubsetSimilarity) {
    // A ⊂ A∪B: J(A, A∪B) = |A| / |A∪B|
    // A = {0..99}, B = {50..149}, A∪B = {0..149}
    // J(A, A∪B) = 100/150 ≈ 0.667
    RecordProperty("input_k", 2000);
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_aub", "{0..149}");
    RecordProperty("expected_jaccard", "0.667 (100/150)");

    MinHasher hasher(2000, UINT64_MAX, 42);

    std::vector<uint64_t> set_a, set_aub;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 0; i < 150; i++) set_aub.push_back(i);

    auto sig_a = hasher.ComputeSignature(set_a);
    auto sig_aub = hasher.ComputeSignature(set_aub);
    double j = MinHasher::EstimateJaccard(sig_a, sig_aub);

    RecordProperty("output_jaccard", std::to_string(j));
    RecordProperty("output_error", std::to_string(std::abs(j - 100.0 / 150.0)));

    EXPECT_NEAR(j, 100.0 / 150.0, 0.05);
}

TEST(MinHasher, BoundedHashRange) {
    // With hash_range=1000, hashes should be in [0, 999]
    uint32_t k = 128;
    uint64_t hash_range = 1000;
    RecordProperty("input_k", static_cast<int>(k));
    RecordProperty("input_hash_range", "1000");
    RecordProperty("input_set", "{0..49}");

    MinHasher hasher(k, hash_range, 42);
    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 50; i++) set.push_back(i);

    auto sig = hasher.ComputeSignature(set);
    auto hashes = hasher.ComputeElementHashes(7);

    bool sig_in_range = true, hashes_in_range = true;
    for (auto v : sig) { if (v >= hash_range) sig_in_range = false; }
    for (auto v : hashes) { if (v >= hash_range) hashes_in_range = false; }

    RecordProperty("output_sig_in_range", sig_in_range ? "true" : "false");
    RecordProperty("output_hashes_in_range", hashes_in_range ? "true" : "false");

    EXPECT_TRUE(sig_in_range) << "All signature values must be < hash_range";
    EXPECT_TRUE(hashes_in_range) << "All element hashes must be < hash_range";
}

TEST(MinHasher, Symmetry) {
    // J(A,B) == J(B,A)
    RecordProperty("input_k", 500);
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{60..179}");

    MinHasher hasher(500, UINT64_MAX, 42);

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 60; i < 180; i++) set_b.push_back(i);

    auto sig_a = hasher.ComputeSignature(set_a);
    auto sig_b = hasher.ComputeSignature(set_b);

    double j_ab = MinHasher::EstimateJaccard(sig_a, sig_b);
    double j_ba = MinHasher::EstimateJaccard(sig_b, sig_a);

    RecordProperty("output_J(A,B)", std::to_string(j_ab));
    RecordProperty("output_J(B,A)", std::to_string(j_ba));

    EXPECT_DOUBLE_EQ(j_ab, j_ba);
}

TEST(MinHasher, Sha256RejectsZeroHashRange) {
    EXPECT_THROW((MinHasher{1, 0, 42}), std::invalid_argument);
}

TEST(MinHasher, Sha256KnownAnswerFullRanks) {
    struct KnownAnswer {
        const char* label;
        uint64_t seed;
        uint32_t coordinate;
        uint64_t element;
        uint64_t expected_rank;
    };

    // Independently generated with Python hashlib from manually serialized
    // domain || uint64_be(seed) || uint32_be(coordinate) || uint64_be(element).
    const KnownAnswer cases[] = {
        {"output_rank_seed0_i0_x0", 0, 0, 0, 0x75b80b391edda39cULL},
        {"output_rank_seed42_i7_xmax", 42, 7,
         std::numeric_limits<uint64_t>::max(),
         0x9d1f1cf4cf9c3cedULL},
        {"output_rank_seed20260729_i127_x2p61m1", 20260729, 127,
         (1ULL << 61) - 1,
         0x26d019c6e8894d5eULL},
    };

    for (const auto& test_case : cases) {
        SCOPED_TRACE("seed=" + std::to_string(test_case.seed) +
                     ", coordinate=" + std::to_string(test_case.coordinate) +
                     ", element=" + std::to_string(test_case.element));
        MinHasher hasher(test_case.coordinate + 1, UINT64_MAX, test_case.seed);
        const auto hashes = hasher.ComputeElementHashes(test_case.element);
        ASSERT_GT(hashes.size(), test_case.coordinate);
        const uint64_t actual_rank = hashes[test_case.coordinate];
        RecordProperty(test_case.label, std::to_string(actual_rank));
        EXPECT_EQ(actual_rank, test_case.expected_rank);
    }
}

TEST(MinHasher, Sha256SeparatesCoordinatesSeedsAndFullWidthElements) {
    const MinHasher coordinates(2, UINT64_MAX, 42);
    const auto coordinate_hashes = coordinates.ComputeElementHashes(7);
    ASSERT_EQ(coordinate_hashes.size(), 2u);
    EXPECT_NE(coordinate_hashes[0], coordinate_hashes[1]);

    const MinHasher seed_42(1, UINT64_MAX, 42);
    const MinHasher seed_43(1, UINT64_MAX, 43);
    EXPECT_NE(seed_42.ComputeElementHashes(7)[0],
              seed_43.ComputeElementHashes(7)[0]);

    EXPECT_NE(seed_42.ComputeElementHashes(7)[0],
              seed_42.ComputeElementHashes((1ULL << 63) + 7)[0]);
}

TEST(MinHasher, Sha256DistinguishesElementsSeparatedByTwoTo61MinusOne) {
    constexpr uint64_t kOffset = (1ULL << 61) - 1;
    constexpr uint64_t kElement = 1234567;
    const MinHasher hasher(16, UINT64_MAX, 42);

    EXPECT_NE(hasher.ComputeElementHashes(kElement),
              hasher.ComputeElementHashes(kElement + kOffset));
}

TEST(MinHasher, Sha256FiniteRangeEqualsFullRankModuloRange) {
    constexpr uint64_t kRange = 1009;
    const MinHasher full_rank(16, UINT64_MAX, 20260729);
    const MinHasher finite(16, kRange, 20260729);
    const auto full_hashes =
        full_rank.ComputeElementHashes(std::numeric_limits<uint64_t>::max());
    const auto finite_hashes =
        finite.ComputeElementHashes(std::numeric_limits<uint64_t>::max());

    ASSERT_EQ(full_hashes.size(), finite_hashes.size());
    for (size_t i = 0; i < full_hashes.size(); ++i) {
        SCOPED_TRACE("coordinate=" + std::to_string(i));
        EXPECT_EQ(finite_hashes[i], full_hashes[i] % kRange);
    }
}

TEST(MinHasher, Sha256PreservesEmptySetAndSignatureSizeContracts) {
    constexpr uint32_t k = 17;
    const MinHasher hasher(k, UINT64_MAX, 42);

    EXPECT_THROW(hasher.ComputeSignature({}), std::invalid_argument);
    EXPECT_EQ(hasher.ComputeSignature({1, 2, 3}).size(), k);
}

TEST(MinHasher, Sha256ReportsExactModelName) {
    EXPECT_EQ(std::string_view(MinHasher::ModelName()),
              "sha256-random-ranking-poc-v1");
}
