#include <gtest/gtest.h>
#include "core/minhash.h"

#include <cmath>
#include <string>

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

// ── Regression: unreduced elements (§5 of the hash-seed-crs plan) ────────────
// h_i(x) = ((a_i * x + b_i) mod P) mod R is defined over Z_P, so hashing x and
// hashing (x mod P) must agree. The original MulModMersenne computed
// hi = (a_i * x) >> 61 without reducing x first; for x >= 2^61 and a_i close to
// P, hi approaches 2^64 and hi + lo wrapped around, yielding a wrong hash.

TEST(MinHasher, ElementHashesInvariantUnderModMersennePrime) {
    constexpr uint64_t kP = (1ULL << 61) - 1;
    MinHasher hasher(128, UINT64_MAX, 42);

    // UINT64_MAX - 8 .. UINT64_MAX - 13 are witnesses: with seed 42 and k=128
    // they drive (a_10 * elem) >> 61 close enough to 2^64 that the old
    // hi + lo addition wrapped, shifting the result by 2^64 mod P = 8.
    const std::vector<uint64_t> large_elems = {
        UINT64_MAX - 8,
        UINT64_MAX - 9,
        UINT64_MAX - 10,
        UINT64_MAX - 11,
        UINT64_MAX - 12,
        UINT64_MAX - 13,
        kP,
        kP + 1,
        1ULL << 61,
        (1ULL << 61) + 12345,
        1ULL << 62,
        1ULL << 63,
        UINT64_MAX - 1,
        UINT64_MAX,
    };

    for (uint64_t elem : large_elems) {
        SCOPED_TRACE("elem=" + std::to_string(elem));
        EXPECT_EQ(hasher.ComputeElementHashes(elem),
                  hasher.ComputeElementHashes(elem % kP));
    }
}

TEST(MinHasher, SignatureInvariantUnderModMersennePrime) {
    constexpr uint64_t kP = (1ULL << 61) - 1;
    MinHasher hasher(64, UINT64_MAX, 42);

    const std::vector<uint64_t> big = {UINT64_MAX, 1ULL << 63,
                                       (1ULL << 61) + 7};
    std::vector<uint64_t> reduced;
    reduced.reserve(big.size());
    for (uint64_t elem : big) reduced.push_back(elem % kP);

    EXPECT_EQ(hasher.ComputeSignature(big), hasher.ComputeSignature(reduced));
}
