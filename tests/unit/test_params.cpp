#include <gtest/gtest.h>
#include "util/params.h"

#include <string>

using namespace piccard;

TEST(NextPowerOf2, EdgeCases) {
    struct Case { uint32_t input; uint32_t expected; };
    Case cases[] = {
        {0, 1}, {1, 1}, {2, 2}, {3, 4}, {4, 4}, {5, 8},
        {1023, 1024}, {1024, 1024}, {1025, 2048}, {4096, 4096}
    };
    for (auto& c : cases) {
        uint32_t result = NextPowerOf2(c.input);
        RecordProperty("input_" + std::to_string(c.input),
                       static_cast<int>(result));
        EXPECT_EQ(result, c.expected);
    }
}

TEST(IsPrime, Basic) {
    struct Case { uint64_t input; bool expected; };
    Case cases[] = {
        {0, false}, {1, false}, {2, true}, {3, true}, {4, false},
        {5, true}, {97, true}, {100, false}, {7919, true}
    };
    for (auto& c : cases) {
        bool result = IsPrime(c.input);
        RecordProperty("IsPrime_" + std::to_string(c.input),
                       result ? "true" : "false");
        EXPECT_EQ(result, c.expected);
    }
}

TEST(FindPlaintextModulus, CongruenceAndPrimality) {
    uint32_t N = 4096;
    uint32_t two_n = 2 * N;
    uint32_t min_val = 128;
    RecordProperty("input_N", static_cast<int>(N));
    RecordProperty("input_min_val", static_cast<int>(min_val));

    uint64_t p = FindPlaintextModulus(min_val, two_n);
    RecordProperty("output_p", std::to_string(p));
    RecordProperty("output_p_mod_2N", std::to_string(p % two_n));
    RecordProperty("output_is_prime", IsPrime(p) ? "true" : "false");

    EXPECT_GT(p, min_val);
    EXPECT_EQ(p % two_n, 1u);
    EXPECT_TRUE(IsPrime(p));
}

TEST(FindPlaintextModulus, SmallValues) {
    RecordProperty("input_min_val", 10);
    RecordProperty("input_modulus", 16);

    uint64_t p = FindPlaintextModulus(10, 16);
    RecordProperty("output_p", std::to_string(p));
    RecordProperty("output_p_mod_16", std::to_string(p % 16));

    EXPECT_GT(p, 10u);
    EXPECT_EQ(p % 16, 1u);
    EXPECT_TRUE(IsPrime(p));
}

TEST(PiccardParams, DefaultValidation) {
    PiccardParams params;
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_security", "STD128");

    params.Validate();

    RecordProperty("output_feature_dim", static_cast<int>(params.feature_dim));
    RecordProperty("output_ring_dim", static_cast<int>(params.ring_dim));
    RecordProperty("output_plaintext_mod", std::to_string(params.plaintext_mod));
    RecordProperty("output_mult_depth", static_cast<int>(params.mult_depth));

    EXPECT_EQ(params.feature_dim, 128u * 64u);
    EXPECT_GE(params.ring_dim, params.feature_dim);
    EXPECT_EQ(params.ring_dim & (params.ring_dim - 1), 0u);
    EXPECT_GE(params.ring_dim, MinRingDimForSecurity(params.security));
    EXPECT_GT(params.plaintext_mod, params.k);
    EXPECT_EQ(params.plaintext_mod % (2 * params.ring_dim), 1u);
    EXPECT_TRUE(IsPrime(params.plaintext_mod));
    // The one-hot circuit needs one multiplication. mult_depth is provisioned
    // at or above that to leave room for noise flooding (R2-W6), so the
    // circuit's own requirement is natural_mult_depth.
    EXPECT_EQ(params.natural_mult_depth, 1u);
    EXPECT_GE(params.mult_depth, params.natural_mult_depth);
}

TEST(PiccardParams, ToySecuritySmallRing) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    RecordProperty("input_k", 16);
    RecordProperty("input_m", 8);
    RecordProperty("input_security", "TOY");

    params.Validate();

    RecordProperty("output_feature_dim", static_cast<int>(params.feature_dim));
    RecordProperty("output_ring_dim", static_cast<int>(params.ring_dim));
    RecordProperty("output_plaintext_mod", std::to_string(params.plaintext_mod));

    EXPECT_EQ(params.feature_dim, 128u);
    EXPECT_GE(params.ring_dim, 1024u);
}

TEST(PiccardParams, LargeKM) {
    PiccardParams params;
    params.k = 256;
    params.m = 64;
    params.security = SecurityLevel::STD128;
    RecordProperty("input_k", 256);
    RecordProperty("input_m", 64);
    RecordProperty("input_security", "STD128");

    params.Validate();

    RecordProperty("output_feature_dim", static_cast<int>(params.feature_dim));
    RecordProperty("output_ring_dim", static_cast<int>(params.ring_dim));
    RecordProperty("output_plaintext_mod", std::to_string(params.plaintext_mod));

    EXPECT_EQ(params.feature_dim, 256u * 64u);
    EXPECT_GE(params.ring_dim, 16384u);
    EXPECT_GT(params.plaintext_mod, 256u);
}

TEST(PiccardParams, InvalidK) {
    PiccardParams params;
    params.k = 0;
    RecordProperty("input_k", 0);
    RecordProperty("expected_outcome", "throws std::invalid_argument");
    EXPECT_THROW(params.Validate(), std::invalid_argument);
}

TEST(PiccardParams, InvalidM) {
    PiccardParams params;
    params.m = 1;
    RecordProperty("input_m", 1);
    RecordProperty("expected_outcome", "throws std::invalid_argument");
    EXPECT_THROW(params.Validate(), std::invalid_argument);
}

TEST(PiccardParams, ThresholdMultDepth) {
    // Verify mult_depth for threshold mode matches what EvalPolyBFV requires.
    // Formula: 1 (initial ct*ct) + baby_depth(s) + (num_chunks - 1)
    // where s = smallest integer with s*s >= k+1
    struct Case {
        uint32_t k;
        uint32_t expected_depth;
    };
    //  k=4:  s=3, baby=2, chunks=2, giant=1  → 1+2+1=4
    //  k=8:  s=3, baby=2, chunks=3, giant=2  → 1+2+2=5
    //  k=16: s=5, baby=3, chunks=4, giant=3  → 1+3+3=7
    //  k=32: s=6, baby=3, chunks=6, giant=5  → 1+3+5=9
    //  k=64: s=9, baby=4, chunks=8, giant=7  → 1+4+7=12
    Case cases[] = {
        {4, 4}, {8, 5}, {16, 7}, {32, 9}, {64, 12}
    };

    for (auto& c : cases) {
        PiccardParams params;
        params.k = c.k;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.threshold_mode = true;
        params.threshold_tau = c.k / 2;
        params.Validate();

        RecordProperty("k_" + std::to_string(c.k) + "_mult_depth",
                       static_cast<int>(params.mult_depth));
        // Assert on natural_mult_depth: this is the number that must keep
        // matching EvalPolyBFV's step-size calculation. mult_depth may sit
        // above it to carry the flooding term.
        EXPECT_EQ(params.natural_mult_depth, c.expected_depth)
            << "k=" << c.k << ": expected natural depth=" << c.expected_depth
            << ", got " << params.natural_mult_depth;
        EXPECT_GE(params.mult_depth, params.natural_mult_depth) << "k=" << c.k;
    }
}

TEST(PiccardParams, NonThresholdMultDepthIsOne) {
    // Without threshold_mode, the circuit needs exactly one multiplication
    RecordProperty("input_threshold_mode", "false");
    RecordProperty("expected_natural_mult_depth", "1");

    for (uint32_t k : {4u, 16u, 64u, 128u}) {
        PiccardParams params;
        params.k = k;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.Validate();

        RecordProperty("k_" + std::to_string(k) + "_natural_mult_depth",
                       static_cast<int>(params.natural_mult_depth));
        EXPECT_EQ(params.natural_mult_depth, 1u) << "k=" << k;
        EXPECT_GE(params.mult_depth, params.natural_mult_depth) << "k=" << k;
    }
}

TEST(PiccardParams, ThresholdPlaintextModStillValid) {
    // Threshold mode increases mult_depth, which may affect ring_dim.
    // Plaintext modulus must still satisfy: prime, > k, ≡ 1 mod 2N.
    RecordProperty("input_threshold_mode", "true");

    for (uint32_t k : {4u, 16u, 64u}) {
        PiccardParams params;
        params.k = k;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.threshold_mode = true;
        params.threshold_tau = k / 2;
        params.Validate();

        uint32_t two_n = 2 * params.ring_dim;
        RecordProperty("k_" + std::to_string(k) + "_plaintext_mod",
                       std::to_string(params.plaintext_mod));
        RecordProperty("k_" + std::to_string(k) + "_ring_dim",
                       static_cast<int>(params.ring_dim));

        EXPECT_GT(params.plaintext_mod, k)
            << "k=" << k << ": p must be > k";
        EXPECT_EQ(params.plaintext_mod % two_n, 1u)
            << "k=" << k << ": p must be ≡ 1 mod 2N";
        EXPECT_TRUE(IsPrime(params.plaintext_mod))
            << "k=" << k << ": p must be prime";
    }
}

TEST(PiccardParams, FeatureDimAndRingDimConsistency) {
    // For various k*m combinations, ring_dim >= feature_dim and is a power of 2
    struct Case {
        uint32_t k; uint32_t m; uint32_t expected_feature_dim;
    };
    Case cases[] = {
        {16, 8, 128}, {32, 16, 512}, {128, 32, 4096}, {64, 64, 4096}
    };

    for (auto& c : cases) {
        PiccardParams params;
        params.k = c.k;
        params.m = c.m;
        params.security = SecurityLevel::TOY;
        params.Validate();

        RecordProperty("k" + std::to_string(c.k) + "_m" + std::to_string(c.m) +
                       "_feature_dim", static_cast<int>(params.feature_dim));
        RecordProperty("k" + std::to_string(c.k) + "_m" + std::to_string(c.m) +
                       "_ring_dim", static_cast<int>(params.ring_dim));

        EXPECT_EQ(params.feature_dim, c.expected_feature_dim);
        EXPECT_GE(params.ring_dim, params.feature_dim);
        EXPECT_EQ(params.ring_dim & (params.ring_dim - 1), 0u)
            << "ring_dim must be power of 2";
    }
}

// ── Public CRS seed (§"CRS 표현") ────────────────────────────────────────────
// hash_seed is a public parameter, not a derived one: Validate()/ValidateSqrt()
// must preserve whatever the caller set and must not range-check it, since
// every uint64_t is a valid seed.

TEST(PiccardParams, HashSeedDefaultsTo42) {
    PiccardParams params;
    EXPECT_EQ(params.hash_seed, 42ULL);
}

TEST(PiccardParams, ValidatePreservesDefaultHashSeed) {
    PiccardParams params;
    params.Validate();
    EXPECT_EQ(params.hash_seed, 42ULL);
}

TEST(PiccardParams, ValidatePreservesCustomHashSeed) {
    const uint64_t seeds[] = {0ULL, 1ULL, 42ULL, 12345ULL,
                              UINT64_MAX - 1, UINT64_MAX};
    for (uint64_t seed : seeds) {
        PiccardParams params;
        params.hash_seed = seed;
        params.Validate();
        RecordProperty("seed_" + std::to_string(seed), "preserved");
        EXPECT_EQ(params.hash_seed, seed);
    }
}

TEST(PiccardParams, ValidateSqrtPreservesCustomHashSeed) {
    const uint64_t seeds[] = {0ULL, 7ULL, UINT64_MAX};
    for (uint64_t seed : seeds) {
        PiccardParams params;
        params.hash_seed = seed;
        params.ValidateSqrt();
        EXPECT_EQ(params.hash_seed, seed);
    }
}

// Extreme seeds must not make expansion throw or produce a degenerate family.
TEST(PiccardParams, ExtremeHashSeedsAreAccepted) {
    for (uint64_t seed : {0ULL, UINT64_MAX}) {
        PiccardParams params;
        params.hash_seed = seed;
        EXPECT_NO_THROW(params.Validate());
    }
}
