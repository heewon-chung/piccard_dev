#include <gtest/gtest.h>
#include "protocol/sqrt_piccard.h"
#include "protocol/piccard.h"

#include <cmath>
#include <numeric>
#include <string>

using namespace piccard;

class SqrtPiccardTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 16;
        params.m = 64;
        params.security = SecurityLevel::TOY;
    }

    PiccardParams params;
};

TEST_F(SqrtPiccardTest, IdenticalSets) {
    params.ValidateSqrt();
    SqrtPiccard engine(params);
    engine.KeyGen();

    std::vector<uint64_t> set_x;
    for (uint64_t i = 1; i <= 100; i++) set_x.push_back(i);

    auto result = engine.Run(set_x, set_x);

    RecordProperty("match_count", std::to_string(result.match_count));
    RecordProperty("jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_GE(result.match_count, static_cast<int64_t>(params.k * 0.8));
    EXPECT_GT(result.jaccard_estimate, 0.9);
}

TEST_F(SqrtPiccardTest, DisjointSets) {
    params.ValidateSqrt();
    SqrtPiccard engine(params);
    engine.KeyGen();

    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 1; i <= 500; i++) set_x.push_back(i);
    for (uint64_t i = 10001; i <= 10500; i++) set_y.push_back(i);

    auto result = engine.Run(set_x, set_y);

    RecordProperty("match_count", std::to_string(result.match_count));
    RecordProperty("jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_LT(result.jaccard_estimate, 0.15);
}

TEST_F(SqrtPiccardTest, PartialOverlap) {
    params.ValidateSqrt();
    SqrtPiccard engine(params);
    engine.KeyGen();

    // 50% overlap: x = {1..200}, y = {101..300}
    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 1; i <= 200; i++) set_x.push_back(i);
    for (uint64_t i = 101; i <= 300; i++) set_y.push_back(i);
    // True J = |{101..200}| / |{1..300}| = 100/300 ≈ 0.333

    auto result = engine.Run(set_x, set_y);

    RecordProperty("jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_GT(result.jaccard_estimate, 0.15);
    EXPECT_LT(result.jaccard_estimate, 0.55);
}

TEST_F(SqrtPiccardTest, MultDepthIsThree) {
    // Two ct-ct multiplications (component-wise AND + digit AND) need
    // depth 2 theoretically, but depth 3 provides necessary noise
    // headroom for the intermediate rotate-and-sum operations.
    params.ValidateSqrt();

    // The circuit's own requirement stays 3; mult_depth is provisioned at or
    // above it to carry the noise-flooding term (R2-W6).
    EXPECT_EQ(params.natural_mult_depth, 3u);
    EXPECT_GE(params.mult_depth, params.natural_mult_depth);
}

TEST_F(SqrtPiccardTest, RingDimSmallerOrEqual) {
    // SqrtPiccard should use <= ring_dim compared to one-hot Piccard
    PiccardParams oh_params;
    oh_params.k = params.k;
    oh_params.m = params.m;
    oh_params.security = SecurityLevel::TOY;
    oh_params.Validate();

    params.ValidateSqrt();

    RecordProperty("onehot_feature_dim", static_cast<int>(oh_params.feature_dim));
    RecordProperty("sqrt_feature_dim", static_cast<int>(params.sqrt_feature_dim));
    RecordProperty("onehot_ring_dim", static_cast<int>(oh_params.ring_dim));
    RecordProperty("sqrt_ring_dim", static_cast<int>(params.ring_dim));

    EXPECT_LT(params.sqrt_feature_dim, oh_params.feature_dim);
}

TEST_F(SqrtPiccardTest, ConsistentWithPiccard) {
    // Both encodings should produce similar Jaccard estimates on the same inputs
    PiccardParams oh_params;
    oh_params.k = params.k;
    oh_params.m = params.m;
    oh_params.security = SecurityLevel::TOY;
    oh_params.Validate();

    Piccard oh_engine(oh_params);
    oh_engine.KeyGen();

    params.ValidateSqrt();
    SqrtPiccard sqrt_engine(params);
    sqrt_engine.KeyGen();

    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 1; i <= 200; i++) set_x.push_back(i);
    for (uint64_t i = 101; i <= 300; i++) set_y.push_back(i);

    auto oh_result = oh_engine.Run(set_x, set_y);
    auto sqrt_result = sqrt_engine.Run(set_x, set_y);

    RecordProperty("onehot_jaccard", std::to_string(oh_result.jaccard_estimate));
    RecordProperty("sqrt_jaccard", std::to_string(sqrt_result.jaccard_estimate));

    // Both should be in a reasonable range of the true Jaccard (~0.333)
    // With k=16, variance is high, so we allow wide tolerance
    EXPECT_NEAR(oh_result.jaccard_estimate, sqrt_result.jaccard_estimate, 0.3);
}

TEST_F(SqrtPiccardTest, Symmetry) {
    params.ValidateSqrt();
    SqrtPiccard engine(params);
    engine.KeyGen();

    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 1; i <= 100; i++) set_x.push_back(i);
    for (uint64_t i = 51; i <= 150; i++) set_y.push_back(i);

    auto r1 = engine.Run(set_x, set_y);
    auto r2 = engine.Run(set_y, set_x);

    EXPECT_EQ(r1.match_count, r2.match_count);
    EXPECT_DOUBLE_EQ(r1.jaccard_estimate, r2.jaccard_estimate);
}

TEST_F(SqrtPiccardTest, FloodedMatchCountIsStillExact) {
    // Flooding must leave the base-sqrt(m) match count untouched.
    //
    // This fixture's SetUp() only fills in k/m/security -- it does not call
    // ValidateSqrt() and there is no `engine` member. Every existing test in
    // this file builds its own, so do the same.
    params.ValidateSqrt();
    SqrtPiccard engine(params);
    engine.KeyGen();

    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 0; i < 100; i++) { set_x.push_back(i); set_y.push_back(i); }

    RecordProperty("input_flood_noise_bits",
                   static_cast<int>(params.FloodNoiseBits()));

    auto result = engine.Run(set_x, set_y);

    RecordProperty("output_match_count",
                   static_cast<int>(result.match_count));
    // Exact, not the EXPECT_GE(k*0.8) the other tests in this file use: for
    // identical sets the base-sqrt(m) circuit is exact (verified across all
    // three input patterns), and an exact assertion is what catches flooding
    // perturbing the value.
    EXPECT_EQ(result.match_count, static_cast<int64_t>(params.k));
}

// ── Shared CRS across encodings (§"벤치마크 난수 계약") ───────────────────────
// The paired one-hot vs sqrt comparison is only meaningful if both encodings
// draw their MinHash signature from the same hash family. The encoding differs
// downstream of the signature, so the same seed must give the same signature.

TEST_F(SqrtPiccardTest, SharesMinHashSignatureWithOneHotForSameSeed) {
    PiccardParams onehot_params = params;
    onehot_params.Validate();
    PiccardParams sqrt_params = params;
    sqrt_params.ValidateSqrt();
    ASSERT_EQ(onehot_params.hash_seed, sqrt_params.hash_seed);

    Piccard onehot_engine(onehot_params);
    onehot_engine.KeyGen();
    SqrtPiccard sqrt_engine(sqrt_params);
    sqrt_engine.KeyGen();

    std::vector<uint64_t> set;
    for (uint64_t i = 1; i <= 100; i++) set.push_back(i);

    EXPECT_EQ(onehot_engine.ComputeSignature(set),
              sqrt_engine.ComputeSignature(set));
}

// Reseeding both engines to the same trial seed keeps them paired, and moving
// to a different seed actually moves the signature.
TEST_F(SqrtPiccardTest, ReseedingBothEnginesKeepsSignaturesPaired) {
    PiccardParams onehot_params = params;
    onehot_params.Validate();
    PiccardParams sqrt_params = params;
    sqrt_params.ValidateSqrt();

    Piccard onehot_engine(onehot_params);
    onehot_engine.KeyGen();
    SqrtPiccard sqrt_engine(sqrt_params);
    sqrt_engine.KeyGen();

    std::vector<uint64_t> set;
    for (uint64_t i = 1; i <= 100; i++) set.push_back(i);

    std::vector<std::vector<uint64_t>> seen;
    for (uint64_t trial_seed : {1001ULL, 2002ULL, 3003ULL}) {
        onehot_engine.SetHashSeed(trial_seed);
        sqrt_engine.SetHashSeed(trial_seed);

        const auto onehot_sig = onehot_engine.ComputeSignature(set);
        const auto sqrt_sig = sqrt_engine.ComputeSignature(set);

        SCOPED_TRACE("trial_seed=" + std::to_string(trial_seed));
        EXPECT_EQ(onehot_sig, sqrt_sig);
        for (const auto& earlier : seen) EXPECT_NE(onehot_sig, earlier);
        seen.push_back(onehot_sig);
    }
}
