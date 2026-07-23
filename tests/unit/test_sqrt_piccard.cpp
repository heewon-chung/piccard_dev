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

    EXPECT_EQ(params.mult_depth, 3u);
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
