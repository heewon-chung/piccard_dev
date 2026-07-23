#include <gtest/gtest.h>
#include "core/sqrt_encoder.h"
#include "util/params.h"

#include <string>

using namespace piccard;

class SqrtEncoderTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 16;
        params.m = 64;
        params.security = SecurityLevel::TOY;
        params.ValidateSqrt();
    }

    PiccardParams params;
};

TEST_F(SqrtEncoderTest, Exactly2KOnes) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_sqrt_base", static_cast<int>(params.sqrt_base));

    SqrtEncoder encoder(params);

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 3;

    auto feature = encoder.Encode(sig);

    int64_t count = 0;
    for (auto v : feature) count += v;
    RecordProperty("output_ones_count", std::to_string(count));

    EXPECT_EQ(count, static_cast<int64_t>(2 * params.k));
}

TEST_F(SqrtEncoderTest, CorrectPositions) {
    SqrtEncoder encoder(params);
    uint32_t b = params.sqrt_base;  // 8
    uint32_t block = 2 * b;         // 16

    // Test with a known value: sig[0] = 53 -> v_lo = 53%8 = 5, v_hi = 53/8 = 6
    std::vector<uint64_t> sig(params.k, 0);
    sig[0] = 53;

    auto feature = encoder.Encode(sig);

    // Check signature 0: lo digit
    EXPECT_EQ(feature[0 * block + 5], 1) << "lo digit of 53 should be at position 5";
    // Check signature 0: hi digit
    EXPECT_EQ(feature[0 * block + b + 6], 1) << "hi digit of 53 should be at position b+6";

    // Check no other bits set in signature 0's block (besides positions 5 and b+6)
    for (uint32_t j = 0; j < block; j++) {
        if (j == 5 || j == b + 6) continue;
        EXPECT_EQ(feature[j], 0) << "Position " << j << " should be 0";
    }
}

TEST_F(SqrtEncoderTest, MutualExclusivity) {
    SqrtEncoder encoder(params);
    uint32_t b = params.sqrt_base;

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 13 + 7;

    auto feature = encoder.Encode(sig);

    // Each b-sized sub-block should have exactly one 1
    uint32_t block = 2 * b;
    for (uint32_t i = 0; i < params.k; i++) {
        // Lo sub-block
        int64_t lo_sum = 0;
        for (uint32_t j = 0; j < b; j++) {
            lo_sum += feature[i * block + j];
        }
        EXPECT_EQ(lo_sum, 1) << "Sig " << i << " lo sub-block should have exactly one 1";

        // Hi sub-block
        int64_t hi_sum = 0;
        for (uint32_t j = 0; j < b; j++) {
            hi_sum += feature[i * block + b + j];
        }
        EXPECT_EQ(hi_sum, 1) << "Sig " << i << " hi sub-block should have exactly one 1";
    }
}

TEST_F(SqrtEncoderTest, ZeroPadding) {
    SqrtEncoder encoder(params);

    std::vector<uint64_t> sig(params.k, 0);
    auto feature = encoder.Encode(sig);

    EXPECT_EQ(feature.size(), params.ring_dim);

    uint32_t data_end = params.k * 2 * params.sqrt_base;
    for (uint32_t i = data_end; i < params.ring_dim; i++) {
        EXPECT_EQ(feature[i], 0) << "Position " << i << " should be zero-padded";
    }
}

TEST_F(SqrtEncoderTest, EncodeDecodeRoundTrip) {
    SqrtEncoder encoder(params);

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 7 + 3;

    auto feature = encoder.Encode(sig);
    auto decoded = encoder.Decode(feature);

    for (uint32_t i = 0; i < params.k; i++) {
        uint32_t expected = static_cast<uint32_t>(sig[i] % params.m);
        EXPECT_EQ(decoded[i], expected) << "Hash function " << i;
    }
}

TEST_F(SqrtEncoderTest, VectorLengthIsRingDim) {
    SqrtEncoder encoder(params);

    std::vector<uint64_t> sig(params.k, 0);
    auto feature = encoder.Encode(sig);

    EXPECT_EQ(feature.size(), params.ring_dim);
}

TEST_F(SqrtEncoderTest, WrongSignatureLengthThrows) {
    SqrtEncoder encoder(params);

    std::vector<uint64_t> bad_sig(params.k + 1, 0);
    EXPECT_THROW(encoder.Encode(bad_sig), std::invalid_argument);
}

TEST_F(SqrtEncoderTest, SelfDotProduct) {
    // Dot product of identical features should equal 2*k (two ones per signature)
    SqrtEncoder encoder(params);

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 3;

    auto feat = encoder.Encode(sig);

    int64_t self_dot = 0;
    for (size_t i = 0; i < feat.size(); i++) {
        self_dot += feat[i] * feat[i];
    }

    EXPECT_EQ(self_dot, static_cast<int64_t>(2 * params.k));
}

TEST_F(SqrtEncoderTest, DifferentMValues) {
    // Test with m=16 (b=4) and m=256 (b=16)
    for (uint32_t m : {16u, 256u}) {
        PiccardParams p;
        p.k = 8;
        p.m = m;
        p.security = SecurityLevel::TOY;
        p.ValidateSqrt();

        uint32_t expected_b = (m == 16) ? 4 : 16;
        EXPECT_EQ(p.sqrt_base, expected_b) << "m=" << m;
        EXPECT_EQ(p.sqrt_feature_dim, p.k * 2 * expected_b) << "m=" << m;

        SqrtEncoder encoder(p);
        std::vector<uint64_t> sig(p.k);
        for (uint32_t i = 0; i < p.k; i++) sig[i] = i * 5;

        auto feature = encoder.Encode(sig);
        EXPECT_EQ(feature.size(), p.ring_dim) << "m=" << m;

        int64_t count = 0;
        for (auto v : feature) count += v;
        EXPECT_EQ(count, static_cast<int64_t>(2 * p.k)) << "m=" << m;

        auto decoded = encoder.Decode(feature);
        for (uint32_t i = 0; i < p.k; i++) {
            EXPECT_EQ(decoded[i], static_cast<uint32_t>(sig[i] % m))
                << "m=" << m << " i=" << i;
        }
    }
}
