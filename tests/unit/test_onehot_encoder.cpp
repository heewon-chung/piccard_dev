#include <gtest/gtest.h>
#include "piccard/core/onehot_encoder.h"
#include "piccard/util/params.h"

#include <string>

using namespace piccard;

class OneHotEncoderTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 16;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.Validate();
    }

    PiccardParams params;
};

TEST_F(OneHotEncoderTest, ExactlyKOnes) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));

    OneHotEncoder encoder(params);

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 3;
    RecordProperty("input_sig_pattern", "i * 3 for i in [0, k)");

    auto feature = encoder.Encode(sig);

    int64_t count = 0;
    for (auto v : feature) count += v;
    RecordProperty("output_ones_count", std::to_string(count));
    RecordProperty("output_feature_length", static_cast<int>(feature.size()));

    EXPECT_EQ(count, static_cast<int64_t>(params.k));
}

TEST_F(OneHotEncoderTest, CorrectPositions) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));

    OneHotEncoder encoder(params);

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 5 + 2;
    RecordProperty("input_sig_pattern", "i * 5 + 2 for i in [0, k)");

    auto feature = encoder.Encode(sig);

    std::string positions;
    for (uint32_t i = 0; i < params.k; i++) {
        uint32_t expected_bucket = static_cast<uint32_t>(sig[i] % params.m);
        uint32_t idx = i * params.m + expected_bucket;
        if (i > 0) positions += ", ";
        positions += std::to_string(idx);
        EXPECT_EQ(feature[idx], 1) << "Hash function " << i << " bucket " << expected_bucket;
    }
    RecordProperty("output_hot_positions", positions);
}

TEST_F(OneHotEncoderTest, ZeroPadding) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_feature_dim", static_cast<int>(params.k * params.m));
    RecordProperty("input_ring_dim", static_cast<int>(params.ring_dim));

    OneHotEncoder encoder(params);

    std::vector<uint64_t> sig(params.k, 0);
    auto feature = encoder.Encode(sig);

    RecordProperty("output_feature_length", static_cast<int>(feature.size()));

    int64_t pad_sum = 0;
    for (uint32_t i = params.k * params.m; i < params.ring_dim; i++) {
        pad_sum += feature[i];
    }
    RecordProperty("output_padding_sum", std::to_string(pad_sum));

    EXPECT_EQ(feature.size(), params.ring_dim);
    for (uint32_t i = params.k * params.m; i < params.ring_dim; i++) {
        EXPECT_EQ(feature[i], 0) << "Position " << i << " should be zero-padded";
    }
}

TEST_F(OneHotEncoderTest, EncodeDecodeRoundTrip) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_sig_pattern", "i * 7 + 3 for i in [0, k)");

    OneHotEncoder encoder(params);

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 7 + 3;

    auto feature = encoder.Encode(sig);
    auto decoded = encoder.Decode(feature);

    bool all_match = true;
    for (uint32_t i = 0; i < params.k; i++) {
        uint32_t expected_bucket = static_cast<uint32_t>(sig[i] % params.m);
        if (decoded[i] != expected_bucket) all_match = false;
        EXPECT_EQ(decoded[i], expected_bucket) << "Hash function " << i;
    }
    RecordProperty("output_round_trip_match", all_match ? "true" : "false");
}

TEST_F(OneHotEncoderTest, WrongSignatureLengthThrows) {
    RecordProperty("input_sig_length", static_cast<int>(params.k + 1));
    RecordProperty("expected_k", static_cast<int>(params.k));
    RecordProperty("expected_outcome", "throws std::invalid_argument");

    OneHotEncoder encoder(params);

    std::vector<uint64_t> bad_sig(params.k + 1, 0);
    EXPECT_THROW(encoder.Encode(bad_sig), std::invalid_argument);
}

TEST_F(OneHotEncoderTest, VectorLengthIsRingDim) {
    RecordProperty("input_ring_dim", static_cast<int>(params.ring_dim));

    OneHotEncoder encoder(params);

    std::vector<uint64_t> sig(params.k, 0);
    auto feature = encoder.Encode(sig);

    RecordProperty("output_feature_length", static_cast<int>(feature.size()));

    EXPECT_EQ(feature.size(), params.ring_dim);
}

TEST_F(OneHotEncoderTest, MutualExclusivity) {
    // Each block of m consecutive slots should have exactly one 1
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_sig_pattern", "i * 13 + 7 for i in [0, k)");
    RecordProperty("expected", "exactly one 1 per block of m");

    OneHotEncoder encoder(params);
    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 13 + 7;

    auto feature = encoder.Encode(sig);

    for (uint32_t i = 0; i < params.k; i++) {
        int64_t block_sum = 0;
        for (uint32_t j = 0; j < params.m; j++) {
            block_sum += feature[i * params.m + j];
        }
        RecordProperty("block_" + std::to_string(i) + "_sum",
                       std::to_string(block_sum));
        EXPECT_EQ(block_sum, 1)
            << "Block " << i << " should have exactly one 1";
    }
}

TEST_F(OneHotEncoderTest, DifferentSignaturesProduceDifferentFeatures) {
    // Two distinct signatures should produce different feature vectors
    RecordProperty("input_sig_a_pattern", "all zeros");
    RecordProperty("input_sig_b_pattern", "all ones");

    OneHotEncoder encoder(params);

    std::vector<uint64_t> sig_a(params.k, 0);
    std::vector<uint64_t> sig_b(params.k, 1);

    auto feat_a = encoder.Encode(sig_a);
    auto feat_b = encoder.Encode(sig_b);

    // Count differing positions
    uint32_t diffs = 0;
    for (size_t i = 0; i < feat_a.size(); i++) {
        if (feat_a[i] != feat_b[i]) diffs++;
    }

    RecordProperty("output_differing_positions", static_cast<int>(diffs));

    EXPECT_GT(diffs, 0u) << "Different signatures must produce different features";
    // Each hash function moves its 1 from bucket 0 to bucket 1 → 2*k differences
    EXPECT_EQ(diffs, 2 * params.k)
        << "Each of k hash functions should differ in exactly 2 positions";
}

TEST_F(OneHotEncoderTest, MatchCountFromDotProduct) {
    // Two identical signatures should produce feature vectors with dot product = k
    // Two disjoint (different bucket) sigs should produce dot product < k
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));

    OneHotEncoder encoder(params);

    std::vector<uint64_t> sig(params.k);
    for (uint32_t i = 0; i < params.k; i++) sig[i] = i * 3;

    auto feat = encoder.Encode(sig);

    // Self dot product
    int64_t self_dot = 0;
    for (size_t i = 0; i < feat.size(); i++) {
        self_dot += feat[i] * feat[i];
    }

    RecordProperty("output_self_dot_product", std::to_string(self_dot));
    RecordProperty("expected_self_dot", std::to_string(params.k));

    EXPECT_EQ(self_dot, static_cast<int64_t>(params.k))
        << "Self dot product of one-hot features should equal k";
}
