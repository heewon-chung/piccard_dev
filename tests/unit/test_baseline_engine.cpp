#include "baseline_engine.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

using namespace piccard;
using namespace piccard::baseline;

namespace {

constexpr uint32_t kUniverse = 64;

std::vector<uint64_t> SetA() {
    return {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
}

std::vector<uint64_t> SetB() {
    return {0, 1, 2, 3, 4, 5, 6, 10, 11, 12};
}

BaselineParams ToyParams() {
    BaselineParams params;
    params.universe_size = kUniverse;
    params.security = SecurityLevel::TOY;
    params.Validate();
    return params;
}

class BaselineEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        engine = std::make_unique<BaselineEngine>(ToyParams());
        engine->Initialize();
    }

    std::unique_ptr<BaselineEngine> engine;
};

}  // namespace

TEST_F(BaselineEngineTest, FrozenToyQueryReturnsExactIntersectionAndJaccard) {
    const auto result = engine->RunQueryPhased(SetA(), SetB());

    RecordProperty("input_universe", static_cast<int>(kUniverse));
    RecordProperty("input_set_size_a", 10);
    RecordProperty("input_set_size_b", 10);
    RecordProperty("expected_intersection", 7);
    RecordProperty("expected_union", 13);
    RecordProperty("output_intersection", result.intersection);
    RecordProperty("output_union", result.union_size);
    RecordProperty("output_jaccard", result.jaccard);

    EXPECT_EQ(result.universe_size, kUniverse);
    EXPECT_EQ(result.ring_dim, engine->GetParams().ring_dim);
    EXPECT_EQ(result.num_ciphertexts, engine->GetParams().num_ciphertexts);
    EXPECT_EQ(result.intersection, 7);
    EXPECT_EQ(result.intersection_count, 7);
    EXPECT_EQ(result.union_size, 13);
    EXPECT_DOUBLE_EQ(result.jaccard, 7.0 / 13.0);
    EXPECT_DOUBLE_EQ(result.jaccard_estimate, 7.0 / 13.0);

    EXPECT_GT(result.phase_encode_ms, 0.0);
    EXPECT_GT(result.phase_encrypt_ms, 0.0);
    EXPECT_GT(result.phase_evaluate_ms, 0.0);
    EXPECT_GT(result.phase_decrypt_ms, 0.0);
    EXPECT_DOUBLE_EQ(
        result.online_ms,
        result.phase_encode_ms + result.phase_encrypt_ms +
            result.phase_evaluate_ms + result.phase_decrypt_ms);
    EXPECT_DOUBLE_EQ(result.total_ms, result.online_ms);
    EXPECT_DOUBLE_EQ(result.phase_compute_ms, result.phase_evaluate_ms);
    EXPECT_DOUBLE_EQ(result.phases.online_ms, result.online_ms);
    EXPECT_DOUBLE_EQ(
        result.phases.TotalOnlineMs(),
        result.phase_encode_ms + result.phase_encrypt_ms +
            result.phase_evaluate_ms + result.phase_decrypt_ms);

    // Setup is available separately and is not part of the online sum.
    EXPECT_DOUBLE_EQ(result.setup_context_ms,
                     engine->GetSetupTimings().context_ms);
    EXPECT_DOUBLE_EQ(result.setup_keygen_ms,
                     engine->GetSetupTimings().keygen_ms);
    EXPECT_DOUBLE_EQ(result.setup_ms, engine->GetSetupTimings().total_ms);
    EXPECT_GE(result.setup_ms, 0.0);

    EXPECT_GT(result.per_ciphertext_bytes, 0u);
    EXPECT_GT(result.party_x_ciphertext_bytes, 0u);
    EXPECT_GT(result.party_y_ciphertext_bytes, 0u);
    EXPECT_GT(result.result_ciphertext_bytes, 0u);
    EXPECT_EQ(result.ct_size_bytes, result.party_x_ciphertext_bytes);
    EXPECT_EQ(result.ciphertext_bytes, result.party_x_ciphertext_bytes);
    EXPECT_EQ(
        result.communication_bytes,
        result.party_x_ciphertext_bytes + result.party_y_ciphertext_bytes +
            result.result_ciphertext_bytes);
    EXPECT_EQ(result.comm_bytes, result.communication_bytes);
    EXPECT_EQ(result.communication.total_bytes, result.communication_bytes);
    EXPECT_EQ(result.communication.upload_bytes,
              result.party_x_ciphertext_bytes +
                  result.party_y_ciphertext_bytes);
    EXPECT_EQ(result.communication.download_bytes,
              result.result_ciphertext_bytes);

    ASSERT_TRUE(result.provenance.actual_ring_dim.has_value());
    EXPECT_EQ(*result.provenance.actual_ring_dim, result.ring_dim);
    EXPECT_FALSE(result.provenance.sanitizer_applicable);
    EXPECT_FALSE(result.provenance.transcript_stat_bits.has_value());
    EXPECT_FALSE(result.provenance.max_queries.has_value());
    EXPECT_FALSE(result.runtime_metadata.context_fingerprint.empty());
}

TEST_F(BaselineEngineTest, ExistingConvenienceApisRemainUsable) {
    const auto chunks_a = engine->EncodeBinaryVectors(SetA());
    const auto chunks_b = engine->EncodeBinaryVectors(SetB());
    ASSERT_EQ(chunks_a.size(), engine->GetParams().num_ciphertexts);
    ASSERT_EQ(chunks_b.size(), engine->GetParams().num_ciphertexts);
    ASSERT_EQ(chunks_a.front().size(), engine->GetParams().ring_dim);
    ASSERT_EQ(chunks_b.front().size(), engine->GetParams().ring_dim);

    const auto ciphertexts_a = engine->EncryptChunks(chunks_a);
    const auto ciphertexts_b = engine->EncryptChunks(chunks_b);
    const auto inner_product =
        engine->ComputeInnerProduct(ciphertexts_a, ciphertexts_b);
    EXPECT_EQ(engine->DecryptIntersection(inner_product), 7);
    EXPECT_DOUBLE_EQ(
        engine->ComputeJaccardFromInnerProduct(
            inner_product, SetA().size(), SetB().size()),
        7.0 / 13.0);
    EXPECT_DOUBLE_EQ(engine->ComputeJaccard(SetA(), SetB()), 7.0 / 13.0);
}

TEST(BaselineEngineSetup, ContextOnlyExcludesKeyGeneration) {
    auto params = ToyParams();
    BaselineEngine engine(params);

    engine.InitializeContextOnly();
    EXPECT_TRUE(engine.IsContextInitialized());
    EXPECT_FALSE(engine.HasGeneratedKeys());
    EXPECT_DOUBLE_EQ(engine.GetSetupTimings().keygen_ms, 0.0);
    EXPECT_THROW(engine.RunQueryPhased(SetA(), SetB()), std::logic_error);

    engine.InitializeKeys();
    EXPECT_TRUE(engine.HasGeneratedKeys());
    EXPECT_GE(engine.GetSetupTimings().total_ms,
              engine.GetSetupTimings().context_ms);
}

TEST_F(BaselineEngineTest, OutOfUniverseElementsStillFailClosed) {
    EXPECT_THROW(engine->EncodeBinaryVectors({kUniverse}),
                 std::out_of_range);
    EXPECT_THROW(engine->RunQueryPhased(SetA(), {0, 1, 2, 3, 4, 5, 6, 10,
                                                  11, kUniverse}),
                 std::out_of_range);
}
