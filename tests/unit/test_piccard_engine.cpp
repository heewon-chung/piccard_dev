#include <gtest/gtest.h>
#include "protocol/dynamic_piccard.h"
#include "protocol/piccard.h"

#include <cmath>
#include <stdexcept>
#include <string>

using namespace piccard;

class PiccardEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 64;
        params.m = 16;
        params.security = SecurityLevel::TOY;
        params.Validate();

        engine = std::make_unique<Piccard>(params);
        engine->KeyGen();
    }

    PiccardParams params;
    std::unique_ptr<Piccard> engine;
};

TEST_F(PiccardEngineTest, IdenticalSets) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_set", "{0..49}");
    RecordProperty("expected_jaccard", "1.0");

    std::vector<uint64_t> set;
    for (uint64_t i = 0; i < 50; i++) set.push_back(i);

    auto result = engine->Run(set, set);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_EQ(result.match_count, static_cast<int64_t>(params.k));
    EXPECT_NEAR(result.jaccard_estimate, 1.0, 0.01);
}

TEST_F(PiccardEngineTest, EvaluateAndEvaluateRawAgreeOnMatchCount) {
    // Flooding must not move the value the receiver reads. Both paths must
    // report the same match count for the same inputs.
    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 0; i < 100; i++) { set_x.push_back(i); set_y.push_back(i); }

    auto ct_x = engine->Encrypt(set_x);
    auto ct_y = engine->Encrypt(set_y);

    auto raw = engine->EvaluateRaw(ct_x, ct_y);
    auto flooded = engine->Evaluate(ct_x, ct_y);

    auto raw_result = engine->Decrypt(raw);
    auto flooded_result = engine->Decrypt(flooded);

    RecordProperty("output_raw_match_count",
                   static_cast<int>(raw_result.match_count));
    RecordProperty("output_flooded_match_count",
                   static_cast<int>(flooded_result.match_count));

    EXPECT_EQ(raw_result.match_count, flooded_result.match_count);
    EXPECT_EQ(flooded_result.match_count, static_cast<int64_t>(params.k));
}

TEST_F(PiccardEngineTest, EvaluateFloodsAndEvaluateRawDoesNot) {
    // The two must differ as ciphertexts: if Evaluate returned the raw result
    // the protocol would ship unflooded output while looking correct.
    std::vector<uint64_t> set_x, set_y;
    for (uint64_t i = 0; i < 50; i++) { set_x.push_back(i); set_y.push_back(i); }

    auto ct_x = engine->Encrypt(set_x);
    auto ct_y = engine->Encrypt(set_y);

    auto raw = engine->EvaluateRaw(ct_x, ct_y);
    auto flooded = engine->Evaluate(ct_x, ct_y);

    const auto& er = raw->GetElements()[0];
    const auto& ef = flooded->GetElements()[0];
    bool differs = false;
    for (size_t i = 0; i < er.GetNumOfElements() && !differs; i++) {
        if (er.GetElementAtIndex(i) != ef.GetElementAtIndex(i)) differs = true;
    }

    RecordProperty("output_raw_differs_from_flooded", differs ? "true" : "false");
    EXPECT_TRUE(differs);
    EXPECT_EQ(flooded->GetLevel(), raw->GetLevel())
        << "the protocol must return immediately after flooding";
}

TEST_F(PiccardEngineTest, KeyGenAdoptsVerifiedRuntimeRingDimension) {
    EXPECT_EQ(engine->GetParams().ring_dim,
              engine->GetBFVContext().GetSlotCount());
    EXPECT_EQ(engine->GetParams().RequestedRingDim(),
              params.RequestedRingDim());
    EXPECT_NO_THROW(engine->GetParams().FloodNoiseBits());

    PiccardParams already_adopted = engine->GetParams();
    EXPECT_THROW(
        already_adopted.AdoptVerifiedRuntimeRingDim(
            engine->GetBFVContext().GetSlotCount()),
        std::logic_error);
}

TEST_F(PiccardEngineTest, DynamicExitUsesTheAdoptedFloodedBasePath) {
    DynamicPiccard dynamic(params);
    dynamic.KeyGen();

    PiccardParams already_adopted = dynamic.GetParams();
    EXPECT_THROW(
        already_adopted.AdoptVerifiedRuntimeRingDim(
            dynamic.GetBFVContext().GetSlotCount()),
        std::logic_error);

    std::vector<uint64_t> set = {1, 2, 3, 4, 5};
    auto bottom = dynamic.InitSet(set);
    auto ct = dynamic.Encrypt(*bottom);
    auto raw = dynamic.EvaluateRaw(ct, ct);
    auto flooded = dynamic.Evaluate(ct, ct);
    EXPECT_NE(raw->GetElements()[0], flooded->GetElements()[0]);
    EXPECT_EQ(flooded->GetLevel(), raw->GetLevel())
        << "the dynamic protocol must return immediately after flooding";
}

TEST_F(PiccardEngineTest, DisjointSets) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{10000..10099}");
    RecordProperty("expected_jaccard", "0.0");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) {
        set_a.push_back(i);
        set_b.push_back(i + 10000);
    }

    auto result = engine->Run(set_a, set_b);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));
    RecordProperty("expected_collision_matches", std::to_string(params.k / params.m));

    double expected_collisions = static_cast<double>(params.k) / params.m;
    EXPECT_NEAR(static_cast<double>(result.match_count), expected_collisions,
                expected_collisions * 0.5 + 5);

    EXPECT_NEAR(result.jaccard_estimate, 0.0, 0.15);
}

TEST_F(PiccardEngineTest, KnownOverlap) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_set_a", "{0..99}");
    RecordProperty("input_set_b", "{50..149}");
    RecordProperty("expected_jaccard", "0.333333 (1/3)");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 100; i++) set_a.push_back(i);
    for (uint64_t i = 50; i < 150; i++) set_b.push_back(i);

    auto result = engine->Run(set_a, set_b);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));
    RecordProperty("output_error", std::to_string(std::abs(result.jaccard_estimate - 1.0 / 3.0)));

    EXPECT_NEAR(result.jaccard_estimate, 1.0 / 3.0, 0.2);
}

TEST_F(PiccardEngineTest, MatchCountIsNonNegative) {
    RecordProperty("input_set_a", "{1, 2, 3, 4, 5}");
    RecordProperty("input_set_b", "{6, 7, 8, 9, 10}");

    std::vector<uint64_t> set_a = {1, 2, 3, 4, 5};
    std::vector<uint64_t> set_b = {6, 7, 8, 9, 10};

    auto result = engine->Run(set_a, set_b);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_GE(result.match_count, 0);
}

TEST_F(PiccardEngineTest, BiasCorrection) {
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_set", "{100, 200, 300, 400, 500}");
    RecordProperty("formula", "J_hat = (v/k - 1/m) / (1 - 1/m)");

    std::vector<uint64_t> set = {100, 200, 300, 400, 500};

    auto result = engine->Run(set, set);

    double k = static_cast<double>(params.k);
    double m = static_cast<double>(params.m);
    double expected_j = (static_cast<double>(result.match_count) / k - 1.0 / m) / (1.0 - 1.0 / m);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));
    RecordProperty("output_expected_from_formula", std::to_string(expected_j));

    EXPECT_DOUBLE_EQ(result.jaccard_estimate, expected_j);
}

TEST_F(PiccardEngineTest, JaccardClampedToZero) {
    // Simulate match_count = 0 (below bucket collision floor)
    // j_hat = (0/64 - 1/16) / (1 - 1/16) = -0.0667, clamped to 0.0
    RecordProperty("input_match_count", "0");
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("formula", "(0/64 - 1/16) / (1 - 1/16) = -0.0667");
    RecordProperty("expected_clamped", "0.0");

    std::vector<int64_t> fake_result(params.ring_dim, 0);
    fake_result[0] = 0;
    auto ct = engine->EncryptFeature(fake_result);
    auto result = engine->Decrypt(ct);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_EQ(result.match_count, 0);
    EXPECT_DOUBLE_EQ(result.jaccard_estimate, 0.0);
}

TEST_F(PiccardEngineTest, JaccardClampedToOne) {
    // Simulate match_count = k + 5 (above maximum possible)
    // j_hat = (69/64 - 1/16) / (1 - 1/16) = 1.0833, clamped to 1.0
    RecordProperty("input_match_count", std::to_string(params.k + 5));
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("formula", "(69/64 - 1/16) / (1 - 1/16) = 1.0833");
    RecordProperty("expected_clamped", "1.0");

    std::vector<int64_t> fake_result(params.ring_dim, 0);
    fake_result[0] = static_cast<int64_t>(params.k + 5);
    auto ct = engine->EncryptFeature(fake_result);
    auto result = engine->Decrypt(ct);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_EQ(result.match_count, static_cast<int64_t>(params.k + 5));
    EXPECT_DOUBLE_EQ(result.jaccard_estimate, 1.0);
}

TEST_F(PiccardEngineTest, Symmetry) {
    // J(A,B) should equal J(B,A)
    RecordProperty("input_set_a", "{0..79}");
    RecordProperty("input_set_b", "{30..119}");

    std::vector<uint64_t> set_a, set_b;
    for (uint64_t i = 0; i < 80; i++) set_a.push_back(i);
    for (uint64_t i = 30; i < 120; i++) set_b.push_back(i);

    auto result_ab = engine->Run(set_a, set_b);
    auto result_ba = engine->Run(set_b, set_a);

    RecordProperty("output_J(A,B)_match", std::to_string(result_ab.match_count));
    RecordProperty("output_J(A,B)_estimate", std::to_string(result_ab.jaccard_estimate));
    RecordProperty("output_J(B,A)_match", std::to_string(result_ba.match_count));
    RecordProperty("output_J(B,A)_estimate", std::to_string(result_ba.jaccard_estimate));

    EXPECT_EQ(result_ab.match_count, result_ba.match_count);
    EXPECT_DOUBLE_EQ(result_ab.jaccard_estimate, result_ba.jaccard_estimate);
}

TEST_F(PiccardEngineTest, MonotonicitySharingMoreIncreasesJaccard) {
    // Adding shared elements should increase the Jaccard estimate
    RecordProperty("input_low_overlap_a", "{0..99}");
    RecordProperty("input_low_overlap_b", "{80..179}");
    RecordProperty("input_high_overlap_a", "{0..99}");
    RecordProperty("input_high_overlap_b", "{50..149}");

    std::vector<uint64_t> a1, b1, a2, b2;
    for (uint64_t i = 0; i < 100; i++) a1.push_back(i);
    for (uint64_t i = 80; i < 180; i++) b1.push_back(i);  // 20% overlap
    for (uint64_t i = 0; i < 100; i++) a2.push_back(i);
    for (uint64_t i = 50; i < 150; i++) b2.push_back(i);  // 50% overlap

    auto result_low = engine->Run(a1, b1);
    auto result_high = engine->Run(a2, b2);

    RecordProperty("output_low_overlap_J", std::to_string(result_low.jaccard_estimate));
    RecordProperty("output_high_overlap_J", std::to_string(result_high.jaccard_estimate));

    EXPECT_LT(result_low.jaccard_estimate, result_high.jaccard_estimate)
        << "Higher overlap should produce higher Jaccard estimate";
}

TEST_F(PiccardEngineTest, SingleElementIdenticalSets) {
    // Extreme case: single-element identical sets
    RecordProperty("input_set", "{42}");
    RecordProperty("expected_jaccard", "1.0");

    std::vector<uint64_t> set = {42};
    auto result = engine->Run(set, set);

    RecordProperty("output_match_count", std::to_string(result.match_count));
    RecordProperty("output_jaccard_estimate", std::to_string(result.jaccard_estimate));

    EXPECT_EQ(result.match_count, static_cast<int64_t>(params.k));
    EXPECT_NEAR(result.jaccard_estimate, 1.0, 0.01);
}

#ifdef PICCARD_GROWN_RING_FIXTURE
TEST(PiccardGrownRing, OneHotUsesRequested8192AndRuntime16384) {
    PiccardParams params;
    params.k = 128;
    params.m = 64;
    params.security = SecurityLevel::TOY;
    params.Validate();

    ASSERT_EQ(params.RequestedRingDim(), 8192u);
    ASSERT_EQ(params.SelectedCalibratedRingDim(), 16384u);
    ASSERT_EQ(params.CoefficientStatBits(), 74u);

    Piccard engine(params);
    engine.KeyGen();

    EXPECT_EQ(engine.GetParams().RequestedRingDim(), 8192u);
    EXPECT_EQ(engine.GetParams().SelectedCalibratedRingDim(), 16384u);
    EXPECT_EQ(engine.GetParams().ring_dim, 16384u);
    EXPECT_EQ(engine.GetBFVContext().GetSlotCount(), 16384u);
    EXPECT_EQ(engine.GetParams().FloodNoiseBits(), 144u);
    RecordProperty("input_requested_ring_dim", 8192);
    RecordProperty("output_selected_calibrated_ring_dim", 16384);
    RecordProperty("output_runtime_ring_dim",
                   static_cast<int>(engine.GetBFVContext().GetSlotCount()));
    RecordProperty("output_flood_noise_bits",
                   static_cast<int>(engine.GetParams().FloodNoiseBits()));

    const std::vector<uint64_t> set = {1, 2, 3, 5, 8, 13};
    auto signature = engine.ComputeSignature(set);
    auto feature = engine.EncodeSignature(signature);
    ASSERT_EQ(feature.size(), 16384u);
    RecordProperty("output_encoded_slots", static_cast<int>(feature.size()));
    auto ct = engine.EncryptFeature(feature);
    EXPECT_EQ(engine.Decrypt(engine.Evaluate(ct, ct)).match_count,
              static_cast<int64_t>(params.k));

    auto& mutated = const_cast<PiccardParams&>(engine.GetParams());
    mutated.ring_dim = 8192;
    EXPECT_THROW(mutated.FloodNoiseBits(), std::logic_error);
}
#endif
