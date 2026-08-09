#include <gtest/gtest.h>
#include "fhe/bfv_context.h"
#include "util/params.h"
#include "util/params_calibration.h"
#include "core/threshold_poly.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "version.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

using namespace piccard;

class BFVContextTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 16;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.Validate();

        ctx = std::make_unique<BFVContext>(params);
        ctx->Initialize();
    }

    PiccardParams params;
    std::unique_ptr<BFVContext> ctx;
};

namespace {

double TowerSumLogQBits(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context) {
    double log_q_bits = 0.0;
    const auto towers =
        context->GetCryptoParameters()->GetElementParams()->GetParams();
    for (const auto& tower : towers) {
        log_q_bits += std::log2(tower->GetModulus().ConvertToDouble());
    }
    return log_q_bits;
}

struct MeasuredSelection {
    PiccardParams params;
    PreThresholdCalibrationRow row;
};

MeasuredSelection BuildMeasuredSelection(uint32_t calibrated_ring_dim) {
    PiccardParams profile;
    CalibrationAccess::Derive(profile);

    PiccardParams measurement = profile;
    measurement.ring_dim = calibrated_ring_dim;
    measurement.mult_depth = 2;
    measurement.scaling_mod_size = 40;
    BFVContext discovery(measurement);
    discovery.Initialize();

    const auto& cc = discovery.GetCryptoContext();
    const auto crypto_params = cc->GetCryptoParameters();
    const auto elem_params = crypto_params->GetElementParams();
    const double log_q = TowerSumLogQBits(cc);
    const double log_delta =
        log_q -
        std::log2(static_cast<double>(
            crypto_params->GetPlaintextModulus()));
    const uint32_t actual_ring_dim = cc->GetRingDimension();
    if (actual_ring_dim != calibrated_ring_dim) {
        throw std::runtime_error(
            "test fixture OpenFHE did not realize requested synthetic N");
    }

    const PreThresholdCalibrationRequest request{
        "primary40",
        Circuit::OneHot,
        "onehot-v1",
        SecurityLevel::STD128,
        profile.ring_dim,
        profile.natural_mult_depth,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        GetOPENFHEVersion(),
    };
    const uint32_t coefficient_stat_bits =
        calibrated_ring_dim == 8192 ? 73u : 74u;
    PreThresholdCalibrationRow row{
        request,
        8192,
        calibrated_ring_dim,
        measurement.mult_depth,
        measurement.scaling_mod_size,
        static_cast<uint32_t>(elem_params->GetParams().size()),
        crypto_params->GetPlaintextModulus(),
        log_q,
        log_delta,
        1,
        4096,
        40,
        UINT64_C(1) << 20,
        60,
        coefficient_stat_bits,
        8,
        1u + coefficient_stat_bits + 8u,
    };
    PiccardParams selected =
        SelectPreThresholdCalibration(profile, request, {row});
    return {std::move(selected), std::move(row)};
}

struct ContextOnlyFailure {
    bool is_invalid_argument = false;
    std::string message;
};

ContextOnlyFailure CaptureContextOnlyFailure(BFVContext* context) {
    try {
        context->InitializeContextOnly();
    } catch (const std::invalid_argument& error) {
        return {true, error.what()};
    } catch (const std::exception& error) {
        return {false, error.what()};
    }
    return {};
}

}  // namespace

TEST_F(BFVContextTest, EncryptDecryptRoundTrip) {
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 1;
    values[1] = 0;
    values[2] = 1;
    values[3] = 0;
    values[4] = 1;
    RecordProperty("input_slots_0_4", "[1, 0, 1, 0, 1]");
    RecordProperty("input_ring_dim", static_cast<int>(params.ring_dim));

    auto ct = ctx->Encrypt(values);
    auto result = ctx->Decrypt(ct);

    RecordProperty("output_slots_0_4",
                   "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + ", " +
                   std::to_string(result[2]) + ", " +
                   std::to_string(result[3]) + ", " +
                   std::to_string(result[4]) + "]");

    for (uint32_t i = 0; i < params.ring_dim; i++) {
        EXPECT_EQ(result[i], values[i]) << "Slot " << i;
    }
}

TEST_F(BFVContextTest, SlotWiseMultiply) {
    std::vector<int64_t> a(params.ring_dim, 0);
    std::vector<int64_t> b(params.ring_dim, 0);
    a[0] = 1; a[1] = 0; a[2] = 1;
    b[0] = 1; b[1] = 1; b[2] = 0;
    RecordProperty("input_a", "[1, 0, 1, ...]");
    RecordProperty("input_b", "[1, 1, 0, ...]");

    auto ct_a = ctx->Encrypt(a);
    auto ct_b = ctx->Encrypt(b);
    auto ct_prod = ctx->Multiply(ct_a, ct_b);
    auto result = ctx->Decrypt(ct_prod);

    RecordProperty("output_product_0_2",
                   "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + ", " +
                   std::to_string(result[2]) + "]");

    EXPECT_EQ(result[0], 1);  // 1*1
    EXPECT_EQ(result[1], 0);  // 0*1
    EXPECT_EQ(result[2], 0);  // 1*0
}

TEST_F(BFVContextTest, Addition) {
    std::vector<int64_t> a(params.ring_dim, 0);
    std::vector<int64_t> b(params.ring_dim, 0);
    a[0] = 3; a[1] = 5;
    b[0] = 7; b[1] = 2;
    RecordProperty("input_a", "[3, 5, ...]");
    RecordProperty("input_b", "[7, 2, ...]");

    auto ct_a = ctx->Encrypt(a);
    auto ct_b = ctx->Encrypt(b);
    auto ct_sum = ctx->Add(ct_a, ct_b);
    auto result = ctx->Decrypt(ct_sum);

    RecordProperty("output_sum_0_1",
                   "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + "]");

    EXPECT_EQ(result[0], 10);
    EXPECT_EQ(result[1], 7);
}

TEST(BFVContextRuntimeMetadata, ToyRuntimeMetadataMatchesLiveContext) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    BFVContext context(params);
    context.InitializeContextOnly();

    const auto metadata = context.GetRuntimeMetadata();
    const auto& live = context.GetCryptoContext();
    const auto crypto_params = live->GetCryptoParameters();
    const auto rns_params =
        std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(
            crypto_params);
    ASSERT_TRUE(rns_params);
    EXPECT_EQ(metadata.actual_ring_dim, live->GetRingDimension());
    EXPECT_NEAR(metadata.log_q_bits, TowerSumLogQBits(live), 1e-9);
    EXPECT_EQ(metadata.plaintext_modulus,
              crypto_params->GetPlaintextModulus());
    EXPECT_EQ(metadata.num_limbs,
              crypto_params->GetElementParams()->GetParams().size());
    EXPECT_EQ(metadata.provisioned_depth,
              rns_params->GetMultiplicativeDepth());
    EXPECT_GT(metadata.scaling_mod_size, 0u);
    EXPECT_EQ(metadata.ordered_rns_moduli.size(), metadata.num_limbs);
    EXPECT_EQ(metadata.security, SecurityLevel::TOY);
    EXPECT_EQ(metadata.requested_ring_dim, params.ring_dim);
    EXPECT_EQ(metadata.natural_depth, params.natural_mult_depth);
    EXPECT_EQ(metadata.openfhe_version, GetOPENFHEVersion());
    EXPECT_NE(metadata.openfhe_version, "unknown");
    EXPECT_EQ(context.ContextFingerprintHex(), context.ContextFingerprintHex());
    EXPECT_EQ(metadata.context_fingerprint, context.ContextFingerprintHex());
    EXPECT_EQ(metadata.context_fingerprint.size(), 64u);
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}

TEST(BFVContextRuntimeMetadata, ContextOnlyFingerprintAndLiveTupleFieldsAreStable) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    BFVContext first(params);
    BFVContext second(params);
    EXPECT_THROW(first.ContextFingerprintHex(), std::logic_error);

    first.InitializeContextOnly();
    second.InitializeContextOnly();
    EXPECT_EQ(first.ContextFingerprintHex(), second.ContextFingerprintHex());

    const auto metadata = first.GetRuntimeMetadata();
    EXPECT_EQ(metadata.context_fingerprint, first.ContextFingerprintHex());
    EXPECT_EQ(metadata.context_fingerprint, second.ContextFingerprintHex());
    ASSERT_EQ(metadata.ordered_rns_moduli.size(), metadata.num_limbs);
    for (const auto& modulus : metadata.ordered_rns_moduli) {
        EXPECT_FALSE(modulus.empty());
    }
    EXPECT_FALSE(first.HasGeneratedKeysForTesting());
}

TEST(BFVContextRuntimeMetadata, StandardSecurityContextsNeverShareFingerprint) {
    PiccardParams std128_params;
    std128_params.k = 16;
    std128_params.m = 16;
    std128_params.security = SecurityLevel::STD128;
    CalibrationAccess::Derive(std128_params);
    PiccardParams std192_params = std128_params;
    std192_params.security = SecurityLevel::STD192;
    CalibrationAccess::Derive(std192_params);

    BFVContext std128(std128_params);
    BFVContext std192(std192_params);
    std128.InitializeContextOnly();
    std192.InitializeContextOnly();
    EXPECT_NE(std128.ContextFingerprintHex(), std192.ContextFingerprintHex());
    EXPECT_EQ(std128.GetRuntimeMetadata().security, SecurityLevel::STD128);
    EXPECT_EQ(std192.GetRuntimeMetadata().security, SecurityLevel::STD192);
    EXPECT_FALSE(std128.HasGeneratedKeysForTesting());
    EXPECT_FALSE(std192.HasGeneratedKeysForTesting());
}

TEST(BFVContextRuntimeMetadata, CalibratedStd128MetadataMatchesLiveContext) {
    PiccardParams params;
    params.k = 128;
    params.m = 64;
    params.security = SecurityLevel::STD128;
    params.Validate();

    BFVContext context(params);
    context.InitializeContextOnly();

    const auto metadata = context.GetRuntimeMetadata();
    const auto& live = context.GetCryptoContext();
    EXPECT_EQ(metadata.actual_ring_dim, live->GetRingDimension());
    EXPECT_NEAR(metadata.log_q_bits, TowerSumLogQBits(live), 1e-9);
    EXPECT_GT(metadata.actual_ring_dim, 0u);
    EXPECT_GT(metadata.log_q_bits, 0.0);
    EXPECT_GT(metadata.plaintext_modulus, 0u);
    EXPECT_GT(metadata.num_limbs, 0u);
}

TEST_F(BFVContextTest, Rotation) {
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 1;
    values[1] = 2;
    values[2] = 3;
    values[3] = 4;
    RecordProperty("input_slots_0_3", "[1, 2, 3, 4]");
    RecordProperty("input_rotation_steps", 1);

    auto ct = ctx->Encrypt(values);
    auto ct_rot = ctx->Rotate(ct, 1);
    auto result = ctx->Decrypt(ct_rot);

    RecordProperty("output_slots_0_2",
                   "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + ", " +
                   std::to_string(result[2]) + "]");

    EXPECT_EQ(result[0], 2);
    EXPECT_EQ(result[1], 3);
    EXPECT_EQ(result[2], 4);
}

TEST_F(BFVContextTest, RotateAndSumSmall) {
    std::vector<int64_t> values(params.ring_dim, 0);
    for (int i = 0; i < 8; i++) values[i] = 1;
    RecordProperty("input_ones_count", 8);
    RecordProperty("input_ring_dim", static_cast<int>(params.ring_dim));

    auto ct = ctx->Encrypt(values);

    auto result_ct = ct;
    for (uint32_t step = 1; step < params.ring_dim; step *= 2) {
        auto rotated = ctx->Rotate(result_ct, static_cast<int>(step));
        result_ct = ctx->Add(result_ct, rotated);
    }

    auto result = ctx->Decrypt(result_ct);
    RecordProperty("output_slot_0", std::to_string(result[0]));

    EXPECT_EQ(result[0], 8);
}

// --- Tests for plaintext operations ---

TEST_F(BFVContextTest, MultiplyPlainElementWise) {
    RecordProperty("input_ct", "[3, 5, 7, 0, ...]");
    RecordProperty("input_pt", "[2, 3, 4, 0, ...]");
    RecordProperty("expected_output", "[6, 15, 28, 0, ...]");

    std::vector<int64_t> a(params.ring_dim, 0);
    std::vector<int64_t> b(params.ring_dim, 0);
    a[0] = 3; a[1] = 5; a[2] = 7;
    b[0] = 2; b[1] = 3; b[2] = 4;

    auto ct = ctx->Encrypt(a);
    auto result_ct = ctx->MultiplyPlain(ct, b);
    auto result = ctx->Decrypt(result_ct);

    RecordProperty("output", "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + ", " + std::to_string(result[2]) + "]");

    EXPECT_EQ(result[0], 6);   // 3*2
    EXPECT_EQ(result[1], 15);  // 5*3
    EXPECT_EQ(result[2], 28);  // 7*4
}

TEST_F(BFVContextTest, MultiplyScalarAll) {
    RecordProperty("input_ct", "[3, 5, 7, 0, ...]");
    RecordProperty("input_scalar", "4");
    RecordProperty("expected_output", "[12, 20, 28, 0, ...]");

    std::vector<int64_t> a(params.ring_dim, 0);
    a[0] = 3; a[1] = 5; a[2] = 7;

    auto ct = ctx->Encrypt(a);
    auto result_ct = ctx->MultiplyScalar(ct, 4);
    auto result = ctx->Decrypt(result_ct);

    RecordProperty("output", "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + ", " + std::to_string(result[2]) + "]");

    EXPECT_EQ(result[0], 12);  // 3*4
    EXPECT_EQ(result[1], 20);  // 5*4
    EXPECT_EQ(result[2], 28);  // 7*4
}

TEST_F(BFVContextTest, AddPlainElementWise) {
    RecordProperty("input_ct", "[10, 20, 0, ...]");
    RecordProperty("input_pt", "[3, 7, 0, ...]");
    RecordProperty("expected_output", "[13, 27, 0, ...]");

    std::vector<int64_t> a(params.ring_dim, 0);
    std::vector<int64_t> b(params.ring_dim, 0);
    a[0] = 10; a[1] = 20;
    b[0] = 3; b[1] = 7;

    auto ct = ctx->Encrypt(a);
    auto result_ct = ctx->AddPlain(ct, b);
    auto result = ctx->Decrypt(result_ct);

    RecordProperty("output", "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + "]");

    EXPECT_EQ(result[0], 13);  // 10+3
    EXPECT_EQ(result[1], 27);  // 20+7
}

// --- Polynomial evaluation tests (need higher mult_depth) ---

class BFVContextPolyTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 16;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.threshold_mode = true;
        params.threshold_tau = 2;
        params.Validate();

        ctx = std::make_unique<BFVContext>(params);
        ctx->Initialize();
    }

    PiccardParams params;
    std::unique_ptr<BFVContext> ctx;
};

TEST_F(BFVContextPolyTest, EvalPolyConstant) {
    // P(x) = 42, evaluated at x = 5
    RecordProperty("input_poly", "P(x) = 42");
    RecordProperty("input_x", "5");
    RecordProperty("expected_output", "42");

    std::vector<int64_t> coeffs = {42};
    std::vector<int64_t> input(params.ring_dim, 5);

    auto ct = ctx->Encrypt(input);
    auto result_ct = ctx->EvalPolyBFV(ct, coeffs);
    auto result = ctx->Decrypt(result_ct);

    RecordProperty("output_slot_0", std::to_string(result[0]));
    EXPECT_EQ(result[0], 42);
}

TEST_F(BFVContextPolyTest, EvalPolyLinear) {
    // P(x) = 3 + 2x, evaluated at x = 5 → 13
    RecordProperty("input_poly", "P(x) = 3 + 2x");
    RecordProperty("input_x", "5");
    RecordProperty("expected_output", "13");

    std::vector<int64_t> coeffs = {3, 2};
    std::vector<int64_t> input(params.ring_dim, 5);

    auto ct = ctx->Encrypt(input);
    auto result_ct = ctx->EvalPolyBFV(ct, coeffs);
    auto result = ctx->Decrypt(result_ct);

    RecordProperty("output_slot_0", std::to_string(result[0]));
    EXPECT_EQ(result[0], 13);  // 3 + 2*5
}

TEST_F(BFVContextPolyTest, EvalPolyThreshold) {
    // Threshold polynomial u_{tau=2}(x) for x in [0..4]
    // u(0)=0, u(1)=0, u(2)=1, u(3)=1, u(4)=1
    RecordProperty("input_poly", "u_{tau=2}(x), degree 4");
    RecordProperty("expected_outputs", "[0, 0, 1, 1, 1]");

    auto poly = BuildThresholdPoly(2, 4, params.plaintext_mod);

    for (int64_t x = 0; x <= 4; x++) {
        std::vector<int64_t> input(params.ring_dim, x);
        auto ct = ctx->Encrypt(input);
        auto result_ct = ctx->EvalPolyBFV(ct, poly);
        auto result = ctx->Decrypt(result_ct);

        int64_t expected = (x >= 2) ? 1 : 0;
        RecordProperty("output_u(" + std::to_string(x) + ")",
                       std::to_string(result[0]));
        EXPECT_EQ(result[0], expected)
            << "u_2(" << x << ") = " << result[0] << ", expected " << expected;
    }
}

TEST_F(BFVContextPolyTest, EvalPolyQuadratic) {
    // P(x) = 1 + 3x + 2x^2, evaluated at x = 4
    // P(4) = 1 + 12 + 32 = 45
    RecordProperty("input_poly", "P(x) = 1 + 3x + 2x^2");
    RecordProperty("input_x", "4");
    RecordProperty("expected_output", "45");

    std::vector<int64_t> coeffs = {1, 3, 2};
    std::vector<int64_t> input(params.ring_dim, 4);

    auto ct = ctx->Encrypt(input);
    auto result_ct = ctx->EvalPolyBFV(ct, coeffs);
    auto result = ctx->Decrypt(result_ct);

    RecordProperty("output_slot_0", std::to_string(result[0]));

    EXPECT_EQ(result[0], 45);  // 1 + 3*4 + 2*16
}

TEST_F(BFVContextTest, ChainedMultiplyThenAdd) {
    // (a * b) + c should work correctly
    RecordProperty("input_a", "[2, 3, 0, ...]");
    RecordProperty("input_b", "[5, 4, 0, ...]");
    RecordProperty("input_c", "[1, 1, 0, ...]");
    RecordProperty("expected", "[11, 13, 0, ...]");

    std::vector<int64_t> a(params.ring_dim, 0), b(params.ring_dim, 0),
                          c(params.ring_dim, 0);
    a[0] = 2; a[1] = 3;
    b[0] = 5; b[1] = 4;
    c[0] = 1; c[1] = 1;

    auto ct_a = ctx->Encrypt(a);
    auto ct_b = ctx->Encrypt(b);
    auto ct_c = ctx->Encrypt(c);

    auto ct_prod = ctx->Multiply(ct_a, ct_b);
    auto ct_result = ctx->Add(ct_prod, ct_c);
    auto result = ctx->Decrypt(ct_result);

    RecordProperty("output", "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + "]");

    EXPECT_EQ(result[0], 11);  // 2*5 + 1
    EXPECT_EQ(result[1], 13);  // 3*4 + 1
}

TEST_F(BFVContextTest, MultiplyPlainByZero) {
    // Multiplying by all-zero plaintext should give all zeros
    RecordProperty("input_ct", "[3, 5, 7, 0, ...]");
    RecordProperty("input_pt", "[0, 0, 0, ...]");
    RecordProperty("expected", "[0, 0, 0, ...]");

    std::vector<int64_t> a(params.ring_dim, 0);
    a[0] = 3; a[1] = 5; a[2] = 7;
    std::vector<int64_t> zero(params.ring_dim, 0);

    auto ct = ctx->Encrypt(a);
    auto result_ct = ctx->MultiplyPlain(ct, zero);
    auto result = ctx->Decrypt(result_ct);

    RecordProperty("output", "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + ", " + std::to_string(result[2]) + "]");

    EXPECT_EQ(result[0], 0);
    EXPECT_EQ(result[1], 0);
    EXPECT_EQ(result[2], 0);
}

TEST_F(BFVContextTest, FloodPreservesPlaintext) {
    // Flooding must be invisible to the receiver's decryption: the whole point
    // is that it hides the evaluation noise without disturbing the message.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 7;
    values[1] = 3;
    RecordProperty("input_slots_0_1", "[7, 3]");
    RecordProperty("input_flood_noise_bits",
                   static_cast<int>(params.FloodNoiseBits()));

    auto ct = ctx->Encrypt(values);
    auto flooded = ctx->Flood(ct);
    auto result = ctx->Decrypt(flooded);

    RecordProperty("output_slots_0_1",
                   "[" + std::to_string(result[0]) + ", " +
                   std::to_string(result[1]) + "]");

    EXPECT_EQ(result[0], 7);
    EXPECT_EQ(result[1], 3);
}

TEST_F(BFVContextTest, FloodDoesNotMutateInput) {
    // Flood() must return a new ciphertext. If it aliased its argument, a
    // caller that floods an intermediate would silently corrupt the value it
    // still intends to compute on.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 5;

    auto ct = ctx->Encrypt(values);
    auto before = ctx->Decrypt(ct);
    auto flooded = ctx->Flood(ct);
    auto after = ctx->Decrypt(ct);

    RecordProperty("input_slot_0", 5);
    RecordProperty("output_original_slot_0", static_cast<int>(after[0]));
    EXPECT_EQ(before[0], after[0]);
    EXPECT_EQ(after[0], 5);
    EXPECT_NE(flooded.get(), ct.get());
}

TEST_F(BFVContextTest, FloodIsRandomised) {
    // A serializer observes the complete released ciphertext, not just c0.
    // Two floods of the same raw ciphertext must therefore serialize
    // differently.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 1;

    auto ct = ctx->Encrypt(values);
    auto a = ctx->Flood(ct);
    auto b = ctx->Flood(ct);

    std::ostringstream serialized_a;
    std::ostringstream serialized_b;
    lbcrypto::Serial::Serialize(a, serialized_a, lbcrypto::SerType::BINARY);
    lbcrypto::Serial::Serialize(b, serialized_b, lbcrypto::SerType::BINARY);

    RecordProperty("output_two_floods_differ", "true");
    EXPECT_NE(serialized_a.str(), serialized_b.str());
}

TEST_F(BFVContextTest, FloodMaskIsTheCalibratedSize) {
    // The three tests above all pass if Flood() added a ONE-BIT mask: they
    // check the plaintext survives, that the input is untouched, and that two
    // draws differ. None pins the magnitude -- and a mask smaller than the
    // evaluation noise leaves the phase distinguishable while the ciphertext
    // still decrypts, so no other signal would ever show it.
    //
    // Measure the decryption noise the way the calibration harness does:
    // ||(c0 + c1*s) - Delta*m||_inf, via CRT interpolation.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 1;

    auto ct = ctx->Encrypt(values);
    auto flooded = ctx->Flood(ct);

    const auto& sk = ctx->GetSecretKeyForCalibration();
    auto cc = ctx->GetCryptoContext();
    auto elem_params = cc->GetCryptoParameters()->GetElementParams();
    lbcrypto::BigInteger Q = elem_params->GetModulus();
    uint64_t t = cc->GetCryptoParameters()->GetPlaintextModulus();

    lbcrypto::DCRTPoly s = sk->GetPrivateElement();
    const auto& c = flooded->GetElements();
    lbcrypto::DCRTPoly b = c[0];
    lbcrypto::DCRTPoly s_pow = s;
    for (size_t i = 1; i < c.size(); i++) {
        b += c[i] * s_pow;
        s_pow *= s;
    }
    b.SetFormat(Format::COEFFICIENT);
    auto big = b.CRTInterpolate();

    const lbcrypto::BigInteger delta = Q / lbcrypto::BigInteger(t);
    const lbcrypto::BigInteger q_half = Q >> 1;
    const lbcrypto::BigInteger delta_half = delta >> 1;
    double worst = 0.0;
    for (uint32_t j = 0; j < big.GetLength(); j++) {
        lbcrypto::BigInteger v = big[j];
        lbcrypto::BigInteger abs_v = (v > q_half) ? (Q - v) : v;
        lbcrypto::BigInteger r = abs_v % delta;
        lbcrypto::BigInteger d = (r > delta_half) ? (delta - r) : r;
        double dd = d.ConvertToDouble();
        if (dd > worst) worst = dd;
    }
    double measured_bits = std::log2(worst);
    double expected_bits = static_cast<double>(params.FloodNoiseBits());

    RecordProperty("input_expected_flood_bits", static_cast<int>(expected_bits));
    RecordProperty("output_measured_noise_bits",
                   static_cast<int>(measured_bits));

    // The derived transcript-aware coefficient target and empirical margin
    // make the sampled mask dominate the calibrated evaluation noise, so the
    // measured maximum sits at the derived mask magnitude to within a bit.
    EXPECT_GE(measured_bits, expected_bits - 1.0);
    EXPECT_LE(measured_bits, expected_bits + 1.0);
}

TEST_F(BFVContextTest, RuntimeRingDimensionIsAdoptedBeforeUse) {
    EXPECT_EQ(ctx->GetSlotCount(), ctx->GetParams().ring_dim);
    EXPECT_EQ(ctx->GetParams().RequestedRingDim(), params.RequestedRingDim());
    EXPECT_NO_THROW(ctx->GetParams().FloodNoiseBits());

    PiccardParams already_adopted = ctx->GetParams();
    EXPECT_THROW(
        already_adopted.AdoptVerifiedRuntimeRingDim(ctx->GetSlotCount()),
        std::logic_error);
}

TEST_F(BFVContextTest, UnsizedContextInitializesButFloodRejects) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    CalibrationAccess::Derive(params);
    ASSERT_FALSE(params.FloodingSized());

    BFVContext ctx(params);
    ASSERT_NO_THROW(ctx.Initialize());
    EXPECT_EQ(ctx.GetSlotCount(), ctx.GetParams().ring_dim);
    EXPECT_FALSE(ctx.GetParams().FloodingSized());

    std::vector<int64_t> values(ctx.GetSlotCount(), 0);
    auto ct = ctx.Encrypt(values);
    EXPECT_THROW(ctx.Flood(ct), std::logic_error);
}

TEST(BFVContextPreThreshold, ReproducesNormalAndGrownMeasuredContracts) {
    for (uint32_t calibrated_ring_dim : {8192u, 16384u}) {
        SCOPED_TRACE(calibrated_ring_dim);
        MeasuredSelection measured =
            BuildMeasuredSelection(calibrated_ring_dim);
        BFVContext context(measured.params);
        ASSERT_NO_THROW(context.Initialize());

        const auto& live = context.GetCryptoContext();
        const auto crypto_params = live->GetCryptoParameters();
        const auto elem_params = crypto_params->GetElementParams();
        const double live_log_q = TowerSumLogQBits(live);
        const double live_log_delta =
            live_log_q -
            std::log2(static_cast<double>(
                crypto_params->GetPlaintextModulus()));

        EXPECT_EQ(context.GetSlotCount(), calibrated_ring_dim);
        EXPECT_EQ(
            context.GetParams().RequestedRingDim(),
            measured.row.key.requested_ring_dim);
        EXPECT_EQ(
            context.GetParams().ring_dim_natural,
            measured.row.natural_ring_dim);
        EXPECT_EQ(
            context.GetParams().SelectedCalibratedRingDim(),
            measured.row.ring_dim_calibrated);
        const auto bfv_crypto_params = std::dynamic_pointer_cast<
            lbcrypto::CryptoParametersBFVRNS>(crypto_params);
        ASSERT_TRUE(bfv_crypto_params);
        EXPECT_EQ(
            bfv_crypto_params->GetMultiplicativeDepth(),
            measured.row.provisioned_depth);
        EXPECT_EQ(
            context.GetParams().scaling_mod_size,
            measured.row.scaling_mod_size);
        EXPECT_EQ(
            crypto_params->GetPlaintextModulus(),
            measured.row.plaintext_mod);
        EXPECT_EQ(
            elem_params->GetParams().size(),
            measured.row.num_limbs);
        EXPECT_NEAR(live_log_q, measured.row.log_q, 1e-9);
        EXPECT_NEAR(live_log_delta, measured.row.log_delta, 1e-9);
        EXPECT_EQ(
            context.RequiredFloodBudgetBits(),
            measured.row.flood_noise_bits + 2u);
        EXPECT_TRUE(context.HasGeneratedKeysForTesting());

        const std::string diagnostics =
            context.CalibrationRingDiagnostics();
        EXPECT_NE(diagnostics.find("requested N=8192"), std::string::npos);
        EXPECT_NE(diagnostics.find("natural N=8192"), std::string::npos);
        EXPECT_NE(
            diagnostics.find(
                "calibrated N=" +
                std::to_string(calibrated_ring_dim)),
            std::string::npos);
        EXPECT_NE(
            diagnostics.find(
                "realized N=" +
                std::to_string(calibrated_ring_dim)),
            std::string::npos);
    }
}

TEST(BFVContextPreThreshold, ContextOnlyInitializationGeneratesNoKeys) {
    PiccardParams params;
    params.k = 128;
    params.m = 64;
    params.security = SecurityLevel::STD128;
    CalibrationAccess::Derive(params);

    BFVContext context(params);
    ASSERT_NO_THROW(context.InitializeContextOnly());
    EXPECT_TRUE(context.GetCryptoContext());
    EXPECT_EQ(context.GetSlotCount(), 8192u);
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}

TEST(BFVContextPreThreshold, RejectsPlaintextModulusNotGreaterThanKBeforeOpenFHE) {
    PiccardParams invalid;
    invalid.k = 16;
    invalid.m = 8;
    invalid.security = SecurityLevel::TOY;
    CalibrationAccess::Derive(invalid);
    ASSERT_EQ(invalid.ring_dim, 1024u);
    invalid.k = 65537;
    invalid.plaintext_mod = 65537;
    ASSERT_EQ(invalid.plaintext_mod, invalid.k);
    ASSERT_TRUE(IsPrime(invalid.plaintext_mod));
    ASSERT_EQ(
        (invalid.plaintext_mod - 1) %
            (UINT64_C(2) * invalid.ring_dim),
        0u);

    BFVContext context(invalid);
    const ContextOnlyFailure failure =
        CaptureContextOnlyFailure(&context);

    EXPECT_TRUE(failure.is_invalid_argument);
    EXPECT_NE(
        failure.message.find(
            "planned packed plaintext parameters are incompatible before "
            "OpenFHE"),
        std::string::npos);
    EXPECT_NE(failure.message.find("p=65537"), std::string::npos);
    EXPECT_NE(failure.message.find("k=65537"), std::string::npos);
    EXPECT_FALSE(context.GetCryptoContext());
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}

TEST(BFVContextPreThreshold, RejectsCompositeCongruentPlaintextModulusBeforeOpenFHE) {
    PiccardParams invalid;
    invalid.k = 16;
    invalid.m = 8;
    invalid.security = SecurityLevel::TOY;
    CalibrationAccess::Derive(invalid);
    ASSERT_EQ(invalid.ring_dim, 1024u);
    invalid.plaintext_mod = 2049;
    ASSERT_GT(invalid.plaintext_mod, invalid.k);
    ASSERT_FALSE(IsPrime(invalid.plaintext_mod));
    ASSERT_EQ(
        (invalid.plaintext_mod - 1) %
            (UINT64_C(2) * invalid.ring_dim),
        0u);

    BFVContext context(invalid);
    const ContextOnlyFailure failure =
        CaptureContextOnlyFailure(&context);

    EXPECT_TRUE(failure.is_invalid_argument);
    EXPECT_NE(
        failure.message.find(
            "planned packed plaintext parameters are incompatible before "
            "OpenFHE"),
        std::string::npos);
    EXPECT_NE(failure.message.find("p=2049"), std::string::npos);
    EXPECT_FALSE(context.GetCryptoContext());
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}

TEST(BFVContextPreThreshold, RejectsPlannedRingIncompatiblePlaintextModulusBeforeOpenFHE) {
    PiccardParams incompatible;
    incompatible.k = 32;
    incompatible.m = 64;
    incompatible.security = SecurityLevel::TOY;
    CalibrationAccess::Derive(incompatible);
    ASSERT_EQ(incompatible.ring_dim, 2048u);
    ASSERT_EQ(incompatible.plaintext_mod, 12289u);
    ASSERT_NE(
        (incompatible.plaintext_mod - 1) %
            (UINT64_C(2) * 4096),
        0u);

    incompatible.ring_dim = 4096;
    BFVContext context(incompatible);
    const ContextOnlyFailure failure =
        CaptureContextOnlyFailure(&context);

    EXPECT_TRUE(failure.is_invalid_argument);
    EXPECT_NE(
        failure.message.find(
            "planned packed plaintext parameters are incompatible before "
            "OpenFHE"),
        std::string::npos);
    EXPECT_NE(failure.message.find("p=12289"), std::string::npos);
    EXPECT_NE(failure.message.find("N=4096"), std::string::npos);
    EXPECT_FALSE(context.GetCryptoContext());
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}

TEST(BFVContextPreThreshold,
     RejectsRealizedStandardSecurityRingIncompatibilityBeforeKeysOrAdoption) {
    PiccardParams profile;
    profile.k = 128;
    profile.m = 64;
    profile.security = SecurityLevel::STD128;
    CalibrationAccess::Derive(profile);
    ASSERT_EQ(profile.ring_dim, 8192u);
    ASSERT_EQ(profile.plaintext_mod, 65537u);
    profile.transcript_stat_bits = 40;
    profile.max_queries = 1;
    profile.flood_margin_bits = 0;

    PiccardParams selected = SelectSanitizerCandidate(
        profile,
        CalibrationCandidate{
            Circuit::OneHot,
            SecurityLevel::STD128,
            8192,
            8192,
            32768,
            1,
            23,
            60,
            0,
            1.0e9,
        });
    ASSERT_EQ(selected.SelectedCalibratedRingDim(), 32768u);
    ASSERT_EQ(selected.plaintext_mod, 65537u);
    ASSERT_EQ(selected.mult_depth, 23u);
    ASSERT_EQ(selected.scaling_mod_size, 60u);
    ASSERT_EQ(
        (selected.plaintext_mod - 1) %
            (UINT64_C(2) * selected.SelectedCalibratedRingDim()),
        0u);

    BFVContext context(selected);
    const ContextOnlyFailure failure =
        CaptureContextOnlyFailure(&context);

    EXPECT_TRUE(failure.is_invalid_argument);
    EXPECT_EQ(
        failure.message,
        "realized packed plaintext parameters are incompatible before "
        "OpenFHE: p=65537, k=128, N=65536, 2N=131072; require prime "
        "p > k and (p - 1) % (2N) == 0");
    ASSERT_TRUE(context.GetCryptoContext());
    EXPECT_EQ(context.GetSlotCount(), 65536u);
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
    EXPECT_EQ(context.GetParams().ring_dim, 8192u);
    EXPECT_EQ(context.GetParams().SelectedCalibratedRingDim(), 32768u);
}

TEST(BFVContextPreThreshold, RejectsStaleOpenFHEVersionBeforeContextOrKeys) {
    MeasuredSelection measured = BuildMeasuredSelection(8192);
    measured.row.key.openfhe_version = "stale-openfhe";
    PreThresholdCalibrationRequest stale_request = measured.row.key;

    PiccardParams profile;
    CalibrationAccess::Derive(profile);
    PiccardParams selected = SelectPreThresholdCalibration(
        profile, stale_request, {measured.row});
    BFVContext context(selected);

    EXPECT_THROW(context.Initialize(), std::invalid_argument);
    EXPECT_FALSE(context.GetCryptoContext());
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}

TEST(BFVContextPreThreshold, RejectsMeasuredFieldMismatchBeforeKeyGeneration) {
    struct Mutation {
        const char* name;
        std::function<void(PreThresholdCalibrationRow&)> apply;
    };
    const Mutation mutations[] = {
        {"num_limbs", [](PreThresholdCalibrationRow& row) {
             ++row.num_limbs;
         }},
        {"log_q_and_log_delta", [](PreThresholdCalibrationRow& row) {
             row.log_q += 1.0;
             row.log_delta += 1.0;
         }},
    };

    for (const auto& mutation : mutations) {
        SCOPED_TRACE(mutation.name);
        MeasuredSelection measured = BuildMeasuredSelection(8192);
        mutation.apply(measured.row);
        PiccardParams profile;
        CalibrationAccess::Derive(profile);
        PiccardParams selected = SelectPreThresholdCalibration(
            profile, measured.row.key, {measured.row});
        BFVContext context(selected);

        EXPECT_THROW(context.Initialize(), std::runtime_error);
        EXPECT_TRUE(context.GetCryptoContext());
        EXPECT_FALSE(context.HasGeneratedKeysForTesting());
    }
}

TEST(BFVContextPreThreshold, RejectsSelectedParameterMutationBeforeContext) {
    MeasuredSelection measured = BuildMeasuredSelection(16384);
    ++measured.params.mult_depth;
    BFVContext context(measured.params);

    EXPECT_THROW(context.Initialize(), std::logic_error);
    EXPECT_FALSE(context.GetCryptoContext());
    EXPECT_FALSE(context.HasGeneratedKeysForTesting());
}

TEST_F(BFVContextTest, SanitizerClaimsUseFixedPocLabels) {
    EXPECT_STREQ(BFVContext::SanitizerModel(),
                 "phase-smudging-enc0-poc-v1");
    EXPECT_STREQ(
        BFVContext::SanitizerAssurance(),
        "empirical-phase-statistical+ciphertext-computational");
}

TEST_F(BFVContextTest, FloodCostIsRecorded) {
    // Not an assertion -- a recorded measurement. bench_noise runs on
    // calibration-derived parameters where FloodNoiseBits() throws, so this
    // fixture is the only place a validated context and Flood() meet.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 1;
    auto ct = ctx->Encrypt(values);

    // Split reference: Flood() re-randomizes with a full Encrypt(zeros) --
    // a packed encode plus a public-key encryption -- before drawing and
    // adding the mask. At large N that re-randomization step may dominate,
    // so the total below alone would misattribute the cost as "flooding
    // noise" when it may be mostly a public-key encryption. Time the two
    // reachable public pieces directly from the test, without instrumenting
    // Flood() itself.
    std::vector<int64_t> zeros(params.ring_dim, 0);
    auto cc = ctx->GetCryptoContext();

    std::vector<double> ms;
    std::vector<double> ms_encrypt_zeros;
    std::vector<double> ms_eval_add;
    for (int i = 0; i < 20; i++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        auto flooded = ctx->Flood(ct);
        auto t1 = std::chrono::high_resolution_clock::now();
        ms.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
        (void)flooded;

        auto e0 = std::chrono::high_resolution_clock::now();
        auto fresh = ctx->Encrypt(zeros);
        auto e1 = std::chrono::high_resolution_clock::now();
        ms_encrypt_zeros.push_back(
            std::chrono::duration<double, std::milli>(e1 - e0).count());

        auto a0 = std::chrono::high_resolution_clock::now();
        auto added = cc->EvalAdd(ct, fresh);
        auto a1 = std::chrono::high_resolution_clock::now();
        ms_eval_add.push_back(
            std::chrono::duration<double, std::milli>(a1 - a0).count());
        (void)added;
    }
    std::sort(ms.begin(), ms.end());
    std::sort(ms_encrypt_zeros.begin(), ms_encrypt_zeros.end());
    std::sort(ms_eval_add.begin(), ms_eval_add.end());

    RecordProperty("input_ring_dim", static_cast<int>(params.ring_dim));
    RecordProperty("input_flood_noise_bits",
                   static_cast<int>(params.FloodNoiseBits()));
    RecordProperty("output_flood_median_us",
                   static_cast<int>(ms[ms.size() / 2] * 1000.0));
    RecordProperty("output_encrypt_zeros_median_us",
                   static_cast<int>(
                       ms_encrypt_zeros[ms_encrypt_zeros.size() / 2] * 1000.0));
    RecordProperty("output_eval_add_median_us",
                   static_cast<int>(
                       ms_eval_add[ms_eval_add.size() / 2] * 1000.0));
    SUCCEED();
}

TEST(BFVContextBudget, RejectsMutatedProfileBeforeRuntimeBudget) {
    // A caller cannot bypass the runtime check by changing a calibrated term.
    // Runtime adoption must revalidate the Phase 2 fingerprint first.
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    RecordProperty("input_calibrated_eval_noise_bits",
                   static_cast<int>(params.eval_noise_bits));
    params.eval_noise_bits = 10000;
    RecordProperty("input_forced_eval_noise_bits", 10000);

    BFVContext ctx(params);
    EXPECT_THROW(ctx.Initialize(), std::logic_error);
}

TEST(BFVContextBudget, AcceptsCalibratedParameters) {
    // The parameters Validate() selects must pass the check it predicted.
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    RecordProperty(
        "input_coefficient_stat_bits",
        static_cast<int>(params.CoefficientStatBits()));
    BFVContext ctx(params);
    EXPECT_NO_THROW(ctx.Initialize());
}

TEST(BFVContextBudget, UsesEachExactTermOncePlusTwo) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    BFVContext ctx(params);
    EXPECT_EQ(ctx.RequiredFloodBudgetBits(), 136u);
    EXPECT_EQ(
        ctx.RequiredFloodBudgetBits(),
        params.eval_noise_bits + params.CoefficientStatBits() +
            params.flood_margin_bits + 2u);
    EXPECT_EQ(ctx.RequiredFloodBudgetBits(), params.FloodNoiseBits() + 2u);
    EXPECT_NO_THROW(ctx.Initialize());
}
