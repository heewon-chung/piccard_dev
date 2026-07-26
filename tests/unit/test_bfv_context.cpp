#include <gtest/gtest.h>
#include "fhe/bfv_context.h"
#include "util/params.h"
#include "core/threshold_poly.h"

#include <cmath>
#include <string>

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
    // Two floods of the same ciphertext must differ. Identical output would
    // mean the mask is deterministic, which hides nothing.
    std::vector<int64_t> values(params.ring_dim, 0);
    values[0] = 1;

    auto ct = ctx->Encrypt(values);
    auto a = ctx->Flood(ct);
    auto b = ctx->Flood(ct);

    const auto& ea = a->GetElements()[0];
    const auto& eb = b->GetElements()[0];
    bool differs = false;
    for (size_t i = 0; i < ea.GetNumOfElements() && !differs; i++) {
        if (ea.GetElementAtIndex(i) != eb.GetElementAtIndex(i)) differs = true;
    }

    RecordProperty("output_two_floods_differ", differs ? "true" : "false");
    EXPECT_TRUE(differs);
}

TEST_F(BFVContextTest, FloodMaskIsTheCalibratedSize) {
    // The three tests above all pass if Flood() added a ONE-BIT mask: they
    // check the plaintext survives, that the input is untouched, and that two
    // draws differ. None pins the magnitude -- and a mask smaller than the
    // evaluation noise leaves the receiver's view unsimulatable while the
    // ciphertext still decrypts, so no other signal would ever show it.
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

    // The mask dominates the evaluation noise by 2^(lambda_stat + margin), so
    // the measured maximum sits at the mask's own magnitude to within a bit.
    EXPECT_GE(measured_bits, expected_bits - 1.0);
    EXPECT_LE(measured_bits, expected_bits + 1.0);
}
