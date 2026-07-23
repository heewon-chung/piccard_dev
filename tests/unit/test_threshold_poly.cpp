#include <gtest/gtest.h>
#include "core/threshold_poly.h"

using namespace piccard;

class ThresholdPolyTest : public ::testing::Test {
protected:
    // Use a small prime for testing
    static constexpr uint64_t p = 65537;  // 2^16 + 1, a Fermat prime
};

TEST_F(ThresholdPolyTest, ModInverseBasic) {
    EXPECT_EQ((ModInverse(2, 7) * 2) % 7, 1);
    EXPECT_EQ((ModInverse(3, 11) * 3) % 11, 1);
    EXPECT_EQ((ModInverse(5, 13) * 5) % 13, 1);
}

TEST_F(ThresholdPolyTest, ModInverseAllNonzero) {
    int64_t q = 17;
    for (int64_t a = 1; a < q; a++) {
        int64_t inv = ModInverse(a, q);
        EXPECT_EQ((a * inv) % q, 1) << "Failed for a=" << a << " mod " << q;
    }
}

TEST_F(ThresholdPolyTest, EvalPolyPlaintextConstant) {
    std::vector<int64_t> coeffs = {42};  // P(x) = 42
    EXPECT_EQ(EvalPolyPlaintext(coeffs, 0, p), 42);
    EXPECT_EQ(EvalPolyPlaintext(coeffs, 5, p), 42);
    EXPECT_EQ(EvalPolyPlaintext(coeffs, 100, p), 42);
}

TEST_F(ThresholdPolyTest, EvalPolyPlaintextLinear) {
    // P(x) = 3 + 2x, mod 17
    std::vector<int64_t> coeffs = {3, 2};
    EXPECT_EQ(EvalPolyPlaintext(coeffs, 0, 17), 3);
    EXPECT_EQ(EvalPolyPlaintext(coeffs, 1, 17), 5);
    EXPECT_EQ(EvalPolyPlaintext(coeffs, 7, 17), 0);  // (3+14) mod 17 = 0
}

TEST_F(ThresholdPolyTest, ThresholdPolySmall) {
    // max_val = 4, tau = 2: u(0)=0, u(1)=0, u(2)=1, u(3)=1, u(4)=1
    uint32_t tau = 2;
    uint32_t max_val = 4;
    auto poly = BuildThresholdPoly(tau, max_val, p);

    EXPECT_EQ(poly.size(), max_val + 1);

    EXPECT_EQ(EvalPolyPlaintext(poly, 0, static_cast<int64_t>(p)), 0);
    EXPECT_EQ(EvalPolyPlaintext(poly, 1, static_cast<int64_t>(p)), 0);
    EXPECT_EQ(EvalPolyPlaintext(poly, 2, static_cast<int64_t>(p)), 1);
    EXPECT_EQ(EvalPolyPlaintext(poly, 3, static_cast<int64_t>(p)), 1);
    EXPECT_EQ(EvalPolyPlaintext(poly, 4, static_cast<int64_t>(p)), 1);
}

TEST_F(ThresholdPolyTest, ThresholdPolyTauZero) {
    // tau = 0: always 1 for all x in [0..max_val]
    uint32_t max_val = 5;
    auto poly = BuildThresholdPoly(0, max_val, p);

    for (uint32_t x = 0; x <= max_val; x++) {
        EXPECT_EQ(EvalPolyPlaintext(poly, static_cast<int64_t>(x),
                                    static_cast<int64_t>(p)), 1)
            << "Failed at x=" << x;
    }
}

TEST_F(ThresholdPolyTest, ThresholdPolyTauMax) {
    // tau = max_val: only u(max_val) = 1, rest = 0
    uint32_t max_val = 5;
    auto poly = BuildThresholdPoly(max_val, max_val, p);

    for (uint32_t x = 0; x < max_val; x++) {
        EXPECT_EQ(EvalPolyPlaintext(poly, static_cast<int64_t>(x),
                                    static_cast<int64_t>(p)), 0)
            << "Failed at x=" << x;
    }
    EXPECT_EQ(EvalPolyPlaintext(poly, static_cast<int64_t>(max_val),
                                static_cast<int64_t>(p)), 1);
}

TEST_F(ThresholdPolyTest, ThresholdPolyTauExceedsMax) {
    // tau = max_val + 1: always 0
    uint32_t max_val = 5;
    auto poly = BuildThresholdPoly(max_val + 1, max_val, p);

    for (uint32_t x = 0; x <= max_val; x++) {
        EXPECT_EQ(EvalPolyPlaintext(poly, static_cast<int64_t>(x),
                                    static_cast<int64_t>(p)), 0)
            << "Failed at x=" << x;
    }
}

TEST_F(ThresholdPolyTest, ThresholdPolyMediumDegree) {
    // Test with k=16 (moderate degree) and various tau values
    uint32_t max_val = 16;
    for (uint32_t tau : {1u, 4u, 8u, 12u, 16u}) {
        auto poly = BuildThresholdPoly(tau, max_val, p);

        for (uint32_t x = 0; x <= max_val; x++) {
            int64_t expected = (x >= tau) ? 1 : 0;
            int64_t actual = EvalPolyPlaintext(poly, static_cast<int64_t>(x),
                                               static_cast<int64_t>(p));
            EXPECT_EQ(actual, expected)
                << "tau=" << tau << ", x=" << x;
        }
    }
}

TEST_F(ThresholdPolyTest, StepFunctionAtBoundary) {
    // For each tau, verify the critical boundary: u(tau-1)=0 and u(tau)=1
    RecordProperty("input_max_val", 20);
    RecordProperty("input_p", std::to_string(p));

    uint32_t max_val = 20;
    for (uint32_t tau = 1; tau <= max_val; tau++) {
        auto poly = BuildThresholdPoly(tau, max_val, p);

        int64_t val_below = EvalPolyPlaintext(
            poly, static_cast<int64_t>(tau - 1), static_cast<int64_t>(p));
        int64_t val_at = EvalPolyPlaintext(
            poly, static_cast<int64_t>(tau), static_cast<int64_t>(p));

        RecordProperty("tau_" + std::to_string(tau) + "_u(tau-1)",
                       std::to_string(val_below));
        RecordProperty("tau_" + std::to_string(tau) + "_u(tau)",
                       std::to_string(val_at));

        EXPECT_EQ(val_below, 0) << "u(" << (tau - 1) << ") should be 0 for tau=" << tau;
        EXPECT_EQ(val_at, 1) << "u(" << tau << ") should be 1 for tau=" << tau;
    }
}

TEST_F(ThresholdPolyTest, PolynomialDegreeMatchesMaxVal) {
    // BuildThresholdPoly(tau, max_val, p) should return max_val + 1 coefficients
    // (degree max_val polynomial)
    RecordProperty("expected", "coeffs.size() == max_val + 1");

    for (uint32_t max_val : {4u, 8u, 16u, 32u}) {
        auto poly = BuildThresholdPoly(max_val / 2, max_val, p);

        RecordProperty("max_val_" + std::to_string(max_val) + "_coeffs_size",
                       static_cast<int>(poly.size()));

        EXPECT_EQ(poly.size(), max_val + 1)
            << "Polynomial for max_val=" << max_val
            << " should have " << (max_val + 1) << " coefficients";
    }
}

TEST_F(ThresholdPolyTest, LargePrimeModulus) {
    // Test with a larger Fermat-friendly prime
    uint64_t large_p = 786433;  // prime, used by OpenFHE for BFV
    uint32_t tau = 5;
    uint32_t max_val = 10;

    RecordProperty("input_p", std::to_string(large_p));
    RecordProperty("input_tau", static_cast<int>(tau));
    RecordProperty("input_max_val", static_cast<int>(max_val));

    auto poly = BuildThresholdPoly(tau, max_val, large_p);

    for (uint32_t x = 0; x <= max_val; x++) {
        int64_t expected = (x >= tau) ? 1 : 0;
        int64_t actual = EvalPolyPlaintext(
            poly, static_cast<int64_t>(x), static_cast<int64_t>(large_p));

        RecordProperty("u(" + std::to_string(x) + ")", std::to_string(actual));

        EXPECT_EQ(actual, expected)
            << "x=" << x << " with large prime p=" << large_p;
    }
}
