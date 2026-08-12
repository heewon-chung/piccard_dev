#include <gtest/gtest.h>
#include "core/threshold_truth.h"
#include "core/onehot_encoder.h"
#include "util/params.h"

#include <algorithm>
#include <cmath>
#include <vector>

using namespace piccard;

// J_tau must be the exact inverse of the bias correction in Piccard::Decrypt:
//   J_hat = (v/k - 1/m) / (1 - 1/m), evaluated at v = tau.
TEST(ThresholdTruth, JaccardThresholdInvertsBiasCorrection) {
    for (uint32_t k : {16u, 32u, 64u, 128u, 256u, 512u}) {
        uint32_t tau = static_cast<uint32_t>(0.6 * k);
        for (uint32_t m : {8u, 64u, 256u}) {
            double j_tau = JaccardThreshold(tau, k, m);
            // Forward map: expected match count at J = j_tau is exactly tau.
            double q = j_tau + (1.0 - j_tau) / m;
            EXPECT_NEAR(q * k, static_cast<double>(tau), 1e-9)
                << "k=" << k << " m=" << m;
        }
    }
}

TEST(ThresholdTruth, JaccardThresholdKnownValue) {
    // k=128, m=64, tau=76: J_tau = (76*64 - 128) / (128 * 63) = 4736/8064
    EXPECT_NEAR(JaccardThreshold(76, 128, 64), 4736.0 / 8064.0, 1e-12);
}

TEST(ThresholdTruth, BucketMatchCountMirrorsOneHotEncoding) {
    // OneHotEncoder::Encode sets feature[i*m + sig[i] % m] = 1, so two
    // signatures match at slot i iff sig_x[i] % m == sig_y[i] % m.
    // Build the one-hot inner product by hand and compare.
    const uint32_t m = 8;
    std::vector<uint64_t> sx = {0, 9, 17, 5, 63, 100};
    // Buckets mod 8: sx -> {0,1,1,5,7,4}, sy -> {0,1,2,5,6,4}.
    // Matches at i = 0, 1, 3, 5 — i=5 matches because 100 % 8 == 4 % 8 == 4.
    std::vector<uint64_t> sy = {8, 9, 18, 5, 62, 4};
    int64_t expected = 0;
    for (size_t i = 0; i < sx.size(); i++) {
        std::vector<int> fx(m, 0), fy(m, 0);
        fx[sx[i] % m] = 1;
        fy[sy[i] % m] = 1;
        for (uint32_t b = 0; b < m; b++) expected += fx[b] * fy[b];
    }
    EXPECT_EQ(expected, 4);
    EXPECT_EQ(BucketMatchCount(sx, sy, m), expected);
}

// BucketMatchCount is a plaintext stand-in for the encrypted inner product
// the server evaluates on real OneHotEncoder::Encode output. The two
// implementations are independent code paths that must agree; runtime
// fhe_agrees only compares match_count >= tau decisions, so a bucketing
// divergence that stays on the same side of tau would pass silently while
// still corrupting jaccard_computed / jaccard_error / jaccard_rel_error.
// Pin BucketMatchCount to the real encoder directly, without any FHE.
TEST(ThresholdTruth, BucketMatchCountMatchesRealOneHotEncoder) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();

    OneHotEncoder encoder(params);
    const uint32_t k = params.k;
    const uint32_t m = params.m;

    auto InnerProduct = [&](const std::vector<uint64_t>& sig_x,
                             const std::vector<uint64_t>& sig_y) -> int64_t {
        std::vector<int64_t> fx = encoder.Encode(sig_x);
        std::vector<int64_t> fy = encoder.Encode(sig_y);
        int64_t dot = 0;
        for (size_t i = 0; i < fx.size(); i++) dot += fx[i] * fy[i];
        return dot;
    };

    // Identical signature pair: every slot's bucket matches itself.
    std::vector<uint64_t> sig_a(k);
    for (uint32_t i = 0; i < k; i++) sig_a[i] = i * 3 + 1;

    // Fully-disjoint-bucket pair: shift every value by 1 so
    // sig_b[i] % m == (sig_a[i] % m + 1) % m never equals sig_a[i] % m.
    std::vector<uint64_t> sig_b(k);
    for (uint32_t i = 0; i < k; i++) sig_b[i] = sig_a[i] + 1;

    // Partial-overlap pair: even slots share sig_a's bucket, odd slots are
    // shifted by 3 (not a multiple of m=8) into a different bucket.
    std::vector<uint64_t> sig_c(k);
    for (uint32_t i = 0; i < k; i++) {
        sig_c[i] = (i % 2 == 0) ? sig_a[i] : sig_a[i] + 3;
    }

    int64_t dot_aa = InnerProduct(sig_a, sig_a);
    int64_t dot_ab = InnerProduct(sig_a, sig_b);
    int64_t dot_ac = InnerProduct(sig_a, sig_c);

    // Sanity-check the pairs actually exercise the intended overlap shape.
    EXPECT_EQ(dot_aa, static_cast<int64_t>(k));
    EXPECT_EQ(dot_ab, 0);
    EXPECT_EQ(dot_ac, static_cast<int64_t>(k / 2));

    EXPECT_EQ(BucketMatchCount(sig_a, sig_a, m), dot_aa);
    EXPECT_EQ(BucketMatchCount(sig_a, sig_b, m), dot_ab);
    EXPECT_EQ(BucketMatchCount(sig_a, sig_c, m), dot_ac);
}

TEST(ThresholdTruth, BucketMatchCountIdenticalAndDisjoint) {
    std::vector<uint64_t> s1 = {1, 2, 3, 4};
    EXPECT_EQ(BucketMatchCount(s1, s1, 64), 4);
    std::vector<uint64_t> s2 = {5, 6, 7, 8};
    EXPECT_EQ(BucketMatchCount(s1, s2, 64), 0);
}

TEST(ThresholdTruth, SigmaMatchesHalfInvSqrtKApproximation) {
    // At the boundary, sigma_J ~ 1/(2 sqrt(k)) for large m. Verified values:
    // k=128, m=64, J=J_tau: sigma = 0.04410 (approx 1/(2*sqrt(128)) = 0.04419)
    double j_tau = JaccardThreshold(76, 128, 64);
    EXPECT_NEAR(JaccardEstimatorSigma(j_tau, 128, 64), 0.04410, 5e-4);
    EXPECT_NEAR(JaccardEstimatorSigma(j_tau, 128, 64),
                1.0 / (2.0 * std::sqrt(128.0)), 2e-3);
}

// The loose approximation above admits a wrong implementation: substituting
// j for q = j + (1-j)/m differs by only ~1.07e-4 at k=128,m=64,J=J_tau --
// comfortably inside the 5e-4 tolerance above. Pin the exact formula
// (sigma_J = sqrt(q(1-q)/k) / (1 - 1/m)) at a tight tolerance, computing q
// independently in the test, across several j and several m -- including
// small m (4, 8), where the j-vs-q gap is largest and a substitution bug is
// easiest to catch.
TEST(ThresholdTruth, SigmaMatchesExactQFormula) {
    for (uint32_t m : {4u, 8u, 16u, 64u}) {
        for (double j : {0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0}) {
            for (uint32_t k : {16u, 64u, 128u, 512u}) {
                double q = j + (1.0 - j) / static_cast<double>(m);
                double expected =
                    std::sqrt(q * (1.0 - q) / static_cast<double>(k)) /
                    (1.0 - 1.0 / static_cast<double>(m));
                EXPECT_NEAR(JaccardEstimatorSigma(j, k, m), expected, 1e-12)
                    << "j=" << j << " k=" << k << " m=" << m;
            }
        }
    }
}

TEST(ThresholdTruth, SyntheticThresholdLiterals) {
    const std::vector<uint32_t> expected_k = {64u, 128u, 256u, 512u};
    const std::vector<uint32_t> expected_tau = {38u, 76u, 153u, 307u};
    ASSERT_EQ(expected_k.size(), kSyntheticThresholdK.size());
    for (size_t i = 0; i < expected_k.size(); ++i) {
        EXPECT_EQ(kSyntheticThresholdK[i], expected_k[i]);
        EXPECT_EQ(SyntheticThresholdTauCount(expected_k[i]), expected_tau[i]);
        const double expected_j_tau =
            (static_cast<double>(expected_tau[i]) / expected_k[i] - 1.0 / 64.0) /
            (1.0 - 1.0 / 64.0);
        EXPECT_NEAR(JaccardThreshold(expected_tau[i], expected_k[i], 64),
                    expected_j_tau, 1e-15);
    }

    const auto grid = SyntheticThresholdGridIndices();
    ASSERT_EQ(grid.size(), 21u);
    for (size_t i = 0; i < grid.size(); ++i) {
        EXPECT_EQ(grid[i], static_cast<int32_t>(i) - 10);
    }
}

TEST(ThresholdTruth, SyntheticThresholdGeometryAndRowSeedKats) {
    const auto center = MakeSyntheticThresholdPoint(128u, 0);
    EXPECT_EQ(center.tau_count, 76u);
    EXPECT_NEAR(center.j_tau, 0.5873015873015873, 1e-15);
    EXPECT_NEAR(center.target_j, center.j_tau, 1e-15);
    EXPECT_EQ(center.realized_intersection, 740u);
    EXPECT_EQ(center.realized_union, 1260u);
    EXPECT_NEAR(center.realized_j, 740.0 / 1260.0, 1e-15);
    EXPECT_EQ(SyntheticThresholdRowSeed(20260729u, 128u, 0, 0),
              4449377846872528327ull);

    const auto lower = MakeSyntheticThresholdPoint(64u, -10);
    EXPECT_EQ(lower.realized_intersection, 655u);
    EXPECT_EQ(lower.realized_union, 1345u);
    EXPECT_NEAR(lower.realized_j, 655.0 / 1345.0, 1e-15);
    EXPECT_EQ(SyntheticThresholdRowSeed(20260729u, 64u, -10, 0),
              8053640992355589680ull);

    const auto upper = MakeSyntheticThresholdPoint(512u, 10);
    EXPECT_EQ(upper.realized_intersection, 818u);
    EXPECT_EQ(upper.realized_union, 1182u);
    EXPECT_NEAR(upper.realized_j, 818.0 / 1182.0, 1e-15);
}

TEST(ThresholdTruth, SyntheticThresholdTheoryAndOutcomeKats) {
    EXPECT_NEAR(
        SyntheticThresholdBinomialDecisionProbability(128u, 76u, 0.59375),
        0.5380497333771499, 1e-15);
    EXPECT_NEAR(SyntheticThresholdGaussianErrorApprox(
                    740.0 / 1260.0, 128u, 64u),
                0.5, 1e-15);
    EXPECT_EQ(SyntheticThresholdDecision(76, 76), 1);
    EXPECT_EQ(SyntheticThresholdDecision(75, 76), 0);
    EXPECT_STREQ(SyntheticThresholdOutcome(1, 1), "TP");
    EXPECT_STREQ(SyntheticThresholdOutcome(1, 0), "FN");
    EXPECT_STREQ(SyntheticThresholdOutcome(0, 1), "FP");
    EXPECT_STREQ(SyntheticThresholdOutcome(0, 0), "TN");
}
