#include <gtest/gtest.h>
#include "core/threshold_truth.h"

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
