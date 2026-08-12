#pragma once

#include <algorithm>   // std::min in BucketMatchCount — header stays self-contained
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace piccard {

// Jaccard threshold corresponding to a match-count threshold tau: the exact
// inverse of the bias correction applied in Piccard::Decrypt
// (J_hat = (v/k - 1/m) / (1 - 1/m)), evaluated at v = tau. A protocol
// decision `match_count >= tau` is therefore the estimator-side image of the
// true-similarity decision `J >= JaccardThreshold(tau, k, m)`.
inline double JaccardThreshold(uint32_t tau, uint32_t k, uint32_t m) {
    double kk = static_cast<double>(k);
    double mm = static_cast<double>(m);
    return (static_cast<double>(tau) / kk - 1.0 / mm) / (1.0 - 1.0 / mm);
}

// The match count the protocol computes, recovered from plaintext signatures:
// the number of positions whose one-hot buckets coincide. Mirrors
// OneHotEncoder::Encode (bucket = sig[i] % m), so this equals the encrypted
// inner product the server evaluates -- without running any FHE.
inline int64_t BucketMatchCount(const std::vector<uint64_t>& sig_x,
                                const std::vector<uint64_t>& sig_y,
                                uint32_t m) {
    size_t n = std::min(sig_x.size(), sig_y.size());
    int64_t count = 0;
    for (size_t i = 0; i < n; i++) {
        if (sig_x[i] % m == sig_y[i] % m) count++;
    }
    return count;
}

// Standard deviation of the bias-corrected Jaccard estimator at true
// similarity J, under the idealized independent-minwise model: each slot
// matches independently with probability q = J + (1-J)/m, so
// match_count ~ Binom(k, q) and
//   sigma_J = sqrt(q(1-q)/k) / (1 - 1/m).
// The SHA-256 rank-hashing family approximates (does not guarantee) that model.
// At the boundary this is approximately 1/(2 sqrt(k)).
inline double JaccardEstimatorSigma(double j, uint32_t k, uint32_t m) {
    double mm = static_cast<double>(m);
    double q = j + (1.0 - j) / mm;
    return std::sqrt(q * (1.0 - q) / static_cast<double>(k)) /
           (1.0 - 1.0 / mm);
}

/** @brief Fixed synthetic-threshold parameter family from the readiness spec. */
inline constexpr std::array<uint32_t, 4> kSyntheticThresholdK = {
    64u, 128u, 256u, 512u};

/** @brief Fixed one-hot bucket count for the synthetic threshold family. */
inline constexpr uint32_t kSyntheticThresholdM = 64u;

/** @brief Fixed canonical set size for the synthetic threshold family. */
inline constexpr uint32_t kSyntheticThresholdSetSize = 1000u;

/** @brief Fixed signed grid bounds for the synthetic threshold family. */
inline constexpr int32_t kSyntheticThresholdGridMin = -10;
inline constexpr int32_t kSyntheticThresholdGridMax = 10;

/** @brief Integer geometry and floating-point fields for one grid point. */
struct SyntheticThresholdPoint {
    uint32_t k = 0;
    uint32_t m = kSyntheticThresholdM;
    uint32_t tau_count = 0;
    int32_t grid_index = 0;
    double j_tau = 0.0;
    double target_j = 0.0;
    double signed_delta = 0.0;
    double absolute_delta = 0.0;
    double alpha = 0.0;
    uint32_t realized_intersection = 0;
    uint32_t realized_union = 0;
    double realized_j = 0.0;
};

/** @brief Return whether k is one of the four fixed synthetic values. */
bool IsSyntheticThresholdK(uint32_t k) noexcept;

/** @brief Return floor(0.6*k) for a supported k, or throw otherwise. */
uint32_t SyntheticThresholdTauCount(uint32_t k);

/** @brief Return whether a signed grid index is in [-10,10]. */
bool IsSyntheticThresholdGridIndex(int32_t grid_index) noexcept;

/** @brief Return the fixed 21-point signed grid in ascending order. */
std::vector<int32_t> SyntheticThresholdGridIndices();

/** @brief Construct one canonical synthetic threshold point. */
SyntheticThresholdPoint MakeSyntheticThresholdPoint(uint32_t k,
                                                    int32_t grid_index);

/** @brief Derive the per-row MinHash seed from the frozen SHA-256 framing. */
uint64_t SyntheticThresholdRowSeed(uint64_t root_seed,
                                   uint32_t k,
                                   int32_t grid_index,
                                   uint64_t trial_index);

/** @brief Exact double-precision binomial survival probability P[X>=tau]. */
double SyntheticThresholdBinomialDecisionProbability(uint32_t k,
                                                     uint32_t tau_count,
                                                     double p);

/** @brief Gaussian error approximation from the frozen no-continuity formula. */
double SyntheticThresholdGaussianErrorApprox(double realized_j,
                                             uint32_t k,
                                             uint32_t m);

/** @brief Apply the inclusive threshold decision rule. */
int SyntheticThresholdDecision(int64_t match_count, uint32_t tau_count) noexcept;

/** @brief Return the exact-J truth-table outcome spelling. */
const char* SyntheticThresholdOutcome(int exact_j_truth, int decision) noexcept;

} // namespace piccard
