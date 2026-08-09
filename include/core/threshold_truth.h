#pragma once

#include <algorithm>   // std::min in BucketMatchCount — header stays self-contained
#include <cmath>
#include <cstddef>
#include <cstdint>
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

} // namespace piccard
