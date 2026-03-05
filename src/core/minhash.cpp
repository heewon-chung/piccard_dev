#include "piccard/core/minhash.h"

#include <algorithm>
#include <limits>
#include <random>
#include <stdexcept>

namespace piccard {

MinHasher::MinHasher(uint32_t k, uint64_t hash_range, uint64_t seed)
    : k_(k), hash_range_(hash_range), a_(k), b_(k) {
    if (k == 0) throw std::invalid_argument("k must be > 0");

    std::mt19937_64 rng(seed);
    // a_i in [1, P-1], b_i in [0, P-1]
    std::uniform_int_distribution<uint64_t> dist_a(1, kMersennePrime - 1);
    std::uniform_int_distribution<uint64_t> dist_b(0, kMersennePrime - 1);

    for (uint32_t i = 0; i < k; i++) {
        a_[i] = dist_a(rng);
        b_[i] = dist_b(rng);
    }
}

uint64_t MinHasher::ModMersenne(uint64_t val) {
    // Fast reduction mod 2^61 - 1
    val = (val >> 61) + (val & kMersennePrime);
    if (val >= kMersennePrime) val -= kMersennePrime;
    return val;
}

uint64_t MinHasher::MulModMersenne(uint64_t a, uint64_t b) {
    // Split into high and low 32-bit parts to avoid 128-bit overflow
    // Using __uint128_t for platforms that support it
    __uint128_t product = static_cast<__uint128_t>(a) * b;
    uint64_t hi = static_cast<uint64_t>(product >> 61);
    uint64_t lo = static_cast<uint64_t>(product) & kMersennePrime;
    return ModMersenne(hi + lo);
}

std::vector<uint64_t> MinHasher::ComputeSignature(const std::vector<uint64_t>& set) const {
    if (set.empty()) throw std::invalid_argument("Set must not be empty");

    std::vector<uint64_t> signature(k_, std::numeric_limits<uint64_t>::max());

    for (uint64_t elem : set) {
        for (uint32_t i = 0; i < k_; i++) {
            // h_i(x) = ((a_i * x + b_i) mod P) mod R
            uint64_t h = ModMersenne(MulModMersenne(a_[i], elem) + b_[i]);
            if (hash_range_ != std::numeric_limits<uint64_t>::max()) {
                h = h % hash_range_;
            }
            signature[i] = std::min(signature[i], h);
        }
    }

    return signature;
}

std::vector<uint64_t> MinHasher::ComputeElementHashes(uint64_t elem) const {
    std::vector<uint64_t> hashes(k_);
    for (uint32_t i = 0; i < k_; i++) {
        uint64_t h = ModMersenne(MulModMersenne(a_[i], elem) + b_[i]);
        if (hash_range_ != std::numeric_limits<uint64_t>::max()) {
            h = h % hash_range_;
        }
        hashes[i] = h;
    }
    return hashes;
}

double MinHasher::EstimateJaccard(const std::vector<uint64_t>& sig_x,
                                  const std::vector<uint64_t>& sig_y) {
    if (sig_x.size() != sig_y.size()) {
        throw std::invalid_argument("Signatures must have the same length");
    }
    if (sig_x.empty()) throw std::invalid_argument("Signatures must not be empty");

    uint32_t matches = 0;
    for (size_t i = 0; i < sig_x.size(); i++) {
        if (sig_x[i] == sig_y[i]) matches++;
    }
    return static_cast<double>(matches) / static_cast<double>(sig_x.size());
}

} // namespace piccard
