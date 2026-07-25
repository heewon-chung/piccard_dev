#include "core/minhash.h"

#include <algorithm>
#include <cassert>
#include <limits>
#include <random>
#include <stdexcept>

#ifdef _OPENMP
#include <omp.h>
#endif

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

// Precondition: both operands must already be reduced (< P). With a, b < 2^61
// the product stays below 2^122, so hi < 2^61 and hi + lo cannot overflow.
// Passing an unreduced operand (e.g. a raw set element) lets hi approach 2^64,
// wrapping hi + lo and shifting the result by 2^64 mod P = 8. Callers reduce
// elements once via ModMersenne before entering the per-hash loop.
uint64_t MinHasher::MulModMersenne(uint64_t a, uint64_t b) {
    assert(a < kMersennePrime && b < kMersennePrime);
    __uint128_t product = static_cast<__uint128_t>(a) * b;
    uint64_t hi = static_cast<uint64_t>(product >> 61);
    uint64_t lo = static_cast<uint64_t>(product) & kMersennePrime;
    return ModMersenne(hi + lo);
}

std::vector<uint64_t> MinHasher::ComputeSignature(const std::vector<uint64_t>& set) const {
    if (set.empty()) throw std::invalid_argument("Set must not be empty");

    std::vector<uint64_t> signature(k_, std::numeric_limits<uint64_t>::max());

#ifdef _OPENMP
    #pragma omp parallel
    {
        std::vector<uint64_t> local_sig(k_, std::numeric_limits<uint64_t>::max());

        #pragma omp for nowait
        for (size_t e = 0; e < set.size(); e++) {
            // Reduce once per element, not once per hash function.
            uint64_t elem = ModMersenne(set[e]);
            for (uint32_t i = 0; i < k_; i++) {
                uint64_t h = ModMersenne(MulModMersenne(a_[i], elem) + b_[i]);
                if (hash_range_ != std::numeric_limits<uint64_t>::max()) {
                    h = h % hash_range_;
                }
                local_sig[i] = std::min(local_sig[i], h);
            }
        }

        #pragma omp critical
        {
            for (uint32_t i = 0; i < k_; i++) {
                signature[i] = std::min(signature[i], local_sig[i]);
            }
        }
    }
#else
    for (uint64_t raw_elem : set) {
        // Reduce once per element, not once per hash function.
        uint64_t elem = ModMersenne(raw_elem);
        for (uint32_t i = 0; i < k_; i++) {
            uint64_t h = ModMersenne(MulModMersenne(a_[i], elem) + b_[i]);
            if (hash_range_ != std::numeric_limits<uint64_t>::max()) {
                h = h % hash_range_;
            }
            signature[i] = std::min(signature[i], h);
        }
    }
#endif

    return signature;
}

std::vector<uint64_t> MinHasher::ComputeElementHashes(uint64_t raw_elem) const {
    // Reduce once per element, not once per hash function.
    const uint64_t elem = ModMersenne(raw_elem);
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
