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

namespace {

// Expand the public CRS seed into the MinHash coefficients
// H = ((a_i, b_i))_{i=1..k}, a_i in [1, P-1] and b_i in [0, P-1].
//
// std::uniform_int_distribution is not specified to produce the same integer
// mapping across standard library implementations, so the seed alone would not
// pin down H. Consume raw std::mt19937_64 words instead and reduce them with
// explicit rejection sampling, which is portable and reproducible.
//
// Per i, draw a then b. Accept a word x when it is below the largest multiple
// of the modulus that fits in 64 bits, which is what makes the reduction
// unbiased; otherwise draw the next word.
//   a_i: accept x < 8*(P-1) = 2^64 - 16, then a_i = 1 + x mod (P-1)
//   b_i: accept x < 8*P     = 2^64 - 8,  then b_i = x mod P
void ExpandHashSeed(uint64_t seed, uint32_t k, uint64_t prime,
                    std::vector<uint64_t>& a, std::vector<uint64_t>& b) {
    const uint64_t a_limit = ~uint64_t{0} - 15;  // 2^64 - 16 == 8 * (P - 1)
    const uint64_t b_limit = ~uint64_t{0} - 7;   // 2^64 -  8 == 8 * P

    std::mt19937_64 rng(seed);
    a.resize(k);
    b.resize(k);
    for (uint32_t i = 0; i < k; i++) {
        uint64_t x;
        do { x = rng(); } while (x >= a_limit);
        a[i] = 1 + x % (prime - 1);
        do { x = rng(); } while (x >= b_limit);
        b[i] = x % prime;
    }
}

} // namespace

MinHasher::MinHasher(uint32_t k, uint64_t hash_range, uint64_t seed)
    : k_(k), hash_range_(hash_range), seed_(seed) {
    if (k == 0) throw std::invalid_argument("k must be > 0");
    ExpandHashSeed(seed, k, kMersennePrime, a_, b_);
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
