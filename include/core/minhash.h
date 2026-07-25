#pragma once

#include <cstdint>
#include <vector>

namespace piccard {

class MinHasher {
public:
    // `seed` is the public CRS seed; there is deliberately no default so that
    // every construction site names the CRS it uses and static/dynamic paths
    // cannot silently diverge. Do not reintroduce a default here or elsewhere.
    MinHasher(uint32_t k, uint64_t hash_range, uint64_t seed);

    // Compute k-dimensional MinHash signature for a set
    std::vector<uint64_t> ComputeSignature(const std::vector<uint64_t>& set) const;

    // Compute k hash values for a single element: (h_1(elem), ..., h_k(elem))
    std::vector<uint64_t> ComputeElementHashes(uint64_t elem) const;

    // Plaintext Jaccard estimate from two signatures (for verification)
    static double EstimateJaccard(const std::vector<uint64_t>& sig_x,
                                  const std::vector<uint64_t>& sig_y);

    uint32_t GetK() const { return k_; }

    // The public CRS seed this hasher was expanded from.
    uint64_t GetSeed() const { return seed_; }

private:
    uint32_t k_;
    uint64_t hash_range_;
    uint64_t seed_;

    // Mersenne prime P = 2^61 - 1 for universal hash family
    static constexpr uint64_t kMersennePrime = (1ULL << 61) - 1;

    // Hash coefficients: h_i(x) = ((a_i * x + b_i) mod P) mod R
    std::vector<uint64_t> a_;
    std::vector<uint64_t> b_;

    // Modular multiplication mod Mersenne prime (avoids overflow)
    static uint64_t MulModMersenne(uint64_t a, uint64_t b);
    static uint64_t ModMersenne(uint64_t val);
};

} // namespace piccard
