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

    // The public CRS seed serialized into each SHA-256 rank input.
    uint64_t GetSeed() const { return seed_; }

    // Stable name for the byte-level random-ranking contract.
    static constexpr const char* ModelName() noexcept {
        return "sha256-random-ranking-poc-v1";
    }

private:
    uint32_t k_;
    uint64_t hash_range_;
    uint64_t seed_;

    uint64_t HashRank(uint32_t coordinate, uint64_t elem) const;
};

} // namespace piccard
