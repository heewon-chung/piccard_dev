#pragma once

#include "core/minhash.h"

#include <cstdint>
#include <vector>

namespace piccard {

// Bottom structure for Dynamic Piccard (Paper Section 3.2, Algorithms 3-5).
// Maintains the d smallest hash values per hash function to support
// element insertion and deletion without recomputing from scratch.
class BottomStructure {
public:
    // `seed` is the public CRS seed; deliberately no default (see MinHasher).
    BottomStructure(uint32_t k, uint32_t d, uint64_t hash_range,
                    uint64_t seed);

    // Algorithm 3: Initialize bottom structure from a set
    void Initialize(const std::vector<uint64_t>& set);

    // Algorithm 4: Insert element into bottom structure
    void Insert(uint64_t elem);

    // Algorithm 5: Delete element from bottom structure
    void Delete(uint64_t elem);

    // Derive MinHash signature: sig[i] = bottom_[i][0] (smallest value)
    std::vector<uint64_t> GetSignature() const;

    uint32_t GetK() const { return k_; }
    uint32_t GetD() const { return d_; }

    // The public CRS seed this structure's hash family was expanded from.
    // Delegates to the hasher so there is a single source of truth.
    uint64_t GetSeed() const { return hasher_.GetSeed(); }
    const std::vector<std::vector<uint64_t>>& GetBottom() const {
        return bottom_;
    }

private:
    uint32_t k_;
    uint32_t d_;
    MinHasher hasher_;
    // bottom_[i] = sorted vector of up to d smallest hash values for h_i
    std::vector<std::vector<uint64_t>> bottom_;

    // Insert a hash value w into bottom_[i] maintaining sorted order and depth limit
    void InsertIntoSorted(uint32_t i, uint64_t w);
};

} // namespace piccard
