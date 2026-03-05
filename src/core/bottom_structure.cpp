#include "piccard/core/bottom_structure.h"

#include <algorithm>
#include <stdexcept>

namespace piccard {

BottomStructure::BottomStructure(uint32_t k, uint32_t d, uint64_t hash_range,
                                 uint64_t seed)
    : k_(k), d_(d), hasher_(k, hash_range, seed), bottom_(k) {
    if (d == 0) throw std::invalid_argument("depth d must be > 0");
}

// Algorithm 3: Initialize(x, H, k, d)
void BottomStructure::Initialize(const std::vector<uint64_t>& set) {
    if (set.empty()) throw std::invalid_argument("Set must not be empty");

    // Reset bottom structure
    for (uint32_t i = 0; i < k_; i++) {
        bottom_[i].clear();
        bottom_[i].reserve(d_ + 1);
    }

    // For each element, compute all k hashes and update bottom arrays
    for (uint64_t elem : set) {
        auto hashes = hasher_.ComputeElementHashes(elem);
        for (uint32_t i = 0; i < k_; i++) {
            InsertIntoSorted(i, hashes[i]);
        }
    }
}

// Algorithm 4: Insert(x*, B_x, H, k, d)
void BottomStructure::Insert(uint64_t elem) {
    auto hashes = hasher_.ComputeElementHashes(elem);
    for (uint32_t i = 0; i < k_; i++) {
        InsertIntoSorted(i, hashes[i]);
    }
}

// Algorithm 5: Delete(x, B_x, H, k)
void BottomStructure::Delete(uint64_t elem) {
    auto hashes = hasher_.ComputeElementHashes(elem);
    for (uint32_t i = 0; i < k_; i++) {
        auto it = std::lower_bound(bottom_[i].begin(), bottom_[i].end(),
                                   hashes[i]);
        if (it != bottom_[i].end() && *it == hashes[i]) {
            bottom_[i].erase(it);
        }
    }
}

std::vector<uint64_t> BottomStructure::GetSignature() const {
    std::vector<uint64_t> sig(k_);
    for (uint32_t i = 0; i < k_; i++) {
        if (bottom_[i].empty()) {
            throw std::runtime_error(
                "Bottom structure empty for hash function " +
                std::to_string(i) + "; re-initialization required");
        }
        sig[i] = bottom_[i][0];
    }
    return sig;
}

void BottomStructure::InsertIntoSorted(uint32_t i, uint64_t w) {
    auto& arr = bottom_[i];

    // If not full, or w is smaller than the largest, insert
    if (arr.size() < d_ || (!arr.empty() && w < arr.back())) {
        auto pos = std::lower_bound(arr.begin(), arr.end(), w);
        arr.insert(pos, w);
        // Trim to depth d
        if (arr.size() > d_) {
            arr.pop_back();
        }
    }
}

} // namespace piccard
