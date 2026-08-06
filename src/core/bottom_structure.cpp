#include "core/bottom_structure.h"

#include <algorithm>
#include <stdexcept>

namespace piccard {

BottomStructure::BottomStructure(uint32_t k, uint32_t d, uint64_t hash_range,
                                 uint64_t seed)
    : k_(k), d_(d), hasher_(k, hash_range, seed), bottom_(k) {
    if (d == 0) throw std::invalid_argument("depth d must be > 0");
}

void BottomStructure::RequireUsable() const {
    if (requires_rebuild_) {
        throw std::logic_error(
            "BottomStructure requires full nonempty Initialize()");
    }
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
    requires_rebuild_ = false;
}

// Algorithm 4: Insert(x*, B_x, H, k, d)
void BottomStructure::Insert(uint64_t elem) {
    RequireUsable();
    auto hashes = hasher_.ComputeElementHashes(elem);
    for (uint32_t i = 0; i < k_; i++) {
        InsertIntoSorted(i, hashes[i]);
    }
}

// Algorithm 5: Delete(x, B_x, H, k)
void BottomStructure::Delete(uint64_t elem) {
    RequireUsable();
    auto hashes = hasher_.ComputeElementHashes(elem);
    for (uint32_t i = 0; i < k_; i++) {
        auto it = std::lower_bound(bottom_[i].begin(), bottom_[i].end(),
                                   hashes[i]);
        if (it != bottom_[i].end() && *it == hashes[i]) {
            bottom_[i].erase(it);
        }
        if (bottom_[i].empty()) requires_rebuild_ = true;
    }
}

std::vector<uint64_t> BottomStructure::GetSignature() const {
    RequireUsable();
    std::vector<uint64_t> sig(k_);
    for (uint32_t i = 0; i < k_; i++) {
        sig[i] = bottom_[i][0];
    }
    return sig;
}

void BottomStructure::InsertIntoSorted(uint32_t i, uint64_t w) {
    auto& arr = bottom_[i];
    auto pos = std::lower_bound(arr.begin(), arr.end(), w);
    if (pos != arr.end() && *pos == w) {
        return;
    }

    // If not full, or w is smaller than the largest, insert
    if (arr.size() < d_ || (!arr.empty() && w < arr.back())) {
        arr.insert(pos, w);
        // Trim to depth d
        if (arr.size() > d_) {
            arr.pop_back();
        }
    }
}

} // namespace piccard
