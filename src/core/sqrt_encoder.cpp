#include "core/sqrt_encoder.h"

#include <stdexcept>

namespace piccard {

SqrtEncoder::SqrtEncoder(const PiccardParams& params)
    : k_(params.k), m_(params.m), base_(params.sqrt_base), ring_dim_(params.ring_dim) {
    if (base_ == 0) {
        throw std::invalid_argument("Params must be validated with ValidateSqrt() before creating SqrtEncoder");
    }
}

std::vector<int64_t> SqrtEncoder::Encode(const std::vector<uint64_t>& signature) const {
    if (signature.size() != k_) {
        throw std::invalid_argument("Signature length must equal k");
    }

    std::vector<int64_t> feature(ring_dim_, 0);
    uint32_t block = 2 * base_;  // slots per signature

    for (uint32_t i = 0; i < k_; i++) {
        uint32_t v = static_cast<uint32_t>(signature[i] % m_);
        uint32_t v_lo = v % base_;
        uint32_t v_hi = v / base_;

        feature[i * block + v_lo] = 1;
        feature[i * block + base_ + v_hi] = 1;
    }

    return feature;
}

std::vector<uint32_t> SqrtEncoder::Decode(const std::vector<int64_t>& feature) const {
    uint32_t block = 2 * base_;
    if (feature.size() < static_cast<size_t>(k_) * block) {
        throw std::invalid_argument("Feature vector too short");
    }

    std::vector<uint32_t> buckets(k_);

    for (uint32_t i = 0; i < k_; i++) {
        uint32_t v_lo = 0;
        uint32_t v_hi = 0;

        // Find the set bit in the low-digit sub-block
        for (uint32_t j = 0; j < base_; j++) {
            if (feature[i * block + j] != 0) {
                v_lo = j;
                break;
            }
        }

        // Find the set bit in the high-digit sub-block
        for (uint32_t j = 0; j < base_; j++) {
            if (feature[i * block + base_ + j] != 0) {
                v_hi = j;
                break;
            }
        }

        buckets[i] = v_hi * base_ + v_lo;
    }

    return buckets;
}

} // namespace piccard
