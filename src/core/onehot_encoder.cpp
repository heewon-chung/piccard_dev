#include "core/onehot_encoder.h"

#include <stdexcept>

namespace piccard {

OneHotEncoder::OneHotEncoder(const PiccardParams& params)
    : k_(params.k), m_(params.m), ring_dim_(params.ring_dim) {
    if (ring_dim_ == 0) {
        throw std::invalid_argument("Params must be validated before creating OneHotEncoder");
    }
}

std::vector<int64_t> OneHotEncoder::Encode(const std::vector<uint64_t>& signature) const {
    if (signature.size() != k_) {
        throw std::invalid_argument("Signature length must equal k");
    }

    std::vector<int64_t> feature(ring_dim_, 0);

    for (uint32_t i = 0; i < k_; i++) {
        uint32_t bucket = static_cast<uint32_t>(signature[i] % m_);
        feature[i * m_ + bucket] = 1;
    }

    return feature;
}

std::vector<uint32_t> OneHotEncoder::Decode(const std::vector<int64_t>& feature) const {
    if (feature.size() < static_cast<size_t>(k_) * m_) {
        throw std::invalid_argument("Feature vector too short");
    }

    std::vector<uint32_t> buckets(k_);

    for (uint32_t i = 0; i < k_; i++) {
        bool found = false;
        for (uint32_t j = 0; j < m_; j++) {
            if (feature[i * m_ + j] != 0) {
                buckets[i] = j;
                found = true;
                break;
            }
        }
        if (!found) {
            buckets[i] = 0;  // default if no bit set
        }
    }

    return buckets;
}

} // namespace piccard
