#pragma once

#include "util/params.h"

#include <cstdint>
#include <vector>

namespace piccard {

class OneHotEncoder {
public:
    explicit OneHotEncoder(const PiccardParams& params);

    // Encode a MinHash signature into a one-hot feature vector of length ring_dim.
    // feature[i*m + sig[i] % m] = 1 for each hash function i in [0, k).
    // Zero-padded from k*m to ring_dim.
    std::vector<int64_t> Encode(const std::vector<uint64_t>& signature) const;

    // Decode a feature vector back to bucket indices (for testing/verification).
    std::vector<uint32_t> Decode(const std::vector<int64_t>& feature) const;

private:
    uint32_t k_;
    uint32_t m_;
    uint32_t ring_dim_;
};

} // namespace piccard
