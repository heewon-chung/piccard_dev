#pragma once

#include "util/params.h"

#include <cstdint>
#include <vector>

namespace piccard {

class SqrtEncoder {
public:
    explicit SqrtEncoder(const PiccardParams& params);

    // Encode a MinHash signature into a base-√m one-hot feature vector.
    // Layout per signature i (b = √m):
    //   [one-hot(v_lo, b) | one-hot(v_hi, b)]
    //   where v = sig[i] % m, v_lo = v % b, v_hi = v / b
    // Total: k * 2 * b slots, zero-padded to ring_dim.
    std::vector<int64_t> Encode(const std::vector<uint64_t>& signature) const;

    // Decode a feature vector back to bucket indices (for testing/verification).
    std::vector<uint32_t> Decode(const std::vector<int64_t>& feature) const;

    uint32_t GetBase() const { return base_; }

private:
    uint32_t k_;
    uint32_t m_;
    uint32_t base_;      // √m
    uint32_t ring_dim_;
};

} // namespace piccard
