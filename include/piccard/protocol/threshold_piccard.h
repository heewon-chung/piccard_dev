#pragma once

#include "piccard/protocol/piccard.h"

#include <cstdint>
#include <vector>

namespace piccard {

class ThresholdPiccard {
public:
    explicit ThresholdPiccard(const PiccardParams& params);

    // ── Protocol API ─────────────────────────────────────────────

    void KeyGen();

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Encrypt(const std::vector<uint64_t>& set) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Evaluate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
             const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;

    bool Decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    bool Run(const std::vector<uint64_t>& set_x,
             const std::vector<uint64_t>& set_y) const;

    // ── Accessors ────────────────────────────────────────────────

    const PiccardParams& GetParams() const;
    const BFVContext& GetBFVContext() const;

    // Benchmark accessors (for per-phase timing in bench_threshold)
    const Piccard& GetPiccard() const { return piccard_; }
    const std::vector<int64_t>& GetThresholdPoly() const { return threshold_poly_; }

private:
    Piccard piccard_;
    std::vector<int64_t> threshold_poly_;
};

} // namespace piccard
