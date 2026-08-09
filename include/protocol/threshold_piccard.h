#pragma once

#include "protocol/piccard.h"

#include <cstdint>
#include <vector>

namespace piccard {

class ThresholdPiccard {
public:
    explicit ThresholdPiccard(const PiccardParams& params);

    // ── Protocol API ─────────────────────────────────────────────

    void KeyGen();

    // Forwarded CRS reseed (see Piccard::SetHashSeed): rebuilds the MinHasher
    // only. BFV keys and the threshold polynomial do not depend on the hash
    // family, so accuracy trials can resample the CRS without re-running
    // KeyGen or rebuilding u_tau.
    void SetHashSeed(uint64_t seed) { piccard_.SetHashSeed(seed); }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Encrypt(const std::vector<uint64_t>& set) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Evaluate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
             const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;

    // The unflooded result. Same contract as Piccard::EvaluateRaw: for callers
    // that must not receive the masking noise -- today only the calibration
    // harness, which measures the evaluation noise that sizes that mask and
    // therefore cannot include it. Returning this to the receiver is a
    // security bug.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    EvaluateRaw(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
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
