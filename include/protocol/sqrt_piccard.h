#pragma once

#include "protocol/piccard.h"      // JaccardResult, BFVContext
#include "core/minhash.h"
#include "core/sqrt_encoder.h"

#include <memory>
#include <vector>

namespace piccard {

class SqrtPiccard {
public:
    explicit SqrtPiccard(const PiccardParams& params);

    void KeyGen();

    // High-level protocol API (same shape as Piccard)
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

    JaccardResult Decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    JaccardResult Run(const std::vector<uint64_t>& set_x,
                      const std::vector<uint64_t>& set_y) const;

    // Replace the public CRS seed. Same invariant as Piccard::SetHashSeed:
    // params_.hash_seed always updates, and the MinHasher is rebuilt if KeyGen()
    // has already run. Used to give one-hot and sqrt the same CRS in a paired
    // trial, so signatures stay comparable.
    void SetHashSeed(uint64_t seed);

    // Advanced/benchmarking API
    std::vector<uint64_t> ComputeSignature(const std::vector<uint64_t>& set) const;
    std::vector<int64_t>  EncodeSignature(const std::vector<uint64_t>& sig) const;
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    EncryptFeature(const std::vector<int64_t>& feature) const;

    const PiccardParams& GetParams() const { return params_; }
    const BFVContext& GetBFVContext() const { return *bfv_; }

private:
    PiccardParams params_;
    std::unique_ptr<BFVContext> bfv_;
    std::unique_ptr<MinHasher> hasher_;
    std::unique_ptr<SqrtEncoder> encoder_;
};

} // namespace piccard
