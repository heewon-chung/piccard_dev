#pragma once

#include "util/params.h"
#include "core/minhash.h"
#include "core/onehot_encoder.h"
#include "fhe/bfv_context.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace piccard {

struct JaccardResult {
    int64_t match_count;        // Raw slot-0 value after rotate-and-sum
    double jaccard_estimate;    // Bias-corrected: (v/k - 1/m) / (1 - 1/m)
};

class Piccard {
public:
    explicit Piccard(const PiccardParams& params);

    // ── High-level protocol API (paper-aligned) ─────────────────

    void KeyGen();

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Encrypt(const std::vector<uint64_t>& set) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Evaluate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
             const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;

    JaccardResult Decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    JaccardResult Run(const std::vector<uint64_t>& set_x,
                      const std::vector<uint64_t>& set_y) const;

    // ── Advanced/benchmarking API (public, documented) ──────────

    std::vector<uint64_t> ComputeSignature(const std::vector<uint64_t>& set) const;
    std::vector<int64_t>  EncodeSignature(const std::vector<uint64_t>& sig) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    EncryptFeature(const std::vector<int64_t>& feature) const;

    const PiccardParams& GetParams() const { return params_; }
    const BFVContext& GetBFVContext() const { return *bfv_; }

protected:
    PiccardParams params_;
    std::unique_ptr<BFVContext> bfv_;
    std::unique_ptr<MinHasher> hasher_;
    std::unique_ptr<OneHotEncoder> encoder_;
};

} // namespace piccard
