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

    // Replace the public CRS seed. Invariant: always updates
    // params_.hash_seed, and rebuilds the MinHasher if KeyGen() has already
    // run. The BFV context and keys do not depend on the hash family, so they
    // are preserved and accuracy trials can resample the CRS without paying
    // for KeyGen again. Must not be called concurrently with a Run()/Encrypt()
    // on the same object.
    void SetHashSeed(uint64_t seed);

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
