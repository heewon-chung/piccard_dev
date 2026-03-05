#pragma once

#include "piccard/util/params.h"
#include "piccard/core/minhash.h"
#include "piccard/core/onehot_encoder.h"
#include "piccard/fhe/bfv_context.h"
#include "piccard/core/bottom_structure.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace piccard {

struct PiccardResult {
    int64_t match_count;        // Raw slot-0 value after rotate-and-sum
    double jaccard_estimate;    // Bias-corrected: (v/k - 1/m) / (1 - 1/m)
};

class PiccardEngine {
public:
    explicit PiccardEngine(const PiccardParams& params);

    void Initialize();

    // Phase 1: MinHash (client-side)
    std::vector<uint64_t> ComputeSignature(const std::vector<uint64_t>& set) const;

    // Phase 2: Encode + Encrypt (client-side)
    std::vector<int64_t> EncodeSignature(const std::vector<uint64_t>& signature) const;
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    EncryptFeature(const std::vector<int64_t>& feature) const;

    // Phase 3: Compute (cloud-side)
    // Multiply slot-wise then rotate-and-sum to get match count in slot 0
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    ComputeMatchCount(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
                      const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;

    // Phase 4: Decode (receiver-side)
    PiccardResult Decode(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    // Convenience: full protocol
    PiccardResult ComputeJaccard(const std::vector<uint64_t>& set_x,
                                 const std::vector<uint64_t>& set_y) const;

    // --- Dynamic variant (Paper Section 3.2, Algorithms 3-5) ---

    // Create a bottom structure initialized from a set
    std::unique_ptr<BottomStructure> CreateBottomStructure(
        const std::vector<uint64_t>& set) const;

    // Full protocol using bottom structures (supports dynamic updates)
    PiccardResult ComputeJaccardDynamic(const BottomStructure& bottom_x,
                                        const BottomStructure& bottom_y) const;

    // --- Threshold variant (Paper Section 3.2) ---

    // Phase 3 variant: threshold computation
    // Returns ciphertext where slot 0 = 1 if match_count >= tau, else 0
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    ComputeThresholdResult(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const;

    // Phase 4 variant: decode threshold result
    bool DecodeThreshold(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    // Convenience: full threshold protocol
    bool ComputeJaccardThreshold(const std::vector<uint64_t>& set_x,
                                 const std::vector<uint64_t>& set_y) const;

    const PiccardParams& GetParams() const { return params_; }
    const BFVContext& GetBFVContext() const { return *bfv_ctx_; }

private:
    PiccardParams params_;
    std::unique_ptr<BFVContext> bfv_ctx_;
    std::unique_ptr<MinHasher> hasher_;
    std::unique_ptr<OneHotEncoder> encoder_;
};

} // namespace piccard
