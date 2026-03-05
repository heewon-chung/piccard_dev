#include "piccard/protocol/piccard_engine.h"
#include "piccard/core/threshold_poly.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace piccard {

PiccardEngine::PiccardEngine(const PiccardParams& params) : params_(params) {}

void PiccardEngine::Initialize() {
    hasher_ = std::make_unique<MinHasher>(params_.k, params_.hash_range);

    // Initialize BFV first: OpenFHE may select a different ring_dim than
    // what PiccardParams::Validate() computed (e.g. a smaller ring_dim
    // that still satisfies the requested security level).
    bfv_ctx_ = std::make_unique<BFVContext>(params_);
    bfv_ctx_->Initialize();
    params_.ring_dim = bfv_ctx_->GetSlotCount();

    // Create encoder AFTER BFV init so it uses the actual ring_dim
    // for output vector sizing.
    encoder_ = std::make_unique<OneHotEncoder>(params_);
}

std::vector<uint64_t>
PiccardEngine::ComputeSignature(const std::vector<uint64_t>& set) const {
    return hasher_->ComputeSignature(set);
}

std::vector<int64_t>
PiccardEngine::EncodeSignature(const std::vector<uint64_t>& signature) const {
    return encoder_->Encode(signature);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
PiccardEngine::EncryptFeature(const std::vector<int64_t>& feature) const {
    return bfv_ctx_->Encrypt(feature);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
PiccardEngine::ComputeMatchCount(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {

    // Step 1: Slot-wise multiply (AND of one-hot vectors)
    auto product = bfv_ctx_->Multiply(ct_x, ct_y);

    // Step 2: Rotate-and-sum to accumulate all slots into slot 0
    // Uses log2(N) rotate+add steps
    auto result = product;
    for (uint32_t step = 1; step < params_.ring_dim; step *= 2) {
        auto rotated = bfv_ctx_->Rotate(result, static_cast<int>(step));
        result = bfv_ctx_->Add(result, rotated);
    }

    return result;
}

PiccardResult
PiccardEngine::Decode(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    auto values = bfv_ctx_->Decrypt(ct);
    int64_t v = values[0];

    // Bias correction: J_hat = (v/k - 1/m) / (1 - 1/m)
    double k = static_cast<double>(params_.k);
    double m = static_cast<double>(params_.m);

    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);

    // Clamp to [0, 1]: the unbiased estimator can overshoot/undershoot
    // due to statistical variance in bucket collisions
    j_hat = std::max(0.0, std::min(1.0, j_hat));

    return PiccardResult{v, j_hat};
}

PiccardResult
PiccardEngine::ComputeJaccard(const std::vector<uint64_t>& set_x,
                              const std::vector<uint64_t>& set_y) const {
    // Phase 1: MinHash
    auto sig_x = ComputeSignature(set_x);
    auto sig_y = ComputeSignature(set_y);

    // Phase 2: Encode + Encrypt
    auto feat_x = EncodeSignature(sig_x);
    auto feat_y = EncodeSignature(sig_y);
    auto ct_x = EncryptFeature(feat_x);
    auto ct_y = EncryptFeature(feat_y);

    // Phase 3: Compute
    auto ct_result = ComputeMatchCount(ct_x, ct_y);

    // Phase 4: Decode
    return Decode(ct_result);
}

// --- Dynamic variant ---

std::unique_ptr<BottomStructure>
PiccardEngine::CreateBottomStructure(const std::vector<uint64_t>& set) const {
    auto bottom = std::make_unique<BottomStructure>(
        params_.k, params_.bottom_depth, params_.hash_range);
    bottom->Initialize(set);
    return bottom;
}

PiccardResult
PiccardEngine::ComputeJaccardDynamic(const BottomStructure& bottom_x,
                                     const BottomStructure& bottom_y) const {
    // Derive signatures from bottom structures
    auto sig_x = bottom_x.GetSignature();
    auto sig_y = bottom_y.GetSignature();

    // Phase 2-4: same as basic protocol
    auto feat_x = EncodeSignature(sig_x);
    auto feat_y = EncodeSignature(sig_y);
    auto ct_x = EncryptFeature(feat_x);
    auto ct_y = EncryptFeature(feat_y);
    auto ct_result = ComputeMatchCount(ct_x, ct_y);
    return Decode(ct_result);
}

// --- Threshold variant ---

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
PiccardEngine::ComputeThresholdResult(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {

    // Step 1: Slot-wise multiply (same as basic)
    auto product = bfv_ctx_->Multiply(ct_x, ct_y);

    // Step 2: Rotate-and-sum (same as basic)
    auto result = product;
    for (uint32_t step = 1; step < params_.ring_dim; step *= 2) {
        auto rotated = bfv_ctx_->Rotate(result, static_cast<int>(step));
        result = bfv_ctx_->Add(result, rotated);
    }

    // Step 3: Mask slot 0 with e_1 = (1, 0, ..., 0)
    std::vector<int64_t> e1(params_.ring_dim, 0);
    e1[0] = 1;
    result = bfv_ctx_->MultiplyPlain(result, e1);

    // Step 4: Evaluate threshold polynomial u_tau
    auto poly = BuildThresholdPoly(params_.threshold_tau, params_.k,
                                   params_.plaintext_mod);
    result = bfv_ctx_->EvalPolyBFV(result, poly);

    return result;
}

bool PiccardEngine::DecodeThreshold(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    auto values = bfv_ctx_->Decrypt(ct);
    return values[0] >= 1;
}

bool PiccardEngine::ComputeJaccardThreshold(
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y) const {

    // Phase 1: MinHash
    auto sig_x = ComputeSignature(set_x);
    auto sig_y = ComputeSignature(set_y);

    // Phase 2: Encode + Encrypt
    auto feat_x = EncodeSignature(sig_x);
    auto feat_y = EncodeSignature(sig_y);
    auto ct_x = EncryptFeature(feat_x);
    auto ct_y = EncryptFeature(feat_y);

    // Phase 3: Threshold compute
    auto ct_result = ComputeThresholdResult(ct_x, ct_y);

    // Phase 4: Decode
    return DecodeThreshold(ct_result);
}

} // namespace piccard
