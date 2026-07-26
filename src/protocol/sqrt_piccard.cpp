#include "protocol/sqrt_piccard.h"

#include <algorithm>

namespace piccard {

SqrtPiccard::SqrtPiccard(const PiccardParams& params) : params_(params) {}

void SqrtPiccard::SetHashSeed(uint64_t seed) {
    params_.hash_seed = seed;
    if (hasher_) {
        hasher_ = std::make_unique<MinHasher>(params_.k, params_.hash_range,
                                              seed);
    }
}

void SqrtPiccard::KeyGen() {
    hasher_ = std::make_unique<MinHasher>(params_.k, params_.hash_range,
                                          params_.hash_seed);

    bfv_ = std::make_unique<BFVContext>(params_);
    bfv_->Initialize();
    params_.ring_dim = bfv_->GetSlotCount();

    encoder_ = std::make_unique<SqrtEncoder>(params_);
}

std::vector<uint64_t>
SqrtPiccard::ComputeSignature(const std::vector<uint64_t>& set) const {
    return hasher_->ComputeSignature(set);
}

std::vector<int64_t>
SqrtPiccard::EncodeSignature(const std::vector<uint64_t>& sig) const {
    return encoder_->Encode(sig);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
SqrtPiccard::EncryptFeature(const std::vector<int64_t>& feature) const {
    return bfv_->Encrypt(feature);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
SqrtPiccard::Encrypt(const std::vector<uint64_t>& set) const {
    auto sig = ComputeSignature(set);
    auto feat = EncodeSignature(sig);
    return EncryptFeature(feat);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
SqrtPiccard::Evaluate(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {

    uint32_t b = params_.sqrt_base;
    uint32_t block = 2 * b;

    // Step 1: Component-wise multiply (depth 1)
    auto product = bfv_->Multiply(ct_x, ct_y);

    // Step 2: Intra-digit rotate-and-sum
    // Collapse each b-sized one-hot block to its first slot.
    // After this, position i*b holds the sum of the b-sized sub-block
    // (0 or 1 for one-hot products). Non-target positions hold cross-block
    // sums but will be discarded by block_mask_ later.
    auto digit_sums = product;
    for (uint32_t step = 1; step < b; step *= 2) {
        auto rotated = bfv_->Rotate(digit_sums, static_cast<int>(step));
        digit_sums = bfv_->Add(digit_sums, rotated);
    }
    // NOTE: No plaintext masking anywhere in this pipeline.
    // Periodic masks (digit_mask_, block_mask_) have large polynomial
    // coefficient norms in the NTT domain, which amplifies noise beyond
    // the depth-2 budget and causes decryption failure.
    // Instead, we rely on the step-4 rotate-and-sum starting at step=2b
    // to naturally accumulate only the correct positions into slot 0.

    // Step 3: AND the two digits (depth 2)
    // Rotate by b to align hi-digit indicator with lo-digit position.
    // At position i*2b: digit_sums holds lo_match, shifted holds hi_match.
    auto shifted = bfv_->Rotate(digit_sums, static_cast<int>(b));
    auto anded = bfv_->Multiply(digit_sums, shifted);

    // Step 4: Sum across k signatures
    // Target values are at positions 0, 2b, 4b, ..., (k-1)*2b.
    // Rotate-and-sum with step=2b, 4b, 8b, ... accumulates exactly
    // these positions (plus zero-padded padding positions) into slot 0.
    auto result = anded;
    for (uint32_t step = block; step < params_.ring_dim; step *= 2) {
        auto rotated = bfv_->Rotate(result, static_cast<int>(step));
        result = bfv_->Add(result, rotated);
    }

    // This ciphertext goes to the receiver, so it carries the masking noise
    // the security proof requires.
    return bfv_->Flood(result);
}

JaccardResult
SqrtPiccard::Decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    auto values = bfv_->Decrypt(ct);
    int64_t v = values[0];

    // Bias correction: J_hat = (v/k - 1/m) / (1 - 1/m)
    double k = static_cast<double>(params_.k);
    double m = static_cast<double>(params_.m);

    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);

    j_hat = std::max(0.0, std::min(1.0, j_hat));

    return JaccardResult{v, j_hat};
}

JaccardResult
SqrtPiccard::Run(const std::vector<uint64_t>& set_x,
                 const std::vector<uint64_t>& set_y) const {
    auto ct_x = Encrypt(set_x);
    auto ct_y = Encrypt(set_y);
    auto ct_result = Evaluate(ct_x, ct_y);
    return Decrypt(ct_result);
}

} // namespace piccard
