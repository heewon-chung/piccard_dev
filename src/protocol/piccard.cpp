#include "protocol/piccard.h"

#include <algorithm>

namespace piccard {

Piccard::Piccard(const PiccardParams& params) : params_(params) {}

void Piccard::SetHashSeed(uint64_t seed) {
    params_.hash_seed = seed;
    if (hasher_) {
        hasher_ = std::make_unique<MinHasher>(params_.k, params_.hash_range,
                                              seed);
    }
}

void Piccard::KeyGen() {
    hasher_ = std::make_unique<MinHasher>(params_.k, params_.hash_range,
                                          params_.hash_seed);

    // Initialize BFV first: OpenFHE may select a different ring_dim than
    // what PiccardParams::Validate() computed (e.g. a smaller ring_dim
    // that still satisfies the requested security level).
    bfv_ = std::make_unique<BFVContext>(params_);
    bfv_->Initialize();
    params_.ring_dim = bfv_->GetSlotCount();

    // Create encoder AFTER BFV init so it uses the actual ring_dim
    // for output vector sizing.
    encoder_ = std::make_unique<OneHotEncoder>(params_);
}

std::vector<uint64_t>
Piccard::ComputeSignature(const std::vector<uint64_t>& set) const {
    return hasher_->ComputeSignature(set);
}

std::vector<int64_t>
Piccard::EncodeSignature(const std::vector<uint64_t>& sig) const {
    return encoder_->Encode(sig);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
Piccard::EncryptFeature(const std::vector<int64_t>& feature) const {
    return bfv_->Encrypt(feature);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
Piccard::Encrypt(const std::vector<uint64_t>& set) const {
    auto sig = ComputeSignature(set);
    auto feat = EncodeSignature(sig);
    return EncryptFeature(feat);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
Piccard::EvaluateRaw(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {

    // Step 1: Slot-wise multiply (AND of one-hot vectors)
    auto product = bfv_->Multiply(ct_x, ct_y);

    // Step 2: Rotate-and-sum to accumulate all slots into slot 0
    auto result = product;
    for (uint32_t step = 1; step < params_.ring_dim; step *= 2) {
        auto rotated = bfv_->Rotate(result, static_cast<int>(step));
        result = bfv_->Add(result, rotated);
    }

    return result;
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
Piccard::Evaluate(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {
    return bfv_->Flood(EvaluateRaw(ct_x, ct_y));
}

JaccardResult
Piccard::Decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    auto values = bfv_->Decrypt(ct);
    int64_t v = values[0];

    // Bias correction: J_hat = (v/k - 1/m) / (1 - 1/m)
    double k = static_cast<double>(params_.k);
    double m = static_cast<double>(params_.m);

    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);

    // Clamp to [0, 1]
    j_hat = std::max(0.0, std::min(1.0, j_hat));

    return JaccardResult{v, j_hat};
}

JaccardResult
Piccard::Run(const std::vector<uint64_t>& set_x,
             const std::vector<uint64_t>& set_y) const {
    auto ct_x = Encrypt(set_x);
    auto ct_y = Encrypt(set_y);
    auto ct_result = Evaluate(ct_x, ct_y);
    return Decrypt(ct_result);
}

} // namespace piccard
