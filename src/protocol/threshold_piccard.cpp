#include "protocol/threshold_piccard.h"
#include "core/threshold_poly.h"

namespace piccard {

ThresholdPiccard::ThresholdPiccard(const PiccardParams& params)
    : piccard_(params) {}

void ThresholdPiccard::KeyGen() {
    piccard_.KeyGen();

    // Precompute threshold polynomial once (bug fix: was per-Evaluate)
    threshold_poly_ = BuildThresholdPoly(
        piccard_.GetParams().threshold_tau,
        piccard_.GetParams().k,
        piccard_.GetParams().plaintext_mod);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
ThresholdPiccard::Encrypt(const std::vector<uint64_t>& set) const {
    return piccard_.Encrypt(set);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
ThresholdPiccard::EvaluateRaw(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {

    // Step 1-2: REUSE Piccard's multiply + rotate-and-sum
    //
    // Raw on purpose: a mask and a degree-k polynomial are applied below, and
    // the flooding mask would exhaust the modulus long before they finished.
    // This method floods its own result at the end instead.
    auto rotated_sum = piccard_.EvaluateRaw(ct_x, ct_y);

    // Step 3: Mask slot 0 with e_1 = (1, 0, ..., 0)
    std::vector<int64_t> e1(piccard_.GetParams().ring_dim, 0);
    e1[0] = 1;
    auto masked = piccard_.GetBFVContext().MultiplyPlain(rotated_sum, e1);

    // Step 4: Evaluate threshold polynomial (precomputed in KeyGen)
    return piccard_.GetBFVContext().EvalPolyBFV(masked, threshold_poly_);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
ThresholdPiccard::Evaluate(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y) const {
    return piccard_.GetBFVContext().Flood(EvaluateRaw(ct_x, ct_y));
}

bool ThresholdPiccard::Decrypt(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    auto values = piccard_.GetBFVContext().Decrypt(ct);
    return values[0] >= 1;
}

bool ThresholdPiccard::Run(const std::vector<uint64_t>& set_x,
                           const std::vector<uint64_t>& set_y) const {
    auto ct_x = Encrypt(set_x);
    auto ct_y = Encrypt(set_y);
    auto ct_result = Evaluate(ct_x, ct_y);
    return Decrypt(ct_result);
}

const PiccardParams& ThresholdPiccard::GetParams() const {
    return piccard_.GetParams();
}

const BFVContext& ThresholdPiccard::GetBFVContext() const {
    return piccard_.GetBFVContext();
}

} // namespace piccard
