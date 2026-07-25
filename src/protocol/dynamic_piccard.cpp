#include "protocol/dynamic_piccard.h"

namespace piccard {

DynamicPiccard::DynamicPiccard(const PiccardParams& params)
    : Piccard(params) {}

std::unique_ptr<BottomStructure>
DynamicPiccard::InitSet(const std::vector<uint64_t>& set) const {
    auto bottom = std::make_unique<BottomStructure>(
        params_.k, params_.bottom_depth, params_.hash_range, params_.hash_seed);
    bottom->Initialize(set);
    return bottom;
}

void DynamicPiccard::Insert(BottomStructure& bs, uint64_t elem) const {
    bs.Insert(elem);
}

void DynamicPiccard::Delete(BottomStructure& bs, uint64_t elem) const {
    bs.Delete(elem);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
DynamicPiccard::Encrypt(const BottomStructure& bs) const {
    auto sig = bs.GetSignature();
    auto feat = EncodeSignature(sig);
    return EncryptFeature(feat);
}

JaccardResult
DynamicPiccard::Run(const BottomStructure& bs_x,
                    const BottomStructure& bs_y) const {
    auto ct_x = Encrypt(bs_x);
    auto ct_y = Encrypt(bs_y);
    auto ct_result = Evaluate(ct_x, ct_y);
    return Decrypt(ct_result);
}

} // namespace piccard
