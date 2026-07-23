#pragma once

#include "protocol/piccard.h"
#include "core/bottom_structure.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace piccard {

class DynamicPiccard : public Piccard {
public:
    explicit DynamicPiccard(const PiccardParams& params);

    // Bring base-class overloads into scope (C++ name hiding)
    using Piccard::Encrypt;
    using Piccard::Run;

    // ── Dynamic-specific API ─────────────────────────────────────

    std::unique_ptr<BottomStructure>
    InitSet(const std::vector<uint64_t>& set) const;

    void Insert(BottomStructure& bs, uint64_t elem) const;
    void Delete(BottomStructure& bs, uint64_t elem) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Encrypt(const BottomStructure& bs) const;

    JaccardResult Run(const BottomStructure& bs_x,
                      const BottomStructure& bs_y) const;

    // ── Inherited unchanged ──────────────────────────────────────
    // void KeyGen();
    // Ciphertext Evaluate(ct_x, ct_y);
    // JaccardResult Decrypt(ct);
};

} // namespace piccard
