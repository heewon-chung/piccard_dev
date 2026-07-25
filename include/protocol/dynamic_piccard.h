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
    // void SetHashSeed(uint64_t);  -- structures built afterwards use the new
    //                                 CRS; ones built before are rejected below.

private:
    // Throws if `bs` was built under a different CRS than the one currently
    // configured. Checked where the structure is consumed rather than where it
    // is created: signatures only become incomparable when they meet, and a
    // creation-time check would put the rejection out of a test's reach.
    void RequireCurrentHashCrs(const BottomStructure& bs) const;
};

} // namespace piccard
