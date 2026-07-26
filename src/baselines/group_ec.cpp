/**
 * @file group_ec.cpp
 * @brief NIST P-256 group backend (OpenSSL-backed). 128-bit security
 *        (FIPS 186-4); the modern/fastest-reasonable secondary backend
 *        alongside the FF group (see group_ff.cpp).
 */

#include "baselines/group_ec.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>
#include <stdexcept>
#include <vector>

namespace piccard {
namespace baselines {

namespace {

constexpr size_t kElementBytes = 33;  // compressed P-256 point
constexpr size_t kExponentBytes = 32;

void AppendBE32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

// GroupElement wrapping an owned EC_POINT*.
struct EcElement : public GroupElement {
    EC_POINT* point;
    explicit EcElement(EC_POINT* pt) : point(pt) {}
    ~EcElement() override { EC_POINT_free(point); }
    EcElement(const EcElement&) = delete;
    EcElement& operator=(const EcElement&) = delete;
};

EC_POINT* AsPoint(const ElementPtr& e) {
    return static_cast<const EcElement*>(e.get())->point;
}

ElementPtr WrapPoint(EC_POINT* pt) { return std::make_shared<EcElement>(pt); }

class EcGroup : public Group {
public:
    EcGroup() {
        group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group_) {
            throw std::runtime_error("EcGroup: EC_GROUP_new_by_curve_name failed");
        }
        ctx_ = BN_CTX_new();
        if (!ctx_) {
            EC_GROUP_free(group_);
            throw std::runtime_error("EcGroup: BN_CTX_new failed");
        }
        order_ = BN_new();
        p_ = BN_new();
        BIGNUM* a = BN_new();
        BIGNUM* b = BN_new();
        if (!order_ || !p_ || !a || !b ||
            EC_GROUP_get_order(group_, order_, ctx_) != 1 ||
            EC_GROUP_get_curve(group_, p_, a, b, ctx_) != 1) {
            BN_free(a);
            BN_free(b);
            BN_free(order_);
            BN_free(p_);
            BN_CTX_free(ctx_);
            EC_GROUP_free(group_);
            throw std::runtime_error("EcGroup: failed to read curve parameters");
        }
        BN_free(a);
        BN_free(b);
    }

    ~EcGroup() override {
        BN_free(order_);
        BN_free(p_);
        BN_CTX_free(ctx_);
        EC_GROUP_free(group_);
    }

    const char* Name() const override { return "EC-P256"; }

    std::vector<uint8_t> RandomExponent() const override {
        BIGNUM* bn = BN_new();
        if (!bn) throw std::runtime_error("EcGroup::RandomExponent: BN_new failed");
        while (true) {
            if (BN_priv_rand_range(bn, order_) != 1) {
                BN_free(bn);
                throw std::runtime_error("EcGroup::RandomExponent: BN_priv_rand_range failed");
            }
            if (!BN_is_zero(bn)) break;
        }
        std::vector<uint8_t> out(kExponentBytes);
        BN_bn2binpad(bn, out.data(), static_cast<int>(kExponentBytes));
        BN_free(bn);
        return out;
    }

    ElementPtr HashToGroup(const std::vector<uint8_t>& msg,
                            size_t* out_hash_exps) const override {
        // Try-and-increment with an unbiased y-bit drawn from the hash itself
        // (not fixed to 0), so both square roots are reachable. P-256's
        // cofactor is 1, so any on-curve, non-infinity point is a valid
        // group element -- no cofactor exponentiation, hence out_hash_exps
        // is left untouched (EC contributes 0 to hash_exps).
        uint32_t ctr = 0;
        while (true) {
            std::vector<uint8_t> input;
            input.reserve(msg.size() + 5);
            input.push_back(0x11);  // domain separation tag: EC hash-to-group
            input.insert(input.end(), msg.begin(), msg.end());
            AppendBE32(input, ctr);

            std::array<uint8_t, SHA256_DIGEST_LENGTH> h{};
            SHA256(input.data(), input.size(), h.data());

            BIGNUM* x = BN_bin2bn(h.data(), static_cast<int>(h.size()), nullptr);
            if (!x) {
                throw std::runtime_error("EcGroup::HashToGroup: BN_bin2bn failed");
            }
            if (BN_mod(x, x, p_, ctx_) != 1) {
                BN_free(x);
                throw std::runtime_error("EcGroup::HashToGroup: BN_mod failed");
            }
            int y_bit = h[SHA256_DIGEST_LENGTH - 1] & 1;

            EC_POINT* pt = EC_POINT_new(group_);
            if (!pt) {
                BN_free(x);
                throw std::runtime_error("EcGroup::HashToGroup: EC_POINT_new failed");
            }
            int ok = EC_POINT_set_compressed_coordinates(group_, pt, x, y_bit, ctx_);
            BN_free(x);

            if (ok == 1 && !EC_POINT_is_at_infinity(group_, pt) &&
                EC_POINT_is_on_curve(group_, pt, ctx_) == 1) {
                (void)out_hash_exps;  // unchanged: no cofactor exponentiation for EC
                return WrapPoint(pt);
            }
            EC_POINT_free(pt);
            ++ctr;
        }
    }

    ElementPtr Exp(const ElementPtr& base, const std::vector<uint8_t>& exp) const override {
        BIGNUM* e = BN_bin2bn(exp.data(), static_cast<int>(exp.size()), nullptr);
        if (!e) {
            throw std::runtime_error("EcGroup::Exp: BN_bin2bn failed");
        }
        EC_POINT* result = EC_POINT_new(group_);
        if (!result) {
            BN_free(e);
            throw std::runtime_error("EcGroup::Exp: EC_POINT_new failed");
        }
        if (EC_POINT_mul(group_, result, nullptr, AsPoint(base), e, ctx_) != 1) {
            BN_free(e);
            EC_POINT_free(result);
            throw std::runtime_error("EcGroup::Exp: EC_POINT_mul failed");
        }
        BN_free(e);
        return WrapPoint(result);
    }

    ElementPtr ExpInverse(const ElementPtr& base,
                           const std::vector<uint8_t>& exp) const override {
        BIGNUM* e = BN_bin2bn(exp.data(), static_cast<int>(exp.size()), nullptr);
        if (!e) {
            throw std::runtime_error("EcGroup::ExpInverse: BN_bin2bn failed");
        }
        BIGNUM* inv = BN_new();
        if (!inv) {
            BN_free(e);
            throw std::runtime_error("EcGroup::ExpInverse: BN_new failed");
        }
        if (!BN_mod_inverse(inv, e, order_, ctx_)) {
            BN_free(e);
            BN_free(inv);
            throw std::runtime_error("EcGroup::ExpInverse: exponent not invertible mod order");
        }
        EC_POINT* result = EC_POINT_new(group_);
        if (!result) {
            BN_free(e);
            BN_free(inv);
            throw std::runtime_error("EcGroup::ExpInverse: EC_POINT_new failed");
        }
        if (EC_POINT_mul(group_, result, nullptr, AsPoint(base), inv, ctx_) != 1) {
            BN_free(e);
            BN_free(inv);
            EC_POINT_free(result);
            throw std::runtime_error("EcGroup::ExpInverse: EC_POINT_mul failed");
        }
        BN_free(e);
        BN_free(inv);
        return WrapPoint(result);
    }

    std::vector<uint8_t> Serialize(const ElementPtr& e) const override {
        std::vector<uint8_t> out(kElementBytes);
        size_t written = EC_POINT_point2oct(group_, AsPoint(e), POINT_CONVERSION_COMPRESSED,
                                             out.data(), out.size(), ctx_);
        if (written != kElementBytes) {
            throw std::runtime_error("EcGroup::Serialize: unexpected compressed point length");
        }
        return out;
    }

    size_t ElementBytes() const override { return kElementBytes; }
    size_t ExponentBytes() const override { return kExponentBytes; }

    bool InSubgroup(const ElementPtr& e) const override {
        EC_POINT* pt = AsPoint(e);
        if (EC_POINT_is_at_infinity(group_, pt)) return false;  // never identity
        return EC_POINT_is_on_curve(group_, pt, ctx_) == 1;      // cofactor 1: on-curve suffices
    }

private:
    EC_GROUP* group_;
    BN_CTX* ctx_;
    BIGNUM* order_;
    BIGNUM* p_;
};

}  // namespace

std::unique_ptr<Group> MakeEcGroup() { return std::make_unique<EcGroup>(); }

}  // namespace baselines
}  // namespace piccard
