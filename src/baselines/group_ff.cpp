/**
 * @file group_ff.cpp
 * @brief DSA-style Z_p^* group backend (|p|=3072, |q|=256), GMP-backed.
 *
 * Domain parameters below were generated once (2026-07-26, OpenSSL 3.6.3 on
 * the dev machine) via:
 *
 *   openssl genpkey -genparam -algorithm DSA \
 *     -pkeyopt dsa_paramgen_bits:3072 -pkeyopt dsa_paramgen_q_bits:256 \
 *     -out dsa3072.pem
 *   openssl pkeyparam -in dsa3072.pem -text   # copy P, Q, G hex digits below
 *
 * They are DSA-style (q | p-1, |q|=256), not a safe prime (whose cofactor
 * would be ~3071 bits, not 256) -- see BCG12 plan Task 0.2 design notes.
 * Independently re-verified (Python, outside GMP) before being pasted here:
 * p and q are prime (Miller-Rabin, 40 rounds), q | (p-1), 1 < g < p, g != 1,
 * g^q mod p == 1. `ValidateParams()` below re-checks the same properties
 * with GMP at every construction. Provenance detail (bit lengths, security
 * target justification) is in docs/bcg12_baseline_notes.md.
 */

#include "baselines/group_ff.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <gmp.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

namespace piccard {
namespace baselines {

namespace {

// p: 3072-bit safe-prime-free DSA modulus.
constexpr const char* kPHex =
    "9ac5994bcabedd6fb1f0487f4c52a094c017baae9225aa1f71ef1f2aaa82563bcbdcf584"
    "edb586103de2f6c5a7abc1d5dc2379182f386c17a0d072ee83b5006171f6fbede98fcaad"
    "a63e629a6d006610b252c328d4e03ab41df0a003193fb442077b6c132e849df5bb706432"
    "98a3d0e9dea4940fc82c4cb03ee6758942555256472c6e54e0f70b63a5f5f4e949aa8285"
    "c1570a72dc017b8fc3b854f3b505f63a8c7450366f314db4cf7bbb2dd3e61130a9a038c2"
    "1a2b78e4493dcbe32475049be94d89139f6a77c61b9a07a26ad19da4004499b06d0d25ce"
    "fe95f763f37cd972d18115e94752133021fa8779367fce691c068459acb4217844d01d03"
    "23f6b0565f3388fd03a2a80a14739f508d93d76790fc15fe7cc88f1c31f0f081f1668b9b"
    "e3c89d1ab88f27100133a86530e2afb80a8ad5063ad543c78b49b0b092cfb1a6a6a32d84"
    "91340cac47a9f6b4a179c798b3aeca5495ae29ee26f6bc555546a5411982e0aa67675b3f"
    "b407ccd5170144c75cd9a5d3bcd7c725e43a89c297fd606f";

// q: 256-bit prime divisor of p-1.
constexpr const char* kQHex =
    "ba93a088af77bc4bd677580bfcede431033182def3e5bf0ff23bcffbbea631bd";

// g: generator of the order-q subgroup.
constexpr const char* kGHex =
    "6d6fac3b5f857f9932be1e27888cc40a35781796533d8015684b72213c8413be9b1fc5f2"
    "e53a2019bd6e4f459397edb7a7ce27070af41a85edbac83fb1222d53f59c62a69f62c750"
    "66d9219e965c38cfbe4cf5be0b2ca3972c3c761c060067570184f5786aae646b59f9ba96"
    "b853fdda9807e72c6d35793d3765bfee1e2865cadee1d994cbbf3368c5ab6d6ff9e45fff"
    "209d5fc3a0afa42d0bc6aa44071e10aa114a852eda95452d576b30b9acebb413e0dab0fc"
    "a1b1b9ae5d301f976b34c2b298dc99e8697ac44ab2207008585e6f33f135160178043ea3"
    "6362bc7bd7d5b8d5d7442d09124f30d5ef08dbb290a057c7cb46c8002832964947f54f4c"
    "cfa4704049698625bc874016581721fe6f16b4f19671359c349206a73a2ff2a5f7c870e7"
    "bb038a709251c19ee2fb1aa1a751d2f8b8fb7ef7e392d7f7dd295abe655fa0db7f8da7af"
    "6d7adc5ab3b23cc57dab2560b66cf53eb403d32d4332a44a119359f1b4e0fdaae15e623d"
    "6e875d9da8f9ec01673615ff7fd0f91589d42fc1056c2cf3";

constexpr size_t kPBits = 3072;
constexpr size_t kQBits = 256;
constexpr size_t kElementBytes = kPBits / 8;   // 384
constexpr size_t kExponentBytes = kQBits / 8;  // 32
// MGF1-SHA512 mask length for hash-to-group: |p| bytes + 128-bit statistical
// security margin so `t mod p` is within negligible distance of uniform.
constexpr size_t kMaskLen = kElementBytes + 16;  // 400

void AppendBE32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

// PKCS#1 MGF1 built on SHA-512.
std::vector<uint8_t> Mgf1Sha512(const std::vector<uint8_t>& seed, size_t mask_len) {
    std::vector<uint8_t> mask;
    mask.reserve(mask_len + SHA512_DIGEST_LENGTH);
    uint32_t counter = 0;
    while (mask.size() < mask_len) {
        std::vector<uint8_t> input = seed;
        AppendBE32(input, counter);
        std::array<uint8_t, SHA512_DIGEST_LENGTH> digest{};
        SHA512(input.data(), input.size(), digest.data());
        mask.insert(mask.end(), digest.begin(), digest.end());
        ++counter;
    }
    mask.resize(mask_len);
    return mask;
}

// GroupElement wrapping a single mpz_t (an element of Z_p^*).
struct FFElement : public GroupElement {
    mpz_t value;
    FFElement() { mpz_init(value); }
    ~FFElement() override { mpz_clear(value); }
    FFElement(const FFElement&) = delete;
    FFElement& operator=(const FFElement&) = delete;
};

const mpz_t& AsMpz(const ElementPtr& e) {
    return static_cast<const FFElement*>(e.get())->value;
}

ElementPtr WrapMpz(const mpz_t value) {
    auto elem = std::make_shared<FFElement>();
    mpz_set(elem->value, value);
    return elem;
}

class FFGroup : public Group {
public:
    FFGroup() {
        mpz_init(p_);
        mpz_init(q_);
        mpz_init(g_);
        mpz_init(cofactor_);

        try {
            if (mpz_set_str(p_, kPHex, 16) != 0) {
                throw std::runtime_error("FFGroup: failed to parse p hex constant");
            }
            if (mpz_set_str(q_, kQHex, 16) != 0) {
                throw std::runtime_error("FFGroup: failed to parse q hex constant");
            }
            if (mpz_set_str(g_, kGHex, 16) != 0) {
                throw std::runtime_error("FFGroup: failed to parse g hex constant");
            }

            ValidateParams();  // p,q prime; q|(p-1); 1<g<p; g^q==1 mod p; g!=1

            mpz_t p_minus_1;
            mpz_init(p_minus_1);
            mpz_sub_ui(p_minus_1, p_, 1);
            mpz_divexact(cofactor_, p_minus_1, q_);  // exact: validated q|(p-1) above
            mpz_clear(p_minus_1);
        } catch (...) {
            mpz_clear(p_);
            mpz_clear(q_);
            mpz_clear(g_);
            mpz_clear(cofactor_);
            throw;
        }
    }

    ~FFGroup() override {
        mpz_clear(p_);
        mpz_clear(q_);
        mpz_clear(g_);
        mpz_clear(cofactor_);
    }

    const char* Name() const override { return "FF-3072/256"; }

    std::vector<uint8_t> RandomExponent() const override {
        while (true) {
            std::vector<uint8_t> buf(kExponentBytes);
            if (RAND_priv_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
                throw std::runtime_error("FFGroup::RandomExponent: RAND_priv_bytes failed");
            }
            mpz_t x;
            mpz_init(x);
            mpz_import(x, buf.size(), 1, 1, 0, 0, buf.data());
            bool reject = (mpz_cmp_ui(x, 0) == 0) || (mpz_cmp(x, q_) >= 0);
            mpz_clear(x);
            if (!reject) return buf;
        }
    }

    ElementPtr HashToGroup(const std::vector<uint8_t>& msg,
                            size_t* out_hash_exps) const override {
        size_t hash_exps = 0;
        uint32_t retry = 0;
        mpz_t t, e;
        mpz_init(t);
        mpz_init(e);
        while (true) {
            std::vector<uint8_t> input;
            input.reserve(msg.size() + 5);
            input.push_back(0x10);  // domain separation tag: FF hash-to-group
            input.insert(input.end(), msg.begin(), msg.end());
            AppendBE32(input, retry);

            std::vector<uint8_t> mask = Mgf1Sha512(input, kMaskLen);
            mpz_import(t, mask.size(), 1, 1, 0, 0, mask.data());
            mpz_mod(t, t, p_);

            if (mpz_cmp_ui(t, 0) == 0) {
                ++retry;
                continue;
            }

            mpz_powm(e, t, cofactor_, p_);  // cofactor exponentiation: e = t^{(p-1)/q} mod p
            ++hash_exps;

            if (mpz_cmp_ui(e, 1) == 0) {  // reject identity, resample
                ++retry;
                continue;
            }
            break;
        }
        mpz_clear(t);
        ElementPtr result = WrapMpz(e);
        mpz_clear(e);
        if (out_hash_exps) *out_hash_exps += hash_exps;
        return result;
    }

    ElementPtr Exp(const ElementPtr& base, const std::vector<uint8_t>& exp) const override {
        mpz_t e, result;
        mpz_init(e);
        mpz_init(result);
        mpz_import(e, exp.size(), 1, 1, 0, 0, exp.data());
        mpz_powm(result, AsMpz(base), e, p_);
        ElementPtr out = WrapMpz(result);
        mpz_clear(e);
        mpz_clear(result);
        return out;
    }

    ElementPtr ExpInverse(const ElementPtr& base,
                           const std::vector<uint8_t>& exp) const override {
        mpz_t e, inv, result;
        mpz_init(e);
        mpz_init(inv);
        mpz_init(result);
        mpz_import(e, exp.size(), 1, 1, 0, 0, exp.data());
        if (mpz_invert(inv, e, q_) == 0) {
            mpz_clear(e);
            mpz_clear(inv);
            mpz_clear(result);
            throw std::runtime_error("FFGroup::ExpInverse: exponent not invertible mod q");
        }
        mpz_powm(result, AsMpz(base), inv, p_);
        ElementPtr out = WrapMpz(result);
        mpz_clear(e);
        mpz_clear(inv);
        mpz_clear(result);
        return out;
    }

    std::vector<uint8_t> Serialize(const ElementPtr& e) const override {
        std::vector<uint8_t> out(kElementBytes, 0);
        std::vector<uint8_t> tmp(kElementBytes, 0);
        size_t count = 0;
        mpz_export(tmp.data(), &count, 1, 1, 0, 0, AsMpz(e));
        std::copy(tmp.begin(), tmp.begin() + static_cast<long>(count),
                  out.begin() + static_cast<long>(kElementBytes - count));
        return out;
    }

    size_t ElementBytes() const override { return kElementBytes; }
    size_t ExponentBytes() const override { return kExponentBytes; }

    bool InSubgroup(const ElementPtr& e) const override {
        const mpz_t& v = AsMpz(e);
        if (mpz_cmp_ui(v, 1) <= 0) return false;  // must be >1 (never identity)
        if (mpz_cmp(v, p_) >= 0) return false;    // must be < p
        mpz_t r;
        mpz_init(r);
        mpz_powm(r, v, q_, p_);
        bool ok = (mpz_cmp_ui(r, 1) == 0);
        mpz_clear(r);
        return ok;
    }

private:
    void ValidateParams() const {
        if (mpz_probab_prime_p(p_, 40) == 0) {
            throw std::runtime_error("FFGroup: p is not prime");
        }
        if (mpz_probab_prime_p(q_, 40) == 0) {
            throw std::runtime_error("FFGroup: q is not prime");
        }
        mpz_t p_minus_1, rem;
        mpz_init(p_minus_1);
        mpz_init(rem);
        mpz_sub_ui(p_minus_1, p_, 1);
        mpz_mod(rem, p_minus_1, q_);
        bool q_divides = (mpz_cmp_ui(rem, 0) == 0);
        mpz_clear(p_minus_1);
        mpz_clear(rem);
        if (!q_divides) {
            throw std::runtime_error("FFGroup: q does not divide p-1");
        }
        if (!(mpz_cmp_ui(g_, 1) > 0 && mpz_cmp(g_, p_) < 0)) {
            throw std::runtime_error("FFGroup: g out of range (1,p)");
        }
        mpz_t gq;
        mpz_init(gq);
        mpz_powm(gq, g_, q_, p_);
        bool ok = (mpz_cmp_ui(gq, 1) == 0);
        mpz_clear(gq);
        if (!ok) {
            throw std::runtime_error("FFGroup: g^q != 1 mod p");
        }
    }

    mpz_t p_;
    mpz_t q_;
    mpz_t g_;
    mpz_t cofactor_;  // (p-1)/q
};

}  // namespace

std::unique_ptr<Group> MakeFiniteFieldGroup() { return std::make_unique<FFGroup>(); }

}  // namespace baselines
}  // namespace piccard
