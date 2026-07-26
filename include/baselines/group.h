#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace piccard { namespace baselines {

struct GroupElement { virtual ~GroupElement() = default; };
using ElementPtr = std::shared_ptr<GroupElement>;

// Prime-order group with hash-to-group and exponentiation. DDH assumed.
class Group {
public:
    virtual ~Group() = default;
    virtual const char* Name() const = 0;                 // "FF-3072/256" | "EC-P256"

    // Fresh CSPRNG exponent in [1, order-1]. NOT seeded (security).
    virtual std::vector<uint8_t> RandomExponent() const = 0;

    // Deterministic hash-to-group with domain separation; never returns identity.
    // Any internal cofactor exponentiation is counted into `out_hash_exps` if non-null.
    virtual ElementPtr HashToGroup(const std::vector<uint8_t>& msg,
                                   size_t* out_hash_exps = nullptr) const = 0;

    virtual ElementPtr Exp(const ElementPtr& base,
                           const std::vector<uint8_t>& exp) const = 0;      // base^exp
    virtual ElementPtr ExpInverse(const ElementPtr& base,
                                  const std::vector<uint8_t>& exp) const = 0; // base^(exp^{-1} mod order)

    virtual std::vector<uint8_t> Serialize(const ElementPtr& e) const = 0;   // canonical
    virtual size_t ElementBytes() const = 0;              // 384 (FF) | 33 (EC compressed)
    virtual size_t ExponentBytes() const = 0;             // 32
    virtual bool   InSubgroup(const ElementPtr& e) const = 0; // validation/tests
};

// H': SHA-256 of a serialized element → 32-byte tag (domain-separated).
std::vector<uint8_t> TagHash(const std::vector<uint8_t>& serialized_element);

// Fixed-width, domain-separated encoder for PSI-CA items (Task 2.1 correctness).
// Layout: 0x01 || value(8B BE)  for raw elements;  0x02 || value(8B BE) || index(4B BE)
// for position-tagged MinHash pairs <v,i>. Injective ⇒ pairs collide iff (v,i) equal.
std::vector<uint8_t> EncodeRawItem(uint64_t value);
std::vector<uint8_t> EncodeTaggedItem(uint64_t value, uint32_t index);

}} // namespace
