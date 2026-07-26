#include "baselines/group.h"
#include "baselines/group_ff.h"
#include "baselines/group_ec.h"
#include <gtest/gtest.h>
using namespace piccard::baselines;
TEST(TagHash, DeterministicAnd32Bytes){
    std::vector<uint8_t> a{1,2,3}, c{1,2,4};
    EXPECT_EQ(TagHash(a).size(), 32u);
    EXPECT_EQ(TagHash(a), TagHash(std::vector<uint8_t>{1,2,3}));
    EXPECT_NE(TagHash(a), TagHash(c));
}
// Known-answer vector: TagHash({1,2,3}) = SHA-256(0x03 || 0x01 0x02 0x03),
// computed independently via `printf '\x03\x01\x02\x03' | openssl dgst -sha256`.
TEST(TagHash, KnownAnswerVector){
    std::vector<uint8_t> expected{
        0x5c,0x42,0xfb,0xeb,0x84,0x24,0xc2,0x8e,0x5c,0x3d,0xaf,0x93,0x34,0xc3,0xa2,0x57,
        0x2f,0xc9,0x97,0x02,0xd1,0xc4,0xbc,0xf9,0x2c,0x5c,0xb9,0xf5,0xc3,0x26,0x35,0xf6};
    EXPECT_EQ(TagHash(std::vector<uint8_t>{1,2,3}), expected);
}
TEST(Encode, InjectiveAndDomainSeparated){
    EXPECT_NE(EncodeRawItem(5), EncodeTaggedItem(5,0));      // domain byte differs
    EXPECT_NE(EncodeTaggedItem(5,1), EncodeTaggedItem(1,5)); // value/index not swappable
    EXPECT_EQ(EncodeTaggedItem(5,1), EncodeTaggedItem(5,1)); // deterministic
    EXPECT_EQ(EncodeTaggedItem(9,9).size(), 13u);            // 1+8+4
    EXPECT_EQ(EncodeRawItem(5),   (std::vector<uint8_t>{0x01,0,0,0,0,0,0,0,5}));
    EXPECT_EQ(EncodeTaggedItem(5,1),(std::vector<uint8_t>{0x02,0,0,0,0,0,0,0,5, 0,0,0,1}));
}

// Fixed-width, big-endian encoding of `n` into a buffer the same width as
// G.RandomExponent()/G.ExponentBytes(), for known-answer Exp() checks.
static std::vector<uint8_t> SmallExp(const Group& G, uint64_t n){
    std::vector<uint8_t> e(G.ExponentBytes(), 0);
    for (size_t i=0;i<8 && i<e.size();i++) e[e.size()-1-i] = uint8_t(n >> (8*i));
    return e;
}

static void CheckGroupContract(const Group& G, size_t expected_element_bytes){
    size_t he=0; auto base=G.HashToGroup({7,7,7}, &he);
    EXPECT_TRUE(G.InSubgroup(base));
    auto a=G.RandomExponent(), b=G.RandomExponent();
    EXPECT_EQ(G.Serialize(G.Exp(G.Exp(base,a),b)), G.Serialize(G.Exp(G.Exp(base,b),a)));
    EXPECT_EQ(G.Serialize(G.ExpInverse(G.Exp(base,a),a)), G.Serialize(base));

    // Exact sizes, not just internal self-consistency (which would pass even
    // if ElementBytes()/ExponentBytes() themselves were wrong).
    EXPECT_EQ(G.ElementBytes(), expected_element_bytes);
    EXPECT_EQ(G.ExponentBytes(), 32u);
    EXPECT_EQ(G.Serialize(base).size(), G.ElementBytes());

    // Known-answer + non-no-op checks: the DH-commutativity and ExpInverse
    // round-trip checks above pass vacuously if Exp/ExpInverse were no-ops
    // (identity functions), since composing no-ops is still a no-op.
    auto one = SmallExp(G, 1);
    auto two = SmallExp(G, 2);
    EXPECT_EQ(G.Serialize(G.Exp(base, one)), G.Serialize(base));  // exponent 1 is the identity
    // Squaring consistency: g^2 computed directly matches (g^1)^2, chaining
    // two real Exp calls end-to-end.
    EXPECT_EQ(G.Serialize(G.Exp(base, two)), G.Serialize(G.Exp(G.Exp(base, one), two)));
    // Non-triviality: g^2 != g^1, and g^a != g for a random exponent a (large-
    // order group) -- together with the identity check above, this rules out
    // Exp being a no-op.
    EXPECT_NE(G.Serialize(G.Exp(base, two)), G.Serialize(G.Exp(base, one)));
    EXPECT_NE(G.Serialize(G.Exp(base, a)), G.Serialize(base));
}
TEST(Group, FiniteFieldContract){ CheckGroupContract(*MakeFiniteFieldGroup(), 384u); }
TEST(Group, FiniteFieldSubgroupValid){
    auto G=MakeFiniteFieldGroup();
    size_t he=0; auto x=G->HashToGroup({1}, &he);
    EXPECT_TRUE(G->InSubgroup(x));
    EXPECT_GE(he, 1u);                       // cofactor exp counted
    // out-of-subgroup element must be rejected (fabricate via a raw non-member if exposed;
    // otherwise assert x != identity and x^q == identity, checked inside InSubgroup)
}
// A shared counter passed across multiple HashToGroup calls (as DGT12 PSI-CA
// does across many items) must accumulate the cofactor-exponentiation count,
// not be overwritten by the last call.
TEST(Group, HashToGroupAccumulatesHashExps){
    auto G=MakeFiniteFieldGroup();
    size_t solo1=0, solo2=0;
    G->HashToGroup({1}, &solo1);
    G->HashToGroup({2}, &solo2);
    ASSERT_GT(solo1, 0u);
    ASSERT_GT(solo2, 0u);
    size_t shared=0;
    G->HashToGroup({1}, &shared);
    G->HashToGroup({2}, &shared);
    EXPECT_EQ(shared, solo1 + solo2);        // accumulated, not overwritten
}
TEST(Group, EcContract){ CheckGroupContract(*MakeEcGroup(), 33u); }
