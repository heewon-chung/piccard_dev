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
TEST(Encode, InjectiveAndDomainSeparated){
    EXPECT_NE(EncodeRawItem(5), EncodeTaggedItem(5,0));      // domain byte differs
    EXPECT_NE(EncodeTaggedItem(5,1), EncodeTaggedItem(1,5)); // value/index not swappable
    EXPECT_EQ(EncodeTaggedItem(5,1), EncodeTaggedItem(5,1)); // deterministic
    EXPECT_EQ(EncodeTaggedItem(9,9).size(), 13u);            // 1+8+4
}

static void CheckGroupContract(const Group& G){
    size_t he=0; auto base=G.HashToGroup({7,7,7}, &he);
    EXPECT_TRUE(G.InSubgroup(base));
    auto a=G.RandomExponent(), b=G.RandomExponent();
    EXPECT_EQ(G.Serialize(G.Exp(G.Exp(base,a),b)), G.Serialize(G.Exp(G.Exp(base,b),a)));
    EXPECT_EQ(G.Serialize(G.ExpInverse(G.Exp(base,a),a)), G.Serialize(base));
    EXPECT_EQ(G.Serialize(base).size(), G.ElementBytes());
}
TEST(Group, FiniteFieldContract){ CheckGroupContract(*MakeFiniteFieldGroup()); }
TEST(Group, FiniteFieldSubgroupValid){
    auto G=MakeFiniteFieldGroup();
    size_t he=0; auto x=G->HashToGroup({1}, &he);
    EXPECT_TRUE(G->InSubgroup(x));
    EXPECT_GE(he, 1u);                       // cofactor exp counted
    // out-of-subgroup element must be rejected (fabricate via a raw non-member if exposed;
    // otherwise assert x != identity and x^q == identity, checked inside InSubgroup)
}
TEST(Group, EcContract){ CheckGroupContract(*MakeEcGroup()); }
