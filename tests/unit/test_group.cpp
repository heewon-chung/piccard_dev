#include "baselines/group.h"
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
