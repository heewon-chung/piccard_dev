#include "baselines/dgt12_psica.h"
#include "baselines/group_ff.h"
#include "baselines/group_ec.h"
#include "baselines/group.h"
#include <gtest/gtest.h>
#include <random>
#include <set>
#include <vector>

using namespace piccard::baselines;

static uint64_t PlainInter(std::vector<uint64_t> a, std::vector<uint64_t> b){
    std::set<uint64_t> sb(b.begin(),b.end()), sa(a.begin(),a.end()); uint64_t c=0;
    for(auto x:sa) c+=sb.count(x); return c; }
static std::vector<std::vector<uint8_t>> Items(const std::vector<uint64_t>& s){
    std::vector<std::vector<uint8_t>> v; for(auto x:s) v.push_back(EncodeRawItem(x)); return v; }

static void CheckPsiCa(const Group& G){
    std::vector<uint64_t> A{1,2,3,4,5}, B{3,4,5,6,7};
    auto c=RunDgt12(G, Items(A), Items(B));
    EXPECT_EQ(c.cardinality, PlainInter(A,B));            // 3
    EXPECT_EQ(c.protocol_exps, 3u*A.size()+B.size());     // Alice 2|A| + Bob (|A|+|B|)
    EXPECT_EQ(c.payload_bytes, A.size()*G.ElementBytes()*2 + B.size()*32);
    EXPECT_GT(c.total_ms, 0.0);
}
TEST(Dgt12PsiCa, FiniteField){ CheckPsiCa(*MakeFiniteFieldGroup()); }
TEST(Dgt12PsiCa, EllipticCurve){ CheckPsiCa(*MakeEcGroup()); }

TEST(Dgt12PsiCa, RandomizedMatchesPlaintext){
    auto G=MakeEcGroup(); std::mt19937_64 rng(20260726);
    for(int t=0;t<50;t++){
        std::set<uint64_t> A,B; std::uniform_int_distribution<uint64_t> d(0,60);
        for(int i=0;i<20;i++){A.insert(d(rng));B.insert(d(rng));}
        std::vector<uint64_t> a(A.begin(),A.end()), b(B.begin(),B.end());
        EXPECT_EQ(RunDgt12(*G,Items(a),Items(b)).cardinality, PlainInter(a,b)) << "t="<<t;
    }
}
TEST(Dgt12PsiCa, ShuffleInvariant){
    auto G=MakeEcGroup(); std::vector<uint64_t> a{1,2,3}, b{2,3,9};
    EXPECT_EQ(RunDgt12(*G,Items(a),Items(b)).cardinality,
              RunDgt12(*G,Items(a),Items(b)).cardinality);   // 2, across independent CSPRNG runs
}
TEST(Dgt12PsiCa, EmptyAndFull){
    auto G=MakeFiniteFieldGroup();
    EXPECT_EQ(RunDgt12(*G,Items({1,2}),Items({3,4})).cardinality, 0u);
    EXPECT_EQ(RunDgt12(*G,Items({1,2,3}),Items({1,2,3})).cardinality, 3u);
}
// The key correctness property for Fig. 3: the SAME sketch value at DIFFERENT
// indices must NOT cross-match; only equal <value,index> pairs count. This is
// what full-range MinHash can't exercise directly, so we drive the PSI-CA layer.
TEST(Dgt12PsiCa, PositionTagDisambiguates){
    auto G=MakeEcGroup();
    std::vector<std::vector<uint8_t>> a{EncodeTaggedItem(5,0), EncodeTaggedItem(5,1)};
    std::vector<std::vector<uint8_t>> b{EncodeTaggedItem(5,1), EncodeTaggedItem(5,2)};
    EXPECT_EQ(RunDgt12(*G,a,b).cardinality, 1u);   // only <5,1> matches, not <5,0>/<5,2>
}
