#include "baselines/dgt12_psica.h"
#include "baselines/group_ff.h"
#include "baselines/group_ec.h"
#include "baselines/group.h"
#include <gtest/gtest.h>
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
