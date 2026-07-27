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

// Instrumentation check with |A| != |B| (5 vs 7) so the 3|A|+|B| coefficient
// formula (and the alice/bob byte-cost formulas, which are asymmetric in v/w)
// is actually pinned rather than accidentally matching a symmetric |A|==|B|
// fixture. `ff_backend` selects the backend-specific hash_exps expectation:
// FF's HashToGroup performs a cofactor exponentiation per hashed item (>0),
// EC's try-and-increment does not (==0).
static void CheckPsiCa(const Group& G, bool ff_backend){
    std::vector<uint64_t> A{1,2,3,4,5}, B{3,4,5,6,7,8,9};
    auto c=RunDgt12(G, Items(A), Items(B));
    ASSERT_EQ(c.cardinality, PlainInter(A,B));              // {3,4,5} = 3
    EXPECT_EQ(c.protocol_exps, 3u*A.size()+B.size());       // Alice 2|A| + Bob (|A|+|B|)
    EXPECT_EQ(c.alice_upload_bytes, A.size()*G.ElementBytes());
    EXPECT_EQ(c.bob_upload_bytes, A.size()*G.ElementBytes() + B.size()*32);
    EXPECT_EQ(c.payload_bytes, c.alice_upload_bytes + c.bob_upload_bytes);
    EXPECT_NEAR(c.total_ms,
                c.hash_to_group_ms + c.alice_round1_ms + c.bob_ms + c.alice_round2_ms,
                1e-6);
    EXPECT_GT(c.total_ms, 0.0);
    if (ff_backend) {
        EXPECT_GT(c.hash_exps, 0u);   // cofactor exps accumulated across all |A|+|B| hashings
    } else {
        EXPECT_EQ(c.hash_exps, 0u);   // EC try-and-increment does no exponentiation
    }
}
TEST(Dgt12PsiCa, FiniteField){ CheckPsiCa(*MakeFiniteFieldGroup(), /*ff_backend=*/true); }
TEST(Dgt12PsiCa, EllipticCurve){ CheckPsiCa(*MakeEcGroup(), /*ff_backend=*/false); }

// Shared randomized correctness driver, run against both backends below with
// >=50 cases each (mt19937_64 seeded for reproducibility; this is test-data
// generation only, not the protocol's CSPRNG path).
static void RandomizedMatchesPlaintextImpl(const Group& G, uint64_t seed){
    std::mt19937_64 rng(seed);
    for(int t=0;t<50;t++){
        std::set<uint64_t> A,B; std::uniform_int_distribution<uint64_t> d(0,60);
        for(int i=0;i<20;i++){A.insert(d(rng));B.insert(d(rng));}
        std::vector<uint64_t> a(A.begin(),A.end()), b(B.begin(),B.end());
        EXPECT_EQ(RunDgt12(G,Items(a),Items(b)).cardinality, PlainInter(a,b)) << "t="<<t;
    }
}
TEST(Dgt12PsiCa, RandomizedMatchesPlaintextFiniteField){
    auto G=MakeFiniteFieldGroup();
    RandomizedMatchesPlaintextImpl(*G, 20260726);
}
TEST(Dgt12PsiCa, RandomizedMatchesPlaintextEllipticCurve){
    auto G=MakeEcGroup();
    RandomizedMatchesPlaintextImpl(*G, 20260726);
}

TEST(Dgt12PsiCa, ShuffleInvariant){
    auto G=MakeEcGroup(); std::vector<uint64_t> a{1,2,3}, b{2,3,9};
    const uint64_t expected = PlainInter(a,b);   // 2
    const uint64_t c1 = RunDgt12(*G,Items(a),Items(b)).cardinality;
    const uint64_t c2 = RunDgt12(*G,Items(a),Items(b)).cardinality;
    EXPECT_EQ(c1, expected) << "run 1 (independent CSPRNG shuffle) must match known plaintext value";
    EXPECT_EQ(c2, expected) << "run 2 (independent CSPRNG shuffle) must match known plaintext value";
    EXPECT_EQ(c1, c2);
}

// Covers: one-side-empty (B={}), unequal-size non-empty with a known
// intersection, and both-empty. Verified against the actual implementation:
// RunDgt12 handles v==0 and/or w==0 without crashing (the masking-round loops
// simply iterate zero times and FisherYatesCsprng(0) is a no-op), so all
// three shapes are exercised directly rather than assumed.
TEST(Dgt12PsiCa, EmptyAndFull){
    auto G=MakeFiniteFieldGroup();
    // One-side-empty: B={} -> cardinality 0.
    EXPECT_EQ(RunDgt12(*G,Items({1,2}),Items({})).cardinality, 0u);
    // Unequal-size non-empty, with a known intersection.
    std::vector<uint64_t> A{1,2,3}, B{2,3,4,5,6,7,8};
    EXPECT_EQ(RunDgt12(*G,Items(A),Items(B)).cardinality, PlainInter(A,B));  // {2,3} = 2
    // Both-empty.
    EXPECT_EQ(RunDgt12(*G,Items({}),Items({})).cardinality, 0u);
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
