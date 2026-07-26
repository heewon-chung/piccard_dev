#include "baselines/bcg12.h"
#include "core/minhash.h"
#include <gtest/gtest.h>

using namespace piccard::baselines;

TEST(Bcg12, MinHashMatchesPlaintextEstimator) {
    Bcg12Params p;
    p.mode = Bcg12Mode::MinHash;
    p.backend = Bcg12Backend::EC;
    p.k = 64;
    p.minhash_seed = 42;
    BCG12 e(p);
    e.Setup();
    std::vector<uint64_t> X{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<uint64_t> Y{6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    auto qc = e.RunQuery(X, Y);
    piccard::MinHasher mh(p.k, UINT64_MAX, p.minhash_seed);
    double ref = piccard::MinHasher::EstimateJaccard(mh.ComputeSignature(X), mh.ComputeSignature(Y));
    EXPECT_DOUBLE_EQ(qc.jaccard_estimate, ref);
    EXPECT_EQ(e.Security(), SecurityClass::AHE_NoLeakage);
    EXPECT_STREQ(e.Name(), "bcg12_mh_ec");
    EXPECT_GT(qc.total_ms, 0.0);
    EXPECT_GT(qc.comm_bytes, 0u);
}

// Partial-overlap fixture -> a non-trivial (!=0, !=1) estimate, the meaningful case.
// (Position-tag disambiguation of equal sketch values at different indices is
// proven directly at the PSI-CA layer in Task 1.2 PositionTagDisambiguates;
// full-range MinHash cannot force intra-signature value repeats, so asserting it
// here would be vacuous.)
TEST(Bcg12, MinHashPartialOverlapIdentity) {
    Bcg12Params p;
    p.mode = Bcg12Mode::MinHash;
    p.backend = Bcg12Backend::FF;
    p.k = 64;
    p.minhash_seed = 7;
    BCG12 e(p);
    e.Setup();
    std::vector<uint64_t> X{1, 2, 3, 4, 5, 6};
    std::vector<uint64_t> Y{4, 5, 6, 7, 8, 9};
    piccard::MinHasher mh(p.k, UINT64_MAX, 7);
    double ref = piccard::MinHasher::EstimateJaccard(mh.ComputeSignature(X), mh.ComputeSignature(Y));
    EXPECT_DOUBLE_EQ(e.RunQuery(X, Y).jaccard_estimate, ref);
}

TEST(Bcg12, ExactEqualsPlaintextJaccard) {
    Bcg12Params p;
    p.mode = Bcg12Mode::Exact;
    p.backend = Bcg12Backend::FF;
    BCG12 e(p);
    e.Setup();
    auto qc = e.RunQuery({1, 2, 3, 4}, {3, 4, 5, 6});  // 2/6
    EXPECT_NEAR(qc.jaccard_estimate, 1.0 / 3.0, 1e-12);
    EXPECT_STREQ(e.Name(), "bcg12_exact_ff");
}

TEST(Bcg12, BackendsAgree) {
    auto run = [&](Bcg12Backend b) {
        Bcg12Params p;
        p.mode = Bcg12Mode::MinHash;
        p.backend = b;
        p.k = 32;
        p.minhash_seed = 9;
        BCG12 e(p);
        e.Setup();
        return e.RunQuery({1, 2, 3, 4, 5}, {3, 4, 5, 6, 7}).jaccard_estimate;
    };
    EXPECT_DOUBLE_EQ(run(Bcg12Backend::FF), run(Bcg12Backend::EC));
}

TEST(Bcg12, SeedParityNonDefault) {
    Bcg12Params p;
    p.mode = Bcg12Mode::MinHash;
    p.backend = Bcg12Backend::EC;
    p.k = 48;
    p.minhash_seed = 1234;
    BCG12 e(p);
    e.Setup();
    piccard::MinHasher mh(48, UINT64_MAX, 1234);
    std::vector<uint64_t> X{2, 4, 6, 8};
    std::vector<uint64_t> Y{4, 6, 8, 10};
    EXPECT_DOUBLE_EQ(e.RunQuery(X, Y).jaccard_estimate,
                      piccard::MinHasher::EstimateJaccard(mh.ComputeSignature(X), mh.ComputeSignature(Y)));
}

TEST(Bcg12, QueryCostComplete) {
    Bcg12Params p;
    p.mode = Bcg12Mode::MinHash;
    p.backend = Bcg12Backend::EC;
    p.k = 32;
    BCG12 e(p);
    e.Setup();
    auto q = e.RunQuery({1, 2, 3}, {2, 3, 4});
    EXPECT_NEAR(q.total_ms, q.phase_encode_ms + q.phase_encrypt_ms + q.phase_compute_ms + q.phase_decrypt_ms, 1e-6);
    EXPECT_GT(q.ct_size_bytes, 0u);
    EXPECT_GT(q.comm_bytes, 0u);
}
