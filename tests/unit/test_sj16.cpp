#include <gtest/gtest.h>

#include <gmpxx.h>

#include <cstdint>
#include <memory>
#include <random>
#include <set>
#include <vector>

#include "baselines/sj16.h"

using piccard::baselines::SJ16;
using piccard::baselines::SJ16Result;

namespace {

// K=1024 for speed, small universe m=256, per the Phase 2 spec.
constexpr unsigned kBits = 1024;
constexpr uint32_t kM = 256;

// Cleartext reference over deduplicated sets.
struct SetStats {
    uint64_t size_x, size_y, inter;
    double jaccard;  // |X n Y| / |X u Y|, 1.0 when the union is empty
};

SetStats CleartextStats(const std::vector<uint64_t>& x,
                        const std::vector<uint64_t>& y) {
    std::set<uint64_t> sx(x.begin(), x.end());
    std::set<uint64_t> sy(y.begin(), y.end());
    uint64_t inter = 0;
    for (uint64_t e : sx) {
        if (sy.count(e)) inter++;
    }
    uint64_t uni = sx.size() + sy.size() - inter;
    double j = (uni == 0) ? 1.0
                          : static_cast<double>(inter) / static_cast<double>(uni);
    return {sx.size(), sy.size(), inter, j};
}

}  // namespace

// Shared, keyed engine for the correctness/edge/comm tests (KeyGen is costly).
class SJ16Test : public ::testing::Test {
protected:
    static std::unique_ptr<SJ16> eng;

    static void SetUpTestSuite() {
        eng = std::make_unique<SJ16>(kBits, /*precompute=*/false);
        eng->Setup();
        eng->SetUniverse(kM);
    }
    static void TearDownTestSuite() { eng.reset(); }

    // Runs the protocol and asserts the reconstructed cardinality is exact.
    SJ16Result RunAndCheck(const std::vector<uint64_t>& x,
                           const std::vector<uint64_t>& y) {
        SetStats s = CleartextStats(x, y);
        SJ16Result r = eng->RunProtocol(x, y);

        mpz_class recon = (r.x1 + r.x2) % eng->N();
        EXPECT_EQ(recon, mpz_class(static_cast<unsigned long>(s.inter)))
            << "(x1+x2) mod N != |X n Y|";
        EXPECT_EQ(r.intersection, s.inter) << "reconstructed intersection";
        return r;
    }
};
std::unique_ptr<SJ16> SJ16Test::eng;

TEST_F(SJ16Test, ExactnessOverRandomInputs) {
    std::mt19937 rng(12345);
    std::uniform_int_distribution<uint32_t> elem(0, kM - 1);
    std::uniform_int_distribution<int> sz(0, 40);

    for (int t = 0; t < 25; ++t) {
        std::vector<uint64_t> x, y;
        int nx = sz(rng), ny = sz(rng);
        for (int i = 0; i < nx; ++i) x.push_back(elem(rng));
        for (int i = 0; i < ny; ++i) y.push_back(elem(rng));
        RunAndCheck(x, y);
    }
}

TEST_F(SJ16Test, ForcedMaskIdentity) {
    // A middling overlap so I is a definite nonzero value.
    std::vector<uint64_t> x = {1, 2, 3, 4, 5};
    std::vector<uint64_t> y = {3, 4, 5, 6, 7};
    SetStats s = CleartextStats(x, y);  // inter == 3
    ASSERT_EQ(s.inter, 3u);

    const mpz_class& N = eng->N();
    mpz_class I(static_cast<unsigned long>(s.inter));

    // r_mask in {0, 1, N-1}
    std::vector<mpz_class> masks = {mpz_class(0), mpz_class(1), N - 1};
    for (const mpz_class& rm : masks) {
        SJ16Result r = eng->RunProtocolWithMask(x, y, rm.get_mpz_t());

        mpz_class exp_x1 = (I + rm) % N;
        mpz_class exp_x2 = (N - rm) % N;
        EXPECT_EQ(r.x1, exp_x1) << "x1 for r_mask=" << rm;
        EXPECT_EQ(r.x2, exp_x2) << "x2 for r_mask=" << rm;

        // Both shares in [0, N).
        EXPECT_GE(r.x1, mpz_class(0));
        EXPECT_LT(r.x1, N);
        EXPECT_GE(r.x2, mpz_class(0));
        EXPECT_LT(r.x2, N);

        // Reconstruction still exact (r_mask=0 => x1=I is a VALID execution).
        EXPECT_EQ((r.x1 + r.x2) % N, I);
    }
}

TEST_F(SJ16Test, ForcedMaskOutOfRangeThrows) {
    // Shares live in [0, N); a mask outside that range is rejected up front.
    const mpz_class& N = eng->N();
    std::vector<uint64_t> x = {1, 2, 3};
    std::vector<uint64_t> y = {2, 3, 4};

    std::vector<mpz_class> bad = {mpz_class(-1), N, N + 1};
    for (const mpz_class& rm : bad) {
        EXPECT_THROW(eng->RunProtocolWithMask(x, y, rm.get_mpz_t()),
                     std::invalid_argument)
            << "r_mask=" << rm << " should be rejected";
    }
}

TEST_F(SJ16Test, FreshMaskAcrossRuns) {
    std::vector<uint64_t> x = {1, 2, 3};
    std::vector<uint64_t> y = {2, 3, 4};
    SJ16Result a = eng->RunProtocol(x, y);
    SJ16Result b = eng->RunProtocol(x, y);
    EXPECT_NE(a.x1, b.x1) << "two default runs produced the same share x1";
    // Both still reconstruct correctly.
    EXPECT_EQ((a.x1 + a.x2) % eng->N(), (b.x1 + b.x2) % eng->N());
}

TEST_F(SJ16Test, EdgeEmptyEmpty) {
    SJ16Result r = RunAndCheck({}, {});
    EXPECT_EQ(r.intersection, 0u);
    EXPECT_DOUBLE_EQ(r.cost.jaccard_estimate, 1.0);  // empty union -> 1.0
}

TEST_F(SJ16Test, EdgeEmptyNonempty) {
    SJ16Result r = RunAndCheck({}, {1, 2, 3});
    EXPECT_EQ(r.intersection, 0u);
    EXPECT_DOUBLE_EQ(r.cost.jaccard_estimate, 0.0);
}

TEST_F(SJ16Test, EdgeDisjoint) {
    SJ16Result r = RunAndCheck({0, 1, 2}, {3, 4, 5});
    EXPECT_EQ(r.intersection, 0u);
}

TEST_F(SJ16Test, EdgeIdentical) {
    std::vector<uint64_t> s = {10, 20, 30, 40};
    SJ16Result r = RunAndCheck(s, s);
    EXPECT_EQ(r.intersection, 4u);
    EXPECT_DOUBLE_EQ(r.cost.jaccard_estimate, 1.0);
}

TEST_F(SJ16Test, EdgeFullUniverse) {
    std::vector<uint64_t> all;
    for (uint32_t i = 0; i < kM; ++i) all.push_back(i);
    SJ16Result r = RunAndCheck(all, all);
    EXPECT_EQ(r.intersection, kM);
    EXPECT_DOUBLE_EQ(r.cost.jaccard_estimate, 1.0);
}

TEST_F(SJ16Test, EdgeSingleton) {
    SJ16Result r = RunAndCheck({7}, {7});
    EXPECT_EQ(r.intersection, 1u);
    EXPECT_DOUBLE_EQ(r.cost.jaccard_estimate, 1.0);
}

TEST_F(SJ16Test, DuplicateInputsAreDeduplicated) {
    // |X|=2, |Y|=2, inter={7}=1 after dedup.
    SJ16Result r = RunAndCheck({5, 5, 5, 7}, {7, 7, 9});
    EXPECT_EQ(r.intersection, 1u);
    // union = 2 + 2 - 1 = 3
    EXPECT_DOUBLE_EQ(r.cost.jaccard_estimate, 1.0 / 3.0);
}

TEST_F(SJ16Test, JaccardExactMatchesCleartext) {
    std::mt19937 rng(999);
    std::uniform_int_distribution<uint32_t> elem(0, kM - 1);
    std::uniform_int_distribution<int> sz(1, 30);
    for (int t = 0; t < 10; ++t) {
        std::vector<uint64_t> x, y;
        int nx = sz(rng), ny = sz(rng);
        for (int i = 0; i < nx; ++i) x.push_back(elem(rng));
        for (int i = 0; i < ny; ++i) y.push_back(elem(rng));
        SetStats s = CleartextStats(x, y);
        SJ16Result r = eng->RunProtocol(x, y);
        // Exact (bit-identical) match: both compute inter/union as doubles.
        EXPECT_DOUBLE_EQ(r.cost.jaccard_estimate, s.jaccard);
        EXPECT_EQ(r.cost.jaccard_estimate - s.jaccard, 0.0);
    }
}

TEST_F(SJ16Test, ElementBeyondUniverseThrows) {
    EXPECT_THROW(eng->RunProtocol({kM}, {}), std::out_of_range);
    EXPECT_THROW(eng->RunProtocol({}, {kM + 5}), std::out_of_range);
}

TEST_F(SJ16Test, CommunicationAccounting) {
    // Serialized ciphertext bytes: ct_size == m * CiphertextBytes(),
    // comm == (m+1) * CiphertextBytes(). K=1024 -> ceil(2*1024/8) = 256 bytes.
    const size_t ct_bytes = (2 * static_cast<size_t>(kBits) + 7) / 8;
    SJ16Result r = eng->RunProtocol({1, 2, 3}, {2, 3, 4});
    EXPECT_EQ(r.cost.ct_size_bytes, static_cast<size_t>(kM) * ct_bytes);
    EXPECT_EQ(r.cost.comm_bytes, (static_cast<size_t>(kM) + 1) * ct_bytes);
}

TEST_F(SJ16Test, RepeatedQueries) {
    RunAndCheck({1, 2}, {2, 3});
    RunAndCheck({4, 5, 6}, {5, 6, 7});
    RunAndCheck({}, {1});
}

// ---- tests that need their own engine (re-keying / precompute) -------------

TEST(SJ16Standalone, SetUniverseZeroThrows) {
    SJ16 e(kBits, false);
    EXPECT_THROW(e.SetUniverse(0), std::invalid_argument);
}

TEST(SJ16Standalone, QueryBeforeUniverseThrows) {
    SJ16 e(kBits, false);
    e.Setup();
    // Universe never set.
    EXPECT_THROW(e.RunProtocol({1}, {1}), std::logic_error);
}

TEST(SJ16Standalone, RepeatedSetup) {
    SJ16 e(kBits, false);
    e.Setup();
    e.Setup();  // regenerate keys; must remain usable
    e.SetUniverse(kM);
    SJ16Result r = e.RunProtocol({1, 2, 3}, {3, 4, 5});
    EXPECT_EQ((r.x1 + r.x2) % e.N(), mpz_class(1));
    EXPECT_EQ(r.intersection, 1u);
}

TEST(SJ16Standalone, PrecomputePoolConsumesExactlyMPlusOne) {
    SJ16 e(kBits, /*precompute=*/true);
    e.Setup();
    e.SetUniverse(kM);

    e.PrepareRandomizerPool(static_cast<size_t>(kM) + 1);
    EXPECT_EQ(e.PoolSize(), static_cast<size_t>(kM) + 1);
    EXPECT_EQ(e.PoolConsumed(), 0u);

    SJ16Result r = e.RunProtocol({1, 2, 3, 4}, {3, 4, 5, 6});

    // Exactly m + 1 randomizers consumed (m for Z[i], one for the mask), and
    // since consumed == pool size with a monotonic index, none was reused.
    EXPECT_EQ(e.PoolConsumed(), static_cast<size_t>(kM) + 1);
    EXPECT_EQ((r.x1 + r.x2) % e.N(), mpz_class(2));  // inter{3,4} = 2
    EXPECT_EQ(r.intersection, 2u);

    // Pool is now fully drained. A second query must throw (no reuse), and the
    // FAILED reservation must NOT advance the consumed counter.
    EXPECT_THROW(e.RunProtocol({1, 2, 3, 4}, {3, 4, 5, 6}), std::runtime_error);
    EXPECT_EQ(e.PoolConsumed(), static_cast<size_t>(kM) + 1)
        << "failed reservation advanced the consumed counter";

    // Refilling resets the index and makes the engine usable again.
    e.PrepareRandomizerPool(static_cast<size_t>(kM) + 1);
    EXPECT_EQ(e.PoolConsumed(), 0u);
    SJ16Result r2 = e.RunProtocol({1, 2, 3, 4}, {3, 4, 5, 6});
    EXPECT_EQ(e.PoolConsumed(), static_cast<size_t>(kM) + 1);
    EXPECT_EQ((r2.x1 + r2.x2) % e.N(), mpz_class(2));
    EXPECT_EQ(r2.intersection, 2u);
}
