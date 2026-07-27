#pragma once

/**
 * @file sj16.h
 * @brief SJ16 (Samanthula & Jiang, TDSC 2016) secure multiset intersection
 *        cardinality, specialized to the set setting (n = 1).
 *
 * Implements Algorithm 1 (p.596) of the paper for the case where every set has
 * max frequency 1, so the m x n frequency matrix collapses to a length-|U|
 * binary indicator vector (design §3.2). The protocol produces additive shares
 * (x1, x2) of the intersection cardinality with
 *
 *     (x1 + x2) mod N == |X n Y|
 *
 * and neither party learns the cardinality itself. Reconstruction of the
 * cardinality happens only in the test/benchmark harness (design §7).
 *
 * Built on the GMP Paillier primitive (paillier.h) and the OS-backed CSPRNG
 * (csprng.h). The dominant cost is P1's |U| encryptions, which run in parallel
 * with per-thread randomness.
 */

#include <gmpxx.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "baselines/paillier.h"
#include "baselines/pjs_baseline.h"

namespace piccard {
namespace baselines {

// One measured trial of the full protocol; retains the ground-truth Jaccard so
// the Phase-4 adapter can compute a mean estimation error (a bare QueryCost has
// no j_true).
struct SJ16Trial {
    QueryCost cost;
    double j_true;
};

// Full protocol result: the additive shares plus the (harness-only)
// reconstructed cardinality and the per-query cost.
struct SJ16Result {
    mpz_class x1;            // = D_sk(S')            in [0, N)
    mpz_class x2;            // = (N - r_mask) mod N  in [0, N)
    uint64_t intersection;  // (x1 + x2) mod N, reconstructed in the harness only
    QueryCost cost;
};

class SJ16 : public PJSBaseline {
public:
    // key_bits is forwarded to Paillier (must be 1024/2048/3072). When
    // precompute is true, RunProtocol consumes rho^N values from a pool that
    // the caller must (re)fill via PrepareRandomizerPool(m+1) before each
    // measured query.
    SJ16(unsigned key_bits, bool precompute = false);

    SJ16(const SJ16&) = delete;
    SJ16& operator=(const SJ16&) = delete;

    const char* Name() const override { return "sj16"; }
    SecurityClass Security() const override {
        return SecurityClass::AHE_NoLeakage;
    }

    // One-time Paillier key generation. Safe to call again (regenerates keys).
    void Setup() override;

    // Sets the universe/domain size m = |U|. Must be called (with u > 0) before
    // any query. Throws std::invalid_argument on u == 0.
    void SetUniverse(uint32_t u);

    // PJSBaseline entry point: returns RunProtocol(x, y).cost.
    QueryCost RunQuery(const std::vector<uint64_t>& x,
                       const std::vector<uint64_t>& y) override;

    // Full protocol; draws a fresh random mask r_mask in [0, N).
    SJ16Result RunProtocol(const std::vector<uint64_t>& x,
                           const std::vector<uint64_t>& y);

    // Test seam: run the protocol with a caller-supplied mask instead of a
    // drawn one. r_mask must lie in [0, N).
    SJ16Result RunProtocolWithMask(const std::vector<uint64_t>& x,
                                   const std::vector<uint64_t>& y,
                                   const mpz_t r_mask);

    // Median wall-clock ms of a single Paillier encryption over `iters`
    // repetitions (Phase-3 calibration). Returns 0 for iters == 0.
    double MeasureEncryptMsMedian(size_t iters) const;

    // Precompute `count` (= m+1) fresh rho^N mod N^2 randomizers, resetting the
    // consumption index. Requires Setup() to have run.
    void PrepareRandomizerPool(size_t count);

    // Introspection for tests: how many pool entries have been consumed since
    // the last PrepareRandomizerPool, and the current pool size.
    size_t PoolConsumed() const { return pool_index_.load(); }
    size_t PoolSize() const { return rho_pool_.size(); }

    // The Paillier modulus N (valid after Setup()); shares live in [0, N).
    const mpz_class& N() const { return n_; }

private:
    // Encrypts `msg` into `c`. In precompute mode this uses the pre-reserved
    // pool entry at `pool_idx` (bounds already guaranteed by the caller's
    // ReservePool); otherwise it delegates to Paillier::Encrypt, which draws a
    // fresh nonce (and `pool_idx` is ignored).
    void EncMsg(mpz_class& c, const mpz_class& msg, size_t pool_idx = 0);

    // Atomically reserves a contiguous block of `count` pool entries and returns
    // the start index; subsequent EncMsg calls index into [start, start+count).
    // Throws std::runtime_error (on the calling thread) if the reservation would
    // exceed the pool size, WITHOUT advancing the consumed counter, so callers
    // can reserve the whole query up front outside any OpenMP region. No-op for
    // count == 0 (returns the current index).
    size_t ReservePool(size_t count);

    // forced_mask == nullptr draws a fresh mask; otherwise it is used as-is.
    SJ16Result RunProtocolImpl(const std::vector<uint64_t>& x,
                               const std::vector<uint64_t>& y,
                               mpz_srcptr forced_mask);

    unsigned key_bits_;
    bool precompute_;
    Paillier paillier_;

    bool keyed_ = false;
    mpz_class n_;     // N   (copied from paillier_ after KeyGen)
    mpz_class n_sq_;  // N^2

    uint32_t m_ = 0;  // universe size; 0 == unset

    std::vector<mpz_class> rho_pool_;   // precomputed rho^N mod N^2
    std::atomic<size_t> pool_index_{0}; // next pool entry to consume
};

}  // namespace baselines
}  // namespace piccard
