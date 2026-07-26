#include "baselines/sj16.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <stdexcept>
#include <vector>

#include "baselines/csprng.h"

#ifdef _OPENMP
#include <omp.h>
#endif

namespace piccard {
namespace baselines {

namespace {

// Wall-clock now() in milliseconds.
inline double NowMs() {
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

}  // namespace

SJ16::SJ16(unsigned key_bits, bool precompute)
    : key_bits_(key_bits), precompute_(precompute), paillier_(key_bits) {}

void SJ16::Setup() {
    paillier_.KeyGen();
    n_ = mpz_class(paillier_.N());
    n_sq_ = n_ * n_;
    keyed_ = true;
    // Any previously built pool is now stale (keyed to the old modulus).
    rho_pool_.clear();
    pool_index_.store(0);
}

void SJ16::SetUniverse(uint32_t u) {
    if (u == 0) {
        throw std::invalid_argument("SJ16::SetUniverse: universe must be > 0");
    }
    m_ = u;
}

void SJ16::PrepareRandomizerPool(size_t count) {
    if (!keyed_) {
        throw std::logic_error(
            "SJ16::PrepareRandomizerPool: Setup() must run first");
    }
    rho_pool_.assign(count, mpz_class());
    CSPRNG& rng = ThreadLocalCSPRNG();
    ScopedMpz rho;
    for (size_t i = 0; i < count; ++i) {
        rng.RandomCoprime(rho.get(), n_.get_mpz_t());
        // rho^N mod N^2
        mpz_powm(rho_pool_[i].get_mpz_t(), rho.get(), n_.get_mpz_t(),
                 n_sq_.get_mpz_t());
    }
    pool_index_.store(0);
}

size_t SJ16::ReservePool(size_t count) {
    // CAS loop: only advance pool_index_ on success, so a failing reservation
    // (which throws) leaves the consumed counter untouched. Bounded and
    // exception-free on success, this runs on the caller thread BEFORE any
    // OpenMP region -- a C++ exception cannot legally escape an omp parallel
    // structured block.
    size_t cur = pool_index_.load(std::memory_order_relaxed);
    for (;;) {
        if (cur + count > rho_pool_.size()) {
            // Exhaustion or reuse: the caller failed to (re)fill the pool.
            throw std::runtime_error("SJ16: randomizer pool exhausted");
        }
        if (pool_index_.compare_exchange_weak(cur, cur + count,
                                              std::memory_order_acq_rel,
                                              std::memory_order_relaxed)) {
            return cur;
        }
        // cur was refreshed with the current value; retry.
    }
}

void SJ16::EncMsg(mpz_class& c, const mpz_class& msg, size_t pool_idx) {
    if (precompute_) {
        // pool_idx is within a range already reserved via ReservePool; no
        // per-call bounds throw (so this is safe inside an OpenMP loop).
        // c = (1 + (msg mod N) * N mod N^2) * rho^N mod N^2
        mpz_class base = ((msg % n_) * n_ + 1) % n_sq_;
        c = (base * rho_pool_[pool_idx]) % n_sq_;
    } else {
        paillier_.Encrypt(c.get_mpz_t(), msg.get_mpz_t());
    }
}

QueryCost SJ16::RunQuery(const std::vector<uint64_t>& x,
                         const std::vector<uint64_t>& y) {
    return RunProtocol(x, y).cost;
}

SJ16Result SJ16::RunProtocol(const std::vector<uint64_t>& x,
                             const std::vector<uint64_t>& y) {
    return RunProtocolImpl(x, y, nullptr);
}

SJ16Result SJ16::RunProtocolWithMask(const std::vector<uint64_t>& x,
                                     const std::vector<uint64_t>& y,
                                     const mpz_t r_mask) {
    // Shares live in [0, N); a mask outside that range yields an invalid share
    // (e.g. x2 = (N - r_mask) mod N goes negative for r_mask >= N, since GMP's
    // mod keeps the dividend's sign). Reject up front.
    if (mpz_sgn(r_mask) < 0 || mpz_cmp(r_mask, n_.get_mpz_t()) >= 0) {
        throw std::invalid_argument(
            "SJ16::RunProtocolWithMask: r_mask must lie in [0, N)");
    }
    return RunProtocolImpl(x, y, r_mask);
}

SJ16Result SJ16::RunProtocolImpl(const std::vector<uint64_t>& x,
                                 const std::vector<uint64_t>& y,
                                 mpz_srcptr forced_mask) {
    if (!keyed_) {
        throw std::logic_error("SJ16: Setup() must run before a query");
    }
    if (m_ == 0) {
        throw std::logic_error("SJ16: SetUniverse() must run before a query");
    }

    const uint32_t m = m_;
    SJ16Result result;
    QueryCost& cost = result.cost;

    // -------- encode: build indicator vectors + deduped set sizes ----------
    double t0 = NowMs();
    std::vector<uint8_t> M1(m, 0), M2(m, 0);
    for (uint64_t e : x) {
        if (e >= m) throw std::out_of_range("SJ16: X element >= universe");
        M1[static_cast<size_t>(e)] = 1;
    }
    for (uint64_t e : y) {
        if (e >= m) throw std::out_of_range("SJ16: Y element >= universe");
        M2[static_cast<size_t>(e)] = 1;
    }
    uint64_t size_x = 0, size_y = 0;
    for (uint32_t i = 0; i < m; ++i) {
        size_x += M1[i];
        size_y += M2[i];
    }
    // Positions of Y's (deduped) elements, for the P2 product.
    std::vector<uint32_t> y_idx;
    y_idx.reserve(static_cast<size_t>(size_y));
    for (uint32_t i = 0; i < m; ++i) {
        if (M2[i]) y_idx.push_back(i);
    }
    cost.phase_encode_ms = NowMs() - t0;

    // -------- encrypt (P1, dominant, parallel): Z[i] = Enc(M1[i]) ----------
    std::vector<mpz_class> Z(m);
    const mpz_class m0(0), m1(1);
    // In precompute mode, reserve the WHOLE query (m for Z + 1 for the mask)
    // atomically on this thread BEFORE the OpenMP region. A short pool throws
    // here (runtime_error propagates normally); inside the loop no per-iteration
    // exhaustion throw can occur. Non-precompute mode ignores pool_base.
    size_t pool_base = precompute_ ? ReservePool(static_cast<size_t>(m) + 1) : 0;
    t0 = NowMs();
    // Any per-iteration exception (e.g. entropy failure inside Paillier::Encrypt)
    // cannot escape an omp parallel structured block, so capture the first one
    // and rethrow after the region. `failed` gives a cheap racy early-out.
    std::exception_ptr enc_error;
    std::atomic<bool> failed{false};
#pragma omp parallel for schedule(static)
    for (long i = 0; i < static_cast<long>(m); ++i) {
        if (failed.load(std::memory_order_relaxed)) continue;
        try {
            EncMsg(Z[static_cast<size_t>(i)],
                   M1[static_cast<size_t>(i)] ? m1 : m0,
                   pool_base + static_cast<size_t>(i));
        } catch (...) {
#pragma omp critical(sj16_enc_error)
            {
                if (!enc_error) enc_error = std::current_exception();
            }
            failed.store(true, std::memory_order_relaxed);
        }
    }
    if (enc_error) std::rethrow_exception(enc_error);
    cost.phase_encrypt_ms = NowMs() - t0;

    // -------- compute (P2): S = product of Z[i] over dedup(Y), then mask ----
    t0 = NowMs();
    // Product over the empty set == 1 (the multiplicative identity, a
    // deterministic Enc(0) with rho=1).
    mpz_class S(1);
    for (uint32_t idx : y_idx) {
        paillier_.AddCipher(S.get_mpz_t(), S.get_mpz_t(),
                            Z[idx].get_mpz_t());
    }

    mpz_class r_mask;
    if (forced_mask != nullptr) {
        mpz_set(r_mask.get_mpz_t(), forced_mask);
    } else {
        ScopedMpz r;
        ThreadLocalCSPRNG().RandomMpz(r.get(), n_.get_mpz_t());  // [0, N)
        r_mask = mpz_class(r.get());
    }
    // x2 = (N - r_mask) mod N
    result.x2 = (n_ - r_mask) % n_;

    mpz_class enc_mask;
    // The mask consumes the last reserved pool entry (index m) in precompute
    // mode; ignored otherwise.
    EncMsg(enc_mask, r_mask, pool_base + static_cast<size_t>(m));
    mpz_class Sp;  // S' = S * Enc(r_mask) mod N^2
    paillier_.AddCipher(Sp.get_mpz_t(), S.get_mpz_t(), enc_mask.get_mpz_t());
    cost.phase_compute_ms = NowMs() - t0;

    // -------- decrypt (P1): x1 = Dec(S') ------------------------------------
    t0 = NowMs();
    paillier_.Decrypt(result.x1.get_mpz_t(), Sp.get_mpz_t());
    cost.phase_decrypt_ms = NowMs() - t0;

    cost.total_ms = cost.phase_encode_ms + cost.phase_encrypt_ms +
                    cost.phase_compute_ms + cost.phase_decrypt_ms;

    // -------- reconstruct (harness only) + Jaccard --------------------------
    mpz_class I = (result.x1 + result.x2) % n_;
    uint64_t intersection = static_cast<uint64_t>(I.get_ui());
    result.intersection = intersection;

    uint64_t uni = size_x + size_y - intersection;  // |X| + |Y| - I
    cost.jaccard_estimate =
        (uni == 0) ? 1.0
                   : static_cast<double>(intersection) / static_cast<double>(uni);

    // -------- communication accounting (sum of produced wire buffers) -------
    // Asymmetric, both directions summed. Each Z[i] (P1->P2 upload) and S'
    // (P2->P1 response) is serialized with the fixed-width Paillier wire
    // encoding; we SUM the returned buffer lengths. Because the encoding is
    // fixed-width this equals the theoretical (m+1)*CiphertextBytes(), a
    // coincidence disclosed against Piccard's variable-length OpenFHE rows.
    // Key/framing/setup traffic is excluded.
    const size_t ct_bytes = paillier_.CiphertextBytes();
    std::vector<unsigned char> buf(ct_bytes);
    size_t ct_size = 0;
    for (uint32_t i = 0; i < m; ++i) {
        ct_size += paillier_.SerializeCiphertext(Z[i].get_mpz_t(), buf.data());
    }
    size_t sp_len = paillier_.SerializeCiphertext(Sp.get_mpz_t(), buf.data());
    cost.ct_size_bytes = ct_size;              // P1 -> P2 upload
    cost.comm_bytes = ct_size + sp_len;        // + P2 -> P1 response

    return result;
}

double SJ16::MeasureEncryptMsMedian(size_t iters) const {
    if (iters == 0) return 0.0;
    std::vector<double> samples;
    samples.reserve(iters);
    mpz_class msg(1), c;
    for (size_t i = 0; i < iters; ++i) {
        double t0 = NowMs();
        paillier_.Encrypt(c.get_mpz_t(), msg.get_mpz_t());
        samples.push_back(NowMs() - t0);
    }
    std::sort(samples.begin(), samples.end());
    size_t mid = samples.size() / 2;
    if (samples.size() % 2 == 1) return samples[mid];
    return 0.5 * (samples[mid - 1] + samples[mid]);
}

}  // namespace baselines
}  // namespace piccard
