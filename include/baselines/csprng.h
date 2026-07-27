#pragma once

/**
 * @file csprng.h
 * @brief OS-backed cryptographic RNG for the GMP-based AHE baselines.
 *
 * GMP's own gmp_randstate_t is not cryptographic, and a single shared mutable
 * state cannot serve parallel encryptions (multiple OpenMP threads calling
 * Paillier::Encrypt concurrently) nor sit behind `const` member functions.
 * CSPRNG instead draws directly from the OS entropy source on every call, so
 * each thread gets its own independent, cryptographically-strong stream via
 * ThreadLocalCSPRNG(). Never share a single CSPRNG instance across threads.
 */

#include <gmp.h>
#include <sys/random.h>

#include <cerrno>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace piccard {
namespace baselines {

// RAII wrapper for a single local mpz_t: mpz_init() in the constructor,
// mpz_clear() in the destructor. Using this for scratch mpz_t locals (instead
// of a bare mpz_init/mpz_clear pair) guarantees the GMP-owned buffer is freed
// even if an intervening call (e.g. CSPRNG::FillBytes on entropy-source
// failure) throws before the matching mpz_clear() would otherwise run. Call
// get() to obtain the underlying mpz_t for use with GMP's C API; a bare
// implicit conversion is deliberately not provided because several GMP
// entry points (e.g. mpz_cmp_ui(), mpz_sgn()) are macros that dereference
// their argument's fields directly and would bypass it.
class ScopedMpz {
public:
    ScopedMpz() { mpz_init(value_); }
    ~ScopedMpz() { mpz_clear(value_); }

    ScopedMpz(const ScopedMpz&) = delete;
    ScopedMpz& operator=(const ScopedMpz&) = delete;

    mpz_t& get() { return value_; }

private:
    mpz_t value_;
};

// One instance per thread; never shared. See ThreadLocalCSPRNG().
class CSPRNG {
public:
    CSPRNG() = default;
    ~CSPRNG() = default;

    CSPRNG(const CSPRNG&) = delete;
    CSPRNG& operator=(const CSPRNG&) = delete;

    // Fills `n` bytes of `buf` with OS entropy. getentropy() caps at 256
    // bytes per call, so this loops in <=256-byte chunks, retrying the same
    // chunk on EINTR and throwing on any other failure.
    void FillBytes(void* buf, size_t n) {
        auto* p = static_cast<unsigned char*>(buf);
        size_t remaining = n;
        while (remaining > 0) {
            size_t chunk = remaining > kMaxChunk ? kMaxChunk : remaining;
            int rc = getentropy(p, chunk);
            if (rc != 0) {
                if (errno == EINTR) {
                    continue;  // retry the same chunk
                }
                throw std::runtime_error(
                    "CSPRNG::FillBytes: getentropy() failed");
            }
            p += chunk;
            remaining -= chunk;
        }
    }

    // Draws a uniform random non-negative integer with exactly `bits` bits
    // of entropy (i.e. uniform over [0, 2^bits)). Byte-granular OS entropy
    // can produce a value wider than `bits`, so the excess high bits are
    // masked off after import.
    void RandomBits(mpz_t out, unsigned bits) {
        if (bits == 0) {
            mpz_set_ui(out, 0);
            return;
        }
        size_t nbytes = (static_cast<size_t>(bits) + 7) / 8;
        std::vector<unsigned char> buf(nbytes);
        FillBytes(buf.data(), nbytes);
        mpz_import(out, nbytes, /*order=*/1, /*size=*/1, /*endian=*/0,
                   /*nails=*/0, buf.data());
        mpz_fdiv_r_2exp(out, out, bits);  // keep only the low `bits` bits
    }

    // Uniform random value in [0, upper) via rejection sampling: draw
    // ceil(log2(upper))-bit values and reject anything >= upper. This avoids
    // the modulo bias a naive `random() % upper` would introduce.
    void RandomMpz(mpz_t out, const mpz_t upper) {
        size_t bits = mpz_sizeinbase(upper, 2);
        do {
            RandomBits(out, static_cast<unsigned>(bits));
        } while (mpz_cmp(out, upper) >= 0);
    }

    // Uniform random rho in Z_n* (0 < rho < n, gcd(rho,n) == 1) — a Paillier
    // encryption nonce. Rejects rho == 0, rho >= n (defensive; RandomMpz
    // already guarantees the range), and any rho not coprime to n.
    void RandomCoprime(mpz_t out, const mpz_t n) {
        ScopedMpz g;
        for (;;) {
            RandomMpz(out, n);
            if (mpz_sgn(out) == 0) continue;     // reject rho == 0
            if (mpz_cmp(out, n) >= 0) continue;  // reject rho >= n
            mpz_gcd(g.get(), out, n);
            if (mpz_cmp_ui(g.get(), 1) == 0) break;  // gcd(rho, n) == 1
        }
    }

private:
    static constexpr size_t kMaxChunk = 256;
};

// thread_local accessor: one CSPRNG per thread, safe to call from parallel
// (e.g. OpenMP) regions without any shared mutable RNG state.
inline CSPRNG& ThreadLocalCSPRNG() {
    thread_local CSPRNG instance;
    return instance;
}

}  // namespace baselines
}  // namespace piccard
