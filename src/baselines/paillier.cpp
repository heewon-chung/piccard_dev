#include "baselines/paillier.h"

#include <stdexcept>
#include <vector>

#include "baselines/csprng.h"

namespace piccard {
namespace baselines {

namespace {

// Draws a prime with exactly `half_bits` bits: sample `half_bits` random
// bits, force the top bit so the value is in [2^(half_bits-1), 2^half_bits),
// then take mpz_nextprime(). If nextprime() crosses the half_bits boundary
// (result has half_bits+1 bits), the draw is rejected and retried with fresh
// randomness rather than accepted with the wrong bit length.
void DrawHalfBitPrime(mpz_t out, unsigned half_bits, CSPRNG& rng) {
    for (;;) {
        rng.RandomBits(out, half_bits);
        mpz_setbit(out, half_bits - 1);  // force top bit
        mpz_nextprime(out, out);
        if (mpz_sizeinbase(out, 2) == half_bits) {
            return;
        }
        // Crossed the bit-length boundary; redraw from scratch.
    }
}

}  // namespace

Paillier::Paillier(unsigned key_bits) : key_bits_(key_bits) {
    if (key_bits != 1024 && key_bits != 2048 && key_bits != 3072) {
        throw std::invalid_argument(
            "Paillier: unsupported key_bits (must be 1024, 2048, or 3072)");
    }
    mpz_inits(n_, n_sq_, lambda_, mu_, nullptr);
}

Paillier::~Paillier() { mpz_clears(n_, n_sq_, lambda_, mu_, nullptr); }

void Paillier::KeyGen() {
    unsigned half = key_bits_ / 2;
    CSPRNG& rng = ThreadLocalCSPRNG();

    ScopedMpz p, q, p1, q1, gcd_val, prod;

    for (;;) {
        DrawHalfBitPrime(p.get(), half, rng);
        DrawHalfBitPrime(q.get(), half, rng);

        if (mpz_cmp(p.get(), q.get()) == 0) continue;  // require p != q

        mpz_mul(n_, p.get(), q.get());
        if (mpz_sizeinbase(n_, 2) != key_bits_) continue;  // exact bit length

        mpz_mul(n_sq_, n_, n_);

        mpz_sub_ui(p1.get(), p.get(), 1);
        mpz_sub_ui(q1.get(), q.get(), 1);

        // lambda = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)
        mpz_gcd(gcd_val.get(), p1.get(), q1.get());
        mpz_mul(prod.get(), p1.get(), q1.get());
        mpz_divexact(lambda_, prod.get(), gcd_val.get());

        if (mpz_invert(mu_, lambda_, n_) == 0) continue;  // gcd(lambda,N)!=1

        break;
    }
}

void Paillier::Encrypt(mpz_t c, const mpz_t m) const {
    ScopedMpz m_mod, base, rho, rho_n;

    mpz_mod(m_mod.get(), m, n_);
    mpz_mul(base.get(), m_mod.get(), n_);
    mpz_add_ui(base.get(), base.get(), 1);
    mpz_mod(base.get(), base.get(), n_sq_);  // base = (1 + (m mod N)*N) mod N^2

    ThreadLocalCSPRNG().RandomCoprime(rho.get(), n_);
    mpz_powm(rho_n.get(), rho.get(), n_, n_sq_);  // rho^N mod N^2

    mpz_mul(c, base.get(), rho_n.get());
    mpz_mod(c, c, n_sq_);
}

void Paillier::Decrypt(mpz_t m, const mpz_t c) const {
    mpz_t u, l;
    mpz_inits(u, l, nullptr);

    mpz_powm(u, c, lambda_, n_sq_);  // u = c^lambda mod N^2
    mpz_sub_ui(l, u, 1);
    mpz_divexact(l, l, n_);  // L(u) = (u-1)/N ; exact for g=1+N ciphertexts
    mpz_mul(m, l, mu_);
    mpz_mod(m, m, n_);

    mpz_clears(u, l, nullptr);
}

void Paillier::AddCipher(mpz_t out, const mpz_t a, const mpz_t b) const {
    mpz_mul(out, a, b);
    mpz_mod(out, out, n_sq_);
}

void Paillier::ScalarMul(mpz_t out, const mpz_t c, const mpz_t k) const {
    mpz_powm(out, c, k, n_sq_);
}

size_t Paillier::CiphertextBytes() const {
    return (2 * static_cast<size_t>(key_bits_) + 7) / 8;
}

size_t Paillier::SerializeCiphertext(const mpz_t c, unsigned char* out) const {
    // mpz_export() has no capacity limit: a value >= N^2 in bit-length would
    // overflow the fixed-width buffer below, and a negative value would be
    // silently serialized as its absolute value. Reject both up front.
    if (mpz_sgn(c) < 0 || mpz_cmp(c, n_sq_) >= 0) {
        throw std::invalid_argument(
            "ciphertext out of range for serialization");
    }

    size_t nbytes = CiphertextBytes();
    std::vector<unsigned char> tmp(nbytes, 0);

    size_t count = 0;
    mpz_export(tmp.data(), &count, /*order=*/1, /*size=*/1, /*endian=*/0,
               /*nails=*/0, c);

    for (size_t i = 0; i < nbytes; i++) out[i] = 0;
    // Right-align: mpz_export never writes leading zero bytes, so a value
    // narrower than the fixed width is zero-padded on the left.
    for (size_t i = 0; i < count; i++) {
        out[nbytes - count + i] = tmp[i];
    }
    return nbytes;
}

}  // namespace baselines
}  // namespace piccard
