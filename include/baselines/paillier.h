#pragma once

/**
 * @file paillier.h
 * @brief GMP-backed Paillier additively-homomorphic cryptosystem.
 *
 * Standard generator g = 1 + N, so encryption is
 *   c = (1 + (m mod N)*N mod N^2) * rho^N mod N^2
 * with rho a fresh nonce drawn from Z_N* (see csprng.h). This is the AHE
 * primitive design decision D1 for the SJ16 baseline (see
 * docs/superpowers/specs/2026-07-24-sj16-baseline-design.md, §4).
 */

#include <gmp.h>

#include <cstddef>

namespace piccard {
namespace baselines {

class Paillier {
public:
    // key_bits must be one of {1024, 2048, 3072}; anything else throws
    // std::invalid_argument.
    explicit Paillier(unsigned key_bits);
    ~Paillier();

    // Owns mpz_t key material — no copy or move.
    Paillier(const Paillier&) = delete;
    Paillier& operator=(const Paillier&) = delete;
    Paillier(Paillier&&) = delete;
    Paillier& operator=(Paillier&&) = delete;

    // Generates a fresh keypair, regenerating internally until every
    // invariant holds: p != q, N has exactly key_bits bits, and mu =
    // lambda^-1 mod N exists.
    void KeyGen();

    // c = (1 + (m mod N)*N mod N^2) * rho^N mod N^2, rho fresh from
    // ThreadLocalCSPRNG(). Logically const: key material is unchanged;
    // randomness comes from external (thread-local) state, not a mutable
    // member.
    void Encrypt(mpz_t c, const mpz_t m) const;

    // u = c^lambda mod N^2; L = (u-1)/N; m = L*mu mod N.
    void Decrypt(mpz_t m, const mpz_t c) const;

    // out = a * b mod N^2 (homomorphic addition of the two plaintexts).
    void AddCipher(mpz_t out, const mpz_t a, const mpz_t b) const;

    // out = c^k mod N^2 (homomorphic scalar multiplication of the
    // plaintext by k).
    void ScalarMul(mpz_t out, const mpz_t c, const mpz_t k) const;

    unsigned KeyBits() const { return key_bits_; }

    // Number of bytes in the fixed-width big-endian wire encoding of a
    // Z_{N^2} element: ceil(2*key_bits / 8).
    size_t CiphertextBytes() const;

    // Serializes `c` into `out` as a fixed-width, zero-padded, big-endian
    // buffer of exactly CiphertextBytes() bytes (value round-trips via
    // mpz_import with the same order/size/endian/nails). Returns the number
    // of bytes written. Throws std::invalid_argument if `c` is negative or
    // `c >= N^2` (out of the valid Z_{N^2} range, and would otherwise
    // overflow the fixed-width buffer).
    size_t SerializeCiphertext(const mpz_t c, unsigned char* out) const;

    const mpz_t& N() const { return n_; }

private:
    unsigned key_bits_;
    mpz_t n_;       // N = p*q
    mpz_t n_sq_;    // N^2
    mpz_t lambda_;  // lcm(p-1, q-1)
    mpz_t mu_;      // lambda^-1 mod N
};

}  // namespace baselines
}  // namespace piccard
