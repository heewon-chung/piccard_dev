#include <gtest/gtest.h>
#include <gmp.h>

#include <cstddef>
#include <vector>

#include "baselines/csprng.h"
#include "baselines/paillier.h"

using piccard::baselines::CSPRNG;
using piccard::baselines::Paillier;
using piccard::baselines::ThreadLocalCSPRNG;

namespace {

// K=1024 for test speed, per Phase 1 spec.
constexpr unsigned kBits = 1024;

}  // namespace

class PaillierTest : public ::testing::Test {};

TEST_F(PaillierTest, RoundtripFixedValues) {
    Paillier p(kBits);
    p.KeyGen();

    mpz_t m, c, dec, n_minus_1;
    mpz_inits(m, c, dec, n_minus_1, nullptr);
    mpz_sub_ui(n_minus_1, p.N(), 1);

    const unsigned long fixed[] = {0, 1, 2, 7};
    for (unsigned long v : fixed) {
        mpz_set_ui(m, v);
        p.Encrypt(c, m);
        p.Decrypt(dec, c);
        EXPECT_EQ(mpz_cmp(dec, m), 0) << "roundtrip failed for m=" << v;
    }

    p.Encrypt(c, n_minus_1);
    p.Decrypt(dec, c);
    EXPECT_EQ(mpz_cmp(dec, n_minus_1), 0) << "roundtrip failed for m=N-1";

    mpz_clears(m, c, dec, n_minus_1, nullptr);
}

TEST_F(PaillierTest, RoundtripRandomValues) {
    Paillier p(kBits);
    p.KeyGen();

    mpz_t m, c, dec;
    mpz_inits(m, c, dec, nullptr);

    CSPRNG& rng = ThreadLocalCSPRNG();
    for (int i = 0; i < 20; i++) {
        rng.RandomMpz(m, p.N());
        p.Encrypt(c, m);
        p.Decrypt(dec, c);
        EXPECT_EQ(mpz_cmp(dec, m), 0)
            << "roundtrip failed for random m, iter " << i;
    }

    mpz_clears(m, c, dec, nullptr);
}

TEST_F(PaillierTest, AdditiveHomomorphism) {
    Paillier p(kBits);
    p.KeyGen();

    CSPRNG& rng = ThreadLocalCSPRNG();
    mpz_t a, b, ca, cb, csum, dec, expected;
    mpz_inits(a, b, ca, cb, csum, dec, expected, nullptr);

    rng.RandomMpz(a, p.N());
    rng.RandomMpz(b, p.N());

    p.Encrypt(ca, a);
    p.Encrypt(cb, b);
    p.AddCipher(csum, ca, cb);
    p.Decrypt(dec, csum);

    mpz_add(expected, a, b);
    mpz_mod(expected, expected, p.N());

    EXPECT_EQ(mpz_cmp(dec, expected), 0);

    mpz_clears(a, b, ca, cb, csum, dec, expected, nullptr);
}

TEST_F(PaillierTest, ScalarMultiplication) {
    Paillier p(kBits);
    p.KeyGen();

    CSPRNG& rng = ThreadLocalCSPRNG();
    mpz_t a, k, ca, cscaled, dec, expected;
    mpz_inits(a, k, ca, cscaled, dec, expected, nullptr);

    rng.RandomMpz(a, p.N());
    mpz_set_ui(k, 17);

    p.Encrypt(ca, a);
    p.ScalarMul(cscaled, ca, k);
    p.Decrypt(dec, cscaled);

    mpz_mul(expected, a, k);
    mpz_mod(expected, expected, p.N());

    EXPECT_EQ(mpz_cmp(dec, expected), 0);

    mpz_clears(a, k, ca, cscaled, dec, expected, nullptr);
}

TEST_F(PaillierTest, EncryptIsRandomized) {
    Paillier p(kBits);
    p.KeyGen();

    mpz_t m, c1, c2;
    mpz_inits(m, c1, c2, nullptr);
    mpz_set_ui(m, 42);

    p.Encrypt(c1, m);
    p.Encrypt(c2, m);

    EXPECT_NE(mpz_cmp(c1, c2), 0)
        << "two Encrypt(m) calls produced identical ciphertexts";

    mpz_clears(m, c1, c2, nullptr);
}

TEST(PaillierKeySizeTest, ModulusSizeNonSquareAndCiphertextBytes) {
    for (unsigned bits : {1024u, 2048u, 3072u}) {
        Paillier p(bits);
        p.KeyGen();

        EXPECT_EQ(mpz_sizeinbase(p.N(), 2), bits) << "K=" << bits;
        EXPECT_EQ(p.KeyBits(), bits);

        // p != q is enforced internally by KeyGen(); verify indirectly
        // (p,q are not exposed by the interface): if p==q had been accepted,
        // N=p^2 would be a perfect square.
        EXPECT_EQ(mpz_perfect_square_p(p.N()), 0)
            << "N is a perfect square (p==q?) at K=" << bits;

        size_t expected_bytes = (2 * static_cast<size_t>(bits) + 7) / 8;
        EXPECT_EQ(p.CiphertextBytes(), expected_bytes) << "K=" << bits;
    }
}

TEST_F(PaillierTest, SerializeCiphertextRoundTrips) {
    Paillier p(kBits);
    p.KeyGen();

    mpz_t m, c, imported;
    mpz_inits(m, c, imported, nullptr);
    mpz_set_ui(m, 12345);
    p.Encrypt(c, m);

    size_t nbytes = p.CiphertextBytes();
    std::vector<unsigned char> buf(nbytes, 0xAA);  // poison, catch under-writes
    size_t written = p.SerializeCiphertext(c, buf.data());
    EXPECT_EQ(written, nbytes);

    mpz_import(imported, nbytes, /*order=*/1, /*size=*/1, /*endian=*/0,
               /*nails=*/0, buf.data());
    EXPECT_EQ(mpz_cmp(imported, c), 0);

    mpz_clears(m, c, imported, nullptr);
}

TEST_F(PaillierTest, SerializeCiphertextZeroPadsSmallValue) {
    Paillier p(kBits);
    p.KeyGen();

    // Random ciphertexts may happen to fill the entire buffer, so the
    // left-padding path is not reliably exercised by a random round-trip.
    // Serialize a known-small value (1) directly to deterministically check
    // zero-padding.
    mpz_t small, imported;
    mpz_inits(small, imported, nullptr);
    mpz_set_ui(small, 1);

    size_t nbytes = p.CiphertextBytes();
    std::vector<unsigned char> buf(nbytes, 0xAA);  // poison, catch under-writes
    size_t written = p.SerializeCiphertext(small, buf.data());
    EXPECT_EQ(written, nbytes);

    for (size_t i = 0; i + 1 < nbytes; i++) {
        EXPECT_EQ(buf[i], 0x00) << "non-zero padding byte at index " << i;
    }
    EXPECT_EQ(buf[nbytes - 1], 0x01);

    mpz_import(imported, nbytes, /*order=*/1, /*size=*/1, /*endian=*/0,
               /*nails=*/0, buf.data());
    EXPECT_EQ(mpz_cmp(imported, small), 0);

    mpz_clears(small, imported, nullptr);
}

TEST_F(PaillierTest, SerializeCiphertextRejectsOutOfRangeValues) {
    Paillier p(kBits);
    p.KeyGen();

    size_t nbytes = p.CiphertextBytes();
    std::vector<unsigned char> buf(nbytes, 0);

    mpz_t negative, n_sq, too_big;
    mpz_inits(negative, n_sq, too_big, nullptr);

    mpz_set_si(negative, -1);
    EXPECT_THROW(p.SerializeCiphertext(negative, buf.data()),
                 std::invalid_argument);

    // n_sq = N^2; c >= N^2 is out of the valid Z_{N^2} range.
    mpz_mul(n_sq, p.N(), p.N());
    EXPECT_THROW(p.SerializeCiphertext(n_sq, buf.data()),
                 std::invalid_argument);

    mpz_add_ui(too_big, n_sq, 1);
    EXPECT_THROW(p.SerializeCiphertext(too_big, buf.data()),
                 std::invalid_argument);

    mpz_clears(negative, n_sq, too_big, nullptr);
}

TEST_F(PaillierTest, SampledNonceIsCoprimeToN) {
    Paillier p(kBits);
    p.KeyGen();

    CSPRNG& rng = ThreadLocalCSPRNG();
    mpz_t rho, g;
    mpz_inits(rho, g, nullptr);

    for (int i = 0; i < 20; i++) {
        rng.RandomCoprime(rho, p.N());
        EXPECT_GT(mpz_sgn(rho), 0) << "iter " << i;
        EXPECT_LT(mpz_cmp(rho, p.N()), 0) << "iter " << i;
        mpz_gcd(g, rho, p.N());
        EXPECT_EQ(mpz_cmp_ui(g, 1), 0) << "gcd(rho,N) != 1 at iter " << i;
    }

    mpz_clears(rho, g, nullptr);
}

TEST(PaillierErrorTest, UnsupportedKeySizeThrows) {
    EXPECT_THROW({ Paillier p(999); }, std::exception);
}
