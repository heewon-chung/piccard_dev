#include "util/params.h"

#include <cmath>
#include <stdexcept>

namespace piccard {

uint32_t NextPowerOf2(uint32_t n) {
    if (n <= 1) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

uint32_t MinRingDimForSecurity(SecurityLevel level) {
    // Minimum ring dimensions that OpenFHE actually enforces for BFV
    // with mult_depth=1. These are larger than the theoretical minimums
    // because OpenFHE accounts for noise growth from key-switching, etc.
    switch (level) {
        case SecurityLevel::TOY:    return 1024;
        case SecurityLevel::STD128: return 8192;
        case SecurityLevel::STD192: return 16384;
        case SecurityLevel::STD256: return 32768;
    }
    return 8192;
}

bool IsPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

uint64_t FindPlaintextModulus(uint32_t min_val, uint32_t modulus) {
    // Find smallest prime p such that p > min_val and p ≡ 1 mod modulus
    // Start from the first candidate: 1 + modulus * ceil((min_val) / modulus)
    uint64_t t = 1;
    while (1 + modulus * t <= min_val) {
        t++;
    }
    for (; t < 1000000; t++) {
        uint64_t p = 1 + static_cast<uint64_t>(modulus) * t;
        if (IsPrime(p)) return p;
    }
    throw std::runtime_error("Failed to find suitable plaintext modulus");
}

void PiccardParams::Validate() {
    if (k == 0) throw std::invalid_argument("k must be > 0");
    if (m < 2) throw std::invalid_argument("m must be >= 2");

    feature_dim = k * m;
    uint32_t min_ring = MinRingDimForSecurity(security);
    ring_dim = NextPowerOf2(feature_dim);
    if (ring_dim < min_ring) {
        ring_dim = min_ring;
    }

    // BFV plaintext modulus: prime p > k, p ≡ 1 mod 2N
    uint32_t two_n = 2 * ring_dim;
    plaintext_mod = FindPlaintextModulus(k, two_n);

    mult_depth = 1;
    if (threshold_mode) {
        // Paterson-Stockmeyer baby-step/giant-step for degree-k polynomial.
        // Must match EvalPolyBFV's step-size calculation exactly.
        uint32_t degree = k;
        uint32_t s = 1;
        while (s * s < degree + 1) s++;

        // Baby-step depth: mirrors the power tree in EvalPolyBFV
        // (even j → square, odd j → multiply by x)
        uint32_t baby_depth = 0;
        {
            uint32_t v = s;
            while (v > 1) {
                baby_depth++;
                if (v % 2 == 1) v--;
                else v /= 2;
            }
        }

        // Giant-step multiplications (Horner over num_chunks)
        uint32_t num_chunks = (degree + s) / s;
        uint32_t giant_mults = num_chunks - 1;

        // +1 for the initial ct_x * ct_y in ComputeThresholdResult
        mult_depth = 1 + baby_depth + giant_mults;
    }
}

void PiccardParams::ValidateSqrt() {
    if (k == 0) throw std::invalid_argument("k must be > 0");
    if (m < 4) throw std::invalid_argument("m must be >= 4 for sqrt encoding");

    // m must be a power of 2
    if ((m & (m - 1)) != 0)
        throw std::invalid_argument("m must be a power of 2 for sqrt encoding");

    // log2(m) must be even so that √m is an integer
    uint32_t log2m = 0;
    { uint32_t tmp = m; while (tmp > 1) { log2m++; tmp >>= 1; } }
    if (log2m % 2 != 0)
        throw std::invalid_argument("log2(m) must be even for sqrt encoding (m must be a perfect square power of 2)");

    sqrt_base = 1u << (log2m / 2);
    sqrt_feature_dim = k * 2 * sqrt_base;

    feature_dim = sqrt_feature_dim;
    uint32_t min_ring = MinRingDimForSecurity(security);
    ring_dim = NextPowerOf2(sqrt_feature_dim);
    if (ring_dim < min_ring) {
        ring_dim = min_ring;
    }

    // Depth 2 for two ct-ct multiplications (component-wise AND, digit AND).
    // Extra depth headroom (+1) needed because the intermediate rotate-and-sum
    // and the large plaintext modulus requirement (p ≡ 1 mod 2N) inflate noise
    // beyond a tight depth-2 budget.
    mult_depth = 3;

    uint32_t two_n = 2 * ring_dim;
    plaintext_mod = FindPlaintextModulus(k, two_n);
}

} // namespace piccard
