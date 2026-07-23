#pragma once

#include <cstdint>

namespace piccard {

enum class SecurityLevel {
    TOY,     // Insecure, for testing only
    STD128,  // 128-bit security
    STD192,  // 192-bit security
    STD256   // 256-bit security
};

struct PiccardParams {
    // User-configurable
    uint32_t k = 128;                          // Number of MinHash functions
    uint32_t m = 64;                           // One-hot bucket size
    SecurityLevel security = SecurityLevel::STD128;
    uint64_t hash_range = UINT64_MAX;          // MinHash range R; UINT64_MAX means use
                                               // full Mersenne prime range (~2^61)

    // Dynamic variant (Paper Section 3.2, Algorithms 3-5)
    uint32_t bottom_depth = 5;                 // Bottom structure depth d

    // Threshold variant (Paper Section 3.2)
    bool threshold_mode = false;               // Enable threshold polynomial evaluation
    uint32_t threshold_tau = 0;                // Threshold value τ (match count threshold)

    // Derived by Validate()
    uint32_t feature_dim = 0;                  // k * m
    uint32_t ring_dim = 0;                     // NextPowerOf2(feature_dim) >= security min
    uint64_t plaintext_mod = 0;                // Prime p > k, p ≡ 1 mod 2N
    uint32_t mult_depth = 1;                   // 1 for basic/dynamic, higher for threshold

    // Derived by ValidateSqrt() — base-√m encoding
    uint32_t sqrt_base = 0;                    // √m (power of 2)
    uint32_t sqrt_feature_dim = 0;             // k * 2 * √m

    void Validate();
    void ValidateSqrt();
};

// Smallest power of 2 >= n (returns 1 for n <= 1)
uint32_t NextPowerOf2(uint32_t n);

// Minimum ring dimension for a given security level
uint32_t MinRingDimForSecurity(SecurityLevel level);

// Find smallest prime p such that p > min_val and p ≡ 1 mod modulus
uint64_t FindPlaintextModulus(uint32_t min_val, uint32_t modulus);

// Check if n is prime
bool IsPrime(uint64_t n);

} // namespace piccard
