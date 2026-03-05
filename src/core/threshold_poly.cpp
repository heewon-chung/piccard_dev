#include "piccard/core/threshold_poly.h"

#include <stdexcept>

namespace piccard {

// Positive modulo: ensures result is in [0, p)
static int64_t PosMod(int64_t a, int64_t p) {
    int64_t r = a % p;
    return r < 0 ? r + p : r;
}

// Modular multiplication using __int128 to avoid overflow
static int64_t MulMod(int64_t a, int64_t b, int64_t p) {
    __int128 product = static_cast<__int128>(a) * b;
    return static_cast<int64_t>(((product % p) + p) % p);
}

int64_t ModInverse(int64_t a, int64_t p) {
    a = PosMod(a, p);
    if (a == 0) throw std::invalid_argument("ModInverse: a must be nonzero");

    // Extended Euclidean algorithm
    int64_t old_r = a, r = p;
    int64_t old_s = 1, s = 0;

    while (r != 0) {
        int64_t q = old_r / r;
        int64_t temp_r = r;
        r = old_r - q * r;
        old_r = temp_r;
        int64_t temp_s = s;
        s = old_s - q * s;
        old_s = temp_s;
    }

    return PosMod(old_s, p);
}

int64_t EvalPolyPlaintext(const std::vector<int64_t>& coeffs, int64_t x,
                          int64_t p) {
    // Horner's method
    int64_t result = 0;
    for (auto it = coeffs.rbegin(); it != coeffs.rend(); ++it) {
        result = PosMod(MulMod(result, x, p) + *it, p);
    }
    return result;
}

std::vector<int64_t> BuildThresholdPoly(uint32_t tau, uint32_t max_val,
                                        uint64_t plaintext_mod) {
    if (plaintext_mod < 2) {
        throw std::invalid_argument("plaintext_mod must be >= 2");
    }
    if (tau > max_val + 1) {
        throw std::invalid_argument("tau must be <= max_val + 1");
    }

    int64_t p = static_cast<int64_t>(plaintext_mod);
    uint32_t n = max_val + 1;  // number of interpolation points

    // Result polynomial coefficients, initialized to 0
    std::vector<int64_t> result(n, 0);

    // Lagrange interpolation: sum over points where y_i = 1 (i.e., i >= tau)
    // L(x) = sum_{i=tau}^{max_val} L_i(x)
    // where L_i(x) = product_{j!=i} (x - j) / (i - j)
    for (uint32_t i = tau; i <= max_val; i++) {
        // Build the i-th Lagrange basis polynomial
        // Start with polynomial "1" (constant 1)
        std::vector<int64_t> basis(1, 1);

        for (uint32_t j = 0; j <= max_val; j++) {
            if (j == i) continue;

            // Compute (i - j)^{-1} mod p
            int64_t denom = PosMod(static_cast<int64_t>(i) - static_cast<int64_t>(j), p);
            int64_t denom_inv = ModInverse(denom, p);

            // Multiply basis polynomial by (x - j) * denom_inv
            // (x - j) * denom_inv = denom_inv * x + (-j * denom_inv)
            size_t old_size = basis.size();
            std::vector<int64_t> new_basis(old_size + 1, 0);

            int64_t neg_j = PosMod(-static_cast<int64_t>(j), p);

            for (size_t idx = 0; idx < old_size; idx++) {
                // x term: basis[idx] * denom_inv * x^(idx+1)
                new_basis[idx + 1] = PosMod(
                    new_basis[idx + 1] + MulMod(basis[idx], denom_inv, p), p);
                // constant term: basis[idx] * (-j) * denom_inv * x^idx
                new_basis[idx] = PosMod(
                    new_basis[idx] + MulMod(MulMod(basis[idx], neg_j, p),
                                            denom_inv, p),
                    p);
            }

            basis = new_basis;
        }

        // Add basis polynomial to result (y_i = 1 for i >= tau)
        for (size_t idx = 0; idx < basis.size() && idx < result.size(); idx++) {
            result[idx] = PosMod(result[idx] + basis[idx], p);
        }
    }

    return result;
}

} // namespace piccard
