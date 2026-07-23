#pragma once

#include <cstdint>
#include <vector>

namespace piccard {

// Build threshold indicator polynomial over Z_p via Lagrange interpolation.
// u_tau(x) = 1 if x >= tau, 0 if x < tau, for x in [0..max_val].
// Returns coefficient vector [c_0, c_1, ..., c_max_val] where
// u_tau(x) = c_0 + c_1*x + c_2*x^2 + ... + c_max_val*x^max_val (mod p).
std::vector<int64_t> BuildThresholdPoly(uint32_t tau, uint32_t max_val,
                                        uint64_t plaintext_mod);

// Modular inverse of a mod p using extended Euclidean algorithm.
// Requires gcd(a, p) = 1 (guaranteed when p is prime and 0 < a < p).
int64_t ModInverse(int64_t a, int64_t p);

// Evaluate polynomial at a point in Z_p (for testing/verification).
int64_t EvalPolyPlaintext(const std::vector<int64_t>& coeffs, int64_t x,
                          int64_t p);

} // namespace piccard
