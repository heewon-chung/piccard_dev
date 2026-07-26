#include "util/params.h"

#include <cmath>
#include <limits>
#include <stdexcept>
#include <string>

namespace piccard {

namespace {

/// One measured point of the noise calibration (R2-W6 / roadmap P1-3).
///
/// `eval_noise_bits` is the ceiling of the worst decryption noise observed for
/// this cell across the all_match / no_match / random input patterns and five
/// repetitions under fresh encryption randomness. `log_delta` is log2(q/t) for
/// the same cell, which is the budget the flooding term has to fit inside.
struct NoiseCalibration {
    Circuit  circuit;
    // Part of the key: the same ring dimension at a different security level is
    // a different measurement, and applying one to the other would silently
    // reuse noise data gathered under a modulus bound that does not apply.
    SecurityLevel security;
    uint32_t ring_dim_requested;
    uint32_t natural_mult_depth;
    uint32_t ring_dim_natural;
    uint32_t mult_depth;
    uint32_t scaling_mod_size;
    uint32_t eval_noise_bits;
    double   log_delta;
};

#include "util/noise_calibration.inc"

const char* SecurityName(SecurityLevel s) {
    switch (s) {
        case SecurityLevel::TOY:    return "TOY";
        case SecurityLevel::STD128: return "STD128";
        case SecurityLevel::STD192: return "STD192";
        case SecurityLevel::STD256: return "STD256";
    }
    return "?";
}

const char* CircuitName(Circuit c) {
    switch (c) {
        case Circuit::OneHot:    return "one-hot";
        case Circuit::Sqrt:      return "base-sqrt(m)";
        case Circuit::Threshold: return "threshold";
    }
    return "?";
}

} // namespace

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

uint32_t PiccardParams::FloodNoiseBits() const {
    if (!flooding_sized_) {
        throw std::logic_error(
            "FloodNoiseBits() on a parameter set whose flooding term was never "
            "sized. Call Validate()/ValidateSqrt(); the derive-only entry "
            "points exist for the calibration harness and leave "
            "eval_noise_bits at 0, which would understate the flooding bound.");
    }
    return eval_noise_bits + flood_margin_bits + lambda_stat;
}

void PiccardParams::SelectFloodingParams(Circuit circuit, uint32_t natural_depth) {
    if (lambda_stat == 0) {
        throw std::invalid_argument(
            "lambda_stat must be > 0: the security proof's receiver-view "
            "simulation requires flooding, and there is no unflooded path");
    }

    // The budget a cell must have: the flooding noise is
    // 2^(eval_noise_bits + flood_margin_bits + lambda_stat), and decryption
    // stays correct while the total is below Delta/2. The +2 keeps the sum
    // clear of the rounding boundary.
    const double required = static_cast<double>(lambda_stat) +
                            static_cast<double>(flood_margin_bits) + 2.0;

    bool key_exists = false;
    double best_capacity = -std::numeric_limits<double>::infinity();

    // Rows are emitted in cost order within a key, so the first match is also
    // the cheapest parameter set that covers this lambda_stat.
    for (const auto& row : kNoiseCalibration) {
        if (row.circuit != circuit) continue;
        if (row.security != security) continue;
        if (row.ring_dim_requested != ring_dim) continue;
        if (row.natural_mult_depth != natural_depth) continue;

        key_exists = true;
        double capacity = row.log_delta - row.eval_noise_bits - 2.0;
        if (capacity > best_capacity) best_capacity = capacity;

        if (row.eval_noise_bits + required <= row.log_delta) {
            flooding_sized_  = true;
            mult_depth       = row.mult_depth;
            scaling_mod_size = row.scaling_mod_size;
            eval_noise_bits  = row.eval_noise_bits;
            ring_dim_natural = row.ring_dim_natural;
            return;
        }
    }

    const std::string where = std::string(CircuitName(circuit)) + " / " +
                              SecurityName(security) +
                              " at ring_dim " + std::to_string(ring_dim) +
                              " (natural depth " + std::to_string(natural_depth) + ")";

    if (!key_exists) {
        throw std::invalid_argument(
            "no noise calibration for " + where +
            "; noise flooding cannot be sized for this configuration. Measure "
            "it with `bench_noise --sweep` (add the (k, m) to the grid if "
            "needed), regenerate with `scripts/make_calibration_table.py "
            "--emit-cpp include/util/noise_calibration.inc`, and rebuild.");
    }

    throw std::invalid_argument(
        "lambda_stat=" + std::to_string(lambda_stat) + " with margin " +
        std::to_string(flood_margin_bits) + " needs " +
        std::to_string(static_cast<int>(required)) +
        " bits of budget for " + where + ", but the widest measured cell "
        "carries only " + std::to_string(static_cast<int>(best_capacity)) +
        ". Lower lambda_stat, lower flood_margin_bits, or extend the "
        "calibration sweep -- raising the ring dimension would double every "
        "runtime and is not done implicitly.");
}

void PiccardParams::DeriveWithoutFlooding() {
    flooding_sized_ = false;
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
    natural_mult_depth = mult_depth;
}

void PiccardParams::Validate() {
    DeriveWithoutFlooding();

    // Everything above is the circuit's own requirement. Flooding headroom is
    // added on top, never by rewriting the Paterson-Stockmeyer depth: that
    // number has to keep matching EvalPolyBFV's step-size calculation exactly.
    SelectFloodingParams(threshold_mode ? Circuit::Threshold : Circuit::OneHot,
                         natural_mult_depth);
}

void PiccardParams::DeriveSqrtWithoutFlooding() {
    flooding_sized_ = false;
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
    natural_mult_depth = mult_depth;
}

void PiccardParams::ValidateSqrt() {
    DeriveSqrtWithoutFlooding();
    SelectFloodingParams(Circuit::Sqrt, natural_mult_depth);
}

} // namespace piccard
