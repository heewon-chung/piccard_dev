#pragma once

#include <cstdint>

namespace piccard {

enum class SecurityLevel {
    TOY,     // Insecure, for testing only
    STD128,  // 128-bit security
    STD192,  // 192-bit security
    STD256   // 256-bit security
};

// Which homomorphic circuit a parameter set is for. The evaluation noise a
// result ciphertext carries -- and therefore how much room the flooding term
// needs -- depends on the circuit, not just on the ring dimension.
enum class Circuit {
    OneHot,     // Piccard and the dynamic variant: one multiply + rotate-and-sum
    Sqrt,       // Piccard+ base-sqrt(m): two multiplies + two rotate-and-sums
    Threshold   // one-hot followed by a degree-k polynomial
};

struct PiccardParams {
    // User-configurable
    uint32_t k = 128;                          // Number of MinHash functions
    uint32_t m = 64;                           // One-hot bucket size
    SecurityLevel security = SecurityLevel::STD128;
    uint64_t hash_range = UINT64_MAX;          // MinHash range R; UINT64_MAX means use
                                               // full Mersenne prime range (~2^61)
    // Public CRS seed. The hash family H = ((a_i,b_i))_{i=1..k} is Expand(hash_seed);
    // this seed is the reproducible serialized handle for that public parameter.
    // Every uint64_t value is valid, so Validate() does not range-check it.
    uint64_t hash_seed = 42;

    // Dynamic variant (Paper Section 3.2, Algorithms 3-5)
    uint32_t bottom_depth = 5;                 // Bottom structure depth d

    // Threshold variant (Paper Section 3.2)
    bool threshold_mode = false;               // Enable threshold polynomial evaluation
    uint32_t threshold_tau = 0;                // Threshold value τ (match count threshold)

    // ── Noise flooding (R2-W6) ───────────────────────────────────
    //
    // The security proof simulates the receiver's view by flooding: before the
    // server returns the result it adds masking noise 2^lambda_stat times the
    // evaluation-noise bound, so an evaluated ciphertext is statistically
    // indistinguishable (within 2^-lambda_stat) from a fresh one.

    // Statistical security parameter. 40 is also supported: Validate() consults
    // the calibration frontier with whatever is set here and picks the cheapest
    // parameters that still cover it, so lowering this genuinely lowers cost.
    uint32_t lambda_stat = 64;

    // Safety margin on the measured evaluation-noise bound. The smudging
    // argument needs B_flood / B_eval_actual >= 2^lambda_stat, so an
    // underestimated B_eval costs security rather than only correctness. The
    // margin therefore inflates the assumed bound; it is not modulus padding.
    uint32_t flood_margin_bits = 8;

    // Ciphertext modulus shaping, selected by Validate() from the calibration
    // table. 0 keeps OpenFHE's default limb size (60 bits). Splitting q into
    // smaller RNS limbs lowers key-switching noise, which dominates our
    // circuits; that is what buys flooding headroom without raising the ring
    // dimension. Also settable by hand for the calibration harness.
    uint32_t scaling_mod_size = 0;

    // Derived: calibrated evaluation-noise bound, in bits.
    uint32_t eval_noise_bits = 0;

    // Derived: the multiplicative depth the circuit itself needs. `mult_depth`
    // is provisioned at or above this to buy flooding headroom, so the two are
    // no longer the same number. For the threshold variant this is the value
    // that must keep matching EvalPolyBFV's Paterson-Stockmeyer step size --
    // assert against this, not against mult_depth.
    uint32_t natural_mult_depth = 0;

    // Derived: the ring dimension this circuit needs before any flooding
    // headroom. For the threshold variant this exceeds ring_dim on its own --
    // a degree-k polynomial needs a long modulus chain either way -- so
    // BFVContext checks the realised dimension against this, not against
    // ring_dim.
    uint32_t ring_dim_natural = 0;

    // log2 of the uniform flooding bound the server adds to the result.
    //
    // Throws unless the flooding term has actually been sized. Returning a
    // number from an unsized parameter set would be worse than failing: with
    // eval_noise_bits still 0 the answer is lambda_stat + margin, which for the
    // default (128, 64) configuration is 72 -- below the 79 bits of evaluation
    // noise that circuit really carries. Flooding with less noise than the
    // evaluation noise leaves the receiver's view unsimulatable while the
    // ciphertext still decrypts, so nothing downstream would notice.
    uint32_t FloodNoiseBits() const;

    // Whether the flooding term has been sized against the calibration table.
    bool FloodingSized() const { return flooding_sized_; }

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

private:
    // Derive feature_dim / ring_dim / plaintext_mod / natural_mult_depth for the
    // circuit WITHOUT sizing the flooding term.
    //
    // Private, and reachable only through util/params_calibration.h. The
    // calibration harness needs them because it measures the very table
    // Validate() looks up, so it cannot require that table to already exist.
    // Every other caller must use Validate()/ValidateSqrt(): a parameter set
    // produced by these alone has no flooding sized, and the security proof
    // does not cover a ciphertext returned under it.
    void DeriveWithoutFlooding();
    void DeriveSqrtWithoutFlooding();

    // Set only by SelectFloodingParams, cleared by the derive-only entry
    // points. Guards FloodNoiseBits() against reporting a bound for a
    // parameter set whose evaluation noise was never looked up.
    bool flooding_sized_ = false;

    friend struct CalibrationAccess;

    // Look up the calibration frontier for (circuit, ring_dim, natural_depth)
    // and adopt the cheapest measured parameters that leave room for
    // 2^lambda_stat flooding. Throws when the configuration was never
    // calibrated, or when no measured cell covers the requested lambda_stat --
    // failing closed, because silently flooding with too little noise weakens
    // the security claim without any visible symptom.
    void SelectFloodingParams(Circuit circuit, uint32_t natural_depth);
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
