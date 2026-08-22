#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

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

struct CalibrationCandidate;
struct PreThresholdCalibrationRequest;
struct PreThresholdCalibrationRow;
struct PiccardParams;

PiccardParams SelectSanitizerCandidate(
    PiccardParams profile,
    const CalibrationCandidate& candidate);

PiccardParams SelectPreThresholdCalibration(
    PiccardParams profile,
    const PreThresholdCalibrationRequest& request,
    const std::vector<PreThresholdCalibrationRow>& candidates);

// Giant-step structure of the Paterson-Stockmeyer threshold evaluator.
//   Horner: result = result * x^s + chunk   (ell-1 sequential ct-ct mults,
//           giant depth ell-1).
//   Tree:   chunks are combined pairwise with precomputed x^{s*2^j}
//           (ell-1 combine mults + ceil(log2 ell)-1 squarings, giant depth
//           ceil(log2 ell)).
// PiccardParams::DeriveWithoutFlooding, BFVContext::EvalPolyBFV and the
// bench_threshold spec dump must all derive the same depth from this value.
enum class GiantStepMode : uint8_t { Horner = 0, Tree = 1 };

// Natural multiplicative depth of the whole threshold circuit for a degree-k
// polynomial: 1 (initial ct_x * ct_y) + baby-step depth + giant-step depth.
uint32_t PatersonStockmeyerNaturalDepth(uint32_t degree, GiantStepMode mode);

// Number of ciphertext-ciphertext multiplications spent in the giant step.
uint32_t PatersonStockmeyerGiantMults(uint32_t degree, GiantStepMode mode);

// PoC-only (review item D-10): a measured threshold calibration row supplied
// by the caller instead of looked up in noise_calibration.inc. Required for
// GiantStepMode::Tree (the frozen table only holds Horner measurements) and
// rejected for GiantStepMode::Horner. Values come from
// `bench_noise --circuit=threshold --giant_step=tree` single-point probes and
// go through the unchanged feasibility check
// (eval_noise + 64 + flood_margin + 2 <= log_delta). The live OpenFHE context
// is still verified at construction (realised N must equal ring_dim_natural;
// the flooding budget must fit the live log2(q/t)).
struct ThresholdCalibrationOverride {
    uint32_t mult_depth;        // provisioned depth (>= natural depth)
    uint32_t scaling_mod_size;  // RNS limb size used by the probe
    uint32_t eval_noise_bits;   // ceil of the worst probe eval_noise_bits
    uint32_t ring_dim_natural;  // ring dimension OpenFHE realised in the probe
    double   log_delta;         // log2(q/t) reported by the probe

    // Needed so the override can live inside PiccardParams::ValidationSnapshot
    // and be compared there. C++17, so this cannot be `= default`.
    // log_delta is compared exactly on purpose: the snapshot holds the value
    // the caller supplied, not one derived by floating-point arithmetic.
    bool operator==(const ThresholdCalibrationOverride& other) const;
};

struct PiccardParams {
    // User-configurable
    uint32_t k = 128;                          // Number of MinHash functions
    uint32_t m = 64;                           // One-hot bucket size
    SecurityLevel security = SecurityLevel::STD128;
    uint64_t hash_range = UINT64_MAX;          // UINT64_MAX keeps the full SHA-256
                                               // rank; finite values are compatibility
                                               // mode and reduce rank modulo this range.
    // Public SHA-256 CRS seed serialized as uint64_be in every coordinate rank.
    // Every uint64_t value is valid, so Validate() does not range-check it.
    uint64_t hash_seed = 42;

    // Dynamic variant (Paper Section 3.2, Algorithms 3-5)
    uint32_t bottom_depth = 5;                 // Bottom structure depth d

    // Threshold variant (Paper Section 3.2)
    bool threshold_mode = false;               // Enable threshold polynomial evaluation
    uint32_t threshold_tau = 0;                // Threshold value τ (match count threshold)

    // ── Transcript-aware phase smudging ──────────────────────────
    //
    // Supported transcript targets are exactly 40, 64, and 128. The selector
    // adjusts this target for max_queries and the selected realized ring
    // dimension; it never treats this field as a coefficient-level target.
    uint32_t transcript_stat_bits = 40;

    // Maximum number of released sanitizer transcripts covered by the target.
    uint64_t max_queries = UINT64_C(1) << 20;

    // Safety margin on the measured evaluation-noise bound. The smudging
    // argument needs the calibrated evaluation bound, coefficient-adjusted
    // transcript target, and this empirical margin to fit independently.
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

    /** @brief Returns the requested ring dimension captured during selection. */
    uint32_t RequestedRingDim() const { return requested_ring_dim_; }

    /** @brief Returns the calibration row's realized ring dimension. */
    uint32_t SelectedCalibratedRingDim() const {
        return selected_calibrated_ring_dim_;
    }

    /** @brief Returns the query-adjusted transcript target. */
    uint32_t QueryStatBits() const { return query_stat_bits_; }

    /** @brief Returns the coefficient-adjusted transcript target. */
    uint32_t CoefficientStatBits() const { return coefficient_stat_bits_; }

    /**
     * @brief Returns the exact selected revision-profile measurement.
     *
     * @throws std::logic_error on legacy or derive-only parameter sets.
     */
    const PreThresholdCalibrationRow& SelectedPreThresholdCalibration() const;

    /** @brief Whether selection retained a revision-profile measured row. */
    bool UsesPreThresholdCalibration() const {
        return static_cast<bool>(selected_pre_threshold_calibration_);
    }

    /**
     * @brief Read-only bridge for pre-Phase-3/4 consumers.
     *
     * Non-threshold paths return CoefficientStatBits(). The threshold
     * compatibility path returns its pinned private coefficient target, never
     * a transcript-level assurance.
     */
    uint32_t LegacyFloodCoefficientBits() const {
        return coefficient_stat_bits_;
    }

    /**
     * @brief Returns log2 of the selected uniform flooding bound.
     *
     * @throws std::logic_error unless flooding was successfully sized.
     */
    uint32_t FloodNoiseBits() const;

    // Whether the flooding term has been sized against the calibration table.
    bool FloodingSized() const { return flooding_sized_; }

    /**
     * @brief Adopts the runtime ring dimension verified against calibration.
     *
     * @throws std::logic_error before selection, after source mutation, or on a
     *         second call.
     * @throws std::invalid_argument if runtime_n differs from the calibrated N.
     */
    void AdoptVerifiedRuntimeRingDim(uint32_t runtime_n);

    // Derived by Validate()
    uint32_t feature_dim = 0;                  // k * m
    uint32_t ring_dim = 0;                     // NextPowerOf2(feature_dim) >= security min
    uint64_t plaintext_mod = 0;                // Prime p > k, p ≡ 1 mod 2N
    uint32_t mult_depth = 1;                   // 1 for basic/dynamic, higher for threshold

    // Threshold variant only. Horner is the frozen default measured in the
    // 2026-08-20 revision run; Tree is the PoC comparison (review item D-10).
    // Tree requires threshold_calibration_override (Task 3); Horner forbids it.
    GiantStepMode giant_step = GiantStepMode::Horner;

    // Caller-supplied measured calibration row for the threshold circuit. It is
    // input, not derived state: ClearFloodingSelection() must leave it alone.
    // Mandatory under GiantStepMode::Tree, forbidden under Horner.
    std::optional<ThresholdCalibrationOverride> threshold_calibration_override;

    // Derived by ValidateSqrt() — base-√m encoding
    uint32_t sqrt_base = 0;                    // √m (power of 2)
    uint32_t sqrt_feature_dim = 0;             // k * 2 * √m

    void Validate();
    void ValidateSqrt();

private:
    struct ValidationSnapshot {
        uint32_t k;
        uint32_t m;
        SecurityLevel security;
        bool threshold_mode;
        GiantStepMode giant_step;
        // giant_step and the override are a pair: Tree cannot be selected
        // without one. Both belong under the same fail-closed revalidation.
        std::optional<ThresholdCalibrationOverride>
            threshold_calibration_override;
        uint32_t transcript_stat_bits;
        uint64_t max_queries;
        uint32_t flood_margin_bits;
        uint32_t eval_noise_bits;
        uint32_t ring_dim;
        uint64_t plaintext_mod;
        uint32_t natural_mult_depth;
        uint32_t ring_dim_natural;
        uint32_t mult_depth;
        uint32_t scaling_mod_size;
        uint32_t feature_dim;
        uint32_t sqrt_base;
        uint32_t sqrt_feature_dim;
        uint32_t requested_ring_dim;
        uint32_t selected_calibrated_ring_dim;
        uint32_t query_stat_bits;
        uint32_t coefficient_stat_bits;
        uint32_t flood_noise_bits;
        double selected_log2_q_over_t;
        Circuit selected_circuit;
        std::shared_ptr<const PreThresholdCalibrationRow>
            selected_pre_threshold_calibration;
        bool runtime_adopted;

        bool operator==(const ValidationSnapshot& other) const;
    };

    void ClearFloodingSelection();
    ValidationSnapshot CurrentValidationSnapshot() const;
    void CaptureValidationSnapshot();
    void VerifyValidationSnapshot() const;

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

    // Set only by a successful calibration selection and cleared by derive-only
    // entry points.
    bool flooding_sized_ = false;
    uint32_t requested_ring_dim_ = 0;
    uint32_t selected_calibrated_ring_dim_ = 0;
    uint32_t query_stat_bits_ = 0;
    uint32_t coefficient_stat_bits_ = 0;
    uint32_t flood_noise_bits_ = 0;
    double selected_log2_q_over_t_ = 0.0;
    Circuit selected_circuit_ = Circuit::OneHot;
    std::shared_ptr<const PreThresholdCalibrationRow>
        selected_pre_threshold_calibration_;
    bool runtime_adopted_ = false;
    bool validation_snapshot_valid_ = false;
    ValidationSnapshot validation_snapshot_{};

    friend struct CalibrationAccess;
    friend PiccardParams SelectSanitizerCandidate(
        PiccardParams profile,
        const CalibrationCandidate& candidate);
    friend PiccardParams SelectPreThresholdCalibration(
        PiccardParams profile,
        const PreThresholdCalibrationRequest& request,
        const std::vector<PreThresholdCalibrationRow>& candidates);

    // Look up the calibration frontier for (circuit, ring_dim, natural_depth)
    // and adopt the cheapest measured parameters that leave room for the
    // requested transcript profile.
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
