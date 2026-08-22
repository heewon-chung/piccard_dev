#pragma once

#include "util/params.h"

#include <stdexcept>
#include <string>
#include <vector>

namespace piccard {

/**
 * @brief One explicit row offered to the transcript-aware sanitizer selector.
 */
struct CalibrationCandidate {
    Circuit circuit;
    SecurityLevel security;
    uint32_t requested_ring_dim;
    uint32_t natural_ring_dim;
    uint32_t calibrated_ring_dim;
    uint32_t natural_mult_depth;
    uint32_t selected_mult_depth;
    uint32_t scaling_mod_size;
    uint32_t eval_noise_bits;
    double log2_q_over_t;
};

/**
 * @brief Complete logical key for one revision-profile calibration cell.
 */
struct PreThresholdCalibrationRequest {
    std::string profile_id;
    Circuit circuit;
    std::string shape_id;
    SecurityLevel security;
    uint32_t requested_ring_dim;
    uint32_t natural_depth;
    std::string consumer_set_sha256;
    std::string openfhe_version;

    bool operator==(const PreThresholdCalibrationRequest& other) const;
};

/**
 * @brief Complete measured contract for one pre-threshold candidate.
 */
struct PreThresholdCalibrationRow {
    PreThresholdCalibrationRequest key;
    uint32_t natural_ring_dim;
    uint32_t ring_dim_calibrated;
    uint32_t provisioned_depth;
    uint32_t scaling_mod_size;
    uint32_t num_limbs;
    uint64_t plaintext_mod;
    double log_q;
    double log_delta;
    uint32_t eval_noise_bits;
    uint64_t ct_bytes;
    uint32_t transcript_stat_bits;
    uint64_t max_queries;
    uint32_t query_stat_bits;
    uint32_t coefficient_stat_bits;
    uint32_t flood_margin_bits;
    uint32_t flood_noise_bits;
};

/** @brief Canonical policy bound to one pre-threshold profile identifier. */
struct PreThresholdProfilePolicy {
    std::string profile_id;
    uint32_t transcript_stat_bits;
    uint64_t max_queries;
    uint32_t flood_margin_bits;
    uint32_t maximum_ring_growth;
};

/** @brief Read-only summary of the compiled schema-v2 calibration table. */
struct PreThresholdTableCoverage {
    bool active;
    uint32_t required;
    uint32_t selected;
    uint32_t infeasible;
    uint32_t missing_required;
    std::vector<PreThresholdCalibrationRequest> selected_keys;
};

/** @brief Exhaustive topology summary for the frozen legacy table. */
struct LegacyCalibrationSelectionKey {
    Circuit circuit;
    SecurityLevel security;
    uint32_t requested_ring_dim;
    uint32_t natural_depth;
};

struct LegacyCalibrationTableCoverage {
    uint32_t rows;
    uint32_t distinct_selection_keys;
    uint32_t toy_rows;
    uint32_t threshold_rows;
    uint32_t invalid_role_rows;
    std::vector<LegacyCalibrationSelectionKey> selection_keys;
};

LegacyCalibrationTableCoverage InspectLegacyCalibrationTableCoverage();

/**
 * @brief Compares the compiled expanded table with canonical required keys.
 *
 * Current/legacy builds return `active=false`. Schema-v2 builds count an
 * explicitly accepted infeasible key separately from missing required keys.
 */
PreThresholdTableCoverage InspectPreThresholdCalibrationCoverage(
    const std::vector<PreThresholdCalibrationRequest>& required,
    const std::vector<PreThresholdCalibrationRequest>& accepted_infeasible);

/** @brief Returns the compiled schema-v2 rows for read-only cutover probes. */
std::vector<PreThresholdCalibrationRow>
InspectPreThresholdCalibrationRows();

/**
 * @brief Resolves one of the three canonical pre-threshold profile policies.
 *
 * @throws std::invalid_argument if profile_id is unknown.
 */
PreThresholdProfilePolicy ResolvePreThresholdProfilePolicy(
    const std::string& profile_id);

/**
 * @brief Rejects policy fields that do not exactly match profile_id.
 *
 * @throws std::invalid_argument if profile_id is unknown or any field differs
 *         from its canonical value.
 */
void ValidatePreThresholdProfilePolicy(
    const std::string& profile_id,
    uint32_t transcript_stat_bits,
    uint64_t max_queries,
    uint32_t flood_margin_bits);

/** @brief One profile/security-scoped explicit ring search request. */
struct ExplicitRingCandidateRequest {
    std::string profile_id;
    SecurityLevel security;
    uint32_t natural_ring_dim;
    std::vector<uint32_t> candidates;
};

/** @brief Validated explicit ring candidates with their isolation identity. */
struct ExplicitRingCandidateSet {
    std::string profile_id;
    SecurityLevel security;
    uint32_t natural_ring_dim;
    std::vector<uint32_t> candidates;
};

/**
 * @brief Signals that a known calibration row lacks sanitizer capacity.
 */
class SanitizerCandidateInfeasible : public std::invalid_argument {
public:
    explicit SanitizerCandidateInfeasible(const std::string& message)
        : std::invalid_argument(message) {}
};

/**
 * @brief Purely selects one candidate for an already-derived parameter value.
 *
 * The input is passed by value so rejection cannot partially mutate caller
 * state. Transcript metadata is derived from calibrated_ring_dim.
 *
 * @throws std::invalid_argument if the candidate key is malformed or does not
 *         match the derived profile.
 * @throws SanitizerCandidateInfeasible if the runtime capacity is insufficient.
 */
PiccardParams SelectSanitizerCandidate(
    PiccardParams profile,
    const CalibrationCandidate& candidate);

/**
 * @brief Selects the cheapest complete matching pre-threshold measurement.
 *
 * Candidates are filtered by the full logical key and exact derived capacity
 * contract, then ordered by (actual N, log q, ciphertext bytes, provisioned
 * depth, scaling-modulus size). Input order never affects the result.
 *
 * @throws std::invalid_argument if no complete matching feasible row exists.
 */
PiccardParams SelectPreThresholdCalibration(
    PiccardParams profile,
    const PreThresholdCalibrationRequest& request,
    const std::vector<PreThresholdCalibrationRow>& candidates);

/**
 * @brief Validates a bounded, explicit, monotone doubling ring list.
 *
 * The canonical profile policy determines the permitted growth: primary40 and
 * sensitivity64 permit factors 1 and 2; feasibility128 additionally permits
 * factor 4. No value may exceed 1048576.
 */
ExplicitRingCandidateSet BuildExplicitRingCandidateSet(
    const ExplicitRingCandidateRequest& request,
    uint32_t transcript_stat_bits,
    uint64_t max_queries,
    uint32_t flood_margin_bits);

/// Back door to the flooding-free parameter derivation, for the noise
/// calibration harness only.
///
/// `benchmarks/bench_noise.cpp` measures the evaluation noise that
/// `PiccardParams::Validate()` later looks up, so it must be able to build a
/// parameter set before that table exists -- and for a configuration not yet in
/// the table, Validate() throws by design.
///
/// Nothing else may include this header. A parameter set produced here has no
/// flooding sized: `FloodNoiseBits()` throws on it, which is what stops such a
/// set from reaching a protocol path that would return an under-flooded
/// ciphertext to the receiver.
struct CalibrationAccess {
    static void Derive(PiccardParams& params) { params.DeriveWithoutFlooding(); }
    static void DeriveSqrt(PiccardParams& params) { params.DeriveSqrtWithoutFlooding(); }

    /**
     * @brief Arms the threshold noise probe with a caller-supplied row.
     *
     * The derive-only entry points above are not enough for the threshold
     * circuit: its measurement runs through Piccard, which adopts the runtime
     * ring dimension and therefore demands a sized flooding term. The probe
     * cannot obtain one the production way. Under GiantStepMode::Tree the
     * frozen table holds no valid row by construction (commit b98f937), and
     * under GiantStepMode::Horner the table's rows are selected on their own
     * provisioned depth and limb size, which would silently replace the
     * (mult_depth, scaling_mod_size) pair the probe was asked to measure.
     *
     * So the probe supplies a permissive placeholder row here, exactly as the
     * pre-threshold probe supplies a permissive CalibrationCandidate to
     * SelectSanitizerCandidate. This waives one rule and one rule only: that
     * GiantStepMode::Horner must not carry an override. Everything else still
     * applies, namely the override's own validity checks, the feasibility
     * inequality (eval_noise + 64 + flood_margin + 2 <= log_delta), the
     * revalidation snapshot (which covers the waiver itself, so it cannot be
     * switched on or off after selection), and BFVContext's live-context
     * verification.
     *
     * The placeholder sizes only the flooding term, which the probe never
     * applies: it measures through EvaluateRaw and reports the live context's
     * log2(q/t) and its own measured noise.
     *
     * @throws std::invalid_argument unless params.threshold_mode is set, or if
     *         the supplied row fails the unchanged feasibility checks.
     */
    static void ArmThresholdProbe(PiccardParams& params,
                                  const ThresholdCalibrationOverride& row);
};

} // namespace piccard
