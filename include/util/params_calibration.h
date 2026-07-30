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
};

} // namespace piccard
