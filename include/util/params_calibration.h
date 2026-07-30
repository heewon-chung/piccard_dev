#pragma once

#include "util/params.h"

#include <stdexcept>
#include <string>

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
