#include "util/params_calibration.h"

#include "util/security_profile.h"

#include <cmath>
#include <sstream>
#include <stdexcept>
#include <string>

namespace piccard {
namespace {

const char* CircuitName(Circuit circuit) {
    switch (circuit) {
        case Circuit::OneHot:
            return "one-hot";
        case Circuit::Sqrt:
            return "base-sqrt(m)";
        case Circuit::Threshold:
            return "threshold";
    }
    return "?";
}

const char* SecurityName(SecurityLevel security) {
    switch (security) {
        case SecurityLevel::TOY:
            return "TOY";
        case SecurityLevel::STD128:
            return "STD128";
        case SecurityLevel::STD192:
            return "STD192";
        case SecurityLevel::STD256:
            return "STD256";
    }
    return "?";
}

Circuit DerivedCircuit(const PiccardParams& profile) {
    if (profile.threshold_mode) {
        return Circuit::Threshold;
    }
    return profile.sqrt_feature_dim == 0 ? Circuit::OneHot : Circuit::Sqrt;
}

std::string CandidateKey(const CalibrationCandidate& candidate) {
    std::ostringstream out;
    out << CircuitName(candidate.circuit) << " / "
        << SecurityName(candidate.security)
        << " / requested N " << candidate.requested_ring_dim
        << " / natural depth " << candidate.natural_mult_depth
        << " / natural N " << candidate.natural_ring_dim
        << " / calibrated N " << candidate.calibrated_ring_dim
        << " / selected depth " << candidate.selected_mult_depth
        << " / scaling-modulus " << candidate.scaling_mod_size;
    return out.str();
}

}  // namespace

PiccardParams SelectSanitizerCandidate(
    PiccardParams profile,
    const CalibrationCandidate& candidate) {
    if (profile.FloodingSized()) {
        throw std::invalid_argument(
            "SelectSanitizerCandidate requires a flooding-unsized profile");
    }
    if (profile.ring_dim == 0 || profile.natural_mult_depth == 0) {
        throw std::invalid_argument(
            "SelectSanitizerCandidate requires derive-only parameter state");
    }
    if (candidate.circuit == Circuit::Threshold) {
        throw std::invalid_argument(
            "threshold calibration uses the private legacy coefficient path");
    }
    if (candidate.circuit != DerivedCircuit(profile) ||
        candidate.security != profile.security ||
        candidate.requested_ring_dim != profile.ring_dim ||
        candidate.natural_mult_depth != profile.natural_mult_depth) {
        throw std::invalid_argument(
            "sanitizer calibration key mismatch: profile requires " +
            std::string(CircuitName(DerivedCircuit(profile))) + " / " +
            SecurityName(profile.security) + " / requested N " +
            std::to_string(profile.ring_dim) + " / natural depth " +
            std::to_string(profile.natural_mult_depth) +
            ", candidate is " + CandidateKey(candidate));
    }
    if (candidate.natural_ring_dim < candidate.requested_ring_dim ||
        candidate.calibrated_ring_dim < candidate.natural_ring_dim) {
        throw std::invalid_argument(
            "sanitizer calibration dimensions are not monotone for " +
            CandidateKey(candidate));
    }
    if (candidate.selected_mult_depth < candidate.natural_mult_depth) {
        throw std::invalid_argument(
            "selected multiplicative depth is below natural depth for " +
            CandidateKey(candidate));
    }
    if (!std::isfinite(candidate.log2_q_over_t) ||
        candidate.log2_q_over_t <= 0.0) {
        throw std::invalid_argument(
            "log2(q/t) must be finite and positive for " +
            CandidateKey(candidate));
    }

    const SanitizerProfile sanitizer = DeriveSanitizerProfile(
        profile.transcript_stat_bits,
        profile.max_queries,
        candidate.calibrated_ring_dim,
        candidate.eval_noise_bits,
        profile.flood_margin_bits);
    const uint32_t required_capacity = CheckedAddBits(
        sanitizer.flood_noise_bits,
        2,
        SanitizerProfileField::FloodNoiseBits);

    if (static_cast<double>(required_capacity) > candidate.log2_q_over_t) {
        std::ostringstream message;
        message << "infeasible sanitizer calibration for "
                << CandidateKey(candidate)
                << ": transcript target " << profile.transcript_stat_bits
                << ", query cap " << profile.max_queries
                << ", query adjustment "
                << sanitizer.query_adjustment_bits
                << ", coefficient adjustment "
                << sanitizer.coefficient_adjustment_bits
                << ", coefficient target "
                << sanitizer.coefficient_stat_bits
                << ", margin " << profile.flood_margin_bits
                << ", eval noise " << candidate.eval_noise_bits
                << ", required capacity " << required_capacity
                << ", available log2(q/t) " << candidate.log2_q_over_t;
        throw SanitizerCandidateInfeasible(message.str());
    }

    profile.flooding_sized_ = true;
    profile.requested_ring_dim_ = candidate.requested_ring_dim;
    profile.selected_calibrated_ring_dim_ =
        candidate.calibrated_ring_dim;
    profile.query_stat_bits_ = sanitizer.query_stat_bits;
    profile.coefficient_stat_bits_ = sanitizer.coefficient_stat_bits;
    profile.flood_noise_bits_ = sanitizer.flood_noise_bits;
    profile.selected_log2_q_over_t_ = candidate.log2_q_over_t;
    profile.selected_circuit_ = candidate.circuit;
    profile.runtime_adopted_ = false;
    profile.mult_depth = candidate.selected_mult_depth;
    profile.scaling_mod_size = candidate.scaling_mod_size;
    profile.eval_noise_bits = candidate.eval_noise_bits;
    profile.ring_dim_natural = candidate.natural_ring_dim;
    profile.CaptureValidationSnapshot();
    return profile;
}

}  // namespace piccard
