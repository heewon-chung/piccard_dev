#include "util/params_calibration.h"

#include "util/security_profile.h"

#include <cmath>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace piccard {
namespace {

constexpr uint64_t kCanonicalMaxQueries = UINT64_C(1) << 20;

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

bool IsPowerOfTwo(uint32_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

std::string ExpectedShapeId(const PiccardParams& profile, Circuit circuit) {
    if (circuit == Circuit::OneHot) {
        return "onehot-v1";
    }
    if (circuit == Circuit::Sqrt) {
        return "sqrt-b" + std::to_string(profile.sqrt_base) + "-v1";
    }
    return {};
}

bool IsLowerHexSha256(const std::string& value) {
    return value.size() == 64 &&
           value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

void ValidatePreThresholdRequest(
    const PiccardParams& profile,
    const PreThresholdCalibrationRequest& request) {
    ValidatePreThresholdProfilePolicy(
        request.profile_id,
        profile.transcript_stat_bits,
        profile.max_queries,
        profile.flood_margin_bits);
    if (profile.FloodingSized()) {
        throw std::invalid_argument(
            "pre-threshold selection requires a flooding-unsized profile");
    }
    if (profile.ring_dim == 0 || profile.natural_mult_depth == 0) {
        throw std::invalid_argument(
            "pre-threshold selection requires derive-only parameter state");
    }
    if (request.profile_id.empty()) {
        throw std::invalid_argument("pre-threshold profile_id must not be empty");
    }
    if (request.circuit != Circuit::OneHot &&
        request.circuit != Circuit::Sqrt) {
        throw std::invalid_argument(
            "pre-threshold calibration accepts only OneHot or Sqrt");
    }
    if (request.security != SecurityLevel::STD128 &&
        request.security != SecurityLevel::STD192) {
        throw std::invalid_argument(
            "pre-threshold calibration accepts only STD128 or STD192");
    }
    if (request.circuit != DerivedCircuit(profile) ||
        request.security != profile.security ||
        request.requested_ring_dim != profile.ring_dim ||
        request.natural_depth != profile.natural_mult_depth ||
        request.shape_id != ExpectedShapeId(profile, request.circuit)) {
        throw std::invalid_argument(
            "pre-threshold request does not match the derived profile");
    }
    if (!IsLowerHexSha256(request.consumer_set_sha256)) {
        throw std::invalid_argument(
            "consumer_set_sha256 must be 64 lowercase hexadecimal characters");
    }
    if (request.openfhe_version.empty()) {
        throw std::invalid_argument(
            "pre-threshold OpenFHE version must not be empty");
    }
}

bool IsCompleteMatchingFeasibleRow(
    const PiccardParams& profile,
    const PreThresholdCalibrationRequest& request,
    const PreThresholdProfilePolicy& policy,
    const PreThresholdCalibrationRow& row) {
    if (!(row.key == request)) {
        return false;
    }
    if (!IsPowerOfTwo(row.natural_ring_dim) ||
        !IsPowerOfTwo(row.ring_dim_calibrated) ||
        row.natural_ring_dim < request.requested_ring_dim ||
        row.ring_dim_calibrated < row.natural_ring_dim ||
        row.ring_dim_calibrated % row.natural_ring_dim != 0) {
        return false;
    }
    const uint32_t growth =
        row.ring_dim_calibrated / row.natural_ring_dim;
    const bool growth_allowed =
        growth != 0 && growth <= policy.maximum_ring_growth &&
        IsPowerOfTwo(growth);
    if (!growth_allowed ||
        row.provisioned_depth < request.natural_depth ||
        row.scaling_mod_size == 0 ||
        row.num_limbs == 0 ||
        row.plaintext_mod == 0 ||
        row.ct_bytes == 0 ||
        !std::isfinite(row.log_q) ||
        !std::isfinite(row.log_delta) ||
        row.log_q <= 0.0 ||
        row.log_delta <= 0.0) {
        return false;
    }
    const double measured_log_delta =
        row.log_q - std::log2(static_cast<double>(row.plaintext_mod));
    constexpr double kMeasuredLogTolerance = 1e-6;
    if (row.log_delta >= row.log_q ||
        std::abs(row.log_delta - measured_log_delta) >
            kMeasuredLogTolerance ||
        row.plaintext_mod %
                (UINT64_C(2) * row.ring_dim_calibrated) !=
            1) {
        return false;
    }
    if (row.transcript_stat_bits != profile.transcript_stat_bits ||
        row.max_queries != profile.max_queries ||
        row.flood_margin_bits != profile.flood_margin_bits) {
        return false;
    }

    try {
        const SanitizerProfile derived = DeriveSanitizerProfile(
            profile.transcript_stat_bits,
            profile.max_queries,
            row.ring_dim_calibrated,
            row.eval_noise_bits,
            profile.flood_margin_bits);
        const uint32_t required_capacity = CheckedAddBits(
            derived.flood_noise_bits,
            2,
            SanitizerProfileField::FloodNoiseBits);
        return row.query_stat_bits == derived.query_stat_bits &&
               row.coefficient_stat_bits ==
                   derived.coefficient_stat_bits &&
               row.flood_noise_bits == derived.flood_noise_bits &&
               static_cast<double>(required_capacity) <= row.log_delta;
    } catch (const std::exception&) {
        return false;
    }
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

auto PreThresholdCost(const PreThresholdCalibrationRow& row) {
    return std::tie(
        row.ring_dim_calibrated,
        row.log_q,
        row.ct_bytes,
        row.provisioned_depth,
        row.scaling_mod_size);
}

bool SamePreThresholdRow(
    const PreThresholdCalibrationRow& left,
    const PreThresholdCalibrationRow& right) {
    return left.key == right.key &&
           std::tie(
               left.natural_ring_dim,
               left.ring_dim_calibrated,
               left.provisioned_depth,
               left.scaling_mod_size,
               left.num_limbs,
               left.plaintext_mod,
               left.log_q,
               left.log_delta,
               left.eval_noise_bits,
               left.ct_bytes,
               left.transcript_stat_bits,
               left.max_queries,
               left.query_stat_bits,
               left.coefficient_stat_bits,
               left.flood_margin_bits,
               left.flood_noise_bits) ==
               std::tie(
                   right.natural_ring_dim,
                   right.ring_dim_calibrated,
                   right.provisioned_depth,
                   right.scaling_mod_size,
                   right.num_limbs,
                   right.plaintext_mod,
                   right.log_q,
                   right.log_delta,
                   right.eval_noise_bits,
                   right.ct_bytes,
                   right.transcript_stat_bits,
                   right.max_queries,
                   right.query_stat_bits,
                   right.coefficient_stat_bits,
                   right.flood_margin_bits,
                   right.flood_noise_bits);
}

}  // namespace

PreThresholdProfilePolicy ResolvePreThresholdProfilePolicy(
    const std::string& profile_id) {
    if (profile_id == "primary40") {
        return PreThresholdProfilePolicy{
            profile_id, 40, kCanonicalMaxQueries, 8, 2};
    }
    if (profile_id == "sensitivity64") {
        return PreThresholdProfilePolicy{
            profile_id, 64, kCanonicalMaxQueries, 8, 2};
    }
    if (profile_id == "feasibility128") {
        return PreThresholdProfilePolicy{
            profile_id, 128, kCanonicalMaxQueries, 8, 4};
    }
    throw std::invalid_argument(
        "unknown pre-threshold profile policy: " + profile_id);
}

void ValidatePreThresholdProfilePolicy(
    const std::string& profile_id,
    uint32_t transcript_stat_bits,
    uint64_t max_queries,
    uint32_t flood_margin_bits) {
    const PreThresholdProfilePolicy policy =
        ResolvePreThresholdProfilePolicy(profile_id);
    if (transcript_stat_bits != policy.transcript_stat_bits ||
        max_queries != policy.max_queries ||
        flood_margin_bits != policy.flood_margin_bits) {
        std::ostringstream message;
        message << "pre-threshold profile policy mismatch for "
                << profile_id << ": expected transcript "
                << policy.transcript_stat_bits << ", max_queries "
                << policy.max_queries << ", margin "
                << policy.flood_margin_bits << "; received transcript "
                << transcript_stat_bits << ", max_queries "
                << max_queries << ", margin " << flood_margin_bits;
        throw std::invalid_argument(message.str());
    }
}

bool PreThresholdCalibrationRequest::operator==(
    const PreThresholdCalibrationRequest& other) const {
    return std::tie(
               profile_id,
               circuit,
               shape_id,
               security,
               requested_ring_dim,
               natural_depth,
               consumer_set_sha256,
               openfhe_version) ==
           std::tie(
               other.profile_id,
               other.circuit,
               other.shape_id,
               other.security,
               other.requested_ring_dim,
               other.natural_depth,
               other.consumer_set_sha256,
               other.openfhe_version);
}

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
    profile.selected_pre_threshold_calibration_.reset();
    profile.runtime_adopted_ = false;
    profile.mult_depth = candidate.selected_mult_depth;
    profile.scaling_mod_size = candidate.scaling_mod_size;
    profile.eval_noise_bits = candidate.eval_noise_bits;
    profile.ring_dim_natural = candidate.natural_ring_dim;
    profile.CaptureValidationSnapshot();
    return profile;
}

PiccardParams SelectPreThresholdCalibration(
    PiccardParams profile,
    const PreThresholdCalibrationRequest& request,
    const std::vector<PreThresholdCalibrationRow>& candidates) {
    ValidatePreThresholdRequest(profile, request);
    const PreThresholdProfilePolicy policy =
        ResolvePreThresholdProfilePolicy(request.profile_id);

    using Cost = std::tuple<uint32_t, double, uint64_t, uint32_t, uint32_t>;
    std::map<Cost, const PreThresholdCalibrationRow*> rows_by_cost;
    for (const auto& candidate : candidates) {
        if (!IsCompleteMatchingFeasibleRow(
                profile, request, policy, candidate)) {
            continue;
        }
        const auto [position, inserted] =
            rows_by_cost.emplace(PreThresholdCost(candidate), &candidate);
        if (!inserted &&
            !SamePreThresholdRow(*position->second, candidate)) {
            throw std::invalid_argument(
                "conflicting equal-cost pre-threshold calibration rows");
        }
    }
    if (rows_by_cost.empty()) {
        throw std::invalid_argument(
            "no complete matching feasible pre-threshold calibration row");
    }
    const PreThresholdCalibrationRow* selected =
        rows_by_cost.begin()->second;

    profile.flooding_sized_ = true;
    profile.requested_ring_dim_ = request.requested_ring_dim;
    profile.selected_calibrated_ring_dim_ =
        selected->ring_dim_calibrated;
    profile.query_stat_bits_ = selected->query_stat_bits;
    profile.coefficient_stat_bits_ = selected->coefficient_stat_bits;
    profile.flood_noise_bits_ = selected->flood_noise_bits;
    profile.selected_log2_q_over_t_ = selected->log_delta;
    profile.plaintext_mod = selected->plaintext_mod;
    profile.selected_circuit_ = request.circuit;
    profile.selected_pre_threshold_calibration_ =
        std::make_shared<const PreThresholdCalibrationRow>(*selected);
    profile.runtime_adopted_ = false;
    profile.mult_depth = selected->provisioned_depth;
    profile.scaling_mod_size = selected->scaling_mod_size;
    profile.eval_noise_bits = selected->eval_noise_bits;
    profile.ring_dim_natural = selected->natural_ring_dim;
    profile.CaptureValidationSnapshot();
    return profile;
}

ExplicitRingCandidateSet BuildExplicitRingCandidateSet(
    const ExplicitRingCandidateRequest& request,
    uint32_t transcript_stat_bits,
    uint64_t max_queries,
    uint32_t flood_margin_bits) {
    constexpr uint32_t kMaximumRingDimension = 1048576;
    ValidatePreThresholdProfilePolicy(
        request.profile_id,
        transcript_stat_bits,
        max_queries,
        flood_margin_bits);
    const PreThresholdProfilePolicy policy =
        ResolvePreThresholdProfilePolicy(request.profile_id);
    if (request.security != SecurityLevel::STD128 &&
        request.security != SecurityLevel::STD192) {
        throw std::invalid_argument(
            "explicit ring candidates accept only STD128 or STD192");
    }
    if (!IsPowerOfTwo(request.natural_ring_dim) ||
        request.natural_ring_dim > kMaximumRingDimension) {
        throw std::invalid_argument(
            "natural ring dimension must be a bounded power of two");
    }
    if (request.candidates.empty() ||
        request.candidates.front() != request.natural_ring_dim) {
        throw std::invalid_argument(
            "explicit ring candidates must start at measured natural N");
    }

    for (size_t index = 0; index < request.candidates.size(); ++index) {
        const uint32_t candidate = request.candidates[index];
        if (!IsPowerOfTwo(candidate) ||
            candidate > kMaximumRingDimension) {
            throw std::invalid_argument(
                "ring candidates must be bounded powers of two");
        }
        if (index != 0) {
            const uint32_t previous = request.candidates[index - 1];
            if (previous > kMaximumRingDimension / 2 ||
                candidate != previous * 2) {
                throw std::invalid_argument(
                    "ring candidates must be strictly monotone doublings");
            }
        }
        const uint32_t growth = candidate / request.natural_ring_dim;
        const bool allowed =
            growth != 0 && growth <= policy.maximum_ring_growth &&
            IsPowerOfTwo(growth);
        if (!allowed) {
            throw std::invalid_argument(
                "ring growth factor is forbidden for this profile policy");
        }
    }

    return ExplicitRingCandidateSet{
        request.profile_id,
        request.security,
        request.natural_ring_dim,
        request.candidates,
    };
}

void CalibrationAccess::ArmThresholdProbe(
    PiccardParams& params,
    const ThresholdCalibrationOverride& row) {
    if (!params.threshold_mode) {
        throw std::invalid_argument(
            "threshold probe arming requires threshold_mode");
    }
    params.threshold_calibration_override = row;
    params.threshold_probe_arming_ = true;
    // Validate() re-derives and then runs the unchanged threshold selector,
    // which validates `row`, applies the feasibility inequality, sizes the
    // flooding term and captures the revalidation snapshot. That snapshot is
    // exactly what AdoptVerifiedRuntimeRingDim requires.
    params.Validate();
}

}  // namespace piccard
