#include "benchmark_provenance.h"

#include "build_info.h"
#include "fhe/bfv_context.h"

#include "scheme/bfvrns/bfvrns-cryptoparameters.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace piccard {
namespace benchmark {
namespace {

bool HasAnyLegacyFheField(const BenchmarkProvenance& provenance) {
    return provenance.actual_ring_dim.has_value() ||
           provenance.log_q_bits.has_value() ||
           provenance.plaintext_modulus.has_value() ||
           provenance.num_limbs.has_value();
}

bool HasAllLegacyFheFields(const BenchmarkProvenance& provenance) {
    return provenance.actual_ring_dim.has_value() &&
           provenance.log_q_bits.has_value() &&
           provenance.plaintext_modulus.has_value() &&
           provenance.num_limbs.has_value();
}

bool HasAnyVersionedContextField(const BenchmarkProvenance& provenance) {
    return provenance.requested_ring_dim.has_value() ||
           provenance.natural_ring_dim.has_value() ||
           provenance.provisioned_ring_dim.has_value() ||
           provenance.realized_ring_dim.has_value() ||
           provenance.calibrated_ring_dim.has_value() ||
           provenance.ring_dim_calibrated.has_value() ||
           provenance.natural_mult_depth.has_value() ||
           provenance.mult_depth.has_value() ||
           provenance.natural_depth.has_value() ||
           provenance.provisioned_depth.has_value() ||
           provenance.log2_q_over_t_bits.has_value() ||
           provenance.log_q_over_t_bits.has_value() ||
           provenance.log2_q_over_t.has_value() ||
           !provenance.ordered_rns_limb_bits.empty() ||
           !provenance.ordered_rns_limb_bit_sizes.empty() ||
           !provenance.ordered_rns_moduli.empty() ||
           provenance.realized_scaling_mod_size.has_value();
}

bool HasAnySanitizerField(const BenchmarkProvenance& provenance) {
    return provenance.transcript_stat_bits.has_value() ||
           provenance.max_queries.has_value() ||
           provenance.query_stat_bits.has_value() ||
           provenance.coefficient_stat_bits.has_value() ||
           provenance.flood_margin_bits.has_value() ||
           provenance.eval_noise_bits.has_value() ||
           provenance.flood_noise_bits.has_value() ||
           provenance.scaling_mod_size.has_value();
}

bool IsVersioned(const BenchmarkProvenance& provenance) {
    return provenance.schema_version == kBenchmarkProvenanceSchemaVersion;
}

void RequireToken(const std::string& value, const char* field) {
    if (value.empty() || value.find_first_of("\t\n\r") != std::string::npos) {
        throw std::invalid_argument(std::string("invalid provenance ") + field);
    }
}

template <typename T>
void RequireOptionalEqual(const std::optional<T>& left,
                          const std::optional<T>& right,
                          const char* field) {
    if (left.has_value() && right.has_value() && left != right) {
        throw std::logic_error(std::string("provenance alias disagrees: ") +
                               field);
    }
}

double RequireFinitePositive(double value, const char* field) {
    if (!std::isfinite(value) || value <= 0.0) {
        throw std::logic_error(std::string("provenance ") + field +
                               " must be finite and positive");
    }
    return value;
}

uint32_t RequirePositive(uint32_t value, const char* field) {
    if (value == 0) {
        throw std::logic_error(std::string("provenance ") + field +
                               " must be positive");
    }
    return value;
}

std::string FormatDouble(double value) {
    if (!std::isfinite(value)) {
        throw std::invalid_argument("provenance floating value must be finite");
    }
    std::ostringstream output;
    output << std::setprecision(17) << value;
    return output.str();
}

std::string OptionalU32(const std::optional<uint32_t>& value) {
    return value.has_value() ? std::to_string(*value) : "N/A";
}

std::string OptionalU64(const std::optional<uint64_t>& value) {
    return value.has_value() ? std::to_string(*value) : "N/A";
}

std::string OptionalDouble(const std::optional<double>& value) {
    return value.has_value() ? FormatDouble(*value) : "N/A";
}

uint64_t ParseUnsigned(const std::string& value, const char* field) {
    RequireToken(value, field);
    if (value == "N/A" || value.front() == '+' || value.front() == '-' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        throw std::invalid_argument(std::string("invalid provenance ") + field);
    }
    size_t consumed = 0;
    unsigned long long parsed = 0;
    try {
        parsed = std::stoull(value, &consumed, 10);
    } catch (...) {
        throw std::invalid_argument(std::string("invalid provenance ") + field);
    }
    if (consumed != value.size()) {
        throw std::invalid_argument(std::string("invalid provenance ") + field);
    }
    return static_cast<uint64_t>(parsed);
}

uint32_t ParseU32(const std::string& value, const char* field) {
    const uint64_t parsed = ParseUnsigned(value, field);
    if (parsed > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(std::string("provenance ") + field +
                                    " exceeds uint32");
    }
    return static_cast<uint32_t>(parsed);
}

std::optional<uint32_t> ParseOptionalU32(const std::string& value,
                                         const char* field) {
    return value == "N/A" ? std::nullopt
                           : std::optional<uint32_t>(ParseU32(value, field));
}

std::optional<uint64_t> ParseOptionalU64(const std::string& value,
                                         const char* field) {
    return value == "N/A" ? std::nullopt
                           : std::optional<uint64_t>(ParseUnsigned(value, field));
}

double ParseDouble(const std::string& value, const char* field) {
    RequireToken(value, field);
    if (value == "N/A") {
        throw std::invalid_argument(std::string("missing provenance ") + field);
    }
    size_t consumed = 0;
    double parsed = 0.0;
    try {
        parsed = std::stod(value, &consumed);
    } catch (...) {
        throw std::invalid_argument(std::string("invalid provenance ") + field);
    }
    if (consumed != value.size() || !std::isfinite(parsed)) {
        throw std::invalid_argument(std::string("invalid provenance ") + field);
    }
    return parsed;
}

std::optional<double> ParseOptionalDouble(const std::string& value,
                                          const char* field) {
    return value == "N/A" ? std::nullopt
                           : std::optional<double>(ParseDouble(value, field));
}

std::vector<std::string> Split(const std::string& value, char delimiter) {
    if (value == "N/A" || value.empty()) return {};
    std::vector<std::string> result;
    size_t start = 0;
    while (true) {
        const size_t end = value.find(delimiter, start);
        const std::string token = value.substr(
            start, end == std::string::npos ? std::string::npos : end - start);
        RequireToken(token, "vector element");
        result.push_back(token);
        if (end == std::string::npos) return result;
        start = end + 1;
    }
}

std::string Join(const std::vector<std::string>& values) {
    if (values.empty()) return "N/A";
    std::ostringstream output;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) output << ',';
        output << values[index];
    }
    return output.str();
}

std::string JoinU32(const std::vector<uint32_t>& values) {
    if (values.empty()) return "N/A";
    std::vector<std::string> strings;
    strings.reserve(values.size());
    for (const uint32_t value : values) strings.push_back(std::to_string(value));
    return Join(strings);
}

std::vector<uint32_t> ParseU32Vector(const std::string& value,
                                     const char* field) {
    std::vector<uint32_t> result;
    for (const auto& token : Split(value, ',')) result.push_back(ParseU32(token, field));
    return result;
}

uint32_t DecimalBitLength(const std::string& value) {
    RequireToken(value, "ordered_rns_moduli");
    if (value.front() == '0' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        throw std::logic_error("ordered RNS modulus is not canonical decimal");
    }
    std::string remaining = value;
    uint32_t bits = 0;
    while (remaining != "0") {
        std::string quotient;
        quotient.reserve(remaining.size());
        unsigned carry = 0;
        for (const char digit : remaining) {
            const unsigned value10 = carry * 10u +
                                     static_cast<unsigned>(digit - '0');
            const unsigned next = value10 / 2u;
            carry = value10 % 2u;
            if (!quotient.empty() || next != 0) {
                quotient.push_back(static_cast<char>('0' + next));
            }
        }
        remaining = quotient.empty() ? "0" : std::move(quotient);
        ++bits;
    }
    return bits;
}

void AppendLine(std::ostringstream& output, const char* key,
                const std::string& value) {
    RequireToken(value, key);
    output << key << '\t' << value << '\n';
}

void AppendOptionalLine(std::ostringstream& output, const char* key,
                        const std::string& value) {
    output << key << '\t' << value << '\n';
}

BenchmarkProvenance MakeLiveFheProvenance(const BFVContext& context) {
    const BFVRuntimeMetadata runtime = context.GetRuntimeMetadata();
    BenchmarkProvenance provenance;
    provenance.schema_version = kBenchmarkProvenanceSchemaVersion;
    provenance.actual_ring_dim = runtime.actual_ring_dim;
    provenance.log_q_bits = runtime.log_q_bits;
    provenance.plaintext_modulus = runtime.plaintext_modulus;
    provenance.num_limbs = runtime.num_limbs;
    provenance.openfhe_version = runtime.openfhe_version;

    provenance.requested_ring_dim = runtime.requested_ring_dim;
    provenance.natural_ring_dim = runtime.natural_ring_dim;
    const uint32_t selected_ring = context.GetParams().SelectedCalibratedRingDim();
    provenance.provisioned_ring_dim = selected_ring != 0
                                           ? selected_ring
                                           : runtime.actual_ring_dim;
    provenance.realized_ring_dim = runtime.actual_ring_dim;
    provenance.calibrated_ring_dim = provenance.provisioned_ring_dim;
    provenance.ring_dim_calibrated = provenance.provisioned_ring_dim;
    provenance.natural_depth = runtime.natural_depth;
    provenance.provisioned_depth = runtime.provisioned_depth;
    provenance.natural_mult_depth = provenance.natural_depth;
    provenance.mult_depth = provenance.provisioned_depth;
    provenance.log2_q_over_t_bits =
        runtime.log_q_bits -
        std::log2(static_cast<double>(runtime.plaintext_modulus));
    provenance.log_q_over_t_bits = provenance.log2_q_over_t_bits;
    provenance.log2_q_over_t = provenance.log2_q_over_t_bits;
    provenance.realized_scaling_mod_size = runtime.scaling_mod_size;

    const auto crypto_params = context.GetCryptoContext()->GetCryptoParameters();
    const auto element_params = crypto_params->GetElementParams();
    if (!element_params) {
        throw std::runtime_error("realized BFV context has no element parameters");
    }
    const auto& towers = element_params->GetParams();
    provenance.ordered_rns_limb_bits.reserve(towers.size());
    provenance.ordered_rns_moduli.reserve(towers.size());
    for (const auto& tower : towers) {
        if (!tower) throw std::runtime_error("realized BFV context has null RNS tower");
        provenance.ordered_rns_limb_bits.push_back(
            static_cast<uint32_t>(tower->GetModulus().GetMSB()));
        provenance.ordered_rns_moduli.push_back(tower->GetModulus().ToString());
    }
    provenance.ordered_rns_limb_bit_sizes = provenance.ordered_rns_limb_bits;
    provenance.residual_capacity_definition = kResidualCapacityDefinition;
    provenance.residual_capacity_status = kResidualCapacityStatusNotExposedByOpenFhe;
    provenance.flooding_assurance = kFloodingAssuranceNotApplicable;
    return provenance;
}

}  // namespace

const char* FloodingAssuranceName(FloodingAssurance assurance) {
    switch (assurance) {
        case FloodingAssurance::NotApplicable:
            return kFloodingAssuranceNotApplicable;
        case FloodingAssurance::EmpiricalPhaseStatisticalCiphertextComputational:
            return kFloodingAssuranceEmpiricalPhaseStatisticalCiphertextComputational;
        case FloodingAssurance::LegacyCoefficientLevel:
            return kFloodingAssuranceLegacyCoefficientLevel;
    }
    throw std::logic_error("unknown flooding assurance");
}

bool IsValidFloodingAssurance(const std::string& assurance) {
    return assurance == kFloodingAssuranceNotApplicable ||
           assurance ==
               kFloodingAssuranceEmpiricalPhaseStatisticalCiphertextComputational ||
           assurance == kFloodingAssuranceLegacyCoefficientLevel;
}

BenchmarkProvenance MakePiccardBenchmarkProvenance(
    const BFVContext& context) {
    BenchmarkProvenance provenance = MakeLiveFheProvenance(context);
    const PiccardParams& params = context.GetParams();
    if (!params.FloodingSized()) {
        throw std::logic_error(
            "Piccard provenance requires selected sanitizer parameters");
    }
    provenance.sanitizer_applicable = true;
    provenance.transcript_stat_bits = params.transcript_stat_bits;
    provenance.max_queries = params.max_queries;
    provenance.query_stat_bits = params.QueryStatBits();
    provenance.coefficient_stat_bits = params.CoefficientStatBits();
    provenance.flood_margin_bits = params.flood_margin_bits;
    provenance.eval_noise_bits = params.eval_noise_bits;
    provenance.flood_noise_bits = params.FloodNoiseBits();
    provenance.scaling_mod_size = params.scaling_mod_size;
    provenance.flooding_assurance =
        params.threshold_mode
            ? kFloodingAssuranceLegacyCoefficientLevel
            : kFloodingAssuranceEmpiricalPhaseStatisticalCiphertextComputational;
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

BenchmarkProvenance MakeFheIndBenchmarkProvenance(
    const BFVContext& context) {
    BenchmarkProvenance provenance = MakeLiveFheProvenance(context);
    provenance.sanitizer_applicable = false;
    provenance.flooding_assurance = kFloodingAssuranceNotApplicable;
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

BenchmarkProvenance MakeAheBenchmarkProvenance() {
    BenchmarkProvenance provenance;
    provenance.schema_version = kBenchmarkProvenanceSchemaVersion;
    provenance.openfhe_version = "not-applicable";
    provenance.flooding_assurance = kFloodingAssuranceNotApplicable;
    provenance.residual_capacity_definition = kResidualCapacityStatusNotApplicable;
    provenance.residual_capacity_status = kResidualCapacityStatusNotApplicable;
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

BenchmarkProvenance MakeEncodingOnlyBenchmarkProvenance() {
    BenchmarkProvenance provenance = MakeAheBenchmarkProvenance();
    provenance.encoding_only = true;
    provenance.legacy_encoding_note = kLegacyEncodingSupersededNote;
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

uint64_t SumOrderedRnsLimbBits(
    const std::vector<uint32_t>& ordered_rns_limb_bits) {
    uint64_t sum = 0;
    for (const uint32_t bits : ordered_rns_limb_bits) {
        if (bits == 0 || sum > std::numeric_limits<uint64_t>::max() - bits) {
            throw std::invalid_argument("invalid ordered RNS limb bit size");
        }
        sum += bits;
    }
    return sum;
}

bool ValidateBenchmarkProvenance(const BenchmarkProvenance& provenance) {
    const bool any_legacy = HasAnyLegacyFheField(provenance);
    const bool all_legacy = HasAllLegacyFheFields(provenance);
    if (any_legacy != all_legacy) {
        throw std::logic_error("partial FHE benchmark provenance");
    }

    if (!provenance.schema_version.empty() && !IsVersioned(provenance)) {
        throw std::logic_error("unknown benchmark provenance schema version");
    }
    const bool versioned = IsVersioned(provenance);
    const bool any_versioned = HasAnyVersionedContextField(provenance);

    RequireOptionalEqual(provenance.actual_ring_dim,
                         provenance.realized_ring_dim,
                         "actual_ring_dim/realized_ring_dim");
    RequireOptionalEqual(provenance.provisioned_ring_dim,
                         provenance.calibrated_ring_dim,
                         "provisioned_ring_dim/calibrated_ring_dim");
    RequireOptionalEqual(provenance.provisioned_ring_dim,
                         provenance.ring_dim_calibrated,
                         "provisioned_ring_dim/ring_dim_calibrated");
    RequireOptionalEqual(provenance.natural_depth,
                         provenance.natural_mult_depth,
                         "natural_depth/natural_mult_depth");
    RequireOptionalEqual(provenance.provisioned_depth,
                         provenance.mult_depth,
                         "provisioned_depth/mult_depth");
    RequireOptionalEqual(provenance.log2_q_over_t_bits,
                         provenance.log_q_over_t_bits,
                         "log2_q_over_t_bits/log_q_over_t_bits");
    RequireOptionalEqual(provenance.log2_q_over_t_bits,
                         provenance.log2_q_over_t,
                         "log2_q_over_t_bits/log2_q_over_t");
    if (!provenance.ordered_rns_limb_bits.empty() &&
        !provenance.ordered_rns_limb_bit_sizes.empty() &&
        provenance.ordered_rns_limb_bits != provenance.ordered_rns_limb_bit_sizes) {
        throw std::logic_error("ordered RNS limb-bit aliases disagree");
    }

    const bool all_sanitizer =
        provenance.transcript_stat_bits.has_value() &&
        provenance.max_queries.has_value() &&
        provenance.query_stat_bits.has_value() &&
        provenance.coefficient_stat_bits.has_value() &&
        provenance.flood_margin_bits.has_value() &&
        provenance.eval_noise_bits.has_value() &&
        provenance.flood_noise_bits.has_value() &&
        provenance.scaling_mod_size.has_value();
    const bool any_sanitizer = HasAnySanitizerField(provenance);
    if (provenance.sanitizer_applicable != all_sanitizer ||
        (!provenance.sanitizer_applicable && any_sanitizer)) {
        throw std::logic_error("inconsistent sanitizer provenance");
    }

    if (!provenance.flooding_assurance.empty() &&
        !IsValidFloodingAssurance(provenance.flooding_assurance)) {
        throw std::logic_error("unknown flooding assurance taxonomy value");
    }
    if (provenance.sanitizer_applicable) {
        if (provenance.flooding_assurance == kFloodingAssuranceNotApplicable) {
            throw std::logic_error("applicable sanitizer cannot be N/A");
        }
        if (provenance.flooding_assurance ==
                kFloodingAssuranceLegacyCoefficientLevel &&
            provenance.query_stat_bits.has_value() &&
            *provenance.query_stat_bits != 0) {
            throw std::logic_error(
                "legacy coefficient-level flooding must have query_stat_bits=0");
        }
    } else if (versioned &&
               provenance.flooding_assurance != kFloodingAssuranceNotApplicable) {
        throw std::logic_error("non-sanitized v2 provenance must be N/A");
    }

    if (provenance.residual_capacity_bits.has_value()) {
        if (!std::isfinite(*provenance.residual_capacity_bits) ||
            *provenance.residual_capacity_bits < 0.0) {
            throw std::logic_error("invalid residual capacity value");
        }
        if (provenance.residual_capacity_status !=
            kResidualCapacityStatusAvailable) {
            throw std::logic_error(
                "residual value requires available residual-capacity status");
        }
    }
    if (provenance.residual_capacity_status ==
            kResidualCapacityStatusNotExposedByOpenFhe &&
        provenance.residual_capacity_bits.has_value()) {
        throw std::logic_error(
            "not-exposed residual capacity must not carry a fabricated value");
    }
    if (!provenance.legacy_encoding_note.empty() &&
        provenance.legacy_encoding_note != kLegacyEncodingSupersededNote) {
        throw std::logic_error("unknown legacy encoding note");
    }

    if (provenance.encoding_only) {
        if (!versioned || any_legacy || any_versioned ||
            provenance.openfhe_version != "not-applicable" ||
            provenance.sanitizer_applicable || any_sanitizer ||
            provenance.flooding_assurance != kFloodingAssuranceNotApplicable ||
            provenance.legacy_encoding_note != kLegacyEncodingSupersededNote) {
            throw std::logic_error(
                "encoding-only provenance must not contain FHE fields");
        }
        if (!provenance.ordered_rns_limb_bits.empty() ||
            !provenance.ordered_rns_limb_bit_sizes.empty() ||
            !provenance.ordered_rns_moduli.empty() ||
            provenance.residual_capacity_bits.has_value() ||
            provenance.residual_capacity_status !=
                kResidualCapacityStatusNotApplicable ||
            provenance.residual_capacity_definition !=
                kResidualCapacityStatusNotApplicable) {
            throw std::logic_error(
                "encoding-only provenance requires N/A FHE metadata");
        }
        return false;
    }

    if (!all_legacy) {
        if (any_versioned) {
            throw std::logic_error("versioned context fields require live FHE fields");
        }
        if (provenance.openfhe_version != "not-applicable") {
            throw std::logic_error(
                "non-FHE benchmark provenance must use not-applicable version");
        }
        if (versioned &&
            provenance.flooding_assurance != kFloodingAssuranceNotApplicable) {
            throw std::logic_error("non-FHE v2 provenance must use N/A assurance");
        }
        if (versioned &&
            provenance.residual_capacity_status !=
                kResidualCapacityStatusNotApplicable) {
            throw std::logic_error("non-FHE v2 residual capacity must be N/A");
        }
        return false;
    }

    if (*provenance.actual_ring_dim == 0 ||
        !std::isfinite(*provenance.log_q_bits) ||
        *provenance.log_q_bits <= 0.0 ||
        *provenance.plaintext_modulus == 0 || *provenance.num_limbs == 0) {
        throw std::logic_error("live FHE benchmark provenance must be positive");
    }
    if (provenance.openfhe_version.empty() ||
        provenance.openfhe_version == "unknown" ||
        provenance.openfhe_version == "not-applicable") {
        throw std::logic_error(
            "live FHE benchmark provenance has invalid OpenFHE version");
    }
    if (provenance.openfhe_version != PICCARD_BUILD_OPENFHE_VERSION) {
        throw std::logic_error(
            "runtime OpenFHE version disagrees with configured build");
    }
    if (provenance.sanitizer_applicable && !all_legacy) {
        throw std::logic_error("Piccard sanitizer requires live FHE provenance");
    }

    if (!versioned) return true;

    const auto require_v2 = [&](const std::optional<uint32_t>& value,
                                const char* field) {
        if (!value.has_value()) RequirePositive(0, field);
        RequirePositive(*value, field);
    };
    require_v2(provenance.requested_ring_dim, "requested_ring_dim");
    require_v2(provenance.natural_ring_dim, "natural_ring_dim");
    require_v2(provenance.provisioned_ring_dim, "provisioned_ring_dim");
    require_v2(provenance.realized_ring_dim, "realized_ring_dim");
    require_v2(provenance.natural_depth, "natural_depth");
    require_v2(provenance.provisioned_depth, "provisioned_depth");
    if (*provenance.requested_ring_dim > *provenance.natural_ring_dim ||
        *provenance.natural_ring_dim > *provenance.provisioned_ring_dim) {
        throw std::logic_error("ring dimensions are not monotone");
    }
    if (*provenance.natural_depth > *provenance.provisioned_depth) {
        throw std::logic_error("depths are not monotone");
    }
    if (!provenance.log2_q_over_t_bits.has_value()) {
        throw std::logic_error("missing log2(q/t) provenance");
    }
    RequireFinitePositive(*provenance.log2_q_over_t_bits, "log2(q/t)");
    const double derived_log_delta =
        *provenance.log_q_bits -
        std::log2(static_cast<double>(*provenance.plaintext_modulus));
    if (std::abs(derived_log_delta - *provenance.log2_q_over_t_bits) > 1e-7) {
        throw std::logic_error("log2(q/t) disagrees with q and t");
    }
    if (provenance.ordered_rns_limb_bits.empty() ||
        provenance.ordered_rns_limb_bits.size() != *provenance.num_limbs ||
        (!provenance.ordered_rns_limb_bit_sizes.empty() &&
         provenance.ordered_rns_limb_bit_sizes != provenance.ordered_rns_limb_bits) ||
        (!provenance.ordered_rns_moduli.empty() &&
         provenance.ordered_rns_moduli.size() != provenance.ordered_rns_limb_bits.size())) {
        throw std::logic_error("ordered RNS limb metadata is incomplete");
    }
    const uint64_t limb_sum = SumOrderedRnsLimbBits(provenance.ordered_rns_limb_bits);
    if (std::llround(*provenance.log_q_bits) !=
        static_cast<long long>(limb_sum)) {
        throw std::logic_error("ordered RNS limb bits disagree with log_q_bits");
    }
    if (!provenance.ordered_rns_moduli.empty()) {
        for (size_t index = 0; index < provenance.ordered_rns_moduli.size(); ++index) {
            if (DecimalBitLength(provenance.ordered_rns_moduli[index]) !=
                provenance.ordered_rns_limb_bits[index]) {
                throw std::logic_error(
                    "ordered RNS limb bits disagree with ordered modulus");
            }
        }
    }
    if (provenance.residual_capacity_definition != kResidualCapacityDefinition ||
        provenance.residual_capacity_status !=
            kResidualCapacityStatusNotExposedByOpenFhe) {
        throw std::logic_error("v2 live provenance lacks residual-capacity status");
    }
    return true;
}

std::string SerializeBenchmarkProvenanceV2(
    const BenchmarkProvenance& provenance) {
    ValidateBenchmarkProvenance(provenance);
    if (!IsVersioned(provenance)) {
        throw std::invalid_argument(
            "versioned provenance serializer requires schema_version v2");
    }
    std::ostringstream output;
    AppendLine(output, "schema_version", provenance.schema_version);
    AppendLine(output, "encoding_only", provenance.encoding_only ? "true" : "false");
    AppendOptionalLine(output, "actual_ring_dim", OptionalU32(provenance.actual_ring_dim));
    AppendOptionalLine(output, "requested_ring_dim", OptionalU32(provenance.requested_ring_dim));
    AppendOptionalLine(output, "natural_ring_dim", OptionalU32(provenance.natural_ring_dim));
    AppendOptionalLine(output, "provisioned_ring_dim", OptionalU32(provenance.provisioned_ring_dim));
    AppendOptionalLine(output, "realized_ring_dim", OptionalU32(provenance.realized_ring_dim));
    AppendOptionalLine(output, "natural_depth", OptionalU32(provenance.natural_depth));
    AppendOptionalLine(output, "provisioned_depth", OptionalU32(provenance.provisioned_depth));
    AppendOptionalLine(output, "log_q_bits", OptionalDouble(provenance.log_q_bits));
    AppendOptionalLine(output, "log2_q_over_t_bits", OptionalDouble(provenance.log2_q_over_t_bits));
    AppendOptionalLine(output, "plaintext_modulus", OptionalU64(provenance.plaintext_modulus));
    AppendOptionalLine(output, "num_limbs", OptionalU32(provenance.num_limbs));
    AppendOptionalLine(output, "ordered_rns_limb_bits", JoinU32(provenance.ordered_rns_limb_bits));
    AppendOptionalLine(output, "ordered_rns_moduli", Join(provenance.ordered_rns_moduli));
    AppendLine(output, "openfhe_version", provenance.openfhe_version);
    AppendLine(output, "flooding_assurance", provenance.flooding_assurance);
    AppendOptionalLine(output, "transcript_stat_bits", OptionalU32(provenance.transcript_stat_bits));
    AppendOptionalLine(output, "max_queries", OptionalU64(provenance.max_queries));
    AppendOptionalLine(output, "query_stat_bits", OptionalU32(provenance.query_stat_bits));
    AppendOptionalLine(output, "coefficient_stat_bits", OptionalU32(provenance.coefficient_stat_bits));
    AppendOptionalLine(output, "flood_margin_bits", OptionalU32(provenance.flood_margin_bits));
    AppendOptionalLine(output, "eval_noise_bits", OptionalU32(provenance.eval_noise_bits));
    AppendOptionalLine(output, "flood_noise_bits", OptionalU32(provenance.flood_noise_bits));
    AppendOptionalLine(output, "scaling_mod_size", OptionalU32(provenance.scaling_mod_size));
    AppendOptionalLine(output, "realized_scaling_mod_size", OptionalU32(provenance.realized_scaling_mod_size));
    AppendLine(output, "residual_capacity_definition", provenance.residual_capacity_definition);
    AppendLine(output, "residual_capacity_status", provenance.residual_capacity_status);
    AppendOptionalLine(output, "residual_capacity_bits", OptionalDouble(provenance.residual_capacity_bits));
    AppendOptionalLine(output, "legacy_encoding_note",
                       provenance.legacy_encoding_note.empty()
                           ? "N/A"
                           : provenance.legacy_encoding_note);
    return output.str();
}

BenchmarkProvenance ParseBenchmarkProvenanceV2(
    const std::string& serialized) {
    if (serialized.empty() || serialized.back() != '\n') {
        throw std::invalid_argument("provenance-v2 must end with LF");
    }
    static const std::vector<std::string> keys = {
        "schema_version", "encoding_only", "actual_ring_dim",
        "requested_ring_dim", "natural_ring_dim", "provisioned_ring_dim",
        "realized_ring_dim", "natural_depth", "provisioned_depth",
        "log_q_bits", "log2_q_over_t_bits", "plaintext_modulus", "num_limbs",
        "ordered_rns_limb_bits", "ordered_rns_moduli", "openfhe_version",
        "flooding_assurance", "transcript_stat_bits", "max_queries",
        "query_stat_bits", "coefficient_stat_bits", "flood_margin_bits",
        "eval_noise_bits", "flood_noise_bits", "scaling_mod_size",
        "realized_scaling_mod_size", "residual_capacity_definition",
        "residual_capacity_status", "residual_capacity_bits",
        "legacy_encoding_note"};

    std::map<std::string, std::string> fields;
    size_t start = 0;
    while (start < serialized.size()) {
        const size_t end = serialized.find('\n', start);
        if (end == std::string::npos) break;
        const std::string line = serialized.substr(start, end - start);
        const size_t tab = line.find('\t');
        if (tab == std::string::npos || line.find('\t', tab + 1) != std::string::npos) {
            throw std::invalid_argument("provenance-v2 row shape mismatch");
        }
        const std::string key = line.substr(0, tab);
        const std::string value = line.substr(tab + 1);
        if (std::find(keys.begin(), keys.end(), key) == keys.end() ||
            !fields.emplace(key, value).second) {
            throw std::invalid_argument("provenance-v2 unknown/duplicate field");
        }
        start = end + 1;
    }
    if (fields.size() != keys.size()) {
        throw std::invalid_argument("provenance-v2 field set is incomplete");
    }
    const auto value = [&](const char* key) -> const std::string& {
        return fields.at(key);
    };
    BenchmarkProvenance provenance;
    provenance.schema_version = value("schema_version");
    if (value("encoding_only") == "true") {
        provenance.encoding_only = true;
    } else if (value("encoding_only") != "false") {
        throw std::invalid_argument("invalid provenance encoding_only");
    }
    provenance.actual_ring_dim = ParseOptionalU32(value("actual_ring_dim"), "actual_ring_dim");
    provenance.requested_ring_dim = ParseOptionalU32(value("requested_ring_dim"), "requested_ring_dim");
    provenance.natural_ring_dim = ParseOptionalU32(value("natural_ring_dim"), "natural_ring_dim");
    provenance.provisioned_ring_dim = ParseOptionalU32(value("provisioned_ring_dim"), "provisioned_ring_dim");
    provenance.realized_ring_dim = ParseOptionalU32(value("realized_ring_dim"), "realized_ring_dim");
    provenance.calibrated_ring_dim = provenance.provisioned_ring_dim;
    provenance.ring_dim_calibrated = provenance.provisioned_ring_dim;
    provenance.natural_depth = ParseOptionalU32(value("natural_depth"), "natural_depth");
    provenance.provisioned_depth = ParseOptionalU32(value("provisioned_depth"), "provisioned_depth");
    provenance.natural_mult_depth = provenance.natural_depth;
    provenance.mult_depth = provenance.provisioned_depth;
    provenance.log_q_bits = ParseOptionalDouble(value("log_q_bits"), "log_q_bits");
    provenance.log2_q_over_t_bits = ParseOptionalDouble(value("log2_q_over_t_bits"), "log2_q_over_t_bits");
    provenance.log_q_over_t_bits = provenance.log2_q_over_t_bits;
    provenance.log2_q_over_t = provenance.log2_q_over_t_bits;
    provenance.plaintext_modulus = ParseOptionalU64(value("plaintext_modulus"), "plaintext_modulus");
    provenance.num_limbs = ParseOptionalU32(value("num_limbs"), "num_limbs");
    provenance.ordered_rns_limb_bits = ParseU32Vector(value("ordered_rns_limb_bits"), "ordered_rns_limb_bits");
    provenance.ordered_rns_limb_bit_sizes = provenance.ordered_rns_limb_bits;
    for (const auto& token : Split(value("ordered_rns_moduli"), ',')) {
        provenance.ordered_rns_moduli.push_back(token);
    }
    provenance.openfhe_version = value("openfhe_version");
    provenance.flooding_assurance = value("flooding_assurance");
    provenance.transcript_stat_bits = ParseOptionalU32(value("transcript_stat_bits"), "transcript_stat_bits");
    provenance.max_queries = ParseOptionalU64(value("max_queries"), "max_queries");
    provenance.query_stat_bits = ParseOptionalU32(value("query_stat_bits"), "query_stat_bits");
    provenance.coefficient_stat_bits = ParseOptionalU32(value("coefficient_stat_bits"), "coefficient_stat_bits");
    provenance.flood_margin_bits = ParseOptionalU32(value("flood_margin_bits"), "flood_margin_bits");
    provenance.eval_noise_bits = ParseOptionalU32(value("eval_noise_bits"), "eval_noise_bits");
    provenance.flood_noise_bits = ParseOptionalU32(value("flood_noise_bits"), "flood_noise_bits");
    provenance.scaling_mod_size = ParseOptionalU32(value("scaling_mod_size"), "scaling_mod_size");
    provenance.realized_scaling_mod_size = ParseOptionalU32(value("realized_scaling_mod_size"), "realized_scaling_mod_size");
    provenance.residual_capacity_definition = value("residual_capacity_definition");
    provenance.residual_capacity_status = value("residual_capacity_status");
    provenance.residual_capacity_bits = ParseOptionalDouble(value("residual_capacity_bits"), "residual_capacity_bits");
    provenance.legacy_encoding_note = value("legacy_encoding_note") == "N/A"
                                          ? ""
                                          : value("legacy_encoding_note");
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

bool PrintBuildProvenanceIfRequested(int argc, char** argv) {
    if (argc != 2 || std::string(argv[1]) != "--print-build-provenance") {
        return false;
    }
    std::cout
        << "{\"build_type\":\"" << PICCARD_BUILD_TYPE
        << "\",\"commit\":\"" << PICCARD_BUILD_COMMIT
        << "\",\"dirty\":" << (PICCARD_BUILD_DIRTY ? "true" : "false")
        << ",\"openfhe_version\":\"" << PICCARD_BUILD_OPENFHE_VERSION
        << "\",\"schema\":\"piccard-build-provenance-v1\""
        << ",\"source_dir\":\"" << PICCARD_BUILD_SOURCE_DIR << "\"}\n";
    return true;
}

}  // namespace benchmark
}  // namespace piccard
