#pragma once

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace piccard {
namespace benchmark {

/**
 * @brief Historical threshold timing/accuracy CSV header.
 *
 * This function is deliberately kept byte-for-byte stable.  It is used by
 * every non-spec mode and is not the successor specification schema below.
 */
inline std::string ThresholdCSVHeader() {
    return
        "label,k,m,set_size,ring_dim,tau,mult_depth,"
        "phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,"
        "phase_multiply_ms,phase_rotate_sum_ms,phase_mask_ms,"
        "phase_poly_eval_ms,phase_decrypt_ms,total_ms,"
        "memory_bytes,ct_size_bytes,"
        "threshold_result,threshold_expected,threshold_correct,"
        "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
        "note,"
        "trials,"
        "total_ms_sd,total_ms_median,"
        "phase_minhash_ms_sd,phase_minhash_ms_median,"
        "phase_encode_ms_sd,phase_encode_ms_median,"
        "phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_multiply_ms_sd,phase_multiply_ms_median,"
        "phase_rotate_sum_ms_sd,phase_rotate_sum_ms_median,"
        "phase_mask_ms_sd,phase_mask_ms_median,"
        "phase_poly_eval_ms_sd,phase_poly_eval_ms_median,"
        "phase_decrypt_ms_sd,phase_decrypt_ms_median,"
        "rel_error_eligible_n,"
        // true-Jaccard truth columns (R3-4, additive)
        "j_tau,match_count,matchcount_expected,fhe_agrees,outcome,"
        "hash_randomness,hash_seed,hash_root_seed,accuracy_trials,"
        // Flooding columns (plan 8 schema, additive)
        "phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
        "flood_lambda_stat,flood_eval_noise_bits,flood_margin_bits,"
        "flood_noise_bits,scaling_mod_size\n";
}

// The spec output is a separate successor contract.  The version marker is
// emitted on every row, including a pre-context SKIPPED row.
inline constexpr const char* kThresholdSpecSchemaVersion =
    "piccard-threshold-spec-v2";
inline constexpr const char* kThresholdSpecSchemaVersionV2 =
    kThresholdSpecSchemaVersion;
inline constexpr const char* kThresholdSpecNotApplicable = "N/A";
inline constexpr const char* kThresholdSpecSkippedStatus = "SKIPPED";
inline constexpr const char* kThresholdFloodingAssuranceLegacyCoefficientLevel =
    "legacy-coefficient-level";
inline constexpr uint32_t kThresholdLegacyCoefficientStatBits = 64;
inline constexpr const char* kThresholdResidualCapacityDefinition =
    "log2(q/t)-required_flood_budget_bits";
inline constexpr const char* kThresholdResidualCapacityStatusNotExposedByOpenFhe =
    "not-exposed-by-openfhe";

/** @brief Versioned row for the threshold polynomial specification dump. */
struct ThresholdSpecRow {
    std::string schema_version = kThresholdSpecSchemaVersion;

    // Historical spec fields, retained first in the successor row.
    uint32_t k = 0;
    uint32_t tau = 0;
    uint32_t degree = 0;
    uint32_t ps_baby_s = 0;
    uint32_t ps_num_chunks = 0;
    uint32_t baby_depth = 0;
    uint32_t giant_mults = 0;
    uint32_t natural_mult_depth = 0;
    int64_t mult_depth = -1;
    int64_t scaling_mod_size = -1;
    int64_t ring_dim = -1;
    int64_t plaintext_mod = -1;
    double log2_q = -1.0;
    int64_t eval_noise_bits = -1;
    int64_t flood_noise_bits = -1;
    int64_t ct_bytes = -1;
    double poly_build_ms = -1.0;
    std::string status;
    std::string note;

    // Complete live V2 context metadata.
    uint32_t requested_ring_dim = 0;
    uint32_t natural_ring_dim = 0;
    uint32_t provisioned_ring_dim = 0;
    uint32_t realized_ring_dim = 0;
    uint32_t natural_depth = 0;
    uint32_t provisioned_depth = 0;
    double log_q_bits = 0.0;
    double log2_q_over_t_bits = 0.0;
    uint64_t plaintext_modulus = 0;
    uint32_t num_limbs = 0;
    uint32_t realized_scaling_mod_size = 0;
    std::vector<std::string> ordered_rns_moduli;
    std::vector<uint32_t> ordered_rns_limb_bits;
    std::string openfhe_version;

    // Threshold keeps the frozen legacy coefficient-level assurance.  The
    // common provenance constructor supplies these exact values; the row
    // validator additionally pins query_stat_bits to zero.
    std::string flooding_assurance;
    uint32_t transcript_stat_bits = 0;
    uint64_t max_queries = 0;
    uint32_t query_stat_bits = 0;
    uint32_t coefficient_stat_bits = 0;
    uint32_t flood_margin_bits = 0;
    uint32_t required_capacity_bits = 0;

    // OpenFHE does not expose a stable post-operation residual budget.
    std::string residual_capacity_definition;
    std::optional<double> residual_capacity_bits;
    std::string residual_capacity_status;

    uint64_t OrderedRnsLimbBitsSum() const {
        uint64_t sum = 0;
        for (const uint32_t bits : ordered_rns_limb_bits) sum += bits;
        return sum;
    }

    uint64_t SumOrderedRnsLimbBits() const {
        return OrderedRnsLimbBitsSum();
    }
};

inline bool IsThresholdSpecSkipped(const ThresholdSpecRow& row) {
    return row.status == kThresholdSpecSkippedStatus;
}

inline bool IsValidThresholdFloodingAssurance(const std::string& value) {
    return value == kThresholdFloodingAssuranceLegacyCoefficientLevel;
}

namespace detail {

inline uint32_t DecimalBitLength(const std::string& value) {
    if (value.empty() || value == "0" ||
        (value.size() > 1 && value.front() == '0') ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        throw std::invalid_argument("threshold RNS modulus is not decimal");
    }
    std::string remaining = value;
    uint32_t bits = 0;
    while (remaining != "0") {
        std::string quotient;
        unsigned carry = 0;
        for (const char digit : remaining) {
            const unsigned value10 = carry * 10u +
                                     static_cast<unsigned>(digit - '0');
            const unsigned next = value10 / 2u;
            carry = value10 % 2u;
            if (!quotient.empty() || next != 0)
                quotient.push_back(static_cast<char>('0' + next));
        }
        remaining = quotient.empty() ? "0" : std::move(quotient);
        ++bits;
    }
    return bits;
}

inline bool HasLiveMetadata(const ThresholdSpecRow& row) {
    return row.requested_ring_dim != 0 || row.natural_ring_dim != 0 ||
           row.provisioned_ring_dim != 0 || row.realized_ring_dim != 0 ||
           row.natural_depth != 0 || row.provisioned_depth != 0 ||
           row.log_q_bits != 0.0 || row.log2_q_over_t_bits != 0.0 ||
           row.plaintext_modulus != 0 || row.num_limbs != 0 ||
           row.realized_scaling_mod_size != 0 ||
           !row.ordered_rns_moduli.empty() ||
           !row.ordered_rns_limb_bits.empty() || !row.openfhe_version.empty() ||
           !row.flooding_assurance.empty() || row.transcript_stat_bits != 0 ||
           row.max_queries != 0 || row.query_stat_bits != 0 ||
           row.coefficient_stat_bits != 0 || row.flood_margin_bits != 0 ||
           row.required_capacity_bits != 0 ||
           !row.residual_capacity_definition.empty() ||
           row.residual_capacity_bits.has_value() ||
           !row.residual_capacity_status.empty();
}

inline std::string CsvToken(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const char c : value) {
        result.push_back(c == ',' || c == '\n' || c == '\r' ? ' ' : c);
    }
    return result;
}

inline std::string OptionalDouble(const std::optional<double>& value) {
    if (!value.has_value()) return kThresholdSpecNotApplicable;
    if (!std::isfinite(*value))
        throw std::invalid_argument("threshold residual value is not finite");
    std::ostringstream out;
    out << std::setprecision(17) << *value;
    return out.str();
}

inline std::string FormatDouble(double value) {
    if (!std::isfinite(value))
        throw std::invalid_argument("threshold spec value is not finite");
    std::ostringstream out;
    out << std::setprecision(17) << value;
    return out.str();
}

}  // namespace detail

/** @brief Validate the successor contract before serializing a row. */
inline void ValidateThresholdSpecRow(const ThresholdSpecRow& row) {
    if (row.schema_version != kThresholdSpecSchemaVersion)
        throw std::invalid_argument("threshold spec schema version mismatch");
    if (row.status.empty())
        throw std::invalid_argument("threshold spec status is required");
    if (IsThresholdSpecSkipped(row)) {
        if (detail::HasLiveMetadata(row)) {
            throw std::invalid_argument(
                "skipped threshold spec cannot contain live metadata");
        }
        return;
    }
    if (row.status != "ok")
        throw std::invalid_argument("unknown threshold spec row status");

    if (!IsValidThresholdFloodingAssurance(row.flooding_assurance))
        throw std::invalid_argument(
            "threshold spec must use legacy coefficient-level assurance");
    if (row.query_stat_bits != 0)
        throw std::invalid_argument(
            "threshold legacy spec must use query_stat_bits=0");
    if (row.coefficient_stat_bits != kThresholdLegacyCoefficientStatBits)
        throw std::invalid_argument(
            "threshold spec coefficient statistic must be 64 bits");
    if (row.residual_capacity_definition !=
            kThresholdResidualCapacityDefinition ||
        row.residual_capacity_status !=
            kThresholdResidualCapacityStatusNotExposedByOpenFhe ||
        row.residual_capacity_bits.has_value())
        throw std::invalid_argument(
            "threshold spec residual capacity must be explicitly unexposed");

    if (row.requested_ring_dim == 0 || row.natural_ring_dim == 0 ||
        row.provisioned_ring_dim == 0 || row.realized_ring_dim == 0 ||
        row.natural_depth == 0 || row.provisioned_depth == 0 ||
        row.plaintext_modulus == 0 || row.num_limbs == 0 ||
        row.realized_scaling_mod_size == 0 || row.openfhe_version.empty())
        throw std::invalid_argument(
            "measured threshold spec is missing live context metadata");
    if (!std::isfinite(row.log_q_bits) || row.log_q_bits <= 0.0 ||
        !std::isfinite(row.log2_q_over_t_bits) ||
        row.log2_q_over_t_bits <= 0.0)
        throw std::invalid_argument(
            "measured threshold spec requires finite q metadata");
    if (row.required_capacity_bits == 0)
        throw std::invalid_argument(
            "measured threshold spec is missing required capacity");
    if (row.num_limbs != row.ordered_rns_moduli.size() ||
        row.num_limbs != row.ordered_rns_limb_bits.size() ||
        row.ordered_rns_moduli.empty())
        throw std::invalid_argument(
            "threshold spec RNS metadata count is inconsistent");

    const uint64_t limb_sum = row.OrderedRnsLimbBitsSum();
    if (std::llround(row.log_q_bits) !=
        static_cast<long long>(limb_sum))
        throw std::invalid_argument(
            "threshold spec RNS limb sum disagrees with log2(q)");
    const double expected_q_over_t =
        row.log_q_bits - std::log2(static_cast<double>(row.plaintext_modulus));
    if (std::abs(expected_q_over_t - row.log2_q_over_t_bits) > 1e-7)
        throw std::invalid_argument(
            "threshold spec log2(q/t) disagrees with q and plaintext modulus");
    for (size_t index = 0; index < row.num_limbs; ++index) {
        if (row.ordered_rns_limb_bits[index] == 0 ||
            detail::DecimalBitLength(row.ordered_rns_moduli[index]) !=
                row.ordered_rns_limb_bits[index])
            throw std::invalid_argument(
                "threshold spec limb bits disagree with ordered modulus");
    }
    if (row.poly_build_ms >= 0.0 && !std::isfinite(row.poly_build_ms))
        throw std::invalid_argument("threshold polynomial time is not finite");
}

/** @brief Header for the additive versioned threshold spec rows. */
inline std::string ThresholdSpecCSVHeader() {
    return
        "k,tau,degree,ps_baby_s,ps_num_chunks,baby_depth,giant_mults,"
        "natural_mult_depth,mult_depth,scaling_mod_size,ring_dim,"
        "plaintext_mod,log2_q,eval_noise_bits,flood_noise_bits,ct_bytes,"
        "poly_build_ms,status,note,"
        "schema_version,requested_ring_dim,natural_ring_dim,"
        "provisioned_ring_dim,realized_ring_dim,natural_depth,"
        "provisioned_depth,log_q_bits,log2_q_over_t_bits,plaintext_modulus,"
        "num_limbs,realized_scaling_mod_size,ordered_rns_moduli,"
        "ordered_rns_limb_bits,ordered_rns_limb_bits_sum,openfhe_version,"
        "flooding_assurance,transcript_stat_bits,max_queries,query_stat_bits,"
        "coefficient_stat_bits,flood_margin_bits,required_capacity_bits,"
        "residual_capacity_definition,residual_capacity_bits,"
        "residual_capacity_status\n";
}

inline std::string SerializeThresholdLimbBits(
    const std::vector<uint32_t>& bits) {
    std::ostringstream out;
    for (size_t index = 0; index < bits.size(); ++index) {
        if (index != 0) out << ';';
        out << bits[index];
    }
    return out.str();
}

inline std::vector<uint32_t> ParseThresholdLimbBits(const std::string& value) {
    if (value.empty() || value == kThresholdSpecNotApplicable) return {};
    std::vector<uint32_t> result;
    size_t begin = 0;
    while (begin <= value.size()) {
        const size_t end = value.find(';', begin);
        const std::string token = value.substr(
            begin, end == std::string::npos ? std::string::npos : end - begin);
        if (token.empty() ||
            token.find_first_not_of("0123456789") != std::string::npos)
            return {};
        size_t consumed = 0;
        unsigned long parsed = 0;
        try {
            parsed = std::stoul(token, &consumed, 10);
        } catch (...) {
            return {};
        }
        if (consumed != token.size() || parsed == 0 || parsed > UINT32_MAX)
            return {};
        result.push_back(static_cast<uint32_t>(parsed));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    return result;
}

/** @brief Serialize one versioned threshold spec row. */
inline void WriteThresholdSpecRow(std::ostream& out,
                                  const ThresholdSpecRow& row) {
    ValidateThresholdSpecRow(row);
    const bool skipped = IsThresholdSpecSkipped(row);
    const auto u32 = [skipped](uint32_t value) {
        return skipped ? std::string(kThresholdSpecNotApplicable)
                       : std::to_string(value);
    };
    const auto u64 = [skipped](uint64_t value) {
        return skipped ? std::string(kThresholdSpecNotApplicable)
                       : std::to_string(value);
    };
    const auto number = [skipped](double value) {
        return skipped ? std::string(kThresholdSpecNotApplicable)
                       : detail::FormatDouble(value);
    };
    const auto text = [skipped](const std::string& value) {
        return skipped || value.empty()
                   ? std::string(kThresholdSpecNotApplicable)
                   : detail::CsvToken(value);
    };
    const std::string limbs =
        skipped ? kThresholdSpecNotApplicable
                : SerializeThresholdLimbBits(row.ordered_rns_limb_bits);
    const std::string moduli = [&] {
        if (skipped) return std::string(kThresholdSpecNotApplicable);
        std::ostringstream value;
        for (size_t index = 0; index < row.ordered_rns_moduli.size(); ++index) {
            if (index != 0) value << ';';
            value << row.ordered_rns_moduli[index];
        }
        return value.str();
    }();
    const std::string poly_time =
        row.poly_build_ms < 0.0
            ? std::string("-1")
            : [&row] {
                  std::ostringstream value;
                  value << std::fixed << std::setprecision(1)
                        << row.poly_build_ms;
                  return value.str();
              }();

    out << row.k << ',' << row.tau << ',' << row.degree << ','
        << row.ps_baby_s << ',' << row.ps_num_chunks << ',' << row.baby_depth
        << ',' << row.giant_mults << ',' << row.natural_mult_depth << ','
        << row.mult_depth << ',' << row.scaling_mod_size << ',' << row.ring_dim
        << ',' << row.plaintext_mod << ',' << std::setprecision(17)
        << row.log2_q << ',' << row.eval_noise_bits << ','
        << row.flood_noise_bits << ',' << row.ct_bytes << ',' << poly_time << ','
        << detail::CsvToken(row.status) << ',' << detail::CsvToken(row.note)
        << ',' << row.schema_version << ',' << u32(row.requested_ring_dim) << ','
        << u32(row.natural_ring_dim) << ',' << u32(row.provisioned_ring_dim)
        << ',' << u32(row.realized_ring_dim) << ',' << u32(row.natural_depth)
        << ',' << u32(row.provisioned_depth) << ',' << number(row.log_q_bits)
        << ',' << number(row.log2_q_over_t_bits) << ','
        << u64(row.plaintext_modulus) << ',' << u32(row.num_limbs) << ','
        << u32(row.realized_scaling_mod_size) << ',' << moduli << ',' << limbs
        << ',' << (skipped ? std::string(kThresholdSpecNotApplicable)
                           : std::to_string(row.OrderedRnsLimbBitsSum()))
        << ',' << text(row.openfhe_version) << ',' << text(row.flooding_assurance)
        << ',' << u32(row.transcript_stat_bits) << ',' << u64(row.max_queries)
        << ',' << u32(row.query_stat_bits) << ','
        << u32(row.coefficient_stat_bits) << ',' << u32(row.flood_margin_bits)
        << ',' << u32(row.required_capacity_bits) << ','
        << text(row.residual_capacity_definition) << ','
        << (skipped ? std::string(kThresholdSpecNotApplicable)
                    : detail::OptionalDouble(row.residual_capacity_bits))
        << ',' << text(row.residual_capacity_status) << '\n';
}

}  // namespace benchmark
}  // namespace piccard
