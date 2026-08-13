#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace piccard {

class BFVContext;

namespace benchmark {

// Versioned provenance is intentionally additive.  The six legacy CSV
// columns consumed by Work 5 continue to use BenchmarkProvenance's original
// fields and serializers; these constants describe the successor sidecar/API.
inline constexpr const char* kBenchmarkProvenanceSchemaVersion =
    "piccard-benchmark-provenance-v2";
inline constexpr const char* kBenchmarkProvenanceSchemaVersionV2 =
    kBenchmarkProvenanceSchemaVersion;

inline constexpr const char* kFloodingAssuranceNotApplicable =
    "not-applicable";
inline constexpr const char*
    kFloodingAssuranceEmpiricalPhaseStatisticalCiphertextComputational =
        "empirical-phase-statistical+ciphertext-computational";
inline constexpr const char* kFloodingAssuranceLegacyCoefficientLevel =
    "legacy-coefficient-level";

inline constexpr const char* kResidualCapacityDefinition =
    "log2(q/t)-required_flood_budget_bits";
inline constexpr const char* kResidualCapacityStatusNotExposedByOpenFhe =
    "not-exposed-by-openfhe";
inline constexpr const char* kResidualCapacityStatusNotExposedByOpenFHE =
    kResidualCapacityStatusNotExposedByOpenFhe;
inline constexpr const char* kResidualCapacityStatusAvailable = "available";
inline constexpr const char* kResidualCapacityStatusNotApplicable =
    "not-applicable";

inline constexpr const char* kLegacyEncodingSupersededNote =
    "legacy-encoding-schema-superseded-by-piccard-benchmark-provenance-v2";

/** @brief Stable flooding-assurance categories in versioned provenance. */
enum class FloodingAssurance {
    NotApplicable,
    EmpiricalPhaseStatisticalCiphertextComputational,
    LegacyCoefficientLevel,
};

/** @brief Return the frozen textual flooding-assurance category. */
const char* FloodingAssuranceName(FloodingAssurance assurance);

/** @brief Return whether a textual assurance category is frozen/recognized. */
bool IsValidFloodingAssurance(const std::string& assurance);

/** @brief Live cryptographic and build provenance for one benchmark row. */
struct BenchmarkProvenance {
    // ── Work 5 fields (do not remove or reorder; old CSV bytes depend on them)
    std::optional<uint32_t> actual_ring_dim;
    std::optional<double> log_q_bits;
    std::optional<uint64_t> plaintext_modulus;
    std::optional<uint32_t> num_limbs;
    std::string openfhe_version;

    bool sanitizer_applicable = false;
    std::optional<uint32_t> transcript_stat_bits;
    std::optional<uint64_t> max_queries;
    std::optional<uint32_t> query_stat_bits;
    std::optional<uint32_t> coefficient_stat_bits;
    std::optional<uint32_t> flood_margin_bits;
    std::optional<uint32_t> eval_noise_bits;
    std::optional<uint32_t> flood_noise_bits;
    std::optional<uint32_t> scaling_mod_size;

    // ── Versioned provenance-v2 fields ────────────────────────────────
    // Empty schema_version means a legacy in-memory value.  The old
    // serializers remain byte-for-byte unchanged; constructors below emit
    // the v2 value and the new sidecar serializer requires it.
    std::string schema_version;

    // Encoding-only rows intentionally carry no FHE context.  Validation is
    // fail-closed if any old or v2 FHE field is populated while this is true.
    bool encoding_only = false;

    // Requested (profile), natural (circuit), provisioned (calibration), and
    // realized (OpenFHE) dimensions are distinct observations.  The legacy
    // actual_ring_dim is retained as an alias for realized_ring_dim.
    std::optional<uint32_t> requested_ring_dim;
    std::optional<uint32_t> natural_ring_dim;
    std::optional<uint32_t> provisioned_ring_dim;
    std::optional<uint32_t> realized_ring_dim;

    // Spelling aliases used by calibration/evidence consumers.  Constructors
    // populate both aliases; validation rejects disagreement when both are
    // present.
    std::optional<uint32_t> calibrated_ring_dim;
    std::optional<uint32_t> ring_dim_calibrated;
    std::optional<uint32_t> natural_mult_depth;
    std::optional<uint32_t> mult_depth;
    std::optional<uint32_t> natural_depth;
    std::optional<uint32_t> provisioned_depth;

    // Total modulus and q/t are both retained.  q/t is not reconstructed
    // from a rounded limb count: it is computed from the realized context.
    std::optional<double> log2_q_over_t_bits;
    std::optional<double> log_q_over_t_bits;
    std::optional<double> log2_q_over_t;

    // Ordered tower information comes directly from OpenFHE's element
    // parameters.  The integer vector is exact (GetMSB per tower); decimal
    // moduli are retained so an independent verifier can round-trip order.
    std::vector<uint32_t> ordered_rns_limb_bits;
    std::vector<uint32_t> ordered_rns_limb_bit_sizes;
    std::vector<std::string> ordered_rns_moduli;

    // Realized context scaling modulus is distinct from the legacy sanitizer
    // field above (which is populated only when sanitizer metadata applies).
    std::optional<uint32_t> realized_scaling_mod_size;

    // Explicit taxonomy rather than an inference from optional numeric
    // fields.  Threshold is intentionally legacy coefficient-level.
    std::string flooding_assurance;

    // OpenFHE does not expose a stable remaining-capacity API.  Report the
    // definition and status, but never fabricate a residual number.
    std::string residual_capacity_definition;
    std::string residual_capacity_status;
    std::optional<double> residual_capacity_bits;

    // Encoding-only successor rows identify why the old encoding spelling is
    // not being reused as a full-FHE record.
    std::string legacy_encoding_note;
};

/** @brief Build complete Piccard provenance from its realized BFV context. */
BenchmarkProvenance MakePiccardBenchmarkProvenance(
    const BFVContext& context);

/** @brief Build FHE-IND provenance: live BFV fields, no Piccard sanitizer. */
BenchmarkProvenance MakeFheIndBenchmarkProvenance(
    const BFVContext& context);

/** @brief Build AHE provenance with exact not-applicable representation. */
BenchmarkProvenance MakeAheBenchmarkProvenance();

/** @brief Build a v2 not-applicable provenance record for local encoding. */
BenchmarkProvenance MakeEncodingOnlyBenchmarkProvenance();

/** @brief Validate that provenance is exactly live-FHE or not-applicable. */
bool ValidateBenchmarkProvenance(const BenchmarkProvenance& provenance);

/** @brief Sum exact ordered RNS limb bit sizes for independent KATs. */
uint64_t SumOrderedRnsLimbBits(
    const std::vector<uint32_t>& ordered_rns_limb_bits);

/** @brief Serialize complete provenance-v2 as a canonical LF-terminated TSV. */
std::string SerializeBenchmarkProvenanceV2(
    const BenchmarkProvenance& provenance);

/** @brief Parse and validate canonical provenance-v2 TSV. */
BenchmarkProvenance ParseBenchmarkProvenanceV2(
    const std::string& serialized);

/** @brief Stable sidecar aliases retained for callers using generic names. */
inline std::string SerializeBenchmarkProvenance(
    const BenchmarkProvenance& provenance) {
    return SerializeBenchmarkProvenanceV2(provenance);
}

inline BenchmarkProvenance ParseBenchmarkProvenance(
    const std::string& serialized) {
    return ParseBenchmarkProvenanceV2(serialized);
}

/** @brief Print configured source/build identity and return true on request. */
bool PrintBuildProvenanceIfRequested(int argc, char** argv);

}  // namespace benchmark
}  // namespace piccard
