#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace piccard::bench {

// The exact 46-column "Work-4 prefix" shared by every bench_real_datasets
// row, accuracy and timing alike, per adjudication A1
// (docs/superpowers/plans/2026-07-29-05-real-dataset-pipeline.md §Phase 5;
// docs/superpowers/specs/2026-08-05-work5-phase5-metrics-bench.md §5.2).
// Field order matches RealDatasetPrefixHeader() and
// SerializeRealDatasetPrefix() exactly. Per adjudication A2, every column
// with a typed Work-4 source (BenchmarkMeasurementKindName,
// ComparisonScopeName, PrimitiveName, ProtocolModelName,
// OutputSemanticsName, AssuranceScopeName, SecurityBasisName, CostScopeName,
// PrecomputationModeName, BenchmarkRunClassName, EstimatorModelName) is
// populated through that source by MakePlaintextAccuracyPrefix /
// MakeFheTimingPrefix below, never via a re-typed string literal.
struct RealDatasetPrefixValues {
    // --- Profile / run identity -------------------------------------------
    std::string profile_id;
    std::string run_class;
    std::optional<uint32_t> target_security_bits;
    std::string cryptographic_profile;
    std::optional<uint32_t> nominal_security_bits;
    bool security_match = false;
    bool comparison_eligible = false;
    std::string comparison_scope;
    std::string primitive;
    std::string protocol_model;
    std::string output_semantics;
    std::string assurance_scope;
    std::string security_basis;
    std::string cost_scope;
    std::string precomputation_mode;
    bool secure_division_included = false;
    std::string measurement_kind;

    // --- Workload / execution identity --------------------------------------
    std::string workload_id;
    std::string workload_manifest_sha256;
    std::string execution_trace_sha256;
    uint64_t root_seed = 0;
    uint32_t omp_threads = 0;

    // --- Estimator / sanitizer provenance ------------------------------------
    std::string estimator_model;
    std::string sanitizer_model;
    std::string sanitizer_assurance;
    std::optional<uint32_t> transcript_stat_bits;
    std::optional<uint64_t> max_queries;
    std::optional<uint32_t> query_stat_bits;
    std::optional<uint32_t> coefficient_stat_bits;
    std::optional<uint32_t> flood_margin_bits;
    std::optional<uint32_t> eval_noise_bits;
    std::optional<uint32_t> flood_noise_bits;

    // --- Live FHE build provenance (empty unless a live BFV context ran) ----
    std::optional<uint32_t> actual_ring_dim;
    std::optional<double> log_q_bits;
    std::optional<uint64_t> plaintext_modulus;
    std::optional<uint32_t> num_limbs;
    std::string openfhe_version;

    // --- Realized workload target ---------------------------------------------
    std::string target_semantics;
    std::optional<double> target_jaccard;
    std::optional<uint64_t> realized_intersection;
    std::optional<uint64_t> realized_union;
    std::optional<double> realized_jaccard;

    // --- Trial counts and run-time flags ---------------------------------------
    std::optional<uint32_t> timing_trials;
    std::optional<uint32_t> accuracy_trials;
    bool omp_dynamic = false;
    std::string measurement_status;
};

// Exact 46-column Work-4 prefix header (adjudication A1). No leading/
// trailing comma or newline; callers append a comma-joined mode-specific
// suffix (see RealAccuracyHeader / RealTimingHeader).
std::string RealDatasetPrefixHeader();

// Serializes `values` as 46 comma-joined prefix cells, in exactly the
// RealDatasetPrefixHeader() column order. No leading/trailing comma or
// newline. Throws std::invalid_argument if a required string field (any
// field without a fixed default of empty/false/0) is empty, so a row built
// from an incomplete RealDatasetPrefixValues fails closed instead of
// silently emitting a blank cell.
std::string SerializeRealDatasetPrefix(const RealDatasetPrefixValues& values);

// Full accuracy-row header: RealDatasetPrefixHeader() plus the accuracy-mode
// columns, newline-terminated.
std::string RealAccuracyHeader();

// Full timing-row header: RealDatasetPrefixHeader() plus the timing-mode
// columns, newline-terminated.
std::string RealTimingHeader();

// Builds the fixed, non-row-varying prefix for a plaintext-estimator
// accuracy row (normative §Phase 5 "Field-complete values", plaintext
// accuracy). `target_jaccard` and the three `realized_*` fields are left
// unset: `target_jaccard` is always empty for Work 5 (real, not synthetic,
// pairs), and the accuracy driver (Sub-phase 5.3) fills
// `realized_intersection`/`realized_union`/`realized_jaccard` per pair
// before serializing.
RealDatasetPrefixValues MakePlaintextAccuracyPrefix(
    const std::string& variant,
    const std::string& accuracy_workload_sha256,
    uint32_t accuracy_trials,
    uint64_t root_seed);

// Builds the Work-4-profile-resolved prefix for an FHE timing row, via
// ResolveBenchmarkProfile(profile_id) and ResolveBaselineCapability for the
// Piccard BFV one-hot MinHash protocol (normative §Phase 5 "Field-complete
// values", FHE timing). Live FHE/sanitizer provenance
// (`sanitizer_model`, `sanitizer_assurance`, the sanitizer numeric fields,
// `actual_ring_dim`, `log_q_bits`, `plaintext_modulus`, `num_limbs`,
// `openfhe_version`) and the per-pair `realized_*` fields are left unset;
// the timing driver (Sub-phase 5.4) fills them from the live BFV context
// after this call returns, before serializing.
RealDatasetPrefixValues MakeFheTimingPrefix(
    const std::string& variant,
    const std::string& profile_id,
    const std::string& timing_workload_sha256,
    uint64_t root_seed,
    uint32_t timing_trials,
    uint32_t omp_threads);

}  // namespace piccard::bench
