#pragma once

#include "benchmark_profile.h"
#include "benchmark_provenance.h"
#include "baseline_profile.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace piccard {

struct PiccardParams;

namespace benchmark {

/** @brief Typed suite provenance carried by every non-threshold row. */
struct BenchmarkProfileMetadata {
    std::string profile_id = "legacy";
    BenchmarkRunClass run_class = BenchmarkRunClass::Legacy;
    uint32_t target_security_bits = 0;
    bool comparison_eligible = false;
    BenchmarkMeasurementKind measurement_kind =
        BenchmarkMeasurementKind::Diagnostic;
};

/** @brief Bind a resolved immutable profile and a concrete row kind. */
BenchmarkProfileMetadata MakeBenchmarkProfileMetadata(
    const BenchmarkProfile& profile,
    BenchmarkMeasurementKind measurement_kind);

/**
 * @brief Estimator implementation represented by a benchmark row.
 */
enum class EstimatorModel {
    Sha256RandomRankingPocV1,
    NotApplicable,
};

/**
 * @brief Return the stable CSV spelling for an explicitly selected estimator.
 */
const char* EstimatorModelName(EstimatorModel model);

enum class SanitizerModel {
    PhaseSmudgingEnc0PocV1,
    NotApplicable,
};

struct SanitizerMetadata {
    std::optional<SanitizerModel> model;
    std::optional<uint32_t> transcript_stat_bits;
    std::optional<uint64_t> max_queries;
    std::optional<uint32_t> query_stat_bits;
    std::optional<uint32_t> coefficient_stat_bits;
    std::optional<uint32_t> flood_margin_bits;
    std::optional<uint32_t> eval_noise_bits;
    std::optional<uint32_t> flood_noise_bits;
};

SanitizerMetadata MakeSanitizerMetadata(const PiccardParams& params);
SanitizerMetadata NotApplicableSanitizerMetadata();

/**
 * @brief Result row shared by Piccard and onehot/sqrt benchmarks.
 */
struct BenchmarkResult {
    BenchmarkProfileMetadata profile;
    std::string label;

    uint32_t param_k = 0;
    uint32_t param_m = 0;
    size_t param_set_size = 0;
    uint32_t param_ring_dim = 0;

    double time_ms = 0.0;
    double phase_minhash_ms = 0.0;
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_multiply_ms = 0.0;
    double phase_rotate_sum_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double phase_bias_correction_ms = 0.0;

    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;

    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = 0.0;
    double jaccard_rel_error = 0.0;

    double accuracy_median = 0.0;
    double accuracy_p25 = 0.0;
    double accuracy_p75 = 0.0;
    double accuracy_p95 = 0.0;
    double accuracy_max = 0.0;

    std::string encoding;
    uint32_t param_mult_depth = 0;
    uint32_t param_num_cts = 0;
    size_t comm_bytes = 0;

    double phase_intra_digit_rotate_ms = 0.0;
    double phase_digit_and_ms = 0.0;
    double phase_cross_k_sum_ms = 0.0;

    size_t trials = 0;
    double time_ms_sd = -1.0;
    double time_ms_median = 0.0;
    double phase_minhash_ms_sd = -1.0;
    double phase_minhash_ms_median = 0.0;
    double phase_encode_ms_sd = -1.0;
    double phase_encode_ms_median = 0.0;
    double phase_encrypt_ms_sd = -1.0;
    double phase_encrypt_ms_median = 0.0;
    double phase_multiply_ms_sd = -1.0;
    double phase_multiply_ms_median = 0.0;
    double phase_rotate_sum_ms_sd = -1.0;
    double phase_rotate_sum_ms_median = 0.0;
    double phase_decrypt_ms_sd = -1.0;
    double phase_decrypt_ms_median = 0.0;
    double phase_bias_correction_ms_sd = -1.0;
    double phase_bias_correction_ms_median = 0.0;
    size_t rel_error_eligible_n = 0;

    std::string hash_randomness;
    uint64_t hash_seed = 0;
    uint64_t hash_root_seed = 0;
    size_t accuracy_trials = 0;

    double phase_flood_ms = 0.0;
    double phase_flood_ms_sd = -1.0;
    double phase_flood_ms_median = 0.0;
    uint32_t scaling_mod_size = 0;

    // Deliberately unset by default. Serializers reject missing provenance.
    std::optional<EstimatorModel> estimator_model;
    SanitizerMetadata sanitizer;
    BenchmarkProvenance provenance;
};

/**
 * @brief Result row for the dynamic benchmark.
 */
struct DynamicResult {
    BenchmarkProfileMetadata profile;
    std::string label;
    uint32_t k = 0;
    uint32_t m = 0;
    size_t set_size = 0;
    uint32_t ring_dim = 0;
    uint32_t depth = 0;

    double phase_init_ms = 0.0;
    double phase_insert_ms = 0.0;
    double phase_delete_ms = 0.0;
    double phase_signature_ms = 0.0;
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_compute_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;

    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = 0.0;
    double jaccard_rel_error = 0.0;

    double ops_insert_per_sec = 0.0;
    double ops_delete_per_sec = 0.0;

    size_t trials = 0;
    double total_ms_sd = -1.0;
    double total_ms_median = 0.0;
    double phase_init_ms_sd = -1.0;
    double phase_init_ms_median = 0.0;
    double phase_insert_ms_sd = -1.0;
    double phase_insert_ms_median = 0.0;
    double phase_delete_ms_sd = -1.0;
    double phase_delete_ms_median = 0.0;
    double phase_signature_ms_sd = -1.0;
    double phase_signature_ms_median = 0.0;
    double phase_encode_ms_sd = -1.0;
    double phase_encode_ms_median = 0.0;
    double phase_encrypt_ms_sd = -1.0;
    double phase_encrypt_ms_median = 0.0;
    double phase_compute_ms_sd = -1.0;
    double phase_compute_ms_median = 0.0;
    double phase_decrypt_ms_sd = -1.0;
    double phase_decrypt_ms_median = 0.0;
    size_t rel_error_eligible_n = 0;

    std::string hash_randomness;
    uint64_t hash_seed = 0;
    uint64_t hash_root_seed = 0;
    size_t accuracy_trials = 0;

    double phase_flood_ms = 0.0;
    double phase_flood_ms_sd = -1.0;
    double phase_flood_ms_median = 0.0;
    uint32_t scaling_mod_size = 0;

    std::optional<EstimatorModel> estimator_model;
    SanitizerMetadata sanitizer;
    BenchmarkProvenance provenance;
};

/**
 * @brief Result row for the protocol comparison benchmark.
 */
struct ComparisonResult {
    BenchmarkProfileMetadata profile;
    std::string scenario;
    std::string method;
    std::optional<BaselineCapability> capability;

    uint32_t universe_size = 0;
    size_t set_size = 0;
    std::optional<uint32_t> k;
    std::optional<uint32_t> m;
    std::optional<uint32_t> ring_dim;
    uint32_t num_cts = 0;
    uint32_t mult_depth = 0;

    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_compute_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;
    size_t comm_bytes = 0;

    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = 0.0;
    double jaccard_rel_error = 0.0;

    // Requested workload and the exact rational workload actually realized.
    double target_jaccard = 0.0;
    size_t realized_intersection = 0;
    size_t realized_union = 0;
    double realized_jaccard = 0.0;

    size_t trials = 0;
    double total_ms_sd = -1.0;
    double total_ms_median = 0.0;
    double phase_encode_ms_sd = -1.0;
    double phase_encode_ms_median = 0.0;
    double phase_encrypt_ms_sd = -1.0;
    double phase_encrypt_ms_median = 0.0;
    double phase_compute_ms_sd = -1.0;
    double phase_compute_ms_median = 0.0;
    double phase_decrypt_ms_sd = -1.0;
    double phase_decrypt_ms_median = 0.0;
    size_t rel_error_eligible_n = 0;

    std::string hash_randomness;
    uint64_t hash_seed = 0;
    uint64_t hash_root_seed = 0;
    size_t accuracy_trials = 0;

    double phase_flood_ms = 0.0;
    double phase_flood_ms_sd = -1.0;
    double phase_flood_ms_median = 0.0;
    uint32_t scaling_mod_size = 0;

    std::string measurement_status = "measured";
    std::string extrapolation_alpha;
    std::string extrapolation_beta;
    std::string extrapolation_residual;
    std::string extrapolation_source;

    std::optional<EstimatorModel> estimator_model;
    SanitizerMetadata sanitizer;
    BenchmarkProvenance provenance;
};

/**
 * @brief Result row for the onehot/sqrt crossover benchmark.
 */
struct CrossoverResult {
    BenchmarkProfileMetadata profile;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t onehot_feature_dim = 0;
    uint32_t sqrt_feature_dim = 0;
    uint32_t onehot_ring_dim = 0;
    uint32_t sqrt_ring_dim = 0;
    double onehot_total_ms = 0.0;
    double sqrt_total_ms = 0.0;
    bool sqrt_faster = false;
    double speedup_ratio = 0.0;
    SanitizerMetadata sanitizer;
    std::optional<uint32_t> onehot_coefficient_stat_bits;
    std::optional<uint32_t> onehot_eval_noise_bits;
    std::optional<uint32_t> onehot_flood_noise_bits;
    std::optional<uint32_t> sqrt_coefficient_stat_bits;
    std::optional<uint32_t> sqrt_eval_noise_bits;
    std::optional<uint32_t> sqrt_flood_noise_bits;
    std::optional<EstimatorModel> estimator_model;
    BenchmarkProvenance onehot_provenance;
    BenchmarkProvenance sqrt_provenance;
};

/**
 * @brief Aggregated output row for the legacy sqrt comparison benchmark.
 */
struct SqrtComparisonResult {
    BenchmarkProfileMetadata profile;
    std::string encoding;
    std::string security;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t ring_dim = 0;
    uint32_t mult_depth = 0;
    double encode_ms = 0.0;
    double encrypt_ms = 0.0;
    double evaluate_ms = 0.0;
    double decrypt_ms = 0.0;
    double total_ms = 0.0;
    double total_ms_sd = 0.0;
    double jaccard_error = 0.0;
    double jaccard_error_sd = 0.0;
    bool has_relative_error = false;
    double jaccard_rel_error = 0.0;
    double jaccard_rel_error_sd = 0.0;
    SanitizerMetadata sanitizer;
    std::optional<EstimatorModel> estimator_model;
    BenchmarkProvenance provenance;
};

std::string SerializeBenchmarkHeader();
std::string SerializeBenchmarkRow(const BenchmarkResult& row,
                                  const BenchmarkProvenance& provenance);

std::string SerializeDynamicHeader();
std::string SerializeDynamicRow(const DynamicResult& row,
                                const BenchmarkProvenance& provenance);

std::string SerializeComparisonHeader();
std::string SerializeComparisonRow(const ComparisonResult& row,
                                   uint32_t omp_threads,
                                   const BenchmarkProvenance& provenance);

std::string SerializeCrossoverHeader();
std::string SerializeCrossoverRow(
    const CrossoverResult& row,
    const BenchmarkProvenance& onehot_provenance,
    const BenchmarkProvenance& sqrt_provenance);

std::string SerializeSqrtComparisonHeader();
std::string SerializeSqrtComparisonRow(
    const SqrtComparisonResult& row,
    const BenchmarkProvenance& provenance);

}  // namespace benchmark
}  // namespace piccard
