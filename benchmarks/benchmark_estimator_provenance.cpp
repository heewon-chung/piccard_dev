#include "benchmark_estimator_provenance.h"

#include "util/params.h"

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace piccard {
namespace benchmark {
namespace {

const char* RequireEstimatorModel(
    const std::optional<EstimatorModel>& estimator_model) {
    if (!estimator_model.has_value()) {
        throw std::logic_error(
            "benchmark row is missing explicit estimator_model provenance");
    }
    return EstimatorModelName(*estimator_model);
}

const char* SanitizerModelName(SanitizerModel model) {
    switch (model) {
        case SanitizerModel::PhaseSmudgingEnc0PocV1:
            return "phase-smudging-enc0-poc-v1";
        case SanitizerModel::NotApplicable:
            return "not-applicable";
    }
    throw std::logic_error("unknown sanitizer model");
}

const char* SanitizerAssuranceName(SanitizerModel model) {
    switch (model) {
        case SanitizerModel::PhaseSmudgingEnc0PocV1:
            return
                "empirical-phase-statistical+ciphertext-computational";
        case SanitizerModel::NotApplicable:
            return "not-applicable";
    }
    throw std::logic_error("unknown sanitizer model");
}

bool RequireSanitizerMetadata(const SanitizerMetadata& metadata) {
    if (!metadata.model.has_value()) {
        throw std::logic_error(
            "benchmark row is missing explicit sanitizer metadata");
    }
    const bool applicable =
        *metadata.model == SanitizerModel::PhaseSmudgingEnc0PocV1;
    const bool all_numeric =
        metadata.transcript_stat_bits.has_value() &&
        metadata.max_queries.has_value() &&
        metadata.query_stat_bits.has_value() &&
        metadata.coefficient_stat_bits.has_value() &&
        metadata.flood_margin_bits.has_value() &&
        metadata.eval_noise_bits.has_value() &&
        metadata.flood_noise_bits.has_value();
    const bool any_numeric =
        metadata.transcript_stat_bits.has_value() ||
        metadata.max_queries.has_value() ||
        metadata.query_stat_bits.has_value() ||
        metadata.coefficient_stat_bits.has_value() ||
        metadata.flood_margin_bits.has_value() ||
        metadata.eval_noise_bits.has_value() ||
        metadata.flood_noise_bits.has_value();
    if (applicable && !all_numeric) {
        throw std::logic_error(
            "applicable sanitizer metadata is missing numeric fields");
    }
    if (!applicable && any_numeric) {
        throw std::logic_error(
            "not-applicable sanitizer metadata has numeric fields");
    }
    return applicable;
}

template <typename T>
void WriteOptional(std::ostringstream& out, const std::optional<T>& value) {
    if (value.has_value()) out << *value;
}

void WriteStandardSanitizerFields(std::ostringstream& out,
                                  const SanitizerMetadata& metadata,
                                  uint32_t scaling_mod_size) {
    const bool applicable = RequireSanitizerMetadata(metadata);
    WriteOptional(out, metadata.transcript_stat_bits);
    out << ",";
    WriteOptional(out, metadata.max_queries);
    out << ",";
    WriteOptional(out, metadata.query_stat_bits);
    out << ",";
    WriteOptional(out, metadata.coefficient_stat_bits);
    out << ",";
    WriteOptional(out, metadata.flood_margin_bits);
    out << ",";
    WriteOptional(out, metadata.eval_noise_bits);
    out << ",";
    WriteOptional(out, metadata.flood_noise_bits);
    out << ",";
    if (applicable) out << scaling_mod_size;
    out << ","
        << SanitizerModelName(*metadata.model) << ","
        << SanitizerAssuranceName(*metadata.model);
}

void WriteBenchmarkProfileFields(std::ostringstream& out,
                                 const BenchmarkProfileMetadata& profile) {
    if (profile.profile_id.empty()) {
        throw std::logic_error("benchmark row is missing profile_id");
    }
    out << "," << profile.profile_id
        << "," << BenchmarkRunClassName(profile.run_class)
        << "," << profile.target_security_bits
        << "," << (profile.comparison_eligible ? "true" : "false")
        << "," << BenchmarkMeasurementKindName(profile.measurement_kind);
}

const char* SecurityClassOf(const std::string& method) {
    if (method == "piccard" || method == "piccard_sqrt") {
        return "CPA/no-leakage";
    }
    if (method == "baseline") return "KPA/leakage";
    if (method.rfind("bcg12", 0) == 0 ||
        method.rfind("sj16", 0) == 0) {
        return "AHE/no-leakage";
    }
    return "unknown";
}

const char* ProtocolModelOf(const std::string& method) {
    if (method.rfind("bcg12", 0) == 0 ||
        method.rfind("sj16", 0) == 0) {
        return "2-party";
    }
    return "3-party-outsourced";
}

}  // namespace

const char* EstimatorModelName(EstimatorModel model) {
    switch (model) {
        case EstimatorModel::Sha256RandomRankingPocV1:
            return "sha256-random-ranking-poc-v1";
        case EstimatorModel::NotApplicable:
            return "not-applicable";
    }
    throw std::logic_error("unknown estimator model");
}

BenchmarkProfileMetadata MakeBenchmarkProfileMetadata(
    const BenchmarkProfile& profile,
    BenchmarkMeasurementKind measurement_kind) {
    BenchmarkProfileMetadata metadata;
    metadata.profile_id = profile.id;
    metadata.run_class = profile.run_class;
    metadata.target_security_bits = profile.target_security_bits;
    metadata.comparison_eligible = profile.comparison_eligible;
    metadata.measurement_kind = measurement_kind;
    return metadata;
}

SanitizerMetadata MakeSanitizerMetadata(const PiccardParams& params) {
    if (!params.FloodingSized()) {
        throw std::logic_error(
            "cannot serialize sanitizer metadata before parameter selection");
    }
    SanitizerMetadata metadata;
    metadata.model = SanitizerModel::PhaseSmudgingEnc0PocV1;
    metadata.transcript_stat_bits = params.transcript_stat_bits;
    metadata.max_queries = params.max_queries;
    metadata.query_stat_bits = params.QueryStatBits();
    metadata.coefficient_stat_bits = params.CoefficientStatBits();
    metadata.flood_margin_bits = params.flood_margin_bits;
    metadata.eval_noise_bits = params.eval_noise_bits;
    metadata.flood_noise_bits = params.FloodNoiseBits();
    return metadata;
}

SanitizerMetadata NotApplicableSanitizerMetadata() {
    SanitizerMetadata metadata;
    metadata.model = SanitizerModel::NotApplicable;
    return metadata;
}

std::string SerializeBenchmarkHeader() {
    return
        "label,k,m,set_size,ring_dim,"
        "time_ms,phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,"
        "phase_multiply_ms,phase_rotate_sum_ms,phase_decrypt_ms,"
        "phase_bias_correction_ms,"
        "memory_bytes,ct_size_bytes,"
        "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
        "accuracy_median,accuracy_p25,accuracy_p75,accuracy_p95,accuracy_max,"
        "encoding,mult_depth,num_cts,comm_bytes,"
        "phase_intra_digit_rotate_ms,phase_digit_and_ms,phase_cross_k_sum_ms,"
        "trials,"
        "time_ms_sd,time_ms_median,"
        "phase_minhash_ms_sd,phase_minhash_ms_median,"
        "phase_encode_ms_sd,phase_encode_ms_median,"
        "phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_multiply_ms_sd,phase_multiply_ms_median,"
        "phase_rotate_sum_ms_sd,phase_rotate_sum_ms_median,"
        "phase_decrypt_ms_sd,phase_decrypt_ms_median,"
        "phase_bias_correction_ms_sd,phase_bias_correction_ms_median,"
        "rel_error_eligible_n,"
        "hash_randomness,hash_seed,hash_root_seed,accuracy_trials,"
        "phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
        "transcript_stat_bits,max_queries,query_stat_bits,"
        "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,"
        "flood_noise_bits,scaling_mod_size,sanitizer_model,"
        "sanitizer_assurance,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind\n";
}

std::string SerializeBenchmarkRow(const BenchmarkResult& r) {
    const char* estimator_model = RequireEstimatorModel(r.estimator_model);
    std::ostringstream out;
    out << r.label << ","
        << r.param_k << ","
        << r.param_m << ","
        << r.param_set_size << ","
        << r.param_ring_dim << ","
        << std::fixed << std::setprecision(3)
        << r.time_ms << ","
        << r.phase_minhash_ms << ","
        << r.phase_encode_ms << ","
        << r.phase_encrypt_ms << ","
        << r.phase_multiply_ms << ","
        << r.phase_rotate_sum_ms << ","
        << r.phase_decrypt_ms << ","
        << r.phase_bias_correction_ms << ","
        << r.memory_bytes << ","
        << r.ct_size_bytes << ","
        << std::fixed << std::setprecision(6)
        << r.jaccard_computed << ","
        << r.jaccard_expected << ","
        << r.jaccard_error << ","
        << r.jaccard_rel_error << ","
        << r.accuracy_median << ","
        << r.accuracy_p25 << ","
        << r.accuracy_p75 << ","
        << r.accuracy_p95 << ","
        << r.accuracy_max << ","
        << r.encoding << ","
        << r.param_mult_depth << ","
        << r.param_num_cts << ","
        << r.comm_bytes << ","
        << std::fixed << std::setprecision(3)
        << r.phase_intra_digit_rotate_ms << ","
        << r.phase_digit_and_ms << ","
        << r.phase_cross_k_sum_ms << ","
        << r.trials << ","
        << r.time_ms_sd << ","
        << r.time_ms_median << ","
        << r.phase_minhash_ms_sd << ","
        << r.phase_minhash_ms_median << ","
        << r.phase_encode_ms_sd << ","
        << r.phase_encode_ms_median << ","
        << r.phase_encrypt_ms_sd << ","
        << r.phase_encrypt_ms_median << ","
        << r.phase_multiply_ms_sd << ","
        << r.phase_multiply_ms_median << ","
        << r.phase_rotate_sum_ms_sd << ","
        << r.phase_rotate_sum_ms_median << ","
        << r.phase_decrypt_ms_sd << ","
        << r.phase_decrypt_ms_median << ","
        << r.phase_bias_correction_ms_sd << ","
        << r.phase_bias_correction_ms_median << ","
        << r.rel_error_eligible_n << ","
        << r.hash_randomness << ","
        << r.hash_seed << ","
        << r.hash_root_seed << ","
        << r.accuracy_trials << ","
        << std::fixed << std::setprecision(3)
        << r.phase_flood_ms << ","
        << r.phase_flood_ms_sd << ","
        << r.phase_flood_ms_median << ",";
    WriteStandardSanitizerFields(out, r.sanitizer, r.scaling_mod_size);
    out << "," << estimator_model;
    WriteBenchmarkProfileFields(out, r.profile);
    out << "\n";
    return out.str();
}

std::string SerializeDynamicHeader() {
    return
        "label,k,m,set_size,ring_dim,depth,"
        "phase_init_ms,phase_insert_ms,phase_delete_ms,"
        "phase_signature_ms,phase_encode_ms,phase_encrypt_ms,"
        "phase_compute_ms,phase_decrypt_ms,total_ms,"
        "memory_bytes,ct_size_bytes,"
        "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
        "ops_insert_per_sec,ops_delete_per_sec,"
        "trials,"
        "total_ms_sd,total_ms_median,"
        "phase_init_ms_sd,phase_init_ms_median,"
        "phase_insert_ms_sd,phase_insert_ms_median,"
        "phase_delete_ms_sd,phase_delete_ms_median,"
        "phase_signature_ms_sd,phase_signature_ms_median,"
        "phase_encode_ms_sd,phase_encode_ms_median,"
        "phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_compute_ms_sd,phase_compute_ms_median,"
        "phase_decrypt_ms_sd,phase_decrypt_ms_median,"
        "rel_error_eligible_n,"
        "hash_randomness,hash_seed,hash_root_seed,accuracy_trials,"
        "phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
        "transcript_stat_bits,max_queries,query_stat_bits,"
        "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,"
        "flood_noise_bits,scaling_mod_size,sanitizer_model,"
        "sanitizer_assurance,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind\n";
}

std::string SerializeDynamicRow(const DynamicResult& r) {
    const char* estimator_model = RequireEstimatorModel(r.estimator_model);
    std::ostringstream out;
    out << r.label << ","
        << r.k << "," << r.m << "," << r.set_size << "," << r.ring_dim
        << "," << r.depth << ","
        << std::fixed << std::setprecision(3)
        << r.phase_init_ms << "," << r.phase_insert_ms << ","
        << r.phase_delete_ms << "," << r.phase_signature_ms << ","
        << r.phase_encode_ms << "," << r.phase_encrypt_ms << ","
        << r.phase_compute_ms << "," << r.phase_decrypt_ms << ","
        << r.total_ms << ","
        << r.memory_bytes << "," << r.ct_size_bytes << ","
        << std::fixed << std::setprecision(6)
        << r.jaccard_computed << "," << r.jaccard_expected << ","
        << r.jaccard_error << "," << r.jaccard_rel_error << ","
        << std::fixed << std::setprecision(1)
        << r.ops_insert_per_sec << "," << r.ops_delete_per_sec << ","
        << r.trials << ","
        << std::fixed << std::setprecision(3)
        << r.total_ms_sd << "," << r.total_ms_median << ","
        << r.phase_init_ms_sd << "," << r.phase_init_ms_median << ","
        << r.phase_insert_ms_sd << "," << r.phase_insert_ms_median << ","
        << r.phase_delete_ms_sd << "," << r.phase_delete_ms_median << ","
        << r.phase_signature_ms_sd << "," << r.phase_signature_ms_median << ","
        << r.phase_encode_ms_sd << "," << r.phase_encode_ms_median << ","
        << r.phase_encrypt_ms_sd << "," << r.phase_encrypt_ms_median << ","
        << r.phase_compute_ms_sd << "," << r.phase_compute_ms_median << ","
        << r.phase_decrypt_ms_sd << "," << r.phase_decrypt_ms_median << ","
        << r.rel_error_eligible_n << ","
        << r.hash_randomness << ","
        << r.hash_seed << ","
        << r.hash_root_seed << ","
        << r.accuracy_trials << ","
        << std::fixed << std::setprecision(3)
        << r.phase_flood_ms << ","
        << r.phase_flood_ms_sd << ","
        << r.phase_flood_ms_median << ",";
    WriteStandardSanitizerFields(out, r.sanitizer, r.scaling_mod_size);
    out << "," << estimator_model;
    WriteBenchmarkProfileFields(out, r.profile);
    out << "\n";
    return out.str();
}

std::string SerializeComparisonHeader() {
    return
        "scenario,method,security_class,"
        "universe_size,set_size,k,m,ring_dim,num_cts,mult_depth,"
        "phase_encode_ms,phase_encrypt_ms,phase_compute_ms,"
        "phase_decrypt_ms,total_ms,"
        "memory_bytes,ct_size_bytes,comm_bytes,"
        "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
        "trials,"
        "total_ms_sd,total_ms_median,"
        "phase_encode_ms_sd,phase_encode_ms_median,"
        "phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_compute_ms_sd,phase_compute_ms_median,"
        "phase_decrypt_ms_sd,phase_decrypt_ms_median,"
        "rel_error_eligible_n,"
        "model,"
        "hash_randomness,hash_seed,hash_root_seed,accuracy_trials,"
        "phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
        "transcript_stat_bits,max_queries,query_stat_bits,"
        "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,"
        "flood_noise_bits,scaling_mod_size,sanitizer_model,"
        "sanitizer_assurance,"
        "measurement_status,extrapolation_alpha,extrapolation_beta,"
        "extrapolation_residual,extrapolation_source,"
        "omp_threads,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind\n";
}

std::string SerializeComparisonRow(const ComparisonResult& r,
                                   uint32_t omp_threads) {
    const char* estimator_model = RequireEstimatorModel(r.estimator_model);
    std::ostringstream out;
    out << r.scenario << ","
        << r.method << ","
        << SecurityClassOf(r.method) << ","
        << r.universe_size << ","
        << r.set_size << ","
        << r.k << ","
        << r.m << ","
        << r.ring_dim << ","
        << r.num_cts << ","
        << r.mult_depth << ","
        << std::fixed << std::setprecision(3)
        << r.phase_encode_ms << ","
        << r.phase_encrypt_ms << ","
        << r.phase_compute_ms << ","
        << r.phase_decrypt_ms << ","
        << r.total_ms << ","
        << r.memory_bytes << ","
        << r.ct_size_bytes << ","
        << r.comm_bytes << ","
        << std::fixed << std::setprecision(6)
        << r.jaccard_computed << ","
        << r.jaccard_expected << ","
        << r.jaccard_error << ","
        << r.jaccard_rel_error << ","
        << r.trials << ","
        << std::fixed << std::setprecision(3)
        << r.total_ms_sd << ","
        << r.total_ms_median << ","
        << r.phase_encode_ms_sd << ","
        << r.phase_encode_ms_median << ","
        << r.phase_encrypt_ms_sd << ","
        << r.phase_encrypt_ms_median << ","
        << r.phase_compute_ms_sd << ","
        << r.phase_compute_ms_median << ","
        << r.phase_decrypt_ms_sd << ","
        << r.phase_decrypt_ms_median << ","
        << r.rel_error_eligible_n << ","
        << ProtocolModelOf(r.method) << ","
        << r.hash_randomness << ","
        << r.hash_seed << ","
        << r.hash_root_seed << ","
        << r.accuracy_trials << ","
        << std::fixed << std::setprecision(3)
        << r.phase_flood_ms << ","
        << r.phase_flood_ms_sd << ","
        << r.phase_flood_ms_median << ",";
    WriteStandardSanitizerFields(out, r.sanitizer, r.scaling_mod_size);
    out << ","
        << r.measurement_status << ","
        << r.extrapolation_alpha << ","
        << r.extrapolation_beta << ","
        << r.extrapolation_residual << ","
        << r.extrapolation_source << ","
        << omp_threads << ","
        << estimator_model;
    WriteBenchmarkProfileFields(out, r.profile);
    out << "\n";
    return out.str();
}

std::string SerializeCrossoverHeader() {
    return
        "k,m,onehot_feature_dim,sqrt_feature_dim,"
        "onehot_N,sqrt_N,"
        "onehot_total_ms,sqrt_total_ms,"
        "sqrt_faster,speedup_ratio,"
        "sanitizer_model,sanitizer_assurance,transcript_stat_bits,"
        "max_queries,query_stat_bits,flood_margin_bits,"
        "onehot_coefficient_stat_bits,onehot_eval_noise_bits,"
        "onehot_flood_noise_bits,sqrt_coefficient_stat_bits,"
        "sqrt_eval_noise_bits,sqrt_flood_noise_bits,estimator_model,"
        "profile_id,run_class,target_security_bits,comparison_eligible,"
        "measurement_kind\n";
}

std::string SerializeCrossoverRow(const CrossoverResult& r) {
    const char* estimator_model = RequireEstimatorModel(r.estimator_model);
    const bool applicable = RequireSanitizerMetadata(r.sanitizer);
    if (!applicable ||
        !r.onehot_coefficient_stat_bits.has_value() ||
        !r.onehot_eval_noise_bits.has_value() ||
        !r.onehot_flood_noise_bits.has_value() ||
        !r.sqrt_coefficient_stat_bits.has_value() ||
        !r.sqrt_eval_noise_bits.has_value() ||
        !r.sqrt_flood_noise_bits.has_value()) {
        throw std::logic_error(
            "crossover row is missing applicable arm sanitizer metadata");
    }
    std::ostringstream out;
    out << r.k << ","
        << r.m << ","
        << r.onehot_feature_dim << ","
        << r.sqrt_feature_dim << ","
        << r.onehot_ring_dim << ","
        << r.sqrt_ring_dim << ","
        << std::fixed << std::setprecision(3)
        << r.onehot_total_ms << ","
        << r.sqrt_total_ms << ","
        << (r.sqrt_faster ? 1 : 0) << ","
        << std::setprecision(4)
        << r.speedup_ratio << ","
        << SanitizerModelName(*r.sanitizer.model) << ","
        << SanitizerAssuranceName(*r.sanitizer.model) << ",";
    WriteOptional(out, r.sanitizer.transcript_stat_bits);
    out << ",";
    WriteOptional(out, r.sanitizer.max_queries);
    out << ",";
    WriteOptional(out, r.sanitizer.query_stat_bits);
    out << ",";
    WriteOptional(out, r.sanitizer.flood_margin_bits);
    out << ",";
    WriteOptional(out, r.onehot_coefficient_stat_bits);
    out << ",";
    WriteOptional(out, r.onehot_eval_noise_bits);
    out << ",";
    WriteOptional(out, r.onehot_flood_noise_bits);
    out << ",";
    WriteOptional(out, r.sqrt_coefficient_stat_bits);
    out << ",";
    WriteOptional(out, r.sqrt_eval_noise_bits);
    out << ",";
    WriteOptional(out, r.sqrt_flood_noise_bits);
    out << ","
        << estimator_model;
    WriteBenchmarkProfileFields(out, r.profile);
    out << "\n";
    return out.str();
}

std::string SerializeSqrtComparisonHeader() {
    return
        "encoding,k,m,N,Depth,Encode,Encrypt,Evaluate,Decrypt,Total(ms),"
        "|err|,rel_err,security,transcript_stat_bits,max_queries,"
        "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
        "eval_noise_bits,flood_noise_bits,sanitizer_model,"
        "sanitizer_assurance,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind\n";
}

std::string SerializeSqrtComparisonRow(const SqrtComparisonResult& r) {
    const char* estimator_model = RequireEstimatorModel(r.estimator_model);
    std::ostringstream out;
    out << r.encoding << ","
        << r.k << ","
        << r.m << ","
        << r.ring_dim << ","
        << r.mult_depth << ","
        << std::fixed << std::setprecision(2)
        << r.encode_ms << ","
        << r.encrypt_ms << ","
        << r.evaluate_ms << ","
        << r.decrypt_ms << ","
        << r.total_ms << "\xC2\xB1" << r.total_ms_sd << ","
        << std::setprecision(4)
        << r.jaccard_error << "\xC2\xB1" << r.jaccard_error_sd << ",";
    if (r.has_relative_error) {
        out << r.jaccard_rel_error << "\xC2\xB1" << r.jaccard_rel_error_sd;
    } else {
        out << "N/A";
    }
    out << "," << r.security << ",";
    const bool applicable = RequireSanitizerMetadata(r.sanitizer);
    if (!applicable) {
        throw std::logic_error(
            "sqrt comparison requires applicable sanitizer metadata");
    }
    WriteOptional(out, r.sanitizer.transcript_stat_bits);
    out << ",";
    WriteOptional(out, r.sanitizer.max_queries);
    out << ",";
    WriteOptional(out, r.sanitizer.query_stat_bits);
    out << ",";
    WriteOptional(out, r.sanitizer.coefficient_stat_bits);
    out << ",";
    WriteOptional(out, r.sanitizer.flood_margin_bits);
    out << ",";
    WriteOptional(out, r.sanitizer.eval_noise_bits);
    out << ",";
    WriteOptional(out, r.sanitizer.flood_noise_bits);
    out << ","
        << SanitizerModelName(*r.sanitizer.model) << ","
        << SanitizerAssuranceName(*r.sanitizer.model) << ","
        << estimator_model;
    WriteBenchmarkProfileFields(out, r.profile);
    out << "\n";
    return out.str();
}

}  // namespace benchmark
}  // namespace piccard
