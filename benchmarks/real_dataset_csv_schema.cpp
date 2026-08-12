#include "real_dataset_csv_schema.h"

#include "baseline_profile.h"
#include "benchmark_estimator_provenance.h"
#include "benchmark_profile.h"
#include "data/real_dataset_metrics.h"

#include <sstream>
#include <stdexcept>

namespace piccard::bench {
namespace {

using piccard::benchmark::AssuranceScopeName;
using piccard::benchmark::BaselineCapability;
using piccard::benchmark::BaselineEvidenceKind;
using piccard::benchmark::BaselineMethod;
using piccard::benchmark::BenchmarkMeasurementKind;
using piccard::benchmark::BenchmarkMeasurementKindName;
using piccard::benchmark::BenchmarkProfile;
using piccard::benchmark::BenchmarkRunClassName;
using piccard::benchmark::ComparisonScope;
using piccard::benchmark::ComparisonScopeName;
using piccard::benchmark::CostScopeName;
using piccard::benchmark::EstimatorModel;
using piccard::benchmark::EstimatorModelName;
using piccard::benchmark::OutputSemantics;
using piccard::benchmark::OutputSemanticsName;
using piccard::benchmark::PrecomputationMode;
using piccard::benchmark::PrecomputationModeName;
using piccard::benchmark::PrimitiveName;
using piccard::benchmark::ProtocolModelName;
using piccard::benchmark::ResolveBaselineCapability;
using piccard::benchmark::ResolveBenchmarkProfile;
using piccard::benchmark::SecurityBasisName;
using piccard::data::FormatReal17;

void RequireNonEmpty(const std::string& value, const char* field_name) {
    if (value.empty()) {
        throw std::invalid_argument(
            std::string("real-dataset prefix is missing ") + field_name);
    }
}

template <typename T>
void WriteOptional(std::ostringstream& out, const std::optional<T>& value) {
    if (value.has_value()) out << *value;
}

void WriteOptionalReal(std::ostringstream& out,
                       const std::optional<double>& value) {
    if (value.has_value()) out << FormatReal17(*value);
}

}  // namespace

std::string RealDatasetPrefixHeader() {
    return
        "profile_id,run_class,target_security_bits,cryptographic_profile,"
        "nominal_security_bits,security_match,comparison_eligible,"
        "comparison_scope,primitive,protocol_model,output_semantics,"
        "assurance_scope,security_basis,cost_scope,precomputation_mode,"
        "secure_division_included,measurement_kind,"
        "workload_id,workload_manifest_sha256,execution_trace_sha256,"
        "root_seed,omp_threads,"
        "estimator_model,sanitizer_model,sanitizer_assurance,"
        "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
        "flood_margin_bits,eval_noise_bits,flood_noise_bits,"
        "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version,"
        "target_semantics,target_jaccard,realized_intersection,realized_union,"
        "realized_jaccard,timing_trials,accuracy_trials,omp_dynamic,"
        "measurement_status";
}

std::string RealAccuracyHeader() {
    return RealDatasetPrefixHeader() +
        ",dataset,variant,dataset_manifest_sha256,records_sha256,"
        "pairs_sha256,pair_id,pair_kind,label,record_a,record_b,"
        "k,m,hash_randomness,accuracy_trial_index,hash_seed,"
        "set_size_a_raw,set_size_b_raw,set_size_a_bucketed,set_size_b_bucketed,"
        "exact_jaccard_raw,exact_jaccard_bucketed,estimated_jaccard,"
        "bucket_match_fraction,abs_error,rel_error,jaccard_bucket,"
        "accuracy_workload_sha256\n";
}

std::string RealTimingHeader() {
    return RealDatasetPrefixHeader() +
        ",dataset,variant,dataset_manifest_sha256,records_sha256,"
        "pairs_sha256,pair_id,pair_kind,label,record_a,record_b,"
        "k,m,hash_seed,trial_index,phase_minhash_ms,phase_encode_ms,"
        "phase_encrypt_ms,phase_cloud_multiply_ms,phase_cloud_rotate_ms,"
        "phase_sanitize_ms,phase_decrypt_ms,phase_bias_correction_ms,"
        "total_query_ms,result_value,ciphertext_bytes,upload_bytes,"
        "download_bytes\n";
}

std::string RealThresholdHeader() {
    return
        "schema_version,dataset,variant,dataset_manifest_sha256,records_sha256,"
        "pairs_sha256,pair_id,pair_kind,label,record_a,record_b,k,m,"
        "hash_randomness,root_seed,split,rank_position,threshold_trial_index,"
        "hash_seed,match_count,decision,label_truth,label_outcome,"
        "exact_j_truth,exact_j_outcome,exact_jaccard_bucketed,"
        "requested_j_threshold,tau_count,realized_j_tau,calibration_fpr,"
        "calibration_fnr,calibration_balanced_error,calibration_digest,"
        "evaluation_digest,threshold_workload_sha256\n";
}

std::string RealThresholdWorkloadRowsHeader() {
    return "pair_id\tlabel\tsplit\trank_position\trecord_a\trecord_b\t"
           "exact_jaccard_bucketed\n";
}

std::string SerializeRealDatasetPrefix(const RealDatasetPrefixValues& v) {
    RequireNonEmpty(v.profile_id, "profile_id");
    RequireNonEmpty(v.run_class, "run_class");
    RequireNonEmpty(v.cryptographic_profile, "cryptographic_profile");
    RequireNonEmpty(v.comparison_scope, "comparison_scope");
    RequireNonEmpty(v.primitive, "primitive");
    RequireNonEmpty(v.protocol_model, "protocol_model");
    RequireNonEmpty(v.output_semantics, "output_semantics");
    RequireNonEmpty(v.assurance_scope, "assurance_scope");
    RequireNonEmpty(v.security_basis, "security_basis");
    RequireNonEmpty(v.cost_scope, "cost_scope");
    RequireNonEmpty(v.precomputation_mode, "precomputation_mode");
    RequireNonEmpty(v.measurement_kind, "measurement_kind");
    RequireNonEmpty(v.workload_id, "workload_id");
    RequireNonEmpty(v.workload_manifest_sha256, "workload_manifest_sha256");
    RequireNonEmpty(v.execution_trace_sha256, "execution_trace_sha256");
    RequireNonEmpty(v.estimator_model, "estimator_model");
    RequireNonEmpty(v.sanitizer_model, "sanitizer_model");
    RequireNonEmpty(v.sanitizer_assurance, "sanitizer_assurance");
    RequireNonEmpty(v.openfhe_version, "openfhe_version");
    RequireNonEmpty(v.target_semantics, "target_semantics");
    RequireNonEmpty(v.measurement_status, "measurement_status");

    std::ostringstream out;
    out << v.profile_id << "," << v.run_class << ",";
    WriteOptional(out, v.target_security_bits);
    out << "," << v.cryptographic_profile << ",";
    WriteOptional(out, v.nominal_security_bits);
    out << "," << (v.security_match ? "true" : "false")
        << "," << (v.comparison_eligible ? "true" : "false")
        << "," << v.comparison_scope
        << "," << v.primitive
        << "," << v.protocol_model
        << "," << v.output_semantics
        << "," << v.assurance_scope
        << "," << v.security_basis
        << "," << v.cost_scope
        << "," << v.precomputation_mode
        << "," << (v.secure_division_included ? "true" : "false")
        << "," << v.measurement_kind
        << "," << v.workload_id
        << "," << v.workload_manifest_sha256
        << "," << v.execution_trace_sha256
        << "," << v.root_seed
        << "," << v.omp_threads
        << "," << v.estimator_model
        << "," << v.sanitizer_model
        << "," << v.sanitizer_assurance
        << ",";
    WriteOptional(out, v.transcript_stat_bits);
    out << ",";
    WriteOptional(out, v.max_queries);
    out << ",";
    WriteOptional(out, v.query_stat_bits);
    out << ",";
    WriteOptional(out, v.coefficient_stat_bits);
    out << ",";
    WriteOptional(out, v.flood_margin_bits);
    out << ",";
    WriteOptional(out, v.eval_noise_bits);
    out << ",";
    WriteOptional(out, v.flood_noise_bits);
    out << ",";
    WriteOptional(out, v.actual_ring_dim);
    out << ",";
    WriteOptionalReal(out, v.log_q_bits);
    out << ",";
    WriteOptional(out, v.plaintext_modulus);
    out << ",";
    WriteOptional(out, v.num_limbs);
    out << "," << v.openfhe_version
        << "," << v.target_semantics
        << ",";
    WriteOptionalReal(out, v.target_jaccard);
    out << ",";
    WriteOptional(out, v.realized_intersection);
    out << ",";
    WriteOptional(out, v.realized_union);
    out << ",";
    WriteOptionalReal(out, v.realized_jaccard);
    out << ",";
    WriteOptional(out, v.timing_trials);
    out << ",";
    WriteOptional(out, v.accuracy_trials);
    out << "," << (v.omp_dynamic ? "true" : "false")
        << "," << v.measurement_status;
    return out.str();
}

RealDatasetPrefixValues MakePlaintextAccuracyPrefix(
    const std::string& variant,
    const std::string& accuracy_workload_sha256,
    uint32_t accuracy_trials,
    uint64_t root_seed) {
    if (variant.empty()) {
        throw std::invalid_argument(
            "MakePlaintextAccuracyPrefix: variant must not be empty");
    }
    if (accuracy_workload_sha256.empty()) {
        throw std::invalid_argument(
            "MakePlaintextAccuracyPrefix: accuracy_workload_sha256 must not "
            "be empty");
    }

    RealDatasetPrefixValues v;
    v.profile_id = "plaintext-estimator";
    v.run_class = "diagnostic";  // new token; BenchmarkRunClassName has none
    v.target_security_bits = std::nullopt;
    v.cryptographic_profile = "not-applicable";
    v.nominal_security_bits = std::nullopt;
    v.security_match = false;
    v.comparison_eligible = false;
    v.comparison_scope = ComparisonScopeName(ComparisonScope::DiagnosticOnly);
    v.primitive = "sha256-minhash";
    v.protocol_model = "plaintext-estimator-pipeline";
    v.output_semantics =
        OutputSemanticsName(OutputSemantics::BiasCorrectedJaccardEstimate);
    v.assurance_scope = "empirical-poc";
    v.security_basis = "not-applicable";
    v.cost_scope = "not-applicable";
    v.precomputation_mode =
        PrecomputationModeName(PrecomputationMode::NotApplicable);
    v.secure_division_included = false;
    v.measurement_kind = BenchmarkMeasurementKindName(
        BenchmarkMeasurementKind::PlaintextEstimator);
    v.workload_id = "real:" + variant + ":accuracy";
    v.workload_manifest_sha256 = accuracy_workload_sha256;
    v.execution_trace_sha256 = "not-applicable";
    v.root_seed = root_seed;
    v.omp_threads = 1;
    v.estimator_model =
        EstimatorModelName(EstimatorModel::Sha256RandomRankingPocV1);
    v.sanitizer_model = "not-applicable";
    v.sanitizer_assurance = "not-applicable";
    // transcript_stat_bits .. flood_noise_bits stay unset: no sanitizer.
    // actual_ring_dim .. num_limbs stay unset: no live FHE context.
    v.openfhe_version = "not-applicable";
    v.target_semantics = "observed-dataset-pair";
    v.target_jaccard = std::nullopt;
    // realized_intersection/union/jaccard: filled per pair by the driver.
    v.timing_trials = std::nullopt;
    v.accuracy_trials = accuracy_trials;
    v.omp_dynamic = false;
    v.measurement_status = "measured";
    return v;
}

RealDatasetPrefixValues MakeFheTimingPrefix(
    const std::string& variant,
    const std::string& profile_id,
    const std::string& timing_workload_sha256,
    uint64_t root_seed,
    uint32_t timing_trials,
    uint32_t omp_threads) {
    if (variant.empty()) {
        throw std::invalid_argument(
            "MakeFheTimingPrefix: variant must not be empty");
    }
    if (timing_workload_sha256.empty()) {
        throw std::invalid_argument(
            "MakeFheTimingPrefix: timing_workload_sha256 must not be empty");
    }

    const BenchmarkProfile& profile = ResolveBenchmarkProfile(profile_id);
    const BaselineCapability capability = ResolveBaselineCapability(
        BaselineMethod::Piccard, profile.target_security_bits,
        BaselineEvidenceKind::Timing);

    RealDatasetPrefixValues v;
    v.profile_id = profile.id;
    v.run_class = BenchmarkRunClassName(profile.run_class);
    v.target_security_bits = profile.target_security_bits;
    v.cryptographic_profile = capability.cryptographic_profile;
    v.nominal_security_bits = capability.nominal_security_bits;
    v.security_match = capability.security_match;
    v.comparison_eligible = profile.comparison_eligible &&
                            capability.comparison_eligible;
    v.comparison_scope = ComparisonScopeName(capability.comparison_scope);
    v.primitive = PrimitiveName(capability.primitive);
    v.protocol_model = ProtocolModelName(capability.protocol_model);
    v.output_semantics = OutputSemanticsName(capability.output_semantics);
    v.assurance_scope = AssuranceScopeName(capability.assurance_scope);
    v.security_basis = SecurityBasisName(capability.security_basis);
    v.cost_scope = CostScopeName(capability.cost_scope);
    v.precomputation_mode =
        PrecomputationModeName(capability.precomputation_mode);
    v.secure_division_included = capability.secure_division_included;
    v.measurement_kind = BenchmarkMeasurementKindName(capability.measurement_kind);
    v.workload_id = "real:" + variant + ":timing:" + profile.id;
    v.workload_manifest_sha256 = timing_workload_sha256;
    v.execution_trace_sha256 = "not-applicable";
    v.root_seed = root_seed;
    v.omp_threads = omp_threads;
    v.estimator_model =
        EstimatorModelName(EstimatorModel::Sha256RandomRankingPocV1);
    // sanitizer_model/sanitizer_assurance/sanitizer numerics and the live FHE
    // build provenance fields stay unset: no live BFV context exists yet.
    // The timing driver (Sub-phase 5.4) fills them from the real context.
    v.target_semantics = "observed-dataset-pair";
    v.target_jaccard = std::nullopt;
    // realized_intersection/union/jaccard: filled per pair by the driver.
    v.timing_trials = timing_trials;
    v.accuracy_trials = std::nullopt;
    v.omp_dynamic = false;
    v.measurement_status = "measured";
    return v;
}

}  // namespace piccard::bench
