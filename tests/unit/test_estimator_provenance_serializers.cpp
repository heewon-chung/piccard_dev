#include "benchmark_estimator_provenance.h"
#include "build_info.h"
#include "util/params.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace piccard::benchmark;

namespace {

size_t CsvColumns(const std::string& line) {
    return static_cast<size_t>(std::count(line.begin(), line.end(), ',')) + 1;
}

void ExpectGoldenCsv(const std::string& actual_header,
                     const std::string& actual_row,
                     const std::string& expected_header,
                     const std::string& expected_row) {
    EXPECT_EQ(actual_header, expected_header);
    EXPECT_EQ(actual_row, expected_row);
    EXPECT_EQ(CsvColumns(actual_header), CsvColumns(actual_row));
}

constexpr const char* kEstimator = "sha256-random-ranking-poc-v1";
constexpr const char* kNotApplicable = "not-applicable";

std::vector<std::string> CsvCells(const std::string& line) {
    std::vector<std::string> cells;
    size_t start = 0;
    for (size_t comma = line.find(',');
         comma != std::string::npos;
         comma = line.find(',', start)) {
        cells.push_back(line.substr(start, comma - start));
        start = comma + 1;
    }
    std::string last = line.substr(start);
    if (!last.empty() && last.back() == '\n') last.pop_back();
    cells.push_back(last);
    return cells;
}

size_t ColumnIndex(const std::string& header, const std::string& name) {
    const auto cells = CsvCells(header);
    const auto it = std::find(cells.begin(), cells.end(), name);
    EXPECT_NE(it, cells.end()) << "missing CSV column " << name;
    return static_cast<size_t>(std::distance(cells.begin(), it));
}

SanitizerMetadata ApplicableMetadata() {
    SanitizerMetadata metadata;
    metadata.model = SanitizerModel::PhaseSmudgingEnc0PocV1;
    metadata.transcript_stat_bits = 40;
    metadata.max_queries = UINT64_C(1048576);
    metadata.query_stat_bits = 60;
    metadata.coefficient_stat_bits = 73;
    metadata.flood_margin_bits = 8;
    metadata.eval_noise_bits = 60;
    metadata.flood_noise_bits = 141;
    return metadata;
}

BenchmarkProvenance ApplicableProvenance(
    uint32_t ring_dim = 8192,
    double log_q_bits = 120.0,
    uint64_t plaintext_modulus = 12289,
    uint32_t num_limbs = 3) {
    BenchmarkProvenance provenance;
    provenance.actual_ring_dim = ring_dim;
    provenance.log_q_bits = log_q_bits;
    provenance.plaintext_modulus = plaintext_modulus;
    provenance.num_limbs = num_limbs;
    provenance.openfhe_version = PICCARD_BUILD_OPENFHE_VERSION;
    provenance.sanitizer_applicable = true;
    const SanitizerMetadata sanitizer = ApplicableMetadata();
    provenance.transcript_stat_bits = sanitizer.transcript_stat_bits;
    provenance.max_queries = sanitizer.max_queries;
    provenance.query_stat_bits = sanitizer.query_stat_bits;
    provenance.coefficient_stat_bits = sanitizer.coefficient_stat_bits;
    provenance.flood_margin_bits = sanitizer.flood_margin_bits;
    provenance.eval_noise_bits = sanitizer.eval_noise_bits;
    provenance.flood_noise_bits = sanitizer.flood_noise_bits;
    provenance.scaling_mod_size = 0;
    return provenance;
}

BenchmarkProvenance FheIndProvenance() {
    BenchmarkProvenance provenance = ApplicableProvenance();
    provenance.sanitizer_applicable = false;
    provenance.transcript_stat_bits.reset();
    provenance.max_queries.reset();
    provenance.query_stat_bits.reset();
    provenance.coefficient_stat_bits.reset();
    provenance.flood_margin_bits.reset();
    provenance.eval_noise_bits.reset();
    provenance.flood_noise_bits.reset();
    provenance.scaling_mod_size.reset();
    return provenance;
}

std::string StandardProvenanceSuffix() {
    return ",8192,120.000000000000,12289,3," +
           std::string(PICCARD_BUILD_OPENFHE_VERSION) + "\n";
}

std::string CrossoverProvenanceSuffix() {
    return "," + std::string(PICCARD_BUILD_OPENFHE_VERSION) +
           ",8192,120.0000,12289,3,8192,120.0000,12289,3\n";
}

}  // namespace

TEST(EstimatorProvenanceSerializers, PiccardGoldenSchema) {
    BenchmarkResult row;
    row.label = "piccard";
    row.param_k = 128;
    row.param_m = 64;
    row.param_set_size = 1000;
    row.param_ring_dim = 8192;
    row.encoding = "onehot";
    row.param_mult_depth = 1;
    row.param_num_cts = 1;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = ApplicableMetadata();
    row.provenance = ApplicableProvenance();

    const std::string expected_header =
        "label,k,m,set_size,ring_dim,time_ms,phase_minhash_ms,phase_encode_ms,"
        "phase_encrypt_ms,phase_multiply_ms,phase_rotate_sum_ms,phase_decrypt_ms,"
        "phase_bias_correction_ms,memory_bytes,ct_size_bytes,jaccard_computed,"
        "jaccard_expected,jaccard_error,jaccard_rel_error,accuracy_median,"
        "accuracy_p25,accuracy_p75,accuracy_p95,accuracy_max,encoding,mult_depth,"
        "num_cts,comm_bytes,phase_intra_digit_rotate_ms,phase_digit_and_ms,"
        "phase_cross_k_sum_ms,trials,time_ms_sd,time_ms_median,"
        "phase_minhash_ms_sd,phase_minhash_ms_median,phase_encode_ms_sd,"
        "phase_encode_ms_median,phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_multiply_ms_sd,phase_multiply_ms_median,phase_rotate_sum_ms_sd,"
        "phase_rotate_sum_ms_median,phase_decrypt_ms_sd,phase_decrypt_ms_median,"
        "phase_bias_correction_ms_sd,phase_bias_correction_ms_median,"
        "rel_error_eligible_n,hash_randomness,hash_seed,hash_root_seed,"
        "accuracy_trials,phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
        "transcript_stat_bits,max_queries,query_stat_bits,"
        "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,"
        "flood_noise_bits,scaling_mod_size,sanitizer_model,"
        "sanitizer_assurance,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind,"
        "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
        "openfhe_version\n";
    const std::string expected_row =
        "piccard,128,64,1000,8192,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,"
        "0.000000,0.000000,onehot,1,1,0,0.000,0.000,0.000,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,40,1048576,60,73,8,60,141,0,"
        "phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "sha256-random-ranking-poc-v1,legacy,legacy,0,false,diagnostic" +
        StandardProvenanceSuffix();

    ExpectGoldenCsv(SerializeBenchmarkHeader(),
                    SerializeBenchmarkRow(row, row.provenance),
                    expected_header, expected_row);
    EXPECT_NE(SerializeBenchmarkRow(row, row.provenance).find(kEstimator),
              std::string::npos);
}

TEST(EstimatorProvenanceSerializers, OneHotAndSqrtGoldenRows) {
    BenchmarkResult onehot;
    onehot.label = "onehot";
    onehot.encoding = "onehot";
    onehot.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    onehot.sanitizer = ApplicableMetadata();
    onehot.provenance = ApplicableProvenance();

    BenchmarkResult sqrt;
    sqrt.label = "sqrt";
    sqrt.encoding = "sqrt";
    sqrt.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    sqrt.sanitizer = ApplicableMetadata();
    sqrt.provenance = ApplicableProvenance();

    const std::string expected_onehot =
        "onehot,0,0,0,0,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,"
        "0.000000,0.000000,onehot,0,0,0,0.000,0.000,0.000,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,40,1048576,60,73,8,60,141,0,"
        "phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "sha256-random-ranking-poc-v1,legacy,legacy,0,false,diagnostic" +
        StandardProvenanceSuffix();
    const std::string expected_sqrt =
        "sqrt,0,0,0,0,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,"
        "0.000000,0.000000,sqrt,0,0,0,0.000,0.000,0.000,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,40,1048576,60,73,8,60,141,0,"
        "phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "sha256-random-ranking-poc-v1,legacy,legacy,0,false,diagnostic" +
        StandardProvenanceSuffix();

    EXPECT_EQ(SerializeBenchmarkRow(onehot, onehot.provenance), expected_onehot);
    EXPECT_EQ(SerializeBenchmarkRow(sqrt, sqrt.provenance), expected_sqrt);
    EXPECT_EQ(CsvColumns(SerializeBenchmarkHeader()), CsvColumns(expected_onehot));
    EXPECT_EQ(CsvColumns(SerializeBenchmarkHeader()), CsvColumns(expected_sqrt));
}

TEST(EstimatorProvenanceSerializers, DynamicGoldenSchema) {
    DynamicResult row;
    row.label = "dynamic";
    row.k = 128;
    row.m = 64;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = ApplicableMetadata();
    row.provenance = ApplicableProvenance();

    const std::string expected_header =
        "label,k,m,set_size,ring_dim,depth,phase_init_ms,phase_insert_ms,"
        "phase_delete_ms,phase_signature_ms,phase_encode_ms,phase_encrypt_ms,"
        "phase_compute_ms,phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,"
        "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
        "ops_insert_per_sec,ops_delete_per_sec,trials,total_ms_sd,total_ms_median,"
        "phase_init_ms_sd,phase_init_ms_median,phase_insert_ms_sd,"
        "phase_insert_ms_median,phase_delete_ms_sd,phase_delete_ms_median,"
        "phase_signature_ms_sd,phase_signature_ms_median,phase_encode_ms_sd,"
        "phase_encode_ms_median,phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_compute_ms_sd,phase_compute_ms_median,phase_decrypt_ms_sd,"
        "phase_decrypt_ms_median,rel_error_eligible_n,hash_randomness,hash_seed,"
        "hash_root_seed,accuracy_trials,phase_flood_ms,phase_flood_ms_sd,"
        "phase_flood_ms_median,transcript_stat_bits,max_queries,"
        "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
        "eval_noise_bits,flood_noise_bits,scaling_mod_size,"
        "sanitizer_model,sanitizer_assurance,estimator_model,profile_id,"
        "run_class,target_security_bits,comparison_eligible,measurement_kind,"
        "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
        "openfhe_version\n";
    const std::string expected_row =
        "dynamic,128,64,0,0,0,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.0,0.0,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,40,1048576,60,73,8,60,141,0,"
        "phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "sha256-random-ranking-poc-v1,legacy,legacy,0,false,diagnostic" +
        StandardProvenanceSuffix();

    ExpectGoldenCsv(SerializeDynamicHeader(),
                    SerializeDynamicRow(row, row.provenance),
                    expected_header, expected_row);
}

TEST(EstimatorProvenanceSerializers, ComparisonClassifiesConcreteModes) {
    struct Case {
        BaselineMethod method;
        EstimatorModel model;
        const char* expected_kind;
    };
    const Case cases[] = {
        {BaselineMethod::Piccard, EstimatorModel::Sha256RandomRankingPocV1,
         "fhe-timing"},
        {BaselineMethod::PiccardSqrt,
         EstimatorModel::Sha256RandomRankingPocV1, "fhe-timing"},
        {BaselineMethod::FheInd, EstimatorModel::NotApplicable,
         "diagnostic"},
        {BaselineMethod::Bcg12MinHashFf,
         EstimatorModel::Sha256RandomRankingPocV1, "psi-timing"},
        {BaselineMethod::Bcg12ExactEc, EstimatorModel::NotApplicable,
         "psi-timing"},
        {BaselineMethod::Sj16Paillier3072, EstimatorModel::NotApplicable,
         "ahe-timing"},
    };

    for (const auto& c : cases) {
        ComparisonResult row;
        row.scenario = "golden";
        row.method = BaselineMethodName(c.method);
        row.capability = ResolveBaselineCapability(
            c.method, 128, BaselineEvidenceKind::Timing);
        row.estimator_model = c.model;
        const bool sanitizer_applies =
            c.method == BaselineMethod::Piccard ||
            c.method == BaselineMethod::PiccardSqrt;
        row.sanitizer = sanitizer_applies
            ? ApplicableMetadata()
            : NotApplicableSanitizerMetadata();
        row.provenance = sanitizer_applies
            ? ApplicableProvenance()
            : (c.method == BaselineMethod::FheInd
                   ? FheIndProvenance()
                   : MakeAheBenchmarkProvenance());
        if (c.method == BaselineMethod::Piccard ||
            c.method == BaselineMethod::PiccardSqrt) {
            row.k = 128;
            row.m = 64;
            row.ring_dim = 8192;
        } else if (c.method == BaselineMethod::FheInd) {
            row.ring_dim = 8192;
        } else if (c.method == BaselineMethod::Bcg12MinHashFf) {
            row.k = 128;
            row.hash_randomness = "fixed";
        }

        const std::string header = SerializeComparisonHeader();
        const std::string serialized =
            SerializeComparisonRow(row, 4, row.provenance);
        const auto cells = CsvCells(serialized);
        EXPECT_EQ(cells[ColumnIndex(header, "measurement_kind")],
                  c.expected_kind);
        EXPECT_EQ(cells[ColumnIndex(header, "protocol_model")],
                  ProtocolModelName(row.capability->protocol_model));
        EXPECT_EQ(cells[ColumnIndex(header, "comparison_scope")],
                  ComparisonScopeName(row.capability->comparison_scope));
        EXPECT_EQ(CsvColumns(header), CsvColumns(serialized));
    }
}

TEST(EstimatorProvenanceSerializers, CrossoverBothArmsGoldenSchema) {
    CrossoverResult row;
    row.k = 128;
    row.m = 64;
    row.onehot_total_ms = 12.5;
    row.sqrt_total_ms = 8.25;
    row.sqrt_faster = true;
    row.speedup_ratio = 1.5152;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = ApplicableMetadata();
    row.onehot_provenance = ApplicableProvenance();
    row.sqrt_provenance = ApplicableProvenance();
    row.sqrt_provenance.coefficient_stat_bits = 72;
    row.sqrt_provenance.eval_noise_bits = 95;
    row.sqrt_provenance.flood_noise_bits = 175;
    row.onehot_coefficient_stat_bits = 73;
    row.onehot_eval_noise_bits = 60;
    row.onehot_flood_noise_bits = 141;
    row.sqrt_coefficient_stat_bits = 72;
    row.sqrt_eval_noise_bits = 95;
    row.sqrt_flood_noise_bits = 175;

    const std::string expected_header =
        "k,m,onehot_feature_dim,sqrt_feature_dim,onehot_N,sqrt_N,"
        "onehot_total_ms,sqrt_total_ms,sqrt_faster,speedup_ratio,"
        "sanitizer_model,sanitizer_assurance,transcript_stat_bits,"
        "max_queries,query_stat_bits,flood_margin_bits,"
        "onehot_coefficient_stat_bits,onehot_eval_noise_bits,"
        "onehot_flood_noise_bits,sqrt_coefficient_stat_bits,"
        "sqrt_eval_noise_bits,sqrt_flood_noise_bits,estimator_model,"
        "profile_id,run_class,target_security_bits,comparison_eligible,"
        "measurement_kind,openfhe_version,onehot_actual_ring_dim,"
        "onehot_log_q_bits,onehot_plaintext_modulus,onehot_num_limbs,"
        "sqrt_actual_ring_dim,sqrt_log_q_bits,sqrt_plaintext_modulus,"
        "sqrt_num_limbs\n";
    const std::string expected_row =
        "128,64,0,0,0,0,12.500,8.250,1,1.5152,"
        "phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "40,1048576,60,8,73,60,141,72,95,175,"
        "sha256-random-ranking-poc-v1,legacy,legacy,0,false,diagnostic" +
        CrossoverProvenanceSuffix();

    ExpectGoldenCsv(SerializeCrossoverHeader(),
                    SerializeCrossoverRow(
                        row, row.onehot_provenance, row.sqrt_provenance),
                    expected_header, expected_row);
}

TEST(EstimatorProvenanceSerializers, SqrtComparisonBothArmsGoldenRows) {
    SqrtComparisonResult onehot;
    onehot.encoding = "OneHot";
    onehot.k = 128;
    onehot.m = 64;
    onehot.ring_dim = 8192;
    onehot.mult_depth = 1;
    onehot.has_relative_error = false;
    onehot.security = "TOY";
    onehot.sanitizer = ApplicableMetadata();
    onehot.provenance = ApplicableProvenance();
    onehot.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;

    SqrtComparisonResult sqrt = onehot;
    sqrt.encoding = "Sqrt";
    sqrt.mult_depth = 3;

    const std::string expected_header =
        "encoding,k,m,N,Depth,Encode,Encrypt,Evaluate,Decrypt,Total(ms),"
        "|err|,rel_err,security,transcript_stat_bits,max_queries,"
        "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
        "eval_noise_bits,flood_noise_bits,sanitizer_model,"
        "sanitizer_assurance,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind,"
        "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
        "openfhe_version\n";
    const std::string expected_onehot =
        "OneHot,128,64,8192,1,0.00,0.00,0.00,0.00,0.00"
        "\xC2\xB1" "0.00,0.0000" "\xC2\xB1" "0.0000,N/A,"
        "TOY,40,1048576,60,73,8,60,141,"
        "phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "sha256-random-ranking-poc-v1,legacy,legacy,0,false,diagnostic" +
        StandardProvenanceSuffix();
    const std::string expected_sqrt =
        "Sqrt,128,64,8192,3,0.00,0.00,0.00,0.00,0.00"
        "\xC2\xB1" "0.00,0.0000" "\xC2\xB1" "0.0000,N/A,"
        "TOY,40,1048576,60,73,8,60,141,"
        "phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "sha256-random-ranking-poc-v1,legacy,legacy,0,false,diagnostic" +
        StandardProvenanceSuffix();

    EXPECT_EQ(SerializeSqrtComparisonHeader(), expected_header);
    EXPECT_EQ(SerializeSqrtComparisonRow(onehot, onehot.provenance),
              expected_onehot);
    EXPECT_EQ(SerializeSqrtComparisonRow(sqrt, sqrt.provenance),
              expected_sqrt);
    EXPECT_EQ(CsvColumns(expected_header), CsvColumns(expected_onehot));
    EXPECT_EQ(CsvColumns(expected_header), CsvColumns(expected_sqrt));
}

TEST(EstimatorProvenanceSerializers, PiccardSanitizerMetadataIsExact) {
    BenchmarkResult row;
    row.label = "piccard";
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = ApplicableMetadata();
    row.provenance = ApplicableProvenance();

    const std::string header = SerializeBenchmarkHeader();
    const std::string serialized = SerializeBenchmarkRow(row, row.provenance);
    const auto cells = CsvCells(serialized);

    EXPECT_EQ(cells[ColumnIndex(header, "sanitizer_model")],
              "phase-smudging-enc0-poc-v1");
    EXPECT_EQ(cells[ColumnIndex(header, "sanitizer_assurance")],
              "empirical-phase-statistical+ciphertext-computational");
    EXPECT_EQ(cells[ColumnIndex(header, "transcript_stat_bits")], "40");
    EXPECT_EQ(cells[ColumnIndex(header, "max_queries")], "1048576");
    EXPECT_EQ(cells[ColumnIndex(header, "query_stat_bits")], "60");
    EXPECT_EQ(cells[ColumnIndex(header, "coefficient_stat_bits")], "73");
    EXPECT_EQ(cells[ColumnIndex(header, "flood_margin_bits")], "8");
    EXPECT_EQ(cells[ColumnIndex(header, "eval_noise_bits")], "60");
    EXPECT_EQ(cells[ColumnIndex(header, "flood_noise_bits")], "141");
    EXPECT_EQ(CsvColumns(header), CsvColumns(serialized));
}

TEST(EstimatorProvenanceSerializers,
     ProductionMetadataHelperCopiesDerivedProfileExactly) {
    piccard::PiccardParams params;
    params.Validate();

    const SanitizerMetadata metadata = MakeSanitizerMetadata(params);

    EXPECT_EQ(metadata.model, SanitizerModel::PhaseSmudgingEnc0PocV1);
    EXPECT_EQ(metadata.transcript_stat_bits, 40u);
    EXPECT_EQ(metadata.max_queries, UINT64_C(1048576));
    EXPECT_EQ(metadata.query_stat_bits, 60u);
    EXPECT_EQ(metadata.coefficient_stat_bits, 73u);
    EXPECT_EQ(metadata.flood_margin_bits, 8u);
    EXPECT_EQ(metadata.eval_noise_bits, 60u);
    EXPECT_EQ(metadata.flood_noise_bits, 141u);
}

TEST(EstimatorProvenanceSerializers,
     ComparisonSanitizerIndependentRowsUseEmptyNumericCells) {
    const BaselineMethod methods[] = {
        BaselineMethod::FheInd,
        BaselineMethod::Bcg12MinHashFf,
        BaselineMethod::Bcg12ExactEc,
        BaselineMethod::Sj16Paillier3072,
    };
    const std::string header = SerializeComparisonHeader();
    const std::vector<std::string> numeric_columns = {
        "transcript_stat_bits",
        "max_queries",
        "query_stat_bits",
        "coefficient_stat_bits",
        "flood_margin_bits",
        "eval_noise_bits",
        "flood_noise_bits",
        "scaling_mod_size",
    };

    for (BaselineMethod method : methods) {
        ComparisonResult row;
        row.scenario = "not-applicable-golden";
        row.method = BaselineMethodName(method);
        row.capability = ResolveBaselineCapability(
            method, 128, BaselineEvidenceKind::Timing);
        row.estimator_model = EstimatorModel::NotApplicable;
        row.sanitizer = NotApplicableSanitizerMetadata();
        row.provenance = method == BaselineMethod::FheInd
            ? FheIndProvenance()
            : MakeAheBenchmarkProvenance();
        if (method == BaselineMethod::FheInd) row.ring_dim = 8192;
        if (method == BaselineMethod::Bcg12MinHashFf) {
            row.k = 128;
            row.hash_randomness = "fixed";
        }

        const std::string serialized =
            SerializeComparisonRow(row, 4, row.provenance);
        const auto cells = CsvCells(serialized);
        EXPECT_EQ(cells[ColumnIndex(header, "sanitizer_model")],
                  "not-applicable");
        EXPECT_EQ(cells[ColumnIndex(header, "sanitizer_assurance")],
                  "not-applicable");
        for (const auto& column : numeric_columns) {
            EXPECT_EQ(cells[ColumnIndex(header, column)], "")
                << "method=" << BaselineMethodName(method)
                << " column=" << column;
        }
        EXPECT_EQ(CsvColumns(header), CsvColumns(serialized));
    }
}

TEST(EstimatorProvenanceSerializers,
     CrossoverCarriesSeparateArmMetadataAndActualN) {
    CrossoverResult row;
    row.k = 128;
    row.m = 64;
    row.onehot_ring_dim = 8192;
    row.sqrt_ring_dim = 4096;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = ApplicableMetadata();
    row.onehot_provenance = ApplicableProvenance(8192);
    row.sqrt_provenance = ApplicableProvenance(4096);
    row.sqrt_provenance.coefficient_stat_bits = 72;
    row.sqrt_provenance.eval_noise_bits = 95;
    row.sqrt_provenance.flood_noise_bits = 175;
    row.onehot_coefficient_stat_bits = 73;
    row.onehot_eval_noise_bits = 60;
    row.onehot_flood_noise_bits = 141;
    row.sqrt_coefficient_stat_bits = 72;
    row.sqrt_eval_noise_bits = 95;
    row.sqrt_flood_noise_bits = 175;

    const std::string header = SerializeCrossoverHeader();
    const std::string serialized = SerializeCrossoverRow(
        row, row.onehot_provenance, row.sqrt_provenance);
    const auto cells = CsvCells(serialized);

    EXPECT_EQ(cells[ColumnIndex(header, "onehot_N")], "8192");
    EXPECT_EQ(cells[ColumnIndex(header, "sqrt_N")], "4096");
    EXPECT_EQ(cells[ColumnIndex(header, "onehot_coefficient_stat_bits")],
              "73");
    EXPECT_EQ(cells[ColumnIndex(header, "onehot_eval_noise_bits")], "60");
    EXPECT_EQ(cells[ColumnIndex(header, "onehot_flood_noise_bits")], "141");
    EXPECT_EQ(cells[ColumnIndex(header, "sqrt_coefficient_stat_bits")],
              "72");
    EXPECT_EQ(cells[ColumnIndex(header, "sqrt_eval_noise_bits")], "95");
    EXPECT_EQ(cells[ColumnIndex(header, "sqrt_flood_noise_bits")], "175");
    EXPECT_EQ(CsvColumns(header), CsvColumns(serialized));
}

TEST(EstimatorProvenanceSerializers,
     SqrtComparisonUsesExplicitDiagnosticProfile) {
    SqrtComparisonResult row;
    row.encoding = "OneHot";
    row.security = "TOY";
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = ApplicableMetadata();
    row.provenance = ApplicableProvenance();

    const std::string header = SerializeSqrtComparisonHeader();
    const std::string serialized =
        SerializeSqrtComparisonRow(row, row.provenance);
    const auto cells = CsvCells(serialized);

    EXPECT_EQ(cells[ColumnIndex(header, "security")], "TOY");
    EXPECT_EQ(cells[ColumnIndex(header, "transcript_stat_bits")], "40");
    EXPECT_EQ(cells[ColumnIndex(header, "max_queries")], "1048576");
    EXPECT_EQ(cells[ColumnIndex(header, "flood_margin_bits")], "8");
    EXPECT_EQ(CsvColumns(header), CsvColumns(serialized));
}

TEST(EstimatorProvenanceSerializers,
     TypedBenchmarkProfileMetadataIsPresentOnEveryRowSchema) {
    const auto primary = MakeBenchmarkProfileMetadata(
        ResolveBenchmarkProfile("std128-t40-primary"),
        BenchmarkMeasurementKind::FheTiming);

    BenchmarkResult benchmark;
    benchmark.label = "piccard";
    benchmark.profile = primary;
    benchmark.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    benchmark.sanitizer = ApplicableMetadata();
    benchmark.provenance = ApplicableProvenance();

    DynamicResult dynamic;
    dynamic.label = "dynamic";
    dynamic.profile = primary;
    dynamic.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    dynamic.sanitizer = ApplicableMetadata();
    dynamic.provenance = ApplicableProvenance();

    ComparisonResult comparison;
    comparison.scenario = "review";
    comparison.method = "piccard";
    comparison.capability = ResolveBaselineCapability(
        BaselineMethod::Piccard, 128, BaselineEvidenceKind::Timing);
    comparison.profile = primary;
    comparison.k = 128;
    comparison.m = 64;
    comparison.ring_dim = 8192;
    comparison.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    comparison.sanitizer = ApplicableMetadata();
    comparison.provenance = ApplicableProvenance();

    CrossoverResult crossover;
    crossover.profile = MakeBenchmarkProfileMetadata(
        ResolveBenchmarkProfile("toy-smoke"),
        BenchmarkMeasurementKind::Diagnostic);
    crossover.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    crossover.sanitizer = ApplicableMetadata();
    crossover.onehot_provenance = ApplicableProvenance();
    crossover.sqrt_provenance = ApplicableProvenance();
    crossover.onehot_coefficient_stat_bits = 73;
    crossover.onehot_eval_noise_bits = 60;
    crossover.onehot_flood_noise_bits = 141;
    crossover.sqrt_coefficient_stat_bits = 73;
    crossover.sqrt_eval_noise_bits = 60;
    crossover.sqrt_flood_noise_bits = 141;

    SqrtComparisonResult sqrt;
    sqrt.encoding = "OneHot";
    sqrt.profile = crossover.profile;
    sqrt.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    sqrt.sanitizer = ApplicableMetadata();
    sqrt.provenance = ApplicableProvenance();

    struct Csv {
        std::string header;
        std::string row;
        const char* expected_profile;
        const char* expected_class;
        const char* expected_kind;
    };
    const std::vector<Csv> csvs = {
        {SerializeBenchmarkHeader(),
         SerializeBenchmarkRow(benchmark, benchmark.provenance),
         "std128-t40-primary", "primary", "fhe-timing"},
        {SerializeDynamicHeader(),
         SerializeDynamicRow(dynamic, dynamic.provenance),
         "std128-t40-primary", "primary", "fhe-timing"},
        {SerializeComparisonHeader(),
         SerializeComparisonRow(comparison, 4, comparison.provenance),
         "std128-t40-primary", "primary", "fhe-timing"},
        {SerializeCrossoverHeader(),
         SerializeCrossoverRow(crossover, crossover.onehot_provenance,
                               crossover.sqrt_provenance),
         "toy-smoke", "smoke", "diagnostic"},
        {SerializeSqrtComparisonHeader(),
         SerializeSqrtComparisonRow(sqrt, sqrt.provenance),
         "toy-smoke", "smoke", "diagnostic"},
    };

    for (const auto& csv : csvs) {
        const auto cells = CsvCells(csv.row);
        EXPECT_EQ(cells[ColumnIndex(csv.header, "profile_id")],
                  csv.expected_profile);
        EXPECT_EQ(cells[ColumnIndex(csv.header, "run_class")],
                  csv.expected_class);
        EXPECT_EQ(cells[ColumnIndex(csv.header, "measurement_kind")],
                  csv.expected_kind);
        EXPECT_EQ(cells[ColumnIndex(csv.header, "target_security_bits")],
                  csv.expected_profile == std::string("toy-smoke") ? "0" : "128");
        EXPECT_EQ(cells[ColumnIndex(csv.header, "comparison_eligible")],
                  csv.expected_profile == std::string("toy-smoke") ? "false" : "true");
    }
}

TEST(EstimatorProvenanceSerializers, LegacyRowsAreLabelledLegacy) {
    BenchmarkResult row;
    row.label = "legacy";
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = ApplicableMetadata();
    row.provenance = ApplicableProvenance();

    const std::string header = SerializeBenchmarkHeader();
    const auto cells = CsvCells(SerializeBenchmarkRow(row, row.provenance));
    EXPECT_EQ(cells[ColumnIndex(header, "profile_id")], "legacy");
    EXPECT_EQ(cells[ColumnIndex(header, "run_class")], "legacy");
    EXPECT_EQ(cells[ColumnIndex(header, "comparison_eligible")], "false");
    EXPECT_EQ(cells[ColumnIndex(header, "measurement_kind")], "diagnostic");
}
