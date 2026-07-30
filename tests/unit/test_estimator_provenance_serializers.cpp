#include "benchmark_estimator_provenance.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

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
        "flood_lambda_stat,flood_eval_noise_bits,flood_margin_bits,"
        "flood_noise_bits,scaling_mod_size,estimator_model\n";
    const std::string expected_row =
        "piccard,128,64,1000,8192,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,"
        "0.000000,0.000000,onehot,1,1,0,0.000,0.000,0.000,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,0,0,0,0,0,sha256-random-ranking-poc-v1\n";

    ExpectGoldenCsv(SerializeBenchmarkHeader(), SerializeBenchmarkRow(row),
                    expected_header, expected_row);
    EXPECT_NE(SerializeBenchmarkRow(row).find(kEstimator), std::string::npos);
}

TEST(EstimatorProvenanceSerializers, OneHotAndSqrtGoldenRows) {
    BenchmarkResult onehot;
    onehot.label = "onehot";
    onehot.encoding = "onehot";
    onehot.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;

    BenchmarkResult sqrt;
    sqrt.label = "sqrt";
    sqrt.encoding = "sqrt";
    sqrt.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;

    const std::string expected_onehot =
        "onehot,0,0,0,0,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,"
        "0.000000,0.000000,onehot,0,0,0,0.000,0.000,0.000,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,0,0,0,0,0,sha256-random-ranking-poc-v1\n";
    const std::string expected_sqrt =
        "sqrt,0,0,0,0,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,0.000000,"
        "0.000000,0.000000,sqrt,0,0,0,0.000,0.000,0.000,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,0,0,0,0,0,sha256-random-ranking-poc-v1\n";

    EXPECT_EQ(SerializeBenchmarkRow(onehot), expected_onehot);
    EXPECT_EQ(SerializeBenchmarkRow(sqrt), expected_sqrt);
    EXPECT_EQ(CsvColumns(SerializeBenchmarkHeader()), CsvColumns(expected_onehot));
    EXPECT_EQ(CsvColumns(SerializeBenchmarkHeader()), CsvColumns(expected_sqrt));
}

TEST(EstimatorProvenanceSerializers, DynamicGoldenSchema) {
    DynamicResult row;
    row.label = "dynamic";
    row.k = 128;
    row.m = 64;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;

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
        "phase_flood_ms_median,flood_lambda_stat,flood_eval_noise_bits,"
        "flood_margin_bits,flood_noise_bits,scaling_mod_size,estimator_model\n";
    const std::string expected_row =
        "dynamic,128,64,0,0,0,"
        "0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0.000,0,0,"
        "0.000000,0.000000,0.000000,0.000000,0.0,0.0,0,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
        "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,0,,0,0,0,"
        "0.000,-1.000,0.000,0,0,0,0,0,sha256-random-ranking-poc-v1\n";

    ExpectGoldenCsv(SerializeDynamicHeader(), SerializeDynamicRow(row),
                    expected_header, expected_row);
}

TEST(EstimatorProvenanceSerializers, ComparisonClassifiesConcreteModes) {
    const std::string expected_header =
        "scenario,method,security_class,universe_size,set_size,k,m,ring_dim,"
        "num_cts,mult_depth,phase_encode_ms,phase_encrypt_ms,phase_compute_ms,"
        "phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,comm_bytes,"
        "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
        "trials,total_ms_sd,total_ms_median,phase_encode_ms_sd,"
        "phase_encode_ms_median,phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_compute_ms_sd,phase_compute_ms_median,phase_decrypt_ms_sd,"
        "phase_decrypt_ms_median,rel_error_eligible_n,model,hash_randomness,"
        "hash_seed,hash_root_seed,accuracy_trials,phase_flood_ms,"
        "phase_flood_ms_sd,phase_flood_ms_median,flood_lambda_stat,"
        "flood_eval_noise_bits,flood_margin_bits,flood_noise_bits,"
        "scaling_mod_size,measurement_kind,extrapolation_alpha,"
        "extrapolation_beta,extrapolation_residual,extrapolation_source,"
        "omp_threads,estimator_model\n";

    struct Case {
        const char* method;
        EstimatorModel model;
        const char* security_class;
        const char* protocol_model;
        const char* expected_estimator;
    };
    const Case cases[] = {
        {"piccard", EstimatorModel::Sha256RandomRankingPocV1,
         "CPA/no-leakage", "3-party-outsourced", kEstimator},
        {"piccard_sqrt", EstimatorModel::Sha256RandomRankingPocV1,
         "CPA/no-leakage", "3-party-outsourced", kEstimator},
        {"baseline", EstimatorModel::NotApplicable,
         "KPA/leakage", "3-party-outsourced", kNotApplicable},
        {"bcg12_mh_ff", EstimatorModel::Sha256RandomRankingPocV1,
         "AHE/no-leakage", "2-party", kEstimator},
        {"bcg12_exact_ec", EstimatorModel::NotApplicable,
         "AHE/no-leakage", "2-party", kNotApplicable},
        {"sj16", EstimatorModel::NotApplicable,
         "AHE/no-leakage", "2-party", kNotApplicable},
    };

    for (const auto& c : cases) {
        ComparisonResult row;
        row.scenario = "golden";
        row.method = c.method;
        row.estimator_model = c.model;

        const std::string expected_row =
            std::string("golden,") + c.method + "," + c.security_class +
            ",0,0,0,0,0,0,0,"
            "0.000,0.000,0.000,0.000,0.000,0,0,0,"
            "0.000000,0.000000,0.000000,0.000000,0,"
            "-1.000,0.000,-1.000,0.000,-1.000,0.000,-1.000,0.000,"
            "-1.000,0.000,0," +
            c.protocol_model +
            ",,0,0,0,0.000,-1.000,0.000,0,0,0,0,0,"
            "measured,,,,,4," + c.expected_estimator + "\n";

        ExpectGoldenCsv(SerializeComparisonHeader(),
                        SerializeComparisonRow(row, 4),
                        expected_header, expected_row);
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

    const std::string expected_header =
        "k,m,onehot_feature_dim,sqrt_feature_dim,onehot_ring_dim,sqrt_ring_dim,"
        "onehot_total_ms,sqrt_total_ms,sqrt_faster,speedup_ratio,"
        "estimator_model\n";
    const std::string expected_row =
        "128,64,0,0,0,0,12.500,8.250,1,1.5152,"
        "sha256-random-ranking-poc-v1\n";

    ExpectGoldenCsv(SerializeCrossoverHeader(), SerializeCrossoverRow(row),
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
    onehot.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;

    SqrtComparisonResult sqrt = onehot;
    sqrt.encoding = "Sqrt";
    sqrt.mult_depth = 3;

    const std::string expected_header =
        "encoding,k,m,N,Depth,Encode,Encrypt,Evaluate,Decrypt,Total(ms),"
        "|err|,rel_err,estimator_model\n";
    const std::string expected_onehot =
        "OneHot,128,64,8192,1,0.00,0.00,0.00,0.00,0.00"
        "\xC2\xB1" "0.00,0.0000" "\xC2\xB1" "0.0000,N/A,"
        "sha256-random-ranking-poc-v1\n";
    const std::string expected_sqrt =
        "Sqrt,128,64,8192,3,0.00,0.00,0.00,0.00,0.00"
        "\xC2\xB1" "0.00,0.0000" "\xC2\xB1" "0.0000,N/A,"
        "sha256-random-ranking-poc-v1\n";

    EXPECT_EQ(SerializeSqrtComparisonHeader(), expected_header);
    EXPECT_EQ(SerializeSqrtComparisonRow(onehot), expected_onehot);
    EXPECT_EQ(SerializeSqrtComparisonRow(sqrt), expected_sqrt);
    EXPECT_EQ(CsvColumns(expected_header), CsvColumns(expected_onehot));
    EXPECT_EQ(CsvColumns(expected_header), CsvColumns(expected_sqrt));
}
