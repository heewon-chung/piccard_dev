#include "threshold_csv_schema.h"

#include <gtest/gtest.h>

#include <cmath>
#include <sstream>
#include <string>
#include <vector>

using piccard::benchmark::ThresholdCSVHeader;
using piccard::benchmark::ThresholdSpecCSVHeader;
using piccard::benchmark::ThresholdSpecRow;
using piccard::benchmark::WriteThresholdSpecRow;
using piccard::benchmark::ParseThresholdLimbBits;
using piccard::benchmark::SerializeThresholdLimbBits;
using piccard::benchmark::kThresholdFloodingAssuranceLegacyCoefficientLevel;

namespace {

TEST(ThresholdSpecProvenanceContract, LegacyHeaderRemainsByteStable) {
    const std::string expected =
        "label,k,m,set_size,ring_dim,tau,mult_depth,"
        "phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,"
        "phase_multiply_ms,phase_rotate_sum_ms,phase_mask_ms,"
        "phase_poly_eval_ms,phase_decrypt_ms,total_ms,"
        "memory_bytes,ct_size_bytes,"
        "threshold_result,threshold_expected,threshold_correct,"
        "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
        "note,trials,total_ms_sd,total_ms_median,"
        "phase_minhash_ms_sd,phase_minhash_ms_median,"
        "phase_encode_ms_sd,phase_encode_ms_median,"
        "phase_encrypt_ms_sd,phase_encrypt_ms_median,"
        "phase_multiply_ms_sd,phase_multiply_ms_median,"
        "phase_rotate_sum_ms_sd,phase_rotate_sum_ms_median,"
        "phase_mask_ms_sd,phase_mask_ms_median,"
        "phase_poly_eval_ms_sd,phase_poly_eval_ms_median,"
        "phase_decrypt_ms_sd,phase_decrypt_ms_median,"
        "rel_error_eligible_n,"
        "j_tau,match_count,matchcount_expected,fhe_agrees,outcome,"
        "hash_randomness,hash_seed,hash_root_seed,accuracy_trials,"
        "phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
        "flood_lambda_stat,flood_eval_noise_bits,flood_margin_bits,"
        "flood_noise_bits,scaling_mod_size\n";
    EXPECT_EQ(ThresholdCSVHeader(), expected);
}

TEST(ThresholdSpecProvenanceContract, SuccessRowCarriesCompleteV2Metadata) {
    const std::string header = ThresholdSpecCSVHeader();
    for (const std::string& field : {
             "schema_version", "requested_ring_dim", "natural_ring_dim",
             "provisioned_ring_dim", "realized_ring_dim", "natural_depth",
             "provisioned_depth", "log_q_bits", "log2_q_over_t_bits",
             "plaintext_modulus", "num_limbs", "ordered_rns_moduli",
             "ordered_rns_limb_bits", "ordered_rns_limb_bits_sum",
             "scaling_mod_size", "openfhe_version", "flooding_assurance",
             "transcript_stat_bits", "max_queries", "query_stat_bits",
             "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
             "flood_noise_bits", "required_capacity_bits",
             "residual_capacity_definition", "residual_capacity_bits",
             "residual_capacity_status"}) {
        EXPECT_NE(header.find(field), std::string::npos) << field;
    }

    ThresholdSpecRow row;
    row.k = 64;
    row.tau = 38;
    row.degree = 64;
    row.ps_baby_s = 9;
    row.ps_num_chunks = 8;
    row.baby_depth = 4;
    row.giant_mults = 7;
    row.natural_mult_depth = 12;
    row.mult_depth = 14;
    row.scaling_mod_size = 40;
    row.ring_dim = 1024;
    row.plaintext_mod = 65537;
    row.log2_q = 200.0;
    row.eval_noise_bits = 331;
    row.flood_noise_bits = 403;
    row.ct_bytes = 123;
    row.poly_build_ms = 1.0;
    row.status = "ok";
    row.requested_ring_dim = 1024;
    row.natural_ring_dim = 1024;
    row.provisioned_ring_dim = 1024;
    row.realized_ring_dim = 1024;
    row.natural_depth = 12;
    row.provisioned_depth = 14;
    row.log_q_bits = 200.0;
    row.plaintext_modulus = 65537;
    row.log2_q_over_t_bits =
        row.log_q_bits - std::log2(static_cast<double>(row.plaintext_modulus));
    row.num_limbs = 5;
    row.realized_scaling_mod_size = 40;
    row.ordered_rns_moduli = {
        "1099511627775", "1099511627775", "1099511627775",
        "1099511627775", "1099511627775"};
    row.ordered_rns_limb_bits = {40, 40, 40, 40, 40};
    row.openfhe_version = "1.5.0";
    row.flooding_assurance = kThresholdFloodingAssuranceLegacyCoefficientLevel;
    row.transcript_stat_bits = 40;
    row.max_queries = UINT64_C(1) << 20;
    row.query_stat_bits = 0;
    row.coefficient_stat_bits = 64;
    row.flood_margin_bits = 8;
    row.required_capacity_bits = 405;
    row.residual_capacity_definition =
        "log2(q/t)-required_flood_budget_bits";
    row.residual_capacity_status = "not-exposed-by-openfhe";

    std::ostringstream out;
    EXPECT_NO_THROW(WriteThresholdSpecRow(out, row));
    const std::string encoded = out.str();
    EXPECT_NE(encoded.find("piccard-threshold-spec-v2"), std::string::npos);
    EXPECT_NE(encoded.find("1099511627775;1099511627775"), std::string::npos);
    EXPECT_NE(encoded.find("legacy-coefficient-level"), std::string::npos);
    EXPECT_NE(encoded.find(",0,64,"), std::string::npos);
    EXPECT_NE(encoded.find("log2(q/t)-required_flood_budget_bits"),
              std::string::npos);
    EXPECT_NE(encoded.find("not-exposed-by-openfhe"), std::string::npos);
    EXPECT_EQ(row.OrderedRnsLimbBitsSum(), 200u);
    EXPECT_EQ(ParseThresholdLimbBits(
                  SerializeThresholdLimbBits(row.ordered_rns_limb_bits)),
              row.ordered_rns_limb_bits);
    EXPECT_TRUE(ParseThresholdLimbBits("40;+40").empty());
}

TEST(ThresholdSpecProvenanceContract,
     RejectsNonLegacyQueryStatsLimbMismatchesAndResidualValues) {
    ThresholdSpecRow row;
    row.status = "ok";
    row.requested_ring_dim = 1024;
    row.natural_ring_dim = 1024;
    row.provisioned_ring_dim = 1024;
    row.realized_ring_dim = 1024;
    row.natural_depth = 1;
    row.provisioned_depth = 1;
    row.log_q_bits = 200.0;
    row.log2_q_over_t_bits = 184.0;
    row.plaintext_modulus = 65537;
    row.num_limbs = 5;
    row.ordered_rns_moduli = {
        "1099511627775", "1099511627775", "1099511627775",
        "1099511627775", "1099511627775"};
    row.ordered_rns_limb_bits = {40, 40, 40, 40, 40};
    row.openfhe_version = "1.5.0";
    row.coefficient_stat_bits = 64;
    row.required_capacity_bits = 1;

    row.flooding_assurance = "transcript-aware";
    EXPECT_THROW({
        std::ostringstream out;
        WriteThresholdSpecRow(out, row);
    }, std::invalid_argument);

    row.flooding_assurance = kThresholdFloodingAssuranceLegacyCoefficientLevel;
    row.query_stat_bits = 1;
    EXPECT_THROW({
        std::ostringstream out;
        WriteThresholdSpecRow(out, row);
    }, std::invalid_argument);

    row.query_stat_bits = 0;
    row.ordered_rns_limb_bits[0] = 39;
    EXPECT_THROW({
        std::ostringstream out;
        WriteThresholdSpecRow(out, row);
    }, std::invalid_argument);

    row.ordered_rns_limb_bits[0] = 40;
    row.ordered_rns_moduli[0] = "0109511627775";
    EXPECT_THROW({
        std::ostringstream out;
        WriteThresholdSpecRow(out, row);
    }, std::invalid_argument);

    row.ordered_rns_moduli[0] = "1099511627775";
    row.residual_capacity_bits = 3.0;
    EXPECT_THROW({
        std::ostringstream out;
        WriteThresholdSpecRow(out, row);
    }, std::invalid_argument);

    row.residual_capacity_bits.reset();
    row.status = "ERROR";
    EXPECT_THROW({
        std::ostringstream out;
        WriteThresholdSpecRow(out, row);
    }, std::invalid_argument);
}

TEST(ThresholdSpecProvenanceContract,
     SkippedRowsSerializeOnlyExplicitNotApplicableTokens) {
    ThresholdSpecRow row;
    row.status = "SKIPPED";
    row.note = "no live context";
    std::ostringstream out;
    EXPECT_NO_THROW(WriteThresholdSpecRow(out, row));
    const std::string encoded = out.str();
    EXPECT_NE(encoded.find(",SKIPPED,no live context,"), std::string::npos);
    EXPECT_NE(encoded.find(",N/A,N/A,N/A,N/A,N/A,N/A,"), std::string::npos);
    EXPECT_EQ(encoded.find("legacy-coefficient-level"), std::string::npos);
    EXPECT_EQ(encoded.find("not-exposed-by-openfhe"), std::string::npos);
}

TEST(ThresholdSpecProvenanceContract, SkippedRowsRejectFabricatedContext) {
    ThresholdSpecRow row;
    row.status = "SKIPPED";
    row.realized_ring_dim = 1024;
    EXPECT_THROW({
        std::ostringstream out;
        WriteThresholdSpecRow(out, row);
    }, std::invalid_argument);
}

}  // namespace
