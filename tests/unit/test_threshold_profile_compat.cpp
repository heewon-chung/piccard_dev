#include "threshold_csv_schema.h"
#include "util/params.h"

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

using piccard::PiccardParams;
using piccard::SecurityLevel;
using piccard::benchmark::ThresholdCSVHeader;

TEST(ThresholdProfileCompat, ToyGoldenRemainsPrivateCoefficientLevel) {
    PiccardParams params;
    params.k = 64;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.threshold_mode = true;
    params.threshold_tau = 32;

    params.Validate();

    EXPECT_EQ(params.LegacyFloodCoefficientBits(), 64u);
    EXPECT_EQ(params.RequestedRingDim(), 1024u);
    EXPECT_EQ(params.ring_dim_natural, 1024u);
    EXPECT_EQ(params.natural_mult_depth, 12u);
    EXPECT_EQ(params.mult_depth, 14u);
    EXPECT_EQ(params.scaling_mod_size, 40u);
    EXPECT_EQ(params.eval_noise_bits, 331u);
    EXPECT_EQ(params.FloodNoiseBits(), 403u);
    EXPECT_EQ(params.QueryStatBits(), 0u);
}

TEST(ThresholdProfileCompat, HeaderBytesRemainLegacyCompatible) {
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
    EXPECT_EQ(ThresholdCSVHeader().find("transcript_stat_bits"),
              std::string::npos);
    EXPECT_EQ(ThresholdCSVHeader().find("sanitizer_assurance"),
              std::string::npos);
}

TEST(ThresholdProfileCompat, Std128MissingCalibrationFailsClosed) {
    PiccardParams params;
    params.k = 256;
    params.m = 64;
    params.security = SecurityLevel::STD128;
    params.threshold_mode = true;
    params.threshold_tau = 128;

    try {
        params.Validate();
        FAIL() << "threshold profile unexpectedly selected a context";
    } catch (const std::invalid_argument& error) {
        EXPECT_EQ(params.ring_dim, 16384u);
        EXPECT_EQ(params.natural_mult_depth, 21u);
        EXPECT_NE(std::string(error.what()).find(
                      "missing threshold legacy calibration"),
                  std::string::npos);
    }
}
