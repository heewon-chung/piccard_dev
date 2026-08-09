#pragma once

#include <string>

namespace piccard {
namespace benchmark {

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

}  // namespace benchmark
}  // namespace piccard
