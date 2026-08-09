#pragma once

#include "fhe/bfv_context.h"
#include "openfhe.h"

#include <cstdint>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace piccard {
namespace std_evidence {
namespace calibration {

// This helper intentionally exposes only the two core diagnostic circuits.
// The legacy bench_noise executable keeps its Threshold path separately.
enum class Pattern : uint8_t { AllMatch = 0, NoMatch = 1, Random = 2 };

const char* PatternName(Pattern pattern);

/** @brief Domain-separated deterministic seed for one calibration pattern. */
uint64_t DerivePatternSeed(uint64_t root_seed,
                           const std::string& circuit,
                           uint32_t realized_ring_dim,
                           uint32_t provisioned_depth,
                           uint32_t scaling_mod_size,
                           Pattern pattern);

/** @brief Makes synthetic signatures with the exact requested match regime. */
std::pair<std::vector<uint64_t>, std::vector<uint64_t>> MakeSignatures(
    Pattern pattern,
    uint32_t k,
    uint32_t m,
    std::mt19937_64& rng);

int64_t ExpectedMatches(const std::vector<uint64_t>& lhs,
                        const std::vector<uint64_t>& rhs,
                        uint32_t m);

/** @brief Exact centered decryption-phase noise in bits. */
double MeasureDecryptionPhaseNoise(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& secret_key,
    const lbcrypto::BigInteger& modulus_q,
    uint64_t plaintext_modulus);

struct ContextDescription {
    BFVRuntimeMetadata metadata;
    lbcrypto::BigInteger modulus_q;
    double log_delta_bits = 0.0;
};

/** @brief Reads the live context once for both calibration and evidence rows. */
ContextDescription DescribeContext(const BFVContext& context);

struct CalibrationBudget {
    uint32_t eval_noise_bits = 0;
    uint32_t query_stat_bits = 0;
    uint32_t coefficient_stat_bits = 0;
    uint32_t flood_margin_bits = 8;
    uint32_t flood_noise_bits = 0;
    uint32_t required_capacity_bits = 0;
    double log_q_over_t_bits = 0.0;
    bool saturated = false;
    bool fits = false;
};

/**
 * @brief Applies the frozen diagnostic transcript-40 capacity rule.
 *
 * The default values are deliberately the smoke limits: one 40-bit
 * transcript target, 2^20 maximum queries, and an eight-bit empirical margin.
 */
CalibrationBudget ComputeBudget(double worst_eval_noise_bits,
                                uint32_t realized_ring_dim,
                                double log_q_bits,
                                uint64_t plaintext_modulus,
                                uint32_t transcript_stat_bits = 40,
                                uint64_t max_queries = UINT64_C(1) << 20,
                                uint32_t flood_margin_bits = 8,
                                double log_delta_bits = 0.0);

}  // namespace calibration
}  // namespace std_evidence
}  // namespace piccard
