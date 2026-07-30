#pragma once

#include <cstdint>

namespace piccard {

/**
 * @brief Identifies a derived profile field for checked-add diagnostics.
 */
enum class SanitizerProfileField {
    QueryStatBits,
    CoefficientStatBits,
    FloodNoiseBits,
};

/**
 * @brief Source inputs and derived bit targets for phase smudging.
 */
struct SanitizerProfile {
    uint32_t transcript_stat_bits;
    uint64_t max_queries;
    uint64_t realized_ring_dim;
    uint32_t eval_noise_bits;
    uint32_t flood_margin_bits;

    uint32_t query_adjustment_bits;
    uint32_t coefficient_adjustment_bits;
    uint32_t query_stat_bits;
    uint32_t coefficient_stat_bits;
    uint32_t flood_noise_bits;
};

/**
 * @brief Computes ceil(log2(value)) using integer arithmetic.
 *
 * @param value Any positive integer.
 * @return Zero for one, otherwise the least number of bits needed to cover
 *         values through @p value.
 * @throws std::invalid_argument if @p value is zero.
 */
uint32_t CeilLog2(uint64_t value);

/**
 * @brief Adds two bit counts and reports which derived field overflowed.
 *
 * @throws std::overflow_error if the sum does not fit in uint32_t.
 */
uint32_t CheckedAddBits(
    uint32_t left,
    uint32_t right,
    SanitizerProfileField field);

/**
 * @brief Derives an overflow-safe transcript-aware sanitizer profile.
 *
 * @param transcript_stat_bits Supported targets are exactly 40, 64, and 128.
 * @param max_queries Inclusive range 1 through 2^63.
 * @param realized_ring_dim Positive power-of-two BFV ring dimension.
 * @param eval_noise_bits Calibrated evaluation-noise bound.
 * @param flood_margin_bits Empirical safety margin.
 * @throws std::invalid_argument for unsupported or malformed inputs.
 * @throws std::overflow_error if any derived bit count overflows uint32_t.
 */
SanitizerProfile DeriveSanitizerProfile(
    uint32_t transcript_stat_bits,
    uint64_t max_queries,
    uint64_t realized_ring_dim,
    uint32_t eval_noise_bits,
    uint32_t flood_margin_bits);

}  // namespace piccard
