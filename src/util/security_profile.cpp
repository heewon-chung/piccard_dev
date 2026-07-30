#include "util/security_profile.h"

#include <limits>
#include <stdexcept>
#include <string>

namespace piccard {
namespace {

const char* FieldName(SanitizerProfileField field) {
    switch (field) {
        case SanitizerProfileField::QueryStatBits:
            return "query_stat_bits";
        case SanitizerProfileField::CoefficientStatBits:
            return "coefficient_stat_bits";
        case SanitizerProfileField::FloodNoiseBits:
            return "flood_noise_bits";
    }
    return "sanitizer_profile_field";
}

bool IsSupportedTranscriptTarget(uint32_t transcript_stat_bits) {
    return transcript_stat_bits == 40 ||
           transcript_stat_bits == 64 ||
           transcript_stat_bits == 128;
}

bool IsPowerOfTwo(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

}  // namespace

uint32_t CeilLog2(uint64_t value) {
    if (value == 0) {
        throw std::invalid_argument("CeilLog2 requires a positive integer");
    }

    uint32_t result = 0;
    --value;
    while (value != 0) {
        value >>= 1;
        ++result;
    }
    return result;
}

uint32_t CheckedAddBits(
    uint32_t left,
    uint32_t right,
    SanitizerProfileField field) {
    if (right > std::numeric_limits<uint32_t>::max() - left) {
        throw std::overflow_error(
            std::string("overflow deriving ") + FieldName(field));
    }
    return left + right;
}

SanitizerProfile DeriveSanitizerProfile(
    uint32_t transcript_stat_bits,
    uint64_t max_queries,
    uint64_t realized_ring_dim,
    uint32_t eval_noise_bits,
    uint32_t flood_margin_bits) {
    if (!IsSupportedTranscriptTarget(transcript_stat_bits)) {
        throw std::invalid_argument(
            "transcript_stat_bits must be exactly 40, 64, or 128");
    }

    constexpr uint64_t kMaxQueries = UINT64_C(1) << 63;
    if (max_queries == 0 || max_queries > kMaxQueries) {
        throw std::invalid_argument(
            "max_queries must be in the inclusive range 1..2^63");
    }

    if (!IsPowerOfTwo(realized_ring_dim)) {
        throw std::invalid_argument(
            "realized_ring_dim must be a positive power of two");
    }

    SanitizerProfile profile{};
    profile.transcript_stat_bits = transcript_stat_bits;
    profile.max_queries = max_queries;
    profile.realized_ring_dim = realized_ring_dim;
    profile.eval_noise_bits = eval_noise_bits;
    profile.flood_margin_bits = flood_margin_bits;

    profile.query_adjustment_bits = CeilLog2(max_queries);
    profile.coefficient_adjustment_bits = CeilLog2(realized_ring_dim);
    profile.query_stat_bits = CheckedAddBits(
        transcript_stat_bits,
        profile.query_adjustment_bits,
        SanitizerProfileField::QueryStatBits);
    profile.coefficient_stat_bits = CheckedAddBits(
        profile.query_stat_bits,
        profile.coefficient_adjustment_bits,
        SanitizerProfileField::CoefficientStatBits);

    const uint32_t eval_and_coefficient_bits = CheckedAddBits(
        eval_noise_bits,
        profile.coefficient_stat_bits,
        SanitizerProfileField::FloodNoiseBits);
    profile.flood_noise_bits = CheckedAddBits(
        eval_and_coefficient_bits,
        flood_margin_bits,
        SanitizerProfileField::FloodNoiseBits);

    return profile;
}

}  // namespace piccard
