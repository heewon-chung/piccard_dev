#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>

namespace piccard::benchmark {

/** @brief Endpoint work unit selected by the named suite/profile policy. */
enum class EncodingWorkUnit {
    LegacyAOnly,
    VersionedPair,
};

/**
 * @brief Resolve the endpoint unit from the frozen profile/suite authority.
 *
 * This intentionally does not infer behavior from an encoder method token.
 * The correctness count is part of the versioned suite contract and remains
 * zero for every legacy Work 5 profile.
 */
inline EncodingWorkUnit ResolveEncodingWorkUnit(
    const std::string_view profile_id,
    const std::string_view suite,
    const uint32_t correctness_trials) {
    const bool legacy_profile =
        profile_id == "work5-std128-t40-single-trial" ||
        profile_id == "work5-std192-t40-single-trial";
    const bool versioned_profile =
        profile_id == "paper-std192-encoding-v1" ||
        profile_id == "readiness-toy-v1";
    const bool legacy_suite = suite == "work5-std128-piccard" ||
        suite == "work5-std128-piccard-m-extra" ||
        suite == "work5-std192-piccard" ||
        suite == "work5-std192-piccard-m-extra";
    const bool versioned_suite =
        suite == "paper-std192-encoding-v1" ||
        suite == "readiness-toy-v1" ||
        suite == "revision-std192-encoding-v1";
    if (legacy_profile && legacy_suite && correctness_trials == 0) {
        return EncodingWorkUnit::LegacyAOnly;
    }
    if (versioned_profile && versioned_suite && correctness_trials == 1) {
        return EncodingWorkUnit::VersionedPair;
    }
    throw std::invalid_argument("encoding work unit does not match frozen profile/suite policy");
}

/** @brief Results from one logical encoder work unit. */
template <typename Value>
struct EncodingEndpointResult {
    Value a;
    std::optional<Value> b;
};

/**
 * @brief Invoke the encoder for the exact endpoint work unit requested.
 *
 * The callback is intentionally supplied by the caller so tests can observe
 * actual encoder invocations without changing the producer artifact schema.
 * Legacy Work 5 invokes the A endpoint once; versioned encoding invokes A and
 * B once each.
 */
template <typename Signature, typename Encode>
auto EncodeEndpointWorkUnit(const EncodingWorkUnit work_unit,
                            const Signature& endpoint_a,
                            const Signature& endpoint_b,
                            Encode&& encode)
    -> EncodingEndpointResult<std::decay_t<decltype(encode(endpoint_a))>> {
    using Value = std::decay_t<decltype(encode(endpoint_a))>;
    auto&& encoder = encode;
    EncodingEndpointResult<Value> result{
        encoder(endpoint_a), std::nullopt};
    if (work_unit == EncodingWorkUnit::VersionedPair) {
        result.b.emplace(encoder(endpoint_b));
    }
    return result;
}

}  // namespace piccard::benchmark
