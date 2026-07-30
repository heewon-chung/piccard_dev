#pragma once

#include "util/params.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
namespace noise_profile {

/** @brief One logical benchmark consumer in canonical (k,m) order. */
struct ConsumerPoint {
    uint32_t k;
    uint32_t m;

    bool operator==(const ConsumerPoint& other) const {
        return k == other.k && m == other.m;
    }
    bool operator<(const ConsumerPoint& other) const {
        return k < other.k || (k == other.k && m < other.m);
    }
};

/** @brief Canonical policy shared by every partition in one profile. */
struct ProfilePolicy {
    std::string profile_id;
    uint32_t transcript_stat_bits;
    uint64_t max_queries;
    uint32_t flood_margin_bits;
    uint32_t repetitions;
    uint32_t max_ring_growth;

    bool operator==(const ProfilePolicy& other) const {
        return profile_id == other.profile_id &&
               transcript_stat_bits == other.transcript_stat_bits &&
               max_queries == other.max_queries &&
               flood_margin_bits == other.flood_margin_bits &&
               repetitions == other.repetitions &&
               max_ring_growth == other.max_ring_growth;
    }
};

/** @brief One full eight-field logical calibration key and its consumers. */
struct ProfilePartition {
    std::string profile_id;
    Circuit circuit;
    std::string shape_id;
    std::string security;
    uint32_t requested_ring_dim;
    uint32_t natural_depth;
    std::string consumer_set_sha256;
    std::string openfhe_version;
    std::string key_id;
    std::vector<ConsumerPoint> consumer_points;
    uint32_t candidate_count_cap;

    bool operator==(const ProfilePartition& other) const {
        return profile_id == other.profile_id &&
               circuit == other.circuit &&
               shape_id == other.shape_id &&
               security == other.security &&
               requested_ring_dim == other.requested_ring_dim &&
               natural_depth == other.natural_depth &&
               consumer_set_sha256 == other.consumer_set_sha256 &&
               openfhe_version == other.openfhe_version &&
               key_id == other.key_id &&
               consumer_points == other.consumer_points &&
               candidate_count_cap == other.candidate_count_cap;
    }
};

inline constexpr std::array<uint32_t, 6> kKSweep = {
    16, 32, 64, 128, 256, 512};
inline constexpr std::array<uint32_t, 5> kOneHotMSweep = {
    16, 32, 64, 128, 256};
inline constexpr std::array<uint32_t, 4> kSqrtMSweep = {
    4, 16, 64, 256};
inline constexpr std::array<uint32_t, 5> kCrossoverK = {
    32, 64, 128, 256, 512};
inline constexpr std::array<uint32_t, 5> kCrossoverM = {
    4, 16, 64, 256, 1024};
inline constexpr std::array<ConsumerPoint, 6> kSqrtComparison = {{
    {128, 64},
    {256, 64},
    {512, 64},
    {1024, 64},
    {128, 256},
    {128, 1024},
}};
inline constexpr std::array<uint32_t, 7> kScalingModGrid = {
    40, 45, 50, 52, 54, 58, 60};
inline constexpr std::array<const char*, 3> kPatterns = {
    "all_match", "no_match", "random"};

/** @brief Returns the canonical deduplicated primary declarations. */
std::vector<ConsumerPoint> PrimaryConsumerDeclarations(Circuit circuit);

/** @brief Compiles declarations using production parameter derivation. */
std::vector<ProfilePartition> CompileMatrix(
    const std::string& openfhe_version,
    const std::string& source_commit);

/** @brief Emits the canonical manifest with exactly one trailing newline. */
std::string CanonicalManifestJson();

/** @brief Returns the exact profile policies in profile-id order. */
std::vector<ProfilePolicy> ProfilePolicies();

/** @brief Lowercase circuit spelling used by manifests and commands. */
const char* CircuitName(Circuit circuit);

}  // namespace noise_profile
}  // namespace piccard
