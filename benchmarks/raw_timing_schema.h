#pragma once

/**
 * @file raw_timing_schema.h
 * @brief Versioned, independently verifiable paper timing artifacts.
 *
 * Work 5 CSV serializers are intentionally not routed through this API.  A
 * paper-v1 producer records its raw calls here and publishes this sidecar in
 * addition to its legacy/summary output.  The sidecar is deliberately small,
 * deterministic TSV so an independent verifier can recompute every aggregate
 * without knowing how a benchmark was executed.
 */

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace piccard::benchmark {

inline constexpr const char* kPaperRawTimingSchemaVersion =
    "piccard-paper-raw-timing-v1";
inline constexpr const char* kPaperTimingProfileVersion = "paper-v1";
inline constexpr const char* kReadinessTimingProfileVersion =
    "readiness-toy-v1";
inline constexpr const char* kTimingFloatFormatVersion = "17-digit";
inline constexpr const char* kTimingNotApplicable = "NOT_APPLICABLE";

/** @brief Whether a producer discards one first-touch call. */
enum class WarmupPolicy {
    None,
    DiscardOne,
};

/** @brief The two legal kinds of a raw timing record. */
enum class SampleKind {
    DiscardedWarmup,
    Measured,
};

/** @brief One raw timing value; no summary is stored in this record. */
struct RawTimingSample {
    std::string producer_id;
    std::string profile_id;
    std::string cell_id;
    std::string phase;
    SampleKind sample_kind = SampleKind::Measured;
    uint64_t trial_index = 0;
    uint64_t seed = 0;
    double raw_ms = 0.0;
};

/** @brief Independently recomputed statistics for one phase. */
struct TimingAggregateV1 {
    std::string producer_id;
    std::string profile_id;
    std::string cell_id;
    std::string phase;
    uint64_t measured_count = 0;
    double mean_ms = 0.0;
    std::optional<double> sample_sd_ms;
    double median_ms = 0.0;
    std::optional<double> ci95_low_ms;
    std::optional<double> ci95_high_ms;
    std::string format_version = kTimingFloatFormatVersion;
};

/** @brief A complete raw sidecar for one producer cell. */
struct RawTimingArtifact {
    std::string producer_id;
    std::string profile_id;
    std::string cell_id;
    WarmupPolicy warmup_policy = WarmupPolicy::None;
    uint64_t expected_measured = 0;
    std::vector<RawTimingSample> samples;
    // Producers may leave this empty; serialization derives it.  A populated
    // vector is checked against a fresh recomputation to make mutations fail
    // closed during parsing and independent verification.
    std::vector<TimingAggregateV1> aggregates;
};

/** @brief Versioned producer contract used by paper/readiness runners. */
struct PaperTimingProducerContract {
    std::string producer_id;
    uint64_t paper_measured_trials = 30;
    uint64_t toy_measured_trials = 1;
    WarmupPolicy warmup_policy = WarmupPolicy::DiscardOne;
    std::string timing_contract = "RAW_MEASURED_V1";
};

/** @brief Stable names for all timing producers in the paper matrix. */
const std::vector<PaperTimingProducerContract>&
PaperTimingProducerContracts();

/** @brief Return the producer's frozen timing contract or NOT_APPLICABLE. */
std::string TimingContractFor(const std::string& producer_id);

/** @brief Return the exact count required by a profile. */
uint64_t ExpectedTimingTrials(const std::string& profile_id);

/** @brief Return the frozen warmup policy for a producer. */
WarmupPolicy ExpectedWarmupPolicy(const std::string& producer_id);

/**
 * @brief Recompute a phase aggregate from measured records only.
 *
 * The implementation uses sample SD (N-1) and the two-sided Student-t 95%
 * interval.  For N=1, SD and both CI endpoints are intentionally absent.
 */
TimingAggregateV1 ComputeTimingAggregateV1(
    const std::string& producer_id,
    const std::string& profile_id,
    const std::string& cell_id,
    const std::string& phase,
    const std::vector<RawTimingSample>& samples);

/** @brief Reject malformed/mutated rows, count, warmup, index, or summaries. */
void ValidateRawTimingArtifact(const RawTimingArtifact& artifact);

/** @brief Serialize a canonical versioned TSV sidecar. */
std::string SerializeRawTimingArtifactV1(const RawTimingArtifact& artifact);

/**
 * @brief Parse and independently validate a canonical versioned TSV sidecar.
 *
 * Parsing is strict: unknown sections/columns, duplicate aggregate phases,
 * changed raw values, warmup/index mutations, and aggregate mismatches throw
 * std::invalid_argument.
 */
RawTimingArtifact ParseRawTimingArtifactV1(const std::string& serialized);

/** @brief Atomically publish one canonical raw sidecar at an explicit path. */
void WriteRawTimingArtifactV1(const std::string& path,
                              const RawTimingArtifact& artifact);

/**
 * @brief Publish one sidecar per artifact below an output directory.
 *
 * File names are derived from producer/cell/phase metadata and are stable
 * across reruns; existing files are rejected to prevent repair-in-place.
 */
void WriteRawTimingArtifactsV1(const std::string& output_directory,
                               const std::vector<RawTimingArtifact>& artifacts);

/** @brief Stable text spellings used by the canonical serializer. */
const char* WarmupPolicyName(WarmupPolicy policy);
const char* SampleKindName(SampleKind kind);

}  // namespace piccard::benchmark
