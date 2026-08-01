#pragma once

#include "util/params.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Evidence class fixed by a named benchmark profile. */
enum class BenchmarkRunClass {
    Primary,
    Sensitivity,
    Feasibility,
    Smoke,
    Legacy,
};

/** @brief Stable row-kind vocabulary for non-threshold evidence. */
enum class BenchmarkMeasurementKind {
    FheTiming,
    FheAccuracy,
    Diagnostic,
};

/** @brief Executable family whose native evidence grid is requested. */
enum class BenchmarkProducer {
    Piccard,
    OneHotSqrt,
    Dynamic,
    Comparison,
    Crossover,
    SqrtComparison,
};

/** @brief CLI mode after combined orchestration has been resolved. */
enum class BenchmarkMode { Timing, Accuracy, Combined };

/** @brief Immutable values selected by one exact profile identifier. */
struct BenchmarkProfile {
    std::string id;
    SecurityLevel security = SecurityLevel::STD128;
    uint32_t target_security_bits = 0;
    uint32_t transcript_stat_bits = 40;
    uint64_t max_queries = UINT64_C(1) << 20;
    uint32_t query_adjustment_bits = 20;
    BenchmarkRunClass run_class = BenchmarkRunClass::Legacy;
    bool failure_is_blocking = true;
    bool comparison_eligible = false;
};

/** @brief One literal row key in a benchmark suite grid. */
struct BenchmarkGridPoint {
    std::string axis;
    uint32_t k = 128;
    uint32_t m = 64;
    size_t set_size = 1000;
    uint32_t universe_size = 0;
    double target_jaccard = 0.5;

    /** @brief Return the canonical human-readable key used by golden tests. */
    std::string Key() const;
};

/** @brief Resolve one of the seven exact named profiles, or fail closed. */
const BenchmarkProfile& ResolveBenchmarkProfile(std::string_view profile_id);

/** @brief Explicit provenance used only by pre-profile legacy invocations. */
BenchmarkProfile LegacyBenchmarkProfile();

/** @brief Stable spelling for CSV provenance. */
const char* BenchmarkRunClassName(BenchmarkRunClass run_class);

/** @brief Stable spelling for typed measurement kinds. */
const char* BenchmarkMeasurementKindName(BenchmarkMeasurementKind kind);

/** @brief Parse a supported CLI mode into the typed representation. */
BenchmarkMode ParseBenchmarkMode(std::string_view mode);

/** @brief Expand combined orchestration into its two concrete row kinds. */
std::vector<BenchmarkMeasurementKind> MeasurementKindsForMode(
    BenchmarkMode mode);

/**
 * @brief Resolve either a native suite grid or exactly one evidence point.
 *
 * Sensitivity and feasibility profiles require evidence_point=true. Diagnostic
 * producers retain their pinned grids and reject legacy/unprofiled runs.
 */
std::vector<BenchmarkGridPoint> ResolveBenchmarkGrid(
    const BenchmarkProfile& profile,
    BenchmarkProducer producer,
    BenchmarkMode mode,
    bool evidence_point,
    const BenchmarkGridPoint& supplied);

}  // namespace benchmark
}  // namespace piccard
