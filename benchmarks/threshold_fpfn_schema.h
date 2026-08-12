#pragma once

#include <string>

namespace piccard {
namespace benchmark {

/** @brief Version identifier for the plaintext synthetic FP/FN CSV family. */
inline constexpr const char* kThresholdFpfnSchemaVersion =
    "piccard-threshold-fpfn-v1";

/** @brief Return the dedicated, versioned synthetic FP/FN CSV header. */
std::string ThresholdFpfnCSVHeader();

}  // namespace benchmark
}  // namespace piccard
