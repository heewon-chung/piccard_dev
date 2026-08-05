#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace piccard::data {

// Exact-Jaccard index over two sorted-unique feature-ID vectors:
// |intersection| / |union|. Inputs must already be sorted ascending with no
// duplicates; this function does not re-sort or de-duplicate them. Returns
// 0.0 when the union is empty (both inputs empty).
double ExactJaccard(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b);

// Formats a finite double as a C-locale decimal/scientific string with 17
// significant digits, byte-identical to format_float() in
// scripts/prepare_real_datasets.py. Negative zero is normalized to "0".
// Throws std::invalid_argument if x is not finite.
std::string FormatReal17(double x);

// Buckets a bucketed exact Jaccard value into the fixed reporting ranges:
// [0, 0.1) -> "b00_10", [0.1, 0.3) -> "b10_30", [0.3, 0.6) -> "b30_60",
// [0.6, 1] -> "b60_100" (the upper endpoint 1 belongs to the last bucket).
// The returned pointer refers to a static string literal.
const char* JaccardBucketLabel(double bucketed_exact_jaccard);

// Summary statistics over a set of finite absolute errors.
//
// n == 0: mae/sample_sd/median/p95/max/ci95_low/ci95_high all hold the 0.0
//   placeholder. Serializers must treat every statistic cell as empty for
//   n == 0 by checking `n`, not these placeholder values.
// n == 1: mae/median/p95/max equal the sole value; sample_sd/ci95_low/
//   ci95_high hold the 0.0 placeholder. Serializers must treat sample_sd
//   and both CI cells as empty for n == 1 by checking `n`.
// n >= 2: every field holds its computed statistic.
struct SummaryStats {
    size_t n = 0;
    double mae = 0.0;
    double sample_sd = 0.0;
    double median = 0.0;
    double p95 = 0.0;
    double max = 0.0;
    double ci95_low = 0.0;
    double ci95_high = 0.0;
};

// Computes SummaryStats over `abs_errors` (already-finite absolute errors;
// sorts a local copy, does not filter non-finite values).
//   median: the center value for odd n, the arithmetic mean of the two
//     center values for even n.
//   p95: nearest-rank sorted[ceil(0.95*n)-1].
//   sample_sd: sample standard deviation, denominator n-1.
//   ci95_{low,high}: mean +/- 1.96*sample_sd/sqrt(n), unclipped.
SummaryStats Summarize(std::vector<double> abs_errors);

}  // namespace piccard::data
