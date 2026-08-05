#include "data/real_dataset_metrics.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <stdexcept>

namespace piccard::data {

double ExactJaccard(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    size_t i = 0, j = 0;
    size_t intersection_size = 0;
    size_t union_size = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] == b[j]) {
            ++intersection_size;
            ++union_size;
            ++i;
            ++j;
        } else if (a[i] < b[j]) {
            ++union_size;
            ++i;
        } else {
            ++union_size;
            ++j;
        }
    }
    union_size += (a.size() - i) + (b.size() - j);
    if (union_size == 0) {
        return 0.0;
    }
    return static_cast<double>(intersection_size) / static_cast<double>(union_size);
}

std::string FormatReal17(double x) {
    if (!std::isfinite(x)) {
        throw std::invalid_argument("FormatReal17: value must be finite");
    }
    if (x == 0.0) {
        x = 0.0;  // normalizes -0.0 to +0.0 before formatting
    }
    char buffer[64];
    const int written = std::snprintf(buffer, sizeof(buffer), "%.17g", x);
    if (written < 0 || static_cast<size_t>(written) >= sizeof(buffer)) {
        throw std::runtime_error("FormatReal17: formatting failed");
    }
    return std::string(buffer, static_cast<size_t>(written));
}

const char* JaccardBucketLabel(double bucketed_exact_jaccard) {
    if (bucketed_exact_jaccard < 0.1) return "b00_10";
    if (bucketed_exact_jaccard < 0.3) return "b10_30";
    if (bucketed_exact_jaccard < 0.6) return "b30_60";
    return "b60_100";
}

SummaryStats Summarize(std::vector<double> abs_errors) {
    SummaryStats stats;
    stats.n = abs_errors.size();
    if (stats.n == 0) {
        return stats;
    }
    std::sort(abs_errors.begin(), abs_errors.end());

    double sum = 0.0;
    for (double v : abs_errors) sum += v;
    const double mean = sum / static_cast<double>(stats.n);
    stats.mae = mean;
    stats.max = abs_errors.back();

    const size_t mid = stats.n / 2;
    if (stats.n % 2 == 1) {
        stats.median = abs_errors[mid];
    } else {
        stats.median = (abs_errors[mid - 1] + abs_errors[mid]) / 2.0;
    }

    const size_t p95_index =
        static_cast<size_t>(std::ceil(0.95 * static_cast<double>(stats.n))) - 1;
    stats.p95 = abs_errors[p95_index];

    if (stats.n == 1) {
        return stats;  // sample_sd/ci95_low/ci95_high stay at the 0.0 placeholder
    }

    double squared_diff_sum = 0.0;
    for (double v : abs_errors) {
        const double diff = v - mean;
        squared_diff_sum += diff * diff;
    }
    stats.sample_sd = std::sqrt(squared_diff_sum / static_cast<double>(stats.n - 1));
    const double margin = 1.96 * stats.sample_sd / std::sqrt(static_cast<double>(stats.n));
    stats.ci95_low = mean - margin;
    stats.ci95_high = mean + margin;

    return stats;
}

}  // namespace piccard::data
