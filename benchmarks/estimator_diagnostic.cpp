#include "estimator_diagnostic.h"

#include "core/minhash.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <iomanip>
#include <limits>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace piccard {
namespace benchmark {

namespace {

constexpr std::string_view kTrialSeedDomain =
    "piccard-estimator-trial-v1";
constexpr double kBiasFloor = 0.01;

uint64_t ParseUint64(const std::string& text, const char* field_name) {
    uint64_t value = 0;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto result = std::from_chars(begin, end, value);
    if (text.empty() || result.ec != std::errc() || result.ptr != end) {
        throw std::invalid_argument(std::string(field_name) +
                                    " must be an unsigned integer");
    }
    return value;
}

void StoreUint64Be(uint64_t value, unsigned char* output) {
    for (int byte = 7; byte >= 0; --byte) {
        output[7 - byte] =
            static_cast<unsigned char>(value >>
                                       (static_cast<unsigned>(byte) * 8));
    }
}

void StoreUint32Be(uint32_t value, unsigned char* output) {
    for (int byte = 3; byte >= 0; --byte) {
        output[3 - byte] =
            static_cast<unsigned char>(value >>
                                       (static_cast<unsigned>(byte) * 8));
    }
}

EstimateStatistics Aggregate(const std::vector<double>& estimates,
                             double realized_jaccard) {
    if (estimates.empty()) {
        throw std::invalid_argument("at least one estimate is required");
    }

    long double sum = 0.0L;
    long double absolute_error_sum = 0.0L;
    for (const double estimate : estimates) {
        if (!std::isfinite(estimate) || estimate < 0.0 || estimate > 1.0) {
            throw std::runtime_error(
                "estimator produced a non-finite or out-of-range value");
        }
        sum += estimate;
        absolute_error_sum += std::fabs(estimate - realized_jaccard);
    }

    EstimateStatistics statistics;
    const long double count = static_cast<long double>(estimates.size());
    statistics.mean = static_cast<double>(sum / count);
    statistics.bias = statistics.mean - realized_jaccard;
    statistics.mae = static_cast<double>(absolute_error_sum / count);

    if (estimates.size() > 1) {
        long double squared_deviation_sum = 0.0L;
        for (const double estimate : estimates) {
            const long double deviation =
                static_cast<long double>(estimate) - statistics.mean;
            squared_deviation_sum += deviation * deviation;
        }
        const long double sample_variance =
            squared_deviation_sum /
            static_cast<long double>(estimates.size() - 1);
        statistics.sample_sd =
            std::sqrt(static_cast<double>(sample_variance));
        statistics.standard_error =
            *statistics.sample_sd / std::sqrt(static_cast<double>(estimates.size()));
    }
    return statistics;
}

void AppendOptional(std::ostringstream& output,
                    const std::optional<double>& value) {
    if (value.has_value()) {
        if (!std::isfinite(*value)) {
            throw std::runtime_error(
                "cannot serialize a non-finite diagnostic statistic");
        }
        output << *value;
    }
}

void RequireFinite(double value) {
    if (!std::isfinite(value)) {
        throw std::runtime_error(
            "cannot serialize a non-finite diagnostic statistic");
    }
}

std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
ComputePairSignatures(const MinHasher& hasher,
                      uint32_t k,
                      uint64_t set_size,
                      uint64_t intersection_size) {
    std::vector<uint64_t> signature_a(
        k, std::numeric_limits<uint64_t>::max());
    std::vector<uint64_t> signature_b(
        k, std::numeric_limits<uint64_t>::max());

    const auto update_minima = [k](std::vector<uint64_t>& signature,
                                   const std::vector<uint64_t>& hashes) {
        for (uint32_t coordinate = 0; coordinate < k; ++coordinate) {
            signature[coordinate] =
                std::min(signature[coordinate], hashes[coordinate]);
        }
    };

    for (uint64_t element = 0; element < set_size; ++element) {
        const std::vector<uint64_t> hashes =
            hasher.ComputeElementHashes(element);
        update_minima(signature_a, hashes);
        if (element < intersection_size) {
            update_minima(signature_b, hashes);
        }
    }
    for (uint64_t offset = 0; offset < set_size - intersection_size;
         ++offset) {
        update_minima(signature_b,
                      hasher.ComputeElementHashes(set_size + offset));
    }
    return {std::move(signature_a), std::move(signature_b)};
}

}  // namespace

EstimateStatistics AggregateEstimates(const std::vector<double>& estimates,
                                      double realized_jaccard) {
    return Aggregate(estimates, realized_jaccard);
}

ExactRational ParseJaccardPoint(const std::string& text) {
    const size_t decimal_position = text.find('.');
    if (text.empty() || text.find('.', decimal_position == std::string::npos
                                              ? text.size()
                                              : decimal_position + 1) !=
                            std::string::npos) {
        throw std::invalid_argument(
            "Jaccard grid point must be an exact unsigned decimal");
    }

    const std::string whole =
        decimal_position == std::string::npos
            ? text
            : text.substr(0, decimal_position);
    std::string fractional =
        decimal_position == std::string::npos
            ? std::string()
            : text.substr(decimal_position + 1);
    if (whole.empty() ||
        (decimal_position != std::string::npos && fractional.empty()) ||
        !std::all_of(text.begin(), text.end(), [](char character) {
            return (character >= '0' && character <= '9') || character == '.';
        })) {
        throw std::invalid_argument(
            "Jaccard grid point must be an exact unsigned decimal");
    }
    if (fractional.size() > 18) {
        throw std::invalid_argument(
            "Jaccard grid point supports at most 18 fractional digits");
    }

    const uint64_t whole_value = ParseUint64(whole, "Jaccard grid point");
    if (whole_value > 1 ||
        (whole_value == 1 &&
         std::any_of(fractional.begin(), fractional.end(),
                     [](char character) { return character != '0'; }))) {
        throw std::invalid_argument("Jaccard grid point must be in [0,1]");
    }

    while (!fractional.empty() && fractional.back() == '0') {
        fractional.pop_back();
    }
    uint64_t denominator = 1;
    for (size_t i = 0; i < fractional.size(); ++i) {
        denominator *= 10;
    }
    const uint64_t fractional_value =
        fractional.empty() ? 0 : ParseUint64(fractional, "Jaccard grid point");
    const uint64_t numerator = whole_value * denominator + fractional_value;
    const uint64_t divisor = std::gcd(numerator, denominator);

    ExactRational result;
    result.numerator = numerator / divisor;
    result.denominator = denominator / divisor;
    if (numerator == 0) {
        result.decimal = "0";
    } else if (numerator == denominator) {
        result.decimal = "1";
    } else {
        result.decimal = "0." + fractional;
    }
    return result;
}

std::vector<ExactRational> ParseJaccardGrid(const std::string& text) {
    if (text.empty()) {
        throw std::invalid_argument("Jaccard grid must not be empty");
    }
    std::vector<ExactRational> grid;
    size_t begin = 0;
    while (begin <= text.size()) {
        const size_t comma = text.find(',', begin);
        const size_t end =
            comma == std::string::npos ? text.size() : comma;
        if (end == begin) {
            throw std::invalid_argument(
                "Jaccard grid contains an empty point");
        }
        grid.push_back(ParseJaccardPoint(text.substr(begin, end - begin)));
        if (comma == std::string::npos) {
            break;
        }
        begin = comma + 1;
    }
    return grid;
}

void ValidateDiagnosticConfig(const DiagnosticConfig& config) {
    if (config.k == 0) {
        throw std::invalid_argument("k must be > 0");
    }
    if (config.m < 2) {
        throw std::invalid_argument("m must be >= 2 for bias correction");
    }
    if (config.set_size == 0) {
        throw std::invalid_argument("set-size must be > 0");
    }
    if (config.set_size > std::numeric_limits<uint64_t>::max() / 2 ||
        config.set_size >
            static_cast<uint64_t>(std::vector<uint64_t>().max_size())) {
        throw std::invalid_argument("set-size is too large");
    }
    if (config.trials == 0) {
        throw std::invalid_argument("trials must be > 0");
    }
    if (config.jaccard_grid.empty()) {
        throw std::invalid_argument("Jaccard grid must not be empty");
    }
    if (config.jaccard_grid.size() >
        static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::invalid_argument("Jaccard grid contains too many points");
    }
    for (const ExactRational& point : config.jaccard_grid) {
        if (point.denominator == 0 || point.numerator > point.denominator) {
            throw std::invalid_argument(
                "Jaccard grid point must be in [0,1]");
        }
    }
}

SetPair ConstructSetPair(uint64_t set_size, const ExactRational& target) {
    if (set_size == 0) {
        throw std::invalid_argument("set-size must be > 0");
    }
    if (target.denominator == 0 || target.numerator > target.denominator) {
        throw std::invalid_argument("Jaccard target must be in [0,1]");
    }
    if (set_size > std::numeric_limits<uint64_t>::max() / 2 ||
        set_size >
            static_cast<uint64_t>(std::vector<uint64_t>().max_size())) {
        throw std::invalid_argument("set-size is too large");
    }

    using Wide = unsigned __int128;
    const Wide scaled_numerator =
        static_cast<Wide>(2) * set_size * target.numerator;
    const Wide scaled_denominator =
        static_cast<Wide>(target.denominator) + target.numerator;
    uint64_t intersection =
        static_cast<uint64_t>(scaled_numerator / scaled_denominator);
    const Wide remainder = scaled_numerator % scaled_denominator;
    if (remainder * 2 > scaled_denominator) {
        ++intersection;
    }

    SetPair pair;
    pair.intersection_size = intersection;
    pair.a.reserve(static_cast<size_t>(set_size));
    pair.b.reserve(static_cast<size_t>(set_size));
    for (uint64_t element = 0; element < set_size; ++element) {
        pair.a.push_back(element);
    }
    for (uint64_t element = 0; element < intersection; ++element) {
        pair.b.push_back(element);
    }
    for (uint64_t offset = 0; offset < set_size - intersection; ++offset) {
        pair.b.push_back(set_size + offset);
    }
    const uint64_t union_size = 2 * set_size - intersection;
    pair.realized_jaccard =
        static_cast<double>(intersection) / static_cast<double>(union_size);
    return pair;
}

uint64_t DeriveTrialSeed(uint64_t root_seed,
                         uint32_t grid_index,
                         uint64_t trial_index) {
    std::array<unsigned char, kTrialSeedDomain.size() + 1 + 8 + 4 + 8>
        input{};
    std::copy(kTrialSeedDomain.begin(), kTrialSeedDomain.end(), input.begin());
    size_t offset = kTrialSeedDomain.size();
    input[offset++] = 0;
    StoreUint64Be(root_seed, input.data() + offset);
    offset += 8;
    StoreUint32Be(grid_index, input.data() + offset);
    offset += 4;
    StoreUint64Be(trial_index, input.data() + offset);

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error(
            "failed to allocate trial-seed SHA-256 context");
    }
    const bool success =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
        EVP_DigestFinal_ex(context, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!success || digest_size != 32) {
        throw std::runtime_error("trial-seed SHA-256 derivation failed");
    }

    uint64_t seed = 0;
    for (size_t i = 0; i < 8; ++i) {
        seed = (seed << 8) | digest[i];
    }
    return seed;
}

DiagnosticRow RunDiagnosticPoint(const DiagnosticConfig& config,
                                 const ExactRational& target,
                                 uint32_t grid_index) {
    ValidateDiagnosticConfig(config);
    const SetPair pair = ConstructSetPair(config.set_size, target);

    std::vector<double> raw_estimates(static_cast<size_t>(config.trials));
    std::vector<double> bucket_estimates(static_cast<size_t>(config.trials));
    std::vector<double> corrected_estimates(static_cast<size_t>(config.trials));

    const double collision_probability = 1.0 / static_cast<double>(config.m);
    const double correction_denominator = 1.0 - collision_probability;
#ifdef _OPENMP
    // Trials are the coarse independent work units. MinHasher also uses
    // OpenMP internally, but nested regions serialize at the default single
    // active level. A small cap avoids provider/contention slowdown from
    // oversubscribing many short SHA-256 operations.
    const int worker_count = std::min(4, omp_get_max_threads());
    #pragma omp parallel for schedule(static) num_threads(worker_count)
#endif
    for (uint64_t trial = 0; trial < config.trials; ++trial) {
        const uint64_t trial_seed =
            DeriveTrialSeed(config.root_seed, grid_index, trial);
        const MinHasher hasher(config.k,
                               std::numeric_limits<uint64_t>::max(),
                               trial_seed);
        auto signatures =
            ComputePairSignatures(hasher,
                                  config.k,
                                  config.set_size,
                                  pair.intersection_size);
        const std::vector<uint64_t>& signature_a = signatures.first;
        const std::vector<uint64_t>& signature_b = signatures.second;

        const double raw =
            MinHasher::EstimateJaccard(signature_a, signature_b);
        uint32_t bucket_matches = 0;
        for (size_t coordinate = 0; coordinate < signature_a.size();
             ++coordinate) {
            if (signature_a[coordinate] % config.m ==
                signature_b[coordinate] % config.m) {
                ++bucket_matches;
            }
        }
        const double bucket =
            static_cast<double>(bucket_matches) / config.k;
        const double corrected = std::clamp(
            (bucket - collision_probability) / correction_denominator,
            0.0, 1.0);

        raw_estimates[static_cast<size_t>(trial)] = raw;
        bucket_estimates[static_cast<size_t>(trial)] = bucket;
        corrected_estimates[static_cast<size_t>(trial)] = corrected;
    }

    DiagnosticRow row;
    row.k = config.k;
    row.m = config.m;
    row.set_size = config.set_size;
    row.target_jaccard = target;
    row.realized_jaccard = pair.realized_jaccard;
    row.intersection_size = pair.intersection_size;
    row.trials = config.trials;
    row.root_seed = config.root_seed;
    row.raw_rank =
        AggregateEstimates(raw_estimates, pair.realized_jaccard);
    row.bucket_match =
        AggregateEstimates(bucket_estimates, pair.realized_jaccard);
    row.corrected =
        AggregateEstimates(corrected_estimates, pair.realized_jaccard);
    row.raw_bias_limit =
        std::max(kBiasFloor, 4.0 * row.raw_rank.standard_error.value_or(0.0));
    row.corrected_bias_limit =
        std::max(kBiasFloor, 4.0 * row.corrected.standard_error.value_or(0.0));
    row.raw_passed = std::fabs(row.raw_rank.bias) <= row.raw_bias_limit;
    row.corrected_passed =
        std::fabs(row.corrected.bias) <= row.corrected_bias_limit;
    return row;
}

std::string SerializeDiagnosticHeader() {
    return "estimator_model,k,m,set_size,target_jaccard,realized_jaccard,"
           "intersection_size,trials,seed,"
           "mean_raw_rank_estimate,raw_rank_bias,raw_rank_mae,"
           "raw_rank_sample_sd,raw_standard_error,"
           "mean_bucket_match_probability,bucket_match_bias,bucket_match_mae,"
           "bucket_match_sample_sd,bucket_standard_error,"
           "mean_bias_corrected_estimate,corrected_bias,corrected_mae,"
           "corrected_sample_sd,corrected_standard_error,"
           "raw_bias_limit,corrected_bias_limit,raw_passed,corrected_passed\n";
}

std::string SerializeDiagnosticRow(const DiagnosticRow& row) {
    RequireFinite(row.realized_jaccard);
    RequireFinite(row.raw_rank.mean);
    RequireFinite(row.raw_rank.bias);
    RequireFinite(row.raw_rank.mae);
    RequireFinite(row.bucket_match.mean);
    RequireFinite(row.bucket_match.bias);
    RequireFinite(row.bucket_match.mae);
    RequireFinite(row.corrected.mean);
    RequireFinite(row.corrected.bias);
    RequireFinite(row.corrected.mae);
    RequireFinite(row.raw_bias_limit);
    RequireFinite(row.corrected_bias_limit);

    std::ostringstream output;
    output << std::setprecision(17)
           << MinHasher::ModelName() << ','
           << row.k << ','
           << row.m << ','
           << row.set_size << ','
           << row.target_jaccard.decimal << ','
           << row.realized_jaccard << ','
           << row.intersection_size << ','
           << row.trials << ','
           << row.root_seed << ','
           << row.raw_rank.mean << ','
           << row.raw_rank.bias << ','
           << row.raw_rank.mae << ',';
    AppendOptional(output, row.raw_rank.sample_sd);
    output << ',';
    AppendOptional(output, row.raw_rank.standard_error);
    output << ','
           << row.bucket_match.mean << ','
           << row.bucket_match.bias << ','
           << row.bucket_match.mae << ',';
    AppendOptional(output, row.bucket_match.sample_sd);
    output << ',';
    AppendOptional(output, row.bucket_match.standard_error);
    output << ','
           << row.corrected.mean << ','
           << row.corrected.bias << ','
           << row.corrected.mae << ',';
    AppendOptional(output, row.corrected.sample_sd);
    output << ',';
    AppendOptional(output, row.corrected.standard_error);
    output << ','
           << row.raw_bias_limit << ','
           << row.corrected_bias_limit << ','
           << (row.raw_passed ? 1 : 0) << ','
           << (row.corrected_passed ? 1 : 0) << '\n';
    return output.str();
}

}  // namespace benchmark
}  // namespace piccard
