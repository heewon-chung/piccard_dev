#include "analysis/deletion_monte_carlo.h"

#include "analysis/deletion_survival.h"

#include <charconv>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

uint64_t ParseUint64(const std::string& value, const char* name) {
    uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size()) {
        throw std::invalid_argument(std::string("invalid ") + name);
    }
    return parsed;
}

long double ParseProbability(const std::string& value) {
    size_t consumed = 0;
    long double parsed = 0.0L;
    try {
        parsed = std::stold(value, &consumed);
    } catch (const std::exception&) {
        throw std::invalid_argument("invalid required_survival");
    }
    if (consumed != value.size()) {
        throw std::invalid_argument("invalid required_survival");
    }
    return parsed;
}

std::vector<uint64_t> ParseRValues(const std::string& value) {
    std::vector<uint64_t> values;
    size_t begin = 0;
    while (begin < value.size()) {
        const size_t end = value.find(',', begin);
        const std::string token = value.substr(begin, end - begin);
        if (token.empty()) {
            throw std::invalid_argument("invalid r_values");
        }
        values.push_back(ParseUint64(token, "r_values"));
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    if (values.empty() || value.empty() || value.back() == ',') {
        throw std::invalid_argument("invalid r_values");
    }
    return values;
}

std::unordered_map<std::string, std::string> ParseOptions(int argc, char** argv) {
    const std::vector<std::string> required = {
        "n", "d", "k", "required_survival", "r_values", "trials", "seed"};
    std::unordered_map<std::string, std::string> options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if (argument.rfind("--", 0) != 0) {
            throw std::invalid_argument("invalid option");
        }
        const size_t equals = argument.find('=');
        if (equals == std::string::npos || equals == 2 ||
            argument.find('=', equals + 1) != std::string::npos) {
            throw std::invalid_argument("invalid option");
        }
        const std::string name = argument.substr(2, equals - 2);
        const std::string value = argument.substr(equals + 1);
        bool known = false;
        for (const std::string& expected : required) {
            known = known || name == expected;
        }
        if (!known || value.empty() || !options.emplace(name, value).second) {
            throw std::invalid_argument("invalid option");
        }
    }
    if (options.size() != required.size()) {
        throw std::invalid_argument("missing option");
    }
    return options;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto options = ParseOptions(argc, argv);
        const uint64_t n = ParseUint64(options.at("n"), "n");
        const uint64_t d = ParseUint64(options.at("d"), "d");
        const uint64_t k = ParseUint64(options.at("k"), "k");
        const long double required_survival = ParseProbability(options.at("required_survival"));
        const std::vector<uint64_t> r_values = ParseRValues(options.at("r_values"));
        const uint64_t trials = ParseUint64(options.at("trials"), "trials");
        const uint64_t seed = ParseUint64(options.at("seed"), "seed");
        if (trials != 1) {
            throw std::invalid_argument("trials must equal 1");
        }
        if (d > UINT32_MAX || k > UINT32_MAX) {
            throw std::invalid_argument("invalid d or k");
        }
        for (uint64_t r : r_values) {
            if (r > n) {
                throw std::invalid_argument("r must not exceed n");
            }
        }

        const piccard::DeletionSurvivalConfig config{
            n, static_cast<uint32_t>(d), static_cast<uint32_t>(k)};
        const piccard::DeletionSurvivalSummary exact =
            piccard::AnalyzeDeletionSurvival(config, required_survival);
        const piccard::DeletionMonteCarloResult simulation =
            piccard::SimulateDeletionSurvival(config, trials, seed);

        std::cout << std::setprecision(17)
                  << "model,n,d,k,required_survival,r,exact_survival,"
                     "union_bound_survival,mc_survival,mc_standard_error,"
                     "maximum_safe_deletions,exact_expected_first_failure,"
                     "exact_expected_safe_deletions,mc_mean_first_failure,"
                     "mc_mean_safe_deletions,trials,seed\n";
        for (uint64_t r : r_values) {
            std::cout << "ideal-independent-random-ranking-v1," << n << ',' << d << ',' << k
                      << ',' << required_survival << ',' << r << ','
                      << piccard::ExactDeletionSurvival(config, r) << ','
                      << piccard::UnionBoundDeletionSurvival(config, r) << ','
                      << simulation.SurvivalAt(r) << ','
                      << simulation.StandardErrorAt(r) << ','
                      << exact.maximum_safe_deletions << ','
                      << exact.expected_first_failure_time << ','
                      << exact.expected_safe_deletions << ','
                      << simulation.mean_first_failure_time << ','
                      << simulation.mean_safe_deletions << ',' << trials << ',' << seed << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
