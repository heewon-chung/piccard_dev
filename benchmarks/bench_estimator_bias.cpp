#include "estimator_diagnostic.h"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

using piccard::benchmark::DiagnosticConfig;
using piccard::benchmark::ParseJaccardGrid;
using piccard::benchmark::RunDiagnosticPoint;
using piccard::benchmark::SerializeDiagnosticHeader;
using piccard::benchmark::SerializeDiagnosticRow;
using piccard::benchmark::ValidateDiagnosticConfig;

uint64_t ParseUint64Option(const std::string& text,
                           const std::string& option_name) {
    uint64_t value = 0;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto result = std::from_chars(begin, end, value);
    if (text.empty() || result.ec != std::errc() || result.ptr != end) {
        throw std::invalid_argument(option_name +
                                    " requires an unsigned integer");
    }
    return value;
}

DiagnosticConfig ParseArguments(int argc, char** argv) {
    DiagnosticConfig config;
    bool saw_k = false;
    bool saw_m = false;
    bool saw_set_size = false;
    bool saw_trials = false;
    bool saw_seed = false;
    bool saw_grid = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        const size_t equals = argument.find('=');
        if (equals == std::string::npos || equals == 0 ||
            equals + 1 == argument.size()) {
            throw std::invalid_argument("invalid argument: " + argument);
        }
        const std::string option = argument.substr(0, equals);
        const std::string value = argument.substr(equals + 1);

        if (option == "--k") {
            const uint64_t parsed = ParseUint64Option(value, option);
            if (parsed > std::numeric_limits<uint32_t>::max()) {
                throw std::invalid_argument("--k exceeds uint32 range");
            }
            config.k = static_cast<uint32_t>(parsed);
            saw_k = true;
        } else if (option == "--m") {
            const uint64_t parsed = ParseUint64Option(value, option);
            if (parsed > std::numeric_limits<uint32_t>::max()) {
                throw std::invalid_argument("--m exceeds uint32 range");
            }
            config.m = static_cast<uint32_t>(parsed);
            saw_m = true;
        } else if (option == "--set-size") {
            config.set_size = ParseUint64Option(value, option);
            saw_set_size = true;
        } else if (option == "--trials") {
            config.trials = ParseUint64Option(value, option);
            saw_trials = true;
        } else if (option == "--seed") {
            config.root_seed = ParseUint64Option(value, option);
            saw_seed = true;
        } else if (option == "--jaccard-grid") {
            config.jaccard_grid = ParseJaccardGrid(value);
            saw_grid = true;
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }

    if (!saw_k || !saw_m || !saw_set_size || !saw_trials || !saw_seed ||
        !saw_grid) {
        throw std::invalid_argument(
            "required options: --k, --m, --set-size, --trials, --seed, "
            "--jaccard-grid");
    }
    ValidateDiagnosticConfig(config);
    if (config.trials < 2) {
        throw std::invalid_argument("--trials must be >= 2");
    }
    return config;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const DiagnosticConfig config = ParseArguments(argc, argv);
        std::cout << SerializeDiagnosticHeader();
        for (size_t grid_index = 0;
             grid_index < config.jaccard_grid.size();
             ++grid_index) {
            const auto row = RunDiagnosticPoint(
                config,
                config.jaccard_grid[grid_index],
                static_cast<uint32_t>(grid_index));
            std::cout << SerializeDiagnosticRow(row);
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "bench_estimator_bias: " << error.what() << '\n';
        return 1;
    }
}
