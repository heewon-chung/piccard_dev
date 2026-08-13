#include "estimator_diagnostic.h"
#include "cpu_revision_adapter.h"
#include "revision_matrix.h"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using piccard::benchmark::DiagnosticConfig;
using piccard::benchmark::ParseJaccardGrid;
using piccard::benchmark::RunDiagnosticPoint;
using piccard::benchmark::SerializeDiagnosticHeader;
using piccard::benchmark::SerializeDiagnosticRow;
using piccard::benchmark::ValidateDiagnosticConfig;

uint64_t ParseUint64Option(const std::string& text,
                           const std::string& option_name);

bool HasRevisionCell(int argc, char** argv) {
    for (int index = 1; index < argc; ++index) {
        if (std::string(argv[index]).rfind("--revision-cell=", 0) == 0) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> CollectArguments(int argc, char** argv) {
    std::vector<std::string> arguments;
    arguments.reserve(argc > 1 ? static_cast<size_t>(argc - 1) : 0u);
    for (int index = 1; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }
    return arguments;
}

std::vector<std::string> CanonicalizeArguments(
    const std::vector<std::string>& arguments) {
    std::vector<std::string> canonical;
    canonical.reserve(arguments.size());
    for (const std::string& argument : arguments) {
        if (argument.rfind("--seed=", 0) == 0 &&
            argument != "--seed={seed}") {
            canonical.emplace_back("--seed={seed}");
        } else {
            canonical.push_back(argument);
        }
    }
    return canonical;
}

uint64_t ConcreteSeed(const std::vector<std::string>& arguments) {
    for (const std::string& argument : arguments) {
        if (argument.rfind("--seed=", 0) != 0) continue;
        const std::string value = argument.substr(7);
        if (value == "{seed}") return 0;
        return ParseUint64Option(value, "--seed");
    }
    throw std::invalid_argument("missing --seed");
}

int RunRevisionCell(int argc, char** argv) {
#ifdef PICCARD_REVISION_MATRIX_PATH
    const auto matrix = piccard::benchmark::LoadAndValidateRevisionMatrix(
        PICCARD_REVISION_MATRIX_PATH);
    const auto arguments = CollectArguments(argc, argv);
    const uint64_t concrete_seed = ConcreteSeed(arguments);
    const auto canonical_arguments = CanonicalizeArguments(arguments);
    const auto request = piccard::benchmark::ParseCpuRevisionArgs(
        canonical_arguments,
        piccard::benchmark::CpuRevisionProducer::EstimatorBias);
    const auto mode = piccard::benchmark::RevisionRunModeForProfile(
        request.profile);
    const auto execution = piccard::benchmark::PlanCpuRevisionExecution(
        matrix, canonical_arguments,
        piccard::benchmark::CpuRevisionProducer::EstimatorBias, mode);
    if (execution.selected_cell_count != 1u ||
        execution.producer_invocation_count != 1u || execution.native_sweep) {
        throw std::logic_error("estimator revision plan is not one-cell");
    }

    DiagnosticConfig config;
    config.k = static_cast<uint32_t>(request.k);
    config.m = static_cast<uint32_t>(request.m);
    config.set_size = request.set_size;
    config.trials = request.trials;
    config.root_seed = concrete_seed;
    config.jaccard_grid = ParseJaccardGrid(request.jaccard_grid);
    ValidateDiagnosticConfig(config);

    std::cout << SerializeDiagnosticHeader();
    for (size_t grid_index = 0; grid_index < config.jaccard_grid.size();
         ++grid_index) {
        const auto row = RunDiagnosticPoint(
            config, config.jaccard_grid[grid_index],
            static_cast<uint32_t>(grid_index));
        std::cout << SerializeDiagnosticRow(row);
    }
    return 0;
#else
    (void)argc;
    (void)argv;
    throw std::runtime_error(
        "bench_estimator_bias was built without PICCARD_REVISION_MATRIX_PATH");
#endif
}

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
        if (HasRevisionCell(argc, argv)) return RunRevisionCell(argc, argv);
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
