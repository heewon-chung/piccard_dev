// CLI entry point + mode dispatch for the real-dataset accuracy/timing
// benchmark (Work 5, master Tasks 7-8). This TU stays FHE-header-free like
// the accuracy driver it dispatches to: --mode=timing (Sub-phase 5.4) does
// need a live BFV context, but that code lives entirely behind
// real_timing_driver.h's plain-typed interface, in a separate translation
// unit (benchmarks/real_timing_driver.cpp, or its OpenFHE-free stand-in
// benchmarks/real_timing_driver_stub.cpp -- CMakeLists.txt selects which one
// to compile in) so this file never needs to include an OpenFHE header
// itself. The KeyGen-free contract for --mode=accuracy still binds
// benchmarks/real_accuracy_driver.cpp, which this file dispatches to before
// any FHE code path exists.
#include "real_accuracy_driver.h"
#include "real_encoding_driver.h"
#include "real_dataset_revision_adapter.h"
#include "real_threshold_driver.h"
#include "real_timing_driver.h"
#include "revision_matrix.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

using piccard::bench::RealAccuracyCliArgs;
using piccard::bench::RealEncodingCliArgs;
using piccard::bench::RealThresholdCliArgs;
using piccard::bench::RealTimingCliArgs;
using piccard::bench::RunRealAccuracyMode;
using piccard::bench::RunRealEncodingMode;
using piccard::bench::RunRealThresholdMode;
using piccard::bench::RunRealTimingMode;
using piccard::benchmark::LoadAndValidateRevisionMatrix;
using piccard::benchmark::PlanRealDatasetRevisionExecution;
using piccard::benchmark::RealDatasetRevisionExecutionPlan;
using piccard::benchmark::RealDatasetRevisionSelection;
using piccard::benchmark::RevisionRunMode;
using piccard::benchmark::SelectRealDatasetRevisionCell;
using piccard::benchmark::ValidateRealDatasetRevisionManifest;

void PrintUsage(std::ostream& out) {
    out << "usage:\n"
           "  bench_real_datasets --dataset-manifest=<path> --mode=accuracy\n"
           "      --k=<uint32> --m=<uint32> --max-pairs=<uint64>\n"
           "      --accuracy_trials=<uint32> --seed=<uint64>\n"
           "      --hash_randomness=<name> --csv=<path>\n"
           "      --workload-manifest-out=<path> --workload-rows-out=<path>\n"
           "  bench_real_datasets --dataset-manifest=<path> --mode=timing\n"
           "      --profile=<id> --k=<uint32> --m=<uint32> --trials=<uint32>\n"
           "      --timing-pair=median --seed=<uint64> --csv=<path>\n"
           "      --workload-manifest-out=<path>\n"
           "  bench_real_datasets --dataset-manifest=<path> --mode=encoding\n"
           "      --profile=work5-std192-t40-single-trial|paper-std192-encoding-v1|readiness-toy-v1\n"
           "      --method=piccard_encode|piccard_sqrt_encode --k=<uint32> --m=<uint32>\n"
           "      --trials=1|30 --timing-pair=median --seed=20260729 --csv=<path>\n"
           "      --workload-manifest-out=<path>\n"
           "  bench_real_datasets --dataset-manifest=<path> --mode=threshold\n"
           "      --k=128 --m=64 --max-pairs=<uint64>\n"
           "      --threshold-trials=1|50 --seed=<uint64>\n"
           "      --hash_randomness=resampled --csv=<path>\n"
           "      --workload-manifest-out=<path> --workload-rows-out=<path>\n";
}

uint64_t ParseUint64Option(const std::string& text, const std::string& option_name) {
    if (text.empty()) {
        throw std::invalid_argument(option_name + " requires an unsigned integer");
    }
    for (const char c : text) {
        if (c < '0' || c > '9') {
            throw std::invalid_argument(option_name + " requires an unsigned integer");
        }
    }
    try {
        size_t consumed = 0;
        const unsigned long long value = std::stoull(text, &consumed, 10);
        if (consumed != text.size()) {
            throw std::invalid_argument(option_name + " requires an unsigned integer");
        }
        return static_cast<uint64_t>(value);
    } catch (const std::out_of_range&) {
        throw std::invalid_argument(option_name + " value out of range");
    }
}

uint32_t ParseUint32Option(const std::string& text, const std::string& option_name) {
    const uint64_t value = ParseUint64Option(text, option_name);
    if (value > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(option_name + " exceeds uint32 range");
    }
    return static_cast<uint32_t>(value);
}

// Scans argv for --mode=<value> (or --mode <value>) without validating any other option, so
// the caller can dispatch to a mode-specific parser before that parser's
// own required-option checks run. A future --mode=timing branch (Sub-phase
// 5.4) plugs in at the dispatch site in main() without touching this
// function or ParseAccuracyArguments below.
std::string ExtractMode(int argc, char** argv) {
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        const size_t equals = argument.find('=');
        if (equals != std::string::npos && argument.substr(0, equals) == "--mode") {
            return argument.substr(equals + 1);
        }
        if (argument == "--mode" && index + 1 < argc) {
            return argv[index + 1];
        }
    }
    throw std::invalid_argument("--mode is required (accuracy|timing|encoding)");
}

bool HasRevisionCell(int argc, char** argv) {
    for (int index = 1; index < argc; ++index) {
        if (std::string(argv[index]).rfind("--revision-cell=", 0) == 0) {
            return true;
        }
    }
    return false;
}

// Mode-specific parsers are defined below.  The revision dispatch seam is
// kept near the common option helpers, so declare the private functions here
// before ExecuteRealDatasetRevisionCell uses them.
RealAccuracyCliArgs ParseAccuracyArguments(int argc, char** argv);
RealTimingCliArgs ParseTimingArguments(int argc, char** argv);
RealEncodingCliArgs ParseEncodingArguments(int argc, char** argv);
RealThresholdCliArgs ParseThresholdArguments(int argc, char** argv);

std::string FindOptionValue(int argc, char** argv, const std::string& option) {
    std::string value;
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        const std::string prefix = option + "=";
        if (argument.rfind(prefix, 0) == 0) {
            if (!value.empty()) {
                throw std::invalid_argument("duplicate " + option);
            }
            value = argument.substr(prefix.size());
        }
    }
    return value;
}

bool HasOption(const std::vector<std::string>& argv,
               const std::string& option) {
    const std::string prefix = option + "=";
    return std::any_of(argv.begin(), argv.end(), [&](const std::string& arg) {
        return arg.rfind(prefix, 0) == 0;
    });
}

void AppendOptionIfMissing(std::vector<std::string>& argv,
                           const std::string& option,
                           const std::string& value) {
    if (!HasOption(argv, option)) argv.push_back(option + "=" + value);
}

RevisionRunMode InferRevisionMode(const std::vector<std::string>& argv) {
    for (const std::string& arg : argv) {
        if (arg == "--profile=readiness-toy-v1") return RevisionRunMode::Toy;
    }
    return RevisionRunMode::Paper;
}

std::vector<std::string> PrepareLegacyRevisionArguments(
    const std::vector<std::string>& planner_argv,
    const RealDatasetRevisionSelection& selection) {
    std::vector<std::string> args;
    args.reserve(planner_argv.size() + 6);
    for (const std::string& arg : planner_argv) {
        const auto omit = [&](const char* prefix) {
            return arg.rfind(prefix, 0) == 0;
        };
        // These are revision-bound control flags.  The historical parsers
        // must not see them; the adapter has already checked them against the
        // canonical plan before this filtering step.
        if (omit("--revision-cell=") || omit("--security=") ||
            omit("--raw-timing-dir=") || omit("--raw-timing-profile=") ||
            omit("--methods=") || omit("--encoding-iters=") ||
            omit("--correctness-trials=") || omit("--cell=")) {
            continue;
        }
        args.push_back(arg);
    }

    const std::string artifact = selection.cell.axis_value;
    if (selection.cell.family == "threshold_dblp_fpfn") {
        AppendOptionIfMissing(args, "--mode", "threshold");
        // The threshold driver predates the matrix and requires a pair cap;
        // the cell's frozen n-axis is the only admissible cap.
        AppendOptionIfMissing(args, "--max-pairs",
                              selection.cell.axes.at("n"));
    } else if (artifact == "accuracy") {
        AppendOptionIfMissing(args, "--k", "128");
        AppendOptionIfMissing(args, "--m", "64");
        AppendOptionIfMissing(args, "--accuracy_trials", "1");
        AppendOptionIfMissing(args, "--hash_randomness", "resampled");
    } else if (artifact == "std128_timing") {
        AppendOptionIfMissing(args, "--timing-pair", "median");
    } else if (artifact == "std192_encoding") {
        // The legacy encoder is a one-method entry point.  The canonical
        // revision cell records the one-hot/sqrt arm pair; the outer runner
        // owns the two method invocations while this C++ process accepts one
        // concrete arm at a time.  No FHE flag is introduced here.
        AppendOptionIfMissing(args, "--method", "piccard_encode");
        AppendOptionIfMissing(args, "--timing-pair", "median");
        const auto it = std::find_if(
            planner_argv.begin(), planner_argv.end(), [](const std::string& arg) {
                return arg.rfind("--encoding-iters=", 0) == 0;
            });
        if (it != planner_argv.end()) {
            AppendOptionIfMissing(args, "--trials",
                                  it->substr(std::string("--encoding-iters=").size()));
        }
    }
    return args;
}

int ExecuteRealDatasetRevisionCell(int argc, char** argv) {
#ifndef PICCARD_REVISION_MATRIX_PATH
    (void)argc;
    (void)argv;
    throw std::runtime_error(
        "revision-cell support is unavailable: matrix path was not compiled in");
#else
    std::vector<std::string> planner_argv;
    planner_argv.reserve(static_cast<size_t>(argc > 1 ? argc - 1 : 0));
    for (int index = 1; index < argc; ++index) planner_argv.emplace_back(argv[index]);

    const RevisionRunMode revision_mode = InferRevisionMode(planner_argv);
    const auto matrix = LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
    const RealDatasetRevisionSelection selection =
        SelectRealDatasetRevisionCell(matrix, planner_argv, revision_mode);
    const RealDatasetRevisionExecutionPlan execution =
        PlanRealDatasetRevisionExecution(matrix, planner_argv, revision_mode);
    if (execution.selected_cell_count != 1 || execution.keygen_calls != 0 ||
        execution.native_sweep || execution.expected_row_count != 1) {
        throw std::invalid_argument(
            "real-dataset revision execution must be exactly one row and zero KeyGen");
    }

    const std::string manifest =
        FindOptionValue(argc, argv, "--dataset-manifest");
    if (manifest.empty()) {
        throw std::invalid_argument(
            "revision-cell real-data execution requires --dataset-manifest");
    }
    ValidateRealDatasetRevisionManifest(selection.cell, manifest);

    const std::vector<std::string> prepared =
        PrepareLegacyRevisionArguments(planner_argv, selection);
    std::vector<std::string> storage;
    storage.reserve(prepared.size() + 1);
    storage.emplace_back("bench_real_datasets");
    storage.insert(storage.end(), prepared.begin(), prepared.end());
    std::vector<char*> prepared_argv;
    prepared_argv.reserve(storage.size());
    for (std::string& value : storage) {
        prepared_argv.push_back(value.data());
    }
    const int prepared_argc = static_cast<int>(prepared_argv.size());

    if (selection.cell.family == "threshold_dblp_fpfn") {
        const RealThresholdCliArgs args =
            ParseThresholdArguments(prepared_argc, prepared_argv.data());
        return RunRealThresholdMode(args);
    }
    if (selection.cell.axis_value == "accuracy") {
        const RealAccuracyCliArgs args =
            ParseAccuracyArguments(prepared_argc, prepared_argv.data());
        return RunRealAccuracyMode(args);
    }
    if (selection.cell.axis_value == "std128_timing") {
        const RealTimingCliArgs args =
            ParseTimingArguments(prepared_argc, prepared_argv.data());
        return RunRealTimingMode(args);
    }
    if (selection.cell.axis_value == "std192_encoding") {
        const RealEncodingCliArgs args =
            ParseEncodingArguments(prepared_argc, prepared_argv.data());
        return RunRealEncodingMode(args);
    }
    throw std::invalid_argument("unsupported C++ real-data revision artifact");
#endif
}

RealAccuracyCliArgs ParseAccuracyArguments(int argc, char** argv) {
    RealAccuracyCliArgs args;
    bool saw_dataset_manifest = false;
    bool saw_k = false;
    bool saw_m = false;
    bool saw_max_pairs = false;
    bool saw_accuracy_trials = false;
    bool saw_seed = false;
    bool saw_hash_randomness = false;
    bool saw_csv = false;
    bool saw_workload_manifest_out = false;
    bool saw_workload_rows_out = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        const size_t equals = argument.find('=');
        if (equals == std::string::npos || equals == 0 || equals + 1 == argument.size()) {
            throw std::invalid_argument("invalid argument: " + argument);
        }
        const std::string option = argument.substr(0, equals);
        const std::string value = argument.substr(equals + 1);

        if (option == "--mode") {
            continue;  // already dispatched on in main()
        } else if (option == "--dataset-manifest") {
            args.dataset_manifest_path = value;
            saw_dataset_manifest = true;
        } else if (option == "--k") {
            args.k = ParseUint32Option(value, option);
            saw_k = true;
        } else if (option == "--m") {
            args.m = ParseUint32Option(value, option);
            saw_m = true;
        } else if (option == "--max-pairs") {
            args.max_pairs = ParseUint64Option(value, option);
            saw_max_pairs = true;
        } else if (option == "--accuracy_trials") {
            args.accuracy_trials = ParseUint32Option(value, option);
            saw_accuracy_trials = true;
        } else if (option == "--seed") {
            args.root_seed = ParseUint64Option(value, option);
            saw_seed = true;
        } else if (option == "--hash_randomness") {
            args.hash_randomness = value;
            saw_hash_randomness = true;
        } else if (option == "--csv") {
            args.csv_path = value;
            saw_csv = true;
        } else if (option == "--workload-manifest-out") {
            args.workload_manifest_out_path = value;
            saw_workload_manifest_out = true;
        } else if (option == "--workload-rows-out") {
            args.workload_rows_out_path = value;
            saw_workload_rows_out = true;
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }

    if (!saw_dataset_manifest || !saw_k || !saw_m || !saw_max_pairs ||
        !saw_accuracy_trials || !saw_seed || !saw_hash_randomness || !saw_csv ||
        !saw_workload_manifest_out || !saw_workload_rows_out) {
        throw std::invalid_argument(
            "--mode=accuracy requires --dataset-manifest, --k, --m, "
            "--max-pairs, --accuracy_trials, --seed, --hash_randomness, "
            "--csv, --workload-manifest-out, and --workload-rows-out "
            "(all mandatory, no defaults)");
    }
    return args;
}

RealTimingCliArgs ParseTimingArguments(int argc, char** argv) {
    RealTimingCliArgs args;
    bool saw_dataset_manifest = false;
    bool saw_profile = false;
    bool saw_k = false;
    bool saw_m = false;
    bool saw_trials = false;
    bool saw_timing_pair = false;
    bool saw_seed = false;
    bool saw_csv = false;
    bool saw_workload_manifest_out = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        const size_t equals = argument.find('=');
        if (equals == std::string::npos || equals == 0 || equals + 1 == argument.size()) {
            throw std::invalid_argument("invalid argument: " + argument);
        }
        const std::string option = argument.substr(0, equals);
        const std::string value = argument.substr(equals + 1);

        if (option == "--mode") {
            continue;  // already dispatched on in main()
        } else if (option == "--dataset-manifest") {
            args.dataset_manifest_path = value;
            saw_dataset_manifest = true;
        } else if (option == "--profile") {
            args.profile_id = value;
            saw_profile = true;
        } else if (option == "--k") {
            args.k = ParseUint32Option(value, option);
            saw_k = true;
        } else if (option == "--m") {
            args.m = ParseUint32Option(value, option);
            saw_m = true;
        } else if (option == "--trials") {
            args.trials = ParseUint32Option(value, option);
            saw_trials = true;
        } else if (option == "--timing-pair") {
            args.timing_pair = value;
            saw_timing_pair = true;
        } else if (option == "--seed") {
            args.root_seed = ParseUint64Option(value, option);
            saw_seed = true;
        } else if (option == "--csv") {
            args.csv_path = value;
            saw_csv = true;
        } else if (option == "--workload-manifest-out") {
            args.workload_manifest_out_path = value;
            saw_workload_manifest_out = true;
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }

    if (!saw_dataset_manifest || !saw_profile || !saw_k || !saw_m ||
        !saw_trials || !saw_timing_pair || !saw_seed || !saw_csv ||
        !saw_workload_manifest_out) {
        throw std::invalid_argument(
            "--mode=timing requires --dataset-manifest, --profile, --k, --m, "
            "--trials, --timing-pair, --seed, --csv, and "
            "--workload-manifest-out (all mandatory, no defaults)");
    }
    if (args.timing_pair != "median") {
        throw std::invalid_argument(
            "--timing-pair only supports 'median'");
    }
    return args;
}

RealEncodingCliArgs ParseEncodingArguments(int argc, char** argv) {
    RealEncodingCliArgs args;
    bool saw_dataset_manifest = false;
    bool saw_profile = false;
    bool saw_method = false;
    bool saw_k = false;
    bool saw_m = false;
    bool saw_trials = false;
    bool saw_timing_pair = false;
    bool saw_seed = false;
    bool saw_csv = false;
    bool saw_workload_manifest_out = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        const size_t equals = argument.find('=');
        if (equals == std::string::npos || equals == 0 || equals + 1 == argument.size()) {
            throw std::invalid_argument("invalid argument: " + argument);
        }
        const std::string option = argument.substr(0, equals);
        const std::string value = argument.substr(equals + 1);
        if (option == "--mode") {
            continue;
        } else if (option == "--dataset-manifest") {
            args.dataset_manifest_path = value;
            saw_dataset_manifest = true;
        } else if (option == "--profile") {
            args.profile_id = value;
            saw_profile = true;
        } else if (option == "--method") {
            args.method = value;
            saw_method = true;
        } else if (option == "--k") {
            args.k = ParseUint32Option(value, option);
            saw_k = true;
        } else if (option == "--m") {
            args.m = ParseUint32Option(value, option);
            saw_m = true;
        } else if (option == "--trials") {
            args.trials = ParseUint32Option(value, option);
            saw_trials = true;
        } else if (option == "--timing-pair") {
            args.timing_pair = value;
            saw_timing_pair = true;
        } else if (option == "--seed") {
            args.root_seed = ParseUint64Option(value, option);
            saw_seed = true;
        } else if (option == "--csv") {
            args.csv_path = value;
            saw_csv = true;
        } else if (option == "--workload-manifest-out") {
            args.workload_manifest_out_path = value;
            saw_workload_manifest_out = true;
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }
    if (!saw_dataset_manifest || !saw_profile || !saw_method || !saw_k || !saw_m ||
        !saw_trials || !saw_timing_pair || !saw_seed || !saw_csv ||
        !saw_workload_manifest_out) {
        throw std::invalid_argument(
            "--mode=encoding requires --dataset-manifest, --profile, --method, "
            "--k, --m, --trials, --timing-pair, --seed, --csv, and "
            "--workload-manifest-out (all mandatory, no defaults)");
    }
    return args;
}

RealThresholdCliArgs ParseThresholdArguments(int argc, char** argv) {
    RealThresholdCliArgs args;
    bool saw_dataset_manifest = false;
    bool saw_k = false;
    bool saw_m = false;
    bool saw_max_pairs = false;
    bool saw_trials = false;
    bool saw_seed = false;
    bool saw_hash_randomness = false;
    bool saw_csv = false;
    bool saw_workload_manifest_out = false;
    bool saw_workload_rows_out = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        const size_t equals = argument.find('=');
        std::string option;
        std::string value;
        if (equals == std::string::npos) {
            option = argument;
            if (index + 1 >= argc) {
                throw std::invalid_argument("missing value for argument: " + argument);
            }
            value = argv[++index];
        } else {
            if (equals == 0 || equals + 1 == argument.size()) {
                throw std::invalid_argument("invalid argument: " + argument);
            }
            option = argument.substr(0, equals);
            value = argument.substr(equals + 1);
        }
        if (option == "--mode") {
            continue;
        } else if (option == "--dataset-manifest") {
            args.dataset_manifest_path = value;
            saw_dataset_manifest = true;
        } else if (option == "--k") {
            args.k = ParseUint32Option(value, option);
            saw_k = true;
        } else if (option == "--m") {
            args.m = ParseUint32Option(value, option);
            saw_m = true;
        } else if (option == "--max-pairs") {
            args.max_pairs = ParseUint64Option(value, option);
            saw_max_pairs = true;
        } else if (option == "--threshold-trials") {
            args.threshold_trials = ParseUint32Option(value, option);
            saw_trials = true;
        } else if (option == "--seed") {
            args.root_seed = ParseUint64Option(value, option);
            saw_seed = true;
        } else if (option == "--hash_randomness") {
            args.hash_randomness = value;
            saw_hash_randomness = true;
        } else if (option == "--csv") {
            args.csv_path = value;
            saw_csv = true;
        } else if (option == "--workload-manifest-out") {
            args.workload_manifest_out_path = value;
            saw_workload_manifest_out = true;
        } else if (option == "--workload-rows-out") {
            args.workload_rows_out_path = value;
            saw_workload_rows_out = true;
        } else {
            throw std::invalid_argument("unknown option: " + option);
        }
    }
    if (!saw_dataset_manifest || !saw_k || !saw_m || !saw_max_pairs ||
        !saw_trials || !saw_seed || !saw_hash_randomness || !saw_csv ||
        !saw_workload_manifest_out || !saw_workload_rows_out) {
        throw std::invalid_argument(
            "--mode=threshold requires --dataset-manifest, --k, --m, "
            "--max-pairs, --threshold-trials, --seed, --hash_randomness, "
            "--csv, --workload-manifest-out, and --workload-rows-out");
    }
    return args;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (HasRevisionCell(argc, argv)) {
            return ExecuteRealDatasetRevisionCell(argc, argv);
        }
        const std::string mode = ExtractMode(argc, argv);
        if (mode == "accuracy") {
            const RealAccuracyCliArgs args = ParseAccuracyArguments(argc, argv);
            return RunRealAccuracyMode(args);
        }
        if (mode == "timing") {
            const RealTimingCliArgs args = ParseTimingArguments(argc, argv);
            return RunRealTimingMode(args);
        }
        if (mode == "encoding") {
            const RealEncodingCliArgs args = ParseEncodingArguments(argc, argv);
            return RunRealEncodingMode(args);
        }
        if (mode == "threshold") {
            const RealThresholdCliArgs args = ParseThresholdArguments(argc, argv);
            return RunRealThresholdMode(args);
        }
        throw std::invalid_argument("unknown --mode: " + mode);
    } catch (const std::exception& error) {
        std::cerr << "bench_real_datasets: " << error.what() << '\n';
        PrintUsage(std::cerr);
        return 2;
    }
}
