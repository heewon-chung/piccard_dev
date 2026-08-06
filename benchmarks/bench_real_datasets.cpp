// CLI entry point + mode dispatch for the real-dataset accuracy/timing
// benchmark (Work 5, master Tasks 7-8). This TU is free to include
// OpenFHE/BFV headers (needed by --mode=timing, Sub-phase 5.4); the
// KeyGen-free contract instead binds benchmarks/real_accuracy_driver.cpp,
// which this file dispatches to for --mode=accuracy before any FHE code
// path exists.
#include "real_accuracy_driver.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

using piccard::bench::RealAccuracyCliArgs;
using piccard::bench::RunRealAccuracyMode;

void PrintUsage(std::ostream& out) {
    out << "usage:\n"
           "  bench_real_datasets --dataset-manifest=<path> --mode=accuracy\n"
           "      --k=<uint32> --m=<uint32> --max-pairs=<uint64>\n"
           "      --accuracy_trials=<uint32> --seed=<uint64>\n"
           "      --hash_randomness=<name> --csv=<path>\n"
           "      --workload-manifest-out=<path> --workload-rows-out=<path>\n"
           "  bench_real_datasets --dataset-manifest=<path> --mode=timing ...\n"
           "      (not implemented yet)\n";
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

// Scans argv for --mode=<value> without validating any other option, so
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
    }
    throw std::invalid_argument("--mode is required (accuracy|timing)");
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

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::string mode = ExtractMode(argc, argv);
        if (mode == "accuracy") {
            const RealAccuracyCliArgs args = ParseAccuracyArguments(argc, argv);
            return RunRealAccuracyMode(args);
        }
        if (mode == "timing") {
            std::cerr << "bench_real_datasets: --mode=timing is not implemented yet\n";
            PrintUsage(std::cerr);
            return 1;
        }
        throw std::invalid_argument("unknown --mode: " + mode);
    } catch (const std::exception& error) {
        std::cerr << "bench_real_datasets: " << error.what() << '\n';
        PrintUsage(std::cerr);
        return 2;
    }
}
