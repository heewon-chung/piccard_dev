// OpenFHE-free entry point for the held-out DBLP threshold experiment.
#include "real_threshold_driver.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

uint64_t ParseUint64(const std::string& text, const std::string& option) {
    if (text.empty()) {
        throw std::invalid_argument(option + " requires an unsigned integer");
    }
    for (const char value : text) {
        if (value < '0' || value > '9') {
            throw std::invalid_argument(option + " requires an unsigned integer");
        }
    }
    size_t consumed = 0;
    try {
        const unsigned long long value = std::stoull(text, &consumed, 10);
        if (consumed != text.size()) {
            throw std::invalid_argument(option + " requires an unsigned integer");
        }
        return static_cast<uint64_t>(value);
    } catch (const std::out_of_range&) {
        throw std::invalid_argument(option + " value out of range");
    }
}

uint32_t ParseUint32(const std::string& text, const std::string& option) {
    const uint64_t value = ParseUint64(text, option);
    if (value > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(option + " exceeds uint32 range");
    }
    return static_cast<uint32_t>(value);
}

void SetOption(const std::string& option, const std::string& value,
               piccard::bench::RealThresholdCliArgs& args,
               bool& dataset_manifest, bool& k, bool& m, bool& max_pairs,
               bool& trials, bool& seed, bool& hash_randomness, bool& csv,
               bool& manifest_out, bool& rows_out) {
    if (option == "--dataset-manifest") {
        args.dataset_manifest_path = value;
        dataset_manifest = true;
    } else if (option == "--k") {
        args.k = ParseUint32(value, option);
        k = true;
    } else if (option == "--m") {
        args.m = ParseUint32(value, option);
        m = true;
    } else if (option == "--max-pairs") {
        args.max_pairs = ParseUint64(value, option);
        max_pairs = true;
    } else if (option == "--threshold-trials") {
        args.threshold_trials = ParseUint32(value, option);
        trials = true;
    } else if (option == "--seed") {
        args.root_seed = ParseUint64(value, option);
        seed = true;
    } else if (option == "--hash_randomness") {
        args.hash_randomness = value;
        hash_randomness = true;
    } else if (option == "--csv") {
        args.csv_path = value;
        csv = true;
    } else if (option == "--workload-manifest-out") {
        args.workload_manifest_out_path = value;
        manifest_out = true;
    } else if (option == "--workload-rows-out") {
        args.workload_rows_out_path = value;
        rows_out = true;
    } else if (option != "--mode") {
        throw std::invalid_argument("unknown option: " + option);
    }
}

piccard::bench::RealThresholdCliArgs ParseArguments(int argc, char** argv) {
    piccard::bench::RealThresholdCliArgs args;
    bool dataset_manifest = false;
    bool k = false;
    bool m = false;
    bool max_pairs = false;
    bool trials = false;
    bool seed = false;
    bool hash_randomness = false;
    bool csv = false;
    bool manifest_out = false;
    bool rows_out = false;

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
        SetOption(option, value, args, dataset_manifest, k, m, max_pairs,
                  trials, seed, hash_randomness, csv, manifest_out, rows_out);
    }
    if (!dataset_manifest || !k || !m || !max_pairs || !trials || !seed ||
        !hash_randomness || !csv || !manifest_out || !rows_out) {
        throw std::invalid_argument(
            "threshold requires --dataset-manifest, --k, --m, --max-pairs, "
            "--threshold-trials, --seed, --hash_randomness, --csv, "
            "--workload-manifest-out, and --workload-rows-out");
    }
    return args;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return piccard::bench::RunRealThresholdMode(ParseArguments(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << "bench_real_threshold: " << error.what() << '\n';
        return 2;
    }
}
