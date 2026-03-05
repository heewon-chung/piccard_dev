#pragma once

/**
 * @file benchmark_utils.h
 * @brief Utility classes for benchmarking Piccard protocol implementation
 *
 * Provides timing, memory tracking, ciphertext sizing, CSV output, and CLI parsing
 * for performance benchmarks. Header-only utilities for simplicity.
 */

#include <chrono>
#include <sys/resource.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdint>
#include <stdexcept>
#include <iomanip>

#include "piccard/util/params.h"
#include "openfhe.h"

namespace piccard {
namespace benchmark {

// ============================================================================
// Timer - High-resolution timing using std::chrono
// ============================================================================

class Timer {
private:
    std::chrono::high_resolution_clock::time_point start_;

public:
    void Start() {
        start_ = std::chrono::high_resolution_clock::now();
    }

    double ElapsedMs() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start_).count();
    }
};

// ============================================================================
// MemoryTracker - Peak RSS measurement using getrusage
// ============================================================================

class MemoryTracker {
public:
    static size_t GetPeakRSS() {
        struct rusage usage;
        getrusage(RUSAGE_SELF, &usage);
#ifdef __APPLE__
        return static_cast<size_t>(usage.ru_maxrss);
#else
        return static_cast<size_t>(usage.ru_maxrss) * 1024;
#endif
    }
};

// ============================================================================
// CiphertextSizer - Measure serialized ciphertext size
// ============================================================================

class CiphertextSizer {
public:
    static size_t GetSerializedSize(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) {
        std::ostringstream oss;
        lbcrypto::Serial::Serialize(ct, oss, lbcrypto::SerType::BINARY);
        return oss.str().size();
    }
};

// ============================================================================
// BenchmarkResult - Result data structure
// ============================================================================

struct BenchmarkResult {
    std::string label;

    // Parameters
    uint32_t param_k = 0;
    uint32_t param_m = 0;
    uint32_t param_ring_dim = 0;

    // Total and per-phase timing (ms)
    double time_ms = 0.0;
    double phase_minhash_ms = 0.0;
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_multiply_ms = 0.0;
    double phase_rotate_sum_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double phase_bias_correction_ms = 0.0;

    // Resources
    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;

    // Accuracy
    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = 0.0;
};

// ============================================================================
// CSVWriter - Write benchmark results to CSV
// ============================================================================

class CSVWriter {
private:
    std::ostream* out_;
    std::ofstream file_;
    bool owns_stream_;

public:
    CSVWriter() : out_(&std::cout), owns_stream_(false) {}

    explicit CSVWriter(const std::string& filename) : owns_stream_(true) {
        file_.open(filename);
        if (!file_.is_open()) {
            throw std::runtime_error("Failed to open CSV file: " + filename);
        }
        out_ = &file_;
    }

    ~CSVWriter() {
        if (owns_stream_ && file_.is_open()) {
            file_.close();
        }
    }

    void WriteHeader() {
        *out_ << "label,k,m,ring_dim,"
              << "time_ms,phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,"
              << "phase_multiply_ms,phase_rotate_sum_ms,phase_decrypt_ms,"
              << "phase_bias_correction_ms,"
              << "memory_bytes,ct_size_bytes,"
              << "jaccard_computed,jaccard_expected,jaccard_error\n";
    }

    void WriteRow(const BenchmarkResult& result) {
        *out_ << result.label << ","
              << result.param_k << ","
              << result.param_m << ","
              << result.param_ring_dim << ","
              << std::fixed << std::setprecision(3)
              << result.time_ms << ","
              << result.phase_minhash_ms << ","
              << result.phase_encode_ms << ","
              << result.phase_encrypt_ms << ","
              << result.phase_multiply_ms << ","
              << result.phase_rotate_sum_ms << ","
              << result.phase_decrypt_ms << ","
              << result.phase_bias_correction_ms << ","
              << result.memory_bytes << ","
              << result.ct_size_bytes << ","
              << std::fixed << std::setprecision(6)
              << result.jaccard_computed << ","
              << result.jaccard_expected << ","
              << result.jaccard_error << "\n";
    }
};

// ============================================================================
// BenchmarkConfig - Configuration and CLI parsing
// ============================================================================

struct BenchmarkConfig {
    uint32_t k;                    // Number of MinHash functions
    uint32_t m;                    // One-hot bucket size
    size_t set_size;               // Size of each party's set
    size_t trials;                 // Number of trials to run
    std::string mode;              // "accuracy" or "timing"
    SecurityLevel security_level;

    BenchmarkConfig()
        : k(128),
          m(64),
          set_size(100),
          trials(10),
          mode("timing"),
          security_level(SecurityLevel::STD128) {}

    // Parse known flags, ignoring unrecognized ones (so callers can
    // layer additional flags on top without triggering errors).
    static BenchmarkConfig ParseArgs(int argc, char** argv) {
        BenchmarkConfig config;

        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);

            if (arg.find("--k=") == 0) {
                config.k = static_cast<uint32_t>(std::stoul(arg.substr(4)));
            } else if (arg.find("--m=") == 0) {
                config.m = static_cast<uint32_t>(std::stoul(arg.substr(4)));
            } else if (arg.find("--set_size=") == 0) {
                config.set_size = std::stoull(arg.substr(11));
            } else if (arg.find("--trials=") == 0) {
                config.trials = std::stoull(arg.substr(9));
            } else if (arg.find("--mode=") == 0) {
                config.mode = arg.substr(7);
                if (config.mode != "accuracy" && config.mode != "timing") {
                    throw std::invalid_argument("Invalid mode: " + config.mode);
                }
            } else if (arg.find("--security=") == 0) {
                std::string sec = arg.substr(11);
                if (sec == "TOY") {
                    config.security_level = SecurityLevel::TOY;
                } else if (sec == "STD128") {
                    config.security_level = SecurityLevel::STD128;
                } else if (sec == "STD192") {
                    config.security_level = SecurityLevel::STD192;
                } else if (sec == "STD256") {
                    config.security_level = SecurityLevel::STD256;
                } else {
                    throw std::invalid_argument("Invalid security level: " + sec);
                }
            } else if (arg == "--help" || arg == "-h") {
                // Handled by caller
            }
            // Silently ignore unrecognized flags (e.g. --universe=)
        }

        return config;
    }

    static void PrintUsage() {
        std::cout << "Usage: bench_piccard [options]\n"
                  << "Options:\n"
                  << "  --k=N              Number of MinHash functions (default: 128)\n"
                  << "  --m=N              One-hot bucket size (default: 64)\n"
                  << "  --set_size=N       Size of each party's set (default: 100)\n"
                  << "  --trials=N         Number of trials to run (default: 10)\n"
                  << "  --mode=MODE        'accuracy' or 'timing' (default: timing)\n"
                  << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256' (default: STD128)\n"
                  << "  --help, -h         Print this help message\n";
    }

    void Print() const {
        std::cerr << "Benchmark Configuration:\n"
                  << "  k:         " << k << "\n"
                  << "  m:         " << m << "\n"
                  << "  Set size:  " << set_size << "\n"
                  << "  Trials:    " << trials << "\n"
                  << "  Mode:      " << mode << "\n"
                  << "  Security:  "
                  << (security_level == SecurityLevel::TOY    ? "TOY" :
                      security_level == SecurityLevel::STD128 ? "STD128" :
                      security_level == SecurityLevel::STD192 ? "STD192" : "STD256") << "\n";
    }
};

} // namespace benchmark
} // namespace piccard
