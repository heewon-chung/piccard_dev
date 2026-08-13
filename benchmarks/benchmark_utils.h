#pragma once

/**
 * @file benchmark_utils.h
 * @brief Utility classes for benchmarking Piccard protocol implementation
 *
 * Provides timing, memory tracking, ciphertext sizing, CSV output, and CLI parsing
 * for performance benchmarks. Header-only utilities for simplicity.
 */

#include <algorithm>
#include <charconv>
#include <chrono>
#include <sys/resource.h>
#include <string>
#include <vector>
#include <fstream>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <iomanip>
#include <unordered_map>
#include <utility>

#include "benchmark_profile.h"
#include "benchmark_estimator_provenance.h"
#include "util/params.h"
#include "openfhe.h"

namespace piccard {
namespace benchmark {

// ============================================================================
// QuickSweep - Reduce a parameter sweep for fast smoke tests
// ============================================================================
//
// Paper-grade runs (STD128/192/256) sweep the full parameter arrays. The TOY
// security level is used only for quick smoke tests (./run_benchmarks.sh
// --quick), where the goal is to exercise the full pipeline in a few minutes,
// not to produce publication numbers. For TOY we keep only the `keep` smallest
// (cheapest) points of each sweep; every other security level is unchanged.
template <typename T>
inline std::vector<T> QuickSweep(std::vector<T> full,
                                 SecurityLevel security,
                                 std::size_t keep = 2) {
    if (security == SecurityLevel::TOY && full.size() > keep) {
        full.resize(keep);
    }
    return full;
}

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

/// Whether accuracy trials redraw the MinHash CRS.
///   Resampled — default: each trial uses HashTrialSeed(root, trial, overlap).
///   Fixed     — audit/sensitivity mode: every trial keeps whatever
///               PiccardParams::hash_seed already holds, so the whole run uses
///               one CRS. This is NOT the pre-CRS behaviour: Phase 1 replaced
///               the coefficient expansion, so even seed 42 no longer
///               reproduces the originally submitted numbers.
/// Timing measurements always use a fixed CRS regardless of this setting, so
/// hash-expansion cost never lands in a reported protocol timing.
enum class HashRandomness { Resampled, Fixed };

inline const char* HashRandomnessName(HashRandomness r) {
    return r == HashRandomness::Fixed ? "fixed" : "resampled";
}

// ============================================================================
// DispersionStats - Mean, sample SD (n-1), median, and n for a phase vector
// ============================================================================

/// Timing dispersion for one phase across the row's trial execution set.
/// sd = -1.0 is the N/A sentinel when n is below 2 (reuses existing convention).
/// trials = 0 denotes an unmeasured skipped row.
struct DispersionStats {
    double mean   = 0.0;
    double sd     = -1.0;  // -1.0 sentinel: undefined when n < 2
    double median = 0.0;
    size_t n      = 0;
};

/// Compute mean, sample standard deviation (n-1 denominator), and median from
/// a vector of doubles. Returns sd=-1.0 when n < 2. Takes v by value so the
/// sort does not modify the caller's vector.
inline DispersionStats ComputeDispersion(std::vector<double> v) {
    DispersionStats s;
    s.n = v.size();
    if (s.n == 0) return s;

    // Mean
    s.mean = std::accumulate(v.begin(), v.end(), 0.0) / static_cast<double>(s.n);

    // Sample standard deviation (n-1 denominator)
    if (s.n >= 2) {
        double sum_sq = 0.0;
        for (double x : v) {
            double d = x - s.mean;
            sum_sq += d * d;
        }
        s.sd = std::sqrt(sum_sq / static_cast<double>(s.n - 1));
    }
    // else s.sd stays -1.0 (N/A sentinel for n < 2)

    // Median (sort copy — caller's vector is untouched)
    std::sort(v.begin(), v.end());
    if (s.n % 2 == 0) {
        s.median = (v[s.n / 2 - 1] + v[s.n / 2]) / 2.0;
    } else {
        s.median = v[s.n / 2];
    }

    return s;
}

// ============================================================================
// AccuracyStats - Compute accuracy statistics from (j_hat, j_true) pairs
// ============================================================================

struct AccuracyStats {
    double median = 0.0;
    double p25 = 0.0;
    double p75 = 0.0;
    double p95 = 0.0;
    double max_error = 0.0;
    size_t num_trials = 0;
};

inline AccuracyStats ComputeAccuracyStats(
    const std::vector<std::pair<double, double>>& estimates) {
    AccuracyStats stats;
    size_t n = estimates.size();
    if (n == 0) return stats;
    stats.num_trials = n;

    std::vector<double> abs_errors;
    abs_errors.reserve(n);
    for (const auto& [j_hat, j_true] : estimates) {
        abs_errors.push_back(std::abs(j_hat - j_true));
    }
    std::sort(abs_errors.begin(), abs_errors.end());

    auto percentile = [&](double p) -> double {
        double idx = p * static_cast<double>(n - 1);
        size_t lo = static_cast<size_t>(idx);
        size_t hi = lo + 1;
        if (hi >= n) return abs_errors.back();
        double frac = idx - static_cast<double>(lo);
        return abs_errors[lo] * (1.0 - frac) + abs_errors[hi] * frac;
    };

    stats.median = percentile(0.5);
    stats.p25 = percentile(0.25);
    stats.p75 = percentile(0.75);
    stats.p95 = percentile(0.95);
    stats.max_error = abs_errors.back();

    return stats;
}

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
        *out_ << SerializeBenchmarkHeader();
    }

    void WriteRow(const BenchmarkResult& result) {
        *out_ << SerializeBenchmarkRow(result, result.provenance);
    }
};

// ============================================================================
// BenchmarkConfig - Configuration and CLI parsing
// ============================================================================

struct BenchmarkConfig {
    uint32_t k;                    // Number of MinHash functions
    uint32_t m;                    // One-hot bucket size
    size_t set_size;               // Size of each party's set
    uint64_t universe_size;         // Explicit element universe (0 if absent)
    size_t trials;                 // Number of trials to run
    std::string mode;              // "accuracy", "timing", or "combined"
    SecurityLevel security_level;
    uint64_t seed;                 // RNG seed for accuracy trials (0 = random)
    double overlap;                // Overlap fraction for combined mode
    size_t accuracy_trials;        // Number of accuracy trials in combined mode
    HashRandomness hash_randomness;  // accuracy CRS mode; timing is always fixed
    uint32_t transcript_stat_bits; // Released-transcript statistical target
    uint64_t max_queries;          // Maximum sanitizer transcripts released
    BenchmarkProfile profile;      // Named immutable evidence profile
    bool evidence_point;           // Run exactly the supplied parameter point
    double target_jaccard;         // Evidence-mode Jaccard target

    BenchmarkConfig()
        : k(128),
          m(64),
          set_size(1000),
          universe_size(0),
          trials(10),
          mode("timing"),
          security_level(SecurityLevel::STD128),
          seed(0),
          overlap(0.3),
          accuracy_trials(100),
          hash_randomness(HashRandomness::Resampled),
          transcript_stat_bits(40),
          max_queries(UINT64_C(1) << 20),
          profile(LegacyBenchmarkProfile()),
          evidence_point(false),
          target_jaccard(0.5) {}

    // Parse known flags, ignoring unrecognized ones (so callers can
    // layer additional flags on top without triggering errors).
    static BenchmarkConfig ParseArgs(
        int argc,
        char** argv,
        std::function<uint64_t()> random_seed = [] {
            return static_cast<uint64_t>(std::random_device{}());
        }) {
        BenchmarkConfig config;
        bool saw_transcript_stat_bits = false;
        bool saw_max_queries = false;
        bool saw_security = false;
        bool saw_profile = false;
        bool saw_overlap = false;
        bool saw_evidence_point = false;
        bool saw_target_jaccard = false;
        bool saw_universe = false;

        auto parse_uint64 = [](const std::string& value,
                               const char* flag) -> uint64_t {
            if (value.empty() || value.front() == '-' ||
                value.front() == '+') {
                throw std::invalid_argument(
                    std::string("Invalid ") + flag + ": " + value);
            }
            uint64_t parsed = 0;
            const char* first = value.data();
            const char* last = first + value.size();
            const auto result = std::from_chars(first, last, parsed);
            if (result.ec != std::errc{} || result.ptr != last) {
                throw std::invalid_argument(
                    std::string("Invalid ") + flag + ": " + value);
            }
            return parsed;
        };

        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);

            if (arg.find("--k=") == 0) {
                config.k = static_cast<uint32_t>(std::stoul(arg.substr(4)));
            } else if (arg.find("--m=") == 0) {
                config.m = static_cast<uint32_t>(std::stoul(arg.substr(4)));
            } else if (arg.find("--set_size=") == 0) {
                config.set_size = std::stoull(arg.substr(11));
            } else if (arg.find("--universe=") == 0) {
                if (saw_universe) {
                    throw std::invalid_argument("Duplicate --universe");
                }
                saw_universe = true;
                const std::string value = arg.substr(11);
                const uint64_t parsed = parse_uint64(value, "--universe");
                if (parsed == 0 || std::to_string(parsed) != value) {
                    throw std::invalid_argument(
                        "Invalid --universe: " + value +
                        " (expected a canonical positive uint64)");
                }
                config.universe_size = parsed;
            } else if (arg.find("--trials=") == 0) {
                config.trials = std::stoull(arg.substr(9));
            } else if (arg.find("--mode=") == 0) {
                config.mode = arg.substr(7);
                if (config.mode != "accuracy" && config.mode != "timing" &&
                    config.mode != "combined" && config.mode != "fpfn" &&
                    config.mode != "spec") {
                    throw std::invalid_argument("Invalid mode: " + config.mode);
                }
            } else if (arg.find("--security=") == 0) {
                if (saw_security) {
                    throw std::invalid_argument("Duplicate --security");
                }
                saw_security = true;
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
            } else if (arg.find("--seed=") == 0) {
                config.seed = std::stoull(arg.substr(7));
            } else if (arg.find("--overlap=") == 0) {
                saw_overlap = true;
                config.overlap = std::stod(arg.substr(10));
            } else if (arg.find("--accuracy_trials=") == 0) {
                config.accuracy_trials = std::stoull(arg.substr(18));
            } else if (arg.find("--hash_randomness=") == 0) {
                std::string hr = arg.substr(18);
                if (hr == "resampled") {
                    config.hash_randomness = HashRandomness::Resampled;
                } else if (hr == "fixed") {
                    config.hash_randomness = HashRandomness::Fixed;
                } else {
                    throw std::invalid_argument(
                        "Invalid hash_randomness: " + hr +
                        " (expected 'resampled' or 'fixed')");
                }
            } else if (arg.find("--transcript_stat_bits=") == 0) {
                if (saw_transcript_stat_bits) {
                    throw std::invalid_argument(
                        "Duplicate --transcript_stat_bits");
                }
                saw_transcript_stat_bits = true;
                const uint64_t parsed = parse_uint64(
                    arg.substr(23), "--transcript_stat_bits");
                if (parsed != 40 && parsed != 64 && parsed != 128) {
                    throw std::invalid_argument(
                        "Invalid --transcript_stat_bits: " +
                        std::to_string(parsed) +
                        " (expected 40, 64, or 128)");
                }
                config.transcript_stat_bits =
                    static_cast<uint32_t>(parsed);
            } else if (arg.find("--max_queries=") == 0) {
                if (saw_max_queries) {
                    throw std::invalid_argument("Duplicate --max_queries");
                }
                saw_max_queries = true;
                const uint64_t parsed =
                    parse_uint64(arg.substr(14), "--max_queries");
                constexpr uint64_t kMaxQueries =
                    UINT64_C(9223372036854775808);
                if (parsed == 0 || parsed > kMaxQueries) {
                    throw std::invalid_argument(
                        "Invalid --max_queries: " +
                        std::to_string(parsed) +
                        " (expected 1..9223372036854775808)");
                }
                config.max_queries = parsed;
            } else if (arg.find("--profile=") == 0) {
                if (saw_profile) {
                    throw std::invalid_argument("Duplicate --profile");
                }
                saw_profile = true;
                config.profile = ResolveBenchmarkProfile(arg.substr(10));
            } else if (arg == "--evidence_point") {
                if (saw_evidence_point) {
                    throw std::invalid_argument("Duplicate --evidence_point");
                }
                saw_evidence_point = true;
                config.evidence_point = true;
            } else if (arg.find("--target-jaccard=") == 0) {
                if (saw_target_jaccard) {
                    throw std::invalid_argument("Duplicate --target-jaccard");
                }
                saw_target_jaccard = true;
                const std::string value = arg.substr(17);
                size_t consumed = 0;
                config.target_jaccard = std::stod(value, &consumed);
                if (consumed != value.size()) {
                    throw std::invalid_argument(
                        "Invalid --target-jaccard: " + value);
                }
                if (!std::isfinite(config.target_jaccard) ||
                    config.target_jaccard < 0.0 ||
                    config.target_jaccard > 1.0) {
                    throw std::invalid_argument(
                        "Invalid --target-jaccard (expected 0..1)");
                }
            } else if (arg == "--help" || arg == "-h") {
                // Handled by caller
            }
            // Silently ignore unrecognized flags (e.g. --universe=)
        }

        if (saw_profile) {
            if (saw_security &&
                config.security_level != config.profile.security) {
                throw std::invalid_argument(
                    "--security conflicts with --profile=" +
                    config.profile.id);
            }
            if (saw_transcript_stat_bits &&
                config.transcript_stat_bits !=
                    config.profile.transcript_stat_bits) {
                throw std::invalid_argument(
                    "--transcript_stat_bits conflicts with --profile=" +
                    config.profile.id);
            }
            if (saw_max_queries &&
                config.max_queries != config.profile.max_queries) {
                throw std::invalid_argument(
                    "--max_queries conflicts with --profile=" +
                    config.profile.id);
            }
            config.security_level = config.profile.security;
            config.transcript_stat_bits = config.profile.transcript_stat_bits;
            config.max_queries = config.profile.max_queries;
        }
        if (config.evidence_point && !saw_profile) {
            throw std::invalid_argument(
                "--evidence_point requires a named --profile");
        }
        if (config.evidence_point && saw_overlap) {
            throw std::invalid_argument(
                "evidence mode rejects legacy --overlap; use --target-jaccard");
        }

        // If no seed specified, generate one from random_device
        if (config.seed == 0) {
            config.seed = random_seed();
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
                  << "  --mode=MODE        'accuracy', 'timing', or 'combined' (default: timing)\n"
                  << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256' (default: STD128)\n"
                  << "  --seed=N           RNG seed for accuracy trials (default: random)\n"
                  << "  --overlap=F        Overlap fraction for combined mode (default: 0.3)\n"
                  << "  --accuracy_trials=N  Accuracy trials in combined mode (default: 100)\n"
                  << "  --hash_randomness=M  'resampled' or 'fixed' (default: resampled)\n"
                  << "  --transcript_stat_bits=N  Transcript target: 40, 64, or 128 (default: 40)\n"
                  << "  --max_queries=N     Query cap in 1..2^63 (default: 1048576)\n"
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
                      security_level == SecurityLevel::STD192 ? "STD192" : "STD256") << "\n"
                  << "  Seed:      " << seed << "\n"
                  << "  Overlap:   " << overlap << "\n"
                  << "  Acc trials:" << accuracy_trials << "\n"
                  << "  Hash rand: " << HashRandomnessName(hash_randomness) << "\n"
                  << "  Transcript stat bits: " << transcript_stat_bits << "\n"
                  << "  Max queries: " << max_queries << "\n";
        std::cerr << "  Profile:    " << profile.id << " ("
                  << BenchmarkRunClassName(profile.run_class) << ")\n"
                  << "  Evidence point: " << (evidence_point ? "yes" : "no")
                  << "\n"
                  << "  Target Jaccard: " << target_jaccard << "\n";
    }
};

inline void ApplyBenchmarkProfile(const BenchmarkConfig& config,
                                  PiccardParams& params) {
    params.transcript_stat_bits = config.transcript_stat_bits;
    params.max_queries = config.max_queries;
}

template <typename Result>
inline void ApplyBenchmarkProfile(
    const BenchmarkConfig& config,
    Result& result,
    BenchmarkMeasurementKind measurement_kind) {
    result.profile =
        MakeBenchmarkProfileMetadata(config.profile, measurement_kind);
}

inline bool IsBaseBenchmarkOption(const std::string& arg) {
    if (arg == "--help" || arg == "-h" || arg == "--evidence_point") {
        return true;
    }
    const char* prefixes[] = {
        "--k=", "--m=", "--set_size=", "--trials=", "--mode=",
        "--universe=", "--revision-cell=", "--security=", "--seed=",
        "--overlap=", "--accuracy_trials=",
        "--hash_randomness=", "--transcript_stat_bits=", "--max_queries=",
        "--profile=", "--target-jaccard=",
    };
    for (const char* prefix : prefixes) {
        if (arg.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

/** @brief Fail after the executable has declared all of its extension flags. */
inline void RejectUnknownBenchmarkOptions(
    int argc,
    char** argv,
    const std::vector<std::string>& extension_prefixes = {}) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (IsBaseBenchmarkOption(arg)) continue;
        bool extension = false;
        for (const auto& prefix : extension_prefixes) {
            if (arg == prefix || arg.rfind(prefix, 0) == 0) {
                extension = true;
                break;
            }
        }
        if (!extension) {
            throw std::invalid_argument("Unknown option: " + arg);
        }
    }
}

// Kept for source compatibility outside the evidence runners. New non-threshold
// evidence sites call ApplyBenchmarkProfile explicitly.
inline void ApplySanitizerConfig(const BenchmarkConfig& config,
                                 PiccardParams& params) {
    ApplyBenchmarkProfile(config, params);
}

struct SqrtComparisonConfig {
    uint64_t seed = 0;
    int trials = 5;
    BenchmarkConfig sanitizer;
    uint32_t flood_margin_bits = 8;
};

inline SqrtComparisonConfig ResolveSqrtComparisonConfig(
    int argc,
    char** argv,
    std::function<uint64_t()> random_seed = [] {
        return static_cast<uint64_t>(std::random_device{}());
    }) {
    int legacy_trials = 5;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg.find("--trials=") == 0) {
            legacy_trials = std::stoi(arg.substr(9));
        }
    }

    BenchmarkConfig sanitizer =
        BenchmarkConfig::ParseArgs(argc, argv, std::move(random_seed));
    if (sanitizer.profile.run_class == BenchmarkRunClass::Legacy) {
        sanitizer.security_level = SecurityLevel::TOY;
    }

    SqrtComparisonConfig resolved;
    resolved.seed = sanitizer.seed;
    resolved.trials = std::max(legacy_trials, 1);
    resolved.sanitizer = sanitizer;
    resolved.flood_margin_bits = 8;
    return resolved;
}

// ============================================================================
// MakeRandomSetsWithOverlap - Randomized test data for accuracy benchmarks
// ============================================================================

/// Generate two sets with target overlap using randomized element selection.
/// Elements are sampled without replacement from [0, universe_max).
/// The overlap fraction is exact: |A ∩ B| = floor(overlap_fraction * set_size).
/// Deterministic given the same rng state.
inline std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeRandomSetsWithOverlap(size_t set_size, double overlap_fraction,
                           std::mt19937_64& rng,
                           uint64_t universe_max = 10'000'000) {
    size_t overlap = static_cast<size_t>(overlap_fraction * set_size);
    size_t unique_a = set_size - overlap;
    size_t unique_b = set_size - overlap;
    size_t total_needed = overlap + unique_a + unique_b;

    if (total_needed > universe_max) {
        throw std::runtime_error(
            "Universe too small: need " + std::to_string(total_needed) +
            " distinct elements but universe_max=" + std::to_string(universe_max));
    }

    // Generate total_needed distinct elements via partial Fisher-Yates shuffle
    // on indices [1, universe_max]. We avoid allocating the full array by
    // using a map to track swapped positions.
    std::vector<uint64_t> sampled(total_needed);
    std::unordered_map<uint64_t, uint64_t> swaps;
    for (size_t i = 0; i < total_needed; i++) {
        std::uniform_int_distribution<uint64_t> dist(i, universe_max - 1);
        uint64_t j = dist(rng);

        // Get value at position i (default: i) and j (default: j)
        // Elements are 0-based: [0, universe_max)
        uint64_t vi = swaps.count(i) ? swaps[i] : i;
        uint64_t vj = swaps.count(j) ? swaps[j] : j;

        sampled[i] = vj;
        swaps[j] = vi;
        // No need to set swaps[i] since we won't revisit index i
    }

    // Partition: first `overlap` shared, next `unique_a` for A, last `unique_b` for B
    std::vector<uint64_t> a, b;
    a.reserve(set_size);
    b.reserve(set_size);

    for (size_t i = 0; i < overlap; i++) {
        a.push_back(sampled[i]);
        b.push_back(sampled[i]);
    }
    for (size_t i = overlap; i < overlap + unique_a; i++) {
        a.push_back(sampled[i]);
    }
    for (size_t i = overlap + unique_a; i < total_needed; i++) {
        b.push_back(sampled[i]);
    }

    return {a, b};
}

/// Overload with explicit universe_size (for bench_comparison compatibility).
inline std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeRandomSetsWithOverlap(size_t set_size, double overlap_fraction,
                           uint64_t universe_size,
                           std::mt19937_64& rng) {
    return MakeRandomSetsWithOverlap(set_size, overlap_fraction, rng,
                                      universe_size);
}

/// Compute a per-trial seed from base seed, trial index, and overlap fraction.
/// Ensures each (trial, overlap) pair gets a distinct but reproducible seed.
inline uint64_t TrialSeed(uint64_t base_seed, size_t trial, double overlap) {
    return base_seed + trial * 10007 + static_cast<uint64_t>(overlap * 1000);
}

/// Domain-separated per-trial seed for the MinHash CRS.
///
/// TrialSeed above owns set generation; this owns hash-family selection. For
/// the same (base_seed, trial, overlap) the two must differ, otherwise the set
/// draw and the hash draw are correlated and the accuracy experiment is not
/// sampling the probability space it claims to. An additive lattice like
/// TrialSeed's would collide with it on some inputs, so mix through a distinct
/// domain tag and a splitmix64 finalizer instead.
///
/// The signature deliberately excludes k, m, set_size, and engine identity:
/// that is what lets a k/m/n sweep and the Piccard / Dynamic / one-hot / sqrt
/// benchmarks reuse one hash seed per trial and keep their comparisons paired.
inline uint64_t HashTrialSeed(uint64_t base_seed, size_t trial, double overlap) {
    uint64_t x = base_seed
               + 0x9E3779B97F4A7C15ULL * (static_cast<uint64_t>(trial) + 1)
               + 0xD1B54A32D192ED03ULL *
                     static_cast<uint64_t>(overlap * 1000.0);
    x ^= 0xA5A5A5A5A5A5A5A5ULL;  // hash-domain tag, absent from TrialSeed
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}

} // namespace benchmark
} // namespace piccard
