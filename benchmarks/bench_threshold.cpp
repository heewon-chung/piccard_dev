#include "benchmark_utils.h"
#include "benchmark_provenance.h"
#include "raw_timing_schema.h"
#include "threshold_csv_schema.h"
#include "threshold_fpfn_schema.h"
#include "protocol/threshold_piccard.h"
#include "protocol/piccard.h"
#include "core/threshold_truth.h"
#include "core/threshold_poly.h"
#include "core/minhash.h"

// OpenFHE serialization registration (required for CiphertextSizer)
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <limits>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;

namespace {

constexpr const char* kRawTimingProducerId = "bench_threshold";

struct RawTimingOptions {
    bool enabled = false;
    bool trials_explicit = false;
    std::string output_directory;
    std::string profile_id;
    size_t measured_trials = 0;
};

static RawTimingOptions ParseRawTimingOptions(int argc, char** argv) {
    RawTimingOptions options;
    for (int index = 1; index < argc; ++index) {
        const std::string arg(argv[index]);
        if (arg.rfind("--raw_timing_dir=", 0) == 0) {
            if (options.enabled) {
                throw std::invalid_argument("duplicate --raw_timing_dir");
            }
            options.enabled = true;
            options.output_directory = arg.substr(17);
            if (options.output_directory.empty()) {
                throw std::invalid_argument(
                    "--raw_timing_dir must not be empty");
            }
        } else if (arg.rfind("--trials=", 0) == 0) {
            options.trials_explicit = true;
        }
    }
    return options;
}

static std::string RawTimingProfileId(const BenchmarkConfig& config) {
    if (config.profile.id == "readiness-toy-v1") {
        return kReadinessTimingProfileVersion;
    }
    if (config.profile.id == "paper-std128-t40-v1" ||
        config.profile.id == "paper-std192-encoding-v1" ||
        config.profile.id.rfind("paper-", 0) == 0) {
        return kPaperTimingProfileVersion;
    }
    throw std::invalid_argument(
        "--raw_timing_dir requires --profile=paper-* or readiness-toy-v1");
}

static void ResolveRawTimingOptions(RawTimingOptions& options,
                                    const BenchmarkConfig& config) {
    if (!options.enabled) return;
    if (config.mode != "timing") {
        throw std::invalid_argument(
            "--raw_timing_dir requires --mode=timing");
    }
    if (TimingContractFor(kRawTimingProducerId) == kTimingNotApplicable) {
        throw std::invalid_argument("bench_threshold has no raw timing contract");
    }
    options.profile_id = RawTimingProfileId(config);
    options.measured_trials = static_cast<size_t>(
        ExpectedTimingTrials(options.profile_id));
    if (options.trials_explicit &&
        config.trials != options.measured_trials) {
        throw std::invalid_argument(
            "versioned raw timing requires exactly " +
            std::to_string(options.measured_trials) + " measured trials");
    }
}

}  // namespace

// ============================================================================
// Helpers (shared with bench_piccard.cpp)
// ============================================================================

static double ExactJaccard(const std::vector<uint64_t>& a,
                           const std::vector<uint64_t>& b) {
    std::set<uint64_t> sa(a.begin(), a.end());
    std::set<uint64_t> sb(b.begin(), b.end());
    size_t inter = 0;
    for (auto x : sa) {
        if (sb.count(x)) inter++;
    }
    size_t uni = sa.size() + sb.size() - inter;
    if (uni == 0) return 1.0;
    return static_cast<double>(inter) / static_cast<double>(uni);
}

static std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeSetsWithOverlap(size_t set_size, double overlap_fraction) {
    size_t overlap = static_cast<size_t>(overlap_fraction * set_size);
    std::vector<uint64_t> a, b;
    for (uint64_t i = 0; i < overlap; i++) {
        a.push_back(i);
        b.push_back(i);
    }
    for (uint64_t i = overlap; i < set_size; i++) {
        a.push_back(i + 1000000);
    }
    for (uint64_t i = overlap; i < set_size; i++) {
        b.push_back(i + 2000000);
    }
    return {a, b};
}

// ============================================================================
// True-Jaccard truth context (R3-4)
//
// The ground truth for a threshold decision is ExactJaccard >= J_tau, NOT the
// MinHash match count: comparing the protocol's decision against the match
// count only re-verifies that BFV evaluation is exact (that check is kept,
// separately, as fhe_agrees).
// ============================================================================

struct TruthContext {
    double j_true = -1.0;          // ExactJaccard(sa, sb)
    double j_tau = -1.0;           // JaccardThreshold(tau, k, m)
    int64_t match_count = -1;      // plaintext bucket match count
    int matchcount_expected = -1;  // match_count >= tau  (old "expected")
    int truth = -1;                // j_true >= j_tau     (new "expected")
};

static TruthContext MakeTruthContext(const ThresholdPiccard& engine,
                                     const std::vector<uint64_t>& sx,
                                     const std::vector<uint64_t>& sy) {
    const auto& P = engine.GetParams();
    TruthContext tc;
    tc.j_true = ExactJaccard(sx, sy);
    tc.j_tau = JaccardThreshold(P.threshold_tau, P.k, P.m);
    auto sig_x = engine.GetPiccard().ComputeSignature(sx);
    auto sig_y = engine.GetPiccard().ComputeSignature(sy);
    // BucketMatchCount takes std::min of the two lengths and would silently
    // truncate a mismatch (the header keeps that behavior deliberately; see
    // core/threshold_truth.h). OneHotEncoder::Encode rejects any signature
    // whose length isn't k, so a length mismatch here is a wiring bug --
    // fail loudly instead of turning it into plausible-looking benchmark
    // data. NDEBUG strips assert() in this Release build, so this must be a
    // real runtime check.
    if (sig_x.size() != P.k || sig_y.size() != P.k) {
        throw std::runtime_error(
            "MakeTruthContext: signature length mismatch (sig_x.size()=" +
            std::to_string(sig_x.size()) + ", sig_y.size()=" +
            std::to_string(sig_y.size()) + ", k=" + std::to_string(P.k) + ")");
    }
    tc.match_count = BucketMatchCount(sig_x, sig_y, P.m);
    tc.matchcount_expected =
        (tc.match_count >= static_cast<int64_t>(P.threshold_tau)) ? 1 : 0;
    tc.truth = (tc.j_true >= tc.j_tau) ? 1 : 0;
    return tc;
}

// TP/FP/TN/FN of a decision against the true-Jaccard truth.
static const char* OutcomeName(int truth, int decision) {
    if (truth == 1) return decision == 1 ? "TP" : "FN";
    return decision == 1 ? "FP" : "TN";
}

// ============================================================================
// Synthetic FP/FN point path (Phase 4)
//
// This path deliberately has its own parser and writer.  It is entered before
// BenchmarkConfig::ParseArgs so a plaintext threshold row cannot accidentally
// resolve a legacy FHE profile or construct an OpenFHE context.
// ============================================================================

struct FpfnConfig {
    std::string profile;
    std::string security;
    std::string hash_randomness = "resampled";
    uint64_t root_seed = 0;
    size_t trials = 0;
    uint32_t m = kSyntheticThresholdM;
    uint32_t set_size = kSyntheticThresholdSetSize;
    uint32_t point_k = 0;
    int32_t grid_index = 0;
    bool saw_profile = false;
    bool saw_seed = false;
    bool saw_trials = false;
    bool saw_point_k = false;
    bool saw_grid_index = false;
    bool saw_security = false;
    bool saw_m = false;
    bool saw_set_size = false;
    bool saw_hash_randomness = false;
};

static uint64_t ParseFpfnUnsigned(const std::string& value,
                                  const char* flag) {
    if (value.empty() || value.front() == '-' || value.front() == '+') {
        throw std::invalid_argument(std::string("invalid ") + flag + ": " +
                                    value);
    }
    uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(),
                                        parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        throw std::invalid_argument(std::string("invalid ") + flag + ": " +
                                    value);
    }
    return parsed;
}

static int32_t ParseFpfnSigned(const std::string& value, const char* flag) {
    if (value.empty() || value.front() == '+') {
        throw std::invalid_argument(std::string("invalid ") + flag + ": " +
                                    value);
    }
    int32_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(),
                                        parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        throw std::invalid_argument(std::string("invalid ") + flag + ": " +
                                    value);
    }
    return parsed;
}

static void RejectFpfnDuplicate(bool& seen, const char* flag) {
    if (seen) throw std::invalid_argument(std::string("duplicate ") + flag);
    seen = true;
}

static FpfnConfig ParseFpfnArgs(int argc, char** argv) {
    FpfnConfig config;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            throw std::invalid_argument("help requested");
        } else if (arg.rfind("--mode=", 0) == 0) {
            if (arg.substr(7) != "fpfn") {
                throw std::invalid_argument(
                    "synthetic threshold path requires --mode=fpfn");
            }
        } else if (arg.rfind("--profile=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_profile, "--profile");
            config.profile = arg.substr(10);
        } else if (arg.rfind("--security=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_security, "--security");
            config.security = arg.substr(11);
            if (config.security != "TOY" && config.security != "STD128" &&
                config.security != "STD192" && config.security != "STD256") {
                throw std::invalid_argument("invalid --security: " +
                                            config.security);
            }
        } else if (arg.rfind("--m=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_m, "--m");
            const uint64_t value = ParseFpfnUnsigned(arg.substr(4), "--m");
            if (value > std::numeric_limits<uint32_t>::max()) {
                throw std::invalid_argument("invalid --m");
            }
            config.m = static_cast<uint32_t>(value);
        } else if (arg.rfind("--set_size=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_set_size, "--set_size");
            const uint64_t value =
                ParseFpfnUnsigned(arg.substr(11), "--set_size");
            if (value > std::numeric_limits<uint32_t>::max()) {
                throw std::invalid_argument("invalid --set_size");
            }
            config.set_size = static_cast<uint32_t>(value);
        } else if (arg.rfind("--trials=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_trials, "--trials");
            config.trials = static_cast<size_t>(
                ParseFpfnUnsigned(arg.substr(9), "--trials"));
        } else if (arg.rfind("--seed=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_seed, "--seed");
            config.root_seed = ParseFpfnUnsigned(arg.substr(7), "--seed");
        } else if (arg.rfind("--point-k=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_point_k, "--point-k");
            const uint64_t value =
                ParseFpfnUnsigned(arg.substr(10), "--point-k");
            if (value > std::numeric_limits<uint32_t>::max()) {
                throw std::invalid_argument("invalid --point-k");
            }
            config.point_k = static_cast<uint32_t>(value);
        } else if (arg.rfind("--grid-index=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_grid_index, "--grid-index");
            config.grid_index = ParseFpfnSigned(arg.substr(13), "--grid-index");
        } else if (arg.rfind("--hash_randomness=", 0) == 0) {
            RejectFpfnDuplicate(config.saw_hash_randomness,
                                "--hash_randomness");
            config.hash_randomness = arg.substr(18);
            if (config.hash_randomness != "resampled") {
                throw std::invalid_argument(
                    "synthetic threshold rows require --hash_randomness=resampled");
            }
        } else {
            throw std::invalid_argument("unknown synthetic threshold option: " +
                                        arg);
        }
    }

    if (!config.saw_profile ||
        (config.profile != "readiness-toy-v1" && config.profile != "paper-v1")) {
        throw std::invalid_argument(
            "--profile must be readiness-toy-v1 or paper-v1");
    }
    if (!config.saw_seed || config.root_seed == 0) {
        throw std::invalid_argument("--seed must be a positive uint64");
    }
    if (!config.saw_trials || config.trials == 0) {
        throw std::invalid_argument("--trials must be a positive integer");
    }
    if (config.profile == "readiness-toy-v1") {
        if (config.trials != 1) {
            throw std::invalid_argument(
                "readiness-toy-v1 requires exactly one trial");
        }
        if (!config.saw_security) config.security = "TOY";
        if (config.saw_security && config.security != "TOY") {
            throw std::invalid_argument(
                "readiness-toy-v1 requires TOY security metadata");
        }
    } else {
        if (config.trials < 1000) {
            throw std::invalid_argument("paper-v1 requires at least 1000 trials");
        }
        if (!config.saw_security) config.security = "STD128";
        if (config.saw_security && config.security == "TOY") {
            throw std::invalid_argument(
                "paper-v1 does not permit TOY security metadata");
        }
    }
    if (config.m != kSyntheticThresholdM) {
        throw std::invalid_argument("synthetic threshold requires --m=64");
    }
    if (config.set_size != kSyntheticThresholdSetSize) {
        throw std::invalid_argument(
            "synthetic threshold requires --set_size=1000");
    }
    if (!config.saw_point_k || !IsSyntheticThresholdK(config.point_k)) {
        throw std::invalid_argument(
            "--point-k must be one of 64, 128, 256, 512");
    }
    if (!config.saw_grid_index ||
        !IsSyntheticThresholdGridIndex(config.grid_index)) {
        throw std::invalid_argument(
            "--grid-index must be in the signed range [-10,10]");
    }
    return config;
}

static std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeSyntheticThresholdSets(uint32_t intersection) {
    std::vector<uint64_t> a;
    std::vector<uint64_t> b;
    a.reserve(kSyntheticThresholdSetSize);
    b.reserve(kSyntheticThresholdSetSize);
    for (uint32_t value = 0; value < kSyntheticThresholdSetSize; ++value) {
        a.push_back(value);
    }
    for (uint32_t value = 0; value < intersection; ++value) {
        b.push_back(value);
    }
    for (uint32_t value = 0;
         value < kSyntheticThresholdSetSize - intersection; ++value) {
        b.push_back(kSyntheticThresholdSetSize + value);
    }
    return {std::move(a), std::move(b)};
}

static void WriteSyntheticThresholdRow(const FpfnConfig& config,
                                       const SyntheticThresholdPoint& point,
                                       uint64_t trial_index,
                                       uint64_t row_seed,
                                       int64_t match_count,
                                       int decision,
                                       int exact_j_truth,
                                       double predicted_decision_probability,
                                       double predicted_error_probability,
                                       double gaussian_error_approx) {
    std::cout << kThresholdFpfnSchemaVersion << ',' << config.profile << ','
              << config.security << ',' << MinHasher::ModelName() << ','
              << config.hash_randomness << ',' << config.root_seed << ','
              << point.k << ',' << point.m << ',' << kSyntheticThresholdSetSize
              << ',' << point.tau_count << ',' << std::setprecision(17)
              << point.j_tau << ',' << point.grid_index << ',' << point.target_j
              << ',' << point.signed_delta << ',' << point.absolute_delta << ','
              << point.alpha << ',' << point.realized_intersection << ','
              << point.realized_union << ',' << point.realized_j << ','
              << trial_index << ',' << row_seed << ',' << match_count << ','
              << decision << ',' << exact_j_truth << ','
              << SyntheticThresholdOutcome(exact_j_truth, decision) << ','
              << predicted_decision_probability << ','
              << predicted_error_probability << ',' << gaussian_error_approx
              << '\n';
}

static int RunSyntheticThresholdPoint(const FpfnConfig& config) {
    const SyntheticThresholdPoint point =
        MakeSyntheticThresholdPoint(config.point_k, config.grid_index);
    const auto sets = MakeSyntheticThresholdSets(point.realized_intersection);
    std::cout << ThresholdFpfnCSVHeader();

    const double p = point.realized_j +
                     (1.0 - point.realized_j) /
                         static_cast<double>(point.m);
    const double predicted_decision_probability =
        SyntheticThresholdBinomialDecisionProbability(point.k,
                                                      point.tau_count, p);
    const int exact_j_truth = point.realized_j >= point.j_tau ? 1 : 0;
    const double predicted_error_probability =
        exact_j_truth == 1 ? 1.0 - predicted_decision_probability
                           : predicted_decision_probability;
    const double gaussian_error_approx = SyntheticThresholdGaussianErrorApprox(
        point.realized_j, point.k, point.m);

    for (uint64_t trial_index = 0; trial_index < config.trials; ++trial_index) {
        const uint64_t row_seed = SyntheticThresholdRowSeed(
            config.root_seed, point.k, point.grid_index, trial_index);
        MinHasher hasher(point.k, std::numeric_limits<uint64_t>::max(), row_seed);
        const auto sig_a = hasher.ComputeSignature(sets.first);
        const auto sig_b = hasher.ComputeSignature(sets.second);
        const int64_t match_count = BucketMatchCount(sig_a, sig_b, point.m);
        const int decision =
            SyntheticThresholdDecision(match_count, point.tau_count);
        WriteSyntheticThresholdRow(
            config, point, trial_index, row_seed, match_count, decision,
            exact_j_truth, predicted_decision_probability,
            predicted_error_probability, gaussian_error_approx);
    }
    return 0;
}

// ============================================================================
// Threshold result struct & CSV writer
// ============================================================================

struct ThresholdResult {
    std::string label;
    uint32_t k = 0;
    uint32_t m = 0;
    size_t set_size = 0;
    uint32_t ring_dim = 0;
    uint32_t tau = 0;
    uint32_t mult_depth = 0;

    double phase_minhash_ms = 0.0;
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_multiply_ms = 0.0;
    double phase_rotate_sum_ms = 0.0;
    double phase_mask_ms = 0.0;
    double phase_poly_eval_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;

    int threshold_result = -1;
    int threshold_expected = -1;
    int threshold_correct = -1;

    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = -1.0;
    double jaccard_rel_error = -1.0;

    std::string note;

    // Dispersion columns (additive — sibling branches inherit)
    size_t trials = 0;  // 0 = unmeasured/skipped sentinel
    double total_ms_sd = -1.0;           double total_ms_median = 0.0;
    double phase_minhash_ms_sd = -1.0;   double phase_minhash_ms_median = 0.0;
    double phase_encode_ms_sd = -1.0;    double phase_encode_ms_median = 0.0;
    double phase_encrypt_ms_sd = -1.0;   double phase_encrypt_ms_median = 0.0;
    double phase_multiply_ms_sd = -1.0;  double phase_multiply_ms_median = 0.0;
    double phase_rotate_sum_ms_sd = -1.0; double phase_rotate_sum_ms_median = 0.0;
    double phase_mask_ms_sd = -1.0;      double phase_mask_ms_median = 0.0;
    double phase_poly_eval_ms_sd = -1.0; double phase_poly_eval_ms_median = 0.0;
    double phase_decrypt_ms_sd = -1.0;   double phase_decrypt_ms_median = 0.0;
    size_t rel_error_eligible_n = 0;

    // True-Jaccard truth columns (R3-4, additive)
    double j_tau = -1.0;            // Jaccard threshold for (tau, k, m)
    int64_t match_count = -1;       // plaintext bucket match count
    int matchcount_expected = -1;   // match_count >= tau (pre-R3-4 "expected")
    int fhe_agrees = -1;            // FHE decision == matchcount_expected; -1 = no FHE run
    std::string outcome;            // TP/FP/TN/FN vs true-Jaccard truth; "" = n/a
    // Hash provenance (plan 9 four-column schema, ComparisonCSVWriter precedent)
    std::string hash_randomness;    // "resampled"/"fixed"; "" = n/a (e.g. SKIPPED)
    uint64_t hash_seed = 0;         // actual CRS this row was measured under
    uint64_t hash_root_seed = 0;    // resampled: derivation root (config.seed);
                                    // fixed: the CRS actually used (or documented 0)
    size_t accuracy_trials = 0;     // accuracy samples in this row (1 per-trial, 0 timing)

    // Flooding columns (plan 8 schema, additive)
    double phase_flood_ms = 0.0;
    double phase_flood_ms_sd = -1.0;
    double phase_flood_ms_median = 0.0;
    uint32_t flood_lambda_stat = 0;
    uint32_t flood_eval_noise_bits = 0;
    uint32_t flood_margin_bits = 0;
    uint32_t flood_noise_bits = 0;
    uint32_t scaling_mod_size = 0;
};

class ThresholdCSVWriter {
    std::ostream* out_;
public:
    ThresholdCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << ThresholdCSVHeader();
    }

    void WriteRow(const ThresholdResult& r) {
        *out_ << r.label << ","
              << r.k << "," << r.m << "," << r.set_size << "," << r.ring_dim << ","
              << r.tau << "," << r.mult_depth << ","
              << std::fixed << std::setprecision(3)
              << r.phase_minhash_ms << "," << r.phase_encode_ms << ","
              << r.phase_encrypt_ms << "," << r.phase_multiply_ms << ","
              << r.phase_rotate_sum_ms << "," << r.phase_mask_ms << ","
              << r.phase_poly_eval_ms << "," << r.phase_decrypt_ms << ","
              << r.total_ms << ","
              << r.memory_bytes << "," << r.ct_size_bytes << ","
              << r.threshold_result << "," << r.threshold_expected << ","
              << r.threshold_correct << ","
              << std::fixed << std::setprecision(6)
              << r.jaccard_computed << "," << r.jaccard_expected << ","
              << r.jaccard_error << "," << r.jaccard_rel_error << ","
              << r.note << ","
              // dispersion columns
              << r.trials << ","
              << std::fixed << std::setprecision(3)
              << r.total_ms_sd << "," << r.total_ms_median << ","
              << r.phase_minhash_ms_sd << "," << r.phase_minhash_ms_median << ","
              << r.phase_encode_ms_sd << "," << r.phase_encode_ms_median << ","
              << r.phase_encrypt_ms_sd << "," << r.phase_encrypt_ms_median << ","
              << r.phase_multiply_ms_sd << "," << r.phase_multiply_ms_median << ","
              << r.phase_rotate_sum_ms_sd << "," << r.phase_rotate_sum_ms_median << ","
              << r.phase_mask_ms_sd << "," << r.phase_mask_ms_median << ","
              << r.phase_poly_eval_ms_sd << "," << r.phase_poly_eval_ms_median << ","
              << r.phase_decrypt_ms_sd << "," << r.phase_decrypt_ms_median << ","
              << r.rel_error_eligible_n << ","
              << std::fixed << std::setprecision(6) << r.j_tau << ","
              << r.match_count << "," << r.matchcount_expected << ","
              << r.fhe_agrees << "," << r.outcome << ","
              << r.hash_randomness << "," << r.hash_seed << ","
              << r.hash_root_seed << "," << r.accuracy_trials << ","
              << std::fixed << std::setprecision(3)
              << r.phase_flood_ms << "," << r.phase_flood_ms_sd << ","
              << r.phase_flood_ms_median << ","
              << r.flood_lambda_stat << "," << r.flood_eval_noise_bits << ","
              << r.flood_margin_bits << "," << r.flood_noise_bits << ","
              << r.scaling_mod_size << "\n";
    }
};

// Sanitize note string: no commas or newlines (CSV safety)
static std::string SanitizeNote(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == ',' || c == '\n' || c == '\r') out += ' ';
        else out += c;
    }
    return out;
}

// Create a SKIPPED row for configurations that fail
static ThresholdResult MakeSkippedRow(const std::string& label, uint32_t k,
                                       uint32_t m, uint32_t tau,
                                       uint32_t mult_depth,
                                       const std::string& reason) {
    ThresholdResult r;
    r.label = label;
    r.k = k;
    r.m = m;
    r.ring_dim = 0;
    r.tau = tau;
    r.mult_depth = mult_depth;
    r.phase_minhash_ms = -1;
    r.phase_encode_ms = -1;
    r.phase_encrypt_ms = -1;
    r.phase_multiply_ms = -1;
    r.phase_rotate_sum_ms = -1;
    r.phase_mask_ms = -1;
    r.phase_poly_eval_ms = -1;
    r.phase_decrypt_ms = -1;
    r.total_ms = -1;
    r.memory_bytes = 0;
    r.ct_size_bytes = 0;
    r.threshold_result = -1;
    r.threshold_expected = -1;
    r.threshold_correct = -1;
    r.note = SanitizeNote(reason);
    return r;
}

static void AddRawTimingSamples(
    std::vector<RawTimingSample>& samples,
    const std::string& producer_id,
    const std::string& profile_id,
    const std::string& cell_id,
    const ThresholdResult& result,
    SampleKind sample_kind,
    uint64_t trial_index,
    uint64_t seed) {
    const auto add = [&](const char* phase, double raw_ms) {
        if (!std::isfinite(raw_ms) || raw_ms < 0.0) {
            throw std::invalid_argument(
                std::string("threshold raw phase is invalid: ") + phase);
        }
        samples.push_back({producer_id, profile_id, cell_id, phase,
                           sample_kind, trial_index, seed, raw_ms});
    };
    add("minhash", result.phase_minhash_ms);
    add("encode", result.phase_encode_ms);
    add("encrypt", result.phase_encrypt_ms);
    add("multiply", result.phase_multiply_ms);
    add("rotate_sum", result.phase_rotate_sum_ms);
    add("mask", result.phase_mask_ms);
    add("poly_eval", result.phase_poly_eval_ms);
    add("flood", result.phase_flood_ms);
    add("decrypt", result.phase_decrypt_ms);
    add("total", result.total_ms);
}

// ============================================================================
// Per-phase timed threshold protocol
// ============================================================================

static ThresholdResult RunTimedThreshold(
    const ThresholdPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    const TruthContext& tc,
    const std::string& label)
{
    Timer timer;
    ThresholdResult tr;
    tr.label = label;
    tr.k = engine.GetParams().k;
    tr.m = engine.GetParams().m;
    tr.set_size = set_x.size();
    tr.ring_dim = engine.GetParams().ring_dim;
    tr.tau = engine.GetParams().threshold_tau;
    tr.mult_depth = engine.GetParams().mult_depth;

    const auto& piccard = engine.GetPiccard();
    const auto& bfv = engine.GetBFVContext();

    // Phase 1: MinHash
    timer.Start();
    auto sig_x = piccard.ComputeSignature(set_x);
    auto sig_y = piccard.ComputeSignature(set_y);
    tr.phase_minhash_ms = timer.ElapsedMs();

    // Phase 2: Encode
    timer.Start();
    auto feat_x = piccard.EncodeSignature(sig_x);
    auto feat_y = piccard.EncodeSignature(sig_y);
    tr.phase_encode_ms = timer.ElapsedMs();

    // Phase 3: Encrypt
    timer.Start();
    auto ct_x = piccard.EncryptFeature(feat_x);
    auto ct_y = piccard.EncryptFeature(feat_y);
    tr.phase_encrypt_ms = timer.ElapsedMs();

    tr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);

    // Phase 4: Multiply (slot-wise)
    timer.Start();
    auto product = bfv.Multiply(ct_x, ct_y);
    tr.phase_multiply_ms = timer.ElapsedMs();

    // Phase 5: Rotate-and-sum
    timer.Start();
    auto result = product;
    for (uint32_t step = 1; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(result, static_cast<int>(step));
        result = bfv.Add(result, rotated);
    }
    tr.phase_rotate_sum_ms = timer.ElapsedMs();

    // Phase 6: Mask slot 0 with e_1 = (1, 0, ..., 0)
    timer.Start();
    std::vector<int64_t> e1(engine.GetParams().ring_dim, 0);
    e1[0] = 1;
    result = bfv.MultiplyPlain(result, e1);
    tr.phase_mask_ms = timer.ElapsedMs();

    // Phase 7: Polynomial evaluation (Paterson-Stockmeyer, precomputed in KeyGen)
    timer.Start();
    result = bfv.EvalPolyBFV(result, engine.GetThresholdPoly());
    tr.phase_poly_eval_ms = timer.ElapsedMs();

    // Phase 7.5: Noise flooding (cloud) — mirrors ThresholdPiccard::Evaluate
    // exit (threshold_piccard.cpp:49): after EvalPolyBFV, NOT rotate-and-sum.
    timer.Start();
    result = bfv.Flood(result);
    tr.phase_flood_ms = timer.ElapsedMs();

    // Phase 8: Decrypt
    timer.Start();
    auto values = bfv.Decrypt(result);
    bool decision = values[0] >= 1;
    tr.phase_decrypt_ms = timer.ElapsedMs();

    tr.total_ms = tr.phase_minhash_ms + tr.phase_encode_ms + tr.phase_encrypt_ms +
                  tr.phase_multiply_ms + tr.phase_rotate_sum_ms + tr.phase_mask_ms +
                  tr.phase_poly_eval_ms + tr.phase_flood_ms + tr.phase_decrypt_ms;

    // flood_lambda_stat keeps plan 8's historical CSV column name; the value
    // comes from the post-rework compatibility bridge (lambda_stat is gone).
    tr.flood_lambda_stat = engine.GetParams().LegacyFloodCoefficientBits();
    tr.flood_eval_noise_bits = engine.GetParams().eval_noise_bits;
    tr.flood_margin_bits = engine.GetParams().flood_margin_bits;
    tr.flood_noise_bits = engine.GetParams().FloodNoiseBits();
    tr.scaling_mod_size = engine.GetParams().scaling_mod_size;
    tr.memory_bytes = MemoryTracker::GetPeakRSS();
    tr.threshold_result = decision ? 1 : 0;
    tr.threshold_expected = tc.truth;
    tr.threshold_correct = ((decision ? 1 : 0) == tc.truth) ? 1 : 0;
    tr.jaccard_expected = tc.j_true;
    tr.j_tau = tc.j_tau;
    tr.match_count = tc.match_count;
    tr.matchcount_expected = tc.matchcount_expected;
    tr.fhe_agrees = ((decision ? 1 : 0) == tc.matchcount_expected) ? 1 : 0;
    tr.outcome = OutcomeName(tc.truth, decision ? 1 : 0);
    // Timing provenance (plan 9-2 convention): timing sweeps run on the
    // engine's fixed CRS. Record it honestly in BOTH seed fields — the engine
    // default is 42 regardless of --seed, so config.seed here would be false
    // provenance. accuracy_trials stays 0 (timing rows claim no accuracy).
    tr.hash_randomness = "fixed";
    tr.hash_seed = engine.GetParams().hash_seed;
    tr.hash_root_seed = engine.GetParams().hash_seed;

    return tr;
}

// ============================================================================
// Multi-trial median helper
// ============================================================================

static ThresholdResult RunMultiTrialThreshold(
    const ThresholdPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    const TruthContext& tc,
    const std::string& label,
    size_t trials,
    RawTimingArtifact* raw_artifact = nullptr,
    uint64_t raw_seed = 0,
    double raw_seed_domain = 0.5)
{
    // Warmup (discarded)
    const auto warmup = RunTimedThreshold(engine, set_x, set_y, tc, "warmup");
    if (raw_artifact != nullptr) {
        AddRawTimingSamples(raw_artifact->samples, raw_artifact->producer_id,
                            raw_artifact->profile_id, raw_artifact->cell_id,
                            warmup, SampleKind::DiscardedWarmup, 0,
                            raw_seed);
    }

    std::vector<double> v_total, v_minhash, v_encode, v_encrypt;
    std::vector<double> v_multiply, v_rotate, v_mask, v_poly, v_flood, v_decrypt;
    size_t ct_size = 0;
    int last_result = 0, last_expected = 0, last_correct = 0;

    for (size_t t = 0; t < trials; t++) {
        auto tr = RunTimedThreshold(engine, set_x, set_y, tc, label);
        if (raw_artifact != nullptr) {
            AddRawTimingSamples(
                raw_artifact->samples, raw_artifact->producer_id,
                raw_artifact->profile_id, raw_artifact->cell_id, tr,
                SampleKind::Measured, static_cast<uint64_t>(t),
                TrialSeed(raw_seed, t, raw_seed_domain));
        }
        v_total.push_back(tr.total_ms);
        v_minhash.push_back(tr.phase_minhash_ms);
        v_encode.push_back(tr.phase_encode_ms);
        v_encrypt.push_back(tr.phase_encrypt_ms);
        v_multiply.push_back(tr.phase_multiply_ms);
        v_rotate.push_back(tr.phase_rotate_sum_ms);
        v_mask.push_back(tr.phase_mask_ms);
        v_poly.push_back(tr.phase_poly_eval_ms);
        v_flood.push_back(tr.phase_flood_ms);
        v_decrypt.push_back(tr.phase_decrypt_ms);
        ct_size = tr.ct_size_bytes;
        last_result = tr.threshold_result;
        last_expected = tr.threshold_expected;
        last_correct = tr.threshold_correct;
    }

    auto d_tot = ComputeDispersion(v_total);
    auto d_mnh = ComputeDispersion(v_minhash);
    auto d_enc = ComputeDispersion(v_encode);
    auto d_cry = ComputeDispersion(v_encrypt);
    auto d_mul = ComputeDispersion(v_multiply);
    auto d_rot = ComputeDispersion(v_rotate);
    auto d_msk = ComputeDispersion(v_mask);
    auto d_pol = ComputeDispersion(v_poly);
    auto d_fld = ComputeDispersion(v_flood);
    auto d_dec = ComputeDispersion(v_decrypt);

    ThresholdResult result;
    result.label = label;
    result.k = engine.GetParams().k;
    result.m = engine.GetParams().m;
    result.set_size = set_x.size();
    result.ring_dim = engine.GetParams().ring_dim;
    result.tau = engine.GetParams().threshold_tau;
    result.mult_depth = engine.GetParams().mult_depth;
    result.total_ms           = d_tot.mean; result.total_ms_sd           = d_tot.sd; result.total_ms_median           = d_tot.median;
    result.phase_minhash_ms   = d_mnh.mean; result.phase_minhash_ms_sd   = d_mnh.sd; result.phase_minhash_ms_median   = d_mnh.median;
    result.phase_encode_ms    = d_enc.mean; result.phase_encode_ms_sd    = d_enc.sd; result.phase_encode_ms_median    = d_enc.median;
    result.phase_encrypt_ms   = d_cry.mean; result.phase_encrypt_ms_sd   = d_cry.sd; result.phase_encrypt_ms_median   = d_cry.median;
    result.phase_multiply_ms  = d_mul.mean; result.phase_multiply_ms_sd  = d_mul.sd; result.phase_multiply_ms_median  = d_mul.median;
    result.phase_rotate_sum_ms = d_rot.mean; result.phase_rotate_sum_ms_sd = d_rot.sd; result.phase_rotate_sum_ms_median = d_rot.median;
    result.phase_mask_ms      = d_msk.mean; result.phase_mask_ms_sd      = d_msk.sd; result.phase_mask_ms_median      = d_msk.median;
    result.phase_poly_eval_ms = d_pol.mean; result.phase_poly_eval_ms_sd = d_pol.sd; result.phase_poly_eval_ms_median = d_pol.median;
    result.phase_flood_ms     = d_fld.mean; result.phase_flood_ms_sd     = d_fld.sd; result.phase_flood_ms_median     = d_fld.median;
    result.phase_decrypt_ms   = d_dec.mean; result.phase_decrypt_ms_sd   = d_dec.sd; result.phase_decrypt_ms_median   = d_dec.median;
    result.memory_bytes = MemoryTracker::GetPeakRSS();
    result.ct_size_bytes = ct_size;
    result.trials = trials;
    result.threshold_result = last_result;
    result.threshold_expected = last_expected;
    result.threshold_correct = last_correct;
    // threshold benchmark has no per-trial jaccard fields in timing mode
    result.rel_error_eligible_n = 0;

    result.threshold_expected = tc.truth;
    result.jaccard_expected = tc.j_true;
    result.j_tau = tc.j_tau;
    result.match_count = tc.match_count;
    result.matchcount_expected = tc.matchcount_expected;
    result.outcome = OutcomeName(tc.truth, last_result);
    result.fhe_agrees = (last_result == tc.matchcount_expected) ? 1 : 0;
    result.hash_randomness = "fixed";
    result.hash_seed = engine.GetParams().hash_seed;
    result.hash_root_seed = engine.GetParams().hash_seed;

    // flood_lambda_stat keeps plan 8's historical CSV column name; the value
    // comes from the post-rework compatibility bridge (lambda_stat is gone).
    result.flood_lambda_stat = engine.GetParams().LegacyFloodCoefficientBits();
    result.flood_eval_noise_bits = engine.GetParams().eval_noise_bits;
    result.flood_margin_bits = engine.GetParams().flood_margin_bits;
    result.flood_noise_bits = engine.GetParams().FloodNoiseBits();
    result.scaling_mod_size = engine.GetParams().scaling_mod_size;

    return result;
}

// Try to create and initialize a threshold engine; returns nullptr on failure
static std::unique_ptr<ThresholdPiccard> TryCreateThresholdEngine(
    uint32_t k, uint32_t m, uint32_t tau, SecurityLevel security,
    PiccardParams& out_params, std::string& out_error)
{
    out_params = PiccardParams{};
    out_params.k = k;
    out_params.m = m;
    out_params.threshold_mode = true;
    out_params.threshold_tau = tau;
    out_params.security = security;

    try {
        out_params.Validate();
    } catch (const std::exception& e) {
        out_error = e.what();
        return nullptr;
    } catch (...) {
        out_error = "unknown exception during Validate()";
        return nullptr;
    }

    // Pre-check: plaintext modulus must satisfy p ≡ 1 (mod 2N).
    // OpenFHE may require a larger ring_dim than Validate() computed
    // (based on mult_depth + security level). If the computed ring_dim
    // already violates the plaintext constraint, skip.
    // For p = 65537 (2^16+1), max ring_dim is 32768 (cyclotomic 65536).
    // Higher mult_depth at STD128 needs ring_dim > 32768, which fails.
    {
        uint64_t p = out_params.plaintext_mod;
        uint64_t two_n = 2ULL * out_params.ring_dim;
        if ((p - 1) % two_n != 0) {
            out_error = "ring_dim " + std::to_string(out_params.ring_dim) +
                        " incompatible with plaintext_mod " + std::to_string(p) +
                        " (mult_depth=" + std::to_string(out_params.mult_depth) + ")";
            return nullptr;
        }
        // Also reject if mult_depth is so high that OpenFHE will internally
        // expand ring_dim beyond what the plaintext modulus supports.
        // Conservative limit: if mult_depth > 21 at STD128, ring_dim
        // will be 65536+ which exceeds p=65537's constraint.
        if (out_params.mult_depth > 21 && security == SecurityLevel::STD128) {
            out_error = "mult_depth " + std::to_string(out_params.mult_depth) +
                        " too high for STD128 (max supported: 21)";
            return nullptr;
        }
    }

    try {
        auto engine = std::make_unique<ThresholdPiccard>(out_params);
        engine->KeyGen();
        // Update ring_dim from engine (OpenFHE may have chosen differently)
        out_params.ring_dim = engine->GetParams().ring_dim;
        return engine;
    } catch (const std::exception& e) {
        out_error = e.what();
        return nullptr;
    } catch (...) {
        out_error = "unknown exception during engine construction";
        return nullptr;
    }
}

static void RunRawTimingThreshold(const BenchmarkConfig& config,
                                  const RawTimingOptions& options,
                                  ThresholdCSVWriter& csv) {
    const uint64_t measured_trials = options.measured_trials;
    if (measured_trials == 0) {
        throw std::invalid_argument("raw timing measured trial count is zero");
    }
    if (options.profile_id == kReadinessTimingProfileVersion &&
        config.security_level != SecurityLevel::TOY) {
        throw std::invalid_argument("readiness raw timing requires TOY security");
    }
    if (options.profile_id == kPaperTimingProfileVersion &&
        config.security_level == SecurityLevel::TOY) {
        throw std::invalid_argument(
            "paper raw timing does not permit TOY security");
    }

    const uint32_t tau = static_cast<uint32_t>(0.6 * config.k);
    PiccardParams params;
    std::string error;
    auto engine = TryCreateThresholdEngine(config.k, config.m, tau,
                                           config.security_level, params, error);
    if (!engine) {
        throw std::runtime_error("raw threshold timing cannot create engine: " +
                                 error);
    }
    // Timing uses one fixed CRS.  Bind it to the supplied root seed so the
    // sidecar's seed column is honest and reruns are reproducible.
    engine->SetHashSeed(config.seed);

    const double intersection_fraction =
        config.target_jaccard == 0.0
            ? 0.0
            : (2.0 * config.target_jaccard) /
                  (1.0 + config.target_jaccard);
    auto [set_a, set_b] = MakeSetsWithOverlap(
        config.set_size, intersection_fraction);
    const TruthContext truth = MakeTruthContext(*engine, set_a, set_b);
    const std::string cell_id =
        "threshold-k" + std::to_string(config.k) + "-m" +
        std::to_string(config.m) + "-n" + std::to_string(config.set_size) +
        "-tau" + std::to_string(tau);

    RawTimingArtifact artifact;
    artifact.producer_id = kRawTimingProducerId;
    artifact.profile_id = options.profile_id;
    artifact.cell_id = cell_id;
    artifact.warmup_policy = WarmupPolicy::DiscardOne;
    if (artifact.warmup_policy != ExpectedWarmupPolicy(artifact.producer_id)) {
        throw std::logic_error("bench_threshold raw warmup policy drift");
    }
    artifact.expected_measured = measured_trials;
    auto row = RunMultiTrialThreshold(
        *engine, set_a, set_b, truth, cell_id + "_timing",
        static_cast<size_t>(measured_trials), &artifact, config.seed,
        config.target_jaccard);
    csv.WriteRow(row);

    ValidateRawTimingArtifact(artifact);
    WriteRawTimingArtifactsV1(options.output_directory, {artifact});
}

// ============================================================================
// Scenario 1: Varying k
// ============================================================================

static void BenchVaryK(const BenchmarkConfig& config,
                       ThresholdCSVWriter& csv) {
    std::vector<uint32_t> all_k = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);
    auto [sa, sb] = MakeSetsWithOverlap(config.set_size, 0.5);

    for (uint32_t k : all_k) {
        uint32_t tau = static_cast<uint32_t>(0.6 * k);
        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(k, config.m, tau,
                                                config.security_level,
                                                params, error);
        if (!engine) {
            std::cerr << "  WARNING: Skipped k=" << k << ": " << error << "\n";
            auto skipped = MakeSkippedRow(
                "SKIPPED_k" + std::to_string(k), k, config.m, tau,
                params.mult_depth, error);
            csv.WriteRow(skipped);
            continue;
        }

        try {
            // Plaintext truth context: no FHE run needed for a reference bit.
            auto tc = MakeTruthContext(*engine, sa, sb);

            std::string label = "vary_k_" + std::to_string(k);
            auto tr = RunMultiTrialThreshold(*engine, sa, sb, tc, label,
                                             config.trials);
            csv.WriteRow(tr);

            std::cerr << "  k=" << k << " tau=" << tau
                      << " depth=" << tr.mult_depth
                      << " N=" << tr.ring_dim
                      << " poly_eval=" << tr.phase_poly_eval_ms << "ms"
                      << " total=" << tr.total_ms << "ms\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: k=" << k << " failed: " << e.what() << "\n";
            auto skipped = MakeSkippedRow(
                "SKIPPED_k" + std::to_string(k), k, config.m, tau,
                params.mult_depth, e.what());
            csv.WriteRow(skipped);
        } catch (...) {
            std::cerr << "  WARNING: k=" << k << " failed (unknown)\n";
            auto skipped = MakeSkippedRow(
                "SKIPPED_k" + std::to_string(k), k, config.m, tau,
                params.mult_depth, "unknown exception");
            csv.WriteRow(skipped);
        }
    }
}

// ============================================================================
// Scenario 2: Varying m
// ============================================================================

static void BenchVaryM(const BenchmarkConfig& config,
                       ThresholdCSVWriter& csv) {
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, config.security_level);
    uint32_t tau = static_cast<uint32_t>(0.6 * config.k);
    auto [sa, sb] = MakeSetsWithOverlap(config.set_size, 0.5);

    for (uint32_t m : m_values) {
        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(config.k, m, tau,
                                                config.security_level,
                                                params, error);
        if (!engine) {
            std::cerr << "  WARNING: Skipped m=" << m << ": " << error << "\n";
            auto skipped = MakeSkippedRow(
                "SKIPPED_m" + std::to_string(m), config.k, m, tau,
                params.mult_depth, error);
            csv.WriteRow(skipped);
            continue;
        }

        try {
            // Plaintext truth context: no FHE run needed for a reference bit.
            auto tc = MakeTruthContext(*engine, sa, sb);

            std::string label = "vary_m_" + std::to_string(m);
            auto tr = RunMultiTrialThreshold(*engine, sa, sb, tc, label,
                                             config.trials);
            csv.WriteRow(tr);

            std::cerr << "  m=" << m
                      << " poly_eval=" << tr.phase_poly_eval_ms << "ms"
                      << " total=" << tr.total_ms << "ms"
                      << " correct=" << tr.threshold_correct << "\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: m=" << m << " failed: " << e.what() << "\n";
            auto skipped = MakeSkippedRow(
                "SKIPPED_m" + std::to_string(m), config.k, m, tau,
                params.mult_depth, e.what());
            csv.WriteRow(skipped);
        } catch (...) {
            std::cerr << "  WARNING: m=" << m << " failed (unknown)\n";
            auto skipped = MakeSkippedRow(
                "SKIPPED_m" + std::to_string(m), config.k, m, tau,
                params.mult_depth, "unknown exception");
            csv.WriteRow(skipped);
        }
    }
}

// ============================================================================
// Scenario 3: Varying set size
// ============================================================================

static void BenchVarySetSize(const BenchmarkConfig& config,
                              ThresholdCSVWriter& csv) {
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000, 100000}, config.security_level);
    uint32_t tau = static_cast<uint32_t>(0.6 * config.k);

    PiccardParams params;
    std::string error;
    auto engine = TryCreateThresholdEngine(config.k, config.m, tau,
                                            config.security_level,
                                            params, error);
    if (!engine) {
        std::cerr << "  WARNING: Cannot create engine: " << error << "\n";
        return;
    }

    for (size_t sz : sizes) {
        auto [sa, sb] = MakeSetsWithOverlap(sz, 0.5);

        try {
            // Plaintext truth context: no FHE run needed for a reference bit.
            auto tc = MakeTruthContext(*engine, sa, sb);

            std::string label = "vary_size_" + std::to_string(sz);
            auto tr = RunMultiTrialThreshold(*engine, sa, sb, tc, label,
                                             config.trials);
            csv.WriteRow(tr);

            std::cerr << "  size=" << sz
                      << " total=" << tr.total_ms << "ms"
                      << " correct=" << tr.threshold_correct << "\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: size=" << sz << " failed: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "  WARNING: size=" << sz << " failed (unknown)\n";
        }
    }
}

// ============================================================================
// Accuracy: threshold decision correctness with error/rel_error
// ============================================================================

static void BenchAccuracyVaryK(const BenchmarkConfig& config,
                                ThresholdCSVWriter& csv) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    for (uint32_t k : k_values) {
        uint32_t tau = static_cast<uint32_t>(0.6 * k);
        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(k, config.m, tau,
                                                config.security_level,
                                                params, error);
        if (!engine) {
            std::cerr << "  WARNING: Skipped k=" << k << ": " << error << "\n";
            continue;
        }

        size_t total_correct = 0;
        size_t total_count = 0;
        size_t total_fp = 0, total_fn = 0, total_disagree = 0;

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(
                    config.set_size, frac, rng);

                // Per-trial CRS (hash-seed-crs convention): resampled by
                // default so trials are independent draws of the hash family;
                // --hash_randomness=fixed keeps the engine's CRS for audits.
                const uint64_t trial_hash_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? HashTrialSeed(config.seed, t, frac)
                        : engine->GetParams().hash_seed;
                engine->SetHashSeed(trial_hash_seed);

                // Ground truth from the exact Jaccard; the match count is kept
                // separately to certify BFV exactness (fhe_agrees).
                auto tc = MakeTruthContext(*engine, sa, sb);

                bool result = engine->Run(sa, sb);   // FHE decision
                bool correct = (result ? 1 : 0) == tc.truth;
                if (correct) total_correct++;
                total_count++;
                if (tc.truth == 0 && result) total_fp++;
                if (tc.truth == 1 && !result) total_fn++;
                if ((result ? 1 : 0) != tc.matchcount_expected) total_disagree++;

                // Bias-corrected estimate from the plaintext match count
                // (identical formula to Piccard::Decrypt).
                double raw_ratio = static_cast<double>(tc.match_count) / k;
                double j_hat = (raw_ratio - 1.0 / config.m) /
                               (1.0 - 1.0 / config.m);
                j_hat = std::max(0.0, std::min(1.0, j_hat));

                ThresholdResult tr;
                tr.label = "accuracy_k" + std::to_string(k) +
                           "_" + std::to_string(frac) +
                           "_t" + std::to_string(t);
                tr.k = k;
                tr.m = config.m;
                tr.set_size = config.set_size;
                tr.ring_dim = engine->GetParams().ring_dim;
                tr.tau = tau;
                tr.mult_depth = engine->GetParams().mult_depth;
                tr.threshold_result = result ? 1 : 0;
                tr.threshold_expected = tc.truth;
                tr.threshold_correct = correct ? 1 : 0;
                tr.jaccard_computed = j_hat;
                tr.jaccard_expected = tc.j_true;
                tr.jaccard_error = std::abs(j_hat - tc.j_true);
                tr.jaccard_rel_error =
                    (tc.j_true > 0.0) ? (tr.jaccard_error / tc.j_true) : -1.0;
                tr.j_tau = tc.j_tau;
                tr.match_count = tc.match_count;
                tr.matchcount_expected = tc.matchcount_expected;
                tr.fhe_agrees =
                    ((result ? 1 : 0) == tc.matchcount_expected) ? 1 : 0;
                tr.outcome = OutcomeName(tc.truth, result ? 1 : 0);
                tr.hash_randomness = HashRandomnessName(config.hash_randomness);
                tr.hash_seed = trial_hash_seed;
                // Plan 9 convention: root = config.seed when resampled; in
                // fixed mode record the CRS actually used — here the engine
                // default (42), which is NOT config.seed in this path.
                tr.hash_root_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? config.seed
                        : trial_hash_seed;
                tr.accuracy_trials = 1;   // one accuracy sample per row
                // phase_flood_ms stays 0: the accuracy path floods inside
                // engine->Run() (library exit) and is not phase-timed.
                tr.flood_lambda_stat = engine->GetParams().LegacyFloodCoefficientBits();
                tr.flood_eval_noise_bits = engine->GetParams().eval_noise_bits;
                tr.flood_margin_bits = engine->GetParams().flood_margin_bits;
                tr.flood_noise_bits = engine->GetParams().FloodNoiseBits();
                tr.scaling_mod_size = engine->GetParams().scaling_mod_size;
                csv.WriteRow(tr);
            }
        }

        double accuracy = (total_count > 0)
            ? 100.0 * total_correct / total_count : 0.0;
        std::cerr << "  k=" << k << " tau=" << tau
                  << " trueJ_acc=" << std::fixed << std::setprecision(1)
                  << accuracy << "%"
                  << " FP=" << total_fp << " FN=" << total_fn
                  << " bfv_disagree=" << total_disagree
                  << " (" << total_correct << "/" << total_count << ")\n";
    }
}

static void BenchAccuracyVaryM(const BenchmarkConfig& config,
                                ThresholdCSVWriter& csv) {
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};
    uint32_t tau = static_cast<uint32_t>(0.6 * config.k);

    for (uint32_t m : m_values) {
        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(config.k, m, tau,
                                                config.security_level,
                                                params, error);
        if (!engine) {
            std::cerr << "  WARNING: Skipped m=" << m << ": " << error << "\n";
            continue;
        }

        size_t total_correct = 0;
        size_t total_count = 0;
        size_t total_fp = 0, total_fn = 0, total_disagree = 0;

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(
                    config.set_size, frac, rng);

                // Per-trial CRS (hash-seed-crs convention): resampled by
                // default so trials are independent draws of the hash family;
                // --hash_randomness=fixed keeps the engine's CRS for audits.
                const uint64_t trial_hash_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? HashTrialSeed(config.seed, t, frac)
                        : engine->GetParams().hash_seed;
                engine->SetHashSeed(trial_hash_seed);

                // Ground truth from the exact Jaccard; the match count is kept
                // separately to certify BFV exactness (fhe_agrees).
                auto tc = MakeTruthContext(*engine, sa, sb);

                bool result = engine->Run(sa, sb);   // FHE decision
                bool correct = (result ? 1 : 0) == tc.truth;
                if (correct) total_correct++;
                total_count++;
                if (tc.truth == 0 && result) total_fp++;
                if (tc.truth == 1 && !result) total_fn++;
                if ((result ? 1 : 0) != tc.matchcount_expected) total_disagree++;

                // Bias-corrected estimate from the plaintext match count
                // (identical formula to Piccard::Decrypt).
                double raw_ratio = static_cast<double>(tc.match_count) / config.k;
                double j_hat = (raw_ratio - 1.0 / m) /
                               (1.0 - 1.0 / m);
                j_hat = std::max(0.0, std::min(1.0, j_hat));

                ThresholdResult tr;
                tr.label = "accuracy_m" + std::to_string(m) +
                           "_" + std::to_string(frac) +
                           "_t" + std::to_string(t);
                tr.k = config.k;
                tr.m = m;
                tr.set_size = config.set_size;
                tr.ring_dim = engine->GetParams().ring_dim;
                tr.tau = tau;
                tr.mult_depth = engine->GetParams().mult_depth;
                tr.threshold_result = result ? 1 : 0;
                tr.threshold_expected = tc.truth;
                tr.threshold_correct = correct ? 1 : 0;
                tr.jaccard_computed = j_hat;
                tr.jaccard_expected = tc.j_true;
                tr.jaccard_error = std::abs(j_hat - tc.j_true);
                tr.jaccard_rel_error =
                    (tc.j_true > 0.0) ? (tr.jaccard_error / tc.j_true) : -1.0;
                tr.j_tau = tc.j_tau;
                tr.match_count = tc.match_count;
                tr.matchcount_expected = tc.matchcount_expected;
                tr.fhe_agrees =
                    ((result ? 1 : 0) == tc.matchcount_expected) ? 1 : 0;
                tr.outcome = OutcomeName(tc.truth, result ? 1 : 0);
                tr.hash_randomness = HashRandomnessName(config.hash_randomness);
                tr.hash_seed = trial_hash_seed;
                // Plan 9 convention: root = config.seed when resampled; in
                // fixed mode record the CRS actually used — here the engine
                // default (42), which is NOT config.seed in this path.
                tr.hash_root_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? config.seed
                        : trial_hash_seed;
                tr.accuracy_trials = 1;   // one accuracy sample per row
                // phase_flood_ms stays 0: the accuracy path floods inside
                // engine->Run() (library exit) and is not phase-timed.
                tr.flood_lambda_stat = engine->GetParams().LegacyFloodCoefficientBits();
                tr.flood_eval_noise_bits = engine->GetParams().eval_noise_bits;
                tr.flood_margin_bits = engine->GetParams().flood_margin_bits;
                tr.flood_noise_bits = engine->GetParams().FloodNoiseBits();
                tr.scaling_mod_size = engine->GetParams().scaling_mod_size;
                csv.WriteRow(tr);
            }
        }

        double accuracy = (total_count > 0)
            ? 100.0 * total_correct / total_count : 0.0;
        std::cerr << "  m=" << m << " tau=" << tau
                  << " trueJ_acc=" << std::fixed << std::setprecision(1)
                  << accuracy << "%"
                  << " FP=" << total_fp << " FN=" << total_fn
                  << " bfv_disagree=" << total_disagree
                  << " (" << total_correct << "/" << total_count << ")\n";
    }
}

static void BenchAccuracyVarySetSize(const BenchmarkConfig& config,
                                      ThresholdCSVWriter& csv) {
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};
    uint32_t tau = static_cast<uint32_t>(0.6 * config.k);

    PiccardParams params;
    std::string error;
    auto engine = TryCreateThresholdEngine(config.k, config.m, tau,
                                            config.security_level,
                                            params, error);
    if (!engine) {
        std::cerr << "  WARNING: Cannot create engine: " << error << "\n";
        return;
    }

    for (size_t sz : sizes) {
        size_t total_correct = 0;
        size_t total_count = 0;
        size_t total_fp = 0, total_fn = 0, total_disagree = 0;

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(sz, frac, rng);

                // Per-trial CRS (hash-seed-crs convention): resampled by
                // default so trials are independent draws of the hash family;
                // --hash_randomness=fixed keeps the engine's CRS for audits.
                const uint64_t trial_hash_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? HashTrialSeed(config.seed, t, frac)
                        : engine->GetParams().hash_seed;
                engine->SetHashSeed(trial_hash_seed);

                // Ground truth from the exact Jaccard; the match count is kept
                // separately to certify BFV exactness (fhe_agrees).
                auto tc = MakeTruthContext(*engine, sa, sb);

                bool result = engine->Run(sa, sb);   // FHE decision
                bool correct = (result ? 1 : 0) == tc.truth;
                if (correct) total_correct++;
                total_count++;
                if (tc.truth == 0 && result) total_fp++;
                if (tc.truth == 1 && !result) total_fn++;
                if ((result ? 1 : 0) != tc.matchcount_expected) total_disagree++;

                // Bias-corrected estimate from the plaintext match count
                // (identical formula to Piccard::Decrypt).
                double raw_ratio = static_cast<double>(tc.match_count) / config.k;
                double j_hat = (raw_ratio - 1.0 / config.m) /
                               (1.0 - 1.0 / config.m);
                j_hat = std::max(0.0, std::min(1.0, j_hat));

                ThresholdResult tr;
                tr.label = "accuracy_size" + std::to_string(sz) +
                           "_" + std::to_string(frac) +
                           "_t" + std::to_string(t);
                tr.k = config.k;
                tr.m = config.m;
                tr.set_size = sz;
                tr.ring_dim = engine->GetParams().ring_dim;
                tr.tau = tau;
                tr.mult_depth = engine->GetParams().mult_depth;
                tr.threshold_result = result ? 1 : 0;
                tr.threshold_expected = tc.truth;
                tr.threshold_correct = correct ? 1 : 0;
                tr.jaccard_computed = j_hat;
                tr.jaccard_expected = tc.j_true;
                tr.jaccard_error = std::abs(j_hat - tc.j_true);
                tr.jaccard_rel_error =
                    (tc.j_true > 0.0) ? (tr.jaccard_error / tc.j_true) : -1.0;
                tr.j_tau = tc.j_tau;
                tr.match_count = tc.match_count;
                tr.matchcount_expected = tc.matchcount_expected;
                tr.fhe_agrees =
                    ((result ? 1 : 0) == tc.matchcount_expected) ? 1 : 0;
                tr.outcome = OutcomeName(tc.truth, result ? 1 : 0);
                tr.hash_randomness = HashRandomnessName(config.hash_randomness);
                tr.hash_seed = trial_hash_seed;
                // Plan 9 convention: root = config.seed when resampled; in
                // fixed mode record the CRS actually used — here the engine
                // default (42), which is NOT config.seed in this path.
                tr.hash_root_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? config.seed
                        : trial_hash_seed;
                tr.accuracy_trials = 1;   // one accuracy sample per row
                // phase_flood_ms stays 0: the accuracy path floods inside
                // engine->Run() (library exit) and is not phase-timed.
                tr.flood_lambda_stat = engine->GetParams().LegacyFloodCoefficientBits();
                tr.flood_eval_noise_bits = engine->GetParams().eval_noise_bits;
                tr.flood_margin_bits = engine->GetParams().flood_margin_bits;
                tr.flood_noise_bits = engine->GetParams().FloodNoiseBits();
                tr.scaling_mod_size = engine->GetParams().scaling_mod_size;
                csv.WriteRow(tr);
            }
        }

        double accuracy = (total_count > 0)
            ? 100.0 * total_correct / total_count : 0.0;
        std::cerr << "  size=" << sz << " tau=" << tau
                  << " trueJ_acc=" << std::fixed << std::setprecision(1)
                  << accuracy << "%"
                  << " FP=" << total_fp << " FN=" << total_fn
                  << " bfv_disagree=" << total_disagree
                  << " (" << total_correct << "/" << total_count << ")\n";
    }
}

// ============================================================================
// FP/FN boundary sweep (R3-4) -- Layer A: plaintext-only statistics
//
// The FP/FN behaviour of the threshold decision is a property of the MinHash
// estimator, not of BFV (Layer B certifies fhe_agrees == 1 separately). So
// this sweep runs entirely on plaintext signatures, which makes thousands of
// trials per grid point affordable, densely sampled inside J_tau +/- 3 sigma
// where the decision error actually lives.
// ============================================================================

static void BenchFpfnVaryK(const BenchmarkConfig& config,
                           ThresholdCSVWriter& csv) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>(
        {16, 32, 64, 128, 256, 512}, config.security_level);
    const uint32_t m = config.m;
    const int kPoints = 21;

    for (uint32_t k : k_values) {
        uint32_t tau = static_cast<uint32_t>(0.6 * k);
        const double j_tau = JaccardThreshold(tau, k, m);
        const double sigma = JaccardEstimatorSigma(j_tau, k, m);

        size_t n_fp = 0, n_fn = 0, n_neg = 0, n_pos = 0;

        for (int p = 0; p < kPoints; p++) {
            // Evenly spaced on [J_tau - 3 sigma, J_tau + 3 sigma]
            double z = 3.0 * (2.0 * p / (kPoints - 1) - 1.0);
            double j_target = j_tau + z * sigma;
            j_target = std::max(0.02, std::min(0.98, j_target));
            double alpha = 2.0 * j_target / (1.0 + j_target);

            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, alpha));
                auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(
                    config.set_size, alpha, rng);
                double j_true = ExactJaccard(sa, sb);

                const uint64_t crs =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? HashTrialSeed(config.seed, t, alpha)
                        : config.seed;
                MinHasher hasher(k, UINT64_MAX, crs);
                auto sig_x = hasher.ComputeSignature(sa);
                auto sig_y = hasher.ComputeSignature(sb);

                int64_t mc = BucketMatchCount(sig_x, sig_y, m);
                int decision = (mc >= static_cast<int64_t>(tau)) ? 1 : 0;
                int truth = (j_true >= j_tau) ? 1 : 0;

                if (truth) { n_pos++; if (!decision) n_fn++; }
                else       { n_neg++; if (decision)  n_fp++; }

                double raw_ratio = static_cast<double>(mc) / k;
                double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);
                j_hat = std::max(0.0, std::min(1.0, j_hat));

                ThresholdResult tr;
                tr.label = "fpfn_k" + std::to_string(k) +
                           "_p" + std::to_string(p) +
                           "_t" + std::to_string(t);
                tr.k = k;
                tr.m = m;
                tr.set_size = config.set_size;
                tr.ring_dim = 0;              // plaintext: no FHE instance
                tr.tau = tau;
                tr.mult_depth = 0;
                tr.threshold_result = decision;
                tr.threshold_expected = truth;
                tr.threshold_correct = (decision == truth) ? 1 : 0;
                tr.jaccard_computed = j_hat;
                tr.jaccard_expected = j_true;
                tr.jaccard_error = std::abs(j_hat - j_true);
                tr.jaccard_rel_error =
                    (j_true > 0.0) ? (tr.jaccard_error / j_true) : -1.0;
                tr.j_tau = j_tau;
                tr.match_count = mc;
                tr.matchcount_expected = decision;  // identical by construction
                tr.fhe_agrees = -1;                 // no FHE in this mode
                tr.outcome = OutcomeName(truth, decision);
                tr.hash_randomness = HashRandomnessName(config.hash_randomness);
                tr.hash_seed = crs;
                // Both modes: config.seed is true provenance here. Resampled:
                // it is the derivation root of HashTrialSeed. Fixed: the
                // hasher above is constructed with config.seed directly, so
                // it IS the actual CRS (no engine default in this mode).
                tr.hash_root_seed = config.seed;
                tr.accuracy_trials = 1;
                // Flood fields keep their defaults (means/constants 0, sd -1):
                // plaintext-only mode, no sized params — FloodNoiseBits()
                // must not be called here (Task 5b Step 4).
                csv.WriteRow(tr);
            }
        }

        std::cerr << "  k=" << k << " tau=" << tau
                  << std::fixed << std::setprecision(4)
                  << " J_tau=" << j_tau << " sigma=" << sigma
                  << " FP=" << n_fp << "/" << n_neg
                  << " FN=" << n_fn << "/" << n_pos << "\n";
    }
}

// ============================================================================
// u_tau construction & evaluation parameter dump (R3-4 paper table)
// ============================================================================

static void BenchSpecDump(const BenchmarkConfig& config) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>(
        {16, 32, 64, 128, 256, 512}, config.security_level);

    // The historical timing/accuracy writer remains separate.  Spec mode
    // has an additive successor contract so the old ring/depth aliases cannot
    // hide the complete live context provenance.
    std::cout << ThresholdSpecCSVHeader();

    for (uint32_t k : k_values) {
        uint32_t tau = static_cast<uint32_t>(0.6 * k);

        // Paterson-Stockmeyer shape for degree k -- mirrors
        // PiccardParams::DeriveWithoutFlooding / BFVContext::EvalPolyBFV.
        uint32_t s = 1;
        while (s * s < k + 1) s++;
        uint32_t baby_depth = 0;
        for (uint32_t v = s; v > 1;) {
            baby_depth++;
            if (v % 2 == 1) v--; else v /= 2;
        }
        uint32_t num_chunks = (k + s) / s;
        uint32_t giant_mults = num_chunks - 1;

        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(k, config.m, tau,
                                               config.security_level,
                                               params, error);
        if (!engine) {
            ThresholdSpecRow row;
            row.k = k;
            row.tau = tau;
            row.degree = k;
            row.ps_baby_s = s;
            row.ps_num_chunks = num_chunks;
            row.baby_depth = baby_depth;
            row.giant_mults = giant_mults;
            row.natural_mult_depth = params.natural_mult_depth;
            row.status = "SKIPPED";
            row.note = SanitizeNote(error);
            // The serializer emits N/A for every context-dependent field in
            // this branch; no context or residual value is invented.
            WriteThresholdSpecRow(std::cout, row);
            std::cerr << "  k=" << k << " SKIPPED: " << error << "\n";
            continue;
        }

        const auto& P = engine->GetParams();
        const auto& bfv = engine->GetBFVContext();
        const auto provenance = MakePiccardBenchmarkProvenance(bfv);
        Timer timer;
        timer.Start();
        auto poly = BuildThresholdPoly(tau, k, P.plaintext_mod);
        double poly_ms = timer.ElapsedMs();

        std::vector<uint64_t> probe(100);
        for (uint64_t i = 0; i < 100; i++) probe[i] = i;
        auto ct = engine->Encrypt(probe);
        size_t ct_bytes = CiphertextSizer::GetSerializedSize(ct);

        const auto required_u32 = [](const std::optional<uint32_t>& value,
                                     const char* field) {
            if (!value.has_value() || *value == 0)
                throw std::runtime_error(
                    std::string("threshold provenance missing ") + field);
            return *value;
        };
        const auto required_u64 = [](const std::optional<uint64_t>& value,
                                     const char* field) {
            if (!value.has_value() || *value == 0)
                throw std::runtime_error(
                    std::string("threshold provenance missing ") + field);
            return *value;
        };
        const auto required_double = [](const std::optional<double>& value,
                                        const char* field) {
            if (!value.has_value() || !std::isfinite(*value) || *value <= 0.0)
                throw std::runtime_error(
                    std::string("threshold provenance missing ") + field);
            return *value;
        };
        if (provenance.flooding_assurance !=
                kThresholdFloodingAssuranceLegacyCoefficientLevel ||
            !provenance.query_stat_bits.has_value() ||
            *provenance.query_stat_bits != 0) {
            throw std::runtime_error(
                "threshold provenance is not legacy coefficient-level/query-zero");
        }

        ThresholdSpecRow row;
        row.k = k;
        row.tau = tau;
        row.degree = static_cast<uint32_t>(poly.size() - 1);
        row.ps_baby_s = s;
        row.ps_num_chunks = num_chunks;
        row.baby_depth = baby_depth;
        row.giant_mults = giant_mults;
        row.natural_mult_depth = P.natural_mult_depth;
        row.mult_depth = P.mult_depth;
        row.scaling_mod_size = P.scaling_mod_size;
        row.ring_dim = P.ring_dim;
        row.plaintext_mod = P.plaintext_mod;
        row.log2_q = required_double(provenance.log_q_bits, "log_q_bits");
        row.eval_noise_bits = static_cast<int64_t>(required_u32(
            provenance.eval_noise_bits, "eval_noise_bits"));
        row.flood_noise_bits = static_cast<int64_t>(required_u32(
            provenance.flood_noise_bits, "flood_noise_bits"));
        row.ct_bytes = static_cast<int64_t>(ct_bytes);
        row.poly_build_ms = poly_ms;
        row.status = "ok";

        // Consume the common provenance constructor rather than rebuilding a
        // partial tuple from the legacy PiccardParams aliases.
        row.requested_ring_dim = required_u32(
            provenance.requested_ring_dim, "requested_ring_dim");
        row.natural_ring_dim = required_u32(
            provenance.natural_ring_dim, "natural_ring_dim");
        row.provisioned_ring_dim = required_u32(
            provenance.provisioned_ring_dim, "provisioned_ring_dim");
        row.realized_ring_dim = required_u32(
            provenance.realized_ring_dim, "realized_ring_dim");
        row.natural_depth = required_u32(provenance.natural_depth,
                                         "natural_depth");
        row.provisioned_depth = required_u32(provenance.provisioned_depth,
                                             "provisioned_depth");
        row.log_q_bits = row.log2_q;
        row.log2_q_over_t_bits = required_double(
            provenance.log2_q_over_t_bits, "log2_q_over_t_bits");
        row.plaintext_modulus = required_u64(
            provenance.plaintext_modulus, "plaintext_modulus");
        row.num_limbs = required_u32(provenance.num_limbs, "num_limbs");
        row.realized_scaling_mod_size = required_u32(
            provenance.realized_scaling_mod_size, "realized_scaling_mod_size");
        row.ordered_rns_moduli = provenance.ordered_rns_moduli;
        row.ordered_rns_limb_bits = provenance.ordered_rns_limb_bits;
        row.openfhe_version = provenance.openfhe_version;
        row.flooding_assurance = provenance.flooding_assurance;
        row.transcript_stat_bits = required_u32(
            provenance.transcript_stat_bits, "transcript_stat_bits");
        row.max_queries = required_u64(provenance.max_queries, "max_queries");
        row.query_stat_bits = *provenance.query_stat_bits;
        if (row.query_stat_bits != 0)
            throw std::runtime_error(
                "threshold spec query_stat_bits must remain zero");
        row.coefficient_stat_bits = required_u32(
            provenance.coefficient_stat_bits, "coefficient_stat_bits");
        row.flood_margin_bits = required_u32(provenance.flood_margin_bits,
                                             "flood_margin_bits");
        row.required_capacity_bits = bfv.RequiredFloodBudgetBits();
        row.residual_capacity_definition =
            provenance.residual_capacity_definition;
        row.residual_capacity_bits = provenance.residual_capacity_bits;
        row.residual_capacity_status = provenance.residual_capacity_status;

        WriteThresholdSpecRow(std::cout, row);
        std::cerr << "  k=" << k << " depth=" << P.natural_mult_depth << "->"
                  << P.mult_depth << " N=" << P.ring_dim
                  << " log2q=" << row.log_q_bits << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

static std::string ParseRequestedMode(int argc, char** argv) {
    bool saw_mode = false;
    std::string mode;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg.rfind("--mode=", 0) == 0) {
            if (saw_mode) {
                throw std::invalid_argument("duplicate --mode");
            }
            saw_mode = true;
            mode = arg.substr(7);
        }
    }
    return mode;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: bench_threshold [options]\n"
                  << "Options:\n"
                  << "  --k=N              Number of MinHash functions (default: 128)\n"
                  << "  --m=N              One-hot bucket size (default: 64)\n"
                  << "  --set_size=N       Size of each party's set (default: 100)\n"
                  << "  --trials=N         Number of trials to run (default: 10)\n"
                  << "  --mode=MODE        'accuracy', 'timing', 'fpfn', or 'spec' (default: timing)\n"
                  << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256'\n";
        return 0;
    }

    std::string requested_mode;
    try {
        // Parse mode occurrence before selecting either parser.  The legacy
        // parser historically retained only the last --mode, so a mode placed
        // after --mode=timing could bypass the dedicated point path.
        requested_mode = ParseRequestedMode(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "bench_threshold: " << error.what() << "\n";
        return 2;
    }

    if (requested_mode == "fpfn") {
        try {
            return RunSyntheticThresholdPoint(ParseFpfnArgs(argc, argv));
        } catch (const std::invalid_argument& error) {
            if (std::string(error.what()) == "help requested") {
                std::cout << "Usage: bench_threshold --mode=fpfn "
                             "--profile=readiness-toy-v1|paper-v1 "
                             "--seed=N --trials=N --point-k=K "
                             "--grid-index=J [--security=LEVEL] "
                             "[--m=64 --set_size=1000]\n";
                return 0;
            }
            std::cerr << "bench_threshold: " << error.what() << "\n";
            return 2;
        } catch (const std::exception& error) {
            std::cerr << "bench_threshold: " << error.what() << "\n";
            return 2;
        }
    }

    BenchmarkConfig config;
    RawTimingOptions raw_options;
    try {
        config = BenchmarkConfig::ParseArgs(argc, argv);
        if (config.mode == "combined") {
            throw std::invalid_argument(
                "bench_threshold does not emit combined mode; select timing, "
                "accuracy, spec, or the dedicated fpfn point path");
        }
        raw_options = ParseRawTimingOptions(argc, argv);
        ResolveRawTimingOptions(raw_options, config);
    } catch (const std::exception& error) {
        std::cerr << "bench_threshold: " << error.what() << "\n";
        return 2;
    }
    config.Print();

    ThresholdCSVWriter csv;
    if (config.mode != "spec") {
        csv.WriteHeader();
    }

    if (raw_options.enabled) {
        RunRawTimingThreshold(config, raw_options, csv);
        return 0;
    }

    if (config.mode == "timing") {
        std::cerr << "\n=== Varying k (median of " << config.trials << " trials) ===\n";
        BenchVaryK(config, csv);

        std::cerr << "\n=== Varying m (median of " << config.trials << " trials) ===\n";
        BenchVaryM(config, csv);

        std::cerr << "\n=== Varying set size (median of " << config.trials << " trials) ===\n";
        BenchVarySetSize(config, csv);
    } else if (config.mode == "accuracy") {
        std::cerr << "\n=== Accuracy vs k ===\n";
        BenchAccuracyVaryK(config, csv);

        std::cerr << "\n=== Accuracy vs m ===\n";
        BenchAccuracyVaryM(config, csv);

        std::cerr << "\n=== Accuracy vs set size ===\n";
        BenchAccuracyVarySetSize(config, csv);
    } else if (config.mode == "fpfn") {
        std::cerr << "\n=== Boundary FP/FN vs k (" << config.trials
                  << " trials/point, plaintext MinHash) ===\n";
        BenchFpfnVaryK(config, csv);
    } else if (config.mode == "spec") {
        std::cerr << "\n=== u_tau spec dump ===\n";
        BenchSpecDump(config);
    }

    return 0;
}
