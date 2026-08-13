#include "benchmark_utils.h"
#include "raw_timing_schema.h"
#include "sqrt_revision_adapter.h"
#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"

#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;
using Clock = std::chrono::high_resolution_clock;

namespace {

constexpr const char* kRawTimingProducerId = "bench_sqrt_comparison";

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
                throw std::invalid_argument("--raw_timing_dir must not be empty");
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
                                    const SqrtComparisonConfig& config) {
    if (!options.enabled) return;
    if (config.sanitizer.mode != "timing") {
        throw std::invalid_argument(
            "--raw_timing_dir requires --mode=timing");
    }
    if (TimingContractFor(kRawTimingProducerId) == kTimingNotApplicable) {
        throw std::invalid_argument(
            "bench_sqrt_comparison has no raw timing contract");
    }
    options.profile_id = RawTimingProfileId(config.sanitizer);
    options.measured_trials =
        static_cast<size_t>(ExpectedTimingTrials(options.profile_id));
    if (options.trials_explicit &&
        static_cast<size_t>(config.trials) != options.measured_trials) {
        throw std::invalid_argument(
            "versioned raw timing requires exactly " +
            std::to_string(options.measured_trials) + " measured trials");
    }
}

}  // namespace

static bool HasRevisionCell(int argc, char** argv) {
    for (int index = 1; index < argc; ++index) {
        if (std::string(argv[index]).rfind("--revision-cell=", 0) == 0) {
            return true;
        }
    }
    return false;
}

static RevisionRunMode RevisionModeForProfile(const std::string& profile) {
    return profile == "readiness-toy-v1" ? RevisionRunMode::Toy
                                         : RevisionRunMode::Paper;
}

static void PrintSqrtRevisionTerminalRow(
    const SqrtRevisionExecutionPlan& execution) {
    const auto& row = execution.selection.plan.expected_rows.at(1);
    std::cerr << "revision_terminal,schema=sqrt-revision-terminal-v1"
              << ",cell_id=" << execution.selection.cell.cell_id
              << ",row_id=" << row.row_id
              << ",status=" << row.status
              << ",terminal_status=" << row.terminal_status
              << ",reason=" << row.reason
              << ",reason_code=" << row.reason_code
              << ",measured_count=" << row.measured_count << "\n";
}

double TrueJaccard(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    std::vector<uint64_t> sa(a.begin(), a.end()), sb(b.begin(), b.end());
    std::sort(sa.begin(), sa.end());
    std::sort(sb.begin(), sb.end());
    std::vector<uint64_t> inter, uni;
    std::set_intersection(sa.begin(), sa.end(), sb.begin(), sb.end(), std::back_inserter(inter));
    std::set_union(sa.begin(), sa.end(), sb.begin(), sb.end(), std::back_inserter(uni));
    return uni.empty() ? 0.0 : static_cast<double>(inter.size()) / uni.size();
}

struct BenchResult {
    double encode_ms;
    double encrypt_ms;
    double evaluate_ms;
    double decrypt_ms;
    double total_ms;
    uint32_t ring_dim;
    uint32_t mult_depth;
    double jaccard_est;
    double jaccard_true;
    SanitizerMetadata sanitizer;
    BenchmarkProvenance provenance;
};

namespace {

static RawTimingArtifact MakeRawTimingArtifact(
    const RawTimingOptions& options,
    const std::string& cell_id,
    const std::string& encoding,
    const std::vector<BenchResult>& results,
    uint64_t root_seed) {
    RawTimingArtifact artifact;
    artifact.producer_id = kRawTimingProducerId;
    artifact.profile_id = options.profile_id;
    artifact.cell_id = cell_id + "_" + encoding;
    artifact.warmup_policy = WarmupPolicy::None;
    artifact.expected_measured = options.measured_trials;
    std::vector<RawTimingSample> samples;
    samples.reserve(results.size() * 5);

    for (size_t trial = 0; trial < results.size(); ++trial) {
        const auto& result = results[trial];
        const uint64_t trial_seed = TrialSeed(root_seed, trial, 0.5);
        const auto add = [&](const char* phase, double raw_ms) {
            samples.push_back(
                {artifact.producer_id, artifact.profile_id, artifact.cell_id,
                 phase, SampleKind::Measured,
                 static_cast<uint64_t>(trial), trial_seed, raw_ms});
        };
        add("encode", result.encode_ms);
        add("encrypt", result.encrypt_ms);
        add("evaluate", result.evaluate_ms);
        add("decrypt", result.decrypt_ms);
        add("total", result.total_ms);
    }
    artifact.samples = std::move(samples);
    return artifact;
}

}  // namespace

template <typename Engine>
BenchResult RunBench(Engine& engine, const std::vector<uint64_t>& set_x,
                     const std::vector<uint64_t>& set_y, double j_true) {
    BenchResult r{};
    r.ring_dim = engine.GetParams().ring_dim;
    r.mult_depth = engine.GetParams().mult_depth;
    r.jaccard_true = j_true;
    r.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    r.provenance = MakePiccardBenchmarkProvenance(engine.GetBFVContext());

    // Encode
    auto t0 = Clock::now();
    auto sig_x = engine.ComputeSignature(set_x);
    auto sig_y = engine.ComputeSignature(set_y);
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    auto t1 = Clock::now();
    r.encode_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Encrypt
    t0 = Clock::now();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    t1 = Clock::now();
    r.encrypt_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Evaluate
    t0 = Clock::now();
    auto ct_result = engine.Evaluate(ct_x, ct_y);
    t1 = Clock::now();
    r.evaluate_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Decrypt
    t0 = Clock::now();
    auto result = engine.Decrypt(ct_result);
    t1 = Clock::now();
    r.decrypt_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    r.total_ms = r.encode_ms + r.encrypt_ms + r.evaluate_ms + r.decrypt_ms;
    r.jaccard_est = result.jaccard_estimate;
    return r;
}

struct Stats {
    double mean;
    double stddev;
};

Stats ComputeStats(const std::vector<double>& vals) {
    if (vals.empty()) return {0.0, 0.0};
    double sum = std::accumulate(vals.begin(), vals.end(), 0.0);
    double mean = sum / static_cast<double>(vals.size());
    double sq_sum = 0.0;
    for (double v : vals) sq_sum += (v - mean) * (v - mean);
    double stddev = (vals.size() > 1) ? std::sqrt(sq_sum / (vals.size() - 1)) : 0.0;
    return {mean, stddev};
}

void PrintHeader(int num_trials) {
    std::cerr << "(Averaged over " << num_trials
              << " trials, mean\xC2\xB1stddev)\n";
    std::cout << SerializeSqrtComparisonHeader();
}

void PrintRow(const BenchmarkConfig& config,
              const std::string& name, uint32_t k, uint32_t m,
              const std::vector<BenchResult>& results) {
    std::vector<double> enc, enr, eva, dec, tot, abs_errs, rel_errs;
    for (auto& r : results) {
        enc.push_back(r.encode_ms);
        enr.push_back(r.encrypt_ms);
        eva.push_back(r.evaluate_ms);
        dec.push_back(r.decrypt_ms);
        tot.push_back(r.total_ms);
        double ae = std::abs(r.jaccard_est - r.jaccard_true);
        abs_errs.push_back(ae);
        if (r.jaccard_true > 0.0)
            rel_errs.push_back(ae / r.jaccard_true);
    }

    auto s_enc = ComputeStats(enc);
    auto s_enr = ComputeStats(enr);
    auto s_eva = ComputeStats(eva);
    auto s_dec = ComputeStats(dec);
    auto s_tot = ComputeStats(tot);
    auto s_abs = ComputeStats(abs_errs);
    auto s_rel = ComputeStats(rel_errs);

    SqrtComparisonResult row;
    row.encoding = name;
    row.security = config.security_level == SecurityLevel::TOY ? "TOY" :
        config.security_level == SecurityLevel::STD128 ? "STD128" :
        config.security_level == SecurityLevel::STD192 ? "STD192" : "STD256";
    row.k = k;
    row.m = m;
    row.ring_dim = results[0].ring_dim;
    row.mult_depth = results[0].mult_depth;
    row.encode_ms = s_enc.mean;
    row.encrypt_ms = s_enr.mean;
    row.evaluate_ms = s_eva.mean;
    row.decrypt_ms = s_dec.mean;
    row.total_ms = s_tot.mean;
    row.total_ms_sd = s_tot.stddev;
    row.jaccard_error = s_abs.mean;
    row.jaccard_error_sd = s_abs.stddev;
    row.has_relative_error = !rel_errs.empty();
    row.jaccard_rel_error = s_rel.mean;
    row.jaccard_rel_error_sd = s_rel.stddev;
    row.sanitizer = results[0].sanitizer;
    row.provenance = results[0].provenance;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    ApplyBenchmarkProfile(
        config, row, BenchmarkMeasurementKind::Diagnostic);
    std::cout << SerializeSqrtComparisonRow(row, row.provenance);
}

int main(int argc, char** argv) {
    const uint32_t n = 500;

    RawTimingOptions raw_options = ParseRawTimingOptions(argc, argv);
    const SqrtComparisonConfig config =
        ResolveSqrtComparisonConfig(argc, argv);
    RejectUnknownBenchmarkOptions(argc, argv,
                                  {"--raw_timing_dir=", "--cell="});
    ResolveRawTimingOptions(raw_options, config);

    const bool revision_cell = HasRevisionCell(argc, argv);
    if (revision_cell) {
        const RevisionMatrix matrix = LoadAndValidateRevisionMatrix(
            PICCARD_REVISION_MATRIX_PATH);
        const auto execution = PlanSqrtRevisionExecution(
            matrix, std::vector<std::string>(argv + 1, argv + argc),
            RevisionModeForProfile(config.sanitizer.profile.id));
        if (execution.role != "accuracy") {
            throw std::invalid_argument(
                "bench_sqrt_comparison revision cells require accuracy_m role");
        }

        const int num_trials = static_cast<int>(execution.onehot_runs);
        std::cerr << "=== Revision sqrt accuracy cell "
                  << execution.selection.cell.cell_id << " (trials="
                  << num_trials << ") ===\n";
        PrintHeader(num_trials);
        std::mt19937_64 revision_rng(config.seed);
        const auto [set_a, set_b] = MakeRandomSetsWithOverlap(
            execution.point.set_size, 0.5, revision_rng);
        const double j_true = TrueJaccard(set_a, set_b);
        std::vector<BenchResult> onehot_results;
        onehot_results.reserve(execution.onehot_runs);
        for (size_t trial = 0; trial < execution.onehot_runs; ++trial) {
            PiccardParams params;
            params.k = execution.point.k;
            params.m = execution.point.m;
            params.security = config.sanitizer.security_level;
            params.hash_seed = config.seed;
            ApplyBenchmarkProfile(config.sanitizer, params);
            params.flood_margin_bits = config.flood_margin_bits;
            params.Validate();
            Piccard engine(params);
            engine.KeyGen();
            onehot_results.push_back(
                RunBench(engine, set_a, set_b, j_true));
        }
        PrintRow(config.sanitizer, "OneHot", execution.point.k,
                 execution.point.m, onehot_results);

        if (!execution.sqrt_applicable) {
            PrintSqrtRevisionTerminalRow(execution);
            return 0;
        }

        std::vector<BenchResult> sqrt_results;
        sqrt_results.reserve(execution.sqrt_runs);
        for (size_t trial = 0; trial < execution.sqrt_runs; ++trial) {
            PiccardParams params;
            params.k = execution.point.k;
            params.m = execution.point.m;
            params.security = config.sanitizer.security_level;
            params.hash_seed = config.seed;
            ApplyBenchmarkProfile(config.sanitizer, params);
            params.flood_margin_bits = config.flood_margin_bits;
            params.ValidateSqrt();
            SqrtPiccard engine(params);
            engine.KeyGen();
            sqrt_results.push_back(
                RunBench(engine, set_a, set_b, j_true));
        }
        PrintRow(config.sanitizer, "Sqrt", execution.point.k,
                 execution.point.m, sqrt_results);
        return 0;
    }

    (void)ResolveBenchmarkGrid(
        config.sanitizer.profile, BenchmarkProducer::SqrtComparison,
        BenchmarkMode::Timing, false, {});
    const uint64_t seed = config.seed;
    const int num_trials = raw_options.enabled
        ? static_cast<int>(raw_options.measured_trials) : config.trials;

    std::mt19937_64 rng(seed);

    std::cerr << "=== Base-sqrt(m) vs One-Hot Comparison ===\n";
    std::cerr << "Set size: n=" << n
              << ", Trials=" << num_trials
              << ", Seed=" << seed << "\n";

    // Test with different (k, m) configurations
    struct Config { uint32_t k; uint32_t m; };
    Config configs[] = {
        // Base
        {128, 64},
        // Larger k
        {256, 64}, {512, 64}, {1024, 64},
        // Larger m (log2(m) must be even for sqrt)
        {128, 256}, {128, 1024},
    };

    PrintHeader(num_trials);

    std::vector<RawTimingArtifact> raw_artifacts;

    for (auto& cfg : configs) {
        std::vector<BenchResult> onehot_results, sqrt_results;

        for (int trial = 0; trial < num_trials; trial++) {
            auto [set_x, set_y] = piccard::benchmark::MakeRandomSetsWithOverlap(
                n, 0.5, rng);
            double j_true = TrueJaccard(set_x, set_y);

            // One-hot
            {
                PiccardParams p;
                p.k = cfg.k;
                p.m = cfg.m;
                p.security = config.sanitizer.security_level;
                ApplyBenchmarkProfile(config.sanitizer, p);
                p.flood_margin_bits = config.flood_margin_bits;
                p.Validate();

                Piccard engine(p);
                engine.KeyGen();
                onehot_results.push_back(RunBench(engine, set_x, set_y, j_true));
            }

            // Sqrt
            {
                PiccardParams p;
                p.k = cfg.k;
                p.m = cfg.m;
                p.security = config.sanitizer.security_level;
                ApplyBenchmarkProfile(config.sanitizer, p);
                p.flood_margin_bits = config.flood_margin_bits;
                p.ValidateSqrt();

                SqrtPiccard engine(p);
                engine.KeyGen();
                sqrt_results.push_back(RunBench(engine, set_x, set_y, j_true));
            }
        }

        PrintRow(config.sanitizer, "OneHot", cfg.k, cfg.m, onehot_results);
        PrintRow(config.sanitizer, "Sqrt", cfg.k, cfg.m, sqrt_results);
        if (raw_options.enabled) {
            const std::string cell_id =
                "k" + std::to_string(cfg.k) + "_m" + std::to_string(cfg.m);
            raw_artifacts.push_back(MakeRawTimingArtifact(
                raw_options, cell_id, "onehot", onehot_results, config.seed));
            raw_artifacts.push_back(MakeRawTimingArtifact(
                raw_options, cell_id, "sqrt", sqrt_results, config.seed));
        }
    }

    if (raw_options.enabled) {
        WriteRawTimingArtifactsV1(raw_options.output_directory, raw_artifacts);
    }

    return 0;
}
