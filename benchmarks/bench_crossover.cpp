#include "benchmark_utils.h"
#include "raw_timing_schema.h"
#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"

// OpenFHE serialization registration (required for CiphertextSizer)
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;

namespace {

constexpr const char* kRawTimingProducerId = "bench_crossover";

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
                                    const BenchmarkConfig& config) {
    if (!options.enabled) return;
    if (TimingContractFor(kRawTimingProducerId) == kTimingNotApplicable) {
        throw std::invalid_argument(
            "bench_crossover has no raw timing contract");
    }
    options.profile_id = RawTimingProfileId(config);
    options.measured_trials =
        static_cast<size_t>(ExpectedTimingTrials(options.profile_id));
    if (options.trials_explicit && config.trials != options.measured_trials) {
        throw std::invalid_argument(
            "versioned raw timing requires exactly " +
            std::to_string(options.measured_trials) + " measured trials");
    }
}

static void AddRawTimingSample(
    RawTimingArtifact& artifact,
    const char* phase,
    SampleKind sample_kind,
    uint64_t trial_index,
    uint64_t seed,
    double raw_ms) {
    artifact.samples.push_back(
        {artifact.producer_id, artifact.profile_id, artifact.cell_id, phase,
         sample_kind, trial_index, seed, raw_ms});
}

}  // namespace

// ============================================================================
// CSV output
// ============================================================================

class CrossoverCSVWriter {
public:
    explicit CrossoverCSVWriter(const BenchmarkConfig& config)
        : out_(&std::cout), config_(&config) {}

    void WriteHeader() {
        *out_ << SerializeCrossoverHeader();
    }

    void WriteRow(const CrossoverResult& r) {
        CrossoverResult profiled = r;
        ApplyBenchmarkProfile(*config_, profiled,
                              BenchmarkMeasurementKind::Diagnostic);
        *out_ << SerializeCrossoverRow(
            profiled, profiled.onehot_provenance,
            profiled.sqrt_provenance);
    }

private:
    std::ostream* out_;
    const BenchmarkConfig* config_;
};

// ============================================================================
// Exact Jaccard
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

// ============================================================================
// Median helper
// ============================================================================

static double Median(std::vector<double>& v) {
    size_t n = v.size();
    if (n == 0) return 0.0;
    std::sort(v.begin(), v.end());
    if (n % 2 == 0) return (v[n / 2 - 1] + v[n / 2]) / 2.0;
    return v[n / 2];
}

// ============================================================================
// Timed run: measure total protocol time (encode + encrypt + evaluate + decrypt)
// ============================================================================

static double RunOneHotTotal(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y)
{
    Timer timer;
    timer.Start();
    auto result = engine.Run(set_x, set_y);
    (void)result;
    return timer.ElapsedMs();
}

static double RunSqrtTotal(
    const SqrtPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y)
{
    Timer timer;
    timer.Start();
    auto result = engine.Run(set_x, set_y);
    (void)result;
    return timer.ElapsedMs();
}

// ============================================================================
// Sweep
// ============================================================================

static void RunCrossoverSweep(const BenchmarkConfig& config,
                              CrossoverCSVWriter& csv,
                              const RawTimingOptions* raw_options = nullptr) {
    std::vector<uint32_t> k_values = {32, 64, 128, 256, 512};
    // All sqrt-valid m values
    std::vector<uint32_t> m_values = {4, 16, 64, 256, 1024};

    std::mt19937_64 rng(config.seed);
    auto [set_a, set_b] = MakeRandomSetsWithOverlap(config.set_size, 0.5, rng);
    const size_t timing_trials = raw_options == nullptr
        ? config.trials : raw_options->measured_trials;
    std::vector<RawTimingArtifact> raw_artifacts;

    for (uint32_t k : k_values) {
        for (uint32_t m : m_values) {
            CrossoverResult cr;
            cr.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
            cr.k = k;
            cr.m = m;
            cr.onehot_feature_dim = k * m;

            uint32_t sqrt_base = 1;
            { uint32_t tmp = m; uint32_t log2m = 0;
              while (tmp > 1) { log2m++; tmp >>= 1; }
              sqrt_base = 1u << (log2m / 2); }
            cr.sqrt_feature_dim = k * 2 * sqrt_base;

            // Validate() fails closed for a configuration the noise-flooding
            // calibration does not cover (R2-W6), and this sweep runs its full
            // grid at every security level. Skip such a cell with a warning
            // rather than aborting the whole sweep -- the same handling
            // bench_threshold uses. `bench_noise --coverage` lists which keys
            // are missing and 3_noise-flooding.md section 8 records why.
            PiccardParams pp;
            PiccardParams sp;
            try {
                pp.k = k; pp.m = m; pp.security = config.security_level;
                ApplyBenchmarkProfile(config, pp);
                pp.Validate();
                sp.k = k; sp.m = m; sp.security = config.security_level;
                ApplyBenchmarkProfile(config, sp);
                sp.ValidateSqrt();
            } catch (const std::exception& e) {
                std::cerr << "WARNING: skipping k=" << k << " m=" << m
                          << ": " << e.what() << "\n";
                continue;
            }

            // OneHot engine
            Piccard onehot(pp);
            onehot.KeyGen();
            cr.onehot_ring_dim = onehot.GetParams().ring_dim;

            // Sqrt engine
            SqrtPiccard sqrt_eng(sp);
            sqrt_eng.KeyGen();
            cr.sqrt_ring_dim = sqrt_eng.GetParams().ring_dim;
            cr.sanitizer = MakeSanitizerMetadata(onehot.GetParams());
            cr.onehot_provenance =
                MakePiccardBenchmarkProvenance(onehot.GetBFVContext());
            cr.sqrt_provenance =
                MakePiccardBenchmarkProvenance(sqrt_eng.GetBFVContext());
            cr.onehot_coefficient_stat_bits =
                onehot.GetParams().CoefficientStatBits();
            cr.onehot_eval_noise_bits = onehot.GetParams().eval_noise_bits;
            cr.onehot_flood_noise_bits =
                onehot.GetParams().FloodNoiseBits();
            cr.sqrt_coefficient_stat_bits =
                sqrt_eng.GetParams().CoefficientStatBits();
            cr.sqrt_eval_noise_bits = sqrt_eng.GetParams().eval_noise_bits;
            cr.sqrt_flood_noise_bits =
                sqrt_eng.GetParams().FloodNoiseBits();

            // Warmup
            RawTimingArtifact artifact;
            RawTimingArtifact* artifact_ptr = nullptr;
            if (raw_options != nullptr) {
                artifact.producer_id = kRawTimingProducerId;
                artifact.profile_id = raw_options->profile_id;
                artifact.cell_id = "k" + std::to_string(k) + "_m" +
                                   std::to_string(m);
                artifact.warmup_policy = WarmupPolicy::DiscardOne;
                artifact.expected_measured = raw_options->measured_trials;
                artifact_ptr = &artifact;
            }
            const double onehot_warmup = RunOneHotTotal(onehot, set_a, set_b);
            const double sqrt_warmup = RunSqrtTotal(sqrt_eng, set_a, set_b);
            if (artifact_ptr != nullptr) {
                AddRawTimingSample(
                    *artifact_ptr, "onehot_total",
                    SampleKind::DiscardedWarmup, 0, config.seed,
                    onehot_warmup);
                AddRawTimingSample(
                    *artifact_ptr, "sqrt_total", SampleKind::DiscardedWarmup,
                    0, config.seed, sqrt_warmup);
            }

            // Multi-trial timing
            std::vector<double> oh_times, sq_times;
            for (size_t t = 0; t < timing_trials; t++) {
                const double onehot_ms = RunOneHotTotal(onehot, set_a, set_b);
                const double sqrt_ms = RunSqrtTotal(sqrt_eng, set_a, set_b);
                oh_times.push_back(onehot_ms);
                sq_times.push_back(sqrt_ms);
                if (artifact_ptr != nullptr) {
                    const uint64_t trial_seed = TrialSeed(config.seed, t, 0.5);
                    AddRawTimingSample(
                        *artifact_ptr, "onehot_total", SampleKind::Measured,
                        static_cast<uint64_t>(t), trial_seed, onehot_ms);
                    AddRawTimingSample(
                        *artifact_ptr, "sqrt_total", SampleKind::Measured,
                        static_cast<uint64_t>(t), trial_seed, sqrt_ms);
                }
            }

            cr.onehot_total_ms = Median(oh_times);
            cr.sqrt_total_ms = Median(sq_times);
            cr.sqrt_faster = (cr.sqrt_total_ms < cr.onehot_total_ms);
            cr.speedup_ratio = (cr.sqrt_total_ms > 0.0)
                ? (cr.onehot_total_ms / cr.sqrt_total_ms) : 0.0;

            csv.WriteRow(cr);
            if (artifact_ptr != nullptr) {
                raw_artifacts.push_back(std::move(artifact));
            }

            std::cerr << "  k=" << k << " m=" << m
                      << " OH_N=" << cr.onehot_ring_dim
                      << " Sq_N=" << cr.sqrt_ring_dim
                      << " OH=" << cr.onehot_total_ms << "ms"
                      << " Sq=" << cr.sqrt_total_ms << "ms"
                      << (cr.sqrt_faster ? " [SQRT FASTER]" : "") << "\n";
        }
    }

    if (raw_options != nullptr && !raw_artifacts.empty()) {
        WriteRawTimingArtifactsV1(raw_options->output_directory, raw_artifacts);
    }
}

// ============================================================================
// Main
// ============================================================================

static void PrintUsage() {
    std::cerr
        << "Usage: bench_crossover [options]\n"
        << "\n"
        << "Crossover-point sweep: find (k, m) configurations where Sqrt encoding\n"
        << "becomes faster than OneHot encoding.\n"
        << "\n"
        << "Sweeps k in {32,64,128,256,512} x m in {4,16,64,256,1024}.\n"
        << "\n"
        << "Options:\n"
        << "  --set_size=N       Set size (default: 1000)\n"
        << "  --trials=N         Timing trials per config (default: 10)\n"
        << "  --security=LEVEL   'TOY', 'STD128', 'STD192', 'STD256' (default: STD128)\n"
        << "  --seed=N           RNG seed (default: random)\n"
        << "  --help, -h         Print this help message\n";
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            PrintUsage();
            return 0;
        }
    }

    RawTimingOptions raw_options = ParseRawTimingOptions(argc, argv);
    auto config = BenchmarkConfig::ParseArgs(argc, argv);
    RejectUnknownBenchmarkOptions(argc, argv, {"--raw_timing_dir="});
    ResolveRawTimingOptions(raw_options, config);
    (void)ResolveBenchmarkGrid(
        config.profile, BenchmarkProducer::Crossover, BenchmarkMode::Timing,
        false, {});
    config.Print();

    CrossoverCSVWriter csv(config);
    csv.WriteHeader();

    std::cerr << "\n=== Crossover sweep (median of "
              << config.trials << " trials) ===\n";
    RunCrossoverSweep(config, csv,
                      raw_options.enabled ? &raw_options : nullptr);

    return 0;
}
