#include "benchmark_utils.h"
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
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;

// ============================================================================
// CSV output
// ============================================================================

class CrossoverCSVWriter {
public:
    CrossoverCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << SerializeCrossoverHeader();
    }

    void WriteRow(const CrossoverResult& r) {
        *out_ << SerializeCrossoverRow(r);
    }

private:
    std::ostream* out_;
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
                              CrossoverCSVWriter& csv) {
    std::vector<uint32_t> k_values = {32, 64, 128, 256, 512};
    // All sqrt-valid m values
    std::vector<uint32_t> m_values = {4, 16, 64, 256, 1024};

    std::mt19937_64 rng(config.seed);
    auto [set_a, set_b] = MakeRandomSetsWithOverlap(config.set_size, 0.5, rng);

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
                ApplySanitizerConfig(config, pp);
                pp.Validate();
                sp.k = k; sp.m = m; sp.security = config.security_level;
                ApplySanitizerConfig(config, sp);
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
            RunOneHotTotal(onehot, set_a, set_b);
            RunSqrtTotal(sqrt_eng, set_a, set_b);

            // Multi-trial timing
            std::vector<double> oh_times, sq_times;
            for (size_t t = 0; t < config.trials; t++) {
                oh_times.push_back(RunOneHotTotal(onehot, set_a, set_b));
                sq_times.push_back(RunSqrtTotal(sqrt_eng, set_a, set_b));
            }

            cr.onehot_total_ms = Median(oh_times);
            cr.sqrt_total_ms = Median(sq_times);
            cr.sqrt_faster = (cr.sqrt_total_ms < cr.onehot_total_ms);
            cr.speedup_ratio = (cr.sqrt_total_ms > 0.0)
                ? (cr.onehot_total_ms / cr.sqrt_total_ms) : 0.0;

            csv.WriteRow(cr);

            std::cerr << "  k=" << k << " m=" << m
                      << " OH_N=" << cr.onehot_ring_dim
                      << " Sq_N=" << cr.sqrt_ring_dim
                      << " OH=" << cr.onehot_total_ms << "ms"
                      << " Sq=" << cr.sqrt_total_ms << "ms"
                      << (cr.sqrt_faster ? " [SQRT FASTER]" : "") << "\n";
        }
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

    auto config = BenchmarkConfig::ParseArgs(argc, argv);
    config.Print();

    CrossoverCSVWriter csv;
    csv.WriteHeader();

    std::cerr << "\n=== Crossover sweep (median of "
              << config.trials << " trials) ===\n";
    RunCrossoverSweep(config, csv);

    return 0;
}
