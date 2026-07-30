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
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;

// ============================================================================
// Per-engine Evaluate timing: OneHot (2 sub-phases)
// Mirrors Piccard::Evaluate (piccard.cpp) and bench_piccard.cpp lines 95-110
// ============================================================================

static void RunOneHotEvaluateTimed(
    const Piccard& engine,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y,
    BenchmarkResult& br,
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_result)
{
    const auto& bfv = engine.GetBFVContext();
    Timer timer;

    // Sub-phase 1: Component-wise multiply (depth 1)
    timer.Start();
    auto product = bfv.Multiply(ct_x, ct_y);
    br.phase_multiply_ms = timer.ElapsedMs();

    // Sub-phase 2: Rotate-and-sum (all slots -> slot 0)
    timer.Start();
    ct_result = product;
    for (uint32_t step = 1; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(ct_result, static_cast<int>(step));
        ct_result = bfv.Add(ct_result, rotated);
    }
    br.phase_rotate_sum_ms = timer.ElapsedMs();

    // Sub-phase 3: Noise flooding (cloud) — mirrors Piccard::Evaluate exit (piccard.cpp:77)
    timer.Start();
    ct_result = bfv.Flood(ct_result);
    br.phase_flood_ms = timer.ElapsedMs();

    // Sqrt-specific fields not applicable
    br.phase_intra_digit_rotate_ms = 0.0;
    br.phase_digit_and_ms = 0.0;
    br.phase_cross_k_sum_ms = 0.0;
}

// ============================================================================
// Per-engine Evaluate timing: Sqrt (4 sub-phases)
// Mirrors SqrtPiccard::Evaluate (sqrt_piccard.cpp lines 42-86)
// ============================================================================

static void RunSqrtEvaluateTimed(
    const SqrtPiccard& engine,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_x,
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_y,
    BenchmarkResult& br,
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_result)
{
    const auto& bfv = engine.GetBFVContext();
    uint32_t b = engine.GetParams().sqrt_base;
    uint32_t block = 2 * b;
    Timer timer;

    // Sub-phase 1: Component-wise multiply (depth 1)
    timer.Start();
    auto product = bfv.Multiply(ct_x, ct_y);
    br.phase_multiply_ms = timer.ElapsedMs();

    // Sub-phase 2: Intra-digit rotate-and-sum
    timer.Start();
    auto digit_sums = product;
    for (uint32_t step = 1; step < b; step *= 2) {
        auto rotated = bfv.Rotate(digit_sums, static_cast<int>(step));
        digit_sums = bfv.Add(digit_sums, rotated);
    }
    br.phase_intra_digit_rotate_ms = timer.ElapsedMs();

    // Sub-phase 3: Digit AND multiply (depth 2)
    timer.Start();
    auto shifted = bfv.Rotate(digit_sums, static_cast<int>(b));
    auto anded = bfv.Multiply(digit_sums, shifted);
    br.phase_digit_and_ms = timer.ElapsedMs();

    // Sub-phase 4: Cross-k sum (rotate-and-sum with step=2b)
    timer.Start();
    ct_result = anded;
    for (uint32_t step = block; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(ct_result, static_cast<int>(step));
        ct_result = bfv.Add(ct_result, rotated);
    }
    br.phase_cross_k_sum_ms = timer.ElapsedMs();

    // Sub-phase 5: Noise flooding (cloud) — mirrors SqrtPiccard::Evaluate exit (sqrt_piccard.cpp:101)
    timer.Start();
    ct_result = bfv.Flood(ct_result);
    br.phase_flood_ms = timer.ElapsedMs();

    // Aggregate into phase_rotate_sum_ms for backward-compatible total
    br.phase_rotate_sum_ms = br.phase_intra_digit_rotate_ms +
                             br.phase_digit_and_ms +
                             br.phase_cross_k_sum_ms;
}

// ============================================================================
// Shared: run full protocol with per-phase timing
// ============================================================================

template <typename Engine>
static BenchmarkResult RunTimedProtocol(
    const Engine& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& label,
    const std::string& encoding_name,
    uint32_t mult_depth)
{
    Timer timer;
    BenchmarkResult br;
    br.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    br.label = label;
    br.encoding = encoding_name;
    br.param_mult_depth = mult_depth;
    br.param_k = engine.GetParams().k;
    br.param_m = engine.GetParams().m;
    br.param_ring_dim = engine.GetParams().ring_dim;
    br.param_num_cts = 1;

    // Phase 1: MinHash
    timer.Start();
    auto sig_x = engine.ComputeSignature(set_x);
    auto sig_y = engine.ComputeSignature(set_y);
    br.phase_minhash_ms = timer.ElapsedMs();

    // Phase 2: Encode
    timer.Start();
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    br.phase_encode_ms = timer.ElapsedMs();

    // Phase 3: Encrypt
    timer.Start();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    br.phase_encrypt_ms = timer.ElapsedMs();

    br.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);
    br.comm_bytes = 3 * br.ct_size_bytes;

    // Phase 4+5: Evaluate (per-engine sub-phase timing)
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ct_result;
    if constexpr (std::is_same_v<Engine, Piccard>) {
        RunOneHotEvaluateTimed(engine, ct_x, ct_y, br, ct_result);
    } else {
        RunSqrtEvaluateTimed(engine, ct_x, ct_y, br, ct_result);
    }

    // Phase 6: Decrypt + bias correction
    timer.Start();
    auto values = engine.GetBFVContext().Decrypt(ct_result);
    int64_t v = values[0];
    double k = static_cast<double>(engine.GetParams().k);
    double m = static_cast<double>(engine.GetParams().m);
    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);
    br.phase_decrypt_ms = timer.ElapsedMs();

    br.time_ms = br.phase_minhash_ms + br.phase_encode_ms +
                 br.phase_encrypt_ms + br.phase_multiply_ms +
                 br.phase_rotate_sum_ms + br.phase_flood_ms +
                 br.phase_decrypt_ms;
    br.memory_bytes = MemoryTracker::GetPeakRSS();
    br.jaccard_computed = j_hat;
    br.jaccard_expected = j_true;
    br.jaccard_error = std::abs(j_hat - j_true);
    br.jaccard_rel_error = (j_true > 0.0) ? (br.jaccard_error / j_true) : -1.0;

    return br;
}

// ============================================================================
// Multi-trial aggregation using ComputeDispersion (benchmark_utils.h)
// ============================================================================
//
// The 3 sqrt-only sub-phases (phase_intra_digit_rotate_ms, phase_digit_and_ms,
// phase_cross_k_sum_ms) have no _sd/_median siblings in BenchmarkResult, so
// they stay mean-only here; every other phase (including the newly added
// phase_flood_ms) gets the full mean/_sd/_median dispersion treatment.

template <typename Engine>
static BenchmarkResult RunMultiTrial(
    const Engine& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& label,
    const std::string& encoding_name,
    uint32_t mult_depth,
    size_t trials)
{
    // Warmup
    RunTimedProtocol(engine, set_x, set_y, j_true, "warmup", encoding_name, mult_depth);

    std::vector<double> v_minhash, v_encode, v_encrypt, v_multiply;
    std::vector<double> v_rotate_sum, v_flood, v_decrypt, v_total;
    double sum_intra_digit = 0.0, sum_digit_and = 0.0, sum_cross_k = 0.0;
    BenchmarkResult last;
    double total_error = 0.0;

    for (size_t t = 0; t < trials; t++) {
        auto br = RunTimedProtocol(engine, set_x, set_y, j_true, label,
                                   encoding_name, mult_depth);
        v_minhash.push_back(br.phase_minhash_ms);
        v_encode.push_back(br.phase_encode_ms);
        v_encrypt.push_back(br.phase_encrypt_ms);
        v_multiply.push_back(br.phase_multiply_ms);
        v_rotate_sum.push_back(br.phase_rotate_sum_ms);
        v_flood.push_back(br.phase_flood_ms);
        v_decrypt.push_back(br.phase_decrypt_ms);
        v_total.push_back(br.time_ms);
        sum_intra_digit += br.phase_intra_digit_rotate_ms;
        sum_digit_and += br.phase_digit_and_ms;
        sum_cross_k += br.phase_cross_k_sum_ms;
        total_error += br.jaccard_error;
        last = br;
    }

    auto d_minhash  = ComputeDispersion(v_minhash);
    auto d_encode   = ComputeDispersion(v_encode);
    auto d_encrypt  = ComputeDispersion(v_encrypt);
    auto d_multiply = ComputeDispersion(v_multiply);
    auto d_rotate   = ComputeDispersion(v_rotate_sum);
    auto d_flood    = ComputeDispersion(v_flood);
    auto d_decrypt  = ComputeDispersion(v_decrypt);
    auto d_total    = ComputeDispersion(v_total);
    double n = static_cast<double>(trials);

    BenchmarkResult result = last;
    result.trials = trials;
    result.phase_minhash_ms = d_minhash.mean; result.phase_minhash_ms_sd = d_minhash.sd; result.phase_minhash_ms_median = d_minhash.median;
    result.phase_encode_ms = d_encode.mean; result.phase_encode_ms_sd = d_encode.sd; result.phase_encode_ms_median = d_encode.median;
    result.phase_encrypt_ms = d_encrypt.mean; result.phase_encrypt_ms_sd = d_encrypt.sd; result.phase_encrypt_ms_median = d_encrypt.median;
    result.phase_multiply_ms = d_multiply.mean; result.phase_multiply_ms_sd = d_multiply.sd; result.phase_multiply_ms_median = d_multiply.median;
    result.phase_rotate_sum_ms = d_rotate.mean; result.phase_rotate_sum_ms_sd = d_rotate.sd; result.phase_rotate_sum_ms_median = d_rotate.median;
    result.phase_flood_ms = d_flood.mean; result.phase_flood_ms_sd = d_flood.sd; result.phase_flood_ms_median = d_flood.median;
    result.phase_decrypt_ms = d_decrypt.mean; result.phase_decrypt_ms_sd = d_decrypt.sd; result.phase_decrypt_ms_median = d_decrypt.median;
    result.time_ms = d_total.mean; result.time_ms_sd = d_total.sd; result.time_ms_median = d_total.median;
    // Sqrt-only sub-phases: mean only (no _sd/_median fields in BenchmarkResult).
    result.phase_intra_digit_rotate_ms = sum_intra_digit / n;
    result.phase_digit_and_ms = sum_digit_and / n;
    result.phase_cross_k_sum_ms = sum_cross_k / n;
    result.jaccard_error = total_error / n;
    result.memory_bytes = MemoryTracker::GetPeakRSS();
    // Noise-flooding parameter fields are constants; copy explicitly from
    // engine.GetParams() so this aggregation path does not leave them at 0.
    result.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    result.scaling_mod_size = engine.GetParams().scaling_mod_size;
    return result;
}

// ============================================================================
// Exact Jaccard for accuracy verification
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
// Timing scenarios
// ============================================================================

static void BenchVaryK(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> k_values = {16, 32, 64, 128, 256, 512};
    uint32_t m = 64;  // sqrt-valid (log2(64)=6, even)

    std::mt19937_64 rng(config.seed);
    auto [set_a, set_b] = MakeRandomSetsWithOverlap(config.set_size, 0.5, rng);
    double j_true = ExactJaccard(set_a, set_b);

    for (uint32_t k : k_values) {
        std::string scenario = "vary_k_" + std::to_string(k);

        // OneHot
        PiccardParams pp;
        pp.k = k; pp.m = m; pp.security = config.security_level;
        ApplySanitizerConfig(config, pp);
        pp.Validate();
        Piccard onehot(pp);
        onehot.KeyGen();

        auto oh = RunMultiTrial(onehot, set_a, set_b, j_true,
                                scenario, "onehot", 1, config.trials);
        csv.WriteRow(oh);

        // Sqrt
        PiccardParams sp;
        sp.k = k; sp.m = m; sp.security = config.security_level;
        ApplySanitizerConfig(config, sp);
        sp.ValidateSqrt();
        SqrtPiccard sqrt_eng(sp);
        sqrt_eng.KeyGen();

        auto sq = RunMultiTrial(sqrt_eng, set_a, set_b, j_true,
                                scenario, "sqrt", 3, config.trials);
        csv.WriteRow(sq);

        std::cerr << "  k=" << k
                  << " onehot: N=" << oh.param_ring_dim
                  << " total=" << oh.time_ms << "ms"
                  << " | sqrt: N=" << sq.param_ring_dim
                  << " total=" << sq.time_ms << "ms\n";
    }
}

static void BenchVaryM(const BenchmarkConfig& config, CSVWriter& csv) {
    // All m values valid for both Validate() and ValidateSqrt()
    std::vector<uint32_t> m_values = {4, 16, 64, 256};

    std::mt19937_64 rng(config.seed + 1);
    auto [set_a, set_b] = MakeRandomSetsWithOverlap(config.set_size, 0.5, rng);
    double j_true = ExactJaccard(set_a, set_b);

    for (uint32_t m : m_values) {
        std::string scenario = "vary_m_" + std::to_string(m);

        // OneHot
        PiccardParams pp;
        pp.k = config.k; pp.m = m; pp.security = config.security_level;
        ApplySanitizerConfig(config, pp);
        pp.Validate();
        Piccard onehot(pp);
        onehot.KeyGen();

        auto oh = RunMultiTrial(onehot, set_a, set_b, j_true,
                                scenario, "onehot", 1, config.trials);
        csv.WriteRow(oh);

        // Sqrt
        PiccardParams sp;
        sp.k = config.k; sp.m = m; sp.security = config.security_level;
        ApplySanitizerConfig(config, sp);
        sp.ValidateSqrt();
        SqrtPiccard sqrt_eng(sp);
        sqrt_eng.KeyGen();

        auto sq = RunMultiTrial(sqrt_eng, set_a, set_b, j_true,
                                scenario, "sqrt", 3, config.trials);
        csv.WriteRow(sq);

        std::cerr << "  m=" << m
                  << " onehot: N=" << oh.param_ring_dim
                  << " total=" << oh.time_ms << "ms"
                  << " | sqrt: N=" << sq.param_ring_dim
                  << " total=" << sq.time_ms << "ms\n";
    }
}

static void BenchVarySetSize(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<size_t> sizes = {100, 1000, 10000, 100000};
    uint32_t m = 64;

    // OneHot engine (reuse across sizes)
    PiccardParams pp;
    pp.k = config.k; pp.m = m; pp.security = config.security_level;
    ApplySanitizerConfig(config, pp);
    pp.Validate();
    Piccard onehot(pp);
    onehot.KeyGen();

    // Sqrt engine (reuse across sizes)
    PiccardParams sp;
    sp.k = config.k; sp.m = m; sp.security = config.security_level;
    ApplySanitizerConfig(config, sp);
    sp.ValidateSqrt();
    SqrtPiccard sqrt_eng(sp);
    sqrt_eng.KeyGen();

    for (size_t sz : sizes) {
        std::string scenario = "vary_size_" + std::to_string(sz);

        std::mt19937_64 rng(config.seed + 2 + sz);
        auto [set_a, set_b] = MakeRandomSetsWithOverlap(sz, 0.5, rng);
        double j_true = ExactJaccard(set_a, set_b);

        auto oh = RunMultiTrial(onehot, set_a, set_b, j_true,
                                scenario, "onehot", 1, config.trials);
        csv.WriteRow(oh);

        auto sq = RunMultiTrial(sqrt_eng, set_a, set_b, j_true,
                                scenario, "sqrt", 3, config.trials);
        csv.WriteRow(sq);

        std::cerr << "  size=" << sz
                  << " onehot: total=" << oh.time_ms << "ms"
                  << " | sqrt: total=" << sq.time_ms << "ms\n";
    }
}

// ============================================================================
// Accuracy mode
// ============================================================================

static void BenchAccuracy(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};
    uint32_t m = 64;

    PiccardParams pp;
    pp.k = config.k; pp.m = m; pp.security = config.security_level;
    ApplySanitizerConfig(config, pp);
    pp.Validate();
    Piccard onehot(pp);
    onehot.KeyGen();

    PiccardParams sp;
    sp.k = config.k; sp.m = m; sp.security = config.security_level;
    ApplySanitizerConfig(config, sp);
    sp.ValidateSqrt();
    SqrtPiccard sqrt_eng(sp);
    sqrt_eng.KeyGen();

    for (double overlap : overlaps) {
        std::string scenario = "accuracy_overlap_" +
            std::to_string(static_cast<int>(overlap * 100));

        std::vector<std::pair<double, double>> oh_estimates, sq_estimates;

        for (size_t t = 0; t < config.accuracy_trials; t++) {
            uint64_t tseed = TrialSeed(config.seed, t, overlap);
            std::mt19937_64 rng(tseed);
            // Both encodings must share the CRS in a given trial, otherwise the
            // paired comparison also measures hash noise.
            const uint64_t trial_hash_seed =
                (config.hash_randomness == HashRandomness::Resampled)
                    ? HashTrialSeed(config.seed, t, overlap)
                    : pp.hash_seed;   // == sp.hash_seed; both default to 42
            onehot.SetHashSeed(trial_hash_seed);
            sqrt_eng.SetHashSeed(trial_hash_seed);
            auto [set_a, set_b] = MakeRandomSetsWithOverlap(
                config.set_size, overlap, rng);
            double j_true = ExactJaccard(set_a, set_b);

            // OneHot
            auto oh_result = onehot.Run(set_a, set_b);
            oh_estimates.emplace_back(oh_result.jaccard_estimate, j_true);

            // Sqrt
            auto sq_result = sqrt_eng.Run(set_a, set_b);
            sq_estimates.emplace_back(sq_result.jaccard_estimate, j_true);
        }

        // OneHot accuracy stats
        auto oh_stats = ComputeAccuracyStats(oh_estimates);
        BenchmarkResult oh_br;
        oh_br.estimator_model =
            EstimatorModel::Sha256RandomRankingPocV1;
        oh_br.label = scenario;
        oh_br.encoding = "onehot";
        oh_br.param_mult_depth = 1;
        oh_br.param_k = config.k;
        oh_br.param_m = m;
        oh_br.param_ring_dim = onehot.GetParams().ring_dim;
        oh_br.param_num_cts = 1;
        oh_br.accuracy_median = oh_stats.median;
        oh_br.accuracy_p25 = oh_stats.p25;
        oh_br.accuracy_p75 = oh_stats.p75;
        oh_br.accuracy_p95 = oh_stats.p95;
        oh_br.accuracy_max = oh_stats.max_error;
        oh_br.trials = oh_stats.num_trials;
        oh_br.accuracy_trials = oh_stats.num_trials;
        oh_br.hash_randomness = HashRandomnessName(config.hash_randomness);
        oh_br.hash_seed = (config.hash_randomness == HashRandomness::Fixed)
                              ? pp.hash_seed : 0;
        oh_br.hash_root_seed = config.seed;
        oh_br.sanitizer = MakeSanitizerMetadata(onehot.GetParams());
        oh_br.scaling_mod_size = onehot.GetParams().scaling_mod_size;
        csv.WriteRow(oh_br);

        // Sqrt accuracy stats
        auto sq_stats = ComputeAccuracyStats(sq_estimates);
        BenchmarkResult sq_br;
        sq_br.estimator_model =
            EstimatorModel::Sha256RandomRankingPocV1;
        sq_br.label = scenario;
        sq_br.encoding = "sqrt";
        sq_br.param_mult_depth = 3;
        sq_br.param_k = config.k;
        sq_br.param_m = m;
        sq_br.param_ring_dim = sqrt_eng.GetParams().ring_dim;
        sq_br.param_num_cts = 1;
        sq_br.accuracy_median = sq_stats.median;
        sq_br.accuracy_p25 = sq_stats.p25;
        sq_br.accuracy_p75 = sq_stats.p75;
        sq_br.accuracy_p95 = sq_stats.p95;
        sq_br.accuracy_max = sq_stats.max_error;
        sq_br.trials = sq_stats.num_trials;
        sq_br.accuracy_trials = sq_stats.num_trials;
        sq_br.hash_randomness = HashRandomnessName(config.hash_randomness);
        sq_br.hash_seed = (config.hash_randomness == HashRandomness::Fixed)
                              ? sp.hash_seed : 0;
        sq_br.hash_root_seed = config.seed;
        sq_br.sanitizer = MakeSanitizerMetadata(sqrt_eng.GetParams());
        sq_br.scaling_mod_size = sqrt_eng.GetParams().scaling_mod_size;
        csv.WriteRow(sq_br);

        std::cerr << "  overlap=" << overlap
                  << " onehot: median_err=" << oh_stats.median
                  << " | sqrt: median_err=" << sq_stats.median << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

static void PrintUsage() {
    std::cerr
        << "Usage: bench_onehot_sqrt [options]\n"
        << "\n"
        << "Dual-encoding benchmark: OneHot vs Sqrt with sub-phase Evaluate timing.\n"
        << "Supersedes bench_sqrt_comparison.cpp with CSV output, multi-trial median,\n"
        << "and per-sub-phase Evaluate breakdown.\n"
        << "\n"
        << "Timing scenarios (--mode=timing):\n"
        << "  1. Vary k       {16..512}, m=64\n"
        << "  2. Vary m       {4, 16, 64, 256} (all sqrt-valid)\n"
        << "  3. Vary set size {100..100000}\n"
        << "\n"
        << "Accuracy mode (--mode=accuracy):\n"
        << "  Per-overlap error analysis for both encodings.\n"
        << "\n"
        << "Options:\n"
        << "  --mode=MODE        'timing' or 'accuracy' (default: timing)\n"
        << "  --k=N              MinHash functions (default: 128)\n"
        << "  --m=N              Bucket size (default: 64)\n"
        << "  --set_size=N       Set size (default: 1000)\n"
        << "  --trials=N         Timing trials (default: 10)\n"
        << "  --accuracy_trials=N  Accuracy trials per overlap (default: 100)\n"
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

    CSVWriter csv;
    csv.WriteHeader();

    if (config.mode == "timing") {
        std::cerr << "\n=== Vary k (median of "
                  << config.trials << " trials) ===\n";
        BenchVaryK(config, csv);

        std::cerr << "\n=== Vary m (median of "
                  << config.trials << " trials) ===\n";
        BenchVaryM(config, csv);

        std::cerr << "\n=== Vary set size (median of "
                  << config.trials << " trials) ===\n";
        BenchVarySetSize(config, csv);
    } else if (config.mode == "accuracy") {
        std::cerr << "\n=== Accuracy comparison ("
                  << config.accuracy_trials << " trials per overlap) ===\n";
        BenchAccuracy(config, csv);
    }

    return 0;
}
