#include "benchmark_utils.h"
#include "protocol/piccard.h"

// OpenFHE serialization registration (required for CiphertextSizer)
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <numeric>
#include <random>
#include <set>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;

// Compute exact Jaccard between two sets
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

// Generate two sets with a given overlap fraction
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
// Per-phase timed protocol execution
// ============================================================================

// Precondition: engine.KeyGen() must have been called.
static BenchmarkResult RunTimedProtocol(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& label)
{
    Timer timer;
    BenchmarkResult br;
    br.label = label;
    br.param_k = engine.GetParams().k;
    br.param_m = engine.GetParams().m;
    br.param_set_size = set_x.size();
    br.param_ring_dim = engine.GetParams().ring_dim;

    // Phase 1: MinHash
    timer.Start();
    auto sig_x = engine.ComputeSignature(set_x);
    auto sig_y = engine.ComputeSignature(set_y);
    br.phase_minhash_ms = timer.ElapsedMs();

    // Phase 2: OneHot encode
    timer.Start();
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    br.phase_encode_ms = timer.ElapsedMs();

    // Phase 3: BFV Encrypt (both parties)
    timer.Start();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    br.phase_encrypt_ms = timer.ElapsedMs();

    // Measure ciphertext size
    br.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);

    // Phase 4: Multiply (cloud)
    // Phase 5: Rotate-and-sum (cloud)
    // Mirrors ComputeMatchCount logic (piccard_engine.cpp:38-46)
    const auto& bfv = engine.GetBFVContext();

    timer.Start();
    auto product = bfv.Multiply(ct_x, ct_y);
    br.phase_multiply_ms = timer.ElapsedMs();

    timer.Start();
    auto result = product;
    for (uint32_t step = 1; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(result, static_cast<int>(step));
        result = bfv.Add(result, rotated);
    }
    br.phase_rotate_sum_ms = timer.ElapsedMs();

    // Phase 6: Decrypt (receiver)
    timer.Start();
    auto values = bfv.Decrypt(result);
    int64_t v = values[0];
    br.phase_decrypt_ms = timer.ElapsedMs();

    // Phase 7: Bias correction (receiver)
    timer.Start();
    double k = static_cast<double>(engine.GetParams().k);
    double m = static_cast<double>(engine.GetParams().m);
    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);
    br.phase_bias_correction_ms = timer.ElapsedMs();

    // Totals
    br.time_ms = br.phase_minhash_ms + br.phase_encode_ms +
                 br.phase_encrypt_ms + br.phase_multiply_ms +
                 br.phase_rotate_sum_ms + br.phase_decrypt_ms +
                 br.phase_bias_correction_ms;
    br.memory_bytes = MemoryTracker::GetPeakRSS();
    br.jaccard_computed = j_hat;
    br.jaccard_expected = j_true;
    br.jaccard_error = std::abs(j_hat - j_true);
    br.jaccard_rel_error = (j_true > 0.0) ? (br.jaccard_error / j_true) : -1.0;

    return br;
}

// ============================================================================
// Multi-trial aggregation using ComputeDispersion (replaces local Median)
// ============================================================================

static BenchmarkResult RunMultiTrial(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& label,
    size_t num_trials)
{
    // Warmup iteration (discarded)
    RunTimedProtocol(engine, set_x, set_y, j_true, "warmup");

    std::vector<double> v_total, v_minhash, v_encode, v_encrypt;
    std::vector<double> v_multiply, v_rotate, v_decrypt, v_bias;
    size_t ct_size = 0;
    double sum_j_hat = 0.0, sum_j_err = 0.0;
    size_t rel_eligible = 0;
    double sum_rel_err = 0.0;

    for (size_t t = 0; t < num_trials; t++) {
        auto br = RunTimedProtocol(engine, set_x, set_y, j_true, label);
        v_total.push_back(br.time_ms);
        v_minhash.push_back(br.phase_minhash_ms);
        v_encode.push_back(br.phase_encode_ms);
        v_encrypt.push_back(br.phase_encrypt_ms);
        v_multiply.push_back(br.phase_multiply_ms);
        v_rotate.push_back(br.phase_rotate_sum_ms);
        v_decrypt.push_back(br.phase_decrypt_ms);
        v_bias.push_back(br.phase_bias_correction_ms);
        ct_size = br.ct_size_bytes;
        sum_j_hat += br.jaccard_computed;
        sum_j_err += br.jaccard_error;
        if (j_true > 0.0) {
            sum_rel_err += br.jaccard_error / j_true;
            rel_eligible++;
        }
    }

    auto d_total    = ComputeDispersion(v_total);
    auto d_minhash  = ComputeDispersion(v_minhash);
    auto d_encode   = ComputeDispersion(v_encode);
    auto d_encrypt  = ComputeDispersion(v_encrypt);
    auto d_multiply = ComputeDispersion(v_multiply);
    auto d_rotate   = ComputeDispersion(v_rotate);
    auto d_decrypt  = ComputeDispersion(v_decrypt);
    auto d_bias     = ComputeDispersion(v_bias);

    BenchmarkResult result;
    result.label          = label;
    result.param_k        = engine.GetParams().k;
    result.param_m        = engine.GetParams().m;
    result.param_set_size = set_x.size();
    result.param_ring_dim = engine.GetParams().ring_dim;
    result.trials         = num_trials;

    result.time_ms = d_total.mean;
    result.time_ms_sd = d_total.sd;
    result.time_ms_median = d_total.median;

    result.phase_minhash_ms = d_minhash.mean;
    result.phase_minhash_ms_sd = d_minhash.sd;
    result.phase_minhash_ms_median = d_minhash.median;

    result.phase_encode_ms = d_encode.mean;
    result.phase_encode_ms_sd = d_encode.sd;
    result.phase_encode_ms_median = d_encode.median;

    result.phase_encrypt_ms = d_encrypt.mean;
    result.phase_encrypt_ms_sd = d_encrypt.sd;
    result.phase_encrypt_ms_median = d_encrypt.median;

    result.phase_multiply_ms = d_multiply.mean;
    result.phase_multiply_ms_sd = d_multiply.sd;
    result.phase_multiply_ms_median = d_multiply.median;

    result.phase_rotate_sum_ms = d_rotate.mean;
    result.phase_rotate_sum_ms_sd = d_rotate.sd;
    result.phase_rotate_sum_ms_median = d_rotate.median;

    result.phase_decrypt_ms = d_decrypt.mean;
    result.phase_decrypt_ms_sd = d_decrypt.sd;
    result.phase_decrypt_ms_median = d_decrypt.median;

    result.phase_bias_correction_ms = d_bias.mean;
    result.phase_bias_correction_ms_sd = d_bias.sd;
    result.phase_bias_correction_ms_median = d_bias.median;

    result.memory_bytes  = MemoryTracker::GetPeakRSS();
    result.ct_size_bytes = ct_size;

    double n = static_cast<double>(num_trials);
    result.jaccard_computed = sum_j_hat / n;
    result.jaccard_expected = j_true;
    result.jaccard_error    = sum_j_err / n;
    result.jaccard_rel_error = (rel_eligible > 0)
        ? (sum_rel_err / static_cast<double>(rel_eligible)) : -1.0;
    result.rel_error_eligible_n = rel_eligible;

    // Timing always runs under one CRS; record which, so a timing row is
    // reproducible from the CSV rather than implicitly "whatever the default is".
    result.hash_seed = engine.GetParams().hash_seed;
    result.hash_root_seed = engine.GetParams().hash_seed;
    result.hash_randomness = "fixed";

    return result;
}

// ============================================================================
// Scenario 1: Varying k
// ============================================================================
static void BenchVaryingK(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);

    for (uint32_t k : k_values) {
        PiccardParams params;
        params.k = k;
        params.m = config.m;
        params.security = config.security_level;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        // Warmup with deterministic sets
        {
            auto [wa, wb] = MakeSetsWithOverlap(config.set_size, 0.5);
            double wj = ExactJaccard(wa, wb);
            RunTimedProtocol(engine, wa, wb, wj, "warmup");
        }

        std::vector<double> v_total, v_minhash, v_encode, v_encrypt;
        std::vector<double> v_multiply, v_rotate, v_decrypt, v_bias;
        size_t ct_size = 0;
        double sum_j_hat = 0.0, sum_j_true = 0.0, sum_j_err = 0.0;
        size_t rel_eligible = 0;
        double sum_rel_err = 0.0;

        for (size_t t = 0; t < config.trials; t++) {
            std::mt19937_64 rng(TrialSeed(config.seed, t, 0.5));
            auto [set_a, set_b] = MakeRandomSetsWithOverlap(config.set_size, 0.5, rng);
            double j_true = ExactJaccard(set_a, set_b);

            std::string label = "vary_k_" + std::to_string(k);
            auto br = RunTimedProtocol(engine, set_a, set_b, j_true, label);
            v_total.push_back(br.time_ms);
            v_minhash.push_back(br.phase_minhash_ms);
            v_encode.push_back(br.phase_encode_ms);
            v_encrypt.push_back(br.phase_encrypt_ms);
            v_multiply.push_back(br.phase_multiply_ms);
            v_rotate.push_back(br.phase_rotate_sum_ms);
            v_decrypt.push_back(br.phase_decrypt_ms);
            v_bias.push_back(br.phase_bias_correction_ms);
            ct_size = br.ct_size_bytes;
            sum_j_hat  += br.jaccard_computed;
            sum_j_true += j_true;
            sum_j_err  += br.jaccard_error;
            if (j_true > 0.0) { sum_rel_err += br.jaccard_error / j_true; rel_eligible++; }
        }

        auto d_total    = ComputeDispersion(v_total);
        auto d_minhash  = ComputeDispersion(v_minhash);
        auto d_encode   = ComputeDispersion(v_encode);
        auto d_encrypt  = ComputeDispersion(v_encrypt);
        auto d_multiply = ComputeDispersion(v_multiply);
        auto d_rotate   = ComputeDispersion(v_rotate);
        auto d_decrypt  = ComputeDispersion(v_decrypt);
        auto d_bias     = ComputeDispersion(v_bias);
        double n = static_cast<double>(config.trials);

        BenchmarkResult result;
        result.label = "vary_k_" + std::to_string(k);
        result.param_k = params.k; result.param_m = params.m;
        result.param_set_size = config.set_size; result.param_ring_dim = params.ring_dim;
        result.trials = config.trials;
        result.time_ms = d_total.mean; result.time_ms_sd = d_total.sd; result.time_ms_median = d_total.median;
        result.phase_minhash_ms = d_minhash.mean; result.phase_minhash_ms_sd = d_minhash.sd; result.phase_minhash_ms_median = d_minhash.median;
        result.phase_encode_ms = d_encode.mean; result.phase_encode_ms_sd = d_encode.sd; result.phase_encode_ms_median = d_encode.median;
        result.phase_encrypt_ms = d_encrypt.mean; result.phase_encrypt_ms_sd = d_encrypt.sd; result.phase_encrypt_ms_median = d_encrypt.median;
        result.phase_multiply_ms = d_multiply.mean; result.phase_multiply_ms_sd = d_multiply.sd; result.phase_multiply_ms_median = d_multiply.median;
        result.phase_rotate_sum_ms = d_rotate.mean; result.phase_rotate_sum_ms_sd = d_rotate.sd; result.phase_rotate_sum_ms_median = d_rotate.median;
        result.phase_decrypt_ms = d_decrypt.mean; result.phase_decrypt_ms_sd = d_decrypt.sd; result.phase_decrypt_ms_median = d_decrypt.median;
        result.phase_bias_correction_ms = d_bias.mean; result.phase_bias_correction_ms_sd = d_bias.sd; result.phase_bias_correction_ms_median = d_bias.median;
        result.memory_bytes = MemoryTracker::GetPeakRSS(); result.ct_size_bytes = ct_size;
        result.jaccard_computed = sum_j_hat / n;
        result.jaccard_expected = sum_j_true / n;
        result.jaccard_error    = sum_j_err / n;
        result.jaccard_rel_error = (rel_eligible > 0) ? (sum_rel_err / static_cast<double>(rel_eligible)) : -1.0;
        result.rel_error_eligible_n = rel_eligible;

        csv.WriteRow(result);

        std::cerr << "  k=" << k
                  << " N=" << params.ring_dim
                  << " time=" << result.time_ms << "ms"
                  << " (mul=" << result.phase_multiply_ms
                  << " rot=" << result.phase_rotate_sum_ms << ")"
                  << " ct=" << result.ct_size_bytes << "B"
                  << " J_hat=" << result.jaccard_computed
                  << " err=" << result.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 2: Varying m
// ============================================================================
static void BenchVaryingM(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, config.security_level);

    for (uint32_t m : m_values) {
        PiccardParams params;
        params.k = config.k;
        params.m = m;
        params.security = config.security_level;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        // Warmup with deterministic sets
        {
            auto [wa, wb] = MakeSetsWithOverlap(config.set_size, 0.5);
            double wj = ExactJaccard(wa, wb);
            RunTimedProtocol(engine, wa, wb, wj, "warmup");
        }

        std::vector<double> v_total, v_minhash, v_encode, v_encrypt;
        std::vector<double> v_multiply, v_rotate, v_decrypt, v_bias;
        size_t ct_size = 0;
        double sum_j_hat = 0.0, sum_j_true = 0.0, sum_j_err = 0.0;
        size_t rel_eligible = 0;
        double sum_rel_err = 0.0;

        for (size_t t = 0; t < config.trials; t++) {
            std::mt19937_64 rng(TrialSeed(config.seed, t, 0.5));
            auto [set_a, set_b] = MakeRandomSetsWithOverlap(config.set_size, 0.5, rng);
            double j_true = ExactJaccard(set_a, set_b);

            std::string label = "vary_m_" + std::to_string(m);
            auto br = RunTimedProtocol(engine, set_a, set_b, j_true, label);
            v_total.push_back(br.time_ms);
            v_minhash.push_back(br.phase_minhash_ms);
            v_encode.push_back(br.phase_encode_ms);
            v_encrypt.push_back(br.phase_encrypt_ms);
            v_multiply.push_back(br.phase_multiply_ms);
            v_rotate.push_back(br.phase_rotate_sum_ms);
            v_decrypt.push_back(br.phase_decrypt_ms);
            v_bias.push_back(br.phase_bias_correction_ms);
            ct_size = br.ct_size_bytes;
            sum_j_hat  += br.jaccard_computed;
            sum_j_true += j_true;
            sum_j_err  += br.jaccard_error;
            if (j_true > 0.0) { sum_rel_err += br.jaccard_error / j_true; rel_eligible++; }
        }

        auto d_total    = ComputeDispersion(v_total);
        auto d_minhash  = ComputeDispersion(v_minhash);
        auto d_encode   = ComputeDispersion(v_encode);
        auto d_encrypt  = ComputeDispersion(v_encrypt);
        auto d_multiply = ComputeDispersion(v_multiply);
        auto d_rotate   = ComputeDispersion(v_rotate);
        auto d_decrypt  = ComputeDispersion(v_decrypt);
        auto d_bias     = ComputeDispersion(v_bias);
        double n = static_cast<double>(config.trials);

        BenchmarkResult result;
        result.label = "vary_m_" + std::to_string(m);
        result.param_k = params.k; result.param_m = params.m;
        result.param_set_size = config.set_size; result.param_ring_dim = params.ring_dim;
        result.trials = config.trials;
        result.time_ms = d_total.mean; result.time_ms_sd = d_total.sd; result.time_ms_median = d_total.median;
        result.phase_minhash_ms = d_minhash.mean; result.phase_minhash_ms_sd = d_minhash.sd; result.phase_minhash_ms_median = d_minhash.median;
        result.phase_encode_ms = d_encode.mean; result.phase_encode_ms_sd = d_encode.sd; result.phase_encode_ms_median = d_encode.median;
        result.phase_encrypt_ms = d_encrypt.mean; result.phase_encrypt_ms_sd = d_encrypt.sd; result.phase_encrypt_ms_median = d_encrypt.median;
        result.phase_multiply_ms = d_multiply.mean; result.phase_multiply_ms_sd = d_multiply.sd; result.phase_multiply_ms_median = d_multiply.median;
        result.phase_rotate_sum_ms = d_rotate.mean; result.phase_rotate_sum_ms_sd = d_rotate.sd; result.phase_rotate_sum_ms_median = d_rotate.median;
        result.phase_decrypt_ms = d_decrypt.mean; result.phase_decrypt_ms_sd = d_decrypt.sd; result.phase_decrypt_ms_median = d_decrypt.median;
        result.phase_bias_correction_ms = d_bias.mean; result.phase_bias_correction_ms_sd = d_bias.sd; result.phase_bias_correction_ms_median = d_bias.median;
        result.memory_bytes = MemoryTracker::GetPeakRSS(); result.ct_size_bytes = ct_size;
        result.jaccard_computed = sum_j_hat / n;
        result.jaccard_expected = sum_j_true / n;
        result.jaccard_error    = sum_j_err / n;
        result.jaccard_rel_error = (rel_eligible > 0) ? (sum_rel_err / static_cast<double>(rel_eligible)) : -1.0;
        result.rel_error_eligible_n = rel_eligible;

        csv.WriteRow(result);

        std::cerr << "  m=" << m
                  << " N=" << params.ring_dim
                  << " time=" << result.time_ms << "ms"
                  << " (mul=" << result.phase_multiply_ms
                  << " rot=" << result.phase_rotate_sum_ms << ")"
                  << " ct=" << result.ct_size_bytes << "B"
                  << " err=" << result.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 3: Varying set size
// ============================================================================
static void BenchVaryingSetSize(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000, 100000}, config.security_level);

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.security = config.security_level;
    params.Validate();

    Piccard engine(params);
    engine.KeyGen();

    for (size_t sz : sizes) {
        // Warmup with deterministic sets
        {
            auto [wa, wb] = MakeSetsWithOverlap(sz, 0.5);
            double wj = ExactJaccard(wa, wb);
            RunTimedProtocol(engine, wa, wb, wj, "warmup");
        }

        std::vector<double> v_total, v_minhash, v_encode, v_encrypt;
        std::vector<double> v_multiply, v_rotate, v_decrypt, v_bias;
        size_t ct_size = 0;
        double sum_j_hat = 0.0, sum_j_true = 0.0, sum_j_err = 0.0;
        size_t rel_eligible = 0;
        double sum_rel_err = 0.0;

        for (size_t t = 0; t < config.trials; t++) {
            std::mt19937_64 rng(TrialSeed(config.seed, t, 0.5));
            auto [set_a, set_b] = MakeRandomSetsWithOverlap(sz, 0.5, rng);
            double j_true = ExactJaccard(set_a, set_b);

            std::string label = "vary_size_" + std::to_string(sz);
            auto br = RunTimedProtocol(engine, set_a, set_b, j_true, label);
            v_total.push_back(br.time_ms);
            v_minhash.push_back(br.phase_minhash_ms);
            v_encode.push_back(br.phase_encode_ms);
            v_encrypt.push_back(br.phase_encrypt_ms);
            v_multiply.push_back(br.phase_multiply_ms);
            v_rotate.push_back(br.phase_rotate_sum_ms);
            v_decrypt.push_back(br.phase_decrypt_ms);
            v_bias.push_back(br.phase_bias_correction_ms);
            ct_size = br.ct_size_bytes;
            sum_j_hat  += br.jaccard_computed;
            sum_j_true += j_true;
            sum_j_err  += br.jaccard_error;
            if (j_true > 0.0) { sum_rel_err += br.jaccard_error / j_true; rel_eligible++; }
        }

        auto d_total    = ComputeDispersion(v_total);
        auto d_minhash  = ComputeDispersion(v_minhash);
        auto d_encode   = ComputeDispersion(v_encode);
        auto d_encrypt  = ComputeDispersion(v_encrypt);
        auto d_multiply = ComputeDispersion(v_multiply);
        auto d_rotate   = ComputeDispersion(v_rotate);
        auto d_decrypt  = ComputeDispersion(v_decrypt);
        auto d_bias     = ComputeDispersion(v_bias);
        double n = static_cast<double>(config.trials);

        BenchmarkResult result;
        result.label = "vary_size_" + std::to_string(sz);
        result.param_k = params.k; result.param_m = params.m;
        result.param_set_size = sz; result.param_ring_dim = params.ring_dim;
        result.trials = config.trials;
        result.time_ms = d_total.mean; result.time_ms_sd = d_total.sd; result.time_ms_median = d_total.median;
        result.phase_minhash_ms = d_minhash.mean; result.phase_minhash_ms_sd = d_minhash.sd; result.phase_minhash_ms_median = d_minhash.median;
        result.phase_encode_ms = d_encode.mean; result.phase_encode_ms_sd = d_encode.sd; result.phase_encode_ms_median = d_encode.median;
        result.phase_encrypt_ms = d_encrypt.mean; result.phase_encrypt_ms_sd = d_encrypt.sd; result.phase_encrypt_ms_median = d_encrypt.median;
        result.phase_multiply_ms = d_multiply.mean; result.phase_multiply_ms_sd = d_multiply.sd; result.phase_multiply_ms_median = d_multiply.median;
        result.phase_rotate_sum_ms = d_rotate.mean; result.phase_rotate_sum_ms_sd = d_rotate.sd; result.phase_rotate_sum_ms_median = d_rotate.median;
        result.phase_decrypt_ms = d_decrypt.mean; result.phase_decrypt_ms_sd = d_decrypt.sd; result.phase_decrypt_ms_median = d_decrypt.median;
        result.phase_bias_correction_ms = d_bias.mean; result.phase_bias_correction_ms_sd = d_bias.sd; result.phase_bias_correction_ms_median = d_bias.median;
        result.memory_bytes = MemoryTracker::GetPeakRSS(); result.ct_size_bytes = ct_size;
        result.jaccard_computed = sum_j_hat / n;
        result.jaccard_expected = sum_j_true / n;
        result.jaccard_error    = sum_j_err / n;
        result.jaccard_rel_error = (rel_eligible > 0) ? (sum_rel_err / static_cast<double>(rel_eligible)) : -1.0;
        result.rel_error_eligible_n = rel_eligible;

        csv.WriteRow(result);

        std::cerr << "  size=" << sz
                  << " time=" << result.time_ms << "ms"
                  << " (minhash=" << result.phase_minhash_ms
                  << " enc=" << result.phase_encrypt_ms
                  << " mul=" << result.phase_multiply_ms
                  << " rot=" << result.phase_rotate_sum_ms << ")"
                  << " err=" << result.jaccard_error << "\n";
    }
}

// ============================================================================
// Accuracy across k values (MinHash convergence)
// ============================================================================
static void BenchAccuracyVaryK(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};

    for (uint32_t k : k_values) {
        PiccardParams params;
        params.k = k;
        params.m = config.m;
        params.security = config.security_level;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        double total_error_all = 0;
        size_t count_all = 0;

        for (double frac : overlaps) {
            double total_error = 0;
            for (size_t t = 0; t < config.trials; t++) {
                // Sets and hash family are drawn from separate domains.
                std::mt19937_64 rng(TrialSeed(config.seed, t, frac));
                const uint64_t trial_hash_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? HashTrialSeed(config.seed, t, frac)
                        : params.hash_seed;
                engine.SetHashSeed(trial_hash_seed);
                auto [set_a, set_b] = MakeRandomSetsWithOverlap(
                    config.set_size, frac, rng);
                double j_true = ExactJaccard(set_a, set_b);
                auto result = engine.Run(set_a, set_b);
                double err = std::abs(result.jaccard_estimate - j_true);
                total_error += err;
                total_error_all += err;
                count_all++;

                BenchmarkResult br;
                br.label = "accuracy_k" + std::to_string(k) +
                           "_" + std::to_string(frac) +
                           "_t" + std::to_string(t);
                br.param_k = params.k;
                br.param_m = params.m;
                br.param_set_size = config.set_size;
                br.param_ring_dim = params.ring_dim;
                br.jaccard_computed = result.jaccard_estimate;
                br.jaccard_expected = j_true;
                br.jaccard_error = err;
                br.jaccard_rel_error = (j_true > 0.0) ? (err / j_true) : -1.0;
                br.trials = 1;              // measured single sample, not skipped
                br.accuracy_trials = 1;
                br.hash_randomness = HashRandomnessName(config.hash_randomness);
                br.hash_seed = trial_hash_seed;
                br.hash_root_seed = config.seed;
                csv.WriteRow(br);
            }
        }

        double avg_error = total_error_all / static_cast<double>(count_all);
        std::cerr << "  k=" << k
                  << " avg_error=" << avg_error << "\n";
    }
}

// ============================================================================
// Accuracy across m values
// ============================================================================
static void BenchAccuracyVaryM(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};

    for (uint32_t m : m_values) {
        PiccardParams params;
        params.k = config.k;
        params.m = m;
        params.security = config.security_level;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        double total_error_all = 0;
        size_t count_all = 0;

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                // Sets and hash family are drawn from separate domains.
                std::mt19937_64 rng(TrialSeed(config.seed, t, frac));
                const uint64_t trial_hash_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? HashTrialSeed(config.seed, t, frac)
                        : params.hash_seed;
                engine.SetHashSeed(trial_hash_seed);
                auto [set_a, set_b] = MakeRandomSetsWithOverlap(
                    config.set_size, frac, rng);
                double j_true = ExactJaccard(set_a, set_b);
                auto result = engine.Run(set_a, set_b);
                double err = std::abs(result.jaccard_estimate - j_true);
                total_error_all += err;
                count_all++;

                BenchmarkResult br;
                br.label = "accuracy_m" + std::to_string(m) +
                           "_" + std::to_string(frac) +
                           "_t" + std::to_string(t);
                br.param_k = params.k;
                br.param_m = params.m;
                br.param_set_size = config.set_size;
                br.param_ring_dim = params.ring_dim;
                br.jaccard_computed = result.jaccard_estimate;
                br.jaccard_expected = j_true;
                br.jaccard_error = err;
                br.jaccard_rel_error = (j_true > 0.0) ? (err / j_true) : -1.0;
                br.trials = 1;              // measured single sample, not skipped
                br.accuracy_trials = 1;
                br.hash_randomness = HashRandomnessName(config.hash_randomness);
                br.hash_seed = trial_hash_seed;
                br.hash_root_seed = config.seed;
                csv.WriteRow(br);
            }
        }

        double avg_error = total_error_all / static_cast<double>(count_all);
        std::cerr << "  m=" << m
                  << " avg_error=" << avg_error << "\n";
    }
}

// ============================================================================
// Accuracy across set sizes
// ============================================================================
static void BenchAccuracyVarySetSize(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000, 100000}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.security = config.security_level;
    params.Validate();

    Piccard engine(params);
    engine.KeyGen();

    for (size_t sz : sizes) {
        double total_error_all = 0;
        size_t count_all = 0;

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(TrialSeed(config.seed, t, frac));
                const uint64_t trial_hash_seed =
                    (config.hash_randomness == HashRandomness::Resampled)
                        ? HashTrialSeed(config.seed, t, frac)
                        : params.hash_seed;
                engine.SetHashSeed(trial_hash_seed);
                auto [set_a, set_b] = MakeRandomSetsWithOverlap(sz, frac, rng);
                double j_true = ExactJaccard(set_a, set_b);
                auto result = engine.Run(set_a, set_b);
                double err = std::abs(result.jaccard_estimate - j_true);
                total_error_all += err;
                count_all++;

                BenchmarkResult br;
                br.label = "accuracy_size" + std::to_string(sz) +
                           "_" + std::to_string(frac) +
                           "_t" + std::to_string(t);
                br.param_k = params.k;
                br.param_m = params.m;
                br.param_set_size = sz;
                br.param_ring_dim = params.ring_dim;
                br.jaccard_computed = result.jaccard_estimate;
                br.jaccard_expected = j_true;
                br.jaccard_error = err;
                br.jaccard_rel_error = (j_true > 0.0) ? (err / j_true) : -1.0;
                br.trials = 1;              // measured single sample, not skipped
                br.accuracy_trials = 1;
                br.hash_randomness = HashRandomnessName(config.hash_randomness);
                br.hash_seed = trial_hash_seed;
                br.hash_root_seed = config.seed;
                csv.WriteRow(br);
            }
        }

        double avg_error = total_error_all / static_cast<double>(count_all);
        std::cerr << "  size=" << sz
                  << " avg_error=" << avg_error << "\n";
    }
}

// ============================================================================
// ZLG+24 comparison reference data
// ============================================================================

struct ZLG24Reference {
    std::string config;
    double total_ms;
    std::string hardware;
    std::string source;
};

// Placeholder: fill with actual numbers from ZLG+24 paper tables
static const std::vector<ZLG24Reference> kZLG24Data = {
    // {"k=128,n=1000",  XXX.X, "Intel Xeon ...", "Table X, [ZLG+24]"},
    // {"k=128,n=10000", XXX.X, "Intel Xeon ...", "Table X, [ZLG+24]"},
};

static void PrintComparison(const std::vector<BenchmarkResult>& results) {
    if (kZLG24Data.empty()) {
        std::cerr << "\n=== ZLG+24 comparison ===\n"
                  << "  (No reference data configured. Fill kZLG24Data "
                  << "with published numbers from ZLG+24.)\n";
        return;
    }

    std::cerr << "\n=== Comparison with ZLG+24 ===\n";
    std::cerr << std::left
              << std::setw(20) << "Config"
              << std::setw(16) << "Piccard (ms)"
              << std::setw(16) << "ZLG+24 (ms)"
              << std::setw(10) << "Speedup"
              << "Source\n";
    std::cerr << std::string(62, '-') << "\n";

    for (const auto& ref : kZLG24Data) {
        // Find matching Piccard result by label substring
        for (const auto& br : results) {
            if (br.label.find(ref.config) != std::string::npos ||
                ref.config.find(br.label) != std::string::npos) {
                double speedup = ref.total_ms / br.time_ms;
                std::cerr << std::left
                          << std::setw(20) << ref.config
                          << std::setw(16) << std::fixed << std::setprecision(1) << br.time_ms
                          << std::setw(16) << ref.total_ms
                          << std::setw(10) << std::setprecision(1) << speedup << "x"
                          << ref.source << "\n";
                break;
            }
        }
    }

    if (!kZLG24Data.empty() && !kZLG24Data[0].hardware.empty()) {
        std::cerr << "  ZLG+24 hardware: " << kZLG24Data[0].hardware << "\n";
    }
}

// ============================================================================
// Combined mode: timing + accuracy for each parameter config
// ============================================================================

static void BenchCombinedVaryingK(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);

    for (uint32_t k : k_values) {
        PiccardParams params;
        params.k = k;
        params.m = config.m;
        params.security = config.security_level;
        params.hash_seed = config.seed;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        // Timing phase: fixed sets, median of config.trials runs
        auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, config.overlap);
        double j_true = ExactJaccard(set_a, set_b);
        std::string label = "vary_k_" + std::to_string(k);
        auto br = RunMultiTrial(engine, set_a, set_b, j_true, label, config.trials);

        // Accuracy phase: random sets per trial
        // The timing row above used this fixed CRS; record it before the
        // accuracy loop reseeds the engine.
        const uint64_t timing_hash_seed = params.hash_seed;
        std::vector<std::pair<double, double>> estimates;
        for (size_t t = 0; t < config.accuracy_trials; t++) {
            std::mt19937_64 rng(TrialSeed(config.seed, t, config.overlap));
            engine.SetHashSeed(
                (config.hash_randomness == HashRandomness::Resampled)
                    ? HashTrialSeed(config.seed, t, config.overlap)
                    : timing_hash_seed);
            auto [sa, sb] = MakeRandomSetsWithOverlap(config.set_size, config.overlap, rng);
            double jt = ExactJaccard(sa, sb);
            auto result = engine.Run(sa, sb);
            estimates.emplace_back(result.jaccard_estimate, jt);
        }
        auto stats = ComputeAccuracyStats(estimates);
        br.accuracy_median = stats.median;
        br.accuracy_p25 = stats.p25;
        br.accuracy_p75 = stats.p75;
        br.accuracy_p95 = stats.p95;
        br.accuracy_max = stats.max_error;

        br.accuracy_trials = stats.num_trials;
        br.hash_randomness = HashRandomnessName(config.hash_randomness);
        br.hash_seed = timing_hash_seed;   // CRS the timing measurement used
        br.hash_root_seed = config.seed;

        csv.WriteRow(br);
        std::cerr << "  k=" << k
                  << " time=" << br.time_ms << "ms"
                  << " median_err=" << stats.median
                  << " P95=" << stats.p95 << "\n";
    }
}

static void BenchCombinedVaryingM(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, config.security_level);

    for (uint32_t m : m_values) {
        PiccardParams params;
        params.k = config.k;
        params.m = m;
        params.security = config.security_level;
        params.hash_seed = config.seed;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, config.overlap);
        double j_true = ExactJaccard(set_a, set_b);
        std::string label = "vary_m_" + std::to_string(m);
        auto br = RunMultiTrial(engine, set_a, set_b, j_true, label, config.trials);

        // The timing row above used this fixed CRS; record it before the
        // accuracy loop reseeds the engine.
        const uint64_t timing_hash_seed = params.hash_seed;
        std::vector<std::pair<double, double>> estimates;
        for (size_t t = 0; t < config.accuracy_trials; t++) {
            std::mt19937_64 rng(TrialSeed(config.seed, t, config.overlap));
            engine.SetHashSeed(
                (config.hash_randomness == HashRandomness::Resampled)
                    ? HashTrialSeed(config.seed, t, config.overlap)
                    : timing_hash_seed);
            auto [sa, sb] = MakeRandomSetsWithOverlap(config.set_size, config.overlap, rng);
            double jt = ExactJaccard(sa, sb);
            auto result = engine.Run(sa, sb);
            estimates.emplace_back(result.jaccard_estimate, jt);
        }
        auto stats = ComputeAccuracyStats(estimates);
        br.accuracy_median = stats.median;
        br.accuracy_p25 = stats.p25;
        br.accuracy_p75 = stats.p75;
        br.accuracy_p95 = stats.p95;
        br.accuracy_max = stats.max_error;

        br.accuracy_trials = stats.num_trials;
        br.hash_randomness = HashRandomnessName(config.hash_randomness);
        br.hash_seed = timing_hash_seed;   // CRS the timing measurement used
        br.hash_root_seed = config.seed;

        csv.WriteRow(br);
        std::cerr << "  m=" << m
                  << " time=" << br.time_ms << "ms"
                  << " median_err=" << stats.median
                  << " P95=" << stats.p95 << "\n";
    }
}

static void BenchCombinedVaryingSetSize(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000, 100000}, config.security_level);

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.security = config.security_level;
    params.hash_seed = config.seed;
    params.Validate();

    Piccard engine(params);
    engine.KeyGen();

    for (size_t sz : sizes) {
        auto [set_a, set_b] = MakeSetsWithOverlap(sz, config.overlap);
        double j_true = ExactJaccard(set_a, set_b);
        std::string label = "vary_size_" + std::to_string(sz);
        auto br = RunMultiTrial(engine, set_a, set_b, j_true, label, config.trials);

        // The timing row above used this fixed CRS; record it before the
        // accuracy loop reseeds the engine.
        const uint64_t timing_hash_seed = params.hash_seed;
        std::vector<std::pair<double, double>> estimates;
        for (size_t t = 0; t < config.accuracy_trials; t++) {
            std::mt19937_64 rng(TrialSeed(config.seed, t, config.overlap));
            engine.SetHashSeed(
                (config.hash_randomness == HashRandomness::Resampled)
                    ? HashTrialSeed(config.seed, t, config.overlap)
                    : timing_hash_seed);
            auto [sa, sb] = MakeRandomSetsWithOverlap(sz, config.overlap, rng);
            double jt = ExactJaccard(sa, sb);
            auto result = engine.Run(sa, sb);
            estimates.emplace_back(result.jaccard_estimate, jt);
        }
        auto stats = ComputeAccuracyStats(estimates);
        br.accuracy_median = stats.median;
        br.accuracy_p25 = stats.p25;
        br.accuracy_p75 = stats.p75;
        br.accuracy_p95 = stats.p95;
        br.accuracy_max = stats.max_error;

        br.accuracy_trials = stats.num_trials;
        br.hash_randomness = HashRandomnessName(config.hash_randomness);
        br.hash_seed = timing_hash_seed;   // CRS the timing measurement used
        br.hash_root_seed = config.seed;

        csv.WriteRow(br);
        std::cerr << "  size=" << sz
                  << " time=" << br.time_ms << "ms"
                  << " median_err=" << stats.median
                  << " P95=" << stats.p95 << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        BenchmarkConfig::PrintUsage();
        return 0;
    }

    auto config = BenchmarkConfig::ParseArgs(argc, argv);
    config.Print();

    CSVWriter csv;
    csv.WriteHeader();

    std::vector<BenchmarkResult> all_results;

    if (config.mode == "timing") {
        std::cerr << "\n=== Varying k (median of " << config.trials << " trials) ===\n";
        BenchVaryingK(config, csv);

        std::cerr << "\n=== Varying m (median of " << config.trials << " trials) ===\n";
        BenchVaryingM(config, csv);

        std::cerr << "\n=== Varying set size (median of " << config.trials << " trials) ===\n";
        BenchVaryingSetSize(config, csv);

        PrintComparison(all_results);
    } else if (config.mode == "combined") {
        std::cerr << "\n=== Combined: Varying k (timing + accuracy) ===\n";
        BenchCombinedVaryingK(config, csv);

        std::cerr << "\n=== Combined: Varying m (timing + accuracy) ===\n";
        BenchCombinedVaryingM(config, csv);

        std::cerr << "\n=== Combined: Varying set size (timing + accuracy) ===\n";
        BenchCombinedVaryingSetSize(config, csv);
    } else if (config.mode == "accuracy") {
        std::cerr << "\n=== Accuracy vs k (MinHash convergence) ===\n";
        BenchAccuracyVaryK(config, csv);

        std::cerr << "\n=== Accuracy vs m ===\n";
        BenchAccuracyVaryM(config, csv);

        std::cerr << "\n=== Accuracy vs set size ===\n";
        BenchAccuracyVarySetSize(config, csv);
    }

    return 0;
}
