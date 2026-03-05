#include "benchmark_utils.h"
#include "piccard/protocol/piccard.h"

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

    return br;
}

// ============================================================================
// Multi-trial median helper
// ============================================================================

static double Median(std::vector<double>& v) {
    size_t n = v.size();
    if (n == 0) return 0.0;
    std::sort(v.begin(), v.end());
    if (n % 2 == 0) return (v[n / 2 - 1] + v[n / 2]) / 2.0;
    return v[n / 2];
}

static BenchmarkResult RunMultiTrial(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& label,
    size_t trials)
{
    // Warmup iteration (discarded)
    RunTimedProtocol(engine, set_x, set_y, j_true, "warmup");

    std::vector<double> v_total, v_minhash, v_encode, v_encrypt;
    std::vector<double> v_multiply, v_rotate, v_decrypt, v_bias;
    size_t ct_size = 0;
    double last_j_hat = 0.0;
    double total_error = 0.0;

    for (size_t t = 0; t < trials; t++) {
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
        last_j_hat = br.jaccard_computed;
        total_error += br.jaccard_error;
    }

    BenchmarkResult median;
    median.label = label;
    median.param_k = engine.GetParams().k;
    median.param_m = engine.GetParams().m;
    median.param_ring_dim = engine.GetParams().ring_dim;
    median.time_ms = Median(v_total);
    median.phase_minhash_ms = Median(v_minhash);
    median.phase_encode_ms = Median(v_encode);
    median.phase_encrypt_ms = Median(v_encrypt);
    median.phase_multiply_ms = Median(v_multiply);
    median.phase_rotate_sum_ms = Median(v_rotate);
    median.phase_decrypt_ms = Median(v_decrypt);
    median.phase_bias_correction_ms = Median(v_bias);
    median.memory_bytes = MemoryTracker::GetPeakRSS();
    median.ct_size_bytes = ct_size;
    median.jaccard_computed = last_j_hat;
    median.jaccard_expected = j_true;
    median.jaccard_error = total_error / static_cast<double>(trials);

    return median;
}

// ============================================================================
// Scenario 1: Varying k
// ============================================================================
static void BenchVaryingK(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> k_values = {64, 128, 256, 512, 1024};
    auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, 0.5);
    double j_true = ExactJaccard(set_a, set_b);

    for (uint32_t k : k_values) {
        PiccardParams params;
        params.k = k;
        params.m = config.m;
        params.security = config.security_level;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        std::string label = "vary_k_" + std::to_string(k);
        auto br = RunMultiTrial(engine, set_a, set_b, j_true, label,
                                config.trials);
        csv.WriteRow(br);

        std::cerr << "  k=" << k
                  << " N=" << params.ring_dim
                  << " time=" << br.time_ms << "ms"
                  << " (mul=" << br.phase_multiply_ms
                  << " rot=" << br.phase_rotate_sum_ms << ")"
                  << " ct=" << br.ct_size_bytes << "B"
                  << " J_hat=" << br.jaccard_computed
                  << " err=" << br.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 2: Varying m
// ============================================================================
static void BenchVaryingM(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> m_values = {16, 32, 64, 128, 256};
    auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, 0.5);
    double j_true = ExactJaccard(set_a, set_b);

    for (uint32_t m : m_values) {
        PiccardParams params;
        params.k = config.k;
        params.m = m;
        params.security = config.security_level;
        params.Validate();

        Piccard engine(params);
        engine.KeyGen();

        std::string label = "vary_m_" + std::to_string(m);
        auto br = RunMultiTrial(engine, set_a, set_b, j_true, label,
                                config.trials);
        csv.WriteRow(br);

        std::cerr << "  m=" << m
                  << " N=" << params.ring_dim
                  << " time=" << br.time_ms << "ms"
                  << " (mul=" << br.phase_multiply_ms
                  << " rot=" << br.phase_rotate_sum_ms << ")"
                  << " ct=" << br.ct_size_bytes << "B"
                  << " err=" << br.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 3: Varying set size
// ============================================================================
static void BenchVaryingSetSize(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<size_t> sizes = {1000, 10000, 50000, 100000, 500000, 1000000};

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.security = config.security_level;
    params.Validate();

    Piccard engine(params);
    engine.KeyGen();

    for (size_t sz : sizes) {
        auto [set_a, set_b] = MakeSetsWithOverlap(sz, 0.5);
        double j_true = ExactJaccard(set_a, set_b);

        std::string label = "vary_size_" + std::to_string(sz);
        auto br = RunMultiTrial(engine, set_a, set_b, j_true, label,
                                config.trials);
        csv.WriteRow(br);

        std::cerr << "  size=" << sz
                  << " time=" << br.time_ms << "ms"
                  << " (minhash=" << br.phase_minhash_ms
                  << " enc=" << br.phase_encrypt_ms
                  << " mul=" << br.phase_multiply_ms
                  << " rot=" << br.phase_rotate_sum_ms << ")"
                  << " err=" << br.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 4: Accuracy across similarity levels
// ============================================================================
static void BenchAccuracy(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.security = config.security_level;
    params.Validate();

    Piccard engine(params);
    engine.KeyGen();

    for (double frac : overlaps) {
        double total_error = 0;
        for (size_t t = 0; t < config.trials; t++) {
            auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, frac);
            double j_true = ExactJaccard(set_a, set_b);
            auto result = engine.Run(set_a, set_b);
            total_error += std::abs(result.jaccard_estimate - j_true);

            BenchmarkResult br;
            br.label = "accuracy_" + std::to_string(frac) + "_t" + std::to_string(t);
            br.param_k = params.k;
            br.param_m = params.m;
            br.param_ring_dim = params.ring_dim;
            br.jaccard_computed = result.jaccard_estimate;
            br.jaccard_expected = j_true;
            br.jaccard_error = std::abs(result.jaccard_estimate - j_true);
            csv.WriteRow(br);
        }
        double avg_error = total_error / static_cast<double>(config.trials);
        std::cerr << "  overlap=" << frac
                  << " avg_error=" << avg_error << "\n";
    }
}

// ============================================================================
// Scenario 5: Accuracy across k values (MinHash convergence)
// ============================================================================
static void BenchAccuracyVaryK(const BenchmarkConfig& config, CSVWriter& csv) {
    std::vector<uint32_t> k_values = {64, 128, 256, 512, 1024};
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
                auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, frac);
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
                br.param_ring_dim = params.ring_dim;
                br.jaccard_computed = result.jaccard_estimate;
                br.jaccard_expected = j_true;
                br.jaccard_error = err;
                csv.WriteRow(br);
            }
        }

        double avg_error = total_error_all / static_cast<double>(count_all);
        std::cerr << "  k=" << k
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
    } else if (config.mode == "accuracy") {
        std::cerr << "\n=== Accuracy (fixed k=" << config.k << ") ===\n";
        BenchAccuracy(config, csv);

        std::cerr << "\n=== Accuracy vs k (MinHash convergence) ===\n";
        BenchAccuracyVaryK(config, csv);
    }

    return 0;
}
