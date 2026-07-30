#include "benchmark_utils.h"
#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"

#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;
using Clock = std::chrono::high_resolution_clock;

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
};

template <typename Engine>
BenchResult RunBench(Engine& engine, const std::vector<uint64_t>& set_x,
                     const std::vector<uint64_t>& set_y, double j_true) {
    BenchResult r{};
    r.ring_dim = engine.GetParams().ring_dim;
    r.mult_depth = engine.GetParams().mult_depth;
    r.jaccard_true = j_true;
    r.sanitizer = MakeSanitizerMetadata(engine.GetParams());

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

void PrintRow(const std::string& name, uint32_t k, uint32_t m,
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
    row.security = "TOY";
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
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    std::cout << SerializeSqrtComparisonRow(row);
}

int main(int argc, char** argv) {
    const uint32_t n = 500;

    const SqrtComparisonConfig config =
        ResolveSqrtComparisonConfig(argc, argv);
    const uint64_t seed = config.seed;
    const int num_trials = config.trials;

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
                ApplySanitizerConfig(config.sanitizer, p);
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
                ApplySanitizerConfig(config.sanitizer, p);
                p.flood_margin_bits = config.flood_margin_bits;
                p.ValidateSqrt();

                SqrtPiccard engine(p);
                engine.KeyGen();
                sqrt_results.push_back(RunBench(engine, set_x, set_y, j_true));
            }
        }

        PrintRow("OneHot", cfg.k, cfg.m, onehot_results);
        PrintRow("Sqrt", cfg.k, cfg.m, sqrt_results);
    }

    return 0;
}
