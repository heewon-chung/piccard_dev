#include "benchmark_utils.h"
#include "protocol/dynamic_piccard.h"
#include "core/bottom_structure.h"

// OpenFHE serialization registration (required for CiphertextSizer)
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <set>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;

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

static double Median(std::vector<double>& v) {
    size_t n = v.size();
    if (n == 0) return 0.0;
    std::sort(v.begin(), v.end());
    if (n % 2 == 0) return (v[n / 2 - 1] + v[n / 2]) / 2.0;
    return v[n / 2];
}

// ============================================================================
// Dynamic result struct & CSV writer
// ============================================================================

struct DynamicResult {
    std::string label;
    uint32_t k = 0;
    uint32_t m = 0;
    size_t set_size = 0;
    uint32_t ring_dim = 0;
    uint32_t depth = 0;

    double phase_init_ms = 0.0;
    double phase_insert_ms = 0.0;
    double phase_delete_ms = 0.0;
    double phase_signature_ms = 0.0;
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_compute_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;

    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = 0.0;
    double jaccard_rel_error = 0.0;  // |J_hat - J_true| / J_true (-1 if J_true=0)

    double ops_insert_per_sec = 0.0;
    double ops_delete_per_sec = 0.0;
};

class DynamicCSVWriter {
    std::ostream* out_;
public:
    DynamicCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << "label,k,m,set_size,ring_dim,depth,"
              << "phase_init_ms,phase_insert_ms,phase_delete_ms,"
              << "phase_signature_ms,phase_encode_ms,phase_encrypt_ms,"
              << "phase_compute_ms,phase_decrypt_ms,total_ms,"
              << "memory_bytes,ct_size_bytes,"
              << "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
              << "ops_insert_per_sec,ops_delete_per_sec\n";
    }

    void WriteRow(const DynamicResult& r) {
        *out_ << r.label << ","
              << r.k << "," << r.m << "," << r.set_size << "," << r.ring_dim << "," << r.depth << ","
              << std::fixed << std::setprecision(3)
              << r.phase_init_ms << "," << r.phase_insert_ms << ","
              << r.phase_delete_ms << "," << r.phase_signature_ms << ","
              << r.phase_encode_ms << "," << r.phase_encrypt_ms << ","
              << r.phase_compute_ms << "," << r.phase_decrypt_ms << ","
              << r.total_ms << ","
              << r.memory_bytes << "," << r.ct_size_bytes << ","
              << std::fixed << std::setprecision(6)
              << r.jaccard_computed << "," << r.jaccard_expected << ","
              << r.jaccard_error << "," << r.jaccard_rel_error << ","
              << std::fixed << std::setprecision(1)
              << r.ops_insert_per_sec << "," << r.ops_delete_per_sec << "\n";
    }
};

// ============================================================================
// Per-phase timed dynamic protocol execution
// ============================================================================

static DynamicResult RunTimedDynamic(
    const DynamicPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    uint32_t depth,
    const std::string& label)
{
    Timer timer;
    DynamicResult dr;
    dr.label = label;
    dr.k = engine.GetParams().k;
    dr.m = engine.GetParams().m;
    dr.set_size = set_x.size();
    dr.ring_dim = engine.GetParams().ring_dim;
    dr.depth = depth;

    // Phase 1: BottomStructure Initialize (plaintext only)
    timer.Start();
    auto bottom_x = engine.InitSet(set_x);
    auto bottom_y = engine.InitSet(set_y);
    dr.phase_init_ms = timer.ElapsedMs();

    // Phase 2: Insert throughput — batch of 100 inserts (plaintext only)
    const size_t num_ops = 100;
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        bottom_x->Insert(3000000 + i);
    }
    dr.phase_insert_ms = timer.ElapsedMs();
    dr.ops_insert_per_sec = (dr.phase_insert_ms > 0)
        ? (num_ops / (dr.phase_insert_ms / 1000.0)) : 0.0;

    // Phase 3: Delete throughput — undo the inserts (plaintext only)
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        bottom_x->Delete(3000000 + i);
    }
    dr.phase_delete_ms = timer.ElapsedMs();
    dr.ops_delete_per_sec = (dr.phase_delete_ms > 0)
        ? (num_ops / (dr.phase_delete_ms / 1000.0)) : 0.0;

    // Phase 4: GetSignature (plaintext only)
    timer.Start();
    auto sig_x = bottom_x->GetSignature();
    auto sig_y = bottom_y->GetSignature();
    dr.phase_signature_ms = timer.ElapsedMs();

    // Phase 5: Encode
    timer.Start();
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    dr.phase_encode_ms = timer.ElapsedMs();

    // Phase 6: Encrypt
    timer.Start();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    dr.phase_encrypt_ms = timer.ElapsedMs();

    dr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);

    // Phase 7: Compute — multiply + rotate-sum (identical to basic protocol)
    const auto& bfv = engine.GetBFVContext();
    timer.Start();
    auto product = bfv.Multiply(ct_x, ct_y);
    auto result = product;
    for (uint32_t step = 1; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(result, static_cast<int>(step));
        result = bfv.Add(result, rotated);
    }
    dr.phase_compute_ms = timer.ElapsedMs();

    // Phase 8: Decrypt + bias correction
    timer.Start();
    auto values = bfv.Decrypt(result);
    int64_t v = values[0];
    double k = static_cast<double>(engine.GetParams().k);
    double m = static_cast<double>(engine.GetParams().m);
    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);
    j_hat = std::max(0.0, std::min(1.0, j_hat));
    dr.phase_decrypt_ms = timer.ElapsedMs();

    dr.total_ms = dr.phase_init_ms + dr.phase_insert_ms + dr.phase_delete_ms +
                  dr.phase_signature_ms + dr.phase_encode_ms + dr.phase_encrypt_ms +
                  dr.phase_compute_ms + dr.phase_decrypt_ms;
    dr.memory_bytes = MemoryTracker::GetPeakRSS();
    dr.jaccard_computed = j_hat;
    dr.jaccard_expected = j_true;
    dr.jaccard_error = std::abs(j_hat - j_true);
    dr.jaccard_rel_error = (j_true > 0.0) ? (dr.jaccard_error / j_true) : -1.0;

    return dr;
}

// ============================================================================
// Multi-trial median helper
// ============================================================================

static DynamicResult RunMultiTrialDynamic(
    const DynamicPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    uint32_t depth,
    const std::string& label,
    size_t trials)
{
    // Warmup (discarded)
    RunTimedDynamic(engine, set_x, set_y, j_true, depth, "warmup");

    std::vector<double> v_total, v_init, v_insert, v_delete, v_sig;
    std::vector<double> v_encode, v_encrypt, v_compute, v_decrypt;
    size_t ct_size = 0;
    double last_j = 0.0, total_err = 0.0;
    double last_ins = 0.0, last_del = 0.0;

    for (size_t t = 0; t < trials; t++) {
        auto dr = RunTimedDynamic(engine, set_x, set_y, j_true, depth, label);
        v_total.push_back(dr.total_ms);
        v_init.push_back(dr.phase_init_ms);
        v_insert.push_back(dr.phase_insert_ms);
        v_delete.push_back(dr.phase_delete_ms);
        v_sig.push_back(dr.phase_signature_ms);
        v_encode.push_back(dr.phase_encode_ms);
        v_encrypt.push_back(dr.phase_encrypt_ms);
        v_compute.push_back(dr.phase_compute_ms);
        v_decrypt.push_back(dr.phase_decrypt_ms);
        ct_size = dr.ct_size_bytes;
        last_j = dr.jaccard_computed;
        total_err += dr.jaccard_error;
        last_ins = dr.ops_insert_per_sec;
        last_del = dr.ops_delete_per_sec;
    }

    DynamicResult med;
    med.label = label;
    med.k = engine.GetParams().k;
    med.m = engine.GetParams().m;
    med.set_size = set_x.size();
    med.ring_dim = engine.GetParams().ring_dim;
    med.depth = depth;
    med.total_ms = Median(v_total);
    med.phase_init_ms = Median(v_init);
    med.phase_insert_ms = Median(v_insert);
    med.phase_delete_ms = Median(v_delete);
    med.phase_signature_ms = Median(v_sig);
    med.phase_encode_ms = Median(v_encode);
    med.phase_encrypt_ms = Median(v_encrypt);
    med.phase_compute_ms = Median(v_compute);
    med.phase_decrypt_ms = Median(v_decrypt);
    med.memory_bytes = MemoryTracker::GetPeakRSS();
    med.ct_size_bytes = ct_size;
    med.jaccard_computed = last_j;
    med.jaccard_expected = j_true;
    med.jaccard_error = total_err / static_cast<double>(trials);
    med.ops_insert_per_sec = last_ins;
    med.ops_delete_per_sec = last_del;

    return med;
}

// ============================================================================
// Scenario 1: Varying k
// ============================================================================

static void BenchVaryK(const BenchmarkConfig& config, uint32_t depth,
                       DynamicCSVWriter& csv) {
    std::vector<uint32_t> k_values = {16, 32, 64, 128, 256, 512};
    // BottomStructure requires set_size >> k to populate all hash buckets
    size_t effective_size = std::max(config.set_size, size_t{10000});
    auto [sa, sb] = MakeSetsWithOverlap(effective_size, 0.5);
    double j_true = ExactJaccard(sa, sb);

    for (uint32_t k : k_values) {
        try {
            PiccardParams params;
            params.k = k;
            params.m = config.m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            std::string label = "vary_k_" + std::to_string(k);
            auto dr = RunMultiTrialDynamic(engine, sa, sb, j_true, depth, label,
                                           config.trials);
            csv.WriteRow(dr);

            std::cerr << "  k=" << k << " d=" << depth
                      << " init=" << dr.phase_init_ms << "ms"
                      << " ins=" << dr.ops_insert_per_sec << " ops/s"
                      << " del=" << dr.ops_delete_per_sec << " ops/s"
                      << " total=" << dr.total_ms << "ms\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: Skipped k=" << k << ": " << e.what() << "\n";
        }
    }
}

// ============================================================================
// Scenario 2: Varying m
// ============================================================================

static void BenchVaryM(const BenchmarkConfig& config, uint32_t depth,
                       DynamicCSVWriter& csv) {
    std::vector<uint32_t> m_values = {16, 32, 64, 128, 256};
    size_t effective_size = std::max(config.set_size, size_t{10000});
    auto [sa, sb] = MakeSetsWithOverlap(effective_size, 0.5);
    double j_true = ExactJaccard(sa, sb);

    for (uint32_t m : m_values) {
        try {
            PiccardParams params;
            params.k = config.k;
            params.m = m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            std::string label = "vary_m_" + std::to_string(m);
            auto dr = RunMultiTrialDynamic(engine, sa, sb, j_true, depth, label,
                                           config.trials);
            csv.WriteRow(dr);

            std::cerr << "  m=" << m << " d=" << depth
                      << " init=" << dr.phase_init_ms << "ms"
                      << " ins=" << dr.ops_insert_per_sec << " ops/s"
                      << " del=" << dr.ops_delete_per_sec << " ops/s"
                      << " total=" << dr.total_ms << "ms\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: Skipped m=" << m << ": " << e.what() << "\n";
        }
    }
}

// ============================================================================
// Scenario 3: Varying set size
// ============================================================================

static void BenchVarySetSize(const BenchmarkConfig& config, uint32_t depth,
                             DynamicCSVWriter& csv) {
    std::vector<size_t> sizes = {100, 1000, 10000, 100000};

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.bottom_depth = depth;
    params.security = config.security_level;
    params.Validate();

    DynamicPiccard engine(params);
    engine.KeyGen();

    for (size_t sz : sizes) {
        try {
            auto [sa, sb] = MakeSetsWithOverlap(sz, 0.5);
            double j_true = ExactJaccard(sa, sb);

            std::string label = "vary_size_" + std::to_string(sz);
            auto dr = RunMultiTrialDynamic(engine, sa, sb, j_true, depth, label,
                                           config.trials);
            csv.WriteRow(dr);

            std::cerr << "  size=" << sz
                      << " init=" << dr.phase_init_ms << "ms"
                      << " total=" << dr.total_ms << "ms\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: Skipped size=" << sz << ": " << e.what() << "\n";
        }
    }
}

// ============================================================================
// Accuracy: varying k
// ============================================================================

static void BenchAccuracyVaryK(const BenchmarkConfig& config, uint32_t depth,
                                DynamicCSVWriter& csv) {
    std::vector<uint32_t> k_values = {16, 32, 64, 128, 256, 512};
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    for (uint32_t k : k_values) {
        try {
            PiccardParams params;
            params.k = k;
            params.m = config.m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            double total_error_all = 0;
            size_t count_all = 0;

            for (double frac : overlaps) {
                for (size_t t = 0; t < config.trials; t++) {
                    std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                    auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(
                        config.set_size, frac, rng);
                    double j_true = ExactJaccard(sa, sb);

                    auto bottom_x = engine.InitSet(sa);
                    auto bottom_y = engine.InitSet(sb);
                    auto result = engine.Run(*bottom_x, *bottom_y);
                    double err = std::abs(result.jaccard_estimate - j_true);
                    total_error_all += err;
                    count_all++;

                    DynamicResult dr;
                    dr.label = "accuracy_k" + std::to_string(k) +
                               "_" + std::to_string(frac) +
                               "_t" + std::to_string(t);
                    dr.k = params.k;
                    dr.m = params.m;
                    dr.set_size = config.set_size;
                    dr.ring_dim = engine.GetParams().ring_dim;
                    dr.depth = depth;
                    dr.jaccard_computed = result.jaccard_estimate;
                    dr.jaccard_expected = j_true;
                    dr.jaccard_error = err;
                    dr.jaccard_rel_error = (j_true > 0.0) ? (err / j_true) : -1.0;
                    csv.WriteRow(dr);
                }
            }

            double avg_error = total_error_all / static_cast<double>(count_all);
            std::cerr << "  k=" << k << " avg_error=" << avg_error << "\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: Skipped k=" << k << ": " << e.what() << "\n";
        }
    }
}

// ============================================================================
// Accuracy: varying m
// ============================================================================

static void BenchAccuracyVaryM(const BenchmarkConfig& config, uint32_t depth,
                                DynamicCSVWriter& csv) {
    std::vector<uint32_t> m_values = {16, 32, 64, 128, 256};
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    for (uint32_t m : m_values) {
        try {
            PiccardParams params;
            params.k = config.k;
            params.m = m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            double total_error_all = 0;
            size_t count_all = 0;

            for (double frac : overlaps) {
                for (size_t t = 0; t < config.trials; t++) {
                    std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                    auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(
                        config.set_size, frac, rng);
                    double j_true = ExactJaccard(sa, sb);

                    auto bottom_x = engine.InitSet(sa);
                    auto bottom_y = engine.InitSet(sb);
                    auto result = engine.Run(*bottom_x, *bottom_y);
                    double err = std::abs(result.jaccard_estimate - j_true);
                    total_error_all += err;
                    count_all++;

                    DynamicResult dr;
                    dr.label = "accuracy_m" + std::to_string(m) +
                               "_" + std::to_string(frac) +
                               "_t" + std::to_string(t);
                    dr.k = params.k;
                    dr.m = params.m;
                    dr.set_size = config.set_size;
                    dr.ring_dim = engine.GetParams().ring_dim;
                    dr.depth = depth;
                    dr.jaccard_computed = result.jaccard_estimate;
                    dr.jaccard_expected = j_true;
                    dr.jaccard_error = err;
                    dr.jaccard_rel_error = (j_true > 0.0) ? (err / j_true) : -1.0;
                    csv.WriteRow(dr);
                }
            }

            double avg_error = total_error_all / static_cast<double>(count_all);
            std::cerr << "  m=" << m << " avg_error=" << avg_error << "\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: Skipped m=" << m << ": " << e.what() << "\n";
        }
    }
}

// ============================================================================
// Accuracy: varying set size
// ============================================================================

static void BenchAccuracyVarySetSize(const BenchmarkConfig& config, uint32_t depth,
                                      DynamicCSVWriter& csv) {
    std::vector<size_t> sizes = {100, 1000, 10000};
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    for (size_t sz : sizes) {
        try {
            PiccardParams params;
            params.k = config.k;
            params.m = config.m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            double total_error_all = 0;
            size_t count_all = 0;

            for (double frac : overlaps) {
                for (size_t t = 0; t < config.trials; t++) {
                    std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                    auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(sz, frac, rng);
                    double j_true = ExactJaccard(sa, sb);

                    auto bottom_x = engine.InitSet(sa);
                    auto bottom_y = engine.InitSet(sb);
                    auto result = engine.Run(*bottom_x, *bottom_y);
                    double err = std::abs(result.jaccard_estimate - j_true);
                    total_error_all += err;
                    count_all++;

                    DynamicResult dr;
                    dr.label = "accuracy_size" + std::to_string(sz) +
                               "_" + std::to_string(frac) +
                               "_t" + std::to_string(t);
                    dr.k = params.k;
                    dr.m = params.m;
                    dr.set_size = sz;
                    dr.ring_dim = engine.GetParams().ring_dim;
                    dr.depth = depth;
                    dr.jaccard_computed = result.jaccard_estimate;
                    dr.jaccard_expected = j_true;
                    dr.jaccard_error = err;
                    dr.jaccard_rel_error = (j_true > 0.0) ? (err / j_true) : -1.0;
                    csv.WriteRow(dr);
                }
            }

            double avg_error = total_error_all / static_cast<double>(count_all);
            std::cerr << "  size=" << sz << " avg_error=" << avg_error << "\n";
        } catch (const std::exception& e) {
            std::cerr << "  WARNING: Skipped size=" << sz << ": " << e.what() << "\n";
        }
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: bench_dynamic [options]\n"
                  << "Options:\n"
                  << "  --k=N              Number of MinHash functions (default: 128)\n"
                  << "  --m=N              One-hot bucket size (default: 64)\n"
                  << "  --set_size=N       Size of each party's set (default: 100)\n"
                  << "  --depth=D          BottomStructure depth (default: 5)\n"
                  << "  --trials=N         Number of trials to run (default: 10)\n"
                  << "  --mode=MODE        'accuracy' or 'timing' (default: timing)\n"
                  << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256'\n";
        return 0;
    }

    auto config = BenchmarkConfig::ParseArgs(argc, argv);

    // Parse --depth flag (not in BenchmarkConfig)
    uint32_t depth = 5;
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg.find("--depth=") == 0) {
            depth = static_cast<uint32_t>(std::stoul(arg.substr(8)));
        }
    }

    config.Print();
    std::cerr << "  Depth:     " << depth << "\n";

    DynamicCSVWriter csv;
    csv.WriteHeader();

    if (config.mode == "timing") {
        std::cerr << "\n=== Varying k (median of " << config.trials << " trials) ===\n";
        BenchVaryK(config, depth, csv);

        std::cerr << "\n=== Varying m (median of " << config.trials << " trials) ===\n";
        BenchVaryM(config, depth, csv);

        std::cerr << "\n=== Varying set size (median of " << config.trials << " trials) ===\n";
        BenchVarySetSize(config, depth, csv);
    } else if (config.mode == "accuracy") {
        std::cerr << "\n=== Accuracy vs k ===\n";
        BenchAccuracyVaryK(config, depth, csv);

        std::cerr << "\n=== Accuracy vs m ===\n";
        BenchAccuracyVaryM(config, depth, csv);

        std::cerr << "\n=== Accuracy vs set size ===\n";
        BenchAccuracyVarySetSize(config, depth, csv);
    }

    return 0;
}
