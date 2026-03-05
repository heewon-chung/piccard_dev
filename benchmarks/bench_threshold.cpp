#include "benchmark_utils.h"
#include "piccard/protocol/threshold_piccard.h"
#include "piccard/protocol/piccard.h"

// OpenFHE serialization registration (required for CiphertextSizer)
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <memory>
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
// Threshold result struct & CSV writer
// ============================================================================

struct ThresholdResult {
    std::string label;
    uint32_t k = 0;
    uint32_t m = 0;
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

    std::string note;
};

class ThresholdCSVWriter {
    std::ostream* out_;
public:
    ThresholdCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << "label,k,m,ring_dim,tau,mult_depth,"
              << "phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,"
              << "phase_multiply_ms,phase_rotate_sum_ms,phase_mask_ms,"
              << "phase_poly_eval_ms,phase_decrypt_ms,total_ms,"
              << "memory_bytes,ct_size_bytes,"
              << "threshold_result,threshold_expected,threshold_correct,"
              << "note\n";
    }

    void WriteRow(const ThresholdResult& r) {
        *out_ << r.label << ","
              << r.k << "," << r.m << "," << r.ring_dim << ","
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
              << r.note << "\n";
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

// ============================================================================
// Per-phase timed threshold protocol
// ============================================================================

static ThresholdResult RunTimedThreshold(
    const ThresholdPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    bool expected_decision,
    const std::string& label)
{
    Timer timer;
    ThresholdResult tr;
    tr.label = label;
    tr.k = engine.GetParams().k;
    tr.m = engine.GetParams().m;
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

    // Phase 8: Decrypt
    timer.Start();
    auto values = bfv.Decrypt(result);
    bool decision = values[0] >= 1;
    tr.phase_decrypt_ms = timer.ElapsedMs();

    tr.total_ms = tr.phase_minhash_ms + tr.phase_encode_ms + tr.phase_encrypt_ms +
                  tr.phase_multiply_ms + tr.phase_rotate_sum_ms + tr.phase_mask_ms +
                  tr.phase_poly_eval_ms + tr.phase_decrypt_ms;
    tr.memory_bytes = MemoryTracker::GetPeakRSS();
    tr.threshold_result = decision ? 1 : 0;
    tr.threshold_expected = expected_decision ? 1 : 0;
    tr.threshold_correct = (decision == expected_decision) ? 1 : 0;

    return tr;
}

// ============================================================================
// Multi-trial median helper
// ============================================================================

static ThresholdResult RunMultiTrialThreshold(
    const ThresholdPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    bool expected_decision,
    const std::string& label,
    size_t trials)
{
    // Warmup (discarded)
    RunTimedThreshold(engine, set_x, set_y, expected_decision, "warmup");

    std::vector<double> v_total, v_minhash, v_encode, v_encrypt;
    std::vector<double> v_multiply, v_rotate, v_mask, v_poly, v_decrypt;
    size_t ct_size = 0;
    int last_result = 0, last_expected = 0, last_correct = 0;

    for (size_t t = 0; t < trials; t++) {
        auto tr = RunTimedThreshold(engine, set_x, set_y, expected_decision, label);
        v_total.push_back(tr.total_ms);
        v_minhash.push_back(tr.phase_minhash_ms);
        v_encode.push_back(tr.phase_encode_ms);
        v_encrypt.push_back(tr.phase_encrypt_ms);
        v_multiply.push_back(tr.phase_multiply_ms);
        v_rotate.push_back(tr.phase_rotate_sum_ms);
        v_mask.push_back(tr.phase_mask_ms);
        v_poly.push_back(tr.phase_poly_eval_ms);
        v_decrypt.push_back(tr.phase_decrypt_ms);
        ct_size = tr.ct_size_bytes;
        last_result = tr.threshold_result;
        last_expected = tr.threshold_expected;
        last_correct = tr.threshold_correct;
    }

    ThresholdResult med;
    med.label = label;
    med.k = engine.GetParams().k;
    med.m = engine.GetParams().m;
    med.ring_dim = engine.GetParams().ring_dim;
    med.tau = engine.GetParams().threshold_tau;
    med.mult_depth = engine.GetParams().mult_depth;
    med.total_ms = Median(v_total);
    med.phase_minhash_ms = Median(v_minhash);
    med.phase_encode_ms = Median(v_encode);
    med.phase_encrypt_ms = Median(v_encrypt);
    med.phase_multiply_ms = Median(v_multiply);
    med.phase_rotate_sum_ms = Median(v_rotate);
    med.phase_mask_ms = Median(v_mask);
    med.phase_poly_eval_ms = Median(v_poly);
    med.phase_decrypt_ms = Median(v_decrypt);
    med.memory_bytes = MemoryTracker::GetPeakRSS();
    med.ct_size_bytes = ct_size;
    med.threshold_result = last_result;
    med.threshold_expected = last_expected;
    med.threshold_correct = last_correct;

    return med;
}

// Default maximum k based on security level
static uint32_t DefaultMaxK(SecurityLevel sec) {
    switch (sec) {
        case SecurityLevel::TOY:
        case SecurityLevel::STD128:
            return 128;
        case SecurityLevel::STD192:
        case SecurityLevel::STD256:
            return 64;
        default:
            return 64;
    }
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
    }
}

// ============================================================================
// Scenario 1: Varying k
// ============================================================================

static void BenchVaryK(const BenchmarkConfig& config, uint32_t max_k,
                       ThresholdCSVWriter& csv) {
    std::vector<uint32_t> all_k = {16, 32, 64, 128};
    auto [sa, sb] = MakeSetsWithOverlap(config.set_size, 0.5);
    double j_true = ExactJaccard(sa, sb);

    for (uint32_t k : all_k) {
        if (k > max_k) break;

        uint32_t tau = k / 2;
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

        // Compute expected threshold using basic protocol
        auto basic_result = engine->GetPiccard().Run(sa, sb);
        bool expected = basic_result.match_count >= static_cast<int64_t>(tau);

        std::string label = "vary_k_" + std::to_string(k);
        auto tr = RunMultiTrialThreshold(*engine, sa, sb, expected, label,
                                         config.trials);
        csv.WriteRow(tr);

        std::cerr << "  k=" << k << " tau=" << tau
                  << " depth=" << tr.mult_depth
                  << " N=" << tr.ring_dim
                  << " poly_eval=" << tr.phase_poly_eval_ms << "ms"
                  << " total=" << tr.total_ms << "ms\n";
    }
}

// ============================================================================
// Scenario 2: Varying tau (fixed k=64)
// ============================================================================

static void BenchVaryTau(const BenchmarkConfig& config,
                         ThresholdCSVWriter& csv) {
    uint32_t k = 64;
    std::vector<uint32_t> taus = {1, k / 4, k / 2, 3 * k / 4, k};
    auto [sa, sb] = MakeSetsWithOverlap(config.set_size, 0.5);

    for (uint32_t tau : taus) {
        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(k, config.m, tau,
                                                config.security_level,
                                                params, error);
        if (!engine) {
            std::cerr << "  WARNING: Skipped tau=" << tau << ": " << error << "\n";
            auto skipped = MakeSkippedRow(
                "SKIPPED_tau" + std::to_string(tau), k, config.m, tau,
                params.mult_depth, error);
            csv.WriteRow(skipped);
            continue;
        }

        auto basic_result = engine->GetPiccard().Run(sa, sb);
        bool expected = basic_result.match_count >= static_cast<int64_t>(tau);

        std::string label = "vary_tau_" + std::to_string(tau);
        auto tr = RunMultiTrialThreshold(*engine, sa, sb, expected, label,
                                         config.trials);
        csv.WriteRow(tr);

        std::cerr << "  tau=" << tau
                  << " poly_eval=" << tr.phase_poly_eval_ms << "ms"
                  << " total=" << tr.total_ms << "ms"
                  << " correct=" << tr.threshold_correct << "\n";
    }
}

// ============================================================================
// Scenario 3: Threshold vs basic timing comparison
// ============================================================================

static void BenchThresholdVsBasic(const BenchmarkConfig& config, uint32_t max_k,
                                   ThresholdCSVWriter& csv) {
    std::vector<uint32_t> all_k = {16, 32, 64, 128};
    auto [sa, sb] = MakeSetsWithOverlap(config.set_size, 0.5);

    for (uint32_t k : all_k) {
        if (k > max_k) break;

        // Basic protocol timing
        PiccardParams basic_params;
        basic_params.k = k;
        basic_params.m = config.m;
        basic_params.security = config.security_level;
        basic_params.Validate();

        Piccard basic_engine(basic_params);
        basic_engine.KeyGen();

        Timer timer;
        timer.Start();
        auto basic_result = basic_engine.Run(sa, sb);
        double basic_total = timer.ElapsedMs();

        // Threshold protocol
        uint32_t tau = k / 2;
        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(k, config.m, tau,
                                                config.security_level,
                                                params, error);
        if (!engine) {
            auto skipped = MakeSkippedRow(
                "SKIPPED_vs_basic_k" + std::to_string(k), k, config.m, tau,
                params.mult_depth, error);
            csv.WriteRow(skipped);
            continue;
        }

        bool expected = basic_result.match_count >= static_cast<int64_t>(tau);
        std::string label = "vs_basic_k" + std::to_string(k);
        auto tr = RunMultiTrialThreshold(*engine, sa, sb, expected, label,
                                         config.trials);
        csv.WriteRow(tr);

        double overhead = (basic_total > 0) ? tr.total_ms / basic_total : 0.0;
        std::cerr << "  k=" << k
                  << " threshold=" << tr.total_ms << "ms"
                  << " basic=" << basic_total << "ms"
                  << " overhead=" << std::fixed << std::setprecision(1)
                  << overhead << "x\n";
    }
}

// ============================================================================
// Accuracy: threshold decision correctness
// ============================================================================

static void BenchAccuracy(const BenchmarkConfig& config, uint32_t max_k,
                          ThresholdCSVWriter& csv) {
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    uint32_t k = std::min(config.k, max_k);
    std::vector<uint32_t> taus = {k / 4, k / 2, 3 * k / 4};

    for (uint32_t tau : taus) {
        PiccardParams params;
        std::string error;
        auto engine = TryCreateThresholdEngine(k, config.m, tau,
                                                config.security_level,
                                                params, error);
        if (!engine) {
            std::cerr << "  WARNING: Skipped tau=" << tau << ": " << error << "\n";
            continue;
        }

        size_t total_correct = 0;
        size_t total_count = 0;
        size_t false_pos = 0;
        size_t false_neg = 0;

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                auto [sa, sb] = MakeSetsWithOverlap(config.set_size, frac);

                // Expected decision from basic protocol
                auto basic = engine->GetPiccard().Run(sa, sb);
                bool expected = basic.match_count >= static_cast<int64_t>(tau);

                // Threshold protocol decision
                bool result = engine->Run(sa, sb);
                bool correct = (result == expected);

                if (correct) total_correct++;
                if (result && !expected) false_pos++;
                if (!result && expected) false_neg++;
                total_count++;

                ThresholdResult tr;
                tr.label = "accuracy_tau" + std::to_string(tau) +
                           "_" + std::to_string(frac) +
                           "_t" + std::to_string(t);
                tr.k = k;
                tr.m = config.m;
                tr.ring_dim = engine->GetParams().ring_dim;
                tr.tau = tau;
                tr.mult_depth = engine->GetParams().mult_depth;
                tr.threshold_result = result ? 1 : 0;
                tr.threshold_expected = expected ? 1 : 0;
                tr.threshold_correct = correct ? 1 : 0;
                csv.WriteRow(tr);
            }
        }

        double accuracy = (total_count > 0)
            ? 100.0 * total_correct / total_count : 0.0;
        double fp_rate = (total_count > 0)
            ? 100.0 * false_pos / total_count : 0.0;
        double fn_rate = (total_count > 0)
            ? 100.0 * false_neg / total_count : 0.0;

        std::cerr << "  tau=" << tau
                  << " accuracy=" << std::fixed << std::setprecision(1)
                  << accuracy << "%"
                  << " FP=" << fp_rate << "%"
                  << " FN=" << fn_rate << "%"
                  << " (" << total_correct << "/" << total_count << ")\n";
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: bench_threshold [options]\n"
                  << "Options:\n"
                  << "  --k=N              Number of MinHash functions (default: 128)\n"
                  << "  --m=N              One-hot bucket size (default: 64)\n"
                  << "  --set_size=N       Size of each party's set (default: 100)\n"
                  << "  --tau=T            Threshold value (default: k/2)\n"
                  << "  --max_k=K          Maximum k to attempt (default: per security)\n"
                  << "  --trials=N         Number of trials to run (default: 10)\n"
                  << "  --mode=MODE        'accuracy' or 'timing' (default: timing)\n"
                  << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256'\n";
        return 0;
    }

    auto config = BenchmarkConfig::ParseArgs(argc, argv);

    // Parse additional flags not in BenchmarkConfig
    uint32_t max_k = DefaultMaxK(config.security_level);
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg.find("--tau=") == 0) {
            // tau is per-scenario; this is just noted
        } else if (arg.find("--max_k=") == 0) {
            max_k = static_cast<uint32_t>(std::stoul(arg.substr(8)));
        }
    }

    config.Print();
    std::cerr << "  Max k:     " << max_k << "\n";

    ThresholdCSVWriter csv;
    csv.WriteHeader();

    if (config.mode == "timing") {
        std::cerr << "\n=== Varying k (median of " << config.trials << " trials) ===\n";
        BenchVaryK(config, max_k, csv);

        std::cerr << "\n=== Varying tau (median of " << config.trials << " trials) ===\n";
        BenchVaryTau(config, csv);

        std::cerr << "\n=== Threshold vs Basic ===\n";
        BenchThresholdVsBasic(config, max_k, csv);
    } else if (config.mode == "accuracy") {
        std::cerr << "\n=== Threshold Accuracy ===\n";
        BenchAccuracy(config, max_k, csv);
    }

    return 0;
}
