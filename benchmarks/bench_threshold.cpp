#include "benchmark_utils.h"
#include "protocol/threshold_piccard.h"
#include "protocol/piccard.h"

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
};

class ThresholdCSVWriter {
    std::ostream* out_;
public:
    ThresholdCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << "label,k,m,set_size,ring_dim,tau,mult_depth,"
              << "phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,"
              << "phase_multiply_ms,phase_rotate_sum_ms,phase_mask_ms,"
              << "phase_poly_eval_ms,phase_decrypt_ms,total_ms,"
              << "memory_bytes,ct_size_bytes,"
              << "threshold_result,threshold_expected,threshold_correct,"
              << "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
              << "note,"
              // dispersion columns (additive)
              << "trials,"
              << "total_ms_sd,total_ms_median,"
              << "phase_minhash_ms_sd,phase_minhash_ms_median,"
              << "phase_encode_ms_sd,phase_encode_ms_median,"
              << "phase_encrypt_ms_sd,phase_encrypt_ms_median,"
              << "phase_multiply_ms_sd,phase_multiply_ms_median,"
              << "phase_rotate_sum_ms_sd,phase_rotate_sum_ms_median,"
              << "phase_mask_ms_sd,phase_mask_ms_median,"
              << "phase_poly_eval_ms_sd,phase_poly_eval_ms_median,"
              << "phase_decrypt_ms_sd,phase_decrypt_ms_median,"
              << "rel_error_eligible_n\n";
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
              << r.rel_error_eligible_n << "\n";
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

    auto d_tot = ComputeDispersion(v_total);
    auto d_mnh = ComputeDispersion(v_minhash);
    auto d_enc = ComputeDispersion(v_encode);
    auto d_cry = ComputeDispersion(v_encrypt);
    auto d_mul = ComputeDispersion(v_multiply);
    auto d_rot = ComputeDispersion(v_rotate);
    auto d_msk = ComputeDispersion(v_mask);
    auto d_pol = ComputeDispersion(v_poly);
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
    result.phase_decrypt_ms   = d_dec.mean; result.phase_decrypt_ms_sd   = d_dec.sd; result.phase_decrypt_ms_median   = d_dec.median;
    result.memory_bytes = MemoryTracker::GetPeakRSS();
    result.ct_size_bytes = ct_size;
    result.trials = trials;
    result.threshold_result = last_result;
    result.threshold_expected = last_expected;
    result.threshold_correct = last_correct;
    // threshold benchmark has no per-trial jaccard fields in timing mode
    result.rel_error_eligible_n = 0;

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

// ============================================================================
// Scenario 1: Varying k
// ============================================================================

static void BenchVaryK(const BenchmarkConfig& config,
                       ThresholdCSVWriter& csv) {
    std::vector<uint32_t> all_k = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);
    auto [sa, sb] = MakeSetsWithOverlap(config.set_size, 0.5);
    double j_true = ExactJaccard(sa, sb);

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
    double j_true = ExactJaccard(sa, sb);

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
            auto basic_result = engine->GetPiccard().Run(sa, sb);
            bool expected = basic_result.match_count >= static_cast<int64_t>(tau);

            std::string label = "vary_m_" + std::to_string(m);
            auto tr = RunMultiTrialThreshold(*engine, sa, sb, expected, label,
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
        double j_true = ExactJaccard(sa, sb);

        try {
            auto basic_result = engine->GetPiccard().Run(sa, sb);
            bool expected = basic_result.match_count >= static_cast<int64_t>(tau);

            std::string label = "vary_size_" + std::to_string(sz);
            auto tr = RunMultiTrialThreshold(*engine, sa, sb, expected, label,
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

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(
                    config.set_size, frac, rng);
                double j_true = ExactJaccard(sa, sb);

                auto basic = engine->GetPiccard().Run(sa, sb);
                bool expected = basic.match_count >= static_cast<int64_t>(tau);
                double j_hat = basic.jaccard_estimate;

                bool result = engine->Run(sa, sb);
                bool correct = (result == expected);
                if (correct) total_correct++;
                total_count++;

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
                tr.threshold_expected = expected ? 1 : 0;
                tr.threshold_correct = correct ? 1 : 0;
                tr.jaccard_computed = j_hat;
                tr.jaccard_expected = j_true;
                tr.jaccard_error = std::abs(j_hat - j_true);
                tr.jaccard_rel_error = (j_true > 0.0) ? (tr.jaccard_error / j_true) : -1.0;
                csv.WriteRow(tr);
            }
        }

        double accuracy = (total_count > 0)
            ? 100.0 * total_correct / total_count : 0.0;
        std::cerr << "  k=" << k << " tau=" << tau
                  << " accuracy=" << std::fixed << std::setprecision(1)
                  << accuracy << "%"
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

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(
                    config.set_size, frac, rng);
                double j_true = ExactJaccard(sa, sb);

                auto basic = engine->GetPiccard().Run(sa, sb);
                bool expected = basic.match_count >= static_cast<int64_t>(tau);
                double j_hat = basic.jaccard_estimate;

                bool result = engine->Run(sa, sb);
                bool correct = (result == expected);
                if (correct) total_correct++;
                total_count++;

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
                tr.threshold_expected = expected ? 1 : 0;
                tr.threshold_correct = correct ? 1 : 0;
                tr.jaccard_computed = j_hat;
                tr.jaccard_expected = j_true;
                tr.jaccard_error = std::abs(j_hat - j_true);
                tr.jaccard_rel_error = (j_true > 0.0) ? (tr.jaccard_error / j_true) : -1.0;
                csv.WriteRow(tr);
            }
        }

        double accuracy = (total_count > 0)
            ? 100.0 * total_correct / total_count : 0.0;
        std::cerr << "  m=" << m
                  << " accuracy=" << std::fixed << std::setprecision(1)
                  << accuracy << "%"
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

        for (double frac : overlaps) {
            for (size_t t = 0; t < config.trials; t++) {
                std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(sz, frac, rng);
                double j_true = ExactJaccard(sa, sb);

                auto basic = engine->GetPiccard().Run(sa, sb);
                bool expected = basic.match_count >= static_cast<int64_t>(tau);
                double j_hat = basic.jaccard_estimate;

                bool result = engine->Run(sa, sb);
                bool correct = (result == expected);
                if (correct) total_correct++;
                total_count++;

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
                tr.threshold_expected = expected ? 1 : 0;
                tr.threshold_correct = correct ? 1 : 0;
                tr.jaccard_computed = j_hat;
                tr.jaccard_expected = j_true;
                tr.jaccard_error = std::abs(j_hat - j_true);
                tr.jaccard_rel_error = (j_true > 0.0) ? (tr.jaccard_error / j_true) : -1.0;
                csv.WriteRow(tr);
            }
        }

        double accuracy = (total_count > 0)
            ? 100.0 * total_correct / total_count : 0.0;
        std::cerr << "  size=" << sz
                  << " accuracy=" << std::fixed << std::setprecision(1)
                  << accuracy << "%"
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
                  << "  --trials=N         Number of trials to run (default: 10)\n"
                  << "  --mode=MODE        'accuracy' or 'timing' (default: timing)\n"
                  << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256'\n";
        return 0;
    }

    auto config = BenchmarkConfig::ParseArgs(argc, argv);
    config.Print();

    ThresholdCSVWriter csv;
    csv.WriteHeader();

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
    }

    return 0;
}
