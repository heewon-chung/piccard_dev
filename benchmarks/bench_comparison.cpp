#include "benchmark_utils.h"
#include "baseline_engine.h"
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
#include <set>
#include <vector>

using namespace piccard;
using namespace piccard::benchmark;
using namespace piccard::baseline;

// ============================================================================
// Shared helpers
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

/// Generate two sets with elements in [0, universe_size) and given overlap.
static std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeSetsWithOverlap(size_t set_size, double overlap_fraction,
                    uint64_t universe_size) {
    size_t overlap = static_cast<size_t>(overlap_fraction * set_size);

    // Ensure we don't exceed universe bounds:
    // Need overlap shared + (set_size - overlap) unique_a + (set_size - overlap) unique_b
    // = 2*set_size - overlap distinct elements
    if (2 * set_size - overlap > universe_size) {
        throw std::runtime_error(
            "Universe too small: need " +
            std::to_string(2 * set_size - overlap) +
            " distinct elements but universe_size=" +
            std::to_string(universe_size));
    }

    std::vector<uint64_t> a, b;
    a.reserve(set_size);
    b.reserve(set_size);

    // Shared elements: [0, overlap)
    for (uint64_t i = 0; i < overlap; i++) {
        a.push_back(i);
        b.push_back(i);
    }
    // Unique to A: [overlap, overlap + (set_size - overlap))
    for (uint64_t i = overlap; i < set_size; i++) {
        a.push_back(i);
    }
    // Unique to B: [set_size, set_size + (set_size - overlap))
    for (uint64_t i = 0; i < set_size - overlap; i++) {
        b.push_back(set_size + i);
    }

    return {a, b};
}

// ============================================================================
// Comparison result (unified for both methods)
// ============================================================================

struct ComparisonResult {
    std::string scenario;
    std::string method;  // "piccard", "piccard_sqrt", or "baseline"

    // Parameters
    uint32_t universe_size = 0;
    size_t set_size = 0;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t ring_dim = 0;
    uint32_t num_cts = 0;
    uint32_t mult_depth = 0;

    // Per-phase timing (ms)
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_compute_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    // Resources
    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;
    size_t comm_bytes = 0;       // Total communication: 2×upload + 1×result download

    // Accuracy
    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = 0.0;
    double jaccard_rel_error = 0.0;  // |J_hat - J_true| / J_true (-1 if J_true=0)
};

// ============================================================================
// CSV output for ComparisonResult
// ============================================================================

/// Security class of each protocol, emitted next to its cost so the comparison
/// table can separate "same security class" from "vs. a weaker baseline".
/// Mirrors piccard::baselines::SecurityClass; kept as a lookup on the method
/// name so adding a protocol touches exactly one place.
static const char* SecurityClassOf(const std::string& method) {
    if (method == "piccard" || method == "piccard_sqrt") return "CPA/no-leakage";
    if (method == "baseline") return "KPA/leakage";  // ZLG+24
    if (method == "bcg12" || method == "sj16") return "AHE/no-leakage";
    return "unknown";
}

class ComparisonCSVWriter {
public:
    ComparisonCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << "scenario,method,security_class,"
              << "universe_size,set_size,k,m,ring_dim,num_cts,mult_depth,"
              << "phase_encode_ms,phase_encrypt_ms,phase_compute_ms,"
              << "phase_decrypt_ms,total_ms,"
              << "memory_bytes,ct_size_bytes,comm_bytes,"
              << "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error\n";
    }

    void WriteRow(const ComparisonResult& r) {
        *out_ << r.scenario << ","
              << r.method << ","
              << SecurityClassOf(r.method) << ","
              << r.universe_size << ","
              << r.set_size << ","
              << r.k << ","
              << r.m << ","
              << r.ring_dim << ","
              << r.num_cts << ","
              << r.mult_depth << ","
              << std::fixed << std::setprecision(3)
              << r.phase_encode_ms << ","
              << r.phase_encrypt_ms << ","
              << r.phase_compute_ms << ","
              << r.phase_decrypt_ms << ","
              << r.total_ms << ","
              << r.memory_bytes << ","
              << r.ct_size_bytes << ","
              << r.comm_bytes << ","
              << std::fixed << std::setprecision(6)
              << r.jaccard_computed << ","
              << r.jaccard_expected << ","
              << r.jaccard_error << ","
              << r.jaccard_rel_error << "\n";
    }

private:
    std::ostream* out_;
};

// ============================================================================
// Timed protocol: Piccard
// ============================================================================

static ComparisonResult RunPiccardTimed(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size)
{
    Timer timer;
    ComparisonResult cr;
    cr.scenario = scenario;
    cr.method = "piccard";
    cr.universe_size = universe_size;
    cr.set_size = set_x.size();
    cr.k = engine.GetParams().k;
    cr.m = engine.GetParams().m;
    cr.ring_dim = engine.GetParams().ring_dim;
    cr.num_cts = 1;  // Piccard always uses 1 ciphertext per party
    cr.mult_depth = 1;

    // Phase 1: Encode (minhash + onehot)
    timer.Start();
    auto sig_x = engine.ComputeSignature(set_x);
    auto sig_y = engine.ComputeSignature(set_y);
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    cr.phase_encode_ms = timer.ElapsedMs();

    // Phase 2: Encrypt
    timer.Start();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    cr.phase_encrypt_ms = timer.ElapsedMs();

    // Measure ciphertext size and communication cost
    cr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);
    // Communication: 2 parties upload 1 ct each + 1 result ct download
    cr.comm_bytes = 3 * cr.ct_size_bytes;

    // Phase 3: Compute (multiply + rotate-and-sum)
    const auto& bfv = engine.GetBFVContext();
    timer.Start();
    auto product = bfv.Multiply(ct_x, ct_y);
    auto result = product;
    for (uint32_t step = 1; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(result, static_cast<int>(step));
        result = bfv.Add(result, rotated);
    }
    cr.phase_compute_ms = timer.ElapsedMs();

    // Phase 4: Decrypt + bias correction
    timer.Start();
    auto values = bfv.Decrypt(result);
    int64_t v = values[0];
    double k = static_cast<double>(engine.GetParams().k);
    double m = static_cast<double>(engine.GetParams().m);
    double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);
    cr.phase_decrypt_ms = timer.ElapsedMs();

    cr.total_ms = cr.phase_encode_ms + cr.phase_encrypt_ms +
                  cr.phase_compute_ms + cr.phase_decrypt_ms;
    cr.memory_bytes = MemoryTracker::GetPeakRSS();
    cr.jaccard_computed = j_hat;
    cr.jaccard_expected = j_true;
    cr.jaccard_error = std::abs(j_hat - j_true);
    cr.jaccard_rel_error = (j_true > 0.0) ? (cr.jaccard_error / j_true) : -1.0;

    return cr;
}

// ============================================================================
// Timed protocol: Baseline (binary vector)
// ============================================================================

static ComparisonResult RunBaselineTimed(
    const BaselineEngine& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario)
{
    Timer timer;
    ComparisonResult cr;
    cr.scenario = scenario;
    cr.method = "baseline";
    cr.universe_size = engine.GetParams().universe_size;
    cr.set_size = set_x.size();
    cr.k = 0;
    cr.m = 0;
    cr.ring_dim = engine.GetParams().ring_dim;
    cr.num_cts = engine.GetParams().num_ciphertexts;

    // Phase 1: Encode (binary vector construction)
    timer.Start();
    auto chunks_x = engine.EncodeBinaryVectors(set_x);
    auto chunks_y = engine.EncodeBinaryVectors(set_y);
    cr.phase_encode_ms = timer.ElapsedMs();

    // Phase 2: Encrypt (all chunks)
    timer.Start();
    auto ct_x = engine.EncryptChunks(chunks_x);
    auto ct_y = engine.EncryptChunks(chunks_y);
    cr.phase_encrypt_ms = timer.ElapsedMs();

    // Measure ciphertext size and communication cost
    size_t per_ct_bytes = CiphertextSizer::GetSerializedSize(ct_x[0]);
    cr.ct_size_bytes = per_ct_bytes * ct_x.size();  // total per party
    // Communication: 2 parties upload num_cts each + 1 result ct download
    cr.comm_bytes = 2 * cr.ct_size_bytes + per_ct_bytes;

    // Phase 3: Compute (multiply + rotate-and-sum for each chunk, aggregate)
    timer.Start();
    auto ct_result = engine.ComputeInnerProduct(ct_x, ct_y);
    cr.phase_compute_ms = timer.ElapsedMs();

    // Phase 4: Decrypt + Jaccard formula
    timer.Start();
    double j = engine.ComputeJaccardFromInnerProduct(
        ct_result, set_x.size(), set_y.size());
    cr.phase_decrypt_ms = timer.ElapsedMs();

    cr.total_ms = cr.phase_encode_ms + cr.phase_encrypt_ms +
                  cr.phase_compute_ms + cr.phase_decrypt_ms;
    cr.memory_bytes = MemoryTracker::GetPeakRSS();
    cr.jaccard_computed = j;
    cr.jaccard_expected = j_true;
    cr.jaccard_error = std::abs(j - j_true);
    cr.jaccard_rel_error = (j_true > 0.0) ? (cr.jaccard_error / j_true) : -1.0;

    return cr;
}

// ============================================================================
// Multi-trial median
// ============================================================================

static double Median(std::vector<double>& v) {
    size_t n = v.size();
    if (n == 0) return 0.0;
    std::sort(v.begin(), v.end());
    if (n % 2 == 0) return (v[n / 2 - 1] + v[n / 2]) / 2.0;
    return v[n / 2];
}

static ComparisonResult RunMultiTrialPiccard(
    const Piccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size,
    size_t trials)
{
    // Warmup
    RunPiccardTimed(engine, set_x, set_y, j_true, "warmup", universe_size);

    std::vector<double> v_encode, v_encrypt, v_compute, v_decrypt, v_total;
    ComparisonResult last;
    double total_error = 0.0;

    for (size_t t = 0; t < trials; t++) {
        auto cr = RunPiccardTimed(engine, set_x, set_y, j_true, scenario,
                                  universe_size);
        v_encode.push_back(cr.phase_encode_ms);
        v_encrypt.push_back(cr.phase_encrypt_ms);
        v_compute.push_back(cr.phase_compute_ms);
        v_decrypt.push_back(cr.phase_decrypt_ms);
        v_total.push_back(cr.total_ms);
        total_error += cr.jaccard_error;
        last = cr;
    }

    ComparisonResult median = last;
    median.phase_encode_ms = Median(v_encode);
    median.phase_encrypt_ms = Median(v_encrypt);
    median.phase_compute_ms = Median(v_compute);
    median.phase_decrypt_ms = Median(v_decrypt);
    median.total_ms = Median(v_total);
    median.jaccard_error = total_error / static_cast<double>(trials);
    median.memory_bytes = MemoryTracker::GetPeakRSS();
    return median;
}

static ComparisonResult RunMultiTrialBaseline(
    const BaselineEngine& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    size_t trials)
{
    // Warmup
    RunBaselineTimed(engine, set_x, set_y, j_true, "warmup");

    std::vector<double> v_encode, v_encrypt, v_compute, v_decrypt, v_total;
    ComparisonResult last;
    double total_error = 0.0;

    for (size_t t = 0; t < trials; t++) {
        auto cr = RunBaselineTimed(engine, set_x, set_y, j_true, scenario);
        v_encode.push_back(cr.phase_encode_ms);
        v_encrypt.push_back(cr.phase_encrypt_ms);
        v_compute.push_back(cr.phase_compute_ms);
        v_decrypt.push_back(cr.phase_decrypt_ms);
        v_total.push_back(cr.total_ms);
        total_error += cr.jaccard_error;
        last = cr;
    }

    ComparisonResult median = last;
    median.phase_encode_ms = Median(v_encode);
    median.phase_encrypt_ms = Median(v_encrypt);
    median.phase_compute_ms = Median(v_compute);
    median.phase_decrypt_ms = Median(v_decrypt);
    median.total_ms = Median(v_total);
    median.jaccard_error = total_error / static_cast<double>(trials);
    median.memory_bytes = MemoryTracker::GetPeakRSS();
    return median;
}

// ============================================================================
// Helper: check if m is valid for sqrt encoding
// ============================================================================

static bool IsSqrtValid(uint32_t m) {
    if (m < 4 || (m & (m - 1)) != 0) return false;
    uint32_t log2m = 0;
    { uint32_t tmp = m; while (tmp > 1) { log2m++; tmp >>= 1; } }
    return (log2m % 2 == 0);
}

// ============================================================================
// Timed protocol: SqrtPiccard
// Mirrors SqrtPiccard::Evaluate (sqrt_piccard.cpp lines 42-86)
// ============================================================================

static ComparisonResult RunSqrtPiccardTimed(
    const SqrtPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size)
{
    Timer timer;
    ComparisonResult cr;
    cr.scenario = scenario;
    cr.method = "piccard_sqrt";
    cr.universe_size = universe_size;
    cr.set_size = set_x.size();
    cr.k = engine.GetParams().k;
    cr.m = engine.GetParams().m;
    cr.ring_dim = engine.GetParams().ring_dim;
    cr.num_cts = 1;
    cr.mult_depth = 3;

    // Phase 1: Encode (minhash + sqrt encoding)
    timer.Start();
    auto sig_x = engine.ComputeSignature(set_x);
    auto sig_y = engine.ComputeSignature(set_y);
    auto feat_x = engine.EncodeSignature(sig_x);
    auto feat_y = engine.EncodeSignature(sig_y);
    cr.phase_encode_ms = timer.ElapsedMs();

    // Phase 2: Encrypt
    timer.Start();
    auto ct_x = engine.EncryptFeature(feat_x);
    auto ct_y = engine.EncryptFeature(feat_y);
    cr.phase_encrypt_ms = timer.ElapsedMs();

    cr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);
    cr.comm_bytes = 3 * cr.ct_size_bytes;

    // Phase 3: Compute (4 sub-phases of sqrt evaluate)
    const auto& bfv = engine.GetBFVContext();
    uint32_t b = engine.GetParams().sqrt_base;
    uint32_t block = 2 * b;

    timer.Start();
    // 3a: Component-wise multiply (depth 1)
    auto product = bfv.Multiply(ct_x, ct_y);
    // 3b: Intra-digit rotate-and-sum
    auto digit_sums = product;
    for (uint32_t step = 1; step < b; step *= 2) {
        auto rotated = bfv.Rotate(digit_sums, static_cast<int>(step));
        digit_sums = bfv.Add(digit_sums, rotated);
    }
    // 3c: Digit AND multiply (depth 2)
    auto shifted = bfv.Rotate(digit_sums, static_cast<int>(b));
    auto anded = bfv.Multiply(digit_sums, shifted);
    // 3d: Cross-k sum
    auto result = anded;
    for (uint32_t step = block; step < engine.GetParams().ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(result, static_cast<int>(step));
        result = bfv.Add(result, rotated);
    }
    cr.phase_compute_ms = timer.ElapsedMs();

    // Phase 4: Decrypt + bias correction
    timer.Start();
    auto values = bfv.Decrypt(result);
    int64_t v = values[0];
    double kd = static_cast<double>(engine.GetParams().k);
    double md = static_cast<double>(engine.GetParams().m);
    double raw_ratio = static_cast<double>(v) / kd;
    double j_hat = (raw_ratio - 1.0 / md) / (1.0 - 1.0 / md);
    cr.phase_decrypt_ms = timer.ElapsedMs();

    cr.total_ms = cr.phase_encode_ms + cr.phase_encrypt_ms +
                  cr.phase_compute_ms + cr.phase_decrypt_ms;
    cr.memory_bytes = MemoryTracker::GetPeakRSS();
    cr.jaccard_computed = j_hat;
    cr.jaccard_expected = j_true;
    cr.jaccard_error = std::abs(j_hat - j_true);
    cr.jaccard_rel_error = (j_true > 0.0) ? (cr.jaccard_error / j_true) : -1.0;

    return cr;
}

// ============================================================================
// Multi-trial: SqrtPiccard
// ============================================================================

static ComparisonResult RunMultiTrialSqrtPiccard(
    const SqrtPiccard& engine,
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y,
    double j_true,
    const std::string& scenario,
    uint32_t universe_size,
    size_t trials)
{
    // Warmup
    RunSqrtPiccardTimed(engine, set_x, set_y, j_true, "warmup", universe_size);

    std::vector<double> v_encode, v_encrypt, v_compute, v_decrypt, v_total;
    ComparisonResult last;
    double total_error = 0.0;

    for (size_t t = 0; t < trials; t++) {
        auto cr = RunSqrtPiccardTimed(engine, set_x, set_y, j_true, scenario,
                                      universe_size);
        v_encode.push_back(cr.phase_encode_ms);
        v_encrypt.push_back(cr.phase_encrypt_ms);
        v_compute.push_back(cr.phase_compute_ms);
        v_decrypt.push_back(cr.phase_decrypt_ms);
        v_total.push_back(cr.total_ms);
        total_error += cr.jaccard_error;
        last = cr;
    }

    ComparisonResult median = last;
    median.phase_encode_ms = Median(v_encode);
    median.phase_encrypt_ms = Median(v_encrypt);
    median.phase_compute_ms = Median(v_compute);
    median.phase_decrypt_ms = Median(v_decrypt);
    median.total_ms = Median(v_total);
    median.jaccard_error = total_error / static_cast<double>(trials);
    median.memory_bytes = MemoryTracker::GetPeakRSS();
    return median;
}

// ============================================================================
// CLI config (extends BenchmarkConfig with universe_size)
// Placed before scenarios so they can reference it.
// ============================================================================

struct ComparisonConfig {
    BenchmarkConfig base;
    uint32_t universe_size = 65536;  // Default: 2^16

    static ComparisonConfig ParseArgs(int argc, char** argv) {
        ComparisonConfig config;
        config.base = BenchmarkConfig::ParseArgs(argc, argv);

        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);
            if (arg.find("--universe=") == 0) {
                config.universe_size =
                    static_cast<uint32_t>(std::stoul(arg.substr(11)));
            }
        }
        return config;
    }

    void Print() const {
        base.Print();
        std::cerr << "  Universe: " << universe_size << "\n";
    }
};

// ============================================================================
// Scenario 1: Vary k (Piccard ring_dim changes; baseline constant)
// ============================================================================

static void BenchVaryK(const ComparisonConfig& cfg,
                       ComparisonCSVWriter& csv) {
    std::vector<uint32_t> k_values = {16, 32, 64, 128, 256, 512};
    const auto& config = cfg.base;
    uint32_t u = cfg.universe_size;

    auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, 0.5, u);
    double j_true = ExactJaccard(set_a, set_b);

    // Baseline: independent of k — run once and reuse
    BaselineParams bp;
    bp.universe_size = u;
    bp.security = config.security_level;
    bp.Validate();

    BaselineEngine baseline(bp);
    baseline.Initialize();

    auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                    "vary_k_baseline", config.trials);

    for (uint32_t k : k_values) {
        std::string scenario = "vary_k_" + std::to_string(k);

        // Piccard (one-hot)
        PiccardParams pp;
        pp.k = k;
        pp.m = config.m;
        pp.security = config.security_level;
        pp.Validate();

        Piccard piccard(pp);
        piccard.KeyGen();

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, u, config.trials);
        csv.WriteRow(pr);

        // SqrtPiccard (default m=64 is sqrt-valid)
        if (IsSqrtValid(config.m)) {
            PiccardParams sp;
            sp.k = k;
            sp.m = config.m;
            sp.security = config.security_level;
            sp.ValidateSqrt();

            SqrtPiccard sqrt_eng(sp);
            sqrt_eng.KeyGen();

            auto sr = RunMultiTrialSqrtPiccard(sqrt_eng, set_a, set_b, j_true,
                                               scenario, u, config.trials);
            csv.WriteRow(sr);

            std::cerr << "  k=" << k
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: N=" << sr.ring_dim
                      << " total=" << sr.total_ms << "ms";
        } else {
            std::cerr << "  k=" << k
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: SKIPPED (m=" << config.m << " not sqrt-valid)";
        }

        // Baseline
        auto br_copy = br;
        br_copy.scenario = scenario;
        csv.WriteRow(br_copy);

        std::cerr << " | baseline: N=" << br_copy.ring_dim
                  << " total=" << br_copy.total_ms << "ms\n";
    }
}

// ============================================================================
// Scenario 2: Vary m (Piccard ring_dim changes; baseline constant)
// ============================================================================

static void BenchVaryM(const ComparisonConfig& cfg,
                       ComparisonCSVWriter& csv) {
    std::vector<uint32_t> m_values = {16, 32, 64, 128, 256};
    const auto& config = cfg.base;
    uint32_t u = cfg.universe_size;

    auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, 0.5, u);
    double j_true = ExactJaccard(set_a, set_b);

    // Baseline: independent of m — run once and reuse
    BaselineParams bp;
    bp.universe_size = u;
    bp.security = config.security_level;
    bp.Validate();

    BaselineEngine baseline(bp);
    baseline.Initialize();

    auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                    "vary_m_baseline", config.trials);

    for (uint32_t m : m_values) {
        std::string scenario = "vary_m_" + std::to_string(m);

        // Piccard (one-hot) — runs for all m
        PiccardParams pp;
        pp.k = config.k;
        pp.m = m;
        pp.security = config.security_level;
        pp.Validate();

        Piccard piccard(pp);
        piccard.KeyGen();

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, u, config.trials);
        csv.WriteRow(pr);

        // SqrtPiccard — only for sqrt-valid m
        if (IsSqrtValid(m)) {
            PiccardParams sp;
            sp.k = config.k;
            sp.m = m;
            sp.security = config.security_level;
            sp.ValidateSqrt();

            SqrtPiccard sqrt_eng(sp);
            sqrt_eng.KeyGen();

            auto sr = RunMultiTrialSqrtPiccard(sqrt_eng, set_a, set_b, j_true,
                                               scenario, u, config.trials);
            csv.WriteRow(sr);

            std::cerr << "  m=" << m
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: N=" << sr.ring_dim
                      << " total=" << sr.total_ms << "ms";
        } else {
            std::cerr << "  m=" << m
                      << " piccard: N=" << pr.ring_dim
                      << " total=" << pr.total_ms << "ms"
                      << " | sqrt: SKIPPED (not sqrt-valid)";
        }

        // Baseline — runs for all m
        auto br_copy = br;
        br_copy.scenario = scenario;
        csv.WriteRow(br_copy);

        std::cerr << " | baseline: N=" << br_copy.ring_dim
                  << " total=" << br_copy.total_ms << "ms\n";
    }
}

// ============================================================================
// Scenario 3: Vary universe size |U| (main comparison — Table in paper)
//
// Piccard ring_dim is constant (determined by k*m and security), while
// baseline ring_dim grows with U_set. This is THE key result.
// ============================================================================

static void BenchVaryUniverse(const ComparisonConfig& cfg,
                              ComparisonCSVWriter& csv) {
    // Universe sizes chosen to span: within Piccard ring_dim, at boundary,
    // and well beyond (forcing larger BFV parameters for baseline).
    std::vector<uint32_t> u_values = {16384, 65536, 262144, 1048576};
    const auto& config = cfg.base;

    for (uint32_t u : u_values) {
        std::string scenario = "vary_universe_" + std::to_string(u);

        // --- Piccard (constant ring_dim) ---
        PiccardParams pp;
        pp.k = config.k;
        pp.m = config.m;
        pp.security = config.security_level;
        pp.Validate();

        Piccard piccard(pp);
        piccard.KeyGen();

        // --- SqrtPiccard (constant ring_dim, smaller than Piccard) ---
        // Created once outside loop since params don't depend on universe
        bool has_sqrt = IsSqrtValid(config.m);
        std::unique_ptr<SqrtPiccard> sqrt_eng;
        if (has_sqrt) {
            PiccardParams sp;
            sp.k = config.k;
            sp.m = config.m;
            sp.security = config.security_level;
            sp.ValidateSqrt();
            sqrt_eng = std::make_unique<SqrtPiccard>(sp);
            sqrt_eng->KeyGen();
        }

        // --- Baseline (ring_dim grows with U) ---
        BaselineParams bp;
        bp.universe_size = u;
        bp.security = config.security_level;
        bp.Validate();

        BaselineEngine baseline(bp);
        baseline.Initialize();

        // Use randomized sets per trial so accuracy varies across trials
        std::vector<double> p_encode, p_encrypt, p_compute, p_decrypt, p_total;
        std::vector<double> s_encode, s_encrypt, s_compute, s_decrypt, s_total;
        std::vector<double> b_encode, b_encrypt, b_compute, b_decrypt, b_total;
        ComparisonResult p_last, s_last, b_last;
        double total_p_err = 0.0, total_s_err = 0.0, total_b_err = 0.0;

        // Warmup with deterministic sets
        {
            auto [wa, wb] = MakeSetsWithOverlap(config.set_size, 0.5, u);
            double wj = ExactJaccard(wa, wb);
            RunPiccardTimed(piccard, wa, wb, wj, "warmup", u);
            if (has_sqrt)
                RunSqrtPiccardTimed(*sqrt_eng, wa, wb, wj, "warmup", u);
            RunBaselineTimed(baseline, wa, wb, wj, "warmup");
        }

        for (size_t t = 0; t < config.trials; t++) {
            std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, 0.5));
            auto [set_a, set_b] = benchmark::MakeRandomSetsWithOverlap(
                config.set_size, 0.5, u, rng);
            double j_true = ExactJaccard(set_a, set_b);

            auto pr = RunPiccardTimed(piccard, set_a, set_b, j_true, scenario, u);
            p_encode.push_back(pr.phase_encode_ms);
            p_encrypt.push_back(pr.phase_encrypt_ms);
            p_compute.push_back(pr.phase_compute_ms);
            p_decrypt.push_back(pr.phase_decrypt_ms);
            p_total.push_back(pr.total_ms);
            total_p_err += pr.jaccard_error;
            p_last = pr;

            if (has_sqrt) {
                auto sr = RunSqrtPiccardTimed(*sqrt_eng, set_a, set_b, j_true, scenario, u);
                s_encode.push_back(sr.phase_encode_ms);
                s_encrypt.push_back(sr.phase_encrypt_ms);
                s_compute.push_back(sr.phase_compute_ms);
                s_decrypt.push_back(sr.phase_decrypt_ms);
                s_total.push_back(sr.total_ms);
                total_s_err += sr.jaccard_error;
                s_last = sr;
            }

            auto br = RunBaselineTimed(baseline, set_a, set_b, j_true, scenario);
            b_encode.push_back(br.phase_encode_ms);
            b_encrypt.push_back(br.phase_encrypt_ms);
            b_compute.push_back(br.phase_compute_ms);
            b_decrypt.push_back(br.phase_decrypt_ms);
            b_total.push_back(br.total_ms);
            total_b_err += br.jaccard_error;
            b_last = br;
        }

        // Aggregate Piccard (median timing, mean error)
        ComparisonResult pr = p_last;
        pr.phase_encode_ms = Median(p_encode);
        pr.phase_encrypt_ms = Median(p_encrypt);
        pr.phase_compute_ms = Median(p_compute);
        pr.phase_decrypt_ms = Median(p_decrypt);
        pr.total_ms = Median(p_total);
        pr.jaccard_error = total_p_err / static_cast<double>(config.trials);
        pr.jaccard_rel_error = (pr.jaccard_expected > 0.0)
            ? (pr.jaccard_error / pr.jaccard_expected) : -1.0;
        pr.memory_bytes = MemoryTracker::GetPeakRSS();
        csv.WriteRow(pr);

        std::cerr << "  U=" << u
                  << " piccard: N=" << pr.ring_dim
                  << " total=" << pr.total_ms << "ms"
                  << " comm=" << (pr.comm_bytes / 1024) << "KB"
                  << " err=" << pr.jaccard_error << "\n";

        // Aggregate SqrtPiccard (median timing, mean error)
        if (has_sqrt) {
            ComparisonResult sr = s_last;
            sr.phase_encode_ms = Median(s_encode);
            sr.phase_encrypt_ms = Median(s_encrypt);
            sr.phase_compute_ms = Median(s_compute);
            sr.phase_decrypt_ms = Median(s_decrypt);
            sr.total_ms = Median(s_total);
            sr.jaccard_error = total_s_err / static_cast<double>(config.trials);
            sr.jaccard_rel_error = (sr.jaccard_expected > 0.0)
                ? (sr.jaccard_error / sr.jaccard_expected) : -1.0;
            sr.memory_bytes = MemoryTracker::GetPeakRSS();
            csv.WriteRow(sr);

            std::cerr << "  U=" << u
                      << " sqrt: N=" << sr.ring_dim
                      << " total=" << sr.total_ms << "ms"
                      << " comm=" << (sr.comm_bytes / 1024) << "KB"
                      << " err=" << sr.jaccard_error << "\n";
        }

        // Aggregate Baseline (median timing, mean error)
        ComparisonResult br = b_last;
        br.phase_encode_ms = Median(b_encode);
        br.phase_encrypt_ms = Median(b_encrypt);
        br.phase_compute_ms = Median(b_compute);
        br.phase_decrypt_ms = Median(b_decrypt);
        br.total_ms = Median(b_total);
        br.jaccard_error = total_b_err / static_cast<double>(config.trials);
        br.jaccard_rel_error = (br.jaccard_expected > 0.0)
            ? (br.jaccard_error / br.jaccard_expected) : -1.0;
        br.memory_bytes = MemoryTracker::GetPeakRSS();
        csv.WriteRow(br);

        std::cerr << "  U=" << u
                  << " baseline: N=" << br.ring_dim
                  << " cts=" << br.num_cts
                  << " total=" << br.total_ms << "ms"
                  << " comm=" << (br.comm_bytes / 1024) << "KB"
                  << " err=" << br.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 4: Vary set size n (fixed universe)
// ============================================================================

static void BenchVarySetSize(const ComparisonConfig& cfg,
                             ComparisonCSVWriter& csv) {
    std::vector<size_t> sizes = {100, 1000, 10000, 100000};
    const auto& config = cfg.base;
    uint32_t u = cfg.universe_size;

    // Piccard engine (reuse across sizes — parameters don't change)
    PiccardParams pp;
    pp.k = config.k;
    pp.m = config.m;
    pp.security = config.security_level;
    pp.Validate();

    Piccard piccard(pp);
    piccard.KeyGen();

    // SqrtPiccard engine (reuse across sizes)
    bool has_sqrt = IsSqrtValid(config.m);
    std::unique_ptr<SqrtPiccard> sqrt_eng;
    if (has_sqrt) {
        PiccardParams sp;
        sp.k = config.k;
        sp.m = config.m;
        sp.security = config.security_level;
        sp.ValidateSqrt();
        sqrt_eng = std::make_unique<SqrtPiccard>(sp);
        sqrt_eng->KeyGen();
    }

    for (size_t sz : sizes) {
        // Scale universe to accommodate large set sizes
        uint32_t eff_u = std::max(u, static_cast<uint32_t>(2 * sz));
        std::string scenario = "vary_size_" + std::to_string(sz);

        // Baseline engine (recreated per size when universe changes)
        BaselineParams bp;
        bp.universe_size = eff_u;
        bp.security = config.security_level;
        bp.Validate();

        BaselineEngine baseline(bp);
        baseline.Initialize();

        auto [set_a, set_b] = MakeSetsWithOverlap(sz, 0.5, eff_u);
        double j_true = ExactJaccard(set_a, set_b);

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, eff_u, config.trials);
        csv.WriteRow(pr);

        std::cerr << "  size=" << sz
                  << " piccard: total=" << pr.total_ms << "ms"
                  << " comm=" << (pr.comm_bytes / 1024) << "KB"
                  << " err=" << pr.jaccard_error << "\n";

        if (has_sqrt) {
            auto sr = RunMultiTrialSqrtPiccard(*sqrt_eng, set_a, set_b, j_true,
                                               scenario, eff_u, config.trials);
            csv.WriteRow(sr);

            std::cerr << "  size=" << sz
                      << " sqrt: total=" << sr.total_ms << "ms"
                      << " comm=" << (sr.comm_bytes / 1024) << "KB"
                      << " err=" << sr.jaccard_error << "\n";
        }

        auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                        scenario, config.trials);
        csv.WriteRow(br);

        std::cerr << "  size=" << sz
                  << " baseline: total=" << br.total_ms << "ms"
                  << " comm=" << (br.comm_bytes / 1024) << "KB"
                  << " err=" << br.jaccard_error << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

static void PrintUsage() {
    std::cerr
        << "Usage: bench_comparison [options]\n"
        << "\n"
        << "Three-way comparison: Piccard vs SqrtPiccard vs binary-vector baseline (ZLG+24).\n"
        << "Reports compute time, end-to-end time, and communication cost.\n"
        << "\n"
        << "Timing scenarios (--mode=timing):\n"
        << "  1. Vary k       — Piccard ring_dim changes; baseline constant\n"
        << "  2. Vary m       — Piccard ring_dim changes; baseline constant\n"
        << "  3. Vary |U|     — Baseline ring_dim grows; Piccard constant\n"
        << "  4. Vary n       — Set size (affects encode/minhash phases)\n"
        << "\n"
        << "Options:\n"
        << "  --mode=MODE        'timing' or 'accuracy' (default: timing)\n"
        << "  --k=N              Piccard MinHash functions (default: 128)\n"
        << "  --m=N              Piccard one-hot bucket size (default: 64)\n"
        << "  --set_size=N       Size of each party's set (default: 1000)\n"
        << "  --trials=N         Number of trials (default: 10)\n"
        << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256' (default: STD128)\n"
        << "  --universe=N       Baseline universe size (default: 65536)\n"
        << "  --help, -h         Print this help message\n"
        << "\n"
        << "Examples:\n"
        << "  bench_comparison --security=TOY --trials=3\n"
        << "  bench_comparison --mode=accuracy --security=TOY --trials=5\n"
        << "  bench_comparison --security=STD128 --trials=5   # paper-grade numbers\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            PrintUsage();
            return 0;
        }
    }

    auto config = ComparisonConfig::ParseArgs(argc, argv);
    config.Print();

    ComparisonCSVWriter csv;
    csv.WriteHeader();

    if (config.base.mode == "timing") {
        std::cerr << "\n=== Vary k (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVaryK(config, csv);

        std::cerr << "\n=== Vary m (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVaryM(config, csv);

        std::cerr << "\n=== Vary universe size (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVaryUniverse(config, csv);

        std::cerr << "\n=== Vary set size (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVarySetSize(config, csv);
    }

    return 0;
}
