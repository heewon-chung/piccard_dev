#include "benchmark_utils.h"
#include "baseline_engine.h"
#include "piccard/protocol/piccard.h"

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
    std::string method;  // "piccard" or "baseline"

    // Parameters
    uint32_t universe_size = 0;
    size_t set_size = 0;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t ring_dim = 0;
    uint32_t num_cts = 0;

    // Per-phase timing (ms)
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_compute_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    // Resources
    size_t memory_bytes = 0;
    size_t ct_size_bytes = 0;

    // Accuracy
    double jaccard_computed = 0.0;
    double jaccard_expected = 0.0;
    double jaccard_error = 0.0;
};

// ============================================================================
// CSV output for ComparisonResult
// ============================================================================

class ComparisonCSVWriter {
public:
    ComparisonCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << "scenario,method,universe_size,set_size,k,m,ring_dim,num_cts,"
              << "phase_encode_ms,phase_encrypt_ms,phase_compute_ms,"
              << "phase_decrypt_ms,total_ms,"
              << "memory_bytes,ct_size_bytes,"
              << "jaccard_computed,jaccard_expected,jaccard_error\n";
    }

    void WriteRow(const ComparisonResult& r) {
        *out_ << r.scenario << ","
              << r.method << ","
              << r.universe_size << ","
              << r.set_size << ","
              << r.k << ","
              << r.m << ","
              << r.ring_dim << ","
              << r.num_cts << ","
              << std::fixed << std::setprecision(3)
              << r.phase_encode_ms << ","
              << r.phase_encrypt_ms << ","
              << r.phase_compute_ms << ","
              << r.phase_decrypt_ms << ","
              << r.total_ms << ","
              << r.memory_bytes << ","
              << r.ct_size_bytes << ","
              << std::fixed << std::setprecision(6)
              << r.jaccard_computed << ","
              << r.jaccard_expected << ","
              << r.jaccard_error << "\n";
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

    // Measure ciphertext size
    cr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x);

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

    // Measure ciphertext size (per-ciphertext * num_cts)
    cr.ct_size_bytes = CiphertextSizer::GetSerializedSize(ct_x[0]) * ct_x.size();

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
// CLI config (extends BenchmarkConfig with universe_size)
// Placed before scenarios so they can reference it.
// ============================================================================

struct ComparisonConfig {
    BenchmarkConfig base;
    uint32_t universe_size = 262144;  // Default: 256K — accommodates set_size up to 100K

    static ComparisonConfig ParseArgs(int argc, char** argv) {
        ComparisonConfig config;
        config.base = BenchmarkConfig::ParseArgs(argc, argv);

        // Override base defaults with paper-suitable values when not
        // explicitly set.  BenchmarkConfig defaults to set_size=100;
        // we want 500 for the comparison benchmark.
        bool set_size_given = false;
        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);
            if (arg.find("--universe=") == 0) {
                config.universe_size =
                    static_cast<uint32_t>(std::stoul(arg.substr(11)));
            }
            if (arg.find("--set_size=") == 0) {
                set_size_given = true;
            }
        }
        if (!set_size_given) {
            config.base.set_size = 500;
        }
        return config;
    }

    void Print() const {
        base.Print();
        std::cerr << "  Universe: " << universe_size << "\n";
    }
};

// ============================================================================
// Scenario 1: Vary universe size (main comparison — Table in paper)
//
// Piccard ring_dim is constant (determined by k*m and security), while
// baseline ring_dim grows with U_set. This is THE key result.
// ============================================================================

static void BenchVaryUniverse(const ComparisonConfig& cfg,
                              ComparisonCSVWriter& csv) {
    // Universe sizes chosen to span: within Piccard ring_dim, at boundary,
    // and well beyond (forcing larger BFV parameters for baseline).
    std::vector<uint32_t> u_values = {1024, 4096, 16384, 65536, 262144, 524288, 1048576};
    const auto& config = cfg.base;

    for (uint32_t u : u_values) {
        std::string scenario = "vary_universe_" + std::to_string(u);

        auto [set_a, set_b] = MakeSetsWithOverlap(config.set_size, 0.5, u);
        double j_true = ExactJaccard(set_a, set_b);

        // --- Piccard (constant ring_dim) ---
        PiccardParams pp;
        pp.k = config.k;
        pp.m = config.m;
        pp.security = config.security_level;
        pp.Validate();

        Piccard piccard(pp);
        piccard.KeyGen();

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, u, config.trials);
        csv.WriteRow(pr);

        std::cerr << "  U=" << u
                  << " piccard: N=" << pr.ring_dim
                  << " total=" << pr.total_ms << "ms"
                  << " err=" << pr.jaccard_error << "\n";

        // --- Baseline (ring_dim grows with U) ---
        BaselineParams bp;
        bp.universe_size = u;
        bp.security = config.security_level;
        bp.Validate();

        BaselineEngine baseline(bp);
        baseline.Initialize();

        auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                        scenario, config.trials);
        csv.WriteRow(br);

        std::cerr << "  U=" << u
                  << " baseline: N=" << br.ring_dim
                  << " cts=" << br.num_cts
                  << " total=" << br.total_ms << "ms"
                  << " err=" << br.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 2: Vary set size (fixed universe)
// ============================================================================

static void BenchVarySetSize(const ComparisonConfig& cfg,
                             ComparisonCSVWriter& csv) {
    std::vector<size_t> sizes = {100, 500, 1000, 5000, 10000, 50000, 100000};
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

    // Baseline engine (reuse across sizes — same universe)
    BaselineParams bp;
    bp.universe_size = u;
    bp.security = config.security_level;
    bp.Validate();

    BaselineEngine baseline(bp);
    baseline.Initialize();

    for (size_t sz : sizes) {
        std::string scenario = "vary_setsize_" + std::to_string(sz);

        auto [set_a, set_b] = MakeSetsWithOverlap(sz, 0.5, u);
        double j_true = ExactJaccard(set_a, set_b);

        auto pr = RunMultiTrialPiccard(piccard, set_a, set_b, j_true,
                                       scenario, u, config.trials);
        csv.WriteRow(pr);

        std::cerr << "  size=" << sz
                  << " piccard: total=" << pr.total_ms << "ms"
                  << " err=" << pr.jaccard_error << "\n";

        auto br = RunMultiTrialBaseline(baseline, set_a, set_b, j_true,
                                        scenario, config.trials);
        csv.WriteRow(br);

        std::cerr << "  size=" << sz
                  << " baseline: total=" << br.total_ms << "ms"
                  << " err=" << br.jaccard_error << "\n";
    }
}

// ============================================================================
// Scenario 3: Accuracy across similarity levels
// ============================================================================

static void BenchAccuracy(const ComparisonConfig& cfg,
                          ComparisonCSVWriter& csv) {
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};
    const auto& config = cfg.base;
    uint32_t u = cfg.universe_size;
    size_t sz = config.set_size;

    // Piccard
    PiccardParams pp;
    pp.k = config.k;
    pp.m = config.m;
    pp.security = config.security_level;
    pp.Validate();

    Piccard piccard(pp);
    piccard.KeyGen();

    // Baseline
    BaselineParams bp;
    bp.universe_size = u;
    bp.security = config.security_level;
    bp.Validate();

    BaselineEngine baseline(bp);
    baseline.Initialize();

    for (double frac : overlaps) {
        std::string scenario = "accuracy_" + std::to_string(frac);

        double total_piccard_error = 0.0;
        double total_baseline_error = 0.0;

        for (size_t t = 0; t < config.trials; t++) {
            auto [set_a, set_b] = MakeSetsWithOverlap(sz, frac, u);
            double j_true = ExactJaccard(set_a, set_b);

            // Piccard
            auto p_result = piccard.Run(set_a, set_b);
            double p_err = std::abs(p_result.jaccard_estimate - j_true);
            total_piccard_error += p_err;

            ComparisonResult pr;
            pr.scenario = scenario;
            pr.method = "piccard";
            pr.universe_size = u;
            pr.set_size = sz;
            pr.k = config.k;
            pr.m = config.m;
            pr.ring_dim = pp.ring_dim;
            pr.num_cts = 1;
            pr.jaccard_computed = p_result.jaccard_estimate;
            pr.jaccard_expected = j_true;
            pr.jaccard_error = p_err;
            csv.WriteRow(pr);

            // Baseline
            double b_j = baseline.ComputeJaccard(set_a, set_b);
            double b_err = std::abs(b_j - j_true);
            total_baseline_error += b_err;

            ComparisonResult br;
            br.scenario = scenario;
            br.method = "baseline";
            br.universe_size = u;
            br.set_size = sz;
            br.k = 0;
            br.m = 0;
            br.ring_dim = bp.ring_dim;
            br.num_cts = bp.num_ciphertexts;
            br.jaccard_computed = b_j;
            br.jaccard_expected = j_true;
            br.jaccard_error = b_err;
            csv.WriteRow(br);
        }

        double avg_p = total_piccard_error / static_cast<double>(config.trials);
        double avg_b = total_baseline_error / static_cast<double>(config.trials);
        std::cerr << "  overlap=" << frac
                  << " piccard_err=" << avg_p
                  << " baseline_err=" << avg_b << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

static void PrintUsage() {
    std::cerr
        << "Usage: bench_comparison [options]\n"
        << "\n"
        << "Side-by-side comparison of Piccard vs binary-vector baseline (ZLG+24).\n"
        << "\n"
        << "Options:\n"
        << "  --mode=MODE        'timing' or 'accuracy' (default: timing)\n"
        << "  --k=N              Piccard MinHash functions (default: 128)\n"
        << "  --m=N              Piccard one-hot bucket size (default: 64)\n"
        << "  --set_size=N       Size of each party's set (default: 500)\n"
        << "  --trials=N         Number of trials (default: 10)\n"
        << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256' (default: STD128)\n"
        << "  --universe=N       Baseline universe size (default: 131072)\n"
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
        std::cerr << "\n=== Vary universe size (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVaryUniverse(config, csv);

        std::cerr << "\n=== Vary set size (median of "
                  << config.base.trials << " trials) ===\n";
        BenchVarySetSize(config, csv);
    } else if (config.base.mode == "accuracy") {
        std::cerr << "\n=== Accuracy comparison ===\n";
        BenchAccuracy(config, csv);
    }

    return 0;
}
