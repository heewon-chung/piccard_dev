// bench_sj16_calibrate.cpp — SJ16 thread-policy + cost-model calibration tool
// (Phase 3 of the SJ16 baseline work; design §5/§6, D3/D4).
//
// This is a STANDALONE CLI (its own main(), NOT a ctest). It:
//   (a) pins the OpenMP thread budget (D4) and records the actual count;
//   (b) fits a linear cost model T(m) = alpha*m + beta per Paillier key size by
//       least squares over >=3 measured universe sizes, with a held-out
//       residual gate (residual < 0.10 => extrapolation authorized);
//   (c) does the paper cross-check descriptively (K=1024 ms/encryption vs the
//       paper's 2.57 ms) — context only, never a pass/fail.
// Results are written to results/sj16_calibration_<host>.txt (git-ignored).
//
// FAST SMOKE RUN (a couple of minutes, K=1024 only):
//   ./build/bench_sj16_calibrate --key_bits=1024 --sizes=1024,2048,4096 \
//       --held_out=8192 --trials=2 --enc_iters=200 --threads=8
//
// FULL PAPER-GRADE RUN (LONG — the K=3072 sweep is tens of minutes per size;
//   size 2^15 at K=3072 is ~19 min for a single query, see design §5):
//   ./build/bench_sj16_calibrate --key_bits=1024,2048,3072 \
//       --sizes=4096,8192,16384 --held_out=32768 --trials=5 \
//       --enc_iters=1000 --threads=8
//
// Do NOT edit src/baselines/* or include/baselines/* — this tool reuses the
// SJ16 public API only.

#include <unistd.h>  // gethostname

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "baselines/sj16.h"
#include "benchmark_utils.h"  // Timer, MakeRandomSetsWithOverlap, ComputeDispersion

using piccard::baselines::SJ16;
using piccard::benchmark::MakeRandomSetsWithOverlap;

namespace {

// ----------------------------------------------------------------------------
// CLI configuration
// ----------------------------------------------------------------------------
struct Config {
    std::vector<unsigned> key_bits{1024, 2048, 3072};
    std::vector<uint32_t> sizes{4096, 8192, 16384};  // fit points (>=3)
    uint32_t held_out = 32768;
    size_t trials = 5;
    int threads = 8;  // resolved from OMP_NUM_THREADS below if unset on CLI
    size_t enc_iters = 1000;
};

std::vector<std::string> Split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

void PrintUsage() {
    std::cout
        << "Usage: bench_sj16_calibrate [options]\n"
        << "  --key_bits=K[,K...]  Paillier key sizes (default 1024,2048,3072)\n"
        << "  --sizes=M[,M...]     Universe sizes to MEASURE for the fit, >=3 "
           "(default 4096,8192,16384)\n"
        << "  --held_out=N         Held-out universe size for the residual gate "
           "(default 32768)\n"
        << "  --trials=N           Timed trials per size (default 5)\n"
        << "  --threads=N          OMP threads to pin (default: OMP_NUM_THREADS "
           "or 8)\n"
        << "  --enc_iters=N        Single-encrypt samples for t_enc "
           "(default 1000)\n"
        << "  --help, -h           This message\n";
}

// Strict full-token parse of a NON-NEGATIVE integer into `out` (finding 4):
// rejects an empty token, a leading '+'/'-' sign, any non-digit or trailing
// character, and overflow of the target type — the whole token must be a run of
// decimal digits that fits in T. Returns true only on a clean, complete parse.
template <typename T>
bool ParseStrictUnsigned(const std::string& tok, T& out) {
    if (tok.empty()) return false;
    if (tok.front() == '+' || tok.front() == '-') return false;  // no sign
    const char* first = tok.data();
    const char* last = tok.data() + tok.size();
    T v{};
    auto [ptr, ec] = std::from_chars(first, last, v);
    if (ec != std::errc()) return false;  // not-a-number or out-of-range
    if (ptr != last) return false;        // trailing / non-digit characters
    out = v;
    return true;
}

// Parses CLI args into `c`. Returns false (and prints a clear message) on ANY
// invalid input: a malformed number, an unsupported --key_bits value, or an
// unknown flag — all of which are fatal so main() exits nonzero before any
// measurement runs.
bool ParseArgs(int argc, char** argv, Config& c, bool& want_help) {
    bool threads_set = false;
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        auto val = [&](const char* pfx) {
            return a.substr(std::string(pfx).size());
        };
        if (a == "--help" || a == "-h") {
            want_help = true;
        } else if (a.rfind("--key_bits=", 0) == 0) {
            c.key_bits.clear();
            auto toks = Split(val("--key_bits="), ',');
            if (toks.empty()) {
                std::cerr << "ERROR: --key_bits has no values.\n";
                return false;
            }
            for (const auto& t : toks) {
                unsigned kb = 0;
                if (!ParseStrictUnsigned(t, kb)) {
                    std::cerr << "ERROR: --key_bits value '" << t
                              << "' is not a valid non-negative integer.\n";
                    return false;
                }
                if (kb != 1024 && kb != 2048 && kb != 3072) {
                    std::cerr << "ERROR: --key_bits value " << kb
                              << " is unsupported (allowed: 1024, 2048, 3072)."
                              << "\n";
                    return false;
                }
                c.key_bits.push_back(kb);
            }
        } else if (a.rfind("--sizes=", 0) == 0) {
            c.sizes.clear();
            auto toks = Split(val("--sizes="), ',');
            if (toks.empty()) {
                std::cerr << "ERROR: --sizes has no values.\n";
                return false;
            }
            for (const auto& t : toks) {
                uint32_t m = 0;
                if (!ParseStrictUnsigned(t, m)) {
                    std::cerr << "ERROR: --sizes value '" << t
                              << "' is not a valid non-negative integer (or "
                                 "overflows uint32).\n";
                    return false;
                }
                c.sizes.push_back(m);
            }
        } else if (a.rfind("--held_out=", 0) == 0) {
            uint32_t m = 0;
            if (!ParseStrictUnsigned(val("--held_out="), m)) {
                std::cerr << "ERROR: --held_out is not a valid non-negative "
                             "integer (or overflows uint32).\n";
                return false;
            }
            c.held_out = m;
        } else if (a.rfind("--trials=", 0) == 0) {
            size_t n = 0;
            if (!ParseStrictUnsigned(val("--trials="), n)) {
                std::cerr << "ERROR: --trials is not a valid non-negative "
                             "integer.\n";
                return false;
            }
            c.trials = n;
        } else if (a.rfind("--threads=", 0) == 0) {
            int n = 0;
            if (!ParseStrictUnsigned(val("--threads="), n)) {
                std::cerr << "ERROR: --threads is not a valid non-negative "
                             "integer.\n";
                return false;
            }
            c.threads = n;
            threads_set = true;
        } else if (a.rfind("--enc_iters=", 0) == 0) {
            size_t n = 0;
            if (!ParseStrictUnsigned(val("--enc_iters="), n)) {
                std::cerr << "ERROR: --enc_iters is not a valid non-negative "
                             "integer.\n";
                return false;
            }
            c.enc_iters = n;
        } else {
            std::cerr << "ERROR: unrecognized flag: " << a << "\n";
            return false;
        }
    }
    if (!threads_set) {
        const char* env = std::getenv("OMP_NUM_THREADS");
        int n = 0;
        if (env && *env && ParseStrictUnsigned(std::string(env), n) && n >= 1) {
            c.threads = n;
        } else {
            c.threads = 8;
        }
    }
    return true;
}

// ----------------------------------------------------------------------------
// Statistics helpers
// ----------------------------------------------------------------------------

// Linear-interpolated percentile p in [0,1] over an already-sorted vector.
double Percentile(const std::vector<double>& sorted, double p) {
    size_t n = sorted.size();
    if (n == 0) return 0.0;
    if (n == 1) return sorted[0];
    double idx = p * static_cast<double>(n - 1);
    size_t lo = static_cast<size_t>(idx);
    size_t hi = std::min(lo + 1, n - 1);
    double frac = idx - static_cast<double>(lo);
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

struct MedIqr {
    double median = 0.0;
    double q1 = 0.0;
    double q3 = 0.0;
    double iqr = 0.0;
};

MedIqr MedianIqr(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    MedIqr r;
    r.median = Percentile(v, 0.5);
    r.q1 = Percentile(v, 0.25);
    r.q3 = Percentile(v, 0.75);
    r.iqr = r.q3 - r.q1;
    return r;
}

struct LinFit {
    double alpha = 0.0;  // slope (ms per universe element)
    double beta = 0.0;   // intercept (ms)
    double r2 = 0.0;
};

// Least-squares fit of y = alpha*x + beta over (x_i, y_i).
LinFit FitLinear(const std::vector<double>& x, const std::vector<double>& y) {
    LinFit f;
    size_t n = x.size();
    if (n < 2) return f;
    double mean_x = 0.0, mean_y = 0.0;
    for (size_t i = 0; i < n; ++i) {
        mean_x += x[i];
        mean_y += y[i];
    }
    mean_x /= static_cast<double>(n);
    mean_y /= static_cast<double>(n);
    double sxx = 0.0, sxy = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double dx = x[i] - mean_x;
        sxx += dx * dx;
        sxy += dx * (y[i] - mean_y);
    }
    if (sxx == 0.0) return f;
    f.alpha = sxy / sxx;
    f.beta = mean_y - f.alpha * mean_x;
    double ss_res = 0.0, ss_tot = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double pred = f.alpha * x[i] + f.beta;
        ss_res += (y[i] - pred) * (y[i] - pred);
        ss_tot += (y[i] - mean_y) * (y[i] - mean_y);
    }
    f.r2 = (ss_tot == 0.0) ? 1.0 : (1.0 - ss_res / ss_tot);
    return f;
}

// ----------------------------------------------------------------------------
// Measurement
// ----------------------------------------------------------------------------

// Generate two sets over the universe [0, m): elements are valid indices < m,
// so SJ16 accepts them. Deterministic given seed. Set size is a fraction of the
// universe (timing is dominated by the m encryptions, not the set contents).
std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeSetsForUniverse(uint32_t m, uint64_t seed) {
    size_t set_size = std::max<size_t>(1, static_cast<size_t>(m) / 4);
    std::mt19937_64 rng(seed);
    // universe_size = m => sampled elements lie in [0, m); overlap 0.5 keeps
    // total distinct = set_size*1.5 = 0.375*m < m.
    return MakeRandomSetsWithOverlap(set_size, 0.5, static_cast<uint64_t>(m),
                                     rng);
}

// Raw per-trial full-query samples for EACH universe size in `sizes`, measured
// with INTERLEAVED (round-robin) order: the outer loop is over trials and the
// inner loop sweeps every size once, so size is not confounded with thermal /
// runtime drift (a fixed size1*trials-then-size2*trials order would be). The
// within-trial size order is ROTATED by the trial index (finding 5), so no size
// is systematically first or last across trials. Each size gets one discarded
// warmup first. Uses SJ16's internally-timed total_ms. Returns one sample vector
// per size, in the same order as `sizes` (raw, unsorted — the caller derives
// median/IQR). Seeding matches the per-size scheme (per-size base = base_seed ^
// m), so results are deterministic regardless of the rotation.
std::vector<std::vector<double>> MeasureQueriesSamples(
    SJ16& s, const std::vector<uint32_t>& sizes, size_t trials,
    uint64_t base_seed) {
    std::vector<std::vector<double>> samples(sizes.size());
    for (auto& v : samples) v.reserve(trials);
    // Warmup pass (discarded): amortizes first-touch allocation / page faults.
    for (uint32_t m : sizes) {
        s.SetUniverse(m);
        auto [wx, wy] =
            MakeSetsForUniverse(m, (base_seed ^ m) ^ 0x9E3779B97F4A7C15ULL);
        (void)s.RunProtocol(wx, wy);
    }
    const size_t nsz = sizes.size();
    // Interleaved measurement: each trial sweeps every size once, rotated.
    for (size_t t = 0; t < trials; ++t) {
        for (size_t k = 0; k < nsz; ++k) {
            size_t si = (k + t) % nsz;  // rotate order per trial
            uint32_t m = sizes[si];
            s.SetUniverse(m);
            auto [x, y] = MakeSetsForUniverse(m, (base_seed ^ m) + t * 1009ULL);
            auto res = s.RunProtocol(x, y);
            samples[si].push_back(res.cost.total_ms);
        }
    }
    return samples;
}

// Median (+ IQR) single-encryption time via the public API. Calling
// MeasureEncryptMsMedian(1) repeatedly yields one raw sample each, so IQR is
// obtainable without touching sj16.* (the median-only API otherwise hides the
// spread).
MedIqr MeasureEncMs(const SJ16& s, size_t enc_iters,
                    std::vector<double>& samples_out) {
    samples_out.clear();
    samples_out.reserve(enc_iters);
    for (size_t i = 0; i < enc_iters; ++i) {
        samples_out.push_back(s.MeasureEncryptMsMedian(1));
    }
    // MedianIqr sorts a COPY, so samples_out keeps its raw acquisition order.
    return MedianIqr(samples_out);
}

// Short git commit for provenance; "unknown" if git is unavailable/not a repo.
std::string GitCommit() {
    std::string commit = "unknown";
    // Full 40-char SHA (not --short): permanently unambiguous provenance.
    FILE* p = popen("git rev-parse HEAD 2>/dev/null", "r");
    if (p) {
        char buf[128] = {0};
        if (std::fgets(buf, sizeof(buf), p)) {
            std::string s(buf);
            while (!s.empty() &&
                   (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
                s.pop_back();
            if (!s.empty()) commit = s;
        }
        pclose(p);
    }
    return commit;
}

// Complete path-bound source manifest hash: SHA-256 of the per-file
// "<digest>  <path>" listing over EVERY source/build input that defines the
// measured binary (all compiled headers + translation units + the CMake build
// definition), in a fixed order. Because the inner listing carries each file's
// path and its own digest, the outer hash binds filenames and file boundaries,
// not just concatenated bytes. Uniquely identifies the measured source tree
// even when uncommitted; "unknown" if popen fails.
std::string SourceSha256() {
    std::string digest = "unknown";
    FILE* p = popen(
        "shasum -a 256 "
        "include/baselines/csprng.h include/baselines/paillier.h "
        "include/baselines/sj16.h include/baselines/pjs_baseline.h "
        "include/util/params.h benchmarks/benchmark_utils.h "
        "benchmarks/bench_sj16_calibrate.cpp "
        "src/baselines/paillier.cpp src/baselines/sj16.cpp "
        "CMakeLists.txt "
        "2>/dev/null | shasum -a 256",
        "r");
    if (p) {
        char buf[256] = {0};
        if (std::fgets(buf, sizeof(buf), p)) {
            std::string s(buf);
            // Capture the first token (the hex digest); shasum prints
            // "<digest>  <filename>".
            std::size_t end = s.find_first_of(" \t\n\r");
            if (end != std::string::npos) s.erase(end);
            if (!s.empty()) digest = s;
        }
        pclose(p);
    }
    return digest;
}

// 1 if the working tree has uncommitted changes, 0 if clean, "unknown" on
// failure. Uses `git status --porcelain`: any output means the tree is dirty.
std::string GitDirty() {
    FILE* p = popen("git status --porcelain 2>/dev/null", "r");
    if (!p) return "unknown";
    char buf[256] = {0};
    bool dirty = std::fgets(buf, sizeof(buf), p) != nullptr;
    pclose(p);
    return dirty ? "1" : "0";
}

std::string HostName() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) != 0) return "unknown";
    std::string h(buf);
    for (char& ch : h) {
        if (!std::isalnum(static_cast<unsigned char>(ch))) ch = '_';
    }
    if (h.empty()) h = "unknown";
    return h;
}

// Per-K calibration outcome, for the results file.
struct KResult {
    unsigned key_bits = 0;
    double t_enc_median = 0.0;
    double t_enc_iqr = 0.0;
    std::vector<double> t_enc_samples;  // raw single-encrypt samples
    LinFit fit;
    std::vector<uint32_t> fit_sizes;              // per fit size
    std::vector<MedIqr> fit_stats;                // per fit size (median/IQR)
    std::vector<std::vector<double>> fit_samples;  // per fit size (raw)
    uint32_t held_size = 0;
    MedIqr held_stats;                  // held-out median/Q1/Q3/IQR
    std::vector<double> held_samples;   // held-out raw samples
    double held_measured = 0.0;
    double held_pred = 0.0;
    double residual = 0.0;
    bool pass = false;
};

}  // namespace

int main(int argc, char** argv) {
    bool want_help = false;
    Config cfg;
    if (!ParseArgs(argc, argv, cfg, want_help)) {
        return 1;  // invalid CLI input: fail fast before any measurement
    }
    if (want_help) {
        PrintUsage();
        return 0;
    }
    // ---- CLI validation (fail fast, BEFORE any measurement) ----------------
    // Reject inputs that would produce div-by-zero, meaningless output, or a
    // corrupted residual gate. Every failure exits nonzero with a clear message.
    if (cfg.key_bits.empty()) {
        std::cerr << "ERROR: --key_bits must have >=1 entry.\n";
        return 1;
    }
    if (cfg.sizes.size() < 3) {
        std::cerr << "ERROR: need >=3 --sizes for a linear fit (got "
                  << cfg.sizes.size() << ").\n";
        return 1;
    }
    for (uint32_t m : cfg.sizes) {
        if (m == 0) {
            std::cerr << "ERROR: --sizes entries must be positive (got 0).\n";
            return 1;
        }
    }
    {
        // All fit sizes must be DISTINCT (duplicates corrupt the fit weighting).
        std::vector<uint32_t> sorted = cfg.sizes;
        std::sort(sorted.begin(), sorted.end());
        if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
            std::cerr << "ERROR: --sizes must be all-distinct (duplicate fit "
                         "size found).\n";
            return 1;
        }
    }
    if (cfg.held_out == 0) {
        std::cerr << "ERROR: --held_out must be positive (got 0).\n";
        return 1;
    }
    if (std::find(cfg.sizes.begin(), cfg.sizes.end(), cfg.held_out) !=
        cfg.sizes.end()) {
        std::cerr << "ERROR: --held_out (" << cfg.held_out
                  << ") must NOT be one of the --sizes fit points; the residual "
                     "gate requires a genuinely held-out size.\n";
        return 1;
    }
    if (cfg.trials < 1) {
        std::cerr << "ERROR: --trials must be >=1 (got " << cfg.trials << ").\n";
        return 1;
    }
    if (cfg.enc_iters < 1) {
        std::cerr << "ERROR: --enc_iters must be >=1 (got " << cfg.enc_iters
                  << ").\n";
        return 1;
    }
    if (cfg.threads < 1) {
        std::cerr << "ERROR: --threads must be >=1 (got " << cfg.threads
                  << ").\n";
        return 1;
    }

    // ---- Thread policy (D4): pin, then OBSERVE the real team size -----------
    // omp_get_max_threads() is only an UPPER BOUND; the number of threads that
    // actually form a team can differ (env caps, dynamic adjustment). Enter a
    // parallel region and read omp_get_num_threads() from the master to record
    // the size real parallel work will actually see, and report both.
    int max_threads = 1;    // upper bound (omp_get_max_threads)
    int observed_team = 1;  // real team size seen inside a parallel region
#ifdef _OPENMP
    omp_set_num_threads(cfg.threads);
    max_threads = omp_get_max_threads();
#pragma omp parallel
    {
        if (omp_get_thread_num() == 0) observed_team = omp_get_num_threads();
    }
#else
    (void)cfg.threads;
#endif
    bool any_failure = false;  // set if any Setup/measurement throws

    std::cout << "========================================================\n"
              << " SJ16 calibration (Phase 3)\n"
              << "========================================================\n"
#ifdef _OPENMP
              << " THREAD BUDGET (pinned, D4): requested=" << cfg.threads
              << "  observed team=" << observed_team
              << "  (omp_get_max_threads=" << max_threads << ")\n"
#else
              << " THREAD BUDGET: OpenMP DISABLED at build time (1 thread)\n"
#endif
              << " trials/size=" << cfg.trials
              << "  enc_iters=" << cfg.enc_iters << "\n"
              << " fit sizes:";
    for (auto m : cfg.sizes) std::cout << " " << m;
    std::cout << "   held_out=" << cfg.held_out << "\n"
              << "--------------------------------------------------------\n";
    std::cout << " NOTE: T(m) fit uses full-query time at the pinned thread "
                 "count;\n"
                 "       t_enc (single-encryption unit cost) is measured "
                 "single-threaded,\n"
                 "       matching design §5's single-thread unit costs and the "
                 "§6 paper check.\n"
              << "--------------------------------------------------------\n";
    std::cout << std::fixed << std::setprecision(4);

    constexpr double kPaperMsPerEnc = 2.57;  // SJ16 §8.2, K=1024
    constexpr double kResidualTau = 0.10;    // held-out residual gate

    std::vector<KResult> results;

    // ---- D4 scaling check: ONE representative size at threads=1 vs threads=P -
    // The full T(m) fit runs only at the pinned team size, so parallel scaling
    // would otherwise be untested. Measure the SMALLEST fit size single-threaded
    // and at the full team (once), report the speedup, and warn if it is far
    // below linear so single- and matched-thread numbers both get reported.
    bool scaling_ran = false;
    double scaling_t1 = 0.0, scaling_tP = 0.0, scaling_speedup = 0.0;
    uint32_t scaling_m = *std::min_element(cfg.sizes.begin(), cfg.sizes.end());
    int scaling_P = observed_team;
    bool scaling_sublinear = false;
#ifdef _OPENMP
    if (scaling_P > 1) {
        unsigned Ksc = cfg.key_bits.front();
        std::cout << "\n[D4 scaling check] size m=" << scaling_m
                  << " at K=" << Ksc << ": threads=1 vs threads=" << scaling_P
                  << " ...\n";
        try {
            SJ16 ssc(Ksc);
            ssc.Setup();
            ssc.SetUniverse(scaling_m);
            // Warmup once at each thread count (discarded).
            {
                auto [wx, wy] = MakeSetsForUniverse(
                    scaling_m, 0x5CA1E5EEDULL ^ 0x9E3779B97F4A7C15ULL);
                omp_set_num_threads(1);
                (void)ssc.RunProtocol(wx, wy);
                omp_set_num_threads(cfg.threads);
                (void)ssc.RunProtocol(wx, wy);
            }
            // ALTERNATE T1,TP,T1,TP,... across trials (not all-T1-then-all-TP)
            // so thermal / runtime drift is shared between the two thread counts
            // rather than confounded with the thread count (finding 5).
            std::vector<double> s1, sP;
            s1.reserve(cfg.trials);
            sP.reserve(cfg.trials);
            for (size_t t = 0; t < cfg.trials; ++t) {
                auto [x, y] =
                    MakeSetsForUniverse(scaling_m, 0x5CA1E5EEDULL + t * 1009ULL);
                omp_set_num_threads(1);
                s1.push_back(ssc.RunProtocol(x, y).cost.total_ms);
                omp_set_num_threads(cfg.threads);
                sP.push_back(ssc.RunProtocol(x, y).cost.total_ms);
            }
            scaling_t1 = MedianIqr(s1).median;
            scaling_tP = MedianIqr(sP).median;
            scaling_speedup =
                (scaling_tP > 0.0) ? scaling_t1 / scaling_tP : 0.0;
            scaling_sublinear =
                scaling_speedup < 0.5 * static_cast<double>(scaling_P);
            scaling_ran = true;
            std::cout << "  T1=" << scaling_t1 << " ms  T" << scaling_P << "="
                      << scaling_tP << " ms  speedup=" << scaling_speedup
                      << "x (ideal " << scaling_P << "x)\n";
            if (scaling_sublinear) {
                std::cout << "  WARNING: speedup (" << scaling_speedup
                          << "x) is far below linear (" << scaling_P
                          << "x); report BOTH single-thread and matched-thread "
                             "numbers, since matched-thread scaling is poor on "
                             "this machine.\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "  D4 scaling check FAILED: " << e.what() << "\n";
            any_failure = true;
        }
    } else {
        std::cout << "\n[D4 scaling check] skipped (observed team is 1 thread; "
                     "nothing to scale).\n";
    }
#else
    std::cout << "\n[D4 scaling check] skipped (OpenMP disabled at build "
                 "time).\n";
#endif

    for (unsigned K : cfg.key_bits) {
        std::cout << "\n### K = " << K << " bits ###\n";
        try {
            SJ16 s(K);
            s.Setup();

            // Single-encryption unit cost (median + IQR + raw samples).
            std::vector<double> enc_samples;
            MedIqr enc = MeasureEncMs(s, cfg.enc_iters, enc_samples);
            std::cout << "  t_enc: median=" << enc.median
                      << " ms  IQR=" << enc.iqr << " ms"
                      << "  (Q1=" << enc.q1 << " Q3=" << enc.q3 << ")\n";

            // Full-query time for the fit sizes AND the held-out size, measured
            // together in ONE trial-major interleaved schedule (finding 5); the
            // fit vs held-out split happens only here in analysis. The held-out
            // size is the last entry of the combined list.
            uint64_t base_seed = 0xC0FFEEULL ^ (static_cast<uint64_t>(K) << 8);
            std::vector<uint32_t> all_sizes = cfg.sizes;
            all_sizes.push_back(cfg.held_out);
            std::vector<std::vector<double>> all_samples =
                MeasureQueriesSamples(s, all_sizes, cfg.trials, base_seed);

            const size_t nfit = cfg.sizes.size();
            std::vector<double> xs, ys;
            std::vector<MedIqr> fit_stats;
            std::vector<std::vector<double>> fit_samples;
            for (size_t si = 0; si < nfit; ++si) {
                uint32_t m = cfg.sizes[si];
                MedIqr st = MedianIqr(all_samples[si]);  // copy -> keep raw
                xs.push_back(static_cast<double>(m));
                ys.push_back(st.median);
                fit_stats.push_back(st);
                fit_samples.push_back(all_samples[si]);
                std::cout << "  m=" << std::setw(7) << m
                          << "  T_median=" << std::setw(10) << st.median
                          << " ms  IQR=" << st.iqr << " ms\n";
            }

            LinFit fit = FitLinear(xs, ys);

            // Held-out prediction + residual gate (last entry of all_samples).
            std::vector<double> held_samples = all_samples[nfit];
            MedIqr held = MedianIqr(held_samples);
            double pred =
                fit.alpha * static_cast<double>(cfg.held_out) + fit.beta;
            double residual = (held.median > 0.0)
                                  ? std::fabs(held.median - pred) / held.median
                                  : 1.0;
            bool pass = residual < kResidualTau;

            std::cout << "  FIT: T(m) = " << fit.alpha << "*m + " << fit.beta
                      << "   R^2=" << fit.r2 << "\n";
            std::cout << "  HELD-OUT m=" << cfg.held_out
                      << ": measured=" << held.median << " ms"
                      << "  predicted=" << pred << " ms"
                      << "  residual=" << residual * 100.0 << "%\n";
            std::cout << "  GATE (residual < " << kResidualTau * 100.0
                      << "%): " << (pass ? "PASS" : "FAIL") << "\n";
            if (!pass) {
                std::cout << "    => extrapolation for K=" << K
                          << " is NOT authorized (design D3 must be revised).\n";
                // A calibration that fails its own residual gate is NOT a
                // success: force a nonzero exit so a failed run is never
                // mistaken for an authoritative one (finding 4).
                any_failure = true;
            }

            // Paper cross-check (K=1024 only, descriptive — NOT pass/fail).
            if (K == 1024) {
                double ratio = kPaperMsPerEnc / enc.median;  // how much faster
                std::cout << "  PAPER CROSS-CHECK (descriptive, not a gate): "
                          << "measured " << enc.median << " ms/enc vs paper "
                          << kPaperMsPerEnc << " ms/enc  (machine ratio "
                          << ratio << "x faster)\n";
            }

            KResult kr;
            kr.key_bits = K;
            kr.t_enc_median = enc.median;
            kr.t_enc_iqr = enc.iqr;
            kr.t_enc_samples = std::move(enc_samples);
            kr.fit = fit;
            kr.fit_sizes = cfg.sizes;
            kr.fit_stats = std::move(fit_stats);
            kr.fit_samples = std::move(fit_samples);
            kr.held_size = cfg.held_out;
            kr.held_stats = held;
            kr.held_samples = std::move(held_samples);
            kr.held_measured = held.median;
            kr.held_pred = pred;
            kr.residual = residual;
            kr.pass = pass;
            results.push_back(std::move(kr));
        } catch (const std::exception& e) {
            std::cerr << "  ERROR: measurement failed for K=" << K << ": "
                      << e.what()
                      << " — this requested K could NOT be validated.\n";
            any_failure = true;
            continue;
        }
    }

    // ---- Machine-readable summary ------------------------------------------
    std::error_code ec;
    std::filesystem::create_directories("results", ec);
    std::string host = HostName();
    std::string path = "results/sj16_calibration_" + host + ".txt";
    std::ofstream out(path);
    if (!out) {
        std::cerr << "\nERROR: could not open " << path << " for writing.\n";
        return 1;
    }
    // overall_status: PASS only if EVERY requested K produced a result (none
    // threw) AND no failure occurred (a residual-gate FAIL sets any_failure, so
    // this also captures gate failures). A failed artifact is unmistakable.
    bool overall_pass =
        !any_failure && results.size() == cfg.key_bits.size();

    // ---- Provenance (finding 5: TKDE reproducibility) ----------------------
    std::string cmdline;
    for (int i = 0; i < argc; ++i) {
        if (i) cmdline += " ";
        cmdline += argv[i];
    }
    std::time_t now = std::time(nullptr);
    // ISO-8601 with timezone offset, e.g. 2026-07-26T14:03:05+0900.
    std::string timestamp = "unknown";
    {
        char tsbuf[64] = {0};
        std::tm local_tm{};
        if (std::tm* lt = std::localtime(&now)) {
            local_tm = *lt;
            if (std::strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%S%z",
                              &local_tm))
                timestamp = tsbuf;
        }
    }
    std::string git_commit = GitCommit();
    std::string source_sha256 = SourceSha256();
    std::string git_dirty = GitDirty();
#ifdef __VERSION__
    std::string compiler = __VERSION__;
#else
    std::string compiler = "unknown";
#endif

    out << std::fixed << std::setprecision(6);
    out << "# SJ16 calibration summary\n";
    out << "overall_status=" << (overall_pass ? "PASS" : "FAIL") << "\n";
    out << "# ---- provenance ----\n";
    out << "cmdline=" << cmdline << "\n";
    out << "timestamp=" << timestamp << "\n";
    out << "git_commit=" << git_commit << "\n";
    out << "git_dirty=" << git_dirty << "\n";
    out << "source_sha256=" << source_sha256 << "\n";
    out << "compiler=" << compiler << "\n";
    out << "precompute_mode=off\n";  // tool always uses SJ16 default (no pool)
    out << "# --------------------\n";
    out << "host=" << host << "\n";
#ifdef _OPENMP
    out << "openmp=1\n";
    out << "threads_requested=" << cfg.threads << "\n";
    out << "threads_observed=" << observed_team << "\n";  // real team size
    out << "threads_max=" << max_threads << "\n";         // omp_get_max_threads
#else
    out << "openmp=0\n";
    out << "threads_requested=1\n";
    out << "threads_observed=1\n";
    out << "threads_max=1\n";
#endif
    out << "trials_per_size=" << cfg.trials << "\n";
    out << "enc_iters=" << cfg.enc_iters << "\n";
    out << "held_out=" << cfg.held_out << "\n";
    out << "residual_tau=" << kResidualTau << "\n";
    out << "paper_ms_per_enc_k1024=" << kPaperMsPerEnc << "\n";
    // D4 scaling check (one size at threads=1 vs the observed team size).
    if (scaling_ran) {
        out << "scaling_ran=1\n";
        out << "scaling_size=" << scaling_m << "\n";
        out << "scaling_threads_p=" << scaling_P << "\n";
        out << "scaling_t1_ms=" << scaling_t1 << "\n";
        out << "scaling_tp_ms=" << scaling_tP << "\n";
        out << "scaling_speedup=" << scaling_speedup << "\n";
        out << "scaling_note="
            << (scaling_sublinear
                    ? "sublinear (<0.5*P): report BOTH single- and "
                      "matched-thread numbers"
                    : "ok")
            << "\n";
    } else {
        out << "scaling_ran=0\n";
    }
    out << "fit_sizes=";
    for (size_t i = 0; i < cfg.sizes.size(); ++i)
        out << (i ? "," : "") << cfg.sizes[i];
    out << "\n";
    out << "# columns: "
           "key_bits,t_enc_median_ms,t_enc_iqr_ms,alpha_ms_per_m,beta_ms,r2,"
           "held_measured_ms,held_pred_ms,held_residual,gate\n";
    for (const auto& r : results) {
        out << r.key_bits << "," << r.t_enc_median << "," << r.t_enc_iqr << ","
            << r.fit.alpha << "," << r.fit.beta << "," << r.fit.r2 << ","
            << r.held_measured << "," << r.held_pred << "," << r.residual << ","
            << (r.pass ? "PASS" : "FAIL") << "\n";
    }

    // ---- Per-size dispersion (finding 3, D3 auditability) ------------------
    // For every K, dump the median/Q1/Q3/IQR and the raw per-trial samples of
    // t_enc, each fit size, and the held-out size so a reviewer can audit the
    // spread behind every fitted coefficient — not just the point estimates.
    auto write_samples = [&out](const std::vector<double>& v) {
        for (size_t i = 0; i < v.size(); ++i) out << (i ? "," : "") << v[i];
    };
    out << "# ---- per-size dispersion (median/q1/q3/iqr + raw samples) ----\n";
    for (const auto& r : results) {
        out << "k" << r.key_bits << "_t_enc median=" << r.t_enc_median
            << " iqr=" << r.t_enc_iqr << " samples=";
        write_samples(r.t_enc_samples);
        out << "\n";
        for (size_t si = 0; si < r.fit_sizes.size(); ++si) {
            const MedIqr& st = r.fit_stats[si];
            out << "k" << r.key_bits << "_fit_m=" << r.fit_sizes[si]
                << " median=" << st.median << " q1=" << st.q1
                << " q3=" << st.q3 << " iqr=" << st.iqr << " samples=";
            write_samples(r.fit_samples[si]);
            out << "\n";
        }
        const MedIqr& hst = r.held_stats;
        out << "k" << r.key_bits << "_heldout_m=" << r.held_size
            << " median=" << hst.median << " q1=" << hst.q1 << " q3=" << hst.q3
            << " iqr=" << hst.iqr << " samples=";
        write_samples(r.held_samples);
        out << "\n";
    }
    out.close();

    std::cout << "\nWrote " << path << "\n";

    if (any_failure) {
        std::cerr << "\nERROR: one or more requested K sizes (or the D4 scaling "
                     "check) could not be validated; see messages above.\n";
        return 1;
    }
    return 0;
}
