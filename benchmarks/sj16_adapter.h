#pragma once

/**
 * @file sj16_adapter.h
 * @brief SJ16-owned bridge between the SJ16 protocol engine and
 *        bench_comparison's ComparisonResult row (Phase 4).
 *
 * The heavy Phase-4 code lives HERE, not in the shared bench_comparison.cpp:
 * per-trial timing (RunSJ16OnTrial) and multi-trial aggregation
 * (FinalizeSJ16). The shared file only constructs the engine, calls Setup()
 * once, SetUniverse(u) per universe, invokes RunSJ16OnTrial inside the existing
 * per-trial loop (reusing that loop's sets), and emits one FinalizeSJ16 row.
 *
 * PRECONDITION: this header must be #included AFTER `struct ComparisonResult`
 * is defined in bench_comparison.cpp (it maps SJ16 costs onto that struct), and
 * only under `#ifdef HAVE_SJ16` (which implies GMP + piccard_baselines linked).
 *
 * Design refs: baseline-design §7 (asymmetric comm accounting, labeling),
 * D5 (offline randomiser precompute reported separately). The SJ16 row is a
 * LOWER BOUND: it shares the intersection cardinality; the secure-division step
 * that would turn the shares into an end-to-end Jaccard is excluded.
 */

#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>               // gethostname

#include "benchmark_utils.h"      // Timer, MemoryTracker, ComputeDispersion
#include "baselines/sj16.h"       // SJ16, SJ16Trial, QueryCost

// One measured SJ16 trial. Reuses the caller's (set_a, set_b) — no independent
// data generation — and retains j_true so FinalizeSJ16 can form a mean error.
//
// In precompute mode (precompute == true, universe > 0) the m+1 randomiser pool
// is (re)filled OUTSIDE the timed region before the query, exactly as design D5
// requires (each query consumes |U|+1 fresh rho^N). Its offline build time and
// peak RSS are reported to stderr, not folded into the measured phases.
inline piccard::baselines::SJ16Trial RunSJ16OnTrial(
    piccard::baselines::SJ16& eng,
    const std::vector<uint64_t>& set_a,
    const std::vector<uint64_t>& set_b,
    double j_true,
    uint32_t universe = 0,
    bool precompute = false,
    unsigned key_bits = 0) {
    if (precompute && universe > 0) {
        piccard::benchmark::Timer pool_timer;
        pool_timer.Start();
        eng.PrepareRandomizerPool(static_cast<size_t>(universe) + 1);
        double pool_ms = pool_timer.ElapsedMs();
        // Report the pool's ACTUAL storage, not process peak RSS (which is
        // dominated by OpenFHE/Paillier and does not reflect the pool). A
        // Paillier ciphertext is an element mod N^2 = 2*key_bits bits, so
        // ceil(2*key_bits/8) bytes on the wire/in the pool. peak RSS is kept
        // as a secondary datum only.
        size_t pool_entries = static_cast<size_t>(universe) + 1;
        size_t ct_bytes =
            (static_cast<size_t>(2) * key_bits + 7) / 8;  // ceil(2*key_bits/8)
        size_t pool_bytes = pool_entries * ct_bytes;
        std::cerr << "  sj16 precompute: offline pool build (m+1="
                  << pool_entries << ") = " << pool_ms
                  << " ms, pool_entries=" << pool_entries
                  << ", pool_bytes=" << pool_bytes << " (" << ct_bytes
                  << " B/ciphertext), peak RSS = "
                  << piccard::benchmark::MemoryTracker::GetPeakRSS()
                  << " bytes (excluded from measured phases)\n";
    }

    piccard::baselines::SJ16Trial trial;
    trial.cost = eng.RunQuery(set_a, set_b);  // one measured query
    trial.j_true = j_true;
    return trial;
}

// Aggregate measured SJ16 trials into a single published ComparisonResult row.
// Mirrors RunMultiTrial* / benchmark-stats dispersion: bare timing columns hold
// the per-phase mean, with matching _sd and _median. Accuracy is the mean
// absolute error mean|jaccard_estimate - j_true| (SJ16 is exact, so ~0).
//
// SJ16 has no BFV ring: ring_dim / k / m remain empty numeric N/A cells and
// mult_depth is zero. num_cts carries the genuine on-wire ciphertext count
// |U|+1. Communication comes straight from the engine's per-direction
// serialized-byte accounting (comm_bytes = P1->P2 upload + P2->P1 response;
// ct_size_bytes = P1->P2 upload only).
inline ComparisonResult FinalizeSJ16(
    const std::vector<piccard::baselines::SJ16Trial>& trials,
    uint32_t u,
    const std::string& scenario,
    size_t set_size = 0) {
    ComparisonResult r;
    r.scenario = scenario;
    r.universe_size = u;
    r.set_size = set_size;
    r.num_cts = u + 1;             // |U| indicator cts + 1 response ct on the wire
    r.mult_depth = 0;

    if (trials.empty()) return r;  // caller guards against this; be safe anyway

    std::vector<double> v_encode, v_encrypt, v_compute, v_decrypt, v_total;
    v_encode.reserve(trials.size());
    v_encrypt.reserve(trials.size());
    v_compute.reserve(trials.size());
    v_decrypt.reserve(trials.size());
    v_total.reserve(trials.size());

    double sum_est = 0.0, sum_true = 0.0, sum_err = 0.0, sum_rel = 0.0;
    size_t rel_eligible = 0;
    size_t ct_size = 0, comm_b = 0;

    for (const auto& t : trials) {
        v_encode.push_back(t.cost.phase_encode_ms);
        v_encrypt.push_back(t.cost.phase_encrypt_ms);
        v_compute.push_back(t.cost.phase_compute_ms);
        v_decrypt.push_back(t.cost.phase_decrypt_ms);
        v_total.push_back(t.cost.total_ms);
        double est = t.cost.jaccard_estimate;
        double err = std::abs(est - t.j_true);
        sum_est += est;
        sum_true += t.j_true;
        sum_err += err;
        if (t.j_true > 0.0) { sum_rel += err / t.j_true; rel_eligible++; }
        ct_size = t.cost.ct_size_bytes;   // constant across trials (fixed u/key)
        comm_b = t.cost.comm_bytes;
    }

    auto d_enc = piccard::benchmark::ComputeDispersion(v_encode);
    auto d_cry = piccard::benchmark::ComputeDispersion(v_encrypt);
    auto d_cmp = piccard::benchmark::ComputeDispersion(v_compute);
    auto d_dec = piccard::benchmark::ComputeDispersion(v_decrypt);
    auto d_tot = piccard::benchmark::ComputeDispersion(v_total);
    double n = static_cast<double>(trials.size());

    r.trials = trials.size();
    // SJ16 uses no MinHash CRS (task 9-1a): hash_randomness/hash_seed/
    // hash_root_seed stay at their blank/0 defaults. accuracy_trials
    // reflects the real sample count (SJ16 accuracy and timing share the
    // same per-trial loop, so it equals `trials`).
    r.accuracy_trials = trials.size();
    r.phase_encode_ms = d_enc.mean;  r.phase_encode_ms_sd = d_enc.sd;  r.phase_encode_ms_median = d_enc.median;
    r.phase_encrypt_ms = d_cry.mean; r.phase_encrypt_ms_sd = d_cry.sd; r.phase_encrypt_ms_median = d_cry.median;
    r.phase_compute_ms = d_cmp.mean; r.phase_compute_ms_sd = d_cmp.sd; r.phase_compute_ms_median = d_cmp.median;
    r.phase_decrypt_ms = d_dec.mean; r.phase_decrypt_ms_sd = d_dec.sd; r.phase_decrypt_ms_median = d_dec.median;
    r.total_ms = d_tot.mean;         r.total_ms_sd = d_tot.sd;         r.total_ms_median = d_tot.median;

    r.memory_bytes = piccard::benchmark::MemoryTracker::GetPeakRSS();
    r.ct_size_bytes = ct_size;
    r.comm_bytes = comm_b;

    r.jaccard_computed = sum_est / n;
    r.jaccard_expected = sum_true / n;
    r.jaccard_error = sum_err / n;
    r.jaccard_rel_error =
        (rel_eligible > 0) ? (sum_rel / static_cast<double>(rel_eligible)) : -1.0;
    r.rel_error_eligible_n = rel_eligible;

    return r;
}

// Same host-label normalisation bench_sj16_calibrate uses to name the artifact:
// gethostname(), then every non-alphanumeric byte replaced with '_'.
inline std::string SJ16HostLabel() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) != 0) return "unknown";
    std::string h(buf);
    for (char& ch : h) {
        if (!std::isalnum(static_cast<unsigned char>(ch))) ch = '_';
    }
    if (h.empty()) h = "unknown";
    return h;
}

// Trim leading/trailing ASCII whitespace (incl. a stray CR from CRLF files).
inline std::string SJ16Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

// Value-returning result of consulting results/sj16_calibration_<host>.txt for
// a PASS fit at `key_bits` (task 13-2). `authorized` is the single gate a
// caller must check before publishing anything: it is true only when the
// artifact exists, a coefficient row for `key_bits` was found, AND that row's
// gate == "PASS". `file_found`/`fit_found` exist only so callers can print the
// same three distinct diagnostics PrintSJ16ExtrapolationNote always has
// (missing artifact vs. no matching key_bits vs. gate != PASS) — do not use
// them as an authorization signal, only `authorized` is that.
struct SJ16Extrapolation {
    bool authorized = false;
    bool file_found = false;   // calibration artifact could be opened
    bool fit_found = false;    // a coefficient row for `key_bits` was parsed
    double alpha = 0.0;
    double beta = 0.0;
    double predicted_ms = 0.0;   // alpha*u + beta; 0 unless authorized
    double held_residual = 0.0;
    std::string gate;
    std::string git_commit = "unknown";
    std::string source_sha256 = "unknown";
};

// Parse results/sj16_calibration_<host>.txt for the PASS-fit row matching
// `key_bits` and return the coefficients needed to predict T(u)=alpha*u+beta,
// without printing anything (PrintSJ16ExtrapolationNote below is the stderr
// wrapper; this is the value-returning core plan 13-2 needs to build a CSV
// row). The coefficient row is CSV: key_bits,t_enc_median,t_enc_iqr,alpha,
// beta,r2,held_measured,held_pred,held_residual,gate. Provenance
// (git_commit, source_sha256) is echoed from key=value lines elsewhere in the
// file so the extrapolated row stays traceable to the artifact that
// authorised it.
//
// ⚠ Gate semantics are load-bearing and must not change here: a missing
// file, no matching key_bits row, or a non-PASS gate all leave
// `authorized=false` — publishing an unauthorized extrapolation would be
// worse than omitting the row entirely.
inline SJ16Extrapolation LoadSJ16Extrapolation(uint32_t u, unsigned key_bits) {
    SJ16Extrapolation ex;
    const std::string path =
        "results/sj16_calibration_" + SJ16HostLabel() + ".txt";
    std::ifstream f(path);
    if (!f) return ex;  // file_found=false, authorized=false
    ex.file_found = true;

    std::string line;
    while (std::getline(f, line)) {
        std::string t = SJ16Trim(line);
        if (t.empty() || t[0] == '#') continue;  // comments / column header
        if (t.rfind("git_commit=", 0) == 0) {
            ex.git_commit = SJ16Trim(t.substr(11));
            continue;
        }
        if (t.rfind("source_sha256=", 0) == 0) {
            ex.source_sha256 = SJ16Trim(t.substr(14));
            continue;
        }
        // Candidate coefficient row: exactly 10 comma-separated fields whose
        // first field parses as the key size. Everything else (key=value lines,
        // sample dumps) is skipped by these two guards.
        std::vector<std::string> cols;
        std::stringstream ss(t);
        std::string cell;
        while (std::getline(ss, cell, ',')) cols.push_back(SJ16Trim(cell));
        if (cols.size() != 10) continue;
        try {
            unsigned kb = static_cast<unsigned>(std::stoul(cols[0]));
            if (kb != key_bits) continue;
            ex.alpha = std::stod(cols[3]);
            ex.beta = std::stod(cols[4]);
            ex.held_residual = std::stod(cols[8]);
            ex.gate = cols[9];
            ex.fit_found = true;
            break;
        } catch (...) {
            continue;  // not a numeric coefficient row
        }
    }

    if (!ex.fit_found) return ex;
    if (ex.gate != "PASS") return ex;  // fit_found but not authorized

    ex.authorized = true;
    ex.predicted_ms = ex.alpha * static_cast<double>(u) + ex.beta;
    return ex;
}

// For a universe `u` that exceeds the measured boundary, print a NUMERIC,
// reproducible extrapolation note to stderr instead of the symbolic
// T(m)=alpha*m+beta. Delegates all parsing/gate logic to
// LoadSJ16Extrapolation (single source of truth); this function only turns
// the result into the same three stderr diagnostics it has always printed —
// text is unchanged so existing operational logs keep working.
inline void PrintSJ16ExtrapolationNote(uint32_t u, unsigned key_bits) {
    const std::string path =
        "results/sj16_calibration_" + SJ16HostLabel() + ".txt";
    SJ16Extrapolation ex = LoadSJ16Extrapolation(u, key_bits);

    if (!ex.file_found) {
        std::cerr << "  U=" << u
                  << " sj16: extrapolation not authorized: no calibration "
                     "artifact (" << path << ")\n";
        return;
    }
    if (!ex.fit_found) {
        std::cerr << "  U=" << u
                  << " sj16: extrapolation NOT authorized: no PASS fit for "
                     "key_bits=" << key_bits << " in " << path << "\n";
        return;
    }
    if (ex.gate != "PASS") {
        std::cerr << "  U=" << u
                  << " sj16: extrapolation NOT authorized: calibration gate="
                  << ex.gate << " (not PASS) for key_bits=" << key_bits << "\n";
        return;
    }

    std::cerr << "  U=" << u
              << " sj16: numeric extrapolation from PASS fit (key_bits="
              << key_bits << "): alpha=" << ex.alpha << " ms/m, beta=" << ex.beta
              << " ms, T(u)=alpha*u+beta=" << ex.predicted_ms
              << " ms, held_residual=" << ex.held_residual
              << ", git_commit=" << ex.git_commit
              << ", source_sha256=" << ex.source_sha256 << "\n";
}

// Build the CSV row for an authorized SJ16 extrapolation (task 13-2). Caller
// MUST have checked ex.authorized == true first — this function does not
// re-check the gate, it only maps an already-authorized fit onto
// ComparisonResult's field conventions:
//   - total_ms = predicted_ms, trials = 0, every *_sd stays at the class's
//     -1 unmeasured default (do NOT set trials>0 or a positive sd — that
//     would misrepresent a prediction as a measurement).
//   - phase_* stay at their 0 default: the fit predicts total time only, a
//     per-phase breakdown would be invented.
//   - jaccard_*/accuracy_trials stay at their 0 default (unmeasured — SJ16
//     was never run at this universe size).
//   - the 8 flood columns stay at their non-Piccard 0/-1 default
//     (ComparisonResult's own member initializers already do this; this
//     function does not touch them).
//   - num_cts = u+1 mirrors FinalizeSJ16's unconditional u+1 (a structural
//     fact of the protocol at this universe size, not a measurement).
//   - ct_size_bytes/comm_bytes stay at 0 (plan-13 D3): the fit gives timing
//     only. Reproducing SJ16's Paillier-serialization byte accounting here
//     would require re-deriving src/baselines/sj16.cpp's internal formula,
//     which is out of this task's file ownership and risks inventing a
//     wrong number — left at 0 for a caption footnote instead of a guess.
inline ComparisonResult FinalizeSJ16Extrapolated(
    const SJ16Extrapolation& ex,
    uint32_t u,
    const std::string& scenario,
    size_t set_size = 0) {
    ComparisonResult r;
    r.scenario = scenario;
    r.universe_size = u;
    r.set_size = set_size;
    r.num_cts = u + 1;
    r.mult_depth = 0;

    r.total_ms = ex.predicted_ms;
    r.trials = 0;  // unmeasured sentinel; leaves total_ms_sd etc. at -1 default

    r.measurement_status = "extrapolated";
    std::ostringstream a, b, res;
    a << std::fixed << std::setprecision(6) << ex.alpha;
    b << std::fixed << std::setprecision(6) << ex.beta;
    res << std::fixed << std::setprecision(6) << ex.held_residual;
    r.extrapolation_alpha = a.str();
    r.extrapolation_beta = b.str();
    r.extrapolation_residual = res.str();
    r.extrapolation_source = ex.git_commit + ":" + ex.source_sha256;

    return r;
}
