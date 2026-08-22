/**
 * @file bench_noise.cpp
 * @brief Decryption-noise calibration harness for noise flooding (R2-W6, P1-3).
 *
 * The security proof applies noise flooding: before returning the result the
 * server adds masking noise of magnitude 2^(lambda_s) times the maximum
 * evaluation noise. Sizing that term needs a number the protocol itself can
 * never observe -- the server has no secret key -- so the bound is measured
 * offline here and baked in as a constant.
 *
 * For a BFV ciphertext (c0, c1) under secret s, decryption computes
 *     c0 + c1*s = Delta*m + e   (mod q),  Delta = floor(q/t)
 * and rounds. We recover ||e||_inf exactly by CRT-interpolating c0 + c1*s to a
 * big integer per coefficient, centering it mod q, and taking the distance to
 * the nearest multiple of Delta. Decryption is correct while ||e||_inf < Delta/2.
 *
 * Two derived quantities are reported per row:
 *
 *   headroom_bits = log2(Delta/2) - log2(B_eval)
 *       Spare budget in bits, matching the convention used in the branch plan.
 *
 *   fits = (eval_noise_bits + margin + target_lambda + 2 <= log_delta)
 *       Whether the plan's Validate() inequality holds for the requested
 *       target. This is the gate that decides a (depth, sms) pair.
 *
 * Circuits are driven through the library API on purpose. The benchmarks
 * elsewhere in this directory re-implement the protocol inline for per-phase
 * timing; duplicating it here would let the calibration drift away from what
 * the protocol actually computes, which is the failure mode this harness
 * exists to prevent.
 *
 * Usage:
 *   bench_noise --sweep [--circuit=onehot|sqrt|threshold|all] [--csv=path]
 *   bench_noise --circuit=onehot --security=STD128 --k=128 --m=64 \
 *               --depth_delta=1 --sms=60
 */

#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"
#include "protocol/threshold_piccard.h"
#include "fhe/bfv_context.h"
#include "util/params.h"
#include "util/params_calibration.h"
#include "util/security_profile.h"

#include "benchmark_utils.h"
#include "noise_calibration_schema.h"
#include "noise_calibration_probe.h"
#include "util/noise_profile_matrix.h"
#include "openfhe.h"

// Required for CiphertextSizer: serialized size is what the paper's
// communication-cost table should report, and it tracks limb count rather than
// the theoretical 2N*ceil(log q) figure.
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace piccard;
namespace calibration_probe = piccard::std_evidence::calibration;
using Pattern = piccard::benchmark::noise_calibration::EvidencePattern;

// ============================================================================
// Noise measurement
// ============================================================================

/// Exact ||(c0 + c1*s) - Delta*m||_inf, in bits. Returns 0.0 for a noiseless
/// ciphertext (does not occur in practice; guards log2(0)).
static double NoiseBits(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                        const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& sk,
                        const lbcrypto::BigInteger& Q,
                        uint64_t t) {
    return calibration_probe::MeasureDecryptionPhaseNoise(ct, sk, Q, t);
}

// ============================================================================
// Context description
// ============================================================================

struct CtxInfo {
    uint32_t ring_dim = 0;
    uint32_t num_limbs = 0;
    double   log_q = 0.0;
    uint64_t plaintext_mod = 0;
    double   log_delta = 0.0;
    lbcrypto::BigInteger Q;
};

static CtxInfo Describe(const BFVContext& bfv) {
    CtxInfo info;
    const auto& cc = bfv.GetCryptoContext();
    auto crypto_params = cc->GetCryptoParameters();
    auto elem_params = crypto_params->GetElementParams();

    info.Q = elem_params->GetModulus();
    info.log_q = std::log2(info.Q.ConvertToDouble());
    info.num_limbs = static_cast<uint32_t>(elem_params->GetParams().size());
    info.ring_dim = cc->GetRingDimension();
    info.plaintext_mod = crypto_params->GetPlaintextModulus();
    info.log_delta = info.log_q - std::log2(static_cast<double>(info.plaintext_mod));
    return info;
}

// ============================================================================
// Input patterns
// ============================================================================

// B_eval is expected to be input-independent for these circuits (feature
// vectors are 0/1 either way, and key-switching noise does not depend on the
// plaintext), but "expected" is not "measured": the sweep runs all three so a
// worst case cannot hide behind a single lucky draw.
static const char* PatternName(Pattern p) {
    switch (p) {
        case Pattern::AllMatch: return "all_match";
        case Pattern::NoMatch:  return "no_match";
        case Pattern::Random:   return "random";
    }
    return "?";
}

/// Deterministic seed for one measurement cell. A single shared generator
/// consumed in grid order makes a cell's signatures depend on which other cells
/// ran before it, so `--circuit=onehot` and `--circuit=all` would disagree on
/// the same cell. Phase 3 pins the calibration table against a re-measurement,
/// which needs that to be reproducible.
static uint64_t CellSeed(uint64_t root, const char* circuit, uint32_t ring_dim,
                         uint32_t depth, uint32_t sms, int pattern) {
    return calibration_probe::DerivePatternSeed(
        root, circuit, ring_dim, depth, sms,
        static_cast<calibration_probe::Pattern>(pattern));
}

/// Synthetic MinHash signatures with an exactly known match count. Both
/// encoders consume sig[i] % m, so driving them directly gives precise control
/// over the plaintext the circuit sees without involving the hash family.
static std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeSignatures(Pattern p, uint32_t k, uint32_t m, std::mt19937_64& rng) {
    return calibration_probe::MakeSignatures(
        static_cast<calibration_probe::Pattern>(p), k, m, rng);
}

static int64_t ExpectedMatches(const std::vector<uint64_t>& sx,
                               const std::vector<uint64_t>& sy,
                               uint32_t m) {
    return calibration_probe::ExpectedMatches(sx, sy, m);
}

// ============================================================================
// Result row
// ============================================================================

struct CalibResult {
    std::string circuit;
    std::string security;
    uint32_t k = 0, m = 0;
    uint32_t ring_dim = 0;
    // What Validate() asked for, before OpenFHE had a say. A limb layout whose
    // total log q exceeds the security table's cap for that dimension does not
    // throw -- OpenFHE silently doubles the ring instead, which doubles every
    // runtime in the paper. Cells that did so are recorded but never counted as
    // feasible.
    uint32_t ring_dim_requested = 0;
    // The dimension this circuit already needs at its own natural depth with
    // OpenFHE's default limb size. For the threshold variant that is larger
    // than the slot requirement -- a degree-k polynomial needs a long modulus
    // chain, and OpenFHE grows the ring to carry it, with or without flooding.
    // Feasibility must therefore be judged against this, not against the slot
    // requirement, or every threshold cell is rejected for a cost flooding did
    // not cause.
    uint32_t ring_dim_baseline = 0;
    uint32_t ring_dim_calibrated = 0;
    bool     ring_dim_grew = false;
    bool     pre_threshold_evidence = false;
    uint32_t mult_depth = 0;
    // The depth Validate()/ValidateSqrt() derives on its own, before any sweep
    // override. Phase 1 knows this value before a context exists, so it is the
    // part of the table key that disambiguates threshold configurations which
    // share a slot requirement but differ in circuit depth (k=32 -> 9,
    // k=128 -> 15, both requesting ring_dim 8192).
    uint32_t natural_mult_depth = 0;
    uint32_t scaling_mod_size = 0;
    uint32_t num_limbs = 0;
    uint64_t plaintext_mod = 0;
    double   log_q = 0.0;
    double   log_delta = 0.0;
    std::string pattern;
    double   eval_noise_bits = 0.0;
    double   headroom_bits = 0.0;
    bool     decrypt_ok = false;
    // The noise measurement folds distance-to-nearest-multiple-of-Delta, so it
    // can never exceed Delta/2 by construction. Once the true noise reaches
    // that ceiling the measurement aliases and UNDERSTATES it -- which, if such
    // a row reached the table, would shrink the flooding magnitude and silently
    // reduce the statistical security parameter. Flag it and never treat it as
    // feasible.
    bool     saturated = false;
    // Match count (all circuits). For the threshold variant the 0/1 decision is
    // checked separately: a bool guard alone passes half the time under a fully
    // corrupted decryption.
    int64_t  expected = 0;
    int64_t  got = 0;
    bool     decision_ok = true;
    size_t   ct_bytes = 0;
    bool     ok = false;            // context built and circuit ran
    std::string error;
};

static const char* SecurityName(SecurityLevel s) {
    switch (s) {
        case SecurityLevel::TOY:    return "TOY";
        case SecurityLevel::STD128: return "STD128";
        case SecurityLevel::STD192: return "STD192";
        case SecurityLevel::STD256: return "STD256";
    }
    return "?";
}

static void Finish(CalibResult& r, const CtxInfo& info, double noise_bits) {
    r.ring_dim      = info.ring_dim;
    r.num_limbs     = info.num_limbs;
    r.plaintext_mod = info.plaintext_mod;
    r.log_q         = info.log_q;
    r.log_delta     = info.log_delta;
    r.eval_noise_bits = noise_bits;
    // log2(Delta/2) - log2(B_eval); matches the branch plan's convention.
    r.headroom_bits = info.log_delta - 1.0 - noise_bits;
    r.saturated = (r.headroom_bits < 0.5);
    r.ok = true;
}

// ============================================================================
// Circuit runners (library API only)
// ============================================================================

// Each runner builds the context once and measures every requested pattern on
// it. KeyGen dominates the cost at large ring dimensions, and the patterns
// differ only in the plaintext, so sharing the context is both faster and a
// cleaner comparison: the per-cell worst case is then taken over patterns that
// saw exactly the same keys.

static std::vector<CalibResult> RunOneHot(PiccardParams params,
                                          const std::vector<Pattern>& pats,
                                          uint64_t root_seed, uint32_t reps) {
    using clk = std::chrono::high_resolution_clock;
    auto span = [](clk::time_point a, clk::time_point b) {
        return std::chrono::duration<double, std::milli>(b - a).count();
    };
    auto t_begin = clk::now();
    const uint32_t requested_ring_dim = params.ring_dim;
    Piccard engine(params);
    engine.KeyGen();
    auto t_keygen = clk::now();
    double ms_enc = 0, ms_eval = 0, ms_noise = 0, ms_dec = 0, ms_ser = 0;

    const auto& bfv = engine.GetBFVContext();
    CtxInfo info = Describe(bfv);

    std::vector<CalibResult> out;
    for (Pattern pat : pats) {
        CalibResult r;
        r.circuit = "onehot";
        r.security = SecurityName(params.security);
        r.ring_dim_requested = requested_ring_dim;
        r.k = params.k;
        r.m = params.m;
        r.mult_depth = params.mult_depth;
        r.scaling_mod_size = params.scaling_mod_size;
        r.pattern = PatternName(pat);

        std::mt19937_64 cell_rng(CellSeed(root_seed, "onehot", info.ring_dim,
                                         params.mult_depth,
                                         params.scaling_mod_size,
                                         static_cast<int>(pat)));
        auto [sx, sy] = MakeSignatures(pat, params.k, params.m, cell_rng);
        r.expected = ExpectedMatches(sx, sy, params.m);

        // Repeat under fresh encryption randomness and keep the worst. One draw
        // is a single sample of a distribution whose observed spread reaches
        // several bits, and a security parameter is sized from this number.
        // KeyGen is shared, so the repetitions cost only the circuit itself.
        double noise = 0.0;
        r.decrypt_ok = true;
        for (uint32_t rep = 0; rep < reps; rep++) {
            auto a = clk::now();
            auto ct_x = engine.EncryptFeature(engine.EncodeSignature(sx));
            auto ct_y = engine.EncryptFeature(engine.EncodeSignature(sy));
            auto b2 = clk::now(); ms_enc += span(a, b2);
            // Raw: this harness measures the evaluation noise that sizes the
            // flooding term, so it must not include the flooding term itself.
            auto ct_res = engine.EvaluateRaw(ct_x, ct_y);
            auto c2 = clk::now(); ms_eval += span(b2, c2);
            noise = std::max(noise, NoiseBits(ct_res, bfv.GetSecretKeyForCalibration(),
                                              info.Q, info.plaintext_mod));
            auto d2 = clk::now(); ms_noise += span(c2, d2);
            r.got = engine.Decrypt(ct_res).match_count;
            auto e2 = clk::now(); ms_dec += span(d2, e2);
            r.decrypt_ok = r.decrypt_ok && (r.expected == r.got);
            if (rep == 0) {
                r.ct_bytes =
                    piccard::benchmark::CiphertextSizer::GetSerializedSize(ct_res);
            }
            ms_ser += span(e2, clk::now());
        }
        Finish(r, info, noise);
        out.push_back(r);
    }
    if (std::getenv("BENCH_NOISE_TIMING")) {
        std::fprintf(stderr,
                "    [timing] keygen %8.1f  enc %7.1f  eval %8.1f  noise %8.1f"
                "  dec %7.1f  ser %7.1f  total %8.1f ms\n",
                span(t_begin, t_keygen), ms_enc, ms_eval, ms_noise, ms_dec,
                ms_ser, span(t_begin, clk::now()));
    }
    return out;
}

static std::vector<CalibResult> RunSqrt(PiccardParams params,
                                        const std::vector<Pattern>& pats,
                                        uint64_t root_seed, uint32_t reps) {
    const uint32_t requested_ring_dim = params.ring_dim;
    SqrtPiccard engine(params);
    engine.KeyGen();

    const auto& bfv = engine.GetBFVContext();
    CtxInfo info = Describe(bfv);

    std::vector<CalibResult> out;
    for (Pattern pat : pats) {
        CalibResult r;
        r.circuit = "sqrt";
        r.security = SecurityName(params.security);
        r.ring_dim_requested = requested_ring_dim;
        r.k = params.k;
        r.m = params.m;
        r.mult_depth = params.mult_depth;
        r.scaling_mod_size = params.scaling_mod_size;
        r.pattern = PatternName(pat);

        std::mt19937_64 cell_rng(CellSeed(root_seed, "sqrt", info.ring_dim,
                                         params.mult_depth,
                                         params.scaling_mod_size,
                                         static_cast<int>(pat)));
        auto [sx, sy] = MakeSignatures(pat, params.k, params.m, cell_rng);
        r.expected = ExpectedMatches(sx, sy, params.m);

        // Repeat under fresh encryption randomness and keep the worst. One draw
        // is a single sample of a distribution whose observed spread reaches
        // several bits, and a security parameter is sized from this number.
        // KeyGen is shared, so the repetitions cost only the circuit itself.
        double noise = 0.0;
        r.decrypt_ok = true;
        for (uint32_t rep = 0; rep < reps; rep++) {
            auto ct_x = engine.EncryptFeature(engine.EncodeSignature(sx));
            auto ct_y = engine.EncryptFeature(engine.EncodeSignature(sy));
            // Raw: this harness measures the evaluation noise that sizes the
            // flooding term, so it must not include the flooding term itself.
            auto ct_res = engine.EvaluateRaw(ct_x, ct_y);
            noise = std::max(noise, NoiseBits(ct_res, bfv.GetSecretKeyForCalibration(),
                                              info.Q, info.plaintext_mod));
            r.got = engine.Decrypt(ct_res).match_count;
            r.decrypt_ok = r.decrypt_ok && (r.expected == r.got);
            if (rep == 0) {
                r.ct_bytes =
                    piccard::benchmark::CiphertextSizer::GetSerializedSize(ct_res);
            }
        }
        Finish(r, info, noise);
        out.push_back(r);
    }
    return out;
}

static std::vector<CalibResult> RunThreshold(PiccardParams params,
                                             const std::vector<Pattern>& pats,
                                             uint64_t root_seed, uint32_t reps) {
    const uint32_t requested_ring_dim = params.ring_dim;
    ThresholdPiccard engine(params);
    engine.KeyGen();

    const auto& bfv = engine.GetBFVContext();
    CtxInfo info = Describe(bfv);
    const Piccard& base = engine.GetPiccard();

    std::vector<CalibResult> out;
    for (Pattern pat : pats) {
        CalibResult r;
        r.circuit = "threshold";
        r.security = SecurityName(params.security);
        r.ring_dim_requested = requested_ring_dim;
        r.k = params.k;
        r.m = params.m;
        r.mult_depth = params.mult_depth;
        r.scaling_mod_size = params.scaling_mod_size;
        r.pattern = PatternName(pat);

        std::mt19937_64 cell_rng(CellSeed(root_seed, "threshold", info.ring_dim,
                                         params.mult_depth,
                                         params.scaling_mod_size,
                                         static_cast<int>(pat)));
        auto [sx, sy] = MakeSignatures(pat, params.k, params.m, cell_rng);
        r.expected = ExpectedMatches(sx, sy, params.m);
        const bool want =
            (r.expected >= static_cast<int64_t>(params.threshold_tau));

        double noise = 0.0;
        r.decrypt_ok = true;
        r.decision_ok = true;
        for (uint32_t rep = 0; rep < reps; rep++) {
            auto ct_x = base.EncryptFeature(base.EncodeSignature(sx));
            auto ct_y = base.EncryptFeature(base.EncodeSignature(sy));
            // Raw: this harness measures the evaluation noise that sizes the
            // flooding term, so it must not include the flooding term itself.
            auto ct_res = engine.EvaluateRaw(ct_x, ct_y);
            noise = std::max(noise, NoiseBits(ct_res, bfv.GetSecretKeyForCalibration(),
                                              info.Q, info.plaintext_mod));

            // The threshold output is a single bit, so comparing it alone would
            // pass half the time on a fully corrupted decryption. Recover the
            // pre-polynomial match count through the base engine and check that
            // too; only both together show the circuit actually decrypted.
            auto ct_match = base.EvaluateRaw(ct_x, ct_y);
            r.got = base.Decrypt(ct_match).match_count;
            r.decision_ok = r.decision_ok && (want == engine.Decrypt(ct_res));
            r.decrypt_ok = r.decrypt_ok && (r.expected == r.got);
            if (rep == 0) {
                r.ct_bytes =
                    piccard::benchmark::CiphertextSizer::GetSerializedSize(ct_res);
            }
        }
        r.decrypt_ok = r.decrypt_ok && r.decision_ok;
        Finish(r, info, noise);
        out.push_back(r);
    }
    return out;
}

// ============================================================================
// Configuration assembly
// ============================================================================

// piccard::Circuit is the same enum the calibration table keys on, so the
// harness uses it rather than defining a parallel one that could drift.
static const char* CircuitName(Circuit c) {
    switch (c) {
        case Circuit::OneHot:    return "onehot";
        case Circuit::Sqrt:      return "sqrt";
        case Circuit::Threshold: return "threshold";
    }
    return "?";
}

/// Validate for the circuit, then apply the sweep overrides. PiccardParams is a
/// plain struct, so the harness can pin (mult_depth, scaling_mod_size) after
/// the derived fields are computed -- that is what lets a grid sweep run
/// through the same code path the protocol uses.
static uint64_t FindCandidatePlaintextModulus(
    uint32_t candidate_max_k,
    uint32_t calibrated_ring_dim) {
    if (candidate_max_k == 0) {
        throw std::invalid_argument(
            "candidate plaintext minimum must be positive");
    }
    if (calibrated_ring_dim == 0) {
        throw std::invalid_argument(
            "candidate plaintext ring dimension must be positive");
    }
    const uint64_t two_n_wide =
        UINT64_C(2) * static_cast<uint64_t>(calibrated_ring_dim);
    if (two_n_wide > std::numeric_limits<uint32_t>::max()) {
        throw std::overflow_error(
            "candidate plaintext cyclotomic order exceeds uint32");
    }
    const uint32_t two_n = static_cast<uint32_t>(two_n_wide);
    const uint64_t plaintext_mod =
        FindPlaintextModulus(candidate_max_k, two_n);
    if (plaintext_mod <= candidate_max_k ||
        !IsPrime(plaintext_mod) ||
        (plaintext_mod - 1) % two_n != 0) {
        throw std::logic_error(
            "derived candidate plaintext modulus violates packed BFV contract");
    }
    return plaintext_mod;
}

// PoC giant-step comparison (review item D-10): the probe that measures the
// tree circuit's evaluation noise has to build the tree circuit. Horner stays
// the default, so every existing invocation is unaffected.
static GiantStepMode g_giant_step = GiantStepMode::Horner;

static PiccardParams BuildParams(Circuit circuit, SecurityLevel sec,
                                 uint32_t k, uint32_t m,
                                 uint32_t depth_delta, uint32_t sms,
                                 bool pre_threshold_evidence,
                                 uint32_t natural_ring_dim = 0,
                                 uint32_t calibrated_ring_dim = 0,
                                 uint32_t* natural_depth_out = nullptr,
                                 uint32_t candidate_max_k = 0) {
    PiccardParams params;
    params.k = k;
    params.m = m;
    params.security = sec;
    // Set before Derive: the threshold natural depth is a function of it.
    params.giant_step = g_giant_step;

    // Derive only: Validate() would consult the calibration table this harness
    // exists to produce, and would throw for any key not yet measured.
    if (circuit == Circuit::Sqrt) {
        CalibrationAccess::DeriveSqrt(params);
    } else {
        if (circuit == Circuit::Threshold) {
            params.threshold_mode = true;
            params.threshold_tau = k / 2;
        }
        CalibrationAccess::Derive(params);
    }

    if (natural_depth_out) *natural_depth_out = params.natural_mult_depth;
    params.mult_depth += depth_delta;
    params.scaling_mod_size = sms;

    // Work 2 made protocol KeyGen adopt only a sanitizer-selected runtime
    // dimension. Evidence still needs the production raw circuit path, so arm
    // that adoption guard with the already validated explicit candidate.
    // EvaluateRaw never applies its placeholder flooding value; the measured
    // result is reduced later with the requested evidence profile.
    if (pre_threshold_evidence) {
        if (natural_ring_dim == 0 || calibrated_ring_dim == 0) {
            throw std::invalid_argument(
                "pre-threshold measurement requires explicit natural and "
                "calibrated ring dimensions");
        }
        const uint32_t plaintext_minimum =
            candidate_max_k == 0 ? k : candidate_max_k;
        if (plaintext_minimum < k) {
            throw std::invalid_argument(
                "candidate maximum consumer k is below current consumer k");
        }
        params.plaintext_mod = FindCandidatePlaintextModulus(
            plaintext_minimum, calibrated_ring_dim);
        params.transcript_stat_bits = 40;
        params.max_queries = 1;
        params.flood_margin_bits = 0;
        params = SelectSanitizerCandidate(
            params,
            CalibrationCandidate{
                circuit,
                sec,
                params.ring_dim,
                natural_ring_dim,
                calibrated_ring_dim,
                params.natural_mult_depth,
                params.mult_depth,
                params.scaling_mod_size,
                0,
                1.0e9,
            });
    }
    return params;
}

/// `baseline_ring_dim` is the dimension the circuit needs untouched; pass 0 to
/// fall back to the slot requirement (single-point mode, where no baseline run
/// has happened).
static std::vector<CalibResult> RunOne(Circuit circuit, SecurityLevel sec,
                                       uint32_t k, uint32_t m,
                                       uint32_t depth_delta, uint32_t sms,
                                       const std::vector<Pattern>& pats,
                                       uint64_t root_seed, uint32_t reps,
                                       uint32_t baseline_ring_dim,
                                       bool pre_threshold_evidence,
                                       uint32_t calibrated_ring_dim = 0,
                                       uint32_t candidate_max_k = 0) {
    try {
        uint32_t natural_depth = 0;
        PiccardParams params =
            BuildParams(
                circuit,
                sec,
                k,
                m,
                depth_delta,
                sms,
                pre_threshold_evidence,
                baseline_ring_dim,
                calibrated_ring_dim,
                &natural_depth,
                candidate_max_k);
        std::vector<CalibResult> rows;
        switch (circuit) {
            case Circuit::OneHot:    rows = RunOneHot(params, pats, root_seed, reps); break;
            case Circuit::Sqrt:      rows = RunSqrt(params, pats, root_seed, reps); break;
            case Circuit::Threshold: rows = RunThreshold(params, pats, root_seed, reps); break;
        }
        for (auto& r : rows) {
            r.natural_mult_depth = natural_depth;
            r.ring_dim_baseline =
                baseline_ring_dim ? baseline_ring_dim : r.ring_dim_requested;
            r.ring_dim_calibrated =
                calibrated_ring_dim ? calibrated_ring_dim : r.ring_dim;
            r.ring_dim_grew = (r.ring_dim > r.ring_dim_baseline);
            r.pre_threshold_evidence = pre_threshold_evidence;
        }
        return rows;
    } catch (const std::exception& e) {
        // An infeasible limb layout (log q above the security table's cap for
        // this ring dimension) surfaces here. Record it rather than skipping,
        // so the sweep output shows which cells were ruled out and why.
        CalibResult r;
        r.circuit = CircuitName(circuit);
        r.security = SecurityName(sec);
        r.k = k;
        r.m = m;
        r.scaling_mod_size = sms;
        r.ring_dim_baseline = baseline_ring_dim;
        r.ring_dim_calibrated = calibrated_ring_dim;
        r.pre_threshold_evidence = pre_threshold_evidence;
        r.pattern = "-";
        r.ok = false;
        r.error = e.what();
        return {r};
    }
    return {};
}

using OpenFHEContextImpl =
    lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>;
using OpenFHEContextFactory =
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>;

struct OpenFHEStaticStateCounts {
    size_t mult = 0;
    size_t automorphism = 0;
    size_t contexts = 0;

    bool IsEmpty() const {
        return mult == 0 && automorphism == 0 && contexts == 0;
    }
    bool operator==(const OpenFHEStaticStateCounts& other) const {
        return mult == other.mult &&
               automorphism == other.automorphism &&
               contexts == other.contexts;
    }
};

static OpenFHEStaticStateCounts GetOpenFHEStaticStateCounts() {
    return {
        OpenFHEContextImpl::GetAllEvalMultKeys().size(),
        OpenFHEContextImpl::GetAllEvalAutomorphismKeys().size(),
        static_cast<size_t>(OpenFHEContextFactory::GetContextCount()),
    };
}

static void ClearStrictMeasurementOpenFHEState() noexcept {
    try { OpenFHEContextImpl::ClearEvalMultKeys(); } catch (...) {}
    try { OpenFHEContextImpl::ClearEvalAutomorphismKeys(); } catch (...) {}
    try { OpenFHEContextFactory::ReleaseAllContexts(); } catch (...) {}
}

class StrictMeasurementOpenFHECleanup final {
public:
    StrictMeasurementOpenFHECleanup() = default;
    StrictMeasurementOpenFHECleanup(
        const StrictMeasurementOpenFHECleanup&) = delete;
    StrictMeasurementOpenFHECleanup& operator=(
        const StrictMeasurementOpenFHECleanup&) = delete;
    ~StrictMeasurementOpenFHECleanup() noexcept {
        ClearStrictMeasurementOpenFHEState();
    }
};

template <typename Measurement>
static auto RunWithStrictMeasurementCleanup(Measurement&& measurement)
    -> decltype(std::forward<Measurement>(measurement)()) {
    StrictMeasurementOpenFHECleanup cleanup;
    return std::forward<Measurement>(measurement)();
}

static uint32_t DiscoverNaturalRingDimension(
    Circuit circuit,
    SecurityLevel security,
    uint32_t k,
    uint32_t m) {
    PiccardParams params = BuildParams(
        circuit,
        security,
        k,
        m,
        0,
        0,
        false);
    BFVContext context(params);
    context.Initialize();
    return context.GetSlotCount();
}

static uint32_t DiscoverNaturalRingDimensionContextOnly(
    Circuit circuit,
    SecurityLevel security,
    uint32_t k,
    uint32_t m) {
    PiccardParams params = BuildParams(
        circuit,
        security,
        k,
        m,
        0,
        0,
        false);
    BFVContext context(params);
    context.InitializeContextOnly();
    return context.GetSlotCount();
}

// ============================================================================
// Output
// ============================================================================

static void WriteCsvHeader(std::ostream& os) {
    os << "circuit,security,k,m,ring_dim,ring_dim_requested,ring_dim_baseline,ring_dim_grew,"
       << "mult_depth,natural_mult_depth,scaling_mod_size,num_limbs,"
       << "plaintext_mod,log_q,log_delta,pattern,eval_noise_bits,headroom_bits,"
       << "saturated,decrypt_ok,decision_ok,expected,got,ct_bytes,status\n";
}

static void WriteCsvRow(std::ostream& os, const CalibResult& r) {
    os << r.circuit << "," << r.security << "," << r.k << "," << r.m << ","
       << r.ring_dim << "," << r.ring_dim_requested << ","
       << r.ring_dim_baseline << "," << (r.ring_dim_grew ? 1 : 0) << ","
       << r.mult_depth << "," << r.natural_mult_depth << ","
       << r.scaling_mod_size << ","
       << r.num_limbs << "," << r.plaintext_mod << ","
       << std::fixed << std::setprecision(1) << r.log_q << ","
       << r.log_delta << "," << r.pattern << ","
       << std::setprecision(2) << r.eval_noise_bits << ","
       << r.headroom_bits << ","
       << (r.saturated ? 1 : 0) << "," << (r.decrypt_ok ? 1 : 0) << ","
       << (r.decision_ok ? 1 : 0) << ","
       << r.expected << "," << r.got << "," << r.ct_bytes << ","
       << (r.ok ? "ok" : ("FAILED: " + r.error)) << "\n";
}

static void PrintRow(const CalibResult& r) {
    std::ostringstream label;
    label << r.circuit << " " << r.security << " (" << r.k << "," << r.m << ")"
          << " d=" << r.mult_depth << " sms=" << r.scaling_mod_size;

    if (!r.ok) {
        std::cout << "  " << std::left << std::setw(46) << label.str()
                  << "  FAILED: " << r.error << "\n" << std::right;
        return;
    }

    std::cout << "  " << std::left << std::setw(46) << label.str() << std::right
              << "  N=" << std::setw(6) << r.ring_dim
              << " logq=" << std::fixed << std::setprecision(1) << std::setw(6) << r.log_q
              << " limbs=" << std::setw(2) << r.num_limbs
              << " t=" << std::setw(8) << r.plaintext_mod
              << " | " << std::left << std::setw(10) << r.pattern << std::right
              << " B_eval=" << std::setprecision(2) << std::setw(7) << r.eval_noise_bits
              << " headroom=" << std::setw(7) << r.headroom_bits
              << (r.pre_threshold_evidence
                      ? "  requested N=" +
                            std::to_string(r.ring_dim_requested) +
                            " natural N=" +
                            std::to_string(r.ring_dim_baseline) +
                            " calibrated N=" +
                            std::to_string(r.ring_dim_calibrated) +
                            " realized N=" +
                            std::to_string(r.ring_dim)
                      : "")
              << "  " << (r.decrypt_ok ? "dec-OK" : "DEC-FAIL")
              << (r.decision_ok ? "" : " DECISION-FAIL")
              << (r.saturated ? "  SATURATED" : "")
              << (r.ring_dim_grew ? "  N-GREW" : "")
              << "\n";
}

// ============================================================================
// Sweep grid
// ============================================================================

struct GridEntry {
    Circuit circuit;
    SecurityLevel security;
    uint32_t k;
    uint32_t m;
};

/// The (k, m) values are chosen for the ring dimension they produce, since
/// B_eval is governed by N and the limb layout rather than by k and m directly.
///
/// TOY rows are mandatory, not optional: 17 of the 18 SecurityLevel uses in
/// tests/ are TOY, so a table that only covers STD128 would make Validate()
/// throw for the entire test suite once the parameter selection lands.
/// `include_large` adds the expensive configurations (N >= 65536, threshold at
/// k=128); `large_only` restricts to exactly those, so a run that already
/// covered the base grid does not repeat it.
static std::vector<GridEntry> BuildGrid(Circuit only, bool include_large,
                                        bool large_only) {
    std::vector<GridEntry> grid;

    auto add = [&](Circuit c, SecurityLevel s, uint32_t k, uint32_t m) {
        if (only == c && !large_only) grid.push_back({c, s, k, m});
    };
    auto add_large = [&](Circuit c, SecurityLevel s, uint32_t k, uint32_t m) {
        if (only == c && (include_large || large_only)) grid.push_back({c, s, k, m});
    };

    // --- one-hot: ring_dim = max(NextPow2(k*m), floor) ---
    // TOY is not optional coverage: 17 of the 18 SecurityLevel uses in tests/
    // are TOY, and the calibration key includes the security level, so a TOY
    // configuration cannot borrow an STD128 measurement.
    add(Circuit::OneHot, SecurityLevel::TOY, 16, 64);      // N = 1024
    add(Circuit::OneHot, SecurityLevel::TOY, 32, 64);      // N = 2048
    add(Circuit::OneHot, SecurityLevel::TOY, 64, 64);      // N = 4096
    add(Circuit::OneHot, SecurityLevel::TOY, 128, 64);     // N = 8192 (e2e test)
    add(Circuit::OneHot, SecurityLevel::TOY, 256, 64);     // N = 16384
    add(Circuit::OneHot, SecurityLevel::TOY, 512, 64);     // N = 32768
    add(Circuit::OneHot, SecurityLevel::TOY, 512, 128);    // N = 65536
    add(Circuit::OneHot, SecurityLevel::TOY, 512, 256);    // N = 131072
    add(Circuit::OneHot, SecurityLevel::STD128, 128, 64);  // N = 8192
    add(Circuit::OneHot, SecurityLevel::STD128, 256, 64);  // N = 16384
    add(Circuit::OneHot, SecurityLevel::STD128, 512, 64);  // N = 32768
    add_large(Circuit::OneHot, SecurityLevel::STD128, 256, 256);   // N = 65536
    add_large(Circuit::OneHot, SecurityLevel::STD128, 512, 256);   // N = 131072
    // bench_crossover sweeps m to 1024 with k to 512, so the one-hot half of
    // that grid reaches these. Without rows here Validate() throws and those
    // benchmarks abort -- they have no handler.
    add_large(Circuit::OneHot, SecurityLevel::STD128, 256, 1024);  // N = 262144
    add_large(Circuit::OneHot, SecurityLevel::STD128, 512, 1024);  // N = 524288

    // --- base-sqrt(m): ring_dim = max(NextPow2(k * 2 * sqrt(m)), floor) ---
    add(Circuit::Sqrt, SecurityLevel::TOY, 16, 64);        // N = 1024 (unit tests)
    add(Circuit::Sqrt, SecurityLevel::TOY, 64, 64);        // N = 1024
    add(Circuit::Sqrt, SecurityLevel::TOY, 128, 64);       // N = 2048
    add(Circuit::Sqrt, SecurityLevel::TOY, 256, 64);       // N = 4096
    add(Circuit::Sqrt, SecurityLevel::TOY, 512, 64);       // N = 8192
    // bench_crossover runs its full 5x5 grid at TOY too (it does not use
    // QuickSweep), so the sqrt encoding reaches these dimensions there.
    add(Circuit::Sqrt, SecurityLevel::TOY, 256, 1024);     // N = 16384
    add(Circuit::Sqrt, SecurityLevel::TOY, 512, 1024);     // N = 32768
    add(Circuit::Sqrt, SecurityLevel::STD128, 256, 64);    // N = 8192
    add(Circuit::Sqrt, SecurityLevel::STD128, 512, 64);    // N = 8192
    add_large(Circuit::Sqrt, SecurityLevel::STD128, 256, 256);   // N = 8192
    // The paper's ciphertext-size comparison includes (512, 256), and
    // bench_crossover sweeps m up to 1024; both land above N = 8192, so the
    // table has to cover them or Phase 1's lookup throws on the paper's own
    // configuration.
    add_large(Circuit::Sqrt, SecurityLevel::STD128, 512, 256);   // N = 16384
    add_large(Circuit::Sqrt, SecurityLevel::STD128, 512, 1024);  // N = 32768

    // --- threshold: depth is set by Paterson-Stockmeyer over degree k ---
    // TOY threshold: the unit tests drive k in {4, 8, 16, 32, 64} at m = 8,
    // which all land on ring_dim 1024 but with natural depths 4, 5, 7, 9 and
    // 12. The table is keyed on that depth, so each one needs its own row or
    // Validate() fails closed and the suite cannot run.
    add(Circuit::Threshold, SecurityLevel::TOY, 4, 8);
    add(Circuit::Threshold, SecurityLevel::TOY, 8, 8);
    add(Circuit::Threshold, SecurityLevel::TOY, 16, 8);
    add(Circuit::Threshold, SecurityLevel::TOY, 32, 8);
    add(Circuit::Threshold, SecurityLevel::TOY, 64, 8);
    add(Circuit::Threshold, SecurityLevel::TOY, 16, 64);
    add(Circuit::Threshold, SecurityLevel::TOY, 32, 64);
    // The threshold sweeps in bench_threshold reach natural depths 7, 9, 12, 15
    // and 21; each is a separate key because the table is keyed on that depth.
    add(Circuit::Threshold, SecurityLevel::STD128, 16, 64);   // depth 7
    add(Circuit::Threshold, SecurityLevel::STD128, 32, 64);   // depth 9
    add(Circuit::Threshold, SecurityLevel::STD128, 64, 64);   // depth 12
    add(Circuit::Threshold, SecurityLevel::TOY, 64, 64);      // depth 12, N = 4096
    add(Circuit::Threshold, SecurityLevel::TOY, 128, 16);     // depth 15, N = 2048
    add(Circuit::Threshold, SecurityLevel::TOY, 128, 32);     // depth 15, N = 4096
    add(Circuit::Threshold, SecurityLevel::TOY, 128, 64);     // depth 15, N = 8192
    add_large(Circuit::Threshold, SecurityLevel::STD128, 128, 64);   // depth 15
    add_large(Circuit::Threshold, SecurityLevel::STD128, 128, 128);  // depth 15, N = 16384
    add_large(Circuit::Threshold, SecurityLevel::STD128, 128, 256);  // depth 15, N = 32768
    add_large(Circuit::Threshold, SecurityLevel::TOY, 128, 128);     // depth 15, N = 16384
    add_large(Circuit::Threshold, SecurityLevel::TOY, 128, 256);     // depth 15, N = 32768
    // Natural depth 21 (threshold k=256). Feasible only at provisioned depth
    // 22, which bench_threshold's own `mult_depth > 21` guard then rejects --
    // that guard was written against pre-flooding semantics. Calibrated anyway
    // so the library supports the configuration; see 3_noise-flooding.md
    // section 8 for the guard that has to be re-tuned by threshold-fpfn.
    add_large(Circuit::Threshold, SecurityLevel::STD128, 256, 64);   // depth 21
    add_large(Circuit::Threshold, SecurityLevel::TOY, 256, 64);      // depth 21

    return grid;
}


// ============================================================================
// Coverage check
// ============================================================================

/// Report every (circuit, security, ring_dim, natural_depth) key that the test
/// suite or a benchmark sweep constructs but the calibration table does not
/// cover, so Validate() would fail closed on it.
///
/// This mirrors the sweeps in the benchmark sources; when one of those changes,
/// this has to change with it. It is the instrument that certifies the table is
/// complete, so getting the sweeps wrong here reports a clean bill of health
/// that is not real -- QuickSweep in particular trims TOY sweeps to their two
/// smallest points, while bench_crossover does not use it at all and runs its
/// full grid at every security level.
static int ReportCoverage() {
    struct Missing { std::string who; std::string key; };
    std::vector<Missing> missing;
    uint32_t checked = 0;

    auto probe = [&](const char* who, Circuit c, SecurityLevel sec,
                     uint32_t k, uint32_t m) {
        checked++;
        PiccardParams p;
        p.k = k;
        p.m = m;
        p.security = sec;
        if (c == Circuit::Threshold) {
            p.threshold_mode = true;
            p.threshold_tau = k / 2;
        }
        try {
            if (c == Circuit::Sqrt) p.ValidateSqrt(); else p.Validate();
        } catch (const std::exception& e) {
            std::string w = e.what();
            auto at = w.find("no noise calibration for ");
            if (at == std::string::npos) return;   // a domain error, not coverage
            auto end = w.find(';', at);
            missing.push_back({who, w.substr(at + 24, end - at - 24)});
        }
    };

    const auto TOY = SecurityLevel::TOY;
    const auto STD = SecurityLevel::STD128;

    for (auto sec : {TOY, STD}) {
        // bench_piccard / bench_comparison / bench_dynamic: k x m, one-hot.
        for (uint32_t k : piccard::benchmark::QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, sec))
            for (uint32_t m : piccard::benchmark::QuickSweep<uint32_t>({16, 32, 64, 128, 256}, sec))
                probe("piccard/comparison/dynamic", Circuit::OneHot, sec, k, m);

        // bench_onehot_sqrt: k sweep at m=64, m sweep at k=128, both encodings.
        for (uint32_t k : {16u, 32u, 64u, 128u, 256u, 512u}) {
            probe("onehot_sqrt", Circuit::OneHot, sec, k, 64);
            probe("onehot_sqrt", Circuit::Sqrt, sec, k, 64);
        }
        for (uint32_t m : {4u, 16u, 64u, 256u}) {
            probe("onehot_sqrt", Circuit::OneHot, sec, 128, m);
            probe("onehot_sqrt", Circuit::Sqrt, sec, 128, m);
        }

        // bench_crossover: full 5x5 grid, no QuickSweep, both encodings.
        for (uint32_t k : {32u, 64u, 128u, 256u, 512u})
            for (uint32_t m : {4u, 16u, 64u, 256u, 1024u}) {
                probe("crossover", Circuit::OneHot, sec, k, m);
                probe("crossover", Circuit::Sqrt, sec, k, m);
            }

        // bench_threshold: k sweep and m sweep, both QuickSwept.
        for (uint32_t k : piccard::benchmark::QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, sec))
            probe("threshold", Circuit::Threshold, sec, k, 64);
        for (uint32_t m : piccard::benchmark::QuickSweep<uint32_t>({16, 32, 64, 128, 256}, sec))
            probe("threshold", Circuit::Threshold, sec, 128, m);
    }

    // Unit and integration tests.
    probe("tests", Circuit::OneHot, TOY, 16, 8);
    probe("tests", Circuit::OneHot, TOY, 64, 16);
    probe("tests", Circuit::OneHot, TOY, 16, 64);
    probe("tests", Circuit::OneHot, TOY, 128, 64);
    probe("tests", Circuit::OneHot, STD, 128, 64);
    probe("tests", Circuit::OneHot, STD, 256, 64);
    probe("tests", Circuit::Sqrt, TOY, 16, 64);
    for (uint32_t k : {4u, 8u, 16u, 32u, 64u})
        probe("tests", Circuit::Threshold, TOY, k, 8);

    std::map<std::string, std::string> by_key;   // key -> constructors
    for (const auto& m : missing) {
        auto& who = by_key[m.key];
        if (who.find(m.who) == std::string::npos) {
            who += (who.empty() ? "" : ", ") + m.who;
        }
    }

    std::cout << "checked " << checked << " configurations, "
              << by_key.size() << " uncalibrated key(s)\n";
    for (const auto& [key, who] : by_key) {
        std::cout << "  " << key << "   <- " << who << "\n";
    }
    return by_key.empty() ? 0 : 1;
}

static int ReportPreThresholdCoverage() {
    const auto matrix = piccard::noise_profile::CompileMatrix(
        piccard::benchmark::noise_calibration::CurrentOpenFHEVersion(),
        piccard::benchmark::noise_calibration::EmbeddedSourceCommit());
    std::vector<PreThresholdCalibrationRequest> required;
    std::vector<PreThresholdCalibrationRequest> accepted_infeasible;
    required.reserve(matrix.size());
    for (const auto& partition : matrix) {
        const SecurityLevel security =
            partition.security == "STD192"
                ? SecurityLevel::STD192
                : SecurityLevel::STD128;
        PreThresholdCalibrationRequest request{
            partition.profile_id,
            partition.circuit,
            partition.shape_id,
            security,
            partition.requested_ring_dim,
            partition.natural_depth,
            partition.consumer_set_sha256,
            partition.openfhe_version,
        };
        required.push_back(request);
        if (partition.profile_id == "feasibility128") {
            accepted_infeasible.push_back(request);
        }
    }
    const auto coverage = InspectPreThresholdCalibrationCoverage(
        required, accepted_infeasible);
    if (!coverage.active) {
        std::cout << "V2 table coverage inactive; current calibration table "
                     "remains authoritative\n";
        return 0;
    }
    std::cout << "V2 table coverage required=" << coverage.required
              << " selected=" << coverage.selected
              << " infeasible=" << coverage.infeasible
              << " missing=" << coverage.missing_required << "\n";
    return coverage.missing_required == 0 ? 0 : 1;
}

static std::string ReadBytes(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("failed to open " + path);
    }
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

static std::string JsonString(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char ch : value) {
        switch (ch) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    out << "\\u00" << std::hex << std::setw(2)
                        << std::setfill('0') << static_cast<int>(ch)
                        << std::dec << std::setfill(' ');
                } else {
                    out << static_cast<char>(ch);
                }
        }
    }
    out << '"';
    return out.str();
}

static piccard::benchmark::noise_calibration::EvidenceIdentity
BuildEvidenceIdentity(
    const piccard::benchmark::noise_calibration::EvidenceOptions& options) {
    piccard::benchmark::noise_calibration::EvidenceIdentity identity;
    identity.profile_id = options.profile;
    identity.key_id = options.key_id;
    identity.circuit = options.circuit;
    identity.shape_id = options.shape_id;
    identity.security = options.security;
    identity.requested_ring_dim = options.requested_ring_dim;
    identity.natural_depth = options.natural_depth;
    identity.consumer_points = options.consumer_points;
    identity.consumer_set_sha256 = options.consumer_set_sha256;
    identity.openfhe_version = options.openfhe_version;
    identity.source_commit = options.source_commit;
    return identity;
}

static Circuit ParseEvidenceCircuit(const std::string& value) {
    if (value == "onehot") {
        return Circuit::OneHot;
    }
    if (value == "sqrt") {
        return Circuit::Sqrt;
    }
    throw std::invalid_argument("evidence circuit must be onehot or sqrt");
}

static SecurityLevel ParseEvidenceSecurity(const std::string& value) {
    if (value == "STD128") {
        return SecurityLevel::STD128;
    }
    if (value == "STD192") {
        return SecurityLevel::STD192;
    }
    throw std::invalid_argument("evidence security must be STD128 or STD192");
}

static std::string PreflightJson(
    const piccard::benchmark::noise_calibration::EvidenceOptions& options,
    uint32_t natural_ring_dim) {
    std::ostringstream output;
    output
        << "{\"source_commit\":\"" << options.source_commit
        << "\",\"openfhe_version\":\"" << options.openfhe_version
        << "\",\"key_id\":\"" << options.key_id
        << "\",\"profile_id\":\"" << options.profile
        << "\",\"circuit\":\"" << options.circuit
        << "\",\"shape_id\":\"" << options.shape_id
        << "\",\"security\":\"" << options.security
        << "\",\"requested_ring_dim\":" << options.requested_ring_dim
        << ",\"natural_depth\":" << options.natural_depth
        << ",\"consumer_set_sha256\":\""
        << options.consumer_set_sha256
        << "\",\"natural_ring_dim\":" << natural_ring_dim
        << "}\n";
    return output.str();
}

static int RunPreflightContext(
    const piccard::benchmark::noise_calibration::EvidenceOptions& options) {
    namespace nc = piccard::benchmark::noise_calibration;
    const std::string manifest = ReadBytes(options.profile_manifest);
    nc::ValidateEvidenceIdentity(BuildEvidenceIdentity(options), manifest);
    const Circuit circuit = ParseEvidenceCircuit(options.circuit);
    const SecurityLevel security =
        ParseEvidenceSecurity(options.security);
    const auto& representative = options.consumer_points.front();
    PiccardParams derived = BuildParams(
        circuit,
        security,
        representative.k,
        representative.m,
        0,
        0,
        false);
    if (derived.ring_dim != options.requested_ring_dim ||
        derived.natural_mult_depth != options.natural_depth) {
        throw std::invalid_argument(
            "preflight production derivation disagrees with logical key");
    }
    const uint32_t natural_ring_dim =
        DiscoverNaturalRingDimensionContextOnly(
            circuit,
            security,
            representative.k,
            representative.m);
    std::cout << PreflightJson(options, natural_ring_dim);
    return 0;
}

static piccard::benchmark::noise_calibration::DetailRow ToDetailRow(
    const piccard::benchmark::noise_calibration::EvidenceOptions& options,
    const std::string& candidate_id,
    const piccard::noise_profile::ConsumerPoint& consumer,
    const std::string& pattern,
    uint32_t rep_index,
    uint64_t rep_seed,
    uint32_t natural_ring_dim,
    uint32_t calibrated_ring_dim,
    uint32_t provisioned_depth,
    const CalibResult& result) {
    namespace nc = piccard::benchmark::noise_calibration;
    nc::DetailRow row;
    row.profile = options.profile;
    row.key_id = options.key_id;
    row.candidate_id = candidate_id;
    row.circuit = options.circuit;
    row.shape_id = options.shape_id;
    row.security = options.security;
    row.consumer_k = consumer.k;
    row.consumer_m = consumer.m;
    row.pattern = pattern;
    row.rep_index = rep_index;
    row.rep_seed = rep_seed;
    row.requested_ring_dim = options.requested_ring_dim;
    row.natural_ring_dim = natural_ring_dim;
    row.ring_dim_calibrated = calibrated_ring_dim;
    row.realized_ring_dim =
        result.ok ? result.ring_dim : calibrated_ring_dim;
    row.ring_growth_factor =
        static_cast<double>(calibrated_ring_dim) /
        static_cast<double>(natural_ring_dim);
    row.natural_depth = options.natural_depth;
    row.provisioned_depth = provisioned_depth;
    row.scaling_mod_size = result.scaling_mod_size;
    row.max_queries = options.max_queries;
    row.flood_margin_bits = options.margin;
    row.openfhe_version = options.openfhe_version;
    row.source_commit = options.source_commit;
    if (!result.ok) {
        row.status_code = nc::StatusCode::ContextError;
        row.error_message = result.error;
        return row;
    }
    row.num_limbs = result.num_limbs;
    row.plaintext_mod = result.plaintext_mod;
    row.log_q = result.log_q;
    row.log_delta = result.log_delta;
    row.eval_noise_bits = result.eval_noise_bits;
    row.headroom_bits = result.headroom_bits;
    row.decrypt_ok = result.decrypt_ok;
    row.saturated = result.saturated;
    row.ct_bytes = result.ct_bytes;
    if (!result.decrypt_ok) {
        row.status_code = nc::StatusCode::DecryptFail;
        row.error_message = "decryption result mismatch";
    } else if (result.saturated) {
        row.status_code = nc::StatusCode::Saturated;
        row.error_message = "noise measurement saturated";
    }
    const SanitizerProfile profile = DeriveSanitizerProfile(
        options.transcript_stat_bits,
        options.max_queries,
        result.ring_dim,
        static_cast<uint32_t>(std::ceil(result.eval_noise_bits)),
        options.margin);
    row.query_stat_bits = profile.query_stat_bits;
    row.coefficient_stat_bits = profile.coefficient_stat_bits;
    row.flood_noise_bits = profile.flood_noise_bits;
    return row;
}

static int RunStrictEvidence(
    const piccard::benchmark::noise_calibration::EvidenceOptions& options) {
    namespace fs = std::filesystem;
    namespace nc = piccard::benchmark::noise_calibration;
    const std::string manifest = ReadBytes(options.profile_manifest);
    nc::ValidateEvidenceIdentity(BuildEvidenceIdentity(options), manifest);
    const Circuit circuit = ParseEvidenceCircuit(options.circuit);
    const SecurityLevel security =
        ParseEvidenceSecurity(options.security);
    const auto& representative = options.consumer_points.front();
    uint32_t candidate_max_k = 0;
    for (const auto& consumer : options.consumer_points) {
        candidate_max_k = std::max(candidate_max_k, consumer.k);
    }
    if (candidate_max_k == 0) {
        throw std::invalid_argument(
            "pre-threshold candidate requires a positive consumer k");
    }
    const uint32_t natural_ring_dim =
        DiscoverNaturalRingDimensionContextOnly(
            circuit,
            security,
            representative.k,
            representative.m);
    const ExplicitRingCandidateSet ring_set = BuildExplicitRingCandidateSet(
        ExplicitRingCandidateRequest{
            options.profile,
            security,
            natural_ring_dim,
            options.ring_candidates,
        },
        options.transcript_stat_bits,
        options.max_queries,
        options.margin);
    if (!fs::is_directory(options.detail_dir)) {
        throw std::invalid_argument(
            "--detail_dir must name an existing directory");
    }

    std::ofstream aggregate_output(
        options.aggregate_csv, std::ios::binary | std::ios::trunc);
    if (!aggregate_output.is_open()) {
        throw std::runtime_error("failed to open aggregate CSV");
    }
    aggregate_output << nc::AggregateCsvHeader() << '\n';

    std::vector<std::tuple<std::string, std::string, std::string, uint64_t>>
        candidate_records;
    for (uint32_t calibrated_ring_dim : ring_set.candidates) {
        for (uint32_t depth_delta = 0;
             depth_delta <= options.max_depth_delta;
             ++depth_delta) {
            for (uint32_t scaling_mod_size :
                 options.scaling_mod_grid) {
                const uint32_t provisioned_depth =
                    options.natural_depth + depth_delta;
                const std::string candidate_id =
                    "N" + std::to_string(calibrated_ring_dim) +
                    "-d" + std::to_string(provisioned_depth) +
                    "-s" + std::to_string(scaling_mod_size);
                std::vector<nc::DetailRow> details;
                for (const auto& consumer : options.consumer_points) {
                    for (const auto& pattern_spec : nc::StrictEvidencePatterns(
                             options.revision_pattern_taxonomy)) {
                        const Pattern pattern = pattern_spec.input;
                        const std::string& pattern_name = pattern_spec.label;
                        for (uint32_t rep = 0; rep < options.reps; ++rep) {
                            const uint64_t rep_seed =
                                nc::DeriveEvidenceSeed(
                                    options.seed,
                                    options.key_id,
                                    candidate_id,
                                    consumer.k,
                                    consumer.m,
                                    pattern_name,
                                    rep);
                            const auto measured =
                                RunWithStrictMeasurementCleanup([&] {
                                    return RunOne(
                                        circuit,
                                        security,
                                        consumer.k,
                                        consumer.m,
                                        depth_delta,
                                        scaling_mod_size,
                                        {pattern},
                                        rep_seed,
                                        1,
                                        natural_ring_dim,
                                        true,
                                        calibrated_ring_dim,
                                        candidate_max_k);
                                });
                            details.push_back(ToDetailRow(
                                options,
                                candidate_id,
                                consumer,
                                pattern_name,
                                rep,
                                rep_seed,
                                natural_ring_dim,
                                calibrated_ring_dim,
                                provisioned_depth,
                                measured.front()));
                        }
                    }
                }
                details = nc::CanonicalizeDetailRows(std::move(details));
                const fs::path detail_path =
                    fs::path(options.detail_dir) /
                    (candidate_id + ".csv");
                std::ofstream detail_output(
                    detail_path, std::ios::binary | std::ios::trunc);
                if (!detail_output.is_open()) {
                    throw std::runtime_error(
                        "failed to open candidate detail CSV");
                }
                detail_output << nc::DetailCsvHeader() << '\n';
                for (const auto& detail : details) {
                    detail_output << nc::SerializeDetailCsvRow(detail)
                                  << '\n';
                }
                detail_output.close();

                nc::AggregateRow aggregate;
                aggregate.profile = options.profile;
                aggregate.circuit = options.circuit;
                aggregate.shape_id = options.shape_id;
                aggregate.security = options.security;
                aggregate.consumer_count =
                    static_cast<uint32_t>(
                        options.consumer_points.size());
                aggregate.consumer_set_sha256 =
                    options.consumer_set_sha256;
                aggregate.seed = options.seed;
                aggregate.requested_ring_dim =
                    options.requested_ring_dim;
                aggregate.natural_ring_dim = natural_ring_dim;
                aggregate.realized_ring_dim = calibrated_ring_dim;
                aggregate.ring_growth_factor =
                    static_cast<double>(calibrated_ring_dim) /
                    static_cast<double>(natural_ring_dim);
                aggregate.ring_dim_calibrated =
                    calibrated_ring_dim;
                aggregate.natural_depth = options.natural_depth;
                aggregate.provisioned_depth = provisioned_depth;
                aggregate.scaling_mod_size = scaling_mod_size;
                if (!details.empty()) {
                    aggregate.num_limbs = details.front().num_limbs;
                    aggregate.plaintext_mod = details.front().plaintext_mod;
                    aggregate.log_q = details.front().log_q;
                    aggregate.log_delta = details.front().log_delta;
                }
                aggregate.max_queries = options.max_queries;
                aggregate.flood_margin_bits = options.margin;
                aggregate.openfhe_version = options.openfhe_version;
                aggregate.source_commit = options.source_commit;
                aggregate = nc::ReduceCandidate(
                    std::move(aggregate),
                    details,
                    options.transcript_stat_bits);
                aggregate_output
                    << nc::SerializeAggregateCsvRow(aggregate) << '\n';
                candidate_records.emplace_back(
                    candidate_id,
                    nc::StatusName(aggregate.status_code),
                    aggregate.detail_sha256,
                    aggregate.detail_row_count);
            }
        }
    }
    aggregate_output.close();

    std::ofstream candidate_manifest(
        options.candidate_manifest,
        std::ios::binary | std::ios::trunc);
    if (!candidate_manifest.is_open()) {
        throw std::runtime_error("failed to open candidate manifest");
    }
    candidate_manifest
        << "{\"schema\":\"piccard-candidate-manifest\","
        << "\"version\":1,\"key_id\":\"" << options.key_id
        << "\",\"source_commit\":\"" << options.source_commit
        << "\",\"openfhe_version\":\"" << options.openfhe_version
        << "\",\"profile_id\":\"" << options.profile
        << "\",\"circuit\":\"" << options.circuit
        << "\",\"shape_id\":\"" << options.shape_id
        << "\",\"security\":\"" << options.security
        << "\",\"requested_ring_dim\":" << options.requested_ring_dim
        << ",\"natural_depth\":" << options.natural_depth
        << ",\"consumer_points\":[";
    for (size_t index = 0; index < options.consumer_points.size(); ++index) {
        candidate_manifest
            << "{\"k\":" << options.consumer_points[index].k
            << ",\"m\":" << options.consumer_points[index].m << "}";
        if (index + 1 != options.consumer_points.size()) {
            candidate_manifest << ',';
        }
    }
    candidate_manifest
        << "],\"consumer_set_sha256\":\""
        << options.consumer_set_sha256 << "\",\"command\":[";
    for (size_t index = 0; index < options.command.size(); ++index) {
        candidate_manifest << JsonString(options.command[index]);
        if (index + 1 != options.command.size()) {
            candidate_manifest << ',';
        }
    }
    candidate_manifest
        << "],\"candidate_count\":" << candidate_records.size()
        << ",\"candidates\":[";
    for (size_t index = 0; index < candidate_records.size(); ++index) {
        const auto& [candidate_id, status, detail_hash, row_count] =
            candidate_records[index];
        candidate_manifest
            << "{\"candidate_id\":\"" << candidate_id
            << "\",\"status_code\":\"" << status
            << "\",\"detail_sha256\":\"" << detail_hash
            << "\",\"detail_row_count\":" << row_count << "}";
        if (index + 1 != candidate_records.size()) {
            candidate_manifest << ',';
        }
    }
    candidate_manifest << "]}\n";
    return 0;
}

static void RequireProbe(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

static int RunDetailIdentityProbe() {
    namespace nc = piccard::benchmark::noise_calibration;
    nc::EvidenceOptions options;
    options.profile = "sensitivity64";
    options.key_id = "probe-key";
    options.circuit = "onehot";
    options.shape_id = "onehot-v1";
    options.security = "STD128";
    options.requested_ring_dim = 8192;
    options.natural_depth = 1;
    options.transcript_stat_bits = 64;
    options.max_queries = 1048576;
    options.margin = 8;
    options.openfhe_version = "probe-openfhe";
    options.source_commit = "probe-source";

    const piccard::noise_profile::ConsumerPoint consumer{16, 8};
    const std::string candidate_id = "N8192-d2-s60";
    const std::string pattern = "random";
    constexpr uint32_t rep_index = 0;
    constexpr uint64_t rep_seed = 20260729;
    constexpr uint32_t natural_ring_dim = 8192;
    constexpr uint32_t calibrated_ring_dim = 8192;
    constexpr uint32_t provisioned_depth = 2;

    CalibResult failed_result;
    failed_result.scaling_mod_size = 60;
    failed_result.ok = false;
    failed_result.error = "probe context error";
    const nc::DetailRow failed = ToDetailRow(
        options,
        candidate_id,
        consumer,
        pattern,
        rep_index,
        rep_seed,
        natural_ring_dim,
        calibrated_ring_dim,
        provisioned_depth,
        failed_result);
    RequireProbe(failed.profile == "sensitivity64",
                 "failed profile moved");
    RequireProbe(failed.key_id == "probe-key",
                 "failed key id moved");
    RequireProbe(failed.candidate_id == "N8192-d2-s60",
                 "failed candidate id moved");
    RequireProbe(failed.circuit == "onehot",
                 "failed circuit moved");
    RequireProbe(failed.shape_id == "onehot-v1",
                 "failed shape id moved");
    RequireProbe(failed.security == "STD128",
                 "failed security moved");
    RequireProbe(failed.consumer_k == 16 && failed.consumer_m == 8,
                 "failed consumer moved");
    RequireProbe(failed.pattern == "random",
                 "failed pattern moved");
    RequireProbe(failed.rep_index == 0 && failed.rep_seed == 20260729,
                 "failed repetition identity moved");
    RequireProbe(failed.requested_ring_dim == 8192,
                 "failed requested ring moved");
    RequireProbe(failed.natural_ring_dim == 8192,
                 "failed natural ring moved");
    RequireProbe(failed.ring_dim_calibrated == 8192,
                 "failed calibrated ring moved");
    RequireProbe(failed.realized_ring_dim == 8192,
                 "failed realized ring moved");
    RequireProbe(failed.natural_depth == 1,
                 "failed natural depth moved");
    RequireProbe(failed.provisioned_depth == 2,
                 "failed provisioned depth was not candidate depth");
    RequireProbe(failed.scaling_mod_size == 60,
                 "failed scaling modulus moved");
    RequireProbe(failed.openfhe_version == "probe-openfhe",
                 "failed OpenFHE provenance moved");
    RequireProbe(failed.source_commit == "probe-source",
                 "failed source provenance moved");
    RequireProbe(failed.status_code == nc::StatusCode::ContextError,
                 "failed status was not CONTEXT_ERROR");
    RequireProbe(failed.error_message == "probe context error",
                 "failed error moved");

    CalibResult success_result;
    success_result.ok = true;
    success_result.ring_dim = 16384;
    success_result.mult_depth = 2;
    success_result.scaling_mod_size = 60;
    success_result.num_limbs = 5;
    success_result.plaintext_mod = 65537;
    success_result.log_q = 301.25;
    success_result.log_delta = 285.5;
    success_result.eval_noise_bits = 23.25;
    success_result.headroom_bits = 261.25;
    success_result.decrypt_ok = true;
    success_result.saturated = false;
    success_result.ct_bytes = 12345;
    const nc::DetailRow success = ToDetailRow(
        options,
        candidate_id,
        consumer,
        pattern,
        rep_index,
        rep_seed,
        natural_ring_dim,
        calibrated_ring_dim,
        provisioned_depth,
        success_result);
    RequireProbe(success.profile == "sensitivity64",
                 "success profile moved");
    RequireProbe(success.key_id == "probe-key",
                 "success key id moved");
    RequireProbe(success.candidate_id == "N8192-d2-s60",
                 "success candidate id moved");
    RequireProbe(success.circuit == "onehot",
                 "success circuit moved");
    RequireProbe(success.shape_id == "onehot-v1",
                 "success shape id moved");
    RequireProbe(success.security == "STD128",
                 "success security moved");
    RequireProbe(success.consumer_k == 16 && success.consumer_m == 8,
                 "success consumer moved");
    RequireProbe(success.pattern == "random",
                 "success pattern moved");
    RequireProbe(success.rep_index == 0 && success.rep_seed == 20260729,
                 "success repetition identity moved");
    RequireProbe(success.requested_ring_dim == 8192,
                 "success requested ring moved");
    RequireProbe(success.natural_ring_dim == 8192,
                 "success natural ring moved");
    RequireProbe(success.ring_dim_calibrated == 8192,
                 "success calibrated ring moved");
    RequireProbe(success.realized_ring_dim == 16384,
                 "success realized ring no longer uses result");
    RequireProbe(success.ring_growth_factor == 1.0,
                 "success ring growth factor moved");
    RequireProbe(success.natural_depth == 1,
                 "success natural depth moved");
    RequireProbe(success.provisioned_depth == 2,
                 "success provisioned depth moved");
    RequireProbe(success.scaling_mod_size == 60,
                 "success scaling modulus moved");
    RequireProbe(success.num_limbs == 5,
                 "success limb count moved");
    RequireProbe(success.plaintext_mod == 65537,
                 "success plaintext modulus moved");
    RequireProbe(success.log_q == 301.25,
                 "success log q moved");
    RequireProbe(success.log_delta == 285.5,
                 "success log delta moved");
    RequireProbe(success.eval_noise_bits == 23.25,
                 "success evaluation noise moved");
    RequireProbe(success.headroom_bits == 261.25,
                 "success headroom moved");
    RequireProbe(success.max_queries == 1048576,
                 "success max queries moved");
    RequireProbe(success.query_stat_bits == 84,
                 "success query statistical bits moved");
    RequireProbe(success.coefficient_stat_bits == 98,
                 "success coefficient statistical bits moved");
    RequireProbe(success.flood_margin_bits == 8,
                 "success flooding margin moved");
    RequireProbe(success.flood_noise_bits == 130,
                 "success flooding noise bits moved");
    RequireProbe(success.decrypt_ok,
                 "success decrypt flag moved");
    RequireProbe(!success.saturated,
                 "success saturation flag moved");
    RequireProbe(success.ct_bytes == 12345,
                 "success ciphertext size moved");
    RequireProbe(success.openfhe_version == "probe-openfhe",
                 "success OpenFHE provenance moved");
    RequireProbe(success.source_commit == "probe-source",
                 "success source provenance moved");
    RequireProbe(success.status_code == nc::StatusCode::Ok,
                 "success status was not OK");
    RequireProbe(success.error_message.empty(),
                 "success error was not empty");

    const std::string& header = nc::DetailCsvHeader();
    const std::string failed_csv = nc::SerializeDetailCsvRow(failed);
    const std::string success_csv = nc::SerializeDetailCsvRow(success);
    const auto header_commas = std::count(header.begin(), header.end(), ',');
    RequireProbe(
        std::count(failed_csv.begin(), failed_csv.end(), ',') ==
            header_commas,
        "failed CSV field count moved");
    RequireProbe(
        std::count(success_csv.begin(), success_csv.end(), ',') ==
            header_commas,
        "success CSV field count moved");

    std::cout
        << "detail identity probe passed: failed_depth=2 success_depth=2\n";
    return 0;
}

static int RunStrictCleanupProbe() {
    ClearStrictMeasurementOpenFHEState();
    RequireProbe(
        GetOpenFHEStaticStateCounts().IsEmpty(),
        "OpenFHE static state was not empty after initial cleanup");

    constexpr uint32_t probe_k = 16;
    constexpr uint32_t probe_m = 8;
    const uint32_t probe_ring_dim = std::max(
        NextPowerOf2(probe_k * probe_m),
        MinRingDimForSecurity(SecurityLevel::TOY));
    RequireProbe(probe_ring_dim == 1024,
                 "unexpected TOY probe ring dimension");

    for (uint32_t iteration = 0; iteration < 3; ++iteration) {
        const OpenFHEStaticStateCounts before =
            GetOpenFHEStaticStateCounts();
        RequireProbe(before.IsEmpty(),
                     "OpenFHE static state was not empty before wrapper");

        bool caught_expected_unwind = false;
        try {
            const auto rows = RunWithStrictMeasurementCleanup([&] {
                auto measured = RunOne(
                    Circuit::OneHot,
                    SecurityLevel::TOY,
                    probe_k,
                    probe_m,
                    0,
                    0,
                    {Pattern::AllMatch},
                    20260729 + iteration,
                    1,
                    probe_ring_dim,
                    true,
                    probe_ring_dim);
                const OpenFHEStaticStateCounts inside =
                    GetOpenFHEStaticStateCounts();
                RequireProbe(inside.mult > before.mult,
                             "eval-multiplication keys were not populated");
                RequireProbe(
                    inside.automorphism > before.automorphism,
                    "eval-automorphism keys were not populated");
                RequireProbe(inside.contexts > before.contexts,
                             "context registry was not populated");
                if (iteration == 2) {
                    throw std::runtime_error("probe unwind");
                }
                return measured;
            });

            RequireProbe(iteration != 2,
                         "exceptional probe did not unwind");
            RequireProbe(
                rows.size() == 1,
                "normal probe did not return exactly one row");
            RequireProbe(rows.front().ok, "normal probe row failed");
            RequireProbe(
                rows.front().decrypt_ok,
                "normal probe row did not decrypt");
            RequireProbe(
                rows.front().pre_threshold_evidence,
                "normal probe did not use strict evidence parameters");
        } catch (const std::runtime_error& error) {
            if (iteration != 2 ||
                std::string(error.what()) != "probe unwind") {
                throw;
            }
            caught_expected_unwind = true;
        }

        if (iteration == 2) {
            RequireProbe(caught_expected_unwind,
                         "exceptional probe did not catch expected unwind");
        }
        const OpenFHEStaticStateCounts after =
            GetOpenFHEStaticStateCounts();
        RequireProbe(after == before,
                     "OpenFHE static state changed across wrapper");
        RequireProbe(after.IsEmpty(),
                     "OpenFHE static state was not empty after wrapper");
    }

    std::cout << "strict cleanup probe passed: iterations=3\n";
    return 0;
}

static int RunCandidatePlaintextProbe() {
    constexpr uint32_t natural_ring_dim = 2048;
    constexpr uint32_t calibrated_ring_dim = 4096;
    constexpr uint32_t candidate_max_k = 32;
    constexpr uint64_t expected_natural_p = 12289;
    constexpr uint64_t expected_candidate_p = 40961;
    const std::vector<std::pair<uint32_t, uint32_t>> consumers{
        {16, 128},
        {32, 64},
    };

    std::vector<PiccardParams> grown;
    for (const auto& [consumer_k, consumer_m] : consumers) {
        PiccardParams natural = BuildParams(
            Circuit::OneHot,
            SecurityLevel::TOY,
            consumer_k,
            consumer_m,
            0,
            40,
            true,
            natural_ring_dim,
            natural_ring_dim,
            nullptr,
            candidate_max_k);
        RequireProbe(
            natural.plaintext_mod == expected_natural_p,
            "natural candidate plaintext modulus moved");

        PiccardParams candidate = BuildParams(
            Circuit::OneHot,
            SecurityLevel::TOY,
            consumer_k,
            consumer_m,
            0,
            40,
            true,
            natural_ring_dim,
            calibrated_ring_dim,
            nullptr,
            candidate_max_k);
        RequireProbe(
            candidate.plaintext_mod == expected_candidate_p,
            "grown candidate retained natural-ring plaintext modulus");
        grown.push_back(std::move(candidate));
    }

    RequireProbe(
        grown.size() == 2 &&
            grown.front().plaintext_mod == grown.back().plaintext_mod,
        "candidate plaintext modulus differs across consumers");
    RequireProbe(
        grown.front().plaintext_mod ==
            FindPlaintextModulus(
                candidate_max_k, 2 * calibrated_ring_dim),
        "candidate plaintext modulus differs from expected formula");
    RequireProbe(
        grown.front().plaintext_mod > candidate_max_k,
        "candidate plaintext modulus does not exceed maximum consumer k");
    RequireProbe(
        IsPrime(grown.front().plaintext_mod),
        "candidate plaintext modulus is not prime");
    RequireProbe(
        (grown.front().plaintext_mod - 1) %
                (UINT64_C(2) * calibrated_ring_dim) ==
            0,
        "candidate plaintext modulus is not compatible with calibrated ring");

    const uint64_t below_boundary =
        FindCandidatePlaintextModulus(576, 32);
    const uint64_t at_boundary =
        FindCandidatePlaintextModulus(577, 32);
    RequireProbe(
        below_boundary == 577 && at_boundary == 641 &&
            below_boundary != at_boundary,
        "candidate plaintext helper ignored its minimum argument");

    bool rejected_low_max = false;
    try {
        (void)BuildParams(
            Circuit::OneHot,
            SecurityLevel::TOY,
            32,
            64,
            0,
            40,
            true,
            natural_ring_dim,
            calibrated_ring_dim,
            nullptr,
            31);
    } catch (const std::invalid_argument& error) {
        rejected_low_max =
            std::string(error.what()) ==
            "candidate maximum consumer k is below current consumer k";
    }
    RequireProbe(
        rejected_low_max,
        "candidate builder accepted maximum k below current consumer k");

    BFVContext context(grown.back());
    context.Initialize();
    const auto ciphertext = context.Encrypt({1});
    const auto plaintext = context.Decrypt(ciphertext);
    RequireProbe(
        context.GetSlotCount() == calibrated_ring_dim,
        "probe did not realize calibrated ring");
    RequireProbe(
        !plaintext.empty() && plaintext.front() == 1,
        "packed encrypt/decrypt round trip failed");

    std::cout
        << "candidate plaintext probe passed: natural_N=2048 "
        << "natural_p=12289 calibrated_N=4096 candidate_p=40961 "
        << "consumers=2 helper_boundary=577->641 low_max_reject=OK "
        << "packed_encrypt=OK\n";
    return 0;
}

// ============================================================================
// Main
// ============================================================================

static void PrintUsage() {
    std::cout
        << "Usage: bench_noise [options]\n"
        << "  --coverage             List keys the tests/benchmarks need but the\n"
        << "                         table does not cover, then exit\n"
        << "  --pre_threshold        Strict OneHot/Sqrt STD128/STD192 evidence mode\n"
        << "  --profile_manifest=P   Profile-manifest path for evidence provenance\n"
        << "  --profile=ID           Exact evidence profile_id\n"
        << "  --key_id=ID            Logical calibration-key identifier\n"
        << "  --scaling_mod_grid=L   Comma-separated positive modulus sizes\n"
        << "  --max_depth_delta=N    Largest evidence depth delta\n"
        << "  --ring_candidates=L    Comma-separated power-of-two ring dimensions\n"
        << "  --timeout_seconds=N    Positive per-candidate timeout\n"
        << "  --transcript_stat_bits=N  Exactly 40, 64, or 128\n"
        << "  --max_queries=N        Inclusive evidence range 1..2^63\n"
        << "  --smoke                Permit fewer than five evidence repetitions\n"
        << "  --revision_pattern_taxonomy  Use zero/random/adversarial labels\n"
        << "  --sweep                Run the calibration grid (default: single point)\n"
        << "  --circuit=C            onehot | sqrt | threshold | all (default: all)\n"
        << "  --security=S           TOY | STD128 (single-point mode; default STD128)\n"
        << "  --k=N --m=N            Single-point parameters (default 128 / 64)\n"
        << "  --giant_step=MODE      horner (default) | tree giant step for the threshold circuit\n"
        << "  --depth_delta=N        Extra multiplicative depth over the circuit's own\n"
        << "  --sms=N                scaling_mod_size; 0 = OpenFHE default (60)\n"
        << "  --patterns=all|match   Input patterns to run (default: all)\n"
        << "  --target_lambda=N      Target lambda_s for the fit summary (default 64)\n"
        << "  --margin=N             Safety margin bits (default 8)\n"
        << "  --include_large        Include N >= 65536 and threshold k=128 (slow)\n"
        << "  --large_only           Run only those expensive configurations\n"
        << "  --max_delta=N          Largest extra depth to try in a sweep (default 2)\n"
        << "  --reps=N               Repeat each measurement under fresh encryption\n"
        << "                         randomness and keep the worst (default 1)\n"
        << "  --csv=PATH             Also write rows to PATH\n"
        << "  --seed=N               RNG seed for signature generation (default 20260725)\n"
        << "  --help, -h             This message\n";
}

int main(int argc, char** argv) {
    std::vector<std::string> raw_args;
    raw_args.reserve(static_cast<size_t>(std::max(argc - 1, 0)));
    for (int index = 1; index < argc; ++index) {
        raw_args.emplace_back(argv[index]);
    }
    if (raw_args.size() == 1 &&
        raw_args.front() == "--strict_cleanup_probe") {
        try {
            return RunStrictCleanupProbe();
        } catch (const std::exception& error) {
            std::cerr << "strict cleanup probe failed: "
                      << error.what() << '\n';
            return 1;
        }
    }
    if (raw_args.size() == 1 &&
        raw_args.front() == "--detail_identity_probe") {
        try {
            return RunDetailIdentityProbe();
        } catch (const std::exception& error) {
            std::cerr << "detail identity probe failed: "
                      << error.what() << '\n';
            return 1;
        }
    }
    if (raw_args.size() == 1 &&
        raw_args.front() == "--candidate_plaintext_probe") {
        try {
            return RunCandidatePlaintextProbe();
        } catch (const std::exception& error) {
            std::cerr << "candidate plaintext probe failed: "
                      << error.what() << '\n';
            return 1;
        }
    }
    if (raw_args.size() == 1 &&
        raw_args.front() == "--print_profile_manifest") {
        std::cout << piccard::noise_profile::CanonicalManifestJson();
        return 0;
    }
    if (raw_args.size() == 1 &&
        raw_args.front() == "--print_source_commit") {
        std::cout
            << piccard::benchmark::noise_calibration::EmbeddedSourceCommit()
            << '\n';
        return 0;
    }

    piccard::benchmark::noise_calibration::EvidenceOptions evidence;
    try {
        evidence =
            piccard::benchmark::noise_calibration::ParseEvidenceOptions(
                raw_args);
    } catch (const std::exception& error) {
        std::cerr << "Invalid pre-threshold evidence command: "
                  << error.what() << "\n";
        return 1;
    }
    if (evidence.pre_threshold && evidence.coverage) {
        return ReportPreThresholdCoverage();
    }
    if (evidence.preflight_context) {
        try {
            return RunPreflightContext(evidence);
        } catch (const std::exception& error) {
            std::cerr << "Preflight failed: " << error.what() << "\n";
            return 1;
        }
    }
    if (evidence.pre_threshold && !evidence.consumer_points.empty()) {
        try {
            return RunStrictEvidence(evidence);
        } catch (const std::exception& error) {
            std::cerr << "Evidence run failed: " << error.what() << "\n";
            return 1;
        }
    }

    bool sweep = false;
    bool include_large = false;
    bool large_only = false;
    uint32_t max_delta = 2;
    uint32_t reps = 1;
    bool all_patterns = true;
    std::string circuit_arg = "all";
    std::string csv_path;
    SecurityLevel security = SecurityLevel::STD128;
    uint32_t k = 128, m = 64;
    uint32_t depth_delta = 0, sms = 0;
    uint32_t target_lambda = 64, margin = 8;
    uint64_t seed = 20260725;

    if (evidence.pre_threshold) {
        circuit_arg = evidence.circuit;
        security = evidence.security == "STD192"
            ? SecurityLevel::STD192
            : SecurityLevel::STD128;
        max_delta = evidence.max_depth_delta;
        reps = evidence.reps;
        target_lambda = evidence.transcript_stat_bits;
        margin = evidence.margin;
        seed = evidence.seed;
        sms = evidence.scaling_mod_grid.front();
    } else {
        for (int i = 1; i < argc; i++) {
            std::string arg(argv[i]);
            if (arg == "--help" || arg == "-h") { PrintUsage(); return 0; }
            else if (arg == "--sweep") sweep = true;
            else if (arg == "--coverage") return ReportCoverage();
            else if (arg == "--include_large") include_large = true;
            else if (arg == "--large_only") large_only = true;
            else if (arg.rfind("--max_delta=", 0) == 0) max_delta = std::stoul(arg.substr(12));
            else if (arg.rfind("--reps=", 0) == 0) reps = std::stoul(arg.substr(7));
            else if (arg.rfind("--circuit=", 0) == 0) circuit_arg = arg.substr(10);
            else if (arg.rfind("--csv=", 0) == 0) csv_path = arg.substr(6);
            else if (arg.rfind("--k=", 0) == 0) k = std::stoul(arg.substr(4));
            else if (arg.rfind("--m=", 0) == 0) m = std::stoul(arg.substr(4));
            else if (arg.rfind("--depth_delta=", 0) == 0) depth_delta = std::stoul(arg.substr(14));
            else if (arg.rfind("--sms=", 0) == 0) sms = std::stoul(arg.substr(6));
            else if (arg.rfind("--target_lambda=", 0) == 0) target_lambda = std::stoul(arg.substr(16));
            else if (arg.rfind("--margin=", 0) == 0) margin = std::stoul(arg.substr(9));
            else if (arg.rfind("--seed=", 0) == 0) seed = std::stoull(arg.substr(7));
            else if (arg.rfind("--patterns=", 0) == 0) all_patterns = (arg.substr(11) == "all");
            else if (arg.rfind("--giant_step=", 0) == 0) {
                const std::string v = arg.substr(13);
                if (v == "horner") g_giant_step = GiantStepMode::Horner;
                else if (v == "tree") g_giant_step = GiantStepMode::Tree;
                else { std::cerr << "Invalid --giant_step: " << v << "\n"; return 1; }
            }
            else if (arg.rfind("--security=", 0) == 0) {
                std::string s = arg.substr(11);
                if (s == "TOY") security = SecurityLevel::TOY;
                else if (s == "STD128") security = SecurityLevel::STD128;
                else if (s == "STD192") security = SecurityLevel::STD192;
                else if (s == "STD256") security = SecurityLevel::STD256;
                else { std::cerr << "Invalid security level: " << s << "\n"; return 1; }
            } else {
                std::cerr << "Unknown argument: " << arg << "\n";
                PrintUsage();
                return 1;
            }
        }
    }

    std::vector<Circuit> circuits;
    if (circuit_arg == "all") {
        circuits = {Circuit::OneHot, Circuit::Sqrt, Circuit::Threshold};
    } else if (circuit_arg == "onehot") {
        circuits = {Circuit::OneHot};
    } else if (circuit_arg == "sqrt") {
        circuits = {Circuit::Sqrt};
    } else if (circuit_arg == "threshold") {
        circuits = {Circuit::Threshold};
    } else {
        std::cerr << "Invalid circuit: " << circuit_arg << "\n";
        return 1;
    }

    std::vector<Pattern> patterns = all_patterns
        ? std::vector<Pattern>{Pattern::AllMatch, Pattern::NoMatch, Pattern::Random}
        : std::vector<Pattern>{Pattern::AllMatch};

    std::ofstream csv;
    if (!csv_path.empty()) {
        csv.open(csv_path);
        if (!csv.is_open()) {
            std::cerr << "Failed to open CSV file: " << csv_path << "\n";
            return 1;
        }
        WriteCsvHeader(csv);
    }

    std::vector<CalibResult> results;

    auto record = [&](const std::vector<CalibResult>& rows) {
        for (const auto& r : rows) {
            results.push_back(r);
            PrintRow(r);
            if (csv.is_open()) WriteCsvRow(csv, r);
        }
        if (csv.is_open()) csv.flush();
        std::cout.flush();
    };

    std::cout << "Noise calibration harness (R2-W6)\n"
              << "  target lambda_s = " << target_lambda
              << ", margin = " << margin << " bits, seed = " << seed
              << ", reps = " << reps << "\n";

    if (!sweep) {
        std::cout << "\n=== single point ===\n";
        for (Circuit c : circuits) {
            if (evidence.pre_threshold) {
                try {
                    const uint32_t natural_ring_dim =
                        DiscoverNaturalRingDimension(c, security, k, m);
                    const ExplicitRingCandidateSet ring_set =
                        BuildExplicitRingCandidateSet(
                            ExplicitRingCandidateRequest{
                                evidence.profile,
                                security,
                                natural_ring_dim,
                                evidence.ring_candidates,
                            },
                            evidence.transcript_stat_bits,
                            evidence.max_queries,
                            evidence.margin);
                    for (uint32_t candidate : ring_set.candidates) {
                        record(RunOne(
                            c,
                            security,
                            k,
                            m,
                            0,
                            sms,
                            patterns,
                            seed,
                            reps,
                            natural_ring_dim,
                            true,
                            candidate));
                    }
                } catch (const std::exception& error) {
                    std::cerr
                        << "Invalid explicit ring candidate set: "
                        << error.what() << "\n";
                    return 1;
                }
                continue;
            }

            // Measure the circuit's own configuration first even here, so a
            // single point is judged against the same baseline the sweep uses.
            // Without it the threshold variant looks like it grew the ring when
            // the growth is its own modulus chain, not the flooding headroom.
            uint32_t baseline = 0;
            if (depth_delta != 0 || sms != 0) {
                for (const auto& r : RunOne(
                         c,
                         security,
                         k,
                         m,
                         0,
                         0,
                         patterns,
                         seed,
                         reps,
                         0,
                         evidence.pre_threshold)) {
                    if (r.ok) { baseline = r.ring_dim; break; }
                }
            }
            record(RunOne(c, security, k, m, depth_delta, sms, patterns, seed,
                          reps, baseline, evidence.pre_threshold));
        }
    } else {
        // OpenFHE rejects a limb layout whose total exceeds the security
        // table's max log q for the ring dimension, so infeasible cells throw
        // and are recorded as failures rather than silently skipped.
        // sms = 0 is OpenFHE's default (60-bit limbs) and is already covered
        // by the per-config baseline run below, so it is not repeated here.
        // 55 sits between 54 and 58 and never won a cell; dropping both keeps
        // the grid affordable at --reps=5, which the measurement needs to be
        // trustworthy near the feasibility boundary.
        const std::vector<uint32_t> sms_grid = {40, 45, 50, 52, 54, 58, 60};
        std::vector<uint32_t> delta_grid;
        for (uint32_t d = 0; d <= max_delta; d++) delta_grid.push_back(d);

        for (Circuit c : circuits) {
            std::cout << "\n=== sweep: " << CircuitName(c) << " ===\n";
            for (const GridEntry& g : BuildGrid(c, include_large, large_only)) {
                // Establish the circuit's own ring dimension first: natural
                // depth, OpenFHE's default limb size, no flooding headroom.
                // Everything else is judged against this.
                auto base_rows = RunOne(
                    c,
                    g.security,
                    g.k,
                    g.m,
                    0,
                    0,
                    patterns,
                    seed,
                    reps,
                    0,
                    evidence.pre_threshold);
                uint32_t baseline = 0;
                for (const auto& r : base_rows) {
                    if (r.ok) { baseline = r.ring_dim; break; }
                }
                if (baseline == 0) {
                    // Without a baseline every later cell would be measured
                    // against the slot requirement instead of the circuit's own
                    // dimension, which is exactly the comparison this pass
                    // exists to avoid. Skip the group rather than record rows
                    // that look authoritative and are not.
                    std::cout << "  *** baseline failed for " << CircuitName(c)
                              << " (" << g.k << "," << g.m << ") -- group skipped\n";
                    record(base_rows);
                    continue;
                }
                for (auto& r : base_rows) {
                    if (baseline) {
                        r.ring_dim_baseline = baseline;
                        r.ring_dim_grew = false;
                    }
                }
                record(base_rows);

                for (uint32_t d : delta_grid) {
                    for (uint32_t s : sms_grid) {
                        if (d == 0 && s == 0) continue;   // already measured
                        record(RunOne(c, g.security, g.k, g.m, d, s, patterns, seed,
                                      reps, baseline, evidence.pre_threshold));
                    }
                }
            }
        }
    }

    // ── Summary: cheapest feasible (depth, sms) per (circuit, N) ────────
    //
    // "Cheapest" means smallest log q, since ciphertext size and per-operation
    // cost both track it. The fit test is the plan's Validate() inequality:
    //     eval_noise_bits + margin + target_lambda + 2 <= log_delta
    // evaluated against the WORST pattern measured for that cell, so a cell
    // only qualifies if every input pattern clears it.
    std::cout << "\n=== summary: cheapest feasible cell per (circuit, N) "
              << "for lambda_s=" << target_lambda << " + margin=" << margin << " ===\n";

    struct Cell {
        double worst_noise = -1.0;
        double log_delta = 0.0;
        double log_q = 0.0;
        uint32_t depth = 0, sms = 0, limbs = 0;
        bool all_decrypt_ok = true;
        bool ring_dim_grew = false;
        bool saturated = false;
    };
    // key: circuit | ring_dim | depth | sms
    std::map<std::string, Cell> cells;
    for (const auto& r : results) {
        if (!r.ok) continue;
        std::ostringstream key;
        key << r.circuit << "|" << std::setw(7) << std::setfill('0') << r.ring_dim
            << "|" << std::setw(3) << r.mult_depth << "|" << std::setw(3) << r.scaling_mod_size;
        Cell& cell = cells[key.str()];
        cell.worst_noise = std::max(cell.worst_noise, r.eval_noise_bits);
        cell.log_delta = r.log_delta;
        cell.log_q = r.log_q;
        cell.depth = r.mult_depth;
        cell.sms = r.scaling_mod_size;
        cell.limbs = r.num_limbs;
        cell.all_decrypt_ok = cell.all_decrypt_ok && r.decrypt_ok;
        cell.ring_dim_grew = cell.ring_dim_grew || r.ring_dim_grew;
        cell.saturated = cell.saturated || r.saturated;
    }

    std::map<std::string, std::pair<std::string, Cell>> best;  // circuit|N -> cell
    for (const auto& [key, cell] : cells) {
        if (!cell.all_decrypt_ok || cell.saturated) continue;
        // Buying flooding headroom by doubling N is not a win: it doubles every
        // timing in the paper. Such cells are excluded from "feasible".
        if (cell.ring_dim_grew) continue;
        double need = cell.worst_noise + margin + target_lambda + 2.0;
        if (need > cell.log_delta) continue;
        std::string group = key.substr(0, key.find('|', key.find('|') + 1));
        auto it = best.find(group);
        // Cheapest means smallest log q. Ties are common and not cosmetic:
        // the same total modulus split into more, smaller limbs carries far
        // less key-switching noise (sqrt at N=1024 differs by 20 bits between
        // two log q = 200 layouts), so break ties on the quieter cell.
        bool better = (it == best.end()) ||
                      (cell.log_q < it->second.second.log_q) ||
                      (cell.log_q == it->second.second.log_q &&
                       cell.worst_noise < it->second.second.worst_noise);
        if (better) {
            best[group] = {key, cell};
        }
    }

    for (const auto& [group, entry] : best) {
        const Cell& cell = entry.second;
        std::cout << "  " << std::left << std::setw(22) << group << std::right
                  << "  depth=" << std::setw(3) << cell.depth
                  << " sms=" << std::setw(3) << cell.sms
                  << " logq=" << std::fixed << std::setprecision(1) << std::setw(6) << cell.log_q
                  << " limbs=" << std::setw(2) << cell.limbs
                  << " worst B_eval=" << std::setprecision(2) << std::setw(7) << cell.worst_noise
                  << " spare=" << std::setw(6)
                  << (cell.log_delta - cell.worst_noise - margin - target_lambda - 2.0)
                  << "\n";
    }

    // Report groups that produced no feasible cell -- these are the ones that
    // need a user decision (plan section 4).
    std::vector<std::string> groups_seen;
    for (const auto& [key, cell] : cells) {
        (void)cell;
        std::string group = key.substr(0, key.find('|', key.find('|') + 1));
        if (std::find(groups_seen.begin(), groups_seen.end(), group) == groups_seen.end()) {
            groups_seen.push_back(group);
        }
    }
    bool any_infeasible = false;
    for (const auto& group : groups_seen) {
        if (best.find(group) == best.end()) {
            if (!any_infeasible) {
                std::cout << "\n  *** NO FEASIBLE CELL (needs a parameter decision) ***\n";
                any_infeasible = true;
            }
            // Report the best headroom actually achieved, to size the shortfall.
            double best_spare = -1e9;
            uint32_t bd = 0, bs = 0;
            for (const auto& [key, cell] : cells) {
                if (key.rfind(group, 0) != 0) continue;
                if (!cell.all_decrypt_ok || cell.ring_dim_grew || cell.saturated) continue;
                double spare = cell.log_delta - cell.worst_noise - margin - target_lambda - 2.0;
                if (spare > best_spare) { best_spare = spare; bd = cell.depth; bs = cell.sms; }
            }
            std::cout << "  " << std::left << std::setw(22) << group << std::right;
            if (best_spare <= -1e8) {
                // Every cell in this group either failed to decrypt or bought
                // its headroom by growing the ring dimension.
                std::cout << "  no usable cell (all grew N or failed to decrypt)\n";
            } else {
                std::cout << "  short by " << std::fixed << std::setprecision(2)
                          << -best_spare << " bits (best: depth=" << bd
                          << " sms=" << bs << ")\n";
            }
        }
    }

    if (csv.is_open()) {
        std::cout << "\nWrote " << results.size() << " rows to " << csv_path << "\n";
    }
    return 0;
}
