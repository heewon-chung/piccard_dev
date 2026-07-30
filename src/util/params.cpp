#include "util/params.h"

#include "util/params_calibration.h"
#include "util/security_profile.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace piccard {

namespace {

/// One measured point of the noise calibration (R2-W6 / roadmap P1-3).
///
/// `eval_noise_bits` is the ceiling of the worst decryption noise observed for
/// this cell across the all_match / no_match / random input patterns and five
/// repetitions under fresh encryption randomness. `log_delta` is log2(q/t) for
/// the same cell, which is the budget the flooding term has to fit inside.
struct NoiseCalibration {
    Circuit  circuit;
    // Part of the key: the same ring dimension at a different security level is
    // a different measurement, and applying one to the other would silently
    // reuse noise data gathered under a modulus bound that does not apply.
    SecurityLevel security;
    uint32_t ring_dim_requested;
    uint32_t natural_mult_depth;
    uint32_t ring_dim_natural;
    uint32_t mult_depth;
    uint32_t scaling_mod_size;
    uint32_t eval_noise_bits;
    double   log_delta;
};

#ifndef PICCARD_NOISE_CALIBRATION_FILE
#define PICCARD_NOISE_CALIBRATION_FILE "util/noise_calibration.inc"
#endif
#include PICCARD_NOISE_CALIBRATION_FILE

const char* SecurityName(SecurityLevel s) {
    switch (s) {
        case SecurityLevel::TOY:    return "TOY";
        case SecurityLevel::STD128: return "STD128";
        case SecurityLevel::STD192: return "STD192";
        case SecurityLevel::STD256: return "STD256";
    }
    return "?";
}

const char* CircuitName(Circuit c) {
    switch (c) {
        case Circuit::OneHot:    return "one-hot";
        case Circuit::Sqrt:      return "base-sqrt(m)";
        case Circuit::Threshold: return "threshold";
    }
    return "?";
}

constexpr uint32_t kThresholdLegacyCoefficientBits = 64;

} // namespace

LegacyCalibrationTableCoverage InspectLegacyCalibrationTableCoverage() {
    LegacyCalibrationTableCoverage result{0, 0, 0, 0, 0, {}};
    std::vector<
        std::tuple<Circuit, SecurityLevel, uint32_t, uint32_t>
    > keys;
    const auto record = [&](Circuit circuit, SecurityLevel security,
                            uint32_t requested, uint32_t depth) {
            ++result.rows;
            if (security == SecurityLevel::TOY) {
                ++result.toy_rows;
            }
            if (circuit == Circuit::Threshold) {
                ++result.threshold_rows;
            }
            if (
                security != SecurityLevel::TOY
                && circuit != Circuit::Threshold
            ) {
                ++result.invalid_role_rows;
            }
            const auto key = std::make_tuple(
                circuit, security, requested, depth);
            if (std::find(keys.begin(), keys.end(), key) == keys.end()) {
                keys.push_back(key);
            }
    };
#ifdef PICCARD_PRE_THRESHOLD_CALIBRATION_V2
    ForEachNoiseCalibrationCandidate(
        [&](const NoiseCalibrationCandidateView& candidate) {
            if (candidate.expanded == nullptr) {
                record(
                    candidate.circuit,
                    candidate.security,
                    candidate.ring_dim_requested,
                    candidate.natural_mult_depth);
            }
        });
#else
    for (const auto& row : kNoiseCalibration) {
        if (
            row.security == SecurityLevel::TOY
            || row.circuit == Circuit::Threshold
        ) {
            record(
                row.circuit, row.security, row.ring_dim_requested,
                row.natural_mult_depth);
        }
    }
#endif
    result.distinct_selection_keys = static_cast<uint32_t>(keys.size());
    for (const auto& key : keys) {
        result.selection_keys.push_back(LegacyCalibrationSelectionKey{
            std::get<0>(key),
            std::get<1>(key),
            std::get<2>(key),
            std::get<3>(key),
        });
    }
    return result;
}

PreThresholdTableCoverage InspectPreThresholdCalibrationCoverage(
    const std::vector<PreThresholdCalibrationRequest>& required,
    const std::vector<PreThresholdCalibrationRequest>& accepted_infeasible) {
#ifdef PICCARD_PRE_THRESHOLD_CALIBRATION_V2
    PreThresholdTableCoverage result{
        true,
        static_cast<uint32_t>(required.size()),
        0,
        0,
        0,
        {},
    };
    ForEachNoiseCalibrationCandidate(
        [&](const NoiseCalibrationCandidateView& candidate) {
            if (candidate.expanded == nullptr) return;
            const auto& key = candidate.expanded->key;
            bool duplicate = false;
            for (const auto& prior : result.selected_keys) {
                if (prior == key) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) result.selected_keys.push_back(key);
        });
    for (const auto& key : required) {
        bool selected = false;
        for (const auto& present : result.selected_keys) {
            if (present == key) {
                selected = true;
                break;
            }
        }
        if (selected) {
            ++result.selected;
            continue;
        }
        bool infeasible = false;
        for (const auto& accepted : accepted_infeasible) {
            if (accepted == key) {
                infeasible = true;
                break;
            }
        }
        if (infeasible) {
            ++result.infeasible;
        } else {
            ++result.missing_required;
        }
    }
    return result;
#else
    (void)required;
    (void)accepted_infeasible;
    return PreThresholdTableCoverage{false, 0, 0, 0, 0, {}};
#endif
}

std::vector<PreThresholdCalibrationRow>
InspectPreThresholdCalibrationRows() {
    std::vector<PreThresholdCalibrationRow> rows;
#ifdef PICCARD_PRE_THRESHOLD_CALIBRATION_V2
    ForEachNoiseCalibrationCandidate(
        [&](const NoiseCalibrationCandidateView& candidate) {
            if (candidate.expanded != nullptr) {
                rows.push_back(*candidate.expanded);
            }
        });
#endif
    return rows;
}

uint32_t NextPowerOf2(uint32_t n) {
    if (n <= 1) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

uint32_t MinRingDimForSecurity(SecurityLevel level) {
    // Minimum ring dimensions that OpenFHE actually enforces for BFV
    // with mult_depth=1. These are larger than the theoretical minimums
    // because OpenFHE accounts for noise growth from key-switching, etc.
    switch (level) {
        case SecurityLevel::TOY:    return 1024;
        case SecurityLevel::STD128: return 8192;
        case SecurityLevel::STD192: return 16384;
        case SecurityLevel::STD256: return 32768;
    }
    return 8192;
}

bool IsPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

uint64_t FindPlaintextModulus(uint32_t min_val, uint32_t modulus) {
    // Find smallest prime p such that p > min_val and p ≡ 1 mod modulus
    // Start from the first candidate: 1 + modulus * ceil((min_val) / modulus)
    uint64_t t = 1;
    while (1 + modulus * t <= min_val) {
        t++;
    }
    for (; t < 1000000; t++) {
        uint64_t p = 1 + static_cast<uint64_t>(modulus) * t;
        if (IsPrime(p)) return p;
    }
    throw std::runtime_error("Failed to find suitable plaintext modulus");
}

bool PiccardParams::ValidationSnapshot::operator==(
    const ValidationSnapshot& other) const {
    return std::tie(
               k,
               m,
               security,
               threshold_mode,
               transcript_stat_bits,
               max_queries,
               flood_margin_bits,
               eval_noise_bits,
               ring_dim,
               plaintext_mod,
               natural_mult_depth,
               ring_dim_natural,
               mult_depth,
               scaling_mod_size,
               feature_dim,
               sqrt_base,
               sqrt_feature_dim,
               requested_ring_dim,
               selected_calibrated_ring_dim,
               query_stat_bits,
               coefficient_stat_bits,
               flood_noise_bits,
               selected_log2_q_over_t,
               selected_circuit,
               selected_pre_threshold_calibration,
               runtime_adopted) ==
           std::tie(
               other.k,
               other.m,
               other.security,
               other.threshold_mode,
               other.transcript_stat_bits,
               other.max_queries,
               other.flood_margin_bits,
               other.eval_noise_bits,
               other.ring_dim,
               other.plaintext_mod,
               other.natural_mult_depth,
               other.ring_dim_natural,
               other.mult_depth,
               other.scaling_mod_size,
               other.feature_dim,
               other.sqrt_base,
               other.sqrt_feature_dim,
               other.requested_ring_dim,
               other.selected_calibrated_ring_dim,
               other.query_stat_bits,
               other.coefficient_stat_bits,
               other.flood_noise_bits,
               other.selected_log2_q_over_t,
               other.selected_circuit,
               other.selected_pre_threshold_calibration,
               other.runtime_adopted);
}

PiccardParams::ValidationSnapshot
PiccardParams::CurrentValidationSnapshot() const {
    return ValidationSnapshot{
        k,
        m,
        security,
        threshold_mode,
        transcript_stat_bits,
        max_queries,
        flood_margin_bits,
        eval_noise_bits,
        ring_dim,
        plaintext_mod,
        natural_mult_depth,
        ring_dim_natural,
        mult_depth,
        scaling_mod_size,
        feature_dim,
        sqrt_base,
        sqrt_feature_dim,
        requested_ring_dim_,
        selected_calibrated_ring_dim_,
        query_stat_bits_,
        coefficient_stat_bits_,
        flood_noise_bits_,
        selected_log2_q_over_t_,
        selected_circuit_,
        selected_pre_threshold_calibration_,
        runtime_adopted_,
    };
}

void PiccardParams::CaptureValidationSnapshot() {
    validation_snapshot_ = CurrentValidationSnapshot();
    validation_snapshot_valid_ = true;
}

void PiccardParams::VerifyValidationSnapshot() const {
    if (!validation_snapshot_valid_) {
        throw std::logic_error(
            "sanitizer validation snapshot is unavailable");
    }
    if (!(CurrentValidationSnapshot() == validation_snapshot_)) {
        throw std::logic_error(
            "sanitizer parameter state changed after calibration selection");
    }

    try {
        if (selected_circuit_ == Circuit::Threshold) {
            const uint32_t eval_and_legacy_coefficient = CheckedAddBits(
                eval_noise_bits,
                kThresholdLegacyCoefficientBits,
                SanitizerProfileField::FloodNoiseBits);
            const uint32_t recomputed_flood_bits = CheckedAddBits(
                eval_and_legacy_coefficient,
                flood_margin_bits,
                SanitizerProfileField::FloodNoiseBits);
            const uint32_t required_capacity = CheckedAddBits(
                recomputed_flood_bits,
                2,
                SanitizerProfileField::FloodNoiseBits);
            if (query_stat_bits_ != 0 ||
                coefficient_stat_bits_ !=
                    kThresholdLegacyCoefficientBits ||
                recomputed_flood_bits != flood_noise_bits_ ||
                static_cast<double>(required_capacity) >
                    selected_log2_q_over_t_) {
                throw std::logic_error(
                    "threshold legacy derived state no longer matches its "
                    "calibration");
            }
            return;
        }

        const SanitizerProfile recomputed = DeriveSanitizerProfile(
            transcript_stat_bits,
            max_queries,
            selected_calibrated_ring_dim_,
            eval_noise_bits,
            flood_margin_bits);
        const uint32_t required_capacity = CheckedAddBits(
            recomputed.flood_noise_bits,
            2,
            SanitizerProfileField::FloodNoiseBits);
        if (recomputed.query_stat_bits != query_stat_bits_ ||
            recomputed.coefficient_stat_bits != coefficient_stat_bits_ ||
            recomputed.flood_noise_bits != flood_noise_bits_ ||
            static_cast<double>(required_capacity) >
                selected_log2_q_over_t_) {
            throw std::logic_error(
                "sanitizer derived state no longer matches its calibration");
        }
    } catch (const std::logic_error&) {
        throw;
    } catch (const std::exception& error) {
        throw std::logic_error(
            std::string("sanitizer state revalidation failed: ") +
            error.what());
    }
}

uint32_t PiccardParams::FloodNoiseBits() const {
    if (!flooding_sized_) {
        throw std::logic_error(
            "FloodNoiseBits() on a parameter set whose flooding term was never "
            "sized. Call Validate()/ValidateSqrt(); the derive-only entry "
            "points exist for the calibration harness and leave "
            "eval_noise_bits at 0, which would understate the flooding bound.");
    }
    if (validation_snapshot_valid_) {
        VerifyValidationSnapshot();
    }
    return flood_noise_bits_;
}

const PreThresholdCalibrationRow&
PiccardParams::SelectedPreThresholdCalibration() const {
    if (!selected_pre_threshold_calibration_) {
        throw std::logic_error(
            "no pre-threshold calibration contract was selected");
    }
    VerifyValidationSnapshot();
    return *selected_pre_threshold_calibration_;
}

void PiccardParams::AdoptVerifiedRuntimeRingDim(uint32_t runtime_n) {
    if (!flooding_sized_ || !validation_snapshot_valid_) {
        throw std::logic_error(
            "runtime ring dimension adoption requires prior sanitizer selection");
    }
    VerifyValidationSnapshot();
    if (runtime_adopted_) {
        throw std::logic_error(
            "runtime ring dimension was already adopted");
    }
    if (runtime_n != selected_calibrated_ring_dim_) {
        throw std::invalid_argument(
            "runtime ring dimension " + std::to_string(runtime_n) +
            " does not match selected calibrated ring dimension " +
            std::to_string(selected_calibrated_ring_dim_));
    }

    ring_dim = runtime_n;
    runtime_adopted_ = true;
    CaptureValidationSnapshot();
}

void PiccardParams::SelectFloodingParams(Circuit circuit, uint32_t natural_depth) {
    bool key_exists = false;
    double best_capacity = -std::numeric_limits<double>::infinity();
    std::string best_infeasible;

#ifdef PICCARD_PRE_THRESHOLD_CALIBRATION_V2
    if (circuit != Circuit::Threshold &&
        (security == SecurityLevel::STD128 ||
         security == SecurityLevel::STD192)) {
        std::vector<PreThresholdCalibrationRow> candidates;
        const std::string expected_shape =
            circuit == Circuit::OneHot
                ? "onehot-v1"
                : "sqrt-b" + std::to_string(sqrt_base) + "-v1";
        ForEachNoiseCalibrationCandidate(
            [&](const NoiseCalibrationCandidateView& candidate) {
                if (candidate.expanded == nullptr) return;
                const auto& row = *candidate.expanded;
                if (row.key.circuit != circuit ||
                    row.key.shape_id != expected_shape ||
                    row.key.security != security ||
                    row.key.requested_ring_dim != ring_dim ||
                    row.key.natural_depth != natural_depth ||
                    row.transcript_stat_bits != transcript_stat_bits ||
                    row.max_queries != max_queries ||
                    row.flood_margin_bits != flood_margin_bits) {
                    return;
                }
                candidates.push_back(row);
            });
        if (!candidates.empty()) {
            *this = SelectPreThresholdCalibration(
                *this, candidates.front().key, candidates);
            return;
        }
    }
#endif

    // Threshold remains an exact private coefficient-level compatibility path
    // until its separate branch. It does not claim transcript-level assurance.
    if (circuit == Circuit::Threshold) {
        for (const auto& row : kNoiseCalibration) {
            if (row.circuit != circuit) continue;
            if (row.security != security) continue;
            if (row.ring_dim_requested != ring_dim) continue;
            if (row.natural_mult_depth != natural_depth) continue;

            key_exists = true;
            const uint32_t eval_and_coefficient = CheckedAddBits(
                row.eval_noise_bits,
                kThresholdLegacyCoefficientBits,
                SanitizerProfileField::FloodNoiseBits);
            const uint32_t flood_bits = CheckedAddBits(
                eval_and_coefficient,
                flood_margin_bits,
                SanitizerProfileField::FloodNoiseBits);
            const uint32_t required_capacity = CheckedAddBits(
                flood_bits,
                2,
                SanitizerProfileField::FloodNoiseBits);
            const double capacity = row.log_delta - row.eval_noise_bits - 2.0;
            if (capacity > best_capacity) best_capacity = capacity;

            if (static_cast<double>(required_capacity) <= row.log_delta) {
                flooding_sized_ = true;
                requested_ring_dim_ = row.ring_dim_requested;
                selected_calibrated_ring_dim_ = row.ring_dim_natural;
                query_stat_bits_ = 0;
                coefficient_stat_bits_ = kThresholdLegacyCoefficientBits;
                flood_noise_bits_ = flood_bits;
                selected_log2_q_over_t_ = row.log_delta;
                selected_circuit_ = Circuit::Threshold;
                runtime_adopted_ = false;
                mult_depth = row.mult_depth;
                scaling_mod_size = row.scaling_mod_size;
                eval_noise_bits = row.eval_noise_bits;
                ring_dim_natural = row.ring_dim_natural;
                CaptureValidationSnapshot();
                return;
            }
        }

        const std::string where =
            std::string(CircuitName(circuit)) + " / " +
            SecurityName(security) + " / requested N " +
            std::to_string(ring_dim) + " / natural depth " +
            std::to_string(natural_depth);
        if (!key_exists) {
            throw std::invalid_argument(
                "missing threshold legacy calibration for " + where);
        }
        throw std::invalid_argument(
            "infeasible threshold legacy calibration for " + where +
            ": private coefficient target 64, margin " +
            std::to_string(flood_margin_bits) +
            ", best available coefficient-and-margin capacity " +
            std::to_string(best_capacity));
    }

    // Rows are emitted in cost order within a key, so the first feasible pure
    // selection is the cheapest measured parameter set for this profile.
    for (const auto& row : kNoiseCalibration) {
        if (row.circuit != circuit) continue;
        if (row.security != security) continue;
        if (row.ring_dim_requested != ring_dim) continue;
        if (row.natural_mult_depth != natural_depth) continue;

        key_exists = true;
        double capacity = row.log_delta - row.eval_noise_bits - 2.0;
        CalibrationCandidate candidate{};
        candidate.circuit = row.circuit;
        candidate.security = row.security;
        candidate.requested_ring_dim = row.ring_dim_requested;
        candidate.natural_ring_dim = row.ring_dim_natural;
        // The current generated table has no independently measured grown-row
        // field. Until Work 3 supplies it, realized N is the measured natural N.
        candidate.calibrated_ring_dim = row.ring_dim_natural;
        candidate.natural_mult_depth = row.natural_mult_depth;
        candidate.selected_mult_depth = row.mult_depth;
        candidate.scaling_mod_size = row.scaling_mod_size;
        candidate.eval_noise_bits = row.eval_noise_bits;
        candidate.log2_q_over_t = row.log_delta;

        try {
            *this = SelectSanitizerCandidate(*this, candidate);
            return;
        } catch (const SanitizerCandidateInfeasible& error) {
            if (capacity > best_capacity) {
                best_capacity = capacity;
                best_infeasible = error.what();
            }
        }
    }

    const std::string where = std::string(CircuitName(circuit)) + " / " +
                              SecurityName(security) +
                              " / requested N " + std::to_string(ring_dim) +
                              " / natural depth " +
                              std::to_string(natural_depth);

    if (!key_exists) {
        throw std::invalid_argument(
            "missing sanitizer calibration for " + where +
            ": transcript target " + std::to_string(transcript_stat_bits) +
            ", query cap " + std::to_string(max_queries) +
            ", margin " + std::to_string(flood_margin_bits) +
            ". Measure the exact calibration key with `bench_noise "
            "--pre_threshold ... --emit-rows="
            "noise_calibration.inc.fragment`, "
            "regenerate include/util/noise_calibration.inc, and rebuild.");
    }

    throw std::invalid_argument(
        best_infeasible.empty()
            ? "infeasible sanitizer calibration for " + where
            : best_infeasible);
}

void PiccardParams::ClearFloodingSelection() {
    flooding_sized_ = false;
    requested_ring_dim_ = 0;
    selected_calibrated_ring_dim_ = 0;
    query_stat_bits_ = 0;
    coefficient_stat_bits_ = 0;
    flood_noise_bits_ = 0;
    selected_log2_q_over_t_ = 0.0;
    selected_circuit_ = Circuit::OneHot;
    selected_pre_threshold_calibration_.reset();
    runtime_adopted_ = false;
    validation_snapshot_valid_ = false;
    validation_snapshot_ = ValidationSnapshot{};
    scaling_mod_size = 0;
    eval_noise_bits = 0;
    ring_dim_natural = 0;
}

void PiccardParams::DeriveWithoutFlooding() {
    ClearFloodingSelection();
    if (k == 0) throw std::invalid_argument("k must be > 0");
    if (m < 2) throw std::invalid_argument("m must be >= 2");

    feature_dim = k * m;
    uint32_t min_ring = MinRingDimForSecurity(security);
    ring_dim = NextPowerOf2(feature_dim);
    if (ring_dim < min_ring) {
        ring_dim = min_ring;
    }

    // BFV plaintext modulus: prime p > k, p ≡ 1 mod 2N
    uint32_t two_n = 2 * ring_dim;
    plaintext_mod = FindPlaintextModulus(k, two_n);

    mult_depth = 1;
    if (threshold_mode) {
        // Paterson-Stockmeyer baby-step/giant-step for degree-k polynomial.
        // Must match EvalPolyBFV's step-size calculation exactly.
        uint32_t degree = k;
        uint32_t s = 1;
        while (s * s < degree + 1) s++;

        // Baby-step depth: mirrors the power tree in EvalPolyBFV
        // (even j → square, odd j → multiply by x)
        uint32_t baby_depth = 0;
        {
            uint32_t v = s;
            while (v > 1) {
                baby_depth++;
                if (v % 2 == 1) v--;
                else v /= 2;
            }
        }

        // Giant-step multiplications (Horner over num_chunks)
        uint32_t num_chunks = (degree + s) / s;
        uint32_t giant_mults = num_chunks - 1;

        // +1 for the initial ct_x * ct_y in ComputeThresholdResult
        mult_depth = 1 + baby_depth + giant_mults;
    }
    natural_mult_depth = mult_depth;
}

void PiccardParams::Validate() {
    DeriveWithoutFlooding();

    // Everything above is the circuit's own requirement. Flooding headroom is
    // added on top, never by rewriting the Paterson-Stockmeyer depth: that
    // number has to keep matching EvalPolyBFV's step-size calculation exactly.
    SelectFloodingParams(threshold_mode ? Circuit::Threshold : Circuit::OneHot,
                         natural_mult_depth);
}

void PiccardParams::DeriveSqrtWithoutFlooding() {
    ClearFloodingSelection();
    if (k == 0) throw std::invalid_argument("k must be > 0");
    if (m < 4) throw std::invalid_argument("m must be >= 4 for sqrt encoding");

    // m must be a power of 2
    if ((m & (m - 1)) != 0)
        throw std::invalid_argument("m must be a power of 2 for sqrt encoding");

    // log2(m) must be even so that √m is an integer
    uint32_t log2m = 0;
    { uint32_t tmp = m; while (tmp > 1) { log2m++; tmp >>= 1; } }
    if (log2m % 2 != 0)
        throw std::invalid_argument("log2(m) must be even for sqrt encoding (m must be a perfect square power of 2)");

    sqrt_base = 1u << (log2m / 2);
    sqrt_feature_dim = k * 2 * sqrt_base;

    feature_dim = sqrt_feature_dim;
    uint32_t min_ring = MinRingDimForSecurity(security);
    ring_dim = NextPowerOf2(sqrt_feature_dim);
    if (ring_dim < min_ring) {
        ring_dim = min_ring;
    }

    // Depth 2 for two ct-ct multiplications (component-wise AND, digit AND).
    // Extra depth headroom (+1) needed because the intermediate rotate-and-sum
    // and the large plaintext modulus requirement (p ≡ 1 mod 2N) inflate noise
    // beyond a tight depth-2 budget.
    mult_depth = 3;

    uint32_t two_n = 2 * ring_dim;
    plaintext_mod = FindPlaintextModulus(k, two_n);
    natural_mult_depth = mult_depth;
}

void PiccardParams::ValidateSqrt() {
    DeriveSqrtWithoutFlooding();
    SelectFloodingParams(Circuit::Sqrt, natural_mult_depth);
}

} // namespace piccard
