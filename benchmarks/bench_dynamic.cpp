#include "benchmark_utils.h"
#include "dynamic_refresh_benchmark.h"
#include "raw_timing_schema.h"
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
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
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
// Dynamic result struct & CSV writer
// ============================================================================

class DynamicCSVWriter {
    std::ostream* out_;
public:
    DynamicCSVWriter() : out_(&std::cout) {}

    void WriteHeader() {
        *out_ << SerializeDynamicHeader();
    }

    void WriteRow(const DynamicResult& r) {
        *out_ << SerializeDynamicRow(r, r.provenance);
    }
};

// Raw timing is deliberately opt-in.  The legacy CSV stream and all Work-5
// command lines remain byte-for-byte unchanged when these options are absent.
struct RawTimingOptions {
    std::string output_directory;
    std::string profile_id;
    std::string cell_id;
    size_t measured_trials = 0;
    bool enabled = false;
    bool trials_explicit = false;
    bool saw_profile = false;
    bool saw_cell = false;
};

static void SetRawTimingOption(std::string& destination,
                               bool& seen,
                               const std::string& value,
                               const char* option) {
    if (seen) throw std::invalid_argument(std::string("Duplicate ") + option);
    if (value.empty()) {
        throw std::invalid_argument(std::string("Empty ") + option);
    }
    seen = true;
    destination = value;
}

static RawTimingOptions ParseRawTimingOptions(int argc, char** argv) {
    RawTimingOptions options;
    bool saw_output = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        const auto parse_value = [&](const char* prefix) {
            return arg.substr(std::char_traits<char>::length(prefix));
        };
        if (arg.rfind("--raw-timing-dir=", 0) == 0) {
            SetRawTimingOption(options.output_directory, saw_output,
                               parse_value("--raw-timing-dir="),
                               "--raw-timing-dir");
        } else if (arg.rfind("--raw_timing_dir=", 0) == 0) {
            SetRawTimingOption(options.output_directory, saw_output,
                               parse_value("--raw_timing_dir="),
                               "--raw_timing_dir");
        } else if (arg.rfind("--raw-timing-output-dir=", 0) == 0) {
            SetRawTimingOption(options.output_directory, saw_output,
                               parse_value("--raw-timing-output-dir="),
                               "--raw-timing-output-dir");
        } else if (arg.rfind("--raw_timing_output_dir=", 0) == 0) {
            SetRawTimingOption(options.output_directory, saw_output,
                               parse_value("--raw_timing_output_dir="),
                               "--raw_timing_output_dir");
        } else if (arg.rfind("--raw-timing-profile=", 0) == 0) {
            SetRawTimingOption(options.profile_id, options.saw_profile,
                               parse_value("--raw-timing-profile="),
                               "--raw-timing-profile");
        } else if (arg.rfind("--raw_timing_profile=", 0) == 0) {
            SetRawTimingOption(options.profile_id, options.saw_profile,
                               parse_value("--raw_timing_profile="),
                               "--raw_timing_profile");
        } else if (arg.rfind("--raw-timing-cell=", 0) == 0) {
            SetRawTimingOption(options.cell_id, options.saw_cell,
                               parse_value("--raw-timing-cell="),
                               "--raw-timing-cell");
        } else if (arg.rfind("--raw_timing_cell=", 0) == 0) {
            SetRawTimingOption(options.cell_id, options.saw_cell,
                               parse_value("--raw_timing_cell="),
                               "--raw_timing_cell");
        } else if (arg.rfind("--trials=", 0) == 0) {
            options.trials_explicit = true;
        }
    }
    options.enabled = saw_output || options.saw_profile || options.saw_cell;
    if (options.enabled && !saw_output) {
        throw std::invalid_argument(
            "raw timing profile/cell requires --raw-timing-dir");
    }
    return options;
}

static std::string ResolveRawTimingProfile(
    const BenchmarkConfig& config,
    const RawTimingOptions& options) {
    std::string profile = options.profile_id;
    if (profile.empty()) profile = config.profile.id;
    if (profile == "toy-smoke" || profile == kReadinessTimingProfileVersion) {
        return kReadinessTimingProfileVersion;
    }
    if (profile == "paper-std128-t40-v1" ||
        profile == "paper-std192-encoding-v1" ||
        profile == kPaperTimingProfileVersion ||
        profile.rfind("paper-", 0) == 0) {
        return kPaperTimingProfileVersion;
    }
    throw std::invalid_argument(
        "raw timing requires paper-v1 or readiness-toy-v1 profile");
}

static void ResolveRawTimingOptions(RawTimingOptions& options,
                                    const BenchmarkConfig& config) {
    if (!options.enabled) return;
    if (config.mode != "timing") {
        throw std::invalid_argument(
            "raw timing sidecars require --mode=timing");
    }
    if (TimingContractFor("bench_dynamic") == kTimingNotApplicable) {
        throw std::invalid_argument("bench_dynamic has no raw timing contract");
    }
    options.profile_id = ResolveRawTimingProfile(config, options);
    options.measured_trials = static_cast<size_t>(
        ExpectedTimingTrials(options.profile_id));
    if (options.trials_explicit &&
        config.trials != options.measured_trials) {
        throw std::invalid_argument(
            "versioned raw timing requires exactly " +
            std::to_string(options.measured_trials) + " measured trials");
    }
}

static std::string DefaultDynamicRawCell(const BenchmarkConfig& config,
                                         uint32_t depth) {
    return "dynamic-k" + std::to_string(config.k) + "-m" +
           std::to_string(config.m) + "-n" + std::to_string(config.set_size) +
           "-d" + std::to_string(depth);
}

static double IntersectionFractionForJaccard(double target_jaccard);

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
    dr.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
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

    // Phase 2: Insert throughput — batch of inserts (plaintext only).
    // Probes run on a scratch copy: the d-depth bottom structure discards
    // evicted originals permanently, so probing the signature-bearing
    // structure can empty it once the probes are deleted again (and, on a
    // hash collision, can drop a shared entry). The copy sits outside the
    // timed region; its rows start at capacity==size, so the first
    // displacing insert costs one reallocation per hash function.
    BottomStructure probe_structure = *bottom_x;
    // The TOY profile is a correctness smoke, not a throughput measurement.
    // A single round trip exercises Insert/Delete without exhausting a small
    // depth-d scratch structure. Paper/legacy profiles keep the 100-op batch.
    const size_t num_ops =
        engine.GetParams().security == SecurityLevel::TOY ? 1 : 100;
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        probe_structure.Insert(3000000 + i);
    }
    dr.phase_insert_ms = timer.ElapsedMs();
    dr.ops_insert_per_sec = (dr.phase_insert_ms > 0)
        ? (num_ops / (dr.phase_insert_ms / 1000.0)) : 0.0;

    // Phase 3: Delete throughput — undo the inserts (plaintext only)
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        probe_structure.Delete(3000000 + i);
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

    // Phase 7.5: Noise flooding (cloud) — mirrors Piccard::Evaluate exit (piccard.cpp:77)
    timer.Start();
    result = bfv.Flood(result);
    dr.phase_flood_ms = timer.ElapsedMs();

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
                  dr.phase_compute_ms + dr.phase_flood_ms + dr.phase_decrypt_ms;
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
    size_t trials,
    std::vector<DynamicResult>* raw_measured = nullptr,
    DynamicResult* raw_warmup = nullptr)
{
    // Warmup (discarded)
    const DynamicResult warmup =
        RunTimedDynamic(engine, set_x, set_y, j_true, depth, "warmup");
    if (raw_warmup != nullptr) *raw_warmup = warmup;

    std::vector<double> v_total, v_init, v_insert, v_delete, v_sig;
    std::vector<double> v_encode, v_encrypt, v_compute, v_flood, v_decrypt;
    size_t ct_size = 0;
    double sum_j_hat = 0.0, total_err = 0.0;
    double sum_ins = 0.0, sum_del = 0.0;

    for (size_t t = 0; t < trials; t++) {
        auto dr = RunTimedDynamic(engine, set_x, set_y, j_true, depth, label);
        if (raw_measured != nullptr) raw_measured->push_back(dr);
        v_total.push_back(dr.total_ms);
        v_init.push_back(dr.phase_init_ms);
        v_insert.push_back(dr.phase_insert_ms);
        v_delete.push_back(dr.phase_delete_ms);
        v_sig.push_back(dr.phase_signature_ms);
        v_encode.push_back(dr.phase_encode_ms);
        v_encrypt.push_back(dr.phase_encrypt_ms);
        v_compute.push_back(dr.phase_compute_ms);
        v_flood.push_back(dr.phase_flood_ms);
        v_decrypt.push_back(dr.phase_decrypt_ms);
        ct_size = dr.ct_size_bytes;
        sum_j_hat += dr.jaccard_computed;
        total_err += dr.jaccard_error;
        sum_ins += dr.ops_insert_per_sec;
        sum_del += dr.ops_delete_per_sec;
    }

    auto d_tot = ComputeDispersion(v_total);
    auto d_ini = ComputeDispersion(v_init);
    auto d_ins = ComputeDispersion(v_insert);
    auto d_del = ComputeDispersion(v_delete);
    auto d_sig = ComputeDispersion(v_sig);
    auto d_enc = ComputeDispersion(v_encode);
    auto d_cry = ComputeDispersion(v_encrypt);
    auto d_cmp = ComputeDispersion(v_compute);
    auto d_flo = ComputeDispersion(v_flood);
    auto d_dec = ComputeDispersion(v_decrypt);
    double n = static_cast<double>(trials);

    DynamicResult result;
    result.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    result.label = label;
    result.k = engine.GetParams().k;
    result.m = engine.GetParams().m;
    result.set_size = set_x.size();
    result.ring_dim = engine.GetParams().ring_dim;
    result.depth = depth;
    result.total_ms        = d_tot.mean;  result.total_ms_sd        = d_tot.sd;  result.total_ms_median        = d_tot.median;
    result.phase_init_ms   = d_ini.mean;  result.phase_init_ms_sd   = d_ini.sd;  result.phase_init_ms_median   = d_ini.median;
    result.phase_insert_ms = d_ins.mean;  result.phase_insert_ms_sd = d_ins.sd;  result.phase_insert_ms_median = d_ins.median;
    result.phase_delete_ms = d_del.mean;  result.phase_delete_ms_sd = d_del.sd;  result.phase_delete_ms_median = d_del.median;
    result.phase_signature_ms = d_sig.mean; result.phase_signature_ms_sd = d_sig.sd; result.phase_signature_ms_median = d_sig.median;
    result.phase_encode_ms  = d_enc.mean; result.phase_encode_ms_sd  = d_enc.sd; result.phase_encode_ms_median  = d_enc.median;
    result.phase_encrypt_ms = d_cry.mean; result.phase_encrypt_ms_sd = d_cry.sd; result.phase_encrypt_ms_median = d_cry.median;
    result.phase_compute_ms = d_cmp.mean; result.phase_compute_ms_sd = d_cmp.sd; result.phase_compute_ms_median = d_cmp.median;
    result.phase_flood_ms = d_flo.mean; result.phase_flood_ms_sd = d_flo.sd; result.phase_flood_ms_median = d_flo.median;
    result.phase_decrypt_ms = d_dec.mean; result.phase_decrypt_ms_sd = d_dec.sd; result.phase_decrypt_ms_median = d_dec.median;
    result.memory_bytes = MemoryTracker::GetPeakRSS();
    result.ct_size_bytes = ct_size;
    result.trials = trials;
    result.jaccard_computed = sum_j_hat / n;
    result.jaccard_expected = j_true;
    result.jaccard_error = total_err / n;
    // eligible subset: j_true is constant per row — either all or none
    size_t elig = (j_true > 0.0) ? trials : 0;
    result.jaccard_rel_error = (elig > 0) ? (result.jaccard_error / j_true) : -1.0;
    result.rel_error_eligible_n = elig;
    result.ops_insert_per_sec = sum_ins / n;
    result.ops_delete_per_sec = sum_del / n;
    // Timing always runs under one CRS; record which, so a timing row is
    // reproducible from the CSV rather than implicitly "whatever the default is".
    result.hash_seed = engine.GetParams().hash_seed;
    result.hash_root_seed = engine.GetParams().hash_seed;
    result.hash_randomness = "fixed";
    // Noise-flooding parameter fields are constants; copy explicitly from
    // engine.GetParams() so this aggregation path does not leave them at 0.
    result.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    result.provenance = MakePiccardBenchmarkProvenance(engine.GetBFVContext());
    result.scaling_mod_size = engine.GetParams().scaling_mod_size;

    return result;
}

namespace {

double RequireDynamicTimingValue(double value, const char* phase) {
    if (!std::isfinite(value) || value < 0.0) {
        throw std::invalid_argument(std::string("dynamic raw phase is invalid: ") +
                                    phase);
    }
    return value;
}

void AppendDynamicTimingSample(std::vector<RawTimingSample>& samples,
                               const std::string& profile_id,
                               const std::string& cell_id,
                               uint64_t seed,
                               uint64_t trial_index,
                               SampleKind kind,
                               const DynamicResult& row,
                               const char* phase,
                               double value) {
    samples.push_back({"bench_dynamic", profile_id, cell_id, phase, kind,
                       trial_index, seed,
                       RequireDynamicTimingValue(value, phase)});
}

RawTimingArtifact MakeDynamicTimingArtifact(
    const std::string& profile_id,
    const std::string& cell_id,
    uint64_t seed,
    const DynamicResult& warmup,
    const std::vector<DynamicResult>& measured) {
    const uint64_t expected_measured = ExpectedTimingTrials(profile_id);
    if (measured.size() != expected_measured) {
        throw std::invalid_argument(
            "dynamic raw timing trial count disagrees with profile");
    }

    RawTimingArtifact artifact;
    artifact.producer_id = "bench_dynamic";
    artifact.profile_id = profile_id;
    artifact.cell_id = cell_id;
    artifact.warmup_policy = WarmupPolicy::DiscardOne;
    if (artifact.warmup_policy != ExpectedWarmupPolicy(artifact.producer_id)) {
        throw std::logic_error("bench_dynamic raw warmup policy drift");
    }
    artifact.expected_measured = expected_measured;
    artifact.samples.reserve((measured.size() + 1) * 10);

    const auto append_row = [&](const DynamicResult& row, uint64_t trial,
                                SampleKind kind, uint64_t sample_seed) {
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "init", row.phase_init_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "insert",
                                  row.phase_insert_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "delete",
                                  row.phase_delete_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "signature",
                                  row.phase_signature_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "encode", row.phase_encode_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "encrypt",
                                  row.phase_encrypt_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "compute",
                                  row.phase_compute_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "flood", row.phase_flood_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "decrypt",
                                  row.phase_decrypt_ms);
        AppendDynamicTimingSample(artifact.samples, profile_id, cell_id, sample_seed,
                                  trial, kind, row, "total", row.total_ms);
    };
    append_row(warmup, 0, SampleKind::DiscardedWarmup, seed);
    for (uint64_t trial = 0; trial < measured.size(); ++trial) {
        append_row(measured[static_cast<size_t>(trial)], trial,
                   SampleKind::Measured,
                   TrialSeed(seed, static_cast<size_t>(trial), 0.5));
    }
    ValidateRawTimingArtifact(artifact);
    return artifact;
}

static DynamicResult AggregateRefreshResults(
    const std::vector<DynamicResult>& rows,
    const std::string& label) {
    if (rows.empty()) {
        throw std::invalid_argument("cannot aggregate empty refresh rows");
    }
    const auto dispersion = [&](auto getter) {
        std::vector<double> values;
        values.reserve(rows.size());
        for (const auto& row : rows) values.push_back(getter(row));
        return ComputeDispersion(values);
    };
    const auto refresh_phase = [](const std::optional<double>& value,
                                  const char* phase) {
        if (!value.has_value() || !std::isfinite(*value) || *value < 0.0) {
            throw std::invalid_argument(
                std::string("refresh row has invalid phase: ") + phase);
        }
        return *value;
    };
    const auto d_update = dispersion([&](const auto& row) {
        return refresh_phase(row.phase_refresh_update_ms, "refresh_update");
    });
    const auto d_signature = dispersion([&](const auto& row) {
        return refresh_phase(row.phase_refresh_signature_ms,
                             "refresh_signature");
    });
    const auto d_encode = dispersion([&](const auto& row) {
        return refresh_phase(row.phase_refresh_encode_ms, "refresh_encode");
    });
    const auto d_encrypt = dispersion([&](const auto& row) {
        return refresh_phase(row.phase_refresh_encrypt_ms, "refresh_encrypt");
    });
    const auto d_serialize = dispersion([&](const auto& row) {
        return refresh_phase(row.phase_refresh_serialize_ms,
                             "refresh_serialize");
    });
    const auto d_replace = dispersion([&](const auto& row) {
        return refresh_phase(row.phase_cloud_replace_ms, "cloud_replace");
    });
    const auto d_total = dispersion([&](const auto& row) {
        return refresh_phase(row.refresh_total_ms, "total");
    });
    const auto d_jaccard = dispersion([](const auto& row) {
        return row.jaccard_computed;
    });
    const auto d_error = dispersion([](const auto& row) {
        return row.jaccard_error;
    });
    const auto d_rel_error = dispersion([](const auto& row) {
        return row.jaccard_rel_error;
    });
    DynamicResult result = rows.front();
    result.label = label;
    result.trials = rows.size();
    result.total_ms = d_total.mean;
    result.total_ms_sd = d_total.sd;
    result.total_ms_median = d_total.median;
    result.phase_refresh_update_ms = d_update.mean;
    result.phase_refresh_signature_ms = d_signature.mean;
    result.phase_refresh_encode_ms = d_encode.mean;
    result.phase_refresh_encrypt_ms = d_encrypt.mean;
    result.phase_refresh_serialize_ms = d_serialize.mean;
    result.phase_cloud_replace_ms = d_replace.mean;
    result.refresh_total_ms = d_total.mean;
    result.phase_insert_ms = d_update.mean;
    result.phase_insert_ms_sd = d_update.sd;
    result.phase_insert_ms_median = d_update.median;
    result.phase_signature_ms = d_signature.mean;
    result.phase_signature_ms_sd = d_signature.sd;
    result.phase_signature_ms_median = d_signature.median;
    result.phase_encode_ms = d_encode.mean;
    result.phase_encode_ms_sd = d_encode.sd;
    result.phase_encode_ms_median = d_encode.median;
    result.phase_encrypt_ms = d_encrypt.mean;
    result.phase_encrypt_ms_sd = d_encrypt.sd;
    result.phase_encrypt_ms_median = d_encrypt.median;
    result.jaccard_computed = d_jaccard.mean;
    result.jaccard_expected = rows.front().jaccard_expected;
    result.jaccard_error = d_error.mean;
    result.jaccard_rel_error = d_rel_error.mean;
    result.rel_error_eligible_n = 0;
    for (const auto& row : rows) {
        result.rel_error_eligible_n += row.rel_error_eligible_n;
    }
    return result;
}

static void RunRawTimingDynamic(const BenchmarkConfig& config,
                                uint32_t depth,
                                const RawTimingOptions& options,
                                DynamicCSVWriter& csv) {
    const std::string profile_id = options.profile_id;
    const uint64_t expected_trials = options.measured_trials;
    if (profile_id == kReadinessTimingProfileVersion &&
        config.security_level != SecurityLevel::TOY) {
        throw std::invalid_argument("readiness raw timing requires TOY security");
    }
    if (profile_id == kPaperTimingProfileVersion &&
        config.security_level == SecurityLevel::TOY) {
        throw std::invalid_argument("paper raw timing does not permit TOY security");
    }

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.bottom_depth = depth;
    params.security = config.security_level;
    params.hash_seed = config.seed;
    ApplyBenchmarkProfile(config, params);
    params.Validate();
    DynamicPiccard engine(params);
    engine.KeyGen();

    const double intersection_fraction =
        IntersectionFractionForJaccard(config.target_jaccard);
    auto [set_a, set_b] = MakeSetsWithOverlap(
        config.set_size, intersection_fraction);
    const double j_true = ExactJaccard(set_a, set_b);
    const std::string cell_id = options.cell_id.empty()
                                    ? DefaultDynamicRawCell(config, depth)
                                    : options.cell_id;
    const std::string label = cell_id + "_timing";
    DynamicResult warmup;
    std::vector<DynamicResult> measured;
    auto row = RunMultiTrialDynamic(engine, set_a, set_b, j_true, depth, label,
                                    static_cast<size_t>(expected_trials),
                                    &measured, &warmup);
    row.accuracy_trials = 0;
    ApplyBenchmarkProfile(config, row, BenchmarkMeasurementKind::FheTiming);
    csv.WriteRow(row);

    const RawTimingArtifact artifact = MakeDynamicTimingArtifact(
        profile_id, cell_id, config.seed, warmup, measured);
    WriteRawTimingArtifactsV1(options.output_directory, {artifact});
}

static void RunRawTimingRefresh(const BenchmarkConfig& config,
                                uint32_t depth,
                                uint64_t refresh_updates,
                                const RawTimingOptions& options,
                                DynamicCSVWriter& csv) {
    const std::string profile_id = options.profile_id;
    const uint64_t expected_trials = options.measured_trials;
    if (profile_id == kReadinessTimingProfileVersion &&
        config.security_level != SecurityLevel::TOY) {
        throw std::invalid_argument("readiness raw timing requires TOY security");
    }
    if (profile_id == kPaperTimingProfileVersion &&
        config.security_level == SecurityLevel::TOY) {
        throw std::invalid_argument("paper raw timing does not permit TOY security");
    }

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.bottom_depth = depth;
    params.security = config.security_level;
    params.hash_seed = config.seed;
    ApplyBenchmarkProfile(config, params);
    params.Validate();
    DynamicPiccard engine(params);
    engine.KeyGen();
    const double intersection_fraction =
        IntersectionFractionForJaccard(config.target_jaccard);
    auto [set_a, set_b] = MakeSetsWithOverlap(
        config.set_size, intersection_fraction);
    const std::string cell_id = options.cell_id.empty()
                                    ? "refresh-updates-" +
                                          std::to_string(refresh_updates)
                                    : options.cell_id;
    const auto measured = RunSingleOwnerRefreshTrials(
        engine, set_a, set_b, depth, refresh_updates, expected_trials);
    auto row = AggregateRefreshResults(measured, cell_id + "_timing");
    ApplyBenchmarkProfile(config, row, BenchmarkMeasurementKind::FheTiming);
    csv.WriteRow(row);

    const RawTimingArtifact artifact = MakeDynamicRefreshTimingArtifact(
        profile_id, cell_id, config.seed, measured);
    WriteRawTimingArtifactsV1(options.output_directory, {artifact});
}

}  // namespace

// ============================================================================
// Scenario 1: Varying k
// ============================================================================

static void BenchVaryK(const BenchmarkConfig& config, uint32_t depth,
                       DynamicCSVWriter& csv) {
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);
    size_t effective_size = config.set_size;
    auto [sa, sb] = MakeSetsWithOverlap(effective_size, 0.5);
    double j_true = ExactJaccard(sa, sb);

    for (uint32_t k : k_values) {
        try {
            PiccardParams params;
            params.k = k;
            params.m = config.m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            ApplyBenchmarkProfile(config, params);
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
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, config.security_level);
    size_t effective_size = config.set_size;
    auto [sa, sb] = MakeSetsWithOverlap(effective_size, 0.5);
    double j_true = ExactJaccard(sa, sb);

    for (uint32_t m : m_values) {
        try {
            PiccardParams params;
            params.k = config.k;
            params.m = m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            ApplyBenchmarkProfile(config, params);
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
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000, 100000}, config.security_level);

    PiccardParams params;
    params.k = config.k;
    params.m = config.m;
    params.bottom_depth = depth;
    params.security = config.security_level;
    ApplyBenchmarkProfile(config, params);
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
    std::vector<uint32_t> k_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256, 512}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    for (uint32_t k : k_values) {
        try {
            PiccardParams params;
            params.k = k;
            params.m = config.m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            ApplyBenchmarkProfile(config, params);
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            double total_error_all = 0;
            size_t count_all = 0;

            for (double frac : overlaps) {
                for (size_t t = 0; t < config.trials; t++) {
                    std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                    const uint64_t trial_hash_seed =
                        (config.hash_randomness ==
                         benchmark::HashRandomness::Resampled)
                            ? benchmark::HashTrialSeed(config.seed, t, frac)
                            : params.hash_seed;
                    // Reseed first: both structures must be built under the CRS
                    // this trial will run under, or Run() rejects them.
                    engine.SetHashSeed(trial_hash_seed);

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
                    dr.estimator_model =
                        EstimatorModel::Sha256RandomRankingPocV1;
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
                    dr.trials = 1;
                    dr.rel_error_eligible_n = (j_true > 0.0) ? 1 : 0;
                    dr.accuracy_trials = 1;
                    dr.hash_randomness =
                        benchmark::HashRandomnessName(config.hash_randomness);
                    dr.hash_seed = trial_hash_seed;
                    dr.hash_root_seed = config.seed;
                    dr.sanitizer = MakeSanitizerMetadata(engine.GetParams());
                    dr.provenance = MakePiccardBenchmarkProvenance(engine.GetBFVContext());
                    dr.scaling_mod_size = engine.GetParams().scaling_mod_size;
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
    std::vector<uint32_t> m_values = QuickSweep<uint32_t>({16, 32, 64, 128, 256}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    for (uint32_t m : m_values) {
        try {
            PiccardParams params;
            params.k = config.k;
            params.m = m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            ApplyBenchmarkProfile(config, params);
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            double total_error_all = 0;
            size_t count_all = 0;

            for (double frac : overlaps) {
                for (size_t t = 0; t < config.trials; t++) {
                    std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                    const uint64_t trial_hash_seed =
                        (config.hash_randomness ==
                         benchmark::HashRandomness::Resampled)
                            ? benchmark::HashTrialSeed(config.seed, t, frac)
                            : params.hash_seed;
                    // Reseed first: both structures must be built under the CRS
                    // this trial will run under, or Run() rejects them.
                    engine.SetHashSeed(trial_hash_seed);

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
                    dr.estimator_model =
                        EstimatorModel::Sha256RandomRankingPocV1;
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
                    dr.trials = 1;
                    dr.rel_error_eligible_n = (j_true > 0.0) ? 1 : 0;
                    dr.accuracy_trials = 1;
                    dr.hash_randomness =
                        benchmark::HashRandomnessName(config.hash_randomness);
                    dr.hash_seed = trial_hash_seed;
                    dr.hash_root_seed = config.seed;
                    dr.sanitizer = MakeSanitizerMetadata(engine.GetParams());
                    dr.provenance = MakePiccardBenchmarkProvenance(engine.GetBFVContext());
                    dr.scaling_mod_size = engine.GetParams().scaling_mod_size;
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
    std::vector<size_t> sizes = QuickSweep<size_t>({100, 1000, 10000}, config.security_level);
    std::vector<double> overlaps = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5,
                                    0.6, 0.7, 0.8, 0.9, 1.0};

    for (size_t sz : sizes) {
        try {
            PiccardParams params;
            params.k = config.k;
            params.m = config.m;
            params.bottom_depth = depth;
            params.security = config.security_level;
            ApplyBenchmarkProfile(config, params);
            params.Validate();

            DynamicPiccard engine(params);
            engine.KeyGen();

            double total_error_all = 0;
            size_t count_all = 0;

            for (double frac : overlaps) {
                for (size_t t = 0; t < config.trials; t++) {
                    std::mt19937_64 rng(benchmark::TrialSeed(config.seed, t, frac));
                    const uint64_t trial_hash_seed =
                        (config.hash_randomness ==
                         benchmark::HashRandomness::Resampled)
                            ? benchmark::HashTrialSeed(config.seed, t, frac)
                            : params.hash_seed;
                    engine.SetHashSeed(trial_hash_seed);
                    auto [sa, sb] = benchmark::MakeRandomSetsWithOverlap(sz, frac, rng);
                    double j_true = ExactJaccard(sa, sb);

                    auto bottom_x = engine.InitSet(sa);
                    auto bottom_y = engine.InitSet(sb);
                    auto result = engine.Run(*bottom_x, *bottom_y);
                    double err = std::abs(result.jaccard_estimate - j_true);
                    total_error_all += err;
                    count_all++;

                    DynamicResult dr;
                    dr.estimator_model =
                        EstimatorModel::Sha256RandomRankingPocV1;
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
                    dr.trials = 1;
                    dr.rel_error_eligible_n = (j_true > 0.0) ? 1 : 0;
                    dr.accuracy_trials = 1;
                    dr.hash_randomness =
                        benchmark::HashRandomnessName(config.hash_randomness);
                    dr.hash_seed = trial_hash_seed;
                    dr.hash_root_seed = config.seed;
                    dr.sanitizer = MakeSanitizerMetadata(engine.GetParams());
                    dr.provenance = MakePiccardBenchmarkProvenance(engine.GetBFVContext());
                    dr.scaling_mod_size = engine.GetParams().scaling_mod_size;
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

static double IntersectionFractionForJaccard(double target_jaccard) {
    return target_jaccard == 0.0
        ? 0.0
        : (2.0 * target_jaccard) / (1.0 + target_jaccard);
}

static uint64_t ParseUnsignedDecimal(std::string_view value,
                                     const char* option) {
    if (value.empty()) {
        throw std::invalid_argument(std::string("Invalid ") + option + ": empty");
    }
    uint64_t parsed = 0;
    for (const char character : value) {
        if (character < '0' || character > '9') {
            throw std::invalid_argument(
                std::string("Invalid ") + option + ": " + std::string(value));
        }
        const uint64_t digit = static_cast<uint64_t>(character - '0');
        if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
            throw std::invalid_argument(
                std::string("Invalid ") + option + ": " + std::string(value));
        }
        parsed = parsed * 10 + digit;
    }
    return parsed;
}

static void RunProfileGrid(const BenchmarkConfig& config,
                           uint32_t depth,
                           DynamicCSVWriter& csv) {
    const BenchmarkMode mode = ParseBenchmarkMode(config.mode);
    const BenchmarkGridPoint supplied{
        "evidence", config.k, config.m, config.set_size, 0,
        config.target_jaccard};
    const auto points = ResolveBenchmarkGrid(
        config.profile, BenchmarkProducer::Dynamic, mode,
        config.evidence_point, supplied);

    for (const auto& point : points) {
        PiccardParams params;
        params.k = point.k;
        params.m = point.m;
        params.bottom_depth = depth;
        params.security = config.security_level;
        params.hash_seed = config.seed;
        ApplyBenchmarkProfile(config, params);
        params.Validate();

        DynamicPiccard engine(params);
        engine.KeyGen();
        const double intersection_fraction =
            IntersectionFractionForJaccard(point.target_jaccard);
        auto [set_a, set_b] = MakeSetsWithOverlap(
            point.set_size, intersection_fraction);
        const double j_true = ExactJaccard(set_a, set_b);
        auto row = RunMultiTrialDynamic(
            engine, set_a, set_b, j_true, depth,
            point.axis + "_timing", config.trials);
        row.accuracy_trials = 0;
        ApplyBenchmarkProfile(
            config, row, BenchmarkMeasurementKind::FheTiming);
        csv.WriteRow(row);
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    if (PrintBuildProvenanceIfRequested(argc, argv)) return 0;
    if (argc < 2) {
        std::cout << "Usage: bench_dynamic [options]\n"
                  << "Options:\n"
                  << "  --k=N              Number of MinHash functions (default: 128)\n"
                  << "  --m=N              One-hot bucket size (default: 64)\n"
                  << "  --set_size=N       Size of each party's set (default: 100)\n"
                  << "  --depth=D          BottomStructure depth (default: 5)\n"
                  << "  --trials=N         Number of trials to run (default: 10)\n"
                  << "  --mode=MODE        'accuracy' or 'timing' (default: timing)\n"
                  << "  --security=LEVEL   'TOY', 'STD128', 'STD192', or 'STD256'\n"
                  << "  --scenario=MODE    'legacy' or 'refresh' (default: legacy)\n"
                  << "  --refresh_updates=N  Positive owner-A updates for refresh\n"
                  << "                     Refresh requires toy-smoke, TOY timing,\n"
                  << "                     evidence_point, and exactly one trial.\n";
        return 0;
    }

    // The frozen Work #5 dynamic argv historically spells this one evidence
    // field with an underscore.  Normalize it locally rather than widening
    // the shared benchmark CLI contract; the canonical parser still owns all
    // numeric validation and duplicate detection.
    std::vector<std::string> normalized_args;
    normalized_args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg.rfind("--target_jaccard=", 0) == 0) {
            arg = "--target-jaccard=" + arg.substr(17);
        }
        normalized_args.push_back(std::move(arg));
    }
    std::vector<char*> normalized_argv;
    normalized_argv.reserve(normalized_args.size());
    for (auto& arg : normalized_args) {
        normalized_argv.push_back(arg.data());
    }
    auto config = BenchmarkConfig::ParseArgs(argc, normalized_argv.data());
    RawTimingOptions raw_timing = ParseRawTimingOptions(argc, argv);
    ResolveRawTimingOptions(raw_timing, config);

    // Parse dynamic-only flags before rejecting unknown benchmark options.
    uint32_t depth = 5;
    std::string scenario = "legacy";
    bool saw_refresh_updates = false;
    uint64_t refresh_updates = 0;
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg.find("--depth=") == 0) {
            depth = static_cast<uint32_t>(std::stoul(arg.substr(8)));
        } else if (arg.find("--scenario=") == 0) {
            scenario = arg.substr(11);
            if (scenario != "legacy" && scenario != "refresh") {
                throw std::invalid_argument("Invalid scenario: " + scenario);
            }
        } else if (arg.find("--refresh_updates=") == 0) {
            if (saw_refresh_updates) {
                throw std::invalid_argument("Duplicate --refresh_updates");
            }
            saw_refresh_updates = true;
            refresh_updates = ParseUnsignedDecimal(
                std::string_view(arg).substr(18), "--refresh_updates");
        }
    }
    RejectUnknownBenchmarkOptions(
        argc, normalized_argv.data(),
        {"--depth=", "--scenario=", "--refresh_updates=",
         "--raw-timing-dir=", "--raw_timing_dir=",
         "--raw-timing-output-dir=", "--raw_timing_output_dir=",
         "--raw-timing-profile=", "--raw_timing_profile=",
         "--raw-timing-cell=", "--raw_timing_cell="});

    config.Print();
    std::cerr << "  Depth:     " << depth << "\n";

    DynamicCSVWriter csv;
    csv.WriteHeader();

    if (scenario == "refresh") {
        if (raw_timing.enabled) {
            if (!saw_refresh_updates ||
                (refresh_updates != 1 && refresh_updates != 2)) {
                throw std::invalid_argument(
                    "raw refresh sidecars require --refresh_updates=1 or 2");
            }
            RunRawTimingRefresh(config, depth, refresh_updates, raw_timing, csv);
            return 0;
        }
        if (config.profile.id != "toy-smoke" ||
            config.security_level != SecurityLevel::TOY ||
            config.mode != "timing" || !config.evidence_point ||
            config.trials != 1 || !saw_refresh_updates ||
            (refresh_updates != 1 && refresh_updates != 2)) {
            throw std::invalid_argument(
                "refresh requires --profile=toy-smoke, --security=TOY, "
                "--mode=timing, --evidence_point, --trials=1, and "
                "--refresh_updates=1 or --refresh_updates=2");
        }
        PiccardParams params;
        params.k = config.k;
        params.m = config.m;
        params.bottom_depth = depth;
        params.security = config.security_level;
        params.hash_seed = config.seed;
        ApplyBenchmarkProfile(config, params);
        params.Validate();
        DynamicPiccard engine(params);
        engine.KeyGen();
        const double intersection_fraction =
            IntersectionFractionForJaccard(config.target_jaccard);
        auto [set_a, set_b] = MakeSetsWithOverlap(
            config.set_size, intersection_fraction);
        auto row = RunSingleOwnerRefresh(
            engine, set_a, set_b, depth, refresh_updates);
        // Refresh rows are correctness-only; phase timings remain incidental
        // diagnostics and must never be aggregated as performance evidence.
        ApplyBenchmarkProfile(config, row, BenchmarkMeasurementKind::Diagnostic);
        csv.WriteRow(row);
        return 0;
    }
    if (saw_refresh_updates) {
        throw std::invalid_argument("--refresh_updates requires --scenario=refresh");
    }

    if (raw_timing.enabled) {
        RunRawTimingDynamic(config, depth, raw_timing, csv);
        return 0;
    }

    if (config.profile.run_class != BenchmarkRunClass::Legacy) {
        RunProfileGrid(config, depth, csv);
        return 0;
    }

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
