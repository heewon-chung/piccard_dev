// Live-FHE timing driver for bench_real_datasets (Work 5 Sub-phase 5.4,
// master Task 8). Unlike real_accuracy_driver.cpp, this translation unit
// has no include restriction: it is the one place in bench_real_datasets
// that constructs a live BFV context and runs the deployed one-hot MinHash
// query protocol end to end, exactly as benchmarks/bench_piccard.cpp does
// for its own timing rows.
#include "real_timing_driver.h"

#include "baseline_profile.h"
#include "benchmark_profile.h"
#include "benchmark_utils.h"
#include "data/real_dataset.h"
#include "data/real_dataset_metrics.h"
#include "protocol/piccard.h"
#include "raw_timing_schema.h"
#include "real_dataset_csv_schema.h"
#include "util/params.h"

// OpenFHE serialization registration, required so the production binary
// serializer below can (de)serialize a BFV ciphertext -- same includes
// benchmarks/bench_piccard.cpp uses for CiphertextSizer.
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace piccard::bench {

namespace {

namespace fs = std::filesystem;

using piccard::BFVContext;
using piccard::BFVRuntimeMetadata;
using piccard::Piccard;
using piccard::PiccardParams;
using piccard::data::FormatReal17;
using piccard::data::LoadRealDataset;
using piccard::data::RealDataset;
using piccard::data::RealDatasetRecord;
using piccard::benchmark::BenchmarkProfile;
using piccard::benchmark::CiphertextSizer;
using piccard::benchmark::RawTimingArtifact;
using piccard::benchmark::RawTimingSample;
using piccard::benchmark::ResolveBenchmarkProfile;
using piccard::benchmark::SampleKind;
using piccard::benchmark::Timer;

// --- Byte encoding + SHA-256 helpers ---------------------------------------
// No shared sha256.h header exists in this codebase (see the identical
// comment in real_accuracy_driver.cpp): every translation unit that needs
// SHA-256 declares its own local OpenSSL-EVP helper.

void AppendUint64Be(uint64_t value, std::string& out) {
    unsigned char buffer[8];
    for (int byte = 7; byte >= 0; --byte) {
        buffer[7 - byte] =
            static_cast<unsigned char>(value >> (static_cast<unsigned>(byte) * 8));
    }
    out.append(reinterpret_cast<const char*>(buffer), 8);
}

void AppendUint32Be(uint32_t value, std::string& out) {
    unsigned char buffer[4];
    for (int byte = 3; byte >= 0; --byte) {
        buffer[3 - byte] =
            static_cast<unsigned char>(value >> (static_cast<unsigned>(byte) * 8));
    }
    out.append(reinterpret_cast<const char*>(buffer), 4);
}

std::array<unsigned char, 32> Sha256Raw(const std::string& data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error(
            "real_timing_driver: failed to allocate SHA-256 context");
    }
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || digest_size != 32) {
        throw std::runtime_error("real_timing_driver: SHA-256 computation failed");
    }
    std::array<unsigned char, 32> result{};
    std::copy(digest.begin(), digest.begin() + 32, result.begin());
    return result;
}

std::string HexFromRaw(const std::array<unsigned char, 32>& digest) {
    static const char kHex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (size_t i = 0; i < 32; ++i) {
        out[2 * i] = kHex[digest[i] >> 4];
        out[2 * i + 1] = kHex[digest[i] & 0x0F];
    }
    return out;
}

std::string Sha256Hex(const std::string& data) {
    return HexFromRaw(Sha256Raw(data));
}

uint64_t FirstEightBytesBigEndian(const std::array<unsigned char, 32>& digest) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | digest[i];
    }
    return value;
}

// hash_seed = first8BE(SHA256("piccard-real-timing-crs-v1" || 0x00 ||
//   BE64(root_seed) || dataset_manifest_sha256_raw32 || BE32(k) || BE32(m) ||
//   BE32(len(profile_id)) || profile_id))
uint64_t DeriveTimingHashSeed(
    uint64_t root_seed,
    const std::array<unsigned char, 32>& dataset_manifest_sha256_raw,
    uint32_t k, uint32_t m, const std::string& profile_id) {
    static const std::string kDomain = "piccard-real-timing-crs-v1";
    std::string buffer;
    buffer.reserve(kDomain.size() + 1 + 8 + 32 + 4 + 4 + 4 + profile_id.size());
    buffer.append(kDomain);
    buffer.push_back('\0');
    AppendUint64Be(root_seed, buffer);
    buffer.append(reinterpret_cast<const char*>(dataset_manifest_sha256_raw.data()),
                 dataset_manifest_sha256_raw.size());
    AppendUint32Be(k, buffer);
    AppendUint32Be(m, buffer);
    AppendUint32Be(static_cast<uint32_t>(profile_id.size()), buffer);
    buffer.append(profile_id);
    return FirstEightBytesBigEndian(Sha256Raw(buffer));
}

// --- File I/O ---------------------------------------------------------------
// Identical pattern to real_accuracy_driver.cpp's helpers of the same name
// (duplicated rather than shared: neither TU may depend on the other).

std::string ReadFileBytes(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error(
            "real_timing_driver: cannot open '" + path.string() + "'");
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    if (in.bad()) {
        throw std::runtime_error(
            "real_timing_driver: read error for '" + path.string() + "'");
    }
    return buffer.str();
}

void AtomicWriteFile(const fs::path& path, const std::string& content) {
    if (path.has_parent_path()) {
        std::error_code mkdir_ec;
        fs::create_directories(path.parent_path(), mkdir_ec);
    }
    static uint64_t counter = 0;
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path temp_path(
        path.string() + ".tmp-" + std::to_string(static_cast<unsigned long long>(now)) +
        "-" + std::to_string(counter++));
    {
        std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error(
                "real_timing_driver: cannot open temp file '" +
                temp_path.string() + "'");
        }
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.flush();
        if (!out) {
            throw std::runtime_error(
                "real_timing_driver: write failed for '" + temp_path.string() + "'");
        }
    }
    std::error_code rename_ec;
    fs::rename(temp_path, path, rename_ec);
    if (rename_ec) {
        std::error_code remove_ec;
        fs::remove(temp_path, remove_ec);
        throw std::runtime_error(
            "real_timing_driver: rename failed for '" + path.string() +
            "': " + rename_ec.message());
    }
}

// --- Argument validation -----------------------------------------------------

void RequireNonEmptyArg(const std::string& value, const char* name) {
    if (value.empty()) {
        throw std::invalid_argument(std::string("--") + name + " is required");
    }
}

// --- Set arithmetic over sorted-unique bucketed feature vectors -------------
// Identical merge to real_accuracy_driver.cpp's ComputeOverlap (duplicated:
// neither TU may depend on the other).

struct SetOverlap {
    uint64_t intersection = 0;
    uint64_t union_size = 0;
};

SetOverlap ComputeOverlap(const std::vector<uint64_t>& a,
                          const std::vector<uint64_t>& b) {
    size_t i = 0, j = 0;
    SetOverlap overlap;
    while (i < a.size() && j < b.size()) {
        if (a[i] == b[j]) {
            ++overlap.intersection;
            ++overlap.union_size;
            ++i;
            ++j;
        } else if (a[i] < b[j]) {
            ++overlap.union_size;
            ++i;
        } else {
            ++overlap.union_size;
            ++j;
        }
    }
    overlap.union_size +=
        static_cast<uint64_t>(a.size() - i) + static_cast<uint64_t>(b.size() - j);
    return overlap;
}

// --- Median-combined-bucketed-size pair selection ---------------------------

// median: center value for odd n, arithmetic mean of the two center values
// for even n -- the same convention as piccard::data::Summarize.
double MedianOfSizes(std::vector<uint64_t> sizes) {
    if (sizes.empty()) {
        throw std::runtime_error(
            "real_timing_driver: cannot select a timing pair from zero sizes");
    }
    std::sort(sizes.begin(), sizes.end());
    const size_t n = sizes.size();
    if (n % 2 == 1) {
        return static_cast<double>(sizes[n / 2]);
    }
    return (static_cast<double>(sizes[n / 2 - 1]) +
           static_cast<double>(sizes[n / 2])) /
          2.0;
}

// Selects the pair minimizing |combined bucketed size - median combined
// bucketed size|, tie-broken by lexically smallest pair_id.
size_t SelectMedianPair(
    const RealDataset& dataset,
    const std::unordered_map<std::string, const RealDatasetRecord*>& records_by_id) {
    if (dataset.pairs.empty()) {
        throw std::runtime_error(
            "real_timing_driver: dataset has no pairs to select a timing pair from");
    }
    std::vector<uint64_t> combined_sizes;
    combined_sizes.reserve(dataset.pairs.size());
    for (const auto& pair : dataset.pairs) {
        const RealDatasetRecord& record_a = *records_by_id.at(pair.record_a);
        const RealDatasetRecord& record_b = *records_by_id.at(pair.record_b);
        combined_sizes.push_back(
            static_cast<uint64_t>(record_a.bucketed_features.size()) +
            static_cast<uint64_t>(record_b.bucketed_features.size()));
    }
    const double median = MedianOfSizes(combined_sizes);

    size_t best_index = 0;
    double best_distance = std::numeric_limits<double>::infinity();
    for (size_t index = 0; index < dataset.pairs.size(); ++index) {
        const double distance =
            std::fabs(static_cast<double>(combined_sizes[index]) - median);
        if (distance < best_distance ||
            (distance == best_distance &&
             dataset.pairs[index].id < dataset.pairs[best_index].id)) {
            best_distance = distance;
            best_index = index;
        }
    }
    return best_index;
}

// --- Ciphertext serialization ------------------------------------------------

std::string SerializeCiphertextBytes(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) {
    std::ostringstream oss;
    lbcrypto::Serial::Serialize(ct, oss, lbcrypto::SerType::BINARY);
    return oss.str();
}

// --- One fully-timed protocol trial (both owners, one selected pair) -------
//
// Phase breakdown mirrors benchmarks/bench_piccard.cpp's RunTimedProtocol
// exactly (multiply / rotate-and-sum / flood / decrypt / bias-correction),
// renamed to this schema's phase_cloud_multiply_ms / phase_cloud_rotate_ms /
// phase_sanitize_ms columns. MinHash, encode, and encrypt are timed once per
// call and therefore already sum both owners, per the normative contract.
// Every trial (including the discarded warmup) freshly encrypts its inputs,
// so BFV's randomized encryption gives every trial a distinct ciphertext
// and a distinct a_sha256/b_sha256 pair for the workload manifest.
struct TimingTrialResult {
    double phase_minhash_ms = 0.0;
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_cloud_multiply_ms = 0.0;
    double phase_cloud_rotate_ms = 0.0;
    double phase_sanitize_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double phase_bias_correction_ms = 0.0;
    double result_value = 0.0;
    size_t ciphertext_bytes = 0;
    size_t upload_bytes = 0;
    size_t download_bytes = 0;
    std::string a_sha256;
    std::string b_sha256;
};

TimingTrialResult RunOneTrial(const Piccard& engine,
                              const std::vector<uint64_t>& set_a,
                              const std::vector<uint64_t>& set_b) {
    Timer timer;
    TimingTrialResult result;

    timer.Start();
    const std::vector<uint64_t> sig_a = engine.ComputeSignature(set_a);
    const std::vector<uint64_t> sig_b = engine.ComputeSignature(set_b);
    result.phase_minhash_ms = timer.ElapsedMs();

    timer.Start();
    const std::vector<int64_t> feat_a = engine.EncodeSignature(sig_a);
    const std::vector<int64_t> feat_b = engine.EncodeSignature(sig_b);
    result.phase_encode_ms = timer.ElapsedMs();

    timer.Start();
    const auto ct_a = engine.EncryptFeature(feat_a);
    const auto ct_b = engine.EncryptFeature(feat_b);
    result.phase_encrypt_ms = timer.ElapsedMs();

    const std::string ct_a_bytes = SerializeCiphertextBytes(ct_a);
    const std::string ct_b_bytes = SerializeCiphertextBytes(ct_b);
    result.upload_bytes = ct_a_bytes.size() + ct_b_bytes.size();
    result.a_sha256 = Sha256Hex(ct_a_bytes);
    result.b_sha256 = Sha256Hex(ct_b_bytes);

    const BFVContext& bfv = engine.GetBFVContext();
    const PiccardParams& params = engine.GetParams();

    timer.Start();
    auto product = bfv.Multiply(ct_a, ct_b);
    result.phase_cloud_multiply_ms = timer.ElapsedMs();

    timer.Start();
    auto rotated_sum = product;
    for (uint32_t step = 1; step < params.ring_dim; step *= 2) {
        auto rotated = bfv.Rotate(rotated_sum, static_cast<int>(step));
        rotated_sum = bfv.Add(rotated_sum, rotated);
    }
    result.phase_cloud_rotate_ms = timer.ElapsedMs();

    timer.Start();
    auto flooded = bfv.Flood(rotated_sum);
    result.phase_sanitize_ms = timer.ElapsedMs();

    const std::string flooded_bytes = SerializeCiphertextBytes(flooded);
    result.ciphertext_bytes = flooded_bytes.size();
    result.download_bytes = flooded_bytes.size();

    timer.Start();
    const auto values = bfv.Decrypt(flooded);
    const int64_t v = values[0];
    result.phase_decrypt_ms = timer.ElapsedMs();

    timer.Start();
    const double k = static_cast<double>(params.k);
    const double m = static_cast<double>(params.m);
    const double raw_ratio = static_cast<double>(v) / k;
    double j_hat = (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m);
    j_hat = std::max(0.0, std::min(1.0, j_hat));
    result.phase_bias_correction_ms = timer.ElapsedMs();
    result.result_value = j_hat;

    return result;
}

double TotalQueryMs(const TimingTrialResult& row) {
    return row.phase_minhash_ms + row.phase_encode_ms + row.phase_encrypt_ms +
          row.phase_cloud_multiply_ms + row.phase_cloud_rotate_ms +
          row.phase_sanitize_ms + row.phase_decrypt_ms +
          row.phase_bias_correction_ms;
}

// The raw sidecar is deliberately built from the same per-trial values that
// feed the legacy CSV.  Keeping this mapping in one place makes it impossible
// for a phase to be emitted at a different trial index from its siblings.
using RawPhaseValue = std::pair<const char*, double>;

std::array<RawPhaseValue, 9> RawPhaseValues(const TimingTrialResult& row) {
    return {{{"total", TotalQueryMs(row)},
             {"phase_minhash_ms", row.phase_minhash_ms},
             {"phase_encode_ms", row.phase_encode_ms},
             {"phase_encrypt_ms", row.phase_encrypt_ms},
             {"phase_cloud_multiply_ms", row.phase_cloud_multiply_ms},
             {"phase_cloud_rotate_ms", row.phase_cloud_rotate_ms},
             {"phase_sanitize_ms", row.phase_sanitize_ms},
             {"phase_decrypt_ms", row.phase_decrypt_ms},
             {"phase_bias_correction_ms", row.phase_bias_correction_ms}}};
}

bool IsVersionedRawTimingProfile(const std::string& profile_id) {
    return profile_id == "readiness-toy-v1" ||
           profile_id.rfind("paper-", 0) == 0;
}

std::string RawTimingProfileId(const std::string& profile_id) {
    if (profile_id == "readiness-toy-v1") {
        return piccard::benchmark::kReadinessTimingProfileVersion;
    }
    if (profile_id.rfind("paper-", 0) == 0) {
        return piccard::benchmark::kPaperTimingProfileVersion;
    }
    throw std::invalid_argument(
        "real timing raw sidecar requires a versioned paper/readiness profile");
}

std::string RawTimingCellId(const RealDataset& dataset,
                            const piccard::data::RealDatasetPair& pair,
                            const RealTimingCliArgs& args) {
    // The selected pair and parameter dimensions are part of the cell identity
    // because one dataset/profile invocation can be repeated at another k/m.
    return "real_timing:" + dataset.variant + ":" + pair.id + ":k=" +
           std::to_string(args.k) + ":m=" + std::to_string(args.m);
}

void AppendRawTimingSamples(const std::string& producer_id,
                            const std::string& profile_id,
                            const std::string& cell_id,
                            const TimingTrialResult& row,
                            SampleKind sample_kind,
                            uint64_t trial_index,
                            uint64_t seed,
                            std::vector<RawTimingSample>& samples) {
    for (const auto& [phase, raw_ms] : RawPhaseValues(row)) {
        samples.push_back({producer_id, profile_id, cell_id, phase, sample_kind,
                           trial_index, seed, raw_ms});
    }
}

RawTimingArtifact MakeRawTimingArtifact(
    const RealDataset& dataset,
    const piccard::data::RealDatasetPair& pair,
    const RealTimingCliArgs& args,
    uint64_t hash_seed,
    const TimingTrialResult& warmup,
    const std::vector<TimingTrialResult>& measured_trials) {
    RawTimingArtifact artifact;
    artifact.producer_id = "real_timing";
    // Raw artifacts use the frozen schema profile IDs, while the legacy CSV
    // retains the exact CLI profile ID (for example paper-std128-t40-v1).
    artifact.profile_id = RawTimingProfileId(args.profile_id);
    artifact.cell_id = RawTimingCellId(dataset, pair, args);
    artifact.warmup_policy = piccard::benchmark::WarmupPolicy::DiscardOne;
    artifact.expected_measured = args.trials;
    artifact.samples.reserve((measured_trials.size() + 1) *
                             RawPhaseValues(warmup).size());

    // hash_seed is the actual MinHash CRS used by every endpoint in this
    // timing invocation.  Encryption randomness is captured separately by the
    // workload manifest's ciphertext digests; the raw timing seed therefore
    // remains the fixed, auditable CRS for warmup and measured rows.
    AppendRawTimingSamples(artifact.producer_id, artifact.profile_id,
                           artifact.cell_id, warmup,
                           SampleKind::DiscardedWarmup, 0, hash_seed,
                           artifact.samples);
    for (uint64_t trial = 0; trial < measured_trials.size(); ++trial) {
        AppendRawTimingSamples(
            artifact.producer_id, artifact.profile_id, artifact.cell_id,
            measured_trials[trial], SampleKind::Measured, trial, hash_seed,
            artifact.samples);
    }
    return artifact;
}

fs::path RawTimingOutputPath(const RealTimingCliArgs& args) {
    if (!args.raw_timing_out_path.empty()) {
        return fs::path(args.raw_timing_out_path);
    }
    return fs::path(args.csv_path + ".raw.tsv");
}

// --- Workload manifest -------------------------------------------------------

std::string Pad3(unsigned value) {
    std::ostringstream out;
    out.width(3);
    out.fill('0');
    out << value;
    return out.str();
}

struct WorkloadInputEntry {
    std::string role;             // "warmup" | "measured"
    std::optional<uint32_t> trial_index;
    std::string a_sha256;
    std::string b_sha256;
};

std::string SerializeTimingWorkloadManifest(
    const std::string& dataset_manifest_sha256, const std::string& pair_id,
    const RealTimingCliArgs& args, const BenchmarkProfile& profile,
    uint64_t hash_seed, const std::vector<WorkloadInputEntry>& inputs) {
    std::ostringstream out;
    out << "key\tvalue\n";
    out << "schema_version\tpiccard-real-timing-workload-v1\n";
    out << "dataset_manifest_sha256\t" << dataset_manifest_sha256 << '\n';
    out << "pair_id\t" << pair_id << '\n';
    out << "k\t" << args.k << '\n';
    out << "m\t" << args.m << '\n';
    out << "profile_id\t" << profile.id << '\n';
    out << "root_seed\t" << args.root_seed << '\n';
    out << "hash_seed\t" << hash_seed << '\n';
    out << "trials\t" << args.trials << '\n';
    out << "input_pair_count\t" << inputs.size() << '\n';
    for (size_t index = 0; index < inputs.size(); ++index) {
        const WorkloadInputEntry& entry = inputs[index];
        const std::string prefix = "input." + Pad3(static_cast<unsigned>(index)) + ".";
        out << prefix << "role\t" << entry.role << '\n';
        out << prefix << "trial_index\t";
        if (entry.trial_index.has_value()) {
            out << *entry.trial_index;
        }
        out << '\n';
        out << prefix << "a_sha256\t" << entry.a_sha256 << '\n';
        out << prefix << "b_sha256\t" << entry.b_sha256 << '\n';
    }
    return out.str();
}

}  // namespace

int RunRealTimingMode(const RealTimingCliArgs& args) {
    RequireNonEmptyArg(args.dataset_manifest_path, "dataset-manifest");
    RequireNonEmptyArg(args.profile_id, "profile");
    RequireNonEmptyArg(args.timing_pair, "timing-pair");
    RequireNonEmptyArg(args.csv_path, "csv");
    RequireNonEmptyArg(args.workload_manifest_out_path, "workload-manifest-out");
    if (args.k == 0) {
        throw std::invalid_argument("--k must be > 0");
    }
    if (args.m < 2) {
        throw std::invalid_argument("--m must be >= 2 for bias correction");
    }
    if (args.trials == 0) {
        throw std::invalid_argument("--trials must be > 0");
    }
    if (args.timing_pair != "median") {
        throw std::invalid_argument("--timing-pair only supports 'median'");
    }

    const fs::path manifest_path(args.dataset_manifest_path);
    const std::string manifest_bytes = ReadFileBytes(manifest_path);
    const std::array<unsigned char, 32> dataset_manifest_sha256_raw =
        Sha256Raw(manifest_bytes);
    const std::string dataset_manifest_sha256 =
        HexFromRaw(dataset_manifest_sha256_raw);

    // Full strict validation happens inside LoadRealDataset before this
    // function ever sees the dataset.
    const RealDataset dataset = LoadRealDataset(manifest_path);

    std::unordered_map<std::string, const RealDatasetRecord*> records_by_id;
    records_by_id.reserve(dataset.records.size());
    for (const auto& record : dataset.records) {
        records_by_id.emplace(record.id, &record);
    }

    const size_t pair_index = SelectMedianPair(dataset, records_by_id);
    const auto& pair = dataset.pairs[pair_index];
    const RealDatasetRecord& record_a = *records_by_id.at(pair.record_a);
    const RealDatasetRecord& record_b = *records_by_id.at(pair.record_b);

    const SetOverlap overlap =
        ComputeOverlap(record_a.bucketed_features, record_b.bucketed_features);
    const double exact_jaccard_bucketed =
        overlap.union_size == 0
            ? 0.0
            : static_cast<double>(overlap.intersection) /
                  static_cast<double>(overlap.union_size);

    const uint64_t hash_seed = DeriveTimingHashSeed(
        args.root_seed, dataset_manifest_sha256_raw, args.k, args.m,
        args.profile_id);

    // Unknown profile fails closed here, before any parameter derivation.
    const BenchmarkProfile& profile = ResolveBenchmarkProfile(args.profile_id);

    // The versioned profiles are the only real-timing profiles that publish a
    // raw artifact.  Freeze their counts at the schema boundary: paper is 30,
    // readiness toy is exactly one.  Legacy Work-5 profiles retain their
    // historical caller-provided count and never enter this branch.
    const bool versioned_raw_timing =
        IsVersionedRawTimingProfile(args.profile_id);
    if (versioned_raw_timing &&
        args.trials != piccard::benchmark::ExpectedTimingTrials(args.profile_id)) {
        throw std::invalid_argument(
            "versioned real timing profile requires its frozen trial count");
    }

    PiccardParams params;
    params.k = args.k;
    params.m = args.m;
    params.security = profile.security;
    params.hash_seed = hash_seed;
    params.transcript_stat_bits = profile.transcript_stat_bits;
    params.max_queries = profile.max_queries;
    // Fail-closed by construction: Validate() selects a calibration row
    // scoped to this exact (circuit, security, ring_dim, natural_depth,
    // transcript, max_queries, margin) key. A profile whose table lacks a
    // feasible row for its security level throws std::invalid_argument here
    // -- it never silently substitutes a row measured for a different
    // security level (see PreThresholdCalibration.NeverBorrowsAcrossSecurityLevels
    // in tests/unit/test_params.cpp and this phase's own resolver-level
    // regression test in tests/unit/test_real_dataset_timing.cpp).
    params.Validate();

    Piccard engine(params);
    engine.KeyGen();

    std::vector<WorkloadInputEntry> workload_inputs;
    workload_inputs.reserve(static_cast<size_t>(args.trials) + 1);

    // One discarded warmup: still freshly encrypts real inputs (for the
    // workload manifest's fresh-input hash contract) but its timing and
    // result are never reported.
    TimingTrialResult warmup_trial;
    {
        warmup_trial =
            RunOneTrial(engine, record_a.bucketed_features, record_b.bucketed_features);
        workload_inputs.push_back(
            {"warmup", std::nullopt, warmup_trial.a_sha256,
             warmup_trial.b_sha256});
    }

    std::vector<TimingTrialResult> measured_trials;
    measured_trials.reserve(args.trials);
    for (uint32_t trial = 0; trial < args.trials; ++trial) {
        TimingTrialResult row =
            RunOneTrial(engine, record_a.bucketed_features, record_b.bucketed_features);
        workload_inputs.push_back({"measured", trial, row.a_sha256, row.b_sha256});
        measured_trials.push_back(std::move(row));
    }

    const std::string workload_manifest_bytes = SerializeTimingWorkloadManifest(
        dataset_manifest_sha256, pair.id, args, profile, hash_seed,
        workload_inputs);
    const std::string timing_workload_sha256 = Sha256Hex(workload_manifest_bytes);

#ifdef _OPENMP
    const uint32_t omp_threads = static_cast<uint32_t>(omp_get_max_threads());
#else
    const uint32_t omp_threads = 1;
#endif

    RealDatasetPrefixValues prefix = MakeFheTimingPrefix(
        dataset.variant, profile.id, timing_workload_sha256, args.root_seed,
        args.trials, omp_threads);

    prefix.sanitizer_model = BFVContext::SanitizerModel();
    prefix.sanitizer_assurance = BFVContext::SanitizerAssurance();
    prefix.transcript_stat_bits = params.transcript_stat_bits;
    prefix.max_queries = params.max_queries;
    prefix.query_stat_bits = params.QueryStatBits();
    prefix.coefficient_stat_bits = params.CoefficientStatBits();
    prefix.flood_margin_bits = params.flood_margin_bits;
    prefix.eval_noise_bits = params.eval_noise_bits;
    prefix.flood_noise_bits = params.FloodNoiseBits();

    const BFVRuntimeMetadata runtime = engine.GetBFVContext().GetRuntimeMetadata();
    prefix.actual_ring_dim = runtime.actual_ring_dim;
    prefix.log_q_bits = runtime.log_q_bits;
    prefix.plaintext_modulus = runtime.plaintext_modulus;
    prefix.num_limbs = runtime.num_limbs;
    prefix.openfhe_version = runtime.openfhe_version;

    prefix.realized_intersection = overlap.intersection;
    prefix.realized_union = overlap.union_size;
    prefix.realized_jaccard = exact_jaccard_bucketed;

    std::ostringstream csv_out;
    csv_out << RealTimingHeader();
    for (uint32_t trial = 0; trial < args.trials; ++trial) {
        const TimingTrialResult& row = measured_trials[trial];
        csv_out << SerializeRealDatasetPrefix(prefix) << ','
                << dataset.dataset << ',' << dataset.variant << ','
                << dataset_manifest_sha256 << ',' << dataset.records_sha256 << ','
                << dataset.pairs_sha256 << ',' << pair.id << ',' << pair.kind << ','
                << pair.label << ',' << pair.record_a << ',' << pair.record_b << ','
                << args.k << ',' << args.m << ',' << hash_seed << ',' << trial << ','
                << FormatReal17(row.phase_minhash_ms) << ','
                << FormatReal17(row.phase_encode_ms) << ','
                << FormatReal17(row.phase_encrypt_ms) << ','
                << FormatReal17(row.phase_cloud_multiply_ms) << ','
                << FormatReal17(row.phase_cloud_rotate_ms) << ','
                << FormatReal17(row.phase_sanitize_ms) << ','
                << FormatReal17(row.phase_decrypt_ms) << ','
                << FormatReal17(row.phase_bias_correction_ms) << ','
                << FormatReal17(TotalQueryMs(row)) << ','
                << FormatReal17(row.result_value) << ','
                << row.ciphertext_bytes << ',' << row.upload_bytes << ','
                << row.download_bytes << '\n';
    }

    AtomicWriteFile(fs::path(args.workload_manifest_out_path), workload_manifest_bytes);
    AtomicWriteFile(fs::path(args.csv_path), csv_out.str());

    if (versioned_raw_timing) {
        const RawTimingArtifact raw_artifact = MakeRawTimingArtifact(
            dataset, pair, args, hash_seed, warmup_trial, measured_trials);
        const fs::path raw_path = RawTimingOutputPath(args);
        if (raw_path.has_parent_path()) {
            std::error_code mkdir_ec;
            fs::create_directories(raw_path.parent_path(), mkdir_ec);
            if (mkdir_ec) {
                throw std::runtime_error(
                    "real_timing_driver: cannot create raw timing output parent '" +
                    raw_path.parent_path().string() + "': " + mkdir_ec.message());
            }
        }
        // WriteRawTimingArtifactV1 validates every phase/index/aggregate and
        // publishes with the schema's no-overwrite atomic protocol.  It is
        // intentionally called only for versioned profiles so legacy output
        // bytes and file topology remain untouched.
        piccard::benchmark::WriteRawTimingArtifactV1(raw_path.string(),
                                                     raw_artifact);
    }

    return 0;
}

}  // namespace piccard::bench
