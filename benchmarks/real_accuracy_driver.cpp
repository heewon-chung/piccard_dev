// FHE-header-free plaintext accuracy driver for bench_real_datasets
// (Work 5 Sub-phase 5.3, master Task 7) [FA2][FA8][FA9].
//
// This translation unit's #include set is a closed allowlist, enforced by
// tests/scripts/test_real_dataset_pipeline.py's DriverIncludeAllowlistTest:
// data/real_dataset.h, data/real_dataset_metrics.h, real_dataset_csv_schema.h,
// core/minhash.h, this file's own real_accuracy_driver.h, and C++
// standard-library headers (including <openssl/evp.h>, the sole SHA-256
// provider anywhere in this codebase -- see the header comment below for
// why both extensions beyond the three originally named project headers
// are safe). No BFV/OpenFHE header may appear here, directly or
// transitively, so an FHE context -- and KeyGen -- can never be
// constructed from this file.
#include "real_accuracy_driver.h"

#include "core/minhash.h"
#include "data/real_dataset.h"
#include "data/real_dataset_metrics.h"
#include "real_dataset_csv_schema.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace piccard::bench {

namespace {

namespace fs = std::filesystem;

using piccard::MinHasher;
using piccard::data::ExactJaccard;
using piccard::data::FormatReal17;
using piccard::data::JaccardBucketLabel;
using piccard::data::LoadRealDataset;
using piccard::data::RealDataset;
using piccard::data::RealDatasetRecord;

// --- Byte encoding + SHA-256 helpers ---------------------------------------
// No shared sha256.h header exists in this codebase: every translation unit
// that needs SHA-256 declares its own local OpenSSL-EVP helper (see
// src/data/real_dataset.cpp, src/core/minhash.cpp,
// benchmarks/estimator_diagnostic.cpp, tests/unit/test_real_dataset.cpp).
// This mirrors that established convention rather than introducing a new
// shared dependency.

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
            "real_accuracy_driver: failed to allocate SHA-256 context");
    }
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || digest_size != 32) {
        throw std::runtime_error("real_accuracy_driver: SHA-256 computation failed");
    }
    std::array<unsigned char, 32> result{};
    std::copy(digest.begin(), digest.begin() + 32, result.begin());
    return result;
}

std::string Sha256Hex(const std::string& data) {
    const std::array<unsigned char, 32> digest = Sha256Raw(data);
    static const char kHex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (size_t i = 0; i < 32; ++i) {
        out[2 * i] = kHex[digest[i] >> 4];
        out[2 * i + 1] = kHex[digest[i] & 0x0F];
    }
    return out;
}

uint64_t FirstEightBytesBigEndian(const std::array<unsigned char, 32>& digest) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | digest[i];
    }
    return value;
}

// hash_seed = first8BE(SHA256("piccard-real-crs-v1" || 0x00 || BE64(root_seed)
//   || BE32(len(pair_id)) || pair_id || BE64(trial_index)))
uint64_t DeriveAccuracyHashSeed(uint64_t root_seed, const std::string& pair_id,
                                uint64_t trial_index) {
    static const std::string kDomain = "piccard-real-crs-v1";
    std::string buffer;
    buffer.reserve(kDomain.size() + 1 + 8 + 4 + pair_id.size() + 8);
    buffer.append(kDomain);
    buffer.push_back('\0');
    AppendUint64Be(root_seed, buffer);
    AppendUint32Be(static_cast<uint32_t>(pair_id.size()), buffer);
    buffer.append(pair_id);
    AppendUint64Be(trial_index, buffer);
    return FirstEightBytesBigEndian(Sha256Raw(buffer));
}

// --- File I/O ---------------------------------------------------------------

std::string ReadFileBytes(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error(
            "real_accuracy_driver: cannot open '" + path.string() + "'");
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    if (in.bad()) {
        throw std::runtime_error(
            "real_accuracy_driver: read error for '" + path.string() + "'");
    }
    return buffer.str();
}

// Writes `content` to a sibling temp file, then renames it into place.
// Never leaves a partial file at `path`: either the temp file is renamed
// whole, or `path` is left untouched.
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
                "real_accuracy_driver: cannot open temp file '" +
                temp_path.string() + "'");
        }
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.flush();
        if (!out) {
            throw std::runtime_error(
                "real_accuracy_driver: write failed for '" + temp_path.string() + "'");
        }
    }
    std::error_code rename_ec;
    fs::rename(temp_path, path, rename_ec);
    if (rename_ec) {
        std::error_code remove_ec;
        fs::remove(temp_path, remove_ec);
        throw std::runtime_error(
            "real_accuracy_driver: rename failed for '" + path.string() +
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

struct SetOverlap {
    uint64_t intersection = 0;
    uint64_t union_size = 0;
};

// Identical merge to piccard::data::ExactJaccard, but returns the raw
// counts (needed for realized_intersection/realized_union) instead of
// their ratio.
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

// --- Workload ----------------------------------------------------------------

struct WorkloadRow {
    std::string pair_id;
    uint32_t trial_index = 0;
    uint64_t hash_seed = 0;
    std::string record_a;
    std::string record_b;
};

std::string SerializeWorkloadRows(const std::vector<WorkloadRow>& rows) {
    std::ostringstream out;
    out << "pair_id\ttrial_index\thash_seed\trecord_a\trecord_b\n";
    for (const auto& row : rows) {
        out << row.pair_id << '\t' << row.trial_index << '\t' << row.hash_seed
            << '\t' << row.record_a << '\t' << row.record_b << '\n';
    }
    return out.str();
}

std::string SerializeWorkloadManifest(const std::string& dataset_manifest_sha256,
                                      const std::string& rows_sha256,
                                      const RealAccuracyCliArgs& args) {
    std::ostringstream out;
    out << "key\tvalue\n";
    out << "schema_version\tpiccard-real-accuracy-workload-v1\n";
    out << "dataset_manifest_sha256\t" << dataset_manifest_sha256 << '\n';
    out << "rows_sha256\t" << rows_sha256 << '\n';
    out << "k\t" << args.k << '\n';
    out << "m\t" << args.m << '\n';
    out << "root_seed\t" << args.root_seed << '\n';
    out << "max_pairs\t" << args.max_pairs << '\n';
    out << "accuracy_trials\t" << args.accuracy_trials << '\n';
    out << "hash_randomness\t" << args.hash_randomness << '\n';
    out << "pair_selection\tmanifest-order-prefix\n";
    return out.str();
}

}  // namespace

int RunRealAccuracyMode(const RealAccuracyCliArgs& args) {
    RequireNonEmptyArg(args.dataset_manifest_path, "dataset-manifest");
    RequireNonEmptyArg(args.hash_randomness, "hash_randomness");
    RequireNonEmptyArg(args.csv_path, "csv");
    RequireNonEmptyArg(args.workload_manifest_out_path, "workload-manifest-out");
    RequireNonEmptyArg(args.workload_rows_out_path, "workload-rows-out");
    if (args.k == 0) {
        throw std::invalid_argument("--k must be > 0");
    }
    if (args.m < 2) {
        throw std::invalid_argument("--m must be >= 2 for bias correction");
    }
    if (args.accuracy_trials == 0) {
        throw std::invalid_argument("--accuracy_trials must be > 0");
    }

    const fs::path manifest_path(args.dataset_manifest_path);
    const std::string manifest_bytes = ReadFileBytes(manifest_path);
    const std::string dataset_manifest_sha256 = Sha256Hex(manifest_bytes);

    // Full strict validation (schema, checksums, feature invariants,
    // pair-endpoint resolution, ...) happens inside LoadRealDataset before
    // this function ever sees the dataset.
    const RealDataset dataset = LoadRealDataset(manifest_path);

    std::unordered_map<std::string, const RealDatasetRecord*> records_by_id;
    records_by_id.reserve(dataset.records.size());
    for (const auto& record : dataset.records) {
        records_by_id.emplace(record.id, &record);
    }

    const size_t selected_pair_count =
        std::min<size_t>(dataset.pairs.size(), args.max_pairs);

    // --- Workload: derive per-(pair_id, trial_index) hash seeds ----------
    std::vector<WorkloadRow> workload_rows;
    workload_rows.reserve(selected_pair_count *
                          static_cast<size_t>(args.accuracy_trials));
    for (size_t pair_index = 0; pair_index < selected_pair_count; ++pair_index) {
        const auto& pair = dataset.pairs[pair_index];
        for (uint32_t trial = 0; trial < args.accuracy_trials; ++trial) {
            WorkloadRow row;
            row.pair_id = pair.id;
            row.trial_index = trial;
            row.hash_seed = DeriveAccuracyHashSeed(args.root_seed, pair.id, trial);
            row.record_a = pair.record_a;
            row.record_b = pair.record_b;
            workload_rows.push_back(std::move(row));
        }
    }
    std::sort(workload_rows.begin(), workload_rows.end(),
             [](const WorkloadRow& a, const WorkloadRow& b) {
                 if (a.pair_id != b.pair_id) return a.pair_id < b.pair_id;
                 return a.trial_index < b.trial_index;
             });

    const std::string workload_rows_bytes = SerializeWorkloadRows(workload_rows);
    const std::string rows_sha256 = Sha256Hex(workload_rows_bytes);
    const std::string workload_manifest_bytes =
        SerializeWorkloadManifest(dataset_manifest_sha256, rows_sha256, args);
    const std::string accuracy_workload_sha256 = Sha256Hex(workload_manifest_bytes);

    const RealDatasetPrefixValues base_prefix = MakePlaintextAccuracyPrefix(
        dataset.variant, accuracy_workload_sha256, args.accuracy_trials,
        args.root_seed);

    // --- Accuracy CSV: run the deployed sha256-random-ranking-poc-v1
    // MinHash estimator (in-process, plaintext-only) over each selected
    // pair/trial ---------------------------------------------------------
    const double collision_probability = 1.0 / static_cast<double>(args.m);
    const double correction_denominator = 1.0 - collision_probability;

    std::ostringstream csv_out;
    csv_out << RealAccuracyHeader();

    for (size_t pair_index = 0; pair_index < selected_pair_count; ++pair_index) {
        const auto& pair = dataset.pairs[pair_index];
        const auto record_a_it = records_by_id.find(pair.record_a);
        const auto record_b_it = records_by_id.find(pair.record_b);
        if (record_a_it == records_by_id.end() || record_b_it == records_by_id.end()) {
            // Unreachable: LoadRealDataset already validated every pair
            // endpoint resolves to a known record ID.
            throw std::runtime_error(
                "real_accuracy_driver: unresolved pair endpoint for '" + pair.id + "'");
        }
        const RealDatasetRecord& record_a = *record_a_it->second;
        const RealDatasetRecord& record_b = *record_b_it->second;

        const double exact_jaccard_raw =
            ExactJaccard(record_a.raw_features, record_b.raw_features);
        const SetOverlap bucketed_overlap =
            ComputeOverlap(record_a.bucketed_features, record_b.bucketed_features);
        const double exact_jaccard_bucketed =
            bucketed_overlap.union_size == 0
                ? 0.0
                : static_cast<double>(bucketed_overlap.intersection) /
                      static_cast<double>(bucketed_overlap.union_size);

        for (uint32_t trial = 0; trial < args.accuracy_trials; ++trial) {
            const uint64_t hash_seed =
                DeriveAccuracyHashSeed(args.root_seed, pair.id, trial);
            // hash_range = UINT64_MAX: full-width signatures, matching the
            // deployed protocol (PiccardParams::hash_range default,
            // include/util/params.h) and the plaintext diagnostic path
            // (benchmarks/estimator_diagnostic.cpp:RunDiagnosticPoint).
            // Bucketing into [0, m) happens afterward via `% m`, exactly
            // as OneHotEncoder::Encode and RunDiagnosticPoint's
            // bucket_matches loop do.
            const MinHasher hasher(args.k, std::numeric_limits<uint64_t>::max(),
                                   hash_seed);
            const std::vector<uint64_t> signature_a =
                hasher.ComputeSignature(record_a.bucketed_features);
            const std::vector<uint64_t> signature_b =
                hasher.ComputeSignature(record_b.bucketed_features);

            uint32_t bucket_matches = 0;
            for (uint32_t coordinate = 0; coordinate < args.k; ++coordinate) {
                if (signature_a[coordinate] % args.m == signature_b[coordinate] % args.m) {
                    ++bucket_matches;
                }
            }
            const double bucket_match_fraction =
                static_cast<double>(bucket_matches) / static_cast<double>(args.k);
            // Deployed Plan-1 bias correction, byte-identical to
            // src/protocol/piccard_engine.cpp:Decode() and
            // benchmarks/estimator_diagnostic.cpp:RunDiagnosticPoint():
            // J_hat = (v/k - 1/m) / (1 - 1/m), clamped to [0, 1].
            double estimated_jaccard =
                (bucket_match_fraction - collision_probability) /
                correction_denominator;
            estimated_jaccard = std::max(0.0, std::min(1.0, estimated_jaccard));

            const double abs_error =
                std::fabs(estimated_jaccard - exact_jaccard_bucketed);

            RealDatasetPrefixValues prefix = base_prefix;
            prefix.realized_intersection = bucketed_overlap.intersection;
            prefix.realized_union = bucketed_overlap.union_size;
            prefix.realized_jaccard = exact_jaccard_bucketed;

            csv_out << SerializeRealDatasetPrefix(prefix) << ','
                    << dataset.dataset << ',' << dataset.variant << ','
                    << dataset_manifest_sha256 << ',' << dataset.records_sha256 << ','
                    << dataset.pairs_sha256 << ',' << pair.id << ',' << pair.kind << ','
                    << pair.label << ',' << pair.record_a << ',' << pair.record_b << ','
                    << args.k << ',' << args.m << ',' << args.hash_randomness << ','
                    << trial << ',' << hash_seed << ','
                    << record_a.raw_features.size() << ','
                    << record_b.raw_features.size() << ','
                    << record_a.bucketed_features.size() << ','
                    << record_b.bucketed_features.size() << ','
                    << FormatReal17(exact_jaccard_raw) << ','
                    << FormatReal17(exact_jaccard_bucketed) << ','
                    << FormatReal17(estimated_jaccard) << ','
                    << FormatReal17(bucket_match_fraction) << ','
                    << FormatReal17(abs_error) << ',';
            if (exact_jaccard_bucketed != 0.0) {
                csv_out << FormatReal17(abs_error / exact_jaccard_bucketed);
            }
            // else: rel_error stays empty (the N/A sentinel) -- never 0 or inf.
            csv_out << ',' << JaccardBucketLabel(exact_jaccard_bucketed) << ','
                    << accuracy_workload_sha256 << '\n';
        }
    }

    AtomicWriteFile(fs::path(args.workload_rows_out_path), workload_rows_bytes);
    AtomicWriteFile(fs::path(args.workload_manifest_out_path), workload_manifest_bytes);
    AtomicWriteFile(fs::path(args.csv_path), csv_out.str());

    return 0;
}

}  // namespace piccard::bench
