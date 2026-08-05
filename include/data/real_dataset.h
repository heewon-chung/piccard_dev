#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace piccard::data {

struct RealDatasetRecord {
    std::string id;
    std::vector<uint64_t> raw_features;       // strictly increasing
    std::vector<uint64_t> bucketed_features;  // strictly increasing, < universe
};

struct RealDatasetPair {
    std::string id;
    std::string record_a;
    std::string record_b;
    std::string kind;    // validated per dataset (e.g. known_match|sampled_nonmatch)
    int label = 0;       // 1 | 0 | -1
};

// min/median/p95/max as recorded in a piccard-real-processed-v1 manifest's
// raw_set_size_* / bucketed_set_size_* fields.
struct RealDatasetSetSizeStats {
    uint64_t min = 0;
    double median = 0.0;
    uint64_t p95 = 0;
    uint64_t max = 0;
};

// Every piccard-real-processed-v1 dataset.manifest.tsv field, typed.
struct RealDataset {
    std::string dataset;
    std::string variant;
    std::string preprocessing_version;
    uint64_t universe_size = 0;
    uint64_t seed = 0;

    std::string source_manifest_file;
    std::string source_manifest_sha256;
    std::string records_file;
    std::string records_sha256;
    uint64_t record_count = 0;
    std::string pairs_file;
    std::string pairs_sha256;
    uint64_t pair_count = 0;

    RealDatasetSetSizeStats raw_set_size;
    RealDatasetSetSizeStats bucketed_set_size;

    uint64_t original_positive_count = 0;
    uint64_t retained_positive_count = 0;
    uint64_t requested_pair_count = 0;
    std::optional<uint64_t> max_documents;      // empty/N-A for dblp_acm
    std::optional<uint64_t> min_related_pairs;  // empty/N-A for dblp_acm

    // Keyed by the exact "dropped.<reason>" manifest key for the dataset.
    std::map<std::string, uint64_t> dropped_counts;

    std::vector<RealDatasetRecord> records;  // records.tsv row order preserved
    std::vector<RealDatasetPair> pairs;      // pairs.tsv row order preserved
};

// Strictly loads and validates a piccard-real-processed-v1 dataset directory
// from its dataset.manifest.tsv: schema literal, checksums of records.tsv /
// pairs.tsv / source.manifest.tsv against the manifest, manifest-relative
// path escape, column counts, duplicate record/pair IDs, unknown pair
// endpoints, unsorted/duplicate/out-of-universe features, invalid label/kind
// combinations, and record/pair count mismatches. Every check completes
// before this function returns a value. Throws std::runtime_error naming the
// failing contract on any violation. Never writes to disk and never prints
// to stdout.
RealDataset LoadRealDataset(const std::filesystem::path& manifest_path);

}  // namespace piccard::data
