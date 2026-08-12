#include "data/real_dataset.h"

#include <openssl/evp.h>

#include <array>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <unordered_set>
#include <utility>

namespace piccard::data {

namespace {

namespace fs = std::filesystem;

[[noreturn]] void Fail(const std::string& message) {
    throw std::runtime_error("LoadRealDataset: " + message);
}

std::string ReadFileBytes(const fs::path& path, const std::string& context) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        Fail(context + ": cannot open '" + path.string() + "'");
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    if (in.bad()) {
        Fail(context + ": read error for '" + path.string() + "'");
    }
    return buffer.str();
}

std::string Sha256Hex(const std::string& data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        Fail("failed to allocate SHA-256 context");
    }
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        Fail("SHA-256 computation failed");
    }
    static const char kHex[] = "0123456789abcdef";
    std::string out(digest_size * 2, '0');
    for (unsigned int i = 0; i < digest_size; ++i) {
        out[2 * i] = kHex[digest[i] >> 4];
        out[2 * i + 1] = kHex[digest[i] & 0x0F];
    }
    return out;
}

bool IsHexSha256(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

// Splits strictly LF-terminated, BOM-free, CR-free `raw` bytes into lines,
// validates that the first line is exactly `expected_header`, rejects blank
// lines, and returns the remaining (data) lines with their trailing '\n'
// stripped.
std::vector<std::string> StrictDataLines(const std::string& raw,
                                          const std::string& expected_header,
                                          const std::string& context) {
    if (raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF &&
        static_cast<unsigned char>(raw[1]) == 0xBB &&
        static_cast<unsigned char>(raw[2]) == 0xBF) {
        Fail(context + ": BOM not allowed");
    }
    if (raw.find('\r') != std::string::npos) {
        Fail(context + ": CR not allowed (file must be LF-terminated)");
    }
    if (raw.empty()) {
        Fail(context + ": empty file");
    }
    if (raw.back() != '\n') {
        Fail(context + ": file must be LF-terminated");
    }

    std::vector<std::string> lines;
    size_t start = 0;
    while (start < raw.size()) {
        size_t pos = raw.find('\n', start);
        lines.push_back(raw.substr(start, pos - start));
        start = pos + 1;
    }

    if (lines.empty() || lines.front() != expected_header) {
        Fail(context + ": missing or malformed header");
    }
    std::vector<std::string> data_lines(lines.begin() + 1, lines.end());
    for (const auto& line : data_lines) {
        if (line.empty()) {
            Fail(context + ": blank line not allowed");
        }
    }
    return data_lines;
}

std::vector<std::string> SplitTab(const std::string& line) {
    std::vector<std::string> fields;
    size_t start = 0;
    while (true) {
        size_t pos = line.find('\t', start);
        if (pos == std::string::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return fields;
}

std::vector<std::pair<std::string, std::string>> ParseTwoColumnManifest(
    const fs::path& path, const std::string& context) {
    std::string raw = ReadFileBytes(path, context);
    std::vector<std::string> data_lines = StrictDataLines(raw, "key\tvalue", context);
    std::vector<std::pair<std::string, std::string>> result;
    result.reserve(data_lines.size());
    for (const auto& line : data_lines) {
        std::vector<std::string> fields = SplitTab(line);
        if (fields.size() != 2) {
            Fail(context + ": expected exactly one tab per manifest row");
        }
        result.emplace_back(fields[0], fields[1]);
    }
    return result;
}

bool IsAllDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

uint64_t ParseUint64Strict(const std::string& s, const std::string& field_name) {
    if (!IsAllDigits(s)) {
        Fail("invalid unsigned integer for " + field_name + ": '" + s + "'");
    }
    try {
        size_t consumed = 0;
        unsigned long long value = std::stoull(s, &consumed, 10);
        if (consumed != s.size()) {
            Fail("invalid unsigned integer for " + field_name + ": '" + s + "'");
        }
        return static_cast<uint64_t>(value);
    } catch (const std::exception&) {
        Fail("invalid unsigned integer for " + field_name + ": '" + s + "'");
    }
}

int ParseIntStrict(const std::string& s, const std::string& field_name) {
    if (s.empty()) {
        Fail("invalid integer for " + field_name + ": ''");
    }
    size_t idx = (s[0] == '-') ? 1 : 0;
    if (idx >= s.size()) {
        Fail("invalid integer for " + field_name + ": '" + s + "'");
    }
    for (size_t i = idx; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            Fail("invalid integer for " + field_name + ": '" + s + "'");
        }
    }
    try {
        size_t consumed = 0;
        long long value = std::stoll(s, &consumed, 10);
        if (consumed != s.size()) {
            Fail("invalid integer for " + field_name + ": '" + s + "'");
        }
        return static_cast<int>(value);
    } catch (const std::exception&) {
        Fail("invalid integer for " + field_name + ": '" + s + "'");
    }
}

double ParseDoubleStrict(const std::string& s, const std::string& field_name) {
    try {
        size_t consumed = 0;
        double value = std::stod(s, &consumed);
        if (consumed != s.size()) {
            Fail("invalid float for " + field_name + ": '" + s + "'");
        }
        return value;
    } catch (const std::exception&) {
        Fail("invalid float for " + field_name + ": '" + s + "'");
    }
}

std::vector<uint64_t> ParseFeatureCsv(const std::string& csv,
                                       const std::string& field_name) {
    std::vector<uint64_t> values;
    if (csv.empty()) return values;
    size_t start = 0;
    while (true) {
        size_t pos = csv.find(',', start);
        std::string token =
            (pos == std::string::npos) ? csv.substr(start) : csv.substr(start, pos - start);
        values.push_back(ParseUint64Strict(token, field_name));
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return values;
}

void ValidateStrictlyIncreasing(const std::vector<uint64_t>& values,
                                 const std::string& context) {
    for (size_t i = 1; i < values.size(); ++i) {
        if (values[i] <= values[i - 1]) {
            Fail(context + ": feature list is not strictly increasing");
        }
    }
}

// Resolves `relative` against `base_dir`, rejecting absolute paths, empty
// paths, backslashes, '.'/'..' components, symlinked components, and any
// resolved escape of `base_dir`.
fs::path ResolveManifestRelativePath(const fs::path& base_dir, const std::string& relative,
                                      const std::string& field_name) {
    if (relative.empty()) {
        Fail("empty path for " + field_name);
    }
    if (relative.front() == '/') {
        Fail("absolute path not allowed for " + field_name + ": '" + relative + "'");
    }
    if (relative.find('\\') != std::string::npos) {
        Fail("invalid path separator for " + field_name + ": '" + relative + "'");
    }

    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= relative.size()) {
        size_t pos = relative.find('/', start);
        std::string part =
            (pos == std::string::npos) ? relative.substr(start) : relative.substr(start, pos - start);
        parts.push_back(part);
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    for (const auto& part : parts) {
        if (part.empty() || part == "." || part == "..") {
            Fail("invalid path component for " + field_name + ": '" + relative + "'");
        }
    }

    fs::path current = base_dir;
    for (const auto& part : parts) {
        current /= part;
        std::error_code ec;
        if (fs::is_symlink(current, ec)) {
            Fail("symlink path not allowed for " + field_name + ": '" + relative + "'");
        }
    }

    std::error_code ec;
    fs::path canonical_base = fs::canonical(base_dir, ec);
    if (ec) {
        Fail("cannot resolve manifest directory");
    }
    fs::path canonical_target = fs::canonical(current, ec);
    if (ec) {
        Fail(field_name + " not found: '" + relative + "'");
    }
    fs::path rel_check = canonical_target.lexically_relative(canonical_base);
    std::string rel_str = rel_check.generic_string();
    if (rel_check.empty() || rel_str == ".." || rel_str.rfind("../", 0) == 0) {
        Fail("path escapes manifest directory for " + field_name + ": '" + relative + "'");
    }
    return current;
}

const std::vector<std::string>& ProcessedManifestKeyPrefix() {
    static const std::vector<std::string> kKeys = {
        "schema_version", "dataset", "variant", "preprocessing_version",
        "universe_size", "seed",
        "source_manifest_file", "source_manifest_sha256",
        "records_file", "records_sha256", "record_count",
        "pairs_file", "pairs_sha256", "pair_count",
        "raw_set_size_min", "raw_set_size_median", "raw_set_size_p95", "raw_set_size_max",
        "bucketed_set_size_min", "bucketed_set_size_median",
        "bucketed_set_size_p95", "bucketed_set_size_max",
        "original_positive_count", "retained_positive_count", "requested_pair_count",
        "max_documents", "min_related_pairs",
    };
    return kKeys;
}

const std::map<std::string, std::vector<std::string>>& DropKeysByDataset() {
    static const std::map<std::string, std::vector<std::string>> kTable = {
        {"dblp_acm", {"dropped.empty_features_dblp", "dropped.empty_features_acm"}},
        {"enron", {"dropped.charset_or_mime", "dropped.empty_body", "dropped.short_body",
                   "dropped.duplicate_copy", "dropped.duplicate_message_id"}},
    };
    return kTable;
}

// dataset -> (pair_kind -> required label). The exact per-dataset
// (pair_kind, label) contracts from the normative shared file grammar.
const std::map<std::string, std::map<std::string, int>>& KindLabelByDataset() {
    static const std::map<std::string, std::map<std::string, int>> kTable = {
        {"dblp_acm", {{"known_match", 1}, {"sampled_nonmatch", 0}}},
        {"enron", {{"thread_related", -1}, {"cross_thread", -1}}},
    };
    return kTable;
}

}  // namespace

RealDataset LoadRealDataset(const std::filesystem::path& manifest_path) {
    const fs::path base_dir = fs::absolute(manifest_path).parent_path();

    std::vector<std::pair<std::string, std::string>> raw_pairs =
        ParseTwoColumnManifest(manifest_path, "dataset.manifest.tsv");

    std::map<std::string, std::string> values;
    for (const auto& [key, value] : raw_pairs) {
        if (!values.emplace(key, value).second) {
            Fail("duplicate manifest key: '" + key + "'");
        }
    }

    auto require = [&](const std::string& key) -> const std::string& {
        auto it = values.find(key);
        if (it == values.end()) {
            Fail("missing required manifest key: '" + key + "'");
        }
        return it->second;
    };

    const std::string schema_version = require("schema_version");
    if (schema_version != "piccard-real-processed-v1") {
        Fail("unsupported schema_version: '" + schema_version + "'");
    }

    const std::string dataset = require("dataset");
    const auto& drop_keys_table = DropKeysByDataset();
    auto drop_keys_it = drop_keys_table.find(dataset);
    if (drop_keys_it == drop_keys_table.end()) {
        Fail("unknown dataset: '" + dataset + "'");
    }

    std::set<std::string> expected_keys(ProcessedManifestKeyPrefix().begin(),
                                        ProcessedManifestKeyPrefix().end());
    if (dataset == "enron") expected_keys.insert("pair_proxy");
    for (const auto& key : drop_keys_it->second) expected_keys.insert(key);
    std::set<std::string> actual_keys;
    for (const auto& entry : values) actual_keys.insert(entry.first);
    if (actual_keys != expected_keys) {
        for (const auto& key : expected_keys) {
            if (!actual_keys.count(key)) {
                Fail("missing required manifest key: '" + key + "'");
            }
        }
        for (const auto& key : actual_keys) {
            if (!expected_keys.count(key)) {
                Fail("unknown manifest key: '" + key + "'");
            }
        }
    }

    RealDataset ds;
    ds.dataset = dataset;
    ds.variant = require("variant");
    ds.preprocessing_version = require("preprocessing_version");
    ds.universe_size = ParseUint64Strict(require("universe_size"), "universe_size");
    if (ds.universe_size == 0) {
        Fail("universe_size must be positive");
    }
    ds.seed = ParseUint64Strict(require("seed"), "seed");

    if (dataset == "dblp_acm") {
        if (ds.variant != "dblp_acm_u65536") {
            Fail("unsupported variant for dataset 'dblp_acm': '" + ds.variant + "'");
        }
        if (ds.preprocessing_version != "dblp-acm-trigram-v1") {
            Fail("unsupported preprocessing_version for dataset 'dblp_acm': '" +
                 ds.preprocessing_version + "'");
        }
    } else if (dataset == "enron") {
        const bool valid_variant = ds.variant == "enron_u65536" ||
                                   ds.variant == "enron_u1048576";
        if (!valid_variant) {
            Fail("unsupported variant for dataset 'enron': '" + ds.variant + "'");
        }
        const uint64_t expected_universe = ds.variant == "enron_u65536"
                                               ? 65536u
                                               : 1048576u;
        if (ds.universe_size != expected_universe) {
            Fail("universe_size does not match Enron variant '" + ds.variant + "'");
        }
        if (ds.preprocessing_version != "enron-shingle5-v2") {
            Fail("unsupported preprocessing_version for dataset 'enron': '" +
                 ds.preprocessing_version + "'");
        }
    }

    ds.source_manifest_file = require("source_manifest_file");
    ds.source_manifest_sha256 = require("source_manifest_sha256");
    if (!IsHexSha256(ds.source_manifest_sha256)) {
        Fail("malformed source_manifest_sha256: '" + ds.source_manifest_sha256 + "'");
    }

    ds.records_file = require("records_file");
    ds.records_sha256 = require("records_sha256");
    if (!IsHexSha256(ds.records_sha256)) {
        Fail("malformed records_sha256: '" + ds.records_sha256 + "'");
    }
    ds.record_count = ParseUint64Strict(require("record_count"), "record_count");

    ds.pairs_file = require("pairs_file");
    ds.pairs_sha256 = require("pairs_sha256");
    if (!IsHexSha256(ds.pairs_sha256)) {
        Fail("malformed pairs_sha256: '" + ds.pairs_sha256 + "'");
    }
    ds.pair_count = ParseUint64Strict(require("pair_count"), "pair_count");

    ds.raw_set_size.min = ParseUint64Strict(require("raw_set_size_min"), "raw_set_size_min");
    ds.raw_set_size.median =
        ParseDoubleStrict(require("raw_set_size_median"), "raw_set_size_median");
    ds.raw_set_size.p95 = ParseUint64Strict(require("raw_set_size_p95"), "raw_set_size_p95");
    ds.raw_set_size.max = ParseUint64Strict(require("raw_set_size_max"), "raw_set_size_max");

    ds.bucketed_set_size.min =
        ParseUint64Strict(require("bucketed_set_size_min"), "bucketed_set_size_min");
    ds.bucketed_set_size.median =
        ParseDoubleStrict(require("bucketed_set_size_median"), "bucketed_set_size_median");
    ds.bucketed_set_size.p95 =
        ParseUint64Strict(require("bucketed_set_size_p95"), "bucketed_set_size_p95");
    ds.bucketed_set_size.max =
        ParseUint64Strict(require("bucketed_set_size_max"), "bucketed_set_size_max");

    ds.original_positive_count =
        ParseUint64Strict(require("original_positive_count"), "original_positive_count");
    ds.retained_positive_count =
        ParseUint64Strict(require("retained_positive_count"), "retained_positive_count");
    ds.requested_pair_count =
        ParseUint64Strict(require("requested_pair_count"), "requested_pair_count");

    if (dataset == "enron") {
        ds.pair_proxy = require("pair_proxy");
        if (ds.pair_proxy != "canonical-subject-proxy-not-thread-ground-truth-v1") {
            Fail("unsupported pair_proxy for dataset 'enron': '" + ds.pair_proxy + "'");
        }
        if (ds.original_positive_count != 0 || ds.retained_positive_count != 0) {
            Fail("Enron positive_count fields must both be zero");
        }
    }

    const std::string& max_documents_str = require("max_documents");
    const std::string& min_related_pairs_str = require("min_related_pairs");
    if (dataset == "dblp_acm") {
        if (!max_documents_str.empty()) {
            Fail("max_documents must be empty (N/A) for dataset 'dblp_acm'");
        }
        if (!min_related_pairs_str.empty()) {
            Fail("min_related_pairs must be empty (N/A) for dataset 'dblp_acm'");
        }
    } else {
        if (max_documents_str.empty()) {
            Fail("max_documents must be set for dataset '" + dataset + "'");
        }
        if (min_related_pairs_str.empty()) {
            Fail("min_related_pairs must be set for dataset '" + dataset + "'");
        }
        ds.max_documents = ParseUint64Strict(max_documents_str, "max_documents");
        ds.min_related_pairs = ParseUint64Strict(min_related_pairs_str, "min_related_pairs");
        if (*ds.max_documents == 0 || *ds.min_related_pairs == 0) {
            Fail("Enron max_documents and min_related_pairs must be positive");
        }
    }

    for (const auto& drop_key : drop_keys_it->second) {
        ds.dropped_counts[drop_key] = ParseUint64Strict(require(drop_key), drop_key);
    }

    const fs::path source_manifest_path =
        ResolveManifestRelativePath(base_dir, ds.source_manifest_file, "source_manifest_file");
    const fs::path records_path =
        ResolveManifestRelativePath(base_dir, ds.records_file, "records_file");
    const fs::path pairs_path =
        ResolveManifestRelativePath(base_dir, ds.pairs_file, "pairs_file");

    const std::string source_bytes = ReadFileBytes(source_manifest_path, "source.manifest.tsv");
    if (Sha256Hex(source_bytes) != ds.source_manifest_sha256) {
        Fail("checksum mismatch for source.manifest.tsv");
    }

    const std::string records_bytes = ReadFileBytes(records_path, "records.tsv");
    if (Sha256Hex(records_bytes) != ds.records_sha256) {
        Fail("checksum mismatch for records.tsv");
    }

    const std::string pairs_bytes = ReadFileBytes(pairs_path, "pairs.tsv");
    if (Sha256Hex(pairs_bytes) != ds.pairs_sha256) {
        Fail("checksum mismatch for pairs.tsv");
    }

    static const std::string kRecordsHeader =
        "record_id\traw_feature_count\traw_features_csv\t"
        "bucketed_feature_count\tbucketed_features_csv";
    std::vector<std::string> record_lines =
        StrictDataLines(records_bytes, kRecordsHeader, "records.tsv");

    std::unordered_set<std::string> seen_record_ids;
    ds.records.reserve(record_lines.size());
    for (const auto& line : record_lines) {
        std::vector<std::string> fields = SplitTab(line);
        if (fields.size() != 5) {
            Fail("wrong column count in records.tsv");
        }
        const std::string& record_id = fields[0];
        if (record_id.empty()) {
            Fail("empty record_id in records.tsv");
        }
        if (!seen_record_ids.insert(record_id).second) {
            Fail("duplicate record id: '" + record_id + "'");
        }

        const uint64_t raw_count = ParseUint64Strict(fields[1], "raw_feature_count");
        std::vector<uint64_t> raw_features = ParseFeatureCsv(fields[2], "raw_features_csv");
        if (raw_features.size() != raw_count) {
            Fail("raw_feature_count mismatch for record '" + record_id + "'");
        }
        ValidateStrictlyIncreasing(raw_features,
                                    "raw_features_csv for record '" + record_id + "'");

        const uint64_t bucketed_count = ParseUint64Strict(fields[3], "bucketed_feature_count");
        std::vector<uint64_t> bucketed_features =
            ParseFeatureCsv(fields[4], "bucketed_features_csv");
        if (bucketed_features.size() != bucketed_count) {
            Fail("bucketed_feature_count mismatch for record '" + record_id + "'");
        }
        ValidateStrictlyIncreasing(bucketed_features,
                                    "bucketed_features_csv for record '" + record_id + "'");
        for (uint64_t bucketed_value : bucketed_features) {
            if (bucketed_value >= ds.universe_size) {
                Fail("bucketed feature out of universe for record '" + record_id + "'");
            }
        }

        RealDatasetRecord record;
        record.id = record_id;
        record.raw_features = std::move(raw_features);
        record.bucketed_features = std::move(bucketed_features);
        ds.records.push_back(std::move(record));
    }
    if (ds.records.size() != ds.record_count) {
        Fail("record_count mismatch: manifest declares " + std::to_string(ds.record_count) +
             ", found " + std::to_string(ds.records.size()));
    }

    static const std::string kPairsHeader = "pair_id\trecord_a\trecord_b\tpair_kind\tlabel";
    std::vector<std::string> pair_lines = StrictDataLines(pairs_bytes, kPairsHeader, "pairs.tsv");

    const auto& valid_kind_labels = KindLabelByDataset().at(dataset);
    std::unordered_set<std::string> seen_pair_ids;
    ds.pairs.reserve(pair_lines.size());
    for (const auto& line : pair_lines) {
        std::vector<std::string> fields = SplitTab(line);
        if (fields.size() != 5) {
            Fail("wrong column count in pairs.tsv");
        }
        const std::string& pair_id = fields[0];
        if (pair_id.empty()) {
            Fail("empty pair_id in pairs.tsv");
        }
        if (!seen_pair_ids.insert(pair_id).second) {
            Fail("duplicate pair id: '" + pair_id + "'");
        }

        const std::string& record_a = fields[1];
        const std::string& record_b = fields[2];
        if (!seen_record_ids.count(record_a)) {
            Fail("unknown pair endpoint: '" + record_a + "'");
        }
        if (!seen_record_ids.count(record_b)) {
            Fail("unknown pair endpoint: '" + record_b + "'");
        }

        const std::string& kind = fields[3];
        auto kind_it = valid_kind_labels.find(kind);
        if (kind_it == valid_kind_labels.end()) {
            Fail("invalid pair_kind for dataset '" + dataset + "': '" + kind + "'");
        }

        const int label = ParseIntStrict(fields[4], "label");
        if (label != kind_it->second) {
            Fail("invalid label for pair_kind '" + kind + "': expected " +
                 std::to_string(kind_it->second) + ", got " + std::to_string(label));
        }

        RealDatasetPair pair;
        pair.id = pair_id;
        pair.record_a = record_a;
        pair.record_b = record_b;
        pair.kind = kind;
        pair.label = label;
        ds.pairs.push_back(std::move(pair));
    }
    if (ds.pairs.size() != ds.pair_count) {
        Fail("pair_count mismatch: manifest declares " + std::to_string(ds.pair_count) +
             ", found " + std::to_string(ds.pairs.size()));
    }

    return ds;
}

}  // namespace piccard::data
