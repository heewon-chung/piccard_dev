#include "data/real_dataset.h"

#include <gtest/gtest.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

using piccard::data::LoadRealDataset;
using piccard::data::RealDataset;

namespace {

namespace fs = std::filesystem;

fs::path FixtureDir() {
    return fs::path(PICCARD_SOURCE_DIR) /
           "tests/fixtures/real_datasets/quick/dblp_acm_u65536";
}

std::string ReadFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("test helper: cannot read " + path.string());
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void WriteFile(const fs::path& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("test helper: cannot write " + path.string());
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::string Sha256Hex(const std::string& data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("test helper: failed to allocate SHA-256 context");
    }
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                     EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                     EVP_DigestFinal_ex(ctx, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("test helper: SHA-256 computation failed");
    }
    static const char kHex[] = "0123456789abcdef";
    std::string out(digest_size * 2, '0');
    for (unsigned int i = 0; i < digest_size; ++i) {
        out[2 * i] = kHex[digest[i] >> 4];
        out[2 * i + 1] = kHex[digest[i] & 0x0F];
    }
    return out;
}

// Splits `content` on '\n' preserving empty trailing entries the way
// std::getline would, so re-joining with "\n" round-trips a LF-terminated
// file byte-for-byte.
std::vector<std::string> SplitLinesKeepTrailingNewline(const std::string& content) {
    std::vector<std::string> lines;
    std::string current;
    for (char c : content) {
        if (c == '\n') {
            lines.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) lines.push_back(current);
    return lines;
}

std::string JoinLinesWithTrailingNewline(const std::vector<std::string>& lines) {
    std::string out;
    for (const auto& line : lines) {
        out += line;
        out += "\n";
    }
    return out;
}

void SetManifestValue(const fs::path& manifest_path, const std::string& key,
                       const std::string& new_value) {
    auto lines = SplitLinesKeepTrailingNewline(ReadFile(manifest_path));
    bool found = false;
    for (auto& line : lines) {
        auto tab = line.find('\t');
        if (tab == std::string::npos) continue;
        if (line.substr(0, tab) == key) {
            line = key + "\t" + new_value;
            found = true;
            break;
        }
    }
    if (!found) {
        throw std::runtime_error("test helper: manifest key not found: " + key);
    }
    WriteFile(manifest_path, JoinLinesWithTrailingNewline(lines));
}

// Rewrites `manifest_key`'s checksum to match the current on-disk bytes of
// `file_name`, for corruption scenarios that must reach validation stages
// downstream of the checksum check.
void RecomputeChecksum(const fs::path& dir, const std::string& file_name,
                        const std::string& manifest_key) {
    SetManifestValue(dir / "dataset.manifest.tsv", manifest_key,
                      Sha256Hex(ReadFile(dir / file_name)));
}

fs::path MakeTempDir(const std::string& stem) {
    static int counter = 0;
    fs::path dir = fs::temp_directory_path() /
                   ("real_dataset_test-" + stem + "-" +
                    std::to_string(static_cast<unsigned long>(getpid())) + "-" +
                    std::to_string(counter++));
    fs::create_directories(dir);
    return dir;
}

fs::path CopyFixture(const std::string& stem) {
    fs::path dest = MakeTempDir(stem);
    for (const auto& entry : fs::directory_iterator(FixtureDir())) {
        if (entry.is_regular_file()) {
            fs::copy_file(entry.path(), dest / entry.path().filename());
        }
    }
    return dest;
}

// Mutates a single tab-separated data row (1-based, header is row 0) of a
// records.tsv/pairs.tsv-style file at `path` using `mutator`, then rewrites
// the file. Returns the original line count (including header) for callers
// that need to append rows instead.
void MutateDataLine(const fs::path& path, size_t data_line_index,
                     const std::function<std::string(const std::string&)>& mutator) {
    auto lines = SplitLinesKeepTrailingNewline(ReadFile(path));
    size_t target = data_line_index + 1;  // skip header
    if (target >= lines.size()) {
        throw std::runtime_error("test helper: data line out of range");
    }
    lines[target] = mutator(lines[target]);
    WriteFile(path, JoinLinesWithTrailingNewline(lines));
}

void AppendDataLine(const fs::path& path, const std::string& new_line) {
    auto lines = SplitLinesKeepTrailingNewline(ReadFile(path));
    lines.push_back(new_line);
    WriteFile(path, JoinLinesWithTrailingNewline(lines));
}

}  // namespace

// ---------------------------------------------------------------------------
// Valid load
// ---------------------------------------------------------------------------

TEST(RealDataset, LoadsValidFixture) {
    RealDataset ds = LoadRealDataset(FixtureDir() / "dataset.manifest.tsv");

    EXPECT_EQ(ds.dataset, "dblp_acm");
    EXPECT_EQ(ds.variant, "dblp_acm_u65536");
    EXPECT_EQ(ds.preprocessing_version, "dblp-acm-trigram-v1");
    EXPECT_EQ(ds.universe_size, 65536u);
    EXPECT_EQ(ds.seed, 7u);
    EXPECT_EQ(ds.record_count, 8u);
    EXPECT_EQ(ds.pair_count, 6u);
    EXPECT_EQ(ds.original_positive_count, 3u);
    EXPECT_EQ(ds.retained_positive_count, 3u);
    EXPECT_EQ(ds.requested_pair_count, 6u);
    EXPECT_FALSE(ds.max_documents.has_value());
    EXPECT_FALSE(ds.min_related_pairs.has_value());
    ASSERT_EQ(ds.dropped_counts.size(), 2u);
    EXPECT_EQ(ds.dropped_counts.at("dropped.empty_features_dblp"), 0u);
    EXPECT_EQ(ds.dropped_counts.at("dropped.empty_features_acm"), 0u);

    EXPECT_EQ(ds.raw_set_size.min, 34u);
    EXPECT_DOUBLE_EQ(ds.raw_set_size.median, 37.5);
    EXPECT_EQ(ds.raw_set_size.p95, 42u);
    EXPECT_EQ(ds.raw_set_size.max, 42u);
    EXPECT_EQ(ds.bucketed_set_size.min, 34u);
    EXPECT_DOUBLE_EQ(ds.bucketed_set_size.median, 37.5);
    EXPECT_EQ(ds.bucketed_set_size.p95, 42u);
    EXPECT_EQ(ds.bucketed_set_size.max, 42u);

    ASSERT_EQ(ds.records.size(), 8u);
    // File order preserved: records.tsv row order is acm:6131..6134 then
    // dblp:6431..6434 (bytewise-ascending record id per the Task-2 writer).
    EXPECT_EQ(ds.records[0].id, "acm:6131");
    EXPECT_EQ(ds.records[4].id, "dblp:6431");
    const auto& first = ds.records[0];
    ASSERT_EQ(first.raw_features.size(), 34u);
    EXPECT_EQ(first.raw_features.front(), 293941716891108309ull);
    EXPECT_EQ(first.raw_features.back(), 18213127801112466939ull);
    EXPECT_TRUE(std::is_sorted(first.raw_features.begin(), first.raw_features.end()));
    ASSERT_EQ(first.bucketed_features.size(), 34u);
    EXPECT_EQ(first.bucketed_features.front(), 1553u);
    EXPECT_EQ(first.bucketed_features.back(), 63493u);
    EXPECT_TRUE(
        std::is_sorted(first.bucketed_features.begin(), first.bucketed_features.end()));
    for (uint64_t v : first.bucketed_features) {
        EXPECT_LT(v, ds.universe_size);
    }

    ASSERT_EQ(ds.pairs.size(), 6u);
    int known_match_count = 0;
    int sampled_nonmatch_count = 0;
    for (const auto& pair : ds.pairs) {
        if (pair.kind == "known_match") {
            EXPECT_EQ(pair.label, 1);
            ++known_match_count;
        } else if (pair.kind == "sampled_nonmatch") {
            EXPECT_EQ(pair.label, 0);
            ++sampled_nonmatch_count;
        } else {
            FAIL() << "unexpected pair kind: " << pair.kind;
        }
        EXPECT_FALSE(pair.id.empty());
        EXPECT_FALSE(pair.record_a.empty());
        EXPECT_FALSE(pair.record_b.empty());
    }
    EXPECT_EQ(known_match_count, 3);
    EXPECT_EQ(sampled_nonmatch_count, 3);
}

TEST(RealDataset, NeverWritesOrPollutesFixtureTree) {
    // Loading twice from the tracked (read-only) fixture must succeed both
    // times and must not mutate any fixture file; a writer would corrupt the
    // checksum invariant the second load depends on.
    std::string before = ReadFile(FixtureDir() / "dataset.manifest.tsv");
    LoadRealDataset(FixtureDir() / "dataset.manifest.tsv");
    LoadRealDataset(FixtureDir() / "dataset.manifest.tsv");
    std::string after = ReadFile(FixtureDir() / "dataset.manifest.tsv");
    EXPECT_EQ(before, after);
}

// ---------------------------------------------------------------------------
// RED: corrupted-fixture rejections (normative Phase 4 RED list)
// ---------------------------------------------------------------------------

TEST(RealDataset, RejectsUnsupportedSchema) {
    fs::path dir = CopyFixture("schema");
    SetManifestValue(dir / "dataset.manifest.tsv", "schema_version",
                      "piccard-real-processed-v2");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsManifestPathEscapeViaDotDot) {
    fs::path dir = CopyFixture("escape-dotdot");
    SetManifestValue(dir / "dataset.manifest.tsv", "records_file", "../records.tsv");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsManifestPathEscapeViaAbsolutePath) {
    fs::path dir = CopyFixture("escape-abs");
    SetManifestValue(dir / "dataset.manifest.tsv", "pairs_file", "/etc/passwd");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsChecksumMismatchOnRecords) {
    fs::path dir = CopyFixture("checksum-records");
    std::string content = ReadFile(dir / "records.tsv");
    ASSERT_GE(content.size(), 2u);
    // Flip one byte (the char before the trailing newline) without updating
    // records_sha256 in the manifest.
    size_t flip_index = content.size() - 2;
    content[flip_index] = static_cast<char>(content[flip_index] ^ 0x01);
    WriteFile(dir / "records.tsv", content);
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsChecksumMismatchOnSourceManifest) {
    fs::path dir = CopyFixture("checksum-source");
    std::string content = ReadFile(dir / "source.manifest.tsv");
    content += "# corrupted trailer that changes bytes without recomputing sha256\n";
    WriteFile(dir / "source.manifest.tsv", content);
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsWrongColumnCountInRecords) {
    fs::path dir = CopyFixture("column-count");
    // Drop the final tab-separated field from one data row, then recompute
    // the checksum so the checksum check itself does not mask this defect.
    MutateDataLine(dir / "records.tsv", 0, [](const std::string& line) {
        auto last_tab = line.rfind('\t');
        return line.substr(0, last_tab);
    });
    RecomputeChecksum(dir, "records.tsv", "records_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsDuplicateRecordIds) {
    fs::path dir = CopyFixture("dup-record-id");
    std::string original = ReadFile(dir / "records.tsv");
    auto lines = SplitLinesKeepTrailingNewline(original);
    ASSERT_GE(lines.size(), 2u);
    std::string duplicate_row = lines[1];
    AppendDataLine(dir / "records.tsv", duplicate_row);
    SetManifestValue(dir / "dataset.manifest.tsv", "record_count", "9");
    RecomputeChecksum(dir, "records.tsv", "records_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsDuplicatePairIds) {
    fs::path dir = CopyFixture("dup-pair-id");
    auto lines = SplitLinesKeepTrailingNewline(ReadFile(dir / "pairs.tsv"));
    ASSERT_GE(lines.size(), 2u);
    std::string duplicate_row = lines[1];
    AppendDataLine(dir / "pairs.tsv", duplicate_row);
    SetManifestValue(dir / "dataset.manifest.tsv", "pair_count", "7");
    RecomputeChecksum(dir, "pairs.tsv", "pairs_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsUnknownPairEndpoint) {
    fs::path dir = CopyFixture("unknown-endpoint");
    MutateDataLine(dir / "pairs.tsv", 0, [](const std::string& line) {
        // record_a is the second tab-separated field.
        auto first_tab = line.find('\t');
        auto second_tab = line.find('\t', first_tab + 1);
        return line.substr(0, first_tab + 1) + "acm:nonexistent" +
               line.substr(second_tab);
    });
    RecomputeChecksum(dir, "pairs.tsv", "pairs_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsUnsortedRawFeatures) {
    fs::path dir = CopyFixture("unsorted-raw");
    MutateDataLine(dir / "records.tsv", 0, [](const std::string& line) {
        // raw_features_csv is the third tab-separated field: swap its first
        // two comma-separated values so the list is no longer increasing.
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string field;
        while (std::getline(ss, field, '\t')) fields.push_back(field);
        auto comma = fields[2].find(',');
        std::string first = fields[2].substr(0, comma);
        auto second_comma = fields[2].find(',', comma + 1);
        std::string second = fields[2].substr(comma + 1, second_comma - comma - 1);
        std::string swapped =
            second + "," + first + fields[2].substr(second_comma);
        fields[2] = swapped;
        std::string out;
        for (size_t i = 0; i < fields.size(); ++i) {
            if (i) out += "\t";
            out += fields[i];
        }
        return out;
    });
    RecomputeChecksum(dir, "records.tsv", "records_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsDuplicateBucketedFeatures) {
    fs::path dir = CopyFixture("dup-bucketed");
    MutateDataLine(dir / "records.tsv", 0, [](const std::string& line) {
        // bucketed_features_csv is the fifth tab-separated field: duplicate
        // its first value in place of the second, keeping the field count
        // (and thus bucketed_feature_count) unchanged but breaking strict
        // increase.
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string field;
        while (std::getline(ss, field, '\t')) fields.push_back(field);
        auto comma = fields[4].find(',');
        std::string first = fields[4].substr(0, comma);
        auto second_comma = fields[4].find(',', comma + 1);
        std::string rest = fields[4].substr(second_comma);
        fields[4] = first + "," + first + rest;
        std::string out;
        for (size_t i = 0; i < fields.size(); ++i) {
            if (i) out += "\t";
            out += fields[i];
        }
        return out;
    });
    RecomputeChecksum(dir, "records.tsv", "records_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsOutOfUniverseBucketedFeature) {
    fs::path dir = CopyFixture("out-of-universe");
    MutateDataLine(dir / "records.tsv", 0, [](const std::string& line) {
        // Replace the last (largest) bucketed feature with a value equal to
        // the universe size (65536), which is out of range ([0, universe)).
        auto last_tab = line.rfind('\t');
        std::string prefix = line.substr(0, last_tab + 1);
        std::string csv = line.substr(last_tab + 1);
        auto last_comma = csv.rfind(',');
        return prefix + csv.substr(0, last_comma + 1) + "65536";
    });
    RecomputeChecksum(dir, "records.tsv", "records_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsInvalidPairKind) {
    fs::path dir = CopyFixture("invalid-kind");
    MutateDataLine(dir / "pairs.tsv", 0, [](const std::string& line) {
        auto last_tab = line.rfind('\t');
        auto second_last_tab = line.rfind('\t', last_tab - 1);
        return line.substr(0, second_last_tab + 1) + "bogus_kind" +
               line.substr(last_tab);
    });
    RecomputeChecksum(dir, "pairs.tsv", "pairs_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsInvalidLabelForKind) {
    fs::path dir = CopyFixture("invalid-label");
    MutateDataLine(dir / "pairs.tsv", 0, [](const std::string& line) {
        // Force a known_match/sampled_nonmatch row (label 1 or 0) to an
        // out-of-domain label value.
        auto last_tab = line.rfind('\t');
        return line.substr(0, last_tab + 1) + "5";
    });
    RecomputeChecksum(dir, "pairs.tsv", "pairs_sha256");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsRecordCountMismatch) {
    fs::path dir = CopyFixture("record-count-mismatch");
    SetManifestValue(dir / "dataset.manifest.tsv", "record_count", "9");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsPairCountMismatch) {
    fs::path dir = CopyFixture("pair-count-mismatch");
    SetManifestValue(dir / "dataset.manifest.tsv", "pair_count", "7");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

TEST(RealDataset, RejectsMissingManifestFile) {
    fs::path dir = CopyFixture("missing-manifest");
    fs::remove(dir / "dataset.manifest.tsv");
    EXPECT_THROW(LoadRealDataset(dir / "dataset.manifest.tsv"), std::runtime_error);
    fs::remove_all(dir);
}

// ---------------------------------------------------------------------------
// Cross-language golden: canonical_feature_hash / bucket_features
// ---------------------------------------------------------------------------
// Independent C++ reimplementation of the piccard-real-feature-v1 primitives
// defined in scripts/prepare_real_datasets.py, pinned against the same
// known-answer vectors as tests/scripts/test_real_dataset_preprocess.py's
// test_canonical_feature_hash_known_answer and
// test_bucket_features_mods_sorts_and_dedups. This is a standalone
// verification of the shared hash-domain contract; it does not exercise
// LoadRealDataset.

namespace {

uint64_t CanonicalFeatureHashReference(const std::string& feature) {
    static const char kDomain[] = "piccard-real-feature-v1";
    std::string input(kDomain, sizeof(kDomain) - 1);
    input.push_back('\0');
    input += feature;

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("test helper: failed to allocate SHA-256 context");
    }
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                     EVP_DigestUpdate(ctx, input.data(), input.size()) == 1 &&
                     EVP_DigestFinal_ex(ctx, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || digest_size != 32) {
        throw std::runtime_error("test helper: SHA-256 computation failed");
    }
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | digest[static_cast<size_t>(i)];
    }
    return value;
}

std::vector<uint64_t> BucketFeaturesReference(const std::vector<uint64_t>& features,
                                               uint64_t universe) {
    std::vector<uint64_t> bucketed;
    bucketed.reserve(features.size());
    for (uint64_t f : features) bucketed.push_back(f % universe);
    std::sort(bucketed.begin(), bucketed.end());
    bucketed.erase(std::unique(bucketed.begin(), bucketed.end()), bucketed.end());
    return bucketed;
}

}  // namespace

TEST(RealDataset, CanonicalFeatureHashMatchesPythonKnownAnswerVector) {
    // Pinned against tests/scripts/test_real_dataset_preprocess.py's
    // test_canonical_feature_hash_known_answer: SHA256("piccard-real-feature-v1"
    // || 0x00 || "title=abc"), first 8 bytes big-endian.
    EXPECT_EQ(CanonicalFeatureHashReference("title=abc"), 9922236350145813300ull);
}

TEST(RealDataset, CanonicalFeatureHashIsDeterministicAndDistinguishesInput) {
    uint64_t a = CanonicalFeatureHashReference("title=abc");
    uint64_t b = CanonicalFeatureHashReference("title=abd");
    EXPECT_EQ(a, CanonicalFeatureHashReference("title=abc"));
    EXPECT_NE(a, b);
}

TEST(RealDataset, BucketFeaturesModsSortsAndDedupsMatchesPythonKnownAnswerVector) {
    // Pinned against tests/scripts/test_real_dataset_preprocess.py's
    // test_bucket_features_mods_sorts_and_dedups: 70000 % 65536 == 4464;
    // 5 % 65536 == 65541 % 65536 == 5 (collapse via dedup).
    std::vector<uint64_t> result =
        BucketFeaturesReference({70000, 5, 65541, 5}, 65536);
    EXPECT_EQ(result, (std::vector<uint64_t>{5, 4464}));
}
