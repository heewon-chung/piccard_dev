// Plaintext DBLP calibration/evaluation threshold driver.  This translation
// unit intentionally has no cryptosystem dependency: it loads processed
// feature vectors, derives MinHash signatures, and writes deterministic CSV
// and TSV artifacts only.
#include "real_threshold_driver.h"

#include "core/minhash.h"
#include "data/real_dataset.h"
#include "data/real_dataset_metrics.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace piccard::bench {
namespace {

namespace fs = std::filesystem;

using piccard::MinHasher;
using piccard::data::FormatReal17;
using piccard::data::LoadRealDataset;
using piccard::data::RealDataset;
using piccard::data::RealDatasetPair;
using piccard::data::RealDatasetRecord;

constexpr uint32_t kFrozenK = 128;
constexpr uint32_t kFrozenM = 64;
constexpr const char* kDataset = "dblp_acm";
constexpr const char* kVariant = "dblp_acm_u65536";
constexpr const char* kSplitDomain = "piccard-dblp-threshold-split-v1";
constexpr const char* kTrialDomain = "piccard-dblp-threshold-eval-v1";
constexpr const char* kWorkloadSchema = "piccard-real-threshold-workload-v1";
constexpr const char* kCsvSchema = "piccard-real-threshold-v1";

constexpr const char* kThresholdHeader =
    "schema_version,dataset,variant,dataset_manifest_sha256,records_sha256,"
    "pairs_sha256,pair_id,pair_kind,label,record_a,record_b,k,m,"
    "hash_randomness,root_seed,split,rank_position,threshold_trial_index,"
    "hash_seed,match_count,decision,label_truth,label_outcome,"
    "exact_j_truth,exact_j_outcome,exact_jaccard_bucketed,"
    "requested_j_threshold,tau_count,realized_j_tau,calibration_fpr,"
    "calibration_fnr,calibration_balanced_error,calibration_digest,"
    "evaluation_digest,threshold_workload_sha256\n";
constexpr const char* kThresholdWorkloadRowsHeader =
    "pair_id\tlabel\tsplit\trank_position\trecord_a\trecord_b\t"
    "exact_jaccard_bucketed\n";

struct PairData {
    const RealDatasetPair* pair = nullptr;
    const RealDatasetRecord* record_a = nullptr;
    const RealDatasetRecord* record_b = nullptr;
    double exact_jaccard = 0.0;
    uint32_t label = 0;
    std::string split;
    uint32_t rank_position = 0;
};

struct ThresholdChoice {
    double requested = 0.0;
    uint32_t tau_count = 0;
    double realized = 0.0;
    double fpr = 0.0;
    double fnr = 0.0;
    double balanced_error = 0.0;
};

void AppendU32Be(uint32_t value, std::string& out) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> static_cast<unsigned>(shift)) & 0xffU));
    }
}

void AppendU64Be(uint64_t value, std::string& out) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> static_cast<unsigned>(shift)) & 0xffU));
    }
}

std::array<unsigned char, 32> Sha256Raw(const std::string& data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> buffer{};
    unsigned int size = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("real_threshold_driver: SHA-256 context allocation failed");
    }
    const bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(context, buffer.data(), &size) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || size != 32) {
        throw std::runtime_error("real_threshold_driver: SHA-256 computation failed");
    }
    std::array<unsigned char, 32> result{};
    std::copy(buffer.begin(), buffer.begin() + 32, result.begin());
    return result;
}

std::string Sha256Hex(const std::string& data) {
    const auto digest = Sha256Raw(data);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result(64, '0');
    for (size_t i = 0; i < digest.size(); ++i) {
        result[2 * i] = kHex[digest[i] >> 4];
        result[2 * i + 1] = kHex[digest[i] & 0x0fU];
    }
    return result;
}

uint64_t DigestU64(const std::string& payload) {
    const auto digest = Sha256Raw(payload);
    uint64_t result = 0;
    for (size_t i = 0; i < 8; ++i) {
        result = (result << 8) | digest[i];
    }
    return result;
}

std::string ReadBytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("real_threshold_driver: cannot open '" + path.string() + "'");
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (input.bad()) {
        throw std::runtime_error("real_threshold_driver: read failed for '" + path.string() + "'");
    }
    return buffer.str();
}

void RefuseExisting(const fs::path& path) {
    if (fs::exists(path)) {
        throw std::runtime_error("real_threshold_driver: refusing to overwrite '" +
                                 path.string() + "'");
    }
}

void AtomicWrite(const fs::path& path, const std::string& bytes) {
    if (path.has_parent_path()) {
        std::error_code error;
        fs::create_directories(path.parent_path(), error);
        if (error) {
            throw std::runtime_error("real_threshold_driver: cannot create output directory: " +
                                     error.message());
        }
    }
    const fs::path temporary = path.string() + ".tmp";
    RefuseExisting(temporary);
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) {
            throw std::runtime_error("real_threshold_driver: cannot create temporary output");
        }
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) {
            std::error_code ignored;
            fs::remove(temporary, ignored);
            throw std::runtime_error("real_threshold_driver: output write failed");
        }
    }
    std::error_code error;
    fs::rename(temporary, path, error);
    if (error) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        throw std::runtime_error("real_threshold_driver: output publication failed: " +
                                 error.message());
    }
}

void RequireNonEmpty(const std::string& value, const char* name) {
    if (value.empty()) {
        throw std::invalid_argument(std::string("--") + name + " is required");
    }
}

std::array<unsigned char, 32> PairRank(const std::string& pair_id) {
    std::string payload(kSplitDomain);
    payload.push_back('\0');
    payload.append(pair_id);
    return Sha256Raw(payload);
}

uint64_t TrialSeed(uint64_t root_seed, const std::string& pair_id,
                   uint64_t trial_index) {
    std::string payload(kTrialDomain);
    payload.push_back('\0');
    AppendU64Be(root_seed, payload);
    AppendU32Be(static_cast<uint32_t>(pair_id.size()), payload);
    payload.append(pair_id);
    AppendU64Be(trial_index, payload);
    return DigestU64(payload);
}

struct Overlap {
    uint64_t intersection = 0;
    uint64_t union_size = 0;
};

Overlap ComputeOverlap(const std::vector<uint64_t>& left,
                       const std::vector<uint64_t>& right) {
    Overlap result;
    size_t i = 0;
    size_t j = 0;
    while (i < left.size() && j < right.size()) {
        if (left[i] == right[j]) {
            ++result.intersection;
            ++result.union_size;
            ++i;
            ++j;
        } else if (left[i] < right[j]) {
            ++result.union_size;
            ++i;
        } else {
            ++result.union_size;
            ++j;
        }
    }
    result.union_size += static_cast<uint64_t>(left.size() - i + right.size() - j);
    return result;
}

double ExactJaccard(const RealDatasetRecord& left, const RealDatasetRecord& right) {
    const Overlap overlap = ComputeOverlap(left.bucketed_features, right.bucketed_features);
    if (overlap.union_size == 0) {
        throw std::runtime_error("real_threshold_driver: zero exact-J denominator");
    }
    return static_cast<double>(overlap.intersection) /
           static_cast<double>(overlap.union_size);
}

std::vector<PairData> SelectPairs(const RealDataset& dataset, uint64_t max_pairs,
                                  std::map<std::string, const RealDatasetRecord*>& records) {
    if (max_pairs == 0) {
        throw std::invalid_argument("--max-pairs must be > 0");
    }
    std::vector<PairData> all;
    all.reserve(dataset.pairs.size());
    for (const auto& pair : dataset.pairs) {
        if (pair.label != 0 && pair.label != 1) {
            throw std::invalid_argument(
                "real_threshold_driver: DBLP threshold labels must be 0 or 1");
        }
        const auto left = records.find(pair.record_a);
        const auto right = records.find(pair.record_b);
        if (left == records.end() || right == records.end()) {
            throw std::runtime_error("real_threshold_driver: unresolved pair endpoint");
        }
        PairData data;
        data.pair = &pair;
        data.record_a = left->second;
        data.record_b = right->second;
        data.exact_jaccard = ExactJaccard(*data.record_a, *data.record_b);
        data.label = static_cast<uint32_t>(pair.label);
        all.push_back(data);
    }
    if (all.empty()) {
        throw std::runtime_error("real_threshold_driver: no pairs available");
    }

    const size_t requested = std::min<size_t>(all.size(), static_cast<size_t>(max_pairs));
    std::vector<PairData> selected;
    selected.reserve(requested);
    std::vector<PairData> by_label[2];
    for (const auto& pair : all) by_label[pair.label].push_back(pair);
    if (requested >= 4 && by_label[0].size() >= 2 && by_label[1].size() >= 2) {
        size_t take_zero = requested / 2;
        size_t take_one = requested - take_zero;
        if (take_zero > by_label[0].size()) {
            take_zero = by_label[0].size();
            take_one = requested - take_zero;
        }
        if (take_one > by_label[1].size()) {
            take_one = by_label[1].size();
            take_zero = requested - take_one;
        }
        if (take_zero <= by_label[0].size() && take_one <= by_label[1].size()) {
            selected.insert(selected.end(), by_label[0].begin(), by_label[0].begin() + take_zero);
            selected.insert(selected.end(), by_label[1].begin(), by_label[1].begin() + take_one);
        }
    }
    if (selected.size() != requested) {
        selected.assign(all.begin(), all.begin() + requested);
    }
    return selected;
}

std::vector<PairData> BuildSplit(std::vector<PairData> selected) {
    std::vector<PairData> by_label[2];
    for (auto& pair : selected) by_label[pair.label].push_back(pair);
    std::vector<PairData> output;
    output.reserve(selected.size());
    for (uint32_t label = 0; label < 2; ++label) {
        std::sort(by_label[label].begin(), by_label[label].end(),
                  [](const PairData& left, const PairData& right) {
                      const auto left_rank = PairRank(left.pair->id);
                      const auto right_rank = PairRank(right.pair->id);
                      if (left_rank != right_rank) return left_rank < right_rank;
                      return left.pair->id < right.pair->id;
                  });
        for (uint32_t rank = 0; rank < by_label[label].size(); ++rank) {
            by_label[label][rank].rank_position = rank;
            by_label[label][rank].split = (rank % 2 == 0) ? "calibration" : "evaluation";
            output.push_back(by_label[label][rank]);
        }
    }
    return output;
}

void RequireSplitClassDenominators(const std::vector<PairData>& pairs) {
    for (const char* split : {"calibration", "evaluation"}) {
        size_t negative = 0;
        size_t positive = 0;
        for (const auto& pair : pairs) {
            if (pair.split != split) continue;
            if (pair.label == 0) {
                ++negative;
            } else {
                ++positive;
            }
        }
        if (negative == 0 || positive == 0) {
            throw std::runtime_error(
                std::string("real_threshold_driver: zero ") + split +
                " class denominator");
        }
    }
}

std::vector<double> CandidateThresholds(const std::vector<PairData>& pairs) {
    std::vector<double> values;
    for (const auto& pair : pairs) {
        if (pair.split == "calibration") values.push_back(pair.exact_jaccard);
    }
    if (values.empty()) throw std::runtime_error("real_threshold_driver: empty calibration split");
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    std::vector<double> candidates = values;
    for (size_t i = 1; i < values.size(); ++i) {
        candidates.push_back((values[i - 1] + values[i]) / 2.0);
    }
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

uint32_t TauCount(double requested, uint32_t k, uint32_t m) {
    const double value = static_cast<double>(k) *
                         (1.0 / static_cast<double>(m) +
                          (1.0 - 1.0 / static_cast<double>(m)) * requested);
    const auto tau = static_cast<uint32_t>(std::ceil(value));
    return std::max<uint32_t>(1, std::min<uint32_t>(k, tau));
}

double RealizedBoundary(uint32_t tau, uint32_t k, uint32_t m) {
    return (static_cast<double>(tau) / static_cast<double>(k) -
            1.0 / static_cast<double>(m)) /
           (1.0 - 1.0 / static_cast<double>(m));
}

ThresholdChoice SelectThreshold(const std::vector<PairData>& pairs,
                                const std::vector<double>& candidates,
                                uint32_t k, uint32_t m) {
    bool initialized = false;
    ThresholdChoice best;
    for (double requested : candidates) {
        uint64_t false_positive = 0;
        uint64_t false_negative = 0;
        uint64_t negative = 0;
        uint64_t positive = 0;
        for (const auto& pair : pairs) {
            if (pair.split != "calibration") continue;
            const bool decision = pair.exact_jaccard >= requested;
            if (pair.label == 0) {
                ++negative;
                if (decision) ++false_positive;
            } else {
                ++positive;
                if (!decision) ++false_negative;
            }
        }
        if (negative == 0 || positive == 0) {
            throw std::runtime_error("real_threshold_driver: zero calibration class denominator");
        }
        ThresholdChoice candidate;
        candidate.requested = requested;
        candidate.tau_count = TauCount(requested, k, m);
        candidate.realized = RealizedBoundary(candidate.tau_count, k, m);
        candidate.fpr = static_cast<double>(false_positive) / static_cast<double>(negative);
        candidate.fnr = static_cast<double>(false_negative) / static_cast<double>(positive);
        candidate.balanced_error = (candidate.fpr + candidate.fnr) / 2.0;
        if (!initialized || candidate.balanced_error < best.balanced_error ||
            (candidate.balanced_error == best.balanced_error &&
             candidate.requested > best.requested)) {
            best = candidate;
            initialized = true;
        }
    }
    return best;
}

std::string Outcome(bool decision, bool truth) {
    if (decision && truth) return "TP";
    if (!decision && !truth) return "TN";
    if (decision) return "FP";
    return "FN";
}

uint32_t MatchCount(const PairData& pair, uint64_t seed, uint32_t k, uint32_t m) {
    const MinHasher hasher(k, std::numeric_limits<uint64_t>::max(), seed);
    const auto left = hasher.ComputeSignature(pair.record_a->bucketed_features);
    const auto right = hasher.ComputeSignature(pair.record_b->bucketed_features);
    uint32_t matches = 0;
    for (uint32_t i = 0; i < k; ++i) {
        if (left[i] % m == right[i] % m) ++matches;
    }
    return matches;
}

std::string SerializeRows(const std::vector<PairData>& pairs) {
    std::ostringstream output;
    output << kThresholdWorkloadRowsHeader;
    for (const auto& pair : pairs) {
        output << pair.pair->id << '\t' << pair.label << '\t' << pair.split << '\t'
               << pair.rank_position << '\t' << pair.pair->record_a << '\t'
               << pair.pair->record_b << '\t' << FormatReal17(pair.exact_jaccard) << '\n';
    }
    return output.str();
}

std::string SerializeManifest(const RealThresholdCliArgs& args,
                              const std::string& dataset_sha,
                              const std::string& rows_sha,
                              const std::string& calibration_sha,
                              const std::string& evaluation_sha,
                              size_t calibration_count, size_t evaluation_count,
                              const std::vector<double>& candidates,
                              const ThresholdChoice& choice) {
    std::ostringstream output;
    output << "key\tvalue\n"
           << "schema_version\t" << kWorkloadSchema << '\n'
           << "dataset_manifest_sha256\t" << dataset_sha << '\n'
           << "rows_sha256\t" << rows_sha << '\n'
           << "calibration_rows_sha256\t" << calibration_sha << '\n'
           << "evaluation_rows_sha256\t" << evaluation_sha << '\n'
           << "k\t" << args.k << '\n'
           << "m\t" << args.m << '\n'
           << "root_seed\t" << args.root_seed << '\n'
           << "max_pairs\t" << args.max_pairs << '\n'
           << "threshold_trials\t" << args.threshold_trials << '\n'
           << "hash_randomness\t" << args.hash_randomness << '\n'
           << "pair_selection\tbalanced-label-prefix\n"
           << "split_domain\t" << kSplitDomain << '\n'
           << "trial_seed_domain\t" << kTrialDomain << '\n'
           << "calibration_pair_count\t" << calibration_count << '\n'
           << "evaluation_pair_count\t" << evaluation_count << '\n'
           << "candidate_count\t" << candidates.size() << '\n';
    for (size_t index = 0; index < candidates.size(); ++index) {
        output << "candidate." << index << "\t" << FormatReal17(candidates[index]) << '\n';
    }
    output << "selected_requested_j_threshold\t" << FormatReal17(choice.requested) << '\n'
           << "tau_count\t" << choice.tau_count << '\n'
           << "realized_j_tau\t" << FormatReal17(choice.realized) << '\n'
           << "calibration_fpr\t" << FormatReal17(choice.fpr) << '\n'
           << "calibration_fnr\t" << FormatReal17(choice.fnr) << '\n'
           << "calibration_balanced_error\t" << FormatReal17(choice.balanced_error) << '\n';
    return output.str();
}

std::string EvaluationDigest(const std::vector<PairData>& pairs) {
    std::ostringstream output;
    for (const auto& pair : pairs) {
        if (pair.split == "evaluation") {
            output << pair.pair->id << '\t' << pair.label << '\t' << pair.rank_position
                   << '\t' << FormatReal17(pair.exact_jaccard) << '\n';
        }
    }
    return Sha256Hex(output.str());
}

std::string CalibrationDigest(const std::vector<PairData>& pairs) {
    std::ostringstream output;
    for (const auto& pair : pairs) {
        if (pair.split == "calibration") {
            output << pair.pair->id << '\t' << pair.label << '\t' << pair.rank_position
                   << '\t' << FormatReal17(pair.exact_jaccard) << '\n';
        }
    }
    return Sha256Hex(output.str());
}

}  // namespace

int RunRealThresholdMode(const RealThresholdCliArgs& args) {
    RequireNonEmpty(args.dataset_manifest_path, "dataset-manifest");
    RequireNonEmpty(args.hash_randomness, "hash_randomness");
    RequireNonEmpty(args.csv_path, "csv");
    RequireNonEmpty(args.workload_manifest_out_path, "workload-manifest-out");
    RequireNonEmpty(args.workload_rows_out_path, "workload-rows-out");
    if (args.k != kFrozenK || args.m != kFrozenM) {
        throw std::invalid_argument(
            "real_threshold_driver: DBLP threshold freezes --k=128 and --m=64");
    }
    if (args.threshold_trials == 0) {
        throw std::invalid_argument("--threshold-trials must be > 0");
    }
    if (args.hash_randomness != "resampled") {
        throw std::invalid_argument(
            "real_threshold_driver: --hash_randomness must be resampled");
    }

    const fs::path dataset_manifest_path(args.dataset_manifest_path);
    const std::string dataset_manifest_bytes = ReadBytes(dataset_manifest_path);
    const std::string dataset_manifest_sha = Sha256Hex(dataset_manifest_bytes);
    const RealDataset dataset = LoadRealDataset(dataset_manifest_path);
    if (dataset.dataset != kDataset || dataset.variant != kVariant ||
        dataset.universe_size != 65536) {
        throw std::invalid_argument(
            "real_threshold_driver: threshold mode accepts only dblp_acm_u65536");
    }

    std::map<std::string, const RealDatasetRecord*> records;
    for (const auto& record : dataset.records) records.emplace(record.id, &record);
    std::vector<PairData> pairs = BuildSplit(SelectPairs(dataset, args.max_pairs, records));
    RequireSplitClassDenominators(pairs);
    const auto candidates = CandidateThresholds(pairs);
    const ThresholdChoice choice = SelectThreshold(pairs, candidates, args.k, args.m);
    const std::string workload_rows = SerializeRows(pairs);
    const std::string calibration_digest = CalibrationDigest(pairs);
    const std::string evaluation_digest = EvaluationDigest(pairs);
    const std::string workload_manifest = SerializeManifest(
        args, dataset_manifest_sha, Sha256Hex(workload_rows), calibration_digest,
        evaluation_digest,
        std::count_if(pairs.begin(), pairs.end(), [](const PairData& p) {
            return p.split == "calibration";
        }),
        std::count_if(pairs.begin(), pairs.end(), [](const PairData& p) {
            return p.split == "evaluation";
        }),
        candidates, choice);
    const std::string workload_sha = Sha256Hex(workload_manifest);

    std::ostringstream csv;
    csv << kThresholdHeader;
    for (const auto& pair : pairs) {
        if (pair.split != "evaluation") continue;
        for (uint32_t trial = 0; trial < args.threshold_trials; ++trial) {
            const uint64_t hash_seed = TrialSeed(args.root_seed, pair.pair->id, trial);
            const uint32_t match_count = MatchCount(pair, hash_seed, args.k, args.m);
            const bool decision = match_count >= choice.tau_count;
            const bool label_truth = pair.label == 1;
            const bool exact_j_truth = pair.exact_jaccard >= choice.realized;
            csv << kCsvSchema << ',' << dataset.dataset << ',' << dataset.variant << ','
                << dataset_manifest_sha << ',' << dataset.records_sha256 << ','
                << dataset.pairs_sha256 << ',' << pair.pair->id << ',' << pair.pair->kind
                << ',' << pair.pair->label << ',' << pair.pair->record_a << ','
                << pair.pair->record_b << ',' << args.k << ',' << args.m << ','
                << args.hash_randomness << ',' << args.root_seed << ',' << pair.split << ','
                << pair.rank_position << ',' << trial << ',' << hash_seed << ','
                << match_count << ',' << (decision ? 1 : 0) << ','
                << pair.pair->label << ',' << Outcome(decision, label_truth) << ','
                << (exact_j_truth ? 1 : 0) << ',' << Outcome(decision, exact_j_truth) << ','
                << FormatReal17(pair.exact_jaccard) << ',' << FormatReal17(choice.requested)
                << ',' << choice.tau_count << ',' << FormatReal17(choice.realized) << ','
                << FormatReal17(choice.fpr) << ',' << FormatReal17(choice.fnr) << ','
                << FormatReal17(choice.balanced_error) << ',' << calibration_digest << ','
                << evaluation_digest << ',' << workload_sha << '\n';
        }
    }

    const fs::path csv_path(args.csv_path);
    const fs::path manifest_path(args.workload_manifest_out_path);
    const fs::path rows_path(args.workload_rows_out_path);
    RefuseExisting(csv_path);
    RefuseExisting(manifest_path);
    RefuseExisting(rows_path);
    AtomicWrite(rows_path, workload_rows);
    AtomicWrite(manifest_path, workload_manifest);
    AtomicWrite(csv_path, csv.str());
    return 0;
}

}  // namespace piccard::bench
