// Work #5 DBLP-ACM STD192 local-encoding diagnostic.  This translation unit
// deliberately depends only on core/data components, and derives a public
// signature before invoking a local encoder.
#include "real_encoding_driver.h"

#include "core/minhash.h"
#include "core/onehot_encoder.h"
#include "core/sqrt_encoder.h"
#include "data/real_dataset.h"
#include "data/real_dataset_metrics.h"
#include "util/params.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
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

constexpr char kProfile[] = "work5-std192-t40-single-trial";
constexpr char kOneHotMethod[] = "piccard_encode";
constexpr char kSqrtMethod[] = "piccard_sqrt_encode";

void Require(const bool condition, const std::string& detail) {
    if (!condition) throw std::invalid_argument(detail);
}

std::string ReadFileBytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open input file: " + path.string());
    std::ostringstream bytes;
    bytes << input.rdbuf();
    if (input.bad()) throw std::runtime_error("cannot read input file: " + path.string());
    return bytes.str();
}

std::array<unsigned char, 32> Sha256Raw(const std::string& data) {
    std::array<unsigned char, 32> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) throw std::runtime_error("cannot allocate SHA-256 state");
    const bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(context, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || digest_size != 32) throw std::runtime_error("SHA-256 failed");
    return digest;
}

std::string Hex(const std::array<unsigned char, 32>& raw) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : raw) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

void AppendU32(std::string& output, const uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

void AppendU64(std::string& output, const uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

uint64_t DeriveHashSeed(const uint64_t root_seed,
                        const std::array<unsigned char, 32>& dataset_hash,
                        const uint32_t k, const uint32_t m,
                        const std::string& profile_id,
                        const std::string& method) {
    std::string payload("piccard-real-encoding-crs-v1\0", 29);
    AppendU64(payload, root_seed);
    payload.append(reinterpret_cast<const char*>(dataset_hash.data()), dataset_hash.size());
    AppendU32(payload, k);
    AppendU32(payload, m);
    AppendU32(payload, static_cast<uint32_t>(profile_id.size()));
    payload.append(profile_id);
    AppendU32(payload, static_cast<uint32_t>(method.size()));
    payload.append(method);
    const auto digest = Sha256Raw(payload);
    uint64_t result = 0;
    for (size_t index = 0; index < 8; ++index) result = (result << 8) | digest[index];
    return result;
}

void AtomicWriteNew(const fs::path& path, const std::string& data) {
    if (fs::exists(path)) throw std::runtime_error("refusing to overwrite: " + path.string());
    const fs::path parent = path.parent_path();
    if (parent.empty() || !fs::is_directory(parent)) {
        throw std::runtime_error("output parent is missing: " + parent.string());
    }
    const fs::path temporary = parent / ("." + path.filename().string() + ".tmp");
    if (fs::exists(temporary)) {
        throw std::runtime_error("temporary output already exists: " + temporary.string());
    }
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("cannot create output: " + temporary.string());
        output.write(data.data(), static_cast<std::streamsize>(data.size()));
        output.flush();
        if (!output) {
            std::error_code remove_error;
            fs::remove(temporary, remove_error);
            throw std::runtime_error("cannot write output: " + temporary.string());
        }
    }
    // A rename can replace a destination that appeared after our initial
    // existence check.  Hard-link publication is the no-replace half of the
    // temp+publish protocol: a concurrent or prior terminal row wins and this
    // first attempt fails closed instead of being overwritten.
    std::error_code publish_error;
    fs::create_hard_link(temporary, path, publish_error);
    if (publish_error) {
        std::error_code remove_error;
        fs::remove(temporary, remove_error);
        throw std::runtime_error("cannot publish output without overwrite: " +
                                 publish_error.message());
    }
    std::error_code remove_error;
    fs::remove(temporary, remove_error);
    if (remove_error) throw std::runtime_error("cannot remove published temporary output: " +
                                               remove_error.message());
}

size_t SelectMedianPair(
    const data::RealDataset& dataset,
    const std::unordered_map<std::string, const data::RealDatasetRecord*>& records) {
    Require(!dataset.pairs.empty(), "processed dataset contains no pairs");
    std::vector<uint64_t> sizes;
    sizes.reserve(dataset.pairs.size());
    for (const auto& pair : dataset.pairs) {
        const auto a = records.find(pair.record_a);
        const auto b = records.find(pair.record_b);
        if (a == records.end() || b == records.end()) {
            throw std::runtime_error("pair references unknown record");
        }
        sizes.push_back(a->second->bucketed_features.size() + b->second->bucketed_features.size());
    }
    std::sort(sizes.begin(), sizes.end());
    const double median = sizes.size() % 2 == 0
        ? (static_cast<double>(sizes[sizes.size() / 2 - 1]) +
           static_cast<double>(sizes[sizes.size() / 2])) / 2.0
        : static_cast<double>(sizes[sizes.size() / 2]);
    size_t selected = 0;
    double best_distance = std::numeric_limits<double>::infinity();
    std::string best_id;
    for (size_t index = 0; index < dataset.pairs.size(); ++index) {
        const auto& pair = dataset.pairs[index];
        const uint64_t sum = records.at(pair.record_a)->bucketed_features.size() +
                             records.at(pair.record_b)->bucketed_features.size();
        const double distance = std::abs(static_cast<double>(sum) - median);
        if (distance < best_distance || (distance == best_distance &&
                                        (best_id.empty() || pair.id < best_id))) {
            selected = index;
            best_distance = distance;
            best_id = pair.id;
        }
    }
    return selected;
}

uint32_t ExactSqrtBase(const uint32_t m) {
    uint32_t base = 1;
    while (base < m / base) ++base;
    Require(base * base == m, "piccard_sqrt_encode requires square m");
    return base;
}

void VerifyDecoded(const std::vector<uint32_t>& decoded,
                   const std::vector<uint64_t>& signature, const uint32_t m) {
    Require(decoded.size() == signature.size(), "encoder decode size mismatch");
    for (size_t index = 0; index < signature.size(); ++index) {
        Require(decoded[index] == signature[index] % m,
                "encoder decode content mismatch");
    }
}

std::string EncodingHeader() {
    return "profile_id,run_class,target_security_bits,comparison_eligible,"
           "comparison_scope,primitive,protocol_model,cost_scope,"
           "secure_division_included,measurement_kind,dataset,variant,"
           "dataset_manifest_sha256,records_sha256,pairs_sha256,pair_id,"
           "pair_kind,label,record_a,record_b,k,m,method,timing_trials,"
           "timing_pair,root_seed,hash_seed,encoder_warmup_calls,"
           "timed_encoder_calls,correctness_encoder_calls,"
           "signature_derivation_timed,phase_encode_ms,encoded_slots,"
           "correctness_status,measurement_status\n";
}

std::string EncodingWorkload(const std::string& dataset_sha, const std::string& pair_id,
                             const RealEncodingCliArgs& args, const uint64_t hash_seed,
                             const uint64_t encoded_slots) {
    std::ostringstream output;
    output << "key\tvalue\n"
           << "schema_version\tpiccard-real-encoding-workload-v1\n"
           << "dataset_manifest_sha256\t" << dataset_sha << '\n'
           << "pair_id\t" << pair_id << '\n'
           << "k\t" << args.k << '\n'
           << "m\t" << args.m << '\n'
           << "profile_id\t" << args.profile_id << '\n'
           << "method\t" << args.method << '\n'
           << "root_seed\t" << args.root_seed << '\n'
           << "hash_seed\t" << hash_seed << '\n'
           << "trials\t" << args.trials << '\n'
           << "timing_pair\t" << args.timing_pair << '\n'
           << "encoder_warmup_calls\t1\n"
           << "timed_encoder_calls\t1\n"
           << "correctness_encoder_calls\t1\n"
           << "signature_derivation_timed\tfalse\n"
           << "encoded_slots\t" << encoded_slots << '\n';
    return output.str();
}

}  // namespace

int RunRealEncodingMode(const RealEncodingCliArgs& args) {
    Require(!args.dataset_manifest_path.empty(), "--dataset-manifest is required");
    Require(args.profile_id == kProfile, "--mode=encoding requires the Work #5 STD192 profile");
    Require(args.method == kOneHotMethod || args.method == kSqrtMethod,
            "--mode=encoding requires piccard_encode or piccard_sqrt_encode");
    Require(args.k == 128 && args.m == 64, "--mode=encoding freezes k=128,m=64");
    Require(args.trials == 1, "--mode=encoding freezes trials=1");
    Require(args.timing_pair == "median", "--timing-pair only supports median");
    Require(args.root_seed == 20260729, "--mode=encoding freezes seed=20260729");
    Require(!args.csv_path.empty() && !args.workload_manifest_out_path.empty(),
            "--mode=encoding requires output paths");

    const fs::path manifest_path(args.dataset_manifest_path);
    const std::string manifest_bytes = ReadFileBytes(manifest_path);
    const auto dataset_sha_raw = Sha256Raw(manifest_bytes);
    const std::string dataset_sha = Hex(dataset_sha_raw);
    const data::RealDataset dataset = data::LoadRealDataset(manifest_path);
    Require(dataset.dataset == "dblp_acm" && dataset.variant == "dblp_acm_u65536" &&
                dataset.universe_size == 65536,
            "--mode=encoding requires the DBLP-ACM U=65536 processed dataset");

    std::unordered_map<std::string, const data::RealDatasetRecord*> records;
    records.reserve(dataset.records.size());
    for (const auto& record : dataset.records) records.emplace(record.id, &record);
    const auto& pair = dataset.pairs[SelectMedianPair(dataset, records)];
    const auto& record_a = *records.at(pair.record_a);

    const uint64_t hash_seed = DeriveHashSeed(args.root_seed, dataset_sha_raw, args.k,
                                               args.m, args.profile_id, args.method);
    const MinHasher hasher(args.k, std::numeric_limits<uint64_t>::max(), hash_seed);
    // Signature derivation is intentionally complete before the warmup/timer.
    const std::vector<uint64_t> signature = hasher.ComputeSignature(record_a.bucketed_features);

    PiccardParams encoder_params;
    encoder_params.k = args.k;
    encoder_params.m = args.m;
    uint64_t slots = 0;
    double elapsed_ms = 0.0;
    if (args.method == kOneHotMethod) {
        encoder_params.ring_dim = NextPowerOf2(args.k * args.m);
        OneHotEncoder encoder(encoder_params);
        const auto warmup = encoder.Encode(signature);
        (void)warmup;
        const auto begin = std::chrono::steady_clock::now();
        const auto timed = encoder.Encode(signature);
        const auto end = std::chrono::steady_clock::now();
        const auto correctness = encoder.Encode(signature);
        VerifyDecoded(encoder.Decode(correctness), signature, args.m);
        slots = timed.size();
        elapsed_ms = std::chrono::duration<double, std::milli>(end - begin).count();
    } else {
        encoder_params.sqrt_base = ExactSqrtBase(args.m);
        encoder_params.ring_dim = NextPowerOf2(args.k * 2 * encoder_params.sqrt_base);
        SqrtEncoder encoder(encoder_params);
        const auto warmup = encoder.Encode(signature);
        (void)warmup;
        const auto begin = std::chrono::steady_clock::now();
        const auto timed = encoder.Encode(signature);
        const auto end = std::chrono::steady_clock::now();
        const auto correctness = encoder.Encode(signature);
        VerifyDecoded(encoder.Decode(correctness), signature, args.m);
        slots = timed.size();
        elapsed_ms = std::chrono::duration<double, std::milli>(end - begin).count();
    }

    const std::string workload = EncodingWorkload(dataset_sha, pair.id, args, hash_seed, slots);
    std::ostringstream csv;
    csv << EncodingHeader()
        << args.profile_id << ",smoke,192,false,encoding-only-diagnostic,"
        << (args.method == kOneHotMethod ? "onehot-encoding" : "sqrt-encoding") << ','
        << (args.method == kOneHotMethod ? "piccard-local-encoding" : "piccard-sqrt-local-encoding")
        << ",encoding-only,false,local-encoder,"
        << dataset.dataset << ',' << dataset.variant << ',' << dataset_sha << ','
        << dataset.records_sha256 << ',' << dataset.pairs_sha256 << ',' << pair.id << ','
        << pair.kind << ',' << pair.label << ',' << pair.record_a << ',' << pair.record_b << ','
        << args.k << ',' << args.m << ',' << args.method << ',' << args.trials << ','
        << args.timing_pair << ',' << args.root_seed << ',' << hash_seed
        << ",1,1,1,false," << data::FormatReal17(elapsed_ms) << ',' << slots
        << ",PASS,measured\n";

    AtomicWriteNew(fs::path(args.workload_manifest_out_path), workload);
    try {
        AtomicWriteNew(fs::path(args.csv_path), csv.str());
    } catch (...) {
        std::error_code remove_error;
        fs::remove(fs::path(args.workload_manifest_out_path), remove_error);
        throw;
    }
    return 0;
}

}  // namespace piccard::bench
