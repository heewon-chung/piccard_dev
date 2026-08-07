#include "comparison_workload.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <tuple>
#include <utility>

#include <unistd.h>

namespace piccard {
namespace benchmark {
namespace {

constexpr char kWorkloadDomain[] = "piccard-review-workload-v1";
constexpr char kTrialDomain[] = "piccard-review-trial-v1";
constexpr char kSetDomain[] = "piccard-review-set-v1";
constexpr char kWarmupHashDomain[] = "piccard-review-hash-warmup-v1";
constexpr char kTimingHashDomain[] = "piccard-review-hash-timing-v1";
constexpr char kAccuracyHashDomain[] = "piccard-review-hash-accuracy-v1";
constexpr char kTraceDomain[] = "piccard-review-execution-trace-v1";

using Bytes = std::vector<uint8_t>;

void AppendU8(Bytes& out, uint8_t value) { out.push_back(value); }

void AppendBE32(Bytes& out, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

void AppendBE64(Bytes& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

void AppendDomain(Bytes& out, const char* domain) {
    const size_t size = std::strlen(domain);
    out.insert(out.end(), domain, domain + size);
    out.push_back(0);
}

void AppendString(Bytes& out, const std::string& value) {
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("workload string exceeds BE32 length");
    }
    AppendBE32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void AppendVector(Bytes& out, const std::vector<uint64_t>& values) {
    AppendBE64(out, static_cast<uint64_t>(values.size()));
    for (uint64_t value : values) AppendBE64(out, value);
}

std::array<uint8_t, 32> Sha256Raw(const uint8_t* data, size_t size) {
    std::array<uint8_t, 32> digest{};
    EVP_MD_CTX* raw = EVP_MD_CTX_new();
    if (raw == nullptr) throw std::runtime_error("EVP_MD_CTX_new failed");
    struct Guard {
        EVP_MD_CTX* value;
        ~Guard() { EVP_MD_CTX_free(value); }
    } guard{raw};
    unsigned int digest_size = 0;
    if (EVP_DigestInit_ex(raw, EVP_sha256(), nullptr) != 1 ||
        (size != 0 && EVP_DigestUpdate(raw, data, size) != 1) ||
        EVP_DigestFinal_ex(raw, digest.data(), &digest_size) != 1 ||
        digest_size != digest.size()) {
        throw std::runtime_error("SHA-256 computation failed");
    }
    return digest;
}

std::string Hex(const std::array<uint8_t, 32>& digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint8_t byte : digest) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0f]);
    }
    return out;
}

uint64_t First8BE(const std::array<uint8_t, 32>& digest) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | digest[i];
    return value;
}

ExactRational Reduced(uint64_t numerator, uint64_t denominator) {
    if (denominator == 0) throw std::invalid_argument("zero rational denominator");
    const uint64_t divisor = std::gcd(numerator, denominator);
    return {numerator / divisor, denominator / divisor};
}

void ValidateUtf8Token(const std::string& value, const char* name) {
    if (value.empty()) {
        throw std::invalid_argument(std::string(name) + " must not be empty");
    }
    if (value.find('\0') != std::string::npos) {
        throw std::invalid_argument(std::string(name) + " contains NUL");
    }
}

const std::vector<std::string>& PrimaryMethods() {
    static const std::vector<std::string> methods = {
        "piccard", "piccard_sqrt", "bcg12_mh_ff", "bcg12_mh_ec",
        "bcg12_exact_ff", "bcg12_exact_ec", "sj16"};
    return methods;
}

const std::vector<std::string>& ToyMethods() {
    static const std::vector<std::string> methods = {
        "piccard", "piccard_sqrt", "bcg12_mh_ec", "bcg12_exact_ec",
        "sj16"};
    return methods;
}

const std::vector<std::string>& SensitivityMethods() {
    static const std::vector<std::string> methods = {
        "sj16", "sj16_precomputed"};
    return methods;
}

void ValidateSuite(const WorkloadSpec& spec) {
    const std::vector<std::string>* expected = nullptr;
    const char* profile = nullptr;
    uint32_t timing = 0;
    uint32_t accuracy = 0;
    if (spec.suite == "primary-review") {
        expected = &PrimaryMethods();
        profile = "std128-t40-primary";
        timing = 30;
        accuracy = 50;
    } else if (spec.suite == "toy-smoke") {
        expected = &ToyMethods();
        profile = "toy-smoke";
        timing = 1;
        accuracy = 1;
    } else if (spec.suite == "sj16-precompute-sensitivity") {
        expected = &SensitivityMethods();
        profile = "std128-t64-sensitivity";
        timing = 3;
        accuracy = 0;
    } else {
        throw std::invalid_argument("unknown frozen comparison suite: " +
                                    spec.suite);
    }
    if (spec.profile_id != profile || spec.methods != *expected ||
        spec.timing_trials != timing || spec.accuracy_trials != accuracy) {
        throw std::invalid_argument(
            "suite profile, ordered methods, or trial counts do not match the frozen policy");
    }
}

void ValidateSpec(const WorkloadSpec& spec) {
    ValidateUtf8Token(spec.suite, "suite");
    ValidateUtf8Token(spec.profile_id, "profile_id");
    if (spec.k == 0 || spec.m == 0 || spec.universe == 0) {
        throw std::invalid_argument("k, m, and universe must be positive");
    }
    if (spec.target_jaccard.denominator == 0 ||
        spec.target_jaccard.numerator > spec.target_jaccard.denominator ||
        Reduced(spec.target_jaccard.numerator,
                spec.target_jaccard.denominator) != spec.target_jaccard) {
        throw std::invalid_argument("target Jaccard must be reduced and in [0,1]");
    }
    std::set<std::string> unique;
    for (const auto& method : spec.methods) {
        ValidateUtf8Token(method, "method");
        if (!unique.insert(method).second) {
            throw std::invalid_argument("duplicate method in workload manifest");
        }
    }
    if (spec.methods.empty()) throw std::invalid_argument("method list is empty");
    const uint64_t record_count = UINT64_C(1) + spec.timing_trials +
                                  spec.accuracy_trials;
    if (record_count > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("record_count exceeds BE32");
    }
    ValidateSuite(spec);
}

uint64_t TargetIntersection(const WorkloadSpec& spec) {
    using U128 = unsigned __int128;
    const U128 numerator = U128{2} * spec.set_size *
                           spec.target_jaccard.numerator;
    const U128 denominator = spec.target_jaccard.denominator +
                             U128{spec.target_jaccard.numerator};
    U128 quotient = numerator / denominator;
    const U128 remainder = numerator % denominator;
    if (U128{2} * remainder > denominator) ++quotient;
    if (quotient > spec.set_size ||
        quotient > std::numeric_limits<uint64_t>::max()) {
        throw std::invalid_argument("target intersection is out of range");
    }
    return static_cast<uint64_t>(quotient);
}

uint64_t TrialSeed(uint64_t root_seed, TrialKind kind, uint32_t index) {
    Bytes input;
    AppendDomain(input, kTrialDomain);
    AppendBE64(input, root_seed);
    AppendU8(input, static_cast<uint8_t>(kind));
    AppendBE32(input, index);
    return First8BE(Sha256(input));
}

uint64_t HashSeed(uint64_t root_seed, TrialKind kind, uint32_t index) {
    Bytes input;
    if (kind == TrialKind::Warmup) {
        AppendDomain(input, kWarmupHashDomain);
    } else if (kind == TrialKind::Timing) {
        AppendDomain(input, kTimingHashDomain);
    } else {
        AppendDomain(input, kAccuracyHashDomain);
    }
    AppendBE64(input, root_seed);
    if (kind == TrialKind::Accuracy) AppendBE32(input, index);
    return First8BE(Sha256(input));
}

Bytes SerializeTrial(const ComparisonTrial& record) {
    Bytes out;
    AppendU8(out, static_cast<uint8_t>(record.kind));
    AppendBE32(out, record.index);
    AppendBE64(out, record.trial_seed);
    AppendBE64(out, record.hash_seed);
    AppendVector(out, record.set_a);
    AppendVector(out, record.set_b);
    AppendBE64(out, record.exact_intersection);
    AppendBE64(out, record.exact_union);
    return out;
}

ComparisonTrial GenerateTrial(const WorkloadSpec& spec,
                              TrialKind kind,
                              uint32_t index,
                              uint64_t intersection) {
    const uint64_t only = spec.set_size - intersection;
    using U128 = unsigned __int128;
    const U128 required = U128{intersection} + U128{2} * only;
    if (required > spec.universe) {
        throw std::invalid_argument("universe is insufficient for realized sets");
    }

    ComparisonTrial record;
    record.kind = kind;
    record.index = index;
    record.trial_seed = TrialSeed(spec.root_seed, kind, index);
    record.hash_seed = HashSeed(spec.root_seed, kind, index);

    struct Ranked {
        std::array<uint8_t, 32> digest;
        uint64_t value;
    };
    std::vector<Ranked> ranked;
    if (spec.universe > std::numeric_limits<size_t>::max()) {
        throw std::invalid_argument("universe is too large for this host");
    }
    ranked.reserve(static_cast<size_t>(spec.universe));
    for (uint64_t x = 0; x < spec.universe; ++x) {
        Bytes input;
        AppendDomain(input, kSetDomain);
        AppendBE64(input, record.trial_seed);
        AppendBE64(input, x);
        ranked.push_back({Sha256(input), x});
    }
    std::sort(ranked.begin(), ranked.end(), [](const Ranked& lhs,
                                                const Ranked& rhs) {
        return std::tie(lhs.digest, lhs.value) <
               std::tie(rhs.digest, rhs.value);
    });

    record.set_a.reserve(static_cast<size_t>(spec.set_size));
    record.set_b.reserve(static_cast<size_t>(spec.set_size));
    for (uint64_t i = 0; i < intersection; ++i) {
        record.set_a.push_back(ranked[static_cast<size_t>(i)].value);
        record.set_b.push_back(ranked[static_cast<size_t>(i)].value);
    }
    for (uint64_t i = 0; i < only; ++i) {
        record.set_a.push_back(
            ranked[static_cast<size_t>(intersection + i)].value);
        record.set_b.push_back(
            ranked[static_cast<size_t>(intersection + only + i)].value);
    }
    std::sort(record.set_a.begin(), record.set_a.end());
    std::sort(record.set_b.begin(), record.set_b.end());
    record.exact_intersection = intersection;
    record.exact_union = static_cast<uint64_t>(required);
    record.exact_jaccard = record.exact_union == 0
        ? ExactRational{1, 1}
        : Reduced(record.exact_intersection, record.exact_union);
    return record;
}

Bytes SerializeWorkload(const WorkloadSpec& spec,
                        const std::vector<ComparisonTrial>& records) {
    Bytes out;
    AppendDomain(out, kWorkloadDomain);
    AppendString(out, spec.suite);
    AppendString(out, spec.profile_id);
    AppendBE64(out, spec.root_seed);
    AppendBE64(out, spec.k);
    AppendBE64(out, spec.m);
    AppendBE64(out, spec.set_size);
    AppendBE64(out, spec.universe);
    AppendBE64(out, spec.target_jaccard.numerator);
    AppendBE64(out, spec.target_jaccard.denominator);
    AppendBE32(out, static_cast<uint32_t>(spec.methods.size()));
    for (const auto& method : spec.methods) AppendString(out, method);
    AppendBE32(out, spec.timing_trials);
    AppendBE32(out, spec.accuracy_trials);
    AppendBE32(out, static_cast<uint32_t>(records.size()));
    for (const auto& record : records) {
        const Bytes bytes = SerializeTrial(record);
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

class Reader {
public:
    explicit Reader(const Bytes& bytes) : bytes_(bytes) {}

    void Domain(const char* expected) {
        const size_t size = std::strlen(expected) + 1;
        Require(size);
        if (!std::equal(expected, expected + size - 1, bytes_.begin() + pos_) ||
            bytes_[pos_ + size - 1] != 0) {
            throw std::invalid_argument("binary artifact domain mismatch");
        }
        pos_ += size;
    }

    uint8_t U8() {
        Require(1);
        return bytes_[pos_++];
    }

    uint32_t BE32() {
        Require(4);
        uint32_t value = 0;
        for (size_t i = 0; i < 4; ++i) value = (value << 8) | bytes_[pos_++];
        return value;
    }

    uint64_t BE64() {
        Require(8);
        uint64_t value = 0;
        for (size_t i = 0; i < 8; ++i) value = (value << 8) | bytes_[pos_++];
        return value;
    }

    std::string String() {
        const uint32_t size = BE32();
        Require(size);
        std::string value(bytes_.begin() + static_cast<ptrdiff_t>(pos_),
                          bytes_.begin() + static_cast<ptrdiff_t>(pos_ + size));
        pos_ += size;
        return value;
    }

    std::vector<uint64_t> Vector() {
        const uint64_t count = BE64();
        if (count > Remaining() / 8) {
            throw std::invalid_argument("truncated VEC64");
        }
        std::vector<uint64_t> values;
        values.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) values.push_back(BE64());
        return values;
    }

    std::array<uint8_t, 32> Raw32() {
        Require(32);
        std::array<uint8_t, 32> value{};
        std::copy_n(bytes_.begin() + static_cast<ptrdiff_t>(pos_), 32,
                    value.begin());
        pos_ += 32;
        return value;
    }

    size_t Remaining() const { return bytes_.size() - pos_; }
    bool AtEnd() const { return pos_ == bytes_.size(); }

private:
    void Require(size_t size) const {
        if (size > bytes_.size() - pos_) {
            throw std::invalid_argument("truncated binary artifact");
        }
    }

    const Bytes& bytes_;
    size_t pos_ = 0;
};

void WriteAll(int fd, const Bytes& bytes) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t written =
            write(fd, bytes.data() + offset, bytes.size() - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "write");
        }
        offset += static_cast<size_t>(written);
    }
}

void AtomicWriteNew(const std::filesystem::path& path, const Bytes& bytes) {
    if (path.extension() != ".bin") {
        throw std::invalid_argument("binary artifacts require a .bin path");
    }
    const auto parent = path.parent_path().empty()
        ? std::filesystem::path(".") : path.parent_path();
    if (!std::filesystem::is_directory(parent)) {
        throw std::runtime_error("artifact parent directory does not exist");
    }
    const std::filesystem::path temp =
        parent / ("." + path.filename().string() + ".tmp-" +
                  std::to_string(static_cast<unsigned long>(getpid())));
    const int fd = open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "create temporary artifact");
    }
    bool close_needed = true;
    try {
        WriteAll(fd, bytes);
        if (fsync(fd) != 0) {
            throw std::system_error(errno, std::generic_category(), "fsync");
        }
        if (close(fd) != 0) {
            close_needed = false;
            throw std::system_error(errno, std::generic_category(), "close");
        }
        close_needed = false;
        if (link(temp.c_str(), path.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "publish new artifact");
        }
        if (unlink(temp.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "remove temporary artifact link");
        }
    } catch (...) {
        if (close_needed) close(fd);
        unlink(temp.c_str());
        throw;
    }
}

std::string TimingKind(const std::string& method) {
    if (method == "piccard" || method == "piccard_sqrt") return "fhe-timing";
    if (method.rfind("bcg12_", 0) == 0) return "psi-timing";
    if (method == "sj16" || method == "sj16_precomputed") return "ahe-timing";
    if (method == "fhe_ind" || method == "baseline") return "diagnostic";
    throw std::invalid_argument("unknown comparison method: " + method);
}

std::string AccuracyKind(const std::string& method) {
    if (method == "piccard" || method == "piccard_sqrt") return "fhe-accuracy";
    if (method.rfind("bcg12_", 0) == 0) return "psi-accuracy";
    if (method == "sj16") return "ahe-accuracy";
    if (method == "fhe_ind" || method == "baseline") return "diagnostic";
    throw std::invalid_argument("method has no accuracy arm: " + method);
}

bool ExactMethod(const std::string& method) {
    return method.rfind("bcg12_exact_", 0) == 0 || method == "sj16" ||
           method == "sj16_precomputed";
}

std::string Precomputation(const std::string& method) {
    if (method == "sj16") return "randomizer-generation-included";
    if (method == "sj16_precomputed") return "randomizers-precomputed";
    if (method == "fhe_ind" || method == "baseline") return "not-applicable";
    return "crs-and-keys-only";
}

bool SameTrial(const ComparisonTrial& lhs, const ComparisonTrial& rhs) {
    return lhs.kind == rhs.kind && lhs.index == rhs.index &&
           lhs.trial_seed == rhs.trial_seed && lhs.hash_seed == rhs.hash_seed &&
           lhs.set_a == rhs.set_a && lhs.set_b == rhs.set_b &&
           lhs.exact_intersection == rhs.exact_intersection &&
           lhs.exact_union == rhs.exact_union;
}

}  // namespace

bool operator==(const ExactRational& lhs, const ExactRational& rhs) {
    return lhs.numerator == rhs.numerator && lhs.denominator == rhs.denominator;
}

bool operator!=(const ExactRational& lhs, const ExactRational& rhs) {
    return !(lhs == rhs);
}

std::string ReviewMeasurementKind(const std::string& method, TrialKind kind) {
    if (kind == TrialKind::Warmup) {
        throw std::invalid_argument("warmup records do not emit aggregate rows");
    }
    return kind == TrialKind::Accuracy
        ? AccuracyKind(method) : TimingKind(method);
}

ReviewMethodRowPolicy ResolveReviewMethodRowPolicy(
    const std::string& method,
    TrialKind kind,
    uint64_t requested_k,
    uint64_t requested_m,
    uint64_t timing_hash_seed) {
    if (kind == TrialKind::Warmup) {
        throw std::invalid_argument("warmup records do not emit aggregate rows");
    }
    // Piccard consumes both configured dimensions. BCG12 MinHash consumes k
    // and the shared full-range CRS, but not one-hot m. Exact BCG12 and SJ16
    // have neither parameter nor a workload hash CRS in their aggregate rows.
    const bool piccard = method == "piccard" || method == "piccard_sqrt";
    const bool minhash = method == "bcg12_mh_ff" || method == "bcg12_mh_ec";
    const bool hash_crs = piccard || minhash;
    if (!piccard && !minhash && method != "bcg12_exact_ff" &&
        method != "bcg12_exact_ec" && method != "sj16" &&
        method != "sj16_precomputed") {
        throw std::invalid_argument("unknown review row method: " + method);
    }
    ReviewMethodRowPolicy policy;
    if (piccard || minhash) policy.k = requested_k;
    if (piccard) policy.m = requested_m;
    if (hash_crs && kind == TrialKind::Timing) {
        policy.hash_seed = timing_hash_seed;
        policy.hash_randomness = "fixed";
    } else if (hash_crs) {
        policy.hash_randomness = "resampled";
    } else {
        policy.hash_randomness = "not-applicable";
    }
    return policy;
}

std::string ReviewNumericCell(double value) {
    if (value < 0.0) return "";
    std::ostringstream out;
    out << std::fixed << std::setprecision(6) << value;
    return out.str();
}

ExactRational ParseExactDecimal(const std::string& text) {
    if (text.empty()) throw std::invalid_argument("empty decimal");
    const size_t dot = text.find('.');
    if (dot != std::string::npos && text.find('.', dot + 1) != std::string::npos) {
        throw std::invalid_argument("decimal contains more than one dot");
    }
    const std::string whole = dot == std::string::npos ? text : text.substr(0, dot);
    const std::string fraction = dot == std::string::npos ? "" : text.substr(dot + 1);
    if (whole.empty() || (dot != std::string::npos && fraction.empty())) {
        throw std::invalid_argument("decimal requires digits around dot");
    }
    auto digits = [](const std::string& value) {
        return std::all_of(value.begin(), value.end(),
                           [](unsigned char c) { return c >= '0' && c <= '9'; });
    };
    if (!digits(whole) || !digits(fraction)) {
        throw std::invalid_argument("decimal contains a non-digit");
    }
    using U128 = unsigned __int128;
    U128 whole_value = 0;
    for (char c : whole) {
        whole_value = whole_value * 10 + (c - '0');
        if (whole_value > std::numeric_limits<uint64_t>::max()) {
            throw std::invalid_argument("decimal whole part exceeds BE64");
        }
    }
    U128 denominator = 1;
    U128 fraction_value = 0;
    for (char c : fraction) {
        denominator *= 10;
        fraction_value = fraction_value * 10 + (c - '0');
        if (denominator > std::numeric_limits<uint64_t>::max()) {
            throw std::invalid_argument("decimal denominator exceeds BE64");
        }
    }
    const U128 numerator = whole_value * denominator + fraction_value;
    if (numerator > std::numeric_limits<uint64_t>::max()) {
        throw std::invalid_argument("decimal numerator exceeds BE64");
    }
    return Reduced(static_cast<uint64_t>(numerator),
                   static_cast<uint64_t>(denominator));
}

ComparisonWorkload ComparisonWorkload::Generate(const WorkloadSpec& spec) {
    ValidateSpec(spec);
    ComparisonWorkload workload;
    workload.spec_ = spec;
    const uint64_t intersection = TargetIntersection(spec);
    workload.records_.push_back(
        GenerateTrial(spec, TrialKind::Warmup, 0, intersection));
    for (uint32_t i = 0; i < spec.timing_trials; ++i) {
        workload.records_.push_back(
            GenerateTrial(spec, TrialKind::Timing, i, intersection));
    }
    for (uint32_t i = 0; i < spec.accuracy_trials; ++i) {
        workload.records_.push_back(
            GenerateTrial(spec, TrialKind::Accuracy, i, intersection));
    }
    workload.bytes_ = SerializeWorkload(spec, workload.records_);
    workload.digest_ = Sha256(workload.bytes_);
    workload.digest_hex_ = Hex(workload.digest_);
    workload.workload_id_ = "review-" + std::to_string(spec.universe) + "-" +
                            workload.digest_hex_.substr(0, 16);
    return workload;
}

ComparisonWorkload ComparisonWorkload::ParseAndVerify(
    const std::vector<uint8_t>& bytes) {
    Reader reader(bytes);
    reader.Domain(kWorkloadDomain);
    WorkloadSpec spec;
    spec.suite = reader.String();
    spec.profile_id = reader.String();
    spec.root_seed = reader.BE64();
    spec.k = reader.BE64();
    spec.m = reader.BE64();
    spec.set_size = reader.BE64();
    spec.universe = reader.BE64();
    spec.target_jaccard = {reader.BE64(), reader.BE64()};
    const uint32_t method_count = reader.BE32();
    if (method_count > reader.Remaining() / 4) {
        throw std::invalid_argument("invalid method_count");
    }
    spec.methods.reserve(method_count);
    for (uint32_t i = 0; i < method_count; ++i) {
        spec.methods.push_back(reader.String());
    }
    spec.timing_trials = reader.BE32();
    spec.accuracy_trials = reader.BE32();
    const uint32_t record_count = reader.BE32();
    if (record_count != UINT64_C(1) + spec.timing_trials + spec.accuracy_trials) {
        throw std::invalid_argument("workload record_count mismatch");
    }
    for (uint32_t i = 0; i < record_count; ++i) {
        const uint8_t kind = reader.U8();
        if (kind > static_cast<uint8_t>(TrialKind::Accuracy)) {
            throw std::invalid_argument("invalid trial kind");
        }
        (void)reader.BE32();
        (void)reader.BE64();
        (void)reader.BE64();
        (void)reader.Vector();
        (void)reader.Vector();
        (void)reader.BE64();
        (void)reader.BE64();
    }
    if (!reader.AtEnd()) throw std::invalid_argument("trailing workload bytes");

    ComparisonWorkload regenerated = Generate(spec);
    if (regenerated.bytes_ != bytes) {
        throw std::invalid_argument(
            "workload bytes do not match regenerated seeds, sets, or rationals");
    }
    return regenerated;
}

std::vector<std::string> ComparisonWorkload::ExecutionOrder(
    const ComparisonTrial& record) const {
    const size_t count = spec_.methods.size();
    if (count == 0) throw std::logic_error("workload method list is empty");
    std::vector<std::string> order;
    order.reserve(count);
    const size_t offset = static_cast<size_t>(record.trial_seed % count);
    for (size_t i = 0; i < count; ++i) {
        order.push_back(spec_.methods[(offset + i) % count]);
    }
    return order;
}

void ComparisonWorkload::WriteNew(const std::filesystem::path& path) const {
    AtomicWriteNew(path, bytes_);
}

std::vector<AggregateIdentity> ExpectedAggregateIdentities(
    const ComparisonWorkload& workload) {
    std::vector<AggregateIdentity> rows;
    const auto& spec = workload.Spec();
    for (const auto& method : spec.methods) {
        AggregateIdentity timing;
        timing.method = method;
        timing.measurement_kind = TimingKind(method);
        timing.evidence_arm = "timing";
        timing.workload_id = workload.WorkloadId();
        timing.workload_manifest_sha256 = workload.ManifestSha256Hex();
        timing.k = spec.k;
        timing.m = spec.m;
        timing.set_size = spec.set_size;
        timing.universe = spec.universe;
        timing.timing_trials = spec.timing_trials;
        timing.accuracy_trials = spec.accuracy_trials;
        timing.aggregate_trials = spec.timing_trials;
        timing.precomputation_mode = Precomputation(method);
        timing.exact_estimator = ExactMethod(method);
        rows.push_back(timing);

        if (spec.accuracy_trials != 0) {
            AggregateIdentity accuracy = timing;
            accuracy.measurement_kind = AccuracyKind(method);
            accuracy.evidence_arm = "accuracy";
            accuracy.aggregate_trials = spec.accuracy_trials;
            rows.push_back(accuracy);
        }
    }
    return rows;
}

void ValidateAggregateMembership(
    const ComparisonWorkload& workload,
    const std::vector<AggregateIdentity>& rows) {
    const auto expected = ExpectedAggregateIdentities(workload);
    if (rows.size() != expected.size()) {
        throw std::invalid_argument("aggregate row count does not match suite");
    }
    std::set<std::pair<std::string, std::string>> seen;
    for (const auto& row : rows) {
        const auto key = std::make_pair(row.method, row.evidence_arm);
        if (!seen.insert(key).second) {
            throw std::invalid_argument("duplicate method-kind aggregate row");
        }
        const auto found = std::find_if(
            expected.begin(), expected.end(), [&](const AggregateIdentity& item) {
                return item.method == row.method &&
                       item.evidence_arm == row.evidence_arm;
            });
        if (found == expected.end()) {
            throw std::invalid_argument("unexpected method-kind aggregate row");
        }
        if (row.measurement_kind != found->measurement_kind ||
            row.workload_id != found->workload_id ||
            row.workload_manifest_sha256 != found->workload_manifest_sha256 ||
            row.k != found->k || row.m != found->m ||
            row.set_size != found->set_size || row.universe != found->universe ||
            row.timing_trials != found->timing_trials ||
            row.accuracy_trials != found->accuracy_trials ||
            row.aggregate_trials != found->aggregate_trials ||
            row.precomputation_mode != found->precomputation_mode ||
            row.exact_estimator != found->exact_estimator) {
            throw std::invalid_argument("aggregate row is not manifest-conditioned");
        }
        if (row.exact_estimator && row.estimator_error != 0.0) {
            throw std::invalid_argument("exact method reported estimator error");
        }
    }
}

ExecutionTrace::ExecutionTrace(const ComparisonWorkload& workload)
    : workload_(workload) {}

void ExecutionTrace::BeginRecord(const ComparisonTrial& record) {
    if (terminated_) throw std::logic_error("execution trace already terminated");
    if (current_.has_value()) throw std::logic_error("trace record already open");
    if (records_.size() >= workload_.Records().size() ||
        !SameTrial(record, workload_.Records()[records_.size()])) {
        throw std::invalid_argument("trace record is not the next manifest trial");
    }
    current_ = Record{record.kind, record.index,
                      static_cast<uint32_t>(workload_.Spec().methods.size()),
                      TraceRecordStatus::Complete, {}};
}

void ExecutionTrace::AppendDispatch(const std::string& method) {
    if (!current_) throw std::logic_error("no open trace record");
    const auto& trial = workload_.Records()[records_.size()];
    const auto expected = workload_.ExecutionOrder(trial);
    if (current_->dispatched.size() >= expected.size() ||
        method != expected[current_->dispatched.size()]) {
        throw std::invalid_argument("dispatch does not match cyclic method order");
    }
    current_->dispatched.push_back(method);
}

void ExecutionTrace::CompleteRecord() {
    if (!current_) throw std::logic_error("no open trace record");
    if (current_->dispatched.size() != current_->expected_method_count) {
        throw std::logic_error("complete trace record is missing dispatches");
    }
    current_->status = TraceRecordStatus::Complete;
    records_.push_back(std::move(*current_));
    current_.reset();
}

void ExecutionTrace::FailRecord() {
    if (!current_) throw std::logic_error("no open trace record");
    if (current_->dispatched.empty() ||
        current_->dispatched.size() > current_->expected_method_count) {
        throw std::logic_error("adapter failure requires a dispatched adapter");
    }
    current_->status = TraceRecordStatus::AdapterFailure;
    records_.push_back(std::move(*current_));
    current_.reset();
    terminated_ = true;
}

std::vector<uint8_t> ExecutionTrace::SerializeAndVerify() const {
    if (current_) throw std::logic_error("cannot serialize an open trace record");
    const bool complete = records_.size() == workload_.Records().size();
    const bool failed = !records_.empty() &&
        records_.back().status == TraceRecordStatus::AdapterFailure;
    if (!complete && !failed) {
        throw std::logic_error("execution trace is incomplete without failure");
    }
    Bytes out;
    AppendDomain(out, kTraceDomain);
    out.insert(out.end(), workload_.ManifestSha256().begin(),
               workload_.ManifestSha256().end());
    AppendBE32(out, static_cast<uint32_t>(workload_.Records().size()));
    AppendBE32(out, static_cast<uint32_t>(records_.size()));
    for (const auto& record : records_) {
        AppendU8(out, static_cast<uint8_t>(record.kind));
        AppendBE32(out, record.trial_index);
        AppendBE32(out, record.expected_method_count);
        AppendBE32(out, static_cast<uint32_t>(record.dispatched.size()));
        AppendU8(out, static_cast<uint8_t>(record.status));
        for (const auto& method : record.dispatched) AppendString(out, method);
    }
    VerifyExecutionTrace(out, workload_);
    return out;
}

std::string ExecutionTrace::WriteNew(const std::filesystem::path& path) const {
    const Bytes bytes = SerializeAndVerify();
    AtomicWriteNew(path, bytes);
    return Sha256Hex(bytes);
}

void VerifyExecutionTrace(const Bytes& bytes,
                          const ComparisonWorkload& workload) {
    Reader reader(bytes);
    reader.Domain(kTraceDomain);
    if (reader.Raw32() != workload.ManifestSha256()) {
        throw std::invalid_argument("execution trace workload digest mismatch");
    }
    const uint32_t expected_records = reader.BE32();
    const uint32_t observed_records = reader.BE32();
    if (expected_records != workload.Records().size() ||
        observed_records == 0 || observed_records > expected_records) {
        throw std::invalid_argument("execution trace record counts are invalid");
    }
    bool failed = false;
    for (uint32_t i = 0; i < observed_records; ++i) {
        const uint8_t kind = reader.U8();
        const uint32_t index = reader.BE32();
        const uint32_t expected_methods = reader.BE32();
        const uint32_t dispatched = reader.BE32();
        const uint8_t status = reader.U8();
        const auto& trial = workload.Records()[i];
        if (kind != static_cast<uint8_t>(trial.kind) || index != trial.index ||
            expected_methods != workload.Spec().methods.size() ||
            status > static_cast<uint8_t>(TraceRecordStatus::AdapterFailure)) {
            throw std::invalid_argument("execution trace record identity is invalid");
        }
        if ((status == static_cast<uint8_t>(TraceRecordStatus::Complete) &&
             dispatched != expected_methods) ||
            (status == static_cast<uint8_t>(TraceRecordStatus::AdapterFailure) &&
             (dispatched == 0 || dispatched > expected_methods))) {
            throw std::invalid_argument("execution trace dispatch count is invalid");
        }
        const auto order = workload.ExecutionOrder(trial);
        for (uint32_t j = 0; j < dispatched; ++j) {
            if (reader.String() != order[j]) {
                throw std::invalid_argument("execution trace dispatch order mismatch");
            }
        }
        if (status == static_cast<uint8_t>(TraceRecordStatus::AdapterFailure)) {
            if (i + 1 != observed_records) {
                throw std::invalid_argument("adapter failure must terminate trace");
            }
            failed = true;
        }
    }
    if (!reader.AtEnd()) throw std::invalid_argument("trailing execution trace bytes");
    if (!failed && observed_records != expected_records) {
        throw std::invalid_argument("complete execution trace is missing records");
    }
}

std::array<uint8_t, 32> Sha256(const Bytes& bytes) {
    return Sha256Raw(bytes.data(), bytes.size());
}

std::string Sha256Hex(const Bytes& bytes) { return Hex(Sha256(bytes)); }

}  // namespace benchmark
}  // namespace piccard
