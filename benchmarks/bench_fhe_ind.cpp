/**
 * Live FHE-IND diagnostic binary.
 *
 * This executable is deliberately separate from bench_std_security_evidence:
 * the latter owns Piccard's calibrated sanitizer path and intentionally does
 * not accept FHE-IND.  This path measures only the local-universe BFV
 * indicator comparator and keeps setup, online phases, and provenance bound
 * to the same frozen workload/context tuple.
 */

#include "baseline_engine.h"
#include "build_info.h"
#include "comparison_workload.h"
#include "std_security_evidence_schema.h"
#include "version.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <fcntl.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <limits.h>
#elif defined(__linux__)
#include <limits.h>
#endif
#include <unistd.h>

namespace {

namespace baseline = piccard::baseline;
namespace benchmark = piccard::benchmark;
namespace evidence = piccard::std_evidence;

constexpr char kCapabilitiesSchema[] =
    "piccard-std-security-fhe-ind-capabilities-v1";
constexpr char kPreflightSchema[] =
    "piccard-std-security-fhe-ind-preflight-v1";
constexpr char kWork5PreflightSchema[] =
    "piccard-work5-fhe-ind-context-preflight-v1";
constexpr char kShapeId[] = "fhe-indicator-v1";
constexpr uint32_t kUniverse = 64;
constexpr uint32_t kSetSize = 10;
constexpr uint32_t kSeed = 7;
constexpr uint32_t kTrials = 1;
constexpr uint32_t kExpectedIntersection = 7;
constexpr uint32_t kExpectedUnion = 13;

struct Options {
    std::string mode;
    std::string method;
    std::string circuit;
    std::string security;
    std::string shape_id;
    std::string cell_id;
    std::string output;
    std::string workload;
    std::string preflight;
    std::string format;
    uint64_t universe = 0;
    uint64_t set_size = 0;
    std::string target_jaccard;
    uint64_t seed = 0;
    uint64_t trials = 0;
    uint64_t work5_n = 0;
    bool capabilities = false;
};

struct TupleData {
    std::string bfv_context_fingerprint;
    std::string circuit;
    std::string shape_id;
    uint32_t k = 0;
    uint32_t m = 0;
    std::string sanitizer_profile;
    piccard::SecurityLevel security = piccard::SecurityLevel::STD128;
    uint32_t requested_ring_dim = 0;
    uint32_t natural_ring_dim = 0;
    uint32_t natural_depth = 0;
    uint32_t realized_ring_dim = 0;
    uint64_t plaintext_modulus = 0;
    uint32_t provisioned_depth = 0;
    uint32_t scaling_mod_size = 0;
    uint32_t num_limbs = 0;
    std::vector<std::string> ordered_rns_moduli;
    std::string openfhe_version;
    double log_q_bits = 0.0;
    std::string context_tuple_sha256;
};

struct WorkloadData {
    benchmark::ComparisonWorkload parsed;
};

struct ProducerIdentity {
    std::string fhe_ind_binary_sha256;
    std::string capabilities_sha256;
};

std::string JsonEscape(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    out << "\\u" << std::hex << std::setw(4)
                        << std::setfill('0') << static_cast<unsigned>(ch)
                        << std::dec << std::setfill(' ');
                } else {
                    out << static_cast<char>(ch);
                }
        }
    }
    out << '"';
    return out.str();
}

template <typename T>
std::string Number(T value) {
    std::ostringstream out;
    if constexpr (std::is_floating_point<T>::value) {
        out << std::setprecision(std::numeric_limits<T>::max_digits10);
    }
    out << value;
    return out.str();
}

class CanonicalJsonObject {
  public:
    void Add(const std::string& key, std::string value) {
        if (!fields_.emplace(key, std::move(value)).second) {
            throw std::logic_error("duplicate canonical JSON key: " + key);
        }
    }

    void AddString(const std::string& key, const std::string& value) {
        Add(key, JsonEscape(value));
    }

    template <typename T>
    void AddNumber(const std::string& key, T value) {
        Add(key, Number(value));
    }

    void AddBool(const std::string& key, bool value) {
        Add(key, value ? "true" : "false");
    }

    void AddArray(const std::string& key,
                  const std::vector<std::string>& values) {
        std::ostringstream out;
        out << '[';
        for (size_t index = 0; index < values.size(); ++index) {
            if (index != 0) out << ',';
            out << JsonEscape(values[index]);
        }
        out << ']';
        Add(key, out.str());
    }

    std::string Serialize() const {
        std::ostringstream out;
        out << '{';
        bool first = true;
        for (const auto& [key, value] : fields_) {
            if (!first) out << ',';
            first = false;
            out << JsonEscape(key) << ':' << value;
        }
        out << '}';
        return out.str();
    }

  private:
    std::map<std::string, std::string> fields_;
};

std::string OptionValue(const std::string& argument, const char* option) {
    const std::string prefix = std::string("--") + option + "=";
    if (argument.rfind(prefix, 0) != 0) return {};
    const std::string value = argument.substr(prefix.size());
    if (value.empty()) {
        throw std::invalid_argument(std::string("--") + option +
                                    " requires a value");
    }
    return value;
}

uint64_t ParseUnsigned(const std::string& value, const char* option) {
    if (value.empty() ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        throw std::invalid_argument(std::string(option) +
                                    " requires an unsigned integer");
    }
    size_t consumed = 0;
    const uint64_t parsed = std::stoull(value, &consumed, 10);
    if (consumed != value.size()) {
        throw std::invalid_argument(std::string(option) +
                                    " requires an unsigned integer");
    }
    return parsed;
}

void MarkOption(std::set<std::string>* seen, const char* option) {
    if (!seen->insert(option).second) {
        throw std::invalid_argument(std::string("duplicate option: --") +
                                    option);
    }
}

Options ParseOptions(int argc, char** argv) {
    Options options;
    options.format = "json";
    std::set<std::string> seen_options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if (argument == "--capabilities") {
            MarkOption(&seen_options, "capabilities");
            options.capabilities = true;
        } else if (const auto value = OptionValue(argument, "mode");
                   !value.empty()) {
            MarkOption(&seen_options, "mode");
            options.mode = value;
        } else if (const auto value = OptionValue(argument, "method");
                   !value.empty()) {
            MarkOption(&seen_options, "method");
            options.method = value;
        } else if (const auto value = OptionValue(argument, "circuit");
                   !value.empty()) {
            MarkOption(&seen_options, "circuit");
            options.circuit = value;
        } else if (const auto value = OptionValue(argument, "security");
                   !value.empty()) {
            MarkOption(&seen_options, "security");
            options.security = value;
        } else if (const auto value = OptionValue(argument, "shape-id");
                   !value.empty()) {
            MarkOption(&seen_options, "shape-id");
            options.shape_id = value;
        } else if (const auto value = OptionValue(argument, "cell-id");
                   !value.empty()) {
            MarkOption(&seen_options, "cell-id");
            options.cell_id = value;
        } else if (const auto value = OptionValue(argument, "output");
                   !value.empty()) {
            MarkOption(&seen_options, "output");
            options.output = value;
        } else if (const auto value = OptionValue(argument, "workload");
                   !value.empty()) {
            MarkOption(&seen_options, "workload");
            options.workload = value;
        } else if (const auto value = OptionValue(argument, "preflight");
                   !value.empty()) {
            MarkOption(&seen_options, "preflight");
            options.preflight = value;
        } else if (const auto value = OptionValue(argument, "format");
                   !value.empty()) {
            MarkOption(&seen_options, "format");
            options.format = value;
        } else if (const auto value = OptionValue(argument, "universe");
                   !value.empty()) {
            MarkOption(&seen_options, "universe");
            options.universe = ParseUnsigned(value, "--universe");
        } else if (const auto value = OptionValue(argument, "set-size");
                   !value.empty()) {
            MarkOption(&seen_options, "set-size");
            options.set_size = ParseUnsigned(value, "--set-size");
        } else if (const auto value = OptionValue(argument, "target-jaccard");
                   !value.empty()) {
            MarkOption(&seen_options, "target-jaccard");
            options.target_jaccard = value;
        } else if (const auto value = OptionValue(argument, "seed");
                   !value.empty()) {
            MarkOption(&seen_options, "seed");
            options.seed = ParseUnsigned(value, "--seed");
        } else if (const auto value = OptionValue(argument, "trials");
                   !value.empty()) {
            MarkOption(&seen_options, "trials");
            options.trials = ParseUnsigned(value, "--trials");
        } else if (const auto value = OptionValue(argument, "n");
                   !value.empty()) {
            MarkOption(&seen_options, "n");
            options.work5_n = ParseUnsigned(value, "--n");
        } else if (argument == "--help") {
            std::cout
                << "bench_fhe_ind --capabilities --format=json | "
                   "--mode=preflight|e2e --method=fhe_ind --circuit=fhe_ind "
                   "--security=STD128|STD192 --shape-id=fhe-indicator-v1 "
                   "--cell-id=fhe-ind-std128|fhe-ind-std192 --universe=64 "
                   "--set-size=10 --target-jaccard=1/2 --seed=7 --trials=1 "
                   "--workload=PATH --output=PATH [--preflight=PATH] "
                   "--format=json|csv\n";
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown option: " + argument);
        }
    }
    if (options.capabilities) {
        if (argc != 3 || std::string(argv[1]) != "--capabilities" ||
            std::string(argv[2]) != "--format=json") {
            throw std::invalid_argument(
                "--capabilities requires exactly --capabilities --format=json");
        }
        return options;
    }
    if (options.mode != "preflight" && options.mode != "e2e" &&
        options.mode != "work5-preflight") {
        throw std::invalid_argument("--mode must be preflight, e2e, or work5-preflight");
    }
    if (options.method != "fhe_ind" || options.circuit != "fhe_ind" ||
        options.shape_id != kShapeId) {
        throw std::invalid_argument("FHE-IND method/circuit/shape is frozen");
    }
    if (options.security != "STD128" && options.security != "STD192") {
        throw std::invalid_argument("--security must be STD128 or STD192");
    }
    if (options.mode == "work5-preflight") {
        if (options.cell_id.empty() || options.universe == 0 || options.work5_n == 0 ||
            (options.universe != 16384 && options.universe != 65536) ||
            options.output.empty() || options.format != "json" ||
            !options.workload.empty() || !options.preflight.empty() ||
            options.set_size != 0 || !options.target_jaccard.empty() ||
            options.seed != 0 || options.trials != 0) {
            throw std::invalid_argument(
                "work5-preflight requires only bound cell-id/n/universe/security and json output");
        }
        return options;
    }
    const std::string expected_cell =
        options.security == "STD128" ? "fhe-ind-std128" : "fhe-ind-std192";
    if (options.cell_id != expected_cell) {
        throw std::invalid_argument("FHE-IND cell does not match security");
    }
    if (options.output.empty() || options.workload.empty()) {
        throw std::invalid_argument("FHE-IND mode requires workload and output");
    }
    if (options.universe != kUniverse || options.set_size != kSetSize ||
        options.target_jaccard != "1/2" || options.seed != kSeed ||
        options.trials != kTrials) {
        throw std::invalid_argument("FHE-IND workload point is frozen");
    }
    if (options.format != (options.mode == "preflight" ? "json" : "csv")) {
        throw std::invalid_argument("FHE-IND mode/format mismatch");
    }
    if (options.mode == "e2e" && options.preflight.empty()) {
        throw std::invalid_argument("FHE-IND e2e requires preflight artifact");
    }
    if (options.mode == "preflight" && !options.preflight.empty()) {
        throw std::invalid_argument("preflight artifact is only valid for e2e");
    }
    return options;
}

piccard::SecurityLevel ParseSecurity(const std::string& value) {
    if (value == "STD128") return piccard::SecurityLevel::STD128;
    if (value == "STD192") return piccard::SecurityLevel::STD192;
    throw std::invalid_argument("unsupported FHE-IND security profile");
}

void RequireAbsolutePath(const std::string& value, const char* option) {
    const std::filesystem::path path(value);
    if (!path.is_absolute()) {
        throw std::invalid_argument(std::string(option) +
                                    " must be an absolute path");
    }
}

std::string ReadFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) throw std::runtime_error("failed to open " + path);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

std::string SelfExecutablePath() {
#if defined(__APPLE__)
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) != -1 || size == 0) {
        throw std::runtime_error("failed to query FHE-IND executable path");
    }
    std::vector<char> buffer(size + 1, '\0');
    if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
        throw std::runtime_error("failed to resolve FHE-IND executable path");
    }
    return std::filesystem::weakly_canonical(buffer.data()).string();
#elif defined(__linux__)
    std::vector<char> buffer(PATH_MAX + 1, '\0');
    const ssize_t length = ::readlink("/proc/self/exe", buffer.data(),
                                      buffer.size() - 1);
    if (length <= 0) {
        throw std::runtime_error("failed to resolve FHE-IND executable path");
    }
    buffer[static_cast<size_t>(length)] = '\0';
    return std::filesystem::weakly_canonical(buffer.data()).string();
#else
    throw std::runtime_error("unsupported platform for FHE-IND executable hash");
#endif
}

std::string Sha256File(const std::string& path) {
    const std::string bytes = ReadFile(path);
    const std::vector<uint8_t> binary(bytes.begin(), bytes.end());
    return benchmark::Sha256Hex(binary);
}

size_t JsonKeyPosition(const std::string& json, const std::string& key) {
    const std::string token = JsonEscape(key) + ":";
    size_t position = json.find(token);
    if (position == std::string::npos ||
        json.find(token, position + token.size()) != std::string::npos) {
        throw std::invalid_argument("workload JSON key is missing/duplicated: " +
                                    key);
    }
    return position + token.size();
}

std::string JsonStringField(const std::string& json, const std::string& key) {
    size_t position = JsonKeyPosition(json, key);
    if (position >= json.size() || json[position] != '"') {
        throw std::invalid_argument("workload JSON field is not a string: " +
                                    key);
    }
    ++position;
    std::string value;
    while (position < json.size()) {
        const char ch = json[position++];
        if (ch == '"') return value;
        if (ch != '\\') {
            value.push_back(ch);
            continue;
        }
        if (position >= json.size()) break;
        const char escaped = json[position++];
        switch (escaped) {
            case '"': value.push_back('"'); break;
            case '\\': value.push_back('\\'); break;
            case '/': value.push_back('/'); break;
            case 'b': value.push_back('\b'); break;
            case 'f': value.push_back('\f'); break;
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            default:
                throw std::invalid_argument("unsupported workload JSON escape");
        }
    }
    throw std::invalid_argument("unterminated workload JSON string: " + key);
}

std::string JsonScalarField(const std::string& json, const std::string& key) {
    size_t position = JsonKeyPosition(json, key);
    while (position < json.size() &&
           (json[position] == ' ' || json[position] == '\n' ||
            json[position] == '\r' || json[position] == '\t')) {
        ++position;
    }
    const size_t end = json.find_first_of(",}\n", position);
    if (end == std::string::npos) {
        throw std::invalid_argument("unterminated workload JSON scalar: " + key);
    }
    std::string value = json.substr(position, end - position);
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\r' ||
            value.back() == '\t')) {
        value.pop_back();
    }
    return value;
}

uint64_t JsonUnsignedField(const std::string& json, const std::string& key) {
    const std::string value = JsonScalarField(json, key);
    return ParseUnsigned(value, key.c_str());
}

uint32_t JsonUint32Field(const std::string& json, const std::string& key) {
    const uint64_t value = JsonUnsignedField(json, key);
    if (value > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("FHE-IND preflight field exceeds uint32_t: " +
                                    key);
    }
    return static_cast<uint32_t>(value);
}

std::vector<std::string> JsonStringArrayField(const std::string& json,
                                              const std::string& key) {
    size_t position = JsonKeyPosition(json, key);
    while (position < json.size() &&
           (json[position] == ' ' || json[position] == '\n' ||
            json[position] == '\r' || json[position] == '\t')) {
        ++position;
    }
    if (position >= json.size() || json[position] != '[') {
        throw std::invalid_argument("workload JSON field is not an array: " +
                                    key);
    }
    ++position;
    std::vector<std::string> values;
    while (position < json.size()) {
        while (position < json.size() &&
               (json[position] == ' ' || json[position] == '\n' ||
                json[position] == '\r' || json[position] == '\t' ||
                json[position] == ',')) {
            ++position;
        }
        if (position < json.size() && json[position] == ']') return values;
        if (position >= json.size() || json[position] != '"') {
            throw std::invalid_argument("workload JSON array entry is not a string");
        }
        ++position;
        std::string value;
        bool closed = false;
        while (position < json.size()) {
            const char ch = json[position++];
            if (ch == '"') {
                closed = true;
                break;
            }
            if (ch == '\\') {
                if (position >= json.size()) break;
                const char escaped = json[position++];
                if (escaped == '"' || escaped == '\\' || escaped == '/') {
                    value.push_back(escaped);
                } else {
                    throw std::invalid_argument("unsupported workload JSON array escape");
                }
            } else {
                value.push_back(ch);
            }
        }
        if (!closed) throw std::invalid_argument("unterminated workload JSON array");
        values.push_back(std::move(value));
    }
    throw std::invalid_argument("unterminated workload JSON array: " + key);
}

uint8_t HexNibble(char value) {
    if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f') {
        return static_cast<uint8_t>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<uint8_t>(value - 'A' + 10);
    }
    throw std::invalid_argument("workload bytes_hex contains non-hex data");
}

std::vector<uint8_t> HexDecode(const std::string& value) {
    if (value.empty() || value.size() % 2 != 0) {
        throw std::invalid_argument("workload bytes_hex has invalid length");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(value.size() / 2);
    for (size_t index = 0; index < value.size(); index += 2) {
        bytes.push_back(static_cast<uint8_t>(
            (HexNibble(value[index]) << 4) | HexNibble(value[index + 1])));
    }
    return bytes;
}

WorkloadData ReadWorkloadArtifact(const std::string& path) {
    const std::string json = ReadFile(path);
    if (JsonStringField(json, "schema") != "piccard-std-security-workload-v1") {
        throw std::invalid_argument("workload artifact schema mismatch");
    }
    const auto bytes = HexDecode(JsonStringField(json, "bytes_hex"));
    const auto parsed = benchmark::ComparisonWorkload::ParseAndVerify(bytes);
    const auto& spec = parsed.Spec();
    const std::vector<std::string> expected_methods = {
        "piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
        "bcg12_exact_ec", "sj16"};
    if (JsonStringField(json, "manifest_sha256") !=
            parsed.ManifestSha256Hex() ||
        JsonStringField(json, "workload_id") != parsed.WorkloadId() ||
        JsonStringField(json, "suite") != "toy-smoke" ||
        JsonStringField(json, "profile_id") != "toy-smoke" ||
        JsonUnsignedField(json, "root_seed") != 7 ||
        JsonUnsignedField(json, "k") != 16 ||
        JsonUnsignedField(json, "m") != 16 ||
        JsonUnsignedField(json, "set_size") != 10 ||
        JsonUnsignedField(json, "universe") != 64 ||
        JsonUnsignedField(json, "target_jaccard_numerator") != 1 ||
        JsonUnsignedField(json, "target_jaccard_denominator") != 2 ||
        JsonUnsignedField(json, "timing_trials") != 1 ||
        JsonUnsignedField(json, "accuracy_trials") != 1 ||
        JsonStringArrayField(json, "methods") != expected_methods ||
        spec.methods != expected_methods) {
        throw std::invalid_argument("workload artifact metadata mismatch");
    }
    if (parsed.Records().size() != 3 ||
        parsed.Records()[0].kind != benchmark::TrialKind::Warmup ||
        parsed.Records()[1].kind != benchmark::TrialKind::Timing ||
        parsed.Records()[1].index != 0 ||
        parsed.Records()[2].kind != benchmark::TrialKind::Accuracy ||
        parsed.Records()[2].index != 0) {
        throw std::invalid_argument("workload artifact record layout mismatch");
    }
    const auto& timing = parsed.Records()[1];
    if (timing.set_a.size() != kSetSize || timing.set_b.size() != kSetSize ||
        timing.exact_intersection != kExpectedIntersection ||
        timing.exact_union != kExpectedUnion ||
        timing.exact_jaccard != benchmark::ExactRational{7, 13}) {
        throw std::invalid_argument("workload timing record is not frozen toy point");
    }
    return WorkloadData{parsed};
}

std::string OrderedRnsSha256(const std::vector<std::string>& moduli) {
    std::vector<uint8_t> bytes;
    for (const auto& modulus : moduli) {
        const uint32_t length = static_cast<uint32_t>(modulus.size());
        for (int shift = 24; shift >= 0; shift -= 8) {
            bytes.push_back(static_cast<uint8_t>(length >> shift));
        }
        bytes.insert(bytes.end(), modulus.begin(), modulus.end());
    }
    return benchmark::Sha256Hex(bytes);
}

TupleData TupleFromContext(const baseline::BaselineEngine& engine,
                           const std::string& security) {
    const auto metadata = engine.GetBFVContext().GetRuntimeMetadata();
    TupleData tuple;
    tuple.bfv_context_fingerprint = metadata.context_fingerprint;
    tuple.circuit = "fhe_ind";
    tuple.shape_id = kShapeId;
    tuple.k = 0;
    tuple.m = 0;
    tuple.sanitizer_profile = "not-applicable";
    tuple.security = ParseSecurity(security);
    tuple.requested_ring_dim = metadata.requested_ring_dim;
    tuple.natural_ring_dim = metadata.natural_ring_dim;
    tuple.natural_depth = metadata.natural_depth;
    tuple.realized_ring_dim = metadata.actual_ring_dim;
    tuple.plaintext_modulus = metadata.plaintext_modulus;
    tuple.provisioned_depth = metadata.provisioned_depth;
    tuple.scaling_mod_size = metadata.scaling_mod_size;
    tuple.num_limbs = metadata.num_limbs;
    tuple.ordered_rns_moduli = metadata.ordered_rns_moduli;
    tuple.openfhe_version = metadata.openfhe_version;
    tuple.log_q_bits = metadata.log_q_bits;

    evidence::ContextTuple context_tuple;
    context_tuple.bfv_context_fingerprint = tuple.bfv_context_fingerprint;
    context_tuple.circuit = tuple.circuit;
    context_tuple.shape_id = tuple.shape_id;
    context_tuple.k = tuple.k;
    context_tuple.m = tuple.m;
    context_tuple.sanitizer_profile = tuple.sanitizer_profile;
    context_tuple.security = tuple.security;
    context_tuple.requested_ring_dim = tuple.requested_ring_dim;
    context_tuple.natural_ring_dim = tuple.natural_ring_dim;
    context_tuple.natural_depth = tuple.natural_depth;
    context_tuple.realized_ring_dim = tuple.realized_ring_dim;
    context_tuple.plaintext_modulus = tuple.plaintext_modulus;
    context_tuple.provisioned_depth = tuple.provisioned_depth;
    context_tuple.scaling_mod_size = tuple.scaling_mod_size;
    context_tuple.num_limbs = tuple.num_limbs;
    context_tuple.ordered_rns_moduli = tuple.ordered_rns_moduli;
    context_tuple.openfhe_version = tuple.openfhe_version;
    tuple.context_tuple_sha256 = evidence::ContextTupleSha256(context_tuple);
    return tuple;
}

void AddTuple(CanonicalJsonObject* object, const TupleData& tuple) {
    object->AddString("bfv_context_fingerprint", tuple.bfv_context_fingerprint);
    object->AddString("circuit", tuple.circuit);
    object->AddString("shape_id", tuple.shape_id);
    object->AddString("security", evidence::SecurityName(tuple.security));
    object->AddString("k", "N/A");
    object->AddString("m", "N/A");
    object->AddString("sanitizer_profile", tuple.sanitizer_profile);
    object->AddNumber("requested_ring_dim", tuple.requested_ring_dim);
    object->AddNumber("natural_ring_dim", tuple.natural_ring_dim);
    object->AddNumber("natural_depth", tuple.natural_depth);
    object->AddNumber("realized_ring_dim", tuple.realized_ring_dim);
    object->AddNumber("plaintext_modulus", tuple.plaintext_modulus);
    object->AddNumber("provisioned_depth", tuple.provisioned_depth);
    object->AddNumber("scaling_mod_size", tuple.scaling_mod_size);
    object->AddNumber("num_limbs", tuple.num_limbs);
    object->AddArray("ordered_rns_moduli", tuple.ordered_rns_moduli);
    object->AddString("openfhe_version", tuple.openfhe_version);
    object->AddNumber("log_q_bits", tuple.log_q_bits);
    object->AddString("context_tuple_sha256", tuple.context_tuple_sha256);
}

void AddBuild(CanonicalJsonObject* object) {
    object->AddString("build_id", PICCARD_BUILD_ID);
    object->AddBool("build_dirty", PICCARD_BUILD_DIRTY != 0);
    object->AddString("build_type", PICCARD_BUILD_TYPE);
    object->AddString("source_commit", PICCARD_BUILD_COMMIT);
}

CanonicalJsonObject CapabilitiesDescriptor(const std::string& binary_sha256) {
    CanonicalJsonObject object;
    object.AddString("schema", kCapabilitiesSchema);
    object.AddString("method", "fhe_ind");
    object.AddBool("context_only_preflight", true);
    object.AddBool("exactly_one_run", true);
    object.AddArray("security_profiles", {"STD128", "STD192"});
    CanonicalJsonObject workload;
    workload.AddNumber("universe", kUniverse);
    workload.AddNumber("set_size", kSetSize);
    workload.AddString("target_jaccard", "1/2");
    workload.AddNumber("seed", kSeed);
    workload.AddNumber("trials", kTrials);
    object.Add("workload", workload.Serialize());
    object.AddArray("context_tuple_fields", {
        "bfv_context_fingerprint", "circuit", "shape_id", "k", "m",
        "sanitizer_profile", "security", "requested_ring_dim",
        "natural_ring_dim", "natural_depth", "realized_ring_dim",
        "plaintext_modulus", "provisioned_depth", "scaling_mod_size",
        "num_limbs", "ordered_rns_moduli", "openfhe_version", "log_q_bits",
        "context_tuple_sha256"});
    CanonicalJsonObject provenance;
    provenance.AddBool("diagnostic_only", true);
    provenance.AddBool("piccard_sanitizer_applicable", false);
    provenance.AddBool("threshold_enabled", false);
    object.Add("provenance", provenance.Serialize());
    object.AddString("fhe_ind_binary_sha256", binary_sha256);
    return object;
}

ProducerIdentity ProducerIdentityForSelf() {
    ProducerIdentity identity;
    identity.fhe_ind_binary_sha256 = Sha256File(SelfExecutablePath());
    const auto descriptor = CapabilitiesDescriptor(
        identity.fhe_ind_binary_sha256);
    const std::string canonical = descriptor.Serialize() + "\n";
    const std::vector<uint8_t> bytes(canonical.begin(), canonical.end());
    identity.capabilities_sha256 = benchmark::Sha256Hex(bytes);
    return identity;
}

std::string JoinReasons(const evidence::PreflightDecision& decision) {
    std::ostringstream out;
    for (size_t index = 0; index < decision.reasons.size(); ++index) {
        if (index != 0) out << "; ";
        out << decision.reasons[index];
    }
    return out.str();
}

std::string PreflightJson(const Options& options, const WorkloadData& workload,
                          const TupleData& tuple,
                          const ProducerIdentity& identity) {
    evidence::PreflightCaps caps{tuple.realized_ring_dim,
                                 tuple.provisioned_depth, tuple.log_q_bits};
    const auto decision = evidence::EvaluatePreflight(caps);
    CanonicalJsonObject object;
    object.AddString("schema", kPreflightSchema);
    object.AddString("mode", "preflight");
    object.AddString("cell_id", options.cell_id);
    object.AddString("method", "fhe_ind");
    object.AddNumber("universe", kUniverse);
    object.AddNumber("set_size", kSetSize);
    object.AddString("target_jaccard", "1/2");
    object.AddNumber("seed", kSeed);
    object.AddNumber("trials", kTrials);
    AddTuple(&object, tuple);
    object.AddString("ordered_rns_moduli_sha256",
                     OrderedRnsSha256(tuple.ordered_rns_moduli));
    object.AddString("workload_id", workload.parsed.WorkloadId());
    object.AddString("workload_manifest_sha256",
                     workload.parsed.ManifestSha256Hex());
    object.AddString("fhe_ind_binary_sha256",
                     identity.fhe_ind_binary_sha256);
    object.AddString("capabilities_sha256", identity.capabilities_sha256);
    object.AddBool("keygen_started", false);
    object.AddBool("skipped", decision.skipped);
    object.AddString("reason", JoinReasons(decision));
    object.AddBool("diagnostic_only", true);
    object.AddBool("piccard_sanitizer_applicable", false);
    object.AddBool("threshold_enabled", false);
    object.AddBool("table_eligible", false);
    object.AddString("calibration_origin", "not-applicable");
    AddBuild(&object);
    return object.Serialize() + "\n";
}

// Work #5 context admission is intentionally independent of the frozen Work
// #4 workload-bound preflight.  n binds the requested cell even though only U
// changes the BFV context parameters.
std::string Work5PreflightJson(const Options& options, const TupleData& tuple,
                               const ProducerIdentity& identity) {
    evidence::PreflightCaps caps{tuple.realized_ring_dim,
                                 tuple.provisioned_depth, tuple.log_q_bits};
    const auto decision = evidence::EvaluatePreflight(caps);
    CanonicalJsonObject object;
    object.AddString("schema", kWork5PreflightSchema);
    object.AddString("mode", "work5-preflight");
    object.AddString("cell_id", options.cell_id);
    object.AddString("method", "fhe_ind");
    object.AddNumber("n", options.work5_n);
    object.AddNumber("universe", options.universe);
    AddTuple(&object, tuple);
    object.AddString("ordered_rns_moduli_sha256",
                     OrderedRnsSha256(tuple.ordered_rns_moduli));
    object.AddString("fhe_ind_binary_sha256", identity.fhe_ind_binary_sha256);
    object.AddString("capabilities_sha256", identity.capabilities_sha256);
    object.AddBool("keygen_started", false);
    object.AddBool("skipped", decision.skipped);
    object.AddString("reason", JoinReasons(decision));
    object.AddBool("diagnostic_only", true);
    object.AddBool("threshold_enabled", false);
    AddBuild(&object);
    return object.Serialize() + "\n";
}

void WriteNew(const std::string& path, const std::string& text) {
    RequireAbsolutePath(path, "--output");
    const std::filesystem::path destination(path);
    if (std::filesystem::exists(destination)) {
        throw std::runtime_error("refusing to overwrite existing artifact: " +
                                 path);
    }
    const auto parent = destination.parent_path();
    if (parent.empty() || !std::filesystem::is_directory(parent)) {
        throw std::runtime_error("diagnostic output parent does not exist: " +
                                 parent.string());
    }
    const auto temporary = parent / ("." + destination.filename().string() +
                                     ".tmp-" + std::to_string(static_cast<unsigned long>(::getpid())));
    const int descriptor = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL,
                                  0644);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "create diagnostic output");
    }
    bool closed = false;
    try {
        size_t offset = 0;
        while (offset < text.size()) {
            const ssize_t written = ::write(descriptor, text.data() + offset,
                                            text.size() - offset);
            if (written < 0) {
                throw std::system_error(errno, std::generic_category(),
                                        "write diagnostic output");
            }
            if (written == 0) {
                throw std::runtime_error("diagnostic output write made no progress");
            }
            offset += static_cast<size_t>(written);
        }
        if (::fsync(descriptor) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "fsync diagnostic output");
        }
        if (::close(descriptor) != 0) {
            closed = true;
            throw std::system_error(errno, std::generic_category(),
                                    "close diagnostic output");
        }
        closed = true;
        if (::link(temporary.c_str(), destination.c_str()) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "atomically install diagnostic output");
        }
        ::unlink(temporary.c_str());
    } catch (...) {
        if (!closed) ::close(descriptor);
        ::unlink(temporary.c_str());
        throw;
    }
}

TupleData TupleFromPreflight(const std::string& json) {
    TupleData tuple;
    tuple.bfv_context_fingerprint = JsonStringField(json, "bfv_context_fingerprint");
    tuple.circuit = JsonStringField(json, "circuit");
    tuple.shape_id = JsonStringField(json, "shape_id");
    tuple.k = 0;
    tuple.m = 0;
    if (JsonStringField(json, "k") != "N/A" ||
        JsonStringField(json, "m") != "N/A") {
        throw std::invalid_argument("FHE-IND preflight k/m are not N/A");
    }
    tuple.sanitizer_profile = JsonStringField(json, "sanitizer_profile");
    tuple.security = ParseSecurity(JsonStringField(json, "security"));
    tuple.requested_ring_dim = JsonUint32Field(json, "requested_ring_dim");
    tuple.natural_ring_dim = JsonUint32Field(json, "natural_ring_dim");
    tuple.natural_depth = JsonUint32Field(json, "natural_depth");
    tuple.realized_ring_dim = JsonUint32Field(json, "realized_ring_dim");
    tuple.plaintext_modulus = JsonUnsignedField(json, "plaintext_modulus");
    tuple.provisioned_depth = JsonUint32Field(json, "provisioned_depth");
    tuple.scaling_mod_size = JsonUint32Field(json, "scaling_mod_size");
    tuple.num_limbs = JsonUint32Field(json, "num_limbs");
    tuple.ordered_rns_moduli = JsonStringArrayField(json, "ordered_rns_moduli");
    tuple.openfhe_version = JsonStringField(json, "openfhe_version");
    const std::string log_q = JsonScalarField(json, "log_q_bits");
    size_t consumed = 0;
    tuple.log_q_bits = std::stod(log_q, &consumed);
    if (consumed != log_q.size() || !std::isfinite(tuple.log_q_bits)) {
        throw std::invalid_argument("FHE-IND preflight log_q_bits is malformed");
    }
    tuple.context_tuple_sha256 = JsonStringField(json, "context_tuple_sha256");
    if (tuple.num_limbs == 0 || tuple.num_limbs != tuple.ordered_rns_moduli.size() ||
        tuple.requested_ring_dim == 0 || tuple.natural_ring_dim == 0 ||
        tuple.natural_depth == 0 || tuple.realized_ring_dim == 0 ||
        tuple.plaintext_modulus == 0 || tuple.provisioned_depth == 0 ||
        tuple.scaling_mod_size == 0 || tuple.bfv_context_fingerprint.empty() ||
        tuple.openfhe_version.empty()) {
        throw std::invalid_argument("FHE-IND preflight tuple is incomplete");
    }
    evidence::ContextTuple context_tuple;
    context_tuple.bfv_context_fingerprint = tuple.bfv_context_fingerprint;
    context_tuple.circuit = tuple.circuit;
    context_tuple.shape_id = tuple.shape_id;
    context_tuple.k = tuple.k;
    context_tuple.m = tuple.m;
    context_tuple.sanitizer_profile = tuple.sanitizer_profile;
    context_tuple.security = tuple.security;
    context_tuple.requested_ring_dim = tuple.requested_ring_dim;
    context_tuple.natural_ring_dim = tuple.natural_ring_dim;
    context_tuple.natural_depth = tuple.natural_depth;
    context_tuple.realized_ring_dim = tuple.realized_ring_dim;
    context_tuple.plaintext_modulus = tuple.plaintext_modulus;
    context_tuple.provisioned_depth = tuple.provisioned_depth;
    context_tuple.scaling_mod_size = tuple.scaling_mod_size;
    context_tuple.num_limbs = tuple.num_limbs;
    context_tuple.ordered_rns_moduli = tuple.ordered_rns_moduli;
    context_tuple.openfhe_version = tuple.openfhe_version;
    if (tuple.context_tuple_sha256 != evidence::ContextTupleSha256(context_tuple)) {
        throw std::invalid_argument("FHE-IND preflight context digest mismatch");
    }
    return tuple;
}

bool ValidatePreflight(const Options& options, const WorkloadData& workload,
                       const TupleData& current,
                       const ProducerIdentity& identity) {
    const std::string json = ReadFile(options.preflight);
    if (JsonStringField(json, "schema") != kPreflightSchema ||
        JsonStringField(json, "mode") != "preflight" ||
        JsonStringField(json, "method") != "fhe_ind" ||
        JsonStringField(json, "circuit") != "fhe_ind" ||
        JsonStringField(json, "shape_id") != kShapeId ||
        JsonStringField(json, "cell_id") != options.cell_id ||
        JsonStringField(json, "security") != options.security ||
        JsonUnsignedField(json, "universe") != kUniverse ||
        JsonUnsignedField(json, "set_size") != kSetSize ||
        JsonStringField(json, "target_jaccard") != "1/2" ||
        JsonUnsignedField(json, "seed") != kSeed ||
        JsonUnsignedField(json, "trials") != kTrials ||
        JsonStringField(json, "k") != "N/A" ||
        JsonStringField(json, "m") != "N/A" ||
        JsonStringField(json, "workload_id") != workload.parsed.WorkloadId() ||
        JsonStringField(json, "workload_manifest_sha256") !=
            workload.parsed.ManifestSha256Hex() ||
        JsonStringField(json, "fhe_ind_binary_sha256") !=
            identity.fhe_ind_binary_sha256 ||
        JsonStringField(json, "capabilities_sha256") !=
            identity.capabilities_sha256 ||
        JsonStringField(json, "sanitizer_profile") != "not-applicable" ||
        JsonStringField(json, "calibration_origin") != "not-applicable" ||
        JsonStringField(json, "source_commit") != PICCARD_BUILD_COMMIT ||
        JsonStringField(json, "build_id") != PICCARD_BUILD_ID ||
        JsonStringField(json, "build_type") != PICCARD_BUILD_TYPE ||
        JsonStringField(json, "openfhe_version") != current.openfhe_version) {
        throw std::invalid_argument("FHE-IND preflight identity mismatch");
    }
    const std::string build_dirty = JsonScalarField(json, "build_dirty");
    const std::string skipped = JsonScalarField(json, "skipped");
    const std::string reason = JsonStringField(json, "reason");
    if (build_dirty != (PICCARD_BUILD_DIRTY != 0 ? "true" : "false") ||
        JsonScalarField(json, "keygen_started") != "false" ||
        JsonScalarField(json, "diagnostic_only") != "true" ||
        JsonScalarField(json, "piccard_sanitizer_applicable") != "false" ||
        JsonScalarField(json, "threshold_enabled") != "false" ||
        JsonScalarField(json, "table_eligible") != "false" ||
        (skipped != "true" && skipped != "false")) {
        throw std::invalid_argument("FHE-IND preflight stage/provenance mismatch");
    }
    const TupleData recorded = TupleFromPreflight(json);
    if (recorded.bfv_context_fingerprint != current.bfv_context_fingerprint ||
        recorded.circuit != current.circuit || recorded.shape_id != current.shape_id ||
        recorded.security != current.security ||
        recorded.requested_ring_dim != current.requested_ring_dim ||
        recorded.natural_ring_dim != current.natural_ring_dim ||
        recorded.natural_depth != current.natural_depth ||
        recorded.realized_ring_dim != current.realized_ring_dim ||
        recorded.plaintext_modulus != current.plaintext_modulus ||
        recorded.provisioned_depth != current.provisioned_depth ||
        recorded.scaling_mod_size != current.scaling_mod_size ||
        recorded.num_limbs != current.num_limbs ||
        recorded.ordered_rns_moduli != current.ordered_rns_moduli ||
        recorded.openfhe_version != current.openfhe_version ||
        std::abs(recorded.log_q_bits - current.log_q_bits) > 1e-9 ||
        recorded.context_tuple_sha256 != current.context_tuple_sha256) {
        throw std::invalid_argument("FHE-IND preflight context tuple mismatch");
    }
    evidence::PreflightCaps caps{current.realized_ring_dim,
                                 current.provisioned_depth, current.log_q_bits};
    const auto decision = evidence::EvaluatePreflight(caps);
    if ((skipped == "true") != decision.skipped ||
        reason != JoinReasons(decision)) {
        throw std::invalid_argument("FHE-IND preflight cap decision mismatch");
    }
    return decision.skipped;
}

std::string CsvCell(const std::string& value) {
    if (value.find_first_of(",\"\n\r") == std::string::npos) return value;
    std::string escaped = "\"";
    for (const char ch : value) {
        if (ch == '"') escaped += "\"\"";
        else escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

std::string CsvHeader() {
    return "cell_id,circuit,shape_id,security,k,m,universe,set_size,target_jaccard,"
           "realized_intersection,realized_union,realized_jaccard,seed,trials,"
           "requested_ring_dim,natural_ring_dim,realized_ring_dim,natural_depth,"
           "provisioned_depth,scaling_mod_size,num_limbs,plaintext_modulus,"
           "bfv_context_fingerprint,log_q_bits,ordered_rns_moduli,"
           "ordered_rns_moduli_sha256,openfhe_version,sanitizer_profile,"
           "context_tuple_sha256,calibration_origin,workload_id,"
           "workload_manifest_sha256,timing_hash_seed,setup_context_ms,"
           "setup_keygen_ms,phase_encode_ms,phase_encrypt_ms,phase_evaluate_ms,"
           "phase_decrypt_ms,online_e2e_ms,full_e2e_ms,match_count,"
           "jaccard_estimate,status,reason,method,fhe_ind_binary_sha256,"
           "capabilities_sha256\n";
}

std::string OrderedRnsJson(const std::vector<std::string>& moduli) {
    std::ostringstream out;
    out << '[';
    for (size_t index = 0; index < moduli.size(); ++index) {
        if (index != 0) out << ',';
        out << JsonEscape(moduli[index]);
    }
    out << ']';
    return out.str();
}

double RequirePositiveTiming(double value, const char* field) {
    if (!std::isfinite(value) || value <= 0.0) {
        throw std::runtime_error(std::string("FHE-IND raw timing is not positive: ") +
                                 field);
    }
    return value;
}

std::string E2eCsv(const Options& options, const WorkloadData& workload,
                   const TupleData& tuple,
                   const ProducerIdentity& identity,
                   const baseline::FheIndQueryResult& result) {
    const double encode = RequirePositiveTiming(result.phase_encode_ms,
                                                "phase_encode_ms");
    const double encrypt = RequirePositiveTiming(result.phase_encrypt_ms,
                                                 "phase_encrypt_ms");
    const double evaluate = RequirePositiveTiming(result.phase_evaluate_ms,
                                                  "phase_evaluate_ms");
    const double decrypt = RequirePositiveTiming(result.phase_decrypt_ms,
                                                 "phase_decrypt_ms");
    const double online = encode + encrypt + evaluate + decrypt;
    const double setup_context = RequirePositiveTiming(result.setup_context_ms,
                                                       "setup_context_ms");
    const double setup_keygen = RequirePositiveTiming(result.setup_keygen_ms,
                                                      "setup_keygen_ms");
    const double full = setup_context + setup_keygen + online;
    if (!std::isfinite(online) || online <= 0.0 || !std::isfinite(full) ||
        full <= 0.0) {
        throw std::runtime_error("FHE-IND derived timings are not positive");
    }
    const std::vector<std::string> fields = {
        options.cell_id,
        "fhe_ind",
        kShapeId,
        options.security,
        "N/A",
        "N/A",
        Number(kUniverse),
        Number(kSetSize),
        "0.5",
        Number(kExpectedIntersection),
        Number(kExpectedUnion),
        Number(7.0 / 13.0),
        Number(kSeed),
        Number(kTrials),
        Number(tuple.requested_ring_dim),
        Number(tuple.natural_ring_dim),
        Number(tuple.realized_ring_dim),
        Number(tuple.natural_depth),
        Number(tuple.provisioned_depth),
        Number(tuple.scaling_mod_size),
        Number(tuple.num_limbs),
        Number(tuple.plaintext_modulus),
        tuple.bfv_context_fingerprint,
        Number(tuple.log_q_bits),
        OrderedRnsJson(tuple.ordered_rns_moduli),
        OrderedRnsSha256(tuple.ordered_rns_moduli),
        tuple.openfhe_version,
        "not-applicable",
        tuple.context_tuple_sha256,
        "not-applicable",
        workload.parsed.WorkloadId(),
        workload.parsed.ManifestSha256Hex(),
        Number(workload.parsed.Records()[1].hash_seed),
        Number(setup_context),
        Number(setup_keygen),
        Number(encode),
        Number(encrypt),
        Number(evaluate),
        Number(decrypt),
        Number(online),
        Number(full),
        Number(kExpectedIntersection),
        Number(7.0 / 13.0),
        "MEASURED",
        "",
        "fhe_ind",
        identity.fhe_ind_binary_sha256,
        identity.capabilities_sha256,
    };
    std::ostringstream out;
    out << CsvHeader();
    for (size_t index = 0; index < fields.size(); ++index) {
        if (index != 0) out << ',';
        out << CsvCell(fields[index]);
    }
    out << '\n';
    return out.str();
}

std::string CapabilitiesJson(const ProducerIdentity& identity) {
    auto object = CapabilitiesDescriptor(identity.fhe_ind_binary_sha256);
    object.AddString("capabilities_sha256", identity.capabilities_sha256);
    return object.Serialize() + "\n";
}

int Run(const Options& options) {
    const ProducerIdentity identity = ProducerIdentityForSelf();
    if (options.capabilities) {
        std::cout << CapabilitiesJson(identity);
        return 0;
    }
    RequireAbsolutePath(options.output, "--output");
    if (options.mode == "work5-preflight") {
        baseline::BaselineParams params;
        params.universe_size = options.universe;
        params.security = ParseSecurity(options.security);
        params.Validate();
        baseline::BaselineEngine engine(params);
        engine.InitializeContextOnly();
        if (engine.HasGeneratedKeys()) {
            throw std::logic_error("Work #5 FHE-IND preflight generated keys");
        }
        WriteNew(options.output, Work5PreflightJson(
            options, TupleFromContext(engine, options.security), identity));
        return 0;
    }
    RequireAbsolutePath(options.workload, "--workload");
    if (options.mode == "e2e") RequireAbsolutePath(options.preflight, "--preflight");

    const WorkloadData workload = ReadWorkloadArtifact(options.workload);
    baseline::BaselineParams params;
    params.universe_size = kUniverse;
    params.security = ParseSecurity(options.security);
    params.Validate();
    baseline::BaselineEngine engine(params);
    engine.InitializeContextOnly();
    const TupleData tuple = TupleFromContext(engine, options.security);

    if (options.mode == "preflight") {
        if (engine.HasGeneratedKeys()) {
            throw std::logic_error("FHE-IND preflight generated keys");
        }
        WriteNew(options.output, PreflightJson(options, workload, tuple,
                                               identity));
        return 0;
    }

    if (ValidatePreflight(options, workload, tuple, identity)) {
        throw std::runtime_error(
            "FHE-IND preflight is SKIPPED_PRECHECK; e2e is not permitted");
    }
    engine.InitializeKeys();
    const TupleData after_keys = TupleFromContext(engine, options.security);
    if (after_keys.context_tuple_sha256 != tuple.context_tuple_sha256 ||
        after_keys.realized_ring_dim != tuple.realized_ring_dim ||
        after_keys.ordered_rns_moduli != tuple.ordered_rns_moduli) {
        throw std::invalid_argument("FHE-IND context tuple changed after keygen");
    }
    const auto& timing = workload.parsed.Records()[1];
    const auto result = engine.RunQueryPhased(timing.set_a, timing.set_b);
    if (result.intersection != kExpectedIntersection ||
        result.union_size != kExpectedUnion ||
        result.jaccard != 7.0 / 13.0) {
        throw std::runtime_error("FHE-IND result does not match frozen workload");
    }
    WriteNew(options.output, E2eCsv(options, workload, tuple, identity, result));
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return Run(ParseOptions(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << "bench_fhe_ind: " << error.what() << '\n';
        return 2;
    }
}
