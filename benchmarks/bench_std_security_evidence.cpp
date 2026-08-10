/**
 * Diagnostic STD128/STD192 evidence probe.
 *
 * This executable is intentionally narrow: it supports the four-cell core
 * smoke matrix's OneHot/Sqrt calibration seam, with one context-only
 * preflight and one observation for each of all_match/no_match/random. It
 * never writes the production calibration table and has no Threshold entry
 * point.
 */

#include "build_info.h"
#include "benchmark_utils.h"
#include "comparison_workload.h"
#include "noise_calibration_probe.h"
#include "protocol/piccard.h"
#include "protocol/sqrt_piccard.h"
#include "std_security_evidence_schema.h"
#include "util/params_calibration.h"
#include "version.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace {

namespace schema = piccard::std_evidence;
namespace probe = piccard::std_evidence::calibration;
namespace workload = piccard::benchmark;

constexpr char kConsumerSerialization[] = "16:16\n";
constexpr char kConsumerSetSha256[] =
    "6ccdf58fe5af9c67abc7fb6c82dd4a94b803187b0a2d65ddaa4c9518aa24524a";
constexpr char kProfileId[] = "primary40";

struct Options {
    std::string mode;
    std::string circuit;
    std::string security;
    std::string shape_id;
    std::string cell_id;
    std::string output;
    std::string calibration;
    std::string workload;
    std::string format = "json";
    uint32_t k = 16;
    uint32_t m = 16;
    uint32_t provisioned_depth = 0;
    uint32_t scaling_mod_size = 40;
    uint64_t seed = 7;
    uint64_t work5_n = 0;
    uint64_t work5_universe = 0;
    bool circuit_specified = false;
    bool security_specified = false;
    bool shape_specified = false;
    bool k_specified = false;
    bool m_specified = false;
    bool depth_specified = false;
    bool scaling_specified = false;
    bool seed_specified = false;
    bool work5_n_specified = false;
    bool work5_universe_specified = false;
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

// All diagnostic JSON is emitted through this tiny object writer.  Keeping
// keys in a map gives us the repository-wide canonical contract
// (UTF-8/compact/sort_keys) without relying on a third-party JSON runtime in
// the benchmark executable.
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

std::string CanonicalJsonStringArray(
    const std::vector<std::string>& values) {
    std::ostringstream out;
    out << '[';
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) out << ',';
        out << JsonEscape(values[index]);
    }
    out << ']';
    return out.str();
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

uint32_t ParseUint32(const std::string& value, const char* option) {
    const uint64_t parsed = ParseUnsigned(value, option);
    if (parsed == 0 || parsed > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(std::string(option) +
                                    " must be a positive uint32");
    }
    return static_cast<uint32_t>(parsed);
}

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

Options ParseOptions(int argc, char** argv) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if (const auto value = OptionValue(argument, "mode"); !value.empty()) {
            options.mode = value;
        } else if (const auto value = OptionValue(argument, "circuit");
                   !value.empty()) {
            options.circuit = value;
            options.circuit_specified = true;
        } else if (const auto value = OptionValue(argument, "security");
                   !value.empty()) {
            options.security = value;
            options.security_specified = true;
        } else if (const auto value = OptionValue(argument, "shape-id");
                   !value.empty()) {
            options.shape_id = value;
            options.shape_specified = true;
        } else if (const auto value = OptionValue(argument, "cell-id");
                   !value.empty()) {
            options.cell_id = value;
        } else if (const auto value = OptionValue(argument, "output");
                   !value.empty()) {
            options.output = value;
        } else if (const auto value = OptionValue(argument, "calibration");
                   !value.empty()) {
            options.calibration = value;
        } else if (const auto value = OptionValue(argument, "workload");
                   !value.empty()) {
            options.workload = value;
        } else if (const auto value = OptionValue(argument, "format");
                   !value.empty()) {
            options.format = value;
        } else if (const auto value = OptionValue(argument, "k");
                   !value.empty()) {
            options.k = ParseUint32(value, "--k");
            options.k_specified = true;
        } else if (const auto value = OptionValue(argument, "m");
                   !value.empty()) {
            options.m = ParseUint32(value, "--m");
            options.m_specified = true;
        } else if (const auto value = OptionValue(argument, "depth");
                   !value.empty()) {
            options.provisioned_depth = ParseUint32(value, "--depth");
            options.depth_specified = true;
        } else if (const auto value = OptionValue(argument, "scaling-mod-size");
                   !value.empty()) {
            options.scaling_mod_size = ParseUint32(value, "--scaling-mod-size");
            options.scaling_specified = true;
        } else if (const auto value = OptionValue(argument, "seed");
                   !value.empty()) {
            options.seed = ParseUnsigned(value, "--seed");
            options.seed_specified = true;
        } else if (const auto value = OptionValue(argument, "n");
                   !value.empty()) {
            options.work5_n = ParseUnsigned(value, "--n");
            options.work5_n_specified = true;
        } else if (const auto value = OptionValue(argument, "universe");
                   !value.empty()) {
            options.work5_universe = ParseUnsigned(value, "--universe");
            options.work5_universe_specified = true;
        } else if (argument == "--help") {
            std::cout
                << "bench_std_security_evidence --mode=workload|preflight|work5-preflight|calibrate "
                   "--circuit=onehot|sqrt --security=TOY|STD128|STD192 "
                   "[--workload=PATH --format=json|csv --depth=N "
                   "--scaling-mod-size=N --output=PATH]\n";
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown option: " + argument);
        }
    }
    if (options.mode != "workload" && options.mode != "preflight" &&
        options.mode != "work5-preflight" &&
        options.mode != "calibrate" &&
        options.mode != "e2e") {
        throw std::invalid_argument(
            "--mode must be workload, preflight, work5-preflight, calibrate, or e2e");
    }
    if (options.mode == "e2e" && options.calibration.empty()) {
        throw std::invalid_argument("--mode=e2e requires --calibration=PATH");
    }
    if (options.format != "json" && options.format != "csv") {
        throw std::invalid_argument("--format must be json or csv");
    }
    if (options.mode != "workload" && options.mode != "e2e" &&
        options.circuit != "onehot" &&
        options.circuit != "sqrt") {
        throw std::invalid_argument("--circuit must be onehot or sqrt");
    }
    if (options.mode != "workload" && options.mode != "e2e" &&
        options.security != "TOY" &&
        options.security != "STD128" && options.security != "STD192") {
        throw std::invalid_argument(
            "--security must be TOY, STD128, or STD192");
    }
    if (options.mode != "workload" && options.mode != "e2e" &&
        options.shape_id.empty()) {
        options.shape_id = options.circuit == "onehot" ? "onehot-v1"
                                                        : "sqrt-b4-v1";
    }
    if (options.mode != "workload" && options.mode != "e2e" &&
        ((options.circuit == "onehot" && options.shape_id != "onehot-v1") ||
        (options.circuit == "sqrt" && options.shape_id != "sqrt-b4-v1"))) {
        throw std::invalid_argument("shape id does not match circuit");
    }
    // The original diagnostic modes are byte-frozen at k=m=16.  The
    // Work #5-only mode carries its own schema and identity binding.
    if (options.mode != "workload" && options.mode != "e2e" &&
        options.mode != "work5-preflight" &&
        (options.k != 16 || options.m != 16)) {
        throw std::invalid_argument(
            "diagnostic smoke workload is frozen at k=16,m=16");
    }
    if (options.mode == "workload" &&
        (options.format != "json" || !options.workload.empty())) {
        throw std::invalid_argument(
            "workload mode emits canonical JSON and does not consume a workload");
    }
    if (options.mode == "e2e" && !options.workload.empty() &&
        options.format != "csv") {
        throw std::invalid_argument(
            "workload-bound e2e requires --format=csv");
    }
    if (options.mode == "work5-preflight") {
        if (options.cell_id.empty() || !options.work5_n_specified ||
            !options.work5_universe_specified || options.work5_n == 0 ||
            (options.work5_universe != 16384 && options.work5_universe != 65536)) {
            throw std::invalid_argument(
                "work5-preflight requires --cell-id, positive --n, and --universe=16384|65536");
        }
        if (options.format != "json" || options.output.empty() ||
            !options.workload.empty() || !options.calibration.empty() ||
            options.depth_specified || options.scaling_specified || options.seed_specified) {
            throw std::invalid_argument(
                "work5-preflight accepts only its bound context identity and --output=json");
        }
    } else if (!options.cell_id.empty() || options.work5_n_specified ||
               options.work5_universe_specified) {
        throw std::invalid_argument("--cell-id, --n, and --universe are Work #5-only options");
    }
    return options;
}

std::string ReadFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) throw std::runtime_error("failed to open " + path);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

std::string Sha256Text(const std::string& text) {
    return workload::Sha256Hex(std::vector<uint8_t>(text.begin(), text.end()));
}

// Forward declarations for the strict scalar/array readers defined below.
std::string JsonStringField(const std::string& json, const std::string& key);
uint64_t JsonUnsignedField(const std::string& json, const std::string& key);
uint32_t JsonUint32Field(const std::string& json, const std::string& key);
std::vector<std::string> JsonStringArrayField(const std::string& json,
                                              const std::string& key);

std::string HexEncode(const std::vector<uint8_t>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const uint8_t byte : bytes) {
        result.push_back(kHex[byte >> 4]);
        result.push_back(kHex[byte & 0x0f]);
    }
    return result;
}

uint8_t HexNibble(char value) {
    if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f')
        return static_cast<uint8_t>(value - 'a' + 10);
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

workload::ComparisonWorkload MakeToyWorkload() {
    workload::WorkloadSpec spec;
    spec.suite = "toy-smoke";
    spec.profile_id = "toy-smoke";
    spec.root_seed = 7;
    spec.k = 16;
    spec.m = 16;
    spec.set_size = 10;
    spec.universe = 64;
    spec.target_jaccard = {1, 2};
    spec.methods = {"piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
                    "bcg12_exact_ec", "sj16"};
    spec.timing_trials = 1;
    spec.accuracy_trials = 1;
    return workload::ComparisonWorkload::Generate(spec);
}

std::string WorkloadJson() {
    const auto generated = MakeToyWorkload();
    const auto& spec = generated.Spec();
    std::ostringstream method_array;
    method_array << '[';
    for (size_t index = 0; index < spec.methods.size(); ++index) {
        if (index != 0) method_array << ',';
        method_array << JsonEscape(spec.methods[index]);
    }
    method_array << ']';
    CanonicalJsonObject object;
    object.AddString("bytes_hex", HexEncode(generated.Bytes()));
    object.AddNumber("accuracy_trials", spec.accuracy_trials);
    object.AddString("manifest_sha256", generated.ManifestSha256Hex());
    object.Add("methods", method_array.str());
    object.AddNumber("k", spec.k);
    object.AddNumber("m", spec.m);
    object.AddString("profile_id", spec.profile_id);
    object.AddNumber("root_seed", spec.root_seed);
    object.AddNumber("set_size", spec.set_size);
    object.AddString("schema", "piccard-std-security-workload-v1");
    object.AddString("suite", spec.suite);
    object.AddNumber("target_jaccard_denominator",
                     spec.target_jaccard.denominator);
    object.AddNumber("target_jaccard_numerator",
                     spec.target_jaccard.numerator);
    object.AddNumber("timing_trials", spec.timing_trials);
    object.AddNumber("universe", spec.universe);
    object.AddString("workload_id", generated.WorkloadId());
    return object.Serialize() + "\n";
}

workload::ComparisonWorkload ReadWorkloadArtifact(const std::string& path) {
    const std::string json = ReadFile(path);
    if (JsonStringField(json, "schema") !=
        "piccard-std-security-workload-v1") {
        throw std::invalid_argument("workload artifact schema mismatch");
    }
    const auto bytes = HexDecode(JsonStringField(json, "bytes_hex"));
    const auto parsed = workload::ComparisonWorkload::ParseAndVerify(bytes);
    const auto& spec = parsed.Spec();
    if (JsonStringField(json, "manifest_sha256") !=
            parsed.ManifestSha256Hex() ||
        JsonStringField(json, "workload_id") != parsed.WorkloadId() ||
        JsonStringField(json, "suite") != spec.suite ||
        JsonStringField(json, "profile_id") != spec.profile_id ||
        JsonUnsignedField(json, "root_seed") != spec.root_seed ||
        JsonUnsignedField(json, "k") != spec.k ||
        JsonUnsignedField(json, "m") != spec.m ||
        JsonUnsignedField(json, "set_size") != spec.set_size ||
        JsonUnsignedField(json, "universe") != spec.universe ||
        JsonUnsignedField(json, "target_jaccard_numerator") !=
            spec.target_jaccard.numerator ||
        JsonUnsignedField(json, "target_jaccard_denominator") !=
            spec.target_jaccard.denominator ||
        JsonUint32Field(json, "timing_trials") != spec.timing_trials ||
        JsonUint32Field(json, "accuracy_trials") != spec.accuracy_trials ||
        JsonStringArrayField(json, "methods") != spec.methods) {
        throw std::invalid_argument("workload artifact metadata mismatch");
    }
    const auto expected = MakeToyWorkload();
    if (parsed.Bytes() != expected.Bytes()) {
        throw std::invalid_argument("workload artifact is not frozen toy-smoke");
    }
    if (parsed.Records().size() != 3 ||
        parsed.Records()[0].kind != workload::TrialKind::Warmup ||
        parsed.Records()[1].kind != workload::TrialKind::Timing ||
        parsed.Records()[1].index != 0 ||
        parsed.Records()[2].kind != workload::TrialKind::Accuracy ||
        parsed.Records()[2].index != 0) {
        throw std::invalid_argument("workload must contain frozen warmup/timing/accuracy records");
    }
    return parsed;
}

size_t JsonKeyPosition(const std::string& json, const std::string& key) {
    size_t position = 0;
    int depth = 0;
    while (position < json.size()) {
        const char ch = json[position];
        if (ch == '{' || ch == '[') {
            ++depth;
            ++position;
            continue;
        }
        if (ch == '}' || ch == ']') {
            --depth;
            ++position;
            continue;
        }
        if (ch != '"') {
            ++position;
            continue;
        }
        const size_t begin = ++position;
        bool escaped = false;
        while (position < json.size()) {
            const char current = json[position++];
            if (escaped) {
                escaped = false;
            } else if (current == '\\') {
                escaped = true;
            } else if (current == '"') {
                break;
            }
        }
        if (position > json.size() || json[position - 1] != '"') {
            break;
        }
        size_t after = position;
        while (after < json.size() &&
               (json[after] == ' ' || json[after] == '\n' ||
                json[after] == '\r' || json[after] == '\t')) {
            ++after;
        }
        if (depth == 1 && json.substr(begin, position - begin - 1) == key &&
            after < json.size() && json[after] == ':') {
            return after + 1;
        }
    }
    throw std::invalid_argument("calibration artifact lacks key " + key);
}

std::string JsonStringField(const std::string& json, const std::string& key) {
    size_t position = JsonKeyPosition(json, key);
    if (position >= json.size() || json[position] != '"') {
        throw std::invalid_argument("calibration field is not a string: " + key);
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
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            default:
                throw std::invalid_argument(
                    "unsupported escape in calibration field: " + key);
        }
    }
    throw std::invalid_argument("unterminated calibration string: " + key);
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
        throw std::invalid_argument("unterminated calibration scalar: " + key);
    }
    std::string value = json.substr(position, end - position);
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\r' ||
            value.back() == '\t')) {
        value.pop_back();
    }
    return value;
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
        throw std::invalid_argument("calibration field is not an array: " + key);
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
            throw std::invalid_argument("calibration array entry is not a string");
        }
        ++position;
        std::string value;
        while (position < json.size()) {
            const char ch = json[position++];
            if (ch == '"') break;
            if (ch == '\\') {
                if (position >= json.size()) break;
                const char escaped = json[position++];
                if (escaped == '"' || escaped == '\\') value.push_back(escaped);
                else throw std::invalid_argument("unsupported array escape");
            } else {
                value.push_back(ch);
            }
        }
        values.push_back(std::move(value));
    }
    throw std::invalid_argument("unterminated calibration array: " + key);
}

uint64_t JsonUnsignedField(const std::string& json, const std::string& key) {
    return ParseUnsigned(JsonScalarField(json, key), key.c_str());
}

uint32_t JsonUint32Field(const std::string& json, const std::string& key) {
    const uint64_t value = JsonUnsignedField(json, key);
    if (value > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument("calibration field overflows uint32: " + key);
    }
    return static_cast<uint32_t>(value);
}

double JsonDoubleField(const std::string& json, const std::string& key) {
    size_t consumed = 0;
    const std::string value = JsonScalarField(json, key);
    const double parsed = std::stod(value, &consumed);
    if (consumed != value.size() || !std::isfinite(parsed)) {
        throw std::invalid_argument("invalid calibration number: " + key);
    }
    return parsed;
}

bool JsonBoolField(const std::string& json, const std::string& key) {
    const std::string value = JsonScalarField(json, key);
    if (value == "true") return true;
    if (value == "false") return false;
    throw std::invalid_argument("invalid calibration boolean: " + key);
}

size_t CountToken(const std::string& json, const std::string& token) {
    size_t count = 0;
    size_t position = 0;
    while ((position = json.find(token, position)) != std::string::npos) {
        ++count;
        position += token.size();
    }
    return count;
}

struct CalibrationArtifact {
    std::string circuit;
    std::string shape_id;
    std::string security;
    std::string source_commit;
    std::string build_id;
    std::string build_type;
    bool build_dirty = false;
    std::string openfhe_version;
    std::string bfv_context_fingerprint;
    std::string context_tuple_sha256;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t seed = 0;
    uint32_t requested_ring_dim = 0;
    uint32_t natural_ring_dim = 0;
    uint32_t realized_ring_dim = 0;
    uint32_t natural_depth = 0;
    uint32_t provisioned_depth = 0;
    uint32_t scaling_mod_size = 0;
    uint32_t num_limbs = 0;
    uint64_t plaintext_modulus = 0;
    double log_q_bits = 0.0;
    uint32_t eval_noise_bits = 0;
    uint32_t query_stat_bits = 0;
    uint32_t coefficient_stat_bits = 0;
    uint32_t flood_margin_bits = 0;
    uint32_t flood_noise_bits = 0;
    uint32_t required_capacity_bits = 0;
    double log_q_over_t_bits = 0.0;
    uint64_t ct_bytes = 0;
    std::vector<std::string> ordered_rns_moduli;
    struct PatternRow {
        std::string pattern;
        uint32_t repetition_index = 0;
        uint64_t seed = 0;
        int64_t expected_matches = 0;
        int64_t observed_matches = 0;
        double eval_noise_bits = 0.0;
        bool decrypt_ok = false;
        bool saturated = false;
    };
    std::vector<PatternRow> patterns;
};

std::vector<std::string> PatternObjects(const std::string& json) {
    size_t position = JsonKeyPosition(json, "patterns");
    position = json.find('[', position);
    if (position == std::string::npos) {
        throw std::invalid_argument("calibration patterns array is missing");
    }
    ++position;
    std::vector<std::string> objects;
    while (position < json.size()) {
        while (position < json.size() &&
               (json[position] == ' ' || json[position] == '\n' ||
                json[position] == '\r' || json[position] == '\t' ||
                json[position] == ',')) {
            ++position;
        }
        if (position < json.size() && json[position] == ']') return objects;
        if (position >= json.size() || json[position] != '{') {
            throw std::invalid_argument("calibration pattern is not an object");
        }
        const size_t begin = position;
        bool in_string = false;
        bool escaped = false;
        int depth = 0;
        for (; position < json.size(); ++position) {
            const char ch = json[position];
            if (in_string) {
                if (escaped) {
                    escaped = false;
                } else if (ch == '\\') {
                    escaped = true;
                } else if (ch == '"') {
                    in_string = false;
                }
                continue;
            }
            if (ch == '"') {
                in_string = true;
            } else if (ch == '{') {
                ++depth;
            } else if (ch == '}') {
                --depth;
                if (depth == 0) {
                    ++position;
                    objects.push_back(json.substr(begin, position - begin));
                    break;
                }
            }
        }
        if (depth != 0) {
            throw std::invalid_argument("unterminated calibration pattern");
        }
    }
    throw std::invalid_argument("unterminated calibration patterns array");
}

int64_t JsonSignedField(const std::string& json, const std::string& key) {
    const std::string value = JsonScalarField(json, key);
    size_t consumed = 0;
    const long long parsed = std::stoll(value, &consumed, 10);
    if (consumed != value.size()) {
        throw std::invalid_argument("invalid signed calibration field: " + key);
    }
    return static_cast<int64_t>(parsed);
}

CalibrationArtifact ReadCalibrationArtifact(const std::string& path) {
    const std::string json = ReadFile(path);
    CalibrationArtifact artifact;
    if (JsonStringField(json, "schema") !=
        "piccard-std-security-diagnostic-calibration-v1" ||
        JsonStringField(json, "calibration_quality") !=
            "diagnostic-one-repetition" ||
        JsonBoolField(json, "table_eligible") ||
        JsonUint32Field(json, "repetitions_per_pattern") != 1 ||
        JsonStringField(json, "profile_id") != kProfileId ||
        JsonStringField(json, "consumer_set_serialization") !=
            kConsumerSerialization ||
        JsonStringField(json, "consumer_set_sha256") != kConsumerSetSha256) {
        throw std::invalid_argument("calibration artifact policy mismatch");
    }
    if (CountToken(json, "\"pattern\"") != 3 ||
        CountToken(json, "\"repetition_index\":0") != 3 ||
        json.find("warmup") != std::string::npos) {
        throw std::invalid_argument(
            "calibration artifact must contain exactly three rep-0 patterns");
    }
    artifact.circuit = JsonStringField(json, "circuit");
    artifact.shape_id = JsonStringField(json, "shape_id");
    artifact.security = JsonStringField(json, "security");
    artifact.source_commit = JsonStringField(json, "source_commit");
    artifact.build_id = JsonStringField(json, "build_id");
    artifact.build_type = JsonStringField(json, "build_type");
    artifact.build_dirty = JsonBoolField(json, "build_dirty");
    artifact.openfhe_version = JsonStringField(json, "openfhe_version");
    artifact.bfv_context_fingerprint =
        JsonStringField(json, "bfv_context_fingerprint");
    artifact.context_tuple_sha256 =
        JsonStringField(json, "context_tuple_sha256");
    artifact.k = JsonUint32Field(json, "k");
    artifact.m = JsonUint32Field(json, "m");
    artifact.seed = JsonUnsignedField(json, "seed");
    artifact.requested_ring_dim =
        JsonUint32Field(json, "requested_ring_dim");
    artifact.natural_ring_dim = JsonUint32Field(json, "natural_ring_dim");
    artifact.realized_ring_dim = JsonUint32Field(json, "realized_ring_dim");
    artifact.natural_depth = JsonUint32Field(json, "natural_depth");
    artifact.provisioned_depth = JsonUint32Field(json, "provisioned_depth");
    artifact.scaling_mod_size = JsonUint32Field(json, "scaling_mod_size");
    artifact.num_limbs = JsonUint32Field(json, "num_limbs");
    artifact.plaintext_modulus = JsonUnsignedField(json, "plaintext_modulus");
    artifact.log_q_bits = JsonDoubleField(json, "log_q_bits");
    artifact.ordered_rns_moduli =
        JsonStringArrayField(json, "ordered_rns_moduli");
    artifact.eval_noise_bits = JsonUint32Field(json, "eval_noise_bits");
    artifact.query_stat_bits = JsonUint32Field(json, "query_stat_bits");
    artifact.coefficient_stat_bits =
        JsonUint32Field(json, "coefficient_stat_bits");
    artifact.flood_margin_bits = JsonUint32Field(json, "flood_margin_bits");
    artifact.flood_noise_bits = JsonUint32Field(json, "flood_noise_bits");
    artifact.required_capacity_bits =
        JsonUint32Field(json, "required_capacity_bits");
    artifact.ct_bytes = JsonUnsignedField(json, "ct_bytes");
    if (artifact.ct_bytes == 0) {
        throw std::invalid_argument("calibration ciphertext size is missing");
    }
    artifact.log_q_over_t_bits = JsonDoubleField(json, "log_q_over_t_bits");
    if (artifact.circuit != "onehot" && artifact.circuit != "sqrt") {
        throw std::invalid_argument("calibration artifact has unsupported circuit");
    }
    if (artifact.security != "TOY" && artifact.security != "STD128" &&
        artifact.security != "STD192") {
        throw std::invalid_argument("calibration artifact has unsupported security");
    }
    if (artifact.k != 16 || artifact.m != 16 || artifact.seed != 7) {
        throw std::invalid_argument("calibration artifact workload mismatch");
    }
    if (artifact.num_limbs != artifact.ordered_rns_moduli.size()) {
        throw std::invalid_argument("calibration artifact RNS count mismatch");
    }
    const auto objects = PatternObjects(json);
    std::set<std::string> pattern_names;
    for (const auto& object : objects) {
        CalibrationArtifact::PatternRow row;
        row.pattern = JsonStringField(object, "pattern");
        row.repetition_index = JsonUint32Field(object, "repetition_index");
        row.seed = JsonUnsignedField(object, "seed");
        row.expected_matches = JsonSignedField(object, "expected_matches");
        row.observed_matches = JsonSignedField(object, "observed_matches");
        row.eval_noise_bits = JsonDoubleField(object, "eval_noise_bits");
        row.decrypt_ok = JsonBoolField(object, "decrypt_ok");
        row.saturated = JsonBoolField(object, "saturated");
        if (row.repetition_index != 0 ||
            (row.pattern != "all_match" && row.pattern != "no_match" &&
             row.pattern != "random") ||
            !pattern_names.insert(row.pattern).second ||
            !std::isfinite(row.eval_noise_bits) || row.eval_noise_bits < 0.0 ||
            !row.decrypt_ok || row.saturated ||
            row.expected_matches < 0 || row.expected_matches > 16 ||
            row.observed_matches != row.expected_matches) {
            throw std::invalid_argument(
                "calibration pattern row failed exact validation");
        }
        if (row.pattern == "all_match" && row.expected_matches != 16) {
            throw std::invalid_argument("all_match calibration row is invalid");
        }
        if (row.pattern == "no_match" && row.expected_matches != 0) {
            throw std::invalid_argument("no_match calibration row is invalid");
        }
        const auto pattern = row.pattern == "all_match"
                                 ? probe::Pattern::AllMatch
                                 : row.pattern == "no_match"
                                       ? probe::Pattern::NoMatch
                                       : probe::Pattern::Random;
        const uint64_t expected_seed = probe::DerivePatternSeed(
            artifact.seed,
            artifact.circuit,
            artifact.realized_ring_dim,
            artifact.provisioned_depth,
            artifact.scaling_mod_size,
            pattern);
        if (row.seed != expected_seed) {
            throw std::invalid_argument("calibration pattern seed mismatch");
        }
        artifact.patterns.push_back(std::move(row));
    }
    if (artifact.patterns.size() != 3 || pattern_names.size() != 3) {
        throw std::invalid_argument("calibration artifact pattern count mismatch");
    }
    double worst_noise = 0.0;
    for (const auto& row : artifact.patterns) {
        worst_noise = std::max(worst_noise, row.eval_noise_bits);
    }
    if (artifact.eval_noise_bits !=
        static_cast<uint32_t>(std::ceil(worst_noise))) {
        throw std::invalid_argument("calibration worst noise reduction mismatch");
    }
    return artifact;
}

piccard::SecurityLevel ParseSecurity(const std::string& value) {
    if (value == "TOY") return piccard::SecurityLevel::TOY;
    return value == "STD128" ? piccard::SecurityLevel::STD128
                              : piccard::SecurityLevel::STD192;
}

piccard::PiccardParams BuildParams(const Options& options) {
    piccard::PiccardParams params;
    params.k = options.k;
    params.m = options.m;
    params.security = ParseSecurity(options.security);
    if (options.circuit == "sqrt") {
        piccard::CalibrationAccess::DeriveSqrt(params);
    } else {
        piccard::CalibrationAccess::Derive(params);
    }
    if (options.provisioned_depth == 0) {
        params.mult_depth = options.circuit == "sqrt"
                                ? 4u
                                : 3u;
    } else {
        params.mult_depth = options.provisioned_depth;
    }
    if (params.mult_depth < params.natural_mult_depth) {
        throw std::invalid_argument("provisioned depth is below natural depth");
    }
    params.scaling_mod_size = options.scaling_mod_size;
    params.transcript_stat_bits = 40;
    params.max_queries = UINT64_C(1) << 20;
    params.flood_margin_bits = 8;
    return params;
}

schema::ContextTuple MakeTuple(const Options& options,
                               const piccard::PiccardParams& params,
                               const probe::ContextDescription& context) {
    const auto& metadata = context.metadata;
    schema::ContextTuple tuple;
    tuple.bfv_context_fingerprint = metadata.context_fingerprint;
    tuple.circuit = options.circuit;
    tuple.shape_id = options.shape_id;
    tuple.k = options.k;
    tuple.m = options.m;
    tuple.sanitizer_profile = kProfileId;
    tuple.security = metadata.security;
    tuple.requested_ring_dim = params.RequestedRingDim() != 0
                                   ? params.RequestedRingDim()
                                   : params.ring_dim;
    tuple.natural_ring_dim = params.ring_dim_natural != 0
                                 ? params.ring_dim_natural
                                 : params.ring_dim;
    tuple.natural_depth = params.natural_mult_depth;
    tuple.realized_ring_dim = metadata.actual_ring_dim;
    tuple.plaintext_modulus = metadata.plaintext_modulus;
    tuple.provisioned_depth = metadata.provisioned_depth;
    tuple.scaling_mod_size = metadata.scaling_mod_size;
    tuple.num_limbs = metadata.num_limbs;
    tuple.ordered_rns_moduli = metadata.ordered_rns_moduli;
    tuple.openfhe_version = metadata.openfhe_version;
    return tuple;
}

piccard::PiccardParams SelectDiagnosticParams(
    const Options& options,
    piccard::PiccardParams profile,
    const probe::ContextDescription& context,
    uint32_t eval_noise_bits = 0) {
    const piccard::Circuit circuit =
        options.circuit == "sqrt" ? piccard::Circuit::Sqrt
                                   : piccard::Circuit::OneHot;
    return piccard::SelectSanitizerCandidate(
        profile,
        piccard::CalibrationCandidate{
            circuit,
            profile.security,
            profile.ring_dim,
            profile.ring_dim,
            context.metadata.actual_ring_dim,
            profile.natural_mult_depth,
            profile.mult_depth,
            profile.scaling_mod_size,
            eval_noise_bits,
            context.log_delta_bits,
        });
}

schema::PreflightDecision CheckCaps(const probe::ContextDescription& context) {
    return schema::EvaluatePreflight({
        context.metadata.actual_ring_dim,
        context.metadata.provisioned_depth,
        context.metadata.log_q_bits,
    });
}

piccard::PiccardParams SelectArtifactParams(
    const Options& options,
    piccard::PiccardParams profile,
    const CalibrationArtifact& artifact) {
    const piccard::Circuit circuit =
        options.circuit == "sqrt" ? piccard::Circuit::Sqrt
                                   : piccard::Circuit::OneHot;
    const piccard::PreThresholdCalibrationRequest request{
        kProfileId,
        circuit,
        options.shape_id,
        ParseSecurity(options.security),
        artifact.requested_ring_dim,
        artifact.natural_depth,
        kConsumerSetSha256,
        artifact.openfhe_version,
    };
    const piccard::PreThresholdCalibrationRow row{
        request,
        artifact.natural_ring_dim,
        artifact.realized_ring_dim,
        artifact.provisioned_depth,
        artifact.scaling_mod_size,
        artifact.num_limbs,
        artifact.plaintext_modulus,
        artifact.log_q_bits,
        artifact.log_q_over_t_bits,
        artifact.eval_noise_bits,
        artifact.ct_bytes,
        40u,
        UINT64_C(1) << 20,
        artifact.query_stat_bits,
        artifact.coefficient_stat_bits,
        artifact.flood_margin_bits,
        artifact.flood_noise_bits,
    };
    return piccard::SelectPreThresholdCalibration(profile, request, {row});
}

std::string JoinReasons(const schema::PreflightDecision& decision) {
    std::ostringstream out;
    for (size_t index = 0; index < decision.reasons.size(); ++index) {
        if (index != 0) out << "; ";
        out << decision.reasons[index];
    }
    return out.str();
}

std::string PreflightJson(const Options& options,
                          const piccard::PiccardParams& params,
                          const probe::ContextDescription& context,
                          const schema::ContextTuple& tuple,
                          const schema::PreflightDecision& decision) {
    const auto& metadata = context.metadata;
    CanonicalJsonObject object;
    object.AddString("build_id", PICCARD_BUILD_ID);
    object.AddBool("build_dirty", PICCARD_BUILD_DIRTY != 0);
    object.AddString("build_type", PICCARD_BUILD_TYPE);
    object.AddString("circuit", options.circuit);
    object.AddString("context_fingerprint", metadata.context_fingerprint);
    object.AddString("context_tuple_sha256",
                     schema::ContextTupleSha256(tuple));
    object.AddNumber("k", options.k);
    object.AddBool("keygen_started", false);
    object.AddNumber("log_q_bits", metadata.log_q_bits);
    object.AddNumber("m", options.m);
    object.AddString("mode", "preflight");
    object.AddNumber("natural_depth", params.natural_mult_depth);
    object.AddNumber("natural_ring_dim", params.ring_dim);
    object.AddNumber("num_limbs", metadata.num_limbs);
    object.AddString("openfhe_version", metadata.openfhe_version);
    object.Add("ordered_rns_moduli",
               CanonicalJsonStringArray(metadata.ordered_rns_moduli));
    object.AddNumber("plaintext_modulus", metadata.plaintext_modulus);
    object.AddNumber("provisioned_depth", metadata.provisioned_depth);
    object.AddNumber("realized_ring_dim", metadata.actual_ring_dim);
    object.AddString("reason", JoinReasons(decision));
    object.AddNumber("requested_ring_dim", params.ring_dim);
    object.AddNumber("scaling_mod_size", metadata.scaling_mod_size);
    object.AddString("schema", "piccard-std-security-preflight-v1");
    object.AddString("security", options.security);
    object.AddString("shape_id", options.shape_id);
    object.AddBool("skipped", decision.skipped);
    object.AddBool("table_eligible", false);
    object.AddString("source_commit", PICCARD_BUILD_COMMIT);
    return object.Serialize() + "\n";
}

// A new schema is intentional: Work #4's preflight serialization is a frozen
// smoke contract.  n and universe do not alter Piccard context parameters, so
// this record binds them as the requested Work #5 cell identity.
std::string Work5PreflightJson(const Options& options,
                               const piccard::PiccardParams& params,
                               const probe::ContextDescription& context,
                               const schema::ContextTuple& tuple,
                               const schema::PreflightDecision& decision) {
    const auto& metadata = context.metadata;
    CanonicalJsonObject object;
    object.AddString("schema", "piccard-work5-piccard-context-preflight-v1");
    object.AddString("mode", "work5-preflight");
    object.AddString("cell_id", options.cell_id);
    object.AddString("circuit", options.circuit);
    object.AddString("shape_id", options.shape_id);
    object.AddString("security", options.security);
    object.AddNumber("k", options.k);
    object.AddNumber("m", options.m);
    object.AddNumber("n", options.work5_n);
    object.AddNumber("universe", options.work5_universe);
    object.AddString("context_fingerprint", metadata.context_fingerprint);
    object.AddString("context_tuple_sha256", schema::ContextTupleSha256(tuple));
    object.AddNumber("requested_ring_dim", params.ring_dim);
    object.AddNumber("natural_ring_dim", params.ring_dim);
    object.AddNumber("natural_depth", params.natural_mult_depth);
    object.AddNumber("realized_ring_dim", metadata.actual_ring_dim);
    object.AddNumber("provisioned_depth", metadata.provisioned_depth);
    object.AddNumber("scaling_mod_size", metadata.scaling_mod_size);
    object.AddNumber("log_q_bits", metadata.log_q_bits);
    object.AddNumber("plaintext_modulus", metadata.plaintext_modulus);
    object.AddNumber("num_limbs", metadata.num_limbs);
    object.Add("ordered_rns_moduli",
               CanonicalJsonStringArray(metadata.ordered_rns_moduli));
    object.AddString("openfhe_version", metadata.openfhe_version);
    object.AddString("build_id", PICCARD_BUILD_ID);
    object.AddBool("build_dirty", PICCARD_BUILD_DIRTY != 0);
    object.AddString("build_type", PICCARD_BUILD_TYPE);
    object.AddString("source_commit", PICCARD_BUILD_COMMIT);
    object.AddBool("keygen_started", false);
    object.AddBool("skipped", decision.skipped);
    object.AddString("reason", JoinReasons(decision));
    return object.Serialize() + "\n";
}

struct Observation {
    probe::Pattern pattern;
    uint64_t seed = 0;
    int64_t expected_matches = 0;
    int64_t observed_matches = 0;
    double eval_noise_bits = 0.0;
    bool decrypt_ok = false;
    bool saturated = false;
    uint64_t ct_bytes = 0;
};

template <typename Engine>
std::vector<Observation> MeasurePatterns(
    Engine& engine,
    const Options& options,
    const probe::ContextDescription& context) {
    std::vector<Observation> observations;
    const auto& bfv = engine.GetBFVContext();
    const std::vector<probe::Pattern> patterns = {
        probe::Pattern::AllMatch,
        probe::Pattern::NoMatch,
        probe::Pattern::Random,
    };
    for (const auto pattern : patterns) {
        const uint64_t seed = probe::DerivePatternSeed(
            options.seed,
            options.circuit,
            context.metadata.actual_ring_dim,
            context.metadata.provisioned_depth,
            context.metadata.scaling_mod_size,
            pattern);
        std::mt19937_64 rng(seed);
        const auto [lhs, rhs] = probe::MakeSignatures(
            pattern, options.k, options.m, rng);
        const auto expected = probe::ExpectedMatches(lhs, rhs, options.m);
        const auto ct_lhs = engine.EncryptFeature(
            engine.EncodeSignature(lhs));
        const auto ct_rhs = engine.EncryptFeature(
            engine.EncodeSignature(rhs));
        const auto raw = engine.EvaluateRaw(ct_lhs, ct_rhs);
        const uint64_t ct_bytes =
            piccard::benchmark::CiphertextSizer::GetSerializedSize(raw);
        const double noise = probe::MeasureDecryptionPhaseNoise(
            raw,
            bfv.GetSecretKeyForCalibration(),
            context.modulus_q,
            context.metadata.plaintext_modulus);
        const auto result = engine.Decrypt(raw);
        const bool saturated = context.log_delta_bits - 1.0 - noise < 0.5;
        observations.push_back({
            pattern,
            seed,
            expected,
            result.match_count,
            noise,
            expected == result.match_count,
            saturated,
            ct_bytes,
        });
    }
    return observations;
}

struct CalibrationResult {
    piccard::PiccardParams params;
    probe::ContextDescription context;
    schema::ContextTuple tuple;
    std::vector<Observation> observations;
    probe::CalibrationBudget budget;
};

CalibrationResult RunCalibration(const Options& options) {
    auto profile = BuildParams(options);

    // Constructing the context alone is the hard preflight boundary. No key
    // generation occurs until the numeric caps have been evaluated.
    {
        piccard::BFVContext preflight_context(profile);
        preflight_context.InitializeContextOnly();
        const auto preflight = probe::DescribeContext(preflight_context);
        const auto decision = CheckCaps(preflight);
        if (decision.skipped) {
            throw std::runtime_error("preflight skip: " + JoinReasons(decision));
        }
        if (preflight_context.HasGeneratedKeysForTesting()) {
            throw std::logic_error("preflight generated keys");
        }
    }

    piccard::BFVContext candidate_context(profile);
    candidate_context.InitializeContextOnly();
    const auto candidate_description = probe::DescribeContext(candidate_context);
    auto params = SelectDiagnosticParams(options, profile, candidate_description);

    CalibrationResult result;
    result.params = params;
    if (options.circuit == "onehot") {
        piccard::Piccard engine(params);
        engine.KeyGen();
        result.context = probe::DescribeContext(engine.GetBFVContext());
        result.tuple = MakeTuple(options, params, result.context);
        result.observations = MeasurePatterns(engine, options, result.context);
    } else {
        piccard::SqrtPiccard engine(params);
        engine.KeyGen();
        result.context = probe::DescribeContext(engine.GetBFVContext());
        result.tuple = MakeTuple(options, params, result.context);
        result.observations = MeasurePatterns(engine, options, result.context);
    }

    double worst_noise = 0.0;
    bool all_decrypt_ok = true;
    bool any_saturated = false;
    for (const auto& observation : result.observations) {
        worst_noise = std::max(worst_noise, observation.eval_noise_bits);
        all_decrypt_ok = all_decrypt_ok && observation.decrypt_ok;
        any_saturated = any_saturated || observation.saturated;
    }
    result.budget = probe::ComputeBudget(
        worst_noise,
        result.context.metadata.actual_ring_dim,
        result.context.metadata.log_q_bits,
        result.context.metadata.plaintext_modulus,
        40,
        UINT64_C(1) << 20,
        8,
        result.context.log_delta_bits);
    if (!all_decrypt_ok) {
        throw std::runtime_error("calibration decryption mismatch");
    }
    if (any_saturated || result.budget.saturated) {
        throw std::runtime_error("calibration noise measurement saturated");
    }
    if (!result.budget.fits) {
        throw std::runtime_error("calibration capacity does not fit");
    }
    return result;
}

std::string CalibrationJson(const Options& options,
                            const CalibrationResult& result) {
    const auto& metadata = result.context.metadata;
    const auto& budget = result.budget;
    CanonicalJsonObject consumer_point;
    consumer_point.AddNumber("k", 16u);
    consumer_point.AddNumber("m", 16u);
    std::ostringstream patterns;
    patterns << '[';
    for (size_t index = 0; index < result.observations.size(); ++index) {
        const auto& observation = result.observations[index];
        if (index != 0) patterns << ',';
        CanonicalJsonObject row;
        row.AddBool("decrypt_ok", observation.decrypt_ok);
        row.AddNumber("eval_noise_bits", observation.eval_noise_bits);
        row.AddNumber("expected_matches", observation.expected_matches);
        row.AddNumber("observed_matches", observation.observed_matches);
        row.AddString("pattern", probe::PatternName(observation.pattern));
        row.AddNumber("repetition_index", 0u);
        row.AddBool("saturated", observation.saturated);
        row.AddNumber("seed", observation.seed);
        patterns << row.Serialize();
    }
    patterns << ']';

    CanonicalJsonObject object;
    object.AddString("bfv_context_fingerprint", metadata.context_fingerprint);
    object.AddString("build_id", PICCARD_BUILD_ID);
    object.AddBool("build_dirty", PICCARD_BUILD_DIRTY != 0);
    object.AddString("build_type", PICCARD_BUILD_TYPE);
    object.AddString("calibration_quality", "diagnostic-one-repetition");
    object.AddNumber("coefficient_stat_bits", budget.coefficient_stat_bits);
    object.AddString("circuit", options.circuit);
    object.Add("consumer_points",
               "[" + consumer_point.Serialize() + "]");
    object.AddString("consumer_set_serialization", kConsumerSerialization);
    object.AddString("consumer_set_sha256", kConsumerSetSha256);
    object.AddString("context_tuple_sha256",
                     schema::ContextTupleSha256(result.tuple));
    object.AddNumber("ct_bytes", result.observations.empty()
                                      ? 0u
                                      : result.observations.front().ct_bytes);
    object.AddNumber("eval_noise_bits", budget.eval_noise_bits);
    object.AddNumber("flood_margin_bits", budget.flood_margin_bits);
    object.AddNumber("flood_noise_bits", budget.flood_noise_bits);
    object.AddNumber("k", options.k);
    object.AddNumber("log_q_bits", metadata.log_q_bits);
    object.AddNumber("log_q_over_t_bits", budget.log_q_over_t_bits);
    object.AddNumber("m", options.m);
    object.AddNumber("natural_depth", result.tuple.natural_depth);
    object.AddNumber("natural_ring_dim", result.tuple.natural_ring_dim);
    object.AddNumber("num_limbs", result.tuple.num_limbs);
    object.AddString("openfhe_version", metadata.openfhe_version);
    object.Add("ordered_rns_moduli",
               CanonicalJsonStringArray(result.tuple.ordered_rns_moduli));
    object.Add("patterns", patterns.str());
    object.AddNumber("plaintext_modulus", result.tuple.plaintext_modulus);
    object.AddString("profile_id", kProfileId);
    object.AddNumber("provisioned_depth", result.tuple.provisioned_depth);
    object.AddNumber("query_stat_bits", budget.query_stat_bits);
    object.AddNumber("realized_ring_dim", result.tuple.realized_ring_dim);
    object.AddNumber("repetitions_per_pattern", 1u);
    object.AddNumber("required_capacity_bits", budget.required_capacity_bits);
    object.AddNumber("requested_ring_dim", result.tuple.requested_ring_dim);
    object.AddNumber("scaling_mod_size", result.tuple.scaling_mod_size);
    object.AddString("schema", "piccard-std-security-diagnostic-calibration-v1");
    object.AddString("security", options.security);
    object.AddNumber("seed", options.seed);
    object.AddString("shape_id", options.shape_id);
    object.AddString("source_commit", PICCARD_BUILD_COMMIT);
    object.AddBool("table_eligible", false);
    return object.Serialize() + "\n";
}

Options OptionsFromArtifact(const Options& requested,
                            const CalibrationArtifact& artifact) {
    if ((requested.circuit_specified && requested.circuit != artifact.circuit) ||
        (requested.shape_specified && requested.shape_id != artifact.shape_id) ||
        (requested.security_specified &&
         requested.security != artifact.security) ||
        (requested.k_specified && requested.k != artifact.k) ||
        (requested.m_specified && requested.m != artifact.m) ||
        (requested.depth_specified &&
         requested.provisioned_depth != artifact.provisioned_depth) ||
        (requested.scaling_specified &&
         requested.scaling_mod_size != artifact.scaling_mod_size) ||
        (requested.seed_specified && requested.seed != artifact.seed)) {
        throw std::invalid_argument(
            "requested e2e cell does not match calibration artifact");
    }
    Options options = requested;
    options.circuit = artifact.circuit;
    options.shape_id = artifact.shape_id;
    options.security = artifact.security;
    options.k = artifact.k;
    options.m = artifact.m;
    options.provisioned_depth = artifact.provisioned_depth;
    options.scaling_mod_size = artifact.scaling_mod_size;
    options.seed = artifact.seed;
    return options;
}

void RequireNear(double left, double right, const char* field) {
    if (!std::isfinite(left) || !std::isfinite(right) ||
        std::abs(left - right) > 1e-9) {
        throw std::invalid_argument(std::string("calibration field mismatch: ") +
                                    field);
    }
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
    return workload::Sha256Hex(bytes);
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

std::string Lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    return value;
}

struct WorkloadMeasurement {
    schema::ContextTuple tuple;
    probe::ContextDescription context;
    piccard::JaccardResult result;
    double setup_context_ms = 0.0;
    double setup_keygen_ms = 0.0;
    double phase_minhash_ms = 0.0;
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_evaluate_ms = 0.0;
    double phase_flood_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    std::string workload_manifest_sha256;
    std::string workload_id;
    std::string calibration_artifact_sha256;
    uint64_t timing_hash_seed = 0;
};

template <typename Engine>
WorkloadMeasurement ExecuteWorkloadCell(
    const Options& options,
    const CalibrationArtifact& artifact,
    const workload::ComparisonWorkload& shared_workload,
    piccard::PiccardParams selected) {
    const auto& records = shared_workload.Records();
    if (records.size() != 3 || records[0].kind != workload::TrialKind::Warmup ||
        records[1].kind != workload::TrialKind::Timing || records[1].index != 0 ||
        records[2].kind != workload::TrialKind::Accuracy || records[2].index != 0) {
        throw std::invalid_argument(
            "workload e2e accepts only the timing record at index 0");
    }
    const auto& timing = records[1];
    if (timing.set_a.size() != 10 || timing.set_b.size() != 10 ||
        timing.exact_intersection != 7 || timing.exact_union != 13 ||
        timing.exact_jaccard != workload::ExactRational{7, 13}) {
        throw std::invalid_argument("workload timing record does not match toy smoke");
    }
    selected.hash_seed = timing.hash_seed;

    Engine engine(selected);
    WorkloadMeasurement measurement;
    measurement.workload_manifest_sha256 = shared_workload.ManifestSha256Hex();
    measurement.workload_id = shared_workload.WorkloadId();
    measurement.timing_hash_seed = timing.hash_seed;

    const auto context_start = std::chrono::steady_clock::now();
    engine.InitializeContextOnly();
    const auto context_stop = std::chrono::steady_clock::now();
    measurement.setup_context_ms = std::chrono::duration<double, std::milli>(
        context_stop - context_start).count();
    measurement.context = probe::DescribeContext(engine.GetBFVContext());
    measurement.tuple = MakeTuple(options, engine.GetParams(), measurement.context);
    if (schema::ContextTupleSha256(measurement.tuple) !=
        artifact.context_tuple_sha256) {
        throw std::invalid_argument(
            "calibration tuple mismatch before live engine key generation");
    }

    const auto keygen_start = std::chrono::steady_clock::now();
    engine.KeyGen();
    const auto keygen_stop = std::chrono::steady_clock::now();
    measurement.setup_keygen_ms = std::chrono::duration<double, std::milli>(
        keygen_stop - keygen_start).count();
    const auto live = probe::DescribeContext(engine.GetBFVContext());
    const auto live_tuple = MakeTuple(options, engine.GetParams(), live);
    if (schema::ContextTupleSha256(live_tuple) !=
        artifact.context_tuple_sha256 || live_tuple != measurement.tuple) {
        throw std::invalid_argument("live engine tuple changed after key generation");
    }
    measurement.context = live;
    measurement.tuple = live_tuple;

    const auto minhash_start = std::chrono::steady_clock::now();
    const auto sig_a = engine.ComputeSignature(timing.set_a);
    const auto sig_b = engine.ComputeSignature(timing.set_b);
    const auto minhash_stop = std::chrono::steady_clock::now();
    measurement.phase_minhash_ms = std::chrono::duration<double, std::milli>(
        minhash_stop - minhash_start).count();

    const auto encode_start = std::chrono::steady_clock::now();
    const auto feature_a = engine.EncodeSignature(sig_a);
    const auto feature_b = engine.EncodeSignature(sig_b);
    const auto encode_stop = std::chrono::steady_clock::now();
    measurement.phase_encode_ms = std::chrono::duration<double, std::milli>(
        encode_stop - encode_start).count();

    const auto encrypt_start = std::chrono::steady_clock::now();
    const auto ct_a = engine.EncryptFeature(feature_a);
    const auto ct_b = engine.EncryptFeature(feature_b);
    const auto encrypt_stop = std::chrono::steady_clock::now();
    measurement.phase_encrypt_ms = std::chrono::duration<double, std::milli>(
        encrypt_stop - encrypt_start).count();

    const auto evaluate_start = std::chrono::steady_clock::now();
    const auto raw = engine.EvaluateRaw(ct_a, ct_b);
    const auto evaluate_stop = std::chrono::steady_clock::now();
    measurement.phase_evaluate_ms = std::chrono::duration<double, std::milli>(
        evaluate_stop - evaluate_start).count();

    const auto flood_start = std::chrono::steady_clock::now();
    const auto receiver_ciphertext = engine.GetBFVContext().Flood(raw);
    const auto flood_stop = std::chrono::steady_clock::now();
    measurement.phase_flood_ms = std::chrono::duration<double, std::milli>(
        flood_stop - flood_start).count();

    const auto decrypt_start = std::chrono::steady_clock::now();
    measurement.result = engine.Decrypt(receiver_ciphertext);
    const auto decrypt_stop = std::chrono::steady_clock::now();
    measurement.phase_decrypt_ms = std::chrono::duration<double, std::milli>(
        decrypt_stop - decrypt_start).count();
    if (measurement.result.match_count < 0 ||
        measurement.result.match_count > static_cast<int64_t>(options.k)) {
        throw std::runtime_error("workload receiver result is outside [0,k]");
    }
    const double k = static_cast<double>(options.k);
    const double m = static_cast<double>(options.m);
    const double raw_ratio =
        static_cast<double>(measurement.result.match_count) / k;
    const double expected_jaccard = std::max(
        0.0, std::min(1.0, (raw_ratio - 1.0 / m) / (1.0 - 1.0 / m)));
    if (std::abs(expected_jaccard - measurement.result.jaccard_estimate) >
        1e-12) {
        throw std::runtime_error("workload bias-correction formula mismatch");
    }
    return measurement;
}

std::string WorkloadCsv(const Options& options,
                        const CalibrationArtifact& artifact,
                        const workload::ComparisonWorkload& shared_workload,
                        const WorkloadMeasurement& measurement) {
    const auto& metadata = measurement.context.metadata;
    const double online = measurement.phase_minhash_ms +
                           measurement.phase_encode_ms +
                           measurement.phase_encrypt_ms +
                           measurement.phase_evaluate_ms +
                           measurement.phase_flood_ms +
                           measurement.phase_decrypt_ms;
    const double full = measurement.setup_context_ms +
                        measurement.setup_keygen_ms + online;
    const std::string cell_id = options.circuit + "-" + Lowercase(options.security);
    const std::string header =
        "cell_id,circuit,shape_id,security,k,m,set_size,target_jaccard,"
        "realized_intersection,realized_union,realized_jaccard,seed,trials,"
        "requested_ring_dim,natural_ring_dim,realized_ring_dim,natural_depth,"
        "provisioned_depth,scaling_mod_size,num_limbs,plaintext_modulus,"
        "log_q_bits,ordered_rns_moduli_sha256,openfhe_version,"
        "sanitizer_profile,transcript_stat_bits,max_queries,flood_margin_bits,"
        "eval_noise_bits,query_stat_bits,coefficient_stat_bits,flood_noise_bits,"
        "context_tuple_sha256,calibration_origin,calibration_artifact_sha256,"
        "workload_id,workload_manifest_sha256,timing_hash_seed,"
        "setup_context_ms,setup_keygen_ms,phase_minhash_ms,phase_encode_ms,"
        "phase_encrypt_ms,phase_evaluate_ms,phase_flood_ms,phase_decrypt_ms,"
        "online_e2e_ms,full_e2e_ms,match_count,jaccard_estimate,status,reason\n";
    std::ostringstream row;
    row << CsvCell(cell_id) << ',' << CsvCell(options.circuit) << ','
        << CsvCell(options.shape_id) << ',' << CsvCell(options.security) << ','
        << options.k << ',' << options.m << ",10,0.5,7,13,"
        << Number(7.0 / 13.0) << ',' << options.seed << ",1,"
        << measurement.tuple.requested_ring_dim << ','
        << measurement.tuple.natural_ring_dim << ','
        << measurement.tuple.realized_ring_dim << ','
        << measurement.tuple.natural_depth << ','
        << measurement.tuple.provisioned_depth << ','
        << measurement.tuple.scaling_mod_size << ',' << metadata.num_limbs
        << ',' << metadata.plaintext_modulus << ',' << Number(metadata.log_q_bits)
        << ',' << OrderedRnsSha256(metadata.ordered_rns_moduli) << ','
        << CsvCell(metadata.openfhe_version) << ',' << kProfileId
        << ",40,1048576,8," << artifact.eval_noise_bits << ','
        << artifact.query_stat_bits << ',' << artifact.coefficient_stat_bits
        << ',' << artifact.flood_noise_bits << ','
        << schema::ContextTupleSha256(measurement.tuple) << ','
        << "diagnostic-artifact," <<
        Sha256Text(ReadFile(options.calibration))
        << ',' << measurement.workload_id << ','
        << measurement.workload_manifest_sha256 << ','
        << measurement.timing_hash_seed << ','
        << Number(measurement.setup_context_ms) << ','
        << Number(measurement.setup_keygen_ms) << ','
        << Number(measurement.phase_minhash_ms) << ','
        << Number(measurement.phase_encode_ms) << ','
        << Number(measurement.phase_encrypt_ms) << ','
        << Number(measurement.phase_evaluate_ms) << ','
        << Number(measurement.phase_flood_ms) << ','
        << Number(measurement.phase_decrypt_ms) << ',' << Number(online) << ','
        << Number(full) << ',' << measurement.result.match_count << ','
        << Number(measurement.result.jaccard_estimate) << ",MEASURED,\n";
    return header + row.str();
}

void Emit(const std::string& text, const std::string& output);

std::string E2eJson(const Options& options,
                    const CalibrationArtifact& artifact,
                    const schema::ContextTuple& tuple,
                    const piccard::JaccardResult& result,
                    const WorkloadMeasurement& measurement);

int RunWorkloadE2e(const Options& requested,
                   const Options& options,
                   const CalibrationArtifact& artifact,
                   const piccard::PiccardParams& selected) {
    const auto shared_workload = requested.workload.empty()
                                     ? MakeToyWorkload()
                                     : ReadWorkloadArtifact(requested.workload);
    WorkloadMeasurement measurement;
    if (options.circuit == "onehot") {
        measurement = ExecuteWorkloadCell<piccard::Piccard>(
            options, artifact, shared_workload, selected);
    } else if (options.circuit == "sqrt") {
        measurement = ExecuteWorkloadCell<piccard::SqrtPiccard>(
            options, artifact, shared_workload, selected);
    } else {
        throw std::invalid_argument(
            "workload e2e does not support Threshold or FHE-IND");
    }
    if (requested.format == "csv") {
        Emit(WorkloadCsv(options, artifact, shared_workload, measurement),
             requested.output);
    } else {
        Emit(E2eJson(options, artifact, measurement.tuple, measurement.result,
                     measurement),
             requested.output);
    }
    return 0;
}

void Emit(const std::string& text, const std::string& output);

std::string E2eJson(const Options& options,
                    const CalibrationArtifact& artifact,
                    const schema::ContextTuple& tuple,
                    const piccard::JaccardResult& result,
                    const WorkloadMeasurement& measurement) {
    CanonicalJsonObject object;
    object.AddString("build_id", PICCARD_BUILD_ID);
    object.AddBool("build_dirty", PICCARD_BUILD_DIRTY != 0);
    object.AddString("build_type", PICCARD_BUILD_TYPE);
    object.AddString("calibration_context_tuple_sha256",
                     artifact.context_tuple_sha256);
    object.AddString("calibration_origin", "diagnostic-artifact");
    object.AddString("calibration_quality", "diagnostic-one-repetition");
    object.AddString("circuit", options.circuit);
    object.AddString("context_tuple_sha256",
                     schema::ContextTupleSha256(tuple));
    object.AddNumber("jaccard_estimate", result.jaccard_estimate);
    object.AddNumber("k", options.k);
    object.AddNumber("m", options.m);
    object.AddNumber("match_count", result.match_count);
    object.AddNumber("realized_intersection", 7u);
    object.AddNumber("realized_union", 13u);
    object.AddString("reason", "");
    object.AddNumber("seed", options.seed);
    object.AddNumber("set_size", 10u);
    object.AddString("schema", "piccard-std-security-e2e-v1");
    object.AddString("security", options.security);
    object.AddString("shape_id", options.shape_id);
    object.AddString("source_commit", PICCARD_BUILD_COMMIT);
    object.Add("status", JsonEscape("MEASURED"));
    object.AddNumber("target_jaccard", 0.5);
    object.AddBool("table_eligible", false);
    object.AddNumber("timing_hash_seed", measurement.timing_hash_seed);
    object.AddNumber("trials", 1u);
    object.AddString("workload_id", measurement.workload_id);
    object.AddString("workload_manifest_sha256",
                     measurement.workload_manifest_sha256);
    return object.Serialize() + "\n";
}

int RunE2e(const Options& requested) {
    const CalibrationArtifact artifact =
        ReadCalibrationArtifact(requested.calibration);
    const Options options = OptionsFromArtifact(requested, artifact);
    if (artifact.source_commit != PICCARD_BUILD_COMMIT ||
        artifact.build_id != PICCARD_BUILD_ID ||
        artifact.build_dirty != (PICCARD_BUILD_DIRTY != 0) ||
        artifact.build_type != PICCARD_BUILD_TYPE ||
        artifact.openfhe_version != GetOPENFHEVersion()) {
        throw std::invalid_argument(
            "calibration source/build/OpenFHE provenance does not match executable");
    }
    auto profile = BuildParams(options);
    piccard::BFVContext preflight(profile);
    preflight.InitializeContextOnly();
    const auto preflight_description = probe::DescribeContext(preflight);
    const auto preflight_decision = CheckCaps(preflight_description);
    if (preflight_decision.skipped) {
        throw std::runtime_error("e2e preflight skip: " +
                                 JoinReasons(preflight_decision));
    }
    const auto preflight_tuple =
        MakeTuple(options, profile, preflight_description);
    if (preflight_description.metadata.context_fingerprint !=
            artifact.bfv_context_fingerprint ||
        preflight_description.metadata.natural_ring_dim !=
            artifact.natural_ring_dim ||
        preflight_description.metadata.requested_ring_dim !=
            artifact.requested_ring_dim ||
        preflight_description.metadata.natural_depth !=
            artifact.natural_depth ||
        preflight_description.metadata.actual_ring_dim !=
            artifact.realized_ring_dim ||
        preflight_description.metadata.provisioned_depth !=
            artifact.provisioned_depth ||
        preflight_description.metadata.scaling_mod_size !=
            artifact.scaling_mod_size ||
        preflight_description.metadata.num_limbs != artifact.num_limbs ||
        preflight_description.metadata.plaintext_modulus !=
            artifact.plaintext_modulus ||
        preflight_description.metadata.ordered_rns_moduli !=
            artifact.ordered_rns_moduli ||
        preflight_description.metadata.openfhe_version !=
            artifact.openfhe_version) {
        throw std::invalid_argument("calibration live context tuple mismatch");
    }
    RequireNear(preflight_description.metadata.log_q_bits,
                artifact.log_q_bits,
                "log_q_bits");
    RequireNear(
        preflight_description.log_delta_bits,
        artifact.log_q_over_t_bits,
        "log_q_over_t_bits");
    if (schema::ContextTupleSha256(preflight_tuple) !=
        artifact.context_tuple_sha256) {
        throw std::invalid_argument("calibration context tuple digest mismatch");
    }
    const auto budget = probe::ComputeBudget(
        artifact.eval_noise_bits,
        artifact.realized_ring_dim,
        artifact.log_q_bits,
        artifact.plaintext_modulus,
        40,
        UINT64_C(1) << 20,
        artifact.flood_margin_bits,
        artifact.log_q_over_t_bits);
    if (budget.query_stat_bits != artifact.query_stat_bits ||
        budget.coefficient_stat_bits != artifact.coefficient_stat_bits ||
        budget.flood_noise_bits != artifact.flood_noise_bits ||
        budget.required_capacity_bits != artifact.required_capacity_bits ||
        !budget.fits) {
        throw std::invalid_argument("calibration budget mismatch");
    }
    const auto selected = options.security == "TOY"
                              ? SelectDiagnosticParams(
                                    options,
                                    profile,
                                    preflight_description,
                                    artifact.eval_noise_bits)
                              : SelectArtifactParams(options, profile, artifact);
    // Every e2e invocation is workload-bound.  With no external workload
    // path, RunWorkloadE2e constructs the same frozen toy-smoke manifest in
    // memory; it never falls back to synthetic all-match signatures.
    return RunWorkloadE2e(requested, options, artifact, selected);
}

void Emit(const std::string& text, const std::string& output) {
    if (output.empty()) {
        std::cout << text;
        return;
    }
    const std::filesystem::path output_path(output);
    if (!output_path.is_absolute()) {
        throw std::invalid_argument(
            "diagnostic output path must be absolute and outside the source tree");
    }
    std::error_code canonical_error;
    // Resolve existing symlinks in the destination and its parent before the
    // source-tree/production-path test.  A lexical check alone lets
    // /tmp/link-to-worktree/file bypass the guard and truncate a source file.
    const auto normalized = std::filesystem::absolute(output_path).lexically_normal();
    const auto resolved =
        std::filesystem::weakly_canonical(normalized, canonical_error);
    if (canonical_error) {
        throw std::invalid_argument("cannot resolve diagnostic output path");
    }
    canonical_error.clear();
    const auto source_root = std::filesystem::weakly_canonical(
        std::filesystem::path(PICCARD_BUILD_SOURCE_DIR), canonical_error);
    if (canonical_error) {
        throw std::invalid_argument("cannot resolve diagnostic source path");
    }
    const auto relative = resolved.lexically_relative(source_root);
    const std::string relative_text = relative.generic_string();
    if (relative_text.empty() ||
        (relative_text != ".." && relative_text.rfind("../", 0) != 0) ||
        relative_text.find("scripts/results/calibration") !=
            std::string::npos ||
        relative_text.find("include/util/noise_calibration") !=
            std::string::npos) {
        throw std::invalid_argument(
            "diagnostic output cannot be written inside the source or production table paths");
    }
    std::ofstream file(normalized, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) throw std::runtime_error("failed to open " + output);
    file << text;
    if (!file) throw std::runtime_error("failed to write " + output);
}

int Run(const Options& options) {
    if (options.mode == "workload") {
        Emit(WorkloadJson(), options.output);
        return 0;
    }
    if (options.mode == "e2e") {
        return RunE2e(options);
    }
    auto params = BuildParams(options);
    piccard::BFVContext context(params);
    context.InitializeContextOnly();
    const auto described = probe::DescribeContext(context);
    const auto tuple = MakeTuple(options, params, described);
    const auto decision = CheckCaps(described);
    if (options.mode == "preflight") {
        if (context.HasGeneratedKeysForTesting()) {
            throw std::logic_error("preflight generated keys");
        }
        Emit(PreflightJson(options, params, described, tuple, decision),
             options.output);
        return 0;
    }
    if (options.mode == "work5-preflight") {
        if (context.HasGeneratedKeysForTesting()) {
            throw std::logic_error("Work #5 preflight generated keys");
        }
        Emit(Work5PreflightJson(options, params, described, tuple, decision),
             options.output);
        return 0;
    }
    if (decision.skipped) {
        throw std::runtime_error("preflight skip: " + JoinReasons(decision));
    }
    const auto result = RunCalibration(options);
    Emit(CalibrationJson(options, result), options.output);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return Run(ParseOptions(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << "bench_std_security_evidence: " << error.what() << '\n';
        return 2;
    }
}
