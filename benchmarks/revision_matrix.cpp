#include "revision_matrix.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace piccard::benchmark {
namespace {

// ---------------------------------------------------------------------------
// Minimal JSON reader
// ---------------------------------------------------------------------------

struct JsonValue {
    enum class Type { Null, Boolean, Number, String, Array, Object };
    Type type = Type::Null;
    bool boolean = false;
    std::string text;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;
};

[[noreturn]] void JsonError(size_t position, const char* message) {
    throw std::invalid_argument(
        "revision matrix JSON error at byte " + std::to_string(position) +
        ": " + message);
}

class JsonParser {
  public:
    explicit JsonParser(std::string input) : input_(std::move(input)) {}

    JsonValue Parse() {
        SkipWhitespace();
        JsonValue value = ParseValue();
        SkipWhitespace();
        if (position_ != input_.size()) JsonError(position_, "trailing data");
        return value;
    }

  private:
    void SkipWhitespace() {
        while (position_ < input_.size() &&
               std::isspace(static_cast<unsigned char>(input_[position_]))) {
            ++position_;
        }
    }

    bool Consume(char expected) {
        SkipWhitespace();
        if (position_ >= input_.size() || input_[position_] != expected) {
            return false;
        }
        ++position_;
        return true;
    }

    JsonValue ParseValue() {
        SkipWhitespace();
        if (position_ >= input_.size()) JsonError(position_, "missing value");
        switch (input_[position_]) {
            case '{': return ParseObject();
            case '[': return ParseArray();
            case '"': return JsonValue{JsonValue::Type::String, false,
                                        ParseString(), {}, {}};
            case 't': return ParseLiteral("true", JsonValue::Type::Boolean);
            case 'f': return ParseLiteral("false", JsonValue::Type::Boolean);
            case 'n': return ParseLiteral("null", JsonValue::Type::Null);
            default:
                if (input_[position_] == '-' ||
                    std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                    return ParseNumber();
                }
        }
        JsonError(position_, "unexpected value");
    }

    JsonValue ParseLiteral(std::string_view literal, JsonValue::Type type) {
        if (input_.compare(position_, literal.size(), literal) != 0) {
            JsonError(position_, "invalid literal");
        }
        position_ += literal.size();
        JsonValue value;
        value.type = type;
        value.boolean = type == JsonValue::Type::Boolean && literal == "true";
        value.text = std::string(literal);
        return value;
    }

    void AppendUtf8(std::string& output, uint32_t codepoint) {
        if (codepoint <= 0x7f) {
            output.push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7ff) {
            output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else if (codepoint <= 0xffff) {
            output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else if (codepoint <= 0x10ffff) {
            output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else {
            JsonError(position_, "invalid Unicode code point");
        }
    }

    uint32_t ParseHex4() {
        if (position_ + 4 > input_.size()) JsonError(position_, "short Unicode escape");
        uint32_t value = 0;
        for (size_t i = 0; i < 4; ++i) {
            const char c = input_[position_++];
            value <<= 4;
            if (c >= '0' && c <= '9') value += static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') value += static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') value += static_cast<uint32_t>(c - 'A' + 10);
            else JsonError(position_ - 1, "invalid Unicode escape");
        }
        return value;
    }

    std::string ParseString() {
        if (position_ >= input_.size() || input_[position_] != '"') {
            JsonError(position_, "string must start with quote");
        }
        ++position_;
        std::string output;
        while (position_ < input_.size()) {
            const unsigned char c = static_cast<unsigned char>(input_[position_++]);
            if (c == '"') return output;
            if (c < 0x20) JsonError(position_ - 1, "control character in string");
            if (c != '\\') {
                output.push_back(static_cast<char>(c));
                continue;
            }
            if (position_ >= input_.size()) JsonError(position_, "short escape");
            const char escaped = input_[position_++];
            switch (escaped) {
                case '"': output.push_back('"'); break;
                case '\\': output.push_back('\\'); break;
                case '/': output.push_back('/'); break;
                case 'b': output.push_back('\b'); break;
                case 'f': output.push_back('\f'); break;
                case 'n': output.push_back('\n'); break;
                case 'r': output.push_back('\r'); break;
                case 't': output.push_back('\t'); break;
                case 'u': {
                    uint32_t codepoint = ParseHex4();
                    if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                        if (position_ + 6 > input_.size() ||
                            input_[position_] != '\\' ||
                            input_[position_ + 1] != 'u') {
                            JsonError(position_, "unpaired high surrogate");
                        }
                        position_ += 2;
                        const uint32_t low = ParseHex4();
                        if (low < 0xdc00 || low > 0xdfff) {
                            JsonError(position_, "invalid low surrogate");
                        }
                        codepoint = 0x10000 +
                            ((codepoint - 0xd800) << 10) + (low - 0xdc00);
                    } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
                        JsonError(position_, "unpaired low surrogate");
                    }
                    AppendUtf8(output, codepoint);
                    break;
                }
                default: JsonError(position_ - 1, "unknown escape");
            }
        }
        JsonError(position_, "unterminated string");
    }

    JsonValue ParseNumber() {
        const size_t begin = position_;
        if (input_[position_] == '-') ++position_;
        if (position_ >= input_.size()) JsonError(position_, "short number");
        if (input_[position_] == '0') {
            ++position_;
        } else {
            if (!std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                JsonError(position_, "invalid number");
            }
            while (position_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                ++position_;
            }
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            if (position_ >= input_.size() ||
                !std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                JsonError(position_, "number requires fraction digits");
            }
            while (position_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                ++position_;
            }
        }
        if (position_ < input_.size() &&
            (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() &&
                (input_[position_] == '+' || input_[position_] == '-')) ++position_;
            if (position_ >= input_.size() ||
                !std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                JsonError(position_, "number requires exponent digits");
            }
            while (position_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                ++position_;
            }
        }
        JsonValue result;
        result.type = JsonValue::Type::Number;
        result.text = input_.substr(begin, position_ - begin);
        return result;
    }

    JsonValue ParseArray() {
        if (!Consume('[')) JsonError(position_, "array must start with bracket");
        JsonValue result;
        result.type = JsonValue::Type::Array;
        SkipWhitespace();
        if (Consume(']')) return result;
        while (true) {
            result.array.push_back(ParseValue());
            SkipWhitespace();
            if (Consume(']')) return result;
            if (!Consume(',')) JsonError(position_, "array requires comma");
        }
    }

    JsonValue ParseObject() {
        if (!Consume('{')) JsonError(position_, "object must start with brace");
        JsonValue result;
        result.type = JsonValue::Type::Object;
        SkipWhitespace();
        if (Consume('}')) return result;
        while (true) {
            SkipWhitespace();
            if (position_ >= input_.size() || input_[position_] != '"') {
                JsonError(position_, "object key must be string");
            }
            const std::string key = ParseString();
            if (!Consume(':')) JsonError(position_, "object requires colon");
            if (!result.object.emplace(key, ParseValue()).second) {
                JsonError(position_, "duplicate object key");
            }
            SkipWhitespace();
            if (Consume('}')) return result;
            if (!Consume(',')) JsonError(position_, "object requires comma");
        }
    }

    std::string input_;
    size_t position_ = 0;
};

const JsonValue& Require(const JsonValue& object, const char* key,
                         JsonValue::Type type) {
    if (object.type != JsonValue::Type::Object) {
        throw std::invalid_argument("revision matrix value is not an object");
    }
    const auto it = object.object.find(key);
    if (it == object.object.end()) {
        throw std::invalid_argument(std::string("revision matrix missing field: ") + key);
    }
    if (it->second.type != type) {
        throw std::invalid_argument(std::string("revision matrix field has wrong type: ") + key);
    }
    return it->second;
}

const JsonValue& RequireAny(const JsonValue& object, const char* key) {
    if (object.type != JsonValue::Type::Object) {
        throw std::invalid_argument("revision matrix value is not an object");
    }
    const auto it = object.object.find(key);
    if (it == object.object.end()) {
        throw std::invalid_argument(std::string("revision matrix missing field: ") + key);
    }
    return it->second;
}

uint64_t Unsigned(const JsonValue& value, const char* key) {
    if (value.type != JsonValue::Type::Number || value.text.empty() ||
        value.text.front() == '-' ||
        value.text.find_first_not_of("0123456789") != std::string::npos) {
        throw std::invalid_argument(std::string("revision matrix field is not an unsigned integer: ") + key);
    }
    size_t consumed = 0;
    uint64_t result = 0;
    try {
        result = std::stoull(value.text, &consumed, 10);
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string("revision matrix integer out of range: ") + key);
    }
    if (consumed != value.text.size()) {
        throw std::invalid_argument(std::string("revision matrix integer is malformed: ") + key);
    }
    return result;
}

std::string ScalarText(const JsonValue& value, const char* key) {
    if (value.type == JsonValue::Type::String ||
        value.type == JsonValue::Type::Number) return value.text;
    if (value.type == JsonValue::Type::Boolean) return value.boolean ? "true" : "false";
    throw std::invalid_argument(std::string("revision matrix axis is not scalar: ") + key);
}

bool Boolean(const JsonValue& value, const char* key) {
    if (value.type != JsonValue::Type::Boolean) {
        throw std::invalid_argument(std::string("revision matrix field is not boolean: ") + key);
    }
    return value.boolean;
}

void ParseOptionalAttributes(const JsonValue& object,
                             const std::set<std::string>& ignored,
                             std::map<std::string, std::string>& attributes,
                             std::map<std::string, std::vector<std::string>>& list_attributes,
                             std::map<std::string, std::map<std::string, std::string>>* object_attributes = nullptr) {
    if (object.type != JsonValue::Type::Object) {
        throw std::invalid_argument("revision matrix value is not an object");
    }
    for (const auto& [key, value] : object.object) {
        if (ignored.count(key) != 0) continue;
        if (value.type == JsonValue::Type::String ||
            value.type == JsonValue::Type::Number ||
            value.type == JsonValue::Type::Boolean) {
            attributes[key] = ScalarText(value, key.c_str());
        } else if (value.type == JsonValue::Type::Array) {
            std::vector<std::string> values;
            values.reserve(value.array.size());
            for (const auto& item : value.array) {
                values.push_back(ScalarText(item, key.c_str()));
            }
            list_attributes[key] = std::move(values);
        } else if (value.type == JsonValue::Type::Object && object_attributes != nullptr) {
            std::map<std::string, std::string> values;
            for (const auto& [nested_key, nested_value] : value.object) {
                values.emplace(nested_key, ScalarText(nested_value, nested_key.c_str()));
            }
            (*object_attributes)[key] = std::move(values);
        }
    }
}

std::string OptionalString(const JsonValue& object, const char* key) {
    const auto it = object.object.find(key);
    if (it == object.object.end()) return {};
    return ScalarText(it->second, key);
}

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::invalid_argument("cannot open revision matrix: " + path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

RevisionRow ParseRow(const JsonValue& value) {
    RevisionRow row;
    row.row_id = Require(value, "row_id", JsonValue::Type::String).text;
    row.status = Require(value, "status", JsonValue::Type::String).text;
    row.reason = Require(value, "reason", JsonValue::Type::String).text;
    const auto& reason_code = Require(value, "reason_code", JsonValue::Type::String).text;
    row.reason_code = reason_code;
    if (reason_code != row.reason) throw std::invalid_argument("row reason/reason_code mismatch");
    row.measured_count = Unsigned(Require(value, "measured_count", JsonValue::Type::Number), "measured_count");
    row.paper_measured_count = Unsigned(Require(value, "paper_measured_count", JsonValue::Type::Number), "paper_measured_count");
    row.toy_measured_count = Unsigned(Require(value, "toy_measured_count", JsonValue::Type::Number), "toy_measured_count");
    row.terminal_status = Require(value, "terminal_status", JsonValue::Type::String).text;
    row.method = OptionalString(value, "method");
    row.timing_contract = OptionalString(value, "timing_contract");
    row.raw_timing_contract = OptionalString(value, "raw_timing_contract");
    row.phase = OptionalString(value, "phase");
    row.pattern = OptionalString(value, "pattern");
    row.variant = OptionalString(value, "variant");
    row.fit_authority = OptionalString(value, "fit_authority");
    ParseOptionalAttributes(
        value,
        {"row_id", "status", "reason", "reason_code", "measured_count",
         "paper_measured_count", "toy_measured_count", "terminal_status",
         "method", "timing_contract", "raw_timing_contract", "phase",
         "pattern", "variant", "fit_authority"},
        row.attributes, row.list_attributes);
    return row;
}

RevisionCell ParseCell(const JsonValue& value) {
    RevisionCell cell;
    cell.cell_id = Require(value, "cell_id", JsonValue::Type::String).text;
    cell.family = Require(value, "family", JsonValue::Type::String).text;
    cell.producer = Require(value, "producer", JsonValue::Type::String).text;
    cell.profile = Require(value, "profile", JsonValue::Type::String).text;
    cell.dataset = Require(value, "dataset", JsonValue::Type::String).text;
    const auto& axes = Require(value, "axes", JsonValue::Type::Object);
    for (const auto& [key, axis_value] : axes.object) cell.axes.emplace(key, ScalarText(axis_value, key.c_str()));
    cell.axis = Require(value, "axis", JsonValue::Type::String).text;
    cell.axis_value = ScalarText(RequireAny(value, "axis_value"), "axis_value");
    cell.paper_count = Unsigned(Require(value, "paper_count", JsonValue::Type::Number), "paper_count");
    cell.toy_count = Unsigned(Require(value, "toy_count", JsonValue::Type::Number), "toy_count");
    cell.paper_trials = Unsigned(Require(value, "paper_trials", JsonValue::Type::Number), "paper_trials");
    cell.toy_trials = Unsigned(Require(value, "toy_trials", JsonValue::Type::Number), "toy_trials");
    const auto& paper_counts = Require(value, "paper_counts", JsonValue::Type::Object);
    for (const auto& [key, count] : paper_counts.object) {
        cell.paper_counts.emplace(key, Unsigned(count, key.c_str()));
    }
    const auto& toy_counts = Require(value, "toy_counts", JsonValue::Type::Object);
    for (const auto& [key, count] : toy_counts.object) {
        cell.toy_counts.emplace(key, Unsigned(count, key.c_str()));
    }
    cell.eligibility = Require(value, "eligibility", JsonValue::Type::String).text;
    cell.table_eligible = Boolean(Require(value, "table_eligible", JsonValue::Type::Boolean), "table_eligible");
    cell.comparison_eligible = Boolean(Require(value, "comparison_eligible", JsonValue::Type::Boolean), "comparison_eligible");
    cell.timeout_class = Require(value, "timeout_class", JsonValue::Type::String).text;
    cell.expected_artifact_schema = Require(value, "expected_artifact_schema", JsonValue::Type::String).text;
    const auto& artifact_schema = Require(value, "artifact_schema", JsonValue::Type::String).text;
    if (artifact_schema != cell.expected_artifact_schema) throw std::invalid_argument("artifact schema aliases disagree");
    cell.invocation_status = Require(value, "invocation_status", JsonValue::Type::String).text;
    ParseOptionalAttributes(
        value,
        {"cell_id", "family", "producer", "profile", "dataset", "axes",
         "axis", "axis_value", "paper_count", "toy_count", "paper_trials",
         "toy_trials", "paper_counts", "toy_counts", "eligibility",
         "table_eligible", "comparison_eligible", "timeout_class",
         "expected_artifact_schema", "artifact_schema", "invocation_status",
         "expected_rows"},
        cell.attributes, cell.list_attributes, &cell.object_attributes);
    const auto& rows = Require(value, "expected_rows", JsonValue::Type::Array);
    for (const auto& row : rows.array) cell.expected_rows.push_back(ParseRow(row));
    return cell;
}

void AddExpected(std::set<std::string>& expected, const std::string& family,
                 const std::string& axis, const std::vector<std::string>& values) {
    expected.insert("paper-v1::" + family + "::control=default");
    for (const auto& value : values) expected.insert("paper-v1::" + family + "::" + axis + "=" + value);
}

std::set<std::string> ExpectedIds() {
    const std::vector<std::string> k = {"16", "32", "64", "128", "256", "512"};
    const std::vector<std::string> m = {"16", "32", "64", "128", "256"};
    const std::vector<std::string> n = {"100", "1000", "10000", "100000"};
    const std::vector<std::string> u = {"16384", "65536", "262144", "1048576"};
    std::set<std::string> ids;
    for (const auto& family : {"piccard_std128", "piccard_std192_encoding"}) {
        AddExpected(ids, family, "k", k);
        AddExpected(ids, family, "m", m);
        AddExpected(ids, family, "n", n);
        AddExpected(ids, family, "u", u);
    }
    AddExpected(ids, "fhe_ind", "n", n);
    AddExpected(ids, "fhe_ind", "u", u);
    AddExpected(ids, "bcg12_minhash", "k", k);
    AddExpected(ids, "bcg12_minhash", "n", n);
    AddExpected(ids, "bcg12_exact", "n", n);
    AddExpected(ids, "sj16", "n", n);
    AddExpected(ids, "sj16", "u", u);
    ids.insert("paper-v1::sj16::fit=per_element");
    ids.insert("paper-v1::sj16::fit=precomputed");
    for (const auto& value : {"0.0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"}) {
        ids.insert("paper-v1::estimator_accuracy::j=" + std::string(value));
    }
    for (const auto& value : k) ids.insert("paper-v1::estimator_accuracy::k=" + value);
    for (const auto& axis : {"timing_m", "accuracy_m", "ciphertext_m", "crossover_m"}) {
        for (const auto& value : m) ids.insert("paper-v1::sqrt_comparison::" + std::string(axis) + "=" + value);
    }
    for (const auto& value : {"primary40", "sensitivity64", "feasibility128"}) ids.insert("paper-v1::flooding::profile=" + std::string(value));
    for (const auto& family : {"dynamic_timing", "dynamic_accuracy"}) {
        AddExpected(ids, family, "k", k);
        AddExpected(ids, family, "m", m);
        AddExpected(ids, family, "n", n);
    }
    ids.insert("paper-v1::dynamic_refresh::control=default");
    ids.insert("paper-v1::deletion_exact::control=default");
    ids.insert("paper-v1::deletion_mc::control=default");
    for (const auto& family : {"threshold_timing", "threshold_spec", "threshold_agreement"}) {
        for (const auto& value : {"16", "32", "64", "128", "256"}) ids.insert("paper-v1::" + std::string(family) + "::k=" + value);
    }
    for (const auto& value_k : {"64", "128", "256", "512"}) {
        for (int index = -10; index <= 10; ++index) {
            ids.insert("paper-v1::threshold_synthetic_fpfn::point=k" + std::string(value_k) + "_j" + std::to_string(index));
        }
    }
    ids.insert("paper-v1::threshold_dblp_fpfn::control=default");
    for (const auto& variant : {"dblp_acm_u65536", "enron_u65536", "enron_u1048576"}) {
        for (const auto& artifact : {"accuracy", "summary", "std128_timing", "std192_encoding"}) {
            ids.insert("paper-v1::real_dataset::" + std::string(variant) + "_artifact=" + artifact);
        }
    }
    return ids;
}

const std::map<std::string, size_t>& ExpectedFamilyCounts() {
    static const std::map<std::string, size_t> values = {
        {"piccard_std128", 20}, {"piccard_std192_encoding", 20}, {"fhe_ind", 9},
        {"bcg12_minhash", 11}, {"bcg12_exact", 5}, {"sj16", 11},
        {"estimator_accuracy", 17}, {"sqrt_comparison", 20}, {"flooding", 3},
        {"dynamic_timing", 16}, {"dynamic_accuracy", 16}, {"dynamic_refresh", 1},
        {"deletion_exact", 1}, {"deletion_mc", 1}, {"threshold_timing", 5},
        {"threshold_spec", 5}, {"threshold_agreement", 5},
        {"threshold_synthetic_fpfn", 84}, {"threshold_dblp_fpfn", 1},
        {"real_dataset", 12},
    };
    return values;
}

const std::string& RequiredAxis(const RevisionCell& cell, const char* axis) {
    const auto it = cell.axes.find(axis);
    if (it == cell.axes.end()) {
        throw std::invalid_argument("revision matrix cell is missing axis");
    }
    return it->second;
}

std::string OptionalAttribute(const std::map<std::string, std::string>& attributes,
                              const char* key) {
    const auto it = attributes.find(key);
    return it == attributes.end() ? std::string{} : it->second;
}

void RequireAttribute(const std::map<std::string, std::string>& attributes,
                      const char* key, const std::string& expected) {
    if (OptionalAttribute(attributes, key) != expected) {
        throw std::invalid_argument(std::string("revision matrix attribute mismatch: ") + key);
    }
}

void RequireListAttribute(
    const std::map<std::string, std::vector<std::string>>& attributes,
    const char* key, const std::vector<std::string>& expected) {
    const auto it = attributes.find(key);
    if (it == attributes.end() || it->second != expected) {
        throw std::invalid_argument(std::string("revision matrix list attribute mismatch: ") + key);
    }
}

void RequireObjectAttribute(
    const std::map<std::string, std::map<std::string, std::string>>& attributes,
    const char* key, const std::map<std::string, std::string>& expected) {
    const auto it = attributes.find(key);
    if (it == attributes.end() || it->second != expected) {
        throw std::invalid_argument(std::string("revision matrix object attribute mismatch: ") + key);
    }
}

void RequireCounts(const RevisionCell& cell, uint64_t paper_count,
                   uint64_t toy_count, uint64_t paper_trials,
                   uint64_t toy_trials,
                   const std::map<std::string, uint64_t>& paper_counts,
                   const std::map<std::string, uint64_t>& toy_counts) {
    if (cell.paper_count != paper_count || cell.toy_count != toy_count ||
        cell.paper_trials != paper_trials || cell.toy_trials != toy_trials ||
        cell.paper_counts != paper_counts || cell.toy_counts != toy_counts) {
        throw std::invalid_argument("revision matrix paper/toy count aliases mismatch");
    }
}

std::string ExpectedProducer(const RevisionCell& cell) {
    if (cell.family == "piccard_std128") return "bench_piccard";
    if (cell.family == "piccard_std192_encoding") return "bench_review_comparison";
    if (cell.family == "fhe_ind") return "bench_fhe_ind";
    if (cell.family == "bcg12_minhash" || cell.family == "bcg12_exact") {
        return "bench_review_comparison";
    }
    if (cell.family == "sj16") {
        return cell.axis == "fit" && cell.axis_value == "per_element"
                   ? "bench_sj16_calibrate"
                   : "bench_review_comparison";
    }
    if (cell.family == "estimator_accuracy") return "bench_estimator_bias";
    if (cell.family == "sqrt_comparison") {
        if (cell.axis == "timing_m") return "bench_onehot_sqrt";
        if (cell.axis == "accuracy_m") return "bench_sqrt_comparison";
        return "bench_crossover";
    }
    if (cell.family == "flooding") return "bench_noise";
    if (cell.family == "dynamic_timing" || cell.family == "dynamic_accuracy" ||
        cell.family == "dynamic_refresh") return "bench_dynamic";
    if (cell.family == "deletion_exact" || cell.family == "deletion_mc") {
        return "bench_deletion_survival";
    }
    if (cell.family == "threshold_timing" || cell.family == "threshold_spec" ||
        cell.family == "threshold_agreement" ||
        cell.family == "threshold_synthetic_fpfn") return "bench_threshold";
    if (cell.family == "threshold_dblp_fpfn") return "bench_real_datasets";
    if (cell.family == "real_dataset") {
        return RequiredAxis(cell, "artifact") == "summary"
                   ? "summarize_real_datasets.py"
                   : "bench_real_datasets";
    }
    return {};
}

std::string ExpectedUniverse(const RevisionCell& cell) {
    if (cell.family == "real_dataset") {
        const auto& variant = RequiredAxis(cell, "variant");
        if (variant == "dblp_acm_u65536" || variant == "enron_u65536") {
            return "65536";
        }
        if (variant == "enron_u1048576") return "1048576";
        return {};
    }
    if (cell.axis == "u") return cell.axis_value;
    if (cell.axis == "n" && cell.axis_value == "100000") return "262144";
    return "65536";
}

std::map<std::string, std::string> ExpectedAxes(const RevisionCell& cell) {
    std::map<std::string, std::string> axes;
    const auto add_common = [&]() {
        axes = {{"k", "128"}, {"m", "64"}, {"n", "1000"},
                {"u", ExpectedUniverse(cell)}};
    };
    if (cell.family == "real_dataset") {
        axes = {{"artifact", cell.axis_value}, {"k", "128"}, {"m", "64"},
                {"n", "1000"}, {"u", ExpectedUniverse(cell)},
                {"variant", OptionalAttribute(cell.attributes, "variant")}};
        return axes;
    }
    if (cell.family == "threshold_dblp_fpfn") {
        add_common();
        axes["variant"] = OptionalAttribute(cell.attributes, "variant");
        return axes;
    }
    add_common();
    if (cell.family == "estimator_accuracy") {
        if (cell.axis == "j") axes["j"] = cell.axis_value;
        else axes["k"] = cell.axis_value;
    } else if (cell.family == "flooding") {
        // The profile selector is represented by the cell axis and the
        // dedicated noise_profile field; the numeric workload axes remain
        // the complete runner geometry.
    } else if (cell.family == "sqrt_comparison") {
        axes["m"] = cell.axis_value;
    } else if (cell.family == "threshold_synthetic_fpfn") {
        axes["k"] = OptionalAttribute(cell.attributes, "point_k");
        axes["grid_index"] = OptionalAttribute(cell.attributes, "grid_index");
    } else if (cell.axis == "k" || cell.axis == "m" || cell.axis == "n" ||
               cell.axis == "u") {
        axes[cell.axis] = cell.axis_value;
    }
    return axes;
}

std::string ExpectedArtifactSchema(const RevisionCell& cell) {
    if (cell.family == "piccard_std128") return "piccard-benchmark-csv-v1";
    if (cell.family == "piccard_std192_encoding") return "review-encoding-csv-v1";
    if (cell.family == "fhe_ind") return "fhe-ind-csv-v1";
    if (cell.family == "bcg12_minhash" || cell.family == "bcg12_exact" ||
        (cell.family == "sj16" && cell.axis != "fit") ||
        (cell.family == "sj16" && cell.axis == "fit" && cell.axis_value == "precomputed")) {
        return "review-comparison-csv-v1";
    }
    if (cell.family == "sj16") return "sj16-calibration-v1";
    if (cell.family == "estimator_accuracy") return "estimator-diagnostic-csv-v1";
    if (cell.family == "sqrt_comparison") return "sqrt-comparison-csv-v1";
    if (cell.family == "flooding") return "noise-profile-v1";
    if (cell.family == "dynamic_timing" || cell.family == "dynamic_accuracy" ||
        cell.family == "dynamic_refresh") return "dynamic-benchmark-csv-v1";
    if (cell.family == "deletion_exact" || cell.family == "deletion_mc") {
        return "deletion-survival-csv-v1";
    }
    if (cell.family == "threshold_timing" || cell.family == "threshold_spec" ||
        cell.family == "threshold_agreement") return "threshold-csv-v1";
    if (cell.family == "threshold_synthetic_fpfn") return "threshold-fpfn-csv-v1";
    if (cell.family == "threshold_dblp_fpfn") return "real-threshold-csv-v1";
    if (cell.family == "real_dataset") return "real-dataset-csv-v1";
    return {};
}

bool IsSquareRootApplicable(const RevisionCell& cell) {
    const auto it = cell.axes.find("m");
    return it != cell.axes.end() &&
           (it->second == "16" || it->second == "64" || it->second == "256");
}

void RequireRow(const RevisionRow& row, const char* row_id, const char* status,
                const char* reason, uint64_t paper_count, uint64_t toy_count,
                const char* method = nullptr, const char* timing_contract = nullptr) {
    if (row.row_id != row_id || row.status != status || row.reason != reason ||
        row.reason_code != reason || row.terminal_status != status ||
        row.measured_count != paper_count || row.paper_measured_count != paper_count ||
        row.toy_measured_count != toy_count) {
        throw std::invalid_argument("revision matrix expected row contract mismatch");
    }
    if (method != nullptr && row.method != method) {
        throw std::invalid_argument("revision matrix row method mismatch");
    }
    if (timing_contract != nullptr && row.timing_contract != timing_contract) {
        throw std::invalid_argument("revision matrix row timing contract mismatch");
    }
}

void RequireRowAttribute(const RevisionRow& row, const char* key,
                         const std::string& expected) {
    const std::string name(key);
    if (name == "fit_authority" || name == "timing_contract" ||
        name == "raw_timing_contract" || name == "phase" ||
        name == "pattern" || name == "variant" || name == "method") {
        const std::string actual = name == "fit_authority" ? row.fit_authority
                                  : name == "timing_contract" ? row.timing_contract
                                  : name == "raw_timing_contract" ? row.raw_timing_contract
                                  : name == "phase" ? row.phase
                                  : name == "pattern" ? row.pattern
                                  : name == "variant" ? row.variant
                                  : row.method;
        if (actual != expected) {
            throw std::invalid_argument(std::string("revision matrix row attribute mismatch: ") + key);
        }
        return;
    }
    RequireAttribute(row.attributes, key, expected);
}

void RequireEligibility(const RevisionCell& cell, const char* eligibility,
                       bool table_eligible, bool comparison_eligible,
                       const char* invocation_status = "RUN") {
    if (cell.eligibility != eligibility || cell.table_eligible != table_eligible ||
        cell.comparison_eligible != comparison_eligible ||
        cell.invocation_status != invocation_status) {
        throw std::invalid_argument("revision matrix eligibility/status contract mismatch");
    }
}

void ValidateFamilyCell(const RevisionCell& cell) {
    const auto id_separator = cell.cell_id.rfind("::");
    const auto id_equals = cell.cell_id.find('=', id_separator == std::string::npos
                                                  ? 0
                                                  : id_separator + 2);
    if (id_separator == std::string::npos || id_equals == std::string::npos ||
        cell.cell_id.substr(id_separator + 2, id_equals - id_separator - 2) != cell.axis ||
        cell.cell_id.substr(id_equals + 1) != cell.axis_value) {
        throw std::invalid_argument("revision matrix cell axis does not match its ID");
    }
    if (cell.producer != ExpectedProducer(cell)) {
        throw std::invalid_argument("revision matrix producer/family binding mismatch");
    }
    if (cell.profile != "paper-v1" || cell.timeout_class != "standard") {
        throw std::invalid_argument("revision matrix profile/timeout mismatch");
    }
    if (cell.expected_artifact_schema != ExpectedArtifactSchema(cell)) {
        throw std::invalid_argument("revision matrix artifact schema mismatch");
    }
    if (cell.axes != ExpectedAxes(cell)) {
        throw std::invalid_argument("revision matrix family axes mismatch");
    }
    if (cell.family == "real_dataset" || cell.family == "threshold_dblp_fpfn") {
        const std::string expected_dataset = cell.family == "threshold_dblp_fpfn"
                                                 ? "dblp_acm"
                                                 : (RequiredAxis(cell, "variant").rfind("dblp_", 0) == 0
                                                        ? "dblp_acm"
                                                        : "enron");
        if (cell.dataset != expected_dataset) {
            throw std::invalid_argument("revision matrix real dataset binding mismatch");
        }
    } else if (cell.dataset != "synthetic") {
        throw std::invalid_argument("revision matrix synthetic dataset binding mismatch");
    }
    if (cell.family == "real_dataset") {
        if (OptionalAttribute(cell.attributes, "variant") != RequiredAxis(cell, "variant") ||
            OptionalAttribute(cell.attributes, "artifact_kind") != RequiredAxis(cell, "artifact") ||
            OptionalAttribute(cell.attributes, "threshold_forbidden") !=
                (RequiredAxis(cell, "variant").rfind("enron_", 0) == 0 ? "true" : "false")) {
            throw std::invalid_argument("revision matrix real variant aliases mismatch");
        }
    }
    if (cell.family == "threshold_dblp_fpfn") {
        if (OptionalAttribute(cell.attributes, "variant") != "dblp_acm_u65536") {
            throw std::invalid_argument("revision matrix DBLP threshold binding mismatch");
        }
    }

    if (cell.family == "piccard_std128") {
        RequireEligibility(cell, "TABLE_ELIGIBLE", true, true);
        RequireCounts(cell, 30, 1, 30, 1,
                      {{"accuracy", 50}, {"timing", 30}},
                      {{"accuracy", 1}, {"timing", 1}});
        if (cell.expected_rows.size() != 2) {
            throw std::invalid_argument("piccard STD128 row topology mismatch");
        }
        RequireRow(cell.expected_rows.at(0), "onehot_timing", "MEASURED", "", 30, 1,
                   "piccard", "full-query");
        RequireRow(cell.expected_rows.at(1), "onehot_accuracy", "MEASURED", "", 50, 1,
                   "piccard", "NOT_APPLICABLE");
        return;
    }
    if (cell.family == "piccard_std192_encoding") {
        RequireEligibility(cell, "DIAGNOSTIC_ONLY", false, false);
        const bool square = IsSquareRootApplicable(cell);
        RequireCounts(cell, 30, 1, 30, 1,
                      {{"correctness", 1}, {"encoding", 30}},
                      {{"correctness", 1}, {"encoding", 1}});
        if (cell.expected_rows.size() != 2) {
            throw std::invalid_argument("piccard STD192 row topology mismatch");
        }
        for (const auto& row : cell.expected_rows) {
            if (row.attributes.find("encoding_only") == row.attributes.end() ||
                OptionalAttribute(row.attributes, "encoding_only") != "true") {
                throw std::invalid_argument("STD192 row is not encoding-only");
            }
        }
        RequireRow(cell.expected_rows.at(0), "piccard_encode", "DIAGNOSTIC", "", 30, 1,
                   "piccard_encode");
        RequireRow(cell.expected_rows.at(1), "piccard_sqrt_encode",
                   square ? "DIAGNOSTIC" : "NOT_APPLICABLE",
                   square ? "" : "sqrt-m-not-perfect-square",
                   square ? 30 : 0, square ? 1 : 0, "piccard_sqrt_encode");
        return;
    }
    if (cell.family == "fhe_ind") {
        RequireEligibility(cell, "DIAGNOSTIC_ONLY", false, false);
        RequireCounts(cell, 30, 1, 30, 1, {{"timing", 30}}, {{"timing", 1}});
        if (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.comparison_eligible ||
            cell.table_eligible || cell.expected_rows.size() != 1) {
            throw std::invalid_argument("FHE-IND eligibility/topology mismatch");
        }
        RequireRow(cell.expected_rows.at(0), "fhe_ind", "DIAGNOSTIC", "", 30, 1,
                   "fhe_ind");
        RequireRowAttribute(cell.expected_rows.at(0), "raw_timing_contract", "raw-phase-v1");
        return;
    }
    if (cell.family == "bcg12_minhash" || cell.family == "bcg12_exact") {
        RequireEligibility(cell, cell.family == "bcg12_minhash" ? "TABLE_ELIGIBLE" : "DIAGNOSTIC_ONLY",
                           cell.family == "bcg12_minhash", cell.family == "bcg12_minhash");
        RequireCounts(cell, 30, 1, 30, 1, {{"timing", 30}}, {{"timing", 1}});
        if (cell.expected_rows.size() != 2) {
            throw std::invalid_argument("BCG12 row topology mismatch");
        }
        if (cell.family == "bcg12_minhash") {
            RequireRow(cell.expected_rows.at(0), "bcg12_mh_ec", "MEASURED", "", 30, 1,
                       "bcg12_mh_ec");
            RequireRow(cell.expected_rows.at(1), "bcg12_mh_ff", "MEASURED", "", 30, 1,
                       "bcg12_mh_ff");
        } else {
            RequireRow(cell.expected_rows.at(0), "bcg12_exact_ec", "DIAGNOSTIC", "", 30, 1,
                       "bcg12_exact_ec");
            RequireRow(cell.expected_rows.at(1), "bcg12_exact_ff", "DIAGNOSTIC", "", 30, 1,
                       "bcg12_exact_ff");
        }
        return;
    }
    if (cell.family == "sj16") {
        RequireAttribute(cell.attributes, "key_bits", "3072");
        RequireAttribute(cell.attributes, "threads", "2");
        if (cell.axis == "fit") {
            if (cell.expected_rows.size() != 1 || cell.eligibility != "DIAGNOSTIC_ONLY" ||
                cell.comparison_eligible || cell.table_eligible ||
                OptionalAttribute(cell.attributes, "key_bits") != "3072" ||
                OptionalAttribute(cell.attributes, "threads") != "2") {
                throw std::invalid_argument("SJ16 fit metadata mismatch");
            }
            const auto& row = cell.expected_rows.front();
            if (cell.axis_value == "per_element") {
                RequireCounts(cell, 30, 1, 30, 1,
                              {{"enc_iters", 30}, {"query_trials", 30}},
                              {{"enc_iters", 1}, {"query_trials", 1}});
                RequireRow(row, "sj16_fit_per_element", "DIAGNOSTIC", "", 30, 1,
                           "bench_sj16_calibrate");
                RequireRowAttribute(row, "held_out", "32768");
                RequireRowAttribute(row, "key_bits", "3072");
                RequireRowAttribute(row, "precomputed", "false");
                RequireRowAttribute(row, "threads", "2");
                RequireRowAttribute(row, "warmup_calls", "1");
                RequireListAttribute(row.list_attributes, "sizes", {"4096", "8192", "16384"});
                RequireAttribute(cell.attributes, "fit_authority", "true");
                RequireAttribute(cell.attributes, "precomputed", "false");
                RequireListAttribute(cell.list_attributes, "sizes", {"4096", "8192", "16384"});
                RequireAttribute(cell.attributes, "held_out", "32768");
            } else {
                RequireCounts(cell, 30, 1, 30, 1, {{"timing", 30}}, {{"timing", 1}});
                RequireRow(row, "sj16_fit_precomputed", "DIAGNOSTIC", "", 30, 1,
                           "bench_review_comparison");
                for (const auto& key_value : {std::pair<const char*, const char*>("k", "128"),
                                              {"m", "64"}, {"n", "1000"}, {"u", "65536"},
                                              {"key_bits", "3072"}, {"threads", "2"},
                                              {"precomputed", "true"}, {"warmup_calls", "1"}}) {
                    RequireRowAttribute(row, key_value.first, key_value.second);
                }
                RequireAttribute(cell.attributes, "fit_authority", "false");
                RequireAttribute(cell.attributes, "precomputed", "true");
                RequireAttribute(cell.attributes, "k", "128");
                RequireAttribute(cell.attributes, "m", "64");
                RequireAttribute(cell.attributes, "n", "1000");
                RequireAttribute(cell.attributes, "u", "65536");
            }
            return;
        }
        const bool extrapolated = RequiredAxis(cell, "u") == "262144" ||
                                   RequiredAxis(cell, "u") == "1048576" ||
                                   (cell.axis == "n" && cell.axis_value == "100000");
        const bool request_metadata = cell.axis == "n" && cell.axis_value == "100000";
        if (cell.expected_rows.size() != 1) {
            throw std::invalid_argument("SJ16 row topology mismatch");
        }
        if (extrapolated) {
            RequireEligibility(cell, "DIAGNOSTIC_ONLY", false, false, "NO_SPAWN");
            RequireRow(cell.expected_rows.front(), "sj16", "EXTRAPOLATED",
                       "sj16-paillier3072-calibration-bound-v1", 0, 0, "sj16");
            RequireRowAttribute(cell.expected_rows.front(), "fit_authority", "per_element");
            if (cell.invocation_status != "NO_SPAWN" || cell.expected_rows.front().measured_count != 0) {
                throw std::invalid_argument("SJ16 extrapolation spawn/count mismatch");
            }
            RequireCounts(cell, request_metadata ? 30 : 0, request_metadata ? 1 : 0,
                          request_metadata ? 30 : 0, request_metadata ? 1 : 0,
                          {{"timing", request_metadata ? 30 : 0}},
                          {{"timing", request_metadata ? 1 : 0}});
        } else {
            RequireEligibility(cell, "TABLE_ELIGIBLE", true, true);
            RequireRow(cell.expected_rows.front(), "sj16", "MEASURED", "", 30, 1,
                       "sj16");
            RequireCounts(cell, 30, 1, 30, 1, {{"timing", 30}}, {{"timing", 1}});
            if (cell.invocation_status != "RUN") {
                throw std::invalid_argument("SJ16 measured cell must run");
            }
        }
        RequireRowAttribute(cell.expected_rows.front(), "key_bits", "3072");
        RequireRowAttribute(cell.expected_rows.front(), "threads", "2");
        return;
    }
    if (cell.family == "estimator_accuracy") {
        const bool j_cell = cell.axis == "j";
        const uint64_t trials = j_cell ? 50 : 500;
        RequireEligibility(cell, "TABLE_ELIGIBLE", true, true);
        RequireCounts(cell, trials, 1, trials, 1, {{"trials", trials}}, {{"trials", 1}});
        RequireAttribute(cell.attributes, "trials", std::to_string(trials));
        if (cell.expected_rows.size() != 1 || cell.expected_rows.front().method != "estimator") {
            throw std::invalid_argument("estimator row topology/method mismatch");
        }
        RequireRow(cell.expected_rows.front(), j_cell ? "estimator" : "estimator_convergence",
                   "MEASURED", "", trials, 1, "estimator");
        RequireAttribute(cell.attributes, "trials", std::to_string(trials));
        RequireRowAttribute(cell.expected_rows.front(), "toy_trials", "1");
        RequireRowAttribute(cell.expected_rows.front(), "trials", std::to_string(trials));
        if (!j_cell) {
            RequireObjectAttribute(cell.object_attributes, "toy_dispersion_sentinels",
                                   {{"median", "N/A"}, {"sd", "-1"}});
        }
        return;
    }
    if (cell.family == "sqrt_comparison") {
        const bool square = IsSquareRootApplicable(cell);
        uint64_t trials = cell.axis == "accuracy_m" ? 50
                          : (cell.axis == "ciphertext_m" ? 1 : 30);
        RequireEligibility(cell, "TABLE_ELIGIBLE", true, true);
        RequireCounts(cell, trials, 1, trials, 1,
                      {{"onehot", trials}, {"sqrt", square ? trials : 0}},
                      {{"onehot", 1}, {"sqrt", square ? 1 : 0}});
        if (cell.expected_rows.size() != 2) {
            throw std::invalid_argument("sqrt comparison row topology mismatch");
        }
        RequireRow(cell.expected_rows.at(0), "onehot", "MEASURED", "", trials, 1,
                   "onehot");
        RequireRow(cell.expected_rows.at(1), "sqrt", square ? "MEASURED" : "NOT_APPLICABLE",
                   square ? "" : "sqrt-m-not-perfect-square", square ? trials : 0,
                   square ? 1 : 0, "sqrt");
        return;
    }
    if (cell.family == "flooding") {
        RequireEligibility(cell, "DIAGNOSTIC_ONLY", false, false);
        const auto profile = cell.axis_value;
        if (OptionalAttribute(cell.attributes, "noise_profile") != profile ||
            OptionalAttribute(cell.attributes, "timing_contract") != "NOT_APPLICABLE") {
            throw std::invalid_argument("flooding profile/timing contract mismatch");
        }
        RequireCounts(cell, 5, 1, 5, 1,
                      {{"repetitions_per_pattern", 5}},
                      {{"repetitions_per_pattern", 1}});
        if (cell.expected_rows.size() != 3) {
            throw std::invalid_argument("flooding row topology mismatch");
        }
        for (size_t index = 0; index < 3; ++index) {
            const char* pattern = index == 0 ? "zero" : (index == 1 ? "random" : "adversarial");
            const auto& row = cell.expected_rows[index];
            RequireRow(row, pattern, "DIAGNOSTIC", "", 5, 1);
            if (row.pattern != pattern || row.timing_contract != "NOT_APPLICABLE") {
                throw std::invalid_argument("flooding row pattern/timing mismatch");
            }
        }
        return;
    }
    if (cell.family == "dynamic_timing" || cell.family == "dynamic_accuracy" ||
        cell.family == "dynamic_refresh") {
        const bool refresh = cell.family == "dynamic_refresh";
        const uint64_t trials = cell.family == "dynamic_accuracy" ? 50 : 30;
        RequireEligibility(cell, "TABLE_ELIGIBLE", true, true);
        if (OptionalAttribute(cell.attributes, "updates") != "1") {
            throw std::invalid_argument("dynamic update count mismatch");
        }
        if (refresh) {
            RequireCounts(cell, 30, 1, 30, 1, {{"refresh", 30}}, {{"refresh", 1}});
            RequireObjectAttribute(cell.object_attributes, "refresh_axes",
                                   {{"k", "128"}, {"m", "64"}, {"n", "1000"}});
            if (cell.expected_rows.size() != 1) {
                throw std::invalid_argument("dynamic refresh row topology mismatch");
            }
            const auto& row = cell.expected_rows.front();
            RequireRow(row, "refresh", "MEASURED", "", 30, 1, "refresh");
            RequireRowAttribute(row, "k", "128");
            RequireRowAttribute(row, "m", "64");
            RequireRowAttribute(row, "n", "1000");
            RequireRowAttribute(row, "updates", "1");
        } else {
            const std::map<std::string, uint64_t> paper =
                {{"delete", trials}, {"insert", trials}};
            const std::map<std::string, uint64_t> toy = {{"delete", 1}, {"insert", 1}};
            RequireCounts(cell, trials, 1, trials, 1, paper, toy);
            if (cell.expected_rows.size() != 2) {
                throw std::invalid_argument("dynamic row topology mismatch");
            }
            const char* first_id = cell.family == "dynamic_accuracy" ? "insert_correctness" : "insert";
            const char* second_id = cell.family == "dynamic_accuracy" ? "delete_correctness" : "delete";
            RequireRow(cell.expected_rows.at(0), first_id, "MEASURED", "", trials, 1);
            RequireRow(cell.expected_rows.at(1), second_id, "MEASURED", "", trials, 1);
            if (cell.expected_rows.at(0).phase != "insert" ||
                cell.expected_rows.at(1).phase != "delete" ||
                OptionalAttribute(cell.expected_rows.at(0).attributes, "updates") != "1" ||
                OptionalAttribute(cell.expected_rows.at(1).attributes, "updates") != "1") {
                throw std::invalid_argument("dynamic phase/update contract mismatch");
            }
        }
        return;
    }
    if (cell.family == "deletion_exact" || cell.family == "deletion_mc") {
        const bool exact = cell.family == "deletion_exact";
        const uint64_t trials = exact ? 0 : 1000;
        RequireEligibility(cell, "DIAGNOSTIC_ONLY", false, false);
        RequireCounts(cell, trials, exact ? 0 : 1, trials, exact ? 0 : 1,
                      {{exact ? "measured" : "trials", trials}},
                      {{exact ? "measured" : "trials", exact ? 0 : 1}});
        RequireAttribute(cell.attributes, "trials", std::to_string(trials));
        if (cell.expected_rows.size() != 1) {
            throw std::invalid_argument("deletion row topology mismatch");
        }
        const auto& row = cell.expected_rows.front();
        RequireRow(row, exact ? "exact" : "monte_carlo", "DIAGNOSTIC", "", trials,
                   exact ? 0 : 1, exact ? "exact" : "monte_carlo");
        if (!exact) RequireRowAttribute(row, "trials", "1000");
        return;
    }
    if (cell.family == "threshold_timing" || cell.family == "threshold_spec" ||
        cell.family == "threshold_agreement") {
        const bool timing = cell.family == "threshold_timing";
        const bool agreement = cell.family == "threshold_agreement";
        const uint64_t trials = timing ? 30 : (agreement ? 50 : 0);
        RequireEligibility(cell, agreement || timing ? "TABLE_ELIGIBLE" : "DIAGNOSTIC_ONLY",
                           agreement || timing, agreement || timing);
        RequireCounts(cell, trials, 1, trials, 1,
                      {{timing ? "timing" : (agreement ? "agreement" : "spec"), trials}},
                      {{timing ? "timing" : (agreement ? "agreement" : "spec"), 1}});
        RequireAttribute(cell.attributes, "k", cell.axis_value);
        if (cell.expected_rows.size() != 1) {
            throw std::invalid_argument("threshold row topology mismatch");
        }
        const char* row_id = timing ? "timing" : (agreement ? "agreement" : "spec");
        const char* status = timing || agreement ? "MEASURED" : "DIAGNOSTIC";
        RequireRow(cell.expected_rows.front(), row_id, status, "", trials, 1,
                   row_id);
        RequireRowAttribute(cell.expected_rows.front(), "k", cell.axis_value);
        return;
    }
    if (cell.family == "threshold_synthetic_fpfn") {
        RequireEligibility(cell, "DIAGNOSTIC_ONLY", false, false);
        RequireCounts(cell, 1000, 1, 1000, 1, {{"trials", 1000}}, {{"trials", 1}});
        RequireAttribute(cell.attributes, "point_k", RequiredAxis(cell, "k"));
        RequireAttribute(cell.attributes, "grid_index", RequiredAxis(cell, "grid_index"));
        if (cell.expected_rows.size() != 1) {
            throw std::invalid_argument("threshold synthetic row topology mismatch");
        }
        const auto& row = cell.expected_rows.front();
        RequireRow(row, "synthetic_fpfn", "DIAGNOSTIC", "", 1000, 1,
                   "synthetic_fpfn");
        RequireRowAttribute(row, "point_k", RequiredAxis(cell, "k"));
        RequireRowAttribute(row, "grid_index", RequiredAxis(cell, "grid_index"));
        RequireRowAttribute(row, "trials", "1000");
        return;
    }
    if (cell.family == "threshold_dblp_fpfn") {
        RequireEligibility(cell, "DIAGNOSTIC_ONLY", false, false);
        RequireCounts(cell, 50, 1, 50, 1, {{"held_out", 50}}, {{"held_out", 1}});
        RequireListAttribute(cell.list_attributes, "truth_bases", {"label", "exact_jaccard"});
        if (cell.expected_rows.size() != 1) {
            throw std::invalid_argument("DBLP threshold row topology mismatch");
        }
        RequireRow(cell.expected_rows.front(), "dblp_held_out", "DIAGNOSTIC", "", 50, 1,
                   "dblp_held_out");
        RequireListAttribute(cell.expected_rows.front().list_attributes, "truth_bases",
                             {"label", "exact_jaccard"});
        return;
    }
    if (cell.family == "real_dataset") {
        const auto artifact = RequiredAxis(cell, "artifact");
        const bool encoding = artifact == "std192_encoding";
        const bool timing = artifact == "std128_timing";
        const uint64_t trials = timing || encoding ? 30 : 1;
        RequireEligibility(cell, encoding ? "DIAGNOSTIC_ONLY" : "TABLE_ELIGIBLE",
                           !encoding, !encoding);
        const std::map<std::string, uint64_t> paper = encoding
            ? std::map<std::string, uint64_t>{{"correctness", 1}, {artifact, 30}}
            : std::map<std::string, uint64_t>{{artifact, trials}};
        const std::map<std::string, uint64_t> toy = encoding
            ? std::map<std::string, uint64_t>{{"correctness", 1}, {artifact, 1}}
            : std::map<std::string, uint64_t>{{artifact, 1}};
        RequireCounts(cell, trials, 1, trials, 1, paper, toy);
        if (cell.expected_rows.size() != 1) {
            throw std::invalid_argument("real dataset row topology mismatch");
        }
        const auto& row = cell.expected_rows.front();
        RequireRow(row, artifact.c_str(), encoding ? "DIAGNOSTIC" : "MEASURED", "",
                   trials, 1, artifact.c_str());
        if (row.variant != RequiredAxis(cell, "variant")) {
            throw std::invalid_argument("real dataset row variant mismatch");
        }
        return;
    }
    throw std::invalid_argument("revision matrix family has no validation contract");
}

bool IsStatus(const std::string& status) {
    return status == "MEASURED" || status == "DIAGNOSTIC" ||
           status == "EXTRAPOLATED" || status == "NOT_APPLICABLE";
}

void ValidateRow(const RevisionRow& row) {
    if (row.row_id.empty() || !IsStatus(row.status)) {
        throw std::invalid_argument("revision matrix row has invalid id/status");
    }
    if (row.reason_code != row.reason || row.terminal_status != row.status ||
        row.measured_count != row.paper_measured_count) {
        throw std::invalid_argument("revision matrix row aliases disagree");
    }
    if (row.status == "NOT_APPLICABLE" && row.reason.empty()) {
        throw std::invalid_argument("NOT_APPLICABLE row requires a reason");
    }
    if (row.status == "EXTRAPOLATED" && row.reason != "sj16-paillier3072-calibration-bound-v1") {
        throw std::invalid_argument("EXTRAPOLATED row has invalid reason");
    }
    if ((row.status == "MEASURED" || row.status == "DIAGNOSTIC") && !row.reason.empty()) {
        throw std::invalid_argument("measured/diagnostic row has an unexplained reason");
    }
    if (row.status == "NOT_APPLICABLE" && row.reason != "sqrt-m-not-perfect-square") {
        throw std::invalid_argument("NOT_APPLICABLE row has invalid reason");
    }
    if (row.status == "NOT_APPLICABLE" || row.status == "EXTRAPOLATED") {
        if (row.measured_count != 0 || row.toy_measured_count != 0) {
            throw std::invalid_argument("terminal non-measured row has measured calls");
        }
    }
}

}  // namespace

RevisionMatrix LoadRevisionMatrix(const std::filesystem::path& path) {
    const JsonValue root = JsonParser(ReadFile(path)).Parse();
    RevisionMatrix matrix;
    matrix.schema = Require(root, "schema", JsonValue::Type::String).text;
    matrix.version = static_cast<uint32_t>(Unsigned(Require(root, "version", JsonValue::Type::Number), "version"));
    matrix.id_grammar = Require(root, "id_grammar", JsonValue::Type::String).text;
    matrix.cell_count = Unsigned(Require(root, "cell_count", JsonValue::Type::Number), "cell_count");
    const auto& families = Require(root, "families", JsonValue::Type::Object);
    for (const auto& [family, count] : families.object) matrix.family_counts.emplace(family, Unsigned(count, family.c_str()));
    const auto& cells = Require(root, "cells", JsonValue::Type::Array);
    for (const auto& cell : cells.array) matrix.cells.push_back(ParseCell(cell));
    ValidateRevisionMatrix(matrix);
    return matrix;
}

void ValidateRevisionMatrix(const RevisionMatrix& matrix) {
    if (matrix.schema != "piccard-revision-matrix-v1" || matrix.version != 1 ||
        matrix.id_grammar != "paper-v1::<family>::<axis>=<value>") {
        throw std::invalid_argument("revision matrix schema/version/grammar mismatch");
    }
    if (matrix.cell_count != 263 || matrix.cells.size() != 263) {
        throw std::invalid_argument("revision matrix must contain exactly 263 cells");
    }
    if (matrix.family_counts != std::map<std::string, uint64_t>(
            ExpectedFamilyCounts().begin(), ExpectedFamilyCounts().end())) {
        throw std::invalid_argument("revision matrix family count table mismatch");
    }
    const auto expected = ExpectedIds();
    std::set<std::string> actual;
    std::string previous;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id <= previous) throw std::invalid_argument("revision matrix IDs are not strictly sorted");
        previous = cell.cell_id;
        if (!actual.insert(cell.cell_id).second) throw std::invalid_argument("duplicate revision matrix cell ID");
        if (cell.profile != "paper-v1" || cell.family.empty() || cell.producer.empty() ||
            cell.axis.empty() || cell.axis_value.empty() || cell.expected_rows.empty()) {
            throw std::invalid_argument("revision matrix cell is incomplete");
        }
        if (cell.invocation_status != "RUN" && cell.invocation_status != "NO_SPAWN") {
            throw std::invalid_argument("revision matrix invocation status is invalid");
        }
        if (cell.table_eligible != (cell.eligibility == "TABLE_ELIGIBLE") ||
            (cell.comparison_eligible &&
             cell.eligibility != "TABLE_ELIGIBLE")) {
            throw std::invalid_argument("revision matrix eligibility flags disagree");
        }
        if (cell.family == "fhe_ind" && (cell.eligibility != "DIAGNOSTIC_ONLY" || cell.comparison_eligible)) {
            throw std::invalid_argument("FHE-IND must remain diagnostic-only");
        }
        std::set<std::string> row_ids;
        for (const auto& row : cell.expected_rows) {
            if (!row_ids.insert(row.row_id).second) throw std::invalid_argument("duplicate expected row ID");
            ValidateRow(row);
        }
        ValidateFamilyCell(cell);
    }
    if (actual != expected) throw std::invalid_argument("revision matrix IDs are missing or unexpected");
    std::map<std::string, uint64_t> expected_counts;
    for (const auto& [family, count] : ExpectedFamilyCounts()) expected_counts[family] = count;
    if (matrix.family_counts != expected_counts) throw std::invalid_argument("revision matrix family counts differ from inventory");
}

RevisionMatrix LoadAndValidateRevisionMatrix(const std::filesystem::path& path) {
    return LoadRevisionMatrix(path);
}

std::vector<std::string> RevisionMatrixCellIds(const RevisionMatrix& matrix) {
    std::vector<std::string> ids;
    ids.reserve(matrix.cells.size());
    for (const auto& cell : matrix.cells) ids.push_back(cell.cell_id);
    return ids;
}

}  // namespace piccard::benchmark
