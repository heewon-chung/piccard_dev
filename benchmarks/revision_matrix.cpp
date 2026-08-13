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
    if (reason_code != row.reason) throw std::invalid_argument("row reason/reason_code mismatch");
    row.measured_count = Unsigned(Require(value, "measured_count", JsonValue::Type::Number), "measured_count");
    row.paper_measured_count = Unsigned(Require(value, "paper_measured_count", JsonValue::Type::Number), "paper_measured_count");
    row.toy_measured_count = Unsigned(Require(value, "toy_measured_count", JsonValue::Type::Number), "toy_measured_count");
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
    cell.eligibility = Require(value, "eligibility", JsonValue::Type::String).text;
    cell.table_eligible = Boolean(Require(value, "table_eligible", JsonValue::Type::Boolean), "table_eligible");
    cell.comparison_eligible = Boolean(Require(value, "comparison_eligible", JsonValue::Type::Boolean), "comparison_eligible");
    cell.timeout_class = Require(value, "timeout_class", JsonValue::Type::String).text;
    cell.expected_artifact_schema = Require(value, "expected_artifact_schema", JsonValue::Type::String).text;
    const auto& artifact_schema = Require(value, "artifact_schema", JsonValue::Type::String).text;
    if (artifact_schema != cell.expected_artifact_schema) throw std::invalid_argument("artifact schema aliases disagree");
    cell.invocation_status = Require(value, "invocation_status", JsonValue::Type::String).text;
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

bool IsStatus(const std::string& status) {
    return status == "MEASURED" || status == "DIAGNOSTIC" ||
           status == "EXTRAPOLATED" || status == "NOT_APPLICABLE";
}

void ValidateRow(const RevisionRow& row) {
    if (row.row_id.empty() || !IsStatus(row.status)) {
        throw std::invalid_argument("revision matrix row has invalid id/status");
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
        if (cell.family == "sj16" && cell.invocation_status == "NO_SPAWN" &&
            cell.axes.at("u") != "262144" && cell.axes.at("u") != "1048576") {
            throw std::invalid_argument("SJ16 NO_SPAWN is only valid for large-U cells");
        }
        if (cell.family == "real_dataset" && cell.axes.count("variant") != 0 &&
            cell.axes.at("variant").rfind("enron_", 0) == 0 &&
            cell.axes.at("artifact").find("threshold") != std::string::npos) {
            throw std::invalid_argument("Enron threshold cell is forbidden");
        }
        std::set<std::string> row_ids;
        for (const auto& row : cell.expected_rows) {
            if (!row_ids.insert(row.row_id).second) throw std::invalid_argument("duplicate expected row ID");
            ValidateRow(row);
        }
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
