#include "std_security_evidence_schema.h"

#include <openssl/evp.h>

#include <cmath>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <variant>

namespace piccard {
namespace std_evidence {
namespace {

void AppendU32(std::string* out, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out->push_back(static_cast<char>((value >> shift) & 0xff));
}

void AppendU64(std::string* out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out->push_back(static_cast<char>((value >> shift) & 0xff));
}

void AppendString(std::string* out, const std::string& value) {
    AppendU32(out, static_cast<uint32_t>(value.size()));
    out->append(value);
}

std::string Sha256Hex(const std::string& bytes) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr ||
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context, bytes.data(), bytes.size()) != 1 ||
        EVP_DigestFinal_ex(context, digest, &digest_size) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("SHA-256 computation failed");
    }
    EVP_MD_CTX_free(context);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest_size * 2);
    for (unsigned int i = 0; i < digest_size; ++i) {
        result.push_back(kHex[digest[i] >> 4]);
        result.push_back(kHex[digest[i] & 0x0f]);
    }
    return result;
}

const std::vector<CellSpec> kCoreCells = {
    {"onehot-std128", EvidenceCircuit::OneHot, "onehot-v1",
     SecurityLevel::STD128},
    {"onehot-std192", EvidenceCircuit::OneHot, "onehot-v1",
     SecurityLevel::STD192},
    {"sqrt-std128", EvidenceCircuit::Sqrt, "sqrt-b4-v1",
     SecurityLevel::STD128},
    {"sqrt-std192", EvidenceCircuit::Sqrt, "sqrt-b4-v1",
     SecurityLevel::STD192},
};

const std::vector<CellSpec> kFheIndCells = {
    {"fhe-ind-std128", EvidenceCircuit::FheInd, "fhe-indicator-v1",
     SecurityLevel::STD128, 0, 0},
    {"fhe-ind-std192", EvidenceCircuit::FheInd, "fhe-indicator-v1",
     SecurityLevel::STD192, 0, 0},
};

}  // namespace

const char* CircuitName(EvidenceCircuit circuit) {
    switch (circuit) {
        case EvidenceCircuit::OneHot:
            return "onehot";
        case EvidenceCircuit::Sqrt:
            return "sqrt";
        case EvidenceCircuit::FheInd:
            return "fhe_ind";
        case EvidenceCircuit::Threshold:
            return "threshold";
    }
    throw std::invalid_argument("unknown evidence circuit");
}

const char* SecurityName(SecurityLevel security) {
    switch (security) {
        case SecurityLevel::TOY:
            return "TOY";
        case SecurityLevel::STD128:
            return "STD128";
        case SecurityLevel::STD192:
            return "STD192";
        case SecurityLevel::STD256:
            return "STD256";
    }
    throw std::invalid_argument("unknown security level");
}

SecurityLevel ParseSecurityName(const std::string& value) {
    for (SecurityLevel security : {SecurityLevel::TOY,
                                   SecurityLevel::STD128,
                                   SecurityLevel::STD192,
                                   SecurityLevel::STD256}) {
        if (value == SecurityName(security)) return security;
    }
    throw std::invalid_argument("unknown security level: " + value);
}

bool operator==(const CellSpec& lhs, const CellSpec& rhs) {
    return std::tie(lhs.cell_id, lhs.circuit, lhs.shape_id, lhs.security,
                    lhs.k, lhs.m, lhs.set_size,
                    lhs.target_jaccard_numerator,
                    lhs.target_jaccard_denominator,
                    lhs.realized_intersection, lhs.realized_union, lhs.seed,
                    lhs.trials, lhs.calibration_repetitions) ==
           std::tie(rhs.cell_id, rhs.circuit, rhs.shape_id, rhs.security,
                    rhs.k, rhs.m, rhs.set_size,
                    rhs.target_jaccard_numerator,
                    rhs.target_jaccard_denominator,
                    rhs.realized_intersection, rhs.realized_union, rhs.seed,
                    rhs.trials, rhs.calibration_repetitions);
}

bool operator!=(const CellSpec& lhs, const CellSpec& rhs) {
    return !(lhs == rhs);
}

const std::vector<CellSpec>& CoreCells() { return kCoreCells; }
const std::vector<CellSpec>& FheIndCells() { return kFheIndCells; }

void ValidateCoreMatrix() {
    static const std::array<CellSpec, 4> expected = {{
        {"onehot-std128", EvidenceCircuit::OneHot, "onehot-v1",
         SecurityLevel::STD128},
        {"onehot-std192", EvidenceCircuit::OneHot, "onehot-v1",
         SecurityLevel::STD192},
        {"sqrt-std128", EvidenceCircuit::Sqrt, "sqrt-b4-v1",
         SecurityLevel::STD128},
        {"sqrt-std192", EvidenceCircuit::Sqrt, "sqrt-b4-v1",
         SecurityLevel::STD192},
    }};
    if (kCoreCells.size() != expected.size())
        throw std::logic_error("core evidence matrix size changed");
    for (size_t i = 0; i < expected.size(); ++i) {
        if (kCoreCells[i] != expected[i])
            throw std::logic_error("core evidence matrix binding changed");
        ValidateCellSpec(kCoreCells[i], false);
    }
}

void ValidateCellSpec(const CellSpec& cell, bool allow_fhe_ind) {
    if (cell.cell_id.empty() || cell.shape_id.empty())
        throw std::invalid_argument("cell id and shape id are required");
    if (cell.circuit == EvidenceCircuit::FheInd && !allow_fhe_ind)
        throw std::invalid_argument("FHE-IND is disabled for this operation");
    const bool fhe_ind = cell.circuit == EvidenceCircuit::FheInd;
    if ((fhe_ind ? (cell.k != 0 || cell.m != 0)
                 : (cell.k != 16 || cell.m != 16)) ||
        cell.set_size != 10 ||
        cell.target_jaccard_numerator != 1 ||
        cell.target_jaccard_denominator != 2 ||
        cell.realized_intersection != 7 || cell.realized_union != 13 ||
        cell.seed != 7 || cell.trials != 1 ||
        cell.calibration_repetitions != 1)
        throw std::invalid_argument("cell does not match frozen smoke workload");
    if (cell.circuit == EvidenceCircuit::OneHot &&
        cell.shape_id != "onehot-v1")
        throw std::invalid_argument("OneHot shape must be onehot-v1");
    if (cell.circuit == EvidenceCircuit::Sqrt &&
        cell.shape_id != "sqrt-b4-v1")
        throw std::invalid_argument("Sqrt shape must be sqrt-b4-v1");
    if (cell.circuit == EvidenceCircuit::FheInd &&
        cell.shape_id != "fhe-indicator-v1")
        throw std::invalid_argument("FHE-IND shape must be fhe-indicator-v1");
    if (cell.security != SecurityLevel::STD128 &&
        cell.security != SecurityLevel::STD192)
        throw std::invalid_argument("evidence security must be STD128/STD192");
}

bool operator==(const CandidateProposal& lhs, const CandidateProposal& rhs) {
    return std::tie(lhs.circuit, lhs.provisioned_depth,
                    lhs.scaling_mod_size) ==
           std::tie(rhs.circuit, rhs.provisioned_depth,
                    rhs.scaling_mod_size);
}

const std::vector<CandidateProposal>& CandidateProposals(
    EvidenceCircuit circuit) {
    static const std::vector<CandidateProposal> kOneHot = {
        {EvidenceCircuit::OneHot, 3, 40},
        {EvidenceCircuit::OneHot, 3, 45},
        {EvidenceCircuit::OneHot, 4, 40},
        {EvidenceCircuit::OneHot, 4, 45},
    };
    static const std::vector<CandidateProposal> kSqrt = {
        {EvidenceCircuit::Sqrt, 4, 40},
        {EvidenceCircuit::Sqrt, 4, 45},
    };
    static const std::vector<CandidateProposal> kEmpty;
    if (circuit == EvidenceCircuit::OneHot) return kOneHot;
    if (circuit == EvidenceCircuit::Sqrt) return kSqrt;
    return kEmpty;
}

const char* StatusName(CellStatus status) {
    switch (status) {
        case CellStatus::Measured:
            return "MEASURED";
        case CellStatus::SkippedPrecheck:
            return "SKIPPED_PRECHECK";
        case CellStatus::Error:
            return "ERROR";
        case CellStatus::DeferredFheIndNotReady:
            return "DEFERRED_FHE_IND_NOT_READY";
    }
    throw std::invalid_argument("unknown evidence status");
}

CellStatus ParseStatusName(const std::string& value) {
    for (CellStatus status : {CellStatus::Measured,
                              CellStatus::SkippedPrecheck,
                              CellStatus::Error,
                              CellStatus::DeferredFheIndNotReady}) {
        if (value == StatusName(status)) return status;
    }
    throw std::invalid_argument("unknown evidence status: " + value);
}

namespace {

bool IsPreflightReason(const std::string& reason) {
    static constexpr std::array<const char*, 3> prefixes = {{
        "realized_ring_dim bound=32768 observed=",
        "provisioned_depth bound=4 observed=",
        "log2(q) bound=240 observed=",
    }};
    if (reason.empty()) return false;
    size_t start = 0;
    while (start < reason.size()) {
        size_t end = reason.find(';', start);
        if (end == std::string::npos) end = reason.size();
        size_t first = start;
        while (first < end && reason[first] == ' ') ++first;
        const std::string part = reason.substr(first, end - first);
        bool matches = false;
        for (const char* prefix : prefixes) {
            const std::string prefix_string(prefix);
            if (part.rfind(prefix_string, 0) == 0 &&
                part.size() > prefix_string.size()) {
                const std::string observed = part.substr(prefix_string.size());
                try {
                    size_t parsed = 0;
                    const double value = std::stod(observed, &parsed);
                    matches = parsed == observed.size() && std::isfinite(value);
                } catch (const std::exception&) {
                    matches = false;
                }
                break;
            }
        }
        if (!matches) return false;
        start = end + 1;
    }
    return true;
}

std::string JoinReasons(const std::vector<std::string>& reasons) {
    std::ostringstream out;
    for (size_t i = 0; i < reasons.size(); ++i) {
        if (i != 0) out << "; ";
        out << reasons[i];
    }
    return out.str();
}

}  // namespace

void ValidateTerminalRecord(const TerminalRecord& record,
                            const CellSpec& expected) {
    ValidateCellSpec(expected);
    if (record.cell_id != expected.cell_id ||
        (record.status == CellStatus::Measured ? !record.reason.empty()
                                                : record.reason.empty()))
        throw std::invalid_argument("terminal record identity/reason mismatch");
    if (record.trials != expected.trials ||
        record.calibration_repetitions != expected.calibration_repetitions)
        throw std::invalid_argument("terminal record repetition mismatch");
    if (record.status == CellStatus::SkippedPrecheck &&
        (record.keygen_started || record.calibration_started ||
         record.e2e_started || !IsPreflightReason(record.reason)))
        throw std::invalid_argument("preflight skip occurred too late");
    if (record.status == CellStatus::SkippedPrecheck) {
        if (!record.preflight_caps_recorded)
            throw std::invalid_argument("preflight caps were not recorded");
        const PreflightDecision decision = EvaluatePreflight(record.preflight_caps);
        if (!decision.skipped || record.reason != JoinReasons(decision.reasons))
            throw std::invalid_argument("preflight skip does not match observed caps");
    }
    const bool fhe_ind = expected.circuit == EvidenceCircuit::FheInd;
    if (record.status == CellStatus::Measured &&
        (!record.keygen_started || record.calibration_started == fhe_ind ||
         !record.e2e_started))
        throw std::invalid_argument("measured record lacks execution stages");
    if (record.status == CellStatus::DeferredFheIndNotReady &&
        (expected.circuit != EvidenceCircuit::FheInd ||
         record.keygen_started || record.calibration_started ||
         record.e2e_started || record.reason.rfind("readiness", 0) != 0))
        throw std::invalid_argument("invalid FHE-IND deferred record");
}

bool operator==(const ContextTuple& lhs, const ContextTuple& rhs) {
    return std::tie(lhs.bfv_context_fingerprint, lhs.circuit, lhs.shape_id,
                    lhs.k, lhs.m,
                    lhs.sanitizer_profile, lhs.security,
                    lhs.requested_ring_dim, lhs.natural_ring_dim,
                    lhs.natural_depth,
                    lhs.realized_ring_dim, lhs.plaintext_modulus,
                    lhs.provisioned_depth, lhs.scaling_mod_size,
                    lhs.num_limbs, lhs.ordered_rns_moduli,
                    lhs.openfhe_version) ==
           std::tie(rhs.bfv_context_fingerprint, rhs.circuit, rhs.shape_id,
                    rhs.k, rhs.m,
                    rhs.sanitizer_profile, rhs.security,
                    rhs.requested_ring_dim, rhs.natural_ring_dim,
                    rhs.natural_depth,
                    rhs.realized_ring_dim, rhs.plaintext_modulus,
                    rhs.provisioned_depth, rhs.scaling_mod_size,
                    rhs.num_limbs, rhs.ordered_rns_moduli,
                    rhs.openfhe_version);
}

bool operator!=(const ContextTuple& lhs, const ContextTuple& rhs) {
    return !(lhs == rhs);
}

std::string CanonicalContextTuple(const ContextTuple& tuple) {
    if (tuple.bfv_context_fingerprint.empty() || tuple.circuit.empty() ||
        tuple.shape_id.empty() ||
        tuple.sanitizer_profile.empty() || tuple.requested_ring_dim == 0 ||
        tuple.natural_ring_dim == 0 ||
        tuple.natural_depth == 0 || tuple.realized_ring_dim == 0 ||
        tuple.plaintext_modulus == 0 || tuple.provisioned_depth == 0 ||
        tuple.scaling_mod_size == 0 || tuple.num_limbs == 0 ||
        tuple.ordered_rns_moduli.empty() ||
        tuple.openfhe_version.empty())
        throw std::invalid_argument("incomplete context tuple");
    if (tuple.num_limbs != tuple.ordered_rns_moduli.size())
        throw std::invalid_argument("RNS limb count does not match tuple");
    std::string bytes("piccard-std-security-context-v1");
    bytes.push_back('\0');
    AppendString(&bytes, tuple.bfv_context_fingerprint);
    AppendString(&bytes, tuple.circuit);
    AppendString(&bytes, tuple.shape_id);
    AppendU32(&bytes, tuple.k);
    AppendU32(&bytes, tuple.m);
    AppendString(&bytes, tuple.sanitizer_profile);
    AppendU32(&bytes, static_cast<uint32_t>(tuple.security));
    AppendU32(&bytes, tuple.requested_ring_dim);
    AppendU32(&bytes, tuple.natural_ring_dim);
    AppendU32(&bytes, tuple.natural_depth);
    AppendU32(&bytes, tuple.realized_ring_dim);
    AppendU64(&bytes, tuple.plaintext_modulus);
    AppendU32(&bytes, tuple.provisioned_depth);
    AppendU32(&bytes, tuple.scaling_mod_size);
    AppendU32(&bytes, tuple.num_limbs);
    AppendU32(&bytes, static_cast<uint32_t>(tuple.ordered_rns_moduli.size()));
    for (const auto& modulus : tuple.ordered_rns_moduli) {
        if (modulus.empty()) throw std::invalid_argument("empty RNS modulus");
        AppendString(&bytes, modulus);
    }
    AppendString(&bytes, tuple.openfhe_version);
    return bytes;
}

std::string ContextTupleSha256(const ContextTuple& tuple) {
    return Sha256Hex(CanonicalContextTuple(tuple));
}

PreflightDecision EvaluatePreflight(const PreflightCaps& caps) {
    if (!std::isfinite(caps.log_q_bits) || caps.log_q_bits < 0.0)
        throw std::invalid_argument("log_q_bits must be finite and non-negative");
    PreflightDecision result;
    if (caps.realized_ring_dim > 32768) {
        result.skipped = true;
        result.reasons.push_back("realized_ring_dim bound=32768 observed=" +
                                 std::to_string(caps.realized_ring_dim));
    }
    if (caps.provisioned_depth > 4) {
        result.skipped = true;
        result.reasons.push_back("provisioned_depth bound=4 observed=" +
                                 std::to_string(caps.provisioned_depth));
    }
    if (caps.log_q_bits > 240.0) {
        result.skipped = true;
        std::ostringstream out;
        out << "log2(q) bound=240 observed=" << std::setprecision(17)
            << caps.log_q_bits;
        result.reasons.push_back(out.str());
    }
    return result;
}

const char* CsvHeader() {
    return "cell_id,circuit,shape_id,security,k,m,set_size,target_jaccard,"
           "realized_intersection,realized_union,realized_jaccard,seed,trials,"
           "requested_ring_dim,natural_ring_dim,realized_ring_dim,natural_depth,"
           "provisioned_depth,scaling_mod_size,num_limbs,plaintext_modulus,"
           "log_q_bits,ordered_rns_moduli_sha256,openfhe_version,"
           "sanitizer_profile,transcript_stat_bits,max_queries,flood_margin_bits,"
           "eval_noise_bits,query_stat_bits,coefficient_stat_bits,flood_noise_bits,"
           "context_tuple_sha256,calibration_origin,calibration_artifact_sha256,"
           "setup_context_ms,setup_keygen_ms,phase_minhash_ms,phase_encode_ms,"
           "phase_encrypt_ms,phase_evaluate_ms,phase_flood_ms,phase_decrypt_ms,"
           "online_e2e_ms,full_e2e_ms,match_count,jaccard_estimate,status,reason\n";
}

namespace {

const char* KindName(ProvenanceKind kind) {
    switch (kind) {
        case ProvenanceKind::Piccard: return "piccard";
        case ProvenanceKind::Threshold: return "threshold";
        case ProvenanceKind::EncodingOnly: return "encoding-only";
        case ProvenanceKind::FheInd: return "fhe-ind";
    }
    throw std::invalid_argument("unknown provenance kind");
}

uint32_t DecimalBitLengthV2(const std::string& value) {
    if (value.empty() || value[0] == '0' ||
        value.find_first_not_of("0123456789") != std::string::npos) {
        throw std::invalid_argument("ordered RNS modulus is not canonical decimal");
    }
    std::string remaining = value;
    uint32_t bits = 0;
    while (remaining != "0") {
        std::string quotient;
        unsigned carry = 0;
        for (const char digit : remaining) {
            const unsigned value10 = carry * 10u +
                                     static_cast<unsigned>(digit - '0');
            const unsigned next = value10 / 2u;
            carry = value10 % 2u;
            if (!quotient.empty() || next != 0)
                quotient.push_back(static_cast<char>('0' + next));
        }
        remaining = quotient.empty() ? "0" : quotient;
        ++bits;
    }
    return bits;
}

std::string OptionalU32V2(const std::optional<uint32_t>& value) {
    return value.has_value() ? std::to_string(*value) : "";
}
std::string OptionalU64V2(const std::optional<uint64_t>& value) {
    return value.has_value() ? std::to_string(*value) : "";
}
std::string OptionalDoubleV2(const std::optional<double>& value) {
    if (!value.has_value()) return "";
    std::ostringstream output;
    output << std::setprecision(17) << *value;
    return output.str();
}

template <typename T>
std::string JsonNumberV2(T value) {
    std::ostringstream output;
    if constexpr (std::is_floating_point<T>::value)
        output << std::setprecision(std::numeric_limits<T>::max_digits10);
    output << value;
    return output.str();
}

std::string JsonEscapeV2(const std::string& value) {
    std::ostringstream output;
    output << '"';
    for (const unsigned char character : value) {
        switch (character) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20) {
                    output << "\\u" << std::hex << std::setw(4)
                           << std::setfill('0') << static_cast<unsigned>(character)
                           << std::dec << std::setfill(' ');
                } else {
                    output << static_cast<char>(character);
                }
        }
    }
    output << '"';
    return output.str();
}

std::string JoinV2(const std::vector<std::string>& values) {
    std::ostringstream output;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) output << ';';
        output << values[index];
    }
    return output.str();
}

std::string JoinBitsV2(const std::vector<uint32_t>& values) {
    std::ostringstream output;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) output << ';';
        output << values[index];
    }
    return output.str();
}

std::vector<std::string> SplitV2(const std::string& value, char delimiter) {
    if (value.empty()) return {};
    std::vector<std::string> result;
    size_t start = 0;
    while (true) {
        const size_t end = value.find(delimiter, start);
        result.push_back(value.substr(
            start, end == std::string::npos ? std::string::npos : end - start));
        if (end == std::string::npos) return result;
        start = end + 1;
    }
}

void AppendFramedV2(std::string* bytes, const std::string& value) {
    AppendU32(bytes, static_cast<uint32_t>(value.size()));
    bytes->append(value);
}

void AppendOptionalFramedV2(std::string* bytes, const std::string& value) {
    bytes->push_back(value.empty() ? '\0' : '\1');
    if (!value.empty()) AppendFramedV2(bytes, value);
}

struct JsonValueV2 {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool boolean = false;
    std::string scalar;
    std::vector<JsonValueV2> array;
    std::map<std::string, JsonValueV2> object;
};

class JsonParserV2 {
  public:
    explicit JsonParserV2(const std::string& input) : input_(input) {}

    JsonValueV2 Parse() {
        Skip();
        JsonValueV2 value = ParseValue();
        Skip();
        if (position_ != input_.size()) Fail("trailing JSON");
        return value;
    }

  private:
    const std::string& input_;
    size_t position_ = 0;

    [[noreturn]] void Fail(const char* message) const {
        throw std::invalid_argument(std::string("invalid provenance JSON: ") +
                                    message);
    }

    void Skip() {
        while (position_ < input_.size() &&
               std::isspace(static_cast<unsigned char>(input_[position_])))
            ++position_;
    }

    bool Consume(char expected) {
        Skip();
        if (position_ >= input_.size() || input_[position_] != expected)
            return false;
        ++position_;
        return true;
    }

    std::string ParseString() {
        Skip();
        if (!Consume('"')) Fail("string expected");
        std::string result;
        while (position_ < input_.size()) {
            const char character = input_[position_++];
            if (character == '"') return result;
            if (character != '\\') {
                if (static_cast<unsigned char>(character) < 0x20)
                    Fail("control character in string");
                result.push_back(character);
                continue;
            }
            if (position_ >= input_.size()) Fail("truncated escape");
            const char escaped = input_[position_++];
            switch (escaped) {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                default: Fail("unsupported string escape");
            }
        }
        Fail("unterminated string");
    }

    JsonValueV2 ParseValue() {
        Skip();
        if (position_ >= input_.size()) Fail("value expected");
        if (input_[position_] == '"') {
            JsonValueV2 result;
            result.type = JsonValueV2::Type::String;
            result.scalar = ParseString();
            return result;
        }
        if (input_[position_] == '{') return ParseObject();
        if (input_[position_] == '[') return ParseArray();
        const size_t begin = position_;
        while (position_ < input_.size() &&
               std::string(" ,}]\n\r\t").find(input_[position_]) ==
                   std::string::npos)
            ++position_;
        const std::string token = input_.substr(begin, position_ - begin);
        if (token == "null") {
            JsonValueV2 result;
            result.type = JsonValueV2::Type::Null;
            return result;
        }
        if (token == "true" || token == "false") {
            JsonValueV2 result;
            result.type = JsonValueV2::Type::Bool;
            result.boolean = token == "true";
            return result;
        }
        if (token.empty()) Fail("scalar expected");
        JsonValueV2 result;
        result.type = JsonValueV2::Type::Number;
        result.scalar = token;
        return result;
    }

    JsonValueV2 ParseObject() {
        JsonValueV2 result;
        result.type = JsonValueV2::Type::Object;
        if (!Consume('{')) Fail("object expected");
        Skip();
        if (Consume('}')) return result;
        while (true) {
            const std::string key = ParseString();
            if (!Consume(':')) Fail("object colon expected");
            if (!result.object.emplace(key, ParseValue()).second)
                Fail("duplicate object key");
            if (Consume('}')) return result;
            if (!Consume(',')) Fail("object comma expected");
        }
    }

    JsonValueV2 ParseArray() {
        JsonValueV2 result;
        result.type = JsonValueV2::Type::Array;
        if (!Consume('[')) Fail("array expected");
        Skip();
        if (Consume(']')) return result;
        while (true) {
            result.array.push_back(ParseValue());
            if (Consume(']')) return result;
            if (!Consume(',')) Fail("array comma expected");
        }
    }
};

const JsonValueV2& JsonFieldV2(const JsonValueV2& root, const char* key) {
    if (root.type != JsonValueV2::Type::Object)
        throw std::invalid_argument("provenance JSON root is not an object");
    const auto found = root.object.find(key);
    if (found == root.object.end())
        throw std::invalid_argument(std::string("missing provenance JSON field: ") + key);
    return found->second;
}

std::string JsonStringV2(const JsonValueV2& root, const char* key) {
    const auto& value = JsonFieldV2(root, key);
    if (value.type != JsonValueV2::Type::String)
        throw std::invalid_argument(std::string("provenance JSON field is not string: ") + key);
    return value.scalar;
}

std::optional<std::string> JsonOptionalStringV2(const JsonValueV2& root,
                                                const char* key) {
    const auto& value = JsonFieldV2(root, key);
    if (value.type == JsonValueV2::Type::Null) return std::nullopt;
    if (value.type != JsonValueV2::Type::String)
        throw std::invalid_argument(std::string("provenance JSON optional field is not string: ") + key);
    return value.scalar;
}

uint64_t ParseUnsignedV2(const std::string& value, const char* field) {
    if (value.empty() || value[0] == '-' || value[0] == '+' ||
        value.find_first_not_of("0123456789") != std::string::npos)
        throw std::invalid_argument(std::string("invalid provenance number: ") + field);
    size_t consumed = 0;
    unsigned long long parsed = 0;
    try { parsed = std::stoull(value, &consumed, 10); }
    catch (...) { throw std::invalid_argument(std::string("invalid provenance number: ") + field); }
    if (consumed != value.size())
        throw std::invalid_argument(std::string("invalid provenance number: ") + field);
    return static_cast<uint64_t>(parsed);
}

std::optional<uint64_t> JsonOptionalUnsignedV2(const JsonValueV2& root,
                                               const char* key) {
    const auto& value = JsonFieldV2(root, key);
    if (value.type == JsonValueV2::Type::Null) return std::nullopt;
    if (value.type != JsonValueV2::Type::Number)
        throw std::invalid_argument(std::string("provenance JSON number expected: ") + key);
    return ParseUnsignedV2(value.scalar, key);
}

std::optional<double> JsonOptionalDoubleV2(const JsonValueV2& root,
                                           const char* key) {
    const auto& value = JsonFieldV2(root, key);
    if (value.type == JsonValueV2::Type::Null) return std::nullopt;
    if (value.type != JsonValueV2::Type::Number)
        throw std::invalid_argument(std::string("provenance JSON number expected: ") + key);
    size_t consumed = 0;
    const double parsed = std::stod(value.scalar, &consumed);
    if (consumed != value.scalar.size() || !std::isfinite(parsed))
        throw std::invalid_argument(std::string("invalid provenance number: ") + key);
    return parsed;
}

std::vector<std::string> JsonStringArrayV2(const JsonValueV2& root,
                                           const char* key) {
    const auto& value = JsonFieldV2(root, key);
    if (value.type != JsonValueV2::Type::Array)
        throw std::invalid_argument(std::string("provenance JSON array expected: ") + key);
    std::vector<std::string> result;
    for (const auto& item : value.array) {
        if (item.type != JsonValueV2::Type::String)
            throw std::invalid_argument(std::string("provenance JSON array string expected: ") + key);
        result.push_back(item.scalar);
    }
    return result;
}

std::vector<uint32_t> JsonBitsArrayV2(const JsonValueV2& root,
                                      const char* key) {
    const auto& value = JsonFieldV2(root, key);
    if (value.type != JsonValueV2::Type::Array)
        throw std::invalid_argument(std::string("provenance JSON array expected: ") + key);
    std::vector<uint32_t> result;
    for (const auto& item : value.array) {
        if (item.type != JsonValueV2::Type::Number)
            throw std::invalid_argument(std::string("provenance JSON integer array expected: ") + key);
        const uint64_t parsed = ParseUnsignedV2(item.scalar, key);
        if (parsed == 0 || parsed > std::numeric_limits<uint32_t>::max())
            throw std::invalid_argument(std::string("provenance JSON integer out of range: ") + key);
        result.push_back(static_cast<uint32_t>(parsed));
    }
    return result;
}

std::string CsvEscapeV2(const std::string& value) {
    if (value.find_first_of(",\"\n\r") == std::string::npos) return value;
    std::string result = "\"";
    for (const char character : value) {
        if (character == '"') result += "\"\"";
        else result.push_back(character);
    }
    result.push_back('"');
    return result;
}

std::vector<std::string> CsvSplitV2(const std::string& line) {
    std::vector<std::string> result;
    std::string field;
    bool quoted = false;
    for (size_t index = 0; index < line.size(); ++index) {
        const char character = line[index];
        if (quoted) {
            if (character == '"' && index + 1 < line.size() &&
                line[index + 1] == '"') {
                field.push_back('"');
                ++index;
            } else if (character == '"') {
                quoted = false;
            } else {
                field.push_back(character);
            }
        } else if (character == '"' && field.empty()) {
            quoted = true;
        } else if (character == ',') {
            result.push_back(field);
            field.clear();
        } else {
            field.push_back(character);
        }
    }
    if (quoted) throw std::invalid_argument("unterminated provenance CSV quote");
    result.push_back(field);
    return result;
}

template <typename T>
std::optional<T> ParseOptionalIntegralV2(const std::string& value,
                                         const char* field) {
    if (value.empty()) return std::nullopt;
    const uint64_t parsed = ParseUnsignedV2(value, field);
    if constexpr (sizeof(T) == sizeof(uint32_t)) {
        if (parsed > std::numeric_limits<uint32_t>::max())
            throw std::invalid_argument(std::string("provenance field out of range: ") + field);
    }
    return static_cast<T>(parsed);
}

std::optional<double> ParseOptionalDoubleV2(const std::string& value,
                                            const char* field) {
    if (value.empty()) return std::nullopt;
    size_t consumed = 0;
    const double parsed = std::stod(value, &consumed);
    if (consumed != value.size() || !std::isfinite(parsed))
        throw std::invalid_argument(std::string("invalid provenance field: ") + field);
    return parsed;
}

}  // namespace

const char* ProvenanceKindName(ProvenanceKind kind) { return KindName(kind); }

ProvenanceKind ParseProvenanceKind(const std::string& value) {
    for (const auto kind : {ProvenanceKind::Piccard, ProvenanceKind::Threshold,
                            ProvenanceKind::EncodingOnly, ProvenanceKind::FheInd}) {
        if (value == KindName(kind)) return kind;
    }
    throw std::invalid_argument("unknown provenance kind: " + value);
}

bool CompleteProvenance::operator==(const CompleteProvenance& other) const {
    return std::tie(schema, kind, circuit, shape_id, security,
                    bfv_context_fingerprint, requested_ring_dim,
                    natural_ring_dim, provisioned_ring_dim, realized_ring_dim,
                    natural_depth, provisioned_depth, log_q_bits,
                    log_q_over_t_bits, plaintext_modulus, num_limbs,
                    scaling_mod_size, ordered_rns_moduli,
                    ordered_rns_limb_bits, openfhe_version, transcript_stat_bits,
                    max_queries, query_stat_bits, coefficient_stat_bits,
                    flood_margin_bits, eval_noise_bits, flood_noise_bits,
                    required_capacity_bits, flooding_assurance,
                    residual_capacity, context_tuple_sha256, status, reason,
                    legacy_encoding_note) ==
           std::tie(other.schema, other.kind, other.circuit, other.shape_id,
                    other.security, other.bfv_context_fingerprint,
                    other.requested_ring_dim, other.natural_ring_dim,
                    other.provisioned_ring_dim, other.realized_ring_dim,
                    other.natural_depth, other.provisioned_depth,
                    other.log_q_bits, other.log_q_over_t_bits,
                    other.plaintext_modulus, other.num_limbs,
                    other.scaling_mod_size, other.ordered_rns_moduli,
                    other.ordered_rns_limb_bits, other.openfhe_version,
                    other.transcript_stat_bits, other.max_queries,
                    other.query_stat_bits, other.coefficient_stat_bits,
                    other.flood_margin_bits, other.eval_noise_bits,
                    other.flood_noise_bits, other.required_capacity_bits,
                    other.flooding_assurance, other.residual_capacity,
                    other.context_tuple_sha256, other.status, other.reason,
                    other.legacy_encoding_note);
}

std::vector<uint32_t> OrderedRnsLimbBitSizes(
    const std::vector<std::string>& ordered_rns_moduli) {
    std::vector<uint32_t> result;
    result.reserve(ordered_rns_moduli.size());
    for (const auto& modulus : ordered_rns_moduli)
        result.push_back(DecimalBitLengthV2(modulus));
    return result;
}

uint64_t SumOrderedRnsLimbBits(const std::vector<uint32_t>& bits) {
    uint64_t result = 0;
    for (const uint32_t value : bits) {
        if (value == 0 || result > std::numeric_limits<uint64_t>::max() - value)
            throw std::invalid_argument("invalid ordered RNS limb bit size");
        result += value;
    }
    return result;
}

void ValidateCompleteProvenance(const CompleteProvenance& provenance) {
    if (provenance.schema != kCompleteProvenanceSchemaV2)
        throw std::invalid_argument("unsupported complete provenance schema");
    if (provenance.circuit.empty() || provenance.shape_id.empty() ||
        provenance.security.empty() || provenance.bfv_context_fingerprint.empty() ||
        provenance.openfhe_version.empty() || provenance.status.empty())
        throw std::invalid_argument("complete provenance identity is incomplete");
    if (!provenance.context_tuple_sha256.empty() &&
        (provenance.context_tuple_sha256.size() != 64 ||
         provenance.context_tuple_sha256.find_first_not_of("0123456789abcdef") !=
             std::string::npos))
        throw std::invalid_argument("invalid complete provenance tuple digest");
    if (provenance.kind == ProvenanceKind::EncodingOnly) {
        if (provenance.security != kNotApplicable ||
            provenance.bfv_context_fingerprint != kNotApplicable ||
            provenance.openfhe_version != kNotApplicable ||
            provenance.flooding_assurance != kNotApplicable ||
            provenance.residual_capacity.status != kResidualCapacityNotApplicable ||
            provenance.residual_capacity.definition != kResidualCapacityNotApplicable ||
            provenance.residual_capacity.bits.has_value() ||
            provenance.legacy_encoding_note.empty())
            throw std::invalid_argument("encoding-only provenance is not N/A");
        if (provenance.requested_ring_dim || provenance.natural_ring_dim ||
            provenance.provisioned_ring_dim || provenance.realized_ring_dim ||
            provenance.natural_depth || provenance.provisioned_depth ||
            provenance.log_q_bits || provenance.log_q_over_t_bits ||
            provenance.plaintext_modulus || provenance.num_limbs ||
            provenance.scaling_mod_size || !provenance.ordered_rns_moduli.empty() ||
            !provenance.ordered_rns_limb_bits.empty() ||
            provenance.transcript_stat_bits || provenance.max_queries ||
            provenance.query_stat_bits || provenance.coefficient_stat_bits ||
            provenance.flood_margin_bits || provenance.eval_noise_bits ||
            provenance.flood_noise_bits || provenance.required_capacity_bits)
            throw std::invalid_argument("encoding-only provenance contains FHE fields");
        return;
    }
    if (provenance.security != "TOY" && provenance.security != "STD128" &&
        provenance.security != "STD192" && provenance.security != "STD256")
        throw std::invalid_argument("unknown complete provenance security");
    const auto require_u32 = [](const std::optional<uint32_t>& value,
                                const char* field) {
        if (!value || *value == 0)
            throw std::invalid_argument(std::string("missing complete provenance field: ") + field);
    };
    require_u32(provenance.requested_ring_dim, "requested_ring_dim");
    require_u32(provenance.natural_ring_dim, "natural_ring_dim");
    require_u32(provenance.provisioned_ring_dim, "provisioned_ring_dim");
    require_u32(provenance.realized_ring_dim, "realized_ring_dim");
    require_u32(provenance.natural_depth, "natural_depth");
    require_u32(provenance.provisioned_depth, "provisioned_depth");
    require_u32(provenance.num_limbs, "num_limbs");
    require_u32(provenance.scaling_mod_size, "scaling_mod_size");
    if (*provenance.requested_ring_dim > *provenance.natural_ring_dim ||
        *provenance.natural_ring_dim > *provenance.provisioned_ring_dim ||
        *provenance.natural_depth > *provenance.provisioned_depth)
        throw std::invalid_argument("complete provenance dimensions are not monotone");
    if (!provenance.log_q_bits || !std::isfinite(*provenance.log_q_bits) ||
        *provenance.log_q_bits <= 0.0 || !provenance.log_q_over_t_bits ||
        !std::isfinite(*provenance.log_q_over_t_bits) ||
        !provenance.plaintext_modulus || *provenance.plaintext_modulus == 0)
        throw std::invalid_argument("complete provenance modulus fields are incomplete");
    const double expected_q_over_t =
        *provenance.log_q_bits -
        std::log2(static_cast<double>(*provenance.plaintext_modulus));
    if (std::abs(expected_q_over_t - *provenance.log_q_over_t_bits) > 1e-7)
        throw std::invalid_argument("complete provenance q/t mismatch");
    if (provenance.ordered_rns_moduli.size() != *provenance.num_limbs ||
        provenance.ordered_rns_limb_bits.size() != *provenance.num_limbs)
        throw std::invalid_argument("complete provenance RNS metadata is incomplete");
    if (OrderedRnsLimbBitSizes(provenance.ordered_rns_moduli) !=
        provenance.ordered_rns_limb_bits)
        throw std::invalid_argument("complete provenance RNS order/bit mismatch");
    if (std::llround(*provenance.log_q_bits) !=
        static_cast<long long>(SumOrderedRnsLimbBits(provenance.ordered_rns_limb_bits)))
        throw std::invalid_argument("complete provenance log_q/RNS mismatch");
    if (provenance.flooding_assurance != kNotApplicable &&
        provenance.flooding_assurance != kFloodingAssurancePiccard &&
        provenance.flooding_assurance != kFloodingAssuranceLegacyCoefficientLevel)
        throw std::invalid_argument("unknown flooding assurance taxonomy");
    if (provenance.kind == ProvenanceKind::Piccard &&
        provenance.flooding_assurance != kFloodingAssurancePiccard)
        throw std::invalid_argument("Piccard provenance assurance mismatch");
    if (provenance.kind == ProvenanceKind::Threshold &&
        provenance.flooding_assurance != kFloodingAssuranceLegacyCoefficientLevel)
        throw std::invalid_argument("Threshold provenance assurance mismatch");
    if (provenance.kind == ProvenanceKind::FheInd &&
        provenance.flooding_assurance != kNotApplicable)
        throw std::invalid_argument("FHE-IND provenance assurance mismatch");
    if (provenance.kind == ProvenanceKind::Piccard &&
        (!provenance.transcript_stat_bits || !provenance.max_queries ||
         !provenance.query_stat_bits || !provenance.coefficient_stat_bits ||
         !provenance.flood_margin_bits || !provenance.eval_noise_bits ||
         !provenance.flood_noise_bits || !provenance.required_capacity_bits))
        throw std::invalid_argument("Piccard sanitizer provenance is incomplete");
    if (provenance.kind != ProvenanceKind::Piccard &&
        (provenance.transcript_stat_bits || provenance.max_queries ||
         provenance.query_stat_bits || provenance.coefficient_stat_bits ||
         provenance.flood_margin_bits || provenance.eval_noise_bits ||
         provenance.flood_noise_bits || provenance.required_capacity_bits))
        throw std::invalid_argument("non-Piccard provenance contains sanitizer fields");
    if (provenance.residual_capacity.status ==
            kResidualCapacityNotExposedByOpenFhe &&
        provenance.residual_capacity.bits.has_value())
        throw std::invalid_argument("fabricated residual capacity");
    if (provenance.residual_capacity.status ==
            kResidualCapacityNotExposedByOpenFhe &&
        provenance.residual_capacity.definition != kResidualCapacityDefinition)
        throw std::invalid_argument("residual capacity definition mismatch");
    if (provenance.residual_capacity.status == kResidualCapacityMeasured) {
        if (!provenance.residual_capacity.bits ||
            !std::isfinite(*provenance.residual_capacity.bits) ||
            *provenance.residual_capacity.bits < 0.0)
            throw std::invalid_argument("measured residual capacity is invalid");
        if (provenance.residual_capacity.definition != kResidualCapacityDefinition)
            throw std::invalid_argument("measured residual capacity definition mismatch");
    } else if (provenance.residual_capacity.status !=
                   kResidualCapacityNotExposedByOpenFhe &&
               provenance.residual_capacity.status != kNotApplicable) {
        throw std::invalid_argument("unknown residual capacity status");
    }
}

std::string CompleteProvenanceCanonical(const CompleteProvenance& provenance) {
    ValidateCompleteProvenance(provenance);
    std::string bytes("piccard-std-security-parameter-provenance-v2");
    bytes.push_back('\0');
    AppendFramedV2(&bytes, KindName(provenance.kind));
    AppendFramedV2(&bytes, provenance.circuit);
    AppendFramedV2(&bytes, provenance.shape_id);
    AppendFramedV2(&bytes, provenance.security);
    AppendFramedV2(&bytes, provenance.bfv_context_fingerprint);
    const auto append_u32 = [&](const std::optional<uint32_t>& value) {
        AppendOptionalFramedV2(&bytes, OptionalU32V2(value));
    };
    const auto append_u64 = [&](const std::optional<uint64_t>& value) {
        AppendOptionalFramedV2(&bytes, OptionalU64V2(value));
    };
    const auto append_double = [&](const std::optional<double>& value) {
        AppendOptionalFramedV2(&bytes, OptionalDoubleV2(value));
    };
    append_u32(provenance.requested_ring_dim);
    append_u32(provenance.natural_ring_dim);
    append_u32(provenance.provisioned_ring_dim);
    append_u32(provenance.realized_ring_dim);
    append_u32(provenance.natural_depth);
    append_u32(provenance.provisioned_depth);
    append_double(provenance.log_q_bits);
    append_double(provenance.log_q_over_t_bits);
    append_u64(provenance.plaintext_modulus);
    append_u32(provenance.num_limbs);
    append_u32(provenance.scaling_mod_size);
    AppendU32(&bytes, static_cast<uint32_t>(provenance.ordered_rns_moduli.size()));
    for (const auto& value : provenance.ordered_rns_moduli) AppendFramedV2(&bytes, value);
    AppendU32(&bytes, static_cast<uint32_t>(provenance.ordered_rns_limb_bits.size()));
    for (const auto value : provenance.ordered_rns_limb_bits) AppendU32(&bytes, value);
    AppendFramedV2(&bytes, provenance.openfhe_version);
    for (const auto& value : {OptionalU32V2(provenance.transcript_stat_bits),
                              OptionalU64V2(provenance.max_queries),
                              OptionalU32V2(provenance.query_stat_bits),
                              OptionalU32V2(provenance.coefficient_stat_bits),
                              OptionalU32V2(provenance.flood_margin_bits),
                              OptionalU32V2(provenance.eval_noise_bits),
                              OptionalU32V2(provenance.flood_noise_bits),
                              OptionalU32V2(provenance.required_capacity_bits)})
        AppendOptionalFramedV2(&bytes, value);
    AppendFramedV2(&bytes, provenance.flooding_assurance);
    AppendFramedV2(&bytes, provenance.residual_capacity.status);
    AppendFramedV2(&bytes, provenance.residual_capacity.definition);
    append_double(provenance.residual_capacity.bits);
    AppendFramedV2(&bytes, provenance.context_tuple_sha256);
    AppendFramedV2(&bytes, provenance.status);
    AppendFramedV2(&bytes, provenance.reason);
    AppendFramedV2(&bytes, provenance.legacy_encoding_note);
    return bytes;
}

std::string CompleteProvenanceSha256(const CompleteProvenance& provenance) {
    return Sha256Hex(CompleteProvenanceCanonical(provenance));
}

std::string CompleteProvenanceJson(const CompleteProvenance& provenance) {
    ValidateCompleteProvenance(provenance);
    std::map<std::string, std::string> fields;
    const auto add_string = [&](const char* key, const std::string& value) {
        fields.emplace(key, JsonEscapeV2(value));
    };
    const auto add_optional_u32 = [&](const char* key,
                                      const std::optional<uint32_t>& value) {
        fields.emplace(key, value ? JsonNumberV2(*value) : "null");
    };
    const auto add_optional_u64 = [&](const char* key,
                                      const std::optional<uint64_t>& value) {
        fields.emplace(key, value ? JsonNumberV2(*value) : "null");
    };
    const auto add_optional_double = [&](const char* key,
                                         const std::optional<double>& value) {
        fields.emplace(key, value ? JsonNumberV2(*value) : "null");
    };
    const auto add_string_array = [&](const char* key,
                                      const std::vector<std::string>& values) {
        std::ostringstream output;
        output << '[';
        for (size_t index = 0; index < values.size(); ++index) {
            if (index != 0) output << ',';
            output << JsonEscapeV2(values[index]);
        }
        output << ']';
        fields.emplace(key, output.str());
    };
    const auto add_bits_array = [&](const char* key,
                                    const std::vector<uint32_t>& values) {
        std::ostringstream output;
        output << '[';
        for (size_t index = 0; index < values.size(); ++index) {
            if (index != 0) output << ',';
            output << values[index];
        }
        output << ']';
        fields.emplace(key, output.str());
    };
    add_string("schema", provenance.schema);
    add_string("kind", KindName(provenance.kind));
    add_string("circuit", provenance.circuit);
    add_string("shape_id", provenance.shape_id);
    add_string("security", provenance.security);
    add_string("bfv_context_fingerprint", provenance.bfv_context_fingerprint);
    add_optional_u32("requested_ring_dim", provenance.requested_ring_dim);
    add_optional_u32("natural_ring_dim", provenance.natural_ring_dim);
    add_optional_u32("provisioned_ring_dim", provenance.provisioned_ring_dim);
    add_optional_u32("realized_ring_dim", provenance.realized_ring_dim);
    add_optional_u32("natural_depth", provenance.natural_depth);
    add_optional_u32("provisioned_depth", provenance.provisioned_depth);
    add_optional_double("log_q_bits", provenance.log_q_bits);
    add_optional_double("log_q_over_t_bits", provenance.log_q_over_t_bits);
    add_optional_u64("plaintext_modulus", provenance.plaintext_modulus);
    add_optional_u32("num_limbs", provenance.num_limbs);
    add_optional_u32("scaling_mod_size", provenance.scaling_mod_size);
    add_string_array("ordered_rns_moduli", provenance.ordered_rns_moduli);
    add_bits_array("ordered_rns_limb_bits", provenance.ordered_rns_limb_bits);
    add_string("openfhe_version", provenance.openfhe_version);
    add_optional_u32("transcript_stat_bits", provenance.transcript_stat_bits);
    add_optional_u64("max_queries", provenance.max_queries);
    add_optional_u32("query_stat_bits", provenance.query_stat_bits);
    add_optional_u32("coefficient_stat_bits", provenance.coefficient_stat_bits);
    add_optional_u32("flood_margin_bits", provenance.flood_margin_bits);
    add_optional_u32("eval_noise_bits", provenance.eval_noise_bits);
    add_optional_u32("flood_noise_bits", provenance.flood_noise_bits);
    add_optional_u32("required_capacity_bits", provenance.required_capacity_bits);
    add_string("flooding_assurance", provenance.flooding_assurance);
    std::ostringstream residual;
    residual << '{' << JsonEscapeV2("bits") << ':'
             << (provenance.residual_capacity.bits
                     ? JsonNumberV2(*provenance.residual_capacity.bits)
                     : "null")
             << ',' << JsonEscapeV2("status") << ':'
             << JsonEscapeV2(provenance.residual_capacity.status)
             << ',' << JsonEscapeV2("definition") << ':'
             << JsonEscapeV2(provenance.residual_capacity.definition) << '}';
    fields.emplace("residual_capacity", residual.str());
    add_string("context_tuple_sha256", provenance.context_tuple_sha256);
    add_string("status", provenance.status);
    add_string("reason", provenance.reason);
    add_string("legacy_encoding_note", provenance.legacy_encoding_note);
    std::ostringstream output;
    output << '{';
    bool first = true;
    for (const auto& [key, value] : fields) {
        if (!first) output << ',';
        first = false;
        output << JsonEscapeV2(key) << ':' << value;
    }
    output << '}';
    return output.str() + '\n';
}

CompleteProvenance ParseCompleteProvenanceJson(const std::string& json) {
    const JsonValueV2 root = JsonParserV2(json).Parse();
    CompleteProvenance provenance;
    provenance.schema = JsonStringV2(root, "schema");
    provenance.kind = ParseProvenanceKind(JsonStringV2(root, "kind"));
    provenance.circuit = JsonStringV2(root, "circuit");
    provenance.shape_id = JsonStringV2(root, "shape_id");
    provenance.security = JsonStringV2(root, "security");
    provenance.bfv_context_fingerprint = JsonStringV2(root, "bfv_context_fingerprint");
    const auto u32 = [&](const char* key) -> std::optional<uint32_t> {
        const auto value = JsonOptionalUnsignedV2(root, key);
        if (!value) return std::nullopt;
        if (*value == 0 || *value > std::numeric_limits<uint32_t>::max())
            throw std::invalid_argument(std::string("provenance field out of range: ") + key);
        return static_cast<uint32_t>(*value);
    };
    provenance.requested_ring_dim = u32("requested_ring_dim");
    provenance.natural_ring_dim = u32("natural_ring_dim");
    provenance.provisioned_ring_dim = u32("provisioned_ring_dim");
    provenance.realized_ring_dim = u32("realized_ring_dim");
    provenance.natural_depth = u32("natural_depth");
    provenance.provisioned_depth = u32("provisioned_depth");
    provenance.log_q_bits = JsonOptionalDoubleV2(root, "log_q_bits");
    provenance.log_q_over_t_bits = JsonOptionalDoubleV2(root, "log_q_over_t_bits");
    const auto plaintext = JsonOptionalUnsignedV2(root, "plaintext_modulus");
    if (plaintext && *plaintext == 0)
        throw std::invalid_argument("plaintext modulus must be positive");
    provenance.plaintext_modulus = plaintext;
    provenance.num_limbs = u32("num_limbs");
    provenance.scaling_mod_size = u32("scaling_mod_size");
    provenance.ordered_rns_moduli = JsonStringArrayV2(root, "ordered_rns_moduli");
    provenance.ordered_rns_limb_bits = JsonBitsArrayV2(root, "ordered_rns_limb_bits");
    provenance.openfhe_version = JsonStringV2(root, "openfhe_version");
    provenance.transcript_stat_bits = u32("transcript_stat_bits");
    provenance.max_queries = JsonOptionalUnsignedV2(root, "max_queries");
    provenance.query_stat_bits = u32("query_stat_bits");
    provenance.coefficient_stat_bits = u32("coefficient_stat_bits");
    provenance.flood_margin_bits = u32("flood_margin_bits");
    provenance.eval_noise_bits = u32("eval_noise_bits");
    provenance.flood_noise_bits = u32("flood_noise_bits");
    provenance.required_capacity_bits = u32("required_capacity_bits");
    provenance.flooding_assurance = JsonStringV2(root, "flooding_assurance");
    const auto& residual = JsonFieldV2(root, "residual_capacity");
    provenance.residual_capacity.status = JsonStringV2(residual, "status");
    provenance.residual_capacity.bits = JsonOptionalDoubleV2(residual, "bits");
    provenance.residual_capacity.definition = JsonStringV2(residual, "definition");
    provenance.context_tuple_sha256 = JsonStringV2(root, "context_tuple_sha256");
    provenance.status = JsonStringV2(root, "status");
    provenance.reason = JsonStringV2(root, "reason");
    provenance.legacy_encoding_note = JsonStringV2(root, "legacy_encoding_note");
    ValidateCompleteProvenance(provenance);
    return provenance;
}

const char* CompleteProvenanceCsvHeader() {
    return "schema,kind,circuit,shape_id,security,bfv_context_fingerprint,"
           "requested_ring_dim,natural_ring_dim,provisioned_ring_dim,realized_ring_dim,"
           "natural_depth,provisioned_depth,log_q_bits,log_q_over_t_bits,plaintext_modulus,"
           "num_limbs,scaling_mod_size,ordered_rns_moduli,ordered_rns_limb_bits,openfhe_version,"
           "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
           "flood_margin_bits,eval_noise_bits,flood_noise_bits,required_capacity_bits,"
           "flooding_assurance,residual_capacity_status,residual_capacity_definition,residual_capacity_bits,"
           "context_tuple_sha256,status,reason,legacy_encoding_note\n";
}

std::string CompleteProvenanceCsvRow(const CompleteProvenance& provenance) {
    ValidateCompleteProvenance(provenance);
    const std::vector<std::string> values = {
        provenance.schema, KindName(provenance.kind), provenance.circuit,
        provenance.shape_id, provenance.security, provenance.bfv_context_fingerprint,
        OptionalU32V2(provenance.requested_ring_dim),
        OptionalU32V2(provenance.natural_ring_dim),
        OptionalU32V2(provenance.provisioned_ring_dim),
        OptionalU32V2(provenance.realized_ring_dim),
        OptionalU32V2(provenance.natural_depth),
        OptionalU32V2(provenance.provisioned_depth),
        OptionalDoubleV2(provenance.log_q_bits),
        OptionalDoubleV2(provenance.log_q_over_t_bits),
        OptionalU64V2(provenance.plaintext_modulus),
        OptionalU32V2(provenance.num_limbs), OptionalU32V2(provenance.scaling_mod_size),
        JoinV2(provenance.ordered_rns_moduli), JoinBitsV2(provenance.ordered_rns_limb_bits),
        provenance.openfhe_version, OptionalU32V2(provenance.transcript_stat_bits),
        OptionalU64V2(provenance.max_queries), OptionalU32V2(provenance.query_stat_bits),
        OptionalU32V2(provenance.coefficient_stat_bits),
        OptionalU32V2(provenance.flood_margin_bits), OptionalU32V2(provenance.eval_noise_bits),
        OptionalU32V2(provenance.flood_noise_bits), OptionalU32V2(provenance.required_capacity_bits),
        provenance.flooding_assurance, provenance.residual_capacity.status,
        provenance.residual_capacity.definition,
        OptionalDoubleV2(provenance.residual_capacity.bits), provenance.context_tuple_sha256,
        provenance.status, provenance.reason, provenance.legacy_encoding_note};
    std::ostringstream output;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) output << ',';
        output << CsvEscapeV2(values[index]);
    }
    output << '\n';
    return output.str();
}

CompleteProvenance ParseCompleteProvenanceCsv(const std::string& csv) {
    const std::string header = CompleteProvenanceCsvHeader();
    if (csv.rfind(header, 0) != 0)
        throw std::invalid_argument("complete provenance CSV header mismatch");
    const std::string rest = csv.substr(header.size());
    if (rest.empty() || rest.back() != '\n' || rest.find('\n') != rest.size() - 1)
        throw std::invalid_argument("complete provenance CSV row count mismatch");
    const auto values = CsvSplitV2(rest.substr(0, rest.size() - 1));
    const auto headers = CsvSplitV2(header.substr(0, header.size() - 1));
    if (values.size() != headers.size())
        throw std::invalid_argument("complete provenance CSV width mismatch");
    std::map<std::string, std::string> fields;
    for (size_t index = 0; index < headers.size(); ++index)
        fields.emplace(headers[index], values[index]);
    const auto field = [&](const char* key) -> const std::string& {
        return fields.at(key);
    };
    CompleteProvenance provenance;
    provenance.schema = field("schema");
    provenance.kind = ParseProvenanceKind(field("kind"));
    provenance.circuit = field("circuit");
    provenance.shape_id = field("shape_id");
    provenance.security = field("security");
    provenance.bfv_context_fingerprint = field("bfv_context_fingerprint");
    provenance.requested_ring_dim = ParseOptionalIntegralV2<uint32_t>(field("requested_ring_dim"), "requested_ring_dim");
    provenance.natural_ring_dim = ParseOptionalIntegralV2<uint32_t>(field("natural_ring_dim"), "natural_ring_dim");
    provenance.provisioned_ring_dim = ParseOptionalIntegralV2<uint32_t>(field("provisioned_ring_dim"), "provisioned_ring_dim");
    provenance.realized_ring_dim = ParseOptionalIntegralV2<uint32_t>(field("realized_ring_dim"), "realized_ring_dim");
    provenance.natural_depth = ParseOptionalIntegralV2<uint32_t>(field("natural_depth"), "natural_depth");
    provenance.provisioned_depth = ParseOptionalIntegralV2<uint32_t>(field("provisioned_depth"), "provisioned_depth");
    provenance.log_q_bits = ParseOptionalDoubleV2(field("log_q_bits"), "log_q_bits");
    provenance.log_q_over_t_bits = ParseOptionalDoubleV2(field("log_q_over_t_bits"), "log_q_over_t_bits");
    provenance.plaintext_modulus = ParseOptionalIntegralV2<uint64_t>(field("plaintext_modulus"), "plaintext_modulus");
    provenance.num_limbs = ParseOptionalIntegralV2<uint32_t>(field("num_limbs"), "num_limbs");
    provenance.scaling_mod_size = ParseOptionalIntegralV2<uint32_t>(field("scaling_mod_size"), "scaling_mod_size");
    provenance.ordered_rns_moduli = SplitV2(field("ordered_rns_moduli"), ';');
    for (const auto& value : SplitV2(field("ordered_rns_limb_bits"), ';'))
        provenance.ordered_rns_limb_bits.push_back(static_cast<uint32_t>(ParseUnsignedV2(value, "ordered_rns_limb_bits")));
    provenance.openfhe_version = field("openfhe_version");
    provenance.transcript_stat_bits = ParseOptionalIntegralV2<uint32_t>(field("transcript_stat_bits"), "transcript_stat_bits");
    provenance.max_queries = ParseOptionalIntegralV2<uint64_t>(field("max_queries"), "max_queries");
    provenance.query_stat_bits = ParseOptionalIntegralV2<uint32_t>(field("query_stat_bits"), "query_stat_bits");
    provenance.coefficient_stat_bits = ParseOptionalIntegralV2<uint32_t>(field("coefficient_stat_bits"), "coefficient_stat_bits");
    provenance.flood_margin_bits = ParseOptionalIntegralV2<uint32_t>(field("flood_margin_bits"), "flood_margin_bits");
    provenance.eval_noise_bits = ParseOptionalIntegralV2<uint32_t>(field("eval_noise_bits"), "eval_noise_bits");
    provenance.flood_noise_bits = ParseOptionalIntegralV2<uint32_t>(field("flood_noise_bits"), "flood_noise_bits");
    provenance.required_capacity_bits = ParseOptionalIntegralV2<uint32_t>(field("required_capacity_bits"), "required_capacity_bits");
    provenance.flooding_assurance = field("flooding_assurance");
    provenance.residual_capacity.status = field("residual_capacity_status");
    provenance.residual_capacity.definition = field("residual_capacity_definition");
    provenance.residual_capacity.bits = ParseOptionalDoubleV2(field("residual_capacity_bits"), "residual_capacity_bits");
    provenance.context_tuple_sha256 = field("context_tuple_sha256");
    provenance.status = field("status");
    provenance.reason = field("reason");
    provenance.legacy_encoding_note = field("legacy_encoding_note");
    ValidateCompleteProvenance(provenance);
    return provenance;
}

}  // namespace std_evidence
}  // namespace piccard
