#include "std_security_evidence_schema.h"

#include <openssl/evp.h>

#include <cmath>
#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <tuple>

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

}  // namespace std_evidence
}  // namespace piccard
