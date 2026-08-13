#pragma once

#include "util/params.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace piccard {
namespace std_evidence {

// Deliberately smaller than piccard::Circuit: Threshold cannot be constructed
// by this evidence path.
enum class EvidenceCircuit : uint8_t {
    OneHot = 0,
    Sqrt = 1,
    FheInd = 2,
    Threshold = 3,
};

const char* CircuitName(EvidenceCircuit circuit);
const char* SecurityName(SecurityLevel security);
SecurityLevel ParseSecurityName(const std::string& value);

struct CellSpec {
    std::string cell_id;
    EvidenceCircuit circuit = EvidenceCircuit::OneHot;
    std::string shape_id;
    SecurityLevel security = SecurityLevel::STD128;
    uint32_t k = 16;
    uint32_t m = 16;
    uint32_t set_size = 10;
    uint32_t target_jaccard_numerator = 1;
    uint32_t target_jaccard_denominator = 2;
    uint32_t realized_intersection = 7;
    uint32_t realized_union = 13;
    uint64_t seed = 7;
    uint32_t trials = 1;
    uint32_t calibration_repetitions = 1;
};

bool operator==(const CellSpec& lhs, const CellSpec& rhs);
bool operator!=(const CellSpec& lhs, const CellSpec& rhs);

const std::vector<CellSpec>& CoreCells();
const std::vector<CellSpec>& FheIndCells();
void ValidateCoreMatrix();
void ValidateCellSpec(const CellSpec& cell, bool allow_fhe_ind = true);

struct CandidateProposal {
    EvidenceCircuit circuit = EvidenceCircuit::OneHot;
    uint32_t provisioned_depth = 0;
    uint32_t scaling_mod_size = 0;
};

bool operator==(const CandidateProposal& lhs, const CandidateProposal& rhs);
const std::vector<CandidateProposal>& CandidateProposals(
    EvidenceCircuit circuit);

enum class CellStatus : uint8_t {
    Measured = 0,
    SkippedPrecheck = 1,
    Error = 2,
    DeferredFheIndNotReady = 3,
};

const char* StatusName(CellStatus status);
CellStatus ParseStatusName(const std::string& value);

struct PreflightCaps {
    uint32_t realized_ring_dim = 0;
    uint32_t provisioned_depth = 0;
    double log_q_bits = 0.0;
};

struct TerminalRecord {
    std::string cell_id;
    CellStatus status = CellStatus::Error;
    std::string reason;
    bool keygen_started = false;
    bool calibration_started = false;
    bool e2e_started = false;
    uint32_t trials = 0;
    uint32_t calibration_repetitions = 0;
    bool preflight_caps_recorded = false;
    PreflightCaps preflight_caps;
};

void ValidateTerminalRecord(const TerminalRecord& record,
                            const CellSpec& expected);

// A complete context identity. RNS strings are decimal OpenFHE tower moduli
// in exactly the live order returned by OpenFHE.
struct ContextTuple {
    std::string bfv_context_fingerprint;
    std::string circuit;
    std::string shape_id;
    uint32_t k = 0;
    uint32_t m = 0;
    std::string sanitizer_profile;
    SecurityLevel security = SecurityLevel::STD128;
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
};

bool operator==(const ContextTuple& lhs, const ContextTuple& rhs);
bool operator!=(const ContextTuple& lhs, const ContextTuple& rhs);

std::string CanonicalContextTuple(const ContextTuple& tuple);
std::string ContextTupleSha256(const ContextTuple& tuple);

struct PreflightDecision {
    bool skipped = false;
    std::vector<std::string> reasons;
};

PreflightDecision EvaluatePreflight(const PreflightCaps& caps);

const char* CsvHeader();

// Successor provenance contract.  The v1 ContextTuple/CsvHeader above is
// deliberately retained byte-for-byte for existing evidence and Work #5.
inline constexpr const char* kCompleteProvenanceSchemaV2 =
    "piccard-std-security-parameter-provenance-v2";
inline constexpr const char* kNotApplicable = "not-applicable";
inline constexpr const char* kFloodingAssurancePiccard =
    "empirical-phase-statistical+ciphertext-computational";
inline constexpr const char* kFloodingAssuranceLegacyCoefficientLevel =
    "legacy-coefficient-level";
inline constexpr const char* kResidualCapacityMeasured = "measured";
inline constexpr const char* kResidualCapacityNotExposedByOpenFhe =
    "not-exposed-by-openfhe";
inline constexpr const char* kResidualCapacityNotApplicable =
    "not-applicable";
inline constexpr const char* kResidualCapacityDefinition =
    "log2(q/t)-required_flood_budget_bits";

enum class ProvenanceKind : uint8_t {
    Piccard = 0,
    Threshold = 1,
    EncodingOnly = 2,
    FheInd = 3,
};

const char* ProvenanceKindName(ProvenanceKind kind);
ProvenanceKind ParseProvenanceKind(const std::string& value);

struct ResidualCapacityEvidence {
    std::string status = kResidualCapacityNotApplicable;
    std::optional<double> bits;
    std::string definition = kResidualCapacityNotApplicable;
    bool operator==(const ResidualCapacityEvidence& other) const {
        return status == other.status && bits == other.bits &&
               definition == other.definition;
    }
};

struct CompleteProvenance {
    std::string schema = kCompleteProvenanceSchemaV2;
    ProvenanceKind kind = ProvenanceKind::Piccard;
    std::string circuit;
    std::string shape_id;
    std::string security;
    std::string bfv_context_fingerprint;

    std::optional<uint32_t> requested_ring_dim;
    std::optional<uint32_t> natural_ring_dim;
    std::optional<uint32_t> provisioned_ring_dim;
    std::optional<uint32_t> realized_ring_dim;
    std::optional<uint32_t> natural_depth;
    std::optional<uint32_t> provisioned_depth;
    std::optional<double> log_q_bits;
    std::optional<double> log_q_over_t_bits;
    std::optional<uint64_t> plaintext_modulus;
    std::optional<uint32_t> num_limbs;
    std::optional<uint32_t> scaling_mod_size;
    std::vector<std::string> ordered_rns_moduli;
    std::vector<uint32_t> ordered_rns_limb_bits;
    std::string openfhe_version;

    std::optional<uint32_t> transcript_stat_bits;
    std::optional<uint64_t> max_queries;
    std::optional<uint32_t> query_stat_bits;
    std::optional<uint32_t> coefficient_stat_bits;
    std::optional<uint32_t> flood_margin_bits;
    std::optional<uint32_t> eval_noise_bits;
    std::optional<uint32_t> flood_noise_bits;
    std::optional<uint32_t> required_capacity_bits;
    std::string flooding_assurance = kNotApplicable;
    ResidualCapacityEvidence residual_capacity;
    std::string context_tuple_sha256;
    std::string status = "MEASURED";
    std::string reason;
    std::string legacy_encoding_note;

    bool operator==(const CompleteProvenance& other) const;
    bool operator!=(const CompleteProvenance& other) const {
        return !(*this == other);
    }
};

std::vector<uint32_t> OrderedRnsLimbBitSizes(
    const std::vector<std::string>& ordered_rns_moduli);
uint64_t SumOrderedRnsLimbBits(const std::vector<uint32_t>& bits);
void ValidateCompleteProvenance(const CompleteProvenance& provenance);
std::string CompleteProvenanceCanonical(const CompleteProvenance& provenance);
std::string CompleteProvenanceSha256(const CompleteProvenance& provenance);
std::string CompleteProvenanceJson(const CompleteProvenance& provenance);
CompleteProvenance ParseCompleteProvenanceJson(const std::string& json);
inline CompleteProvenance ParseCompleteProvenanceJsonV2(
    const std::string& json) {
    return ParseCompleteProvenanceJson(json);
}
const char* CompleteProvenanceCsvHeader();
std::string CompleteProvenanceCsvRow(const CompleteProvenance& provenance);
CompleteProvenance ParseCompleteProvenanceCsv(const std::string& csv);
inline std::string CompleteProvenanceCsvHeaderString() {
    return CompleteProvenanceCsvHeader();
}
inline std::string CompleteProvenanceCsvRowString(
    const CompleteProvenance& provenance) {
    return CompleteProvenanceCsvRow(provenance);
}

}  // namespace std_evidence
}  // namespace piccard
