#pragma once

#include "util/params.h"

#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
namespace std_evidence {

// Deliberately smaller than piccard::Circuit: Threshold cannot be constructed
// by this evidence path.
enum class EvidenceCircuit : uint8_t { OneHot = 0, Sqrt = 1, FheInd = 2 };

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

}  // namespace std_evidence
}  // namespace piccard
