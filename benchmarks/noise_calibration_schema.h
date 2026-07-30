#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {
namespace noise_calibration {

/**
 * @brief Strictly parsed command-line inputs for pre-threshold evidence.
 */
struct EvidenceOptions {
    bool pre_threshold = false;
    bool coverage = false;
    bool smoke = false;
    std::string profile_manifest;
    std::string profile;
    std::string key_id;
    std::string circuit;
    std::string security;
    std::vector<uint32_t> scaling_mod_grid;
    uint32_t max_depth_delta = 0;
    std::vector<uint32_t> ring_candidates;
    uint32_t timeout_seconds = 0;
    uint32_t transcript_stat_bits = 0;
    uint64_t max_queries = 0;
    uint32_t margin = 0;
    uint32_t reps = 0;
    uint64_t seed = 0;
};

/**
 * @brief One circuit/security pair covered by the pre-threshold runner.
 */
struct CoverageEntry {
    std::string circuit;
    std::string security;

    bool operator==(const CoverageEntry& other) const {
        return circuit == other.circuit && security == other.security;
    }
};

/**
 * @brief Canonical outcome for one detail or aggregate evidence row.
 */
enum class StatusCode {
    Ok,
    Saturated,
    DecryptFail,
    ContextError,
    Timeout,
    ProcessError,
};

/**
 * @brief One fresh-encryption measurement in a candidate detail CSV.
 */
struct DetailRow {
    std::string profile;
    std::string key_id;
    std::string candidate_id;
    std::string circuit;
    std::string shape_id;
    std::string security;
    uint32_t consumer_k = 0;
    uint32_t consumer_m = 0;
    std::string pattern;
    uint32_t rep_index = 0;
    uint64_t rep_seed = 0;
    std::optional<uint32_t> requested_ring_dim;
    std::optional<uint32_t> natural_ring_dim;
    std::optional<uint32_t> ring_dim_calibrated;
    std::optional<uint32_t> realized_ring_dim;
    std::optional<double> ring_growth_factor;
    std::optional<uint32_t> natural_depth;
    std::optional<uint32_t> provisioned_depth;
    std::optional<uint32_t> scaling_mod_size;
    std::optional<uint32_t> num_limbs;
    std::optional<uint64_t> plaintext_mod;
    std::optional<double> log_q;
    std::optional<double> log_delta;
    std::optional<double> eval_noise_bits;
    std::optional<double> headroom_bits;
    std::optional<uint64_t> max_queries;
    std::optional<uint32_t> query_stat_bits;
    std::optional<uint32_t> coefficient_stat_bits;
    std::optional<uint32_t> flood_margin_bits;
    std::optional<uint32_t> flood_noise_bits;
    bool decrypt_ok = false;
    bool saturated = false;
    std::optional<uint64_t> ct_bytes;
    std::string openfhe_version;
    std::string source_commit;
    StatusCode status_code = StatusCode::Ok;
    std::string error_message;
};

/**
 * @brief Candidate-level reductions and provenance for the aggregate CSV.
 */
struct AggregateRow {
    std::string profile;
    std::string circuit;
    std::string shape_id;
    std::string security;
    uint32_t consumer_count = 0;
    std::string consumer_set_sha256;
    std::optional<uint32_t> worst_consumer_k;
    std::optional<uint32_t> worst_consumer_m;
    uint32_t pattern_count = 0;
    uint32_t repetitions_per_pattern = 0;
    uint64_t detail_row_count = 0;
    std::string detail_sha256;
    uint64_t seed = 0;
    std::optional<uint32_t> requested_ring_dim;
    std::optional<uint32_t> natural_ring_dim;
    std::optional<uint32_t> realized_ring_dim;
    std::optional<double> ring_growth_factor;
    std::optional<uint32_t> ring_dim_calibrated;
    std::optional<uint32_t> natural_depth;
    std::optional<uint32_t> provisioned_depth;
    std::optional<uint32_t> scaling_mod_size;
    std::optional<uint32_t> num_limbs;
    std::optional<uint64_t> plaintext_mod;
    std::optional<double> log_q;
    std::optional<double> log_delta;
    std::optional<double> eval_noise_bits;
    std::optional<double> headroom_bits;
    std::optional<uint64_t> max_queries;
    std::optional<uint32_t> query_stat_bits;
    std::optional<uint32_t> coefficient_stat_bits;
    std::optional<uint32_t> flood_margin_bits;
    std::optional<uint32_t> flood_noise_bits;
    bool decrypt_ok = false;
    bool saturated = false;
    std::optional<uint64_t> ct_bytes;
    std::string openfhe_version;
    std::string source_commit;
    StatusCode status_code = StatusCode::Ok;
    std::string error_message;
    std::string consumer_results_sha256;
};

/** @brief Parses and validates pre-threshold evidence arguments. */
EvidenceOptions ParseEvidenceOptions(const std::vector<std::string>& args);

/** @brief Returns the exact OneHot/Sqrt STD128/STD192 coverage matrix. */
std::vector<CoverageEntry> PreThresholdCoverageMatrix();

/** @brief Returns the canonical aggregate CSV header. */
const std::string& AggregateCsvHeader();

/** @brief Returns the canonical detail CSV header. */
const std::string& DetailCsvHeader();

/** @brief Serializes one aggregate row with RFC 4180 escaping. */
std::string SerializeAggregateCsvRow(const AggregateRow& row);

/** @brief Serializes one detail row with RFC 4180 escaping. */
std::string SerializeDetailCsvRow(const DetailRow& row);

/** @brief Sorts detail rows by the canonical evidence tuple. */
std::vector<DetailRow> CanonicalizeDetailRows(std::vector<DetailRow> rows);

/** @brief Computes a lowercase SHA-256 digest. */
std::string Sha256Hex(const std::string& bytes);

/** @brief Hashes the detail header and canonical rows for one candidate. */
std::string DetailSha256(const std::vector<DetailRow>& rows);

/** @brief Reduces detail evidence into one canonical candidate aggregate. */
AggregateRow ReduceCandidate(
    AggregateRow aggregate,
    const std::vector<DetailRow>& details,
    uint32_t transcript_stat_bits);

/** @brief Computes the required detail-row count without overflow. */
uint64_t ExpectedDetailRowCount(
    uint32_t consumer_count,
    uint32_t pattern_count,
    uint32_t repetitions_per_pattern);

/** @brief Checks the exact consumer_count * 3 * 5 evidence invariant. */
bool HasCompleteEvidence(const AggregateRow& row);

/** @brief Returns the canonical uppercase spelling of a status. */
const char* StatusName(StatusCode status);

/** @brief Returns the OpenFHE version supplied by the linked package. */
std::string CurrentOpenFHEVersion();

/** @brief Returns the source commit embedded at configure time. */
std::string EmbeddedSourceCommit();

}  // namespace noise_calibration
}  // namespace benchmark
}  // namespace piccard
