#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Exact non-negative rational whose components fit the wire BE64s. */
struct ExactRational {
    uint64_t numerator = 0;
    uint64_t denominator = 1;
};

bool operator==(const ExactRational& lhs, const ExactRational& rhs);
bool operator!=(const ExactRational& lhs, const ExactRational& rhs);

/** @brief Parse a non-exponent decimal into a reduced exact rational. */
ExactRational ParseExactDecimal(const std::string& text);

enum class TrialKind : uint8_t { Warmup = 0, Timing = 1, Accuracy = 2 };

/** @brief Family-qualified row kind required by reviewer comparison suites. */
std::string ReviewMeasurementKind(const std::string& method, TrialKind kind);

/** @brief Method-conditioned applicability for one emitted CSV aggregate row. */
struct ReviewMethodRowPolicy {
    std::optional<uint64_t> k;
    std::optional<uint64_t> m;
    std::optional<uint64_t> hash_seed;
    std::string hash_randomness;
};

/** @brief Resolve applicability and CRS cells for one method/arm row. */
ReviewMethodRowPolicy ResolveReviewMethodRowPolicy(
    const std::string& method,
    TrialKind kind,
    uint64_t requested_k,
    uint64_t requested_m,
    uint64_t timing_hash_seed);

/** @brief Serialize a numeric field, using an empty cell for numeric N/A. */
std::string ReviewNumericCell(double value);

/** @brief One immutable canonical trial supplied by reference to every adapter. */
struct ComparisonTrial {
    TrialKind kind = TrialKind::Warmup;
    uint32_t index = 0;
    uint64_t trial_seed = 0;
    uint64_t hash_seed = 0;
    std::vector<uint64_t> set_a;
    std::vector<uint64_t> set_b;
    uint64_t exact_intersection = 0;
    uint64_t exact_union = 0;
    ExactRational exact_jaccard;
};

/** @brief All values frozen into a piccard-review-workload-v1 manifest. */
struct WorkloadSpec {
    std::string suite;
    std::string profile_id;
    uint64_t root_seed = 0;
    uint64_t k = 0;
    uint64_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    ExactRational target_jaccard;
    std::vector<std::string> methods;
    uint32_t timing_trials = 0;
    uint32_t accuracy_trials = 0;
};

/** @brief Canonical workload bytes plus regenerated, immutable trial records. */
class ComparisonWorkload {
public:
    /** @brief Generate canonical records and their complete binary encoding. */
    static ComparisonWorkload Generate(const WorkloadSpec& spec);
    /** @brief Reparse bytes, regenerate all derived fields, and compare exactly. */
    static ComparisonWorkload ParseAndVerify(const std::vector<uint8_t>& bytes);

    const WorkloadSpec& Spec() const { return spec_; }
    const std::vector<ComparisonTrial>& Records() const { return records_; }
    const std::vector<uint8_t>& Bytes() const { return bytes_; }
    const std::array<uint8_t, 32>& ManifestSha256() const { return digest_; }
    const std::string& ManifestSha256Hex() const { return digest_hex_; }
    const std::string& WorkloadId() const { return workload_id_; }

    /** @brief Derive the trial-seed rotation of the manifest method list. */
    std::vector<std::string> ExecutionOrder(
        const ComparisonTrial& record) const;

    /** @brief Atomically publish to a new .bin path; existing paths fail. */
    void WriteNew(const std::filesystem::path& path) const;

private:
    WorkloadSpec spec_;
    std::vector<ComparisonTrial> records_;
    std::vector<uint8_t> bytes_;
    std::array<uint8_t, 32> digest_{};
    std::string digest_hex_;
    std::string workload_id_;
};

/**
 * @brief SHA-256 of only the canonical ordered ComparisonTrial payload.
 *
 * This is deliberately separate from the piccard-review-workload-v1 manifest
 * digest: Work #5 method groups have distinct suite metadata and method lists,
 * while equal trial records must remain joinable across those groups.
 */
std::string TrialPayloadSha256(const ComparisonWorkload& workload);

/** @brief Minimal group identity used by Phase-4 strict aggregate validation. */
struct AggregateIdentity {
    std::string method;
    std::string measurement_kind;
    std::string evidence_arm;
    std::string workload_id;
    std::string workload_manifest_sha256;
    uint64_t k = 0;
    uint64_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint32_t timing_trials = 0;
    uint32_t accuracy_trials = 0;
    uint32_t aggregate_trials = 0;
    std::string precomputation_mode;
    bool exact_estimator = false;
    double estimator_error = 0.0;
};

/** @brief Return the exact method-kind rows required by the manifest suite. */
std::vector<AggregateIdentity> ExpectedAggregateIdentities(
    const ComparisonWorkload& workload);

/** @brief Reject missing, duplicate, unexpected, substituted, or unbound rows. */
void ValidateAggregateMembership(
    const ComparisonWorkload& workload,
    const std::vector<AggregateIdentity>& rows);

enum class TraceRecordStatus : uint8_t { Complete = 0, AdapterFailure = 1 };

/** @brief Strict builder for one manifest-bound execution trace. */
class ExecutionTrace {
public:
    /** @brief Bind a new trace builder to one immutable workload. */
    explicit ExecutionTrace(const ComparisonWorkload& workload);

    /** @brief Begin the next manifest record; records cannot be skipped. */
    void BeginRecord(const ComparisonTrial& record);
    /** @brief Append the next cyclic dispatch immediately before invocation. */
    void AppendDispatch(const std::string& method);
    /** @brief Close a fully dispatched record. */
    void CompleteRecord();
    /** @brief Close and terminate after a dispatched adapter failed. */
    void FailRecord();

    /** @brief Encode and independently reparse the trace. */
    std::vector<uint8_t> SerializeAndVerify() const;
    /** @brief Atomically publish a verified trace and return its SHA-256. */
    std::string WriteNew(const std::filesystem::path& path) const;

private:
    struct Record {
        TrialKind kind = TrialKind::Warmup;
        uint32_t trial_index = 0;
        uint32_t expected_method_count = 0;
        TraceRecordStatus status = TraceRecordStatus::Complete;
        std::vector<std::string> dispatched;
    };

    ComparisonWorkload workload_;
    std::vector<Record> records_;
    std::optional<Record> current_;
    bool terminated_ = false;
};

/** @brief Reparse and regenerate a trace's exact cyclic schedules. */
void VerifyExecutionTrace(const std::vector<uint8_t>& bytes,
                          const ComparisonWorkload& workload);

std::array<uint8_t, 32> Sha256(const std::vector<uint8_t>& bytes);
/** @brief Lowercase hexadecimal SHA-256 of arbitrary bytes. */
std::string Sha256Hex(const std::vector<uint8_t>& bytes);

}  // namespace benchmark
}  // namespace piccard
