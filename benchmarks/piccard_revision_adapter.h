#pragma once

/**
 * @file piccard_revision_adapter.h
 * @brief Pure parser and exact-cell selector for Piccard revision argv.
 *
 * This interface deliberately has no OpenFHE or process-launch dependency.
 * It accepts only the ordered argv emitted by PlanPiccardRevisionCell and
 * returns the one canonical matrix cell that the later runner may execute.
 */

#include "benchmark_profile.h"
#include "revision_invocation_plan.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Parsed, validated successor arguments for one Piccard cell. */
struct PiccardRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string profile;
    std::string mode;
    std::string security;
    bool evidence_point = false;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t trials = 0;
    uint64_t accuracy_trials = 0;
    std::string seed;
    std::string raw_timing_dir;
};

/** @brief One exact matrix cell and its byte-identical planned invocation. */
struct PiccardRevisionSelection {
    RevisionCell cell;
    std::map<std::string, std::string> axes;
    RevisionInvocationPlan plan;
};

/** @brief Deterministic bounded synthetic workload for one Piccard cell. */
struct BoundedOverlapSets {
    std::vector<uint64_t> set_a;
    std::vector<uint64_t> set_b;
    uint64_t intersection_size = 0;
    uint64_t union_size = 0;
    double target_jaccard = 0.0;
    double realized_jaccard = 0.0;
};

/** @brief Versioned identity prepended to successor Piccard rows. */
struct PiccardRevisionIdentity {
    std::string schema = "piccard-revision-cell-v1";
    std::string cell_id;
    uint64_t universe_size = 0;
};

/** @brief Pure successor execution plan; it never constructs Piccard/KeyGen. */
struct PiccardRevisionExecutionPlan {
    PiccardRevisionSelection selection;
    BenchmarkGridPoint point;
    std::size_t selected_point_count = 0;
    std::size_t keygen_calls = 0;
    bool native_sweep = false;
};

/**
 * @brief Parse and strictly validate one planner-produced Piccard argv.
 *
 * Unknown, duplicate, missing, reordered-at-selection, or malformed values
 * are rejected.  The returned request retains the original argv for the
 * selector's byte-for-byte replan check.
 */
PiccardRevisionRequest ParsePiccardRevisionArgs(
    const std::vector<std::string>& argv);

/**
 * @brief Select exactly one validated matrix cell and replan its argv.
 *
 * The supplied request must be an exact byte-for-byte match for the selected
 * cell's PlanPiccardRevisionCell output under `mode`.
 */
PiccardRevisionSelection SelectPiccardRevisionCell(
    const RevisionMatrix& matrix,
    const PiccardRevisionRequest& request,
    RevisionRunMode mode);

/** @brief Parse argv and perform exact-cell selection in one pure operation. */
PiccardRevisionSelection SelectPiccardRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/**
 * @brief Generate sorted unique sets inside `[0, universe)`.
 *
 * The integer overlap is the canonical floor realization of the requested
 * Jaccard target for two sets of size `set_size`; the returned realized value
 * is always computed from the actual intersection and union. The construction
 * is deterministic and does not consume process-global randomness.
 */
BoundedOverlapSets MakeBoundedOverlapSets(
    uint64_t set_size,
    double target_jaccard,
    uint64_t universe);

/** @brief Return the successor identity header prefix without a newline. */
std::string PiccardRevisionIdentityHeader();

/** @brief Serialize schema, canonical cell ID, and explicit universe. */
std::string SerializePiccardRevisionIdentity(
    const PiccardRevisionIdentity& identity);

/** @brief Serialize the exact successor identity header, newline terminated. */
std::string SerializePiccardRevisionIdentityHeader();

/** @brief Serialize one selected successor identity row, newline terminated. */
std::string SerializePiccardRevisionIdentityRow(
    const PiccardRevisionSelection& selection);

/** @brief Build one-point successor execution metadata without KeyGen. */
PiccardRevisionExecutionPlan PlanPiccardRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Pure one-cell execution records used by successor-path tests. */
std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Argument-order convenience overload for planner-produced argv. */
std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix,
    RevisionRunMode mode);

/** @brief Infer Paper/Toy mode from the planner-bound profile when omitted. */
std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix);

/** @brief Matrix-first convenience overload with inferred Paper/Toy mode. */
std::vector<PiccardRevisionExecutionPlan> PlanPiccardExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv);

/** @brief Bind a selected cell's canonical identity for successor output. */
PiccardRevisionIdentity MakePiccardRevisionIdentity(
    const PiccardRevisionSelection& selection);

}  // namespace benchmark
}  // namespace piccard
