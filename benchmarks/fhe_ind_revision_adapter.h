#pragma once

/**
 * @file fhe_ind_revision_adapter.h
 * @brief Pure successor adapter for the FHE-IND diagnostic matrix cells.
 *
 * The adapter is intentionally independent of OpenFHE.  It validates one
 * planner-produced argv, binds it to exactly one canonical matrix cell, and
 * describes the one bounded workload that the live producer may execute.
 * Constructing any of these values never creates a crypto context or starts
 * key generation.
 */

#include "revision_invocation_plan.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Parsed and strictly validated successor FHE-IND arguments. */
struct FheIndRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string mode;
    std::string cell_id;
    std::string security;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t trials = 0;
    std::string raw_timing_out;
    std::string raw_timing_profile;
    std::string seed;
};

/** @brief One exact FHE-IND matrix cell and its canonical plan. */
struct FheIndRevisionSelection {
    RevisionCell cell;
    std::map<std::string, std::string> axes;
    RevisionInvocationPlan plan;
};

/** @brief Deterministic sets bounded by the selected explicit universe. */
struct FheIndBoundedWorkload {
    std::vector<uint64_t> set_a;
    std::vector<uint64_t> set_b;
    uint64_t intersection_size = 0;
    uint64_t union_size = 0;
    double target_jaccard = 0.0;
    double realized_jaccard = 0.0;
};

/** @brief Pure one-point successor execution description. */
struct FheIndRevisionExecutionPlan {
    FheIndRevisionSelection selection;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t trial_count = 0;
    std::size_t selected_point_count = 0;
    std::size_t keygen_calls = 0;
    bool native_sweep = false;
};

/**
 * @brief Parse the exact ordered argv emitted by PlanFheIndRevisionCell.
 *
 * Unknown, duplicate, missing, malformed, or profile-inconsistent values
 * are rejected.  Selection additionally performs the byte-for-byte plan
 * comparison, so reordered arguments cannot select a cell.
 */
FheIndRevisionRequest ParseFheIndRevisionArgs(
    const std::vector<std::string>& argv);

/** @brief Select one canonical matrix cell and revalidate its plan. */
FheIndRevisionSelection SelectFheIndRevisionCell(
    const RevisionMatrix& matrix,
    const FheIndRevisionRequest& request,
    RevisionRunMode mode);

/** @brief Parse and select one canonical matrix cell. */
FheIndRevisionSelection SelectFheIndRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Build deterministic sorted unique sets inside `[0, universe)`. */
FheIndBoundedWorkload MakeFheIndBoundedWorkload(
    uint64_t set_size,
    double target_jaccard,
    uint64_t universe);

/** @brief Identity header for successor-only diagnostic artifacts. */
std::string SerializeFheIndRevisionIdentityHeader();

/** @brief Identity row for the selected FHE-IND cell. */
std::string SerializeFheIndRevisionIdentityRow(
    const FheIndRevisionSelection& selection);

/** @brief Terminal diagnostic row for one planned successor execution. */
std::string SerializeFheIndRevisionTerminalRow(
    const FheIndRevisionExecutionPlan& execution);

/** @brief Build one-point execution metadata without key generation. */
FheIndRevisionExecutionPlan PlanFheIndRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Pure execution spy; it always returns exactly one selected point. */
std::vector<FheIndRevisionExecutionPlan> PlanFheIndExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Argument-order convenience overload for the execution spy. */
std::vector<FheIndRevisionExecutionPlan> PlanFheIndExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix,
    RevisionRunMode mode);

/** @brief Infer Paper/Toy mode from the planner-bound profile. */
std::vector<FheIndRevisionExecutionPlan> PlanFheIndExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix);

}  // namespace benchmark
}  // namespace piccard
