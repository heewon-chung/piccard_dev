#pragma once

/**
 * @file sqrt_revision_adapter.h
 * @brief Pure selector and execution-plan adapter for sqrt/one-hot evidence.
 *
 * The adapter is intentionally independent of OpenFHE.  It binds the
 * canonical revision matrix cell to one producer invocation, and records the
 * applicable arms before a producer constructs a crypto context.  In
 * particular, a non-square m is a terminal NOT_APPLICABLE sqrt row, not a
 * producer failure; the one-hot arm remains applicable.
 */

#include "revision_invocation_plan.h"
#include "benchmark_profile.h"

#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Strictly parsed successor arguments for a sqrt-family cell. */
struct SqrtRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string profile;
    std::string cell;
    std::string mode;
    std::string security;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t trials = 0;
    std::string seed;
};

/** @brief Selected matrix cell and byte-identical canonical plan. */
struct SqrtRevisionSelection {
    RevisionCell cell;
    RevisionInvocationPlan plan;
};

/** @brief Pure one-cell execution metadata consumed by producer entrypoints. */
struct SqrtRevisionExecutionPlan {
    SqrtRevisionSelection selection;
    BenchmarkGridPoint point;
    std::string role;
    std::size_t selected_point_count = 0;
    std::size_t onehot_runs = 0;
    std::size_t sqrt_runs = 0;
    bool sqrt_applicable = false;
    bool native_sweep = false;
};

/** @brief Parse and validate the exact planner argument vocabulary. */
SqrtRevisionRequest ParseSqrtRevisionArgs(
    const std::vector<std::string>& argv);

/** @brief Select one canonical sqrt-family cell and byte-match its plan. */
SqrtRevisionSelection SelectSqrtRevisionCell(
    const RevisionMatrix& matrix,
    const SqrtRevisionRequest& request,
    RevisionRunMode mode);

/** @brief Parse argv and select one canonical cell in a pure operation. */
SqrtRevisionSelection SelectSqrtRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Build a one-point plan without constructing an FHE context. */
SqrtRevisionExecutionPlan PlanSqrtRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Return whether the matrix's sqrt arm is applicable for this cell. */
bool IsSqrtRevisionArmApplicable(const RevisionCell& cell);

/** @brief Return the frozen terminal reason for a non-applicable sqrt arm. */
std::string SqrtRevisionArmReason(const RevisionCell& cell);

}  // namespace benchmark
}  // namespace piccard
