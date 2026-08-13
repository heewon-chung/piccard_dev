#pragma once

/**
 * @file threshold_revision_adapter.h
 * @brief Pure parser and exact-cell selector for threshold revision argv.
 *
 * The threshold benchmark has several historical sweep modes.  This adapter
 * is the successor seam: it accepts only the canonical argv emitted by the
 * revision invocation planner and binds it to exactly one matrix cell before
 * any OpenFHE context or benchmark loop is created.
 */

#include "revision_invocation_plan.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Parsed, strictly validated argv for one threshold revision cell. */
struct ThresholdRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string profile;
    std::string mode;
    std::string cell;
    std::string security;
    std::string seed;
    std::string hash_randomness;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t set_size = 0;
    uint32_t point_k = 0;
    int32_t grid_index = 0;
    uint64_t trials = 0;
};

/** @brief One exact matrix cell and its byte-identical canonical plan. */
struct ThresholdRevisionSelection {
    RevisionCell cell;
    RevisionInvocationPlan plan;
    std::string kind;
};

/** @brief Pure one-cell execution metadata; it never creates an FHE object. */
struct ThresholdRevisionExecutionPlan {
    ThresholdRevisionSelection selection;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t set_size = 0;
    uint32_t point_k = 0;
    int32_t grid_index = 0;
    uint64_t trials = 0;
    std::size_t selected_point_count = 0;
    std::size_t keygen_calls = 0;
    bool native_sweep = false;
};

/** @brief Parse canonical threshold successor flags with duplicate rejection. */
ThresholdRevisionRequest ParseThresholdRevisionArgs(
    const std::vector<std::string>& argv);

/** @brief Select the one matrix cell and require byte-identical canonical argv. */
ThresholdRevisionSelection SelectThresholdRevisionCell(
    const RevisionMatrix& matrix,
    const ThresholdRevisionRequest& request,
    RevisionRunMode mode);

/** @brief Parse and select one threshold successor cell. */
ThresholdRevisionSelection SelectThresholdRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Build pure one-cell execution metadata for a threshold argv. */
ThresholdRevisionExecutionPlan PlanThresholdRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Execution spy used to prove that no threshold sweep is planned. */
std::vector<ThresholdRevisionExecutionPlan> PlanThresholdExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Convenience overload with argv first. */
std::vector<ThresholdRevisionExecutionPlan> PlanThresholdExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix,
    RevisionRunMode mode);

/** @brief Infer Paper/Toy mode from the concrete planner profile. */
std::vector<ThresholdRevisionExecutionPlan> PlanThresholdExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix);

}  // namespace benchmark
}  // namespace piccard
