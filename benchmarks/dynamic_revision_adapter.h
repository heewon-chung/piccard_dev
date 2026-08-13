#pragma once

/**
 * @file dynamic_revision_adapter.h
 * @brief Pure parser and exact-cell selector for dynamic revision argv.
 *
 * The adapter is deliberately independent of OpenFHE and process launch. It
 * validates the canonical argv emitted by PlanDynamicRevisionCell, binds the
 * request to exactly one matrix cell, and exposes a one-cell execution plan
 * for the successor producer path.
 */

#include "revision_invocation_plan.h"
#include "benchmark_profile.h"
#include "piccard_revision_adapter.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Parsed and strictly validated dynamic successor arguments. */
struct DynamicRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string profile;
    std::string cell;
    std::string mode;
    std::string security;
    bool evidence_point = false;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t trials = 0;
    uint64_t updates = 0;
    std::string seed;
    std::string raw_timing_dir;
    std::string raw_timing_profile;
};

/** @brief One exact matrix cell and its byte-identical canonical plan. */
struct DynamicRevisionSelection {
    RevisionCell cell;
    RevisionInvocationPlan plan;
};

/** @brief Pure one-cell successor execution metadata. */
struct DynamicRevisionExecutionPlan {
    DynamicRevisionSelection selection;
    BenchmarkGridPoint point;
    std::string kind;
    uint64_t update_count = 0;
    uint64_t protocol_runs = 0;
    std::size_t selected_point_count = 0;
    std::size_t keygen_calls = 0;
    bool versioned_correctness = false;
    bool raw_timing = false;
    bool native_sweep = false;
};

/** @brief Parse one planner-produced dynamic argv without side effects. */
DynamicRevisionRequest ParseDynamicRevisionArgs(
    const std::vector<std::string>& argv);

/** @brief Select exactly one dynamic matrix cell and verify its exact plan. */
DynamicRevisionSelection SelectDynamicRevisionCell(
    const RevisionMatrix& matrix,
    const DynamicRevisionRequest& request,
    RevisionRunMode mode);

/** @brief Parse argv and select one dynamic matrix cell. */
DynamicRevisionSelection SelectDynamicRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Build one-cell execution metadata; never constructs an FHE context. */
DynamicRevisionExecutionPlan PlanDynamicRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Pure execution spy proving a revision invocation does not sweep. */
std::vector<DynamicRevisionExecutionPlan> PlanDynamicExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Infer paper/toy mode from the canonical profile. */
std::vector<DynamicRevisionExecutionPlan> PlanDynamicExecutionSpy(
    const std::vector<std::string>& argv,
    const RevisionMatrix& matrix);

}  // namespace benchmark
}  // namespace piccard
