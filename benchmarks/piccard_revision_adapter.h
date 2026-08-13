#pragma once

/**
 * @file piccard_revision_adapter.h
 * @brief Pure parser and exact-cell selector for Piccard revision argv.
 *
 * This interface deliberately has no OpenFHE or process-launch dependency.
 * It accepts only the ordered argv emitted by PlanPiccardRevisionCell and
 * returns the one canonical matrix cell that the later runner may execute.
 */

#include "revision_invocation_plan.h"

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

}  // namespace benchmark
}  // namespace piccard
