#pragma once

/**
 * @file revision_invocation_plan.h
 * @brief Pure planning API for one canonical Piccard revision cell.
 *
 * This API is deliberately independent of OpenFHE and has no process-launch
 * side effects.  It converts one already-parsed matrix cell into the exact
 * ordered argv that a later orchestrator may give to the Piccard producer.
 */

#include "revision_matrix.h"

#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Invocation mode used to select profile and expected row counts. */
enum class RevisionRunMode {
    Paper,
    Toy,
    DryRun,
};

/** @brief A producer invocation plan; constructing it never spawns a process. */
struct RevisionInvocationPlan {
    std::string cell_id;
    std::string producer;
    std::string concrete_profile;
    std::string invocation_status;
    std::vector<std::string> argv;
    std::vector<RevisionRow> expected_rows;
};

/**
 * @brief Plan exactly one validated `piccard_std128` matrix cell.
 *
 * The selector key is the complete canonical cell ID.  Only cells with the
 * `RUN` status and the frozen Piccard STD128 contract are accepted.  `Toy`
 * projects each expected row's measured count to its toy count; `Paper` and
 * `DryRun` retain paper counts.  `DryRun` does not change the cell's
 * invocation status: an outer orchestrator owns no-spawn policy.
 */
RevisionInvocationPlan PlanPiccardRevisionCell(const RevisionCell& cell,
                                               RevisionRunMode mode);

/**
 * @brief Plan exactly one validated `fhe_ind` matrix cell.
 *
 * `Paper` and `DryRun` retain the paper diagnostic count; `Toy` projects the
 * expected row to its toy count.  The returned argv is pure data and no
 * producer or FHE context is launched.
 */
RevisionInvocationPlan PlanFheIndRevisionCell(const RevisionCell& cell,
                                              RevisionRunMode mode);

/**
 * @brief Plan one synthetic threshold timing/spec/agreement matrix cell.
 *
 * Only the fifteen `threshold_timing`, `threshold_spec`, and
 * `threshold_agreement` cells are accepted.  The returned argv is pure data;
 * no threshold producer or FHE context is launched.
 */
RevisionInvocationPlan PlanThresholdRevisionCell(const RevisionCell& cell,
                                                 RevisionRunMode mode);

}  // namespace benchmark
}  // namespace piccard
