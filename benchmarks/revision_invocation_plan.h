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
 * @brief Plan exactly one validated `estimator_accuracy` matrix cell.
 *
 * The j-axis points use 50 paper trials and the k-axis convergence points use
 * 500 paper trials; both project to one toy trial.  The returned argv is pure
 * data and no estimator producer is launched.
 */
RevisionInvocationPlan PlanEstimatorRevisionCell(const RevisionCell& cell,
                                                 RevisionRunMode mode);

/**
 * @brief Plan exactly one validated deletion survival matrix cell.
 *
 * Exact deletion is a zero-trial diagnostic; Monte Carlo deletion uses 1000
 * paper trials and one toy trial.  The returned argv is pure data and no
 * deletion producer is launched.
 */
RevisionInvocationPlan PlanDeletionRevisionCell(const RevisionCell& cell,
                                                RevisionRunMode mode);

/**
 * @brief Plan exactly one validated `sqrt_comparison` matrix cell.
 *
 * The returned plan preserves explicit NOT_APPLICABLE sqrt rows for
 * non-square m values; no producer is launched while planning.
 */
RevisionInvocationPlan PlanSqrtRevisionCell(const RevisionCell& cell,
                                            RevisionRunMode mode);

/**
 * @brief Plan exactly one validated `piccard_std192_encoding` matrix cell.
 *
 * The encoding plan is local and diagnostic-only: it carries no FHE setup,
 * key-generation, or raw timing artifact arguments.
 */
RevisionInvocationPlan PlanStd192EncodingRevisionCell(
    const RevisionCell& cell, RevisionRunMode mode);

/**
 * @brief Plan one validated BCG12 MinHash or exact comparison cell.
 *
 * MinHash accepts the control, k, and n axes; exact comparison accepts only
 * the control and n axes.  The returned argv is pure data and does not launch
 * the review-comparison producer.
 */
RevisionInvocationPlan PlanBcg12RevisionCell(const RevisionCell& cell,
                                             RevisionRunMode mode);

/**
 * @brief Plan one validated SJ16 comparison or calibration cell.
 *
 * The planner preserves explicit NO_SPAWN extrapolation cells as metadata-only
 * plans with empty argv.  It never launches an SJ16 or calibration producer.
 */
RevisionInvocationPlan PlanSj16RevisionCell(const RevisionCell& cell,
                                            RevisionRunMode mode);

/**
 * @brief Plan one validated dynamic timing, accuracy, or refresh cell.
 *
 * The planner emits pure argv data for `bench_dynamic`; it never launches a
 * producer or creates an FHE context.  Paper and dry-run use the paper
 * profile/counts while Toy projects expected row counts to one.
 */
RevisionInvocationPlan PlanDynamicRevisionCell(const RevisionCell& cell,
                                               RevisionRunMode mode);

/**
 * @brief Plan one validated flooding/noise-profile matrix cell.
 *
 * The returned argv is for the `scripts/run_noise_profiles.sh` wrapper and
 * is pure data: planning never launches the noise producer.  Paper and
 * dry-run cover all three profile axes; Toy is executable only for the
 * representative `primary40` profile.
 */
RevisionInvocationPlan PlanFloodingRevisionCell(const RevisionCell& cell,
                                                RevisionRunMode mode);

/**
 * @brief Plan one validated real-dataset artifact cell.
 *
 * The planner accepts the accuracy, summary, STD128 timing, and STD192
 * encoding cells for the DBLP-ACM and Enron variants.  It emits pure argv
 * data for either `bench_real_datasets` or `summarize_real_datasets.py`; no
 * dataset, FHE context, or producer process is touched while planning.
 */
RevisionInvocationPlan PlanRealDatasetRevisionCell(const RevisionCell& cell,
                                                   RevisionRunMode mode);

/**
 * @brief Plan one supported threshold matrix cell.
 *
 * The fifteen `threshold_timing`, `threshold_spec`, and
 * `threshold_agreement` cells plus the eighty-four
 * `threshold_synthetic_fpfn` points and the single DBLP threshold control
 * cell are accepted.  The returned argv is pure data; no threshold producer
 * or FHE context is launched.
 */
RevisionInvocationPlan PlanThresholdRevisionCell(const RevisionCell& cell,
                                                 RevisionRunMode mode);

/**
 * @brief Dispatch one validated matrix cell to its family-specific planner.
 *
 * The dispatcher is pure: it never launches a producer or constructs an FHE
 * context.  Family planners retain the matrix's RUN/NO_SPAWN status and
 * project Paper, Toy, or DryRun row counts according to their contracts.
 */
RevisionInvocationPlan PlanRevisionCell(const RevisionCell& cell,
                                        RevisionRunMode mode);

}  // namespace benchmark
}  // namespace piccard
