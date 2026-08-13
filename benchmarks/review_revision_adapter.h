#pragma once

/**
 * @file review_revision_adapter.h
 * @brief Pure selector and concrete-CLI adapter for review baselines.
 *
 * The revision matrix deliberately uses the abstract ``paper-v1`` profile
 * and producer-neutral argument names.  The review-comparison executable has
 * a different, older CLI.  This seam checks the planner output against the
 * canonical matrix first, then translates it to the concrete review CLI.
 * Parsing and planning never constructs a baseline/FHE object and never
 * starts a process.
 */

#include "revision_invocation_plan.h"

#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Strictly parsed planner argv for one review-comparison cell. */
struct ReviewRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string profile;
    std::string suite;
    std::string cell;
    std::string method;
    std::vector<std::string> methods;
    std::string security;
    uint64_t k = 0;
    uint64_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t trials = 0;
    uint64_t accuracy_trials = 0;
    uint64_t encoding_iters = 0;
    uint64_t correctness_trials = 0;
    uint64_t key_bits = 0;
    uint64_t threads = 0;
    std::string seed;
    std::string output;
};

/** @brief Exact matrix cell and byte-identical planner output. */
struct ReviewRevisionSelection {
    RevisionCell cell;
    RevisionInvocationPlan plan;
};

/** @brief Concrete one-cell execution metadata for bench_review_comparison. */
struct ReviewRevisionExecutionPlan {
    ReviewRevisionSelection selection;
    std::string concrete_suite;
    std::string concrete_profile;
    std::string concrete_security;
    std::vector<std::string> concrete_methods;
    uint64_t timing_trials = 0;
    uint64_t accuracy_trials = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t selected_point_count = 0;
    bool producer_must_spawn = false;
};

/** @brief Parse exactly the ordered argv emitted by a review planner. */
ReviewRevisionRequest ParseReviewRevisionArgs(
    const std::vector<std::string>& argv);

/** @brief Select one supported RUN cell and byte-check its canonical plan. */
ReviewRevisionSelection SelectReviewRevisionCell(
    const RevisionMatrix& matrix,
    const ReviewRevisionRequest& request,
    RevisionRunMode mode);

/** @brief Parse and select one review cell in one pure operation. */
ReviewRevisionSelection SelectReviewRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Translate the abstract planner request to the concrete producer CLI. */
ReviewRevisionExecutionPlan PlanReviewRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/**
 * @brief Return the concrete argv understood by bench_review_comparison.
 *
 * The returned vector contains no ``--revision-cell`` selector and is only
 * intended for the producer boundary after the pure selection has succeeded.
 * A non-square sqrt row is intentionally omitted from the concrete method
 * list; its matrix row remains an explicit versioned NOT_APPLICABLE terminal
 * row in the selection.
 */
std::vector<std::string> MakeConcreteReviewArgs(
    const ReviewRevisionExecutionPlan& execution);

/** @brief True only for matrix rows whose sqrt encoding is structurally valid. */
bool ReviewSqrtEncodingApplicable(const ReviewRevisionExecutionPlan& execution);

}  // namespace benchmark
}  // namespace piccard
