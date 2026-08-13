#pragma once

/**
 * @file real_dataset_revision_adapter.h
 * @brief Pure selector and manifest-binding seam for real-data revision cells.
 *
 * The real-data producers predate the Phase 9 matrix and intentionally keep
 * their legacy command line.  This adapter is the small, FHE-free boundary
 * between the canonical invocation planner and those producers.  It parses
 * one planner invocation, binds it to exactly one real-data (or DBLP
 * threshold) cell, and validates the processed manifest before a timing
 * driver can construct a context.
 */

#include "revision_invocation_plan.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief Parsed revision argv; parsing has no filesystem or producer effects. */
struct RealDatasetRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string mode;
};

/** @brief One exact matrix cell and its canonical planner invocation. */
struct RealDatasetRevisionSelection {
    RevisionCell cell;
    RevisionInvocationPlan plan;
};

/** @brief Pure one-cell execution metadata consumed before the real driver. */
struct RealDatasetRevisionExecutionPlan {
    RealDatasetRevisionSelection selection;
    std::string artifact;
    std::string dataset;
    std::string variant;
    std::string concrete_profile;
    std::size_t selected_cell_count = 0;
    std::size_t expected_row_count = 0;
    std::size_t keygen_calls = 0;
    bool encoding_only = false;
    bool native_sweep = false;
    // STD192 real-data encoding is a local diagnostic with two applicable
    // arms.  These fields make the one-cell/two-method topology explicit
    // without changing the matrix's artifact-level row/count contract.
    std::vector<std::string> encoding_methods;
    std::size_t encoding_timed_pairs = 0;
    std::size_t encoding_correctness_calls = 0;
};

/**
 * @brief Parse the strict revision option vocabulary.
 *
 * Runtime paths and numeric seed/count substitutions are accepted and
 * canonicalized during selection.  Unknown and duplicate options are
 * rejected.  This makes the planner placeholders useful in tests while
 * allowing the later runner to substitute real output paths.
 */
RealDatasetRevisionRequest ParseRealDatasetRevisionArgs(
    const std::vector<std::string>& argv);

/** @brief Return argv in the planner's placeholder form for exact matching. */
std::vector<std::string> CanonicalizeRealDatasetRevisionArgs(
    const std::vector<std::string>& argv,
    const std::vector<std::string>& canonical_plan_argv);

/**
 * @brief Select one real-data/DBLP-threshold cell by canonical cell ID.
 *
 * Summary cells are selectable as metadata, but are not executable by the
 * C++ real-data producer; PlanRealDatasetRevisionExecution rejects them with
 * an explicit summarizer-owned error.
 */
RealDatasetRevisionSelection SelectRealDatasetRevisionCell(
    const RevisionMatrix& matrix,
    const RealDatasetRevisionRequest& request,
    RevisionRunMode mode);

/** @brief Parse and select one canonical real-data revision cell. */
RealDatasetRevisionSelection SelectRealDatasetRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief Return whether a selected cell belongs to the Python summarizer. */
bool IsRealDatasetSummaryCell(const RevisionCell& cell);

/**
 * @brief Validate dataset/variant/universe and threshold label binding.
 *
 * This is deliberately called before dispatching to any live timing driver.
 * It loads only the processed manifest and performs no FHE setup.  A missing,
 * placeholder, unreadable, mismatched, or threshold-ineligible manifest
 * fails closed.
 */
void ValidateRealDatasetRevisionManifest(
    const RevisionCell& cell,
    const std::filesystem::path& manifest_path);

/** @brief Build one-point execution metadata without KeyGen or benchmarking. */
RealDatasetRevisionExecutionPlan PlanRealDatasetRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

/** @brief One-element execution spy used by pure adapter tests. */
std::vector<RealDatasetRevisionExecutionPlan>
PlanRealDatasetRevisionExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    RevisionRunMode mode);

}  // namespace benchmark
}  // namespace piccard
