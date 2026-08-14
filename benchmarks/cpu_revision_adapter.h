#pragma once

/**
 * @file cpu_revision_adapter.h
 * @brief Pure selectors for the CPU-only revision benchmark producers.
 *
 * The adapter is deliberately independent of the estimator, deletion, and
 * SJ16 engines.  It parses the canonical argv emitted by the revision
 * invocation planner, selects one matrix cell, and exposes a one-invocation
 * execution seam for tests.  No producer process, Paillier key, or FHE
 * context is created by this interface.
 */

#include "revision_invocation_plan.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace piccard {
namespace benchmark {

/** @brief CPU producer covered by the canonical revision adapter. */
enum class CpuRevisionProducer {
    EstimatorBias,
    DeletionSurvival,
    Sj16Calibrate,
};

/** @brief Parsed canonical successor arguments for one CPU producer. */
struct CpuRevisionRequest {
    std::vector<std::string> argv;
    std::string revision_cell;
    std::string profile;
    std::string cell;
    std::string jaccard_grid;
    std::string seed;
    std::string output;
    uint64_t k = 0;
    uint64_t m = 0;
    uint64_t set_size = 0;
    uint64_t universe = 0;
    uint64_t trials = 0;
    uint64_t query_trials = 0;
    uint64_t enc_iters = 0;
    uint64_t key_bits = 0;
    uint64_t warmup = 0;
    uint32_t held_out = 0;
    uint32_t threads = 0;
    std::vector<uint32_t> sizes;
    bool precomputed = false;
    std::string raw_timing_dir;
    std::string raw_timing_profile;
};

/** @brief One exact matrix cell and its canonical producer plan. */
struct CpuRevisionSelection {
    RevisionCell cell;
    RevisionInvocationPlan plan;
};

/** @brief Pure execution metadata proving that one cell was selected. */
struct CpuRevisionExecutionPlan {
    CpuRevisionSelection selection;
    std::size_t selected_cell_count = 0;
    std::size_t producer_invocation_count = 0;
    bool native_sweep = false;
};

/** @brief Parse and validate the planner-produced argv for one producer. */
CpuRevisionRequest ParseCpuRevisionArgs(
    const std::vector<std::string>& argv,
    CpuRevisionProducer producer);

/** @brief Return the concrete run mode encoded by a canonical profile. */
RevisionRunMode RevisionRunModeForProfile(const std::string& profile);

/** @brief Select one cell and require byte-identical canonical argv. */
CpuRevisionSelection SelectCpuRevisionCell(
    const RevisionMatrix& matrix,
    const CpuRevisionRequest& request,
    CpuRevisionProducer producer,
    RevisionRunMode mode);

/** @brief Parse and select one cell in one pure operation. */
CpuRevisionSelection SelectCpuRevisionCell(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    CpuRevisionProducer producer,
    RevisionRunMode mode);

/** @brief Build one producer execution plan without invoking the producer. */
CpuRevisionExecutionPlan PlanCpuRevisionExecution(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    CpuRevisionProducer producer,
    RevisionRunMode mode);

/** @brief Execution spy that must contain exactly one selected cell. */
std::vector<CpuRevisionExecutionPlan> PlanCpuRevisionExecutionSpy(
    const RevisionMatrix& matrix,
    const std::vector<std::string>& argv,
    CpuRevisionProducer producer,
    RevisionRunMode mode);

}  // namespace benchmark
}  // namespace piccard
