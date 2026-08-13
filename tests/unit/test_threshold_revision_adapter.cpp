#include "threshold_revision_adapter.h"

#include "revision_invocation_plan.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace piccard::benchmark;

RevisionMatrix Load() {
    return LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

std::vector<const RevisionCell*> ThresholdCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> result;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "threshold_timing" ||
            cell.family == "threshold_spec" ||
            cell.family == "threshold_agreement" ||
            cell.family == "threshold_synthetic_fpfn") {
            result.push_back(&cell);
        }
    }
    return result;
}

std::vector<std::string> ReplaceArg(std::vector<std::string> argv,
                                    const std::string& prefix,
                                    const std::string& replacement) {
    const auto it = std::find_if(
        argv.begin(), argv.end(), [&](const std::string& arg) {
            return arg.rfind(prefix, 0) == 0;
        });
    EXPECT_NE(it, argv.end());
    if (it != argv.end()) *it = replacement;
    return argv;
}

TEST(ThresholdRevisionAdapter,
     ParsesAndSelectsEveryThresholdCellForPaperToyAndDryRun) {
    const RevisionMatrix matrix = Load();
    const auto cells = ThresholdCells(matrix);
    ASSERT_EQ(cells.size(), 99u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy,
                                       RevisionRunMode::DryRun}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const RevisionInvocationPlan expected =
                PlanThresholdRevisionCell(*cell, mode);
            const auto request = ParseThresholdRevisionArgs(expected.argv);
            const auto selection =
                SelectThresholdRevisionCell(matrix, request, mode);
            EXPECT_EQ(selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(selection.plan.argv, expected.argv);
            EXPECT_EQ(request.revision_cell, cell->cell_id);
            EXPECT_EQ(request.m, 64u);
            EXPECT_EQ(request.set_size, 1000u);
            EXPECT_EQ(request.seed, "{seed}");
            if (cell->family == "threshold_synthetic_fpfn") {
                EXPECT_EQ(request.mode, "fpfn");
                EXPECT_EQ(request.point_k,
                          std::stoul(cell->axes.at("k")));
                EXPECT_EQ(request.grid_index,
                          std::stoi(cell->axes.at("grid_index")));
            } else {
                EXPECT_EQ(request.k, std::stoul(cell->axes.at("k")));
                EXPECT_EQ(request.cell, selection.kind);
                EXPECT_EQ(request.mode, selection.kind == "agreement"
                                             ? "accuracy"
                                             : selection.kind);
            }
        }
    }
}

TEST(ThresholdRevisionAdapter,
     ExecutionSpyPlansOnePointAndNoNativeSweepForEverySupportedCell) {
    const RevisionMatrix matrix = Load();
    const auto cells = ThresholdCells(matrix);
    ASSERT_EQ(cells.size(), 99u);

    for (const RevisionCell* cell : cells) {
        const auto argv =
            PlanThresholdRevisionCell(*cell, RevisionRunMode::Toy).argv;
        const auto executions = PlanThresholdExecutionSpy(argv, matrix);
        ASSERT_EQ(executions.size(), 1u);
        EXPECT_EQ(executions.front().selection.cell.cell_id, cell->cell_id);
        EXPECT_EQ(executions.front().selected_point_count, 1u);
        EXPECT_EQ(executions.front().keygen_calls, 0u);
        EXPECT_FALSE(executions.front().native_sweep);
        EXPECT_EQ(executions.front().trials, 1u);
    }
}

TEST(ThresholdRevisionAdapter,
     SyntheticPointDomainRetainsPointKAndGridIndexAndExactToyCount) {
    const RevisionMatrix matrix = Load();
    size_t count = 0;
    for (const auto& cell : matrix.cells) {
        if (cell.family != "threshold_synthetic_fpfn") continue;
        ++count;
        const auto argv =
            PlanThresholdRevisionCell(cell, RevisionRunMode::Toy).argv;
        const auto execution =
            PlanThresholdRevisionExecution(matrix, argv, RevisionRunMode::Toy);
        EXPECT_EQ(execution.k, std::stoul(cell.axes.at("k")));
        EXPECT_EQ(execution.point_k, std::stoul(cell.axes.at("k")));
        EXPECT_EQ(execution.grid_index,
                  std::stoi(cell.axes.at("grid_index")));
        EXPECT_EQ(execution.selection.kind, "synthetic_fpfn");
        EXPECT_EQ(execution.selection.plan.expected_rows.front().measured_count,
                  1u);
    }
    EXPECT_EQ(count, 84u);
}

TEST(ThresholdRevisionAdapter,
     RejectsUnknownDuplicateMissingMismatchAndSweepDrift) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell = nullptr;
    for (const auto& candidate : matrix.cells) {
        if (candidate.family == "threshold_timing") {
            cell = &candidate;
            break;
        }
    }
    ASSERT_NE(cell, nullptr);
    const auto plan =
        PlanThresholdRevisionCell(*cell, RevisionRunMode::Paper);

    auto unknown = plan.argv;
    unknown.push_back("--unexpected=1");
    EXPECT_THROW(ParseThresholdRevisionArgs(unknown), std::invalid_argument);

    auto duplicate = plan.argv;
    duplicate.push_back("--trials=30");
    EXPECT_THROW(ParseThresholdRevisionArgs(duplicate), std::invalid_argument);

    auto missing = plan.argv;
    missing.erase(missing.begin());
    EXPECT_THROW(ParseThresholdRevisionArgs(missing), std::invalid_argument);

    auto drift = ReplaceArg(plan.argv, "--k=", "--k=32");
    const auto drift_request = ParseThresholdRevisionArgs(drift);
    EXPECT_THROW(SelectThresholdRevisionCell(matrix, drift_request,
                                              RevisionRunMode::Paper),
                 std::invalid_argument);

    auto wrong_count = ReplaceArg(plan.argv, "--trials=", "--trials=31");
    const auto wrong_count_request = ParseThresholdRevisionArgs(wrong_count);
    EXPECT_THROW(SelectThresholdRevisionCell(matrix, wrong_count_request,
                                              RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(ThresholdRevisionAdapter, EnforcesSyntheticPointFlagsAndMethodBinding) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* synthetic = nullptr;
    const RevisionCell* agreement = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "threshold_synthetic_fpfn" && synthetic == nullptr)
            synthetic = &cell;
        if (cell.family == "threshold_agreement" && agreement == nullptr)
            agreement = &cell;
    }
    ASSERT_NE(synthetic, nullptr);
    ASSERT_NE(agreement, nullptr);

    auto synthetic_argv =
        PlanThresholdRevisionCell(*synthetic, RevisionRunMode::Toy).argv;
    synthetic_argv.push_back("--cell=agreement");
    EXPECT_THROW(ParseThresholdRevisionArgs(synthetic_argv),
                 std::invalid_argument);

    auto agreement_argv =
        PlanThresholdRevisionCell(*agreement, RevisionRunMode::Toy).argv;
    agreement_argv = ReplaceArg(agreement_argv, "--cell=", "--cell=timing");
    const auto request = ParseThresholdRevisionArgs(agreement_argv);
    EXPECT_THROW(SelectThresholdRevisionCell(matrix, request,
                                              RevisionRunMode::Toy),
                 std::invalid_argument);
}

}  // namespace
