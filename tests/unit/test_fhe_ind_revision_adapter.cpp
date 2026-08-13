#include "fhe_ind_revision_adapter.h"

#include "revision_invocation_plan.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace {

using piccard::benchmark::FheIndRevisionExecutionPlan;
using piccard::benchmark::FheIndRevisionRequest;
using piccard::benchmark::FheIndRevisionSelection;
using piccard::benchmark::LoadAndValidateRevisionMatrix;
using piccard::benchmark::MakeFheIndBoundedWorkload;
using piccard::benchmark::PlanFheIndRevisionCell;
using piccard::benchmark::PlanFheIndRevisionExecution;
using piccard::benchmark::PlanFheIndExecutionSpy;
using piccard::benchmark::RevisionCell;
using piccard::benchmark::RevisionInvocationPlan;
using piccard::benchmark::RevisionMatrix;
using piccard::benchmark::RevisionRunMode;
using piccard::benchmark::ParseFheIndRevisionArgs;
using piccard::benchmark::SelectFheIndRevisionCell;
using piccard::benchmark::SerializeFheIndRevisionIdentityHeader;
using piccard::benchmark::SerializeFheIndRevisionIdentityRow;
using piccard::benchmark::SerializeFheIndRevisionTerminalRow;

RevisionMatrix Load() {
    return LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

std::vector<const RevisionCell*> FheIndCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "fhe_ind") cells.push_back(&cell);
    }
    return cells;
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

TEST(FheIndRevisionAdapter,
     ParsesAndSelectsEveryFheIndPaperToyAndDryRunPlanExactly) {
    const RevisionMatrix matrix = Load();
    const auto cells = FheIndCells(matrix);
    ASSERT_EQ(cells.size(), 9u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy,
                                       RevisionRunMode::DryRun}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const RevisionInvocationPlan expected =
                PlanFheIndRevisionCell(*cell, mode);
            const FheIndRevisionRequest request =
                ParseFheIndRevisionArgs(expected.argv);
            const FheIndRevisionSelection selection =
                SelectFheIndRevisionCell(matrix, request, mode);

            EXPECT_EQ(request.argv, expected.argv);
            EXPECT_EQ(request.revision_cell, cell->cell_id);
            EXPECT_EQ(request.cell_id, cell->cell_id);
            EXPECT_EQ(request.mode, "e2e");
            EXPECT_EQ(request.set_size,
                      std::stoull(cell->axes.at("n")));
            EXPECT_EQ(request.universe,
                      std::stoull(cell->axes.at("u")));
            EXPECT_EQ(selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(selection.cell.axes, cell->axes);
            EXPECT_EQ(selection.plan.argv, expected.argv);
        }
    }
}

TEST(FheIndRevisionAdapter, RejectsUnknownDuplicateMissingAndMismatchedFlags) {
    const RevisionMatrix matrix = Load();
    const auto cells = FheIndCells(matrix);
    ASSERT_FALSE(cells.empty());
    const RevisionInvocationPlan plan =
        PlanFheIndRevisionCell(*cells.front(), RevisionRunMode::Paper);

    auto unknown = plan.argv;
    unknown.push_back("--unexpected=1");
    EXPECT_THROW(ParseFheIndRevisionArgs(unknown), std::invalid_argument);

    auto duplicate = plan.argv;
    duplicate.push_back(plan.argv.front());
    EXPECT_THROW(ParseFheIndRevisionArgs(duplicate), std::invalid_argument);

    auto missing = plan.argv;
    missing.erase(missing.begin());
    EXPECT_THROW(ParseFheIndRevisionArgs(missing), std::invalid_argument);

    auto mismatched_security = ReplaceArg(
        plan.argv, "--security=", "--security=TOY");
    EXPECT_THROW(ParseFheIndRevisionArgs(mismatched_security),
                 std::invalid_argument);

    auto mismatched_trials = ReplaceArg(
        plan.argv, "--trials=", "--trials=1");
    EXPECT_THROW(ParseFheIndRevisionArgs(mismatched_trials),
                 std::invalid_argument);

    auto mismatched_universe = ReplaceArg(
        plan.argv, "--universe=", "--universe=16384");
    const FheIndRevisionRequest universe_request =
        ParseFheIndRevisionArgs(mismatched_universe);
    EXPECT_THROW(SelectFheIndRevisionCell(
                     matrix, universe_request, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(FheIndRevisionAdapter,
     BoundedWorkloadIsDeterministicUniqueAndWithinSelectedUniverse) {
    const auto first = MakeFheIndBoundedWorkload(100000, 0.5, 262144);
    const auto repeat = MakeFheIndBoundedWorkload(100000, 0.5, 262144);
    ASSERT_EQ(first.set_a.size(), 100000u);
    ASSERT_EQ(first.set_b.size(), 100000u);
    EXPECT_EQ(first.set_a, repeat.set_a);
    EXPECT_EQ(first.set_b, repeat.set_b);
    EXPECT_EQ(first.intersection_size, 66666u);
    EXPECT_EQ(first.union_size, 133334u);
    EXPECT_DOUBLE_EQ(first.realized_jaccard, 66666.0 / 133334.0);
    EXPECT_TRUE(std::is_sorted(first.set_a.begin(), first.set_a.end()));
    EXPECT_TRUE(std::is_sorted(first.set_b.begin(), first.set_b.end()));
    EXPECT_EQ(std::adjacent_find(first.set_a.begin(), first.set_a.end()),
              first.set_a.end());
    EXPECT_EQ(std::adjacent_find(first.set_b.begin(), first.set_b.end()),
              first.set_b.end());
    EXPECT_LT(first.set_a.back(), 262144u);
    EXPECT_LT(first.set_b.back(), 262144u);

    EXPECT_THROW(MakeFheIndBoundedWorkload(100000, 0.5, 133333),
                 std::invalid_argument);
}

TEST(FheIndRevisionAdapter,
     ExecutionSpySelectsOneDiagnosticPointWithoutKeyGeneration) {
    const RevisionMatrix matrix = Load();
    const auto cells = FheIndCells(matrix);
    ASSERT_EQ(cells.size(), 9u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy}) {
        for (const RevisionCell* cell : cells) {
            const RevisionInvocationPlan plan =
                PlanFheIndRevisionCell(*cell, mode);
            const auto executions =
                PlanFheIndExecutionSpy(plan.argv, matrix, mode);
            ASSERT_EQ(executions.size(), 1u);
            const FheIndRevisionExecutionPlan& execution = executions.front();
            EXPECT_EQ(execution.selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(execution.set_size,
                      std::stoull(cell->axes.at("n")));
            EXPECT_EQ(execution.universe,
                      std::stoull(cell->axes.at("u")));
            EXPECT_EQ(execution.selected_point_count, 1u);
            EXPECT_EQ(execution.keygen_calls, 0u);
            EXPECT_FALSE(execution.native_sweep);
            ASSERT_EQ(execution.selection.plan.expected_rows.size(), 1u);
            EXPECT_EQ(execution.selection.plan.expected_rows.front().status,
                      "DIAGNOSTIC");
            EXPECT_EQ(execution.selection.plan.expected_rows.front().method,
                      "fhe_ind");
            const uint64_t expected_count =
                mode == RevisionRunMode::Toy ? 1u : 30u;
            EXPECT_EQ(execution.selection.plan.expected_rows.front()
                          .measured_count,
                      expected_count);
        }
    }
}

TEST(FheIndRevisionAdapter, EmitsVersionedIdentityAndDiagnosticTerminalRow) {
    const RevisionMatrix matrix = Load();
    const auto cell = FheIndCells(matrix).front();
    const auto plan = PlanFheIndRevisionExecution(
        matrix,
        PlanFheIndRevisionCell(*cell, RevisionRunMode::Toy).argv,
        RevisionRunMode::Toy);
    EXPECT_EQ(SerializeFheIndRevisionIdentityHeader(),
              "schema,cell_id,set_size,universe_size,trial_count\n");
    EXPECT_EQ(SerializeFheIndRevisionIdentityRow(plan.selection),
              "fhe-ind-revision-cell-v1," + cell->cell_id +
                  ",1000,65536,1\n");
    EXPECT_EQ(SerializeFheIndRevisionTerminalRow(plan),
              "fhe-ind-revision-cell-v1," + cell->cell_id +
                  ",1000,65536,1,DIAGNOSTIC,fhe_ind\n");
}

}  // namespace
