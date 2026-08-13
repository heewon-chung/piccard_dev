#include "piccard_revision_adapter.h"

#include "revision_invocation_plan.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <iterator>
#include <set>
#include <string>
#include <vector>

namespace {

using piccard::benchmark::LoadAndValidateRevisionMatrix;
using piccard::benchmark::PlanPiccardRevisionCell;
using piccard::benchmark::RevisionCell;
using piccard::benchmark::RevisionInvocationPlan;
using piccard::benchmark::RevisionMatrix;
using piccard::benchmark::RevisionRunMode;
using piccard::benchmark::ParsePiccardRevisionArgs;
using piccard::benchmark::PiccardRevisionRequest;
using piccard::benchmark::PiccardRevisionSelection;
using piccard::benchmark::BoundedOverlapSets;
using piccard::benchmark::PlanPiccardRevisionExecution;
using piccard::benchmark::PlanPiccardExecutionSpy;
using piccard::benchmark::PiccardRevisionExecutionPlan;
using piccard::benchmark::MakeBoundedOverlapSets;
using piccard::benchmark::SerializePiccardRevisionIdentityHeader;
using piccard::benchmark::SerializePiccardRevisionIdentityRow;
using piccard::benchmark::SelectPiccardRevisionCell;

RevisionMatrix Load() {
    return LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

std::vector<const RevisionCell*> PiccardCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "piccard_std128") cells.push_back(&cell);
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

TEST(PiccardRevisionAdapter,
     ParsesAndSelectsEveryPiccardPaperToyAndDryRunPlanExactly) {
    const RevisionMatrix matrix = Load();
    const auto cells = PiccardCells(matrix);
    ASSERT_EQ(cells.size(), 20u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy,
                                       RevisionRunMode::DryRun}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const RevisionInvocationPlan expected =
                PlanPiccardRevisionCell(*cell, mode);
            const PiccardRevisionRequest request =
                ParsePiccardRevisionArgs(expected.argv);
            const PiccardRevisionSelection selection =
                SelectPiccardRevisionCell(matrix, request, mode);

            EXPECT_EQ(selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(selection.cell.axes, cell->axes);
            EXPECT_EQ(selection.plan.cell_id, cell->cell_id);
            EXPECT_EQ(selection.plan.argv, expected.argv);
            EXPECT_EQ(request.argv, expected.argv);
            EXPECT_EQ(request.revision_cell, cell->cell_id);
            EXPECT_EQ(request.mode, "combined");
            EXPECT_TRUE(request.evidence_point);
            EXPECT_EQ(request.k, std::stoull(cell->axes.at("k")));
            EXPECT_EQ(request.m, std::stoull(cell->axes.at("m")));
            EXPECT_EQ(request.set_size, std::stoull(cell->axes.at("n")));
            EXPECT_EQ(request.universe, std::stoull(cell->axes.at("u")));
        }
    }
}

TEST(PiccardRevisionAdapter, RejectsUnknownDuplicateMissingAndMismatchedFlags) {
    const RevisionMatrix matrix = Load();
    const auto cells = PiccardCells(matrix);
    ASSERT_FALSE(cells.empty());
    const RevisionInvocationPlan plan =
        PlanPiccardRevisionCell(*cells.front(), RevisionRunMode::Paper);

    auto unknown = plan.argv;
    unknown.push_back("--unexpected=1");
    EXPECT_THROW(ParsePiccardRevisionArgs(unknown), std::invalid_argument);

    auto duplicate = plan.argv;
    duplicate.push_back(plan.argv.front());
    EXPECT_THROW(ParsePiccardRevisionArgs(duplicate), std::invalid_argument);

    auto missing = plan.argv;
    missing.erase(missing.begin());
    EXPECT_THROW(ParsePiccardRevisionArgs(missing), std::invalid_argument);

    auto mismatched_axis = ReplaceArg(
        plan.argv, "--k=", "--k=16");
    const PiccardRevisionRequest mismatched_request =
        ParsePiccardRevisionArgs(mismatched_axis);
    EXPECT_THROW(SelectPiccardRevisionCell(
                     matrix, mismatched_request, RevisionRunMode::Paper),
                 std::invalid_argument);

    auto mismatched_universe = ReplaceArg(
        plan.argv, "--universe=", "--universe=16384");
    const PiccardRevisionRequest mismatched_universe_request =
        ParsePiccardRevisionArgs(mismatched_universe);
    EXPECT_THROW(SelectPiccardRevisionCell(
                     matrix, mismatched_universe_request,
                     RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(PiccardRevisionAdapter, RejectsByteDifferentOrderAndProfileOrSecurity) {
    const RevisionMatrix matrix = Load();
    const auto cells = PiccardCells(matrix);
    ASSERT_FALSE(cells.empty());
    const RevisionInvocationPlan plan =
        PlanPiccardRevisionCell(*cells.front(), RevisionRunMode::Paper);

    auto reordered = plan.argv;
    std::swap(reordered[0], reordered[1]);
    const PiccardRevisionRequest reordered_request =
        ParsePiccardRevisionArgs(reordered);
    EXPECT_THROW(SelectPiccardRevisionCell(
                     matrix, reordered_request, RevisionRunMode::Paper),
                 std::invalid_argument);

    auto wrong_profile = ReplaceArg(
        plan.argv, "--profile=", "--profile=readiness-toy-v1");
    EXPECT_THROW(ParsePiccardRevisionArgs(wrong_profile),
                 std::invalid_argument);

    auto wrong_security = ReplaceArg(
        plan.argv, "--security=", "--security=TOY");
    EXPECT_THROW(ParsePiccardRevisionArgs(wrong_security),
                 std::invalid_argument);
}

TEST(PiccardRevisionAdapter, AdjacentPlansRemainSingleCellSelections) {
    const RevisionMatrix matrix = Load();
    const auto cells = PiccardCells(matrix);
    ASSERT_EQ(cells.size(), 20u);

    for (size_t index = 0; index < cells.size(); ++index) {
        const RevisionInvocationPlan plan = PlanPiccardRevisionCell(
            *cells[index], RevisionRunMode::Paper);
        const auto request = ParsePiccardRevisionArgs(plan.argv);
        const auto selection = SelectPiccardRevisionCell(
            matrix, request, RevisionRunMode::Paper);
        EXPECT_EQ(selection.cell.cell_id, cells[index]->cell_id);
        EXPECT_EQ(selection.cell.axes.size(), 4u);
        if (index + 1 < cells.size()) {
            EXPECT_NE(selection.cell.cell_id, cells[index + 1]->cell_id);
        }
    }
}

TEST(PiccardRevisionAdapter,
     BoundedWorkloadIsDeterministicSortedUniqueAndUsesExplicitUniverse) {
    const BoundedOverlapSets first = MakeBoundedOverlapSets(
        100000, 0.5, 262144);
    const BoundedOverlapSets repeat = MakeBoundedOverlapSets(
        100000, 0.5, 262144);

    ASSERT_EQ(first.set_a.size(), 100000u);
    ASSERT_EQ(first.set_b.size(), 100000u);
    EXPECT_EQ(first.set_a, repeat.set_a);
    EXPECT_EQ(first.set_b, repeat.set_b);
    EXPECT_EQ(first.intersection_size, 66666u);
    EXPECT_EQ(first.union_size, 133334u);
    const std::set<uint64_t> set_a(first.set_a.begin(), first.set_a.end());
    const std::set<uint64_t> set_b(first.set_b.begin(), first.set_b.end());
    std::set<uint64_t> intersection;
    std::set<uint64_t> union_set;
    std::set_intersection(set_a.begin(), set_a.end(), set_b.begin(),
                          set_b.end(), std::inserter(intersection,
                                                     intersection.begin()));
    std::set_union(set_a.begin(), set_a.end(), set_b.begin(), set_b.end(),
                   std::inserter(union_set, union_set.begin()));
    EXPECT_EQ(intersection.size(), 66666u);
    EXPECT_EQ(union_set.size(), 133334u);
    EXPECT_DOUBLE_EQ(static_cast<double>(intersection.size()) /
                         static_cast<double>(union_set.size()),
                     66666.0 / 133334.0);
    EXPECT_DOUBLE_EQ(first.realized_jaccard,
                     static_cast<double>(first.intersection_size) /
                         static_cast<double>(first.union_size));
    EXPECT_EQ(first.target_jaccard, 0.5);

    EXPECT_TRUE(std::is_sorted(first.set_a.begin(), first.set_a.end()));
    EXPECT_TRUE(std::is_sorted(first.set_b.begin(), first.set_b.end()));
    EXPECT_EQ(std::adjacent_find(first.set_a.begin(), first.set_a.end()),
              first.set_a.end());
    EXPECT_EQ(std::adjacent_find(first.set_b.begin(), first.set_b.end()),
              first.set_b.end());
    EXPECT_LT(first.set_a.back(), 262144u);
    EXPECT_LT(first.set_b.back(), 262144u);

    EXPECT_THROW(MakeBoundedOverlapSets(100000, 0.5, 133333),
                 std::invalid_argument);
    EXPECT_THROW(MakeBoundedOverlapSets(10, -0.1, 64),
                 std::invalid_argument);
    EXPECT_THROW(MakeBoundedOverlapSets(10, 1.1, 64),
                 std::invalid_argument);
}

TEST(PiccardRevisionAdapter, BoundedWorkloadHonorsExactEndpointTargets) {
    const auto disjoint = MakeBoundedOverlapSets(10, 0.0, 20);
    EXPECT_EQ(disjoint.intersection_size, 0u);
    EXPECT_EQ(disjoint.union_size, 20u);
    EXPECT_DOUBLE_EQ(disjoint.realized_jaccard, 0.0);

    const auto identical = MakeBoundedOverlapSets(10, 1.0, 10);
    EXPECT_EQ(identical.intersection_size, 10u);
    EXPECT_EQ(identical.union_size, 10u);
    EXPECT_DOUBLE_EQ(identical.realized_jaccard, 1.0);
    EXPECT_EQ(identical.set_a, identical.set_b);
}

TEST(PiccardRevisionAdapter,
     ExecutionPlanSelectsOnePointForEveryCellWithoutKeyGeneration) {
    const RevisionMatrix matrix = Load();
    const auto cells = PiccardCells(matrix);
    ASSERT_EQ(cells.size(), 20u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const RevisionInvocationPlan expected =
                PlanPiccardRevisionCell(*cell, mode);
            const auto executions =
                PlanPiccardExecutionSpy(expected.argv, matrix, mode);
            ASSERT_EQ(executions.size(), 1u);
            const PiccardRevisionExecutionPlan& execution = executions.front();
            const auto inferred_executions =
                PlanPiccardExecutionSpy(expected.argv, matrix);
            ASSERT_EQ(inferred_executions.size(), 1u);
            EXPECT_EQ(inferred_executions.front().selection.cell.cell_id,
                      cell->cell_id);
            EXPECT_EQ(execution.selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(execution.selection.axes, cell->axes);
            EXPECT_EQ(execution.point.k, std::stoul(cell->axes.at("k")));
            EXPECT_EQ(execution.point.m, std::stoul(cell->axes.at("m")));
            EXPECT_EQ(execution.point.set_size,
                      std::stoull(cell->axes.at("n")));
            EXPECT_EQ(execution.point.universe_size,
                      std::stoul(cell->axes.at("u")));
            EXPECT_EQ(execution.selected_point_count, 1u);
            EXPECT_EQ(execution.keygen_calls, 0u);
            EXPECT_FALSE(execution.native_sweep);
            ASSERT_EQ(execution.selection.plan.expected_rows.size(), 2u);
            const uint64_t expected_count =
                mode == RevisionRunMode::Toy ? 1u : 30u;
            EXPECT_EQ(execution.selection.plan.expected_rows[0].measured_count,
                      expected_count);
            EXPECT_EQ(execution.selection.plan.expected_rows[1].measured_count,
                      mode == RevisionRunMode::Toy ? 1u : 50u);
        }
    }
}

TEST(PiccardRevisionAdapter, VersionedIdentityPrefixesOnlySuccessorRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = PiccardCells(matrix);
    ASSERT_FALSE(cells.empty());
    const auto plan = PlanPiccardRevisionExecution(
        matrix,
        PlanPiccardRevisionCell(*cells.front(), RevisionRunMode::Paper).argv,
        RevisionRunMode::Paper);
    EXPECT_EQ(SerializePiccardRevisionIdentityHeader(),
              "schema,cell_id,universe_size\n");
    EXPECT_EQ(SerializePiccardRevisionIdentityRow(plan.selection),
              "piccard-revision-cell-v1," + cells.front()->cell_id +
                  ",65536\n");
}

}  // namespace
