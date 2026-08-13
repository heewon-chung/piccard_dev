#include "piccard_revision_adapter.h"

#include "revision_invocation_plan.h"

#include <gtest/gtest.h>

#include <algorithm>
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

}  // namespace
