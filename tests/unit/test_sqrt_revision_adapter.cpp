#include "sqrt_revision_adapter.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace piccard::benchmark;

RevisionMatrix Load() {
    return LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

std::vector<const RevisionCell*> Cells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "sqrt_comparison") cells.push_back(&cell);
    }
    return cells;
}

TEST(SqrtRevisionAdapter,
     SelectsExactlyOneCanonicalCellAndPreservesArmTerminalRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = Cells(matrix);
    ASSERT_EQ(cells.size(), 32u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy,
                                       RevisionRunMode::DryRun}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const auto plan = PlanSqrtRevisionCell(*cell, mode);
            const auto execution =
                PlanSqrtRevisionExecution(matrix, plan.argv, mode);
            EXPECT_EQ(execution.selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(execution.selection.plan.argv, plan.argv);
            EXPECT_EQ(execution.selected_point_count, 1u);
            EXPECT_FALSE(execution.native_sweep);
            EXPECT_EQ(execution.point.k, std::stoul(cell->axes.at("k")));
            EXPECT_EQ(execution.point.m,
                      std::stoul(cell->axes.at("m")));
            EXPECT_EQ(execution.point.set_size,
                      std::stoul(cell->axes.at("n")));
            EXPECT_EQ(execution.point.universe_size,
                      std::stoul(cell->axes.at("u")));
            EXPECT_EQ(execution.onehot_runs,
                      mode == RevisionRunMode::Toy ? 1u :
                      cell->expected_rows.at(0).paper_measured_count);

            const bool square = IsSqrtRevisionArmApplicable(*cell);
            EXPECT_EQ(execution.sqrt_applicable, square);
            EXPECT_EQ(execution.sqrt_runs,
                      square ? (mode == RevisionRunMode::Toy ? 1u :
                                cell->expected_rows.at(1).paper_measured_count)
                             : 0u);
            EXPECT_EQ(SqrtRevisionArmReason(*cell),
                      square ? "" : "sqrt-m-not-perfect-square");
            EXPECT_EQ(execution.selection.plan.expected_rows.at(1).status,
                      square ? "MEASURED" : "NOT_APPLICABLE");
        }
    }
}

TEST(SqrtRevisionAdapter, RejectsGeometryRoleCountOrByteMismatches) {
    const RevisionMatrix matrix = Load();
    const auto cells = Cells(matrix);
    ASSERT_FALSE(cells.empty());
    const auto canonical =
        PlanSqrtRevisionCell(*cells.front(), RevisionRunMode::Toy);

    auto changed_m = canonical.argv;
    auto it = std::find_if(changed_m.begin(), changed_m.end(),
                           [](const std::string& arg) {
                               return arg.rfind("--m=", 0) == 0;
                           });
    ASSERT_NE(it, changed_m.end());
    *it = "--m=16";
    EXPECT_THROW(PlanSqrtRevisionExecution(matrix, changed_m,
                                           RevisionRunMode::Toy),
                 std::invalid_argument);

    auto changed_trials = canonical.argv;
    it = std::find_if(changed_trials.begin(), changed_trials.end(),
                      [](const std::string& arg) {
                          return arg.rfind("--trials=", 0) == 0;
                      });
    ASSERT_NE(it, changed_trials.end());
    *it = "--trials=2";
    EXPECT_THROW(PlanSqrtRevisionExecution(matrix, changed_trials,
                                           RevisionRunMode::Toy),
                 std::invalid_argument);

    auto unknown = canonical.argv;
    unknown.push_back("--extra=1");
    EXPECT_THROW(ParseSqrtRevisionArgs(unknown), std::invalid_argument);

    auto reordered = canonical.argv;
    std::swap(reordered.front(), reordered.at(1));
    EXPECT_THROW(PlanSqrtRevisionExecution(matrix, reordered,
                                           RevisionRunMode::Toy),
                 std::invalid_argument);
}

TEST(SqrtRevisionAdapter,
     CanonicalizesConcreteSeedOnlyForPlannerAndKeepsToyCounts) {
    const RevisionMatrix matrix = Load();
    const auto cells = Cells(matrix);
    ASSERT_FALSE(cells.empty());

    for (const RevisionCell* cell : cells) {
        SCOPED_TRACE(cell->cell_id);
        const auto canonical =
            PlanSqrtRevisionCell(*cell, RevisionRunMode::Toy).argv;
        auto runtime = canonical;
        auto seed = std::find_if(
            runtime.begin(), runtime.end(), [](const std::string& arg) {
                return arg.rfind("--seed=", 0) == 0;
            });
        ASSERT_NE(seed, runtime.end());
        *seed = "--seed=20260729";

        const auto execution = PlanSqrtRevisionExecution(
            matrix, runtime, RevisionRunMode::Toy);
        EXPECT_EQ(execution.selection.plan.argv, canonical);
        EXPECT_EQ(execution.onehot_runs, 1u);
        EXPECT_EQ(execution.sqrt_runs,
                  execution.sqrt_applicable ? 1u : 0u);
    }
}

TEST(SqrtRevisionAdapter,
     RejectsMissingDuplicateAndMalformedConcreteSeedBeforeSelection) {
    const RevisionMatrix matrix = Load();
    const auto cell = Cells(matrix).front();
    const auto canonical =
        PlanSqrtRevisionCell(*cell, RevisionRunMode::Toy).argv;

    auto missing = canonical;
    missing.erase(std::remove_if(
        missing.begin(), missing.end(), [](const std::string& arg) {
            return arg.rfind("--seed=", 0) == 0;
        }), missing.end());
    EXPECT_THROW(PlanSqrtRevisionExecution(matrix, missing,
                                           RevisionRunMode::Toy),
                 std::invalid_argument);

    auto duplicate = canonical;
    duplicate.push_back("--seed=20260729");
    EXPECT_THROW(PlanSqrtRevisionExecution(matrix, duplicate,
                                           RevisionRunMode::Toy),
                 std::invalid_argument);

    for (const std::string value : {"0", "0007", "abc", "{seed}extra"}) {
        auto malformed = canonical;
        auto seed = std::find_if(
            malformed.begin(), malformed.end(), [](const std::string& arg) {
                return arg.rfind("--seed=", 0) == 0;
            });
        ASSERT_NE(seed, malformed.end());
        *seed = "--seed=" + value;
        EXPECT_THROW(PlanSqrtRevisionExecution(matrix, malformed,
                                               RevisionRunMode::Toy),
                     std::invalid_argument)
            << value;
    }
}

}  // namespace
