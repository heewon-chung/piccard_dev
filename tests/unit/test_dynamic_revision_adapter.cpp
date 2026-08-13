#include "dynamic_revision_adapter.h"

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

std::vector<const RevisionCell*> DynamicCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.producer == "bench_dynamic") cells.push_back(&cell);
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

TEST(DynamicRevisionAdapter,
     ParsesAndSelectsEveryDynamicCellForPaperToyAndDryRun) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    ASSERT_EQ(cells.size(), 33u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy,
                                       RevisionRunMode::DryRun}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const auto expected = PlanDynamicRevisionCell(*cell, mode);
            const auto request = ParseDynamicRevisionArgs(expected.argv);
            const auto selection = SelectDynamicRevisionCell(
                matrix, request, mode);
            EXPECT_EQ(selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(selection.plan.argv, expected.argv);
            EXPECT_EQ(request.revision_cell, cell->cell_id);
            EXPECT_EQ(request.k, std::stoul(cell->axes.at("k")));
            EXPECT_EQ(request.m, std::stoul(cell->axes.at("m")));
            EXPECT_EQ(request.set_size, std::stoull(cell->axes.at("n")));
            EXPECT_EQ(request.universe, std::stoull(cell->axes.at("u")));
            EXPECT_EQ(request.updates, 1u);
        }
    }
}

TEST(DynamicRevisionAdapter, RejectsMalformedDuplicateAndMismatchedFlags) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    ASSERT_FALSE(cells.empty());
    const auto plan = PlanDynamicRevisionCell(*cells.front(),
                                              RevisionRunMode::Paper);

    auto unknown = plan.argv;
    unknown.push_back("--unexpected=1");
    EXPECT_THROW(ParseDynamicRevisionArgs(unknown), std::invalid_argument);

    auto duplicate = plan.argv;
    duplicate.push_back(plan.argv.front());
    EXPECT_THROW(ParseDynamicRevisionArgs(duplicate), std::invalid_argument);

    auto missing = plan.argv;
    missing.erase(missing.begin());
    EXPECT_THROW(ParseDynamicRevisionArgs(missing), std::invalid_argument);

    auto wrong_mode = ReplaceArg(
        plan.argv, "--mode=", std::string("--mode=") +
            (std::find(plan.argv.begin(), plan.argv.end(), "--cell=accuracy") !=
                     plan.argv.end()
                 ? "timing"
                 : "accuracy"));
    EXPECT_THROW(ParseDynamicRevisionArgs(wrong_mode), std::invalid_argument);

    auto wrong_updates = ReplaceArg(plan.argv, "--updates=", "--updates=2");
    EXPECT_THROW(ParseDynamicRevisionArgs(wrong_updates), std::invalid_argument);

    auto wrong_universe = ReplaceArg(plan.argv, "--universe=", "--universe=1");
    const auto request = ParseDynamicRevisionArgs(wrong_universe);
    EXPECT_THROW(SelectDynamicRevisionCell(matrix, request,
                                            RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(DynamicRevisionAdapter,
     AccuracyUsesVersionedCorrectnessAndAllRevisionCellsRemainOnePoint) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    ASSERT_EQ(cells.size(), 33u);

    for (const RevisionCell* cell : cells) {
        const auto plan = PlanDynamicRevisionCell(*cell,
                                                  RevisionRunMode::Toy);
        const auto executions = PlanDynamicExecutionSpy(plan.argv, matrix);
        ASSERT_EQ(executions.size(), 1u);
        const auto& execution = executions.front();
        EXPECT_EQ(execution.selection.cell.cell_id, cell->cell_id);
        EXPECT_EQ(execution.selected_point_count, 1u);
        EXPECT_EQ(execution.keygen_calls, 0u);
        EXPECT_EQ(execution.update_count, 1u);
        EXPECT_EQ(execution.protocol_runs, 1u);
        EXPECT_FALSE(execution.native_sweep);
        EXPECT_EQ(execution.versioned_correctness,
                  cell->family == "dynamic_accuracy");
        EXPECT_EQ(execution.raw_timing,
                  cell->family != "dynamic_accuracy");
    }
}

TEST(DynamicRevisionAdapter, AccuracyRejectsRawTimingAndTimingRequiresIt) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    const RevisionCell* accuracy = nullptr;
    const RevisionCell* timing = nullptr;
    for (const auto* cell : cells) {
        if (cell->family == "dynamic_accuracy" && accuracy == nullptr) {
            accuracy = cell;
        }
        if (cell->family == "dynamic_timing" && timing == nullptr) {
            timing = cell;
        }
    }
    ASSERT_NE(accuracy, nullptr);
    ASSERT_NE(timing, nullptr);

    const auto accuracy_plan = PlanDynamicRevisionCell(
        *accuracy, RevisionRunMode::Paper);
    auto bad_accuracy = accuracy_plan.argv;
    bad_accuracy.push_back("--raw-timing-dir={output}/raw");
    EXPECT_THROW(ParseDynamicRevisionArgs(bad_accuracy), std::invalid_argument);

    const auto timing_plan = PlanDynamicRevisionCell(
        *timing, RevisionRunMode::Paper);
    auto bad_timing = timing_plan.argv;
    bad_timing.erase(std::remove_if(
        bad_timing.begin(), bad_timing.end(), [](const std::string& arg) {
            return arg.rfind("--raw-timing-dir=", 0) == 0;
        }), bad_timing.end());
    EXPECT_THROW(ParseDynamicRevisionArgs(bad_timing), std::invalid_argument);
}

}  // namespace
