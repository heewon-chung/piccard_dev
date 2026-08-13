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
     SuccessorCliSeamCanonicalizesRuntimeValuesAndRetainsConcreteBindings) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    ASSERT_EQ(cells.size(), 33u);

    for (const RevisionRunMode mode : {RevisionRunMode::Toy,
                                       RevisionRunMode::Paper}) {
        for (const RevisionCell* cell : cells) {
            const auto canonical = PlanDynamicRevisionCell(*cell, mode).argv;
            auto runtime = canonical;
            for (auto& argument : runtime) {
                if (argument == "--seed={seed}") {
                    argument = "--seed=20260729";
                } else if (argument == "--raw-timing-dir={output}/raw") {
                    argument = "--raw-timing-dir=/tmp/piccard-dynamic-raw";
                }
            }
            runtime.push_back(
                "--revision-identity-out=/tmp/piccard-dynamic-identity.csv");

            const auto options = ParseDynamicRevisionCliOptions(runtime);
            EXPECT_TRUE(options.enabled);
            EXPECT_EQ(options.planner_argv, canonical);
            EXPECT_EQ(options.runtime_seed, 20260729u);
            EXPECT_EQ(options.identity_output,
                      "/tmp/piccard-dynamic-identity.csv");
            if (cell->family == "dynamic_accuracy") {
                EXPECT_TRUE(options.raw_timing_dir.empty());
            } else {
                EXPECT_EQ(options.raw_timing_dir,
                          "/tmp/piccard-dynamic-raw");
            }
        }
    }
}

TEST(DynamicRevisionAdapter,
     SuccessorCliSeamRejectsMalformedOrMissingRuntimeBindingsBeforePlanning) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    ASSERT_FALSE(cells.empty());
    const auto timing = std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "dynamic_timing";
        });
    ASSERT_NE(timing, cells.end());
    const auto canonical = PlanDynamicRevisionCell(
        **timing, RevisionRunMode::Toy).argv;

    auto runtime = canonical;
    for (auto& argument : runtime) {
        if (argument == "--seed={seed}") argument = "--seed=7";
        if (argument == "--raw-timing-dir={output}/raw") {
            argument = "--raw-timing-dir=/tmp/piccard-dynamic-raw";
        }
    }
    runtime.push_back("--revision-identity-out=/tmp/piccard-dynamic-identity.csv");

    auto missing_seed = runtime;
    missing_seed.erase(std::remove_if(
        missing_seed.begin(), missing_seed.end(), [](const std::string& arg) {
            return arg.rfind("--seed=", 0) == 0;
        }), missing_seed.end());
    EXPECT_THROW(ParseDynamicRevisionCliOptions(missing_seed),
                 std::invalid_argument);

    auto duplicate_seed = runtime;
    duplicate_seed.push_back("--seed=8");
    EXPECT_THROW(ParseDynamicRevisionCliOptions(duplicate_seed),
                 std::invalid_argument);

    for (const std::string value : {"0", "0007", "abc", "{seed}extra"}) {
        auto malformed = runtime;
        auto seed = std::find_if(
            malformed.begin(), malformed.end(), [](const std::string& arg) {
                return arg.rfind("--seed=", 0) == 0;
            });
        ASSERT_NE(seed, malformed.end());
        *seed = "--seed=" + value;
        EXPECT_THROW(ParseDynamicRevisionCliOptions(malformed),
                     std::invalid_argument);
    }

    auto missing_raw = runtime;
    missing_raw.erase(std::remove_if(
        missing_raw.begin(), missing_raw.end(), [](const std::string& arg) {
            return arg.rfind("--raw-timing-dir=", 0) == 0;
        }), missing_raw.end());
    EXPECT_THROW(ParseDynamicRevisionCliOptions(missing_raw),
                 std::invalid_argument);

    auto malformed_raw = runtime;
    auto raw = std::find_if(
        malformed_raw.begin(), malformed_raw.end(), [](const std::string& arg) {
            return arg.rfind("--raw-timing-dir=", 0) == 0;
        });
    ASSERT_NE(raw, malformed_raw.end());
    *raw = "--raw-timing-dir={output}/raw";
    EXPECT_THROW(ParseDynamicRevisionCliOptions(malformed_raw),
                 std::invalid_argument);

    auto duplicate_raw = runtime;
    duplicate_raw.push_back("--raw-timing-dir=/tmp/other-raw");
    EXPECT_THROW(ParseDynamicRevisionCliOptions(duplicate_raw),
                 std::invalid_argument);

    auto missing_identity = runtime;
    missing_identity.erase(std::remove_if(
        missing_identity.begin(), missing_identity.end(), [](const std::string& arg) {
            return arg.rfind("--revision-identity-out=", 0) == 0;
        }), missing_identity.end());
    EXPECT_THROW(ParseDynamicRevisionCliOptions(missing_identity),
                 std::invalid_argument);
}

TEST(DynamicRevisionAdapter, LegacyArgumentsRemainOutsideRuntimeSeam) {
    const auto options = ParseDynamicRevisionCliOptions({
        "--seed=0007", "--raw-timing-dir=relative/raw"});
    EXPECT_FALSE(options.enabled);
    EXPECT_TRUE(options.planner_argv.empty());
    EXPECT_THROW(ParseDynamicRevisionCliOptions({
                     "--revision-identity-out="}),
                 std::invalid_argument);
    EXPECT_THROW(ParseDynamicRevisionCliOptions({
                     "--revision-identity-out=/tmp/legacy-identity.csv",
                     "--revision-identity-out=/tmp/legacy-identity-2.csv"}),
                 std::invalid_argument);
    EXPECT_THROW(ParseDynamicRevisionCliOptions({
                     "--revision-identity-out=/tmp/legacy-identity.csv"}),
                 std::invalid_argument);
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
