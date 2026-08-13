#include "revision_invocation_plan.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using piccard::benchmark::LoadAndValidateRevisionMatrix;
using piccard::benchmark::RevisionCell;
using piccard::benchmark::RevisionInvocationPlan;
using piccard::benchmark::RevisionMatrix;
using piccard::benchmark::RevisionRunMode;
using piccard::benchmark::PlanPiccardRevisionCell;
using piccard::benchmark::PlanFheIndRevisionCell;

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

std::vector<const RevisionCell*> FheIndCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "fhe_ind") cells.push_back(&cell);
    }
    return cells;
}

std::string Arg(const RevisionInvocationPlan& plan, size_t index) {
    EXPECT_LT(index, plan.argv.size());
    return plan.argv.at(index);
}

void ExpectCommonPlan(const RevisionCell& cell,
                      const RevisionInvocationPlan& plan,
                      const std::string& profile,
                      const std::string& security,
                      uint64_t timing_trials,
                      uint64_t accuracy_trials) {
    ASSERT_EQ(plan.cell_id, cell.cell_id);
    ASSERT_EQ(plan.producer, "bench_piccard");
    ASSERT_EQ(plan.concrete_profile, profile);
    ASSERT_EQ(plan.invocation_status, "RUN");
    ASSERT_EQ(plan.argv.size(), 13u);
    EXPECT_EQ(Arg(plan, 0), "--revision-cell=" + cell.cell_id);
    EXPECT_EQ(Arg(plan, 1), "--profile=" + profile);
    EXPECT_EQ(Arg(plan, 2), "--mode=combined");
    EXPECT_EQ(Arg(plan, 3), "--evidence_point");
    EXPECT_EQ(Arg(plan, 4), "--security=" + security);
    EXPECT_EQ(Arg(plan, 5), "--k=" + cell.axes.at("k"));
    EXPECT_EQ(Arg(plan, 6), "--m=" + cell.axes.at("m"));
    EXPECT_EQ(Arg(plan, 7), "--set_size=" + cell.axes.at("n"));
    EXPECT_EQ(Arg(plan, 8), "--universe=" + cell.axes.at("u"));
    EXPECT_EQ(Arg(plan, 9),
              "--trials=" + std::to_string(timing_trials));
    EXPECT_EQ(Arg(plan, 10),
              "--accuracy_trials=" + std::to_string(accuracy_trials));
    EXPECT_EQ(Arg(plan, 11), "--seed={seed}");
    EXPECT_EQ(Arg(plan, 12), "--raw_timing_dir={output}");
}

}  // namespace

TEST(RevisionInvocationPlan, ExhaustivelyPlansAllTwentyPiccardCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = PiccardCells(matrix);
    ASSERT_EQ(cells.size(), 20u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanPiccardRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanPiccardRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanPiccardRevisionCell(*cell, RevisionRunMode::DryRun);

        ExpectCommonPlan(*cell, paper, "paper-std128-t40-v1", "STD128", 30,
                         50);
        ExpectCommonPlan(*cell, toy, "readiness-toy-v1", "TOY", 1, 1);
        ExpectCommonPlan(*cell, dry_run, "paper-std128-t40-v1", "STD128", 30,
                         50);

        ASSERT_EQ(paper.expected_rows.size(), 2u);
        ASSERT_EQ(toy.expected_rows.size(), 2u);
        ASSERT_EQ(dry_run.expected_rows.size(), 2u);
        EXPECT_EQ(paper.expected_rows[0].measured_count,
                  paper.expected_rows[0].paper_measured_count);
        EXPECT_EQ(paper.expected_rows[1].measured_count,
                  paper.expected_rows[1].paper_measured_count);
        EXPECT_EQ(toy.expected_rows[0].measured_count,
                  toy.expected_rows[0].toy_measured_count);
        EXPECT_EQ(toy.expected_rows[1].measured_count,
                  toy.expected_rows[1].toy_measured_count);
        EXPECT_EQ(dry_run.expected_rows[0].measured_count,
                  dry_run.expected_rows[0].paper_measured_count);
        EXPECT_EQ(dry_run.expected_rows[1].measured_count,
                  dry_run.expected_rows[1].paper_measured_count);

        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(toy.invocation_status, "RUN");
        EXPECT_EQ(dry_run.invocation_status, "RUN");
        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan, RejectsNonPiccardOrNonRunCells) {
    RevisionMatrix matrix = Load();
    RevisionCell cell = *PiccardCells(matrix).front();

    cell.family = "fhe_ind";
    EXPECT_THROW(PlanPiccardRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = *PiccardCells(matrix).front();
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanPiccardRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan, RejectsMissingAxesAndCountMismatches) {
    RevisionMatrix matrix = Load();
    const RevisionCell source = *PiccardCells(matrix).front();

    RevisionCell missing_axis = source;
    missing_axis.axes.erase("u");
    EXPECT_THROW(
        PlanPiccardRevisionCell(missing_axis, RevisionRunMode::Paper),
        std::invalid_argument);

    RevisionCell wrong_count = source;
    wrong_count.paper_counts["timing"] = 29;
    EXPECT_THROW(
        PlanPiccardRevisionCell(wrong_count, RevisionRunMode::Paper),
        std::invalid_argument);

    wrong_count = source;
    wrong_count.expected_rows[1].toy_measured_count = 2;
    EXPECT_THROW(
        PlanPiccardRevisionCell(wrong_count, RevisionRunMode::Toy),
        std::invalid_argument);
}

TEST(RevisionInvocationPlan, StructFieldsFollowDeclaredApiOrder) {
    RevisionInvocationPlan plan{
        "cell", "bench_piccard", "paper-std128-t40-v1", "RUN", {}, {}};
    EXPECT_EQ(plan.cell_id, "cell");
    EXPECT_EQ(plan.producer, "bench_piccard");
    EXPECT_EQ(plan.concrete_profile, "paper-std128-t40-v1");
    EXPECT_EQ(plan.invocation_status, "RUN");
    EXPECT_TRUE(plan.argv.empty());
    EXPECT_TRUE(plan.expected_rows.empty());
}

TEST(RevisionInvocationPlan, ExhaustivelyPlansAllNineFheIndCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = FheIndCells(matrix);
    ASSERT_EQ(cells.size(), 9u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanFheIndRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanFheIndRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanFheIndRevisionCell(*cell, RevisionRunMode::DryRun);

        ASSERT_EQ(paper.cell_id, cell->cell_id);
        ASSERT_EQ(paper.producer, "bench_fhe_ind");
        ASSERT_EQ(paper.concrete_profile, "paper-v1");
        ASSERT_EQ(paper.invocation_status, "RUN");
        ASSERT_EQ(paper.argv.size(), 10u);
        EXPECT_EQ(paper.argv,
                  (std::vector<std::string>{
                      "--revision-cell=" + cell->cell_id,
                      "--mode=e2e",
                      "--cell-id=" + cell->cell_id,
                      "--security=STD128",
                      "--n=" + cell->axes.at("n"),
                      "--universe=" + cell->axes.at("u"),
                      "--trials=30",
                      "--raw-timing-out={output}/raw",
                      "--raw-timing-profile=paper-v1",
                      "--seed={seed}"}));

        ASSERT_EQ(toy.cell_id, cell->cell_id);
        ASSERT_EQ(toy.producer, "bench_fhe_ind");
        ASSERT_EQ(toy.concrete_profile, "readiness-toy-v1");
        ASSERT_EQ(toy.invocation_status, "RUN");
        ASSERT_EQ(toy.argv.size(), 10u);
        EXPECT_EQ(toy.argv,
                  (std::vector<std::string>{
                      "--revision-cell=" + cell->cell_id,
                      "--mode=e2e",
                      "--cell-id=" + cell->cell_id,
                      "--security=TOY",
                      "--n=" + cell->axes.at("n"),
                      "--universe=" + cell->axes.at("u"),
                      "--trials=1",
                      "--raw-timing-out={output}/raw",
                      "--raw-timing-profile=readiness-toy-v1",
                      "--seed={seed}"}));
        EXPECT_EQ(dry_run.argv, paper.argv);
        EXPECT_EQ(dry_run.concrete_profile, "paper-v1");

        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);
        EXPECT_EQ(paper.expected_rows.front().measured_count,
                  paper.expected_rows.front().paper_measured_count);
        EXPECT_EQ(toy.expected_rows.front().measured_count,
                  toy.expected_rows.front().toy_measured_count);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count,
                  dry_run.expected_rows.front().paper_measured_count);
        EXPECT_EQ(paper.expected_rows.front().row_id, "fhe_ind");
        EXPECT_EQ(paper.expected_rows.front().status, "DIAGNOSTIC");
        EXPECT_EQ(paper.expected_rows.front().terminal_status, "DIAGNOSTIC");
        EXPECT_EQ(paper.expected_rows.front().method, "fhe_ind");
        EXPECT_EQ(paper.expected_rows.front().raw_timing_contract,
                  "raw-phase-v1");

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan, RejectsInvalidFheIndIdentityGeometryAndRows) {
    RevisionMatrix matrix = Load();
    const RevisionCell source = *FheIndCells(matrix).front();

    RevisionCell cell = source;
    cell.family = "piccard_std128";
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.producer = "bench_piccard";
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes.erase("u");
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["u"] = "16384";
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts["timing"] = 29;
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().raw_timing_contract = "wrong";
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.eligibility = "TABLE_ELIGIBLE";
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_artifact_schema = "other-schema";
    EXPECT_THROW(PlanFheIndRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}
