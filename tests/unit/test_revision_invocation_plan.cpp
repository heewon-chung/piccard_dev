#include "revision_invocation_plan.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
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
using piccard::benchmark::RevisionRow;
using piccard::benchmark::RevisionRunMode;
using piccard::benchmark::PlanPiccardRevisionCell;
using piccard::benchmark::PlanFheIndRevisionCell;
using piccard::benchmark::PlanEstimatorRevisionCell;
using piccard::benchmark::PlanDeletionRevisionCell;
using piccard::benchmark::PlanSqrtRevisionCell;
using piccard::benchmark::PlanStd192EncodingRevisionCell;
using piccard::benchmark::PlanThresholdRevisionCell;
using piccard::benchmark::PlanBcg12RevisionCell;
using piccard::benchmark::PlanSj16RevisionCell;
using piccard::benchmark::PlanDynamicRevisionCell;
using piccard::benchmark::PlanFloodingRevisionCell;
using piccard::benchmark::PlanRealDatasetRevisionCell;
using piccard::benchmark::PlanRevisionCell;

RevisionMatrix Load() {
    return LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

std::vector<std::string> ReadFixtureLines(const std::string& filename) {
    const std::filesystem::path matrix_path(PICCARD_REVISION_MATRIX_PATH);
    const std::filesystem::path fixture_path =
        matrix_path.parent_path().parent_path() / "tests" / "fixtures" /
        "revision_matrix" / filename;
    std::ifstream input(fixture_path);
    EXPECT_TRUE(input.is_open());
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
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

std::vector<const RevisionCell*> EstimatorCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "estimator_accuracy") cells.push_back(&cell);
    }
    return cells;
}

std::vector<const RevisionCell*> DeletionCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "deletion_exact" || cell.family == "deletion_mc") {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<const RevisionCell*> SqrtCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "sqrt_comparison") cells.push_back(&cell);
    }
    return cells;
}

std::vector<const RevisionCell*> Std192EncodingCells(
    const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "piccard_std192_encoding") cells.push_back(&cell);
    }
    return cells;
}

std::vector<const RevisionCell*> Bcg12Cells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "bcg12_minhash" || cell.family == "bcg12_exact") {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<const RevisionCell*> Sj16Cells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "sj16") cells.push_back(&cell);
    }
    return cells;
}

std::vector<const RevisionCell*> DynamicCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "dynamic_timing" ||
            cell.family == "dynamic_accuracy" ||
            cell.family == "dynamic_refresh") {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<const RevisionCell*> FloodingCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "flooding") cells.push_back(&cell);
    }
    return cells;
}

std::vector<const RevisionCell*> RealDatasetAccuracySummaryCells(
    const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "real_dataset" &&
            (cell.axis_value == "accuracy" || cell.axis_value == "summary")) {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<const RevisionCell*> RealDatasetTimingCells(
    const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "real_dataset" &&
            cell.axis_value == "std128_timing") {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<const RevisionCell*> RealDatasetEncodingCells(
    const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "real_dataset" &&
            cell.axis_value == "std192_encoding") {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<const RevisionCell*> ThresholdCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "threshold_timing" ||
            cell.family == "threshold_spec" ||
            cell.family == "threshold_agreement") {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<const RevisionCell*> SyntheticThresholdCells(
    const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "threshold_synthetic_fpfn") cells.push_back(&cell);
    }
    return cells;
}

std::vector<const RevisionCell*> DblpThresholdCells(
    const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "threshold_dblp_fpfn") cells.push_back(&cell);
    }
    return cells;
}

bool HasArg(const RevisionInvocationPlan& plan, const std::string& prefix) {
    return std::any_of(
        plan.argv.begin(), plan.argv.end(),
        [&](const std::string& arg) { return arg.rfind(prefix, 0) == 0; });
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

TEST(RevisionInvocationPlan,
     ExhaustivelyPlansAllSeventeenEstimatorCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = EstimatorCells(matrix);
    ASSERT_EQ(cells.size(), 17u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanEstimatorRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanEstimatorRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanEstimatorRevisionCell(*cell, RevisionRunMode::DryRun);

        const bool j_cell = cell->axis == "j";
        const std::string profile = "paper-v1";
        const std::string cell_selector =
            j_cell ? "estimator-j" : "estimator-k";
        const std::string paper_trials = j_cell ? "50" : "500";
        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--profile=paper-v1",
            "--cell=" + cell_selector,
            "--k=" + cell->axes.at("k"),
            "--m=64",
            "--set_size=1000",
            "--universe=65536",
            "--trials=" + paper_trials,
            j_cell ? "--jaccard-grid=" + cell->axis_value
                   : "--jaccard-grid=0.5",
            "--seed={seed}",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--profile=readiness-toy-v1",
            "--cell=" + cell_selector,
            "--k=" + cell->axes.at("k"),
            "--m=64",
            "--set_size=1000",
            "--universe=65536",
            "--trials=1",
            j_cell ? "--jaccard-grid=" + cell->axis_value
                   : "--jaccard-grid=0.5",
            "--seed={seed}",
        };

        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, "bench_estimator_bias");
        EXPECT_EQ(toy.producer, "bench_estimator_bias");
        EXPECT_EQ(paper.concrete_profile, profile);
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, profile);
        EXPECT_EQ(paper.invocation_status, "RUN");
        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);
        EXPECT_EQ(paper.expected_rows.front().status, "MEASURED");
        EXPECT_EQ(paper.expected_rows.front().terminal_status, "MEASURED");
        EXPECT_EQ(paper.expected_rows.front().method, "estimator");
        EXPECT_EQ(paper.expected_rows.front().measured_count,
                  paper.expected_rows.front().paper_measured_count);
        EXPECT_EQ(toy.expected_rows.front().measured_count,
                  toy.expected_rows.front().toy_measured_count);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count,
                  dry_run.expected_rows.front().paper_measured_count);
        EXPECT_FALSE(HasArg(paper, "--security="));
        EXPECT_FALSE(HasArg(paper, "--raw"));

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidEstimatorIdentityGeometryCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = EstimatorCells(matrix);
    ASSERT_EQ(cells.size(), 17u);
    const RevisionCell source = *cells.front();

    RevisionCell cell = source;
    cell.family = "piccard_std128";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.producer = "bench_piccard";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.dataset = "enron";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis = "m";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis_value = "1.1";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["k"] = "64";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["m"] = "128";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes.erase("u");
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts["trials"] = 49;
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["trials"] = "500";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().method = "wrong";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().status = "DIAGNOSTIC";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().attributes["trials"] = "49";
    EXPECT_THROW(PlanEstimatorRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan, ExhaustivelyPlansBothDeletionCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = DeletionCells(matrix);
    ASSERT_EQ(cells.size(), 2u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanDeletionRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanDeletionRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanDeletionRevisionCell(*cell, RevisionRunMode::DryRun);

        const bool exact = cell->family == "deletion_exact";
        const std::string selector = exact ? "exact" : "monte-carlo";
        const std::string paper_trials = exact ? "0" : "1000";
        const std::string toy_trials = exact ? "0" : "1";
        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--profile=paper-v1",
            "--cell=" + selector,
            "--k=128",
            "--m=64",
            "--set_size=1000",
            "--universe=65536",
            "--trials=" + paper_trials,
            "--seed={seed}",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--profile=readiness-toy-v1",
            "--cell=" + selector,
            "--k=128",
            "--m=64",
            "--set_size=1000",
            "--universe=65536",
            "--trials=" + toy_trials,
            "--seed={seed}",
        };

        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, "bench_deletion_survival");
        EXPECT_EQ(toy.producer, "bench_deletion_survival");
        EXPECT_EQ(paper.concrete_profile, "paper-v1");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);
        const auto& paper_row = paper.expected_rows.front();
        EXPECT_EQ(paper_row.row_id, exact ? "exact" : "monte_carlo");
        EXPECT_EQ(paper_row.status, "DIAGNOSTIC");
        EXPECT_EQ(paper_row.terminal_status, "DIAGNOSTIC");
        EXPECT_EQ(paper_row.method, exact ? "exact" : "monte_carlo");
        EXPECT_EQ(paper_row.measured_count, exact ? 0u : 1000u);
        EXPECT_EQ(toy.expected_rows.front().measured_count,
                  exact ? 0u : 1u);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count,
                  exact ? 0u : 1000u);
        EXPECT_FALSE(HasArg(paper, "--security="));
        EXPECT_FALSE(HasArg(paper, "--raw"));

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidDeletionIdentityGeometryCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = DeletionCells(matrix);
    ASSERT_EQ(cells.size(), 2u);
    const RevisionCell exact = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "deletion_exact";
        });

    RevisionCell cell = exact;
    cell.family = "estimator_accuracy";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.producer = "bench_estimator_bias";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.dataset = "enron";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.axis = "k";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.axis_value = "-1";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.axes["k"] = "64";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.axes.erase("u");
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.paper_counts["measured"] = 1;
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.attributes["trials"] = "1";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.expected_rows.front().method = "monte_carlo";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.expected_rows.front().status = "MEASURED";
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact;
    cell.expected_rows.front().measured_count = 1;
    EXPECT_THROW(PlanDeletionRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan, ExhaustivelyPlansAllTwentySqrtCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = SqrtCells(matrix);
    ASSERT_EQ(cells.size(), 20u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanSqrtRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanSqrtRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanSqrtRevisionCell(*cell, RevisionRunMode::DryRun);

        const std::string axis = cell->axis;
        const std::string mode = axis.substr(0, axis.size() - 2u);
        const std::string producer =
            axis == "timing_m"
                ? "bench_onehot_sqrt"
                : (axis == "accuracy_m" ? "bench_sqrt_comparison"
                                         : "bench_crossover");
        const uint64_t m = std::stoull(cell->axes.at("m"));
        const bool square = m == 16 || m == 64 || m == 256;
        const std::string paper_profile = "paper-std128-t40-v1";
        const std::string paper_trials =
            axis == "timing_m" ? "30"
            : (axis == "accuracy_m" ? "50"
                                     : (axis == "ciphertext_m" ? "1" : "30"));
        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--profile=" + paper_profile,
            "--cell=" + axis,
            "--mode=" + mode,
            "--security=STD128",
            "--k=128",
            "--m=" + cell->axes.at("m"),
            "--set_size=1000",
            "--universe=65536",
            "--trials=" + paper_trials,
            "--seed={seed}",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--profile=readiness-toy-v1",
            "--cell=" + axis,
            "--mode=" + mode,
            "--security=TOY",
            "--k=128",
            "--m=" + cell->axes.at("m"),
            "--set_size=1000",
            "--universe=65536",
            "--trials=1",
            "--seed={seed}",
        };

        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, producer);
        EXPECT_EQ(toy.producer, producer);
        EXPECT_EQ(paper.concrete_profile, paper_profile);
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, paper_profile);
        EXPECT_EQ(paper.invocation_status, "RUN");
        ASSERT_EQ(paper.expected_rows.size(), 2u);
        ASSERT_EQ(toy.expected_rows.size(), 2u);
        ASSERT_EQ(dry_run.expected_rows.size(), 2u);

        const auto& paper_onehot = paper.expected_rows.at(0);
        const auto& paper_sqrt = paper.expected_rows.at(1);
        EXPECT_EQ(paper_onehot.row_id, "onehot");
        EXPECT_EQ(paper_onehot.method, "onehot");
        EXPECT_EQ(paper_onehot.status, "MEASURED");
        EXPECT_EQ(paper_onehot.terminal_status, "MEASURED");
        EXPECT_EQ(paper_onehot.measured_count, std::stoull(paper_trials));
        EXPECT_EQ(paper_onehot.paper_measured_count,
                  std::stoull(paper_trials));
        EXPECT_EQ(paper_onehot.toy_measured_count, 1u);
        EXPECT_EQ(paper_sqrt.row_id, "sqrt");
        EXPECT_EQ(paper_sqrt.method, "sqrt");
        EXPECT_EQ(paper_sqrt.status, square ? "MEASURED" : "NOT_APPLICABLE");
        EXPECT_EQ(paper_sqrt.terminal_status,
                  square ? "MEASURED" : "NOT_APPLICABLE");
        EXPECT_EQ(paper_sqrt.reason,
                  square ? "" : "sqrt-m-not-perfect-square");
        EXPECT_EQ(paper_sqrt.reason_code,
                  square ? "" : "sqrt-m-not-perfect-square");
        EXPECT_EQ(paper_sqrt.measured_count,
                  square ? std::stoull(paper_trials) : 0u);
        EXPECT_EQ(paper_sqrt.paper_measured_count,
                  square ? std::stoull(paper_trials) : 0u);
        EXPECT_EQ(paper_sqrt.toy_measured_count, square ? 1u : 0u);
        EXPECT_EQ(toy.expected_rows.at(0).measured_count, 1u);
        EXPECT_EQ(toy.expected_rows.at(1).measured_count, square ? 1u : 0u);
        EXPECT_EQ(dry_run.expected_rows.at(0).measured_count,
                  paper.expected_rows.at(0).measured_count);
        EXPECT_EQ(dry_run.expected_rows.at(1).status,
                  paper.expected_rows.at(1).status);
        EXPECT_EQ(dry_run.expected_rows.at(1).measured_count,
                  paper.expected_rows.at(1).measured_count);
        EXPECT_FALSE(HasArg(paper, "--raw"));

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidSqrtIdentityGeometryCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = SqrtCells(matrix);
    ASSERT_EQ(cells.size(), 20u);
    const RevisionCell timing = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->cell_id ==
                   "paper-v1::sqrt_comparison::timing_m=16";
        });

    RevisionCell cell = timing;
    cell.family = "estimator_accuracy";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.producer = "bench_crossover";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.dataset = "enron";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.axis = "m";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.axis_value = "17";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.axes["m"] = "17";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.axes["k"] = "64";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.axes.erase("u");
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.paper_counts["onehot"] = 29;
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.expected_rows.front().status = "NOT_APPLICABLE";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.expected_rows.at(1).reason = "wrong";
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.expected_rows.pop_back();
    EXPECT_THROW(PlanSqrtRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan,
     ExhaustivelyPlansAllTwentyStd192EncodingCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = Std192EncodingCells(matrix);
    ASSERT_EQ(cells.size(), 20u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanStd192EncodingRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanStd192EncodingRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanStd192EncodingRevisionCell(*cell, RevisionRunMode::DryRun);

        const std::string m = cell->axes.at("m");
        const bool square = m == "16" || m == "64" || m == "256";
        const std::string paper_profile = "paper-std192-encoding-v1";
        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--profile=" + paper_profile,
            "--suite=encoding",
            "--methods=piccard_encode,piccard_sqrt_encode",
            "--security=STD192",
            "--k=" + cell->axes.at("k"),
            "--m=" + m,
            "--n=" + cell->axes.at("n"),
            "--universe=" + cell->axes.at("u"),
            "--encoding-iters=30",
            "--correctness-trials=1",
            "--seed={seed}",
            "--output={output}/encoding.csv",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--profile=readiness-toy-v1",
            "--suite=encoding",
            "--methods=piccard_encode,piccard_sqrt_encode",
            "--security=STD192",
            "--k=" + cell->axes.at("k"),
            "--m=" + m,
            "--n=" + cell->axes.at("n"),
            "--universe=" + cell->axes.at("u"),
            "--encoding-iters=1",
            "--correctness-trials=1",
            "--seed={seed}",
            "--output={output}/encoding.csv",
        };

        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, "bench_review_comparison");
        EXPECT_EQ(toy.producer, "bench_review_comparison");
        EXPECT_EQ(paper.concrete_profile, paper_profile);
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, paper_profile);
        EXPECT_EQ(paper.invocation_status, "RUN");
        ASSERT_EQ(paper.expected_rows.size(), 2u);
        ASSERT_EQ(toy.expected_rows.size(), 2u);
        ASSERT_EQ(dry_run.expected_rows.size(), 2u);

        const auto& paper_encode = paper.expected_rows.at(0);
        const auto& paper_sqrt = paper.expected_rows.at(1);
        EXPECT_EQ(paper_encode.row_id, "piccard_encode");
        EXPECT_EQ(paper_encode.status, "DIAGNOSTIC");
        EXPECT_EQ(paper_encode.terminal_status, "DIAGNOSTIC");
        EXPECT_EQ(paper_encode.method, "piccard_encode");
        EXPECT_EQ(paper_encode.attributes.at("encoding_only"), "true");
        EXPECT_EQ(paper_encode.measured_count, 30u);
        EXPECT_EQ(paper_encode.paper_measured_count, 30u);
        EXPECT_EQ(paper_encode.toy_measured_count, 1u);
        EXPECT_EQ(paper_sqrt.row_id, "piccard_sqrt_encode");
        EXPECT_EQ(paper_sqrt.status, square ? "DIAGNOSTIC" : "NOT_APPLICABLE");
        EXPECT_EQ(paper_sqrt.terminal_status,
                  square ? "DIAGNOSTIC" : "NOT_APPLICABLE");
        EXPECT_EQ(paper_sqrt.reason,
                  square ? "" : "sqrt-m-not-perfect-square");
        EXPECT_EQ(paper_sqrt.reason_code,
                  square ? "" : "sqrt-m-not-perfect-square");
        EXPECT_EQ(paper_sqrt.attributes.at("encoding_only"), "true");
        EXPECT_EQ(paper_sqrt.measured_count, square ? 30u : 0u);
        EXPECT_EQ(paper_sqrt.paper_measured_count, square ? 30u : 0u);
        EXPECT_EQ(paper_sqrt.toy_measured_count, square ? 1u : 0u);
        EXPECT_EQ(toy.expected_rows.at(0).measured_count, 1u);
        EXPECT_EQ(toy.expected_rows.at(1).measured_count, square ? 1u : 0u);
        EXPECT_EQ(dry_run.expected_rows.at(0).measured_count, 30u);
        EXPECT_EQ(dry_run.expected_rows.at(1).measured_count,
                  square ? 30u : 0u);
        EXPECT_FALSE(HasArg(paper, "--security=TOY"));
        EXPECT_FALSE(HasArg(paper, "--raw"));
        EXPECT_FALSE(HasArg(paper, "--fhe"));
        EXPECT_FALSE(HasArg(paper, "--key"));

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidStd192EncodingIdentityGeometryCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = Std192EncodingCells(matrix);
    ASSERT_EQ(cells.size(), 20u);
    const RevisionCell control = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->cell_id ==
                   "paper-v1::piccard_std192_encoding::control=default";
        });

    RevisionCell cell = control;
    cell.family = "piccard_std128";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.producer = "bench_piccard";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.dataset = "enron";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.expected_artifact_schema = "piccard-benchmark-csv-v1";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.axis = "x";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.axis_value = "-1";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.axes["k"] = "1024";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.axes["m"] = "32";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.axes.erase("u");
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    const RevisionCell n100000 = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->cell_id ==
                   "paper-v1::piccard_std192_encoding::n=100000";
        });
    cell = n100000;
    cell.axes["u"] = "65536";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.paper_counts["encoding"] = 29;
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.expected_rows.front().attributes["encoding_only"] = "false";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.expected_rows.at(1).status = "MEASURED";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.expected_rows.at(1).reason = "wrong";
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);

    cell = control;
    cell.expected_rows.pop_back();
    EXPECT_THROW(
        PlanStd192EncodingRevisionCell(cell, RevisionRunMode::Paper),
        std::invalid_argument);
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
        "cell", "bench_piccard", "piccard_std128", "paper-v1",
        "paper-std128-t40-v1", "standard", "piccard-benchmark-csv-v1",
        "bench_piccard", {}, "RUN", {}, {}};
    EXPECT_EQ(plan.cell_id, "cell");
    EXPECT_EQ(plan.producer, "bench_piccard");
    EXPECT_EQ(plan.family, "piccard_std128");
    EXPECT_EQ(plan.abstract_profile, "paper-v1");
    EXPECT_EQ(plan.concrete_profile, "paper-std128-t40-v1");
    EXPECT_EQ(plan.timeout_class, "standard");
    EXPECT_EQ(plan.expected_artifact_schema, "piccard-benchmark-csv-v1");
    EXPECT_EQ(plan.executable, "bench_piccard");
    EXPECT_TRUE(plan.environment.empty());
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

TEST(RevisionInvocationPlan, ExhaustivelyPlansAllFifteenThresholdFheCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = ThresholdCells(matrix);
    ASSERT_EQ(cells.size(), 15u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanThresholdRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanThresholdRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanThresholdRevisionCell(*cell, RevisionRunMode::DryRun);

        ASSERT_EQ(paper.cell_id, cell->cell_id);
        ASSERT_EQ(paper.invocation_status, "RUN");
        ASSERT_EQ(dry_run.argv, paper.argv);
        ASSERT_EQ(dry_run.concrete_profile, "paper-v1");
        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);
        EXPECT_EQ(paper.expected_rows.front().measured_count,
                  paper.expected_rows.front().paper_measured_count);
        EXPECT_EQ(toy.expected_rows.front().measured_count,
                  toy.expected_rows.front().toy_measured_count);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count,
                  dry_run.expected_rows.front().paper_measured_count);

        if (cell->family == "threshold_timing" ||
            cell->family == "threshold_spec" ||
            cell->family == "threshold_agreement") {
            const std::string mode =
                cell->family == "threshold_timing"
                    ? "timing"
                    : (cell->family == "threshold_spec" ? "spec" : "accuracy");
            const std::string row_id =
                cell->family == "threshold_timing"
                    ? "timing"
                    : (cell->family == "threshold_spec" ? "spec" : "agreement");
            const std::string cell_selector = "--cell=" + row_id;
            const std::string paper_trials =
                cell->family == "threshold_timing"
                    ? "30"
                    : (cell->family == "threshold_spec" ? "0" : "50");
            const std::vector<std::string> expected_paper = {
                "--revision-cell=" + cell->cell_id,
                "--profile=paper-v1",
                "--mode=" + mode,
                cell_selector,
                "--security=STD128",
                "--k=" + cell->axes.at("k"),
                "--m=64",
                "--set_size=1000",
                "--trials=" + paper_trials,
                "--seed={seed}",
            };
            const std::vector<std::string> expected_toy = {
                "--revision-cell=" + cell->cell_id,
                "--profile=readiness-toy-v1",
                "--mode=" + mode,
                cell_selector,
                "--security=TOY",
                "--k=" + cell->axes.at("k"),
                "--m=64",
                "--set_size=1000",
                "--trials=1",
                "--seed={seed}",
            };
            EXPECT_EQ(paper.argv, expected_paper);
            EXPECT_EQ(toy.argv, expected_toy);
            EXPECT_EQ(paper.producer, "bench_threshold");
            EXPECT_EQ(toy.producer, "bench_threshold");
            EXPECT_EQ(paper.concrete_profile, "paper-v1");
            EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
            EXPECT_EQ(paper.expected_rows.front().row_id, row_id);
            EXPECT_EQ(paper.expected_rows.front().method, row_id);
            EXPECT_EQ(paper.expected_rows.front().status,
                      cell->family == "threshold_spec" ? "DIAGNOSTIC"
                                                        : "MEASURED");
            EXPECT_EQ(paper.expected_rows.front().attributes.at("k"),
                      cell->axes.at("k"));
            EXPECT_FALSE(HasArg(paper, "--raw"));
        } else {
            FAIL() << "unexpected threshold family: " << cell->family;
        }

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     ExhaustivelyPlansAllEightyFourSyntheticThresholdPoints) {
    const RevisionMatrix matrix = Load();
    const auto cells = SyntheticThresholdCells(matrix);
    ASSERT_EQ(cells.size(), 84u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const RevisionInvocationPlan paper =
            PlanThresholdRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanThresholdRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanThresholdRevisionCell(*cell, RevisionRunMode::DryRun);

        const std::string point_k = cell->axes.at("k");
        const std::string grid_index = cell->axes.at("grid_index");
        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--profile=paper-v1",
            "--mode=fpfn",
            "--point-k=" + point_k,
            "--grid-index=" + grid_index,
            "--m=64",
            "--set_size=1000",
            "--trials=1000",
            "--seed={seed}",
            "--hash_randomness=resampled",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--profile=readiness-toy-v1",
            "--mode=fpfn",
            "--point-k=" + point_k,
            "--grid-index=" + grid_index,
            "--m=64",
            "--set_size=1000",
            "--trials=1",
            "--seed={seed}",
            "--hash_randomness=resampled",
        };

        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.producer, "bench_threshold");
        EXPECT_EQ(toy.producer, "bench_threshold");
        EXPECT_EQ(paper.concrete_profile, "paper-v1");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(paper.expected_rows.size(), 1u);
        EXPECT_EQ(toy.expected_rows.size(), 1u);
        EXPECT_EQ(dry_run.expected_rows.size(), 1u);
        EXPECT_EQ(paper.expected_rows.front().row_id, "synthetic_fpfn");
        EXPECT_EQ(paper.expected_rows.front().status, "DIAGNOSTIC");
        EXPECT_EQ(paper.expected_rows.front().method, "synthetic_fpfn");
        EXPECT_EQ(paper.expected_rows.front().attributes.at("point_k"),
                  point_k);
        EXPECT_EQ(paper.expected_rows.front().attributes.at("grid_index"),
                  grid_index);
        EXPECT_EQ(paper.expected_rows.front().attributes.at("trials"),
                  "1000");
        EXPECT_EQ(paper.expected_rows.front().measured_count, 1000u);
        EXPECT_EQ(toy.expected_rows.front().measured_count, 1u);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count, 1000u);
        EXPECT_FALSE(HasArg(paper, "--security="));
        EXPECT_FALSE(HasArg(paper, "--raw_timing"));
        EXPECT_FALSE(HasArg(paper, "--accuracy_trials"));

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());

    const auto first = std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->cell_id ==
                   "paper-v1::threshold_synthetic_fpfn::point=k64_j-10";
        });
    ASSERT_NE(first, cells.end());
    const auto last = std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->cell_id ==
                   "paper-v1::threshold_synthetic_fpfn::point=k512_j10";
        });
    ASSERT_NE(last, cells.end());
    EXPECT_EQ((*first)->axes.at("grid_index"), "-10");
    EXPECT_EQ((*last)->axes.at("grid_index"), "10");
}

TEST(RevisionInvocationPlan,
     RejectsInvalidSyntheticThresholdFamilyGeometryCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = SyntheticThresholdCells(matrix);
    ASSERT_FALSE(cells.empty());
    const RevisionCell source = *cells.front();

    RevisionCell cell = source;
    cell.family = "threshold_dblp_fpfn";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.producer = "bench_piccard";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.dataset = "enron";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_artifact_schema = "threshold-csv-v1";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis = "k";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis_value = "k64_j-11";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["k"] = "32";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["grid_index"] = "-11";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes.erase("u");
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts["trials"] = 999;
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["point_k"] = "999";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().attributes["grid_index"] = "10";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().attributes["trials"] = "999";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan,
     PlansTheSingleDblpThresholdControlCellAcrossAllModes) {
    const RevisionMatrix matrix = Load();
    const auto cells = DblpThresholdCells(matrix);
    ASSERT_EQ(cells.size(), 1u);
    const RevisionCell& cell = *cells.front();

    const RevisionInvocationPlan paper =
        PlanThresholdRevisionCell(cell, RevisionRunMode::Paper);
    const RevisionInvocationPlan toy =
        PlanThresholdRevisionCell(cell, RevisionRunMode::Toy);
    const RevisionInvocationPlan dry_run =
        PlanThresholdRevisionCell(cell, RevisionRunMode::DryRun);

    const std::vector<std::string> expected_paper = {
        "--revision-cell=" + cell.cell_id,
        "--mode=threshold",
        "--dataset-manifest={dblp_acm_u65536_manifest}",
        "--k=128",
        "--m=64",
        "--threshold-trials=50",
        "--seed={seed}",
        "--hash_randomness=resampled",
        "--csv={output}/threshold.csv",
        "--workload-manifest-out={output}/threshold.manifest.tsv",
        "--workload-rows-out={output}/threshold.rows.tsv",
    };
    const std::vector<std::string> expected_toy = {
        "--revision-cell=" + cell.cell_id,
        "--mode=threshold",
        "--dataset-manifest={dblp_acm_u65536_manifest}",
        "--k=128",
        "--m=64",
        "--threshold-trials=1",
        "--seed={seed}",
        "--hash_randomness=resampled",
        "--csv={output}/threshold.csv",
        "--workload-manifest-out={output}/threshold.manifest.tsv",
        "--workload-rows-out={output}/threshold.rows.tsv",
    };

    EXPECT_EQ(paper.argv, expected_paper);
    EXPECT_EQ(toy.argv, expected_toy);
    EXPECT_EQ(dry_run.argv, expected_paper);
    EXPECT_EQ(paper.cell_id, cell.cell_id);
    EXPECT_EQ(paper.producer, "bench_real_datasets");
    EXPECT_EQ(toy.producer, "bench_real_datasets");
    EXPECT_EQ(paper.concrete_profile, "paper-v1");
    EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
    EXPECT_EQ(dry_run.concrete_profile, "paper-v1");
    EXPECT_EQ(paper.invocation_status, "RUN");
    ASSERT_EQ(paper.expected_rows.size(), 1u);
    ASSERT_EQ(toy.expected_rows.size(), 1u);
    ASSERT_EQ(dry_run.expected_rows.size(), 1u);
    EXPECT_EQ(paper.expected_rows.front().row_id, "dblp_held_out");
    EXPECT_EQ(paper.expected_rows.front().status, "DIAGNOSTIC");
    EXPECT_EQ(paper.expected_rows.front().method, "dblp_held_out");
    EXPECT_EQ(paper.expected_rows.front().list_attributes.at("truth_bases"),
              std::vector<std::string>({"label", "exact_jaccard"}));
    EXPECT_EQ(paper.expected_rows.front().measured_count, 50u);
    EXPECT_EQ(toy.expected_rows.front().measured_count, 1u);
    EXPECT_EQ(dry_run.expected_rows.front().measured_count, 50u);
    EXPECT_FALSE(HasArg(paper, "--profile="));
    EXPECT_FALSE(HasArg(paper, "--security="));
    EXPECT_FALSE(HasArg(paper, "--raw_timing"));
}

TEST(RevisionInvocationPlan,
     RejectsInvalidDblpThresholdIdentityGeometryCountsAndTruth) {
    const RevisionMatrix matrix = Load();
    const auto cells = DblpThresholdCells(matrix);
    ASSERT_EQ(cells.size(), 1u);
    const RevisionCell source = *cells.front();

    RevisionCell cell = source;
    cell.family = "threshold_synthetic_fpfn";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.producer = "bench_threshold";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.dataset = "enron";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["variant"] = "enron_u65536";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis = "k";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis_value = "-1";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["k"] = "-1";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["m"] = "128";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes.erase("u");
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_artifact_schema = "threshold-fpfn-csv-v1";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts["held_out"] = 49;
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.list_attributes["truth_bases"] = {"label"};
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().method = "synthetic_fpfn";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().list_attributes["truth_bases"] = {"label"};
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan, RejectsInvalidThresholdFamilyGeometryCountsAndRows) {
    RevisionMatrix matrix = Load();
    const auto cells = ThresholdCells(matrix);
    ASSERT_FALSE(cells.empty());

    const RevisionCell timing = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "threshold_timing";
        });
    RevisionCell cell = timing;
    cell.family = "fhe_ind";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.family = "threshold_dblp_fpfn";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.producer = "bench_piccard";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.dataset = "enron";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.axes["k"] = "512";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.axes.erase("u");
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.paper_counts["timing"] = 29;
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing;
    cell.expected_rows.front().attributes["k"] = "32";
    EXPECT_THROW(PlanThresholdRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan, ExhaustivelyPlansAllSixteenBcg12Cells) {
    const RevisionMatrix matrix = Load();
    const auto cells = Bcg12Cells(matrix);
    ASSERT_EQ(cells.size(), 16u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        const bool minhash = cell->family == "bcg12_minhash";
        const std::string suite = minhash ? "bcg12-minhash" : "bcg12-exact";
        const std::string methods =
            minhash ? "bcg12_mh_ec,bcg12_mh_ff"
                    : "bcg12_exact_ec,bcg12_exact_ff";
        const std::string row_status = minhash ? "MEASURED" : "DIAGNOSTIC";

        const RevisionInvocationPlan paper =
            PlanBcg12RevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanBcg12RevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanBcg12RevisionCell(*cell, RevisionRunMode::DryRun);

        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--profile=paper-v1",
            "--suite=" + suite,
            "--methods=" + methods,
            "--k=" + cell->axes.at("k"),
            "--m=64",
            "--n=" + cell->axes.at("n"),
            "--universe=" + cell->axes.at("u"),
            "--trials=30",
            "--seed={seed}",
            "--output={output}/comparison.csv",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--profile=readiness-toy-v1",
            "--suite=" + suite,
            "--methods=" + methods,
            "--k=" + cell->axes.at("k"),
            "--m=64",
            "--n=" + cell->axes.at("n"),
            "--universe=" + cell->axes.at("u"),
            "--trials=1",
            "--seed={seed}",
            "--output={output}/comparison.csv",
        };

        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(toy.cell_id, cell->cell_id);
        EXPECT_EQ(dry_run.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, "bench_review_comparison");
        EXPECT_EQ(toy.producer, "bench_review_comparison");
        EXPECT_EQ(dry_run.producer, "bench_review_comparison");
        EXPECT_EQ(paper.concrete_profile, "paper-v1");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(toy.invocation_status, "RUN");
        EXPECT_EQ(dry_run.invocation_status, "RUN");
        ASSERT_EQ(paper.expected_rows.size(), 2u);
        ASSERT_EQ(toy.expected_rows.size(), 2u);
        ASSERT_EQ(dry_run.expected_rows.size(), 2u);
        for (size_t row_index = 0; row_index < 2u; ++row_index) {
            EXPECT_EQ(paper.expected_rows.at(row_index).status, row_status);
            EXPECT_EQ(toy.expected_rows.at(row_index).status, row_status);
            EXPECT_EQ(dry_run.expected_rows.at(row_index).status, row_status);
            EXPECT_EQ(paper.expected_rows.at(row_index).measured_count,
                      paper.expected_rows.at(row_index).paper_measured_count);
            EXPECT_EQ(toy.expected_rows.at(row_index).measured_count,
                      toy.expected_rows.at(row_index).toy_measured_count);
            EXPECT_EQ(dry_run.expected_rows.at(row_index).measured_count,
                      dry_run.expected_rows.at(row_index).paper_measured_count);
            EXPECT_EQ(paper.expected_rows.at(row_index).paper_measured_count,
                      30u);
            EXPECT_EQ(toy.expected_rows.at(row_index).toy_measured_count, 1u);
        }
        EXPECT_EQ(paper.expected_rows.at(0).method,
                  minhash ? "bcg12_mh_ec" : "bcg12_exact_ec");
        EXPECT_EQ(paper.expected_rows.at(1).method,
                  minhash ? "bcg12_mh_ff" : "bcg12_exact_ff");
        EXPECT_FALSE(HasArg(paper, "--security="));
        EXPECT_FALSE(HasArg(paper, "--raw"));
        EXPECT_FALSE(HasArg(paper, "--fhe"));

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidBcg12IdentityGeometryCountsEligibilityAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = Bcg12Cells(matrix);
    ASSERT_EQ(cells.size(), 16u);

    const RevisionCell minhash_control = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "bcg12_minhash" &&
                   cell->axis == "control";
        });
    const RevisionCell minhash_n100000 = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "bcg12_minhash" &&
                   cell->axis_value == "100000";
        });
    const RevisionCell exact_control = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "bcg12_exact" && cell->axis == "control";
        });

    RevisionCell cell = minhash_control;
    cell.family = "piccard_std128";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.producer = "bench_piccard";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.profile = "readiness-toy-v1";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.dataset = "enron";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.eligibility = "DIAGNOSTIC_ONLY";
    cell.table_eligible = false;
    cell.comparison_eligible = false;
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.axis = "u";
    cell.axis_value = "65536";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.cell_id = "paper-v1::bcg12_minhash::k=128";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.axes.erase("u");
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.axes["m"] = "128";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.axis = "k";
    cell.axis_value = "999";
    cell.cell_id = "paper-v1::bcg12_minhash::k=999";
    cell.axes["k"] = "999";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_n100000;
    cell.axes["u"] = "65536";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.axes["u"] = "262144";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = exact_control;
    cell.axis = "k";
    cell.axis_value = "128";
    cell.cell_id = "paper-v1::bcg12_exact::k=128";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.paper_counts["timing"] = 29;
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.expected_rows.front().method = "wrong";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.expected_rows.back().status = "DIAGNOSTIC";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = minhash_control;
    cell.attributes["unexpected"] = "true";
    EXPECT_THROW(PlanBcg12RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan, ExhaustivelyPlansAllElevenSj16Cells) {
    const RevisionMatrix matrix = Load();
    const auto cells = Sj16Cells(matrix);
    ASSERT_EQ(cells.size(), 11u);

    std::set<std::vector<std::string>> run_paper_argv;
    std::set<std::vector<std::string>> run_toy_argv;
    std::set<std::vector<std::string>> run_dry_run_argv;
    size_t no_spawn_count = 0;
    for (const RevisionCell* cell : cells) {
        SCOPED_TRACE(cell->cell_id);
        const bool no_spawn = cell->invocation_status == "NO_SPAWN";
        const bool fit = cell->axis == "fit";
        const bool per_element = fit && cell->axis_value == "per_element";
        const bool precomputed = fit && cell->axis_value == "precomputed";
        ASSERT_TRUE(!fit || per_element || precomputed);

        const RevisionInvocationPlan paper =
            PlanSj16RevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanSj16RevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanSj16RevisionCell(*cell, RevisionRunMode::DryRun);

        ASSERT_EQ(paper.cell_id, cell->cell_id);
        ASSERT_EQ(toy.cell_id, cell->cell_id);
        ASSERT_EQ(dry_run.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, cell->producer);
        EXPECT_EQ(toy.producer, cell->producer);
        EXPECT_EQ(dry_run.producer, cell->producer);
        EXPECT_EQ(paper.concrete_profile, "paper-v1");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-v1");
        EXPECT_EQ(paper.invocation_status, cell->invocation_status);
        EXPECT_EQ(toy.invocation_status, cell->invocation_status);
        EXPECT_EQ(dry_run.invocation_status, cell->invocation_status);
        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);

        if (no_spawn) {
            ++no_spawn_count;
            EXPECT_TRUE(paper.argv.empty());
            EXPECT_TRUE(toy.argv.empty());
            EXPECT_TRUE(dry_run.argv.empty());
            EXPECT_EQ(paper.expected_rows.front().status, "EXTRAPOLATED");
            EXPECT_EQ(paper.expected_rows.front().reason,
                      "sj16-paillier3072-calibration-bound-v1");
            EXPECT_EQ(paper.expected_rows.front().fit_authority,
                      "per_element");
            EXPECT_EQ(paper.expected_rows.front().measured_count, 0u);
            EXPECT_EQ(toy.expected_rows.front().measured_count, 0u);
            EXPECT_EQ(dry_run.expected_rows.front().measured_count, 0u);
            EXPECT_EQ(paper.expected_rows.front().paper_measured_count, 0u);
            EXPECT_EQ(paper.expected_rows.front().toy_measured_count, 0u);
            continue;
        }

        const std::string paper_trials = "30";
        const std::string toy_trials = "1";
        std::vector<std::string> expected_paper;
        std::vector<std::string> expected_toy;
        if (per_element) {
            expected_paper = {
                "--revision-cell=" + cell->cell_id,
                "--profile=paper-v1",
                "--cell=fit-per-element",
                "--key-bits=3072",
                "--sizes=4096,8192,16384",
                "--held-out=32768",
                "--threads=2",
                "--precomputed=false",
                "--query-trials=" + paper_trials,
                "--enc-iters=" + paper_trials,
                "--warmup=1",
                "--seed={seed}",
                "--output={output}/calibration.csv",
            };
            expected_toy = expected_paper;
            expected_toy[1] = "--profile=readiness-toy-v1";
            expected_toy[8] = "--query-trials=" + toy_trials;
            expected_toy[9] = "--enc-iters=" + toy_trials;
        } else if (precomputed) {
            expected_paper = {
                "--revision-cell=" + cell->cell_id,
                "--profile=paper-v1",
                "--cell=sj16-fit-precomputed",
                "--method=sj16_precomputed",
                "--k=128",
                "--m=64",
                "--n=1000",
                "--universe=65536",
                "--key-bits=3072",
                "--threads=2",
                "--trials=" + paper_trials,
                "--warmup=1",
                "--seed={seed}",
                "--output={output}/comparison.csv",
            };
            expected_toy = expected_paper;
            expected_toy[1] = "--profile=readiness-toy-v1";
            expected_toy[10] = "--trials=" + toy_trials;
        } else {
            expected_paper = {
                "--revision-cell=" + cell->cell_id,
                "--profile=paper-v1",
                "--suite=sj16",
                "--method=sj16",
                "--k=128",
                "--m=64",
                "--n=" + cell->axes.at("n"),
                "--universe=" + cell->axes.at("u"),
                "--key-bits=3072",
                "--threads=2",
                "--trials=" + paper_trials,
                "--seed={seed}",
                "--output={output}/comparison.csv",
            };
            expected_toy = expected_paper;
            expected_toy[1] = "--profile=readiness-toy-v1";
            expected_toy[10] = "--trials=" + toy_trials;
        }
        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        run_paper_argv.insert(paper.argv);
        run_toy_argv.insert(toy.argv);
        run_dry_run_argv.insert(dry_run.argv);

        const RevisionRow& paper_row = paper.expected_rows.front();
        const RevisionRow& toy_row = toy.expected_rows.front();
        EXPECT_EQ(paper_row.measured_count, paper_row.paper_measured_count);
        EXPECT_EQ(toy_row.measured_count, toy_row.toy_measured_count);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count,
                  dry_run.expected_rows.front().paper_measured_count);
        EXPECT_EQ(paper_row.paper_measured_count, 30u);
        EXPECT_EQ(toy_row.toy_measured_count, 1u);
        if (per_element) {
            EXPECT_EQ(paper_row.status, "DIAGNOSTIC");
            EXPECT_EQ(paper_row.method, "bench_sj16_calibrate");
            EXPECT_EQ(cell->attributes.at("fit_authority"), "true");
        } else if (precomputed) {
            EXPECT_EQ(paper_row.status, "DIAGNOSTIC");
            EXPECT_EQ(paper_row.method, "bench_review_comparison");
            EXPECT_EQ(cell->attributes.at("fit_authority"), "false");
        } else {
            EXPECT_EQ(paper_row.status, "MEASURED");
            EXPECT_EQ(paper_row.method, "sj16");
            EXPECT_TRUE(paper_row.fit_authority.empty());
        }
    }
    EXPECT_EQ(no_spawn_count, 3u);
    EXPECT_EQ(run_paper_argv.size(), 8u);
    EXPECT_EQ(run_toy_argv.size(), 8u);
    EXPECT_EQ(run_dry_run_argv.size(), 8u);
}

TEST(RevisionInvocationPlan,
     RejectsInvalidSj16IdentityGeometryCountsAuthorityAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = Sj16Cells(matrix);
    ASSERT_EQ(cells.size(), 11u);

    const RevisionCell measured = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis == "control";
        });
    const RevisionCell extrapolated = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis == "n" && cell->axis_value == "100000";
        });
    const RevisionCell per_element = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis == "fit" && cell->axis_value == "per_element";
        });
    const RevisionCell precomputed = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis == "fit" && cell->axis_value == "precomputed";
        });

    RevisionCell cell = measured;
    cell.family = "bcg12_minhash";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.producer = "bench_sj16_calibrate";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.profile = "readiness-toy-v1";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.dataset = "enron";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.expected_artifact_schema = "sj16-calibration-v1";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.timeout_class = "extended";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.eligibility = "DIAGNOSTIC_ONLY";
    cell.table_eligible = false;
    cell.comparison_eligible = false;
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.cell_id = "paper-v1::sj16::k=128";
    cell.axis = "k";
    cell.axis_value = "128";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.axes.erase("u");
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.axes["m"] = "128";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.axes["k"] = "2048";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.attributes["key_bits"] = "2048";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.attributes["threads"] = "1";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.paper_counts["timing"] = 29;
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.expected_rows.front().method = "wrong";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.expected_rows.front().status = "DIAGNOSTIC";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = measured;
    cell.expected_rows.front().attributes["key_bits"] = "2048";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = extrapolated;
    cell.invocation_status = "RUN";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = extrapolated;
    cell.paper_count = 0;
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = extrapolated;
    cell.expected_rows.front().reason = "wrong-reason";
    cell.expected_rows.front().reason_code = "wrong-reason";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = extrapolated;
    cell.expected_rows.front().fit_authority.clear();
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = per_element;
    cell.attributes["fit_authority"] = "false";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = per_element;
    cell.list_attributes["sizes"].push_back("32768");
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = per_element;
    cell.expected_rows.front().method = "wrong";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = per_element;
    cell.expected_rows.front().attributes["warmup_calls"] = "2";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = precomputed;
    cell.attributes["fit_authority"] = "true";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = precomputed;
    cell.attributes["precomputed"] = "false";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = precomputed;
    cell.expected_rows.front().attributes["k"] = "64";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = precomputed;
    cell.expected_rows.front().method = "wrong";
    EXPECT_THROW(PlanSj16RevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan, ExhaustivelyPlansAllThirtyThreeDynamicCells) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    ASSERT_EQ(cells.size(), 33u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        SCOPED_TRACE(cell->cell_id);
        const bool timing = cell->family == "dynamic_timing";
        const bool accuracy = cell->family == "dynamic_accuracy";
        const bool refresh = cell->family == "dynamic_refresh";
        ASSERT_TRUE(timing || accuracy || refresh);

        const uint64_t paper_trials = accuracy ? 50u : 30u;
        const std::string cell_name =
            timing ? "timing" : (accuracy ? "accuracy" : "refresh");
        const std::string raw_profile =
            "paper-v1";
        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--profile=paper-std128-t40-v1",
            "--cell=" + cell_name,
            "--mode=" + cell_name,
            "--evidence_point",
            "--security=STD128",
            "--k=" + cell->axes.at("k"),
            "--m=" + cell->axes.at("m"),
            "--set_size=" + cell->axes.at("n"),
            "--universe=" + cell->axes.at("u"),
            "--trials=" + std::to_string(paper_trials),
            "--updates=1",
            "--seed={seed}",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--profile=readiness-toy-v1",
            "--cell=" + cell_name,
            "--mode=" + cell_name,
            "--evidence_point",
            "--security=TOY",
            "--k=" + cell->axes.at("k"),
            "--m=" + cell->axes.at("m"),
            "--set_size=" + cell->axes.at("n"),
            "--universe=" + cell->axes.at("u"),
            "--trials=1",
            "--updates=1",
            "--seed={seed}",
        };
        std::vector<std::string> expected_paper_with_raw = expected_paper;
        std::vector<std::string> expected_toy_with_raw = expected_toy;
        if (!accuracy) {
            expected_paper_with_raw.push_back(
                "--raw-timing-dir={output}/raw");
            expected_paper_with_raw.push_back(
                "--raw-timing-profile=" + raw_profile);
            expected_toy_with_raw.push_back(
                "--raw-timing-dir={output}/raw");
            expected_toy_with_raw.push_back(
                "--raw-timing-profile=readiness-toy-v1");
        }

        const RevisionInvocationPlan paper =
            PlanDynamicRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanDynamicRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanDynamicRevisionCell(*cell, RevisionRunMode::DryRun);

        EXPECT_EQ(paper.argv,
                  accuracy ? expected_paper : expected_paper_with_raw);
        EXPECT_EQ(toy.argv,
                  accuracy ? expected_toy : expected_toy_with_raw);
        EXPECT_EQ(dry_run.argv,
                  accuracy ? expected_paper : expected_paper_with_raw);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(toy.cell_id, cell->cell_id);
        EXPECT_EQ(dry_run.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, "bench_dynamic");
        EXPECT_EQ(toy.producer, "bench_dynamic");
        EXPECT_EQ(dry_run.producer, "bench_dynamic");
        EXPECT_EQ(paper.concrete_profile, "paper-std128-t40-v1");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-std128-t40-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(toy.invocation_status, "RUN");
        EXPECT_EQ(dry_run.invocation_status, "RUN");

        ASSERT_EQ(paper.expected_rows.size(), refresh ? 1u : 2u);
        ASSERT_EQ(toy.expected_rows.size(), refresh ? 1u : 2u);
        ASSERT_EQ(dry_run.expected_rows.size(), refresh ? 1u : 2u);
        const std::vector<std::string> expected_row_ids =
            refresh ? std::vector<std::string>{"refresh"}
                    : (accuracy
                           ? std::vector<std::string>{"insert_correctness",
                                                      "delete_correctness"}
                           : std::vector<std::string>{"insert", "delete"});
        for (size_t row_index = 0; row_index < expected_row_ids.size();
             ++row_index) {
            const RevisionRow& paper_row = paper.expected_rows.at(row_index);
            const RevisionRow& toy_row = toy.expected_rows.at(row_index);
            const RevisionRow& dry_row = dry_run.expected_rows.at(row_index);
            EXPECT_EQ(paper_row.row_id, expected_row_ids.at(row_index));
            EXPECT_EQ(toy_row.row_id, expected_row_ids.at(row_index));
            EXPECT_EQ(dry_row.row_id, expected_row_ids.at(row_index));
            EXPECT_EQ(paper_row.status, "MEASURED");
            EXPECT_EQ(toy_row.status, "MEASURED");
            EXPECT_EQ(dry_row.status, "MEASURED");
            EXPECT_EQ(paper_row.terminal_status, "MEASURED");
            EXPECT_EQ(toy_row.terminal_status, "MEASURED");
            EXPECT_EQ(dry_row.terminal_status, "MEASURED");
            EXPECT_TRUE(paper_row.reason.empty());
            EXPECT_TRUE(paper_row.reason_code.empty());
            EXPECT_TRUE(toy_row.reason.empty());
            EXPECT_TRUE(toy_row.reason_code.empty());
            EXPECT_EQ(paper_row.measured_count, paper_trials);
            EXPECT_EQ(paper_row.paper_measured_count, paper_trials);
            EXPECT_EQ(toy_row.measured_count, 1u);
            EXPECT_EQ(toy_row.toy_measured_count, 1u);
            EXPECT_EQ(dry_row.measured_count, paper_trials);
            EXPECT_EQ(dry_row.paper_measured_count, paper_trials);
            const std::map<std::string, std::string> expected_row_attributes =
                refresh
                    ? std::map<std::string, std::string>{{"k", "128"},
                                                          {"m", "64"},
                                                          {"n", "1000"},
                                                          {"updates", "1"}}
                    : std::map<std::string, std::string>{{"updates", "1"}};
            EXPECT_EQ(paper_row.attributes, expected_row_attributes);
            EXPECT_EQ(toy_row.attributes, expected_row_attributes);
            EXPECT_EQ(paper_row.phase, refresh ? "" :
                                                 (row_index == 0 ? "insert"
                                                                  : "delete"));
            if (refresh) {
                EXPECT_EQ(paper_row.method, "refresh");
            } else {
                EXPECT_TRUE(paper_row.method.empty());
            }
        }
        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidDynamicIdentityGeometryCountsEligibilityAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = DynamicCells(matrix);
    ASSERT_EQ(cells.size(), 33u);

    const RevisionCell timing_control = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "dynamic_timing" &&
                   cell->axis == "control";
        });
    const RevisionCell timing_n100000 = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "dynamic_timing" && cell->axis == "n" &&
                   cell->axis_value == "100000";
        });
    const RevisionCell accuracy = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "dynamic_accuracy" &&
                   cell->axis == "control";
        });
    const RevisionCell refresh = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->family == "dynamic_refresh";
        });

    RevisionCell cell = timing_control;
    cell.family = "sj16";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.producer = "bench_piccard";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.profile = "readiness-toy-v1";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.dataset = "enron";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.eligibility = "DIAGNOSTIC_ONLY";
    cell.table_eligible = false;
    cell.comparison_eligible = false;
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.axis = "q";
    cell.axis_value = "default";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.cell_id = "paper-v1::dynamic_timing::control=wrong";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.axes.erase("u");
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.axes["k"] = "256";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.axes["m"] = "128";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_n100000;
    cell.axes["u"] = "65536";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.paper_count = 29;
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.paper_counts["insert"] = 49;
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.attributes["updates"] = "2";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.expected_rows.front().phase = "delete";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.expected_rows.front().attributes["updates"] = "2";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = timing_control;
    cell.expected_rows.pop_back();
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = refresh;
    cell.axis = "k";
    cell.axis_value = "128";
    cell.cell_id = "paper-v1::dynamic_refresh::k=128";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = refresh;
    cell.axes["u"] = "262144";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = refresh;
    cell.object_attributes["refresh_axes"]["n"] = "10000";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = refresh;
    cell.expected_rows.front().method = "wrong";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = refresh;
    cell.expected_rows.front().attributes["k"] = "64";
    EXPECT_THROW(PlanDynamicRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan,
     ExhaustivelyPlansAllThreeFloodingCellsAndSupportedToySelection) {
    const RevisionMatrix matrix = Load();
    const auto cells = FloodingCells(matrix);
    ASSERT_EQ(cells.size(), 3u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    std::set<std::vector<std::string>> toy_argv;
    for (const RevisionCell* cell : cells) {
        SCOPED_TRACE(cell->cell_id);
        ASSERT_EQ(cell->axis, "profile");
        ASSERT_TRUE(cell->axis_value == "primary40" ||
                    cell->axis_value == "sensitivity64" ||
                    cell->axis_value == "feasibility128");

        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--run-profile=paper-v1",
            "--profile=" + cell->axis_value,
            "--repetitions=5",
            "--results-root={output}",
            "--seed={seed}",
            "--threads={threads}",
        };
        const std::vector<std::string> expected_dry_run = expected_paper;

        const RevisionInvocationPlan paper =
            PlanFloodingRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan dry_run =
            PlanFloodingRevisionCell(*cell, RevisionRunMode::DryRun);
        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(dry_run.argv, expected_dry_run);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(dry_run.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, "bench_noise");
        EXPECT_EQ(dry_run.producer, "bench_noise");
        EXPECT_EQ(paper.concrete_profile, "paper-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(dry_run.invocation_status, "RUN");
        EXPECT_FALSE(HasArg(paper, "--resume"));
        EXPECT_FALSE(HasArg(paper, "--smoke"));
        EXPECT_FALSE(HasArg(paper, "--finalize-dir"));
        EXPECT_FALSE(HasArg(paper, "--bench-noise"));
        EXPECT_FALSE(HasArg(dry_run, "--dry-run"));

        ASSERT_EQ(paper.expected_rows.size(), 3u);
        ASSERT_EQ(dry_run.expected_rows.size(), 3u);
        const std::vector<std::string> patterns = {
            "zero", "random", "adversarial"};
        for (size_t row_index = 0; row_index < patterns.size(); ++row_index) {
            const RevisionRow& paper_row = paper.expected_rows.at(row_index);
            const RevisionRow& dry_row = dry_run.expected_rows.at(row_index);
            EXPECT_EQ(paper_row.row_id, patterns.at(row_index));
            EXPECT_EQ(paper_row.pattern, patterns.at(row_index));
            EXPECT_EQ(dry_row.row_id, patterns.at(row_index));
            EXPECT_EQ(dry_row.pattern, patterns.at(row_index));
            EXPECT_EQ(paper_row.status, "DIAGNOSTIC");
            EXPECT_EQ(paper_row.terminal_status, "DIAGNOSTIC");
            EXPECT_EQ(dry_row.status, "DIAGNOSTIC");
            EXPECT_EQ(dry_row.terminal_status, "DIAGNOSTIC");
            EXPECT_EQ(paper_row.timing_contract, "NOT_APPLICABLE");
            EXPECT_EQ(dry_row.timing_contract, "NOT_APPLICABLE");
            EXPECT_TRUE(paper_row.reason.empty());
            EXPECT_TRUE(paper_row.reason_code.empty());
            EXPECT_TRUE(dry_row.reason.empty());
            EXPECT_TRUE(dry_row.reason_code.empty());
            EXPECT_EQ(paper_row.measured_count, 5u);
            EXPECT_EQ(paper_row.paper_measured_count, 5u);
            EXPECT_EQ(paper_row.toy_measured_count, 1u);
            EXPECT_EQ(dry_row.measured_count, 5u);
            EXPECT_TRUE(paper_row.method.empty());
            EXPECT_TRUE(dry_row.method.empty());
            EXPECT_TRUE(paper_row.attributes.empty());
            EXPECT_TRUE(paper_row.list_attributes.empty());
        }

        paper_argv.insert(paper.argv);
        dry_run_argv.insert(dry_run.argv);

        if (cell->axis_value != "primary40") {
            EXPECT_THROW(PlanFloodingRevisionCell(*cell, RevisionRunMode::Toy),
                         std::invalid_argument);
            continue;
        }

        const RevisionInvocationPlan toy =
            PlanFloodingRevisionCell(*cell, RevisionRunMode::Toy);
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--run-profile=readiness-toy-v1",
            "--profile=primary40",
            "--repetitions=1",
            "--results-root={output}",
            "--seed={seed}",
            "--threads={threads}",
        };
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(toy.cell_id, cell->cell_id);
        EXPECT_EQ(toy.producer, "bench_noise");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(toy.invocation_status, "RUN");
        EXPECT_FALSE(HasArg(toy, "--dry-run"));
        EXPECT_FALSE(HasArg(toy, "--resume"));
        EXPECT_FALSE(HasArg(toy, "--smoke"));
        EXPECT_FALSE(HasArg(toy, "--finalize-dir"));
        EXPECT_FALSE(HasArg(toy, "--bench-noise"));
        ASSERT_EQ(toy.expected_rows.size(), 3u);
        for (const RevisionRow& toy_row : toy.expected_rows) {
            EXPECT_EQ(toy_row.measured_count, 1u);
            EXPECT_EQ(toy_row.toy_measured_count, 1u);
            EXPECT_EQ(toy_row.paper_measured_count, 5u);
        }
        toy_argv.insert(toy.argv);
    }

    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), 1u);
}

TEST(RevisionInvocationPlan,
     RejectsInvalidFloodingIdentityCountsRowsAndUnsupportedToyProfiles) {
    const RevisionMatrix matrix = Load();
    const auto cells = FloodingCells(matrix);
    ASSERT_EQ(cells.size(), 3u);
    const RevisionCell primary = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis_value == "primary40";
        });
    const RevisionCell sensitivity = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis_value == "sensitivity64";
        });

    RevisionCell cell = primary;
    cell.family = "dynamic_timing";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.producer = "bench_dynamic";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.profile = "readiness-toy-v1";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.dataset = "enron";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.eligibility = "TABLE_ELIGIBLE";
    cell.table_eligible = true;
    cell.comparison_eligible = true;
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.axis = "control";
    cell.axis_value = "default";
    cell.cell_id = "paper-v1::flooding::control=default";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.axis_value = "primary41";
    cell.cell_id = "paper-v1::flooding::profile=primary41";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.axes.erase("u");
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.axes["k"] = "256";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.axes["u"] = "262144";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.paper_count = 4;
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.paper_counts["repetitions_per_pattern"] = 4;
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.attributes["noise_profile"] = "sensitivity64";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.attributes["timing_contract"] = "full-query";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.expected_rows.front().pattern = "random";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.expected_rows.front().timing_contract = "full-query";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.expected_rows.front().status = "MEASURED";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.expected_rows.front().row_id = "wrong";
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = primary;
    cell.expected_rows.pop_back();
    EXPECT_THROW(PlanFloodingRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    EXPECT_THROW(PlanFloodingRevisionCell(sensitivity, RevisionRunMode::Toy),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan,
     ExhaustivelyPlansAllRealDatasetAccuracyAndSummaryCellsAcrossModes) {
    const RevisionMatrix matrix = Load();
    const auto cells = RealDatasetAccuracySummaryCells(matrix);
    ASSERT_EQ(cells.size(), 6u);

    std::set<std::string> cell_ids;
    std::set<std::vector<std::string>> accuracy_argv;
    std::set<std::vector<std::string>> summary_argv;
    for (const RevisionCell* cell : cells) {
        SCOPED_TRACE(cell->cell_id);
        ASSERT_TRUE(cell_ids.insert(cell->cell_id).second);
        const bool accuracy = cell->axis_value == "accuracy";
        const std::string variant = cell->axes.at("variant");

        const std::vector<std::string> expected_argv = accuracy
            ? std::vector<std::string>{
                  "--revision-cell=" + cell->cell_id,
                  "--mode=accuracy",
                  "--dataset-manifest={variant_manifest}",
                  "--max-pairs={max_pairs}",
                  "--seed={seed}",
                  "--csv={output}/accuracy.csv",
                  "--workload-manifest-out={output}/accuracy.manifest.tsv",
                  "--workload-rows-out={output}/accuracy.rows.tsv",
              }
            : std::vector<std::string>{
                  "--revision-cell=" + cell->cell_id,
                  "--accuracy-csv={output}/accuracy.csv",
                  "--output={output}/summary.csv",
                  "--variant=" + variant,
              };

        const RevisionInvocationPlan paper =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::DryRun);

        EXPECT_EQ(paper.argv, expected_argv);
        EXPECT_EQ(toy.argv, expected_argv);
        EXPECT_EQ(dry_run.argv, expected_argv);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(toy.cell_id, cell->cell_id);
        EXPECT_EQ(dry_run.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer,
                  accuracy ? "bench_real_datasets"
                           : "summarize_real_datasets.py");
        EXPECT_EQ(toy.producer, paper.producer);
        EXPECT_EQ(dry_run.producer, paper.producer);
        EXPECT_EQ(paper.concrete_profile, "paper-v1");
        EXPECT_EQ(toy.concrete_profile, "paper-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(toy.invocation_status, "RUN");
        EXPECT_EQ(dry_run.invocation_status, "RUN");
        EXPECT_FALSE(HasArg(paper, "--security="));
        EXPECT_FALSE(HasArg(paper, "--fhe"));
        EXPECT_FALSE(HasArg(paper, "--threshold"));

        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);
        for (const RevisionInvocationPlan* plan : {&paper, &toy, &dry_run}) {
            const RevisionRow& row = plan->expected_rows.front();
            EXPECT_EQ(row.row_id, cell->axis_value);
            EXPECT_EQ(row.status, "MEASURED");
            EXPECT_EQ(row.terminal_status, "MEASURED");
            EXPECT_TRUE(row.reason.empty());
            EXPECT_TRUE(row.reason_code.empty());
            EXPECT_EQ(row.method, cell->axis_value);
            EXPECT_EQ(row.variant, variant);
            EXPECT_TRUE(row.timing_contract.empty());
            EXPECT_TRUE(row.raw_timing_contract.empty());
            EXPECT_TRUE(row.phase.empty());
            EXPECT_TRUE(row.pattern.empty());
            EXPECT_TRUE(row.fit_authority.empty());
            EXPECT_TRUE(row.truth_bases.empty());
            EXPECT_TRUE(row.field_values.empty());
            EXPECT_TRUE(row.attributes.empty());
            EXPECT_TRUE(row.list_attributes.empty());
            EXPECT_EQ(row.measured_count, 1u);
            EXPECT_EQ(row.paper_measured_count, 1u);
            EXPECT_EQ(row.toy_measured_count, 1u);
        }

        if (accuracy) {
            accuracy_argv.insert(paper.argv);
        } else {
            summary_argv.insert(paper.argv);
        }
    }

    EXPECT_EQ(cell_ids.size(), 6u);
    EXPECT_EQ(accuracy_argv.size(), 3u);
    EXPECT_EQ(summary_argv.size(), 3u);
}

TEST(RevisionInvocationPlan,
     RejectsInvalidRealDatasetAccuracyAndSummaryIdentityAxesCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = RealDatasetAccuracySummaryCells(matrix);
    ASSERT_EQ(cells.size(), 6u);
    const RevisionCell accuracy = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis_value == "accuracy" &&
                   cell->axes.at("variant") == "dblp_acm_u65536";
        });
    const RevisionCell summary = **std::find_if(
        cells.begin(), cells.end(), [](const RevisionCell* cell) {
            return cell->axis_value == "summary" &&
                   cell->axes.at("variant") == "enron_u1048576";
        });

    RevisionCell cell = accuracy;
    cell.family = "piccard_std128";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.producer = "summarize_real_datasets.py";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.profile = "readiness-toy-v1";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.dataset = "enron";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.axis = "artifact";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.axis_value = "summary";
    cell.cell_id = "paper-v1::real_dataset::dblp_acm_u65536_artifact=summary";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.cell_id = "paper-v1::real_dataset::dblp_acm_u65536_artifact=wrong";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.axes["variant"] = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.axes["u"] = "1048576";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.axes.erase("m");
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.axes["k"] = "256";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.attributes["variant"] = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.attributes["artifact_kind"] = "summary";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.attributes["threshold_forbidden"] = "true";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.paper_count = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.toy_count = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = accuracy;
    cell.paper_counts["accuracy"] = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.toy_counts["accuracy"] = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = accuracy;
    cell.expected_rows.front().row_id = "summary";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.expected_rows.front().method = "summary";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.expected_rows.front().variant = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.expected_rows.front().status = "DIAGNOSTIC";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = accuracy;
    cell.expected_rows.pop_back();
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = summary;
    cell.producer = "bench_real_datasets";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = summary;
    cell.axes["u"] = "65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = summary;
    cell.paper_counts["summary"] = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = summary;
    cell.expected_rows.front().variant = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan,
     ExhaustivelyPlansAllRealDatasetStd128TimingCellsAcrossModes) {
    const RevisionMatrix matrix = Load();
    const auto cells = RealDatasetTimingCells(matrix);
    ASSERT_EQ(cells.size(), 3u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        SCOPED_TRACE(cell->cell_id);
        const std::string variant = cell->axes.at("variant");
        const std::string universe = cell->axes.at("u");
        ASSERT_TRUE(variant == "dblp_acm_u65536" ||
                    variant == "enron_u65536" ||
                    variant == "enron_u1048576");
        ASSERT_TRUE(universe == "65536" || universe == "1048576");

        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--mode=timing",
            "--dataset-manifest={variant_manifest}",
            "--profile=paper-std128-t40-v1",
            "--security=STD128",
            "--k=128",
            "--m=64",
            "--trials=30",
            "--seed={seed}",
            "--raw-timing-dir={output}/raw",
            "--raw-timing-profile=paper-v1",
            "--csv={output}/timing.csv",
            "--workload-manifest-out={output}/timing.manifest.tsv",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--mode=timing",
            "--dataset-manifest={variant_manifest}",
            "--profile=readiness-toy-v1",
            "--security=TOY",
            "--k=128",
            "--m=64",
            "--trials=1",
            "--seed={seed}",
            "--raw-timing-dir={output}/raw",
            "--raw-timing-profile=readiness-toy-v1",
            "--csv={output}/timing.csv",
            "--workload-manifest-out={output}/timing.manifest.tsv",
        };

        const RevisionInvocationPlan paper =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::DryRun);
        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.producer, "bench_real_datasets");
        EXPECT_EQ(toy.producer, "bench_real_datasets");
        EXPECT_EQ(dry_run.producer, "bench_real_datasets");
        EXPECT_EQ(paper.concrete_profile, "paper-std128-t40-v1");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-std128-t40-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(toy.invocation_status, "RUN");
        EXPECT_EQ(dry_run.invocation_status, "RUN");
        EXPECT_FALSE(HasArg(paper, "--dry-run"));
        EXPECT_FALSE(HasArg(toy, "--dry-run"));
        EXPECT_FALSE(HasArg(paper, "--resume"));
        EXPECT_FALSE(HasArg(paper, "--smoke"));
        EXPECT_FALSE(HasArg(paper, "--finalize-dir"));

        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);
        EXPECT_EQ(paper.expected_rows.front().row_id, "std128_timing");
        EXPECT_EQ(paper.expected_rows.front().status, "MEASURED");
        EXPECT_EQ(paper.expected_rows.front().method, "std128_timing");
        EXPECT_EQ(paper.expected_rows.front().variant, variant);
        EXPECT_EQ(paper.expected_rows.front().measured_count, 30u);
        EXPECT_EQ(paper.expected_rows.front().paper_measured_count, 30u);
        EXPECT_EQ(paper.expected_rows.front().toy_measured_count, 1u);
        EXPECT_EQ(toy.expected_rows.front().measured_count, 1u);
        EXPECT_EQ(toy.expected_rows.front().paper_measured_count, 30u);
        EXPECT_EQ(toy.expected_rows.front().toy_measured_count, 1u);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count, 30u);

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidRealDatasetStd128TimingIdentityAxesCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = RealDatasetTimingCells(matrix);
    ASSERT_EQ(cells.size(), 3u);
    const RevisionCell source = *cells.front();

    RevisionCell cell = source;
    cell.family = "real_dataset_other";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.producer = "summarize_real_datasets.py";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.profile = "readiness-toy-v1";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.dataset = "enron";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis = "control";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis_value = "accuracy";
    cell.cell_id = "paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.cell_id =
        "paper-v1::real_dataset::dblp_acm_u65536_artifact=std128_wrong";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["variant"] = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["u"] = "1048576";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["k"] = "256";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes.erase("m");
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["variant"] = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["artifact_kind"] = "accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["threshold_forbidden"] =
        source.attributes.at("threshold_forbidden") == "true" ? "false"
                                                                  : "true";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_count = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_trials = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts["std128_timing"] = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.toy_count = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.toy_trials = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.toy_counts["std128_timing"] = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().row_id = "accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().method = "accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().variant = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().status = "DIAGNOSTIC";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().measured_count = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.pop_back();
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

}

TEST(RevisionInvocationPlan,
     ExhaustivelyPlansAllRealDatasetStd192EncodingCellsAcrossModes) {
    const RevisionMatrix matrix = Load();
    const auto cells = RealDatasetEncodingCells(matrix);
    ASSERT_EQ(cells.size(), 3u);

    std::set<std::vector<std::string>> paper_argv;
    std::set<std::vector<std::string>> toy_argv;
    std::set<std::vector<std::string>> dry_run_argv;
    for (const RevisionCell* cell : cells) {
        SCOPED_TRACE(cell->cell_id);
        const std::string variant = cell->axes.at("variant");
        const std::string universe = cell->axes.at("u");
        ASSERT_TRUE(variant == "dblp_acm_u65536" ||
                    variant == "enron_u65536" ||
                    variant == "enron_u1048576");
        ASSERT_TRUE(universe == "65536" || universe == "1048576");

        const std::vector<std::string> expected_paper = {
            "--revision-cell=" + cell->cell_id,
            "--mode=encoding",
            "--dataset-manifest={variant_manifest}",
            "--profile=paper-std192-encoding-v1",
            "--methods=onehot,sqrt",
            "--k=128",
            "--m=64",
            "--encoding-iters=30",
            "--correctness-trials=1",
            "--seed={seed}",
            "--csv={output}/encoding.csv",
            "--workload-manifest-out={output}/encoding.manifest.tsv",
        };
        const std::vector<std::string> expected_toy = {
            "--revision-cell=" + cell->cell_id,
            "--mode=encoding",
            "--dataset-manifest={variant_manifest}",
            "--profile=readiness-toy-v1",
            "--methods=onehot,sqrt",
            "--k=128",
            "--m=64",
            "--encoding-iters=1",
            "--correctness-trials=1",
            "--seed={seed}",
            "--csv={output}/encoding.csv",
            "--workload-manifest-out={output}/encoding.manifest.tsv",
        };

        const RevisionInvocationPlan paper =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Paper);
        const RevisionInvocationPlan toy =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Toy);
        const RevisionInvocationPlan dry_run =
            PlanRealDatasetRevisionCell(*cell, RevisionRunMode::DryRun);
        EXPECT_EQ(paper.argv, expected_paper);
        EXPECT_EQ(toy.argv, expected_toy);
        EXPECT_EQ(dry_run.argv, expected_paper);
        EXPECT_EQ(paper.cell_id, cell->cell_id);
        EXPECT_EQ(toy.cell_id, cell->cell_id);
        EXPECT_EQ(dry_run.cell_id, cell->cell_id);
        EXPECT_EQ(paper.producer, "bench_real_datasets");
        EXPECT_EQ(toy.producer, "bench_real_datasets");
        EXPECT_EQ(dry_run.producer, "bench_real_datasets");
        EXPECT_EQ(paper.concrete_profile, "paper-std192-encoding-v1");
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(dry_run.concrete_profile, "paper-std192-encoding-v1");
        EXPECT_EQ(paper.invocation_status, "RUN");
        EXPECT_EQ(toy.invocation_status, "RUN");
        EXPECT_EQ(dry_run.invocation_status, "RUN");

        for (const RevisionInvocationPlan* plan : {&paper, &toy, &dry_run}) {
            EXPECT_FALSE(HasArg(*plan, "--security="));
            EXPECT_FALSE(HasArg(*plan, "--fhe"));
            EXPECT_FALSE(HasArg(*plan, "--raw-timing"));
            EXPECT_FALSE(HasArg(*plan, "--context"));
            EXPECT_FALSE(HasArg(*plan, "--keygen"));
            EXPECT_FALSE(HasArg(*plan, "--key"));
            EXPECT_FALSE(HasArg(*plan, "--dry-run"));
        }

        ASSERT_EQ(paper.expected_rows.size(), 1u);
        ASSERT_EQ(toy.expected_rows.size(), 1u);
        ASSERT_EQ(dry_run.expected_rows.size(), 1u);
        for (const RevisionInvocationPlan* plan : {&paper, &toy, &dry_run}) {
            const RevisionRow& row = plan->expected_rows.front();
            EXPECT_EQ(row.row_id, "std192_encoding");
            EXPECT_EQ(row.status, "DIAGNOSTIC");
            EXPECT_EQ(row.terminal_status, "DIAGNOSTIC");
            EXPECT_TRUE(row.reason.empty());
            EXPECT_TRUE(row.reason_code.empty());
            EXPECT_EQ(row.method, "std192_encoding");
            EXPECT_EQ(row.variant, variant);
            EXPECT_TRUE(row.timing_contract.empty());
            EXPECT_TRUE(row.raw_timing_contract.empty());
            EXPECT_TRUE(row.phase.empty());
            EXPECT_TRUE(row.pattern.empty());
            EXPECT_TRUE(row.fit_authority.empty());
            EXPECT_TRUE(row.truth_bases.empty());
            EXPECT_TRUE(row.field_values.empty());
            EXPECT_TRUE(row.attributes.empty());
            EXPECT_TRUE(row.list_attributes.empty());
            EXPECT_EQ(row.paper_measured_count, 30u);
            EXPECT_EQ(row.toy_measured_count, 1u);
        }
        EXPECT_EQ(paper.expected_rows.front().measured_count, 30u);
        EXPECT_EQ(toy.expected_rows.front().measured_count, 1u);
        EXPECT_EQ(dry_run.expected_rows.front().measured_count, 30u);

        paper_argv.insert(paper.argv);
        toy_argv.insert(toy.argv);
        dry_run_argv.insert(dry_run.argv);
    }
    EXPECT_EQ(paper_argv.size(), cells.size());
    EXPECT_EQ(toy_argv.size(), cells.size());
    EXPECT_EQ(dry_run_argv.size(), cells.size());
}

TEST(RevisionInvocationPlan,
     RejectsInvalidRealDatasetStd192EncodingIdentityAxesCountsAndRows) {
    const RevisionMatrix matrix = Load();
    const auto cells = RealDatasetEncodingCells(matrix);
    ASSERT_EQ(cells.size(), 3u);
    const RevisionCell source = *cells.front();

    RevisionCell cell = source;
    cell.family = "real_dataset_other";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.producer = "summarize_real_datasets.py";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.profile = "readiness-toy-v1";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.dataset = "enron";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_artifact_schema = "wrong-schema";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.invocation_status = "NO_SPAWN";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.eligibility = "TABLE_ELIGIBLE";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.table_eligible = true;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.comparison_eligible = true;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis = "artifact";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axis_value = "accuracy";
    cell.cell_id = "paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.cell_id =
        "paper-v1::real_dataset::dblp_acm_u65536_artifact=std192_wrong";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["variant"] = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["u"] = "1048576";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["k"] = "256";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes.erase("m");
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.axes["n"] = "10000";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["variant"] = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["artifact_kind"] = "accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.attributes["threshold_forbidden"] =
        source.attributes.at("threshold_forbidden") == "true" ? "false"
                                                                  : "true";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.list_attributes["unexpected"] = {"value"};
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.object_attributes["unexpected"]["key"] = "value";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_count = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_trials = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts["std192_encoding"] = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts.erase("correctness");
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.paper_counts["correctness"] = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.toy_count = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.toy_trials = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.toy_counts["std192_encoding"] = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.toy_counts.erase("correctness");
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().row_id = "accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().method = "accuracy";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().variant = "enron_u65536";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().status = "MEASURED";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().terminal_status = "MEASURED";
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().measured_count = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().paper_measured_count = 29;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.front().toy_measured_count = 2;
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Toy),
                 std::invalid_argument);

    cell = source;
    cell.expected_rows.pop_back();
    EXPECT_THROW(PlanRealDatasetRevisionCell(cell, RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(RevisionInvocationPlan,
     DispatchesEveryValidatedCellAcrossPaperAndDryRunWithoutSpawning) {
    const RevisionMatrix matrix = Load();
    ASSERT_EQ(matrix.cells.size(), 263u);

    std::set<std::string> paper_ids;
    std::set<std::string> dry_run_ids;
    std::map<std::string, std::vector<std::string>> paper_argv_by_id;
    std::vector<std::string> previous_paper_argv;
    std::vector<std::string> previous_dry_run_argv;
    size_t run_count = 0;
    size_t no_spawn_count = 0;

    for (const RevisionCell& cell : matrix.cells) {
        SCOPED_TRACE(cell.cell_id);
        for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                           RevisionRunMode::DryRun}) {
            const RevisionInvocationPlan plan = PlanRevisionCell(cell, mode);
            const bool dry_run = mode == RevisionRunMode::DryRun;
            auto& plan_ids = dry_run ? dry_run_ids : paper_ids;
            auto& previous_argv =
                dry_run ? previous_dry_run_argv : previous_paper_argv;

            ASSERT_TRUE(plan_ids.insert(plan.cell_id).second);
            EXPECT_EQ(plan.cell_id, cell.cell_id);
            EXPECT_EQ(plan.producer, cell.producer);
            EXPECT_EQ(plan.family, cell.family);
            EXPECT_EQ(plan.abstract_profile, cell.profile);
            EXPECT_EQ(plan.timeout_class, cell.timeout_class);
            EXPECT_EQ(plan.expected_artifact_schema,
                      cell.expected_artifact_schema);
            const std::string expected_executable =
                cell.family == "flooding"
                    ? "scripts/run_noise_profiles.sh"
                    : (cell.family == "real_dataset" &&
                               cell.axis_value == "summary"
                           ? "scripts/summarize_real_datasets.py"
                           : cell.producer);
            EXPECT_EQ(plan.executable, expected_executable);
            EXPECT_EQ(plan.environment.at("OMP_DYNAMIC"), "FALSE");
            EXPECT_EQ(plan.environment.at("OMP_NUM_THREADS"),
                      cell.family == "sj16" ? "2" : "{threads}");
            EXPECT_EQ(plan.invocation_status, cell.invocation_status);
            ASSERT_EQ(plan.expected_rows.size(), cell.expected_rows.size());

            for (size_t row_index = 0; row_index < plan.expected_rows.size();
                 ++row_index) {
                const RevisionRow& source_row =
                    cell.expected_rows.at(row_index);
                const RevisionRow& planned_row =
                    plan.expected_rows.at(row_index);
                EXPECT_EQ(planned_row.row_id, source_row.row_id);
                if (cell.invocation_status == "RUN") {
                    EXPECT_EQ(planned_row.measured_count,
                              source_row.paper_measured_count);
                } else {
                    EXPECT_EQ(planned_row.status, "EXTRAPOLATED");
                    EXPECT_EQ(planned_row.terminal_status, "EXTRAPOLATED");
                    EXPECT_EQ(planned_row.measured_count, 0u);
                }
            }

            if (cell.invocation_status == "RUN") {
                if (!dry_run) ++run_count;
                ASSERT_FALSE(plan.argv.empty());
                EXPECT_EQ(plan.argv.front(),
                          "--revision-cell=" + cell.cell_id);
                EXPECT_EQ(std::count(plan.argv.begin(), plan.argv.end(),
                                     "--revision-cell=" + cell.cell_id),
                          1);
                if (!previous_argv.empty()) {
                    EXPECT_NE(plan.argv, previous_argv);
                }
                previous_argv = plan.argv;
            } else {
                if (!dry_run) ++no_spawn_count;
                EXPECT_TRUE(plan.argv.empty());
                EXPECT_TRUE(previous_argv.empty() ||
                            previous_argv != plan.argv);
            }
            if (dry_run) {
                ASSERT_EQ(paper_argv_by_id.count(cell.cell_id), 1u);
                EXPECT_EQ(plan.argv, paper_argv_by_id.at(cell.cell_id));
                EXPECT_EQ(plan.environment.at("PICCARD_REVISION_DRY_RUN"),
                          "1");
                if (cell.family == "flooding") {
                    EXPECT_EQ(plan.environment.at("DRY_RUN"), "1");
                } else {
                    EXPECT_EQ(plan.environment.count("DRY_RUN"), 0u);
                }
            } else {
                paper_argv_by_id[cell.cell_id] = plan.argv;
                EXPECT_EQ(plan.environment.count("PICCARD_REVISION_DRY_RUN"),
                          0u);
                EXPECT_EQ(plan.environment.count("DRY_RUN"), 0u);
            }
        }
    }

    EXPECT_EQ(run_count, 260u);
    EXPECT_EQ(no_spawn_count, 3u);
    EXPECT_EQ(paper_ids.size(), 263u);
    EXPECT_EQ(dry_run_ids.size(), 263u);
}

TEST(RevisionInvocationPlan,
     DispatchesExactlyTheExecutableToyFixtureAndPreservesNoFheEncoding) {
    const RevisionMatrix matrix = Load();
    const std::vector<std::string> executable_ids =
        ReadFixtureLines("executable_toy_cell_ids.txt");
    ASSERT_EQ(executable_ids.size(), 104u);

    std::set<std::string> plan_ids;
    std::vector<std::string> previous_argv;
    for (const std::string& cell_id : executable_ids) {
        const auto cell_it = std::find_if(
            matrix.cells.begin(), matrix.cells.end(),
            [&](const RevisionCell& cell) { return cell.cell_id == cell_id; });
        ASSERT_NE(cell_it, matrix.cells.end()) << cell_id;
        const RevisionCell& cell = *cell_it;
        ASSERT_EQ(cell.invocation_status, "RUN") << cell_id;

        const RevisionInvocationPlan plan =
            PlanRevisionCell(cell, RevisionRunMode::Toy);
        SCOPED_TRACE(cell.cell_id);
        ASSERT_TRUE(plan_ids.insert(plan.cell_id).second);
        EXPECT_EQ(plan.cell_id, cell.cell_id);
        EXPECT_EQ(plan.producer, cell.producer);
        EXPECT_EQ(plan.family, cell.family);
        EXPECT_EQ(plan.abstract_profile, cell.profile);
        EXPECT_EQ(plan.timeout_class, cell.timeout_class);
        EXPECT_EQ(plan.expected_artifact_schema,
                  cell.expected_artifact_schema);
        const std::string expected_executable =
            cell.family == "flooding"
                ? "scripts/run_noise_profiles.sh"
                : (cell.family == "real_dataset" &&
                           cell.axis_value == "summary"
                       ? "scripts/summarize_real_datasets.py"
                       : cell.producer);
        EXPECT_EQ(plan.executable, expected_executable);
        EXPECT_EQ(plan.environment.at("OMP_DYNAMIC"), "FALSE");
        EXPECT_EQ(plan.environment.at("OMP_NUM_THREADS"),
                  cell.family == "sj16" ? "2" : "{threads}");
        EXPECT_EQ(plan.environment.count("PICCARD_REVISION_DRY_RUN"), 0u);
        EXPECT_EQ(plan.environment.count("DRY_RUN"), 0u);
        EXPECT_EQ(plan.invocation_status, "RUN");
        ASSERT_FALSE(plan.argv.empty());
        EXPECT_EQ(plan.argv.front(), "--revision-cell=" + cell.cell_id);
        EXPECT_EQ(std::count(plan.argv.begin(), plan.argv.end(),
                             "--revision-cell=" + cell.cell_id),
                  1);
        if (!previous_argv.empty()) EXPECT_NE(plan.argv, previous_argv);
        previous_argv = plan.argv;

        ASSERT_EQ(plan.expected_rows.size(), cell.expected_rows.size());
        for (size_t row_index = 0; row_index < plan.expected_rows.size();
             ++row_index) {
            const RevisionRow& source_row = cell.expected_rows.at(row_index);
            const RevisionRow& planned_row = plan.expected_rows.at(row_index);
            EXPECT_EQ(planned_row.row_id, source_row.row_id);
            EXPECT_LE(planned_row.measured_count, 1u);
            EXPECT_EQ(planned_row.measured_count,
                      source_row.toy_measured_count);
            if (source_row.toy_measured_count == 0u) {
                EXPECT_EQ(planned_row.measured_count, 0u);
            }
        }

        if (cell.family == "real_dataset" &&
            cell.axis_value == "std192_encoding") {
            EXPECT_FALSE(HasArg(plan, "--security="));
            EXPECT_FALSE(HasArg(plan, "--fhe"));
            EXPECT_FALSE(HasArg(plan, "--context"));
            EXPECT_FALSE(HasArg(plan, "--keygen"));
            EXPECT_FALSE(HasArg(plan, "--key"));
        }
    }
    EXPECT_EQ(plan_ids.size(), 104u);
}

TEST(RevisionInvocationPlan, RejectsUnknownFamilyBeforeAnyProducerPlanning) {
    RevisionMatrix matrix = Load();
    ASSERT_FALSE(matrix.cells.empty());
    RevisionCell unknown = matrix.cells.front();
    unknown.family = "unknown_revision_family";
    EXPECT_THROW(PlanRevisionCell(unknown, RevisionRunMode::Paper),
                 std::invalid_argument);
}
