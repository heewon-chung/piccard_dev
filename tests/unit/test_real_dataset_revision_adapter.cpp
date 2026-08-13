#include "real_dataset_revision_adapter.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace {

using namespace piccard::benchmark;

RevisionMatrix Load() {
    return LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

const RevisionCell* Find(const RevisionMatrix& matrix, const std::string& id) {
    const auto it = std::find_if(
        matrix.cells.begin(), matrix.cells.end(),
        [&](const RevisionCell& cell) { return cell.cell_id == id; });
    EXPECT_NE(it, matrix.cells.end());
    return it == matrix.cells.end() ? nullptr : &*it;
}

std::vector<const RevisionCell*> Cells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> result;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "real_dataset" ||
            cell.family == "threshold_dblp_fpfn") {
            result.push_back(&cell);
        }
    }
    return result;
}

TEST(RealDatasetRevisionAdapter,
     SelectsEveryCppRealCellAcrossPaperToyAndDryRunWithoutExecution) {
    const RevisionMatrix matrix = Load();
    const auto cells = Cells(matrix);
    ASSERT_EQ(cells.size(), 13u);
    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy,
                                       RevisionRunMode::DryRun}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const RevisionInvocationPlan plan =
                cell->family == "real_dataset"
                    ? PlanRealDatasetRevisionCell(*cell, mode)
                    : PlanThresholdRevisionCell(*cell, mode);
            const auto request = ParseRealDatasetRevisionArgs(plan.argv);
            const auto selection =
                SelectRealDatasetRevisionCell(matrix, request, mode);
            EXPECT_EQ(selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(selection.plan.argv, plan.argv);
            EXPECT_EQ(request.revision_cell, cell->cell_id);
            if (!IsRealDatasetSummaryCell(*cell)) {
                const auto execution = PlanRealDatasetRevisionExecution(
                    matrix, plan.argv, mode);
                EXPECT_EQ(execution.selected_cell_count, 1u);
                EXPECT_EQ(execution.expected_row_count, 1u);
                EXPECT_EQ(execution.keygen_calls, 0u);
                EXPECT_FALSE(execution.native_sweep);
                EXPECT_EQ(execution.encoding_only,
                          cell->family == "real_dataset" &&
                              cell->axis_value == "std192_encoding");
            }
        }
    }
}

TEST(RealDatasetRevisionAdapter,
     SummaryIsExplicitlyOwnedByPythonSummarizerAndCannotRunInCpp) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell = Find(
        matrix,
        "paper-v1::real_dataset::dblp_acm_u65536_artifact=summary");
    ASSERT_NE(cell, nullptr);
    ASSERT_TRUE(IsRealDatasetSummaryCell(*cell));
    const auto plan = PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Toy);
    EXPECT_EQ(plan.concrete_profile, "not-applicable");
    EXPECT_TRUE(std::none_of(
        plan.argv.begin(), plan.argv.end(),
        [](const std::string& arg) { return arg.rfind("--profile=", 0) == 0; }));
    EXPECT_THROW(PlanRealDatasetRevisionExecution(matrix, plan.argv,
                                                   RevisionRunMode::Toy),
                 std::invalid_argument);
}

TEST(RealDatasetRevisionAdapter,
     RuntimePathsAndSeedCanonicalizeToPlannerPlaceholders) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell = Find(
        matrix,
        "paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy");
    ASSERT_NE(cell, nullptr);
    const auto plan = PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Toy);
    auto runtime = plan.argv;
    for (std::string& arg : runtime) {
        if (arg == "--dataset-manifest={variant_manifest}") {
            arg = "--dataset-manifest=/tmp/processed/dblp_acm_u65536/dataset.manifest.tsv";
        } else if (arg == "--seed={seed}") {
            arg = "--seed=7";
        } else if (arg == "--max-pairs={max_pairs}") {
            arg = "--max-pairs=2";
        } else if (arg == "--csv={output}/accuracy.csv") {
            arg = "--csv=/tmp/results/accuracy.csv";
        } else if (arg == "--workload-manifest-out={output}/accuracy.manifest.tsv") {
            arg = "--workload-manifest-out=/tmp/results/accuracy.manifest.tsv";
        } else if (arg == "--workload-rows-out={output}/accuracy.rows.tsv") {
            arg = "--workload-rows-out=/tmp/results/accuracy.rows.tsv";
        }
    }
    const auto request = ParseRealDatasetRevisionArgs(runtime);
    const auto selection =
        SelectRealDatasetRevisionCell(matrix, request, RevisionRunMode::Toy);
    EXPECT_EQ(selection.cell.cell_id, cell->cell_id);
}

TEST(RealDatasetRevisionAdapter, RejectsUnknownDuplicateAndWrongCellFlags) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell = Find(
        matrix,
        "paper-v1::real_dataset::dblp_acm_u65536_artifact=std192_encoding");
    ASSERT_NE(cell, nullptr);
    const auto plan = PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Toy);

    auto unknown = plan.argv;
    unknown.push_back("--unexpected=1");
    EXPECT_THROW(ParseRealDatasetRevisionArgs(unknown), std::invalid_argument);

    auto duplicate = plan.argv;
    duplicate.push_back(plan.argv.front());
    EXPECT_THROW(ParseRealDatasetRevisionArgs(duplicate), std::invalid_argument);

    auto wrong_method = plan.argv;
    auto it = std::find_if(
        wrong_method.begin(), wrong_method.end(),
        [](const std::string& arg) { return arg.rfind("--methods=", 0) == 0; });
    ASSERT_NE(it, wrong_method.end());
    *it = "--methods=onehot";
    EXPECT_THROW(SelectRealDatasetRevisionCell(
                     matrix, wrong_method, RevisionRunMode::Toy),
                 std::invalid_argument);
}

TEST(RealDatasetRevisionAdapter, ThresholdIsDBLPOnlyAndManifestBindsExactly) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell = Find(
        matrix, "paper-v1::threshold_dblp_fpfn::control=default");
    ASSERT_NE(cell, nullptr);
    const auto plan = PlanThresholdRevisionCell(*cell, RevisionRunMode::Toy);
    EXPECT_NO_THROW(ValidateRealDatasetRevisionManifest(
        *cell,
        std::filesystem::path(
            "tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv")));

    auto mismatched = *cell;
    mismatched.axes["variant"] = "enron_u65536";
    EXPECT_THROW(ValidateRealDatasetRevisionManifest(
                     mismatched,
                     std::filesystem::path(
                         "tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv")),
                 std::invalid_argument);
    EXPECT_FALSE(plan.argv.empty());
}

TEST(RealDatasetRevisionAdapter, EncodingCellCarriesNoFheExecutionMetadata) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell = Find(
        matrix,
        "paper-v1::real_dataset::enron_u65536_artifact=std192_encoding");
    ASSERT_NE(cell, nullptr);
    const auto plan = PlanRealDatasetRevisionExecution(
        matrix,
        PlanRealDatasetRevisionCell(*cell, RevisionRunMode::Toy).argv,
        RevisionRunMode::Toy);
    EXPECT_TRUE(plan.encoding_only);
    EXPECT_EQ(plan.concrete_profile, "readiness-toy-v1");
    EXPECT_EQ(plan.keygen_calls, 0u);
}

}  // namespace
