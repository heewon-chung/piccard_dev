#include "revision_matrix.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace {

using piccard::benchmark::RevisionCell;
using piccard::benchmark::RevisionMatrix;
using piccard::benchmark::RevisionMatrixCellIds;
using piccard::benchmark::LoadRevisionMatrix;
using piccard::benchmark::ValidateRevisionMatrix;

RevisionMatrix Load() {
    return LoadRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

const RevisionCell& Find(const RevisionMatrix& matrix, const std::string& id) {
    const auto it = std::find_if(
        matrix.cells.begin(), matrix.cells.end(),
        [&](const RevisionCell& cell) { return cell.cell_id == id; });
    EXPECT_NE(it, matrix.cells.end());
    return *it;
}

std::vector<std::string> Lines(const std::string& path) {
    std::ifstream input(path);
    EXPECT_TRUE(input.is_open());
    std::vector<std::string> result;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty()) result.push_back(line);
    }
    return result;
}

}  // namespace

TEST(RevisionMatrix, CanonicalInventoryHasExactCardinalitiesAndSortedIds) {
    const RevisionMatrix matrix = Load();
    ASSERT_EQ(matrix.schema, "piccard-revision-matrix-v1");
    ASSERT_EQ(matrix.version, 1u);
    ASSERT_EQ(matrix.cell_count, 263u);
    ASSERT_EQ(matrix.cells.size(), 263u);

    const std::map<std::string, size_t> expected = {
        {"piccard_std128", 20}, {"piccard_std192_encoding", 20},
        {"fhe_ind", 9}, {"bcg12_minhash", 11}, {"bcg12_exact", 5},
        {"sj16", 11}, {"estimator_accuracy", 17}, {"sqrt_comparison", 20},
        {"flooding", 3}, {"dynamic_timing", 16},
        {"dynamic_accuracy", 16}, {"dynamic_refresh", 1},
        {"deletion_exact", 1}, {"deletion_mc", 1},
        {"threshold_timing", 5}, {"threshold_spec", 5},
        {"threshold_agreement", 5}, {"threshold_synthetic_fpfn", 84},
        {"threshold_dblp_fpfn", 1}, {"real_dataset", 12},
    };
    std::map<std::string, size_t> actual;
    for (const auto& cell : matrix.cells) ++actual[cell.family];
    EXPECT_EQ(actual, expected);

    const auto ids = RevisionMatrixCellIds(matrix);
    EXPECT_TRUE(std::is_sorted(ids.begin(), ids.end()));
    EXPECT_EQ(ids, Lines(PICCARD_REVISION_MATRIX_PAPER_GOLDEN));
    EXPECT_EQ(Lines(PICCARD_REVISION_MATRIX_PAPER_GOLDEN).size(), 263u);
    EXPECT_EQ(Lines(PICCARD_REVISION_MATRIX_TOY_GOLDEN).size(), 20u);
    EXPECT_EQ(Lines(PICCARD_REVISION_MATRIX_EXECUTABLE_TOY_GOLDEN).size(),
              104u);
}

TEST(RevisionMatrix, RequiredTerminalRowsAndProducerBindingsAreLiteral) {
    const RevisionMatrix matrix = Load();
    const auto& sqrt_invalid = Find(
        matrix, "paper-v1::sqrt_comparison::timing_m=32");
    ASSERT_EQ(sqrt_invalid.expected_rows.size(), 2u);
    const auto sqrt_row = std::find_if(
        sqrt_invalid.expected_rows.begin(), sqrt_invalid.expected_rows.end(),
        [](const auto& row) { return row.row_id == "sqrt"; });
    ASSERT_NE(sqrt_row, sqrt_invalid.expected_rows.end());
    EXPECT_EQ(sqrt_row->status, "NOT_APPLICABLE");
    EXPECT_EQ(sqrt_row->reason, "sqrt-m-not-perfect-square");
    EXPECT_EQ(sqrt_invalid.producer, "bench_onehot_sqrt");

    const auto& extrapolated = Find(
        matrix, "paper-v1::sj16::u=262144");
    ASSERT_EQ(extrapolated.invocation_status, "NO_SPAWN");
    ASSERT_EQ(extrapolated.expected_rows.size(), 1u);
    EXPECT_EQ(extrapolated.expected_rows.front().status, "EXTRAPOLATED");
    EXPECT_EQ(extrapolated.expected_rows.front().reason,
              "sj16-paillier3072-calibration-bound-v1");

    const auto& fhe_ind = Find(matrix, "paper-v1::fhe_ind::n=1000");
    EXPECT_EQ(fhe_ind.producer, "bench_fhe_ind");
    EXPECT_EQ(fhe_ind.eligibility, "DIAGNOSTIC_ONLY");
    EXPECT_FALSE(fhe_ind.comparison_eligible);

    const auto& refresh = Find(
        matrix, "paper-v1::dynamic_refresh::control=default");
    EXPECT_EQ(refresh.producer, "bench_dynamic");
    EXPECT_EQ(refresh.axes.at("k"), "128");
    EXPECT_EQ(refresh.axes.at("m"), "64");
    EXPECT_EQ(refresh.axes.at("n"), "1000");
}

TEST(RevisionMatrix, ValidationRejectsOmittedDuplicateAndSilentRows) {
    RevisionMatrix matrix = Load();
    ASSERT_NO_THROW(ValidateRevisionMatrix(matrix));

    matrix.cells.pop_back();
    EXPECT_THROW(ValidateRevisionMatrix(matrix), std::invalid_argument);

    matrix = Load();
    matrix.cells.push_back(matrix.cells.front());
    EXPECT_THROW(ValidateRevisionMatrix(matrix), std::invalid_argument);

    matrix = Load();
    matrix.cells.front().expected_rows.clear();
    EXPECT_THROW(ValidateRevisionMatrix(matrix), std::invalid_argument);
}
