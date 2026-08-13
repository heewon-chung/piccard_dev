#include "revision_matrix.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

namespace {

const piccard::benchmark::RevisionCell& Find(
    const piccard::benchmark::RevisionMatrix& matrix, const std::string& id) {
    const auto it = std::find_if(
        matrix.cells.begin(), matrix.cells.end(),
        [&](const auto& cell) { return cell.cell_id == id; });
    EXPECT_NE(it, matrix.cells.end());
    return *it;
}

}  // namespace

TEST(RevisionSingleCellAdapters, MatrixFreezesOneSelectorPerInvocation) {
    const auto matrix = piccard::benchmark::LoadRevisionMatrix(
        PICCARD_REVISION_MATRIX_PATH);
    for (const auto& cell : matrix.cells) {
        ASSERT_FALSE(cell.axis.empty());
        ASSERT_FALSE(cell.axis_value.empty());
        ASSERT_FALSE(cell.producer.empty());
        ASSERT_FALSE(cell.expected_rows.empty());
        EXPECT_TRUE(cell.invocation_status == "RUN" ||
                    cell.invocation_status == "NO_SPAWN");
    }
    EXPECT_EQ(Find(matrix, "paper-v1::threshold_synthetic_fpfn::point=k64_j-10").axes.at("grid_index"),
              "-10");
    EXPECT_EQ(Find(matrix, "paper-v1::threshold_synthetic_fpfn::point=k64_j-10").axes.at("k"),
              "64");
    EXPECT_EQ(Find(matrix, "paper-v1::real_dataset::enron_u65536_artifact=accuracy").axes.at("variant"),
              "enron_u65536");
    EXPECT_EQ(Find(matrix, "paper-v1::real_dataset::enron_u65536_artifact=accuracy").axes.at("artifact"),
              "accuracy");
}

TEST(RevisionSingleCellAdapters, SyntheticToyInventoryAddsExactly84Points) {
    const auto matrix = piccard::benchmark::LoadRevisionMatrix(
        PICCARD_REVISION_MATRIX_PATH);
    size_t points = 0;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "threshold_synthetic_fpfn") ++points;
    }
    EXPECT_EQ(points, 84u);
}
