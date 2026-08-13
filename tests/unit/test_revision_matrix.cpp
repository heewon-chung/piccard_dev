#include "revision_matrix.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <set>
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

RevisionCell& MutableFind(RevisionMatrix& matrix, const std::string& id) {
    const auto it = std::find_if(
        matrix.cells.begin(), matrix.cells.end(),
        [&](RevisionCell& cell) { return cell.cell_id == id; });
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

TEST(RevisionMatrix, RequiredGeometryAndPaperCountsAreLiteral) {
    const RevisionMatrix matrix = Load();
    for (const auto& family : {"piccard_std128", "piccard_std192_encoding",
                               "fhe_ind", "bcg12_minhash", "bcg12_exact", "sj16",
                               "dynamic_timing", "dynamic_accuracy"}) {
        const auto& control = Find(
            matrix, std::string("paper-v1::") + family + "::control=default");
        EXPECT_EQ(control.axes.at("u"), "65536");
        const auto& n100000 = Find(
            matrix, std::string("paper-v1::") + family + "::n=100000");
        EXPECT_EQ(n100000.axes.at("u"), "262144");
    }
    const auto& std192 = Find(
        matrix, "paper-v1::piccard_std192_encoding::control=default");
    EXPECT_EQ(std192.paper_count, 30u);
    EXPECT_EQ(std192.paper_counts.at("encoding"), 30u);
    EXPECT_EQ(std192.paper_counts.at("correctness"), 1u);
    EXPECT_EQ(std192.expected_rows.front().paper_measured_count, 30u);

    const auto& dblp = Find(
        matrix, "paper-v1::threshold_dblp_fpfn::control=default");
    EXPECT_EQ(dblp.dataset, "dblp_acm");
    EXPECT_EQ(dblp.axes.at("variant"), "dblp_acm_u65536");
    EXPECT_EQ(dblp.axes.at("u"), "65536");
    EXPECT_EQ(dblp.paper_counts.at("held_out"), 50u);

    const auto& enron = Find(
        matrix, "paper-v1::real_dataset::enron_u1048576_artifact=accuracy");
    EXPECT_EQ(enron.dataset, "enron");
    EXPECT_EQ(enron.axes.at("u"), "1048576");
    const auto& real_encoding = Find(
        matrix, "paper-v1::real_dataset::dblp_acm_u65536_artifact=std192_encoding");
    EXPECT_EQ(real_encoding.paper_count, 30u);
    EXPECT_EQ(real_encoding.paper_counts.at("std192_encoding"), 30u);

    const auto& sj_terminal = Find(
        matrix, "paper-v1::sj16::n=100000");
    EXPECT_EQ(sj_terminal.invocation_status, "NO_SPAWN");
    EXPECT_EQ(sj_terminal.expected_rows.front().status, "EXTRAPOLATED");
    EXPECT_EQ(sj_terminal.expected_rows.front().measured_count, 0u);
    EXPECT_EQ(sj_terminal.paper_count, 30u);
}

TEST(RevisionMatrix, ToyInventoriesAreExactAndDerived) {
    const std::set<std::string> expected_toy = {
        "paper-v1::bcg12_exact::control=default",
        "paper-v1::bcg12_minhash::control=default",
        "paper-v1::deletion_exact::control=default",
        "paper-v1::deletion_mc::control=default",
        "paper-v1::dynamic_accuracy::control=default",
        "paper-v1::dynamic_refresh::control=default",
        "paper-v1::dynamic_timing::control=default",
        "paper-v1::estimator_accuracy::j=0.5",
        "paper-v1::fhe_ind::control=default",
        "paper-v1::flooding::profile=primary40",
        "paper-v1::piccard_std128::control=default",
        "paper-v1::piccard_std192_encoding::control=default",
        "paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy",
        "paper-v1::real_dataset::enron_u65536_artifact=accuracy",
        "paper-v1::sj16::fit=per_element",
        "paper-v1::sqrt_comparison::timing_m=64",
        "paper-v1::threshold_agreement::k=64",
        "paper-v1::threshold_dblp_fpfn::control=default",
        "paper-v1::threshold_spec::k=64",
        "paper-v1::threshold_timing::k=64",
    };
    const auto toy_lines = Lines(PICCARD_REVISION_MATRIX_TOY_GOLDEN);
    ASSERT_EQ(toy_lines.size(), expected_toy.size());
    EXPECT_EQ(std::set<std::string>(toy_lines.begin(), toy_lines.end()), expected_toy);

    const auto executable_lines = Lines(PICCARD_REVISION_MATRIX_EXECUTABLE_TOY_GOLDEN);
    ASSERT_EQ(executable_lines.size(), 104u);
    std::set<std::string> expected_executable = expected_toy;
    for (const auto& cell : Load().cells) {
        if (cell.family == "threshold_synthetic_fpfn") {
            expected_executable.insert(cell.cell_id);
        }
    }
    EXPECT_EQ(std::set<std::string>(executable_lines.begin(), executable_lines.end()),
              expected_executable);
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

TEST(RevisionMatrix, ValidationRejectsRunnerContractMutations) {
    auto matrix = Load();
    auto expect_rejected = [](RevisionMatrix& candidate) {
        EXPECT_THROW(ValidateRevisionMatrix(candidate), std::invalid_argument);
    };

    auto& control = MutableFind(
        matrix, "paper-v1::piccard_std128::control=default");
    control.producer = "bench_review_comparison";
    expect_rejected(matrix);

    matrix = Load();
    MutableFind(matrix, "paper-v1::piccard_std128::control=default").axes["u"] = "16384";
    expect_rejected(matrix);
    matrix = Load();
    MutableFind(matrix, "paper-v1::piccard_std128::n=100000").axes["u"] = "65536";
    expect_rejected(matrix);

    matrix = Load();
    MutableFind(matrix, "paper-v1::real_dataset::enron_u1048576_artifact=accuracy").dataset = "synthetic";
    expect_rejected(matrix);
    matrix = Load();
    auto& real = MutableFind(
        matrix, "paper-v1::real_dataset::enron_u1048576_artifact=accuracy");
    real.axes["variant"] = "enron_u65536";
    expect_rejected(matrix);
    matrix = Load();
    MutableFind(matrix, "paper-v1::threshold_dblp_fpfn::control=default").attributes["variant"] = "enron_u65536";
    expect_rejected(matrix);

    for (const auto& mutation : {std::string("paper_count"), std::string("toy_count"),
                                 std::string("paper_trials"), std::string("toy_trials")}) {
        matrix = Load();
        auto& cell = MutableFind(
            matrix, "paper-v1::piccard_std128::control=default");
        if (mutation == "paper_count") cell.paper_count = 31;
        if (mutation == "toy_count") cell.toy_count = 2;
        if (mutation == "paper_trials") cell.paper_trials = 31;
        if (mutation == "toy_trials") cell.toy_trials = 2;
        expect_rejected(matrix);
    }
    matrix = Load();
    MutableFind(matrix, "paper-v1::piccard_std128::control=default").paper_counts["timing"] = 31;
    expect_rejected(matrix);
    matrix = Load();
    MutableFind(matrix, "paper-v1::piccard_std128::control=default").toy_counts["timing"] = 2;
    expect_rejected(matrix);
    matrix = Load();
    MutableFind(matrix, "paper-v1::piccard_std128::control=default").expected_rows[0].paper_measured_count = 31;
    expect_rejected(matrix);

    matrix = Load();
    MutableFind(matrix, "paper-v1::dynamic_refresh::control=default").attributes["updates"] = "2";
    expect_rejected(matrix);
    matrix = Load();
    MutableFind(matrix, "paper-v1::dynamic_refresh::control=default").expected_rows[0].attributes["updates"] = "2";
    expect_rejected(matrix);

    const std::string fit_id = "paper-v1::sj16::fit=per_element";
    for (const auto& mutation : {std::string("sizes"), std::string("held_out"),
                                 std::string("key_bits"), std::string("threads"),
                                 std::string("precomputed"), std::string("fit_authority")}) {
        matrix = Load();
        auto& fit = MutableFind(matrix, fit_id);
        if (mutation == "sizes") fit.list_attributes["sizes"] = {"4096", "8192"};
        else if (mutation == "held_out") fit.attributes["held_out"] = "16384";
        else if (mutation == "key_bits") fit.attributes["key_bits"] = "2048";
        else if (mutation == "threads") fit.attributes["threads"] = "1";
        else if (mutation == "precomputed") fit.attributes["precomputed"] = "true";
        else fit.attributes["fit_authority"] = "false";
        expect_rejected(matrix);
    }
    matrix = Load();
    MutableFind(matrix, fit_id).paper_counts["enc_iters"] = 29;
    expect_rejected(matrix);
    matrix = Load();
    MutableFind(matrix, fit_id).expected_rows[0].attributes["warmup_calls"] = "0";
    expect_rejected(matrix);

    matrix = Load();
    auto& extrapolated = MutableFind(matrix, "paper-v1::sj16::u=262144");
    extrapolated.expected_rows[0].reason.clear();
    extrapolated.expected_rows[0].reason_code.clear();
    expect_rejected(matrix);
    matrix = Load();
    MutableFind(matrix, "paper-v1::sqrt_comparison::timing_m=32").expected_rows[1].status = "MEASURED";
    expect_rejected(matrix);
}
