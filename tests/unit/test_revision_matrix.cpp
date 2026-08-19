#include "revision_matrix.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using piccard::benchmark::RevisionCell;
using piccard::benchmark::RevisionMatrix;
using piccard::benchmark::RevisionMatrixCellIds;
using piccard::benchmark::LoadRevisionMatrix;
using piccard::benchmark::ValidateRevisionMatrix;
using piccard::benchmark::ValidateRevisionMatrixToyFixtures;

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
    ASSERT_EQ(matrix.cell_count, 275u);
    ASSERT_EQ(matrix.cells.size(), 275u);

    const std::map<std::string, size_t> expected = {
        {"piccard_std128", 20}, {"piccard_std192_encoding", 20},
        {"fhe_ind", 9}, {"bcg12_minhash", 11}, {"bcg12_exact", 5},
        {"sj16", 11}, {"estimator_accuracy", 17}, {"sqrt_comparison", 32},
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
    EXPECT_EQ(Lines(PICCARD_REVISION_MATRIX_PAPER_GOLDEN).size(), 275u);
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

    for (const auto& family : {"threshold_timing", "threshold_spec",
                               "threshold_agreement"}) {
        const auto& k256 = Find(
            matrix, std::string("paper-v1::") + family + "::k=256");
        EXPECT_EQ(k256.invocation_status, "RUN");
        ASSERT_EQ(k256.expected_rows.size(), 1u);
        EXPECT_NE(k256.expected_rows.front().status, "NOT_APPLICABLE");
    }

    const auto& refresh = Find(
        matrix, "paper-v1::dynamic_refresh::control=default");
    EXPECT_EQ(refresh.producer, "bench_dynamic");
    EXPECT_EQ(refresh.axes.at("k"), "128");
    EXPECT_EQ(refresh.axes.at("m"), "64");
    EXPECT_EQ(refresh.axes.at("n"), "1000");
}

TEST(RevisionMatrix, Sj16TimeoutClassesBindFitAndRunStatus) {
    const RevisionMatrix matrix = Load();
    for (const auto& cell : matrix.cells) {
        if (cell.family != "sj16") continue;
        const bool no_spawn =
            cell.axis == "u" && (cell.axis_value == "262144" ||
                                 cell.axis_value == "1048576");
        EXPECT_EQ(cell.timeout_class, no_spawn ? "standard" : "long")
            << cell.cell_id;
        EXPECT_EQ(cell.invocation_status,
                  (cell.axis == "u" &&
                           (cell.axis_value == "262144" ||
                            cell.axis_value == "1048576"))
                      ? "NO_SPAWN"
                      : "RUN")
            << cell.cell_id;
    }
}

TEST(RevisionMatrix, LargestSetSizeCellsOutrankTheStandardTimeout) {
    // paper-v1 is one non-resumable run, so a cell that overruns its stop
    // aborts the whole matrix.  Measured on the campaign host, piccard_std128
    // needs 759 s at n=100000 and piccard_std192_encoding 693 s, both past the
    // 600 s standard stop, so no 100000-element point may sit at standard:
    // the slow baselines keep `long`, the rest take `extended`.
    const RevisionMatrix matrix = Load();
    size_t top_of_sweep = 0;
    for (const auto& cell : matrix.cells) {
        if ((cell.axis != "n" && cell.axis != "timing_n") ||
            cell.axis_value != "100000") {
            continue;
        }
        ++top_of_sweep;
        const bool slow_baseline =
            cell.family == "sj16" || cell.family == "bcg12_exact";
        EXPECT_EQ(cell.timeout_class, slow_baseline ? "long" : "extended")
            << cell.cell_id;
    }
    EXPECT_EQ(top_of_sweep, 9u);
}

TEST(RevisionMatrix, StandardTimeoutAtTheTopOfTheSweepFailsClosed) {
    RevisionMatrix matrix = Load();
    for (auto& cell : matrix.cells) {
        if (cell.cell_id != "paper-v1::piccard_std128::n=100000") continue;
        cell.timeout_class = "standard";
    }
    EXPECT_THROW(ValidateRevisionMatrix(matrix), std::invalid_argument);
}

TEST(RevisionMatrix, ThresholdPhaseCellsOutrankTheStandardTimeout) {
    // The fourth paper-v1 attempt was the first run to reach the threshold
    // phase and was killed at threshold_agreement::k=128 after 600.1 s.
    // Re-measured to natural completion: agreement 138/160/881/1455/2886 s at
    // k=16/32/64/128/256, threshold_timing 202.8 s at its worst point, the
    // synthetic FP/FN sweep 391.8 s at its worst point, and the DBLP FP/FN
    // control 237.9 s.  Only threshold_spec (6.1 s) still clears 3x under the
    // standard stop, so it is the one threshold family left there.
    const RevisionMatrix matrix = Load();
    size_t agreement = 0, timing = 0, spec = 0, synthetic = 0, dblp = 0;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "threshold_agreement") {
            ++agreement;
            const bool past_extended =
                cell.axis_value == "128" || cell.axis_value == "256";
            EXPECT_EQ(cell.timeout_class, past_extended ? "long" : "extended")
                << cell.cell_id;
        } else if (cell.family == "threshold_timing") {
            ++timing;
            EXPECT_EQ(cell.timeout_class, "extended") << cell.cell_id;
        } else if (cell.family == "threshold_synthetic_fpfn") {
            ++synthetic;
            EXPECT_EQ(cell.timeout_class, "extended") << cell.cell_id;
        } else if (cell.family == "threshold_dblp_fpfn") {
            ++dblp;
            EXPECT_EQ(cell.timeout_class, "extended") << cell.cell_id;
        } else if (cell.family == "threshold_spec") {
            ++spec;
            EXPECT_EQ(cell.timeout_class, "standard") << cell.cell_id;
        }
    }
    EXPECT_EQ(agreement, 5u);
    EXPECT_EQ(timing, 5u);
    EXPECT_EQ(spec, 5u);
    EXPECT_EQ(synthetic, 84u);
    EXPECT_EQ(dblp, 1u);
}

TEST(RevisionMatrix, EveryTimeoutClassKeepsAThreefoldMeasuredMargin) {
    // Slowest natural completion observed per cell against its stop.  A stop
    // is a safety net for a hang, not a budget, so a measurement may take at
    // most a third of it.
    const std::vector<std::pair<std::string, double>> measured = {
        {"paper-v1::threshold_agreement::k=16", 138.0},
        {"paper-v1::threshold_agreement::k=32", 160.0},
        {"paper-v1::threshold_agreement::k=64", 881.0},
        {"paper-v1::threshold_agreement::k=128", 1455.0},
        {"paper-v1::threshold_agreement::k=256", 2886.0},
        {"paper-v1::threshold_timing::k=128", 202.8},
        {"paper-v1::threshold_timing::k=256", 157.0},
        {"paper-v1::threshold_spec::k=256", 6.1},
        {"paper-v1::threshold_synthetic_fpfn::point=k512_j-10", 391.8},
        {"paper-v1::threshold_synthetic_fpfn::point=k256_j-10", 199.6},
        {"paper-v1::threshold_dblp_fpfn::control=default", 237.9},
        {"paper-v1::piccard_std128::n=100000", 759.0},
        {"paper-v1::piccard_std192_encoding::n=100000", 693.0},
        {"paper-v1::dynamic_accuracy::n=100000", 384.4},
        {"paper-v1::dynamic_timing::n=100000", 241.7},
    };
    const RevisionMatrix matrix = Load();
    for (const auto& entry : measured) {
        const auto found = std::find_if(
            matrix.cells.begin(), matrix.cells.end(),
            [&](const RevisionCell& cell) { return cell.cell_id == entry.first; });
        ASSERT_NE(found, matrix.cells.end()) << entry.first;
        const double stop = found->timeout_class == "standard"    ? 600.0
                            : found->timeout_class == "extended"  ? 3600.0
                            : found->timeout_class == "long"      ? 64800.0
                                                                  : 0.0;
        EXPECT_GE(stop, 3.0 * entry.second) << entry.first;
    }
}

TEST(RevisionMatrix, LoweredThresholdTimeoutClassesFailClosed) {
    const std::vector<std::pair<std::string, std::string>> lowered = {
        {"paper-v1::threshold_agreement::k=256", "extended"},
        {"paper-v1::threshold_agreement::k=64", "standard"},
        {"paper-v1::threshold_timing::k=128", "standard"},
        {"paper-v1::threshold_synthetic_fpfn::point=k512_j0", "standard"},
        {"paper-v1::threshold_dblp_fpfn::control=default", "standard"},
    };
    for (const auto& entry : lowered) {
        RevisionMatrix matrix = Load();
        for (auto& cell : matrix.cells) {
            if (cell.cell_id == entry.first) cell.timeout_class = entry.second;
        }
        EXPECT_THROW(ValidateRevisionMatrix(matrix), std::invalid_argument)
            << entry.first;
    }
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
    EXPECT_EQ(sj_terminal.axes.at("u"), "262144");
    EXPECT_EQ(sj_terminal.invocation_status, "RUN");
    EXPECT_EQ(sj_terminal.expected_rows.front().status, "MEASURED");
    EXPECT_EQ(sj_terminal.expected_rows.front().measured_count, 30u);
    EXPECT_EQ(sj_terminal.paper_count, 30u);
}

TEST(RevisionMatrix, Sj16N100000IsMeasuredAndOnlyLargeUCellsExtrapolate) {
    const RevisionMatrix matrix = Load();
    const auto& n100000 = Find(matrix, "paper-v1::sj16::n=100000");
    ASSERT_EQ(n100000.axes.at("k"), "128");
    ASSERT_EQ(n100000.axes.at("m"), "64");
    ASSERT_EQ(n100000.axes.at("n"), "100000");
    ASSERT_EQ(n100000.axes.at("u"), "262144");
    EXPECT_EQ(n100000.profile, "paper-v1");
    EXPECT_EQ(n100000.paper_count, 30u);
    EXPECT_EQ(n100000.toy_count, 1u);
    EXPECT_EQ(n100000.paper_counts.at("timing"), 30u);
    EXPECT_EQ(n100000.toy_counts.at("timing"), 1u);
    EXPECT_EQ(n100000.invocation_status, "RUN");
    ASSERT_EQ(n100000.expected_rows.size(), 1u);
    EXPECT_EQ(n100000.expected_rows.front().status, "MEASURED");
    EXPECT_EQ(n100000.expected_rows.front().measured_count, 30u);
    EXPECT_EQ(n100000.expected_rows.front().paper_measured_count, 30u);
    EXPECT_EQ(n100000.expected_rows.front().toy_measured_count, 1u);

    for (const auto& value : {"262144", "1048576"}) {
        const auto& cell = Find(
            matrix, std::string("paper-v1::sj16::u=") + value);
        EXPECT_EQ(cell.invocation_status, "NO_SPAWN") << cell.cell_id;
        ASSERT_EQ(cell.expected_rows.size(), 1u);
        EXPECT_EQ(cell.expected_rows.front().status, "EXTRAPOLATED")
            << cell.cell_id;
        EXPECT_EQ(cell.expected_rows.front().reason,
                  "sj16-paillier3072-calibration-bound-v1")
            << cell.cell_id;
    }
}

TEST(RevisionMatrix, ToyInventoriesAreExactAndDerived) {
    const auto matrix = Load();
    const auto toy_lines = Lines(PICCARD_REVISION_MATRIX_TOY_GOLDEN);
    const auto executable_lines = Lines(PICCARD_REVISION_MATRIX_EXECUTABLE_TOY_GOLDEN);
    ASSERT_EQ(toy_lines.size(), 20u);
    ASSERT_EQ(executable_lines.size(), 104u);
    EXPECT_NO_THROW(ValidateRevisionMatrixToyFixtures(
        matrix, toy_lines, executable_lines));
}

TEST(RevisionMatrix, ValidationRejectsCoordinatedToyInventoryDrift) {
    const auto matrix = Load();
    auto toy_lines = Lines(PICCARD_REVISION_MATRIX_TOY_GOLDEN);
    auto executable_lines = Lines(PICCARD_REVISION_MATRIX_EXECUTABLE_TOY_GOLDEN);
    const std::string original = "paper-v1::piccard_std128::control=default";
    const std::string replacement = "paper-v1::piccard_std128::k=16";
    ASSERT_NE(std::find(toy_lines.begin(), toy_lines.end(), original), toy_lines.end());
    ASSERT_NE(std::find(executable_lines.begin(), executable_lines.end(), original), executable_lines.end());
    std::replace(toy_lines.begin(), toy_lines.end(), original, replacement);
    std::replace(executable_lines.begin(), executable_lines.end(), original, replacement);
    std::sort(toy_lines.begin(), toy_lines.end());
    std::sort(executable_lines.begin(), executable_lines.end());
    EXPECT_THROW(ValidateRevisionMatrixToyFixtures(
        matrix, toy_lines, executable_lines), std::invalid_argument);
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

TEST(RevisionMatrix, ValidationRejectsReciprocalFamilyPayloadSwaps) {
    auto matrix = Load();
    const std::string std128_id =
        "paper-v1::piccard_std128::control=default";
    const std::string std192_id =
        "paper-v1::piccard_std192_encoding::control=default";
    auto& std128 = MutableFind(matrix, std128_id);
    auto& std192 = MutableFind(matrix, std192_id);
    std::swap(std128.family, std192.family);
    std::swap(std128.producer, std192.producer);
    std::swap(std128.profile, std192.profile);
    std::swap(std128.dataset, std192.dataset);
    std::swap(std128.axes, std192.axes);
    std::swap(std128.axis, std192.axis);
    std::swap(std128.axis_value, std192.axis_value);
    std::swap(std128.paper_count, std192.paper_count);
    std::swap(std128.toy_count, std192.toy_count);
    std::swap(std128.paper_trials, std192.paper_trials);
    std::swap(std128.toy_trials, std192.toy_trials);
    std::swap(std128.paper_counts, std192.paper_counts);
    std::swap(std128.toy_counts, std192.toy_counts);
    std::swap(std128.eligibility, std192.eligibility);
    std::swap(std128.table_eligible, std192.table_eligible);
    std::swap(std128.comparison_eligible, std192.comparison_eligible);
    std::swap(std128.timeout_class, std192.timeout_class);
    std::swap(std128.expected_artifact_schema, std192.expected_artifact_schema);
    std::swap(std128.invocation_status, std192.invocation_status);
    std::swap(std128.attributes, std192.attributes);
    std::swap(std128.list_attributes, std192.list_attributes);
    std::swap(std128.object_attributes, std192.object_attributes);
    std::swap(std128.expected_rows, std192.expected_rows);
    EXPECT_THROW(ValidateRevisionMatrix(matrix), std::invalid_argument);
}
