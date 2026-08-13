#include "cpu_revision_adapter.h"

#include <gtest/gtest.h>

#include <algorithm>
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

TEST(CpuRevisionAdapter, SelectsEstimatorJAndKAsSingleCells) {
    const RevisionMatrix matrix = Load();
    for (const std::string& id : {
             "paper-v1::estimator_accuracy::j=0.5",
             "paper-v1::estimator_accuracy::k=128"}) {
        const RevisionCell* cell = Find(matrix, id);
        ASSERT_NE(cell, nullptr);
        const RevisionRunMode mode = RevisionRunMode::Toy;
        const auto plan = PlanEstimatorRevisionCell(*cell, mode);
        const auto request = ParseCpuRevisionArgs(
            plan.argv, CpuRevisionProducer::EstimatorBias);
        EXPECT_EQ(request.cell,
                  id.find("::j=") == std::string::npos ? "estimator-k"
                                                         : "estimator-j");
        const auto execution = PlanCpuRevisionExecution(
            matrix, plan.argv, CpuRevisionProducer::EstimatorBias, mode);
        EXPECT_EQ(execution.selected_cell_count, 1u);
        EXPECT_EQ(execution.producer_invocation_count, 1u);
        EXPECT_FALSE(execution.native_sweep);
        EXPECT_EQ(execution.selection.cell.cell_id, id);
        EXPECT_EQ(execution.selection.plan.argv, plan.argv);
        EXPECT_EQ(request.trials, 1u);
    }
}

TEST(CpuRevisionAdapter, SeparatesExactDeletionFromMonteCarloTrials) {
    const RevisionMatrix matrix = Load();
    for (const std::string id : {
             "paper-v1::deletion_exact::control=default",
             "paper-v1::deletion_mc::control=default"}) {
        const RevisionCell* cell = Find(matrix, id);
        ASSERT_NE(cell, nullptr);
        const auto plan = PlanDeletionRevisionCell(*cell, RevisionRunMode::Toy);
        const auto request = ParseCpuRevisionArgs(
            plan.argv, CpuRevisionProducer::DeletionSurvival);
        EXPECT_EQ(request.cell,
                  id.find("deletion_exact") != std::string::npos ? "exact"
                                                                   : "monte-carlo");
        EXPECT_EQ(request.trials,
                  id.find("deletion_exact") != std::string::npos ? 0u : 1u);
        const auto spy = PlanCpuRevisionExecutionSpy(
            matrix, plan.argv, CpuRevisionProducer::DeletionSurvival,
            RevisionRunMode::Toy);
        ASSERT_EQ(spy.size(), 1u);
        EXPECT_EQ(spy.front().selection.cell.cell_id, id);
    }
}

TEST(CpuRevisionAdapter, SelectsOnlyFrozenSj16FitCell) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell =
        Find(matrix, "paper-v1::sj16::fit=per_element");
    ASSERT_NE(cell, nullptr);
    const auto plan = PlanSj16RevisionCell(*cell, RevisionRunMode::Toy);
    const auto request = ParseCpuRevisionArgs(
        plan.argv, CpuRevisionProducer::Sj16Calibrate);
    EXPECT_EQ(request.key_bits, 3072u);
    EXPECT_EQ(request.sizes, (std::vector<uint32_t>{4096, 8192, 16384}));
    EXPECT_EQ(request.held_out, 32768u);
    EXPECT_EQ(request.query_trials, 1u);
    EXPECT_EQ(request.enc_iters, 1u);
    const auto execution = PlanCpuRevisionExecution(
        matrix, plan.argv, CpuRevisionProducer::Sj16Calibrate,
        RevisionRunMode::Toy);
    EXPECT_EQ(execution.selected_cell_count, 1u);
    EXPECT_EQ(execution.producer_invocation_count, 1u);
    EXPECT_EQ(execution.selection.cell.cell_id, cell->cell_id);
}

TEST(CpuRevisionAdapter, RejectsUnknownDuplicateAndNonCanonicalArguments) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell =
        Find(matrix, "paper-v1::estimator_accuracy::j=0.5");
    ASSERT_NE(cell, nullptr);
    const auto plan = PlanEstimatorRevisionCell(*cell, RevisionRunMode::Toy);

    auto unknown = plan.argv;
    unknown.push_back("--unexpected=1");
    EXPECT_THROW(ParseCpuRevisionArgs(unknown, CpuRevisionProducer::EstimatorBias),
                 std::invalid_argument);

    auto duplicate = plan.argv;
    duplicate.push_back("--k=128");
    EXPECT_THROW(ParseCpuRevisionArgs(duplicate, CpuRevisionProducer::EstimatorBias),
                 std::invalid_argument);

    auto mismatched = plan.argv;
    auto it = std::find_if(mismatched.begin(), mismatched.end(),
                           [](const std::string& value) {
                               return value.rfind("--jaccard-grid=", 0) == 0;
                           });
    ASSERT_NE(it, mismatched.end());
    *it = "--jaccard-grid=0.6";
    const auto request = ParseCpuRevisionArgs(
        mismatched, CpuRevisionProducer::EstimatorBias);
    EXPECT_THROW(SelectCpuRevisionCell(
                     matrix, request, CpuRevisionProducer::EstimatorBias,
                     RevisionRunMode::Toy),
                 std::invalid_argument);
}

}  // namespace
