#include "review_revision_adapter.h"

#include "revision_invocation_plan.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace {

using namespace piccard::benchmark;

RevisionMatrix Load() {
    return LoadAndValidateRevisionMatrix(PICCARD_REVISION_MATRIX_PATH);
}

std::vector<const RevisionCell*> OwnedCells(const RevisionMatrix& matrix) {
    std::vector<const RevisionCell*> cells;
    for (const auto& cell : matrix.cells) {
        if (cell.producer == "bench_review_comparison" &&
            cell.invocation_status == "RUN" &&
            (cell.family == "bcg12_minhash" ||
             cell.family == "bcg12_exact" || cell.family == "sj16" ||
             cell.family == "piccard_std192_encoding")) {
            cells.push_back(&cell);
        }
    }
    return cells;
}

std::vector<std::string> Replace(std::vector<std::string> argv,
                                 const std::string& prefix,
                                 const std::string& value) {
    const auto it = std::find_if(
        argv.begin(), argv.end(), [&](const std::string& arg) {
            return arg.rfind(prefix, 0) == 0;
        });
    EXPECT_NE(it, argv.end());
    if (it != argv.end()) *it = value;
    return argv;
}

TEST(ReviewRevisionAdapter,
     SelectsEveryOwnedRunCellAndPreservesPlannerBytesForPaperAndToy) {
    const RevisionMatrix matrix = Load();
    const auto cells = OwnedCells(matrix);
    ASSERT_EQ(cells.size(), 43u);

    for (const RevisionRunMode mode : {RevisionRunMode::Paper,
                                       RevisionRunMode::Toy}) {
        for (const RevisionCell* cell : cells) {
            SCOPED_TRACE(cell->cell_id);
            const RevisionInvocationPlan expected =
                PlanRevisionCell(*cell, mode);
            ASSERT_FALSE(expected.argv.empty());
            const ReviewRevisionRequest request =
                ParseReviewRevisionArgs(expected.argv);
            const ReviewRevisionSelection selection =
                SelectReviewRevisionCell(matrix, request, mode);
            EXPECT_EQ(selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(selection.plan.argv, expected.argv);
            EXPECT_EQ(request.revision_cell, cell->cell_id);

            const ReviewRevisionExecutionPlan execution =
                PlanReviewRevisionExecution(matrix, expected.argv, mode);
            EXPECT_EQ(execution.selection.cell.cell_id, cell->cell_id);
            EXPECT_EQ(execution.selected_point_count, 1u);
            EXPECT_TRUE(execution.producer_must_spawn);
            EXPECT_EQ(execution.set_size,
                      std::stoull(cell->axes.at("n")));
            EXPECT_EQ(execution.universe,
                      std::stoull(cell->axes.at("u")));
            EXPECT_EQ(execution.accuracy_trials, 0u);
            EXPECT_FALSE(MakeConcreteReviewArgs(execution).empty());
        }
    }
}

TEST(ReviewRevisionAdapter, MapsAbstractPaperToConcreteProducerProfiles) {
    const RevisionMatrix matrix = Load();
    const auto cells = OwnedCells(matrix);
    for (const RevisionCell* cell : cells) {
        const auto paper = PlanReviewRevisionExecution(
            matrix, PlanRevisionCell(*cell, RevisionRunMode::Paper).argv,
            RevisionRunMode::Paper);
        EXPECT_EQ(paper.concrete_profile,
                  cell->family == "piccard_std192_encoding"
                      ? "paper-std192-encoding-v1"
                      : "std128-t40-primary");
        EXPECT_EQ(paper.concrete_security,
                  cell->family == "piccard_std192_encoding"
                      ? "STD192" : "STD128");
        EXPECT_EQ(paper.concrete_suite, cell->family);

        const auto toy = PlanReviewRevisionExecution(
            matrix, PlanRevisionCell(*cell, RevisionRunMode::Toy).argv,
            RevisionRunMode::Toy);
        EXPECT_EQ(toy.concrete_profile, "readiness-toy-v1");
        EXPECT_EQ(toy.concrete_security, "TOY");
    }
}

TEST(ReviewRevisionAdapter,
     ConcreteArgsContainExactlyOneCellGeometryAndNoPlannerOutputFlag) {
    const RevisionMatrix matrix = Load();
    const auto cells = OwnedCells(matrix);
    for (const RevisionCell* cell : cells) {
        const auto execution = PlanReviewRevisionExecution(
            matrix, PlanRevisionCell(*cell, RevisionRunMode::Paper).argv,
            RevisionRunMode::Paper);
        const auto args = MakeConcreteReviewArgs(execution);
        EXPECT_EQ(std::count_if(args.begin(), args.end(), [](const std::string& arg) {
                      return arg.rfind("--k=", 0) == 0;
                  }), 1);
        EXPECT_EQ(std::count_if(args.begin(), args.end(), [](const std::string& arg) {
                      return arg.rfind("--m=", 0) == 0;
                  }), 1);
        EXPECT_EQ(std::count_if(args.begin(), args.end(), [](const std::string& arg) {
                      return arg.rfind("--set-size=", 0) == 0;
                  }), 1);
        EXPECT_EQ(std::count_if(args.begin(), args.end(), [](const std::string& arg) {
                      return arg.rfind("--universe=", 0) == 0;
                  }), 1);
        EXPECT_EQ(std::count_if(args.begin(), args.end(), [](const std::string& arg) {
                      return arg.rfind("--revision-cell=", 0) == 0;
                  }), 0);
        EXPECT_EQ(std::count_if(args.begin(), args.end(), [](const std::string& arg) {
                      return arg.rfind("--output=", 0) == 0;
                  }), 0);
        EXPECT_NE(std::find(args.begin(), args.end(), "--diagnostic-security"),
                  args.end());
    }
}

TEST(ReviewRevisionAdapter,
     NonSquareStd192EncodingKeepsVersionedSqrtNotApplicableTerminalRow) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* non_square = nullptr;
    const RevisionCell* square = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id ==
            "paper-v1::piccard_std192_encoding::m=32") non_square = &cell;
        if (cell.cell_id ==
            "paper-v1::piccard_std192_encoding::m=64") square = &cell;
    }
    ASSERT_NE(non_square, nullptr);
    ASSERT_NE(square, nullptr);

    const auto non_square_execution = PlanReviewRevisionExecution(
        matrix, PlanRevisionCell(*non_square, RevisionRunMode::Toy).argv,
        RevisionRunMode::Toy);
    ASSERT_EQ(non_square_execution.selection.plan.expected_rows.size(), 2u);
    EXPECT_EQ(non_square_execution.selection.plan.expected_rows[1].status,
              "NOT_APPLICABLE");
    EXPECT_EQ(non_square_execution.selection.plan.expected_rows[1].reason_code,
              "sqrt-m-not-perfect-square");
    EXPECT_FALSE(ReviewSqrtEncodingApplicable(non_square_execution));
    EXPECT_EQ(non_square_execution.concrete_methods,
              std::vector<std::string>{"piccard_encode"});

    const auto square_execution = PlanReviewRevisionExecution(
        matrix, PlanRevisionCell(*square, RevisionRunMode::Toy).argv,
        RevisionRunMode::Toy);
    EXPECT_TRUE(ReviewSqrtEncodingApplicable(square_execution));
    EXPECT_EQ(square_execution.concrete_methods,
              (std::vector<std::string>{"piccard_encode",
                                        "piccard_sqrt_encode"}));
}

TEST(ReviewRevisionAdapter, RejectsNoSpawnSj16ExtrapolationBeforeProducer) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* no_spawn = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.cell_id == "paper-v1::sj16::u=262144") no_spawn = &cell;
    }
    ASSERT_NE(no_spawn, nullptr);
    const auto plan = PlanSj16RevisionCell(*no_spawn, RevisionRunMode::Paper);
    EXPECT_TRUE(plan.argv.empty());
    EXPECT_THROW(PlanReviewRevisionExecution(matrix, plan.argv,
                                              RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(ReviewRevisionAdapter, RejectsGeometryMethodOrderAndProfileDrift) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* cell = nullptr;
    for (const auto& candidate : matrix.cells) {
        if (candidate.cell_id == "paper-v1::bcg12_minhash::control=default") {
            cell = &candidate;
            break;
        }
    }
    ASSERT_NE(cell, nullptr);
    const auto plan = PlanBcg12RevisionCell(*cell, RevisionRunMode::Paper);

    for (const auto& mutated : {
             Replace(plan.argv, "--k=", "--k=16"),
             Replace(plan.argv, "--universe=", "--universe=16384"),
             Replace(plan.argv, "--methods=", "--methods=bcg12_mh_ec"),
             Replace(plan.argv, "--profile=", "--profile=readiness-toy-v1")}) {
        const auto request = ParseReviewRevisionArgs(mutated);
        EXPECT_THROW(SelectReviewRevisionCell(matrix, request,
                                               RevisionRunMode::Paper),
                     std::invalid_argument);
    }

    auto reordered = plan.argv;
    std::swap(reordered.front(), reordered.back());
    const auto request = ParseReviewRevisionArgs(reordered);
    EXPECT_THROW(SelectReviewRevisionCell(matrix, request,
                                           RevisionRunMode::Paper),
                 std::invalid_argument);
}

TEST(ReviewRevisionAdapter, RejectsUnownedSqrtProducerFamily) {
    const RevisionMatrix matrix = Load();
    const RevisionCell* sqrt = nullptr;
    for (const auto& cell : matrix.cells) {
        if (cell.family == "sqrt_comparison" && cell.invocation_status == "RUN") {
            sqrt = &cell;
            break;
        }
    }
    ASSERT_NE(sqrt, nullptr);
    const auto plan = PlanSqrtRevisionCell(*sqrt, RevisionRunMode::Paper);
    EXPECT_THROW(SelectReviewRevisionCell(matrix, plan.argv,
                                           RevisionRunMode::Paper),
                 std::invalid_argument);
}

}  // namespace
