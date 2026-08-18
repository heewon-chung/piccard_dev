#include "dynamic_probe_workload.h"

#include "core/bottom_structure.h"
#include "util/params.h"

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace piccard::benchmark {
namespace {

// Frozen copy of bench_dynamic.cpp's MakeSetsWithOverlap (bench_dynamic.cpp:48).
// The regression below pins one exact historical failure, so the fixture is
// reproduced here rather than shared: if the benchmark's generator ever
// changes, this test must keep generating the set that used to crash.
std::pair<std::vector<uint64_t>, std::vector<uint64_t>>
MakeSetsWithOverlap(size_t set_size, double overlap_fraction) {
    size_t overlap = static_cast<size_t>(overlap_fraction * set_size);
    std::vector<uint64_t> a, b;
    for (uint64_t i = 0; i < overlap; i++) {
        a.push_back(i);
        b.push_back(i);
    }
    for (uint64_t i = overlap; i < set_size; i++) {
        a.push_back(i + 1000000);
    }
    for (uint64_t i = overlap; i < set_size; i++) {
        b.push_back(i + 2000000);
    }
    return {a, b};
}

// The exact configuration of revision cell paper-v1::dynamic_timing::n=100:
// k=128, m=64, depth=5 (default), set_size=100, seed=20260729, and the default
// target Jaccard 0.5, whose intersection fraction is 2J/(1+J) = 2/3.
constexpr uint32_t kPaperK = 128;
constexpr uint32_t kPaperDepth = 5;
constexpr uint64_t kPaperSeed = 20260729;
constexpr size_t kPaperSetSize = 100;
constexpr double kPaperOverlapFraction = 2.0 / 3.0;
constexpr size_t kPaperNumOps = 100;

BottomStructure MakePaperProbeStructure(const std::vector<uint64_t>& set_x) {
    PiccardParams defaults;
    BottomStructure bottom(kPaperK, kPaperDepth, defaults.hash_range,
                           kPaperSeed);
    bottom.Initialize(set_x);
    return bottom;
}

// Regression: the paper probe batch used to abort the process here. Deleting
// the probes back out empties a bottom row whose d retained hashes were all
// probe hashes; the next Delete then threw std::logic_error from
// BottomStructure::RequireUsable with nothing to catch it. The TOY matrix
// cannot reach this: TOY forces num_ops=1.
TEST(DynamicProbeWorkloadTest, PaperN100CellSurvivesTheProbeBatch) {
    const auto [set_x, set_y] =
        MakeSetsWithOverlap(kPaperSetSize, kPaperOverlapFraction);
    BottomStructure probe_structure = MakePaperProbeStructure(set_x);

    ProbeWorkloadTiming timing;
    ASSERT_NO_THROW(
        timing = RunProbeWorkload(probe_structure, set_x, kDynamicProbeBase,
                                  kPaperNumOps));

    // This cell is the one that empties a row, so the rebuild path must have
    // actually run — otherwise the test would pass without covering the fix.
    EXPECT_GE(timing.rebuild_count, 1u);
    EXPECT_GT(timing.rebuild_ms, 0.0);
    EXPECT_FALSE(probe_structure.RequiresRebuild());
    EXPECT_NO_THROW((void)probe_structure.GetSignature());
}

// Afterwards, every value the scratch structure still holds must be an owner
// hash a from-scratch Initialize would also hold, and no row may be empty.
//
// Equality is deliberately NOT asserted: the probe batch is lossy by design.
// Inserting probes evicts owner hashes permanently, so deleting the probes
// back out leaves rows shorter than a fresh Initialize. That loss is exactly
// why the probes run on a scratch copy and never on the signature-bearing
// structure. What must hold is that no probe hash survives and no owner hash
// is fabricated -- i.e. containment.
TEST(DynamicProbeWorkloadTest, EndStateIsALossySubsetOfTheOwnerSetAlone) {
    const auto [set_x, set_y] =
        MakeSetsWithOverlap(kPaperSetSize, kPaperOverlapFraction);
    BottomStructure probe_structure = MakePaperProbeStructure(set_x);
    RunProbeWorkload(probe_structure, set_x, kDynamicProbeBase, kPaperNumOps);

    const BottomStructure reference = MakePaperProbeStructure(set_x);
    const auto& probed = probe_structure.GetBottom();
    const auto& expected = reference.GetBottom();
    ASSERT_EQ(probed.size(), expected.size());
    for (size_t row = 0; row < probed.size(); ++row) {
        EXPECT_FALSE(probed[row].empty()) << "row " << row << " is empty";
        for (uint64_t value : probed[row]) {
            EXPECT_NE(std::find(expected[row].begin(), expected[row].end(),
                                value),
                      expected[row].end())
                << "row " << row << " retained a non-owner hash " << value;
        }
    }
}

// A workload that never empties a row must not rebuild at all, so the guard
// cannot silently inflate the common path.
TEST(DynamicProbeWorkloadTest, LargeSetNeedsNoRebuild) {
    const auto [set_x, set_y] = MakeSetsWithOverlap(10000, 2.0 / 3.0);
    BottomStructure probe_structure = MakePaperProbeStructure(set_x);

    const auto timing = RunProbeWorkload(probe_structure, set_x,
                                         kDynamicProbeBase, kPaperNumOps);
    EXPECT_EQ(timing.rebuild_count, 0u);
    EXPECT_EQ(timing.rebuild_ms, 0.0);
}

// Sweep every distinct (k, n) the paper's dynamic_timing family runs. m never
// reaches BottomStructure, so k and n are the only axes that matter here. The
// n=100 cell is the one that historically aborted; the rest are latent -- the
// hazard exists at every n, and only the frozen seed decides whether a row
// actually empties. All of them must complete.
TEST(DynamicProbeWorkloadTest, EveryPaperTimingConfigCompletes) {
    struct Config { uint32_t k; size_t n; };
    // revision_matrix.json paper-v1::dynamic_timing axes.
    const Config configs[] = {
        {16, 1000},  {32, 1000},   {64, 1000},    {128, 1000},
        {256, 1000}, {512, 1000},  {128, 100},    {128, 10000},
        {128, 100000},
    };

    PiccardParams defaults;
    for (const auto& config : configs) {
        SCOPED_TRACE("k=" + std::to_string(config.k) + " n=" +
                     std::to_string(config.n));
        const auto [set_x, set_y] =
            MakeSetsWithOverlap(config.n, kPaperOverlapFraction);
        BottomStructure probe_structure(config.k, kPaperDepth,
                                        defaults.hash_range, kPaperSeed);
        probe_structure.Initialize(set_x);

        ProbeWorkloadTiming timing;
        ASSERT_NO_THROW(
            timing = RunProbeWorkload(probe_structure, set_x,
                                      kDynamicProbeBase, kPaperNumOps));
        RecordProperty("rebuilds_k" + std::to_string(config.k) + "_n" +
                           std::to_string(config.n),
                       static_cast<int>(timing.rebuild_count));
        EXPECT_FALSE(probe_structure.RequiresRebuild());
    }
}

// The TOY smoke path (num_ops == 1) stays a plain round trip.
TEST(DynamicProbeWorkloadTest, SingleOpRoundTripIsUnchanged) {
    const auto [set_x, set_y] = MakeSetsWithOverlap(10, 2.0 / 3.0);
    BottomStructure probe_structure = MakePaperProbeStructure(set_x);

    const auto timing =
        RunProbeWorkload(probe_structure, set_x, kDynamicProbeBase, 1);
    EXPECT_EQ(timing.rebuild_count, 0u);
    EXPECT_FALSE(probe_structure.RequiresRebuild());
}

}  // namespace
}  // namespace piccard::benchmark
