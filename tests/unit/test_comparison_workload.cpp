#include "comparison_workload.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

using namespace piccard::benchmark;

namespace {

WorkloadSpec ToySpec(uint64_t seed = 7) {
    WorkloadSpec spec;
    spec.suite = "toy-smoke";
    spec.profile_id = "toy-smoke";
    spec.root_seed = seed;
    spec.k = 16;
    spec.m = 16;
    spec.set_size = 10;
    spec.universe = 64;
    spec.target_jaccard = ParseExactDecimal("0.5");
    spec.methods = {"piccard", "piccard_sqrt", "bcg12_mh_ec",
                    "bcg12_exact_ec", "sj16"};
    spec.timing_trials = 1;
    spec.accuracy_trials = 1;
    return spec;
}

std::filesystem::path TempPath(const std::string& stem) {
    return std::filesystem::temp_directory_path() /
           (stem + "-" + std::to_string(static_cast<unsigned long>(getpid())) +
            ".bin");
}

AggregateIdentity Row(const ComparisonWorkload& workload,
                      std::string method,
                      std::string kind,
                      std::string arm,
                      uint32_t trials,
                      std::string precomputation = "crs-and-keys-only") {
    AggregateIdentity row;
    row.method = std::move(method);
    row.measurement_kind = std::move(kind);
    row.evidence_arm = std::move(arm);
    row.workload_id = workload.WorkloadId();
    row.workload_manifest_sha256 = workload.ManifestSha256Hex();
    row.k = workload.Spec().k;
    row.m = workload.Spec().m;
    row.set_size = workload.Spec().set_size;
    row.universe = workload.Spec().universe;
    row.timing_trials = workload.Spec().timing_trials;
    row.accuracy_trials = workload.Spec().accuracy_trials;
    row.aggregate_trials = trials;
    row.precomputation_mode = std::move(precomputation);
    return row;
}

std::vector<AggregateIdentity> ValidToyRows(
    const ComparisonWorkload& workload) {
    std::vector<AggregateIdentity> rows;
    const struct {
        const char* method;
        const char* timing_kind;
        const char* accuracy_kind;
        bool exact;
    } cases[] = {
        {"piccard", "fhe-timing", "fhe-accuracy", false},
        {"piccard_sqrt", "fhe-timing", "fhe-accuracy", false},
        {"bcg12_mh_ec", "psi-timing", "psi-accuracy", false},
        {"bcg12_exact_ec", "psi-timing", "psi-accuracy", true},
        {"sj16", "ahe-timing", "ahe-accuracy", true},
    };
    for (const auto& c : cases) {
        auto timing = Row(workload, c.method, c.timing_kind, "timing", 1,
                          c.method == std::string("sj16")
                              ? "randomizer-generation-included"
                              : "crs-and-keys-only");
        timing.exact_estimator = c.exact;
        rows.push_back(std::move(timing));
        auto accuracy = Row(workload, c.method, c.accuracy_kind, "accuracy", 1,
                            c.method == std::string("sj16")
                                ? "randomizer-generation-included"
                                : "crs-and-keys-only");
        accuracy.exact_estimator = c.exact;
        accuracy.estimator_error = c.exact ? 0.0 : 0.125;
        rows.push_back(std::move(accuracy));
    }
    return rows;
}

std::vector<std::string> CsvCells(const std::string& line) {
    std::stringstream fields(line);
    std::vector<std::string> cells;
    std::string cell;
    while (std::getline(fields, cell, ',')) cells.push_back(cell);
    return cells;
}

}  // namespace

TEST(ComparisonWorkload, DeterministicBinaryDigestAndCanonicalRecords) {
    const ComparisonWorkload workload = ComparisonWorkload::Generate(ToySpec());

    EXPECT_EQ(workload.Bytes().size(), 832u);
    EXPECT_EQ(workload.ManifestSha256Hex(),
              "669d54d779bc31e46a57b92c0e46153b657f1c039158c46987c7cf2f9ad3ccaa");
    EXPECT_EQ(workload.WorkloadId(), "review-64-669d54d779bc31e4");
    ASSERT_EQ(workload.Records().size(), 3u);

    const auto& warmup = workload.Records()[0];
    EXPECT_EQ(warmup.kind, TrialKind::Warmup);
    EXPECT_EQ(warmup.index, 0u);
    EXPECT_EQ(warmup.trial_seed, UINT64_C(6435688777652229028));
    EXPECT_EQ(warmup.hash_seed, UINT64_C(4096026444048912533));
    EXPECT_EQ(warmup.set_a,
              (std::vector<uint64_t>{6, 11, 13, 15, 25, 29, 33, 38, 47, 61}));
    EXPECT_EQ(warmup.set_b,
              (std::vector<uint64_t>{4, 6, 11, 18, 29, 33, 38, 39, 47, 61}));
    EXPECT_EQ(warmup.exact_jaccard, (ExactRational{7, 13}));

    EXPECT_EQ(workload.ExecutionOrder(warmup),
              (std::vector<std::string>{"bcg12_exact_ec", "sj16", "piccard",
                                        "piccard_sqrt", "bcg12_mh_ec"}));
    EXPECT_EQ(ComparisonWorkload::ParseAndVerify(workload.Bytes()).Bytes(),
              workload.Bytes());
}

TEST(ComparisonWorkload, ExactCardinalityJaccardAndCrsRules) {
    const ComparisonWorkload workload = ComparisonWorkload::Generate(ToySpec());
    ASSERT_EQ(workload.Records().size(), 3u);
    const uint64_t timing_hash_seed = workload.Records()[1].hash_seed;
    EXPECT_EQ(timing_hash_seed, UINT64_C(15329580584519071531));
    EXPECT_NE(workload.Records()[2].hash_seed, timing_hash_seed);
    std::vector<uint64_t> trial_seeds;

    for (const auto& record : workload.Records()) {
        trial_seeds.push_back(record.trial_seed);
        EXPECT_TRUE(std::is_sorted(record.set_a.begin(), record.set_a.end()));
        EXPECT_TRUE(std::is_sorted(record.set_b.begin(), record.set_b.end()));
        EXPECT_EQ(record.set_a.size(), 10u);
        EXPECT_EQ(record.set_b.size(), 10u);
        std::vector<uint64_t> intersection;
        std::set_intersection(record.set_a.begin(), record.set_a.end(),
                              record.set_b.begin(), record.set_b.end(),
                              std::back_inserter(intersection));
        EXPECT_EQ(intersection.size(), 7u);
        EXPECT_EQ(record.exact_intersection, 7u);
        EXPECT_EQ(record.exact_union, 13u);
        EXPECT_EQ(record.exact_jaccard, (ExactRational{7, 13}));
    }
    std::sort(trial_seeds.begin(), trial_seeds.end());
    EXPECT_EQ(std::adjacent_find(trial_seeds.begin(), trial_seeds.end()),
              trial_seeds.end());

    EXPECT_EQ(ReviewMeasurementKind("piccard", TrialKind::Accuracy),
              "fhe-accuracy");
    EXPECT_EQ(ReviewMeasurementKind("bcg12_mh_ec", TrialKind::Timing),
              "psi-timing");
    EXPECT_EQ(ReviewMeasurementKind("sj16", TrialKind::Accuracy),
              "ahe-accuracy");

    const auto piccard_policy = ResolveReviewMethodRowPolicy(
        "piccard", TrialKind::Timing, 16, 16, timing_hash_seed);
    EXPECT_EQ(piccard_policy.k, std::optional<uint64_t>(16));
    EXPECT_EQ(piccard_policy.m, std::optional<uint64_t>(16));
    EXPECT_EQ(piccard_policy.hash_seed,
              std::optional<uint64_t>(timing_hash_seed));
    EXPECT_EQ(piccard_policy.hash_randomness, "fixed");

    const auto minhash_policy = ResolveReviewMethodRowPolicy(
        "bcg12_mh_ec", TrialKind::Timing, 16, 16, timing_hash_seed);
    EXPECT_EQ(minhash_policy.k, std::optional<uint64_t>(16));
    EXPECT_EQ(minhash_policy.m, std::nullopt);
    EXPECT_EQ(minhash_policy.hash_seed,
              std::optional<uint64_t>(timing_hash_seed));

    const auto exact_policy = ResolveReviewMethodRowPolicy(
        "bcg12_exact_ec", TrialKind::Timing, 16, 16, timing_hash_seed);
    EXPECT_EQ(exact_policy.k, std::nullopt);
    EXPECT_EQ(exact_policy.m, std::nullopt);
    EXPECT_EQ(exact_policy.hash_seed, std::nullopt);
    EXPECT_EQ(exact_policy.hash_randomness, "not-applicable");

    const auto accuracy_policy = ResolveReviewMethodRowPolicy(
        "piccard", TrialKind::Accuracy, 16, 16, timing_hash_seed);
    EXPECT_EQ(accuracy_policy.hash_seed, std::nullopt);
    EXPECT_EQ(accuracy_policy.hash_randomness, "resampled");
    EXPECT_EQ(ReviewNumericCell(-1.0), "");
    EXPECT_EQ(ReviewNumericCell(0.0), "0.000000");
}

TEST(ComparisonWorkload, ToyProducerCsvBindsSerializerContract) {
#ifdef PICCARD_SOURCE_DIR
    std::ifstream input(std::string(PICCARD_SOURCE_DIR) +
                        "/.omo/evidence/work4-phase4-toy-results.csv");
    ASSERT_TRUE(input.good());
    std::string line;
    ASSERT_TRUE(std::getline(input, line));
    const auto header = CsvCells(line);
    ASSERT_EQ(header.size(), 66u);
    std::map<std::string, size_t> column;
    for (size_t i = 0; i < header.size(); ++i) column.emplace(header[i], i);
    for (const char* name : {"method", "measurement_kind", "evidence_arm",
                             "comparison_eligible", "workload_id",
                             "workload_manifest_sha256", "execution_trace_sha256",
                             "k", "m", "hash_randomness", "hash_seed",
                             "total_ms_sd", "measurement_status"}) {
        ASSERT_TRUE(column.find(name) != column.end()) << name;
    }
    const std::string expected_digest =
        "669d54d779bc31e46a57b92c0e46153b657f1c039158c46987c7cf2f9ad3ccaa";
    const std::string expected_trace =
        "a15f85b1b64255c7a317daeea589c1626b76faa6787e8901e5c2bf0643f4f0ec";
    const struct {
        const char* method;
        const char* kind;
        const char* arm;
        const char* k;
        const char* m;
        const char* randomness;
        const char* hash_seed;
    } expected_rows[] = {
        {"piccard", "fhe-timing", "timing", "16", "16", "fixed",
         "15329580584519071531"},
        {"piccard", "fhe-accuracy", "accuracy", "16", "16", "resampled", ""},
        {"piccard_sqrt", "fhe-timing", "timing", "16", "16", "fixed",
         "15329580584519071531"},
        {"piccard_sqrt", "fhe-accuracy", "accuracy", "16", "16", "resampled", ""},
        {"bcg12_mh_ec", "psi-timing", "timing", "16", "", "fixed",
         "15329580584519071531"},
        {"bcg12_mh_ec", "psi-accuracy", "accuracy", "16", "", "resampled", ""},
        {"bcg12_exact_ec", "psi-timing", "timing", "", "", "not-applicable", ""},
        {"bcg12_exact_ec", "psi-accuracy", "accuracy", "", "", "not-applicable", ""},
        {"sj16", "ahe-timing", "timing", "", "", "not-applicable", ""},
        {"sj16", "ahe-accuracy", "accuracy", "", "", "not-applicable", ""},
    };
    size_t rows = 0;
    while (std::getline(input, line)) {
        const auto cells = CsvCells(line);
        ASSERT_EQ(cells.size(), header.size());
        ASSERT_LT(rows, std::size(expected_rows));
        const auto& expected = expected_rows[rows];
        EXPECT_EQ(cells[column.at("method")], expected.method);
        EXPECT_EQ(cells[column.at("measurement_kind")], expected.kind);
        EXPECT_EQ(cells[column.at("evidence_arm")], expected.arm);
        EXPECT_EQ(cells[column.at("k")], expected.k);
        EXPECT_EQ(cells[column.at("m")], expected.m);
        EXPECT_EQ(cells[column.at("hash_randomness")], expected.randomness);
        EXPECT_EQ(cells[column.at("hash_seed")], expected.hash_seed);
        EXPECT_EQ(cells[column.at("comparison_eligible")], "false");
        EXPECT_EQ(cells[column.at("workload_id")],
                  "review-64-669d54d779bc31e4");
        EXPECT_EQ(cells[column.at("workload_manifest_sha256")], expected_digest);
        EXPECT_EQ(cells[column.at("execution_trace_sha256")], expected_trace);
        EXPECT_EQ(cells[column.at("measurement_status")], "measured");
        const std::string& sd = cells[column.at("total_ms_sd")];
        EXPECT_TRUE(sd.empty());
        ++rows;
    }
    EXPECT_EQ(rows, 10u);
#else
    GTEST_SKIP() << "PICCARD_SOURCE_DIR is not defined";
#endif
}

TEST(ComparisonWorkload, SeedSensitivityAndExactHalfRoundsDown) {
    const auto first = ComparisonWorkload::Generate(ToySpec(7));
    const auto second = ComparisonWorkload::Generate(ToySpec(8));
    EXPECT_NE(first.ManifestSha256Hex(), second.ManifestSha256Hex());
    EXPECT_NE(first.Records()[0].set_a, second.Records()[0].set_a);

    WorkloadSpec tie = ToySpec();
    tie.set_size = 2;
    tie.universe = 3;
    tie.target_jaccard = ParseExactDecimal("0.6");
    const auto tied = ComparisonWorkload::Generate(tie);
    EXPECT_EQ(tied.Records()[0].exact_intersection, 1u);
    EXPECT_EQ(tied.Records()[0].exact_jaccard, (ExactRational{1, 3}));
}

TEST(ComparisonWorkload, RejectsTamperInvalidMembershipAndInsufficientUniverse) {
    const auto workload = ComparisonWorkload::Generate(ToySpec());
    auto tampered = workload.Bytes();
    tampered.back() ^= 0x01;
    EXPECT_THROW(ComparisonWorkload::ParseAndVerify(tampered),
                 std::invalid_argument);

    WorkloadSpec invalid = ToySpec();
    invalid.universe = 12;
    EXPECT_THROW(ComparisonWorkload::Generate(invalid), std::invalid_argument);

    invalid = ToySpec();
    invalid.methods.push_back("sj16");
    EXPECT_THROW(ComparisonWorkload::Generate(invalid), std::invalid_argument);
}

TEST(ComparisonWorkload, FrozenSuitesEnforceExactRowsAndTrials) {
    const auto toy = ComparisonWorkload::Generate(ToySpec());
    auto rows = ValidToyRows(toy);
    EXPECT_NO_THROW(ValidateAggregateMembership(toy, rows));

    auto duplicate = rows;
    duplicate.push_back(duplicate.front());
    EXPECT_THROW(ValidateAggregateMembership(toy, duplicate),
                 std::invalid_argument);
    auto missing = rows;
    missing.pop_back();
    EXPECT_THROW(ValidateAggregateMembership(toy, missing),
                 std::invalid_argument);
    auto wrong_trials = rows;
    wrong_trials[0].aggregate_trials = 2;
    EXPECT_THROW(ValidateAggregateMembership(toy, wrong_trials),
                 std::invalid_argument);
    auto wrong_arm = rows;
    wrong_arm[0].measurement_kind = "fhe-accuracy";
    EXPECT_THROW(ValidateAggregateMembership(toy, wrong_arm),
                 std::invalid_argument);
    auto cross_suite = rows;
    cross_suite[0].method = "bcg12_mh_ff";
    EXPECT_THROW(ValidateAggregateMembership(toy, cross_suite),
                 std::invalid_argument);
    auto wrong_params = rows;
    wrong_params[0].k = 128;
    EXPECT_THROW(ValidateAggregateMembership(toy, wrong_params),
                 std::invalid_argument);
    auto nonzero_exact_error = rows;
    nonzero_exact_error[7].estimator_error = 0.01;
    EXPECT_THROW(ValidateAggregateMembership(toy, nonzero_exact_error),
                 std::invalid_argument);
}

TEST(ComparisonWorkload, ToySmokeAcceptsOneAccuracyTrialAndRejectsTwo) {
    EXPECT_NO_THROW(ComparisonWorkload::Generate(ToySpec()));

    auto two_accuracy_trials = ToySpec();
    two_accuracy_trials.accuracy_trials = 2;
    EXPECT_THROW(ComparisonWorkload::Generate(two_accuracy_trials),
                 std::invalid_argument);
}

TEST(ComparisonWorkload, PrimaryAndSj16SensitivityMembershipIsFrozen) {
    WorkloadSpec primary;
    primary.suite = "primary-review";
    primary.profile_id = "std128-t40-primary";
    primary.root_seed = 20260729;
    primary.k = 128;
    primary.m = 64;
    primary.set_size = 10;
    primary.universe = 64;
    primary.target_jaccard = ParseExactDecimal("0.5");
    primary.methods = {"piccard", "piccard_sqrt", "bcg12_mh_ff",
                       "bcg12_mh_ec", "bcg12_exact_ff", "bcg12_exact_ec",
                       "sj16"};
    primary.timing_trials = 30;
    primary.accuracy_trials = 50;
    const auto p = ComparisonWorkload::Generate(primary);
    const auto primary_rows = ExpectedAggregateIdentities(p);
    EXPECT_EQ(primary_rows.size(), 14u);
    EXPECT_NO_THROW(ValidateAggregateMembership(p, primary_rows));

    WorkloadSpec sensitivity = primary;
    sensitivity.suite = "sj16-precompute-sensitivity";
    sensitivity.profile_id = "std128-t64-sensitivity";
    sensitivity.methods = {"sj16", "sj16_precomputed"};
    sensitivity.timing_trials = 3;
    sensitivity.accuracy_trials = 0;
    const auto s = ComparisonWorkload::Generate(sensitivity);
    auto rows = ExpectedAggregateIdentities(s);
    ASSERT_EQ(rows.size(), 2u);
    EXPECT_EQ(rows[0].precomputation_mode, "randomizer-generation-included");
    EXPECT_EQ(rows[1].precomputation_mode, "randomizers-precomputed");
    EXPECT_NO_THROW(ValidateAggregateMembership(s, rows));
    auto exact_error = rows;
    exact_error[0].estimator_error = 0.01;
    EXPECT_THROW(ValidateAggregateMembership(s, exact_error),
                 std::invalid_argument);
    auto missing = rows;
    missing.pop_back();
    EXPECT_THROW(ValidateAggregateMembership(s, missing), std::invalid_argument);
    auto extra = rows;
    extra.push_back(rows.front());
    EXPECT_THROW(ValidateAggregateMembership(s, extra), std::invalid_argument);
    std::swap(rows[0].precomputation_mode, rows[1].precomputation_mode);
    EXPECT_THROW(ValidateAggregateMembership(s, rows), std::invalid_argument);
}

TEST(ComparisonWorkload, ExecutionTraceBindsManifestAndCanonicalDispatchOrder) {
    const auto workload = ComparisonWorkload::Generate(ToySpec());
    ExecutionTrace trace(workload);
    for (const auto& record : workload.Records()) {
        trace.BeginRecord(record);
        for (const auto& method : workload.ExecutionOrder(record)) {
            trace.AppendDispatch(method);
        }
        trace.CompleteRecord();
    }
    const auto bytes = trace.SerializeAndVerify();
    EXPECT_EQ(bytes.size(), 320u);
    EXPECT_EQ(Sha256Hex(bytes),
              "a15f85b1b64255c7a317daeea589c1626b76faa6787e8901e5c2bf0643f4f0ec");
    EXPECT_NO_THROW(VerifyExecutionTrace(bytes, workload));

    auto reordered = bytes;
    reordered.back() ^= 1;
    EXPECT_THROW(VerifyExecutionTrace(reordered, workload),
                 std::invalid_argument);

    auto missing = bytes;
    constexpr size_t kTraceDomainBytes =
        sizeof("piccard-review-execution-trace-v1");
    const size_t observed_count = kTraceDomainBytes + 32 + 4;
    std::fill(missing.begin() + static_cast<ptrdiff_t>(observed_count),
              missing.begin() + static_cast<ptrdiff_t>(observed_count + 4), 0);
    EXPECT_THROW(VerifyExecutionTrace(missing, workload),
                 std::invalid_argument);
}

TEST(ComparisonWorkload, TraceRepresentsFailureAndRejectsMalformedTrials) {
    const auto workload = ComparisonWorkload::Generate(ToySpec());
    ExecutionTrace failed(workload);
    failed.BeginRecord(workload.Records().front());
    failed.AppendDispatch(workload.ExecutionOrder(workload.Records().front())[0]);
    failed.FailRecord();
    EXPECT_NO_THROW(VerifyExecutionTrace(failed.SerializeAndVerify(), workload));
    EXPECT_THROW(failed.BeginRecord(workload.Records()[1]), std::logic_error);

    ExecutionTrace wrong(workload);
    wrong.BeginRecord(workload.Records().front());
    EXPECT_THROW(wrong.AppendDispatch("piccard"), std::invalid_argument);
    EXPECT_THROW(wrong.CompleteRecord(), std::logic_error);
}

TEST(ComparisonWorkload, ArtifactWritesAreAtomicAndNeverOverwrite) {
    const auto workload = ComparisonWorkload::Generate(ToySpec());
    const auto workload_path = TempPath("piccard-workload-test");
    const auto trace_path = TempPath("piccard-trace-test");
    std::error_code ignored;
    std::filesystem::remove(workload_path, ignored);
    std::filesystem::remove(trace_path, ignored);

    workload.WriteNew(workload_path);
    EXPECT_TRUE(std::filesystem::exists(workload_path));
    EXPECT_THROW(workload.WriteNew(workload_path), std::runtime_error);

    ExecutionTrace trace(workload);
    for (const auto& record : workload.Records()) {
        trace.BeginRecord(record);
        for (const auto& method : workload.ExecutionOrder(record)) {
            trace.AppendDispatch(method);
        }
        trace.CompleteRecord();
    }
    trace.WriteNew(trace_path);
    EXPECT_TRUE(std::filesystem::exists(trace_path));
    EXPECT_THROW(trace.WriteNew(trace_path), std::runtime_error);

    std::filesystem::remove(workload_path, ignored);
    std::filesystem::remove(trace_path, ignored);
}
