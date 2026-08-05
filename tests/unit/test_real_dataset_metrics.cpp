#include "data/real_dataset_metrics.h"
#include "real_dataset_csv_schema.h"

#include "baseline_profile.h"
#include "benchmark_estimator_provenance.h"
#include "benchmark_profile.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using namespace piccard::data;

// ---------------------------------------------------------------------------
// ExactJaccard — sorted-unique uint64 feature-ID vectors.
// ---------------------------------------------------------------------------

TEST(ExactJaccardTest, BothEmptyIsZero) {
    EXPECT_DOUBLE_EQ(ExactJaccard({}, {}), 0.0);
}

TEST(ExactJaccardTest, OneEmptyIsZero) {
    EXPECT_DOUBLE_EQ(ExactJaccard({}, {1, 2, 3}), 0.0);
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2, 3}, {}), 0.0);
}

TEST(ExactJaccardTest, DisjointSetsIsZero) {
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2}, {3, 4}), 0.0);
}

TEST(ExactJaccardTest, IdenticalSetsIsOne) {
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2, 3}, {1, 2, 3}), 1.0);
}

TEST(ExactJaccardTest, PartialOverlapHandCalculated) {
    // {1,2,3} vs {2,3,4}: intersection={2,3} (2), union={1,2,3,4} (4).
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2, 3}, {2, 3, 4}), 0.5);
}

TEST(ExactJaccardTest, SubsetRelationshipHandCalculated) {
    // {1,2} subset of {1,2,3,4}: intersection=2, union=4.
    EXPECT_DOUBLE_EQ(ExactJaccard({1, 2}, {1, 2, 3, 4}), 0.5);
}

// ---------------------------------------------------------------------------
// FormatReal17 — must byte-match format_float() in
// scripts/prepare_real_datasets.py (shared golden table, Python side in
// tests/scripts/test_real_dataset_preprocess.py::FormattingGoldenTests).
// ---------------------------------------------------------------------------

namespace {
struct FormatVector {
    double input;
    const char* expected;
};

// Independently verified against scripts/prepare_real_datasets.py's
// format_float() before either side of this golden table was written; see
// FormattingGoldenTests in tests/scripts/test_real_dataset_preprocess.py for
// the byte-identical Python-side pin.
const std::vector<FormatVector>& FormatGoldenVectors() {
    static const std::vector<FormatVector> kVectors = {
        {0.0, "0"},
        {-0.0, "0"},
        {1.0, "1"},
        {-1.0, "-1"},
        {0.5, "0.5"},
        {-0.5, "-0.5"},
        {2.5, "2.5"},
        {7.5, "7.5"},
        {100.0, "100"},
        {-100.0, "-100"},
        {5.0, "5"},
        {42.0, "42"},
        {0.001, "0.001"},
        // Bucket boundaries (also exercised as JaccardBucketLabel inputs below).
        {0.1, "0.10000000000000001"},
        {0.3, "0.29999999999999999"},
        {0.6, "0.59999999999999998"},
        // Needs all 17 significant digits.
        {123456789.123456789, "123456789.12345679"},
        {0.6000000000000001, "0.60000000000000009"},
        {3.14159265358979, "3.14159265358979"},
        {1234567890123456.0, "1234567890123456"},
        {9999999999999998.0, "9999999999999998"},
        // Very small / very large magnitudes.
        {1e-300, "1e-300"},
        {1e300, "1.0000000000000001e+300"},
        {-1e300, "-1.0000000000000001e+300"},
        {1e-5, "1.0000000000000001e-05"},
        {1e16, "10000000000000000"},
        {1e17, "1e+17"},
        {1e-16, "9.9999999999999998e-17"},
        {1.7976931348623157e308, "1.7976931348623157e+308"},
        {2.2250738585072014e-308, "2.2250738585072014e-308"},
    };
    return kVectors;
}
}  // namespace

TEST(FormatReal17Test, MatchesSharedGoldenVectors) {
    for (const auto& v : FormatGoldenVectors()) {
        EXPECT_EQ(FormatReal17(v.input), v.expected) << "input=" << v.input;
    }
}

TEST(FormatReal17Test, RejectsNonFinite) {
    EXPECT_THROW(FormatReal17(std::numeric_limits<double>::quiet_NaN()), std::invalid_argument);
    EXPECT_THROW(FormatReal17(std::numeric_limits<double>::infinity()), std::invalid_argument);
    EXPECT_THROW(FormatReal17(-std::numeric_limits<double>::infinity()), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// JaccardBucketLabel — [0,.1)->b00_10, [.1,.3)->b10_30, [.3,.6)->b30_60,
// [.6,1]->b60_100. Upper endpoint 1 belongs to b60_100.
// ---------------------------------------------------------------------------

TEST(JaccardBucketLabelTest, LowerBucket) {
    EXPECT_STREQ(JaccardBucketLabel(0.0), "b00_10");
    EXPECT_STREQ(JaccardBucketLabel(0.099999), "b00_10");
}

TEST(JaccardBucketLabelTest, LowerBoundaryZeroPointOneIsExclusiveUpper) {
    EXPECT_STREQ(JaccardBucketLabel(0.1), "b10_30");
}

TEST(JaccardBucketLabelTest, MidBucket) {
    EXPECT_STREQ(JaccardBucketLabel(0.29999), "b10_30");
}

TEST(JaccardBucketLabelTest, BoundaryZeroPointThree) {
    EXPECT_STREQ(JaccardBucketLabel(0.3), "b30_60");
}

TEST(JaccardBucketLabelTest, UpperMidBucket) {
    EXPECT_STREQ(JaccardBucketLabel(0.59999), "b30_60");
}

TEST(JaccardBucketLabelTest, BoundaryZeroPointSix) {
    EXPECT_STREQ(JaccardBucketLabel(0.6), "b60_100");
}

TEST(JaccardBucketLabelTest, BoundaryOneBelongsToTopBucket) {
    EXPECT_STREQ(JaccardBucketLabel(1.0), "b60_100");
}

// ---------------------------------------------------------------------------
// Summarize — over finite abs errors.
// ---------------------------------------------------------------------------

TEST(SummarizeTest, EmptyInputHasZeroCount) {
    SummaryStats stats = Summarize({});
    EXPECT_EQ(stats.n, 0u);
}

TEST(SummarizeTest, SingleValueAllStatsEqualSoleValue) {
    SummaryStats stats = Summarize({0.25});
    EXPECT_EQ(stats.n, 1u);
    EXPECT_DOUBLE_EQ(stats.mae, 0.25);
    EXPECT_DOUBLE_EQ(stats.median, 0.25);
    EXPECT_DOUBLE_EQ(stats.p95, 0.25);
    EXPECT_DOUBLE_EQ(stats.max, 0.25);
}

TEST(SummarizeTest, GoldenTwoPairMedianIsMeanOfBothAndP95IsLargerNearestRank) {
    // Hand-calculated golden case (normative §Phase 5 RED): median of a
    // two-element set is the arithmetic mean of the two values; nearest-rank
    // P95 for n=2 is sorted[ceil(0.95*2)-1] = sorted[1], the larger value.
    SummaryStats stats = Summarize({0.3, 0.1});  // unsorted input on purpose
    EXPECT_EQ(stats.n, 2u);
    EXPECT_DOUBLE_EQ(stats.mae, 0.2);
    EXPECT_DOUBLE_EQ(stats.median, 0.2);
    EXPECT_DOUBLE_EQ(stats.p95, 0.3);
    EXPECT_DOUBLE_EQ(stats.max, 0.3);
    // sample_sd = sqrt(((0.1-0.2)^2 + (0.3-0.2)^2) / (2-1)) = sqrt(0.02).
    EXPECT_NEAR(stats.sample_sd, std::sqrt(0.02), 1e-12);
    // margin = 1.96 * sample_sd / sqrt(2) = 1.96 * 0.1 = 0.196 exactly
    // (sample_sd / sqrt(2) == 0.1 for this vector).
    EXPECT_NEAR(stats.ci95_low, 0.2 - 0.196, 1e-9);
    EXPECT_NEAR(stats.ci95_high, 0.2 + 0.196, 1e-9);
}

TEST(SummarizeTest, OddCountMedianIsCenterValue) {
    // n=5: sorted {0.1, 0.2, 0.3, 0.4, 0.5}; median is the center (0.3);
    // p95 = sorted[ceil(0.95*5)-1] = sorted[ceil(4.75)-1] = sorted[4] = 0.5.
    SummaryStats stats = Summarize({0.5, 0.1, 0.4, 0.2, 0.3});
    EXPECT_EQ(stats.n, 5u);
    EXPECT_DOUBLE_EQ(stats.median, 0.3);
    EXPECT_DOUBLE_EQ(stats.p95, 0.5);
    EXPECT_DOUBLE_EQ(stats.max, 0.5);
    EXPECT_NEAR(stats.mae, 0.3, 1e-12);
}

TEST(SummarizeTest, AsymmetricOddVectorPinsMedianDistinctFromMean) {
    // Asymmetric n=3: sorted {0.1, 0.1, 0.7}; median is the center value
    // (0.1) while the mean is 0.3 — a mean-as-median implementation fails.
    SummaryStats stats = Summarize({0.7, 0.1, 0.1});
    EXPECT_EQ(stats.n, 3u);
    EXPECT_DOUBLE_EQ(stats.median, 0.1);
    EXPECT_NEAR(stats.mae, 0.3, 1e-12);
    EXPECT_DOUBLE_EQ(stats.max, 0.7);
}

TEST(SummarizeTest, AsymmetricEvenVectorPinsMeanOfTwoCentersDistinctFromMean) {
    // Asymmetric n=4: sorted {0.1, 0.1, 0.2, 0.8}; median is the mean of the
    // two center values (0.1+0.2)/2 = 0.15 while the mean is 0.3.
    SummaryStats stats = Summarize({0.8, 0.1, 0.2, 0.1});
    EXPECT_EQ(stats.n, 4u);
    EXPECT_DOUBLE_EQ(stats.median, 0.15);
    EXPECT_NEAR(stats.mae, 0.3, 1e-12);
}

TEST(SummarizeTest, NearestRankP95DiffersFromMaxAtTwentyValues) {
    // n=20: for n < 20, ceil(0.95*n)-1 == n-1 makes p95 == max vacuously;
    // at n=20, p95 = sorted[ceil(19)-1] = sorted[18] while max = sorted[19].
    // Vector: 0.01..0.19 (19 values) plus an outlier 5.0.
    std::vector<double> values;
    for (int i = 1; i <= 19; ++i) values.push_back(i / 100.0);
    values.push_back(5.0);
    SummaryStats stats = Summarize(values);
    EXPECT_EQ(stats.n, 20u);
    EXPECT_NEAR(stats.p95, 0.19, 1e-12);
    EXPECT_DOUBLE_EQ(stats.max, 5.0);
    // median = (sorted[9] + sorted[10]) / 2 = (0.10 + 0.11) / 2 = 0.105;
    // mae = (sum(0.01..0.19) + 5.0) / 20 = (1.9 + 5.0) / 20 = 0.345.
    EXPECT_NEAR(stats.median, 0.105, 1e-12);
    EXPECT_NEAR(stats.mae, 0.345, 1e-12);
}

// ---------------------------------------------------------------------------
// Typed Work-4-prefix CSV schema (adjudications A1/A2, normative §Phase 5).
// ---------------------------------------------------------------------------

using namespace piccard::bench;
using piccard::benchmark::AssuranceScope;
using piccard::benchmark::AssuranceScopeName;
using piccard::benchmark::BaselineCapability;
using piccard::benchmark::BaselineEvidenceKind;
using piccard::benchmark::BaselineMethod;
using piccard::benchmark::BenchmarkMeasurementKind;
using piccard::benchmark::BenchmarkMeasurementKindName;
using piccard::benchmark::BenchmarkRunClass;
using piccard::benchmark::BenchmarkRunClassName;
using piccard::benchmark::ComparisonScope;
using piccard::benchmark::ComparisonScopeName;
using piccard::benchmark::CostScope;
using piccard::benchmark::CostScopeName;
using piccard::benchmark::EstimatorModel;
using piccard::benchmark::EstimatorModelName;
using piccard::benchmark::OutputSemantics;
using piccard::benchmark::OutputSemanticsName;
using piccard::benchmark::PrecomputationMode;
using piccard::benchmark::PrecomputationModeName;
using piccard::benchmark::Primitive;
using piccard::benchmark::PrimitiveName;
using piccard::benchmark::ProtocolModel;
using piccard::benchmark::ProtocolModelName;
using piccard::benchmark::ResolveBaselineCapability;

namespace {

// Pasted byte-for-byte from normative §Phase 5 (starting `profile_id,
// run_class,...`, ending `...,omp_dynamic,measurement_status`) — adjudication
// A1. Not `bench_review_comparison.cpp`'s CsvHeader() or
// SerializeComparisonHeader() order.
const char* kExpectedPrefixHeader =
    "profile_id,run_class,target_security_bits,cryptographic_profile,"
    "nominal_security_bits,security_match,comparison_eligible,"
    "comparison_scope,primitive,protocol_model,output_semantics,"
    "assurance_scope,security_basis,cost_scope,precomputation_mode,"
    "secure_division_included,measurement_kind,"
    "workload_id,workload_manifest_sha256,execution_trace_sha256,"
    "root_seed,omp_threads,"
    "estimator_model,sanitizer_model,sanitizer_assurance,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,"
    "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version,"
    "target_semantics,target_jaccard,realized_intersection,realized_union,"
    "realized_jaccard,timing_trials,accuracy_trials,omp_dynamic,"
    "measurement_status";

const char* kExpectedAccuracySuffix =
    "dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,"
    "pair_id,pair_kind,label,record_a,record_b,"
    "k,m,hash_randomness,accuracy_trial_index,hash_seed,"
    "set_size_a_raw,set_size_b_raw,set_size_a_bucketed,set_size_b_bucketed,"
    "exact_jaccard_raw,exact_jaccard_bucketed,estimated_jaccard,"
    "bucket_match_fraction,abs_error,rel_error,jaccard_bucket,"
    "accuracy_workload_sha256";

const char* kExpectedTimingSuffix =
    "dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,"
    "pair_id,pair_kind,label,record_a,record_b,"
    "k,m,hash_seed,trial_index,phase_minhash_ms,phase_encode_ms,"
    "phase_encrypt_ms,phase_cloud_multiply_ms,phase_cloud_rotate_ms,"
    "phase_sanitize_ms,phase_decrypt_ms,phase_bias_correction_ms,"
    "total_query_ms,result_value,ciphertext_bytes,upload_bytes,"
    "download_bytes";

}  // namespace

TEST(RealDatasetPrefixHeaderTest, MatchesNormativeA1ColumnListExactly) {
    EXPECT_EQ(RealDatasetPrefixHeader(), kExpectedPrefixHeader);
    // 46 columns, per adjudication A1.
    const std::string prefix_header = kExpectedPrefixHeader;
    EXPECT_EQ(std::count(prefix_header.begin(), prefix_header.end(), ',') + 1,
             46);
}

TEST(RealAccuracyHeaderTest, IsPrefixPlusAccuracySuffix) {
    const std::string expected =
        std::string(kExpectedPrefixHeader) + "," + kExpectedAccuracySuffix + "\n";
    EXPECT_EQ(RealAccuracyHeader(), expected);
}

TEST(RealTimingHeaderTest, IsPrefixPlusTimingSuffix) {
    const std::string expected =
        std::string(kExpectedPrefixHeader) + "," + kExpectedTimingSuffix + "\n";
    EXPECT_EQ(RealTimingHeader(), expected);
}

TEST(MakePlaintextAccuracyPrefixTest, FixedValuesMatchNormativeTableViaTypedSources) {
    const RealDatasetPrefixValues v = MakePlaintextAccuracyPrefix(
        "dblp_acm_u65536", "deadbeef00112233445566778899aabbccddeeff00112233445566778899aa",
        5, 20260729ULL);

    EXPECT_EQ(v.profile_id, "plaintext-estimator");
    EXPECT_EQ(v.run_class, "diagnostic");  // new token: no BenchmarkRunClass case
    EXPECT_FALSE(v.target_security_bits.has_value());
    EXPECT_EQ(v.cryptographic_profile, "not-applicable");
    EXPECT_FALSE(v.nominal_security_bits.has_value());
    EXPECT_FALSE(v.security_match);
    EXPECT_FALSE(v.comparison_eligible);
    // Typed-source pins [F1][F4]: compare against the function call, not a
    // re-typed literal.
    EXPECT_EQ(v.comparison_scope, ComparisonScopeName(ComparisonScope::DiagnosticOnly));
    EXPECT_EQ(v.primitive, "sha256-minhash");
    EXPECT_EQ(v.protocol_model, "plaintext-estimator-pipeline");
    EXPECT_EQ(v.output_semantics,
             OutputSemanticsName(OutputSemantics::BiasCorrectedJaccardEstimate));
    EXPECT_EQ(v.assurance_scope, "empirical-poc");
    EXPECT_EQ(v.security_basis, "not-applicable");
    EXPECT_EQ(v.cost_scope, "not-applicable");
    EXPECT_EQ(v.precomputation_mode,
             PrecomputationModeName(PrecomputationMode::NotApplicable));
    EXPECT_FALSE(v.secure_division_included);
    EXPECT_EQ(v.measurement_kind,
             BenchmarkMeasurementKindName(BenchmarkMeasurementKind::PlaintextEstimator));
    EXPECT_EQ(v.workload_id, "real:dblp_acm_u65536:accuracy");
    EXPECT_EQ(v.workload_manifest_sha256,
             "deadbeef00112233445566778899aabbccddeeff00112233445566778899aa");
    EXPECT_EQ(v.execution_trace_sha256, "not-applicable");
    EXPECT_EQ(v.root_seed, 20260729ULL);
    EXPECT_EQ(v.omp_threads, 1u);
    EXPECT_EQ(v.estimator_model,
             EstimatorModelName(EstimatorModel::Sha256RandomRankingPocV1));
    EXPECT_EQ(v.sanitizer_model, "not-applicable");
    EXPECT_EQ(v.sanitizer_assurance, "not-applicable");
    EXPECT_FALSE(v.transcript_stat_bits.has_value());
    EXPECT_FALSE(v.max_queries.has_value());
    EXPECT_FALSE(v.actual_ring_dim.has_value());
    EXPECT_FALSE(v.log_q_bits.has_value());
    EXPECT_EQ(v.openfhe_version, "not-applicable");
    EXPECT_EQ(v.target_semantics, "observed-dataset-pair");
    EXPECT_FALSE(v.target_jaccard.has_value());
    EXPECT_FALSE(v.realized_intersection.has_value());
    EXPECT_FALSE(v.timing_trials.has_value());
    ASSERT_TRUE(v.accuracy_trials.has_value());
    EXPECT_EQ(*v.accuracy_trials, 5u);
    EXPECT_FALSE(v.omp_dynamic);
    EXPECT_EQ(v.measurement_status, "measured");
}

TEST(MakePlaintextAccuracyPrefixTest, RejectsEmptyVariantOrWorkloadSha) {
    EXPECT_THROW(MakePlaintextAccuracyPrefix("", "abc", 1, 1), std::invalid_argument);
    EXPECT_THROW(MakePlaintextAccuracyPrefix("dblp_acm_u65536", "", 1, 1),
                std::invalid_argument);
}

TEST(SerializeRealDatasetPrefixTest, AccuracyGoldenRow) {
    RealDatasetPrefixValues v = MakePlaintextAccuracyPrefix(
        "dblp_acm_u65536", "0000000000000000000000000000000000000000000000000000000000000abc",
        2, 7ULL);
    // The accuracy driver (Sub-phase 5.3) fills these per pair.
    v.realized_intersection = 3;
    v.realized_union = 5;
    v.realized_jaccard = 0.6;  // exercises FormatReal17 reuse (17-sig-digit form)

    const std::string row = SerializeRealDatasetPrefix(v);
    const std::string expected =
        "plaintext-estimator,diagnostic,,not-applicable,,false,false,"
        "diagnostic-only,sha256-minhash,plaintext-estimator-pipeline,"
        "bias-corrected-jaccard-estimate,empirical-poc,not-applicable,"
        "not-applicable,not-applicable,false,plaintext-estimator,"
        "real:dblp_acm_u65536:accuracy,"
        "0000000000000000000000000000000000000000000000000000000000000abc,"
        "not-applicable,7,1,"
        "sha256-random-ranking-poc-v1,not-applicable,not-applicable,,,,,,,,"
        ",,,,not-applicable,"
        "observed-dataset-pair,,3,5,0.59999999999999998,,2,false,measured";
    EXPECT_EQ(row, expected);
}

TEST(SerializeRealDatasetPrefixTest, ThrowsWhenRequiredStringFieldIsMissing) {
    RealDatasetPrefixValues v = MakePlaintextAccuracyPrefix(
        "dblp_acm_u65536", "abc", 1, 1);
    v.openfhe_version.clear();
    EXPECT_THROW(SerializeRealDatasetPrefix(v), std::invalid_argument);
}

TEST(MakeFheTimingPrefixTest, ResolvesWork4ProfileAndCapabilityViaTypedSources) {
    const RealDatasetPrefixValues v = MakeFheTimingPrefix(
        "dblp_acm_u65536", "toy-smoke",
        "1111111111111111111111111111111111111111111111111111111111111111",
        20260729ULL, 2, 1);

    EXPECT_EQ(v.profile_id, "toy-smoke");
    EXPECT_EQ(v.run_class, BenchmarkRunClassName(BenchmarkRunClass::Smoke));
    ASSERT_TRUE(v.target_security_bits.has_value());
    EXPECT_EQ(*v.target_security_bits, 0u);  // TOY profile

    const BaselineCapability capability = ResolveBaselineCapability(
        BaselineMethod::Piccard, 0, BaselineEvidenceKind::Timing);
    EXPECT_EQ(v.cryptographic_profile, capability.cryptographic_profile);
    EXPECT_EQ(v.security_match, capability.security_match);
    EXPECT_EQ(v.comparison_eligible, capability.comparison_eligible);
    EXPECT_EQ(v.comparison_scope, ComparisonScopeName(ComparisonScope::EndToEndEstimator));
    EXPECT_EQ(v.primitive, PrimitiveName(Primitive::BfvOneHotMinHash));
    EXPECT_EQ(v.protocol_model, ProtocolModelName(ProtocolModel::PiccardTwoOwnerOutsourced));
    EXPECT_EQ(v.output_semantics,
             OutputSemanticsName(OutputSemantics::BiasCorrectedJaccardEstimate));
    EXPECT_EQ(v.assurance_scope,
             AssuranceScopeName(AssuranceScope::LiveBfvEmpiricalSanitizerPoc));
    EXPECT_EQ(v.cost_scope, CostScopeName(CostScope::FullQueryExcludingOneTimeSetup));
    EXPECT_EQ(v.precomputation_mode,
             PrecomputationModeName(PrecomputationMode::CrsAndKeysOnly));
    EXPECT_FALSE(v.secure_division_included);
    EXPECT_EQ(v.measurement_kind, BenchmarkMeasurementKindName(BenchmarkMeasurementKind::FheTiming));
    EXPECT_EQ(v.workload_id, "real:dblp_acm_u65536:timing:toy-smoke");
    EXPECT_EQ(v.workload_manifest_sha256,
             "1111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_EQ(v.execution_trace_sha256, "not-applicable");
    EXPECT_EQ(v.root_seed, 20260729ULL);
    EXPECT_EQ(v.omp_threads, 1u);
    EXPECT_EQ(v.estimator_model,
             EstimatorModelName(EstimatorModel::Sha256RandomRankingPocV1));
    // Live sanitizer/FHE provenance is not yet known at this call site
    // (Sub-phase 5.4 fills it from a real BFV context).
    EXPECT_TRUE(v.sanitizer_model.empty());
    EXPECT_TRUE(v.openfhe_version.empty());
    EXPECT_EQ(v.target_semantics, "observed-dataset-pair");
    EXPECT_FALSE(v.target_jaccard.has_value());
    ASSERT_TRUE(v.timing_trials.has_value());
    EXPECT_EQ(*v.timing_trials, 2u);
    EXPECT_FALSE(v.accuracy_trials.has_value());
    EXPECT_FALSE(v.omp_dynamic);
    EXPECT_EQ(v.measurement_status, "measured");
}

TEST(SerializeRealDatasetPrefixTest, TimingGoldenRowWithLiveProvenanceFilledIn) {
    RealDatasetPrefixValues v = MakeFheTimingPrefix(
        "dblp_acm_u65536", "toy-smoke",
        "2222222222222222222222222222222222222222222222222222222222222222",
        7ULL, 3, 4);
    // The timing driver (Sub-phase 5.4) fills these from the live context.
    v.sanitizer_model = "phase-smudging-enc0-poc-v1";
    v.sanitizer_assurance = "empirical-phase-statistical+ciphertext-computational";
    v.transcript_stat_bits = 40;
    v.max_queries = UINT64_C(1) << 20;
    v.query_stat_bits = 20;
    v.coefficient_stat_bits = 12;
    v.flood_margin_bits = 8;
    v.eval_noise_bits = 4;
    v.flood_noise_bits = 6;
    v.actual_ring_dim = 8192;
    v.log_q_bits = 218.5;
    v.plaintext_modulus = 65537;
    v.num_limbs = 4;
    v.openfhe_version = "1.2.3";
    v.realized_intersection = 10;
    v.realized_union = 20;
    v.realized_jaccard = 0.5;

    const std::string row = SerializeRealDatasetPrefix(v);
    const std::string expected =
        "toy-smoke,smoke,0,live-BFV-TOY,0,true,false,"
        "end-to-end-estimator,bfv-onehot-minhash,piccard-two-owner-outsourced,"
        "bias-corrected-jaccard-estimate,live-bfv+empirical-sanitizer-poc,"
        "openfhe-hesea-standard-live-context,full-query-excluding-one-time-setup,"
        "crs-and-keys-only,false,fhe-timing,"
        "real:dblp_acm_u65536:timing:toy-smoke,"
        "2222222222222222222222222222222222222222222222222222222222222222,"
        "not-applicable,7,4,"
        "sha256-random-ranking-poc-v1,phase-smudging-enc0-poc-v1,"
        "empirical-phase-statistical+ciphertext-computational,"
        "40,1048576,20,12,8,4,6,"
        "8192,218.5,65537,4,1.2.3,"
        "observed-dataset-pair,,10,20,0.5,3,,false,measured";
    EXPECT_EQ(row, expected);
}
