#include "noise_calibration_schema.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace nc = piccard::benchmark::noise_calibration;

namespace {

std::vector<std::string> RequiredEvidenceArgs() {
    return {
        "--pre_threshold",
        "--profile_manifest=profiles.json",
        "--profile=primary40",
        "--key_id=primary40:onehot:STD128",
        "--circuit=onehot",
        "--security=STD128",
        "--scaling_mod_grid=40,52,60",
        "--max_depth_delta=2",
        "--ring_candidates=8192,16384",
        "--timeout_seconds=300",
        "--transcript_stat_bits=40",
        "--max_queries=1048576",
        "--margin=8",
        "--reps=5",
        "--seed=20260729",
    };
}

nc::DetailRow SuccessfulDetail(
    uint32_t consumer_k,
    uint32_t consumer_m,
    const std::string& pattern,
    uint32_t rep_index,
    double eval_noise_bits,
    double headroom_bits,
    uint64_t ct_bytes) {
    nc::DetailRow row;
    row.profile = "primary40";
    row.key_id = "primary40:onehot:STD128";
    row.candidate_id = "N8192-d3-s52";
    row.circuit = "onehot";
    row.shape_id = "onehot-v1";
    row.security = "STD128";
    row.consumer_k = consumer_k;
    row.consumer_m = consumer_m;
    row.pattern = pattern;
    row.rep_index = rep_index;
    row.rep_seed = 1000 + rep_index;
    row.requested_ring_dim = 8192;
    row.natural_ring_dim = 8192;
    row.ring_dim_calibrated = 8192;
    row.realized_ring_dim = 8192;
    row.ring_growth_factor = 1.0;
    row.natural_depth = 2;
    row.provisioned_depth = 3;
    row.scaling_mod_size = 52;
    row.num_limbs = 4;
    row.plaintext_mod = 65537;
    row.log_q = 208.0;
    row.log_delta = 192.0;
    row.eval_noise_bits = eval_noise_bits;
    row.headroom_bits = headroom_bits;
    row.max_queries = 1048576;
    row.query_stat_bits = 60;
    row.coefficient_stat_bits = 73;
    row.flood_margin_bits = 8;
    row.flood_noise_bits = 110;
    row.decrypt_ok = true;
    row.saturated = false;
    row.ct_bytes = ct_bytes;
    row.openfhe_version = nc::CurrentOpenFHEVersion();
    row.source_commit = nc::EmbeddedSourceCommit();
    row.status_code = nc::StatusCode::Ok;
    return row;
}

nc::AggregateRow AggregateTemplate() {
    nc::AggregateRow row;
    row.profile = "primary40";
    row.circuit = "onehot";
    row.shape_id = "onehot-v1";
    row.security = "STD128";
    row.consumer_count = 1;
    row.consumer_set_sha256 =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    row.seed = 20260729;
    row.requested_ring_dim = 8192;
    row.natural_ring_dim = 8192;
    row.realized_ring_dim = 8192;
    row.ring_growth_factor = 1.0;
    row.ring_dim_calibrated = 8192;
    row.natural_depth = 2;
    row.provisioned_depth = 3;
    row.scaling_mod_size = 52;
    row.num_limbs = 4;
    row.plaintext_mod = 65537;
    row.log_q = 208.0;
    row.log_delta = 192.0;
    row.max_queries = 1048576;
    row.flood_margin_bits = 8;
    row.openfhe_version = nc::CurrentOpenFHEVersion();
    row.source_commit = nc::EmbeddedSourceCommit();
    return row;
}

std::vector<nc::DetailRow> CompleteDetails() {
    std::vector<nc::DetailRow> rows;
    const std::vector<std::string> patterns = {
        "all_match", "no_match", "random"};
    for (const auto& pattern : patterns) {
        for (uint32_t rep = 0; rep < 5; ++rep) {
            rows.push_back(SuccessfulDetail(
                128,
                64,
                pattern,
                rep,
                24.0 + rep,
                167.0 - rep,
                4096 + rep));
        }
    }
    return rows;
}

size_t CsvFieldCount(const std::string& csv_record) {
    size_t fields = 1;
    bool quoted = false;
    for (size_t index = 0; index < csv_record.size(); ++index) {
        const char ch = csv_record[index];
        if (ch == '"') {
            if (quoted && index + 1 < csv_record.size() &&
                csv_record[index + 1] == '"') {
                ++index;
            } else {
                quoted = !quoted;
            }
        } else if (ch == ',' && !quoted) {
            ++fields;
        }
    }
    return fields;
}

std::vector<std::string> ParseCsvRecord(const std::string& csv_record) {
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;
    for (size_t index = 0; index < csv_record.size(); ++index) {
        const char ch = csv_record[index];
        if (ch == '"') {
            if (quoted && index + 1 < csv_record.size() &&
                csv_record[index + 1] == '"') {
                field += '"';
                ++index;
            } else {
                quoted = !quoted;
            }
        } else if (ch == ',' && !quoted) {
            fields.push_back(field);
            field.clear();
        } else {
            field += ch;
        }
    }
    fields.push_back(field);
    return fields;
}

}  // namespace

TEST(NoiseEvidenceParser, IsInactiveForLegacyDeveloperMode) {
    const nc::EvidenceOptions options =
        nc::ParseEvidenceOptions({"--circuit=threshold", "--security=TOY"});
    EXPECT_FALSE(options.pre_threshold);
}

TEST(NoiseEvidenceParser, CoverageModeNeedsNoCandidateIdentity) {
    const nc::EvidenceOptions options =
        nc::ParseEvidenceOptions({"--coverage", "--pre_threshold"});
    EXPECT_TRUE(options.pre_threshold);
    EXPECT_TRUE(options.coverage);
}

TEST(NoiseEvidenceParser, CoverageModeStillRejectsLegacyPairs) {
    EXPECT_THROW(
        nc::ParseEvidenceOptions(
            {"--coverage", "--pre_threshold", "--circuit=threshold"}),
        std::invalid_argument);
    EXPECT_THROW(
        nc::ParseEvidenceOptions(
            {"--coverage", "--pre_threshold", "--security=TOY"}),
        std::invalid_argument);
}

TEST(NoiseEvidenceParser, AcceptsCanonicalOneHotStd128Options) {
    const nc::EvidenceOptions options =
        nc::ParseEvidenceOptions(RequiredEvidenceArgs());

    EXPECT_TRUE(options.pre_threshold);
    EXPECT_EQ(options.profile_manifest, "profiles.json");
    EXPECT_EQ(options.profile, "primary40");
    EXPECT_EQ(options.key_id, "primary40:onehot:STD128");
    EXPECT_EQ(options.circuit, "onehot");
    EXPECT_EQ(options.security, "STD128");
    EXPECT_EQ(options.scaling_mod_grid, (std::vector<uint32_t>{40, 52, 60}));
    EXPECT_EQ(options.max_depth_delta, 2u);
    EXPECT_EQ(options.ring_candidates, (std::vector<uint32_t>{8192, 16384}));
    EXPECT_EQ(options.timeout_seconds, 300u);
    EXPECT_EQ(options.transcript_stat_bits, 40u);
    EXPECT_EQ(options.max_queries, UINT64_C(1048576));
    EXPECT_EQ(options.margin, 8u);
    EXPECT_EQ(options.reps, 5u);
    EXPECT_EQ(options.seed, UINT64_C(20260729));
}

TEST(NoiseEvidenceParser, AcceptsSqrtStd192AndSplitValueSyntax) {
    const nc::EvidenceOptions options = nc::ParseEvidenceOptions({
        "--pre_threshold",
        "--profile_manifest", "profiles.json",
        "--profile", "sensitivity64",
        "--key_id", "sensitivity64:sqrt:STD192",
        "--circuit", "sqrt",
        "--security", "STD192",
        "--scaling_mod_grid", "40,60",
        "--max_depth_delta", "1",
        "--ring_candidates", "16384",
        "--timeout_seconds", "60",
        "--transcript_stat_bits", "64",
        "--max_queries", "1048576",
        "--margin", "8",
        "--reps", "5",
        "--seed", "0",
    });

    EXPECT_EQ(options.circuit, "sqrt");
    EXPECT_EQ(options.security, "STD192");
    EXPECT_EQ(options.transcript_stat_bits, 64u);
    EXPECT_EQ(options.max_queries, UINT64_C(1) << 20);
    EXPECT_EQ(options.margin, 8u);
    EXPECT_EQ(options.seed, 0u);
}

TEST(NoiseEvidenceParser, AcceptsOnlyCanonicalProfilePolicies) {
    for (const auto& [profile_id, stat_bits] :
         std::vector<std::pair<std::string, uint32_t>>{
             {"primary40", 40},
             {"sensitivity64", 64},
             {"feasibility128", 128},
         }) {
        auto args = RequiredEvidenceArgs();
        args[2] = "--profile=" + profile_id;
        args[3] = "--key_id=" + profile_id + ":onehot:STD128";
        args[10] = "--transcript_stat_bits=" + std::to_string(stat_bits);
        EXPECT_NO_THROW(nc::ParseEvidenceOptions(args));
    }
}

TEST(NoiseEvidenceParser, RejectsUnknownOrMismatchedProfilePolicy) {
    const std::vector<std::pair<size_t, std::string>> mismatches = {
        {2, "--profile=unknown40"},
        {10, "--transcript_stat_bits=64"},
        {11, "--max_queries=1048575"},
        {12, "--margin=9"},
    };
    for (const auto& [index, replacement] : mismatches) {
        auto args = RequiredEvidenceArgs();
        args[index] = replacement;
        EXPECT_THROW(nc::ParseEvidenceOptions(args), std::invalid_argument)
            << replacement;
    }
}

TEST(NoiseEvidenceParser, RejectsUnsupportedCircuitBeforeExecution) {
    for (const char* circuit : {"threshold", "all", "bogus"}) {
        auto args = RequiredEvidenceArgs();
        args[4] = std::string("--circuit=") + circuit;
        EXPECT_THROW(nc::ParseEvidenceOptions(args), std::invalid_argument);
    }
}

TEST(NoiseEvidenceParser, RejectsUnsupportedSecurityBeforeExecution) {
    for (const char* security : {"TOY", "STD256", "bogus"}) {
        auto args = RequiredEvidenceArgs();
        args[5] = std::string("--security=") + security;
        EXPECT_THROW(nc::ParseEvidenceOptions(args), std::invalid_argument);
    }
}

TEST(NoiseEvidenceParser, RejectsMalformedStrictNumericInputs) {
    const std::vector<std::pair<size_t, std::string>> invalid = {
        {6, "--scaling_mod_grid=40,,60"},
        {6, "--scaling_mod_grid=0"},
        {7, "--max_depth_delta=-1"},
        {8, "--ring_candidates=8193"},
        {9, "--timeout_seconds=0"},
        {10, "--transcript_stat_bits=41"},
        {11, "--max_queries=0"},
        {11, "--max_queries=9223372036854775809"},
        {12, "--margin=-1"},
        {13, "--reps=0"},
        {14, "--seed=12x"},
    };

    for (const auto& [index, replacement] : invalid) {
        auto args = RequiredEvidenceArgs();
        args[index] = replacement;
        EXPECT_THROW(nc::ParseEvidenceOptions(args), std::invalid_argument)
            << replacement;
    }
}

TEST(NoiseEvidenceParser, RequiresFiveRepetitionsUnlessSmokeIsExplicit) {
    auto args = RequiredEvidenceArgs();
    args[13] = "--reps=4";
    EXPECT_THROW(nc::ParseEvidenceOptions(args), std::invalid_argument);

    args.push_back("--smoke");
    const nc::EvidenceOptions options = nc::ParseEvidenceOptions(args);
    EXPECT_TRUE(options.smoke);
    EXPECT_EQ(options.reps, 4u);
}

TEST(NoiseEvidenceParser, RequiresEvidenceIdentityAndSearchInputs) {
    for (size_t index : {1u, 2u, 3u, 6u, 8u}) {
        auto args = RequiredEvidenceArgs();
        args.erase(args.begin() + static_cast<std::ptrdiff_t>(index));
        EXPECT_THROW(nc::ParseEvidenceOptions(args), std::invalid_argument);
    }
}

TEST(NoiseCoverage, PreThresholdMatrixContainsOnlyRevisionPairs) {
    const auto matrix = nc::PreThresholdCoverageMatrix();
    ASSERT_EQ(matrix.size(), 4u);
    EXPECT_EQ(matrix[0], (nc::CoverageEntry{"onehot", "STD128"}));
    EXPECT_EQ(matrix[1], (nc::CoverageEntry{"onehot", "STD192"}));
    EXPECT_EQ(matrix[2], (nc::CoverageEntry{"sqrt", "STD128"}));
    EXPECT_EQ(matrix[3], (nc::CoverageEntry{"sqrt", "STD192"}));
}

TEST(NoiseCalibrationSchema, HeadersAreExact) {
    constexpr const char* kAggregateHeader =
        "profile,circuit,shape_id,security,consumer_count,"
        "consumer_set_sha256,worst_consumer_k,worst_consumer_m,pattern_count,"
        "repetitions_per_pattern,detail_row_count,detail_sha256,seed,"
        "requested_ring_dim,natural_ring_dim,realized_ring_dim,"
        "ring_growth_factor,ring_dim_calibrated,natural_depth,"
        "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,"
        "log_delta,eval_noise_bits,headroom_bits,max_queries,query_stat_bits,"
        "coefficient_stat_bits,flood_margin_bits,flood_noise_bits,decrypt_ok,"
        "saturated,ct_bytes,openfhe_version,source_commit,status_code,"
        "error_message,consumer_results_sha256";
    constexpr const char* kDetailHeader =
        "profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,"
        "consumer_m,pattern,rep_index,rep_seed,requested_ring_dim,"
        "natural_ring_dim,ring_dim_calibrated,realized_ring_dim,"
        "ring_growth_factor,natural_depth,provisioned_depth,scaling_mod_size,"
        "num_limbs,plaintext_mod,log_q,log_delta,eval_noise_bits,"
        "headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
        "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,"
        "openfhe_version,source_commit,status_code,error_message";

    EXPECT_EQ(nc::AggregateCsvHeader(), kAggregateHeader);
    EXPECT_EQ(nc::DetailCsvHeader(), kDetailHeader);
    EXPECT_EQ(CsvFieldCount(nc::AggregateCsvHeader()), 40u);
    EXPECT_EQ(CsvFieldCount(nc::DetailCsvHeader()), 37u);
}

TEST(NoiseCalibrationSchema, SuccessRowsMatchTheirHeaderCounts) {
    nc::AggregateRow aggregate = AggregateTemplate();
    aggregate.worst_consumer_k = 128;
    aggregate.worst_consumer_m = 64;
    aggregate.pattern_count = 3;
    aggregate.repetitions_per_pattern = 5;
    aggregate.detail_row_count = 15;
    aggregate.detail_sha256 = std::string(64, 'b');
    aggregate.eval_noise_bits = 28.0;
    aggregate.headroom_bits = 163.0;
    aggregate.query_stat_bits = 60;
    aggregate.coefficient_stat_bits = 73;
    aggregate.flood_noise_bits = 109;
    aggregate.decrypt_ok = true;
    aggregate.saturated = false;
    aggregate.ct_bytes = 4100;
    aggregate.status_code = nc::StatusCode::Ok;
    aggregate.consumer_results_sha256 = std::string(64, 'c');

    const nc::DetailRow detail =
        SuccessfulDetail(128, 64, "random", 4, 28.0, 163.0, 4100);
    EXPECT_EQ(
        CsvFieldCount(nc::SerializeAggregateCsvRow(aggregate)),
        CsvFieldCount(nc::AggregateCsvHeader()));
    EXPECT_EQ(
        CsvFieldCount(nc::SerializeDetailCsvRow(detail)),
        CsvFieldCount(nc::DetailCsvHeader()));
}

TEST(NoiseCalibrationSchema, SerializationAlwaysAddsBuildProvenance) {
    nc::AggregateRow aggregate = AggregateTemplate();
    aggregate.openfhe_version.clear();
    aggregate.source_commit.clear();
    const auto aggregate_fields =
        ParseCsvRecord(nc::SerializeAggregateCsvRow(aggregate));
    ASSERT_EQ(aggregate_fields.size(), 40u);
    EXPECT_EQ(aggregate_fields[35], nc::CurrentOpenFHEVersion());
    EXPECT_EQ(aggregate_fields[36], nc::EmbeddedSourceCommit());

    nc::DetailRow detail =
        SuccessfulDetail(128, 64, "random", 0, 20.0, 170.0, 4000);
    detail.openfhe_version.clear();
    detail.source_commit.clear();
    const auto detail_fields =
        ParseCsvRecord(nc::SerializeDetailCsvRow(detail));
    ASSERT_EQ(detail_fields.size(), 37u);
    EXPECT_EQ(detail_fields[33], nc::CurrentOpenFHEVersion());
    EXPECT_EQ(detail_fields[34], nc::EmbeddedSourceCommit());
}

TEST(NoiseCalibrationSchema, FailureRowsEscapeTextAndLeaveUnavailableNumbersEmpty) {
    for (nc::StatusCode status : {
             nc::StatusCode::ContextError,
             nc::StatusCode::DecryptFail,
             nc::StatusCode::Saturated,
             nc::StatusCode::Timeout,
             nc::StatusCode::ProcessError}) {
        nc::AggregateRow aggregate = AggregateTemplate();
        aggregate.realized_ring_dim.reset();
        aggregate.ring_growth_factor.reset();
        aggregate.num_limbs.reset();
        aggregate.plaintext_mod.reset();
        aggregate.log_q.reset();
        aggregate.log_delta.reset();
        aggregate.eval_noise_bits.reset();
        aggregate.headroom_bits.reset();
        aggregate.query_stat_bits.reset();
        aggregate.coefficient_stat_bits.reset();
        aggregate.flood_noise_bits.reset();
        aggregate.ct_bytes.reset();
        aggregate.status_code = status;
        aggregate.error_message = "failed, \"quoted\"\nnext line";

        const std::string serialized =
            nc::SerializeAggregateCsvRow(aggregate);
        EXPECT_EQ(
            CsvFieldCount(serialized),
            CsvFieldCount(nc::AggregateCsvHeader()));
        EXPECT_NE(
            serialized.find("\"failed, \"\"quoted\"\"\nnext line\""),
            std::string::npos);
        const auto fields = ParseCsvRecord(serialized);
        ASSERT_EQ(fields.size(), 40u);
        for (size_t index : {
                 15u, 16u, 21u, 22u, 23u, 24u, 25u, 26u,
                 28u, 29u, 31u, 34u}) {
            EXPECT_TRUE(fields[index].empty()) << "field " << index;
        }
        EXPECT_EQ(fields[32], "0");
        EXPECT_EQ(fields[33], "0");
        EXPECT_NE(std::string(nc::StatusName(status)), "INFEASIBLE");
    }
}

TEST(NoiseCalibrationSchema, DetailRowsSortByTheCanonicalTuple) {
    auto a = SuccessfulDetail(128, 64, "random", 1, 20.0, 170.0, 4000);
    auto b = a;
    auto c = a;
    auto d = a;
    auto e = a;
    b.key_id = "a";
    c.candidate_id = "A";
    d.consumer_k = 64;
    e.consumer_m = 32;
    a.rep_index = 2;

    const auto sorted = nc::CanonicalizeDetailRows({a, b, c, d, e});
    ASSERT_EQ(sorted.size(), 5u);
    EXPECT_EQ(sorted[0].key_id, "a");
    EXPECT_EQ(sorted[1].candidate_id, "A");
    EXPECT_EQ(sorted[2].consumer_k, 64u);
    EXPECT_EQ(sorted[3].consumer_m, 32u);
    EXPECT_EQ(sorted[4].rep_index, 2u);
}

TEST(NoiseCalibrationSchema, DetailHashIncludesHeaderAndCanonicalRows) {
    auto first =
        SuccessfulDetail(128, 64, "random", 1, 20.0, 170.0, 4000);
    auto second =
        SuccessfulDetail(128, 64, "all_match", 0, 21.0, 169.0, 4001);
    first.openfhe_version = "test-openfhe";
    first.source_commit = "test-commit";
    second.openfhe_version = "test-openfhe";
    second.source_commit = "test-commit";

    const std::string canonical_bytes =
        nc::DetailCsvHeader() + "\n" +
        nc::SerializeDetailCsvRow(second) + "\n" +
        nc::SerializeDetailCsvRow(first) + "\n";
    EXPECT_EQ(
        nc::DetailSha256({first, second}),
        nc::Sha256Hex(canonical_bytes));
    EXPECT_EQ(
        nc::DetailSha256({first, second}),
        "dd6dd55b828bb94467104cd51972f386e78f7e944fbb280a47f44af4361b0740");

    first.candidate_id = "other-candidate";
    EXPECT_NE(
        nc::DetailSha256({first, second}),
        nc::Sha256Hex(canonical_bytes));
}

TEST(NoiseCalibrationSchema, ReducesCompleteCandidateDeterministically) {
    auto details = CompleteDetails();
    std::reverse(details.begin(), details.end());

    const nc::AggregateRow aggregate =
        nc::ReduceCandidate(AggregateTemplate(), details, 40);

    EXPECT_EQ(aggregate.worst_consumer_k, 128u);
    EXPECT_EQ(aggregate.worst_consumer_m, 64u);
    EXPECT_EQ(aggregate.pattern_count, 3u);
    EXPECT_EQ(aggregate.repetitions_per_pattern, 5u);
    EXPECT_EQ(aggregate.detail_row_count, 15u);
    EXPECT_EQ(aggregate.eval_noise_bits, 28.0);
    EXPECT_EQ(aggregate.headroom_bits, 163.0);
    EXPECT_EQ(aggregate.decrypt_ok, true);
    EXPECT_EQ(aggregate.saturated, false);
    EXPECT_EQ(aggregate.ct_bytes, 4100u);
    EXPECT_EQ(aggregate.query_stat_bits, 60u);
    EXPECT_EQ(aggregate.coefficient_stat_bits, 73u);
    EXPECT_EQ(aggregate.flood_noise_bits, 109u);
    EXPECT_EQ(aggregate.status_code, nc::StatusCode::Ok);
    EXPECT_TRUE(nc::HasCompleteEvidence(aggregate));
    EXPECT_EQ(aggregate.detail_sha256, nc::DetailSha256(details));
    EXPECT_EQ(
        aggregate.consumer_results_sha256,
        "5a2be46d592a7b0d847c96a42b4ebc5e4e6fb6fc0af52595f49839dcecf19bd6");

    const nc::AggregateRow second =
        nc::ReduceCandidate(AggregateTemplate(), CompleteDetails(), 40);
    EXPECT_EQ(
        aggregate.consumer_results_sha256,
        second.consumer_results_sha256);
}

TEST(NoiseCalibrationSchema, RejectsMixedCandidateContextOrProvenance) {
    auto details = CompleteDetails();
    details[1].source_commit = "different-commit";
    EXPECT_THROW(
        nc::ReduceCandidate(AggregateTemplate(), details, 40),
        std::invalid_argument);

    details = CompleteDetails();
    details[1].realized_ring_dim = 16384;
    EXPECT_THROW(
        nc::ReduceCandidate(AggregateTemplate(), details, 40),
        std::invalid_argument);
}

TEST(NoiseCalibrationSchema, AppliesCanonicalFailurePrecedence) {
    auto details = CompleteDetails();
    details[0].status_code = nc::StatusCode::Saturated;
    details[0].saturated = true;
    details[1].status_code = nc::StatusCode::DecryptFail;
    details[1].decrypt_ok = false;
    details[2].status_code = nc::StatusCode::ContextError;
    details[3].status_code = nc::StatusCode::Timeout;
    details[4].status_code = nc::StatusCode::ProcessError;

    const nc::AggregateRow aggregate =
        nc::ReduceCandidate(AggregateTemplate(), details, 40);
    EXPECT_EQ(aggregate.status_code, nc::StatusCode::ProcessError);
    EXPECT_EQ(aggregate.decrypt_ok, false);

    details[4].status_code = nc::StatusCode::Ok;
    EXPECT_EQ(
        nc::ReduceCandidate(AggregateTemplate(), details, 40).status_code,
        nc::StatusCode::Timeout);
    details[3].status_code = nc::StatusCode::Ok;
    EXPECT_EQ(
        nc::ReduceCandidate(AggregateTemplate(), details, 40).status_code,
        nc::StatusCode::ContextError);
    details[2].status_code = nc::StatusCode::Ok;
    EXPECT_EQ(
        nc::ReduceCandidate(AggregateTemplate(), details, 40).status_code,
        nc::StatusCode::DecryptFail);
    details[1].status_code = nc::StatusCode::Ok;
    details[1].decrypt_ok = true;
    EXPECT_EQ(
        nc::ReduceCandidate(AggregateTemplate(), details, 40).status_code,
        nc::StatusCode::Saturated);
}

TEST(NoiseCalibrationSchema, CanonicalizesMeasurementFailuresIntoStatus) {
    auto details = CompleteDetails();
    details[0].decrypt_ok = false;
    EXPECT_EQ(
        nc::ReduceCandidate(AggregateTemplate(), details, 40).status_code,
        nc::StatusCode::DecryptFail);

    details[0].decrypt_ok = true;
    details[0].saturated = true;
    EXPECT_EQ(
        nc::ReduceCandidate(AggregateTemplate(), details, 40).status_code,
        nc::StatusCode::Saturated);
}

TEST(NoiseCalibrationSchema, CompletenessRequiresConsumerTimesPatternsTimesReps) {
    EXPECT_EQ(nc::ExpectedDetailRowCount(2, 3, 5), 30u);

    nc::AggregateRow aggregate = AggregateTemplate();
    aggregate.consumer_count = 2;
    aggregate.pattern_count = 3;
    aggregate.repetitions_per_pattern = 5;
    aggregate.detail_row_count = 29;
    EXPECT_FALSE(nc::HasCompleteEvidence(aggregate));
    aggregate.detail_row_count = 30;
    EXPECT_TRUE(nc::HasCompleteEvidence(aggregate));
}

TEST(NoiseCalibrationSchema, UsesBuildProvenanceRatherThanPlaceholders) {
    EXPECT_EQ(
        nc::Sha256Hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const std::string version = nc::CurrentOpenFHEVersion();
    EXPECT_FALSE(version.empty());
    EXPECT_NE(version, "unknown");
    EXPECT_NE(version, "OPENFHE_VERSION");
    EXPECT_NE(version, "BASE_OPENFHE_VERSION");

    const std::string commit = nc::EmbeddedSourceCommit();
    ASSERT_EQ(commit.size(), 40u);
    EXPECT_TRUE(std::all_of(
        commit.begin(),
        commit.end(),
        [](char ch) {
            return (ch >= '0' && ch <= '9') ||
                   (ch >= 'a' && ch <= 'f');
        }));
}
