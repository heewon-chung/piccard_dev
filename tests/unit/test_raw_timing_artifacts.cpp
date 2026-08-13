#include "raw_timing_schema.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace piccard::benchmark {
namespace {

RawTimingArtifact ToyArtifact() {
    RawTimingArtifact artifact;
    artifact.producer_id = "bench_piccard";
    artifact.profile_id = "readiness-toy-v1";
    artifact.cell_id = "piccard.control";
    artifact.warmup_policy = WarmupPolicy::DiscardOne;
    artifact.expected_measured = 1;
    artifact.samples = {
        {"bench_piccard", "readiness-toy-v1", "piccard.control", "total",
         SampleKind::DiscardedWarmup, 0, 0x11, 99.0},
        {"bench_piccard", "readiness-toy-v1", "piccard.control", "total",
         SampleKind::Measured, 0, 0x22, 3.25},
    };
    return artifact;
}

RawTimingArtifact PaperArtifact() {
    RawTimingArtifact artifact;
    artifact.producer_id = "bench_onehot_sqrt";
    artifact.profile_id = "paper-v1";
    artifact.cell_id = "onehot.control";
    artifact.warmup_policy = WarmupPolicy::DiscardOne;
    artifact.expected_measured = 30;
    artifact.samples.push_back({"bench_onehot_sqrt", "paper-v1",
                                "onehot.control", "encode",
                                SampleKind::DiscardedWarmup, 0, 7, 100.0});
    for (uint64_t trial = 0; trial < 30; ++trial) {
        artifact.samples.push_back({"bench_onehot_sqrt", "paper-v1",
                                    "onehot.control", "encode",
                                    SampleKind::Measured, trial, 100 + trial,
                                    1.0 + static_cast<double>(trial)});
    }
    return artifact;
}

TEST(RawTimingArtifacts, ToySerializesOneMeasuredSampleAndNAAggregates) {
    const auto artifact = ToyArtifact();
    const std::string serialized = SerializeRawTimingArtifactV1(artifact);

    EXPECT_NE(serialized.find("schema_version\tpiccard-paper-raw-timing-v1\n"),
              std::string::npos);
    EXPECT_NE(serialized.find("discarded_warmup"),
              std::string::npos);
    EXPECT_NE(serialized.find("aggregate\tbench_piccard\treadiness-toy-v1"),
              std::string::npos);
    EXPECT_NE(serialized.find("\t1\t3.25\tN/A\t3.25\tN/A\tN/A\t17-digit"),
              std::string::npos);

    const auto parsed = ParseRawTimingArtifactV1(serialized);
    EXPECT_EQ(parsed.samples.size(), 2u);
    ASSERT_EQ(parsed.aggregates.size(), 1u);
    EXPECT_EQ(parsed.aggregates.front().measured_count, 1u);
    EXPECT_DOUBLE_EQ(parsed.aggregates.front().mean_ms, 3.25);
    EXPECT_FALSE(parsed.aggregates.front().sample_sd_ms.has_value());
    EXPECT_FALSE(parsed.aggregates.front().ci95_low_ms.has_value());
    EXPECT_FALSE(parsed.aggregates.front().ci95_high_ms.has_value());
}

TEST(RawTimingArtifacts, PaperUsesThirtyMeasuredRowsAndStudentTInterval) {
    const auto artifact = PaperArtifact();
    const auto serialized = SerializeRawTimingArtifactV1(artifact);
    const auto parsed = ParseRawTimingArtifactV1(serialized);

    ASSERT_EQ(parsed.samples.size(), 31u);
    ASSERT_EQ(parsed.aggregates.size(), 1u);
    const auto& aggregate = parsed.aggregates.front();
    EXPECT_EQ(aggregate.measured_count, 30u);
    EXPECT_DOUBLE_EQ(aggregate.mean_ms, 15.5);
    EXPECT_NEAR(*aggregate.sample_sd_ms,
                std::sqrt(77.5), 1e-14);
    EXPECT_DOUBLE_EQ(aggregate.median_ms, 15.5);
    EXPECT_LT(*aggregate.ci95_low_ms, aggregate.mean_ms);
    EXPECT_GT(*aggregate.ci95_high_ms, aggregate.mean_ms);
    EXPECT_EQ(aggregate.format_version, "17-digit");
}

TEST(RawTimingArtifacts, AllNamedTimingProducersHaveVersionedContracts) {
    const std::vector<std::string> required = {
        "bench_piccard", "bench_onehot_sqrt", "bench_sqrt_comparison",
        "bench_crossover", "bench_dynamic", "bench_threshold",
        "bench_review_comparison", "bench_fhe_ind", "bench_sj16_calibrate",
        "real_timing", "dynamic_refresh"};
    const auto contracts = PaperTimingProducerContracts();
    for (const auto& producer : required) {
        const auto it = std::find_if(
            contracts.begin(), contracts.end(), [&](const auto& contract) {
                return contract.producer_id == producer;
            });
        ASSERT_NE(it, contracts.end()) << producer;
        EXPECT_EQ(it->paper_measured_trials, 30u) << producer;
        EXPECT_EQ(it->toy_measured_trials, 1u) << producer;
        EXPECT_NE(it->timing_contract, "NOT_APPLICABLE") << producer;
    }
    EXPECT_EQ(TimingContractFor("bench_noise"), "NOT_APPLICABLE");
}

TEST(RawTimingArtifacts, RejectsMutatedRawSampleOrTrialIndex) {
    const auto original = SerializeRawTimingArtifactV1(ToyArtifact());
    std::string mutated_sample = original;
    const auto sample_pos = mutated_sample.find("\t3.25\n");
    ASSERT_NE(sample_pos, std::string::npos);
    mutated_sample.replace(sample_pos, std::string("\t3.25").size(),
                           "\t4.2500000000000000");
    EXPECT_THROW(ParseRawTimingArtifactV1(mutated_sample), std::invalid_argument);

    std::string mutated_trial = original;
    const auto trial_pos = mutated_trial.find("piccard.control\ttotal\tmeasured");
    ASSERT_NE(trial_pos, std::string::npos);
    const auto row_end = mutated_trial.find('\n', trial_pos);
    ASSERT_NE(row_end, std::string::npos);
    const auto row_start = mutated_trial.rfind('\n', trial_pos);
    ASSERT_NE(row_start, std::string::npos);
    const auto zero = mutated_trial.find("\t0\t34\t3.25", row_start);
    ASSERT_NE(zero, std::string::npos);
    mutated_trial.replace(zero, 2, "\t1");
    EXPECT_THROW(ParseRawTimingArtifactV1(mutated_trial), std::invalid_argument);
}

TEST(RawTimingArtifacts, RejectsAggregateInconsistentWithRawRows) {
    std::string serialized = SerializeRawTimingArtifactV1(ToyArtifact());
    const auto mean_pos = serialized.find("\t1\t3.25\tN/A\t3.25\tN/A\tN/A\t17-digit");
    ASSERT_NE(mean_pos, std::string::npos);
    serialized.replace(mean_pos, std::string("\t1\t3.25").size(),
                       "\t1\t4.25");
    EXPECT_THROW(ParseRawTimingArtifactV1(serialized), std::invalid_argument);
}

TEST(RawTimingArtifacts, RejectsWarmupMutationAndPhaseIndexMismatch) {
    auto artifact = ToyArtifact();
    artifact.samples.front().sample_kind = SampleKind::Measured;
    EXPECT_THROW(SerializeRawTimingArtifactV1(artifact), std::invalid_argument);

    artifact = ToyArtifact();
    artifact.samples.back().phase = "encrypt";
    EXPECT_THROW(SerializeRawTimingArtifactV1(artifact), std::invalid_argument);
}

TEST(RawTimingArtifacts, NoWarmupPolicyHasNoSyntheticWarmup) {
    RawTimingArtifact artifact = ToyArtifact();
    artifact.producer_id = "dynamic_refresh";
    artifact.cell_id = "dynamic.refresh";
    artifact.warmup_policy = WarmupPolicy::None;
    artifact.samples.erase(artifact.samples.begin());
    artifact.samples.front().producer_id = "dynamic_refresh";
    artifact.samples.front().cell_id = "dynamic.refresh";
    artifact.samples.front().sample_kind = SampleKind::Measured;
    artifact.samples.front().trial_index = 0;
    artifact.expected_measured = 1;
    const auto parsed = ParseRawTimingArtifactV1(
        SerializeRawTimingArtifactV1(artifact));
    EXPECT_EQ(parsed.samples.size(), 1u);
    EXPECT_EQ(parsed.samples.front().sample_kind, SampleKind::Measured);
}

}  // namespace
}  // namespace piccard::benchmark
