// Work 5 Sub-phase 5.4 regression tests that need a live OpenFHE build:
//
//  - RealDatasetTimingToyEquality: the deployed full-FHE query pipeline
//    (Piccard/BFVContext, TOY security) reproduces exactly the same
//    bucket-match count and bias-corrected estimate as the plaintext
//    estimator path (benchmarks/real_accuracy_driver.cpp's inline
//    computation) for the same k/m/hash_seed and one real fixture pair.
//  - RealDatasetTimingResolver: STD192 never borrows a calibration row
//    measured for a different security level. This drives the
//    profile/calibration selection path directly with the resolved
//    std192-t40-primary benchmark profile against a calibration-row
//    fixture that lacks any valid STD192 row, and asserts the selection
//    fails closed *before* any BFV context is constructed -- no
//    Piccard/BFVContext object is created anywhere in that test.
//
// Kept in a separate translation unit/target from test_real_dataset_metrics
// (which stays OpenFHE-free) because this file links piccard_fhe.
#include "benchmark_profile.h"
#include "core/minhash.h"
#include "data/real_dataset.h"
#include "protocol/piccard.h"
#include "util/params.h"
#include "util/params_calibration.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

using piccard::CalibrationAccess;
using piccard::Circuit;
using piccard::MinHasher;
using piccard::Piccard;
using piccard::PiccardParams;
using piccard::PreThresholdCalibrationRequest;
using piccard::PreThresholdCalibrationRow;
using piccard::SecurityLevel;
using piccard::SelectPreThresholdCalibration;
using piccard::data::LoadRealDataset;
using piccard::data::RealDataset;
using piccard::benchmark::BenchmarkProfile;
using piccard::benchmark::ResolveBenchmarkProfile;

fs::path QuickFixtureManifest() {
    return fs::path(PICCARD_SOURCE_DIR) /
           "tests/fixtures/real_datasets/quick/dblp_acm_u65536" /
           "dataset.manifest.tsv";
}

TEST(RealDatasetTimingToyEquality, FullFheMatchesPlaintextEstimatorOnOneFixturePair) {
    const RealDataset dataset = LoadRealDataset(QuickFixtureManifest());
    ASSERT_FALSE(dataset.pairs.empty());
    const auto& pair = dataset.pairs.front();

    const auto find_record = [&](const std::string& id) {
        auto it = std::find_if(dataset.records.begin(), dataset.records.end(),
                               [&](const auto& r) { return r.id == id; });
        EXPECT_NE(it, dataset.records.end());
        return *it;
    };
    const auto record_a = find_record(pair.record_a);
    const auto record_b = find_record(pair.record_b);

    constexpr uint32_t kK = 16;
    constexpr uint32_t kM = 16;
    constexpr uint64_t kHashSeed = 424242;

    // Plaintext estimator path: byte-identical logic to
    // benchmarks/real_accuracy_driver.cpp's inline per-trial computation.
    const MinHasher hasher(kK, std::numeric_limits<uint64_t>::max(), kHashSeed);
    const std::vector<uint64_t> sig_a = hasher.ComputeSignature(record_a.bucketed_features);
    const std::vector<uint64_t> sig_b = hasher.ComputeSignature(record_b.bucketed_features);
    uint32_t bucket_matches = 0;
    for (uint32_t coordinate = 0; coordinate < kK; ++coordinate) {
        if (sig_a[coordinate] % kM == sig_b[coordinate] % kM) ++bucket_matches;
    }
    const double collision_probability = 1.0 / static_cast<double>(kM);
    double expected_estimate =
        (static_cast<double>(bucket_matches) / static_cast<double>(kK) -
        collision_probability) /
        (1.0 - collision_probability);
    expected_estimate = std::max(0.0, std::min(1.0, expected_estimate));

    // Full-FHE path: the deployed one-hot MinHash BFV query pipeline at TOY
    // security, same k/m/hash_seed, same bucketed sets.
    PiccardParams params;
    params.k = kK;
    params.m = kM;
    params.security = SecurityLevel::TOY;
    params.hash_seed = kHashSeed;
    params.Validate();

    Piccard engine(params);
    engine.KeyGen();
    const auto result = engine.Run(record_a.bucketed_features, record_b.bucketed_features);

    EXPECT_EQ(result.match_count, static_cast<int64_t>(bucket_matches));
    EXPECT_DOUBLE_EQ(result.jaccard_estimate, expected_estimate);
}

// A minimal but otherwise complete STD128 row for the (OneHot, "onehot-v1",
// requested-ring-dim, natural-depth=1) key shared by every mutation in this
// test -- deliberately the *wrong* security level, so it can never be a
// legitimate match for an STD192 request.
PreThresholdCalibrationRow WrongSecurityRow(const PreThresholdCalibrationRequest& key) {
    PreThresholdCalibrationRow row;
    row.key = key;
    row.key.security = SecurityLevel::STD128;
    row.natural_ring_dim = key.requested_ring_dim;
    row.ring_dim_calibrated = key.requested_ring_dim;
    row.provisioned_depth = key.natural_depth;
    row.scaling_mod_size = 40;
    row.num_limbs = 5;
    row.plaintext_mod = 65537;
    row.log_q = 200.0;
    row.log_delta = 183.9999779867;
    row.eval_noise_bits = 60;
    row.ct_bytes = 4096;
    row.transcript_stat_bits = 40;
    row.max_queries = UINT64_C(1) << 20;
    row.query_stat_bits = 60;
    row.coefficient_stat_bits = 73;
    row.flood_margin_bits = 8;
    row.flood_noise_bits = 141;
    return row;
}

TEST(RealDatasetTimingResolver,
    Std192NeverFallsBackToStd128BeforeContextConstruction) {
    // Resolve the exact benchmark profile bench_real_datasets --mode=timing
    // would use for --profile=std192-t40-primary.
    const BenchmarkProfile& profile = ResolveBenchmarkProfile("std192-t40-primary");
    ASSERT_EQ(profile.security, SecurityLevel::STD192);
    ASSERT_EQ(profile.transcript_stat_bits, 40u);

    // Derive-only parameter state (no flooding sized, no BFV context built
    // anywhere in this test -- CalibrationAccess::Derive is the same
    // flooding-free seam benchmarks/bench_noise.cpp uses to measure the
    // calibration table before it exists).
    PiccardParams profile_params;
    profile_params.k = 128;
    profile_params.m = 64;
    profile_params.security = profile.security;
    profile_params.transcript_stat_bits = profile.transcript_stat_bits;
    profile_params.max_queries = profile.max_queries;
    CalibrationAccess::Derive(profile_params);
    ASSERT_FALSE(profile_params.FloodingSized());

    PreThresholdCalibrationRequest request;
    request.profile_id = "primary40";  // canonical policy id for transcript=40
    request.circuit = Circuit::OneHot;
    request.shape_id = "onehot-v1";
    request.security = SecurityLevel::STD192;
    request.requested_ring_dim = profile_params.ring_dim;
    request.natural_depth = profile_params.natural_mult_depth;
    request.consumer_set_sha256 = std::string(64, 'a');
    request.openfhe_version = "test-openfhe";

    // The calibration fixture available to the resolver has a row for this
    // exact shape/ring/depth key, but measured at STD128 -- never a valid
    // substitute for an STD192 request.
    const std::vector<PreThresholdCalibrationRow> std128_only_candidates = {
        WrongSecurityRow(request),
    };

    EXPECT_THROW(
        (void)SelectPreThresholdCalibration(
            profile_params, request, std128_only_candidates),
        std::invalid_argument);

    // Also confirm the empty-fixture case fails closed identically.
    EXPECT_THROW(
        (void)SelectPreThresholdCalibration(profile_params, request, {}),
        std::invalid_argument);
}

}  // namespace
