#include "dynamic_refresh_benchmark.h"

#include "benchmark_utils.h"
#include "protocol/dynamic_ciphertext_store.h"
#include "protocol/dynamic_piccard.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <stdexcept>

namespace piccard::benchmark {
namespace {

double ExactJaccard(const std::vector<uint64_t>& a,
                    const std::vector<uint64_t>& b) {
    std::vector<uint64_t> a_unique = a;
    std::vector<uint64_t> b_unique = b;
    std::sort(a_unique.begin(), a_unique.end());
    std::sort(b_unique.begin(), b_unique.end());
    a_unique.erase(std::unique(a_unique.begin(), a_unique.end()), a_unique.end());
    b_unique.erase(std::unique(b_unique.begin(), b_unique.end()), b_unique.end());
    size_t intersection = 0;
    size_t a_index = 0;
    size_t b_index = 0;
    while (a_index < a_unique.size() && b_index < b_unique.size()) {
        if (a_unique[a_index] == b_unique[b_index]) {
            ++intersection;
            ++a_index;
            ++b_index;
        } else if (a_unique[a_index] < b_unique[b_index]) {
            ++a_index;
        } else {
            ++b_index;
        }
    }
    const size_t union_size = a_unique.size() + b_unique.size() - intersection;
    return union_size == 0 ? 1.0 : static_cast<double>(intersection) / union_size;
}

const char* ReplaceStatusName(ReplaceStatus status) {
    switch (status) {
        case ReplaceStatus::Applied: return "applied";
        case ReplaceStatus::StaleEpoch: return "stale-epoch";
        case ReplaceStatus::FutureEpoch: return "future-epoch";
    }
    throw std::logic_error("unknown refresh replace status");
}

}  // namespace

DynamicResult RunSingleOwnerRefresh(
    const DynamicPiccard& engine,
    const std::vector<uint64_t>& set_a,
    const std::vector<uint64_t>& set_b,
    uint32_t depth,
    uint64_t refresh_updates) {
    if (set_a.empty() || set_b.empty()) {
        throw std::invalid_argument("refresh requires nonempty input sets");
    }
    if (refresh_updates != 1 && refresh_updates != 2) {
        throw std::invalid_argument("refresh_updates must be exactly 1 or 2");
    }
    const uint64_t max_value = *std::max_element(set_a.begin(), set_a.end());
    if (max_value == std::numeric_limits<uint64_t>::max()) {
        throw std::invalid_argument("refresh input value cannot be UINT64_MAX");
    }
    if (refresh_updates > std::numeric_limits<uint64_t>::max() - max_value) {
        throw std::invalid_argument("refresh updates overflow input value space");
    }
    const size_t max_size = std::vector<uint64_t>().max_size();
    if (set_a.size() > max_size ||
        refresh_updates > static_cast<uint64_t>(max_size - set_a.size())) {
        throw std::invalid_argument("refresh updates exceed vector capacity");
    }
    const uint64_t next_value = max_value + 1;

    DynamicResult row;
    row.label = "refresh_owner_a_0_to_" + std::to_string(refresh_updates);
    row.dynamic_scenario = "refresh";
    row.k = engine.GetParams().k;
    row.m = engine.GetParams().m;
    row.set_size = set_a.size();
    row.ring_dim = engine.GetParams().ring_dim;
    row.depth = depth;
    row.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    row.sanitizer = MakeSanitizerMetadata(engine.GetParams());
    row.scaling_mod_size = engine.GetParams().scaling_mod_size;
    row.provenance = MakePiccardBenchmarkProvenance(engine.GetBFVContext());
    row.hash_seed = engine.GetParams().hash_seed;
    row.hash_root_seed = engine.GetParams().hash_seed;
    row.hash_randomness = "fixed";
    row.accuracy_trials = 0;
    row.trials = 1;
    row.updates_requested = refresh_updates;
    row.initial_epoch = 0;
    row.refresh_owner_set_id = "owner-a";
    row.refresh_updates = refresh_updates;
    row.refresh_epoch_before = 0;
    row.refresh_epoch_after = refresh_updates;

    const auto bottom_a = engine.InitSet(set_a);
    const auto bottom_b = engine.InitSet(set_b);
    const auto feature_a_initial = engine.EncodeSignature(bottom_a->GetSignature());
    const auto feature_b = engine.EncodeSignature(bottom_b->GetSignature());
    const auto ciphertext_a_initial = engine.EncryptFeature(feature_a_initial);
    const auto ciphertext_b = engine.EncryptFeature(feature_b);
    const auto codec = engine.GetBFVContext().ExportPublicCiphertextCodec();
    DynamicCiphertextStore store(
        codec,
        MakeVersionedCiphertext("owner-a", 0, engine.GetParams(), *codec,
                                codec->Serialize(ciphertext_a_initial)),
        MakeVersionedCiphertext("owner-b", 0, engine.GetParams(), *codec,
                                codec->Serialize(ciphertext_b)));
    const VersionedCiphertext saved_b = store.ReadPair().second;

    std::vector<uint64_t> refreshed_set_a = set_a;
    refreshed_set_a.reserve(set_a.size() + refresh_updates);
    double update_ms = 0.0;
    double signature_ms = 0.0;
    double encode_ms = 0.0;
    double encrypt_ms = 0.0;
    double serialize_ms = 0.0;
    double replace_ms = 0.0;
    size_t upload_bytes = 0;
    uint64_t applied_updates = 0;
    Timer timer;
    for (uint64_t offset = 0; offset < refresh_updates; ++offset) {
        timer.Start();
        const uint64_t value = next_value + offset;
        refreshed_set_a.push_back(value);
        bottom_a->Insert(value);
        update_ms += timer.ElapsedMs();

        timer.Start();
        const auto signature_a = bottom_a->GetSignature();
        signature_ms += timer.ElapsedMs();

        timer.Start();
        const auto feature_a = engine.EncodeSignature(signature_a);
        encode_ms += timer.ElapsedMs();

        timer.Start();
        const auto ciphertext_a = engine.EncryptFeature(feature_a);
        encrypt_ms += timer.ElapsedMs();

        timer.Start();
        const auto upload = codec->Serialize(ciphertext_a);
        serialize_ms += timer.ElapsedMs();

        const uint64_t expected_epoch = offset;
        const uint64_t next_epoch = offset + 1;
        const auto replacement = MakeVersionedCiphertext(
            "owner-a", next_epoch, engine.GetParams(), *codec, upload);
        timer.Start();
        const auto outcome = store.TryReplace("owner-a", expected_epoch, replacement);
        replace_ms += timer.ElapsedMs();
        if (outcome.status != ReplaceStatus::Applied ||
            outcome.observed_epoch != next_epoch) {
            throw std::runtime_error("refresh replacement was not applied at the expected epoch");
        }
        upload_bytes += upload.size();
        ++applied_updates;
    }
    row.phase_refresh_update_ms = update_ms;
    row.phase_refresh_signature_ms = signature_ms;
    row.phase_refresh_encode_ms = encode_ms;
    row.phase_refresh_encrypt_ms = encrypt_ms;
    row.phase_refresh_serialize_ms = serialize_ms;
    row.phase_cloud_replace_ms = replace_ms;
    row.refresh_status = ReplaceStatusName(ReplaceStatus::Applied);
    row.refresh_upload_bytes = upload_bytes;
    row.refresh_ciphertexts_uploaded = static_cast<uint32_t>(applied_updates);
    row.updates_applied = applied_updates;
    row.final_epoch = applied_updates;
    row.ciphertext_upload_count = applied_updates;
    row.refresh_context_fingerprint = codec->ContextFingerprintHex();
    row.refresh_public_key_fingerprint = codec->PublicKeyFingerprintHex();
    row.refresh_total_ms = *row.phase_refresh_update_ms +
                           *row.phase_refresh_signature_ms +
                           *row.phase_refresh_encode_ms +
                           *row.phase_refresh_encrypt_ms +
                           *row.phase_refresh_serialize_ms +
                           *row.phase_cloud_replace_ms;

    row.phase_insert_ms = *row.phase_refresh_update_ms;
    row.phase_insert_ms_median = row.phase_insert_ms;
    row.phase_insert_ms_sd = -1.0;
    row.phase_signature_ms = *row.phase_refresh_signature_ms;
    row.phase_signature_ms_median = row.phase_signature_ms;
    row.phase_signature_ms_sd = -1.0;
    row.phase_encode_ms = *row.phase_refresh_encode_ms;
    row.phase_encode_ms_median = row.phase_encode_ms;
    row.phase_encode_ms_sd = -1.0;
    row.phase_encrypt_ms = *row.phase_refresh_encrypt_ms;
    row.phase_encrypt_ms_median = row.phase_encrypt_ms;
    row.phase_encrypt_ms_sd = -1.0;
    row.phase_init_ms = row.phase_delete_ms = row.phase_compute_ms =
        row.phase_decrypt_ms = row.phase_flood_ms = 0.0;
    row.phase_init_ms_median = row.phase_delete_ms_median =
        row.phase_compute_ms_median = row.phase_decrypt_ms_median =
        row.phase_flood_ms_median = 0.0;
    row.phase_init_ms_sd = row.phase_delete_ms_sd =
        row.phase_compute_ms_sd = row.phase_decrypt_ms_sd =
        row.phase_flood_ms_sd = -1.0;
    row.total_ms = *row.refresh_total_ms;
    row.total_ms_median = row.total_ms;
    row.total_ms_sd = -1.0;
    row.ct_size_bytes = *row.refresh_upload_bytes;
    row.memory_bytes = MemoryTracker::GetPeakRSS();

    const CloudCiphertextPair stored = store.ReadPair();
    if (!(stored.second == saved_b)) {
        throw std::runtime_error("refresh changed owner-b envelope");
    }
    row.owner_b_unchanged = "true";
    if (stored.first.epoch != refresh_updates) {
        throw std::runtime_error("refresh final owner-a epoch does not match requested updates");
    }
    const auto stored_a = codec->Deserialize(stored.first.serialized_ciphertext);
    const auto stored_b = codec->Deserialize(stored.second.serialized_ciphertext);
    const JaccardResult decrypted = engine.Decrypt(engine.Evaluate(stored_a, stored_b));
    const auto feature_a = engine.EncodeSignature(bottom_a->GetSignature());
    const int64_t local_inner_product = std::inner_product(
        feature_a.begin(), feature_a.end(), feature_b.begin(), int64_t{0});
    if (decrypted.match_count != local_inner_product) {
        throw std::runtime_error("stored refresh result differs from local inner product");
    }
    row.local_inner_product = local_inner_product;
    row.decrypted_inner_product = decrypted.match_count;
    row.correctness_status = "PASS";
    row.jaccard_computed = decrypted.jaccard_estimate;
    row.jaccard_expected = ExactJaccard(refreshed_set_a, set_b);
    row.jaccard_error = std::abs(row.jaccard_computed - row.jaccard_expected);
    if (row.jaccard_expected > 0.0) {
        row.jaccard_rel_error = row.jaccard_error / row.jaccard_expected;
        row.rel_error_eligible_n = 1;
    } else {
        row.jaccard_rel_error = -1.0;
        row.rel_error_eligible_n = 0;
    }
    return row;
}

std::vector<DynamicResult> RunSingleOwnerRefreshTrials(
    const DynamicPiccard& engine,
    const std::vector<uint64_t>& set_a,
    const std::vector<uint64_t>& set_b,
    uint32_t depth,
    uint64_t refresh_updates,
    uint64_t measured_trials) {
    if (measured_trials == 0) {
        throw std::invalid_argument("measured_trials must be positive");
    }
    if (measured_trials >
        static_cast<uint64_t>(std::vector<DynamicResult>().max_size())) {
        throw std::invalid_argument("measured_trials exceeds vector capacity");
    }

    std::vector<DynamicResult> rows;
    rows.reserve(static_cast<size_t>(measured_trials));
    for (uint64_t trial = 0; trial < measured_trials; ++trial) {
        rows.push_back(RunSingleOwnerRefresh(
            engine, set_a, set_b, depth, refresh_updates));
    }
    return rows;
}

namespace {

double RequireRefreshPhase(const std::optional<double>& value,
                           const char* phase) {
    if (!value.has_value()) {
        throw std::invalid_argument(std::string("refresh row is missing phase: ") +
                                    phase);
    }
    if (!std::isfinite(*value) || *value < 0.0) {
        throw std::invalid_argument(std::string("refresh phase is invalid: ") +
                                    phase);
    }
    return *value;
}

void AppendRefreshPhaseSamples(std::vector<RawTimingSample>& samples,
                               const std::string& profile_id,
                               const std::string& cell_id,
                               uint64_t seed,
                               uint64_t trial_index,
                               const DynamicResult& row,
                               const char* phase,
                               const std::optional<double>& value) {
    samples.push_back({"dynamic_refresh", profile_id, cell_id, phase,
                       SampleKind::Measured, trial_index, seed,
                       RequireRefreshPhase(value, phase)});
}

}  // namespace

RawTimingArtifact MakeDynamicRefreshTimingArtifact(
    const std::string& profile_id,
    const std::string& cell_id,
    uint64_t seed,
    const std::vector<DynamicResult>& measured_trials) {
    const uint64_t expected_measured = ExpectedTimingTrials(profile_id);
    if (measured_trials.size() != expected_measured) {
        throw std::invalid_argument(
            "refresh raw timing trial count disagrees with profile");
    }

    RawTimingArtifact artifact;
    artifact.producer_id = "dynamic_refresh";
    artifact.profile_id = profile_id;
    artifact.cell_id = cell_id;
    artifact.warmup_policy = WarmupPolicy::None;
    if (artifact.warmup_policy != ExpectedWarmupPolicy(artifact.producer_id)) {
        throw std::logic_error("dynamic_refresh raw warmup policy drift");
    }
    artifact.expected_measured = expected_measured;
    artifact.samples.reserve(measured_trials.size() * 7);
    for (uint64_t trial = 0; trial < measured_trials.size(); ++trial) {
        const auto& row = measured_trials[static_cast<size_t>(trial)];
        const uint64_t trial_seed =
            TrialSeed(seed, static_cast<size_t>(trial), 0.5);
        AppendRefreshPhaseSamples(artifact.samples, profile_id, cell_id, trial_seed,
                                  trial, row, "refresh_update",
                                  row.phase_refresh_update_ms);
        AppendRefreshPhaseSamples(artifact.samples, profile_id, cell_id, trial_seed,
                                  trial, row, "refresh_signature",
                                  row.phase_refresh_signature_ms);
        AppendRefreshPhaseSamples(artifact.samples, profile_id, cell_id, trial_seed,
                                  trial, row, "refresh_encode",
                                  row.phase_refresh_encode_ms);
        AppendRefreshPhaseSamples(artifact.samples, profile_id, cell_id, trial_seed,
                                  trial, row, "refresh_encrypt",
                                  row.phase_refresh_encrypt_ms);
        AppendRefreshPhaseSamples(artifact.samples, profile_id, cell_id, trial_seed,
                                  trial, row, "refresh_serialize",
                                  row.phase_refresh_serialize_ms);
        AppendRefreshPhaseSamples(artifact.samples, profile_id, cell_id, trial_seed,
                                  trial, row, "cloud_replace",
                                  row.phase_cloud_replace_ms);
        AppendRefreshPhaseSamples(artifact.samples, profile_id, cell_id, trial_seed,
                                  trial, row, "total",
                                  row.refresh_total_ms);
    }
    ValidateRawTimingArtifact(artifact);
    return artifact;
}

}  // namespace piccard::benchmark
