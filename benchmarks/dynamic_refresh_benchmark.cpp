#include "dynamic_refresh_benchmark.h"

#include "benchmark_utils.h"
#include "protocol/dynamic_ciphertext_store.h"
#include "protocol/dynamic_piccard.h"

#include <algorithm>
#include <cmath>
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
    if (refresh_updates == 0) {
        throw std::invalid_argument("refresh_updates must be positive");
    }

    DynamicResult row;
    row.label = "refresh_owner_a_0_to_1";
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
    row.refresh_owner_set_id = "owner-a";
    row.refresh_updates = refresh_updates;
    row.refresh_epoch_before = 0;
    row.refresh_epoch_after = 1;

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
    const uint64_t next_value = *std::max_element(set_a.begin(), set_a.end()) + 1;

    Timer timer;
    timer.Start();
    for (uint64_t offset = 0; offset < refresh_updates; ++offset) {
        const uint64_t value = next_value + offset;
        refreshed_set_a.push_back(value);
        bottom_a->Insert(value);
    }
    row.phase_refresh_update_ms = timer.ElapsedMs();

    timer.Start();
    const auto signature_a = bottom_a->GetSignature();
    row.phase_refresh_signature_ms = timer.ElapsedMs();

    timer.Start();
    const auto feature_a = engine.EncodeSignature(signature_a);
    row.phase_refresh_encode_ms = timer.ElapsedMs();

    timer.Start();
    const auto ciphertext_a = engine.EncryptFeature(feature_a);
    row.phase_refresh_encrypt_ms = timer.ElapsedMs();

    timer.Start();
    const auto upload = codec->Serialize(ciphertext_a);
    row.phase_refresh_serialize_ms = timer.ElapsedMs();

    const auto replacement = MakeVersionedCiphertext(
        "owner-a", 1, engine.GetParams(), *codec, upload);
    timer.Start();
    const auto outcome = store.TryReplace("owner-a", 0, replacement);
    row.phase_cloud_replace_ms = timer.ElapsedMs();
    if (outcome.status != ReplaceStatus::Applied || outcome.observed_epoch != 1) {
        throw std::runtime_error("refresh replacement was not applied at epoch 1");
    }

    row.refresh_status = ReplaceStatusName(outcome.status);
    row.refresh_upload_bytes = upload.size();
    row.refresh_ciphertexts_uploaded = 1;
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
    const auto stored_a = codec->Deserialize(stored.first.serialized_ciphertext);
    const auto stored_b = codec->Deserialize(stored.second.serialized_ciphertext);
    const JaccardResult decrypted = engine.Decrypt(engine.Evaluate(stored_a, stored_b));
    const int64_t local_inner_product = std::inner_product(
        feature_a.begin(), feature_a.end(), feature_b.begin(), int64_t{0});
    if (decrypted.match_count != local_inner_product) {
        throw std::runtime_error("stored refresh result differs from local inner product");
    }
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

}  // namespace piccard::benchmark
