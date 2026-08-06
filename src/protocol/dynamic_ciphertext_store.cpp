#include "protocol/dynamic_ciphertext_store.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace piccard {

namespace {

constexpr char kEstimatorModel[] = "sha256-random-ranking-poc-v1";
constexpr char kEncodingModel[] = "onehot-mod-m-v1";

void ValidatePayload(const PublicCiphertextCodec& codec,
                     const VersionedCiphertext& envelope) {
    if (envelope.owner_set_id.empty()) {
        throw std::invalid_argument("owner_set_id is empty");
    }
    if (envelope.estimator_model != kEstimatorModel ||
        envelope.encoding_model != kEncodingModel) {
        throw std::invalid_argument(
            "dynamic estimator or encoding model mismatch");
    }
    if (envelope.context_fingerprint != codec.ContextFingerprintHex() ||
        envelope.public_key_fingerprint != codec.PublicKeyFingerprintHex() ||
        envelope.ciphertext_key_tag != codec.CiphertextKeyTag()) {
        throw std::invalid_argument("dynamic ciphertext crypto binding mismatch");
    }
    static_cast<void>(codec.Deserialize(envelope.serialized_ciphertext));
}

bool SameImmutableBinding(const VersionedCiphertext& left,
                          const VersionedCiphertext& right) {
    return left.owner_set_id == right.owner_set_id &&
           left.hash_seed == right.hash_seed &&
           left.estimator_model == right.estimator_model &&
           left.k == right.k && left.m == right.m &&
           left.hash_range == right.hash_range &&
           left.encoding_model == right.encoding_model &&
           left.context_fingerprint == right.context_fingerprint &&
           left.public_key_fingerprint == right.public_key_fingerprint &&
           left.ciphertext_key_tag == right.ciphertext_key_tag;
}

bool SameSharedBinding(const VersionedCiphertext& left,
                       const VersionedCiphertext& right) {
    return left.hash_seed == right.hash_seed &&
           left.estimator_model == right.estimator_model &&
           left.k == right.k && left.m == right.m &&
           left.hash_range == right.hash_range &&
           left.encoding_model == right.encoding_model &&
           left.context_fingerprint == right.context_fingerprint &&
           left.public_key_fingerprint == right.public_key_fingerprint &&
           left.ciphertext_key_tag == right.ciphertext_key_tag;
}

}  // namespace

bool operator==(const VersionedCiphertext& left,
                const VersionedCiphertext& right) {
    return left.owner_set_id == right.owner_set_id &&
           left.epoch == right.epoch &&
           left.hash_seed == right.hash_seed &&
           left.estimator_model == right.estimator_model &&
           left.k == right.k && left.m == right.m &&
           left.hash_range == right.hash_range &&
           left.encoding_model == right.encoding_model &&
           left.context_fingerprint == right.context_fingerprint &&
           left.public_key_fingerprint == right.public_key_fingerprint &&
           left.ciphertext_key_tag == right.ciphertext_key_tag &&
           left.serialized_ciphertext == right.serialized_ciphertext;
}

VersionedCiphertext MakeVersionedCiphertext(
    std::string owner_set_id,
    uint64_t epoch,
    const PiccardParams& params,
    const PublicCiphertextCodec& codec,
    std::vector<uint8_t> serialized_ciphertext) {
    return {std::move(owner_set_id),
            epoch,
            params.hash_seed,
            kEstimatorModel,
            params.k,
            params.m,
            params.hash_range,
            kEncodingModel,
            codec.ContextFingerprintHex(),
            codec.PublicKeyFingerprintHex(),
            codec.CiphertextKeyTag(),
            std::move(serialized_ciphertext)};
}

DynamicCiphertextStore::DynamicCiphertextStore(
    std::shared_ptr<const PublicCiphertextCodec> codec,
    VersionedCiphertext first,
    VersionedCiphertext second)
    : codec_(std::move(codec)), first_(std::move(first)), second_(std::move(second)) {
    if (!codec_) {
        throw std::invalid_argument("ciphertext codec is null");
    }
    if (first_.owner_set_id.empty() || second_.owner_set_id.empty() ||
        first_.owner_set_id == second_.owner_set_id) {
        throw std::invalid_argument("owner_set_ids must be distinct and nonempty");
    }
    if (first_.epoch != 0 || second_.epoch != 0) {
        throw std::invalid_argument("initial ciphertext epochs must be zero");
    }
    ValidatePayload(*codec_, first_);
    ValidatePayload(*codec_, second_);
    if (!SameSharedBinding(first_, second_)) {
        throw std::invalid_argument("initial ciphertext bindings do not match");
    }
}

ReplaceOutcome DynamicCiphertextStore::TryReplace(
    std::string_view owner_set_id,
    uint64_t expected_epoch,
    VersionedCiphertext replacement) {
    if (expected_epoch == std::numeric_limits<uint64_t>::max()) {
        throw std::invalid_argument("expected epoch cannot be UINT64_MAX");
    }
    if (replacement.epoch != expected_epoch + 1) {
        throw std::invalid_argument("replacement epoch is not the next epoch");
    }
    if (owner_set_id.empty() || replacement.owner_set_id.empty() ||
        replacement.owner_set_id != owner_set_id) {
        throw std::invalid_argument("replacement owner_set_id does not match");
    }
    ValidatePayload(*codec_, replacement);

    std::lock_guard<std::mutex> lock(mutex_);
    VersionedCiphertext* current = nullptr;
    if (owner_set_id == first_.owner_set_id) {
        current = &first_;
    } else if (owner_set_id == second_.owner_set_id) {
        current = &second_;
    } else {
        throw std::invalid_argument("owner_set_id is unknown");
    }
    if (!SameImmutableBinding(*current, replacement)) {
        throw std::invalid_argument("replacement immutable binding mismatch");
    }
    if (expected_epoch < current->epoch) {
        return {ReplaceStatus::StaleEpoch, current->epoch};
    }
    if (expected_epoch > current->epoch) {
        return {ReplaceStatus::FutureEpoch, current->epoch};
    }
    *current = std::move(replacement);
    return {ReplaceStatus::Applied, current->epoch};
}

CloudCiphertextPair DynamicCiphertextStore::ReadPair() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {first_, second_};
}

}  // namespace piccard
