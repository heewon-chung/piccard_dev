#pragma once

#include "fhe/public_ciphertext_codec.h"
#include "util/params.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace piccard {

struct VersionedCiphertext {
    std::string owner_set_id;
    uint64_t epoch = 0;
    uint64_t hash_seed = 0;
    std::string estimator_model;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t hash_range = 0;
    std::string encoding_model;
    std::string context_fingerprint;
    std::string public_key_fingerprint;
    std::string ciphertext_key_tag;
    std::vector<uint8_t> serialized_ciphertext;
};

bool operator==(const VersionedCiphertext& left,
                const VersionedCiphertext& right);

VersionedCiphertext MakeVersionedCiphertext(
    std::string owner_set_id,
    uint64_t epoch,
    const PiccardParams& params,
    const PublicCiphertextCodec& codec,
    std::vector<uint8_t> serialized_ciphertext);

enum class ReplaceStatus { Applied, StaleEpoch, FutureEpoch };

struct ReplaceOutcome {
    ReplaceStatus status;
    uint64_t observed_epoch;
};

struct CloudCiphertextPair {
    VersionedCiphertext first;
    VersionedCiphertext second;
};

class DynamicCiphertextStore final {
public:
    DynamicCiphertextStore(
        std::shared_ptr<const PublicCiphertextCodec> codec,
        VersionedCiphertext first,
        VersionedCiphertext second);

    ReplaceOutcome TryReplace(
        std::string_view owner_set_id,
        uint64_t expected_epoch,
        VersionedCiphertext replacement);

    CloudCiphertextPair ReadPair() const;

private:
    std::shared_ptr<const PublicCiphertextCodec> codec_;
    VersionedCiphertext first_;
    VersionedCiphertext second_;
    mutable std::mutex mutex_;
};

}  // namespace piccard
