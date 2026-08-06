#pragma once

#include "openfhe.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace piccard {

class BFVContext;
class PublicCiphertextCodecTestPeer;

class PublicCiphertextCodec final {
public:
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    const std::string& ContextFingerprintHex() const noexcept;
    const std::string& PublicKeyFingerprintHex() const noexcept;
    const std::string& CiphertextKeyTag() const noexcept;
    std::vector<uint8_t> Serialize(const Ciphertext& ciphertext) const;
    Ciphertext Deserialize(const std::vector<uint8_t>& bytes) const;

private:
    friend class BFVContext;
    friend class PublicCiphertextCodecTestPeer;

    static void RequireCanonicalSerialization(
        const std::vector<uint8_t>& supplied,
        const std::vector<uint8_t>& canonical);
    PublicCiphertextCodec(
        lbcrypto::CryptoContext<lbcrypto::DCRTPoly> context,
        lbcrypto::PublicKey<lbcrypto::DCRTPoly> public_key,
        std::string context_fingerprint_hex,
        std::string public_key_fingerprint_hex,
        std::string ciphertext_key_tag);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> context_;
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> public_key_;
    std::string context_fingerprint_hex_;
    std::string public_key_fingerprint_hex_;
    std::string ciphertext_key_tag_;
};

}  // namespace piccard
