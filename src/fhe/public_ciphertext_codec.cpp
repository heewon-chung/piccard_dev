#include "fhe/public_ciphertext_codec.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <sstream>
#include <stdexcept>
#include <utility>

namespace piccard {

namespace {

std::vector<uint8_t> SerializeBinary(
    const PublicCiphertextCodec::Ciphertext& ciphertext) {
    std::ostringstream stream(std::ios::out | std::ios::binary);
    lbcrypto::Serial::Serialize(ciphertext, stream, lbcrypto::SerType::BINARY);
    const std::string serialized = stream.str();
    return {serialized.begin(), serialized.end()};
}

PublicCiphertextCodec::Ciphertext DeserializeBinary(
    std::istream& stream) {
    PublicCiphertextCodec::Ciphertext ciphertext;
    lbcrypto::Serial::Deserialize(ciphertext, stream, lbcrypto::SerType::BINARY);
    return ciphertext;
}

}  // namespace

PublicCiphertextCodec::PublicCiphertextCodec(
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> context,
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> public_key,
    std::string context_fingerprint_hex,
    std::string public_key_fingerprint_hex,
    std::string ciphertext_key_tag)
    : context_(std::move(context)),
      public_key_(std::move(public_key)),
      context_fingerprint_hex_(std::move(context_fingerprint_hex)),
      public_key_fingerprint_hex_(std::move(public_key_fingerprint_hex)),
      ciphertext_key_tag_(std::move(ciphertext_key_tag)) {}

const std::string& PublicCiphertextCodec::ContextFingerprintHex() const noexcept {
    return context_fingerprint_hex_;
}

const std::string& PublicCiphertextCodec::PublicKeyFingerprintHex() const noexcept {
    return public_key_fingerprint_hex_;
}

const std::string& PublicCiphertextCodec::CiphertextKeyTag() const noexcept {
    return ciphertext_key_tag_;
}

std::vector<uint8_t> PublicCiphertextCodec::Serialize(
    const Ciphertext& ciphertext) const {
    if (!ciphertext) {
        throw std::invalid_argument("ciphertext is null");
    }
    if (ciphertext->GetCryptoContext() != context_ ||
        ciphertext->GetKeyTag() != ciphertext_key_tag_) {
        throw std::invalid_argument(
            "ciphertext does not match the live context and public key");
    }

    // OpenFHE canonicalizes a DCRTPoly while loading it. Normalize before
    // emission so a freshly serialized ciphertext is accepted by Deserialize.
    const auto intermediate = SerializeBinary(ciphertext);
    const std::string intermediate_string(
        intermediate.begin(), intermediate.end());
    std::istringstream intermediate_stream(
        intermediate_string, std::ios::in | std::ios::binary);
    const auto decoded = DeserializeBinary(intermediate_stream);
    if (!decoded || decoded->GetCryptoContext() != context_ ||
        decoded->GetKeyTag() != ciphertext_key_tag_) {
        throw std::invalid_argument(
            "ciphertext does not match the live context and public key");
    }
    return SerializeBinary(decoded);
}

PublicCiphertextCodec::Ciphertext PublicCiphertextCodec::Deserialize(
    const std::vector<uint8_t>& bytes) const {
    if (bytes.empty()) {
        throw std::invalid_argument("ciphertext bytes are empty");
    }

    const std::string input(bytes.begin(), bytes.end());
    std::istringstream stream(input, std::ios::in | std::ios::binary);
    Ciphertext ciphertext;
    try {
        ciphertext = DeserializeBinary(stream);
    } catch (const std::exception&) {
        throw std::invalid_argument("ciphertext bytes are corrupt");
    }
    if (stream.peek() != std::char_traits<char>::eof()) {
        throw std::invalid_argument("ciphertext bytes contain trailing data");
    }
    if (!ciphertext || ciphertext->GetCryptoContext() != context_ ||
        ciphertext->GetKeyTag() != ciphertext_key_tag_) {
        throw std::invalid_argument(
            "decoded ciphertext does not match the live context and public key");
    }
    RequireCanonicalSerialization(bytes, Serialize(ciphertext));
    return ciphertext;
}

void PublicCiphertextCodec::RequireCanonicalSerialization(
    const std::vector<uint8_t>& supplied,
    const std::vector<uint8_t>& canonical) {
    if (supplied != canonical) {
        throw std::invalid_argument("ciphertext bytes are not canonical");
    }
}

}  // namespace piccard
