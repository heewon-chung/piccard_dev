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

PublicCiphertextCodec::Ciphertext DeserializeBinaryExact(
    const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        throw std::invalid_argument("ciphertext bytes are empty");
    }
    const std::string input(bytes.begin(), bytes.end());
    std::istringstream stream(input, std::ios::in | std::ios::binary);
    PublicCiphertextCodec::Ciphertext ciphertext;
    try {
        lbcrypto::Serial::Deserialize(
            ciphertext, stream, lbcrypto::SerType::BINARY);
    } catch (const std::exception&) {
        throw std::invalid_argument("ciphertext bytes are corrupt");
    }
    if (stream.peek() != std::char_traits<char>::eof()) {
        throw std::invalid_argument("ciphertext bytes contain trailing data");
    }
    return ciphertext;
}

void RequireLiveBinding(
    const PublicCiphertextCodec::Ciphertext& ciphertext,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& context,
    const std::string& ciphertext_key_tag,
    const char* error) {
    if (!ciphertext || ciphertext->GetCryptoContext() != context ||
        ciphertext->GetKeyTag() != ciphertext_key_tag) {
        throw std::invalid_argument(error);
    }
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
    RequireLiveBinding(ciphertext, context_, ciphertext_key_tag_,
                       "ciphertext does not match the live context and public key");
    const auto direct = SerializeBinary(ciphertext);
    const auto normalized = DeserializeBinaryExact(direct);
    RequireLiveBinding(normalized, context_, ciphertext_key_tag_,
                       "ciphertext does not match the live context and public key");
    const auto canonical = SerializeBinary(normalized);
    const auto fixed_point = DeserializeBinaryExact(canonical);
    RequireLiveBinding(fixed_point, context_, ciphertext_key_tag_,
                       "ciphertext does not match the live context and public key");
    if (SerializeBinary(fixed_point) != canonical) {
        throw std::logic_error(
            "one-pass ciphertext normalization is not a fixed point");
    }
    return canonical;
}

PublicCiphertextCodec::Ciphertext PublicCiphertextCodec::Deserialize(
    const std::vector<uint8_t>& bytes) const {
    const auto ciphertext = DeserializeBinaryExact(bytes);
    RequireLiveBinding(ciphertext, context_, ciphertext_key_tag_,
                       "decoded ciphertext does not match the live context and public key");
    RequireCanonicalSerialization(bytes, SerializeBinary(ciphertext));
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
