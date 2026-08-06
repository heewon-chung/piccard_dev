#include <gtest/gtest.h>

#include "fhe/bfv_context.h"
#include "fhe/public_ciphertext_codec.h"
#include "util/params.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <sstream>
#include <vector>

namespace piccard {

class PublicCiphertextCodecTestPeer {
public:
    static void RequireCanonical(
        const std::vector<uint8_t>& supplied,
        const std::vector<uint8_t>& canonical) {
        PublicCiphertextCodec::RequireCanonicalSerialization(supplied, canonical);
    }
};

}  // namespace piccard

namespace {

using namespace piccard;

std::vector<uint8_t> DirectOpenFHEBinary(
    const PublicCiphertextCodec::Ciphertext& ciphertext) {
    std::ostringstream stream(std::ios::out | std::ios::binary);
    lbcrypto::Serial::Serialize(ciphertext, stream, lbcrypto::SerType::BINARY);
    const std::string bytes = stream.str();
    return {bytes.begin(), bytes.end()};
}

PublicCiphertextCodec::Ciphertext DirectOpenFHEBinaryDecode(
    const std::vector<uint8_t>& bytes) {
    const std::string input(bytes.begin(), bytes.end());
    std::istringstream stream(input, std::ios::in | std::ios::binary);
    PublicCiphertextCodec::Ciphertext ciphertext;
    lbcrypto::Serial::Deserialize(ciphertext, stream, lbcrypto::SerType::BINARY);
    EXPECT_EQ(stream.peek(), std::char_traits<char>::eof());
    return ciphertext;
}

std::vector<uint8_t> OnePassCanonicalOpenFHEBinary(
    const PublicCiphertextCodec::Ciphertext& ciphertext) {
    return DirectOpenFHEBinary(
        DirectOpenFHEBinaryDecode(DirectOpenFHEBinary(ciphertext)));
}

TEST(PublicCiphertextCodecTest, RoundTripsAndBindsContextPublicKeyAndTag) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();
    BFVContext context(params);
    context.Initialize();

    const auto codec = context.ExportPublicCiphertextCodec();
    ASSERT_TRUE(codec);
    EXPECT_EQ(codec->ContextFingerprintHex().size(), 64u);
    EXPECT_EQ(codec->PublicKeyFingerprintHex().size(), 64u);
    EXPECT_TRUE(std::all_of(codec->ContextFingerprintHex().begin(),
                            codec->ContextFingerprintHex().end(),
                            [](char c) {
                                return std::isdigit(static_cast<unsigned char>(c)) ||
                                       (c >= 'a' && c <= 'f');
                            }));
    EXPECT_FALSE(codec->CiphertextKeyTag().empty());

    const auto ciphertext = context.Encrypt({1, 0, 1, 0});
    const auto bytes = codec->Serialize(ciphertext);
    ASSERT_FALSE(bytes.empty());
    const auto decoded = codec->Deserialize(bytes);
    EXPECT_EQ(decoded->GetKeyTag(), codec->CiphertextKeyTag());
    EXPECT_EQ(codec->Serialize(decoded), bytes);
}

TEST(PublicCiphertextCodecTest, EmitsOnePassFixedPointOpenFHEWireBytes) {
    // Catches a production serializer that omits the required one-pass
    // S(D(S(c))) canonicalization or emits bytes that are not a fixed point.
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();
    BFVContext context(params);
    context.Initialize();

    const auto codec = context.ExportPublicCiphertextCodec();
    const auto ciphertext = context.Encrypt({1, 2, 3});
    const auto bytes = codec->Serialize(ciphertext);
    EXPECT_EQ(bytes, OnePassCanonicalOpenFHEBinary(ciphertext));
    EXPECT_EQ(DirectOpenFHEBinary(DirectOpenFHEBinaryDecode(bytes)), bytes);
}

TEST(PublicCiphertextCodecTest, RejectsNullCiphertext) {
    // Catches removal of Serialize's null-ciphertext guard.
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();
    BFVContext context(params);
    context.Initialize();

    const auto codec = context.ExportPublicCiphertextCodec();
    PublicCiphertextCodec::Ciphertext null_ciphertext;
    EXPECT_THROW(codec->Serialize(null_ciphertext), std::invalid_argument);
}

TEST(PublicCiphertextCodecTest, RejectsUninitializedEmptyCorruptAndTrailingBytes) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();

    BFVContext uninitialized(params);
    EXPECT_THROW(uninitialized.ExportPublicCiphertextCodec(), std::logic_error);

    BFVContext context(params);
    context.Initialize();
    const auto codec = context.ExportPublicCiphertextCodec();
    const auto bytes = codec->Serialize(context.Encrypt({1, 2, 3}));
    EXPECT_THROW(codec->Deserialize({}), std::invalid_argument);
    auto corrupt = bytes;
    corrupt[0] ^= 0xff;
    EXPECT_THROW(codec->Deserialize(corrupt), std::invalid_argument);
    auto trailing = bytes;
    trailing.push_back(0x00);
    EXPECT_THROW(codec->Deserialize(trailing), std::invalid_argument);
}

TEST(PublicCiphertextCodecTest, RejectsContextMismatch) {
    // Catches removal of Serialize's retained-live-context binding check.
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();
    PiccardParams other_params = params;
    other_params.mult_depth = 2;
    other_params.Validate();

    BFVContext first(params);
    BFVContext other(other_params);
    first.Initialize();
    other.Initialize();
    const auto codec = first.ExportPublicCiphertextCodec();
    EXPECT_THROW(codec->Serialize(other.Encrypt({1, 2, 3})),
                 std::invalid_argument);
}

TEST(PublicCiphertextCodecTest, RejectsKeyTagMismatch) {
    // Catches removal of Serialize's generated-public-key-tag binding check.
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();
    BFVContext context(params);
    context.Initialize();
    const auto codec = context.ExportPublicCiphertextCodec();
    const auto ciphertext = context.Encrypt({1, 2, 3});
    ASSERT_EQ(ciphertext->GetCryptoContext(), context.GetCryptoContext());
    ciphertext->SetKeyTag("deliberately-wrong-key-tag");
    ASSERT_NE(ciphertext->GetKeyTag(), codec->CiphertextKeyTag());
    EXPECT_THROW(codec->Serialize(ciphertext),
                 std::invalid_argument);
}

TEST(PublicCiphertextCodecTest, RejectsNonCanonicalByteRepresentation) {
    EXPECT_NO_THROW(PublicCiphertextCodecTestPeer::RequireCanonical(
        {0x01, 0x02}, {0x01, 0x02}));
    EXPECT_THROW(PublicCiphertextCodecTestPeer::RequireCanonical(
        {0x01, 0x02}, {0x01, 0x03}), std::invalid_argument);
}

}  // namespace
