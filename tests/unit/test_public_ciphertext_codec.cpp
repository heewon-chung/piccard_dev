#include <gtest/gtest.h>

#include "fhe/bfv_context.h"
#include "fhe/public_ciphertext_codec.h"
#include "util/params.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>
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

TEST(PublicCiphertextCodecTest, RejectsUninitializedMalformedAndWrongKey) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();

    BFVContext uninitialized(params);
    EXPECT_THROW(uninitialized.ExportPublicCiphertextCodec(), std::logic_error);

    BFVContext first(params);
    BFVContext second(params);
    first.Initialize();
    second.Initialize();
    const auto first_codec = first.ExportPublicCiphertextCodec();
    const auto second_codec = second.ExportPublicCiphertextCodec();
    EXPECT_EQ(first_codec->ContextFingerprintHex(),
              second_codec->ContextFingerprintHex());
    EXPECT_NE(first_codec->PublicKeyFingerprintHex(),
              second_codec->PublicKeyFingerprintHex());

    const auto bytes = first_codec->Serialize(first.Encrypt({1, 2, 3}));
    EXPECT_THROW(second_codec->Deserialize(bytes), std::invalid_argument);
    EXPECT_THROW(first_codec->Deserialize({}), std::invalid_argument);
    auto corrupt = bytes;
    corrupt[0] ^= 0xff;
    EXPECT_THROW(first_codec->Deserialize(corrupt), std::invalid_argument);
    auto trailing = bytes;
    trailing.push_back(0x00);
    EXPECT_THROW(first_codec->Deserialize(trailing), std::invalid_argument);
}

TEST(PublicCiphertextCodecTest, RejectsNonCanonicalByteRepresentation) {
    EXPECT_NO_THROW(PublicCiphertextCodecTestPeer::RequireCanonical(
        {0x01, 0x02}, {0x01, 0x02}));
    EXPECT_THROW(PublicCiphertextCodecTestPeer::RequireCanonical(
        {0x01, 0x02}, {0x01, 0x03}), std::invalid_argument);
}

}  // namespace
