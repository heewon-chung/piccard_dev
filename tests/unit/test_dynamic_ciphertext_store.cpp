#include <gtest/gtest.h>

#include "fhe/bfv_context.h"
#include "fhe/public_ciphertext_codec.h"
#include "protocol/dynamic_ciphertext_store.h"
#include "util/params.h"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

using namespace piccard;

class DynamicCiphertextStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 16;
        params.m = 16;
        params.security = SecurityLevel::TOY;
        params.Validate();
        context = std::make_unique<BFVContext>(params);
        context->Initialize();
        codec = context->ExportPublicCiphertextCodec();
    }

    VersionedCiphertext Envelope(
        const std::string& owner_set_id,
        uint64_t epoch,
        int64_t marker) {
        const auto ciphertext = context->Encrypt({marker, 0, 1, 0});
        return MakeVersionedCiphertext(
            owner_set_id, epoch, params, *codec,
            codec->Serialize(ciphertext));
    }

    VersionedCiphertext A(uint64_t epoch) {
        return Envelope("owner-a", epoch, 1);
    }

    VersionedCiphertext B(uint64_t epoch) {
        return Envelope("owner-b", epoch, 2);
    }

    PiccardParams params;
    std::unique_ptr<BFVContext> context;
    std::shared_ptr<const PublicCiphertextCodec> codec;
};

TEST_F(DynamicCiphertextStoreTest,
       AppliesOneOwnerAndDistinguishesReplayFromFuture) {
    DynamicCiphertextStore store(codec, A(0), B(0));
    const VersionedCiphertext peer_before = store.ReadPair().second;

    const auto applied = store.TryReplace("owner-a", 0, A(1));
    EXPECT_EQ(applied.status, ReplaceStatus::Applied);
    EXPECT_EQ(applied.observed_epoch, 1u);
    EXPECT_EQ(store.ReadPair().second, peer_before);

    const auto stale = store.TryReplace("owner-a", 0, A(1));
    EXPECT_EQ(stale.status, ReplaceStatus::StaleEpoch);
    EXPECT_EQ(stale.observed_epoch, 1u);

    const auto future = store.TryReplace("owner-a", 2, A(3));
    EXPECT_EQ(future.status, ReplaceStatus::FutureEpoch);
    EXPECT_EQ(future.observed_epoch, 1u);
    EXPECT_EQ(store.ReadPair().second, peer_before);
}

TEST_F(DynamicCiphertextStoreTest,
       RejectsOwnerCrsCryptoAndMalformedPackagesAtomically) {
    DynamicCiphertextStore store(codec, A(0), B(0));
    const CloudCiphertextPair before = store.ReadPair();

    auto wrong_owner = A(1);
    wrong_owner.owner_set_id = "owner-c";
    EXPECT_THROW(store.TryReplace("owner-a", 0, wrong_owner),
                 std::invalid_argument);

    auto wrong_crs = A(1);
    ++wrong_crs.hash_seed;
    EXPECT_THROW(store.TryReplace("owner-a", 0, wrong_crs),
                 std::invalid_argument);

    auto wrong_crypto = A(1);
    wrong_crypto.public_key_fingerprint.assign(64, '0');
    EXPECT_THROW(store.TryReplace("owner-a", 0, wrong_crypto),
                 std::invalid_argument);

    auto corrupt = A(1);
    corrupt.serialized_ciphertext = {0x01, 0x02, 0x03};
    EXPECT_THROW(store.TryReplace("owner-a", 0, corrupt),
                 std::invalid_argument);

    EXPECT_EQ(store.ReadPair().first, before.first);
    EXPECT_EQ(store.ReadPair().second, before.second);
}

TEST_F(DynamicCiphertextStoreTest, RejectsSkippedDestinationEpoch) {
    DynamicCiphertextStore store(codec, A(0), B(0));
    EXPECT_THROW(store.TryReplace("owner-a", 0, A(2)),
                 std::invalid_argument);
    EXPECT_EQ(store.ReadPair().first.epoch, 0u);
}

TEST_F(DynamicCiphertextStoreTest, RejectsConstructorWithIdenticalOwners) {
    EXPECT_THROW(DynamicCiphertextStore store(codec, A(0), A(0)),
                 std::invalid_argument);
}

TEST_F(DynamicCiphertextStoreTest, RejectsConstructorWithMismatchedHashSeed) {
    auto other = B(0);
    ++other.hash_seed;
    EXPECT_THROW(DynamicCiphertextStore store(codec, A(0), std::move(other)),
                 std::invalid_argument);
}

}  // namespace
