#include <gtest/gtest.h>

#include "fhe/public_ciphertext_codec.h"
#include "protocol/dynamic_ciphertext_store.h"
#include "protocol/dynamic_piccard.h"

#include <cstdint>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace piccard;

VersionedCiphertext EncryptEnvelope(
    const DynamicPiccard& engine,
    const std::shared_ptr<const PublicCiphertextCodec>& codec,
    const std::string& owner_set_id,
    uint64_t epoch,
    const BottomStructure& bottom) {
    const auto ciphertext = engine.Encrypt(bottom);
    return MakeVersionedCiphertext(
        owner_set_id, epoch, engine.GetParams(), *codec,
        codec->Serialize(ciphertext));
}

int64_t LocalMatchCount(const DynamicPiccard& engine,
                        const BottomStructure& left,
                        const BottomStructure& right) {
    const auto a = engine.EncodeSignature(left.GetSignature());
    const auto b = engine.EncodeSignature(right.GetSignature());
    return std::inner_product(a.begin(), a.end(), b.begin(), int64_t{0});
}

int64_t StoredMatchCount(
    const DynamicPiccard& engine,
    const std::shared_ptr<const PublicCiphertextCodec>& codec,
    const CloudCiphertextPair& pair) {
    const auto first = codec->Deserialize(pair.first.serialized_ciphertext);
    const auto second = codec->Deserialize(pair.second.serialized_ciphertext);
    return engine.Decrypt(engine.Evaluate(first, second)).match_count;
}

TEST(DynamicRefreshE2E, RefreshesOnlyOneOwnerAndRejectsReplay) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.bottom_depth = 5;
    params.hash_seed = 7;
    params.security = SecurityLevel::TOY;
    params.Validate();

    DynamicPiccard engine(params);
    engine.KeyGen();
    const auto codec = engine.GetBFVContext().ExportPublicCiphertextCodec();

    std::vector<uint64_t> a_values;
    std::vector<uint64_t> b_values;
    for (uint64_t value = 0; value < 50; ++value) {
        a_values.push_back(value);
    }
    for (uint64_t value = 25; value < 75; ++value) {
        b_values.push_back(value);
    }
    auto bottom_a = engine.InitSet(a_values);
    const auto bottom_b = engine.InitSet(b_values);

    const auto old_a = EncryptEnvelope(
        engine, codec, "owner-a", 0, *bottom_a);
    const auto old_b = EncryptEnvelope(
        engine, codec, "owner-b", 0, *bottom_b);
    DynamicCiphertextStore store(codec, old_a, old_b);

    const int64_t old_local = LocalMatchCount(engine, *bottom_a, *bottom_b);
    EXPECT_EQ(StoredMatchCount(engine, codec, store.ReadPair()), old_local);

    const auto old_feature = engine.EncodeSignature(bottom_a->GetSignature());
    std::optional<uint64_t> chosen;
    for (uint64_t value = 1000; value <= 100000; ++value) {
        BottomStructure candidate = *bottom_a;
        engine.Insert(candidate, value);
        const auto candidate_feature =
            engine.EncodeSignature(candidate.GetSignature());
        const int64_t candidate_local =
            LocalMatchCount(engine, candidate, *bottom_b);
        if (candidate_feature != old_feature && candidate_local != old_local) {
            chosen = value;
            break;
        }
    }
    ASSERT_TRUE(chosen.has_value());

    engine.Insert(*bottom_a, *chosen);
    const int64_t new_local = LocalMatchCount(engine, *bottom_a, *bottom_b);
    EXPECT_NE(old_local, new_local);
    EXPECT_EQ(StoredMatchCount(engine, codec, store.ReadPair()), old_local);

    const auto replacement = EncryptEnvelope(
        engine, codec, "owner-a", 1, *bottom_a);
    const auto outcome = store.TryReplace("owner-a", 0, replacement);
    EXPECT_EQ(outcome.status, ReplaceStatus::Applied);
    EXPECT_NE(old_a.serialized_ciphertext, replacement.serialized_ciphertext);
    EXPECT_EQ(store.ReadPair().second, old_b);
    EXPECT_EQ(StoredMatchCount(engine, codec, store.ReadPair()), new_local);

    auto replay_package = old_a;
    replay_package.epoch = 1;
    const auto replay = store.TryReplace("owner-a", 0, replay_package);
    EXPECT_EQ(replay.status, ReplaceStatus::StaleEpoch);
    EXPECT_EQ(StoredMatchCount(engine, codec, store.ReadPair()), new_local);
}

}  // namespace
