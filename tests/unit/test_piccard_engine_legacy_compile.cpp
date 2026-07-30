#include <gtest/gtest.h>

#include "protocol/piccard_engine.h"

namespace piccard {
namespace {

TEST(PiccardEngineLegacyCompile, ConstructorRetainsPublicHashSeed) {
    PiccardParams params;
    params.hash_seed = 20260729;

    const PiccardEngine engine(params);

    EXPECT_EQ(engine.GetParams().hash_seed, 20260729ULL);
}

} // namespace
} // namespace piccard
