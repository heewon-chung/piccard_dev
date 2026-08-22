#include <gtest/gtest.h>
#include "util/params.h"
#include "util/params_calibration.h"

#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace piccard;

namespace {

CalibrationCandidate GrownOneHotCandidate(double log2_q_over_t = 200.0) {
    CalibrationCandidate candidate{};
    candidate.circuit = Circuit::OneHot;
    candidate.security = SecurityLevel::STD128;
    candidate.requested_ring_dim = 8192;
    candidate.natural_ring_dim = 8192;
    candidate.calibrated_ring_dim = 16384;
    candidate.natural_mult_depth = 1;
    candidate.selected_mult_depth = 3;
    candidate.scaling_mod_size = 40;
    candidate.eval_noise_bits = 60;
    candidate.log2_q_over_t = log2_q_over_t;
    return candidate;
}

PreThresholdCalibrationRequest PrimaryOneHotRequest() {
    return PreThresholdCalibrationRequest{
        "primary40",
        Circuit::OneHot,
        "onehot-v1",
        SecurityLevel::STD128,
        8192,
        1,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "OpenFHE-test",
    };
}

PreThresholdCalibrationRow PrimaryOneHotRow(
    uint32_t calibrated_ring_dim = 8192) {
    const uint32_t coefficient_bits =
        calibrated_ring_dim == 8192 ? 73u : 74u;
    return PreThresholdCalibrationRow{
        PrimaryOneHotRequest(),
        8192,
        calibrated_ring_dim,
        3,
        40,
        5,
        65537,
        200.0,
        183.9999779867,
        60,
        4096,
        40,
        UINT64_C(1) << 20,
        60,
        coefficient_bits,
        8,
        60u + coefficient_bits + 8u,
    };
}

PiccardParams DerivedDefaultOneHotProfile() {
    PiccardParams params;
    CalibrationAccess::Derive(params);
    return params;
}

PiccardParams SelectedGrownOneHotProfile() {
    return SelectSanitizerCandidate(
        DerivedDefaultOneHotProfile(),
        GrownOneHotCandidate());
}

PiccardParams SelectedThresholdCompatibilityProfile() {
    PiccardParams params;
    params.k = 64;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.threshold_mode = true;
    params.threshold_tau = 32;
    params.Validate();
    return params;
}

std::string InvalidArgumentMessage(const std::function<void()>& action) {
    try {
        action();
    } catch (const std::invalid_argument& error) {
        return error.what();
    }
    return {};
}

static_assert(
    std::is_same_v<
        decltype(std::declval<const PiccardParams&>().RequestedRingDim()),
        uint32_t>);
static_assert(
    std::is_same_v<
        decltype(std::declval<const PiccardParams&>().SelectedCalibratedRingDim()),
        uint32_t>);
static_assert(
    std::is_same_v<
        decltype(std::declval<const PiccardParams&>().QueryStatBits()),
        uint32_t>);
static_assert(
    std::is_same_v<
        decltype(std::declval<const PiccardParams&>().CoefficientStatBits()),
        uint32_t>);
static_assert(
    std::is_same_v<
        decltype(std::declval<const PiccardParams&>().FloodNoiseBits()),
        uint32_t>);
static_assert(
    !std::is_reference_v<
        decltype(std::declval<const PiccardParams&>().RequestedRingDim())>);
static_assert(
    !std::is_reference_v<
        decltype(std::declval<const PiccardParams&>().SelectedCalibratedRingDim())>);
static_assert(
    !std::is_reference_v<
        decltype(std::declval<const PiccardParams&>().QueryStatBits())>);
static_assert(
    !std::is_reference_v<
        decltype(std::declval<const PiccardParams&>().CoefficientStatBits())>);

}  // namespace

TEST(NextPowerOf2, EdgeCases) {
    struct Case { uint32_t input; uint32_t expected; };
    Case cases[] = {
        {0, 1}, {1, 1}, {2, 2}, {3, 4}, {4, 4}, {5, 8},
        {1023, 1024}, {1024, 1024}, {1025, 2048}, {4096, 4096}
    };
    for (auto& c : cases) {
        uint32_t result = NextPowerOf2(c.input);
        RecordProperty("input_" + std::to_string(c.input),
                       static_cast<int>(result));
        EXPECT_EQ(result, c.expected);
    }
}

TEST(IsPrime, Basic) {
    struct Case { uint64_t input; bool expected; };
    Case cases[] = {
        {0, false}, {1, false}, {2, true}, {3, true}, {4, false},
        {5, true}, {97, true}, {100, false}, {7919, true}
    };
    for (auto& c : cases) {
        bool result = IsPrime(c.input);
        RecordProperty("IsPrime_" + std::to_string(c.input),
                       result ? "true" : "false");
        EXPECT_EQ(result, c.expected);
    }
}

TEST(FindPlaintextModulus, CongruenceAndPrimality) {
    uint32_t N = 4096;
    uint32_t two_n = 2 * N;
    uint32_t min_val = 128;
    RecordProperty("input_N", static_cast<int>(N));
    RecordProperty("input_min_val", static_cast<int>(min_val));

    uint64_t p = FindPlaintextModulus(min_val, two_n);
    RecordProperty("output_p", std::to_string(p));
    RecordProperty("output_p_mod_2N", std::to_string(p % two_n));
    RecordProperty("output_is_prime", IsPrime(p) ? "true" : "false");

    EXPECT_GT(p, min_val);
    EXPECT_EQ(p % two_n, 1u);
    EXPECT_TRUE(IsPrime(p));
}

TEST(FindPlaintextModulus, SmallValues) {
    RecordProperty("input_min_val", 10);
    RecordProperty("input_modulus", 16);

    uint64_t p = FindPlaintextModulus(10, 16);
    RecordProperty("output_p", std::to_string(p));
    RecordProperty("output_p_mod_16", std::to_string(p % 16));

    EXPECT_GT(p, 10u);
    EXPECT_EQ(p % 16, 1u);
    EXPECT_TRUE(IsPrime(p));
}

TEST(PiccardParams, DefaultValidation) {
    PiccardParams params;
    RecordProperty("input_k", static_cast<int>(params.k));
    RecordProperty("input_m", static_cast<int>(params.m));
    RecordProperty("input_security", "STD128");

    params.Validate();

    RecordProperty("output_feature_dim", static_cast<int>(params.feature_dim));
    RecordProperty("output_ring_dim", static_cast<int>(params.ring_dim));
    RecordProperty("output_plaintext_mod", std::to_string(params.plaintext_mod));
    RecordProperty("output_mult_depth", static_cast<int>(params.mult_depth));

    EXPECT_EQ(params.feature_dim, 128u * 64u);
    EXPECT_GE(params.ring_dim, params.feature_dim);
    EXPECT_EQ(params.ring_dim & (params.ring_dim - 1), 0u);
    EXPECT_GE(params.ring_dim, MinRingDimForSecurity(params.security));
    EXPECT_GT(params.plaintext_mod, params.k);
    EXPECT_EQ(params.plaintext_mod % (2 * params.ring_dim), 1u);
    EXPECT_TRUE(IsPrime(params.plaintext_mod));
    // The one-hot circuit needs one multiplication. mult_depth is provisioned
    // at or above that to leave room for noise flooding (R2-W6), so the
    // circuit's own requirement is natural_mult_depth.
    EXPECT_EQ(params.natural_mult_depth, 1u);
    EXPECT_GE(params.mult_depth, params.natural_mult_depth);
}

TEST(PiccardParams, SanitizerDefaultsResolveToTranscriptAndQueryCap) {
    PiccardParams params;

    EXPECT_EQ(params.transcript_stat_bits, 40u);
    EXPECT_EQ(params.max_queries, UINT64_C(1) << 20);

    params.Validate();

    EXPECT_EQ(params.RequestedRingDim(), 8192u);
    EXPECT_EQ(params.SelectedCalibratedRingDim(), 8192u);
    EXPECT_EQ(params.QueryStatBits(), 60u);
    EXPECT_EQ(params.CoefficientStatBits(), 73u);
}

TEST(PiccardParams, FloodNoiseUsesEvalCoefficientAndMarginExactlyOnce) {
    PiccardParams params;
    params.Validate();

    EXPECT_EQ(
        params.FloodNoiseBits(),
        params.eval_noise_bits + 73u + params.flood_margin_bits);
}

TEST(SanitizerCandidate, RealizedRingDimensionDrivesCoefficientBits) {
    const PiccardParams profile = DerivedDefaultOneHotProfile();
    const PiccardParams selected =
        SelectSanitizerCandidate(profile, GrownOneHotCandidate());

    RecordProperty("requested_ring_dim", selected.RequestedRingDim());
    RecordProperty(
        "selected_calibrated_ring_dim",
        selected.SelectedCalibratedRingDim());
    RecordProperty("query_stat_bits", selected.QueryStatBits());
    RecordProperty(
        "coefficient_stat_bits",
        selected.CoefficientStatBits());
    RecordProperty("flood_noise_bits", selected.FloodNoiseBits());
    EXPECT_EQ(selected.RequestedRingDim(), 8192u);
    EXPECT_EQ(selected.SelectedCalibratedRingDim(), 16384u);
    EXPECT_EQ(selected.QueryStatBits(), 60u);
    EXPECT_EQ(selected.CoefficientStatBits(), 74u);
    EXPECT_EQ(selected.FloodNoiseBits(), 142u);
}

TEST(SanitizerCandidate, RejectsCellThatOnlyFitsOldCoefficientFormula) {
    const PiccardParams profile = DerivedDefaultOneHotProfile();
    const CalibrationCandidate old_formula_only = GrownOneHotCandidate(120.0);

    // Hand-check the fixture's boundary: the old coefficient-only target 40
    // would require 60 + 40 + 8 + 2 = 110, while the transcript-aware target
    // uses coefficient bits 74 and requires 144.
    ASSERT_LE(110.0, old_formula_only.log2_q_over_t);
    ASSERT_GT(144.0, old_formula_only.log2_q_over_t);

    const std::string message = InvalidArgumentMessage([&] {
        (void)SelectSanitizerCandidate(profile, old_formula_only);
    });

    ASSERT_FALSE(message.empty());
    RecordProperty("infeasible_diagnostic", message);
    EXPECT_NE(message.find("infeasible sanitizer calibration"), std::string::npos);
    EXPECT_NE(message.find("required capacity 144"), std::string::npos);
    EXPECT_NE(message.find("available log2(q/t) 120"), std::string::npos);
}

TEST(PiccardParams, MissingCalibrationIsAHardDistinctFailure) {
    PiccardParams params;
    params.security = SecurityLevel::STD192;

    const std::string message =
        InvalidArgumentMessage([&] { params.Validate(); });

    ASSERT_FALSE(message.empty());
    RecordProperty("missing_diagnostic", message);
    EXPECT_NE(message.find("missing sanitizer calibration"), std::string::npos);
    EXPECT_EQ(message.find("infeasible sanitizer calibration"), std::string::npos);
    EXPECT_NE(message.find("one-hot / STD192"), std::string::npos);
}

TEST(PiccardParams, DeriveOnlyCalibrationAccessLeavesFloodingUnsized) {
    PiccardParams one_hot;
    CalibrationAccess::Derive(one_hot);
    EXPECT_FALSE(one_hot.FloodingSized());
    EXPECT_THROW(one_hot.FloodNoiseBits(), std::logic_error);

    PiccardParams sqrt;
    CalibrationAccess::DeriveSqrt(sqrt);
    EXPECT_FALSE(sqrt.FloodingSized());
    EXPECT_THROW(sqrt.FloodNoiseBits(), std::logic_error);
}

TEST(SanitizerCandidate, ExactTranscriptTargetsRemainDistinct) {
    const CalibrationCandidate candidate = GrownOneHotCandidate(1000.0);

    PiccardParams forty = DerivedDefaultOneHotProfile();
    forty.transcript_stat_bits = 40;
    const PiccardParams selected_forty =
        SelectSanitizerCandidate(forty, candidate);

    PiccardParams sixty_four = DerivedDefaultOneHotProfile();
    sixty_four.transcript_stat_bits = 64;
    const PiccardParams selected_sixty_four =
        SelectSanitizerCandidate(sixty_four, candidate);

    PiccardParams one_twenty_eight = DerivedDefaultOneHotProfile();
    one_twenty_eight.transcript_stat_bits = 128;
    const PiccardParams selected_one_twenty_eight =
        SelectSanitizerCandidate(one_twenty_eight, candidate);

    EXPECT_EQ(selected_forty.QueryStatBits(), 60u);
    EXPECT_EQ(selected_forty.CoefficientStatBits(), 74u);
    EXPECT_EQ(selected_sixty_four.QueryStatBits(), 84u);
    EXPECT_EQ(selected_sixty_four.CoefficientStatBits(), 98u);
    EXPECT_EQ(selected_one_twenty_eight.QueryStatBits(), 148u);
    EXPECT_EQ(selected_one_twenty_eight.CoefficientStatBits(), 162u);
}

TEST(SanitizerCandidate, UnsupportedTranscriptTargetIsRejectedExactly) {
    PiccardParams profile = DerivedDefaultOneHotProfile();
    profile.transcript_stat_bits = 41;

    const std::string message = InvalidArgumentMessage([&] {
        (void)SelectSanitizerCandidate(profile, GrownOneHotCandidate());
    });

    ASSERT_FALSE(message.empty());
    EXPECT_NE(
        message.find("transcript_stat_bits must be exactly 40, 64, or 128"),
        std::string::npos);
}

TEST(PreThresholdCalibration, StoresEveryLogicalKeyAndMeasuredField) {
    const PreThresholdCalibrationRow row = PrimaryOneHotRow();

    EXPECT_EQ(row.key.profile_id, "primary40");
    EXPECT_EQ(row.key.circuit, Circuit::OneHot);
    EXPECT_EQ(row.key.shape_id, "onehot-v1");
    EXPECT_EQ(row.key.security, SecurityLevel::STD128);
    EXPECT_EQ(row.key.requested_ring_dim, 8192u);
    EXPECT_EQ(row.key.natural_depth, 1u);
    EXPECT_EQ(
        row.key.consumer_set_sha256,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    EXPECT_EQ(row.key.openfhe_version, "OpenFHE-test");
    EXPECT_EQ(row.natural_ring_dim, 8192u);
    EXPECT_EQ(row.ring_dim_calibrated, 8192u);
    EXPECT_EQ(row.provisioned_depth, 3u);
    EXPECT_EQ(row.scaling_mod_size, 40u);
    EXPECT_EQ(row.num_limbs, 5u);
    EXPECT_EQ(row.plaintext_mod, 65537u);
    EXPECT_DOUBLE_EQ(row.log_q, 200.0);
    EXPECT_DOUBLE_EQ(row.log_delta, 183.9999779867);
    EXPECT_EQ(row.eval_noise_bits, 60u);
    EXPECT_EQ(row.ct_bytes, 4096u);
    EXPECT_EQ(row.transcript_stat_bits, 40u);
    EXPECT_EQ(row.max_queries, UINT64_C(1) << 20);
    EXPECT_EQ(row.query_stat_bits, 60u);
    EXPECT_EQ(row.coefficient_stat_bits, 73u);
    EXPECT_EQ(row.flood_margin_bits, 8u);
    EXPECT_EQ(row.flood_noise_bits, 141u);
}

TEST(PreThresholdCalibration, RejectsEveryLogicalKeyMutation) {
    const PreThresholdCalibrationRequest request = PrimaryOneHotRequest();
    struct Mutation {
        const char* name;
        std::function<void(PreThresholdCalibrationRow&)>
            apply;
    };
    const Mutation mutations[] = {
        {"profile_id", [](PreThresholdCalibrationRow& row) {
             row.key.profile_id = "sensitivity64";
         }},
        {"circuit", [](PreThresholdCalibrationRow& row) {
             row.key.circuit = Circuit::Sqrt;
         }},
        {"shape_id", [](PreThresholdCalibrationRow& row) {
             row.key.shape_id = "sqrt-b8-v1";
         }},
        {"security", [](PreThresholdCalibrationRow& row) {
             row.key.security = SecurityLevel::STD192;
         }},
        {"requested_ring_dim", [](PreThresholdCalibrationRow& row) {
             row.key.requested_ring_dim = 16384;
         }},
        {"natural_depth", [](PreThresholdCalibrationRow& row) {
             row.key.natural_depth = 2;
         }},
        {"consumer_set_sha256", [](PreThresholdCalibrationRow& row) {
             row.key.consumer_set_sha256 =
                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
         }},
        {"openfhe_version", [](PreThresholdCalibrationRow& row) {
             row.key.openfhe_version = "stale";
         }},
    };

    for (const auto& mutation : mutations) {
        SCOPED_TRACE(mutation.name);
        PreThresholdCalibrationRow row = PrimaryOneHotRow();
        mutation.apply(row);
        EXPECT_THROW(
            (void)SelectPreThresholdCalibration(
                DerivedDefaultOneHotProfile(), request, {row}),
            std::invalid_argument);
    }
}

TEST(PreThresholdProfilePolicy, ResolvesOnlyCanonicalPolicies) {
    const auto primary = ResolvePreThresholdProfilePolicy("primary40");
    EXPECT_EQ(primary.transcript_stat_bits, 40u);
    EXPECT_EQ(primary.max_queries, UINT64_C(1) << 20);
    EXPECT_EQ(primary.flood_margin_bits, 8u);
    EXPECT_EQ(primary.maximum_ring_growth, 2u);

    const auto sensitivity =
        ResolvePreThresholdProfilePolicy("sensitivity64");
    EXPECT_EQ(sensitivity.transcript_stat_bits, 64u);
    EXPECT_EQ(sensitivity.maximum_ring_growth, 2u);

    const auto feasibility =
        ResolvePreThresholdProfilePolicy("feasibility128");
    EXPECT_EQ(feasibility.transcript_stat_bits, 128u);
    EXPECT_EQ(feasibility.maximum_ring_growth, 4u);

    EXPECT_THROW(
        (void)ResolvePreThresholdProfilePolicy("unknown"),
        std::invalid_argument);
}

TEST(PreThresholdCalibration, RejectsProfilePolicyMismatch) {
    struct Fixture {
        const char* name;
        std::function<void(PiccardParams&, PreThresholdCalibrationRequest&,
                           PreThresholdCalibrationRow&)> mutate;
    };
    const Fixture fixtures[] = {
        {"unknown_profile", [](PiccardParams&,
                               PreThresholdCalibrationRequest& request,
                               PreThresholdCalibrationRow& row) {
             request.profile_id = "unknown";
             row.key.profile_id = "unknown";
         }},
        {"transcript", [](PiccardParams& profile,
                           PreThresholdCalibrationRequest&,
                           PreThresholdCalibrationRow& row) {
             profile.transcript_stat_bits = 64;
             row.transcript_stat_bits = 64;
             row.query_stat_bits = 84;
             row.coefficient_stat_bits = 97;
             row.flood_noise_bits = 165;
         }},
        {"max_queries", [](PiccardParams& profile,
                            PreThresholdCalibrationRequest&,
                            PreThresholdCalibrationRow& row) {
             profile.max_queries = 1;
             row.max_queries = 1;
             row.query_stat_bits = 40;
             row.coefficient_stat_bits = 53;
             row.flood_noise_bits = 121;
         }},
        {"margin", [](PiccardParams& profile,
                       PreThresholdCalibrationRequest&,
                       PreThresholdCalibrationRow& row) {
             profile.flood_margin_bits = 9;
             row.flood_margin_bits = 9;
             row.flood_noise_bits = 142;
         }},
    };

    for (const auto& fixture : fixtures) {
        SCOPED_TRACE(fixture.name);
        PiccardParams profile = DerivedDefaultOneHotProfile();
        PreThresholdCalibrationRequest request = PrimaryOneHotRequest();
        PreThresholdCalibrationRow row = PrimaryOneHotRow();
        fixture.mutate(profile, request, row);
        EXPECT_THROW(
            (void)SelectPreThresholdCalibration(profile, request, {row}),
            std::invalid_argument);
    }
}

TEST(PreThresholdCalibration, NeverBorrowsAcrossSecurityLevels) {
    PreThresholdCalibrationRow std192 = PrimaryOneHotRow();
    std192.key.security = SecurityLevel::STD192;

    EXPECT_THROW(
        (void)SelectPreThresholdCalibration(
            DerivedDefaultOneHotProfile(),
            PrimaryOneHotRequest(),
            {std192}),
        std::invalid_argument);

    PiccardParams profile192;
    profile192.security = SecurityLevel::STD192;
    CalibrationAccess::Derive(profile192);
    PreThresholdCalibrationRequest request192 = PrimaryOneHotRequest();
    request192.security = SecurityLevel::STD192;
    request192.requested_ring_dim = profile192.ring_dim;
    PreThresholdCalibrationRow std128 = PrimaryOneHotRow();
    EXPECT_THROW(
        (void)SelectPreThresholdCalibration(
            profile192, request192, {std128}),
        std::invalid_argument);
}

TEST(PreThresholdCalibration, RecomputesEveryDerivedCapacityField) {
    struct Mutation {
        const char* name;
        std::function<void(PreThresholdCalibrationRow&)> apply;
    };
    const Mutation mutations[] = {
        {"transcript_stat_bits", [](PreThresholdCalibrationRow& row) {
             ++row.transcript_stat_bits;
         }},
        {"max_queries", [](PreThresholdCalibrationRow& row) {
             ++row.max_queries;
         }},
        {"query_stat_bits", [](PreThresholdCalibrationRow& row) {
             ++row.query_stat_bits;
         }},
        {"coefficient_stat_bits", [](PreThresholdCalibrationRow& row) {
             ++row.coefficient_stat_bits;
         }},
        {"flood_margin_bits", [](PreThresholdCalibrationRow& row) {
             ++row.flood_margin_bits;
         }},
        {"flood_noise_bits", [](PreThresholdCalibrationRow& row) {
             ++row.flood_noise_bits;
         }},
    };
    for (const auto& mutation : mutations) {
        SCOPED_TRACE(mutation.name);
        PreThresholdCalibrationRow row = PrimaryOneHotRow();
        mutation.apply(row);
        EXPECT_THROW(
            (void)SelectPreThresholdCalibration(
                DerivedDefaultOneHotProfile(),
                PrimaryOneHotRequest(),
                {row}),
            std::invalid_argument);
    }
}

TEST(PreThresholdCalibration, DoublingRingAddsExactlyOneCoefficientBit) {
    const PiccardParams natural = SelectPreThresholdCalibration(
        DerivedDefaultOneHotProfile(),
        PrimaryOneHotRequest(),
        {PrimaryOneHotRow(8192)});
    const PiccardParams grown = SelectPreThresholdCalibration(
        DerivedDefaultOneHotProfile(),
        PrimaryOneHotRequest(),
        {PrimaryOneHotRow(16384)});

    EXPECT_EQ(
        grown.CoefficientStatBits(),
        natural.CoefficientStatBits() + 1u);
}

TEST(PreThresholdCalibration, RejectsInvalidGrowthAndOverflow) {
    std::vector<PreThresholdCalibrationRow> invalid_rows;
    PreThresholdCalibrationRow non_integral = PrimaryOneHotRow();
    non_integral.ring_dim_calibrated = 12288;
    invalid_rows.push_back(non_integral);
    PreThresholdCalibrationRow shrink = PrimaryOneHotRow();
    shrink.ring_dim_calibrated = 4096;
    invalid_rows.push_back(shrink);
    PreThresholdCalibrationRow forbidden = PrimaryOneHotRow();
    forbidden.ring_dim_calibrated = 32768;
    invalid_rows.push_back(forbidden);
    PreThresholdCalibrationRow overflow = PrimaryOneHotRow();
    overflow.eval_noise_bits = std::numeric_limits<uint32_t>::max();
    overflow.flood_noise_bits = std::numeric_limits<uint32_t>::max();
    invalid_rows.push_back(overflow);

    for (const auto& row : invalid_rows) {
        EXPECT_THROW(
            (void)SelectPreThresholdCalibration(
                DerivedDefaultOneHotProfile(),
                PrimaryOneHotRequest(),
                {row}),
            std::invalid_argument);
    }
}

TEST(PreThresholdCalibration, ChoosesMeasuredCostIndependentOfInputOrder) {
    PreThresholdCalibrationRow expensive_n = PrimaryOneHotRow(16384);
    expensive_n.log_q = 170.0;
    expensive_n.log_delta = 153.9999779867;
    expensive_n.ct_bytes = 100;

    PreThresholdCalibrationRow expensive_q = PrimaryOneHotRow();
    expensive_q.log_q = 210.0;
    expensive_q.log_delta = 193.9999779867;
    expensive_q.ct_bytes = 3000;
    expensive_q.provisioned_depth = 2;
    expensive_q.scaling_mod_size = 35;

    PreThresholdCalibrationRow winner = PrimaryOneHotRow();
    winner.log_q = 200.0;
    winner.ct_bytes = 4000;
    winner.provisioned_depth = 4;
    winner.scaling_mod_size = 45;

    const auto select = [&](std::vector<PreThresholdCalibrationRow> rows) {
        return SelectPreThresholdCalibration(
            DerivedDefaultOneHotProfile(),
            PrimaryOneHotRequest(),
            rows);
    };
    const PiccardParams forward =
        select({expensive_n, expensive_q, winner});
    const PiccardParams reverse =
        select({winner, expensive_q, expensive_n});

    EXPECT_DOUBLE_EQ(
        forward.SelectedPreThresholdCalibration().log_q,
        200.0);
    EXPECT_DOUBLE_EQ(
        reverse.SelectedPreThresholdCalibration().log_q,
        200.0);
    EXPECT_EQ(forward.mult_depth, 4u);
    EXPECT_EQ(reverse.mult_depth, 4u);
}

TEST(PreThresholdCalibration, UsesCiphertextDepthAndScalingTieBreakers) {
    PreThresholdCalibrationRow high_ct = PrimaryOneHotRow();
    high_ct.ct_bytes = 5000;

    PreThresholdCalibrationRow high_depth = PrimaryOneHotRow();
    high_depth.ct_bytes = 4000;
    high_depth.provisioned_depth = 4;
    high_depth.scaling_mod_size = 35;

    PreThresholdCalibrationRow high_sms = PrimaryOneHotRow();
    high_sms.ct_bytes = 4000;
    high_sms.provisioned_depth = 3;
    high_sms.scaling_mod_size = 45;

    PreThresholdCalibrationRow winner = PrimaryOneHotRow();
    winner.ct_bytes = 4000;
    winner.provisioned_depth = 3;
    winner.scaling_mod_size = 40;

    const PiccardParams selected = SelectPreThresholdCalibration(
        DerivedDefaultOneHotProfile(),
        PrimaryOneHotRequest(),
        {high_ct, high_depth, high_sms, winner});
    const auto& row = selected.SelectedPreThresholdCalibration();
    EXPECT_EQ(row.ct_bytes, 4000u);
    EXPECT_EQ(row.provisioned_depth, 3u);
    EXPECT_EQ(row.scaling_mod_size, 40u);
}

TEST(PreThresholdCalibration, RejectsConflictingEqualCostRowsInAnyOrder) {
    PreThresholdCalibrationRow first = PrimaryOneHotRow();
    PreThresholdCalibrationRow second = PrimaryOneHotRow();
    ++second.eval_noise_bits;
    ++second.flood_noise_bits;

    const auto select =
        [&](const std::vector<PreThresholdCalibrationRow>& rows) {
            return SelectPreThresholdCalibration(
                DerivedDefaultOneHotProfile(),
                PrimaryOneHotRequest(),
                rows);
        };
    for (const auto& rows :
         {std::vector<PreThresholdCalibrationRow>{first, second},
          std::vector<PreThresholdCalibrationRow>{second, first}}) {
        const std::string message =
            InvalidArgumentMessage([&] { (void)select(rows); });
        EXPECT_NE(
            message.find("conflicting equal-cost"),
            std::string::npos);
    }

    EXPECT_NO_THROW((void)select({first, first}));
}

TEST(PreThresholdCalibration, RejectsImpossibleMeasuredLogRelationship) {
    PreThresholdCalibrationRow impossible = PrimaryOneHotRow();
    impossible.log_q = 100.0;
    impossible.log_delta = 200.0;

    EXPECT_THROW(
        (void)SelectPreThresholdCalibration(
            DerivedDefaultOneHotProfile(),
            PrimaryOneHotRequest(),
            {impossible}),
        std::invalid_argument);
}

TEST(PreThresholdCalibration, CheaperIncompleteOrMismatchedRowCannotWin) {
    PreThresholdCalibrationRow valid = PrimaryOneHotRow();
    valid.log_q = 200.0;
    valid.ct_bytes = 4000;

    PreThresholdCalibrationRow incomplete = PrimaryOneHotRow();
    incomplete.log_q = 1.0;
    incomplete.log_delta = 1000.0;
    incomplete.ct_bytes = 0;

    PreThresholdCalibrationRow mismatched = PrimaryOneHotRow();
    mismatched.key.profile_id = "sensitivity64";
    mismatched.log_q = 1.0;
    mismatched.log_delta = 1000.0;
    mismatched.ct_bytes = 1;

    const PiccardParams selected = SelectPreThresholdCalibration(
        DerivedDefaultOneHotProfile(),
        PrimaryOneHotRequest(),
        {incomplete, mismatched, valid});
    EXPECT_DOUBLE_EQ(
        selected.SelectedPreThresholdCalibration().log_q,
        200.0);
}

TEST(ExplicitRingCandidates, PreservesExplicitMonotoneDoublingLists) {
    const ExplicitRingCandidateSet primary = BuildExplicitRingCandidateSet(
        ExplicitRingCandidateRequest{
            "primary40",
            SecurityLevel::STD128,
            8192,
            {8192, 16384},
        },
        40,
        UINT64_C(1) << 20,
        8);
    const ExplicitRingCandidateSet feasibility =
        BuildExplicitRingCandidateSet(
            ExplicitRingCandidateRequest{
                "feasibility128",
                SecurityLevel::STD192,
                8192,
                {8192, 16384, 32768},
            },
            128,
            UINT64_C(1) << 20,
            8);

    EXPECT_EQ(primary.candidates, (std::vector<uint32_t>{8192, 16384}));
    EXPECT_EQ(
        feasibility.candidates,
        (std::vector<uint32_t>{8192, 16384, 32768}));
}

TEST(ExplicitRingCandidates, RejectsEveryInvalidSequenceShape) {
    const std::vector<std::vector<uint32_t>> invalid = {
        {4096, 8192},
        {8192, 12288},
        {8192, 32768},
        {8192, 8192},
        {8192, 16384, 32768},
        {524288, 1048576, 2097152},
    };
    for (const auto& candidates : invalid) {
        SCOPED_TRACE(::testing::PrintToString(candidates));
        EXPECT_THROW(
            (void)BuildExplicitRingCandidateSet(
                ExplicitRingCandidateRequest{
                    "primary40",
                    SecurityLevel::STD128,
                    candidates.front() == 4096 ? 8192u : candidates.front(),
                    candidates,
                },
                40,
                UINT64_C(1) << 20,
                8),
            std::invalid_argument);
    }
}

TEST(ExplicitRingCandidates, FeasibilityAlonePermitsFourfoldGrowth) {
    EXPECT_NO_THROW(
        (void)BuildExplicitRingCandidateSet(
            ExplicitRingCandidateRequest{
                "feasibility128",
                SecurityLevel::STD128,
                8192,
                {8192, 16384, 32768},
            },
            128,
            UINT64_C(1) << 20,
            8));
    EXPECT_THROW(
        (void)BuildExplicitRingCandidateSet(
            ExplicitRingCandidateRequest{
                "sensitivity64",
                SecurityLevel::STD128,
                8192,
                {8192, 16384, 32768},
            },
            64,
            UINT64_C(1) << 20,
            8),
        std::invalid_argument);
    EXPECT_THROW(
        (void)BuildExplicitRingCandidateSet(
            ExplicitRingCandidateRequest{
                "primary40",
                SecurityLevel::STD128,
                8192,
                {8192, 16384, 32768},
            },
            128,
            UINT64_C(1) << 20,
            8),
        std::invalid_argument);
}

TEST(ExplicitRingCandidates, RejectsUnknownOrMismatchedProfilePolicy) {
    const auto build = [](
                           const std::string& profile_id,
                           uint32_t transcript_stat_bits,
                           uint64_t max_queries,
                           uint32_t margin) {
        return BuildExplicitRingCandidateSet(
            ExplicitRingCandidateRequest{
                profile_id,
                SecurityLevel::STD128,
                8192,
                {8192},
            },
            transcript_stat_bits,
            max_queries,
            margin);
    };

    EXPECT_THROW(
        (void)build("unknown", 40, UINT64_C(1) << 20, 8),
        std::invalid_argument);
    EXPECT_THROW(
        (void)build("primary40", 64, UINT64_C(1) << 20, 8),
        std::invalid_argument);
    EXPECT_THROW(
        (void)build("primary40", 40, (UINT64_C(1) << 20) - 1, 8),
        std::invalid_argument);
    EXPECT_THROW(
        (void)build("primary40", 40, UINT64_C(1) << 20, 9),
        std::invalid_argument);
}

TEST(ExplicitRingCandidates, RetainsSecurityIdentityWithoutBorrowing) {
    const auto std128 = BuildExplicitRingCandidateSet(
        ExplicitRingCandidateRequest{
            "primary40",
            SecurityLevel::STD128,
            8192,
            {8192, 16384},
        },
        40,
        UINT64_C(1) << 20,
        8);
    const auto std192 = BuildExplicitRingCandidateSet(
        ExplicitRingCandidateRequest{
            "primary40",
            SecurityLevel::STD192,
            16384,
            {16384, 32768},
        },
        40,
        UINT64_C(1) << 20,
        8);

    EXPECT_EQ(std128.security, SecurityLevel::STD128);
    EXPECT_EQ(std128.natural_ring_dim, 8192u);
    EXPECT_EQ(std192.security, SecurityLevel::STD192);
    EXPECT_EQ(std192.natural_ring_dim, 16384u);
    EXPECT_NE(std128.candidates, std192.candidates);
}

TEST(PiccardParams, RuntimeAdoptionRequiresPriorSelection) {
    PiccardParams never_derived;
    EXPECT_THROW(
        never_derived.AdoptVerifiedRuntimeRingDim(8192),
        std::logic_error);

    PiccardParams derived_only = DerivedDefaultOneHotProfile();
    EXPECT_THROW(
        derived_only.AdoptVerifiedRuntimeRingDim(8192),
        std::logic_error);
}

TEST(PiccardParams, GrownRuntimeAdoptionPreservesRequestedDimension) {
    PiccardParams selected = SelectedGrownOneHotProfile();

    EXPECT_THROW(
        selected.AdoptVerifiedRuntimeRingDim(8192),
        std::invalid_argument);
    EXPECT_EQ(selected.RequestedRingDim(), 8192u);
    EXPECT_EQ(selected.SelectedCalibratedRingDim(), 16384u);
    EXPECT_EQ(selected.ring_dim, 8192u);
    EXPECT_EQ(selected.FloodNoiseBits(), 142u);

    EXPECT_NO_THROW(selected.AdoptVerifiedRuntimeRingDim(16384));
    EXPECT_EQ(selected.RequestedRingDim(), 8192u);
    EXPECT_EQ(selected.SelectedCalibratedRingDim(), 16384u);
    EXPECT_EQ(selected.ring_dim, 16384u);
    EXPECT_EQ(selected.FloodNoiseBits(), 142u);
}

TEST(PiccardParams, RuntimeAdoptionIsOneTime) {
    PiccardParams selected = SelectedGrownOneHotProfile();
    selected.AdoptVerifiedRuntimeRingDim(16384);

    EXPECT_THROW(
        selected.AdoptVerifiedRuntimeRingDim(16384),
        std::logic_error);
}

TEST(PiccardParams, StaleSourceBeforeAdoptionFailsClosed) {
    struct Mutation {
        const char* name;
        std::function<void(PiccardParams&)> apply;
    };
    const Mutation mutations[] = {
        {"eval_noise_bits", [](PiccardParams& params) {
             ++params.eval_noise_bits;
         }},
        {"flood_margin_bits", [](PiccardParams& params) {
             ++params.flood_margin_bits;
         }},
        {"transcript_stat_bits", [](PiccardParams& params) {
             params.transcript_stat_bits = 64;
         }},
        {"max_queries", [](PiccardParams& params) {
             ++params.max_queries;
         }},
        {"ring_dim", [](PiccardParams& params) {
             params.ring_dim = 16384;
         }},
    };

    for (const auto& mutation : mutations) {
        SCOPED_TRACE(mutation.name);
        PiccardParams selected = SelectedGrownOneHotProfile();
        mutation.apply(selected);
        EXPECT_THROW(selected.FloodNoiseBits(), std::logic_error);
    }
}

TEST(PiccardParams, StaleSourcePreventsRuntimeAdoption) {
    PiccardParams selected = SelectedGrownOneHotProfile();
    ++selected.flood_margin_bits;

    EXPECT_THROW(
        selected.AdoptVerifiedRuntimeRingDim(16384),
        std::logic_error);
    EXPECT_EQ(selected.ring_dim, 8192u);
}

TEST(PiccardParams, StaleSourceAfterAdoptionFailsClosed) {
    struct Mutation {
        const char* name;
        std::function<void(PiccardParams&)> apply;
    };
    const Mutation mutations[] = {
        {"eval_noise_bits", [](PiccardParams& params) {
             ++params.eval_noise_bits;
         }},
        {"flood_margin_bits", [](PiccardParams& params) {
             ++params.flood_margin_bits;
         }},
        {"transcript_stat_bits", [](PiccardParams& params) {
             params.transcript_stat_bits = 64;
         }},
        {"max_queries", [](PiccardParams& params) {
             ++params.max_queries;
         }},
        {"ring_dim", [](PiccardParams& params) {
             params.ring_dim = 8192;
         }},
    };

    for (const auto& mutation : mutations) {
        SCOPED_TRACE(mutation.name);
        PiccardParams selected = SelectedGrownOneHotProfile();
        selected.AdoptVerifiedRuntimeRingDim(16384);
        mutation.apply(selected);
        EXPECT_THROW(selected.FloodNoiseBits(), std::logic_error);
    }
}

TEST(PiccardParams, ThresholdCompatibilityUsesPrivateCoefficientTarget) {
    const PiccardParams selected = SelectedThresholdCompatibilityProfile();

    EXPECT_EQ(selected.RequestedRingDim(), 1024u);
    EXPECT_EQ(selected.SelectedCalibratedRingDim(), 1024u);
    EXPECT_EQ(selected.QueryStatBits(), 0u);
    EXPECT_EQ(selected.CoefficientStatBits(), 64u);
    EXPECT_EQ(
        selected.FloodNoiseBits(),
        selected.eval_noise_bits + 64u + selected.flood_margin_bits);
}

TEST(PiccardParams, ThresholdCompatibilityAdoptsSelectedRuntimeOnce) {
    PiccardParams selected = SelectedThresholdCompatibilityProfile();

    EXPECT_THROW(
        selected.AdoptVerifiedRuntimeRingDim(2048),
        std::invalid_argument);
    EXPECT_EQ(selected.ring_dim, 1024u);

    EXPECT_NO_THROW(selected.AdoptVerifiedRuntimeRingDim(1024));
    EXPECT_EQ(selected.RequestedRingDim(), 1024u);
    EXPECT_EQ(selected.SelectedCalibratedRingDim(), 1024u);
    EXPECT_EQ(selected.ring_dim, 1024u);
    EXPECT_EQ(selected.QueryStatBits(), 0u);
    EXPECT_EQ(selected.CoefficientStatBits(), 64u);
    EXPECT_EQ(
        selected.FloodNoiseBits(),
        selected.eval_noise_bits + 64u + selected.flood_margin_bits);

    EXPECT_THROW(
        selected.AdoptVerifiedRuntimeRingDim(1024),
        std::logic_error);
}

TEST(PiccardParams, ThresholdCompatibilityMutationsFailClosedBeforeAdoption) {
    struct Mutation {
        const char* name;
        std::function<void(PiccardParams&)> apply;
    };
    const Mutation mutations[] = {
        {"eval_noise_bits", [](PiccardParams& params) {
             ++params.eval_noise_bits;
         }},
        {"flood_margin_bits", [](PiccardParams& params) {
             ++params.flood_margin_bits;
         }},
        {"transcript_stat_bits", [](PiccardParams& params) {
             params.transcript_stat_bits = 64;
         }},
        {"max_queries", [](PiccardParams& params) {
             ++params.max_queries;
         }},
        {"ring_dim", [](PiccardParams& params) {
             params.ring_dim = 2048;
         }},
    };

    for (const auto& mutation : mutations) {
        SCOPED_TRACE(mutation.name);
        PiccardParams selected = SelectedThresholdCompatibilityProfile();
        mutation.apply(selected);
        EXPECT_THROW(selected.FloodNoiseBits(), std::logic_error);
    }
}

TEST(PiccardParams, ThresholdCompatibilityMutationsFailClosedAfterAdoption) {
    struct Mutation {
        const char* name;
        std::function<void(PiccardParams&)> apply;
    };
    const Mutation mutations[] = {
        {"eval_noise_bits", [](PiccardParams& params) {
             ++params.eval_noise_bits;
         }},
        {"flood_margin_bits", [](PiccardParams& params) {
             ++params.flood_margin_bits;
         }},
        {"transcript_stat_bits", [](PiccardParams& params) {
             params.transcript_stat_bits = 64;
         }},
        {"max_queries", [](PiccardParams& params) {
             ++params.max_queries;
         }},
        {"ring_dim", [](PiccardParams& params) {
             params.ring_dim = 2048;
         }},
    };

    for (const auto& mutation : mutations) {
        SCOPED_TRACE(mutation.name);
        PiccardParams selected = SelectedThresholdCompatibilityProfile();
        selected.AdoptVerifiedRuntimeRingDim(1024);
        mutation.apply(selected);
        EXPECT_THROW(selected.FloodNoiseBits(), std::logic_error);
    }
}

TEST(PiccardParams, Infeasible128IsNotReportedAsMissingCalibration) {
    PiccardParams params;
    params.transcript_stat_bits = 128;

    const std::string message =
        InvalidArgumentMessage([&] { params.Validate(); });

    ASSERT_FALSE(message.empty());
    RecordProperty("infeasible_128_diagnostic", message);
    EXPECT_NE(message.find("infeasible sanitizer calibration"), std::string::npos);
    EXPECT_EQ(message.find("missing sanitizer calibration"), std::string::npos);
    EXPECT_NE(message.find("transcript target 128"), std::string::npos);
    EXPECT_NE(message.find("query cap 1048576"), std::string::npos);
}

TEST(PiccardParams, ToySecuritySmallRing) {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    RecordProperty("input_k", 16);
    RecordProperty("input_m", 8);
    RecordProperty("input_security", "TOY");

    params.Validate();

    RecordProperty("output_feature_dim", static_cast<int>(params.feature_dim));
    RecordProperty("output_ring_dim", static_cast<int>(params.ring_dim));
    RecordProperty("output_plaintext_mod", std::to_string(params.plaintext_mod));

    EXPECT_EQ(params.feature_dim, 128u);
    EXPECT_GE(params.ring_dim, 1024u);
}

TEST(PiccardParams, LargeKM) {
    PiccardParams params;
    params.k = 256;
    params.m = 64;
    params.security = SecurityLevel::STD128;
    RecordProperty("input_k", 256);
    RecordProperty("input_m", 64);
    RecordProperty("input_security", "STD128");

    params.Validate();

    RecordProperty("output_feature_dim", static_cast<int>(params.feature_dim));
    RecordProperty("output_ring_dim", static_cast<int>(params.ring_dim));
    RecordProperty("output_plaintext_mod", std::to_string(params.plaintext_mod));

    EXPECT_EQ(params.feature_dim, 256u * 64u);
    EXPECT_GE(params.ring_dim, 16384u);
    EXPECT_GT(params.plaintext_mod, 256u);
}

TEST(PiccardParams, InvalidK) {
    PiccardParams params;
    params.k = 0;
    RecordProperty("input_k", 0);
    RecordProperty("expected_outcome", "throws std::invalid_argument");
    EXPECT_THROW(params.Validate(), std::invalid_argument);
}

TEST(PiccardParams, InvalidM) {
    PiccardParams params;
    params.m = 1;
    RecordProperty("input_m", 1);
    RecordProperty("expected_outcome", "throws std::invalid_argument");
    EXPECT_THROW(params.Validate(), std::invalid_argument);
}

TEST(PiccardParams, ThresholdMultDepth) {
    // Verify mult_depth for threshold mode matches what EvalPolyBFV requires.
    // Formula: 1 (initial ct*ct) + baby_depth(s) + (num_chunks - 1)
    // where s = smallest integer with s*s >= k+1
    struct Case {
        uint32_t k;
        uint32_t expected_depth;
    };
    //  k=4:  s=3, baby=2, chunks=2, giant=1  → 1+2+1=4
    //  k=8:  s=3, baby=2, chunks=3, giant=2  → 1+2+2=5
    //  k=16: s=5, baby=3, chunks=4, giant=3  → 1+3+3=7
    //  k=32: s=6, baby=3, chunks=6, giant=5  → 1+3+5=9
    //  k=64: s=9, baby=4, chunks=8, giant=7  → 1+4+7=12
    Case cases[] = {
        {4, 4}, {8, 5}, {16, 7}, {32, 9}, {64, 12}
    };

    for (auto& c : cases) {
        PiccardParams params;
        params.k = c.k;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.threshold_mode = true;
        params.threshold_tau = c.k / 2;
        params.Validate();

        RecordProperty("k_" + std::to_string(c.k) + "_mult_depth",
                       static_cast<int>(params.mult_depth));
        // Assert on natural_mult_depth: this is the number that must keep
        // matching EvalPolyBFV's step-size calculation. mult_depth may sit
        // above it to carry the flooding term.
        EXPECT_EQ(params.natural_mult_depth, c.expected_depth)
            << "k=" << c.k << ": expected natural depth=" << c.expected_depth
            << ", got " << params.natural_mult_depth;
        EXPECT_GE(params.mult_depth, params.natural_mult_depth) << "k=" << c.k;
    }
}

TEST(PiccardParams, ThresholdK256Std128SelectsMeasuredProvisionedDepth) {
    PiccardParams params;
    params.k = 256;
    params.m = 64;
    params.security = SecurityLevel::STD128;
    params.threshold_mode = true;
    params.threshold_tau = 153;

    ASSERT_NO_THROW(params.Validate());
    EXPECT_EQ(params.natural_mult_depth, 21u);
    EXPECT_EQ(params.mult_depth, 22u);
    EXPECT_EQ(params.ring_dim, 16384u);
    EXPECT_EQ(params.ring_dim_natural, 32768u);
    EXPECT_EQ(params.SelectedCalibratedRingDim(), 32768u);
    EXPECT_EQ(params.scaling_mod_size, 45u);
    EXPECT_EQ(params.eval_noise_bits, 713u);
}

TEST(PiccardParams, NonThresholdMultDepthIsOne) {
    // Without threshold_mode, the circuit needs exactly one multiplication
    RecordProperty("input_threshold_mode", "false");
    RecordProperty("expected_natural_mult_depth", "1");

    for (uint32_t k : {4u, 16u, 64u, 128u}) {
        PiccardParams params;
        params.k = k;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.Validate();

        RecordProperty("k_" + std::to_string(k) + "_natural_mult_depth",
                       static_cast<int>(params.natural_mult_depth));
        EXPECT_EQ(params.natural_mult_depth, 1u) << "k=" << k;
        EXPECT_GE(params.mult_depth, params.natural_mult_depth) << "k=" << k;
    }
}

TEST(PiccardParams, ThresholdPlaintextModStillValid) {
    // Threshold mode increases mult_depth, which may affect ring_dim.
    // Plaintext modulus must still satisfy: prime, > k, ≡ 1 mod 2N.
    RecordProperty("input_threshold_mode", "true");

    for (uint32_t k : {4u, 16u, 64u}) {
        PiccardParams params;
        params.k = k;
        params.m = 8;
        params.security = SecurityLevel::TOY;
        params.threshold_mode = true;
        params.threshold_tau = k / 2;
        params.Validate();

        uint32_t two_n = 2 * params.ring_dim;
        RecordProperty("k_" + std::to_string(k) + "_plaintext_mod",
                       std::to_string(params.plaintext_mod));
        RecordProperty("k_" + std::to_string(k) + "_ring_dim",
                       static_cast<int>(params.ring_dim));

        EXPECT_GT(params.plaintext_mod, k)
            << "k=" << k << ": p must be > k";
        EXPECT_EQ(params.plaintext_mod % two_n, 1u)
            << "k=" << k << ": p must be ≡ 1 mod 2N";
        EXPECT_TRUE(IsPrime(params.plaintext_mod))
            << "k=" << k << ": p must be prime";
    }
}

TEST(PiccardParams, FeatureDimAndRingDimConsistency) {
    // For various k*m combinations, ring_dim >= feature_dim and is a power of 2
    struct Case {
        uint32_t k; uint32_t m; uint32_t expected_feature_dim;
    };
    Case cases[] = {
        {16, 8, 128}, {32, 16, 512}, {128, 32, 4096}, {64, 64, 4096}
    };

    for (auto& c : cases) {
        PiccardParams params;
        params.k = c.k;
        params.m = c.m;
        params.security = SecurityLevel::TOY;
        params.Validate();

        RecordProperty("k" + std::to_string(c.k) + "_m" + std::to_string(c.m) +
                       "_feature_dim", static_cast<int>(params.feature_dim));
        RecordProperty("k" + std::to_string(c.k) + "_m" + std::to_string(c.m) +
                       "_ring_dim", static_cast<int>(params.ring_dim));

        EXPECT_EQ(params.feature_dim, c.expected_feature_dim);
        EXPECT_GE(params.ring_dim, params.feature_dim);
        EXPECT_EQ(params.ring_dim & (params.ring_dim - 1), 0u)
            << "ring_dim must be power of 2";
    }
}

// ── Public CRS seed (§"CRS 표현") ────────────────────────────────────────────
// hash_seed is a public parameter, not a derived one: Validate()/ValidateSqrt()
// must preserve whatever the caller set and must not range-check it, since
// every uint64_t is a valid seed.

TEST(PiccardParams, HashSeedDefaultsTo42) {
    PiccardParams params;
    EXPECT_EQ(params.hash_seed, 42ULL);
}

TEST(PiccardParams, ValidatePreservesDefaultHashSeed) {
    PiccardParams params;
    params.Validate();
    EXPECT_EQ(params.hash_seed, 42ULL);
}

TEST(PiccardParams, ValidatePreservesCustomHashSeed) {
    const uint64_t seeds[] = {0ULL, 1ULL, 42ULL, 12345ULL,
                              UINT64_MAX - 1, UINT64_MAX};
    for (uint64_t seed : seeds) {
        PiccardParams params;
        params.hash_seed = seed;
        params.Validate();
        RecordProperty("seed_" + std::to_string(seed), "preserved");
        EXPECT_EQ(params.hash_seed, seed);
    }
}

TEST(PiccardParams, ValidateSqrtPreservesCustomHashSeed) {
    const uint64_t seeds[] = {0ULL, 7ULL, UINT64_MAX};
    for (uint64_t seed : seeds) {
        PiccardParams params;
        params.hash_seed = seed;
        params.ValidateSqrt();
        EXPECT_EQ(params.hash_seed, seed);
    }
}

// Extreme seeds must not make expansion throw or produce a degenerate family.
TEST(PiccardParams, ExtremeHashSeedsAreAccepted) {
    const uint64_t seeds[] = {0ULL, UINT64_MAX};
    for (uint64_t seed : seeds) {
        PiccardParams params;
        params.hash_seed = seed;
        EXPECT_NO_THROW(params.Validate());
    }
}

TEST(PiccardParams, ThresholdMultDepthTree) {
    // Tree giant step: depth = 1 + baby_depth + ceil(log2(num_chunks)).
    struct Case { uint32_t k; uint32_t expected_depth; uint32_t expected_giant_mults; };
    Case cases[] = {
        {4, 4, 1}, {8, 5, 3}, {16, 6, 4}, {32, 7, 7},
        {64, 8, 9}, {128, 9, 13}, {256, 10, 18},
    };
    for (auto& c : cases) {
        PiccardParams params;
        params.k = c.k;
        params.m = 64;
        params.security = SecurityLevel::STD128;
        params.threshold_mode = true;
        params.threshold_tau = c.k / 2;
        params.giant_step = GiantStepMode::Tree;
        CalibrationAccess::Derive(params);  // derive only: tree has no table rows
        EXPECT_EQ(params.natural_mult_depth, c.expected_depth) << "k=" << c.k;
        EXPECT_EQ(PatersonStockmeyerNaturalDepth(c.k, GiantStepMode::Tree),
                  c.expected_depth) << "k=" << c.k;
        EXPECT_EQ(PatersonStockmeyerGiantMults(c.k, GiantStepMode::Tree),
                  c.expected_giant_mults) << "k=" << c.k;
    }
    EXPECT_EQ(PatersonStockmeyerNaturalDepth(128, GiantStepMode::Horner), 15u);
    EXPECT_EQ(PatersonStockmeyerNaturalDepth(256, GiantStepMode::Horner), 21u);
    EXPECT_EQ(PatersonStockmeyerGiantMults(128, GiantStepMode::Horner), 10u);
}

TEST(PiccardParams, GiantStepMutationAfterValidateIsDetected) {
    // giant_step is part of the validation snapshot: flipping it after a
    // successful selection must be caught by the fail-closed revalidation.
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.threshold_mode = true;
    params.threshold_tau = 8;
    params.Validate();  // Horner, TOY row exists
    ASSERT_TRUE(params.FloodingSized());
    params.giant_step = GiantStepMode::Tree;
    EXPECT_THROW(params.FloodNoiseBits(), std::logic_error);
}

namespace {
PiccardParams MakeTreeStd128(uint32_t k) {
    PiccardParams p;
    p.k = k;
    p.m = 64;
    p.security = SecurityLevel::STD128;
    p.threshold_mode = true;
    p.threshold_tau = static_cast<uint32_t>(0.6 * k);
    p.giant_step = GiantStepMode::Tree;
    return p;
}
}  // namespace

TEST(PiccardParams, ThresholdOverrideFeasible) {
    PiccardParams params = MakeTreeStd128(128);  // natural depth 9
    // 320 + 64 + 8 + 2 = 394 <= 416 -> feasible.
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{11, 54, 320, 16384, 416.0};
    params.Validate();
    EXPECT_EQ(params.natural_mult_depth, 9u);
    EXPECT_EQ(params.mult_depth, 11u);
    EXPECT_EQ(params.scaling_mod_size, 54u);
    EXPECT_EQ(params.eval_noise_bits, 320u);
    EXPECT_EQ(params.ring_dim_natural, 16384u);
    EXPECT_EQ(params.RequestedRingDim(), 8192u);
    EXPECT_EQ(params.SelectedCalibratedRingDim(), 16384u);
    EXPECT_TRUE(params.FloodingSized());
    EXPECT_EQ(params.FloodNoiseBits(), 320u + 64u + 8u);
}

TEST(PiccardParams, ThresholdOverrideInfeasible) {
    PiccardParams params = MakeTreeStd128(128);
    // 340 + 64 + 8 + 2 = 414 > 400 -> infeasible.
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{10, 40, 340, 16384, 400.0};
    EXPECT_THROW(params.Validate(), std::invalid_argument);
}

TEST(PiccardParams, ThresholdOverrideRejectsDepthBelowNatural) {
    PiccardParams params = MakeTreeStd128(128);
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{8, 54, 300, 16384, 416.0};  // 8 < 9
    EXPECT_THROW(params.Validate(), std::invalid_argument);
}

TEST(PiccardParams, TreeWithoutOverrideNeverAdoptsHornerRow) {
    // (8192,7) and (8192,9) exist in the frozen table but were measured on
    // the Horner circuit; Tree k=32 / k=128 must not silently adopt them.
    for (uint32_t k : {32u, 128u}) {
        PiccardParams params = MakeTreeStd128(k);
        EXPECT_THROW(params.Validate(), std::invalid_argument) << "k=" << k;
    }
}

TEST(PiccardParams, HornerRejectsOverride) {
    PiccardParams params = MakeTreeStd128(128);
    params.giant_step = GiantStepMode::Horner;
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{16, 45, 531, 32768, 614.0};
    EXPECT_THROW(params.Validate(), std::invalid_argument);
}

TEST(PiccardParams, HornerTablePathUnchanged) {
    PiccardParams params = MakeTreeStd128(128);
    params.giant_step = GiantStepMode::Horner;
    params.Validate();
    EXPECT_EQ(params.natural_mult_depth, 15u);
    EXPECT_EQ(params.RequestedRingDim(), 8192u);
    EXPECT_EQ(params.SelectedCalibratedRingDim(), 32768u);
}

// Discrimination guard for ThresholdOverrideFeasible. That test's override
// values {11, 54, ..., 16384, 416.0} were copied from the frozen (8192, 9)
// Horner row, so three of its five assertions would also hold if the selector
// silently ignored the override and read the table. Here every observable
// field is a value NO Threshold/STD128 (8192, natural 9) table row carries:
// the table offers mult_depth {9, 10, 11}, scaling_mod_size {40, 50, 54},
// eval_noise_bits {313, 314, 326, 336} and ring_dim_natural 16384 only.
TEST(PiccardParams, ThresholdOverrideValuesCannotComeFromTheTable) {
    PiccardParams params = MakeTreeStd128(128);  // natural depth 9
    // 300 + 64 + 8 + 2 = 374 <= 410 -> feasible.
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{13, 60, 300, 32768, 410.0};
    params.Validate();
    EXPECT_EQ(params.mult_depth, 13u);
    EXPECT_EQ(params.scaling_mod_size, 60u);
    EXPECT_EQ(params.eval_noise_bits, 300u);
    EXPECT_EQ(params.ring_dim_natural, 32768u);
    EXPECT_EQ(params.SelectedCalibratedRingDim(), 32768u);
    EXPECT_EQ(params.FloodNoiseBits(), 300u + 64u + 8u);
}

// Pins the feasibility inequality to the OVERRIDE's log_delta rather than the
// table row's. The (8192, 9) rows reach log_delta 416.0, so if the table value
// leaked in, the 393.0 case below would be accepted instead of rejected.
TEST(PiccardParams, ThresholdOverrideFeasibilityBoundaryUsesOverrideLogDelta) {
    // required_capacity = 320 + 64 + 8 + 2 = 394.
    PiccardParams at_boundary = MakeTreeStd128(128);
    at_boundary.threshold_calibration_override =
        ThresholdCalibrationOverride{11, 54, 320, 16384, 394.0};
    at_boundary.Validate();  // 394 <= 394 -> exactly feasible
    EXPECT_TRUE(at_boundary.FloodingSized());

    PiccardParams below_boundary = MakeTreeStd128(128);
    below_boundary.threshold_calibration_override =
        ThresholdCalibrationOverride{11, 54, 320, 16384, 393.0};
    EXPECT_THROW(below_boundary.Validate(), std::invalid_argument);
}

// The override is caller input, not derived selection state, so the
// ClearFloodingSelection() that opens every Validate()/derive-only entry point
// must leave it in place. If it were cleared, the second Validate() would fail
// closed with "GiantStepMode::Tree requires threshold_calibration_override".
TEST(PiccardParams, ThresholdOverrideSurvivesRevalidation) {
    PiccardParams params = MakeTreeStd128(128);
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{11, 54, 320, 16384, 416.0};
    params.Validate();
    CalibrationAccess::Derive(params);  // derive-only: clears the selection
    EXPECT_FALSE(params.FloodingSized());
    ASSERT_TRUE(params.threshold_calibration_override.has_value());
    params.Validate();
    EXPECT_TRUE(params.FloodingSized());
    EXPECT_EQ(params.eval_noise_bits, 320u);
}

// The remaining validation rejections the brief specifies, each of which would
// otherwise resolve to a feasible row (300 + 64 + 8 + 2 = 374 <= 416).
TEST(PiccardParams, ThresholdOverrideRejectsMalformedFields) {
    struct Case {
        const char* what;
        ThresholdCalibrationOverride ov;
    };
    const Case cases[] = {
        {"ring_dim_natural not a power of two",
         ThresholdCalibrationOverride{11, 54, 300, 24576, 416.0}},
        {"ring_dim_natural below the requested N",
         ThresholdCalibrationOverride{11, 54, 300, 4096, 416.0}},
        {"ring_dim_natural zero",
         ThresholdCalibrationOverride{11, 54, 300, 0, 416.0}},
        {"eval_noise_bits zero",
         ThresholdCalibrationOverride{11, 54, 0, 16384, 416.0}},
        {"log_delta zero",
         ThresholdCalibrationOverride{11, 54, 300, 16384, 0.0}},
        {"log_delta negative",
         ThresholdCalibrationOverride{11, 54, 300, 16384, -1.0}},
        {"log_delta not finite",
         ThresholdCalibrationOverride{
             11, 54, 300, 16384,
             std::numeric_limits<double>::quiet_NaN()}},
        {"log_delta infinite",
         ThresholdCalibrationOverride{
             11, 54, 300, 16384,
             std::numeric_limits<double>::infinity()}},
    };
    for (const Case& c : cases) {
        PiccardParams params = MakeTreeStd128(128);
        params.threshold_calibration_override = c.ov;
        EXPECT_THROW(params.Validate(), std::invalid_argument) << c.what;
    }
}

// The override is the mandatory companion of giant_step under Tree, so it sits
// in ValidationSnapshot alongside it. These mirror Task 1's
// GiantStepMutationAfterValidateIsDetected. Both mutate ONLY the override:
// every other snapshot field (including the derived eval_noise_bits and the
// private selected_log2_q_over_t_) is left exactly as the selection wrote it,
// so the detection can only come from the override being compared. Remove the
// field from the two std::tie lists and both of these fail.
TEST(PiccardParams, ThresholdOverrideMutationAfterValidateIsDetected) {
    PiccardParams params = MakeTreeStd128(128);
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{11, 54, 320, 16384, 416.0};
    params.Validate();
    ASSERT_TRUE(params.FloodingSized());
    ASSERT_NO_THROW(params.FloodNoiseBits());

    // A budget claim inflated after the fact. It changes no derived field --
    // the selector already copied what it needed -- so nothing but the
    // snapshot's own copy of the override can catch it.
    params.threshold_calibration_override->log_delta = 4096.0;
    EXPECT_THROW(params.FloodNoiseBits(), std::logic_error);
}

TEST(PiccardParams, ThresholdOverrideRemovalAfterValidateIsDetected) {
    PiccardParams params = MakeTreeStd128(128);
    params.threshold_calibration_override =
        ThresholdCalibrationOverride{11, 54, 320, 16384, 416.0};
    params.Validate();
    ASSERT_TRUE(params.FloodingSized());
    ASSERT_NO_THROW(params.FloodNoiseBits());

    // Tree cannot stand without an override; a set that has dropped one is not
    // the set the calibration was selected for.
    params.threshold_calibration_override = std::nullopt;
    EXPECT_THROW(params.FloodNoiseBits(), std::logic_error);
}

// The Horner default carries no override, and that absence must round-trip
// through the snapshot without becoming a spurious mismatch.
TEST(PiccardParams, HornerAbsentOverrideRevalidatesCleanly) {
    PiccardParams params = MakeTreeStd128(128);
    params.giant_step = GiantStepMode::Horner;
    params.Validate();
    ASSERT_TRUE(params.FloodingSized());
    EXPECT_NO_THROW(params.FloodNoiseBits());
    EXPECT_NO_THROW(params.AdoptVerifiedRuntimeRingDim(
        params.SelectedCalibratedRingDim()));
}
