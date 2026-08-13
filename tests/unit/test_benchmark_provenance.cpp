#include "benchmark_provenance.h"

#include "fhe/bfv_context.h"
#include "util/params.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace piccard::benchmark {
namespace {

PiccardParams ToyParams() {
    PiccardParams params;
    params.k = 16;
    params.m = 8;
    params.security = SecurityLevel::TOY;
    params.Validate();
    return params;
}

TEST(BenchmarkProvenanceV2, LiveContextCarriesCompleteOrderedMetadata) {
    BFVContext context(ToyParams());
    context.InitializeContextOnly();

    const BenchmarkProvenance provenance =
        MakePiccardBenchmarkProvenance(context);
    ASSERT_EQ(provenance.schema_version, kBenchmarkProvenanceSchemaVersion);
    ASSERT_TRUE(provenance.requested_ring_dim.has_value());
    ASSERT_TRUE(provenance.natural_ring_dim.has_value());
    ASSERT_TRUE(provenance.provisioned_ring_dim.has_value());
    ASSERT_TRUE(provenance.realized_ring_dim.has_value());
    EXPECT_EQ(provenance.actual_ring_dim, provenance.realized_ring_dim);
    ASSERT_TRUE(provenance.natural_depth.has_value());
    ASSERT_TRUE(provenance.provisioned_depth.has_value());
    ASSERT_TRUE(provenance.log2_q_over_t_bits.has_value());
    ASSERT_TRUE(provenance.plaintext_modulus.has_value());
    ASSERT_TRUE(provenance.num_limbs.has_value());
    ASSERT_EQ(provenance.ordered_rns_limb_bits.size(),
              static_cast<size_t>(*provenance.num_limbs));
    ASSERT_FALSE(provenance.ordered_rns_moduli.empty());
    ASSERT_EQ(provenance.ordered_rns_limb_bits.size(),
              provenance.ordered_rns_moduli.size());
    EXPECT_EQ(SumOrderedRnsLimbBits(provenance.ordered_rns_limb_bits),
              static_cast<uint64_t>(std::llround(*provenance.log_q_bits)));
    EXPECT_EQ(provenance.flooding_assurance,
              kFloodingAssuranceEmpiricalPhaseStatisticalCiphertextComputational);
    EXPECT_EQ(provenance.residual_capacity_status,
              kResidualCapacityStatusNotExposedByOpenFhe);
    EXPECT_FALSE(provenance.residual_capacity_bits.has_value());
}

TEST(BenchmarkProvenanceV2, ThresholdUsesLegacyCoefficientAssurance) {
    PiccardParams params = ToyParams();
    params.threshold_mode = true;
    params.threshold_tau = 2;
    params.Validate();

    BFVContext context(params);
    context.InitializeContextOnly();
    const BenchmarkProvenance provenance =
        MakePiccardBenchmarkProvenance(context);
    EXPECT_EQ(provenance.flooding_assurance,
              kFloodingAssuranceLegacyCoefficientLevel);
    ASSERT_TRUE(provenance.query_stat_bits.has_value());
    EXPECT_EQ(*provenance.query_stat_bits, 0u);
}

TEST(BenchmarkProvenanceV2, OrderedLimbBitsAndVersionedRoundTripAreExact) {
    BenchmarkProvenance provenance;
    provenance.schema_version = kBenchmarkProvenanceSchemaVersion;
    provenance.actual_ring_dim = 16384;
    provenance.requested_ring_dim = 8192;
    provenance.natural_ring_dim = 8192;
    provenance.provisioned_ring_dim = 16384;
    provenance.realized_ring_dim = 16384;
    provenance.natural_depth = 1;
    provenance.provisioned_depth = 3;
    provenance.log_q_bits = 179.25;
    provenance.log2_q_over_t_bits =
        179.25 - std::log2(static_cast<double>(65537));
    provenance.plaintext_modulus = 65537;
    provenance.num_limbs = 3;
    provenance.ordered_rns_limb_bits = {59, 60, 60};
    provenance.ordered_rns_limb_bit_sizes = provenance.ordered_rns_limb_bits;
    provenance.ordered_rns_moduli = {
        "288230376151711744", "576460752303423488",
        "576460752303423489"};
    provenance.openfhe_version = "1.5.0";
    provenance.flooding_assurance = kFloodingAssuranceNotApplicable;
    provenance.residual_capacity_definition = kResidualCapacityDefinition;
    provenance.residual_capacity_status = kResidualCapacityStatusNotExposedByOpenFhe;

    const std::string serialized = SerializeBenchmarkProvenanceV2(provenance);
    const BenchmarkProvenance parsed =
        ParseBenchmarkProvenanceV2(serialized);
    EXPECT_EQ(parsed.ordered_rns_limb_bits,
              provenance.ordered_rns_limb_bits);
    EXPECT_EQ(parsed.ordered_rns_moduli, provenance.ordered_rns_moduli);
    EXPECT_EQ(parsed.requested_ring_dim, provenance.requested_ring_dim);
    EXPECT_EQ(parsed.provisioned_ring_dim, provenance.provisioned_ring_dim);
    EXPECT_EQ(parsed.realized_ring_dim, provenance.realized_ring_dim);
    EXPECT_EQ(parsed.residual_capacity_status,
              kResidualCapacityStatusNotExposedByOpenFhe);
}

TEST(BenchmarkProvenanceV2, EncodingOnlyUsesNAToRejectFheFields) {
    const BenchmarkProvenance provenance =
        MakeEncodingOnlyBenchmarkProvenance();
    EXPECT_TRUE(provenance.encoding_only);
    EXPECT_EQ(provenance.openfhe_version, "not-applicable");
    EXPECT_EQ(provenance.flooding_assurance, kFloodingAssuranceNotApplicable);
    EXPECT_TRUE(provenance.ordered_rns_limb_bits.empty());
    EXPECT_FALSE(provenance.realized_ring_dim.has_value());
    EXPECT_NO_THROW(ValidateBenchmarkProvenance(provenance));

    auto populated = provenance;
    populated.realized_ring_dim = 8192;
    EXPECT_THROW(ValidateBenchmarkProvenance(populated), std::logic_error);
}

TEST(BenchmarkProvenanceV2, AssuranceTaxonomyRejectsUnknownAndPreservesLegacyNote) {
    BenchmarkProvenance provenance = MakeEncodingOnlyBenchmarkProvenance();
    provenance.legacy_encoding_note = kLegacyEncodingSupersededNote;
    EXPECT_NO_THROW(ValidateBenchmarkProvenance(provenance));

    provenance.flooding_assurance = "fabricated-assurance";
    EXPECT_THROW(ValidateBenchmarkProvenance(provenance), std::logic_error);
}

}  // namespace
}  // namespace piccard::benchmark
