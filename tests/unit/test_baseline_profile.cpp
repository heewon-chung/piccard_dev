#include "baseline_profile.h"
#include "benchmark_estimator_provenance.h"
#include "build_info.h"

#include <gtest/gtest.h>

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace piccard::benchmark;

namespace {

BaselineCapability Capability(
    BaselineMethod method,
    uint32_t target_bits,
    BaselineEvidenceKind evidence = BaselineEvidenceKind::Timing,
    BaselineSecurityPolicy policy = BaselineSecurityPolicy::AllowDiagnostic,
    bool precomputed_randomizers = false) {
    return ResolveBaselineCapability(
        method, target_bits, evidence, policy, precomputed_randomizers);
}

}  // namespace

namespace {

std::vector<std::string> CsvCells(const std::string& line) {
    std::vector<std::string> cells;
    size_t start = 0;
    for (size_t comma = line.find(','); comma != std::string::npos;
         comma = line.find(',', start)) {
        cells.push_back(line.substr(start, comma - start));
        start = comma + 1;
    }
    std::string last = line.substr(start);
    if (!last.empty() && last.back() == '\n') last.pop_back();
    cells.push_back(last);
    return cells;
}

size_t ColumnIndex(const std::string& header, const std::string& name) {
    const auto cells = CsvCells(header);
    const auto it = std::find(cells.begin(), cells.end(), name);
    EXPECT_NE(it, cells.end()) << "missing CSV column " << name;
    return static_cast<size_t>(std::distance(cells.begin(), it));
}

BenchmarkProvenance LiveBfvProvenance() {
    BenchmarkProvenance provenance;
    provenance.actual_ring_dim = 8192;
    provenance.log_q_bits = 120.0;
    provenance.plaintext_modulus = 12289;
    provenance.num_limbs = 3;
    provenance.openfhe_version = PICCARD_BUILD_OPENFHE_VERSION;
    return provenance;
}

ComparisonResult BaseComparisonRow() {
    ComparisonResult row;
    row.scenario = "taxonomy";
    row.estimator_model = EstimatorModel::NotApplicable;
    row.sanitizer = NotApplicableSanitizerMetadata();
    row.measurement_status = "measured";
    return row;
}

}  // namespace

TEST(BaselineProfile, Bcg12ParametersAreOnlyNominalStd128Matches) {
    const auto ff = Capability(BaselineMethod::Bcg12MinHashFf, 128);
    const auto ec = Capability(BaselineMethod::Bcg12MinHashEc, 128);

    EXPECT_EQ(ff.cryptographic_profile, "FF-3072/256");
    EXPECT_EQ(ff.nominal_security_bits, std::optional<uint32_t>(128));
    EXPECT_TRUE(ff.security_match);
    EXPECT_TRUE(ff.comparison_eligible);
    EXPECT_EQ(ff.security_basis,
              SecurityBasis::FiniteFieldDh3072Subgroup256ParameterMap);

    EXPECT_EQ(ec.cryptographic_profile, "P-256");
    EXPECT_EQ(ec.nominal_security_bits, std::optional<uint32_t>(128));
    EXPECT_TRUE(ec.security_match);
    EXPECT_TRUE(ec.comparison_eligible);
    EXPECT_EQ(ec.security_basis, SecurityBasis::NistP256ParameterMap);

    EXPECT_FALSE(Capability(BaselineMethod::Bcg12MinHashFf, 192)
                     .security_match);
    EXPECT_FALSE(Capability(BaselineMethod::Bcg12ExactEc, 192)
                     .security_match);
}

TEST(BaselineProfile, Sj16CapabilitiesDoNotInheritAcrossKeySizes) {
    const auto p1024 = Capability(BaselineMethod::Sj16Paillier1024, 128);
    const auto p2048 = Capability(BaselineMethod::Sj16Paillier2048, 128);
    const auto p3072 = Capability(BaselineMethod::Sj16Paillier3072, 128);

    EXPECT_EQ(p1024.nominal_security_bits, std::optional<uint32_t>(80));
    EXPECT_EQ(p1024.security_basis,
              SecurityBasis::RsaIfcModulusSizeProxyApproximately80Bits);
    EXPECT_FALSE(p1024.security_match);
    EXPECT_FALSE(p1024.comparison_eligible);

    EXPECT_EQ(p2048.nominal_security_bits, std::optional<uint32_t>(112));
    EXPECT_EQ(p2048.security_basis,
              SecurityBasis::RsaIfcModulusSizeProxyApproximately112Bits);
    EXPECT_FALSE(p2048.security_match);
    EXPECT_FALSE(p2048.comparison_eligible);

    EXPECT_EQ(p3072.nominal_security_bits, std::optional<uint32_t>(128));
    EXPECT_EQ(p3072.security_basis,
              SecurityBasis::RsaIfcModulusSizeProxyNotEquivalentSecurityProof);
    EXPECT_TRUE(p3072.security_match);
    EXPECT_TRUE(p3072.comparison_eligible);
    EXPECT_FALSE(Capability(BaselineMethod::Sj16Paillier3072, 192)
                     .security_match);
}

TEST(BaselineProfile, StrictParityRejectsUnsupportedAheBeforeUse) {
    EXPECT_THROW(
        Capability(BaselineMethod::Bcg12MinHashFf, 192,
                   BaselineEvidenceKind::Timing,
                   BaselineSecurityPolicy::RequireMatch),
        std::invalid_argument);
    EXPECT_THROW(
        Capability(BaselineMethod::Sj16Paillier2048, 128,
                   BaselineEvidenceKind::Timing,
                   BaselineSecurityPolicy::RequireMatch),
        std::invalid_argument);
}

TEST(BaselineProfile, DiagnosticModeKeepsUnmatchedAheIneligible) {
    const auto bcg = Capability(BaselineMethod::Bcg12ExactFf, 192);
    const auto sj = Capability(BaselineMethod::Sj16Paillier1024, 128);

    EXPECT_FALSE(bcg.security_match);
    EXPECT_FALSE(bcg.comparison_eligible);
    EXPECT_EQ(bcg.measurement_kind, BenchmarkMeasurementKind::Diagnostic);
    EXPECT_FALSE(sj.security_match);
    EXPECT_FALSE(sj.comparison_eligible);
    EXPECT_EQ(sj.measurement_kind, BenchmarkMeasurementKind::Diagnostic);
}

TEST(BaselineProfile, Sj16IsAlwaysAnIntersectionSharesLowerBound) {
    for (const auto method : {BaselineMethod::Sj16Paillier1024,
                              BaselineMethod::Sj16Paillier2048,
                              BaselineMethod::Sj16Paillier3072}) {
        const auto timing = Capability(method, 128);
        const auto accuracy = Capability(
            method, 128, BaselineEvidenceKind::Accuracy);
        EXPECT_EQ(timing.protocol_model, ProtocolModel::Sj16IntersectionShares);
        EXPECT_EQ(timing.output_semantics,
                  OutputSemantics::HarnessReconstructedJaccardPlaintextUnion);
        EXPECT_EQ(timing.assurance_scope,
                  AssuranceScope::IntersectionSharesLowerBound);
        EXPECT_EQ(timing.comparison_scope,
                  ComparisonScope::ComponentLowerBound);
        EXPECT_FALSE(timing.secure_division_included);
        EXPECT_FALSE(accuracy.secure_division_included);
    }
}

TEST(BaselineProfile, Bcg12ExactAndMinHashModesRemainDistinct) {
    const auto minhash = Capability(BaselineMethod::Bcg12MinHashEc, 128);
    const auto exact = Capability(BaselineMethod::Bcg12ExactEc, 128);

    EXPECT_EQ(minhash.protocol_model,
              ProtocolModel::Bcg12CardinalityOnMinHash);
    EXPECT_EQ(minhash.output_semantics,
              OutputSemantics::MinHashCollisionJaccardEstimate);
    EXPECT_EQ(minhash.comparison_scope,
              ComparisonScope::MatchedEstimatorComponent);
    EXPECT_EQ(exact.protocol_model, ProtocolModel::Bcg12ExactCardinality);
    EXPECT_EQ(exact.output_semantics,
              OutputSemantics::HarnessReconstructedExactJaccard);
    EXPECT_EQ(exact.comparison_scope,
              ComparisonScope::MatchedCardinalityComponent);
}

TEST(BaselineProfile, MeasurementKindsAreMethodConditioned) {
    EXPECT_EQ(Capability(BaselineMethod::Bcg12MinHashFf, 128)
                  .measurement_kind,
              BenchmarkMeasurementKind::PsiTiming);
    EXPECT_EQ(Capability(BaselineMethod::Bcg12ExactEc, 128,
                         BaselineEvidenceKind::Accuracy)
                  .measurement_kind,
              BenchmarkMeasurementKind::PsiAccuracy);
    EXPECT_EQ(Capability(BaselineMethod::Sj16Paillier3072, 128)
                  .measurement_kind,
              BenchmarkMeasurementKind::AheTiming);
    EXPECT_EQ(Capability(BaselineMethod::Sj16Paillier3072, 128,
                         BaselineEvidenceKind::Accuracy)
                  .measurement_kind,
              BenchmarkMeasurementKind::AheAccuracy);
}

TEST(BaselineProfile, Sj16PrecomputedRandomizersAreSensitivityOnly) {
    const auto included = Capability(BaselineMethod::Sj16Paillier3072, 128);
    const auto precomputed = Capability(
        BaselineMethod::Sj16Paillier3072, 128,
        BaselineEvidenceKind::Timing,
        BaselineSecurityPolicy::AllowDiagnostic, true);

    EXPECT_EQ(included.cost_scope,
              CostScope::FullQueryExcludingOneTimeSetup);
    EXPECT_EQ(included.precomputation_mode,
              PrecomputationMode::RandomizerGenerationIncluded);
    EXPECT_TRUE(included.comparison_eligible);
    EXPECT_EQ(precomputed.cost_scope,
              CostScope::OnlineQueryWithPrecomputedRandomizers);
    EXPECT_EQ(precomputed.precomputation_mode,
              PrecomputationMode::RandomizersPrecomputed);
    EXPECT_FALSE(precomputed.comparison_eligible);
}

TEST(BaselineProfile, FheIndIsOnlyTheLocalBfvDiagnosticPrimitive) {
    const auto fhe_ind = Capability(BaselineMethod::FheInd, 192);

    EXPECT_EQ(fhe_ind.cryptographic_profile, "live-BFV-STD192");
    EXPECT_EQ(fhe_ind.nominal_security_bits, std::optional<uint32_t>(192));
    EXPECT_TRUE(fhe_ind.security_match);
    EXPECT_FALSE(fhe_ind.comparison_eligible);
    EXPECT_EQ(fhe_ind.primitive, Primitive::BfvIndicatorComparison);
    EXPECT_EQ(fhe_ind.protocol_model,
              ProtocolModel::LocalUniverseSizedBfvComparator);
    EXPECT_EQ(fhe_ind.output_semantics,
              OutputSemantics::IntersectionIndicatorVector);
    EXPECT_EQ(fhe_ind.assurance_scope,
              AssuranceScope::LiveBfvPrimitiveOnly);
    EXPECT_EQ(fhe_ind.comparison_scope, ComparisonScope::DiagnosticOnly);
    EXPECT_EQ(fhe_ind.security_basis,
              SecurityBasis::OpenFheHeseaStandardLiveContext);
    EXPECT_EQ(fhe_ind.cost_scope, CostScope::PrimitiveOnly);
    EXPECT_EQ(fhe_ind.precomputation_mode,
              PrecomputationMode::NotApplicable);
    EXPECT_FALSE(fhe_ind.secure_division_included);
    EXPECT_EQ(fhe_ind.measurement_kind,
              BenchmarkMeasurementKind::Diagnostic);
}

TEST(BaselineProfile, ExactTaxonomyNamesAreStable) {
    EXPECT_STREQ(SecurityBasisName(
                     SecurityBasis::RsaIfcModulusSizeProxyNotEquivalentSecurityProof),
                 "rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security");
    EXPECT_STREQ(CostScopeName(CostScope::FullQueryExcludingOneTimeSetup),
                 "full-query-excluding-one-time-setup");
    EXPECT_STREQ(PrecomputationModeName(
                     PrecomputationMode::RandomizersPrecomputed),
                 "randomizers-precomputed");
    EXPECT_STREQ(ComparisonScopeName(ComparisonScope::DiagnosticOnly),
                 "diagnostic-only");
    EXPECT_STREQ(ProtocolModelName(
                     ProtocolModel::LocalUniverseSizedBfvComparator),
                 "local-universe-sized-BFV-comparator");
}

TEST(BaselineProfile, SerializerEmitsTypedFheIndTaxonomyAndLiveProvenance) {
    ComparisonResult row = BaseComparisonRow();
    row.method = "baseline";
    row.capability = Capability(BaselineMethod::FheInd, 128);
    row.ring_dim = 8192;
    row.provenance = LiveBfvProvenance();

    const std::string header = SerializeComparisonHeader();
    const auto cells = CsvCells(
        SerializeComparisonRow(row, 2, row.provenance));
    const auto value = [&](const std::string& column) -> const std::string& {
        return cells[ColumnIndex(header, column)];
    };

    EXPECT_EQ(value("cryptographic_profile"), "live-BFV-STD128");
    EXPECT_EQ(value("nominal_security_bits"), "128");
    EXPECT_EQ(value("security_match"), "true");
    EXPECT_EQ(value("comparison_eligible"), "false");
    EXPECT_EQ(value("comparison_scope"), "diagnostic-only");
    EXPECT_EQ(value("primitive"), "bfv-indicator-comparison");
    EXPECT_EQ(value("protocol_model"),
              "local-universe-sized-BFV-comparator");
    EXPECT_EQ(value("output_semantics"), "intersection-indicator-vector");
    EXPECT_EQ(value("assurance_scope"), "live-bfv-primitive-only");
    EXPECT_EQ(value("security_basis"),
              "openfhe-hesea-standard-live-context");
    EXPECT_EQ(value("cost_scope"), "primitive-only");
    EXPECT_EQ(value("precomputation_mode"), "not-applicable");
    EXPECT_EQ(value("secure_division_included"), "false");
    EXPECT_EQ(value("measurement_kind"), "diagnostic");
    EXPECT_EQ(value("k"), "");
    EXPECT_EQ(value("m"), "");
    EXPECT_EQ(value("ring_dim"), "8192");
    EXPECT_EQ(value("actual_ring_dim"), "8192");
    EXPECT_EQ(value("sanitizer_model"), "not-applicable");
}

TEST(BaselineProfile, SerializerEnforcesBcg12ParameterRules) {
    ComparisonResult minhash = BaseComparisonRow();
    minhash.method = "bcg12_mh_ec";
    minhash.capability = Capability(BaselineMethod::Bcg12MinHashEc, 128);
    minhash.k = 128;
    minhash.hash_randomness = "fixed";
    minhash.provenance = MakeAheBenchmarkProvenance();

    const std::string header = SerializeComparisonHeader();
    auto cells = CsvCells(
        SerializeComparisonRow(minhash, 2, minhash.provenance));
    EXPECT_EQ(cells[ColumnIndex(header, "k")], "128");
    EXPECT_EQ(cells[ColumnIndex(header, "m")], "");
    EXPECT_EQ(cells[ColumnIndex(header, "ring_dim")], "");
    EXPECT_EQ(cells[ColumnIndex(header, "measurement_kind")], "psi-timing");

    minhash.m = 64;
    EXPECT_THROW(SerializeComparisonRow(minhash, 2, minhash.provenance),
                 std::logic_error);

    ComparisonResult exact = BaseComparisonRow();
    exact.method = "bcg12_exact_ff";
    exact.capability = Capability(BaselineMethod::Bcg12ExactFf, 128);
    exact.provenance = MakeAheBenchmarkProvenance();
    EXPECT_NO_THROW(SerializeComparisonRow(exact, 2, exact.provenance));
    exact.k = 128;
    EXPECT_THROW(SerializeComparisonRow(exact, 2, exact.provenance),
                 std::logic_error);
}

TEST(BaselineProfile, SerializerEnforcesPiccardAndSj16ParameterRules) {
    ComparisonResult piccard = BaseComparisonRow();
    piccard.method = "piccard";
    piccard.capability = Capability(BaselineMethod::Piccard, 128);
    piccard.k = 128;
    piccard.m = 64;
    piccard.ring_dim = 8192;
    piccard.estimator_model = EstimatorModel::Sha256RandomRankingPocV1;
    piccard.provenance = LiveBfvProvenance();
    EXPECT_NO_THROW(SerializeComparisonRow(piccard, 2, piccard.provenance));
    piccard.m.reset();
    EXPECT_THROW(SerializeComparisonRow(piccard, 2, piccard.provenance),
                 std::logic_error);

    ComparisonResult sj16 = BaseComparisonRow();
    sj16.method = "sj16";
    sj16.capability = Capability(BaselineMethod::Sj16Paillier3072, 128);
    sj16.provenance = MakeAheBenchmarkProvenance();
    EXPECT_NO_THROW(SerializeComparisonRow(sj16, 2, sj16.provenance));
    sj16.ring_dim = 1;
    EXPECT_THROW(SerializeComparisonRow(sj16, 2, sj16.provenance),
                 std::logic_error);
}

TEST(BaselineProfile, SerializerRejectsMissingOrMismatchedTypedCapability) {
    ComparisonResult row = BaseComparisonRow();
    row.method = "baseline";
    row.ring_dim = 8192;
    row.provenance = LiveBfvProvenance();
    EXPECT_THROW(SerializeComparisonRow(row, 2, row.provenance),
                 std::logic_error);

    row.capability = Capability(BaselineMethod::FheInd, 128);
    row.method = "sj16";
    EXPECT_THROW(SerializeComparisonRow(row, 2, row.provenance),
                 std::logic_error);
}
