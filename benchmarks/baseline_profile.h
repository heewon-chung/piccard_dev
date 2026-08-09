#pragma once

#include "benchmark_profile.h"

#include <cstdint>
#include <optional>
#include <string>

namespace piccard {
namespace benchmark {

/** @brief Concrete implemented protocol/primitive represented by one row. */
enum class BaselineMethod {
    Piccard,
    PiccardSqrt,
    FheInd,
    Bcg12MinHashFf,
    Bcg12MinHashEc,
    Bcg12ExactFf,
    Bcg12ExactEc,
    Sj16Paillier1024,
    Sj16Paillier2048,
    Sj16Paillier3072,
};

/** @brief Requested evidence arm before method-specific classification. */
enum class BaselineEvidenceKind { Timing, Accuracy };

/** @brief Fail closed or retain an unmatched diagnostic capability row. */
enum class BaselineSecurityPolicy { RequireMatch, AllowDiagnostic };

enum class Primitive {
    BfvOneHotMinHash,
    BfvSqrtMinHash,
    BfvIndicatorComparison,
    Bcg12Ff,
    Bcg12Ec,
    Paillier1024,
    Paillier2048,
    Paillier3072,
};

enum class ProtocolModel {
    PiccardTwoOwnerOutsourced,
    PiccardSqrtTwoOwnerOutsourced,
    LocalUniverseSizedBfvComparator,
    Bcg12CardinalityOnMinHash,
    Bcg12ExactCardinality,
    Sj16IntersectionShares,
};

enum class OutputSemantics {
    BiasCorrectedJaccardEstimate,
    ScalarIntersectionPlaintextJaccard,
    MinHashCollisionJaccardEstimate,
    HarnessReconstructedExactJaccard,
    HarnessReconstructedJaccardPlaintextUnion,
};

enum class AssuranceScope {
    LiveBfvEmpiricalSanitizerPoc,
    LiveBfvPrimitiveOnly,
    ImplementedBaselineParameterMap,
    IntersectionSharesLowerBound,
};

enum class SecurityBasis {
    OpenFheHeseaStandardLiveContext,
    FiniteFieldDh3072Subgroup256ParameterMap,
    NistP256ParameterMap,
    RsaIfcModulusSizeProxyApproximately80Bits,
    RsaIfcModulusSizeProxyApproximately112Bits,
    RsaIfcModulusSizeProxyNotEquivalentSecurityProof,
};

enum class CostScope {
    FullQueryExcludingOneTimeSetup,
    OnlineQueryWithPrecomputedRandomizers,
    PrimitiveOnly,
};

enum class PrecomputationMode {
    CrsAndKeysOnly,
    RandomizerGenerationIncluded,
    RandomizersPrecomputed,
    NotApplicable,
};

enum class ComparisonScope {
    EndToEndEstimator,
    MatchedEstimatorComponent,
    MatchedCardinalityComponent,
    ComponentLowerBound,
    DiagnosticOnly,
};

/** @brief Complete method-conditioned capability metadata for one row. */
struct BaselineCapability {
    BaselineMethod method = BaselineMethod::FheInd;
    BaselineEvidenceKind evidence_kind = BaselineEvidenceKind::Timing;
    uint32_t target_security_bits = 0;
    std::string cryptographic_profile;
    std::optional<uint32_t> nominal_security_bits;
    bool security_match = false;
    bool comparison_eligible = false;
    ComparisonScope comparison_scope = ComparisonScope::DiagnosticOnly;
    Primitive primitive = Primitive::BfvIndicatorComparison;
    ProtocolModel protocol_model =
        ProtocolModel::LocalUniverseSizedBfvComparator;
    OutputSemantics output_semantics =
        OutputSemantics::ScalarIntersectionPlaintextJaccard;
    AssuranceScope assurance_scope = AssuranceScope::LiveBfvPrimitiveOnly;
    SecurityBasis security_basis =
        SecurityBasis::OpenFheHeseaStandardLiveContext;
    CostScope cost_scope = CostScope::PrimitiveOnly;
    PrecomputationMode precomputation_mode =
        PrecomputationMode::NotApplicable;
    bool secure_division_included = false;
    BenchmarkMeasurementKind measurement_kind =
        BenchmarkMeasurementKind::Diagnostic;
};

/**
 * @brief Resolve the fixed implemented capability map.
 *
 * RequireMatch rejects an unsupported target before protocol setup. In
 * AllowDiagnostic mode an unmatched method is retained as diagnostic and
 * comparison-ineligible.
 */
BaselineCapability ResolveBaselineCapability(
    BaselineMethod method,
    uint32_t target_security_bits,
    BaselineEvidenceKind evidence_kind,
    BaselineSecurityPolicy policy = BaselineSecurityPolicy::AllowDiagnostic,
    bool precomputed_randomizers = false);

/** @brief Reject any capability tuple that is not exactly map-derived. */
void ValidateBaselineCapability(const BaselineCapability& capability);

const char* BaselineMethodName(BaselineMethod method);
const char* BaselineCapabilityMethodName(
    const BaselineCapability& capability);
const char* BaselineEvidenceKindName(BaselineEvidenceKind evidence_kind);
const char* PrimitiveName(Primitive primitive);
const char* ProtocolModelName(ProtocolModel model);
const char* OutputSemanticsName(OutputSemantics semantics);
const char* AssuranceScopeName(AssuranceScope scope);
const char* SecurityBasisName(SecurityBasis basis);
const char* CostScopeName(CostScope scope);
const char* PrecomputationModeName(PrecomputationMode mode);
const char* ComparisonScopeName(ComparisonScope scope);

}  // namespace benchmark
}  // namespace piccard
