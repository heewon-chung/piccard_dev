#include "baseline_profile.h"

#include <stdexcept>
#include <string>

namespace piccard {
namespace benchmark {
namespace {

bool IsPiccard(BaselineMethod method) {
    return method == BaselineMethod::Piccard ||
           method == BaselineMethod::PiccardSqrt;
}

bool IsBcg12(BaselineMethod method) {
    return method == BaselineMethod::Bcg12MinHashFf ||
           method == BaselineMethod::Bcg12MinHashEc ||
           method == BaselineMethod::Bcg12ExactFf ||
           method == BaselineMethod::Bcg12ExactEc;
}

bool IsBcg12Ff(BaselineMethod method) {
    return method == BaselineMethod::Bcg12MinHashFf ||
           method == BaselineMethod::Bcg12ExactFf;
}

bool IsBcg12MinHash(BaselineMethod method) {
    return method == BaselineMethod::Bcg12MinHashFf ||
           method == BaselineMethod::Bcg12MinHashEc;
}

bool IsSj16(BaselineMethod method) {
    return method == BaselineMethod::Sj16Paillier1024 ||
           method == BaselineMethod::Sj16Paillier2048 ||
           method == BaselineMethod::Sj16Paillier3072;
}

BenchmarkMeasurementKind MatchedMeasurementKind(
    BaselineMethod method,
    BaselineEvidenceKind evidence_kind) {
    if (IsPiccard(method)) {
        return evidence_kind == BaselineEvidenceKind::Timing
            ? BenchmarkMeasurementKind::FheTiming
            : BenchmarkMeasurementKind::FheAccuracy;
    }
    if (IsBcg12(method)) {
        return evidence_kind == BaselineEvidenceKind::Timing
            ? BenchmarkMeasurementKind::PsiTiming
            : BenchmarkMeasurementKind::PsiAccuracy;
    }
    if (IsSj16(method)) {
        return evidence_kind == BaselineEvidenceKind::Timing
            ? BenchmarkMeasurementKind::AheTiming
            : BenchmarkMeasurementKind::AheAccuracy;
    }
    return BenchmarkMeasurementKind::Diagnostic;
}

}  // namespace

BaselineCapability ResolveBaselineCapability(
    BaselineMethod method,
    uint32_t target_security_bits,
    BaselineEvidenceKind evidence_kind,
    BaselineSecurityPolicy policy,
    bool precomputed_randomizers) {
    BaselineCapability capability;
    capability.method = method;
    capability.target_security_bits = target_security_bits;
    capability.secure_division_included = false;

    if (IsPiccard(method)) {
        capability.cryptographic_profile = target_security_bits == 0
            ? "live-BFV-TOY"
            : "live-BFV-STD" + std::to_string(target_security_bits);
        capability.nominal_security_bits = target_security_bits;
        capability.security_match = true;
        capability.comparison_eligible = target_security_bits > 0;
        capability.comparison_scope = ComparisonScope::EndToEndEstimator;
        capability.primitive = method == BaselineMethod::Piccard
            ? Primitive::BfvOneHotMinHash : Primitive::BfvSqrtMinHash;
        capability.protocol_model = method == BaselineMethod::Piccard
            ? ProtocolModel::PiccardTwoOwnerOutsourced
            : ProtocolModel::PiccardSqrtTwoOwnerOutsourced;
        capability.output_semantics =
            OutputSemantics::BiasCorrectedJaccardEstimate;
        capability.assurance_scope =
            AssuranceScope::LiveBfvEmpiricalSanitizerPoc;
        capability.security_basis =
            SecurityBasis::OpenFheHeseaStandardLiveContext;
        capability.cost_scope = CostScope::FullQueryExcludingOneTimeSetup;
        capability.precomputation_mode = PrecomputationMode::CrsAndKeysOnly;
    } else if (method == BaselineMethod::FheInd) {
        if (precomputed_randomizers) {
            throw std::invalid_argument(
                "FHE-IND does not support Paillier randomizer precomputation");
        }
        capability.cryptographic_profile = target_security_bits == 0
            ? "live-BFV-TOY"
            : "live-BFV-STD" + std::to_string(target_security_bits);
        capability.nominal_security_bits = target_security_bits;
        capability.security_match = true;
        capability.comparison_eligible = false;
        capability.comparison_scope = ComparisonScope::DiagnosticOnly;
        capability.primitive = Primitive::BfvIndicatorComparison;
        capability.protocol_model =
            ProtocolModel::LocalUniverseSizedBfvComparator;
        capability.output_semantics =
            OutputSemantics::IntersectionIndicatorVector;
        capability.assurance_scope = AssuranceScope::LiveBfvPrimitiveOnly;
        capability.security_basis =
            SecurityBasis::OpenFheHeseaStandardLiveContext;
        capability.cost_scope = CostScope::PrimitiveOnly;
        capability.precomputation_mode = PrecomputationMode::NotApplicable;
    } else if (IsBcg12(method)) {
        if (precomputed_randomizers) {
            throw std::invalid_argument(
                "BCG12 does not support Paillier randomizer precomputation");
        }
        const bool ff = IsBcg12Ff(method);
        capability.cryptographic_profile = ff ? "FF-3072/256" : "P-256";
        capability.nominal_security_bits = 128;
        capability.security_match = target_security_bits == 128;
        capability.comparison_eligible = capability.security_match;
        capability.comparison_scope = IsBcg12MinHash(method)
            ? ComparisonScope::MatchedEstimatorComponent
            : ComparisonScope::MatchedCardinalityComponent;
        capability.primitive = ff ? Primitive::Bcg12Ff : Primitive::Bcg12Ec;
        capability.protocol_model = IsBcg12MinHash(method)
            ? ProtocolModel::Bcg12CardinalityOnMinHash
            : ProtocolModel::Bcg12ExactCardinality;
        capability.output_semantics = IsBcg12MinHash(method)
            ? OutputSemantics::MinHashCollisionJaccardEstimate
            : OutputSemantics::HarnessReconstructedExactJaccard;
        capability.assurance_scope =
            AssuranceScope::ImplementedBaselineParameterMap;
        capability.security_basis = ff
            ? SecurityBasis::FiniteFieldDh3072Subgroup256ParameterMap
            : SecurityBasis::NistP256ParameterMap;
        capability.cost_scope = CostScope::FullQueryExcludingOneTimeSetup;
        capability.precomputation_mode = PrecomputationMode::CrsAndKeysOnly;
    } else if (IsSj16(method)) {
        uint32_t nominal_bits = 0;
        if (method == BaselineMethod::Sj16Paillier1024) {
            capability.cryptographic_profile = "Paillier-1024";
            nominal_bits = 80;
            capability.primitive = Primitive::Paillier1024;
            capability.security_basis =
                SecurityBasis::RsaIfcModulusSizeProxyApproximately80Bits;
        } else if (method == BaselineMethod::Sj16Paillier2048) {
            capability.cryptographic_profile = "Paillier-2048";
            nominal_bits = 112;
            capability.primitive = Primitive::Paillier2048;
            capability.security_basis =
                SecurityBasis::RsaIfcModulusSizeProxyApproximately112Bits;
        } else {
            capability.cryptographic_profile = "Paillier-3072";
            nominal_bits = 128;
            capability.primitive = Primitive::Paillier3072;
            capability.security_basis =
                SecurityBasis::RsaIfcModulusSizeProxyNotEquivalentSecurityProof;
        }
        capability.nominal_security_bits = nominal_bits;
        capability.security_match =
            method == BaselineMethod::Sj16Paillier3072 &&
            target_security_bits == 128;
        capability.comparison_eligible =
            capability.security_match && !precomputed_randomizers;
        capability.comparison_scope = ComparisonScope::ComponentLowerBound;
        capability.protocol_model = ProtocolModel::Sj16IntersectionShares;
        capability.output_semantics =
            OutputSemantics::HarnessReconstructedJaccardPlaintextUnion;
        capability.assurance_scope =
            AssuranceScope::IntersectionSharesLowerBound;
        capability.cost_scope = precomputed_randomizers
            ? CostScope::OnlineQueryWithPrecomputedRandomizers
            : CostScope::FullQueryExcludingOneTimeSetup;
        capability.precomputation_mode = precomputed_randomizers
            ? PrecomputationMode::RandomizersPrecomputed
            : PrecomputationMode::RandomizerGenerationIncluded;
    } else {
        throw std::invalid_argument("unknown implemented baseline method");
    }

    if (policy == BaselineSecurityPolicy::RequireMatch &&
        !capability.security_match) {
        throw std::invalid_argument(
            std::string(BaselineMethodName(method)) +
            " does not match target security " +
            std::to_string(target_security_bits));
    }
    capability.measurement_kind = capability.security_match
        ? MatchedMeasurementKind(method, evidence_kind)
        : BenchmarkMeasurementKind::Diagnostic;
    if (method == BaselineMethod::FheInd || precomputed_randomizers) {
        capability.comparison_eligible = false;
    }
    return capability;
}

void ValidateBaselineCapability(const BaselineCapability& capability) {
    BaselineEvidenceKind evidence = BaselineEvidenceKind::Timing;
    switch (capability.measurement_kind) {
        case BenchmarkMeasurementKind::FheAccuracy:
        case BenchmarkMeasurementKind::PsiAccuracy:
        case BenchmarkMeasurementKind::AheAccuracy:
            evidence = BaselineEvidenceKind::Accuracy;
            break;
        case BenchmarkMeasurementKind::FheTiming:
        case BenchmarkMeasurementKind::PsiTiming:
        case BenchmarkMeasurementKind::AheTiming:
        case BenchmarkMeasurementKind::Diagnostic:
            break;
        case BenchmarkMeasurementKind::PlaintextEstimator:
            throw std::logic_error(
                "implemented comparison method cannot be plaintext-estimator");
    }
    const bool precomputed = capability.precomputation_mode ==
        PrecomputationMode::RandomizersPrecomputed;
    const BaselineCapability expected = ResolveBaselineCapability(
        capability.method, capability.target_security_bits, evidence,
        BaselineSecurityPolicy::AllowDiagnostic, precomputed);
    if (capability.cryptographic_profile != expected.cryptographic_profile ||
        capability.nominal_security_bits != expected.nominal_security_bits ||
        capability.security_match != expected.security_match ||
        capability.comparison_eligible != expected.comparison_eligible ||
        capability.comparison_scope != expected.comparison_scope ||
        capability.primitive != expected.primitive ||
        capability.protocol_model != expected.protocol_model ||
        capability.output_semantics != expected.output_semantics ||
        capability.assurance_scope != expected.assurance_scope ||
        capability.security_basis != expected.security_basis ||
        capability.cost_scope != expected.cost_scope ||
        capability.precomputation_mode != expected.precomputation_mode ||
        capability.secure_division_included !=
            expected.secure_division_included ||
        capability.measurement_kind != expected.measurement_kind) {
        throw std::logic_error(
            "comparison capability tuple does not match the fixed map");
    }
}

const char* BaselineMethodName(BaselineMethod method) {
    switch (method) {
        case BaselineMethod::Piccard: return "piccard";
        case BaselineMethod::PiccardSqrt: return "piccard_sqrt";
        case BaselineMethod::FheInd: return "baseline";
        case BaselineMethod::Bcg12MinHashFf: return "bcg12_mh_ff";
        case BaselineMethod::Bcg12MinHashEc: return "bcg12_mh_ec";
        case BaselineMethod::Bcg12ExactFf: return "bcg12_exact_ff";
        case BaselineMethod::Bcg12ExactEc: return "bcg12_exact_ec";
        case BaselineMethod::Sj16Paillier1024:
        case BaselineMethod::Sj16Paillier2048:
        case BaselineMethod::Sj16Paillier3072: return "sj16";
    }
    throw std::logic_error("unknown baseline method");
}

const char* BaselineCapabilityMethodName(
    const BaselineCapability& capability) {
    if (IsSj16(capability.method) &&
        capability.precomputation_mode ==
            PrecomputationMode::RandomizersPrecomputed) {
        return "sj16_precomputed";
    }
    return BaselineMethodName(capability.method);
}

const char* PrimitiveName(Primitive primitive) {
    switch (primitive) {
        case Primitive::BfvOneHotMinHash: return "bfv-onehot-minhash";
        case Primitive::BfvSqrtMinHash: return "bfv-sqrt-minhash";
        case Primitive::BfvIndicatorComparison: return "bfv-indicator-comparison";
        case Primitive::Bcg12Ff: return "bcg12-ff";
        case Primitive::Bcg12Ec: return "bcg12-ec";
        case Primitive::Paillier1024: return "paillier-1024";
        case Primitive::Paillier2048: return "paillier-2048";
        case Primitive::Paillier3072: return "paillier-3072";
    }
    throw std::logic_error("unknown primitive");
}

const char* ProtocolModelName(ProtocolModel model) {
    switch (model) {
        case ProtocolModel::PiccardTwoOwnerOutsourced:
            return "piccard-two-owner-outsourced";
        case ProtocolModel::PiccardSqrtTwoOwnerOutsourced:
            return "piccard-sqrt-two-owner-outsourced";
        case ProtocolModel::LocalUniverseSizedBfvComparator:
            return "local-universe-sized-BFV-comparator";
        case ProtocolModel::Bcg12CardinalityOnMinHash:
            return "bcg12-cardinality-on-minhash";
        case ProtocolModel::Bcg12ExactCardinality:
            return "bcg12-exact-cardinality";
        case ProtocolModel::Sj16IntersectionShares:
            return "sj16-intersection-shares";
    }
    throw std::logic_error("unknown protocol model");
}

const char* OutputSemanticsName(OutputSemantics semantics) {
    switch (semantics) {
        case OutputSemantics::BiasCorrectedJaccardEstimate:
            return "bias-corrected-jaccard-estimate";
        case OutputSemantics::IntersectionIndicatorVector:
            return "intersection-indicator-vector";
        case OutputSemantics::MinHashCollisionJaccardEstimate:
            return "minhash-collision-jaccard-estimate";
        case OutputSemantics::HarnessReconstructedExactJaccard:
            return "harness-reconstructed-exact-jaccard";
        case OutputSemantics::HarnessReconstructedJaccardPlaintextUnion:
            return "harness-reconstructed-jaccard-with-plaintext-union";
    }
    throw std::logic_error("unknown output semantics");
}

const char* AssuranceScopeName(AssuranceScope scope) {
    switch (scope) {
        case AssuranceScope::LiveBfvEmpiricalSanitizerPoc:
            return "live-bfv+empirical-sanitizer-poc";
        case AssuranceScope::LiveBfvPrimitiveOnly:
            return "live-bfv-primitive-only";
        case AssuranceScope::ImplementedBaselineParameterMap:
            return "implemented-baseline-parameter-map";
        case AssuranceScope::IntersectionSharesLowerBound:
            return "intersection-shares-lower-bound";
    }
    throw std::logic_error("unknown assurance scope");
}

const char* SecurityBasisName(SecurityBasis basis) {
    switch (basis) {
        case SecurityBasis::OpenFheHeseaStandardLiveContext:
            return "openfhe-hesea-standard-live-context";
        case SecurityBasis::FiniteFieldDh3072Subgroup256ParameterMap:
            return "finite-field-dh-3072-subgroup-256-parameter-map";
        case SecurityBasis::NistP256ParameterMap:
            return "nist-p256-parameter-map";
        case SecurityBasis::RsaIfcModulusSizeProxyApproximately80Bits:
            return "rsa-ifc-modulus-size-proxy-approximately-80-bits";
        case SecurityBasis::RsaIfcModulusSizeProxyApproximately112Bits:
            return "rsa-ifc-modulus-size-proxy-approximately-112-bits";
        case SecurityBasis::RsaIfcModulusSizeProxyNotEquivalentSecurityProof:
            return "rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security";
    }
    throw std::logic_error("unknown security basis");
}

const char* CostScopeName(CostScope scope) {
    switch (scope) {
        case CostScope::FullQueryExcludingOneTimeSetup:
            return "full-query-excluding-one-time-setup";
        case CostScope::OnlineQueryWithPrecomputedRandomizers:
            return "online-query-with-precomputed-randomizers";
        case CostScope::PrimitiveOnly: return "primitive-only";
    }
    throw std::logic_error("unknown cost scope");
}

const char* PrecomputationModeName(PrecomputationMode mode) {
    switch (mode) {
        case PrecomputationMode::CrsAndKeysOnly: return "crs-and-keys-only";
        case PrecomputationMode::RandomizerGenerationIncluded:
            return "randomizer-generation-included";
        case PrecomputationMode::RandomizersPrecomputed:
            return "randomizers-precomputed";
        case PrecomputationMode::NotApplicable: return "not-applicable";
    }
    throw std::logic_error("unknown precomputation mode");
}

const char* ComparisonScopeName(ComparisonScope scope) {
    switch (scope) {
        case ComparisonScope::EndToEndEstimator: return "end-to-end-estimator";
        case ComparisonScope::MatchedEstimatorComponent:
            return "matched-estimator-component";
        case ComparisonScope::MatchedCardinalityComponent:
            return "matched-cardinality-component";
        case ComparisonScope::ComponentLowerBound:
            return "component-lower-bound";
        case ComparisonScope::DiagnosticOnly: return "diagnostic-only";
    }
    throw std::logic_error("unknown comparison scope");
}

}  // namespace benchmark
}  // namespace piccard
