#include "std_security_evidence_schema.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <string>

using namespace piccard;
using namespace piccard::std_evidence;

TEST(StdSecurityEvidenceSchema, CoreMatrixIsExactlyFourFrozenCells) {
    const auto& cells = CoreCells();
    EXPECT_NO_THROW(ValidateCoreMatrix());
    ASSERT_EQ(cells.size(), 4u);
    EXPECT_EQ(cells[0].cell_id, "onehot-std128");
    EXPECT_EQ(cells[1].cell_id, "onehot-std192");
    EXPECT_EQ(cells[2].cell_id, "sqrt-std128");
    EXPECT_EQ(cells[3].cell_id, "sqrt-std192");
    const std::array<EvidenceCircuit, 4> circuits = {
        EvidenceCircuit::OneHot, EvidenceCircuit::OneHot,
        EvidenceCircuit::Sqrt, EvidenceCircuit::Sqrt};
    const std::array<SecurityLevel, 4> securities = {
        SecurityLevel::STD128, SecurityLevel::STD192,
        SecurityLevel::STD128, SecurityLevel::STD192};
    std::set<std::string> ids;
    for (size_t i = 0; i < cells.size(); ++i) {
        EXPECT_EQ(cells[i].circuit, circuits[i]);
        EXPECT_EQ(cells[i].security, securities[i]);
        EXPECT_TRUE(ids.insert(cells[i].cell_id).second);
        EXPECT_EQ(cells[i].shape_id,
                  i < 2 ? "onehot-v1" : "sqrt-b4-v1");
        EXPECT_EQ(cells[i].target_jaccard_numerator, 1u);
        EXPECT_EQ(cells[i].target_jaccard_denominator, 2u);
        EXPECT_EQ(cells[i].realized_intersection, 7u);
        EXPECT_EQ(cells[i].realized_union, 13u);
        EXPECT_EQ(cells[i].seed, 7u);
    }
    for (const auto& cell : cells) {
        EXPECT_NO_THROW(ValidateCellSpec(cell, false));
        EXPECT_EQ(cell.k, 16u);
        EXPECT_EQ(cell.m, 16u);
        EXPECT_EQ(cell.set_size, 10u);
        EXPECT_EQ(cell.trials, 1u);
        EXPECT_EQ(cell.calibration_repetitions, 1u);
    }
    auto changed = cells.front();
    changed.k = 17;
    EXPECT_THROW(ValidateCellSpec(changed, false), std::invalid_argument);
    changed = cells.front();
    changed.trials = 2;
    EXPECT_THROW(ValidateCellSpec(changed, false), std::invalid_argument);
}

TEST(StdSecurityEvidenceSchema, FheIndIsSeparateAndThresholdCannotBeNamed) {
    ASSERT_EQ(FheIndCells().size(), 2u);
    EXPECT_EQ(FheIndCells()[0].cell_id, "fhe-ind-std128");
    EXPECT_EQ(FheIndCells()[1].cell_id, "fhe-ind-std192");
    for (const auto& cell : FheIndCells()) {
        EXPECT_NO_THROW(ValidateCellSpec(cell));
        EXPECT_EQ(cell.k, 0u);
        EXPECT_EQ(cell.m, 0u);
    }
    EXPECT_THROW(ParseSecurityName("Threshold"), std::invalid_argument);
    EXPECT_THROW(ParseStatusName("MISSING_CALIBRATION"), std::invalid_argument);
}

TEST(StdSecurityEvidenceSchema, CandidateGridIsBoundedAndExact) {
    const std::vector<CandidateProposal> expected_onehot = {
        {EvidenceCircuit::OneHot, 3, 40},
        {EvidenceCircuit::OneHot, 3, 45},
        {EvidenceCircuit::OneHot, 4, 40},
        {EvidenceCircuit::OneHot, 4, 45},
    };
    const std::vector<CandidateProposal> expected_sqrt = {
        {EvidenceCircuit::Sqrt, 4, 40},
        {EvidenceCircuit::Sqrt, 4, 45},
    };
    EXPECT_EQ(CandidateProposals(EvidenceCircuit::OneHot), expected_onehot);
    EXPECT_EQ(CandidateProposals(EvidenceCircuit::Sqrt), expected_sqrt);
    for (const auto circuit : {EvidenceCircuit::OneHot,
                               EvidenceCircuit::Sqrt}) {
        for (const auto& proposal : CandidateProposals(circuit)) {
            EXPECT_LE(proposal.provisioned_depth, 4u);
            EXPECT_TRUE(proposal.scaling_mod_size == 40 ||
                        proposal.scaling_mod_size == 45);
        }
    }
    EXPECT_TRUE(CandidateProposals(EvidenceCircuit::FheInd).empty());
}

TEST(StdSecurityEvidenceSchema, TupleDigestIncludesOrderedLiveFields) {
    ContextTuple tuple;
    tuple.bfv_context_fingerprint =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    tuple.circuit = "onehot";
    tuple.shape_id = "onehot-v1";
    tuple.k = 16;
    tuple.m = 16;
    tuple.sanitizer_profile = "primary40";
    tuple.security = SecurityLevel::STD128;
    tuple.requested_ring_dim = 8192;
    tuple.natural_ring_dim = 8192;
    tuple.natural_depth = 1;
    tuple.realized_ring_dim = 8192;
    tuple.plaintext_modulus = 65537;
    tuple.provisioned_depth = 3;
    tuple.scaling_mod_size = 40;
    tuple.ordered_rns_moduli = {"1152921504606846881", "1152921504606846883"};
    tuple.num_limbs = static_cast<uint32_t>(tuple.ordered_rns_moduli.size());
    tuple.openfhe_version = "1.5.0";
    const auto digest = ContextTupleSha256(tuple);
    EXPECT_EQ(digest.size(), 64u);
    EXPECT_EQ(tuple, tuple);
    auto security_changed = tuple;
    security_changed.security = SecurityLevel::STD192;
    EXPECT_NE(digest, ContextTupleSha256(security_changed));
    auto order_changed = tuple;
    std::reverse(order_changed.ordered_rns_moduli.begin(),
                 order_changed.ordered_rns_moduli.end());
    EXPECT_NE(digest, ContextTupleSha256(order_changed));
    auto modulus_changed = tuple;
    modulus_changed.ordered_rns_moduli[1] = "1152921504606846887";
    EXPECT_NE(digest, ContextTupleSha256(modulus_changed));
    auto q_changed = tuple;
    q_changed.plaintext_modulus++;
    EXPECT_NE(digest, ContextTupleSha256(q_changed));
    auto fingerprint_changed = tuple;
    fingerprint_changed.bfv_context_fingerprint[0] = 'f';
    EXPECT_NE(digest, ContextTupleSha256(fingerprint_changed));
    auto circuit_changed = tuple;
    circuit_changed.circuit = "sqrt";
    EXPECT_NE(digest, ContextTupleSha256(circuit_changed));
    auto shape_changed = tuple;
    shape_changed.shape_id = "onehot-v2";
    EXPECT_NE(digest, ContextTupleSha256(shape_changed));
    auto k_changed = tuple;
    k_changed.k++;
    EXPECT_NE(digest, ContextTupleSha256(k_changed));
    auto m_changed = tuple;
    m_changed.m++;
    EXPECT_NE(digest, ContextTupleSha256(m_changed));
    auto sanitizer_changed = tuple;
    sanitizer_changed.sanitizer_profile = "primary45";
    EXPECT_NE(digest, ContextTupleSha256(sanitizer_changed));
    auto requested_changed = tuple;
    requested_changed.requested_ring_dim *= 2;
    EXPECT_NE(digest, ContextTupleSha256(requested_changed));
    auto natural_ring_changed = tuple;
    natural_ring_changed.natural_ring_dim *= 2;
    EXPECT_NE(digest, ContextTupleSha256(natural_ring_changed));
    auto natural_depth_changed = tuple;
    natural_depth_changed.natural_depth++;
    EXPECT_NE(digest, ContextTupleSha256(natural_depth_changed));
    auto realized_changed = tuple;
    realized_changed.realized_ring_dim *= 2;
    EXPECT_NE(digest, ContextTupleSha256(realized_changed));
    auto provisioned_changed = tuple;
    provisioned_changed.provisioned_depth++;
    EXPECT_NE(digest, ContextTupleSha256(provisioned_changed));
    auto scaling_changed = tuple;
    scaling_changed.scaling_mod_size = 45;
    EXPECT_NE(digest, ContextTupleSha256(scaling_changed));
    auto limbs_changed = tuple;
    limbs_changed.num_limbs++;
    EXPECT_THROW(ContextTupleSha256(limbs_changed), std::invalid_argument);
    auto version_changed = tuple;
    version_changed.openfhe_version = "1.5.1";
    EXPECT_NE(digest, ContextTupleSha256(version_changed));
    EXPECT_NE(tuple, security_changed);
}

TEST(StdSecurityEvidenceSchema, PreflightBoundsAreInclusiveAtLimit) {
    EXPECT_FALSE(EvaluatePreflight({32768, 4, 240.0}).skipped);
    const auto decision = EvaluatePreflight({32769, 5, 240.0001});
    ASSERT_TRUE(decision.skipped);
    ASSERT_EQ(decision.reasons.size(), 3u);
    EXPECT_NE(decision.reasons[0].find("observed=32769"), std::string::npos);
    EXPECT_NE(decision.reasons[1].find("observed=5"), std::string::npos);
    EXPECT_NE(decision.reasons[2].find("observed=240.0001"), std::string::npos);
}

TEST(StdSecurityEvidenceSchema, TerminalRowsAreFailClosed) {
    const auto& cell = CoreCells().front();
    TerminalRecord skipped{"onehot-std128", CellStatus::SkippedPrecheck,
                           "realized_ring_dim bound=32768 observed=65536",
                           false, false, false, 1, 1, true,
                           {65536, 4, 240.0}};
    EXPECT_NO_THROW(ValidateTerminalRecord(skipped, cell));
    skipped.keygen_started = true;
    EXPECT_THROW(ValidateTerminalRecord(skipped, cell), std::invalid_argument);
    skipped.keygen_started = false;
    skipped.reason = "MISSING_CALIBRATION observed=0";
    EXPECT_THROW(ValidateTerminalRecord(skipped, cell), std::invalid_argument);
    skipped.reason = "realized_ring_dim bound=32768 observed=garbage";
    EXPECT_THROW(ValidateTerminalRecord(skipped, cell), std::invalid_argument);
    skipped.reason = "realized_ring_dim bound=32768 observed=65536";
    skipped.preflight_caps = {32768, 4, 240.0};
    EXPECT_THROW(ValidateTerminalRecord(skipped, cell), std::invalid_argument);
    skipped.preflight_caps = {65536, 5, 240.0001};
    skipped.reason = "realized_ring_dim bound=32768 observed=65536";
    EXPECT_THROW(ValidateTerminalRecord(skipped, cell), std::invalid_argument);
    skipped.reason = "realized_ring_dim bound=32768 observed=65536; "
                     "provisioned_depth bound=4 observed=5; "
                     "log2(q) bound=240 observed=240.0001";
    EXPECT_NO_THROW(ValidateTerminalRecord(skipped, cell));
    TerminalRecord measured{"onehot-std128", CellStatus::Measured, "", true,
                            true, true, 1, 1, false, {}};
    EXPECT_NO_THROW(ValidateTerminalRecord(measured, cell));

    const auto& fhe_cell = FheIndCells().front();
    TerminalRecord deferred{"fhe-ind-std128", CellStatus::DeferredFheIndNotReady,
                            "readiness capability_missing", false, false,
                            false, 1, 1, false, {}};
    EXPECT_NO_THROW(ValidateTerminalRecord(deferred, fhe_cell));
    deferred.e2e_started = true;
    EXPECT_THROW(ValidateTerminalRecord(deferred, fhe_cell), std::invalid_argument);

    TerminalRecord fhe_measured{"fhe-ind-std128", CellStatus::Measured, "",
                                true, false, true, 1, 1, false, {}};
    EXPECT_NO_THROW(ValidateTerminalRecord(fhe_measured, fhe_cell));
    fhe_measured.calibration_started = true;
    EXPECT_THROW(ValidateTerminalRecord(fhe_measured, fhe_cell),
                 std::invalid_argument);
}

TEST(StdSecurityEvidenceSchema, CompleteV2ProvenanceBindsEveryBoundaryField) {
    CompleteProvenance provenance;
    provenance.schema = kCompleteProvenanceSchemaV2;
    provenance.kind = ProvenanceKind::Piccard;
    provenance.circuit = "onehot";
    provenance.shape_id = "onehot-v1";
    provenance.security = "STD128";
    provenance.bfv_context_fingerprint =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    provenance.requested_ring_dim = 8192;
    provenance.natural_ring_dim = 8192;
    provenance.provisioned_ring_dim = 8192;
    provenance.realized_ring_dim = 8192;
    provenance.natural_depth = 1;
    provenance.provisioned_depth = 3;
    provenance.log_q_bits = 120;
    provenance.log_q_over_t_bits = 103.99997798638864;
    provenance.plaintext_modulus = 65537;
    provenance.num_limbs = 2;
    provenance.scaling_mod_size = 40;
    provenance.ordered_rns_moduli = {"576460752303423487", "2305843009213693951"};
    provenance.ordered_rns_limb_bits = {59, 61};
    provenance.openfhe_version = "1.5.0";
    provenance.transcript_stat_bits = 40;
    provenance.max_queries = 1048576;
    provenance.query_stat_bits = 60;
    provenance.coefficient_stat_bits = 73;
    provenance.flood_margin_bits = 8;
    provenance.eval_noise_bits = 20;
    provenance.flood_noise_bits = 101;
    provenance.required_capacity_bits = 103;
    provenance.flooding_assurance = kFloodingAssurancePiccard;
    provenance.residual_capacity = {
        kResidualCapacityNotExposedByOpenFhe, std::nullopt};
    provenance.residual_capacity.definition = kResidualCapacityDefinition;
    provenance.status = "MEASURED";
    EXPECT_NO_THROW(ValidateCompleteProvenance(provenance));
    const auto digest = CompleteProvenanceSha256(provenance);
    EXPECT_EQ(digest.size(), 64u);

    auto reordered = provenance;
    std::reverse(reordered.ordered_rns_limb_bits.begin(),
                 reordered.ordered_rns_limb_bits.end());
    EXPECT_THROW(ValidateCompleteProvenance(reordered), std::invalid_argument);
    auto missing = provenance;
    missing.ordered_rns_limb_bits.pop_back();
    EXPECT_THROW(ValidateCompleteProvenance(missing), std::invalid_argument);
    auto wrong_ring = provenance;
    wrong_ring.provisioned_ring_dim = *wrong_ring.provisioned_ring_dim * 2;
    EXPECT_NO_THROW(ValidateCompleteProvenance(wrong_ring));
    EXPECT_NE(digest, CompleteProvenanceSha256(wrong_ring));
    auto unknown_assurance = provenance;
    unknown_assurance.flooding_assurance = "invented";
    EXPECT_THROW(ValidateCompleteProvenance(unknown_assurance), std::invalid_argument);
    auto fabricated_residual = provenance;
    fabricated_residual.residual_capacity.bits = 4.0;
    EXPECT_THROW(ValidateCompleteProvenance(fabricated_residual), std::invalid_argument);
    auto downgraded = provenance;
    downgraded.schema = "piccard-std-security-context-v1";
    EXPECT_THROW(ValidateCompleteProvenance(downgraded), std::invalid_argument);
}

TEST(StdSecurityEvidenceSchema, CompleteV2JsonAndCsvRoundTrip) {
    CompleteProvenance provenance;
    provenance.schema = kCompleteProvenanceSchemaV2;
    provenance.kind = ProvenanceKind::EncodingOnly;
    provenance.circuit = "encoding";
    provenance.shape_id = "encoding-v1";
    provenance.security = "not-applicable";
    provenance.bfv_context_fingerprint = "not-applicable";
    provenance.openfhe_version = "not-applicable";
    provenance.flooding_assurance = kNotApplicable;
    provenance.residual_capacity = {kResidualCapacityNotApplicable,
                                    std::nullopt};
    provenance.legacy_encoding_note =
        "legacy-encoding-schema-superseded-by-piccard-benchmark-provenance-v2";
    EXPECT_NO_THROW(ValidateCompleteProvenance(provenance));
    EXPECT_EQ(ParseCompleteProvenanceJson(CompleteProvenanceJson(provenance)),
              provenance);
    EXPECT_EQ(ParseCompleteProvenanceCsv(
                  CompleteProvenanceCsvHeader() +
                  CompleteProvenanceCsvRow(provenance)), provenance);
}
