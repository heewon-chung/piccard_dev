#!/usr/bin/env python3
"""Behavior tests for the strict Phase-3 comparison reporting taxonomy."""

import csv
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SUMMARIZER = ROOT / "scripts" / "summarize_results.py"
VERIFIER = ROOT / "scripts" / "verify_reporting_gaps.py"


FIELDS = [
    "scenario", "method", "cryptographic_profile",
    "nominal_security_bits", "security_match", "comparison_eligible",
    "comparison_scope", "primitive", "protocol_model", "output_semantics",
    "assurance_scope", "security_basis", "cost_scope",
    "precomputation_mode", "secure_division_included", "measurement_kind",
    "evidence_arm", "measurement_status", "universe_size", "set_size", "k", "m",
    "ring_dim", "num_cts", "mult_depth", "total_ms", "total_ms_sd",
    "trials", "ct_size_bytes", "comm_bytes", "phase_flood_ms",
    "phase_flood_ms_sd", "profile_id", "run_class",
    "target_security_bits", "sanitizer_model", "sanitizer_assurance",
    "transcript_stat_bits", "max_queries", "query_stat_bits",
    "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
    "flood_noise_bits", "actual_ring_dim", "log_q_bits",
    "plaintext_modulus", "num_limbs", "openfhe_version",
    "hash_randomness", "hash_seed",
]


def base_row(method):
    row = {field: "" for field in FIELDS}
    row.update({
        "scenario": "vary_universe_64",
        "method": method,
        "evidence_arm": "timing",
        "measurement_status": "measured",
        "universe_size": "64",
        "set_size": "16",
        "num_cts": "1",
        "mult_depth": "0",
        "total_ms": "2.0",
        "total_ms_sd": "0.1",
        "trials": "1",
        "ct_size_bytes": "100",
        "comm_bytes": "300",
        "phase_flood_ms": "0",
        "phase_flood_ms_sd": "-1",
        "profile_id": "std128-t40-primary",
        "run_class": "primary",
        "target_security_bits": "128",
        "secure_division_included": "false",
        "sanitizer_model": "not-applicable",
        "sanitizer_assurance": "not-applicable",
    })
    return row


def piccard_row(evidence_arm="timing", sqrt=False):
    row = base_row("piccard_sqrt" if sqrt else "piccard")
    row.update({
        "cryptographic_profile": "live-BFV-STD128",
        "nominal_security_bits": "128",
        "security_match": "true",
        "comparison_eligible": "true",
        "comparison_scope": "end-to-end-estimator",
        "primitive": "bfv-sqrt-minhash" if sqrt else "bfv-onehot-minhash",
        "protocol_model": (
            "piccard-sqrt-two-owner-outsourced" if sqrt
            else "piccard-two-owner-outsourced"
        ),
        "output_semantics": "bias-corrected-jaccard-estimate",
        "assurance_scope": "live-bfv+empirical-sanitizer-poc",
        "security_basis": "openfhe-hesea-standard-live-context",
        "cost_scope": "full-query-excluding-one-time-setup",
        "precomputation_mode": "crs-and-keys-only",
        "measurement_kind": f"fhe-{evidence_arm}",
        "evidence_arm": evidence_arm,
        "k": "16", "m": "16", "ring_dim": "1024",
        "actual_ring_dim": "1024", "log_q_bits": "160",
        "plaintext_modulus": "12289", "num_limbs": "4",
        "openfhe_version": "1.5.0",
        "sanitizer_model": "phase-smudging-enc0-poc-v1",
        "sanitizer_assurance":
            "empirical-phase-statistical+ciphertext-computational",
        "transcript_stat_bits": "40", "max_queries": "1048576",
        "query_stat_bits": "60", "coefficient_stat_bits": "70",
        "flood_margin_bits": "8", "eval_noise_bits": "56",
        "flood_noise_bits": "134",
    })
    return row


def fhe_ind_row(evidence_arm="timing"):
    row = base_row("fhe_ind")
    row.update({
        "cryptographic_profile": "live-BFV-STD128",
        "nominal_security_bits": "128",
        "security_match": "true",
        "comparison_eligible": "false",
        "comparison_scope": "diagnostic-only",
        "primitive": "bfv-indicator-comparison",
        "protocol_model": "local-universe-sized-BFV-comparator",
        "output_semantics": "scalar-intersection-plaintext-jaccard",
        "assurance_scope": "live-bfv-primitive-only",
        "security_basis": "openfhe-hesea-standard-live-context",
        "cost_scope": "primitive-only",
        "precomputation_mode": "not-applicable",
        "measurement_kind": "diagnostic",
        "evidence_arm": evidence_arm,
        "ring_dim": "1024",
        "actual_ring_dim": "1024", "log_q_bits": "120",
        "plaintext_modulus": "12289", "num_limbs": "2",
        "openfhe_version": "1.5.0",
    })
    return row


def bcg12_row(method="bcg12_mh_ff"):
    row = base_row(method)
    ff = method.endswith("_ff")
    exact = "_exact_" in method
    row.update({
        "cryptographic_profile": "FF-3072/256" if ff else "P-256",
        "nominal_security_bits": "128",
        "security_match": "true",
        "comparison_eligible": "true",
        "comparison_scope": (
            "matched-cardinality-component" if exact
            else "matched-estimator-component"
        ),
        "primitive": "bcg12-ff" if ff else "bcg12-ec",
        "protocol_model": (
            "bcg12-exact-cardinality" if exact
            else "bcg12-cardinality-on-minhash"
        ),
        "output_semantics": (
            "harness-reconstructed-exact-jaccard" if exact
            else "minhash-collision-jaccard-estimate"
        ),
        "assurance_scope": "implemented-baseline-parameter-map",
        "security_basis": (
            "finite-field-dh-3072-subgroup-256-parameter-map" if ff
            else "nist-p256-parameter-map"
        ),
        "cost_scope": "full-query-excluding-one-time-setup",
        "precomputation_mode": "crs-and-keys-only",
        "measurement_kind": "psi-timing",
        "k": "" if exact else "16",
        "hash_randomness": "" if exact else "fixed",
        "hash_seed": "" if exact else "7",
        "openfhe_version": "not-applicable",
    })
    return row


def sj16_row(bits=3072, precomputed=False):
    method = "sj16_precomputed" if precomputed else "sj16"
    row = base_row(method)
    nominal = {1024: "80", 2048: "112", 3072: "128"}[bits]
    match = bits == 3072
    row.update({
        "cryptographic_profile": f"Paillier-{bits}",
        "nominal_security_bits": nominal,
        "security_match": "true" if match else "false",
        "comparison_eligible": "false" if precomputed or not match else "true",
        "comparison_scope": "component-lower-bound",
        "primitive": f"paillier-{bits}",
        "protocol_model": "sj16-intersection-shares",
        "output_semantics":
            "harness-reconstructed-jaccard-with-plaintext-union",
        "assurance_scope": "intersection-shares-lower-bound",
        "security_basis": {
            1024: "rsa-ifc-modulus-size-proxy-approximately-80-bits",
            2048: "rsa-ifc-modulus-size-proxy-approximately-112-bits",
            3072:
                "rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security",
        }[bits],
        "cost_scope": (
            "online-query-with-precomputed-randomizers" if precomputed
            else "full-query-excluding-one-time-setup"
        ),
        "precomputation_mode": (
            "randomizers-precomputed" if precomputed
            else "randomizer-generation-included"
        ),
        "measurement_kind": "ahe-timing" if match else "diagnostic",
        "openfhe_version": "not-applicable",
    })
    return row


class ReportingTaxonomyTest(unittest.TestCase):
    def run_programs(self, rows):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        csv_dir = Path(temp.name)
        with (csv_dir / "comparison_timing.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        summary = subprocess.run(
            ["python3", str(SUMMARIZER), str(csv_dir)],
            cwd=ROOT, capture_output=True, text=True,
        )
        verify = subprocess.run(
            ["python3", str(VERIFIER), str(csv_dir)],
            cwd=ROOT, capture_output=True, text=True,
        )
        return summary, verify

    def test_valid_typed_taxonomy_is_rendered_and_verified(self):
        summary, verify = self.run_programs([
            piccard_row(), fhe_ind_row(), bcg12_row(),
            bcg12_row("bcg12_exact_ec"), sj16_row(),
        ])
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        combined = summary.stdout + summary.stderr + verify.stdout + verify.stderr
        self.assertIn("local-universe-sized-BFV-comparator", combined)
        self.assertIn("intersection-shares-lower-bound", combined)
        self.assertNotIn("KPA/leakage", combined)
        self.assertNotIn("EPSet", combined)

    def test_combined_producer_shape_is_rendered_and_verified(self):
        piccard_timing = piccard_row()
        piccard_timing["total_ms"] = "3.0"
        sqrt_timing = piccard_row(sqrt=True)
        sqrt_timing["total_ms"] = "5.0"
        fhe_ind_timing = fhe_ind_row()
        fhe_ind_timing["total_ms"] = "7.0"

        piccard_accuracy = piccard_row("accuracy")
        piccard_accuracy["total_ms"] = "0.0"
        sqrt_accuracy = piccard_row("accuracy", sqrt=True)
        sqrt_accuracy["total_ms"] = "0.0"
        fhe_ind_accuracy = fhe_ind_row("accuracy")
        fhe_ind_accuracy["total_ms"] = "0.0"

        summary, verify = self.run_programs([
            piccard_timing, sqrt_timing, fhe_ind_timing,
            piccard_accuracy, sqrt_accuracy, fhe_ind_accuracy,
        ])
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn("7.0", summary.stdout)

    def test_same_arm_duplicate_is_still_rejected(self):
        summary, verify = self.run_programs([
            piccard_row(), fhe_ind_row(), fhe_ind_row(),
        ])
        self.assertNotEqual(summary.returncode, 0)
        self.assertNotEqual(verify.returncode, 0)

    def test_old_fhe_ind_taxonomy_is_rejected_by_both_programs(self):
        old = fhe_ind_row()
        old["output_semantics"] = "intersection-indicator-vector"
        summary, verify = self.run_programs([piccard_row(), old])
        self.assertNotEqual(summary.returncode, 0)
        self.assertNotEqual(verify.returncode, 0)

    def test_sj16_key_sizes_and_legacy_measurement_semantics_are_strict(self):
        inherited = sj16_row(2048)
        inherited["security_match"] = "true"
        inherited["comparison_eligible"] = "true"
        inherited["measurement_kind"] = "ahe-timing"
        summary, verify = self.run_programs([
            piccard_row(), fhe_ind_row(), inherited,
        ])
        self.assertNotEqual(summary.returncode, 0)
        self.assertNotEqual(verify.returncode, 0)

        legacy = sj16_row()
        legacy["measurement_kind"] = "measured"
        summary, verify = self.run_programs([
            piccard_row(), fhe_ind_row(), legacy,
        ])
        self.assertNotEqual(summary.returncode, 0)
        self.assertNotEqual(verify.returncode, 0)

    def test_precomputed_sj16_cannot_replace_included_cost_row(self):
        summary, verify = self.run_programs([
            piccard_row(), fhe_ind_row(), sj16_row(precomputed=True),
        ])
        self.assertNotEqual(summary.returncode, 0)
        self.assertNotEqual(verify.returncode, 0)


if __name__ == "__main__":
    unittest.main()
