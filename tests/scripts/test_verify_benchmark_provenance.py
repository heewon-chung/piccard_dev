#!/usr/bin/env python3
"""Behavior tests for strict benchmark row provenance validation."""

import csv
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "verify_benchmark_provenance.py"
SOURCE = ROOT / ".omo" / "evidence" / "work4-phase4-toy-results.csv"


class BenchmarkProvenanceVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.csv_path = Path(self.temp.name) / "results.csv"
        with SOURCE.open(newline="") as stream:
            reader = csv.DictReader(stream)
            self.fields = list(reader.fieldnames or ())
            self.rows = list(reader)
        self.write_rows(self.rows)

    def write_rows(self, rows):
        with self.csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self.fields)
            writer.writeheader()
            writer.writerows(rows)

    def run_verifier(self):
        return subprocess.run(
            ["python3", str(VERIFIER), f"--csv={self.csv_path}"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def assert_rejects(self, rows, cause):
        self.write_rows(rows)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(cause, result.stderr)

    def test_valid_persisted_toy_rows_pass(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"verdict": "PASS"', result.stdout)

    def test_measured_rows_require_each_core_metric_to_be_finite(self):
        required_metrics = (
            "total_ms", "total_ms_median", "jaccard_computed",
            "jaccard_expected", "jaccard_error",
        )
        for column in required_metrics:
            for value in ("", "NaN"):
                with self.subTest(column=column, value=value):
                    rows = [dict(row) for row in self.rows]
                    rows[0][column] = value
                    self.assert_rejects(rows, column)

    def test_complete_std128_capability_fixture_passes(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            row.update(profile_id="std128-t40-primary", run_class="primary",
                       target_security_bits="128", security_match="true",
                       comparison_eligible="true")
            if row["method"] in {"piccard", "piccard_sqrt"}:
                row.update(cryptographic_profile="live-BFV-STD128",
                           nominal_security_bits="128")
            elif row["method"] == "sj16":
                row.update(cryptographic_profile="Paillier-3072",
                           nominal_security_bits="128", primitive="paillier-3072",
                           security_basis="rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security")
        self.write_rows(rows)
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_actual_fhe_metadata_fails(self):
        rows = [dict(row) for row in self.rows]
        rows[0]["actual_ring_dim"] = ""
        self.assert_rejects(rows, "actual FHE metadata")

    def test_invalid_ahe_profile_and_unmatched_std192_claim_fail(self):
        rows = [dict(row) for row in self.rows]
        rows[8]["cryptographic_profile"] = "Paillier-4096"
        self.assert_rejects(rows, "AHE profile")

        rows = [dict(row) for row in self.rows]
        rows[8].update(profile_id="std192-t40-primary", run_class="primary",
                       target_security_bits="192", cryptographic_profile="Paillier-3072",
                       nominal_security_bits="128", primitive="paillier-3072",
                       security_match="true", comparison_eligible="true")
        self.assert_rejects(rows, "STD192")

    def test_sj16_lower_bound_and_model_markers_are_required(self):
        rows = [dict(row) for row in self.rows]
        rows[8]["assurance_scope"] = "not-applicable"
        self.assert_rejects(rows, "lower-bound")

        rows = [dict(row) for row in self.rows]
        rows[0]["estimator_model"] = ""
        self.assert_rejects(rows, "estimator_model")

        rows = [dict(row) for row in self.rows]
        rows[0]["sanitizer_model"] = ""
        self.assert_rejects(rows, "sanitizer_model")

        rows = [dict(row) for row in self.rows]
        rows[0]["query_stat_bits"] = "61"
        self.assert_rejects(rows, "query_stat_bits")

    def test_nonfinite_numeric_and_csv_shape_fail_closed(self):
        for value in ("NaN", "Inf", "-Inf"):
            with self.subTest(value=value):
                rows = [dict(row) for row in self.rows]
                rows[0]["total_ms"] = value
                self.assert_rejects(rows, "finite numeric")

        text = self.csv_path.read_text().splitlines()
        text[1] += ",extra-cell"
        self.csv_path.write_text("\n".join(text) + "\n")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("column count", result.stderr)

    def test_required_column_is_not_optional(self):
        missing = "measurement_status"
        fields = [field for field in self.fields if field != missing]
        with self.csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.rows)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("required columns", result.stderr)


if __name__ == "__main__":
    unittest.main()
