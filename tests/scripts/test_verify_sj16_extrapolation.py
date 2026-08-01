#!/usr/bin/env python3
"""Schema-migration tests for the SJ16 extrapolation gate."""

import csv
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "verify_sj16_extrapolation.py"
FIELDS = [
    "method", "measurement_kind", "measurement_status", "trials",
    "total_ms", "total_ms_sd", "phase_encode_ms", "extrapolation_alpha",
    "extrapolation_source",
]


def measured():
    return {
        "method": "sj16", "measurement_kind": "ahe-timing",
        "measurement_status": "measured", "trials": "2", "total_ms": "3.0",
        "total_ms_sd": "0.2", "phase_encode_ms": "1.0",
        "extrapolation_alpha": "", "extrapolation_source": "",
    }


def extrapolated():
    row = measured()
    row.update(measurement_status="extrapolated", trials="0", total_ms="7.0",
               total_ms_sd="-1.000", phase_encode_ms="0",
               extrapolation_alpha="1.25", extrapolation_source="fit.csv")
    return row


class Sj16ExtrapolationVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.csv_path = self.root / "comparison_timing.csv"

    def write(self, rows, fields=FIELDS):
        with self.csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    def run_verifier(self, *extra):
        return subprocess.run(
            ["python3", str(VERIFIER), str(self.root), *extra],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_new_measured_and_extrapolated_rows_pass(self):
        self.write([measured(), extrapolated()])
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"verdict": "PASS"', result.stdout)
        self.assertNotIn("DEPRECATED", result.stdout + result.stderr)

    def test_old_schema_requires_explicit_migration_flag(self):
        fields = [field for field in FIELDS if field != "measurement_status"]
        old_measured = measured()
        old_measured["measurement_kind"] = "measured"
        old_extrapolated = extrapolated()
        old_extrapolated["measurement_kind"] = "extrapolated"
        self.write([old_measured, old_extrapolated], fields)

        rejected = self.run_verifier()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("legacy SJ16 schema", rejected.stderr)

        accepted = self.run_verifier("--legacy-sj16-schema")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("DEPRECATED", accepted.stdout + accepted.stderr)

    def test_mixed_legacy_and_new_semantics_are_forbidden(self):
        legacy = extrapolated()
        legacy["measurement_kind"] = "extrapolated"
        legacy["measurement_status"] = ""
        self.write([measured(), legacy])
        result = self.run_verifier("--legacy-sj16-schema")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mixed legacy/new", result.stderr)

    def test_new_schema_rejects_wrong_kind_status_and_nonfinite_values(self):
        cases = (
            ("measurement_kind", "measured", "mixed legacy/new"),
            ("measurement_kind", "ahe-accuracy", "ahe-timing"),
            ("measurement_status", "skipped", "measurement_status"),
            ("total_ms", "NaN", "finite"),
        )
        for column, value, cause in cases:
            with self.subTest(column=column, value=value):
                rows = [measured(), extrapolated()]
                rows[0][column] = value
                self.write(rows)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(cause, result.stderr)


if __name__ == "__main__":
    unittest.main()
