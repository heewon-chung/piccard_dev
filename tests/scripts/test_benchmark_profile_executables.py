#!/usr/bin/env python3
"""Executable golden tests for named comparison-profile CSV output."""

import csv
import io
import subprocess
import sys
import unittest


BENCH_COMPARISON = sys.argv[1] if len(sys.argv) > 1 else "bench_comparison"


class NamedComparisonExecutableTest(unittest.TestCase):
    def run_actual_toy_point(
        self, mode="combined", timing_trials=1, accuracy_trials=1
    ):
        completed = subprocess.run(
            [
                BENCH_COMPARISON,
                "--profile=toy-smoke",
                "--security=TOY",
                f"--mode={mode}",
                "--evidence_point",
                "--k=16",
                "--m=16",
                "--set_size=16",
                "--universe=64",
                "--target-jaccard=0.5",
                f"--trials={timing_trials}",
                f"--accuracy_trials={accuracy_trials}",
                "--seed=7",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return list(csv.DictReader(io.StringIO(completed.stdout)))

    def assert_toy_workload_provenance(self, row):
        self.assertEqual(row["universe_size"], "64")
        self.assertEqual(row["set_size"], "16")
        self.assertEqual(row["target_jaccard"], "0.500000")
        self.assertEqual(row["realized_intersection"], "11")
        self.assertEqual(row["realized_union"], "21")
        self.assertEqual(row["realized_jaccard"], "0.523810")

    def assert_baseline_is_diagnostic(self, row):
        self.assertEqual(row["profile_id"], "legacy")
        self.assertEqual(row["run_class"], "legacy")
        self.assertEqual(row["comparison_eligible"], "false")
        self.assertEqual(row["measurement_kind"], "diagnostic")

    def test_toy_evidence_point_runs_actual_producer_once(self):
        rows = self.run_actual_toy_point()
        self.assertEqual(len(rows), 6)
        self.assertEqual(
            [(row["method"], row["measurement_kind"]) for row in rows],
            [
                ("piccard", "fhe-timing"),
                ("piccard_sqrt", "fhe-timing"),
                ("baseline", "diagnostic"),
                ("piccard", "fhe-accuracy"),
                ("piccard_sqrt", "fhe-accuracy"),
                ("baseline", "diagnostic"),
            ],
        )
        for row in rows:
            self.assert_toy_workload_provenance(row)
            if row["method"] == "baseline":
                self.assert_baseline_is_diagnostic(row)
            else:
                self.assertEqual(row["profile_id"], "toy-smoke")
                self.assertEqual(row["run_class"], "smoke")
                self.assertEqual(row["comparison_eligible"], "false")
        for method in ("piccard", "piccard_sqrt", "baseline"):
            method_rows = [row for row in rows if row["method"] == method]
            self.assertEqual(
                [(row["trials"], row["accuracy_trials"])
                 for row in method_rows],
                [("1", "0"), ("0", "1")],
            )

    def test_toy_timing_mode_does_not_require_accuracy_trials(self):
        rows = self.run_actual_toy_point("timing", accuracy_trials=0)
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            [row["measurement_kind"] for row in rows],
            ["fhe-timing", "fhe-timing", "diagnostic"],
        )
        for row in rows:
            self.assert_toy_workload_provenance(row)
            self.assertEqual(row["trials"], "1")
            self.assertEqual(row["accuracy_trials"], "0")
            self.assertEqual(row["jaccard_computed"], "0.000000")

    def test_toy_accuracy_mode_does_not_require_timing_trials(self):
        rows = self.run_actual_toy_point("accuracy", timing_trials=0)
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            [row["measurement_kind"] for row in rows],
            ["fhe-accuracy", "fhe-accuracy", "diagnostic"],
        )
        for row in rows:
            self.assert_toy_workload_provenance(row)
            self.assertEqual(row["trials"], "0")
            self.assertEqual(row["accuracy_trials"], "1")
            self.assertEqual(row["total_ms"], "0.000")

    def test_production_binary_rejects_synthetic_fixture_option(self):
        completed = subprocess.run(
            [
                BENCH_COMPARISON,
                "--profile=toy-smoke",
                "--security=TOY",
                "--mode=timing",
                "--evidence_point",
                "--k=16",
                "--m=16",
                "--set_size=16",
                "--universe=64",
                "--target-jaccard=0.5",
                "--trials=1",
                "--accuracy_trials=0",
                "--seed=7",
                "--emit_evidence_fixture",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Unknown option", completed.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
