#!/usr/bin/env python3
"""Executable golden tests for named comparison-profile CSV output."""

import csv
import io
import subprocess
import sys
import unittest


BENCH_COMPARISON = sys.argv[1] if len(sys.argv) > 1 else "bench_comparison"


class NamedComparisonExecutableTest(unittest.TestCase):
    def run_fixture(self, mode):
        completed = subprocess.run(
            [
                BENCH_COMPARISON,
                "--profile=std128-t40-primary",
                f"--mode={mode}",
                "--target-jaccard=0.5",
                "--trials=1",
                "--accuracy_trials=1",
                "--seed=7",
                "--emit_evidence_fixture",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return list(csv.DictReader(io.StringIO(completed.stdout)))

    def run_actual_toy_point(self, mode="combined", accuracy_trials=1):
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
                "--trials=1",
                f"--accuracy_trials={accuracy_trials}",
                "--seed=7",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return list(csv.DictReader(io.StringIO(completed.stdout)))

    def assert_workload_provenance(self, row):
        self.assertEqual(row["target_jaccard"], "0.500000")
        self.assertEqual(row["realized_intersection"], "667")
        self.assertEqual(row["realized_union"], "1333")
        self.assertEqual(row["realized_jaccard"], "0.500375")

    def assert_baseline_is_diagnostic(self, row):
        self.assertEqual(row["profile_id"], "legacy")
        self.assertEqual(row["run_class"], "legacy")
        self.assertEqual(row["comparison_eligible"], "false")
        self.assertEqual(row["measurement_kind"], "diagnostic")

    def test_timing_mode_emits_only_timing_aggregates(self):
        rows = self.run_fixture("timing")
        self.assertEqual(len(rows), 6)
        self.assertEqual(
            [(row["universe_size"], row["method"]) for row in rows],
            [
                ("16384", "piccard"),
                ("16384", "piccard_sqrt"),
                ("16384", "baseline"),
                ("65536", "piccard"),
                ("65536", "piccard_sqrt"),
                ("65536", "baseline"),
            ],
        )
        for row in rows:
            self.assert_workload_provenance(row)
            self.assertEqual(row["trials"], "1")
            self.assertEqual(row["accuracy_trials"], "0")
            self.assertEqual(row["jaccard_computed"], "0.000000")
            if row["method"] == "baseline":
                self.assert_baseline_is_diagnostic(row)
            else:
                self.assertEqual(row["profile_id"], "std128-t40-primary")
                self.assertEqual(row["comparison_eligible"], "true")
                self.assertEqual(row["measurement_kind"], "fhe-timing")

    def test_accuracy_mode_emits_only_accuracy_aggregates(self):
        rows = self.run_fixture("accuracy")
        self.assertEqual(len(rows), 6)
        for row in rows:
            self.assert_workload_provenance(row)
            self.assertEqual(row["trials"], "0")
            self.assertEqual(row["accuracy_trials"], "1")
            self.assertEqual(row["total_ms"], "0.000")
            if row["method"] == "baseline":
                self.assert_baseline_is_diagnostic(row)
            else:
                self.assertEqual(row["profile_id"], "std128-t40-primary")
                self.assertEqual(row["comparison_eligible"], "true")
                self.assertEqual(row["measurement_kind"], "fhe-accuracy")

    def test_combined_mode_emits_distinct_timing_and_accuracy_rows(self):
        rows = self.run_fixture("combined")
        self.assertEqual(len(rows), 12)
        for universe in ("16384", "65536"):
            universe_rows = [
                row for row in rows if row["universe_size"] == universe
            ]
            self.assertEqual(len(universe_rows), 6)
            for method in ("piccard", "piccard_sqrt", "baseline"):
                method_rows = [
                    row for row in universe_rows if row["method"] == method
                ]
                self.assertEqual(len(method_rows), 2)
                self.assert_workload_provenance(method_rows[0])
                self.assert_workload_provenance(method_rows[1])
                if method == "baseline":
                    for row in method_rows:
                        self.assert_baseline_is_diagnostic(row)
                else:
                    self.assertEqual(
                        [row["measurement_kind"] for row in method_rows],
                        ["fhe-timing", "fhe-accuracy"],
                    )
                self.assertEqual(
                    [(row["trials"], row["accuracy_trials"])
                     for row in method_rows],
                    [("1", "0"), ("0", "1")],
                )

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
            self.assertEqual(row["universe_size"], "64")
            self.assertEqual(row["set_size"], "16")
            self.assertEqual(row["target_jaccard"], "0.500000")
            self.assertEqual(row["realized_intersection"], "11")
            self.assertEqual(row["realized_union"], "21")
            self.assertEqual(row["realized_jaccard"], "0.523810")
        for row in rows:
            if row["method"] == "baseline":
                self.assert_baseline_is_diagnostic(row)

    def test_toy_timing_mode_does_not_require_accuracy_trials(self):
        rows = self.run_actual_toy_point("timing", accuracy_trials=0)
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            [row["measurement_kind"] for row in rows],
            ["fhe-timing", "fhe-timing", "diagnostic"],
        )
        for row in rows:
            self.assertEqual(row["trials"], "1")
            self.assertEqual(row["accuracy_trials"], "0")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
