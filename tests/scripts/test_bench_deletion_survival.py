#!/usr/bin/env python3
import csv
import io
import subprocess
import sys
import unittest


BENCH = sys.argv[1]
HEADER = [
    "model", "n", "d", "k", "required_survival", "r", "exact_survival",
    "union_bound_survival", "mc_survival", "mc_standard_error",
    "maximum_safe_deletions", "exact_expected_first_failure",
    "exact_expected_safe_deletions", "mc_mean_first_failure",
    "mc_mean_safe_deletions", "trials", "seed",
]


class BenchDeletionSurvivalTest(unittest.TestCase):
    def test_one_trial_csv_schema_and_summary(self):
        completed = subprocess.run(
            [BENCH, "--n=64", "--d=3", "--k=8", "--required_survival=0.99",
             "--r_values=1,4,8", "--trials=1", "--seed=7"],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        reader = csv.DictReader(io.StringIO(completed.stdout))
        self.assertEqual(reader.fieldnames, HEADER)
        rows = list(reader)
        self.assertEqual(len(rows), 3)
        summaries = set()
        for row in rows:
            self.assertEqual(row["model"], "ideal-independent-random-ranking-v1")
            self.assertEqual(row["required_survival"], "0.99")
            self.assertEqual(row["trials"], "1")
            self.assertEqual(row["seed"], "7")
            self.assertIn(row["mc_survival"], {"0", "1"})
            summaries.add(tuple(row[column] for column in [
                "maximum_safe_deletions", "exact_expected_first_failure",
                "exact_expected_safe_deletions", "mc_mean_first_failure",
                "mc_mean_safe_deletions", "trials", "seed",
            ]))
        self.assertEqual(len(summaries), 1)

    def test_revision_cell_d5_toy_emits_the_full_r_grid(self):
        grid = ",".join(str(r) for r in range(0, 521, 20))
        completed = subprocess.run(
            [BENCH, "--revision-cell=paper-v1::deletion_mc::d=5",
             "--profile=readiness-toy-v1", "--cell=monte-carlo", "--k=128", "--m=64",
             "--d=5", "--set_size=1024", "--universe=65536", f"--r_values={grid}",
             "--trials=1", "--seed=20260729"],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        reader = csv.DictReader(io.StringIO(completed.stdout))
        self.assertEqual(reader.fieldnames, HEADER)
        rows = list(reader)
        self.assertEqual([row["r"] for row in rows], [str(r) for r in range(0, 521, 20)])
        for row in rows:
            self.assertEqual(row["n"], "1024")
            self.assertEqual(row["d"], "5")
            self.assertEqual(row["k"], "128")
            self.assertEqual(row["trials"], "1")
            self.assertEqual(row["maximum_safe_deletions"], "156")
        self.assertAlmostEqual(float(rows[0]["exact_expected_first_failure"]), 357.745, places=2)
        # r=520 for (1024,5,128): exact survival 0.01285
        self.assertAlmostEqual(float(rows[-1]["exact_survival"]), 0.01285, places=4)

    def test_revision_cell_control_argv_is_unchanged(self):
        completed = subprocess.run(
            [BENCH, "--revision-cell=paper-v1::deletion_mc::control=default",
             "--profile=readiness-toy-v1", "--cell=monte-carlo", "--k=128", "--m=64",
             "--set_size=1000", "--universe=65536", "--trials=1", "--seed=20260729"],
            capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rows = list(csv.DictReader(io.StringIO(completed.stdout)))
        self.assertEqual([row["r"] for row in rows], ["1", "4", "8"])
        self.assertEqual(rows[0]["n"], "1000")
        self.assertEqual(rows[0]["d"], "64")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
