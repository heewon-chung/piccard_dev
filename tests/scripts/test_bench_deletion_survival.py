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


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
