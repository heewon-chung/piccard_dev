#!/usr/bin/env python3
"""Executable boundary for the paper's 11-point threshold agreement sweep."""

from __future__ import annotations

import csv
import io
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = Path(sys.argv.pop()).resolve()
CELL_ID = "paper-v1::threshold_agreement::k=64"


class ThresholdRevisionAgreementCliTest(unittest.TestCase):
    def test_revision_cell_covers_all_eleven_overlap_points(self) -> None:
        command = [
            str(BENCHMARK),
            f"--revision-cell={CELL_ID}",
            "--profile=readiness-toy-v1",
            "--mode=accuracy",
            "--cell=agreement",
            "--security=TOY",
            "--k=64",
            "--m=64",
            "--set_size=1000",
            "--trials=1",
            "--seed=20260729",
        ]
        completed = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)

        rows = list(csv.DictReader(io.StringIO(completed.stdout)))
        expected_labels = [
            f"{CELL_ID}::overlap_index={index}::trial=0"
            for index in range(11)
        ]
        self.assertEqual([row["label"] for row in rows], expected_labels)
        self.assertTrue(all(row["k"] == "64" for row in rows))
        self.assertTrue(all(row["accuracy_trials"] == "1" for row in rows))
        self.assertTrue(all(row["fhe_agrees"] == "1" for row in rows))


if __name__ == "__main__":
    unittest.main()
