#!/usr/bin/env python3
"""Contract for the paper benchmark script surface."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"

EXPECTED_FILES = (
    "enron_preprocess.py",
    "make_calibration_archive.py",
    "make_calibration_table.py",
    "noise_profiles.json",
    "prepare_real_datasets.py",
    "revision_benchmark_common.py",
    "revision_flooding_adapter.py",
    "run_noise_profiles.sh",
    "run_revision_benchmarks.py",
    "seal_revision_benchmarks.py",
    "summarize_real_datasets.py",
    "templates/noise_calibration_wrapper.inc",
    "validate_revision_matrix.py",
    "verify_benchmark_provenance.py",
    "verify_real_dataset_outputs.py",
    "verify_review_comparison.py",
    "verify_revision_benchmarks.py",
    "verify_threshold_outputs.py",
)


class ScriptInventoryTest(unittest.TestCase):
    def test_only_canonical_paper_benchmark_scripts_are_shipped(self) -> None:
        actual = tuple(sorted(
            file_path.relative_to(SCRIPTS).as_posix()
            for file_path in SCRIPTS.rglob("*")
            if file_path.is_file()
            and "__pycache__" not in file_path.parts
            and file_path.suffix != ".pyc"
        ))
        self.assertEqual(actual, EXPECTED_FILES)


if __name__ == "__main__":
    unittest.main()
