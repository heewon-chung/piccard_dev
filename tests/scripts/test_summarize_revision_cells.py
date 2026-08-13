"""Fail-closed tests for the one-cell real-data summary successor path.

The tests use a tiny in-memory-shaped accuracy CSV and never start a benchmark,
load OpenFHE, or touch the Enron source tree.  The frozen argv KAT in this file
is intentionally compared with the checked-in contract: the C++ invocation
planner remains the authority for the ordered producer argv.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "summarize_real_datasets.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"
CONTRACT = ROOT / "benchmarks" / "revision_summary_argv_contract.json"

sys.path.insert(0, str(ROOT))
from scripts import summarize_real_datasets as summarizer  # noqa: E402


SUMMARY_VARIANTS = (
    "dblp_acm_u65536",
    "enron_u1048576",
    "enron_u65536",
)


def _summary_id(variant: str) -> str:
    return f"paper-v1::real_dataset::{variant}_artifact=summary"


def _concrete_argv(cell_id: str, variant: str, root: Path) -> list[str]:
    return [
        f"--revision-cell={cell_id}",
        f"--accuracy-csv={root / 'accuracy.csv'}",
        f"--output={root / 'summary.csv'}",
        f"--variant={variant}",
    ]


def _accuracy_row(variant: str) -> list[str]:
    row = ["0"] * len(summarizer.ACCURACY_HEADER_FIELDS)
    indices = {name: index for index, name in
               enumerate(summarizer.ACCURACY_HEADER_FIELDS)}
    row[indices["dataset"]] = "dblp_acm" if variant.startswith("dblp") else "enron"
    row[indices["variant"]] = variant
    row[indices["exact_jaccard_bucketed"]] = "0.25"
    row[indices["abs_error"]] = "0.125"
    row[indices["record_a"]] = "a"
    row[indices["record_b"]] = "b"
    row[indices["set_size_a_raw"]] = "2"
    row[indices["set_size_b_raw"]] = "2"
    row[indices["set_size_a_bucketed"]] = "2"
    row[indices["set_size_b_bucketed"]] = "2"
    return row


def _write_accuracy(path: Path, variant: str) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(summarizer.ACCURACY_HEADER_FIELDS)
        writer.writerow(_accuracy_row(variant))


class SummarizeRevisionCellsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = summarizer.load_revision_matrix(MATRIX)
        cls.contract = summarizer.load_revision_summary_contract(CONTRACT)

    def test_contract_is_exact_three_cell_kat_and_matches_matrix_bytes(self):
        expected_ids = {_summary_id(variant) for variant in SUMMARY_VARIANTS}
        self.assertEqual(
            {entry["cell_id"] for entry in self.contract["cells"]},
            expected_ids,
        )
        self.assertEqual(
            hashlib.sha256(MATRIX.read_bytes()).hexdigest(),
            self.contract["matrix_sha256"],
        )
        for variant in SUMMARY_VARIANTS:
            cell_id = _summary_id(variant)
            entry = next(item for item in self.contract["cells"]
                         if item["cell_id"] == cell_id)
            self.assertEqual(
                entry["argv"],
                [
                    f"--revision-cell={cell_id}",
                    "--accuracy-csv={output}/accuracy.csv",
                    "--output={output}/summary.csv",
                    f"--variant={variant}",
                ],
            )

    def test_all_three_cells_select_one_summary_plan_without_fanout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for variant in SUMMARY_VARIANTS:
                cell_id = _summary_id(variant)
                request = summarizer.parse_revision_summary_args(
                    _concrete_argv(cell_id, variant, root))
                selected = summarizer.select_revision_summary_cell(
                    self.matrix, self.contract, request)
                self.assertEqual(selected["cell"]["cell_id"], cell_id)
                self.assertEqual(selected["variant"], variant)
                self.assertEqual(selected["artifact"], "summary")
                self.assertEqual(selected["selected_cell_count"], 1)
                self.assertEqual(selected["artifact_count"], 1)
                self.assertEqual(selected["terminal_count"], 1)
                self.assertEqual(selected["canonical_argv"], [
                    f"--revision-cell={cell_id}",
                    "--accuracy-csv={output}/accuracy.csv",
                    "--output={output}/summary.csv",
                    f"--variant={variant}",
                ])

    def test_successor_cli_writes_one_bound_summary_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            variant = "dblp_acm_u65536"
            accuracy = root / "accuracy.csv"
            output = root / "summary.csv"
            _write_accuracy(accuracy, variant)
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT),
                    *_concrete_argv(_summary_id(variant), variant, root),
                ], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertTrue(output.is_file())
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["accuracy.csv", "summary.csv"],
            )
            with output.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[0], list(summarizer.SUMMARY_HEADER_FIELDS))
            self.assertEqual(len(rows), 5)  # header + the four frozen buckets
            self.assertTrue(all(row[1] == variant for row in rows[1:]))

    def test_legacy_input_output_cli_remains_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            accuracy = root / "legacy.csv"
            output = root / "legacy-summary.csv"
            _write_accuracy(accuracy, "dblp_acm_u65536")
            result = subprocess.run(
                [sys.executable, str(SCRIPT),
                 f"--input={accuracy}", f"--output={output}"],
                cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

    def test_parser_rejects_unknown_duplicate_missing_and_legacy_mixing(self):
        variant = "dblp_acm_u65536"
        cell_id = _summary_id(variant)
        good = _concrete_argv(cell_id, variant, Path("/tmp/out"))
        mutations = [
            good + ["--unknown=1"],
            good + [good[0]],
            good[:-1],
            ["--input=/tmp/accuracy.csv", *good],
        ]
        for argv in mutations:
            with self.subTest(argv=argv):
                with self.assertRaises(summarizer.RevisionSummaryError):
                    summarizer.parse_revision_summary_args(argv)

    def test_selection_rejects_unknown_cell_variant_path_drift_and_contract_drift(self):
        variant = "dblp_acm_u65536"
        cell_id = _summary_id(variant)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            good = _concrete_argv(cell_id, variant, root)

            unknown = _concrete_argv(
                "paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy",
                variant, root)
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    self.matrix, self.contract,
                    summarizer.parse_revision_summary_args(unknown))

            wrong_variant = _concrete_argv(cell_id, "enron_u65536", root)
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    self.matrix, self.contract,
                    summarizer.parse_revision_summary_args(wrong_variant))

            wrong_input = list(good)
            wrong_input[1] = f"--accuracy-csv={root / 'wrong.csv'}"
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    self.matrix, self.contract,
                    summarizer.parse_revision_summary_args(wrong_input))

            wrong_output = list(good)
            wrong_output[2] = f"--output={root / 'summary-enron.csv'}"
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    self.matrix, self.contract,
                    summarizer.parse_revision_summary_args(wrong_output))

            drifted = copy.deepcopy(self.contract)
            drifted["cells"][0]["argv"] = list(drifted["cells"][0]["argv"])
            drifted["cells"][0]["argv"][1] = "--accuracy-csv={output}/drift.csv"
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    self.matrix, drifted,
                    summarizer.parse_revision_summary_args(good))

            duplicate = copy.deepcopy(self.contract)
            duplicate["cells"].append(copy.deepcopy(duplicate["cells"][0]))
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    self.matrix, duplicate,
                    summarizer.parse_revision_summary_args(good))

            unknown = copy.deepcopy(self.contract)
            unknown["cells"][0]["cell_id"] = (
                "paper-v1::real_dataset::unknown_u65536_artifact=summary")
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    self.matrix, unknown,
                    summarizer.parse_revision_summary_args(good))

            mutated_matrix = copy.deepcopy(self.matrix)
            mutated_matrix["cells"][0]["producer"] = "unknown-producer"
            with self.assertRaises(summarizer.RevisionSummaryError):
                summarizer.select_revision_summary_cell(
                    mutated_matrix, self.contract,
                    summarizer.parse_revision_summary_args(good))

    def test_successor_requires_existing_input_and_matching_input_identity(self):
        variant = "dblp_acm_u65536"
        cell_id = _summary_id(variant)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "summary.csv"
            missing = subprocess.run(
                [sys.executable, str(SCRIPT),
                 *_concrete_argv(cell_id, variant, root)],
                cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(missing.returncode, 0)
            self.assertFalse(output.exists())

            accuracy = root / "accuracy.csv"
            _write_accuracy(accuracy, "enron_u65536")
            mismatch = subprocess.run(
                [sys.executable, str(SCRIPT),
                 *_concrete_argv(cell_id, variant, root)],
                cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
