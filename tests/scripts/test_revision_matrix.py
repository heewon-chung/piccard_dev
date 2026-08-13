#!/usr/bin/env python3
"""Pure-Python contract tests for the canonical Phase 9 matrix."""

from __future__ import annotations

import copy
import pathlib
import unittest

from scripts import validate_revision_matrix


ROOT = pathlib.Path(__file__).resolve().parents[2]
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"
FIXTURES = ROOT / "tests" / "fixtures" / "revision_matrix"


class RevisionMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = validate_revision_matrix.load_document(MATRIX)
        validate_revision_matrix.validate_document(cls.document, FIXTURES)

    def test_exact_263_20_104_cardinalities_and_sorted_goldens(self):
        cells = self.document["cells"]
        self.assertEqual(len(cells), 263)
        ids = [cell["cell_id"] for cell in cells]
        self.assertEqual(ids, sorted(ids))
        paper = (FIXTURES / "paper_cell_ids.txt").read_text().splitlines()
        toy = (FIXTURES / "toy_cell_ids.txt").read_text().splitlines()
        executable = (FIXTURES / "executable_toy_cell_ids.txt").read_text().splitlines()
        self.assertEqual(ids, paper)
        self.assertEqual(len(toy), 20)
        self.assertEqual(len(executable), 104)
        self.assertEqual(executable, sorted(executable))

    def test_family_counts_and_required_contract_literals(self):
        counts = {}
        for cell in self.document["cells"]:
            counts[cell["family"]] = counts.get(cell["family"], 0) + 1
        self.assertEqual(counts, self.document["families"])
        self.assertEqual(counts["threshold_synthetic_fpfn"], 84)
        self.assertEqual(counts["real_dataset"], 12)

        sqrt = next(c for c in self.document["cells"]
                    if c["cell_id"] == "paper-v1::sqrt_comparison::timing_m=32")
        sqrt_row = next(r for r in sqrt["expected_rows"] if r["row_id"] == "sqrt")
        self.assertEqual(sqrt_row["status"], "NOT_APPLICABLE")
        self.assertEqual(sqrt_row["reason"], "sqrt-m-not-perfect-square")

        sj = next(c for c in self.document["cells"]
                  if c["cell_id"] == "paper-v1::sj16::u=262144")
        self.assertEqual(sj["invocation_status"], "NO_SPAWN")
        self.assertEqual(sj["expected_rows"][0]["status"], "EXTRAPOLATED")
        self.assertEqual(
            sj["expected_rows"][0]["reason"],
            "sj16-paillier3072-calibration-bound-v1")

    def test_duplicate_omitted_and_silent_rows_fail_closed(self):
        omitted = copy.deepcopy(self.document)
        omitted["cells"].pop()
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(omitted, FIXTURES)

        duplicate = copy.deepcopy(self.document)
        duplicate["cells"].append(copy.deepcopy(duplicate["cells"][0]))
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(duplicate, FIXTURES)

        silent = copy.deepcopy(self.document)
        silent["cells"][0]["expected_rows"] = []
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(silent, FIXTURES)

    def test_enron_has_no_threshold_cell_and_every_row_has_terminal_fields(self):
        for cell in self.document["cells"]:
            if cell["family"] == "real_dataset" and cell["axes"].get("variant", "").startswith("enron"):
                self.assertNotIn("threshold", cell["cell_id"])
            for row in cell["expected_rows"]:
                self.assertIn("row_id", row)
                self.assertIn("status", row)
                self.assertIn("reason", row)
                self.assertIn("measured_count", row)


if __name__ == "__main__":
    unittest.main()
