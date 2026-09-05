#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts import summarize_deletion_survival as summ  # noqa: E402
from scripts import revision_benchmark_common as common  # noqa: E402

HEADER = ("model,n,d,k,required_survival,r,exact_survival,union_bound_survival,"
          "mc_survival,mc_standard_error,maximum_safe_deletions,"
          "exact_expected_first_failure,exact_expected_safe_deletions,"
          "mc_mean_first_failure,mc_mean_safe_deletions,trials,seed")
GRID = list(range(0, 521, 20))


def fake_rows(mc: bool) -> str:
    lines = [HEADER]
    for r in GRID:
        exact = summ.exact_survival(1024, 5, 128, r)
        mc_value = exact if mc else 0.0
        se = math.sqrt(mc_value * (1 - mc_value) / 100000) if mc else 0.0
        lines.append(",".join([
            "ideal-independent-random-ranking-v1", "1024", "5", "128", "0.99", str(r),
            repr(exact), "0", repr(mc_value), repr(se), "156",
            "357.74523193297700", "356.74523193297700",
            "357.6" if mc else "0", "356.6" if mc else "0",
            "100000" if mc else "0", "20260729"]))
    return "\n".join(lines) + "\n"


def write_cell(root: Path, cell_id: str, text: str, *, provenance_id: str = "abc",
               stdout_sha256: str | None = None) -> None:
    """Write one cell's stdout.log plus a receipt whose digest matches it, so a
    mutation test exercises the gate it means to and not the digest gate."""
    out = root / "cells" / common.slug(cell_id)
    out.mkdir(parents=True, exist_ok=True)
    (out / "stdout.log").write_text(text)
    digest = hashlib.sha256((out / "stdout.log").read_bytes()).hexdigest()
    (out / "receipt.json").write_text(json.dumps({
        "cell_id": cell_id, "execution_status": "COMPLETED", "provenance_id": provenance_id,
        "stdout_sha256": stdout_sha256 if stdout_sha256 is not None else digest}))


def read_manifest(root: Path) -> dict:
    return json.loads((root / "run.json").read_text())


def write_manifest(root: Path, manifest: dict) -> None:
    (root / "run.json").write_text(json.dumps(manifest))


def mutate_both_cells(root: Path, transform) -> None:
    """Apply ``transform`` to each cell's data rows (header excluded) and rewrite
    the cell, receipt digest included."""
    for cell_id in (summ.EXACT_ID, summ.MC_ID):
        lines = (root / "cells" / common.slug(cell_id) / "stdout.log").read_text().rstrip("\n").split("\n")
        write_cell(root, cell_id, "\n".join([lines[0]] + list(transform(lines[1:]))) + "\n")


def fake_root(tmp: Path) -> Path:
    root = tmp / "results"
    matrix = ROOT / "benchmarks" / "revision_matrix.json"
    (root).mkdir()
    (root / "matrix.json").write_bytes(matrix.read_bytes())
    sha = hashlib.sha256(matrix.read_bytes()).hexdigest()
    cells = []
    for cid, mc in ((summ.EXACT_ID, False), (summ.MC_ID, True)):
        write_cell(root, cid, fake_rows(mc))
        cells.append({"cell_id": cid, "execution_status": "COMPLETED", "provenance_id": "abc"})
    write_manifest(root, {
        "schema": "piccard-deletion-survival-run-v1", "state": "COMPLETED",
        "cell_ids": [c["cell_id"] for c in cells], "cells": cells, "provenance_id": "abc",
        "provenance": {"matrix_sha256": sha, "seed": 20260729}})
    return root


class ExactFormulaTest(unittest.TestCase):
    def test_matches_manuscript_values(self) -> None:
        self.assertAlmostEqual(summ.exact_survival(1024, 5, 128, 156), 0.990107, places=6)
        self.assertAlmostEqual(summ.exact_survival(1024, 5, 128, 157), 0.989783, places=6)
        self.assertEqual(summ.exact_survival(1024, 5, 128, 0), 1.0)
        self.assertAlmostEqual(summ.exact_survival(1024, 5, 128, 520), 0.0128, places=4)


class SummarizeTest(unittest.TestCase):
    def test_end_to_end_on_a_fake_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            result = summ.summarize(root)
            self.assertEqual(result["schema"], "piccard-deletion-survival-summary-v1")
            self.assertEqual(result["config"], {"n": 1024, "d": 5, "k": 128, "required_survival": "0.99"})
            self.assertEqual(result["trials"], 100000)
            self.assertEqual(result["exact"]["maximum_safe_deletions"], 156)
            self.assertAlmostEqual(result["exact"]["expected_first_failure"], 357.745, places=3)
            self.assertAlmostEqual(result["exact"]["S_156"], 0.990107, places=6)
            self.assertEqual(len(result["points"]), 27)
            self.assertEqual(sum(p["figure_marker"] for p in result["points"]), 14)
            self.assertEqual(result["monte_carlo"]["mean_first_failure"], 357.6)
            self.assertEqual(result["max_abs_z_at_markers"], 0.0)
            tex = summ.render_coordinates(result["points"], trials=result["trials"],
                                          seed=result["seed"])
            self.assertIn("% Monte-Carlo, 100000 runs, seed 20260729\n", tex)
            self.assertIn("(0,1.0000) (20,1.0000) (40,1.0000)", tex)
            self.assertIn("(520,0.0128)", tex)
            self.assertEqual(tex.count("\\addplot"), 2)
            # marker block lists only the 14 multiples of 40
            marker_block = tex.split("\\addplot")[2]
            self.assertNotIn("(20,", marker_block)
            self.assertIn("(40,", marker_block)

    def test_refuses_incomplete_run_or_matrix_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            manifest = json.loads((root / "run.json").read_text())
            manifest["state"] = "FAILED"
            (root / "run.json").write_text(json.dumps(manifest))
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            (root / "matrix.json").write_bytes((root / "matrix.json").read_bytes() + b"\n")
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_exact_columns_must_agree_between_the_two_cells(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            path = root / "cells" / common.slug(summ.EXACT_ID) / "stdout.log"
            write_cell(root, summ.EXACT_ID, path.read_text().replace(",156,", ",155,", 1))
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)


class GateTest(unittest.TestCase):
    """Each mutation is a run the figure must not be drawn from."""

    def test_refuses_a_truncated_grid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            mutate_both_cells(root, lambda rows: rows[:-1])
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_reordered_rows(self) -> None:
        def swap(rows: list[str]) -> list[str]:
            rows = list(rows)
            rows[1], rows[2] = rows[2], rows[1]
            return rows

        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            mutate_both_cells(root, swap)
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_a_seed_other_than_the_pinned_one(self) -> None:
        # Self-consistent but not the manuscript's seed: still refused.
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            mutate_both_cells(root, lambda rows: [r[: -len("20260729")] + "7" for r in rows])
            manifest = read_manifest(root)
            manifest["provenance"]["seed"] = 7
            write_manifest(root, manifest)
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_a_csv_seed_that_disagrees_with_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            mutate_both_cells(root, lambda rows: [r[: -len("20260729")] + "7" for r in rows])
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_a_manifest_seed_that_disagrees_with_the_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            manifest = read_manifest(root)
            manifest["provenance"]["seed"] = 7
            write_manifest(root, manifest)
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_a_mixed_provenance_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            manifest = read_manifest(root)
            manifest["mixed_provenance"] = True
            manifest["provenance_cells"] = {"abc": [summ.EXACT_ID], "def": [summ.MC_ID]}
            write_manifest(root, manifest)
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_a_cell_whose_provenance_id_differs_from_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            write_cell(root, summ.MC_ID, fake_rows(True), provenance_id="def")
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_a_receipt_whose_stdout_digest_is_wrong(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            write_cell(root, summ.MC_ID, fake_rows(True), stdout_sha256="0" * 64)
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)

    def test_refuses_a_matrix_that_is_not_the_committed_one(self) -> None:
        # Archive and manifest agree with each other, but not with the matrix
        # digest the committed argv contract was built against.
        with tempfile.TemporaryDirectory() as tmp:
            root = fake_root(Path(tmp))
            (root / "matrix.json").write_bytes((root / "matrix.json").read_bytes() + b"\n")
            manifest = read_manifest(root)
            manifest["provenance"]["matrix_sha256"] = hashlib.sha256(
                (root / "matrix.json").read_bytes()).hexdigest()
            write_manifest(root, manifest)
            with self.assertRaises(summ.SummaryError):
                summ.summarize(root)


if __name__ == "__main__":
    unittest.main()
