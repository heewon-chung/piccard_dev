from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_revision_benchmarks.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"


class RevisionRunnerContractTest(unittest.TestCase):
    def run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(RUNNER), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_dry_run_requires_absolute_results_root_and_never_spawns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=dry-run",
                "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "dry"),
                "--seed", "20260729",
                "--threads", "2",
                "--matrix", str(MATRIX),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            root = Path(temporary) / "dry"
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["mode"], "dry-run")
            self.assertEqual(manifest["spawned_processes"], 0)
            self.assertEqual(manifest["cell_count"], 263)

    def test_paper_requires_explicit_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=paper",
                "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "paper"),
                "--seed", "20260729",
                "--threads", "2",
                "--matrix", str(MATRIX),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("authorize-paper-run", result.stderr)

    def test_results_root_must_be_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            results = Path(temporary) / "already-there"
            results.mkdir()
            result = self.run_runner(
                "--mode=dry-run",
                "--build-dir", str(build),
                "--results-root", str(results),
                "--seed", "1",
                "--threads", "1",
                "--matrix", str(MATRIX),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fresh", result.stderr.lower())

    def test_toy_selection_is_104_cells_and_excludes_raw_enron(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=toy",
                "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "toy"),
                "--seed", "20260729",
                "--threads", "2",
                "--matrix", str(MATRIX),
                "--no-exec",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            root = Path(temporary) / "toy"
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["cell_count"], 104)
            argv_text = (root / "planned_argv.jsonl").read_text()
            self.assertNotIn("maildir", argv_text)
            self.assertGreater(manifest["toy_measured_count"], 0)


if __name__ == "__main__":
    unittest.main()
