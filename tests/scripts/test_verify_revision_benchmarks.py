from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_revision_benchmarks.py"
VERIFIER = ROOT / "scripts" / "verify_revision_benchmarks.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"


class RevisionVerifierContractTest(unittest.TestCase):
    def test_verifier_rejects_changed_manifest_and_cell_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dry"
            build = Path(temporary) / "build"
            build.mkdir()
            run = subprocess.run(
                [sys.executable, str(RUNNER), "--mode=dry-run",
                 "--build-dir", str(build), "--results-root", str(root),
                 "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            manifest = root / "run.json"
            value = json.loads(manifest.read_text())
            value["cell_count"] = 262
            manifest.write_text(json.dumps(value, sort_keys=True) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_verifier_rejects_swapped_security_method(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dry"
            build = Path(temporary) / "build"
            build.mkdir()
            run = subprocess.run(
                [sys.executable, str(RUNNER), "--mode=dry-run",
                 "--build-dir", str(build), "--results-root", str(root),
                 "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            argv_file = root / "planned_argv.jsonl"
            lines = argv_file.read_text().splitlines()
            mutated = json.loads(lines[0])
            mutated["argv"].append("--security=STD192")
            lines[0] = json.dumps(mutated, sort_keys=True)
            argv_file.write_text("\n".join(lines) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)


if __name__ == "__main__":
    unittest.main()
