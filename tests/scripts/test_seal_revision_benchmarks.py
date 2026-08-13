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
SEAL = ROOT / "scripts" / "seal_revision_benchmarks.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"


class RevisionSealContractTest(unittest.TestCase):
    def test_seal_is_no_replace_and_records_readiness_status(self) -> None:
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
            verify = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run",
                 "--write-receipt"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            seal = subprocess.run(
                [sys.executable, str(SEAL), str(root)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(seal.returncode, 0, seal.stderr)
            payload = json.loads((root / "seal.json").read_text())
            self.assertEqual(payload["readiness_status"], "READINESS_ONLY")
            self.assertEqual(payload["performance_status"],
                             "PAPER_PERFORMANCE_PENDING")
            original = (root / "seal.json").read_bytes()
            second = subprocess.run(
                [sys.executable, str(SEAL), str(root)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(original, (root / "seal.json").read_bytes())

            before = {path.relative_to(root).as_posix(): path.read_bytes()
                      for path in root.rglob("*") if path.is_file()}
            post = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=post-seal"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(post.returncode, 0, post.stderr)
            after = {path.relative_to(root).as_posix(): path.read_bytes()
                     for path in root.rglob("*") if path.is_file()}
            self.assertEqual(before, after)
            (root / "post-seal-forgery.txt").write_text("forged\n")
            rejected = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=post-seal"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
