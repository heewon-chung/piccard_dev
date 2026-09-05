#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts import run_deletion_survival as sweep  # noqa: E402
from scripts import revision_benchmark_common as common  # noqa: E402

RUNNER = ROOT / "scripts" / "run_deletion_survival.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"
GRID = ",".join(str(r) for r in range(0, 521, 20))


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(RUNNER), *args], cwd=ROOT,
                          capture_output=True, text=True)


def make_stub_build(tmp: Path, exit_code: int = 0) -> Path:
    build = tmp / "build"
    build.mkdir()
    stub = build / "bench_deletion_survival"
    stub.write_text(f"#!/bin/sh\necho stub \"$@\"\nexit {exit_code}\n")
    stub.chmod(0o755)
    return build


class CellListTest(unittest.TestCase):
    def test_exactly_the_two_d5_cells_in_exact_then_mc_order(self) -> None:
        self.assertEqual(sweep.DELETION_CELL_IDS,
                         ("paper-v1::deletion_exact::d=5", "paper-v1::deletion_mc::d=5"))
        document, _ = common.load_matrix(MATRIX)
        by_id = {c["cell_id"]: c for c in document["cells"]}
        for cid in sweep.DELETION_CELL_IDS:
            self.assertEqual(by_id[cid]["invocation_status"], "RUN")

    def test_plan_uses_paper_argv_and_single_thread_env(self) -> None:
        document, _ = common.load_matrix(MATRIX)
        plans = sweep.plan(document, Path("/b"), Path("/r"), seed=20260729, threads=1)
        self.assertEqual([p["cell_id"] for p in plans], list(sweep.DELETION_CELL_IDS))
        mc = plans[1]
        self.assertEqual(mc["command"][0], "/b/bench_deletion_survival")
        self.assertIn("--trials=100000", mc["argv"])
        self.assertIn("--d=5", mc["argv"])
        self.assertIn(f"--r_values={GRID}", mc["argv"])
        self.assertIn("--seed=20260729", mc["argv"])
        self.assertIn("--trials=0", plans[0]["argv"])
        self.assertEqual(mc["env"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1",
                                     "PICCARD_REVISION_CELL": mc["cell_id"],
                                     "PICCARD_REVISION_MODE": "paper"})
        self.assertEqual(mc["timeout_seconds"], 600)
        self.assertEqual(mc["schema"], "piccard-deletion-survival-cell-v1")

    def test_matches_orchestrator_command(self) -> None:
        from run_revision_benchmarks import _materialized_command
        document, _ = common.load_matrix(MATRIX)
        by_id = {c["cell_id"]: c for c in document["cells"]}
        with tempfile.TemporaryDirectory() as tmp:
            root, build = Path(tmp) / "r", Path(tmp) / "b"
            plans = {p["cell_id"]: p for p in sweep.plan(document, build, root, seed=20260729, threads=1)}
            for cid in sweep.DELETION_CELL_IDS:
                _, command = _materialized_command(by_id[cid], "paper", root=root, build_dir=build,
                                                   seed=20260729, threads=1,
                                                   variant_manifests=None, dblp_manifest=None)
                self.assertEqual(command, plans[cid]["command"], cid)


class DryRunTest(unittest.TestCase):
    def test_dry_run_writes_two_plans_and_spawns_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            r = run("--mode=dry-run", "--build-dir=/nonexistent", f"--results-root={root}")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len((root / "planned_argv.jsonl").read_text().splitlines()), 2)
            self.assertFalse((root / "cells").exists())

    def test_run_mode_refuses_relative_root(self) -> None:
        r = run("--mode=run", "--build-dir=/x", "--results-root=rel/dir")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("absolute", r.stderr)


class RunModeTest(unittest.TestCase):
    def test_run_writes_receipts_manifest_and_matrix_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = make_stub_build(t)
            root = t / "results"
            r = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r.returncode, 0, r.stderr)
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["schema"], "piccard-deletion-survival-run-v1")
            self.assertEqual(manifest["state"], "COMPLETED")
            self.assertEqual([c["cell_id"] for c in manifest["cells"]], list(sweep.DELETION_CELL_IDS))
            self.assertEqual(manifest["provenance"]["threads"], 1)
            self.assertEqual(manifest["provenance"]["seed"], 20260729)
            archive = root / "matrix.json"
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                             manifest["provenance"]["matrix_sha256"])
            receipt = json.loads((root / "cells" / common.slug(sweep.DELETION_CELL_IDS[1]) / "receipt.json").read_text())
            self.assertEqual(receipt["execution_status"], "COMPLETED")
            self.assertEqual(receipt["schema"], "piccard-deletion-survival-cell-v1")
            self.assertIn("--trials=100000", receipt["argv"])

    def test_failed_cell_marks_run_failed_and_resume_reruns_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = make_stub_build(t)
            flag = t / "fail_once"
            flag.write_text("")
            (build / "bench_deletion_survival").write_text(
                f"#!/bin/sh\nif [ -e {flag} ]; then exit 3; fi\nexit 0\n")
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 1, r1.stderr)
            self.assertEqual(json.loads((root / "run.json").read_text())["state"], "FAILED")
            flag.unlink()
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("ran 2, skipped 0", r2.stdout)
            self.assertEqual(json.loads((root / "run.json").read_text())["state"], "COMPLETED")

    def test_resume_refuses_changed_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = make_stub_build(t)
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            (build / "bench_deletion_survival").write_text("#!/bin/sh\necho changed\nexit 0\n")
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertNotEqual(r2.returncode, 0)
            self.assertIn("provenance", r2.stderr)
            self.assertIn("bench_deletion_survival", r2.stderr)


if __name__ == "__main__":
    unittest.main()
