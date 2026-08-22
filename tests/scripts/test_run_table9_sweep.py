from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))   # revision_benchmark_common imports validate_revision_matrix top-level
from scripts import run_table9_sweep as sweep  # noqa: E402
from scripts import revision_benchmark_common as common  # noqa: E402

RUNNER = ROOT / "scripts" / "run_table9_sweep.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(RUNNER), *args], cwd=ROOT,
                          capture_output=True, text=True)


class CellListTest(unittest.TestCase):
    def test_57_ids_exist_in_matrix_and_are_run_cells(self) -> None:
        document, _ = common.load_matrix(MATRIX)
        by_id = {c["cell_id"]: c for c in document["cells"]}
        self.assertEqual(len(sweep.TABLE9_CELL_IDS), 57)
        self.assertEqual(len(set(sweep.TABLE9_CELL_IDS)), 57)
        for cid in sweep.TABLE9_CELL_IDS:
            self.assertIn(cid, by_id, cid)
            self.assertEqual(by_id[cid]["invocation_status"], "RUN", cid)
        families = [by_id[c]["family"] for c in sweep.TABLE9_CELL_IDS]
        self.assertEqual(families.count("piccard_std128"), 13)
        self.assertEqual(families.count("sqrt_comparison"), 12)
        self.assertEqual(families.count("bcg12_minhash"), 13)
        self.assertEqual(families.count("sj16"), 13)
        self.assertEqual(families.count("fhe_ind"), 6)
        self.assertTrue(all(f == "sj16" for f in families[-13:]))
        self.assertEqual(sweep.TABLE9_CELL_IDS[-1], "paper-v1::sj16::u=1048576")

    def test_materialized_argv_matches_orchestrator_conventions(self) -> None:
        document, _ = common.load_matrix(MATRIX)
        plans = sweep.plan(document, Path("/b"), Path("/r"), seed=20260729, threads=16)
        self.assertEqual(len(plans), 57)
        for p in plans:
            self.assertIn("--trials=30", p["argv"], p["cell_id"])
            self.assertIn(f"--revision-cell={p['cell_id']}", p["argv"])
            if p["family"] == "sj16":
                self.assertIn("--threads=16", p["argv"], p["cell_id"])
            self.assertEqual(p["env"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "16",
                                        "PICCARD_REVISION_CELL": p["cell_id"],
                                        "PICCARD_REVISION_MODE": "paper"})
            self.assertEqual(p["timeout_seconds"], {"standard": 600, "extended": 3600, "long": 64800}[p["timeout_class"]])


class DryRunTest(unittest.TestCase):
    def test_dry_run_writes_plan_and_spawns_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            r = run("--mode=dry-run", "--build-dir=/nonexistent", f"--results-root={root}")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len((root / "planned_argv.jsonl").read_text().splitlines()), 57)
            self.assertFalse((root / "cells").exists())
            self.assertFalse((root / "run.json").exists())

    def test_run_mode_refuses_relative_root(self) -> None:
        r = run("--mode=run", "--build-dir=/x", "--results-root=rel/dir")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("absolute", r.stderr)


class RunModeTest(unittest.TestCase):
    def make_stub_build(self, tmp: Path, failing: str | None = None) -> Path:
        build = tmp / "build"
        build.mkdir()
        for name in ("bench_piccard", "bench_onehot_sqrt", "bench_review_comparison", "bench_fhe_ind"):
            stub = build / name
            stub.write_text(f"#!/bin/sh\necho stub \"$@\"\nexit {3 if name == failing else 0}\n")
            stub.chmod(0o755)
        return build

    def test_run_writes_receipts_and_resume_reruns_only_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t, failing="bench_fhe_ind")
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 1, r1.stderr)
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["state"], "FAILED")
            self.assertTrue(manifest["dirty_allowed"])
            self.assertEqual(len(manifest["cells"]), 57)
            failed = [c for c in manifest["cells"] if c["execution_status"] != "COMPLETED"]
            self.assertEqual({c["family"] for c in failed}, {"fhe_ind"})
            self.assertEqual(len(failed), 6)
            self.assertEqual(len(manifest["provenance"]["binaries"]["bench_piccard"]["sha256"]), 64)
            receipt = json.loads((root / "cells" / common.slug("paper-v1::fhe_ind::n=100") / "receipt.json").read_text())
            self.assertEqual(receipt["execution_status"], "FAILED")
            self.assertEqual(receipt["exit_code"], 3)
            (build / "bench_fhe_ind").write_text("#!/bin/sh\nexit 0\n")
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertNotEqual(r2.returncode, 0)          # binary changed -> provenance refusal
            self.assertIn("provenance", r2.stderr)

    def test_resume_reruns_failed_cells_when_provenance_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t)
            flag = t / "fail_once"
            flag.write_text("")
            # fhe_ind fails while the flag file exists, succeeds after it is removed; binary bytes never change.
            (build / "bench_fhe_ind").write_text(f"#!/bin/sh\nif [ -e {flag} ]; then exit 3; fi\nexit 0\n")
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 1, r1.stderr)
            flag.unlink()
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("ran 6, skipped 51", r2.stdout)
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["state"], "COMPLETED")
            self.assertEqual(len(manifest["cells"]), 57)
            self.assertTrue(all(c["execution_status"] == "COMPLETED" for c in manifest["cells"]))
            events = [json.loads(l) for l in (root / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(e["event"] == "START" for e in events), 57 + 6)
            self.assertEqual(sum(e["event"] == "RESUME" for e in events), 1)
            r3 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty", "--threads=8")
            self.assertNotEqual(r3.returncode, 0)
            self.assertIn("provenance", r3.stderr)


if __name__ == "__main__":
    unittest.main()
