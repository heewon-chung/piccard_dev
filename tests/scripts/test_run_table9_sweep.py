from __future__ import annotations

import json
import os
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
    # The exact ordered 42-cell grid (cheap producers first, SJ16 last; see
    # run_table9_sweep.py's module docstring). Family counts and exclusion
    # lists alone let a wrong id silently replace a required one (e.g. an
    # existing k=32 cell swapped in for a required k=64 cell keeps every
    # count and exclusion true) -- pinning the literal sequence is the only
    # check that catches that substitution.
    EXPECTED_TABLE9_CELL_IDS: tuple[str, ...] = (
        "paper-v1::piccard_std128::u=16384",
        "paper-v1::piccard_std128::u=65536",
        "paper-v1::piccard_std128::u=262144",
        "paper-v1::piccard_std128::u=1048576",
        "paper-v1::piccard_std128::n=100",
        "paper-v1::piccard_std128::n=10000",
        "paper-v1::piccard_std128::k=16",
        "paper-v1::piccard_std128::k=64",
        "paper-v1::piccard_std128::k=256",
        "paper-v1::piccard_std128::k=512",
        "paper-v1::piccard_std128::m=16",
        "paper-v1::piccard_std128::m=128",
        "paper-v1::piccard_std128::m=256",
        "paper-v1::sqrt_comparison::timing_u=16384",
        "paper-v1::sqrt_comparison::timing_u=65536",
        "paper-v1::sqrt_comparison::timing_u=262144",
        "paper-v1::sqrt_comparison::timing_u=1048576",
        "paper-v1::sqrt_comparison::timing_n=100",
        "paper-v1::sqrt_comparison::timing_n=10000",
        "paper-v1::sqrt_comparison::timing_k=16",
        "paper-v1::sqrt_comparison::timing_k=64",
        "paper-v1::sqrt_comparison::timing_k=256",
        "paper-v1::sqrt_comparison::timing_k=512",
        "paper-v1::sqrt_comparison::timing_m=16",
        "paper-v1::sqrt_comparison::timing_m=256",
        "paper-v1::bcg12_minhash::u=65536",
        "paper-v1::bcg12_minhash::n=100",
        "paper-v1::bcg12_minhash::n=10000",
        "paper-v1::bcg12_minhash::k=16",
        "paper-v1::bcg12_minhash::k=64",
        "paper-v1::bcg12_minhash::k=256",
        "paper-v1::bcg12_minhash::k=512",
        "paper-v1::fhe_ind::u=16384",
        "paper-v1::fhe_ind::u=65536",
        "paper-v1::fhe_ind::u=262144",
        "paper-v1::fhe_ind::u=1048576",
        "paper-v1::fhe_ind::n=100",
        "paper-v1::fhe_ind::n=10000",
        "paper-v1::sj16::u=16384",
        "paper-v1::sj16::u=65536",
        "paper-v1::sj16::n=100",
        "paper-v1::sj16::n=10000",
    )

    def test_42_ids_exist_in_matrix_and_are_run_cells(self) -> None:
        document, _ = common.load_matrix(MATRIX)
        by_id = {c["cell_id"]: c for c in document["cells"]}
        self.assertEqual(len(sweep.TABLE9_CELL_IDS), 42)
        self.assertEqual(len(set(sweep.TABLE9_CELL_IDS)), 42)
        self.assertEqual(sweep.TABLE9_CELL_IDS, self.EXPECTED_TABLE9_CELL_IDS)
        for cid in sweep.TABLE9_CELL_IDS:
            self.assertIn(cid, by_id, cid)
            self.assertEqual(by_id[cid]["invocation_status"], "RUN", cid)
        families = [by_id[c]["family"] for c in sweep.TABLE9_CELL_IDS]
        self.assertEqual(families.count("piccard_std128"), 13)
        self.assertEqual(families.count("sqrt_comparison"), 12)
        self.assertEqual(families.count("bcg12_minhash"), 7)
        self.assertEqual(families.count("fhe_ind"), 6)
        self.assertEqual(families.count("sj16"), 4)
        # BCG12 consumes no |U| beyond its default point, and no m at all
        for excluded in ("paper-v1::bcg12_minhash::u=16384", "paper-v1::bcg12_minhash::u=262144",
                         "paper-v1::bcg12_minhash::u=1048576", "paper-v1::bcg12_minhash::m=16",
                         "paper-v1::bcg12_minhash::m=128", "paper-v1::bcg12_minhash::m=256"):
            self.assertNotIn(excluded, sweep.TABLE9_CELL_IDS, excluded)
        # SJ16 consumes no k or m, and its two large-|U| cells stay extrapolated (infeasible)
        for excluded in ("paper-v1::sj16::k=16", "paper-v1::sj16::k=64", "paper-v1::sj16::k=256",
                         "paper-v1::sj16::k=512", "paper-v1::sj16::m=16", "paper-v1::sj16::m=128",
                         "paper-v1::sj16::m=256", "paper-v1::sj16::u=262144", "paper-v1::sj16::u=1048576"):
            self.assertNotIn(excluded, sweep.TABLE9_CELL_IDS, excluded)
        self.assertEqual(sweep.TABLE9_CELL_IDS[-1], "paper-v1::sj16::n=10000")

    def test_materialized_argv_matches_orchestrator_conventions(self) -> None:
        document, _ = common.load_matrix(MATRIX)
        plans = sweep.plan(document, Path("/b"), Path("/r"), seed=20260729, threads=16)
        self.assertEqual(len(plans), 42)
        for p in plans:
            self.assertIn("--trials=30", p["argv"], p["cell_id"])
            self.assertIn(f"--revision-cell={p['cell_id']}", p["argv"])
            if p["family"] == "sj16":
                self.assertIn("--threads=16", p["argv"], p["cell_id"])
            # OMP_NUM_THREADS is the binding that matters for every family
            # (fhe_ind, bcg12, piccard, sqrt); --threads on the CLI is inert
            # for bench_review_comparison but is still emitted for sj16.
            self.assertEqual(p["env"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "16",
                                        "PICCARD_REVISION_CELL": p["cell_id"],
                                        "PICCARD_REVISION_MODE": "paper"})
            self.assertEqual(p["timeout_seconds"], {"standard": 600, "extended": 3600, "long": 64800}[p["timeout_class"]])

    def test_materialized_command_equals_orchestrator_command_for_every_family(self) -> None:
        # The checks above only spot-check a few flags in isolation, which
        # lets an unrelated argv divergence (a missing flag, a wrong value,
        # a different ordering) slip through undetected as long as the
        # spot-checked flags still happen to be present. Rebuild each
        # sampled cell's command through the orchestrator's own
        # _materialized_command (scripts/run_revision_benchmarks.py) --
        # same producer/root/build_dir/seed/threads inputs -- and require
        # the two full command lists to be identical, not merely overlapping.
        sys.path.insert(0, str(ROOT / "scripts"))
        from run_revision_benchmarks import _materialized_command

        document, _ = common.load_matrix(MATRIX)
        by_id = {c["cell_id"]: c for c in document["cells"]}
        # One representative cell from each of the five families the sweep covers.
        sample_ids = (
            "paper-v1::piccard_std128::u=16384",
            "paper-v1::sqrt_comparison::timing_u=16384",
            "paper-v1::bcg12_minhash::k=16",
            "paper-v1::fhe_ind::u=16384",
            "paper-v1::sj16::u=16384",
        )
        for cid in sample_ids:
            self.assertIn(cid, sweep.TABLE9_CELL_IDS, cid)
        self.assertEqual({by_id[cid]["family"] for cid in sample_ids},
                         {"piccard_std128", "sqrt_comparison", "bcg12_minhash", "fhe_ind", "sj16"})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "r"
            build_dir = Path(tmp) / "b"
            plans = sweep.plan(document, build_dir, root, seed=20260729, threads=16)
            plan_by_id = {p["cell_id"]: p for p in plans}
            for cid in sample_ids:
                _, orchestrator_command = _materialized_command(
                    by_id[cid], "paper", root=root, build_dir=build_dir,
                    seed=20260729, threads=16, variant_manifests=None, dblp_manifest=None)
                self.assertEqual(orchestrator_command, plan_by_id[cid]["command"], cid)


class DryRunTest(unittest.TestCase):
    def test_dry_run_writes_plan_and_spawns_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            r = run("--mode=dry-run", "--build-dir=/nonexistent", f"--results-root={root}")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len((root / "planned_argv.jsonl").read_text().splitlines()), 42)
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
            self.assertEqual(len(manifest["cells"]), 42)
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

    def test_failed_cell_retry_archives_the_old_directory(self) -> None:
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
            target_dir = root / "cells" / common.slug("paper-v1::fhe_ind::n=100")
            self.assertTrue((target_dir / "stdout.log").exists())          # a stale artifact is present
            flag.unlink()
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            archived = root / "cells" / (common.slug("paper-v1::fhe_ind::n=100") + ".attempt-1")
            self.assertTrue(archived.exists())
            self.assertTrue((archived / "stdout.log").exists())          # the failed attempt's evidence survives
            self.assertTrue(target_dir.exists())                          # fresh directory for the successful retry
            receipt = json.loads((target_dir / "receipt.json").read_text())
            self.assertEqual(receipt["execution_status"], "COMPLETED")
            events = [json.loads(l) for l in (root / "events.jsonl").read_text().splitlines()]
            retry_events = [e for e in events if e["event"] == "RETRY"]
            self.assertEqual(len(retry_events), 6)          # all 6 fhe_ind cells had a stale directory
            self.assertIn("paper-v1::fhe_ind::n=100", {e["cell_id"] for e in retry_events})
            # a cell that never ran before must not get an .attempt-0
            self.assertFalse((root / "cells" /
                              (common.slug("paper-v1::piccard_std128::u=16384") + ".attempt-0")).exists())

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
            self.assertIn("ran 6, skipped 36", r2.stdout)
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["state"], "COMPLETED")
            self.assertEqual(len(manifest["cells"]), 42)
            self.assertTrue(all(c["execution_status"] == "COMPLETED" for c in manifest["cells"]))
            events = [json.loads(l) for l in (root / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(e["event"] == "START" for e in events), 42 + 6)
            self.assertEqual(sum(e["event"] == "RESUME" for e in events), 1)
            r3 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty", "--threads=8")
            self.assertNotEqual(r3.returncode, 0)
            self.assertIn("provenance", r3.stderr)

    def test_provenance_change_names_the_differing_key_and_can_be_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t)
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            manifest_before = json.loads((root / "run.json").read_text())
            old_binary_sha = manifest_before["provenance"]["binaries"]["bench_piccard"]["sha256"]
            old_id = manifest_before["provenance_id"]
            (build / "bench_piccard").write_text("#!/bin/sh\necho changed\nexit 0\n")
            (build / "bench_piccard").chmod(0o755)
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertNotEqual(r2.returncode, 0)
            self.assertIn("provenance", r2.stderr)
            self.assertIn("bench_piccard", r2.stderr, r2.stderr)          # names the differing key
            r3 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty",
                     "--accept-provenance-change")
            self.assertEqual(r3.returncode, 0, r3.stderr)
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(len(manifest["provenance_history"]), 1)
            old_provenance = manifest["provenance_history"][0]["provenance"]
            self.assertEqual(old_provenance["binaries"]["bench_piccard"]["sha256"], old_binary_sha)
            self.assertNotEqual(manifest["provenance"]["binaries"]["bench_piccard"]["sha256"], old_binary_sha)
            # J-2: every cell's receipt still matched (nothing needed a re-run), but the
            # run's *current* provenance no longer matches what any cell was measured
            # under -- that must still be flagged, not silently presented as homogeneous.
            new_id = manifest["provenance_id"]
            self.assertNotEqual(new_id, old_id)
            self.assertTrue(manifest["mixed_provenance"])
            self.assertIn("MIXED PROVENANCE", r3.stdout)
            self.assertEqual(set(manifest["provenance_cells"][old_id]), {c["cell_id"] for c in manifest["cells"]})
            self.assertNotIn(new_id, manifest["provenance_cells"])

    def test_override_resume_attributes_provenance_per_cell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t)
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            manifest1 = json.loads((root / "run.json").read_text())
            old_id = manifest1["provenance_id"]
            old_planned_bytes = (root / "planned_argv.jsonl").read_bytes()
            target_cell = "paper-v1::fhe_ind::n=100"
            target_receipt = root / "cells" / common.slug(target_cell) / "receipt.json"
            target_receipt.unlink()          # force revalidation to re-run exactly this one cell
            (build / "bench_piccard").write_text("#!/bin/sh\necho changed\nexit 0\n")
            (build / "bench_piccard").chmod(0o755)          # binary bytes change -> provenance differs
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty",
                     "--accept-provenance-change")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("MIXED PROVENANCE: 2 ids", r2.stdout)
            manifest2 = json.loads((root / "run.json").read_text())
            new_id = manifest2["provenance_id"]
            self.assertNotEqual(new_id, old_id)
            self.assertEqual(len(manifest2["provenance_history"]), 1)
            self.assertEqual(manifest2["provenance_history"][0]["provenance_id"], old_id)
            by_id = {c["cell_id"]: c for c in manifest2["cells"]}
            self.assertEqual(len(by_id), 42)
            self.assertEqual(by_id[target_cell]["provenance_id"], new_id)
            for cid, record in by_id.items():
                if cid != target_cell:
                    self.assertEqual(record["provenance_id"], old_id, cid)
            self.assertEqual(json.loads(target_receipt.read_text())["provenance_id"], new_id)
            untouched_receipt = json.loads(
                (root / "cells" / common.slug("paper-v1::fhe_ind::u=16384") / "receipt.json").read_text())
            self.assertEqual(untouched_receipt["provenance_id"], old_id)
            self.assertTrue(manifest2["mixed_provenance"])
            self.assertEqual(set(manifest2["provenance_cells"][old_id]) | {target_cell}, set(by_id))
            self.assertEqual(manifest2["provenance_cells"][new_id], [target_cell])
            # The original plan is never overwritten under an accepted provenance change.
            self.assertEqual((root / "planned_argv.jsonl").read_bytes(), old_planned_bytes)
            self.assertTrue((root / f"planned_argv.{new_id}.jsonl").exists())

    def test_relative_build_dir_resolves_against_the_actual_invocation_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t)
            other_cwd = t / "elsewhere"
            other_cwd.mkdir()
            rel_build = os.path.relpath(build, other_cwd)          # e.g. "../build"; not reachable from ROOT
            root = t / "results"
            r = subprocess.run([sys.executable, str(RUNNER), "--mode=run", f"--build-dir={rel_build}",
                               f"--results-root={root}", "--allow-dirty"],
                              cwd=other_cwd, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            manifest = json.loads((root / "run.json").read_text())
            # provenance must bind the SAME absolute directory the command actually executes,
            # regardless of which relative path or cwd the operator invoked from.
            self.assertEqual(manifest["provenance"]["build_dir"], str(build.resolve()))
            self.assertTrue(all(c["execution_status"] == "COMPLETED" for c in manifest["cells"]))

    def test_corrupt_manifest_is_rebuilt_from_receipts_instead_of_raising(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t)
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            # simulate a crash mid-write: run.json is truncated to invalid JSON.
            (root / "run.json").write_text('{"schema": "piccard-table9-sweep-run-v1", "cells": [')
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r2.returncode, 0, r2.stderr)          # does not raise
            self.assertIn("rebuild", r2.stderr.lower())
            manifest = json.loads((root / "run.json").read_text())
            self.assertTrue(manifest.get("rebuilt_from_receipts"))
            self.assertEqual(len(manifest["cells"]), 42)
            self.assertTrue(all(c["execution_status"] == "COMPLETED" for c in manifest["cells"]))
            events = [json.loads(l) for l in (root / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(e["event"] == "REBUILD" for e in events), 1)

    def test_normal_resume_has_single_provenance_id(self) -> None:
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
            self.assertNotIn("MIXED PROVENANCE", r2.stdout)
            manifest = json.loads((root / "run.json").read_text())
            self.assertFalse(manifest.get("mixed_provenance", False))
            ids_seen = {c["provenance_id"] for c in manifest["cells"]}
            self.assertEqual(len(ids_seen), 1)
            self.assertEqual(manifest["provenance_id"], next(iter(ids_seen)))

    def test_resume_revalidates_missing_receipt_and_reruns_only_that_cell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t)
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            target = root / "cells" / common.slug("paper-v1::fhe_ind::n=100") / "receipt.json"
            target.unlink()
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("ran 1, skipped 41", r2.stdout)
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["state"], "COMPLETED")
            self.assertEqual(len(manifest["cells"]), 42)
            self.assertTrue(target.exists())
            events = [json.loads(l) for l in (root / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(e["event"] == "REVALIDATE" for e in events), 1)

    def test_resume_revalidates_receipt_reporting_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            build = self.make_stub_build(t)
            root = t / "results"
            r1 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r1.returncode, 0, r1.stderr)
            receipt_path = root / "cells" / common.slug("paper-v1::fhe_ind::n=100") / "receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["execution_status"] = "FAILED"
            receipt_path.write_text(json.dumps(receipt))
            r2 = run("--mode=run", f"--build-dir={build}", f"--results-root={root}", "--allow-dirty")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("ran 1, skipped 41", r2.stdout)
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["state"], "COMPLETED")
            self.assertTrue(all(c["execution_status"] == "COMPLETED" for c in manifest["cells"]))


if __name__ == "__main__":
    unittest.main()
