#!/usr/bin/env python3
"""Contract for resuming a crashed revision results root.

A resume is only useful if the root it produces is indistinguishable, to
independent verification, from a root that never crashed.  These tests pin the
three properties that make that true: resume refuses whenever the run's identity
or provenance moved, it accepts a cell as complete only by re-deriving that
cell's own evidence, and it leaves the event/phase streams in the exact shape
the verifier demands.
"""

from __future__ import annotations

import json
import shutil
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

sys.path.insert(0, str(ROOT / "scripts"))

from revision_benchmark_common import (  # noqa: E402
    PHASES,
    RevisionContractError,
    binary_metadata,
    canonical_json,
    file_inventory,
    load_matrix,
    phase_for_cell,
    select_cells,
    sha256_file,
    source_metadata,
    tool_metadata,
    write_json,
)
import run_revision_benchmarks as runner  # noqa: E402


class RevisionResumeContractTest(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(RUNNER), *args], cwd=ROOT,
                              text=True, capture_output=True)

    def dry_root(self, temporary: Path) -> tuple[Path, Path]:
        """Produce a real fresh dry-run root and its build directory."""
        build = temporary / "build"
        build.mkdir()
        root = temporary / "dry"
        result = self.run_runner(
            "--mode=dry-run", "--build-dir", str(build),
            "--results-root", str(root), "--seed", "20260729",
            "--threads", "2", "--matrix", str(MATRIX))
        self.assertEqual(result.returncode, 0, result.stderr)
        return root, build

    def miniature_root(self, temporary: Path) -> dict[str, object]:
        """Build a faithful miniature of a crashed executable results root.

        The canonical matrix is frozen at 275 cells, so a hermetic structural
        test cannot shrink it.  It can, however, drive the resume machinery over
        a subset of real matrix cells: ``_prepare_resume`` reasons only about
        the plans and cells it is handed, which is exactly what makes a
        four-cell miniature a faithful stand-in for a 275-cell crash.
        """
        document, matrix_sha = load_matrix(MATRIX)
        # The runner resolves both paths, and the verifier re-materializes argv
        # from the resolved values; on macOS /var and /private/var would
        # otherwise disagree.
        build = temporary / "build"
        build.mkdir()
        build = build.resolve()
        root = (temporary / "results")
        (root / "canonical").mkdir(parents=True)
        root = root.resolve()
        (root / "canonical" / "revision_matrix.json").write_bytes(
            MATRIX.read_bytes())

        cells = [cell for cell in select_cells(document, "toy")
                 if phase_for_cell(cell) == "synthetic"][:4]
        self.assertEqual(len(cells), 4)

        plans: list[dict[str, object]] = []
        for cell in cells:
            canonical, command = runner._materialized_command(
                cell, "toy", root=root, build_dir=build, seed=20260729,
                threads=2,
                variant_manifests={"dblp_acm_u65536": root / "manifest.tsv"},
                dblp_manifest=root / "manifest.tsv")
            plans.append({
                "schema": "piccard-revision-planned-cell-v1", "version": 1,
                "cell_id": cell["cell_id"], "family": cell["family"],
                "phase": phase_for_cell(cell), "producer": cell["producer"],
                "invocation_status": cell["invocation_status"],
                "expected_artifact_schema": cell["expected_artifact_schema"],
                "timeout_class": cell["timeout_class"],
                "expected_rows": cell["expected_rows"],
                "canonical_argv": canonical,
                "argv": (command[1:] if command and command[0] == sys.executable
                         else command),
                "command": command,
                "output_dir": str(runner.cell_output(root, cell["cell_id"])),
                "timeout_seconds": runner._timeout_seconds(cell["timeout_class"]),
            })

        # Three cells finished; the fourth crashed mid-flight, leaving a stale
        # artifact and a START event with no END -- the shape of a real crash.
        sequence = 0
        events: list[dict[str, object]] = []
        for index, (cell, plan) in enumerate(zip(cells, plans)):
            output = Path(plan["output_dir"])
            output.mkdir(parents=True, exist_ok=True)
            crashed = index == 3
            (output / "stdout.log").write_text(f"cell {index}\n", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            (output / "artifact.csv").write_text(
                "partial\n" if crashed else f"rows,{index}\n", encoding="utf-8")
            sequence += 1
            events.append({
                "schema": runner.EVENT_SCHEMA, "version": 1,
                "sequence": sequence, "event": "START", "time_ns": 1000 + sequence,
                "cell_id": cell["cell_id"], "argv": plan["command"],
                "stdout": f"cells/{output.name}/stdout.log",
                "stderr": f"cells/{output.name}/stderr.log",
            })
            if crashed:
                continue
            sequence += 1
            events.append({
                "schema": runner.EVENT_SCHEMA, "version": 1,
                "sequence": sequence, "event": "END", "time_ns": 2000 + sequence,
                "cell_id": cell["cell_id"], "exit_code": 0,
                "start_ns": 1000 * (index + 1), "end_ns": 1000 * (index + 1) + 500,
                "stdout_path": f"cells/{output.name}/stdout.log",
                "stderr_path": f"cells/{output.name}/stderr.log",
                "stdout_sha256": sha256_file(output / "stdout.log"),
                "stderr_sha256": sha256_file(output / "stderr.log"),
            })
            write_json(output / "receipt.json", {
                "schema": runner.CELL_SCHEMA, "version": 1,
                "cell_id": cell["cell_id"], "family": cell["family"],
                "producer": cell["producer"], "phase": plan["phase"],
                "invocation_status": cell["invocation_status"],
                "expected_artifact_schema": cell["expected_artifact_schema"],
                "timeout_class": plan["timeout_class"],
                "timeout_seconds": plan["timeout_seconds"],
                "expected_rows": cell["expected_rows"],
                "canonical_argv": plan["canonical_argv"], "argv": plan["argv"],
                "warmup_calls": 1, "mode": "toy",
                "execution_status": "COMPLETED", "exit_code": 0,
                "start_event_sequence": sequence - 1,
                "end_event_sequence": sequence,
                "stdout": {"path": f"cells/{output.name}/stdout.log",
                           "sha256": sha256_file(output / "stdout.log")},
                "stderr": {"path": f"cells/{output.name}/stderr.log",
                           "sha256": sha256_file(output / "stderr.log")},
                "artifact_inventory": file_inventory(
                    output, exclude={"stdout.log", "stderr.log", "receipt.json"}),
            })

        runner._write_jsonl(root / "events.jsonl", events)
        runner._write_jsonl(root / "planned_argv.jsonl", plans)
        runner._write_jsonl(root / "phases.jsonl", [
            {"schema": "piccard-revision-phase-v1", "phase": phase,
             "state": state, "reason": "", "index": PHASES.index(phase),
             "time_ns": 1}
            for phase, state in (("preflight", "STARTED"),
                                 ("preflight", "COMPLETED"),
                                 ("synthetic", "STARTED"))
        ])
        manifest = {
            "schema": runner.SCHEMA, "version": 1, "mode": "toy",
            "profile": runner.TOY_PROFILE, "seed": 20260729, "threads": 2,
            "warmup_calls": 1, "matrix_path": str(MATRIX),
            "matrix_sha256": matrix_sha, "cell_count": len(cells),
            "cell_ids": [cell["cell_id"] for cell in cells],
            "phase_order": list(PHASES),
            "phase_status": {phase: "PENDING" for phase in PHASES},
            "state": "FAILED", "failure": "producer failed for the fourth cell",
            "spawned_processes": 3,
            "source": source_metadata(ROOT), "scripts": runner._script_hashes(),
            "tools": tool_metadata(build),
            "binaries": binary_metadata(build, cells),
            "build_dir": str(build.resolve()),
            "input_bindings": {
                "variant_manifests": {"dblp_acm_u65536": str(root / "manifest.tsv")},
                "dblp_manifest": str(root / "manifest.tsv"),
            },
        }
        write_json(root / "run.json", manifest)
        return {"root": root, "build": build, "cells": cells, "plans": plans,
                "manifest": manifest, "matrix_sha": matrix_sha}

    # ------------------------------------------------------------------
    # a fresh run must be exactly what it was before resume existed
    # ------------------------------------------------------------------

    def test_fresh_run_records_no_resume_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _ = self.dry_root(Path(temporary))
            manifest = json.loads((root / "run.json").read_text())
            self.assertNotIn("resume", manifest)
            self.assertFalse((root / "resume.jsonl").exists())
            self.assertFalse((root / runner.SUPERSEDED_DIR).exists())
            verify = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run",
                 "--write-receipt"], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            seal = subprocess.run([sys.executable, str(SEAL), str(root)],
                                  cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(seal.returncode, 0, seal.stderr)
            payload = json.loads((root / "seal.json").read_text())
            self.assertFalse(payload["resumed"])
            self.assertEqual(payload["resume_count"], 0)
            self.assertIsNone(payload["provenance_sha256"])

    # ------------------------------------------------------------------
    # refusals
    # ------------------------------------------------------------------

    def test_resume_requires_an_existing_results_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=toy", "--resume", "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "absent"),
                "--seed", "20260729", "--threads", "2", "--matrix", str(MATRIX))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("existing results-root", result.stderr)

    def test_resume_is_refused_for_dry_run_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, build = self.dry_root(Path(temporary))
            result = self.run_runner(
                "--mode=dry-run", "--resume", "--build-dir", str(build),
                "--results-root", str(root), "--seed", "20260729",
                "--threads", "2", "--matrix", str(MATRIX))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dry-run", result.stderr)

    def test_resume_refuses_sealed_verified_and_completed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            root, build, cells = state["root"], state["build"], state["cells"]

            def attempt() -> None:
                runner._require_resumable_manifest(
                    root, mode="toy", seed=20260729, threads=2,
                    matrix_path=MATRIX, matrix_sha=state["matrix_sha"],
                    cells=cells, build_dir=build)

            attempt()  # the crashed root is resumable to begin with

            (root / "verification").mkdir()
            write_json(root / "verification" / "receipt.json", {"verdict": "PASS"})
            with self.assertRaisesRegex(RevisionContractError, "verification receipt"):
                attempt()
            shutil.rmtree(root / "verification")

            manifest = json.loads((root / "run.json").read_text())
            manifest["state"] = "COMPLETED"
            write_json(root / "run.json", manifest)
            with self.assertRaisesRegex(RevisionContractError, "already completed"):
                attempt()
            manifest["state"] = "FAILED"
            write_json(root / "run.json", manifest)

            (root / "seal.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(RevisionContractError, "sealed and terminal"):
                attempt()

    def test_resume_refuses_a_different_run_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            root, build, cells = state["root"], state["build"], state["cells"]
            baseline = dict(seed=20260729, threads=2, matrix_path=MATRIX,
                            matrix_sha=state["matrix_sha"], cells=cells,
                            build_dir=build)
            mutations = {
                "seed": dict(baseline, seed=7),
                "threads": dict(baseline, threads=16),
                "matrix_sha256": dict(baseline, matrix_sha="0" * 64),
                "build_dir": dict(baseline, build_dir=Path(temporary)),
                "cell_ids": dict(baseline, cells=cells[:2]),
            }
            for label, arguments in mutations.items():
                with self.subTest(label=label):
                    with self.assertRaisesRegex(RevisionContractError, "resume refused"):
                        runner._require_resumable_manifest(
                            root, mode="toy", **arguments)

    def test_resume_refuses_any_provenance_drift(self) -> None:
        """A resumed paper run may never mix two builds."""
        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            manifest, build, cells = state["manifest"], state["build"], state["cells"]
            runner._require_identical_provenance(
                manifest, build_dir=build, cells=cells)
            for registry in ("source", "scripts", "tools", "binaries"):
                with self.subTest(registry=registry):
                    drifted = dict(manifest)
                    drifted[registry] = dict(manifest[registry] or {})
                    drifted[registry]["piccard-resume-probe"] = "drifted"
                    with self.assertRaisesRegex(
                            RevisionContractError,
                            f"recorded {registry} provenance differs"):
                        runner._require_identical_provenance(
                            drifted, build_dir=build, cells=cells)

    def test_resume_refuses_a_replanned_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            root, plans = state["root"], state["plans"]
            runner._require_recorded_plans(root, plans)
            drifted = [dict(plan) for plan in plans]
            drifted[0]["timeout_seconds"] = 1
            with self.assertRaisesRegex(RevisionContractError, "does not match"):
                runner._require_recorded_plans(root, drifted)

    # ------------------------------------------------------------------
    # completion is re-derived, never trusted
    # ------------------------------------------------------------------

    def test_completion_is_re_derived_from_the_cells_own_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            root, plans, cells = state["root"], state["plans"], state["cells"]
            events = runner._read_jsonl(root / "events.jsonl", "events")
            by_cell: dict[str, list[dict[str, object]]] = {}
            for event in events:
                by_cell.setdefault(str(event["cell_id"]), []).append(event)

            plan, cell = plans[0], cells[0]
            output = Path(plan["output_dir"])
            receipt_path = output / "receipt.json"
            pristine = receipt_path.read_bytes()
            self.assertTrue(runner._cell_is_complete(
                root, plan, cell, by_cell[plan["cell_id"]]))

            # the crashed cell has a START with no END and no receipt at all
            self.assertFalse(runner._cell_is_complete(
                root, plans[3], cells[3], by_cell[plans[3]["cell_id"]]))

            def rejects(label: str) -> None:
                with self.subTest(label=label):
                    self.assertFalse(runner._cell_is_complete(
                        root, plan, cell, by_cell[plan["cell_id"]]))
                receipt_path.write_bytes(pristine)

            receipt = json.loads(pristine)
            receipt["execution_status"] = "FAILED"
            write_json(receipt_path, receipt)
            rejects("a FAILED receipt is never accepted")

            receipt = json.loads(pristine)
            receipt["stdout"]["sha256"] = "0" * 64
            write_json(receipt_path, receipt)
            rejects("a stdout digest that does not match disk")

            receipt = json.loads(pristine)
            receipt["canonical_argv"] = ["--tampered"]
            write_json(receipt_path, receipt)
            rejects("argv that disagrees with the plan")

            receipt_path.unlink()
            rejects("a missing receipt")

            (output / "stray.csv").write_text("left behind\n", encoding="utf-8")
            self.assertFalse(runner._cell_is_complete(
                root, plan, cell, by_cell[plan["cell_id"]]),
                "a stale artifact must invalidate the recorded inventory")
            (output / "stray.csv").unlink()

            self.assertFalse(runner._cell_is_complete(
                root, plan, cell, by_cell[plan["cell_id"]][:1]),
                "a START without an END is not a completed cell")
            failed_end = [dict(item) for item in by_cell[plan["cell_id"]]]
            failed_end[1]["exit_code"] = 1
            self.assertFalse(runner._cell_is_complete(
                root, plan, cell, failed_end),
                "a nonzero producer exit is not a completed cell")

    # ------------------------------------------------------------------
    # the rewritten evidence is what the verifier demands
    # ------------------------------------------------------------------

    def test_resume_rewrites_evidence_into_a_verifiable_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            root, plans, cells = state["root"], state["plans"], state["cells"]
            manifest = json.loads((root / "run.json").read_text())
            provenance = runner._provenance(manifest)
            crashed = plans[3]

            complete, resume_index = runner._prepare_resume(
                root, manifest=manifest, plans=plans, cells=cells,
                provenance=provenance)

            self.assertEqual(complete, {plan["cell_id"] for plan in plans[:3]})
            self.assertEqual(PHASES[resume_index], "synthetic")

            # events: contiguous from one, two per surviving cell, none for the
            # crashed cell
            events = runner._read_jsonl(root / "events.jsonl", "events")
            self.assertEqual([event["sequence"] for event in events],
                             list(range(1, len(events) + 1)))
            self.assertEqual(len(events), 6)
            self.assertNotIn(crashed["cell_id"],
                             {event["cell_id"] for event in events})
            for plan in plans[:3]:
                pair = [event for event in events
                        if event["cell_id"] == plan["cell_id"]]
                self.assertEqual([item["event"] for item in pair],
                                 ["START", "END"])
                receipt = json.loads(
                    (Path(plan["output_dir"]) / "receipt.json").read_text())
                self.assertEqual(receipt["start_event_sequence"],
                                 pair[0]["sequence"])
                self.assertEqual(receipt["end_event_sequence"],
                                 pair[1]["sequence"])

            # phases: truncated to the canonical completed-phase prefix
            phases = [(record["phase"], record["state"]) for record in
                      runner._read_jsonl(root / "phases.jsonl", "phases")]
            self.assertEqual(phases, [("preflight", "STARTED"),
                                      ("preflight", "COMPLETED")])

            # the crashed cell restarts from an empty directory, and nothing
            # it produced was destroyed
            self.assertFalse(Path(crashed["output_dir"]).exists())
            archived = (root / runner.SUPERSEDED_DIR / "attempt-1" / "cells" /
                        Path(crashed["output_dir"]).name)
            self.assertTrue((archived / "artifact.csv").is_file())
            self.assertEqual((archived / "artifact.csv").read_text(), "partial\n")
            dropped = runner._read_jsonl(
                root / runner.SUPERSEDED_DIR / "attempt-1" / "events-dropped.jsonl",
                "dropped")
            self.assertEqual([event["cell_id"] for event in dropped],
                             [crashed["cell_id"]])

            # the resume is a recorded act, in run.json and in its own stream
            reloaded = json.loads((root / "run.json").read_text())
            self.assertNotIn("failure", reloaded)
            resume = reloaded["resume"]
            self.assertTrue(resume["resumed"])
            self.assertEqual(resume["resume_count"], 1)
            self.assertEqual(len(resume["attempts"]), 1)
            attempt = resume["attempts"][0]
            self.assertEqual(attempt["cells_retained"], 3)
            self.assertEqual(attempt["cells_pending"], 1)
            self.assertEqual(attempt["cells_discarded"], [crashed["cell_id"]])
            self.assertEqual(attempt["resumed_at_phase"], "synthetic")
            self.assertEqual(attempt["superseded_failure"],
                             "producer failed for the fourth cell")
            self.assertEqual(resume["provenance_sha256"],
                             runner._provenance_digest(provenance))
            self.assertEqual(reloaded["spawned_processes"], 3)
            self.assertEqual(reloaded["event_sequence"], 6)
            self.assertEqual(reloaded["phase_status"]["preflight"], "COMPLETED")
            self.assertEqual(reloaded["phase_status"]["synthetic"], "PENDING")
            recorded = runner._read_jsonl(root / "resume.jsonl", "resume stream")
            self.assertEqual(len(recorded), 1)
            self.assertEqual(recorded[0]["schema"], runner.RESUME_EVENT_SCHEMA)

    def test_resumed_evidence_passes_the_real_structural_verifier(self) -> None:
        """Drive a crashed miniature to the end and verify it with the verifier.

        Resume only ever touches the run's structural evidence -- the event
        stream, the phase stream, the receipts, and the plan inventory -- so the
        four verifier checks that own those streams are the ones that decide
        whether a resumed root is admissible.  They are called here directly,
        unmodified, on evidence that really did survive a crash and a resume.
        """
        import verify_revision_benchmarks as verifier

        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            root, plans, cells = state["root"], state["plans"], state["cells"]
            manifest = json.loads((root / "run.json").read_text())
            complete, resume_index = runner._prepare_resume(
                root, manifest=manifest, plans=plans, cells=cells,
                provenance=runner._provenance(manifest))
            manifest["state"] = "RUNNING"

            def fake_producer(*_args: object, **kwargs: object):
                kwargs["stdout"].write(b"resumed producer\n")

                class Completed:
                    returncode = 0

                return Completed()

            # Replay the runner's own phase loop over the remaining work.
            from unittest.mock import patch
            with patch.object(runner.subprocess, "run", fake_producer):
                for phase in PHASES:
                    if phase in {"verification", "seal"}:
                        continue
                    if PHASES.index(phase) < resume_index:
                        continue
                    runner._phase(root, manifest, phase, "STARTED")
                    if phase == "preflight":
                        runner._phase(root, manifest, phase, "COMPLETED")
                        continue
                    for plan in [item for item in plans if item["phase"] == phase]:
                        if plan["cell_id"] in complete:
                            continue
                        runner._run_one(root=root, manifest=manifest, plan=plan,
                                        command=plan["command"], mode="toy")
                    runner._phase(root, manifest, phase, "COMPLETED")
            runner._phase(root, manifest, "verification", "STARTED")

            reloaded = json.loads((root / "run.json").read_text())
            verifier._check_phases(root, reloaded, stage="verification")
            checked = verifier._check_plans(root, "toy", cells, reloaded)
            verifier._check_events(root, "toy", checked)
            verifier._check_receipts(root, "toy", cells, checked)

            # every cell now carries exactly one zero-exit pair, including the
            # one that had to be re-run
            events = runner._read_jsonl(root / "events.jsonl", "events")
            self.assertEqual([event["sequence"] for event in events],
                             list(range(1, len(events) + 1)))
            self.assertEqual(len(events), 8)
            statuses = {
                plan["cell_id"]: json.loads(
                    (Path(plan["output_dir"]) / "receipt.json").read_text()
                )["execution_status"] for plan in plans}
            self.assertEqual(set(statuses.values()), {"COMPLETED"})

    def test_repeated_resume_accumulates_attempts_without_clobbering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self.miniature_root(Path(temporary))
            root, plans, cells = state["root"], state["plans"], state["cells"]
            manifest = json.loads((root / "run.json").read_text())
            provenance = runner._provenance(manifest)
            runner._prepare_resume(root, manifest=manifest, plans=plans,
                                   cells=cells, provenance=provenance)
            manifest = json.loads((root / "run.json").read_text())
            runner._prepare_resume(root, manifest=manifest, plans=plans,
                                   cells=cells, provenance=provenance)
            resume = json.loads((root / "run.json").read_text())["resume"]
            self.assertEqual(resume["resume_count"], 2)
            self.assertEqual([item["attempt"] for item in resume["attempts"]],
                             [1, 2])
            self.assertTrue((root / runner.SUPERSEDED_DIR / "attempt-1").is_dir())
            self.assertTrue((root / runner.SUPERSEDED_DIR / "attempt-2").is_dir())
            self.assertEqual(
                len(runner._read_jsonl(root / "resume.jsonl", "resume")), 2)


if __name__ == "__main__":
    unittest.main()
