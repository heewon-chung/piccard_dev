#!/usr/bin/env python3
"""RED fail-closed contracts for the Work #5 evidence verifier.

The verifier is deliberately exercised through a fresh runner-produced root,
then through one semantic mutation at a time.  Until Phase 3 supplies the
runner and verifier, failures are intentionally attributed only to those
missing entities.
"""

from __future__ import annotations

import csv
import io
import json
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_review_comparison as review_verifier
import run_work5_benchmarks as work5_runner
import verify_work5_benchmarks as work5_verifier
RUNNER = ROOT / "scripts" / "run_work5_benchmarks.py"
VERIFIER = ROOT / "scripts" / "verify_work5_benchmarks.py"
FAKE_BENCHMARK = ROOT / "tests" / "fixtures" / "work5" / "fake_work5_benchmark.py"
CONTRACT = ROOT / "tests" / "fixtures" / "work5" / "single_trial_contract.json"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n"
                            for row in rows), encoding="utf-8")


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class Work5VerifierContractTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.assertTrue(
            RUNNER.is_file(),
            "Phase 3 entity absent: scripts/run_work5_benchmarks.py is required",
        )
        self.assertTrue(
            VERIFIER.is_file(),
            "Phase 3 entity absent: scripts/verify_work5_benchmarks.py is required",
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = Path(self.temp.name)
        self.build = self.tmp / "build"
        self.build.mkdir()
        for name in ("bench_review_comparison", "bench_fhe_ind", "bench_comparison"):
            binary = self.build / name
            shutil.copy2(FAKE_BENCHMARK, binary)
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        self.events = self.tmp / "fake-events.jsonl"

    def produce_parameter_root(self, name: str,
                               extra_environment: dict[str, str] | None = None) -> Path:
        results = self.tmp / name
        environment = os.environ.copy()
        environment.update({
            "PICCARD_WORK5_FAKE_EVENT_LOG": str(self.events),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        if extra_environment:
            environment.update(extra_environment)
        run = subprocess.run(
            [
                "python3", str(RUNNER), "--phase=parameters",
                f"--build-dir={self.build}", f"--results-root={results}",
                "--seed=7", "--threads=2",
            ],
            cwd=ROOT, env=environment, text=True, capture_output=True,
            check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return results

    def verify(self, results: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VERIFIER), str(results), "--require-phase=parameters",
             "--allow-test-fixture"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    @staticmethod
    def rebind_cells(root: Path, rows: list[dict[str, Any]]) -> None:
        write_jsonl(root / "cells.jsonl", rows)
        run_path = root / "run.json"
        run = json.loads(run_path.read_text(encoding="utf-8"))
        run["cells_sha256"] = hashlib.sha256((root / "cells.jsonl").read_bytes()).hexdigest()
        # Fixture mutations deliberately recompute the attacker-controlled
        # parameter inventory too, so each assertion reaches the independent
        # semantic verifier rather than failing only at an obsolete hash.
        inventory = run.get("phase_inventory", {}).get("parameters", {})
        for artifact in inventory.get("artifacts", []):
            artifact["sha256"] = work5_runner.sha256_file(root / artifact["path"])
        run_path.write_text(json.dumps(run, sort_keys=True, separators=(",", ":")) + "\n",
                            encoding="utf-8")

    @staticmethod
    def fixture_actual_payload(record: dict[str, Any]) -> str:
        """Method-neutral marker for a materialized fake workload only.

        The real producer's hash is reconstructed from ordered trial records.
        The hermetic fixture has no such records, so its distinct test-domain
        marker is used solely to test that a skip commitment is never treated
        as an actual payload digest.
        """
        material = {key: record[key] for key in
                    ("security", "k", "m", "n", "U", "target_jaccard", "seed")}
        return hashlib.sha256(
            b"piccard-work5-test-actual-payload-v1\0" +
            (json.dumps(material, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("ascii")
        ).hexdigest()

    @staticmethod
    def forged_skip_commitment(record: dict[str, Any], **overrides: Any) -> str:
        """Independent commitment oracle with one intentionally wrong field."""
        material = {key: record[key] for key in
                    ("security", "axis", "axis_value", "k", "m", "n", "U")}
        material.update({"target_jaccard": record["target_jaccard"],
                         "seed": record["seed"], "executed_trials": 3})
        material.update(overrides)
        return hashlib.sha256(
            b"piccard-work5-planned-payload-v1\0" +
            (json.dumps(material, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("ascii")
        ).hexdigest()

    def mark_fixture_measurements_actual(self, root: Path) -> list[dict[str, Any]]:
        rows = read_jsonl(root / "cells.jsonl")
        for row in rows:
            if row["status"] == "MEASURED":
                row["trial_payload_sha256"] = self.fixture_actual_payload(row)
        self.rebind_cells(root, rows)
        return rows

    def rebind_copied_parameter_root(self, source: Path, candidate: Path) -> list[dict[str, Any]]:
        """Copy a valid fixture root while preserving its root-bound contract.

        A raw A->B copy is intentionally invalid: ``run.json`` binds the
        canonical results-root and every frozen producer argv embeds B's
        staging paths.  This test-only helper first updates those dependent
        values and their hashes, then proves the copied baseline verifies
        before a semantic mutation is introduced.  It never changes the
        production verifier's identity checks.
        """
        shutil.copytree(source, candidate)
        rows = read_jsonl(candidate / "cells.jsonl")
        run_path = candidate / "run.json"
        run = json.loads(run_path.read_text(encoding="utf-8"))
        expected_by_id = {cell["cell_id"]: cell for cell in work5_runner.frozen_cells()}
        self.assertEqual({row["cell_id"] for row in rows}, set(expected_by_id))
        build_dir = Path(run["build_dir"])
        canonical_root = candidate.resolve()
        for row in rows:
            expected = expected_by_id[row["cell_id"]]
            row["argv"] = work5_runner.planned_argv(build_dir, canonical_root, expected)
            command_path = candidate / row["command_path"]
            command_path.write_bytes(work5_runner.canonical_json({
                "schema": "piccard-work5-command-v1", "cell_id": row["cell_id"],
                "argv": row["argv"], "environment": row["environment"],
            }))
            row["command_sha256"] = work5_runner.sha256_file(command_path)
        self.rebind_cells(candidate, rows)
        run = json.loads(run_path.read_text(encoding="utf-8"))
        run["results_root"] = str(canonical_root)
        run["results_root_sha256"] = work5_runner.results_root_digest(canonical_root)
        run_path.write_bytes(work5_runner.canonical_json(run))
        verified = self.verify(candidate)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        return rows

    def test_semantic_verifier_registers_both_piccard_m_extra_suites(self) -> None:
        expected = {
            "work5-std128-piccard-m-extra":
                ("work5-std128-t40-single-trial", ["piccard"], 1, 1),
            "work5-std192-piccard-m-extra":
                ("work5-std192-t40-single-trial", ["piccard_encode"], 1, 1),
        }
        self.assertEqual({name: review_verifier.SUITES[name] for name in expected}, expected)

    def test_nonfixture_m_extra_requires_onehot_only_and_checks_context_identity(self) -> None:
        root = self.tmp / "production-shaped-m-extra"
        root.mkdir()

        def install(relative: str, payload: bytes) -> tuple[str, str]:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return relative, hashlib.sha256(payload).hexdigest()

        cell_id = "work5-std128-piccard-m-extra::m=32"
        source_commit = "a" * 40
        piccard_binary = "b" * 64
        argv = ["/production/bench_review_comparison", "--suite=work5-std128-piccard-m-extra"]
        environment = {"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"}
        command = json.dumps({"schema": "piccard-work5-command-v1", "cell_id": cell_id,
                              "argv": argv, "environment": environment},
                             sort_keys=True, separators=(",", ":")).encode() + b"\n"
        artifacts = {}
        for name, payload in (("command", command), ("stdout", b"producer stdout\n"),
                              ("stderr", b""), ("workload", b"workload\n"),
                              ("trace", b"trace\n"), ("csv", b"csv\n")):
            relative, digest = install(f"{name}/{cell_id}.{name}", payload)
            artifacts[f"{name}_path"] = relative
            artifacts[f"{name}_sha256"] = digest
        context = {
            "schema": "piccard-work5-piccard-context-preflight-v1",
            "mode": "work5-preflight", "keygen_started": False, "cell_id": cell_id,
            "circuit": "onehot", "security": "STD128", "k": 128, "m": 32,
            "n": 1000, "universe": 16384, "source_commit": source_commit,
            "piccard_binary_sha256": piccard_binary, "realized_ring_dim": 32768,
            "provisioned_depth": 4, "log_q_bits": 240.0,
            "context_tuple_sha256": "c" * 64, "skipped": False,
        }
        onehot_path, onehot_digest = install(
            f"context/{cell_id}.onehot.json",
            json.dumps(context, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        record = {
            "cell_id": cell_id, "status": "MEASURED", "methods": ["piccard"],
            "context_started": True, "security": "STD128", "k": 128, "m": 32,
            "n": 1000, "U": 16384, "argv": argv, "environment": environment,
            **artifacts,
            "context_onehot_path": onehot_path,
            "context_onehot_sha256": onehot_digest,
            "context_sqrt_path": None, "context_sqrt_sha256": None,
            "context_fhe_ind_path": None, "context_fhe_ind_sha256": None,
        }
        run = {"test_fixture_mode": False, "git_sha": source_commit,
               "executables": {"bench_std_security_evidence": piccard_binary}}
        self.assertEqual(work5_verifier.expected_context_labels(["piccard"]),
                         ("context_onehot",))
        self.assertEqual(work5_verifier.expected_context_labels(
            ["piccard", "piccard_sqrt"]),
            ("context_onehot", "context_sqrt"))
        self.assertEqual(work5_verifier.expected_context_labels(["fhe_ind"]),
                         ("context_fhe_ind",))
        self.assertFalse(run["test_fixture_mode"])
        work5_verifier.verify_artifacts(root, record, test_fixture=False)
        work5_verifier.verify_context(root, run, record)

        missing = dict(record)
        missing["context_onehot_path"] = None
        missing["context_onehot_sha256"] = None
        with self.assertRaises(work5_verifier.VerificationError):
            work5_verifier.verify_artifacts(root, missing, test_fixture=False)

        sqrt_path, sqrt_digest = install(f"context/{cell_id}.forged-sqrt.json", b"forged\n")
        extra_sqrt = dict(record)
        extra_sqrt["context_sqrt_path"] = sqrt_path
        extra_sqrt["context_sqrt_sha256"] = sqrt_digest
        with self.assertRaises(work5_verifier.VerificationError):
            work5_verifier.verify_artifacts(root, extra_sqrt, test_fixture=False)

        wrong_context = dict(context)
        wrong_context["m"] = 64
        wrong_path, wrong_digest = install(
            f"context/{cell_id}.wrong-onehot.json",
            json.dumps(wrong_context, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        wrong_identity = dict(record)
        wrong_identity["context_onehot_path"] = wrong_path
        wrong_identity["context_onehot_sha256"] = wrong_digest
        work5_verifier.verify_artifacts(root, wrong_identity, test_fixture=False)
        with self.assertRaises(work5_verifier.VerificationError):
            work5_verifier.verify_context(root, run, wrong_identity)

    def test_valid_parameter_root_passes(self) -> None:
        results = self.produce_parameter_root("valid")
        self.mark_fixture_measurements_actual(results)
        verified = self.verify(results)
        self.assertEqual(verified.returncode, 0, verified.stderr)

    @staticmethod
    def dynamic_refresh_csv(updates: int) -> bytes:
        values = {
            "label": f"refresh_owner_a_0_to_{updates}", "k": "16", "m": "16",
            "set_size": "100", "depth": "5", "trials": "1", "hash_seed": "7",
            "accuracy_trials": "0", "profile_id": "toy-smoke", "run_class": "smoke",
            "target_security_bits": "0", "comparison_eligible": "false",
            "measurement_kind": "diagnostic", "dynamic_scenario": "refresh",
            "updates_requested": str(updates), "updates_applied": str(updates),
            "initial_epoch": "0", "final_epoch": str(updates),
            "owner_b_unchanged": "true", "ciphertext_upload_count": str(updates),
            "local_inner_product": "7", "decrypted_inner_product": "7",
            "correctness_status": "PASS", "refresh_owner_set_id": "owner-a",
            "refresh_updates": str(updates), "refresh_epoch_before": "0",
            "refresh_epoch_after": str(updates), "refresh_status": "applied",
            "refresh_upload_bytes": "1", "refresh_ciphertexts_uploaded": str(updates),
        }
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=sorted(work5_verifier.DYNAMIC_CSV_FIELDS),
                                lineterminator="\n")
        writer.writeheader()
        writer.writerow(values)
        return stream.getvalue().encode("utf-8")

    def dynamic_root(self, name: str) -> tuple[Path, dict[str, Any]]:
        root = self.tmp / name
        dynamic = root / "dynamic"
        dynamic.mkdir(parents=True)
        commands = work5_runner.planned_dynamic_commands(self.build, root)
        command = {
            "schema": "piccard-work5-dynamic-command-v1",
            "commands": [{"label": label, "argv": argv} for label, argv in commands],
            "environment": {"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"},
        }
        (dynamic / "commands.json").write_bytes(work5_runner.canonical_json(command))
        terminal = {
            "schema": "piccard-work5-dynamic-terminal-v1", "status": "MEASURED",
            "scenario": "refresh", "profile": "toy-smoke", "security": "TOY",
            "updates": [1, 2], "trials": 1, "measurement_kind": "diagnostic",
            "commands": command["commands"], "detail": "PASS",
            "ended_at_utc": "2026-08-12T00:00:00Z",
        }
        (dynamic / "terminal.json").write_bytes(work5_runner.canonical_json(terminal))
        for updates, (label, _argv) in zip((1, 2), commands):
            payload = self.dynamic_refresh_csv(updates)
            (dynamic / f"{label}.csv").write_bytes(payload)
            (dynamic / f"{label}.stdout").write_bytes(payload)
            (dynamic / f"{label}.stderr").write_bytes(b"")
        artifacts = [path for path in dynamic.rglob("*") if path.is_file()]
        run = {
            "build_dir": str(self.build),
            "phase_inventory": {"dynamic": {
                "artifacts": [{"path": path.relative_to(root).as_posix(),
                               "sha256": work5_runner.sha256_file(path)}
                              for path in sorted(artifacts)],
            }},
        }
        return root, run

    @staticmethod
    def mutate_dynamic_csv(root: Path, label: str, field: str, value: str) -> None:
        dynamic = root / "dynamic"
        source = dynamic / f"{label}.csv"
        reader = csv.DictReader(io.StringIO(source.read_text(encoding="utf-8")))
        row = next(reader)
        row[field] = value
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=reader.fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerow(row)
        payload = stream.getvalue().encode("utf-8")
        source.write_bytes(payload)
        (dynamic / f"{label}.stdout").write_bytes(payload)

    def test_dynamic_semantic_verifier_accepts_two_rows_and_rejects_mutations(self) -> None:
        root, run = self.dynamic_root("dynamic-valid")
        work5_verifier.verify_dynamic(root, run)
        self.assertTrue(callable(work5_verifier.verify_dynamic))
        cases = {
            "owner_b_change": ("updates-1", "owner_b_unchanged", "false"),
            "epoch_discontinuity": ("updates-2", "final_epoch", "1"),
            "replay_acceptance": ("updates-2", "updates_applied", "3"),
            "wrong_upload_count": ("updates-2", "ciphertext_upload_count", "1"),
            "local_decrypted_mismatch": ("updates-1", "decrypted_inner_product", "8"),
            "timing_promotion": ("updates-1", "measurement_kind", "fhe_timing"),
        }
        for name, (label, field, value) in cases.items():
            with self.subTest(name=name):
                candidate, candidate_run = self.dynamic_root(f"dynamic-{name}")
                self.mutate_dynamic_csv(candidate, label, field, value)
                with self.assertRaises(work5_verifier.VerificationError):
                    work5_verifier.verify_dynamic(candidate, candidate_run)

    def test_dynamic_semantic_verifier_rejects_missing_or_external_artifacts(self) -> None:
        missing, missing_run = self.dynamic_root("dynamic-missing")
        (missing / "dynamic" / "updates-2.csv").unlink()
        with self.assertRaises(work5_verifier.VerificationError):
            work5_verifier.verify_dynamic(missing, missing_run)

        external, external_run = self.dynamic_root("dynamic-external")
        external_run["phase_inventory"]["dynamic"]["artifacts"].append({
            "path": "../outside.csv", "sha256": "0" * 64,
        })
        with self.assertRaises(work5_verifier.VerificationError):
            work5_verifier.verify_dynamic(external, external_run)

    def test_dynamic_phase_inventory_counts_are_exact(self) -> None:
        root, run = self.dynamic_root("dynamic-inventory")
        run.update({"completed_phases": ["dynamic"]})
        run["phase_inventory"]["dynamic"].update({
            "schema": "piccard-work5-phase-inventory-v1", "phase": "dynamic",
            "row_counts": {"correctness_rows": 2, "updates_1": 1,
                           "updates_2": 1, "errors": 0},
        })
        work5_verifier.verify_phase_inventories(root, run)
        run["phase_inventory"]["dynamic"]["row_counts"]["updates_2"] = 2
        with self.assertRaises(work5_verifier.VerificationError):
            work5_verifier.verify_phase_inventories(root, run)

    def test_phase_receipt_path_is_new_only_and_expectation_syntax_is_strict(self) -> None:
        results = self.produce_parameter_root("receipt")
        self.mark_fixture_measurements_actual(results)
        output = results / "verification" / "parameters.json"
        command = [
            "python3", str(VERIFIER), str(results), "--require-phase=parameters",
            "--allow-test-fixture", f"--verification-out={output}",
        ]
        first = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(first.returncode, 0, first.stderr)
        receipt = json.loads(output.read_text(encoding="utf-8"))
        run = json.loads((results / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema"], "piccard-work5-verification-receipt-v1")
        self.assertEqual(receipt["verdict"], "PASS")
        self.assertEqual(receipt["phase"], "parameters")
        self.assertEqual(receipt["run_sha256"], hashlib.sha256(
            (results / "run.json").read_bytes()).hexdigest())
        self.assertEqual(receipt["phase_inventory_sha256"],
                         work5_verifier.phase_inventory_sha256(
                             run["phase_inventory"]["parameters"]))
        second = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("already exists", second.stderr)
        self.assertEqual(work5_verifier._parse_expected_completed("toy,parameters"),
                         ["toy", "parameters"])
        with self.assertRaises(work5_verifier.VerificationError):
            work5_verifier._parse_expected_completed("parameters,toy")

    def test_status_aware_payload_commitments_accept_mixed_groups_and_reject_forgery(self) -> None:
        """Mixed real-payload/skip-commitment groups are valid only status-aware.

        Each generated root forces the FHE-IND ``U=65536`` cell to its
        observation-backed preflight terminal.  SJ16 at that same key is
        already a frozen projected-runtime skip.  Thus STD128 and STD192 both
        exercise exactly one materialized Piccard payload beside FHE/SJ skip
        commitments without touching an immutable production evidence root.
        """
        mixed_roots: dict[str, Path] = {}
        for security in ("STD128", "STD192"):
            root = self.produce_parameter_root(
                f"mixed-{security.lower()}",
                {
                    "PICCARD_WORK5_TEST_FORCE_PRECHECK_REASON": "RING_DIM_CAP",
                    "PICCARD_WORK5_TEST_FORCE_PRECHECK_CELL":
                        f"work5-{security.lower()}-fhe-ind::U=65536",
                },
            )
            rows = self.mark_fixture_measurements_actual(root)
            group = [row for row in rows if
                     (row["security"], row["axis"], row["axis_value"], row["k"],
                      row["m"], row["n"], row["U"], row["target_jaccard"], row["seed"]) ==
                     (security, "U", 65536, 128, 64, 1000, 65536, "0.5", 7)]
            self.assertEqual(
                [(row["methods"], row["status"], row["reason_code"]) for row in group],
                [(["piccard", "piccard_sqrt"] if security == "STD128" else
                  ["piccard_encode", "piccard_sqrt_encode"], "MEASURED", None),
                 (["fhe_ind"], "SKIPPED_PRECHECK", "RING_DIM_CAP"),
                 (["sj16"], "SKIPPED_PRECHECK", "PROJECTED_RUNTIME_CAP")],
            )
            measured = group[0]
            self.assertNotEqual(measured["trial_payload_sha256"],
                                group[1]["trial_payload_sha256"])
            self.assertEqual(group[1]["trial_payload_sha256"],
                             work5_runner.planned_payload_sha256(group[1]))
            self.assertEqual(group[1]["trial_payload_sha256"],
                             work5_verifier.planned_payload_commitment(group[1]))
            self.assertEqual(group[2]["trial_payload_sha256"],
                             work5_runner.planned_payload_sha256(group[2]))
            self.assertEqual(group[2]["trial_payload_sha256"],
                             work5_verifier.planned_payload_commitment(group[2]))
            mixed_roots[security] = root

        # This is the RED boundary before the status-aware verifier fix: it
        # incorrectly compares the actual marker with both skip commitments.
        for security, root in mixed_roots.items():
            with self.subTest(valid_mixed_group=security):
                verified = self.verify(root)
                self.assertEqual(verified.returncode, 0, verified.stderr)

        source = mixed_roots["STD128"]

        def mutate(name: str, expected_error: str,
                   change: Callable[[list[dict[str, Any]], Path], None]) -> None:
            candidate = self.tmp / name
            rows = self.rebind_copied_parameter_root(source, candidate)
            change(rows, candidate)
            self.rebind_cells(candidate, rows)
            verified = self.verify(candidate)
            self.assertNotEqual(verified.returncode, 0, name)
            self.assertIn(expected_error, verified.stderr, verified.stderr)
            self.assertNotIn("canonical results-root identity mismatch", verified.stderr,
                             verified.stderr)

        def u65536(rows: list[dict[str, Any]], methods: list[str]) -> dict[str, Any]:
            return next(row for row in rows if row["security"] == "STD128" and
                        row["axis"] == "U" and row["axis_value"] == 65536 and
                        row["methods"] == methods)

        mutate("measured-planned-commitment",
               "work5-std128-piccard::U=65536: measured cell carries a skip commitment",
               lambda rows, _: u65536(
            rows, ["piccard", "piccard_sqrt"]).__setitem__(
                "trial_payload_sha256", work5_runner.planned_payload_sha256(
                    u65536(rows, ["piccard", "piccard_sqrt"]))))
        mutate("skipped-actual-payload",
               "work5-std128-fhe-ind::U=65536: skip planned-payload commitment mismatch",
               lambda rows, _: u65536(
            rows, ["fhe_ind"]).__setitem__(
                "trial_payload_sha256", u65536(
                    rows, ["piccard", "piccard_sqrt"])["trial_payload_sha256"]))

        skip = next(row for row in read_jsonl(source / "cells.jsonl")
                    if row["methods"] == ["fhe_ind"] and row["axis"] == "U" and
                    row["axis_value"] == 65536)
        changed = {
            "security": "TOY", "axis": "m", "axis_value": 65537, "k": 129,
            "m": 65, "n": 1001, "U": 65537, "target_jaccard": "0.4", "seed": 8,
            "executed_trials": 4,
        }
        for field, value in changed.items():
            mutate(f"skip-commitment-{field}",
                   "work5-std128-fhe-ind::U=65536: skip planned-payload commitment mismatch",
                   lambda rows, _, field=field, value=value:
                   u65536(rows, ["fhe_ind"]).__setitem__(
                       "trial_payload_sha256",
                       self.forged_skip_commitment(skip, **{field: value})))

        def skipped_workload(rows: list[dict[str, Any]], _: Path) -> None:
            measured = u65536(rows, ["piccard", "piccard_sqrt"])
            target = u65536(rows, ["fhe_ind"])
            target["workload_path"] = measured["workload_path"]
            target["workload_sha256"] = measured["workload_sha256"]

        def divergent_measured(rows: list[dict[str, Any]], _: Path) -> None:
            controls = [row for row in rows if row["axis"] == "control" and
                        row["status"] == "MEASURED"]
            self.assertGreaterEqual(len(controls), 2)
            controls[1]["trial_payload_sha256"] = "d" * 64

        def measured_to_skipped(rows: list[dict[str, Any]], _: Path) -> None:
            u65536(rows, ["piccard", "piccard_sqrt"])["status"] = "SKIPPED_PRECHECK"

        def skipped_to_measured(rows: list[dict[str, Any]], _: Path) -> None:
            u65536(rows, ["fhe_ind"])["status"] = "MEASURED"

        mutate("skipped-workload-artifact",
               "work5-std128-fhe-ind::U=65536: preflight skip has output artifact",
               skipped_workload)
        mutate("measured-to-skipped",
               "work5-std128-piccard::U=65536: skip planned-payload commitment mismatch",
               measured_to_skipped)
        mutate("skipped-to-measured",
               "work5-std128-fhe-ind::U=65536: measured cell carries a skip commitment",
               skipped_to_measured)
        mutate("jointly-measured-divergence",
               "trial payload hashes diverge for jointly measured cell",
               divergent_measured)

    def test_root_binding_exact_argv_and_orphan_inventory_fail_even_when_rehashed(self) -> None:
        source = self.produce_parameter_root("identity-source")
        self.mark_fixture_measurements_actual(source)
        copied = self.tmp / "identity-copy"
        shutil.copytree(source, copied)
        self.assertNotEqual(self.verify(copied).returncode, 0,
                            "A->B copy must not verify under B")

        # Rebind every affected hash after forging a benign-looking /bin/true
        # command.  The independent verifier must still reconstruct the exact
        # frozen argv rather than trusting self-consistent record hashes.
        records = read_jsonl(source / "cells.jsonl")
        record = records[0]
        record["argv"][0] = "/bin/true"
        command = source / record["command_path"]
        command_value = json.loads(command.read_text(encoding="utf-8"))
        command_value["argv"] = record["argv"]
        command.write_text(json.dumps(command_value, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")
        record["command_sha256"] = hashlib.sha256(command.read_bytes()).hexdigest()
        write_jsonl(source / "cells.jsonl", records)
        run_path = source / "run.json"
        run = json.loads(run_path.read_text(encoding="utf-8"))
        run["cells_sha256"] = hashlib.sha256((source / "cells.jsonl").read_bytes()).hexdigest()
        run_path.write_text(json.dumps(run, sort_keys=True, separators=(",", ":")) + "\n",
                            encoding="utf-8")
        self.assertNotEqual(self.verify(source).returncode, 0,
                            "rehashed /bin/true command must not verify")

        # A separate valid root demonstrates an extra, unreferenced file is
        # rejected rather than ignored by a count-only verifier.
        orphan = self.produce_parameter_root("identity-orphan")
        self.mark_fixture_measurements_actual(orphan)
        (orphan / "csv" / "orphan.csv").write_text("forged\n", encoding="utf-8")
        self.assertNotEqual(self.verify(orphan).returncode, 0,
                            "orphan producer artifact must not verify")

    def test_semantic_matrix_mutations_fail_closed(self) -> None:
        source = self.produce_parameter_root("source")
        self.mark_fixture_measurements_actual(source)

        def change_method(rows: list[dict[str, Any]], _: Path) -> None:
            rows[0]["methods"] = ["threshold"]

        def add_bcg12_to_std192(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["security"] == "STD192")
            row["methods"] = ["bcg12_mh_ec"]

        def add_oversized_universe(rows: list[dict[str, Any]], _: Path) -> None:
            rows[0]["U"] = 262144

        def change_control_axis(rows: list[dict[str, Any]], _: Path) -> None:
            rows[0]["axis"] = "k"
            rows[0]["axis_value"] = 128

        def change_applicability(rows: list[dict[str, Any]], _: Path) -> None:
            rows[0]["applicability"]["k"] = False

        def forge_m_extra_control_reference(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["suite"].endswith("-m-extra"))
            row["control_cell_id"] = "work5-std192-piccard::control"

        def add_sqrt_to_m_extra(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["suite"].endswith("-m-extra"))
            row["methods"] = ["piccard", "piccard_sqrt"]

        def copy_control_timing_to_m_extra(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["suite"].endswith("-m-extra"))
            row["control_timing_ms"] = 1.0

        def add_sqrt_context_to_m_extra(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["suite"].endswith("-m-extra"))
            row["context_sqrt_path"] = "context/forged-sqrt.json"
            row["context_sqrt_sha256"] = "0" * 64

        def add_context_to_std192_encoding(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["piccard_encode"] and
                       item["security"] == "STD192")
            row["context_onehot_path"] = "context/forged-onehot.json"
            row["context_onehot_sha256"] = "0" * 64

        def start_keygen_for_std192_encoding(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["piccard_encode"] and
                       item["security"] == "STD192")
            row["keygen_started"] = True

        def lie_about_std192_encoding_taxonomy(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["piccard_encode"] and
                       item["security"] == "STD192")
            row["taxonomy"]["piccard_encode"]["cost_scope"] = "primitive-only"

        def make_fhe_ind_comparison_eligible(
                rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["fhe_ind"])
            row["taxonomy"]["fhe_ind"]["semantic_comparison_eligible"] = True

        def change_fhe_ind_protocol_model(
                rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["fhe_ind"])
            row["taxonomy"]["fhe_ind"]["protocol_model"] = "made-up-model"

        def give_sj16_secure_division(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["sj16"])
            row["taxonomy"]["sj16"]["secure_division_included"] = True

        def change_sj16_cost_scope(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["sj16"])
            row["taxonomy"]["sj16"]["cost_scope"] = "component-lower-bound"

        def change_sj16_comparison_scope(
                rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["sj16"])
            row["taxonomy"]["sj16"]["comparison_scope"] = "end-to-end-estimator"

        def forge_skip_after_keygen(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows
                       if item["status"] == "SKIPPED_PRECHECK")
            row["keygen_started"] = True

        def forge_skip_output(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows
                       if item["status"] == "SKIPPED_PRECHECK")
            row["csv_path"] = "csv/forged.csv"
            row["csv_sha256"] = "0" * 64

        def change_frozen_skip_reason(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows
                       if item["suite"] == "work5-std128-sj16" and
                       item["axis"] == "U")
            row["reason_code"] = "WORKLOAD_GEOMETRY"

        def remove_payload_hash(rows: list[dict[str, Any]], _: Path) -> None:
            rows[0].pop("trial_payload_sha256", None)

        def duplicate_terminal(rows: list[dict[str, Any]], _: Path) -> None:
            rows.append(dict(rows[0]))

        def change_trials(_: list[dict[str, Any]], root: Path) -> None:
            run_json = root / "run.json"
            payload = json.loads(run_json.read_text(encoding="utf-8"))
            payload["trials"] = 2
            run_json.write_text(json.dumps(payload, sort_keys=True) + "\n",
                                encoding="utf-8")

        mutations: tuple[tuple[str, Callable[[list[dict[str, Any]], Path], None]], ...] = (
            ("threshold", change_method),
            ("bcg12-std192", add_bcg12_to_std192),
            ("u262144", add_oversized_universe),
            ("control-axis", change_control_axis),
            ("applicability", change_applicability),
            ("m-extra-control-reference", forge_m_extra_control_reference),
            ("m-extra-sqrt", add_sqrt_to_m_extra),
            ("m-extra-copied-timing", copy_control_timing_to_m_extra),
            ("m-extra-sqrt-context", add_sqrt_context_to_m_extra),
            ("std192-encoding-context", add_context_to_std192_encoding),
            ("std192-encoding-keygen", start_keygen_for_std192_encoding),
            ("std192-encoding-taxonomy", lie_about_std192_encoding_taxonomy),
            ("fhe-ind-eligible", make_fhe_ind_comparison_eligible),
            ("fhe-ind-protocol-model", change_fhe_ind_protocol_model),
            ("sj16-secure-division", give_sj16_secure_division),
            ("sj16-cost-scope", change_sj16_cost_scope),
            ("sj16-comparison-scope", change_sj16_comparison_scope),
            ("trials2", change_trials),
            ("forged-skip", forge_skip_after_keygen),
            ("skip-output", forge_skip_output),
            ("frozen-skip-reason", change_frozen_skip_reason),
            ("missing-payload-hash", remove_payload_hash),
            ("duplicate-terminal", duplicate_terminal),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                candidate = self.tmp / name
                shutil.copytree(source, candidate)
                rows = read_jsonl(candidate / "cells.jsonl")
                mutate(rows, candidate)
                write_jsonl(candidate / "cells.jsonl", rows)
                verified = self.verify(candidate)
                self.assertNotEqual(verified.returncode, 0, verified.stdout)

        contract = load_contract()
        self.assertTrue(contract["hard_exclusions"]["threshold"])
        self.assertTrue(contract["hard_exclusions"]["bcg12_std192"])
        self.assertFalse(contract["hard_exclusions"]
                         ["fhe_ind_comparison_eligible"])
        self.assertEqual(contract["hard_exclusions"]["fhe_ind_protocol_model"],
                         "local-universe-sized-BFV-comparator")
        self.assertEqual(contract["hard_exclusions"]["fhe_ind_comparison_scope"],
                         "diagnostic-only")
        self.assertFalse(contract["hard_exclusions"]
                         ["sj16_secure_division_included"])
        self.assertEqual(contract["hard_exclusions"]["sj16_comparison_scope"],
                         "component-lower-bound")
        self.assertEqual(contract["hard_exclusions"]["sj16_cost_scope"],
                         "full-query-excluding-one-time-setup")

    def test_recomputed_provenance_and_bfv_caps_reject_rehashed_mutations(self) -> None:
        source = self.produce_parameter_root("provenance-source")
        self.mark_fixture_measurements_actual(source)

        def rewrite_run(root: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
            path = root / "run.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            mutate(payload)
            path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                            encoding="utf-8")

        mutations: list[tuple[str, Callable[[Path], None]]] = [
            ("dirty-flip", lambda root: rewrite_run(
                root, lambda run: run.__setitem__("git_dirty", not run["git_dirty"]))),
            ("command-template", lambda root: rewrite_run(
                root, lambda run: run.__setitem__("command_template_sha256", "0" * 64))),
            ("semantic-dependency", lambda root: rewrite_run(
                root, lambda run: run["scripts"].__setitem__(
                    "verify_benchmark_provenance.py", "0" * 64))),
            ("binary-path", lambda root: rewrite_run(
                root, lambda run: run["executable_paths"].__setitem__(
                    "bench_review_comparison", "/bin/true"))),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                candidate = self.tmp / name
                shutil.copytree(source, candidate)
                mutate(candidate)
                self.assertNotEqual(self.verify(candidate).returncode, 0)

        candidate = self.tmp / "bfv-cap"
        shutil.copytree(source, candidate)
        matrix_path = candidate / "matrix.json"
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        matrix["bfv_caps"]["log_q_bits"] = 999.0
        matrix_path.write_text(json.dumps(matrix, sort_keys=True, separators=(",", ":")) + "\n",
                               encoding="utf-8")
        rewrite_run(candidate, lambda run: run.__setitem__(
            "matrix_sha256", hashlib.sha256(matrix_path.read_bytes()).hexdigest()))
        self.assertNotEqual(self.verify(candidate).returncode, 0,
                            "rehashed BFV caps mutation must not verify")


if __name__ == "__main__":
    unittest.main()
