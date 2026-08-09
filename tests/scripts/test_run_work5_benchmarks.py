#!/usr/bin/env python3
"""RED contracts for the Work #5 single-trial benchmark runner.

The tests use a command sentinel rather than an FHE test double.  They pin the
runner's matrix and fail-closed lifecycle without accepting synthetic timing as
evidence.  Until Phase 3 adds ``scripts/run_work5_benchmarks.py``, each
lifecycle test intentionally fails at the missing-runner boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_work5_benchmarks.py"
CONTRACT = ROOT / "tests" / "fixtures" / "work5" / "single_trial_contract.json"
FAKE_BENCHMARK = ROOT / "tests" / "fixtures" / "work5" / "fake_work5_benchmark.py"


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line]


def target_value(record: dict[str, Any]) -> Any:
    if "target" in record:
        return record["target"]
    return record["target_jaccard"]


AXES = ("k", "m", "n", "U")


def parameter_cell_key(cell: dict[str, Any]) -> str:
    """Canonical, order-sensitive key for one frozen Work #5 parameter cell."""
    control_marker = "|null" if cell["axis"] == "control" else ""
    return (f"{cell['cell_id']}{control_marker}|k={cell['k']},m={cell['m']},"
            f"n={cell['n']},U={cell['U']}")


def frozen_parameter_cells(contract: dict[str, Any]) -> list[dict[str, Any]]:
    """Construct the complete ordered matrix independently of a future runner."""
    control = contract["control"]
    cells: list[dict[str, Any]] = []
    profile_security = {
        profile["id"]: profile["security"] for profile in contract["profiles"]
    }
    for suite in contract["suites"]:
        base = {
            "profile": suite["profile"],
            "security": profile_security[suite["profile"]],
            "suite": suite["id"],
            "axis": contract["control_cell"]["axis"],
            "axis_value": contract["control_cell"]["axis_value"],
            "cell_id": contract["control_cell"]["cell_id_format"].format(
                suite=suite["id"]),
            **{axis: control[axis] for axis in AXES},
        }
        cells.append(base)
        for axis in suite["applicable_axes"]:
            for value in contract["parameter_axes"][axis]:
                if value == control[axis]:
                    continue
                cell = dict(base)
                cell["axis"] = axis
                cell["axis_value"] = value
                cell["cell_id"] = f"{suite['id']}::{axis}={value}"
                cell[axis] = value
                cells.append(cell)
    return cells


def matrix_key_digest(keys: list[str]) -> str:
    # Compact JSON makes the frozen list and its digest language-independent.
    material = json.dumps(keys, separators=(",", ":"), ensure_ascii=True) + "\n"
    return hashlib.sha256(material.encode("ascii")).hexdigest()


class Work5ContractFixtureTest(unittest.TestCase):
    def test_contract_fixture_is_self_consistent(self) -> None:
        contract = load_contract()
        self.assertEqual(contract["schema"], "piccard-work5-phase1-contract-v2")
        self.assertEqual(contract["control"], {
            "k": 128, "m": 64, "n": 1000, "U": 16384,
            "target_jaccard": "0.5", "seed": 7,
            "timing_trials": 1, "accuracy_trials": 1, "executed_trials": 3,
        })
        self.assertEqual(contract["control_cell"], {
            "axis": "control", "axis_value": None,
            "cell_id_format": "{suite}::control",
        })
        self.assertEqual(contract["parameter_axes"], {
            "k": [16, 32, 64, 128, 256, 512],
            "m": [16, 32, 64, 128, 256],
            "n": [100, 1000, 10000, 100000],
            "U": [16384, 65536],
        })
        self.assertEqual(contract["allowed_universes"], [16384, 65536])
        self.assertEqual(contract["excluded_universes"], [262144, 1048576])

        cells = frozen_parameter_cells(contract)
        keys = [parameter_cell_key(cell) for cell in cells]
        self.assertEqual(keys, contract["expected_parameter_cell_keys"])
        self.assertEqual(matrix_key_digest(keys),
                         contract["expected_parameter_cell_key_sha256"])
        self.assertEqual(len(keys), 61)
        self.assertEqual(len(set(keys)), len(keys))
        self.assertEqual(len({cell["cell_id"] for cell in cells}), len(cells))
        self.assertEqual(sum(cell["security"] == "STD128" for cell in cells), 37)
        self.assertEqual(sum(cell["security"] == "STD192" for cell in cells), 24)
        self.assertEqual(
            [cell["cell_id"] for cell in cells],
            [key.split("|", 1)[0] for key in contract["expected_parameter_cell_keys"]],
        )

        control = contract["control"]
        suite_by_id = {suite["id"]: suite for suite in contract["suites"]}
        for cell in cells:
            suite = suite_by_id[cell["suite"]]
            self.assertEqual(set(suite["applicability"]), set(AXES))
            self.assertEqual(
                [axis for axis in AXES if suite["applicability"][axis]],
                suite["applicable_axes"],
            )
            if cell["axis"] == "control":
                self.assertIsNone(cell["axis_value"])
                self.assertEqual(cell["cell_id"], f"{cell['suite']}::control")
                self.assertEqual({axis: cell[axis] for axis in AXES},
                                 {axis: control[axis] for axis in AXES})
            else:
                self.assertIn(cell["axis"], suite["applicable_axes"])
                self.assertEqual(cell["cell_id"],
                                 f"{cell['suite']}::{cell['axis']}={cell['axis_value']}")
                self.assertIn(cell["axis_value"],
                              contract["parameter_axes"][cell["axis"]])
                self.assertNotEqual(cell["axis_value"], control[cell["axis"]])
                for axis in AXES:
                    self.assertEqual(cell[axis],
                                     cell["axis_value"] if axis == cell["axis"]
                                     else control[axis])
        self.assertEqual(sum(suite["planned_cells"] for suite in contract["suites"]
                             if suite["profile"].startswith("work5-std128")), 37)
        self.assertEqual(sum(suite["planned_cells"] for suite in contract["suites"]
                             if suite["profile"].startswith("work5-std192")), 24)
        self.assertEqual(len(contract["required_precheck_skips"]), 10)
        self.assertEqual(len([item for item in contract["required_precheck_skips"]
                              if item["reason_code"] == "PROJECTED_RUNTIME_CAP"]), 2)
        self.assertEqual(len([item for item in contract["required_precheck_skips"]
                              if item["reason_code"] == "WORKLOAD_GEOMETRY"]), 8)
        self.assertEqual(contract["terminal_statuses"],
                         ["MEASURED", "SKIPPED_PRECHECK", "ERROR"])
        self.assertEqual(contract["hard_exclusions"], {
            "threshold": True,
            "bcg12_std192": True,
            "fhe_ind_comparison_eligible": False,
            "sj16_cost_scope": "component-lower-bound",
            "sj16_secure_division_included": False,
        })
        self.assertEqual(contract["lifecycle"], {
            "preflight_before_keygen": True,
            "timeout_status": "ERROR",
            "timeout_reason_code": "TIMEOUT",
            "refuse_existing_results_root": True,
            "resume_rejects_hash_mismatch": True,
            "terminal_cells_never_rerun": True,
        })


class Work5RunnerContractTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.assertTrue(
            RUNNER.is_file(),
            "Phase 3 entity absent: scripts/run_work5_benchmarks.py is required",
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

    def run_runner(self, phase: str, results_root: Path,
                   *, env: dict[str, str] | None = None,
                   resume: bool = False) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged.update({
            "PICCARD_WORK5_FAKE_EVENT_LOG": str(self.events),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        if env:
            merged.update(env)
        command = [
            "python3", str(RUNNER), f"--phase={phase}",
            f"--build-dir={self.build}", f"--results-root={results_root}",
            "--seed=7", "--threads=2",
        ]
        if resume:
            command.append("--resume")
        return subprocess.run(command, cwd=ROOT, env=merged, text=True,
                              capture_output=True, check=False)

    def assert_parameter_matrix(self, results_root: Path) -> list[dict[str, Any]]:
        contract = load_contract()
        run = json.loads((results_root / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run["schema"], "piccard-work5-run-v1")
        self.assertEqual(run["trials"], 1)
        self.assertEqual(run["accuracy_trials"], 1)
        self.assertTrue((results_root / "matrix.json").is_file())
        records = read_jsonl(results_root / "cells.jsonl")
        expected_cells = frozen_parameter_cells(contract)
        self.assertEqual(Counter(record["security"] for record in records),
                         Counter(contract["parameter_cell_counts"]))
        self.assertEqual(len(records), 61)
        self.assertEqual([parameter_cell_key(record) for record in records],
                         contract["expected_parameter_cell_keys"])
        self.assertEqual(len({record["cell_id"] for record in records}),
                         len(records))

        expected_suites = {suite["id"]: suite for suite in contract["suites"]}
        observed_suites: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record, expected_cell in zip(records, expected_cells):
            self.assertEqual({field: record[field] for field in (
                "cell_id", "profile", "suite", "security", "axis", "axis_value",
                "k", "m", "n", "U",
            )}, expected_cell)
            self.assertIn(record["status"], contract["terminal_statuses"])
            self.assertIn(record["suite"], expected_suites)
            expected = expected_suites[record["suite"]]
            observed_suites[record["suite"]].append(record)
            self.assertEqual(record["profile"], expected["profile"])
            self.assertEqual(record["methods"], expected["methods"])
            self.assertEqual(str(record["target_jaccard"]),
                             contract["control"]["target_jaccard"])
            self.assertEqual(record["seed"], contract["control"]["seed"])
            self.assertEqual(record["applicability"], expected["applicability"])
            self.assertEqual(record["profile_comparison_eligible"],
                             contract["profile_comparison_eligible"])
            self.assertEqual(set(record["taxonomy"]), set(record["methods"]))
            expected_taxonomy: dict[str, dict[str, Any]] = {}
            for method in record["methods"]:
                method_taxonomy = dict(contract["taxonomy"][method])
                semantic = method_taxonomy["semantic_comparison_eligible"]
                if isinstance(semantic, dict):
                    method_taxonomy["semantic_comparison_eligible"] = semantic[
                        record["security"]]
                expected_taxonomy[method] = method_taxonomy
            self.assertEqual(record["taxonomy"], expected_taxonomy)
            self.assertIn(record["U"], contract["allowed_universes"])
            self.assertNotIn(record["U"], contract["excluded_universes"])
            self.assertTrue(contract["hard_exclusions"]["threshold"])
            self.assertTrue(all("threshold" not in method.lower()
                                for method in record["methods"]))
            if contract["hard_exclusions"]["bcg12_std192"] and \
                    record["security"] == "STD192":
                self.assertTrue(all("bcg12" not in method
                                    for method in record["methods"]))
            if "fhe_ind" in record["methods"]:
                self.assertEqual(
                    record["taxonomy"]["fhe_ind"]["semantic_comparison_eligible"],
                    contract["hard_exclusions"]["fhe_ind_comparison_eligible"],
                )
                self.assertFalse(record["taxonomy"]["fhe_ind"]
                                 ["secure_division_included"])
            if "sj16" in record["methods"]:
                self.assertEqual(record["taxonomy"]["sj16"]["cost_scope"],
                                 contract["hard_exclusions"]["sj16_cost_scope"])
                self.assertEqual(record["taxonomy"]["sj16"]
                                 ["secure_division_included"],
                                 contract["hard_exclusions"]
                                 ["sj16_secure_division_included"])
            self.assert_record_status_schema(record, contract)

        for suite_id, expected in expected_suites.items():
            self.assertEqual(len(observed_suites[suite_id]),
                             expected["planned_cells"], suite_id)
        self.assertFalse(any(record["status"] == "ERROR" for record in records))

        required = {
            (item["suite"], item["axis"], item["axis_value"]): item
            for item in contract["required_precheck_skips"]
        }
        observed_required = {}
        for record in records:
            key = (record["suite"], record["axis"], record["axis_value"])
            if key not in required:
                continue
            observed_required[key] = record
            self.assertEqual(record["status"], "SKIPPED_PRECHECK")
            self.assertEqual(record["reason_code"], required[key]["reason_code"])
            self.assertFalse(record["keygen_started"])
            self.assertFalse(record["measurement_started"])
            self.assertIsNone(record["csv_path"])
            self.assertIsNone(record["csv_sha256"])
            self.assertIsNone(record["trace_path"])
            self.assertIsNone(record["trace_sha256"])
            self.assertIsNone(record["workload_path"])
            self.assertIsNone(record["workload_sha256"])
        self.assertEqual(set(observed_required), set(required))

        payloads: dict[tuple[Any, ...], set[str]] = defaultdict(set)
        for record in records:
            key = (
                record["security"], record["axis"], record["axis_value"],
                record["k"], record["m"], record["n"], record["U"],
                target_value(record), record["seed"],
            )
            payloads[key].add(record["trial_payload_sha256"])
        for key, digests in payloads.items():
            if sum(1 for record in records if (
                    record["security"], record["axis"], record["axis_value"],
                    record["k"], record["m"], record["n"], record["U"],
                    target_value(record), record["seed"],
            ) == key) > 1:
                self.assertEqual(len(digests), 1, key)
        return records

    def assert_record_status_schema(self, record: dict[str, Any],
                                    contract: dict[str, Any]) -> None:
        schema = contract["status_schema"]
        for field in schema["required_fields"]:
            self.assertIn(field, record, field)
        self.assertIsInstance(record["argv"], list)
        self.assertIsInstance(record["environment"], dict)
        self.assertIsInstance(record["started_at_utc"], str)
        self.assertIsInstance(record["ended_at_utc"], str)
        self.assertRegex(record["trial_payload_sha256"], r"^[0-9a-f]{64}$")
        for flag in ("preflight_started", "workload_started", "context_started",
                     "keygen_started", "measurement_started"):
            self.assertIsInstance(record[flag], bool)
        for path_field, hash_field in schema["artifact_pairs"]:
            path, digest = record[path_field], record[hash_field]
            self.assertEqual(path is None, digest is None,
                             f"{path_field}/{hash_field} must be paired")
            if path is not None:
                self.assertIsInstance(path, str)
                self.assertFalse(Path(path).is_absolute())
                self.assertNotIn("..", Path(path).parts)
                self.assertRegex(digest, r"^[0-9a-f]{64}$")

        status = record["status"]
        if status == "MEASURED":
            expected = schema["measured"]
            self.assertEqual({name: record[name] for name in expected["flags"]},
                             expected["flags"])
            self.assertEqual(record["exit_code"], expected["exit_code"])
            self.assertEqual(record["measured_trials"], expected["measured_trials"])
            self.assertEqual(record["reason_code"], expected["reason_code"])
            self.assertIsNone(record["reason_detail"])
            self.assertTrue(expected["all_artifacts"] == "present")
            for path_field, hash_field in schema["artifact_pairs"]:
                self.assertIsNotNone(record[path_field])
                self.assertIsNotNone(record[hash_field])
        elif status == "SKIPPED_PRECHECK":
            expected = schema["skipped_precheck"]
            self.assertEqual({name: record[name] for name in expected["flags"]},
                             expected["flags"])
            self.assertEqual(record["exit_code"], expected["exit_code"])
            self.assertEqual(record["measured_trials"], expected["measured_trials"])
            self.assertIn(record["reason_code"],
                          contract["allowed_precheck_reason_codes"])
            self.assertIsInstance(record["reason_detail"], str)
            self.assertTrue(record["reason_detail"])
            self.assertEqual(expected["command_log_artifacts"], "present")
            for path_field, hash_field in schema["artifact_pairs"][:3]:
                self.assertIsNotNone(record[path_field])
                self.assertIsNotNone(record[hash_field])
            self.assertEqual(expected["output_artifacts"], "null")
            for path_field, hash_field in schema["artifact_pairs"][3:]:
                self.assertIsNone(record[path_field])
                self.assertIsNone(record[hash_field])
        else:
            expected = schema["error"]
            self.assertEqual({name: record[name]
                              for name in expected["minimum_flags"]},
                             expected["minimum_flags"])
            self.assertEqual(record["measured_trials"], expected["measured_trials"])
            self.assertEqual(expected["exit_code"], "nonzero")
            self.assertIsInstance(record["exit_code"], int)
            self.assertNotEqual(record["exit_code"], 0)
            self.assertIn(record["reason_code"],
                          contract["allowed_error_reason_codes"])
            self.assertIsInstance(record["reason_detail"], str)
            self.assertTrue(record["reason_detail"])
            self.assertEqual(expected["command_log_artifacts"], "present")
            for path_field, hash_field in schema["artifact_pairs"][:3]:
                self.assertIsNotNone(record[path_field])
                self.assertIsNotNone(record[hash_field])
            self.assertEqual(expected["output_artifacts"], "null-or-paired")

    def test_parameter_run_materializes_only_the_frozen_matrix(self) -> None:
        results = self.tmp / "work5-parameters"
        run = self.run_runner("parameters", results)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assert_parameter_matrix(results)

    def test_geometry_preflight_cannot_reach_the_keygen_command_sentinel(self) -> None:
        results = self.tmp / "work5-preflight"
        sentinel = self.tmp / "keygen-sentinel"
        run = self.run_runner(
            "parameters", results,
            env={
                "PICCARD_WORK5_FAKE_FORBID_ARGUMENT": "--set-size=100000",
                "PICCARD_WORK5_FAKE_FORBID_COMBINATION":
                    "--methods=sj16|--universe=65536",
                "PICCARD_WORK5_FAKE_KEYGEN_SENTINEL": str(sentinel),
            },
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(sentinel.exists())
        self.assert_parameter_matrix(results)
        events = read_jsonl(self.events)
        self.assertFalse(any("--set-size=100000" in event["argv"]
                             for event in events))
        self.assertFalse(any(
            "--methods=sj16" in event["argv"] and
            "--universe=65536" in event["argv"]
            for event in events
        ))
        self.assertTrue(load_contract()["lifecycle"]["preflight_before_keygen"])

    def test_timeout_is_terminal_error_not_a_precheck_skip(self) -> None:
        results = self.tmp / "work5-timeout"
        started = time.monotonic()
        run = self.run_runner("toy", results,
                              env={
                                  "PICCARD_WORK5_FAKE_MODE": "sleep",
                                  "PICCARD_WORK5_FAKE_SLEEP_SECONDS": "1.0",
                                  "PICCARD_WORK5_TEST_CELL_TIMEOUT_SECONDS": "0.05",
                              })
        elapsed = time.monotonic() - started
        self.assertNotEqual(run.returncode, 0)
        self.assertLess(elapsed, 0.75,
                        "runner did not exercise subprocess timeout handling")
        records = read_jsonl(results / "cells.jsonl")
        self.assertTrue(records)
        lifecycle = load_contract()["lifecycle"]
        self.assertTrue(any(record["status"] == "ERROR" and
                            record["reason_code"] == lifecycle["timeout_reason_code"]
                            for record in records))
        self.assertFalse(any(record["status"] == "SKIPPED_PRECHECK" and
                             record["reason_code"] == lifecycle["timeout_reason_code"]
                             for record in records))
        self.assertTrue(any(event["argv"] for event in read_jsonl(self.events)))
        self.assertEqual(lifecycle["timeout_status"], "ERROR")

    def test_existing_results_are_never_overwritten_without_resume(self) -> None:
        results = self.tmp / "preexisting"
        results.mkdir()
        marker = results / "marker"
        marker.write_text("preserve\n", encoding="utf-8")
        run = self.run_runner("toy", results)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
        self.assertIn("resume", run.stderr.lower())
        self.assertTrue(load_contract()["lifecycle"]["refuse_existing_results_root"])

    def test_resume_rejects_hash_drift_and_never_reruns_terminal_cells(self) -> None:
        results = self.tmp / "work5-resume"
        first = self.run_runner("parameters", results)
        self.assertEqual(first.returncode, 0, first.stderr)
        before = self.events.read_bytes()
        resumed = self.run_runner("parameters", results, resume=True)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(self.events.read_bytes(), before)

        matrix = results / "matrix.json"
        matrix.write_bytes(matrix.read_bytes() + b" ")
        rejected = self.run_runner("parameters", results, resume=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("hash", rejected.stderr.lower())
        self.assertEqual(self.events.read_bytes(), before)
        lifecycle = load_contract()["lifecycle"]
        self.assertTrue(lifecycle["resume_rejects_hash_mismatch"])
        self.assertTrue(lifecycle["terminal_cells_never_rerun"])


if __name__ == "__main__":
    unittest.main()
