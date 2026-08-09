#!/usr/bin/env python3
"""RED contracts for the Work #5 single-trial benchmark runner.

The tests use a command sentinel rather than an FHE test double.  They pin the
runner's matrix and fail-closed lifecycle without accepting synthetic timing as
evidence.  Until Phase 3 adds ``scripts/run_work5_benchmarks.py``, each
lifecycle test intentionally fails at the missing-runner boundary.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
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


class Work5ContractFixtureTest(unittest.TestCase):
    def test_contract_fixture_is_self_consistent(self) -> None:
        contract = load_contract()
        self.assertEqual(contract["schema"], "piccard-work5-phase1-contract-v1")
        self.assertEqual(sum(suite["planned_cells"] for suite in contract["suites"]
                             if suite["profile"].startswith("work5-std128")), 37)
        self.assertEqual(sum(suite["planned_cells"] for suite in contract["suites"]
                             if suite["profile"].startswith("work5-std192")), 24)
        self.assertEqual(len(contract["required_precheck_skips"]), 10)
        self.assertEqual(len([item for item in contract["required_precheck_skips"]
                              if item["reason_code"] == "PROJECTED_RUNTIME_CAP"]), 2)
        self.assertEqual(len([item for item in contract["required_precheck_skips"]
                              if item["reason_code"] == "WORKLOAD_GEOMETRY"]), 8)


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
        self.assertEqual(Counter(record["security"] for record in records),
                         Counter(contract["parameter_cell_counts"]))
        self.assertEqual(len(records), 61)

        expected_suites = {suite["id"]: suite for suite in contract["suites"]}
        observed_suites: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            self.assertIn(record["status"], contract["terminal_statuses"])
            self.assertIn(record["suite"], expected_suites)
            expected = expected_suites[record["suite"]]
            observed_suites[record["suite"]].append(record)
            self.assertEqual(record["profile"], expected["profile"])
            self.assertEqual(record["methods"], expected["methods"])
            self.assertIn(record["axis"], expected["applicable_axes"])
            self.assertIn("applicability", record)
            self.assertIn(record["U"], contract["allowed_universes"])
            self.assertNotIn(record["U"], contract["excluded_universes"])
            self.assertTrue(all("threshold" not in method.lower()
                                for method in record["methods"]))
            if record["security"] == "STD192":
                self.assertTrue(all("bcg12" not in method
                                    for method in record["methods"]))
            if record["status"] == "MEASURED":
                self.assertEqual(record["measured_trials"], 1)
            else:
                self.assertEqual(record["measured_trials"], 0)
            self.assertIn("trial_payload_sha256", record)
            self.assertEqual(len(record["trial_payload_sha256"]), 64)

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
            self.assertFalse(record.get("csv_path"))
            self.assertFalse(record.get("trace_path"))
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
                "PICCARD_WORK5_FAKE_KEYGEN_SENTINEL": str(sentinel),
            },
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(sentinel.exists())
        self.assert_parameter_matrix(results)
        events = read_jsonl(self.events)
        self.assertFalse(any("--set-size=100000" in event["argv"]
                             for event in events))

    def test_timeout_is_terminal_error_not_a_precheck_skip(self) -> None:
        results = self.tmp / "work5-timeout"
        run = self.run_runner("toy", results,
                              env={"PICCARD_WORK5_FAKE_MODE": "timeout"})
        self.assertNotEqual(run.returncode, 0)
        records = read_jsonl(results / "cells.jsonl")
        self.assertTrue(records)
        self.assertTrue(any(record["status"] == "ERROR" and
                            record["reason_code"] == "TIMEOUT"
                            for record in records))
        self.assertFalse(any(record["status"] == "SKIPPED_PRECHECK" and
                             record["reason_code"] == "TIMEOUT"
                             for record in records))

    def test_existing_results_are_never_overwritten_without_resume(self) -> None:
        results = self.tmp / "preexisting"
        results.mkdir()
        marker = results / "marker"
        marker.write_text("preserve\n", encoding="utf-8")
        run = self.run_runner("toy", results)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
        self.assertIn("resume", run.stderr.lower())

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


if __name__ == "__main__":
    unittest.main()
