#!/usr/bin/env python3
"""RED fail-closed contracts for the Work #5 evidence verifier.

The verifier is deliberately exercised through a fresh runner-produced root,
then through one semantic mutation at a time.  Until Phase 3 supplies the
runner and verifier, failures are intentionally attributed only to those
missing entities.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
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

    def produce_parameter_root(self, name: str) -> Path:
        results = self.tmp / name
        environment = os.environ.copy()
        environment.update({
            "PICCARD_WORK5_FAKE_EVENT_LOG": str(self.events),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
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
            ["python3", str(VERIFIER), str(results), "--require-phase=parameters"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    def test_valid_parameter_root_passes(self) -> None:
        results = self.produce_parameter_root("valid")
        verified = self.verify(results)
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_semantic_matrix_mutations_fail_closed(self) -> None:
        source = self.produce_parameter_root("source")

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

        def make_fhe_ind_comparison_eligible(
                rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["fhe_ind"])
            row["taxonomy"]["fhe_ind"]["semantic_comparison_eligible"] = True

        def give_sj16_secure_division(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["sj16"])
            row["taxonomy"]["sj16"]["secure_division_included"] = True

        def change_sj16_cost_scope(rows: list[dict[str, Any]], _: Path) -> None:
            row = next(item for item in rows if item["methods"] == ["sj16"])
            row["taxonomy"]["sj16"]["cost_scope"] = "full-query"

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
            ("fhe-ind-eligible", make_fhe_ind_comparison_eligible),
            ("sj16-secure-division", give_sj16_secure_division),
            ("sj16-cost-scope", change_sj16_cost_scope),
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
        self.assertFalse(contract["hard_exclusions"]
                         ["sj16_secure_division_included"])
        self.assertEqual(contract["hard_exclusions"]["sj16_cost_scope"],
                         "component-lower-bound")


if __name__ == "__main__":
    unittest.main()
