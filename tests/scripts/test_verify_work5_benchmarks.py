#!/usr/bin/env python3
"""RED fail-closed contracts for the Work #5 evidence verifier.

The verifier is deliberately exercised through a fresh runner-produced root,
then through one semantic mutation at a time.  Until Phase 3 supplies the
runner and verifier, failures are intentionally attributed only to those
missing entities.
"""

from __future__ import annotations

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
            ["python3", str(VERIFIER), str(results), "--require-phase=parameters",
             "--allow-test-fixture"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    def test_semantic_verifier_registers_both_piccard_m_extra_suites(self) -> None:
        expected = {
            "work5-std128-piccard-m-extra":
                ("work5-std128-t40-single-trial", ["piccard"], 1, 1),
            "work5-std192-piccard-m-extra":
                ("work5-std192-t40-single-trial", ["piccard"], 1, 1),
        }
        self.assertEqual({name: review_verifier.SUITES[name] for name in expected}, expected)

    def test_valid_parameter_root_passes(self) -> None:
        results = self.produce_parameter_root("valid")
        verified = self.verify(results)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        production = subprocess.run(
            ["python3", str(VERIFIER), str(results), "--require-phase=parameters"],
            cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertNotEqual(production.returncode, 0)

    def test_root_binding_exact_argv_and_orphan_inventory_fail_even_when_rehashed(self) -> None:
        source = self.produce_parameter_root("identity-source")
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
        (orphan / "csv" / "orphan.csv").write_text("forged\n", encoding="utf-8")
        self.assertNotEqual(self.verify(orphan).returncode, 0,
                            "orphan producer artifact must not verify")

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
