#!/usr/bin/env python3
"""RED contracts for the Work #5 single-trial benchmark runner.

The tests use a command sentinel rather than an FHE test double.  They pin the
runner's matrix and fail-closed lifecycle without accepting synthetic timing as
evidence.  Until Phase 3 adds ``scripts/run_work5_benchmarks.py``, each
lifecycle test intentionally fails at the missing-runner boundary.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import run_work5_benchmarks as work5_runner
import verify_work5_benchmarks as work5_verifier
RUNNER = ROOT / "scripts" / "run_work5_benchmarks.py"
CONTRACT = ROOT / "tests" / "fixtures" / "work5" / "single_trial_contract.json"

# Phase 6A deliberately keeps this test oracle local.  The runner and the
# verifier each carry their own literal production tuple, so a shared test
# fixture must not silently become their schema source.
DYNAMIC_CSV_HEADER = tuple(
    "label,k,m,set_size,ring_dim,depth,phase_init_ms,phase_insert_ms,"
    "phase_delete_ms,phase_signature_ms,phase_encode_ms,phase_encrypt_ms,"
    "phase_compute_ms,phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,"
    "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
    "ops_insert_per_sec,ops_delete_per_sec,trials,total_ms_sd,total_ms_median,"
    "phase_init_ms_sd,phase_init_ms_median,phase_insert_ms_sd,"
    "phase_insert_ms_median,phase_delete_ms_sd,phase_delete_ms_median,"
    "phase_signature_ms_sd,phase_signature_ms_median,phase_encode_ms_sd,"
    "phase_encode_ms_median,phase_encrypt_ms_sd,phase_encrypt_ms_median,"
    "phase_compute_ms_sd,phase_compute_ms_median,phase_decrypt_ms_sd,"
    "phase_decrypt_ms_median,rel_error_eligible_n,hash_randomness,hash_seed,"
    "hash_root_seed,accuracy_trials,phase_flood_ms,phase_flood_ms_sd,"
    "phase_flood_ms_median,transcript_stat_bits,max_queries,query_stat_bits,"
    "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,flood_noise_bits,"
    "scaling_mod_size,sanitizer_model,sanitizer_assurance,estimator_model,"
    "profile_id,run_class,target_security_bits,comparison_eligible,"
    "measurement_kind,actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
    "openfhe_version,dynamic_scenario,updates_requested,updates_applied,"
    "initial_epoch,final_epoch,owner_b_unchanged,ciphertext_upload_count,"
    "local_inner_product,decrypted_inner_product,correctness_status,"
    "refresh_owner_set_id,refresh_updates,refresh_epoch_before,"
    "refresh_epoch_after,refresh_status,phase_refresh_update_ms,"
    "phase_refresh_signature_ms,phase_refresh_encode_ms,"
    "phase_refresh_encrypt_ms,phase_refresh_serialize_ms,"
    "phase_cloud_replace_ms,refresh_total_ms,refresh_upload_bytes,"
    "refresh_ciphertexts_uploaded,refresh_context_fingerprint,"
    "refresh_public_key_fingerprint".split(",")
)


def dynamic_refresh_values(updates: int) -> dict[str, str]:
    """Return one syntactically complete, non-performance dynamic row."""
    values = {name: "0.000" for name in DYNAMIC_CSV_HEADER}
    values.update({
        "label": f"refresh_owner_a_0_to_{updates}", "k": "16", "m": "16",
        "set_size": "100", "ring_dim": "1024", "depth": "5",
        "memory_bytes": "0", "ct_size_bytes": "1", "trials": "1",
        "rel_error_eligible_n": "1", "hash_randomness": "fixed",
        "hash_seed": "7", "hash_root_seed": "7", "accuracy_trials": "0",
        "transcript_stat_bits": "40", "max_queries": "1048576",
        "query_stat_bits": "60", "coefficient_stat_bits": "70",
        "flood_margin_bits": "8", "eval_noise_bits": "56", "flood_noise_bits": "134",
        "scaling_mod_size": "40", "sanitizer_model": "phase-smudging-enc0-poc-v1",
        "sanitizer_assurance": "empirical-phase-statistical+ciphertext-computational",
        "estimator_model": "sha256-random-ranking-poc-v1", "profile_id": "toy-smoke",
        "run_class": "smoke", "target_security_bits": "0",
        "comparison_eligible": "false", "measurement_kind": "diagnostic",
        "actual_ring_dim": "1024", "log_q_bits": "160.000", "plaintext_modulus": "12289",
        "num_limbs": "4", "openfhe_version": "1.5.0", "dynamic_scenario": "refresh",
        "updates_requested": str(updates), "updates_applied": str(updates),
        "initial_epoch": "0", "final_epoch": str(updates), "owner_b_unchanged": "true",
        "ciphertext_upload_count": str(updates), "local_inner_product": "7",
        "decrypted_inner_product": "7", "correctness_status": "PASS",
        "refresh_owner_set_id": "owner-a", "refresh_updates": str(updates),
        "refresh_epoch_before": "0", "refresh_epoch_after": str(updates),
        "refresh_status": "applied", "refresh_upload_bytes": "1",
        "refresh_ciphertexts_uploaded": str(updates),
        "refresh_context_fingerprint": "a" * 64,
        "refresh_public_key_fingerprint": "b" * 63 + str(updates),
    })
    for name in ("total_ms_sd", "phase_init_ms_sd", "phase_insert_ms_sd",
                 "phase_delete_ms_sd", "phase_signature_ms_sd", "phase_encode_ms_sd",
                 "phase_encrypt_ms_sd", "phase_compute_ms_sd", "phase_decrypt_ms_sd",
                 "phase_flood_ms_sd"):
        values[name] = "-1.000"
    values["ops_insert_per_sec"] = values["ops_delete_per_sec"] = "0.0"
    return values
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
STAGE_ORDER = ("preflight_started", "context_started", "workload_started",
               "keygen_started", "measurement_started")


def stage_flags(*started: bool) -> dict[str, bool]:
    return dict(zip(STAGE_ORDER, started))


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
            "control_cell_id": suite["control_cell_id"],
        }
        if suite["owns_control"]:
            cells.append(base)
        for axis in suite["applicable_axes"]:
            for value in suite["axis_values"][axis]:
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
    def test_toy_producer_command_is_frozen(self) -> None:
        root = ROOT / ".omo" / "evidence" / "test-toy-command"
        argv = work5_runner.planned_toy_argv(ROOT / "build", root)
        self.assertEqual(work5_runner.TOY_CELL, {
            "cell_id": "toy-smoke", "suite": "toy-smoke", "profile": "toy-smoke",
            "security": "TOY", "k": 16, "m": 16, "n": 10, "U": 64,
            "methods": ["piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
                        "bcg12_exact_ec", "sj16"],
        })
        self.assertEqual(argv[1:14], [
            "--suite=toy-smoke", "--profile=toy-smoke", "--k=16", "--m=16",
            "--set-size=10", "--universe=64", "--target-jaccard=0.5",
            "--trials=1", "--accuracy-trials=1", "--seed=7",
            "--methods=piccard,piccard_sqrt,fhe_ind,bcg12_mh_ec,bcg12_exact_ec,sj16",
            "--sj16-key-bits=1024", "--allow-unmatched-security",
        ])
        self.assertTrue(argv[-2].endswith("/.tmp/toy-smoke/workload.manifest.bin"))
        self.assertTrue(argv[-1].endswith("/.tmp/toy-smoke/execution.trace.bin"))

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
        self.assertEqual(contract["sqrt_supported_m"], [16, 64, 256])
        self.assertEqual([suite["id"] for suite in contract["suites"]], [
            "work5-std128-piccard", "work5-std128-piccard-m-extra",
            "work5-std128-fhe-ind", "work5-std128-bcg12-mh",
            "work5-std128-bcg12-exact", "work5-std128-sj16",
            "work5-std192-piccard", "work5-std192-piccard-m-extra",
            "work5-std192-fhe-ind", "work5-std192-sj16",
        ])

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
                self.assertTrue(suite["owns_control"])
                self.assertIsNone(cell["control_cell_id"])
                self.assertIsNone(cell["axis_value"])
                self.assertEqual(cell["cell_id"], f"{cell['suite']}::control")
                self.assertEqual({axis: cell[axis] for axis in AXES},
                                 {axis: control[axis] for axis in AXES})
            else:
                self.assertIn(cell["axis"], suite["applicable_axes"])
                self.assertEqual(cell["cell_id"],
                                 f"{cell['suite']}::{cell['axis']}={cell['axis_value']}")
                self.assertIn(cell["axis_value"], suite["axis_values"][cell["axis"]])
                if suite["owns_control"]:
                    self.assertNotEqual(cell["axis_value"], control[cell["axis"]])
                    self.assertIsNone(cell["control_cell_id"])
                else:
                    self.assertEqual(cell["control_cell_id"], suite["control_cell_id"])
                for axis in AXES:
                    self.assertEqual(cell[axis],
                                     cell["axis_value"] if axis == cell["axis"]
                                     else control[axis])
        for suite in contract["suites"]:
            has_sqrt = any(method in {"piccard_sqrt", "piccard_sqrt_encode"}
                           for method in suite["methods"])
            if has_sqrt:
                self.assertEqual(suite["axis_values"].get("m"),
                                 contract["sqrt_supported_m"])
            if suite["id"].endswith("-m-extra"):
                expected_method = (["piccard_encode"] if suite["profile"].startswith("work5-std192")
                                   else ["piccard"])
                self.assertEqual(suite["methods"], expected_method)
                self.assertFalse(suite["owns_control"])
                self.assertEqual(suite["axis_values"], {"m": [32, 128]})
        by_id = {cell["cell_id"]: cell for cell in cells}
        m_extra_cells = [cell for cell in cells if cell["suite"].endswith("-m-extra")]
        self.assertEqual([(cell["suite"], cell["axis"], cell["axis_value"])
                          for cell in m_extra_cells], [
                              ("work5-std128-piccard-m-extra", "m", 32),
                              ("work5-std128-piccard-m-extra", "m", 128),
                              ("work5-std192-piccard-m-extra", "m", 32),
                              ("work5-std192-piccard-m-extra", "m", 128),
                          ])
        for cell in m_extra_cells:
            self.assertIn(cell["control_cell_id"], by_id)
            self.assertEqual(by_id[cell["control_cell_id"]]["profile"], cell["profile"])
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
            "fhe_ind_protocol_model": "local-universe-sized-BFV-comparator",
            "fhe_ind_comparison_scope": "diagnostic-only",
            "sj16_cost_scope": "full-query-excluding-one-time-setup",
            "sj16_comparison_scope": "component-lower-bound",
            "sj16_secure_division_included": False,
            "std192_piccard_encoding_only": True,
            "std192_piccard_context_started": False,
            "std192_piccard_keygen_started": False,
            "std192_piccard_forbidden_context_artifacts": True,
            "std192_piccard_forbidden_fhe_timing_columns": True,
        })
        # The producer keeps SJ16's full-query timing boundary while retaining
        # its lower-bound comparison scope.  Phase 1 must not rewrite Work #4.
        self.assertEqual(contract["hard_exclusions"]["sj16_cost_scope"],
                         "full-query-excluding-one-time-setup")
        self.assertEqual(
            contract["taxonomy"]["fhe_ind"]["protocol_model"],
            contract["hard_exclusions"]["fhe_ind_protocol_model"],
        )
        lifecycle = contract["lifecycle"]
        self.assertEqual({key: lifecycle[key] for key in (
            "preflight_before_keygen", "timeout_status", "timeout_reason_code",
            "phase_cap_reason_code",
            "refuse_existing_results_root", "resume_rejects_hash_mismatch",
            "terminal_cells_never_rerun",
        )}, {
            "preflight_before_keygen": True,
            "timeout_status": "ERROR",
            "timeout_reason_code": "TIMEOUT",
            "phase_cap_reason_code": "PHASE_CAP_EXHAUSTED",
            "refuse_existing_results_root": True,
            "resume_rejects_hash_mismatch": True,
            "terminal_cells_never_rerun": True,
        })
        self.assertEqual(lifecycle["stage_order"], list(STAGE_ORDER))
        self.assertEqual(lifecycle["error_scenarios"], {
            "timeout_after_admission": {
                "reason_code": "TIMEOUT",
                "flags": stage_flags(True, True, True, True, True),
            },
            "pre_setup": {
                "reason_code": "EXCEPTION",
                "flags": stage_flags(True, True, False, False, False),
            },
            "setup": {
                "reason_code": "EXCEPTION",
                "flags": stage_flags(True, True, True, True, False),
            },
        })
        self.assertEqual(lifecycle["test_hooks"], {
            "force_precheck_reason": "PICCARD_WORK5_TEST_FORCE_PRECHECK_REASON",
            "force_precheck_cell": "PICCARD_WORK5_TEST_FORCE_PRECHECK_CELL",
            "force_error_stage": "PICCARD_WORK5_TEST_FORCE_ERROR_STAGE",
            "force_error_cell": "PICCARD_WORK5_TEST_FORCE_ERROR_CELL",
            "subprocess_timeout_seconds": "PICCARD_WORK5_TEST_SUBPROCESS_TIMEOUT_SECONDS",
        })
        schema = contract["status_schema"]
        self.assertEqual(schema["measured"]["flags"],
                         stage_flags(True, True, True, True, True))
        self.assertEqual(schema["skipped_precheck"]["stage_flags_by_reason"], {
            "WORKLOAD_GEOMETRY": stage_flags(True, False, False, False, False),
            "PROJECTED_RUNTIME_CAP": stage_flags(True, False, False, False, False),
            "RING_DIM_CAP": stage_flags(True, True, False, False, False),
            "DEPTH_CAP": stage_flags(True, True, False, False, False),
            "LOGQ_CAP": stage_flags(True, True, False, False, False),
        })
        self.assertEqual(schema["error"], {
            "requires_preflight_started": True,
            "monotonic_stage_flags": True,
            "measured_trials": 0,
            "exit_code": "nonzero",
            "command_log_artifacts": "present",
            "output_artifacts": "null-or-paired",
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
                "k", "m", "n", "U", "control_cell_id",
            )}, expected_cell)
            self.assertIn(record["status"], contract["terminal_statuses"])
            self.assertIn(record["suite"], expected_suites)
            expected = expected_suites[record["suite"]]
            observed_suites[record["suite"]].append(record)
            self.assertEqual(record["profile"], expected["profile"])
            self.assertEqual(record["methods"], expected["methods"])
            if record["suite"].endswith("-m-extra"):
                self.assertEqual(record["methods"],
                                 ["piccard_encode"] if record["security"] == "STD192"
                                 else ["piccard"])
                self.assertEqual(record["control_cell_id"],
                                 record["suite"].replace("-m-extra", "") + "::control")
                self.assertFalse(any(key.startswith("control_timing") for key in record))
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
            encoding_only = (record["security"] == "STD192" and
                             set(record["methods"]) <=
                             {"piccard_encode", "piccard_sqrt_encode"})
            if encoding_only:
                self.assertFalse(record["context_started"])
                self.assertFalse(record["keygen_started"])
                self.assertEqual(record["taxonomy"], {
                    method: contract["taxonomy"][method]
                    for method in record["methods"]
                })
                for label in ("context_onehot", "context_sqrt", "context_fhe_ind"):
                    self.assertIsNone(record[f"{label}_path"])
                    self.assertIsNone(record[f"{label}_sha256"])
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
                self.assertEqual(
                    record["taxonomy"]["fhe_ind"]["protocol_model"],
                    contract["hard_exclusions"]["fhe_ind_protocol_model"],
                )
                self.assertEqual(
                    record["taxonomy"]["fhe_ind"]["comparison_scope"],
                    contract["hard_exclusions"]["fhe_ind_comparison_scope"],
                )
                self.assertFalse(record["taxonomy"]["fhe_ind"]
                                 ["secure_division_included"])
            if "sj16" in record["methods"]:
                self.assertEqual(record["taxonomy"]["sj16"]["comparison_scope"],
                                 contract["hard_exclusions"]
                                 ["sj16_comparison_scope"])
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
        self.assertEqual(
            sum(record["reason_code"] == "WORKLOAD_GEOMETRY"
                for record in observed_required.values()), 8)
        self.assertEqual(
            sum(record["reason_code"] == "PROJECTED_RUNTIME_CAP"
                for record in observed_required.values()), 2)

        measured_payloads: dict[tuple[Any, ...], set[str]] = defaultdict(set)
        for record in records:
            key = (
                record["security"], record["axis"], record["axis_value"],
                record["k"], record["m"], record["n"], record["U"],
                target_value(record), record["seed"],
            )
            if record["status"] == "MEASURED":
                measured_payloads[key].add(record["trial_payload_sha256"])
            elif record["status"] == "SKIPPED_PRECHECK":
                self.assertEqual(record["trial_payload_sha256"],
                                 work5_runner.planned_payload_sha256(record))
        for key, digests in measured_payloads.items():
            if sum(1 for record in records if record["status"] == "MEASURED" and (
                    record["security"], record["axis"], record["axis_value"],
                    record["k"], record["m"], record["n"], record["U"],
                    target_value(record), record["seed"],
            ) == key) > 1:
                self.assertEqual(len(digests), 1, key)
        return records

    def test_m_extra_cells_never_invoke_sqrt_or_copy_a_control_timing(self) -> None:
        results = self.tmp / "work5-m-extra"
        run = self.run_runner("parameters", results)
        self.assertEqual(run.returncode, 0, run.stderr)
        records = self.assert_parameter_matrix(results)
        m_extra = [record for record in records if record["suite"].endswith("-m-extra")]
        self.assertEqual(len(m_extra), 4)
        for record in m_extra:
            expected_method = (["piccard_encode"] if record["security"] == "STD192"
                               else ["piccard"])
            self.assertEqual(record["methods"], expected_method)
            self.assertEqual(record["axis"], "m")
            self.assertIn(record["m"], (32, 128))
            self.assertEqual(record["control_cell_id"],
                             record["suite"].replace("-m-extra", "") + "::control")
            self.assertNotIn("piccard_sqrt", " ".join(record["argv"]))
            self.assertFalse(any(field.startswith("control_timing") for field in record))
        events = read_jsonl(self.events)
        m_extra_events = [event for event in events if any(
            arg.startswith("--suite=work5-") and arg.endswith("-piccard-m-extra")
            for arg in event["argv"])]
        # The fixture records both the runner's dispatch boundary and the
        # sentinel process, so each of the four calls appears twice.
        self.assertEqual(len(m_extra_events), 8)
        self.assertTrue(all(any(methods in event["argv"] for methods in
                                ("--methods=piccard", "--methods=piccard_encode")) and
                            "piccard_sqrt" not in " ".join(event["argv"])
                            for event in m_extra_events))

    def assert_stage_flags(self, record: dict[str, Any],
                           expected: dict[str, bool]) -> None:
        self.assertEqual({flag: record[flag] for flag in STAGE_ORDER}, expected)

    def assert_monotonic_stage_flags(self, record: dict[str, Any]) -> None:
        seen_not_started = False
        for flag in STAGE_ORDER:
            self.assertIsInstance(record[flag], bool)
            if not record[flag]:
                seen_not_started = True
            else:
                self.assertFalse(
                    seen_not_started,
                    f"{flag} started after a later-stage predecessor was absent",
                )

    def assert_record_status_schema(self, record: dict[str, Any],
                                    contract: dict[str, Any]) -> None:
        schema = contract["status_schema"]
        for field in schema["required_fields"]:
            self.assertIn(field, record, field)
        self.assertIn(record["status"], contract["terminal_statuses"])
        self.assertIsInstance(record["argv"], list)
        self.assertIsInstance(record["environment"], dict)
        self.assertIsInstance(record["started_at_utc"], str)
        self.assertIsInstance(record["ended_at_utc"], str)
        self.assertRegex(record["trial_payload_sha256"], r"^[0-9a-f]{64}$")
        encoding_only = (record["security"] == "STD192" and
                         set(record["methods"]) <= {"piccard_encode", "piccard_sqrt_encode"})
        if not encoding_only:
            self.assert_monotonic_stage_flags(record)
        self.assertTrue(record["preflight_started"])
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
            expected = schema["encoding_measured" if encoding_only else "measured"]
            self.assert_stage_flags(record, expected["flags"])
            self.assertEqual(record["exit_code"], expected["exit_code"])
            self.assertEqual(record["measured_trials"], expected["measured_trials"])
            self.assertEqual(record["reason_code"], expected["reason_code"])
            self.assertIsNone(record["reason_detail"])
            self.assertEqual(expected["all_artifacts"], "present")
            for path_field, hash_field in schema["artifact_pairs"]:
                self.assertIsNotNone(record[path_field])
                self.assertIsNotNone(record[hash_field])
        elif status == "SKIPPED_PRECHECK":
            expected = schema["skipped_precheck"]
            self.assertEqual(record["exit_code"], expected["exit_code"])
            self.assertEqual(record["measured_trials"], expected["measured_trials"])
            self.assertIn(record["reason_code"],
                          contract["allowed_precheck_reason_codes"])
            self.assertIn(record["reason_code"],
                          expected["stage_flags_by_reason"])
            self.assert_stage_flags(
                record, expected["stage_flags_by_reason"][record["reason_code"]])
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
            self.assertTrue(expected["requires_preflight_started"])
            self.assertTrue(expected["monotonic_stage_flags"])
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
        records = self.assert_parameter_matrix(results)
        events = read_jsonl(self.events)
        context_cells = {event["cell_id"] for event in events
                         if event.get("kind") == "context-preflight"}
        self.assertIn("work5-std128-piccard::control", context_cells)
        self.assertFalse(any(cell.startswith("work5-std192-piccard")
                             for cell in context_cells))
        for record in records:
            if record["security"] == "STD192" and \
                    set(record["methods"]) <= {"piccard_encode", "piccard_sqrt_encode"}:
                self.assertFalse(record["context_started"])
                self.assertFalse(record["keygen_started"])

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
        records = self.assert_parameter_matrix(results)
        self.assertEqual(sum(
            record["status"] == "SKIPPED_PRECHECK" and
            record["reason_code"] == "WORKLOAD_GEOMETRY"
            for record in records
        ), 8)
        self.assertEqual(sum(
            record["status"] == "SKIPPED_PRECHECK" and
            record["reason_code"] == "PROJECTED_RUNTIME_CAP"
            for record in records
        ), 2)
        events = read_jsonl(self.events)
        self.assertFalse(any("--set-size=100000" in event["argv"]
                             for event in events))
        self.assertFalse(any(
            "--methods=sj16" in event["argv"] and
            "--universe=65536" in event["argv"]
            for event in events
        ))
        self.assertTrue(load_contract()["lifecycle"]["preflight_before_keygen"])

    def test_every_method_group_gets_a_cell_local_staging_directory_before_argv(self) -> None:
        results = self.tmp / "work5-staging"
        run = self.run_runner("parameters", results)
        self.assertEqual(run.returncode, 0, run.stderr)
        records = self.assert_parameter_matrix(results)
        for suite in ("work5-std128-bcg12-mh", "work5-std128-sj16"):
            record = next(item for item in records if item["suite"] == suite and
                          item["axis"] == "control")
            staged = results / ".tmp" / record["cell_id"]
            self.assertTrue(staged.is_dir(), f"missing staging directory for {suite}")
            self.assertTrue(any(part == ".tmp" for part in Path(record["argv"][-2].split("=", 1)[1]).parts))

    def test_context_only_bfv_cap_skips_before_workload_or_keygen(self) -> None:
        contract = load_contract()
        lifecycle = contract["lifecycle"]
        results = self.tmp / "work5-context-cap"
        run = self.run_runner(
            "parameters", results,
            env={
                lifecycle["test_hooks"]["force_precheck_reason"]: "RING_DIM_CAP",
                lifecycle["test_hooks"]["force_precheck_cell"]:
                    "work5-std128-piccard::control",
            },
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        records = self.assert_parameter_matrix(results)
        record = next(item for item in records
                      if item["cell_id"] == "work5-std128-piccard::control")
        self.assertEqual(record["status"], "SKIPPED_PRECHECK")
        self.assertEqual(record["reason_code"], "RING_DIM_CAP")
        self.assert_record_status_schema(record, contract)
        self.assert_stage_flags(
            record,
            contract["status_schema"]["skipped_precheck"]
            ["stage_flags_by_reason"]["RING_DIM_CAP"],
        )

    def test_14400_second_phase_preserves_subprocess_wall_timeout(self) -> None:
        results = self.tmp / "work5-timeout"
        started = time.monotonic()
        run = self.run_runner("parameters", results,
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
        contract = load_contract()
        lifecycle = contract["lifecycle"]
        timeout = next(record for record in records
                       if record["status"] == lifecycle["timeout_status"] and
                       record["reason_code"] == lifecycle["timeout_reason_code"])
        self.assert_record_status_schema(timeout, contract)
        self.assert_stage_flags(
            timeout,
            lifecycle["error_scenarios"]["timeout_after_admission"]["flags"],
        )
        self.assertIn("subprocess wall timeout", timeout["reason_detail"])
        run_json = json.loads((results / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run_json["phase_timeout_seconds"]["parameters"], 14400)
        self.assertFalse(any(record["status"] == "SKIPPED_PRECHECK" and
                             record["reason_code"] == lifecycle["timeout_reason_code"]
                             for record in records))
        self.assertTrue(any(event["argv"] for event in read_jsonl(self.events)))
        self.assertEqual(lifecycle["timeout_status"], "ERROR")

    def test_descendant_pipe_holder_cannot_extend_terminal_timeout(self) -> None:
        results = self.tmp / "work5-descendant-pipe"
        pid_path = self.tmp / "escaped-descendant.pid"
        started = time.monotonic()
        try:
            run = self.run_runner("parameters", results, env={
                "PICCARD_WORK5_FAKE_MODE": "descendant_pipe",
                "PICCARD_WORK5_FAKE_SLEEP_SECONDS": "30",
                "PICCARD_WORK5_FAKE_DESCENDANT_PID": str(pid_path),
                "PICCARD_WORK5_TEST_CELL_TIMEOUT_SECONDS": "0.05",
            })
            elapsed = time.monotonic() - started
            self.assertNotEqual(run.returncode, 0)
            self.assertLess(elapsed, 1.5,
                            "escaped descendant pipe held terminalization past its bound")
            records = read_jsonl(results / "cells.jsonl")
            error = next(record for record in records if record["status"] == "ERROR")
            self.assertEqual(error["reason_code"], "TIMEOUT")
            self.assertTrue((results / error["command_path"]).is_file())
            self.assertTrue((results / error["stdout_path"]).is_file())
            self.assertTrue((results / error["stderr_path"]).is_file())
        finally:
            if pid_path.exists():
                try:
                    os.kill(int(pid_path.read_text(encoding="ascii")), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_stalled_provenance_uses_subprocess_wall_timeout_not_phase_cap(self) -> None:
        results = self.tmp / "work5-stalled-provenance"
        started = time.monotonic()
        run = self.run_runner("parameters", results, env={
            "PICCARD_WORK5_TEST_GIT_EXECUTABLE": str(self.build / "bench_comparison"),
            "PICCARD_WORK5_FAKE_MODE": "sleep",
            "PICCARD_WORK5_FAKE_SLEEP_SECONDS": "30",
            "PICCARD_WORK5_TEST_SUBPROCESS_TIMEOUT_SECONDS": "0.05",
        })
        elapsed = time.monotonic() - started
        self.assertNotEqual(run.returncode, 0)
        self.assertLess(elapsed, 1.0, "stalled git was not phase-bounded")
        timeout = json.loads((results / "run-level-timeout.json").read_text())
        self.assertEqual((timeout["status"], timeout["reason_code"], timeout["cell_started"]),
                         ("ERROR", "TIMEOUT", False))
        self.assertIn("subprocess wall timeout", timeout["reason_detail"])
        self.assertEqual(timeout["phase_timeout_seconds"], 14400)
        self.assertFalse((results / "cells.jsonl").exists())
        self.assertFalse((results / "run.json").exists())
        self.assertFalse((results / "matrix.json").exists())

    def test_sigterm_flushes_a_terminal_error_and_stops_the_child(self) -> None:
        results = self.tmp / "work5-sigterm"
        environment = os.environ.copy()
        environment.update({"PICCARD_WORK5_FAKE_EVENT_LOG": str(self.events),
                            "PICCARD_WORK5_FAKE_MODE": "sleep",
                            "PICCARD_WORK5_FAKE_SLEEP_SECONDS": "5",
                            "PYTHONDONTWRITEBYTECODE": "1"})
        process = subprocess.Popen(
            ["python3", str(RUNNER), "--phase=parameters", f"--build-dir={self.build}",
             f"--results-root={results}", "--seed=7", "--threads=2"],
            cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 3
        while not (results / "cells.jsonl").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.15)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0, stderr)
        records = read_jsonl(results / "cells.jsonl")
        self.assertTrue(records)
        error = next(record for record in records if record["status"] == "ERROR")
        self.assertEqual(error["reason_code"], "EXCEPTION")
        self.assertIn("signal", error["reason_detail"])

    def test_exhausted_phase_budget_is_phase_cap_before_subprocess_start(self) -> None:
        results = self.tmp / "work5-phase-cap"
        run = self.run_runner("parameters", results, env={
            "PICCARD_WORK5_TEST_PHASE_TIMEOUT_SECONDS": "0.000001"})
        self.assertNotEqual(run.returncode, 0)
        timeout = json.loads((results / "run-level-timeout.json").read_text())
        self.assertEqual((timeout["status"], timeout["reason_code"], timeout["cell_started"]),
                         ("ERROR", "PHASE_CAP_EXHAUSTED", False))
        self.assertFalse((results / "cells.jsonl").exists())
        self.assertFalse(self.events.exists(), "phase cap must start no producer subprocess")

    def test_existing_fresh_root_is_not_mutated_by_exhausted_phase(self) -> None:
        results = self.tmp / "existing-timeout-root"
        results.mkdir()
        marker = results / "caller-sentinel.txt"
        marker.write_text("preserve this root\n", encoding="utf-8")
        before = {path.relative_to(results): path.read_bytes()
                  for path in results.rglob("*") if path.is_file()}
        run = self.run_runner("parameters", results, env={
            "PICCARD_WORK5_TEST_PHASE_TIMEOUT_SECONDS": "0.000001"})
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("results root already exists", run.stderr)
        after = {path.relative_to(results): path.read_bytes()
                 for path in results.rglob("*") if path.is_file()}
        self.assertEqual(after, before)
        self.assertFalse((results / "run-level-timeout.json").exists())

    def test_invalid_resume_root_is_rejected_before_phase_timeout_write(self) -> None:
        results = self.tmp / "invalid-resume-timeout-root"
        results.mkdir()
        marker = results / "caller-sentinel.txt"
        marker.write_text("resume must be validated\n", encoding="utf-8")
        run = self.run_runner("parameters", results, resume=True, env={
            "PICCARD_WORK5_TEST_PHASE_TIMEOUT_SECONDS": "0.000001"})
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("validated Work #5 state", run.stderr)
        self.assertEqual(marker.read_text(encoding="utf-8"), "resume must be validated\n")
        self.assertFalse((results / "run-level-timeout.json").exists())

    def test_pre_setup_and_setup_errors_have_stage_specific_terminal_flags(self) -> None:
        contract = load_contract()
        lifecycle = contract["lifecycle"]
        for stage in ("pre_setup", "setup"):
            with self.subTest(stage=stage):
                results = self.tmp / f"work5-{stage}-error"
                run = self.run_runner(
                    "parameters", results,
                    env={
                        lifecycle["test_hooks"]["force_error_stage"]: stage,
                        lifecycle["test_hooks"]["force_error_cell"]:
                            "work5-std128-piccard::control",
                    },
                )
                self.assertNotEqual(run.returncode, 0)
                records = read_jsonl(results / "cells.jsonl")
                error = next(record for record in records
                             if record["status"] == "ERROR")
                self.assertEqual(error["reason_code"],
                                 lifecycle["error_scenarios"][stage]
                                 ["reason_code"])
                self.assert_record_status_schema(error, contract)
                self.assert_stage_flags(
                    error, lifecycle["error_scenarios"][stage]["flags"])
                self.assertFalse(any(record["status"] == "SKIPPED_PRECHECK"
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
        self.assertTrue(load_contract()["lifecycle"]["refuse_existing_results_root"])

    def test_production_toy_root_precreates_inventory_safe_gates_directory(self) -> None:
        results = self.tmp / "production-toy-root"
        capability = work5_runner.validate_results_root(results, resume=False)
        production_run = {
            "schema": "piccard-work5-run-v1", "test_fixture_mode": False,
            "completed_phases": [], "phase_inventory": {}, "cells_sha256": None,
        }
        with mock.patch.object(work5_runner, "initial_run", return_value=production_run):
            run = work5_runner.create_initial_root(
                capability, self.build, {}, {"schema": "piccard-work5-matrix-v1"},
                test_fixture=False, deadline=time.monotonic() + 30,
            )

        self.assertFalse(run["test_fixture_mode"])
        gates = results / "gates"
        self.assertTrue(gates.is_dir() and not gates.is_symlink())
        self.assertEqual(list(gates.iterdir()), [])

        toy_paths = work5_runner.toy_artifact_paths(results)
        toy = {}
        for label, path in toy_paths.items():
            work5_runner.atomic_write(path, f"{label}\n".encode("ascii"), new=True)
            toy[f"{label}_path"] = path.relative_to(results).as_posix()
        work5_runner.atomic_write(results / "toy.json", b"{}\n", new=True)
        work5_runner.install_phase_inventory(
            run, "toy", work5_runner.phase_inventory_document(
                results, "toy", [results / "toy.json", *toy_paths.values()],
                row_counts={"terminal_cells": 0, "measured": 1,
                            "skipped": 0, "errors": 0},
            ),
        )
        work5_runner.atomic_write(results / "run.json", work5_runner.canonical_json(run))
        work5_verifier.verify_inventory(results, [], toy, run)

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

    def test_real_phase_argv_is_source_bound_and_fixture_mode_cannot_start_it(self) -> None:
        root = self.tmp / "future-final-root"
        commands = work5_runner.planned_real_commands(self.build, root)
        self.assertEqual([label for label, _ in commands], ["prepare", "measure", "verify"])
        prepare, measure, verify = (argv for _label, argv in commands)
        self.assertEqual(prepare, [
            sys.executable, str(ROOT / "scripts" / "prepare_real_datasets.py"),
            "dblp-acm", "--source-manifest",
            str(ROOT / "datasets" / "manifests" / "dblp_acm.source.tsv"),
            "--output-dir", str(root / "real" / "dblp_acm_u65536"),
            "--universe", "65536", "--pairs", "10000", "--seed", "20260729", "--strict",
        ])
        self.assertIn("--single-trial-validation", measure)
        self.assertIn("--seed=20260729", measure)
        self.assertIn("--threads=2", measure)
        self.assertIn(str(root / "real" / "dblp_acm_u65536" / "dataset.manifest.tsv"), measure)
        self.assertEqual(verify[1], str(ROOT / "scripts" / "verify_real_dataset_outputs.py"))
        self.assertNotIn(str(ROOT / "datasets" / "data" / "processed" /
                              "dblp_acm_u65536"), "\n".join(sum((argv for _, argv in commands), [])))

        denied = self.run_runner("real", self.tmp / "fixture-real")
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("fixture mode", denied.stderr)
        self.assertFalse((self.tmp / "fixture-real").exists(),
                         "fixture-mode real call must not create a Work #5 root")
        self.assertFalse(self.events.exists(), "fixture-mode real call started a producer")

    def test_dynamic_phase_argv_is_frozen_for_the_two_correctness_rows(self) -> None:
        root = self.tmp / "future-final-root"
        commands = work5_runner.planned_dynamic_commands(self.build, root)
        self.assertEqual([label for label, _ in commands], ["updates-1", "updates-2"])
        for expected_updates, (_label, argv) in zip((1, 2), commands):
            self.assertEqual(argv, [
                str(self.build / "bench_dynamic"), "--scenario=refresh",
                f"--refresh_updates={expected_updates}", "--profile=toy-smoke",
                "--security=TOY", "--mode=timing", "--evidence_point", "--k=16",
                "--m=16", "--set_size=100", "--target_jaccard=0.5", "--depth=5",
                "--trials=1", "--seed=7",
            ])

    @staticmethod
    def dynamic_refresh_csv(updates: int) -> bytes:
        """A complete frozen producer row for lifecycle-only unit tests."""
        values = dynamic_refresh_values(updates)
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=DYNAMIC_CSV_HEADER,
                                lineterminator="\n")
        writer.writeheader()
        writer.writerow(values)
        return stream.getvalue().encode("utf-8")

    def test_dynamic_csv_semantic_mutations_fail_before_phase_publication(self) -> None:
        original = self.dynamic_refresh_csv(2)
        self.assertEqual(work5_runner.validate_dynamic_csv(original, 2)["correctness_status"],
                         "PASS")
        cases = {
            "owner_b_change": ("owner_b_unchanged", "false"),
            "epoch_discontinuity": ("final_epoch", "1"),
            "wrong_upload_count": ("ciphertext_upload_count", "1"),
            "local_decrypted_mismatch": ("decrypted_inner_product", "8"),
            "negative_memory": ("memory_bytes", "-1"),
            "timing_promotion": ("measurement_kind", "fhe_timing"),
        }
        for name, (field, value) in cases.items():
            with self.subTest(name=name):
                reader = csv.DictReader(io.StringIO(original.decode("utf-8")))
                row = next(reader)
                row[field] = value
                stream = io.StringIO()
                writer = csv.DictWriter(stream, fieldnames=reader.fieldnames,
                                        lineterminator="\n")
                writer.writeheader()
                writer.writerow(row)
                with self.assertRaises(work5_runner.Work5Error):
                    work5_runner.validate_dynamic_csv(stream.getvalue().encode("utf-8"), 2)

    def test_dynamic_csv_header_is_exact_and_rejects_future_or_promotion_columns(self) -> None:
        """RED: subset admission must not permit future performance semantics."""
        self.assertEqual(len(DYNAMIC_CSV_HEADER), 97)
        baseline = self.dynamic_refresh_csv(1)
        self.assertEqual(work5_runner.validate_dynamic_csv(baseline, 1)["correctness_status"], "PASS")
        row = next(csv.DictReader(io.StringIO(baseline.decode("utf-8"))))
        mutations = [
            ("future_column", [*DYNAMIC_CSV_HEADER, "future_column"]),
            ("performance_eligible", [*DYNAMIC_CSV_HEADER, "performance_eligible"]),
            ("performance_rank", [*DYNAMIC_CSV_HEADER, "performance_rank"]),
            ("ranking", [*DYNAMIC_CSV_HEADER, "ranking"]),
            ("speedup", [*DYNAMIC_CSV_HEADER, "speedup"]),
            ("throughput_rank", [*DYNAMIC_CSV_HEADER, "throughput_rank"]),
            ("primary_metric", [*DYNAMIC_CSV_HEADER, "primary_metric"]),
            ("paper_value", [*DYNAMIC_CSV_HEADER, "paper_value"]),
            ("aggregate_total_ms", [*DYNAMIC_CSV_HEADER, "aggregate_total_ms"]),
            ("reordered", [DYNAMIC_CSV_HEADER[1], DYNAMIC_CSV_HEADER[0], *DYNAMIC_CSV_HEADER[2:]]),
        ]
        for name, header in mutations:
            with self.subTest(name=name):
                values = dict(row)
                if len(header) == 98:
                    values[header[-1]] = "1"
                stream = io.StringIO()
                writer = csv.DictWriter(stream, fieldnames=header, lineterminator="\n")
                writer.writeheader()
                writer.writerow(values)
                with self.assertRaises(work5_runner.Work5Error):
                    work5_runner.validate_dynamic_csv(stream.getvalue().encode("utf-8"), 1)

    def test_dynamic_phase_requires_real_receipt_order_and_is_terminal(self) -> None:
        root = self.tmp / "dynamic-terminal"
        root.mkdir()
        (root / "dynamic").mkdir()
        capability = work5_runner.ResultsRootCapability(root=root, resume=True, fresh=False)
        args = type("Args", (), {"resume": True, "build_dir": str(self.build)})()
        commands = work5_runner.planned_dynamic_commands(self.build, root)
        run = {
            "completed_phases": ["toy", "parameters", "real"],
            "phase_inventory": {"toy": {}, "parameters": {}, "real": {}},
            "git_dirty": False,
        }
        results = [
            subprocess.CompletedProcess(argv, 0, self.dynamic_refresh_csv(updates), b"")
            for updates, (_label, argv) in zip((1, 2), commands)
        ]
        with mock.patch.object(work5_runner, "source_provenance", return_value={}), \
             mock.patch.object(work5_runner, "executable_map", return_value={}), \
             mock.patch.object(work5_runner, "resume_validate",
                               return_value=(run, [{"status": "MEASURED"}] * 61)), \
             mock.patch.object(work5_runner, "require_prior_receipt") as prior_receipt, \
             mock.patch.object(work5_runner, "bounded_subprocess", side_effect=results):
            self.assertEqual(work5_runner.run_dynamic_phase(
                args, capability, deadline=time.monotonic() + 30), 0)
        prior_receipt.assert_called_once_with(
            root, run, "real", ["toy", "parameters", "real"])
        self.assertEqual(run["completed_phases"], ["toy", "parameters", "real", "dynamic"])
        self.assertEqual(run["phase_inventory"]["dynamic"]["row_counts"], {
            "correctness_rows": 2, "updates_1": 1, "updates_2": 1, "errors": 0,
        })
        self.assertEqual(json.loads((root / "dynamic" / "terminal.json").read_text(encoding="utf-8"))[
            "status"], "MEASURED")

    def test_dynamic_phase_first_error_is_terminal_and_cannot_retry(self) -> None:
        root = self.tmp / "dynamic-error"
        root.mkdir()
        (root / "dynamic").mkdir()
        capability = work5_runner.ResultsRootCapability(root=root, resume=True, fresh=False)
        args = type("Args", (), {"resume": True, "build_dir": str(self.build)})()
        commands = work5_runner.planned_dynamic_commands(self.build, root)
        run = {
            "completed_phases": ["toy", "parameters", "real"],
            "phase_inventory": {"toy": {}, "parameters": {}, "real": {}},
            "git_dirty": False,
        }
        with mock.patch.object(work5_runner, "source_provenance", return_value={}), \
             mock.patch.object(work5_runner, "executable_map", return_value={}), \
             mock.patch.object(work5_runner, "resume_validate",
                               return_value=(run, [{"status": "MEASURED"}] * 61)), \
             mock.patch.object(work5_runner, "require_prior_receipt"), \
             mock.patch.object(work5_runner, "bounded_subprocess",
                               return_value=subprocess.CompletedProcess(
                                   commands[0][1], 2, b"", b"first failure")):
            with self.assertRaisesRegex(work5_runner.Work5Error,
                                        "dynamic updates-1 subprocess failed"):
                work5_runner.run_dynamic_phase(args, capability, deadline=time.monotonic() + 30)
            terminal = json.loads((root / "dynamic" / "terminal.json").read_text(encoding="utf-8"))
            self.assertEqual(terminal["status"], "ERROR")
            self.assertIn("first failure", terminal["detail"])
            with self.assertRaisesRegex(work5_runner.Work5Error, "prior artifacts"):
                work5_runner.run_dynamic_phase(args, capability, deadline=time.monotonic() + 30)

    def test_dynamic_phase_rejects_wrong_lifecycle_before_producer(self) -> None:
        root = self.tmp / "dynamic-wrong-order"
        root.mkdir()
        (root / "dynamic").mkdir()
        capability = work5_runner.ResultsRootCapability(root=root, resume=True, fresh=False)
        args = type("Args", (), {"resume": True, "build_dir": str(self.build)})()
        run = {"completed_phases": ["toy", "parameters"],
               "phase_inventory": {"toy": {}, "parameters": {}}, "git_dirty": False}
        with mock.patch.object(work5_runner, "source_provenance", return_value={}), \
             mock.patch.object(work5_runner, "executable_map", return_value={}), \
             mock.patch.object(work5_runner, "resume_validate",
                               return_value=(run, [{"status": "MEASURED"}] * 61)):
            with self.assertRaisesRegex(work5_runner.Work5Error, "exact ordered"):
                work5_runner.run_dynamic_phase(args, capability, deadline=time.monotonic() + 30)
        self.assertEqual(list((root / "dynamic").iterdir()), [])

    def test_dynamic_phase_requires_an_independent_real_receipt_before_writing(self) -> None:
        root = self.tmp / "dynamic-no-real-receipt"
        root.mkdir()
        (root / "dynamic").mkdir()
        capability = work5_runner.ResultsRootCapability(root=root, resume=True, fresh=False)
        args = type("Args", (), {"resume": True, "build_dir": str(self.build)})()
        run = {
            "completed_phases": ["toy", "parameters", "real"],
            "phase_inventory": {"toy": {}, "parameters": {}, "real": {}},
            "git_dirty": False,
        }
        with mock.patch.object(work5_runner, "source_provenance", return_value={}), \
             mock.patch.object(work5_runner, "executable_map", return_value={}), \
             mock.patch.object(work5_runner, "resume_validate",
                               return_value=(run, [{"status": "MEASURED"}] * 61)), \
             mock.patch.object(work5_runner, "require_prior_receipt",
                               side_effect=work5_runner.Work5Error("missing real receipt")):
            with self.assertRaisesRegex(work5_runner.Work5Error, "missing real receipt"):
                work5_runner.run_dynamic_phase(args, capability, deadline=time.monotonic() + 30)
        self.assertEqual(list((root / "dynamic").iterdir()), [])

    def test_parameter_phase_inventory_is_exactly_terminal_and_hashed(self) -> None:
        results = self.tmp / "parameter-inventory"
        completed = self.run_runner("parameters", results)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run = json.loads((results / "run.json").read_text(encoding="utf-8"))
        inventory = run["phase_inventory"]["parameters"]
        self.assertEqual(run["completed_phases"], ["parameters"])
        self.assertEqual(inventory["row_counts"]["terminal_cells"], 61)
        self.assertEqual(sum(inventory["row_counts"][name]
                             for name in ("measured", "skipped", "errors")), 61)
        artifacts = {entry["path"]: entry["sha256"] for entry in inventory["artifacts"]}
        self.assertIn("cells.jsonl", artifacts)
        self.assertEqual(artifacts["cells.jsonl"],
                         hashlib.sha256((results / "cells.jsonl").read_bytes()).hexdigest())

    def test_real_first_subprocess_error_is_terminal_and_cannot_retry(self) -> None:
        root = self.tmp / "real-terminal"
        root.mkdir()
        (root / "real").mkdir()
        capability = work5_runner.ResultsRootCapability(
            root=root, resume=True, fresh=False)
        run = {
            "completed_phases": ["toy", "parameters"],
            "phase_inventory": {"toy": {}, "parameters": {}},
            "git_dirty": False,
        }
        args = type("Args", (), {"resume": True, "build_dir": str(self.build)})()
        commands = [("prepare", ["/test/failing-prepare"])]
        with mock.patch.object(work5_runner, "source_provenance", return_value={}), \
             mock.patch.object(work5_runner, "executable_map", return_value={}), \
             mock.patch.object(work5_runner, "resume_validate", return_value=(run, [{"status": "MEASURED"}] * 61)), \
             mock.patch.object(work5_runner, "require_prior_receipt"), \
             mock.patch.object(work5_runner, "planned_real_commands", return_value=commands), \
             mock.patch.object(work5_runner, "bounded_subprocess",
                               return_value=subprocess.CompletedProcess(commands[0][1], 2, b"", b"first failure")):
            with self.assertRaisesRegex(work5_runner.Work5Error, "real prepare subprocess failed"):
                work5_runner.run_real_phase(args, capability, deadline=time.monotonic() + 30)
            terminal = json.loads((root / "real" / "terminal.json").read_text(encoding="utf-8"))
            self.assertEqual(terminal["status"], "ERROR")
            self.assertIn("first failure", terminal["detail"])
            self.assertEqual(run["completed_phases"], ["toy", "parameters"])
            with self.assertRaisesRegex(work5_runner.Work5Error, "prior artifacts"):
                work5_runner.run_real_phase(args, capability, deadline=time.monotonic() + 30)


if __name__ == "__main__":
    unittest.main()
