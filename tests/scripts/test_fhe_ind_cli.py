#!/usr/bin/env python3
"""Subprocess contract tests for the live ``bench_fhe_ind`` CLI."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import pathlib
import subprocess
import sys
import tempfile
import unittest


if len(sys.argv) != 2:
    raise SystemExit("usage: test_fhe_ind_cli.py BENCH_FHE_IND_BINARY_OR_FIXTURE")

BINARY = pathlib.Path(sys.argv[1]).resolve()
if not BINARY.is_file():
    print(
        f"EXPECTED RED: bench_fhe_ind binary is missing: {BINARY}",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _command(*args: str) -> list[str]:
    if BINARY.suffix == ".py":
        return [sys.executable, str(BINARY), *args]
    return [str(BINARY), *args]


IS_FIXTURE = BINARY.suffix == ".py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(*args), text=True, capture_output=True, check=False
    )


def _single_json(stdout: str) -> dict:
    """Parse exactly one JSON object, rejecting banners/trailing output."""

    document = stdout.lstrip()
    if not document:
        raise AssertionError("CLI emitted no JSON object")
    try:
        value, end = json.JSONDecoder().raw_decode(document)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"CLI output is not one JSON object: {stdout!r}") from exc
    if document[end:].strip():
        raise AssertionError(f"CLI emitted trailing output: {stdout!r}")
    if not isinstance(value, dict):
        raise AssertionError(f"CLI JSON value is not an object: {value!r}")
    return value


def _workload(root: pathlib.Path) -> pathlib.Path:
    path = root / "workload.json"
    producer = BINARY.with_name("bench_std_security_evidence")
    if producer.is_file() and producer.stat().st_mode & 0o111:
        generated = subprocess.run(
            [str(producer), "--mode=workload", "--output=" + str(path)],
            text=True, capture_output=True, check=False,
        )
        if generated.returncode != 0:
            raise AssertionError(
                f"bench_std_security_evidence workload failed: {generated.stderr!r}"
            )
        return path
    path.write_text(
        json.dumps(
            {
                "workload_id": "phase1-fhe-ind-toy",
                "manifest_sha256": "a" * 64,
                "universe": 64,
                "set_size": 10,
                "target_jaccard_numerator": 1,
                "target_jaccard_denominator": 2,
                "root_seed": 7,
                "timing_trials": 1,
                "accuracy_trials": 1,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _preflight_command(root: pathlib.Path, output: pathlib.Path) -> list[str]:
    return [
        "--mode=preflight",
        "--method=fhe_ind",
        "--circuit=fhe_ind",
        "--shape-id=fhe-indicator-v1",
        "--security=STD128",
        "--cell-id=fhe-ind-std128",
        "--universe=64",
        "--set-size=10",
        "--target-jaccard=1/2",
        "--seed=7",
        "--trials=1",
        "--output=" + str(output),
        "--workload=" + str(_workload(root)),
        "--format=json",
    ]


class FheIndCliContractTest(unittest.TestCase):
    def test_capabilities_are_one_json_object_and_typed(self):
        result = _run("--capabilities", "--format=json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        capabilities = _single_json(result.stdout)

        self.assertEqual(
            capabilities["schema"],
            "piccard-std-security-fhe-ind-capabilities-v1",
        )
        self.assertEqual(capabilities["method"], "fhe_ind")
        self.assertTrue(capabilities["context_only_preflight"])
        self.assertTrue(capabilities["exactly_one_run"])
        self.assertEqual(capabilities["security_profiles"], ["STD128", "STD192"])
        self.assertEqual(
            capabilities["workload"],
            {"universe": 64, "set_size": 10, "target_jaccard": "1/2", "seed": 7, "trials": 1},
        )
        self.assertIn("context_tuple_sha256", capabilities["context_tuple_fields"])
        self.assertTrue(capabilities["provenance"]["diagnostic_only"])
        self.assertFalse(capabilities["provenance"]["piccard_sanitizer_applicable"])
        self.assertFalse(capabilities["provenance"]["threshold_enabled"])
        self.assertRegex(capabilities["fhe_ind_binary_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(capabilities["capabilities_sha256"], r"^[0-9a-f]{64}$")
        descriptor = dict(capabilities)
        descriptor.pop("capabilities_sha256")
        expected_capabilities_sha256 = hashlib.sha256(
            (json.dumps(descriptor, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        self.assertEqual(capabilities["capabilities_sha256"],
                         expected_capabilities_sha256)

    def test_preflight_is_context_only_and_no_keygen(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            output = root / "preflight.json"
            result = subprocess.run(
                _command(*_preflight_command(root, output)),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            self.assertTrue(output.is_file())
            preflight = _single_json(output.read_text(encoding="utf-8"))

        self.assertEqual(
            preflight["schema"], "piccard-std-security-fhe-ind-preflight-v1"
        )
        self.assertEqual(preflight["mode"], "preflight")
        self.assertEqual(preflight["method"], "fhe_ind")
        self.assertEqual(preflight["circuit"], "fhe_ind")
        self.assertEqual(preflight["shape_id"], "fhe-indicator-v1")
        self.assertEqual(preflight["k"], "N/A")
        self.assertEqual(preflight["m"], "N/A")
        self.assertFalse(preflight["keygen_started"])
        self.assertTrue(preflight["diagnostic_only"])
        self.assertFalse(preflight["table_eligible"])
        self.assertGreater(preflight["realized_ring_dim"], 0)
        self.assertEqual(preflight["sanitizer_profile"], "not-applicable")
        self.assertEqual(preflight["calibration_origin"], "not-applicable")
        self.assertTrue(preflight["openfhe_version"])
        self.assertTrue(preflight["ordered_rns_moduli"])
        self.assertRegex(preflight["fhe_ind_binary_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(preflight["capabilities_sha256"], r"^[0-9a-f]{64}$")
        if IS_FIXTURE:
            self.assertEqual(preflight["openfhe_version"], "fake-openfhe-1")
            self.assertEqual(preflight["ordered_rns_moduli"],
                             ["1000000007", "1000000009"])
        else:
            self.assertTrue(all(value.isdigit() for value in
                                preflight["ordered_rns_moduli"]))

    def test_e2e_emits_one_csv_row_with_bound_timing_and_correctness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workload = _workload(root)
            preflight = root / "preflight.json"
            preflight_result = subprocess.run(
                _command(*_preflight_command(root, preflight)),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(preflight_result.returncode, 0, preflight_result.stderr)

            output = root / "e2e.csv"
            result = _run(
                "--mode=e2e",
                "--method=fhe_ind",
                "--circuit=fhe_ind",
                "--shape-id=fhe-indicator-v1",
                "--security=STD128",
                "--cell-id=fhe-ind-std128",
                "--universe=64",
                "--set-size=10",
                "--target-jaccard=1/2",
                "--seed=7",
                "--trials=1",
                "--output=" + str(output),
                "--workload=" + str(workload),
                "--preflight=" + str(preflight),
                "--format=csv",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")

            with output.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            row = rows[0]

        self.assertEqual(row["method"], "fhe_ind")
        self.assertEqual(row["cell_id"], "fhe-ind-std128")
        self.assertEqual(row["circuit"], "fhe_ind")
        self.assertEqual(row["shape_id"], "fhe-indicator-v1")
        self.assertEqual(row["k"], "N/A")
        self.assertEqual(row["m"], "N/A")
        self.assertEqual(row["realized_intersection"], "7")
        self.assertEqual(row["realized_union"], "13")
        self.assertEqual(row["realized_jaccard"], "0.53846153846153844")
        self.assertEqual(row["match_count"], "7")
        self.assertTrue(
            math.isclose(float(row["jaccard_estimate"]), 7 / 13, rel_tol=0, abs_tol=1e-15)
        )
        self.assertEqual(row["status"], "MEASURED")
        self.assertEqual(row["reason"], "")
        self.assertRegex(row["fhe_ind_binary_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(row["capabilities_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(row["sanitizer_profile"], "not-applicable")
        self.assertEqual(row["calibration_origin"], "not-applicable")
        self.assertTrue(row["workload_id"])
        self.assertEqual(len(row["workload_manifest_sha256"]), 64)
        if IS_FIXTURE:
            self.assertEqual(row["workload_id"], "phase1-fhe-ind-toy")
            self.assertEqual(row["workload_manifest_sha256"], "a" * 64)

        for key in (
            "setup_context_ms",
            "setup_keygen_ms",
            "phase_encode_ms",
            "phase_encrypt_ms",
            "phase_evaluate_ms",
            "phase_decrypt_ms",
            "online_e2e_ms",
            "full_e2e_ms",
        ):
            self.assertGreater(float(row[key]), 0.0, key)
        self.assertAlmostEqual(
            sum(float(row[key]) for key in ("phase_encode_ms", "phase_encrypt_ms",
                                             "phase_evaluate_ms", "phase_decrypt_ms")),
            float(row["online_e2e_ms"]),
            places=9,
        )
        self.assertAlmostEqual(
            float(row["setup_context_ms"])
            + float(row["setup_keygen_ms"])
            + float(row["online_e2e_ms"]),
            float(row["full_e2e_ms"]),
            places=9,
        )

    def test_duplicate_option_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            output = root / "preflight.json"
            arguments = _preflight_command(root, output) + ["--mode=preflight"]
            result = subprocess.run(
                _command(*arguments), text=True, capture_output=True, check=False
            )
        self.assertNotEqual(result.returncode, 0)

    def test_output_overwrite_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            output = root / "preflight.json"
            arguments = _preflight_command(root, output)
            first = subprocess.run(
                _command(*arguments), text=True, capture_output=True, check=False
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            original = output.read_bytes()
            second = subprocess.run(
                _command(*arguments), text=True, capture_output=True, check=False
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes(), original)

    @unittest.skipIf(IS_FIXTURE, "fixture does not expose live tuple recomputation")
    def test_tampered_preflight_skip_decision_is_rejected_before_e2e(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            workload = _workload(root)
            preflight = root / "preflight.json"
            first = subprocess.run(
                _command(*_preflight_command(root, preflight)),
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            value = json.loads(preflight.read_text(encoding="utf-8"))
            value["skipped"] = True
            value["reason"] = "tampered"
            preflight.write_text(json.dumps(value, sort_keys=True) + "\n",
                                 encoding="utf-8")
            output = root / "e2e.csv"
            result = _run(
                "--mode=e2e", "--method=fhe_ind", "--circuit=fhe_ind",
                "--shape-id=fhe-indicator-v1", "--security=STD128",
                "--cell-id=fhe-ind-std128", "--universe=64", "--set-size=10",
                "--target-jaccard=1/2", "--seed=7", "--trials=1",
                "--output=" + str(output), "--workload=" + str(workload),
                "--preflight=" + str(preflight), "--format=csv",
            )
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipIf(IS_FIXTURE, "fixture does not parse canonical workload bytes")
    def test_malformed_workload_is_rejected_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            malformed = root / "malformed-workload.json"
            malformed.write_text(
                json.dumps({"schema": "piccard-std-security-workload-v1",
                            "bytes_hex": "00"}, sort_keys=True) + "\n",
                encoding="utf-8")
            output = root / "preflight.json"
            arguments = _preflight_command(root, output)
            arguments = [
                "--workload=" + str(malformed)
                if argument.startswith("--workload=") else argument
                for argument in arguments
            ]
            result = subprocess.run(
                _command(*arguments), text=True, capture_output=True, check=False
            )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
