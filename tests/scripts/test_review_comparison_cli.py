#!/usr/bin/env python3
"""No-setup boundary tests for the Phase-4 reviewer comparison CLI."""

import csv
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

if len(sys.argv) != 2:
    raise SystemExit("usage: test_review_comparison_cli.py BENCH_BINARY")
BENCH_BINARY = pathlib.Path(sys.argv.pop()).resolve()
ROOT = pathlib.Path(__file__).resolve().parents[2]

CANONICAL_TOY_METHODS = (
    "piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
    "bcg12_exact_ec", "sj16",
)


def _read_be32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "big"), offset + 4


def _read_string(data, offset):
    length, offset = _read_be32(data, offset)
    return data[offset:offset + length].decode(), offset + length


def _workload_methods(path):
    data = path.read_bytes()
    domain = b"piccard-review-workload-v1\0"
    if not data.startswith(domain):
        raise AssertionError("workload domain is not canonical")
    offset = len(domain)
    _, offset = _read_string(data, offset)  # suite
    _, offset = _read_string(data, offset)  # profile
    offset += 7 * 8  # root seed, geometry, and target rational
    count, offset = _read_be32(data, offset)
    methods = []
    for _ in range(count):
        method, offset = _read_string(data, offset)
        methods.append(method)
    return methods


class ReviewComparisonCliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = BENCH_BINARY

    def base_command(self, root: pathlib.Path):
        # Deliberately matches the frozen Phase-4 command by omitting
        # --security; the named toy profile is authoritative.
        return [
            str(self.binary),
            "--suite=toy-smoke",
            "--profile=toy-smoke",
            "--k=16",
            "--m=16",
            "--set-size=10",
            "--universe=64",
            "--target-jaccard=0.5",
            "--trials=1",
            "--accuracy-trials=1",
            "--seed=7",
            "--methods=piccard,piccard_sqrt,fhe_ind,bcg12_mh_ec,bcg12_exact_ec,sj16",
            "--sj16-key-bits=1024",
            "--allow-unmatched-security",
            f"--manifest-out={root / 'missing' / 'workload.bin'}",
            f"--execution-trace-out={root / 'missing' / 'trace.bin'}",
        ]

    def work5_std192_sj16_command(self, root: pathlib.Path, policy: str):
        return [
            str(self.binary),
            "--suite=work5-std192-sj16",
            "--profile=work5-std192-t40-single-trial",
            "--k=128",
            "--m=64",
            "--set-size=10",
            "--universe=64",
            "--target-jaccard=0.5",
            "--trials=1",
            "--accuracy-trials=1",
            "--seed=7",
            "--methods=sj16",
            "--sj16-key-bits=3072",
            policy,
            f"--manifest-out={root / 'workload.bin'}",
            f"--execution-trace-out={root / 'trace.bin'}",
        ]

    def work5_m_extra_command(self, root: pathlib.Path, methods: str):
        return [
            str(self.binary),
            "--suite=work5-std128-piccard-m-extra",
            "--profile=work5-std128-t40-single-trial",
            "--k=128",
            "--m=32",
            "--set-size=10",
            "--universe=64",
            "--target-jaccard=0.5",
            "--trials=1",
            "--accuracy-trials=1",
            "--seed=7",
            f"--methods={methods}",
            "--sj16-key-bits=3072",
            "--diagnostic-security",
            f"--manifest-out={root / 'missing' / 'workload.bin'}",
            f"--execution-trace-out={root / 'missing' / 'trace.bin'}",
        ]

    def run_cli(self, command):
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def work5_std192_encoding_command(self, root: pathlib.Path, *, suite: str,
                                       m: int, methods: str):
        return [
            str(self.binary), f"--suite={suite}",
            "--profile=work5-std192-t40-single-trial", "--security=STD192",
            "--k=128", f"--m={m}", "--set-size=1000", "--universe=16384",
            "--target-jaccard=0.5", "--trials=1", "--accuracy-trials=1",
            "--seed=7", f"--methods={methods}", "--sj16-key-bits=3072",
            "--diagnostic-security", f"--manifest-out={root / 'workload.bin'}",
            f"--execution-trace-out={root / 'trace.bin'}",
        ]

    def test_named_profile_supplies_omitted_security_before_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cli(self.base_command(pathlib.Path(tmp)))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("parent directory does not exist", result.stderr)
        self.assertNotIn("missing --security", result.stderr)

    def test_reused_or_aliased_output_paths_fail_before_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            existing = root / "existing.bin"
            existing.write_bytes(b"owned")
            command = self.base_command(root)
            command[-2] = f"--manifest-out={existing}"
            command[-1] = f"--execution-trace-out={root / 'trace.bin'}"
            reused = self.run_cli(command)
            self.assertEqual(reused.returncode, 2)
            self.assertEqual(reused.stdout, "")
            self.assertIn("new output paths", reused.stderr)

            same = self.base_command(root)
            target = root / "same.bin"
            same[-2] = f"--manifest-out={target}"
            same[-1] = f"--execution-trace-out={target}"
            aliased = self.run_cli(same)
            self.assertEqual(aliased.returncode, 2)
            self.assertEqual(aliased.stdout, "")
            self.assertIn("must differ", aliased.stderr)

    def test_help_documents_profile_derived_security(self):
        result = self.run_cli([str(self.binary), "--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("--security=LEVEL (optional with --profile)", result.stdout)
        self.assertIn("Profile supplies security when --security is omitted.", result.stdout)

    def test_toy_profile_rejects_two_accuracy_trials_before_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = self.base_command(pathlib.Path(tmp))
            command[command.index("--accuracy-trials=1")] = "--accuracy-trials=2"
            result = self.run_cli(command)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("trial counts do not match the frozen policy", result.stderr)

    def test_toy_smoke_manifest_freezes_canonical_fhe_ind_method_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            command = self.base_command(root)
            command[command.index(
                "--methods=piccard,piccard_sqrt,fhe_ind,bcg12_mh_ec,bcg12_exact_ec,sj16"
            )] = "--methods=" + ",".join(CANONICAL_TOY_METHODS)
            command[-2] = f"--manifest-out={root / 'workload.bin'}"
            command[-1] = f"--execution-trace-out={root / 'trace.bin'}"
            result = self.run_cli(command)

            # Workload bytes are durably written before adapter setup, and the
            # completed Phase-3 producer must preserve the canonical method
            # order in that manifest.
            manifest = root / "workload.bin"
            self.assertTrue(manifest.is_file(), result.stderr)
            self.assertEqual(_workload_methods(manifest),
                             list(CANONICAL_TOY_METHODS))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_work5_std192_sj16_requires_literal_allow_unmatched_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            result = self.run_cli(self.work5_std192_sj16_command(
                root, "--diagnostic-security"))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("requires literal --allow-unmatched-security",
                          result.stderr)
            self.assertFalse((root / "workload.bin").exists())
            self.assertFalse((root / "trace.bin").exists())

    def test_work5_std192_sj16_accepts_literal_allow_unmatched_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            result = self.run_cli(self.work5_std192_sj16_command(
                root, "--allow-unmatched-security"))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "workload.bin").is_file())
            self.assertTrue((root / "trace.bin").is_file())
            self.assertEqual(len(result.stdout.splitlines()), 3)

    def test_work5_m_extra_registers_piccard_only_without_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            accepted = self.run_cli(self.work5_m_extra_command(root, "piccard"))
            self.assertEqual(accepted.returncode, 2)
            self.assertEqual(accepted.stdout, "")
            self.assertIn("parent directory does not exist", accepted.stderr)
            self.assertNotIn("frozen policy", accepted.stderr)

            rejected = self.run_cli(self.work5_m_extra_command(
                root, "piccard,piccard_sqrt"))
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, "")
            self.assertIn("frozen policy", rejected.stderr)

    def test_std192_encoding_only_shared_and_m_extra_execute_without_fhe_or_calibration(self):
        cases = (
            ("work5-std192-piccard", 64, "piccard_encode,piccard_sqrt_encode",
             ["piccard_encode", "piccard_sqrt_encode"]),
            ("work5-std192-piccard-m-extra", 32, "piccard_encode",
             ["piccard_encode"]),
        )
        for suite, m, methods, expected_methods in cases:
            with self.subTest(suite=suite):
                with tempfile.TemporaryDirectory() as tmp:
                    root = pathlib.Path(tmp)
                    environment = os.environ.copy()
                    environment.update({"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"})
                    result = subprocess.run(
                        self.work5_std192_encoding_command(
                            root, suite=suite, m=m, methods=methods),
                        text=True, capture_output=True, check=False, env=environment)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn("calibration", result.stderr.lower())
                    self.assertNotIn("openfhe", result.stderr.lower())
                    rows = list(csv.DictReader(result.stdout.splitlines()))
                    self.assertEqual([row["method"] for row in rows],
                                     [method for method in expected_methods
                                      for _ in ("timing", "accuracy")])
                    self.assertNotIn("piccard_sqrt_encode",
                                     [row["method"] for row in rows]
                                     if suite.endswith("m-extra") else [])
                    forbidden = {"phase_encode_ms", "phase_encrypt_ms",
                                 "phase_compute_ms", "phase_decrypt_ms",
                                 "actual_ring_dim", "log_q_bits", "sanitizer_model"}
                    self.assertFalse(forbidden & set(rows[0]))
                    for row in rows:
                        self.assertEqual(
                            (row["encoder_warmup_calls"], row["encoder_timed_calls"],
                             row["encoder_correctness_calls"],
                             row["encoder_correctness_status"]),
                            ("1", "1", "1", "PASS"))
                        self.assertEqual(row["comparison_eligible"], "false")
                        self.assertEqual(row["comparison_scope"],
                                         "encoding-only-diagnostic")
                        self.assertEqual(row["cost_scope"], "encoding-only")
                        self.assertEqual(row["secure_division_included"], "false")
                    # Bind the verifier to exactly the direct producer stdout.
                    (root / "rows.csv").write_text(result.stdout, encoding="utf-8")
                    verifier = subprocess.run(
                        ["python3", str(pathlib.Path(__file__).resolve().parents[2] /
                                        "scripts" / "verify_review_comparison.py"),
                         f"--csv={root / 'rows.csv'}",
                         f"--workload={root / 'workload.bin'}",
                         f"--execution-trace={root / 'trace.bin'}"],
                        text=True, capture_output=True, check=False, env=environment)
                    self.assertEqual(verifier.returncode, 0, verifier.stderr)

                    # The independent semantic parser must reject both a
                    # taxonomy lie and an injected FHE timing column.
                    fields = list(rows[0])
                    bad_taxonomy = [dict(row) for row in rows]
                    bad_taxonomy[0]["cost_scope"] = "primitive-only"
                    with (root / "rows.csv").open("w", newline="") as stream:
                        writer = csv.DictWriter(stream, fieldnames=fields)
                        writer.writeheader()
                        writer.writerows(bad_taxonomy)
                    rejected = subprocess.run(
                        ["python3", str(pathlib.Path(__file__).resolve().parents[2] /
                                        "scripts" / "verify_review_comparison.py"),
                         f"--csv={root / 'rows.csv'}",
                         f"--workload={root / 'workload.bin'}",
                         f"--execution-trace={root / 'trace.bin'}"],
                        text=True, capture_output=True, check=False, env=environment)
                    self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                    self.assertIn("cost_scope", rejected.stderr)

                    forged_fields = [*fields, "phase_encrypt_ms"]
                    with (root / "rows.csv").open("w", newline="") as stream:
                        writer = csv.DictWriter(stream, fieldnames=forged_fields)
                        writer.writeheader()
                        for row in rows:
                            writer.writerow({**row, "phase_encrypt_ms": "0.1"})
                    rejected = subprocess.run(
                        ["python3", str(pathlib.Path(__file__).resolve().parents[2] /
                                        "scripts" / "verify_review_comparison.py"),
                         f"--csv={root / 'rows.csv'}",
                         f"--workload={root / 'workload.bin'}",
                         f"--execution-trace={root / 'trace.bin'}"],
                        text=True, capture_output=True, check=False, env=environment)
                    self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                    self.assertIn("schema", rejected.stderr)

    def test_versioned_encoding_profile_times_both_endpoints_and_audits_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            result = self.run_cli([
                str(self.binary),
                "--suite=readiness-toy-v1",
                "--profile=readiness-toy-v1",
                "--security=TOY",
                "--k=16", "--m=16", "--set-size=10", "--universe=64",
                "--target-jaccard=0.5", "--trials=1",
                "--accuracy-trials=0", "--seed=20260729",
                "--methods=piccard_encode,piccard_sqrt_encode",
                "--sj16-key-bits=1024", "--allow-unmatched-security",
                f"--manifest-out={root / 'workload.bin'}",
                f"--execution-trace-out={root / 'trace.bin'}",
            ])
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = list(csv.DictReader(result.stdout.splitlines()))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["profile_id"], "readiness-toy-v1")
            self.assertEqual(row["timing_trials"], "1")
            self.assertEqual(row["accuracy_trials"], "0")
            self.assertEqual(row["correctness_trials"], "1")
            self.assertEqual(row["encoder_warmup_pairs"], "1")
            self.assertEqual(row["timed_encoder_pairs"], "1")
            self.assertEqual(row["correctness_pair_calls"], "1")
            self.assertEqual(row["signature_derivation_timed"], "false")
            self.assertEqual(row["correctness_status"], "PASS")
            self.assertEqual(float(row["encode_pair_ms"]),
                             float(row["encode_a_ms"]) +
                             float(row["encode_b_ms"]))
            forbidden = {"actual_ring_dim", "log_q_bits", "plaintext_modulus",
                         "num_limbs", "openfhe_version", "phase_encrypt_ms",
                         "phase_decrypt_ms"}
            self.assertFalse(forbidden & set(row))

    def test_revision_encoding_materializes_runtime_seed_and_output_at_executable_boundary(self):
        """The planner's concrete seed/path must reach the real producer parser."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            output = root / "cell" / "encoding.csv"
            output.parent.mkdir()
            result = subprocess.run(
                [
                    str(self.binary),
                    "--revision-cell=paper-v1::piccard_std192_encoding::control=default",
                    "--profile=readiness-toy-v1",
                    "--suite=encoding",
                    "--methods=piccard_encode,piccard_sqrt_encode",
                    "--security=STD192",
                    "--k=128", "--m=64", "--n=1000", "--universe=65536",
                    "--encoding-iters=1", "--correctness-trials=1",
                    "--seed=20260729", f"--output={output}",
                ],
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "OMP_NUM_THREADS": "2",
                     "OMP_DYNAMIC": "FALSE"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output.parent / "workload.bin").is_file())
            self.assertTrue((output.parent / "execution-trace.bin").is_file())
            self.assertIn("20260729", result.stdout)
            self.assertIn("schema=review-encoding-terminal-v1", result.stderr)
            self.assertNotIn("{seed}", result.stdout + result.stderr)
            self.assertNotIn("{output}", result.stdout + result.stderr)

    def test_revision_encoding_real_cell_passes_campaign_family_verifier(self):
        """The real successor cell must satisfy the campaign's family path."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import (
            cell_output, file_inventory, materialize_cell_argv)
        from verify_revision_benchmarks import (
            _REVIEW_ENCODING_HEADER, _check_family_artifacts)

        matrix = json.loads((ROOT / "benchmarks" / "revision_matrix.json").read_text())
        cell = next(item for item in matrix["cells"] if item["cell_id"] ==
                    "paper-v1::piccard_std192_encoding::control=default")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "results"
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            recorded_argv = materialize_cell_argv(
                cell, "toy", root=root, output=output, seed=20260729, threads=2)
            command = [str(self.binary), *recorded_argv]
            result = subprocess.run(
                command, text=True, capture_output=True, check=False,
                env={**os.environ, "OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[0],
                             _REVIEW_ENCODING_HEADER.rstrip("\n"))
            rows = list(csv.DictReader(result.stdout.splitlines()))
            self.assertTrue(rows)
            self.assertEqual({row["target_semantics"] for row in rows}, {"jaccard"})
            self.assertEqual({row["root_seed"] for row in rows}, {"20260729"})
            self.assertNotIn("{seed}", result.stdout + result.stderr)
            self.assertNotIn("{output}", result.stdout + result.stderr)
            (output / "stdout.log").write_text(result.stdout, encoding="utf-8")
            (output / "stderr.log").write_text(result.stderr, encoding="utf-8")
            inventory = file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})
            self.assertEqual({item["path"] for item in inventory},
                             {"workload.bin", "execution-trace.bin"})
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": inventory}) + "\n",
                encoding="utf-8")
            _check_family_artifacts(
                root, "toy", [cell],
                {cell["cell_id"]: {"command": command}})

    def test_revision_encoding_rejects_malformed_runtime_seed_before_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            output = root / "cell" / "encoding.csv"
            output.parent.mkdir()
            command = [
                str(self.binary),
                "--revision-cell=paper-v1::piccard_std192_encoding::control=default",
                "--profile=readiness-toy-v1", "--suite=encoding",
                "--methods=piccard_encode,piccard_sqrt_encode",
                "--security=STD192", "--k=128", "--m=64",
                "--n=1000", "--universe=65536", "--encoding-iters=1",
                "--correctness-trials=1", "--seed=not-a-number",
                f"--output={output}",
            ]
            result = self.run_cli(command)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("concrete review --seed", result.stderr)
            self.assertFalse((output.parent / "workload.bin").exists())
            self.assertFalse((output.parent / "execution-trace.bin").exists())

    def test_legacy_baseline_method_is_rejected_before_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            command = self.base_command(root)
            command[command.index(
                "--methods=piccard,piccard_sqrt,fhe_ind,bcg12_mh_ec,bcg12_exact_ec,sj16"
            )] = (
                "--methods=piccard,piccard_sqrt,baseline,bcg12_mh_ec,"
                "bcg12_exact_ec,sj16"
            )
            command[-2] = f"--manifest-out={root / 'workload.bin'}"
            command[-1] = f"--execution-trace-out={root / 'trace.bin'}"
            result = self.run_cli(command)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("frozen policy", result.stderr)
        self.assertFalse((root / "workload.bin").exists())
        self.assertFalse((root / "trace.bin").exists())


if __name__ == "__main__":
    unittest.main()
