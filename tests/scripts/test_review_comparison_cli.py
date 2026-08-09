#!/usr/bin/env python3
"""No-setup boundary tests for the Phase-4 reviewer comparison CLI."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

if len(sys.argv) != 2:
    raise SystemExit("usage: test_review_comparison_cli.py BENCH_BINARY")
BENCH_BINARY = pathlib.Path(sys.argv.pop()).resolve()

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

    def run_cli(self, command):
        return subprocess.run(command, text=True, capture_output=True, check=False)

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
