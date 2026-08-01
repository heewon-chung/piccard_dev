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
            "--accuracy-trials=2",
            "--seed=7",
            "--methods=piccard,piccard_sqrt,bcg12_mh_ec,bcg12_exact_ec,sj16",
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


if __name__ == "__main__":
    unittest.main()
