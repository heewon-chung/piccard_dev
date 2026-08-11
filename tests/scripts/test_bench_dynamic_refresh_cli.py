#!/usr/bin/env python3
"""Boundary contract for the one-owner dynamic refresh CLI."""

import csv
import io
import subprocess
import sys
import unittest


if len(sys.argv) != 2:
    raise SystemExit("usage: test_bench_dynamic_refresh_cli.py BENCH_DYNAMIC")
BENCH_DYNAMIC = sys.argv.pop()


class BenchDynamicRefreshCliTest(unittest.TestCase):
    def base_command(self):
        return [
            BENCH_DYNAMIC,
            "--scenario=refresh",
            "--refresh_updates=1",
            "--profile=toy-smoke",
            "--security=TOY",
            "--mode=timing",
            "--evidence_point",
            "--k=16",
            "--m=16",
            "--set_size=100",
            "--target-jaccard=0.5",
            "--depth=5",
            "--trials=1",
            "--seed=7",
        ]

    def run_cli(self, command):
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def assert_rejected_before_refresh(self, command):
        result = self.run_cli(command)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("refresh_owner_a_0_to_1", result.stdout)
        self.assertNotIn("refresh_owner_a_0_to_1", result.stderr)

    def test_refresh_contract(self):
        result = self.run_cli(self.base_command())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("warmup", result.stdout.lower())
        rows = list(csv.DictReader(io.StringIO(result.stdout)))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["dynamic_scenario"], "refresh")
        self.assertEqual(row["refresh_status"], "applied")
        self.assertEqual(row["refresh_owner_set_id"], "owner-a")
        self.assertEqual(row["refresh_epoch_before"], "0")
        self.assertEqual(row["refresh_epoch_after"], "1")
        self.assertEqual(row["refresh_ciphertexts_uploaded"], "1")
        self.assertGreater(int(row["refresh_upload_bytes"]), 0)

    def test_two_updates_are_a_real_two_epoch_sequence(self):
        command = self.base_command()
        command = ["--refresh_updates=2" if arg == "--refresh_updates=1" else arg
                   for arg in command]
        result = self.run_cli(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = list(csv.DictReader(io.StringIO(result.stdout)))[0]
        self.assertEqual(row["refresh_updates"], "2")
        self.assertEqual(row["refresh_epoch_before"], "0")
        self.assertEqual(row["refresh_epoch_after"], "2")
        self.assertEqual(row["refresh_ciphertexts_uploaded"], "2")

    def test_rejects_update_counts_outside_frozen_one_or_two(self):
        command = self.base_command()
        command = ["--refresh_updates=3" if arg == "--refresh_updates=1" else arg
                   for arg in command]
        self.assert_rejected_before_refresh(command)

    def test_rejects_all_refresh_preconditions_and_invalid_updates(self):
        cases = {
            "wrong_profile": ["--profile=legacy"],
            "non_toy": ["--security=STD128"],
            "wrong_mode": ["--mode=accuracy"],
            "missing_evidence": ["--evidence_point"],
            "many_trials": ["--trials=2"],
            "zero_updates": ["--refresh_updates=0"],
            "missing_updates": ["--refresh_updates=1"],
            "trailing_updates": ["--refresh_updates=1x"],
            "negative_updates": ["--refresh_updates=-1"],
        }
        for name, replacement in cases.items():
            with self.subTest(name=name):
                command = self.base_command()
                if name == "missing_evidence":
                    command.remove("--evidence_point")
                elif name == "missing_updates":
                    command.remove("--refresh_updates=1")
                else:
                    for value in replacement:
                        prefix = value.split("=", 1)[0] + "="
                        command = [arg for arg in command if not arg.startswith(prefix)]
                        command.append(value)
                self.assert_rejected_before_refresh(command)

    def test_legacy_rejects_refresh_updates(self):
        self.assert_rejected_before_refresh([
            BENCH_DYNAMIC, "--refresh_updates=1", "--k=16", "--seed=7"
        ])


if __name__ == "__main__":
    unittest.main()
