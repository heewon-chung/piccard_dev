#!/usr/bin/env python3
"""Boundary contract for the one-owner dynamic refresh CLI."""

import csv
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
# CTest invokes this file directly with the built binary path.  The Phase-6
# gate also runs it through ``python -m unittest``; in that form unittest owns
# argv, so use the explicit in-tree Release/default build path (or an override)
# rather than rejecting the test module during import.
if len(sys.argv) == 2 and Path(sys.argv[1]).name == "bench_dynamic":
    BENCH_DYNAMIC = sys.argv.pop()
else:
    BENCH_DYNAMIC = os.environ.get("PICCARD_BENCH_DYNAMIC",
                                   str(ROOT / "build" / "bench_dynamic"))


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
        self.assertEqual(row["updates_requested"], "1")
        self.assertEqual(row["updates_applied"], "1")
        self.assertEqual(row["initial_epoch"], "0")
        self.assertEqual(row["final_epoch"], "1")
        self.assertEqual(row["owner_b_unchanged"], "true")
        self.assertEqual(row["ciphertext_upload_count"], "1")
        self.assertEqual(row["local_inner_product"], row["decrypted_inner_product"])
        self.assertEqual(row["correctness_status"], "PASS")
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
        self.assertEqual(row["updates_requested"], "2")
        self.assertEqual(row["updates_applied"], "2")
        self.assertEqual(row["initial_epoch"], "0")
        self.assertEqual(row["final_epoch"], "2")
        self.assertEqual(row["owner_b_unchanged"], "true")
        self.assertEqual(row["ciphertext_upload_count"], "2")
        self.assertEqual(row["local_inner_product"], row["decrypted_inner_product"])
        self.assertEqual(row["correctness_status"], "PASS")
        self.assertEqual(row["refresh_updates"], "2")
        self.assertEqual(row["refresh_epoch_before"], "0")
        self.assertEqual(row["refresh_epoch_after"], "2")
        self.assertEqual(row["refresh_ciphertexts_uploaded"], "2")

    def test_accepts_the_frozen_work5_target_jaccard_argv_spelling(self):
        command = ["--target_jaccard=0.5" if arg == "--target-jaccard=0.5" else arg
                   for arg in self.base_command()]
        result = self.run_cli(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = list(csv.DictReader(io.StringIO(result.stdout)))[0]
        self.assertEqual(row["dynamic_scenario"], "refresh")

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
