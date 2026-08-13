#!/usr/bin/env python3
"""Boundary contract for the one-owner dynamic refresh CLI."""

import csv
import io
import json
import os
import subprocess
import sys
import tempfile
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

    def revision_command(self, family, output, *, seed="20260729",
                         identity=True, raw=True):
        matrix = json.loads(
            (ROOT / "benchmarks" / "revision_matrix.json").read_text())
        cell = next(item for item in matrix["cells"]
                    if item["family"] == family and
                    item["cell_id"].endswith("control=default"))
        cid = cell["cell_id"]
        kind = ("accuracy" if family == "dynamic_accuracy" else
                ("refresh" if family == "dynamic_refresh" else "timing"))
        command = [
            BENCH_DYNAMIC,
            f"--revision-cell={cid}",
            "--profile=readiness-toy-v1",
            f"--cell={kind}", f"--mode={kind}",
            "--evidence_point", "--security=TOY", "--k=128", "--m=64",
            "--set_size=1000", "--universe=65536", "--trials=1",
            "--updates=1", f"--seed={seed}",
        ]
        if identity:
            command.append(f"--revision-identity-out={output / 'identity.csv'}")
        if family != "dynamic_accuracy" and raw:
            command += [f"--raw-timing-dir={output / 'raw'}",
                        "--raw-timing-profile=readiness-toy-v1"]
        return cell, command

    def run_revision_cell(self, family, root):
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        cell = next(item for item in json.loads(
            (ROOT / "benchmarks" / "revision_matrix.json").read_text())["cells"]
                    if item["family"] == family and
                    item["cell_id"].endswith("control=default"))
        output = cell_output(root, cell["cell_id"])
        output.mkdir(parents=True)
        cell, command = self.revision_command(family, output)
        result = self.run_cli(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        output.joinpath("producer.stdout").write_text(
            result.stdout, encoding="utf-8")
        output.joinpath("producer.stderr").write_text(
            result.stderr, encoding="utf-8")
        return cell, command, output

    def verify_revision_cell(self, root, output, cell, command):
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import file_inventory
        from verify_revision_benchmarks import _check_family_artifacts
        (output / "stdout.log").write_text(
            output.joinpath("producer.stdout").read_text(), encoding="utf-8")
        (output / "stderr.log").write_text(
            output.joinpath("producer.stderr").read_text(), encoding="utf-8")
        receipt = {"artifact_inventory": file_inventory(
            output, exclude={"stdout.log", "stderr.log", "receipt.json",
                             "producer.stdout", "producer.stderr"})}
        (output / "receipt.json").write_text(json.dumps(receipt) + "\n")
        _check_family_artifacts(
            root, "toy", [cell], {cell["cell_id"]: {"command": command}})

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

    def test_revision_accuracy_timing_refresh_cross_executable_verifier_boundary(self):
        with tempfile.TemporaryDirectory(prefix="piccard-dynamic-revision-") as temporary:
            root = Path(temporary)
            for family in ("dynamic_accuracy", "dynamic_timing", "dynamic_refresh"):
                with self.subTest(family=family):
                    cell, command, output = self.run_revision_cell(family, root)
                    self.verify_revision_cell(root, output, cell, command)

                    identity = output / "identity.csv"
                    identity_payload = identity.read_text()
                    identity.write_text(identity_payload.replace(
                        "65536", "32768"), encoding="utf-8")
                    with self.assertRaises(Exception):
                        self.verify_revision_cell(root, output, cell, command)
                    identity.write_text(identity_payload, encoding="utf-8")

                    if family != "dynamic_accuracy":
                        raw_path = next((output / "raw").glob("*.tsv"))
                        raw_lines = raw_path.read_text(encoding="utf-8").splitlines()
                        sample_index = next(index for index, line in enumerate(raw_lines)
                                            if line.startswith("sample\t"))
                        fields = raw_lines[sample_index].split("\t")
                        fields[7] = "0"
                        raw_lines[sample_index] = "\t".join(fields)
                        raw_path.write_text("\n".join(raw_lines) + "\n",
                                            encoding="utf-8")
                        with self.assertRaises(Exception):
                            self.verify_revision_cell(root, output, cell, command)

    def test_revision_runtime_bindings_fail_before_benchmark_setup(self):
        for family in ("dynamic_accuracy", "dynamic_timing", "dynamic_refresh"):
            with self.subTest(family=family), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = root / "cell"
                output.mkdir()
                _, valid = self.revision_command(family, output)
                cases = {
                    "missing_seed": [arg for arg in valid
                                     if not arg.startswith("--seed=")],
                    "duplicate_seed": valid + ["--seed=8"],
                    "malformed_seed": ["--seed=0007" if arg == "--seed=20260729"
                                        else arg for arg in valid],
                    "missing_identity": [arg for arg in valid
                                          if not arg.startswith("--revision-identity-out=")],
                }
                if family != "dynamic_accuracy":
                    cases.update({
                        "missing_raw_path": [arg for arg in valid
                                              if not arg.startswith("--raw-timing-dir=")],
                        "duplicate_raw_path": valid +
                        [f"--raw-timing-dir={output / 'other-raw'}"],
                        "placeholder_raw_path": [
                            "--raw-timing-dir={output}/raw" if arg.startswith("--raw-timing-dir=")
                            else arg for arg in valid],
                    })
                for name, command in cases.items():
                    with self.subTest(case=name):
                        result = self.run_cli(command)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, "")
                        self.assertNotIn("Benchmark Configuration:", result.stderr)
                        self.assertFalse((output / "identity.csv").exists())
                        self.assertFalse((output / "raw").exists())


if __name__ == "__main__":
    unittest.main()
