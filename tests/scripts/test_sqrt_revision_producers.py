#!/usr/bin/env python3
"""Executable-boundary checks for the sqrt successor producer family.

Each case runs one real producer with a materialized seed and feeds its exact
stdout/stderr through the campaign's family verifier.  This catches parser
success that never reaches the producer wire contract, including square and
non-square terminal topology.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"
SEED = "20260729"


class SqrtRevisionProducerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts

        cls.cell_output = cell_output
        cls.check_family_artifacts = _check_family_artifacts
        cls.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        cls.cells = {cell["cell_id"]: cell for cell in cls.matrix["cells"]}

    def run_case(self, producer: str, cell_id: str, role: str, mode: str,
                 m: int) -> None:
        cell = self.cells[cell_id]
        self.assertEqual(cell["axis"], role)
        command = [
            producer,
            f"--revision-cell={cell_id}",
            "--profile=readiness-toy-v1",
            f"--cell={role}",
            f"--mode={mode}",
            "--security=TOY",
            "--k=128",
            f"--m={m}",
            "--set_size=1000",
            "--universe=65536",
            "--trials=1",
            f"--seed={SEED}",
        ]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                   check=False)
        self.assertEqual(completed.returncode, 0,
                         completed.stderr.decode("utf-8", errors="replace"))

        with tempfile.TemporaryDirectory(prefix="sqrt-revision-producer-") as temporary:
            root = Path(temporary)
            output = type(self).cell_output(root, cell_id)
            output.mkdir(parents=True)
            (output / "stdout.log").write_bytes(completed.stdout)
            (output / "stderr.log").write_bytes(completed.stderr)
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n",
                encoding="utf-8")
            type(self).check_family_artifacts(
                root, "toy", [cell], {cell_id: {"command": command}})

    def test_onehot_timing_square_and_terminal_nonsquare(self) -> None:
        producer = str(Path(sys.argv[1]).resolve())
        self.run_case(
            producer, "paper-v1::sqrt_comparison::timing_m=64",
            "timing_m", "timing", 64)
        self.run_case(
            producer, "paper-v1::sqrt_comparison::timing_m=32",
            "timing_m", "timing", 32)

    def test_accuracy_square_and_terminal_nonsquare(self) -> None:
        producer = str(Path(sys.argv[2]).resolve())
        self.run_case(
            producer, "paper-v1::sqrt_comparison::accuracy_m=16",
            "accuracy_m", "accuracy", 16)
        self.run_case(
            producer, "paper-v1::sqrt_comparison::accuracy_m=32",
            "accuracy_m", "accuracy", 32)

    def test_ciphertext_square_and_terminal_nonsquare(self) -> None:
        producer = str(Path(sys.argv[3]).resolve())
        self.run_case(
            producer, "paper-v1::sqrt_comparison::ciphertext_m=16",
            "ciphertext_m", "ciphertext", 16)
        self.run_case(
            producer, "paper-v1::sqrt_comparison::ciphertext_m=32",
            "ciphertext_m", "ciphertext", 32)

    def test_crossover_square_and_terminal_nonsquare(self) -> None:
        producer = str(Path(sys.argv[3]).resolve())
        self.run_case(
            producer, "paper-v1::sqrt_comparison::crossover_m=16",
            "crossover_m", "crossover", 16)
        self.run_case(
            producer, "paper-v1::sqrt_comparison::crossover_m=32",
            "crossover_m", "crossover", 32)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *sys.argv[4:]])
