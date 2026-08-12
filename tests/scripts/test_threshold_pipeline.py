"""Independent contract tests for the Phase-4 synthetic threshold pipeline.

These tests intentionally keep the literals here instead of importing the
implementation's threshold/grid helpers.  That makes a changed helper fail
against the approved contract rather than teaching the test the same mistake.
"""

from __future__ import annotations

import csv
import math
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("PICCARD_BENCH_THRESHOLD", ROOT / "build" / "bench_threshold"))
SEED = 20_260_729


def _run_point(k: int, grid_index: int, trials: int = 1):
    command = [
        str(BINARY),
        "--mode=fpfn",
        "--profile=readiness-toy-v1",
        "--security=TOY",
        "--m=64",
        "--set_size=1000",
        f"--trials={trials}",
        f"--point-k={k}",
        f"--grid-index={grid_index}",
        f"--seed={SEED}",
        "--hash_randomness=resampled",
    ]
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)


class ThresholdPipelineContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            raise AssertionError(f"Phase-4 benchmark binary is missing: {BINARY}")

    def test_point_selectors_are_required_and_fail_closed(self):
        result = subprocess.run(
            [
                str(BINARY),
                "--mode=fpfn",
                "--profile=readiness-toy-v1",
                "--security=TOY",
                "--m=64",
                "--set_size=1000",
                "--trials=1",
                f"--seed={SEED}",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_point_emits_exactly_one_selected_row_with_literal_geometry(self):
        result = _run_point(64, 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = list(csv.DictReader(result.stdout.splitlines()))
        self.assertEqual(len(rows), 1)
        row = rows[0]

        # Approved fixed literals: k=64, m=64, tau=floor(.6*k)=38,
        # J_tau=(tau/k-1/m)/(1-1/m), and the central signed grid point.
        self.assertEqual(int(row["k"]), 64)
        self.assertEqual(int(row["m"]), 64)
        self.assertEqual(int(row["tau_count"]), 38)
        j_tau = (38.0 / 64.0 - 1.0 / 64.0) / (1.0 - 1.0 / 64.0)
        self.assertAlmostEqual(float(row["j_tau"]), j_tau, delta=1e-12)
        self.assertEqual(int(row["grid_index"]), 0)
        self.assertAlmostEqual(float(row["target_j"]), j_tau, delta=1e-12)
        alpha = 2.0 * j_tau / (1.0 + j_tau)
        c = math.floor(1000.0 * alpha)
        self.assertEqual(int(row["realized_intersection"]), c)
        self.assertEqual(int(row["realized_union"]), 2000 - c)
        self.assertAlmostEqual(
            float(row["realized_j"]), c / float(2000 - c), delta=1e-15
        )
        self.assertEqual(int(row["set_size"]), 1000)
        self.assertEqual(int(row["trial_index"]), 0)
        self.assertEqual(int(row["root_seed"]), SEED)

    def test_all_four_k_literals_and_inclusive_boundary_decision(self):
        expected_tau = {64: 38, 128: 76, 256: 153, 512: 307}
        for k, tau in expected_tau.items():
            result = _run_point(k, 0)
            self.assertEqual(result.returncode, 0, result.stderr)
            row = next(csv.DictReader(result.stdout.splitlines()))
            self.assertEqual(int(row["tau_count"]), tau)
            self.assertIn(int(row["decision"]), (0, 1))
            # The binary must report the match-count decision, not a strict
            # comparison or a decision copied from the truth field.
            match_count = int(row["match_count"])
            self.assertEqual(int(row["decision"]), int(match_count >= tau))

    def test_paper_profile_rejects_sub_1000_trials(self):
        result = subprocess.run(
            [
                str(BINARY),
                "--mode=fpfn",
                "--profile=paper-v1",
                "--security=STD128",
                "--m=64",
                "--set_size=1000",
                "--trials=999",
                "--point-k=128",
                "--grid-index=0",
                f"--seed={SEED}",
                "--hash_randomness=resampled",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_theory_kats_pin_center_and_symmetric_offsets(self):
        import scripts.verify_threshold_outputs as verifier

        expected = {
            (128, -1): (0.4476584452846713, 0.4101770352747402),
            (128, 0): (0.5380497333771499, 0.5),
            (128, 1): (0.6169907624916408, 0.4203171765639403),
        }
        for (k, grid_index), (probability, gaussian) in expected.items():
            point = verifier._point(k, grid_index)
            p = point["realized_j"] + (1.0 - point["realized_j"]) / 64.0
            self.assertAlmostEqual(
                verifier.binomial_decision_probability(k, point["tau_count"], p),
                probability,
                delta=1e-15,
            )
            self.assertAlmostEqual(
                verifier.gaussian_error_approx(point["realized_j"], k),
                gaussian,
                delta=1e-15,
            )

    def test_unknown_and_combined_modes_fail_without_csv(self):
        for mode in ("combined", "unknown"):
            result = subprocess.run(
                [str(BINARY), f"--mode={mode}"],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_duplicate_mode_is_rejected_independent_of_order(self):
        # Do not provide --profile here: the first ordering used to fall
        # through to BenchmarkConfig's legacy parser, which silently retained
        # the last mode and emitted the adjacent 42-row timing sweep.
        for first, second in (
            ("timing", "fpfn"),
            ("fpfn", "timing"),
            ("fpfn", "fpfn"),
        ):
            result = subprocess.run(
                [
                    str(BINARY),
                    f"--mode={first}",
                    f"--mode={second}",
                    "--security=TOY",
                    "--trials=1",
                    "--point-k=128",
                    "--grid-index=0",
                    f"--seed={SEED}",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(
                result.returncode,
                0,
                f"duplicate mode unexpectedly succeeded: {first}, {second}",
            )
            self.assertEqual(result.stdout, "")

    def test_verifier_rejects_full_mutation_matrix(self):
        import scripts.verify_threshold_outputs as verifier

        result = _run_point(128, 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(csv.DictReader(result.stdout.splitlines()))
        mutations = {
            "k": {**row, "k": "64"},
            "grid": {**row, "grid_index": "1"},
            "row seed": {**row, "row_seed": str(int(row["row_seed"]) + 1)},
            "security": {**row, "security": "STD128"},
            "outcome": {**row, "outcome": "TP"},
            "probability": {
                **row,
                "predicted_decision_probability": "0.0",
            },
        }
        for name, mutated in mutations.items():
            with self.subTest(field=name):
                with self.assertRaises(verifier.VerificationError):
                    verifier._validate_row(mutated, "toy", SEED)

        # Coverage mutations are checked at the independent artifact level,
        # not only at the individual-row level.
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_rows([], "toy", SEED, 1)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_rows([row], "toy", SEED, 1)
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_rows([row, row], "toy", SEED, 1)

    def _summarizer_command(self, csv_path: Path, *extra: str):
        return subprocess.run(
            [
                "python3",
                str(ROOT / "scripts" / "summarize_threshold_fpfn.py"),
                "--csv",
                str(csv_path),
                *extra,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def _verified_toy_csv(self) -> Path:
        # A checked-in synthetic artifact keeps this positive summary test
        # hermetic; it is not a paper/data benchmark output.
        path = ROOT / "tests" / "fixtures" / "threshold_fpfn_toy_v1.csv"
        self.assertTrue(path.is_file())
        return path

    def test_summarizer_accepts_fully_verified_toy_artifact(self):
        result = self._summarizer_command(
            self._verified_toy_csv(),
            "--mode=toy",
            f"--seed={SEED}",
            "--trials=1",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"rows": 84', result.stdout)
        self.assertIn('"profile": "readiness-toy-v1"', result.stdout)

    def test_summarizer_rejects_header_only_missing_duplicate_and_mixed_profile(self):
        valid = self._verified_toy_csv()
        header = ",".join(
            (
                "schema_version",
                "profile",
                "security",
                "estimator_model",
                "hash_randomness",
                "root_seed",
                "k",
                "m",
                "set_size",
                "tau_count",
                "j_tau",
                "grid_index",
                "target_j",
                "signed_delta",
                "absolute_delta",
                "alpha",
                "realized_intersection",
                "realized_union",
                "realized_j",
                "trial_index",
                "row_seed",
                "match_count",
                "decision",
                "exact_j_truth",
                "outcome",
                "predicted_decision_probability",
                "predicted_error_probability",
                "gaussian_error_approx",
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            header_only = tmp_path / "header-only.csv"
            header_only.write_text(header + "\n", encoding="utf-8")
            missing = tmp_path / "missing.csv"
            duplicate = tmp_path / "duplicate.csv"
            mixed = tmp_path / "mixed.csv"

            # Read the header separately so the fixture remains literal and
            # the mutated files retain the exact artifact schema.
            with valid.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                fieldnames = reader.fieldnames
                rows = list(reader)
            self.assertIsNotNone(fieldnames)

            with duplicate.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
                writer.writerow(rows[-1])
            with mixed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                rows[0]["profile"] = "paper-v1"
                writer.writerows(rows)

            for name, path in (
                ("header-only", header_only),
                ("missing", missing),
                ("duplicate", duplicate),
                ("mixed profile", mixed),
            ):
                with self.subTest(artifact=name):
                    result = self._summarizer_command(
                        path,
                        "--mode=toy",
                        f"--seed={SEED}",
                        "--trials=1",
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_summarizer_rejects_toy_security_mutation(self):
        valid = self._verified_toy_csv()
        with tempfile.TemporaryDirectory() as tmp:
            mutated = Path(tmp) / "security-mutated.csv"
            with valid.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                fieldnames = reader.fieldnames
                rows = list(reader)
            self.assertIsNotNone(fieldnames)
            rows[0]["security"] = "STD128"
            with mutated.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            result = self._summarizer_command(
                mutated,
                "--mode=toy",
                f"--seed={SEED}",
                "--trials=1",
            )
            self.assertNotEqual(result.returncode, 0)

    def test_verifier_module_exposes_independent_literal_checks(self):
        # The verifier is a separate executable module, not a subprocess shim
        # around the C++ producer.  Importing it is part of the contract.
        import scripts.verify_threshold_outputs as verifier

        self.assertEqual(verifier.SUPPORTED_K, (64, 128, 256, 512))
        self.assertEqual(tuple(verifier.GRID_INDICES), tuple(range(-10, 11)))
        self.assertEqual(verifier.tau_count(64), 38)
        self.assertEqual(verifier.tau_count(128), 76)
        self.assertEqual(verifier.tau_count(256), 153)
        self.assertEqual(verifier.tau_count(512), 307)

    def test_orchestrator_order_is_4_by_21(self):
        # This test is intentionally run against a tiny receipt-producing fake
        # child.  It checks orchestration count/order without spending a full
        # 84-point MinHash run in the unit suite.
        runner = ROOT / "scripts" / "run_threshold_fpfn_grid.py"
        self.assertTrue(runner.is_file())
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            log = tmp_path / "invocations.log"
            fake = tmp_path / "fake_child.py"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import csv,sys\n"
                "args={x[2:].split('=',1)[0]:x.split('=',1)[1] for x in sys.argv[1:] if x.startswith('--') and '=' in x}\n"
                f"open({str(log)!r},'a').write(args['point-k']+','+args['grid-index']+'\\n')\n"
                "print('schema_version,profile,security,estimator_model,hash_randomness,root_seed,k,m,set_size,tau_count,j_tau,grid_index,target_j,signed_delta,absolute_delta,alpha,realized_intersection,realized_union,realized_j,trial_index,row_seed,match_count,decision,exact_j_truth,outcome,predicted_decision_probability,predicted_error_probability,gaussian_error_approx')\n"
                "print('piccard-threshold-fpfn-v1,readiness-toy-v1,TOY,sha256-random-ranking-poc-v1,resampled,20260729,'+args['point-k']+',64,1000,1,0.5,'+args['grid-index']+',0.5,0,0,0.6,1000,1000,1,0,1,1,1,1,TP,0.5,0.5,0.5')\n"
            )
            fake.chmod(0o755)
            output = tmp_path / "combined.csv"
            result = subprocess.run(
                [
                    "python3",
                    str(runner),
                    f"--binary={fake}",
                    "--profile=readiness-toy-v1",
                    f"--output={output}",
                    f"--seed={SEED}",
                    "--trials=1",
                    "--security=TOY",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [line.strip() for line in log.read_text().splitlines()]
            self.assertEqual(len(calls), 84)
            self.assertEqual(calls[0], "64,-10")
            self.assertEqual(calls[-1], "512,10")
            expected = [f"{k},{j}" for k in (64, 128, 256, 512) for j in range(-10, 11)]
            self.assertEqual(calls, expected)


if __name__ == "__main__":
    unittest.main()
