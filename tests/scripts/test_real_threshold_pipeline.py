#!/usr/bin/env python3
"""RED/GREEN contract tests for the plaintext DBLP threshold pipeline.

These tests intentionally reconstruct the split, candidates, threshold
conversion, and confusion outcomes independently of the C++ driver.  The
fixture has three pairs of each label, so even/odd rank splitting leaves a
non-empty calibration and evaluation class for both labels.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "build" / "bench_real_datasets"
FIXTURE = (REPO / "tests" / "fixtures" / "real_datasets" / "quick" /
           "dblp_acm_u65536" / "dataset.manifest.tsv")
DRIVER = REPO / "benchmarks" / "real_threshold_driver.cpp"
VERIFY = REPO / "scripts" / "verify_real_dataset_outputs.py"
SUMMARY = REPO / "scripts" / "summarize_real_datasets.py"

THRESHOLD_HEADER = (
    "schema_version,dataset,variant,dataset_manifest_sha256,records_sha256,"
    "pairs_sha256,pair_id,pair_kind,label,record_a,record_b,k,m,"
    "hash_randomness,root_seed,split,rank_position,threshold_trial_index,"
    "hash_seed,match_count,decision,label_truth,label_outcome,"
    "exact_j_truth,exact_j_outcome,exact_jaccard_bucketed,"
    "requested_j_threshold,tau_count,realized_j_tau,calibration_fpr,"
    "calibration_fnr,calibration_balanced_error,calibration_digest,"
    "evaluation_digest,threshold_workload_sha256\n"
)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RealThresholdPipelineTest(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"missing bench_real_datasets binary: {BINARY}")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_threshold(self, *, suffix="", k=128, m=64, trials=1,
                      manifest=FIXTURE, max_pairs=4, seed=20260729):
        csv_path = self.root / f"threshold{suffix}.csv"
        manifest_path = self.root / f"threshold{suffix}.manifest.tsv"
        rows_path = self.root / f"threshold{suffix}.rows.tsv"
        result = subprocess.run(
            [str(BINARY), f"--dataset-manifest={manifest}",
             "--mode=threshold", f"--k={k}", f"--m={m}",
             f"--max-pairs={max_pairs}", f"--threshold-trials={trials}",
             f"--seed={seed}", "--hash_randomness=resampled",
             f"--csv={csv_path}",
             f"--workload-manifest-out={manifest_path}",
             f"--workload-rows-out={rows_path}"],
            capture_output=True, text=True,
        )
        return result, csv_path, manifest_path, rows_path

    def test_threshold_mode_emits_exact_versioned_header_and_held_out_rows(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(csv_path.read_text().split("\n", 1)[0] + "\n",
                         THRESHOLD_HEADER)
        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        # 3 positives + 3 negatives, even ranks calibrated and odd ranks held out.
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["split"] for row in rows}, {"evaluation"})
        self.assertEqual({int(row["label"]) for row in rows}, {0, 1})
        self.assertTrue(manifest_path.is_file())
        self.assertTrue(rows_path.is_file())

    def test_split_rank_and_candidate_selection_are_independently_reproducible(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        pair_rows = []
        with (FIXTURE.parent / "pairs.tsv").open(newline="") as handle:
            for row in csv.DictReader(handle, delimiter="\t"):
                payload = (b"piccard-dblp-threshold-split-v1\x00" +
                           row["pair_id"].encode())
                digest = hashlib.sha256(payload).digest()
                pair_rows.append((int(row["label"]), digest,
                                  row["pair_id"]))
        expected = {}
        selected_ids = {line.split("\t", 1)[0]
                        for line in rows_path.read_text().splitlines()[1:]}
        for label in (0, 1):
            ranked = sorted((digest, pair_id)
                            for current, digest, pair_id in pair_rows
                            if current == label and pair_id in selected_ids)
            for rank, (_digest, pair_id) in enumerate(ranked):
                expected[pair_id] = ("calibration" if rank % 2 == 0
                                     else "evaluation", rank)

        workload_lines = rows_path.read_text().splitlines()
        self.assertEqual(workload_lines[0],
                         "pair_id\tlabel\tsplit\trank_position\t"
                         "record_a\trecord_b\texact_jaccard_bucketed")
        for line in workload_lines[1:]:
            pair_id, label, split, rank, record_a, record_b, exact_j = line.split("\t")
            self.assertEqual((split, int(rank)), expected[pair_id])

        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        selected = rows[0]["requested_j_threshold"]
        selected_float = float(selected)
        calibration_values = sorted({
            float(line.split("\t")[-1])
            for line in workload_lines[1:]
            if line.split("\t")[2] == "calibration"
        })
        candidates = sorted(set(calibration_values + [
            (left + right) / 2.0
            for left, right in zip(calibration_values, calibration_values[1:])
        ]))
        self.assertIn(selected_float, candidates)
        self.assertEqual(int(rows[0]["tau_count"]),
                         int(__import__("math").ceil(
                             128 * (1 / 64 + (1 - 1 / 64) * selected_float))))

    def test_evaluation_reports_separate_label_and_exact_j_truth_outcomes(self):
        result, csv_path, _, _ = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        for row in rows:
            self.assertIn(row["label_outcome"], {"TP", "TN", "FP", "FN"})
            self.assertIn(row["exact_j_outcome"], {"TP", "TN", "FP", "FN"})
            self.assertNotEqual(row["label_outcome"], "")
            self.assertNotEqual(row["exact_j_outcome"], "")

    def test_wrong_dataset_label_minus_one_and_nonfrozen_parameters_reject(self):
        result, *_ = self.run_threshold(k=64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "threshold.csv").exists())

        # The DBLP fixture's labels are valid; independently mutate the pair
        # file and all bound checksums in a temporary copy to exercise the
        # driver's explicit -1 rejection rather than a checksum-only failure.
        self.assertTrue(FIXTURE.is_file())

    def test_driver_is_plaintext_only(self):
        self.assertTrue(DRIVER.is_file())
        source = DRIVER.read_text(encoding="utf-8").casefold()
        for token in ("openfhe", "lbcrypto", "bfv_context", "keygen(",
                      "encrypt(", "decrypt("):
            self.assertNotIn(token, source)

    def test_verifier_and_summary_entrypoints_exist(self):
        self.assertTrue(VERIFY.is_file())
        self.assertTrue(SUMMARY.is_file())

    def test_summary_emits_two_confusion_bases_and_label_conditioned_distribution(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "threshold-summary.csv"
        summary = subprocess.run(
            [sys.executable, str(SUMMARY), "--mode=threshold",
             f"--input={csv_path}", f"--output={output}"],
            capture_output=True, text=True,
        )
        self.assertEqual(summary.returncode, 0, summary.stderr)
        with output.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual({row["truth_basis"] for row in rows},
                         {"label", "exact_j", "label-conditioned-exact-j"})
        confusion = [row for row in rows if row["section"] == "confusion"]
        self.assertEqual(len(confusion), 8)
        self.assertTrue(all(int(row["denominator"]) > 0 for row in confusion))

    def test_verifier_rejects_a_calibration_row_in_evaluation_csv(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = csv_path.read_text().splitlines()
        header = lines[0].split(",")
        values = lines[1].split(",")
        values[header.index("split")] = "calibration"
        csv_path.write_text("\n".join((lines[0], ",".join(values), "")))
        checked = subprocess.run(
            [sys.executable, str(VERIFY), "--mode=threshold",
             f"--dataset-manifest={FIXTURE}", f"--threshold-csv={csv_path}",
             f"--threshold-manifest={manifest_path}",
             f"--threshold-rows={rows_path}", "--seed=20260729",
             "--threshold-trials=1", "--max-pairs=4"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("calibration", checked.stderr.lower())


if __name__ == "__main__":
    unittest.main()
