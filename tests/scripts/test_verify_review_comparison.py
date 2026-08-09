#!/usr/bin/env python3
"""Behavior tests for the manifest-bound reviewer comparison gate."""

import csv
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.scripts.review_verifier_fixtures import write_review_fixture


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "verify_review_comparison.py"
EVIDENCE = ROOT / ".omo" / "evidence"


class ReviewComparisonVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.csv_path = self.root / "results.csv"
        self.workload_path = self.root / "workload.bin"
        self.trace_path = self.root / "trace.bin"
        shutil.copyfile(EVIDENCE / "work4-phase4-toy-results.csv", self.csv_path)
        shutil.copyfile(EVIDENCE / "work4-phase4-toy-workload.bin", self.workload_path)
        shutil.copyfile(EVIDENCE / "work4-phase4-toy-trace.bin", self.trace_path)

    def run_verifier(self):
        return subprocess.run(
            [
                "python3", str(VERIFIER),
                f"--csv={self.csv_path}",
                f"--workload={self.workload_path}",
                f"--execution-trace={self.trace_path}",
            ],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def read_rows(self):
        with self.csv_path.open(newline="") as stream:
            reader = csv.DictReader(stream)
            return list(reader.fieldnames or ()), list(reader)

    def write_rows(self, fields, rows):
        with self.csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def write_canonical_toy_fixture(self, methods=None):
        with (EVIDENCE / "work4-phase4-toy-results.csv").open(
                newline="", encoding="utf-8") as source:
            fields = next(csv.reader(source))
        return write_review_fixture(
            "toy-smoke", fields, self.csv_path,
            self.workload_path, self.trace_path, methods=methods,
        )

    def assert_rejects_mutation(self, column, value, cause, row_index=0):
        fields, rows = self.read_rows()
        rows[row_index][column] = value
        self.write_rows(fields, rows)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(cause, result.stderr)

    def test_persisted_toy_artifact_passes_without_rerunning_benchmark(self):
        _, rows = self.read_rows()
        self.assertTrue(any(
            row["measurement_status"] == "measured" and
            row["trials"] == "1" and row["total_ms_sd"] == ""
            for row in rows
        ))
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"verdict": "PASS"', result.stdout)
        self.assertIn('"rows": 12', result.stdout)

    def test_toy_artifact_requires_the_complete_73_column_detail_schema(self):
        fields, rows = self.read_rows()
        detail_columns = (
            "intersection_count", "phase_encode_ms", "phase_encrypt_ms",
            "phase_compute_ms", "phase_decrypt_ms", "ct_size_bytes",
            "comm_bytes",
        )
        self.assertEqual(len(fields), 73)
        for column in detail_columns:
            with self.subTest(column=column):
                reduced_fields = [field for field in fields if field != column]
                reduced_rows = [
                    {field: row[field] for field in reduced_fields}
                    for row in rows
                ]
                self.write_rows(reduced_fields, reduced_rows)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("73-column", result.stderr)
        self.write_rows(fields, rows)

    def test_fhe_ind_jaccard_and_error_are_manifest_bound(self):
        fields, rows = self.read_rows()
        fhe_index = next(
            index for index, row in enumerate(rows)
            if row["method"] == "fhe_ind"
        )
        for column, value, cause in (
                ("jaccard_computed", "0.500000", "FHE-IND computed Jaccard"),
                ("jaccard_expected", "0.500000", "expected Jaccard"),
                ("jaccard_error", "0.100000", "FHE-IND reported nonzero Jaccard error"),
        ):
            with self.subTest(column=column):
                mutated = [dict(row) for row in rows]
                mutated[fhe_index][column] = value
                self.write_rows(fields, mutated)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)
        self.write_rows(fields, rows)

    def test_fhe_ind_taxonomy_and_phase_binding_fail_closed(self):
        fields, rows = self.read_rows()
        fhe_index = next(
            index for index, row in enumerate(rows)
            if row["method"] == "fhe_ind" and row["evidence_arm"] == "timing"
        )
        cases = (
            ("comparison_eligible", "true",
             "diagnostic suite cannot be comparison eligible"),
            ("k", "16", "k mismatch"),
            ("m", "16", "m mismatch"),
            ("sanitizer_model", "phase-smudging-enc0-poc-v1",
             "sanitizer_model"),
            ("secure_division_included", "true", "secure_division_included"),
            ("workload_manifest_sha256", "0" * 64,
             "workload_manifest_sha256 mismatch"),
            ("phase_compute_ms", "0.100000", "phase total mismatch"),
        )
        for column, value, cause in cases:
            with self.subTest(column=column):
                mutated = [dict(row) for row in rows]
                mutated[fhe_index][column] = value
                self.write_rows(fields, mutated)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)
        self.write_rows(fields, rows)

    def test_canonical_toy_fixture_contains_one_diagnostic_fhe_ind_pair(self):
        rows = self.write_canonical_toy_fixture()
        self.assertEqual(
            [row["method"] for row in rows[::2]],
            ["piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
             "bcg12_exact_ec", "sj16"],
        )
        fhe_rows = [row for row in rows if row["method"] == "fhe_ind"]
        self.assertEqual(len(fhe_rows), 2)
        self.assertTrue(all(row["k"] == "" and row["m"] == ""
                            for row in fhe_rows))
        self.assertTrue(all(row["estimator_model"] == "not-applicable"
                            for row in fhe_rows))
        self.assertTrue(all(row["sanitizer_model"] == "not-applicable"
                            for row in fhe_rows))
        self.assertTrue(all(row["actual_ring_dim"] == "1024"
                            for row in fhe_rows))
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"rows": 12', result.stdout)

    def test_primary_review_14_row_non_benchmark_fixture_passes(self):
        fields, _ = self.read_rows()
        rows = write_review_fixture(
            "primary-review", fields, self.csv_path,
            self.workload_path, self.trace_path,
        )
        self.assertEqual(len(rows), 14)
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"suite": "primary-review"', result.stdout)
        self.assertIn('"rows": 14', result.stdout)

    def test_sj16_precompute_2_row_non_benchmark_fixture_passes(self):
        fields, _ = self.read_rows()
        rows = write_review_fixture(
            "sj16-precompute-sensitivity", fields, self.csv_path,
            self.workload_path, self.trace_path,
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["precomputation_mode"] for row in rows},
            {"randomizer-generation-included", "randomizers-precomputed"},
        )
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"suite": "sj16-precompute-sensitivity"', result.stdout)
        self.assertIn('"rows": 2', result.stdout)

    def test_measured_rows_require_each_core_metric_to_be_finite(self):
        fields, rows = self.read_rows()
        required_metrics = (
            "total_ms", "total_ms_median", "jaccard_computed",
            "jaccard_expected", "jaccard_error",
        )
        for column in required_metrics:
            for value in ("", "NaN"):
                with self.subTest(column=column, value=value):
                    mutated = [dict(row) for row in rows]
                    mutated[0][column] = value
                    self.write_rows(fields, mutated)
                    result = self.run_verifier()
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(column, result.stderr)

    def test_method_elsewhere_does_not_satisfy_required_workload_membership(self):
        self.assert_rejects_mutation("workload_id", "review-elsewhere-deadbeef", "workload_id", 8)

    def test_group_conditions_are_exactly_manifest_bound(self):
        cases = (
            ("workload_manifest_sha256", "0" * 64, "workload_manifest_sha256"),
            ("profile_id", "std128-t40-primary", "profile_id"),
            ("root_seed", "8", "root_seed"),
            ("omp_threads", "3", "omp_threads"),
            ("target_jaccard", "0.25", "target_jaccard"),
            ("timing_trials", "2", "timing_trials"),
            ("measurement_status", "extrapolated", "measurement_status"),
            ("security_match", "false", "security_match"),
        )
        for column, value, cause in cases:
            with self.subTest(column=column):
                fields, rows = self.read_rows()
                original = [dict(row) for row in rows]
                rows[0][column] = value
                self.write_rows(fields, rows)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)
                self.write_rows(fields, original)

    def test_duplicate_unexpected_and_missing_method_kind_pairs_fail(self):
        fields, rows = self.read_rows()
        mutations = []
        duplicate = [dict(row) for row in rows]
        duplicate.append(dict(rows[0]))
        mutations.append((duplicate, "duplicate method-kind"))
        unexpected = [dict(row) for row in rows]
        unexpected[0]["method"] = "unexpected"
        mutations.append((unexpected, "unexpected method-kind"))
        missing = [dict(row) for row in rows[:-1]]
        mutations.append((missing, "missing method-kind"))
        for mutated, cause in mutations:
            with self.subTest(cause=cause):
                self.write_rows(fields, mutated)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)

    def test_fhe_ind_membership_and_legacy_aliases_fail_closed(self):
        rows = self.write_canonical_toy_fixture()
        fields, _ = self.read_rows()
        fhe_timing = next(row for row in rows
                          if row["method"] == "fhe_ind" and
                          row["evidence_arm"] == "timing")
        cases = (
            ([*rows, dict(fhe_timing)], "duplicate method-kind"),
            ([row for row in rows if row["method"] != "fhe_ind"],
             "missing method-kind"),
            ([dict(row, method="baseline") if row is fhe_timing else dict(row)
              for row in rows], "unexpected method-kind"),
        )
        for mutated, cause in cases:
            with self.subTest(cause=cause):
                self.write_rows(fields, mutated)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)

    def test_manifest_method_order_and_legacy_substitution_are_rejected(self):
        canonical = ("piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
                     "bcg12_exact_ec", "sj16")
        for methods, cause in (
                (canonical[1:] + canonical[:1], "ordered method list"),
                (("piccard", "baseline", "bcg12_mh_ec", "bcg12_exact_ec",
                  "sj16", "fhe_ind"), "ordered method list"),
        ):
            with self.subTest(methods=methods):
                self.write_canonical_toy_fixture(methods=methods)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)

    def test_primary_fixture_never_promotes_diagnostic_fhe_ind(self):
        fields, _ = self.read_rows()
        rows = write_review_fixture(
            "primary-review", fields, self.csv_path,
            self.workload_path, self.trace_path,
        )
        self.assertNotIn("fhe_ind", {row["method"] for row in rows})
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_row_parameters_membership_and_trial_counts_are_exact(self):
        cases = (
            (0, "k", "17", "k"),
            (0, "m", "17", "m"),
            (0, "set_size", "11", "set_size"),
            (0, "universe_size", "65", "universe_size"),
            (0, "measurement_kind", "fhe-accuracy", "measurement_kind"),
            (0, "trials", "2", "aggregate trial count"),
            (8, "jaccard_error", "0.1", "exact method"),
        )
        fields, rows = self.read_rows()
        for index, column, value, cause in cases:
            with self.subTest(column=column):
                mutated = [dict(row) for row in rows]
                mutated[index][column] = value
                self.write_rows(fields, mutated)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)

    def test_workload_and_execution_trace_bytes_are_reparsed(self):
        for path, cause in ((self.workload_path, "workload"), (self.trace_path, "execution trace")):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                tampered = bytearray(original)
                tampered[-1] ^= 1
                path.write_bytes(tampered)
                result = self.run_verifier()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(cause, result.stderr)
                path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
