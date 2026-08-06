#!/usr/bin/env python3
"""Executable pipeline tests for bench_real_datasets (Work 5 Sub-phase 5.3,
accuracy mode).

Runs the BUILT bench_real_datasets binary against the tracked DBLP-ACM quick
fixture (and, for the zero-Jaccard sentinel case, a small hand-written
synthetic fixture built in a temporary directory) and checks its output
against the normative plan's byte-level contracts: exact CSV header, row
count, seed provenance (independently recomputed with hashlib), workload
manifest/rows SHA-256 binding, the rel_error N/A sentinel at zero exact
Jaccard, determinism, and root-seed sensitivity.

A missing bench_real_datasets binary is a test FAILURE, never a skip [F3]:
a skipped suite would go green vacuously and mask a dropped build target.

Hermetic: every test writes its outputs under tempfile.TemporaryDirectory();
none of them touch the real datasets/ tree or the network.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "build" / "bench_real_datasets"
DRIVER_SOURCE = REPO / "benchmarks" / "real_accuracy_driver.cpp"
QUICK_FIXTURE_MANIFEST = (
    REPO / "tests" / "fixtures" / "real_datasets" / "quick" / "dblp_acm_u65536"
    / "dataset.manifest.tsv"
)

# Pasted byte-for-byte from normative plan §Phase 5 / the Sub-phase 5.2
# schema TU (adjudication A1), independently of benchmarks/real_dataset_csv_schema.cpp
# so this test does not tautologically re-derive the header from the
# implementation under test.
_PREFIX_HEADER = (
    "profile_id,run_class,target_security_bits,cryptographic_profile,"
    "nominal_security_bits,security_match,comparison_eligible,"
    "comparison_scope,primitive,protocol_model,output_semantics,"
    "assurance_scope,security_basis,cost_scope,precomputation_mode,"
    "secure_division_included,measurement_kind,"
    "workload_id,workload_manifest_sha256,execution_trace_sha256,"
    "root_seed,omp_threads,"
    "estimator_model,sanitizer_model,sanitizer_assurance,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,"
    "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version,"
    "target_semantics,target_jaccard,realized_intersection,realized_union,"
    "realized_jaccard,timing_trials,accuracy_trials,omp_dynamic,"
    "measurement_status"
)
_ACCURACY_SUFFIX = (
    "dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,"
    "pair_id,pair_kind,label,record_a,record_b,"
    "k,m,hash_randomness,accuracy_trial_index,hash_seed,"
    "set_size_a_raw,set_size_b_raw,set_size_a_bucketed,set_size_b_bucketed,"
    "exact_jaccard_raw,exact_jaccard_bucketed,estimated_jaccard,"
    "bucket_match_fraction,abs_error,rel_error,jaccard_bucket,"
    "accuracy_workload_sha256"
)
EXPECTED_ACCURACY_HEADER_LF = _PREFIX_HEADER + "," + _ACCURACY_SUFFIX + "\n"

_ACCURACY_HASH_DOMAIN = b"piccard-real-crs-v1"

# The driver TU's #include set is a closed allowlist [FA2][FA9]: no
# BFV/OpenFHE header may appear, directly or transitively, so KeyGen can
# never run from this translation unit. Two additions beyond the three
# named project headers were made by the Sub-phase 5.3 executor, each
# because the header was independently confirmed FHE-free and is required
# to reuse the deployed estimator pipeline / compute the required SHA-256
# provenance hashes (see the phase report for the full justification):
#   - core/minhash.h: the deployed sha256-random-ranking-poc-v1 MinHash
#     primitive (include/core/minhash.h includes only <cstdint>, <vector>).
#   - real_accuracy_driver.h: this TU's own public interface header
#     (declares RealAccuracyCliArgs / RunRealAccuracyMode; includes only
#     <cstdint>, <string>).
_ALLOWED_QUOTED_INCLUDES = {
    "real_accuracy_driver.h",
    "data/real_dataset.h",
    "data/real_dataset_metrics.h",
    "real_dataset_csv_schema.h",
    "core/minhash.h",
}
# openssl/evp.h is the sole non-stdlib angle-bracket exception: it is a
# pure crypto library with no lattice/FHE code whatsoever, it is the only
# SHA-256 provider used anywhere in this codebase (src/data/real_dataset.cpp,
# src/core/minhash.cpp, benchmarks/estimator_diagnostic.cpp,
# tests/unit/test_real_dataset.cpp all declare their own local OpenSSL-EVP
# helper -- no shared sha256.h header exists to allowlist instead), and the
# accuracy driver cannot derive its hash_seed/workload SHA-256 provenance
# without a certified SHA-256 implementation.
_ALLOWED_ANGLE_INCLUDES = {
    "openssl/evp.h",
    "algorithm", "array", "chrono", "cmath", "cstdint", "filesystem",
    "fstream", "limits", "sstream", "stdexcept", "string", "system_error",
    "unordered_map", "utility", "vector",
}
_FORBIDDEN_TOKENS = ("openfhe", "lbcrypto", "binfhe", "pke/", "core/lattice")


def require_binary() -> None:
    """A missing binary is a hard failure, never a skip [F3]."""
    if not BINARY.is_file():
        raise AssertionError(
            f"bench_real_datasets binary not found at {BINARY}. This is a "
            "build-target regression, not a skip condition: build it with "
            "'cmake --build build -j4 --target bench_real_datasets' before "
            "running this suite."
        )


def derive_hash_seed(root_seed: int, pair_id: str, trial_index: int) -> int:
    """Independent Python re-implementation of the normative per-(pair_id,
    trial_index) seed derivation, for cross-checking the C++ driver's
    output (never imported from the implementation under test)."""
    pair_bytes = pair_id.encode("utf-8")
    buffer = (
        _ACCURACY_HASH_DOMAIN
        + b"\x00"
        + root_seed.to_bytes(8, "big")
        + len(pair_bytes).to_bytes(4, "big")
        + pair_bytes
        + trial_index.to_bytes(8, "big")
    )
    digest = hashlib.sha256(buffer).digest()
    return int.from_bytes(digest[:8], "big")


def parse_two_column_tsv(path: Path) -> dict:
    values = {}
    lines = path.read_text(encoding="utf-8").split("\n")
    assert lines[-1] == "", "file must be LF-terminated"
    lines = lines[:-1]
    assert lines[0] == "key\tvalue"
    for line in lines[1:]:
        key, value = line.split("\t", 1)
        assert key not in values, f"duplicate manifest key: {key!r}"
        values[key] = value
    return values


class RealDatasetPipelineAccuracyTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        require_binary()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out_dir = Path(self.temp.name)

    def run_accuracy(self, *, dataset_manifest: Path, k=16, m=16, max_pairs=2,
                     accuracy_trials=1, seed=7, hash_randomness="resampled",
                     suffix=""):
        csv_path = self.out_dir / f"accuracy{suffix}.csv"
        workload_manifest_path = self.out_dir / f"workload{suffix}.manifest.tsv"
        workload_rows_path = self.out_dir / f"workload{suffix}.rows.tsv"
        completed = subprocess.run(
            [
                str(BINARY),
                f"--dataset-manifest={dataset_manifest}",
                "--mode=accuracy",
                f"--k={k}",
                f"--m={m}",
                f"--max-pairs={max_pairs}",
                f"--accuracy_trials={accuracy_trials}",
                f"--seed={seed}",
                f"--hash_randomness={hash_randomness}",
                f"--csv={csv_path}",
                f"--workload-manifest-out={workload_manifest_path}",
                f"--workload-rows-out={workload_rows_path}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed, csv_path, workload_manifest_path, workload_rows_path

    def test_exact_header_bytes(self):
        _, csv_path, _, _ = self.run_accuracy(dataset_manifest=QUICK_FIXTURE_MANIFEST)
        content = csv_path.read_text(encoding="utf-8")
        header_line = content.split("\n", 1)[0] + "\n"
        self.assertEqual(header_line, EXPECTED_ACCURACY_HEADER_LF)

    def test_row_count_equals_pairs_times_trials(self):
        _, csv_path, _, _ = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, max_pairs=2, accuracy_trials=3)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 2 * 3)

    def test_seed_provenance_recomputation(self):
        _, csv_path, _, _ = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, seed=7, max_pairs=2,
            accuracy_trials=1)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            expected = derive_hash_seed(7, row["pair_id"], int(row["accuracy_trial_index"]))
            self.assertEqual(int(row["hash_seed"]), expected)

    def test_workload_manifest_and_rows_sha_binding(self):
        _, csv_path, manifest_path, rows_path = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, max_pairs=2, accuracy_trials=1)
        manifest = parse_two_column_tsv(manifest_path)
        self.assertEqual(manifest["schema_version"], "piccard-real-accuracy-workload-v1")
        self.assertEqual(manifest["pair_selection"], "manifest-order-prefix")

        rows_bytes = rows_path.read_bytes()
        self.assertEqual(manifest["rows_sha256"], hashlib.sha256(rows_bytes).hexdigest())

        dataset_manifest_bytes = QUICK_FIXTURE_MANIFEST.read_bytes()
        self.assertEqual(
            manifest["dataset_manifest_sha256"],
            hashlib.sha256(dataset_manifest_bytes).hexdigest())

        manifest_bytes = manifest_path.read_bytes()
        expected_workload_sha = hashlib.sha256(manifest_bytes).hexdigest()

        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["workload_manifest_sha256"], expected_workload_sha)
            self.assertEqual(row["accuracy_workload_sha256"], expected_workload_sha)

    def test_workload_rows_header_and_sort_order(self):
        _, _, _, rows_path = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, max_pairs=2, accuracy_trials=2)
        lines = rows_path.read_text(encoding="utf-8").split("\n")
        self.assertEqual(lines[0], "pair_id\ttrial_index\thash_seed\trecord_a\trecord_b")
        self.assertEqual(lines[-1], "")
        data_lines = lines[1:-1]
        self.assertEqual(len(data_lines), 4)
        keys = [tuple(line.split("\t")[:2]) for line in data_lines]
        sort_keys = [(pair_id, int(trial)) for pair_id, trial in keys]
        self.assertEqual(sort_keys, sorted(sort_keys))

    def test_zero_jaccard_pair_gets_empty_rel_error_sentinel(self):
        fixture_dir = self.out_dir / "zero_j_fixture"
        manifest_path = _write_zero_jaccard_fixture(fixture_dir)
        _, csv_path, _, _ = self.run_accuracy(
            dataset_manifest=manifest_path, max_pairs=1, accuracy_trials=1,
            suffix="-zeroj")
        with csv_path.open(newline="", encoding="utf-8") as handle:
            content = handle.read()
        with io.StringIO(content) as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["exact_jaccard_bucketed"], "0")
        self.assertEqual(row["rel_error"], "")
        self.assertNotEqual(row["abs_error"], "")

    def test_root_seed_sensitivity(self):
        _, csv_a, _, _ = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, seed=7, max_pairs=2,
            accuracy_trials=1, suffix="-seed7")
        _, csv_b, _, _ = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, seed=8, max_pairs=2,
            accuracy_trials=1, suffix="-seed8")
        with csv_a.open(newline="", encoding="utf-8") as handle:
            rows_a = {row["pair_id"]: row["hash_seed"] for row in csv.DictReader(handle)}
        with csv_b.open(newline="", encoding="utf-8") as handle:
            rows_b = {row["pair_id"]: row["hash_seed"] for row in csv.DictReader(handle)}
        self.assertEqual(set(rows_a), set(rows_b))
        self.assertTrue(any(rows_a[pair_id] != rows_b[pair_id] for pair_id in rows_a))

    def test_byte_identical_csv_across_repeated_runs(self):
        _, csv_a, manifest_a, rows_a = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, max_pairs=2, accuracy_trials=2,
            suffix="-run1")
        _, csv_b, manifest_b, rows_b = self.run_accuracy(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, max_pairs=2, accuracy_trials=2,
            suffix="-run2")
        self.assertEqual(csv_a.read_bytes(), csv_b.read_bytes())
        self.assertEqual(manifest_a.read_bytes(), manifest_b.read_bytes())
        self.assertEqual(rows_a.read_bytes(), rows_b.read_bytes())

    def test_missing_output_flags_are_rejected(self):
        csv_path = self.out_dir / "accuracy.csv"
        completed = subprocess.run(
            [
                str(BINARY),
                f"--dataset-manifest={QUICK_FIXTURE_MANIFEST}",
                "--mode=accuracy",
                "--k=16", "--m=16", "--max-pairs=2", "--accuracy_trials=1",
                "--seed=7", "--hash_randomness=resampled",
                f"--csv={csv_path}",
                # --workload-manifest-out and --workload-rows-out omitted.
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertFalse(csv_path.exists())

    def test_timing_mode_reports_not_implemented(self):
        completed = subprocess.run(
            [
                str(BINARY),
                f"--dataset-manifest={QUICK_FIXTURE_MANIFEST}",
                "--mode=timing",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("not implemented", completed.stderr.lower())


class DriverIncludeAllowlistTest(unittest.TestCase):
    """Statically enforces the KeyGen-free driver-TU contract [FA2][FA9]."""

    def test_driver_tu_includes_are_from_the_closed_allowlist(self):
        self.assertTrue(DRIVER_SOURCE.is_file(),
                        f"expected {DRIVER_SOURCE} to exist")
        source = DRIVER_SOURCE.read_text(encoding="utf-8")
        includes = re.findall(r'^\s*#include\s*([<"])([^">]+)[">]', source,
                              re.MULTILINE)
        self.assertTrue(includes, "expected at least one #include directive")
        for delimiter, path in includes:
            lowered = path.lower()
            for forbidden in _FORBIDDEN_TOKENS:
                self.assertNotIn(forbidden, lowered,
                                 f"forbidden token {forbidden!r} in include {path!r}")
            if delimiter == '"':
                self.assertIn(path, _ALLOWED_QUOTED_INCLUDES,
                             f"quoted include not in the FHE-free allowlist: {path!r}")
            else:
                self.assertIn(path, _ALLOWED_ANGLE_INCLUDES,
                             f"angle-bracket include not in the FHE-free allowlist: {path!r}")


def _write_zero_jaccard_fixture(root: Path) -> Path:
    """Hand-writes a minimal piccard-real-processed-v1 dataset directory with
    exactly one pair whose bucketed feature sets are completely disjoint, so
    exact_jaccard_bucketed == 0 and the rel_error N/A sentinel is exercised.

    Not produced by scripts/prepare_real_datasets.py -- written directly
    against the normative TSV grammar (docs/superpowers/plans/
    2026-07-29-05-real-dataset-pipeline.md §"Exact shared file grammar" and
    "Processed manifests require:"), which src/data/real_dataset.cpp's
    LoadRealDataset validates independently of any particular generator: it
    checks manifest-key completeness, checksums, strictly-increasing
    features, and per-dataset pair_kind/label pairs, but places no
    constraint on record-ID shape or on cross-consistency of the set-size
    statistics fields, so a small hand-written fixture is a faithful,
    independently-constructed input.
    """
    root.mkdir(parents=True, exist_ok=True)

    source_manifest_bytes = b"key\tvalue\n"
    (root / "source.manifest.tsv").write_bytes(source_manifest_bytes)

    records_header = (
        "record_id\traw_feature_count\traw_features_csv\t"
        "bucketed_feature_count\tbucketed_features_csv\n"
    )
    records_rows = (
        "rec_a\t3\t1,2,3\t3\t1,2,3\n"
        "rec_b\t3\t100,101,102\t3\t100,101,102\n"
    )
    records_bytes = (records_header + records_rows).encode("utf-8")
    (root / "records.tsv").write_bytes(records_bytes)

    pairs_header = "pair_id\trecord_a\trecord_b\tpair_kind\tlabel\n"
    pairs_rows = "zero-j-pair:1\trec_a\trec_b\tsampled_nonmatch\t0\n"
    pairs_bytes = (pairs_header + pairs_rows).encode("utf-8")
    (root / "pairs.tsv").write_bytes(pairs_bytes)

    manifest_lines = [
        ("schema_version", "piccard-real-processed-v1"),
        ("dataset", "dblp_acm"),
        ("variant", "dblp_acm_u65536"),
        ("preprocessing_version", "dblp-acm-trigram-v1"),
        ("universe_size", "1000"),
        ("seed", "7"),
        ("source_manifest_file", "source.manifest.tsv"),
        ("source_manifest_sha256", hashlib.sha256(source_manifest_bytes).hexdigest()),
        ("records_file", "records.tsv"),
        ("records_sha256", hashlib.sha256(records_bytes).hexdigest()),
        ("record_count", "2"),
        ("pairs_file", "pairs.tsv"),
        ("pairs_sha256", hashlib.sha256(pairs_bytes).hexdigest()),
        ("pair_count", "1"),
        ("raw_set_size_min", "3"),
        ("raw_set_size_median", "3"),
        ("raw_set_size_p95", "3"),
        ("raw_set_size_max", "3"),
        ("bucketed_set_size_min", "3"),
        ("bucketed_set_size_median", "3"),
        ("bucketed_set_size_p95", "3"),
        ("bucketed_set_size_max", "3"),
        ("original_positive_count", "0"),
        ("retained_positive_count", "0"),
        ("requested_pair_count", "1"),
        ("max_documents", ""),
        ("min_related_pairs", ""),
        ("dropped.empty_features_dblp", "0"),
        ("dropped.empty_features_acm", "0"),
    ]
    manifest_text = "key\tvalue\n" + "".join(f"{k}\t{v}\n" for k, v in manifest_lines)
    manifest_path = root / "dataset.manifest.tsv"
    manifest_path.write_bytes(manifest_text.encode("utf-8"))
    return manifest_path


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[1:])
