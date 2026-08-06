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
import importlib.util
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
SUMMARIZE_SCRIPT = REPO / "scripts" / "summarize_real_datasets.py"
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

_TIMING_SUFFIX = (
    "dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,"
    "pair_id,pair_kind,label,record_a,record_b,"
    "k,m,hash_seed,trial_index,phase_minhash_ms,phase_encode_ms,"
    "phase_encrypt_ms,phase_cloud_multiply_ms,phase_cloud_rotate_ms,"
    "phase_sanitize_ms,phase_decrypt_ms,phase_bias_correction_ms,"
    "total_query_ms,result_value,ciphertext_bytes,upload_bytes,"
    "download_bytes"
)
EXPECTED_TIMING_HEADER_LF = _PREFIX_HEADER + "," + _TIMING_SUFFIX + "\n"

# Sub-phase 5.5 (scripts/summarize_real_datasets.py) -- pasted byte-for-byte
# from normative plan §Phase 5 "The exact summary header is:", independently
# of the script under test.
SUMMARY_HEADER_LF = (
    "dataset,variant,jaccard_bucket,n,mae,sample_sd,median,p95,max,"
    "ci95_low,ci95_high\n"
)
_BUCKET_ORDER = ("b00_10", "b10_30", "b30_60", "b60_100")
_ACCURACY_HEADER_FIELDS = EXPECTED_ACCURACY_HEADER_LF.strip("\n").split(",")

_ACCURACY_HASH_DOMAIN = b"piccard-real-crs-v1"
_TIMING_HASH_DOMAIN = b"piccard-real-timing-crs-v1"

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


def derive_timing_hash_seed(root_seed: int, dataset_manifest_sha256_raw: bytes,
                            k: int, m: int, profile_id: str) -> int:
    """Independent Python re-implementation of the normative timing seed
    derivation, for cross-checking the C++ driver's output (never imported
    from the implementation under test)."""
    profile_bytes = profile_id.encode("utf-8")
    buffer = (
        _TIMING_HASH_DOMAIN
        + b"\x00"
        + root_seed.to_bytes(8, "big")
        + dataset_manifest_sha256_raw
        + k.to_bytes(4, "big")
        + m.to_bytes(4, "big")
        + len(profile_bytes).to_bytes(4, "big")
        + profile_bytes
    )
    digest = hashlib.sha256(buffer).digest()
    return int.from_bytes(digest[:8], "big")


def parse_records_tsv(path: Path) -> dict:
    """Maps record_id -> bucketed_feature_count from a records.tsv file."""
    lines = path.read_text(encoding="utf-8").split("\n")
    assert lines[-1] == ""
    lines = lines[:-1]
    header = lines[0].split("\t")
    assert header[0] == "record_id"
    assert header[3] == "bucketed_feature_count"
    sizes = {}
    for line in lines[1:]:
        cells = line.split("\t")
        sizes[cells[0]] = int(cells[3])
    return sizes


def parse_pairs_tsv(path: Path) -> list:
    """Returns [(pair_id, record_a, record_b, pair_kind, label), ...]."""
    lines = path.read_text(encoding="utf-8").split("\n")
    assert lines[-1] == ""
    lines = lines[:-1]
    header = lines[0].split("\t")
    assert header == ["pair_id", "record_a", "record_b", "pair_kind", "label"]
    return [tuple(line.split("\t")) for line in lines[1:]]


def expected_median_pair(fixture_dir: Path) -> str:
    """Independently recomputes the median-combined-bucketed-size pair
    selection (lexical pair_id tie-break) from the fixture's records.tsv
    and pairs.tsv, mirroring the normative selection rule without importing
    the implementation under test."""
    sizes = parse_records_tsv(fixture_dir / "records.tsv")
    pairs = parse_pairs_tsv(fixture_dir / "pairs.tsv")
    combined = [
        (pair_id, sizes[record_a] + sizes[record_b])
        for pair_id, record_a, record_b, _kind, _label in pairs
    ]
    values = sorted(size for _pid, size in combined)
    n = len(values)
    median = (
        values[n // 2]
        if n % 2 == 1
        else (values[n // 2 - 1] + values[n // 2]) / 2.0
    )
    best_pair_id = None
    best_distance = None
    for pair_id, size in combined:
        distance = abs(size - median)
        if (
            best_distance is None
            or distance < best_distance
            or (distance == best_distance and pair_id < best_pair_id)
        ):
            best_distance = distance
            best_pair_id = pair_id
    return best_pair_id


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


def load_summarizer_module():
    """Loads scripts/summarize_real_datasets.py by file path (mirroring
    load_module() in tests/scripts/test_real_dataset_preprocess.py), for
    tests that check module-level attributes directly rather than through
    the CLI subprocess boundary."""
    spec = importlib.util.spec_from_file_location(
        "summarize_real_datasets", SUMMARIZE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_accuracy_csv(path: Path, rows) -> None:
    """Writes a synthetic accuracy CSV matching EXPECTED_ACCURACY_HEADER_LF's
    exact 73-column shape. `rows` is a list of dicts; any of the header's
    columns not present in a given dict default to the empty-field N/A
    sentinel. summarize_real_datasets.py only reads dataset/variant/
    exact_jaccard_bucketed/abs_error, so the untouched columns' placeholder
    content never affects the tests built on this helper."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(_ACCURACY_HEADER_FIELDS)
        for row in rows:
            writer.writerow([row.get(name, "") for name in _ACCURACY_HEADER_FIELDS])


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

class RealDatasetPipelineTimingTest(unittest.TestCase):
    """--mode=timing (Work 5 Sub-phase 5.4). TOY scale, trials=1 for every
    assertion except the contiguous-index/cardinality checks, which need
    trials=2 (per the phase's benchmark execution policy)."""

    maxDiff = None

    def setUp(self):
        require_binary()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out_dir = Path(self.temp.name)
        self.fixture_dir = QUICK_FIXTURE_MANIFEST.parent

    def run_timing(self, *, dataset_manifest: Path, profile="toy-smoke", k=16,
                   m=16, trials=1, timing_pair="median", seed=7, suffix=""):
        csv_path = self.out_dir / f"timing{suffix}.csv"
        workload_manifest_path = self.out_dir / f"timing_workload{suffix}.manifest.tsv"
        completed = subprocess.run(
            [
                str(BINARY),
                f"--dataset-manifest={dataset_manifest}",
                "--mode=timing",
                f"--profile={profile}",
                f"--k={k}",
                f"--m={m}",
                f"--trials={trials}",
                f"--timing-pair={timing_pair}",
                f"--seed={seed}",
                f"--csv={csv_path}",
                f"--workload-manifest-out={workload_manifest_path}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed, csv_path, workload_manifest_path

    def test_exact_header_bytes(self):
        _, csv_path, _ = self.run_timing(dataset_manifest=QUICK_FIXTURE_MANIFEST)
        content = csv_path.read_text(encoding="utf-8")
        header_line = content.split("\n", 1)[0] + "\n"
        self.assertEqual(header_line, EXPECTED_TIMING_HEADER_LF)

    def test_row_count_equals_trials(self):
        _, csv_path, _ = self.run_timing(dataset_manifest=QUICK_FIXTURE_MANIFEST, trials=1)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["trial_index"], "0")

    def test_input_pair_count_and_contiguous_indices(self):
        _, _, manifest_path = self.run_timing(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, trials=2, suffix="-trials2")
        manifest = parse_two_column_tsv(manifest_path)
        self.assertEqual(manifest["schema_version"], "piccard-real-timing-workload-v1")
        self.assertEqual(manifest["input_pair_count"], "3")
        self.assertEqual(manifest["input.000.role"], "warmup")
        self.assertEqual(manifest["input.000.trial_index"], "")
        self.assertEqual(manifest["input.001.role"], "measured")
        self.assertEqual(manifest["input.001.trial_index"], "0")
        self.assertEqual(manifest["input.002.role"], "measured")
        self.assertEqual(manifest["input.002.trial_index"], "1")
        self.assertNotIn("input.003.role", manifest)

        hash_re = re.compile(r"^[0-9a-f]{64}$")
        all_hashes = []
        for index in ("000", "001", "002"):
            a = manifest[f"input.{index}.a_sha256"]
            b = manifest[f"input.{index}.b_sha256"]
            self.assertRegex(a, hash_re)
            self.assertRegex(b, hash_re)
            all_hashes.extend([a, b])
        # Every trial (including the warmup) freshly re-encrypts under BFV's
        # randomized encryption, so all six hashes must be pairwise distinct.
        self.assertEqual(len(set(all_hashes)), len(all_hashes))

    def test_prefix_workload_sha_equals_manifest_sha(self):
        _, csv_path, manifest_path = self.run_timing(dataset_manifest=QUICK_FIXTURE_MANIFEST)
        expected_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["workload_manifest_sha256"], expected_sha)

    def test_median_pair_selection(self):
        expected_pair_id = expected_median_pair(self.fixture_dir)
        _, csv_path, _ = self.run_timing(dataset_manifest=QUICK_FIXTURE_MANIFEST)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["pair_id"], expected_pair_id)

    def test_timing_root_seed_sensitivity(self):
        _, csv_a, _ = self.run_timing(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, seed=7, suffix="-seed7")
        _, csv_b, _ = self.run_timing(
            dataset_manifest=QUICK_FIXTURE_MANIFEST, seed=8, suffix="-seed8")
        with csv_a.open(newline="", encoding="utf-8") as handle:
            hash_a = list(csv.DictReader(handle))[0]["hash_seed"]
        with csv_b.open(newline="", encoding="utf-8") as handle:
            hash_b = list(csv.DictReader(handle))[0]["hash_seed"]
        self.assertNotEqual(hash_a, hash_b)

    def test_hash_seed_matches_independent_recomputation(self):
        _, csv_path, _ = self.run_timing(dataset_manifest=QUICK_FIXTURE_MANIFEST, seed=7)
        dataset_manifest_sha256_raw = hashlib.sha256(
            QUICK_FIXTURE_MANIFEST.read_bytes()).digest()
        expected = derive_timing_hash_seed(
            7, dataset_manifest_sha256_raw, 16, 16, "toy-smoke")
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(int(row["hash_seed"]), expected)

    def test_missing_output_flags_are_rejected(self):
        csv_path = self.out_dir / "timing.csv"
        completed = subprocess.run(
            [
                str(BINARY),
                f"--dataset-manifest={QUICK_FIXTURE_MANIFEST}",
                "--mode=timing",
                "--profile=toy-smoke", "--k=16", "--m=16", "--trials=1",
                "--timing-pair=median", "--seed=7",
                f"--csv={csv_path}",
                # --workload-manifest-out omitted.
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertFalse(csv_path.exists())

    def test_measurement_kind_is_fhe_timing(self):
        _, csv_path, _ = self.run_timing(dataset_manifest=QUICK_FIXTURE_MANIFEST)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["measurement_kind"], "fhe-timing")
            self.assertEqual(row["profile_id"], "toy-smoke")


class SummarizeRealDatasetsTest(unittest.TestCase):
    """scripts/summarize_real_datasets.py (Work 5 Sub-phase 5.5): CLI
    contract, bucket grouping/all-four-buckets emission, and statistics
    identical to piccard::data::Summarize (Sub-phase 5.1), tested through
    the real subprocess boundary (mandatory flags, exit codes, stdout
    silence) exactly as the accuracy/timing modes are above.

    Hermetic: every test writes its inputs/outputs under
    tempfile.TemporaryDirectory(); none of them touch the real datasets/
    tree or the network.
    """

    maxDiff = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out_dir = Path(self.temp.name)

    def run_summarizer(self, input_path: Path, output_path: Path):
        return subprocess.run(
            [
                sys.executable, str(SUMMARIZE_SCRIPT),
                f"--input={input_path}",
                f"--output={output_path}",
            ],
            capture_output=True,
            text=True,
        )

    def read_summary_rows(self, output_path: Path):
        with output_path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def test_golden_summary_from_5_3_fixture_accuracy_run(self):
        # Same TOY invocation as RealDatasetPipelineAccuracyTest above
        # (k=16 m=16 max-pairs=2 accuracy_trials=1 seed=7), per the phase's
        # benchmark execution policy.
        require_binary()
        accuracy_csv = self.out_dir / "accuracy.csv"
        subprocess.run(
            [
                str(BINARY),
                f"--dataset-manifest={QUICK_FIXTURE_MANIFEST}",
                "--mode=accuracy",
                "--k=16", "--m=16", "--max-pairs=2", "--accuracy_trials=1",
                "--seed=7", "--hash_randomness=resampled",
                f"--csv={accuracy_csv}",
                f"--workload-manifest-out={self.out_dir / 'wm.tsv'}",
                f"--workload-rows-out={self.out_dir / 'wr.tsv'}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        with accuracy_csv.open(newline="", encoding="utf-8") as handle:
            accuracy_rows = list(csv.DictReader(handle))
        # Hand-verified against this fixture's actual output (independently
        # of the summarizer under test): both pairs land in b00_10 with
        # exact_jaccard_bucketed == abs_error == 0, so the summary's b00_10
        # bucket has n=2 with every statistic equal to 0 and the other
        # three buckets are empty (n=0).
        self.assertEqual(len(accuracy_rows), 2)
        for row in accuracy_rows:
            self.assertEqual(row["jaccard_bucket"], "b00_10")
            self.assertEqual(float(row["exact_jaccard_bucketed"]), 0.0)
            self.assertEqual(float(row["abs_error"]), 0.0)

        output_csv = self.out_dir / "summary.csv"
        completed = self.run_summarizer(accuracy_csv, output_csv)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")

        content = output_csv.read_text(encoding="utf-8")
        self.assertEqual(content.split("\n", 1)[0] + "\n", SUMMARY_HEADER_LF)

        rows = self.read_summary_rows(output_csv)
        self.assertEqual(len(rows), 4)
        self.assertEqual([row["jaccard_bucket"] for row in rows], list(_BUCKET_ORDER))
        by_bucket = {row["jaccard_bucket"]: row for row in rows}

        golden = by_bucket["b00_10"]
        self.assertEqual(golden["dataset"], "dblp_acm")
        self.assertEqual(golden["variant"], "dblp_acm_u65536")
        self.assertEqual(golden["n"], "2")
        for field in ("mae", "sample_sd", "median", "p95", "max",
                      "ci95_low", "ci95_high"):
            self.assertEqual(golden[field], "0")

        for bucket in ("b10_30", "b30_60", "b60_100"):
            empty = by_bucket[bucket]
            self.assertEqual(empty["n"], "0")
            for field in ("mae", "sample_sd", "median", "p95", "max",
                          "ci95_low", "ci95_high"):
                self.assertEqual(empty[field], "")

    def test_n0_n1_n2_bucket_cases(self):
        # b10_30 n=1 mirrors SummarizeTest.SingleValueAllStatsEqualSoleValue
        # (tests/unit/test_real_dataset_metrics.cpp); b30_60 n=2 mirrors
        # SummarizeTest.GoldenTwoPairMedianIsMeanOfBothAndP95IsLargerNearestRank
        # ({0.3, 0.1} unsorted); b00_10 and b60_100 stay at n=0.
        rows = [
            {"dataset": "ds", "variant": "v1",
             "exact_jaccard_bucketed": "0.15", "abs_error": "0.25"},
            {"dataset": "ds", "variant": "v1",
             "exact_jaccard_bucketed": "0.35", "abs_error": "0.3"},
            {"dataset": "ds", "variant": "v1",
             "exact_jaccard_bucketed": "0.45", "abs_error": "0.1"},
        ]
        input_csv = self.out_dir / "accuracy_n012.csv"
        _write_accuracy_csv(input_csv, rows)
        output_csv = self.out_dir / "summary_n012.csv"
        completed = self.run_summarizer(input_csv, output_csv)
        self.assertEqual(completed.returncode, 0, completed.stderr)

        by_bucket = {row["jaccard_bucket"]: row
                     for row in self.read_summary_rows(output_csv)}
        self.assertEqual(set(by_bucket), set(_BUCKET_ORDER))

        n0 = by_bucket["b00_10"]
        self.assertEqual(n0["n"], "0")
        for field in ("mae", "sample_sd", "median", "p95", "max",
                      "ci95_low", "ci95_high"):
            self.assertEqual(n0[field], "")

        n1 = by_bucket["b10_30"]
        self.assertEqual(n1["n"], "1")
        self.assertEqual(n1["mae"], "0.25")
        self.assertEqual(n1["median"], "0.25")
        self.assertEqual(n1["p95"], "0.25")
        self.assertEqual(n1["max"], "0.25")
        self.assertEqual(n1["sample_sd"], "")
        self.assertEqual(n1["ci95_low"], "")
        self.assertEqual(n1["ci95_high"], "")

        n2 = by_bucket["b30_60"]
        self.assertEqual(n2["n"], "2")
        self.assertAlmostEqual(float(n2["mae"]), 0.2, places=12)
        self.assertAlmostEqual(float(n2["median"]), 0.2, places=12)
        self.assertAlmostEqual(float(n2["p95"]), 0.3, places=12)
        self.assertAlmostEqual(float(n2["max"]), 0.3, places=12)
        self.assertAlmostEqual(float(n2["sample_sd"]), 0.02 ** 0.5, places=12)
        self.assertAlmostEqual(float(n2["ci95_low"]), 0.2 - 0.196, places=9)
        self.assertAlmostEqual(float(n2["ci95_high"]), 0.2 + 0.196, places=9)

        n0_top = by_bucket["b60_100"]
        self.assertEqual(n0_top["n"], "0")
        self.assertEqual(n0_top["mae"], "")

    def test_asymmetric_and_n20_vectors_mirror_5_1_gate_findings(self):
        rows = []
        # Mirrors SummarizeTest.AsymmetricOddVectorPinsMedianDistinctFromMean:
        # sorted {0.1, 0.1, 0.7}; median (0.1) must differ from the mean (0.3).
        for abs_error in (0.7, 0.1, 0.1):
            rows.append({"dataset": "ds", "variant": "asym-odd",
                         "exact_jaccard_bucketed": "0.05",
                         "abs_error": repr(abs_error)})
        # Mirrors
        # SummarizeTest.AsymmetricEvenVectorPinsMeanOfTwoCentersDistinctFromMean:
        # sorted {0.1, 0.1, 0.2, 0.8}; median (0.15) must differ from mean (0.3).
        for abs_error in (0.8, 0.1, 0.2, 0.1):
            rows.append({"dataset": "ds", "variant": "asym-even",
                         "exact_jaccard_bucketed": "0.05",
                         "abs_error": repr(abs_error)})
        # Mirrors SummarizeTest.NearestRankP95DiffersFromMaxAtTwentyValues:
        # 0.01..0.19 (19 values) plus an outlier 5.0; p95 (sorted[18]=0.19)
        # must differ from max (5.0), which only diverges at n>=20.
        for i in range(1, 20):
            rows.append({"dataset": "ds", "variant": "n20",
                         "exact_jaccard_bucketed": "0.05",
                         "abs_error": repr(i / 100.0)})
        rows.append({"dataset": "ds", "variant": "n20",
                     "exact_jaccard_bucketed": "0.05", "abs_error": "5.0"})

        input_csv = self.out_dir / "accuracy_gate.csv"
        _write_accuracy_csv(input_csv, rows)
        output_csv = self.out_dir / "summary_gate.csv"
        completed = self.run_summarizer(input_csv, output_csv)
        self.assertEqual(completed.returncode, 0, completed.stderr)

        by_variant_bucket = {
            (row["variant"], row["jaccard_bucket"]): row
            for row in self.read_summary_rows(output_csv)
        }

        odd = by_variant_bucket[("asym-odd", "b00_10")]
        self.assertEqual(odd["n"], "3")
        self.assertAlmostEqual(float(odd["median"]), 0.1, places=12)
        self.assertAlmostEqual(float(odd["mae"]), 0.3, places=12)
        self.assertAlmostEqual(float(odd["max"]), 0.7, places=12)
        self.assertGreater(abs(float(odd["median"]) - float(odd["mae"])), 0.1)

        even = by_variant_bucket[("asym-even", "b00_10")]
        self.assertEqual(even["n"], "4")
        self.assertAlmostEqual(float(even["median"]), 0.15, places=12)
        self.assertAlmostEqual(float(even["mae"]), 0.3, places=12)
        self.assertGreater(abs(float(even["median"]) - float(even["mae"])), 0.1)

        n20 = by_variant_bucket[("n20", "b00_10")]
        self.assertEqual(n20["n"], "20")
        self.assertAlmostEqual(float(n20["p95"]), 0.19, places=12)
        self.assertAlmostEqual(float(n20["max"]), 5.0, places=12)
        self.assertAlmostEqual(float(n20["median"]), 0.105, places=12)
        self.assertAlmostEqual(float(n20["mae"]), 0.345, places=12)
        self.assertGreater(abs(float(n20["p95"]) - float(n20["max"])), 1.0)

    def test_byte_identical_rerun(self):
        rows = [
            {"dataset": "ds", "variant": "v1",
             "exact_jaccard_bucketed": "0.15", "abs_error": "0.25"},
            {"dataset": "ds", "variant": "v1",
             "exact_jaccard_bucketed": "0.35", "abs_error": "0.3"},
            {"dataset": "ds", "variant": "v1",
             "exact_jaccard_bucketed": "0.45", "abs_error": "0.1"},
        ]
        input_csv = self.out_dir / "accuracy_rerun.csv"
        _write_accuracy_csv(input_csv, rows)
        output_a = self.out_dir / "summary_a.csv"
        output_b = self.out_dir / "summary_b.csv"
        completed_a = self.run_summarizer(input_csv, output_a)
        completed_b = self.run_summarizer(input_csv, output_b)
        self.assertEqual(completed_a.returncode, 0, completed_a.stderr)
        self.assertEqual(completed_b.returncode, 0, completed_b.stderr)
        self.assertEqual(output_a.read_bytes(), output_b.read_bytes())

    def test_missing_input_flag_exits_nonzero(self):
        output_csv = self.out_dir / "summary.csv"
        completed = subprocess.run(
            [sys.executable, str(SUMMARIZE_SCRIPT), f"--output={output_csv}"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertFalse(output_csv.exists())

    def test_missing_output_flag_exits_nonzero(self):
        input_csv = self.out_dir / "accuracy.csv"
        input_csv.write_text(EXPECTED_ACCURACY_HEADER_LF, encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(SUMMARIZE_SCRIPT), f"--input={input_csv}"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")

    def test_wrong_header_is_rejected(self):
        input_csv = self.out_dir / "bad_header.csv"
        input_csv.write_text("a,b,c\n1,2,3\n", encoding="utf-8")
        output_csv = self.out_dir / "summary.csv"
        completed = self.run_summarizer(input_csv, output_csv)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertNotEqual(completed.stderr, "")
        self.assertFalse(output_csv.exists())

    def test_nan_cell_is_rejected(self):
        rows = [{"dataset": "ds", "variant": "v",
                 "exact_jaccard_bucketed": "nan", "abs_error": "0.1"}]
        input_csv = self.out_dir / "nan_accuracy.csv"
        _write_accuracy_csv(input_csv, rows)
        output_csv = self.out_dir / "summary.csv"
        completed = self.run_summarizer(input_csv, output_csv)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertNotEqual(completed.stderr, "")
        self.assertFalse(output_csv.exists())

    def test_inf_abs_error_cell_is_rejected(self):
        rows = [{"dataset": "ds", "variant": "v",
                 "exact_jaccard_bucketed": "0.05", "abs_error": "inf"}]
        input_csv = self.out_dir / "inf_accuracy.csv"
        _write_accuracy_csv(input_csv, rows)
        output_csv = self.out_dir / "summary.csv"
        completed = self.run_summarizer(input_csv, output_csv)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertFalse(output_csv.exists())

    def test_empty_input_no_groups_emits_no_rows(self):
        input_csv = self.out_dir / "empty_accuracy.csv"
        _write_accuracy_csv(input_csv, [])
        output_csv = self.out_dir / "summary_empty.csv"
        completed = self.run_summarizer(input_csv, output_csv)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        content = output_csv.read_text(encoding="utf-8")
        self.assertEqual(content, SUMMARY_HEADER_LF)


class SummarizerFormatFloatGoldenTest(unittest.TestCase):
    """Confirms scripts/summarize_real_datasets.py's float formatting is
    byte-identical to the shared golden vectors already pinned in
    tests/scripts/test_real_dataset_preprocess.py::FormattingGoldenTests
    and tests/unit/test_real_dataset_metrics.cpp::FormatGoldenVectors(). A
    representative subset is duplicated here with a keep-in-sync comment,
    following this repo's existing convention for this shared table."""

    # Keep in sync with FormattingGoldenTests.GOLDEN_VECTORS in
    # tests/scripts/test_real_dataset_preprocess.py.
    GOLDEN_VECTORS = (
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (0.5, "0.5"),
        (0.1, "0.10000000000000001"),
        (0.6000000000000001, "0.60000000000000009"),
        (1e-300, "1e-300"),
        (1e300, "1.0000000000000001e+300"),
    )

    @classmethod
    def setUpClass(cls):
        cls.module = load_summarizer_module()

    def test_format_float_matches_shared_golden_vectors(self):
        for value, expected in self.GOLDEN_VECTORS:
            with self.subTest(value=value):
                self.assertEqual(self.module.format_float(value), expected)


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
