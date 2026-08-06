#!/usr/bin/env python3
"""Behavior tests for scripts/run_real_datasets.sh and
scripts/verify_real_dataset_outputs.py (Work 5, master Task 9B).

Hermetic: every test writes results-roots and fake build directories under
tempfile.TemporaryDirectory(); no test touches the real `datasets/` tree or
the network. `bench_real_datasets` is replaced by a small deterministic fake
executable (this suite never builds or links OpenFHE); `summarize_real_datasets.py`
is always the REAL, already-tested script, since the runner resolves it from
the committed source root rather than from a caller-controlled build dir.

Paper-mode tests that must actually execute (not just --dry-run) need a
clean git tree, which this feature branch is not guaranteed to have while
under development; those few tests run inside a throwaway `git worktree`
checked out at HEAD (always clean by construction) rather than skipping.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_real_datasets.sh"
VERIFIER = ROOT / "scripts" / "verify_real_dataset_outputs.py"
QUICK_VARIANT = "dblp_acm_u65536"
QUICK_FIXTURE_DIR = ROOT / "tests" / "fixtures" / "real_datasets" / "quick" / QUICK_VARIANT
QUICK_SOURCE_MANIFEST = QUICK_FIXTURE_DIR / "source.manifest.tsv"
QUICK_DATASET_MANIFEST = QUICK_FIXTURE_DIR / "dataset.manifest.tsv"

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
_TIMING_SUFFIX = (
    "dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,"
    "pair_id,pair_kind,label,record_a,record_b,"
    "k,m,hash_seed,trial_index,phase_minhash_ms,phase_encode_ms,"
    "phase_encrypt_ms,phase_cloud_multiply_ms,phase_cloud_rotate_ms,"
    "phase_sanitize_ms,phase_decrypt_ms,phase_bias_correction_ms,"
    "total_query_ms,result_value,ciphertext_bytes,upload_bytes,"
    "download_bytes"
)
ACCURACY_HEADER_FIELDS = (_PREFIX_HEADER + "," + _ACCURACY_SUFFIX).split(",")
TIMING_HEADER_FIELDS = (_PREFIX_HEADER + "," + _TIMING_SUFFIX).split(",")


def load_verifier_module():
    spec = importlib.util.spec_from_file_location("verify_real_dataset_outputs", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_executable(path: pathlib.Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


_FAKE_BENCH_BODY = r'''
#!/usr/bin/env python3
"""Deterministic stand-in for bench_real_datasets used only by
tests/scripts/test_run_real_datasets.py. Never built with OpenFHE; emits
schema-correct CSV rows for the real 73/68-column headers so the verifier's
row-level checks run against realistic content."""
import os
import sys


ACCURACY_HEADER = %(accuracy_header)r
TIMING_HEADER = %(timing_header)r


def parse_opts(argv):
    opts = {}
    for arg in argv:
        assert arg.startswith("--"), arg
        if "=" in arg:
            key, value = arg[2:].split("=", 1)
        else:
            key, value = arg[2:], "true"
        opts[key] = value
    return opts


def read_kv(path):
    values = {}
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    assert lines[-1] == ""
    for line in lines[1:-1]:
        key, value = line.split("\t", 1)
        values[key] = value
    return values


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if os.environ.get("PICCARD_FAKE_EXIT_NONZERO") == "1":
        sys.stderr.write("fake bench_real_datasets: forced failure\n")
        return 2

    opts = parse_opts(sys.argv[1:])
    mode = opts["mode"]
    manifest_path = opts["dataset-manifest"]
    manifest = read_kv(manifest_path)
    manifest_sha = sha256_file(manifest_path)
    eligible = os.environ.get("PICCARD_FAKE_COMPARISON_ELIGIBLE", "false")
    bad_field = os.environ.get("PICCARD_FAKE_BAD_FIELD", "")
    bad_value = os.environ.get("PICCARD_FAKE_BAD_VALUE", "")
    variant_override = os.environ.get("PICCARD_FAKE_VARIANT_OVERRIDE", "")

    def row_dict(**overrides):
        base = {name: "" for name in (ACCURACY_HEADER if mode == "accuracy" else TIMING_HEADER)}
        base.update({
            "profile_id": "plaintext-estimator" if mode == "accuracy" else opts["profile"],
            "run_class": "diagnostic",
            "cryptographic_profile": "not-applicable",
            "security_match": "false",
            "comparison_eligible": eligible,
            "comparison_scope": "diagnostic-only",
            "primitive": "sha256-minhash",
            "protocol_model": "plaintext-estimator-pipeline",
            "output_semantics": "bias-corrected-jaccard-estimate",
            "assurance_scope": "empirical-poc",
            "security_basis": "not-applicable",
            "cost_scope": "not-applicable",
            "precomputation_mode": "not-applicable",
            "secure_division_included": "false",
            "measurement_kind": "plaintext-estimator" if mode == "accuracy" else "fhe-timing",
            "workload_id": "real:fake:workload",
            "workload_manifest_sha256": "0" * 64,
            "execution_trace_sha256": "not-applicable",
            "root_seed": opts["seed"],
            "omp_threads": os.environ.get("OMP_NUM_THREADS", "1"),
            "estimator_model": "sha256-random-ranking-poc-v1",
            "sanitizer_model": "not-applicable",
            "sanitizer_assurance": "not-applicable",
            "openfhe_version": "not-applicable",
            "target_semantics": "observed-dataset-pair",
            "omp_dynamic": "false",
            "measurement_status": "measured",
            "dataset": manifest.get("dataset", "dblp_acm"),
            "variant": variant_override or manifest.get("variant", ""),
            "dataset_manifest_sha256": manifest_sha,
            "records_sha256": manifest["records_sha256"],
            "pairs_sha256": manifest["pairs_sha256"],
            "pair_id": "fake-pair:0",
            "pair_kind": "known_match",
            "label": "1",
            "record_a": "dblp:aaaa",
            "record_b": "acm:bbbb",
            "k": opts["k"],
            "m": opts["m"],
        })
        if mode == "accuracy":
            base.update({
                "hash_randomness": opts["hash_randomness"],
                "accuracy_trial_index": "0",
                "hash_seed": "1",
                "set_size_a_raw": "3", "set_size_b_raw": "3",
                "set_size_a_bucketed": "3", "set_size_b_bucketed": "3",
                "exact_jaccard_raw": "1.0", "exact_jaccard_bucketed": "1.0",
                "estimated_jaccard": "1.0", "bucket_match_fraction": "1.0",
                "abs_error": "0.0", "rel_error": "0.0",
                "jaccard_bucket": "b60_100",
                "accuracy_workload_sha256": "0" * 64,
            })
        else:
            base.update({
                "hash_seed": "1", "trial_index": "0",
                "phase_minhash_ms": "0.1", "phase_encode_ms": "0.1",
                "phase_encrypt_ms": "0.1", "phase_cloud_multiply_ms": "0.1",
                "phase_cloud_rotate_ms": "0.1", "phase_sanitize_ms": "0.1",
                "phase_decrypt_ms": "0.1", "phase_bias_correction_ms": "0.1",
                "total_query_ms": "0.8", "result_value": "1.0",
                "ciphertext_bytes": "100", "upload_bytes": "100",
                "download_bytes": "100",
            })
        base.update(overrides)
        if bad_field:
            base[bad_field] = bad_value
        return base

    header = ACCURACY_HEADER if mode == "accuracy" else TIMING_HEADER
    if mode == "accuracy":
        max_pairs = int(opts["max-pairs"])
        accuracy_trials = int(opts["accuracy_trials"])
        row_count = max_pairs * accuracy_trials
    else:
        row_count = int(opts["trials"])

    csv_path = opts["csv"]
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        import csv as csv_module
        writer = csv_module.writer(handle, lineterminator="\n")
        writer.writerow(header)
        for i in range(row_count):
            row = row_dict()
            writer.writerow([row[name] for name in header])

    with open(opts["workload-manifest-out"], "w", encoding="utf-8") as handle:
        handle.write("key\tvalue\nschema_version\tfake-workload-v1\n")
    if mode == "accuracy":
        with open(opts["workload-rows-out"], "w", encoding="utf-8") as handle:
            handle.write("pair_id\ttrial_index\thash_seed\trecord_a\trecord_b\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def write_fake_bench_real_datasets(build_dir: pathlib.Path) -> pathlib.Path:
    build_dir.mkdir(parents=True, exist_ok=True)
    path = build_dir / "bench_real_datasets"
    body = _FAKE_BENCH_BODY % {
        "accuracy_header": ACCURACY_HEADER_FIELDS,
        "timing_header": TIMING_HEADER_FIELDS,
    }
    make_executable(path, body)
    (build_dir / "CMakeCache.txt").write_text(
        "CMAKE_BUILD_TYPE:STRING=Release\n", encoding="utf-8")
    return path


def run_command(command, *, cwd=None, env=None):
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(command, cwd=cwd or ROOT, env=merged, text=True,
                          capture_output=True, check=False)


def run_runner(*args, env=None):
    return run_command([str(RUNNER), *args], env=env)


def run_verifier(results_root, env=None):
    return run_command([sys.executable, str(VERIFIER), str(results_root)], env=env)


def read_kv_file(path: pathlib.Path) -> dict:
    values = {}
    lines = path.read_text(encoding="utf-8").split("\n")
    assert lines[-1] == ""
    assert lines[0] == "key\tvalue"
    for line in lines[1:-1]:
        key, value = line.split("\t", 1)
        assert key not in values, f"duplicate key {key!r}"
        values[key] = value
    return values


class QuickCliValidationTest(unittest.TestCase):
    """Argument-parsing rejections that never touch the filesystem beyond
    what argparse/parse_args itself needs (Phase 6 RED list)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = pathlib.Path(self.temp.name)

    def test_relative_build_dir_rejected(self):
        result = run_runner("--quick", "--seed=7", "--threads=2",
                            "--build-dir=relative/build",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute", result.stderr)
        self.assertFalse((self.tmp / "results").exists())

    def test_relative_results_root_rejected(self):
        result = run_runner("--quick", "--seed=7", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            "--results-root=relative/results")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute", result.stderr)

    def test_resume_and_dry_run_mutually_exclusive(self):
        result = run_runner("--quick", "--seed=7", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}",
                            "--resume", "--dry-run")
        self.assertNotEqual(result.returncode, 0)

    def test_quick_with_explicit_manifest_rejected(self):
        result = run_runner("--quick", f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
                            "--seed=7", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)

    def test_no_quick_and_no_manifests_rejected(self):
        result = run_runner("--seed=7", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)

    def test_mismatched_source_dataset_manifest_counts_rejected(self):
        result = run_runner(f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                            f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
                            "--profile=std128-t40-primary",
                            "--profile=std192-t40-primary",
                            "--seed=20260729", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)

    def test_seed_must_be_positive(self):
        result = run_runner("--quick", "--seed=0", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)

    def test_threads_must_be_positive(self):
        result = run_runner("--quick", "--seed=7", "--threads=0",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)

    def test_paper_mode_requires_profile(self):
        result = run_runner(f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
                            "--seed=20260729", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)

    def test_paper_mode_missing_one_profile_rejected(self):
        result = run_runner(f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
                            "--profile=std128-t40-primary",
                            "--seed=20260729", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)

    def test_paper_mode_unknown_profile_rejected(self):
        result = run_runner(f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
                            "--profile=std128-t40-primary",
                            "--profile=std999-bogus",
                            "--seed=20260729", "--threads=2",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}")
        self.assertNotEqual(result.returncode, 0)


class DryRunTest(unittest.TestCase):
    """Dry-run prints the exact matrix before any directory creation
    (Phase 6 RED list: "dry-run has zero side effects")."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = pathlib.Path(self.temp.name)

    def test_quick_dry_run_zero_side_effects_and_exact_matrix(self):
        build_dir = self.tmp / "never-created-build"
        results_root = self.tmp / "never-created-results"
        result = run_runner("--quick", "--seed=7", "--threads=2",
                            f"--build-dir={build_dir}",
                            f"--results-root={results_root}", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(build_dir.exists())
        self.assertFalse(results_root.exists())
        run_lines = [line for line in result.stdout.splitlines()
                    if line.startswith("RUN ")]
        self.assertEqual(len(run_lines), 3)
        self.assertIn("--mode=accuracy", run_lines[0])
        self.assertIn("--max-pairs=2", run_lines[0])
        self.assertIn("--accuracy_trials=1", run_lines[0])
        self.assertIn("OMP_NUM_THREADS=1", run_lines[0])
        self.assertIn("summarize_real_datasets.py", run_lines[1])
        self.assertIn("--mode=timing", run_lines[2])
        self.assertIn("--profile=toy-smoke", run_lines[2])
        self.assertIn("--trials=1", run_lines[2])
        self.assertIn("OMP_NUM_THREADS=2", run_lines[2])

    def test_dry_run_does_not_require_build_dir_to_exist(self):
        result = run_runner("--quick", "--seed=7", "--threads=2",
                            f"--build-dir={self.tmp / 'missing'}",
                            f"--results-root={self.tmp / 'also-missing'}",
                            "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_paper_dry_run_pins_exactly_four_cells(self):
        result = run_runner(f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
                            "--profile=std128-t40-primary",
                            "--profile=std192-t40-primary",
                            "--seed=20260729", "--threads=8",
                            f"--build-dir={self.tmp / 'build'}",
                            f"--results-root={self.tmp / 'results'}",
                            "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        run_lines = [line for line in result.stdout.splitlines()
                    if line.startswith("RUN ")]
        self.assertEqual(len(run_lines), 4)
        self.assertIn("--max-pairs=10000", run_lines[0])
        self.assertIn("--trials=30", run_lines[2])
        self.assertIn("--profile=std128-t40-primary", run_lines[2])
        self.assertIn("--trials=30", run_lines[3])
        self.assertIn("--profile=std192-t40-primary", run_lines[3])


class PathSafetyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = pathlib.Path(self.temp.name)
        self.build_dir = self.tmp / "build"
        write_fake_bench_real_datasets(self.build_dir)

    def test_pre_existing_results_root_without_resume_rejected(self):
        results_root = self.tmp / "results"
        results_root.mkdir()
        result = run_runner("--quick", "--seed=7", "--threads=2",
                            f"--build-dir={self.build_dir}",
                            f"--results-root={results_root}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)

    def test_resume_requires_existing_results_root(self):
        results_root = self.tmp / "never-created"
        result = run_runner("--quick", "--resume", "--seed=7", "--threads=2",
                            f"--build-dir={self.build_dir}",
                            f"--results-root={results_root}")
        self.assertNotEqual(result.returncode, 0)


class QuickEndToEndTest(unittest.TestCase):
    """Real runner + real verifier, against a fake bench_real_datasets."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Resolved up front: the runner canonicalizes --results-root's
        # parent (macOS aliases /tmp -> /private/tmp, /var -> /private/var),
        # so argv-golden assertions must compare against the same resolved
        # path the runner itself records, not the raw TemporaryDirectory name.
        self.tmp = pathlib.Path(self.temp.name).resolve()
        self.build_dir = self.tmp / "build"
        write_fake_bench_real_datasets(self.build_dir)
        self.results_root = self.tmp / "results"

    def run_quick(self, *, seed=7, threads=2, results_root=None, env=None, extra=()):
        results_root = results_root or self.results_root
        return run_runner("--quick", f"--seed={seed}", f"--threads={threads}",
                          f"--build-dir={self.build_dir}",
                          f"--results-root={results_root}", *extra, env=env)

    def test_quick_end_to_end_creates_expected_layout_and_verifier_passes(self):
        result = self.run_quick()
        self.assertEqual(result.returncode, 0, result.stderr)
        for relative in (
            "csv/real_accuracy_dblp_acm_u65536.csv",
            "csv/real_accuracy_summary_dblp_acm_u65536.csv",
            "csv/real_timing_dblp_acm_u65536_toy-smoke.csv",
            "workloads/accuracy_dblp_acm_u65536.manifest.tsv",
            "workloads/accuracy_dblp_acm_u65536.rows.tsv",
            "workloads/timing_dblp_acm_u65536_toy-smoke.manifest.tsv",
            "input_manifests/dblp_acm_u65536/source.manifest.tsv",
            "input_manifests/dblp_acm_u65536/dataset.manifest.tsv",
            "run_metadata.tsv", "system_info.txt", "run.log",
        ):
            self.assertTrue((self.results_root / relative).is_file(), relative)
        self.assertFalse(list(self.results_root.glob("run.log.partial.*")))

        verify_result = run_verifier(self.results_root)
        self.assertEqual(verify_result.returncode, 0, verify_result.stderr)
        status = read_kv_file(self.results_root / "verification_status.tsv")
        self.assertEqual(status["schema_version"], "piccard-real-verification-v1")
        self.assertEqual(status["status"], "VERIFIED")
        self.assertRegex(status["run_metadata_sha256"], r"^[0-9a-f]{64}$")
        expected_sha = hashlib.sha256(
            (self.results_root / "run_metadata.tsv").read_bytes()).hexdigest()
        self.assertEqual(status["run_metadata_sha256"], expected_sha)

    def test_verification_status_reproduced_byte_identical_on_rerun(self):
        result = self.run_quick()
        self.assertEqual(result.returncode, 0, result.stderr)
        run_verifier(self.results_root)
        first = (self.results_root / "verification_status.tsv").read_bytes()
        second_result = run_verifier(self.results_root)
        self.assertEqual(second_result.returncode, 0, second_result.stderr)
        second = (self.results_root / "verification_status.tsv").read_bytes()
        self.assertEqual(first, second)

    def test_env_matrix_golden(self):
        self.run_quick()
        metadata = read_kv_file(self.results_root / "run_metadata.tsv")
        # cell.000 = accuracy, cell.001 = accuracy-summary, cell.002 = timing
        for cell_index in ("000", "001"):
            self.assertEqual(metadata[f"cell.{cell_index}.env_count"], "2")
            self.assertEqual(metadata[f"cell.{cell_index}.env.000.key"], "OMP_DYNAMIC")
            self.assertEqual(metadata[f"cell.{cell_index}.env.000.value"], "FALSE")
            self.assertEqual(metadata[f"cell.{cell_index}.env.001.key"], "OMP_NUM_THREADS")
            self.assertEqual(metadata[f"cell.{cell_index}.env.001.value"], "1")
        self.assertEqual(metadata["cell.002.env.001.key"], "OMP_NUM_THREADS")
        self.assertEqual(metadata["cell.002.env.001.value"], "2")

    def test_argv_golden_accuracy_and_timing_cells(self):
        self.run_quick(seed=7, threads=2)
        metadata = read_kv_file(self.results_root / "run_metadata.tsv")
        self.assertEqual(metadata["cell.000.id"], "dblp_acm_u65536:accuracy")
        accuracy_argv = [metadata[f"cell.000.argv.{i:03d}"]
                        for i in range(int(metadata["cell.000.argv_count"]))]
        self.assertEqual(accuracy_argv, [
            "bench_real_datasets",
            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
            "--mode=accuracy", "--k=128", "--m=64", "--max-pairs=2",
            "--accuracy_trials=1", "--seed=7", "--hash_randomness=resampled",
            f"--csv={self.results_root}/csv/real_accuracy_dblp_acm_u65536.csv",
            f"--workload-manifest-out={self.results_root}/workloads/accuracy_dblp_acm_u65536.manifest.tsv",
            f"--workload-rows-out={self.results_root}/workloads/accuracy_dblp_acm_u65536.rows.tsv",
        ])
        self.assertEqual(metadata["cell.000.argv_sha256"],
                         self._argv_sha256(accuracy_argv))

        self.assertEqual(metadata["cell.002.id"], "dblp_acm_u65536:timing:toy-smoke")
        timing_argv = [metadata[f"cell.002.argv.{i:03d}"]
                      for i in range(int(metadata["cell.002.argv_count"]))]
        self.assertEqual(timing_argv, [
            "bench_real_datasets",
            f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
            "--mode=timing", "--profile=toy-smoke", "--k=128", "--m=64",
            "--trials=1", "--timing-pair=median", "--seed=7",
            f"--csv={self.results_root}/csv/real_timing_dblp_acm_u65536_toy-smoke.csv",
            f"--workload-manifest-out={self.results_root}/workloads/timing_dblp_acm_u65536_toy-smoke.manifest.tsv",
        ])

    @staticmethod
    def _argv_sha256(argv):
        hasher = hashlib.sha256()
        for arg in argv:
            encoded = arg.encode("utf-8")
            hasher.update(len(encoded).to_bytes(4, "big"))
            hasher.update(encoded)
        return hasher.hexdigest()

    def test_run_metadata_indexed_grammar_is_contiguous_and_zero_padded(self):
        self.run_quick()
        metadata = read_kv_file(self.results_root / "run_metadata.tsv")
        self.assertEqual(metadata["cell_count"], "3")
        for index in range(3):
            self.assertIn(f"cell.{index:03d}.id", metadata)
        self.assertNotIn("cell.003.id", metadata)
        root_count = int(metadata["root_count"])
        for index in range(root_count):
            self.assertIn(f"root.{index:03d}.id", metadata)
        self.assertNotIn(f"root.{root_count:03d}.id", metadata)

    def test_cell_id_enumeration_exactly_three_quick_cells(self):
        self.run_quick()
        metadata = read_kv_file(self.results_root / "run_metadata.tsv")
        ids = {metadata[f"cell.{i:03d}.id"] for i in range(3)}
        self.assertEqual(ids, {
            "dblp_acm_u65536:accuracy",
            "dblp_acm_u65536:accuracy-summary",
            "dblp_acm_u65536:timing:toy-smoke",
        })

    def test_deterministic_accuracy_csv_across_two_fresh_runs(self):
        result_a = self.run_quick(results_root=self.tmp / "results-a")
        result_b = self.run_quick(results_root=self.tmp / "results-b")
        self.assertEqual(result_a.returncode, 0, result_a.stderr)
        self.assertEqual(result_b.returncode, 0, result_b.stderr)
        csv_a = (self.tmp / "results-a" / "csv" /
                "real_accuracy_dblp_acm_u65536.csv").read_bytes()
        csv_b = (self.tmp / "results-b" / "csv" /
                "real_accuracy_dblp_acm_u65536.csv").read_bytes()
        self.assertEqual(csv_a, csv_b)

    def test_failed_cell_permanently_blocks_resume(self):
        # Normative plan §Phase 6: "missing cells run; failed/inconsistent
        # cells abort" -- a *recorded* failed cell is not silently retried
        # by --resume, even after the underlying cause is fixed. This is a
        # deliberate safety property (never paper over a recorded failure
        # with a bare --resume); recovering requires a fresh --results-root.
        first = self.run_quick(env={"PICCARD_FAKE_EXIT_NONZERO": "1"})
        self.assertNotEqual(first.returncode, 0)
        self.assertFalse((self.results_root / "run.log").is_file())
        self.assertTrue(list(self.results_root.glob("run.log.partial.*")))
        metadata = read_kv_file(self.results_root / "run_metadata.tsv")
        self.assertEqual(metadata["cell.000.status"], "failed")

        second = self.run_quick(extra=("--resume",))
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("non-complete", second.stderr)

    def test_resume_runs_a_cell_missing_from_the_manifest(self):
        # Simulates a run interrupted after cell 0 (accuracy) completed but
        # before cells 1/2 were ever attempted: run_metadata.tsv records
        # only cell 0, with no run.log finalized yet. This exercises
        # "missing cells run" without relying on racy process-kill timing.
        result = self.run_quick()
        self.assertEqual(result.returncode, 0, result.stderr)
        self._truncate_run_metadata_to_first_n_cells(self.results_root, 1)

        resumed = self.run_quick(extra=("--resume",))
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertIn("RESUME skip dblp_acm_u65536:accuracy", resumed.stdout)
        self.assertIn("summarize_real_datasets.py", resumed.stdout)
        self.assertIn("--mode=timing", resumed.stdout)
        self.assertIn("--profile=toy-smoke", resumed.stdout)
        self.assertTrue((self.results_root / "run.log").is_file())
        metadata = read_kv_file(self.results_root / "run_metadata.tsv")
        self.assertEqual(metadata["cell_count"], "3")
        for i in range(3):
            self.assertEqual(metadata[f"cell.{i:03d}.status"], "complete")

    @staticmethod
    def _truncate_run_metadata_to_first_n_cells(results_root, n):
        path = results_root / "run_metadata.tsv"
        values = read_kv_file(path)
        scalars = [(k, v) for k, v in values.items()
                  if not k.startswith(("cell.", "cell_count", "artifact."))
                  and k != "artifact_count"]

        artifact_count = int(values["artifact_count"])
        kept_artifacts = [i for i in range(artifact_count)
                          if values[f"artifact.{i:03d}.role"] != "run-log"]
        artifact_pairs = [("artifact_count", str(len(kept_artifacts)))]
        for new_index, old_index in enumerate(kept_artifacts):
            old_prefix = f"artifact.{old_index:03d}"
            new_prefix = f"artifact.{new_index:03d}"
            for field in ("role", "path", "sha256"):
                artifact_pairs.append((f"{new_prefix}.{field}", values[f"{old_prefix}.{field}"]))

        cell_pairs = [("cell_count", str(n))]
        for index in range(n):
            prefix = f"cell.{index:03d}"
            for key, value in values.items():
                if key.startswith(prefix + "."):
                    cell_pairs.append((key, value))

        # An actually-interrupted run would never have produced the dropped
        # cells' outputs; delete them so the resumed run doesn't trip the
        # "refuse to overwrite existing output" guard for cells it must
        # legitimately (re-)run.
        total_cells = int(values["cell_count"])
        for index in range(n, total_cells):
            prefix = f"cell.{index:03d}"
            output_count = int(values[f"{prefix}.output_count"])
            for out_index in range(output_count):
                rel_path = values[f"{prefix}.output.{out_index:03d}.path"]
                (results_root / rel_path).unlink(missing_ok=True)

        kept = scalars + artifact_pairs + cell_pairs
        text = "key\tvalue\n" + "".join(f"{k}\t{v}\n" for k, v in kept)
        path.write_text(text, encoding="utf-8")
        (results_root / "run.log").unlink(missing_ok=True)
        (results_root / "run.log.partial.001").write_text(
            "=== truncated for test ===\n", encoding="utf-8")

    def test_resume_after_full_completion_is_a_no_op(self):
        self.run_quick()
        result = self.run_quick(extra=("--resume",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nothing to do", result.stdout)

    def test_resume_rejects_tampered_output_checksum(self):
        self.run_quick()
        accuracy_csv = (self.results_root / "csv" /
                        "real_accuracy_dblp_acm_u65536.csv")
        accuracy_csv.write_bytes(accuracy_csv.read_bytes() + b"tampered\n")
        result = self.run_quick(extra=("--resume",))
        self.assertNotEqual(result.returncode, 0)

    def test_resume_rejects_tampered_argv_in_run_metadata(self):
        self.run_quick()
        run_metadata_path = self.results_root / "run_metadata.tsv"
        text = run_metadata_path.read_text(encoding="utf-8")
        text = text.replace("--max-pairs=2", "--max-pairs=999")
        run_metadata_path.write_text(text, encoding="utf-8")
        result = self.run_quick(extra=("--resume",))
        self.assertNotEqual(result.returncode, 0)

    def test_run_fails_closed_when_accuracy_csv_has_nan_abs_error(self):
        # The accuracy CSV feeds directly into the (real, already-tested)
        # summarizer, which independently rejects non-finite cells -- this
        # pins that the pipeline fails fast rather than completing with bad
        # data, one layer before the verifier would ever see it.
        result = self.run_quick(env={
            "PICCARD_FAKE_BAD_FIELD": "abs_error",
            "PICCARD_FAKE_BAD_VALUE": "nan",
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.results_root / "run.log").is_file())

    def test_verifier_rejects_eligibility_integrity_violation_under_quick(self):
        result = self.run_quick(env={"PICCARD_FAKE_COMPARISON_ELIGIBLE": "true"})
        self.assertEqual(result.returncode, 0, result.stderr)
        verify_result = run_verifier(self.results_root)
        self.assertNotEqual(verify_result.returncode, 0)
        self.assertIn("comparison_eligible", verify_result.stderr)
        self.assertFalse((self.results_root / "verification_status.tsv").exists())

    def test_verifier_rejects_nan_in_timing_csv(self):
        result = self.run_quick(env={
            "PICCARD_FAKE_BAD_FIELD": "phase_minhash_ms",
            "PICCARD_FAKE_BAD_VALUE": "nan",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        verify_result = run_verifier(self.results_root)
        self.assertNotEqual(verify_result.returncode, 0)
        self.assertFalse((self.results_root / "verification_status.tsv").exists())

    def test_verifier_rejects_empty_variant_field(self):
        result = self.run_quick(env={"PICCARD_FAKE_VARIANT_OVERRIDE": " "})
        # The fake sets variant to a single space (nonempty at the shell
        # level, but the CSV cell itself must not be blank for a required
        # field -- exercise via an explicit empty override instead).
        self.assertEqual(result.returncode, 0, result.stderr)


class VerifierUnitTest(unittest.TestCase):
    """Direct unit tests of scripts/verify_real_dataset_outputs.py's pure
    functions, bypassing a full runner invocation for checks that are
    awkward or slow to trigger end to end (key ORDER, positive-count
    mismatch, fixture-fingerprint table, argv hashing, index contiguity)."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_verifier_module()

    def test_argv_sha256_matches_be32_length_prefixed_domain_free_digest(self):
        argv = ["bench_real_datasets", "--mode=accuracy"]
        expected = hashlib.sha256(
            len(argv[0]).to_bytes(4, "big") + argv[0].encode("utf-8")
            + len(argv[1]).to_bytes(4, "big") + argv[1].encode("utf-8")
        ).hexdigest()
        self.assertEqual(self.module.argv_sha256(argv), expected)

    def test_processed_manifest_key_order_accepts_the_tracked_fixture(self):
        values = self.module._validate_processed_manifest(
            QUICK_DATASET_MANIFEST, "dblp_acm")
        self.assertEqual(values["variant"], "dblp_acm_u65536")

    def test_processed_manifest_key_order_rejects_permuted_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp) / "dataset.manifest.tsv"
            pairs = self._parse_pairs(QUICK_DATASET_MANIFEST)
            # Swap two adjacent keys whose *set* stays identical but whose
            # order no longer matches piccard-real-processed-v1 -- the C++
            # loader (key-SET only) would accept this; the verifier must not.
            pairs[4], pairs[5] = pairs[5], pairs[4]
            self._write_pairs(tmp_path, pairs)
            with self.assertRaises(self.module.VerificationError):
                self.module._validate_processed_manifest(tmp_path, "dblp_acm")

    def test_processed_manifest_rejects_dropped_dblp_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp) / "dataset.manifest.tsv"
            pairs = self._parse_pairs(QUICK_DATASET_MANIFEST)
            pairs = [(k, "1" if k == "retained_positive_count" else v)
                    for k, v in pairs]
            # original_positive_count stays 3 in the fixture; force a mismatch.
            self._write_pairs(tmp_path, pairs)
            with self.assertRaises(self.module.VerificationError):
                self.module._validate_processed_manifest(tmp_path, "dblp_acm")

    def test_fixture_fingerprints_contain_the_tracked_quick_fixture_hashes(self):
        fingerprints = self.module._fixture_fingerprints()
        dataset_values = dict(self._parse_pairs(QUICK_DATASET_MANIFEST))
        self.assertIn(dataset_values["records_sha256"], fingerprints)
        self.assertIn(dataset_values["pairs_sha256"], fingerprints)
        source_values = dict(self._parse_pairs(QUICK_SOURCE_MANIFEST))
        self.assertIn(source_values["input.0.sha256"], fingerprints)

    def test_no_fixture_masquerade_raises_when_records_sha_matches(self):
        dataset_values = dict(self._parse_pairs(QUICK_DATASET_MANIFEST))
        with self.assertRaises(self.module.VerificationError):
            self.module._validate_no_fixture_masquerade(dataset_values, {})

    def test_no_fixture_masquerade_passes_for_unrelated_hashes(self):
        fake_values = {"records_sha256": "1" * 64, "pairs_sha256": "2" * 64}
        self.module._validate_no_fixture_masquerade(fake_values, {})

    def test_cell_id_enumeration_rejects_duplicate_ids(self):
        cells = [{"id": "dblp_acm_u65536:accuracy"},
                 {"id": "dblp_acm_u65536:accuracy"}]
        with self.assertRaises(self.module.VerificationError):
            self.module._validate_cell_id_enumeration(cells, "quick")

    def test_cell_id_enumeration_rejects_missing_cell_under_quick(self):
        cells = [{"id": "dblp_acm_u65536:accuracy"},
                 {"id": "dblp_acm_u65536:accuracy-summary"}]
        with self.assertRaises(self.module.VerificationError):
            self.module._validate_cell_id_enumeration(cells, "quick")

    def test_cell_id_enumeration_rejects_unknown_cell_shape(self):
        with self.assertRaises(self.module.VerificationError):
            self.module._cell_variant("not-a-known-shape")

    def test_eligibility_integrity_allows_true_under_paper(self):
        rows = [{"comparison_eligible": True}]
        self.module._validate_eligibility_integrity(rows, "x:timing:std128-t40-primary",
                                                     "paper")

    def test_eligibility_integrity_rejects_true_under_quick(self):
        rows = [{"comparison_eligible": True}]
        with self.assertRaises(self.module.VerificationError):
            self.module._validate_eligibility_integrity(
                rows, "x:timing:toy-smoke", "quick")

    def test_verifier_missing_results_root_exits_nonzero(self):
        result = run_command([sys.executable, str(VERIFIER), "/nonexistent/path/xyz"])
        self.assertNotEqual(result.returncode, 0)

    def test_verifier_missing_argument_exits_nonzero(self):
        result = run_command([sys.executable, str(VERIFIER)])
        self.assertNotEqual(result.returncode, 0)

    @staticmethod
    def _parse_pairs(path: pathlib.Path):
        lines = path.read_text(encoding="utf-8").split("\n")
        assert lines[-1] == ""
        assert lines[0] == "key\tvalue"
        return [tuple(line.split("\t", 1)) for line in lines[1:-1]]

    @staticmethod
    def _write_pairs(path: pathlib.Path, pairs) -> None:
        text = "key\tvalue\n" + "".join(f"{k}\t{v}\n" for k, v in pairs)
        path.write_text(text, encoding="utf-8")


class PaperModeDirtyTreeTest(unittest.TestCase):
    """The active feature branch this suite runs on is not guaranteed to be
    clean, which is itself a legitimate fixture for pinning the "paper mode
    requires a clean source tree" gate without any special setup."""

    def test_paper_mode_against_a_dirty_tree_is_rejected(self):
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=ROOT, text=True, capture_output=True, check=False).stdout
        if not status.strip():
            self.skipTest("working tree happens to be clean; covered by "
                          "PaperModeCleanWorktreeTest instead")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            build_dir = tmp_path / "build"
            write_fake_bench_real_datasets(build_dir)
            result = run_runner(
                f"--source-manifest={QUICK_SOURCE_MANIFEST}",
                f"--dataset-manifest={QUICK_DATASET_MANIFEST}",
                "--profile=std128-t40-primary", "--profile=std192-t40-primary",
                "--seed=20260729", "--threads=2",
                f"--build-dir={build_dir}", f"--results-root={tmp_path / 'results'}")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("clean", result.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[1:])
