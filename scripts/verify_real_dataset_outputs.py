#!/usr/bin/env python3
"""Fail-fast, non-circular verifier for `scripts/run_real_datasets.sh` output
(Work 5, master Task 9B).

`verify_real_dataset_outputs.py <results-root>` parses the exact
`run_metadata.tsv` schema the runner writes (`piccard-real-run-v1`),
resolves every recorded input/output path against its role-scoped canonical
root, independently recomputes every argv/manifest/input/output SHA-256 and
every semantic row invariant, and -- only if everything matches -- atomically
writes `verification_status.tsv` containing exactly
`schema_version=piccard-real-verification-v1`,
`run_metadata_sha256=<sha256 of run_metadata.tsv>`, and `status=VERIFIED`.

This module never writes anything on failure and never trusts a stale
`verification_status.tsv`: every invocation re-verifies from scratch. It is
stdlib-only, does no network access, and never mutates anything outside the
results root it is pointed at (source-root/build-dir/committed-source-root
paths recorded in run_metadata.tsv are only ever read).

Two binding checks the runner deliberately leaves to this module (Phase 6
"Highlights"):

  * exact processed-manifest key ORDER (the C++ loader -- src/data/
    real_dataset.cpp -- validates only the key SET);
  * the eligibility-integrity cross-check: `comparison_eligible=true` is
    resolver-derived from the requested profile alone, so a row carrying it
    is only trustworthy evidence under `evidence_mode=paper`. Any such row
    inside a `quick` run is rejected outright, regardless of which cell
    produced it.

It also independently rejects "fixture masquerading": a `paper`-mode run
whose processed content-hashes or raw input checksums match the checked-in
`tests/fixtures/real_datasets/quick/dblp_acm_u65536/` fixture, no matter what
citation/acquisition metadata or filenames were attached to it.
"""

from __future__ import annotations

import csv
import hashlib
import math
import os
import re
import sys
import tempfile
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
from prepare_real_datasets import (  # noqa: E402
    ManifestError,
    parse_two_column_tsv,
    sha256_file,
    validate_source_manifest,
)

REPO_ROOT = _SCRIPT_DIR.parent


class VerificationError(ValueError):
    """Raised for any fail-closed verification defect."""


# ---------------------------------------------------------------------------
# Schema literals / exact CSV headers, pasted independently of the producer
# (benchmarks/real_dataset_csv_schema.cpp / scripts/prepare_real_datasets.py)
# so this validation never tautologically re-derives from the code it checks.
# ---------------------------------------------------------------------------

RUN_SCHEMA_VERSION = "piccard-real-run-v1"
VERIFICATION_SCHEMA_VERSION = "piccard-real-verification-v1"

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
ACCURACY_HEADER_FIELDS = tuple((_PREFIX_HEADER + "," + _ACCURACY_SUFFIX).split(","))
TIMING_HEADER_FIELDS = tuple((_PREFIX_HEADER + "," + _TIMING_SUFFIX).split(","))

SUMMARY_HEADER_FIELDS = (
    "dataset", "variant", "jaccard_bucket", "n", "mae", "sample_sd",
    "median", "p95", "max", "ci95_low", "ci95_high",
)
_BUCKET_ORDER = ("b00_10", "b10_30", "b30_60", "b60_100")

# Fields that must never be an empty cell in either row schema (mirrors
# SerializeRealDatasetPrefix's RequireNonEmpty list plus the mode-specific
# identity columns), independently of the C++ serializer's own checks --
# "model/path omission" (Phase 6 RED list).
_REQUIRED_NONEMPTY_FIELDS = frozenset({
    "profile_id", "run_class", "cryptographic_profile", "comparison_scope",
    "primitive", "protocol_model", "output_semantics", "assurance_scope",
    "security_basis", "cost_scope", "precomputation_mode", "measurement_kind",
    "workload_id", "workload_manifest_sha256", "execution_trace_sha256",
    "estimator_model", "sanitizer_model", "sanitizer_assurance",
    "openfhe_version", "target_semantics", "measurement_status",
    "dataset", "variant", "dataset_manifest_sha256", "records_sha256",
    "pairs_sha256", "pair_id", "pair_kind", "record_a", "record_b",
})
_BOOL_FIELDS = frozenset({
    "security_match", "comparison_eligible", "secure_division_included",
    "omp_dynamic",
})
_INT_FIELDS = frozenset({
    "target_security_bits", "nominal_security_bits", "root_seed",
    "omp_threads", "transcript_stat_bits", "max_queries", "query_stat_bits",
    "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
    "flood_noise_bits", "actual_ring_dim", "plaintext_modulus", "num_limbs",
    "realized_intersection", "realized_union", "timing_trials",
    "accuracy_trials", "label", "k", "m", "accuracy_trial_index",
    "hash_seed", "set_size_a_raw", "set_size_b_raw", "set_size_a_bucketed",
    "set_size_b_bucketed", "trial_index", "ciphertext_bytes",
    "upload_bytes", "download_bytes",
})
_FLOAT_FIELDS = frozenset({
    "log_q_bits", "target_jaccard", "realized_jaccard",
    "exact_jaccard_raw", "exact_jaccard_bucketed", "estimated_jaccard",
    "bucket_match_fraction", "abs_error", "rel_error",
    "phase_minhash_ms", "phase_encode_ms", "phase_encrypt_ms",
    "phase_cloud_multiply_ms", "phase_cloud_rotate_ms",
    "phase_sanitize_ms", "phase_decrypt_ms", "phase_bias_correction_ms",
    "total_query_ms", "result_value",
})

# Exact `piccard-real-processed-v1` dataset.manifest.tsv key ORDER, pasted
# independently of scripts/prepare_real_datasets.py's private
# `_processed_manifest_key_order` -- the C++ loader (src/data/
# real_dataset.cpp) validates only the key SET, so this is the one place the
# exact order contract is re-checked end to end (Phase 6 Highlights (a)).
_PROCESSED_MANIFEST_KEY_PREFIX = (
    "schema_version", "dataset", "variant", "preprocessing_version",
    "universe_size", "seed",
    "source_manifest_file", "source_manifest_sha256",
    "records_file", "records_sha256", "record_count",
    "pairs_file", "pairs_sha256", "pair_count",
    "raw_set_size_min", "raw_set_size_median", "raw_set_size_p95", "raw_set_size_max",
    "bucketed_set_size_min", "bucketed_set_size_median",
    "bucketed_set_size_p95", "bucketed_set_size_max",
    "original_positive_count", "retained_positive_count", "requested_pair_count",
    "max_documents", "min_related_pairs",
)
_PROCESSED_MANIFEST_DROP_KEYS = {
    "dblp_acm": ("dropped.empty_features_dblp", "dropped.empty_features_acm"),
}


def _processed_manifest_key_order(dataset: str) -> tuple:
    if dataset not in _PROCESSED_MANIFEST_DROP_KEYS:
        raise VerificationError(
            f"unknown dataset for processed manifest key order: {dataset!r}")
    return _PROCESSED_MANIFEST_KEY_PREFIX + _PROCESSED_MANIFEST_DROP_KEYS[dataset]


# rev. 4 descope: DBLP-ACM only. Any other variant token is unknown.
QUICK_VARIANT = "dblp_acm_u65536"
PAPER_PROFILES = ("std128-t40-primary", "std192-t40-primary")
QUICK_TIMING_PROFILE = "toy-smoke"

_FIXTURE_ROOT = (
    REPO_ROOT / "tests" / "fixtures" / "real_datasets" / "quick" / QUICK_VARIANT
)
_FIXTURE_SOURCE_MANIFEST = _FIXTURE_ROOT / "source.manifest.tsv"
_FIXTURE_DATASET_MANIFEST = _FIXTURE_ROOT / "dataset.manifest.tsv"

_INDEXED_KEY_RE = re.compile(r"^[a-z_]+\.(\d+)\.")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise VerificationError(message)


# ---------------------------------------------------------------------------
# run_metadata.tsv parsing helpers
# ---------------------------------------------------------------------------

def _load_kv(path: Path) -> dict:
    pairs = parse_two_column_tsv(path)
    values: dict = {}
    for key, value in pairs:
        if key in values:
            fail(f"duplicate manifest key: {key!r}")
        values[key] = value
    return values


def _require(values: dict, key: str) -> str:
    if key not in values:
        fail(f"missing required key: {key!r}")
    return values[key]


def _indexed_count(values: dict, count_key: str) -> int:
    raw = _require(values, count_key)
    if not raw.isdigit():
        fail(f"{count_key} is not a non-negative integer: {raw!r}")
    return int(raw)


def _indexed_prefixes_present(values: dict, family_prefix: str) -> set:
    found = set()
    pattern = re.compile(rf"^{re.escape(family_prefix)}\.(\d+)\.")
    for key in values:
        match = pattern.match(key)
        if match:
            found.add(int(match.group(1)))
    return found


def _check_contiguous_zero_padded(values: dict, family_prefix: str, count: int) -> None:
    # Trailing "(\.|$)" handles both nested families (cell.000.input.000.role)
    # and leaf-valued families with no further suffix (cell.000.argv.000).
    pattern = re.compile(rf"^{re.escape(family_prefix)}\.(\d+)(?:\.|$)")
    seen = set()
    widths = set()
    for key in values:
        match = pattern.match(key)
        if match:
            seen.add(int(match.group(1)))
            widths.add(len(match.group(1)))
    expected = set(range(count))
    if seen != expected:
        fail(f"{family_prefix} indices are not exactly contiguous 0..{count - 1}: "
             f"found {sorted(seen)!r}")
    if count > 0 and widths != {3}:
        fail(f"{family_prefix} indices are not zero-padded to width 3: "
             f"widths found {sorted(widths)!r}")


def argv_sha256(argv) -> str:
    """SHA-256 over BE32(length)||argument-bytes for each argv element in
    order -- no domain separator (normative plan §Phase 6 grammar block)."""
    hasher = hashlib.sha256()
    for argument in argv:
        encoded = argument.encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
    return hasher.hexdigest()


def _resolve_under(root: Path, relative: str, label: str) -> Path:
    if not relative or Path(relative).is_absolute():
        fail(f"{label} must be a non-empty relative path: {relative!r}")
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        fail(f"{label} escapes its declared root: {relative!r}")
    return candidate


# ---------------------------------------------------------------------------
# Roots / artifacts
# ---------------------------------------------------------------------------

def _parse_roots(values: dict, results_root: Path) -> dict:
    root_count = _indexed_count(values, "root_count")
    _check_contiguous_zero_padded(values, "root", root_count)
    roots = {}
    for index in range(root_count):
        prefix = f"root.{index:03d}"
        root_id = _require(values, f"{prefix}.id")
        raw_path = _require(values, f"{prefix}.path")
        if root_id in roots:
            fail(f"duplicate root id: {root_id!r}")
        path = Path(raw_path)
        if not path.is_absolute():
            fail(f"root {root_id!r} path is not absolute: {raw_path!r}")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            fail(f"root {root_id!r} path does not exist: {raw_path!r} ({exc})")
        roots[root_id] = resolved
    if "results-root" not in roots:
        fail("run_metadata.tsv is missing the results-root entry")
    if roots["results-root"] != results_root:
        fail("run_metadata.tsv results-root does not match the directory "
             "the verifier was invoked against")
    return roots


def _parse_artifacts(values: dict, results_root: Path) -> list:
    artifact_count = _indexed_count(values, "artifact_count")
    _check_contiguous_zero_padded(values, "artifact", artifact_count)
    artifacts = []
    for index in range(artifact_count):
        prefix = f"artifact.{index:03d}"
        role = _require(values, f"{prefix}.role")
        rel_path = _require(values, f"{prefix}.path")
        declared_sha = _require(values, f"{prefix}.sha256")
        if not _SHA256_RE.match(declared_sha):
            fail(f"malformed artifact sha256 for {role!r}: {declared_sha!r}")
        resolved = _resolve_under(results_root, rel_path, f"artifact {role!r} path")
        if not resolved.is_file():
            fail(f"artifact {role!r} is missing on disk: {rel_path!r}")
        actual_sha = sha256_file(resolved)
        if actual_sha != declared_sha:
            fail(f"artifact {role!r} checksum mismatch: declared {declared_sha!r}, "
                 f"actual {actual_sha!r}")
        artifacts.append({"role": role, "path": rel_path, "sha256": declared_sha,
                          "resolved": resolved})
    return artifacts


# ---------------------------------------------------------------------------
# Cells
# ---------------------------------------------------------------------------

_ACCURACY_ID_RE = re.compile(r"^([A-Za-z0-9_]+):accuracy$")
_SUMMARY_ID_RE = re.compile(r"^([A-Za-z0-9_]+):accuracy-summary$")
_TIMING_ID_RE = re.compile(r"^([A-Za-z0-9_]+):timing:([A-Za-z0-9-]+)$")


def _parse_cells(values: dict, results_root: Path, roots: dict) -> list:
    cell_count = _indexed_count(values, "cell_count")
    _check_contiguous_zero_padded(values, "cell", cell_count)
    cells = []
    seen_ids = set()
    for index in range(cell_count):
        prefix = f"cell.{index:03d}"
        cell_id = _require(values, f"{prefix}.id")
        if cell_id in seen_ids:
            fail(f"duplicate cell id: {cell_id!r}")
        seen_ids.add(cell_id)

        argv_count = _indexed_count(values, f"{prefix}.argv_count")
        _check_contiguous_zero_padded(values, f"{prefix}.argv", argv_count)
        argv = [_require(values, f"{prefix}.argv.{i:03d}") for i in range(argv_count)]
        declared_argv_sha = _require(values, f"{prefix}.argv_sha256")
        actual_argv_sha = argv_sha256(argv)
        if actual_argv_sha != declared_argv_sha:
            fail(f"cell {cell_id!r} argv_sha256 mismatch: declared "
                 f"{declared_argv_sha!r}, recomputed {actual_argv_sha!r}")

        env_count = _indexed_count(values, f"{prefix}.env_count")
        _check_contiguous_zero_padded(values, f"{prefix}.env", env_count)
        env = []
        for i in range(env_count):
            key = _require(values, f"{prefix}.env.{i:03d}.key")
            value = _require(values, f"{prefix}.env.{i:03d}.value")
            env.append((key, value))
        env_keys = [key for key, _ in env]
        if env_keys != sorted(env_keys):
            fail(f"cell {cell_id!r} environment keys are not sorted ASCII: {env_keys!r}")

        input_count = _indexed_count(values, f"{prefix}.input_count")
        _check_contiguous_zero_padded(values, f"{prefix}.input", input_count)
        inputs = []
        for i in range(input_count):
            ip = f"{prefix}.input.{i:03d}"
            role = _require(values, f"{ip}.role")
            root_id = _require(values, f"{ip}.root_id")
            rel_path = _require(values, f"{ip}.path")
            declared_sha = _require(values, f"{ip}.sha256")
            if root_id not in roots:
                fail(f"cell {cell_id!r} input {role!r} references unknown root "
                     f"{root_id!r}")
            resolved = _resolve_under(roots[root_id], rel_path,
                                      f"cell {cell_id!r} input {role!r}")
            if not resolved.is_file():
                fail(f"cell {cell_id!r} input {role!r} is missing on disk: "
                     f"{resolved}")
            actual_sha = sha256_file(resolved)
            if actual_sha != declared_sha:
                fail(f"cell {cell_id!r} input {role!r} checksum mismatch: "
                     f"declared {declared_sha!r}, actual {actual_sha!r}")
            inputs.append({"role": role, "root_id": root_id, "path": rel_path,
                           "sha256": declared_sha, "resolved": resolved})

        output_count = _indexed_count(values, f"{prefix}.output_count")
        _check_contiguous_zero_padded(values, f"{prefix}.output", output_count)
        outputs = []
        for i in range(output_count):
            op = f"{prefix}.output.{i:03d}"
            rel_path = _require(values, f"{op}.path")
            declared_sha = _require(values, f"{op}.sha256")
            resolved = _resolve_under(results_root, rel_path,
                                      f"cell {cell_id!r} output")
            if not resolved.is_file():
                fail(f"cell {cell_id!r} output is missing on disk: {resolved}")
            actual_sha = sha256_file(resolved)
            if actual_sha != declared_sha:
                fail(f"cell {cell_id!r} output checksum mismatch: declared "
                     f"{declared_sha!r}, actual {actual_sha!r}")
            outputs.append({"path": rel_path, "sha256": declared_sha,
                            "resolved": resolved})

        status = _require(values, f"{prefix}.status")
        if status != "complete":
            fail(f"cell {cell_id!r} is not complete (status={status!r}); an "
                 "interrupted run cannot be verified")

        cells.append({
            "id": cell_id, "argv": argv, "env": env, "inputs": inputs,
            "outputs": outputs, "status": status,
        })
    return cells


def _cell_variant(cell_id: str) -> str:
    for pattern in (_ACCURACY_ID_RE, _SUMMARY_ID_RE, _TIMING_ID_RE):
        match = pattern.match(cell_id)
        if match:
            return match.group(1)
    fail(f"cell id does not match any known shape: {cell_id!r}")


def _validate_cell_id_enumeration(cells: list, evidence_mode: str) -> None:
    ids = [cell["id"] for cell in cells]
    if len(ids) != len(set(ids)):
        fail("duplicate cell IDs present in run_metadata.tsv")
    by_variant: dict = {}
    for cell_id in ids:
        variant = _cell_variant(cell_id)
        by_variant.setdefault(variant, set()).add(cell_id)

    if evidence_mode == "quick":
        expected_variants = {QUICK_VARIANT}
        expected_by_variant = {
            QUICK_VARIANT: {
                f"{QUICK_VARIANT}:accuracy",
                f"{QUICK_VARIANT}:accuracy-summary",
                f"{QUICK_VARIANT}:timing:{QUICK_TIMING_PROFILE}",
            }
        }
    else:
        expected_variants = set(by_variant)
        expected_by_variant = {}
        for variant in by_variant:
            if variant != QUICK_VARIANT:
                fail(f"unknown variant for paper-mode evidence (rev. 4 "
                     f"descope: DBLP-ACM only): {variant!r}")
            expected_by_variant[variant] = {
                f"{variant}:accuracy",
                f"{variant}:accuracy-summary",
                *(f"{variant}:timing:{profile}" for profile in PAPER_PROFILES),
            }

    if set(by_variant) != expected_variants:
        fail(f"unexpected variant set for evidence_mode={evidence_mode!r}: "
             f"found {sorted(by_variant)!r}")
    for variant, expected_ids in expected_by_variant.items():
        actual_ids = by_variant[variant]
        if actual_ids != expected_ids:
            fail(f"variant {variant!r} cell-ID set mismatch: expected "
                 f"{sorted(expected_ids)!r}, got {sorted(actual_ids)!r}")


# ---------------------------------------------------------------------------
# Row-level semantic checks
# ---------------------------------------------------------------------------

def _parse_cell_value(field: str, raw: str, row_number: int, cell_id: str):
    if field in _BOOL_FIELDS:
        if raw not in ("true", "false"):
            fail(f"cell {cell_id!r} row {row_number}: field {field!r} must be "
                 f"'true'/'false', got {raw!r}")
        return raw == "true"
    if field in _REQUIRED_NONEMPTY_FIELDS and raw == "":
        fail(f"cell {cell_id!r} row {row_number}: required field {field!r} is empty")
    if raw == "":
        return None
    if field in _INT_FIELDS:
        try:
            return int(raw)
        except ValueError:
            fail(f"cell {cell_id!r} row {row_number}: field {field!r} is not an "
                 f"integer: {raw!r}")
    if field in _FLOAT_FIELDS:
        try:
            value = float(raw)
        except ValueError:
            fail(f"cell {cell_id!r} row {row_number}: field {field!r} is not a "
                 f"float: {raw!r}")
        if not math.isfinite(value):
            fail(f"cell {cell_id!r} row {row_number}: field {field!r} must be "
                 f"finite, got {raw!r}")
        return value
    return raw


def _read_rows(csv_path: Path, header_fields: tuple, cell_id: str) -> list:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            fail(f"cell {cell_id!r} CSV is empty: missing header row")
        if header != list(header_fields):
            fail(f"cell {cell_id!r} CSV header does not match the expected schema")
        rows = []
        for row_number, raw_row in enumerate(reader, start=2):
            if len(raw_row) != len(header_fields):
                fail(f"cell {cell_id!r} row {row_number}: expected "
                     f"{len(header_fields)} columns, got {len(raw_row)}")
            parsed = {}
            for field, raw in zip(header_fields, raw_row):
                parsed[field] = _parse_cell_value(field, raw, row_number, cell_id)
            rows.append(parsed)
        return rows


def _output_path_for(cell: dict, suffix: str) -> Path:
    for output in cell["outputs"]:
        if output["path"].endswith(suffix):
            return output["resolved"]
    fail(f"cell {cell['id']!r} has no output ending in {suffix!r}")


def _validate_eligibility_integrity(rows: list, cell_id: str, evidence_mode: str) -> None:
    if evidence_mode == "paper":
        return
    for row in rows:
        if row.get("comparison_eligible") is True:
            fail(f"cell {cell_id!r}: comparison_eligible=true row found under "
                 f"evidence_mode={evidence_mode!r}; only evidence_mode=paper "
                 "may carry comparison-eligible rows")


def _validate_processed_manifest(manifest_path: Path, dataset: str) -> dict:
    pairs = parse_two_column_tsv(manifest_path)
    actual_order = tuple(key for key, _ in pairs)
    expected_order = _processed_manifest_key_order(dataset)
    if actual_order != expected_order:
        fail(f"processed manifest {manifest_path} key order does not match "
             f"the exact piccard-real-processed-v1 order for dataset "
             f"{dataset!r}: expected {expected_order!r}, got {actual_order!r}")
    values = dict(pairs)
    original = values.get("original_positive_count")
    retained = values.get("retained_positive_count")
    if original != retained:
        fail(f"processed manifest {manifest_path}: original_positive_count "
             f"({original!r}) != retained_positive_count ({retained!r})")
    return values


def _fixture_fingerprints() -> set:
    """Checked-in fixture fingerprint table: every raw `input.*.sha256` from
    the tracked quick source manifest plus the tracked quick processed
    manifest's records_sha256/pairs_sha256 (Phase 6 Highlights)."""
    fingerprints = set()
    source_pairs = parse_two_column_tsv(_FIXTURE_SOURCE_MANIFEST)
    for key, value in source_pairs:
        if key.endswith(".sha256"):
            fingerprints.add(value)
    dataset_values = dict(parse_two_column_tsv(_FIXTURE_DATASET_MANIFEST))
    for key in ("records_sha256", "pairs_sha256"):
        if key in dataset_values:
            fingerprints.add(dataset_values[key])
    return fingerprints


def _validate_no_fixture_masquerade(processed_values: dict, source_manifest_values: dict) -> None:
    fingerprints = _fixture_fingerprints()
    for key in ("records_sha256", "pairs_sha256"):
        if processed_values.get(key) in fingerprints:
            fail("fixture masquerading detected: processed manifest "
                 f"{key}={processed_values.get(key)!r} matches the checked-in "
                 "quick fixture, but evidence_mode=paper")
    for key, value in source_manifest_values.items():
        if key.endswith(".sha256") and value in fingerprints:
            fail("fixture masquerading detected: source manifest "
                 f"{key}={value!r} matches the checked-in quick fixture, "
                 "but evidence_mode=paper")


# ---------------------------------------------------------------------------
# Top-level verify()
# ---------------------------------------------------------------------------

def verify(results_root: Path) -> str:
    """Runs the full verification pipeline against `results_root` and
    returns the finalized `verification_status.tsv` bytes (also written
    atomically as a side effect). Raises VerificationError on any failure,
    writing nothing."""
    results_root = Path(results_root).resolve(strict=True)
    if not results_root.is_dir():
        fail(f"--results-root is not a directory: {results_root}")

    run_metadata_path = results_root / "run_metadata.tsv"
    if not run_metadata_path.is_file():
        fail(f"run_metadata.tsv is missing under {results_root}")
    values = _load_kv(run_metadata_path)

    schema_version = _require(values, "schema_version")
    if schema_version != RUN_SCHEMA_VERSION:
        fail(f"unexpected run_metadata.tsv schema_version: {schema_version!r}")

    evidence_mode = _require(values, "evidence_mode")
    if evidence_mode not in ("paper", "quick"):
        fail(f"unexpected evidence_mode: {evidence_mode!r}")

    source_commit = _require(values, "source_commit")
    if not _COMMIT_RE.match(source_commit):
        fail(f"source_commit is not a full lowercase 40-hex commit: {source_commit!r}")
    git_dirty = _require(values, "git_dirty")
    if git_dirty not in ("true", "false"):
        fail(f"git_dirty must be 'true'/'false': {git_dirty!r}")
    if evidence_mode == "paper" and git_dirty != "false":
        fail("evidence_mode=paper requires a clean source tree (git_dirty=false)")
    build_type = _require(values, "build_type")
    if evidence_mode == "paper" and build_type != "Release":
        fail(f"evidence_mode=paper requires build_type=Release, got {build_type!r}")

    roots = _parse_roots(values, results_root)
    artifacts = _parse_artifacts(values, results_root)
    cells = _parse_cells(values, results_root, roots)

    if not cells:
        fail("run_metadata.tsv declares zero cells")
    _validate_cell_id_enumeration(cells, evidence_mode)

    run_log_present = any(a["path"] == "run.log" for a in artifacts)
    if not run_log_present:
        fail("run.log artifact is missing; an unfinalized run cannot be verified")

    by_id = {cell["id"]: cell for cell in cells}
    processed_manifest_cache: dict = {}
    source_values_by_variant: dict = {}

    for artifact in artifacts:
        if artifact["role"].startswith("copied-source-manifest-"):
            variant = artifact["role"][len("copied-source-manifest-"):]
            source_values_by_variant[variant] = dict(
                parse_two_column_tsv(artifact["resolved"]))

    for cell in cells:
        variant = _cell_variant(cell["id"])
        processed_input = next(
            (i for i in cell["inputs"] if i["role"] == "processed-manifest"), None)
        if processed_input is not None and variant not in processed_manifest_cache:
            processed_manifest_cache[variant] = _validate_processed_manifest(
                processed_input["resolved"], "dblp_acm")

        if cell["id"].endswith(":accuracy"):
            csv_path = _output_path_for(cell, f"real_accuracy_{variant}.csv")
            rows = _read_rows(csv_path, ACCURACY_HEADER_FIELDS, cell["id"])
            _validate_eligibility_integrity(rows, cell["id"], evidence_mode)
        elif ":timing:" in cell["id"]:
            profile = cell["id"].split(":timing:", 1)[1]
            csv_path = _output_path_for(cell, f"real_timing_{variant}_{profile}.csv")
            rows = _read_rows(csv_path, TIMING_HEADER_FIELDS, cell["id"])
            _validate_eligibility_integrity(rows, cell["id"], evidence_mode)
        elif cell["id"].endswith(":accuracy-summary"):
            csv_path = _output_path_for(cell, f"real_accuracy_summary_{variant}.csv")
            with csv_path.open(newline="", encoding="utf-8") as handle:
                reader = csv.reader(handle)
                header = next(reader)
                if header != list(SUMMARY_HEADER_FIELDS):
                    fail(f"cell {cell['id']!r} summary CSV header mismatch")
        else:
            fail(f"unrecognized cell id shape: {cell['id']!r}")

    if evidence_mode == "paper":
        for variant, processed_values in processed_manifest_cache.items():
            if variant not in source_values_by_variant:
                fail(f"no copied source manifest artifact found for variant "
                     f"{variant!r}")
            source_values = source_values_by_variant[variant]
            source_root_id = f"source-root-{variant}"
            if source_root_id not in roots:
                fail(f"no {source_root_id!r} root recorded for variant {variant!r}")
            original_source_path = roots[source_root_id] / "source.manifest.tsv"
            if not original_source_path.is_file():
                fail(f"original source manifest is missing for re-validation: "
                     f"{original_source_path}")
            copied_bytes_sha = sha256_file(
                (results_root / "input_manifests" / variant / "source.manifest.tsv"))
            original_sha = sha256_file(original_source_path)
            if copied_bytes_sha != original_sha:
                fail(f"copied source manifest for variant {variant!r} does not "
                     "byte-match the original at its source-root")
            try:
                validate_source_manifest(original_source_path, "dblp_acm")
            except ManifestError as exc:
                fail(f"source manifest re-validation failed for variant "
                     f"{variant!r}: {exc}")
            _validate_no_fixture_masquerade(processed_values, source_values)

    run_metadata_sha256 = sha256_file(run_metadata_path)
    status_pairs = [
        ("schema_version", VERIFICATION_SCHEMA_VERSION),
        ("run_metadata_sha256", run_metadata_sha256),
        ("status", "VERIFIED"),
    ]
    status_bytes = ("key\tvalue\n" + "".join(f"{k}\t{v}\n" for k, v in status_pairs)
                    ).encode("utf-8")
    status_path = results_root / "verification_status.tsv"
    fd, tmp_name = tempfile.mkstemp(prefix=".verification_status.tsv.tmp-",
                                    dir=str(results_root))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(status_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, status_path)
    except BaseException:
        try:
            os.remove(tmp_name)
        except OSError:
            pass
        raise
    return status_bytes.decode("utf-8")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.stderr.write("usage: verify_real_dataset_outputs.py <results-root>\n")
        return 2
    try:
        verify(Path(argv[0]))
    except (VerificationError, OSError) as exc:
        sys.stderr.write(f"verify_real_dataset_outputs: FAIL: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
