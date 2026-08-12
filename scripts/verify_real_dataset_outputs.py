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
import struct
import sys
import tempfile
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
from prepare_real_datasets import (  # noqa: E402
    ManifestError,
    format_float,
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
_ENCODING_HEADER = (
    "profile_id,run_class,target_security_bits,comparison_eligible,"
    "comparison_scope,primitive,protocol_model,cost_scope,"
    "secure_division_included,measurement_kind,dataset,variant,"
    "dataset_manifest_sha256,records_sha256,pairs_sha256,pair_id,pair_kind,"
    "label,record_a,record_b,k,m,method,timing_trials,timing_pair,root_seed,"
    "hash_seed,encoder_warmup_calls,timed_encoder_calls,"
    "correctness_encoder_calls,signature_derivation_timed,phase_encode_ms,"
    "encoded_slots,correctness_status,measurement_status"
)
ACCURACY_HEADER_FIELDS = tuple((_PREFIX_HEADER + "," + _ACCURACY_SUFFIX).split(","))
TIMING_HEADER_FIELDS = tuple((_PREFIX_HEADER + "," + _TIMING_SUFFIX).split(","))
ENCODING_HEADER_FIELDS = tuple(_ENCODING_HEADER.split(","))

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
    "enron": ("dropped.charset_or_mime", "dropped.empty_body", "dropped.short_body",
              "dropped.duplicate_copy", "dropped.duplicate_message_id"),
}


def _processed_manifest_key_order(dataset: str) -> tuple:
    if dataset not in _PROCESSED_MANIFEST_DROP_KEYS:
        raise VerificationError(
            f"unknown dataset for processed manifest key order: {dataset!r}")
    pair_proxy = ("pair_proxy",) if dataset == "enron" else ()
    return (_PROCESSED_MANIFEST_KEY_PREFIX + pair_proxy +
            _PROCESSED_MANIFEST_DROP_KEYS[dataset])


# Quick evidence remains the single tracked DBLP-ACM fixture. Paper evidence
# admits the frozen DBLP-ACM and two Enron variants below.
QUICK_VARIANT = "dblp_acm_u65536"
PAPER_VARIANTS = {"dblp_acm_u65536", "enron_u65536", "enron_u1048576"}
PAPER_PROFILES = ("std128-t40-primary", "std192-t40-primary")
QUICK_TIMING_PROFILE = "toy-smoke"
SINGLE_TRIAL_PROFILES = (
    "work5-std128-t40-single-trial",
    "work5-std192-t40-single-trial",
)
SINGLE_TRIAL_SEED = 20260729
SINGLE_TRIAL_VARIANT = "dblp_acm_u65536"
SINGLE_TRIAL_SOURCE_MANIFEST = (
    REPO_ROOT / "datasets" / "manifests" / "dblp_acm.source.tsv"
).resolve()
_LEGACY_PROCESSED_DIR = (
    REPO_ROOT / "datasets" / "data" / "processed" / "dblp_acm_u65536"
).resolve()
_SINGLE_TRIAL_SOURCE_HASHES = {
    "input.0.sha256": "32863e8b4e7e18e5254c3e0e05cbc282af2e1e6e9d58e124605ebcbaa178ae7f",
    "input.1.sha256": "32055f1dfa619a4fdca33e7de729c66686a2fb3c71589921a6a3bd3af389120e",
    "input.2.sha256": "d9d7c9feaba3d19a2e73ba8bd6ae08407d8b16082881f6e55abc2d703682d53a",
}

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

def _parse_roots(values: dict, results_root: Path, evidence_mode: str) -> dict:
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
    # Codex stop-gate bypass fix: a root ID's PATH is bound to its class
    # RELATIVE to the run's declared committed-source-root, not merely
    # trusted from run_metadata.tsv -- otherwise a tampered metadata file
    # could relocate e.g. a processed-dataset root to any directory holding
    # byte-identical files and every downstream checksum would still
    # "verify" against the wrong provenance origin. (Binding is relative to
    # the declared repo root, not this verifier's own location, so the
    # hermetic scratch-repo test pattern remains valid; a whole-repo
    # relocation is content-equal provenance and stays acceptable.)
    committed = roots.get("committed-source-root")
    if committed is not None:
        # Content anchor (Codex stop-gate rounds 2-3): committed-source-root
        # is itself declared by the mutable metadata, so before it is used
        # as an anchor its pipeline scripts must be BYTE-IDENTICAL to the
        # ones shipped next to this verifier -- a planted directory with
        # renamed/edited scripts fails; '/' fails. THREAT-MODEL BOUNDARY
        # (recorded in .omo evidence): a full content-equal replica of the
        # repo remains indistinguishable by construction; provenance is
        # content-based, and content-equal relocation is the accepted
        # residual. Adversarial defense beyond that rests on the fixture
        # fingerprints and the external approval records, not on
        # run_metadata self-description.
        for required in ("run_real_datasets.sh", "prepare_real_datasets.py",
                         "summarize_real_datasets.py"):
            candidate = committed / "scripts" / required
            anchor = _SCRIPT_DIR / required
            if not candidate.is_file():
                fail("committed-source-root does not look like the pipeline "
                     f"source tree (missing scripts/{required}): "
                     f"{str(committed)!r}")
            if sha256_file(candidate) != sha256_file(anchor):
                fail(f"committed-source-root scripts/{required} does not "
                     "byte-match the verifier's own pipeline script; "
                     "the declared source root is not this pipeline")
    fixture_tree = None if committed is None else committed / "tests" / "fixtures"
    for root_id, resolved in roots.items():
        variant = None
        for prefix_name in ("source-root-", "processed-dataset-"):
            if root_id.startswith(prefix_name):
                variant = root_id[len(prefix_name):]
        if variant is None:
            continue
        if committed is None:
            fail(f"root {root_id!r} requires a committed-source-root entry "
                 "to bind its location class")
        if evidence_mode == "quick":
            expected_quick = (committed / "tests" / "fixtures" /
                              "real_datasets" / "quick" / variant)
            if resolved != expected_quick:
                fail(f"root {root_id!r} must be the tracked quick fixture "
                     f"directory {str(expected_quick)!r} under evidence_mode="
                     f"quick, not {str(resolved)!r}")
            # Content anchor (Codex stop-gate round 4): a partially forged
            # tree (genuine script copies + a fake fixture at the right
            # relative path) must not pass. The quick fixture's files are
            # bound byte-for-byte to the checked-in fixture shipped next
            # to this verifier; the only accepted "forgery" is a full
            # content-equal replica, per the recorded threat-model
            # boundary.
            anchor_dir = (_SCRIPT_DIR.parent / "tests" / "fixtures" /
                          "real_datasets" / "quick" / variant)
            for fixture_file in ("source.manifest.tsv", "dataset.manifest.tsv",
                                 "records.tsv", "pairs.tsv"):
                candidate = resolved / fixture_file
                anchor = anchor_dir / fixture_file
                if not anchor.is_file():
                    fail(f"verifier's own tracked fixture is missing "
                         f"{fixture_file} for variant {variant!r}")
                if not candidate.is_file() or (sha256_file(candidate)
                                               != sha256_file(anchor)):
                    fail(f"quick fixture {fixture_file} under root "
                         f"{root_id!r} does not byte-match the checked-in "
                         "fixture next to this verifier")
        else:
            if resolved == fixture_tree or fixture_tree in resolved.parents:
                fail(f"root {root_id!r} resolves inside the checked-in fixture "
                     f"tree ({str(resolved)!r}) under evidence_mode=paper")
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
_ENCODING_ID_RE = re.compile(
    r"^([A-Za-z0-9_]+):encoding:([A-Za-z0-9-]+):(piccard_encode|piccard_sqrt_encode)$")


def _expected_input_root_id(role: str, cell_id: str) -> str:
    """Role-scoped root-id allowlist for cell inputs (Phase 6: "no role may
    borrow another role's allowlist"). A tampered run_metadata.tsv could
    otherwise repoint an input's root_id at some other role's root and
    still pass a pure checksum comparison, as long as identical bytes
    happen to live at both locations (e.g. the committed source root
    legitimately contains a byte-identical copy of a tracked fixture)."""
    variant = _cell_variant(cell_id)
    if role == "processed-manifest":
        return f"processed-dataset-{variant}"
    if role == "accuracy-csv":
        return "results-root"
    fail(f"cell {cell_id!r} has an unrecognized input role: {role!r}")


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
            expected_root_id = _expected_input_root_id(role, cell_id)
            if root_id != expected_root_id:
                fail(f"cell {cell_id!r} input {role!r} declares root_id "
                     f"{root_id!r}, but that role may only use "
                     f"{expected_root_id!r} (no role may borrow another "
                     "role's allowlist)")
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
    for pattern in (_ACCURACY_ID_RE, _SUMMARY_ID_RE, _TIMING_ID_RE, _ENCODING_ID_RE):
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
    elif evidence_mode == "single-trial-validation":
        expected_variants = {SINGLE_TRIAL_VARIANT}
        expected_by_variant = {
            SINGLE_TRIAL_VARIANT: {
                f"{SINGLE_TRIAL_VARIANT}:accuracy",
                f"{SINGLE_TRIAL_VARIANT}:accuracy-summary",
                f"{SINGLE_TRIAL_VARIANT}:timing:work5-std128-t40-single-trial",
                f"{SINGLE_TRIAL_VARIANT}:encoding:work5-std192-t40-single-trial:piccard_encode",
                f"{SINGLE_TRIAL_VARIANT}:encoding:work5-std192-t40-single-trial:piccard_sqrt_encode",
            }
        }
    else:
        expected_variants = set(by_variant)
        expected_by_variant = {}
        for variant in by_variant:
            if variant not in PAPER_VARIANTS:
                fail(f"unknown variant for paper-mode evidence: {variant!r}")
            timing_profiles = (PAPER_PROFILES if variant == QUICK_VARIANT else
                               ("std128-t40-primary",))
            expected_by_variant[variant] = {
                f"{variant}:accuracy",
                f"{variant}:accuracy-summary",
                *(f"{variant}:timing:{profile}" for profile in timing_profiles),
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


_ACCURACY_WORKLOAD_KEY_ORDER = (
    "schema_version", "dataset_manifest_sha256", "rows_sha256", "k", "m",
    "root_seed", "max_pairs", "accuracy_trials", "hash_randomness",
    "pair_selection")
_TIMING_WORKLOAD_KEY_PREFIX = (
    "schema_version", "dataset_manifest_sha256", "pair_id", "k", "m",
    "profile_id", "root_seed", "hash_seed", "trials", "input_pair_count")
_ENCODING_WORKLOAD_KEY_ORDER = (
    "schema_version", "dataset_manifest_sha256", "pair_id", "k", "m",
    "profile_id", "method", "root_seed", "hash_seed", "trials",
    "timing_pair", "encoder_warmup_calls", "timed_encoder_calls",
    "correctness_encoder_calls", "signature_derivation_timed", "encoded_slots")
_ACCURACY_ROWS_HEADER = "pair_id\ttrial_index\thash_seed\trecord_a\trecord_b"


def _argv_value(cell: dict, flag: str) -> str:
    prefix = f"--{flag}="
    for argument in cell["argv"]:
        if argument.startswith(prefix):
            return argument[len(prefix):]
    fail(f"cell {cell['id']!r} argv is missing the {prefix!r} option")


def _cell_processed_sha(cell: dict) -> str:
    for entry in cell["inputs"]:
        if entry["role"] == "processed-manifest":
            return entry["sha256"]
    fail(f"cell {cell['id']!r} has no processed-manifest input")


def _cell_processed_dir(cell: dict) -> Path:
    for entry in cell["inputs"]:
        if entry["role"] == "processed-manifest":
            return entry["resolved"].parent
    fail(f"cell {cell['id']!r} has no processed-manifest input")


_RECORDS_HEADER = (
    "record_id\traw_feature_count\traw_features_csv\t"
    "bucketed_feature_count\tbucketed_features_csv")
_PAIRS_HEADER = "pair_id\trecord_a\trecord_b\tpair_kind\tlabel"


def _strict_nonnegative_int(raw: str, label: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", raw):
        fail(f"{label} must be a canonical non-negative decimal integer")
    return int(raw)


def _strict_feature_vector(raw: str, declared_count: int, label: str) -> tuple:
    if declared_count == 0:
        if raw != "":
            fail(f"{label} must be empty when its declared count is zero")
        return ()
    if raw == "":
        fail(f"{label} is empty despite a nonzero declared count")
    values = tuple(_strict_nonnegative_int(value, f"{label} item")
                   for value in raw.split(","))
    if len(values) != declared_count:
        fail(f"{label} count does not match its declared count")
    if any(left >= right for left, right in zip(values, values[1:])):
        fail(f"{label} is not strictly increasing and unique")
    return values


def _load_bound_processed_dataset(processed_dir: Path, processed_values: dict) -> dict:
    """Strictly load the records/pairs bytes bound by dataset.manifest.tsv.

    Metadata and CSV hashes alone cannot attest to the ground truth they
    describe: a malicious producer can consistently rehash them.  This loader
    therefore validates both committed processed files before any row truth is
    recomputed from their raw/bucketed feature vectors.
    """
    dataset = processed_values.get("dataset")
    if dataset not in {"dblp_acm", "enron"}:
        fail(f"unsupported processed dataset: {dataset!r}")
    records_path = _resolve_under(processed_dir, processed_values["records_file"],
                                  "processed records_file")
    pairs_path = _resolve_under(processed_dir, processed_values["pairs_file"],
                                "processed pairs_file")
    if not records_path.is_file() or not pairs_path.is_file():
        fail("processed records.tsv or pairs.tsv is missing")
    if sha256_file(records_path) != processed_values["records_sha256"]:
        fail("processed records.tsv checksum does not match dataset.manifest.tsv")
    if sha256_file(pairs_path) != processed_values["pairs_sha256"]:
        fail("processed pairs.tsv checksum does not match dataset.manifest.tsv")
    try:
        record_lines = records_path.read_text(encoding="utf-8", errors="strict").split("\n")
        pair_lines = pairs_path.read_text(encoding="utf-8", errors="strict").split("\n")
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"processed records/pairs are not strict UTF-8: {exc}")
    if not record_lines or record_lines[-1] != "" or record_lines[0] != _RECORDS_HEADER:
        fail("processed records.tsv header or termination mismatch")
    if not pair_lines or pair_lines[-1] != "" or pair_lines[0] != _PAIRS_HEADER:
        fail("processed pairs.tsv header or termination mismatch")

    records = {}
    for line_number, line in enumerate(record_lines[1:-1], start=2):
        fields = line.split("\t")
        if len(fields) != 5 or not fields[0]:
            fail(f"processed records.tsv line {line_number} has malformed fields")
        record_id, raw_count, raw_csv, bucketed_count, bucketed_csv = fields
        if record_id in records:
            fail(f"processed records.tsv duplicates record_id {record_id!r}")
        raw_size = _strict_nonnegative_int(raw_count, "processed raw_feature_count")
        bucketed_size = _strict_nonnegative_int(bucketed_count,
                                                "processed bucketed_feature_count")
        records[record_id] = {
            "raw": _strict_feature_vector(raw_csv, raw_size,
                                          "processed raw_features_csv"),
            "bucketed": _strict_feature_vector(bucketed_csv, bucketed_size,
                                                "processed bucketed_features_csv"),
        }
        universe = int(processed_values["universe_size"])
        if any(value >= universe for value in records[record_id]["bucketed"]):
            fail(f"processed records.tsv record {record_id!r} has a bucketed "
                 "feature outside universe_size")
    if len(records) != _strict_nonnegative_int(processed_values["record_count"],
                                                "processed record_count"):
        fail("processed records.tsv count does not match dataset.manifest.tsv")

    pairs = []
    pair_ids = set()
    positive_count = 0
    for line_number, line in enumerate(pair_lines[1:-1], start=2):
        fields = line.split("\t")
        if len(fields) != 5 or not all(fields[:4]):
            fail(f"processed pairs.tsv line {line_number} has malformed fields")
        pair_id, record_a, record_b, pair_kind, label_raw = fields
        if pair_id in pair_ids:
            fail(f"processed pairs.tsv duplicates pair_id {pair_id!r}")
        pair_ids.add(pair_id)
        if record_a not in records or record_b not in records:
            fail(f"processed pairs.tsv pair {pair_id!r} references an unknown record")
        if record_a == record_b:
            fail(f"processed pairs.tsv pair {pair_id!r} has identical endpoints")
        if dataset == "enron":
            if label_raw != "-1":
                fail(f"processed pairs.tsv pair {pair_id!r} Enron label must be -1")
            expected_label = {"thread_related": -1, "cross_thread": -1}.get(pair_kind)
        else:
            if label_raw not in ("0", "1"):
                fail(f"processed pairs.tsv pair {pair_id!r} label is not binary")
            expected_label = {"known_match": 1, "sampled_nonmatch": 0}.get(pair_kind)
        label = int(label_raw)
        if expected_label is None or label != expected_label:
            fail(f"processed pairs.tsv pair {pair_id!r} pair_kind/label mismatch")
        if label > 0:
            positive_count += label
        pairs.append({"pair_id": pair_id, "record_a": record_a,
                      "record_b": record_b, "pair_kind": pair_kind,
                      "label": label})
    if len(pairs) != _strict_nonnegative_int(processed_values["pair_count"],
                                              "processed pair_count"):
        fail("processed pairs.tsv count does not match dataset.manifest.tsv")
    expected_positive_count = (0 if dataset == "enron" else
                                _strict_nonnegative_int(
                                    processed_values["retained_positive_count"],
                                    "processed retained_positive_count"))
    if positive_count != expected_positive_count:
        fail("processed pairs.tsv positive count does not match dataset.manifest.tsv")
    return {"records": records, "pairs": pairs}


def _truth_overlap(left: tuple, right: tuple) -> tuple:
    """Return (intersection, union) for canonical sorted-unique vectors."""
    i = j = intersection = union = 0
    while i < len(left) and j < len(right):
        if left[i] == right[j]:
            intersection += 1
            union += 1
            i += 1
            j += 1
        elif left[i] < right[j]:
            union += 1
            i += 1
        else:
            union += 1
            j += 1
    union += len(left) - i + len(right) - j
    return intersection, union


def _truth_jaccard(left: tuple, right: tuple) -> tuple:
    intersection, union = _truth_overlap(left, right)
    return intersection, union, (0.0 if union == 0 else intersection / union)


def _numeric_truth_equal(observed, expected: float, field: str, cell_id: str,
                         row_number: int) -> None:
    if observed is None or not isinstance(observed, float) or not math.isclose(
            observed, expected, rel_tol=1e-12, abs_tol=1e-15):
        rendered = format_float(expected)
        fail(f"cell {cell_id!r} row {row_number}: {field} truth mismatch "
             f"(expected canonical value {rendered!r})")


def _validate_accuracy_truth(cell: dict, csv_rows: list,
                             processed_dataset: dict) -> None:
    """Recompute every accuracy truth/value coupling from bound records/pairs."""
    cell_id = cell["id"]
    pairs = {pair["pair_id"]: pair for pair in processed_dataset["pairs"]}
    records = processed_dataset["records"]
    for offset, row in enumerate(csv_rows, start=2):
        pair_id = str(row.get("pair_id"))
        pair = pairs.get(pair_id)
        if pair is None:
            fail(f"cell {cell_id!r} row {offset}: pair_id {pair_id!r} is absent from pairs.tsv")
        for field in ("pair_kind", "record_a", "record_b"):
            if str(row.get(field)) != pair[field]:
                fail(f"cell {cell_id!r} row {offset}: {field} truth mismatch")
        if row.get("label") != pair["label"]:
            fail(f"cell {cell_id!r} row {offset}: label truth mismatch")
        record_a, record_b = records[pair["record_a"]], records[pair["record_b"]]
        raw_intersection, raw_union, raw_jaccard = _truth_jaccard(
            record_a["raw"], record_b["raw"])
        bucketed_intersection, bucketed_union, bucketed_jaccard = _truth_jaccard(
            record_a["bucketed"], record_b["bucketed"])
        del raw_intersection, raw_union  # CSV does not expose raw overlap counts.
        expected_ints = {
            "set_size_a_raw": len(record_a["raw"]),
            "set_size_b_raw": len(record_b["raw"]),
            "set_size_a_bucketed": len(record_a["bucketed"]),
            "set_size_b_bucketed": len(record_b["bucketed"]),
            "realized_intersection": bucketed_intersection,
            "realized_union": bucketed_union,
        }
        for field, expected in expected_ints.items():
            if row.get(field) != expected:
                fail(f"cell {cell_id!r} row {offset}: {field} truth mismatch")
        for field, expected in (("realized_jaccard", bucketed_jaccard),
                                ("exact_jaccard_raw", raw_jaccard),
                                ("exact_jaccard_bucketed", bucketed_jaccard)):
            _numeric_truth_equal(row.get(field), expected, field, cell_id, offset)

        k, m = row.get("k"), row.get("m")
        if not isinstance(k, int) or k <= 0 or not isinstance(m, int) or m < 2:
            fail(f"cell {cell_id!r} row {offset}: k/m estimator parameters are invalid")
        fraction = row.get("bucket_match_fraction")
        if not isinstance(fraction, float):
            fail(f"cell {cell_id!r} row {offset}: bucket_match_fraction truth mismatch")
        candidate_matches = round(fraction * k)
        if candidate_matches < 0 or candidate_matches > k or not math.isclose(
                fraction * k, candidate_matches, rel_tol=0.0, abs_tol=1e-12):
            fail(f"cell {cell_id!r} row {offset}: bucket_match_fraction truth mismatch")
        expected_fraction = candidate_matches / k
        _numeric_truth_equal(fraction, expected_fraction, "bucket_match_fraction", cell_id, offset)
        collision = 1.0 / m
        expected_estimated = max(0.0, min(1.0, (fraction - collision) / (1.0 - collision)))
        _numeric_truth_equal(row.get("estimated_jaccard"), expected_estimated,
                             "estimated_jaccard", cell_id, offset)
        expected_abs_error = abs(expected_estimated - bucketed_jaccard)
        _numeric_truth_equal(row.get("abs_error"), expected_abs_error,
                             "abs_error", cell_id, offset)
        rel_error = row.get("rel_error")
        if bucketed_jaccard == 0.0:
            if rel_error is not None:
                fail(f"cell {cell_id!r} row {offset}: rel_error truth mismatch")
        else:
            _numeric_truth_equal(rel_error, expected_abs_error / bucketed_jaccard,
                                 "rel_error", cell_id, offset)
        expected_bucket = ("b00_10" if bucketed_jaccard < 0.1 else
                           "b10_30" if bucketed_jaccard < 0.3 else
                           "b30_60" if bucketed_jaccard < 0.6 else "b60_100")
        if str(row.get("jaccard_bucket")) != expected_bucket:
            fail(f"cell {cell_id!r} row {offset}: jaccard_bucket truth mismatch")


def _read_processed_pairs(processed_dir: Path, processed_values: dict) -> list:
    """Returns [(pair_id, record_a, record_b)] in file (manifest) order."""
    pairs_path = processed_dir / processed_values["pairs_file"]
    lines = pairs_path.read_text(encoding="utf-8").split("\n")
    out = []
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        out.append((fields[0], fields[1], fields[2]))
    return out


def _median_pair_id(processed_dir: Path, processed_values: dict) -> str:
    """Recomputes the timing pair selection: the pair minimizing distance
    from the median combined bucketed set size (mean-of-two-centers median),
    tie-broken by lexical pair_id."""
    records_path = processed_dir / processed_values["records_file"]
    sizes = {}
    for line in records_path.read_text(encoding="utf-8").split("\n")[1:]:
        if not line:
            continue
        fields = line.split("\t")
        sizes[fields[0]] = int(fields[3])
    combined = []
    for pair_id, record_a, record_b in _read_processed_pairs(processed_dir,
                                                             processed_values):
        if record_a not in sizes or record_b not in sizes:
            fail(f"pair {pair_id!r} references a record missing from "
                 "records.tsv")
        combined.append((pair_id, sizes[record_a] + sizes[record_b]))
    values = sorted(c for _, c in combined)
    n = len(values)
    if n == 0:
        fail("processed dataset has zero pairs; timing pair selection is "
             "undefined")
    if n % 2 == 1:
        median = float(values[n // 2])
    else:
        median = (values[n // 2 - 1] + values[n // 2]) / 2.0
    return min(combined, key=lambda e: (abs(e[1] - median), e[0]))[0]


def _derive_accuracy_hash_seed(root_seed: int, pair_id: str, trial_index: int) -> int:
    pair_bytes = pair_id.encode("utf-8")
    payload = (b"piccard-real-crs-v1\x00" + struct.pack(">Q", root_seed)
               + struct.pack(">I", len(pair_bytes)) + pair_bytes
               + struct.pack(">Q", trial_index))
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _derive_timing_hash_seed(root_seed: int, dataset_sha_raw: bytes, k: int,
                             m: int, profile_id: str) -> int:
    profile_bytes = profile_id.encode("utf-8")
    payload = (b"piccard-real-timing-crs-v1\x00" + struct.pack(">Q", root_seed)
               + dataset_sha_raw + struct.pack(">I", k) + struct.pack(">I", m)
               + struct.pack(">I", len(profile_bytes)) + profile_bytes)
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _derive_encoding_hash_seed(root_seed: int, dataset_sha_raw: bytes, k: int,
                               m: int, profile_id: str, method: str) -> int:
    profile_bytes = profile_id.encode("utf-8")
    method_bytes = method.encode("utf-8")
    payload = (b"piccard-real-encoding-crs-v1\x00" + struct.pack(">Q", root_seed)
               + dataset_sha_raw + struct.pack(">I", k) + struct.pack(">I", m)
               + struct.pack(">I", len(profile_bytes)) + profile_bytes
               + struct.pack(">I", len(method_bytes)) + method_bytes)
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _validate_accuracy_workload(cell: dict, variant: str, csv_rows: list,
                                processed_values: dict,
                                processed_dataset: dict) -> None:
    """Codex stop-gate round 5: the workload manifest/rows are OUTPUTS whose
    file hashes were already bound, but their CONTENT is a semantic
    invariant — schema literal, argv bindings, rows binding, seed
    derivations, and row-count coupling to the accuracy CSV must all
    recompute, or a header-only/fabricated artifact set could be
    certified."""
    cell_id = cell["id"]
    manifest_path = _output_path_for(cell, f"accuracy_{variant}.manifest.tsv")
    rows_path = _output_path_for(cell, f"accuracy_{variant}.rows.tsv")
    pairs = parse_two_column_tsv(manifest_path)
    if tuple(key for key, _ in pairs) != _ACCURACY_WORKLOAD_KEY_ORDER:
        fail(f"cell {cell_id!r} accuracy workload manifest key order/set "
             "does not match piccard-real-accuracy-workload-v1")
    wl = dict(pairs)
    if wl["schema_version"] != "piccard-real-accuracy-workload-v1":
        fail(f"cell {cell_id!r} accuracy workload schema_version mismatch: "
             f"{wl['schema_version']!r}")
    if wl["pair_selection"] != "manifest-order-prefix":
        fail(f"cell {cell_id!r} accuracy workload pair_selection mismatch")
    for key, flag in (("k", "k"), ("m", "m"), ("root_seed", "seed"),
                      ("max_pairs", "max-pairs"),
                      ("accuracy_trials", "accuracy_trials"),
                      ("hash_randomness", "hash_randomness")):
        if wl[key] != _argv_value(cell, flag):
            fail(f"cell {cell_id!r} accuracy workload {key!r} does not match "
                 f"the cell argv --{flag}")
    if wl["dataset_manifest_sha256"] != _cell_processed_sha(cell):
        fail(f"cell {cell_id!r} accuracy workload dataset_manifest_sha256 does "
             "not match the processed-manifest input")
    if wl["rows_sha256"] != sha256_file(rows_path):
        fail(f"cell {cell_id!r} accuracy workload rows_sha256 does not match "
             "the rows file")

    lines = rows_path.read_text(encoding="utf-8").split("\n")
    if not lines or lines[0] != _ACCURACY_ROWS_HEADER or lines[-1] != "":
        fail(f"cell {cell_id!r} accuracy workload rows header/termination "
             "mismatch")
    root_seed = int(wl["root_seed"])
    trials_n = int(wl["accuracy_trials"])
    expected_pairs = min(int(processed_values["pair_count"]),
                         int(wl["max_pairs"]))
    # Codex stop-gate round 6: bind to the EXACT manifest-order-prefix
    # pair list, not just counts/membership -- duplicated (pair, trial)
    # rows hiding an omitted pair must fail.
    all_pairs = processed_dataset["pairs"]
    selected_pairs = all_pairs[:expected_pairs]
    records_by_pair = {
        pair["pair_id"]: (pair["record_a"], pair["record_b"])
        for pair in selected_pairs
    }
    expected_entries = sorted(
        (pair["pair_id"], trial) for pair in selected_pairs
        for trial in range(trials_n))
    entries = []
    for line in lines[1:-1]:
        fields = line.split("\t")
        if len(fields) != 5:
            fail(f"cell {cell_id!r} accuracy workload rows line has "
                 f"{len(fields)} fields, expected 5")
        pair_id, trial_raw, seed_raw, record_a, record_b = fields
        trial_index = int(trial_raw)
        derived = _derive_accuracy_hash_seed(root_seed, pair_id, trial_index)
        if seed_raw != str(derived):
            fail(f"cell {cell_id!r} accuracy workload hash_seed for "
                 f"({pair_id!r}, trial {trial_index}) does not recompute")
        if records_by_pair.get(pair_id) != (record_a, record_b):
            fail(f"cell {cell_id!r} accuracy workload rows carry wrong "
                 f"endpoints for pair {pair_id!r}")
        entries.append((pair_id, trial_index))
    if entries != expected_entries:
        fail(f"cell {cell_id!r} accuracy workload rows do not equal the "
             "exact manifest-order-prefix (pair, trial) list")

    manifest_sha = sha256_file(manifest_path)
    csv_keys = sorted((str(row.get("pair_id")),
                       int(row.get("accuracy_trial_index")))
                      for row in csv_rows)
    if csv_keys != expected_entries:
        fail(f"cell {cell_id!r} accuracy CSV rows are not in one-to-one "
             "correspondence with the workload (pair, trial) list")
    for row in csv_rows:
        for column in ("workload_manifest_sha256", "accuracy_workload_sha256"):
            if str(row.get(column)) != manifest_sha:
                fail(f"cell {cell_id!r} accuracy CSV column {column!r} does "
                     "not equal the workload manifest SHA-256")
        pair_id = str(row.get("pair_id"))
        trial_index = int(row.get("accuracy_trial_index"))
        derived = _derive_accuracy_hash_seed(root_seed, pair_id, trial_index)
        if str(row.get("hash_seed")) != str(derived):
            fail(f"cell {cell_id!r} accuracy CSV hash_seed for "
                 f"({pair_id!r}, {trial_index}) does not recompute")
        expected_records = records_by_pair.get(pair_id)
        if expected_records != (str(row.get("record_a")),
                                str(row.get("record_b"))):
            fail(f"cell {cell_id!r} accuracy CSV endpoints for {pair_id!r} do "
                 "not match pairs.tsv")
    _validate_accuracy_truth(cell, csv_rows, processed_dataset)


def _validate_timing_workload(cell: dict, variant: str, profile: str,
                              csv_rows: list) -> None:
    cell_id = cell["id"]
    manifest_path = _output_path_for(
        cell, f"timing_{variant}_{profile}.manifest.tsv")
    pairs = parse_two_column_tsv(manifest_path)
    keys = tuple(key for key, _ in pairs)
    if keys[:len(_TIMING_WORKLOAD_KEY_PREFIX)] != _TIMING_WORKLOAD_KEY_PREFIX:
        fail(f"cell {cell_id!r} timing workload manifest key prefix does not "
             "match piccard-real-timing-workload-v1")
    wl = dict(pairs)
    if wl["schema_version"] != "piccard-real-timing-workload-v1":
        fail(f"cell {cell_id!r} timing workload schema_version mismatch")
    for key, flag in (("k", "k"), ("m", "m"), ("root_seed", "seed"),
                      ("trials", "trials"), ("profile_id", "profile")):
        if wl[key] != _argv_value(cell, flag):
            fail(f"cell {cell_id!r} timing workload {key!r} does not match "
                 f"the cell argv --{flag}")
    processed_sha = _cell_processed_sha(cell)
    if wl["dataset_manifest_sha256"] != processed_sha:
        fail(f"cell {cell_id!r} timing workload dataset_manifest_sha256 does "
             "not match the processed-manifest input")
    root_seed = int(wl["root_seed"])
    k = int(wl["k"])
    m = int(wl["m"])
    derived = _derive_timing_hash_seed(root_seed, bytes.fromhex(processed_sha),
                                       k, m, wl["profile_id"])
    if wl["hash_seed"] != str(derived):
        fail(f"cell {cell_id!r} timing workload hash_seed does not recompute")
    trials_n = int(wl["trials"])
    if int(wl["input_pair_count"]) != trials_n + 1:
        fail(f"cell {cell_id!r} timing workload input_pair_count != trials+1")
    seen_shas = []
    for index in range(trials_n + 1):
        prefix = f"input.{index:03d}"
        role = wl.get(f"{prefix}.role")
        trial_raw = wl.get(f"{prefix}.trial_index")
        a_sha = wl.get(f"{prefix}.a_sha256", "")
        b_sha = wl.get(f"{prefix}.b_sha256", "")
        if index == 0:
            if role != "warmup" or trial_raw != "":
                fail(f"cell {cell_id!r} timing workload input.000 must be the "
                     "warmup with an empty trial_index")
        else:
            if role != "measured" or trial_raw != str(index - 1):
                fail(f"cell {cell_id!r} timing workload {prefix} must be "
                     f"measured trial {index - 1}")
        for sha in (a_sha, b_sha):
            if not _SHA256_RE.match(sha or ""):
                fail(f"cell {cell_id!r} timing workload {prefix} carries a "
                     "malformed input sha256")
            seen_shas.append(sha)
    if len(set(seen_shas)) != len(seen_shas):
        fail(f"cell {cell_id!r} timing workload input hashes are not pairwise "
             "distinct (fresh per-trial encryption is required)")
    if wl.get(f"input.{trials_n + 1:03d}.role") is not None:
        fail(f"cell {cell_id!r} timing workload has more input entries than "
             "input_pair_count")

    # Codex stop-gate round 6: the timing pair is not a free choice -- it
    # must be the median-combined-bucketed-size pair recomputed from the
    # anchored records/pairs files, and every CSV row must carry it.
    processed_manifest_path = next(
        i for i in cell["inputs"] if i["role"] == "processed-manifest")["resolved"]
    processed_manifest_values = dict(parse_two_column_tsv(processed_manifest_path))
    processed_values = _validate_processed_manifest(
        processed_manifest_path, processed_manifest_values["dataset"])
    processed_dir = _cell_processed_dir(cell)
    expected_pair = _median_pair_id(processed_dir, processed_values)
    if wl["pair_id"] != expected_pair:
        fail(f"cell {cell_id!r} timing workload pair_id {wl['pair_id']!r} is "
             f"not the recomputed median pair {expected_pair!r}")
    records_by_pair = {p: (a, b) for p, a, b in
                       _read_processed_pairs(processed_dir, processed_values)}
    expected_records = records_by_pair[expected_pair]

    manifest_sha = sha256_file(manifest_path)
    if len(csv_rows) != trials_n:
        fail(f"cell {cell_id!r} timing CSV data-row count {len(csv_rows)} != "
             f"trials {trials_n}")
    for offset, row in enumerate(csv_rows):
        if int(row.get("trial_index")) != offset:
            fail(f"cell {cell_id!r} timing CSV trial_index sequence mismatch "
                 f"at data row {offset}")
        if str(row.get("hash_seed")) != str(derived):
            fail(f"cell {cell_id!r} timing CSV hash_seed does not recompute")
        if str(row.get("workload_manifest_sha256")) != manifest_sha:
            fail(f"cell {cell_id!r} timing CSV workload_manifest_sha256 does "
                 "not equal the workload manifest SHA-256")
        if str(row.get("pair_id")) != expected_pair:
            fail(f"cell {cell_id!r} timing CSV pair_id does not equal the "
                 "recomputed median pair")
        if (str(row.get("record_a")), str(row.get("record_b"))) != expected_records:
            fail(f"cell {cell_id!r} timing CSV endpoints do not match "
                 "pairs.tsv for the median pair")


def _validate_encoding_workload(cell: dict, variant: str, profile: str,
                                method: str, csv_rows: list) -> None:
    """Validate the local-encoder-only STD192 row without accepting FHE shape.

    The schema is intentionally independent from RealTimingHeader: a context,
    calibration, key, ciphertext, or end-to-end timing field is a hard
    failure, not an optional empty value.
    """
    cell_id = cell["id"]
    forbidden = {
        "phase_minhash_ms", "phase_encrypt_ms", "phase_cloud_multiply_ms",
        "phase_cloud_rotate_ms", "phase_sanitize_ms", "phase_decrypt_ms",
        "phase_bias_correction_ms", "total_query_ms", "ciphertext_bytes",
        "upload_bytes", "download_bytes", "actual_ring_dim", "log_q_bits",
        "plaintext_modulus", "num_limbs", "openfhe_version", "sanitizer_model",
        "sanitizer_assurance", "transcript_stat_bits", "max_queries",
        "query_stat_bits", "coefficient_stat_bits", "flood_margin_bits",
        "eval_noise_bits", "flood_noise_bits",
    }
    if forbidden.intersection(ENCODING_HEADER_FIELDS):
        fail(f"cell {cell_id!r} encoding schema contains a forbidden FHE field")
    manifest_path = _output_path_for(
        cell, f"encoding_{variant}_{profile}_{method}.manifest.tsv")
    pairs = parse_two_column_tsv(manifest_path)
    if tuple(key for key, _ in pairs) != _ENCODING_WORKLOAD_KEY_ORDER:
        fail(f"cell {cell_id!r} encoding workload key order mismatch")
    wl = dict(pairs)
    if wl["schema_version"] != "piccard-real-encoding-workload-v1":
        fail(f"cell {cell_id!r} encoding workload schema mismatch")
    for key, flag in (("k", "k"), ("m", "m"), ("root_seed", "seed"),
                      ("trials", "trials"), ("profile_id", "profile"),
                      ("method", "method"), ("timing_pair", "timing-pair")):
        if wl[key] != _argv_value(cell, flag):
            fail(f"cell {cell_id!r} encoding workload {key!r} does not bind argv")
    if wl["dataset_manifest_sha256"] != _cell_processed_sha(cell):
        fail(f"cell {cell_id!r} encoding workload dataset manifest mismatch")
    if (wl["encoder_warmup_calls"], wl["timed_encoder_calls"],
            wl["correctness_encoder_calls"], wl["signature_derivation_timed"]) != \
            ("1", "1", "1", "false"):
        fail(f"cell {cell_id!r} encoding call-count/timing boundary mismatch")
    if profile != "work5-std192-t40-single-trial" or method not in {
            "piccard_encode", "piccard_sqrt_encode"}:
        fail(f"cell {cell_id!r} encoding method/profile mismatch")
    if (wl["k"], wl["m"], wl["trials"], wl["timing_pair"], wl["root_seed"]) != \
            ("128", "64", "1", "median", str(SINGLE_TRIAL_SEED)):
        fail(f"cell {cell_id!r} encoding frozen parameter mismatch")
    derived = _derive_encoding_hash_seed(
        int(wl["root_seed"]), bytes.fromhex(_cell_processed_sha(cell)),
        int(wl["k"]), int(wl["m"]), profile, method)
    if wl["hash_seed"] != str(derived):
        fail(f"cell {cell_id!r} encoding hash seed does not recompute")

    processed_manifest_path = next(
        i for i in cell["inputs"] if i["role"] == "processed-manifest")["resolved"]
    processed_manifest_values = dict(parse_two_column_tsv(processed_manifest_path))
    processed_values = _validate_processed_manifest(
        processed_manifest_path, processed_manifest_values["dataset"])
    expected_pair = _median_pair_id(_cell_processed_dir(cell), processed_values)
    records = {pair_id: (record_a, record_b) for pair_id, record_a, record_b in
               _read_processed_pairs(_cell_processed_dir(cell), processed_values)}
    if wl["pair_id"] != expected_pair:
        fail(f"cell {cell_id!r} encoding pair is not the recomputed median pair")
    if len(csv_rows) != 1:
        fail(f"cell {cell_id!r} encoding CSV must contain exactly one row")
    row = csv_rows[0]
    expected = {
        "profile_id": profile, "run_class": "smoke", "target_security_bits": "192",
        "comparison_eligible": "false", "comparison_scope": "encoding-only-diagnostic",
        "primitive": "onehot-encoding" if method == "piccard_encode" else "sqrt-encoding",
        "protocol_model": "piccard-local-encoding" if method == "piccard_encode"
        else "piccard-sqrt-local-encoding",
        "cost_scope": "encoding-only", "secure_division_included": "false",
        "measurement_kind": "local-encoder", "dataset": "dblp_acm",
        "variant": variant, "dataset_manifest_sha256": _cell_processed_sha(cell),
        "records_sha256": processed_values["records_sha256"],
        "pairs_sha256": processed_values["pairs_sha256"], "pair_id": expected_pair,
        "method": method, "k": "128", "m": "64", "timing_trials": "1",
        "timing_pair": "median", "root_seed": str(SINGLE_TRIAL_SEED),
        "hash_seed": str(derived), "encoder_warmup_calls": "1",
        "timed_encoder_calls": "1", "correctness_encoder_calls": "1",
        "signature_derivation_timed": "false", "correctness_status": "PASS",
        "measurement_status": "measured",
    }
    for key, value in expected.items():
        if str(row.get(key)) != value:
            fail(f"cell {cell_id!r} encoding CSV {key!r} mismatch")
    if (str(row.get("record_a")), str(row.get("record_b"))) != records[expected_pair]:
        fail(f"cell {cell_id!r} encoding CSV endpoints do not match pairs.tsv")
    if str(row.get("pair_kind")) not in {"known_match", "sampled_nonmatch"} or \
            str(row.get("label")) not in {"0", "1"}:
        fail(f"cell {cell_id!r} encoding CSV pair provenance is invalid")
    try:
        measured = float(str(row.get("phase_encode_ms")))
        slots = int(str(row.get("encoded_slots")))
    except ValueError as error:
        raise VerificationError(f"cell {cell_id!r} encoding numeric field is malformed") from error
    if not math.isfinite(measured) or measured < 0 or slots != (8192 if method == "piccard_encode" else 2048):
        fail(f"cell {cell_id!r} encoding timing/shape field is invalid")
    if wl["encoded_slots"] != str(slots):
        fail(f"cell {cell_id!r} encoding workload output shape mismatch")


def _validate_summary_recomputation(cell: dict, summary_path: Path) -> None:
    """The summary is a pure function of the accuracy CSV; regenerate it
    with the real summarizer and demand byte identity."""
    accuracy_input = next(
        (i for i in cell["inputs"] if i["role"] == "accuracy-csv"), None)
    if accuracy_input is None:
        fail(f"cell {cell['id']!r} has no accuracy-csv input to recompute "
             "the summary from")
    import summarize_real_datasets as _summarizer
    with tempfile.TemporaryDirectory() as tmp:
        regenerated = Path(tmp) / "regenerated.csv"
        try:
            _summarizer.run(accuracy_input["resolved"], regenerated)
        except Exception as exc:  # noqa: BLE001 - any summarizer failure is a verdict
            fail(f"cell {cell['id']!r} summary recomputation failed: {exc}")
        if regenerated.read_bytes() != summary_path.read_bytes():
            fail(f"cell {cell['id']!r} summary CSV does not byte-match the "
                 "recomputation from its accuracy CSV")


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
    if values.get("dataset") != dataset:
        fail(f"processed manifest {manifest_path}: dataset does not match "
             f"the bound dataset {dataset!r}")
    if dataset == "dblp_acm":
        if values.get("variant") != "dblp_acm_u65536":
            fail(f"processed manifest {manifest_path}: unsupported DBLP variant")
        if values.get("preprocessing_version") != "dblp-acm-trigram-v1":
            fail(f"processed manifest {manifest_path}: unsupported DBLP preprocessing profile")
    elif dataset == "enron":
        variant = values.get("variant")
        expected_universe = {"enron_u65536": "65536",
                             "enron_u1048576": "1048576"}.get(variant)
        if expected_universe is None:
            fail(f"processed manifest {manifest_path}: unsupported Enron variant")
        if values.get("universe_size") != expected_universe:
            fail(f"processed manifest {manifest_path}: universe_size does not "
                 "match the Enron variant")
        if values.get("preprocessing_version") != "enron-shingle5-v2":
            fail(f"processed manifest {manifest_path}: unsupported Enron preprocessing profile")
        if values.get("pair_proxy") != "canonical-subject-proxy-not-thread-ground-truth-v1":
            fail(f"processed manifest {manifest_path}: unsupported Enron pair_proxy")
        if values.get("original_positive_count") != "0" or values.get("retained_positive_count") != "0":
            fail(f"processed manifest {manifest_path}: Enron positive_count fields must be zero")
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

def _canonical_status_bytes(run_metadata_sha256: str) -> bytes:
    """The one true serialization of verification_status.tsv for a given
    run_metadata hash — used both to write the status and to byte-compare
    any pre-existing status file."""
    status_pairs = [
        ("schema_version", VERIFICATION_SCHEMA_VERSION),
        ("run_metadata_sha256", run_metadata_sha256),
        ("status", "VERIFIED"),
    ]
    return ("key\tvalue\n" + "".join(f"{k}\t{v}\n" for k, v in status_pairs)
            ).encode("utf-8")


def _check_existing_status_not_stale(results_root: Path, run_metadata_sha256: str) -> None:
    """A pre-existing verification_status.tsv is never silently overwritten.
    If it exists, it must already agree with the current run_metadata.tsv
    (same schema, same hash, status=VERIFIED); a rerun that reproduces
    identical bytes is fine, but anything stale/mismatched fails outright --
    the operator must delete it deliberately before re-verifying."""
    status_path = results_root / "verification_status.tsv"
    if not status_path.is_file():
        return
    # Codex stop-gate bypass fix: comparing three PARSED values let a
    # tampered-but-parseable status (extra keys, reordered lines, cosmetic
    # edits) pass and then be silently rewritten in canonical form,
    # destroying the tamper evidence. The only acceptable pre-existing
    # status is the byte-exact canonical serialization this verifier
    # would write for the current run_metadata.tsv.
    expected_bytes = _canonical_status_bytes(run_metadata_sha256)
    try:
        existing_bytes = status_path.read_bytes()
    except OSError as exc:
        fail(f"existing verification_status.tsv is unreadable: {exc}")
    if existing_bytes != expected_bytes:
        fail("existing verification_status.tsv is stale or non-canonical (its "
             "bytes do not equal the canonical status for the current "
             "run_metadata.tsv); delete it before re-verifying")


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
    run_metadata_sha256 = sha256_file(run_metadata_path)
    _check_existing_status_not_stale(results_root, run_metadata_sha256)
    values = _load_kv(run_metadata_path)

    schema_version = _require(values, "schema_version")
    if schema_version != RUN_SCHEMA_VERSION:
        fail(f"unexpected run_metadata.tsv schema_version: {schema_version!r}")

    evidence_mode = _require(values, "evidence_mode")
    if evidence_mode not in ("paper", "quick", "single-trial-validation"):
        fail(f"unexpected evidence_mode: {evidence_mode!r}")

    source_commit = _require(values, "source_commit")
    if not _COMMIT_RE.match(source_commit):
        fail(f"source_commit is not a full lowercase 40-hex commit: {source_commit!r}")
    git_dirty = _require(values, "git_dirty")
    if git_dirty not in ("true", "false"):
        fail(f"git_dirty must be 'true'/'false': {git_dirty!r}")
    if evidence_mode in ("paper", "single-trial-validation") and git_dirty != "false":
        fail(f"evidence_mode={evidence_mode} requires a clean source tree (git_dirty=false)")
    build_type = _require(values, "build_type")
    if evidence_mode in ("paper", "single-trial-validation") and build_type != "Release":
        fail(f"evidence_mode={evidence_mode} requires build_type=Release, got {build_type!r}")

    roots = _parse_roots(values, results_root, evidence_mode)
    artifacts = _parse_artifacts(values, results_root)
    cells = _parse_cells(values, results_root, roots)

    if not cells:
        fail("run_metadata.tsv declares zero cells")
    _validate_cell_id_enumeration(cells, evidence_mode)
    # Codex stop-gate round 2: root presence is bound to the cell
    # enumeration in BOTH modes -- deleting a variant's source/processed
    # root entries (and adjusting root_count) must fail, not silently skip
    # the per-variant topology checks above.
    for cell in cells:
        variant = _cell_variant(cell["id"])
        for required_root in (f"source-root-{variant}",
                              f"processed-dataset-{variant}"):
            if required_root not in roots:
                fail(f"run_metadata.tsv is missing the {required_root!r} root "
                     f"entry required by cell {cell['id']!r}")

    run_log_present = any(a["path"] == "run.log" for a in artifacts)
    if not run_log_present:
        fail("run.log artifact is missing; an unfinalized run cannot be verified")

    by_id = {cell["id"]: cell for cell in cells}
    processed_manifest_cache: dict = {}
    processed_dataset_cache: dict = {}
    source_values_by_variant: dict = {}

    for artifact in artifacts:
        if artifact["role"].startswith("copied-source-manifest-"):
            variant = artifact["role"][len("copied-source-manifest-"):]
            source_values_by_variant[variant] = dict(
                parse_two_column_tsv(artifact["resolved"]))

    # Bind each variant's source-of-truth dataset before interpreting any
    # cell.  Cell metadata is deliberately not trusted to arrive in producer
    # order, so an accuracy-summary cell cannot bypass the dataset loader by
    # appearing first.
    for cell in cells:
        variant = _cell_variant(cell["id"])
        processed_input = next(
            (i for i in cell["inputs"] if i["role"] == "processed-manifest"), None)
        if processed_input is not None and variant not in processed_manifest_cache:
            manifest_values = dict(parse_two_column_tsv(processed_input["resolved"]))
            dataset = manifest_values.get("dataset")
            processed_manifest_cache[variant] = _validate_processed_manifest(
                processed_input["resolved"], dataset)
            processed_dataset_cache[variant] = _load_bound_processed_dataset(
                processed_input["resolved"].parent,
                processed_manifest_cache[variant])

    for cell in cells:
        variant = _cell_variant(cell["id"])

        if cell["id"].endswith(":accuracy"):
            csv_path = _output_path_for(cell, f"real_accuracy_{variant}.csv")
            rows = _read_rows(csv_path, ACCURACY_HEADER_FIELDS, cell["id"])
            _validate_eligibility_integrity(rows, cell["id"], evidence_mode)
            _validate_accuracy_workload(cell, variant, rows,
                                        processed_manifest_cache[variant],
                                        processed_dataset_cache[variant])
        elif ":timing:" in cell["id"]:
            profile = cell["id"].split(":timing:", 1)[1]
            csv_path = _output_path_for(cell, f"real_timing_{variant}_{profile}.csv")
            rows = _read_rows(csv_path, TIMING_HEADER_FIELDS, cell["id"])
            _validate_eligibility_integrity(rows, cell["id"], evidence_mode)
            _validate_timing_workload(cell, variant, profile, rows)
        elif ":encoding:" in cell["id"]:
            _variant, _marker, profile, method = cell["id"].split(":", 3)
            csv_path = _output_path_for(
                cell, f"real_encoding_{variant}_{profile}_{method}.csv")
            rows = _read_rows(csv_path, ENCODING_HEADER_FIELDS, cell["id"])
            _validate_eligibility_integrity(rows, cell["id"], evidence_mode)
            _validate_encoding_workload(cell, variant, profile, method, rows)
        elif cell["id"].endswith(":accuracy-summary"):
            csv_path = _output_path_for(cell, f"real_accuracy_summary_{variant}.csv")
            with csv_path.open(newline="", encoding="utf-8") as handle:
                reader = csv.reader(handle)
                header = next(reader)
                if header != list(SUMMARY_HEADER_FIELDS):
                    fail(f"cell {cell['id']!r} summary CSV header mismatch")
            _validate_summary_recomputation(cell, csv_path)
        else:
            fail(f"unrecognized cell id shape: {cell['id']!r}")

    if evidence_mode in ("paper", "single-trial-validation"):
        for variant, processed_values in processed_manifest_cache.items():
            if variant not in source_values_by_variant:
                fail(f"no copied source manifest artifact found for variant "
                     f"{variant!r}")
            source_values = source_values_by_variant[variant]
            source_root_id = f"source-root-{variant}"
            if source_root_id not in roots:
                fail(f"no {source_root_id!r} root recorded for variant {variant!r}")
            source_manifest_root_id = f"source-manifest-{variant}"
            if source_manifest_root_id in roots:
                original_source_path = roots[source_manifest_root_id]
            else:
                original_source_path = roots[source_root_id] / (
                    "dblp_acm.source.tsv" if evidence_mode == "single-trial-validation"
                    else "source.manifest.tsv")
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
                validate_source_manifest(original_source_path,
                                         processed_values["dataset"])
            except ManifestError as exc:
                fail(f"source manifest re-validation failed for variant "
                     f"{variant!r}: {exc}")
            _validate_no_fixture_masquerade(processed_values, source_values)
            if evidence_mode == "single-trial-validation":
                if original_source_path.resolve() != SINGLE_TRIAL_SOURCE_MANIFEST:
                    fail("single-trial-validation source manifest path is not frozen")
                if {key: source_values.get(key) for key in _SINGLE_TRIAL_SOURCE_HASHES} != \
                        _SINGLE_TRIAL_SOURCE_HASHES:
                    fail("single-trial-validation source hashes do not match frozen DBLP-ACM bytes")
                if _LEGACY_PROCESSED_DIR == roots[f"processed-dataset-{variant}"] or \
                        _LEGACY_PROCESSED_DIR in roots[f"processed-dataset-{variant}"].parents:
                    fail("single-trial-validation processed root is the forbidden prior run")
                expected_processed = {
                    "record_count": "4910", "pair_count": "10000",
                    "requested_pair_count": "10000", "seed": str(SINGLE_TRIAL_SEED),
                    "original_positive_count": "2224", "retained_positive_count": "2224",
                }
                if any(processed_values.get(key) != value
                       for key, value in expected_processed.items()):
                    fail("single-trial-validation processed manifest contract mismatch")

    status_bytes = _canonical_status_bytes(run_metadata_sha256)
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
