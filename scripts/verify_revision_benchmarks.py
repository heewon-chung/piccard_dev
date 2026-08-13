#!/usr/bin/env python3
"""Independent, fail-closed verifier for a revision readiness root.

The verifier never trusts a runner-side cell list or summary.  It reloads the
canonical matrix, reconstructs the selected inventory and expected argv, and
then checks receipts, event ordering, source/tool hashes, status taxonomy and
the no-paper/no-Enron-toy boundary.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
from fractions import Fraction
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from revision_benchmark_common import (  # noqa: E402
    CELL_SCHEMA,
    EVENT_SCHEMA,
    PHASES,
    RevisionContractError,
    canonical_plan_argv,
    cell_output,
    expected_paper_ids,
    expected_row_count,
    file_inventory,
    load_matrix,
    phase_for_cell,
    representative_toy_ids,
    select_cells,
    sha256_file,
    source_metadata,
    write_json,
    script_hashes,
    binary_metadata,
    dry_run_source_metadata,
    dry_run_tool_metadata,
    materialize_cell_argv,
    command_for_producer,
    producer_output_dir,
    tool_metadata,
)


VERIFICATION_SCHEMA = "piccard-revision-verification-receipt-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# The versioned encoding workload adds a correctness record after the timing
# records.  Keep its hash domain here rather than borrowing a producer-side
# table: the verifier must independently derive the kind-3 hash seed and must
# reject a correctness record that reuses the timing/accuracy domain.
_CORRECTNESS_HASH_DOMAIN = b"piccard-review-hash-correctness-v1\0"


def _correctness_hash_seed(root_seed: int, index: int) -> int:
    payload = (_CORRECTNESS_HASH_DOMAIN + struct.pack(">Q", root_seed) +
               struct.pack(">I", index))
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def fail(message: str) -> "NoReturn":
    raise RevisionContractError(message)


def load_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is missing or unsafe")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {label}: {exc}")


def require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def _root(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        fail("results root must be an absolute non-symlink directory")
    return path.resolve()


def _safe_relative(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute() \
            or "\\" in value or any(part in {"", ".", ".."}
                                   for part in value.split("/")):
        fail(f"{label} is not a safe relative path")
    candidate = root / value
    try:
        candidate.resolve(strict=False).relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes result root")
    if candidate.is_symlink():
        fail(f"{label} is a symlink")
    return candidate


def _check_matrix(root: Path, manifest: dict[str, Any], mode: str) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    matrix_path = Path(manifest.get("matrix_path", ""))
    if not matrix_path.is_absolute():
        fail("run matrix_path must be absolute")
    document, digest = load_matrix(matrix_path)
    if manifest.get("matrix_sha256") != digest:
        fail("run matrix digest does not match canonical matrix")
    canonical = root / "canonical" / "revision_matrix.json"
    if not canonical.is_file() or sha256_file(canonical) != digest:
        fail("copied canonical matrix is missing or changed")
    cells = select_cells(document, mode)
    ids = [cell["cell_id"] for cell in cells]
    if manifest.get("cell_count") != len(ids) or manifest.get("cell_ids") != ids:
        fail("run cell inventory does not equal independently selected matrix cells")
    if len(ids) != len(set(ids)):
        fail("selected cell inventory contains duplicate IDs")
    return document, digest, cells


def _check_run_manifest(root: Path, mode: str) -> dict[str, Any]:
    manifest = load_json(root / "run.json", "run manifest")
    if not isinstance(manifest, dict) or manifest.get("schema") != "piccard-revision-readiness-run-v1":
        fail("run manifest schema mismatch")
    if manifest.get("mode") != mode or manifest.get("phase_order") != list(PHASES):
        fail("run mode or phase order mismatch")
    if not isinstance(manifest.get("seed"), int) or manifest["seed"] <= 0:
        fail("run seed is invalid")
    if not isinstance(manifest.get("threads"), int) or manifest["threads"] <= 0:
        fail("run threads are invalid")
    if manifest.get("warmup_calls") != 1:
        fail("exactly one discarded warmup call is required")
    if mode == "toy":
        if manifest.get("readiness_status") != "READINESS_ONLY" or \
                manifest.get("performance_status") != "PAPER_PERFORMANCE_PENDING":
            fail("toy run status must remain readiness-only/performance-pending")
    if mode == "dry-run" and manifest.get("spawned_processes") != 0:
        fail("dry-run spawned a producer")
    return manifest


def _check_source_and_tools(manifest: dict[str, Any], root: Path,
                            cells: list[dict[str, Any]], mode: str) -> None:
    source = manifest.get("source")
    expected_source = (dry_run_source_metadata(ROOT) if mode == "dry-run"
                       else source_metadata(ROOT))
    if not isinstance(source, dict) or source != expected_source:
        fail("source commit/dirty metadata changed")
    scripts = manifest.get("scripts")
    if scripts != script_hashes():
        fail("runner/verifier/script hash metadata changed")
    build_dir = Path(manifest.get("build_dir", ""))
    expected_tools = (dry_run_tool_metadata(build_dir) if mode == "dry-run"
                      else tool_metadata(build_dir))
    if manifest.get("tools") != expected_tools:
        fail("compiler/CMake/OpenFHE tool metadata changed")
    expected_binaries = binary_metadata(build_dir, cells)
    if manifest.get("binaries") != expected_binaries:
        fail("producer binary registry/hash metadata changed")
    # Do not require a missing build in dry-run, but reject mutation of any
    # binary that was present when the run was recorded.
    for producer, metadata in manifest.get("binaries", {}).items():
        path = Path(metadata.get("path", ""))
        if metadata.get("sha256") == "MISSING":
            continue
        if not path.is_file() or sha256_file(path) != metadata.get("sha256"):
            fail(f"producer binary changed: {producer}")


def _check_phases(root: Path, manifest: dict[str, Any], *, stage: str = "complete") -> None:
    phase_file = root / "phases.jsonl"
    if not phase_file.is_file():
        fail("phase receipt stream is missing")
    records = []
    for line in phase_file.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if value.get("schema") != "piccard-revision-phase-v1":
            fail("phase record schema mismatch")
        records.append(value)
    expected: list[tuple[str, str]] = []
    for phase in PHASES:
        expected.append((phase, "STARTED"))
        if stage == "verification" and phase == "verification":
            break
        if stage == "sealed" and phase == "seal":
            break
        expected.append((phase, "COMPLETED"))
    observed = [(record.get("phase"), record.get("state")) for record in records]
    if observed != expected:
        fail("phase state machine is not exact and ordered")
    if stage == "complete" and any(
            manifest.get("phase_status", {}).get(phase) != "COMPLETED"
            for phase in PHASES):
        fail("run manifest has incomplete phase state")
    if stage == "sealed" and manifest.get("phase_status", {}).get("seal") != "STARTED":
        fail("sealed run lacks the terminal seal STARTED state")


def _read_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is missing")
    result: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            fail(f"{label} contains a non-object record")
        result.append(value)
    return result


def _check_plans(root: Path, mode: str, cells: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = _read_jsonl(root / "planned_argv.jsonl", "planned argv")
    expected_ids = {cell["cell_id"] for cell in cells}
    if len(records) != len(expected_ids):
        fail("planned argv inventory count mismatch")
    by_id: dict[str, dict[str, Any]] = {}
    cell_by_id = {cell["cell_id"]: cell for cell in cells}
    bindings = manifest.get("input_bindings")
    if not isinstance(bindings, dict):
        fail("run input bindings are missing")
    variants_raw = bindings.get("variant_manifests")
    if not isinstance(variants_raw, dict):
        fail("variant manifest bindings are missing")
    variants = {key: Path(value) for key, value in variants_raw.items()}
    dblp = Path(bindings.get("dblp_manifest", ""))
    build_dir = Path(manifest.get("build_dir", ""))
    if not build_dir.is_absolute():
        fail("bound build directory is invalid")
    for record in records:
        cid = record.get("cell_id")
        if cid in by_id or cid not in expected_ids:
            fail("planned argv has missing, duplicate, or unexpected cell")
        cell = cell_by_id[cid]
        if record.get("schema") != "piccard-revision-planned-cell-v1" or \
                record.get("family") != cell["family"] or \
                record.get("producer") != cell["producer"] or \
                record.get("phase") != phase_for_cell(cell):
            fail(f"planned cell metadata mismatch: {cid}")
        canonical = canonical_plan_argv(cell, mode)
        if record.get("canonical_argv") != canonical:
            fail(f"canonical argv mismatch: {cid}")
        output_dir = cell_output(root, cid)
        materialized = materialize_cell_argv(
            cell, mode, root=root, output=output_dir,
            seed=manifest["seed"], threads=manifest["threads"],
            variant_manifests=variants, dblp_manifest=dblp)
        producer = cell["producer"]
        if producer == "bench_fhe_ind":
            materialized += [f"--output={output_dir / 'fhe_ind.csv'}",
                             f"--revision-identity-out={output_dir / 'identity.csv'}"]
        elif producer == "bench_dynamic":
            materialized += [f"--revision-identity-out={output_dir / 'identity.csv'}"]
        expected_command = command_for_producer(
            producer, root=root, build_dir=build_dir) + materialized
        expected_argv = (expected_command[1:] if expected_command and
                         expected_command[0] == sys.executable else expected_command)
        argv = record.get("argv")
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            fail(f"materialized argv malformed: {cid}")
        command = record.get("command")
        if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
            fail(f"producer command malformed: {cid}")
        expected_record_argv = command[1:] if command and command[0] == sys.executable else command
        if argv != expected_record_argv or argv != expected_argv or command != expected_command:
            fail(f"materialized argv/command mismatch: {cid}")
        joined = "\0".join(argv).lower()
        if mode == "toy" and ("maildir" in joined or "enron_mail" in joined):
            fail("toy argv must not access raw Enron/maildir input")
        if cell["family"] == "piccard_std192_encoding":
            forbidden = ("openfhe", "encrypt", "keygen", "ciphertext", "--security=STD128")
            if any(item.lower() in joined for item in forbidden):
                fail(f"STD192 encoding cell contains forbidden FHE argument: {cid}")
            if "piccard_encode" not in joined or "piccard_sqrt_encode" not in joined:
                fail(f"STD192 encoding cell does not name both encoding arms: {cid}")
        output = _safe_relative(root, Path(record.get("output_dir", "")).relative_to(root).as_posix()
                                if Path(record.get("output_dir", "")).is_absolute()
                                and str(Path(record["output_dir"]).resolve()).startswith(str(root.resolve()))
                                else record.get("output_dir"), "output_dir")
        if output != cell_output(root, cid):
            fail(f"planned output directory mismatch: {cid}")
        by_id[cid] = record
    return by_id


def _check_events(root: Path, mode: str, plans: dict[str, dict[str, Any]]) -> None:
    events = _read_jsonl(root / "events.jsonl", "event stream") if (root / "events.jsonl").exists() else []
    if mode == "dry-run":
        if events:
            fail("dry-run must not contain producer START/END events")
        return
    if [event.get("sequence") for event in events] != list(range(1, len(events) + 1)):
        fail("event sequence is not globally contiguous")
    by_id: dict[str, list[dict[str, Any]]] = {}
    previous_end = 0
    for event in events:
        if event.get("schema") != EVENT_SCHEMA or event.get("event") not in {"START", "END"}:
            fail("event schema or event type mismatch")
        by_id.setdefault(event.get("cell_id"), []).append(event)
    for cid, plan in plans.items():
        if plan["invocation_status"] == "NO_SPAWN":
            continue
        selected = by_id.get(cid, [])
        if len(selected) != 2 or selected[0]["event"] != "START" or selected[1]["event"] != "END":
            fail(f"missing or unordered START/END receipt for {cid}")
        end = selected[1]
        start = selected[0]
        if start.get("argv") != plan.get("command") or end.get("exit_code") != 0:
            fail(f"event argv/exit binding mismatch for {cid}")
        if not isinstance(end.get("start_ns"), int) or not isinstance(end.get("end_ns"), int) or \
                end["start_ns"] > end["end_ns"] or end["start_ns"] < previous_end:
            fail(f"event timestamps are invalid for {cid}")
        previous_end = end["end_ns"]
        for key in ("stdout_sha256", "stderr_sha256"):
            require_sha(end.get(key), f"{cid}.{key}")
        for key in ("stdout_path", "stderr_path"):
            path = _safe_relative(root, end.get(key), f"{cid}.{key}")
            if sha256_file(path) != end[key.replace("_path", "_sha256")]:
                fail(f"{cid} {key} hash binding mismatch")


def _check_receipts(root: Path, mode: str, cells: list[dict[str, Any]], plans: dict[str, dict[str, Any]]) -> None:
    for cell in cells:
        cid = cell["cell_id"]
        receipt_path = cell_output(root, cid) / "receipt.json"
        receipt = load_json(receipt_path, f"receipt {cid}")
        if receipt.get("schema") != CELL_SCHEMA or receipt.get("cell_id") != cid:
            fail(f"receipt schema/identity mismatch: {cid}")
        if receipt.get("canonical_argv") != plans[cid]["canonical_argv"]:
            fail(f"receipt canonical argv mismatch: {cid}")
        expected_status = (
            "NO_SPAWN" if cell["invocation_status"] == "NO_SPAWN" else
            ("PLANNED" if mode == "dry-run" else "COMPLETED"))
        if receipt.get("execution_status") != expected_status:
            fail(f"receipt status mismatch for {cid}")
        if mode != "dry-run" and cell["invocation_status"] == "RUN":
            selected_events = [event for event in _read_jsonl(root / "events.jsonl", "event stream")
                               if event.get("cell_id") == cid]
            if receipt.get("start_event_sequence") != selected_events[0].get("sequence") or \
                    receipt.get("end_event_sequence") != selected_events[1].get("sequence"):
                fail(f"receipt event sequence binding mismatch for {cid}")
        expected_rows = cell["expected_rows"]
        observed_rows = receipt.get("expected_rows")
        if observed_rows != expected_rows:
            fail(f"receipt row taxonomy mismatch for {cid}")
        if mode == "toy":
            for row in expected_rows:
                if row["status"] in {"MEASURED", "DIAGNOSTIC"} and \
                        row["toy_measured_count"] not in {0, 1}:
                    fail(f"toy row count is not one-or-zero for {cid}")
        stdout = receipt.get("stdout", {})
        stderr = receipt.get("stderr", {})
        for item, label in ((stdout, "stdout"), (stderr, "stderr")):
            path = _safe_relative(root, item.get("path"), f"{cid}.{label}")
            digest = require_sha(item.get("sha256"), f"{cid}.{label}.sha256")
            if sha256_file(path) != digest:
                fail(f"{cid}.{label} hash mismatch")
        output = cell_output(root, cid)
        actual_artifacts = file_inventory(
            output, exclude={"stdout.log", "stderr.log", "receipt.json"})
        if actual_artifacts != receipt.get("artifact_inventory", []):
            fail(f"artifact inventory changed or was forged for {cid}")


def _check_family_taxonomy(cells: list[dict[str, Any]]) -> None:
    for cell in cells:
        rows = cell["expected_rows"]
        row_ids = [row["row_id"] for row in rows]
        if len(row_ids) != len(set(row_ids)):
            fail(f"duplicate expected row ID in {cell['cell_id']}")
        if cell["family"] == "piccard_std192_encoding":
            if any(row.get("method") not in {"piccard_encode", "piccard_sqrt_encode"}
                   for row in rows):
                fail("STD192 encoding taxonomy contains a non-encoding method")
        if cell["family"].startswith("threshold_") and cell["dataset"] == "enron":
            fail("threshold evaluator is forbidden for Enron")


_REVIEW_HEADER = (
    "suite,scenario,method,profile_id,run_class,target_security_bits,"
    "cryptographic_profile,nominal_security_bits,security_match,"
    "comparison_eligible,comparison_scope,primitive,protocol_model,"
    "output_semantics,assurance_scope,security_basis,cost_scope,"
    "precomputation_mode,secure_division_included,measurement_kind,"
    "evidence_arm,workload_id,workload_manifest_sha256,"
    "execution_trace_sha256,root_seed,omp_threads,omp_dynamic,k,m,"
    "set_size,universe_size,target_semantics,target_jaccard_numerator,"
    "target_jaccard_denominator,target_jaccard,realized_intersection,"
    "realized_union,realized_jaccard,timing_trials,accuracy_trials,"
    "trials,hash_randomness,hash_seed,estimator_model,sanitizer_model,"
    "sanitizer_assurance,transcript_stat_bits,max_queries,query_stat_bits,"
    "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,"
    "flood_noise_bits,scaling_mod_size,actual_ring_dim,log_q_bits,"
    "plaintext_modulus,num_limbs,openfhe_version,total_ms,total_ms_sd,"
    "total_ms_median,jaccard_computed,jaccard_expected,jaccard_error,"
    "intersection_count,phase_encode_ms,phase_encrypt_ms,"
    "phase_compute_ms,phase_decrypt_ms,ct_size_bytes,comm_bytes,"
    "measurement_status\n"
)
_REVIEW_ENCODING_HEADER = (
    "suite,scenario,method,profile_id,run_class,target_security_bits,"
    "cryptographic_profile,nominal_security_bits,security_match,"
    "comparison_eligible,comparison_scope,primitive,protocol_model,"
    "output_semantics,assurance_scope,security_basis,cost_scope,"
    "precomputation_mode,secure_division_included,measurement_kind,"
    "evidence_arm,workload_id,workload_manifest_sha256,"
    "execution_trace_sha256,root_seed,omp_threads,omp_dynamic,k,m,"
    "set_size,universe_size,target_semantics,target_jaccard_numerator,"
    "target_jaccard_denominator,target_jaccard,realized_intersection,"
    "realized_union,realized_jaccard,timing_trials,accuracy_trials,"
    "correctness_trials,trials,hash_randomness,hash_seed,"
    "encoder_input_construction,encoder_warmup_pairs,"
    "timed_encoder_pairs,correctness_pair_calls,"
    "signature_derivation_timed,encode_a_ms,encode_b_ms,"
    "encode_pair_ms,encoded_slots_a,encoded_slots_b,"
    "correctness_feature_sha256_a,correctness_feature_sha256_b,"
    "correctness_status,measurement_status\n"
)
_SQRT_HEADER = (
    "encoding,k,m,N,Depth,Encode,Encrypt,Evaluate,Decrypt,Total(ms),"
    "|err|,rel_err,security,transcript_stat_bits,max_queries,"
    "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
    "eval_noise_bits,flood_noise_bits,sanitizer_model,"
    "sanitizer_assurance,estimator_model,profile_id,run_class,"
    "target_security_bits,comparison_eligible,measurement_kind,"
    "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
    "openfhe_version\n"
)
_SQRT_TIMING_HEADER = (
    "label,k,m,set_size,ring_dim,time_ms,phase_minhash_ms,phase_encode_ms,"
    "phase_encrypt_ms,phase_multiply_ms,phase_rotate_sum_ms,phase_decrypt_ms,"
    "phase_bias_correction_ms,memory_bytes,ct_size_bytes,jaccard_computed,"
    "jaccard_expected,jaccard_error,jaccard_rel_error,accuracy_median,"
    "accuracy_p25,accuracy_p75,accuracy_p95,accuracy_max,encoding,mult_depth,"
    "num_cts,comm_bytes,phase_intra_digit_rotate_ms,phase_digit_and_ms,"
    "phase_cross_k_sum_ms,trials,time_ms_sd,time_ms_median,phase_minhash_ms_sd,"
    "phase_minhash_ms_median,phase_encode_ms_sd,phase_encode_ms_median,"
    "phase_encrypt_ms_sd,phase_encrypt_ms_median,phase_multiply_ms_sd,"
    "phase_multiply_ms_median,phase_rotate_sum_ms_sd,"
    "phase_rotate_sum_ms_median,phase_decrypt_ms_sd,phase_decrypt_ms_median,"
    "phase_bias_correction_ms_sd,phase_bias_correction_ms_median,"
    "rel_error_eligible_n,hash_randomness,hash_seed,hash_root_seed,"
    "accuracy_trials,phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,scaling_mod_size,"
    "sanitizer_model,sanitizer_assurance,estimator_model,profile_id,run_class,"
    "target_security_bits,comparison_eligible,measurement_kind,actual_ring_dim,"
    "log_q_bits,plaintext_modulus,num_limbs,openfhe_version\n"
)
_CROSSOVER_HEADER = (
    "k,m,onehot_feature_dim,sqrt_feature_dim,onehot_N,sqrt_N,"
    "onehot_total_ms,sqrt_total_ms,sqrt_faster,speedup_ratio,"
    "sanitizer_model,sanitizer_assurance,transcript_stat_bits,"
    "max_queries,query_stat_bits,flood_margin_bits,"
    "onehot_coefficient_stat_bits,onehot_eval_noise_bits,"
    "onehot_flood_noise_bits,sqrt_coefficient_stat_bits,"
    "sqrt_eval_noise_bits,sqrt_flood_noise_bits,estimator_model,"
    "profile_id,run_class,target_security_bits,comparison_eligible,"
    "measurement_kind,openfhe_version,onehot_actual_ring_dim,"
    "onehot_log_q_bits,onehot_plaintext_modulus,onehot_num_limbs,"
    "sqrt_actual_ring_dim,sqrt_log_q_bits,sqrt_plaintext_modulus,"
    "sqrt_num_limbs\n"
)
_THRESHOLD_HEADER = (
    "label,k,m,set_size,ring_dim,tau,mult_depth,"
    "phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,"
    "phase_multiply_ms,phase_rotate_sum_ms,phase_mask_ms,"
    "phase_poly_eval_ms,phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,"
    "threshold_result,threshold_expected,threshold_correct,"
    "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,note,"
    "trials,total_ms_sd,total_ms_median,phase_minhash_ms_sd,"
    "phase_minhash_ms_median,phase_encode_ms_sd,phase_encode_ms_median,"
    "phase_encrypt_ms_sd,phase_encrypt_ms_median,phase_multiply_ms_sd,"
    "phase_multiply_ms_median,phase_rotate_sum_ms_sd,"
    "phase_rotate_sum_ms_median,phase_mask_ms_sd,phase_mask_ms_median,"
    "phase_poly_eval_ms_sd,phase_poly_eval_ms_median,phase_decrypt_ms_sd,"
    "phase_decrypt_ms_median,rel_error_eligible_n,j_tau,match_count,"
    "matchcount_expected,fhe_agrees,outcome,hash_randomness,hash_seed,"
    "hash_root_seed,accuracy_trials,phase_flood_ms,phase_flood_ms_sd,"
    "phase_flood_ms_median,flood_lambda_stat,flood_eval_noise_bits,"
    "flood_margin_bits,flood_noise_bits,scaling_mod_size\n"
)
_THRESHOLD_SPEC_HEADER = (
    "k,tau,degree,ps_baby_s,ps_num_chunks,baby_depth,giant_mults,"
    "natural_mult_depth,mult_depth,scaling_mod_size,ring_dim,plaintext_mod,"
    "log2_q,eval_noise_bits,flood_noise_bits,ct_bytes,poly_build_ms,status,"
    "note,schema_version,requested_ring_dim,natural_ring_dim,"
    "provisioned_ring_dim,realized_ring_dim,natural_depth,provisioned_depth,"
    "log_q_bits,log2_q_over_t_bits,plaintext_modulus,num_limbs,"
    "realized_scaling_mod_size,ordered_rns_moduli,ordered_rns_limb_bits,"
    "ordered_rns_limb_bits_sum,openfhe_version,flooding_assurance,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,required_capacity_bits,residual_capacity_definition,"
    "residual_capacity_bits,residual_capacity_status\n"
)
_THRESHOLD_FPFN_HEADER = (
    "schema_version,profile,security,estimator_model,hash_randomness,"
    "root_seed,k,m,set_size,tau_count,j_tau,grid_index,target_j,"
    "signed_delta,absolute_delta,alpha,realized_intersection,realized_union,"
    "realized_j,trial_index,row_seed,match_count,decision,exact_j_truth,"
    "outcome,predicted_decision_probability,predicted_error_probability,"
    "gaussian_error_approx\n"
)
_DELETION_HEADER = (
    "model,n,d,k,required_survival,r,exact_survival,union_bound_survival,"
    "mc_survival,mc_standard_error,maximum_safe_deletions,"
    "exact_expected_first_failure,exact_expected_safe_deletions,"
    "mc_mean_first_failure,mc_mean_safe_deletions,trials,seed\n"
)
_ESTIMATOR_HEADER = (
    "estimator_model,k,m,set_size,target_jaccard,realized_jaccard,"
    "intersection_size,trials,seed,mean_raw_rank_estimate,raw_rank_bias,"
    "raw_rank_mae,raw_rank_sample_sd,raw_standard_error,"
    "mean_bucket_match_probability,bucket_match_bias,bucket_match_mae,"
    "bucket_match_sample_sd,bucket_standard_error,"
    "mean_bias_corrected_estimate,corrected_bias,corrected_mae,"
    "corrected_sample_sd,corrected_standard_error,raw_bias_limit,"
    "corrected_bias_limit,raw_passed,corrected_passed\n"
)
_FHE_IND_HEADER = (
    "cell_id,circuit,shape_id,security,k,m,universe,set_size,target_jaccard,"
    "realized_intersection,realized_union,realized_jaccard,seed,trials,"
    "requested_ring_dim,natural_ring_dim,realized_ring_dim,natural_depth,"
    "provisioned_depth,scaling_mod_size,num_limbs,plaintext_modulus,"
    "bfv_context_fingerprint,log_q_bits,ordered_rns_moduli,"
    "ordered_rns_moduli_sha256,openfhe_version,sanitizer_profile,"
    "context_tuple_sha256,calibration_origin,workload_id,"
    "workload_manifest_sha256,timing_hash_seed,setup_context_ms,"
    "setup_keygen_ms,phase_encode_ms,phase_encrypt_ms,phase_evaluate_ms,"
    "phase_decrypt_ms,online_e2e_ms,full_e2e_ms,match_count,jaccard_estimate,"
    "status,reason,method,fhe_ind_binary_sha256,capabilities_sha256\n"
)
_REAL_PREFIX = (
    "profile_id,run_class,target_security_bits,cryptographic_profile,"
    "nominal_security_bits,security_match,comparison_eligible,comparison_scope,"
    "primitive,protocol_model,output_semantics,assurance_scope,security_basis,"
    "cost_scope,precomputation_mode,secure_division_included,measurement_kind,"
    "workload_id,workload_manifest_sha256,execution_trace_sha256,root_seed,"
    "omp_threads,estimator_model,sanitizer_model,sanitizer_assurance,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,actual_ring_dim,"
    "log_q_bits,plaintext_modulus,num_limbs,openfhe_version,target_semantics,"
    "target_jaccard,realized_intersection,realized_union,realized_jaccard,"
    "timing_trials,accuracy_trials,omp_dynamic,measurement_status"
)
_REAL_ACCURACY_HEADER = _REAL_PREFIX + ",dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,pair_id,pair_kind,label,record_a,record_b,k,m,hash_randomness,accuracy_trial_index,hash_seed,set_size_a_raw,set_size_b_raw,set_size_a_bucketed,set_size_b_bucketed,exact_jaccard_raw,exact_jaccard_bucketed,estimated_jaccard,bucket_match_fraction,abs_error,rel_error,jaccard_bucket,accuracy_workload_sha256\n"
_REAL_TIMING_HEADER = _REAL_PREFIX + ",dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,pair_id,pair_kind,label,record_a,record_b,k,m,hash_seed,trial_index,phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,phase_cloud_multiply_ms,phase_cloud_rotate_ms,phase_sanitize_ms,phase_decrypt_ms,phase_bias_correction_ms,total_query_ms,result_value,ciphertext_bytes,upload_bytes,download_bytes\n"
_REAL_ENCODING_HEADER = (
    "profile_id,run_class,target_security_bits,comparison_eligible,"
    "comparison_scope,primitive,protocol_model,cost_scope,"
    "secure_division_included,measurement_kind,dataset,variant,"
    "dataset_manifest_sha256,records_sha256,pairs_sha256,pair_id,pair_kind,"
    "label,record_a,record_b,k,m,method,timing_trials,timing_pair,root_seed,"
    "hash_seed,encoder_warmup_pairs,timed_encoder_pairs,"
    "correctness_pair_calls,signature_derivation_timed,encode_a_ms,"
    "encode_b_ms,encode_pair_ms,encoded_slots_a,encoded_slots_b,"
    "correctness_status,measurement_status\n"
)
_REAL_THRESHOLD_HEADER = "schema_version,dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,pair_id,pair_kind,label,record_a,record_b,k,m,hash_randomness,root_seed,split,rank_position,threshold_trial_index,hash_seed,match_count,decision,label_truth,label_outcome,exact_j_truth,exact_j_outcome,exact_jaccard_bucketed,requested_j_threshold,tau_count,realized_j_tau,calibration_fpr,calibration_fnr,calibration_balanced_error,calibration_digest,evaluation_digest,threshold_workload_sha256\n"
_DYNAMIC_HEADER = (
    "label,k,m,set_size,ring_dim,depth,phase_init_ms,phase_insert_ms,"
    "phase_delete_ms,phase_signature_ms,phase_encode_ms,phase_encrypt_ms,"
    "phase_compute_ms,phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,"
    "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
    "ops_insert_per_sec,ops_delete_per_sec,trials,total_ms_sd,total_ms_median,"
    "phase_init_ms_sd,phase_init_ms_median,phase_insert_ms_sd,"
    "phase_insert_ms_median,phase_delete_ms_sd,phase_delete_ms_median,"
    "phase_signature_ms_sd,phase_signature_ms_median,phase_encode_ms_sd,"
    "phase_encode_ms_median,phase_encrypt_ms_sd,phase_encrypt_ms_median,"
    "phase_compute_ms_sd,phase_compute_ms_median,phase_decrypt_ms_sd,"
    "phase_decrypt_ms_median,rel_error_eligible_n,hash_randomness,hash_seed,"
    "hash_root_seed,accuracy_trials,phase_flood_ms,phase_flood_ms_sd,"
    "phase_flood_ms_median,transcript_stat_bits,max_queries,query_stat_bits,"
    "coefficient_stat_bits,flood_margin_bits,eval_noise_bits,flood_noise_bits,"
    "scaling_mod_size,sanitizer_model,sanitizer_assurance,estimator_model,"
    "profile_id,run_class,target_security_bits,comparison_eligible,"
    "measurement_kind,actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
    "openfhe_version,dynamic_scenario,updates_requested,updates_applied,"
    "initial_epoch,final_epoch,owner_b_unchanged,ciphertext_upload_count,"
    "local_inner_product,decrypted_inner_product,correctness_status,"
    "refresh_owner_set_id,refresh_updates,refresh_epoch_before,"
    "refresh_epoch_after,refresh_status,phase_refresh_update_ms,"
    "phase_refresh_signature_ms,phase_refresh_encode_ms,"
    "phase_refresh_encrypt_ms,phase_refresh_serialize_ms,phase_cloud_replace_ms,"
    "refresh_total_ms,refresh_upload_bytes,refresh_ciphertexts_uploaded,"
    "refresh_context_fingerprint,refresh_public_key_fingerprint\n"
)

_EXACT_HEADERS = {
    "review-comparison-csv-v1": _REVIEW_HEADER,
    "review-encoding-csv-v1": _REVIEW_ENCODING_HEADER,
    "sqrt-comparison-csv-v1": _SQRT_HEADER,
    "threshold-csv-v1": _THRESHOLD_HEADER,
    "threshold-fpfn-csv-v1": _THRESHOLD_FPFN_HEADER,
    "deletion-survival-csv-v1": _DELETION_HEADER,
    "estimator-diagnostic-csv-v1": _ESTIMATOR_HEADER,
    "fhe-ind-csv-v1": _FHE_IND_HEADER,
    "piccard-benchmark-csv-v1": _SQRT_TIMING_HEADER,
    "dynamic-benchmark-csv-v1": _DYNAMIC_HEADER,
    "real-threshold-csv-v1": _REAL_THRESHOLD_HEADER,
}


def _csv_table(payload: bytes, header: str, label: str) -> list[dict[str, str]]:
    """Parse one CSV artifact and require its exact, byte-stable header."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{label} is not UTF-8 CSV")
    if not text.startswith(header):
        fail(f"{label} header mismatch")
    reader = csv.reader(io.StringIO(text, newline=""))
    rows_raw = list(reader)
    expected_fields = header.rstrip("\n").split(",")
    if not rows_raw or rows_raw[0] != expected_fields:
        fail(f"{label} header fields mismatch")
    if any(len(row) != len(expected_fields) for row in rows_raw[1:]):
        fail(f"{label} contains a malformed row")
    return [dict(zip(expected_fields, row)) for row in rows_raw[1:]]


def _output_path(root: Path, output: Path, value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    try:
        path.resolve(strict=False).relative_to(output.resolve())
    except ValueError:
        fail(f"{label} escapes its canonical cell output")
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is missing or unsafe")
    return path


def _command_value(command: list[str], prefix: str) -> list[str]:
    return [arg[len(prefix):] for arg in command if arg.startswith(prefix)]


def _canonical_payload(root: Path, output: Path, plan: dict[str, Any],
                      schema: str) -> tuple[bytes, str]:
    """Return the producer's canonical primary artifact, never an arbitrary CSV."""
    command = plan.get("command", [])
    if not isinstance(command, list):
        fail("planned producer command is malformed")
    if schema == "noise-profile-v1":
        roots = _command_value(command, "--results-root=")
        if roots:
            if len(roots) != 1:
                fail("noise producer has duplicate results-root bindings")
            bound = Path(roots[0]).resolve(strict=False)
            payload = producer_output_dir({"family": "flooding"}, output)
            if bound != payload.resolve():
                fail("noise producer results-root is not the canonical payload root")
            # The wrapper creates a nested profiles/<profile>/<key> shard;
            # the family validator resolves that path from its manifests.
            return b"", "payload"
    prefixes = ("--csv=", "--output=")
    for prefix in prefixes:
        values = _command_value(command, prefix)
        if not values:
            continue
        if len(values) != 1:
            fail(f"producer has duplicate {prefix[:-1]} bindings")
        # review-comparison's --output is an abstract planner token; its
        # successor intentionally emits the versioned CSV on stdout.
        if schema in {"review-comparison-csv-v1", "review-encoding-csv-v1"}:
            break
        path = _output_path(root, output, values[0], prefix[:-1])
        return path.read_bytes(), path.relative_to(output).as_posix()
    # These producers are deliberately stdout-only.  An unrelated CSV in the
    # cell directory must never be promoted to evidence by a generic scan.
    return (output / "stdout.log").read_bytes(), "stdout.log"


def _reject_unrelated_csvs(output: Path, receipt: dict[str, Any], allowed: set[str],
                           allowed_prefixes: tuple[str, ...] = ()) -> None:
    for item in receipt.get("artifact_inventory", []):
        path = str(item.get("path", ""))
        if path.endswith(".csv") and path not in allowed and not any(
                path.startswith(prefix) for prefix in allowed_prefixes):
            # Dynamic/FHE identity sidecars are bound separately by their
            # explicit selector and are not the primary family artifact.
            if path != "identity.csv":
                fail(f"unrelated CSV artifact is not admissible: {path}")


def _terminal_records(stderr: bytes, cell_id: str) -> list[dict[str, str]]:
    records = []
    for line in stderr.decode("utf-8", errors="strict").splitlines():
        if not line.startswith("revision_terminal,"):
            continue
        values: dict[str, str] = {}
        for token in line.split(",")[1:]:
            key, separator, value = token.partition("=")
            if not separator or not key or key in values:
                fail(f"malformed revision terminal row for {cell_id}")
            values[key] = value
        if values.get("cell_id") != cell_id:
            fail(f"revision terminal row identity mismatch for {cell_id}")
        records.append(values)
    return records


def _int_field(row: dict[str, str], field: str, cid: str) -> int:
    try:
        value = int(row[field])
    except (KeyError, ValueError):
        fail(f"invalid {field} field for {cid}")
    return value


def _command_int(command: list[str], prefix: str, label: str) -> int | None:
    values = _command_value(command, prefix)
    if not values:
        return None
    if len(values) != 1:
        fail(f"{label} has duplicate {prefix} bindings")
    try:
        return int(values[0])
    except ValueError:
        fail(f"{label} has a non-integer {prefix} binding")


def _command_file(root: Path, command: list[str], prefix: str,
                  label: str) -> Path | None:
    values = _command_value(command, prefix)
    if not values:
        return None
    if len(values) != 1:
        fail(f"{label} has duplicate {prefix} bindings")
    path = Path(values[0])
    if not path.is_absolute():
        path = root / path
    if path.is_symlink() or not path.is_file():
        fail(f"{label} binding is missing or unsafe")
    return path


def _tsv_rows(path: Path, label: str) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        fail(f"{label} is not readable UTF-8 TSV")
    reader = csv.DictReader(io.StringIO(text), delimiter="\t")
    if not reader.fieldnames:
        fail(f"{label} has no TSV header")
    return [dict(row) for row in reader]


def _expected_dataset_name(variant: str) -> str:
    return "dblp_acm" if variant.startswith("dblp_acm_") else "enron"


def _row_value(row: dict[str, str], field: str, cid: str) -> str:
    """Return a required CSV value, rejecting a missing/blank identity field."""
    value = row.get(field)
    if value is None or value == "":
        fail(f"missing {field} identity field for {cid}")
    return value


def _float_value(row: dict[str, str], field: str, cid: str) -> float:
    value = _row_value(row, field, cid)
    try:
        parsed = float(value)
    except ValueError:
        fail(f"invalid {field} field for {cid}")
    if not math.isfinite(parsed):
        fail(f"non-finite {field} field for {cid}")
    return parsed


def _require_value(row: dict[str, str], field: str, expected: Any, cid: str,
                   *, optional: bool = False) -> None:
    """Bind a row field to an independently derived value.

    Canonical identity and security fields are mandatory whenever the exact
    producer schema exposes them.  Tests must construct an actual-shape row;
    a blank value cannot be used to erase an adjacent cell's conflicting
    identity.
    """
    actual = row.get(field)
    if actual is None:
        return
    if actual == "":
        if not optional:
            fail(f"missing {field} identity field for {cid}")
        return
    expected_text = str(expected).lower() if isinstance(expected, bool) else str(expected)
    if actual != expected_text:
        fail(f"{field} is not bound to canonical cell {cid}")


def _command_value_once(command: list[str], prefix: str, cid: str) -> str | None:
    values = _command_value(command, prefix)
    if len(values) > 1:
        fail(f"{cid} has duplicate {prefix} bindings")
    return values[0] if values else None


def _command_int_once(command: list[str], prefix: str, cid: str) -> int | None:
    value = _command_value_once(command, prefix, cid)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        fail(f"{cid} has a non-integer {prefix} binding")


def _profile_security(profile_id: str, command: list[str]) -> tuple[str, str]:
    """Return (run_class, target security bits) for a named plan profile."""
    if profile_id == "readiness-toy-v1":
        return "smoke", "0"
    security = _command_value(command, "--security=")
    if security == ["STD192"] or "encoding" in profile_id:
        return "primary", "192"
    if security == ["STD128"] or profile_id.startswith("paper-"):
        return "primary", "128"
    return "primary", ""


def _review_taxonomy(method: str, target_bits: int,
                     matrix_eligible: bool) -> dict[str, str]:
    """Independent taxonomy for the non-Piccard comparison producers."""
    matched = target_bits == 128
    if method.startswith("bcg12_"):
        exact = method.startswith("bcg12_exact_")
        finite_field = method.endswith("_ff")
        return {
            "cryptographic_profile": "FF-3072/256" if finite_field else "P-256",
            "nominal_security_bits": "128",
            "security_match": str(matched).lower(),
            "comparison_eligible": str(matched and matrix_eligible).lower(),
            "comparison_scope": ("matched-cardinality-component" if exact
                                 else "matched-estimator-component"),
            "primitive": "bcg12-ff" if finite_field else "bcg12-ec",
            "protocol_model": ("bcg12-exact-cardinality" if exact
                               else "bcg12-cardinality-on-minhash"),
            "output_semantics": ("harness-reconstructed-exact-jaccard" if exact
                                 else "minhash-collision-jaccard-estimate"),
            "assurance_scope": "implemented-baseline-parameter-map",
            "security_basis": ("finite-field-dh-3072-subgroup-256-parameter-map"
                               if finite_field else "nist-p256-parameter-map"),
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
            "secure_division_included": "false",
        }
    if method in {"sj16", "sj16_precomputed"}:
        precomputed = method == "sj16_precomputed"
        return {
            "cryptographic_profile": "Paillier-3072",
            "nominal_security_bits": "128",
            "security_match": str(matched).lower(),
            "comparison_eligible": str(matched and matrix_eligible and
                                       not precomputed).lower(),
            "comparison_scope": "component-lower-bound",
            "primitive": "paillier-3072",
            "protocol_model": "sj16-intersection-shares",
            "output_semantics": "harness-reconstructed-jaccard-with-plaintext-union",
            "assurance_scope": "intersection-shares-lower-bound",
            "security_basis": "rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security",
            "cost_scope": ("online-query-with-precomputed-randomizers" if precomputed
                           else "full-query-excluding-one-time-setup"),
            "precomputation_mode": ("randomizers-precomputed" if precomputed
                                    else "randomizer-generation-included"),
            "secure_division_included": "false",
        }
    return {}


def _revision_suite_for_family(family: str) -> str:
    """Return the concrete versioned suite emitted by the C++ adapter."""
    return {
        "bcg12_minhash": "revision-bcg12-minhash-v1",
        "bcg12_exact": "revision-bcg12-exact-v1",
        "sj16": "revision-sj16-v1",
        "piccard_std192_encoding": "revision-std192-encoding-v1",
    }.get(family, "")


def _bind_review_sidecars(output: Path, rows: list[dict[str, str]],
                          cell: dict[str, Any], plan: dict[str, Any],
                          mode: str, cid: str) -> None:
    """Bind review rows to the canonical workload and execution trace bytes."""
    workload_path = output / "workload.bin"
    trace_path = output / "execution-trace.bin"
    if any(path.is_symlink() or not path.is_file()
           for path in (workload_path, trace_path)):
        fail(f"review workload/trace sidecars are missing for {cid}")
    try:
        from verify_review_comparison import (
            WORKLOAD_DOMAIN, Reader, Trial, VerificationError,
            Workload, expected_kind, hash_seed, realized_intersection,
            regenerate_sets, trial_seed, verify_trace)
        data = workload_path.read_bytes()
        reader = Reader(data, "revision workload")
        reader.domain(WORKLOAD_DOMAIN)
        suite = reader.string()
        profile_id = reader.string()
        root_seed = reader.u64()
        k, m, set_size, universe = (reader.u64() for _ in range(4))
        numerator, denominator = reader.u64(), reader.u64()
        if denominator == 0:
            fail(f"review workload target denominator is zero for {cid}")
        method_count = reader.u32()
        methods = tuple(reader.string() for _ in range(method_count))
        # Only the versioned encoding workload has a fourth trial-count field.
        # This discriminator comes from the immutable matrix cell and method
        # topology, never from an untrusted suite string in the workload.  The
        # legacy comparison wire must remain byte-compatible with Work 5.
        encoding_workload = (
            cell.get("expected_artifact_schema") == "review-encoding-csv-v1" or
            cell.get("family") == "piccard_std192_encoding" or
            (bool(methods) and set(methods) <= {
                "piccard_encode", "piccard_sqrt_encode"}))
        timing_trials = reader.u32()
        accuracy_trials = reader.u32()
        correctness_trials = reader.u32() if encoding_workload else 0
        record_count = reader.u32()
        records = []
        for _ in range(record_count):
            records.append(Trial(reader.u8(), reader.u32(), reader.u64(), reader.u64(),
                                 tuple(reader.vector()), tuple(reader.vector()),
                                 reader.u64(), reader.u64()))
        reader.finish()
        command = plan.get("command", [])
        abstract_profile = _command_value_once(command, "--profile=", cid)
        expected_profile = abstract_profile
        if abstract_profile == "paper-v1":
            expected_profile = ("paper-std192-encoding-v1" if encoding_workload
                                else "std128-t40-primary")
        axes = cell["axes"]
        expected_methods = tuple(
            str(item["method"]) for item in cell["expected_rows"]
            if item.get("terminal_status") != "NOT_APPLICABLE")
        expected_timing = int(cell["expected_rows"][0][
            "toy_measured_count" if mode == "toy" else "paper_measured_count"])
        expected_accuracy = 0
        expected_correctness = 1 if encoding_workload else 0
        expected_seed = _command_int_once(command, "--seed=", cid)
        expected_suite = _revision_suite_for_family(str(cell.get("family", "")))
        if not expected_suite:
            # This helper is used only for the versioned review families.  A
            # synthetic test cell must not silently widen the accepted suite
            # grammar.
            fail(f"unsupported versioned review family for {cid}")
        if suite != expected_suite or profile_id != expected_profile or \
                expected_seed is None or root_seed != expected_seed or \
                (k, m, set_size, universe) != tuple(
                    int(axes[name]) for name in ("k", "m", "n", "u")) or \
                (numerator, denominator) != (1, 2) or \
                methods != expected_methods or timing_trials != expected_timing or \
                accuracy_trials != expected_accuracy or \
                correctness_trials != expected_correctness or \
                record_count != (1 + timing_trials + accuracy_trials +
                                 correctness_trials):
            fail(f"review workload identity/topology mismatch for {cid}")
        target = Fraction(numerator, denominator)
        if target.numerator != numerator or target.denominator != denominator or \
                not 0 <= target <= 1:
            fail(f"review workload target is not canonical for {cid}")
        expected_intersection = realized_intersection(set_size, target)
        expected_records = ([(0, 0)] +
                           [(1, index) for index in range(timing_trials)] +
                           [(2, index) for index in range(accuracy_trials)] +
                           [(3, index) for index in range(correctness_trials)])
        for record, identity in zip(records, expected_records):
            if (record.kind, record.index) != identity or \
                    record.trial_seed != trial_seed(root_seed, *identity) or \
                    record.hash_seed != (
                        _correctness_hash_seed(root_seed, identity[1])
                        if identity[0] == 3 else hash_seed(root_seed, *identity)):
                fail(f"review workload trial identity mismatch for {cid}")
            expected_a, expected_b = regenerate_sets(
                universe, set_size, expected_intersection, record.trial_seed)
            if record.set_a != expected_a or record.set_b != expected_b or \
                    record.intersection != expected_intersection or \
                    record.union != 2 * set_size - expected_intersection:
                fail(f"review workload trial payload mismatch for {cid}")
        workload = Workload(
            suite, profile_id, root_seed, k, m, set_size, universe,
            target, methods,
            timing_trials, accuracy_trials, tuple(records), sha256_file(workload_path))
        trace_digest = verify_trace(trace_path, workload)
    except (OSError, VerificationError) as exc:
        fail(f"review workload/trace sidecars are invalid for {cid}: {exc}")
    for row in rows:
        _require_value(row, "workload_id", workload.workload_id, cid)
        _require_value(row, "workload_manifest_sha256", workload.digest, cid)
        _require_value(row, "execution_trace_sha256", trace_digest, cid)
        _require_value(row, "evidence_arm", "timing", cid)
        method = _row_value(row, "method", cid)
        try:
            kind = expected_kind(method, "timing")
        except VerificationError as exc:
            fail(f"review measurement method is invalid for {cid}: {exc}")
        _require_value(row, "measurement_kind", kind, cid)


def _bind_cell_shape(rows: list[dict[str, str]], cell: dict[str, Any],
                     plan: dict[str, Any], cid: str) -> None:
    """Bind every shape/security field exposed by a family CSV header.

    Shape is derived from the canonical matrix and the concrete argv, never
    from a producer's row.  This is deliberately shared by all CSV families
    so an artifact from an adjacent k/m/n/U cell cannot pass merely because
    its method/count topology happens to match.
    """
    command = plan.get("command", [])
    if not isinstance(command, list):
        fail(f"malformed command for {cid}")
    axes = cell.get("axes", {})
    arg_to_axis = (("--k=", "k"), ("--m=", "m"),
                   ("--set_size=", "n"), ("--n=", "n"),
                   ("--universe=", "u"))
    expected_axes: dict[str, int | float] = {}
    for flag, axis in arg_to_axis:
        value = _command_value_once(command, flag, cid)
        if value is None:
            continue
        try:
            expected_axes[axis] = int(value)
        except ValueError:
            fail(f"{cid} has invalid {flag} binding")
    for axis, value in axes.items():
        if axis in {"k", "m", "n", "u"} and axis not in expected_axes:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                expected_axes[axis] = value
    # BCG12 MinHash consumes k but not the one-hot m dimension.  Exact-
    # cardinality BCG12 and SJ16 consume neither MinHash dimension.  Their
    # serializers intentionally emit the corresponding fields as N/A/blank;
    # retaining an m axis for MinHash would reject a legitimate producer row.
    if cell.get("family") in {"bcg12_minhash", "bcg12_exact", "sj16"}:
        expected_axes.pop("m", None)
    if cell.get("family") in {"bcg12_exact", "sj16"}:
        expected_axes.pop("k", None)
    # Matrix aliases are explicit in the schema; bind their exposed CSV names.
    row_fields = {"k": ("k",), "m": ("m",), "n": ("set_size", "n"),
                  "u": ("universe_size", "universe")}
    for axis, fields in row_fields.items():
        if axis not in expected_axes:
            continue
        value = expected_axes[axis]
        for row in rows:
            for field in fields:
                if field in row:
                    _require_value(row, field, value, cid)
    seed = _command_int_once(command, "--seed=", cid)
    if seed is not None:
        for row in rows:
            _require_value(row, "root_seed", seed, cid)
    profile = _command_value_once(command, "--profile=", cid)
    if profile is not None:
        run_class, target_bits = _profile_security(profile, command)
        row_profile = profile
        if (cell.get("expected_artifact_schema") ==
                "review-comparison-csv-v1" and profile == "paper-v1"):
            row_profile = "std128-t40-primary"
        elif (cell.get("family") == "piccard_std192_encoding" and
              profile == "paper-v1"):
            row_profile = "paper-std192-encoding-v1"
        for row in rows:
            _require_value(row, "profile_id", row_profile, cid)
            _require_value(row, "run_class", run_class, cid)
            if target_bits:
                _require_value(row, "target_security_bits", target_bits, cid)
    security = _command_value_once(command, "--security=", cid)
    if security is not None:
        for row in rows:
            _require_value(row, "security", security, cid)
    if "dataset" in cell:
        dataset = cell["dataset"]
        for row in rows:
            _require_value(row, "dataset", dataset, cid)
    variant = cell.get("variant")
    if variant is not None:
        for row in rows:
            _require_value(row, "variant", variant, cid)
    if "comparison_eligible" in cell:
        expected_eligible = bool(cell["comparison_eligible"])
        if profile == "readiness-toy-v1":
            expected_eligible = False
        for row in rows:
            _require_value(row, "comparison_eligible",
                           expected_eligible, cid)

    if cell.get("expected_artifact_schema") == "review-comparison-csv-v1":
        target_bits = int(_profile_security(profile, command)[1] or 128) \
            if profile is not None else 128
        universe = expected_axes.get("u")
        for row in rows:
            _require_value(row, "suite",
                           _revision_suite_for_family(str(cell["family"])), cid)
            if universe is not None:
                _require_value(row, "scenario", f"review-{universe}", cid)
            method = _row_value(row, "method", cid)
            taxonomy = _review_taxonomy(
                method, target_bits, bool(cell.get("comparison_eligible", False)))
            if not taxonomy:
                fail(f"unknown review taxonomy method for {cid}: {method}")
            for field, expected in taxonomy.items():
                _require_value(row, field, expected, cid)
            for field in ("workload_id", "workload_manifest_sha256",
                          "execution_trace_sha256"):
                _row_value(row, field, cid)

    # The two encoding-only families are intentionally excluded from the
    # end-to-end comparison table.  Their rows still need an explicit,
    # canonical security/cost taxonomy: a producer must not relabel an
    # encoding diagnostic as a full protocol measurement.  Bind these fields
    # from the matrix family rather than trusting a row's self-description.
    encoding_only = cell.get("family") == "piccard_std192_encoding" or \
        (cell.get("family") == "real_dataset" and
         str(cell.get("axis_value")) == "std192_encoding")
    if encoding_only:
        encoding_target = (_profile_security(profile, command)[1]
                           if profile is not None else "192")
        taxonomy = {
            "target_security_bits": encoding_target,
            "cryptographic_profile": "local-encoding-only",
            "nominal_security_bits": "",
            "security_match": "false",
            "comparison_eligible": "false",
            "comparison_scope": "encoding-only-diagnostic",
            "cost_scope": "encoding-only",
            "secure_division_included": "false",
            "signature_derivation_timed": "false",
        }
        review_encoding = cell.get("family") == "piccard_std192_encoding"
        for row in rows:
            for field, expected in taxonomy.items():
                if field in row:
                    _require_value(row, field, expected, cid,
                                   optional=(field == "nominal_security_bits"))
            if review_encoding:
                expected_suite = _revision_suite_for_family(
                    str(cell.get("family", "")))
                if not expected_suite:
                    fail(f"unsupported versioned review family for {cid}")
                _require_value(row, "suite", expected_suite, cid)
                if "u" in expected_axes:
                    _require_value(row, "scenario",
                                   f"review-{expected_axes['u']}", cid)
                method = _row_value(row, "method", cid)
                _require_value(row, "primitive",
                               "onehot-encoding" if method == "piccard_encode"
                               else "sqrt-encoding", cid)
                _require_value(row, "protocol_model",
                               "piccard-local-encoding" if method == "piccard_encode"
                               else "piccard-sqrt-local-encoding", cid)
                for field, expected in {
                    "output_semantics": "encoded-feature-vector",
                    "assurance_scope": "deterministic-encoder-correctness",
                    "security_basis": "local-encoding-no-cryptographic-security-claim",
                    "precomputation_mode": "not-applicable",
                }.items():
                    _require_value(row, field, expected, cid)

    # Estimator-j cells expose the target Jaccard as a row field.  It is a
    # matrix axis, not a producer-chosen annotation, so compare it
    # independently of the integer geometry binding above.
    if "j" in axes:
        expected_j = float(axes["j"])
        for row in rows:
            if "target_jaccard" in row:
                actual_j = _float_value(row, "target_jaccard", cid)
                if not math.isclose(actual_j, expected_j,
                                    rel_tol=0.0, abs_tol=1e-12):
                    fail(f"target_jaccard is not bound to canonical cell {cid}")
    # The concrete seed/randomness/security policy is part of the evidence
    # identity even for rows whose numerical shape is otherwise sparse.
    hash_randomness = _command_value_once(command, "--hash_randomness=", cid)
    if hash_randomness is not None:
        for row in rows:
            _require_value(row, "hash_randomness", hash_randomness, cid)


def _threshold_outcome(decision: bool, truth: bool) -> str:
    if decision and truth:
        return "TP"
    if not decision and not truth:
        return "TN"
    if decision:
        return "FP"
    return "FN"


def _threshold_seed(root_seed: int, pair_id: str, trial_index: int) -> int:
    domain = b"piccard-dblp-threshold-eval-v1\0"
    encoded = pair_id.encode("utf-8")
    payload = (domain + struct.pack(">Q", root_seed) +
               struct.pack(">I", len(encoded)) + encoded +
               struct.pack(">Q", trial_index))
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _threshold_tau(requested: float, k: int, m: int) -> int:
    return max(1, min(k, math.ceil(k * (1.0 / m +
                                        (1.0 - 1.0 / m) * requested))))


def _threshold_boundary(tau: int, k: int, m: int) -> float:
    return (tau / float(k) - 1.0 / float(m)) / (1.0 - 1.0 / float(m))


def _check_real_threshold_science(root: Path, output: Path,
                                  rows: list[dict[str, str]],
                                  cell: dict[str, Any],
                                  plan: dict[str, Any], mode: str,
                                  cid: str) -> None:
    """Recompute held-out threshold truth and outcomes independently.

    The producer's workload/processed files are used only as an input source;
    decisions and both truth bases are reconstructed here.  When the complete
    processed dataset is present, the older standalone real-dataset verifier
    is also invoked to recompute pair selection, split, trial seeds and
    calibration choice.  Minimal schema KATs may omit those files, but still
    have to provide every row-level scientific field and satisfy the same
    formulas.
    """
    command = plan.get("command", [])
    root_seed = _command_int_once(command, "--seed=", cid)
    if root_seed is None:
        fail(f"real threshold command has no root seed for {cid}")
    k_expected = int(cell["axes"].get("k", 128))
    m_expected = int(cell["axes"].get("m", 64))
    trial_expected = (_command_int_once(command, "--threshold-trials=", cid) or
                      int(cell["expected_rows"][0][
                          "toy_measured_count" if mode == "toy"
                          else "paper_measured_count"]))
    if trial_expected <= 0:
        fail(f"real threshold trial count is not positive for {cid}")
    required = {
        "schema_version", "dataset", "variant", "pair_id", "pair_kind",
        "label", "record_a", "record_b", "k", "m", "hash_randomness",
        "root_seed", "split", "rank_position", "threshold_trial_index",
        "hash_seed", "match_count", "decision", "label_truth",
        "label_outcome", "exact_j_truth", "exact_j_outcome",
        "exact_jaccard_bucketed", "requested_j_threshold", "tau_count",
        "realized_j_tau", "calibration_fpr", "calibration_fnr",
        "calibration_balanced_error", "threshold_workload_sha256",
    }
    for row in rows:
        for field in required:
            _row_value(row, field, cid)
        if row["schema_version"] != "piccard-real-threshold-v1" or \
                row["dataset"] != "dblp_acm" or \
                row["variant"] != "dblp_acm_u65536" or \
                row["hash_randomness"] != "resampled" or \
                row["split"] != "evaluation":
            fail(f"real threshold dataset/schema binding mismatch for {cid}")
        if _int_field(row, "k", cid) != k_expected or \
                _int_field(row, "m", cid) != m_expected or \
                _int_field(row, "root_seed", cid) != root_seed:
            fail(f"real threshold parameter/seed binding mismatch for {cid}")
        label = _int_field(row, "label", cid)
        trial = _int_field(row, "threshold_trial_index", cid)
        match_count = _int_field(row, "match_count", cid)
        decision = _int_field(row, "decision", cid)
        label_truth = _int_field(row, "label_truth", cid)
        exact_truth = _int_field(row, "exact_j_truth", cid)
        tau = _int_field(row, "tau_count", cid)
        rank = _int_field(row, "rank_position", cid)
        if label not in {0, 1} or trial not in range(trial_expected) or \
                rank < 0 or match_count < 0 or match_count > k_expected or \
                decision not in {0, 1} or label_truth not in {0, 1} or \
                exact_truth not in {0, 1} or tau < 1 or tau > k_expected:
            fail(f"real threshold integer domain mismatch for {cid}")
        exact_j = _float_value(row, "exact_jaccard_bucketed", cid)
        requested = _float_value(row, "requested_j_threshold", cid)
        realized_tau = _float_value(row, "realized_j_tau", cid)
        if not 0.0 <= exact_j <= 1.0 or not 0.0 <= requested <= 1.0:
            fail(f"real threshold Jaccard domain mismatch for {cid}")
        expected_tau = _threshold_tau(requested, k_expected, m_expected)
        expected_realized = _threshold_boundary(expected_tau, k_expected, m_expected)
        if tau != expected_tau or not math.isclose(realized_tau, expected_realized,
                                                   rel_tol=0.0, abs_tol=1e-12):
            fail(f"real threshold boundary recomputation mismatch for {cid}")
        expected_decision = int(match_count >= tau)
        expected_label_truth = label
        expected_exact_truth = int(exact_j >= realized_tau)
        if decision != expected_decision or label_truth != expected_label_truth or \
                exact_truth != expected_exact_truth:
            fail(f"real threshold truth/decision mismatch for {cid}")
        if row["label_outcome"] != _threshold_outcome(
                bool(decision), bool(label_truth)) or \
                row["exact_j_outcome"] != _threshold_outcome(
                    bool(decision), bool(exact_truth)):
            fail(f"real threshold outcome mismatch for {cid}")
        expected_seed = _threshold_seed(root_seed, row["pair_id"], trial)
        if _int_field(row, "hash_seed", cid) != expected_seed:
            fail(f"real threshold trial seed mismatch for {cid}")
        for field in ("calibration_fpr", "calibration_fnr",
                      "calibration_balanced_error"):
            value = _float_value(row, field, cid)
            if not 0.0 <= value <= 1.0:
                fail(f"real threshold calibration field out of range for {cid}")

    keys = {(row["pair_id"], _int_field(row, "threshold_trial_index", cid))
            for row in rows}
    if len(keys) != len(rows):
        fail(f"real threshold has duplicate pair/trial keys for {cid}")
    by_pair: dict[str, set[int]] = {}
    for pair_id, trial in keys:
        by_pair.setdefault(pair_id, set()).add(trial)
    if not by_pair or any(values != set(range(trial_expected))
                          for values in by_pair.values()):
        fail(f"real threshold has incomplete pair/trial coverage for {cid}")

    workload = _command_file(root, command, "--workload-rows-out=", cid)
    workload_rows: dict[str, dict[str, str]] = {}
    if workload is not None:
        try:
            text = workload.read_text(encoding="utf-8")
            lines = text.splitlines()
            expected_header = ["pair_id", "label", "split", "rank_position",
                               "record_a", "record_b", "exact_jaccard_bucketed"]
            if not lines or lines[0].split("\t") != expected_header:
                fail(f"real threshold workload header mismatch for {cid}")
            reader = csv.DictReader(io.StringIO(text), delimiter="\t")
            for item in reader:
                pair_id = str(item.get("pair_id", ""))
                if not pair_id or pair_id in workload_rows:
                    fail(f"real threshold workload pair identity is malformed for {cid}")
                workload_rows[pair_id] = dict(item)
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            fail(f"cannot read real threshold workload for {cid}: {exc}")
        for row in rows:
            pair = workload_rows.get(row["pair_id"])
            if pair is None or pair.get("split") != "evaluation" or \
                    pair.get("record_a") != row["record_a"] or \
                    pair.get("record_b") != row["record_b"] or \
                    pair.get("pair_kind") not in {None, row["pair_kind"]}:
                fail(f"real threshold row does not bind held-out workload for {cid}")
            for field in ("label", "rank_position", "exact_jaccard_bucketed"):
                if not math.isclose(float(row[field]), float(pair[field]),
                                    rel_tol=0.0, abs_tol=1e-12):
                    fail(f"real threshold workload field {field} mismatch for {cid}")
        if {row["pair_id"] for row in rows} != set(workload_rows):
            fail(f"real threshold output/workload pair set mismatch for {cid}")

    workload_manifest = _command_file(root, command, "--workload-manifest-out=", cid)
    if workload_manifest is not None:
        workload_sha = sha256_file(workload_manifest)
        if any(row["threshold_workload_sha256"] != workload_sha for row in rows):
            fail(f"real threshold workload manifest digest mismatch for {cid}")
    elif any(not row["threshold_workload_sha256"] for row in rows):
        fail(f"real threshold workload digest is missing for {cid}")

    dataset_manifest = _command_file(root, command, "--dataset-manifest=", cid)
    if dataset_manifest is not None:
        dataset_sha = sha256_file(dataset_manifest)
        if any(row["dataset_manifest_sha256"] != dataset_sha for row in rows):
            fail(f"real threshold dataset manifest digest mismatch for {cid}")
        # When the full processed fixture and workload manifests are present,
        # delegate to the independently maintained verifier that recomputes
        # split selection, calibration choice and MinHash match counts.
        if workload_manifest is not None and workload is not None:
            try:
                from verify_real_dataset_outputs import verify_threshold_artifacts
                verify_threshold_artifacts(
                    dataset_manifest, output / "threshold.csv", workload_manifest,
                    workload, root_seed=root_seed, threshold_trials=trial_expected,
                    max_pairs=_command_int_once(command, "--max-pairs=", cid) or 1000,
                    k=k_expected, m=m_expected)
            except RevisionContractError:
                raise
            except Exception as exc:  # noqa: BLE001 - evidence is untrusted
                fail(f"real threshold independent recomputation failed for {cid}: {exc}")


def _check_sj16_calibration(root: Path, output: Path, plan: dict[str, Any],
                            cell: dict[str, Any], mode: str, cid: str) -> None:
    """Parse the typed SJ16 calibration grammar and bind its full topology."""
    values = _command_value(plan.get("command", []), "--output=")
    if len(values) != 1:
        fail(f"SJ16 calibration lacks one canonical --output for {cid}")
    artifact = _output_path(root, output, values[0], "SJ16 calibration")
    try:
        lines = artifact.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"SJ16 calibration is not readable for {cid}: {exc}")
    if not lines or lines[0] != "# SJ16 calibration summary":
        fail(f"SJ16 calibration grammar header mismatch for {cid}")
    metadata: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        # Dispersion records use key=value tokens too, but are parsed by the
        # typed detail grammar below.  Treating them as metadata would make a
        # valid repeated detail key look like duplicate metadata.
        if line.startswith("k3072_"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key or key in metadata:
            fail(f"SJ16 calibration has duplicate/malformed metadata for {cid}")
        metadata[key] = value
    expected_profile = "readiness-toy-v1" if mode == "toy" else "paper-v1"
    expected_trials = 1 if mode == "toy" else 30
    expected_sizes = [4096, 8192, 16384]
    expected_keys = {
        "overall_status": "PASS", "key_bits": "3072", "precompute_mode": "off",
        "trials_per_size": str(expected_trials), "enc_iters": str(expected_trials),
        "held_out": "32768", "residual_tau": "0.1", "fit_sizes": ",".join(
            str(size) for size in expected_sizes),
    }
    # These fields identify the command/profile even though host/timestamp are
    # intentionally machine-specific provenance.
    for key, expected in expected_keys.items():
        if metadata.get(key) != expected:
            fail(f"SJ16 calibration {key} topology mismatch for {cid}")
    command = plan.get("command", [])
    key_arg = _command_value_once(command, "--key-bits=", cid)
    if key_arg not in {None, "3072"}:
        fail(f"SJ16 calibration key size is not canonical for {cid}")
    profile_arg = _command_value_once(command, "--profile=", cid)
    if profile_arg not in {None, expected_profile}:
        fail(f"SJ16 calibration profile mismatch for {cid}")
    for prefix, expected in (("--sizes=", "4096,8192,16384"),
                             ("--held-out=", "32768"),
                             ("--threads=", "2"),
                             ("--warmup=", "1")):
        value = _command_value_once(command, prefix, cid)
        if value is not None and value != expected:
            fail(f"SJ16 calibration {prefix} topology mismatch for {cid}")
    query_trials = (_command_value_once(command, "--query-trials=", cid) or
                    _command_value_once(command, "--trials=", cid))
    enc_iters = _command_value_once(command, "--enc-iters=", cid)
    if query_trials is not None and query_trials != str(expected_trials):
        fail(f"SJ16 calibration query trial count mismatch for {cid}")
    if enc_iters is not None and enc_iters != str(expected_trials):
        fail(f"SJ16 calibration encryption iteration count mismatch for {cid}")
    if metadata.get("threads_requested") not in {None, "2"} or \
            metadata.get("threads_observed") not in {None, "2"}:
        fail(f"SJ16 calibration thread topology mismatch for {cid}")

    columns = [index for index, line in enumerate(lines)
               if line.startswith("# columns: ")]
    expected_columns = ["key_bits", "t_enc_median_ms", "t_enc_iqr_ms",
                        "alpha_ms_per_m", "beta_ms", "r2", "held_measured_ms",
                        "held_pred_ms", "held_residual", "gate"]
    if columns != [next((index for index, line in enumerate(lines)
                         if line.startswith("# columns: ")), -1)]:
        # This branch is deliberately explicit to reject multiple declarations.
        fail(f"SJ16 calibration must declare exactly one columns header for {cid}")
    header_index = columns[0]
    if lines[header_index] != "# columns: " + ",".join(expected_columns):
        fail(f"SJ16 calibration columns header mismatch for {cid}")
    data_rows: list[list[str]] = []
    for line in lines[header_index + 1:]:
        if not line or line.startswith("#") or "=" in line:
            continue
        fields = line.split(",")
        if len(fields) == len(expected_columns):
            data_rows.append(fields)
    if len(data_rows) != 1:
        fail(f"SJ16 calibration must contain exactly one declared K row for {cid}")
    declared = dict(zip(expected_columns, data_rows[0]))
    if declared["key_bits"] != "3072" or declared["gate"] != "PASS":
        fail(f"SJ16 calibration declared K/gate mismatch for {cid}")
    for field in expected_columns[1:-1]:
        try:
            if not math.isfinite(float(declared[field])):
                raise ValueError
        except ValueError:
            fail(f"SJ16 calibration declared field {field} is not finite for {cid}")

    # The detailed dispersion grammar must contain one encryption line, each
    # fit size once, and the held-out size once.  Every sample list is tied to
    # its mode count; this prevents a token-only fake from authorizing an
    # extrapolation.
    detail_re = re.compile(
        r"^k3072_(?P<kind>t_enc|fit_m=(?P<fit>\d+)|heldout_m=(?P<held>\d+)) "
        r"median=(?P<median>[^ ]+)"
        r"(?: q1=(?P<q1>[^ ]+) q3=(?P<q3>[^ ]+) iqr=(?P<iqr>[^ ]+))? samples=(?P<samples>.*)$")
    seen_details: set[str] = set()
    for line in lines:
        match = detail_re.match(line)
        if match is None:
            continue
        kind = match.group("kind")
        detail_key = ("t_enc" if kind == "t_enc" else
                      f"fit_m={match.group('fit')}" if match.group("fit") else
                      f"heldout_m={match.group('held')}")
        if detail_key in seen_details:
            fail(f"SJ16 calibration duplicate dispersion row for {cid}")
        seen_details.add(detail_key)
        if kind == "t_enc":
            sample_count = expected_trials
        else:
            size = int(match.group("fit") or match.group("held"))
            if match.group("fit") and size not in expected_sizes:
                fail(f"SJ16 calibration has an unexpected fit size for {cid}")
            if match.group("held") and size != 32768:
                fail(f"SJ16 calibration held-out size mismatch for {cid}")
            sample_count = expected_trials
        numeric = [match.group(name) for name in ("median", "q1", "q3", "iqr")
                   if match.group(name) is not None]
        try:
            if any(not math.isfinite(float(value)) for value in numeric):
                raise ValueError
            samples = [item for item in match.group("samples").split(",") if item]
            if len(samples) != sample_count or any(not math.isfinite(float(item))
                                                   for item in samples):
                raise ValueError
        except ValueError:
            fail(f"SJ16 calibration dispersion/sample topology mismatch for {cid}")
    required_details = {"t_enc", *(f"fit_m={size}" for size in expected_sizes),
                        "heldout_m=32768"}
    if seen_details != required_details:
        fail(f"SJ16 calibration dispersion topology mismatch for {cid}")


def _check_n_a_terminal(stderr: bytes, cell: dict[str, Any], *, row_id: str,
                        reason: str) -> None:
    rows = _terminal_records(stderr, cell["cell_id"])
    matching = [row for row in rows if row.get("row_id") == row_id]
    if len(matching) != 1:
        fail(f"missing or duplicate NOT_APPLICABLE terminal row for {cell['cell_id']}")
    row = matching[0]
    if row.get("status") != "NOT_APPLICABLE" or \
            row.get("terminal_status") != "NOT_APPLICABLE" or \
            row.get("reason") != reason or row.get("reason_code") != reason or \
            row.get("measured_count") != "0":
        fail(f"NOT_APPLICABLE terminal binding mismatch for {cell['cell_id']}")


def _check_terminal_ids(stderr: bytes, cell: dict[str, Any],
                        expected: set[str], *, reason: str) -> None:
    """Require the complete terminal-row set for a producer family.

    A valid N/A row is bound to the logical method it replaces.  Accepting an
    additional terminal row would let a producer silently drop a second
    method while keeping the receipt's aggregate count unchanged.
    """
    rows = _terminal_records(stderr, cell["cell_id"])
    observed = [str(row.get("row_id", "")) for row in rows]
    if len(observed) != len(set(observed)) or set(observed) != expected:
        fail(f"terminal row taxonomy mismatch for {cell['cell_id']}")
    for row_id in expected:
        row = next(row for row in rows if row.get("row_id") == row_id)
        if row.get("status") != "NOT_APPLICABLE" or \
                row.get("terminal_status") != "NOT_APPLICABLE" or \
                row.get("reason") != reason or row.get("reason_code") != reason or \
                row.get("measured_count") != "0":
            fail(f"terminal N/A binding mismatch for {cell['cell_id']}")


def _check_noise_artifacts(root: Path, output: Path, receipt: dict[str, Any],
                           plan: dict[str, Any], cell: dict[str, Any],
                           mode: str) -> None:
    """Validate the wrapper's manifest-bound nested flooding shard.

    ``run_noise_profiles.sh`` deliberately owns a payload directory below the
    lifecycle cell directory.  The aggregate and detail CSVs are therefore
    admissible only at the key selected by the run/profile/revision manifests;
    a flat or copied CSV must not satisfy this family.
    """
    command = plan.get("command", [])
    roots = _command_value(command, "--results-root=")
    if len(roots) != 1:
        fail(f"noise producer must bind exactly one results-root for {cell['cell_id']}")
    payload = Path(roots[0])
    if not payload.is_absolute():
        payload = root / payload
    try:
        payload.resolve(strict=False).relative_to(output.resolve())
    except ValueError:
        fail(f"noise payload escapes canonical output for {cell['cell_id']}")
    if payload.resolve() != (output / "payload").resolve():
        fail(f"noise payload path is not the canonical cell payload for {cell['cell_id']}")
    if payload.is_symlink() or not payload.is_dir():
        fail(f"noise payload directory is missing or unsafe for {cell['cell_id']}")

    def safe_payload(relative: str, label: str) -> Path:
        path = _safe_relative(payload, relative, label)
        if path.is_symlink() or not path.is_file():
            fail(f"{label} is missing or unsafe for {cell['cell_id']}")
        return path

    run_manifest = load_json(safe_payload("run_manifest.json", "noise run manifest"),
                             "noise run manifest")
    profile = str(cell.get("axis_value"))
    expected_profile = "readiness-toy-v1" if mode == "toy" else "paper-v1"
    repetitions = 1 if mode == "toy" else 5
    if run_manifest.get("schema") != "piccard-noise-revision-run-v1" or \
            run_manifest.get("profile_id") != profile or \
            run_manifest.get("run_profile") != expected_profile or \
            run_manifest.get("status") != "READINESS_ONLY" or \
            run_manifest.get("table_eligible") is not False or \
            run_manifest.get("repetitions_per_pattern") != repetitions or \
            run_manifest.get("patterns") != ["zero", "random", "adversarial"] or \
            run_manifest.get("invocation_count") != 1:
        fail(f"noise run manifest identity/topology mismatch for {cell['cell_id']}")

    resolved = load_json(safe_payload("resolved_noise_profiles.json",
                                      "resolved noise profile matrix"),
                         "resolved noise profile matrix")
    if not isinstance(resolved, dict) or not isinstance(resolved.get("profiles"), list):
        fail(f"resolved noise profile matrix is malformed for {cell['cell_id']}")
    source_commit = str(resolved.get("source_commit", ""))
    if source_commit in {"runtime-source-commit", ""} or len(source_commit) != 40:
        fail(f"resolved noise profile source is not bound for {cell['cell_id']}")

    profiles_root = payload / "profiles" / profile
    profile_manifest_path = profiles_root / "profile_manifest.json"
    if profile_manifest_path.is_symlink() or not profile_manifest_path.is_file():
        fail(f"noise profile manifest is missing for {cell['cell_id']}")
    profile_manifest = load_json(profile_manifest_path, "noise profile manifest")
    if profile_manifest.get("schema") != "piccard-noise-revision-profile-v1" or \
            profile_manifest.get("profile_id") != profile or \
            profile_manifest.get("source_commit") != source_commit or \
            profile_manifest.get("key_count") != 1 or \
            profile_manifest.get("profile_verdict") != "READINESS_ONLY" or \
            profile_manifest.get("table_eligible") is not False:
        fail(f"noise profile manifest identity mismatch for {cell['cell_id']}")
    key_verdicts = profile_manifest.get("key_verdicts")
    if not isinstance(key_verdicts, dict) or len(key_verdicts) != 1:
        fail(f"noise profile key verdict topology mismatch for {cell['cell_id']}")
    key_id, key_verdict = next(iter(key_verdicts.items()))
    if key_verdict != "SELECTED" or not isinstance(key_id, str) or not key_id:
        fail(f"noise profile key verdict mismatch for {cell['cell_id']}")

    shard = profiles_root / key_id
    identity_path = shard / "revision_identity.json"
    if identity_path.is_symlink() or not identity_path.is_file():
        fail(f"noise shard revision identity is missing for {cell['cell_id']}")
    identity = load_json(identity_path, "noise shard revision identity")
    if identity.get("schema") != "piccard-noise-revision-shard-v1" or \
            identity.get("cell_id") != cell["cell_id"] or \
            identity.get("run_profile") != expected_profile or \
            identity.get("profile_id") != profile or \
            identity.get("key_id") != key_id or \
            identity.get("repetitions_per_pattern") != repetitions or \
            identity.get("patterns") != ["zero", "random", "adversarial"] or \
            identity.get("status") != "READINESS_ONLY" or \
            identity.get("table_eligible") is not False:
        fail(f"noise shard revision identity mismatch for {cell['cell_id']}")
    # Resolve the expected consumer set independently from the tracked noise
    # matrix; manifests identify the artifact but cannot redefine its family.
    try:
        from revision_flooding_adapter import select_noise_partition
        noise_matrix = json.loads((ROOT / "scripts" / "noise_profiles.json").read_text(
            encoding="utf-8"))
        partition = select_noise_partition(noise_matrix, profile)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        fail(f"cannot resolve canonical noise partition: {exc}")
    expected_consumers = {(str(point["k"]), str(point["m"]))
                          for point in partition["consumer_points"]}
    identity_consumers = {
        (str(point.get("k")), str(point.get("m")))
        for point in identity.get("consumer_points", [])
        if isinstance(point, dict)
    }
    if identity.get("consumer_set_sha256") != partition["consumer_set_sha256"] or \
            identity_consumers != expected_consumers:
        fail(f"noise shard consumer identity mismatch for {cell['cell_id']}")

    aggregate_path = shard / "aggregate.csv"
    details_dir = shard / "details"
    candidates_path = shard / "candidates.json"
    if any(path.is_symlink() or not path.is_file()
           for path in (aggregate_path, candidates_path)) or \
            details_dir.is_symlink() or not details_dir.is_dir():
        fail(f"noise shard payload is incomplete for {cell['cell_id']}")
    aggregate_header = (
        "profile,circuit,shape_id,security,consumer_count,consumer_set_sha256,"
        "worst_consumer_k,worst_consumer_m,pattern_count,repetitions_per_pattern,"
        "detail_row_count,detail_sha256,seed,requested_ring_dim,natural_ring_dim,"
        "realized_ring_dim,ring_growth_factor,ring_dim_calibrated,natural_depth,"
        "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,log_delta,"
        "eval_noise_bits,headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
        "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,openfhe_version,"
        "source_commit,status_code,error_message,consumer_results_sha256\n")
    aggregate_rows = _csv_table(aggregate_path.read_bytes(), aggregate_header,
                                f"noise aggregate {cell['cell_id']}")
    if not aggregate_rows or any(
            row.get("profile") != profile or
            row.get("consumer_count") != str(len(expected_consumers)) or
            row.get("consumer_set_sha256") != partition["consumer_set_sha256"] or
            row.get("pattern_count") != "3" or
            row.get("repetitions_per_pattern") != str(repetitions) or
            row.get("source_commit") != source_commit
            for row in aggregate_rows):
        fail(f"noise aggregate identity/repetition mismatch for {cell['cell_id']}")
    detail_paths = sorted(path for path in details_dir.glob("*.csv")
                          if path.is_file() and not path.is_symlink())
    if not detail_paths:
        fail(f"noise detail CSVs are missing for {cell['cell_id']}")
    candidates = load_json(candidates_path, "noise candidate manifest")
    required_candidate_fields = {
        "schema", "version", "key_id", "source_commit", "openfhe_version",
        "profile_id", "circuit", "shape_id", "security", "requested_ring_dim",
        "natural_depth", "consumer_points", "consumer_set_sha256", "command",
        "candidate_count", "candidates",
    }
    if set(candidates) != required_candidate_fields or \
            candidates.get("schema") != "piccard-candidate-manifest" or \
            candidates.get("version") != 1 or \
            candidates.get("key_id") != key_id or \
            candidates.get("profile_id") != profile or \
            candidates.get("source_commit") != source_commit or \
            not isinstance(candidates.get("candidates"), list) or \
            candidates.get("candidate_count") != len(candidates["candidates"]):
        fail(f"noise candidate manifest identity/schema mismatch for {cell['cell_id']}")
    candidate_records = candidates["candidates"]
    candidate_ids = [str(record.get("candidate_id", ""))
                     for record in candidate_records if isinstance(record, dict)]
    if len(candidate_ids) != len(candidate_records) or \
            not candidate_ids or len(candidate_ids) != len(set(candidate_ids)) or \
            {path.stem for path in detail_paths} != set(candidate_ids):
        fail(f"noise candidate/detail topology mismatch for {cell['cell_id']}")
    aggregate_by_candidate: dict[str, dict[str, str]] = {}
    for aggregate in aggregate_rows:
        try:
            aggregate_id = (
                f"N{int(aggregate['ring_dim_calibrated'])}-d"
                f"{int(aggregate['provisioned_depth'])}-s"
                f"{int(aggregate['scaling_mod_size'])}")
        except (KeyError, ValueError):
            fail(f"noise aggregate candidate identity is malformed for {cell['cell_id']}")
        if aggregate_id in aggregate_by_candidate:
            fail(f"noise aggregate has duplicate candidate identity for {cell['cell_id']}")
        aggregate_by_candidate[aggregate_id] = aggregate
    if set(aggregate_by_candidate) != set(candidate_ids):
        fail(f"noise aggregate/candidate topology mismatch for {cell['cell_id']}")
    for candidate in candidate_records:
        aggregate = aggregate_by_candidate[candidate["candidate_id"]]
        if candidate.get("status_code") != aggregate.get("status_code") or \
                candidate.get("detail_sha256") != aggregate.get("detail_sha256") or \
                str(candidate.get("detail_row_count")) != aggregate.get("detail_row_count"):
            fail(f"noise aggregate/candidate binding mismatch for {cell['cell_id']}")
    detail_header = (
        "profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,consumer_m,"
        "pattern,rep_index,rep_seed,requested_ring_dim,natural_ring_dim,"
        "ring_dim_calibrated,realized_ring_dim,ring_growth_factor,natural_depth,"
        "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,log_delta,"
        "eval_noise_bits,headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
        "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,openfhe_version,"
        "source_commit,status_code,error_message\n")
    observed: set[tuple[str, str, str, str]] = set()
    for detail_path in detail_paths:
        rows = _csv_table(detail_path.read_bytes(), detail_header,
                          f"noise detail {cell['cell_id']}")
        for row in rows:
            key = (row.get("consumer_k", ""), row.get("consumer_m", ""),
                   row.get("pattern", ""), row.get("rep_index", ""))
            if (row.get("profile") != profile or row.get("key_id") != key_id or
                    row.get("pattern") not in {"zero", "random", "adversarial"} or
                    row.get("source_commit") != source_commit or
                    (row.get("consumer_k"), row.get("consumer_m"))
                    not in expected_consumers):
                fail(f"noise detail identity/pattern mismatch for {cell['cell_id']}")
            try:
                rep_index = int(row["rep_index"])
            except (KeyError, ValueError):
                fail(f"noise detail repetition index is invalid for {cell['cell_id']}")
            if rep_index not in range(repetitions) or key in observed:
                fail(f"noise detail repetition topology mismatch for {cell['cell_id']}")
            observed.add(key)
        candidate = next(record for record in candidate_records
                         if record.get("candidate_id") == detail_path.stem)
        if candidate.get("detail_row_count") != len(rows) or \
                candidate.get("detail_sha256") != sha256_file(detail_path):
            fail(f"noise candidate/detail binding mismatch for {cell['cell_id']}")
    expected_detail_count = len(expected_consumers) * 3 * repetitions
    if len(observed) != expected_detail_count or any(
            int(row.get("detail_row_count", "-1")) != expected_detail_count
            for row in aggregate_rows):
        fail(f"noise detail row count mismatch for {cell['cell_id']}")

    allowed = {
        "payload/run_manifest.json", "payload/resolved_noise_profiles.json",
        f"payload/profiles/{profile}/profile_manifest.json",
        f"payload/profiles/{profile}/{key_id}/revision_identity.json",
        f"payload/profiles/{profile}/{key_id}/aggregate.csv",
        f"payload/profiles/{profile}/{key_id}/candidates.json",
    }
    allowed.update(path.relative_to(output).as_posix()
                   for path in detail_paths)
    actual = {str(item.get("path", "")) for item in receipt.get("artifact_inventory", [])}
    if actual != allowed:
        fail(f"noise artifact inventory contains unrelated or missing files for {cell['cell_id']}")


def _check_family_artifacts(root: Path, mode: str, cells: list[dict[str, Any]],
                            plans: dict[str, dict[str, Any]]) -> None:
    """Validate each producer's canonical artifact and semantic row shape.

    This registry is deliberately explicit.  A CSV is evidence only when it
    comes from the producer-declared stdout/path (or the flooding directory
    contract); an arbitrary CSV copied into a cell can never satisfy a row
    check.  The parser is family-aware because several producers share a
    logical schema while using different terminal/N/A conventions.
    """
    if mode == "dry-run":
        return
    supported = {
        "review-comparison-csv-v1", "deletion-survival-csv-v1",
        "dynamic-benchmark-csv-v1", "estimator-diagnostic-csv-v1",
        "fhe-ind-csv-v1", "noise-profile-v1", "piccard-benchmark-csv-v1",
        "review-encoding-csv-v1", "sqrt-comparison-csv-v1",
        "real-dataset-csv-v1", "real-threshold-csv-v1",
        "sj16-calibration-v1", "threshold-csv-v1", "threshold-fpfn-csv-v1",
    }
    for cell in cells:
        if cell["invocation_status"] == "NO_SPAWN":
            continue
        cid = cell["cell_id"]
        schema = cell["expected_artifact_schema"]
        if schema not in supported:
            fail(f"no independent artifact validator is registered for {schema}")
        output = cell_output(root, cid)
        receipt = load_json(output / "receipt.json", f"receipt {cid}")
        stdout = (output / "stdout.log").read_bytes()
        stderr = (output / "stderr.log").read_bytes()
        plan = plans[cid]
        # The real summary is independently regenerated from its canonical
        # accuracy input.  It is the only summary producer without a fixed
        # C++ CSV header.
        is_summary = cell["family"] == "real_dataset" and \
            str(cell.get("axis_value")) == "summary"
        allowed_csvs: set[str] = set()
        if schema == "noise-profile-v1":
            # The successor wrapper owns a nested profiles/<profile>/<key>
            # tree; its aggregate/detail CSVs are checked below by their
            # manifest-bound paths rather than by a flat basename allowlist.
            allowed_csvs = {str(item.get("path", ""))
                            for item in receipt.get("artifact_inventory", [])
                            if str(item.get("path", "")).endswith(".csv")}
        elif is_summary:
            allowed_csvs = {"summary.csv"}
        elif schema not in {"review-comparison-csv-v1", "review-encoding-csv-v1",
                            "sqrt-comparison-csv-v1", "threshold-csv-v1",
                            "threshold-fpfn-csv-v1", "dynamic-benchmark-csv-v1",
                            "piccard-benchmark-csv-v1", "estimator-diagnostic-csv-v1",
                            "deletion-survival-csv-v1", "fhe-ind-csv-v1"}:
            for prefix in ("--csv=", "--output="):
                values = _command_value(plan.get("command", []), prefix)
                if len(values) == 1:
                    allowed_csvs.add(Path(values[0]).name)
        if schema != "noise-profile-v1":
            _reject_unrelated_csvs(output, receipt, allowed_csvs)
        if is_summary:
            argv = plan.get("command", [])
            def one_path(prefix: str) -> Path:
                values = _command_value(argv, prefix)
                if len(values) != 1:
                    fail(f"summary plan lacks exactly one {prefix} binding")
                return Path(values[0])
            accuracy = one_path("--accuracy-csv=")
            actual = one_path("--output=")
            variant_values = _command_value(argv, "--variant=")
            if len(variant_values) != 1:
                fail("summary plan lacks one variant binding")
            actual = _output_path(root, output, str(actual), "summary output")
            if not accuracy.is_file() or accuracy.is_symlink():
                fail(f"summary accuracy input is missing for {cid}")
            with tempfile.TemporaryDirectory(prefix="piccard-summary-verify.") as temporary:
                verify_root_dir = Path(temporary) / "cells"
                verify_accuracy = verify_root_dir / accuracy.parent.name / "accuracy.csv"
                verify_accuracy.parent.mkdir(parents=True)
                verify_accuracy.write_bytes(accuracy.read_bytes())
                recomputed = verify_root_dir / output.name / "summary.csv"
                recomputed.parent.mkdir(parents=True)
                command = [sys.executable, str(ROOT / "scripts" / "summarize_real_datasets.py"),
                           f"--revision-cell={cid}", f"--accuracy-csv={verify_accuracy}",
                           f"--output={recomputed}", f"--variant={variant_values[0]}"]
                completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                           text=True, check=False)
                if completed.returncode != 0 or actual.read_bytes() != recomputed.read_bytes():
                    fail(f"real summary artifact is not independently reproducible: {cid}")
            continue

        # SJ16 writes a structured key=value artifact, not a CSV stream.
        if schema == "sj16-calibration-v1":
            _check_sj16_calibration(root, output, plan, cell, mode, cid)
            continue

        if schema == "noise-profile-v1":
            _check_noise_artifacts(root, output, receipt, plan, cell, mode)
            continue

        if schema == "sqrt-comparison-csv-v1":
            axis = str(cell.get("axis"))
            expected = [row for row in cell["expected_rows"]
                        if row.get("terminal_status") != "NOT_APPLICABLE"]
            if axis == "accuracy_m":
                rows = _csv_table(stdout, _SQRT_HEADER, f"sqrt accuracy {cid}")
                _bind_cell_shape(rows, cell, plan, cid)
                wanted = {"onehot": "OneHot", "sqrt": "Sqrt"}
                if len(rows) != len(expected) or \
                        {row.get("encoding") for row in rows} != \
                        {wanted[str(item["method"])] for item in expected}:
                    fail(f"sqrt accuracy row taxonomy mismatch for {cid}")
                na = any(item.get("terminal_status") == "NOT_APPLICABLE"
                         for item in cell["expected_rows"])
                _check_terminal_ids(stderr, cell,
                                    {"sqrt"} if na else set(),
                                    reason="sqrt-m-not-perfect-square")
            elif axis == "timing_m":
                rows = _csv_table(stdout, _SQRT_TIMING_HEADER,
                                  f"sqrt timing {cid}")
                _bind_cell_shape(rows, cell, plan, cid)
                wanted = {"onehot", "sqrt"}
                applicable_methods = {str(item["method"]) for item in expected}
                if len(rows) != len(expected) or \
                        {row.get("encoding") for row in rows} != \
                        (wanted & applicable_methods) or \
                        any(row.get("label") != "revision_" + cid or
                            _int_field(row, "trials", cid) !=
                            int(item["toy_measured_count"] if mode == "toy" else
                                item["paper_measured_count"])
                            for row, item in zip(
                                sorted(rows, key=lambda value: value.get("encoding", "")),
                                sorted(expected, key=lambda value: value.get("method", "")))):
                    fail(f"sqrt timing row/trial taxonomy mismatch for {cid}")
                na = any(item.get("terminal_status") == "NOT_APPLICABLE"
                         for item in cell["expected_rows"])
                _check_terminal_ids(stderr, cell,
                                    {"sqrt"} if na else set(),
                                    reason="sqrt-m-not-perfect-square")
            else:
                rows = _csv_table(stdout, _CROSSOVER_HEADER, f"sqrt crossover {cid}")
                _bind_cell_shape(rows, cell, plan, cid)
                if len(rows) != 1:
                    fail(f"sqrt crossover/ciphertext requires one combined row for {cid}")
                nonsquare = any(item.get("terminal_status") == "NOT_APPLICABLE"
                                for item in cell["expected_rows"])
                if nonsquare and rows[0].get("sqrt_N") != "N/A":
                    fail(f"sqrt N/A crossover fields are not bound for {cid}")
                _check_terminal_ids(stderr, cell,
                                    {"sqrt"} if nonsquare else set(),
                                    reason="sqrt-m-not-perfect-square")
            continue

        if schema == "threshold-csv-v1":
            if cell["family"] == "threshold_spec":
                rows = _csv_table(stdout, _THRESHOLD_SPEC_HEADER, f"threshold spec {cid}")
                _bind_cell_shape(rows, cell, plan, cid)
                if len(rows) != 1 or rows[0].get("schema_version") != "piccard-threshold-spec-v2" or \
                        _int_field(rows[0], "k", cid) != int(cell["axes"]["k"]):
                    fail(f"threshold spec k/schema topology mismatch for {cid}")
                if rows[0].get("status") not in {"ok", "SKIPPED"}:
                    fail(f"threshold spec status mismatch for {cid}")
                if rows[0].get("status") == "SKIPPED":
                    live = ("requested_ring_dim", "natural_ring_dim", "provisioned_ring_dim",
                            "realized_ring_dim", "log_q_bits", "plaintext_modulus",
                            "openfhe_version", "ordered_rns_moduli")
                    if any(rows[0].get(field) != "N/A" for field in live):
                        fail(f"threshold spec SKIPPED row fabricated live metadata for {cid}")
                continue
            rows = _csv_table(stdout, _THRESHOLD_HEADER, f"threshold {cid}")
            _bind_cell_shape(rows, cell, plan, cid)
            expected_count = int(cell["expected_rows"][0]["toy_measured_count"]
                                 if mode == "toy" else cell["expected_rows"][0]["paper_measured_count"])
            if cell["family"] == "threshold_agreement":
                labels = [f"{cid}::trial={index}" for index in range(expected_count)]
                if len(rows) != expected_count or [row.get("label") for row in rows] != labels or \
                        any(_int_field(row, "trials", cid) != 0 or
                            _int_field(row, "accuracy_trials", cid) != 1
                            for row in rows):
                    fail(f"threshold agreement row/trial topology mismatch for {cid}")
            else:
                if len(rows) != 1 or rows[0].get("label") != cid or \
                        _int_field(rows[0], "trials", cid) != expected_count:
                    fail(f"threshold timing row/trial topology mismatch for {cid}")
            continue

        if schema == "threshold-fpfn-csv-v1":
            rows = _csv_table(stdout, _THRESHOLD_FPFN_HEADER, f"threshold FP/FN {cid}")
            _bind_cell_shape(rows, cell, plan, cid)
            expected_count = int(cell["expected_rows"][0]["toy_measured_count"]
                                 if mode == "toy" else cell["expected_rows"][0]["paper_measured_count"])
            trials = [_int_field(row, "trial_index", cid) for row in rows]
            if len(rows) != expected_count or sorted(trials) != list(range(expected_count)) or \
                    any(_int_field(row, "k", cid) != int(cell["point_k"]) or
                        _int_field(row, "grid_index", cid) != int(cell["grid_index"])
                        for row in rows):
                fail(f"threshold FP/FN point/trial topology mismatch for {cid}")
            # Reuse the independently maintained plaintext verifier for the
            # complete scientific contract (geometry, derived row seed,
            # MinHash bucket match, inclusive decision, exact-J truth,
            # outcome, binomial tail and Gaussian overlay).  This verifier is
            # deliberately separate from the C++ producer and rejects NaN or
            # forged probability fields as well as identity swaps.
            try:
                from verify_threshold_outputs import _validate_row as _validate_fpfn_row
                root_seed = _command_int_once(plan.get("command", []), "--seed=", cid)
                if root_seed is None:
                    fail(f"threshold FP/FN command has no bound root seed for {cid}")
                fpfn_mode = "toy" if mode == "toy" else "paper"
                keys = []
                for row in rows:
                    keys.append(_validate_fpfn_row(row, fpfn_mode, root_seed))
                if keys != [(int(cell["point_k"]), int(cell["grid_index"]), index)
                            for index in range(expected_count)]:
                    fail(f"threshold FP/FN row keys are not canonical for {cid}")
            except RevisionContractError:
                raise
            except Exception as exc:  # noqa: BLE001 - producer evidence is untrusted
                fail(f"threshold FP/FN scientific recomputation failed for {cid}: {exc}")
            continue

        if schema == "review-encoding-csv-v1":
            rows = _csv_table(stdout, _REVIEW_ENCODING_HEADER, f"review encoding {cid}")
            _bind_cell_shape(rows, cell, plan, cid)
            _bind_review_sidecars(output, rows, cell, plan, mode, cid)
            applicable = [row for row in cell["expected_rows"]
                          if row.get("terminal_status") != "NOT_APPLICABLE"]
            wanted = {str(row["method"]) for row in applicable}
            if {row.get("method") for row in rows} != wanted or len(rows) != len(wanted) or \
                    any(_int_field(row, "timed_encoder_pairs", cid) !=
                        int(item["toy_measured_count"] if mode == "toy" else item["paper_measured_count"])
                        for row, item in zip(sorted(rows, key=lambda x: x.get("method", "")),
                                              sorted(applicable, key=lambda x: x.get("method", "")))):
                fail(f"review encoding method/timed-pair topology mismatch for {cid}")
            if any(row.get("correctness_pair_calls") != "1" for row in rows):
                fail(f"review encoding correctness-pair count mismatch for {cid}")
            _check_terminal_ids(
                stderr, cell,
                {"piccard_sqrt_encode"}
                if len(applicable) != len(cell["expected_rows"]) else set(),
                reason="sqrt-m-not-perfect-square")
            continue

        # All remaining schemas are stdout or explicitly bound single-file
        # CSV producers.  Their semantic checks are intentionally family-
        # specific; there is no global method-token scan.
        if schema == "real-dataset-csv-v1":
            artifact = str(cell.get("axis_value"))
            variant = str(cell["variant"])
            expected_dataset = _expected_dataset_name(variant)
            if artifact == "std192_encoding":
                payload, _ = _canonical_payload(root, output, plan, schema)
                rows = _csv_table(payload, _REAL_ENCODING_HEADER,
                                  f"real encoding {cid}")
                _bind_cell_shape(rows, cell, plan, cid)
                expected_trials = int(cell["expected_rows"][0][
                    "toy_measured_count" if mode == "toy" else "paper_measured_count"])
                if len(rows) != 2 or \
                        {row.get("method") for row in rows} != {
                            "piccard_encode", "piccard_sqrt_encode"} or \
                        any(_int_field(row, "timed_encoder_pairs", cid) != expected_trials or
                            row.get("correctness_pair_calls") != "1" or
                            row.get("correctness_status") != "PASS"
                            for row in rows):
                    fail(f"real encoding method/count taxonomy mismatch for {cid}")
            else:
                header = (_REAL_ACCURACY_HEADER if artifact == "accuracy"
                          else _REAL_TIMING_HEADER)
                payload, _ = _canonical_payload(root, output, plan, schema)
                rows = _csv_table(payload, header, f"real dataset {cid}")
                _bind_cell_shape(rows, cell, plan, cid)
            if not rows or any(row.get("dataset") != expected_dataset or
                               row.get("variant") != variant or
                               _int_field(row, "k", cid) != int(cell["axes"]["k"]) or
                               _int_field(row, "m", cid) != int(cell["axes"]["m"])
                               for row in rows):
                fail(f"real dataset variant binding mismatch for {cid}")
            if artifact == "accuracy":
                trials = (_command_int(plan.get("command", []),
                                       "--accuracy_trials=", cid) or
                          int(cell["expected_rows"][0][
                              "toy_measured_count" if mode == "toy" else
                              "paper_measured_count"]))
                keys = set()
                for row in rows:
                    pair_id = row.get("pair_id", "")
                    if not pair_id or row.get("pair_kind", "") == "":
                        fail(f"real accuracy pair identity is incomplete for {cid}")
                    trial = _int_field(row, "accuracy_trial_index", cid)
                    if trial not in range(trials) or (pair_id, trial) in keys:
                        fail(f"real accuracy pair/trial topology mismatch for {cid}")
                    keys.add((pair_id, trial))
                by_pair: dict[str, set[int]] = {}
                for pair_id, trial in keys:
                    by_pair.setdefault(pair_id, set()).add(trial)
                if any(indices != set(range(trials)) for indices in by_pair.values()):
                    fail(f"real accuracy trial coverage mismatch for {cid}")
                workload = _command_file(root, plan.get("command", []),
                                         "--workload-rows-out=", cid)
                if workload is not None:
                    workload_rows = _tsv_rows(workload, f"real accuracy workload {cid}")
                    wanted: set[tuple[str, int]] = set()
                    for workload_row in workload_rows:
                        try:
                            workload_trial = int(workload_row.get("trial_index", "-1"))
                        except ValueError:
                            fail(f"real accuracy workload trial is malformed for {cid}")
                        workload_pair = str(workload_row.get("pair_id", ""))
                        if not workload_pair or (workload_pair, workload_trial) in wanted:
                            fail(f"real accuracy workload topology is malformed for {cid}")
                        wanted.add((workload_pair, workload_trial))
                    if keys != wanted:
                        fail(f"real accuracy rows do not match workload topology for {cid}")
            elif artifact == "std128_timing":
                trials = (_command_int(plan.get("command", []), "--trials=", cid) or
                          int(cell["expected_rows"][0][
                              "toy_measured_count" if mode == "toy" else
                              "paper_measured_count"]))
                pair_keys = {(row.get("pair_id", ""), row.get("record_a", ""),
                              row.get("record_b", "")) for row in rows}
                indices = {_int_field(row, "trial_index", cid) for row in rows}
                if len(pair_keys) != 1 or len(rows) != trials or \
                        indices != set(range(trials)) or \
                        any(not row.get("pair_id") or row.get("pair_kind", "") == ""
                            for row in rows):
                    fail(f"real timing pair/trial topology mismatch for {cid}")
            continue
        if schema == "real-threshold-csv-v1":
            payload, _ = _canonical_payload(root, output, plan, schema)
            rows = _csv_table(payload, _REAL_THRESHOLD_HEADER,
                              f"real threshold {cid}")
            _bind_cell_shape(rows, cell, plan, cid)
            trials = (_command_int(plan.get("command", []),
                                   "--threshold-trials=", cid) or
                      int(cell["expected_rows"][0][
                          "toy_measured_count" if mode == "toy" else
                          "paper_measured_count"]))
            keys: set[tuple[str, int]] = set()
            for row in rows:
                pair_id = row.get("pair_id", "")
                trial = _int_field(row, "threshold_trial_index", cid)
                if row.get("dataset") != "dblp_acm" or \
                        row.get("variant") != "dblp_acm_u65536" or \
                        _int_field(row, "k", cid) != int(cell["axes"]["k"]) or \
                        _int_field(row, "m", cid) != int(cell["axes"]["m"]) or \
                        row.get("split") != "evaluation" or not pair_id or \
                        trial not in range(trials) or (pair_id, trial) in keys:
                    fail(f"real threshold row identity/trial mismatch for {cid}")
                keys.add((pair_id, trial))
            by_pair: dict[str, set[int]] = {}
            for pair_id, trial in keys:
                by_pair.setdefault(pair_id, set()).add(trial)
            if not rows or any(indices != set(range(trials))
                               for indices in by_pair.values()):
                fail(f"real threshold dataset binding mismatch for {cid}")
            workload = _command_file(root, plan.get("command", []),
                                     "--workload-rows-out=", cid)
            if workload is not None:
                workload_rows = _tsv_rows(workload, f"real threshold workload {cid}")
                evaluation_pairs: dict[str, str] = {}
                for workload_row in workload_rows:
                    if workload_row.get("split") != "evaluation":
                        continue
                    pair_id = str(workload_row.get("pair_id", ""))
                    rank = str(workload_row.get("rank_position", ""))
                    if pair_id in evaluation_pairs:
                        fail(f"real threshold held-out workload has duplicate pair for {cid}")
                    evaluation_pairs[pair_id] = rank
                if not evaluation_pairs or any(not pair_id or not rank
                                               for pair_id, rank in evaluation_pairs.items()):
                    fail(f"real threshold held-out workload is malformed for {cid}")
                output_ranks = {
                    str(row.get("pair_id", "")): str(row.get("rank_position", ""))
                    for row in rows
                }
                if output_ranks != evaluation_pairs:
                    fail(f"real threshold held-out rank binding mismatch for {cid}")
                wanted = {(pair_id, trial) for pair_id in evaluation_pairs
                          for trial in range(trials)}
                if keys != wanted:
                    fail(f"real threshold rows do not match held-out workload for {cid}")
            _check_real_threshold_science(root, output, rows, cell, plan, mode, cid)
            continue
        header = _EXACT_HEADERS.get(schema)
        payload, source = _canonical_payload(root, output, plan, schema)
        if header is not None:
            rows = _csv_table(payload, header, f"{schema} {cid}")
        else:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                fail(f"{schema} artifact is not UTF-8 for {cid}")
            rows = list(csv.DictReader(io.StringIO(text)))
        _bind_cell_shape(rows, cell, plan, cid)
        expected_rows = [row for row in cell["expected_rows"]
                         if row.get("terminal_status") != "NOT_APPLICABLE"]
        expected_counts = [int(row["toy_measured_count"] if mode == "toy"
                               else row["paper_measured_count"])
                           for row in expected_rows]
        if schema == "fhe-ind-csv-v1":
            if len(rows) != 1 or rows[0].get("cell_id") != cid or \
                    rows[0].get("method") != "fhe_ind" or \
                    _int_field(rows[0], "trials", cid) != expected_counts[0]:
                fail(f"FHE-IND cell/trial taxonomy mismatch for {cid}")
        elif schema == "review-comparison-csv-v1":
            _bind_review_sidecars(output, rows, cell, plan, mode, cid)
            expected_by_method = {
                str(item["method"]): int(item["toy_measured_count"] if mode == "toy"
                                          else item["paper_measured_count"])
                for item in expected_rows
            }
            observed_by_method: dict[str, int] = {}
            for row in rows:
                method = str(row.get("method", ""))
                if method in observed_by_method:
                    fail(f"review comparison has duplicate method row for {cid}")
                observed_by_method[method] = _int_field(row, "trials", cid)
            if observed_by_method != expected_by_method:
                fail(f"review comparison row/trial taxonomy mismatch for {cid}")
        elif schema == "piccard-benchmark-csv-v1":
            if len(rows) != 2 or any(row.get("label") != cid for row in rows):
                fail(f"Piccard cell identity/row topology mismatch for {cid}")
            expected_timing = int(expected_rows[0]["toy_measured_count"] if mode == "toy"
                                  else expected_rows[0]["paper_measured_count"])
            expected_accuracy = int(expected_rows[1]["toy_measured_count"] if mode == "toy"
                                    else expected_rows[1]["paper_measured_count"])
            observed = sorted((_int_field(row, "trials", cid),
                               _int_field(row, "accuracy_trials", cid))
                              for row in rows)
            wanted = sorted(((expected_timing, 0),
                             (expected_accuracy, expected_accuracy)))
            if observed != wanted:
                fail(f"Piccard measured-count binding mismatch for {cid}")
        elif schema == "estimator-diagnostic-csv-v1":
            if len(rows) != 1 or _int_field(rows[0], "trials", cid) != expected_counts[0]:
                fail(f"estimator trial topology mismatch for {cid}")
        elif schema == "dynamic-benchmark-csv-v1":
            if cell["family"] == "dynamic_accuracy":
                labels = sorted(row.get("label") for row in rows)
                wanted = sorted((cid + "::insert_correctness", cid + "::delete_correctness"))
                if labels != wanted or sorted(_int_field(row, "trials", cid) for row in rows) != sorted(expected_counts):
                    fail(f"dynamic accuracy row/trial topology mismatch for {cid}")
            elif len(rows) != 1 or rows[0].get("label") != cid or \
                    _int_field(rows[0], "trials", cid) != expected_counts[0]:
                fail(f"dynamic aggregate row/trial topology mismatch for {cid}")
        elif schema == "deletion-survival-csv-v1":
            if len(rows) != 3 or {row.get("r") for row in rows} != {"1", "4", "8"} or \
                    any(_int_field(row, "trials", cid) != expected_counts[0] for row in rows):
                fail(f"deletion survival topology mismatch for {cid}")


def verify_root(root: Path, *, mode: str, write_receipt: bool = False,
                lifecycle_stage: str = "complete") -> dict[str, Any]:
    root = _root(root)
    if mode not in {"toy", "dry-run", "paper", "post-seal"}:
        fail(f"unsupported verifier mode: {mode}")
    raw_manifest = load_json(root / "run.json", "run manifest")
    effective_mode = raw_manifest.get("mode") if mode == "post-seal" else mode
    if effective_mode not in {"toy", "dry-run", "paper"}:
        fail("sealed run has an unsupported mode")
    if mode == "post-seal":
        from seal_revision_benchmarks import verify_post_seal
        verify_post_seal(root)
        if write_receipt:
            fail("post-seal verification is read-only")
        lifecycle_stage = "complete" if effective_mode == "dry-run" else "sealed"
    manifest = _check_run_manifest(root, effective_mode)
    _, matrix_sha, cells = _check_matrix(root, manifest, effective_mode)
    expected_measured = sum(expected_row_count(cell, effective_mode) for cell in cells)
    if manifest.get("toy_measured_count") != expected_measured:
        fail("run measured-count summary does not match canonical cell rows")
    _check_source_and_tools(manifest, root, cells, effective_mode)
    _check_phases(root, manifest, stage=lifecycle_stage)
    plans = _check_plans(root, effective_mode, cells, manifest)
    _check_events(root, effective_mode, plans)
    _check_receipts(root, effective_mode, cells, plans)
    _check_family_taxonomy(cells)
    _check_family_artifacts(root, effective_mode, cells, plans)
    if mode == "post-seal":
        seal = load_json(root / "seal.json", "seal")
        if seal.get("readiness_status") != "READINESS_ONLY" or \
                seal.get("performance_status") != "PAPER_PERFORMANCE_PENDING":
            fail("post-seal toy status is not readiness-only")
        sums = root / "seal.json.sha256"
        if not sums.is_file() or sums.read_text(encoding="ascii") != \
                f"{sha256_file(root / 'seal.json')}  seal.json\n":
            fail("seal checksum mismatch")
    receipt = {
        "schema": VERIFICATION_SCHEMA, "version": 1, "verdict": "PASS",
        "mode": effective_mode, "results_root": str(root),
        "matrix_sha256": matrix_sha, "cell_count": len(cells),
        "cell_ids_sha256": __import__("hashlib").sha256(
            ("\n".join(cell["cell_id"] for cell in cells) + "\n").encode("ascii")
        ).hexdigest(),
        "phase_order": list(PHASES),
        "spawned_processes": manifest.get("spawned_processes"),
        "performance_status": manifest.get("performance_status"),
        "readiness_status": manifest.get("readiness_status"),
        "receipt_count": len(cells),
    }
    if write_receipt:
        verification = root / "verification"
        verification.mkdir(exist_ok=True)
        write_json(verification / "receipt.json", receipt)
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--mode", required=True,
                        choices=("toy", "dry-run", "paper", "post-seal"))
    parser.add_argument("--write-receipt", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        receipt = verify_root(Path(args.root), mode=args.mode,
                              write_receipt=args.write_receipt)
        print(f"revision verify: PASS ({receipt['cell_count']} cells)")
        return 0
    except (RevisionContractError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"verify_revision_benchmarks: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
