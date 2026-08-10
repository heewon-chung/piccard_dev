#!/usr/bin/env python3
"""Independent fail-closed verifier for Work #5 evidence roots.

The verifier has no mutation path.  In particular, it never repairs a hash,
fills in a terminal row, or converts an ERROR into a skip.  ``verification.json``
and ``SHA256SUMS`` are Phase-7 seal artifacts and are intentionally not made by
this Phase-3 verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

import run_work5_benchmarks as runner
import verify_review_comparison as review_verifier

SOURCE_ROOT = Path(__file__).resolve().parents[1]

RUNNER_SCHEMA = "piccard-work5-run-v1"
MATRIX_SCHEMA = "piccard-work5-matrix-v1"
DISCLAIMER = "single-trial implementation evidence; not a performance or ranking claim"
EXPECTED_KEY_SHA256 = "e51edfd36870410c48a0df5d2388c2e25e56b7c6dea65f33d76c213443cb435c"
AXES = ("k", "m", "n", "U")
STAGES = ("preflight_started", "context_started", "workload_started",
          "keygen_started", "measurement_started")
CONTROL = {"k": 128, "m": 64, "n": 1000, "U": 16384}
BFV_CAPS = {"realized_ring_dim": 32768, "provisioned_depth": 4,
            "log_q_bits": 240.0}
CONTEXT_LABELS = ("context_onehot", "context_sqrt", "context_fhe_ind")
PARAMETERS = {"k": (16, 32, 64, 128, 256, 512),
              "m": (16, 32, 64, 128, 256),
              "n": (100, 1000, 10000, 100000),
              "U": (16384, 65536)}
PROFILES = {"work5-std128-t40-single-trial": "STD128",
            "work5-std192-t40-single-trial": "STD192"}
SUITES = (
    ("work5-std128-piccard", "work5-std128-t40-single-trial", ("piccard", "piccard_sqrt"), ("k", "m", "n", "U")),
    ("work5-std128-fhe-ind", "work5-std128-t40-single-trial", ("fhe_ind",), ("n", "U")),
    ("work5-std128-bcg12-mh", "work5-std128-t40-single-trial", ("bcg12_mh_ec", "bcg12_mh_ff"), ("k", "n")),
    ("work5-std128-bcg12-exact", "work5-std128-t40-single-trial", ("bcg12_exact_ec", "bcg12_exact_ff"), ("n",)),
    ("work5-std128-sj16", "work5-std128-t40-single-trial", ("sj16",), ("n", "U")),
    ("work5-std192-piccard", "work5-std192-t40-single-trial", ("piccard", "piccard_sqrt"), ("k", "m", "n", "U")),
    ("work5-std192-fhe-ind", "work5-std192-t40-single-trial", ("fhe_ind",), ("n", "U")),
    ("work5-std192-sj16", "work5-std192-t40-single-trial", ("sj16",), ("n", "U")),
)
TAXONOMY: dict[str, dict[str, Any]] = {
    "piccard": {"primitive": "bfv-onehot-minhash", "protocol_model": "piccard-two-owner-outsourced", "comparison_scope": "end-to-end-estimator", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "piccard_sqrt": {"primitive": "bfv-sqrt-minhash", "protocol_model": "piccard-sqrt-two-owner-outsourced", "comparison_scope": "end-to-end-estimator", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "fhe_ind": {"primitive": "bfv-indicator-comparison", "protocol_model": "local-universe-sized-BFV-comparator", "comparison_scope": "diagnostic-only", "cost_scope": "primitive-only", "secure_division_included": False, "semantic_comparison_eligible": False},
    "bcg12_mh_ec": {"primitive": "bcg12-ec", "protocol_model": "bcg12-cardinality-on-minhash", "comparison_scope": "matched-estimator-component", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "bcg12_mh_ff": {"primitive": "bcg12-ff", "protocol_model": "bcg12-cardinality-on-minhash", "comparison_scope": "matched-estimator-component", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "bcg12_exact_ec": {"primitive": "bcg12-ec", "protocol_model": "bcg12-exact-cardinality", "comparison_scope": "matched-cardinality-component", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "bcg12_exact_ff": {"primitive": "bcg12-ff", "protocol_model": "bcg12-exact-cardinality", "comparison_scope": "matched-cardinality-component", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "sj16": {"primitive": "paillier-3072", "protocol_model": "sj16-intersection-shares", "comparison_scope": "component-lower-bound", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": {"STD128": True, "STD192": False}},
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read {label}: {exc}") from exc
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def expected_cells() -> list[dict[str, Any]]:
    cells: list[dict[str, Any]] = []
    for suite, profile, methods, applicable_axes in SUITES:
        base = {"cell_id": f"{suite}::control", "profile": profile, "suite": suite,
                "security": PROFILES[profile], "axis": "control", "axis_value": None,
                **CONTROL, "methods": list(methods),
                "applicability": {axis: axis in applicable_axes for axis in AXES},
                "profile_comparison_eligible": False}
        cells.append(base)
        for axis in applicable_axes:
            for value in PARAMETERS[axis]:
                if value == CONTROL[axis]:
                    continue
                cell = dict(base)
                cell.update({"cell_id": f"{suite}::{axis}={value}", "axis": axis,
                             "axis_value": value, axis: value})
                cells.append(cell)
    keys = []
    for cell in cells:
        marker = "|null" if cell["axis"] == "control" else ""
        keys.append(f"{cell['cell_id']}{marker}|k={cell['k']},m={cell['m']},n={cell['n']},U={cell['U']}")
    digest = hashlib.sha256((json.dumps(keys, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")).hexdigest()
    require(len(cells) == 61 and digest == EXPECTED_KEY_SHA256,
            "verifier frozen matrix is internally inconsistent")
    require(sum(cell["security"] == "STD128" for cell in cells) == 37 and
            sum(cell["security"] == "STD192" for cell in cells) == 24,
            "verifier frozen profile counts are inconsistent")
    return cells


def expected_taxonomy(methods: list[str], security: str) -> dict[str, dict[str, Any]]:
    result = {}
    for method in methods:
        item = dict(TAXONOMY[method])
        if isinstance(item["semantic_comparison_eligible"], dict):
            item["semantic_comparison_eligible"] = item["semantic_comparison_eligible"][security]
        result[method] = item
    return result


def relative_file(root: Path, value: Any, label: str) -> Path:
    require(isinstance(value, str) and value and not Path(value).is_absolute(),
            f"{label} path must be a non-empty relative path")
    candidate = (root / value).resolve(strict=False)
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise VerificationError(f"{label} path escapes root") from exc
    return candidate


def verify_artifacts(root: Path, record: dict[str, Any], *, test_fixture: bool) -> None:
    status = record["status"]
    piccard = bool(set(record["methods"]) & {"piccard", "piccard_sqrt"})
    fhe_ind = record["methods"] == ["fhe_ind"]
    context_ran = status != "ERROR" and bool(record.get("context_started")) and not test_fixture
    pairs = (("command", True), ("stdout", True), ("stderr", True),
             ("context_onehot", context_ran and piccard),
             ("context_sqrt", context_ran and piccard),
             ("context_fhe_ind", context_ran and fhe_ind),
             ("workload", status == "MEASURED"), ("trace", status == "MEASURED"),
             ("csv", status == "MEASURED"))
    for name, mandatory in pairs:
        path_value, digest = record.get(f"{name}_path"), record.get(f"{name}_sha256")
        require((path_value is None) == (digest is None),
                f"{record['cell_id']}: {name} path/hash pair mismatch")
        if mandatory:
            require(path_value is not None, f"{record['cell_id']}: missing {name} artifact")
        if path_value is None:
            continue
        require(isinstance(digest, str) and len(digest) == 64 and
                all(ch in "0123456789abcdef" for ch in digest),
                f"{record['cell_id']}: malformed {name} hash")
        path = relative_file(root, path_value, f"{record['cell_id']} {name}")
        require(path.is_file() and sha256_file(path) == digest,
                f"{record['cell_id']}: {name} artifact hash mismatch")
    if status == "SKIPPED_PRECHECK":
        require(all(record.get(f"{name}_path") is None for name in ("workload", "trace", "csv")),
                f"{record['cell_id']}: preflight skip has output artifact")
        if record.get("reason_code") in {"WORKLOAD_GEOMETRY", "PROJECTED_RUNTIME_CAP"}:
            require(all(record.get(f"{name}_path") is None for name in CONTEXT_LABELS),
                    f"{record['cell_id']}: pre-context skip has context artifact")
    if status == "ERROR":
        require(all(record.get(f"{name}_path") is None for name in (*CONTEXT_LABELS,
                                                                  "workload", "trace", "csv")),
                f"{record['cell_id']}: ERROR has leftover producer output")
    command_path = relative_file(root, record["command_path"], f"{record['cell_id']} command")
    command = load_object(command_path, "command artifact")
    require(command.get("schema") == "piccard-work5-command-v1" and
            command.get("cell_id") == record["cell_id"] and
            command.get("argv") == record["argv"] and
            command.get("environment") == record["environment"],
            f"{record['cell_id']}: command artifact does not bind record")


def source_provenance() -> dict[str, Any]:
    def git(*arguments: str) -> str:
        result = subprocess.run(["git", *arguments], cwd=SOURCE_ROOT, text=True,
                                capture_output=True, check=False)
        require(result.returncode == 0, "cannot read current source provenance")
        return result.stdout.strip()
    return {"git_sha": git("rev-parse", "HEAD"),
            "git_tree": git("rev-parse", "HEAD^{tree}"),
            "repository_root": str(Path(git("rev-parse", "--show-toplevel")).resolve()),
            "git_dirty": bool(git("status", "--porcelain=v1", "--untracked-files=no"))}


def results_root_digest(root: Path) -> str:
    return hashlib.sha256(canonical_json({"schema": "piccard-work5-results-root-v1",
                                          "results_root": str(root.resolve())})).hexdigest()


def verify_context(root: Path, run: dict[str, Any], record: dict[str, Any]) -> None:
    if record["status"] == "ERROR" or run.get("test_fixture_mode") or \
            not record.get("context_started") or \
            not set(record["methods"]) & {"piccard", "piccard_sqrt", "fhe_ind"}:
        return
    labels = (("context_fhe_ind", "fhe_ind", "piccard-work5-fhe-ind-context-preflight-v1"),) if \
        record["methods"] == ["fhe_ind"] else \
        (("context_onehot", "onehot", "piccard-work5-piccard-context-preflight-v1"),
         ("context_sqrt", "sqrt", "piccard-work5-piccard-context-preflight-v1"))
    breached_codes: set[str] = set()
    tuples: set[str] = set()
    for label, circuit, schema in labels:
        path = relative_file(root, record.get(f"{label}_path"), f"{record['cell_id']} {label}")
        value = load_object(path, "context preflight")
        require(value.get("schema") == schema and value.get("mode") == "work5-preflight" and
                value.get("keygen_started") is False and value.get("cell_id") == record["cell_id"] and
                value.get("security") == record["security"] and value.get("n") == record["n"] and
                value.get("universe") == record["U"] and value.get("source_commit") == run["git_sha"],
                f"{record['cell_id']}: context preflight identity mismatch")
        if circuit == "fhe_ind":
            require(value.get("method") == "fhe_ind" and
                    value.get("fhe_ind_binary_sha256") == run["executables"].get("bench_fhe_ind"),
                    f"{record['cell_id']}: FHE-IND context method/binary mismatch")
        else:
            require(value.get("circuit") == circuit and value.get("k") == record["k"] and
                    value.get("m") == record["m"] and
                    value.get("piccard_binary_sha256") ==
                    run["executables"].get("bench_std_security_evidence"),
                    f"{record['cell_id']}: Piccard context identity/binary mismatch")
        tuples.add(str(value.get("context_tuple_sha256")))
        try:
            breached = next((code for code, key, limit in
                             (("RING_DIM_CAP", "realized_ring_dim", BFV_CAPS["realized_ring_dim"]),
                              ("DEPTH_CAP", "provisioned_depth", BFV_CAPS["provisioned_depth"]),
                              ("LOGQ_CAP", "log_q_bits", BFV_CAPS["log_q_bits"]))
                             if float(value[key]) > limit), None)
        except (KeyError, TypeError, ValueError) as exc:
            raise VerificationError(f"{record['cell_id']}: context observed caps malformed") from exc
        require(bool(value.get("skipped")) == (breached is not None),
                f"{record['cell_id']}: context skip/cap mismatch")
        if breached:
            breached_codes.add(breached)
    if len(labels) == 2:
        require(len(tuples) == 2, f"{record['cell_id']}: onehot/sqrt contexts are not distinct")
    if record["status"] == "SKIPPED_PRECHECK" and record.get("reason_code") in {"RING_DIM_CAP", "DEPTH_CAP", "LOGQ_CAP"}:
        require(record["reason_code"] in breached_codes,
                f"{record['cell_id']}: cap skip is not observation-backed")


def verify_live_semantics(root: Path, record: dict[str, Any]) -> None:
    if record["status"] != "MEASURED":
        return
    csv_path = relative_file(root, record["csv_path"], f"{record['cell_id']} csv")
    workload_path = relative_file(root, record["workload_path"], f"{record['cell_id']} workload")
    trace_path = relative_file(root, record["trace_path"], f"{record['cell_id']} trace")
    try:
        _, rows = review_verifier.load_csv(csv_path, review_verifier.REVIEW_REQUIRED_COLUMNS)
        workload = review_verifier.parse_workload(workload_path)
        trace_digest = review_verifier.verify_trace(trace_path, workload)
        review_verifier.verify_rows(rows, workload, trace_digest)
        review_verifier.validate_rows(rows)
    except (review_verifier.VerificationError, OSError, ValueError) as exc:
        raise VerificationError(f"{record['cell_id']}: semantic producer verification failed: {exc}") from exc
    require((workload.suite, workload.profile, workload.root_seed, workload.k, workload.m,
             workload.set_size, workload.universe, list(workload.methods),
             workload.timing_trials, workload.accuracy_trials) ==
            (record["suite"], record["profile"], 7, record["k"], record["m"], record["n"],
             record["U"], record["methods"], 1, 1),
            f"{record['cell_id']}: parsed workload does not bind terminal cell")


def expected_stage_flags(status: str, reason: Any) -> dict[str, bool]:
    if status == "MEASURED":
        return dict(zip(STAGES, (True, True, True, True, True)))
    if status == "SKIPPED_PRECHECK":
        if reason in ("WORKLOAD_GEOMETRY", "PROJECTED_RUNTIME_CAP"):
            return dict(zip(STAGES, (True, False, False, False, False)))
        return dict(zip(STAGES, (True, True, False, False, False)))
    raise VerificationError("ERROR has no single fixed stage pattern")


def verify_status(record: dict[str, Any]) -> None:
    status = record.get("status")
    require(status in ("MEASURED", "SKIPPED_PRECHECK", "ERROR"),
            f"{record.get('cell_id')}: status is not terminal")
    flags = {name: record.get(name) for name in STAGES}
    require(all(isinstance(value, bool) for value in flags.values()),
            f"{record['cell_id']}: stage flags are not booleans")
    observed = tuple(flags[name] for name in STAGES)
    require(observed == tuple(sorted(observed, reverse=True)),
            f"{record['cell_id']}: stage flags are not monotonic")
    require(record.get("preflight_started") is True,
            f"{record['cell_id']}: terminal record lacks preflight")
    if status == "MEASURED":
        require(flags == expected_stage_flags(status, None) and record.get("exit_code") == 0 and
                record.get("measured_trials") == 1 and record.get("reason_code") is None and
                record.get("reason_detail") is None,
                f"{record['cell_id']}: MEASURED state invariant failed")
    elif status == "SKIPPED_PRECHECK":
        allowed = {"WORKLOAD_GEOMETRY", "RING_DIM_CAP", "DEPTH_CAP", "LOGQ_CAP", "PROJECTED_RUNTIME_CAP"}
        require(record.get("reason_code") in allowed and isinstance(record.get("reason_detail"), str) and
                bool(record["reason_detail"]) and record.get("exit_code") is None and
                record.get("measured_trials") == 0 and flags == expected_stage_flags(status, record["reason_code"]),
                f"{record['cell_id']}: SKIPPED_PRECHECK state invariant failed")
    else:
        require(record.get("reason_code") in {"TIMEOUT", "PHASE_CAP_EXHAUSTED", "SUBPROCESS_EXIT", "VERIFIER_FAILURE", "ARTIFACT_MISMATCH", "EXCEPTION"} and
                isinstance(record.get("reason_detail"), str) and bool(record["reason_detail"]) and
                isinstance(record.get("exit_code"), int) and record["exit_code"] != 0 and
                record.get("measured_trials") == 0,
                f"{record['cell_id']}: ERROR state invariant failed")


def workload_trial_payload(path: Path, target: dict[str, Any]) -> str:
    """Independently reconstruct the public TrialPayloadSha256 wire format."""
    data, offset = path.read_bytes(), 0

    def take(size: int) -> bytes:
        nonlocal offset
        require(size >= 0 and offset + size <= len(data), "truncated workload manifest")
        value = data[offset:offset + size]
        offset += size
        return value

    def u32() -> int:
        return int.from_bytes(take(4), "big")

    def u64() -> int:
        return int.from_bytes(take(8), "big")

    def string() -> str:
        try:
            return take(u32()).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError("non-UTF-8 workload string") from exc

    require(take(len(b"piccard-review-workload-v1\0")) == b"piccard-review-workload-v1\0",
            "workload domain mismatch")
    suite, profile = string(), string()
    root_seed, k, m, n, universe, target_num, target_den = (u64() for _ in range(7))
    methods = [string() for _ in range(u32())]
    timing_trials, accuracy_trials, record_count = u32(), u32(), u32()
    require((suite, profile, root_seed, k, m, n, universe, target_num, target_den, methods,
             timing_trials, accuracy_trials, record_count) ==
            (target["suite"], target["profile"], 7, target["k"], target["m"], target["n"], target["U"],
             1, 2, target["methods"], 1, 1, 3), "workload does not bind frozen cell")
    payload = bytearray(b"piccard-work5-trial-payload-v1\0")
    for _ in range(record_count):
        payload.extend(take(1 + 4 + 8 + 8))
        for _ in range(2):
            count_bytes = take(8)
            count = int.from_bytes(count_bytes, "big")
            require(count <= (len(data) - offset) // 8, "invalid workload set vector")
            payload.extend(count_bytes)
            payload.extend(take(count * 8))
        intersection_bytes, union_bytes = take(8), take(8)
        intersection, union = int.from_bytes(intersection_bytes, "big"), int.from_bytes(union_bytes, "big")
        divisor = math.gcd(intersection, union) if union else 1
        numerator, denominator = ((intersection // divisor, union // divisor) if union else (1, 1))
        payload.extend(intersection_bytes)
        payload.extend(union_bytes)
        payload.extend(numerator.to_bytes(8, "big"))
        payload.extend(denominator.to_bytes(8, "big"))
    require(offset == len(data), "trailing workload bytes")
    return hashlib.sha256(payload).hexdigest()


def verify_matrix(root: Path, run: dict[str, Any], expected: list[dict[str, Any]]) -> None:
    path = root / "matrix.json"
    require(path.is_file() and run.get("matrix_sha256") == sha256_file(path),
            "matrix hash mismatch")
    matrix = load_object(path, "matrix.json")
    require(matrix.get("schema") == MATRIX_SCHEMA and
            matrix.get("parameter_cell_key_sha256") == EXPECTED_KEY_SHA256 and
            matrix.get("parameter_cell_counts") == {"STD128": 37, "STD192": 24} and
            matrix.get("allowed_universes") == [16384, 65536] and
            matrix.get("excluded_universes") == [262144, 1048576],
            "matrix frozen bounds mismatch")
    require(matrix.get("trials") == {"timing_trials": 1, "accuracy_trials": 1,
                                      "executed_trials": 3},
            "matrix trial invariant mismatch")
    require(matrix.get("bfv_caps") == BFV_CAPS,
            "matrix BFV-cap admission bounds mismatch")
    admission = matrix.get("sj16_admission")
    require(isinstance(admission, dict) and admission.get("executed_trials") == 3 and
            admission.get("formula") == "executed_trials * (18.0 * (U + 1) + 60000.0)" and
            admission.get("threshold_ms") == 1800000.0 and
            admission.get("projected_cell_ms") == {"16384": 1064790.0, "65536": 3718998.0} and
            admission.get("calibration") == "not-run; deterministic admission guard only",
            "matrix SJ16 admission guard mismatch")
    source = admission.get("formula_source")
    require(source == "scripts/run_benchmarks.sh", "matrix SJ16 formula source mismatch")
    source_path = Path(__file__).resolve().parents[1] / source
    require(source_path.is_file() and admission.get("formula_source_sha256") == sha256_file(source_path),
            "matrix SJ16 formula source hash mismatch")
    observed = matrix.get("cells")
    require(isinstance(observed, list) and len(observed) == len(expected),
            "matrix cell count mismatch")
    for actual, target in zip(observed, expected):
        require(actual == target, "matrix cell membership/order mismatch")


def verify_run(root: Path, run: dict[str, Any]) -> None:
    require(run.get("schema") == RUNNER_SCHEMA and isinstance(run.get("created_at_utc"), str) and
            isinstance(run.get("source_root"), str) and isinstance(run.get("git_sha"), str) and
            isinstance(run.get("git_dirty"), bool) and run.get("build_type") == "Release",
            "run provenance schema mismatch")
    require(run.get("environment") == {"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"},
            "run OpenMP environment mismatch")
    require(run.get("trials") == 1 and run.get("accuracy_trials") == 1 and
            run.get("parameter_cell_executed_trials") == 3 and
            run.get("cell_timeout_seconds") == 1800 and run.get("disclaimer") == DISCLAIMER,
            "run single-trial invariant mismatch")
    require(isinstance(run.get("executables"), dict) and isinstance(run.get("scripts"), dict) and
            isinstance(run.get("command_template_sha256"), str) and len(run["command_template_sha256"]) == 64,
            "run provenance hashes missing")
    provenance = source_provenance()
    require(run.get("source_root") == str(SOURCE_ROOT.resolve()) and
            run.get("git_sha") == provenance["git_sha"] and
            run.get("git_tree") == provenance["git_tree"] and
            run.get("repository_root") == provenance["repository_root"] and
            run.get("git_dirty") == provenance["git_dirty"],
            "current/pinned source identity mismatch")
    require(run.get("results_root") == str(root.resolve()) and
            run.get("results_root_sha256") == results_root_digest(root),
            "canonical results-root identity mismatch")
    require(run.get("scripts") == runner.script_hashes(),
            "current script identity mismatch")
    require(run.get("command_template_sha256") == runner.command_template_sha256(),
            "command template identity mismatch")
    build_dir = Path(run.get("build_dir", ""))
    require(build_dir.is_absolute() and build_dir.is_dir(), "build directory identity is invalid")
    cache = build_dir / "CMakeCache.txt"
    require(run.get("build_identity") == {"cmake_cache_sha256": sha256_file(cache) if cache.is_file() else None},
            "build identity mismatch")
    test_fixture = bool(run.get("test_fixture_mode"))
    expected_names = set(runner.required_executable_names(test_fixture))
    require(set(run["executables"]) == expected_names and
            isinstance(run.get("executable_paths"), dict) and
            set(run["executable_paths"]) == expected_names,
            "executable identity key set mismatch")
    for name in sorted(expected_names):
        path = (build_dir / name).resolve()
        require(run["executable_paths"].get(name) == str(path) and path.is_file() and
                os.access(path, os.X_OK) and sha256_file(path) == run["executables"][name],
                f"executable identity mismatch: {name}")
    require(isinstance(run.get("cells_sha256"), str) and len(run["cells_sha256"]) == 64,
            "run terminal-record hash missing")
    completed = run.get("completed_phases")
    if test_fixture:
        require(completed == ["parameters"], "fixture root has an invalid completed-phase declaration")
    else:
        require(completed in (["toy"], ["toy", "parameters"]),
                "production root has an invalid completed-phase declaration")


def verify_toy(root: Path, run: dict[str, Any]) -> dict[str, Any]:
    """Verify the immutable, six-method toy smoke before the parameter matrix."""
    path = root / "toy.json"
    require(path.is_file() and run.get("toy_sha256") == sha256_file(path),
            "toy evidence hash is missing or mismatched")
    toy = load_object(path, "toy.json")
    expected = runner.TOY_CELL
    require(toy.get("schema") == "piccard-work5-toy-v1" and
            toy.get("cell_id") == expected["cell_id"] and
            all(toy.get(key) == expected[key] for key in
                ("suite", "profile", "security", "k", "m", "n", "U", "methods")) and
            toy.get("target_jaccard") == "0.5" and toy.get("seed") == 7 and
            toy.get("trials") == {"timing_trials": 1, "accuracy_trials": 1,
                                  "executed_trials": 3} and
            toy.get("status") == "MEASURED" and toy.get("reason_code") is None and
            toy.get("reason_detail") is None and toy.get("exit_code") == 0 and
            toy.get("environment") == {"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"} and
            isinstance(toy.get("started_at_utc"), str) and isinstance(toy.get("ended_at_utc"), str),
            "toy evidence contract mismatch")
    build_dir = Path(run["build_dir"])
    require(toy.get("argv") == runner.planned_toy_argv(build_dir, root),
            "toy argv is not the exact frozen producer command")
    labels = ("command", "stdout", "stderr", "workload", "trace", "csv")
    paths: dict[str, Path] = {}
    for label in labels:
        value, digest = toy.get(f"{label}_path"), toy.get(f"{label}_sha256")
        require(isinstance(digest, str) and len(digest) == 64,
                f"toy {label} artifact hash is malformed")
        artifact = relative_file(root, value, f"toy {label}")
        require(artifact.is_file() and sha256_file(artifact) == digest,
                f"toy {label} artifact hash mismatch")
        paths[label] = artifact
    command = load_object(paths["command"], "toy command artifact")
    require(command == {"schema": "piccard-work5-toy-command-v1", "cell_id": "toy-smoke",
                        "argv": toy["argv"], "environment": toy["environment"]},
            "toy command artifact does not bind the producer invocation")
    try:
        _, rows = review_verifier.load_csv(paths["csv"], review_verifier.REVIEW_REQUIRED_COLUMNS)
        workload = review_verifier.parse_workload(paths["workload"])
        trace_digest = review_verifier.verify_trace(paths["trace"], workload)
        review_verifier.verify_rows(rows, workload, trace_digest)
        review_verifier.validate_rows(rows)
    except (review_verifier.VerificationError, OSError, ValueError) as exc:
        raise VerificationError(f"toy semantic producer verification failed: {exc}") from exc
    require((workload.suite, workload.profile, workload.root_seed, workload.k, workload.m,
             workload.set_size, workload.universe, list(workload.methods),
             workload.timing_trials, workload.accuracy_trials) ==
            ("toy-smoke", "toy-smoke", 7, 16, 16, 10, 64, expected["methods"], 1, 1),
            "toy workload does not bind frozen configuration")
    require(all(record.intersection == 7 and record.union == 13 for record in workload.records),
            "toy workload exact intersection/union mismatch")
    require(toy.get("trial_payload_sha256") == workload_trial_payload(paths["workload"], expected),
            "toy TrialPayloadSha256 mismatch")
    return toy


def read_records(root: Path) -> list[dict[str, Any]]:
    path = root / "cells.jsonl"
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse cells.jsonl: {exc}") from exc
    require(all(isinstance(row, dict) for row in rows), "cells.jsonl row is not an object")
    return rows


def verify_records(root: Path, run: dict[str, Any], expected: list[dict[str, Any]]) -> None:
    require(run.get("cells_sha256") == sha256_file(root / "cells.jsonl"),
            "terminal record hash mismatch")
    records = read_records(root)
    require(len(records) == 61 and len({record.get("cell_id") for record in records}) == 61,
            "terminal record count or uniqueness mismatch")
    require(sum(record.get("security") == "STD128" for record in records) == 37 and
            sum(record.get("security") == "STD192" for record in records) == 24,
            "terminal profile totals mismatch")
    expected_payloads: dict[tuple[Any, ...], set[str]] = {}
    for actual, target in zip(records, expected):
        for field in ("cell_id", "profile", "suite", "security", "axis", "axis_value", "k", "m", "n", "U",
                      "methods", "applicability", "profile_comparison_eligible"):
            require(actual.get(field) == target[field],
                    f"{target['cell_id']}: frozen {field} mismatch")
        require(actual.get("target_jaccard") == "0.5" and actual.get("seed") == 7,
                f"{target['cell_id']}: target/seed mismatch")
        require(actual.get("taxonomy") == expected_taxonomy(target["methods"], target["security"]),
                f"{target['cell_id']}: taxonomy mismatch")
        payload = actual.get("trial_payload_sha256")
        require(isinstance(payload, str) and len(payload) == 64 and
                all(ch in "0123456789abcdef" for ch in payload),
                f"{target['cell_id']}: missing trial payload hash")
        require(actual.get("environment") == {"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"} and
                isinstance(actual.get("argv"), list) and actual["argv"],
                f"{target['cell_id']}: argv/environment mismatch")
        expected_argv = runner.planned_argv(Path(run["build_dir"]), root, target)
        require(actual["argv"] == expected_argv and actual["argv"][0] ==
                str((Path(run["build_dir"]) / "bench_review_comparison").resolve()),
                f"{target['cell_id']}: argv is not the exact frozen producer command")
        require(isinstance(actual.get("started_at_utc"), str) and isinstance(actual.get("ended_at_utc"), str),
                f"{target['cell_id']}: timestamps missing")
        verify_status(actual)
        verify_artifacts(root, actual, test_fixture=bool(run.get("test_fixture_mode")))
        verify_context(root, run, actual)
        if actual["status"] == "MEASURED" and not run.get("test_fixture_mode"):
            workload_path = relative_file(root, actual["workload_path"],
                                          f"{target['cell_id']} workload")
            require(payload == workload_trial_payload(workload_path, target),
                    f"{target['cell_id']}: TrialPayloadSha256 mismatch")
            verify_live_semantics(root, actual)
        key = (actual["security"], actual["axis"], actual["axis_value"], actual["k"], actual["m"],
               actual["n"], actual["U"], actual["target_jaccard"], actual["seed"])
        expected_payloads.setdefault(key, set()).add(payload)
    for key, digests in expected_payloads.items():
        matching = sum(1 for cell in expected if (cell["security"], cell["axis"], cell["axis_value"],
                   cell["k"], cell["m"], cell["n"], cell["U"], "0.5", 7) == key)
        if matching > 1:
            require(len(digests) == 1, f"trial payload hashes diverge for shared cell {key}")
    require(not any(record["status"] == "ERROR" for record in records),
            "parameter evidence contains ERROR terminal record")

    required_skips = {
        ("work5-std128-sj16", "U", 65536): "PROJECTED_RUNTIME_CAP",
        ("work5-std192-sj16", "U", 65536): "PROJECTED_RUNTIME_CAP",
    }
    for suite, _, _, axes in SUITES:
        if "n" in axes:
            required_skips[(suite, "n", 100000)] = "WORKLOAD_GEOMETRY"
    require(len(required_skips) == 10, "internal required skip count mismatch")
    found: set[tuple[str, str, int]] = set()
    for record in records:
        key = (record["suite"], record["axis"], record["axis_value"])
        if key in required_skips:
            found.add(key)
            require(record["status"] == "SKIPPED_PRECHECK" and
                    record["reason_code"] == required_skips[key] and
                    not record["keygen_started"] and not record["measurement_started"],
                    f"{record['cell_id']}: frozen preflight skip invariant failed")
    require(found == set(required_skips), "missing frozen preflight skip")

    if run.get("test_fixture_mode"):
        # Verify the sentinel is visibly non-evidence; a final seal below rejects it.
        for record in records:
            if record["status"] != "MEASURED":
                continue
            marker = (root / record["csv_path"]).read_bytes().splitlines()[0]
            require(marker == b"method,evidence_arm,status", "test fixture CSV marker mismatch")
    return records


def verify_inventory(root: Path, records: list[dict[str, Any]],
                     toy: dict[str, Any] | None) -> None:
    """Every on-disk artifact must be referenced exactly once by the lifecycle."""
    expected = {"run.json", "matrix.json", "cells.jsonl"}
    if toy is not None:
        expected.add("toy.json")
    owners: set[str] = set()
    if toy is not None:
        for name in ("command", "stdout", "stderr", "workload", "trace", "csv"):
            relative = toy.get(f"{name}_path")
            require(isinstance(relative, str) and relative not in owners,
                    f"toy artifact ownership is invalid: {name}")
            owners.add(relative)
            expected.add(relative)
    for record in records:
        for name in ("command", "stdout", "stderr", *CONTEXT_LABELS,
                     "workload", "trace", "csv"):
            relative = record.get(f"{name}_path")
            if relative is None:
                continue
            require(relative not in owners, f"artifact referenced by multiple terminal cells: {relative}")
            owners.add(relative)
            expected.add(relative)
    actual: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        require(not path.is_symlink(), f"symlinked artifact is forbidden: {relative}")
        if path.is_file():
            actual.add(relative)
    require(actual == expected, "artifact inventory has orphan, missing, or leftover producer output")


def verify_existing_seal(root: Path, run: dict[str, Any]) -> None:
    require(not run.get("test_fixture_mode"), "test fixture artifacts cannot be complete evidence")
    require(run.get("git_dirty") is False, "complete evidence requires a clean tracked tree")
    require(run.get("completed_phases") == ["toy", "parameters", "real", "dynamic"],
            "complete evidence is missing required phases")
    verification = root / "verification.json"
    sums = root / "SHA256SUMS"
    require(verification.is_file() and sums.is_file(), "complete evidence seal artifacts are missing")
    # SHA256SUMS uses exactly '<sha256><two spaces><relative path>' per line.
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        require(separator == "  " and len(digest) == 64 and relative,
                "malformed SHA256SUMS entry")
        path = relative_file(root, relative, "SHA256SUMS")
        require(path.is_file() and sha256_file(path) == digest,
                f"SHA256SUMS mismatch: {relative}")


def process(args: argparse.Namespace) -> int:
    root = Path(args.results_root).resolve()
    require(root.is_dir(), "results root does not exist")
    run = load_object(root / "run.json", "run.json")
    verify_run(root, run)
    if run.get("test_fixture_mode") and not args.allow_test_fixture:
        raise VerificationError("fixture-mode roots are not production evidence")
    if args.allow_test_fixture and not run.get("test_fixture_mode"):
        raise VerificationError("--allow-test-fixture is valid only for fixture-mode roots")
    expected = expected_cells()
    verify_matrix(root, run, expected)
    fixture = bool(run.get("test_fixture_mode"))
    if args.require_phase == "toy":
        require(not fixture and run.get("completed_phases") == ["toy"],
                "toy verification requires a production root sealed before parameters")
        toy = verify_toy(root, run)
        require(read_records(root) == [], "toy evidence has parameter terminal records")
        verify_inventory(root, [], toy)
        result_phase, terminal_cells = "toy", 0
    else:
        if args.require_phase and args.require_phase != "parameters":
            raise VerificationError(f"Phase-4 verifier cannot verify {args.require_phase!r} evidence")
        toy = None if fixture else verify_toy(root, run)
        records = verify_records(root, run, expected)
        verify_inventory(root, records, toy)
        result_phase, terminal_cells = "parameters", 61
    if args.require_complete:
        verify_existing_seal(root, run)
    print(json.dumps({"schema": "piccard-work5-verification-v1", "verdict": "PASS",
                      "phase": result_phase, "terminal_cells": terminal_cells,
                      "test_fixture_mode": bool(run.get("test_fixture_mode"))},
                     sort_keys=True))
    return 0


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_root")
    parser.add_argument("--require-phase", choices=("toy", "parameters", "real", "dynamic"))
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--allow-test-fixture", action="store_true",
                        help="test-only: inspect a root explicitly marked fixture mode")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    try:
        return process(parse_args(sys.argv[1:] if argv is None else argv))
    except VerificationError as exc:
        print(f"verify_work5_benchmarks: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
