#!/usr/bin/env python3
"""Independent fail-closed verifier for Work #5 evidence roots.

The verifier never repairs a hash, fills in a terminal row, or converts an
ERROR into a skip.  It can write one new phase receipt only after successful
verification when the caller supplies a phase-specific output path.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
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
EXPECTED_KEY_SHA256 = "b123e80e3a0e5bf6d599a18e637085c8cf26f14966ec362afb72707d7b2d8f9e"
AXES = ("k", "m", "n", "U")
STAGES = ("preflight_started", "context_started", "workload_started",
          "keygen_started", "measurement_started")
CONTROL = {"k": 128, "m": 64, "n": 1000, "U": 16384}
BFV_CAPS = {"realized_ring_dim": 32768, "provisioned_depth": 4,
            "log_q_bits": 240.0}
CONTEXT_LABELS = ("context_onehot", "context_sqrt", "context_fhe_ind")
CONTEXT_SPECS = {
    "context_onehot": ("onehot", "piccard-work5-piccard-context-preflight-v1"),
    "context_sqrt": ("sqrt", "piccard-work5-piccard-context-preflight-v1"),
    "context_fhe_ind": ("fhe_ind", "piccard-work5-fhe-ind-context-preflight-v1"),
}
DYNAMIC_CSV_FIELDS = frozenset({
    "label", "k", "m", "set_size", "depth", "trials", "hash_seed",
    "accuracy_trials", "profile_id", "run_class", "target_security_bits",
    "comparison_eligible", "measurement_kind", "dynamic_scenario",
    "updates_requested", "updates_applied", "initial_epoch", "final_epoch",
    "owner_b_unchanged", "ciphertext_upload_count", "local_inner_product",
    "decrypted_inner_product", "correctness_status", "refresh_owner_set_id",
    "refresh_updates", "refresh_epoch_before", "refresh_epoch_after",
    "refresh_status", "refresh_upload_bytes", "refresh_ciphertexts_uploaded",
})
PHASE_ORDERS = {
    "toy": ["toy"],
    "parameters": ["toy", "parameters"],
    "real": ["toy", "parameters", "real"],
    "dynamic": ["toy", "parameters", "real", "dynamic"],
}
PARAMETERS = {"k": (16, 32, 64, 128, 256, 512),
              "m": (16, 32, 64, 128, 256),
              "n": (100, 1000, 10000, 100000),
              "U": (16384, 65536)}
PROFILES = {"work5-std128-t40-single-trial": "STD128",
            "work5-std192-t40-single-trial": "STD192"}
# Match the runner's independent frozen definition: ordinary Piccard groups
# retain only the sqrt-supported m values, while the two unsupported sqrt
# shapes are Piccard-only cells sharing (but never copying) their control.
SUITES = (
    ("work5-std128-piccard", "work5-std128-t40-single-trial",
     ("piccard", "piccard_sqrt"), ("k", "m", "n", "U"),
     {"m": (16, 64, 256)}, True, None),
    ("work5-std128-piccard-m-extra", "work5-std128-t40-single-trial",
     ("piccard",), ("m",), {"m": (32, 128)}, False,
     "work5-std128-piccard::control"),
    ("work5-std128-fhe-ind", "work5-std128-t40-single-trial",
     ("fhe_ind",), ("n", "U"), {}, True, None),
    ("work5-std128-bcg12-mh", "work5-std128-t40-single-trial",
     ("bcg12_mh_ec", "bcg12_mh_ff"), ("k", "n"), {}, True, None),
    ("work5-std128-bcg12-exact", "work5-std128-t40-single-trial",
     ("bcg12_exact_ec", "bcg12_exact_ff"), ("n",), {}, True, None),
    ("work5-std128-sj16", "work5-std128-t40-single-trial",
     ("sj16",), ("n", "U"), {}, True, None),
    ("work5-std192-piccard", "work5-std192-t40-single-trial",
     ("piccard_encode", "piccard_sqrt_encode"), ("k", "m", "n", "U"),
     {"m": (16, 64, 256)}, True, None),
    ("work5-std192-piccard-m-extra", "work5-std192-t40-single-trial",
     ("piccard_encode",), ("m",), {"m": (32, 128)}, False,
     "work5-std192-piccard::control"),
    ("work5-std192-fhe-ind", "work5-std192-t40-single-trial",
     ("fhe_ind",), ("n", "U"), {}, True, None),
    ("work5-std192-sj16", "work5-std192-t40-single-trial",
     ("sj16",), ("n", "U"), {}, True, None),
)
TAXONOMY: dict[str, dict[str, Any]] = {
    "piccard": {"primitive": "bfv-onehot-minhash", "protocol_model": "piccard-two-owner-outsourced", "comparison_scope": "end-to-end-estimator", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "piccard_sqrt": {"primitive": "bfv-sqrt-minhash", "protocol_model": "piccard-sqrt-two-owner-outsourced", "comparison_scope": "end-to-end-estimator", "cost_scope": "full-query-excluding-one-time-setup", "secure_division_included": False, "semantic_comparison_eligible": True},
    "piccard_encode": {"primitive": "onehot-encoding", "protocol_model": "piccard-local-encoding", "comparison_scope": "encoding-only-diagnostic", "cost_scope": "encoding-only", "secure_division_included": False, "semantic_comparison_eligible": False},
    "piccard_sqrt_encode": {"primitive": "sqrt-encoding", "protocol_model": "piccard-sqrt-local-encoding", "comparison_scope": "encoding-only-diagnostic", "cost_scope": "encoding-only", "secure_division_included": False, "semantic_comparison_eligible": False},
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


def planned_payload_commitment(record: dict[str, Any]) -> str:
    """Independently reconstruct a skipped cell's legacy payload commitment.

    A preflight skip deliberately has no materialized ``ComparisonTrial``
    records.  Its legacy-named field is instead the runner's frozen
    ``piccard-work5-planned-payload-v1`` commitment.  Keep this serializer
    local to the verifier so a matching runner/verifier defect cannot bless a
    forged skip commitment.
    """
    material = {key: record[key] for key in ("security", "axis", "axis_value",
                                              "k", "m", "n", "U")}
    material.update({"target_jaccard": "0.5", "seed": 7, "executed_trials": 3})
    return hashlib.sha256(
        b"piccard-work5-planned-payload-v1\0" + canonical_json(material)
    ).hexdigest()


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read {label}: {exc}") from exc
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def expected_cells() -> list[dict[str, Any]]:
    cells: list[dict[str, Any]] = []
    definitions: dict[str, dict[str, Any]] = {}
    for suite, profile, methods, applicable_axes, overrides, owns_control, control_cell_id in SUITES:
        require(suite not in definitions and set(applicable_axes).issubset(AXES),
                "verifier suite definition is malformed")
        values = {axis: tuple(overrides.get(axis, PARAMETERS[axis])) for axis in applicable_axes}
        require(all(values[axis] and set(values[axis]).issubset(PARAMETERS[axis])
                    for axis in applicable_axes),
                "verifier suite domain is malformed")
        require(not (any(method in {"piccard_sqrt", "piccard_sqrt_encode"}
                         for method in methods) and
                     any(value not in {16, 64, 256} for value in values.get("m", ()))),
                "verifier sqrt domain is malformed")
        require(owns_control == (control_cell_id is None),
                "verifier control ownership is malformed")
        definitions[suite] = {"profile": profile, "methods": methods,
                              "applicable_axes": applicable_axes, "axis_values": values,
                              "owns_control": owns_control,
                              "control_cell_id": control_cell_id}
    for suite, details in definitions.items():
        if details["control_cell_id"] is not None:
            control_suite, separator, control_axis = details["control_cell_id"].partition("::")
            source = definitions.get(control_suite)
            require(separator == "::" and control_axis == "control" and source is not None and
                    source["owns_control"] and source["profile"] == details["profile"],
                    f"verifier shared control is malformed: {suite}")
        profile, methods, applicable_axes = (details["profile"], details["methods"],
                                              details["applicable_axes"])
        base = {"profile": profile, "suite": suite, "security": PROFILES[profile],
                **CONTROL, "methods": list(methods),
                "applicability": {axis: axis in applicable_axes for axis in AXES},
                "profile_comparison_eligible": False,
                "control_cell_id": details["control_cell_id"]}
        if details["owns_control"]:
            cells.append({"cell_id": f"{suite}::control", "axis": "control",
                          "axis_value": None, **base})
        for axis in applicable_axes:
            for value in details["axis_values"][axis]:
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


def expected_context_labels(methods: list[str]) -> tuple[str, ...]:
    """Freeze required context artifacts solely from the ordered method list."""
    if methods == ["fhe_ind"]:
        return ("context_fhe_ind",)
    labels: list[str] = []
    if "piccard" in methods:
        labels.append("context_onehot")
    if "piccard_sqrt" in methods:
        labels.append("context_sqrt")
    return tuple(labels)


def required_context_labels(record: dict[str, Any], *, test_fixture: bool) -> tuple[str, ...]:
    """Context must be absent before admission or in the explicitly fake mode."""
    if test_fixture or record["status"] == "ERROR" or not record.get("context_started"):
        return ()
    return expected_context_labels(record["methods"])


def verify_artifacts(root: Path, record: dict[str, Any], *, test_fixture: bool) -> None:
    status = record["status"]
    required_context = set(required_context_labels(record, test_fixture=test_fixture))
    pairs = (("command", True), ("stdout", True), ("stderr", True),
             *((label, label in required_context) for label in CONTEXT_LABELS),
             ("workload", status == "MEASURED"), ("trace", status == "MEASURED"),
             ("csv", status == "MEASURED"))
    for name, mandatory in pairs:
        path_value, digest = record.get(f"{name}_path"), record.get(f"{name}_sha256")
        require((path_value is None) == (digest is None),
                f"{record['cell_id']}: {name} path/hash pair mismatch")
        if name in CONTEXT_LABELS and name not in required_context:
            require(path_value is None,
                    f"{record['cell_id']}: forbidden {name} artifact is present")
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
    labels = required_context_labels(record, test_fixture=bool(run.get("test_fixture_mode")))
    if not labels:
        return
    breached_codes: set[str] = set()
    tuples: set[str] = set()
    for label in labels:
        circuit, schema = CONTEXT_SPECS[label]
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
        workload, _rows = review_verifier.verify_csv_artifacts(
            csv_path, workload_path, trace_path)
    except (review_verifier.VerificationError, OSError, ValueError) as exc:
        raise VerificationError(f"{record['cell_id']}: semantic producer verification failed: {exc}") from exc
    require((workload.suite, workload.profile, workload.root_seed, workload.k, workload.m,
             workload.set_size, workload.universe, list(workload.methods),
             workload.timing_trials, workload.accuracy_trials) ==
            (record["suite"], record["profile"], 7, record["k"], record["m"], record["n"],
             record["U"], record["methods"], 1, 1),
            f"{record['cell_id']}: parsed workload does not bind terminal cell")


def is_encoding_only_record(record: dict[str, Any]) -> bool:
    methods = record.get("methods")
    return (record.get("security") == "STD192" and isinstance(methods, list) and
            bool(methods) and set(methods) <= {"piccard_encode", "piccard_sqrt_encode"})


def expected_stage_flags(status: str, reason: Any,
                         record: dict[str, Any] | None = None) -> dict[str, bool]:
    if status == "MEASURED":
        if record is not None and is_encoding_only_record(record):
            return dict(zip(STAGES, (True, False, True, False, True)))
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
    if is_encoding_only_record(record):
        require(flags["context_started"] is False and flags["keygen_started"] is False,
                f"{record['cell_id']}: encoding-only cell entered context/keygen")
    else:
        require(observed == tuple(sorted(observed, reverse=True)),
                f"{record['cell_id']}: stage flags are not monotonic")
    require(record.get("preflight_started") is True,
            f"{record['cell_id']}: terminal record lacks preflight")
    if status == "MEASURED":
        require(flags == expected_stage_flags(status, None, record) and record.get("exit_code") == 0 and
                record.get("measured_trials") == 1 and record.get("reason_code") is None and
                record.get("reason_detail") is None,
                f"{record['cell_id']}: MEASURED state invariant failed")
    elif status == "SKIPPED_PRECHECK":
        allowed = {"WORKLOAD_GEOMETRY", "RING_DIM_CAP", "DEPTH_CAP", "LOGQ_CAP", "PROJECTED_RUNTIME_CAP"}
        require(record.get("reason_code") in allowed and isinstance(record.get("reason_detail"), str) and
                bool(record["reason_detail"]) and record.get("exit_code") is None and
                record.get("measured_trials") == 0 and flags == expected_stage_flags(status, record["reason_code"], record),
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


def phase_inventory_sha256(inventory: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(inventory)).hexdigest()


def verify_phase_inventories(root: Path, run: dict[str, Any]) -> None:
    """Validate each completed phase's local, hashed, non-overlapping files."""
    completed = run.get("completed_phases")
    inventories = run.get("phase_inventory")
    require(isinstance(completed, list) and isinstance(inventories, dict) and
            set(inventories) == set(completed),
            "phase inventory does not exactly match completed phases")
    seen: set[str] = set()
    for phase in completed:
        inventory = inventories.get(phase)
        require(isinstance(inventory, dict) and
                inventory.get("schema") == "piccard-work5-phase-inventory-v1" and
                inventory.get("phase") == phase and
                isinstance(inventory.get("artifacts"), list) and inventory["artifacts"] and
                isinstance(inventory.get("row_counts"), dict),
                f"{phase} phase inventory schema mismatch")
        paths: list[str] = []
        for artifact in inventory["artifacts"]:
            require(isinstance(artifact, dict) and set(artifact) == {"path", "sha256"},
                    f"{phase} phase inventory artifact schema mismatch")
            relative = artifact["path"]
            require(isinstance(relative, str) and relative not in paths,
                    f"{phase} phase inventory has duplicate artifact path")
            path = relative_file(root, relative, f"{phase} inventory artifact")
            require(path.is_file() and not path.is_symlink() and
                    isinstance(artifact["sha256"], str) and len(artifact["sha256"]) == 64 and
                    sha256_file(path) == artifact["sha256"],
                    f"{phase} phase inventory artifact hash mismatch: {relative}")
            paths.append(relative)
            require(relative not in seen,
                    f"phase inventory artifact belongs to multiple phases: {relative}")
            seen.add(relative)
        require(paths == sorted(paths), f"{phase} phase inventory artifact order is not canonical")
        if phase == "toy":
            require(inventory["row_counts"] == {"terminal_cells": 0, "measured": 1,
                                                "skipped": 0, "errors": 0},
                    "toy phase inventory row counts mismatch")
        elif phase == "parameters":
            counts = inventory["row_counts"]
            require(set(counts) == {"terminal_cells", "measured", "skipped", "errors"} and
                    all(isinstance(value, int) and value >= 0 for value in counts.values()) and
                    counts["terminal_cells"] == 61 and
                    counts["measured"] + counts["skipped"] + counts["errors"] == 61,
                    "parameter phase inventory row counts mismatch")
            if not run.get("test_fixture_mode"):
                require(counts == {"terminal_cells": 61, "measured": 49,
                                   "skipped": 12, "errors": 0},
                        "production parameter phase counts must be 49/12/0")
        elif phase == "real":
            require(inventory["row_counts"] == {"datasets": 1,
                                                "accuracy_rows": runner.REAL_PAIR_COUNT,
                                                "std128_timing_rows": 1,
                                                "std192_encoding_rows": 2,
                                                "errors": 0},
                    "real phase inventory row counts mismatch")
        elif phase == "dynamic":
            require(inventory["row_counts"] == {"correctness_rows": 2,
                                                "updates_1": 1,
                                                "updates_2": 1,
                                                "errors": 0},
                    "dynamic phase inventory row counts mismatch")


def verify_phase_inventory_membership(root: Path, run: dict[str, Any], phase: str,
                                      expected_paths: set[str]) -> None:
    inventory = run["phase_inventory"][phase]
    actual_paths = {artifact["path"] for artifact in inventory["artifacts"]}
    require(actual_paths == expected_paths,
            f"{phase} phase inventory does not bind its exact lifecycle artifacts")


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
        require(completed in (["toy"], ["toy", "parameters"],
                              ["toy", "parameters", "real"],
                              ["toy", "parameters", "real", "dynamic"]),
                "production root has an invalid completed-phase declaration")
    verify_phase_inventories(root, run)


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
    measured_payloads: dict[tuple[Any, ...], list[str]] = {}
    for actual, target in zip(records, expected):
        for field in ("cell_id", "profile", "suite", "security", "axis", "axis_value", "k", "m", "n", "U",
                      "methods", "applicability", "profile_comparison_eligible", "control_cell_id"):
            require(actual.get(field) == target[field],
                    f"{target['cell_id']}: frozen {field} mismatch")
        if target["control_cell_id"] is not None:
            require(not any(key.startswith("control_timing") for key in actual),
                    f"{target['cell_id']}: shared control timing copy is forbidden")
        require(actual.get("target_jaccard") == "0.5" and actual.get("seed") == 7,
                f"{target['cell_id']}: target/seed mismatch")
        require(actual.get("taxonomy") == expected_taxonomy(target["methods"], target["security"]),
                f"{target['cell_id']}: taxonomy mismatch")
        payload = actual.get("trial_payload_sha256")
        require(isinstance(payload, str) and len(payload) == 64 and
                all(ch in "0123456789abcdef" for ch in payload),
                f"{target['cell_id']}: missing trial payload hash")
        planned_commitment = planned_payload_commitment(actual)
        if actual["status"] == "SKIPPED_PRECHECK":
            require(payload == planned_commitment,
                    f"{target['cell_id']}: skip planned-payload commitment mismatch")
        elif actual["status"] == "MEASURED":
            require(payload != planned_commitment,
                    f"{target['cell_id']}: measured cell carries a skip commitment")
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
        if actual["status"] == "MEASURED":
            measured_payloads.setdefault(key, []).append(payload)
    for key, digests in measured_payloads.items():
        if len(digests) > 1:
            require(len(set(digests)) == 1,
                    f"trial payload hashes diverge for jointly measured cell {key}")
    require(not any(record["status"] == "ERROR" for record in records),
            "parameter evidence contains ERROR terminal record")
    if not run.get("test_fixture_mode"):
        require(sum(record["status"] == "MEASURED" for record in records) == 49 and
                sum(record["status"] == "SKIPPED_PRECHECK" for record in records) == 12,
                "production parameter matrix must contain exactly 49 measured and 12 skipped cells")

    required_skips = {
        ("work5-std128-sj16", "U", 65536): "PROJECTED_RUNTIME_CAP",
        ("work5-std192-sj16", "U", 65536): "PROJECTED_RUNTIME_CAP",
    }
    for suite, _, _, axes, _, _, _ in SUITES:
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


def verify_real(root: Path, run: dict[str, Any]) -> None:
    """Validate the real phase as a DBLP contract, never as a timing claim."""
    real_root = root / "real"
    require(real_root.is_dir() and not real_root.is_symlink(),
            "real phase directory is missing or unsafe")
    command_path = real_root / "commands.json"
    terminal_path = real_root / "terminal.json"
    require(command_path.is_file() and terminal_path.is_file(),
            "real phase command/terminal artifact is missing")
    commands = runner.planned_real_commands(Path(run["build_dir"]), root)
    expected_commands = [{"label": label, "argv": argv} for label, argv in commands]
    command = load_object(command_path, "real command artifact")
    require(command == {"schema": "piccard-work5-real-command-v1",
                        "commands": expected_commands,
                        "environment": {"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"}},
            "real command artifact does not bind the frozen producer argv")
    terminal = load_object(terminal_path, "real terminal artifact")
    require(terminal.get("schema") == "piccard-work5-real-terminal-v1" and
            terminal.get("status") == "MEASURED" and terminal.get("detail") == "PASS" and
            terminal.get("dataset") == runner.REAL_DATASET and
            terminal.get("variant") == runner.REAL_VARIANT and
            terminal.get("source_manifest") == str(runner.REAL_SOURCE_MANIFEST) and
            terminal.get("pairs") == runner.REAL_PAIR_COUNT and
            terminal.get("seed") == runner.REAL_SEED and terminal.get("threads") == runner.REAL_THREADS and
            terminal.get("profiles") == list(runner.REAL_PROFILES) and
            terminal.get("accuracy_trials") == 1 and terminal.get("timing_trials") == 1 and
            terminal.get("timing_pair") == "median" and
            terminal.get("commands") == expected_commands and
            isinstance(terminal.get("ended_at_utc"), str),
            "real terminal contract mismatch")
    for label, _argv in commands:
        require((real_root / f"{label}.stdout").is_file() and
                (real_root / f"{label}.stderr").is_file(),
                f"real {label} logs are missing")
    measurements = real_root / "measurements"
    processed = real_root / runner.REAL_VARIANT
    require(measurements.is_dir() and processed.is_dir() and
            (processed / "dataset.manifest.tsv").is_file(),
            "real processed dataset or measurement root is missing")
    try:
        import verify_real_dataset_outputs as real_verifier
        real_verifier.verify(measurements)
    except Exception as exc:  # noqa: BLE001 - every real verifier failure is terminal
        raise VerificationError(f"real dataset semantic verification failed: {exc}") from exc
    bad_path_words = ("context", "calibration", "keygen", "encrypt", "decrypt", "eval")
    for path in real_root.rglob("*"):
        require(not path.is_symlink(), "real phase contains a symlink")
        if path.is_file():
            require(not any(word in path.name.casefold() for word in bad_path_words),
                    "real phase contains a forbidden STD192 FHE artifact name")
    expected_paths = {path.relative_to(root).as_posix()
                      for path in real_root.rglob("*") if path.is_file()}
    verify_phase_inventory_membership(root, run, "real", expected_paths)


def _dynamic_canonical_integer(row: dict[str, str], key: str) -> int:
    """Parse one producer number without accepting alternate spellings."""
    value = row.get(key)
    require(isinstance(value, str) and value, f"dynamic CSV field is missing: {key}")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise VerificationError(f"dynamic CSV field is not an integer: {key}") from exc
    require(str(parsed) == value, f"dynamic CSV integer is not canonical: {key}")
    return parsed


def verify_dynamic_csv(path: Path, updates: int) -> None:
    """Independently verify one dynamic correctness row, never its timing.

    This code intentionally does not call the runner's producer-side CSV
    validator.  A matching producer/verifier defect must not turn a changed
    owner, epoch, upload, or plaintext/ciphertext result into a PASS.
    """
    require(updates in (1, 2), "dynamic verifier received an unfrozen update count")
    try:
        text = path.read_text(encoding="utf-8")
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = reader.fieldnames
        require(fieldnames is not None and len(fieldnames) == len(set(fieldnames)) and
                DYNAMIC_CSV_FIELDS.issubset(fieldnames),
                "dynamic CSV header misses frozen correctness fields")
        rows = list(reader)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise VerificationError(f"cannot parse dynamic CSV: {exc}") from exc
    require(len(rows) == 1 and None not in rows[0],
            "dynamic phase requires exactly one well-formed CSV row per update")
    row = rows[0]
    require(all(row.get(name) not in (None, "") for name in DYNAMIC_CSV_FIELDS),
            "dynamic CSV contains an empty frozen correctness field")
    expected_text = {
        "label": f"refresh_owner_a_0_to_{updates}", "k": "16", "m": "16",
        "set_size": "100", "depth": "5", "trials": "1", "hash_seed": "7",
        "accuracy_trials": "0", "profile_id": "toy-smoke", "run_class": "smoke",
        "target_security_bits": "0", "comparison_eligible": "false",
        "measurement_kind": "diagnostic", "dynamic_scenario": "refresh",
        "owner_b_unchanged": "true", "correctness_status": "PASS",
        "refresh_owner_set_id": "owner-a", "refresh_status": "applied",
    }
    require(all(row[name] == value for name, value in expected_text.items()),
            "dynamic CSV violates the frozen correctness/provenance contract")
    expected_numbers = {
        "updates_requested": updates, "updates_applied": updates,
        "initial_epoch": 0, "final_epoch": updates,
        "ciphertext_upload_count": updates, "refresh_updates": updates,
        "refresh_epoch_before": 0, "refresh_epoch_after": updates,
        "refresh_ciphertexts_uploaded": updates,
    }
    observed = {key: _dynamic_canonical_integer(row, key)
                for key in (*expected_numbers, "local_inner_product",
                            "decrypted_inner_product", "refresh_upload_bytes")}
    require(all(observed[key] == value for key, value in expected_numbers.items()),
            "dynamic CSV update/epoch/upload counters are inconsistent")
    require(observed["local_inner_product"] == observed["decrypted_inner_product"],
            "dynamic CSV local/decrypted inner products differ")
    require(observed["refresh_upload_bytes"] > 0,
            "dynamic CSV upload must contain one non-empty ciphertext")


def verify_dynamic(root: Path, run: dict[str, Any]) -> None:
    """Verify the terminal two-row TOY refresh correctness phase."""
    dynamic_root = root / "dynamic"
    require(dynamic_root.is_dir() and not dynamic_root.is_symlink(),
            "dynamic phase directory is missing or unsafe")
    command_path = dynamic_root / "commands.json"
    terminal_path = dynamic_root / "terminal.json"
    require(command_path.is_file() and terminal_path.is_file(),
            "dynamic phase command/terminal artifact is missing")
    commands = runner.planned_dynamic_commands(Path(run["build_dir"]), root)
    require(len(commands) == 2, "dynamic command count is not frozen")
    expected_commands = [{"label": label, "argv": argv} for label, argv in commands]
    command = load_object(command_path, "dynamic command artifact")
    require(command == {"schema": "piccard-work5-dynamic-command-v1",
                        "commands": expected_commands,
                        "environment": {"OMP_NUM_THREADS": "2", "OMP_DYNAMIC": "FALSE"}},
            "dynamic command artifact does not bind the frozen producer argv")
    terminal = load_object(terminal_path, "dynamic terminal artifact")
    require(terminal.get("schema") == "piccard-work5-dynamic-terminal-v1" and
            terminal.get("status") == "MEASURED" and terminal.get("detail") == "PASS" and
            terminal.get("scenario") == "refresh" and terminal.get("profile") == "toy-smoke" and
            terminal.get("security") == "TOY" and terminal.get("updates") == [1, 2] and
            terminal.get("trials") == 1 and terminal.get("measurement_kind") == "diagnostic" and
            terminal.get("commands") == expected_commands and
            isinstance(terminal.get("ended_at_utc"), str),
            "dynamic terminal contract mismatch")
    expected_paths = {"dynamic/commands.json", "dynamic/terminal.json"}
    for updates, (label, _argv) in zip((1, 2), commands):
        csv_path = dynamic_root / f"{label}.csv"
        stdout_path = dynamic_root / f"{label}.stdout"
        stderr_path = dynamic_root / f"{label}.stderr"
        require(csv_path.is_file() and stdout_path.is_file() and stderr_path.is_file() and
                not csv_path.is_symlink() and not stdout_path.is_symlink() and
                not stderr_path.is_symlink(),
                f"dynamic {label} CSV or logs are missing or unsafe")
        require(csv_path.read_bytes() == stdout_path.read_bytes(),
                f"dynamic {label} CSV must be the exact producer stdout")
        verify_dynamic_csv(csv_path, updates)
        expected_paths.update({f"dynamic/{label}.csv", f"dynamic/{label}.stdout",
                               f"dynamic/{label}.stderr"})
    observed_paths: set[str] = set()
    for path in dynamic_root.rglob("*"):
        require(not path.is_symlink(), "dynamic phase contains a symlink")
        if path.is_file():
            observed_paths.add(path.relative_to(root).as_posix())
    require(observed_paths == expected_paths,
            "dynamic phase contains an unexpected or missing artifact")
    verify_phase_inventory_membership(root, run, "dynamic", expected_paths)


def verify_inventory(root: Path, records: list[dict[str, Any]],
                     toy: dict[str, Any] | None, run: dict[str, Any]) -> None:
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
    for inventory in run["phase_inventory"].values():
        for artifact in inventory["artifacts"]:
            expected.add(artifact["path"])
    receipt_dir = root / "verification"
    if receipt_dir.exists():
        require(receipt_dir.is_dir() and not receipt_dir.is_symlink(),
                "verification receipt path is malformed")
        for receipt in receipt_dir.iterdir():
            require(receipt.is_file() and not receipt.is_symlink() and
                    receipt.suffix == ".json" and
                    receipt.stem in run["completed_phases"],
                    "verification receipt inventory is malformed")
            expected.add(receipt.relative_to(root).as_posix())
    for optional in ("verification.json", "SHA256SUMS"):
        if (root / optional).is_file():
            expected.add(optional)
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


def _expected_toy_inventory_paths(toy: dict[str, Any]) -> set[str]:
    return {"toy.json", *(toy[f"{name}_path"] for name in
                           ("command", "stdout", "stderr", "workload", "trace", "csv"))}


def _expected_parameter_inventory_paths(records: list[dict[str, Any]]) -> set[str]:
    paths = {"cells.jsonl"}
    for record in records:
        for name in ("command", "stdout", "stderr", *CONTEXT_LABELS,
                     "workload", "trace", "csv"):
            relative = record.get(f"{name}_path")
            if relative is not None:
                paths.add(relative)
    return paths


def _parse_expected_completed(value: str) -> list[str]:
    phases = value.split(",") if value else []
    require(phases and all(phase in PHASE_ORDERS for phase in phases) and
            len(phases) == len(set(phases)) and
            phases == PHASE_ORDERS.get(phases[-1]),
            "--expect-completed-phases must be one exact ordered lifecycle prefix")
    return phases


def write_receipt(root: Path, run: dict[str, Any], phase: str, output: Path,
                  terminal_cells: int) -> None:
    output = output.resolve(strict=False)
    expected = ((root / "verification.json").resolve() if phase == "complete" else
                (root / "verification" / f"{phase}.json").resolve())
    require(output.resolve(strict=False) == expected,
            "--verification-out must be the exact new path for this verified phase")
    try:
        output.resolve(strict=False).relative_to(root.resolve())
    except ValueError as exc:
        raise VerificationError("--verification-out escapes results root") from exc
    if output.parent.exists():
        require(output.parent.is_dir() and not output.parent.is_symlink(),
                "--verification-out parent is unsafe")
    else:
        require(output.parent == root / "verification",
                "--verification-out parent is not the canonical receipt directory")
    require(not output.exists() and not output.is_symlink(),
            "--verification-out already exists or is unsafe")
    inventory = (run["phase_inventory"].get(phase) if phase != "complete" else
                 {"schema": "piccard-work5-complete-inventory-v1",
                  "phases": run["completed_phases"]})
    require(isinstance(inventory, dict), "receipt phase inventory is missing")
    receipt = {
        "schema": "piccard-work5-verification-receipt-v1", "verdict": "PASS",
        "phase": phase, "results_root": str(root.resolve()),
        "run_sha256": sha256_file(root / "run.json"), "git_sha": run["git_sha"],
        "completed_phases": run["completed_phases"],
        "phase_inventory_sha256": phase_inventory_sha256(inventory),
        "terminal_cells": terminal_cells,
    }
    runner.atomic_write(output, canonical_json(receipt), new=True)


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
    requested_phase = args.require_phase
    # A complete seal must also independently traverse the final dynamic
    # phase; otherwise a valid four-phase declaration could bypass its own
    # correctness receipt checks by omitting --require-phase.
    if args.require_complete and requested_phase is None:
        requested_phase = "dynamic"
    if requested_phase == "toy":
        require(not fixture and run.get("completed_phases") == ["toy"],
                "toy verification requires a production root sealed before parameters")
        toy = verify_toy(root, run)
        require(read_records(root) == [], "toy evidence has parameter terminal records")
        verify_phase_inventory_membership(root, run, "toy", _expected_toy_inventory_paths(toy))
        verify_inventory(root, [], toy, run)
        result_phase, terminal_cells = "toy", 0
    else:
        if requested_phase and requested_phase not in ("parameters", "real", "dynamic"):
            raise VerificationError(f"verifier cannot verify {requested_phase!r} evidence")
        toy = None if fixture else verify_toy(root, run)
        records = verify_records(root, run, expected)
        if toy is not None:
            verify_phase_inventory_membership(root, run, "toy", _expected_toy_inventory_paths(toy))
        verify_phase_inventory_membership(root, run, "parameters",
                                          _expected_parameter_inventory_paths(records))
        if requested_phase == "dynamic":
            require(not fixture and run.get("completed_phases") == PHASE_ORDERS["dynamic"],
                    "dynamic verification requires the exact toy,parameters,real,dynamic lifecycle")
            verify_real(root, run)
            verify_dynamic(root, run)
            result_phase, terminal_cells = "dynamic", 61
        elif requested_phase == "real":
            require(not fixture and run.get("completed_phases") == PHASE_ORDERS["real"],
                    "real verification requires the exact toy,parameters,real lifecycle")
            verify_real(root, run)
            result_phase, terminal_cells = "real", 61
        else:
            require((fixture and run.get("completed_phases") == ["parameters"]) or
                    (not fixture and run.get("completed_phases") == PHASE_ORDERS["parameters"]),
                    "parameter verification requires the exact completed phase state")
            result_phase, terminal_cells = "parameters", 61
        verify_inventory(root, records, toy, run)
    if args.require_complete:
        verify_existing_seal(root, run)
        result_phase = "complete"
    if args.expect_git_sha is not None:
        require(args.expect_git_sha == run["git_sha"], "--expect-git-sha mismatch")
    if args.expect_completed_phases is not None:
        require(_parse_expected_completed(args.expect_completed_phases) == run["completed_phases"],
                "--expect-completed-phases mismatch")
    if args.verification_out is not None:
        write_receipt(root, run, result_phase, Path(args.verification_out), terminal_cells)
    result = {"schema": "piccard-work5-verification-v1", "verdict": "PASS",
              "phase": result_phase, "terminal_cells": terminal_cells,
              "test_fixture_mode": bool(run.get("test_fixture_mode"))}
    print(json.dumps(result, sort_keys=True))
    return 0


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_root")
    parser.add_argument("--require-phase", choices=("toy", "parameters", "real", "dynamic"))
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--expect-git-sha")
    parser.add_argument("--expect-completed-phases")
    parser.add_argument("--verification-out")
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
