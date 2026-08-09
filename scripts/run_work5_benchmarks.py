#!/usr/bin/env python3
"""Fail-closed Phase-3 lifecycle for the frozen Work #5 parameter matrix.

This file deliberately orchestrates evidence; it does not estimate a result,
retry a command, or manufacture a production measurement.  The only
implemented execution phase is ``parameters``.  The later toy/real/dynamic
phases have their own approved implementation work and are rejected here
before a results root is created.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


SOURCE_ROOT = Path(__file__).resolve().parents[1]
RUNNER_SCHEMA = "piccard-work5-run-v1"
MATRIX_SCHEMA = "piccard-work5-matrix-v1"
DISCLAIMER = "single-trial implementation evidence; not a performance or ranking claim"
TARGET_JACCARD = "0.5"
SEED = 7
THREADS = 2
TIMING_TRIALS = 1
ACCURACY_TRIALS = 1
EXECUTED_TRIALS = 3  # one discarded warmup, one timing, one accuracy trial
CELL_TIMEOUT_SECONDS = 1800
PARAMETER_TIMEOUT_SECONDS = 14400
SJ16_ADMISSION_CAP_MS = 1_800_000.0
BFV_CAPS = {"realized_ring_dim": 32768, "provisioned_depth": 4,
            "log_q_bits": 240.0}
AXES = ("k", "m", "n", "U")
STAGE_FLAGS = ("preflight_started", "context_started", "workload_started",
               "keygen_started", "measurement_started")
EXPECTED_KEY_SHA256 = "e51edfd36870410c48a0df5d2388c2e25e56b7c6dea65f33d76c213443cb435c"

CONTROL = {"k": 128, "m": 64, "n": 1000, "U": 16384}
PARAMETER_AXES = {
    "k": (16, 32, 64, 128, 256, 512),
    "m": (16, 32, 64, 128, 256),
    "n": (100, 1000, 10000, 100000),
    "U": (16384, 65536),
}
PROFILES = {
    "work5-std128-t40-single-trial": {"security": "STD128", "bits": 128},
    "work5-std192-t40-single-trial": {"security": "STD192", "bits": 192},
}
SUITES = (
    ("work5-std128-piccard", "work5-std128-t40-single-trial",
     ("piccard", "piccard_sqrt"), ("k", "m", "n", "U")),
    ("work5-std128-fhe-ind", "work5-std128-t40-single-trial",
     ("fhe_ind",), ("n", "U")),
    ("work5-std128-bcg12-mh", "work5-std128-t40-single-trial",
     ("bcg12_mh_ec", "bcg12_mh_ff"), ("k", "n")),
    ("work5-std128-bcg12-exact", "work5-std128-t40-single-trial",
     ("bcg12_exact_ec", "bcg12_exact_ff"), ("n",)),
    ("work5-std128-sj16", "work5-std128-t40-single-trial",
     ("sj16",), ("n", "U")),
    ("work5-std192-piccard", "work5-std192-t40-single-trial",
     ("piccard", "piccard_sqrt"), ("k", "m", "n", "U")),
    ("work5-std192-fhe-ind", "work5-std192-t40-single-trial",
     ("fhe_ind",), ("n", "U")),
    ("work5-std192-sj16", "work5-std192-t40-single-trial",
     ("sj16",), ("n", "U")),
)
TAXONOMY: dict[str, dict[str, Any]] = {
    "piccard": {"primitive": "bfv-onehot-minhash",
                "protocol_model": "piccard-two-owner-outsourced",
                "comparison_scope": "end-to-end-estimator",
                "cost_scope": "full-query-excluding-one-time-setup",
                "secure_division_included": False,
                "semantic_comparison_eligible": True},
    "piccard_sqrt": {"primitive": "bfv-sqrt-minhash",
                     "protocol_model": "piccard-sqrt-two-owner-outsourced",
                     "comparison_scope": "end-to-end-estimator",
                     "cost_scope": "full-query-excluding-one-time-setup",
                     "secure_division_included": False,
                     "semantic_comparison_eligible": True},
    "fhe_ind": {"primitive": "bfv-indicator-comparison",
                "protocol_model": "local-universe-sized-BFV-comparator",
                "comparison_scope": "diagnostic-only", "cost_scope": "primitive-only",
                "secure_division_included": False,
                "semantic_comparison_eligible": False},
    "bcg12_mh_ec": {"primitive": "bcg12-ec",
                    "protocol_model": "bcg12-cardinality-on-minhash",
                    "comparison_scope": "matched-estimator-component",
                    "cost_scope": "full-query-excluding-one-time-setup",
                    "secure_division_included": False,
                    "semantic_comparison_eligible": True},
    "bcg12_mh_ff": {"primitive": "bcg12-ff",
                    "protocol_model": "bcg12-cardinality-on-minhash",
                    "comparison_scope": "matched-estimator-component",
                    "cost_scope": "full-query-excluding-one-time-setup",
                    "secure_division_included": False,
                    "semantic_comparison_eligible": True},
    "bcg12_exact_ec": {"primitive": "bcg12-ec",
                       "protocol_model": "bcg12-exact-cardinality",
                       "comparison_scope": "matched-cardinality-component",
                       "cost_scope": "full-query-excluding-one-time-setup",
                       "secure_division_included": False,
                       "semantic_comparison_eligible": True},
    "bcg12_exact_ff": {"primitive": "bcg12-ff",
                       "protocol_model": "bcg12-exact-cardinality",
                       "comparison_scope": "matched-cardinality-component",
                       "cost_scope": "full-query-excluding-one-time-setup",
                       "secure_division_included": False,
                       "semantic_comparison_eligible": True},
    "sj16": {"primitive": "paillier-3072",
             "protocol_model": "sj16-intersection-shares",
             "comparison_scope": "component-lower-bound",
             "cost_scope": "full-query-excluding-one-time-setup",
             "secure_division_included": False,
             "semantic_comparison_eligible": {"STD128": True, "STD192": False}},
}


class Work5Error(RuntimeError):
    """A fail-closed lifecycle or provenance violation."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write(path: Path, data: bytes, *, new: bool = False) -> None:
    """Durably install ``data``; ``new`` is an atomic no-overwrite operation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if new:
            # link(2) is the no-replace half of temp+rename: unlike os.replace,
            # it cannot turn a terminal artifact into a new artifact.
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise Work5Error(f"refusing to overwrite existing artifact: {path}") from exc
            temporary.unlink()
        else:
            os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Work5Error(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise Work5Error(f"{label} must be a JSON object")
    return value


def git(*arguments: str) -> str:
    result = subprocess.run(["git", *arguments], cwd=SOURCE_ROOT, text=True,
                            capture_output=True, check=False)
    if result.returncode != 0:
        raise Work5Error(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def source_identity() -> tuple[str, bool]:
    # Untracked evidence is deliberately outside the source identity.  A final
    # evidence run still records a dirty tracked tree and cannot be sealed.
    return (git("rev-parse", "HEAD"),
            bool(git("status", "--porcelain=v1", "--untracked-files=no")))


def compiler_descriptor() -> dict[str, str]:
    compiler = os.environ.get("CXX", "c++")
    try:
        result = subprocess.run([compiler, "--version"], text=True,
                                capture_output=True, check=False, timeout=5)
        version = (result.stdout or result.stderr).splitlines()
        return {"path": compiler, "version": version[0] if result.returncode == 0 and version else "unavailable"}
    except (OSError, subprocess.TimeoutExpired):
        return {"path": compiler, "version": "unavailable"}


def host_descriptor() -> dict[str, Any]:
    try:
        memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, ValueError, OSError):
        memory = None
    return {"os": platform.platform(), "cpu": platform.machine(), "ram_bytes": memory}


def suite_definitions() -> dict[str, dict[str, Any]]:
    definitions: dict[str, dict[str, Any]] = {}
    for suite, profile, methods, axes in SUITES:
        definitions[suite] = {"profile": profile, "methods": list(methods),
                              "applicable_axes": tuple(axes),
                              "applicability": {axis: axis in axes for axis in AXES}}
    return definitions


def expanded_taxonomy(methods: list[str], security: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for method in methods:
        entry = dict(TAXONOMY[method])
        if isinstance(entry["semantic_comparison_eligible"], dict):
            entry["semantic_comparison_eligible"] = entry["semantic_comparison_eligible"][security]
        result[method] = entry
    return result


def cell_key(cell: dict[str, Any]) -> str:
    marker = "|null" if cell["axis"] == "control" else ""
    return (f"{cell['cell_id']}{marker}|k={cell['k']},m={cell['m']},"
            f"n={cell['n']},U={cell['U']}")


def frozen_cells() -> list[dict[str, Any]]:
    definitions = suite_definitions()
    cells: list[dict[str, Any]] = []
    for suite, details in definitions.items():
        profile = details["profile"]
        base = {"cell_id": f"{suite}::control", "profile": profile, "suite": suite,
                "security": PROFILES[profile]["security"], "axis": "control",
                "axis_value": None, **CONTROL,
                "methods": list(details["methods"]),
                "applicability": dict(details["applicability"]),
                "profile_comparison_eligible": False}
        cells.append(base)
        for axis in details["applicable_axes"]:
            for value in PARAMETER_AXES[axis]:
                if value == CONTROL[axis]:
                    continue
                cell = dict(base)
                cell["axis"] = axis
                cell["axis_value"] = value
                cell["cell_id"] = f"{suite}::{axis}={value}"
                cell[axis] = value
                cells.append(cell)
    keys = [cell_key(cell) for cell in cells]
    digest = sha256_bytes((json.dumps(keys, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii"))
    if len(cells) != 61 or digest != EXPECTED_KEY_SHA256:
        raise Work5Error("internal frozen Work #5 matrix does not match its digest")
    if sum(cell["security"] == "STD128" for cell in cells) != 37 or \
       sum(cell["security"] == "STD192" for cell in cells) != 24:
        raise Work5Error("internal Work #5 profile cell count mismatch")
    return cells


def projected_sj16_ms(universe: int) -> float:
    return EXECUTED_TRIALS * (18.0 * (universe + 1) + 60000.0)


def matrix_document(cells: list[dict[str, Any]]) -> dict[str, Any]:
    formula_source = SOURCE_ROOT / "scripts" / "run_benchmarks.sh"
    if not formula_source.is_file():
        raise Work5Error(f"missing SJ16 admission-source file: {formula_source}")
    return {
        "schema": MATRIX_SCHEMA,
        "parameter_cell_key_sha256": EXPECTED_KEY_SHA256,
        "parameter_cell_counts": {"STD128": 37, "STD192": 24},
        "allowed_universes": [16384, 65536],
        "excluded_universes": [262144, 1048576],
        "trials": {"timing_trials": TIMING_TRIALS,
                   "accuracy_trials": ACCURACY_TRIALS,
                   "executed_trials": EXECUTED_TRIALS},
        "bfv_caps": dict(BFV_CAPS),
        "sj16_admission": {
            "executed_trials": EXECUTED_TRIALS,
            "formula": "executed_trials * (18.0 * (U + 1) + 60000.0)",
            "formula_source": "scripts/run_benchmarks.sh",
            "formula_source_sha256": sha256_file(formula_source),
            "threshold_ms": SJ16_ADMISSION_CAP_MS,
            "projected_cell_ms": {"16384": projected_sj16_ms(16384),
                                  "65536": projected_sj16_ms(65536)},
            "calibration": "not-run; deterministic admission guard only",
        },
        "cells": [
            {key: cell[key] for key in ("cell_id", "profile", "suite", "security", "axis",
                                        "axis_value", "k", "m", "n", "U", "methods",
                                        "applicability", "profile_comparison_eligible")}
            for cell in cells
        ],
    }


def relative_artifact(root: Path, path: Path) -> str:
    try:
        relative = path.resolve(strict=False).relative_to(root.resolve())
    except ValueError as exc:
        raise Work5Error(f"artifact escapes results root: {path}") from exc
    if not relative.parts or ".." in relative.parts:
        raise Work5Error(f"invalid relative artifact path: {path}")
    return relative.as_posix()


def artifact_pair(root: Path, path: Path) -> tuple[str | None, str | None]:
    if not path.is_file():
        return None, None
    return relative_artifact(root, path), sha256_file(path)


def artifact_paths(root: Path, cell_id: str) -> dict[str, Path]:
    return {
        "command": root / "commands" / f"{cell_id}.json",
        "stdout": root / "logs" / f"{cell_id}.stdout",
        "stderr": root / "logs" / f"{cell_id}.stderr",
        "workload": root / "workloads" / f"{cell_id}.manifest.bin",
        "trace": root / "traces" / f"{cell_id}.trace.bin",
        "csv": root / "csv" / f"{cell_id}.csv",
    }


def planned_payload_sha256(cell: dict[str, Any]) -> str:
    """Bind skipped cells without attempting forbidden workload materialization.

    Geometry skips have no valid ``ComparisonTrial`` records: generating one
    would itself violate the no-workload-before-geometry rule.  Their required
    field is therefore a domain-separated planned-payload commitment.  Measured
    production cells replace it with the parsed C++ TrialPayloadSha256 value.
    """
    material = {key: cell[key] for key in ("security", "axis", "axis_value", "k", "m", "n", "U")}
    material.update({"target_jaccard": TARGET_JACCARD, "seed": SEED,
                     "executed_trials": EXECUTED_TRIALS})
    return sha256_bytes(b"piccard-work5-planned-payload-v1\0" + canonical_json(material))


def command_environment() -> dict[str, str]:
    return {"OMP_NUM_THREADS": str(THREADS), "OMP_DYNAMIC": "FALSE"}


def process_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(command_environment())
    return environment


def is_test_fixture_mode() -> bool:
    # The Phase-1 fixture exposes this one sentinel.  It is not a user-facing
    # option and final/sealed evidence rejects it in the independent verifier.
    return bool(os.environ.get("PICCARD_WORK5_FAKE_EVENT_LOG"))


def executable_map(build_dir: Path, *, test_fixture: bool) -> dict[str, str]:
    required = ("bench_review_comparison", "bench_fhe_ind", "bench_comparison")
    result: dict[str, str] = {}
    for name in required:
        path = build_dir / name
        if not path.is_file() or not os.access(path, os.X_OK):
            raise Work5Error(f"missing executable: {path}")
        result[name] = sha256_file(path)
    if not test_fixture:
        # It is the existing context-only API.  It is deliberately required
        # before a live BFV/indicator cell can reach workload or keygen.
        path = build_dir / "bench_std_security_evidence"
        if path.is_file() and os.access(path, os.X_OK):
            result["bench_std_security_evidence"] = sha256_file(path)
    return result


def planned_argv(build_dir: Path, root: Path, cell: dict[str, Any]) -> list[str]:
    paths = artifact_paths(root, cell["cell_id"])
    policy = "--allow-unmatched-security" if cell["suite"] == "work5-std192-sj16" \
        else "--diagnostic-security"
    return [
        str((build_dir / "bench_review_comparison").resolve()),
        f"--suite={cell['suite']}", f"--profile={cell['profile']}",
        f"--k={cell['k']}", f"--m={cell['m']}", f"--set-size={cell['n']}",
        f"--universe={cell['U']}", f"--target-jaccard={TARGET_JACCARD}",
        "--trials=1", "--accuracy-trials=1", "--seed=7",
        "--methods=" + ",".join(cell["methods"]), "--sj16-key-bits=3072", policy,
        f"--manifest-out={paths['workload']}",
        f"--execution-trace-out={paths['trace']}",
    ]


def write_command_and_logs(root: Path, cell: dict[str, Any], argv: list[str],
                           stdout: bytes = b"", stderr: bytes = b"") -> None:
    paths = artifact_paths(root, cell["cell_id"])
    if not paths["command"].exists():
        payload = {"schema": "piccard-work5-command-v1", "cell_id": cell["cell_id"],
                   "argv": argv, "environment": command_environment()}
        atomic_write(paths["command"], canonical_json(payload), new=True)
    if not paths["stdout"].exists():
        atomic_write(paths["stdout"], stdout, new=True)
    if not paths["stderr"].exists():
        atomic_write(paths["stderr"], stderr, new=True)


def update_logs(root: Path, cell: dict[str, Any], stdout: bytes, stderr: bytes) -> None:
    # The empty log files were atomically claimed before execution; replacing
    # their contents is safe because no terminal record exists yet.
    paths = artifact_paths(root, cell["cell_id"])
    atomic_write(paths["stdout"], stdout)
    atomic_write(paths["stderr"], stderr)


def stage_values(preflight: bool, context: bool, workload: bool, keygen: bool,
                 measurement: bool) -> dict[str, bool]:
    return dict(zip(STAGE_FLAGS, (preflight, context, workload, keygen, measurement)))


def record_for(root: Path, cell: dict[str, Any], argv: list[str], *, status: str,
               reason_code: str | None, reason_detail: str | None,
               flags: dict[str, bool], exit_code: int | None,
               started: str, trial_payload: str | None = None) -> dict[str, Any]:
    paths = artifact_paths(root, cell["cell_id"])
    record = {
        **{key: cell[key] for key in ("cell_id", "profile", "suite", "security", "axis",
                                      "axis_value", "k", "m", "n", "U", "methods",
                                      "applicability", "profile_comparison_eligible")},
        "target_jaccard": TARGET_JACCARD,
        "seed": SEED,
        "taxonomy": expanded_taxonomy(cell["methods"], cell["security"]),
        "trial_payload_sha256": trial_payload or planned_payload_sha256(cell),
        "status": status,
        "reason_code": reason_code,
        "reason_detail": reason_detail,
        **flags,
        "measured_trials": 1 if status == "MEASURED" else 0,
        "started_at_utc": started,
        "ended_at_utc": utc_now(),
        "argv": argv,
        "environment": command_environment(),
        "exit_code": exit_code,
    }
    for label in ("command", "stdout", "stderr", "workload", "trace", "csv"):
        path, digest = artifact_pair(root, paths[label])
        record[f"{label}_path"] = path
        record[f"{label}_sha256"] = digest
    return record


def write_cells(root: Path, records: list[dict[str, Any]]) -> None:
    ids = [record.get("cell_id") for record in records]
    if len(ids) != len(set(ids)):
        raise Work5Error("duplicate terminal cell record")
    payload = b"".join(canonical_json(record) for record in records)
    atomic_write(root / "cells.jsonl", payload)


def terminalize(root: Path, records: list[dict[str, Any]], record: dict[str, Any]) -> None:
    if any(existing["cell_id"] == record["cell_id"] for existing in records):
        raise Work5Error(f"terminal cell is immutable: {record['cell_id']}")
    records.append(record)
    write_cells(root, records)


def geometry_reason(cell: dict[str, Any]) -> str | None:
    # Same rounded rule as ComparisonWorkload::TargetIntersection for 1/2.
    intersection = (2 * cell["n"] * 1 + 3 // 2) // 3
    required_union = intersection + 2 * (cell["n"] - intersection)
    if required_union > cell["U"]:
        return (f"required_union={required_union} exceeds U={cell['U']} "
                f"for target_jaccard=1/2")
    return None


def forced_value(name: str, cell_id: str) -> str | None:
    configured = os.environ.get(name)
    selected = os.environ.get(name.replace("REASON", "CELL").replace("STAGE", "CELL"))
    return configured if configured and selected == cell_id else None


def context_preflight(build_dir: Path, root: Path, cell: dict[str, Any], *, test_fixture: bool) -> None:
    """Admit a BFV cell only after a context-only observation.

    The current public context-only probe is intentionally frozen to its
    diagnostic smoke geometry.  It cannot truthfully describe arbitrary Work
    #5 k/m/U configurations.  Consequently a live Phase-4 invocation fails
    before workload creation until a compatible public preflight API exists;
    that is the plan's explicit stop condition, not a hidden key-generation
    fallback.  The hermetic Phase-1 fake is allowed only to exercise the
    lifecycle state machine and never produces sealable evidence.
    """
    if test_fixture or not any(method in {"piccard", "piccard_sqrt", "fhe_ind"}
                               for method in cell["methods"]):
        return
    helper = build_dir / "bench_std_security_evidence"
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise Work5Error("context-only preflight executable is unavailable before keygen")
    raise Work5Error(
        "context-only preflight cannot bind this Work #5 cell to the existing "
        "smoke-only API; refusing workload/keygen")


def assert_fake_success(stdout: bytes) -> None:
    try:
        marker = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Work5Error(f"test fixture returned invalid marker: {exc}") from exc
    if marker != {"schema": "piccard-work5-test-command-v1", "status": "MEASURED"}:
        raise Work5Error("test fixture marker is not a measured command marker")


def write_test_artifacts(root: Path, cell: dict[str, Any]) -> str:
    """Create non-evidence sentinels solely for the hermetic Phase-1 fixture."""
    paths = artifact_paths(root, cell["cell_id"])
    payload = planned_payload_sha256(cell)
    atomic_write(paths["workload"],
                 ("piccard-work5-test-workload-v1\n" + payload + "\n").encode("ascii"), new=True)
    atomic_write(paths["trace"],
                 ("piccard-work5-test-trace-v1\n" + payload + "\n").encode("ascii"), new=True)
    rows = ["method,evidence_arm,status"]
    for method in cell["methods"]:
        rows.append(f"{method},timing,MEASURED")
        rows.append(f"{method},accuracy,MEASURED")
    atomic_write(paths["csv"], ("\n".join(rows) + "\n").encode("utf-8"), new=True)
    return payload


def note_test_dispatch(argv: list[str]) -> None:
    """Make timeout dispatch observable without treating it as a result.

    The fake executable normally writes this same shape after Python startup.
    A 50ms wall timeout can legitimately expire before that startup completes,
    so the fixture's event file also records the runner's dispatch boundary.
    This hook is unreachable without the test-only event-log environment.
    """
    value = os.environ.get("PICCARD_WORK5_FAKE_EVENT_LOG")
    if not value:
        return
    path = Path(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"argv": argv}, sort_keys=True) + "\n")
        stream.flush()


def validate_live_rows(path: Path, cell: dict[str, Any]) -> None:
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream, strict=True))
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise Work5Error(f"row verification failed: {exc}") from exc
    if not rows or not rows[0] or "method" not in rows[0] or "evidence_arm" not in rows[0]:
        raise Work5Error("row verification failed: missing method/evidence_arm CSV schema")
    expected = {(method, arm) for method in cell["methods"] for arm in ("timing", "accuracy")}
    observed = {(row.get("method"), row.get("evidence_arm")) for row in rows}
    if observed != expected or len(rows) != len(expected):
        raise Work5Error("row verification failed: method/arm membership is not frozen")
    for row in rows:
        if row.get("trials") != "1":
            raise Work5Error("row verification failed: aggregate trials are not one")
        if row.get("profile_id") != cell["profile"]:
            raise Work5Error("row verification failed: profile mismatch")
        if row.get("measurement_status") != "measured":
            raise Work5Error("row verification failed: row is not live measured output")


def trial_payload_sha256_from_workload(path: Path, cell: dict[str, Any]) -> str:
    """Parse the C++ manifest and reproduce TrialPayloadSha256 independently."""
    data = path.read_bytes()
    position = 0

    def take(size: int) -> bytes:
        nonlocal position
        if size < 0 or position + size > len(data):
            raise Work5Error("artifact mismatch: truncated workload manifest")
        value = data[position:position + size]
        position += size
        return value

    def u32() -> int:
        return int.from_bytes(take(4), "big")

    def u64() -> int:
        return int.from_bytes(take(8), "big")

    def string() -> str:
        length = u32()
        try:
            return take(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Work5Error("artifact mismatch: non-UTF-8 workload string") from exc

    domain = b"piccard-review-workload-v1\0"
    if take(len(domain)) != domain:
        raise Work5Error("artifact mismatch: workload domain")
    suite, profile = string(), string()
    values = [u64() for _ in range(7)]
    root_seed, k, m, set_size, universe, target_num, target_den = values
    method_count = u32()
    methods = [string() for _ in range(method_count)]
    timing_trials, accuracy_trials, record_count = u32(), u32(), u32()
    if (suite != cell["suite"] or profile != cell["profile"] or root_seed != SEED or
            (k, m, set_size, universe) != (cell["k"], cell["m"], cell["n"], cell["U"]) or
            (target_num, target_den) != (1, 2) or methods != cell["methods"] or
            (timing_trials, accuracy_trials, record_count) != (1, 1, 3)):
        raise Work5Error("artifact mismatch: workload does not bind frozen cell")
    payload = bytearray(b"piccard-work5-trial-payload-v1\0")
    for _ in range(record_count):
        payload.extend(take(1 + 4 + 8 + 8))
        for _ in range(2):
            count_bytes = take(8)
            count = int.from_bytes(count_bytes, "big")
            if count > (len(data) - position) // 8:
                raise Work5Error("artifact mismatch: invalid workload set vector")
            payload.extend(count_bytes)
            payload.extend(take(count * 8))
        intersection_bytes, union_bytes = take(8), take(8)
        intersection, union = int.from_bytes(intersection_bytes, "big"), int.from_bytes(union_bytes, "big")
        if union == 0:
            numerator, denominator = 1, 1
        else:
            divisor = math.gcd(intersection, union)
            numerator, denominator = intersection // divisor, union // divisor
        payload.extend(intersection_bytes)
        payload.extend(union_bytes)
        payload.extend(numerator.to_bytes(8, "big"))
        payload.extend(denominator.to_bytes(8, "big"))
    if position != len(data):
        raise Work5Error("artifact mismatch: trailing workload bytes")
    return sha256_bytes(bytes(payload))


def run_parameter_cell(build_dir: Path, root: Path, cell: dict[str, Any],
                       records: list[dict[str, Any]], *, test_fixture: bool,
                       timeout: float) -> None:
    started = utc_now()
    argv = planned_argv(build_dir, root, cell)
    flags = stage_values(True, False, False, False, False)
    # The command/log triplet is claimed before any terminal decision.  It is
    # retained even for a cheap skip, making the no-keygen decision auditable.
    write_command_and_logs(root, cell, argv)

    geometry = geometry_reason(cell)
    if geometry is not None:
        terminalize(root, records, record_for(
            root, cell, argv, status="SKIPPED_PRECHECK", reason_code="WORKLOAD_GEOMETRY",
            reason_detail=geometry, flags=flags, exit_code=None, started=started))
        return
    if cell["methods"] == ["sj16"] and projected_sj16_ms(cell["U"]) > SJ16_ADMISSION_CAP_MS:
        terminalize(root, records, record_for(
            root, cell, argv, status="SKIPPED_PRECHECK", reason_code="PROJECTED_RUNTIME_CAP",
            reason_detail=(f"projected_cell_ms={projected_sj16_ms(cell['U']):.1f} "
                           f"> cap_ms={SJ16_ADMISSION_CAP_MS:.1f}; executed_trials=3"),
            flags=flags, exit_code=None, started=started))
        return

    flags["context_started"] = True
    forced_precheck = forced_value("PICCARD_WORK5_TEST_FORCE_PRECHECK_REASON", cell["cell_id"])
    if forced_precheck is not None:
        if forced_precheck not in ("RING_DIM_CAP", "DEPTH_CAP", "LOGQ_CAP"):
            raise Work5Error(f"invalid test-only context precheck reason: {forced_precheck}")
        terminalize(root, records, record_for(
            root, cell, argv, status="SKIPPED_PRECHECK", reason_code=forced_precheck,
            reason_detail=f"test-only context observation admitted {forced_precheck}",
            flags=flags, exit_code=None, started=started))
        return

    forced_error = forced_value("PICCARD_WORK5_TEST_FORCE_ERROR_STAGE", cell["cell_id"])
    if forced_error == "pre_setup":
        terminalize(root, records, record_for(
            root, cell, argv, status="ERROR", reason_code="EXCEPTION",
            reason_detail="test-only injected pre-setup exception", flags=flags,
            exit_code=70, started=started))
        raise Work5Error("terminal ERROR at pre_setup")

    try:
        context_preflight(build_dir, root, cell, test_fixture=test_fixture)
        flags["workload_started"] = True
        flags["keygen_started"] = True
        if forced_error == "setup":
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="EXCEPTION",
                reason_detail="test-only injected setup exception", flags=flags,
                exit_code=70, started=started))
            raise Work5Error("terminal ERROR at setup")

        flags["measurement_started"] = True
        try:
            if test_fixture:
                note_test_dispatch(argv)
            completed = subprocess.run(argv, cwd=SOURCE_ROOT, env=process_environment(),
                                       capture_output=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, bytes) else (exc.stdout or "").encode()
            stderr = exc.stderr if isinstance(exc.stderr, bytes) else (exc.stderr or "").encode()
            update_logs(root, cell, stdout, stderr)
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="TIMEOUT",
                reason_detail=f"subprocess exceeded {timeout:g} seconds", flags=flags,
                exit_code=124, started=started))
            raise Work5Error("terminal ERROR/TIMEOUT")

        update_logs(root, cell, completed.stdout, completed.stderr)
        if completed.returncode != 0:
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="SUBPROCESS_EXIT",
                reason_detail=f"benchmark exited {completed.returncode}", flags=flags,
                exit_code=completed.returncode or 1, started=started))
            raise Work5Error("terminal ERROR/SUBPROCESS_EXIT")

        paths = artifact_paths(root, cell["cell_id"])
        if test_fixture:
            assert_fake_success(completed.stdout)
            payload = write_test_artifacts(root, cell)
        else:
            if not paths["workload"].is_file() or not paths["trace"].is_file():
                raise Work5Error("artifact mismatch: benchmark did not create workload/trace")
            validate_live_rows_from_bytes = completed.stdout
            # Validate before atomically installing the CSV representation.
            descriptor, temporary_name = tempfile.mkstemp(prefix=".work5-rows-", suffix=".csv")
            os.close(descriptor)
            temporary_csv = Path(temporary_name)
            try:
                temporary_csv.write_bytes(validate_live_rows_from_bytes)
                validate_live_rows(temporary_csv, cell)
            finally:
                try:
                    temporary_csv.unlink()
                except FileNotFoundError:
                    pass
            atomic_write(paths["csv"], validate_live_rows_from_bytes, new=True)
            payload = trial_payload_sha256_from_workload(paths["workload"], cell)
        terminalize(root, records, record_for(
            root, cell, argv, status="MEASURED", reason_code=None, reason_detail=None,
            flags=flags, exit_code=0, started=started, trial_payload=payload))
    except Work5Error as exc:
        if not any(record["cell_id"] == cell["cell_id"] for record in records):
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="EXCEPTION",
                reason_detail=str(exc), flags=flags, exit_code=70, started=started))
        raise
    except BaseException as exc:
        # Signal/exception handling must leave exactly one immutable terminal.
        if not any(record["cell_id"] == cell["cell_id"] for record in records):
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="EXCEPTION",
                reason_detail=f"{type(exc).__name__}: {exc}", flags=flags,
                exit_code=130 if isinstance(exc, KeyboardInterrupt) else 70,
                started=started))
        raise Work5Error(f"terminal ERROR/EXCEPTION: {type(exc).__name__}") from exc


def validate_record_artifacts(root: Path, record: dict[str, Any]) -> None:
    for name in ("command", "stdout", "stderr", "workload", "trace", "csv"):
        path_value, digest = record.get(f"{name}_path"), record.get(f"{name}_sha256")
        if (path_value is None) != (digest is None):
            raise Work5Error(f"resume artifact pair mismatch: {record.get('cell_id')} {name}")
        if path_value is None:
            continue
        if not isinstance(path_value, str) or Path(path_value).is_absolute() or ".." in Path(path_value).parts:
            raise Work5Error(f"resume artifact path is unsafe: {record.get('cell_id')} {name}")
        path = (root / path_value).resolve(strict=False)
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise Work5Error("resume artifact path escapes root") from exc
        if not path.is_file() or digest != sha256_file(path):
            raise Work5Error(f"resume artifact hash mismatch: {record.get('cell_id')} {name}")


def read_records(root: Path) -> list[dict[str, Any]]:
    path = root / "cells.jsonl"
    if not path.exists():
        return []
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Work5Error(f"cannot read terminal records: {exc}") from exc
    if not all(isinstance(row, dict) for row in rows):
        raise Work5Error("terminal records must be JSON objects")
    if len({row.get("cell_id") for row in rows}) != len(rows):
        raise Work5Error("resume has duplicate terminal records")
    for row in rows:
        validate_record_artifacts(root, row)
    return rows


def resume_validate(root: Path, build_dir: Path, executable_hashes: dict[str, str],
                    matrix: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = read_json(root / "run.json", "run.json")
    if run.get("schema") != RUNNER_SCHEMA:
        raise Work5Error("resume run schema mismatch")
    source_sha, dirty = source_identity()
    if run.get("git_sha") != source_sha or run.get("git_dirty") != dirty:
        raise Work5Error("resume source SHA/dirty identity mismatch")
    if run.get("build_dir") != str(build_dir) or run.get("executables") != executable_hashes:
        raise Work5Error("resume binary hash identity mismatch")
    if run.get("scripts") != script_hashes():
        raise Work5Error("resume script hash identity mismatch")
    if run.get("environment") != command_environment() or \
       run.get("command_template_sha256") != command_template_sha256():
        raise Work5Error("resume command/environment identity mismatch")
    matrix_path = root / "matrix.json"
    if not matrix_path.is_file() or run.get("matrix_sha256") != sha256_file(matrix_path):
        raise Work5Error("resume matrix hash mismatch")
    if read_json(matrix_path, "matrix.json") != matrix:
        raise Work5Error("resume matrix semantic mismatch")
    records = read_records(root)
    cells_path = root / "cells.jsonl"
    if run.get("cells_sha256") != sha256_file(cells_path):
        raise Work5Error("resume terminal-record hash mismatch")
    expected_ids = {cell["cell_id"] for cell in frozen_cells()}
    if any(record.get("cell_id") not in expected_ids for record in records):
        raise Work5Error("resume contains terminal record outside frozen matrix")
    return run, records


def command_template_sha256() -> str:
    template = {"producer": "bench_review_comparison", "argv": [
        "--suite", "--profile", "--k", "--m", "--set-size", "--universe",
        "--target-jaccard=0.5", "--trials=1", "--accuracy-trials=1", "--seed=7",
        "--methods", "--sj16-key-bits=3072", "security-policy", "--manifest-out",
        "--execution-trace-out"], "no_shell": True}
    return sha256_bytes(canonical_json(template))


def script_hashes() -> dict[str, str]:
    return {"run_work5_benchmarks.py": sha256_file(Path(__file__)),
            "verify_work5_benchmarks.py": sha256_file(
                SOURCE_ROOT / "scripts" / "verify_work5_benchmarks.py")}


def initial_run(build_dir: Path, executable_hashes: dict[str, str], matrix_sha: str,
                *, test_fixture: bool) -> dict[str, Any]:
    source_sha, dirty = source_identity()
    return {
        "schema": RUNNER_SCHEMA,
        "created_at_utc": utc_now(), "source_root": str(SOURCE_ROOT.resolve()),
        "git_sha": source_sha, "git_dirty": dirty, "build_type": "Release",
        "build_dir": str(build_dir), "compiler": compiler_descriptor(),
        "openfhe_version": os.environ.get("PICCARD_OPENFHE_VERSION", "recorded-by-live-producer"),
        "host": host_descriptor(), "environment": command_environment(),
        "executables": executable_hashes,
        "scripts": script_hashes(),
        "matrix_sha256": matrix_sha, "command_template_sha256": command_template_sha256(),
        "trials": TIMING_TRIALS, "accuracy_trials": ACCURACY_TRIALS,
        "parameter_cell_executed_trials": EXECUTED_TRIALS,
        "cell_timeout_seconds": CELL_TIMEOUT_SECONDS,
        "phase_timeout_seconds": {"parameters": PARAMETER_TIMEOUT_SECONDS,
                                  "real": 7200, "dynamic": 600},
        "disclaimer": DISCLAIMER, "test_fixture_mode": test_fixture,
        "completed_phases": [], "cells_sha256": None,
    }


def validate_new_root(root: Path, resume: bool) -> None:
    if not root.is_absolute():
        raise Work5Error("--results-root must be absolute")
    if root.exists() and not resume:
        raise Work5Error("results root already exists; use --resume only for validated state")
    if resume and not root.is_dir():
        raise Work5Error("--resume requires an existing results root")
    resolved = root.resolve(strict=False)
    source = SOURCE_ROOT.resolve()
    try:
        resolved.relative_to(source)
    except ValueError:
        return
    # The approved path is normally .omo/evidence/work5-single-trial/... in
    # this checkout.  Permit only a new descendant there, never an arbitrary
    # source-tree path that could collide with tracked input or code.
    evidence_root = (source / ".omo" / "evidence").resolve(strict=False)
    try:
        relative = resolved.relative_to(evidence_root)
    except ValueError as exc:
        raise Work5Error("an in-worktree --results-root must be under .omo/evidence") from exc
    if not relative.parts:
        raise Work5Error("--results-root must name a new evidence-run directory")


def process(args: argparse.Namespace) -> int:
    build_dir = Path(args.build_dir).resolve()
    root = Path(args.results_root).resolve()
    validate_new_root(root, args.resume)
    if args.phase != "parameters":
        raise Work5Error(f"Phase 3 implements only --phase=parameters; {args.phase!r} is not live yet")
    test_fixture = is_test_fixture_mode()
    executable_hashes = executable_map(build_dir, test_fixture=test_fixture)
    cells = frozen_cells()
    matrix = matrix_document(cells)
    if args.resume:
        run, records = resume_validate(root, build_dir, executable_hashes, matrix)
    else:
        root.mkdir(parents=True)
        for directory in ("commands", "logs", "csv", "workloads", "traces", "real", "dynamic"):
            (root / directory).mkdir(exist_ok=False)
        matrix_path = root / "matrix.json"
        atomic_write(matrix_path, canonical_json(matrix), new=True)
        run = initial_run(build_dir, executable_hashes, sha256_file(matrix_path), test_fixture=test_fixture)
        atomic_write(root / "run.json", canonical_json(run), new=True)
        records = []
        write_cells(root, records)
        run["cells_sha256"] = sha256_file(root / "cells.jsonl")
        atomic_write(root / "run.json", canonical_json(run))

    expected_by_id = {cell["cell_id"]: cell for cell in cells}
    terminal_ids = {record["cell_id"] for record in records}
    for cell_id, cell in expected_by_id.items():
        if cell_id in terminal_ids:
            continue
        # A crash before the terminal append may leave an unbound artifact.
        # Treat that as incompatible resume state rather than silently running
        # the cell again and potentially overwriting its first attempt.
        if args.resume and any(path.exists() for path in artifact_paths(root, cell_id).values()):
            raise Work5Error(f"resume has unbound artifacts for PENDING cell: {cell_id}")

    timeout = float(os.environ.get("PICCARD_WORK5_TEST_CELL_TIMEOUT_SECONDS", CELL_TIMEOUT_SECONDS))
    if timeout <= 0:
        raise Work5Error("cell timeout must be positive")
    deadline = time.monotonic() + PARAMETER_TIMEOUT_SECONDS
    for cell in cells:
        if cell["cell_id"] in terminal_ids:
            continue  # terminal records are immutable and never rerun
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            started = utc_now()
            argv = planned_argv(build_dir, root, cell)
            write_command_and_logs(root, cell, argv)
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="TIMEOUT",
                reason_detail=f"parameter phase exceeded {PARAMETER_TIMEOUT_SECONDS} seconds",
                flags=stage_values(True, False, False, False, False), exit_code=124,
                started=started))
            raise Work5Error("terminal ERROR/TIMEOUT: parameter phase cap")
        run_parameter_cell(build_dir, root, cell, records, test_fixture=test_fixture,
                           timeout=min(timeout, remaining))
        terminal_ids.add(cell["cell_id"])
        run["cells_sha256"] = sha256_file(root / "cells.jsonl")
        atomic_write(root / "run.json", canonical_json(run))

    if len(records) != len(cells):
        raise Work5Error("parameter phase ended with PENDING cells")
    if any(record["status"] == "ERROR" for record in records):
        raise Work5Error("parameter phase contains terminal ERROR")
    if "parameters" not in run["completed_phases"]:
        run["completed_phases"].append("parameters")
        atomic_write(root / "run.json", canonical_json(run))
    return 0


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--threads", type=int, default=THREADS)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--phase", choices=("toy", "parameters", "real", "dynamic", "all"),
                        default="parameters")
    args = parser.parse_args(list(argv))
    if args.seed != SEED:
        parser.error("--seed is frozen at 7")
    if args.threads != THREADS:
        parser.error("--threads is frozen at 2")
    if not Path(args.build_dir).is_absolute():
        parser.error("--build-dir must be absolute")
    if not Path(args.results_root).is_absolute():
        parser.error("--results-root must be absolute")
    return args


def main(argv: Iterable[str] | None = None) -> int:
    try:
        return process(parse_args(sys.argv[1:] if argv is None else argv))
    except Work5Error as exc:
        print(f"run_work5_benchmarks: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
