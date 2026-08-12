#!/usr/bin/env python3
"""Fail-closed lifecycle for the executed Work #5 evidence phases.

This file deliberately orchestrates evidence; it does not estimate a result,
retry a command, or manufacture a production measurement.  The toy smoke is
recorded and independently verifiable before the production parameter matrix
may be resumed in the same evidence root.  The real phase is source-bound to
the DBLP-ACM single-trial contract, and the bounded dynamic correctness path.
"""

from __future__ import annotations

import argparse
import csv
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import math
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import verify_review_comparison as review_verifier


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
REAL_PHASE_TIMEOUT_SECONDS = 7200
SJ16_ADMISSION_CAP_MS = 1_800_000.0
BFV_CAPS = {"realized_ring_dim": 32768, "provisioned_depth": 4,
            "log_q_bits": 240.0}
AXES = ("k", "m", "n", "U")
STAGE_FLAGS = ("preflight_started", "context_started", "workload_started",
               "keygen_started", "measurement_started")
EXPECTED_KEY_SHA256 = "b123e80e3a0e5bf6d599a18e637085c8cf26f14966ec362afb72707d7b2d8f9e"

REAL_DATASET = "dblp_acm"
REAL_VARIANT = "dblp_acm_u65536"
REAL_SOURCE_MANIFEST = (SOURCE_ROOT / "datasets" / "manifests" /
                        "dblp_acm.source.tsv").resolve()
REAL_SEED = 20260729
REAL_THREADS = 2
REAL_PAIR_COUNT = 10000
REAL_PROFILES = ("work5-std128-t40-single-trial",
                 "work5-std192-t40-single-trial")

DYNAMIC_PROFILE = "toy-smoke"
DYNAMIC_SECURITY = "TOY"
DYNAMIC_UPDATES = (1, 2)
DYNAMIC_K = 16
DYNAMIC_M = 16
DYNAMIC_SET_SIZE = 100
DYNAMIC_DEPTH = 5

CONTROL = {"k": 128, "m": 64, "n": 1000, "U": 16384}
TOY_CELL = {
    "cell_id": "toy-smoke",
    "suite": "toy-smoke",
    "profile": "toy-smoke",
    "security": "TOY",
    "k": 16,
    "m": 16,
    "n": 10,
    "U": 64,
    "methods": ["piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
                "bcg12_exact_ec", "sj16"],
}
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
# Each entry freezes: suite, profile, methods, applicable axes, per-axis values,
# whether the suite owns a control cell, and an optional shared control reference.
# The sqrt encoding accepts only even log2(m), so m=32 and m=128 are Piccard-only
# cells in their dedicated suites.  Their reference binds the comparison baseline
# without importing or copying a measured timing value.
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
    "piccard_encode": {"primitive": "onehot-encoding",
                       "protocol_model": "piccard-local-encoding",
                       "comparison_scope": "encoding-only-diagnostic",
                       "cost_scope": "encoding-only",
                       "secure_division_included": False,
                       "semantic_comparison_eligible": False},
    "piccard_sqrt_encode": {"primitive": "sqrt-encoding",
                            "protocol_model": "piccard-sqrt-local-encoding",
                            "comparison_scope": "encoding-only-diagnostic",
                            "cost_scope": "encoding-only",
                            "secure_division_included": False,
                            "semantic_comparison_eligible": False},
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


class PhaseBudgetExpired(Work5Error):
    """The fixed parameter-phase cap elapsed before a new subprocess started."""


class SubprocessTimedOut(Work5Error):
    """A subprocess used its bounded timeout without completing."""

    def __init__(self, message: str, *, phase_cap_exhausted: bool,
                 stdout: bytes = b"", stderr: bytes = b""):
        super().__init__(message)
        self.phase_cap_exhausted = phase_cap_exhausted
        self.stdout = stdout
        self.stderr = stderr


class SignalAbort(BaseException):
    """Raised only after the active child has been terminated."""


@dataclass
class ResultsRootCapability:
    """Admission result that is required before this process may write a root."""

    root: Path
    resume: bool
    fresh: bool
    claimed_by_runner: bool = False


_ACTIVE_CHILD: subprocess.Popen[bytes] | None = None


def _signal_abort(signum: int, _frame: Any) -> None:
    global _ACTIVE_CHILD
    if _ACTIVE_CHILD is not None and _ACTIVE_CHILD.poll() is None:
        _signal_process_group(_ACTIVE_CHILD, signal.SIGTERM)
    raise SignalAbort(f"received signal {signum}")


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


def select_subprocess_timeout(deadline: float, *, limit: float = CELL_TIMEOUT_SECONDS) -> tuple[float, bool]:
    """Select one wall timeout and whether the phase, rather than wall, binds it."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PhaseBudgetExpired("parameter phase cap exhausted before subprocess start")
    wall_limit = min(float(CELL_TIMEOUT_SECONDS), limit)
    return min(wall_limit, remaining), remaining <= wall_limit


def phase_timeout(deadline: float, *, limit: float = CELL_TIMEOUT_SECONDS) -> float:
    """Return the only permitted subprocess timeout for the active phase."""
    return select_subprocess_timeout(deadline, limit=limit)[0]


def subprocess_wall_limit(limit: float) -> float:
    """Fixture-only shorter wall used to test the production 1800s boundary."""
    override = os.environ.get("PICCARD_WORK5_TEST_SUBPROCESS_TIMEOUT_SECONDS")
    if override is None:
        return limit
    if not is_test_fixture_mode():
        raise Work5Error("test-only subprocess timeout override is forbidden outside fixture mode")
    try:
        parsed = float(override)
    except ValueError as exc:
        raise Work5Error("test-only subprocess timeout override must be numeric") from exc
    if parsed <= 0:
        raise Work5Error("test-only subprocess timeout override must be positive")
    return min(limit, parsed)


def timeout_reason_code(error: PhaseBudgetExpired | SubprocessTimedOut) -> str:
    """Keep an admitted process wall timeout distinct from phase exhaustion."""
    if isinstance(error, PhaseBudgetExpired) or error.phase_cap_exhausted:
        return "PHASE_CAP_EXHAUSTED"
    # The approved Phase-3 contract names an admitted process timeout TIMEOUT.
    return "TIMEOUT"


def _cleanup_timeout(deadline: float) -> float | None:
    """Return a bounded cleanup wait that never borrows past the phase cap."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return min(1.0, remaining)


def _signal_process_group(process: subprocess.Popen[bytes], signal_number: int) -> None:
    try:
        os.killpg(process.pid, signal_number)
    except (ProcessLookupError, PermissionError):
        pass


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def terminate_process_group(process: subprocess.Popen[bytes], deadline: float) -> tuple[bytes, bytes]:
    """TERM then KILL a process group without waiting on inherited pipe FDs."""
    stdout = stderr = b""
    _signal_process_group(process, signal.SIGTERM)
    cleanup_timeout = _cleanup_timeout(deadline)
    if cleanup_timeout is None:
        _signal_process_group(process, signal.SIGKILL)
        _close_process_pipes(process)
        return stdout, stderr
    try:
        stdout, stderr = process.communicate(timeout=cleanup_timeout)
        return stdout or b"", stderr or b""
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
    _signal_process_group(process, signal.SIGKILL)
    cleanup_timeout = _cleanup_timeout(deadline)
    if cleanup_timeout is None:
        _close_process_pipes(process)
        return stdout, stderr
    try:
        final_stdout, final_stderr = process.communicate(timeout=cleanup_timeout)
        return final_stdout or stdout or b"", final_stderr or stderr or b""
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout if isinstance(exc.stdout, bytes) else b"") or stdout
        stderr = (exc.stderr if isinstance(exc.stderr, bytes) else b"") or stderr
        # A descendant that escaped the group may retain stdout/stderr.  Do not
        # let that pipe hold terminalization hostage after the producer died.
        _close_process_pipes(process)
        cleanup_timeout = _cleanup_timeout(deadline)
        if cleanup_timeout is None:
            return stdout, stderr
        try:
            process.wait(timeout=cleanup_timeout)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return stdout, stderr


def bounded_subprocess(argv: list[str], *, deadline: float, cwd: Path,
                       env: dict[str, str] | None = None,
                       limit: float = CELL_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[bytes]:
    """Run an argv array in its own process group under the phase deadline."""
    limit = subprocess_wall_limit(limit)
    timeout, phase_cap_exhausted = select_subprocess_timeout(deadline, limit=limit)
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
    except OSError as exc:
        raise Work5Error(f"cannot start subprocess {argv[0]!r}: {exc}") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stdout, stderr = terminate_process_group(process, deadline)
        raise SubprocessTimedOut("subprocess exceeded bounded phase timeout",
                                 phase_cap_exhausted=phase_cap_exhausted,
                                 stdout=stdout, stderr=stderr)
    except BaseException:
        terminate_process_group(process, deadline)
        raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def git(*arguments: str, deadline: float) -> str:
    test_override = os.environ.get("PICCARD_WORK5_TEST_GIT_EXECUTABLE")
    if test_override and not is_test_fixture_mode():
        raise Work5Error("test-only git override is forbidden outside fixture mode")
    try:
        result = bounded_subprocess([test_override or "git", *arguments], cwd=SOURCE_ROOT,
                                    deadline=deadline, env=os.environ.copy())
    except SubprocessTimedOut as exc:
        if exc.phase_cap_exhausted:
            raise PhaseBudgetExpired("parameter phase cap exhausted during source provenance") from exc
        raise
    if result.returncode != 0:
        raise Work5Error(f"git {' '.join(arguments)} failed: " +
                         result.stderr.decode("utf-8", "replace").strip())
    return result.stdout.decode("utf-8", "replace").strip()


def source_identity(deadline: float) -> tuple[str, bool]:
    # Untracked evidence is deliberately outside the source identity.  A final
    # evidence run still records a dirty tracked tree and cannot be sealed.
    return (git("rev-parse", "HEAD", deadline=deadline),
            bool(git("status", "--porcelain=v1", "--untracked-files=no", deadline=deadline)))


def source_provenance(deadline: float) -> dict[str, Any]:
    """Pinned source identity used both at creation and resume.

    The repository root is canonicalized rather than inferred from an output
    path, which prevents a copied evidence directory from becoming a valid
    continuation under a different checkout.
    """
    return {"git_sha": git("rev-parse", "HEAD", deadline=deadline),
            "git_tree": git("rev-parse", "HEAD^{tree}", deadline=deadline),
            "repository_root": str(Path(git("rev-parse", "--show-toplevel", deadline=deadline)).resolve()),
            "git_dirty": bool(git("status", "--porcelain=v1", "--untracked-files=no", deadline=deadline))}


def results_root_digest(root: Path) -> str:
    return sha256_bytes(canonical_json({"schema": "piccard-work5-results-root-v1",
                                        "results_root": str(root.resolve())}))


def compiler_descriptor(deadline: float) -> dict[str, str]:
    compiler = os.environ.get("CXX", "c++")
    try:
        result = bounded_subprocess([compiler, "--version"], cwd=SOURCE_ROOT,
                                    deadline=deadline, env=os.environ.copy())
        version = (result.stdout or result.stderr).decode("utf-8", "replace").splitlines()
        return {"path": compiler, "version": version[0] if result.returncode == 0 and version else "unavailable"}
    except SubprocessTimedOut as exc:
        if exc.phase_cap_exhausted:
            raise PhaseBudgetExpired("parameter phase cap exhausted during compiler provenance") from exc
        raise
    except OSError:
        return {"path": compiler, "version": "unavailable"}


def host_descriptor() -> dict[str, Any]:
    try:
        memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, ValueError, OSError):
        memory = None
    return {"os": platform.platform(), "cpu": platform.machine(), "ram_bytes": memory}


def suite_definitions() -> dict[str, dict[str, Any]]:
    definitions: dict[str, dict[str, Any]] = {}
    for suite, profile, methods, axes, axis_values, owns_control, control_cell_id in SUITES:
        if suite in definitions or not set(axes).issubset(AXES):
            raise Work5Error("internal Work #5 suite definition is malformed")
        values = {axis: tuple(axis_values.get(axis, PARAMETER_AXES[axis])) for axis in axes}
        if any(not values[axis] or not set(values[axis]).issubset(PARAMETER_AXES[axis])
               for axis in axes):
            raise Work5Error("internal Work #5 suite axis domain is malformed")
        if any(method in {"piccard_sqrt", "piccard_sqrt_encode"}
               for method in methods) and any(value not in {16, 64, 256}
                                              for value in values.get("m", ())):
            raise Work5Error("sqrt suite contains an unsupported m value")
        if owns_control != (control_cell_id is None):
            raise Work5Error("internal Work #5 control ownership is malformed")
        definitions[suite] = {
            "profile": profile, "methods": list(methods), "applicable_axes": tuple(axes),
            "axis_values": values, "owns_control": owns_control,
            "control_cell_id": control_cell_id,
            "applicability": {axis: axis in axes for axis in AXES},
        }
    for suite, details in definitions.items():
        control_cell_id = details["control_cell_id"]
        if control_cell_id is None:
            continue
        control_suite, separator, control_axis = control_cell_id.partition("::")
        source = definitions.get(control_suite)
        if separator != "::" or control_axis != "control" or source is None or \
                not source["owns_control"] or source["profile"] != details["profile"]:
            raise Work5Error(f"internal Work #5 shared control is malformed: {suite}")
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
        base = {"profile": profile, "suite": suite,
                "security": PROFILES[profile]["security"], **CONTROL,
                "methods": list(details["methods"]),
                "applicability": dict(details["applicability"]),
                "profile_comparison_eligible": False,
                "control_cell_id": details["control_cell_id"]}
        if details["owns_control"]:
            cells.append({"cell_id": f"{suite}::control", "axis": "control",
                          "axis_value": None, **base})
        for axis in details["applicable_axes"]:
            for value in details["axis_values"][axis]:
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
                                        "applicability", "profile_comparison_eligible",
                                        "control_cell_id")}
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
        "context_onehot": root / "context" / f"{cell_id}.onehot.json",
        "context_sqrt": root / "context" / f"{cell_id}.sqrt.json",
        "context_fhe_ind": root / "context" / f"{cell_id}.fhe-ind.json",
    }


def toy_artifact_paths(root: Path) -> dict[str, Path]:
    """Final, immutable artifacts for the mandatory six-method toy smoke."""
    base = root / "toy"
    return {"command": base / "command.json", "stdout": base / "comparison.stdout",
            "stderr": base / "comparison.stderr", "workload": base / "workload.manifest.bin",
            "trace": base / "execution.trace.bin", "csv": base / "comparison.csv"}


def toy_staging_paths(root: Path) -> dict[str, Path]:
    base = root / ".tmp" / "toy-smoke"
    return {"command": base / "command.json", "stdout": base / "comparison.stdout",
            "stderr": base / "comparison.stderr", "workload": base / "workload.manifest.bin",
            "trace": base / "execution.trace.bin", "csv": base / "comparison.csv"}


def staging_paths(root: Path, cell_id: str) -> dict[str, Path]:
    base = root / ".tmp" / cell_id
    return {"command": base / "command.json",
            "stdout": base / "benchmark.stdout",
            "stderr": base / "benchmark.stderr",
            "workload": base / "workload.manifest.bin",
            "trace": base / "execution.trace.bin", "csv": base / "rows.csv",
            "context_onehot": base / "context.onehot.json",
            "context_sqrt": base / "context.sqrt.json",
            "context_fhe_ind": base / "context.fhe-ind.json"}


def ensure_staging_directory(root: Path, cell_id: str) -> None:
    """Claim the cell-local staging directory before argv construction.

    This is deliberately done for BCG12/SJ16 as well as BFV groups: a command
    must never be able to manufacture a final evidence path directly.
    """
    directory = (root / ".tmp" / cell_id)
    directory.mkdir(parents=True, exist_ok=False)


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


def is_encoding_only_cell(cell: dict[str, Any]) -> bool:
    """True only for the frozen STD192 local encoder producer contract."""
    methods = cell.get("methods")
    return (cell.get("security") == "STD192" and isinstance(methods, list) and
            bool(methods) and set(methods) <= {"piccard_encode", "piccard_sqrt_encode"})


def process_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(command_environment())
    return environment


def is_test_fixture_mode() -> bool:
    # The Phase-1 fixture exposes this one sentinel.  It is not a user-facing
    # option and final/sealed evidence rejects it in the independent verifier.
    return bool(os.environ.get("PICCARD_WORK5_FAKE_EVENT_LOG"))


def required_executable_names(test_fixture: bool) -> tuple[str, ...]:
    return (("bench_review_comparison", "bench_fhe_ind", "bench_comparison") if test_fixture else
            ("bench_review_comparison", "bench_fhe_ind", "bench_comparison",
             "bench_std_security_evidence", "bench_real_datasets", "bench_dynamic"))


def executable_map(build_dir: Path, *, test_fixture: bool) -> dict[str, str]:
    required = required_executable_names(test_fixture)
    result: dict[str, str] = {}
    for name in required:
        path = build_dir / name
        if not path.is_file() or not os.access(path, os.X_OK):
            raise Work5Error(f"missing executable: {path}")
        result[name] = sha256_file(path)
    return result


def executable_paths(build_dir: Path, executable_hashes: dict[str, str]) -> dict[str, str]:
    return {name: str((build_dir / name).resolve()) for name in executable_hashes}


def planned_argv(build_dir: Path, root: Path, cell: dict[str, Any]) -> list[str]:
    paths = staging_paths(root, cell["cell_id"])
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


def planned_toy_argv(build_dir: Path, root: Path) -> list[str]:
    """The exact, six-method producer invocation for the frozen toy smoke."""
    paths = toy_staging_paths(root)
    return [
        str((build_dir / "bench_review_comparison").resolve()),
        "--suite=toy-smoke", "--profile=toy-smoke", "--k=16", "--m=16",
        "--set-size=10", "--universe=64", "--target-jaccard=0.5",
        "--trials=1", "--accuracy-trials=1", "--seed=7",
        "--methods=" + ",".join(TOY_CELL["methods"]), "--sj16-key-bits=1024",
        "--allow-unmatched-security", f"--manifest-out={paths['workload']}",
        f"--execution-trace-out={paths['trace']}",
    ]


def write_command_artifact(root: Path, cell: dict[str, Any], argv: list[str]) -> None:
    """Install the planned command from the cell-local staging directory."""
    paths = artifact_paths(root, cell["cell_id"])
    staged = staging_paths(root, cell["cell_id"])
    if paths["command"].exists() or staged["command"].exists():
        raise Work5Error(f"refusing to overwrite planned command: {cell['cell_id']}")
    payload = {"schema": "piccard-work5-command-v1", "cell_id": cell["cell_id"],
               "argv": argv, "environment": command_environment()}
    atomic_write(staged["command"], canonical_json(payload), new=True)
    install_staged(staged["command"], paths["command"])


def install_logs(root: Path, cell: dict[str, Any], stdout: bytes, stderr: bytes) -> None:
    """Atomically install raw producer logs without replacing a prior attempt."""
    paths = artifact_paths(root, cell["cell_id"])
    staged = staging_paths(root, cell["cell_id"])
    finals = (paths["stdout"], paths["stderr"])
    if any(path.exists() for path in finals):
        if all(path.is_file() for path in finals):
            return
        raise Work5Error(f"partial terminal log state for {cell['cell_id']}")
    atomic_write(staged["stdout"], stdout, new=True)
    atomic_write(staged["stderr"], stderr, new=True)
    install_staged(staged["stdout"], paths["stdout"])
    install_staged(staged["stderr"], paths["stderr"])


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
                                      "applicability", "profile_comparison_eligible",
                                      "control_cell_id")},
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
    for label in ("command", "stdout", "stderr", "context_onehot", "context_sqrt",
                  "context_fhe_ind", "workload", "trace", "csv"):
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


def install_staged(staged: Path, final: Path) -> None:
    """Install a validated producer artifact without replacing a prior attempt."""
    if not staged.is_file():
        raise Work5Error(f"artifact mismatch: staged artifact is missing: {staged}")
    final.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(staged, final)
    except FileExistsError as exc:
        raise Work5Error(f"refusing to overwrite existing artifact: {final}") from exc
    staged.unlink()


def install_toy_logs(root: Path, stdout: bytes, stderr: bytes) -> None:
    final, staged = toy_artifact_paths(root), toy_staging_paths(root)
    if final["stdout"].exists() or final["stderr"].exists():
        raise Work5Error("toy smoke logs are immutable")
    atomic_write(staged["stdout"], stdout, new=True)
    atomic_write(staged["stderr"], stderr, new=True)
    install_staged(staged["stdout"], final["stdout"])
    install_staged(staged["stderr"], final["stderr"])


def toy_artifact_pair(root: Path, label: str) -> tuple[str | None, str | None]:
    return artifact_pair(root, toy_artifact_paths(root)[label])


def toy_document(root: Path, argv: list[str], *, status: str, reason_code: str | None,
                 reason_detail: str | None, exit_code: int | None,
                 started_at_utc: str, trial_payload_sha256: str | None) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": "piccard-work5-toy-v1", "cell_id": TOY_CELL["cell_id"],
        **{key: TOY_CELL[key] for key in ("suite", "profile", "security", "k", "m", "n", "U", "methods")},
        "target_jaccard": TARGET_JACCARD, "seed": SEED,
        "trials": {"timing_trials": 1, "accuracy_trials": 1, "executed_trials": 3},
        "status": status, "reason_code": reason_code, "reason_detail": reason_detail,
        "started_at_utc": started_at_utc, "ended_at_utc": utc_now(),
        "argv": argv, "environment": command_environment(), "exit_code": exit_code,
        "trial_payload_sha256": trial_payload_sha256,
    }
    for label in ("command", "stdout", "stderr", "workload", "trace", "csv"):
        path, digest = toy_artifact_pair(root, label)
        document[f"{label}_path"] = path
        document[f"{label}_sha256"] = digest
    return document


def write_toy_document(root: Path, document: dict[str, Any]) -> str:
    path = root / "toy.json"
    atomic_write(path, canonical_json(document), new=True)
    return sha256_file(path)


def root_relative_file(root: Path, path: Path, label: str) -> str:
    """Return one non-link, regular artifact path bound inside ``root``."""
    resolved_root = root.resolve()
    try:
        relative = path.resolve(strict=True).relative_to(resolved_root).as_posix()
    except (OSError, ValueError) as exc:
        raise Work5Error(f"{label} is not a regular artifact inside results root: {path}") from exc
    if path.is_symlink() or not path.is_file():
        raise Work5Error(f"{label} must be a non-symlink regular file: {path}")
    return relative


def phase_inventory_document(root: Path, phase: str, paths: Iterable[Path], *,
                             row_counts: dict[str, int]) -> dict[str, Any]:
    """Seal exact phase-local paths before appending the lifecycle state.

    The inventory is intentionally independent of a later verifier receipt:
    a receipt validates this immutable list, but is never retroactively added
    to it.  That avoids both a receipt/self-hash cycle and an unclaimed-output
    loophole.
    """
    artifacts: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in paths:
        relative = root_relative_file(root, path, f"{phase} artifact")
        if relative in seen:
            raise Work5Error(f"duplicate {phase} phase artifact: {relative}")
        seen.add(relative)
        artifacts.append({"path": relative, "sha256": sha256_file(path)})
    if not artifacts:
        raise Work5Error(f"{phase} phase inventory cannot be empty")
    return {"schema": "piccard-work5-phase-inventory-v1", "phase": phase,
            "artifacts": sorted(artifacts, key=lambda item: item["path"]),
            "row_counts": row_counts}


def phase_inventory_sha256(inventory: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(inventory))


def install_phase_inventory(run: dict[str, Any], phase: str,
                            inventory: dict[str, Any]) -> None:
    completed = run.get("completed_phases")
    inventories = run.get("phase_inventory")
    if not isinstance(completed, list) or not isinstance(inventories, dict):
        raise Work5Error("run lifecycle state is malformed")
    if phase in completed or phase in inventories:
        raise Work5Error(f"{phase} phase is terminal and cannot be rerun")
    if inventory.get("phase") != phase:
        raise Work5Error("phase inventory phase mismatch")
    completed.append(phase)
    inventories[phase] = inventory


def require_prior_receipt(root: Path, run: dict[str, Any], phase: str,
                          expected_completed: list[str]) -> None:
    """Require the prior independent verifier receipt before a new producer."""
    receipt_path = root / "verification" / f"{phase}.json"
    receipt = read_json(receipt_path, f"{phase} verification receipt")
    inventory = run.get("phase_inventory", {}).get(phase)
    if (receipt.get("schema") != "piccard-work5-verification-receipt-v1" or
            receipt.get("verdict") != "PASS" or receipt.get("phase") != phase or
            receipt.get("results_root") != str(root.resolve()) or
            receipt.get("run_sha256") != sha256_file(root / "run.json") or
            receipt.get("git_sha") != run.get("git_sha") or
            receipt.get("completed_phases") != expected_completed or
            not isinstance(inventory, dict) or
            receipt.get("phase_inventory_sha256") != phase_inventory_sha256(inventory)):
        raise Work5Error(f"missing or invalid independent {phase} verification receipt")


def discard_toy_staging(root: Path) -> None:
    for path in toy_staging_paths(root).values():
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def create_initial_root(root_capability: ResultsRootCapability, build_dir: Path,
                        executable_hashes: dict[str, str], matrix: dict[str, Any], *,
                        test_fixture: bool, deadline: float) -> dict[str, Any]:
    """Create the immutable skeleton shared by the toy and parameter phases."""
    root = root_capability.root
    claim_fresh_root(root_capability)
    for directory in ("commands", "logs", "csv", "workloads", "traces", "context", "real", "dynamic", "toy", ".tmp"):
        (root / directory).mkdir(exist_ok=False)
    matrix_path = root / "matrix.json"
    atomic_write(matrix_path, canonical_json(matrix), new=True)
    run = initial_run(build_dir, executable_hashes, sha256_file(matrix_path), root,
                      test_fixture=test_fixture, deadline=deadline)
    atomic_write(root / "run.json", canonical_json(run), new=True)
    write_cells(root, [])
    run["cells_sha256"] = sha256_file(root / "cells.jsonl")
    atomic_write(root / "run.json", canonical_json(run))
    return run


def run_toy_phase(args: argparse.Namespace, root_capability: ResultsRootCapability,
                  *, deadline: float) -> int:
    """Execute exactly one canonical toy comparison, then make it immutable."""
    if is_test_fixture_mode():
        raise Work5Error("fixture mode cannot produce production toy evidence")
    root, build_dir = root_capability.root, Path(args.build_dir).resolve()
    source_provenance(deadline)
    executable_hashes = executable_map(build_dir, test_fixture=False)
    matrix = matrix_document(frozen_cells())
    if args.resume:
        run, records = resume_validate(root, build_dir, executable_hashes, matrix, deadline=deadline)
        if records or (root / "toy.json").exists() or run.get("completed_phases"):
            raise Work5Error("toy smoke is terminal and cannot be rerun in the same root")
    else:
        run = create_initial_root(root_capability, build_dir, executable_hashes, matrix,
                                 test_fixture=False, deadline=deadline)
    staging = toy_staging_paths(root)
    staging["command"].parent.mkdir(exist_ok=False)
    final = toy_artifact_paths(root)
    argv, started = planned_toy_argv(build_dir, root), utc_now()
    command = {"schema": "piccard-work5-toy-command-v1", "cell_id": TOY_CELL["cell_id"],
               "argv": argv, "environment": command_environment()}
    atomic_write(staging["command"], canonical_json(command), new=True)
    install_staged(staging["command"], final["command"])
    stdout = stderr = b""
    try:
        global _ACTIVE_CHILD
        timeout, phase_cap_exhausted = select_subprocess_timeout(deadline)
        _ACTIVE_CHILD = subprocess.Popen(argv, cwd=SOURCE_ROOT, env=process_environment(),
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         start_new_session=True)
        try:
            stdout, stderr = _ACTIVE_CHILD.communicate(timeout=timeout)
            completed = subprocess.CompletedProcess(argv, _ACTIVE_CHILD.returncode, stdout, stderr)
            _ACTIVE_CHILD = None
        except subprocess.TimeoutExpired:
            child, _ACTIVE_CHILD = _ACTIVE_CHILD, None
            stdout, stderr = terminate_process_group(child, deadline)
            raise SubprocessTimedOut("toy benchmark subprocess exceeded bounded phase timeout",
                                     phase_cap_exhausted=phase_cap_exhausted,
                                     stdout=stdout, stderr=stderr)
        if completed.returncode != 0:
            raise Work5Error("toy benchmark subprocess failed: " +
                             stderr.decode("utf-8", "replace").strip())
        if not staging["workload"].is_file() or not staging["trace"].is_file():
            raise Work5Error("artifact mismatch: toy benchmark did not create workload/trace")
        atomic_write(staging["csv"], stdout, new=True)
        validate_live_rows(staging["csv"], TOY_CELL)
        verify_live_artifacts(staging["csv"], staging["workload"], staging["trace"], TOY_CELL)
        payload = trial_payload_sha256_from_workload(staging["workload"], TOY_CELL)
        install_toy_logs(root, stdout, stderr)
        for label in ("workload", "trace", "csv"):
            install_staged(staging[label], final[label])
        toy_sha = write_toy_document(root, toy_document(
            root, argv, status="MEASURED", reason_code=None, reason_detail=None,
            exit_code=0, started_at_utc=started, trial_payload_sha256=payload))
        run["toy_sha256"] = toy_sha
        install_phase_inventory(run, "toy", phase_inventory_document(
            root, "toy", [root / "toy.json", *final.values()],
            row_counts={"terminal_cells": 0, "measured": 1, "skipped": 0,
                        "errors": 0}))
        atomic_write(root / "run.json", canonical_json(run))
        return 0
    except BaseException as exc:
        if isinstance(exc, SubprocessTimedOut):
            stdout, stderr = exc.stdout, exc.stderr
            reason = timeout_reason_code(exc)
        elif isinstance(exc, SignalAbort):
            reason = "EXCEPTION"
            stderr = f"SignalAbort: {exc}".encode("utf-8", "replace")
        else:
            reason = "ARTIFACT_MISMATCH" if str(exc).startswith("artifact mismatch:") else "EXCEPTION"
            if not stderr:
                stderr = f"{type(exc).__name__}: {exc}".encode("utf-8", "replace")
        discard_toy_staging(root)
        if not final["stdout"].exists():
            install_toy_logs(root, stdout, stderr)
        if not (root / "toy.json").exists():
            run["toy_sha256"] = write_toy_document(root, toy_document(
                root, argv, status="ERROR", reason_code=reason,
                reason_detail=stderr.decode("utf-8", "replace"),
                exit_code=124 if reason in {"TIMEOUT", "PHASE_CAP_EXHAUSTED"} else 70,
                started_at_utc=started, trial_payload_sha256=None))
            atomic_write(root / "run.json", canonical_json(run))
        raise Work5Error(f"terminal toy ERROR/{reason}") from exc


def discard_staging(root: Path, cell_id: str) -> None:
    """Remove only unsealed cell-local temporary files after a terminal error."""
    for path in staging_paths(root, cell_id).values():
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def discard_unsealed_outputs(root: Path, cell_id: str) -> None:
    """Remove outputs from a failed, as-yet-unterminalized producer attempt."""
    paths = artifact_paths(root, cell_id)
    for name in ("context_onehot", "context_sqrt", "context_fhe_ind",
                 "workload", "trace", "csv"):
        try:
            paths[name].unlink()
        except FileNotFoundError:
            pass


def context_preflight(build_dir: Path, root: Path, cell: dict[str, Any], *,
                      test_fixture: bool, timeout: float,
                      deadline: float) -> tuple[str | None, dict[str, dict[str, Any]]]:
    """Run and validate a cell-bound, context-only admission record.

    The Work #5 modes are intentionally distinct from Work #4's byte-frozen
    smoke modes.  The producer writes under ``.tmp``; only a successfully
    parsed, cap-checked record is installed under the evidence tree.
    """
    note_test_context_preflight(cell["cell_id"])
    if test_fixture or not any(method in {"piccard", "piccard_sqrt", "fhe_ind"}
                               for method in cell["methods"]):
        return None, {}
    staged = staging_paths(root, cell["cell_id"])
    finals = artifact_paths(root, cell["cell_id"])
    specs: list[tuple[str, Path, Path, list[str], str, dict[str, Any]]] = []
    if cell["methods"] == ["fhe_ind"]:
        helper = build_dir / "bench_fhe_ind"
        argv = [str(helper.resolve()), "--mode=work5-preflight", "--method=fhe_ind",
                "--circuit=fhe_ind", f"--security={cell['security']}",
                "--shape-id=fhe-indicator-v1", f"--cell-id={cell['cell_id']}",
                f"--n={cell['n']}", f"--universe={cell['U']}",
                f"--output={staged['context_fhe_ind']}", "--format=json"]
        schema = "piccard-work5-fhe-ind-context-preflight-v1"
        expected = {"cell_id": cell["cell_id"], "method": "fhe_ind", "n": cell["n"],
                    "universe": cell["U"], "security": cell["security"]}
        specs.append(("context_fhe_ind", helper, staged["context_fhe_ind"], argv, schema, expected))
    else:
        helper = build_dir / "bench_std_security_evidence"
        context_specs: list[tuple[str, str, str]] = []
        if "piccard" in cell["methods"]:
            context_specs.append(("context_onehot", "onehot", "onehot-v1"))
        if "piccard_sqrt" in cell["methods"]:
            context_specs.append(("context_sqrt", "sqrt", "sqrt-b4-v1"))
        for label, circuit, shape in context_specs:
            argv = [str(helper.resolve()), "--mode=work5-preflight", f"--circuit={circuit}",
                    f"--security={cell['security']}", f"--shape-id={shape}",
                    f"--cell-id={cell['cell_id']}", f"--k={cell['k']}", f"--m={cell['m']}",
                    f"--n={cell['n']}", f"--universe={cell['U']}",
                    f"--output={staged[label]}", "--format=json"]
            specs.append((label, helper, staged[label], argv,
                          "piccard-work5-piccard-context-preflight-v1",
                          {"cell_id": cell["cell_id"], "circuit": circuit,
                           "security": cell["security"], "k": cell["k"], "m": cell["m"],
                           "n": cell["n"], "universe": cell["U"]}))
    observed_by_label: dict[str, dict[str, Any]] = {}
    reason: str | None = None
    for label, helper, staging, argv, schema, expected in specs:
        if staging.exists() or finals[label].exists():
            raise Work5Error("context preflight output already exists")
        if not helper.is_file() or not os.access(helper, os.X_OK):
            raise Work5Error("context-only preflight executable is unavailable before workload/keygen")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PhaseBudgetExpired("parameter phase cap exhausted before context preflight")
        try:
            completed = bounded_subprocess(
                argv, cwd=SOURCE_ROOT, env=process_environment(), deadline=deadline,
                limit=timeout)
        except SubprocessTimedOut as exc:
            raise SubprocessTimedOut(
                "context-only preflight subprocess exceeded its bounded timeout",
                phase_cap_exhausted=exc.phase_cap_exhausted,
                stdout=exc.stdout, stderr=exc.stderr) from exc
        if completed.returncode != 0:
            raise Work5Error("context-only preflight subprocess failed before workload/keygen: " +
                             completed.stderr.decode("utf-8", "replace").strip())
        try:
            observed = json.loads(staging.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Work5Error(f"artifact mismatch: malformed context preflight: {exc}") from exc
        if not isinstance(observed, dict) or observed.get("schema") != schema or \
                observed.get("mode") != "work5-preflight" or observed.get("keygen_started") is not False or \
                any(observed.get(name) != value for name, value in expected.items()):
            raise Work5Error("artifact mismatch: context preflight does not bind this frozen cell")
        binary_field = ("fhe_ind_binary_sha256" if label == "context_fhe_ind"
                        else "piccard_binary_sha256")
        required_caps = ("realized_ring_dim", "provisioned_depth", "log_q_bits",
                         "context_tuple_sha256", "source_commit", "build_id", binary_field)
        if any(name not in observed for name in required_caps) or \
                observed["source_commit"] != source_provenance(deadline)["git_sha"] or \
                observed[binary_field] != sha256_file(helper):
            raise Work5Error("artifact mismatch: context preflight lacks current observed provenance")
        try:
            breached = next((code for code, value, cap in
                             (("RING_DIM_CAP", float(observed["realized_ring_dim"]), BFV_CAPS["realized_ring_dim"]),
                              ("DEPTH_CAP", float(observed["provisioned_depth"]), BFV_CAPS["provisioned_depth"]),
                              ("LOGQ_CAP", float(observed["log_q_bits"]), BFV_CAPS["log_q_bits"]))
                             if value > cap), None)
        except (TypeError, ValueError) as exc:
            raise Work5Error("artifact mismatch: context cap fields are invalid") from exc
        if bool(observed.get("skipped")) != (breached is not None):
            raise Work5Error("artifact mismatch: context skip does not match observed caps")
        install_staged(staging, finals[label])
        observed_by_label[label] = observed
        reason = reason or breached
    return reason, observed_by_label


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
    staged = staging_paths(root, cell["cell_id"])
    payload = planned_payload_sha256(cell)
    atomic_write(staged["workload"],
                 ("piccard-work5-test-workload-v1\n" + payload + "\n").encode("ascii"), new=True)
    atomic_write(staged["trace"],
                 ("piccard-work5-test-trace-v1\n" + payload + "\n").encode("ascii"), new=True)
    rows = ["method,evidence_arm,status"]
    for method in cell["methods"]:
        rows.append(f"{method},timing,MEASURED")
        rows.append(f"{method},accuracy,MEASURED")
    atomic_write(staged["csv"], ("\n".join(rows) + "\n").encode("utf-8"), new=True)
    for name in ("workload", "trace", "csv"):
        install_staged(staged[name], paths[name])
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


def note_test_context_preflight(cell_id: str) -> None:
    """Expose only the fixture-mode context-producer boundary to tests."""
    value = os.environ.get("PICCARD_WORK5_FAKE_EVENT_LOG")
    if not value:
        return
    path = Path(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"kind": "context-preflight", "cell_id": cell_id,
                                 "argv": []}, sort_keys=True) + "\n")
        stream.flush()


def validate_live_rows(path: Path, cell: dict[str, Any]) -> None:
    # The CSV is checked together with its parsed workload and trace below.
    # This quick gate keeps the pre-terminal ordering explicit for diagnostics.
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream, strict=True))
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise Work5Error(f"row verification failed: {exc}") from exc
    expected = {(method, arm) for method in cell["methods"] for arm in ("timing", "accuracy")}
    if not rows or {(row.get("method"), row.get("evidence_arm")) for row in rows} != expected or \
            len(rows) != len(expected):
        raise Work5Error("row verification failed: method/arm membership is not frozen")


def verify_live_artifacts(csv_path: Path, workload_path: Path, trace_path: Path,
                          cell: dict[str, Any]) -> None:
    """Use the established binary/CSV semantic verifier before terminalizing."""
    try:
        workload, _rows = review_verifier.verify_csv_artifacts(
            csv_path, workload_path, trace_path)
    except (review_verifier.VerificationError, OSError, ValueError, csv.Error) as exc:
        raise Work5Error(f"semantic verifier failure: {exc}") from exc
    if (workload.suite, workload.profile, workload.root_seed, workload.k, workload.m,
            workload.set_size, workload.universe, list(workload.methods),
            workload.timing_trials, workload.accuracy_trials) != \
            (cell["suite"], cell["profile"], SEED, cell["k"], cell["m"], cell["n"],
             cell["U"], cell["methods"], 1, 1):
        raise Work5Error("semantic verifier failure: workload is not this frozen cell")


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
                       timeout: float, deadline: float) -> None:
    started = utc_now()
    ensure_staging_directory(root, cell["cell_id"])
    argv = planned_argv(build_dir, root, cell)
    flags = stage_values(True, False, False, False, False)
    # The command/log triplet is claimed before any terminal decision.  It is
    # retained even for a cheap skip, making the no-keygen decision auditable.
    write_command_artifact(root, cell, argv)

    geometry = geometry_reason(cell)
    if geometry is not None:
        install_logs(root, cell, b"", b"")
        terminalize(root, records, record_for(
            root, cell, argv, status="SKIPPED_PRECHECK", reason_code="WORKLOAD_GEOMETRY",
            reason_detail=geometry, flags=flags, exit_code=None, started=started))
        return
    if cell["methods"] == ["sj16"] and projected_sj16_ms(cell["U"]) > SJ16_ADMISSION_CAP_MS:
        install_logs(root, cell, b"", b"")
        terminalize(root, records, record_for(
            root, cell, argv, status="SKIPPED_PRECHECK", reason_code="PROJECTED_RUNTIME_CAP",
            reason_detail=(f"projected_cell_ms={projected_sj16_ms(cell['U']):.1f} "
                           f"> cap_ms={SJ16_ADMISSION_CAP_MS:.1f}; executed_trials=3"),
            flags=flags, exit_code=None, started=started))
        return

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PhaseBudgetExpired("parameter phase cap exhausted before context preflight")
        encoding_only = is_encoding_only_cell(cell)
        if not encoding_only:
            flags["context_started"] = True
        forced_precheck = forced_value("PICCARD_WORK5_TEST_FORCE_PRECHECK_REASON", cell["cell_id"])
        if forced_precheck is not None and not encoding_only:
            if not test_fixture:
                raise Work5Error("test-only precheck hook is forbidden outside fixture mode")
            if forced_precheck not in ("RING_DIM_CAP", "DEPTH_CAP", "LOGQ_CAP"):
                raise Work5Error(f"invalid test-only context precheck reason: {forced_precheck}")
            install_logs(root, cell, b"", b"")
            terminalize(root, records, record_for(
                root, cell, argv, status="SKIPPED_PRECHECK", reason_code=forced_precheck,
                reason_detail=f"test-only context observation admitted {forced_precheck}",
                flags=flags, exit_code=None, started=started))
            return

        forced_error = forced_value("PICCARD_WORK5_TEST_FORCE_ERROR_STAGE", cell["cell_id"])
        if forced_error == "pre_setup":
            raise Work5Error("test-only injected pre-setup exception")

        if not encoding_only:
            context_reason, _context = context_preflight(
                build_dir, root, cell, test_fixture=test_fixture,
                timeout=timeout, deadline=deadline)
            if context_reason is not None:
                install_logs(root, cell, b"", b"")
                terminalize(root, records, record_for(
                    root, cell, argv, status="SKIPPED_PRECHECK", reason_code=context_reason,
                    reason_detail="observed Work #5 context cap exceeded", flags=flags,
                    exit_code=None, started=started))
                return
        flags["workload_started"] = True
        if not encoding_only:
            flags["keygen_started"] = True
        if forced_error == "setup":
            raise Work5Error("test-only injected setup exception")

        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PhaseBudgetExpired("parameter phase cap exhausted before measurement")
            flags["measurement_started"] = True
            if test_fixture:
                note_test_dispatch(argv)
            global _ACTIVE_CHILD
            timeout_limit = timeout
            subprocess_timeout, phase_cap_exhausted = select_subprocess_timeout(
                deadline, limit=timeout_limit)
            _ACTIVE_CHILD = subprocess.Popen(
                argv, cwd=SOURCE_ROOT, env=process_environment(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
            try:
                stdout, stderr = _ACTIVE_CHILD.communicate(timeout=subprocess_timeout)
                completed = subprocess.CompletedProcess(argv, _ACTIVE_CHILD.returncode, stdout, stderr)
                _ACTIVE_CHILD = None
            except subprocess.TimeoutExpired:
                child = _ACTIVE_CHILD
                _ACTIVE_CHILD = None
                stdout, stderr = terminate_process_group(child, deadline)
                raise SubprocessTimedOut("benchmark subprocess exceeded bounded phase timeout",
                                         phase_cap_exhausted=phase_cap_exhausted,
                                         stdout=stdout, stderr=stderr)
        except SubprocessTimedOut as exc:
            stdout, stderr = exc.stdout, exc.stderr
            install_logs(root, cell, stdout, stderr)
            discard_staging(root, cell["cell_id"])
            discard_unsealed_outputs(root, cell["cell_id"])
            reason_code = timeout_reason_code(exc)
            detail = (f"parameter phase cap exhausted during benchmark subprocess "
                      f"(cap={PARAMETER_TIMEOUT_SECONDS:g}s)"
                      if reason_code == "PHASE_CAP_EXHAUSTED" else
                      f"subprocess wall timeout after {timeout:g} seconds")
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code=reason_code,
                reason_detail=detail, flags=flags,
                exit_code=124, started=started))
            raise Work5Error(f"terminal ERROR/{reason_code}")
        except SignalAbort as exc:
            if _ACTIVE_CHILD is not None:
                stdout, stderr = terminate_process_group(_ACTIVE_CHILD, deadline)
                _ACTIVE_CHILD = None
            else:
                stdout, stderr = b"", b""
            install_logs(root, cell, stdout, stderr)
            discard_staging(root, cell["cell_id"])
            discard_unsealed_outputs(root, cell["cell_id"])
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="EXCEPTION",
                reason_detail=str(exc), flags=flags, exit_code=128,
                started=started))
            raise Work5Error("terminal ERROR/signal") from exc

        install_logs(root, cell, completed.stdout, completed.stderr)
        if completed.returncode != 0:
            discard_unsealed_outputs(root, cell["cell_id"])
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="SUBPROCESS_EXIT",
                reason_detail=f"benchmark exited {completed.returncode}", flags=flags,
                exit_code=completed.returncode or 1, started=started))
            raise Work5Error("terminal ERROR/SUBPROCESS_EXIT")

        paths = artifact_paths(root, cell["cell_id"])
        staged = staging_paths(root, cell["cell_id"])
        if test_fixture:
            assert_fake_success(completed.stdout)
            payload = write_test_artifacts(root, cell)
        else:
            if not staged["workload"].is_file() or not staged["trace"].is_file():
                raise Work5Error("artifact mismatch: benchmark did not create workload/trace")
            validate_live_rows_from_bytes = completed.stdout
            # Validate before atomically installing the CSV representation.
            atomic_write(staged["csv"], validate_live_rows_from_bytes, new=True)
            validate_live_rows(staged["csv"], cell)
            verify_live_artifacts(staged["csv"], staged["workload"], staged["trace"], cell)
            payload = trial_payload_sha256_from_workload(staged["workload"], cell)
            for name in ("workload", "trace", "csv"):
                install_staged(staged[name], paths[name])
        terminalize(root, records, record_for(
            root, cell, argv, status="MEASURED", reason_code=None, reason_detail=None,
            flags=flags, exit_code=0, started=started, trial_payload=payload))
    except Work5Error as exc:
        discard_staging(root, cell["cell_id"])
        if not any(record["cell_id"] == cell["cell_id"] for record in records):
            discard_unsealed_outputs(root, cell["cell_id"])
            detail = str(exc)
            reason = (timeout_reason_code(exc) if isinstance(exc, (PhaseBudgetExpired, SubprocessTimedOut)) else
                      "VERIFIER_FAILURE" if detail.startswith("semantic verifier failure:") else
                      "ARTIFACT_MISMATCH" if detail.startswith("artifact mismatch:") else "EXCEPTION")
            if reason == "TIMEOUT":
                detail = f"subprocess wall timeout: {detail}"
            elif reason == "PHASE_CAP_EXHAUSTED":
                detail = f"parameter phase cap exhausted: {detail}"
            install_logs(root, cell, b"", detail.encode("utf-8", "replace"))
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code=reason,
                reason_detail=detail, flags=flags,
                exit_code=124 if reason in {"TIMEOUT", "PHASE_CAP_EXHAUSTED"} else 70,
                started=started))
        raise
    except BaseException as exc:
        # Signal/exception handling must leave exactly one immutable terminal.
        discard_staging(root, cell["cell_id"])
        if not any(record["cell_id"] == cell["cell_id"] for record in records):
            discard_unsealed_outputs(root, cell["cell_id"])
            install_logs(root, cell, b"", f"{type(exc).__name__}: {exc}".encode("utf-8", "replace"))
            terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="EXCEPTION",
                reason_detail=f"{type(exc).__name__}: {exc}", flags=flags,
                exit_code=130 if isinstance(exc, KeyboardInterrupt) else 70,
                started=started))
        raise Work5Error(f"terminal ERROR/EXCEPTION: {type(exc).__name__}") from exc


def validate_record_artifacts(root: Path, record: dict[str, Any]) -> None:
    for name in ("command", "stdout", "stderr", "context_onehot", "context_sqrt",
                 "context_fhe_ind", "workload", "trace", "csv"):
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
                    matrix: dict[str, Any], *, deadline: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = read_json(root / "run.json", "run.json")
    if run.get("schema") != RUNNER_SCHEMA:
        raise Work5Error("resume run schema mismatch")
    source_sha, dirty = source_identity(deadline)
    provenance = source_provenance(deadline)
    if run.get("git_sha") != source_sha or run.get("git_dirty") != dirty or \
            run.get("git_tree") != provenance["git_tree"] or \
            run.get("repository_root") != provenance["repository_root"] or \
            provenance["git_dirty"] != dirty:
        raise Work5Error("resume source SHA/dirty identity mismatch")
    if run.get("results_root") != str(root.resolve()) or \
            run.get("results_root_sha256") != results_root_digest(root):
        raise Work5Error("resume canonical results-root identity mismatch")
    if run.get("build_dir") != str(build_dir) or run.get("executables") != executable_hashes or \
            run.get("executable_paths") != executable_paths(build_dir, executable_hashes):
        raise Work5Error("resume binary hash identity mismatch")
    cache = build_dir / "CMakeCache.txt"
    if run.get("build_identity") != {"cmake_cache_sha256": sha256_file(cache) if cache.is_file() else None}:
        raise Work5Error("resume build identity mismatch")
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
        "--execution-trace-out"], "frozen_suites": [entry[0] for entry in SUITES],
        "real": {"mode": "single-trial-validation", "dataset": REAL_DATASET,
                 "variant": REAL_VARIANT, "pairs": REAL_PAIR_COUNT,
                 "seed": REAL_SEED, "threads": REAL_THREADS,
                 "profiles": list(REAL_PROFILES), "accuracy_trials": 1,
                 "timing_trials": 1, "timing_pair": "median"},
        "dynamic": {"scenario": "refresh", "profile": DYNAMIC_PROFILE,
                    "security": DYNAMIC_SECURITY, "updates": list(DYNAMIC_UPDATES),
                    "k": DYNAMIC_K, "m": DYNAMIC_M, "set_size": DYNAMIC_SET_SIZE,
                    "depth": DYNAMIC_DEPTH, "target_jaccard": TARGET_JACCARD,
                    "trials": 1, "seed": SEED,
                    "measurement_kind": "diagnostic"},
        "no_shell": True}
    return sha256_bytes(canonical_json(template))


def script_hashes() -> dict[str, str]:
    scripts = ("run_work5_benchmarks.py", "verify_work5_benchmarks.py",
               "capture_work5_phase6_prelive.py", "seal_work5_benchmarks.py",
               "verify_review_comparison.py", "verify_benchmark_provenance.py",
               "prepare_real_datasets.py", "run_real_datasets.sh",
               "verify_real_dataset_outputs.py", "summarize_real_datasets.py")
    return {name: sha256_file(SOURCE_ROOT / "scripts" / name) for name in scripts}


def initial_run(build_dir: Path, executable_hashes: dict[str, str], matrix_sha: str,
                root: Path, *, test_fixture: bool, deadline: float) -> dict[str, Any]:
    source_sha, dirty = source_identity(deadline)
    provenance = source_provenance(deadline)
    cache = build_dir / "CMakeCache.txt"
    return {
        "schema": RUNNER_SCHEMA,
        "created_at_utc": utc_now(), "source_root": str(SOURCE_ROOT.resolve()),
        "git_sha": source_sha, "git_dirty": dirty, "git_tree": provenance["git_tree"],
        "repository_root": provenance["repository_root"], "build_type": "Release",
        "build_dir": str(build_dir), "compiler": compiler_descriptor(deadline),
        "build_identity": {"cmake_cache_sha256": sha256_file(cache) if cache.is_file() else None},
        "results_root": str(root.resolve()), "results_root_sha256": results_root_digest(root),
        "openfhe_version": os.environ.get("PICCARD_OPENFHE_VERSION", DYNAMIC_OPENFHE_VERSION),
        "host": host_descriptor(), "environment": command_environment(),
        "executables": executable_hashes,
        "executable_paths": executable_paths(build_dir, executable_hashes),
        "scripts": script_hashes(),
        "matrix_sha256": matrix_sha, "command_template_sha256": command_template_sha256(),
        "trials": TIMING_TRIALS, "accuracy_trials": ACCURACY_TRIALS,
        "parameter_cell_executed_trials": EXECUTED_TRIALS,
        "cell_timeout_seconds": CELL_TIMEOUT_SECONDS,
        "phase_timeout_seconds": {"toy": CELL_TIMEOUT_SECONDS,
                                  "parameters": PARAMETER_TIMEOUT_SECONDS,
                                  "real": REAL_PHASE_TIMEOUT_SECONDS, "dynamic": 600},
        "disclaimer": DISCLAIMER, "test_fixture_mode": test_fixture,
        "completed_phases": [], "phase_inventory": {}, "cells_sha256": None,
    }


def validate_results_root(root: Path, resume: bool) -> ResultsRootCapability:
    """Validate root ownership before a timeout path can create an artifact.

    A fresh root is represented by a capability that has not yet claimed its
    directory.  A timeout writer may claim it exactly once.  Conversely, an
    existing root has to present the minimum immutable resume skeleton before
    any deadline/provenance path can proceed, and is never writable by the
    run-level timeout path.
    """
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
        pass
    else:
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
    if resume:
        required = ("run.json", "matrix.json", "cells.jsonl")
        absent = [name for name in required if not (root / name).is_file()]
        if absent:
            raise Work5Error("--resume requires validated Work #5 state: missing " +
                             ", ".join(absent))
        run = read_json(root / "run.json", "run.json")
        matrix = read_json(root / "matrix.json", "matrix.json")
        if run.get("schema") != RUNNER_SCHEMA or matrix.get("schema") != MATRIX_SCHEMA:
            raise Work5Error("--resume requires validated Work #5 run/matrix schemas")
    return ResultsRootCapability(root=root, resume=resume, fresh=not resume)


def claim_fresh_root(capability: ResultsRootCapability) -> None:
    """Atomically claim a caller-validated new root without overwrite rights."""
    if not capability.fresh:
        raise Work5Error("resume root cannot be claimed as a new results root")
    if capability.claimed_by_runner:
        return
    try:
        capability.root.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise Work5Error("results root was created after fresh-root validation") from exc
    capability.claimed_by_runner = True


def planned_real_commands(build_dir: Path, root: Path) -> list[tuple[str, list[str]]]:
    """Return the only production DBLP-ACM real-phase argv arrays.

    Keeping this list centrally reconstructable prevents a real-phase record
    from silently choosing a different source, profile, seed, or timing mode.
    The output locations must not exist before the first producer starts.
    """
    processed = root / "real" / REAL_VARIANT
    measurements = root / "real" / "measurements"
    return [
        ("prepare", [
            sys.executable, str(SOURCE_ROOT / "scripts" / "prepare_real_datasets.py"),
            "dblp-acm", "--source-manifest", str(REAL_SOURCE_MANIFEST),
            "--output-dir", str(processed), "--universe", "65536", "--pairs",
            str(REAL_PAIR_COUNT), "--seed", str(REAL_SEED), "--strict",
        ]),
        ("measure", [
            str(SOURCE_ROOT / "scripts" / "run_real_datasets.sh"),
            "--single-trial-validation", "--source-manifest", str(REAL_SOURCE_MANIFEST),
            "--dataset-manifest", str(processed / "dataset.manifest.tsv"),
            f"--seed={REAL_SEED}", f"--threads={REAL_THREADS}",
            f"--build-dir={build_dir}", f"--results-root={measurements}",
        ]),
        ("verify", [
            sys.executable, str(SOURCE_ROOT / "scripts" / "verify_real_dataset_outputs.py"),
            str(measurements),
        ]),
    ]


def planned_dynamic_commands(build_dir: Path, root: Path) -> list[tuple[str, list[str]]]:
    """Return the two and only two dynamic correctness producer argv arrays.

    ``root`` deliberately remains an argument even though the dynamic producer
    writes CSV to stdout: keeping the planner shape identical to the real
    phase makes the command/identity record independently reconstructable.
    The dynamic path is TOY correctness evidence only, never an aggregate or
    a performance comparison.
    """
    del root
    command_prefix = [
        str(build_dir / "bench_dynamic"), "--scenario=refresh",
        "--profile=toy-smoke", "--security=TOY", "--mode=timing",
        "--evidence_point", "--k=16", "--m=16", "--set_size=100",
        "--target_jaccard=0.5", "--depth=5", "--trials=1", "--seed=7",
    ]
    return [
        (f"updates-{updates}", [*command_prefix[:2],
                                f"--refresh_updates={updates}",
                                *command_prefix[2:]])
        for updates in DYNAMIC_UPDATES
    ]


# This is intentionally an ordered tuple, not a set.  The dynamic producer
# is a correctness diagnostic only; admitting a future/ranking column would
# make it possible to promote it into a performance artifact after the fact.
DYNAMIC_CSV_HEADER = tuple(
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
    "phase_refresh_encrypt_ms,phase_refresh_serialize_ms,"
    "phase_cloud_replace_ms,refresh_total_ms,refresh_upload_bytes,"
    "refresh_ciphertexts_uploaded,refresh_context_fingerprint,"
    "refresh_public_key_fingerprint".split(",")
)
# Retain a named set for non-schema callers, but never use it for admission.
DYNAMIC_CSV_FIELDS = frozenset(DYNAMIC_CSV_HEADER)
DYNAMIC_OPENFHE_VERSION = "1.5.0"


def _dynamic_canonical_integer(row: dict[str, str], key: str) -> int:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise Work5Error(f"dynamic CSV field is missing: {key}")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise Work5Error(f"dynamic CSV field is not an integer: {key}") from exc
    if str(parsed) != value:
        raise Work5Error(f"dynamic CSV integer is not canonical: {key}")
    return parsed


def _dynamic_decimal(row: dict[str, str], key: str, *, nonnegative: bool = True) -> Decimal:
    value = row.get(key)
    if not isinstance(value, str) or not value or "e" in value.casefold():
        raise Work5Error(f"dynamic CSV field is not a canonical finite decimal: {key}")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise Work5Error(f"dynamic CSV field is not a decimal: {key}") from exc
    if not parsed.is_finite() or (nonnegative and parsed < 0):
        raise Work5Error(f"dynamic CSV decimal is out of range: {key}")
    return parsed


def _dynamic_same_millis(left: Decimal, right: Decimal) -> bool:
    quantum = Decimal("0.001")
    return left.quantize(quantum) == right.quantize(quantum)


def validate_dynamic_csv(raw: bytes, updates: int) -> dict[str, str]:
    """Fail closed over one frozen dynamic correctness CSV row.

    The runner applies this producer-side check before phase publication; the
    independent verifier reconstructs the same public contract separately.
    It intentionally validates correctness counters and provenance labels, not
    timing values, because no dynamic timing result is a Work #5 claim.
    """
    if updates not in DYNAMIC_UPDATES:
        raise Work5Error("dynamic CSV validator received an unfrozen update count")
    try:
        text = raw.decode("utf-8", "strict")
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = reader.fieldnames
        if fieldnames != list(DYNAMIC_CSV_HEADER):
            raise Work5Error("dynamic CSV header is not the exact frozen 97-column schema")
        rows = list(reader)
    except UnicodeDecodeError as exc:
        raise Work5Error("dynamic CSV is not strict UTF-8") from exc
    except csv.Error as exc:
        raise Work5Error(f"dynamic CSV is malformed: {exc}") from exc
    if len(rows) != 1 or any(None in row for row in rows):
        raise Work5Error("dynamic phase requires exactly one well-formed CSV row per update")
    row = rows[0]
    if any(row.get(name) in (None, "") for name in DYNAMIC_CSV_HEADER):
        raise Work5Error("dynamic CSV contains an empty frozen schema field")
    expected_text = {
        "label": f"refresh_owner_a_0_to_{updates}", "k": str(DYNAMIC_K),
        "m": str(DYNAMIC_M), "set_size": str(DYNAMIC_SET_SIZE), "ring_dim": "1024",
        "depth": str(DYNAMIC_DEPTH), "trials": "1", "hash_seed": str(SEED),
        "hash_root_seed": str(SEED), "accuracy_trials": "0", "profile_id": DYNAMIC_PROFILE,
        "run_class": "smoke", "target_security_bits": "0",
        "comparison_eligible": "false", "measurement_kind": "diagnostic",
        "dynamic_scenario": "refresh", "owner_b_unchanged": "true",
        "correctness_status": "PASS", "refresh_owner_set_id": "owner-a",
        "refresh_status": "applied", "hash_randomness": "fixed",
        "sanitizer_model": "phase-smudging-enc0-poc-v1",
        "sanitizer_assurance": "empirical-phase-statistical+ciphertext-computational",
        "estimator_model": "sha256-random-ranking-poc-v1", "actual_ring_dim": "1024",
        "plaintext_modulus": "12289", "num_limbs": "4",
        "openfhe_version": DYNAMIC_OPENFHE_VERSION,
    }
    if any(row[name] != value for name, value in expected_text.items()):
        raise Work5Error("dynamic CSV violates the frozen correctness/provenance contract")
    expected_numbers = {
        "updates_requested": updates, "updates_applied": updates,
        "initial_epoch": 0, "final_epoch": updates,
        "ciphertext_upload_count": updates, "refresh_updates": updates,
        "refresh_epoch_before": 0, "refresh_epoch_after": updates,
        "refresh_ciphertexts_uploaded": updates,
    }
    observed = {key: _dynamic_canonical_integer(row, key)
                for key in (*expected_numbers, "local_inner_product",
                            "decrypted_inner_product", "refresh_upload_bytes", "ct_size_bytes",
                            "memory_bytes", "rel_error_eligible_n", "transcript_stat_bits",
                            "max_queries", "query_stat_bits", "coefficient_stat_bits",
                            "flood_margin_bits", "eval_noise_bits", "flood_noise_bits",
                            "scaling_mod_size")}
    resource_integer_fields = ("memory_bytes", "ct_size_bytes", "refresh_upload_bytes",
                               "ciphertext_upload_count", "refresh_ciphertexts_uploaded")
    if any(observed[name] < 0 for name in resource_integer_fields):
        raise Work5Error("dynamic CSV resource integer is negative")
    if any(observed[key] != value for key, value in expected_numbers.items()):
        raise Work5Error("dynamic CSV update/epoch/upload counters are inconsistent")
    if observed["local_inner_product"] != observed["decrypted_inner_product"]:
        raise Work5Error("dynamic CSV local/decrypted inner products differ")
    if observed["refresh_upload_bytes"] <= 0:
        raise Work5Error("dynamic CSV upload must contain one non-empty ciphertext")
    if observed["refresh_upload_bytes"] != observed["ct_size_bytes"]:
        raise Work5Error("dynamic CSV upload bytes must equal ciphertext bytes")
    expected_fixed_numbers = {
        "local_inner_product": 7, "decrypted_inner_product": 7, "rel_error_eligible_n": 1,
        "transcript_stat_bits": 40, "max_queries": 1048576, "query_stat_bits": 60,
        "coefficient_stat_bits": 70, "flood_margin_bits": 8, "eval_noise_bits": 56,
        "flood_noise_bits": 134, "scaling_mod_size": 40,
    }
    if any(observed[name] != value for name, value in expected_fixed_numbers.items()):
        raise Work5Error("dynamic CSV fixed numeric provenance mismatch")
    diagnostic_decimals = (
        "phase_init_ms", "phase_insert_ms", "phase_delete_ms", "phase_signature_ms",
        "phase_encode_ms", "phase_encrypt_ms", "phase_compute_ms", "phase_decrypt_ms",
        "total_ms", "phase_refresh_update_ms", "phase_refresh_signature_ms",
        "phase_refresh_encode_ms", "phase_refresh_encrypt_ms", "phase_refresh_serialize_ms",
        "phase_cloud_replace_ms", "refresh_total_ms", "jaccard_computed", "jaccard_expected",
        "jaccard_error", "jaccard_rel_error", "log_q_bits",
    )
    decimals = {name: _dynamic_decimal(row, name) for name in diagnostic_decimals}
    if decimals["jaccard_computed"] > 1 or decimals["jaccard_expected"] > 1:
        raise Work5Error("dynamic CSV Jaccard diagnostic is outside [0,1]")
    if decimals["log_q_bits"] <= 0:
        raise Work5Error("dynamic CSV log_q_bits must be positive")
    if decimals["refresh_total_ms"] != decimals["total_ms"]:
        raise Work5Error("dynamic CSV refresh total must equal diagnostic total")
    for phase in ("total", "phase_init", "phase_insert", "phase_delete", "phase_signature",
                  "phase_encode", "phase_encrypt", "phase_compute", "phase_decrypt"):
        value = decimals["total_ms"] if phase == "total" else decimals[f"{phase}_ms"]
        median = _dynamic_decimal(row, f"{phase}_ms_median")
        if not _dynamic_same_millis(value, median):
            raise Work5Error(f"dynamic CSV median does not match diagnostic phase: {phase}")
    for name in ("total_ms_sd", "phase_init_ms_sd", "phase_insert_ms_sd",
                 "phase_delete_ms_sd", "phase_signature_ms_sd", "phase_encode_ms_sd",
                 "phase_encrypt_ms_sd", "phase_compute_ms_sd", "phase_decrypt_ms_sd"):
        if row[name] != "-1.000":
            raise Work5Error(f"dynamic CSV legacy standard deviation is not disabled: {name}")
    if (row["phase_flood_ms"], row["phase_flood_ms_sd"], row["phase_flood_ms_median"]) != \
            ("0.000", "-1.000", "0.000"):
        raise Work5Error("dynamic CSV flood timing contract mismatch")
    if (row["ops_insert_per_sec"], row["ops_delete_per_sec"]) != ("0.0", "0.0"):
        raise Work5Error("dynamic CSV operation rates must remain non-performance diagnostics")
    for name in ("refresh_context_fingerprint", "refresh_public_key_fingerprint"):
        value = row[name]
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise Work5Error(f"dynamic CSV fingerprint is not lowercase SHA-256: {name}")
    return row


def _write_real_terminal(root: Path, *, status: str, detail: str,
                         commands: list[tuple[str, list[str]]]) -> Path:
    path = root / "real" / "terminal.json"
    if path.exists():
        raise Work5Error("real phase already has a terminal record")
    atomic_write(path, canonical_json({
        "schema": "piccard-work5-real-terminal-v1", "status": status,
        "dataset": REAL_DATASET, "variant": REAL_VARIANT,
        "source_manifest": str(REAL_SOURCE_MANIFEST), "pairs": REAL_PAIR_COUNT,
        "seed": REAL_SEED, "threads": REAL_THREADS, "profiles": list(REAL_PROFILES),
        "accuracy_trials": 1, "timing_trials": 1, "timing_pair": "median",
        "commands": [{"label": label, "argv": argv} for label, argv in commands],
        "detail": detail, "ended_at_utc": utc_now(),
    }), new=True)
    return path


def _real_phase_artifacts(root: Path) -> list[Path]:
    real_root = root / "real"
    return sorted((path for path in real_root.rglob("*") if path.is_file()),
                  key=lambda path: path.as_posix())


def run_real_phase(args: argparse.Namespace, root_capability: ResultsRootCapability,
                   *, deadline: float) -> int:
    """Execute exactly one production DBLP-ACM real phase after Phase 4 state.

    This function is intentionally never called by Phase-5 pre-live checks.
    It has no fixture branch, no alternate dataset switch, and no retry path:
    once a real artifact or terminal record exists, the root is permanently
    ineligible for another real producer attempt.
    """
    if is_test_fixture_mode():
        raise Work5Error("fixture mode cannot produce production real evidence")
    if not args.resume:
        raise Work5Error("production real evidence requires --resume after toy and parameters")
    root, build_dir = root_capability.root, Path(args.build_dir).resolve()
    source_provenance(deadline)
    executable_hashes = executable_map(build_dir, test_fixture=False)
    matrix = matrix_document(frozen_cells())
    run, records = resume_validate(root, build_dir, executable_hashes, matrix, deadline=deadline)
    if run.get("git_dirty"):
        raise Work5Error("production real evidence requires a clean tracked source tree")
    if run.get("completed_phases") != ["toy", "parameters"]:
        raise Work5Error("real phase requires the exact ordered toy,parameters lifecycle")
    if len(records) != 61 or any(record.get("status") == "ERROR" for record in records):
        raise Work5Error("real phase requires a terminal error-free parameter matrix")
    require_prior_receipt(root, run, "parameters", ["toy", "parameters"])
    real_root = root / "real"
    if any(real_root.iterdir()):
        raise Work5Error("real phase has prior artifacts and cannot be retried or overwritten")
    commands = planned_real_commands(build_dir, root)
    for _label, argv in commands:
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise Work5Error("real phase argv construction failed")
    command_path = real_root / "commands.json"
    atomic_write(command_path, canonical_json({
        "schema": "piccard-work5-real-command-v1",
        "commands": [{"label": label, "argv": argv} for label, argv in commands],
        "environment": command_environment(),
    }), new=True)
    try:
        for label, argv in commands:
            result = bounded_subprocess(argv, deadline=deadline, cwd=SOURCE_ROOT,
                                        env=process_environment())
            stdout_path, stderr_path = (real_root / f"{label}.stdout",
                                        real_root / f"{label}.stderr")
            atomic_write(stdout_path, result.stdout or b"", new=True)
            atomic_write(stderr_path, result.stderr or b"", new=True)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
                raise Work5Error(f"real {label} subprocess failed: {detail}")
        terminal = _write_real_terminal(root, status="MEASURED", detail="PASS", commands=commands)
        artifacts = _real_phase_artifacts(root)
        if terminal not in artifacts:
            raise Work5Error("real terminal artifact is missing")
        install_phase_inventory(run, "real", phase_inventory_document(
            root, "real", artifacts,
            row_counts={"datasets": 1, "accuracy_rows": REAL_PAIR_COUNT,
                        "std128_timing_rows": 1, "std192_encoding_rows": 2,
                        "errors": 0}))
        atomic_write(root / "run.json", canonical_json(run))
        return 0
    except BaseException as exc:
        if not (real_root / "terminal.json").exists():
            _write_real_terminal(root, status="ERROR",
                                 detail=f"{type(exc).__name__}: {exc}", commands=commands)
        raise


def _write_dynamic_terminal(root: Path, *, status: str, detail: str,
                            commands: list[tuple[str, list[str]]]) -> Path:
    path = root / "dynamic" / "terminal.json"
    if path.exists():
        raise Work5Error("dynamic phase already has a terminal record")
    atomic_write(path, canonical_json({
        "schema": "piccard-work5-dynamic-terminal-v1", "status": status,
        "scenario": "refresh", "profile": DYNAMIC_PROFILE,
        "security": DYNAMIC_SECURITY, "updates": list(DYNAMIC_UPDATES),
        "trials": 1, "measurement_kind": "diagnostic",
        "commands": [{"label": label, "argv": argv} for label, argv in commands],
        "detail": detail, "ended_at_utc": utc_now(),
    }), new=True)
    return path


def _dynamic_phase_artifacts(root: Path) -> list[Path]:
    dynamic_root = root / "dynamic"
    return sorted((path for path in dynamic_root.rglob("*") if path.is_file()),
                  key=lambda path: path.as_posix())


def run_dynamic_phase(args: argparse.Namespace, root_capability: ResultsRootCapability,
                      *, deadline: float) -> int:
    """Execute the terminal TOY refresh correctness phase once, after real.

    This is a live producer solely for the future final root.  The Phase-6
    code gate tests this function with isolated fixtures and invokes
    ``bench_dynamic`` directly; it never invokes this lifecycle entrypoint.
    """
    if is_test_fixture_mode():
        raise Work5Error("fixture mode cannot produce production dynamic evidence")
    if not args.resume:
        raise Work5Error("production dynamic evidence requires --resume after real")
    root, build_dir = root_capability.root, Path(args.build_dir).resolve()
    source_provenance(deadline)
    executable_hashes = executable_map(build_dir, test_fixture=False)
    matrix = matrix_document(frozen_cells())
    run, records = resume_validate(root, build_dir, executable_hashes, matrix, deadline=deadline)
    if run.get("git_dirty"):
        raise Work5Error("production dynamic evidence requires a clean tracked source tree")
    if run.get("completed_phases") != ["toy", "parameters", "real"]:
        raise Work5Error("dynamic phase requires the exact ordered toy,parameters,real lifecycle")
    if len(records) != 61 or any(record.get("status") == "ERROR" for record in records):
        raise Work5Error("dynamic phase requires a terminal error-free parameter matrix")
    require_prior_receipt(root, run, "real", ["toy", "parameters", "real"])
    dynamic_root = root / "dynamic"
    if any(dynamic_root.iterdir()):
        raise Work5Error("dynamic phase has prior artifacts and cannot be retried or overwritten")
    commands = planned_dynamic_commands(build_dir, root)
    if len(commands) != len(DYNAMIC_UPDATES):
        raise Work5Error("dynamic phase command count is not frozen")
    for _label, argv in commands:
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise Work5Error("dynamic phase argv construction failed")
    command_path = dynamic_root / "commands.json"
    atomic_write(command_path, canonical_json({
        "schema": "piccard-work5-dynamic-command-v1",
        "commands": [{"label": label, "argv": argv} for label, argv in commands],
        "environment": command_environment(),
    }), new=True)
    validated_rows: list[dict[str, str]] = []
    try:
        for updates, (label, argv) in zip(DYNAMIC_UPDATES, commands):
            result = bounded_subprocess(argv, deadline=deadline, cwd=SOURCE_ROOT,
                                        env=process_environment())
            stdout_path, stderr_path = (dynamic_root / f"{label}.stdout",
                                        dynamic_root / f"{label}.stderr")
            atomic_write(stdout_path, result.stdout or b"", new=True)
            atomic_write(stderr_path, result.stderr or b"", new=True)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
                raise Work5Error(f"dynamic {label} subprocess failed: {detail}")
            validated_rows.append(validate_dynamic_csv(result.stdout or b"", updates))
            atomic_write(dynamic_root / f"{label}.csv", result.stdout or b"", new=True)
        if (len(validated_rows) != 2 or
                validated_rows[0]["refresh_context_fingerprint"] !=
                validated_rows[1]["refresh_context_fingerprint"] or
                validated_rows[0]["refresh_public_key_fingerprint"] ==
                validated_rows[1]["refresh_public_key_fingerprint"]):
            raise Work5Error("dynamic CSV fingerprint binding is inconsistent across commands")
        terminal = _write_dynamic_terminal(root, status="MEASURED", detail="PASS",
                                           commands=commands)
        artifacts = _dynamic_phase_artifacts(root)
        if terminal not in artifacts:
            raise Work5Error("dynamic terminal artifact is missing")
        install_phase_inventory(run, "dynamic", phase_inventory_document(
            root, "dynamic", artifacts,
            row_counts={"correctness_rows": 2, "updates_1": 1,
                        "updates_2": 1, "errors": 0}))
        atomic_write(root / "run.json", canonical_json(run))
        return 0
    except BaseException as exc:
        if not (dynamic_root / "terminal.json").exists():
            _write_dynamic_terminal(root, status="ERROR",
                                    detail=f"{type(exc).__name__}: {exc}", commands=commands)
        raise


def write_run_level_timeout(capability: ResultsRootCapability, *, phase: str,
                            phase_seconds: float, reason_code: str, detail: str) -> None:
    """Record a pre-cell deadline failure without fabricating a terminal cell."""
    if not capability.fresh:
        return
    root = capability.root
    if not capability.claimed_by_runner:
        try:
            claim_fresh_root(capability)
        except Work5Error:
            # A racer created a root after validation.  Preserve it rather
            # than treating our former absence observation as write authority.
            return
    cells = root / "cells.jsonl"
    if cells.exists() and cells.read_text(encoding="utf-8").strip():
        return
    path = root / "run-level-timeout.json"
    if path.exists():
        return
    atomic_write(path, canonical_json({
        "schema": "piccard-work5-run-level-timeout-v1",
        "phase": phase,
        "status": "ERROR",
        "reason_code": reason_code,
        "reason_detail": detail,
        "phase_timeout_seconds": phase_seconds,
        "cell_started": False,
        "recorded_at_utc": utc_now(),
    }), new=True)


def process(args: argparse.Namespace) -> int:
    # The phase clock begins before provenance, binary identity, matrix, root,
    # or metadata work.  No preflight subprocess may borrow time from it.
    test_fixture = is_test_fixture_mode()
    phase_seconds = {"toy": CELL_TIMEOUT_SECONDS, "parameters": PARAMETER_TIMEOUT_SECONDS,
                     "real": REAL_PHASE_TIMEOUT_SECONDS, "dynamic": 600,
                     "all": PARAMETER_TIMEOUT_SECONDS}[args.phase]
    if test_fixture and os.environ.get("PICCARD_WORK5_TEST_PHASE_TIMEOUT_SECONDS"):
        phase_seconds = float(os.environ["PICCARD_WORK5_TEST_PHASE_TIMEOUT_SECONDS"])
    if phase_seconds <= 0:
        raise Work5Error("parameter phase timeout must be positive")
    deadline = time.monotonic() + phase_seconds
    build_dir = Path(args.build_dir).resolve()
    root = Path(args.results_root).resolve()
    # Root admission intentionally precedes the first deadline check.  Thus an
    # already-existing fresh root cannot be changed into a timeout record merely
    # because the phase cap is already exhausted.
    root_capability = validate_results_root(root, args.resume)
    # The handler is installed before any root mutation so an interrupt cannot
    # leave a running producer without a terminal ERROR path.
    signal.signal(signal.SIGTERM, _signal_abort)
    signal.signal(signal.SIGINT, _signal_abort)
    try:
        phase_timeout(deadline)
        if args.phase == "toy":
            return run_toy_phase(args, root_capability, deadline=deadline)
        if args.phase == "real":
            return run_real_phase(args, root_capability, deadline=deadline)
        if args.phase == "dynamic":
            return run_dynamic_phase(args, root_capability, deadline=deadline)
        if args.phase != "parameters":
            raise Work5Error(f"--phase={args.phase!r} is not live yet")
        if not test_fixture and not args.resume:
            raise Work5Error("production parameter evidence requires a sealed toy phase and --resume")
        # Bind source identity before any output-root mutation.  A stalled
        # provenance command therefore produces the distinct run-level
        # terminal record rather than pretending that a parameter cell began.
        source_provenance(deadline)
        executable_hashes = executable_map(build_dir, test_fixture=test_fixture)
        phase_timeout(deadline)
        cells = frozen_cells()
        matrix = matrix_document(cells)
        phase_timeout(deadline)
        if args.resume:
            run, records = resume_validate(root, build_dir, executable_hashes, matrix,
                                           deadline=deadline)
            if not test_fixture:
                toy_path = root / "toy.json"
                if run.get("completed_phases") != ["toy"] or \
                        not toy_path.is_file() or run.get("toy_sha256") != sha256_file(toy_path):
                    raise Work5Error("production parameter evidence requires a verified terminal toy smoke")
                toy = read_json(toy_path, "toy.json")
                if toy.get("schema") != "piccard-work5-toy-v1" or toy.get("status") != "MEASURED":
                    raise Work5Error("production parameter evidence requires a measured toy smoke")
                require_prior_receipt(root, run, "toy", ["toy"])
        else:
            run = create_initial_root(root_capability, build_dir, executable_hashes, matrix,
                                     test_fixture=test_fixture, deadline=deadline)
            records = []

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

        timeout = (float(os.environ.get("PICCARD_WORK5_TEST_CELL_TIMEOUT_SECONDS", CELL_TIMEOUT_SECONDS))
                   if test_fixture else float(CELL_TIMEOUT_SECONDS))
        timeout = subprocess_wall_limit(timeout)
        if timeout <= 0:
            raise Work5Error("cell timeout must be positive")
        for cell in cells:
            if cell["cell_id"] in terminal_ids:
                continue  # terminal records are immutable and never rerun
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                started = utc_now()
                ensure_staging_directory(root, cell["cell_id"])
                argv = planned_argv(build_dir, root, cell)
                write_command_artifact(root, cell, argv)
                install_logs(root, cell, b"", b"parameter phase cap exhausted before subprocess start")
                terminalize(root, records, record_for(
                root, cell, argv, status="ERROR", reason_code="PHASE_CAP_EXHAUSTED",
                    reason_detail=f"parameter phase cap exhausted ({phase_seconds:g} seconds)",
                    flags=stage_values(True, False, False, False, False), exit_code=124,
                    started=started))
                run["cells_sha256"] = sha256_file(root / "cells.jsonl")
                atomic_write(root / "run.json", canonical_json(run))
                raise Work5Error("terminal ERROR/PHASE_CAP_EXHAUSTED: parameter phase cap")
            try:
                run_parameter_cell(build_dir, root, cell, records, test_fixture=test_fixture,
                                   timeout=timeout, deadline=deadline)
            except Work5Error:
                run["cells_sha256"] = sha256_file(root / "cells.jsonl")
                atomic_write(root / "run.json", canonical_json(run))
                raise
            terminal_ids.add(cell["cell_id"])
            run["cells_sha256"] = sha256_file(root / "cells.jsonl")
            atomic_write(root / "run.json", canonical_json(run))

        if len(records) != len(cells):
            raise Work5Error("parameter phase ended with PENDING cells")
        if any(record["status"] == "ERROR" for record in records):
            raise Work5Error("parameter phase contains terminal ERROR")
        if "parameters" not in run["completed_phases"]:
            parameter_paths: list[Path] = [root / "cells.jsonl"]
            for record in records:
                for label in ("command", "stdout", "stderr", "context_onehot",
                              "context_sqrt", "context_fhe_ind", "workload", "trace", "csv"):
                    relative = record.get(f"{label}_path")
                    if relative is not None:
                        parameter_paths.append(root / relative)
            status_counts = {status: sum(record["status"] == status for record in records)
                             for status in ("MEASURED", "SKIPPED_PRECHECK", "ERROR")}
            install_phase_inventory(run, "parameters", phase_inventory_document(
                root, "parameters", parameter_paths,
                row_counts={"terminal_cells": len(records),
                            "measured": status_counts["MEASURED"],
                            "skipped": status_counts["SKIPPED_PRECHECK"],
                            "errors": status_counts["ERROR"]}))
            atomic_write(root / "run.json", canonical_json(run))
        return 0
    except (PhaseBudgetExpired, SubprocessTimedOut) as exc:
        reason_code = timeout_reason_code(exc)
        detail = (str(exc) if reason_code == "PHASE_CAP_EXHAUSTED" else
                  f"subprocess wall timeout before any cell began: {exc}")
        write_run_level_timeout(root_capability, phase=args.phase, phase_seconds=phase_seconds,
                                reason_code=reason_code, detail=detail)
        raise


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
