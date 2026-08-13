#!/usr/bin/env python3
"""Independent, fail-closed verifier for a revision readiness root.

The verifier never trusts a runner-side cell list or summary.  It reloads the
canonical matrix, reconstructs the selected inventory and expected argv, and
then checks receipts, event ordering, source/tool hashes, status taxonomy and
the no-paper/no-Enron-toy boundary.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
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
    materialize_argv,
    command_for_producer,
    tool_metadata,
)


VERIFICATION_SCHEMA = "piccard-revision-verification-receipt-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _check_source_and_tools(manifest: dict[str, Any], root: Path, cells: list[dict[str, Any]]) -> None:
    source = manifest.get("source")
    if not isinstance(source, dict) or source != source_metadata(ROOT):
        fail("source commit/dirty metadata changed")
    scripts = manifest.get("scripts")
    if scripts != script_hashes():
        fail("runner/verifier/script hash metadata changed")
    build_dir = Path(manifest.get("build_dir", ""))
    if manifest.get("tools") != tool_metadata(build_dir):
        fail("compiler/CMake/OpenFHE tool metadata changed")
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
        materialized = materialize_argv(
            canonical, root=root, output=output_dir,
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


def _check_family_artifacts(root: Path, mode: str, cells: list[dict[str, Any]],
                            plans: dict[str, dict[str, Any]]) -> None:
    """Validate producer evidence independently of runner inventories.

    Each matrix schema must be explicitly registered.  Generic CSV producers
    must emit non-empty evidence containing every terminal method/status token;
    the real-data summary is stronger: it is recomputed byte-for-byte from its
    bound accuracy CSV using the checked-in summarizer.
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
        evidence_paths = [output / "stdout.log", output / "stderr.log"]
        evidence = b"".join(path.read_bytes() for path in evidence_paths
                            if path.is_file())
        for item in receipt.get("artifact_inventory", []):
            path = output / item["path"]
            if path.is_file():
                evidence += path.read_bytes()
        if not evidence.strip():
            fail(f"producer evidence is empty for {cid}")
        is_summary = (cell["family"] == "real_dataset" and
                      str(cell["axis_value"]) == "summary")
        for row in cell["expected_rows"] if not is_summary else []:
            tokens = [str(row.get("method", ""))]
            if row.get("terminal_status") == "NOT_APPLICABLE":
                tokens.extend(("NOT_APPLICABLE", str(row.get("reason_code", ""))))
            for token in tokens:
                if token and token.encode("utf-8") not in evidence:
                    fail(f"producer evidence lacks terminal token {token!r} for {cid}")

        if is_summary:
            argv = plans[cid]["command"]
            def option(prefix: str) -> Path:
                values = [Path(arg[len(prefix):]) for arg in argv if arg.startswith(prefix)]
                if len(values) != 1:
                    fail(f"summary plan lacks exactly one {prefix} binding")
                return values[0]
            accuracy = option("--accuracy-csv=")
            actual = option("--output=")
            variant_values = [arg.split("=", 1)[1] for arg in argv
                              if arg.startswith("--variant=")]
            if len(variant_values) != 1:
                fail("summary plan lacks one variant binding")
            with tempfile.TemporaryDirectory(prefix="piccard-summary-verify.") as temporary:
                verify_cells = Path(temporary) / "cells"
                verify_accuracy = verify_cells / accuracy.parent.name / "accuracy.csv"
                verify_accuracy.parent.mkdir(parents=True)
                verify_accuracy.write_bytes(accuracy.read_bytes())
                recomputed = verify_cells / output.name / "summary.csv"
                recomputed.parent.mkdir(parents=True)
                command = [sys.executable, str(ROOT / "scripts" / "summarize_real_datasets.py"),
                           f"--revision-cell={cid}", f"--accuracy-csv={verify_accuracy}",
                           f"--output={recomputed}", f"--variant={variant_values[0]}"]
                completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                           text=True, check=False)
                if completed.returncode != 0 or not actual.is_file() or \
                        actual.read_bytes() != recomputed.read_bytes():
                    fail(f"real summary artifact is not independently reproducible: {cid}")


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
    _check_source_and_tools(manifest, root, cells)
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
