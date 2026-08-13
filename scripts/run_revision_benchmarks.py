#!/usr/bin/env python3
"""Run or dry-plan the versioned Piccard revision benchmark matrix.

The runner is an orchestration boundary.  It never constructs an FHE context
itself and it does not derive a second experiment matrix.  A dry-run is
strictly no-spawn; toy mode selects the frozen 104-cell readiness inventory
and projects every measured count to one, with one discarded warmup call.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from revision_benchmark_common import (  # noqa: E402
    MATRIX_DEFAULT,
    PHASES,
    RevisionContractError,
    TOY_PROFILE,
    append_jsonl,
    canonical_json,
    canonical_plan_argv,
    cell_output,
    command_for_cell,
    binary_metadata,
    expected_row_count,
    file_inventory,
    load_matrix,
    materialize_cell_argv,
    phase_for_cell,
    producer_extra_args,
    select_cells,
    sha256_file,
    source_metadata,
    tool_metadata,
    write_json,
)


SCHEMA = "piccard-revision-readiness-run-v1"
CELL_SCHEMA = "piccard-revision-cell-receipt-v1"
EVENT_SCHEMA = "piccard-revision-event-v1"


def _fail(message: str) -> "NoReturn":
    raise RevisionContractError(message)


def _absolute_directory(value: str, label: str, *, must_exist: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        _fail(f"{label} must be an absolute path")
    if path.is_symlink():
        _fail(f"{label} must not be a symlink")
    if must_exist and not path.is_dir():
        _fail(f"{label} must be an existing directory")
    return path.resolve()


def _fresh_results_root(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        _fail("results-root must be an absolute path")
    if path.exists() or path.is_symlink():
        _fail("results-root must be a fresh absent directory")
    if not path.parent.is_dir() or path.parent.is_symlink():
        _fail("results-root parent must be an existing non-symlink directory")
    return path.resolve()


def _parse_positive(value: str, label: str) -> int:
    try:
        number = int(value, 10)
    except ValueError as exc:
        _fail(f"{label} must be a positive integer")
    if number <= 0 or str(number) != value:
        _fail(f"{label} must be a positive integer")
    return number


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_toy_manifests(results_root: Path) -> tuple[dict[str, Path], Path]:
    """Create bounded, non-maildir fixture manifests for readiness-only runs.

    DBLP is copied byte-for-byte.  Enron is prepared from the tracked tiny RFC
    fixture using the production preprocessor, so its manifest/drop keys,
    labels, pair kinds, and digests are real Enron contracts.  The actual
    untracked maildir is never read.
    """
    source = ROOT / "tests" / "fixtures" / "real_datasets" / "quick" / "dblp_acm_u65536"
    if not source.is_dir():
        _fail("bounded real-data fixture is missing")
    manifests: dict[str, Path] = {}
    destination_root = results_root / "toy-input"
    destination = destination_root / "dblp_acm_u65536"
    shutil.copytree(source, destination)
    manifests["dblp_acm_u65536"] = destination / "dataset.manifest.tsv"
    enron_source = (ROOT / "tests" / "fixtures" / "real_datasets" /
                    "enron_maildir" / "source.manifest.tsv")
    for universe in (65536, 1048576):
        variant = f"enron_u{universe}"
        destination = destination_root / variant
        command = [
            sys.executable, str(SCRIPT_DIR / "prepare_real_datasets.py"),
            "enron", "--source-manifest", str(enron_source),
            "--output-dir", str(destination), "--universe", str(universe),
            "--max-documents", "7", "--pairs", "4",
            "--min-related-pairs", "1", "--seed", "7", "--strict",
        ]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                   text=True, check=False)
        if completed.returncode != 0:
            _fail("tracked Enron toy fixture preparation failed: " +
                  completed.stderr.strip())
        manifests[variant] = destination / "dataset.manifest.tsv"
    return manifests, manifests["dblp_acm_u65536"]


def _script_hashes() -> dict[str, str]:
    names = (
        "revision_benchmark_common.py", "run_revision_benchmarks.py",
        "verify_revision_benchmarks.py", "seal_revision_benchmarks.py",
        "validate_revision_matrix.py",
    )
    result: dict[str, str] = {}
    for name in names:
        path = SCRIPT_DIR / name
        if path.is_file():
            result[name] = sha256_file(path)
    return result


def _materialized_command(
    cell: dict[str, Any], mode: str, *, root: Path, build_dir: Path,
    seed: int, threads: int, variant_manifests: dict[str, Path],
    dblp_manifest: Path,
) -> tuple[list[str], list[str]]:
    """Build one command while reserving cell output for lifecycle evidence.

    In particular, flooding's wrapper receives ``cell_output/payload`` as its
    ``--results-root``.  The cell directory itself is created for stdout,
    stderr, and receipt files; the absent payload child is owned by the
    wrapper.
    """
    canonical = canonical_plan_argv(cell, mode)
    output = cell_output(root, cell["cell_id"])
    output.mkdir(parents=True, exist_ok=True)
    argv = materialize_cell_argv(
        cell, mode, root=root, output=output, seed=seed, threads=threads,
        variant_manifests=variant_manifests, dblp_manifest=dblp_manifest)
    argv.extend(producer_extra_args(cell, output))
    command = command_for_cell(cell, root=root, build_dir=build_dir)
    return canonical, command + argv


def _write_initial_manifest(
    root: Path, *, mode: str, seed: int, threads: int, matrix_path: Path,
    matrix_sha: str, cells: list[dict[str, Any]], source: dict[str, Any],
    binaries: dict[str, Any], scripts: dict[str, str], tools: dict[str, str],
    build_dir: Path, variant_manifests: dict[str, Path], dblp_manifest: Path,
) -> dict[str, Any]:
    phases = {phase: "PENDING" for phase in PHASES}
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "version": 1,
        "mode": mode,
        "profile": TOY_PROFILE if mode == "toy" else "paper-v1",
        "seed": seed,
        "threads": threads,
        "warmup_calls": 1,
        "matrix_path": str(matrix_path),
        "matrix_sha256": matrix_sha,
        "cell_count": len(cells),
        "cell_ids": [cell["cell_id"] for cell in cells],
        "phase_order": list(PHASES),
        "phase_status": phases,
        "state": "PLANNED",
        "spawned_processes": 0,
        "planned_processes": sum(
            cell["invocation_status"] == "RUN" for cell in cells),
        "toy_measured_count": sum(expected_row_count(cell, mode) for cell in cells),
        "performance_status": (
            "PAPER_PERFORMANCE_PENDING" if mode == "toy" else "UNSET"),
        "readiness_status": "READINESS_ONLY" if mode == "toy" else "UNSET",
        "source": source,
        "binaries": binaries,
        "scripts": scripts,
        "tools": tools,
        "build_dir": str(build_dir.resolve()),
        "input_bindings": {
            "variant_manifests": {key: str(value.resolve()) for key, value in
                                  sorted(variant_manifests.items())},
            "dblp_manifest": str(dblp_manifest.resolve()),
        },
    }
    write_json(root / "run.json", manifest)
    return manifest


def _binary_metadata(build_dir: Path, cells: list[dict[str, Any]]) -> dict[str, Any]:
    # Keep this compatibility shim for callers/tests while sharing the exact
    # logical-producer registry with independent verification.
    return binary_metadata(build_dir, cells)


def _event(root: Path, sequence: int, event: str, **fields: Any) -> None:
    append_jsonl(root / "events.jsonl", {
        "schema": EVENT_SCHEMA, "version": 1, "sequence": sequence,
        "event": event, "time_ns": time.time_ns(), **fields,
    })


def _phase(root: Path, manifest: dict[str, Any], phase: str,
           state: str, *, reason: str = "") -> None:
    manifest["phase_status"][phase] = state
    write_json(root / "run.json", manifest)
    append_jsonl(root / "phases.jsonl", {
        "schema": "piccard-revision-phase-v1", "phase": phase,
        "state": state, "reason": reason,
        "index": PHASES.index(phase), "time_ns": time.time_ns(),
    })


def _record_plans(root: Path, plans: list[dict[str, Any]]) -> None:
    path = root / "planned_argv.jsonl"
    for plan in plans:
        append_jsonl(path, plan)


def _run_one(
    *, root: Path, manifest: dict[str, Any], plan: dict[str, Any],
    command: list[str], mode: str,
) -> None:
    cell_id = plan["cell_id"]
    output = Path(plan["output_dir"])
    stdout = output / "stdout.log"
    stderr = output / "stderr.log"
    stdout.parent.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, Any] = {
        "schema": CELL_SCHEMA, "version": 1,
        "cell_id": cell_id, "family": plan["family"],
        "producer": plan["producer"], "phase": plan["phase"],
        "invocation_status": plan["invocation_status"],
        "expected_artifact_schema": plan["expected_artifact_schema"],
        "expected_rows": plan["expected_rows"],
        "canonical_argv": plan["canonical_argv"], "argv": plan["argv"],
        "warmup_calls": 1, "mode": mode,
    }
    if plan["invocation_status"] == "NO_SPAWN":
        stdout.write_text("", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        receipt.update({"execution_status": "NO_SPAWN", "exit_code": 0,
                        "stdout": {"path": str(stdout.relative_to(root)),
                                   "sha256": sha256_file(stdout)},
                        "stderr": {"path": str(stderr.relative_to(root)),
                                   "sha256": sha256_file(stderr)},
                        "artifact_inventory": []})
        write_json(output / "receipt.json", receipt)
        return
    if mode == "dry-run":
        stdout.write_text("PLANNED\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        receipt.update({"execution_status": "PLANNED", "exit_code": None,
                        "stdout": {"path": str(stdout.relative_to(root)),
                                   "sha256": sha256_file(stdout)},
                        "stderr": {"path": str(stderr.relative_to(root)),
                                   "sha256": sha256_file(stderr)},
                        "artifact_inventory": []})
        write_json(output / "receipt.json", receipt)
        return

    sequence = int(manifest.get("event_sequence", 0)) + 1
    manifest["event_sequence"] = sequence
    _event(root, sequence, "START", cell_id=cell_id,
           argv=command, stdout=str(stdout.relative_to(root)),
           stderr=str(stderr.relative_to(root)))
    start_ns = time.time_ns()
    environment = os.environ.copy()
    environment.update({"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(manifest["threads"]),
                        "PICCARD_REVISION_CELL": cell_id,
                        "PICCARD_REVISION_MODE": mode})
    try:
        with stdout.open("wb") as out, stderr.open("wb") as err:
            completed = subprocess.run(
                command, cwd=ROOT, env=environment, stdout=out, stderr=err,
                check=False,
                timeout=plan["timeout_seconds"],
            )
        exit_code = int(completed.returncode)
    except subprocess.TimeoutExpired:
        exit_code = -124
    end_ns = time.time_ns()
    sequence += 1
    manifest["event_sequence"] = sequence
    _event(root, sequence, "END", cell_id=cell_id, exit_code=exit_code,
           start_ns=start_ns, end_ns=end_ns,
           stdout_path=str(stdout.relative_to(root)),
           stderr_path=str(stderr.relative_to(root)),
           stdout_sha256=sha256_file(stdout), stderr_sha256=sha256_file(stderr))
    receipt.update({
        "execution_status": "COMPLETED" if exit_code == 0 else "FAILED",
        "exit_code": exit_code, "start_event_sequence": sequence - 1,
        "end_event_sequence": sequence,
        "stdout": {"path": str(stdout.relative_to(root)),
                   "sha256": sha256_file(stdout)},
        "stderr": {"path": str(stderr.relative_to(root)),
                   "sha256": sha256_file(stderr)},
        "artifact_inventory": file_inventory(output, exclude={"stdout.log", "stderr.log", "receipt.json"}),
    })
    write_json(output / "receipt.json", receipt)
    if exit_code != 0:
        _fail(f"producer failed for {cell_id} with exit code {exit_code}; evidence preserved")
    manifest["spawned_processes"] += 1


def _load_verify_and_seal(root: Path, mode: str) -> None:
    from verify_revision_benchmarks import verify_root
    from seal_revision_benchmarks import create_seal
    verify_root(root, mode=mode, write_receipt=True,
                lifecycle_stage="verification")
    manifest = json.loads((root / "run.json").read_text(encoding="utf-8"))
    _phase(root, manifest, "verification", "COMPLETED")
    _phase(root, manifest, "seal", "STARTED")
    manifest["state"] = "COMPLETED"
    write_json(root / "run.json", manifest)
    create_seal(root)


def run(args: argparse.Namespace) -> int:
    mode = args.mode
    if mode not in {"toy", "dry-run", "paper"}:
        _fail("mode must be toy, dry-run, or paper")
    if mode == "paper" and not args.authorize_paper_run:
        _fail("paper mode requires the explicit --authorize-paper-run token")
    build_dir = _absolute_directory(args.build_dir, "build-dir", must_exist=True)
    results_root = _fresh_results_root(args.results_root)
    seed = _parse_positive(args.seed, "seed")
    threads = _parse_positive(args.threads, "threads")
    matrix_path = Path(args.matrix)
    if not matrix_path.is_absolute():
        _fail("matrix must be an absolute path")

    document, matrix_sha = load_matrix(matrix_path)
    cells = select_cells(document, mode)
    source = source_metadata(ROOT)
    if mode in {"toy", "paper"} and source.get("dirty"):
        _fail("executable revision runs require a tracked-clean source tree")
    results_root.mkdir()
    _fsync_directory(results_root.parent)
    try:
        (results_root / "canonical").mkdir()
        (results_root / "canonical" / "revision_matrix.json").write_bytes(
            matrix_path.read_bytes())
        variant_manifests, dblp_manifest = _copy_toy_manifests(results_root)
        binaries = _binary_metadata(build_dir, cells)
        manifest = _write_initial_manifest(
            results_root, mode=mode, seed=seed, threads=threads,
            matrix_path=matrix_path, matrix_sha=matrix_sha, cells=cells,
            source=source, binaries=binaries,
            scripts=_script_hashes(), tools=tool_metadata(build_dir),
            build_dir=build_dir, variant_manifests=variant_manifests,
            dblp_manifest=dblp_manifest)
        if mode in {"toy", "paper"}:
            missing = sorted(name for name, item in binaries.items()
                             if item.get("sha256") == "MISSING")
            if missing:
                _fail("executable revision run has missing producers: " +
                      ",".join(missing))
        plans: list[dict[str, Any]] = []
        for cell in cells:
            canonical, command = _materialized_command(
                cell, mode, root=results_root, build_dir=build_dir, seed=seed,
                threads=threads, variant_manifests=variant_manifests,
                dblp_manifest=dblp_manifest)
            output = cell_output(results_root, cell["cell_id"])
            plans.append({
                "schema": "piccard-revision-planned-cell-v1", "version": 1,
                "cell_id": cell["cell_id"], "family": cell["family"],
                "phase": phase_for_cell(cell), "producer": cell["producer"],
                "invocation_status": cell["invocation_status"],
                "expected_artifact_schema": cell["expected_artifact_schema"],
                "expected_rows": cell["expected_rows"],
                "canonical_argv": canonical, "argv": command[1:] if command and command[0] == sys.executable else command,
                "command": command, "output_dir": str(output),
                "timeout_seconds": 3600 if cell["timeout_class"] == "extended" else 600,
            })
        _record_plans(results_root, plans)
        manifest["state"] = "RUNNING"
        write_json(results_root / "run.json", manifest)
        event_sequence = 0
        for phase in PHASES:
            if mode != "dry-run" and phase in {"verification", "seal"}:
                continue
            _phase(results_root, manifest, phase, "STARTED")
            if phase in {"preflight", "verification", "seal"}:
                _phase(results_root, manifest, phase, "COMPLETED")
                continue
            for plan in [item for item in plans if item["phase"] == phase]:
                _run_one(root=results_root, manifest=manifest, plan=plan,
                         command=plan["command"], mode=mode)
            _phase(results_root, manifest, phase, "COMPLETED")
        manifest["state"] = "COMPLETED" if mode == "dry-run" else "VERIFYING"
        manifest["event_sequence"] = int(manifest.get("event_sequence", event_sequence))
        if mode == "toy":
            manifest["performance_status"] = "PAPER_PERFORMANCE_PENDING"
            manifest["readiness_status"] = "READINESS_ONLY"
        elif mode == "paper":
            manifest["performance_status"] = "PAPER_PERFORMANCE_RECORDED"
        write_json(results_root / "run.json", manifest)
        if mode != "dry-run":
            _phase(results_root, manifest, "verification", "STARTED")
            _load_verify_and_seal(results_root, mode)
        print(f"revision {mode}: {len(cells)} cells; spawned={manifest['spawned_processes']}")
        return 0
    except Exception as exc:
        try:
            if (results_root / "run.json").is_file():
                failed = json.loads((results_root / "run.json").read_text(encoding="utf-8"))
                failed["state"] = "FAILED"
                failed["failure"] = str(exc)
                write_json(results_root / "run.json", failed)
        except Exception:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True,
                        choices=("toy", "dry-run", "paper"))
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--threads", required=True)
    parser.add_argument("--matrix", default=str(MATRIX_DEFAULT))
    parser.add_argument("--authorize-paper-run", action="store_true",
                        help="required explicit token for paper mode")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except RevisionContractError as exc:
        print(f"run_revision_benchmarks: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"run_revision_benchmarks: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
