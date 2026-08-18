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
    dry_run_source_metadata,
    dry_run_tool_metadata,
    expected_row_count,
    file_inventory,
    load_matrix,
    materialize_cell_argv,
    phase_for_cell,
    producer_extra_args,
    validate_paper_manifest_bindings,
    select_cells,
    sha256_bytes,
    sha256_file,
    source_metadata,
    tool_metadata,
    write_json,
)


SCHEMA = "piccard-revision-readiness-run-v1"
CELL_SCHEMA = "piccard-revision-cell-receipt-v1"
EVENT_SCHEMA = "piccard-revision-event-v1"
RESUME_SCHEMA = "piccard-revision-resume-v1"
RESUME_EVENT_SCHEMA = "piccard-revision-resume-event-v1"
SUPERSEDED_DIR = "superseded"
EXECUTABLE_PHASES = tuple(phase for phase in PHASES
                          if phase not in {"verification", "seal"})


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


def _resumable_results_root(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        _fail("results-root must be an absolute path")
    if path.is_symlink():
        _fail("results-root must not be a symlink")
    if not path.is_dir():
        _fail("--resume requires an existing results-root directory")
    if not (path / "run.json").is_file():
        _fail("--resume requires a results-root that already holds run.json")
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


def _dry_run_manifest_bindings(results_root: Path) -> tuple[dict[str, Path], Path]:
    """Return path-only bindings for the static no-spawn dry plan.

    Dry-run must describe where executable modes *would* consume processed
    manifests without constructing a toy input tree or invoking a preprocessor.
    These paths are deliberately absent placeholders under the result root;
    only command materialization records them.  Toy mode continues to use the
    bounded, real-grammar fixtures from :func:`_copy_toy_manifests`.
    """
    binding_root = results_root / "planned-inputs"
    variants = {
        variant: binding_root / variant / "dataset.manifest.tsv"
        for variant in ("dblp_acm_u65536", "enron_u65536", "enron_u1048576")
    }
    return variants, variants["dblp_acm_u65536"]


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


def _timeout_seconds(timeout_class: str) -> int:
    if timeout_class == "standard":
        return 600
    if timeout_class == "extended":
        return 3600
    if timeout_class == "long":
        return 64800
    _fail(f"unsupported revision timeout class: {timeout_class}")


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
        "timeout_class": plan["timeout_class"],
        "timeout_seconds": plan["timeout_seconds"],
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


def _read_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        _fail(f"resume refused: {label} is missing")
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            _fail(f"resume refused: {label} holds a truncated or malformed record")
        if not isinstance(value, dict):
            _fail(f"resume refused: {label} holds a non-object record")
        records.append(value)
    return records


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    payload = b"".join(canonical_json(record) for record in records)
    with path.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _provenance(values: dict[str, Any]) -> dict[str, Any]:
    return {key: values.get(key) for key in
            ("source", "scripts", "tools", "binaries")}


def _provenance_digest(provenance: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(provenance))


def _require_identical_provenance(
    manifest: dict[str, Any], *, build_dir: Path, cells: list[dict[str, Any]],
) -> dict[str, Any]:
    """Refuse to resume across any change of source, scripts, tools, or binaries.

    Independent verification re-derives all four registries live and compares
    them to ``run.json`` for whole-dictionary equality, so a root resumed after
    a rebuild can never verify.  More importantly, a paper measurement whose
    cells came from two different binaries is not one measurement.  The runner
    therefore refuses first and names the registry that moved, rather than
    letting the operator spend hours on a root the verifier will reject.
    """
    live = {
        "source": source_metadata(ROOT),
        "scripts": _script_hashes(),
        "tools": tool_metadata(build_dir),
        "binaries": binary_metadata(build_dir, cells),
    }
    recorded = _provenance(manifest)
    for key, value in live.items():
        if recorded.get(key) != value:
            _fail(f"resume refused: recorded {key} provenance differs from the "
                  f"current tree and build; a resumed run may not mix builds. "
                  f"Rebuilding or editing tracked sources ends the run's "
                  f"provenance: start a fresh results-root instead")
    return live


def _require_resumable_manifest(
    root: Path, *, mode: str, seed: int, threads: int, matrix_path: Path,
    matrix_sha: str, cells: list[dict[str, Any]], build_dir: Path,
) -> dict[str, Any]:
    """Bind a resume to exactly the run that produced the existing evidence."""
    if mode == "dry-run":
        _fail("--resume is not applicable to dry-run: a dry plan is a static "
              "projection with no partial execution to continue")
    for name in ("seal.json", "seal.json.sha256"):
        if (root / name).exists() or (root / name).is_symlink():
            _fail("resume refused: the results root is sealed and terminal")
    if (root / "verification" / "receipt.json").is_file():
        _fail("resume refused: the results root already carries a verification "
              "receipt")
    try:
        manifest = json.loads((root / "run.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"resume refused: run manifest is unreadable: {exc}")
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        _fail("resume refused: run manifest schema mismatch")
    if manifest.get("state") == "COMPLETED":
        _fail("resume refused: the recorded run already completed")
    identity: tuple[tuple[str, Any, Any], ...] = (
        ("mode", manifest.get("mode"), mode),
        ("seed", manifest.get("seed"), seed),
        ("threads", manifest.get("threads"), threads),
        ("matrix_path", manifest.get("matrix_path"), str(matrix_path)),
        ("matrix_sha256", manifest.get("matrix_sha256"), matrix_sha),
        ("cell_count", manifest.get("cell_count"), len(cells)),
        ("cell_ids", manifest.get("cell_ids"),
         [cell["cell_id"] for cell in cells]),
        ("build_dir", manifest.get("build_dir"), str(build_dir.resolve())),
        ("phase_order", manifest.get("phase_order"), list(PHASES)),
        ("warmup_calls", manifest.get("warmup_calls"), 1),
        ("profile", manifest.get("profile"),
         TOY_PROFILE if mode == "toy" else "paper-v1"),
    )
    for label, recorded, expected in identity:
        if recorded != expected:
            _fail(f"resume refused: recorded {label} does not match this "
                  f"invocation")
    return manifest


def _resume_input_bindings(
    manifest: dict[str, Any], mode: str,
    variant_manifests: dict[str, Path] | None, dblp_manifest: Path | None,
) -> tuple[dict[str, Path], Path]:
    """Reuse the exact dataset bindings the original attempt recorded.

    Toy mode must never re-prepare ``toy-input``: the Enron fixture is produced
    by a subprocess and any byte drift would break the per-cell dataset digests
    already recorded in completed receipts.  Paper mode keeps its explicit CLI
    bindings but must point at the same files.
    """
    bindings = manifest.get("input_bindings")
    if not isinstance(bindings, dict):
        _fail("resume refused: run manifest has no input bindings")
    recorded_variants = bindings.get("variant_manifests")
    recorded_dblp = bindings.get("dblp_manifest")
    if not isinstance(recorded_variants, dict) or not isinstance(recorded_dblp, str):
        _fail("resume refused: run manifest input bindings are malformed")
    if mode == "paper":
        assert variant_manifests is not None and dblp_manifest is not None
        supplied = {key: str(value.resolve())
                    for key, value in sorted(variant_manifests.items())}
        if supplied != recorded_variants or str(dblp_manifest.resolve()) != recorded_dblp:
            _fail("resume refused: the supplied paper dataset bindings differ "
                  "from the ones the recorded run used")
    resolved = {key: Path(value) for key, value in recorded_variants.items()}
    for variant, path in sorted(resolved.items()):
        if path.is_symlink() or not path.is_file():
            _fail(f"resume refused: bound dataset manifest for {variant} is "
                  f"missing or is a symlink")
    return resolved, Path(recorded_dblp)


def _require_recorded_plans(root: Path, plans: list[dict[str, Any]]) -> None:
    """Refuse when the plan this invocation derives is not the recorded plan.

    ``planned_argv.jsonl`` must keep exactly one record per cell for
    verification to pass, so resume never re-plans.  Instead it re-derives the
    plan and demands byte equality with what is already on disk.
    """
    recorded = _read_jsonl(root / "planned_argv.jsonl", "planned argv stream")
    if recorded != plans:
        _fail("resume refused: the recorded plan inventory does not match the "
              "plan this invocation derives")


def _cell_is_complete(
    root: Path, plan: dict[str, Any], cell: dict[str, Any],
    events: list[dict[str, Any]],
) -> bool:
    """Re-derive, rather than trust, one cell's completion record.

    Every predicate here is one the independent verifier also applies, so a
    cell accepted as complete is a cell the final verification pass will accept
    without re-running it.  Re-hashing a cell's own evidence costs milliseconds
    against benchmark cells that cost minutes to hours, so resume never trusts
    a receipt's self-report alone.
    """
    output = Path(plan["output_dir"])
    receipt_path = output / "receipt.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return False
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(receipt, dict):
        return False
    no_spawn = cell["invocation_status"] == "NO_SPAWN"
    if (receipt.get("schema") != CELL_SCHEMA or
            receipt.get("cell_id") != cell["cell_id"] or
            receipt.get("execution_status") != ("NO_SPAWN" if no_spawn else "COMPLETED") or
            receipt.get("canonical_argv") != plan["canonical_argv"] or
            receipt.get("timeout_class") != plan["timeout_class"] or
            receipt.get("timeout_seconds") != plan["timeout_seconds"] or
            receipt.get("expected_rows") != cell["expected_rows"]):
        return False
    for label in ("stdout", "stderr"):
        item = receipt.get(label)
        if not isinstance(item, dict):
            return False
        candidate = root / str(item.get("path", ""))
        if candidate.is_symlink() or not candidate.is_file():
            return False
        if sha256_file(candidate) != item.get("sha256"):
            return False
    inventory = file_inventory(
        output, exclude={"stdout.log", "stderr.log", "receipt.json"})
    if inventory != receipt.get("artifact_inventory"):
        return False
    if no_spawn:
        return not events
    if len(events) != 2 or events[0].get("event") != "START" or \
            events[1].get("event") != "END":
        return False
    return (events[0].get("argv") == plan["command"] and
            events[1].get("exit_code") == 0)


def _resume_phase_index(plans: list[dict[str, Any]], complete: set[str]) -> int:
    """Return the first executable phase index that still owes a cell."""
    for phase in EXECUTABLE_PHASES:
        if any(plan["cell_id"] not in complete for plan in plans
               if plan["phase"] == phase):
            return PHASES.index(phase)
    return PHASES.index("verification")


def _prepare_resume(
    root: Path, *, manifest: dict[str, Any], plans: list[dict[str, Any]],
    cells: list[dict[str, Any]], provenance: dict[str, Any],
) -> tuple[set[str], int]:
    """Reduce a crashed root to a consistent prefix and report what remains.

    Independent verification requires a globally contiguous event sequence with
    exactly one zero-exit START/END pair per executed cell, an exact phase state
    machine, and a per-cell artifact inventory equal to the cell directory byte
    for byte.  A crashed attempt violates all three, so resume rewrites the
    evidence down to the cells it could independently re-derive as complete.
    Nothing is destroyed: every discarded record and cell directory is moved
    under ``superseded/`` first, keeping the codebase's evidence-preserving
    failure contract.
    """
    cells_by_id = {cell["cell_id"]: cell for cell in cells}
    events = _read_jsonl(root / "events.jsonl", "event stream") \
        if (root / "events.jsonl").is_file() else []
    events_by_cell: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        events_by_cell.setdefault(str(event.get("cell_id")), []).append(event)

    complete = {
        plan["cell_id"] for plan in plans
        if _cell_is_complete(root, plan, cells_by_id[plan["cell_id"]],
                             events_by_cell.get(plan["cell_id"], []))
    }
    discarded = sorted(plan["cell_id"] for plan in plans
                       if plan["cell_id"] not in complete
                       and Path(plan["output_dir"]).is_dir()
                       and any(Path(plan["output_dir"]).iterdir()))
    resume_index = _resume_phase_index(plans, complete)

    attempt_number = int(
        (manifest.get("resume") or {}).get("resume_count", 0)) + 1
    archive = root / SUPERSEDED_DIR / f"attempt-{attempt_number}"
    if archive.exists() or archive.is_symlink():
        # The attempt counter only advances once a resume finishes rewriting
        # the evidence, so a collision means an earlier resume died mid-repair
        # and the root's state is unknown.  Refuse rather than overwrite it.
        _fail(f"resume refused: {archive.name} already exists under "
              f"{SUPERSEDED_DIR}/; a previous resume did not finish and the "
              f"root must be triaged by hand")
    archive.mkdir(parents=True)

    # Phase stream: keep exactly the canonical prefix of the phases whose cells
    # are all complete.  This is pure truncation -- resume never synthesizes a
    # phase record for a phase that did not actually run.
    phase_records = _read_jsonl(root / "phases.jsonl", "phase stream")
    expected_prefix = [(phase, state) for phase in PHASES[:resume_index]
                       for state in ("STARTED", "COMPLETED")]
    observed = [(record.get("phase"), record.get("state"))
                for record in phase_records]
    if observed[:len(expected_prefix)] != expected_prefix:
        _fail("resume refused: the recorded phase stream does not contain the "
              "completed-phase prefix this evidence implies")
    dropped_phases = phase_records[len(expected_prefix):]
    _write_jsonl(archive / "phases-dropped.jsonl", dropped_phases)
    _write_jsonl(root / "phases.jsonl", phase_records[:len(expected_prefix)])

    # Event stream: keep only the pairs belonging to cells that survived, in
    # their original order, renumbered so the sequence stays contiguous from 1.
    kept_events = [event for event in events
                   if str(event.get("cell_id")) in complete]
    _write_jsonl(archive / "events-dropped.jsonl",
                 [event for event in events
                  if str(event.get("cell_id")) not in complete])
    for sequence, event in enumerate(kept_events, start=1):
        event["sequence"] = sequence
    _write_jsonl(root / "events.jsonl", kept_events)

    # Renumbering the surviving events invalidates the sequence bindings that
    # the surviving receipts recorded, and the verifier cross-checks them.
    renumbered: dict[str, list[int]] = {}
    for event in kept_events:
        renumbered.setdefault(str(event["cell_id"]), []).append(event["sequence"])
    for plan in plans:
        cell_id = plan["cell_id"]
        if cell_id not in complete or cell_id not in renumbered:
            continue
        receipt_path = Path(plan["output_dir"]) / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        start, end = renumbered[cell_id]
        if (receipt.get("start_event_sequence"), receipt.get("end_event_sequence")) \
                != (start, end):
            receipt["start_event_sequence"] = start
            receipt["end_event_sequence"] = end
            write_json(receipt_path, receipt)

    # Stale partial artifacts from the crashed attempt would fail both the
    # per-cell inventory equality and the family artifact allowlists, and the
    # flooding wrapper additionally requires its payload root to be absent.
    # Every incomplete cell therefore restarts from an empty directory.
    for plan in plans:
        output = Path(plan["output_dir"])
        if plan["cell_id"] in complete or not output.is_dir():
            continue
        if any(output.iterdir()):
            destination = archive / "cells" / output.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(output), str(destination))
        else:
            output.rmdir()

    spawned = sum(1 for plan in plans if plan["cell_id"] in complete
                  and plan["invocation_status"] == "RUN")
    attempt = {
        "attempt": attempt_number,
        "time_ns": time.time_ns(),
        "resumed_at_phase": PHASES[resume_index],
        "cells_retained": len(complete),
        "cells_pending": len(plans) - len(complete),
        "cells_discarded": discarded,
        "superseded_dir": f"{SUPERSEDED_DIR}/attempt-{attempt_number}",
        "superseded_failure": manifest.get("failure"),
        "provenance_sha256": _provenance_digest(provenance),
    }
    resume = manifest.get("resume") or {
        "schema": RESUME_SCHEMA, "version": 1, "resume_count": 0, "attempts": [],
    }
    resume["resumed"] = True
    resume["resume_count"] = attempt_number
    resume["attempts"] = list(resume.get("attempts", [])) + [attempt]
    resume["provenance_sha256"] = attempt["provenance_sha256"]
    manifest["resume"] = resume
    manifest.pop("failure", None)
    manifest["phase_status"] = {
        phase: ("COMPLETED" if PHASES.index(phase) < resume_index else "PENDING")
        for phase in PHASES}
    manifest["event_sequence"] = len(kept_events)
    manifest["spawned_processes"] = spawned
    write_json(root / "run.json", manifest)
    append_jsonl(root / "resume.jsonl",
                 {"schema": RESUME_EVENT_SCHEMA, "version": 1, **attempt})
    _fsync_directory(archive)
    print(f"revision resume: retained {len(complete)}/{len(plans)} cells; "
          f"continuing from phase {PHASES[resume_index]}; "
          f"superseded evidence in {attempt['superseded_dir']}")
    return complete, resume_index


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
    results_root = (_resumable_results_root(args.results_root) if args.resume
                    else _fresh_results_root(args.results_root))
    seed = _parse_positive(args.seed, "seed")
    threads = _parse_positive(args.threads, "threads")
    matrix_path = Path(args.matrix)
    if not matrix_path.is_absolute():
        _fail("matrix must be an absolute path")

    document, matrix_sha = load_matrix(matrix_path)
    cells = select_cells(document, mode)
    if mode == "paper":
        if not args.paper_dblp_manifest or not args.paper_enron_u65536_manifest or \
                not args.paper_enron_u1048576_manifest:
            _fail("paper mode requires --paper-dblp-manifest, "
                  "--paper-enron-u65536-manifest, and "
                  "--paper-enron-u1048576-manifest")
        variant_manifests = {
            "dblp_acm_u65536": Path(args.paper_dblp_manifest),
            "enron_u65536": Path(args.paper_enron_u65536_manifest),
            "enron_u1048576": Path(args.paper_enron_u1048576_manifest),
        }
        dblp_manifest = Path(args.paper_dblp_manifest)
        validated = validate_paper_manifest_bindings(
            dblp_manifest=dblp_manifest,
            variant_manifests=variant_manifests,
            root_seed=seed,
        )
        dblp_manifest = validated["dblp_acm_u65536"]
        variant_manifests = validated
    else:
        supplied_paper_manifests = (
            args.paper_dblp_manifest, args.paper_enron_u65536_manifest,
            args.paper_enron_u1048576_manifest)
        if any(supplied_paper_manifests):
            _fail("paper manifest arguments are only valid in paper mode")
        variant_manifests = None
        dblp_manifest = None
    source = (dry_run_source_metadata(ROOT) if mode == "dry-run"
              else source_metadata(ROOT))
    if mode in {"toy", "paper"} and source.get("dirty"):
        _fail("executable revision runs require a tracked-clean source tree")
    # Resume admission runs before the root is touched, so a refusal leaves the
    # existing evidence exactly as the crashed attempt left it.
    resume_manifest: dict[str, Any] | None = None
    resume_provenance: dict[str, Any] | None = None
    if args.resume:
        resume_manifest = _require_resumable_manifest(
            results_root, mode=mode, seed=seed, threads=threads,
            matrix_path=matrix_path, matrix_sha=matrix_sha, cells=cells,
            build_dir=build_dir)
        resume_provenance = _require_identical_provenance(
            resume_manifest, build_dir=build_dir, cells=cells)
        variant_manifests, dblp_manifest = _resume_input_bindings(
            resume_manifest, mode, variant_manifests, dblp_manifest)
    else:
        results_root.mkdir()
        _fsync_directory(results_root.parent)
    try:
        if resume_manifest is not None:
            manifest = resume_manifest
            binaries = manifest["binaries"]
        else:
            (results_root / "canonical").mkdir()
            (results_root / "canonical" / "revision_matrix.json").write_bytes(
                matrix_path.read_bytes())
            if mode == "toy":
                variant_manifests, dblp_manifest = _copy_toy_manifests(results_root)
            elif mode == "dry-run":
                variant_manifests, dblp_manifest = _dry_run_manifest_bindings(
                    results_root)
            assert variant_manifests is not None and dblp_manifest is not None
            binaries = _binary_metadata(build_dir, cells)
            manifest = _write_initial_manifest(
                results_root, mode=mode, seed=seed, threads=threads,
                matrix_path=matrix_path, matrix_sha=matrix_sha, cells=cells,
                source=source, binaries=binaries,
                scripts=_script_hashes(), tools=(
                    dry_run_tool_metadata(build_dir) if mode == "dry-run"
                    else tool_metadata(build_dir)),
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
                "timeout_class": cell["timeout_class"],
                "expected_rows": cell["expected_rows"],
                "canonical_argv": canonical, "argv": command[1:] if command and command[0] == sys.executable else command,
                "command": command, "output_dir": str(output),
                "timeout_seconds": _timeout_seconds(cell["timeout_class"]),
            })
        if resume_manifest is not None:
            assert resume_provenance is not None
            _require_recorded_plans(results_root, plans)
            completed_cells, resume_index = _prepare_resume(
                results_root, manifest=manifest, plans=plans, cells=cells,
                provenance=resume_provenance)
        else:
            _record_plans(results_root, plans)
            completed_cells, resume_index = set(), 0
        manifest["state"] = "RUNNING"
        write_json(results_root / "run.json", manifest)
        event_sequence = 0
        for phase in PHASES:
            if mode != "dry-run" and phase in {"verification", "seal"}:
                continue
            if PHASES.index(phase) < resume_index:
                continue
            _phase(results_root, manifest, phase, "STARTED")
            if phase in {"preflight", "verification", "seal"}:
                _phase(results_root, manifest, phase, "COMPLETED")
                continue
            for plan in [item for item in plans if item["phase"] == phase]:
                if plan["cell_id"] in completed_cells:
                    continue
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
    parser.add_argument("--resume", action="store_true",
                        help="continue an existing unsealed results-root, "
                             "re-running every cell that is not independently "
                             "re-derivable as complete; refused if the source "
                             "tree, scripts, tools, or producer binaries moved")
    parser.add_argument("--paper-dblp-manifest",
                        help="processed DBLP-ACM manifest for executable paper mode")
    parser.add_argument("--paper-enron-u65536-manifest",
                        help="processed Enron U=65536 manifest for executable paper mode")
    parser.add_argument("--paper-enron-u1048576-manifest",
                        help="processed Enron U=1048576 manifest for executable paper mode")
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
