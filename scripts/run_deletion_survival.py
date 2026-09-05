#!/usr/bin/env python3
"""Run the two d=5 deletion-survival cells of the revision matrix with the
orchestrator's exact argv and record provenance.

A deliberately narrow sibling of scripts/run_revision_benchmarks.py in the
mould of scripts/run_table9_sweep.py: same matrix, same canonical argv, same
env, same per-cell output layout, but only the two cells behind
fig:del-survival ((n,d,k) = (1024,5,128), r = 0,20,...,520; exact curve and
10^5-trial Monte-Carlo).  No phases, no verification, no seal.  The producer
does no cryptography and is single-threaded, so --threads defaults to 1.

  python3 scripts/run_deletion_survival.py --mode=dry-run --build-dir=build --results-root=/abs/dir
  python3 scripts/run_deletion_survival.py --mode=run     --build-dir=build --results-root=/abs/dir
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))   # revision_benchmark_common does `from validate_revision_matrix import ...`
from scripts.revision_benchmark_common import (  # noqa: E402
    append_jsonl, binary_metadata, canonical_json, canonical_plan_argv, cell_output,
    command_for_cell, dry_run_tool_metadata, load_matrix, materialize_cell_argv,
    producer_extra_args, script_hashes, sha256_bytes, sha256_file, source_metadata, tool_metadata,
    write_json,
)

RUN_SCHEMA = "piccard-deletion-survival-run-v1"
CELL_SCHEMA = "piccard-deletion-survival-cell-v1"
MATRIX_DEFAULT = ROOT / "benchmarks" / "revision_matrix.json"
TIMEOUT_SECONDS = {"standard": 600, "extended": 3600, "long": 64800}

# Exact first (instant), then the 10^5-trial Monte-Carlo cell.
DELETION_CELL_IDS: tuple[str, ...] = (
    "paper-v1::deletion_exact::d=5",
    "paper-v1::deletion_mc::d=5",
)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _git_porcelain() -> str:
    return subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                          text=True, check=False).stdout.strip()


def _cpu_model() -> str:
    """Best-effort CPU model string, so a resume cannot silently cross to a
    materially different machine without that showing up in provenance.
    """
    try:
        out = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=5, check=False).stdout
        for line in out.splitlines():
            if line.startswith("Model name:"):
                return line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                             text=True, timeout=5, check=False).stdout.strip()
        if out:
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    return "unavailable"


def plan(document: dict[str, Any], build_dir: Path, root: Path, *, seed: int,
         threads: int) -> list[dict[str, Any]]:
    by_id = {c["cell_id"]: c for c in document["cells"]}
    plans = []
    for cid in DELETION_CELL_IDS:
        cell = by_id[cid]
        if cell["invocation_status"] != "RUN":
            raise SystemExit(f"{cid} is not a RUN cell in the matrix")
        output = cell_output(root, cid)
        argv = materialize_cell_argv(cell, "paper", root=root, output=output, seed=seed, threads=threads)
        argv.extend(producer_extra_args(cell, output))
        command = command_for_cell(cell, root=root, build_dir=build_dir)
        plans.append({
            "schema": CELL_SCHEMA, "version": 1, "cell_id": cid,
            "family": cell["family"], "producer": cell["producer"],
            "timeout_class": cell["timeout_class"],
            "timeout_seconds": TIMEOUT_SECONDS[cell["timeout_class"]],
            "expected_rows": cell["expected_rows"],
            "canonical_argv": canonical_plan_argv(cell, "paper"),
            "argv": argv, "command": command + argv,
            "env": {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(threads),
                    "PICCARD_REVISION_CELL": cid, "PICCARD_REVISION_MODE": "paper"},
            "output_dir": str(output),
        })
    return plans


def _provenance(build_dir: Path, cells: list[dict[str, Any]], matrix_sha: str,
                seed: int, threads: int) -> dict[str, Any]:
    tools = (tool_metadata(build_dir) if (build_dir / "CMakeCache.txt").exists()
             else dry_run_tool_metadata(build_dir))
    binaries = binary_metadata(build_dir, cells)
    missing = sorted(name for name, meta in binaries.items() if meta.get("sha256") == "MISSING")
    if missing:
        raise SystemExit(f"missing benchmark binaries in {build_dir}: {', '.join(missing)}")
    # script_hashes() covers revision_benchmark_common.py and validate_revision_matrix.py --
    # load_matrix() calls validate_document() from the latter on every invocation, deciding
    # whether the matrix is even acceptable, so it is load-bearing and must be hashed, not
    # just assumed stable.  It also pulls in three scripts this narrow runner never touches
    # (run_revision_benchmarks.py, verify_revision_benchmarks.py, seal_revision_benchmarks.py);
    # reusing the orchestrator's own enumeration rather than hand-listing files here means this
    # set cannot drift out of sync with it again, and refusing a resume across a changed
    # verifier or sealer is arguably correct anyway.
    return {"source": source_metadata(ROOT), "tools": tools,
            "binaries": binaries, "matrix_sha256": matrix_sha,
            "seed": seed, "threads": threads, "build_dir": str(build_dir),
            "host": {"machine": platform.machine(), "cpu_count": os.cpu_count(), "cpu_model": _cpu_model()},
            "runner_sha256": sha256_file(Path(__file__)),
            "scripts": script_hashes()}


def _provenance_id(provenance: dict[str, Any]) -> str:
    """A stable short identity for one provenance record.

    Lets every cell stamp *which* provenance it was measured under, so an
    accepted provenance change never has to erase that fact for the cells
    that ran before it.
    """
    return sha256_bytes(canonical_json(provenance))[:16]


def _provenance_diff(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Name which top-level provenance keys differ (one level deep).

    ``binaries`` and ``scripts`` are each drilled one level further so the
    operator sees which binary's sha256 moved, or which script's, rather
    than just "binaries differ" / "scripts differ" -- the whole point is
    telling "I rebuilt one binary" or "I edited the matrix validator" apart
    from "I am pointing at a different matrix".
    """
    lines: list[str] = []
    for key in sorted(set(old) | set(new)):
        if key == "binaries":
            old_binaries, new_binaries = old.get("binaries", {}), new.get("binaries", {})
            for name in sorted(set(old_binaries) | set(new_binaries)):
                o, n = old_binaries.get(name), new_binaries.get(name)
                if o != n:
                    o_sha = o.get("sha256") if o else "absent"
                    n_sha = n.get("sha256") if n else "absent"
                    lines.append(f"binaries.{name}.sha256: {o_sha} -> {n_sha}")
            continue
        if key == "scripts":
            old_scripts, new_scripts = old.get("scripts", {}), new.get("scripts", {})
            for name in sorted(set(old_scripts) | set(new_scripts)):
                o, n = old_scripts.get(name), new_scripts.get(name)
                if o != n:
                    lines.append(f"scripts.{name}: {o!r} -> {n!r}")
            continue
        if old.get(key) != new.get(key):
            lines.append(f"{key}: {old.get(key)!r} -> {new.get(key)!r}")
    return lines


def _archive_failed_attempt(output: Path, root: Path, cell_id: str) -> None:
    """Move a stale cell directory aside before re-running into a fresh one.

    Some producers refuse to overwrite their own artifacts on a second run
    into the same directory -- comparison_workload.cpp:648 publishes an
    immutable workload.bin, raw_timing_schema.cpp:535 refuses to write when
    the target .tsv or its .tmp already exists -- so a cell that failed
    after either artifact appeared would otherwise fail again instantly on
    every resume, precisely the case resume exists for.  The old directory
    is never deleted: its stdout/stderr is the evidence for why it failed.
    A first attempt with nothing there yet does not create an .attempt-0.
    """
    if not output.exists():
        return
    existing = list(output.parent.glob(f"{output.name}.attempt-*"))
    archived = output.parent / f"{output.name}.attempt-{1 + len(existing)}"
    output.rename(archived)
    append_jsonl(root / "events.jsonl", {"event": "RETRY", "cell_id": cell_id,
                                         "archived_to": str(archived), "time": _now()})


def _run_one(p: dict[str, Any], root: Path, sequence: int, provenance_id: str) -> dict[str, Any]:
    output = Path(p["output_dir"])
    _archive_failed_attempt(output, root, p["cell_id"])
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(p["env"])
    append_jsonl(root / "events.jsonl", {"sequence": sequence, "event": "START",
                                         "cell_id": p["cell_id"], "time": _now()})
    started = _now()
    t0 = time.monotonic()
    with (output / "stdout.log").open("wb") as out, (output / "stderr.log").open("wb") as err:
        try:
            completed = subprocess.run(p["command"], cwd=ROOT, env=env, stdout=out, stderr=err,
                                       check=False, timeout=p["timeout_seconds"])
            exit_code = int(completed.returncode)
            status = "COMPLETED" if exit_code == 0 else "FAILED"
        except subprocess.TimeoutExpired:
            exit_code, status = -124, "TIMEOUT"
        except OSError as error:                       # executable missing or not runnable
            err.write(f"spawn failed: {error}\n".encode())
            exit_code, status = -2, "FAILED"
    receipt = {**{k: p[k] for k in ("schema", "version", "cell_id", "family", "producer",
                                    "timeout_class", "timeout_seconds", "expected_rows",
                                    "canonical_argv", "argv")},
               "execution_status": status, "exit_code": exit_code,
               "duration_s": round(time.monotonic() - t0, 3),
               "started_at": started, "finished_at": _now(),
               "stdout_sha256": sha256_file(output / "stdout.log"),
               "stderr_sha256": sha256_file(output / "stderr.log"),
               "provenance_id": provenance_id}
    write_json(output / "receipt.json", receipt)
    append_jsonl(root / "events.jsonl", {"sequence": sequence + 1, "event": "END",
                                         "cell_id": p["cell_id"], "exit_code": exit_code,
                                         "execution_status": status, "time": _now()})
    return {k: receipt[k] for k in ("cell_id", "family", "execution_status", "exit_code",
                                    "duration_s", "started_at", "finished_at", "provenance_id")}


def _write_manifest(path: Path, value: dict[str, Any]) -> None:
    """Write run.json atomically: serialize to a temp file in the same
    directory, fsync it, then os.replace() into place.  run.json is
    rewritten after every cell, so a crash mid-write must never leave it
    truncated -- a reader sees either the old manifest or the new one,
    never a half-written one.  Local to this script rather than a change to
    the shared ``write_json``, which the orchestrator also uses.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f"{path.name}.tmp"
    payload = canonical_json(value)
    with tmp.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def _rebuild_manifest_from_receipts(plans: list[dict[str, Any]], provenance: dict[str, Any],
                                    provenance_id: str, *, dirty_allowed: bool) -> dict[str, Any]:
    """Reconstruct a run.json skeleton from per-cell receipt.json files when
    the manifest itself is corrupt or truncated (e.g. a crash mid-write).

    Receipts are the authoritative per-cell record -- the resume
    revalidation loop re-checks each one independently anyway -- so no
    completed work is actually lost; only the manifest's own bookkeeping
    (provenance_history, the original started_at) is.  The rebuilt
    manifest's own provenance is the one computed for *this* invocation;
    if a recovered cell's own provenance_id disagrees, that is exactly what
    the mixed_provenance check below is for.
    """
    cells: list[dict[str, Any]] = []
    for p in plans:
        try:
            receipt = json.loads((Path(p["output_dir"]) / "receipt.json").read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if receipt.get("cell_id") != p["cell_id"] or receipt.get("execution_status") != "COMPLETED":
            continue
        cells.append({k: receipt[k] for k in ("cell_id", "family", "execution_status", "exit_code",
                                              "duration_s", "started_at", "finished_at", "provenance_id")
                      if k in receipt})
    return {"schema": RUN_SCHEMA, "version": 1, "started_at": _now(), "state": "STARTED",
            "mode": "paper", "dirty_allowed": dirty_allowed,
            "platform": platform.platform(), "cpu_count": os.cpu_count(),
            "provenance": provenance, "provenance_id": provenance_id,
            "cell_ids": [p["cell_id"] for p in plans],
            "planned_processes": len(plans), "cells": cells,
            "rebuilt_from_receipts": True, "rebuilt_at": _now()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", required=True, choices=("dry-run", "run"))
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--seed", type=int, default=20260729)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--matrix", default=str(MATRIX_DEFAULT))
    parser.add_argument("--allow-dirty", action="store_true",
                        help="permit a dirty git tree; recorded in run.json as dirty_allowed")
    parser.add_argument("--accept-provenance-change", action="store_true",
                        help="permit a resume whose provenance differs from the recorded run; the "
                             "old provenance is preserved in run.json's provenance_history, never overwritten silently")
    args = parser.parse_args(argv)

    # Resolve every path argument to an absolute path immediately, before
    # anything hashes a binary or spawns a subprocess under one of them:
    # binary_metadata() would otherwise hash a relative build_dir against
    # *this process's* cwd while subprocess.run() executes cells with
    # cwd=ROOT, so an unresolved relative --build-dir invoked from outside
    # the repo silently hashes one binary and runs another.  --results-root
    # keeps its own "must be absolute in run mode" business rule below,
    # checked against the flag exactly as the operator typed it -- resolving
    # first would make that check vacuous (Path.resolve() is always
    # absolute), so the check reads args.results_root, not the resolved root.
    results_root_was_relative = not Path(args.results_root).is_absolute()
    build_dir = Path(args.build_dir).resolve()
    root = Path(args.results_root).resolve()
    matrix_path = Path(args.matrix).resolve()
    document, matrix_sha = load_matrix(matrix_path)
    plans = plan(document, build_dir, root, seed=args.seed, threads=args.threads)

    if args.mode == "dry-run":
        root.mkdir(parents=True, exist_ok=True)
        with (root / "planned_argv.jsonl").open("w") as handle:
            for p in plans:
                handle.write(json.dumps(p, sort_keys=True) + "\n")
        print(f"dry-run: {len(plans)} cells planned -> {root / 'planned_argv.jsonl'}")
        return 0

    if results_root_was_relative:
        print("--results-root must be absolute in run mode", file=sys.stderr)
        return 2
    dirty = _git_porcelain()
    if dirty and not args.allow_dirty:
        print("refusing to run on a dirty tree (--allow-dirty is for local checks only):\n" + dirty,
              file=sys.stderr)
        return 2

    by_id = {c["cell_id"]: c for c in document["cells"]}
    provenance = _provenance(build_dir, [by_id[c] for c in DELETION_CELL_IDS], matrix_sha,
                             args.seed, args.threads)
    provenance_id = _provenance_id(provenance)
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "run.json"
    is_resume = manifest_path.exists()
    if is_resume:
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as error:
            # A crash mid-write (before the atomic-write fix below existed,
            # or from any other cause) can leave run.json truncated.  Do not
            # raise: the per-cell receipts are the authoritative record
            # regardless (see the revalidation loop below), so rebuild the
            # manifest from them instead of losing hours of completed work
            # to an unreadable bookkeeping file.  provenance_history and the
            # original started_at are not recoverable and are not invented.
            print(f"run.json is corrupt or truncated ({error}); rebuilding the manifest from "
                  "per-cell receipt.json files -- no completed work is lost, only run-level "
                  "bookkeeping (provenance_history, original timestamps) is reset", file=sys.stderr)
            manifest = _rebuild_manifest_from_receipts(plans, provenance, provenance_id,
                                                        dirty_allowed=bool(args.allow_dirty))
            with (root / "planned_argv.jsonl").open("w") as handle:
                for p in plans:
                    handle.write(json.dumps(p, sort_keys=True) + "\n")
            _write_manifest(manifest_path, manifest)
            append_jsonl(root / "events.jsonl", {"event": "REBUILD", "time": _now(), "reason": str(error),
                                                 "recovered_cells": len(manifest["cells"])})
        else:
            if manifest.get("provenance") != provenance:
                diffs = _provenance_diff(manifest.get("provenance", {}), provenance)
                if not args.accept_provenance_change:
                    print("resume refused: provenance differs from the recorded run "
                          "(source, tools, binaries, matrix, seed, threads, or scripts changed):\n"
                          + "\n".join(diffs), file=sys.stderr)
                    return 2
                # Never overwrite provenance silently: the prior record is kept in
                # provenance_history (with its own id) so an operator can always
                # see what changed and when, rather than losing hours of completed
                # cells to hand-editing.  Cells already measured keep the OLD
                # provenance_id in their own receipt/manifest record forever --
                # only cells run from this point on carry the new id -- so the
                # override never misattributes evidence that was gathered before
                # it.  The original planned_argv.jsonl is therefore left
                # untouched (it is still exactly what the P1 cells ran under);
                # the new plan goes to a file named after the new provenance_id.
                old_id = manifest.get("provenance_id") or _provenance_id(manifest["provenance"])
                manifest.setdefault("provenance_history", []).append(
                    {"replaced_at": _now(), "provenance_id": old_id, "provenance": manifest["provenance"]})
                manifest["provenance"] = provenance
                manifest["provenance_id"] = provenance_id
                new_plan_path = root / f"planned_argv.{provenance_id}.jsonl"
                with new_plan_path.open("w") as handle:
                    for p in plans:
                        handle.write(json.dumps(p, sort_keys=True) + "\n")
                append_jsonl(root / "events.jsonl", {"event": "PROVENANCE_CHANGE", "time": _now(), "diff": diffs,
                                                     "provenance_id": provenance_id,
                                                     "planned_argv_file": new_plan_path.name})
                print("provenance changed, accepted via --accept-provenance-change "
                      f"(new plan recorded at {new_plan_path.name}):\n" + "\n".join(diffs))
            else:
                recorded = [json.loads(l) for l in (root / "planned_argv.jsonl").read_text().splitlines()]
                if [r["command"] for r in recorded] != [p["command"] for p in plans]:
                    print("resume refused: planned argv differs from the recorded plan (provenance)",
                          file=sys.stderr)
                    return 2
            append_jsonl(root / "events.jsonl", {"event": "RESUME", "time": _now()})
    else:
        manifest = {"schema": RUN_SCHEMA, "version": 1, "started_at": _now(), "state": "STARTED",
                    "mode": "paper", "dirty_allowed": bool(args.allow_dirty),
                    "platform": platform.platform(), "cpu_count": os.cpu_count(),
                    "provenance": provenance, "provenance_id": provenance_id,
                    "cell_ids": list(DELETION_CELL_IDS),
                    "planned_processes": len(plans), "cells": []}
        with (root / "planned_argv.jsonl").open("w") as handle:
            for p in plans:
                handle.write(json.dumps(p, sort_keys=True) + "\n")
        _write_manifest(manifest_path, manifest)

    # Archive the matrix this run was planned against.  provenance.matrix_sha256
    # alone is enough to detect drift but not to reproduce it: once
    # benchmarks/revision_matrix.json evolves in the repository, nothing could
    # otherwise reconstruct what a past run's cells meant, and a summarizer
    # comparing against the repo's *current* matrix would refuse a perfectly
    # good archived run forever.  Same class of check as the provenance
    # comparison above; it belongs beside it.
    matrix_archive_path = root / "matrix.json"
    if is_resume:
        if not matrix_archive_path.is_file():
            print(f"resume refused: matrix.json archive is missing from {root} "
                  "-- it must never be deleted or moved out from under a run", file=sys.stderr)
            return 2
        archived_sha = sha256_file(matrix_archive_path)
        recorded_sha = manifest["provenance"]["matrix_sha256"]
        if archived_sha != recorded_sha:
            print("resume refused: matrix.json archive does not match the recorded digest "
                  f"(archived {archived_sha}, recorded {recorded_sha}) -- matrix.json must never "
                  "be hand-edited or replaced after a run starts", file=sys.stderr)
            return 2
    else:
        matrix_archive_path.write_bytes(matrix_path.read_bytes())
        archived_sha = sha256_file(matrix_archive_path)
        if archived_sha != matrix_sha:
            # The file changed under us between hashing (load_matrix, above) and
            # copying -- a hard failure, not a resume-refusal: this is a fresh
            # run and nothing has been measured yet.
            raise SystemExit(f"matrix.json archive write is corrupt: expected {matrix_sha}, "
                             f"got {archived_sha}")

    plan_by_id = {p["cell_id"]: p for p in plans}
    valid_completed: list[dict[str, Any]] = []
    for c in manifest["cells"]:
        if c["execution_status"] != "COMPLETED":
            continue
        # A manifest record saying COMPLETED is not itself evidence: verify the
        # cell's own receipt still exists, parses, and agrees, so a lost or
        # truncated artifact (partial rsync, cleanup, interrupted write) causes
        # a re-run instead of a false COMPLETED claim.
        receipt_path = Path(plan_by_id[c["cell_id"]]["output_dir"]) / "receipt.json"
        reason = None
        try:
            receipt = json.loads(receipt_path.read_text())
        except (OSError, json.JSONDecodeError):
            receipt = None
            reason = "receipt.json missing or unreadable"
        if receipt is not None:
            if receipt.get("cell_id") != c["cell_id"]:
                reason = "receipt.json cell_id does not match"
            elif receipt.get("execution_status") != "COMPLETED":
                reason = f"receipt.json execution_status is {receipt.get('execution_status')!r}, not COMPLETED"
        if reason is not None:
            print(f"revalidate: {c['cell_id']} will be re-run ({reason})")
            append_jsonl(root / "events.jsonl", {"event": "REVALIDATE", "cell_id": c["cell_id"],
                                                 "reason": reason, "time": _now()})
            continue
        valid_completed.append(c)
    completed = {c["cell_id"] for c in valid_completed}
    manifest["cells"] = valid_completed
    events_path = root / "events.jsonl"
    sequence = len(events_path.read_text().splitlines()) if events_path.exists() else 0   # monotonic across resumes
    ran = failed = 0
    for p in plans:
        if p["cell_id"] in completed:
            continue
        record = _run_one(p, root, sequence, provenance_id)
        sequence += 2
        manifest["cells"].append(record)
        ran += 1
        failed += record["execution_status"] != "COMPLETED"
        manifest["state"] = "RUNNING"
        _write_manifest(manifest_path, manifest)
        print(f"[{len(manifest['cells'])}/{len(plans)}] {p['cell_id']} {record['execution_status']} "
              f"exit={record['exit_code']} {record['duration_s']}s", flush=True)

    manifest["cells"].sort(key=lambda c: DELETION_CELL_IDS.index(c["cell_id"]))
    manifest["finished_at"] = _now()
    manifest["state"] = "FAILED" if failed else "COMPLETED"

    # A run whose cells were measured under more than one provenance (an
    # accepted override mid-sweep) must say so loudly: nobody should read a
    # mixed run as homogeneous without noticing.  The receipts remain the
    # authoritative per-cell record; this is just the manifest-level index.
    # "Mixed" covers both shapes: cells disagree with each other, AND cells
    # all agree with each other but disagree with *this run's* provenance --
    # the latter happens when an override resume finds every cell already
    # complete (zero re-runs), which would otherwise silently relabel a run
    # measured under one provenance (e.g. 8 threads) as another (16 threads).
    cell_ids_seen = {c["provenance_id"] for c in manifest["cells"] if c.get("provenance_id")}
    state_label = manifest["state"]
    if cell_ids_seen and cell_ids_seen != {provenance_id}:
        all_ids_seen = sorted(cell_ids_seen | {provenance_id})
        manifest["mixed_provenance"] = True
        provenance_cells: dict[str, list[str]] = {}
        for c in manifest["cells"]:
            pid = c.get("provenance_id")
            if pid:
                provenance_cells.setdefault(pid, []).append(c["cell_id"])
        manifest["provenance_cells"] = provenance_cells
        state_label = f"{manifest['state']} (MIXED PROVENANCE: {len(all_ids_seen)} ids)"

    _write_manifest(manifest_path, manifest)
    print(f"run {state_label}: ran {ran}, skipped {len(completed)}, failed {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
