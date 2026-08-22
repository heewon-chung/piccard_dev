#!/usr/bin/env python3
"""Run the 42 Table IX cells of the revision matrix sequentially with the
orchestrator's exact argv and record provenance.

A deliberately narrow sibling of scripts/run_revision_benchmarks.py: same
matrix, same canonical argv, same env, same per-cell output layout, but only
the cells that fill tbl:comp; no phases, no verification, no seal.

This runner measures only cells whose varied parameter is a real input to
the protocol under test (2026-08-23, final user decision, verified in
source): SJ16 (`Sj16Adapter(method, key_bits, universe, ...)`,
`bench_review_comparison.cpp:941-950`), BCG12 (`Bcg12Params` has only
`mode/backend/k/minhash_seed`; `bcg12.cpp` never references `universe`,
`bcg12.h:12-18`), and FHE-IND (`BaselineEngine` takes only
`universe_size`/`set_size`, `baseline_engine.h:37,57`) each ignore some of
the swept axes -- re-running such a cell would measure the same
configuration again, not a parameter dependence, and the verifier already
asserts those row fields are blank. SJ16's two large-|U| cells
(sj16::u=262144, sj16::u=1048576) are additionally excluded as infeasible
-- the sj16::fit=precomputed cell alone took 9.5 h at |U|=2^16 on the
2026-08-20 run -- so the paper keeps their existing extrapolated values.
42 cells: piccard_std128 13, sqrt_comparison 12, bcg12_minhash 7, fhe_ind
6, sj16 4. The matrix still contains every excluded cell and
plan()/family-keyed logic still handles them for a possible future full
run; TABLE9_CELL_IDS simply does not include them. Table rows for
unconsumed parameters repeat the default-point measurement with a
footnote citing the implementation.

  python3 scripts/run_table9_sweep.py --mode=dry-run --build-dir=build --results-root=/abs/dir
  python3 scripts/run_table9_sweep.py --mode=run     --build-dir=build --results-root=/abs/dir
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
    producer_extra_args, sha256_bytes, sha256_file, source_metadata, tool_metadata, write_json,
)

RUN_SCHEMA = "piccard-table9-sweep-run-v1"
CELL_SCHEMA = "piccard-table9-sweep-cell-v1"
MATRIX_DEFAULT = ROOT / "benchmarks" / "revision_matrix.json"
TIMEOUT_SECONDS = {"standard": 600, "extended": 3600, "long": 64800}

_U = ("16384", "65536", "262144", "1048576")
_N = ("100", "10000")
_K = ("16", "64", "256", "512")
_M = ("16", "128", "256")


def _ids(family: str, prefix: str = "", *, skip_m: tuple[str, ...] = ()) -> list[str]:
    ids = [f"paper-v1::{family}::{prefix}u={v}" for v in _U]
    ids += [f"paper-v1::{family}::{prefix}n={v}" for v in _N]
    ids += [f"paper-v1::{family}::{prefix}k={v}" for v in _K]
    ids += [f"paper-v1::{family}::{prefix}m={v}" for v in _M if v not in skip_m]
    return ids


# BCG12 consumes only n and k (no |U|, no m): the u=65536 default point plus
# both n cells and all four k cells.  See module docstring.
_BCG12_MINHASH_IDS: tuple[str, ...] = (
    "paper-v1::bcg12_minhash::u=65536",
    "paper-v1::bcg12_minhash::n=100", "paper-v1::bcg12_minhash::n=10000",
    "paper-v1::bcg12_minhash::k=16", "paper-v1::bcg12_minhash::k=64",
    "paper-v1::bcg12_minhash::k=256", "paper-v1::bcg12_minhash::k=512",
)

# FHE-IND consumes only |U| and n (no k, no m).  See module docstring.
_FHE_IND_IDS: tuple[str, ...] = tuple(
    [f"paper-v1::fhe_ind::u={v}" for v in _U] + [f"paper-v1::fhe_ind::n={v}" for v in _N]
)

# SJ16 consumes |U| and n (no k, no m); the two large-|U| cells stay
# extrapolated (infeasible, see module docstring).
_SJ16_MEASURED_IDS: tuple[str, ...] = (
    "paper-v1::sj16::u=16384", "paper-v1::sj16::u=65536",
    "paper-v1::sj16::n=100", "paper-v1::sj16::n=10000",
)

# Execution order: cheap producers first, SJ16 last.  The default point is
# the u=65536 cell of each family.
TABLE9_CELL_IDS: tuple[str, ...] = tuple(
    _ids("piccard_std128")
    + _ids("sqrt_comparison", "timing_", skip_m=("128",))
    + list(_BCG12_MINHASH_IDS)
    + list(_FHE_IND_IDS)
    + list(_SJ16_MEASURED_IDS)
)
assert len(TABLE9_CELL_IDS) == 42 and len(set(TABLE9_CELL_IDS)) == 42


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _git_porcelain() -> str:
    return subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                          text=True, check=False).stdout.strip()


def plan(document: dict[str, Any], build_dir: Path, root: Path, *, seed: int,
         threads: int) -> list[dict[str, Any]]:
    by_id = {c["cell_id"]: c for c in document["cells"]}
    plans = []
    for cid in TABLE9_CELL_IDS:
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
    return {"source": source_metadata(ROOT), "tools": tools,
            "binaries": binaries, "matrix_sha256": matrix_sha,
            "seed": seed, "threads": threads, "build_dir": str(build_dir),
            "runner_sha256": sha256_file(Path(__file__)),
            "common_sha256": sha256_file(ROOT / "scripts" / "revision_benchmark_common.py")}


def _provenance_id(provenance: dict[str, Any]) -> str:
    """A stable short identity for one provenance record.

    Lets every cell stamp *which* provenance it was measured under, so an
    accepted provenance change never has to erase that fact for the cells
    that ran before it.
    """
    return sha256_bytes(canonical_json(provenance))[:16]


def _provenance_diff(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Name which top-level provenance keys differ (one level deep).

    ``binaries`` is drilled one level further so the operator sees which
    binary's sha256 moved rather than just "binaries differ" -- the whole
    point is telling "I rebuilt one binary" apart from "I am pointing at a
    different matrix".
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
        if old.get(key) != new.get(key):
            lines.append(f"{key}: {old.get(key)!r} -> {new.get(key)!r}")
    return lines


def _run_one(p: dict[str, Any], root: Path, sequence: int, provenance_id: str) -> dict[str, Any]:
    output = Path(p["output_dir"])
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", required=True, choices=("dry-run", "run"))
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--seed", type=int, default=20260729)
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--matrix", default=str(MATRIX_DEFAULT))
    parser.add_argument("--allow-dirty", action="store_true",
                        help="permit a dirty git tree; recorded in run.json as dirty_allowed")
    parser.add_argument("--accept-provenance-change", action="store_true",
                        help="permit a resume whose provenance differs from the recorded run; the "
                             "old provenance is preserved in run.json's provenance_history, never overwritten silently")
    args = parser.parse_args(argv)

    root = Path(args.results_root)
    build_dir = Path(args.build_dir)
    document, matrix_sha = load_matrix(Path(args.matrix))
    plans = plan(document, build_dir, root, seed=args.seed, threads=args.threads)

    if args.mode == "dry-run":
        root.mkdir(parents=True, exist_ok=True)
        with (root / "planned_argv.jsonl").open("w") as handle:
            for p in plans:
                handle.write(json.dumps(p, sort_keys=True) + "\n")
        print(f"dry-run: {len(plans)} cells planned -> {root / 'planned_argv.jsonl'}")
        return 0

    if not root.is_absolute():
        print("--results-root must be absolute in run mode", file=sys.stderr)
        return 2
    dirty = _git_porcelain()
    if dirty and not args.allow_dirty:
        print("refusing to run on a dirty tree (--allow-dirty is for local checks only):\n" + dirty,
              file=sys.stderr)
        return 2

    by_id = {c["cell_id"]: c for c in document["cells"]}
    provenance = _provenance(build_dir, [by_id[c] for c in TABLE9_CELL_IDS], matrix_sha,
                             args.seed, args.threads)
    provenance_id = _provenance_id(provenance)
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "run.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
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
                print("resume refused: planned argv differs from the recorded plan (provenance)", file=sys.stderr)
                return 2
        append_jsonl(root / "events.jsonl", {"event": "RESUME", "time": _now()})
    else:
        manifest = {"schema": RUN_SCHEMA, "version": 1, "started_at": _now(), "state": "STARTED",
                    "mode": "paper", "dirty_allowed": bool(args.allow_dirty),
                    "platform": platform.platform(), "cpu_count": os.cpu_count(),
                    "provenance": provenance, "provenance_id": provenance_id,
                    "cell_ids": list(TABLE9_CELL_IDS),
                    "planned_processes": len(plans), "cells": []}
        with (root / "planned_argv.jsonl").open("w") as handle:
            for p in plans:
                handle.write(json.dumps(p, sort_keys=True) + "\n")
        write_json(manifest_path, manifest)

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
        write_json(manifest_path, manifest)
        print(f"[{len(manifest['cells'])}/{len(plans)}] {p['cell_id']} {record['execution_status']} "
              f"exit={record['exit_code']} {record['duration_s']}s", flush=True)

    manifest["cells"].sort(key=lambda c: TABLE9_CELL_IDS.index(c["cell_id"]))
    manifest["finished_at"] = _now()
    manifest["state"] = "FAILED" if failed else "COMPLETED"

    # A run whose cells were measured under more than one provenance (an
    # accepted override mid-sweep) must say so loudly: nobody should read a
    # mixed run as homogeneous without noticing.  The receipts remain the
    # authoritative per-cell record; this is just the manifest-level index.
    provenance_ids_seen = sorted({c["provenance_id"] for c in manifest["cells"] if c.get("provenance_id")})
    state_label = manifest["state"]
    if len(provenance_ids_seen) > 1:
        manifest["mixed_provenance"] = True
        provenance_cells: dict[str, list[str]] = {}
        for c in manifest["cells"]:
            pid = c.get("provenance_id")
            if pid:
                provenance_cells.setdefault(pid, []).append(c["cell_id"])
        manifest["provenance_cells"] = provenance_cells
        state_label = f"{manifest['state']} (MIXED PROVENANCE: {len(provenance_ids_seen)} ids)"

    write_json(manifest_path, manifest)
    print(f"run {state_label}: ran {ran}, skipped {len(completed)}, failed {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
