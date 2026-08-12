#!/usr/bin/env python3
"""Run the fixed synthetic threshold grid as exactly 84 point children."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Sequence

try:
    from scripts.verify_threshold_outputs import (
        REQUIRED_COLUMNS,
        GRID_INDICES,
        M,
        SET_SIZE,
        SUPPORTED_K,
    )
except ModuleNotFoundError:  # direct invocation from a different cwd
    from verify_threshold_outputs import (  # type: ignore
        REQUIRED_COLUMNS,
        GRID_INDICES,
        M,
        SET_SIZE,
        SUPPORTED_K,
    )


class GridRunnerError(ValueError):
    """Raised when a point child or receipt violates the orchestration contract."""


def _validate_child_receipt(
    stdout: str,
    *,
    profile: str,
    security: str,
    root_seed: int,
    k: int,
    grid_index: int,
    trials: int,
) -> list[dict[str, str]]:
    reader = csv.DictReader(stdout.splitlines())
    if tuple(reader.fieldnames or ()) != REQUIRED_COLUMNS:
        raise GridRunnerError("child CSV header does not match the versioned schema")
    rows = list(reader)
    if len(rows) != trials:
        raise GridRunnerError(
            f"child ({k},{grid_index}) returned {len(rows)} rows; expected {trials}"
        )
    seen_trials: set[int] = set()
    for row in rows:
        if row.get("schema_version") != "piccard-threshold-fpfn-v1":
            raise GridRunnerError("child schema_version mismatch")
        if row.get("profile") != profile or row.get("security") != security:
            raise GridRunnerError("child profile/security receipt mismatch")
        if row.get("root_seed") != str(root_seed):
            raise GridRunnerError("child root_seed receipt mismatch")
        try:
            row_k = int(row["k"])
            row_m = int(row["m"])
            row_n = int(row["set_size"])
            row_grid = int(row["grid_index"])
            trial_index = int(row["trial_index"])
        except (KeyError, ValueError) as exc:
            raise GridRunnerError("child has malformed selector fields") from exc
        if (row_k, row_grid) != (k, grid_index):
            raise GridRunnerError("child emitted an adjacent or wrong point")
        if row_m != M or row_n != SET_SIZE:
            raise GridRunnerError("child emitted non-canonical m or set size")
        if trial_index < 0 or trial_index >= trials or trial_index in seen_trials:
            raise GridRunnerError("child has missing or duplicate trial index")
        seen_trials.add(trial_index)
    if seen_trials != set(range(trials)):
        raise GridRunnerError("child trial coverage is incomplete")
    return rows


def run_grid(
    *,
    binary: Path,
    profile: str,
    security: str,
    root_seed: int,
    trials: int,
    output: Path,
) -> int:
    if profile not in {"readiness-toy-v1", "paper-v1"}:
        raise GridRunnerError("profile must be readiness-toy-v1 or paper-v1")
    if root_seed <= 0 or root_seed > (1 << 64) - 1:
        raise GridRunnerError("seed must be a positive uint64")
    if trials <= 0 or (profile == "readiness-toy-v1" and trials != 1) or (
        profile == "paper-v1" and trials < 1000
    ):
        raise GridRunnerError("invalid trial count for selected profile")
    expected_security = "TOY" if profile == "readiness-toy-v1" else "STD128"
    if security != expected_security:
        raise GridRunnerError(
            f"{profile} requires security metadata {expected_security}"
        )
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise GridRunnerError(f"benchmark binary is not executable: {binary}")
    if output.exists():
        raise GridRunnerError(f"refusing to overwrite existing output: {output}")

    all_rows: list[dict[str, str]] = []
    child_count = 0
    for k in SUPPORTED_K:
        for grid_index in GRID_INDICES:
            command = [
                str(binary),
                "--mode=fpfn",
                f"--profile={profile}",
                f"--security={security}",
                f"--m={M}",
                f"--set_size={SET_SIZE}",
                f"--trials={trials}",
                f"--point-k={k}",
                f"--grid-index={grid_index}",
                f"--seed={root_seed}",
                "--hash_randomness=resampled",
            ]
            result = subprocess.run(command, text=True, capture_output=True)
            if result.returncode != 0:
                detail = result.stderr.strip() or result.stdout.strip()
                raise GridRunnerError(
                    f"child ({k},{grid_index}) failed with {result.returncode}: {detail}"
                )
            all_rows.extend(
                _validate_child_receipt(
                    result.stdout,
                    profile=profile,
                    security=security,
                    root_seed=root_seed,
                    k=k,
                    grid_index=grid_index,
                    trials=trials,
                )
            )
            child_count += 1

    expected_children = len(SUPPORTED_K) * len(GRID_INDICES)
    if child_count != expected_children:
        raise GridRunnerError(
            f"child receipt count mismatch: {child_count} != {expected_children}"
        )
    if len(all_rows) != expected_children * trials:
        raise GridRunnerError("combined row count mismatch")

    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=REQUIRED_COLUMNS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(all_rows)
        os.replace(temporary_name, output)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return child_count


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--security", default=None)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--trials", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    security = args.security or (
        "TOY" if args.profile == "readiness-toy-v1" else "STD128"
    )
    try:
        child_count = run_grid(
            binary=args.binary,
            profile=args.profile,
            security=security,
            root_seed=args.seed,
            trials=args.trials,
            output=args.output,
        )
    except (OSError, OverflowError, GridRunnerError) as exc:
        print(f"run_threshold_fpfn_grid: FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"run_threshold_fpfn_grid: PASS ({child_count} children, {child_count * args.trials} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
