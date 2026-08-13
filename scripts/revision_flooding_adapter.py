#!/usr/bin/env python3
"""Pure planning helpers for the versioned flooding revision cells.

The legacy noise-profile runner owns a deliberately large profile matrix.  A
revision cell is a smaller, explicit contract around one of those profiles;
this module validates that contract and produces the one shard command that a
runner may execute.  It never imports OpenFHE, starts a process, or writes a
result.

The public functions intentionally accept ordinary dictionaries so that the
planner can be used from the shell wrapper and from small Python contract
tests without introducing a second runtime dependency.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


PAPER_PROFILE = "paper-v1"
TOY_PROFILE = "readiness-toy-v1"
PROFILE_IDS = ("primary40", "sensitivity64", "feasibility128")
PATTERNS = ("zero", "random", "adversarial")
CONTROL_GEOMETRY = {"k": 128, "m": 64, "n": 1000, "u": 65536}
NOISE_MATRIX_NAME = "noise_profiles.json"


class FloodingRevisionError(ValueError):
    """Raised when a flooding revision-cell contract is malformed."""


def _reject(message: str) -> None:
    raise FloodingRevisionError("invalid flooding revision cell: " + message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _reject(message)


def load_revision_matrix(path: str | Path) -> Mapping[str, Any]:
    """Load the canonical revision matrix without mutating it."""

    matrix_path = Path(path)
    try:
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FloodingRevisionError(
            f"cannot load revision matrix {matrix_path}: {error}"
        ) from error
    _require(isinstance(matrix, dict), "revision matrix must be an object")
    _require(matrix.get("schema") == "piccard-revision-matrix-v1" and
             matrix.get("version") == 1,
             "revision matrix schema/version mismatch")
    return matrix


def select_cell(matrix: Mapping[str, Any], cell_id: str) -> Mapping[str, Any]:
    """Return exactly the requested flooding cell from the revision matrix."""

    cells = matrix.get("cells")
    _require(isinstance(cells, list), "revision matrix cells must be a list")
    matches = [cell for cell in cells
               if isinstance(cell, dict) and cell.get("cell_id") == cell_id]
    _require(len(matches) == 1, "cell ID is missing or duplicated")
    cell = matches[0]
    validate_cell(cell, cell_id)
    return cell


def validate_cell(cell: Mapping[str, Any], expected_id: str | None = None) -> None:
    """Fail closed on the frozen three-cell flooding contract."""

    cell_id = cell.get("cell_id")
    _require(isinstance(cell_id, str) and cell_id,
             "cell_id must be a non-empty string")
    if expected_id is not None:
        _require(cell_id == expected_id, "selected cell ID mismatch")
    _require(cell_id.startswith("paper-v1::flooding::profile="),
             "cell ID must bind paper-v1/flooding/profile")
    profile_id = cell_id.rsplit("=", 1)[-1]
    _require(profile_id in PROFILE_IDS, "unknown flooding profile")
    _require(cell.get("profile") == PAPER_PROFILE,
             "matrix profile must be paper-v1")
    _require(cell.get("family") == "flooding", "family must be flooding")
    _require(cell.get("producer") == "bench_noise",
             "logical producer must be bench_noise")
    _require(cell.get("artifact_schema") == "noise-profile-v1" and
             cell.get("expected_artifact_schema") == "noise-profile-v1",
             "artifact schema must be noise-profile-v1")
    _require(cell.get("dataset") == "synthetic", "dataset must be synthetic")
    _require(cell.get("axis") == "profile" and
             cell.get("axis_value") == profile_id and
             cell.get("noise_profile") == profile_id,
             "profile axis is inconsistent with cell ID")
    _require(cell.get("invocation_status") == "RUN",
             "flooding cell must be RUN")
    _require(cell.get("eligibility") == "DIAGNOSTIC_ONLY" and
             cell.get("table_eligible") is False and
             cell.get("comparison_eligible") is False,
             "flooding cell must be diagnostic-only")
    _require(cell.get("timeout_class") == "standard",
             "timeout class must be standard")
    _require(cell.get("timing_contract") == "NOT_APPLICABLE",
             "flooding timing contract must be NOT_APPLICABLE")

    axes = cell.get("axes")
    _require(axes == CONTROL_GEOMETRY,
             "flooding axes must use the frozen control geometry")

    _require(cell.get("paper_count") == 5 and cell.get("paper_trials") == 5,
             "paper repetitions must be five")
    _require(cell.get("toy_count") == 1 and cell.get("toy_trials") == 1,
             "toy repetitions must be one")
    _require(cell.get("paper_counts") == {"repetitions_per_pattern": 5},
             "paper repetition metadata mismatch")
    _require(cell.get("toy_counts") == {"repetitions_per_pattern": 1},
             "toy repetition metadata mismatch")

    rows = cell.get("expected_rows")
    _require(isinstance(rows, list) and len(rows) == len(PATTERNS),
             "flooding requires exactly three expected rows")
    for row, pattern in zip(rows, PATTERNS):
        _require(isinstance(row, dict), "expected row must be an object")
        _require(row.get("row_id") == pattern and row.get("pattern") == pattern,
                 f"expected row must select {pattern}")
        _require(row.get("status") == "DIAGNOSTIC" and
                 row.get("terminal_status") == "DIAGNOSTIC",
                 "flooding rows must be DIAGNOSTIC")
        _require(row.get("timing_contract") == "NOT_APPLICABLE",
                 "flooding rows must not claim timing")
        _require(row.get("reason") == "" and row.get("reason_code") == "",
                 "flooding rows must not carry a failure reason")
        _require(row.get("paper_measured_count") == 5 and
                 row.get("toy_measured_count") == 1 and
                 row.get("measured_count") == 5,
                 "flooding row repetition counts mismatch")


def select_noise_partition(noise_matrix: Mapping[str, Any],
                           profile_id: str) -> Mapping[str, Any]:
    """Select the single canonical STD128 one-hot shard for a profile.

    The legacy profile matrix contains many keys.  The revision contract uses
    the existing STD128 one-hot key whose logical control point includes
    ``k=128,m=64``.  Requiring one exact match makes accidental profile-wide
    fan-out impossible in the successor path while retaining the key's full
    consumer-set identity.
    """

    _require(profile_id in PROFILE_IDS, "unknown noise profile")
    partitions = noise_matrix.get("partitions")
    _require(isinstance(partitions, list), "noise matrix partitions must be a list")
    matches = []
    for partition in partitions:
        if not isinstance(partition, dict):
            continue
        if partition.get("profile_id") != profile_id:
            continue
        if (partition.get("circuit") == "onehot" and
                partition.get("shape_id") == "onehot-v1" and
                partition.get("security") == "STD128" and
                partition.get("requested_ring_dim") == 8192 and
                partition.get("natural_depth") == 1 and
                any(point == {"k": 128, "m": 64} for point in
                    partition.get("consumer_points", []))):
            matches.append(partition)
    _require(len(matches) == 1,
             "noise matrix must have one canonical STD128 one-hot shard")
    partition = matches[0]
    _require(len(partition.get("consumer_points", [])) > 0,
             "canonical noise shard has no consumer points")
    return partition


def plan_cell(cell: Mapping[str, Any], run_profile: str,
              output_root: str = "{output}", seed: str = "{seed}",
              threads: str = "{threads}",
              wrapper: str = "scripts/run_noise_profiles.sh") -> dict[str, Any]:
    """Build pure metadata and one immutable wrapper invocation.

    The wrapper is the executable owner of the successor interface; it then
    resolves the selected matrix cell to one internal ``bench_noise`` shard.
    Keeping that boundary explicit is important because ``bench_noise`` itself
    intentionally retains its legacy evidence CLI.
    """

    validate_cell(cell)
    _require(run_profile in (PAPER_PROFILE, TOY_PROFILE),
             "run profile must be paper-v1 or readiness-toy-v1")
    profile_id = str(cell["axis_value"])
    if run_profile == TOY_PROFILE:
        _require(profile_id == "primary40",
                 "readiness-toy-v1 supports primary40 only")
    repetitions = 5 if run_profile == PAPER_PROFILE else 1
    # The exact shard identity is resolved by the wrapper after loading the
    # tracked noise matrix.  Keep this command at the canonical public
    # boundary so planning remains process-free and deterministic.
    command = [
        wrapper,
        f"--revision-cell={cell['cell_id']}",
        f"--run-profile={run_profile}",
        f"--profile={profile_id}",
        f"--repetitions={repetitions}",
        f"--results-root={output_root}",
        f"--seed={seed}",
        f"--threads={threads}",
    ]
    return {
        "schema": "flooding-revision-invocation-v1",
        "cell_id": cell["cell_id"],
        "logical_producer": "bench_noise",
        "run_profile": run_profile,
        "profile_id": profile_id,
        "repetitions_per_pattern": repetitions,
        "patterns": list(PATTERNS),
        "table_eligible": False,
        "status": "READINESS_ONLY" if run_profile == TOY_PROFILE
        else "DRY_RUN_ONLY",
        "timing_contract": "NOT_APPLICABLE",
        "command": command,
        "environment": {
            "DRY_RUN": "1" if run_profile == PAPER_PROFILE else "0",
            "OMP_DYNAMIC": "FALSE",
            "OMP_NUM_THREADS": threads,
        },
    }


# Descriptive aliases make the module convenient for independent contract
# tests and preserve a small, stable surface for the shell wrapper.
load_cell = select_cell
build_plan = plan_cell


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--cell-id", required=True)
    parser.add_argument("--run-profile", required=True,
                        choices=(PAPER_PROFILE, TOY_PROFILE))
    parser.add_argument("--output", default="{output}")
    args = parser.parse_args(argv)
    try:
        matrix = load_revision_matrix(args.matrix)
        cell = select_cell(matrix, args.cell_id)
        plan = plan_cell(cell, args.run_profile, args.output)
    except FloodingRevisionError as error:
        parser.error(str(error))
    print(json.dumps(plan, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
