#!/usr/bin/env python3
"""Summarize a scripts/run_deletion_survival.py run into the fig:del-survival
coordinates, the paper's scalars, and a Monte-Carlo-vs-exact agreement table.

Reads only the run's own artefacts (run.json, the archived matrix.json, and
the two cells' stdout CSVs).  Exact columns are re-derived in Python from
Pr[r* > r] = (1 - C(r,d)/C(n,d))^k and must agree with the producer's
exact_survival column to 1e-9, and the exact cell's exact columns must be
byte-identical to the Monte-Carlo cell's, so a stale or mismatched cell can
never be summarized.

Everything fig:del-survival assumes about its run is also a gate: both cells
must carry the full ordered 27-point grid r = 0,20,...,520 (hence exactly 14
markers) at (n,d,k) = (1024,5,128), with trials 0 / 100000 and seed 20260729 on
every row and in the manifest; the run must be single-provenance, with every
manifest cell COMPLETED under the run's provenance_id and every receipt's
stdout_sha256 matching its own stdout.log; and the archived matrix.json must be
the committed matrix, i.e. the digest in benchmarks/revision_summary_argv_contract.json.

  python3 scripts/summarize_deletion_survival.py --results-root=/abs/dir [--output-dir=/abs/dir/summary]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts.revision_benchmark_common import slug  # noqa: E402

EXACT_ID = "paper-v1::deletion_exact::d=5"
MC_ID = "paper-v1::deletion_mc::d=5"
HEADER = [
    "model", "n", "d", "k", "required_survival", "r", "exact_survival",
    "union_bound_survival", "mc_survival", "mc_standard_error",
    "maximum_safe_deletions", "exact_expected_first_failure",
    "exact_expected_safe_deletions", "mc_mean_first_failure",
    "mc_mean_safe_deletions", "trials", "seed",
]
EXACT_COLUMNS = ("r", "exact_survival", "union_bound_survival", "maximum_safe_deletions",
                 "exact_expected_first_failure", "exact_expected_safe_deletions")

# What fig:del-survival assumes about the run it is drawn from.  The figure's
# 27-point curve and 14 markers, its caption's (n,d,k), its trial count and its
# seed are all baked into the manuscript, so a run that differs in any of them
# must be refused rather than quietly plotted.
GRID = [str(r) for r in range(0, 521, 20)]
EXPECTED_CONFIG = (1024, 5, 128)
EXPECTED_TRIALS = 100000
EXPECTED_SEED = 20260729
ARGV_CONTRACT = ROOT / "benchmarks" / "revision_summary_argv_contract.json"


class SummaryError(RuntimeError):
    pass


def exact_survival(n: int, d: int, k: int, r: int) -> float:
    if r < d:
        return 1.0
    q = math.comb(r, d) / math.comb(n, d)
    if q >= 1.0:
        return 0.0
    return math.exp(k * math.log1p(-q))


def parse_cell_csv(text: str) -> list[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames != HEADER:
        raise SummaryError(f"unexpected deletion CSV header: {reader.fieldnames}")
    rows = list(reader)
    if not rows:
        raise SummaryError("deletion CSV has no rows")
    return rows


def _load_cell(root: Path, cell_id: str, provenance_id: Any, *, trials: int) -> list[dict[str, str]]:
    out = root / "cells" / slug(cell_id)
    receipt = json.loads((out / "receipt.json").read_text())
    if receipt.get("cell_id") != cell_id or receipt.get("execution_status") != "COMPLETED":
        raise SummaryError(f"{cell_id}: receipt is not COMPLETED")
    if receipt.get("provenance_id") != provenance_id:
        raise SummaryError(f"{cell_id}: receipt provenance_id {receipt.get('provenance_id')!r} "
                           f"!= run provenance_id {provenance_id!r}")
    stdout_bytes = (out / "stdout.log").read_bytes()
    digest = hashlib.sha256(stdout_bytes).hexdigest()
    if receipt.get("stdout_sha256") != digest:
        raise SummaryError(f"{cell_id}: stdout.log digest {digest} != receipt "
                           f"stdout_sha256 {receipt.get('stdout_sha256')!r}")
    rows = parse_cell_csv(stdout_bytes.decode())
    _check_rows(rows, cell_id, trials=trials)
    return rows


def _check_rows(rows: list[dict[str, str]], cell_id: str, *, trials: int) -> None:
    """Every row must sit on the figure's grid, at the figure's configuration,
    with the pinned trial count and seed -- not just the first one."""
    if [row["r"] for row in rows] != GRID:
        raise SummaryError(f"{cell_id}: r column is not the ordered 27-point grid "
                           f"0,20,...,520 (got {len(rows)} rows: {[row['r'] for row in rows]})")
    for row in rows:
        config = (int(row["n"]), int(row["d"]), int(row["k"]))
        if config != EXPECTED_CONFIG:
            raise SummaryError(f"{cell_id}: unexpected configuration {config} at r={row['r']}")
        if int(row["trials"]) != trials:
            raise SummaryError(f"{cell_id}: trials {row['trials']} != {trials} at r={row['r']}")
        if int(row["seed"]) != EXPECTED_SEED:
            raise SummaryError(f"{cell_id}: seed {row['seed']} != {EXPECTED_SEED} at r={row['r']}")


def join(exact_rows: list[dict[str, str]], mc_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    if len(exact_rows) != len(mc_rows):
        raise SummaryError("exact and Monte-Carlo cells have different row counts")
    points = []
    for e, m in zip(exact_rows, mc_rows):
        for column in EXACT_COLUMNS:
            if e[column] != m[column]:
                raise SummaryError(f"exact column {column} differs between cells at r={e['r']}")
        r = int(e["r"])
        exact = float(e["exact_survival"])
        mc = float(m["mc_survival"])
        se = float(m["mc_standard_error"])
        z = 0.0 if se == 0.0 else (mc - exact) / se
        points.append({"r": r, "exact": exact, "mc": mc, "se": se, "z": z,
                       "figure_marker": r % 40 == 0})
    return points


def summarize(root: Path) -> dict[str, Any]:
    manifest = json.loads((root / "run.json").read_text())
    if manifest.get("state") != "COMPLETED":
        raise SummaryError(f"run state is {manifest.get('state')!r}, not COMPLETED")
    if manifest.get("cell_ids") != [EXACT_ID, MC_ID]:
        raise SummaryError("run does not contain exactly the two d=5 deletion cells")
    archived = hashlib.sha256((root / "matrix.json").read_bytes()).hexdigest()
    recorded = manifest["provenance"]["matrix_sha256"]
    if archived != recorded:
        raise SummaryError(f"matrix.json archive {archived} != recorded {recorded}")
    # A run whose archived matrix is internally consistent can still have come
    # from a matrix that is not the committed one; the argv contract carries the
    # digest the rest of the revision tooling was built against.
    contract = json.loads(ARGV_CONTRACT.read_text())["matrix_sha256"]
    if archived != contract:
        raise SummaryError(f"matrix.json archive {archived} != committed matrix {contract} "
                           f"in {ARGV_CONTRACT.name}")

    if manifest.get("mixed_provenance"):
        raise SummaryError("run has mixed provenance: "
                           f"{manifest.get('provenance_cells')}")
    provenance_id = manifest.get("provenance_id")
    for cell in manifest.get("cells", []):
        if cell.get("execution_status") != "COMPLETED":
            raise SummaryError(f"{cell.get('cell_id')}: manifest execution_status is "
                               f"{cell.get('execution_status')!r}, not COMPLETED")
        if cell.get("provenance_id") != provenance_id:
            raise SummaryError(f"{cell.get('cell_id')}: manifest provenance_id "
                               f"{cell.get('provenance_id')!r} != run provenance_id {provenance_id!r}")
    manifest_seed = int(manifest["provenance"]["seed"])
    if manifest_seed != EXPECTED_SEED:
        raise SummaryError(f"run seed {manifest_seed} != {EXPECTED_SEED}")

    exact_rows = _load_cell(root, EXACT_ID, provenance_id, trials=0)
    mc_rows = _load_cell(root, MC_ID, provenance_id, trials=EXPECTED_TRIALS)
    first = mc_rows[0]
    n, d, k = EXPECTED_CONFIG
    trials = EXPECTED_TRIALS
    points = join(exact_rows, mc_rows)
    for p in points:
        if abs(exact_survival(n, d, k, p["r"]) - p["exact"]) > 1e-9:
            raise SummaryError(f"producer exact_survival disagrees with the closed form at r={p['r']}")
    markers = [p for p in points if p["figure_marker"]]
    return {
        "schema": "piccard-deletion-survival-summary-v1",
        "config": {"n": n, "d": d, "k": k, "required_survival": first["required_survival"]},
        "trials": trials, "seed": int(first["seed"]),
        "matrix_sha256": recorded, "run_provenance_id": manifest.get("provenance_id"),
        "exact": {
            "maximum_safe_deletions": int(first["maximum_safe_deletions"]),
            "expected_first_failure": float(first["exact_expected_first_failure"]),
            "expected_safe_deletions": float(first["exact_expected_safe_deletions"]),
            "S_156": exact_survival(n, d, k, 156),
            "S_157": exact_survival(n, d, k, 157),
        },
        "monte_carlo": {
            "mean_first_failure": float(first["mc_mean_first_failure"]),
            "mean_safe_deletions": float(first["mc_mean_safe_deletions"]),
        },
        "points": points,
        "max_abs_z_at_markers": max(abs(p["z"]) for p in markers),
        "markers_above": sum(p["mc"] > p["exact"] for p in markers),
        "markers_below": sum(p["mc"] < p["exact"] for p in markers),
        "markers_equal": sum(p["mc"] == p["exact"] for p in markers),
    }


def _block(pairs: list[str]) -> str:
    lines = []
    for i in range(0, len(pairs), 6):
        lines.append("\t\t" + " ".join(pairs[i:i + 6]))
    return "\n".join(lines)


def render_coordinates(points: list[dict[str, Any]], source: str = "run", *,
                       trials: int, seed: int) -> str:
    exact = [f"({p['r']},{p['exact']:.4f})" for p in points]
    mc = [f"({p['r']},{p['mc']:.4f})" for p in points if p["figure_marker"]]
    return (
        f"% generated by scripts/summarize_deletion_survival.py from {source}\n"
        "% exact, Pr[r* > r], (n,d,k)=(1024,5,128)\n"
        "\t\\addplot[smooth, thick, blue] coordinates {\n"
        f"{_block(exact)}\n"
        "\t};\n"
        f"% Monte-Carlo, {trials} runs, seed {seed}\n"
        "\t\\addplot[only marks, mark=o, mark size=1.6pt, red] coordinates {\n"
        f"{_block(mc)}\n"
        "\t};\n"
    )


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# fig:del-survival regeneration", "",
        f"(n,d,k) = ({result['config']['n']},{result['config']['d']},{result['config']['k']}), "
        f"Monte-Carlo {result['trials']} trials, seed {result['seed']}, matrix {result['matrix_sha256'][:12]}…", "",
        "| r | exact | MC | SE | z |", "|---|---|---|---|---|",
    ]
    for p in result["points"]:
        if p["figure_marker"]:
            lines.append(f"| {p['r']} | {p['exact']:.5f} | {p['mc']:.5f} | {p['se']:.5f} | {p['z']:+.2f} |")
    e, m = result["exact"], result["monte_carlo"]
    lines += [
        "",
        f"- max |z| over the 14 markers: {result['max_abs_z_at_markers']:.2f}; "
        f"above/below/equal: {result['markers_above']}/{result['markers_below']}/{result['markers_equal']}",
        f"- exact: max safe deletions {e['maximum_safe_deletions']}, E[r*] = {e['expected_first_failure']:.4f}, "
        f"S(156) = {e['S_156']:.6f}, S(157) = {e['S_157']:.6f}",
        f"- Monte-Carlo: E[r*] = {m['mean_first_failure']:.4f}",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--output-dir")
    args = parser.parse_args(argv)
    root = Path(args.results_root).resolve()
    out = Path(args.output_dir).resolve() if args.output_dir else root / "summary"
    result = summarize(root)
    out.mkdir(parents=True, exist_ok=True)
    (out / "del_survival.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (out / "fig_del_survival_coordinates.tex").write_text(
        render_coordinates(result["points"], root.name, trials=result["trials"], seed=result["seed"]))
    (out / "summary.md").write_text(render_markdown(result))
    print(f"summary written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
