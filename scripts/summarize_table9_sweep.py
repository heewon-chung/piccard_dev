#!/usr/bin/env python3
"""Summarize a Table IX sweep (scripts/run_table9_sweep.py) into CSV, LaTeX
rows for tbl:comp, and a flatness report, using only the producers' own
sidecar aggregates (mean, sample SD, median, Student-t 95% CI).

Not every baseline consumes every axis the table varies, so several rows
repeat the family's default-point measurement instead of pointing at a cell
that would only re-measure the same configuration:
  - SJ16's Sj16Adapter constructor takes (method, key_bits, universe, ...) --
    no k or m (benchmarks/bench_review_comparison.cpp:941-950).
  - BCG12Params is {mode, backend, k, minhash_seed} and src/baselines/
    bcg12.cpp never references universe -- no |U| or m
    (include/baselines/bcg12.h:12-18).
  - FHE-IND's BaselineEngine takes only universe_size (benchmarks/baseline_engine.h:37,
    also referenced at 57); the benchmark harness's own Options struct additionally
    varies set_size (benchmarks/bench_fhe_ind.cpp:70,86-87) -- no k or m in either.

SJ16 at |U| = 2^18 and 2^20 was never executed; those two cells have no
sidecar at all, and the paper carries a calibrated extrapolation instead
(EXTRAPOLATED_SJ16).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts.revision_benchmark_common import slug  # noqa: E402
from scripts.run_table9_sweep import TABLE9_CELL_IDS  # noqa: E402

PRINTED = ("piccard", "piccard_plus", "bcg12_ec", "sj16", "fhe_ind")
# family -> [(filename needle, phase, column, cell_id suffix in the sidecar header)]
SOURCES = {
    "piccard_std128": [("bench_piccard__", "total", "piccard", "")],
    "sqrt_comparison": [("__sqrt__", "total", "piccard_plus", "::sqrt")],   # bench_onehot_sqrt stamps '<cell>::<arm>' (bench_onehot_sqrt.cpp:870,906)
    "bcg12_minhash": [("bcg12_mh_ec", "total", "bcg12_ec", "::bcg12_mh_ec"),
                      ("bcg12_mh_ff", "total", "bcg12_ff", "::bcg12_mh_ff")],
    "sj16": [("__sj16__", "total", "sj16", "::sj16")],
    "fhe_ind": [("bench_fhe_ind__", "online_e2e", "fhe_ind", "")],
}
FAMILY_OF = {"piccard": "piccard_std128", "piccard_plus": "sqrt_comparison",
             "bcg12_ec": "bcg12_minhash", "bcg12_ff": "bcg12_minhash", "sj16": "sj16",
             "fhe_ind": "fhe_ind"}
TABLE_ROWS = (  # (block, u, n, k, m) in tbl:comp order
    ("u", 16384, 1000, 128, 64), ("u", 65536, 1000, 128, 64), ("u", 262144, 1000, 128, 64), ("u", 1048576, 1000, 128, 64),
    ("n", 65536, 100, 128, 64), ("n", 65536, 1000, 128, 64), ("n", 65536, 10000, 128, 64),
    ("k", 65536, 1000, 16, 64), ("k", 65536, 1000, 64, 64), ("k", 65536, 1000, 128, 64), ("k", 65536, 1000, 256, 64), ("k", 65536, 1000, 512, 64),
    ("m", 65536, 1000, 128, 16), ("m", 65536, 1000, 128, 64), ("m", 65536, 1000, 128, 128), ("m", 65536, 1000, 128, 256),
)
DEFAULT = (65536, 1000, 128, 64)


class SweepError(RuntimeError):
    pass


class Aggregate(NamedTuple):
    mean_ms: float
    sd_ms: float
    median_ms: float
    ci95_half_ms: float
    measured_count: int
    ci95_low_ms: float
    ci95_high_ms: float


# Axes each protocol actually consumes.  A row whose block is not in this set
# repeats the family's default-point measurement, because the sweep does not
# measure a cell that would only re-measure the same configuration.  See the
# module docstring for the source evidence.
CONSUMED_AXES = {
    "piccard": {"u", "n", "k", "m"},
    "piccard_plus": {"u", "n", "k", "m"},
    "bcg12_ec": {"n", "k"},
    "bcg12_ff": {"n", "k"},
    "sj16": {"u", "n"},
    "fhe_ind": {"u", "n"},
}
# SJ16 at these universes was never executed; the paper carries a calibrated
# extrapolation.  (mean_ms, ci95_half_ms or None when there is no interval.)
EXTRAPOLATED_SJ16 = {262144: (285389.0, None), 1048576: (1141500.0, None)}


def cell_for(block: str, u: int, n: int, k: int, m: int, column: str) -> str | None:
    """Return the matrix cell whose measurement fills this row, or None.

    None means "no sidecar for this row": either the cell is not applicable
    (Piccard+ at a non-square m) or the value comes from the paper's
    extrapolation (SJ16 at |U| = 2^18, 2^20).
    """
    family = FAMILY_OF[column]
    if column == "piccard_plus" and int(m ** 0.5) ** 2 != m:
        return None
    if column == "sj16" and block == "u" and u in EXTRAPOLATED_SJ16:
        return None
    prefix = "timing_" if family == "sqrt_comparison" else ""
    if (u, n, k, m) == DEFAULT or block not in CONSUMED_AXES[column]:
        return f"paper-v1::{family}::{prefix}u=65536"
    value = {"u": u, "n": n, "k": k, "m": m}[block]
    return f"paper-v1::{family}::{prefix}{block}={value}"


def _parse_sidecar(path: Path, phase: str, expected_cell_id: str) -> Aggregate:
    header: dict[str, str] = {}
    samples = 0
    columns: list[str] = []
    agg: Aggregate | None = None
    for line in path.read_text().splitlines():
        f = line.split("\t")
        if len(f) == 2:
            header[f[0]] = f[1]
        elif f[0] == "sample" and len(f) > 5 and f[4] == phase and f[5] == "measured":
            samples += 1
        elif f[0] == "aggregate" and len(f) > 1 and f[1] == "producer_id":
            columns = f
        elif f[0] == "aggregate" and columns and f[columns.index("phase")] == phase:
            row = dict(zip(columns, f))
            low, high = float(row["ci95_low_ms"]), float(row["ci95_high_ms"])
            agg = Aggregate(float(row["mean_ms"]), float(row["sample_sd_ms"]), float(row["median_ms"]),
                            (high - low) / 2.0, int(row["measured_count"]), low, high)
    if header.get("schema_version") != "piccard-paper-raw-timing-v1" or header.get("profile_id") != "paper-v1":
        raise SweepError(f"{path}: not a paper-v1 raw-timing-v1 sidecar")
    if header.get("cell_id") != expected_cell_id:
        raise SweepError(f"{path}: sidecar cell_id {header.get('cell_id')!r} != {expected_cell_id!r}")
    if agg is None:
        raise SweepError(f"{path}: no aggregate for phase {phase}")
    if header.get("expected_measured") != "30" or samples != 30 or agg.measured_count != 30:
        raise SweepError(f"{path}: expected 30 measured samples; header={header.get('expected_measured')} "
                         f"samples={samples} aggregate={agg.measured_count}")
    return agg


def load_aggregates(root: Path) -> dict[tuple[str, str], Aggregate]:
    out: dict[tuple[str, str], Aggregate] = {}
    for cell_id in TABLE9_CELL_IDS:
        cell_dir = root / "cells" / slug(cell_id)
        if not cell_dir.is_dir():
            continue
        family = cell_id.split("::")[1]
        for needle, phase, column, suffix in SOURCES[family]:
            matches = [p for p in cell_dir.rglob("*.tsv") if needle in p.name]
            if len(matches) != 1:
                raise SweepError(f"{cell_dir}: expected one sidecar containing {needle!r}, found {len(matches)}")
            out[(cell_id, column)] = _parse_sidecar(matches[0], phase, cell_id + suffix)
    return out


def _num(value: float, decimals: int) -> str:
    return f"{value:,.{decimals}f}".replace(",", "{,}")


def format_cell(agg: Aggregate | None) -> str:
    if agg is None:
        return "---"
    d = 0 if agg.mean_ms >= 10000 else 1
    if agg.measured_count == 0 or agg.ci95_half_ms != agg.ci95_half_ms:  # extrapolated: no interval
        return f"${_num(agg.mean_ms, d)}$"
    return f"${_num(agg.mean_ms, d)}\\pm{_num(agg.ci95_half_ms, d)}$"


def _lookup(aggs: dict[tuple[str, str], Aggregate], row: tuple, column: str) -> Aggregate | None:
    block, u, n, k, m = row
    if column == "sj16" and block == "u" and u in EXTRAPOLATED_SJ16:
        mean, half = EXTRAPOLATED_SJ16[u]
        return Aggregate(mean, 0.0, mean, half if half is not None else float("nan"),
                         0, 0.0, 0.0)
    cid = cell_for(*row, column)
    return None if cid is None else aggs.get((cid, column))


def render_rows(aggs: dict[tuple[str, str], Aggregate]) -> str:
    lines = []
    for row in TABLE_ROWS:
        _, u, n, k, m = row
        cells = " & ".join(format_cell(_lookup(aggs, row, c)) for c in PRINTED)
        lines.append(f"\t$2^{{{u.bit_length() - 1}}}$ & {n:,} & {k} & {m} & {cells} \\\\")
    return "\n".join(lines) + "\n"


def missing_cells(aggs: dict[tuple[str, str], Aggregate]) -> list[str]:
    """Rows whose sidecar is absent.  Extrapolated and N/A rows are not gaps."""
    gaps = set()
    for row in TABLE_ROWS:
        for c in PRINTED:
            cid = cell_for(*row, c)
            if cid is not None and (cid, c) not in aggs:
                gaps.add(f"{cid}:{c}")
    return sorted(gaps)


def flatness(aggs: dict[tuple[str, str], Aggregate]) -> str:
    """Report max/min of mean_ms within each block, per column, over measured
    rows only (1.000 = perfectly flat).  A cell reads one of three ways:
      - a ratio, when the block has two or more distinct measured cells;
      - "not an input", when every row in the block resolves to the same
        cell id (per CONSUMED_AXES / cell_for) -- the ratio would be a
        tautology, one number divided by itself;
      - "insufficient measured rows", when fewer than two real (non-
        extrapolated) aggregates are available -- extrapolated rows
        (measured_count == 0, e.g. EXTRAPOLATED_SJ16) are always excluded
        from the ratio and, when present, are called out by count.
    """
    lines = ["# Flatness report", "",
             "max/min of mean_ms within each block, per column, over MEASURED rows only "
             "(1.000 = perfectly flat). \"not an input\" = every row in the block is the same "
             "cell (the axis isn't a protocol input, not a measurement). \"insufficient measured "
             "rows\" = fewer than two real aggregates; extrapolated rows are always excluded and "
             "counted when present.", "",
             "| block | " + " | ".join(PRINTED) + " |", "|---|" + "---|" * len(PRINTED)]
    for block in ("u", "n", "k", "m"):
        rows = [r for r in TABLE_ROWS if r[0] == block]
        cells = []
        for c in PRINTED:
            distinct_ids = {cid for cid in (cell_for(*r, c) for r in rows) if cid is not None}
            if len(distinct_ids) <= 1:
                cells.append("n/a (not an input)")
                continue
            looked_up = [_lookup(aggs, r, c) for r in rows]
            extrapolated = [a for a in looked_up if a is not None and a.measured_count == 0]
            measured = [a.mean_ms for a in looked_up if a is not None and a.measured_count > 0]
            if len(measured) < 2:
                cells.append("n/a (insufficient measured rows)")
            elif extrapolated:
                ratio = max(measured) / min(measured)
                cells.append(f"{ratio:.3f} ({len(extrapolated)} of {len(rows)} rows extrapolated, excluded)")
            else:
                cells.append(f"{max(measured) / min(measured):.3f}")
        lines.append(f"| {block} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def write_csv(aggs: dict[tuple[str, str], Aggregate], path: Path) -> None:
    with path.open("w", newline="") as handle:
        w = csv.writer(handle)
        w.writerow(["cell_id", "column", "measured_count", "mean_ms", "sd_ms", "median_ms", "ci95_half_ms"])
        for (cid, column), a in sorted(aggs.items()):
            w.writerow([cid, column, a.measured_count, f"{a.mean_ms:.6f}", f"{a.sd_ms:.6f}",
                        f"{a.median_ms:.6f}", f"{a.ci95_half_ms:.6f}"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--partial", action="store_true", help="tolerate missing cells (tests only)")
    parser.add_argument("--allow-nonstandard", action="store_true",
                        help="summarize a run that is not COMPLETED, was dirty, carries mixed provenance, "
                             "or is not 16 threads / seed 20260729")
    args = parser.parse_args(argv)
    root = Path(args.results_root)
    manifest = json.loads((root / "run.json").read_text())
    prov = manifest.get("provenance", {})
    nonstandard = (manifest.get("state") != "COMPLETED" or manifest.get("dirty_allowed")
                   or manifest.get("mixed_provenance")
                   or prov.get("threads") != 16 or prov.get("seed") != 20260729
                   or any(c.get("execution_status") != "COMPLETED" for c in manifest.get("cells", [])))
    if nonstandard and not args.allow_nonstandard:
        print("refusing a nonstandard run (state, dirty tree, mixed provenance, threads, seed, "
              "or failed cells); pass --allow-nonstandard to override", file=sys.stderr)
        return 1
    try:
        aggs = load_aggregates(root)
    except SweepError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    gaps = missing_cells(aggs)
    if gaps and not args.partial:
        print("missing cells: " + ", ".join(gaps), file=sys.stderr)
        return 1
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(aggs, out / "table9.csv")
    (out / "table9_rows.tex").write_text(render_rows(aggs))
    (out / "flatness.md").write_text(flatness(aggs))
    print(f"wrote {out}: {len(aggs)} aggregates, {len(gaps)} missing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
