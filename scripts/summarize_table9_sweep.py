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

SJ16 at |U| = 2^18 and 2^20 is `NO_SPAWN` in the matrix and will never be
measured -- not merely unswept by this campaign. Those two cells have no
sidecar at all, and the paper prints EXTRAPOLATED_SJ16 for both rows, but
the name is only half accurate: the |U|=2^18 figure (285,388.74 ms) is not
an extrapolation, it is the 2026-08-20 campaign's own sj16::n=100000
measurement, reused for that row; only the |U|=2^20 figure is a calibrated
extrapolation from it. See the comment above EXTRAPOLATED_SJ16.

Every printed number is bound to evidence, not merely to intention: the
run's declared thread count is cross-checked against what a producer
actually recorded (check_thread_provenance); load_aggregates fails if a
real cell directory exists for either EXTRAPOLATED_SJ16 id, since that
would mean the constants are stale; and the run's own matrix_sha256 must
match the sha256 of <results-root>/matrix.json -- the matrix the run was
actually planned against, archived alongside it -- never the repository's
present matrix, which keeps evolving after a run is archived
(_archived_matrix_sha256).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts.revision_benchmark_common import sha256_file, slug  # noqa: E402
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
# SJ16 at these two universes is NO_SPAWN in the matrix: not measured in
# this campaign, and not scheduled by any full run either.  Despite the
# name, only one of the two values is actually extrapolated:
#   - |U|=2^18 (285,389 ms) is NOT an extrapolation -- it is the 2026-08-20
#     campaign's own sj16::n=100000 measurement (sidecar aggregate
#     285,388.74 ms), reused as-is for this row.  That receipt's argv
#     records "--threads=2", but that flag is inert for
#     bench_review_comparison (only OMP_NUM_THREADS applies, and that
#     artifact's own omp_threads field records 16), so this is a genuine
#     16-thread measurement, not a mix of thread counts.
#   - |U|=2^20 (1,141,500 ms) IS a calibrated extrapolation, derived from
#     the |U|=2^18 measurement above.
# (mean_ms, ci95_half_ms or None when there is no interval.)
EXTRAPOLATED_SJ16 = {262144: (285389.0, None), 1048576: (1141500.0, None)}


def _manifest_cell_gap(manifest: dict) -> tuple[set[str], set[str]]:
    """(missing, unexpected): the symmetric difference between the
    manifest's COMPLETED cell ids and the full TABLE9_CELL_IDS set.

    A run can declare fewer cells than the sweep requires (or cells outside
    it) while genuine sidecars from an unrelated run or attempt still sit on
    disk under the same results root.  This binds the printed table to what
    THIS run's manifest claims to have executed, not merely to what files
    happen to exist.
    """
    completed = {c.get("cell_id") for c in manifest.get("cells", []) if c.get("execution_status") == "COMPLETED"}
    expected = set(TABLE9_CELL_IDS)
    return expected - completed, completed - expected


def _archived_matrix_sha256(root: Path) -> str:
    """sha256 of `<root>/matrix.json` -- the exact matrix this run was
    planned against, archived alongside the run itself.

    Deliberately never the repository's present matrix: a summary
    describes a run, not the repository's current state, and the matrix
    keeps evolving after a run is archived. Comparing against the repo's
    copy would make an old, valid run permanently unreproducible the
    moment the matrix next changes for unrelated reasons (Q-3 v2 -- the
    v1 design compared against the repo's matrix and was wrong for exactly
    this reason). If a results root predates archiving its own matrix,
    that is a missing prerequisite, not something to silently substitute
    the repo's copy for -- so this raises rather than falling back.
    """
    matrix_path = root / "matrix.json"
    if not matrix_path.is_file():
        raise SweepError(f"{root}: no matrix.json -- a results root must archive the exact matrix it "
                         f"was planned against; the repository's current matrix is not a substitute")
    return sha256_file(matrix_path)


# The one producer that actually records omp_threads/omp_dynamic in its
# output.  Measured directly against the real archived run: all 11
# bench_review_comparison cells (7 bcg12_minhash + 4 sj16) record it (value
# {'16'}); all 31 cells from the other three producers (bench_piccard,
# bench_onehot_sqrt, bench_fhe_ind) record nothing of the kind.  Hard-coded
# here as a single producer name -- rather than a family list -- because
# check_thread_provenance derives the actual per-cell "must record" set from
# <results-root>/matrix.json's own `producer` field below, so this constant
# only has to name what that field's value looks like when it should record;
# it does not need to be kept in sync with which families exist.
_THREAD_RECORDING_PRODUCER = "bench_review_comparison"


def check_thread_provenance(root: Path, declared_threads: int | None) -> None:
    """Cross-check every `--threads` claim against what a producer actually
    recorded, for every `TABLE9_CELL_IDS` cell directory present under
    `root`.

    `--threads` is inert for `bench_review_comparison` (only
    `OMP_NUM_THREADS` applies at runtime) -- Task 1 established this is
    exactly how the old matrix could claim `threads: 2` while its own
    artifacts recorded `omp_threads=16`. So `run.json`'s declared
    `provenance.threads` is an intention, not a fact, unless it is checked
    against a producer's own record -- and a missing declaration is not an
    exemption from that either.

    A cell whose `<results-root>/matrix.json` entry names
    `_THREAD_RECORDING_PRODUCER` as its producer MUST have a direct-child
    file (non-recursive) that parses as CSV with an `omp_threads` column
    *and at least one data row under it* (in practice: that producer's
    comparison output, whether written to its `--output` CSV or only
    captured in `stdout.log`); a missing file, or a file with the column
    heading but zero rows (a truncated/killed-after-header producer, or a
    trimmed fixture) is a missing-evidence failure either way, named and
    distinguished from each other, not a silent pass -- the entire point of
    this check is to verify the claim against fact, not merely against
    whichever cells happen to volunteer a heading. Any row that is actually
    present, in a must-record cell or not, still gets checked: the thread
    count must equal `declared_threads` and `omp_dynamic` (if present) must
    be `'false'` (Q-1).
    """
    if declared_threads is None:
        raise SweepError("run.json has no provenance.threads -- every run this summarizer accepts "
                         "records one")
    matrix = json.loads((root / "matrix.json").read_text())
    producer_by_cell = {c["cell_id"]: c.get("producer") for c in matrix["cells"]}
    for cell_id in TABLE9_CELL_IDS:
        cell_dir = root / "cells" / slug(cell_id)
        if not cell_dir.is_dir():
            continue
        must_record = producer_by_cell.get(cell_id) == _THREAD_RECORDING_PRODUCER
        checked = 0            # rows actually compared against declared_threads
        header_only_file = None  # first file seen with the column but zero rows
        for path in sorted(cell_dir.iterdir()):
            if not path.is_file():
                continue
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            reader = csv.DictReader(text.splitlines())
            if not reader.fieldnames or "omp_threads" not in reader.fieldnames:
                continue
            rows_in_file = 0
            for row in reader:
                rows_in_file += 1
                checked += 1
                recorded = row.get("omp_threads")
                if recorded != str(declared_threads):
                    raise SweepError(f"{cell_dir}: {path.name} records omp_threads={recorded!r} for cell "
                                     f"{cell_id!r}, but run.json's provenance.threads is {declared_threads}")
                dynamic = row.get("omp_dynamic")
                if dynamic is not None and dynamic != "false":
                    raise SweepError(f"{cell_dir}: {path.name} records omp_dynamic={dynamic!r} for cell "
                                     f"{cell_id!r}, expected 'false'")
            if rows_in_file == 0 and header_only_file is None:
                header_only_file = path.name
        if must_record and checked == 0:
            if header_only_file is not None:
                raise SweepError(f"{cell_dir}: {header_only_file} carries the omp_threads column but has "
                                 f"no data rows -- the thread claim for cell {cell_id!r} "
                                 f"(producer {_THREAD_RECORDING_PRODUCER!r}) is unverified, not exempt")
            raise SweepError(f"{cell_dir}: cell {cell_id!r} (producer {_THREAD_RECORDING_PRODUCER!r}) "
                             f"records no omp_threads anywhere in its directory -- the thread claim for "
                             f"this cell is unverified, not exempt")


def _load_receipt(cell_dir: Path, expected_cell_id: str) -> dict:
    receipt_path = cell_dir / "receipt.json"
    if not receipt_path.is_file():
        raise SweepError(f"{cell_dir}: no receipt.json")
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("execution_status") != "COMPLETED":
        raise SweepError(f"{cell_dir}: receipt execution_status={receipt.get('execution_status')!r}, "
                         f"expected 'COMPLETED'")
    if receipt.get("cell_id") != expected_cell_id:
        raise SweepError(f"{cell_dir}: receipt cell_id {receipt.get('cell_id')!r} != {expected_cell_id!r}")
    return receipt


def _select_sidecar(cell_dir: Path, needle: str) -> Path:
    """Pick the one sidecar this cell's own directory holds for a family source.

    `scripts/run_table9_sweep.py`'s receipt schema (argv, canonical_argv,
    cell_id, duration_s, execution_status, exit_code, expected_rows, family,
    finished_at, producer, provenance_id, schema, started_at,
    stderr_sha256, stdout_sha256, timeout_class, timeout_seconds, version)
    carries no artifact inventory -- that field belongs to the full
    orchestrator's receipt schema (`run_revision_benchmarks.py`'s
    `file_inventory`), not the sweep runner's. So this is a plain,
    *non-recursive* scan of exactly `cell_dir` and its immediate `raw/`
    subdirectory: `bench_piccard`/`bench_fhe_ind` write their .tsv at
    either location depending on the run, while `bench_review_comparison`
    and `bench_onehot_sqrt` always write into `raw/`. Nothing deeper is
    ever walked, so a Task 2 archived `cells/<slug>.attempt-N/` sibling is
    never in scope (selection only ever reads inside the exact `cell_dir`
    passed in), and any path under an ".attempt-" segment is excluded
    defensively. One deterministic rule -- no inventory-first fallback.
    """
    search_dirs = [cell_dir] + ([cell_dir / "raw"] if (cell_dir / "raw").is_dir() else [])
    candidates = [p for d in search_dirs for p in d.glob("*.tsv") if ".attempt-" not in p.parts]
    matches = [p for p in candidates if needle in p.name]
    if len(matches) != 1:
        raise SweepError(f"{cell_dir}: expected exactly one sidecar containing {needle!r} under "
                         f"{cell_dir.name}/ or {cell_dir.name}/raw/, found {len(matches)}: "
                         f"{[p.name for p in matches]}"
                         + ("" if matches else f" (tsvs present: {[p.name for p in candidates]})"))
    return matches[0]


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


# Two-sided 95% Student-t critical value for N=30 (df=29), taken verbatim
# from the producer's own frozen table rather than recomputed here, so a
# different libm/statistics implementation could never silently diverge from
# the CI the producer itself built (benchmarks/raw_timing_schema.cpp:23-53,
# kStudentT95[29] == 2.045229642132703).
STUDENT_T95_N30 = 2.045229642132703

# Tolerance for cross-checking a recorded aggregate against the same value
# recomputed here from its own raw samples (see _parse_sidecar): tight
# enough to catch a tampered or corrupted field, loose enough to tolerate
# float round-trip noise from the producer's own text serialization.
_REL_TOL = 1e-9
_ABS_TOL = 1e-12


def _close(computed: float, recorded: float) -> bool:
    return abs(computed - recorded) <= max(_ABS_TOL, _REL_TOL * max(abs(computed), abs(recorded)))


def _parse_sidecar(path: Path, phase: str, expected_cell_id: str) -> Aggregate:
    """Parse one raw-timing sidecar and verify it, not just read it.

    The producer's own schema validates and recomputes each aggregate from
    its samples before ever writing them (benchmarks/raw_timing_schema.cpp);
    this reader is not allowed to be weaker than that writer, so it
    recomputes mean/sample-SD/median/95% half-width from the 30 parsed
    'measured' samples for `phase` and requires them to agree with the
    recorded aggregate within `_REL_TOL`/`_ABS_TOL` (K-2).
    """
    header: dict[str, str] = {}
    sample_columns: list[str] = []
    agg_columns: list[str] = []
    trial_indices: set[int] = set()
    raw_values: list[float] = []
    agg_rows_for_phase = 0
    agg: Aggregate | None = None
    for line in path.read_text().splitlines():
        f = line.split("\t")
        if len(f) == 2:
            header[f[0]] = f[1]
        elif f[0] == "sample" and len(f) > 1 and f[1] == "producer_id":
            sample_columns = f
        elif f[0] == "sample" and sample_columns and len(f) == len(sample_columns):
            row = dict(zip(sample_columns, f))
            if row["phase"] != phase or row["sample_kind"] != "measured":
                continue
            if (row["producer_id"], row["profile_id"], row["cell_id"]) != \
               (header.get("producer_id"), header.get("profile_id"), header.get("cell_id")):
                raise SweepError(f"{path}: sample metadata disagrees with the file header")
            idx = int(row["trial_index"])
            if idx in trial_indices:
                raise SweepError(f"{path}: duplicate measured trial_index {idx} for phase {phase}")
            trial_indices.add(idx)
            raw_values.append(float(row["raw_ms"]))
        elif f[0] == "aggregate" and len(f) > 1 and f[1] == "producer_id":
            agg_columns = f
        elif f[0] == "aggregate" and agg_columns and f[agg_columns.index("phase")] == phase:
            agg_rows_for_phase += 1
            row = dict(zip(agg_columns, f))
            low, high = float(row["ci95_low_ms"]), float(row["ci95_high_ms"])
            agg = Aggregate(float(row["mean_ms"]), float(row["sample_sd_ms"]), float(row["median_ms"]),
                            (high - low) / 2.0, int(row["measured_count"]), low, high)
    if header.get("schema_version") != "piccard-paper-raw-timing-v1" or header.get("profile_id") != "paper-v1":
        raise SweepError(f"{path}: not a paper-v1 raw-timing-v1 sidecar")
    if header.get("cell_id") != expected_cell_id:
        raise SweepError(f"{path}: sidecar cell_id {header.get('cell_id')!r} != {expected_cell_id!r}")
    if agg_rows_for_phase == 0:
        raise SweepError(f"{path}: no aggregate row for phase {phase}")
    if agg_rows_for_phase > 1:
        raise SweepError(f"{path}: {agg_rows_for_phase} aggregate rows for phase {phase}, expected exactly one")
    assert agg is not None
    n = len(raw_values)
    if header.get("expected_measured") != "30" or n != 30 or agg.measured_count != 30:
        raise SweepError(f"{path}: expected 30 measured samples; header={header.get('expected_measured')} "
                         f"samples={n} aggregate={agg.measured_count}")
    if trial_indices != set(range(30)):
        raise SweepError(f"{path}: measured trial indices for phase {phase} must be exactly 0..29, "
                         f"got {sorted(trial_indices)}")
    computed_mean = sum(raw_values) / n
    sorted_vals = sorted(raw_values)
    computed_median = ((sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0
                        if n % 2 == 0 else sorted_vals[n // 2])
    sum_sq = sum((v - computed_mean) ** 2 for v in raw_values)
    computed_sd = math.sqrt(sum_sq / (n - 1))
    computed_half = STUDENT_T95_N30 * computed_sd / math.sqrt(n)
    for label, computed, recorded in (("mean_ms", computed_mean, agg.mean_ms),
                                       ("sample_sd_ms", computed_sd, agg.sd_ms),
                                       ("median_ms", computed_median, agg.median_ms),
                                       ("ci95 half-width", computed_half, agg.ci95_half_ms)):
        if not _close(computed, recorded):
            raise SweepError(f"{path}: recorded {label}={recorded} for phase {phase} disagrees with the "
                             f"samples' own recomputed {label}={computed} (tolerance: {_REL_TOL:g} relative "
                             f"/ {_ABS_TOL:g} absolute)")
    return agg


def load_aggregates(root: Path) -> dict[tuple[str, str], Aggregate]:
    out: dict[tuple[str, str], Aggregate] = {}
    for cell_id in TABLE9_CELL_IDS:
        cell_dir = root / "cells" / slug(cell_id)
        if not cell_dir.is_dir():
            continue
        _load_receipt(cell_dir, cell_id)  # validates execution_status/cell_id; the sidecar itself is
        family = cell_id.split("::")[1]   # located by exact scan (_select_sidecar), not by receipt content
        for needle, phase, column, suffix in SOURCES[family]:
            path = _select_sidecar(cell_dir, needle)
            out[(cell_id, column)] = _parse_sidecar(path, phase, cell_id + suffix)
    # EXTRAPOLATED_SJ16 may only be used when there is genuinely nothing
    # else to use: if a real cell directory exists for either id it stands
    # in for, that is a drift between the constant and the matrix/sweep
    # that must be caught, not silently shadowed (Q-2).  This has to check
    # the results tree, not `out`: TABLE9_CELL_IDS deliberately excludes
    # both ids, so `out` can never contain them by construction, and a
    # guard that only looked there could never fire.  `cell_dir` here is
    # always the exact canonical `cells/<slug>/` path (never a glob over
    # `cells/`), so a `cells/<slug>.attempt-N/` sibling -- a failed
    # attempt, not a measurement -- is never mistaken for one.
    for u in EXTRAPOLATED_SJ16:
        natural_id = f"paper-v1::sj16::u={u}"
        natural_dir = root / "cells" / slug(natural_id)
        if natural_dir.is_dir():
            raise SweepError(f"{natural_dir}: a real cell directory exists for {natural_id!r}, which "
                             f"EXTRAPOLATED_SJ16 assumes was never measured -- update the constant (and "
                             f"cell_for) instead of silently using the stale value")
    return out


def _num(value: float, decimals: int) -> str:
    return f"{value:,.{decimals}f}".replace(",", "{,}")


def format_cell(agg: Aggregate | None) -> str:
    if agg is None:
        return "---"
    d = 0 if agg.mean_ms >= 10000 else 1
    if agg.measured_count == 0 or agg.ci95_half_ms != agg.ci95_half_ms:  # extrapolated: no interval
        # Synthetic (EXTRAPOLATED_SJ16): carries the paper's existing
        # double-dagger footnote for these two calibrated, never-executed
        # cells (Piccard_MR_R1.tex:2115, footnote text at :2141), so the
        # rendered LaTeX can never read as a measurement.
        return f"${_num(agg.mean_ms, d)}^{{\\ddagger\\ddagger}}$"
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
    recorded_matrix_sha = prov.get("matrix_sha256")
    try:
        archived_matrix_sha = _archived_matrix_sha256(root)
    except SweepError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if recorded_matrix_sha != archived_matrix_sha:
        print(f"matrix mismatch: run.json provenance.matrix_sha256={recorded_matrix_sha!r} but "
              f"{root}/matrix.json hashes to {archived_matrix_sha!r} -- the archive is inconsistent "
              f"with its own record (no override)", file=sys.stderr)
        return 1
    nonstandard = (manifest.get("state") != "COMPLETED" or manifest.get("dirty_allowed")
                   or manifest.get("mixed_provenance")
                   or prov.get("threads") != 16 or prov.get("seed") != 20260729
                   or any(c.get("execution_status") != "COMPLETED" for c in manifest.get("cells", [])))
    if nonstandard and not args.allow_nonstandard:
        print("refusing a nonstandard run (state, dirty tree, mixed provenance, threads, seed, "
              "or failed cells); pass --allow-nonstandard to override", file=sys.stderr)
        return 1
    missing_ids, unexpected_ids = _manifest_cell_gap(manifest)
    if (missing_ids or unexpected_ids) and not args.partial:
        print("manifest COMPLETED cell set does not match TABLE9_CELL_IDS -- missing: "
              + (", ".join(sorted(missing_ids)) or "(none)") + "; unexpected: "
              + (", ".join(sorted(unexpected_ids)) or "(none)"), file=sys.stderr)
        return 1
    try:
        check_thread_provenance(root, prov.get("threads"))
        aggs = load_aggregates(root)
        gaps = missing_cells(aggs)
        if gaps and not args.partial:
            print("missing cells: " + ", ".join(gaps), file=sys.stderr)
            return 1
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        write_csv(aggs, out / "table9.csv")
        (out / "table9_rows.tex").write_text(render_rows(aggs))
        (out / "flatness.md").write_text(flatness(aggs))
    except SweepError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"wrote {out}: {len(aggs)} aggregates, {len(gaps)} missing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
