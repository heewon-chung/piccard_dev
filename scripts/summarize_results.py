#!/usr/bin/env python3
"""
summarize_results.py — Parse benchmark CSVs and produce 26 comparison tables.

Usage:
    python3 scripts/summarize_results.py results/<dir>/csv
    python3 scripts/summarize_results.py results/<dir>/csv --latex
    python3 scripts/summarize_results.py results/<dir>/csv --save-dir results/<dir>/tables
"""

import argparse
import contextlib
import csv
import io
import math
import re
import sys
from collections import defaultdict
from pathlib import Path


def log2(x):
    return math.log2(x) if x > 0 else 0


# ── CSV readers ─────────────────────────────────────────────────────

def read_csv(path):
    """Read a CSV file, return list of dicts. Skip empty/missing files."""
    if not path.exists():
        return []
    with open(path) as f:
        lines = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Skip stderr lines that may be mixed in
            if line.startswith(("Benchmark", "===", "  ", "(No", "---")):
                continue
            lines.append(line)
        if not lines:
            return []
        reader = csv.DictReader(lines)
        return list(reader)


# ── Formatting helpers ──────────────────────────────────────────────

def fmt_ms(val):
    """Format milliseconds: show 1 decimal for >=1ms, 3 for sub-ms."""
    v = float(val)
    if v >= 1.0:
        return f"{v:.1f}"
    return f"{v:.3f}"


def fmt_bytes(val):
    v = int(val)
    if v == 0:
        return "-"
    if v >= 1024 * 1024:
        return f"{v / (1024*1024):.1f} MB"
    if v >= 1024:
        return f"{v / 1024:.1f} KB"
    return f"{v} B"


def fmt_err(val):
    v = float(val)
    if v == 0:
        return "0 (exact)"
    return f"{v:.4f}"


def fmt_rel_err(val):
    v = float(val)
    if v < 0:
        return "N/A"
    if v == 0:
        return "0 (exact)"
    return f"{v:.4f}"


# ── Dispersion helpers ───────────────────────────────────────────────

def _t_critical_95(df):
    """Two-sided 95% Student-t critical value; linear interpolation for df not in table."""
    _tbl = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
            6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
            15: 2.131, 20: 2.086, 30: 2.042, 60: 2.000, 120: 1.980}
    if df <= 0:
        return float("nan")
    dfs = sorted(_tbl.keys())
    if df >= dfs[-1]:
        return 1.960  # normal approximation
    for i, d in enumerate(dfs):
        if df <= d:
            if i == 0 or d == df:
                return _tbl[d]
            d_lo, d_hi = dfs[i - 1], d
            frac = (df - d_lo) / (d_hi - d_lo)
            return _tbl[d_lo] + frac * (_tbl[d_hi] - _tbl[d_lo])
    return 1.960


def fmt_disp(row, col, ci=False):
    """Format mean ± sd (or ± CI half-width under --ci).

    sd=-1 sentinel (n < 2) → bare mean.
    Missing _sd column → warn once to stderr and return bare mean.
    """
    sd_col = col + "_sd"
    if sd_col not in row:
        sys.stderr.write(f"WARNING: missing column {sd_col!r} — rendering dash\n")
        return "-"
    mean_val = float(row.get(col, "0"))
    sd_val = float(row.get(sd_col, "-1"))
    if sd_val < 0:  # n < 2 sentinel — dispersion undefined
        return fmt_ms(str(mean_val))
    if ci:
        n = int(row.get("trials", "0"))
        if n < 2:
            return "N/A"
        half = _t_critical_95(n - 1) * sd_val / (n ** 0.5)
        return f"{fmt_ms(str(mean_val))}±{fmt_ms(str(half))}"
    return f"{fmt_ms(str(mean_val))}±{fmt_ms(str(sd_val))}"


def get_trials(row):
    """Return trials count as string; '-' for unmeasured/skipped (0) or missing."""
    t = row.get("trials", None)
    if t is None:
        sys.stderr.write("WARNING: missing required column 'trials' — rendering dash\n")
        return "-"
    v = int(t)
    return "-" if v == 0 else str(v)


def print_table(headers, rows, col_widths=None):
    """Print a formatted ASCII table."""
    if col_widths is None:
        col_widths = []
        for i, h in enumerate(headers):
            w = len(h)
            for row in rows:
                if i < len(row):
                    w = max(w, len(str(row[i])))
            col_widths.append(w + 2)

    header_line = ""
    for h, w in zip(headers, col_widths):
        header_line += str(h).rjust(w)
    print(header_line)
    print("-" * sum(col_widths))

    for row in rows:
        line = ""
        for val, w in zip(row, col_widths):
            line += str(val).rjust(w)
        print(line)


def print_latex_table(caption, label, headers, rows):
    """Print a LaTeX tabular."""
    ncols = len(headers)
    col_spec = "r" * ncols
    print(f"\\begin{{table}}[t]")
    print(f"\\centering")
    print(f"\\caption{{{caption}}}")
    print(f"\\label{{{label}}}")
    print(f"\\begin{{tabular}}{{{col_spec}}}")
    print("\\toprule")
    print(" & ".join(str(h) for h in headers) + " \\\\")
    print("\\midrule")
    for row in rows:
        print(" & ".join(str(v) for v in row) + " \\\\")
    print("\\bottomrule")
    print(f"\\end{{tabular}}")
    print(f"\\end{{table}}")
    print()


# ── Filter helper ───────────────────────────────────────────────────

def filter_rows(data, key, prefix):
    """Filter rows where data[key] starts with prefix."""
    return [r for r in data if r.get(key, "").startswith(prefix)]


# ── T1–T3: Piccard Timing ──────────────────────────────────────────

def table_piccard_timing(data, scenario, tnum, title, latex=False, ci=False):
    """Piccard timing table filtered by scenario prefix (vary_k_, vary_m_, vary_size_)."""
    rows_data = filter_rows(data, "label", scenario)
    if not rows_data:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    headers = ["Label", "Tri", "k", "m", "n", "N", "MinHash", "Encode", "Encrypt",
               "Multiply", "RotSum", "Decrypt", "Total (ms)", "CT Size"]
    rows = []
    for r in rows_data:
        rows.append([
            r.get("label", ""),
            get_trials(r),
            r.get("k", ""),
            r.get("m", ""),
            r.get("set_size", ""),
            r.get("ring_dim", ""),
            fmt_disp(r, "phase_minhash_ms", ci=ci),
            fmt_disp(r, "phase_encode_ms", ci=ci),
            fmt_disp(r, "phase_encrypt_ms", ci=ci),
            fmt_disp(r, "phase_multiply_ms", ci=ci),
            fmt_disp(r, "phase_rotate_sum_ms", ci=ci),
            fmt_disp(r, "phase_decrypt_ms", ci=ci),
            fmt_disp(r, "time_ms", ci=ci),
            fmt_bytes(r.get("ct_size_bytes", "0")),
        ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$", "vary_size_": "$n$"}
        param_label = param_map.get(scenario, "Param")
        lh = [param_label, "$n$", "$N$", "MinHash", "Encode", "Encrypt",
              "Multiply", "RotSum", "Decrypt", "Total (ms)", "CT Size"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""),
                fmt_ms(r.get("phase_minhash_ms", "0")),
                fmt_ms(r.get("phase_encode_ms", "0")),
                fmt_ms(r.get("phase_encrypt_ms", "0")),
                fmt_ms(r.get("phase_multiply_ms", "0")),
                fmt_ms(r.get("phase_rotate_sum_ms", "0")),
                fmt_ms(r.get("phase_decrypt_ms", "0")),
                fmt_ms(r.get("time_ms", "0")),
                fmt_bytes(r.get("ct_size_bytes", "0")),
            ])
        tab_id = scenario.rstrip("_").replace("_", "-")
        print_latex_table(title, f"tab:piccard-timing-{tab_id}", lh, lr)


# ── T4–T6: Piccard Accuracy ────────────────────────────────────────

def table_accuracy_stats(data, param_prefix, param_name, tnum, title, latex=False):
    """Generic accuracy table: group by parameter, compute error statistics.

    Works for piccard accuracy (accuracy_k, accuracy_m, accuracy_size)
    and dynamic accuracy (same label patterns).
    """
    filtered = [r for r in data if r.get("label", "").startswith(param_prefix)]
    if not filtered:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    # Group by parameter value from labels like "accuracy_k64_0.5_t0" → "64"
    groups = defaultdict(list)
    prefix_len = len(param_prefix)
    for r in filtered:
        label = r.get("label", "")
        rest = label[prefix_len:]
        param_val = rest.split("_")[0]
        groups[param_val].append(r)

    if not groups:
        return

    show_theoretical = (param_prefix == "accuracy_k")
    headers = [param_name, "Trials", "Mean |err|", "Max |err|", "RMSE",
               "Std Dev", "1/sqrt(k)" if show_theoretical else "Mean Rel Err"]

    rows = []
    for pval in sorted(groups.keys(), key=lambda s: float(s)):
        trials = groups[pval]
        errors = [abs(float(r.get("jaccard_error", "0"))) for r in trials]
        n = len(errors)
        mean_err = sum(errors) / n
        max_err = max(errors)
        rmse = (sum(e ** 2 for e in errors) / n) ** 0.5
        std_dev = (sum((e - mean_err) ** 2 for e in errors) / n) ** 0.5

        if show_theoretical:
            k_val = int(float(pval))
            last_col = f"{1.0 / (k_val ** 0.5):.4f}"
        else:
            rel_errs = [float(r.get("jaccard_rel_error", "-1")) for r in trials]
            valid_rel = [e for e in rel_errs if e >= 0]
            last_col = f"{sum(valid_rel) / len(valid_rel):.4f}" if valid_rel else "N/A"

        rows.append([
            pval, str(n),
            f"{mean_err:.4f}", f"{max_err:.4f}",
            f"{rmse:.4f}", f"{std_dev:.4f}",
            last_col,
        ])

    print_table(headers, rows)

    if latex:
        print()
        pn = f"${param_name}$" if len(param_name) <= 2 else param_name
        lh = [pn, "Trials", "Mean $|\\epsilon|$", "Max $|\\epsilon|$",
              "RMSE", "Std Dev",
              "$1/\\sqrt{k}$" if show_theoretical else "Mean Rel Err"]
        tab_id = param_prefix.replace("accuracy_", "")
        print_latex_table(title, f"tab:accuracy-{tab_id}", lh, rows)


# ── T7–T9: Piccard Combined ────────────────────────────────────────

def table_piccard_combined(data, scenario, tnum, title, latex=False, ci=False):
    """Piccard combined timing + accuracy table."""
    rows_data = filter_rows(data, "label", scenario)
    if not rows_data:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    headers = ["Label", "Tri", "k", "m", "n", "N", "Time (ms)",
               "Median Err", "P25", "P75", "P95", "Max Err"]
    rows = []
    for r in rows_data:
        rows.append([
            r.get("label", ""),
            get_trials(r),
            r.get("k", ""),
            r.get("m", ""),
            r.get("set_size", ""),
            r.get("ring_dim", ""),
            fmt_disp(r, "time_ms", ci=ci),
            fmt_err(r.get("accuracy_median", "0")),
            fmt_err(r.get("accuracy_p25", "0")),
            fmt_err(r.get("accuracy_p75", "0")),
            fmt_err(r.get("accuracy_p95", "0")),
            fmt_err(r.get("accuracy_max", "0")),
        ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$", "vary_size_": "$n$"}
        param_label = param_map.get(scenario, "Param")
        lh = [param_label, "$n$", "$N$", "Time (ms)",
              "Median Err", "P25", "P75", "P95", "Max Err"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""),
                fmt_ms(r.get("time_ms", "0")),
                fmt_err(r.get("accuracy_median", "0")),
                fmt_err(r.get("accuracy_p25", "0")),
                fmt_err(r.get("accuracy_p75", "0")),
                fmt_err(r.get("accuracy_p95", "0")),
                fmt_err(r.get("accuracy_max", "0")),
            ])
        tab_id = scenario.rstrip("_").replace("_", "-")
        print_latex_table(title, f"tab:combined-{tab_id}", lh, lr)


# ── T10–T13: Comparison Timing ─────────────────────────────────────

def table_comparison_timing(data, scenario, tnum, title, latex=False, ci=False):
    """Comparison timing: Piccard vs Baseline side by side."""
    rows_data = filter_rows(data, "scenario", scenario)
    if not rows_data:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    # Group by scenario value, then by method
    groups = {}
    order = []
    for r in rows_data:
        scen = r.get("scenario", "")
        if scen not in groups:
            groups[scen] = {}
            order.append(scen)
        method = r.get("method", "")
        groups[scen][method] = r

    headers = ["Scenario", "Tri", "k", "m", "n", "|U|", "N_p", "N_b",
               "Piccard (ms)", "Baseline (ms)", "Speedup",
               "Piccard CT", "Baseline CT", "Comm P", "Comm B"]
    rows = []
    for scen in order:
        methods = groups[scen]
        p = methods.get("piccard", {})
        b = methods.get("baseline", {})

        p_time = float(p.get("total_ms", "0"))
        b_time = float(b.get("total_ms", "0"))
        speedup = f"{b_time / p_time:.1f}x" if p_time > 0 else "-"

        rows.append([
            scen,
            get_trials(p) if p else get_trials(b),
            p.get("k", b.get("k", "")),
            p.get("m", b.get("m", "")),
            p.get("set_size", b.get("set_size", "")),
            p.get("universe_size", b.get("universe_size", "")),
            p.get("ring_dim", ""),
            b.get("ring_dim", ""),
            fmt_disp(p, "total_ms", ci=ci) if p else "-",
            fmt_disp(b, "total_ms", ci=ci) if b else "-",
            speedup,
            fmt_bytes(p.get("ct_size_bytes", "0")),
            fmt_bytes(b.get("ct_size_bytes", "0")),
            fmt_bytes(p.get("comm_bytes", "0")),
            fmt_bytes(b.get("comm_bytes", "0")),
        ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$",
                     "vary_size_": "$n$", "vary_universe_": "$|U|$"}
        param_label = param_map.get(scenario, "Param")
        lh = [param_label, "$N_P$", "$N_B$",
              "Piccard (ms)", "Baseline (ms)", "Speedup", "Comm P", "Comm B"]
        lr = []
        for scen in order:
            methods = groups[scen]
            p = methods.get("piccard", {})
            b = methods.get("baseline", {})
            pval = scen.split("_")[-1]
            if scenario in ("vary_size_", "vary_universe_"):
                pval = f"{int(pval):,}"
            p_time = float(p.get("total_ms", "0"))
            b_time = float(b.get("total_ms", "0"))
            speedup = f"{b_time / p_time:.1f}$\\times$" if p_time > 0 else "-"
            lr.append([
                pval, p.get("ring_dim", ""), b.get("ring_dim", ""),
                fmt_ms(p.get("total_ms", "0")), fmt_ms(b.get("total_ms", "0")),
                speedup, fmt_bytes(p.get("comm_bytes", "0")),
                fmt_bytes(b.get("comm_bytes", "0")),
            ])
        tab_id = scenario.rstrip("_").replace("_", "-")
        print_latex_table(title, f"tab:comparison-{tab_id}", lh, lr)


# ── T14: Communication Cost ────────────────────────────────────────

def table_communication_cost(data, tnum, latex=False):
    """Communication cost comparison across all scenarios."""
    if not data:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: Communication Cost — Piccard vs Baseline")
    print(f"{'=' * 70}")

    # Group by scenario, then method
    groups = {}
    order = []
    for r in data:
        scen = r.get("scenario", "")
        if scen not in groups:
            groups[scen] = {}
            order.append(scen)
        method = r.get("method", "")
        groups[scen][method] = r

    headers = ["Scenario", "k", "|U|", "n",
               "Piccard CTs", "Piccard Comm",
               "Baseline CTs", "Baseline Comm", "Ratio"]
    rows = []
    for scen in order:
        methods = groups[scen]
        p = methods.get("piccard", {})
        b = methods.get("baseline", {})

        p_comm = int(p.get("comm_bytes", "0"))
        b_comm = int(b.get("comm_bytes", "0"))
        ratio = f"{b_comm / p_comm:.1f}x" if p_comm > 0 else "-"

        rows.append([
            scen,
            p.get("k", ""),
            p.get("universe_size", ""),
            p.get("set_size", ""),
            p.get("num_cts", ""),
            fmt_bytes(p_comm),
            b.get("num_cts", ""),
            fmt_bytes(b_comm),
            ratio,
        ])

    print_table(headers, rows)

    if latex:
        print()
        lh = ["Scenario", "$k$", "$|U|$", "$n$",
              "P CTs", "P Comm", "B CTs", "B Comm", "Ratio"]
        print_latex_table("Communication cost: Piccard vs.\\ baseline.",
                          "tab:communication-cost", lh, rows)


# ── T15–T17: Dynamic Timing ────────────────────────────────────────

def table_dynamic_timing(data, scenario, tnum, title, latex=False, ci=False):
    """Dynamic benchmark timing table."""
    rows_data = filter_rows(data, "label", scenario)
    if not rows_data:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    headers = ["Label", "Tri", "k", "m", "n", "N", "Depth",
               "Init", "Insert", "Delete", "Compute", "Decrypt",
               "Total (ms)", "CT Size", "Ins/s", "Del/s"]
    rows = []
    for r in rows_data:
        rows.append([
            r.get("label", ""),
            get_trials(r),
            r.get("k", ""),
            r.get("m", ""),
            r.get("set_size", ""),
            r.get("ring_dim", ""),
            r.get("depth", ""),
            fmt_disp(r, "phase_init_ms", ci=ci),
            fmt_disp(r, "phase_insert_ms", ci=ci),
            fmt_disp(r, "phase_delete_ms", ci=ci),
            fmt_disp(r, "phase_compute_ms", ci=ci),
            fmt_disp(r, "phase_decrypt_ms", ci=ci),
            fmt_disp(r, "total_ms", ci=ci),
            fmt_bytes(r.get("ct_size_bytes", "0")),
            r.get("ops_insert_per_sec", ""),
            r.get("ops_delete_per_sec", ""),
        ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$", "vary_size_": "$n$"}
        param_label = param_map.get(scenario, "Param")
        lh = [param_label, "$n$", "$N$", "Depth",
              "Init", "Insert", "Delete", "Compute", "Decrypt",
              "Total (ms)", "CT Size"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""), r.get("depth", ""),
                fmt_ms(r.get("phase_init_ms", "0")),
                fmt_ms(r.get("phase_insert_ms", "0")),
                fmt_ms(r.get("phase_delete_ms", "0")),
                fmt_ms(r.get("phase_compute_ms", "0")),
                fmt_ms(r.get("phase_decrypt_ms", "0")),
                fmt_ms(r.get("total_ms", "0")),
                fmt_bytes(r.get("ct_size_bytes", "0")),
            ])
        tab_id = scenario.rstrip("_").replace("_", "-")
        print_latex_table(title, f"tab:dynamic-{tab_id}", lh, lr)


# ── T18–T20: Dynamic Accuracy ──────────────────────────────────────
# Reuses table_accuracy_stats with dynamic_accuracy data and
# label prefixes: "accuracy_k", "accuracy_m", "accuracy_size"


# ── T21–T23: Threshold Timing ──────────────────────────────────────

def table_threshold_timing(data, scenario, tnum, title, latex=False, ci=False):
    """Threshold benchmark timing table."""
    rows_data = filter_rows(data, "label", scenario)
    if not rows_data:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    headers = ["Label", "Tri", "k", "m", "n", "N", "tau", "Depth",
               "MinHash", "Encode", "Encrypt", "Multiply",
               "RotSum", "Mask", "PolyEval", "Decrypt",
               "Total (ms)", "CT Size"]
    rows = []
    for r in rows_data:
        rows.append([
            r.get("label", ""),
            get_trials(r),
            r.get("k", ""),
            r.get("m", ""),
            r.get("set_size", ""),
            r.get("ring_dim", ""),
            r.get("tau", ""),
            r.get("mult_depth", ""),
            fmt_disp(r, "phase_minhash_ms", ci=ci),
            fmt_disp(r, "phase_encode_ms", ci=ci),
            fmt_disp(r, "phase_encrypt_ms", ci=ci),
            fmt_disp(r, "phase_multiply_ms", ci=ci),
            fmt_disp(r, "phase_rotate_sum_ms", ci=ci),
            fmt_disp(r, "phase_mask_ms", ci=ci),
            fmt_disp(r, "phase_poly_eval_ms", ci=ci),
            fmt_disp(r, "phase_decrypt_ms", ci=ci),
            fmt_disp(r, "total_ms", ci=ci),
            fmt_bytes(r.get("ct_size_bytes", "0")),
        ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$", "vary_size_": "$n$"}
        param_label = param_map.get(scenario, "Param")
        lh = [param_label, "$n$", "$N$", "$\\tau$", "Depth",
              "MinHash", "Encode", "Encrypt", "Multiply",
              "RotSum", "Mask", "PolyEval", "Decrypt",
              "Total (ms)", "CT Size"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""),
                r.get("tau", ""), r.get("mult_depth", ""),
                fmt_ms(r.get("phase_minhash_ms", "0")),
                fmt_ms(r.get("phase_encode_ms", "0")),
                fmt_ms(r.get("phase_encrypt_ms", "0")),
                fmt_ms(r.get("phase_multiply_ms", "0")),
                fmt_ms(r.get("phase_rotate_sum_ms", "0")),
                fmt_ms(r.get("phase_mask_ms", "0")),
                fmt_ms(r.get("phase_poly_eval_ms", "0")),
                fmt_ms(r.get("phase_decrypt_ms", "0")),
                fmt_ms(r.get("total_ms", "0")),
                fmt_bytes(r.get("ct_size_bytes", "0")),
            ])
        tab_id = scenario.rstrip("_").replace("_", "-")
        print_latex_table(title, f"tab:threshold-{tab_id}", lh, lr)


# ── T24–T26: Threshold Accuracy ────────────────────────────────────

def table_threshold_accuracy(data, param_prefix, param_name, tnum, title, latex=False):
    """Threshold accuracy: group by parameter, show threshold correctness + Jaccard error."""
    filtered = [r for r in data if r.get("label", "").startswith(param_prefix)]
    if not filtered:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    # Group by parameter value
    groups = defaultdict(list)
    prefix_len = len(param_prefix)
    for r in filtered:
        label = r.get("label", "")
        rest = label[prefix_len:]
        param_val = rest.split("_")[0]
        groups[param_val].append(r)

    if not groups:
        return

    headers = [param_name, "Trials", "Thresh Acc",
               "Mean |J err|", "Max |J err|", "RMSE J",
               "Mean Rel Err"]
    rows = []
    for pval in sorted(groups.keys(), key=lambda s: float(s)):
        trials = groups[pval]
        n = len(trials)

        # Threshold correctness
        correct = sum(1 for r in trials if r.get("threshold_correct", "0") == "1")
        thresh_acc = f"{correct / n:.3f}" if n > 0 else "N/A"

        # Jaccard error stats
        errors = [abs(float(r.get("jaccard_error", "0"))) for r in trials]
        mean_err = sum(errors) / n
        max_err = max(errors)
        rmse = (sum(e ** 2 for e in errors) / n) ** 0.5

        rel_errs = [float(r.get("jaccard_rel_error", "-1")) for r in trials]
        valid_rel = [e for e in rel_errs if e >= 0]
        mean_rel = f"{sum(valid_rel) / len(valid_rel):.4f}" if valid_rel else "N/A"

        rows.append([
            pval, str(n), thresh_acc,
            f"{mean_err:.4f}", f"{max_err:.4f}",
            f"{rmse:.4f}", mean_rel,
        ])

    print_table(headers, rows)

    if latex:
        print()
        pn = f"${param_name}$" if len(param_name) <= 2 else param_name
        tab_id = param_prefix.replace("accuracy_", "")
        lh = [pn, "Trials", "Thresh Acc",
              "Mean $|\\epsilon_J|$", "Max $|\\epsilon_J|$", "RMSE",
              "Mean Rel Err"]
        print_latex_table(title, f"tab:threshold-accuracy-{tab_id}", lh, rows)


# ── Save helper ──────────────────────────────────────────────────────

def run_and_save(func, save_path, *args, **kwargs):
    """Run a table function. Print to stdout and save to file if path given."""
    if save_path is None:
        func(*args, **kwargs)
        return
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        func(*args, **kwargs)
    output = buf.getvalue()
    print(output, end="")
    if output.strip():
        with open(save_path, "w") as f:
            f.write(output)


# ── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Summarize Piccard benchmark results (26 tables).")
    parser.add_argument("results_dir",
                        help="Path to CSV results directory")
    parser.add_argument("--latex", action="store_true",
                        help="Also emit LaTeX table fragments")
    parser.add_argument("--save-dir",
                        help="Save each table as a separate .txt file")
    parser.add_argument("--ci", action="store_true",
                        help="Render 95%% two-sided Student-t confidence intervals "
                             "instead of raw standard deviation (n≥2 required)")
    args = parser.parse_args()

    d = Path(args.results_dir)
    if not d.is_dir():
        print(f"Error: {d} is not a directory", file=sys.stderr)
        sys.exit(1)

    sd = Path(args.save_dir) if args.save_dir else None
    if sd:
        sd.mkdir(parents=True, exist_ok=True)

    # Print system info if available (check both parent dir and current dir)
    for candidate in [d.parent / "system_info.txt", d / "system_info.txt"]:
        if candidate.exists():
            print("=" * 70)
            print("  System Information")
            print("=" * 70)
            print(candidate.read_text())
            break

    # Detect security levels from CSV filenames (security-only, no k-suffix)
    configs = []
    seen = set()
    for f in sorted(d.glob("piccard_timing_*.csv")):
        stem = f.stem
        rest = stem.replace("piccard_timing_", "")
        m = re.match(r"(STD\d+|TOY)$", rest)
        if m:
            sec = m.group(1)
            if sec not in seen:
                seen.add(sec)
                configs.append(sec)

    if not configs:
        # Fall back: no suffix
        configs = [None]

    for sec in configs:
        suffix = f"_{sec}" if sec else ""

        if sec:
            print(f"\n{'=' * 70}")
            print(f"  Security Level: {sec}")
            print(f"{'=' * 70}")

        # ── Read all CSVs ─────────────────────────────────────────
        piccard_timing = read_csv(d / f"piccard_timing{suffix}.csv")
        piccard_accuracy = read_csv(d / f"piccard_accuracy{suffix}.csv")
        piccard_combined = read_csv(d / f"piccard_combined{suffix}.csv")
        comparison_timing = read_csv(d / f"comparison_timing{suffix}.csv")
        dynamic_timing = read_csv(d / f"dynamic_timing{suffix}.csv")
        dynamic_accuracy = read_csv(d / f"dynamic_accuracy{suffix}.csv")
        threshold_timing = read_csv(d / f"threshold_timing{suffix}.csv")
        threshold_accuracy = read_csv(d / f"threshold_accuracy{suffix}.csv")

        fs = suffix  # file suffix for saved tables
        lx = args.latex
        ci = args.ci

        def sp(name):
            """Build save path or None."""
            return sd / f"{name}{fs}.txt" if sd else None

        # ── T1–T3: Piccard Timing ─────────────────────────────────
        run_and_save(table_piccard_timing, sp("T01_piccard_timing_vary_k"),
                     piccard_timing, "vary_k_", 1,
                     "Piccard Timing — Varying k", latex=lx, ci=ci)
        run_and_save(table_piccard_timing, sp("T02_piccard_timing_vary_m"),
                     piccard_timing, "vary_m_", 2,
                     "Piccard Timing — Varying m", latex=lx, ci=ci)
        run_and_save(table_piccard_timing, sp("T03_piccard_timing_vary_n"),
                     piccard_timing, "vary_size_", 3,
                     "Piccard Timing — Varying n", latex=lx, ci=ci)

        # ── T4–T6: Piccard Accuracy ───────────────────────────────
        run_and_save(table_accuracy_stats, sp("T04_piccard_accuracy_vary_k"),
                     piccard_accuracy, "accuracy_k", "k", 4,
                     "Piccard Accuracy — Varying k", latex=lx)
        run_and_save(table_accuracy_stats, sp("T05_piccard_accuracy_vary_m"),
                     piccard_accuracy, "accuracy_m", "m", 5,
                     "Piccard Accuracy — Varying m", latex=lx)
        run_and_save(table_accuracy_stats, sp("T06_piccard_accuracy_vary_n"),
                     piccard_accuracy, "accuracy_size", "n", 6,
                     "Piccard Accuracy — Varying n", latex=lx)

        # ── T7–T9: Piccard Combined ───────────────────────────────
        run_and_save(table_piccard_combined, sp("T07_piccard_combined_vary_k"),
                     piccard_combined, "vary_k_", 7,
                     "Piccard Combined — Varying k", latex=lx, ci=ci)
        run_and_save(table_piccard_combined, sp("T08_piccard_combined_vary_m"),
                     piccard_combined, "vary_m_", 8,
                     "Piccard Combined — Varying m", latex=lx, ci=ci)
        run_and_save(table_piccard_combined, sp("T09_piccard_combined_vary_n"),
                     piccard_combined, "vary_size_", 9,
                     "Piccard Combined — Varying n", latex=lx, ci=ci)

        # ── T10–T13: Comparison Timing ────────────────────────────
        run_and_save(table_comparison_timing, sp("T10_comparison_vary_k"),
                     comparison_timing, "vary_k_", 10,
                     "Comparison — Varying k", latex=lx, ci=ci)
        run_and_save(table_comparison_timing, sp("T11_comparison_vary_m"),
                     comparison_timing, "vary_m_", 11,
                     "Comparison — Varying m", latex=lx, ci=ci)
        run_and_save(table_comparison_timing, sp("T12_comparison_vary_n"),
                     comparison_timing, "vary_size_", 12,
                     "Comparison — Varying n", latex=lx, ci=ci)
        run_and_save(table_comparison_timing, sp("T13_comparison_vary_universe"),
                     comparison_timing, "vary_universe_", 13,
                     "Comparison — Varying |U|", latex=lx, ci=ci)

        # ── T14: Communication Cost ───────────────────────────────
        run_and_save(table_communication_cost, sp("T14_communication_cost"),
                     comparison_timing, 14, latex=lx)

        # ── T15–T17: Dynamic Timing ───────────────────────────────
        run_and_save(table_dynamic_timing, sp("T15_dynamic_timing_vary_k"),
                     dynamic_timing, "vary_k_", 15,
                     "Dynamic Timing — Varying k", latex=lx, ci=ci)
        run_and_save(table_dynamic_timing, sp("T16_dynamic_timing_vary_m"),
                     dynamic_timing, "vary_m_", 16,
                     "Dynamic Timing — Varying m", latex=lx, ci=ci)
        run_and_save(table_dynamic_timing, sp("T17_dynamic_timing_vary_n"),
                     dynamic_timing, "vary_size_", 17,
                     "Dynamic Timing — Varying n", latex=lx, ci=ci)

        # ── T18–T20: Dynamic Accuracy ─────────────────────────────
        run_and_save(table_accuracy_stats, sp("T18_dynamic_accuracy_vary_k"),
                     dynamic_accuracy, "accuracy_k", "k", 18,
                     "Dynamic Accuracy — Varying k", latex=lx)
        run_and_save(table_accuracy_stats, sp("T19_dynamic_accuracy_vary_m"),
                     dynamic_accuracy, "accuracy_m", "m", 19,
                     "Dynamic Accuracy — Varying m", latex=lx)
        run_and_save(table_accuracy_stats, sp("T20_dynamic_accuracy_vary_n"),
                     dynamic_accuracy, "accuracy_size", "n", 20,
                     "Dynamic Accuracy — Varying n", latex=lx)

        # ── T21–T23: Threshold Timing ─────────────────────────────
        run_and_save(table_threshold_timing, sp("T21_threshold_timing_vary_k"),
                     threshold_timing, "vary_k_", 21,
                     "Threshold Timing — Varying k", latex=lx, ci=ci)
        run_and_save(table_threshold_timing, sp("T22_threshold_timing_vary_m"),
                     threshold_timing, "vary_m_", 22,
                     "Threshold Timing — Varying m", latex=lx, ci=ci)
        run_and_save(table_threshold_timing, sp("T23_threshold_timing_vary_n"),
                     threshold_timing, "vary_size_", 23,
                     "Threshold Timing — Varying n", latex=lx, ci=ci)

        # ── T24–T26: Threshold Accuracy ───────────────────────────
        run_and_save(table_threshold_accuracy, sp("T24_threshold_accuracy_vary_k"),
                     threshold_accuracy, "accuracy_k", "k", 24,
                     "Threshold Accuracy — Varying k", latex=lx)
        run_and_save(table_threshold_accuracy, sp("T25_threshold_accuracy_vary_m"),
                     threshold_accuracy, "accuracy_m", "m", 25,
                     "Threshold Accuracy — Varying m", latex=lx)
        run_and_save(table_threshold_accuracy, sp("T26_threshold_accuracy_vary_n"),
                     threshold_accuracy, "accuracy_size", "n", 26,
                     "Threshold Accuracy — Varying n", latex=lx)

    if sd:
        saved = [f.name for f in sorted(sd.glob("T*.txt"))]
        if saved:
            print(f"\n  Saved {len(saved)} table files to {sd}/")
            for name in saved:
                print(f"    {name}")

    print()


if __name__ == "__main__":
    main()
