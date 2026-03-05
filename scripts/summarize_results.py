#!/usr/bin/env python3
"""
summarize_results.py — Parse benchmark CSVs and produce comparison tables.

Usage:
    python3 scripts/summarize_results.py results/2026-02-27_100243_quick
    python3 scripts/summarize_results.py results/2026-02-27_100243_quick --latex
"""

import argparse
import contextlib
import csv
import io
import math
import os
import sys
from pathlib import Path


def log2(x):
    return math.log2(x) if x > 0 else 0


# ── CSV readers ─────────────────────────────────────────────────────

def read_csv(path):
    """Read a CSV file, return list of dicts. Skip empty files."""
    if not path.exists():
        return []
    with open(path) as f:
        # The CSV mixes stdout (CSV data) and stderr (progress) in the
        # same file because the benchmark script captures both.  Filter
        # to only lines that look like CSV rows (contain commas and
        # don't start with common stderr prefixes).
        lines = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Skip stderr lines
            if line.startswith(("Benchmark", "===", "  ", "(No", "---")):
                continue
            lines.append(line)
        if not lines:
            return []
        reader = csv.DictReader(lines)
        return list(reader)


# ── Formatting helpers ──────────────────────────────────────────────

def fmt_ms(val):
    """Format milliseconds: show 1 decimal for >1ms, 3 for sub-ms."""
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


def print_table(headers, rows, col_widths=None):
    """Print a formatted ASCII table."""
    if col_widths is None:
        col_widths = []
        for i, h in enumerate(headers):
            w = len(h)
            for row in rows:
                w = max(w, len(str(row[i])))
            col_widths.append(w + 2)

    # Header
    header_line = ""
    for h, w in zip(headers, col_widths):
        header_line += str(h).rjust(w)
    print(header_line)
    print("-" * sum(col_widths))

    # Rows
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


# ── Table 1: Piccard parameter sensitivity ──────────────────────────

def table_piccard_timing(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 1: Piccard Timing — Parameter Sensitivity")
    print("=" * 70)

    headers = ["Label", "k", "m", "N", "MinHash", "Encode", "Encrypt",
               "Multiply", "RotSum", "Decrypt", "Total (ms)", "CT Size"]
    rows = []
    for r in data:
        label = r.get("label", "")
        # Only timing rows (vary_k, vary_m, vary_size)
        if not any(label.startswith(p) for p in ("vary_k", "vary_m", "vary_size")):
            continue
        rows.append([
            label,
            r["k"],
            r["m"],
            r["ring_dim"],
            fmt_ms(r["phase_minhash_ms"]),
            fmt_ms(r["phase_encode_ms"]),
            fmt_ms(r["phase_encrypt_ms"]),
            fmt_ms(r["phase_multiply_ms"]),
            fmt_ms(r["phase_rotate_sum_ms"]),
            fmt_ms(r["phase_decrypt_ms"]),
            fmt_ms(r["time_ms"]),
            fmt_bytes(r["ct_size_bytes"]),
        ])

    if not rows:
        print("  (no timing data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        # Match paper Table 4 format: n, k, m, N, MinHash, Encrypt, Compute, Decrypt, Total
        latex_headers = ["$n$", "$k$", "$m$", "$N$",
                         "MinHash", "Encrypt", "Compute", "Decrypt",
                         "Total (ms)"]
        latex_rows = []
        for r in data:
            label = r.get("label", "")
            if not any(label.startswith(p) for p in ("vary_k", "vary_m", "vary_size")):
                continue
            # Extract set size from label (vary_size_1000 -> 1000)
            n_str = "-"
            if label.startswith("vary_size_"):
                n_str = f"{int(label.split('_')[-1]):,}"
            else:
                # For vary_k/vary_m, set_size comes from config default (500)
                n_str = "500"
            minhash = float(r["phase_minhash_ms"]) + float(r["phase_encode_ms"])
            compute = float(r["phase_multiply_ms"]) + float(r["phase_rotate_sum_ms"])
            decrypt = float(r["phase_decrypt_ms"]) + float(r["phase_bias_correction_ms"])
            latex_rows.append([
                n_str, r["k"], r["m"], r["ring_dim"],
                fmt_ms(str(minhash)),
                fmt_ms(r["phase_encrypt_ms"]),
                fmt_ms(str(compute)),
                fmt_ms(str(decrypt)),
                fmt_ms(r["time_ms"]),
            ])
        print_latex_table(
            "Running time of Piccard with varying parameters, where $n$ denotes the set size, "
            "$k$ the number of hash functions, $m$ the hash range, and $N$ the ring dimension.",
            "tab:piccard-params", latex_headers, latex_rows)


# ── Table 2: Piccard vs Baseline — vary universe ────────────────────

def table_comparison_universe(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 2: Piccard vs Baseline — Varying Universe Size")
    print("=" * 70)

    # Group by scenario
    scenarios = {}
    for r in data:
        scen = r.get("scenario", "")
        if not scen.startswith("vary_universe"):
            continue
        scenarios.setdefault(scen, {})[r["method"]] = r

    headers = ["U_set", "Method", "N", "#CTs", "Encode", "Encrypt",
               "Compute", "Decrypt", "Total (ms)", "CT Size", "Error", "Speedup"]
    rows = []
    for scen in sorted(scenarios.keys(), key=lambda s: int(s.split("_")[-1])):
        pair = scenarios[scen]
        p = pair.get("piccard")
        b = pair.get("baseline")
        if not p or not b:
            continue
        u = p["universe_size"]
        p_total = float(p["total_ms"])
        b_total = float(b["total_ms"])
        speedup = b_total / p_total if p_total > 0 else 0

        rows.append([
            u, "Piccard", p["ring_dim"], p["num_cts"],
            fmt_ms(p["phase_encode_ms"]), fmt_ms(p["phase_encrypt_ms"]),
            fmt_ms(p["phase_compute_ms"]), fmt_ms(p["phase_decrypt_ms"]),
            fmt_ms(p["total_ms"]), fmt_bytes(p["ct_size_bytes"]),
            fmt_err(p["jaccard_error"]), "",
        ])
        rows.append([
            "", "Baseline", b["ring_dim"], b["num_cts"],
            fmt_ms(b["phase_encode_ms"]), fmt_ms(b["phase_encrypt_ms"]),
            fmt_ms(b["phase_compute_ms"]), fmt_ms(b["phase_decrypt_ms"]),
            fmt_ms(b["total_ms"]), fmt_bytes(b["ct_size_bytes"]),
            fmt_err(b["jaccard_error"]), f"{speedup:.1f}x",
        ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        # Full per-phase breakdown (Table 4-style)
        lh = ["$|\\mathcal{U}|$", "Method", "$N$", "\\#CTs",
              "Encode", "Encrypt", "Compute", "Decrypt",
              "Total (ms)", "CT Size", "Speedup"]
        lr = []
        for scen in sorted(scenarios.keys(), key=lambda s: int(s.split("_")[-1])):
            pair = scenarios[scen]
            p, b = pair.get("piccard"), pair.get("baseline")
            if not p or not b:
                continue
            p_total = float(p["total_ms"])
            b_total = float(b["total_ms"])
            speedup = b_total / p_total if p_total > 0 else 0
            u = int(p["universe_size"])
            u_str = f"$2^{{{int(round(log2(u)))}}}$" if u > 0 and (u & (u-1)) == 0 else f"{u:,}"
            ct_ratio = f"{float(b['ct_size_bytes'])/float(p['ct_size_bytes']):.1f}$\\times$" if float(p['ct_size_bytes']) > 0 else "-"
            lr.append([u_str, "Piccard", p["ring_dim"], p["num_cts"],
                        fmt_ms(p["phase_encode_ms"]),
                        fmt_ms(p["phase_encrypt_ms"]),
                        fmt_ms(p["phase_compute_ms"]),
                        fmt_ms(p["phase_decrypt_ms"]),
                        fmt_ms(p["total_ms"]),
                        fmt_bytes(p["ct_size_bytes"]), ""])
            lr.append(["", "Baseline", b["ring_dim"], b["num_cts"],
                        fmt_ms(b["phase_encode_ms"]),
                        fmt_ms(b["phase_encrypt_ms"]),
                        fmt_ms(b["phase_compute_ms"]),
                        fmt_ms(b["phase_decrypt_ms"]),
                        fmt_ms(b["total_ms"]),
                        fmt_bytes(b["ct_size_bytes"]),
                        f"{speedup:.1f}$\\times$"])
        print_latex_table(
            "Running time comparison: Piccard vs.\\ baseline~\\cite{{zlg24}} with varying universe size ($n = 500$, STD128).",
            "tab:comparison-universe", lh, lr)


# ── Table 3: Piccard vs Baseline — vary set size ────────────────────

def table_comparison_setsize(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 3: Piccard vs Baseline — Varying Set Size")
    print("=" * 70)

    scenarios = {}
    for r in data:
        scen = r.get("scenario", "")
        if not scen.startswith("vary_setsize"):
            continue
        scenarios.setdefault(scen, {})[r["method"]] = r

    headers = ["|S|", "Method", "Encode", "Encrypt", "Compute",
               "Decrypt", "Total (ms)", "Error", "Speedup"]
    rows = []
    for scen in sorted(scenarios.keys(), key=lambda s: int(s.split("_")[-1])):
        pair = scenarios[scen]
        p = pair.get("piccard")
        b = pair.get("baseline")
        if not p or not b:
            continue
        p_total = float(p["total_ms"])
        b_total = float(b["total_ms"])
        speedup = b_total / p_total if p_total > 0 else 0
        rows.append([
            p["set_size"], "Piccard",
            fmt_ms(p["phase_encode_ms"]), fmt_ms(p["phase_encrypt_ms"]),
            fmt_ms(p["phase_compute_ms"]), fmt_ms(p["phase_decrypt_ms"]),
            fmt_ms(p["total_ms"]), fmt_err(p["jaccard_error"]), "",
        ])
        rows.append([
            "", "Baseline",
            fmt_ms(b["phase_encode_ms"]), fmt_ms(b["phase_encrypt_ms"]),
            fmt_ms(b["phase_compute_ms"]), fmt_ms(b["phase_decrypt_ms"]),
            fmt_ms(b["total_ms"]), fmt_err(b["jaccard_error"]),
            f"{speedup:.1f}x",
        ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        lh = ["$n$", "Method",
              "Encode", "Encrypt", "Compute", "Decrypt",
              "Total (ms)", "Speedup"]
        lr = []
        for scen in sorted(scenarios.keys(), key=lambda s: int(s.split("_")[-1])):
            pair = scenarios[scen]
            p, b = pair.get("piccard"), pair.get("baseline")
            if not p or not b:
                continue
            p_total = float(p["total_ms"])
            b_total = float(b["total_ms"])
            speedup = b_total / p_total if p_total > 0 else 0
            n = f"{int(p['set_size']):,}"
            lr.append([n, "Piccard",
                        fmt_ms(p["phase_encode_ms"]),
                        fmt_ms(p["phase_encrypt_ms"]),
                        fmt_ms(p["phase_compute_ms"]),
                        fmt_ms(p["phase_decrypt_ms"]),
                        fmt_ms(p["total_ms"]), ""])
            lr.append(["", "Baseline",
                        fmt_ms(b["phase_encode_ms"]),
                        fmt_ms(b["phase_encrypt_ms"]),
                        fmt_ms(b["phase_compute_ms"]),
                        fmt_ms(b["phase_decrypt_ms"]),
                        fmt_ms(b["total_ms"]),
                        f"{speedup:.1f}$\\times$"])
        print_latex_table(
            "Running time comparison: Piccard vs.\\ baseline~\\cite{{zlg24}} with varying set size ($|\\mathcal{{U}}| = 2^{{18}}$, STD128).",
            "tab:comparison-setsize", lh, lr)


# ── Table 4: Accuracy comparison ────────────────────────────────────

def table_accuracy(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 4: Accuracy — Piccard vs Baseline")
    print("=" * 70)

    # Group by overlap level, then average across trials
    from collections import defaultdict
    groups = defaultdict(lambda: {"piccard": [], "baseline": []})

    for r in data:
        scen = r.get("scenario", "")
        if not scen.startswith("accuracy"):
            continue
        method = r["method"]
        groups[scen][method].append(r)

    headers = ["Overlap", "J_true", "Piccard J", "Piccard Err",
               "Baseline J", "Baseline Err"]
    rows = []

    for scen in sorted(groups.keys()):
        g = groups[scen]
        p_list = g["piccard"]
        b_list = g["baseline"]
        if not p_list or not b_list:
            continue

        j_true = float(p_list[0]["jaccard_expected"])
        p_j = sum(float(r["jaccard_computed"]) for r in p_list) / len(p_list)
        p_err = sum(float(r["jaccard_error"]) for r in p_list) / len(p_list)
        b_j = sum(float(r["jaccard_computed"]) for r in b_list) / len(b_list)
        b_err = sum(float(r["jaccard_error"]) for r in b_list) / len(b_list)

        # Extract overlap from scenario name
        overlap = scen.replace("accuracy_", "")

        rows.append([
            overlap,
            f"{j_true:.4f}",
            f"{p_j:.4f}",
            fmt_err(str(p_err)),
            f"{b_j:.4f}",
            fmt_err(str(b_err)),
        ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        lh = ["Overlap", "$J_{\\text{true}}$",
              "Piccard $\\hat{J}$", "Piccard $|\\epsilon|$",
              "Baseline $\\hat{J}$", "Baseline $|\\epsilon|$"]
        print_latex_table(
            "Accuracy comparison: Piccard (approximate) vs.\\ baseline (exact).",
            "tab:accuracy", lh, rows)


# ── Piccard accuracy (standalone) ───────────────────────────────────

def table_piccard_accuracy(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 5: Piccard Accuracy Across Similarity Levels")
    print("=" * 70)

    from collections import defaultdict
    # Group by overlap fraction (extracted from label like "accuracy_0.5_t0")
    groups = defaultdict(list)
    for r in data:
        label = r.get("label", "")
        if not label.startswith("accuracy_"):
            continue
        # Skip accuracy_k* rows (those belong to Table 10: accuracy vs k)
        if label.startswith("accuracy_k"):
            continue
        # Parse overlap from "accuracy_0.500000_t0"
        parts = label.split("_")
        if len(parts) >= 2:
            overlap = parts[1]
            groups[overlap].append(r)

    headers = ["Overlap", "k", "m", "J_true", "J_hat (avg)", "Avg Error"]
    rows = []
    for overlap in sorted(groups.keys(), key=float):
        trials = groups[overlap]
        j_true = float(trials[0]["jaccard_expected"])
        avg_j = sum(float(r["jaccard_computed"]) for r in trials) / len(trials)
        avg_err = sum(float(r["jaccard_error"]) for r in trials) / len(trials)
        rows.append([
            overlap,
            trials[0]["k"],
            trials[0]["m"],
            f"{j_true:.4f}",
            f"{avg_j:.4f}",
            fmt_err(str(avg_err)),
        ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)


# ── Table 6: Dynamic protocol timing ─────────────────────────────────

def is_skipped(r, field="total_ms"):
    """Check if a row is a SKIPPED configuration (timing = -1)."""
    return float(r.get(field, "0")) < 0


def fmt_ops(val):
    """Format ops/sec with commas."""
    v = float(val)
    if v <= 0:
        return "-"
    if v >= 1000000:
        return f"{v/1000000:.1f}M"
    if v >= 1000:
        return f"{v/1000:.1f}K"
    return f"{v:.0f}"


def table_dynamic_timing(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 6: Dynamic Protocol Timing")
    print("=" * 70)

    headers = ["Label", "k", "m", "d", "Init (ms)", "Insert (ops/s)",
               "Delete (ops/s)", "Compute (ms)", "Total (ms)", "CT Size"]
    rows = []
    for r in data:
        label = r.get("label", "")
        if label.startswith("accuracy_"):
            continue
        compute = float(r.get("phase_encode_ms", "0")) + \
                  float(r.get("phase_encrypt_ms", "0")) + \
                  float(r.get("phase_compute_ms", "0")) + \
                  float(r.get("phase_decrypt_ms", "0"))
        rows.append([
            label,
            r.get("k", ""),
            r.get("m", ""),
            r.get("depth", ""),
            fmt_ms(r.get("phase_init_ms", "0")),
            fmt_ops(r.get("ops_insert_per_sec", "0")),
            fmt_ops(r.get("ops_delete_per_sec", "0")),
            fmt_ms(str(compute)),
            fmt_ms(r.get("total_ms", "0")),
            fmt_bytes(r.get("ct_size_bytes", "0")),
        ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        lh = ["Config", "$k$", "$d$", "Init (ms)",
              "Insert (ops/s)", "Delete (ops/s)",
              "FHE (ms)", "Total (ms)"]
        lr = []
        for r in data:
            label = r.get("label", "")
            if not label.startswith("dynamic_vs_basic"):
                continue
            fhe = float(r.get("phase_encode_ms", "0")) + \
                  float(r.get("phase_encrypt_ms", "0")) + \
                  float(r.get("phase_compute_ms", "0")) + \
                  float(r.get("phase_decrypt_ms", "0"))
            lr.append([
                label.replace("_", "\\_"),
                r.get("k", ""), r.get("depth", ""),
                fmt_ms(r.get("phase_init_ms", "0")),
                fmt_ops(r.get("ops_insert_per_sec", "0")),
                fmt_ops(r.get("ops_delete_per_sec", "0")),
                fmt_ms(str(fhe)),
                fmt_ms(r.get("total_ms", "0")),
            ])
        if lr:
            print_latex_table(
                "Dynamic variant timing: BottomStructure operations and end-to-end protocol.",
                "tab:dynamic-timing", lh, lr)


# ── Table 7: Threshold protocol timing ───────────────────────────────

def table_threshold_timing(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 7: Threshold Protocol Timing")
    print("=" * 70)

    headers = ["Label", "k", "tau", "Depth", "N", "Encrypt",
               "Mul", "RotSum", "Mask", "PolyEval", "Decrypt",
               "Total (ms)", "CT Size", "Note"]
    rows = []
    for r in data:
        label = r.get("label", "")
        if label.startswith("accuracy_"):
            continue
        if is_skipped(r):
            rows.append([
                label, r.get("k", ""), r.get("tau", ""),
                r.get("mult_depth", ""), "N/A",
                "N/A", "N/A", "N/A", "N/A", "N/A", "N/A",
                "N/A", "-", r.get("note", ""),
            ])
        else:
            rows.append([
                label,
                r.get("k", ""), r.get("tau", ""),
                r.get("mult_depth", ""), r.get("ring_dim", ""),
                fmt_ms(r.get("phase_encrypt_ms", "0")),
                fmt_ms(r.get("phase_multiply_ms", "0")),
                fmt_ms(r.get("phase_rotate_sum_ms", "0")),
                fmt_ms(r.get("phase_mask_ms", "0")),
                fmt_ms(r.get("phase_poly_eval_ms", "0")),
                fmt_ms(r.get("phase_decrypt_ms", "0")),
                fmt_ms(r.get("total_ms", "0")),
                fmt_bytes(r.get("ct_size_bytes", "0")),
                r.get("note", ""),
            ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        lh = ["$k$", "$\\tau$", "Depth", "$N$",
              "Encrypt", "Compute", "PolyEval",
              "Total (ms)", "CT Size"]
        lr = []
        for r in data:
            label = r.get("label", "")
            if not label.startswith("vary_k_"):
                continue
            if is_skipped(r):
                lr.append([r.get("k", ""), r.get("tau", ""),
                           r.get("mult_depth", ""), "---",
                           "---", "---", "---", "---", "---"])
            else:
                compute = float(r.get("phase_multiply_ms", "0")) + \
                          float(r.get("phase_rotate_sum_ms", "0")) + \
                          float(r.get("phase_mask_ms", "0"))
                lr.append([
                    r.get("k", ""), r.get("tau", ""),
                    r.get("mult_depth", ""), r.get("ring_dim", ""),
                    fmt_ms(r.get("phase_encrypt_ms", "0")),
                    fmt_ms(str(compute)),
                    fmt_ms(r.get("phase_poly_eval_ms", "0")),
                    fmt_ms(r.get("total_ms", "0")),
                    fmt_bytes(r.get("ct_size_bytes", "0")),
                ])
        if lr:
            print_latex_table(
                "Threshold variant timing: polynomial evaluation dominates at higher $k$.",
                "tab:threshold-timing", lh, lr)


# ── Table 8: Threshold accuracy ──────────────────────────────────────

def table_threshold_accuracy(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 8: Threshold Accuracy")
    print("=" * 70)

    from collections import defaultdict

    # Group by tau, then aggregate correctness
    tau_groups = defaultdict(lambda: {"correct": 0, "total": 0, "fp": 0, "fn": 0})

    for r in data:
        label = r.get("label", "")
        if not label.startswith("accuracy_"):
            continue
        # Skip SKIPPED rows
        if r.get("threshold_correct", "-1") == "-1":
            continue

        tau = r.get("tau", "0")
        correct = int(r.get("threshold_correct", "0"))
        result = int(r.get("threshold_result", "0"))
        expected = int(r.get("threshold_expected", "0"))

        g = tau_groups[tau]
        g["total"] += 1
        g["correct"] += correct
        if result == 1 and expected == 0:
            g["fp"] += 1
        if result == 0 and expected == 1:
            g["fn"] += 1

    headers = ["tau", "Trials", "Correct", "Accuracy (%)", "FP Rate (%)", "FN Rate (%)"]
    rows = []
    for tau in sorted(tau_groups.keys(), key=lambda t: int(t)):
        g = tau_groups[tau]
        total = g["total"]
        if total == 0:
            continue
        accuracy = 100.0 * g["correct"] / total
        fp_rate = 100.0 * g["fp"] / total
        fn_rate = 100.0 * g["fn"] / total
        rows.append([
            tau,
            str(total),
            str(g["correct"]),
            f"{accuracy:.1f}",
            f"{fp_rate:.1f}",
            f"{fn_rate:.1f}",
        ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        lh = ["$\\tau$", "Trials", "Correct", "Accuracy (\\%)",
              "FP Rate (\\%)", "FN Rate (\\%)"]
        print_latex_table(
            "Threshold variant accuracy: decision correctness across threshold values.",
            "tab:threshold-accuracy", lh, rows)


# ── Table 9: Communication cost comparison ──────────────────────────────

def table_communication_cost(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 9: Communication Cost — Piccard vs Baseline")
    print("=" * 70)

    # Group by scenario (vary_universe_*), then compare ct_size
    scenarios = {}
    for r in data:
        scen = r.get("scenario", "")
        if not scen.startswith("vary_universe"):
            continue
        scenarios.setdefault(scen, {})[r["method"]] = r

    headers = ["|U|", "Piccard N", "Piccard #CTs", "Piccard CT Size",
               "Baseline N", "Baseline #CTs", "Baseline CT Size", "Size Ratio"]
    rows = []
    for scen in sorted(scenarios.keys(), key=lambda s: int(s.split("_")[-1])):
        pair = scenarios[scen]
        p = pair.get("piccard")
        b = pair.get("baseline")
        if not p or not b:
            continue
        u = p["universe_size"]
        p_ct = int(p.get("ct_size_bytes", "0"))
        b_ct = int(b.get("ct_size_bytes", "0"))
        ratio = b_ct / p_ct if p_ct > 0 else 0
        rows.append([
            u,
            p["ring_dim"], p["num_cts"], fmt_bytes(str(p_ct)),
            b["ring_dim"], b["num_cts"], fmt_bytes(str(b_ct)),
            f"{ratio:.1f}x",
        ])

    if not rows:
        print("  (no data)")
        return

    print_table(headers, rows)

    if latex:
        print()
        lh = ["$|\\mathcal{U}|$", "\\multicolumn{2}{c}{Piccard}", "CT Size",
              "\\multicolumn{2}{c}{Baseline}", "CT Size", "Ratio"]
        # Simplified LaTeX with clear columns
        lh2 = ["$|\\mathcal{U}|$", "$N_P$", "\\#CTs",
               "Size (P)", "$N_B$", "\\#CTs", "Size (B)", "Ratio"]
        lr = []
        for scen in sorted(scenarios.keys(), key=lambda s: int(s.split("_")[-1])):
            pair = scenarios[scen]
            p, b = pair.get("piccard"), pair.get("baseline")
            if not p or not b:
                continue
            u = int(p["universe_size"])
            u_str = f"$2^{{{int(round(log2(u)))}}}$" if u > 0 and (u & (u-1)) == 0 else f"{u:,}"
            p_ct = int(p.get("ct_size_bytes", "0"))
            b_ct = int(b.get("ct_size_bytes", "0"))
            ratio = b_ct / p_ct if p_ct > 0 else 0
            lr.append([
                u_str, p["ring_dim"], p["num_cts"], fmt_bytes(str(p_ct)),
                b["ring_dim"], b["num_cts"], fmt_bytes(str(b_ct)),
                f"{ratio:.1f}$\\times$",
            ])
        if lr:
            print_latex_table(
                "Communication cost: Piccard (constant) vs.\\ baseline (grows with $|\\mathcal{U}|$). "
                "Size is per-party ciphertext payload.",
                "tab:communication-cost", lh2, lr)


# ── Table 10: Accuracy vs k (MinHash convergence) ──────────────────────

def table_accuracy_vary_k(data, latex=False):
    if not data:
        return

    print("\n" + "=" * 70)
    print("  Table 10: Accuracy vs k — MinHash Convergence")
    print("=" * 70)

    from collections import defaultdict

    # Group by k (from labels like "accuracy_k64_0.500000_t0")
    k_groups = defaultdict(list)
    for r in data:
        label = r.get("label", "")
        if not label.startswith("accuracy_k"):
            continue
        # Parse k from "accuracy_k64_0.500000_t0"
        parts = label.split("_")
        if len(parts) >= 2:
            k_str = parts[1]  # "k64"
            k_groups[k_str].append(r)

    if not k_groups:
        print("  (no accuracy_k* data)")
        return

    headers = ["k", "Trials", "Mean |err|", "Max |err|", "RMSE",
               "Std Dev", "1/sqrt(k)"]
    rows = []
    for k_str in sorted(k_groups.keys(), key=lambda s: int(s[1:])):
        trials = k_groups[k_str]
        k_val = int(k_str[1:])
        errors = [float(r["jaccard_error"]) for r in trials]
        n = len(errors)
        mean_err = sum(errors) / n
        max_err = max(errors)
        rmse = (sum(e**2 for e in errors) / n) ** 0.5
        std_dev = (sum((e - mean_err)**2 for e in errors) / n) ** 0.5
        theoretical = 1.0 / (k_val ** 0.5)
        rows.append([
            str(k_val), str(n),
            f"{mean_err:.4f}", f"{max_err:.4f}",
            f"{rmse:.4f}", f"{std_dev:.4f}",
            f"{theoretical:.4f}",
        ])

    print_table(headers, rows)

    if latex:
        print()
        lh = ["$k$", "Trials", "Mean $|\\epsilon|$", "Max $|\\epsilon|$",
              "RMSE", "Std Dev", "$1/\\sqrt{k}$"]
        print_latex_table(
            "Estimation error decreases with $k$: MinHash convergence "
            "at rate $O(1/\\sqrt{k})$.",
            "tab:accuracy-vs-k", lh, rows)


# ── Save helper ──────────────────────────────────────────────────────────

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
        description="Summarize Piccard benchmark results.")
    parser.add_argument("results_dir",
                        help="Path to results directory")
    parser.add_argument("--latex", action="store_true",
                        help="Also emit LaTeX table fragments")
    parser.add_argument("--save-dir",
                        help="Save each table as a separate .txt file in this directory")
    args = parser.parse_args()

    d = Path(args.results_dir)
    if not d.is_dir():
        print(f"Error: {d} is not a directory", file=sys.stderr)
        sys.exit(1)

    sd = Path(args.save_dir) if args.save_dir else None
    if sd:
        sd.mkdir(parents=True, exist_ok=True)

    # Print system info if available
    sys_info = d / "system_info.txt"
    if sys_info.exists():
        print("=" * 70)
        print("  System Information")
        print("=" * 70)
        print(sys_info.read_text())

    # Detect security levels from CSV filenames.
    # New convention: piccard_timing_STD128.csv, piccard_timing_STD192.csv, ...
    # Old convention: piccard_timing.csv (no suffix)
    security_levels = []
    for f in sorted(d.glob("piccard_timing_*.csv")):
        # Extract security level from e.g. "piccard_timing_STD128.csv"
        stem = f.stem  # "piccard_timing_STD128"
        sec = stem.replace("piccard_timing_", "")
        if sec:
            security_levels.append(sec)

    if not security_levels:
        # Fall back to old naming convention (no suffix)
        security_levels = [None]

    for sec in security_levels:
        suffix = f"_{sec}" if sec else ""
        sec_label = f" ({sec})" if sec else ""

        if sec:
            print("\n" + "=" * 70)
            print(f"  Security level: {sec}")
            print("=" * 70)

        # Read CSVs for this security level
        piccard_timing = read_csv(d / f"piccard_timing{suffix}.csv")
        piccard_accuracy = read_csv(d / f"piccard_accuracy{suffix}.csv")
        comparison_timing = read_csv(d / f"comparison_timing{suffix}.csv")
        comparison_accuracy = read_csv(d / f"comparison_accuracy{suffix}.csv")

        # File suffix for saved tables
        file_suffix = f"_{sec}" if sec else ""

        # Generate tables (print to stdout + save individually)
        run_and_save(table_piccard_timing,
                     sd / f"table1_piccard_timing{file_suffix}.txt" if sd else None,
                     piccard_timing, latex=args.latex)
        run_and_save(table_comparison_universe,
                     sd / f"table2_comparison_universe{file_suffix}.txt" if sd else None,
                     comparison_timing, latex=args.latex)
        run_and_save(table_comparison_setsize,
                     sd / f"table3_comparison_setsize{file_suffix}.txt" if sd else None,
                     comparison_timing, latex=args.latex)
        run_and_save(table_accuracy,
                     sd / f"table4_accuracy{file_suffix}.txt" if sd else None,
                     comparison_accuracy, latex=args.latex)
        run_and_save(table_piccard_accuracy,
                     sd / f"table5_piccard_accuracy{file_suffix}.txt" if sd else None,
                     piccard_accuracy, latex=args.latex)

        # Dynamic and threshold benchmark CSVs
        dynamic_timing = read_csv(d / f"dynamic_timing{suffix}.csv")
        dynamic_accuracy = read_csv(d / f"dynamic_accuracy{suffix}.csv")
        threshold_timing = read_csv(d / f"threshold_timing{suffix}.csv")
        threshold_accuracy = read_csv(d / f"threshold_accuracy{suffix}.csv")

        run_and_save(table_dynamic_timing,
                     sd / f"table6_dynamic_timing{file_suffix}.txt" if sd else None,
                     dynamic_timing, latex=args.latex)
        run_and_save(table_threshold_timing,
                     sd / f"table7_threshold_timing{file_suffix}.txt" if sd else None,
                     threshold_timing, latex=args.latex)
        run_and_save(table_threshold_accuracy,
                     sd / f"table8_threshold_accuracy{file_suffix}.txt" if sd else None,
                     threshold_accuracy, latex=args.latex)

        # Communication cost (from comparison timing data)
        run_and_save(table_communication_cost,
                     sd / f"table9_communication_cost{file_suffix}.txt" if sd else None,
                     comparison_timing, latex=args.latex)

        # Accuracy vs k (from piccard accuracy data)
        run_and_save(table_accuracy_vary_k,
                     sd / f"table10_accuracy_vs_k{file_suffix}.txt" if sd else None,
                     piccard_accuracy, latex=args.latex)

    if sd:
        saved = [f.name for f in sorted(sd.glob("table*.txt"))]
        if saved:
            print(f"\n  Saved {len(saved)} table files to {sd}/")
            for name in saved:
                print(f"    {name}")

    print()


if __name__ == "__main__":
    main()
