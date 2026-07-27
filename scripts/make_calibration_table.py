#!/usr/bin/env python3
"""Derive the noise-flooding calibration table from bench_noise CSV output.

The table this emits is what Phase 1 bakes into src/util/params.cpp: for each
circuit and parameter shape, the (mult_depth, scaling_mod_size) that leaves room
for 2^lambda_s flooding, and the measured evaluation-noise bound that sizes the
flooding term.

Selection rules, kept identical to the summary in benchmarks/bench_noise.cpp:

  * a cell is the worst of its input patterns (max eval_noise_bits)
  * a cell is usable only if every pattern decrypted, none saturated the
    measurement, and it did not grow the ring dimension past the one the
    circuit already needs
  * among usable cells, pick the smallest log q; break ties on lower noise,
    since the same modulus split into more, smaller limbs carries much less
    key-switching noise

The row key is (circuit, ring_dim_requested, natural_mult_depth). All three are
known to Validate() before a crypto context exists, which is what lets the
parameter selection look the row up. ring_dim_natural is carried as data: for
the threshold variant it exceeds ring_dim_requested on its own, so Phase 2 must
compare the realised dimension against it rather than against the request.

Usage:
    scripts/make_calibration_table.py [--dir DIR] [--lambda 64] [--margin 8]
                                      [--out PATH]
"""

import argparse
import csv
import math
import glob
import os
import subprocess
import sys
from collections import defaultdict

CIRCUIT_ORDER = {"onehot": 0, "sqrt": 1, "threshold": 2}


def load(directory):
    rows = []
    # probe_*.csv are ad-hoc single-shot measurements kept as evidence for a
    # decision (see 3_noise-flooding.md section 8). They are not part of the
    # calibrated grid -- they use --reps=1 and one input pattern -- so they must
    # not feed the table.
    paths = sorted(f for f in glob.glob(os.path.join(directory, "*.csv"))
                   if not os.path.basename(f).startswith("probe_"))
    if not paths:
        sys.exit(f"no CSV files in {directory}")
    for path in paths:
        with open(path, newline="") as fh:
            for row in csv.DictReader(fh):
                if row.get("status") == "ok":
                    rows.append(row)
    return rows, paths


def build_cells(rows):
    """Collapse (key, depth, sms) into one cell holding the worst pattern."""
    cells = {}
    for r in rows:
        key = (
            r["circuit"],
            r["security"],
            int(r["ring_dim_requested"]),
            int(r["natural_mult_depth"]),
            int(r["mult_depth"]),
            int(r["scaling_mod_size"]),
        )
        c = cells.setdefault(
            key,
            {
                "noise": -1.0,
                "ok": True,
                "grew": False,
                "saturated": False,
                "patterns": set(),
            },
        )
        c["noise"] = max(c["noise"], float(r["eval_noise_bits"]))
        c["log_delta"] = float(r["log_delta"])
        c["log_q"] = float(r["log_q"])
        c["limbs"] = int(r["num_limbs"])
        c["ring_dim"] = int(r["ring_dim"])
        c["ring_dim_natural"] = int(r["ring_dim_baseline"])
        c["t"] = int(r["plaintext_mod"])
        c["ct_bytes"] = max(c.get("ct_bytes", 0), int(r["ct_bytes"]))
        c["ok"] = c["ok"] and r["decrypt_ok"] == "1"
        c["grew"] = c["grew"] or r["ring_dim_grew"] == "1"
        c["saturated"] = c["saturated"] or r["saturated"] == "1"
        c["patterns"].add(r["pattern"])
    return cells


def select(cells, lam, margin):
    # Seed the group set from every cell, not only the usable ones. A group
    # whose cells all failed would otherwise appear in neither the table nor the
    # rejected list -- it would simply vanish, which is the one case that most
    # needs to be loud.
    groups = {}
    for (circuit, sec, req, nat_depth, depth, sms), c in cells.items():
        groups.setdefault((circuit, sec, req, nat_depth), [])
        if not c["ok"] or c["grew"] or c["saturated"]:
            continue
        spare = c["log_delta"] - c["noise"] - margin - lam - 2
        groups[(circuit, sec, req, nat_depth)].append((spare, depth, sms, c))

    chosen, rejected = {}, {}
    for key, cands in groups.items():
        feasible = [x for x in cands if x[0] >= 0]
        if not feasible:
            # cands may be empty: every cell failed to decrypt, saturated, or
            # grew the ring. rejected[key] = None says exactly that.
            rejected[key] = max(cands, key=lambda x: x[0]) if cands else None
            continue
        # smallest log q, then lowest noise
        chosen[key] = min(feasible, key=lambda x: (x[3]["log_q"], x[3]["noise"]))
    return chosen, rejected



def frontier(cells):
    """Per key, the cells worth keeping across every lambda_s.

    A cell is on the frontier when no cheaper cell (smaller log q, ties broken
    on noise) can carry at least as large a lambda_s. Validate() then scans the
    frontier in cost order and takes the first row whose budget covers the
    lambda_s actually configured -- which is what makes lowering lambda_s to 40
    select cheaper parameters on its own, instead of reusing the 64-bit row.
    """
    groups = {}
    for (circuit, sec, req, nat_depth, depth, sms), c in cells.items():
        groups.setdefault((circuit, sec, req, nat_depth), [])
        if not c["ok"] or c["grew"] or c["saturated"]:
            continue
        groups[(circuit, sec, req, nat_depth)].append((depth, sms, c))

    out = {}
    for key, cands in groups.items():
        cands.sort(key=lambda x: (x[2]["log_q"], x[2]["noise"]))
        keep, best_capacity = [], -1e18
        for depth, sms, c in cands:
            # largest (lambda_s + margin) this cell can carry
            # ceil to match what SelectFloodingParams actually compares against
            capacity = c["log_delta"] - math.ceil(c["noise"]) - 2
            if capacity > best_capacity:
                keep.append((depth, sms, c, capacity))
                best_capacity = capacity
        out[key] = keep
    return out


def emit_cpp(front, path, commit, row_count):
    lines = []
    lines.append("// Generated by scripts/make_calibration_table.py -- do not edit by hand.")
    lines.append("//")
    lines.append("// Noise calibration frontier for the flooding parameter selection (R2-W6,")
    lines.append("// roadmap P1-3). Each row records a (mult_depth, scaling_mod_size) that was")
    lines.append("// measured to decrypt correctly without growing the ring dimension past the")
    lines.append("// one the circuit already needs, together with the worst evaluation noise")
    lines.append("// observed for it.")
    lines.append("//")
    lines.append("// Rows are ordered by cost (log q, then noise) within a key, so the first row")
    lines.append("// whose budget covers the configured lambda_s is also the cheapest one.")
    lines.append("//")
    lines.append(f"// source commit : {commit}")
    lines.append("// measured with : OpenFHE 1.5.0, macOS arm64")
    lines.append(f"// measurements  : {row_count} rows, benchmarks/bench_noise --sweep --reps=5")
    lines.append("// raw data      : scripts/results/calibration/*.csv")
    lines.append("")
    lines.append("// clang-format off")
    lines.append("constexpr NoiseCalibration kNoiseCalibration[] = {")
    lines.append("    // circuit, security, req_N, nat_depth, nat_N, depth, sms,")
    lines.append("    //   eval_noise_bits, log_delta")
    for key in sorted(front, key=lambda x: (CIRCUIT_ORDER[x[0]], x[1], x[2], x[3])):
        circuit, sec, req, nat_depth = key
        enum = {"onehot": "Circuit::OneHot", "sqrt": "Circuit::Sqrt",
                "threshold": "Circuit::Threshold"}[circuit]
        for depth, sms, c, capacity in front[key]:
            lines.append(
                f"    {{{enum}, SecurityLevel::{sec}, {req}, {nat_depth}, "
                f"{c['ring_dim_natural']}, "
                f"{depth}, {sms}, {math.ceil(c['noise'])}, {c['log_delta']:.1f}}},"
                f"  // carries lambda_s + margin <= {capacity:.1f}")
    lines.append("};")
    lines.append("// clang-format on")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="scripts/results/calibration")
    ap.add_argument("--lam", "--lambda", dest="lam", type=int, default=64,
                    help="lambda_s")
    ap.add_argument("--margin", type=int, default=8)
    ap.add_argument("--out", default=None)
    ap.add_argument("--emit-cpp", dest="emit_cpp", default=None,
                    help="also write the C++ frontier table to this path")
    args = ap.parse_args()

    rows, paths = load(args.dir)
    cells = build_cells(rows)
    chosen, rejected = select(cells, args.lam, args.margin)

    dest = args.out or os.path.join(args.dir, "TABLE.md")

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        # Exclude this script's own outputs: regenerating them dirties the tree,
        # so counting them would make every run report "dirty" no matter what.
        outputs = {os.path.basename(dest), "noise_calibration.inc"}
        dirty = [
            line for line in subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True, text=True, check=True).stdout.splitlines()
            if line.strip() and os.path.basename(line.split()[-1]) not in outputs
        ]
        if dirty:
            commit += " (working tree dirty)"
    except Exception:
        commit = "unknown"

    partial = sorted(
        {(k[0], c["patterns"] and tuple(sorted(c["patterns"])))
         for k, c in cells.items() if len(c["patterns"]) < 3}
    )

    out = []
    out.append("# Noise calibration table (R2-W6 / roadmap P1-3)")
    out.append("")
    out.append("Generated by `scripts/make_calibration_table.py` from")
    out.append(f"`{args.dir}/*.csv` ({len(rows)} measured rows).")
    out.append("")
    out.append(f"- source commit: `{commit}`")
    out.append("- OpenFHE 1.5.0, macOS arm64")
    out.append(f"- selection target: lambda_s = {args.lam}, margin = {args.margin} bits")
    out.append("")
    out.append("`eval_noise_bits` is the worst value over the input patterns measured for")
    out.append("that cell. A cell qualifies only when every pattern decrypted, none")
    out.append("saturated the measurement, and the realised ring dimension did not exceed")
    out.append("`ring_dim_natural` -- the dimension the circuit already needs untouched.")
    out.append("")
    out.append("The key is (circuit, ring_dim_requested, natural_mult_depth): all three are")
    out.append("known before a crypto context exists, which is what the parameter selection")
    out.append("in `src/util/params.cpp` looks up. For the threshold variant")
    out.append("`ring_dim_natural` exceeds `ring_dim_requested` on its own -- a degree-k")
    out.append("polynomial needs a long modulus chain, with or without flooding -- so growth")
    out.append("must be judged against it, not against the request.")
    out.append("")
    if partial:
        out.append("> **Incomplete pattern coverage** for: " +
                   ", ".join(f"{c} ({'/'.join(p)})" for c, p in partial if p))
        out.append("")

    out.append("| circuit | security | ring_dim_requested | natural_depth | ring_dim_natural | "
               "mult_depth | scaling_mod_size | log q | limbs | t | eval_noise_bits | "
               "log Delta | spare | ct (bytes) |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for key in sorted(chosen, key=lambda x: (CIRCUIT_ORDER[x[0]], x[1], x[2], x[3])):
        spare, depth, sms, c = chosen[key]
        out.append(
            f"| {key[0]} | {key[1]} | {key[2]} | {key[3]} | {c['ring_dim_natural']} | {depth} | "
            f"{sms} | {c['log_q']:.0f} | {c['limbs']} | {c['t']} | {c['noise']:.2f} | "
            f"{c['log_delta']:.1f} | {spare:.2f} | {c['ct_bytes']} |")

    if rejected:
        out.append("")
        out.append("## No feasible cell")
        out.append("")
        out.append("| circuit | security | ring_dim_requested | natural_depth | short by (bits) |")
        out.append("|---|---|---|---|---|")
        for key in sorted(rejected, key=lambda x: (CIRCUIT_ORDER[x[0]], x[1], x[2], x[3])):
            best = rejected[key]
            short = f"{-best[0]:.2f}" if best else "no usable cell at all"
            out.append(f"| {key[0]} | {key[1]} | {key[2]} | {key[3]} | {short} |")

    if args.emit_cpp:
        front = frontier(cells)
        n = sum(len(v) for v in front.values())
        emit_cpp(front, args.emit_cpp, commit, len(rows))
        print(f"wrote {args.emit_cpp} ({n} frontier rows over {len(front)} keys)",
              file=sys.stderr)

    text = "\n".join(out) + "\n"
    with open(dest, "w") as fh:
        fh.write(text)
    print(text)
    print(f"wrote {dest}", file=sys.stderr)
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
