#!/usr/bin/env python3
"""
summarize_results.py — Parse benchmark CSVs and produce 28 comparison tables.

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
from math import comb, sqrt
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


# ── Comparison-table extra methods ───────────────────────────────────
# The comparison timing/comm tables render Piccard vs the FHE-IND comparator
# ("baseline" CSV key, see FHE_IND_DISCLOSURE below) side by side. These
# additional methods (when present in the CSV) are emitted as their own
# supplementary rows so they are no longer silently dropped — notably `sj16`.
COMPARISON_EXTRA_METHODS = (
    "piccard_sqrt", "bcg12", "sj16", "sj16_precomputed"
)

# Static labels for exact-key supplementary methods. BCG12 variant labels are
# built from each row's typed comparison scope and primitive below.
_METHOD_LABELS = {
    "piccard_sqrt":
        "piccard_sqrt [end-to-end-estimator; bfv-sqrt-minhash]",
    "sj16": (
        "sj16 [component-lower-bound; intersection-shares-lower-bound; "
        "secure division excluded]"
    ),
    "sj16_precomputed": (
        "sj16_precomputed [component-lower-bound; "
        "intersection-shares-lower-bound; secure division excluded; "
        "randomizers-precomputed]"
    ),
}

# Exact disclosure sentence appended to the ASCII title AND the LaTeX caption of
# the comparison timing and communication tables whenever an sj16 row is present.
# SJ16 publishes shares of the intersection cardinality only; the secure-division
# step that would yield an end-to-end Jaccard is excluded, so its timing/comm are
# an optimistic lower bound and must not be read as a full-protocol cost.
SJ16_LOWER_BOUND_NOTE = (
    "SJ16: shares of intersection cardinality; "
    "secure division excluded — optimistic lower bound."
)

# Printed in the Method column of every primary (Piccard-vs-comparator) row.
# The CSV method key stays "baseline" for internal compatibility. Its typed
# capability identifies only the local universe-sized BFV primitive and marks
# it diagnostic-only and comparison-ineligible; no external protocol or
# security theorem is attributed to this implementation.
FHE_IND_DISCLOSURE = (
    "FHE-IND [local-universe-sized-BFV-comparator; diagnostic-only]"
)


_REQUIRED_TAXONOMY = {
    "cryptographic_profile", "nominal_security_bits", "security_match",
    "comparison_eligible", "comparison_scope", "primitive",
    "protocol_model", "output_semantics", "assurance_scope",
    "security_basis", "cost_scope", "precomputation_mode",
    "secure_division_included", "measurement_kind", "evidence_arm",
    "measurement_status",
    "target_security_bits", "k", "m", "ring_dim", "sanitizer_model",
    "openfhe_version", "actual_ring_dim", "log_q_bits",
    "plaintext_modulus", "num_limbs", "hash_randomness", "hash_seed",
}


def _expect_taxonomy(row, expected):
    method = row.get("method", "")
    for field, want in expected.items():
        got = row.get(field, "")
        if got != want:
            raise ValueError(
                f"{method}: {field}={got!r}, expected {want!r}")


def _require_positive_numeric(row, fields):
    for field in fields:
        value = row.get(field, "")
        try:
            valid = float(value) > 0
        except ValueError:
            valid = False
        if not valid:
            raise ValueError(
                f"{row.get('method', '')}: {field} must be positive numeric")


def validate_comparison_taxonomy(rows):
    """Fail closed on any comparison row outside the Phase-3 truth table."""
    if not rows:
        return
    missing = _REQUIRED_TAXONOMY - set(rows[0])
    if missing:
        raise ValueError(f"comparison CSV missing taxonomy columns: {sorted(missing)}")

    boundaries = defaultdict(set)
    row_keys = set()
    for row in rows:
        method = row.get("method", "")
        target = row.get("target_security_bits", "")
        joined = " ".join(row.values())
        if "KPA/leakage" in joined or "EPSet" in joined:
            raise ValueError(f"{method}: forbidden legacy FHE-IND taxonomy")
        if row.get("measurement_status") not in {
            "measured", "extrapolated", "infeasible", "skipped", "error"
        }:
            raise ValueError(f"{method}: invalid measurement_status")
        if row.get("secure_division_included") != "false":
            raise ValueError(f"{method}: secure division token must be false")
        if row.get("security_basis") in {"", "not-applicable"}:
            raise ValueError(f"{method}: missing implemented security_basis")

        evidence = row.get("evidence_arm", "")
        if evidence not in {"timing", "accuracy"}:
            raise ValueError(f"{method}: invalid evidence_arm")
        if method in {"piccard", "piccard_sqrt"}:
            sqrt = method == "piccard_sqrt"
            _expect_taxonomy(row, {
                "cryptographic_profile": (
                    "live-BFV-TOY" if target == "0" else f"live-BFV-STD{target}"
                ),
                "nominal_security_bits": target,
                "security_match": "true",
                "comparison_eligible": "false" if target == "0" else "true",
                "comparison_scope": "end-to-end-estimator",
                "primitive": "bfv-sqrt-minhash" if sqrt else "bfv-onehot-minhash",
                "protocol_model": (
                    "piccard-sqrt-two-owner-outsourced" if sqrt
                    else "piccard-two-owner-outsourced"
                ),
                "output_semantics": "bias-corrected-jaccard-estimate",
                "assurance_scope": "live-bfv+empirical-sanitizer-poc",
                "security_basis": "openfhe-hesea-standard-live-context",
                "cost_scope": "full-query-excluding-one-time-setup",
                "precomputation_mode": "crs-and-keys-only",
                "measurement_kind": f"fhe-{evidence}",
            })
            _require_positive_numeric(row, ("k", "m", "ring_dim"))
            if row.get("sanitizer_model") == "not-applicable":
                raise ValueError(f"{method}: Piccard sanitizer cannot be absent")
            _require_positive_numeric(
                row, ("actual_ring_dim", "log_q_bits", "plaintext_modulus",
                      "num_limbs"))
        elif method == "baseline":
            _expect_taxonomy(row, {
                "cryptographic_profile": (
                    "live-BFV-TOY" if target == "0" else f"live-BFV-STD{target}"
                ),
                "nominal_security_bits": target,
                "security_match": "true",
                "comparison_eligible": "false",
                "comparison_scope": "diagnostic-only",
                "primitive": "bfv-indicator-comparison",
                "protocol_model": "local-universe-sized-BFV-comparator",
                "output_semantics": "intersection-indicator-vector",
                "assurance_scope": "live-bfv-primitive-only",
                "security_basis": "openfhe-hesea-standard-live-context",
                "cost_scope": "primitive-only",
                "precomputation_mode": "not-applicable",
                "measurement_kind": "diagnostic",
                "k": "", "m": "",
                "sanitizer_model": "not-applicable",
            })
            _require_positive_numeric(
                row, ("ring_dim", "actual_ring_dim", "log_q_bits",
                      "plaintext_modulus", "num_limbs"))
        elif method.startswith("bcg12_"):
            parts = method.split("_")
            if len(parts) != 3 or parts[1] not in {"mh", "exact"} or \
                    parts[2] not in {"ff", "ec"}:
                raise ValueError(f"unknown BCG12 method {method!r}")
            exact, ff = parts[1] == "exact", parts[2] == "ff"
            matched = target == "128"
            _expect_taxonomy(row, {
                "cryptographic_profile": "FF-3072/256" if ff else "P-256",
                "nominal_security_bits": "128",
                "security_match": "true" if matched else "false",
                "comparison_eligible": "true" if matched else "false",
                "comparison_scope": (
                    "matched-cardinality-component" if exact
                    else "matched-estimator-component"
                ),
                "primitive": "bcg12-ff" if ff else "bcg12-ec",
                "protocol_model": (
                    "bcg12-exact-cardinality" if exact
                    else "bcg12-cardinality-on-minhash"
                ),
                "output_semantics": (
                    "harness-reconstructed-exact-jaccard" if exact
                    else "minhash-collision-jaccard-estimate"
                ),
                "assurance_scope": "implemented-baseline-parameter-map",
                "security_basis": (
                    "finite-field-dh-3072-subgroup-256-parameter-map" if ff
                    else "nist-p256-parameter-map"
                ),
                "cost_scope": "full-query-excluding-one-time-setup",
                "precomputation_mode": "crs-and-keys-only",
                "measurement_kind": f"psi-{evidence}" if matched else "diagnostic",
                "m": "", "ring_dim": "",
                "sanitizer_model": "not-applicable",
                "openfhe_version": "not-applicable",
            })
            if exact:
                if row.get("k") != "":
                    raise ValueError(f"{method}: exact mode requires empty k")
            else:
                _require_positive_numeric(row, ("k",))
                if row.get("hash_randomness", "") == "" or \
                        row.get("hash_seed", "") == "":
                    raise ValueError(
                        f"{method}: MinHash mode requires workload hash seed")
        elif method in {"sj16", "sj16_precomputed"}:
            profile = row.get("cryptographic_profile", "")
            try:
                bits = int(profile.removeprefix("Paillier-"))
            except ValueError as error:
                raise ValueError(f"{method}: invalid Paillier profile") from error
            if bits not in {1024, 2048, 3072} or profile != f"Paillier-{bits}":
                raise ValueError(f"{method}: unsupported Paillier profile")
            nominal = {1024: "80", 2048: "112", 3072: "128"}[bits]
            basis = {
                1024: "rsa-ifc-modulus-size-proxy-approximately-80-bits",
                2048: "rsa-ifc-modulus-size-proxy-approximately-112-bits",
                3072:
                    "rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security",
            }[bits]
            matched = bits == 3072 and target == "128"
            precomputed = method == "sj16_precomputed"
            _expect_taxonomy(row, {
                "nominal_security_bits": nominal,
                "security_match": "true" if matched else "false",
                "comparison_eligible": (
                    "true" if matched and not precomputed else "false"
                ),
                "comparison_scope": "component-lower-bound",
                "primitive": f"paillier-{bits}",
                "protocol_model": "sj16-intersection-shares",
                "output_semantics":
                    "harness-reconstructed-jaccard-with-plaintext-union",
                "assurance_scope": "intersection-shares-lower-bound",
                "security_basis": basis,
                "cost_scope": (
                    "online-query-with-precomputed-randomizers" if precomputed
                    else "full-query-excluding-one-time-setup"
                ),
                "precomputation_mode": (
                    "randomizers-precomputed" if precomputed
                    else "randomizer-generation-included"
                ),
                "measurement_kind": f"ahe-{evidence}" if matched else "diagnostic",
                "k": "", "m": "", "ring_dim": "",
                "sanitizer_model": "not-applicable",
                "openfhe_version": "not-applicable",
            })
        else:
            raise ValueError(f"unknown comparison method {method!r}")

        key = (row.get("scenario", ""), method,
               row.get("measurement_kind", ""), evidence)
        if key in row_keys:
            raise ValueError(f"duplicate comparison taxonomy row {key}")
        row_keys.add(key)
        boundaries[(method, row.get("measurement_kind", ""))].add((
            row.get("cost_scope", ""), row.get("precomputation_mode", "")))

    for key, values in boundaries.items():
        if len(values) != 1:
            raise ValueError(f"mixed cost/precomputation scopes for {key}: {values}")
    for row in rows:
        if row.get("method") == "sj16_precomputed":
            companion = (row.get("scenario", ""), "sj16",
                         row.get("measurement_kind", ""),
                         row.get("evidence_arm", ""))
            if companion not in row_keys:
                raise ValueError(
                    "sj16_precomputed cannot replace the included-cost sj16 row")


def has_sj16_row(rows):
    """True if any row in `rows` is an sj16 method row."""
    return any(r.get("method", "") == "sj16" for r in rows)


def _boundary_match(name, base):
    """True if `name` is exactly `base` or a `base_`-prefixed variant.

    Boundary-aware on purpose: a bare `name.startswith(base)` would also
    match an unrelated future method name that merely shares the prefix
    (e.g. a hypothetical "bcg12x").
    """
    return name == base or name.startswith(base + "_")


# Deterministic output order for extra-method rows: piccard_sqrt, then all
# bcg12 variants (sorted), then sj16.
_EXTRA_METHOD_RANK = {base: i for i, base in enumerate(COMPARISON_EXTRA_METHODS)}


def _extra_method_base(name):
    """Which COMPARISON_EXTRA_METHODS bucket `name` belongs to, or None.

    Only "bcg12" uses boundary-aware (variant) matching — multiple BCG12
    variants can coexist in one scenario (bcg12_mh_ff + bcg12_mh_ec in
    vary_universe; bcg12_exact_ec + bcg12_exact_ff in vary_size_100/1000).
    "piccard_sqrt" and "sj16" deliberately stay exact matches: extending the
    boundary-aware predicate to them would let a future piccard_sqrt_*
    variant silently land under the comparator-side columns (piccard_side
    below assumes `extra == "piccard_sqrt"` is an exact check).
    """
    for base in COMPARISON_EXTRA_METHODS:
        if base == "bcg12":
            if _boundary_match(name, base):
                return base
        elif name == base:
            return base
    return None


def _extra_method_keys(methods):
    """All extra-method CSV keys present in one scenario's `methods` dict,
    in deterministic order: piccard_sqrt -> sorted bcg12_* -> sj16.

    Enumerates every matching key actually present (never just one), so
    e.g. both bcg12_mh_ff and bcg12_mh_ec are emitted as separate rows.
    """
    keys = [k for k in methods if _extra_method_base(k) is not None]
    keys.sort(key=lambda k: (_EXTRA_METHOD_RANK[_extra_method_base(k)], k))
    return keys


def method_tag(method, row=None):
    """Plain (ASCII) supplementary-row label for a comparison method.

    Exact-key methods (piccard_sqrt, bcg12, sj16) use the static table above.
    BCG12 variant labels are built from the row's typed comparison scope and
    primitive so display metadata cannot drift from serialized capability.

    Rows marked extrapolated append an explicit status suffix.
    """
    if method in _METHOD_LABELS:
        base = _METHOD_LABELS[method]
    elif row is not None and _boundary_match(method, "bcg12"):
        base = (
            f"{method} [{row.get('comparison_scope', '')}; "
            f"{row.get('primitive', '')}]"
        )
    else:
        base = method
    if row is not None and row.get("measurement_kind", "measured") == "extrapolated":
        return f"{base} [extrapolated]"
    return base


def method_tag_latex(method, row=None):
    """LaTeX-safe label: escape underscores so tabular rows compile."""
    return method_tag(method, row).replace("_", "\\_")


def fmt_speedup(method_ms, piccard_ms, *, latex: bool, row_role: str) -> str:
    """Format a comparison-table Speedup cell: how many x faster Piccard is
    than `method_ms`. Extracted from table_comparison_timing's two inline
    call sites (ASCII + LaTeX, primary + supplementary) — output preserved
    byte-for-byte.

    row_role controls the zero-value policy (this is the behavior being
    preserved, not a new choice):
      - "primary": guarded on piccard_ms > 0 only, so method_ms == 0 still
        renders "0.0x" (a genuinely-zero comparator time is a real ratio).
      - "supplementary": guarded on method_ms > 0 and piccard_ms > 0, so a
        missing/zero method row renders "-" instead of a misleading 0.0x.
    """
    if row_role == "primary":
        ok = piccard_ms > 0
    elif row_role == "supplementary":
        ok = method_ms > 0 and piccard_ms > 0
    else:
        raise ValueError(f"unknown row_role: {row_role!r}")
    if not ok:
        return "-"
    suffix = "$\\times$" if latex else "x"
    return f"{method_ms / piccard_ms:.1f}{suffix}"


def fmt_ratio(method_bytes, piccard_bytes, *, latex: bool, row_role: str) -> str:
    """Format a communication-table Ratio cell: method_bytes / piccard_bytes.
    Extracted from table_communication_cost's two inline call sites (primary
    + supplementary) — output preserved byte-for-byte.

    Both roles use the same guard (piccard_bytes > 0 only); `row_role` is
    accepted for signature symmetry with fmt_speedup. `latex` is likewise
    accepted but intentionally IGNORED: the LaTeX communication table
    currently reuses the ASCII `rows` list (see table_communication_cost), so
    its Ratio cells must keep the plain "x" suffix, never "$\\times$". Do not
    switch this to $\\times$ without an explicit plan update — the reporting
    plan requires that change to be reviewed, not a silent output change.
    """
    del row_role, latex  # both roles/formats share the same "x" guard today
    if piccard_bytes > 0:
        return f"{method_bytes / piccard_bytes:.1f}x"
    return "-"


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
               "Multiply", "RotSum", "Flood", "Decrypt", "Total (ms)", "CT Size"]
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
            fmt_disp(r, "phase_flood_ms", ci=ci),
            fmt_disp(r, "phase_decrypt_ms", ci=ci),
            fmt_disp(r, "time_ms", ci=ci),
            fmt_bytes(r.get("ct_size_bytes", "0")),
        ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$", "vary_size_": "$n$"}
        param_label = param_map.get(scenario, "Param")
        lh = [param_label, "$n$", "$N$", "Trials", "MinHash", "Encode", "Encrypt",
              "Multiply", "RotSum", "Flood", "Decrypt", "Total (ms)", "CT Size"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""), get_trials(r),
                fmt_disp(r, "phase_minhash_ms", ci=ci),
                fmt_disp(r, "phase_encode_ms", ci=ci),
                fmt_disp(r, "phase_encrypt_ms", ci=ci),
                fmt_disp(r, "phase_multiply_ms", ci=ci),
                fmt_disp(r, "phase_rotate_sum_ms", ci=ci),
                fmt_disp(r, "phase_flood_ms", ci=ci),
                fmt_disp(r, "phase_decrypt_ms", ci=ci),
                fmt_disp(r, "time_ms", ci=ci),
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

    # Split by hash_randomness only when mixed; pooling would report a mean describing neither mode.
    modes = {r.get("hash_randomness", "") for r in filtered}
    split_modes = len(modes) > 1

    # Group by parameter value from labels like "accuracy_k64_0.5_t0" → "64"
    groups = defaultdict(list)
    prefix_len = len(param_prefix)
    for r in filtered:
        label = r.get("label", "")
        rest = label[prefix_len:]
        param_val = rest.split("_")[0]
        mode = r.get("hash_randomness", "") if split_modes else ""
        groups[(param_val, mode)].append(r)

    if not groups:
        return

    show_theoretical = (param_prefix == "accuracy_k")
    headers = [param_name]
    if split_modes:
        headers.append("Hash")
    headers += ["Trials", "Mean |err|", "Max |err|", "RMSE", "Std Dev",
                "1/sqrt(k)" if show_theoretical else "Mean Rel Err"]

    rows = []
    for key in sorted(groups.keys(), key=lambda kv: (float(kv[0]), kv[1])):
        pval, mode = key
        trials = groups[key]
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

        row = [pval]
        if split_modes:
            row.append(mode or "n/a")
        row += [str(n), f"{mean_err:.4f}", f"{max_err:.4f}",
                f"{rmse:.4f}", f"{std_dev:.4f}", last_col]
        rows.append(row)

    print_table(headers, rows)

    if latex:
        print()
        pn = f"${param_name}$" if len(param_name) <= 2 else param_name
        lh = [pn]
        if split_modes:
            lh.append("Hash")
        lh += ["Trials", "Mean $|\\epsilon|$", "Max $|\\epsilon|$", "RMSE",
               "Std Dev",
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
        lh = [param_label, "$n$", "$N$", "Trials", "Time (ms)",
              "Median Err", "P25", "P75", "P95", "Max Err"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""), get_trials(r),
                fmt_disp(r, "time_ms", ci=ci),
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
    """Comparison timing: Piccard vs the FHE-IND comparator side by side."""
    rows_data = [
        row for row in filter_rows(data, "scenario", scenario)
        if row.get("evidence_arm") == "timing"
    ]
    if not rows_data:
        return

    sj16_present = has_sj16_row(rows_data)

    ascii_title = f"{title} {SJ16_LOWER_BOUND_NOTE}" if sj16_present else title
    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {ascii_title}")
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

    headers = ["Method", "Scenario", "Tri", "k", "m", "n", "|U|", "N_p", "N_c",
               "Piccard (ms)", "Comparator (ms)", "Speedup",
               "Piccard CT", "Comparator CT", "Comm P", "Comm C", "Flood"]
    rows = []
    for scen in order:
        methods = groups[scen]
        p = methods.get("piccard", {})
        b = methods.get("baseline", {})

        p_time = float(p.get("total_ms", "0"))
        b_time = float(b.get("total_ms", "0"))
        speedup = fmt_speedup(b_time, p_time, latex=False, row_role="primary")

        rows.append([
            FHE_IND_DISCLOSURE,
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
            fmt_disp(p, "phase_flood_ms", ci=ci) if p else "-",
        ])

        # Supplementary rows for methods the side-by-side Piccard/Comparator
        # row does not carry (sj16, bcg12 variants, piccard_sqrt). Emitted so
        # they are no longer silently dropped; the main row above is left
        # untouched. _extra_method_keys() enumerates every matching CSV key
        # actually present in this scenario (e.g. both bcg12_mh_ff and
        # bcg12_mh_ec), in deterministic order.
        #
        # Column placement is correctness-critical: piccard_sqrt is a Piccard
        # variant, so its value belongs under the Piccard-labeled columns; sj16
        # and bcg12 are NOT Piccard, so their values go under the Comparator-
        # labeled columns and the Piccard columns are blanked. No non-Piccard
        # method is ever printed under a "Piccard *" column.
        for key in _extra_method_keys(methods):
            e = methods[key]
            e_time = float(e.get("total_ms", "0"))
            # Same sense as the main Speedup column: method_time / piccard_time,
            # i.e. how many x faster Piccard is than this method.
            sp = fmt_speedup(e_time, p_time, latex=False, row_role="supplementary")
            piccard_side = (key == "piccard_sqrt")
            ring_cell = e.get("ring_dim", "")
            time_cell = fmt_disp(e, "total_ms", ci=ci)
            ct_cell = fmt_bytes(e.get("ct_size_bytes", "0"))
            comm_cell = fmt_bytes(e.get("comm_bytes", "0"))
            rows.append([
                "  " + method_tag(key, e),
                scen,
                get_trials(e),
                e.get("k", ""), e.get("m", ""),
                e.get("set_size", ""), e.get("universe_size", ""),
                ring_cell if piccard_side else "",    # N_p
                "" if piccard_side else ring_cell,    # N_c
                time_cell if piccard_side else "",    # Piccard (ms)
                "" if piccard_side else time_cell,    # Comparator (ms)
                sp,
                ct_cell if piccard_side else "",      # Piccard CT
                "" if piccard_side else ct_cell,      # Comparator CT
                comm_cell if piccard_side else "",    # Comm P
                "" if piccard_side else comm_cell,    # Comm C
                fmt_disp(e, "phase_flood_ms", ci=ci),  # Flood (0 for non-Piccard methods)
            ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$",
                     "vary_size_": "$n$", "vary_universe_": "$|U|$"}
        param_label = param_map.get(scenario, "Param")
        lh = ["Method", param_label, "Trials", "$N_P$", "$N_C$",
              "Piccard (ms)", "Comparator (ms)", "Speedup", "Comm P", "Comm C", "Flood"]
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
            speedup = fmt_speedup(b_time, p_time, latex=True, row_role="primary")
            lr.append([
                FHE_IND_DISCLOSURE,
                pval, get_trials(p) if p else get_trials(b),
                p.get("ring_dim", ""), b.get("ring_dim", ""),
                fmt_disp(p, "total_ms", ci=ci) if p else "-",
                fmt_disp(b, "total_ms", ci=ci) if b else "-",
                speedup, fmt_bytes(p.get("comm_bytes", "0")),
                fmt_bytes(b.get("comm_bytes", "0")),
                fmt_disp(p, "phase_flood_ms", ci=ci) if p else "-",
            ])
            # Supplementary LaTeX rows for sj16/bcg12 variants/piccard_sqrt
            # when present. piccard_sqrt stays on the Piccard side; sj16/bcg12
            # sit under the Comparator-side columns (never under "Piccard
            # (ms)"/"Comm P").
            for key in _extra_method_keys(methods):
                e = methods[key]
                e_time = float(e.get("total_ms", "0"))
                sp = fmt_speedup(e_time, p_time, latex=True, row_role="supplementary")
                piccard_side = (key == "piccard_sqrt")
                ring_cell = e.get("ring_dim", "")
                time_l = fmt_disp(e, "total_ms", ci=ci)
                comm_l = fmt_bytes(e.get("comm_bytes", "0"))
                lr.append([
                    method_tag_latex(key, e), pval, get_trials(e),
                    ring_cell if piccard_side else "",   # $N_P$
                    "" if piccard_side else ring_cell,   # $N_C$
                    time_l if piccard_side else "",   # Piccard (ms)
                    "" if piccard_side else time_l,   # Comparator (ms)
                    sp,
                    comm_l if piccard_side else "",   # Comm P
                    "" if piccard_side else comm_l,   # Comm C
                    fmt_disp(e, "phase_flood_ms", ci=ci),  # Flood (0 for non-Piccard methods)
                ])
        tab_id = scenario.rstrip("_").replace("_", "-")
        latex_caption = title
        if sj16_present:
            latex_caption = f"{title} {SJ16_LOWER_BOUND_NOTE}"
        print_latex_table(latex_caption, f"tab:comparison-{tab_id}", lh, lr)


# ── T14: Communication Cost ────────────────────────────────────────

def table_communication_cost(data, tnum, latex=False):
    """Communication cost comparison across all scenarios."""
    data = [row for row in data if row.get("evidence_arm") == "timing"]
    if not data:
        return

    sj16_present = has_sj16_row(data)

    comm_title = "Communication Cost — Piccard vs. Comparators (FHE-IND)"
    if sj16_present:
        comm_title = f"{comm_title} {SJ16_LOWER_BOUND_NOTE}"
    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {comm_title}")
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

    headers = ["Method", "Scenario", "k", "|U|", "n",
               "Piccard CTs", "Piccard Comm",
               "Comparator CTs", "Comparator Comm", "Ratio"]
    rows = []
    for scen in order:
        methods = groups[scen]
        p = methods.get("piccard", {})
        b = methods.get("baseline", {})

        p_comm = int(p.get("comm_bytes", "0"))
        b_comm = int(b.get("comm_bytes", "0"))
        ratio = fmt_ratio(b_comm, p_comm, latex=False, row_role="primary")

        rows.append([
            FHE_IND_DISCLOSURE,
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

        # Supplementary rows for sj16/bcg12 variants/piccard_sqrt so their
        # communication is no longer dropped. Ratio is the method's comm
        # relative to Piccard. piccard_sqrt is a Piccard variant → Piccard-
        # side columns; sj16/bcg12 go under the Comparator-side columns,
        # never under "Piccard CTs"/"Piccard Comm".
        for key in _extra_method_keys(methods):
            e = methods[key]
            e_comm = int(e.get("comm_bytes", "0"))
            e_ratio = fmt_ratio(e_comm, p_comm, latex=False, row_role="supplementary")
            piccard_side = (key == "piccard_sqrt")
            cts_cell = e.get("num_cts", "")
            comm_cell = fmt_bytes(e_comm)
            rows.append([
                "  " + method_tag(key, e),
                scen,
                e.get("k", ""),
                e.get("universe_size", ""),
                e.get("set_size", ""),
                cts_cell if piccard_side else "",    # Piccard CTs
                comm_cell if piccard_side else "",   # Piccard Comm
                "" if piccard_side else cts_cell,    # Comparator CTs
                "" if piccard_side else comm_cell,   # Comparator Comm
                e_ratio,
            ])

    print_table(headers, rows)

    if latex:
        print()
        # Reuses the ASCII `rows` list built above (not a fresh `lr`), so the
        # LaTeX table's width and cell content match the ASCII one
        # automatically. Consequence: its Ratio cells keep the ASCII "x"
        # suffix rather than "$\times$" — see fmt_ratio()'s docstring.
        lh = ["Method", "Scenario", "$k$", "$|U|$", "$n$",
              "P CTs", "P Comm", "C CTs", "C Comm", "Ratio"]
        latex_caption = "Communication cost: Piccard vs.\\ Comparators (FHE-IND)."
        if sj16_present:
            latex_caption = f"{latex_caption} {SJ16_LOWER_BOUND_NOTE}"
        print_latex_table(latex_caption, "tab:communication-cost", lh, rows)


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
               "Init", "Insert", "Delete", "Compute", "Flood", "Decrypt",
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
            fmt_disp(r, "phase_flood_ms", ci=ci),
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
        lh = [param_label, "$n$", "$N$", "Trials", "Depth",
              "Init", "Insert", "Delete", "Compute", "Flood", "Decrypt",
              "Total (ms)", "CT Size"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""), get_trials(r), r.get("depth", ""),
                fmt_disp(r, "phase_init_ms", ci=ci),
                fmt_disp(r, "phase_insert_ms", ci=ci),
                fmt_disp(r, "phase_delete_ms", ci=ci),
                fmt_disp(r, "phase_compute_ms", ci=ci),
                fmt_disp(r, "phase_flood_ms", ci=ci),
                fmt_disp(r, "phase_decrypt_ms", ci=ci),
                fmt_disp(r, "total_ms", ci=ci),
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
               "RotSum", "Mask", "PolyEval", "Flood", "Decrypt",
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
            fmt_disp(r, "phase_flood_ms", ci=ci),
            fmt_disp(r, "phase_decrypt_ms", ci=ci),
            fmt_disp(r, "total_ms", ci=ci),
            fmt_bytes(r.get("ct_size_bytes", "0")),
        ])

    print_table(headers, rows)

    if latex:
        print()
        param_map = {"vary_k_": "$k$", "vary_m_": "$m$", "vary_size_": "$n$"}
        param_label = param_map.get(scenario, "Param")
        lh = [param_label, "$n$", "$N$", "Trials", "$\\tau$", "Depth",
              "MinHash", "Encode", "Encrypt", "Multiply",
              "RotSum", "Mask", "PolyEval", "Flood", "Decrypt",
              "Total (ms)", "CT Size"]
        lr = []
        for r in rows_data:
            pval = r.get("label", "").split("_")[-1]
            if scenario == "vary_size_":
                pval = f"{int(pval):,}"
            lr.append([
                pval, r.get("set_size", ""), r.get("ring_dim", ""), get_trials(r),
                r.get("tau", ""), r.get("mult_depth", ""),
                fmt_disp(r, "phase_minhash_ms", ci=ci),
                fmt_disp(r, "phase_encode_ms", ci=ci),
                fmt_disp(r, "phase_encrypt_ms", ci=ci),
                fmt_disp(r, "phase_multiply_ms", ci=ci),
                fmt_disp(r, "phase_rotate_sum_ms", ci=ci),
                fmt_disp(r, "phase_mask_ms", ci=ci),
                fmt_disp(r, "phase_poly_eval_ms", ci=ci),
                fmt_disp(r, "phase_flood_ms", ci=ci),
                fmt_disp(r, "phase_decrypt_ms", ci=ci),
                fmt_disp(r, "total_ms", ci=ci),
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

    headers = [param_name, "Trials", "True-J Acc", "FP", "FN", "BFV Agree",
               "Mean |J err|", "Max |J err|", "RMSE J", "Mean Rel Err"]
    rows = []
    for pval in sorted(groups.keys(), key=lambda s: float(s)):
        trials = groups[pval]
        n = len(trials)

        # Threshold correctness
        correct = sum(1 for r in trials if r.get("threshold_correct", "0") == "1")
        thresh_acc = f"{correct / n:.3f}" if n > 0 else "N/A"

        # New-format columns (R3-4). Old CSVs lack them: fall back to N/A so
        # historical results still render.
        n_fp = sum(1 for r in trials if r.get("outcome") == "FP")
        n_fn = sum(1 for r in trials if r.get("outcome") == "FN")
        agrees = [int(r["fhe_agrees"]) for r in trials
                  if r.get("fhe_agrees", "") not in ("", "-1")]
        bfv_agree = f"{sum(agrees) / len(agrees):.3f}" if agrees else "N/A"
        has_outcome = any(r.get("outcome") for r in trials)
        fp_s = str(n_fp) if has_outcome else "N/A"
        fn_s = str(n_fn) if has_outcome else "N/A"
        if not has_outcome:
            # Old CSVs: threshold_correct is the *tautological* match-count
            # accuracy — the very number R3-4 rejects. Never present it
            # under the True-J Acc header.
            thresh_acc = "N/A"

        # Jaccard error stats
        errors = [abs(float(r.get("jaccard_error", "0"))) for r in trials]
        mean_err = sum(errors) / n
        max_err = max(errors)
        rmse = (sum(e ** 2 for e in errors) / n) ** 0.5

        rel_errs = [float(r.get("jaccard_rel_error", "-1")) for r in trials]
        valid_rel = [e for e in rel_errs if e >= 0]
        mean_rel = f"{sum(valid_rel) / len(valid_rel):.4f}" if valid_rel else "N/A"

        rows.append([
            pval, str(n), thresh_acc, fp_s, fn_s, bfv_agree,
            f"{mean_err:.4f}", f"{max_err:.4f}",
            f"{rmse:.4f}", mean_rel,
        ])

    print_table(headers, rows)

    if latex:
        print()
        pn = f"${param_name}$" if len(param_name) <= 2 else param_name
        tab_id = param_prefix.replace("accuracy_", "")
        lh = [pn, "Trials", "True-$J$ Acc", "FP", "FN", "BFV Agr.",
              "Mean $|\\epsilon_J|$", "Max $|\\epsilon_J|$", "RMSE",
              "Mean Rel Err"]
        print_latex_table(title, f"tab:threshold-accuracy-{tab_id}", lh, rows)


# ── T27: Threshold FP/FN near the true-Jaccard boundary ─────────────

def _binom_sf(tau, k, q):
    """P[Binom(k, q) >= tau]; stdlib only (no scipy on the bench machines)."""
    if q <= 0.0:
        return 1.0 if tau <= 0 else 0.0
    if q >= 1.0:
        return 1.0
    return sum(comb(k, i) * (q ** i) * ((1.0 - q) ** (k - i))
               for i in range(tau, k + 1))


def _decide_prob_theory(j, k, tau, m):
    """P(protocol decides 1 | true Jaccard j): match_count ~ Binom(k, q(j))."""
    q = j + (1.0 - j) / m
    return _binom_sf(tau, k, q)


def _wilson(p_hat, n, z=1.96):
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 1.0)
    denom = 1.0 + z * z / n
    center = (p_hat + z * z / (2 * n)) / denom
    half = z * sqrt(p_hat * (1.0 - p_hat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


_FPFN_POINT_RE = re.compile(r"^fpfn_k(\d+)_p(\d+)_t\d+$")


def table_threshold_fpfn(data, tnum, title, latex=False):
    """FP/FN vs true Jaccard near the boundary, with an idealized binomial
    theory overlay (exact only under ideal minwise hashing; the SHA-256
    rank-hashing family approximates it).

    Summary per k: FP rate over true negatives, FN rate over true positives
    (each with a Wilson 95% CI), precision, recall, and the same rates
    predicted by match_count ~ Binom(k, q(J)) on the *sampled* J values.
    Curve per k: 0.5-sigma bins of z = (J - J_tau)/sigma_J with empirical and
    theoretical P(decide = 1). The two edge bins absorb clamped |z| >= 2.5
    outliers (including the z = +3 endpoint) and are labeled open-ended.
    """
    rows_in = [r for r in data if r.get("label", "").startswith("fpfn_")]
    if not rows_in:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    by_k = defaultdict(list)
    for r in rows_in:
        by_k[int(r["k"])].append(r)

    sum_headers = ["k", "tau", "J_tau", "sigma_J", "Total n", "Trials/pt",
                   "FP rate [95% CI]", "FN rate [95% CI]",
                   "Prec", "Rec", "Idz.FP", "Idz.FN"]
    sum_rows = []
    curve_blocks = []

    for k in sorted(by_k):
        rows = by_k[k]
        tau = int(rows[0]["tau"])
        m = int(rows[0]["m"])
        j_tau = float(rows[0]["j_tau"])
        q_tau = j_tau + (1.0 - j_tau) / m
        sigma = sqrt(q_tau * (1.0 - q_tau) / k) / (1.0 - 1.0 / m)

        tp = fp = tn = fn = 0
        th_fp_sum = th_fn_sum = 0.0
        bins = defaultdict(lambda: [0, 0, 0.0, 0.0])  # z-bin -> [n, dec1, sumJ, sumTh]
        for r in rows:
            j = float(r["jaccard_expected"])
            dec = int(r["threshold_result"])
            truth = int(r["threshold_expected"])
            th = _decide_prob_theory(j, k, tau, m)
            if truth == 1:
                th_fn_sum += 1.0 - th
                if dec == 1: tp += 1
                else: fn += 1
            else:
                th_fp_sum += th
                if dec == 1: fp += 1
                else: tn += 1
            z = (j - j_tau) / sigma if sigma > 0 else 0.0
            b = max(-6, min(5, int(math.floor(z / 0.5))))  # 12 bins over [-3, 3)
            cell = bins[b]
            cell[0] += 1; cell[1] += dec; cell[2] += j; cell[3] += th

        n_neg, n_pos = fp + tn, tp + fn
        if n_neg:
            fp_rate = fp / n_neg
            fp_lo, fp_hi = _wilson(fp_rate, n_neg)
            fp_cell = f"{fp_rate:.4f} [{fp_lo:.4f},{fp_hi:.4f}]"
        else:
            fp_cell = "N/A"
        if n_pos:
            fn_rate = fn / n_pos
            fn_lo, fn_hi = _wilson(fn_rate, n_pos)
            fn_cell = f"{fn_rate:.4f} [{fn_lo:.4f},{fn_hi:.4f}]"
        else:
            fn_cell = "N/A"
        prec_cell = f"{tp / (tp + fp):.4f}" if (tp + fp) else "N/A"
        rec_cell = f"{tp / (tp + fn):.4f}" if (tp + fn) else "N/A"

        # Per-point trial count: labels are fpfn_k{k}_p{p}_t{t}, so group by
        # the point id (p) the same way the trial id (t) split is used
        # elsewhere. len(rows) is the *total* n across all points for this
        # k (Trials/pt x number of points), which is easy to mistake for the
        # per-point sample size the R3-4 commitment is expressed against.
        # A row whose label fails to parse, or whose label-k disagrees with
        # this group's k, means the data isn't what it claims to be; either
        # case must force "varies" rather than silently reporting a
        # possibly-understated uniform count.
        pt_counts = defaultdict(int)
        all_matched = True
        k_agrees = True
        for r in rows:
            pm = _FPFN_POINT_RE.match(r.get("label", ""))
            if pm:
                if int(pm.group(1)) != k:
                    k_agrees = False
                pt_counts[pm.group(2)] += 1
            else:
                all_matched = False
        distinct_counts = set(pt_counts.values())
        if all_matched and k_agrees and len(distinct_counts) == 1:
            trials_per_pt = str(distinct_counts.pop())
        else:
            trials_per_pt = "varies"

        sum_rows.append([
            str(k), str(tau), f"{j_tau:.4f}", f"{sigma:.4f}", str(len(rows)), trials_per_pt,
            fp_cell, fn_cell, prec_cell, rec_cell,
            f"{th_fp_sum / n_neg:.4f}" if n_neg else "N/A",
            f"{th_fn_sum / n_pos:.4f}" if n_pos else "N/A",
        ])

        c_rows = []
        for b in sorted(bins):
            n, d1, sj, sth = bins[b]
            # The clamp above folds z <= -3 into bin -6 and z >= +3 (incl. the
            # exact +3 endpoint) into bin 5; a half-open [+2.5,+3.0) label
            # would misdescribe those rows, so the edge bins are open-ended.
            if b == -6:
                zlab = "(-inf,-2.5)"
            elif b == 5:
                zlab = "[+2.5,+inf)"
            else:
                zlab = f"[{b * 0.5:+.1f},{(b + 1) * 0.5:+.1f})"
            c_rows.append([zlab, str(n),
                           f"{sj / n:.4f}", f"{d1 / n:.4f}", f"{sth / n:.4f}",
                           f"{abs(d1 / n - sth / n):.4f}"])
        curve_blocks.append((k, c_rows))

    print_table(sum_headers, sum_rows)
    for k, c_rows in curve_blocks:
        print(f"\n  Decision curve, k={k} (z = (J - J_tau)/sigma):")
        print_table(["z bin", "n", "mean J", "emp P(dec=1)", "idz. theory", "|diff|"],
                    c_rows)

    if latex:
        print()
        lh = ["$k$", r"$\tau$", r"$J_\tau$", r"$\sigma_J$", "Total $n$", "Trials/pt",
              "FP rate", "FN rate", "Prec.", "Rec.",
              "FP (idealized)", "FN (idealized)"]
        print_latex_table(title, "tab:threshold-fpfn", lh, sum_rows)


# ── T28: u_tau construction & evaluation parameters ─────────────────

def table_threshold_spec(data, tnum, title, latex=False):
    """Per-k u_tau spec: degree, Paterson-Stockmeyer shape, depth, modulus,
    noise/flooding budget. SKIPPED rows carry the infeasibility reason."""
    if not data:
        return

    print(f"\n{'=' * 70}")
    print(f"  Table {tnum}: {title}")
    print(f"{'=' * 70}")

    headers = ["k", "tau", "deg", "PS s", "chunks", "depth(nat)", "depth(prov)",
               "limb", "N", "p", "log2 q", "eval noise", "flood bits",
               "ct KB", "status"]
    rows = []
    for r in sorted(data, key=lambda r: int(r["k"])):
        if r.get("status") == "SKIPPED":
            rows.append([r["k"], r["tau"], r["degree"], r["ps_baby_s"],
                         r["ps_num_chunks"], r["natural_mult_depth"], "-", "-",
                         "-", "-", "-", "-", "-", "-",
                         f"SKIPPED: {r.get('note', '')[:40]}"])
            continue
        ct_kb = f"{int(r['ct_bytes']) / 1024:.0f}"
        rows.append([r["k"], r["tau"], r["degree"], r["ps_baby_s"],
                     r["ps_num_chunks"], r["natural_mult_depth"],
                     r["mult_depth"], r["scaling_mod_size"], r["ring_dim"],
                     r["plaintext_mod"], r["log2_q"], r["eval_noise_bits"],
                     r["flood_noise_bits"], ct_kb, "ok"])
    print_table(headers, rows)

    if latex:
        print()
        lh = ["$k$", r"$\tau$", r"$\deg u_\tau$", "$s$", "chunks",
              "depth", "prov.", "limb", "$N$", "$p$", r"$\log_2 q$",
              "noise", "flood", "ct KB", "status"]
        print_latex_table(title, "tab:threshold-spec", lh, rows)


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
        description="Summarize Piccard benchmark results (28 tables).")
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
        validate_comparison_taxonomy(comparison_timing)
        dynamic_timing = read_csv(d / f"dynamic_timing{suffix}.csv")
        dynamic_accuracy = read_csv(d / f"dynamic_accuracy{suffix}.csv")
        threshold_timing = read_csv(d / f"threshold_timing{suffix}.csv")
        threshold_accuracy = read_csv(d / f"threshold_accuracy{suffix}.csv")
        threshold_fpfn = read_csv(d / f"threshold_fpfn{suffix}.csv")
        threshold_spec = read_csv(d / f"threshold_spec{suffix}.csv")

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
                     "Piccard vs. Comparators (FHE-IND) — Varying k", latex=lx, ci=ci)
        run_and_save(table_comparison_timing, sp("T11_comparison_vary_m"),
                     comparison_timing, "vary_m_", 11,
                     "Piccard vs. Comparators (FHE-IND) — Varying m", latex=lx, ci=ci)
        run_and_save(table_comparison_timing, sp("T12_comparison_vary_n"),
                     comparison_timing, "vary_size_", 12,
                     "Piccard vs. Comparators (FHE-IND) — Varying n", latex=lx, ci=ci)
        run_and_save(table_comparison_timing, sp("T13_comparison_vary_universe"),
                     comparison_timing, "vary_universe_", 13,
                     "Piccard vs. Comparators (FHE-IND) — Varying |U|", latex=lx, ci=ci)

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

        # ── T27: Threshold boundary FP/FN ─────────────────────────
        run_and_save(table_threshold_fpfn, sp("T27_threshold_fpfn_boundary"),
                     threshold_fpfn, 27,
                     "Threshold FP/FN near the true-Jaccard boundary "
                     "(empirical vs idealized binomial overlay)",
                     latex=lx)

        # ── T28: u_tau spec ───────────────────────────────────────
        run_and_save(table_threshold_spec, sp("T28_threshold_spec"),
                     threshold_spec, 28,
                     "Threshold polynomial u_tau: construction and "
                     "evaluation parameters", latex=lx)

    if sd:
        saved = [f.name for f in sorted(sd.glob("T*.txt"))]
        if saved:
            print(f"\n  Saved {len(saved)} table files to {sd}/")
            for name in saved:
                print(f"    {name}")

    print()


if __name__ == "__main__":
    main()
