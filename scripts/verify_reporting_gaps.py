#!/usr/bin/env python3
"""Verify strict comparison taxonomy and its rendered reporting surfaces."""

import csv
import pathlib
import subprocess
import sys

import summarize_results as sr


FHE_IND_LABEL = (
    "FHE-IND [local-universe-sized-BFV-comparator; diagnostic-only]"
)
FORBIDDEN = ("KPA/leakage", "EPSet", "AHE/no-leakage")


def fail(message):
    raise SystemExit(f"reporting taxonomy verification failed: {message}")


def main():
    if len(sys.argv) != 2:
        fail("usage: verify_reporting_gaps.py <csv-dir>")
    csv_dir = pathlib.Path(sys.argv[1])
    comparison = csv_dir / "comparison_timing.csv"
    if not comparison.is_file():
        fail(f"missing {comparison}")
    with comparison.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        fail("comparison_timing.csv has no rows")

    try:
        sr.validate_comparison_taxonomy(rows)
    except (ValueError, KeyError) as error:
        fail(str(error))

    rendered = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).with_name(
            "summarize_results.py")), str(csv_dir), "--latex"],
        check=False, capture_output=True, text=True,
    )
    if rendered.returncode != 0:
        fail(f"summarizer rejected fixture: {rendered.stderr.strip()}")
    output = rendered.stdout + rendered.stderr
    if FHE_IND_LABEL not in output:
        fail("rendered output lacks the exact FHE-IND capability label")
    for token in FORBIDDEN:
        if token in output:
            fail(f"rendered output contains forbidden token {token!r}")

    methods = {row["method"] for row in rows}
    for method in sorted(methods - {"piccard", "fhe_ind"}):
        rendered_method = method.replace("_", "\\_")
        if method not in output and rendered_method not in output:
            fail(f"rendered output silently dropped method {method!r}")
    if any(method in {"sj16", "sj16_precomputed"} for method in methods):
        for token in (
            "intersection-shares-lower-bound", "secure division excluded"
        ):
            if token not in output:
                fail(f"rendered SJ16 output lacks {token!r}")

    print(
        "OK: strict capability taxonomy; "
        "local-universe-sized-BFV-comparator; "
        "intersection-shares-lower-bound"
    )


if __name__ == "__main__":
    main()
