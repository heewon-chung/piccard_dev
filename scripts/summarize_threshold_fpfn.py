#!/usr/bin/env python3
"""Summarize the versioned synthetic threshold FP/FN CSV without FHE claims."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys
from typing import Iterable, Mapping, Sequence


def summarize_rows(rows: Iterable[Mapping[str, str]]) -> dict[str, object]:
    grouped: dict[int, list[Mapping[str, str]]] = {}
    profile = None
    for row in rows:
        profile = profile or row.get("profile")
        k = int(row["k"])
        grouped.setdefault(k, []).append(row)

    by_k: dict[str, dict[str, object]] = {}
    for k in (64, 128, 256, 512):
        selected = grouped.get(k, [])
        truth_positive = sum(int(row["exact_j_truth"]) == 1 for row in selected)
        truth_negative = len(selected) - truth_positive
        fp = sum(row["outcome"] == "FP" for row in selected)
        fn = sum(row["outcome"] == "FN" for row in selected)
        by_k[str(k)] = {
            "rows": len(selected),
            "points": len({int(row["grid_index"]) for row in selected}),
            "trials": len({int(row["trial_index"]) for row in selected}),
            "false_positive_rows": fp,
            "false_negative_rows": fn,
            "false_positive_rate": fp / truth_negative if truth_negative else None,
            "false_negative_rate": fn / truth_positive if truth_positive else None,
            "mean_predicted_error_probability": (
                sum(float(row["predicted_error_probability"]) for row in selected)
                / len(selected)
                if selected
                else None
            ),
        }

    return {
        "schema_version": "piccard-threshold-fpfn-v1",
        "profile": profile,
        "rows": sum(len(rows_for_k) for rows_for_k in grouped.values()),
        "by_k": by_k,
        "paper_performance_status": "not measured by this plaintext pipeline",
    }


def summarize_csv(path: Path) -> dict[str, object]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"k", "grid_index", "trial_index", "exact_j_truth", "outcome", "predicted_error_probability"}
        if not required.issubset(set(reader.fieldnames or ())):
            raise ValueError("CSV is not a threshold FP/FN result")
        return summarize_rows(reader)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        summary = summarize_csv(args.csv)
        if args.format == "json":
            rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        else:
            rendered_lines = [
                f"schema_version={summary['schema_version']}",
                f"profile={summary['profile']}",
                f"rows={summary['rows']}",
            ]
            for k, values in summary["by_k"].items():
                rendered_lines.append(
                    f"k={k} points={values['points']} rows={values['rows']} "
                    f"FP={values['false_positive_rows']} FN={values['false_negative_rows']}"
                )
            rendered = "\n".join(rendered_lines) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, ValueError, KeyError) as exc:
        print(f"summarize_threshold_fpfn: FAIL: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
