#!/usr/bin/env python3
"""Accuracy-CSV summarizer for bench_real_datasets (Work 5, Sub-phase 5.5).

Reads a 5.3-produced plaintext-accuracy CSV (the 73-column RealAccuracyHeader:
the 46-column Work-4 prefix plus the accuracy-mode suffix), groups rows by
(dataset, variant) and then by the bucketed exact Jaccard's reporting bucket,
and writes one summary row per (dataset, variant, jaccard_bucket) -- always
all four buckets, even when a bucket has zero rows.

Bucket rule (byte-identical to piccard::data::JaccardBucketLabel, Sub-phase
5.1): [0, 0.1) -> b00_10, [0.1, 0.3) -> b10_30, [0.3, 0.6) -> b30_60,
[0.6, 1] -> b60_100. Statistics (mae/sample_sd/median/p95/max/ci95_low/
ci95_high) are byte-identical to piccard::data::Summarize: median is the
center value for odd n / mean of the two center values for even n; p95 is
nearest-rank sorted[ceil(0.95*n)-1]; sample_sd uses denominator n-1; the CI is
the unclipped normal interval mean +/- 1.96*sample_sd/sqrt(n). n == 0 leaves
every statistic cell empty; n == 1 leaves sample_sd/ci95_low/ci95_high empty
while mae/median/p95/max equal the sole value.

This module is stdlib-only, performs no network access, and never touches
`datasets/data/` -- it only reads/writes the paths its caller passes in.
Floats are formatted with the shared 17-significant-digit C-locale
convention via prepare_real_datasets.format_float() (imported, not
reimplemented, to avoid drift between the two scripts).

CLI: summarize_real_datasets.py --input=<accuracy.csv> --output=<summary.csv>
Both flags are mandatory with no default. The output is written atomically
(sibling temp file, fsync, atomic rename). Any malformed input (wrong
header, non-finite numeric cell, wrong column count) is a nonzero exit with
a stderr message; nothing is ever written to stdout.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
import tempfile
from pathlib import Path

# Both scripts live in scripts/; when this file is invoked as a top-level
# script (directly, or via `python3 scripts/summarize_real_datasets.py`),
# Python always sets sys.path[0] to this file's own resolved directory, so
# this import finds prepare_real_datasets.py regardless of the caller's
# working directory. Reusing format_float here (rather than reimplementing
# it) is the Sub-phase 5.5 contract: one 17-significant-digit formatter,
# never two copies that can drift apart.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
from prepare_real_datasets import format_float  # noqa: E402


class SummarizerError(ValueError):
    """Raised for header mismatch, malformed rows, or non-finite cells."""


# Pasted byte-for-byte from normative plan §Phase 5 (adjudication A1's
# 46-column Work-4 prefix plus the accuracy-mode suffix), independently of
# benchmarks/real_dataset_csv_schema.cpp so this validation is not
# tautologically re-derived from the C++ implementation it is checking.
_PREFIX_HEADER = (
    "profile_id,run_class,target_security_bits,cryptographic_profile,"
    "nominal_security_bits,security_match,comparison_eligible,"
    "comparison_scope,primitive,protocol_model,output_semantics,"
    "assurance_scope,security_basis,cost_scope,precomputation_mode,"
    "secure_division_included,measurement_kind,"
    "workload_id,workload_manifest_sha256,execution_trace_sha256,"
    "root_seed,omp_threads,"
    "estimator_model,sanitizer_model,sanitizer_assurance,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,"
    "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version,"
    "target_semantics,target_jaccard,realized_intersection,realized_union,"
    "realized_jaccard,timing_trials,accuracy_trials,omp_dynamic,"
    "measurement_status"
)
_ACCURACY_SUFFIX = (
    "dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,"
    "pair_id,pair_kind,label,record_a,record_b,"
    "k,m,hash_randomness,accuracy_trial_index,hash_seed,"
    "set_size_a_raw,set_size_b_raw,set_size_a_bucketed,set_size_b_bucketed,"
    "exact_jaccard_raw,exact_jaccard_bucketed,estimated_jaccard,"
    "bucket_match_fraction,abs_error,rel_error,jaccard_bucket,"
    "accuracy_workload_sha256"
)
ACCURACY_HEADER_FIELDS = tuple((_PREFIX_HEADER + "," + _ACCURACY_SUFFIX).split(","))

# Exact summary header, normative plan §Phase 5 "The exact summary header
# is:".
SUMMARY_HEADER_FIELDS = (
    "dataset", "variant", "jaccard_bucket", "n", "mae", "sample_sd",
    "median", "p95", "max", "ci95_low", "ci95_high",
)

# Fixed bucket order, normative plan §Phase 5 "Summaries group bucketed
# exact Jaccard into...": every (dataset, variant) group always emits all
# four buckets in this order.
_BUCKET_ORDER = ("b00_10", "b10_30", "b30_60", "b60_100")


def jaccard_bucket_label(bucketed_exact_jaccard: float) -> str:
    """Byte-identical bucket rule to piccard::data::JaccardBucketLabel
    (src/data/real_dataset_metrics.cpp): [0,.1) b00_10, [.1,.3) b10_30,
    [.3,.6) b30_60, [.6,1] b60_100 (the upper endpoint 1 belongs here)."""
    if bucketed_exact_jaccard < 0.1:
        return "b00_10"
    if bucketed_exact_jaccard < 0.3:
        return "b10_30"
    if bucketed_exact_jaccard < 0.6:
        return "b30_60"
    return "b60_100"


def summarize(abs_errors) -> dict:
    """Byte-identical statistics to piccard::data::Summarize
    (src/data/real_dataset_metrics.cpp) over `abs_errors` (already-finite
    absolute errors). Returns a dict with keys n/mae/sample_sd/median/p95/
    max/ci95_low/ci95_high; every key other than n is None exactly when the
    corresponding CSV cell must be left empty (n == 0 for every statistic;
    n == 1 additionally for sample_sd/ci95_low/ci95_high)."""
    ordered = sorted(abs_errors)
    n = len(ordered)
    if n == 0:
        return {"n": 0, "mae": None, "sample_sd": None, "median": None,
                "p95": None, "max": None, "ci95_low": None, "ci95_high": None}

    mean = sum(ordered) / n
    maximum = ordered[-1]

    mid = n // 2
    if n % 2 == 1:
        median = ordered[mid]
    else:
        median = (ordered[mid - 1] + ordered[mid]) / 2.0

    p95_index = math.ceil(0.95 * n) - 1
    p95 = ordered[p95_index]

    if n == 1:
        return {"n": 1, "mae": mean, "sample_sd": None, "median": median,
                "p95": p95, "max": maximum, "ci95_low": None, "ci95_high": None}

    squared_diff_sum = sum((v - mean) ** 2 for v in ordered)
    sample_sd = math.sqrt(squared_diff_sum / (n - 1))
    margin = 1.96 * sample_sd / math.sqrt(n)
    return {
        "n": n, "mae": mean, "sample_sd": sample_sd, "median": median,
        "p95": p95, "max": maximum,
        "ci95_low": mean - margin, "ci95_high": mean + margin,
    }


def _parse_finite_float(raw: str, *, field: str, row_number: int) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise SummarizerError(
            f"row {row_number}: field {field!r} is not a valid float: {raw!r}"
        ) from exc
    if not math.isfinite(value):
        raise SummarizerError(
            f"row {row_number}: field {field!r} must be finite, got {raw!r}"
        )
    return value


def read_accuracy_rows(input_path: Path):
    """Validates the exact RealAccuracyHeader() header (column set and
    order) and yields (dataset, variant, exact_jaccard_bucketed, abs_error)
    per data row, rejecting non-finite values in either numeric field and
    any row whose column count does not match the header."""
    with input_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise SummarizerError("input CSV is empty: missing header row") from exc
        if header != list(ACCURACY_HEADER_FIELDS):
            raise SummarizerError(
                "input CSV header does not match the expected RealAccuracyHeader "
                f"({len(ACCURACY_HEADER_FIELDS)} columns)"
            )
        expected_width = len(ACCURACY_HEADER_FIELDS)
        dataset_index = header.index("dataset")
        variant_index = header.index("variant")
        jaccard_index = header.index("exact_jaccard_bucketed")
        abs_error_index = header.index("abs_error")

        for row_number, row in enumerate(reader, start=2):
            if len(row) != expected_width:
                raise SummarizerError(
                    f"row {row_number}: expected {expected_width} columns, "
                    f"got {len(row)}"
                )
            dataset = row[dataset_index]
            variant = row[variant_index]
            exact_jaccard_bucketed = _parse_finite_float(
                row[jaccard_index], field="exact_jaccard_bucketed",
                row_number=row_number)
            abs_error = _parse_finite_float(
                row[abs_error_index], field="abs_error", row_number=row_number)
            yield dataset, variant, exact_jaccard_bucketed, abs_error


def build_summary_rows(input_path: Path):
    """Groups accuracy rows by (dataset, variant) in first-seen order, then
    by jaccard_bucket, and returns one formatted output row per (dataset,
    variant, bucket) with all four buckets always present per group."""
    groups: dict = {}
    group_order = []
    for dataset, variant, exact_jaccard_bucketed, abs_error in read_accuracy_rows(input_path):
        key = (dataset, variant)
        if key not in groups:
            groups[key] = {bucket: [] for bucket in _BUCKET_ORDER}
            group_order.append(key)
        bucket = jaccard_bucket_label(exact_jaccard_bucketed)
        groups[key][bucket].append(abs_error)

    output_rows = []
    for dataset, variant in group_order:
        for bucket in _BUCKET_ORDER:
            stats = summarize(groups[(dataset, variant)][bucket])
            output_rows.append(_format_summary_row(dataset, variant, bucket, stats))
    return output_rows


def _format_summary_row(dataset: str, variant: str, bucket: str, stats: dict):
    def cell(value):
        return "" if value is None else format_float(value)

    return [
        dataset, variant, bucket, str(stats["n"]),
        cell(stats["mae"]), cell(stats["sample_sd"]), cell(stats["median"]),
        cell(stats["p95"]), cell(stats["max"]),
        cell(stats["ci95_low"]), cell(stats["ci95_high"]),
    ]


def _write_atomic(output_path: Path, rows) -> None:
    """Writes the summary CSV to a sibling temp file, fsyncs it, and
    atomically renames it into place -- no partial output is ever visible
    at `output_path`."""
    parent = output_path.parent
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.tmp-", dir=str(parent))
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(SUMMARY_HEADER_FIELDS)
            for row in rows:
                writer.writerow(row)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, output_path)
    except BaseException:
        try:
            os.remove(tmp_name)
        except OSError:
            pass
        raise


def run(input_path: Path, output_path: Path) -> None:
    rows = build_summary_rows(input_path)
    _write_atomic(output_path, rows)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="summarize_real_datasets.py")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        run(Path(args.input), Path(args.output))
    except (SummarizerError, OSError) as exc:
        sys.stderr.write(f"summarize_real_datasets: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
