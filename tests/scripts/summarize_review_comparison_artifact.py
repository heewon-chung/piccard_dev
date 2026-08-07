#!/usr/bin/env python3
"""Validate and summarize one persisted Phase-4 TOY producer result."""

import argparse
import csv
import hashlib
from pathlib import Path


EXPECTED_ROWS = [
    ("piccard", "fhe-timing", "timing", "16", "16", "fixed", "15329580584519071531"),
    ("piccard", "fhe-accuracy", "accuracy", "16", "16", "resampled", ""),
    ("piccard_sqrt", "fhe-timing", "timing", "16", "16", "fixed", "15329580584519071531"),
    ("piccard_sqrt", "fhe-accuracy", "accuracy", "16", "16", "resampled", ""),
    ("bcg12_mh_ec", "psi-timing", "timing", "16", "", "fixed", "15329580584519071531"),
    ("bcg12_mh_ec", "psi-accuracy", "accuracy", "16", "", "resampled", ""),
    ("bcg12_exact_ec", "psi-timing", "timing", "", "", "not-applicable", ""),
    ("bcg12_exact_ec", "psi-accuracy", "accuracy", "", "", "not-applicable", ""),
    ("sj16", "ahe-timing", "timing", "", "", "not-applicable", ""),
    ("sj16", "ahe-accuracy", "accuracy", "", "", "not-applicable", ""),
]
EXPECTED_WORKLOAD_SHA256 = (
    "669d54d779bc31e46a57b92c0e46153b657f1c039158c46987c7cf2f9ad3ccaa"
)
EXPECTED_TRACE_SHA256 = (
    "a15f85b1b64255c7a317daeea589c1626b76faa6787e8901e5c2bf0643f4f0ec"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"artifact check failed: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--stderr", type=Path, required=True)
    parser.add_argument("--shape-output", type=Path)
    parser.add_argument("--hash-output", type=Path)
    args = parser.parse_args()

    with args.csv.open(newline="") as stream:
        rows = list(csv.reader(stream))
    require(rows, "CSV is empty")
    header = rows[0]
    require(len(header) == 66, f"CSV header has {len(header)} columns, expected 66")
    data = rows[1:]
    require(len(data) == 10, f"CSV has {len(data)} data rows, expected 10")
    columns = {name: index for index, name in enumerate(header)}
    required_columns = {
        "method",
        "measurement_kind",
        "evidence_arm",
        "comparison_eligible",
        "workload_id",
        "workload_manifest_sha256",
        "execution_trace_sha256",
        "k",
        "m",
        "hash_randomness",
        "hash_seed",
        "total_ms_sd",
        "measurement_status",
    }
    require(required_columns <= columns.keys(), "required CSV column is missing")

    for index, row in enumerate(data):
        require(len(row) == len(header), f"row {index} has {len(row)} columns")
        expected = EXPECTED_ROWS[index]
        for name, value in zip(
            ("method", "measurement_kind", "evidence_arm", "k", "m", "hash_randomness", "hash_seed"),
            expected,
        ):
            require(row[columns[name]] == value, f"row {index} {name} mismatch")
        require(row[columns["comparison_eligible"]] == "false", f"row {index} eligibility")
        require(row[columns["workload_id"]] == "review-64-669d54d779bc31e4", f"row {index} workload id")
        require(row[columns["workload_manifest_sha256"]] == EXPECTED_WORKLOAD_SHA256, f"row {index} workload hash")
        require(row[columns["execution_trace_sha256"]] == EXPECTED_TRACE_SHA256, f"row {index} trace hash")
        require(row[columns["measurement_status"]] == "measured", f"row {index} status")
        sd = row[columns["total_ms_sd"]]
        require(sd == "", f"row {index} one-trial SD is not empty")

    workload_hash = sha256(args.workload)
    trace_hash = sha256(args.trace)
    require(workload_hash == EXPECTED_WORKLOAD_SHA256, "workload artifact hash")
    require(trace_hash == EXPECTED_TRACE_SHA256, "trace artifact hash")
    stderr_bytes = args.stderr.read_bytes()
    require(stderr_bytes == b"", "producer stderr is not empty")

    shape_lines = [
        f"csv_rows_including_header={len(rows)}",
        f"csv_data_rows={len(data)}",
        f"csv_columns={len(header)}",
        "row_shape_check=PASS",
    ]
    hash_lines = [
        f"csv_sha256={sha256(args.csv)}",
        f"workload_bytes={args.workload.stat().st_size}",
        f"workload_sha256={workload_hash}",
        f"trace_bytes={args.trace.stat().st_size}",
        f"trace_sha256={trace_hash}",
        f"stderr_bytes={len(stderr_bytes)}",
        f"stderr_sha256={sha256(args.stderr)}",
    ]
    if args.shape_output:
        args.shape_output.write_text("\n".join(shape_lines) + "\n")
    if args.hash_output:
        args.hash_output.write_text("\n".join(hash_lines) + "\n")

    print("review_toy_artifact_check=PASS")
    for line in shape_lines + hash_lines:
        print(line)
    print("method_applicability_check=PASS")
    print("one_trial_sd_empty_check=PASS")
    print("stderr_empty_check=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
