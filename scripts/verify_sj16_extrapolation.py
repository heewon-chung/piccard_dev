#!/usr/bin/env python3
"""Verify measured/extrapolated SJ16 timing rows under the typed schema."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path


class VerificationError(ValueError):
    pass


REQUIRED = {
    "method", "measurement_kind", "trials", "total_ms", "total_ms_sd",
    "phase_encode_ms", "extrapolation_alpha", "extrapolation_source",
}


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def finite(row, column, number):
    try:
        value = float(row[column])
    except ValueError as error:
        raise VerificationError(f"row {number}: {column} must be finite") from error
    require(math.isfinite(value), f"row {number}: {column} must be finite")
    return value


def load(path: Path):
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            records = list(csv.reader(stream, strict=True))
    except (OSError, UnicodeError, csv.Error) as error:
        raise VerificationError(f"cannot parse CSV: {error}") from error
    require(records, "CSV is empty")
    header = records[0]
    require(len(set(header)) == len(header), "duplicate CSV columns")
    missing = REQUIRED - set(header)
    require(not missing, f"missing required columns: {', '.join(sorted(missing))}")
    rows = []
    for number, values in enumerate(records[1:], 2):
        require(len(values) == len(header), f"CSV column count mismatch on line {number}")
        rows.append(dict(zip(header, values)))
    return header, rows


def migrate(rows, header, legacy):
    sj16 = [dict(row) for row in rows if row["method"] == "sj16"]
    require(sj16, "no SJ16 rows")
    legacy_rows = [row for row in sj16 if row["measurement_kind"] in {"measured", "extrapolated"}]
    new_rows = [row for row in sj16 if row["measurement_kind"] == "ahe-timing"]
    require(not (legacy_rows and new_rows), "mixed legacy/new SJ16 semantics are forbidden")
    if legacy_rows:
        require(legacy, "legacy SJ16 schema requires --legacy-sj16-schema")
        require(len(legacy_rows) == len(sj16), "mixed legacy/new SJ16 semantics are forbidden")
        for row in sj16:
            row["measurement_status"] = row["measurement_kind"]
            row["measurement_kind"] = "ahe-timing"
        print("DEPRECATED: --legacy-sj16-schema migration mode", file=sys.stderr)
    else:
        require("measurement_status" in header, "new SJ16 schema requires measurement_status")
        require(not legacy, "--legacy-sj16-schema accepts only legacy rows, not new semantics")
    return sj16


def verify(rows):
    measured = []
    extrapolated = []
    for number, row in enumerate(rows, 2):
        require(row["measurement_kind"] == "ahe-timing",
                f"row {number}: measurement_kind must be ahe-timing")
        status = row.get("measurement_status", "")
        require(status in {"measured", "extrapolated"},
                f"row {number}: measurement_status must be measured or extrapolated")
        total = finite(row, "total_ms", number)
        require(total > 0, f"row {number}: total_ms must be positive")
        if status == "extrapolated":
            require(row["trials"] == "0", f"row {number}: extrapolated trials must be 0")
            require(finite(row, "total_ms_sd", number) == -1.0,
                    f"row {number}: extrapolated total_ms_sd sentinel must be -1")
            require(finite(row, "phase_encode_ms", number) == 0.0,
                    f"row {number}: extrapolated phase breakdown must be zero")
            require(bool(row["extrapolation_alpha"] and row["extrapolation_source"]),
                    f"row {number}: extrapolation provenance missing")
            finite(row, "extrapolation_alpha", number)
            extrapolated.append(row)
        else:
            require(row["trials"].isdigit() and int(row["trials"]) > 0,
                    f"row {number}: measured trials must be positive")
            require(row["extrapolation_alpha"] == "" and row["extrapolation_source"] == "",
                    f"row {number}: measured row carries extrapolation fields")
            if row["total_ms_sd"]:
                finite(row, "total_ms_sd", number)
            finite(row, "phase_encode_ms", number)
            measured.append(row)
    require(measured, "no measured SJ16 timing rows")
    require(extrapolated, "no extrapolated SJ16 timing rows")
    return len(measured), len(extrapolated)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path,
                        help="comparison_timing.csv or its containing directory")
    parser.add_argument("--legacy-sj16-schema", action="store_true")
    args = parser.parse_args(argv)
    path = args.path / "comparison_timing.csv" if args.path.is_dir() else args.path
    try:
        header, rows = load(path)
        sj16 = migrate(rows, header, args.legacy_sj16_schema)
        measured, extrapolated = verify(sj16)
    except VerificationError as error:
        print(f"verify_sj16_extrapolation: FAIL: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"verifier": "sj16-extrapolation", "verdict": "PASS",
                      "measured": measured, "extrapolated": extrapolated}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
