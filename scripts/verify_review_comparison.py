#!/usr/bin/env python3
"""Verify one reviewer CSV against its canonical workload and execution trace."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import struct
import sys
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from verify_benchmark_provenance import (
    REQUIRED_COLUMNS, VerificationError, load_csv, require, validate_rows,
    validate_measured_metrics, _parse_int, _finite,
)


WORKLOAD_DOMAIN = b"piccard-review-workload-v1\0"
TRACE_DOMAIN = b"piccard-review-execution-trace-v1\0"
TRIAL_DOMAIN = b"piccard-review-trial-v1\0"
SET_DOMAIN = b"piccard-review-set-v1\0"
HASH_DOMAINS = {
    0: b"piccard-review-hash-warmup-v1\0",
    1: b"piccard-review-hash-timing-v1\0",
    2: b"piccard-review-hash-accuracy-v1\0",
}
SUITES = {
    "primary-review": ("std128-t40-primary", [
        "piccard", "piccard_sqrt", "bcg12_mh_ff", "bcg12_mh_ec",
        "bcg12_exact_ff", "bcg12_exact_ec", "sj16"], 30, 50),
    "toy-smoke": ("toy-smoke", [
        "piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
        "bcg12_exact_ec", "sj16"], 1, 1),
    "sj16-precompute-sensitivity": ("std128-t64-sensitivity", [
        "sj16", "sj16_precomputed"], 3, 0),
    # Work #5 uses the same canonical workload/trace wire format, but has
    # one warmup, timing, and accuracy record per cell.  Keeping these entries
    # here lets its independent lifecycle verifier semantically parse the
    # producer bytes rather than merely checking their hashes.
    "work5-std128-piccard": ("work5-std128-t40-single-trial", ["piccard", "piccard_sqrt"], 1, 1),
    "work5-std128-piccard-m-extra": ("work5-std128-t40-single-trial", ["piccard"], 1, 1),
    "work5-std128-fhe-ind": ("work5-std128-t40-single-trial", ["fhe_ind"], 1, 1),
    "work5-std128-bcg12-mh": ("work5-std128-t40-single-trial", ["bcg12_mh_ec", "bcg12_mh_ff"], 1, 1),
    "work5-std128-bcg12-exact": ("work5-std128-t40-single-trial", ["bcg12_exact_ec", "bcg12_exact_ff"], 1, 1),
    "work5-std128-sj16": ("work5-std128-t40-single-trial", ["sj16"], 1, 1),
    "work5-std192-piccard": ("work5-std192-t40-single-trial", ["piccard", "piccard_sqrt"], 1, 1),
    "work5-std192-piccard-m-extra": ("work5-std192-t40-single-trial", ["piccard"], 1, 1),
    "work5-std192-fhe-ind": ("work5-std192-t40-single-trial", ["fhe_ind"], 1, 1),
    "work5-std192-sj16": ("work5-std192-t40-single-trial", ["sj16"], 1, 1),
}
REVIEW_REQUIRED_COLUMNS = REQUIRED_COLUMNS | {
    "suite", "scenario", "workload_id", "workload_manifest_sha256",
    "execution_trace_sha256", "root_seed", "omp_threads", "omp_dynamic",
    "k", "m", "set_size", "universe_size", "target_semantics",
    "target_jaccard_numerator", "target_jaccard_denominator",
    "target_jaccard", "realized_intersection", "realized_union",
    "realized_jaccard", "timing_trials", "accuracy_trials", "trials",
    "hash_randomness", "hash_seed",
}
REVIEW_DETAIL_COLUMNS = {
    "intersection_count", "phase_encode_ms", "phase_encrypt_ms",
    "phase_compute_ms", "phase_decrypt_ms", "ct_size_bytes", "comm_bytes",
}
TOY_REVIEW_COLUMNS = REVIEW_REQUIRED_COLUMNS | REVIEW_DETAIL_COLUMNS


class Reader:
    def __init__(self, data: bytes, label: str):
        self.data = data
        self.pos = 0
        self.label = label

    def take(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.data):
            raise VerificationError(f"truncated {self.label}")
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def domain(self, expected: bytes) -> None:
        require(self.take(len(expected)) == expected, f"{self.label} domain mismatch")

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def string(self) -> str:
        size = self.u32()
        try:
            value = self.take(size).decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError(f"invalid UTF-8 in {self.label}") from error
        require(value != "" and "\0" not in value, f"invalid string in {self.label}")
        return value

    def vector(self) -> list[int]:
        count = self.u64()
        require(count <= (len(self.data) - self.pos) // 8, f"invalid vector in {self.label}")
        return [self.u64() for _ in range(count)]

    def finish(self) -> None:
        require(self.pos == len(self.data), f"trailing {self.label} bytes")


@dataclass(frozen=True)
class Trial:
    kind: int
    index: int
    trial_seed: int
    hash_seed: int
    set_a: tuple[int, ...]
    set_b: tuple[int, ...]
    intersection: int
    union: int


@dataclass(frozen=True)
class Workload:
    suite: str
    profile: str
    root_seed: int
    k: int
    m: int
    set_size: int
    universe: int
    target: Fraction
    methods: tuple[str, ...]
    timing_trials: int
    accuracy_trials: int
    records: tuple[Trial, ...]
    digest: str

    @property
    def workload_id(self):
        return f"review-{self.universe}-{self.digest[:16]}"


def be32(value: int) -> bytes:
    return struct.pack(">I", value)


def be64(value: int) -> bytes:
    return struct.pack(">Q", value)


def first8(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "big")


def trial_seed(root_seed: int, kind: int, index: int) -> int:
    return first8(TRIAL_DOMAIN + be64(root_seed) + bytes([kind]) + be32(index))


def hash_seed(root_seed: int, kind: int, index: int) -> int:
    suffix = be32(index) if kind == 2 else b""
    return first8(HASH_DOMAINS[kind] + be64(root_seed) + suffix)


def realized_intersection(set_size: int, target: Fraction) -> int:
    value = Fraction(2 * set_size * target.numerator,
                     target.denominator + target.numerator)
    quotient, remainder = divmod(value.numerator, value.denominator)
    return quotient + (1 if 2 * remainder > value.denominator else 0)


def regenerate_sets(universe: int, size: int, intersection: int, seed: int):
    only = size - intersection
    require(intersection + 2 * only <= universe,
            "workload universe is insufficient for realized sets")
    ranked = sorted(
        range(universe),
        key=lambda value: (hashlib.sha256(SET_DOMAIN + be64(seed) + be64(value)).digest(), value),
    )
    shared = ranked[:intersection]
    set_a = tuple(sorted(shared + ranked[intersection:intersection + only]))
    set_b = tuple(sorted(shared + ranked[intersection + only:intersection + 2 * only]))
    return set_a, set_b


def parse_workload(path: Path) -> Workload:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read workload: {error}") from error
    reader = Reader(data, "workload")
    reader.domain(WORKLOAD_DOMAIN)
    suite = reader.string()
    profile = reader.string()
    root_seed = reader.u64()
    k, m, set_size, universe = (reader.u64() for _ in range(4))
    numerator, denominator = reader.u64(), reader.u64()
    require(denominator != 0, "workload target denominator is zero")
    target = Fraction(numerator, denominator)
    require(target.numerator == numerator and target.denominator == denominator and 0 <= target <= 1,
            "workload target rational is not canonical")
    method_count = reader.u32()
    methods = tuple(reader.string() for _ in range(method_count))
    timing_trials, accuracy_trials, record_count = reader.u32(), reader.u32(), reader.u32()
    records = []
    for _ in range(record_count):
        kind, index = reader.u8(), reader.u32()
        record = Trial(kind, index, reader.u64(), reader.u64(),
                       tuple(reader.vector()), tuple(reader.vector()),
                       reader.u64(), reader.u64())
        records.append(record)
    reader.finish()

    require(suite in SUITES, f"unknown frozen comparison suite {suite!r}")
    expected_profile, expected_methods, expected_timing, expected_accuracy = SUITES[suite]
    require(profile == expected_profile, "workload profile does not match frozen suite")
    require(list(methods) == expected_methods, "workload ordered method list does not match frozen suite")
    require(timing_trials == expected_timing and accuracy_trials == expected_accuracy,
            "workload trial counts do not match frozen suite")
    require(record_count == 1 + timing_trials + accuracy_trials,
            "workload record count does not match trial counts")
    require(k > 0 and m > 0 and universe > 0, "workload k/m/universe must be positive")

    expected_intersection = realized_intersection(set_size, target)
    expected_kinds = [(0, 0)] + [(1, i) for i in range(timing_trials)] + [(2, i) for i in range(accuracy_trials)]
    for position, (record, identity) in enumerate(zip(records, expected_kinds)):
        require((record.kind, record.index) == identity,
                f"workload record {position} kind/index is noncanonical")
        require(record.trial_seed == trial_seed(root_seed, record.kind, record.index),
                f"workload record {position} trial seed mismatch")
        require(record.hash_seed == hash_seed(root_seed, record.kind, record.index),
                f"workload record {position} hash seed mismatch")
        expected_a, expected_b = regenerate_sets(universe, set_size, expected_intersection, record.trial_seed)
        require(record.set_a == expected_a and record.set_b == expected_b,
                f"workload record {position} set bytes do not regenerate")
        expected_union = 2 * set_size - expected_intersection
        require(record.intersection == expected_intersection and record.union == expected_union,
                f"workload record {position} exact cardinalities mismatch")
    digest = hashlib.sha256(data).hexdigest()
    return Workload(suite, profile, root_seed, k, m, set_size, universe,
                    target, methods, timing_trials, accuracy_trials,
                    tuple(records), digest)


def execution_order(workload: Workload, trial: Trial):
    offset = trial.trial_seed % len(workload.methods)
    return workload.methods[offset:] + workload.methods[:offset]


def verify_trace(path: Path, workload: Workload) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read execution trace: {error}") from error
    reader = Reader(data, "execution trace")
    reader.domain(TRACE_DOMAIN)
    require(reader.take(32).hex() == workload.digest,
            "execution trace workload digest mismatch")
    expected_records, observed_records = reader.u32(), reader.u32()
    require(expected_records == len(workload.records) and observed_records == expected_records,
            "execution trace must contain every manifest record")
    for position, trial in enumerate(workload.records):
        kind, index = reader.u8(), reader.u32()
        expected_methods, dispatched, status = reader.u32(), reader.u32(), reader.u8()
        require((kind, index) == (trial.kind, trial.index),
                f"execution trace record {position} identity mismatch")
        require(expected_methods == len(workload.methods) and dispatched == expected_methods and status == 0,
                f"execution trace record {position} is incomplete or failed")
        actual = tuple(reader.string() for _ in range(dispatched))
        require(actual == execution_order(workload, trial),
                f"execution trace record {position} dispatch order mismatch")
    reader.finish()
    return hashlib.sha256(data).hexdigest()


def expected_kind(method: str, arm: str) -> str:
    if method in {"piccard", "piccard_sqrt"}:
        return f"fhe-{arm}"
    if method == "fhe_ind":
        return "diagnostic"
    if method.startswith("bcg12_"):
        return f"psi-{arm}"
    if method in {"sj16", "sj16_precomputed"}:
        return f"ahe-{arm}"
    raise VerificationError(f"unexpected method-kind method {method!r}")


def verify_rows(rows: list[dict[str, str]], workload: Workload, trace_digest: str):
    if workload.suite == "toy-smoke":
        require(set(rows[0]) == TOY_REVIEW_COLUMNS and len(rows[0]) == 73,
                "canonical toy reviewer CSV must use the 73-column schema"
                " including FHE-IND detail fields")
    expected_pairs = {(method, "timing") for method in workload.methods}
    if workload.accuracy_trials:
        expected_pairs |= {(method, "accuracy") for method in workload.methods}
    actual_pairs = []
    for row in rows:
        pair = (row["method"], row["evidence_arm"])
        require(row["method"] != "baseline",
                "unexpected method-kind: legacy baseline label is not accepted; use fhe_ind")
        if pair in actual_pairs:
            raise VerificationError(f"duplicate method-kind pair {pair}")
        actual_pairs.append(pair)
    unexpected = set(actual_pairs) - expected_pairs
    missing = expected_pairs - set(actual_pairs)
    require(not unexpected, f"unexpected method-kind pair(s): {sorted(unexpected)}")
    require(not missing, f"missing method-kind pair(s): {sorted(missing)}")

    first = workload.records[0]
    realized = Fraction(first.intersection, first.union) if first.union else Fraction(1, 1)
    threads = {row["omp_threads"] for row in rows}
    require(len(threads) == 1 and next(iter(threads)).isdigit() and int(next(iter(threads))) > 0,
            "omp_threads must match across the comparison group")
    for row_number, row in enumerate(rows, 2):
        method, arm = row["method"], row["evidence_arm"]
        validate_measured_metrics(row, row_number)
        checks = {
            "suite": workload.suite,
            "scenario": f"review-{workload.universe}",
            "profile_id": workload.profile,
            "workload_id": workload.workload_id,
            "workload_manifest_sha256": workload.digest,
            "execution_trace_sha256": trace_digest,
            "root_seed": str(workload.root_seed),
            "omp_dynamic": "false",
            "set_size": str(workload.set_size),
            "universe_size": str(workload.universe),
            "target_semantics": "jaccard",
            "target_jaccard_numerator": str(workload.target.numerator),
            "target_jaccard_denominator": str(workload.target.denominator),
            "timing_trials": str(workload.timing_trials),
            "accuracy_trials": str(workload.accuracy_trials),
            "measurement_kind": expected_kind(method, arm),
            "measurement_status": "measured",
            "realized_intersection": str(first.intersection),
            "realized_union": str(first.union),
        }
        for column, expected in checks.items():
            require(row.get(column) == expected,
                    f"row {row_number}: {column} mismatch ({row.get(column)!r} != {expected!r})")
        aggregate_trials = str(
            workload.timing_trials if arm == "timing" else workload.accuracy_trials)
        require(row["trials"] == aggregate_trials,
                f"row {row_number}: aggregate trial count mismatch "
                f"({row['trials']!r} != {aggregate_trials!r})")
        for column, expected in (("target_jaccard", workload.target), ("realized_jaccard", realized)):
            try:
                actual = float(row[column])
            except ValueError as error:
                raise VerificationError(f"row {row_number}: {column} is invalid") from error
            require(math.isfinite(actual) and math.isclose(
                actual, float(expected), rel_tol=0.0, abs_tol=5e-12),
                f"row {row_number}: {column} mismatch")

        piccard = method in {"piccard", "piccard_sqrt"}
        minhash = method in {"bcg12_mh_ff", "bcg12_mh_ec"}
        expected_k = str(workload.k) if piccard or minhash else ""
        expected_m = str(workload.m) if piccard else ""
        require(row["k"] == expected_k, f"row {row_number}: k mismatch")
        require(row["m"] == expected_m, f"row {row_number}: m mismatch")
        if piccard or minhash:
            require(row["hash_randomness"] == ("fixed" if arm == "timing" else "resampled"),
                    f"row {row_number}: hash randomness mismatch")
            expected_hash = str(workload.records[1].hash_seed) if arm == "timing" else ""
            require(row["hash_seed"] == expected_hash, f"row {row_number}: hash seed mismatch")
        else:
            require(row["hash_randomness"] == "not-applicable" and row["hash_seed"] == "",
                    f"row {row_number}: exact method has fabricated hash parameters")
        if method.startswith("bcg12_exact_") or method.startswith("sj16"):
            require(math.isfinite(float(row["jaccard_error"])) and
                    float(row["jaccard_error"]) == 0.0,
                    f"row {row_number}: exact method reported nonzero estimator error")
            require(math.isclose(float(row["jaccard_computed"]), float(realized),
                                 rel_tol=0.0, abs_tol=5e-6),
                    f"row {row_number}: exact method result is not workload-bound")
        require(math.isclose(float(row["jaccard_expected"]), float(realized),
                             rel_tol=0.0, abs_tol=5e-6),
                f"row {row_number}: expected Jaccard is not workload-bound")

        if method == "fhe_ind":
            observed = _parse_int(row, "intersection_count", row_number)
            require(observed == first.intersection,
                    f"row {row_number}: FHE-IND intersection is not workload-bound")
            computed = _finite(row["jaccard_computed"], "jaccard_computed", row_number)
            expected = _finite(row["jaccard_expected"], "jaccard_expected", row_number)
            error = _finite(row["jaccard_error"], "jaccard_error", row_number)
            require(math.isclose(computed, float(realized), rel_tol=0.0, abs_tol=5e-6),
                    f"row {row_number}: FHE-IND computed Jaccard is not workload-bound")
            require(math.isclose(expected, float(realized), rel_tol=0.0, abs_tol=5e-6),
                    f"row {row_number}: FHE-IND expected Jaccard is not workload-bound")
            require(error == 0.0,
                    f"row {row_number}: FHE-IND reported nonzero Jaccard error")
            phases = [
                _finite(row[column], column, row_number)
                for column in ("phase_encode_ms", "phase_encrypt_ms",
                               "phase_compute_ms", "phase_decrypt_ms")
            ]
            require(all(value >= 0.0 for value in phases),
                    f"row {row_number}: FHE-IND phases must be nonnegative")
            require(math.isclose(sum(phases), float(row["total_ms"]),
                                 rel_tol=0.0, abs_tol=5e-5),
                    f"row {row_number}: FHE-IND phase total mismatch")
            _parse_int(row, "ct_size_bytes", row_number, positive=True)
            _parse_int(row, "comm_bytes", row_number, positive=True)
        else:
            require(all(row[column] == "" for column in REVIEW_DETAIL_COLUMNS),
                    f"row {row_number}: non-FHE row fabricates FHE detail fields")

        if workload.suite == "primary-review":
            require(row["security_match"] == "true" and row["comparison_eligible"] == "true",
                    f"row {row_number}: strict unmatched security is forbidden")
        else:
            require(row["comparison_eligible"] == "false",
                    f"row {row_number}: diagnostic suite cannot be comparison eligible")


def resolve_manifest_artifacts(manifest_path: Path, cell_id: str):
    """Resolve checksum-bound review artifacts under declared manifest subroots."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read run manifest: {error}") from error
    require(manifest.get("schema") == "piccard-pre-threshold-run-v1",
            "invalid run manifest schema")
    root = manifest_path.resolve().parent
    directories = manifest.get("directories")
    require(isinstance(directories, dict), "run manifest directories are invalid")
    expected_roots = {"csv": "csv", "workload": "workloads", "trace": "traces"}
    require(all(directories.get(subroot) == subroot
                for subroot in expected_roots.values()),
            "run manifest review subroots are invalid")
    cells = manifest.get("cells")
    require(isinstance(cells, list), "run manifest cells are invalid")
    matches = [cell for cell in cells
               if isinstance(cell, dict) and cell.get("cell_id") == cell_id]
    require(len(matches) == 1, "run manifest cell_id is missing or duplicate")
    require(matches[0].get("producer") == "bench_review_comparison",
            "run manifest cell is not a review producer")
    output = matches[0].get("output")
    require(isinstance(output, dict), "run manifest cell output is invalid")
    resolved = {}
    for key, subroot in expected_roots.items():
        relative = output.get(key)
        require(isinstance(relative, str) and relative != "" and
                not Path(relative).is_absolute(),
                f"run manifest {key} path is invalid")
        path = (root / relative).resolve(strict=False)
        declared = (root / subroot).resolve()
        try:
            path.relative_to(declared)
        except ValueError as error:
            raise VerificationError(
                f"run manifest {key} path escapes declared subroot") from error
        require(path.is_file(), f"run manifest {key} is missing")
        expected = output.get(f"{key}_sha256")
        require(isinstance(expected, str) and len(expected) == 64 and
                all(character in "0123456789abcdef" for character in expected),
                f"run manifest {key} checksum is invalid")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                f"run manifest {key} checksum mismatch")
        resolved[key] = path
    try:
        with resolved["csv"].open(newline="", encoding="utf-8") as stream:
            row_count = len(list(csv.reader(stream, strict=True))) - 1
    except (OSError, UnicodeError, csv.Error) as error:
        raise VerificationError(f"cannot count manifest CSV rows: {error}") from error
    require(output.get("csv_row_count") == row_count,
            "run manifest CSV row count mismatch")
    require(output.get("expected_csv_rows") == row_count,
            "run manifest frozen expected row count mismatch")
    return resolved["csv"], resolved["workload"], resolved["trace"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--workload", type=Path)
    parser.add_argument("--execution-trace", "--trace", dest="trace", type=Path)
    parser.add_argument("--run-manifest", type=Path)
    parser.add_argument("--cell-id")
    args = parser.parse_args(argv)
    try:
        explicit = (args.csv, args.workload, args.trace)
        if args.run_manifest is not None:
            if any(value is not None for value in explicit):
                parser.error("--run-manifest cannot be combined with explicit artifacts")
            if not args.cell_id:
                parser.error("--run-manifest requires --cell-id")
            csv_path, workload_path, trace_path = resolve_manifest_artifacts(
                args.run_manifest, args.cell_id)
        else:
            if args.cell_id is not None:
                parser.error("--cell-id requires --run-manifest")
            if any(value is None for value in explicit):
                parser.error("--csv, --workload, and --execution-trace are required")
            csv_path, workload_path, trace_path = explicit
        _, rows = load_csv(csv_path, REVIEW_REQUIRED_COLUMNS)
        workload = parse_workload(workload_path)
        trace_digest = verify_trace(trace_path, workload)
        verify_rows(rows, workload, trace_digest)
        validate_rows(rows)
    except (VerificationError, OSError, ValueError, OverflowError) as error:
        print(f"verify_review_comparison: FAIL: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"verifier": "review-comparison", "verdict": "PASS", "suite": workload.suite,
                      "workload_id": workload.workload_id, "rows": len(rows)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
