#!/usr/bin/env python3
"""Fail-closed validation for benchmark row taxonomy and live provenance."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Iterable


class VerificationError(ValueError):
    """A user-facing artifact validation failure."""


REQUIRED_COLUMNS = {
    "method", "profile_id", "run_class", "target_security_bits",
    "cryptographic_profile", "nominal_security_bits", "security_match",
    "comparison_eligible", "comparison_scope", "primitive",
    "protocol_model", "output_semantics", "assurance_scope",
    "security_basis", "cost_scope", "precomputation_mode",
    "secure_division_included", "measurement_kind", "evidence_arm",
    "estimator_model", "sanitizer_model", "sanitizer_assurance",
    "transcript_stat_bits", "max_queries", "query_stat_bits",
    "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
    "flood_noise_bits", "scaling_mod_size", "actual_ring_dim",
    "log_q_bits", "plaintext_modulus", "num_limbs", "openfhe_version",
    "measurement_status", "total_ms", "total_ms_sd", "total_ms_median",
    "jaccard_computed", "jaccard_expected", "jaccard_error",
}

INTEGER_COLUMNS = {
    "target_security_bits", "nominal_security_bits", "root_seed",
    "omp_threads", "k", "m", "set_size", "universe_size",
    "target_jaccard_numerator", "target_jaccard_denominator",
    "realized_intersection", "realized_union", "timing_trials",
    "accuracy_trials", "trials", "hash_seed", "transcript_stat_bits",
    "max_queries", "query_stat_bits", "coefficient_stat_bits",
    "flood_margin_bits", "eval_noise_bits", "flood_noise_bits",
    "scaling_mod_size", "actual_ring_dim", "plaintext_modulus", "num_limbs",
}
FLOAT_COLUMNS = {
    "target_jaccard", "realized_jaccard", "log_q_bits", "total_ms",
    "total_ms_sd", "total_ms_median", "jaccard_computed",
    "jaccard_expected", "jaccard_error", "phase_encode_ms",
    "phase_intersect_ms", "phase_aggregate_ms", "phase_decrypt_ms",
    "extrapolation_alpha",
}
BOOLEAN_COLUMNS = {
    "security_match", "comparison_eligible", "secure_division_included",
    "omp_dynamic",
}

PROFILES = {
    "std128-t40-primary": ("primary", 128, 40, True),
    "std192-t40-primary": ("primary", 192, 40, True),
    "std128-t64-sensitivity": ("sensitivity", 128, 64, False),
    "std192-t64-sensitivity": ("sensitivity", 192, 64, False),
    "std128-t128-feasibility": ("feasibility", 128, 128, False),
    "std192-t128-feasibility": ("feasibility", 192, 128, False),
    "toy-smoke": ("smoke", 0, 40, False),
}

SANITIZER_NUMERIC = (
    "transcript_stat_bits", "max_queries", "query_stat_bits",
    "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
    "flood_noise_bits", "scaling_mod_size",
)
FHE_NUMERIC = ("actual_ring_dim", "log_q_bits", "plaintext_modulus", "num_limbs")
MEASURED_REQUIRED_NUMERIC = (
    "total_ms", "total_ms_median", "jaccard_computed",
    "jaccard_expected", "jaccard_error",
)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UINT = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_csv(path: Path, required: Iterable[str] = REQUIRED_COLUMNS):
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            records = list(csv.reader(stream, strict=True))
    except (OSError, UnicodeError, csv.Error) as error:
        raise VerificationError(f"cannot parse CSV {path}: {error}") from error
    require(bool(records), "CSV is empty")
    header = records[0]
    require(bool(header) and all(header), "CSV header contains an empty column")
    require(len(set(header)) == len(header), "CSV header contains duplicate columns")
    missing = sorted(set(required) - set(header))
    require(not missing, f"missing required columns: {', '.join(missing)}")
    rows = []
    for line_number, values in enumerate(records[1:], 2):
        require(
            len(values) == len(header),
            f"CSV column count mismatch on line {line_number}: "
            f"got {len(values)}, expected {len(header)}",
        )
        rows.append(dict(zip(header, values)))
    require(bool(rows), "CSV has no data rows")
    return header, rows


def _parse_int(row: dict[str, str], column: str, row_number: int, *, positive=False):
    value = row.get(column, "")
    require(value != "", f"row {row_number}: {column} is required")
    require(UINT.fullmatch(value) is not None,
            f"row {row_number}: {column} must be a finite numeric integer")
    parsed = int(value)
    if positive:
        require(parsed > 0, f"row {row_number}: {column} must be positive")
    return parsed


def _finite(value: str, column: str, row_number: int) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise VerificationError(
            f"row {row_number}: {column} must be a finite numeric value"
        ) from error
    require(math.isfinite(parsed),
            f"row {row_number}: {column} must be a finite numeric value")
    return parsed


def _exact(row: dict[str, str], row_number: int, expected: dict[str, str]) -> None:
    for column, value in expected.items():
        require(row.get(column) == value,
                f"row {row_number}: {column}={row.get(column)!r}, expected {value!r}")


def _validate_numeric_cells(row: dict[str, str], row_number: int) -> None:
    for column in INTEGER_COLUMNS & row.keys():
        value = row[column]
        if value:
            require(UINT.fullmatch(value) is not None,
                    f"row {row_number}: {column} must be a finite numeric integer")
    for column in FLOAT_COLUMNS & row.keys():
        value = row[column]
        if value:
            _finite(value, column, row_number)
    for column in BOOLEAN_COLUMNS & row.keys():
        require(row[column] in {"true", "false"},
                f"row {row_number}: {column} must be true or false")


def validate_measured_metrics(row: dict[str, str], row_number: int) -> None:
    """Require the evidence-bearing numeric cells on every measured row."""
    if row.get("measurement_status") != "measured":
        return
    for column in MEASURED_REQUIRED_NUMERIC:
        value = row.get(column, "")
        require(value != "",
                f"row {row_number}: measured {column} is required")
        _finite(value, column, row_number)


def _validate_profile(row: dict[str, str], row_number: int):
    profile = row["profile_id"]
    require(profile in PROFILES, f"row {row_number}: unknown profile_id {profile!r}")
    run_class, target, transcript, profile_eligible = PROFILES[profile]
    _exact(row, row_number, {
        "run_class": run_class,
        "target_security_bits": str(target),
    })
    return target, transcript, profile_eligible


def _validate_models(row: dict[str, str], row_number: int, family: str) -> None:
    estimator = row["estimator_model"]
    sanitizer = row["sanitizer_model"]
    if family in {"piccard", "bcg12_mh"}:
        require(estimator == "sha256-random-ranking-poc-v1",
                f"row {row_number}: estimator_model is missing or invalid")
    else:
        require(estimator == "not-applicable",
                f"row {row_number}: estimator_model must be not-applicable")

    if family == "piccard":
        _exact(row, row_number, {
            "sanitizer_model": "phase-smudging-enc0-poc-v1",
            "sanitizer_assurance":
                "empirical-phase-statistical+ciphertext-computational",
        })
        for column in SANITIZER_NUMERIC:
            _parse_int(row, column, row_number, positive=True)
        transcript = int(row["transcript_stat_bits"])
        max_queries = int(row["max_queries"])
        ring_dim = int(row["actual_ring_dim"])
        require(max_queries & (max_queries - 1) == 0,
                f"row {row_number}: sanitizer max_queries must be a power of two")
        require(ring_dim & (ring_dim - 1) == 0,
                f"row {row_number}: actual FHE metadata ring dimension must be a power of two")
        query_bits = transcript + (max_queries.bit_length() - 1)
        coefficient_bits = query_bits + (ring_dim.bit_length() - 1)
        flood_bits = (int(row["eval_noise_bits"]) + coefficient_bits +
                      int(row["flood_margin_bits"]))
        require(int(row["query_stat_bits"]) == query_bits,
                f"row {row_number}: sanitizer query_stat_bits is inconsistent")
        require(int(row["coefficient_stat_bits"]) == coefficient_bits,
                f"row {row_number}: sanitizer coefficient_stat_bits is inconsistent")
        require(int(row["flood_noise_bits"]) == flood_bits,
                f"row {row_number}: sanitizer flood_noise_bits is inconsistent")
    else:
        require(sanitizer == "not-applicable",
                f"row {row_number}: sanitizer_model must be not-applicable")
        require(row["sanitizer_assurance"] == "not-applicable",
                f"row {row_number}: sanitizer_assurance must be not-applicable")
        for column in SANITIZER_NUMERIC:
            require(row[column] == "",
                    f"row {row_number}: baseline sanitizer field {column} must be empty")


def _validate_fhe(row: dict[str, str], row_number: int, live_fhe: bool) -> None:
    if live_fhe:
        for column in FHE_NUMERIC:
            value = row[column]
            require(value != "", f"row {row_number}: missing actual FHE metadata {column}")
            parsed = _finite(value, column, row_number)
            require(parsed > 0, f"row {row_number}: actual FHE metadata {column} must be positive")
        require(row["openfhe_version"] not in {"", "unknown", "not-applicable"},
                f"row {row_number}: missing actual FHE metadata openfhe_version")
    else:
        for column in FHE_NUMERIC:
            require(row[column] == "",
                    f"row {row_number}: non-FHE row has actual FHE metadata {column}")
        require(row["openfhe_version"] == "not-applicable",
                f"row {row_number}: non-FHE openfhe_version must be not-applicable")


def _validate_method(row: dict[str, str], row_number: int,
                     target: int, profile_eligible: bool) -> None:
    method = row["method"]
    arm = row["evidence_arm"]
    require(arm in {"timing", "accuracy"},
            f"row {row_number}: invalid evidence_arm {arm!r}")
    require(row["secure_division_included"] == "false",
            f"row {row_number}: secure_division_included must be false")

    if method in {"piccard", "piccard_sqrt"}:
        sqrt = method == "piccard_sqrt"
        _exact(row, row_number, {
            "cryptographic_profile": "live-BFV-TOY" if target == 0 else f"live-BFV-STD{target}",
            "nominal_security_bits": str(target),
            "security_match": "true",
            "comparison_eligible": "true" if profile_eligible else "false",
            "comparison_scope": "end-to-end-estimator",
            "primitive": "bfv-sqrt-minhash" if sqrt else "bfv-onehot-minhash",
            "protocol_model": "piccard-sqrt-two-owner-outsourced" if sqrt else "piccard-two-owner-outsourced",
            "output_semantics": "bias-corrected-jaccard-estimate",
            "assurance_scope": "live-bfv+empirical-sanitizer-poc",
            "security_basis": "openfhe-hesea-standard-live-context",
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
        })
        require(row["measurement_kind"] == f"fhe-{arm}",
                f"row {row_number}: invalid Piccard measurement_kind")
        _validate_fhe(row, row_number, True)
        _validate_models(row, row_number, "piccard")
        return

    if method in {"baseline", "fhe_ind"}:
        _exact(row, row_number, {
            "cryptographic_profile": "live-BFV-TOY" if target == 0 else f"live-BFV-STD{target}",
            "nominal_security_bits": str(target), "security_match": "true",
            "comparison_eligible": "false", "comparison_scope": "diagnostic-only",
            "primitive": "bfv-indicator-comparison",
            "protocol_model": "local-universe-sized-BFV-comparator",
            "output_semantics": "intersection-indicator-vector",
            "assurance_scope": "live-bfv-primitive-only",
            "security_basis": "openfhe-hesea-standard-live-context",
            "cost_scope": "primitive-only", "precomputation_mode": "not-applicable",
            "measurement_kind": "diagnostic",
        })
        _validate_models(row, row_number, "exact")
        _validate_fhe(row, row_number, True)
        return

    if method.startswith("bcg12_"):
        match = target == 128
        ff = method.endswith("_ff")
        exact = method.startswith("bcg12_exact_")
        require(method in {"bcg12_mh_ff", "bcg12_mh_ec", "bcg12_exact_ff", "bcg12_exact_ec"},
                f"row {row_number}: unknown BCG12 method {method!r}")
        _exact(row, row_number, {
            "cryptographic_profile": "FF-3072/256" if ff else "P-256",
            "nominal_security_bits": "128", "security_match": str(match).lower(),
            "comparison_eligible": str(match and profile_eligible).lower(),
            "comparison_scope": "matched-cardinality-component" if exact else "matched-estimator-component",
            "primitive": "bcg12-ff" if ff else "bcg12-ec",
            "protocol_model": "bcg12-exact-cardinality" if exact else "bcg12-cardinality-on-minhash",
            "output_semantics": "harness-reconstructed-exact-jaccard" if exact else "minhash-collision-jaccard-estimate",
            "assurance_scope": "implemented-baseline-parameter-map",
            "security_basis": "finite-field-dh-3072-subgroup-256-parameter-map" if ff else "nist-p256-parameter-map",
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
        })
        require(row["measurement_kind"] in {f"psi-{arm}", "diagnostic"},
                f"row {row_number}: BCG12 measurement_kind is invalid")
        _validate_models(row, row_number, "exact" if exact else "bcg12_mh")
        _validate_fhe(row, row_number, False)
        return

    if method in {"sj16", "sj16_precomputed"}:
        profile = row["cryptographic_profile"]
        ahe = {
            "Paillier-1024": ("80", "paillier-1024", "rsa-ifc-modulus-size-proxy-approximately-80-bits"),
            "Paillier-2048": ("112", "paillier-2048", "rsa-ifc-modulus-size-proxy-approximately-112-bits"),
            "Paillier-3072": ("128", "paillier-3072", "rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security"),
        }
        require(profile in ahe, f"row {row_number}: invalid AHE profile {profile!r}")
        nominal, primitive, basis = ahe[profile]
        match = profile == "Paillier-3072" and target == 128
        if target == 192 and (row["security_match"] == "true" or row["comparison_eligible"] == "true"):
            raise VerificationError(f"row {row_number}: no implemented AHE profile is an STD192 match")
        precomputed = method == "sj16_precomputed"
        _exact(row, row_number, {
            "nominal_security_bits": nominal, "primitive": primitive,
            "security_match": str(match).lower(),
            "comparison_eligible": str(match and profile_eligible and not precomputed).lower(),
            "comparison_scope": "component-lower-bound",
            "protocol_model": "sj16-intersection-shares",
            "output_semantics": "harness-reconstructed-jaccard-with-plaintext-union",
            "assurance_scope": "intersection-shares-lower-bound",
            "security_basis": basis,
            "cost_scope": "online-query-with-precomputed-randomizers" if precomputed else "full-query-excluding-one-time-setup",
            "precomputation_mode": "randomizers-precomputed" if precomputed else "randomizer-generation-included",
        })
        require(row["measurement_kind"] in ({"ahe-timing", "diagnostic"} if precomputed else {f"ahe-{arm}", "diagnostic"}),
                f"row {row_number}: AHE measurement_kind is invalid")
        _validate_models(row, row_number, "exact")
        _validate_fhe(row, row_number, False)
        return

    raise VerificationError(f"row {row_number}: unknown method {method!r}")


def validate_rows(rows: list[dict[str, str]]) -> None:
    for row_number, row in enumerate(rows, 2):
        _validate_numeric_cells(row, row_number)
        require(row["measurement_status"] in {"measured", "extrapolated", "infeasible", "skipped", "error"},
                f"row {row_number}: invalid measurement_status")
        validate_measured_metrics(row, row_number)
        target, transcript, profile_eligible = _validate_profile(row, row_number)
        _validate_method(row, row_number, target, profile_eligible)
        if row["method"] in {"piccard", "piccard_sqrt"}:
            require(int(row["transcript_stat_bits"]) == transcript,
                    f"row {row_number}: sanitizer profile transcript_stat_bits mismatch")
        for hash_column in ("workload_manifest_sha256", "execution_trace_sha256"):
            if hash_column in row and row[hash_column]:
                require(HEX64.fullmatch(row[hash_column]) is not None,
                        f"row {row_number}: {hash_column} is not lowercase SHA-256")


def resolve_manifest_csv(manifest_path: Path, cell_id: str) -> Path:
    """Resolve one checksum-bound CSV beneath the manifest's declared root."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read run manifest: {error}") from error
    require(manifest.get("schema") == "piccard-pre-threshold-run-v1",
            "invalid run manifest schema")
    root = manifest_path.resolve().parent
    directories = manifest.get("directories")
    require(isinstance(directories, dict) and directories.get("csv") == "csv",
            "run manifest CSV subroot is invalid")
    cells = manifest.get("cells")
    require(isinstance(cells, list), "run manifest cells are invalid")
    matches = [cell for cell in cells
               if isinstance(cell, dict) and cell.get("cell_id") == cell_id]
    require(len(matches) == 1, "run manifest cell_id is missing or duplicate")
    output = matches[0].get("output")
    require(isinstance(output, dict), "run manifest cell output is invalid")
    relative = output.get("csv")
    require(isinstance(relative, str) and relative != "" and
            not Path(relative).is_absolute(), "run manifest CSV path is invalid")
    path = (root / relative).resolve(strict=False)
    csv_root = (root / "csv").resolve()
    try:
        path.relative_to(csv_root)
    except ValueError as error:
        raise VerificationError("run manifest CSV path escapes declared subroot") from error
    require(path.is_file(), "run manifest CSV is missing")
    expected = output.get("csv_sha256")
    require(isinstance(expected, str) and HEX64.fullmatch(expected) is not None,
            "run manifest CSV checksum is invalid")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
            "run manifest CSV checksum mismatch")
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            row_count = len(list(csv.reader(stream, strict=True))) - 1
    except (OSError, UnicodeError, csv.Error) as error:
        raise VerificationError(f"cannot count manifest CSV rows: {error}") from error
    require(output.get("csv_row_count") == row_count,
            "run manifest CSV row count mismatch")
    require(output.get("expected_csv_rows") == row_count,
            "run manifest frozen expected row count mismatch")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", nargs="?", type=Path)
    parser.add_argument("--csv", dest="csv_option", type=Path)
    parser.add_argument("--run-manifest", type=Path)
    parser.add_argument("--cell-id")
    args = parser.parse_args(argv)
    try:
        explicit = args.csv_option or args.csv_path
        if args.run_manifest is not None:
            if explicit is not None:
                parser.error("--run-manifest cannot be combined with a CSV path")
            if not args.cell_id:
                parser.error("--run-manifest requires --cell-id")
            path = resolve_manifest_csv(args.run_manifest, args.cell_id)
        else:
            if args.cell_id is not None:
                parser.error("--cell-id requires --run-manifest")
            if explicit is None:
                parser.error("one CSV path is required")
            if args.csv_option is not None and args.csv_path is not None:
                parser.error("provide the CSV once, positionally or with --csv")
            path = explicit
        _, rows = load_csv(path)
        validate_rows(rows)
    except VerificationError as error:
        print(f"verify_benchmark_provenance: FAIL: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"verifier": "benchmark-provenance", "verdict": "PASS", "rows": len(rows)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
