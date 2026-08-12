#!/usr/bin/env python3
"""Fail-closed verifier for the synthetic threshold FP/FN CSV family.

The verifier deliberately reconstructs the fixed grid, canonical sets, row
seed, MinHash signatures, exact binomial tail, and Gaussian overlay itself. It
does not import the C++ producer or trust producer-computed truth fields.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
from pathlib import Path
import sys
from typing import Iterable, Mapping, Sequence


SCHEMA_VERSION = "piccard-threshold-fpfn-v1"
ESTIMATOR_MODEL = "sha256-random-ranking-poc-v1"
SUPPORTED_K = (64, 128, 256, 512)
GRID_INDICES = tuple(range(-10, 11))
M = 64
SET_SIZE = 1000
TAU_COUNTS = {64: 38, 128: 76, 256: 153, 512: 307}
SEED_DOMAIN = b"piccard-threshold-fpfn-seed-v1"
MINHASH_DOMAIN = b"piccard-minhash-poc-v1"
REQUIRED_COLUMNS = (
    "schema_version",
    "profile",
    "security",
    "estimator_model",
    "hash_randomness",
    "root_seed",
    "k",
    "m",
    "set_size",
    "tau_count",
    "j_tau",
    "grid_index",
    "target_j",
    "signed_delta",
    "absolute_delta",
    "alpha",
    "realized_intersection",
    "realized_union",
    "realized_j",
    "trial_index",
    "row_seed",
    "match_count",
    "decision",
    "exact_j_truth",
    "outcome",
    "predicted_decision_probability",
    "predicted_error_probability",
    "gaussian_error_approx",
)


class VerificationError(ValueError):
    """Raised for any malformed or scientifically inconsistent output."""


def tau_count(k: int) -> int:
    try:
        return TAU_COUNTS[k]
    except KeyError as exc:
        raise VerificationError(f"unsupported k: {k}") from exc


def jaccard_threshold(k: int) -> float:
    tau = tau_count(k)
    return (tau / float(k) - 1.0 / M) / (1.0 - 1.0 / M)


def _point(k: int, grid_index: int) -> dict[str, float | int]:
    if k not in SUPPORTED_K:
        raise VerificationError(f"unsupported k: {k}")
    if grid_index not in GRID_INDICES:
        raise VerificationError(f"grid index out of range: {grid_index}")
    j_tau = jaccard_threshold(k)
    target_j = min(1.0, max(0.0, j_tau + 0.01 * float(grid_index)))
    signed_delta = target_j - j_tau
    alpha = 2.0 * target_j / (1.0 + target_j)
    intersection = math.floor(float(SET_SIZE) * alpha)
    union = 2 * SET_SIZE - intersection
    realized_j = intersection / float(union)
    return {
        "k": k,
        "m": M,
        "set_size": SET_SIZE,
        "tau_count": tau_count(k),
        "grid_index": grid_index,
        "j_tau": j_tau,
        "target_j": target_j,
        "signed_delta": signed_delta,
        "absolute_delta": abs(signed_delta),
        "alpha": alpha,
        "realized_intersection": intersection,
        "realized_union": union,
        "realized_j": realized_j,
    }


def row_seed(root_seed: int, k: int, grid_index: int, trial_index: int) -> int:
    if root_seed <= 0 or root_seed > (1 << 64) - 1:
        raise VerificationError("root seed must be a positive uint64")
    if k not in SUPPORTED_K or grid_index not in GRID_INDICES or trial_index < 0:
        raise VerificationError("invalid row-seed coordinates")
    payload = (
        SEED_DOMAIN
        + b"\x00"
        + root_seed.to_bytes(8, "big", signed=False)
        + k.to_bytes(4, "big", signed=False)
        + (grid_index + 10).to_bytes(4, "big", signed=False)
        + trial_index.to_bytes(8, "big", signed=False)
    )
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _binomial_survival(k: int, threshold: int, p: float) -> float:
    if k <= 0 or threshold < 0 or threshold > k or not math.isfinite(p):
        raise VerificationError("invalid binomial arguments")
    if p < 0.0 or p > 1.0:
        raise VerificationError("binomial p outside [0,1]")
    if p == 0.0:
        return 1.0 if threshold == 0 else 0.0
    if p == 1.0:
        return 1.0
    one_minus_p = 1.0 - p
    pmf = one_minus_p**k
    result = 0.0
    for x in range(k + 1):
        if x >= threshold:
            result += pmf
        if x == k:
            break
        pmf *= ((k - x) / float(x + 1)) * (p / one_minus_p)
    return min(1.0, max(0.0, result))


def binomial_decision_probability(k: int, threshold: int, p: float) -> float:
    """Public KAT helper; uses the exact ascending survival recurrence."""
    return _binomial_survival(k, threshold, p)


def gaussian_error_approx(realized_j: float, k: int, m: int = M) -> float:
    if k not in SUPPORTED_K or m != M or not (0.0 <= realized_j <= 1.0):
        raise VerificationError("invalid Gaussian arguments")
    p_j = realized_j + (1.0 - realized_j) / float(m)
    p_tau = tau_count(k) / float(k)
    z = math.sqrt(float(k)) * abs(p_j - p_tau) / math.sqrt(p_tau * (1.0 - p_tau))
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def _minhash_signature(elements: Sequence[int], k: int, seed: int) -> list[int]:
    """Recompute SHA-256 random-ranking MinHash exactly as the C++ producer."""
    if not elements:
        raise VerificationError("canonical set must not be empty")
    signature = [(1 << 64) - 1] * k
    element_bytes = [int(element).to_bytes(8, "big", signed=False) for element in elements]
    seed_bytes = seed.to_bytes(8, "big", signed=False)
    for coordinate in range(k):
        prefix = MINHASH_DOMAIN + seed_bytes + coordinate.to_bytes(4, "big")
        minimum = (1 << 64) - 1
        for encoded in element_bytes:
            rank = int.from_bytes(hashlib.sha256(prefix + encoded).digest()[:8], "big")
            if rank < minimum:
                minimum = rank
        signature[coordinate] = minimum
    return signature


def _canonical_match_count(point: Mapping[str, float | int], seed: int) -> int:
    intersection = int(point["realized_intersection"])
    a = range(SET_SIZE)
    b = list(range(intersection)) + list(
        range(SET_SIZE, SET_SIZE + SET_SIZE - intersection)
    )
    sig_a = _minhash_signature(list(a), int(point["k"]), seed)
    sig_b = _minhash_signature(b, int(point["k"]), seed)
    return sum((left % M) == (right % M) for left, right in zip(sig_a, sig_b))


def _int(row: Mapping[str, str], field: str) -> int:
    value = row.get(field, "")
    if value == "":
        raise VerificationError(f"missing {field}")
    try:
        return int(value, 10)
    except ValueError as exc:
        raise VerificationError(f"invalid integer {field}: {value!r}") from exc


def _float(row: Mapping[str, str], field: str) -> float:
    value = row.get(field, "")
    if value == "":
        raise VerificationError(f"missing {field}")
    try:
        result = float(value)
    except ValueError as exc:
        raise VerificationError(f"invalid float {field}: {value!r}") from exc
    if not math.isfinite(result):
        raise VerificationError(f"non-finite float {field}")
    return result


def _expect_float(actual: float, expected: float, field: str) -> None:
    if not math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-12):
        raise VerificationError(
            f"{field} mismatch: got {actual:.17g}, expected {expected:.17g}"
        )


def _validate_row(row: Mapping[str, str], mode: str, root_seed: int) -> tuple[int, int, int]:
    profile = "readiness-toy-v1" if mode == "toy" else "paper-v1"
    if row.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError("schema_version mismatch")
    if row.get("profile") != profile:
        raise VerificationError("profile mismatch")
    if row.get("estimator_model") != ESTIMATOR_MODEL:
        raise VerificationError("estimator_model mismatch")
    if row.get("hash_randomness") != "resampled":
        raise VerificationError("hash_randomness must be resampled")
    if row.get("security") not in {"TOY", "STD128", "STD192", "STD256"}:
        raise VerificationError("invalid security metadata")

    if _int(row, "root_seed") != root_seed:
        raise VerificationError("root_seed mismatch")
    k = _int(row, "k")
    grid_index = _int(row, "grid_index")
    trial_index = _int(row, "trial_index")
    if trial_index < 0:
        raise VerificationError("negative trial_index")
    point = _point(k, grid_index)
    for field in ("m", "set_size", "tau_count", "realized_intersection", "realized_union"):
        if _int(row, field) != int(point[field]):
            raise VerificationError(f"{field} mismatch")
    if _int(row, "decision") not in (0, 1):
        raise VerificationError("decision must be 0 or 1")
    if _int(row, "exact_j_truth") not in (0, 1):
        raise VerificationError("exact_j_truth must be 0 or 1")

    for field in (
        "j_tau",
        "target_j",
        "signed_delta",
        "absolute_delta",
        "alpha",
        "realized_j",
    ):
        _expect_float(_float(row, field), float(point[field]), field)

    expected_seed = row_seed(root_seed, k, grid_index, trial_index)
    if _int(row, "row_seed") != expected_seed:
        raise VerificationError("row_seed mismatch")
    expected_match_count = _canonical_match_count(point, expected_seed)
    if _int(row, "match_count") != expected_match_count:
        raise VerificationError("match_count mismatch")
    expected_decision = int(expected_match_count >= int(point["tau_count"]))
    if _int(row, "decision") != expected_decision:
        raise VerificationError("inclusive threshold decision mismatch")
    expected_truth = int(float(point["realized_j"]) >= float(point["j_tau"]))
    if _int(row, "exact_j_truth") != expected_truth:
        raise VerificationError("exact-J truth mismatch")
    outcome = row.get("outcome")
    expected_outcome = (
        "TP" if expected_truth and expected_decision else
        "FN" if expected_truth else
        "FP" if expected_decision else
        "TN"
    )
    if outcome != expected_outcome:
        raise VerificationError("outcome mismatch")

    p = float(point["realized_j"]) + (
        1.0 - float(point["realized_j"])
    ) / M
    expected_probability = _binomial_survival(k, int(point["tau_count"]), p)
    expected_error = (
        1.0 - expected_probability if expected_truth else expected_probability
    )
    _expect_float(
        _float(row, "predicted_decision_probability"),
        expected_probability,
        "predicted_decision_probability",
    )
    _expect_float(
        _float(row, "predicted_error_probability"),
        expected_error,
        "predicted_error_probability",
    )
    _expect_float(
        _float(row, "gaussian_error_approx"),
        gaussian_error_approx(float(point["realized_j"]), k),
        "gaussian_error_approx",
    )
    return k, grid_index, trial_index


def verify_rows(rows: Iterable[Mapping[str, str]], mode: str, root_seed: int, trials: int) -> int:
    if mode not in {"toy", "paper"}:
        raise VerificationError("mode must be toy or paper")
    if root_seed <= 0 or root_seed > (1 << 64) - 1:
        raise VerificationError("seed must be positive")
    if trials <= 0 or (mode == "toy" and trials != 1) or (mode == "paper" and trials < 1000):
        raise VerificationError("invalid trial count for selected mode")
    rows = list(rows)
    if not rows:
        raise VerificationError("CSV contains no rows")
    expected_keys = [
        (k, grid_index, trial_index)
        for k in SUPPORTED_K
        for grid_index in GRID_INDICES
        for trial_index in range(trials)
    ]
    actual_keys = []
    seen = set()
    for row in rows:
        key = _validate_row(row, mode, root_seed)
        if key in seen:
            raise VerificationError(f"duplicate row: {key}")
        seen.add(key)
        actual_keys.append(key)
    if len(rows) != len(expected_keys):
        raise VerificationError(
            f"row count mismatch: got {len(rows)}, expected {len(expected_keys)}"
        )
    if set(actual_keys) != set(expected_keys):
        missing = sorted(set(expected_keys) - set(actual_keys))
        extra = sorted(set(actual_keys) - set(expected_keys))
        raise VerificationError(f"grid coverage mismatch: missing={missing[:3]} extra={extra[:3]}")
    if actual_keys != expected_keys:
        raise VerificationError("rows are not in canonical k/grid/trial order")
    return len(rows)


def verify_csv(path: Path, mode: str, root_seed: int, trials: int) -> int:
    if not path.is_file():
        raise VerificationError(f"CSV does not exist: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != REQUIRED_COLUMNS:
            raise VerificationError("CSV header does not match the versioned schema")
        return verify_rows(reader, mode, root_seed, trials)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("toy", "paper"), required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--trials", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        count = verify_csv(args.csv, args.mode, args.seed, args.trials)
    except (OSError, OverflowError, VerificationError) as exc:
        print(f"verify_threshold_outputs: FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"verify_threshold_outputs: PASS ({count} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
