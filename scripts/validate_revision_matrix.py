#!/usr/bin/env python3
"""Fail-closed validator for ``benchmarks/revision_matrix.json``.

The JSON document is the sole canonical matrix.  This module intentionally
contains only schema/inventory rules (not a second producer matrix); expected
IDs are derived from the frozen grammar and axes so omitted or duplicated
cells cannot pass silently.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
from collections import Counter
from typing import Any


FAMILY_COUNTS = {
    "piccard_std128": 20,
    "piccard_std192_encoding": 20,
    "fhe_ind": 9,
    "bcg12_minhash": 11,
    "bcg12_exact": 5,
    "sj16": 11,
    "estimator_accuracy": 17,
    "sqrt_comparison": 20,
    "flooding": 3,
    "dynamic_timing": 16,
    "dynamic_accuracy": 16,
    "dynamic_refresh": 1,
    "deletion_exact": 1,
    "deletion_mc": 1,
    "threshold_timing": 5,
    "threshold_spec": 5,
    "threshold_agreement": 5,
    "threshold_synthetic_fpfn": 84,
    "threshold_dblp_fpfn": 1,
    "real_dataset": 12,
}
K_VALUES = ("16", "32", "64", "128", "256", "512")
M_VALUES = ("16", "32", "64", "128", "256")
N_VALUES = ("100", "1000", "10000", "100000")
U_VALUES = ("16384", "65536", "262144", "1048576")
SQRT_M = {"16", "64", "256"}
ID_RE = re.compile(r"^paper-v1::[a-z0-9_]+::[a-z0-9_]+=[A-Za-z0-9_.-]+$")
STATUSES = {"MEASURED", "DIAGNOSTIC", "EXTRAPOLATED", "NOT_APPLICABLE"}


def load_document(path: pathlib.Path | str) -> dict[str, Any]:
    path = pathlib.Path(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("revision matrix root must be an object")
    return value


def _add_expected(ids: set[str], family: str, axis: str,
                  values: tuple[str, ...]) -> None:
    ids.add(f"paper-v1::{family}::control=default")
    ids.update(f"paper-v1::{family}::{axis}={value}" for value in values)


def expected_ids() -> set[str]:
    ids: set[str] = set()
    for family in ("piccard_std128", "piccard_std192_encoding"):
        _add_expected(ids, family, "k", K_VALUES)
        _add_expected(ids, family, "m", M_VALUES)
        _add_expected(ids, family, "n", N_VALUES)
        _add_expected(ids, family, "u", U_VALUES)
    _add_expected(ids, "fhe_ind", "n", N_VALUES)
    _add_expected(ids, "fhe_ind", "u", U_VALUES)
    _add_expected(ids, "bcg12_minhash", "k", K_VALUES)
    _add_expected(ids, "bcg12_minhash", "n", N_VALUES)
    _add_expected(ids, "bcg12_exact", "n", N_VALUES)
    _add_expected(ids, "sj16", "n", N_VALUES)
    _add_expected(ids, "sj16", "u", U_VALUES)
    ids.update({"paper-v1::sj16::fit=per_element",
                "paper-v1::sj16::fit=precomputed"})
    ids.update(f"paper-v1::estimator_accuracy::j={i / 10:.1f}"
               for i in range(11))
    ids.update(f"paper-v1::estimator_accuracy::k={value}" for value in K_VALUES)
    for axis in ("timing_m", "accuracy_m", "ciphertext_m", "crossover_m"):
        ids.update(f"paper-v1::sqrt_comparison::{axis}={value}"
                   for value in M_VALUES)
    ids.update(f"paper-v1::flooding::profile={value}"
               for value in ("primary40", "sensitivity64", "feasibility128"))
    for family in ("dynamic_timing", "dynamic_accuracy"):
        _add_expected(ids, family, "k", K_VALUES)
        _add_expected(ids, family, "m", M_VALUES)
        _add_expected(ids, family, "n", N_VALUES)
    ids.update({"paper-v1::dynamic_refresh::control=default",
                "paper-v1::deletion_exact::control=default",
                "paper-v1::deletion_mc::control=default"})
    for family in ("threshold_timing", "threshold_spec", "threshold_agreement"):
        ids.update(f"paper-v1::{family}::k={value}" for value in ("16", "32", "64", "128", "256"))
    for value_k in ("64", "128", "256", "512"):
        for index in range(-10, 11):
            ids.add(f"paper-v1::threshold_synthetic_fpfn::point=k{value_k}_j{index}")
    ids.add("paper-v1::threshold_dblp_fpfn::control=default")
    for variant in ("dblp_acm_u65536", "enron_u65536", "enron_u1048576"):
        ids.update(f"paper-v1::real_dataset::{variant}_artifact={artifact}"
                   for artifact in ("accuracy", "summary", "std128_timing", "std192_encoding"))
    return ids


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _integer(value: Any, label: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
             f"{label} must be a non-negative integer")
    return value


def _row(row: dict[str, Any], label: str) -> None:
    required = {"row_id", "status", "reason", "reason_code", "measured_count",
                "paper_measured_count", "toy_measured_count"}
    _require(required <= row.keys(), f"{label} is missing expected row fields")
    _require(isinstance(row["row_id"], str) and row["row_id"], f"{label} row_id invalid")
    _require(row["status"] in STATUSES, f"{label} status invalid")
    _require(isinstance(row["reason"], str), f"{label} reason invalid")
    _require(row["reason_code"] == row["reason"], f"{label} reason_code mismatch")
    measured = _integer(row["measured_count"], f"{label}.measured_count")
    paper = _integer(row["paper_measured_count"], f"{label}.paper_measured_count")
    toy = _integer(row["toy_measured_count"], f"{label}.toy_measured_count")
    _require(measured == paper, f"{label} measured_count must be paper count")
    if row["status"] in {"MEASURED", "DIAGNOSTIC"}:
        _require(not row["reason"], f"{label} measured/diagnostic reason must be empty")
    elif row["status"] == "NOT_APPLICABLE":
        _require(row["reason"] == "sqrt-m-not-perfect-square",
                 f"{label} has invalid NOT_APPLICABLE reason")
        _require(measured == 0 and toy == 0, f"{label} N/A row has measured calls")
    else:
        _require(row["reason"] == "sj16-paillier3072-calibration-bound-v1",
                 f"{label} has invalid extrapolation reason")
        _require(measured == 0 and toy == 0, f"{label} extrapolated row has measured calls")


def _expected_row_shape(cell: dict[str, Any]) -> list[tuple[str, str, str, int, int]]:
    family = cell["family"]
    axes = cell["axes"]
    axis_value = str(cell["axis_value"])
    if family == "piccard_std128":
        return [("onehot_timing", "MEASURED", "", 30, 1),
                ("onehot_accuracy", "MEASURED", "", 50, 1)]
    if family == "piccard_std192_encoding":
        ok = str(axes.get("m")) in SQRT_M
        return [("piccard_encode", "DIAGNOSTIC", "", 1, 1),
                ("piccard_sqrt_encode", "DIAGNOSTIC" if ok else "NOT_APPLICABLE",
                 "" if ok else "sqrt-m-not-perfect-square", 1 if ok else 0, 1 if ok else 0)]
    if family == "fhe_ind":
        return [("fhe_ind", "DIAGNOSTIC", "", 30, 1)]
    if family == "bcg12_minhash":
        return [("bcg12_mh_ec", "MEASURED", "", 30, 1),
                ("bcg12_mh_ff", "MEASURED", "", 30, 1)]
    if family == "bcg12_exact":
        return [("bcg12_exact_ec", "DIAGNOSTIC", "", 30, 1),
                ("bcg12_exact_ff", "DIAGNOSTIC", "", 30, 1)]
    if family == "sj16":
        if cell["axis"] == "fit":
            rid = "sj16_fit_per_element" if cell["axis_value"] == "per_element" else "sj16_fit_precomputed"
            return [(rid, "DIAGNOSTIC", "", 30, 1)]
        if str(axes.get("u")) in {"262144", "1048576"}:
            return [("sj16", "EXTRAPOLATED", "sj16-paillier3072-calibration-bound-v1", 0, 0)]
        return [("sj16", "MEASURED", "", 30, 1)]
    if family == "estimator_accuracy":
        if cell["axis"] == "j":
            return [("estimator", "MEASURED", "", 50, 1)]
        return [("estimator_convergence", "MEASURED", "", 500, 1)]
    if family == "sqrt_comparison":
        ok = str(axes.get("m")) in SQRT_M
        count = 50 if cell["axis"] == "accuracy_m" else (1 if cell["axis"] == "ciphertext_m" else 30)
        return [("onehot", "MEASURED", "", count, 1),
                ("sqrt", "MEASURED" if ok else "NOT_APPLICABLE",
                 "" if ok else "sqrt-m-not-perfect-square", count if ok else 0, 1 if ok else 0)]
    if family == "flooding":
        return [(pattern, "DIAGNOSTIC", "", 5, 1)
                for pattern in ("zero", "random", "adversarial")]
    if family == "dynamic_timing":
        return [("insert", "MEASURED", "", 30, 1), ("delete", "MEASURED", "", 30, 1)]
    if family == "dynamic_accuracy":
        return [("insert_correctness", "MEASURED", "", 50, 1),
                ("delete_correctness", "MEASURED", "", 50, 1)]
    if family == "dynamic_refresh":
        return [("refresh", "MEASURED", "", 30, 1)]
    if family == "deletion_exact":
        return [("exact", "DIAGNOSTIC", "", 0, 0)]
    if family == "deletion_mc":
        return [("monte_carlo", "DIAGNOSTIC", "", 1000, 1)]
    if family == "threshold_timing":
        return [("timing", "MEASURED", "", 30, 1)]
    if family == "threshold_spec":
        return [("spec", "DIAGNOSTIC", "", 0, 1)]
    if family == "threshold_agreement":
        return [("agreement", "MEASURED", "", 50, 1)]
    if family == "threshold_synthetic_fpfn":
        return [("synthetic_fpfn", "DIAGNOSTIC", "", 1000, 1)]
    if family == "threshold_dblp_fpfn":
        return [("dblp_held_out", "DIAGNOSTIC", "", 1, 1)]
    if family == "real_dataset":
        artifact = str(axes.get("artifact"))
        return [(artifact, "DIAGNOSTIC" if artifact == "std192_encoding" else "MEASURED", "", 1, 1)]
    raise ValueError(f"unknown matrix family: {family}")


def _expected_producer(cell: dict[str, Any]) -> str:
    family = cell["family"]
    if family in {"piccard_std128"}: return "bench_piccard"
    if family == "piccard_std192_encoding": return "bench_review_comparison"
    if family == "fhe_ind": return "bench_fhe_ind"
    if family in {"bcg12_minhash", "bcg12_exact"}: return "bench_review_comparison"
    if family == "sj16": return "bench_sj16_calibrate" if cell["axis"] == "fit" and str(cell["axis_value"]) == "per_element" else "bench_review_comparison"
    if family == "estimator_accuracy": return "bench_estimator_bias"
    if family == "sqrt_comparison":
        return {"timing_m": "bench_onehot_sqrt", "accuracy_m": "bench_sqrt_comparison",
                "ciphertext_m": "bench_crossover", "crossover_m": "bench_crossover"}[cell["axis"]]
    if family == "flooding": return "bench_noise"
    if family in {"dynamic_timing", "dynamic_accuracy", "dynamic_refresh"}: return "bench_dynamic"
    if family in {"deletion_exact", "deletion_mc"}: return "bench_deletion_survival"
    if family in {"threshold_timing", "threshold_spec", "threshold_agreement", "threshold_synthetic_fpfn"}: return "bench_threshold"
    if family == "threshold_dblp_fpfn": return "bench_real_datasets"
    if family == "real_dataset": return "summarize_real_datasets.py" if cell["axes"].get("artifact") == "summary" else "bench_real_datasets"
    raise ValueError(f"unknown producer family: {family}")


def _validate_cell(cell: Any, index: int) -> None:
    label = f"cell[{index}]"
    _require(isinstance(cell, dict), f"{label} must be an object")
    required = {"cell_id", "family", "producer", "profile", "dataset", "axes", "axis",
                "axis_value", "paper_count", "toy_count", "paper_trials", "toy_trials",
                "eligibility", "table_eligible", "comparison_eligible", "timeout_class",
                "expected_artifact_schema", "artifact_schema", "invocation_status", "expected_rows"}
    _require(required <= cell.keys(), f"{label} missing required fields")
    _require(isinstance(cell["cell_id"], str) and ID_RE.fullmatch(cell["cell_id"]), f"{label} has invalid cell ID")
    _require(cell["profile"] == "paper-v1", f"{label} profile must be paper-v1")
    _require(cell["producer"] == _expected_producer(cell), f"{label} producer binding mismatch")
    _require(isinstance(cell["axes"], dict), f"{label}.axes must be an object")
    _require(cell["axis_value"] != "", f"{label}.axis_value must be explicit")
    for key in ("paper_count", "toy_count", "paper_trials", "toy_trials"):
        _integer(cell[key], f"{label}.{key}")
    _require(cell["artifact_schema"] == cell["expected_artifact_schema"], f"{label} artifact schema mismatch")
    _require(cell["invocation_status"] in {"RUN", "NO_SPAWN"}, f"{label} invocation status invalid")
    _require(cell["table_eligible"] == (cell["eligibility"] == "TABLE_ELIGIBLE"), f"{label} table eligibility mismatch")
    _require(not cell["comparison_eligible"] or cell["eligibility"] == "TABLE_ELIGIBLE", f"{label} comparison eligibility mismatch")
    if cell["family"] == "fhe_ind":
        _require(cell["eligibility"] == "DIAGNOSTIC_ONLY" and not cell["comparison_eligible"], f"{label} FHE-IND is not diagnostic-only")
    if cell["family"] == "sj16" and cell["invocation_status"] == "NO_SPAWN":
        _require(str(cell["axes"].get("u")) in {"262144", "1048576"}, f"{label} SJ16 NO_SPAWN axis invalid")
    if cell["family"] == "real_dataset" and str(cell["axes"].get("variant", "")).startswith("enron_"):
        _require("threshold" not in str(cell["axes"].get("artifact", "")), f"{label} Enron threshold cell forbidden")
    rows = cell["expected_rows"]
    _require(isinstance(rows, list) and rows, f"{label} expected_rows is empty")
    row_ids = [row.get("row_id") for row in rows if isinstance(row, dict)]
    _require(len(row_ids) == len(set(row_ids)), f"{label} has duplicate expected row IDs")
    for row_index, row in enumerate(rows): _row(row, f"{label}.expected_rows[{row_index}]")
    expected = _expected_row_shape(cell)
    observed = [(r["row_id"], r["status"], r["reason"], r["paper_measured_count"], r["toy_measured_count"]) for r in rows]
    _require(observed == expected, f"{label} expected row topology/count mismatch")


def validate_document(document: dict[str, Any], fixture_root: pathlib.Path | str | None = None) -> None:
    _require(document.get("schema") == "piccard-revision-matrix-v1", "matrix schema mismatch")
    _require(document.get("version") == 1, "matrix version mismatch")
    _require(document.get("id_grammar") == "paper-v1::<family>::<axis>=<value>", "matrix ID grammar mismatch")
    cells = document.get("cells")
    _require(isinstance(cells, list) and len(cells) == 263, "matrix must contain exactly 263 cells")
    _require(document.get("cell_count") == 263, "matrix cell_count mismatch")
    _require(document.get("families") == FAMILY_COUNTS, "matrix family count table mismatch")
    ids = [cell.get("cell_id") if isinstance(cell, dict) else None for cell in cells]
    _require(ids == sorted(ids), "matrix cell IDs must be sorted")
    _require(len(ids) == len(set(ids)), "matrix cell IDs must be unique")
    _require(set(ids) == expected_ids(), "matrix IDs are missing, duplicated, or unexpected")
    for index, cell in enumerate(cells): _validate_cell(cell, index)
    counts = Counter(cell["family"] for cell in cells)
    _require(dict(counts) == FAMILY_COUNTS, "matrix family cardinalities mismatch")
    if fixture_root is not None:
        fixture_root = pathlib.Path(fixture_root)
        paper = (fixture_root / "paper_cell_ids.txt").read_text(encoding="ascii").splitlines()
        toy = (fixture_root / "toy_cell_ids.txt").read_text(encoding="ascii").splitlines()
        executable = (fixture_root / "executable_toy_cell_ids.txt").read_text(encoding="ascii").splitlines()
        _require(ids == paper and len(paper) == 263, "paper ID golden mismatch")
        _require(len(toy) == 20 and toy == sorted(toy), "toy ID golden cardinality/order mismatch")
        synthetic = [value for value in ids if "::threshold_synthetic_fpfn::" in value]
        _require(executable == sorted(toy + synthetic) and len(executable) == 104,
                 "executable toy ID golden mismatch")


def validate_file(path: pathlib.Path | str, fixture_root: pathlib.Path | str | None = None) -> dict[str, Any]:
    document = load_document(path)
    validate_document(document, fixture_root)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", default="benchmarks/revision_matrix.json")
    parser.add_argument("--fixtures", default="tests/fixtures/revision_matrix")
    args = parser.parse_args(argv)
    validate_file(args.matrix, args.fixtures)
    print("revision matrix: valid (263 cells; 20 representative toy; 104 executable toy)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
