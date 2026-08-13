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
REPRESENTATIVE_TOY_IDS = frozenset({
    "paper-v1::bcg12_exact::control=default",
    "paper-v1::bcg12_minhash::control=default",
    "paper-v1::deletion_exact::control=default",
    "paper-v1::deletion_mc::control=default",
    "paper-v1::dynamic_accuracy::control=default",
    "paper-v1::dynamic_refresh::control=default",
    "paper-v1::dynamic_timing::control=default",
    "paper-v1::estimator_accuracy::j=0.5",
    "paper-v1::fhe_ind::control=default",
    "paper-v1::flooding::profile=primary40",
    "paper-v1::piccard_std128::control=default",
    "paper-v1::piccard_std192_encoding::control=default",
    "paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy",
    "paper-v1::real_dataset::enron_u65536_artifact=accuracy",
    "paper-v1::sj16::fit=per_element",
    "paper-v1::sqrt_comparison::timing_m=64",
    "paper-v1::threshold_agreement::k=64",
    "paper-v1::threshold_dblp_fpfn::control=default",
    "paper-v1::threshold_spec::k=64",
    "paper-v1::threshold_timing::k=64",
})


def expected_executable_toy_ids() -> set[str]:
    ids = set(REPRESENTATIVE_TOY_IDS)
    ids.update(
        f"paper-v1::threshold_synthetic_fpfn::point=k{k}_j{index}"
        for k in ("64", "128", "256", "512")
        for index in range(-10, 11)
    )
    return ids


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


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _expected_universe(cell: dict[str, Any]) -> int:
    family = cell["family"]
    axis = cell["axis"]
    if family == "real_dataset":
        return {"dblp_acm_u65536": 65536, "enron_u65536": 65536,
                "enron_u1048576": 1048576}[cell["axes"].get("variant")]
    if axis == "u":
        return int(cell["axis_value"])
    if axis == "n" and _text(cell["axis_value"]) == "100000":
        return 262144
    return 65536


def _expected_axes(cell: dict[str, Any]) -> dict[str, Any]:
    family = cell["family"]
    axis = cell["axis"]
    value = cell["axis_value"]
    if family == "real_dataset":
        variant = cell.get("variant")
        return {"artifact": value, "k": 128, "m": 64, "n": 1000,
                "u": _expected_universe(cell), "variant": variant}
    axes = {"k": 128, "m": 64, "n": 1000, "u": _expected_universe(cell)}
    if family == "threshold_dblp_fpfn":
        axes["variant"] = cell.get("variant")
    elif family == "estimator_accuracy":
        if axis == "j":
            axes["j"] = float(value)
        else:
            axes["k"] = int(value)
    elif family == "flooding":
        pass
    elif family == "sqrt_comparison":
        axes["m"] = int(value)
    elif family == "threshold_synthetic_fpfn":
        axes["k"] = cell.get("point_k")
        axes["grid_index"] = cell.get("grid_index")
    elif axis in {"k", "m", "n", "u"}:
        axes[axis] = int(value)
    return axes


def _expected_artifact_schema(cell: dict[str, Any]) -> str:
    family = cell["family"]
    if family == "piccard_std128":
        return "piccard-benchmark-csv-v1"
    if family == "piccard_std192_encoding":
        return "review-encoding-csv-v1"
    if family == "fhe_ind":
        return "fhe-ind-csv-v1"
    if family in {"bcg12_minhash", "bcg12_exact"}:
        return "review-comparison-csv-v1"
    if family == "sj16":
        return "sj16-calibration-v1" if cell["axis"] == "fit" and cell["axis_value"] == "per_element" else "review-comparison-csv-v1"
    if family == "estimator_accuracy":
        return "estimator-diagnostic-csv-v1"
    if family == "sqrt_comparison":
        return "sqrt-comparison-csv-v1"
    if family == "flooding":
        return "noise-profile-v1"
    if family in {"dynamic_timing", "dynamic_accuracy", "dynamic_refresh"}:
        return "dynamic-benchmark-csv-v1"
    if family in {"deletion_exact", "deletion_mc"}:
        return "deletion-survival-csv-v1"
    if family in {"threshold_timing", "threshold_spec", "threshold_agreement"}:
        return "threshold-csv-v1"
    if family == "threshold_synthetic_fpfn":
        return "threshold-fpfn-csv-v1"
    if family == "threshold_dblp_fpfn":
        return "real-threshold-csv-v1"
    if family == "real_dataset":
        return "real-dataset-csv-v1"
    raise ValueError(f"unknown matrix family: {family}")


def _row(row: dict[str, Any], label: str) -> None:
    required = {"row_id", "status", "reason", "reason_code", "measured_count",
                "paper_measured_count", "toy_measured_count", "terminal_status"}
    _require(required <= row.keys(), f"{label} is missing expected row fields")
    _require(isinstance(row["row_id"], str) and row["row_id"], f"{label} row_id invalid")
    _require(row["status"] in STATUSES, f"{label} status invalid")
    _require(isinstance(row["reason"], str), f"{label} reason invalid")
    _require(row["reason_code"] == row["reason"], f"{label} reason_code mismatch")
    _require(row["terminal_status"] == row["status"], f"{label} terminal_status mismatch")
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


def _row_spec(row_id: str, status: str, reason: str, paper: int, toy: int,
              **fields: Any) -> dict[str, Any]:
    return {"row_id": row_id, "status": status, "reason": reason,
            "paper_measured_count": paper, "measured_count": paper,
            "toy_measured_count": toy, **fields}


def _expected_row_shape(cell: dict[str, Any]) -> list[dict[str, Any]]:
    family = cell["family"]
    axes = cell["axes"]
    axis_value = _text(cell["axis_value"])
    if family == "piccard_std128":
        return [_row_spec("onehot_timing", "MEASURED", "", 30, 1,
                          method="piccard", timing_contract="full-query"),
                _row_spec("onehot_accuracy", "MEASURED", "", 50, 1,
                          method="piccard", timing_contract="NOT_APPLICABLE")]
    if family == "piccard_std192_encoding":
        ok = _text(axes.get("m")) in SQRT_M
        return [_row_spec("piccard_encode", "DIAGNOSTIC", "", 30, 1,
                          method="piccard_encode", encoding_only=True),
                _row_spec("piccard_sqrt_encode", "DIAGNOSTIC" if ok else "NOT_APPLICABLE",
                          "" if ok else "sqrt-m-not-perfect-square", 30 if ok else 0,
                          1 if ok else 0, method="piccard_sqrt_encode", encoding_only=True)]
    if family == "fhe_ind":
        return [_row_spec("fhe_ind", "DIAGNOSTIC", "", 30, 1,
                          method="fhe_ind", raw_timing_contract="raw-phase-v1")]
    if family == "bcg12_minhash":
        return [_row_spec("bcg12_mh_ec", "MEASURED", "", 30, 1,
                          method="bcg12_mh_ec"),
                _row_spec("bcg12_mh_ff", "MEASURED", "", 30, 1,
                          method="bcg12_mh_ff")]
    if family == "bcg12_exact":
        return [_row_spec("bcg12_exact_ec", "DIAGNOSTIC", "", 30, 1,
                          method="bcg12_exact_ec"),
                _row_spec("bcg12_exact_ff", "DIAGNOSTIC", "", 30, 1,
                          method="bcg12_exact_ff")]
    if family == "sj16":
        if cell["axis"] == "fit":
            rid = "sj16_fit_per_element" if cell["axis_value"] == "per_element" else "sj16_fit_precomputed"
            if cell["axis_value"] == "per_element":
                return [_row_spec(rid, "DIAGNOSTIC", "", 30, 1,
                                  method="bench_sj16_calibrate", held_out=32768,
                                  key_bits=3072, precomputed=False, sizes=[4096, 8192, 16384],
                                  threads=2, warmup_calls=1)]
            return [_row_spec(rid, "DIAGNOSTIC", "", 30, 1,
                              method="bench_review_comparison", k=128, m=64, n=1000,
                              u=65536, key_bits=3072, precomputed=True, threads=2,
                              warmup_calls=1)]
        extrapolated = (_text(axes.get("u")) in {"262144", "1048576"} or
                        (cell["axis"] == "n" and _text(cell["axis_value"]) == "100000"))
        if extrapolated:
            return [_row_spec("sj16", "EXTRAPOLATED",
                              "sj16-paillier3072-calibration-bound-v1", 0, 0,
                              method="sj16", fit_authority="per_element")]
        return [_row_spec("sj16", "MEASURED", "", 30, 1,
                          method="sj16", key_bits=3072, threads=2)]
    if family == "estimator_accuracy":
        if cell["axis"] == "j":
            return [_row_spec("estimator", "MEASURED", "", 50, 1,
                              method="estimator", toy_trials=1, trials=50)]
        return [_row_spec("estimator_convergence", "MEASURED", "", 500, 1,
                          method="estimator", toy_trials=1, trials=500)]
    if family == "sqrt_comparison":
        ok = str(axes.get("m")) in SQRT_M
        count = 50 if cell["axis"] == "accuracy_m" else (1 if cell["axis"] == "ciphertext_m" else 30)
        return [_row_spec("onehot", "MEASURED", "", count, 1, method="onehot"),
                _row_spec("sqrt", "MEASURED" if ok else "NOT_APPLICABLE",
                          "" if ok else "sqrt-m-not-perfect-square", count if ok else 0,
                          1 if ok else 0, method="sqrt")]
    if family == "flooding":
        return [_row_spec(pattern, "DIAGNOSTIC", "", 5, 1,
                          pattern=pattern, timing_contract="NOT_APPLICABLE")
                for pattern in ("zero", "random", "adversarial")]
    if family == "dynamic_timing":
        return [_row_spec("insert", "MEASURED", "", 30, 1, phase="insert", updates=1),
                _row_spec("delete", "MEASURED", "", 30, 1, phase="delete", updates=1)]
    if family == "dynamic_accuracy":
        return [_row_spec("insert_correctness", "MEASURED", "", 50, 1,
                          phase="insert", updates=1),
                _row_spec("delete_correctness", "MEASURED", "", 50, 1,
                          phase="delete", updates=1)]
    if family == "dynamic_refresh":
        return [_row_spec("refresh", "MEASURED", "", 30, 1, method="refresh",
                          k=128, m=64, n=1000, updates=1)]
    if family == "deletion_exact":
        return [_row_spec("exact", "DIAGNOSTIC", "", 0, 0, method="exact")]
    if family == "deletion_mc":
        return [_row_spec("monte_carlo", "DIAGNOSTIC", "", 1000, 1,
                          method="monte_carlo", trials=1000)]
    if family == "threshold_timing":
        return [_row_spec("timing", "MEASURED", "", 30, 1, method="timing",
                          k=cell["axes"]["k"])]
    if family == "threshold_spec":
        return [_row_spec("spec", "DIAGNOSTIC", "", 0, 1, method="spec",
                          k=cell["axes"]["k"])]
    if family == "threshold_agreement":
        return [_row_spec("agreement", "MEASURED", "", 50, 1, method="agreement",
                          k=cell["axes"]["k"])]
    if family == "threshold_synthetic_fpfn":
        return [_row_spec("synthetic_fpfn", "DIAGNOSTIC", "", 1000, 1,
                          method="synthetic_fpfn", point_k=cell["point_k"],
                          grid_index=cell["grid_index"], trials=1000)]
    if family == "threshold_dblp_fpfn":
        return [_row_spec("dblp_held_out", "DIAGNOSTIC", "", 50, 1,
                          method="dblp_held_out", truth_bases=["label", "exact_jaccard"])]
    if family == "real_dataset":
        artifact = str(axes.get("artifact"))
        count = 30 if artifact in {"std128_timing", "std192_encoding"} else 1
        return [_row_spec(artifact, "DIAGNOSTIC" if artifact == "std192_encoding" else "MEASURED",
                          "", count, 1, method=artifact, variant=cell["variant"])]
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


def _expected_counts(cell: dict[str, Any]) -> tuple[int, int, int, int, dict[str, int], dict[str, int]]:
    family = cell["family"]
    axis = cell["axis"]
    value = _text(cell["axis_value"])
    if family == "piccard_std128":
        return 30, 1, 30, 1, {"accuracy": 50, "timing": 30}, {"accuracy": 1, "timing": 1}
    if family == "piccard_std192_encoding":
        return 30, 1, 30, 1, {"correctness": 1, "encoding": 30}, {"correctness": 1, "encoding": 1}
    if family in {"fhe_ind", "bcg12_minhash", "bcg12_exact"}:
        return 30, 1, 30, 1, {"timing": 30}, {"timing": 1}
    if family == "sj16":
        if axis == "fit" and value == "per_element":
            return 30, 1, 30, 1, {"enc_iters": 30, "query_trials": 30}, {"enc_iters": 1, "query_trials": 1}
        if axis == "fit" and value == "precomputed":
            return 30, 1, 30, 1, {"timing": 30}, {"timing": 1}
        if axis == "u" and value in {"262144", "1048576"}:
            return 0, 0, 0, 0, {"timing": 0}, {"timing": 0}
        if axis == "n" and value == "100000":
            return 30, 1, 30, 1, {"timing": 30}, {"timing": 1}
        return 30, 1, 30, 1, {"timing": 30}, {"timing": 1}
    if family == "estimator_accuracy":
        trials = 50 if axis == "j" else 500
        return trials, 1, trials, 1, {"trials": trials}, {"trials": 1}
    if family == "sqrt_comparison":
        trials = 50 if axis == "accuracy_m" else (1 if axis == "ciphertext_m" else 30)
        sqrt = 1 if _text(cell["axes"].get("m")) in SQRT_M else 0
        return trials, 1, trials, 1, {"onehot": trials, "sqrt": trials * sqrt}, {"onehot": 1, "sqrt": sqrt}
    if family == "flooding":
        return 5, 1, 5, 1, {"repetitions_per_pattern": 5}, {"repetitions_per_pattern": 1}
    if family == "dynamic_timing":
        return 30, 1, 30, 1, {"delete": 30, "insert": 30}, {"delete": 1, "insert": 1}
    if family == "dynamic_accuracy":
        return 50, 1, 50, 1, {"delete": 50, "insert": 50}, {"delete": 1, "insert": 1}
    if family == "dynamic_refresh":
        return 30, 1, 30, 1, {"refresh": 30}, {"refresh": 1}
    if family == "deletion_exact":
        return 0, 0, 0, 0, {"measured": 0}, {"measured": 0}
    if family == "deletion_mc":
        return 1000, 1, 1000, 1, {"trials": 1000}, {"trials": 1}
    if family == "threshold_timing":
        return 30, 1, 30, 1, {"timing": 30}, {"timing": 1}
    if family == "threshold_spec":
        return 0, 1, 0, 1, {"spec": 0}, {"spec": 1}
    if family == "threshold_agreement":
        return 50, 1, 50, 1, {"agreement": 50}, {"agreement": 1}
    if family == "threshold_synthetic_fpfn":
        return 1000, 1, 1000, 1, {"trials": 1000}, {"trials": 1}
    if family == "threshold_dblp_fpfn":
        return 50, 1, 50, 1, {"held_out": 50}, {"held_out": 1}
    if family == "real_dataset":
        artifact = str(cell["axes"]["artifact"])
        count = 30 if artifact in {"std128_timing", "std192_encoding"} else 1
        if artifact == "std192_encoding":
            return count, 1, count, 1, {"correctness": 1, artifact: 30}, {"correctness": 1, artifact: 1}
        return count, 1, count, 1, {artifact: count}, {artifact: 1}
    raise ValueError(f"unknown matrix family: {family}")


def _expected_eligibility(cell: dict[str, Any]) -> tuple[str, bool, bool, str]:
    family = cell["family"]
    if family == "piccard_std128" or family in {"bcg12_minhash", "estimator_accuracy",
                                                    "sqrt_comparison", "dynamic_timing",
                                                    "dynamic_accuracy"}:
        return "TABLE_ELIGIBLE", True, True, "RUN"
    if family == "piccard_std192_encoding" or family in {"fhe_ind", "bcg12_exact",
                                                           "flooding", "deletion_exact",
                                                           "deletion_mc", "threshold_spec",
                                                           "threshold_synthetic_fpfn",
                                                           "threshold_dblp_fpfn"}:
        return "DIAGNOSTIC_ONLY", False, False, "RUN"
    if family == "sj16":
        if cell["axis"] == "fit":
            return "DIAGNOSTIC_ONLY", False, False, "RUN"
        if cell["axis"] == "u" and _text(cell["axis_value"]) in {"262144", "1048576"}:
            return "DIAGNOSTIC_ONLY", False, False, "NO_SPAWN"
        if cell["axis"] == "n" and _text(cell["axis_value"]) == "100000":
            return "DIAGNOSTIC_ONLY", False, False, "NO_SPAWN"
        return "TABLE_ELIGIBLE", True, True, "RUN"
    if family == "dynamic_refresh" or family == "threshold_timing" or family == "threshold_agreement":
        return "TABLE_ELIGIBLE", True, True, "RUN"
    if family == "real_dataset":
        encoding = cell["axes"]["artifact"] == "std192_encoding"
        return ("DIAGNOSTIC_ONLY", False, False, "RUN") if encoding else ("TABLE_ELIGIBLE", True, True, "RUN")
    raise ValueError(f"unknown eligibility family: {family}")


def _validate_cell(cell: Any, index: int) -> None:
    label = f"cell[{index}]"
    _require(isinstance(cell, dict), f"{label} must be an object")
    required = {"cell_id", "family", "producer", "profile", "dataset", "axes", "axis",
                "axis_value", "paper_count", "toy_count", "paper_trials", "toy_trials",
                "paper_counts", "toy_counts",
                "eligibility", "table_eligible", "comparison_eligible", "timeout_class",
                "expected_artifact_schema", "artifact_schema", "invocation_status", "expected_rows"}
    _require(required <= cell.keys(), f"{label} missing required fields")
    _require(isinstance(cell["cell_id"], str) and ID_RE.fullmatch(cell["cell_id"]), f"{label} has invalid cell ID")
    id_family, id_selector = cell["cell_id"].split("::", 2)[1:]
    id_axis, id_value = id_selector.split("=", 1)
    _require(cell["family"] == id_family and cell["axis"] == id_axis and
             _text(cell["axis_value"]) == id_value,
             f"{label} ID/family/axis binding mismatch")
    _require(cell["profile"] == "paper-v1", f"{label} profile must be paper-v1")
    _require(cell["producer"] == _expected_producer(cell), f"{label} producer binding mismatch")
    expected_timeout_class = (
        "extended"
        if cell["family"] == "sj16" and cell["axis"] == "fit" and
        _text(cell["axis_value"]) == "per_element"
        else "standard")
    _require(cell["timeout_class"] == expected_timeout_class,
             f"{label} timeout class contract mismatch")
    _require(isinstance(cell["axes"], dict), f"{label}.axes must be an object")
    _require(cell["axis_value"] != "", f"{label}.axis_value must be explicit")
    for key in ("paper_count", "toy_count", "paper_trials", "toy_trials"):
        _integer(cell[key], f"{label}.{key}")
    _require(isinstance(cell["paper_counts"], dict) and isinstance(cell["toy_counts"], dict),
             f"{label} count aliases must be objects")
    for counts, name in ((cell["paper_counts"], "paper_counts"),
                         (cell["toy_counts"], "toy_counts")):
        for key, value in counts.items():
            _integer(value, f"{label}.{name}.{key}")
    _require(cell["axes"] == _expected_axes(cell), f"{label} family axes mismatch")
    _require(cell["artifact_schema"] == cell["expected_artifact_schema"], f"{label} artifact schema mismatch")
    _require(cell["expected_artifact_schema"] == _expected_artifact_schema(cell),
             f"{label} artifact schema contract mismatch")
    eligibility, table_eligible, comparison_eligible, invocation_status = _expected_eligibility(cell)
    _require((cell["eligibility"], cell["table_eligible"], cell["comparison_eligible"],
              cell["invocation_status"]) ==
             (eligibility, table_eligible, comparison_eligible, invocation_status),
             f"{label} eligibility/status contract mismatch")

    if cell["family"] == "real_dataset":
        variant = cell.get("variant")
        _require(variant in {"dblp_acm_u65536", "enron_u65536", "enron_u1048576"},
                 f"{label} real variant invalid")
        _require(cell["dataset"] == ("dblp_acm" if variant == "dblp_acm_u65536" else "enron"),
                 f"{label} real dataset mismatch")
        _require(cell["axes"]["variant"] == variant and
                 cell.get("artifact_kind") == cell["axes"]["artifact"],
                 f"{label} real variant/artifact aliases mismatch")
        _require(cell.get("threshold_forbidden") == variant.startswith("enron_"),
                 f"{label} real threshold-forbidden alias mismatch")
    elif cell["family"] == "threshold_dblp_fpfn":
        _require(cell["dataset"] == "dblp_acm" and cell.get("variant") == "dblp_acm_u65536" and
                 cell["axes"].get("variant") == "dblp_acm_u65536",
                 f"{label} DBLP threshold binding mismatch")
        _require(cell.get("truth_bases") == ["label", "exact_jaccard"],
                 f"{label} DBLP truth bases mismatch")
    else:
        _require(cell["dataset"] == "synthetic", f"{label} synthetic dataset mismatch")

    if cell["family"] == "flooding":
        _require(cell.get("noise_profile") == cell["axis_value"] and
                 cell.get("timing_contract") == "NOT_APPLICABLE",
                 f"{label} flooding profile contract mismatch")
    if cell["family"] in {"dynamic_timing", "dynamic_accuracy", "dynamic_refresh"}:
        _require(cell.get("updates") == 1, f"{label} dynamic update count mismatch")
    if cell["family"] == "dynamic_refresh":
        _require(cell.get("refresh_axes") == {"k": 128, "m": 64, "n": 1000},
                 f"{label} dynamic refresh axes mismatch")
    if cell["family"] in {"deletion_exact", "deletion_mc"}:
        _require(cell.get("trials") == (0 if cell["family"] == "deletion_exact" else 1000),
                 f"{label} deletion trial contract mismatch")
    if cell["family"] == "estimator_accuracy":
        expected_trials = 50 if cell["axis"] == "j" else 500
        _require(cell.get("trials") == expected_trials, f"{label} estimator trial contract mismatch")
        if cell["axis"] == "k":
            _require(cell.get("toy_dispersion_sentinels") == {"median": "N/A", "sd": -1},
                     f"{label} estimator toy sentinels mismatch")
    if cell["family"] == "threshold_synthetic_fpfn":
        _require(cell.get("point_k") == cell["axes"]["k"] and
                 cell.get("grid_index") == cell["axes"]["grid_index"],
                 f"{label} threshold point aliases mismatch")
    if cell["family"] == "sj16":
        _require(cell.get("key_bits") == 3072 and cell.get("threads") == 2,
                 f"{label} SJ16 key/thread contract mismatch")
        if cell["axis"] == "fit":
            _require(cell.get("fit_authority") == (cell["axis_value"] == "per_element"),
                     f"{label} SJ16 fit authority mismatch")
            _require(cell.get("precomputed") == (cell["axis_value"] == "precomputed"),
                     f"{label} SJ16 precomputed contract mismatch")
            if cell["axis_value"] == "per_element":
                _require(cell.get("sizes") == [4096, 8192, 16384] and cell.get("held_out") == 32768,
                         f"{label} SJ16 per-element fit inputs mismatch")
            else:
                _require(cell.get("axes") == {"k": 128, "m": 64, "n": 1000, "u": 65536},
                         f"{label} SJ16 precomputed fit axes mismatch")
    rows = cell["expected_rows"]
    _require(isinstance(rows, list) and rows, f"{label} expected_rows is empty")
    row_ids = [row.get("row_id") for row in rows if isinstance(row, dict)]
    _require(len(row_ids) == len(set(row_ids)), f"{label} has duplicate expected row IDs")
    for row_index, row in enumerate(rows): _row(row, f"{label}.expected_rows[{row_index}]")
    expected = _expected_row_shape(cell)
    _require(len(rows) == len(expected), f"{label} expected row topology mismatch")
    for row_index, (observed, contract) in enumerate(zip(rows, expected)):
        for key, value in contract.items():
            _require(observed.get(key) == value,
                     f"{label}.expected_rows[{row_index}] {key} contract mismatch")

    paper_count, toy_count, paper_trials, toy_trials, paper_counts, toy_counts = _expected_counts(cell)
    _require((cell["paper_count"], cell["toy_count"], cell["paper_trials"], cell["toy_trials"],
              cell["paper_counts"], cell["toy_counts"]) ==
             (paper_count, toy_count, paper_trials, toy_trials, paper_counts, toy_counts),
             f"{label} paper/toy count aliases mismatch")


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
        expected_toy = sorted(REPRESENTATIVE_TOY_IDS)
        _require(toy == expected_toy and len(toy) == 20,
                 "toy ID golden representative selection mismatch")
        expected_executable = sorted(expected_executable_toy_ids())
        _require(executable == expected_executable and len(executable) == 104,
                 "executable toy ID golden derived selection mismatch")


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
