#!/usr/bin/env python3
"""Validate and summarize the frozen STD128/STD192 diagnostic matrix.

This report generator is deliberately independent of the production benchmark
tables.  It accepts only a completed runner manifest, revalidates every bound
artifact, and emits one long-form row per security cell plus a paired Markdown
view for the two circuits.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
runner = importlib.import_module("run_std_security_evidence")


SUMMARY_SCHEMA = "piccard-std-security-tuple-summary-v1"
DISCLAIMER = (
    "Diagnostic smoke evidence only: one timing trial and one calibration "
    "repetition per pattern; not table-eligible and not paper-grade."
)
CORE_IDS = tuple(cell[0] for cell in runner.CORE_CELLS)
FHE_IDS = tuple(cell[0] for cell in runner.FHE_IND_CELLS)
SECURITY_ORDER = ("STD128", "STD192")
TUPLE_FIELDS = (
    "requested_ring_dim",
    "natural_ring_dim",
    "realized_ring_dim",
    "natural_depth",
    "provisioned_depth",
    "scaling_mod_size",
    "num_limbs",
    "plaintext_modulus",
    "ordered_rns_moduli",
    "log_q_bits",
    "ordered_rns_moduli_sha256",
    "openfhe_version",
    "context_tuple_sha256",
    "sanitizer_profile",
)
TIMING_FIELDS = (
    "setup_context_ms",
    "setup_keygen_ms",
    "phase_minhash_ms",
    "phase_encode_ms",
    "phase_encrypt_ms",
    "phase_evaluate_ms",
    "phase_flood_ms",
    "phase_decrypt_ms",
    "online_e2e_ms",
    "full_e2e_ms",
)
FHE_TUPLE_FIELDS = (
    "universe", "bfv_context_fingerprint", "requested_ring_dim",
    "natural_ring_dim", "realized_ring_dim",
    "natural_depth", "provisioned_depth", "scaling_mod_size", "num_limbs",
    "plaintext_modulus", "ordered_rns_moduli", "ordered_rns_moduli_sha256",
    "log_q_bits", "openfhe_version",
    "context_tuple_sha256", "sanitizer_profile", "k", "m",
)
FHE_TIMING_FIELDS = (
    "setup_context_ms", "setup_keygen_ms", "phase_encode_ms",
    "phase_encrypt_ms", "phase_evaluate_ms", "phase_decrypt_ms",
    "online_e2e_ms", "full_e2e_ms", "match_count", "jaccard_estimate",
)
PAIR_BINDING_FIELDS = (
    "workload_manifest_sha256",
    "circuit",
    "shape_id",
    "k",
    "m",
    "set_size",
    "universe",
    "seed",
    "target_jaccard",
    "realized_intersection",
    "realized_union",
    "realized_jaccard",
    "trials",
)
CSV_FIELDS = (
    "pair_id",
    "cell_id",
    "security",
    "status",
    "reason",
    *PAIR_BINDING_FIELDS,
    "calibration_quality",
    "calibration_origin",
    "calibration_artifact_sha256",
    *TUPLE_FIELDS,
    *TIMING_FIELDS,
    "bfv_context_fingerprint",
    "match_count",
    "jaccard_estimate",
    "timing_ratio_std192_over_std128_online",
    "timing_ratio_std192_over_std128_full",
    "timing_ratio_label",
)


class SummaryError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise SummaryError(message)


def _strict_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"summary {field} must be an integer")
    return value


def _path_under(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        fail(f"summary {label} path is missing")
    path = Path(value)
    if not path.is_absolute():
        fail(f"summary {label} path must be absolute")
    resolved_root = root.resolve()
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise SummaryError(f"summary {label} path escapes results root") from exc
    if not path.is_file():
        fail(f"summary {label} artifact is missing: {path}")
    return path


def _bound_artifact(root: Path, binding: Any, label: str) -> Path:
    if not isinstance(binding, dict):
        fail(f"summary {label} binding is missing")
    path = _path_under(root, binding.get("path"), label)
    expected_hash = binding.get("sha256")
    if not isinstance(expected_hash, str) or \
       expected_hash != runner.sha256_file(path):
        fail(f"summary {label} hash binding mismatch")
    return path


def _validate_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    identity = manifest.get("identity")
    if not isinstance(identity, dict) or \
       not isinstance(identity.get("source_commit"), str) or \
       not identity["source_commit"] or \
       not isinstance(identity.get("source_dirty"), bool) or \
       not isinstance(identity.get("binary_sha256"), str) or \
       not identity["binary_sha256"]:
        fail("summary manifest identity is incomplete")
    embedded = identity.get("embedded")
    if not isinstance(embedded, dict):
        fail("summary embedded build provenance is missing")
    runner.embedded_identity({**embedded})
    if embedded.get("build_dirty") != identity["source_dirty"]:
        fail("summary embedded/source dirty state mismatch")
    binary_value = identity.get("binary")
    if not isinstance(binary_value, str) or not Path(binary_value).is_absolute():
        fail("summary binary provenance path is missing")
    binary = Path(binary_value)
    if not binary.is_file() or \
       runner.sha256_file(binary) != identity["binary_sha256"]:
        fail("summary binary provenance hash mismatch")
    return identity


def _validate_workload(manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        fail("summary artifact table is missing")
    workload_path = _bound_artifact(root, artifacts.get("workload"), "workload")
    expected_path = root / "workload" / "workload.json"
    if workload_path.resolve() != expected_path.resolve():
        fail("summary workload path is not the frozen artifact")
    return runner.validate_workload(workload_path)


def _expected_cell(cell_id: str) -> dict[str, Any]:
    for cell in runner.CORE_CELLS + runner.FHE_IND_CELLS:
        if cell[0] == cell_id:
            return runner.cell_dict(cell)
    fail(f"summary unknown cell: {cell_id}")


def _validate_preflight_artifacts(
        manifest: dict[str, Any], root: Path, cell: dict[str, Any],
        identity: dict[str, Any], artifact_record: dict[str, Any],
        terminal_record: dict[str, Any]) -> dict[tuple[int, int], dict[str, Any]]:
    candidates = runner.CANDIDATES[cell["circuit"]]
    entries = terminal_record.get("preflight_caps")
    bindings = artifact_record.get("preflights")
    if not isinstance(entries, list) or len(entries) != len(candidates) or \
       not isinstance(bindings, list) or len(bindings) != len(candidates):
        fail(f"summary preflight bindings are incomplete: {cell['cell_id']}")
    result: dict[tuple[int, int], dict[str, Any]] = {}
    for candidate, entry, binding in zip(candidates, entries, bindings):
        if not isinstance(entry, dict) or entry.get("candidate") != list(candidate):
            fail(f"summary preflight candidate mismatch: {cell['cell_id']}")
        path = _bound_artifact(root, binding,
                               f"{cell['cell_id']} preflight")
        expected_path = root / "preflight" / runner.candidate_name(
            cell["cell_id"], *candidate)
        if path.resolve() != expected_path.resolve():
            fail(f"summary preflight path mismatch: {cell['cell_id']}")
        data = runner.read_canonical_json(path)
        runner.validate_preflight(data, cell, candidate[0], candidate[1], identity)
        if runner.embedded_identity(data) != identity["embedded"]:
            fail(f"summary preflight embedded provenance mismatch: {cell['cell_id']}")
        expected_summary = {
            "candidate": list(candidate),
            "realized_ring_dim": data.get("realized_ring_dim"),
            "provisioned_depth": data.get("provisioned_depth"),
            "log_q_bits": data.get("log_q_bits"),
            "skipped": data.get("skipped"),
            "reason": data.get("reason"),
        }
        if entry != expected_summary:
            fail(f"summary preflight summary mismatch: {cell['cell_id']}")
        result[candidate] = data
    return result


def _validate_cell(
        manifest: dict[str, Any], root: Path, cell: dict[str, Any],
        workload: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    cells = manifest["cells"]
    artifacts = manifest["artifacts"]
    record = cells.get(cell["cell_id"])
    artifact_record = artifacts.get(cell["cell_id"])
    if not isinstance(record, dict) or not isinstance(artifact_record, dict):
        fail(f"summary cell/artifact record is missing: {cell['cell_id']}")
    if record.get("cell_id") != cell["cell_id"] or \
       record.get("preflight_caps_recorded") is not True:
        fail(f"summary cell identity/checkpoint contract mismatch: {cell['cell_id']}")
    status = record.get("status")
    if status not in ("MEASURED", "SKIPPED_PRECHECK"):
        fail(f"summary cell is not terminally valid: {cell['cell_id']}")
    for field, expected in (("trials", 1), ("calibration_repetitions", 1)):
        if _strict_int(record.get(field), f"{cell['cell_id']} {field}") != expected:
            fail(f"summary repetition contract mismatch: {cell['cell_id']}")
    preflights = _validate_preflight_artifacts(
        manifest, root, cell, identity, artifact_record, record)
    if status == "SKIPPED_PRECHECK":
        if record.get("keygen_started") is not False or \
           record.get("calibration_started") is not False or \
           record.get("e2e_started") is not False:
            fail(f"summary skipped stage contract mismatch: {cell['cell_id']}")
        expected_reason = "; ".join(
            data["reason"] for data in preflights.values() if data["reason"])
        if not expected_reason or record.get("reason") != expected_reason or \
           any(not data["skipped"] for data in preflights.values()):
            fail(f"summary skipped preflight reason mismatch: {cell['cell_id']}")
        if "calibration" in artifact_record or "measurement" in artifact_record:
            fail(f"summary skipped cell has measured artifacts: {cell['cell_id']}")
        return {"cell": cell, "record": record, "status": status,
                "row": None, "calibration": None}

    if record.get("keygen_started") is not True or \
       record.get("calibration_started") is not True or \
       record.get("e2e_started") is not True or record.get("reason") != "":
        fail(f"summary measured stage contract mismatch: {cell['cell_id']}")
    candidate_value = record.get("candidate")
    if not isinstance(candidate_value, list) or len(candidate_value) != 2 or \
       any(isinstance(value, bool) or not isinstance(value, int)
           for value in candidate_value):
        fail(f"summary measured candidate is malformed: {cell['cell_id']}")
    candidate = (candidate_value[0], candidate_value[1])
    if candidate not in preflights or preflights[candidate].get("skipped"):
        fail(f"summary measured candidate is not feasible: {cell['cell_id']}")
    calibration_path = _bound_artifact(
        root, artifact_record.get("calibration"),
        f"{cell['cell_id']} calibration")
    expected_calibration = root / "calibration" / f"{cell['cell_id']}.json"
    if calibration_path.resolve() != expected_calibration.resolve() or \
       record.get("calibration_path") != str(calibration_path) or \
       record.get("calibration_sha256") != runner.sha256_file(calibration_path):
        fail(f"summary calibration binding mismatch: {cell['cell_id']}")
    calibration = runner.read_canonical_json(calibration_path)
    runner.validate_calibration(calibration, cell, candidate[0], candidate[1],
                                preflights[candidate])
    measurement_path = _bound_artifact(
        root, artifact_record.get("measurement"),
        f"{cell['cell_id']} measurement")
    expected_measurement = root / "measurements" / f"{cell['cell_id']}.csv"
    if measurement_path.resolve() != expected_measurement.resolve() or \
       record.get("measurement_path") != str(measurement_path) or \
       record.get("measurement_sha256") != runner.sha256_file(measurement_path):
        fail(f"summary measurement binding mismatch: {cell['cell_id']}")
    row = runner.validate_measurement(
        measurement_path, cell, workload, calibration_path)
    return {"cell": cell, "record": record, "status": status,
            "row": row, "calibration": calibration}


def _validate_fhe_cells(manifest: dict[str, Any], root: Path,
                        workload: dict[str, Any],
                        identity: dict[str, Any]) -> dict[str, Any]:
    """Validate FHE-IND terminal rows while keeping them out of core pairs."""

    gate = identity.get("fhe_ind")
    if not isinstance(gate, dict) or gate.get("mode") == "off":
        if set(manifest.get("cells", {})) != set(CORE_IDS):
            fail("summary off-mode manifest contains FHE-IND cells")
        return {"mode": "off", "entries": {}}
    if gate.get("mode") not in ("auto", "require") or \
       type(gate.get("ready")) is not bool or \
       not isinstance(gate.get("reason"), str) or \
       not gate["reason"].startswith("readiness"):
        fail("summary FHE-IND readiness identity is malformed")
    if gate.get("ready"):
        binary_value = gate.get("binary")
        if not isinstance(binary_value, str) or not Path(binary_value).is_absolute():
            fail("summary FHE-IND binary provenance path is missing")
        binary = Path(binary_value)
        if not binary.is_file() or not os.access(binary, os.X_OK) or \
           gate.get("binary_sha256") != runner.sha256_file(binary):
            fail("summary FHE-IND binary provenance hash mismatch")
        capabilities_hash = gate.get("capabilities_sha256")
        if not isinstance(capabilities_hash, str) or len(capabilities_hash) != 64 or \
           any(character not in "0123456789abcdef" for character in capabilities_hash):
            fail("summary FHE-IND capabilities provenance is malformed")
    if set(manifest.get("cells", {})) != set(CORE_IDS + FHE_IDS):
        fail("summary FHE-IND manifest must contain exactly two FHE cells")
    readiness = {
        "ready": gate.get("ready") is True,
        "binary_sha256": gate.get("binary_sha256"),
        "capabilities_sha256": gate.get("capabilities_sha256"),
        "binary": gate.get("binary"),
    }
    entries: dict[str, Any] = {}
    for cell_id in FHE_IDS:
        cell = _expected_cell(cell_id)
        record = manifest["cells"].get(cell_id)
        artifact_record = manifest["artifacts"].get(cell_id)
        if not isinstance(record, dict) or not isinstance(artifact_record, dict):
            fail(f"summary FHE-IND cell/artifact record is missing: {cell_id}")
        if record.get("cell_id") != cell_id or record.get("trials") != 1 or \
           record.get("calibration_repetitions") != 1 or \
           record.get("calibration_applicable") is not False:
            fail(f"summary FHE-IND repetition contract mismatch: {cell_id}")
        status = record.get("status")
        if status == "DEFERRED_FHE_IND_NOT_READY":
            if readiness["ready"] or record.get("reason") != gate.get("reason") or \
               record.get("keygen_started") or record.get("calibration_started") or \
               record.get("e2e_started") or \
               set(artifact_record) - {"log"}:
                fail(f"summary deferred FHE-IND contract mismatch: {cell_id}")
            entries[cell_id] = {"cell": cell, "record": record,
                                "status": status, "row": None,
                                "preflight": None}
            continue
        if status == "SKIPPED_PRECHECK":
            if not readiness["ready"] or record.get("keygen_started") is not False or \
               record.get("calibration_started") is not False or \
               record.get("e2e_started") is not False or \
               record.get("preflight_caps_recorded") is not True or \
               set(artifact_record) - {"preflight", "log"}:
                fail(f"summary FHE-IND skipped stage contract mismatch: {cell_id}")
            preflight_binding = artifact_record.get("preflight")
            preflight_path = _bound_artifact(
                root, preflight_binding, f"{cell_id} FHE-IND preflight")
            expected_preflight = root / "preflight" / f"{cell_id}.json"
            if preflight_path.resolve() != expected_preflight.resolve() or \
               record.get("preflight_path") != str(preflight_path) or \
               record.get("preflight_sha256") != runner.sha256_file(preflight_path):
                fail(f"summary FHE-IND preflight binding mismatch: {cell_id}")
            preflight = runner.read_canonical_json(preflight_path)
            runner.validate_fhe_preflight(preflight, cell, workload, readiness)
            if not preflight.get("skipped") or \
               record.get("reason") != preflight.get("reason"):
                fail(f"summary FHE-IND skip reason mismatch: {cell_id}")
            entries[cell_id] = {"cell": cell, "record": record,
                                "status": status, "row": None,
                                "preflight": preflight}
            continue
        if status != "MEASURED" or not readiness["ready"] or \
           record.get("keygen_started") is not True or \
           record.get("calibration_started") is not False or \
           record.get("e2e_started") is not True or record.get("reason") != "":
            fail(f"summary FHE-IND measured stage mismatch: {cell_id}")
        preflight_binding = artifact_record.get("preflight")
        measurement_binding = artifact_record.get("measurement")
        preflight_path = _bound_artifact(root, preflight_binding,
                                         f"{cell_id} FHE-IND preflight")
        expected_preflight = root / "preflight" / f"{cell_id}.json"
        if preflight_path.resolve() != expected_preflight.resolve() or \
           record.get("preflight_path") != str(preflight_path) or \
           record.get("preflight_sha256") != runner.sha256_file(preflight_path):
            fail(f"summary FHE-IND preflight binding mismatch: {cell_id}")
        preflight = runner.read_canonical_json(preflight_path)
        runner.validate_fhe_preflight(preflight, cell, workload, readiness)
        measurement_path = _bound_artifact(root, measurement_binding,
                                           f"{cell_id} FHE-IND measurement")
        expected_measurement = root / "measurements" / f"{cell_id}.csv"
        if measurement_path.resolve() != expected_measurement.resolve() or \
           record.get("measurement_path") != str(measurement_path) or \
           record.get("measurement_sha256") != runner.sha256_file(measurement_path):
            fail(f"summary FHE-IND measurement binding mismatch: {cell_id}")
        row = runner.validate_fhe_measurement(
            measurement_path, cell, workload, preflight, readiness)
        entries[cell_id] = {"cell": cell, "record": record,
                            "status": status, "row": row,
                            "preflight": preflight}
    return {"mode": gate.get("mode"), "entries": entries}


def validate_manifest(path: Path) -> tuple[dict[str, Any], Path, dict[str, Any],
                                               dict[str, Any], dict[str, Any]]:
    if not path.is_absolute():
        fail("--manifest must be absolute")
    manifest = runner.read_canonical_json(path)
    if manifest.get("schema") != "piccard-std-security-evidence-manifest-v1" or \
       manifest.get("complete") is not True:
        fail("summary requires a complete runner manifest")
    root = path.parent.resolve()
    identity = _validate_identity(manifest)
    workload = _validate_workload(manifest, root)
    cells = manifest.get("cells")
    if not isinstance(cells, dict):
        fail("summary manifest cell table is malformed")
    gate = identity.get("fhe_ind", {"mode": "off"})
    mode = gate.get("mode") if isinstance(gate, dict) else "off"
    expected_ids = CORE_IDS if mode == "off" else CORE_IDS + FHE_IDS
    expected_cells = runner.CORE_CELLS if mode == "off" else \
        runner.CORE_CELLS + runner.FHE_IND_CELLS
    if set(cells) != set(expected_ids):
        fail("summary manifest cell set does not match FHE-IND mode")
    runner.validate_control_artifacts(manifest, root, expected_cells)
    runner.validate_summary_artifacts(manifest, root)
    validated: dict[str, Any] = {}
    for cell_id in CORE_IDS:
        validated[cell_id] = _validate_cell(
            manifest, root, _expected_cell(cell_id), workload, identity)
    fhe_validated = _validate_fhe_cells(manifest, root, workload, identity)
    return manifest, root, workload, validated, fhe_validated


def _binding(workload: dict[str, Any], entry: dict[str, Any]) -> dict[str, str]:
    cell = entry["cell"]
    row = entry["row"]
    values = {
        "workload_manifest_sha256": workload["manifest_sha256"],
        "circuit": cell["circuit"],
        "shape_id": cell["shape_id"],
        "k": "16",
        "m": "16",
        "set_size": "10",
        "universe": "64",
        "seed": "7",
        "target_jaccard": "0.5",
        "realized_intersection": "7",
        "realized_union": "13",
        "realized_jaccard": "0.53846153846153844",
        "trials": "1",
    }
    if row is not None:
        for key in PAIR_BINDING_FIELDS:
            if key == "workload_manifest_sha256":
                continue
            if key == "universe" and key not in row:
                continue
            if row.get(key) != values[key]:
                fail(f"summary frozen binding mismatch: {entry['cell']['cell_id']} {key}")
        if row.get("workload_manifest_sha256") != values["workload_manifest_sha256"]:
            fail(f"summary workload binding mismatch: {entry['cell']['cell_id']}")
    return values


def pair_cells(workload: dict[str, Any], validated: dict[str, Any]) -> dict[str, dict[str, Any]]:
    pairs: dict[str, dict[str, Any]] = {}
    for circuit in ("onehot", "sqrt"):
        entries = {
            security: validated[f"{circuit}-{security.lower()}"]
            for security in SECURITY_ORDER
        }
        bindings = {security: _binding(workload, entry)
                    for security, entry in entries.items()}
        if bindings["STD128"] != bindings["STD192"]:
            fail(f"summary refuses to pair incompatible {circuit} workloads")
        pairs[circuit] = {
            "entries": entries,
            "binding": bindings["STD128"],
        }
    return pairs


def _ratio(numerator: str, denominator: str) -> str:
    try:
        numerator_value = float(numerator)
        denominator_value = float(denominator)
    except (TypeError, ValueError) as exc:
        fail("summary timing value is malformed")
        raise AssertionError from exc
    if numerator_value < 0.0 or denominator_value <= 0.0:
        return ""
    return format(numerator_value / denominator_value, ".17g")


def _row_for_csv(pair_id: str, security: str, entry: dict[str, Any],
                 binding: dict[str, str], ratios: dict[str, str]) -> dict[str, str]:
    row = {field: "" for field in CSV_FIELDS}
    row.update({"pair_id": pair_id, "circuit": entry["cell"]["circuit"],
                "cell_id": entry["cell"]["cell_id"], "security": security,
                "status": entry["status"],
                "reason": entry["record"].get("reason", "")})
    row.update(binding)
    data = entry["row"]
    if data is not None:
        calibration = entry["calibration"] or {}
        row["calibration_quality"] = calibration.get("calibration_quality", "")
        if calibration.get("ordered_rns_moduli") is not None:
            row["ordered_rns_moduli"] = json.dumps(
                calibration["ordered_rns_moduli"],
                ensure_ascii=False, separators=(",", ":"))
        for key in ("calibration_origin", "calibration_artifact_sha256", *TUPLE_FIELDS,
                    *TIMING_FIELDS, "match_count", "jaccard_estimate"):
            if key in data:
                row[key] = data[key]
        row["timing_ratio_std192_over_std128_online"] = ratios["online"]
        row["timing_ratio_std192_over_std128_full"] = ratios["full"]
        row["timing_ratio_label"] = ratios["label"]
    return row


def _row_for_fhe_csv(entry: dict[str, Any], workload: dict[str, Any]) -> dict[str, str]:
    row = {field: "" for field in CSV_FIELDS}
    cell = entry["cell"]
    data = entry["row"] or {}
    preflight = entry["preflight"] or {}
    row.update({
        "pair_id": "fhe_ind",
        "cell_id": cell["cell_id"],
        "security": cell["security"],
        "status": entry["status"],
        "reason": entry["record"].get("reason", ""),
        "workload_manifest_sha256": workload.get(
            "manifest_sha256", workload.get("workload_manifest_sha256", "")),
        "circuit": "fhe_ind",
        "shape_id": "fhe-indicator-v1",
        "k": "N/A", "m": "N/A", "set_size": "10", "universe": "64",
        "seed": "7", "target_jaccard": "0.5",
        "realized_intersection": "7", "realized_union": "13",
        "realized_jaccard": "0.53846153846153844", "trials": "1",
        "calibration_origin": "not-applicable",
    })
    if data:
        for key in (*FHE_TUPLE_FIELDS, *FHE_TIMING_FIELDS,
                    "bfv_context_fingerprint", "ordered_rns_moduli",
                    "ordered_rns_moduli_sha256"):
            if key in data:
                row[key] = data[key]
        if data.get("ordered_rns_moduli"):
            row["ordered_rns_moduli"] = data["ordered_rns_moduli"]
    if preflight:
        for key in ("bfv_context_fingerprint", "requested_ring_dim",
                    "natural_ring_dim", "realized_ring_dim", "natural_depth",
                    "provisioned_depth", "scaling_mod_size", "num_limbs",
                    "plaintext_modulus", "log_q_bits", "openfhe_version",
                    "context_tuple_sha256", "sanitizer_profile"):
            if key in preflight:
                row[key] = str(preflight[key])
        if preflight.get("ordered_rns_moduli"):
            row["ordered_rns_moduli"] = json.dumps(
                preflight["ordered_rns_moduli"], separators=(",", ":"))
    return row


def render_csv(pairs: dict[str, dict[str, Any]],
               fhe: dict[str, Any] | None = None,
               workload: dict[str, Any] | None = None) -> bytes:
    import io
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for circuit in ("onehot", "sqrt"):
        pair = pairs[circuit]
        left = pair["entries"]["STD128"]["row"]
        right = pair["entries"]["STD192"]["row"]
        ratios = {"online": "", "full": "", "label": ""}
        if left is not None and right is not None:
            online = _ratio(right["online_e2e_ms"], left["online_e2e_ms"])
            full = _ratio(right["full_e2e_ms"], left["full_e2e_ms"])
            if online and full:
                ratios = {"online": online, "full": full,
                          "label": "single-run diagnostic"}
        for security in SECURITY_ORDER:
            writer.writerow(_row_for_csv(
                circuit, security, pair["entries"][security],
                pair["binding"], ratios if security == "STD192" else
                {"online": "", "full": "", "label": ""}))
    if fhe is not None and fhe.get("mode") != "off":
        fhe_workload = workload or pairs["onehot"]["binding"]
        for cell_id in FHE_IDS:
            writer.writerow(_row_for_fhe_csv(fhe["entries"][cell_id],
                                             fhe_workload))
    return stream.getvalue().encode("utf-8")


def _md_value(value: str, changed: bool) -> str:
    if not value:
        return "not measured"
    return f"**{value}**" if changed else value


def _report_field(entry: dict[str, Any], field: str) -> str:
    if entry["row"] is None:
        return ""
    if field == "ordered_rns_moduli":
        calibration = entry["calibration"] or {}
        return json.dumps(calibration.get("ordered_rns_moduli", []),
                          ensure_ascii=False, separators=(",", ":"))
    return entry["row"].get(field, "")


def render_markdown(manifest_path: Path, workload: dict[str, Any],
                    pairs: dict[str, dict[str, Any]],
                    fhe: dict[str, Any] | None = None) -> bytes:
    scope = "OneHot and Sqrt"
    if fhe is not None and fhe.get("mode") != "off":
        scope += "; FHE-IND (readiness-gated)"
    scope += "; Threshold excluded"
    lines = [
        "# STD128/STD192 Diagnostic Parameter-Tuple Comparison",
        "",
        DISCLAIMER,
        "",
        "## Material Passport",
        "",
        f"- Artifact type: `{SUMMARY_SCHEMA}`",
        "- Verification status: `VERIFIED` after manifest and artifact hash validation",
        f"- Source manifest: `{manifest_path}`",
        f"- Scope: {scope}",
        "",
        f"Workload manifest SHA-256: `{workload['manifest_sha256']}`",
        "",
    ]
    for circuit in ("onehot", "sqrt"):
        pair = pairs[circuit]
        entries = pair["entries"]
        left = entries["STD128"]
        right = entries["STD192"]
        lines.extend([f"## {circuit.title()} (`{circuit}`)", ""])
        lines.extend([
            "Pair binding (must be identical across security levels):",
            "",
            f"- Workload SHA-256: `{pair['binding']['workload_manifest_sha256']}`",
            f"- Shape: `{pair['binding']['shape_id']}`; `k={pair['binding']['k']}`, "
            f"`m={pair['binding']['m']}`; set size `{pair['binding']['set_size']}`",
            f"- Seed `{pair['binding']['seed']}`; target Jaccard `{pair['binding']['target_jaccard']}`; "
            f"realized Jaccard `{pair['binding']['realized_jaccard']}`; trials `{pair['binding']['trials']}`",
            "",
            "| Context tuple field | STD128 | STD192 | Comparison |",
            "| --- | --- | --- | --- |",
        ])
        for field in TUPLE_FIELDS:
            left_value = _report_field(left, field)
            right_value = _report_field(right, field)
            compared = left["row"] is not None and right["row"] is not None
            changed = compared and left_value != right_value
            lines.append(
                f"| `{field}` | {_md_value(left_value, changed)} | "
                f"{_md_value(right_value, changed)} | "
                f"{'changed' if changed else 'same' if compared else 'not compared'} |"
            )
        lines.extend(["", "| Cell | Status | Calibration origin | Reason |", "| --- | --- | --- | --- |"])
        for security in SECURITY_ORDER:
            entry = entries[security]
            data = entry["row"]
            origin = data.get("calibration_origin", "") if data else ""
            lines.append(
                f"| `{security}` | `{entry['status']}` | "
                f"{origin or 'not measured'} | "
                f"{entry['record'].get('reason', '') or '—'} |"
            )
        lines.extend(["", "| Timing / correctness | STD128 | STD192 |", "| --- | --- | --- |"])
        for field in (*TIMING_FIELDS, "match_count", "jaccard_estimate"):
            left_value = _report_field(left, field)
            right_value = _report_field(right, field)
            compared = left["row"] is not None and right["row"] is not None
            lines.append(
                f"| `{field}` | {_md_value(left_value, compared and left_value != right_value)} | "
                f"{_md_value(right_value, compared and left_value != right_value)} |"
            )
        if left["row"] is not None and right["row"] is not None:
            online_ratio = _ratio(right["row"]["online_e2e_ms"],
                                  left["row"]["online_e2e_ms"])
            full_ratio = _ratio(right["row"]["full_e2e_ms"],
                                left["row"]["full_e2e_ms"])
            if online_ratio and full_ratio:
                lines.extend([
                    "",
                    "Timing ratios (STD192 / STD128; single-run diagnostic):",
                    "",
                    f"- Online e2e ratio: `{online_ratio}`",
                    f"- Full e2e ratio: `{full_ratio}`",
                ])
            else:
                lines.extend(["", "Timing ratios: not reported because a denominator was not positive."])
        else:
            lines.extend(["", "Timing ratios: not reported because one security cell was skipped."])
        lines.append("")
    if fhe is not None and fhe.get("mode") != "off":
        lines.extend([
            "## FHE-IND readiness gate", "",
            "FHE-IND is reported only as a separately typed diagnostic method; "
            "Piccard sanitizer/calibration fields are not inherited.", "",
            "| Cell | Status | Reason |", "| --- | --- | --- |",
        ])
        for cell_id in FHE_IDS:
            entry = fhe["entries"][cell_id]
            lines.append(
                f"| `{cell_id}` | `{entry['status']}` | "
                f"{entry['record'].get('reason', '') or '—'} |"
            )
        fhe_left = fhe["entries"][FHE_IDS[0]]
        fhe_right = fhe["entries"][FHE_IDS[1]]
        if fhe_left["row"] is not None and fhe_right["row"] is not None:
            lines.extend([
                "", "FHE-IND paired diagnostic values (STD192 / STD128 are "
                "not Piccard sanitizer comparisons):", "",
                "| Context tuple field | STD128 | STD192 | Comparison |",
                "| --- | --- | --- | --- |",
            ])
            for field in FHE_TUPLE_FIELDS:
                left_value = fhe_left["preflight"].get(
                    field, fhe_left["row"].get(field, ""))
                right_value = fhe_right["preflight"].get(
                    field, fhe_right["row"].get(field, ""))
                if field == "ordered_rns_moduli":
                    left_value = json.dumps(left_value, separators=(",", ":"))
                    right_value = json.dumps(right_value, separators=(",", ":"))
                else:
                    left_value = str(left_value)
                    right_value = str(right_value)
                changed = left_value != right_value
                lines.append(
                    f"| `{field}` | {_md_value(left_value, changed)} | "
                    f"{_md_value(right_value, changed)} | "
                    f"{'changed' if changed else 'same'} |"
                )
            lines.extend([
                "", "| FHE-IND timing / correctness | STD128 | STD192 |",
                "| --- | --- | --- |",
            ])
            for field in FHE_TIMING_FIELDS:
                left_value = str(fhe_left["row"].get(field, ""))
                right_value = str(fhe_right["row"].get(field, ""))
                changed = left_value != right_value
                lines.append(
                    f"| `{field}` | {_md_value(left_value, changed)} | "
                    f"{_md_value(right_value, changed)} |"
                )
            online_ratio = _ratio(fhe_right["row"]["online_e2e_ms"],
                                   fhe_left["row"]["online_e2e_ms"])
            full_ratio = _ratio(fhe_right["row"]["full_e2e_ms"],
                                fhe_left["row"]["full_e2e_ms"])
            if online_ratio and full_ratio:
                lines.extend([
                    "", "FHE-IND timing ratios (single-run diagnostic):", "",
                    f"- Online e2e ratio: `{online_ratio}`",
                    f"- Full e2e ratio: `{full_ratio}`",
                ])
        lines.append("")
    return "\n".join(lines).encode("utf-8")


def write_reports(manifest_path: Path, root: Path, manifest: dict[str, Any],
                  workload: dict[str, Any], pairs: dict[str, dict[str, Any]],
                  output_dir: Path, fhe: dict[str, Any] | None = None) -> None:
    expected_dir = root / "summary"
    if output_dir.resolve() != expected_dir.resolve():
        fail("--output-dir must be the manifest's summary directory")
    csv_path = output_dir / "parameter-tuples.csv"
    markdown_path = output_dir / "parameter-tuples.md"
    if csv_path.exists() or markdown_path.exists():
        fail("summary output already exists; refusing partial overwrite")
    csv_bytes = render_csv(pairs, fhe, workload)
    markdown_bytes = render_markdown(manifest_path, workload, pairs, fhe)
    runner.atomic_write(csv_path, csv_bytes, refuse_existing=True)
    runner.atomic_write(markdown_path, markdown_bytes, refuse_existing=True)
    manifest.setdefault("artifacts", {})["summary"] = {
        "parameter-tuples.csv": {
            "path": str(csv_path), "sha256": runner.sha256_file(csv_path),
        },
        "parameter-tuples.md": {
            "path": str(markdown_path), "sha256": runner.sha256_file(markdown_path),
        },
    }
    manifest["summary"] = {
        "schema": SUMMARY_SCHEMA,
        "status": "GENERATED",
        "pair_ids": ["onehot", "sqrt"] +
                    (["fhe_ind"] if fhe is not None and
                     fhe.get("mode") != "off" else []),
    }
    runner.atomic_write(manifest_path, runner.canonical_json(manifest))


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(list(argv))
    if not Path(args.manifest).is_absolute():
        parser.error("--manifest must be absolute")
    if not Path(args.output_dir).is_absolute():
        parser.error("--output-dir must be absolute")
    return args


def main(argv: Iterable[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        manifest_path = Path(args.manifest)
        output_dir = Path(args.output_dir).resolve()
        manifest, root, workload, validated, fhe = validate_manifest(manifest_path)
        if output_dir != (root / "summary").resolve():
            fail("--output-dir must be the manifest's summary directory")
        output_dir.mkdir(parents=True, exist_ok=True)
        pairs = pair_cells(workload, validated)
        write_reports(manifest_path, root, manifest, workload, pairs, output_dir, fhe)
        return 0
    except (OSError, runner.RunnerError, SummaryError) as exc:
        print(f"summarize_std_security_evidence: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
