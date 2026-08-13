#!/usr/bin/env python3
"""Fail-closed runner for the frozen STD128/STD192 diagnostic smoke matrix.

The runner deliberately owns only orchestration and artifact state.  OpenFHE
context construction, calibration, tuple binding, and the one-run protocol are
performed by bench_std_security_evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SOURCE_ROOT = Path(__file__).resolve().parents[1]
CAP_RING = 32768
CAP_DEPTH = 4
CAP_LOG_Q = 240.0
CORE_CELLS = (
    ("onehot-std128", "onehot", "onehot-v1", "STD128"),
    ("onehot-std192", "onehot", "onehot-v1", "STD192"),
    ("sqrt-std128", "sqrt", "sqrt-b4-v1", "STD128"),
    ("sqrt-std192", "sqrt", "sqrt-b4-v1", "STD192"),
)
FHE_IND_CELLS = (
    ("fhe-ind-std128", "fhe_ind", "fhe-indicator-v1", "STD128"),
    ("fhe-ind-std192", "fhe_ind", "fhe-indicator-v1", "STD192"),
)
CANDIDATES = {
    "onehot": ((3, 40), (3, 45), (4, 40), (4, 45)),
    "sqrt": ((4, 40), (4, 45)),
}
WORKLOAD_SCHEMA = "piccard-std-security-workload-v1"
CALIBRATION_SCHEMA = "piccard-std-security-diagnostic-calibration-v1"
CALIBRATION_SCHEMA_V2 = "piccard-std-security-diagnostic-calibration-v2"
SUMMARY_SCHEMA = "piccard-std-security-tuple-summary-v1"
SUMMARY_SCHEMA_V2 = "piccard-std-security-tuple-summary-v2"
SUMMARY_FILES = ("parameter-tuples.csv", "parameter-tuples.md")
FHE_IND_CAPABILITIES_SCHEMA = "piccard-std-security-fhe-ind-capabilities-v1"
FHE_IND_PREFLIGHT_SCHEMA = "piccard-std-security-fhe-ind-preflight-v1"
FHE_IND_REASON_PREFIX = "readiness"
MEASUREMENT_COLUMNS = {
    "cell_id",
    "circuit",
    "shape_id",
    "security",
    "k",
    "m",
    "set_size",
    "target_jaccard",
    "realized_intersection",
    "realized_union",
    "realized_jaccard",
    "seed",
    "trials",
    "requested_ring_dim",
    "natural_ring_dim",
    "realized_ring_dim",
    "natural_depth",
    "provisioned_depth",
    "scaling_mod_size",
    "num_limbs",
    "plaintext_modulus",
    "log_q_bits",
    "ordered_rns_moduli_sha256",
    "openfhe_version",
    "sanitizer_profile",
    "transcript_stat_bits",
    "max_queries",
    "flood_margin_bits",
    "eval_noise_bits",
    "query_stat_bits",
    "coefficient_stat_bits",
    "flood_noise_bits",
    "context_tuple_sha256",
    "calibration_origin",
    "calibration_artifact_sha256",
    "workload_id",
    "workload_manifest_sha256",
    "timing_hash_seed",
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
    "match_count",
    "jaccard_estimate",
    "status",
    "reason",
}
FHE_MEASUREMENT_COLUMNS = {
    "cell_id", "circuit", "shape_id", "security", "k", "m", "universe",
    "set_size", "target_jaccard", "realized_intersection", "realized_union",
    "realized_jaccard", "seed", "trials", "requested_ring_dim",
    "natural_ring_dim", "realized_ring_dim", "natural_depth",
    "provisioned_depth", "scaling_mod_size", "num_limbs", "plaintext_modulus",
    "bfv_context_fingerprint", "log_q_bits", "ordered_rns_moduli",
    "ordered_rns_moduli_sha256",
    "openfhe_version",
    "sanitizer_profile", "context_tuple_sha256", "calibration_origin",
    "workload_id", "workload_manifest_sha256", "timing_hash_seed",
    "setup_context_ms", "setup_keygen_ms", "phase_encode_ms",
    "phase_encrypt_ms", "phase_evaluate_ms", "phase_decrypt_ms",
    "online_e2e_ms", "full_e2e_ms", "match_count", "jaccard_estimate",
    "status", "reason", "method",
    "fhe_ind_binary_sha256", "capabilities_sha256",
}

ACTIVE_SCHEMA_VERSION = "v1"
V2_PRELIGHT_SCHEMA = "piccard-std-security-preflight-v2"
V2_MEASUREMENT_COLUMNS = frozenset({
    "complete_provenance_json", "complete_provenance_sha256",
})


class RunnerError(RuntimeError):
    pass


class CalibrationInfeasible(RunnerError):
    """A bounded candidate failed only its capacity-fit feasibility check."""


def active_cells(include_fhe: str, *, fhe_ready: bool = False) -> tuple:
    """Return the frozen terminal-cell order for the requested FHE mode."""

    if include_fhe == "off":
        return CORE_CELLS
    if include_fhe == "auto" and not fhe_ready:
        return CORE_CELLS + FHE_IND_CELLS
    if include_fhe in ("auto", "require") and fhe_ready:
        return CORE_CELLS + FHE_IND_CELLS
    raise RunnerError(f"unknown FHE-IND inclusion mode: {include_fhe}")


def canonical_json(value: Any) -> bytes:
    """Serialize the runner's JSON using the benchmark's wire contract.

    The C++ producer uses ``std::setprecision(max_digits10)`` with the
    default (non-fixed) float format.  Python's ``json.dumps`` chooses a
    shortest-round-trip representation instead, so values such as measured
    noise bounds can differ by one printed digit even though they parse to the
    same IEEE-754 value.  Reproducing the producer's ``.17g`` spelling keeps
    the byte-level canonical check strict while accepting artifacts emitted by
    the executable itself.
    """

    def encode_string(text: str) -> str:
        # JsonEscape in bench_std_security_evidence.cpp emits UTF-8 directly,
        # escapes quote/backslash and the three named controls, and uses a
        # four-digit Unicode escape for all remaining C0 controls.
        escaped: list[str] = ['"']
        for character in text:
            codepoint = ord(character)
            if character == '"':
                escaped.append('\\"')
            elif character == "\\":
                escaped.append('\\\\')
            elif character == "\n":
                escaped.append("\\n")
            elif character == "\r":
                escaped.append("\\r")
            elif character == "\t":
                escaped.append("\\t")
            elif codepoint < 0x20:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(character)
        escaped.append('"')
        return "".join(escaped)

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            return str(item)
        if isinstance(item, float):
            if not math.isfinite(item):
                raise RunnerError("non-finite value cannot be canonical JSON")
            return format(item, ".17g")
        if isinstance(item, str):
            return encode_string(item)
        if isinstance(item, list):
            return "[" + ",".join(encode(element) for element in item) + "]"
        if isinstance(item, dict):
            entries = []
            for key in sorted(item):
                if not isinstance(key, str):
                    raise RunnerError("canonical JSON object keys must be strings")
                entries.append(encode_string(key) + ":" + encode(item[key]))
            return "{" + ",".join(entries) + "}"
        raise RunnerError(f"unsupported canonical JSON value: {type(item)!r}")

    return (encode(value) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def capabilities_descriptor(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the hash-domain capabilities object.

    ``capabilities_sha256`` is self-referential if it is included in its own
    input.  The producer therefore hashes the canonical descriptor with that
    one derived field removed; the executable hash remains part of the
    descriptor and binds the declaration to the exact producer.
    """

    descriptor = dict(payload)
    descriptor.pop("capabilities_sha256", None)
    return descriptor


def capabilities_sha256(payload: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(capabilities_descriptor(payload)))


def is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and \
        all(character in "0123456789abcdef" for character in value)


def ordered_rns_sha256(moduli: list[str]) -> str:
    framed = bytearray()
    for modulus in moduli:
        encoded = modulus.encode("utf-8")
        framed.extend(len(encoded).to_bytes(4, "big"))
        framed.extend(encoded)
    return sha256_bytes(bytes(framed))


def _v2_frame(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(4, "big") + encoded


def _v2_optional(value: Any, *, floating: bool = False) -> bytes:
    if value is None:
        return b"\x00"
    if floating:
        # This is the spelling emitted by std::ostringstream with precision 17
        # for the finite values used by the diagnostic artifacts.
        text = format(float(value), ".17g")
    else:
        text = str(value)
    return b"\x01" + _v2_frame(text)


def complete_provenance_canonical(provenance: dict[str, Any]) -> bytes:
    """Mirror the C++ V2 domain/framing exactly for independent verification."""

    fields = [
        provenance["kind"], provenance["circuit"], provenance["shape_id"],
        provenance["security"], provenance["bfv_context_fingerprint"],
    ]
    result = bytearray(b"piccard-std-security-parameter-provenance-v2\x00")
    for value in fields:
        result.extend(_v2_frame(value))
    for key in ("requested_ring_dim", "natural_ring_dim", "provisioned_ring_dim",
                "realized_ring_dim", "natural_depth", "provisioned_depth"):
        result.extend(_v2_optional(provenance.get(key)))
    result.extend(_v2_optional(provenance.get("log_q_bits"), floating=True))
    result.extend(_v2_optional(provenance.get("log_q_over_t_bits"), floating=True))
    result.extend(_v2_optional(provenance.get("plaintext_modulus")))
    result.extend(_v2_optional(provenance.get("num_limbs")))
    result.extend(_v2_optional(provenance.get("scaling_mod_size")))
    moduli = provenance["ordered_rns_moduli"]
    result.extend(len(moduli).to_bytes(4, "big"))
    for value in moduli:
        result.extend(_v2_frame(value))
    limbs = provenance["ordered_rns_limb_bits"]
    result.extend(len(limbs).to_bytes(4, "big"))
    for value in limbs:
        result.extend(int(value).to_bytes(4, "big"))
    result.extend(_v2_frame(provenance["openfhe_version"]))
    for key in ("transcript_stat_bits", "max_queries", "query_stat_bits",
                "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
                "flood_noise_bits", "required_capacity_bits"):
        result.extend(_v2_optional(provenance.get(key)))
    result.extend(_v2_frame(provenance["flooding_assurance"]))
    residual = provenance["residual_capacity"]
    result.extend(_v2_frame(residual["status"]))
    result.extend(_v2_frame(residual["definition"]))
    result.extend(_v2_optional(residual.get("bits"), floating=True))
    result.extend(_v2_frame(provenance.get("context_tuple_sha256", "")))
    result.extend(_v2_frame(provenance["status"]))
    result.extend(_v2_frame(provenance.get("reason", "")))
    result.extend(_v2_frame(provenance.get("legacy_encoding_note", "")))
    return bytes(result)


def validate_complete_provenance(provenance: Any) -> dict[str, Any]:
    if not isinstance(provenance, dict) or \
       provenance.get("schema") != "piccard-std-security-parameter-provenance-v2":
        raise RunnerError("complete provenance schema mismatch")
    required = ("kind", "circuit", "shape_id", "security",
                "bfv_context_fingerprint", "openfhe_version",
                "ordered_rns_moduli", "ordered_rns_limb_bits",
                "flooding_assurance", "residual_capacity", "status")
    if any(key not in provenance for key in required):
        raise RunnerError("complete provenance field set is incomplete")
    if provenance.get("kind") not in ("piccard", "threshold", "fhe-ind", "encoding-only"):
        raise RunnerError("complete provenance kind is unknown")
    if not all(isinstance(provenance.get(key), str) and provenance[key]
               for key in ("circuit", "shape_id", "security",
                           "bfv_context_fingerprint", "openfhe_version")):
        raise RunnerError("complete provenance identity is incomplete")
    residual = provenance.get("residual_capacity")
    if not isinstance(residual, dict) or \
       not isinstance(residual.get("status"), str) or \
       not isinstance(residual.get("definition"), str):
        raise RunnerError("complete provenance residual evidence is malformed")
    if residual["status"] not in ("measured", "not-exposed-by-openfhe", "not-applicable"):
        raise RunnerError("complete provenance residual status is unknown")
    if residual["status"] == "not-exposed-by-openfhe" and residual.get("bits") is not None:
        raise RunnerError("complete provenance contains fabricated residual capacity")
    if residual["status"] == "not-exposed-by-openfhe" and \
       residual["definition"] != "log2(q/t)-required_flood_budget_bits":
        raise RunnerError("complete provenance residual definition mismatch")
    if residual["status"] == "not-applicable" and residual.get("bits") is not None:
        raise RunnerError("non-FHE residual capacity has a value")
    if provenance["kind"] == "encoding-only":
        if provenance["security"] != "not-applicable" or \
           provenance["bfv_context_fingerprint"] != "not-applicable" or \
           provenance["openfhe_version"] != "not-applicable" or \
           provenance["flooding_assurance"] != "not-applicable" or \
           residual["status"] != "not-applicable" or \
           residual["definition"] != "not-applicable" or \
           not isinstance(provenance.get("legacy_encoding_note"), str) or \
           not provenance["legacy_encoding_note"]:
            raise RunnerError("encoding-only provenance is not N/A")
        fhe_fields = (
            "requested_ring_dim", "natural_ring_dim", "provisioned_ring_dim",
            "realized_ring_dim", "natural_depth", "provisioned_depth",
            "log_q_bits", "log_q_over_t_bits", "plaintext_modulus",
            "num_limbs", "scaling_mod_size", "transcript_stat_bits",
            "max_queries", "query_stat_bits", "coefficient_stat_bits",
            "flood_margin_bits", "eval_noise_bits", "flood_noise_bits",
            "required_capacity_bits",
        )
        if any(provenance.get(key) is not None for key in fhe_fields) or \
           provenance.get("ordered_rns_moduli") or \
           provenance.get("ordered_rns_limb_bits"):
            raise RunnerError("encoding-only provenance contains FHE fields")
        return provenance
    if provenance["security"] not in ("TOY", "STD128", "STD192", "STD256"):
        raise RunnerError("complete provenance security is unknown")
    numeric = ("requested_ring_dim", "natural_ring_dim", "provisioned_ring_dim",
               "realized_ring_dim", "natural_depth", "provisioned_depth",
               "plaintext_modulus", "num_limbs", "scaling_mod_size")
    if any(isinstance(provenance.get(key), bool) or
           not isinstance(provenance.get(key), int) or provenance[key] <= 0
           for key in numeric):
        raise RunnerError("complete provenance numeric fields are incomplete")
    if provenance["requested_ring_dim"] > provenance["natural_ring_dim"] or \
       provenance["natural_ring_dim"] > provenance["provisioned_ring_dim"] or \
       provenance["natural_depth"] > provenance["provisioned_depth"]:
        raise RunnerError("complete provenance dimensions are not monotone")
    for key in ("log_q_bits", "log_q_over_t_bits"):
        if isinstance(provenance.get(key), bool) or \
           not isinstance(provenance.get(key), (int, float)) or \
           not math.isfinite(float(provenance[key])) or provenance[key] <= 0:
            raise RunnerError(f"complete provenance {key} is malformed")
    expected_q_over_t = provenance["log_q_bits"] - math.log2(
        provenance["plaintext_modulus"])
    if not math.isclose(expected_q_over_t, provenance["log_q_over_t_bits"],
                        rel_tol=0.0, abs_tol=1e-7):
        raise RunnerError("complete provenance q/t mismatch")
    moduli = provenance["ordered_rns_moduli"]
    limbs = provenance["ordered_rns_limb_bits"]
    if not isinstance(moduli, list) or not isinstance(limbs, list) or \
       len(moduli) != provenance["num_limbs"] or \
       len(limbs) != provenance["num_limbs"]:
        raise RunnerError("complete provenance ordered RNS metadata is incomplete")
    if any(not isinstance(value, str) or not value.isdigit() or value.startswith("0")
           for value in moduli) or \
       any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
           for value in limbs):
        raise RunnerError("complete provenance ordered RNS metadata is malformed")
    if [int(value).bit_length() for value in moduli] != limbs:
        raise RunnerError("complete provenance ordered RNS order/bit mismatch")
    if round(provenance["log_q_bits"]) != sum(limbs):
        raise RunnerError("complete provenance log_q/RNS mismatch")
    assurance = provenance["flooding_assurance"]
    if assurance not in ("not-applicable",
                         "empirical-phase-statistical+ciphertext-computational",
                         "legacy-coefficient-level"):
        raise RunnerError("complete provenance assurance taxonomy is unknown")
    expected_assurance = {
        "piccard": "empirical-phase-statistical+ciphertext-computational",
        "threshold": "legacy-coefficient-level",
        "fhe-ind": "not-applicable",
    }[provenance["kind"]]
    if assurance != expected_assurance:
        raise RunnerError("complete provenance assurance/kind mismatch")
    if provenance["kind"] == "piccard":
        sanitizer = ("transcript_stat_bits", "max_queries", "query_stat_bits",
                     "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
                     "flood_noise_bits", "required_capacity_bits")
        if any(isinstance(provenance.get(key), bool) or
               not isinstance(provenance.get(key), int) or provenance[key] < 0
               for key in sanitizer):
            raise RunnerError("complete provenance sanitizer fields are incomplete")
    elif any(provenance.get(key) is not None for key in (
            "transcript_stat_bits", "max_queries", "query_stat_bits",
            "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
            "flood_noise_bits", "required_capacity_bits")):
        raise RunnerError("non-Piccard provenance contains sanitizer fields")
    return provenance


def validate_v2_provenance_binding(data: dict[str, Any]) -> dict[str, Any]:
    provenance = validate_complete_provenance(data.get("provenance"))
    digest = data.get("provenance_sha256")
    expected = sha256_bytes(complete_provenance_canonical(provenance))
    if digest != expected:
        raise RunnerError("complete provenance hash binding mismatch")
    if provenance.get("context_tuple_sha256") != data.get("context_tuple_sha256"):
        raise RunnerError("complete provenance/context tuple binding mismatch")
    return provenance


def derive_timing_hash_seed(root_seed: int) -> int:
    """Derive the frozen ComparisonWorkload Timing[0] CRS seed."""

    if isinstance(root_seed, bool) or not isinstance(root_seed, int) or \
       root_seed < 0:
        raise RunnerError("workload root_seed is malformed")
    domain = b"piccard-review-hash-timing-v1\x00"
    digest = hashlib.sha256(domain + root_seed.to_bytes(8, "big")).digest()
    return int.from_bytes(digest[:8], "big")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_uint(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RunnerError(f"preflight {field} must be a non-negative integer")
    return value


def _json_float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RunnerError(f"preflight {field} must be numeric")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0.0:
        raise RunnerError(f"preflight {field} must be finite and non-negative")
    return parsed


def derive_pattern_seed(root_seed: int, circuit: str, realized_ring_dim: int,
                        provisioned_depth: int, scaling_mod_size: int,
                        pattern_index: int) -> int:
    mask = (1 << 64) - 1
    value = root_seed & mask
    for character in circuit:
        value = (value * 0x100000001B3 + ord(character)) & mask
    value ^= (0x9E3779B97F4A7C15 * realized_ring_dim) & mask
    value ^= (0xD1B54A32D192ED03 * provisioned_depth) & mask
    value ^= (0xA5A5A5A5A5A5A5A5 * scaling_mod_size) & mask
    value ^= (0xBF58476D1CE4E5B9 * (pattern_index + 1)) & mask
    value ^= value >> 30
    value = (value * 0xBF58476D1CE4E5B9) & mask
    value ^= value >> 27
    value = (value * 0x94D049BB133111EB) & mask
    value ^= value >> 31
    return value & mask


class _Mt19937_64:
    """Small, explicit clone of ``std::mt19937_64`` for the frozen probe.

    The calibration probe uses ``uniform_int_distribution<uint64_t>(0, 15)``.
    On the supported libc++/libstdc++ implementations that distribution is an
    independent four-bit draw, i.e. one engine output masked to its low four
    bits.  Keeping the engine here makes the random-pattern expectation
    independently derivable during resume instead of trusting two
    attacker-controlled JSON fields that merely agree with one another.
    """

    _STATE_SIZE = 312
    _PERIOD_OFFSET = 156
    _MATRIX_A = 0xB5026F5AA96619E9
    _MASK = (1 << 64) - 1

    def __init__(self, seed: int) -> None:
        self._state = [seed & self._MASK]
        for index in range(1, self._STATE_SIZE):
            previous = self._state[index - 1]
            self._state.append(
                (6364136223846793005 * (previous ^ (previous >> 62)) + index)
                & self._MASK
            )
        self._index = self._STATE_SIZE

    def next(self) -> int:
        if self._index >= self._STATE_SIZE:
            for index in range(self._STATE_SIZE):
                adjacent = self._state[(index + 1) % self._STATE_SIZE]
                value = (self._state[index] & 0xFFFFFFFF80000000) | \
                        (adjacent & 0x7FFFFFFF)
                twisted = self._state[
                    (index + self._PERIOD_OFFSET) % self._STATE_SIZE
                ] ^ (value >> 1)
                if value & 1:
                    twisted ^= self._MATRIX_A
                self._state[index] = twisted & self._MASK
            self._index = 0

        value = self._state[self._index]
        self._index += 1
        value ^= (value >> 29) & 0x5555555555555555
        value ^= (value << 17) & 0x71D67FFFEDA60000
        value &= self._MASK
        value ^= (value << 37) & 0xFFF7EEE000000000
        value &= self._MASK
        value ^= value >> 43
        return value & self._MASK


def random_expected_matches(seed: int, *, k: int = 16, m: int = 16) -> int:
    """Recompute the probe's deterministic random signature match count.

    The workload contract freezes ``k=m=16``.  Rejecting other dimensions is
    intentional: silently applying the four-bit libc++ distribution model to
    a future modulus would make resume validation unsound.
    """

    if k != 16 or m != 16:
        raise RunnerError("random calibration expectation requires k=m=16")
    generator = _Mt19937_64(seed)
    matches = 0
    for _ in range(k):
        lhs = generator.next() & 0xF
        rhs = generator.next() & 0xF
        matches += lhs == rhs
    return matches


def preflight_reason(data: dict[str, Any]) -> str:
    """Recompute the only reasons that can authorize a preflight skip."""

    reasons: list[str] = []
    realized_ring_dim = _json_uint(data.get("realized_ring_dim"),
                                   "realized_ring_dim")
    provisioned_depth = _json_uint(data.get("provisioned_depth"),
                                   "provisioned_depth")
    log_q_bits = _json_float(data.get("log_q_bits"), "log_q_bits")
    if realized_ring_dim > CAP_RING:
        reasons.append(
            f"realized_ring_dim bound={CAP_RING} observed={realized_ring_dim}")
    if provisioned_depth > CAP_DEPTH:
        reasons.append(
            f"provisioned_depth bound={CAP_DEPTH} observed={provisioned_depth}")
    if log_q_bits > CAP_LOG_Q:
        reasons.append(
            f"log2(q) bound=240 observed={format(log_q_bits, '.17g')}")
    return "; ".join(reasons)


def embedded_identity(data: dict[str, Any]) -> dict[str, Any]:
    fields = ("build_id", "build_dirty", "build_type", "openfhe_version")
    result = {field: data.get(field) for field in fields}
    if not isinstance(result["build_id"], str) or not result["build_id"]:
        raise RunnerError("preflight build_id is missing")
    if not isinstance(result["build_dirty"], bool):
        raise RunnerError("preflight build_dirty is malformed")
    if result["build_type"] != "Release":
        raise RunnerError("diagnostic runner requires an embedded Release build")
    if not isinstance(result["openfhe_version"], str) or \
       not result["openfhe_version"]:
        raise RunnerError("preflight OpenFHE provenance is missing")
    return result


def read_canonical_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"invalid JSON artifact: {path}: {exc}") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise RunnerError(f"non-canonical JSON artifact: {path}")
    return value


def atomic_write(path: Path, data: bytes, *, refuse_existing: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if refuse_existing and path.exists():
        raise RunnerError(f"refusing to overwrite existing artifact: {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def git(*args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=SOURCE_ROOT,
                               capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RunnerError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def source_identity() -> dict[str, Any]:
    dirty_text = git("status", "--porcelain=v1", "--untracked-files=all")
    return {
        "source_commit": git("rev-parse", "HEAD"),
        "source_dirty": bool(dirty_text),
    }


def outside_source(path: Path) -> bool:
    source = SOURCE_ROOT.resolve()
    try:
        path.resolve(strict=False).relative_to(source)
    except ValueError:
        return True
    return False


def run_process(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    # No retry is intentional: a failed subprocess is evidence of an ERROR,
    # not a reason to silently create a second trial.
    return subprocess.run(command, cwd=SOURCE_ROOT, env=env,
                          capture_output=True, text=True, check=False)


def immutable_fhe_snapshot(binary: Path) -> tuple[object, Path, str]:
    """Copy one opened producer inode into a private executable snapshot.

    The runner must never invoke the user-supplied pathname after readiness.
    Opening the source once before copying also makes a pathname replacement
    during the copy harmless: the descriptor continues to refer to the inode
    that was selected for this run.  The private directory is kept alive by
    the returned ``TemporaryDirectory`` object until ``process`` returns.
    """

    guard = tempfile.TemporaryDirectory(prefix="piccard-fhe-ind-")
    source_fd: int | None = None
    destination_fd: int | None = None
    try:
        source_fd = os.open(
            str(binary), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise OSError("producer is not a regular file")
        destination_fd, destination_name = tempfile.mkstemp(
            prefix="producer-", dir=guard.name)
        destination_path = Path(destination_name)
        with os.fdopen(source_fd, "rb", closefd=True) as source:
            source_fd = None
            with os.fdopen(destination_fd, "wb", closefd=True) as destination:
                destination_fd = None
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
        os.chmod(destination_path, stat.S_IMODE(source_stat.st_mode))
        return guard, destination_path, sha256_file(destination_path)
    except Exception:
        if source_fd is not None:
            os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
        guard.cleanup()
        raise


def _decode_single_json_object(text: str, label: str) -> dict[str, Any]:
    """Decode exactly one JSON object, rejecting stdout protocol smuggling."""

    if not isinstance(text, str) or not text.strip():
        raise RunnerError(f"{label} produced no JSON object")

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RunnerError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicate_pairs)
    try:
        value, end = decoder.raw_decode(text.lstrip())
    except (json.JSONDecodeError, RunnerError) as exc:
        raise RunnerError(f"{label} is not one JSON object") from exc
    if text.lstrip()[end:].strip() or not isinstance(value, dict):
        raise RunnerError(f"{label} must contain exactly one JSON object")
    return value


def _capability_value(payload: dict[str, Any], key: str) -> Any:
    if key in payload:
        return payload[key]
    supports = payload.get("supports")
    if isinstance(supports, dict):
        return supports.get(key)
    return None


def validate_fhe_ind_capabilities(payload: dict[str, Any],
                                  expected_binary_sha256: str) -> None:
    """Validate the explicit FHE-IND readiness proof, fail closed."""

    if payload.get("schema") != FHE_IND_CAPABILITIES_SCHEMA:
        raise RunnerError("readiness schema version is unsupported")
    method = _capability_value(payload, "method")
    methods = _capability_value(payload, "methods")
    if method != "fhe_ind":
        raise RunnerError("readiness method=fhe_ind is not advertised")
    if methods is not None and methods != ["fhe_ind"]:
        raise RunnerError("readiness advertises an unsupported method")
    if _capability_value(payload, "context_only_preflight") is not True or \
       _capability_value(payload, "exactly_one_run") is not True:
        raise RunnerError("readiness preflight/one-run capability is missing")
    profiles = _capability_value(payload, "security_profiles")
    if profiles != ["STD128", "STD192"]:
        raise RunnerError("readiness STD128/STD192 support is incomplete")
    workload = payload.get("workload")
    if not isinstance(workload, dict) or workload != {
            "universe": 64,
            "set_size": 10,
            "target_jaccard": "1/2",
            "seed": 7,
            "trials": 1,
    }:
        raise RunnerError("readiness workload point is not the frozen toy point")
    tuple_fields = _capability_value(payload, "context_tuple_fields")
    if tuple_fields is None:
        tuple_fields = _capability_value(payload, "tuple_fields")
    required_tuple_fields = {
        "bfv_context_fingerprint", "circuit", "shape_id", "k", "m",
        "sanitizer_profile", "security", "requested_ring_dim",
        "natural_ring_dim", "natural_depth", "realized_ring_dim",
        "plaintext_modulus", "provisioned_depth", "scaling_mod_size",
        "num_limbs", "ordered_rns_moduli", "log_q_bits",
        "openfhe_version", "context_tuple_sha256",
    }
    if not isinstance(tuple_fields, list) or \
       len(tuple_fields) != len(required_tuple_fields) or \
       any(not isinstance(field, str) for field in tuple_fields) or \
       set(tuple_fields) != required_tuple_fields:
        raise RunnerError("readiness full context-tuple fields are incomplete")
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict) or \
       provenance.get("diagnostic_only") is not True or \
       provenance.get("piccard_sanitizer_applicable") is not False or \
       provenance.get("threshold_enabled") is not False:
        raise RunnerError("readiness typed provenance is unsafe")
    declared_binary_sha256 = payload.get("fhe_ind_binary_sha256")
    if not is_sha256_hex(declared_binary_sha256) or \
       declared_binary_sha256 != expected_binary_sha256:
        raise RunnerError("readiness producer binary hash mismatch")
    declared_capabilities_sha256 = payload.get("capabilities_sha256")
    if not is_sha256_hex(declared_capabilities_sha256) or \
       declared_capabilities_sha256 != capabilities_sha256(payload):
        raise RunnerError("readiness capabilities hash mismatch")


def probe_fhe_ind(binary: Path | None, env: dict[str, str]) -> dict[str, Any]:
    """Probe an explicitly supplied FHE-IND binary without creating output."""

    if binary is None:
        return {
            "ready": False,
            "reason": "readiness capability_missing: --fhe-ind-binary was not provided",
            "binary": None,
            "binary_sha256": None,
            "snapshot_sha256": None,
            "capabilities_sha256": None,
        }
    if not binary.is_absolute():
        raise RunnerError("--fhe-ind-binary must be absolute")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return {
            "ready": False,
            "reason": "readiness executable_missing: explicit FHE-IND binary is not executable",
            "binary": str(binary.resolve()),
            "binary_sha256": None,
            "snapshot_sha256": None,
            "capabilities_sha256": None,
        }
    source_binary = str(binary.resolve())
    try:
        snapshot_guard, execution_binary, binary_hash = immutable_fhe_snapshot(binary)
    except OSError as exc:
        return {
            "ready": False,
            "reason": f"readiness snapshot_failed: cannot snapshot binary: {exc}",
            "binary": source_binary,
            "binary_sha256": None,
            "snapshot_sha256": None,
            "capabilities_sha256": None,
        }

    def failed(reason: str, *, capabilities_hash: str | None = None,
               observed_hash: str | None = binary_hash) -> dict[str, Any]:
        return {
            "ready": False,
            "reason": reason,
            "binary": source_binary,
            "execution_binary": str(execution_binary),
            "binary_sha256": observed_hash,
            "snapshot_sha256": binary_hash,
            "capabilities_sha256": capabilities_hash,
            "_snapshot_guard": snapshot_guard,
        }

    completed = run_process(
        [str(execution_binary), "--capabilities", "--format=json"], env)
    try:
        after_probe_hash = sha256_file(execution_binary)
    except OSError as exc:
        return failed(
            f"readiness probe_failed: cannot rehash snapshot: {exc}")
    if after_probe_hash != binary_hash:
        return failed(
            "readiness probe_failed: private producer snapshot changed during capability probe",
            observed_hash=after_probe_hash)
    if completed.returncode != 0:
        return failed(
            "readiness probe_failed: capability command returned nonzero")
    if completed.stderr.strip():
        return failed(
            "readiness probe_failed: capability command wrote stderr")
    try:
        payload = _decode_single_json_object(completed.stdout,
                                             "FHE-IND capabilities")
        validate_fhe_ind_capabilities(payload, binary_hash)
    except RunnerError as exc:
        return failed(f"readiness capability_invalid: {exc}")
    return {
        "ready": True,
        "reason": "readiness verified",
        "binary": source_binary,
        "execution_binary": str(execution_binary),
        "binary_sha256": binary_hash,
        "snapshot_sha256": binary_hash,
        "capabilities_sha256": capabilities_sha256(payload),
        "capabilities": payload,
        "_snapshot_guard": snapshot_guard,
    }


def cell_dict(cell: tuple[str, str, str, str]) -> dict[str, Any]:
    cell_id, circuit, shape_id, security = cell
    if circuit == "fhe_ind":
        return {
            "cell_id": cell_id,
            "circuit": circuit,
            "shape_id": shape_id,
            "security": security,
            "k": "N/A",
            "m": "N/A",
            "set_size": 10,
            "universe": 64,
            "target_jaccard": "1/2",
            "realized_intersection": 7,
            "realized_union": 13,
            "seed": 7,
            "trials": 1,
            "calibration_repetitions": 1,
            "calibration_applicable": False,
        }
    return {
        "cell_id": cell_id,
        "circuit": circuit,
        "shape_id": shape_id,
        "security": security,
        "k": 16,
        "m": 16,
        "set_size": 10,
        "target_jaccard": "1/2",
        "realized_intersection": 7,
        "realized_union": 13,
        "seed": 7,
        "trials": 1,
        "calibration_repetitions": 1,
    }


def candidate_name(cell_id: str, depth: int, scaling: int) -> str:
    return f"{cell_id}-depth{depth}-sms{scaling}.json"


def command_env() -> dict[str, str]:
    env = os.environ.copy()
    env["OMP_DYNAMIC"] = "FALSE"
    env["OMP_NUM_THREADS"] = "1"
    return env


def validate_outside_results(results_root: Path) -> None:
    if not results_root.is_absolute():
        raise RunnerError("--results-root must be absolute")
    if not outside_source(results_root):
        raise RunnerError("--results-root must be outside the Git worktree")


def binary_path(build_dir: Path) -> Path:
    if not build_dir.is_absolute():
        raise RunnerError("--build-dir must be absolute")
    binary = build_dir / "bench_std_security_evidence"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RunnerError(f"missing executable: {binary}")
    return binary


def validate_workload(path: Path) -> dict[str, Any]:
    workload = read_canonical_json(path)
    if workload.get("schema") != WORKLOAD_SCHEMA:
        raise RunnerError("workload schema mismatch")
    for key in ("manifest_sha256", "workload_id", "bytes_hex", "suite"):
        if not isinstance(workload.get(key), str) or not workload[key]:
            raise RunnerError(f"workload field missing: {key}")
    if workload["suite"] != "toy-smoke" or workload.get("root_seed") != 7:
        raise RunnerError("workload is not the frozen toy-smoke manifest")
    if workload.get("profile_id") != "toy-smoke" or \
       workload.get("k") != 16 or workload.get("m") != 16 or \
       workload.get("set_size") != 10 or workload.get("universe") != 64 or \
       workload.get("target_jaccard_numerator") != 1 or \
       workload.get("target_jaccard_denominator") != 2 or \
       workload.get("methods") != ["piccard", "piccard_sqrt", "fhe_ind",
                                    "bcg12_mh_ec", "bcg12_exact_ec", "sj16"]:
        raise RunnerError("workload metadata is not the frozen toy-smoke manifest")
    if workload.get("timing_trials") != 1 or workload.get("accuracy_trials") != 1:
        raise RunnerError("workload trial counts are not frozen at one")
    try:
        workload_bytes = bytes.fromhex(workload["bytes_hex"])
    except (TypeError, ValueError) as exc:
        raise RunnerError("workload bytes_hex is malformed") from exc
    if sha256_bytes(workload_bytes) != workload["manifest_sha256"]:
        raise RunnerError("workload bytes/digest do not match")
    return workload


def invoke_workload(binary: Path, path: Path, env: dict[str, str]) -> dict[str, Any]:
    if path.exists():
        raise RunnerError(f"refusing to overwrite workload artifact: {path}")
    completed = run_process([str(binary), "--mode=workload", f"--output={path}"], env)
    if completed.returncode != 0:
        raise RunnerError(f"workload command failed: {completed.stderr.strip()}")
    return validate_workload(path)


def validate_workload_against_binary(path: Path, binary: Path,
                                    env: dict[str, str]) -> None:
    """Re-derive the frozen manifest from this exact executable on resume."""

    descriptor, temporary = tempfile.mkstemp(prefix="std-security-workload-",
                                             suffix=".json")
    os.close(descriptor)
    temporary_path = Path(temporary)
    try:
        completed = run_process(
            [str(binary), "--mode=workload", f"--output={temporary_path}"], env)
        if completed.returncode != 0:
            raise RunnerError("resume workload derivation failed")
        expected = validate_workload(temporary_path)
        actual = validate_workload(path)
        if canonical_json(expected) != canonical_json(actual):
            raise RunnerError("resume workload does not match this executable")
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def validate_preflight(data: dict[str, Any], cell: dict[str, Any],
                       depth: int, scaling: int,
                       identity: dict[str, Any] | None = None) -> None:
    expected_schema = V2_PRELIGHT_SCHEMA if ACTIVE_SCHEMA_VERSION == "v2" \
        else "piccard-std-security-preflight-v1"
    if data.get("schema") != expected_schema or \
       data.get("mode") != "preflight" or data.get("keygen_started") is not False:
        raise RunnerError("preflight schema/stage contract mismatch")
    for key in ("circuit", "shape_id", "security", "k", "m"):
        if data.get(key) != cell[key]:
            raise RunnerError(f"preflight {key} mismatch")
    if data.get("provisioned_depth") != depth or data.get("scaling_mod_size") != scaling:
        raise RunnerError("preflight candidate mismatch")
    for key in ("realized_ring_dim", "provisioned_depth", "log_q_bits"):
        if key not in data:
            raise RunnerError(f"preflight field missing: {key}")
    _json_uint(data.get("requested_ring_dim"), "requested_ring_dim")
    _json_uint(data.get("natural_ring_dim"), "natural_ring_dim")
    _json_uint(data.get("realized_ring_dim"), "realized_ring_dim")
    _json_uint(data.get("natural_depth"), "natural_depth")
    _json_uint(data.get("provisioned_depth"), "provisioned_depth")
    _json_uint(data.get("scaling_mod_size"), "scaling_mod_size")
    _json_uint(data.get("num_limbs"), "num_limbs")
    _json_uint(data.get("plaintext_modulus"), "plaintext_modulus")
    _json_float(data.get("log_q_bits"), "log_q_bits")
    if not isinstance(data.get("skipped"), bool) or \
       not isinstance(data.get("reason"), str):
        raise RunnerError("preflight decision fields are malformed")
    if data.get("table_eligible") is not False:
        raise RunnerError("preflight cannot be table-eligible")
    if not isinstance(data.get("source_commit"), str) or \
       not data["source_commit"]:
        raise RunnerError("preflight source provenance is missing")
    embedded = embedded_identity(data)
    if identity is not None:
        if data.get("source_commit") != identity["source_commit"]:
            raise RunnerError("preflight source commit mismatch")
        if embedded["build_dirty"] != identity["source_dirty"]:
            raise RunnerError(
                "embedded build dirty state does not match the current source")
    expected_reason = preflight_reason(data)
    if bool(expected_reason) != data["skipped"] or data["reason"] != expected_reason:
        raise RunnerError("preflight skip decision/reason mismatch")
    if ACTIVE_SCHEMA_VERSION == "v2":
        provenance = validate_v2_provenance_binding(data)
        if provenance["circuit"] != cell["circuit"] or \
           provenance["shape_id"] != cell["shape_id"] or \
           provenance["security"] != cell["security"] or \
           provenance["provisioned_depth"] != depth or \
           provenance["scaling_mod_size"] != scaling:
            raise RunnerError("preflight complete provenance identity mismatch")


def preflight_candidate(binary: Path, results_root: Path, cell: dict[str, Any],
                        depth: int, scaling: int, env: dict[str, str],
                        log: list[str], identity: dict[str, Any],
                        *, resume: bool) -> dict[str, Any]:
    path = results_root / "preflight" / candidate_name(cell["cell_id"], depth, scaling)
    if path.exists():
        if resume:
            validate_preflight_against_binary(
                path, binary, cell, depth, scaling, env, identity)
        data = read_canonical_json(path)
        validate_preflight(data, cell, depth, scaling, identity)
        log.append(f"REUSED_PREFLIGHT {path}")
        return data
    command = [str(binary), "--mode=preflight", f"--circuit={cell['circuit']}",
               f"--security={cell['security']}", f"--shape-id={cell['shape_id']}",
               "--k=16", "--m=16", "--seed=7", f"--depth={depth}",
               f"--scaling-mod-size={scaling}", f"--output={path}"]
    if ACTIVE_SCHEMA_VERSION == "v2":
        command.insert(2, "--schema=v2")
    completed = run_process(command, env)
    log.append("$ " + " ".join(command))
    if completed.stdout:
        log.append(completed.stdout.rstrip())
    if completed.stderr:
        log.append(completed.stderr.rstrip())
    if completed.returncode != 0:
        raise RunnerError(f"preflight failed for depth={depth},sms={scaling}")
    data = read_canonical_json(path)
    validate_preflight(data, cell, depth, scaling, identity)
    return data


def validate_preflight_against_binary(path: Path, binary: Path,
                                      cell: dict[str, Any], depth: int,
                                      scaling: int, env: dict[str, str],
                                      identity: dict[str, Any]) -> None:
    """Reconstruct a context-only candidate to defeat self-consistent tamper."""

    descriptor, temporary = tempfile.mkstemp(prefix="std-security-preflight-",
                                             suffix=".json")
    os.close(descriptor)
    temporary_path = Path(temporary)
    try:
        command = [str(binary), "--mode=preflight",
                   f"--circuit={cell['circuit']}",
                   f"--security={cell['security']}",
                   f"--shape-id={cell['shape_id']}", "--k=16", "--m=16",
                   "--seed=7", f"--depth={depth}",
                   f"--scaling-mod-size={scaling}",
                   f"--output={temporary_path}"]
        if ACTIVE_SCHEMA_VERSION == "v2":
            command.insert(2, "--schema=v2")
        completed = run_process(command, env)
        if completed.returncode != 0:
            raise RunnerError("resume preflight derivation failed")
        regenerated = read_canonical_json(temporary_path)
        validate_preflight(regenerated, cell, depth, scaling, identity)
        recorded = read_canonical_json(path)
        if canonical_json(regenerated) != canonical_json(recorded):
            raise RunnerError(
                f"resume preflight does not match this executable: {path.name}")
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def validate_calibration(data: dict[str, Any], cell: dict[str, Any],
                         depth: int, scaling: int,
                         preflight: dict[str, Any]) -> None:
    for key in (
            "k", "m", "seed", "requested_ring_dim", "natural_ring_dim",
            "natural_depth", "realized_ring_dim", "plaintext_modulus",
            "provisioned_depth", "scaling_mod_size", "num_limbs",
            "eval_noise_bits", "query_stat_bits", "coefficient_stat_bits",
            "flood_margin_bits", "flood_noise_bits",
            "required_capacity_bits", "ct_bytes", "repetitions_per_pattern"):
        _json_uint(data.get(key), f"calibration {key}")
    log_q_bits = _json_float(data.get("log_q_bits"), "calibration log_q_bits")
    log_q_over_t_bits = _json_float(
        data.get("log_q_over_t_bits"), "calibration log_q_over_t_bits")
    if type(data.get("build_dirty")) is not bool:
        raise RunnerError("calibration build_dirty is malformed")
    expected_schema = CALIBRATION_SCHEMA_V2 if ACTIVE_SCHEMA_VERSION == "v2" \
        else CALIBRATION_SCHEMA
    if data.get("schema") != expected_schema or \
       data.get("calibration_quality") != "diagnostic-one-repetition" or \
       data.get("table_eligible") is not False:
        raise RunnerError("calibration policy mismatch")
    for key in ("circuit", "shape_id", "security", "k", "m", "seed"):
        expected = cell[key] if key not in ("seed",) else 7
        if data.get(key) != expected:
            raise RunnerError(f"calibration {key} mismatch")
    if data.get("provisioned_depth") != depth or data.get("scaling_mod_size") != scaling:
        raise RunnerError("calibration candidate mismatch")
    if data.get("table_eligible") is not False:
        raise RunnerError("diagnostic calibration cannot be table-eligible")
    if data.get("profile_id") != "primary40":
        raise RunnerError("calibration sanitizer profile mismatch")
    tuple_fields = {
        "context_tuple_sha256": "context_tuple_sha256",
        "bfv_context_fingerprint": "context_fingerprint",
        "requested_ring_dim": "requested_ring_dim",
        "natural_ring_dim": "natural_ring_dim",
        "natural_depth": "natural_depth",
        "realized_ring_dim": "realized_ring_dim",
        "plaintext_modulus": "plaintext_modulus",
        "provisioned_depth": "provisioned_depth",
        "scaling_mod_size": "scaling_mod_size",
        "num_limbs": "num_limbs",
        "ordered_rns_moduli": "ordered_rns_moduli",
        "openfhe_version": "openfhe_version",
    }
    for calibration_key, preflight_key in tuple_fields.items():
        if data.get(calibration_key) != preflight.get(preflight_key):
            raise RunnerError(
                f"calibration/preflight tuple field mismatch: {calibration_key}")
    for key in ("build_id", "build_dirty", "build_type", "source_commit",
                "openfhe_version"):
        if data.get(key) != preflight.get(key):
            raise RunnerError(f"calibration/preflight provenance mismatch: {key}")
    consumer_points = data.get("consumer_points")
    if not isinstance(consumer_points, list) or len(consumer_points) != 1 or \
       not isinstance(consumer_points[0], dict) or \
       _json_uint(consumer_points[0].get("k"),
                  "calibration consumer_points.k") != 16 or \
       _json_uint(consumer_points[0].get("m"),
                  "calibration consumer_points.m") != 16 or \
       data.get("consumer_set_serialization") != "16:16\n" or \
       data.get("consumer_set_sha256") != \
       "6ccdf58fe5af9c67abc7fb6c82dd4a94b803187b0a2d65ddaa4c9518aa24524a":
        raise RunnerError("calibration consumer declaration mismatch")
    patterns = data.get("patterns")
    if not isinstance(patterns, list) or len(patterns) != 3:
        raise RunnerError("calibration pattern count mismatch")
    if data.get("repetitions_per_pattern") != 1:
        raise RunnerError("calibration repetition count mismatch")
    expected_patterns = ("all_match", "no_match", "random")
    worst_noise = 0.0
    for pattern_index, (expected_pattern, observation) in enumerate(
            zip(expected_patterns, patterns)):
        if not isinstance(observation, dict) or \
           observation.get("pattern") != expected_pattern or \
           observation.get("decrypt_ok") is not True or \
           observation.get("saturated") is not False:
            raise RunnerError("calibration pattern contract mismatch")
        repetition_index = _json_uint(
            observation.get("repetition_index"),
            "calibration pattern repetition_index")
        pattern_seed = _json_uint(observation.get("seed"),
                                  "calibration pattern seed")
        expected_matches = _json_uint(
            observation.get("expected_matches"),
            "calibration pattern expected_matches")
        observed_matches = _json_uint(
            observation.get("observed_matches"),
            "calibration pattern observed_matches")
        if repetition_index != 0 or not 0 <= expected_matches <= 16 or \
           observed_matches != expected_matches:
            raise RunnerError("calibration pattern match contract mismatch")
        if expected_pattern == "all_match" and expected_matches != 16:
            raise RunnerError("all_match calibration row is invalid")
        if expected_pattern == "no_match" and expected_matches != 0:
            raise RunnerError("no_match calibration row is invalid")
        expected_seed = derive_pattern_seed(
            7, cell["circuit"], int(data["realized_ring_dim"]), depth,
            scaling, pattern_index)
        if pattern_seed != expected_seed:
            raise RunnerError("calibration pattern seed mismatch")
        if expected_pattern == "random" and expected_matches != \
           random_expected_matches(expected_seed, k=data["k"], m=data["m"]):
            raise RunnerError("random calibration match count is invalid")
        noise = _json_float(observation.get("eval_noise_bits"),
                            "calibration pattern eval_noise_bits")
        worst_noise = max(worst_noise, noise)
    expected_eval_noise = math.ceil(worst_noise)
    if data.get("eval_noise_bits") != expected_eval_noise:
        raise RunnerError("calibration worst noise reduction mismatch")
    if data["ct_bytes"] <= 0:
        raise RunnerError("calibration ciphertext size is missing")
    realized_ring_dim = data["realized_ring_dim"]
    plaintext_modulus = data["plaintext_modulus"]
    log_q_over_t = log_q_over_t_bits
    query_stat_bits = 40 + 20
    coefficient_stat_bits = query_stat_bits + math.ceil(math.log2(realized_ring_dim))
    flood_noise_bits = expected_eval_noise + coefficient_stat_bits + 8
    required_capacity_bits = flood_noise_bits + 2
    if data.get("query_stat_bits") != query_stat_bits or \
       data.get("coefficient_stat_bits") != coefficient_stat_bits or \
       data.get("flood_noise_bits") != flood_noise_bits or \
       data.get("required_capacity_bits") != required_capacity_bits or \
       data.get("flood_margin_bits") != 8:
        raise RunnerError("calibration capacity arithmetic mismatch")
    expected_log_q_over_t = log_q_bits - math.log2(plaintext_modulus)
    if not math.isclose(log_q_over_t, expected_log_q_over_t,
                        rel_tol=0.0, abs_tol=1e-9) or \
       required_capacity_bits > log_q_over_t or \
       log_q_over_t - 1.0 - worst_noise < 0.5:
        raise RunnerError("calibration capacity fit/saturation mismatch")
    if ACTIVE_SCHEMA_VERSION == "v2":
        provenance = validate_v2_provenance_binding(data)
        if provenance["circuit"] != cell["circuit"] or \
           provenance["shape_id"] != cell["shape_id"] or \
           provenance["security"] != cell["security"] or \
           provenance["provisioned_depth"] != depth or \
           provenance["scaling_mod_size"] != scaling:
            raise RunnerError("calibration complete provenance identity mismatch")
        preflight_provenance = preflight.get("provenance")
        expected_preflight = preflight_provenance \
            if isinstance(preflight_provenance, dict) else None
        if expected_preflight is None:
            raise RunnerError("calibration/preflight complete provenance mismatch")
        for key in ("schema", "kind", "circuit", "shape_id", "security",
                    "bfv_context_fingerprint", "requested_ring_dim",
                    "natural_ring_dim", "provisioned_ring_dim",
                    "realized_ring_dim", "natural_depth", "provisioned_depth",
                    "log_q_bits", "log_q_over_t_bits", "plaintext_modulus",
                    "num_limbs", "scaling_mod_size", "ordered_rns_moduli",
                    "ordered_rns_limb_bits", "openfhe_version",
                    "flooding_assurance", "residual_capacity"):
            if provenance.get(key) != expected_preflight.get(key):
                raise RunnerError(
                    f"calibration/preflight complete provenance mismatch: {key}")


def calibrate_candidate(binary: Path, results_root: Path, cell: dict[str, Any],
                        depth: int, scaling: int, preflight: dict[str, Any],
                        env: dict[str, str], log: list[str], *, resume: bool) -> Path:
    path = results_root / "calibration" / f"{cell['cell_id']}.json"
    if resume and path.exists():
        data = read_canonical_json(path)
        validate_calibration(data, cell, depth, scaling, preflight)
        log.append(f"REUSED_CALIBRATION {path}")
        return path
    if path.exists():
        raise RunnerError(f"refusing to overwrite calibration artifact: {path}")
    command = [str(binary), "--mode=calibrate", f"--circuit={cell['circuit']}",
               f"--security={cell['security']}", f"--shape-id={cell['shape_id']}",
               "--k=16", "--m=16", "--seed=7", f"--depth={depth}",
               f"--scaling-mod-size={scaling}", f"--output={path}"]
    if ACTIVE_SCHEMA_VERSION == "v2":
        command.insert(2, "--schema=v2")
    completed = run_process(command, env)
    log.append("$ " + " ".join(command))
    if completed.stdout:
        log.append(completed.stdout.rstrip())
    if completed.stderr:
        log.append(completed.stderr.rstrip())
    if completed.returncode != 0:
        is_exact_capacity_failure = (
            completed.returncode == 2 and
            completed.stdout == "" and
            completed.stderr ==
            "bench_std_security_evidence: calibration capacity does not fit\n" and
            not path.exists()
        )
        if is_exact_capacity_failure:
            raise CalibrationInfeasible(
                f"calibration capacity infeasible for depth={depth},sms={scaling}")
        raise RunnerError(f"calibration failed for depth={depth},sms={scaling}")
    data = read_canonical_json(path)
    validate_calibration(data, cell, depth, scaling, preflight)
    return path


def validate_measurement(path: Path, cell: dict[str, Any], workload: dict[str, Any],
                         calibration_path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.reader(source))
    if len(rows) != 2:
        raise RunnerError("measurement must contain exactly one CSV data row")
    header, row = rows
    expected_columns = MEASUREMENT_COLUMNS | V2_MEASUREMENT_COLUMNS \
        if ACTIVE_SCHEMA_VERSION == "v2" else MEASUREMENT_COLUMNS
    if set(header) != expected_columns or len(header) != len(expected_columns):
        raise RunnerError("measurement CSV header mismatch")
    if len(row) != len(header):
        raise RunnerError("measurement CSV row width mismatch")
    data = dict(zip(header, row))
    if data.get("cell_id") != cell["cell_id"] or data.get("circuit") != cell["circuit"] or \
       data.get("shape_id") != cell["shape_id"] or data.get("security") != cell["security"]:
        raise RunnerError("measurement cell identity mismatch")
    expected_frozen = {
        "k": str(cell["k"]), "m": str(cell["m"]), "set_size": "10",
        "target_jaccard": "0.5", "realized_intersection": "7",
        "realized_union": "13", "realized_jaccard": "0.53846153846153844",
        "seed": "7", "trials": "1", "sanitizer_profile": "primary40",
        "transcript_stat_bits": "40", "max_queries": "1048576",
        "flood_margin_bits": "8",
    }
    for key, expected in expected_frozen.items():
        if data.get(key) != expected:
            raise RunnerError(f"measurement frozen field mismatch: {key}")
    if data.get("status") != "MEASURED" or data.get("trials") != "1":
        raise RunnerError("measurement terminal/status mismatch")
    if data.get("workload_id") != workload.get("workload_id") or \
       data.get("workload_manifest_sha256") != workload.get("manifest_sha256"):
        raise RunnerError("measurement workload digest mismatch")
    expected_timing_hash_seed = str(
        derive_timing_hash_seed(workload["root_seed"])
    )
    if data.get("timing_hash_seed") != expected_timing_hash_seed:
        raise RunnerError("measurement Timing[0] hash seed mismatch")
    if data.get("realized_intersection") != "7" or \
       data.get("realized_union") != "13" or \
       data.get("target_jaccard") != "0.5":
        raise RunnerError("measurement workload geometry mismatch")
    if data.get("calibration_artifact_sha256") != sha256_file(calibration_path):
        raise RunnerError("measurement calibration hash mismatch")
    calibration = read_canonical_json(calibration_path)
    if data.get("calibration_origin") != "diagnostic-artifact" or \
       data.get("context_tuple_sha256") != calibration.get("context_tuple_sha256") or \
       data.get("openfhe_version") != calibration.get("openfhe_version") or \
       data.get("realized_ring_dim") != str(calibration.get("realized_ring_dim")) or \
       data.get("provisioned_depth") != str(calibration.get("provisioned_depth")) or \
       data.get("scaling_mod_size") != str(calibration.get("scaling_mod_size")):
        raise RunnerError("measurement/calibration tuple binding mismatch")
    if ACTIVE_SCHEMA_VERSION == "v2":
        try:
            measurement_provenance = json.loads(
                data["complete_provenance_json"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise RunnerError("measurement complete provenance JSON is malformed") from exc
        measurement_wrapper = {
            "provenance": measurement_provenance,
            "provenance_sha256": data["complete_provenance_sha256"],
            "context_tuple_sha256": data["context_tuple_sha256"],
        }
        validate_v2_provenance_binding(measurement_wrapper)
        calibration_provenance = validate_v2_provenance_binding(calibration)
        comparable = dict(measurement_provenance)
        expected = dict(calibration_provenance)
        comparable.pop("status", None)
        comparable.pop("reason", None)
        expected.pop("status", None)
        expected.pop("reason", None)
        if comparable != expected:
            raise RunnerError("measurement/calibration complete provenance mismatch")
    for key in ("requested_ring_dim", "natural_ring_dim", "realized_ring_dim",
                "natural_depth", "provisioned_depth", "scaling_mod_size",
                "num_limbs", "plaintext_modulus"):
        try:
            if int(data[key]) != int(calibration[key]):
                raise RunnerError(f"measurement/calibration field mismatch: {key}")
        except (KeyError, TypeError, ValueError) as exc:
            raise RunnerError(f"measurement/calibration field malformed: {key}") from exc
    for key in ("eval_noise_bits", "query_stat_bits", "coefficient_stat_bits",
                "flood_noise_bits"):
        try:
            if int(data[key]) != int(calibration[key]):
                raise RunnerError(f"measurement/calibration field mismatch: {key}")
        except (KeyError, TypeError, ValueError) as exc:
            raise RunnerError(f"measurement/calibration field malformed: {key}") from exc
    try:
        if abs(float(data["log_q_bits"]) - float(calibration["log_q_bits"])) > 1e-9:
            raise RunnerError("measurement/calibration field mismatch: log_q_bits")
    except (KeyError, TypeError, ValueError) as exc:
        raise RunnerError("measurement/calibration field malformed: log_q_bits") from exc
    if data.get("ordered_rns_moduli_sha256") != \
       ordered_rns_sha256(calibration.get("ordered_rns_moduli", [])) or \
       data.get("sanitizer_profile") != "primary40":
        raise RunnerError("measurement calibration provenance mismatch")
    if data.get("reason") != "":
        raise RunnerError("measured row contains a failure reason")
    timing_fields = ("setup_context_ms", "setup_keygen_ms", "phase_minhash_ms",
                     "phase_encode_ms", "phase_encrypt_ms", "phase_evaluate_ms",
                     "phase_flood_ms", "phase_decrypt_ms", "online_e2e_ms",
                     "full_e2e_ms")
    timings: dict[str, float] = {}
    for key in timing_fields:
        try:
            timings[key] = float(data[key])
            if not math.isfinite(timings[key]) or timings[key] < 0.0:
                raise RunnerError(f"negative timing field: {key}")
        except (KeyError, TypeError, ValueError) as exc:
            raise RunnerError(f"invalid timing field: {key}") from exc
    online_sum = sum(timings[key] for key in (
        "phase_minhash_ms", "phase_encode_ms", "phase_encrypt_ms",
        "phase_evaluate_ms", "phase_flood_ms", "phase_decrypt_ms"))
    full_sum = timings["setup_context_ms"] + timings["setup_keygen_ms"] + online_sum
    if not math.isclose(online_sum, timings["online_e2e_ms"],
                        rel_tol=0.0, abs_tol=1e-9) or \
       not math.isclose(full_sum, timings["full_e2e_ms"],
                        rel_tol=0.0, abs_tol=1e-9):
        raise RunnerError("measurement timing totals do not reconcile")
    try:
        match_count = int(data["match_count"])
        estimate = float(data["jaccard_estimate"])
    except (KeyError, ValueError) as exc:
        raise RunnerError("measurement correctness fields are malformed") from exc
    if str(match_count) != data["match_count"] or not 0 <= match_count <= 16:
        raise RunnerError("measurement match count is outside the frozen workload")
    expected_estimate = (match_count / 16.0 - 1.0 / 16.0) / (1.0 - 1.0 / 16.0)
    if not math.isclose(estimate, expected_estimate, rel_tol=0.0, abs_tol=1e-15):
        raise RunnerError("measurement bias correction mismatch")
    if match_count != 10 or not math.isclose(estimate, 0.6, rel_tol=0.0, abs_tol=1e-15):
        raise RunnerError("measurement does not bind the frozen Timing[0] workload")
    return data


def _validate_fhe_context_tuple(data: dict[str, Any], cell: dict[str, Any],
                                readiness: dict[str, Any], *,
                                json_values: bool = False) -> None:
    if data.get("method") != "fhe_ind" or data.get("circuit") != "fhe_ind" or \
       data.get("shape_id") != "fhe-indicator-v1" or \
       data.get("security") != cell["security"]:
        raise RunnerError("FHE-IND context identity mismatch")
    if data.get("k") != "N/A" or data.get("m") != "N/A":
        raise RunnerError("FHE-IND k/m must be structurally not applicable")
    if data.get("sanitizer_profile") != "not-applicable" or \
       data.get("calibration_origin") != "not-applicable":
        raise RunnerError("FHE-IND sanitizer/calibration must be not-applicable")
    for key in ("requested_ring_dim", "natural_ring_dim", "realized_ring_dim",
                "natural_depth", "provisioned_depth", "scaling_mod_size",
                "num_limbs", "plaintext_modulus"):
        try:
            if json_values:
                value = _json_uint(data.get(key), f"FHE-IND tuple {key}")
            else:
                raw = data[key]
                if not isinstance(raw, str) or not raw.isascii() or \
                   not raw.isdigit():
                    raise ValueError(key)
                value = int(raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise RunnerError(f"FHE-IND tuple field is malformed: {key}") from exc
        if value <= 0:
            raise RunnerError(f"FHE-IND tuple field is non-positive: {key}")
    if not isinstance(data.get("ordered_rns_moduli"), list) or \
       not data["ordered_rns_moduli"] or \
       any(not isinstance(value, str) or not value
           for value in data["ordered_rns_moduli"]):
        raise RunnerError("FHE-IND ordered RNS tuple is malformed")
    if any(not value.isascii() or not value.isdigit() or int(value) <= 0
           for value in data["ordered_rns_moduli"]):
        raise RunnerError("FHE-IND ordered RNS tuple is not decimal")
    if int(data["num_limbs"]) != len(data["ordered_rns_moduli"]):
        raise RunnerError("FHE-IND RNS limb count mismatch")
    if not isinstance(data.get("context_tuple_sha256"), str) or \
       len(data["context_tuple_sha256"]) != 64 or \
       any(ch not in "0123456789abcdef" for ch in data["context_tuple_sha256"]):
        raise RunnerError("FHE-IND context tuple digest is malformed")
    for key in ("bfv_context_fingerprint", "openfhe_version"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise RunnerError(f"FHE-IND tuple provenance is missing: {key}")
    binary_hash = readiness.get("binary_sha256")
    capabilities_hash = readiness.get("capabilities_sha256")
    if not is_sha256_hex(binary_hash) or not is_sha256_hex(capabilities_hash) or \
       data.get("fhe_ind_binary_sha256") != binary_hash or \
       data.get("capabilities_sha256") != capabilities_hash:
        raise RunnerError("FHE-IND readiness provenance mismatch")


def validate_fhe_preflight(data: dict[str, Any], cell: dict[str, Any],
                           workload: dict[str, Any],
                           readiness: dict[str, Any]) -> None:
    if data.get("schema") != FHE_IND_PREFLIGHT_SCHEMA or \
       data.get("mode") != "preflight" or \
       data.get("keygen_started") is not False or \
       data.get("cell_id") != cell["cell_id"]:
        raise RunnerError("FHE-IND preflight schema/stage mismatch")
    if data.get("universe") != 64 or data.get("set_size") != 10 or \
       data.get("target_jaccard") != "1/2" or data.get("seed") != 7 or \
       data.get("trials") != 1:
        raise RunnerError("FHE-IND preflight workload binding mismatch")
    if type(data.get("skipped")) is not bool or \
       not isinstance(data.get("reason"), str):
        raise RunnerError("FHE-IND preflight skip fields are malformed")
    expected_reason = preflight_reason(data)
    if data.get("skipped") != bool(expected_reason) or \
       data.get("reason") != expected_reason:
        raise RunnerError("FHE-IND preflight cap decision mismatch")
    _validate_fhe_context_tuple(data, cell, readiness, json_values=True)
    if data.get("table_eligible") is not False or \
       data.get("diagnostic_only") is not True:
        raise RunnerError("FHE-IND preflight provenance is not diagnostic-only")
    if data.get("workload_id") != workload.get("workload_id") or \
       data.get("workload_manifest_sha256") != workload.get("manifest_sha256"):
        raise RunnerError("FHE-IND preflight workload digest mismatch")


def _validate_csv_nonnegative(data: dict[str, str], fields: Iterable[str]) -> None:
    for field in fields:
        try:
            value = float(data[field])
        except (KeyError, TypeError, ValueError) as exc:
            raise RunnerError(f"FHE-IND timing field is malformed: {field}") from exc
        if not math.isfinite(value) or value <= 0.0:
            raise RunnerError(
                f"FHE-IND timing field must be positive: {field}")


def validate_fhe_measurement(path: Path, cell: dict[str, Any],
                             workload: dict[str, Any],
                             preflight: dict[str, Any],
                             readiness: dict[str, Any]) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.reader(source))
    if len(rows) != 2:
        raise RunnerError("FHE-IND measurement must contain exactly one CSV row")
    header, row = rows
    if set(header) != FHE_MEASUREMENT_COLUMNS or \
       len(header) != len(FHE_MEASUREMENT_COLUMNS) or len(row) != len(header):
        raise RunnerError("FHE-IND measurement CSV header mismatch")
    data = dict(zip(header, row))
    if data.get("cell_id") != cell["cell_id"] or \
       data.get("status") != "MEASURED" or data.get("reason") != "":
        raise RunnerError("FHE-IND measurement terminal identity mismatch")
    if data.get("universe") != "64" or data.get("set_size") != "10" or \
       data.get("target_jaccard") != "0.5" or data.get("seed") != "7" or \
       data.get("trials") != "1" or data.get("realized_intersection") != "7" or \
       data.get("realized_union") != "13" or \
       data.get("realized_jaccard") != "0.53846153846153844":
        raise RunnerError("FHE-IND measurement workload geometry mismatch")
    if data.get("workload_id") != workload.get("workload_id") or \
       data.get("workload_manifest_sha256") != workload.get("manifest_sha256") or \
       data.get("timing_hash_seed") != str(derive_timing_hash_seed(workload["root_seed"])):
        raise RunnerError("FHE-IND measurement workload digest mismatch")
    try:
        context_data = dict(data)
        context_data["ordered_rns_moduli"] = json.loads(
            data["ordered_rns_moduli"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RunnerError("FHE-IND ordered RNS tuple is malformed") from exc
    _validate_fhe_context_tuple(context_data, cell, readiness)
    if context_data["ordered_rns_moduli"] != preflight.get("ordered_rns_moduli"):
        raise RunnerError("FHE-IND measurement/preflight RNS tuple mismatch")
    for key in ("bfv_context_fingerprint", "requested_ring_dim",
                "natural_ring_dim", "realized_ring_dim",
                "natural_depth", "provisioned_depth", "scaling_mod_size",
                "num_limbs", "plaintext_modulus", "context_tuple_sha256",
                "openfhe_version"):
        if data.get(key) != str(preflight.get(key)):
            raise RunnerError(f"FHE-IND measurement/preflight mismatch: {key}")
    try:
        if abs(float(data["log_q_bits"]) - float(preflight["log_q_bits"])) > 1e-9:
            raise RunnerError("FHE-IND measurement/preflight mismatch: log_q_bits")
    except (KeyError, TypeError, ValueError) as exc:
        raise RunnerError("FHE-IND measurement log_q_bits is malformed") from exc
    measured_rns_hash = ordered_rns_sha256(context_data["ordered_rns_moduli"])
    if data.get("ordered_rns_moduli_sha256") != measured_rns_hash or \
       measured_rns_hash != ordered_rns_sha256(preflight.get(
           "ordered_rns_moduli", [])):
        raise RunnerError("FHE-IND ordered RNS digest mismatch")
    _validate_csv_nonnegative(data, (
        "setup_context_ms", "setup_keygen_ms", "phase_encode_ms",
        "phase_encrypt_ms", "phase_evaluate_ms", "phase_decrypt_ms",
        "online_e2e_ms", "full_e2e_ms"))
    online = sum(float(data[field]) for field in (
        "phase_encode_ms", "phase_encrypt_ms", "phase_evaluate_ms",
        "phase_decrypt_ms"))
    full = float(data["setup_context_ms"]) + float(data["setup_keygen_ms"]) + online
    if not math.isclose(online, float(data["online_e2e_ms"]),
                        rel_tol=0.0, abs_tol=1e-9) or \
       not math.isclose(full, float(data["full_e2e_ms"]),
                        rel_tol=0.0, abs_tol=1e-9):
        raise RunnerError("FHE-IND timing totals do not reconcile")
    if data.get("match_count") != "7" or \
       not math.isclose(float(data.get("jaccard_estimate", "nan")),
                        7.0 / 13.0, rel_tol=0.0, abs_tol=1e-15):
        raise RunnerError("FHE-IND correctness does not bind the frozen workload")
    return data


def measurement_workload_binding(path: Path) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.reader(source))
    if len(rows) != 2:
        raise RunnerError("measurement binding requires one CSV row")
    data = dict(zip(rows[0], rows[1]))
    return {
        "workload_id": data["workload_id"],
        "workload_manifest_sha256": data["workload_manifest_sha256"],
        "timing_hash_seed": data["timing_hash_seed"],
        "match_count": data["match_count"],
        "jaccard_estimate": data["jaccard_estimate"],
    }


def bind_measurement_workload(manifest: dict[str, Any], path: Path) -> None:
    current = measurement_workload_binding(path)
    recorded = manifest.get("workload_binding")
    if recorded is not None and recorded != current:
        raise RunnerError("cells do not share the same workload/timing binding")
    manifest["workload_binding"] = current


def measure_cell(binary: Path, results_root: Path, cell: dict[str, Any],
                 calibration_path: Path, candidate: tuple[int, int],
                 workload: dict[str, Any], env: dict[str, str],
                 log: list[str]) -> Path:
    depth, scaling = candidate
    path = results_root / "measurements" / f"{cell['cell_id']}.csv"
    if path.exists():
        raise RunnerError(f"refusing to overwrite measurement artifact: {path}")
    command = [str(binary), "--mode=e2e", f"--circuit={cell['circuit']}",
               f"--security={cell['security']}", f"--shape-id={cell['shape_id']}",
               "--k=16", "--m=16", "--seed=7", f"--depth={depth}",
               f"--scaling-mod-size={scaling}", f"--calibration={calibration_path}",
               f"--workload={results_root / 'workload' / 'workload.json'}",
               "--format=csv", f"--output={path}"]
    if ACTIVE_SCHEMA_VERSION == "v2":
        command.insert(2, "--schema=v2")
    completed = run_process(command, env)
    log.append("$ " + " ".join(command))
    if completed.stdout:
        log.append(completed.stdout.rstrip())
    if completed.stderr:
        log.append(completed.stderr.rstrip())
    if completed.returncode != 0:
        raise RunnerError("e2e subprocess failed")
    validate_measurement(path, cell, workload, calibration_path)
    return path


def fhe_preflight_path(results_root: Path, cell_id: str) -> Path:
    return results_root / "preflight" / f"{cell_id}.json"


def fhe_measurement_path(results_root: Path, cell_id: str) -> Path:
    return results_root / "measurements" / f"{cell_id}.csv"


def assert_fhe_binary_stable(readiness: dict[str, Any], phase: str) -> None:
    # All FHE-IND subprocesses run from the private snapshot made during the
    # capability probe.  The original pathname is retained only as source
    # provenance and is never consulted for execution or stability checks.
    binary_value = readiness.get("execution_binary")
    expected = readiness.get("binary_sha256")
    if not isinstance(binary_value, str) or not is_sha256_hex(expected):
        raise RunnerError(f"{phase} producer identity is incomplete")
    try:
        observed = sha256_file(Path(binary_value))
    except OSError as exc:
        raise RunnerError(f"{phase} producer binary cannot be rehashed: {exc}") \
            from exc
    if observed != expected:
        raise RunnerError(f"{phase} producer snapshot changed after readiness probe")


def invoke_fhe_preflight(readiness: dict[str, Any], results_root: Path,
                         cell: dict[str, Any], workload: dict[str, Any],
                         env: dict[str, str], log: list[str], *,
                         resume: bool) -> tuple[Path, dict[str, Any]]:
    path = fhe_preflight_path(results_root, cell["cell_id"])
    command_base = [str(readiness["execution_binary"]), "--mode=preflight",
                    "--method=fhe_ind", "--circuit=fhe_ind",
                    f"--security={cell['security']}",
                    "--shape-id=fhe-indicator-v1", f"--cell-id={cell['cell_id']}",
                    "--universe=64",
                    "--set-size=10", "--target-jaccard=1/2", "--seed=7",
                    "--trials=1",
                    f"--workload={results_root / 'workload' / 'workload.json'}",
                    "--format=json"]
    if resume and path.exists():
        descriptor, temporary = tempfile.mkstemp(prefix="fhe-ind-preflight-",
                                                  suffix=".json")
        os.close(descriptor)
        temporary_path = Path(temporary)
        temporary_path.unlink()
        try:
            assert_fhe_binary_stable(readiness, "FHE-IND preflight before invocation")
            completed = run_process(command_base + [f"--output={temporary_path}"], env)
            assert_fhe_binary_stable(readiness, "FHE-IND preflight after invocation")
            if completed.returncode != 0:
                raise RunnerError("resume FHE-IND preflight derivation failed")
            regenerated = read_canonical_json(temporary_path)
            validate_fhe_preflight(regenerated, cell, workload, readiness)
            recorded = read_canonical_json(path)
            if canonical_json(regenerated) != canonical_json(recorded):
                raise RunnerError(
                    f"resume FHE-IND preflight does not match binary: {path.name}")
            log.append(f"REUSED_FHE_PREFLIGHT {path}")
            return path, recorded
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
    if path.exists():
        raise RunnerError(f"refusing to overwrite FHE-IND preflight artifact: {path}")
    assert_fhe_binary_stable(readiness, "FHE-IND preflight before invocation")
    completed = run_process(command_base + [f"--output={path}"], env)
    assert_fhe_binary_stable(readiness, "FHE-IND preflight after invocation")
    log.append("$ " + " ".join(command_base + [f"--output={path}"]))
    if completed.stdout:
        log.append(completed.stdout.rstrip())
    if completed.stderr:
        log.append(completed.stderr.rstrip())
    if completed.returncode != 0:
        raise RunnerError("FHE-IND preflight subprocess failed")
    data = read_canonical_json(path)
    validate_fhe_preflight(data, cell, workload, readiness)
    return path, data


def measure_fhe_cell(readiness: dict[str, Any], results_root: Path,
                     cell: dict[str, Any], workload: dict[str, Any],
                     preflight: dict[str, Any], env: dict[str, str],
                     log: list[str]) -> Path:
    path = fhe_measurement_path(results_root, cell["cell_id"])
    if path.exists():
        raise RunnerError(f"refusing to overwrite FHE-IND measurement artifact: {path}")
    assert_fhe_binary_stable(readiness, "FHE-IND e2e before invocation")
    command = [str(readiness["execution_binary"]), "--mode=e2e", "--method=fhe_ind",
               "--circuit=fhe_ind", f"--security={cell['security']}",
               "--shape-id=fhe-indicator-v1", f"--cell-id={cell['cell_id']}",
               "--universe=64", "--set-size=10",
               "--target-jaccard=1/2", "--seed=7", "--trials=1",
               f"--workload={results_root / 'workload' / 'workload.json'}",
               f"--preflight={fhe_preflight_path(results_root, cell['cell_id'])}",
               "--format=csv", f"--output={path}"]
    completed = run_process(command, env)
    assert_fhe_binary_stable(readiness, "FHE-IND e2e after invocation")
    log.append("$ " + " ".join(command))
    if completed.stdout:
        log.append(completed.stdout.rstrip())
    if completed.stderr:
        log.append(completed.stderr.rstrip())
    if completed.returncode != 0:
        raise RunnerError("FHE-IND e2e subprocess failed")
    validate_fhe_measurement(path, cell, workload, preflight, readiness)
    return path


def result_file(results_root: Path, raw_path: Any, label: str) -> Path:
    if not isinstance(raw_path, (str, os.PathLike)) or not raw_path:
        raise RunnerError(f"{label} path is missing")
    path = Path(raw_path)
    if not path.is_absolute():
        raise RunnerError(f"{label} path must be absolute")
    resolved_root = results_root.resolve()
    resolved_path = path.resolve(strict=False)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise RunnerError(f"{label} path escapes results root") from exc
    if not path.is_file():
        raise RunnerError(f"{label} artifact is missing: {path}")
    return path


def validate_resume_cell(manifest: dict[str, Any], results_root: Path,
                        cell: dict[str, Any], workload: dict[str, Any],
                        identity: dict[str, Any], binary: Path,
                        env: dict[str, str]) -> None:
    cell_id = cell["cell_id"]
    record = manifest.get("cells", {}).get(cell_id)
    if not isinstance(record, dict):
        raise RunnerError(f"resume cell record is missing: {cell_id}")
    status = record.get("status")
    if status == "ERROR":
        raise RunnerError(f"resume refuses prior ERROR cell: {cell_id}")
    if status not in ("MEASURED", "SKIPPED_PRECHECK"):
        raise RunnerError(f"invalid resumable status for {cell_id}")
    if record.get("trials") != 1 or record.get("calibration_repetitions") != 1:
        raise RunnerError(f"resume repetition contract mismatch: {cell_id}")
    if record.get("preflight_caps_recorded") is not True:
        raise RunnerError(f"resume preflight record is incomplete: {cell_id}")
    entries = record.get("preflight_caps")
    expected_candidates = CANDIDATES[cell["circuit"]]
    if not isinstance(entries, list) or len(entries) != len(expected_candidates):
        raise RunnerError(f"resume preflight candidate count mismatch: {cell_id}")
    artifact_record = manifest.get("artifacts", {}).get(cell_id)
    if not isinstance(artifact_record, dict):
        raise RunnerError(f"resume artifact manifest entry is missing: {cell_id}")
    artifact_preflights = artifact_record.get("preflights")
    if not isinstance(artifact_preflights, list) or \
       len(artifact_preflights) != len(expected_candidates):
        raise RunnerError(f"resume preflight artifact bindings are incomplete: {cell_id}")
    preflight_by_candidate: dict[tuple[int, int], dict[str, Any]] = {}
    for candidate, item, artifact in zip(expected_candidates, entries,
                                        artifact_preflights):
        if not isinstance(item, dict) or item.get("candidate") != list(candidate):
            raise RunnerError(f"resume preflight candidate identity mismatch: {cell_id}")
        path = result_file(
            results_root,
            results_root / "preflight" / candidate_name(cell_id, *candidate),
            f"{cell_id} preflight",
        )
        if not isinstance(artifact, dict) or artifact.get("path") != str(path) or \
           artifact.get("sha256") != sha256_file(path):
            raise RunnerError(f"resume preflight artifact hash mismatch: {cell_id}")
        validate_preflight_against_binary(
            path, binary, cell, candidate[0], candidate[1], env, identity)
        data = read_canonical_json(path)
        validate_preflight(data, cell, candidate[0], candidate[1], identity)
        expected_summary = {
            "candidate": list(candidate),
            "realized_ring_dim": data.get("realized_ring_dim"),
            "provisioned_depth": data.get("provisioned_depth"),
            "log_q_bits": data.get("log_q_bits"),
            "skipped": data.get("skipped"),
            "reason": data.get("reason"),
        }
        if item != expected_summary:
            raise RunnerError(f"resume preflight summary mismatch: {cell_id}")
        preflight_by_candidate[candidate] = data
        bind_embedded_identity(manifest, data)

    if status == "SKIPPED_PRECHECK":
        expected_reason = "; ".join(
            data["reason"] for data in preflight_by_candidate.values()
            if data["reason"]
        )
        if not expected_reason or record.get("reason") != expected_reason or \
           record.get("keygen_started") is not False or \
           record.get("calibration_started") is not False or \
           record.get("e2e_started") is not False:
            raise RunnerError(f"resume preflight skip contract mismatch: {cell_id}")
        if any(not data["skipped"] for data in preflight_by_candidate.values()):
            raise RunnerError(f"resume skip lacks a cap violation: {cell_id}")
        if "calibration" in artifact_record or "measurement" in artifact_record or \
           any(record.get(key) is not None for key in (
               "candidate", "calibration_path", "calibration_sha256",
               "measurement_path", "measurement_sha256")):
            raise RunnerError(f"resume skip contains measured artifacts: {cell_id}")
        return

    if record.get("keygen_started") is not True or \
       record.get("calibration_started") is not True or \
       record.get("e2e_started") is not True or \
       record.get("reason") != "":
        raise RunnerError(f"resume measured stage contract mismatch: {cell_id}")
    candidate_value = record.get("candidate")
    if not isinstance(candidate_value, list) or len(candidate_value) != 2:
        raise RunnerError(f"resume measured candidate is missing: {cell_id}")
    candidate = (candidate_value[0], candidate_value[1])
    if candidate not in preflight_by_candidate or preflight_by_candidate[candidate]["skipped"]:
        raise RunnerError(f"resume measured candidate is not feasible: {cell_id}")
    calibration_path = result_file(
        results_root, record.get("calibration_path"), f"{cell_id} calibration")
    expected_calibration = results_root / "calibration" / f"{cell_id}.json"
    if calibration_path.resolve() != expected_calibration.resolve():
        raise RunnerError(f"resume calibration path mismatch: {cell_id}")
    calibration_hash = sha256_file(calibration_path)
    if record.get("calibration_sha256") != calibration_hash:
        raise RunnerError(f"resume calibration hash mismatch: {cell_id}")
    calibration_binding = artifact_record.get("calibration")
    if not isinstance(calibration_binding, dict) or \
       calibration_binding.get("path") != str(calibration_path) or \
       calibration_binding.get("sha256") != calibration_hash:
        raise RunnerError(f"resume calibration artifact binding mismatch: {cell_id}")
    calibration = read_canonical_json(calibration_path)
    validate_calibration(calibration, cell, candidate[0], candidate[1],
                         preflight_by_candidate[candidate])
    measurement_path = result_file(
        results_root, record.get("measurement_path"), f"{cell_id} measurement")
    expected_measurement = results_root / "measurements" / f"{cell_id}.csv"
    if measurement_path.resolve() != expected_measurement.resolve():
        raise RunnerError(f"resume measurement path mismatch: {cell_id}")
    measurement_hash = sha256_file(measurement_path)
    if record.get("measurement_sha256") != measurement_hash:
        raise RunnerError(f"resume measurement hash mismatch: {cell_id}")
    measurement_binding = artifact_record.get("measurement")
    if not isinstance(measurement_binding, dict) or \
       measurement_binding.get("path") != str(measurement_path) or \
       measurement_binding.get("sha256") != measurement_hash:
        raise RunnerError(f"resume measurement artifact binding mismatch: {cell_id}")
    validate_measurement(measurement_path, cell, workload, calibration_path)
    bind_measurement_workload(manifest, measurement_path)


def validate_fhe_resume_cell(manifest: dict[str, Any], results_root: Path,
                             cell: dict[str, Any], workload: dict[str, Any],
                             readiness: dict[str, Any], env: dict[str, str]) -> None:
    cell_id = cell["cell_id"]
    record = manifest.get("cells", {}).get(cell_id)
    artifacts = manifest.get("artifacts", {}).get(cell_id)
    if not isinstance(record, dict) or not isinstance(artifacts, dict):
        raise RunnerError(f"resume FHE-IND cell record is missing: {cell_id}")
    if record.get("cell_id") != cell_id or record.get("trials") != 1 or \
       record.get("calibration_repetitions") != 1 or \
       record.get("calibration_applicable") is not False:
        raise RunnerError(f"resume FHE-IND repetition/identity mismatch: {cell_id}")
    status = record.get("status")
    if status == "DEFERRED_FHE_IND_NOT_READY":
        if readiness.get("ready") or record.get("reason") != readiness.get("reason") or \
           record.get("keygen_started") or record.get("calibration_started") or \
           record.get("e2e_started") or artifacts.get("preflight") is not None or \
           artifacts.get("measurement") is not None:
            raise RunnerError(f"resume deferred FHE-IND contract mismatch: {cell_id}")
        return
    if status not in ("MEASURED", "SKIPPED_PRECHECK") or \
       not readiness.get("ready") or \
       record.get("calibration_started") is not False or \
       record.get("preflight_caps_recorded") is not True:
        raise RunnerError(f"resume FHE-IND measured stage mismatch: {cell_id}")
    if status == "MEASURED" and (
            record.get("keygen_started") is not True or
            record.get("e2e_started") is not True or record.get("reason") != ""):
        raise RunnerError(f"resume FHE-IND measured stage mismatch: {cell_id}")
    if status == "SKIPPED_PRECHECK" and (
            record.get("keygen_started") is not False or
            record.get("e2e_started") is not False):
        raise RunnerError(f"resume FHE-IND skip stage mismatch: {cell_id}")
    preflight_binding = artifacts.get("preflight")
    measurement_binding = artifacts.get("measurement")
    preflight_path = result_file(results_root,
                                 preflight_binding.get("path")
                                 if isinstance(preflight_binding, dict) else None,
                                 f"{cell_id} FHE-IND preflight")
    expected_preflight = fhe_preflight_path(results_root, cell_id)
    if preflight_path.resolve() != expected_preflight.resolve() or \
       preflight_binding.get("sha256") != sha256_file(preflight_path) or \
       record.get("preflight_path") != str(preflight_path) or \
       record.get("preflight_sha256") != sha256_file(preflight_path):
        raise RunnerError(f"resume FHE-IND preflight binding mismatch: {cell_id}")
    _, preflight = invoke_fhe_preflight(
        readiness, results_root, cell, workload, env, [], resume=True)
    if status == "SKIPPED_PRECHECK":
        if not preflight.get("skipped") or record.get("reason") != \
           preflight.get("reason") or set(artifacts) - {"preflight", "log"}:
            raise RunnerError(f"resume FHE-IND skip contract mismatch: {cell_id}")
        return
    measurement_path = result_file(
        results_root,
        measurement_binding.get("path") if isinstance(measurement_binding, dict)
        else None,
        f"{cell_id} FHE-IND measurement")
    expected_measurement = fhe_measurement_path(results_root, cell_id)
    if measurement_path.resolve() != expected_measurement.resolve() or \
       measurement_binding.get("sha256") != sha256_file(measurement_path):
        raise RunnerError(f"resume FHE-IND measurement binding mismatch: {cell_id}")
    if record.get("measurement_path") != str(measurement_path) or \
       record.get("measurement_sha256") != sha256_file(measurement_path):
        raise RunnerError(f"resume FHE-IND measurement hash mismatch: {cell_id}")
    validate_fhe_measurement(measurement_path, cell, workload, preflight, readiness)


def fhe_terminal_record(cell: dict[str, Any], status: str, reason: str,
                        *, keygen: bool, e2e: bool,
                        preflight_recorded: bool = False) -> dict[str, Any]:
    return {
        "cell_id": cell["cell_id"],
        "status": status,
        "reason": reason,
        "keygen_started": keygen,
        "calibration_started": False,
        "e2e_started": e2e,
        "trials": 1,
        "calibration_repetitions": 1,
        "calibration_applicable": False,
        "preflight_caps_recorded": preflight_recorded,
        "preflight_caps": [],
    }


def terminal_record(cell: dict[str, Any], status: str, reason: str,
                    *, keygen: bool, calibration: bool, e2e: bool,
                    preflights: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cell_id": cell["cell_id"],
        "status": status,
        "reason": reason,
        "keygen_started": keygen,
        "calibration_started": calibration,
        "e2e_started": e2e,
        "trials": 1,
        "calibration_repetitions": 1,
        "preflight_caps_recorded": bool(preflights),
        "preflight_caps": [
            {
                "candidate": item["candidate"],
                "realized_ring_dim": item["data"].get("realized_ring_dim"),
                "provisioned_depth": item["data"].get("provisioned_depth"),
                "log_q_bits": item["data"].get("log_q_bits"),
                "skipped": item["data"].get("skipped"),
                "reason": item["data"].get("reason"),
            }
            for item in preflights
        ],
    }


def terminal_tsv_bytes(cells: dict[str, Any],
                       cell_tuples: tuple | None = None) -> bytes:
    lines = ["cell_id\tstatus\treason\tartifact_sha256"]
    ordered = CORE_CELLS if cell_tuples is None else cell_tuples
    for cell_id in (item[0] for item in ordered):
        record = cells.get(cell_id, {})
        artifact_hash = record.get("measurement_sha256") or record.get("calibration_sha256") or ""
        reason = str(record.get("reason", "")).replace("\t", " ").replace("\r", " ").replace("\n", " ")
        lines.append("\t".join((cell_id, str(record.get("status", "")),
                                reason, str(artifact_hash))))
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_terminal_tsv(path: Path, cells: dict[str, Any],
                       cell_tuples: tuple | None = None) -> None:
    atomic_write(path, terminal_tsv_bytes(cells, cell_tuples))


def bind_control_artifacts(manifest: dict[str, Any], results_root: Path,
                           cell_tuples: tuple | None = None) -> None:
    artifacts = manifest.setdefault("artifacts", {})
    terminal_path = results_root / "terminal-cells.tsv"
    if terminal_path.exists():
        artifacts["terminal-cells.tsv"] = {
            "path": str(terminal_path), "sha256": sha256_file(terminal_path),
        }
    ordered = CORE_CELLS if cell_tuples is None else cell_tuples
    for cell_tuple in ordered:
        cell_id = cell_tuple[0]
        log_path = results_root / "logs" / f"{cell_id}.log"
        if log_path.exists():
            artifacts.setdefault(cell_id, {})["log"] = {
                "path": str(log_path), "sha256": sha256_file(log_path),
            }


def validate_control_artifacts(manifest: dict[str, Any], results_root: Path,
                              cell_tuples: tuple | None = None) -> None:
    artifacts = manifest.get("artifacts", {})
    cells = manifest.get("cells")
    if not isinstance(cells, dict):
        raise RunnerError("resume manifest cell table is malformed")
    ordered = CORE_CELLS if cell_tuples is None else cell_tuples
    core_ids = {cell[0] for cell in ordered}
    if set(cells) - core_ids:
        raise RunnerError("resume manifest contains an unknown cell")
    terminal_path = results_root / "terminal-cells.tsv"
    terminal = artifacts.get("terminal-cells.tsv")
    if not isinstance(terminal, dict) or terminal.get("path") != str(terminal_path) or \
       not terminal_path.is_file() or terminal.get("sha256") != sha256_file(terminal_path):
        raise RunnerError("resume terminal-cells artifact binding mismatch")
    if terminal_path.read_bytes() != terminal_tsv_bytes(manifest.get("cells", {}),
                                                       ordered):
        raise RunnerError("resume terminal-cells semantic binding mismatch")
    for cell_tuple in ordered:
        cell_id = cell_tuple[0]
        log_path = results_root / "logs" / f"{cell_id}.log"
        if cell_id not in cells:
            # A process can stop after the previous terminal checkpoint but
            # before starting this cell.  Its blank terminal row is valid;
            # any existing preflight/calibration files are revalidated when
            # the missing cell is resumed.
            continue
        binding = artifacts.get(cell_id, {}).get("log")
        if not isinstance(binding, dict) or binding.get("path") != str(log_path) or \
           not log_path.is_file() or binding.get("sha256") != sha256_file(log_path):
            raise RunnerError(f"resume log artifact binding mismatch: {cell_id}")


def validate_summary_artifacts(manifest: dict[str, Any],
                               results_root: Path) -> None:
    """Reject stale, forged, or unbound paired reports on resume."""

    summary_dir = results_root / "summary"
    summary_metadata = manifest.get("summary")
    summary_binding = manifest.get("artifacts", {}).get("summary")
    existing_files = [summary_dir / name for name in SUMMARY_FILES
                      if (summary_dir / name).exists()]
    if summary_metadata is None and summary_binding is None:
        if existing_files:
            raise RunnerError("resume summary artifacts are unbound")
        return
    gate = manifest.get("identity", {}).get("fhe_ind", {})
    expected_pair_ids = ["onehot", "sqrt"]
    if isinstance(gate, dict) and gate.get("mode") != "off":
        expected_pair_ids.append("fhe_ind")
    expected_summary_schema = "piccard-std-security-tuple-summary-v2" \
        if ACTIVE_SCHEMA_VERSION == "v2" else SUMMARY_SCHEMA
    if summary_metadata != {
            "schema": expected_summary_schema,
            "status": "GENERATED",
            "pair_ids": expected_pair_ids,
    }:
        raise RunnerError("resume summary metadata mismatch")
    if not isinstance(summary_binding, dict) or \
       set(summary_binding) != set(SUMMARY_FILES):
        raise RunnerError("resume summary artifact bindings are incomplete")
    for name in SUMMARY_FILES:
        binding = summary_binding.get(name)
        if not isinstance(binding, dict):
            raise RunnerError(f"resume summary binding is malformed: {name}")
        path = result_file(results_root, binding.get("path"),
                           f"summary {name}")
        expected = summary_dir / name
        if path.resolve() != expected.resolve() or \
           binding.get("sha256") != sha256_file(path):
            raise RunnerError(f"resume summary artifact hash mismatch: {name}")


def record_partial_cell_artifacts(manifest: dict[str, Any], results_root: Path,
                                  cell_id: str,
                                  preflights: list[dict[str, Any]]) -> None:
    """Bind every artifact that exists even when a cell terminates ERROR."""

    record: dict[str, Any] = {"preflights": []}
    for item in preflights:
        path = results_root / "preflight" / candidate_name(cell_id, *item["candidate"])
        if path.is_file():
            record["preflights"].append({
                "path": str(path), "sha256": sha256_file(path),
            })
    calibration_path = results_root / "calibration" / f"{cell_id}.json"
    if calibration_path.is_file():
        record["calibration"] = {
            "path": str(calibration_path), "sha256": sha256_file(calibration_path),
        }
    measurement_path = results_root / "measurements" / f"{cell_id}.csv"
    if measurement_path.is_file():
        record["measurement"] = {
            "path": str(measurement_path), "sha256": sha256_file(measurement_path),
        }
    manifest.setdefault("artifacts", {})[cell_id] = record


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    atomic_write(path, canonical_json(manifest))


def process_fhe_cells(manifest: dict[str, Any], manifest_path: Path,
                      results_root: Path, workload: dict[str, Any],
                      readiness: dict[str, Any], env: dict[str, str],
                      *, resume: bool, cell_order: tuple) -> bool:
    """Terminalize the two FHE-IND cells after the explicit readiness gate."""

    failed = False
    if not readiness.get("ready"):
        for cell_tuple in FHE_IND_CELLS:
            cell = cell_dict(cell_tuple)
            cell_id = cell["cell_id"]
            if resume and cell_id in manifest["cells"]:
                continue
            record = fhe_terminal_record(
                cell, "DEFERRED_FHE_IND_NOT_READY", readiness["reason"],
                keygen=False, e2e=False)
            manifest["cells"][cell_id] = record
            manifest["artifacts"][cell_id] = {}
            atomic_write(results_root / "logs" / f"{cell_id}.log",
                         (readiness["reason"] + "\n").encode("utf-8"))
            write_terminal_tsv(results_root / "terminal-cells.tsv",
                                manifest["cells"], cell_order)
            bind_control_artifacts(manifest, results_root, cell_order)
            write_manifest(manifest_path, manifest)
        return False

    for cell_tuple in FHE_IND_CELLS:
        cell = cell_dict(cell_tuple)
        cell_id = cell["cell_id"]
        if resume and cell_id in manifest["cells"]:
            continue
        log: list[str] = []
        preflight_path: Path | None = None
        measurement_path: Path | None = None
        try:
            preflight_path, preflight = invoke_fhe_preflight(
                readiness, results_root, cell, workload, env, log,
                resume=resume)
            if preflight.get("skipped"):
                record = fhe_terminal_record(
                    cell, "SKIPPED_PRECHECK", preflight["reason"],
                    keygen=False, e2e=False, preflight_recorded=True)
                record.update({
                    "preflight_path": str(preflight_path),
                    "preflight_sha256": sha256_file(preflight_path),
                })
                manifest["cells"][cell_id] = record
                manifest["artifacts"][cell_id] = {
                    "preflight": {"path": str(preflight_path),
                                   "sha256": record["preflight_sha256"]},
                }
            else:
                record = fhe_terminal_record(cell, "MEASURED", "", keygen=True,
                                             e2e=True, preflight_recorded=True)
                measurement_path = measure_fhe_cell(
                    readiness, results_root, cell, workload, preflight, env, log)
                record.update({
                    "preflight_path": str(preflight_path),
                    "preflight_sha256": sha256_file(preflight_path),
                    "measurement_path": str(measurement_path),
                    "measurement_sha256": sha256_file(measurement_path),
                })
                manifest["cells"][cell_id] = record
                manifest["artifacts"][cell_id] = {
                    "preflight": {"path": str(preflight_path),
                                   "sha256": record["preflight_sha256"]},
                    "measurement": {"path": str(measurement_path),
                                     "sha256": record["measurement_sha256"]},
                }
        except RunnerError as exc:
            failed = True
            partial: dict[str, Any] = {}
            if preflight_path is not None and preflight_path.is_file():
                partial["preflight"] = {
                    "path": str(preflight_path),
                    "sha256": sha256_file(preflight_path),
                }
            if measurement_path is not None and measurement_path.is_file():
                partial["measurement"] = {
                    "path": str(measurement_path),
                    "sha256": sha256_file(measurement_path),
                }
            manifest["artifacts"][cell_id] = partial
            manifest["cells"][cell_id] = fhe_terminal_record(
                cell, "ERROR", str(exc), keygen=preflight_path is not None,
                e2e=measurement_path is not None,
                preflight_recorded=preflight_path is not None)
        atomic_write(results_root / "logs" / f"{cell_id}.log",
                     ("\n".join(log) + "\n").encode("utf-8"))
        write_terminal_tsv(results_root / "terminal-cells.tsv",
                           manifest["cells"], cell_order)
        bind_control_artifacts(manifest, results_root, cell_order)
        write_manifest(manifest_path, manifest)
    return failed


def bind_embedded_identity(manifest: dict[str, Any], data: dict[str, Any]) -> None:
    current = embedded_identity(data)
    identity = manifest.setdefault("identity", {})
    recorded = identity.get("embedded")
    if recorded is not None and recorded != current:
        raise RunnerError("inconsistent embedded build/OpenFHE provenance")
    identity["embedded"] = current


def fhe_gate_identity(include_fhe: str, readiness: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": include_fhe,
        "ready": bool(readiness.get("ready")),
        "reason": readiness.get("reason"),
        "binary": readiness.get("binary"),
        "binary_sha256": readiness.get("binary_sha256"),
        "snapshot_sha256": readiness.get("snapshot_sha256"),
        "capabilities_sha256": readiness.get("capabilities_sha256"),
    }


def dry_run(binary: Path | None, results_root: Path | None,
            include_fhe: str, readiness: dict[str, Any]) -> int:
    prospective_cells = CORE_CELLS
    payload = {
        "schema": "piccard-std-security-dry-run-v1",
        "cells": [cell_dict(cell) for cell in prospective_cells],
        "candidates": {
            circuit: [{"provisioned_depth": depth, "scaling_mod_size": scaling}
                       for depth, scaling in proposals]
            for circuit, proposals in CANDIDATES.items()
        },
        "caps": {"realized_ring_dim": CAP_RING, "provisioned_depth": CAP_DEPTH,
                 "log_q_bits": CAP_LOG_Q},
        "include_fhe_ind": include_fhe,
        "fhe_ind_readiness": {
            key: value for key, value in readiness.items()
            if key not in ("capabilities", "execution_binary", "_snapshot_guard")
        },
        "fhe_ind_cells": [cell_dict(cell) for cell in FHE_IND_CELLS]
        if include_fhe != "off" else [],
        "prospective_results_root": str(results_root) if results_root else None,
        "prospective_paths": {
            "workload": str(results_root / "workload" / "workload.json")
            if results_root else "<results-root>/workload/workload.json",
            "measurements": [
                str(results_root / "measurements" / f"{cell[0]}.csv")
                if results_root else f"<results-root>/measurements/{cell[0]}.csv"
                for cell in prospective_cells
            ],
            "fhe_ind_measurements": [
                str(results_root / "measurements" / f"{cell[0]}.csv")
                if results_root else f"<results-root>/measurements/{cell[0]}.csv"
                for cell in FHE_IND_CELLS
            ] if include_fhe != "off" else [],
        },
        "binary": str(binary) if binary else None,
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def process(args: argparse.Namespace) -> int:
    global ACTIVE_SCHEMA_VERSION
    ACTIVE_SCHEMA_VERSION = args.schema
    binary = binary_path(Path(args.build_dir))
    env = command_env()
    fhe_binary = Path(args.fhe_ind_binary).resolve() \
        if args.fhe_ind_binary else None
    if args.include_fhe_ind == "off":
        readiness = {
            "ready": False,
            "reason": "readiness disabled: FHE-IND inclusion is off",
            "binary": None,
            "binary_sha256": None,
            "snapshot_sha256": None,
            "capabilities_sha256": None,
        }
    else:
        readiness = probe_fhe_ind(fhe_binary, env)
        if args.include_fhe_ind == "require" and not readiness.get("ready"):
            raise RunnerError(readiness["reason"])
    fhe_ready = bool(readiness.get("ready"))
    cell_order = active_cells(args.include_fhe_ind, fhe_ready=fhe_ready)
    raw_results_root = Path(args.results_root) if args.results_root else None
    if raw_results_root is not None and not raw_results_root.is_absolute():
        raise RunnerError("--results-root must be absolute")
    results_root = raw_results_root.resolve() if raw_results_root else None
    if args.dry_run:
        if results_root:
            validate_outside_results(results_root)
        return dry_run(binary, results_root, args.include_fhe_ind, readiness)
    if results_root is None:
        raise RunnerError("--results-root is required unless --dry-run is used")
    validate_outside_results(results_root)
    identity = source_identity()
    binary_hash = sha256_file(binary)
    if results_root.exists() and not args.resume:
        raise RunnerError("results root exists; use --resume only for validated state")
    if args.resume and not results_root.exists():
        raise RunnerError("--resume requires an existing results root")
    if not results_root.exists():
        results_root.mkdir(parents=True)
    for name in ("workload", "preflight", "calibration", "measurements", "logs", "summary"):
        (results_root / name).mkdir(exist_ok=True)

    manifest_path = results_root / "manifest.json"
    manifest_schema = "piccard-std-security-evidence-manifest-v2" \
        if args.schema == "v2" else "piccard-std-security-evidence-manifest-v1"
    if args.resume:
        manifest = read_canonical_json(manifest_path)
        if manifest.get("schema") != manifest_schema:
            raise RunnerError("resume manifest schema mismatch")
        recorded = manifest.get("identity", {})
        if recorded.get("source_commit") != identity["source_commit"] or \
           recorded.get("source_dirty") != identity["source_dirty"] or \
           recorded.get("binary_sha256") != binary_hash or \
           recorded.get("threads") != 1 or \
           recorded.get("thread_environment") != {
               "OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"
           } or recorded.get("fhe_ind") != fhe_gate_identity(
               args.include_fhe_ind, readiness):
            raise RunnerError("resume source/binary identity mismatch")
    else:
        manifest = {
            "schema": manifest_schema,
            "artifact_schema": args.schema,
            "identity": {
                **identity,
                "binary": str(binary),
                "binary_sha256": binary_hash,
                "build_dir": str(Path(args.build_dir).resolve()),
                "threads": 1,
                "thread_environment": {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"},
                "os": platform.platform(),
                "cpu": platform.machine(),
                "fhe_ind": fhe_gate_identity(args.include_fhe_ind, readiness),
            },
            "cells": {},
            "artifacts": {},
        }

    workload_path = results_root / "workload" / "workload.json"
    if workload_path.exists():
        workload = validate_workload(workload_path)
    elif args.resume:
        raise RunnerError("resume workload artifact is missing")
    else:
        workload = invoke_workload(binary, workload_path, env)
    if args.resume:
        validate_workload_against_binary(workload_path, binary, env)
        workload_artifact = manifest.get("artifacts", {}).get("workload", {})
        if workload_artifact.get("path") != str(workload_path) or \
           workload_artifact.get("sha256") != sha256_file(workload_path):
            raise RunnerError("resume workload artifact binding mismatch")
        validate_control_artifacts(manifest, results_root, cell_order)
        validate_summary_artifacts(manifest, results_root)
        recorded_embedded = manifest.get("identity", {}).get("embedded")
        if not isinstance(recorded_embedded, dict):
            raise RunnerError("resume embedded build provenance is missing")
        if recorded_embedded.get("build_type") != "Release" or \
           recorded_embedded.get("build_dirty") != identity["source_dirty"]:
            raise RunnerError("resume embedded build provenance mismatch")
        for cell_tuple in CORE_CELLS:
            if cell_tuple[0] in manifest["cells"]:
                validate_resume_cell(manifest, results_root,
                                     cell_dict(cell_tuple), workload, identity,
                                     binary, env)
        for cell_tuple in FHE_IND_CELLS:
            if cell_tuple[0] in manifest["cells"]:
                validate_fhe_resume_cell(
                    manifest, results_root, cell_dict(cell_tuple), workload,
                    readiness, env)
    manifest["artifacts"]["workload"] = {
        "path": str(workload_path), "sha256": sha256_file(workload_path),
    }
    write_manifest(manifest_path, manifest)
    failed = False

    for cell_tuple in CORE_CELLS:
        cell = cell_dict(cell_tuple)
        cell_id = cell["cell_id"]
        existing = manifest["cells"].get(cell_id)
        if args.resume and existing:
            if existing.get("status") == "ERROR":
                raise RunnerError(f"resume refuses prior ERROR cell: {cell_id}")
            if existing.get("status") not in ("MEASURED", "SKIPPED_PRECHECK"):
                raise RunnerError(f"invalid resumable status for {cell_id}")
            measurement = existing.get("measurement_path")
            if existing.get("status") == "MEASURED":
                if not measurement or sha256_file(Path(measurement)) != existing.get("measurement_sha256"):
                    raise RunnerError(f"resume measurement hash mismatch: {cell_id}")
            continue

        log: list[str] = []
        preflights: list[dict[str, Any]] = []
        feasible: list[tuple[tuple[int, int], dict[str, Any]]] = []
        calibration_path: Path | None = None
        measurement_path: Path | None = None
        keygen_started = False
        calibration_started = False
        e2e_started = False
        try:
            for candidate in CANDIDATES[cell["circuit"]]:
                depth, scaling = candidate
                data = preflight_candidate(binary, results_root, cell, depth,
                                            scaling, env, log, identity,
                                            resume=args.resume)
                bind_embedded_identity(manifest, data)
                preflights.append({"candidate": [depth, scaling], "data": data})
                if not data["skipped"]:
                    feasible.append((candidate, data))
            if not feasible:
                reasons = "; ".join(
                    item["data"].get("reason", "") for item in preflights
                    if item["data"].get("reason"))
                record = terminal_record(cell, "SKIPPED_PRECHECK", reasons,
                                         keygen=False, calibration=False, e2e=False,
                                         preflights=preflights)
                manifest["cells"][cell_id] = record
                manifest["artifacts"][cell_id] = {
                    "preflights": [
                        {"path": str(results_root / "preflight" /
                                      candidate_name(cell_id, *item["candidate"])),
                         "sha256": sha256_file(results_root / "preflight" /
                                                candidate_name(cell_id, *item["candidate"]))}
                        for item in preflights
                    ]
                }
                atomic_write(results_root / "logs" / f"{cell_id}.log",
                             ("\n".join(log) + "\n").encode("utf-8"))
                write_terminal_tsv(results_root / "terminal-cells.tsv",
                                   manifest["cells"], cell_order)
                bind_control_artifacts(manifest, results_root, cell_order)
                write_manifest(manifest_path, manifest)
                continue

            chosen: tuple[tuple[int, int], dict[str, Any]] | None = None
            calibration_errors: list[str] = []
            for candidate, preflight in sorted(
                    feasible,
                    key=lambda item: (item[1]["realized_ring_dim"],
                                      item[1]["log_q_bits"], item[0][0], item[0][1])):
                try:
                    calibration_started = True
                    keygen_started = True
                    calibration_path = calibrate_candidate(
                        binary, results_root, cell, candidate[0], candidate[1],
                        preflight, env, log, resume=args.resume)
                    chosen = (candidate, preflight)
                    break
                except CalibrationInfeasible as exc:
                    calibration_errors.append(str(exc))
            if calibration_path is None or chosen is None:
                raise RunnerError("no feasible calibration: " + "; ".join(calibration_errors))

            e2e_started = True
            measurement_path = measure_cell(binary, results_root, cell,
                                            calibration_path, chosen[0], workload,
                                            env, log)
            bind_measurement_workload(manifest, measurement_path)
            record = terminal_record(cell, "MEASURED", "", keygen=True,
                                     calibration=True, e2e=True,
                                     preflights=preflights)
            record.update({
                "candidate": list(chosen[0]),
                "calibration_path": str(calibration_path),
                "calibration_sha256": sha256_file(calibration_path),
                "measurement_path": str(measurement_path),
                "measurement_sha256": sha256_file(measurement_path),
            })
            manifest["artifacts"][cell_id] = {
                "preflights": [
                    {"path": str(results_root / "preflight" /
                                  candidate_name(cell_id, *item["candidate"])),
                     "sha256": sha256_file(results_root / "preflight" /
                                            candidate_name(cell_id, *item["candidate"]))}
                    for item in preflights
                ],
                "calibration": {"path": str(calibration_path),
                                "sha256": record["calibration_sha256"]},
                "measurement": {"path": str(measurement_path),
                                 "sha256": record["measurement_sha256"]},
            }
        except RunnerError as exc:
            failed = True
            record_partial_cell_artifacts(manifest, results_root, cell_id, preflights)
            record = terminal_record(cell, "ERROR", str(exc),
                                     keygen=keygen_started,
                                     calibration=calibration_started,
                                     e2e=e2e_started, preflights=preflights)
            manifest["cells"][cell_id] = record
        else:
            manifest["cells"][cell_id] = record
        atomic_write(results_root / "logs" / f"{cell_id}.log",
                     ("\n".join(log) + "\n").encode("utf-8"))
        write_terminal_tsv(results_root / "terminal-cells.tsv",
                           manifest["cells"], cell_order)
        bind_control_artifacts(manifest, results_root, cell_order)
        write_manifest(manifest_path, manifest)

    if args.include_fhe_ind != "off":
        failed = process_fhe_cells(
            manifest, manifest_path, results_root, workload, readiness, env,
            resume=args.resume, cell_order=cell_order) or failed
    manifest["complete"] = not failed and all(
        manifest["cells"].get(cell[0], {}).get("status") in
        ("MEASURED", "SKIPPED_PRECHECK", "DEFERRED_FHE_IND_NOT_READY")
        for cell in cell_order)
    write_manifest(manifest_path, manifest)
    return 2 if failed or not manifest["complete"] else 0


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--results-root")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--include-fhe-ind", choices=("auto", "require", "off"),
                        default="auto")
    parser.add_argument("--fhe-ind-binary")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--schema", choices=("v1", "v2"), default="v1")
    args = parser.parse_args(list(argv))
    if args.threads != 1:
        parser.error("--threads is frozen at 1")
    if args.include_fhe_ind == "require" and not args.fhe_ind_binary:
        parser.error("--fhe-ind-binary is mandatory with --include-fhe-ind=require")
    if args.fhe_ind_binary and not Path(args.fhe_ind_binary).is_absolute():
        parser.error("--fhe-ind-binary must be absolute")
    return args


def main(argv: Iterable[str] | None = None) -> int:
    try:
        return process(parse_args(sys.argv[1:] if argv is None else argv))
    except RunnerError as exc:
        print(f"run_std_security_evidence: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
