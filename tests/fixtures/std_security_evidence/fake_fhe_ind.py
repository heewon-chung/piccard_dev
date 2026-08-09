#!/usr/bin/env python3
"""Strict protocol fixture for the Phase 6 FHE-IND readiness tests."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from pathlib import Path


CAPABILITIES = {
    "schema": "piccard-std-security-fhe-ind-capabilities-v1",
    "method": "fhe_ind",
    "context_only_preflight": True,
    "exactly_one_run": True,
    "security_profiles": ["STD128", "STD192"],
    "workload": {"universe": 64, "set_size": 10,
                  "target_jaccard": "1/2", "seed": 7, "trials": 1},
    "context_tuple_fields": [
        "bfv_context_fingerprint", "circuit", "shape_id", "k", "m",
        "sanitizer_profile", "security", "requested_ring_dim",
        "natural_ring_dim", "natural_depth", "realized_ring_dim",
        "plaintext_modulus", "provisioned_depth", "scaling_mod_size",
        "num_limbs", "ordered_rns_moduli", "openfhe_version",
        "log_q_bits", "context_tuple_sha256",
    ],
    "provenance": {"diagnostic_only": True,
                   "piccard_sanitizer_applicable": False,
                   "threshold_enabled": False},
}
MODULI = ["1000000007", "1000000009"]


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()


def write_json(path: Path, value: dict) -> None:
    path.write_bytes(canonical(value))


def ordered_hash() -> str:
    framed = b"".join(len(item.encode()).to_bytes(4, "big") + item.encode()
                      for item in MODULI)
    return hashlib.sha256(framed).hexdigest()


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--capabilities", action="store_true")
    parser.add_argument("--mode")
    parser.add_argument("--method")
    parser.add_argument("--circuit")
    parser.add_argument("--security", default="STD128")
    parser.add_argument("--shape-id")
    parser.add_argument("--cell-id")
    parser.add_argument("--universe", type=int)
    parser.add_argument("--set-size", type=int)
    parser.add_argument("--target-jaccard")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--trials", type=int)
    parser.add_argument("--output")
    parser.add_argument("--workload")
    parser.add_argument("--preflight")
    parser.add_argument("--format", default="json")
    return parser.parse_args()


def context(args: argparse.Namespace) -> dict:
    if os.environ.get("FAKE_FHE_OVERSIZE") == "1":
        ring = 65536
    else:
        ring = 8192 if args.security == "STD128" else 16384
    return {
        "cell_id": "",
        "bfv_context_fingerprint": hashlib.sha256(
            f"fhe-ind|{args.security}".encode()).hexdigest(),
        "build_id": "fake-fhe-build-v1", "build_dirty": True,
        "build_type": "Release", "source_commit": "fake-source",
        "method": "fhe_ind", "circuit": "fhe_ind",
        "shape_id": "fhe-indicator-v1", "security": args.security,
        "k": "N/A", "m": "N/A", "universe": 64, "set_size": 10,
        "target_jaccard": "1/2", "seed": 7, "trials": 1,
        "requested_ring_dim": ring, "natural_ring_dim": ring,
        "natural_depth": 1, "realized_ring_dim": ring,
        "plaintext_modulus": 65537,
        "provisioned_depth": 10 if os.environ.get("FAKE_FHE_OVERSIZE") == "1" else 2,
        "scaling_mod_size": 40, "num_limbs": len(MODULI),
        "ordered_rns_moduli": MODULI,
        "log_q_bits": 200,
        "openfhe_version": "fake-openfhe-1",
        "sanitizer_profile": "not-applicable",
        "calibration_origin": "not-applicable",
        "context_tuple_sha256": hashlib.sha256(
            f"tuple|{args.security}".encode()).hexdigest(),
        "diagnostic_only": True, "table_eligible": False,
    }


def validate_request(parsed: argparse.Namespace, expected_mode: str) -> None:
    if parsed.mode != expected_mode or parsed.method != "fhe_ind" or \
       parsed.circuit != "fhe_ind" or parsed.shape_id != "fhe-indicator-v1" or \
       parsed.security not in ("STD128", "STD192") or parsed.cell_id not in (
           "fhe-ind-std128", "fhe-ind-std192") or parsed.universe != 64 or \
       parsed.set_size != 10 or parsed.target_jaccard != "1/2" or \
       parsed.seed != 7 or parsed.trials != 1 or parsed.output is None or \
       parsed.workload is None or parsed.format != ("json" if expected_mode ==
                                                     "preflight" else "csv"):
        raise SystemExit(2)
    if expected_mode == "e2e" and parsed.preflight is None:
        raise SystemExit(2)


def main() -> int:
    parsed = args()
    if parsed.capabilities:
        if sys.argv[1:] != ["--capabilities", "--format=json"]:
            return 2
        print(json.dumps(CAPABILITIES, sort_keys=True, separators=(",", ":")))
        return 0
    if parsed.mode == "preflight":
        validate_request(parsed, "preflight")
        value = context(parsed)
        skipped = os.environ.get("FAKE_FHE_OVERSIZE") == "1"
        value.update({"schema": "piccard-std-security-fhe-ind-preflight-v1",
                      "mode": "preflight", "cell_id": parsed.cell_id,
                      "keygen_started": False, "skipped": skipped,
                      "reason": (
                          "realized_ring_dim bound=32768 observed=65536; "
                          "provisioned_depth bound=4 observed=10"
                      ) if skipped else ""})
        write_json(Path(parsed.output), value)
        return 0
    if parsed.mode == "e2e":
        validate_request(parsed, "e2e")
        workload = json.loads(Path(parsed.workload).read_text())
        if workload.get("universe") != 64 or workload.get("set_size") != 10 or \
           workload.get("target_jaccard_numerator") != 1 or \
           workload.get("target_jaccard_denominator") != 2 or \
           workload.get("root_seed") != 7 or workload.get("timing_trials") != 1 or \
           workload.get("accuracy_trials") != 1:
            return 2
        value = context(parsed)
        header = [
            "cell_id", "circuit", "shape_id", "security", "k", "m", "universe",
            "set_size", "target_jaccard", "realized_intersection", "realized_union",
            "realized_jaccard", "seed", "trials", "requested_ring_dim",
            "natural_ring_dim", "realized_ring_dim", "natural_depth",
            "provisioned_depth", "scaling_mod_size", "num_limbs", "plaintext_modulus",
            "bfv_context_fingerprint", "log_q_bits", "ordered_rns_moduli",
            "ordered_rns_moduli_sha256",
            "openfhe_version", "sanitizer_profile", "context_tuple_sha256",
            "calibration_origin", "workload_id", "workload_manifest_sha256",
            "timing_hash_seed", "setup_context_ms", "setup_keygen_ms",
            "phase_encode_ms", "phase_encrypt_ms", "phase_evaluate_ms",
            "phase_decrypt_ms", "online_e2e_ms", "full_e2e_ms", "match_count",
            "jaccard_estimate", "status", "reason", "method",
        ]
        row = {key: "" for key in header}
        row.update({key: str(value[key]) for key in (
            "cell_id", "circuit", "shape_id", "security", "k", "m", "universe",
            "set_size", "target_jaccard", "seed", "trials",
            "requested_ring_dim", "natural_ring_dim", "realized_ring_dim",
            "natural_depth", "provisioned_depth", "scaling_mod_size", "num_limbs",
            "plaintext_modulus", "openfhe_version", "sanitizer_profile",
            "context_tuple_sha256", "calibration_origin", "method")})
        row.update({
            "cell_id": parsed.cell_id,
            "target_jaccard": "0.5",
            "bfv_context_fingerprint": value["bfv_context_fingerprint"],
            "realized_intersection": "7", "realized_union": "13",
            "realized_jaccard": "0.53846153846153844", "log_q_bits": "200",
            "ordered_rns_moduli": json.dumps(MODULI, separators=(",", ":")),
            "ordered_rns_moduli_sha256": ordered_hash(),
            "workload_id": workload["workload_id"],
            "workload_manifest_sha256": workload["manifest_sha256"],
            "timing_hash_seed": str(int.from_bytes(hashlib.sha256(
                b"piccard-review-hash-timing-v1\x00" + (7).to_bytes(8, "big")
            ).digest()[:8], "big")),
            "setup_context_ms": "5", "setup_keygen_ms": "6",
            "phase_encode_ms": "1", "phase_encrypt_ms": "2",
            "phase_evaluate_ms": "3", "phase_decrypt_ms": "4",
            "online_e2e_ms": "10", "full_e2e_ms": "21",
            "match_count": "7", "jaccard_estimate": "0.53846153846153844",
            "status": "MEASURED", "reason": "",
        })
        with Path(parsed.output).open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=header, lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
