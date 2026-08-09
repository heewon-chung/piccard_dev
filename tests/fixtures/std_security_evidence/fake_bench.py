#!/usr/bin/env python3
"""Small deterministic producer used by the external-runner tests.

It intentionally implements only the diagnostic executable's four modes.  The
fixture is not a cryptographic test double: it exists to exercise the runner's
caps, immutable-artifact, resume, and terminal-state handling without creating
OpenFHE contexts in every Python unit test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(os.environ.get("FAKE_SOURCE_ROOT",
                          str(Path(__file__).resolve().parents[3])))
HEADER = [
    "cell_id", "circuit", "shape_id", "security", "k", "m", "set_size",
    "target_jaccard", "realized_intersection", "realized_union",
    "realized_jaccard", "seed", "trials", "requested_ring_dim",
    "natural_ring_dim", "realized_ring_dim", "natural_depth",
    "provisioned_depth", "scaling_mod_size", "num_limbs",
    "plaintext_modulus", "log_q_bits", "ordered_rns_moduli_sha256",
    "openfhe_version", "sanitizer_profile", "transcript_stat_bits",
    "max_queries", "flood_margin_bits", "eval_noise_bits",
    "query_stat_bits", "coefficient_stat_bits", "flood_noise_bits",
    "context_tuple_sha256", "calibration_origin",
    "calibration_artifact_sha256", "workload_id",
    "workload_manifest_sha256", "timing_hash_seed", "setup_context_ms",
    "setup_keygen_ms", "phase_minhash_ms", "phase_encode_ms",
    "phase_encrypt_ms", "phase_evaluate_ms", "phase_flood_ms",
    "phase_decrypt_ms", "online_e2e_ms", "full_e2e_ms", "match_count",
    "jaccard_estimate", "status", "reason",
]


def canonical(value):
    def encode(item):
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            return str(item)
        if isinstance(item, float):
            return format(item, ".17g")
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(encode(v) for v in item) + "]"
        if isinstance(item, dict):
            return "{" + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + encode(item[k])
                for k in sorted(item)
            ) + "}"
        raise TypeError(type(item))
    return (encode(value) + "\n").encode()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def options() -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--output")
    parser.add_argument("--circuit", default="onehot")
    parser.add_argument("--security", default="STD128")
    parser.add_argument("--shape-id", default="onehot-v1")
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--scaling-mod-size", type=int, default=40)
    parser.add_argument("--calibration")
    parser.add_argument("--workload")
    parser.add_argument("--format", default="json")
    args, _ = parser.parse_known_args()
    return args


def source_commit() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def source_dirty() -> bool:
    return bool(subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT, text=True,
    ).strip())


def caps(args: argparse.Namespace) -> tuple[int, int, float]:
    ring = int(os.environ.get("FAKE_RING_DIM", "8192"))
    depth = int(os.environ.get("FAKE_REALIZED_DEPTH", str(args.depth)))
    log_q = float(os.environ.get("FAKE_LOG_Q", "200"))
    return ring, depth, log_q


def identity(args: argparse.Namespace) -> dict:
    ring, realized_depth, log_q = caps(args)
    security_ring = 16384 if args.security == "STD192" else 8192
    ring = ring if "FAKE_RING_DIM" in os.environ else security_ring
    context_key = f"{args.circuit}|{args.security}|{args.depth}|{args.scaling_mod_size}|{ring}|{log_q}"
    fingerprint = hashlib.sha256(("fake-bfv|" + context_key).encode()).hexdigest()
    tuple_digest = hashlib.sha256(("fake-tuple|" + context_key).encode()).hexdigest()
    return {
        "build_id": "fake-build-v1",
        "build_dirty": source_dirty(),
        "build_type": "Release",
        "source_commit": source_commit(),
        "openfhe_version": "fake-openfhe-1",
        "context_fingerprint": fingerprint,
        "context_tuple_sha256": tuple_digest,
        "requested_ring_dim": security_ring,
        "natural_ring_dim": security_ring,
        "natural_depth": 1,
        "realized_ring_dim": ring,
        "plaintext_modulus": 65537,
        "provisioned_depth": args.depth,
        "scaling_mod_size": args.scaling_mod_size,
        "num_limbs": 4,
        "ordered_rns_moduli": ["1000000007", "1000000009", "1000000033", "1000000087"],
        "log_q_bits": log_q,
    }


def derive_seed(root_seed: int, circuit: str, ring: int, depth: int,
                scaling: int, pattern: int) -> int:
    mask = (1 << 64) - 1
    value = root_seed & mask
    for character in circuit:
        value = (value * 0x100000001B3 + ord(character)) & mask
    value ^= (0x9E3779B97F4A7C15 * ring) & mask
    value ^= (0xD1B54A32D192ED03 * depth) & mask
    value ^= (0xA5A5A5A5A5A5A5A5 * scaling) & mask
    value ^= (0xBF58476D1CE4E5B9 * (pattern + 1)) & mask
    value ^= value >> 30
    value = (value * 0xBF58476D1CE4E5B9) & mask
    value ^= value >> 27
    value = (value * 0x94D049BB133111EB) & mask
    value ^= value >> 31
    return value & mask


class Mt19937_64:
    def __init__(self, seed: int) -> None:
        mask = (1 << 64) - 1
        self.state = [seed & mask]
        for index in range(1, 312):
            previous = self.state[index - 1]
            self.state.append(
                (6364136223846793005 * (previous ^ (previous >> 62)) + index)
                & mask
            )
        self.index = 312
        self.mask = mask

    def next(self) -> int:
        if self.index >= 312:
            for index in range(312):
                value = (self.state[index] & 0xFFFFFFFF80000000) | \
                        (self.state[(index + 1) % 312] & 0x7FFFFFFF)
                twisted = self.state[(index + 156) % 312] ^ (value >> 1)
                if value & 1:
                    twisted ^= 0xB5026F5AA96619E9
                self.state[index] = twisted & self.mask
            self.index = 0
        value = self.state[self.index]
        self.index += 1
        value ^= (value >> 29) & 0x5555555555555555
        value ^= (value << 17) & 0x71D67FFFEDA60000
        value &= self.mask
        value ^= (value << 37) & 0xFFF7EEE000000000
        value &= self.mask
        value ^= value >> 43
        return value & self.mask


def random_expected_matches(seed: int) -> int:
    generator = Mt19937_64(seed)
    return sum(
        (generator.next() & 0xF) == (generator.next() & 0xF)
        for _ in range(16)
    )


def timing_hash_seed(root_seed: int) -> int:
    digest = hashlib.sha256(
        b"piccard-review-hash-timing-v1\x00" + root_seed.to_bytes(8, "big")
    ).digest()
    return int.from_bytes(digest[:8], "big")


def preflight(args: argparse.Namespace) -> None:
    live = identity(args)
    reasons = []
    if live["realized_ring_dim"] > 32768:
        reasons.append(
            f"realized_ring_dim bound=32768 observed={live['realized_ring_dim']}"
        )
    if live["provisioned_depth"] > 4:
        reasons.append(
            f"provisioned_depth bound=4 observed={live['provisioned_depth']}"
        )
    if live["log_q_bits"] > 240:
        reasons.append(
            f"log2(q) bound=240 observed={format(live['log_q_bits'], '.17g')}"
        )
    value = {
        **live,
        "circuit": args.circuit,
        "k": 16,
        "m": 16,
        "mode": "preflight",
        "keygen_started": False,
        "reason": "; ".join(reasons),
        "schema": "piccard-std-security-preflight-v1",
        "security": args.security,
        "shape_id": args.shape_id,
        "skipped": bool(reasons),
        "table_eligible": False,
    }
    write_json(Path(args.output), value)


def calibration(args: argparse.Namespace) -> None:
    fail_mode = os.environ.get("FAKE_FAIL_MODE")
    if args.scaling_mod_size == 40 and fail_mode in (
            "calibration-capacity", "calibration-capacity-extra"):
        suffix = "" if fail_mode == "calibration-capacity" else " (extra)"
        print(
            "bench_std_security_evidence: calibration capacity does not fit" +
            suffix,
            file=sys.stderr,
        )
        raise SystemExit(2)
    live = identity(args)
    coefficient_bits = 60 + (live["realized_ring_dim"].bit_length() - 1)
    log_q_over_t = live["log_q_bits"] - __import__("math").log2(live["plaintext_modulus"])
    random_seed = derive_seed(7, args.circuit, live["realized_ring_dim"],
                              args.depth, args.scaling_mod_size, 2)
    observations = [
        ("all_match", 16), ("no_match", 0),
        ("random", random_expected_matches(random_seed)),
    ]
    value = {
        **live,
        "bfv_context_fingerprint": live.pop("context_fingerprint"),
        "calibration_quality": "diagnostic-one-repetition",
        "circuit": args.circuit,
        "coefficient_stat_bits": coefficient_bits,
        "consumer_points": [{"k": 16, "m": 16}],
        "consumer_set_serialization": "16:16\n",
        "consumer_set_sha256": "6ccdf58fe5af9c67abc7fb6c82dd4a94b803187b0a2d65ddaa4c9518aa24524a",
        "eval_noise_bits": 1,
        "flood_margin_bits": 8,
        "flood_noise_bits": 1 + coefficient_bits + 8,
        "ct_bytes": 1,
        "k": 16,
        "log_q_over_t_bits": log_q_over_t,
        "m": 16,
        "patterns": [
            {"decrypt_ok": True, "eval_noise_bits": 1,
             "expected_matches": expected, "observed_matches": expected,
             "pattern": pattern, "repetition_index": 0,
             "saturated": False,
             "seed": derive_seed(7, args.circuit, live["realized_ring_dim"],
                                 args.depth, args.scaling_mod_size, index)}
            for index, (pattern, expected) in enumerate(observations)
        ],
        "profile_id": "primary40",
        "query_stat_bits": 60,
        "required_capacity_bits": 1 + coefficient_bits + 8 + 2,
        "repetitions_per_pattern": 1,
        "schema": "piccard-std-security-diagnostic-calibration-v1",
        "security": args.security,
        "seed": 7,
        "shape_id": args.shape_id,
        "table_eligible": False,
    }
    write_json(Path(args.output), value)


def workload(args: argparse.Namespace) -> None:
    value = {
        "accuracy_trials": 1,
        "bytes_hex": "00",
        "manifest_sha256": hashlib.sha256(b"\x00").hexdigest(),
        "methods": ["piccard", "piccard_sqrt", "bcg12_mh_ec",
                    "bcg12_exact_ec", "sj16"],
        "profile_id": "toy-smoke",
        "root_seed": 7,
        "schema": "piccard-std-security-workload-v1",
        "k": 16,
        "m": 16,
        "set_size": 10,
        "suite": "toy-smoke",
        "target_jaccard_denominator": 2,
        "target_jaccard_numerator": 1,
        "timing_trials": 1,
        "universe": 64,
        "workload_id": "fake-workload-v1",
    }
    write_json(Path(args.output), value)


def e2e(args: argparse.Namespace) -> None:
    if os.environ.get("FAKE_FAIL_MODE") == "e2e":
        print("forced fake e2e failure", file=sys.stderr)
        raise SystemExit(7)
    calibration_data = json.loads(Path(args.calibration).read_text())
    workload_data = json.loads(Path(args.workload).read_text())
    framed = b"".join(
        len(modulus.encode()).to_bytes(4, "big") + modulus.encode()
        for modulus in calibration_data["ordered_rns_moduli"]
    )
    row = {key: "" for key in HEADER}
    row.update({
        "cell_id": f"{args.circuit}-{args.security.lower()}",
        "circuit": args.circuit,
        "shape_id": args.shape_id,
        "security": args.security,
        "k": "16", "m": "16", "set_size": "10", "target_jaccard": "0.5",
        "realized_intersection": "7", "realized_union": "13",
        "realized_jaccard": "0.53846153846153844", "seed": "7", "trials": "1",
        "requested_ring_dim": str(calibration_data["requested_ring_dim"]),
        "natural_ring_dim": str(calibration_data["natural_ring_dim"]),
        "realized_ring_dim": str(calibration_data["realized_ring_dim"]),
        "natural_depth": str(calibration_data["natural_depth"]),
        "provisioned_depth": str(calibration_data["provisioned_depth"]),
        "scaling_mod_size": str(calibration_data["scaling_mod_size"]),
        "num_limbs": str(calibration_data["num_limbs"]),
        "plaintext_modulus": str(calibration_data["plaintext_modulus"]),
        "log_q_bits": format(calibration_data["log_q_bits"], ".17g"),
        "ordered_rns_moduli_sha256": hashlib.sha256(framed).hexdigest(),
        "openfhe_version": calibration_data["openfhe_version"],
        "sanitizer_profile": "primary40", "transcript_stat_bits": "40",
        "max_queries": "1048576", "flood_margin_bits": "8",
        "eval_noise_bits": "1", "query_stat_bits": "60",
        "coefficient_stat_bits": str(calibration_data["coefficient_stat_bits"]),
        "flood_noise_bits": str(calibration_data["flood_noise_bits"]),
        "context_tuple_sha256": calibration_data["context_tuple_sha256"],
        "calibration_origin": "diagnostic-artifact",
        "calibration_artifact_sha256": hashlib.sha256(Path(args.calibration).read_bytes()).hexdigest(),
        "workload_id": workload_data["workload_id"],
        "workload_manifest_sha256": workload_data["manifest_sha256"],
        "timing_hash_seed": str(timing_hash_seed(workload_data["root_seed"])),
        "setup_context_ms": "1", "setup_keygen_ms": "2",
        "phase_minhash_ms": "1", "phase_encode_ms": "1", "phase_encrypt_ms": "1",
        "phase_evaluate_ms": "1", "phase_flood_ms": "1", "phase_decrypt_ms": "1",
        "online_e2e_ms": "6", "full_e2e_ms": "9", "match_count": "10",
        "jaccard_estimate": "0.59999999999999998", "status": "MEASURED", "reason": "",
    })
    if args.format == "csv":
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(",".join(HEADER) + "\n" +
                                     ",".join(row[key] for key in HEADER) + "\n")
    else:
        write_json(Path(args.output), {"schema": "fake-e2e-v1", **row})


def main() -> int:
    args = options()
    if args.mode == "workload":
        workload(args)
    elif args.mode == "preflight":
        preflight(args)
    elif args.mode == "calibrate":
        calibration(args)
    elif args.mode == "e2e":
        e2e(args)
    else:
        raise SystemExit(f"unsupported mode: {args.mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
