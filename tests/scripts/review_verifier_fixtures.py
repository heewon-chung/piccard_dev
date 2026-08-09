"""Independent, non-benchmark fixtures for reviewer-verifier tests."""

import csv
import hashlib
import struct


WORKLOAD_DOMAIN = b"piccard-review-workload-v1\0"
TRACE_DOMAIN = b"piccard-review-execution-trace-v1\0"
TRIAL_DOMAIN = b"piccard-review-trial-v1\0"
HASH_DOMAINS = {
    0: b"piccard-review-hash-warmup-v1\0",
    1: b"piccard-review-hash-timing-v1\0",
    2: b"piccard-review-hash-accuracy-v1\0",
}
SUITES = {
    "toy-smoke": {
        "profile": "toy-smoke",
        "run_class": "smoke",
        "methods": (
            "piccard", "piccard_sqrt", "fhe_ind", "bcg12_mh_ec",
            "bcg12_exact_ec", "sj16",
        ),
        "timing": 1,
        "accuracy": 1,
        "seed": 7,
    },
    "primary-review": {
        "profile": "std128-t40-primary",
        "run_class": "primary",
        "methods": (
            "piccard", "piccard_sqrt", "bcg12_mh_ff", "bcg12_mh_ec",
            "bcg12_exact_ff", "bcg12_exact_ec", "sj16",
        ),
        "timing": 30,
        "accuracy": 50,
        "seed": 19,
    },
    "sj16-precompute-sensitivity": {
        "profile": "std128-t64-sensitivity",
        "run_class": "sensitivity",
        "methods": ("sj16", "sj16_precomputed"),
        "timing": 3,
        "accuracy": 0,
        "seed": 23,
    },
}


def _be32(value):
    return struct.pack(">I", value)


def _be64(value):
    return struct.pack(">Q", value)


def _string(value):
    encoded = value.encode("utf-8")
    return _be32(len(encoded)) + encoded


def _first8(payload):
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")


def _trial_seed(root_seed, kind, index):
    return _first8(TRIAL_DOMAIN + _be64(root_seed) + bytes([kind]) + _be32(index))


def _hash_seed(root_seed, kind, index):
    suffix = _be32(index) if kind == 2 else b""
    return _first8(HASH_DOMAINS[kind] + _be64(root_seed) + suffix)


def _method_metadata(method, primary):
    if method == "fhe_ind":
        target_bits = "128" if primary else "0"
        profile = "live-BFV-STD128" if primary else "live-BFV-TOY"
        return {
            "cryptographic_profile": profile,
            "nominal_security_bits": target_bits,
            "security_match": "true",
            "comparison_eligible": "false",
            "comparison_scope": "diagnostic-only",
            "primitive": "bfv-indicator-comparison",
            "protocol_model": "local-universe-sized-BFV-comparator",
            "output_semantics": "intersection-indicator-vector",
            "assurance_scope": "live-bfv-primitive-only",
            "security_basis": "openfhe-hesea-standard-live-context",
            "cost_scope": "primitive-only",
            "precomputation_mode": "not-applicable",
            "estimator_model": "not-applicable",
            "sanitizer_model": "not-applicable",
            "sanitizer_assurance": "not-applicable",
            "actual_ring_dim": "1024",
            "log_q_bits": "160.0",
            "plaintext_modulus": "12289",
            "num_limbs": "4",
            "openfhe_version": "1.5.0",
        }

    if method in {"piccard", "piccard_sqrt"}:
        sqrt = method == "piccard_sqrt"
        return {
            "cryptographic_profile": "live-BFV-STD128",
            "nominal_security_bits": "128",
            "security_match": "true",
            "comparison_eligible": "true" if primary else "false",
            "comparison_scope": "end-to-end-estimator",
            "primitive": "bfv-sqrt-minhash" if sqrt else "bfv-onehot-minhash",
            "protocol_model": (
                "piccard-sqrt-two-owner-outsourced" if sqrt
                else "piccard-two-owner-outsourced"
            ),
            "output_semantics": "bias-corrected-jaccard-estimate",
            "assurance_scope": "live-bfv+empirical-sanitizer-poc",
            "security_basis": "openfhe-hesea-standard-live-context",
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
            "estimator_model": "sha256-random-ranking-poc-v1",
            "sanitizer_model": "phase-smudging-enc0-poc-v1",
            "sanitizer_assurance":
                "empirical-phase-statistical+ciphertext-computational",
            "transcript_stat_bits": "40",
            "max_queries": "1048576",
            "query_stat_bits": "60",
            "coefficient_stat_bits": "70",
            "flood_margin_bits": "8",
            "eval_noise_bits": "92" if sqrt else "56",
            "flood_noise_bits": "170" if sqrt else "134",
            "scaling_mod_size": "40",
            "actual_ring_dim": "1024",
            "log_q_bits": "200.0" if sqrt else "160.0",
            "plaintext_modulus": "12289",
            "num_limbs": "5" if sqrt else "4",
            "openfhe_version": "1.5.0",
        }

    if method.startswith("bcg12_"):
        ff = method.endswith("_ff")
        exact = method.startswith("bcg12_exact_")
        return {
            "cryptographic_profile": "FF-3072/256" if ff else "P-256",
            "nominal_security_bits": "128",
            "security_match": "true",
            "comparison_eligible": "true" if primary else "false",
            "comparison_scope": (
                "matched-cardinality-component" if exact
                else "matched-estimator-component"
            ),
            "primitive": "bcg12-ff" if ff else "bcg12-ec",
            "protocol_model": (
                "bcg12-exact-cardinality" if exact
                else "bcg12-cardinality-on-minhash"
            ),
            "output_semantics": (
                "harness-reconstructed-exact-jaccard" if exact
                else "minhash-collision-jaccard-estimate"
            ),
            "assurance_scope": "implemented-baseline-parameter-map",
            "security_basis": (
                "finite-field-dh-3072-subgroup-256-parameter-map" if ff
                else "nist-p256-parameter-map"
            ),
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
            "estimator_model": (
                "not-applicable" if exact else "sha256-random-ranking-poc-v1"
            ),
            "sanitizer_model": "not-applicable",
            "sanitizer_assurance": "not-applicable",
            "openfhe_version": "not-applicable",
        }

    precomputed = method == "sj16_precomputed"
    return {
        "cryptographic_profile": "Paillier-3072",
        "nominal_security_bits": "128",
        "security_match": "true",
        "comparison_eligible": "true" if primary and not precomputed else "false",
        "comparison_scope": "component-lower-bound",
        "primitive": "paillier-3072",
        "protocol_model": "sj16-intersection-shares",
        "output_semantics": "harness-reconstructed-jaccard-with-plaintext-union",
        "assurance_scope": "intersection-shares-lower-bound",
        "security_basis":
            "rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security",
        "cost_scope": (
            "online-query-with-precomputed-randomizers" if precomputed
            else "full-query-excluding-one-time-setup"
        ),
        "precomputation_mode": (
            "randomizers-precomputed" if precomputed
            else "randomizer-generation-included"
        ),
        "estimator_model": "not-applicable",
        "sanitizer_model": "not-applicable",
        "sanitizer_assurance": "not-applicable",
        "openfhe_version": "not-applicable",
    }


def write_review_fixture(suite, fields, csv_path, workload_path, trace_path,
                         methods=None):
    """Write a canonical empty-set fixture without invoking a benchmark."""
    spec = SUITES[suite]
    methods = tuple(spec["methods"] if methods is None else methods)
    records = [(0, 0)]
    records.extend((1, index) for index in range(spec["timing"]))
    records.extend((2, index) for index in range(spec["accuracy"]))

    workload = bytearray(WORKLOAD_DOMAIN)
    workload.extend(_string(suite))
    workload.extend(_string(spec["profile"]))
    workload.extend(_be64(spec["seed"]))
    workload.extend(_be64(1) + _be64(1) + _be64(0) + _be64(1))
    workload.extend(_be64(1) + _be64(1))
    workload.extend(_be32(len(methods)))
    for method in methods:
        workload.extend(_string(method))
    workload.extend(_be32(spec["timing"]) + _be32(spec["accuracy"]))
    workload.extend(_be32(len(records)))

    encoded_records = []
    for kind, index in records:
        seed = _trial_seed(spec["seed"], kind, index)
        hash_value = _hash_seed(spec["seed"], kind, index)
        encoded_records.append((kind, index, seed, hash_value))
        workload.extend(bytes([kind]) + _be32(index) + _be64(seed) + _be64(hash_value))
        workload.extend(_be64(0) + _be64(0))  # two empty VEC64 values
        workload.extend(_be64(0) + _be64(0))  # exact intersection and union
    workload_bytes = bytes(workload)
    workload_path.write_bytes(workload_bytes)
    workload_digest = hashlib.sha256(workload_bytes).digest()

    trace = bytearray(TRACE_DOMAIN + workload_digest)
    trace.extend(_be32(len(records)) + _be32(len(records)))
    for kind, index, seed, _ in encoded_records:
        offset = seed % len(methods)
        order = methods[offset:] + methods[:offset]
        trace.extend(bytes([kind]) + _be32(index))
        trace.extend(_be32(len(methods)) + _be32(len(methods)) + b"\0")
        for method in order:
            trace.extend(_string(method))
    trace_bytes = bytes(trace)
    trace_path.write_bytes(trace_bytes)

    digest_hex = workload_digest.hex()
    trace_hex = hashlib.sha256(trace_bytes).hexdigest()
    timing_hash_seed = str(encoded_records[1][3])
    primary = suite == "primary-review"
    rows = []
    for method in methods:
        arms = ("timing", "accuracy") if spec["accuracy"] else ("timing",)
        for arm in arms:
            row = {field: "" for field in fields}
            row.update({
                "suite": suite,
                "scenario": "review-1",
                "method": method,
                "profile_id": spec["profile"],
                "run_class": spec["run_class"],
                "target_security_bits": (
                    "0" if spec["profile"] == "toy-smoke" else "128"
                ),
                "secure_division_included": "false",
                "measurement_kind": (
                    f"fhe-{arm}" if method in {"piccard", "piccard_sqrt"}
                    else "diagnostic" if method == "fhe_ind"
                    else f"psi-{arm}" if method.startswith("bcg12_")
                    else f"ahe-{arm}"
                ),
                "evidence_arm": arm,
                "workload_id": f"review-1-{digest_hex[:16]}",
                "workload_manifest_sha256": digest_hex,
                "execution_trace_sha256": trace_hex,
                "root_seed": str(spec["seed"]),
                "omp_threads": "2",
                "omp_dynamic": "false",
                "k": "1" if method in {"piccard", "piccard_sqrt", "bcg12_mh_ff", "bcg12_mh_ec"} else "",
                "m": "1" if method in {"piccard", "piccard_sqrt"} else "",
                "set_size": "0",
                "universe_size": "1",
                "target_semantics": "jaccard",
                "target_jaccard_numerator": "1",
                "target_jaccard_denominator": "1",
                "target_jaccard": "1.000000000000",
                "realized_intersection": "0",
                "realized_union": "0",
                "realized_jaccard": "1.000000000000",
                "timing_trials": str(spec["timing"]),
                "accuracy_trials": str(spec["accuracy"]),
                "trials": str(spec["timing"] if arm == "timing" else spec["accuracy"]),
                "hash_randomness": (
                    "fixed" if arm == "timing" else "resampled"
                ) if method in {"piccard", "piccard_sqrt", "bcg12_mh_ff", "bcg12_mh_ec"} else "not-applicable",
                "hash_seed": timing_hash_seed if arm == "timing" and method in {
                    "piccard", "piccard_sqrt", "bcg12_mh_ff", "bcg12_mh_ec"
                } else "",
                "total_ms": "1.000000",
                "total_ms_sd": "",
                "total_ms_median": "1.000000",
                "jaccard_computed": "1.000000",
                "jaccard_expected": "1.000000",
                "jaccard_error": "0.000000",
                "measurement_status": "measured",
            })
            row.update(_method_metadata(method, primary))
            rows.append(row)

    with csv_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return rows
