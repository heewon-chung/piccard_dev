"""Independent, non-benchmark fixtures for reviewer-verifier tests."""

import csv
import hashlib
import struct


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


def _realized_intersection(set_size, target_numerator, target_denominator):
    numerator = 2 * set_size * target_numerator
    denominator = target_denominator + target_numerator
    quotient, remainder = divmod(numerator, denominator)
    return quotient + (1 if 2 * remainder > denominator else 0)


def _regenerate_sets(universe, set_size, intersection, seed):
    only = set_size - intersection
    ranked = sorted(
        range(universe),
        key=lambda value: (
            hashlib.sha256(SET_DOMAIN + _be64(seed) + _be64(value)).digest(),
            value,
        ),
    )
    shared = ranked[:intersection]
    set_a = tuple(sorted(shared + ranked[intersection:intersection + only]))
    set_b = tuple(sorted(shared + ranked[intersection + only:intersection + 2 * only]))
    return set_a, set_b


def _method_metadata(method, primary, target_security_bits):
    target_bits = str(target_security_bits)
    if method == "fhe_ind":
        profile = (
            f"live-BFV-STD{target_security_bits}"
            if target_security_bits else "live-BFV-TOY"
        )
        return {
            "cryptographic_profile": profile,
            "nominal_security_bits": target_bits,
            "security_match": "true",
            "comparison_eligible": "false",
            "comparison_scope": "diagnostic-only",
            "primitive": "bfv-indicator-comparison",
            "protocol_model": "local-universe-sized-BFV-comparator",
            "output_semantics": "scalar-intersection-plaintext-jaccard",
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
        target_bits = str(target_security_bits)
        return {
            "cryptographic_profile": (
                f"live-BFV-STD{target_security_bits}" if target_security_bits
                else "live-BFV-TOY"
            ),
            "nominal_security_bits": target_bits,
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
        match = target_security_bits == 128
        return {
            "cryptographic_profile": "FF-3072/256" if ff else "P-256",
            "nominal_security_bits": "128",
            "security_match": str(match).lower(),
            "comparison_eligible": str(match and primary).lower(),
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
        "security_match": str(target_security_bits == 128).lower(),
        "comparison_eligible": str(
            target_security_bits == 128 and primary and not precomputed
        ).lower(),
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
    """Write a verifier fixture without invoking a benchmark.

    The toy fixture uses the same U=64, set-size=10, target=1/2 workload as
    the persisted reviewer artifact, so FHE-IND detail cells are bound to its
    manifest-derived 7/13 result. The larger review fixtures remain compact
    empty-set fixtures because their tests exercise taxonomy, not workload
    scale.
    """
    spec = SUITES[suite]
    methods = tuple(spec["methods"] if methods is None else methods)
    toy = suite == "toy-smoke"
    workload_k = 16 if toy else 1
    workload_m = 16 if toy else 1
    workload_set_size = 10 if toy else 0
    workload_universe = 64 if toy else 1
    target_numerator = 1
    target_denominator = 2 if toy else 1
    expected_intersection = _realized_intersection(
        workload_set_size, target_numerator, target_denominator)
    expected_union = 2 * workload_set_size - expected_intersection
    expected_jaccard = (
        1.0 if expected_union == 0
        else expected_intersection / expected_union
    )
    records = [(0, 0)]
    records.extend((1, index) for index in range(spec["timing"]))
    records.extend((2, index) for index in range(spec["accuracy"]))

    workload = bytearray(WORKLOAD_DOMAIN)
    workload.extend(_string(suite))
    workload.extend(_string(spec["profile"]))
    workload.extend(_be64(spec["seed"]))
    workload.extend(_be64(workload_k) + _be64(workload_m) +
                    _be64(workload_set_size) + _be64(workload_universe))
    workload.extend(_be64(target_numerator) + _be64(target_denominator))
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
        if toy:
            set_a, set_b = _regenerate_sets(
                workload_universe, workload_set_size, expected_intersection, seed)
        else:
            set_a, set_b = (), ()
        workload.extend(_be64(len(set_a)))
        for value in set_a:
            workload.extend(_be64(value))
        workload.extend(_be64(len(set_b)))
        for value in set_b:
            workload.extend(_be64(value))
        workload.extend(_be64(expected_intersection if toy else 0) +
                        _be64(expected_union if toy else 0))
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
    target_security_bits = 0 if spec["profile"] == "toy-smoke" else 128
    rows = []
    for method in methods:
        arms = ("timing", "accuracy") if spec["accuracy"] else ("timing",)
        for arm in arms:
            row = {field: "" for field in fields}
            row.update({
                "suite": suite,
                "scenario": f"review-{workload_universe}",
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
                "workload_id": f"review-{workload_universe}-{digest_hex[:16]}",
                "workload_manifest_sha256": digest_hex,
                "execution_trace_sha256": trace_hex,
                "root_seed": str(spec["seed"]),
                "omp_threads": "2",
                "omp_dynamic": "false",
                "k": str(workload_k) if method in {"piccard", "piccard_sqrt", "bcg12_mh_ff", "bcg12_mh_ec"} else "",
                "m": str(workload_m) if method in {"piccard", "piccard_sqrt"} else "",
                "set_size": str(workload_set_size),
                "universe_size": str(workload_universe),
                "target_semantics": "jaccard",
                "target_jaccard_numerator": str(target_numerator),
                "target_jaccard_denominator": str(target_denominator),
                "target_jaccard": f"{target_numerator / target_denominator:.12f}",
                "realized_intersection": str(expected_intersection if toy else 0),
                "realized_union": str(expected_union if toy else 0),
                "realized_jaccard": f"{expected_jaccard:.12f}",
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
                "jaccard_computed": f"{expected_jaccard:.6f}",
                "jaccard_expected": f"{expected_jaccard:.6f}",
                "jaccard_error": "0.000000",
                "measurement_status": "measured",
            })
            row.update(_method_metadata(method, primary, target_security_bits))
            row.update({
                "intersection_count": str(expected_intersection) if method == "fhe_ind" else "",
                "phase_encode_ms": "0.100000" if method == "fhe_ind" else "",
                "phase_encrypt_ms": "0.200000" if method == "fhe_ind" else "",
                "phase_compute_ms": "0.300000" if method == "fhe_ind" else "",
                "phase_decrypt_ms": "0.400000" if method == "fhe_ind" else "",
                "ct_size_bytes": "1" if method == "fhe_ind" else "",
                "comm_bytes": "2" if method == "fhe_ind" else "",
            })
            rows.append(row)

    with csv_path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return rows
