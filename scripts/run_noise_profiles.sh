#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import secrets
import subprocess
import sys
import tempfile
import time


AGGREGATE_HEADER = (
    "profile,circuit,shape_id,security,consumer_count,"
    "consumer_set_sha256,worst_consumer_k,worst_consumer_m,pattern_count,"
    "repetitions_per_pattern,detail_row_count,detail_sha256,seed,"
    "requested_ring_dim,natural_ring_dim,realized_ring_dim,"
    "ring_growth_factor,ring_dim_calibrated,natural_depth,"
    "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,"
    "log_delta,eval_noise_bits,headroom_bits,max_queries,query_stat_bits,"
    "coefficient_stat_bits,flood_margin_bits,flood_noise_bits,decrypt_ok,"
    "saturated,ct_bytes,openfhe_version,source_commit,status_code,"
    "error_message,consumer_results_sha256"
)
DETAIL_HEADER = (
    "profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,"
    "consumer_m,pattern,rep_index,rep_seed,requested_ring_dim,"
    "natural_ring_dim,ring_dim_calibrated,realized_ring_dim,"
    "ring_growth_factor,natural_depth,provisioned_depth,scaling_mod_size,"
    "num_limbs,plaintext_mod,log_q,log_delta,eval_noise_bits,"
    "headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,"
    "openfhe_version,source_commit,status_code,error_message"
)
SCALING_GRID = [40, 45, 50, 52, 54, 58, 60]
ABSOLUTE_N_CAP = 1048576
ROOT_SEED = 20260729


def fail(message, code=1):
    print(message, file=sys.stderr)
    raise SystemExit(code)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def atomic_json_if_changed(path, value):
    rendered = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if path.is_file() and path.read_bytes() == rendered:
        return
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as output:
        output.write(rendered)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def write_once_json(path, value):
    if path.exists():
        raise ValueError("refusing to overwrite write-once receipt")
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    rendered = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        os.write(descriptor, rendered)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(temporary, 0o444)
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_cli(arguments):
    result = {
        "results_root": None,
        "profile": None,
        "resume": False,
        "bench_noise": None,
        "smoke": False,
    }
    names = {
        "--results-root": "results_root",
        "--profile": "profile",
        "--bench-noise": "bench_noise",
    }
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--resume":
            if result["resume"]:
                fail("duplicate --resume")
            result["resume"] = True
        elif argument == "--smoke":
            if result["smoke"]:
                fail("duplicate --smoke")
            result["smoke"] = True
        else:
            matched = False
            for option, key in names.items():
                prefix = option + "="
                if argument.startswith(prefix):
                    if result[key] is not None:
                        fail("duplicate " + option)
                    value = argument[len(prefix):]
                    if not value:
                        fail(option + " requires a value")
                    result[key] = value
                    matched = True
                    break
                if argument == option:
                    if result[key] is not None:
                        fail("duplicate " + option)
                    index += 1
                    if index >= len(arguments) or arguments[index].startswith("--"):
                        fail(option + " requires a value")
                    result[key] = arguments[index]
                    matched = True
                    break
            if not matched:
                fail("unknown runner argument: " + argument)
        index += 1
    if result["profile"] not in {
        "primary40", "sensitivity64", "feasibility128"
    }:
        fail("--profile must be primary40|sensitivity64|feasibility128")
    if result["smoke"] and result["profile"] != "sensitivity64":
        fail("--smoke uses exactly the sensitivity64 four-cell matrix")
    return result


def resolve_timing(bench):
    timeout_override = os.environ.get("PICCARD_TEST_TIMEOUT_MS")
    grace_override = os.environ.get("PICCARD_TEST_TERM_GRACE_MS")
    if timeout_override is None and grace_override is None:
        return 120000, 30000, False
    guarded = (
        os.environ.get("PICCARD_TEST_SUPERVISOR") == "1"
        and bench.name == "fake_bench_noise"
    )
    if not guarded:
        fail(
            "timing override requires PICCARD_TEST_SUPERVISOR=1 and "
            "fake_bench_noise")
    if timeout_override is None or grace_override is None:
        fail("both timing overrides are required")
    try:
        timeout_ms = int(timeout_override)
        grace_ms = int(grace_override)
    except ValueError:
        fail("timing overrides must be positive integers")
    if timeout_ms < 10 or grace_ms < 10:
        fail("timing overrides must be at least 10 ms")
    return timeout_ms, grace_ms, True


def supervise(
    command, timeout_ms, grace_ms, environment, test_readiness=False
):
    child_environment = environment
    readiness_marker = None
    if test_readiness:
        ready_dir = environment.get("PICCARD_TEST_READY_DIR")
        if not ready_dir:
            fail("guarded test supervision requires PICCARD_TEST_READY_DIR")
        readiness_marker = (
            Path(ready_dir) /
            f"ready-{os.getpid()}-{secrets.token_hex(12)}")
        child_environment = environment.copy()
        child_environment["PICCARD_TEST_READY_MARKER"] = str(
            readiness_marker)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=child_environment,
        start_new_session=True,
    )
    if readiness_marker is not None:
        readiness_deadline = time.monotonic() + 10.0
        while (
            not readiness_marker.exists()
            and process.poll() is None
            and time.monotonic() < readiness_deadline
        ):
            time.sleep(0.002)
        if not readiness_marker.exists():
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            fail(
                "guarded fake benchmark did not publish readiness "
                f"(returncode={process.returncode}, stderr={stderr.strip()})")
        readiness_marker.unlink(missing_ok=True)
        started = time.monotonic()
    deadline = started + timeout_ms / 1000.0
    timed_out = False
    term_sent = False
    kill_sent = False
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.002)
    if process.poll() is None:
        timed_out = True
        term_sent = True
        os.killpg(process.pid, signal.SIGTERM)
        grace_deadline = time.monotonic() + grace_ms / 1000.0
        while process.poll() is None and time.monotonic() < grace_deadline:
            time.sleep(0.002)
        if process.poll() is None:
            kill_sent = True
            os.killpg(process.pid, signal.SIGKILL)
    stdout, stderr = process.communicate()
    return {
        "returncode": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "term_sent": term_sent,
        "kill_sent": kill_sent,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
    }


def profile_policy(matrix, profile_id):
    return next(
        policy for policy in matrix["profiles"]
        if policy["profile_id"] == profile_id
    )


def consumer_argument(partition):
    return ",".join(
        f"{consumer['k']}:{consumer['m']}"
        for consumer in partition["consumer_points"]
    )


def identity_arguments(partition, matrix, policy, manifest_path):
    return [
        "--pre_threshold",
        f"--profile_manifest={manifest_path}",
        f"--profile={partition['profile_id']}",
        f"--key_id={partition['key_id']}",
        f"--circuit={partition['circuit']}",
        f"--shape_id={partition['shape_id']}",
        f"--security={partition['security']}",
        f"--requested_ring_dim={partition['requested_ring_dim']}",
        f"--natural_depth={partition['natural_depth']}",
        f"--consumer_points={consumer_argument(partition)}",
        f"--consumer_set_sha256={partition['consumer_set_sha256']}",
        f"--openfhe_version={matrix['openfhe_version']}",
        f"--source_commit={runtime_source_commit}",
        f"--transcript_stat_bits={policy['transcript_stat_bits']}",
        f"--max_queries={policy['max_queries']}",
        f"--margin={policy['flood_margin_bits']}",
        f"--seed={ROOT_SEED}",
    ]


def validate_preflight(preflight, partition, matrix):
    expected = {
        "source_commit": runtime_source_commit,
        "openfhe_version": matrix["openfhe_version"],
        "key_id": partition["key_id"],
        "profile_id": partition["profile_id"],
        "circuit": partition["circuit"],
        "shape_id": partition["shape_id"],
        "security": partition["security"],
        "requested_ring_dim": partition["requested_ring_dim"],
        "natural_depth": partition["natural_depth"],
        "consumer_set_sha256": partition["consumer_set_sha256"],
    }
    for key, value in expected.items():
        if preflight.get(key) != value:
            raise ValueError(
                f"preflight {key} mismatch: {preflight.get(key)!r} != {value!r}")
    natural = preflight.get("natural_ring_dim")
    if (
        not isinstance(natural, int)
        or natural < partition["requested_ring_dim"]
        or natural > ABSOLUTE_N_CAP
        or natural & (natural - 1)
    ):
        raise ValueError("preflight natural_ring_dim is invalid")
    return natural


def timeout_for(largest_n):
    if largest_n <= 32768:
        return 2700
    if largest_n <= 65536:
        return 7200
    if largest_n <= 131072:
        return 21600
    if largest_n <= 262144:
        return 43200
    return 86400


def search_topology(partition, natural_ring_dim, policy, smoke):
    if smoke:
        rings = [natural_ring_dim]
        scaling_grid = [40]
        max_depth_delta = 0
        reps = 1
    else:
        rings = []
        value = natural_ring_dim
        while (
            value <= ABSOLUTE_N_CAP
            and value <= natural_ring_dim * policy["max_ring_growth"]
        ):
            rings.append(value)
            value *= 2
        scaling_grid = SCALING_GRID
        max_depth_delta = 6
        reps = policy["repetitions"]
    candidate_ids = [
        f"N{ring}-d{partition['natural_depth'] + delta}-s{sms}"
        for ring in rings
        for delta in range(max_depth_delta + 1)
        for sms in scaling_grid
    ]
    return rings, scaling_grid, max_depth_delta, reps, candidate_ids


def expected_identity(partition, source_commit):
    return {
        "key_id": partition["key_id"],
        "profile_id": partition["profile_id"],
        "circuit": partition["circuit"],
        "shape_id": partition["shape_id"],
        "security": partition["security"],
        "requested_ring_dim": partition["requested_ring_dim"],
        "natural_depth": partition["natural_depth"],
        "consumer_points": partition["consumer_points"],
        "consumer_set_sha256": partition["consumer_set_sha256"],
        "source_commit": source_commit,
        "openfhe_version": matrix["openfhe_version"],
    }


def validate_command(
    command, partition, rings, scaling_grid, max_delta, reps, final_directory
):
    if not isinstance(command, list) or not all(
        isinstance(value, str) for value in command
    ):
        raise ValueError("candidate command is malformed")
    values = {}
    switches = []
    for argument in command:
        if argument.startswith("--") and "=" in argument:
            key, value = argument.split("=", 1)
            if key in values:
                raise ValueError("candidate command has duplicate " + key)
            values[key] = value
        elif argument.startswith("--"):
            switches.append(argument)
        else:
            raise ValueError("candidate command has positional argument")
    expected_switches = ["--pre_threshold"]
    if options["smoke"]:
        expected_switches.append("--smoke")
    if sorted(switches) != sorted(expected_switches):
        raise ValueError("candidate command switch/extra option mismatch")
    largest_n = max(rings)
    expected = {
        "--profile_manifest": str(resolved_manifest_path),
        "--profile": partition["profile_id"],
        "--key_id": partition["key_id"],
        "--circuit": partition["circuit"],
        "--shape_id": partition["shape_id"],
        "--security": partition["security"],
        "--requested_ring_dim": str(partition["requested_ring_dim"]),
        "--natural_depth": str(partition["natural_depth"]),
        "--consumer_points": consumer_argument(partition),
        "--consumer_set_sha256": partition["consumer_set_sha256"],
        "--openfhe_version": matrix["openfhe_version"],
        "--source_commit": runtime_source_commit,
        "--transcript_stat_bits": str(policy["transcript_stat_bits"]),
        "--max_queries": str(policy["max_queries"]),
        "--margin": str(policy["flood_margin_bits"]),
        "--seed": str(ROOT_SEED),
        "--ring_candidates": ",".join(map(str, rings)),
        "--scaling_mod_grid": ",".join(map(str, scaling_grid)),
        "--max_depth_delta": str(max_delta),
        "--timeout_seconds": str(timeout_for(largest_n)),
        "--reps": str(reps),
        "--aggregate_csv": str(final_directory / "aggregate.csv"),
        "--detail_dir": str(final_directory / "details"),
        "--candidate_manifest": str(final_directory / "candidates.json"),
    }
    if set(values) != set(expected):
        raise ValueError("candidate command missing/unknown/extra option")
    for key, value in expected.items():
        if values.get(key) != value:
            raise ValueError("candidate command mismatch for " + key)


def validate_shard(shard, partition, parent_digest):
    manifest_path = shard / "shard_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("missing shard manifest")
    if not isinstance(parent_digest, str) or len(parent_digest) != 64:
        raise ValueError("missing immutable parent shard digest")
    if sha256_file(manifest_path) != parent_digest:
        raise ValueError("immutable parent shard digest mismatch")
    manifest = json.loads(manifest_path.read_text())
    identity = expected_identity(partition, runtime_source_commit)
    if manifest.get("status") != "COMPLETE" or any(
        manifest.get(key) != value for key, value in identity.items()
    ):
        raise ValueError("incomplete or wrong shard identity")
    if (
        manifest.get("smoke_only") != options["smoke"]
        or manifest.get("table_eligible") != (not options["smoke"])
    ):
        raise ValueError("shard smoke eligibility mismatch")
    natural = manifest.get("natural_ring_dim")
    if not isinstance(natural, int):
        raise ValueError("invalid stored natural ring dimension")
    rings, scaling, max_delta, reps, candidate_ids = search_topology(
        partition, natural, policy, options["smoke"])
    expected_detail_rows = len(partition["consumer_points"]) * 3 * reps
    if (
        manifest.get("candidate_count") != len(candidate_ids)
        or manifest.get("expected_detail_rows") != expected_detail_rows
        or manifest.get("ring_candidates") != rings
        or manifest.get("scaling_mod_grid") != scaling
        or manifest.get("max_depth_delta") != max_delta
        or manifest.get("repetitions") != reps
    ):
        raise ValueError("shard search/count topology mismatch")
    validate_command(
        manifest.get("measurement_command", [])[1:],
        partition, rings, scaling, max_delta, reps, shard)
    for relative, expected_hash in manifest.get("files", {}).items():
        path = shard / relative
        if not path.is_file() or sha256_file(path) != expected_hash:
            raise ValueError("shard file hash mismatch")
    actual_payload_files = {
        path.relative_to(shard).as_posix()
        for path in shard.rglob("*")
        if path.is_file() and path.name != "shard_manifest.json"
    }
    if actual_payload_files != set(manifest.get("files", {})):
        raise ValueError("shard payload file topology mismatch")
    rows, _ = validate_measurement(
        shard, partition, natural, rings, scaling, max_delta, reps,
        manifest["measurement_command"][1:], shard)
    expected_verdict = (
        "SELECTED" if any(row["status_code"] == "OK" for row in rows)
        else "INFEASIBLE")
    if manifest.get("key_verdict") != expected_verdict:
        raise ValueError("shard key verdict mismatch")
    return manifest


def validate_measurement(
    directory, partition, natural_ring_dim, rings, scaling_grid,
    max_depth_delta, reps, expected_command, final_directory
):
    aggregate_path = directory / "aggregate.csv"
    candidate_manifest_path = directory / "candidates.json"
    details_dir = directory / "details"
    if not aggregate_path.is_file() or not candidate_manifest_path.is_file():
        raise ValueError("missing CSV or candidate manifest")
    with aggregate_path.open(newline="") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
    if ",".join(reader.fieldnames or []) != AGGREGATE_HEADER:
        raise ValueError("truncated or wrong aggregate CSV header")
    candidate_ids = [
        f"N{ring}-d{partition['natural_depth'] + delta}-s{sms}"
        for ring in rings
        for delta in range(max_depth_delta + 1)
        for sms in scaling_grid
    ]
    if len(rows) != len(candidate_ids):
        raise ValueError("truncated aggregate CSV row count")
    manifest = json.loads(candidate_manifest_path.read_text())
    identity = expected_identity(partition, runtime_source_commit)
    if any(manifest.get(key) != value for key, value in identity.items()):
        raise ValueError("candidate manifest full key mismatch")
    if manifest.get("command") != expected_command:
        raise ValueError("candidate manifest command mismatch")
    validate_command(
        manifest["command"], partition, rings, scaling_grid,
        max_depth_delta, reps, final_directory)
    if manifest.get("candidate_count") != len(candidate_ids):
        raise ValueError("candidate manifest count mismatch")
    detail_paths = {path.stem: path for path in details_dir.glob("*.csv")}
    if set(detail_paths) != set(candidate_ids):
        raise ValueError("candidate detail file count mismatch")
    candidates = manifest.get("candidates", [])
    candidate_map = {
        candidate.get("candidate_id"): candidate for candidate in candidates
    }
    if (
        len(candidates) != len(candidate_ids)
        or set(candidate_map) != set(candidate_ids)
    ):
        raise ValueError("candidate list count mismatch")
    aggregate_map = {}
    candidate_specs = {
        f"N{ring}-d{partition['natural_depth'] + delta}-s{sms}":
            (ring, partition["natural_depth"] + delta, sms)
        for ring in rings
        for delta in range(max_depth_delta + 1)
        for sms in scaling_grid
    }
    for row in rows:
        for key in (
            "profile", "circuit", "shape_id", "security",
            "consumer_set_sha256", "openfhe_version", "source_commit"
        ):
            expected = {
                "profile": partition["profile_id"],
                "circuit": partition["circuit"],
                "shape_id": partition["shape_id"],
                "security": partition["security"],
                "consumer_set_sha256": partition["consumer_set_sha256"],
                "openfhe_version": matrix["openfhe_version"],
                "source_commit": runtime_source_commit,
            }[key]
            if row[key] != expected:
                raise ValueError("aggregate identity mismatch for " + key)
        cid = (
            f"N{row['ring_dim_calibrated']}-d"
            f"{row['provisioned_depth']}-s{row['scaling_mod_size']}")
        if cid in aggregate_map:
            raise ValueError("duplicate aggregate candidate identity")
        ring, depth, sms = candidate_specs.get(cid, (None, None, None))
        if (
            ring is None
            or row["requested_ring_dim"]
            != str(partition["requested_ring_dim"])
            or row["natural_ring_dim"] != str(natural_ring_dim)
            or row["realized_ring_dim"] != str(ring)
            or row["natural_depth"] != str(partition["natural_depth"])
            or row["provisioned_depth"] != str(depth)
            or row["scaling_mod_size"] != str(sms)
            or row["consumer_count"] != str(len(partition["consumer_points"]))
            or row["repetitions_per_pattern"] != str(reps)
        ):
            raise ValueError("aggregate search identity mismatch")
        aggregate_map[cid] = row
    if set(aggregate_map) != set(candidate_ids):
        raise ValueError("aggregate candidate identity mismatch")
    allowed_statuses = {
        "OK", "SATURATED", "DECRYPT_FAIL",
        "CONTEXT_ERROR", "TIMEOUT", "PROCESS_ERROR",
    }
    expected_detail_rows = len(partition["consumer_points"]) * 3 * reps
    for candidate_id in candidate_ids:
        candidate = candidate_map[candidate_id]
        detail_path = detail_paths[candidate_id]
        with detail_path.open(newline="") as source:
            detail_reader = csv.DictReader(source)
            detail_rows = list(detail_reader)
        if ",".join(detail_reader.fieldnames or []) != DETAIL_HEADER:
            raise ValueError("wrong detail CSV header")
        if len(detail_rows) != expected_detail_rows:
            raise ValueError("detail CSV row count mismatch")
        if sha256_file(detail_path) != candidate.get("detail_sha256"):
            raise ValueError("detail CSV hash mismatch")
        if candidate.get("detail_row_count") != expected_detail_rows:
            raise ValueError("candidate detail row count mismatch")
        aggregate = aggregate_map[candidate_id]
        if (
            candidate.get("status_code") not in allowed_statuses
            or aggregate["status_code"] not in allowed_statuses
        ):
            raise ValueError("undeclared candidate/aggregate status")
        if (
            candidate.get("status_code") != aggregate["status_code"]
            or candidate.get("detail_sha256") != aggregate["detail_sha256"]
            or str(candidate.get("detail_row_count"))
            != aggregate["detail_row_count"]
            or len(aggregate["consumer_results_sha256"]) != 64
        ):
            raise ValueError("aggregate/candidate binding mismatch")
        expected_consumers = {
            (str(point["k"]), str(point["m"]))
            for point in partition["consumer_points"]
        }
        observed = set()
        observed_rows = set()
        expected_rows = {
            (str(point["k"]), str(point["m"]), pattern, str(rep))
            for point in partition["consumer_points"]
            for pattern in ("all_match", "no_match", "random")
            for rep in range(reps)
        }
        ring, depth, sms = candidate_specs[candidate_id]
        status_rank = {
            "OK": 0, "SATURATED": 1, "DECRYPT_FAIL": 2,
            "CONTEXT_ERROR": 3, "TIMEOUT": 4, "PROCESS_ERROR": 5,
        }
        effective_status = "OK"
        consumer_reductions = {}
        first_detail = detail_rows[0]
        for detail in detail_rows:
            if (
                detail["profile"] != partition["profile_id"]
                or detail["key_id"] != partition["key_id"]
                or detail["candidate_id"] != candidate_id
                or detail["circuit"] != partition["circuit"]
                or detail["shape_id"] != partition["shape_id"]
                or detail["security"] != partition["security"]
                or detail["requested_ring_dim"]
                != str(partition["requested_ring_dim"])
                or detail["natural_ring_dim"] != str(natural_ring_dim)
                or detail["ring_dim_calibrated"] != str(ring)
                or detail["realized_ring_dim"] != str(ring)
                or detail["natural_depth"]
                != str(partition["natural_depth"])
                or detail["provisioned_depth"] != str(depth)
                or detail["scaling_mod_size"] != str(sms)
                or detail["openfhe_version"] != matrix["openfhe_version"]
                or detail["source_commit"] != runtime_source_commit
                or detail["status_code"] not in allowed_statuses
            ):
                raise ValueError("detail identity/provenance mismatch")
            observed.add((detail["consumer_k"], detail["consumer_m"]))
            detail_key = (
                detail["consumer_k"], detail["consumer_m"],
                detail["pattern"], detail["rep_index"]
            )
            if detail_key not in expected_rows:
                raise ValueError("detail row topology mismatch")
            observed_rows.add(detail_key)
            detail_status = detail["status_code"]
            if detail["saturated"] == "1" and status_rank[
                "SATURATED"] > status_rank[detail_status]:
                detail_status = "SATURATED"
            if detail["decrypt_ok"] != "1" and status_rank[
                "DECRYPT_FAIL"] > status_rank[detail_status]:
                detail_status = "DECRYPT_FAIL"
            if status_rank[detail_status] > status_rank[effective_status]:
                effective_status = detail_status
            consumer_key = (int(detail["consumer_k"]), int(detail["consumer_m"]))
            reduction = consumer_reductions.setdefault(consumer_key, {
                "eval": None, "headroom": None, "decrypt": True,
                "saturated": False, "ct_bytes": None, "status": "OK",
            })
            eval_value = (
                float(detail["eval_noise_bits"])
                if detail["eval_noise_bits"] else None)
            headroom_value = (
                float(detail["headroom_bits"])
                if detail["headroom_bits"] else None)
            ct_value = int(detail["ct_bytes"]) if detail["ct_bytes"] else None
            if eval_value is not None and (
                reduction["eval"] is None or eval_value > reduction["eval"]
            ):
                reduction["eval"] = eval_value
            if headroom_value is not None and (
                reduction["headroom"] is None
                or headroom_value < reduction["headroom"]
            ):
                reduction["headroom"] = headroom_value
            reduction["decrypt"] &= detail["decrypt_ok"] == "1"
            reduction["saturated"] |= detail["saturated"] == "1"
            if ct_value is not None and (
                reduction["ct_bytes"] is None
                or ct_value > reduction["ct_bytes"]
            ):
                reduction["ct_bytes"] = ct_value
            if status_rank[detail_status] > status_rank[reduction["status"]]:
                reduction["status"] = detail_status
        if observed != expected_consumers:
            raise ValueError("detail consumer topology mismatch")
        if observed_rows != expected_rows:
            raise ValueError("detail row topology mismatch")
        if (
            candidate.get("status_code") != effective_status
            or aggregate["status_code"] != effective_status
        ):
            raise ValueError("detail status reduction mismatch")
        def number(value):
            return "" if value is None else format(value, ".17g")
        consumer_lines = []
        overall_eval = None
        overall_headroom = None
        overall_decrypt = True
        overall_saturated = False
        overall_ct = None
        worst_k = 0
        worst_m = 0
        for (consumer_k, consumer_m), reduction in sorted(
            consumer_reductions.items()
        ):
            consumer_lines.append(
                f"{consumer_k},{consumer_m},{number(reduction['eval'])},"
                f"{number(reduction['headroom'])},"
                f"{1 if reduction['decrypt'] else 0},"
                f"{1 if reduction['saturated'] else 0},"
                f"{'' if reduction['ct_bytes'] is None else reduction['ct_bytes']},"
                f"{reduction['status']}\n")
            if reduction["eval"] is not None and (
                overall_eval is None or reduction["eval"] > overall_eval
            ):
                overall_eval = reduction["eval"]
                worst_k, worst_m = consumer_k, consumer_m
            if reduction["headroom"] is not None and (
                overall_headroom is None
                or reduction["headroom"] < overall_headroom
            ):
                overall_headroom = reduction["headroom"]
            overall_decrypt &= reduction["decrypt"]
            overall_saturated |= reduction["saturated"]
            if reduction["ct_bytes"] is not None and (
                overall_ct is None or reduction["ct_bytes"] > overall_ct
            ):
                overall_ct = reduction["ct_bytes"]
        expected_consumer_hash = sha256_bytes(
            "".join(consumer_lines).encode())
        expected_reductions = {
            "consumer_count": str(len(consumer_reductions)),
            "worst_consumer_k": str(worst_k),
            "worst_consumer_m": str(worst_m),
            "pattern_count": "3",
            "repetitions_per_pattern": str(reps),
            "eval_noise_bits": number(overall_eval),
            "headroom_bits": number(overall_headroom),
            "decrypt_ok": "1" if overall_decrypt else "0",
            "saturated": "1" if overall_saturated else "0",
            "ct_bytes": "" if overall_ct is None else str(overall_ct),
            "consumer_results_sha256": expected_consumer_hash,
        }
        for field, expected_value in expected_reductions.items():
            if aggregate[field] != expected_value:
                raise ValueError("aggregate reduction mismatch for " + field)
        for field in (
            "num_limbs", "plaintext_mod", "log_q", "log_delta",
            "max_queries", "flood_margin_bits"
        ):
            if aggregate[field] != first_detail[field]:
                raise ValueError("aggregate context reduction mismatch for " + field)
        if overall_eval is not None:
            query_bits = policy["transcript_stat_bits"] + (
                policy["max_queries"] - 1).bit_length()
            coefficient_bits = query_bits + (ring - 1).bit_length()
            flood_bits = (
                int(__import__("math").ceil(overall_eval))
                + coefficient_bits + policy["flood_margin_bits"])
            for field, expected_value in {
                "query_stat_bits": str(query_bits),
                "coefficient_stat_bits": str(coefficient_bits),
                "flood_noise_bits": str(flood_bits),
            }.items():
                if aggregate[field] != expected_value:
                    raise ValueError(
                        "aggregate capacity reduction mismatch for " + field)
    return rows, manifest


def write_failure_atomic(
    profile_dir, partition, status, detail, process_result, smoke,
    natural_ring_dim=""
):
    target = profile_dir / partition["key_id"]
    if target.exists():
        raise ValueError("refusing to overwrite an existing failed shard")
    temporary = Path(tempfile.mkdtemp(
        prefix="." + partition["key_id"] + ".tmp-", dir=profile_dir))
    failure = {
        "schema": "piccard-runner-failure",
        "version": 1,
        "key_id": partition["key_id"],
        "status_code": status,
        "detail": detail,
        "exit_code": process_result.get("returncode"),
        "term_sent": process_result.get("term_sent", False),
        "kill_sent": process_result.get("kill_sent", False),
        "elapsed_ms": process_result.get("elapsed_ms", 0),
        "smoke_only": smoke,
        "table_eligible": False,
    }
    atomic_json(temporary / "failure.json", failure)
    fields = {name: "" for name in AGGREGATE_HEADER.split(",")}
    fields.update({
        "profile": partition["profile_id"],
        "circuit": partition["circuit"],
        "shape_id": partition["shape_id"],
        "security": partition["security"],
        "consumer_count": str(len(partition["consumer_points"])),
        "consumer_set_sha256": partition["consumer_set_sha256"],
        "pattern_count": "3",
        "repetitions_per_pattern":
            str(1 if smoke else policy["repetitions"]),
        "seed": str(ROOT_SEED),
        "requested_ring_dim": str(partition["requested_ring_dim"]),
        "natural_ring_dim":
            str(natural_ring_dim) if natural_ring_dim else "",
        "natural_depth": str(partition["natural_depth"]),
        "max_queries": str(policy["max_queries"]),
        "flood_margin_bits": str(policy["flood_margin_bits"]),
        "openfhe_version": matrix["openfhe_version"],
        "source_commit": runtime_source_commit,
        "status_code": status,
        "error_message": detail,
    })
    with (temporary / "aggregate.csv").open(
        "w", encoding="utf-8", newline=""
    ) as output:
        writer = csv.DictWriter(
            output, fieldnames=AGGREGATE_HEADER.split(","),
            lineterminator="\n")
        writer.writeheader()
        writer.writerow(fields)
    atomic_json(temporary / "shard_manifest.json", {
        "schema": "piccard-shard-manifest",
        "version": 1,
        "key_id": partition["key_id"],
        "status": "INCOMPLETE",
        "key_verdict": "INCOMPLETE",
        "candidate_count": 0,
        "smoke_only": smoke,
        "table_eligible": False,
        "files": {
            "aggregate.csv": sha256_file(temporary / "aggregate.csv"),
            "failure.json": sha256_file(temporary / "failure.json"),
        },
    })
    os.replace(temporary, target)
    print(
        f"{status} {partition['key_id']} {detail} "
        f"term_sent={str(failure['term_sent']).lower()} "
        f"kill_sent={str(failure['kill_sent']).lower()}",
        file=sys.stderr,
    )


script_dir = Path(sys.argv[1]).resolve()
repo_root = script_dir.parent
options = parse_cli(sys.argv[2:])
matrix_path = script_dir / "noise_profiles.json"
matrix_bytes = matrix_path.read_bytes()
matrix = json.loads(matrix_bytes)
if matrix.get("source_commit") != "runtime-source-commit":
    fail("tracked matrix must use runtime-source-commit policy")
if any(p["circuit"] == "threshold" for p in matrix["partitions"]):
    fail("threshold is forbidden in the profile runner")
matrix_sha = sha256_bytes(matrix_bytes)

bench = Path(
    options["bench_noise"] or (repo_root / "build" / "bench_noise")
).resolve()
if not bench.is_file() or not os.access(bench, os.X_OK):
    fail("benchmark path must be an executable file")
default_timeout_ms, grace_ms, test_timing = resolve_timing(bench)

environment = os.environ.copy()
environment["PICCARD_PROFILE_MANIFEST"] = str(matrix_path)
printer = supervise(
    [str(bench), "--print_profile_manifest"],
    120000,
    grace_ms,
    environment,
)
if (
    printer["timed_out"]
    or printer["returncode"] != 0
    or printer["stdout"].encode() != matrix_bytes
):
    fail("benchmark profile printer does not match tracked JSON")
source_printer = supervise(
    [str(bench), "--print_source_commit"],
    120000,
    grace_ms,
    environment,
)
runtime_source_commit = source_printer["stdout"].strip()
if (
    source_printer["timed_out"]
    or source_printer["returncode"] != 0
    or len(runtime_source_commit) != 40
    or any(ch not in "0123456789abcdef" for ch in runtime_source_commit)
):
    fail("benchmark embedded source commit is invalid")
git_head = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=repo_root,
    text=True,
    capture_output=True,
    check=True,
).stdout.strip()
git_status = subprocess.run(
    ["git", "status", "--porcelain=v1", "--untracked-files=all"],
    cwd=repo_root,
    text=True,
    capture_output=True,
    check=True,
).stdout
source_tree_dirty = bool(git_status)
guarded_fake = (
    os.environ.get("PICCARD_TEST_SUPERVISOR") == "1"
    and bench.name == "fake_bench_noise"
)

dry_run = os.environ.get("DRY_RUN") == "1"
if options["results_root"] is None:
    if not options["smoke"]:
        fail("--results-root is required outside --smoke")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    options["results_root"] = (
        f"/tmp/piccard-noise-smoke-{stamp}-{os.getpid()}")
results_root = Path(options["results_root"])
if not results_root.is_absolute():
    fail("--results-root must be absolute")
resolved_root = results_root.resolve(strict=False)
try:
    resolved_root.relative_to(repo_root)
    fail("--results-root must be outside the Git worktree")
except ValueError:
    pass

if dry_run:
    if resolved_root.exists():
        fail("dry-run results root must not exist")
elif options["resume"]:
    if not resolved_root.is_dir():
        fail("--resume requires an existing results root")
else:
    if resolved_root.exists():
        fail("first invocation requires a nonexistent results root")

if not options["smoke"] and not dry_run:
    if runtime_source_commit != git_head:
        fail("actual Git HEAD does not match benchmark embedded source", 2)
    if source_tree_dirty and not guarded_fake:
        fail("evidence mode requires a clean source tree")

resolved_matrix_bytes = matrix_bytes.replace(
    b'"source_commit":"runtime-source-commit"',
    ('"source_commit":"' + runtime_source_commit + '"').encode(),
    1,
)
if resolved_matrix_bytes == matrix_bytes:
    fail("failed to resolve runtime source in profile manifest")
resolved_matrix = json.loads(resolved_matrix_bytes)

run_identity = {
    "schema": "piccard-noise-run",
    "version": 1,
    "source_commit": runtime_source_commit,
    "git_head": git_head,
    "source_tree_dirty": source_tree_dirty,
    "openfhe_version": matrix["openfhe_version"],
    "matrix_sha256": matrix_sha,
    "resolved_matrix_sha256": sha256_bytes(resolved_matrix_bytes),
    "benchmark_sha256": sha256_file(bench),
    "command_policy": "phase3-v1",
    "python_version": platform.python_version(),
    "platform": platform.platform(),
    "smoke_only": options["smoke"],
    "table_eligible": False if options["smoke"] else True,
}
if not dry_run:
    run_manifest_path = resolved_root / "run_manifest.json"
    if options["resume"]:
        existing_identity = json.loads(run_manifest_path.read_text())
        if set(existing_identity) != set(run_identity) | {"run_nonce"}:
            fail("frozen run manifest schema mismatch", 2)
        for key, value in run_identity.items():
            if existing_identity[key] != value:
                fail("frozen run identity mismatch for " + key)
        if (
            not isinstance(existing_identity["run_nonce"], str)
            or len(existing_identity["run_nonce"]) != 32
        ):
            fail("frozen run nonce is invalid", 2)
        run_identity = existing_identity
        resolved_manifest_path = resolved_root / "resolved_noise_profiles.json"
        if resolved_manifest_path.read_bytes() != resolved_matrix_bytes:
            fail("resolved profile manifest source/topology mismatch", 2)
    else:
        run_identity["run_nonce"] = secrets.token_hex(16)
        temporary_root = Path(tempfile.mkdtemp(
            prefix="." + resolved_root.name + ".tmp-",
            dir=resolved_root.parent,
        ))
        atomic_json(temporary_root / "run_manifest.json", run_identity)
        with (temporary_root / "resolved_noise_profiles.json").open(
            "wb"
        ) as output:
            output.write(resolved_matrix_bytes)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_root, resolved_root)
    resolved_manifest_path = resolved_root / "resolved_noise_profiles.json"
else:
    resolved_manifest_path = (
        Path(tempfile.gettempdir()) /
        ("piccard-resolved-profile-"
         + sha256_bytes(resolved_matrix_bytes) + ".json")
    )
    if (
        not resolved_manifest_path.is_file()
        or resolved_manifest_path.read_bytes() != resolved_matrix_bytes
    ):
        temporary_resolved = resolved_manifest_path.with_suffix(".tmp")
        temporary_resolved.write_bytes(resolved_matrix_bytes)
        os.replace(temporary_resolved, resolved_manifest_path)

environment["PICCARD_PROFILE_MANIFEST"] = str(resolved_manifest_path)

partitions = [
    partition for partition in matrix["partitions"]
    if partition["profile_id"] == options["profile"]
]
if options["smoke"]:
    partitions = [
        partition for partition in partitions
        if partition["consumer_points"] == [{"k": 128, "m": 64}]
    ]
    if len(partitions) != 4:
        fail("smoke matrix must contain exactly four singleton cells")
policy = profile_policy(matrix, options["profile"])

profile_dir = resolved_root / "profiles" / options["profile"]
if not dry_run:
    profile_dir.mkdir(parents=True, exist_ok=True)

profile_manifest_path = profile_dir / "profile_manifest.json"
parent_digests = {}
if options["resume"]:
    try:
        seal_path = profile_dir / "completion_seal.json"
        seal = json.loads(seal_path.read_text())
        if set(seal) != {
            "schema", "version", "run_nonce", "profile_id",
            "profile_manifest_sha256", "shard_manifest_sha256"
        }:
            fail("resume completion seal schema mismatch", 2)
        if (
            seal["schema"] != "piccard-profile-completion-seal"
            or seal["version"] != 1
            or seal["run_nonce"] != run_identity["run_nonce"]
            or seal["profile_id"] != options["profile"]
            or seal["profile_manifest_sha256"]
            != sha256_file(profile_manifest_path)
        ):
            fail("resume completion seal mismatch", 2)
        prior_profile_manifest = json.loads(profile_manifest_path.read_text())
        if (
            prior_profile_manifest.get("profile_id") != options["profile"]
            or prior_profile_manifest.get("source_commit")
            != runtime_source_commit
            or prior_profile_manifest.get("smoke_only") != options["smoke"]
        ):
            fail("resume profile manifest identity mismatch", 2)
        parent_digests = prior_profile_manifest.get(
            "shard_manifest_sha256", {})
        if seal["shard_manifest_sha256"] != parent_digests:
            fail("resume completion seal shard digest mismatch", 2)
    except (OSError, ValueError) as error:
        fail("resume profile manifest is missing or malformed: " + str(error), 2)

any_incomplete = False
key_verdicts = {}
for partition in partitions:
    target = profile_dir / partition["key_id"]
    if options["resume"] and target.exists():
        try:
            prior = validate_shard(
                target, partition, parent_digests.get(partition["key_id"]))
            key_verdicts[partition["key_id"]] = prior["key_verdict"]
        except Exception as error:
            print(
                f"resume shard hash validation failed: {error}",
                file=sys.stderr,
            )
            any_incomplete = True
            break
        print("SKIP " + partition["key_id"])
        continue
    if target.exists():
        fail("refusing to overwrite prior shard " + partition["key_id"])

    preflight_command = [
        str(bench),
        "--preflight_context",
        *identity_arguments(
            partition, matrix, policy, resolved_manifest_path),
        "--scaling_mod_grid=40",
        "--max_depth_delta=0",
        f"--ring_candidates={partition['requested_ring_dim']}",
        "--timeout_seconds=120",
        f"--reps={1 if options['smoke'] else policy['repetitions']}",
    ]
    if options["smoke"]:
        preflight_command.append("--smoke")
    preflight = supervise(
        preflight_command,
        default_timeout_ms if test_timing else 120000,
        grace_ms,
        environment,
        test_readiness=test_timing,
    )
    try:
        if preflight["timed_out"]:
            raise TimeoutError("preflight wall timeout")
        if preflight["returncode"] != 0:
            raise RuntimeError(
                "preflight exit " + str(preflight["returncode"]))
        natural_ring_dim = validate_preflight(
            json.loads(preflight["stdout"]), partition, matrix)
    except Exception as error:
        if not dry_run:
            failure_status = (
                "TIMEOUT" if preflight["timed_out"] else "PROCESS_ERROR")
            write_failure_atomic(
                profile_dir,
                partition,
                failure_status,
                str(error),
                preflight,
                options["smoke"],
            )
        else:
            print(
                "PROCESS_ERROR " + partition["key_id"] + " " + str(error),
                file=sys.stderr,
            )
        any_incomplete = True
        break

    rings, scaling_grid, max_depth_delta, reps, candidate_ids = (
        search_topology(
            partition, natural_ring_dim, policy, options["smoke"]))
    candidate_count = len(candidate_ids)
    largest_n = max(rings)
    timeout_seconds = timeout_for(largest_n)

    temporary_path = (
        profile_dir / ("." + partition["key_id"] + ".tmp-" + str(os.getpid()))
        if not dry_run else
        resolved_root / "profiles" / options["profile"] /
        ("." + partition["key_id"] + ".dry-run")
    )
    measurement_command = [
        str(bench),
        *identity_arguments(
            partition, matrix, policy, resolved_manifest_path),
        f"--scaling_mod_grid={','.join(map(str, scaling_grid))}",
        f"--max_depth_delta={max_depth_delta}",
        f"--ring_candidates={','.join(map(str, rings))}",
        f"--timeout_seconds={timeout_seconds}",
        f"--reps={reps}",
        f"--aggregate_csv={temporary_path / 'aggregate.csv'}",
        f"--detail_dir={temporary_path / 'details'}",
        f"--candidate_manifest={temporary_path / 'candidates.json'}",
    ]
    if options["smoke"]:
        measurement_command.append("--smoke")
    if dry_run:
        print(
            "SHARD "
            + partition["key_id"]
            + f" candidates={candidate_count}"
            + f" largest_n={largest_n}"
            + f" timeout={timeout_seconds}"
            + " command="
            + json.dumps(measurement_command, separators=(",", ":"))
        )
        continue

    temporary_path.mkdir()
    (temporary_path / "details").mkdir()
    measurement = supervise(
        measurement_command,
        default_timeout_ms
        if test_timing
        else timeout_seconds * 1000,
        grace_ms,
        environment,
        test_readiness=test_timing,
    )
    if measurement["timed_out"] or measurement["returncode"] != 0:
        status = "TIMEOUT" if measurement["timed_out"] else "PROCESS_ERROR"
        detail = (
            "measurement wall timeout"
            if measurement["timed_out"]
            else "measurement exit " + str(measurement["returncode"])
        )
        shutil.rmtree(temporary_path)
        write_failure_atomic(
            profile_dir,
            partition,
            status,
            detail,
            measurement,
            options["smoke"],
            natural_ring_dim,
        )
        any_incomplete = True
        break
    executed_command = measurement_command
    measurement_command = []
    for argument in executed_command:
        if argument.startswith("--aggregate_csv="):
            argument = f"--aggregate_csv={target / 'aggregate.csv'}"
        elif argument.startswith("--detail_dir="):
            argument = f"--detail_dir={target / 'details'}"
        elif argument.startswith("--candidate_manifest="):
            argument = f"--candidate_manifest={target / 'candidates.json'}"
        measurement_command.append(argument)
    try:
        candidate_value = json.loads(
            (temporary_path / "candidates.json").read_text())
        candidate_value["command"] = measurement_command[1:]
        atomic_json(temporary_path / "candidates.json", candidate_value)
    except Exception as error:
        shutil.rmtree(temporary_path)
        write_failure_atomic(
            profile_dir, partition, "PROCESS_ERROR",
            "candidate command normalization failed: " + str(error),
            measurement, options["smoke"], natural_ring_dim)
        any_incomplete = True
        break
    try:
        aggregate_rows, candidate_manifest = validate_measurement(
            temporary_path,
            partition,
            natural_ring_dim,
            rings,
            scaling_grid,
            max_depth_delta,
            reps,
            measurement_command[1:],
            target,
        )
    except Exception as error:
        shutil.rmtree(temporary_path)
        write_failure_atomic(
            profile_dir,
            partition,
            "PROCESS_ERROR",
            str(error),
            measurement,
            options["smoke"],
            natural_ring_dim,
        )
        any_incomplete = True
        break

    files = {}
    for path in sorted(
        candidate
        for candidate in temporary_path.rglob("*")
        if candidate.is_file()
    ):
        files[path.relative_to(temporary_path).as_posix()] = sha256_file(path)
    key_verdict = (
        "SELECTED"
        if any(row["status_code"] == "OK" for row in aggregate_rows)
        else "INFEASIBLE"
    )
    shard_manifest = {
        "schema": "piccard-shard-manifest",
        "version": 1,
        "key_id": partition["key_id"],
        "profile_id": partition["profile_id"],
        "status": "COMPLETE",
        "key_verdict": key_verdict,
        "candidate_count": candidate_count,
        "expected_detail_rows":
            len(partition["consumer_points"]) * 3 * reps,
        "natural_ring_dim": natural_ring_dim,
        "largest_candidate_ring_dim": largest_n,
        "timeout_seconds": timeout_seconds,
        "measurement_command": measurement_command,
        "executed_command": executed_command,
        **expected_identity(partition, runtime_source_commit),
        "ring_candidates": rings,
        "scaling_mod_grid": scaling_grid,
        "max_depth_delta": max_depth_delta,
        "repetitions": reps,
        "smoke_only": options["smoke"],
        "table_eligible": False if options["smoke"] else True,
        "files": files,
    }
    atomic_json(temporary_path / "shard_manifest.json", shard_manifest)
    os.replace(temporary_path, target)
    key_verdicts[partition["key_id"]] = key_verdict

if not dry_run:
    shard_digests = {
        partition["key_id"]: sha256_file(
            profile_dir / partition["key_id"] / "shard_manifest.json")
        for partition in partitions
        if (profile_dir / partition["key_id"] / "shard_manifest.json").is_file()
    }
    if any_incomplete and options["profile"] == "primary40":
        profile_verdict = "FAIL_REQUIRED"
    elif any_incomplete:
        profile_verdict = "FAIL_INCOMPLETE"
    elif (
        options["profile"] in {"primary40", "sensitivity64"}
        and any(value == "INFEASIBLE" for value in key_verdicts.values())
    ):
        profile_verdict = "FAIL_REQUIRED"
    elif (
        options["profile"] == "feasibility128"
        and any(value == "INFEASIBLE" for value in key_verdicts.values())
    ):
        profile_verdict = "PASS_FEASIBILITY_WITH_INFEASIBLE"
    else:
        profile_verdict = "PASS"
    profile_value = {
        "schema": "piccard-profile-run",
        "version": 1,
        "profile_id": options["profile"],
        "key_count": len(partitions),
        "key_verdicts": key_verdicts,
        "profile_verdict": profile_verdict,
        "source_commit": runtime_source_commit,
        "openfhe_version": matrix["openfhe_version"],
        "smoke_only": options["smoke"],
        "table_eligible": False if options["smoke"] else True,
        "shard_manifest_sha256": shard_digests,
    }
    if options["resume"]:
        if prior_profile_manifest != profile_value:
            fail("resume profile manifest semantics mismatch", 2)
    else:
        atomic_json(profile_manifest_path, profile_value)
        write_once_json(profile_dir / "completion_seal.json", {
            "schema": "piccard-profile-completion-seal",
            "version": 1,
            "run_nonce": run_identity["run_nonce"],
            "profile_id": options["profile"],
            "profile_manifest_sha256": sha256_file(profile_manifest_path),
            "shard_manifest_sha256": shard_digests,
        })

required_failure = (
    not dry_run
    and profile_verdict in {"FAIL_INCOMPLETE", "FAIL_REQUIRED"}
)
raise SystemExit(2 if any_incomplete or required_failure else 0)
PY
