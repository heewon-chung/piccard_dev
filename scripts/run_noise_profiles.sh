#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
import csv
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import secrets
import stat
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
DIAGNOSTIC_LOG_NAMES = {
    "stdout": "benchmark.stdout.log",
    "stderr": "benchmark.stderr.log",
}
MAX_DIAGNOSTIC_LOG_BYTES = 1_048_576
MAX_SUCCESSOR_DIAGNOSTIC_BYTES = 4_096


def fail(message, code=1):
    print(message, file=sys.stderr)
    raise SystemExit(code)


def bounded_successor_diagnostic(stderr):
    """Return child stderr in a deterministic, bounded failure message."""
    if not stderr:
        return ""
    payload = str(stderr).strip().encode("utf-8", errors="replace")
    if len(payload) <= MAX_SUCCESSOR_DIAGNOSTIC_BYTES:
        return payload.decode("utf-8", errors="replace")
    marker = b"\n[PICCARD_SUCCESSOR_DIAGNOSTIC_TRUNCATED]\n"
    budget = MAX_SUCCESSOR_DIAGNOSTIC_BYTES - len(marker)
    head = budget // 2
    tail = budget - head
    return (payload[:head] + marker + payload[-tail:]).decode(
        "utf-8", errors="replace")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_benchmark_binary(path, expected_sha256):
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("benchmark binary disappeared") from error
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("benchmark binary is not a direct regular file")
    if sha256_file(path) != expected_sha256:
        raise ValueError("benchmark binary SHA changed during the run")


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
        "finalize_dir": None,
        "reps": None,
        "seed": None,
        "max_queries": None,
        "margin": None,
        "revision_cell": None,
        "run_profile": None,
        "repetitions": None,
        "threads": None,
    }
    names = {
        "--results-root": "results_root",
        "--profile": "profile",
        "--bench-noise": "bench_noise",
        "--finalize-dir": "finalize_dir",
        "--reps": "reps",
        "--seed": "seed",
        "--max-queries": "max_queries",
        "--margin": "margin",
        "--revision-cell": "revision_cell",
        "--run-profile": "run_profile",
        "--repetitions": "repetitions",
        "--threads": "threads",
    }
    integer_options = {
        "reps", "seed", "max_queries", "margin", "repetitions", "threads"
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
                    if key in integer_options:
                        if not value.isdigit():
                            fail(option + " requires a nonnegative integer")
                        value = int(value)
                    result[key] = value
                    matched = True
                    break
                if argument == option:
                    if result[key] is not None:
                        fail("duplicate " + option)
                    index += 1
                    if index >= len(arguments) or arguments[index].startswith("--"):
                        fail(option + " requires a value")
                    value = arguments[index]
                    if key in integer_options:
                        if not value.isdigit():
                            fail(option + " requires a nonnegative integer")
                        value = int(value)
                    result[key] = value
                    matched = True
                    break
            if not matched:
                fail("unknown runner argument: " + argument)
        index += 1
    if result["finalize_dir"] is not None:
        if (
            result["results_root"] is None
            or result["profile"] is not None
            or result["resume"]
            or result["bench_noise"] is not None
            or result["smoke"]
            or result["reps"] is not None
            or result["seed"] is not None
            or result["max_queries"] is not None
            or result["margin"] is not None
            or result["revision_cell"] is not None
            or result["run_profile"] is not None
            or result["repetitions"] is not None
            or result["threads"] is not None
        ):
            fail(
                "--finalize-dir requires only one --results-root and "
                "cannot be mixed with execution options")
        return result
    if result["run_profile"] is not None and result["run_profile"] not in {
        "paper-v1", "readiness-toy-v1"
    }:
        fail("--run-profile must be paper-v1|readiness-toy-v1")
    if result["revision_cell"] is not None:
        if result["run_profile"] is None:
            fail("--revision-cell requires --run-profile")
        if result["profile"] not in {
            "primary40", "sensitivity64", "feasibility128"
        }:
            fail("revision-cell path requires --profile=primary40|sensitivity64|feasibility128")
        if result["smoke"] or result["resume"]:
            fail("revision-cell path rejects --smoke and --resume")
        if result["reps"] is not None:
            fail("revision-cell path uses --repetitions, not --reps")
        expected_repetitions = (
            5 if result["run_profile"] == "paper-v1" else 1
        )
        if result["repetitions"] is not None and result["repetitions"] != expected_repetitions:
            fail(
                f"--repetitions={result['repetitions']} contradicts "
                f"{result['run_profile']} value {expected_repetitions}")
        if result["run_profile"] == "readiness-toy-v1" and result["profile"] != "primary40":
            fail("readiness-toy-v1 supports primary40 only")
        if result["results_root"] is None:
            fail("revision-cell path requires --results-root")
        return result
    if result["run_profile"] is not None:
        if result["profile"] is None:
            result["profile"] = "primary40"
        if result["run_profile"] == "readiness-toy-v1" and result["profile"] != "primary40":
            fail("readiness-toy-v1 selects primary40 only")
        if result["smoke"] or result["resume"]:
            fail("successor --run-profile rejects --smoke and --resume")
        if result["reps"] is not None:
            fail("successor --run-profile uses --repetitions, not --reps")
        expected_repetitions = (
            5 if result["run_profile"] == "paper-v1" else 1
        )
        if result["repetitions"] is not None and result["repetitions"] != expected_repetitions:
            fail(
                f"--repetitions={result['repetitions']} contradicts "
                f"{result['run_profile']} value {expected_repetitions}")
        if result["results_root"] is None:
            fail("successor --run-profile requires --results-root")
        return result
    if result["repetitions"] is not None or result["threads"] is not None:
        fail("--repetitions/--threads require --run-profile")
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


class SupervisionError(RuntimeError):
    def __init__(self, message, process_result, capture_state):
        super().__init__(message)
        self.process_result = process_result
        self.capture_state = capture_state


def empty_process_result():
    return {
        "returncode": None,
        "stdout": None,
        "stderr": None,
        "timed_out": False,
        "term_sent": False,
        "kill_sent": False,
        "elapsed_ms": 0,
    }


def remove_created_capture(path, identity):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (info.st_dev, info.st_ino) != identity
    ):
        raise ValueError("diagnostic capture ownership changed")
    path.unlink()


def supervise(
    command, timeout_ms, grace_ms, environment, test_readiness=False,
    capture_paths=None,
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
    capture_files = {}
    capture_identities = {}
    if capture_paths is not None:
        if set(capture_paths) != set(DIAGNOSTIC_LOG_NAMES):
            raise SupervisionError(
                "diagnostic capture path set mismatch",
                empty_process_result(),
                "NOT_STARTED",
            )
        try:
            for stream in ("stdout", "stderr"):
                if (
                    stream == "stderr"
                    and guarded_fake
                    and os.environ.get(
                        "PICCARD_TEST_FAIL_SECOND_CAPTURE") == "1"
                ):
                    raise OSError("guarded second diagnostic sink failure")
                descriptor = os.open(
                    capture_paths[stream],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                info = os.fstat(descriptor)
                capture_identities[stream] = (info.st_dev, info.st_ino)
                capture_files[stream] = os.fdopen(descriptor, "wb")
        except Exception as error:
            for output in capture_files.values():
                output.close()
            for stream, identity in capture_identities.items():
                remove_created_capture(capture_paths[stream], identity)
            raise SupervisionError(
                "diagnostic capture setup failed: " + str(error),
                empty_process_result(),
                "NOT_STARTED",
            ) from error
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdout=(
                capture_files["stdout"]
                if capture_paths is not None else subprocess.PIPE
            ),
            stderr=(
                capture_files["stderr"]
                if capture_paths is not None else subprocess.PIPE
            ),
            text=capture_paths is None,
            env=child_environment,
            start_new_session=True,
        )
    except Exception as error:
        for output in capture_files.values():
            output.close()
        for stream, identity in capture_identities.items():
            remove_created_capture(capture_paths[stream], identity)
        raise SupervisionError(
            "benchmark launch failed: " + str(error),
            empty_process_result(),
            "NOT_STARTED",
        ) from error

    timed_out = False
    term_sent = False
    kill_sent = False
    stdout = None
    stderr = None
    supervision_error = None
    capture_error = None
    try:
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
                    kill_sent = True
                    os.killpg(process.pid, signal.SIGKILL)
                if capture_paths is None:
                    stdout, stderr = process.communicate()
                else:
                    process.wait()
                raise RuntimeError(
                    "guarded fake benchmark did not publish readiness "
                    f"(returncode={process.returncode})")
            readiness_marker.unlink(missing_ok=True)
            started = time.monotonic()
        deadline = started + timeout_ms / 1000.0
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.002)
        if process.poll() is None:
            timed_out = True
            term_sent = True
            os.killpg(process.pid, signal.SIGTERM)
            grace_deadline = time.monotonic() + grace_ms / 1000.0
            while (
                process.poll() is None
                and time.monotonic() < grace_deadline
            ):
                time.sleep(0.002)
            if process.poll() is None:
                kill_sent = True
                os.killpg(process.pid, signal.SIGKILL)
        if capture_paths is None:
            stdout, stderr = process.communicate()
        else:
            process.wait()
    except Exception as error:
        if process.poll() is None:
            kill_sent = True
            os.killpg(process.pid, signal.SIGKILL)
        if capture_paths is None:
            process.communicate()
        else:
            process.wait()
        receipt = {
            "returncode": process.returncode,
            "stdout": None,
            "stderr": None,
            "timed_out": timed_out,
            "term_sent": term_sent,
            "kill_sent": kill_sent,
            "elapsed_ms":
                round((time.monotonic() - started) * 1000, 3),
        }
        supervision_error = SupervisionError(
            str(error), receipt, "COMPLETE")
        supervision_error.__cause__ = error
    finally:
        readiness_marker.unlink(
            missing_ok=True) if readiness_marker is not None else None
        for output in capture_files.values():
            if not output.closed:
                try:
                    output.flush()
                    os.fsync(output.fileno())
                except Exception as error:
                    if capture_error is None:
                        capture_error = error
                finally:
                    output.close()
    if supervision_error is not None:
        raise supervision_error
    if capture_error is not None:
        receipt = {
            "returncode": process.returncode,
            "stdout": None,
            "stderr": None,
            "timed_out": timed_out,
            "term_sent": term_sent,
            "kill_sent": kill_sent,
            "elapsed_ms":
                round((time.monotonic() - started) * 1000, 3),
        }
        raise SupervisionError(
            "diagnostic capture durability failed: " + str(capture_error),
            receipt,
            "COMPLETE",
        ) from capture_error
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


def validate_cli_confirmations(options, policy):
    expected = {
        # effective values -- what the shard commands actually receive,
        # not the raw policy: smoke shards run with --reps=1
        "reps": 1 if options["smoke"] else policy["repetitions"],
        "seed": ROOT_SEED,
        "max_queries": policy["max_queries"],
        "margin": policy["flood_margin_bits"],
    }
    for name, expected_value in expected.items():
        supplied = options[name]
        if supplied is not None and supplied != expected_value:
            fail(f"--{name.replace('_', '-')}={supplied} contradicts the "
                 f"effective run value {expected_value}; the CLI may "
                 "confirm but never override the profile matrix")


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
        "run_nonce": runtime_run_nonce,
        "benchmark_sha256": runtime_benchmark_sha256,
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
            raise ValueError(
                "candidate command mismatch for " + key + ": "
                + repr(values.get(key)) + " != " + repr(value))


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
            "worst_consumer_k": "" if overall_eval is None else str(worst_k),
            "worst_consumer_m": "" if overall_eval is None else str(worst_m),
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


def persist_bounded_diagnostic(source, destination):
    """Return path/hash/original_bytes/stored_bytes/truncated metadata."""
    source_info = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(source_info.st_mode):
        raise ValueError("diagnostic source is not a direct regular file")
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_descriptor = os.open(source, source_flags)
    destination_descriptor = None
    try:
        opened_info = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(opened_info.st_mode)
            or (opened_info.st_dev, opened_info.st_ino)
            != (source_info.st_dev, source_info.st_ino)
        ):
            raise ValueError("diagnostic source identity changed")
        original_size = opened_info.st_size
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )

        def write_bytes(data):
            view = memoryview(data)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]

        def copy_bytes(byte_count):
            remaining = byte_count
            while remaining:
                block = os.read(source_descriptor, min(65536, remaining))
                if not block:
                    raise ValueError("diagnostic source shortened while copying")
                write_bytes(block)
                remaining -= len(block)

        truncated = original_size > MAX_DIAGNOSTIC_LOG_BYTES
        if not truncated:
            copy_bytes(original_size)
        else:
            marker = (
                "\n[PICCARD_DIAGNOSTIC_TRUNCATED "
                f"original_bytes={original_size}]\n"
            ).encode("ascii")
            payload_budget = MAX_DIAGNOSTIC_LOG_BYTES - len(marker)
            head_bytes = payload_budget // 2
            tail_bytes = payload_budget - head_bytes
            copy_bytes(head_bytes)
            write_bytes(marker)
            os.lseek(source_descriptor, original_size - tail_bytes, os.SEEK_SET)
            copy_bytes(tail_bytes)
        os.fsync(destination_descriptor)
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)
    stored_size = destination.stat().st_size
    return {
        "path": destination.name,
        "sha256": sha256_file(destination),
        "original_bytes": original_size,
        "stored_bytes": stored_size,
        "truncated": truncated,
    }


def validate_owned_failure_publish_temporary(
    path, profile_dir, partition
):
    expected_prefix = (
        "." + partition["key_id"]
        + ".piccard-failure-v2.tmp-" + runtime_run_nonce + "-"
    )
    if (
        path.parent != profile_dir
        or not path.name.startswith(expected_prefix)
        or path.name == expected_prefix
    ):
        raise ValueError("unowned failure publisher temporary basename")
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ValueError("unowned failure publisher temporary")
    marker = path / ".piccard-failure-publisher-owner.json"
    marker_info = marker.lstat()
    if (
        marker.is_symlink()
        or not stat.S_ISREG(marker_info.st_mode)
        or marker_info.st_nlink != 1
    ):
        raise ValueError("unowned failure publisher temporary marker")
    expected = {
        "key_id": partition["key_id"],
        "profile_id": partition["profile_id"],
        "run_nonce": runtime_run_nonce,
        "temporary_realpath": str(path.resolve(strict=True)),
        "schema": "piccard-failure-publisher-owner",
        "version": 1,
    }
    rendered = (
        json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if marker.read_bytes() != rendered:
        raise ValueError("unowned failure publisher temporary marker")


def remove_owned_failure_publish_temporary(path, profile_dir, partition):
    validate_owned_failure_publish_temporary(path, profile_dir, partition)
    shutil.rmtree(path)


def write_failure_atomic(
    profile_dir, partition, status, detail, process_result, smoke,
    natural_ring_dim="", *, phase, capture_state,
    diagnostic_source_dir=None,
):
    legal_state = (
        (phase == "preflight"
         and capture_state == "NOT_APPLICABLE"
         and diagnostic_source_dir is None)
        or
        (phase == "measurement"
         and capture_state == "NOT_STARTED"
         and diagnostic_source_dir is None)
        or
        (phase == "measurement"
         and capture_state == "COMPLETE"
         and diagnostic_source_dir is not None)
    )
    if not legal_state:
        raise ValueError("invalid failure diagnostic capture state")
    target = profile_dir / partition["key_id"]
    if target.exists():
        raise ValueError("refusing to overwrite an existing failed shard")
    temporary = Path(tempfile.mkdtemp(
        prefix=(
            "." + partition["key_id"]
            + ".piccard-failure-v2.tmp-" + runtime_run_nonce + "-"
        ),
        dir=profile_dir,
    ))
    marker = temporary / ".piccard-failure-publisher-owner.json"
    marker_value = {
        "key_id": partition["key_id"],
        "profile_id": partition["profile_id"],
        "run_nonce": runtime_run_nonce,
        "temporary_realpath": str(temporary.resolve(strict=True)),
        "schema": "piccard-failure-publisher-owner",
        "version": 1,
    }
    marker_descriptor = os.open(
        marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(marker_descriptor, "wb", closefd=False) as output:
            output.write(
                (json.dumps(
                    marker_value, sort_keys=True, separators=(",", ":"))
                 + "\n").encode())
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(marker_descriptor)
    fsync_directory(temporary)
    publisher_owned = True
    diagnostic_logs = {}
    failure = {
        "schema": "piccard-runner-failure",
        "version": 2,
        "key_id": partition["key_id"],
        "status_code": status,
        "detail": detail,
        "exit_code": process_result.get("returncode"),
        "term_sent": process_result.get("term_sent", False),
        "kill_sent": process_result.get("kill_sent", False),
        "elapsed_ms": process_result.get("elapsed_ms", 0),
        "smoke_only": smoke,
        "table_eligible": False,
        "phase": phase,
        "capture_state": capture_state,
        "diagnostic_logs": diagnostic_logs,
    }
    try:
        if (
            guarded_fake
            and os.environ.get("PICCARD_TEST_PUBLISH_PAYLOAD_FAILURE") == "1"
        ):
            raise OSError("guarded failure publisher payload failure")
        if capture_state == "COMPLETE":
            for stream, name in DIAGNOSTIC_LOG_NAMES.items():
                diagnostic_logs[stream] = persist_bounded_diagnostic(
                    diagnostic_source_dir / name,
                    temporary / name,
                )
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
            output.flush()
            os.fsync(output.fileno())
        files = {
            "aggregate.csv": sha256_file(temporary / "aggregate.csv"),
            "failure.json": sha256_file(temporary / "failure.json"),
        }
        files.update({
            metadata["path"]: metadata["sha256"]
            for metadata in diagnostic_logs.values()
        })
        atomic_json(temporary / "shard_manifest.json", {
            "schema": "piccard-shard-manifest",
            "version": 1,
            "key_id": partition["key_id"],
            "profile_id": partition["profile_id"],
            "status": "INCOMPLETE",
            "key_verdict": "INCOMPLETE",
            "candidate_count": 0,
            "smoke_only": smoke,
            "table_eligible": False,
            "source_commit": runtime_source_commit,
            "openfhe_version": matrix["openfhe_version"],
            "run_nonce": runtime_run_nonce,
            "benchmark_sha256": runtime_benchmark_sha256,
            "files": files,
        })
        fsync_directory(temporary)
        validate_owned_failure_publish_temporary(
            temporary, profile_dir, partition)
        marker.unlink()
        publisher_owned = False
        fsync_directory(temporary)
        os.replace(temporary, target)
        fsync_directory(profile_dir)
    except Exception as error:
        if publisher_owned:
            cleanup_path = temporary
            if (
                guarded_fake
                and os.environ.get(
                    "PICCARD_TEST_SWAP_PUBLISHER_CLEANUP") == "1"
                and diagnostic_source_dir is not None
            ):
                cleanup_path = diagnostic_source_dir
            try:
                remove_owned_failure_publish_temporary(
                    cleanup_path, profile_dir, partition)
            except Exception as cleanup_error:
                raise cleanup_error from error
        raise
    print(
        f"{status} {partition['key_id']} {detail} "
        f"term_sent={str(failure['term_sent']).lower()} "
        f"kill_sent={str(failure['kill_sent']).lower()}",
        file=sys.stderr,
    )


INCOMPLETE_SHARD_FIELDS = {
    "schema", "version", "key_id", "profile_id", "status", "key_verdict",
    "candidate_count", "smoke_only", "table_eligible", "source_commit",
    "openfhe_version", "run_nonce", "benchmark_sha256", "files",
}
FAILURE_FIELDS = {
    "schema", "version", "key_id", "status_code", "detail", "exit_code",
    "term_sent", "kill_sent", "elapsed_ms", "smoke_only",
    "table_eligible", "phase", "capture_state", "diagnostic_logs",
}
DIAGNOSTIC_LOG_FIELDS = {
    "path", "sha256", "original_bytes", "stored_bytes", "truncated",
}


def validate_incomplete_shard(shard, partition, parent_digest):
    info = shard.lstat()
    if shard.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ValueError("incomplete shard is not a direct real directory")
    manifest_path = shard / "shard_manifest.json"
    if parent_digest is not None:
        if (
            not isinstance(parent_digest, str)
            or len(parent_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in parent_digest)
        ):
            raise ValueError("invalid incomplete parent shard digest")
        if sha256_file(manifest_path) != parent_digest:
            raise ValueError("immutable parent shard digest mismatch")
    manifest = load_json_exact(
        manifest_path,
        INCOMPLETE_SHARD_FIELDS,
        "incomplete shard manifest",
    )
    expected = expected_identity(partition, runtime_source_commit)
    identity_fields = (
        "key_id", "profile_id", "source_commit", "openfhe_version",
        "run_nonce", "benchmark_sha256",
    )
    if (
        manifest["schema"] != "piccard-shard-manifest"
        or manifest["version"] != 1
        or manifest["status"] != "INCOMPLETE"
        or manifest["key_verdict"] != "INCOMPLETE"
        or manifest["candidate_count"] != 0
        or manifest["smoke_only"] != options["smoke"]
        or manifest["table_eligible"] is not False
        or any(manifest[field] != expected[field] for field in identity_fields)
    ):
        raise ValueError("incomplete shard identity/schema mismatch")
    failure = load_json_exact(
        shard / "failure.json", FAILURE_FIELDS, "failure receipt")
    if (
        failure["schema"] != "piccard-runner-failure"
        or failure["version"] != 2
        or failure["key_id"] != partition["key_id"]
        or failure["status_code"] not in {"PROCESS_ERROR", "TIMEOUT"}
        or not isinstance(failure["detail"], str)
        or not failure["detail"]
        or failure["smoke_only"] != options["smoke"]
        or failure["table_eligible"] is not False
    ):
        raise ValueError("failure receipt identity/schema mismatch")
    exit_code = failure["exit_code"]
    if exit_code is not None and (
        isinstance(exit_code, bool) or not isinstance(exit_code, int)
    ):
        raise ValueError("failure exit_code type mismatch")
    if (
        not isinstance(failure["term_sent"], bool)
        or not isinstance(failure["kill_sent"], bool)
    ):
        raise ValueError("failure signal receipt type mismatch")
    elapsed_ms = failure["elapsed_ms"]
    if (
        isinstance(elapsed_ms, bool)
        or not isinstance(elapsed_ms, (int, float))
        or not math.isfinite(elapsed_ms)
        or elapsed_ms < 0
    ):
        raise ValueError("failure elapsed_ms type mismatch")
    state = (failure["phase"], failure["capture_state"])
    if state not in {
        ("preflight", "NOT_APPLICABLE"),
        ("measurement", "NOT_STARTED"),
        ("measurement", "COMPLETE"),
    }:
        raise ValueError("failure phase/capture_state mismatch")
    if state == ("measurement", "NOT_STARTED") and (
        exit_code is not None
        or failure["term_sent"]
        or failure["kill_sent"]
    ):
        raise ValueError("NOT_STARTED process receipt mismatch")

    diagnostic_logs = failure["diagnostic_logs"]
    truncation_checks = {}
    if state == ("measurement", "COMPLETE"):
        if (
            not isinstance(diagnostic_logs, dict)
            or set(diagnostic_logs) != set(DIAGNOSTIC_LOG_NAMES)
        ):
            raise ValueError("diagnostic log topology mismatch")
        expected_payloads = {
            "aggregate.csv", "failure.json",
            *DIAGNOSTIC_LOG_NAMES.values(),
        }
        for stream, expected_path in DIAGNOSTIC_LOG_NAMES.items():
            metadata = diagnostic_logs[stream]
            if (
                not isinstance(metadata, dict)
                or set(metadata) != DIAGNOSTIC_LOG_FIELDS
            ):
                raise ValueError("diagnostic metadata schema mismatch")
            if metadata["path"] != expected_path:
                raise ValueError("diagnostic path mismatch")
            digest = metadata["sha256"]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)
            ):
                raise ValueError("diagnostic sha256 type mismatch")
            original_bytes = metadata["original_bytes"]
            stored_bytes = metadata["stored_bytes"]
            if (
                isinstance(original_bytes, bool)
                or not isinstance(original_bytes, int)
                or original_bytes < 0
            ):
                raise ValueError("diagnostic original_bytes type mismatch")
            if (
                isinstance(stored_bytes, bool)
                or not isinstance(stored_bytes, int)
                or stored_bytes < 0
            ):
                raise ValueError("diagnostic stored_bytes type mismatch")
            if not isinstance(metadata["truncated"], bool):
                raise ValueError("diagnostic truncated type mismatch")
            if stored_bytes > MAX_DIAGNOSTIC_LOG_BYTES:
                raise ValueError("diagnostic stored_bytes exceeds cap")
            if metadata["truncated"]:
                if (
                    original_bytes <= MAX_DIAGNOSTIC_LOG_BYTES
                    or stored_bytes != MAX_DIAGNOSTIC_LOG_BYTES
                ):
                    raise ValueError("diagnostic truncation size mismatch")
                marker = (
                    "\n[PICCARD_DIAGNOSTIC_TRUNCATED "
                    f"original_bytes={original_bytes}]\n"
                ).encode("ascii")
                payload_budget = MAX_DIAGNOSTIC_LOG_BYTES - len(marker)
                marker_offset = payload_budget // 2
                truncation_checks[expected_path] = (marker_offset, marker)
            elif original_bytes != stored_bytes:
                raise ValueError("diagnostic untruncated size mismatch")
    else:
        if diagnostic_logs != {}:
            raise ValueError("diagnostic logs forbidden for capture state")
        expected_payloads = {"aggregate.csv", "failure.json"}

    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != expected_payloads:
        raise ValueError("incomplete shard payload topology mismatch")
    for relative, digest in files.items():
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ValueError("incomplete shard payload digest type mismatch")
        path = shard / relative
        path_info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(path_info.st_mode):
            raise ValueError("incomplete shard payload is non-regular")
        actual_digest = sha256_file(path)
        if actual_digest != digest:
            raise ValueError("incomplete shard payload hash mismatch")
        for metadata in diagnostic_logs.values():
            if metadata["path"] == relative and (
                metadata["sha256"] != digest
                or metadata["stored_bytes"] != path_info.st_size
            ):
                raise ValueError("diagnostic payload binding mismatch")
        if relative in truncation_checks:
            marker_offset, marker = truncation_checks[relative]
            content = path.read_bytes()
            if (
                content[
                    marker_offset:marker_offset + len(marker)
                ] != marker
                or content.count(marker) != 1
            ):
                raise ValueError("diagnostic truncation marker mismatch")
    actual_topology = {
        path.relative_to(shard).as_posix()
        for path in shard.rglob("*")
    }
    if actual_topology != expected_payloads | {"shard_manifest.json"}:
        raise ValueError("incomplete shard payload topology mismatch")

    aggregate_path = shard / "aggregate.csv"
    with aggregate_path.open(newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != AGGREGATE_HEADER.split(","):
            raise ValueError("incomplete aggregate header mismatch")
        rows = list(reader)
    if len(rows) != 1:
        raise ValueError("incomplete aggregate row count mismatch")
    row = rows[0]
    aggregate_expected = {
        "profile": partition["profile_id"],
        "circuit": partition["circuit"],
        "shape_id": partition["shape_id"],
        "security": partition["security"],
        "consumer_count": str(len(partition["consumer_points"])),
        "consumer_set_sha256": partition["consumer_set_sha256"],
        "pattern_count": "3",
        "repetitions_per_pattern":
            str(1 if options["smoke"] else policy["repetitions"]),
        "seed": str(ROOT_SEED),
        "requested_ring_dim": str(partition["requested_ring_dim"]),
        "natural_depth": str(partition["natural_depth"]),
        "max_queries": str(policy["max_queries"]),
        "flood_margin_bits": str(policy["flood_margin_bits"]),
        "openfhe_version": matrix["openfhe_version"],
        "source_commit": runtime_source_commit,
        "status_code": failure["status_code"],
        "error_message": failure["detail"],
    }
    if any(row[field] != value for field, value in aggregate_expected.items()):
        raise ValueError("incomplete aggregate identity/status mismatch")


def validate_owned_shard_temporary(path, profile_dir, partition):
    expected_name = (
        "." + partition["key_id"]
        + ".piccard-shard-v1.tmp-" + runtime_run_nonce
    )
    if path.parent != profile_dir or path.name != expected_name:
        raise ValueError("unowned shard temporary basename")
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ValueError("unowned shard temporary")
    marker = path / ".piccard-shard-owner.json"
    marker_info = marker.lstat()
    if (
        marker.is_symlink()
        or not stat.S_ISREG(marker_info.st_mode)
        or marker_info.st_nlink != 1
    ):
        raise ValueError("unowned shard temporary marker")
    expected = {
        "key_id": partition["key_id"],
        "profile_id": partition["profile_id"],
        "run_nonce": runtime_run_nonce,
        "schema": "piccard-shard-owner",
        "version": 1,
    }
    data = marker.read_bytes()
    rendered = (
        json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if data != rendered:
        raise ValueError("unowned shard temporary marker")


def remove_owned_shard_temporary(path, profile_dir, partition):
    validate_owned_shard_temporary(path, profile_dir, partition)
    shutil.rmtree(path)


def publish_measurement_failure(
    profile_dir, partition, status, detail, process_result, smoke,
    natural_ring_dim, capture_state, diagnostic_source_dir,
    raw_temporary,
):
    write_failure_atomic(
        profile_dir,
        partition,
        status,
        detail,
        process_result,
        smoke,
        natural_ring_dim,
        phase="measurement",
        capture_state=capture_state,
        diagnostic_source_dir=diagnostic_source_dir,
    )
    cleanup_path = raw_temporary
    if (
        guarded_fake
        and os.environ.get("PICCARD_TEST_SWAP_RAW_CLEANUP") == "1"
    ):
        cleanup_path = profile_dir / partition["key_id"]
    remove_owned_shard_temporary(cleanup_path, profile_dir, partition)


RUN_MANIFEST_FIELDS = {
    "schema", "version", "source_commit", "git_head",
    "source_tree_dirty", "openfhe_version", "matrix_sha256",
    "resolved_matrix_sha256", "benchmark_sha256", "command_policy",
    "python_version", "platform", "smoke_only", "table_eligible",
    "run_nonce",
}
PROFILE_MANIFEST_FIELDS = {
    "schema", "version", "profile_id", "key_count", "key_verdicts",
    "profile_verdict", "source_commit", "openfhe_version", "smoke_only",
    "table_eligible", "shard_manifest_sha256",
}
SEAL_FIELDS = {
    "schema", "version", "run_nonce", "profile_id",
    "profile_manifest_sha256", "shard_manifest_sha256",
}
SHARD_MANIFEST_FIELDS = {
    "schema", "version", "key_id", "profile_id", "status",
    "key_verdict", "candidate_count", "expected_detail_rows",
    "natural_ring_dim", "largest_candidate_ring_dim", "timeout_seconds",
    "measurement_command", "executed_command", "circuit", "shape_id",
    "security", "requested_ring_dim", "natural_depth", "consumer_points",
    "consumer_set_sha256", "source_commit", "openfhe_version",
    "run_nonce", "benchmark_sha256",
    "ring_candidates", "scaling_mod_grid", "max_depth_delta",
    "repetitions", "smoke_only", "table_eligible", "files",
}
CANDIDATE_MANIFEST_FIELDS = {
    "schema", "version", "key_id", "source_commit", "openfhe_version",
    "profile_id", "circuit", "shape_id", "security",
    "requested_ring_dim", "natural_depth", "consumer_points",
    "consumer_set_sha256", "command", "candidate_count", "candidates",
    "run_nonce", "benchmark_sha256",
}
CANDIDATE_RECEIPT_FIELDS = {
    "candidate_id", "status_code", "detail_sha256", "detail_row_count",
}


def load_json_exact(path, fields, label):
    if not path.is_file() or path.is_symlink():
        raise ValueError(label + " is missing or non-regular")
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(label + " schema mismatch")
    return value


def numeric_field(row, name, *, integer=False):
    value = row.get(name, "")
    if value == "":
        raise ValueError("unavailable numeric candidate field " + name)
    try:
        parsed = int(value) if integer else float(value)
    except ValueError as error:
        raise ValueError("malformed numeric candidate field " + name) from error
    if (
        isinstance(parsed, float) and not math.isfinite(parsed)
    ) or parsed <= 0:
        raise ValueError("non-positive numeric candidate field " + name)
    return parsed


def finalized_candidate(row, shard, shard_path):
    if (
        row["status_code"] != "OK"
        or row["decrypt_ok"] != "1"
        or row["saturated"] != "0"
        or row["pattern_count"] != "3"
        or int(row["repetitions_per_pattern"]) < 5
    ):
        return None
    required_numeric_fields = (
        "natural_ring_dim", "ring_dim_calibrated", "provisioned_depth",
        "scaling_mod_size", "num_limbs", "plaintext_mod", "log_q",
        "log_delta", "eval_noise_bits", "ct_bytes", "max_queries",
        "query_stat_bits", "coefficient_stat_bits", "flood_margin_bits",
        "flood_noise_bits", "pattern_count", "repetitions_per_pattern",
        "detail_row_count",
    )
    if any(row.get(field, "") == "" for field in required_numeric_fields):
        return None
    measured = numeric_field(row, "eval_noise_bits")
    compiled = math.ceil(measured)
    if compiled <= 0 or compiled > 0xFFFFFFFF:
        raise ValueError("compiled eval-noise uint32 conversion failed")
    candidate_id = (
        f"N{row['ring_dim_calibrated']}-d"
        f"{row['provisioned_depth']}-s{row['scaling_mod_size']}")
    record = {
        "candidate_id": candidate_id,
        "natural_ring_dim":
            numeric_field(row, "natural_ring_dim", integer=True),
        "ring_dim_calibrated":
            numeric_field(row, "ring_dim_calibrated", integer=True),
        "provisioned_depth":
            numeric_field(row, "provisioned_depth", integer=True),
        "scaling_mod_size":
            numeric_field(row, "scaling_mod_size", integer=True),
        "num_limbs": numeric_field(row, "num_limbs", integer=True),
        "plaintext_mod":
            numeric_field(row, "plaintext_mod", integer=True),
        "log_q": numeric_field(row, "log_q"),
        "log_delta": numeric_field(row, "log_delta"),
        "measured_eval_noise_bits": measured,
        "eval_noise_bits": compiled,
        "ct_bytes": numeric_field(row, "ct_bytes", integer=True),
        "transcript_stat_bits": policy["transcript_stat_bits"],
        "max_queries": numeric_field(row, "max_queries", integer=True),
        "query_stat_bits":
            numeric_field(row, "query_stat_bits", integer=True),
        "coefficient_stat_bits":
            numeric_field(row, "coefficient_stat_bits", integer=True),
        "flood_margin_bits":
            numeric_field(row, "flood_margin_bits", integer=True),
        "flood_noise_bits":
            numeric_field(row, "flood_noise_bits", integer=True),
        "pattern_count": numeric_field(row, "pattern_count", integer=True),
        "repetitions_per_pattern":
            numeric_field(row, "repetitions_per_pattern", integer=True),
        "detail_row_count":
            numeric_field(row, "detail_row_count", integer=True),
        "detail_sha256": row["detail_sha256"],
        "consumer_results_sha256": row["consumer_results_sha256"],
        "aggregate_csv_sha256":
            sha256_file(shard_path / "aggregate.csv"),
        "candidate_manifest_sha256":
            sha256_file(shard_path / "candidates.json"),
        "shard_manifest_sha256":
            sha256_file(shard_path / "shard_manifest.json"),
    }
    if (
        abs(
            record["log_delta"]
            - (
                record["log_q"]
                - math.log2(record["plaintext_mod"])
            )
        )
        > 1e-6
    ):
        raise ValueError("candidate log_delta mismatch")
    required = record["flood_noise_bits"] + 2
    record["_required_capacity_bits"] = required
    record["_feasible"] = required <= record["log_delta"]
    return record


def choose_frontier(rows, shard, shard_path):
    candidates = []
    for row in rows:
        candidate = finalized_candidate(row, shard, shard_path)
        if candidate is not None:
            candidates.append(candidate)
    feasible = [candidate for candidate in candidates if candidate["_feasible"]]
    if feasible:
        by_cost = {}
        for candidate in feasible:
            cost = (
                candidate["ring_dim_calibrated"],
                candidate["log_q"],
                candidate["ct_bytes"],
                candidate["provisioned_depth"],
                candidate["scaling_mod_size"],
            )
            public = {
                key: value for key, value in candidate.items()
                if not key.startswith("_")
            }
            if cost in by_cost and by_cost[cost] != public:
                raise ValueError("conflicting equal-cost frontier candidates")
            by_cost[cost] = public
        return min(by_cost.items(), key=lambda item: item[0])[1], None
    if candidates:
        best = min(
            candidates,
            key=lambda candidate:
                candidate["_required_capacity_bits"]
                - candidate["log_delta"],
        )
        shortfall = (
            best["_required_capacity_bits"] - best["log_delta"])
        return None, {
            "shortfall_bits": shortfall,
            "reason": "INSUFFICIENT_CAPACITY",
            "best_candidate_id": best["candidate_id"],
            "best_measured_eval_noise_bits":
                best["measured_eval_noise_bits"],
            "required_capacity_bits": best["_required_capacity_bits"],
            "log_delta": best["log_delta"],
        }
    return None, {
        "shortfall_bits": None,
        "reason": "NO_COMPLETE_NUMERIC_OK_CANDIDATE",
        "best_candidate_id": None,
        "best_measured_eval_noise_bits": None,
        "required_capacity_bits": None,
        "log_delta": None,
    }


def validate_owned_finalization_sibling(
    sibling, final_dir, results_root, run_nonce
):
    expected_name = (
        "." + final_dir.name
        + ".piccard-finalize-v1.tmp-" + run_nonce
    )
    if sibling.parent != final_dir.parent or sibling.name != expected_name:
        raise ValueError("unowned finalization temp sibling basename")
    info = sibling.lstat()
    if sibling.is_symlink() or not stat.S_ISDIR(info.st_mode):
        raise ValueError("unowned finalization temp sibling")
    marker = sibling / ".piccard-finalize-owner.json"
    marker_info = marker.lstat()
    if (
        marker.is_symlink()
        or not stat.S_ISREG(marker_info.st_mode)
        or marker_info.st_nlink != 1
    ):
        raise ValueError("unowned finalization temp marker")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(marker, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != marker_info.st_dev
            or opened.st_ino != marker_info.st_ino
        ):
            raise ValueError("replaced finalization owner marker")
        data = b""
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            data += chunk
    finally:
        os.close(descriptor)
    owner = json.loads(data)
    expected = {
        "final_dir_realpath": str(final_dir.resolve(strict=False)),
        "results_root_realpath": str(results_root.resolve(strict=True)),
        "run_nonce": run_nonce,
        "schema": "piccard-finalize-owner",
        "version": 1,
    }
    rendered = (
        json.dumps(owner, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if owner != expected or data != rendered:
        raise ValueError("unowned finalization temp marker")


def finalize_results(script_dir, repo_root, options):
    global matrix
    global runtime_source_commit
    global runtime_run_nonce
    global runtime_benchmark_sha256
    global resolved_manifest_path
    global policy

    results_argument = Path(options["results_root"])
    final_argument = Path(options["finalize_dir"])
    if not results_argument.is_absolute() or not final_argument.is_absolute():
        fail("finalization paths must be absolute")
    if not results_argument.is_dir() or results_argument.is_symlink():
        fail("finalization results root must be a direct real directory")
    results_root = results_argument.resolve(strict=True)
    final_dir = final_argument.resolve(strict=False)
    if final_dir.exists() or final_dir.is_symlink():
        fail("final directory already exists")
    if not final_dir.parent.is_dir():
        fail("final directory parent must exist")

    run_path = results_root / "run_manifest.json"
    run = load_json_exact(
        run_path, RUN_MANIFEST_FIELDS, "run manifest")
    if (
        run["schema"] != "piccard-noise-run"
        or run["version"] != 1
        or run["source_tree_dirty"] is not False
        or run["smoke_only"] is not False
        or run["table_eligible"] is not True
        or run["source_commit"] != run["git_head"]
    ):
        fail("run is smoke/noneligible, dirty, or mixed-source")
    matrix_path = script_dir / "noise_profiles.json"
    matrix_bytes = matrix_path.read_bytes()
    if sha256_bytes(matrix_bytes) != run["matrix_sha256"]:
        fail("run matrix hash mismatch")
    resolved_manifest_path = results_root / "resolved_noise_profiles.json"
    resolved_bytes = resolved_manifest_path.read_bytes()
    if sha256_bytes(resolved_bytes) != run["resolved_matrix_sha256"]:
        fail("resolved profile matrix hash mismatch")
    expected_resolved = matrix_bytes.replace(
        b'"source_commit":"runtime-source-commit"',
        ('"source_commit":"' + run["source_commit"] + '"').encode(),
        1,
    )
    if resolved_bytes != expected_resolved:
        fail("resolved profile matrix identity mismatch")
    matrix = json.loads(resolved_bytes)
    runtime_source_commit = run["source_commit"]
    runtime_run_nonce = run["run_nonce"]
    runtime_benchmark_sha256 = run["benchmark_sha256"]
    options["smoke"] = False
    partitions_by_profile = {
        profile_id: [
            partition for partition in matrix["partitions"]
            if partition["profile_id"] == profile_id
        ]
        for profile_id in (
            "primary40", "sensitivity64", "feasibility128")
    }
    if sum(map(len, partitions_by_profile.values())) != 34:
        fail("resolved profile matrix must contain exactly 34 keys")
    profiles_root = results_root / "profiles"
    actual_profiles = {
        path.name for path in profiles_root.iterdir()
        if path.is_dir() and not path.is_symlink()
    }
    expected_profiles = set(partitions_by_profile)
    if actual_profiles != expected_profiles:
        fail("missing, duplicate, or unknown profile directory")

    finalized_profiles = []
    finalized_keys = []
    archive_members = []
    for profile_id in (
        "primary40", "sensitivity64", "feasibility128"
    ):
        options["profile"] = profile_id
        policy = profile_policy(matrix, profile_id)
        partitions = partitions_by_profile[profile_id]
        profile_dir = profiles_root / profile_id
        profile_path = profile_dir / "profile_manifest.json"
        seal_path = profile_dir / "completion_seal.json"
        profile_value = load_json_exact(
            profile_path, PROFILE_MANIFEST_FIELDS, "profile manifest")
        seal = load_json_exact(
            seal_path, SEAL_FIELDS, "completion seal")
        expected_key_ids = {
            partition["key_id"] for partition in partitions}
        if (
            profile_value["schema"] != "piccard-profile-run"
            or profile_value["version"] != 1
            or profile_value["profile_id"] != profile_id
            or profile_value["key_count"] != len(partitions)
            or set(profile_value["key_verdicts"]) != expected_key_ids
            or set(profile_value["shard_manifest_sha256"])
            != expected_key_ids
            or profile_value["source_commit"] != run["source_commit"]
            or profile_value["openfhe_version"]
            != run["openfhe_version"]
            or profile_value["smoke_only"] is not False
            or profile_value["table_eligible"] is not True
        ):
            fail("profile manifest identity/topology mismatch")
        allowed_profile_verdicts = (
            {"PASS"} if profile_id != "feasibility128"
            else {"PASS", "PASS_FEASIBILITY_WITH_INFEASIBLE"}
        )
        if profile_value["profile_verdict"] not in allowed_profile_verdicts:
            fail("profile measurement verdict is not acceptable")
        if (
            seal["schema"] != "piccard-profile-completion-seal"
            or seal["version"] != 1
            or seal["run_nonce"] != run["run_nonce"]
            or seal["profile_id"] != profile_id
            or seal["profile_manifest_sha256"] != sha256_file(profile_path)
            or seal["shard_manifest_sha256"]
            != profile_value["shard_manifest_sha256"]
        ):
            fail("profile completion seal mismatch")
        expected_children = expected_key_ids | {
            "profile_manifest.json", "completion_seal.json"}
        if {path.name for path in profile_dir.iterdir()} != expected_children:
            fail("profile directory topology mismatch")
        archive_members.extend([
            profile_path.relative_to(results_root).as_posix(),
            seal_path.relative_to(results_root).as_posix(),
        ])
        profile_shards = []
        frontier_verdicts = []
        for partition in partitions:
            shard_path = profile_dir / partition["key_id"]
            parent_digest = profile_value[
                "shard_manifest_sha256"][partition["key_id"]]
            try:
                shard = validate_shard(
                    shard_path, partition, parent_digest)
            except Exception as error:
                fail("shard semantic validation failed: " + str(error))
            if set(shard) != SHARD_MANIFEST_FIELDS:
                fail("shard manifest exhaustive schema mismatch")
            candidate_path = shard_path / "candidates.json"
            candidate_manifest = load_json_exact(
                candidate_path,
                CANDIDATE_MANIFEST_FIELDS,
                "candidate manifest",
            )
            if (
                candidate_manifest["schema"]
                != "piccard-candidate-manifest"
                or candidate_manifest["version"] != 1
                or any(
                    not isinstance(receipt, dict)
                    or set(receipt) != CANDIDATE_RECEIPT_FIELDS
                    for receipt in candidate_manifest["candidates"]
                )
            ):
                fail("candidate manifest exhaustive schema mismatch")
            with (shard_path / "aggregate.csv").open(newline="") as source:
                rows = list(csv.DictReader(source))
            selected, infeasibility = choose_frontier(
                rows, shard, shard_path)
            frontier = (
                "SELECTED" if selected is not None else "INFEASIBLE")
            if profile_id != "feasibility128" and frontier != "SELECTED":
                fail("required profile key has no feasible frontier")
            frontier_verdicts.append(frontier)
            finalized_keys.append({
                "profile_id": partition["profile_id"],
                "circuit": partition["circuit"],
                "shape_id": partition["shape_id"],
                "security": partition["security"],
                "requested_ring_dim": partition["requested_ring_dim"],
                "natural_depth": partition["natural_depth"],
                "consumer_set_sha256":
                    partition["consumer_set_sha256"],
                "openfhe_version": partition["openfhe_version"],
                "key_id": partition["key_id"],
                "measurement_key_verdict": shard["key_verdict"],
                "frontier_verdict": frontier,
                "shard_manifest_sha256": parent_digest,
                "selected_row": selected,
                "infeasibility": infeasibility,
            })
            profile_shards.append({
                "key_id": partition["key_id"],
                "shard_manifest_sha256": parent_digest,
            })
            archive_members.append(
                (shard_path / "shard_manifest.json")
                .relative_to(results_root).as_posix())
            archive_members.extend(
                (shard_path / relative)
                .relative_to(results_root).as_posix()
                for relative in shard["files"]
            )
        final_profile_verdict = (
            "PASS_FEASIBILITY_WITH_INFEASIBLE"
            if (
                profile_id == "feasibility128"
                and "INFEASIBLE" in frontier_verdicts
            )
            else "PASS"
        )
        finalized_profiles.append({
            "profile_id": profile_id,
            "measurement_profile_verdict":
                profile_value["profile_verdict"],
            "finalization_profile_verdict": final_profile_verdict,
            "profile_manifest_sha256": sha256_file(profile_path),
            "completion_seal_sha256": sha256_file(seal_path),
            "shards": sorted(
                profile_shards, key=lambda value: value["key_id"]),
        })

    matches = [
        path for path in final_dir.parent.iterdir()
        if path.name.startswith(
            "." + final_dir.name + ".piccard-finalize-v1.tmp-")
    ]
    if len(matches) > 1:
        fail("more than one finalization temp sibling exists")
    if matches:
        try:
            validate_owned_finalization_sibling(
                matches[0], final_dir, results_root, run["run_nonce"])
        except Exception as error:
            fail("owned finalization temp validation failed: " + str(error))
        shutil.rmtree(matches[0])

    temporary = final_dir.with_name(
        "." + final_dir.name
        + ".piccard-finalize-v1.tmp-" + run["run_nonce"])
    if temporary.exists() or temporary.is_symlink():
        fail("finalization temp collision")
    owned = False
    try:
        temporary.mkdir(mode=0o700)
        owned = True
        owner = {
            "final_dir_realpath": str(final_dir.resolve(strict=False)),
            "results_root_realpath":
                str(results_root.resolve(strict=True)),
            "run_nonce": run["run_nonce"],
            "schema": "piccard-finalize-owner",
            "version": 1,
        }
        owner_path = temporary / ".piccard-finalize-owner.json"
        descriptor = os.open(
            owner_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            data = (
                json.dumps(owner, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode()
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        archive_module_path = script_dir / "make_calibration_archive.py"
        archive_spec = importlib.util.spec_from_file_location(
            "piccard_make_calibration_archive", archive_module_path)
        archive_module = importlib.util.module_from_spec(archive_spec)
        archive_spec.loader.exec_module(archive_module)
        archive_path = temporary / "selected-shards.tar.zst"
        archive = archive_module.build_archive(
            results_root, sorted(archive_members), archive_path)
        archive_module.verify_archive(archive_path, archive)

        combined = {
            "schema": "piccard-calibration-finalized",
            "version": 1,
            "table_eligible": True,
            "run": {
                **run,
                "run_manifest_sha256": sha256_file(run_path),
            },
            "profiles": finalized_profiles,
            "keys": sorted(
                finalized_keys, key=lambda value: value["key_id"]),
            "archive": archive,
        }
        table_module_path = script_dir / "make_calibration_table.py"
        table_spec = importlib.util.spec_from_file_location(
            "piccard_make_calibration_table", table_module_path)
        table_module = importlib.util.module_from_spec(table_spec)
        table_spec.loader.exec_module(table_module)
        table_module.validate_finalized_manifest(combined)
        manifest_path = temporary / "manifest.json"
        atomic_json(manifest_path, combined)
        with manifest_path.open("rb") as source:
            os.fsync(source.fileno())
        owner_path.unlink()
        directory_descriptor = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        os.replace(temporary, final_dir)
        owned = False
        parent_descriptor = os.open(final_dir.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except Exception:
        if owned:
            shutil.rmtree(temporary)
        raise
    print("FINALIZED " + str(final_dir))


def _load_flooding_adapter(script_dir):
    """Load the pure successor planner without importing it at shell start."""
    import importlib.util

    module_path = script_dir / "revision_flooding_adapter.py"
    spec = importlib.util.spec_from_file_location(
        "piccard_revision_flooding_adapter", module_path)
    if spec is None or spec.loader is None:
        fail("flooding revision planner is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_successor_matrices(script_dir, adapter, cell_id=None):
    revision_path = script_dir.parent / "benchmarks" / "revision_matrix.json"
    revision_matrix = json.loads(revision_path.read_text(encoding="utf-8"))
    noise_path = script_dir / "noise_profiles.json"
    noise_matrix = json.loads(noise_path.read_text(encoding="utf-8"))
    if cell_id is None:
        return revision_matrix, noise_matrix, None
    cell = adapter.select_cell(revision_matrix, cell_id)
    return revision_matrix, noise_matrix, cell


def _successor_output_root(repo_root, options):
    root_argument = options.get("results_root")
    if root_argument is None:
        fail("successor flooding path requires --results-root")
    root = Path(root_argument)
    if not root.is_absolute():
        fail("--results-root must be absolute")
    resolved = root.resolve(strict=False)
    try:
        resolved.relative_to(repo_root)
        fail("--results-root must be outside the Git worktree")
    except ValueError:
        pass
    if resolved.exists() or resolved.is_symlink():
        fail("successor results root must not already exist")
    return resolved


def _successor_source_commit(repo_root, bench, dry_run, grace_ms, environment):
    """Bind toy artifacts to the binary source; dry-run never spawns."""
    if dry_run:
        return "runtime-source-commit"
    if not bench.is_file() or not os.access(bench, os.X_OK):
        fail("benchmark path must be an executable file")
    result = supervise(
        [str(bench), "--print_source_commit"],
        120000,
        grace_ms,
        environment,
    )
    if (
        result["timed_out"] or result["returncode"] != 0 or
        result["stdout"] is None
    ):
        fail("benchmark source-commit probe failed")
    source_commit = result["stdout"].strip()
    if (
        len(source_commit) != 40 or
        any(ch not in "0123456789abcdef" for ch in source_commit)
    ):
        fail("benchmark embedded source commit is invalid")
    return source_commit


def _successor_identity_arguments(partition, matrix, policy,
                                  manifest_path, source_commit):
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
        f"--source_commit={source_commit}",
        f"--transcript_stat_bits={policy['transcript_stat_bits']}",
        f"--max_queries={policy['max_queries']}",
        f"--margin={policy['flood_margin_bits']}",
        f"--seed={ROOT_SEED}",
    ]


def _successor_partition_command(
    bench, partition, matrix, policy, manifest_path, source_commit,
    repetitions, output_dir, seed, threads, smoke,
):
    """Return the one immutable bench_noise shard command for a partition."""
    command = [
        str(bench),
        *_successor_identity_arguments(
            partition, matrix, policy, manifest_path, source_commit),
        "--scaling_mod_grid=40",
        "--max_depth_delta=0",
        f"--ring_candidates={partition['requested_ring_dim']}",
        "--timeout_seconds=120",
        f"--reps={repetitions}",
        "--revision_pattern_taxonomy",
        f"--aggregate_csv={output_dir / 'aggregate.csv'}",
        f"--detail_dir={output_dir / 'details'}",
        f"--candidate_manifest={output_dir / 'candidates.json'}",
    ]
    # The producer's seed is part of the command identity.  The runner's
    # frozen policy uses one deterministic root seed; accepting a matching
    # explicit confirmation is useful for the generic orchestrator while
    # never allowing it to alter the matrix-derived value.
    if seed != ROOT_SEED:
        fail(f"--seed={seed} contradicts frozen successor seed {ROOT_SEED}")
    if threads != 2:
        fail(f"--threads={threads} contradicts frozen successor threads 2")
    if smoke:
        command.append("--smoke")
    return command


def _resolved_successor_manifest(noise_matrix, source_commit,
                                tracked_manifest_bytes):
    """Replace exactly one source sentinel without reserializing JSON."""
    if not isinstance(tracked_manifest_bytes, bytes):
        fail("tracked noise matrix bytes are required")
    sentinel = b"runtime-source-commit"
    if tracked_manifest_bytes.count(sentinel) != 1:
        fail("tracked noise matrix must contain exactly one source sentinel")
    try:
        tracked_matrix = json.loads(tracked_manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("tracked noise matrix is not valid UTF-8 JSON")
    if tracked_matrix != noise_matrix:
        fail("tracked noise matrix changed while resolving")
    if noise_matrix.get("source_commit") != "runtime-source-commit":
        fail("tracked noise matrix must use runtime-source-commit policy")
    try:
        replacement = source_commit.encode("ascii")
    except UnicodeEncodeError:
        fail("resolved noise matrix source commit is not ASCII")
    return tracked_manifest_bytes.replace(sentinel, replacement, 1)


def _write_successor_metadata(root, cell_id, run_profile, profile_id,
                              source_commit, noise_matrix, partition,
                              command, repetitions, status):
    """Write a small, immutable readiness envelope around one shard."""
    profiles_root = root / "profiles" / profile_id
    shard_root = profiles_root / partition["key_id"]
    (profiles_root / "profile_manifest.json").write_text(
        json.dumps({
            "schema": "piccard-noise-revision-profile-v1",
            "version": 1,
            "profile_id": profile_id,
            "key_count": 1,
            "key_verdicts": {partition["key_id"]: "SELECTED"},
            "profile_verdict": status,
            "source_commit": source_commit,
            "openfhe_version": noise_matrix["openfhe_version"],
            "smoke_only": True,
            "table_eligible": False,
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (shard_root / "revision_identity.json").write_text(
        json.dumps({
            "schema": "piccard-noise-revision-shard-v1",
            "version": 1,
            "cell_id": cell_id,
            "run_profile": run_profile,
            "profile_id": profile_id,
            "key_id": partition["key_id"],
            "circuit": partition["circuit"],
            "shape_id": partition["shape_id"],
            "security": partition["security"],
            "consumer_points": partition["consumer_points"],
            "consumer_set_sha256": partition["consumer_set_sha256"],
            "repetitions_per_pattern": repetitions,
            "patterns": ["zero", "random", "adversarial"],
            "timing_contract": "NOT_APPLICABLE",
            "status": status,
            "table_eligible": False,
            "command": command,
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return shard_root


def _run_successor_flooding(script_dir, repo_root, options):
    """Run or dry-plan the versioned flooding successor path.

    A revision-cell invocation executes at most one direct bench_noise
    command.  An explicit profile-only successor invocation is retained for
    the readiness contract and may cover the complete primary40 topology;
    the no-fan-out rule applies only when ``--revision-cell`` is present.
    """
    adapter = _load_flooding_adapter(script_dir)
    revision_matrix, noise_matrix, cell = _read_successor_matrices(
        script_dir, adapter, options.get("revision_cell"))
    run_profile = options["run_profile"]
    # Paper-v1 is always planning-only in this revision task.  DRY_RUN=1 is
    # also an explicit no-spawn request for the toy profile, which is useful
    # for the readiness orchestrator and its invocation spy.
    dry_run = (
        run_profile == adapter.PAPER_PROFILE or
        os.environ.get("DRY_RUN") == "1"
    )
    output_root = _successor_output_root(repo_root, options)
    profile_id = options.get("profile") or "primary40"
    if cell is not None:
        if cell["axis_value"] != profile_id:
            fail("--profile does not match --revision-cell profile")
        selected_partitions = [
            adapter.select_noise_partition(noise_matrix, profile_id)
        ]
    else:
        if profile_id not in {
            "primary40", "sensitivity64", "feasibility128"
        }:
            fail("successor --run-profile selects a known noise profile")
        if run_profile == adapter.TOY_PROFILE and profile_id != "primary40":
            fail("readiness-toy-v1 selects primary40 only")
        selected_partitions = [
            partition for partition in noise_matrix["partitions"]
            if partition.get("profile_id") == profile_id
        ]
        if not selected_partitions:
            fail("primary40 successor profile has no partitions")

    # Only a toy run may spawn.  Paper-v1 is a deterministic planning mode,
    # even if the caller forgot to set DRY_RUN=1; this is the phase-9 safety
    # boundary and prevents an accidental paper campaign.
    bench_argument = options.get("bench_noise")
    bench = Path(bench_argument or (repo_root / "build" / "bench_noise"))
    if not dry_run and (not bench.is_file() or not os.access(bench, os.X_OK)):
        fail("benchmark path must be an executable file")
    if dry_run and bench_argument is not None and bench.exists() and (
        not bench.is_file() or not os.access(bench, os.X_OK)
    ):
        fail("benchmark path must be an executable file")
    bench = bench.resolve(strict=False)

    environment = os.environ.copy()
    environment["OMP_DYNAMIC"] = "FALSE"
    environment["OMP_NUM_THREADS"] = str(options.get("threads") or 2)
    grace_ms = 30000
    if bench.is_file() and os.access(bench, os.X_OK):
        _, grace_ms, _ = resolve_timing(bench)
    source_commit = _successor_source_commit(
        repo_root, bench, dry_run, grace_ms, environment)
    tracked_manifest_path = script_dir / "noise_profiles.json"
    resolved_noise = _resolved_successor_manifest(
        noise_matrix, source_commit, tracked_manifest_path.read_bytes())

    policy_by_id = {
        policy["profile_id"]: policy
        for policy in noise_matrix["profiles"]
    }
    policy = policy_by_id[profile_id]
    repetitions = 5 if run_profile == adapter.PAPER_PROFILE else 1
    if options.get("repetitions") is not None and options["repetitions"] != repetitions:
        fail(
            f"--repetitions={options['repetitions']} contradicts "
            f"{run_profile} value {repetitions}")
    seed = options.get("seed") if options.get("seed") is not None else ROOT_SEED
    threads = options.get("threads") if options.get("threads") is not None else 2

    if dry_run:
        for partition in selected_partitions:
            placeholder = output_root / "profiles" / profile_id / partition["key_id"]
            command = _successor_partition_command(
                bench, partition, noise_matrix, policy,
                "{profile_manifest}", source_commit, repetitions,
                placeholder, seed, threads,
                run_profile == adapter.TOY_PROFILE)
            print(
                "SHARD " + (options.get("revision_cell") or profile_id) +
                " profile=" + profile_id +
                " repetitions=" + str(repetitions) +
                " status=" + (
                    "READINESS_ONLY" if run_profile == adapter.TOY_PROFILE
                    else "DRY_RUN_ONLY"
                ) + " command=" +
                json.dumps(command, separators=(",", ":"))
            )
        return

    resolved_root = output_root
    resolved_root.mkdir(parents=True, exist_ok=False)
    manifest_path = resolved_root / "resolved_noise_profiles.json"
    manifest_path.write_bytes(resolved_noise)
    invocation_count = 0
    for partition in selected_partitions:
        shard_root = resolved_root / "profiles" / profile_id / partition["key_id"]
        shard_root.mkdir(parents=True, exist_ok=False)
        (shard_root / "details").mkdir()
        command = _successor_partition_command(
            bench, partition, noise_matrix, policy, manifest_path,
            source_commit, repetitions, shard_root, seed, threads,
            run_profile == adapter.TOY_PROFILE)
        environment["PICCARD_PROFILE_MANIFEST"] = str(manifest_path)
        try:
            verify_benchmark_binary(bench, sha256_file(bench))
            result = supervise(command, 120000, grace_ms, environment)
            if result["timed_out"]:
                fail("successor flooding shard timed out")
            if result["returncode"] != 0:
                diagnostic = bounded_successor_diagnostic(result["stderr"])
                message = (
                    "successor flooding shard exited " +
                    str(result["returncode"])
                )
                if diagnostic:
                    message += ": " + diagnostic
                fail(message)
        except SupervisionError as error:
            fail("successor flooding shard failed: " + str(error))
        invocation_count += 1
        _write_successor_metadata(
            resolved_root,
            options.get("revision_cell") or
            "paper-v1::flooding::profile=" + profile_id,
            run_profile,
            profile_id,
            source_commit,
            noise_matrix,
            partition,
            command,
            repetitions,
            "READINESS_ONLY",
        )
    run_manifest = {
        "schema": "piccard-noise-revision-run-v1",
        "version": 1,
        "cell_id": options.get("revision_cell"),
        "run_profile": run_profile,
        "profile_id": profile_id,
        "status": "READINESS_ONLY",
        "table_eligible": False,
        "timing_contract": "NOT_APPLICABLE",
        "repetitions_per_pattern": repetitions,
        "patterns": ["zero", "random", "adversarial"],
        "invocation_count": invocation_count,
        "source_commit": source_commit,
        "openfhe_version": noise_matrix["openfhe_version"],
    }
    (resolved_root / "run_manifest.json").write_text(
        json.dumps(run_manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print("READY " + str(resolved_root) + " invocations=" + str(invocation_count))


script_dir = Path(sys.argv[1]).resolve()
repo_root = script_dir.parent
options = parse_cli(sys.argv[2:])
if options["finalize_dir"] is not None:
    try:
        finalize_results(script_dir, repo_root, options)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        fail("finalization failed: " + str(error), 2)
    raise SystemExit(0)
if options.get("revision_cell") is not None or options.get("run_profile") is not None:
    try:
        _run_successor_flooding(script_dir, script_dir.parent, options)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        fail("successor flooding run failed: " + str(error), 2)
    raise SystemExit(0)
matrix_path = script_dir / "noise_profiles.json"
matrix_bytes = matrix_path.read_bytes()
matrix = json.loads(matrix_bytes)
if matrix.get("source_commit") != "runtime-source-commit":
    fail("tracked matrix must use runtime-source-commit policy")
if any(p["circuit"] == "threshold" for p in matrix["partitions"]):
    fail("threshold is forbidden in the profile runner")
matrix_sha = sha256_bytes(matrix_bytes)
policy = profile_policy(matrix, options["profile"])
validate_cli_confirmations(options, policy)

bench = Path(
    options["bench_noise"] or (repo_root / "build" / "bench_noise")
).resolve()
if not bench.is_file() or not os.access(bench, os.X_OK):
    fail("benchmark path must be an executable file")
initial_benchmark_sha256 = sha256_file(bench)
default_timeout_ms, grace_ms, test_timing = resolve_timing(bench)

environment = os.environ.copy()
environment["PICCARD_PROFILE_MANIFEST"] = str(matrix_path)
verify_benchmark_binary(bench, initial_benchmark_sha256)
printer = supervise(
    [str(bench), "--print_profile_manifest"],
    120000,
    grace_ms,
    environment,
)
verify_benchmark_binary(bench, initial_benchmark_sha256)
if (
    printer["timed_out"]
    or printer["returncode"] != 0
    or printer["stdout"].encode() != matrix_bytes
):
    fail("benchmark profile printer does not match tracked JSON")
verify_benchmark_binary(bench, initial_benchmark_sha256)
source_printer = supervise(
    [str(bench), "--print_source_commit"],
    120000,
    grace_ms,
    environment,
)
verify_benchmark_binary(bench, initial_benchmark_sha256)
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
    "benchmark_sha256": initial_benchmark_sha256,
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
runtime_run_nonce = run_identity.get("run_nonce", "0" * 32)
runtime_benchmark_sha256 = run_identity["benchmark_sha256"]

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

profile_dir = resolved_root / "profiles" / options["profile"]
if not dry_run:
    profile_dir.mkdir(parents=True, exist_ok=True)

profile_manifest_path = profile_dir / "profile_manifest.json"
parent_digests = {}
prior_profile_manifest = None
if options["resume"]:
    try:
        seal_path = profile_dir / "completion_seal.json"
        receipt_exists = profile_manifest_path.exists()
        seal_exists = seal_path.exists()
        if receipt_exists != seal_exists:
            fail("resume receipt/seal presence mismatch", 2)
        if receipt_exists:
            seal = json.loads(seal_path.read_text())
            if set(seal) != SEAL_FIELDS:
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
            prior_profile_manifest = load_json_exact(
                profile_manifest_path,
                PROFILE_MANIFEST_FIELDS,
                "resume profile manifest",
            )
            if (
                prior_profile_manifest["profile_id"] != options["profile"]
                or prior_profile_manifest["source_commit"]
                != runtime_source_commit
                or prior_profile_manifest["smoke_only"] != options["smoke"]
            ):
                fail("resume profile manifest identity mismatch", 2)
            parent_digests = prior_profile_manifest[
                "shard_manifest_sha256"]
            if seal["shard_manifest_sha256"] != parent_digests:
                fail("resume completion seal shard digest mismatch", 2)
    except (OSError, ValueError) as error:
        fail("resume profile manifest is missing or malformed: " + str(error), 2)

any_incomplete = False
key_verdicts = {}
for partition in partitions:
    target = profile_dir / partition["key_id"]
    owned_temporary = (
        profile_dir /
        (
            "." + partition["key_id"]
            + ".piccard-shard-v1.tmp-" + runtime_run_nonce
        )
    )
    if not dry_run and (owned_temporary.exists() or owned_temporary.is_symlink()):
        if not options["resume"]:
            fail("pre-existing shard temporary collision", 2)
        try:
            validate_owned_shard_temporary(
                owned_temporary, profile_dir, partition)
        except Exception as error:
            fail("owned shard temporary validation failed: " + str(error), 2)
        remove_owned_shard_temporary(
            owned_temporary, profile_dir, partition)
    if options["resume"] and target.exists():
        try:
            stored = json.loads(
                (target / "shard_manifest.json").read_text())
            if stored.get("status") == "INCOMPLETE":
                parent_digest = None
                if prior_profile_manifest is not None:
                    if partition["key_id"] not in parent_digests:
                        raise ValueError(
                            "missing incomplete parent shard digest")
                    parent_digest = parent_digests[partition["key_id"]]
                validate_incomplete_shard(
                    target, partition, parent_digest)
                shutil.rmtree(target)
            else:
                parent_digest = parent_digests.get(
                    partition["key_id"],
                    sha256_file(target / "shard_manifest.json"),
                )
                prior = validate_shard(target, partition, parent_digest)
                key_verdicts[partition["key_id"]] = prior["key_verdict"]
                print("SKIP " + partition["key_id"])
                continue
        except Exception as error:
            print(
                f"resume shard hash validation failed: {error}",
                file=sys.stderr,
            )
            any_incomplete = True
            break
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
    preflight = None
    try:
        verify_benchmark_binary(bench, runtime_benchmark_sha256)
        preflight = supervise(
            preflight_command,
            default_timeout_ms if test_timing else 120000,
            grace_ms,
            environment,
            test_readiness=test_timing,
        )
        verify_benchmark_binary(bench, runtime_benchmark_sha256)
        if preflight["timed_out"]:
            raise TimeoutError("preflight wall timeout")
        if preflight["returncode"] != 0:
            raise RuntimeError(
                "preflight exit " + str(preflight["returncode"]))
        natural_ring_dim = validate_preflight(
            json.loads(preflight["stdout"]), partition, matrix)
    except Exception as error:
        if preflight is None:
            preflight = {
                "returncode": None, "timed_out": False,
                "term_sent": False, "kill_sent": False, "elapsed_ms": 0,
            }
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
                phase="preflight",
                capture_state="NOT_APPLICABLE",
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
        owned_temporary if not dry_run else
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
    atomic_json(temporary_path / ".piccard-shard-owner.json", {
        "key_id": partition["key_id"],
        "profile_id": partition["profile_id"],
        "run_nonce": runtime_run_nonce,
        "schema": "piccard-shard-owner",
        "version": 1,
    })
    (temporary_path / "details").mkdir()
    measurement_capture_paths = {
        stream: temporary_path / name
        for stream, name in DIAGNOSTIC_LOG_NAMES.items()
    }
    measurement = empty_process_result()
    measurement_capture_state = "NOT_STARTED"
    measurement_diagnostic_source = None
    measurement_error = None
    try:
        if (
            guarded_fake
            and os.environ.get("PICCARD_TEST_PRE_BINDING_FAILURE") == "1"
        ):
            raise OSError("guarded pre-binding failure")
        verify_benchmark_binary(bench, runtime_benchmark_sha256)
        measurement = supervise(
            measurement_command,
            default_timeout_ms
            if test_timing
            else timeout_seconds * 1000,
            grace_ms,
            environment,
            test_readiness=test_timing,
            capture_paths=measurement_capture_paths,
        )
        measurement_capture_state = "COMPLETE"
        measurement_diagnostic_source = temporary_path
        verify_benchmark_binary(bench, runtime_benchmark_sha256)
    except SupervisionError as error:
        measurement = error.process_result
        measurement_capture_state = error.capture_state
        measurement_diagnostic_source = (
            temporary_path
            if measurement_capture_state == "COMPLETE" else None
        )
        measurement_error = error
    except Exception as error:
        measurement_error = error
    if measurement_error is not None:
        publish_measurement_failure(
            profile_dir, partition, "PROCESS_ERROR",
            "benchmark binding failed: " + str(measurement_error),
            measurement,
            options["smoke"],
            natural_ring_dim,
            measurement_capture_state,
            measurement_diagnostic_source,
            temporary_path,
        )
        any_incomplete = True
        break
    if measurement["timed_out"] or measurement["returncode"] != 0:
        status = "TIMEOUT" if measurement["timed_out"] else "PROCESS_ERROR"
        detail = (
            "measurement wall timeout"
            if measurement["timed_out"]
            else "measurement exit " + str(measurement["returncode"])
        )
        publish_measurement_failure(
            profile_dir,
            partition,
            status,
            detail,
            measurement,
            options["smoke"],
            natural_ring_dim,
            measurement_capture_state,
            measurement_diagnostic_source,
            temporary_path,
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
        candidate_value["run_nonce"] = runtime_run_nonce
        candidate_value["benchmark_sha256"] = runtime_benchmark_sha256
        atomic_json(temporary_path / "candidates.json", candidate_value)
    except Exception as error:
        publish_measurement_failure(
            profile_dir, partition, "PROCESS_ERROR",
            "candidate command normalization failed: " + str(error),
            measurement, options["smoke"], natural_ring_dim,
            measurement_capture_state, measurement_diagnostic_source,
            temporary_path)
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
        publish_measurement_failure(
            profile_dir,
            partition,
            "PROCESS_ERROR",
            str(error),
            measurement,
            options["smoke"],
            natural_ring_dim,
            measurement_capture_state,
            measurement_diagnostic_source,
            temporary_path,
        )
        any_incomplete = True
        break

    for capture_path in measurement_capture_paths.values():
        capture_path.unlink()
    (temporary_path / ".piccard-shard-owner.json").unlink()
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
    seal_value = {
        "schema": "piccard-profile-completion-seal",
        "version": 1,
        "run_nonce": run_identity["run_nonce"],
        "profile_id": options["profile"],
        "profile_manifest_sha256": None,
        "shard_manifest_sha256": shard_digests,
    }
    if (
        options["resume"]
        and prior_profile_manifest is not None
        and prior_profile_manifest["profile_verdict"] not in {
            "FAIL_INCOMPLETE", "FAIL_REQUIRED"
        }
    ):
        if prior_profile_manifest != profile_value:
            fail("resume profile manifest semantics mismatch", 2)
    elif options["resume"]:
        atomic_json(profile_manifest_path, profile_value)
        seal_value["profile_manifest_sha256"] = sha256_file(
            profile_manifest_path)
        atomic_json(profile_dir / "completion_seal.json", seal_value)
    else:
        atomic_json(profile_manifest_path, profile_value)
        seal_value["profile_manifest_sha256"] = sha256_file(
            profile_manifest_path)
        write_once_json(
            profile_dir / "completion_seal.json", seal_value)

required_failure = (
    not dry_run
    and profile_verdict in {"FAIL_INCOMPLETE", "FAIL_REQUIRED"}
)
raise SystemExit(2 if any_incomplete or required_failure else 0)
PY
