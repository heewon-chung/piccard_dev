import csv
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest


REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "scripts" / "run_noise_profiles.sh"
MATRIX = REPO / "scripts" / "noise_profiles.json"


FAKE_BENCH = r"""#!/usr/bin/env python3
import csv, hashlib, json, math, os, pathlib, signal, sys, time

args = sys.argv[1:]
with open(os.environ["FAKE_INVOCATION_LOG"], "a") as invocation_log:
    invocation_log.write(json.dumps(args, separators=(",", ":")) + "\n")
value = lambda name, default="": next(
    (a.split("=", 1)[1] for a in args if a.startswith(name + "=")), default)
mode = os.environ.get("FAKE_MODE", "success")
log_path = os.environ.get("FAKE_SIGNAL_LOG")

def log(text):
    if log_path:
        with open(log_path, "a") as out:
            out.write(text + "\n")

def hang():
    signal.signal(signal.SIGTERM, lambda *_: log("TERM"))
    while True:
        time.sleep(1)

manifest_path = pathlib.Path(
    os.environ.get("PICCARD_PROFILE_MANIFEST", value("--profile_manifest")))
manifest = json.loads(manifest_path.read_text())

if "--print_profile_manifest" in args:
    sys.stdout.write(manifest_path.read_text())
    raise SystemExit(0)
if "--print_source_commit" in args:
    print(os.environ["FAKE_EMBEDDED_SOURCE"])
    raise SystemExit(0)

key_id = value("--key_id")
partition = next(p for p in manifest["partitions"] if p["key_id"] == key_id)

if "--preflight_context" in args:
    if mode == "preflight_hang":
        hang()
    if mode == "malformed_preflight":
        print("{broken")
        raise SystemExit(0)
    result = {
        "source_commit": manifest["source_commit"],
        "openfhe_version": manifest["openfhe_version"],
        "key_id": key_id,
        "profile_id": partition["profile_id"],
        "circuit": partition["circuit"],
        "shape_id": partition["shape_id"],
        "security": partition["security"],
        "requested_ring_dim": partition["requested_ring_dim"],
        "natural_depth": partition["natural_depth"],
        "consumer_set_sha256": partition["consumer_set_sha256"],
        "natural_ring_dim": partition["requested_ring_dim"],
    }
    if mode == "wrong_key":
        result["key_id"] += "x"
    elif mode == "wrong_source":
        result["source_commit"] = "0" * 40
    elif mode == "wrong_openfhe":
        result["openfhe_version"] = "stale"
    elif mode == "wrong_n":
        result["requested_ring_dim"] *= 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0)

if mode == "measurement_hang":
    hang()
if mode == "replace_binary":
    benchmark_path = pathlib.Path(os.environ["FAKE_BENCH_PATH"])
    replacement = benchmark_path.with_name(benchmark_path.name + ".replacement")
    replacement.write_bytes(benchmark_path.read_bytes() + b"\n# replaced\n")
    replacement.chmod(0o755)
    replacement.replace(benchmark_path)
if mode in ("crash", "publisher_cleanup_path_swap",
            "raw_cleanup_path_swap"):
    os.write(1, b"FAKE_BENCH_STDOUT crash\n")
    os.write(2, b"FAKE_BENCH_STDERR crash\n")
    raise SystemExit(23)
if mode == "signal":
    os.write(1, b"FAKE_BENCH_STDOUT signal\n")
    os.write(2, b"FAKE_BENCH_STDERR signal\n")
    os.kill(os.getpid(), signal.SIGSEGV)
if mode == "diagnostic_flood":
    sys.stdout.buffer.write(
        b"OUT-HEAD\n" + b"O" * 1_200_000 + b"\nOUT-TAIL\n")
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(
        b"ERR-HEAD\n" + b"E" * 1_200_000 + b"\nERR-TAIL\n")
    sys.stderr.buffer.flush()
    raise SystemExit(29)
if mode == "oom":
    raise SystemExit(137)
if mode == "missing_csv":
    raise SystemExit(0)

aggregate_header = (
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
detail_header = (
    "profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,"
    "consumer_m,pattern,rep_index,rep_seed,requested_ring_dim,"
    "natural_ring_dim,ring_dim_calibrated,realized_ring_dim,"
    "ring_growth_factor,natural_depth,provisioned_depth,scaling_mod_size,"
    "num_limbs,plaintext_mod,log_q,log_delta,eval_noise_bits,"
    "headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,"
    "openfhe_version,source_commit,status_code,error_message"
)
rings = [int(x) for x in value("--ring_candidates").split(",")]
sms_values = [int(x) for x in value("--scaling_mod_grid").split(",")]
max_delta = int(value("--max_depth_delta"))
reps = int(value("--reps"))
consumers = [tuple(map(int, x.split(":"))) for x in value("--consumer_points").split(",")]
patterns = ("all_match", "no_match", "random")
details_dir = pathlib.Path(value("--detail_dir"))
aggregate_path = pathlib.Path(value("--aggregate_csv"))
candidate_manifest_path = pathlib.Path(value("--candidate_manifest"))

candidates = []
aggregate_rows = []

def is_prime(number):
    if number < 2:
        return False
    if number < 4:
        return True
    if number % 2 == 0 or number % 3 == 0:
        return False
    divisor = 5
    while divisor * divisor <= number:
        if number % divisor == 0 or number % (divisor + 2) == 0:
            return False
        divisor += 6
    return True

def plaintext_modulus(ring):
    multiplier = 1
    largest_k = max(k for k, _ in consumers)
    while 1 + 2 * ring * multiplier <= largest_k:
        multiplier += 1
    while not is_prime(1 + 2 * ring * multiplier):
        multiplier += 1
    return 1 + 2 * ring * multiplier

for ring in rings:
    for delta in range(max_delta + 1):
        for sms in sms_values:
            cid = f"N{ring}-d{partition['natural_depth'] + delta}-s{sms}"
            detail_path = details_dir / f"{cid}.csv"
            rows = []
            for k, m in consumers:
                for pattern in patterns:
                    for rep in range(reps):
                        fields = [""] * len(detail_header.split(","))
                        fields[:11] = [
                            partition["profile_id"], key_id, cid,
                            partition["circuit"], partition["shape_id"],
                            partition["security"], str(k), str(m), pattern,
                            str(rep), str(rep + 1),
                        ]
                        fields[11:19] = [
                            str(partition["requested_ring_dim"]),
                            str(partition["requested_ring_dim"]), str(ring),
                            str(ring), str(ring / partition["requested_ring_dim"]),
                            str(partition["natural_depth"]),
                            str(partition["natural_depth"] + delta), str(sms),
                        ]
                        finalization_no_numeric = (
                            mode == "finalization"
                            and partition["profile_id"] == "feasibility128"
                            and partition["security"] == "STD192"
                        )
                        row_status = (
                            "CONTEXT_ERROR" if mode == "infeasible" else
                            "PROCESS_ERROR" if mode == "detail_error" else
                            "PARAMETER_GENERATION_FAILED"
                            if mode == "undeclared_status" else "OK"
                        )
                        if mode == "finalization" and not finalization_no_numeric:
                            plaintext = plaintext_modulus(ring)
                            log_q = 300.0
                            log_delta = log_q - math.log2(plaintext)
                            eval_noise = 40.25
                            query_bits = int(value("--transcript_stat_bits")) + (
                                int(value("--max_queries")) - 1).bit_length()
                            coefficient_bits = query_bits + (ring - 1).bit_length()
                            flood_bits = (
                                math.ceil(eval_noise) + coefficient_bits
                                + int(value("--margin"))
                            )
                            fields[19:30] = [
                                "6", str(plaintext), str(log_q),
                                format(log_delta, ".17g"),
                                str(eval_noise),
                                format(log_delta - eval_noise, ".17g"),
                                value("--max_queries"), str(query_bits),
                                str(coefficient_bits), value("--margin"),
                                str(flood_bits),
                            ]
                        fields[30:37] = [
                            "1", "0", "4096", manifest["openfhe_version"],
                            manifest["source_commit"], row_status, "",
                        ]
                        rows.append(fields)
            with detail_path.open("w", newline="") as out:
                writer = csv.writer(out, lineterminator="\n")
                writer.writerow(detail_header.split(","))
                writer.writerows(rows)
            detail_hash = hashlib.sha256(detail_path.read_bytes()).hexdigest()
            fields = [""] * len(aggregate_header.split(","))
            fields[:13] = [
                partition["profile_id"], partition["circuit"],
                partition["shape_id"], partition["security"],
                str(len(consumers)), partition["consumer_set_sha256"],
                "", "", "3", str(reps),
                str(len(rows)), detail_hash, value("--seed"),
            ]
            fields[13:22] = [
                str(partition["requested_ring_dim"]),
                str(partition["requested_ring_dim"]), str(ring),
                str(ring / partition["requested_ring_dim"]), str(ring),
                str(partition["natural_depth"]),
                str(partition["natural_depth"] + delta), str(sms), "",
            ]
            aggregate_status = (
                "OK" if mode == "detail_error" else row_status)
            if mode == "finalization" and not finalization_no_numeric:
                numeric = rows[0]
                ordered_consumers = sorted(consumers)
                fields[6:8] = [
                    str(ordered_consumers[0][0]),
                    str(ordered_consumers[0][1]),
                ]
                fields[21:32] = numeric[19:30]
                consumer_canonical = "".join(
                    f"{k},{m},{format(float(numeric[23]), '.17g')},"
                    f"{format(float(numeric[24]), '.17g')},1,0,4096,"
                    f"{row_status}\n"
                    for k, m in ordered_consumers
                )
            else:
                consumer_canonical = "".join(
                    f"{k},{m},,,1,0,4096,{row_status}\n"
                    for k, m in sorted(consumers)
                )
            consumer_hash = hashlib.sha256(
                consumer_canonical.encode()).hexdigest()
            fields[32:40] = [
                "1", "0", "4096", manifest["openfhe_version"],
                manifest["source_commit"], aggregate_status, "", consumer_hash,
            ]
            aggregate_rows.append(fields)
            candidates.append({
                "candidate_id": cid,
                "status_code": aggregate_status,
                "detail_sha256": detail_hash,
                "detail_row_count": len(rows),
            })

with aggregate_path.open("w", newline="") as out:
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(aggregate_header.split(","))
    if mode != "truncated_csv":
        writer.writerows(aggregate_rows)
candidate_manifest_path.write_text(json.dumps({
    "schema": "piccard-candidate-manifest",
    "version": 1,
    "key_id": key_id,
    "source_commit": manifest["source_commit"],
    "openfhe_version": manifest["openfhe_version"],
    "profile_id": partition["profile_id"],
    "circuit": partition["circuit"],
    "shape_id": partition["shape_id"],
    "security": partition["security"],
    "requested_ring_dim": partition["requested_ring_dim"],
    "natural_depth": partition["natural_depth"],
    "consumer_points": partition["consumer_points"],
    "consumer_set_sha256": partition["consumer_set_sha256"],
    "command": args,
    "candidate_count": len(candidates),
    "candidates": candidates,
}, sort_keys=True, separators=(",", ":")) + "\n")
"""


class NoiseProfileRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fake = self.root / "fake_bench_noise"
        self.fake_impl = self.root / "fake_bench_noise_impl"
        self.fake_impl.write_text(FAKE_BENCH)
        self.fake_impl.chmod(0o755)
        self.fake.write_text(textwrap.dedent("""\
            #!/bin/sh
            case "${FAKE_MODE:-}" in
              preflight_hang)
                case " $* " in
                  *" --preflight_context "*)
                    trap 'echo TERM >>"$FAKE_SIGNAL_LOG"' TERM
                    : >"$PICCARD_TEST_READY_MARKER"
                    while :; do sleep 1; done
                    ;;
                esac
                ;;
              preflight_startup_delay)
                case " $* " in
                  *" --preflight_context "*)
                    sleep 0.2
                    trap 'echo TERM >>"$FAKE_SIGNAL_LOG"' TERM
                    : >"$PICCARD_TEST_READY_MARKER"
                    while :; do sleep 1; done
                    ;;
                esac
                ;;
              measurement_hang)
                case " $* " in
                  *" --print_profile_manifest "*|*" --print_source_commit "*|*" --preflight_context "*) ;;
                  *)
                    trap 'echo TERM >>"$FAKE_SIGNAL_LOG"' TERM
                    printf '%s\\n' 'FAKE_BENCH_STDOUT timeout'
                    printf '%s\\n' 'FAKE_BENCH_STDERR timeout' >&2
                    : >"$PICCARD_TEST_READY_MARKER"
                    while :; do sleep 1; done
                    ;;
                esac
                ;;
              measurement_no_readiness)
                case " $* " in
                  *" --print_profile_manifest "*|*" --print_source_commit "*|*" --preflight_context "*) ;;
                  *)
                    printf '%s\\n' 'FAKE_BENCH_STDOUT no readiness'
                    printf '%s\\n' 'FAKE_BENCH_STDERR no readiness' >&2
                    exit 17
                    ;;
                esac
                ;;
            esac
            if [ -n "${PICCARD_TEST_READY_MARKER:-}" ]; then
              : >"$PICCARD_TEST_READY_MARKER"
            fi
            exec "$FAKE_BENCH_IMPL" "$@"
        """))
        self.fake.chmod(0o755)
        self.signal_log = self.root / "signals.log"
        self.env = os.environ.copy()
        self.env["FAKE_SIGNAL_LOG"] = str(self.signal_log)
        self.env["FAKE_BENCH_IMPL"] = str(self.fake_impl)
        self.env["FAKE_BENCH_PATH"] = str(self.fake)
        self.invocation_log = self.root / "invocations.jsonl"
        self.env["FAKE_INVOCATION_LOG"] = str(self.invocation_log)
        self.ready_dir = self.root / "ready"
        self.ready_dir.mkdir()
        self.env["PICCARD_TEST_READY_DIR"] = str(self.ready_dir)
        self.env["FAKE_EMBEDDED_SOURCE"] = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.env["PICCARD_TEST_SUPERVISOR"] = "1"
        self.test_timing_env = {
            "PICCARD_TEST_SUPERVISOR": "1",
            "PICCARD_TEST_TIMEOUT_MS": "50",
            "PICCARD_TEST_TERM_GRACE_MS": "20",
        }
        self.diagnostic_flood_timing_env = {
            "PICCARD_TEST_SUPERVISOR": "1",
            "PICCARD_TEST_TIMEOUT_MS": "2000",
            "PICCARD_TEST_TERM_GRACE_MS": "100",
        }

    def tearDown(self):
        self.temp.cleanup()

    def run_runner(self, *args, mode="success", dry_run=False):
        env = self.env.copy()
        env["FAKE_MODE"] = mode
        if mode in (
            "preflight_hang", "preflight_startup_delay", "measurement_hang",
            "measurement_no_readiness",
        ):
            env.update(self.test_timing_env)
        if mode == "diagnostic_flood":
            env.update(self.diagnostic_flood_timing_env)
        guarded_faults = {
            "capture_setup_failure": {
                "PICCARD_TEST_FAIL_SECOND_CAPTURE": "1",
            },
            "pre_binding_failure": {
                "PICCARD_TEST_PRE_BINDING_FAILURE": "1",
            },
            "publisher_cleanup_path_swap": {
                "PICCARD_TEST_PUBLISH_PAYLOAD_FAILURE": "1",
                "PICCARD_TEST_SWAP_PUBLISHER_CLEANUP": "1",
            },
            "raw_cleanup_path_swap": {
                "PICCARD_TEST_SWAP_RAW_CLEANUP": "1",
            },
        }
        env.update(guarded_faults.get(mode, {}))
        if dry_run:
            env["DRY_RUN"] = "1"
        return subprocess.run(
            [str(RUNNER), *args, f"--bench-noise={self.fake}"],
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            timeout=60 if mode == "finalization" else 10,
        )

    def measurement_invocation_count(self):
        if not self.invocation_log.exists():
            return 0
        return sum(
            any(argument.startswith("--aggregate_csv=") for argument in args)
            for args in (
                json.loads(line)
                for line in self.invocation_log.read_text().splitlines()
            )
        )

    def build_finalizable_root(self):
        roots = {}
        for profile in (
            "primary40", "sensitivity64", "feasibility128"
        ):
            profile_root = self.root / ("full-" + profile)
            result = self.run_runner(
                f"--profile={profile}",
                f"--results-root={profile_root}",
                mode="finalization",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            roots[profile] = profile_root
        combined = roots["primary40"]
        run_path = combined / "run_manifest.json"
        run = json.loads(run_path.read_text())
        run["source_tree_dirty"] = False
        run_path.write_text(
            json.dumps(run, sort_keys=True, separators=(",", ":")) + "\n")
        for profile in ("sensitivity64", "feasibility128"):
            source = roots[profile] / "profiles" / profile
            destination = combined / "profiles" / profile
            shutil.copytree(source, destination)
            shard_hashes = {}
            for shard in sorted(destination.glob("key-*")):
                candidate_path = shard / "candidates.json"
                candidate = json.loads(candidate_path.read_text())
                candidate["run_nonce"] = run["run_nonce"]
                candidate["benchmark_sha256"] = run["benchmark_sha256"]
                candidate["command"] = [
                    argument.replace(
                        str(roots[profile]), str(combined))
                    for argument in candidate["command"]
                ]
                candidate_path.write_text(
                    json.dumps(
                        candidate, sort_keys=True, separators=(",", ":"))
                    + "\n")
                shard_path = shard / "shard_manifest.json"
                shard_value = json.loads(shard_path.read_text())
                shard_value["run_nonce"] = run["run_nonce"]
                shard_value["benchmark_sha256"] = run["benchmark_sha256"]
                for field in ("measurement_command", "executed_command"):
                    shard_value[field] = [
                        argument.replace(
                            str(roots[profile]), str(combined))
                        for argument in shard_value[field]
                    ]
                shard_value["files"]["candidates.json"] = hashlib.sha256(
                    candidate_path.read_bytes()).hexdigest()
                shard_path.write_text(
                    json.dumps(
                        shard_value, sort_keys=True, separators=(",", ":"))
                    + "\n")
                shard_hashes[shard.name] = hashlib.sha256(
                    shard_path.read_bytes()).hexdigest()
            profile_path = destination / "profile_manifest.json"
            profile_value = json.loads(profile_path.read_text())
            profile_value["shard_manifest_sha256"] = shard_hashes
            profile_path.write_text(
                json.dumps(
                    profile_value, sort_keys=True, separators=(",", ":"))
                + "\n")
            seal_path = destination / "completion_seal.json"
            seal = json.loads(seal_path.read_text())
            seal["run_nonce"] = run["run_nonce"]
            seal["profile_manifest_sha256"] = hashlib.sha256(
                profile_path.read_bytes()).hexdigest()
            seal["shard_manifest_sha256"] = shard_hashes
            seal_path.chmod(0o644)
            seal_path.write_text(
                json.dumps(seal, sort_keys=True, separators=(",", ":"))
                + "\n")
            seal_path.chmod(0o444)
        return combined

    def run_finalize(self, result_root, final_dir, *extra):
        return subprocess.run(
            [
                str(RUNNER),
                f"--results-root={result_root}",
                f"--finalize-dir={final_dir}",
                *extra,
            ],
            cwd=REPO,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=120,
        )

    def smoke_args(self, result_root):
        return (
            "--profile=sensitivity64",
            "--smoke",
            f"--results-root={result_root}",
        )

    def repin_mutated_shard(self, result_root, shard):
        shard_manifest_path = shard / "shard_manifest.json"
        shard_manifest = json.loads(shard_manifest_path.read_text())
        for relative in list(shard_manifest["files"]):
            shard_manifest["files"][relative] = hashlib.sha256(
                (shard / relative).read_bytes()).hexdigest()
        shard_manifest_path.write_text(
            json.dumps(shard_manifest, sort_keys=True, separators=(",", ":"))
            + "\n")
        profile_manifest_path = (
            result_root / "profiles" / "sensitivity64" /
            "profile_manifest.json")
        profile_manifest = json.loads(profile_manifest_path.read_text())
        profile_manifest["shard_manifest_sha256"][
            shard_manifest["key_id"]] = hashlib.sha256(
                shard_manifest_path.read_bytes()).hexdigest()
        profile_manifest_path.write_text(
            json.dumps(profile_manifest, sort_keys=True, separators=(",", ":"))
            + "\n")
        seal_path = (
            result_root / "profiles" / "sensitivity64" /
            "completion_seal.json")
        seal = json.loads(seal_path.read_text())
        seal["profile_manifest_sha256"] = hashlib.sha256(
            profile_manifest_path.read_bytes()).hexdigest()
        seal["shard_manifest_sha256"] = profile_manifest[
            "shard_manifest_sha256"]
        seal_path.chmod(0o644)
        seal_path.write_text(
            json.dumps(seal, sort_keys=True, separators=(",", ":")) + "\n")
        seal_path.chmod(0o444)

    def test_dry_run_is_deterministic_and_covers_exact_matrix(self):
        result_root = self.root / "dry"
        args = (
            "--profile=primary40",
            f"--results-root={result_root}",
        )
        first = self.run_runner(*args, dry_run=True)
        second = self.run_runner(*args, dry_run=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stdout.count("SHARD "), 28)
        self.assertNotIn("--circuit=threshold", first.stdout.lower())
        self.assertIn("candidates=98", first.stdout)
        self.assertIn("timeout=86400", first.stdout)
        self.assertFalse(result_root.exists())

    def test_smoke_runs_exact_four_cells_and_marks_them_ineligible(self):
        result_root = self.root / "smoke"
        result = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((result_root / "run_manifest.json").read_text())
        self.assertTrue(manifest["smoke_only"])
        self.assertFalse(manifest["table_eligible"])
        self.assertEqual(
            manifest["source_commit"], self.env["FAKE_EMBEDDED_SOURCE"])
        self.assertIn("source_tree_dirty", manifest)
        resolved = json.loads(
            (result_root / "resolved_noise_profiles.json").read_text())
        self.assertEqual(
            resolved["source_commit"], self.env["FAKE_EMBEDDED_SOURCE"])
        shards = list((result_root / "profiles" / "sensitivity64").glob("key-*"))
        self.assertEqual(len(shards), 4)
        for shard in shards:
            data = json.loads((shard / "shard_manifest.json").read_text())
            self.assertEqual(data["candidate_count"], 1)
            self.assertFalse(data["table_eligible"])
            self.assertEqual(data["schema"], "piccard-shard-manifest")
            self.assertEqual(data["version"], 1)
            self.assertFalse((shard / "benchmark.stdout.log").exists())
            self.assertFalse((shard / "benchmark.stderr.log").exists())
            candidates = json.loads((shard / "candidates.json").read_text())
            expected_payload = {"aggregate.csv", "candidates.json"} | {
                "details/" + receipt["candidate_id"] + ".csv"
                for receipt in candidates["candidates"]
            }
            actual_payload = {
                path.relative_to(shard).as_posix()
                for path in shard.rglob("*")
                if path.is_file() and path.name != "shard_manifest.json"
            }
            self.assertEqual(set(data["files"]), expected_payload)
            self.assertEqual(actual_payload, expected_payload)
            for field in (
                "profile_id", "circuit", "shape_id", "security",
                "requested_ring_dim", "natural_depth", "consumer_points",
                "consumer_set_sha256", "source_commit", "openfhe_version",
                "command",
            ):
                self.assertIn(field, candidates)

    def test_resume_skips_only_revalidated_complete_shards(self):
        result_root = self.root / "resume"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        before = {
            path: path.stat().st_mtime_ns
            for path in result_root.rglob("*")
            if path.is_file()
        }
        second = self.run_runner(
            "--profile=sensitivity64",
            "--smoke",
            "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        after = {path: path.stat().st_mtime_ns for path in before}
        self.assertEqual(before, after)
        self.assertEqual(second.stdout.count("SKIP "), 4)

    def test_resume_fails_closed_on_hash_mismatch(self):
        result_root = self.root / "tamper"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        aggregate = next(result_root.rglob("aggregate.csv"))
        aggregate.write_text(aggregate.read_text() + "tamper\n")
        second = self.run_runner(
            "--profile=sensitivity64",
            "--smoke",
            "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(second.returncode, 2)
        self.assertIn("hash", second.stderr.lower())

    def test_resume_revalidates_manifest_counts_before_skipping(self):
        result_root = self.root / "manifest-tamper"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        shard_manifest_path = next(result_root.rglob("shard_manifest.json"))
        shard_manifest = json.loads(shard_manifest_path.read_text())
        shard_manifest["candidate_count"] += 1
        shard_manifest_path.write_text(
            json.dumps(shard_manifest, sort_keys=True, separators=(",", ":"))
            + "\n")
        profile_manifest_path = (
            result_root / "profiles" / "sensitivity64" /
            "profile_manifest.json")
        profile_manifest = json.loads(profile_manifest_path.read_text())
        profile_manifest["shard_manifest_sha256"][
            shard_manifest["key_id"]] = hashlib.sha256(
                shard_manifest_path.read_bytes()).hexdigest()
        profile_manifest_path.write_text(
            json.dumps(profile_manifest, sort_keys=True, separators=(",", ":"))
            + "\n")
        seal_path = (
            result_root / "profiles" / "sensitivity64" /
            "completion_seal.json")
        seal = json.loads(seal_path.read_text())
        seal["profile_manifest_sha256"] = hashlib.sha256(
            profile_manifest_path.read_bytes()).hexdigest()
        seal["shard_manifest_sha256"] = profile_manifest[
            "shard_manifest_sha256"]
        seal_path.chmod(0o644)
        seal_path.write_text(
            json.dumps(seal, sort_keys=True, separators=(",", ":")) + "\n")
        seal_path.chmod(0o444)
        second = self.run_runner(
            "--profile=sensitivity64",
            "--smoke",
            "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(second.returncode, 2)
        self.assertIn("count", second.stderr.lower())

    def test_preflight_identity_and_json_failures_are_terminal(self):
        for mode in (
            "wrong_key",
            "wrong_source",
            "wrong_openfhe",
            "wrong_n",
            "malformed_preflight",
        ):
            with self.subTest(mode=mode):
                result = self.run_runner(
                    *self.smoke_args(self.root / mode), mode=mode)
                self.assertEqual(result.returncode, 2)
                self.assertIn("PROCESS_ERROR", result.stderr)

    def test_preflight_hang_receives_term_then_kill_quickly(self):
        result = self.run_runner(
            *self.smoke_args(self.root / "preflight-hang"),
            mode="preflight_hang",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("TERM", self.signal_log.read_text())
        self.assertIn("kill_sent=true", result.stderr)
        failure = json.loads(next(
            (self.root / "preflight-hang").rglob("failure.json")).read_text())
        self.assertEqual(failure["status_code"], "TIMEOUT")
        self.assertLess(failure["elapsed_ms"], 500)
        with next(
            (self.root / "preflight-hang").rglob("aggregate.csv")
        ).open(newline="") as source:
            rows = list(csv.reader(source))
        self.assertEqual(rows[1][37], "TIMEOUT")

    def test_delayed_trap_waits_for_readiness_before_timeout(self):
        root = self.root / "delayed-trap"
        result = self.run_runner(
            *self.smoke_args(root), mode="preflight_startup_delay")
        self.assertEqual(result.returncode, 2)
        failure = json.loads(next(root.rglob("failure.json")).read_text())
        self.assertEqual(failure["status_code"], "TIMEOUT")
        self.assertTrue(failure["term_sent"])
        self.assertTrue(failure["kill_sent"])
        self.assertIn("TERM", self.signal_log.read_text())

    def test_measurement_timeout_is_atomic_and_visible(self):
        result_root = self.root / "measurement-hang"
        result = self.run_runner(
            *self.smoke_args(result_root), mode="measurement_hang")
        self.assertEqual(result.returncode, 2)
        failure = next(result_root.rglob("failure.json"))
        data = json.loads(failure.read_text())
        self.assertEqual(data["version"], 2)
        self.assertEqual(data["phase"], "measurement")
        self.assertEqual(data["capture_state"], "COMPLETE")
        self.assertEqual(data["status_code"], "TIMEOUT")
        self.assertTrue(data["term_sent"])
        self.assertTrue(data["kill_sent"])
        self.assertLess(data["elapsed_ms"], 500)
        manifest = json.loads(
            (failure.parent / "shard_manifest.json").read_text())
        expected_logs = {
            "stdout": b"FAKE_BENCH_STDOUT timeout\n",
            "stderr": b"FAKE_BENCH_STDERR timeout\n",
        }
        for stream, expected in expected_logs.items():
            log_path = failure.parent / f"benchmark.{stream}.log"
            content = log_path.read_bytes()
            self.assertIn(expected, content)
            metadata = data["diagnostic_logs"][stream]
            digest = hashlib.sha256(content).hexdigest()
            self.assertEqual(metadata["path"], log_path.name)
            self.assertEqual(metadata["sha256"], digest)
            self.assertEqual(metadata["original_bytes"], len(content))
            self.assertEqual(metadata["stored_bytes"], len(content))
            self.assertFalse(metadata["truncated"])
            self.assertEqual(manifest["files"][log_path.name], digest)
        aggregate = next(result_root.rglob("aggregate.csv"))
        with aggregate.open(newline="") as source:
            rows = list(csv.reader(source))
        self.assertEqual(",".join(rows[0]), (
            "profile,circuit,shape_id,security,consumer_count,"
            "consumer_set_sha256,worst_consumer_k,worst_consumer_m,"
            "pattern_count,repetitions_per_pattern,detail_row_count,"
            "detail_sha256,seed,requested_ring_dim,natural_ring_dim,"
            "realized_ring_dim,ring_growth_factor,ring_dim_calibrated,"
            "natural_depth,provisioned_depth,scaling_mod_size,num_limbs,"
            "plaintext_mod,log_q,log_delta,eval_noise_bits,headroom_bits,"
            "max_queries,query_stat_bits,coefficient_stat_bits,"
            "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,"
            "ct_bytes,openfhe_version,source_commit,status_code,"
            "error_message,consumer_results_sha256"))
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(rows[1]), 40)
        self.assertEqual(rows[1][37], "TIMEOUT")
        self.assertEqual(rows[1][0], "sensitivity64")
        self.assertEqual(rows[1][36], self.env["FAKE_EMBEDDED_SOURCE"])
        self.assertNotIn("FAKE_BENCH_STD", rows[1][38])
        self.assertNotIn("FAKE_BENCH_STD", result.stderr)
        profile = json.loads(
            (result_root / "profiles" / "sensitivity64" /
             "profile_manifest.json").read_text())
        self.assertEqual(profile["profile_verdict"], "FAIL_INCOMPLETE")

    def test_measurement_process_error_persists_exact_child_logs_without_canonical_leakage(self):
        cases = {
            "crash": (
                b"FAKE_BENCH_STDOUT crash\n",
                b"FAKE_BENCH_STDERR crash\n",
                23,
            ),
            "signal": (
                b"FAKE_BENCH_STDOUT signal\n",
                b"FAKE_BENCH_STDERR signal\n",
                -signal.SIGSEGV,
            ),
        }
        for mode, (expected_stdout, expected_stderr, returncode) in cases.items():
            with self.subTest(mode=mode):
                result_root = self.root / ("captured-" + mode)
                result = self.run_runner(
                    *self.smoke_args(result_root), mode=mode)
                self.assertEqual(result.returncode, 2)
                shard = next(
                    (result_root / "profiles" / "sensitivity64").glob(
                        "key-*"))
                stdout_path = shard / "benchmark.stdout.log"
                stderr_path = shard / "benchmark.stderr.log"
                self.assertEqual(stdout_path.read_bytes(), expected_stdout)
                self.assertEqual(stderr_path.read_bytes(), expected_stderr)
                failure = json.loads((shard / "failure.json").read_text())
                self.assertEqual(failure["version"], 2)
                self.assertEqual(failure["phase"], "measurement")
                self.assertEqual(failure["capture_state"], "COMPLETE")
                self.assertEqual(failure["status_code"], "PROCESS_ERROR")
                self.assertEqual(
                    failure["detail"], f"measurement exit {returncode}")
                self.assertEqual(failure["exit_code"], returncode)
                self.assertFalse(failure["term_sent"])
                self.assertFalse(failure["kill_sent"])
                self.assertEqual(
                    set(failure["diagnostic_logs"]), {"stdout", "stderr"})
                manifest = json.loads(
                    (shard / "shard_manifest.json").read_text())
                for stream, path in (
                    ("stdout", stdout_path), ("stderr", stderr_path)
                ):
                    metadata = failure["diagnostic_logs"][stream]
                    content = path.read_bytes()
                    digest = hashlib.sha256(content).hexdigest()
                    self.assertEqual(metadata["path"], path.name)
                    self.assertEqual(metadata["sha256"], digest)
                    self.assertEqual(
                        metadata["original_bytes"], len(content))
                    self.assertEqual(metadata["stored_bytes"], len(content))
                    self.assertFalse(metadata["truncated"])
                    self.assertEqual(manifest["files"][path.name], digest)
                with (shard / "aggregate.csv").open(
                    newline=""
                ) as source:
                    row = next(csv.DictReader(source))
                self.assertEqual(row["status_code"], "PROCESS_ERROR")
                self.assertEqual(
                    row["error_message"], f"measurement exit {returncode}")
                self.assertNotIn("FAKE_BENCH_STD", row["error_message"])
                self.assertNotIn("FAKE_BENCH_STD", result.stderr)

    def test_measurement_supervision_failures_are_atomic_and_catchable(self):
        no_readiness_root = self.root / "no-readiness"
        no_readiness = self.run_runner(
            *self.smoke_args(no_readiness_root),
            mode="measurement_no_readiness",
        )
        self.assertEqual(no_readiness.returncode, 2)
        no_readiness_shard = next(
            (no_readiness_root / "profiles" / "sensitivity64").glob("key-*"))
        self.assertEqual(
            {path.name for path in no_readiness_shard.iterdir()},
            {
                "aggregate.csv", "benchmark.stderr.log",
                "benchmark.stdout.log", "failure.json",
                "shard_manifest.json",
            },
        )
        failure = json.loads(
            (no_readiness_shard / "failure.json").read_text())
        self.assertEqual(failure["phase"], "measurement")
        self.assertEqual(failure["capture_state"], "COMPLETE")
        self.assertTrue(
            failure["detail"].startswith("benchmark binding failed:"))
        expected = {
            "stdout": b"FAKE_BENCH_STDOUT no readiness\n",
            "stderr": b"FAKE_BENCH_STDERR no readiness\n",
        }
        manifest = json.loads(
            (no_readiness_shard / "shard_manifest.json").read_text())
        for stream, content in expected.items():
            log = no_readiness_shard / f"benchmark.{stream}.log"
            self.assertEqual(log.read_bytes(), content)
            digest = hashlib.sha256(content).hexdigest()
            self.assertEqual(
                failure["diagnostic_logs"][stream]["sha256"], digest)
            self.assertEqual(manifest["files"][log.name], digest)
            self.assertNotIn(content.decode().strip(), failure["detail"])
        self.assertNotIn("FAKE_BENCH_STD", no_readiness.stderr)
        no_readiness_profile = no_readiness_shard.parent
        self.assertFalse(any(
            path.name.startswith(".") and ".tmp-" in path.name
            for path in no_readiness_profile.iterdir()
        ))

        for mode in ("capture_setup_failure", "pre_binding_failure"):
            with self.subTest(mode=mode):
                before = self.measurement_invocation_count()
                result_root = self.root / mode
                result = self.run_runner(
                    *self.smoke_args(result_root), mode=mode)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.measurement_invocation_count(), before)
                shard = next(
                    (result_root / "profiles" / "sensitivity64").glob(
                        "key-*"))
                self.assertEqual(
                    {path.name for path in shard.iterdir()},
                    {"aggregate.csv", "failure.json", "shard_manifest.json"},
                )
                failure = json.loads((shard / "failure.json").read_text())
                self.assertEqual(failure["phase"], "measurement")
                self.assertEqual(failure["capture_state"], "NOT_STARTED")
                self.assertEqual(failure["diagnostic_logs"], {})
                self.assertEqual(failure["status_code"], "PROCESS_ERROR")
                self.assertFalse(any(
                    shard.glob("benchmark.*.log")))
                self.assertFalse(any(
                    path.name.startswith(".") and ".tmp-" in path.name
                    for path in shard.parent.iterdir()
                ))

        swapped_root = self.root / "publisher-cleanup-swap"
        swapped = self.run_runner(
            *self.smoke_args(swapped_root),
            mode="publisher_cleanup_path_swap",
        )
        self.assertNotEqual(swapped.returncode, 0)
        self.assertIn("unowned", swapped.stderr.lower())
        swapped_profile = (
            swapped_root / "profiles" / "sensitivity64")
        self.assertFalse(any(swapped_profile.glob("key-*")))
        run = json.loads((swapped_root / "run_manifest.json").read_text())
        raw_temporaries = list(swapped_profile.glob(
            ".*.piccard-shard-v1.tmp-" + run["run_nonce"]))
        publisher_temporaries = list(swapped_profile.glob(
            ".*.piccard-failure-v2.tmp-" + run["run_nonce"] + "-*"))
        self.assertEqual(len(raw_temporaries), 1)
        self.assertEqual(len(publisher_temporaries), 1)
        raw_temporary = raw_temporaries[0]
        publisher_temporary = publisher_temporaries[0]
        self.assertEqual(
            json.loads(
                (raw_temporary / ".piccard-shard-owner.json").read_text()
            )["schema"],
            "piccard-shard-owner",
        )
        self.assertEqual(
            json.loads(
                (publisher_temporary /
                 ".piccard-failure-publisher-owner.json").read_text()
            )["schema"],
            "piccard-failure-publisher-owner",
        )
        self.assertEqual(
            (raw_temporary / "benchmark.stdout.log").read_bytes(),
            b"FAKE_BENCH_STDOUT crash\n",
        )
        self.assertEqual(
            (raw_temporary / "benchmark.stderr.log").read_bytes(),
            b"FAKE_BENCH_STDERR crash\n",
        )

        raw_swap_root = self.root / "raw-cleanup-swap"
        raw_swap = self.run_runner(
            *self.smoke_args(raw_swap_root), mode="raw_cleanup_path_swap")
        self.assertNotEqual(raw_swap.returncode, 0)
        self.assertIn("unowned", raw_swap.stderr.lower())
        raw_swap_profile = (
            raw_swap_root / "profiles" / "sensitivity64")
        published = list(raw_swap_profile.glob("key-*"))
        self.assertEqual(len(published), 1)
        published_bytes = {
            path.relative_to(published[0]).as_posix(): path.read_bytes()
            for path in published[0].rglob("*") if path.is_file()
        }
        raw_swap_run = json.loads(
            (raw_swap_root / "run_manifest.json").read_text())
        raw_swap_temporaries = list(raw_swap_profile.glob(
            ".*.piccard-shard-v1.tmp-" + raw_swap_run["run_nonce"]))
        self.assertEqual(len(raw_swap_temporaries), 1)
        self.assertTrue(
            (raw_swap_temporaries[0] /
             ".piccard-shard-owner.json").is_file())
        self.assertEqual(
            {
                path.relative_to(published[0]).as_posix(): path.read_bytes()
                for path in published[0].rglob("*") if path.is_file()
            },
            published_bytes,
        )

    def test_measurement_diagnostic_logs_are_deterministically_bounded(self):
        result_root = self.root / "diagnostic-flood"
        result = self.run_runner(
            *self.smoke_args(result_root), mode="diagnostic_flood")
        self.assertEqual(result.returncode, 2)
        shard = next(
            (result_root / "profiles" / "sensitivity64").glob("key-*"))
        failure = json.loads((shard / "failure.json").read_text())
        self.assertEqual(failure["detail"], "measurement exit 29")
        self.assertEqual(failure["exit_code"], 29)
        marker = (
            b"\n[PICCARD_DIAGNOSTIC_TRUNCATED "
            b"original_bytes=1200019]\n")
        payload_budget = 1_048_576 - len(marker)
        head_bytes = payload_budget // 2
        tail_bytes = payload_budget - head_bytes
        raw_streams = {
            "stdout": (
                b"OUT-HEAD\n" + b"O" * 1_200_000 + b"\nOUT-TAIL\n"),
            "stderr": (
                b"ERR-HEAD\n" + b"E" * 1_200_000 + b"\nERR-TAIL\n"),
        }
        for stream, raw in raw_streams.items():
            path = shard / f"benchmark.{stream}.log"
            stored = path.read_bytes()
            metadata = failure["diagnostic_logs"][stream]
            self.assertEqual(metadata["original_bytes"], 1_200_019)
            self.assertEqual(metadata["stored_bytes"], 1_048_576)
            self.assertTrue(metadata["truncated"])
            self.assertEqual(len(stored), 1_048_576)
            self.assertEqual(
                metadata["sha256"], hashlib.sha256(stored).hexdigest())
            expected = raw[:head_bytes] + marker + raw[-tail_bytes:]
            self.assertEqual(stored, expected)
            self.assertEqual(
                stored[head_bytes:head_bytes + len(marker)], marker)
            self.assertEqual(stored.count(marker), 1)

    def test_timeout_and_process_error_shards_resume_to_completion(self):
        for mode in ("measurement_hang", "crash"):
            with self.subTest(mode=mode):
                result_root = self.root / ("recover-" + mode)
                failed = self.run_runner(
                    *self.smoke_args(result_root), mode=mode)
                self.assertEqual(failed.returncode, 2)
                profile_dir = (
                    result_root / "profiles" / "sensitivity64")
                incomplete = next(profile_dir.glob("key-*"))
                failure = json.loads(
                    (incomplete / "failure.json").read_text())
                self.assertEqual(failure["version"], 2)
                self.assertEqual(failure["phase"], "measurement")
                self.assertEqual(failure["capture_state"], "COMPLETE")
                self.assertEqual(
                    set(failure["diagnostic_logs"]),
                    {"stdout", "stderr"},
                )
                receipt = json.loads(
                    (profile_dir / "profile_manifest.json").read_text())
                self.assertIn(
                    incomplete.name,
                    receipt["shard_manifest_sha256"],
                )
                resumed = self.run_runner(
                    "--profile=sensitivity64", "--smoke", "--resume",
                    f"--results-root={result_root}",
                )
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                profile = json.loads(
                    (result_root / "profiles" / "sensitivity64" /
                     "profile_manifest.json").read_text())
                self.assertEqual(profile["profile_verdict"], "PASS")
                self.assertEqual(len(profile["key_verdicts"]), 4)
                for shard in profile_dir.glob("key-*"):
                    self.assertFalse(
                        (shard / "benchmark.stdout.log").exists())
                    self.assertFalse(
                        (shard / "benchmark.stderr.log").exists())

    def test_resume_rejects_tampered_incomplete_diagnostic_log_before_recompute(self):
        cases = {
            "log_only": "incomplete shard payload hash mismatch",
            "manifest_only_repin": "immutable parent shard digest mismatch",
            "missing_receipt_parent_digest":
                "missing incomplete parent shard digest",
            "no_receipt_malformed_v2":
                "diagnostic stored_bytes type mismatch",
        }
        for mutation, expected_error in cases.items():
            with self.subTest(mutation=mutation):
                result_root = self.root / ("resume-tamper-" + mutation)
                first = self.run_runner(
                    *self.smoke_args(result_root), mode="crash")
                self.assertEqual(first.returncode, 2, first.stderr)
                profile_dir = (
                    result_root / "profiles" / "sensitivity64")
                shard = next(profile_dir.glob("key-*"))
                stderr_path = shard / "benchmark.stderr.log"
                shard_manifest_path = shard / "shard_manifest.json"
                failure_path = shard / "failure.json"
                if mutation in ("log_only", "manifest_only_repin"):
                    content = bytearray(stderr_path.read_bytes())
                    content[0] ^= 1
                    stderr_path.write_bytes(content)
                    if mutation == "manifest_only_repin":
                        shard_manifest = json.loads(
                            shard_manifest_path.read_text())
                        shard_manifest["files"][
                            stderr_path.name] = hashlib.sha256(
                                stderr_path.read_bytes()).hexdigest()
                        shard_manifest_path.write_text(
                            json.dumps(
                                shard_manifest,
                                sort_keys=True,
                                separators=(",", ":"),
                            ) + "\n")
                elif mutation == "missing_receipt_parent_digest":
                    profile_path = profile_dir / "profile_manifest.json"
                    profile = json.loads(profile_path.read_text())
                    profile["shard_manifest_sha256"].pop(shard.name)
                    profile_path.write_text(
                        json.dumps(
                            profile, sort_keys=True, separators=(",", ":"))
                        + "\n")
                    seal_path = profile_dir / "completion_seal.json"
                    seal = json.loads(seal_path.read_text())
                    seal["shard_manifest_sha256"].pop(shard.name)
                    seal["profile_manifest_sha256"] = hashlib.sha256(
                        profile_path.read_bytes()).hexdigest()
                    seal_path.chmod(0o644)
                    seal_path.write_text(
                        json.dumps(
                            seal, sort_keys=True, separators=(",", ":"))
                        + "\n")
                    seal_path.chmod(0o444)
                else:
                    (profile_dir / "profile_manifest.json").unlink()
                    (profile_dir / "completion_seal.json").unlink()
                    failure = json.loads(failure_path.read_text())
                    failure["diagnostic_logs"]["stderr"][
                        "stored_bytes"] = True
                    failure_path.write_text(
                        json.dumps(
                            failure, sort_keys=True, separators=(",", ":"))
                        + "\n")
                    shard_manifest = json.loads(
                        shard_manifest_path.read_text())
                    shard_manifest["files"][
                        failure_path.name] = hashlib.sha256(
                            failure_path.read_bytes()).hexdigest()
                    shard_manifest_path.write_text(
                        json.dumps(
                            shard_manifest,
                            sort_keys=True,
                            separators=(",", ":"),
                        ) + "\n")
                before = {
                    path.relative_to(shard).as_posix(): path.read_bytes()
                    for path in shard.rglob("*") if path.is_file()
                }
                invocation_count = self.measurement_invocation_count()
                resumed = self.run_runner(
                    "--profile=sensitivity64",
                    "--smoke",
                    "--resume",
                    f"--results-root={result_root}",
                )
                self.assertEqual(resumed.returncode, 2)
                self.assertIn(expected_error, resumed.stderr)
                self.assertEqual(
                    self.measurement_invocation_count(), invocation_count)
                self.assertTrue(shard.is_dir())
                after = {
                    path.relative_to(shard).as_posix(): path.read_bytes()
                    for path in shard.rglob("*") if path.is_file()
                }
                self.assertEqual(after, before)

    def test_resume_recovers_when_interrupted_before_profile_receipt(self):
        result_root = self.root / "missing-receipt"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        profile_dir = result_root / "profiles" / "sensitivity64"
        run = json.loads((result_root / "run_manifest.json").read_text())
        interrupted_key = sorted(profile_dir.glob("key-*"))[0]
        key_id = interrupted_key.name
        shutil.rmtree(interrupted_key)
        staged = profile_dir / (
            "." + key_id
            + ".piccard-shard-v1.tmp-" + run["run_nonce"])
        staged.mkdir()
        (staged / ".piccard-shard-owner.json").write_text(
            json.dumps({
                "key_id": key_id,
                "profile_id": "sensitivity64",
                "run_nonce": run["run_nonce"],
                "schema": "piccard-shard-owner",
                "version": 1,
            }, sort_keys=True, separators=(",", ":")) + "\n")
        (staged / "partial").write_text("interrupted\n")
        (profile_dir / "profile_manifest.json").unlink()
        (profile_dir / "completion_seal.json").unlink()
        resumed = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(resumed.stdout.count("SKIP "), 3)
        self.assertFalse(staged.exists())
        self.assertEqual(len(list(profile_dir.glob("key-*"))), 4)

    def test_process_failures_never_disappear(self):
        for mode in (
            "crash",
            "signal",
            "oom",
            "missing_csv",
            "truncated_csv",
        ):
            with self.subTest(mode=mode):
                result_root = self.root / mode
                result = self.run_runner(
                    *self.smoke_args(result_root), mode=mode)
                self.assertEqual(result.returncode, 2)
                failure = next(result_root.rglob("failure.json"))
                data = json.loads(failure.read_text())
                self.assertEqual(data["status_code"], "PROCESS_ERROR")
                aggregate = next(result_root.rglob("aggregate.csv"))
                with aggregate.open(newline="") as source:
                    rows = list(csv.reader(source))
                self.assertEqual(len(rows), 2)
                self.assertEqual(len(rows[1]), 40)
                self.assertEqual(rows[1][37], "PROCESS_ERROR")
                if mode in ("missing_csv", "truncated_csv"):
                    shard = failure.parent
                    manifest = json.loads(
                        (shard / "shard_manifest.json").read_text())
                    self.assertEqual(
                        data["schema"], "piccard-runner-failure")
                    self.assertEqual(data["version"], 2)
                    self.assertEqual(data["phase"], "measurement")
                    self.assertEqual(data["capture_state"], "COMPLETE")
                    self.assertEqual(
                        set(data["diagnostic_logs"]),
                        {"stdout", "stderr"},
                    )
                    self.assertEqual(
                        manifest["schema"], "piccard-shard-manifest")
                    self.assertEqual(manifest["version"], 1)
                    self.assertEqual(
                        set(manifest["files"]),
                        {
                            "aggregate.csv", "failure.json",
                            "benchmark.stdout.log", "benchmark.stderr.log",
                        },
                    )
                    self.assertEqual(
                        {path.name for path in shard.iterdir()},
                        {
                            "aggregate.csv", "failure.json",
                            "benchmark.stdout.log", "benchmark.stderr.log",
                            "shard_manifest.json",
                        },
                    )
                    for stream in ("stdout", "stderr"):
                        log = shard / f"benchmark.{stream}.log"
                        self.assertEqual(log.read_bytes(), b"")
                        digest = hashlib.sha256(b"").hexdigest()
                        self.assertEqual(
                            data["diagnostic_logs"][stream]["sha256"],
                            digest,
                        )
                        self.assertEqual(
                            manifest["files"][log.name], digest)
                    with aggregate.open(newline="") as source:
                        row = next(csv.DictReader(source))
                    self.assertEqual(
                        row["error_message"], data["detail"])
                    self.assertEqual(manifest["candidate_count"], 0)
                    self.assertEqual(
                        manifest["key_verdict"], "INCOMPLETE")
                    self.assertFalse(data["table_eligible"])

    def test_binary_replacement_is_detected_and_shards_bind_run_identity(self):
        original_benchmark = self.fake.read_bytes()
        replaced_root = self.root / "binary-replaced"
        replaced = self.run_runner(
            *self.smoke_args(replaced_root), mode="replace_binary")
        self.assertEqual(replaced.returncode, 2)
        self.assertIn("benchmark", replaced.stderr.lower())

        # Restore the fixture benchmark, then prove successful shard evidence
        # carries both immutable run bindings.
        self.fake.write_bytes(original_benchmark)
        self.fake.chmod(0o755)
        bound_root = self.root / "binary-bound"
        completed = self.run_runner(*self.smoke_args(bound_root))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        run = json.loads((bound_root / "run_manifest.json").read_text())
        shard_dir = next(
            (bound_root / "profiles" / "sensitivity64").glob("key-*"))
        shard = json.loads((shard_dir / "shard_manifest.json").read_text())
        candidate = json.loads((shard_dir / "candidates.json").read_text())
        for value in (shard, candidate):
            self.assertEqual(value["run_nonce"], run["run_nonce"])
            self.assertEqual(
                value["benchmark_sha256"], run["benchmark_sha256"])

    def test_root_and_timing_overrides_fail_closed(self):
        relative = self.run_runner(
            "--profile=sensitivity64",
            "--smoke",
            "--results-root=relative",
        )
        self.assertNotEqual(relative.returncode, 0)
        in_tree = self.run_runner(
            "--profile=sensitivity64",
            "--smoke",
            f"--results-root={REPO / 'bad-root'}",
        )
        self.assertNotEqual(in_tree.returncode, 0)
        existing = self.root / "existing"
        existing.mkdir()
        exists = self.run_runner(*self.smoke_args(existing))
        self.assertNotEqual(exists.returncode, 0)

        unsafe_env = self.env.copy()
        unsafe_env.update(self.test_timing_env)
        unsafe_env["PICCARD_TEST_SUPERVISOR"] = "0"
        unsafe = subprocess.run(
            [
                str(RUNNER),
                "--profile=sensitivity64",
                "--smoke",
                f"--results-root={self.root / 'unsafe'}",
                f"--bench-noise={self.fake}",
            ],
            cwd=REPO,
            env=unsafe_env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(unsafe.returncode, 0)
        self.assertIn("timing override", unsafe.stderr.lower())

    def test_tracked_manifest_is_stable_while_smoke_binds_new_source(self):
        tracked_before = MATRIX.read_bytes()
        different_source = "a" * 40
        self.env["FAKE_EMBEDDED_SOURCE"] = different_source
        result_root = self.root / "post-commit-smoke"
        result = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(MATRIX.read_bytes(), tracked_before)
        resolved = json.loads(
            (result_root / "resolved_noise_profiles.json").read_text())
        self.assertEqual(resolved["source_commit"], different_source)
        self.assertEqual(
            [p["key_id"] for p in resolved["partitions"]],
            [p["key_id"] for p in json.loads(tracked_before)["partitions"]],
        )

    def test_non_smoke_rejects_binary_source_different_from_git_head(self):
        self.env["FAKE_EMBEDDED_SOURCE"] = "b" * 40
        result = self.run_runner(
            "--profile=feasibility128",
            f"--results-root={self.root / 'source-mismatch'}",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("git head", result.stderr.lower())

    def test_multi_ring_feasibility_matches_candidates_by_id_and_resumes(self):
        result_root = self.root / "multi-ring"
        first = self.run_runner(
            "--profile=feasibility128",
            f"--results-root={result_root}",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        shards = list(
            (result_root / "profiles" / "feasibility128").glob("key-*"))
        self.assertEqual(len(shards), 2)
        all_candidate_ids = set()
        for shard in shards:
            candidates = json.loads((shard / "candidates.json").read_text())
            candidate_ids = [c["candidate_id"] for c in candidates["candidates"]]
            all_candidate_ids.update(candidate_ids)
            natural = json.loads(
                (shard / "shard_manifest.json").read_text())[
                    "natural_ring_dim"]
            doubled = natural * 2
            self.assertLess(
                candidate_ids.index(f"N{natural}-d1-s40"),
                candidate_ids.index(f"N{doubled}-d1-s40"),
            )
        self.assertIn("N8192-d1-s40", all_candidate_ids)
        self.assertIn("N16384-d1-s40", all_candidate_ids)
        resumed = self.run_runner(
            "--profile=feasibility128",
            "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(resumed.stdout.count("SKIP "), 2)
        self.env["FAKE_EMBEDDED_SOURCE"] = "c" * 40
        mismatched = self.run_runner(
            "--profile=feasibility128",
            "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(mismatched.returncode, 2)
        self.assertIn("git head", mismatched.stderr.lower())

    def test_profile_verdict_truth_table(self):
        required_root = self.root / "required-infeasible"
        required = self.run_runner(
            *self.smoke_args(required_root), mode="infeasible")
        self.assertEqual(required.returncode, 2)
        required_manifest = json.loads(
            (required_root / "profiles" / "sensitivity64" /
             "profile_manifest.json").read_text())
        self.assertEqual(
            required_manifest["profile_verdict"],
            "FAIL_REQUIRED",
        )

        feasibility_root = self.root / "allowed-infeasible"
        feasibility = self.run_runner(
            "--profile=feasibility128",
            f"--results-root={feasibility_root}",
            mode="infeasible",
        )
        self.assertEqual(feasibility.returncode, 0, feasibility.stderr)
        feasibility_manifest = json.loads(
            (feasibility_root / "profiles" / "feasibility128" /
             "profile_manifest.json").read_text())
        self.assertEqual(
            feasibility_manifest["profile_verdict"],
            "PASS_FEASIBILITY_WITH_INFEASIBLE",
        )
        aggregate_paths = sorted(
            (feasibility_root / "profiles" / "feasibility128").glob(
                "key-*/aggregate.csv"))
        self.assertEqual(len(aggregate_paths), 2)
        unavailable_reductions = (
            "worst_consumer_k", "worst_consumer_m",
            "eval_noise_bits", "headroom_bits",
            "query_stat_bits", "coefficient_stat_bits",
            "flood_noise_bits",
        )
        for aggregate_path in aggregate_paths:
            with aggregate_path.open(newline="") as source:
                aggregate_rows = list(csv.DictReader(source))
            self.assertTrue(aggregate_rows)
            for row in aggregate_rows:
                with self.subTest(
                    shard=aggregate_path.parent.name,
                    ring=row["realized_ring_dim"],
                    depth=row["provisioned_depth"],
                    scaling=row["scaling_mod_size"],
                ):
                    for field in unavailable_reductions:
                        self.assertEqual(row[field], "")

    def test_resume_parent_digest_rejects_rehashed_mutable_shard(self):
        result_root = self.root / "rehash-tamper"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        shard = next(
            (result_root / "profiles" / "sensitivity64").glob("key-*"))
        candidates_path = shard / "candidates.json"
        candidates = json.loads(candidates_path.read_text())
        candidates["candidates"][0]["candidate_id"] += "-tampered"
        candidates_path.write_text(
            json.dumps(candidates, sort_keys=True, separators=(",", ":"))
            + "\n")
        shard_manifest_path = shard / "shard_manifest.json"
        shard_manifest = json.loads(shard_manifest_path.read_text())
        shard_manifest["files"]["candidates.json"] = hashlib.sha256(
            candidates_path.read_bytes()).hexdigest()
        shard_manifest_path.write_text(
            json.dumps(shard_manifest, sort_keys=True, separators=(",", ":"))
            + "\n")
        resumed = self.run_runner(
            "--profile=sensitivity64",
            "--smoke",
            "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("digest", resumed.stderr.lower())

    def test_resume_requires_every_parent_shard_digest(self):
        result_root = self.root / "missing-parent-digest"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        profile_path = (
            result_root / "profiles" / "sensitivity64" /
            "profile_manifest.json")
        profile = json.loads(profile_path.read_text())
        profile["shard_manifest_sha256"].pop(
            next(iter(profile["shard_manifest_sha256"])))
        profile_path.write_text(
            json.dumps(profile, sort_keys=True, separators=(",", ":"))
            + "\n")
        resumed = self.run_runner(
            "--profile=sensitivity64",
            "--smoke",
            "--resume",
            f"--results-root={result_root}",
        )
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("completion seal", resumed.stderr.lower())

    def test_resume_cross_validates_candidate_aggregate_and_detail(self):
        for mutation in ("candidate", "aggregate", "detail"):
            with self.subTest(mutation=mutation):
                result_root = self.root / ("cross-" + mutation)
                first = self.run_runner(*self.smoke_args(result_root))
                self.assertEqual(first.returncode, 0, first.stderr)
                shard = next(
                    (result_root / "profiles" / "sensitivity64").glob(
                        "key-*"))
                if mutation == "candidate":
                    path = shard / "candidates.json"
                    value = json.loads(path.read_text())
                    value["circuit"] = "sqrt" if value["circuit"] == "onehot" \
                        else "onehot"
                    path.write_text(
                        json.dumps(
                            value, sort_keys=True, separators=(",", ":"))
                        + "\n")
                elif mutation == "aggregate":
                    path = shard / "aggregate.csv"
                    with path.open(newline="") as source:
                        rows = list(csv.DictReader(source))
                        fields = source.seek(0) or list(rows[0])
                    rows[0]["status_code"] = "SATURATED"
                    with path.open("w", newline="") as output:
                        writer = csv.DictWriter(
                            output, fieldnames=fields, lineterminator="\n")
                        writer.writeheader()
                        writer.writerows(rows)
                else:
                    detail_path = next((shard / "details").glob("*.csv"))
                    with detail_path.open(newline="") as source:
                        details = list(csv.DictReader(source))
                        detail_fields = list(details[0])
                    details[0]["profile"] = "primary40"
                    with detail_path.open("w", newline="") as output:
                        writer = csv.DictWriter(
                            output, fieldnames=detail_fields,
                            lineterminator="\n")
                        writer.writeheader()
                        writer.writerows(details)
                    detail_hash = hashlib.sha256(
                        detail_path.read_bytes()).hexdigest()
                    candidates_path = shard / "candidates.json"
                    candidates = json.loads(candidates_path.read_text())
                    candidates["candidates"][0][
                        "detail_sha256"] = detail_hash
                    candidates_path.write_text(
                        json.dumps(
                            candidates, sort_keys=True, separators=(",", ":"))
                        + "\n")
                    aggregate_path = shard / "aggregate.csv"
                    with aggregate_path.open(newline="") as source:
                        aggregates = list(csv.DictReader(source))
                        aggregate_fields = list(aggregates[0])
                    aggregates[0]["detail_sha256"] = detail_hash
                    with aggregate_path.open("w", newline="") as output:
                        writer = csv.DictWriter(
                            output, fieldnames=aggregate_fields,
                            lineterminator="\n")
                        writer.writeheader()
                        writer.writerows(aggregates)
                self.repin_mutated_shard(result_root, shard)
                resumed = self.run_runner(
                    "--profile=sensitivity64",
                    "--smoke",
                    "--resume",
                    f"--results-root={result_root}",
                )
                self.assertEqual(resumed.returncode, 2)
                self.assertIn(
                    mutation,
                    resumed.stderr.lower(),
                )

    def test_detail_status_reduction_cannot_be_relabelled_ok(self):
        result_root = self.root / "detail-status-error"
        result = self.run_runner(
            *self.smoke_args(result_root), mode="detail_error")
        self.assertEqual(result.returncode, 2)
        self.assertIn("detail status", result.stderr.lower())
        profile = json.loads(
            (result_root / "profiles" / "sensitivity64" /
             "profile_manifest.json").read_text())
        self.assertNotIn("SELECTED", profile.get("key_verdicts", {}).values())

    def test_undeclared_candidate_status_is_rejected(self):
        result = self.run_runner(
            *self.smoke_args(self.root / "undeclared"),
            mode="undeclared_status",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("status", result.stderr.lower())

    def test_resume_rejects_complete_command_policy_tampering(self):
        mutations = (
            ("max_queries", "--max_queries=", "--max_queries=999"),
            ("margin", "--margin=", "--margin=99"),
            ("output", "--aggregate_csv=", "--aggregate_csv=/tmp/wrong.csv"),
            ("extra", None, "--unexpected_option=1"),
            ("duplicate", None, "--max_queries=1048576"),
        )
        for name, prefix, replacement in mutations:
            with self.subTest(name=name):
                result_root = self.root / ("command-" + name)
                first = self.run_runner(*self.smoke_args(result_root))
                self.assertEqual(first.returncode, 0, first.stderr)
                shard = next(
                    (result_root / "profiles" / "sensitivity64").glob(
                        "key-*"))
                candidates_path = shard / "candidates.json"
                candidates = json.loads(candidates_path.read_text())
                shard_path = shard / "shard_manifest.json"
                shard_manifest = json.loads(shard_path.read_text())
                for command in (
                    candidates["command"],
                    shard_manifest["measurement_command"][1:],
                ):
                    if prefix is None:
                        command.append(replacement)
                    else:
                        index = next(
                            i for i, arg in enumerate(command)
                            if arg.startswith(prefix))
                        command[index] = replacement
                candidates_path.write_text(
                    json.dumps(
                        candidates, sort_keys=True, separators=(",", ":"))
                    + "\n")
                shard_path.write_text(
                    json.dumps(
                        shard_manifest,
                        sort_keys=True,
                        separators=(",", ":"))
                    + "\n")
                self.repin_mutated_shard(result_root, shard)
                resumed = self.run_runner(
                    "--profile=sensitivity64", "--smoke", "--resume",
                    f"--results-root={result_root}")
                self.assertEqual(resumed.returncode, 2)
                self.assertIn("command", resumed.stderr.lower())

    def test_resume_rejects_profile_manifest_tampering(self):
        result_root = self.root / "profile-tamper"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        profile_path = (
            result_root / "profiles" / "sensitivity64" /
            "profile_manifest.json")
        profile = json.loads(profile_path.read_text())
        profile["profile_verdict"] = "PASS_FEASIBILITY_WITH_INFEASIBLE"
        profile_path.write_text(
            json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n")
        resumed = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--resume",
            f"--results-root={result_root}")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("completion seal", resumed.stderr.lower())

    def test_run_manifest_is_write_once_and_completion_is_sealed(self):
        result_root = self.root / "write-once-run"
        first = self.run_runner(*self.smoke_args(result_root))
        self.assertEqual(first.returncode, 0, first.stderr)
        run_path = result_root / "run_manifest.json"
        before = (run_path.read_bytes(), run_path.stat().st_ino,
                  run_path.stat().st_mode)
        seal = (result_root / "profiles" / "sensitivity64" /
                "completion_seal.json")
        self.assertTrue(seal.is_file())
        resumed = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--resume",
            f"--results-root={result_root}")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        after = (run_path.read_bytes(), run_path.stat().st_ino,
                 run_path.stat().st_mode)
        self.assertEqual(before, after)
        self.assertEqual(seal.stat().st_mode & 0o222, 0)

    def test_resume_rejects_run_manifest_repin_or_extra_field(self):
        root = self.root / "run-repin"
        first = self.run_runner(*self.smoke_args(root))
        self.assertEqual(first.returncode, 0, first.stderr)
        run_path = root / "run_manifest.json"
        run = json.loads(run_path.read_text())
        run["profile_manifest_sha256"] = {"sensitivity64": "0" * 64}
        run_path.write_text(
            json.dumps(run, sort_keys=True, separators=(",", ":")) + "\n")
        resumed = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--resume",
            f"--results-root={root}")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("run manifest schema", resumed.stderr.lower())

    def test_resume_recomputes_numeric_reductions_and_consumer_hash(self):
        mutations = {
            "eval_noise_bits": "999",
            "headroom_bits": "-999",
            "decrypt_ok": "0",
            "saturated": "1",
            "ct_bytes": "999999",
            "consumer_results_sha256": "f" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                root = self.root / ("reduce-" + field)
                first = self.run_runner(*self.smoke_args(root))
                self.assertEqual(first.returncode, 0, first.stderr)
                shard = next(
                    (root / "profiles" / "sensitivity64").glob("key-*"))
                aggregate_path = shard / "aggregate.csv"
                with aggregate_path.open(newline="") as source:
                    rows = list(csv.DictReader(source))
                    fields = list(rows[0])
                rows[0][field] = replacement
                with aggregate_path.open("w", newline="") as output:
                    writer = csv.DictWriter(
                        output, fieldnames=fields, lineterminator="\n")
                    writer.writeheader()
                    writer.writerows(rows)
                self.repin_mutated_shard(root, shard)
                resumed = self.run_runner(
                    "--profile=sensitivity64", "--smoke", "--resume",
                    f"--results-root={root}")
                self.assertEqual(resumed.returncode, 2)
                self.assertIn("reduction", resumed.stderr.lower())

    def test_finalization_is_deterministic_atomic_and_immutable(self):
        result_root = self.build_finalizable_root()
        first = self.root / "finalized-a"
        second = self.root / "finalized-b"
        finalized = self.run_finalize(result_root, first)
        self.assertEqual(finalized.returncode, 0, finalized.stderr)
        repeated = self.run_finalize(result_root, second)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(
            sorted(path.name for path in first.iterdir()),
            ["manifest.json", "selected-shards.tar.zst"],
        )
        self.assertEqual(
            (first / "manifest.json").read_bytes(),
            (second / "manifest.json").read_bytes(),
        )
        self.assertEqual(
            (first / "selected-shards.tar.zst").read_bytes(),
            (second / "selected-shards.tar.zst").read_bytes(),
        )
        combined = json.loads((first / "manifest.json").read_text())
        infeasible = next(
            key for key in combined["keys"]
            if key["frontier_verdict"] == "INFEASIBLE"
        )
        self.assertEqual(
            infeasible["measurement_key_verdict"], "SELECTED")
        self.assertEqual(
            infeasible["infeasibility"]["reason"],
            "NO_COMPLETE_NUMERIC_OK_CANDIDATE",
        )
        self.assertTrue(all(
            infeasible["infeasibility"][field] is None
            for field in (
                "shortfall_bits", "best_candidate_id",
                "best_measured_eval_noise_bits",
                "required_capacity_bits", "log_delta",
            )
        ))
        immutable = self.run_finalize(result_root, first)
        self.assertNotEqual(immutable.returncode, 0)
        self.assertIn("final directory", immutable.stderr.lower())

        missing_profile = result_root / "profiles" / "feasibility128"
        saved_profile = result_root / "profiles" / ".saved-feasibility128"
        missing_profile.rename(saved_profile)
        failed = self.root / "failed-missing-profile"
        missing = self.run_finalize(result_root, failed)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("profile", missing.stderr.lower())
        self.assertFalse(failed.exists())
        saved_profile.rename(missing_profile)

        detail = next(result_root.rglob("details/*.csv"))
        saved_detail = detail.with_suffix(".saved")
        detail.rename(saved_detail)
        corrupt = self.root / "failed-shard"
        mismatch = self.run_finalize(result_root, corrupt)
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("shard", mismatch.stderr.lower())
        self.assertFalse(corrupt.exists())
        saved_detail.rename(detail)

        blocked = self.root / "blocked-final"
        sibling = blocked.with_name(
            "." + blocked.name + ".piccard-finalize-v1.tmp-unowned")
        sibling.mkdir()
        (sibling / ".piccard-finalize-owner.json").write_text("{}\n")
        collision = self.run_finalize(result_root, blocked)
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("owned", collision.stderr.lower())
        self.assertFalse(blocked.exists())
        self.assertEqual(
            (sibling / ".piccard-finalize-owner.json").read_text(), "{}\n")

    def test_finalization_never_removes_owned_marker_with_wrong_temp_name(self):
        result_root = self.build_finalizable_root()
        final_dir = self.root / "owned-name-probe"
        run = json.loads((result_root / "run_manifest.json").read_text())
        wrong = final_dir.with_name(
            "." + final_dir.name
            + ".piccard-finalize-v1.tmp-wrong-suffix")
        wrong.mkdir()
        owner = {
            "final_dir_realpath": str(final_dir.resolve(strict=False)),
            "results_root_realpath": str(result_root.resolve(strict=True)),
            "run_nonce": run["run_nonce"],
            "schema": "piccard-finalize-owner",
            "version": 1,
        }
        (wrong / ".piccard-finalize-owner.json").write_text(
            json.dumps(owner, sort_keys=True, separators=(",", ":")) + "\n")
        sentinel = wrong / "sentinel"
        sentinel.write_text("must survive\n")
        result = self.run_finalize(result_root, final_dir)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(final_dir.exists())
        self.assertEqual(sentinel.read_text(), "must survive\n")

    def test_finalization_cli_is_exclusive_and_removed_modes_are_unknown(self):
        result_root = self.root / "unused-results"
        final_dir = self.root / "unused-final"
        for extra in (
            "--profile=primary40",
            "--resume",
            "--smoke",
            f"--bench-noise={self.fake}",
            "--finalize-manifest=legacy.json",
            "--archive=legacy.tar.zst",
            "--reps=5",
            "--seed=20260729",
            "--max-queries=1048576",
            "--margin=8",
        ):
            with self.subTest(extra=extra):
                result = self.run_finalize(
                    result_root, final_dir, extra)
                self.assertNotEqual(result.returncode, 0)

    def test_phase5_profile_arguments_accepted_when_matching(self):
        result_root = self.root / "phase5-match"
        baseline_args = (
            "--profile=primary40",
            f"--results-root={result_root}",
        )
        confirmed_args = (
            "--profile=primary40",
            "--reps=5",
            "--seed=20260729",
            "--max-queries=1048576",
            "--margin=8",
            f"--results-root={result_root}",
        )
        baseline = self.run_runner(*baseline_args, dry_run=True)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        confirmed = self.run_runner(*confirmed_args, dry_run=True)
        self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
        self.assertEqual(confirmed.stdout, baseline.stdout)
        self.assertEqual(confirmed.stdout.count("SHARD "), 28)
        self.assertFalse(result_root.exists())

    def test_phase5_profile_arguments_rejected_on_mismatch(self):
        result_root = self.root / "phase5-mismatch"
        correct = {
            "--reps": "5",
            "--seed": "20260729",
            "--max-queries": "1048576",
            "--margin": "8",
        }
        wrong = {
            "--reps": "4",
            "--seed": "1",
            "--max-queries": "65536",
            "--margin": "9",
        }
        for option in correct:
            with self.subTest(option=option):
                args = [
                    "--profile=primary40",
                    f"--results-root={result_root}",
                ] + [
                    f"{other}={value}"
                    for other, value in correct.items()
                    if other != option
                ] + [f"{option}={wrong[option]}"]
                result = self.run_runner(*args, dry_run=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("SHARD ", result.stdout)
                self.assertIn(f"{option}={wrong[option]}", result.stderr)
                self.assertIn(correct[option], result.stderr)
                self.assertFalse(result_root.exists())

    def test_phase5_profile_arguments_accepted_space_separated(self):
        result_root = self.root / "phase5-space-separated"
        correct = {
            "--reps": "5",
            "--seed": "20260729",
            "--max-queries": "1048576",
            "--margin": "8",
        }
        for option in correct:
            with self.subTest(option=option):
                args = [
                    "--profile=primary40",
                    f"--results-root={result_root}",
                ]
                for other, value in correct.items():
                    if other == option:
                        args.extend([other, value])
                    else:
                        args.append(f"{other}={value}")
                result = self.run_runner(*args, dry_run=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(result_root.exists())

    def test_phase5_profile_arguments_duplicate_rejected(self):
        result_root = self.root / "phase5-duplicate"
        correct = {
            "--reps": "5",
            "--seed": "20260729",
            "--max-queries": "1048576",
            "--margin": "8",
        }
        for option in correct:
            with self.subTest(option=option):
                args = [
                    "--profile=primary40",
                    f"--results-root={result_root}",
                ] + [
                    f"{other}={value}" for other, value in correct.items()
                ] + [f"{option}={correct[option]}"]
                result = self.run_runner(*args, dry_run=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"duplicate {option}", result.stderr)
                self.assertFalse(result_root.exists())

    def test_smoke_reps_validated_against_effective_value(self):
        mismatch_root = self.root / "phase5-smoke-mismatch"
        mismatch = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--reps=5",
            f"--results-root={mismatch_root}",
            dry_run=True,
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertNotIn("SHARD ", mismatch.stdout)
        self.assertIn("--reps=5", mismatch.stderr)
        self.assertFalse(mismatch_root.exists())

        matching_root = self.root / "phase5-smoke-match"
        matching = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--reps=1",
            f"--results-root={matching_root}",
            dry_run=True,
        )
        self.assertEqual(matching.returncode, 0, matching.stderr)

    def test_evidence_confirmation_mismatch_leaves_no_results_root(self):
        # Regression: on a real (non-dry-run) invocation, a mismatched
        # CLI confirmation must be rejected before the results root is
        # created. Otherwise a failed run leaves a populated root behind
        # and the corrected retry dies on "first invocation requires a
        # nonexistent results root" instead of succeeding.
        result_root = self.root / "phase5-evidence-mismatch"
        mismatch = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--reps=5",
            f"--results-root={result_root}",
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("--reps=5", mismatch.stderr)
        self.assertFalse(result_root.exists())

        retry = self.run_runner(
            "--profile=sensitivity64", "--smoke", "--reps=1",
            f"--results-root={result_root}",
        )
        self.assertEqual(retry.returncode, 0, retry.stderr)

    def test_unknown_runner_argument_still_rejected(self):
        result_root = self.root / "phase5-unknown"
        result = self.run_runner(
            "--profile=primary40", "--frobnicate=1",
            f"--results-root={result_root}",
            dry_run=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown runner argument", result.stderr)


if __name__ == "__main__":
    unittest.main()
