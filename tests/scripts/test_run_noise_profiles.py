import csv
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest


REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "scripts" / "run_noise_profiles.sh"
MATRIX = REPO / "scripts" / "noise_profiles.json"


FAKE_BENCH = r"""#!/usr/bin/env python3
import csv, hashlib, json, os, pathlib, signal, sys, time

args = sys.argv[1:]
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
if mode == "crash":
    raise RuntimeError("fake crash")
if mode == "signal":
    os.kill(os.getpid(), signal.SIGSEGV)
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
                        row_status = (
                            "CONTEXT_ERROR" if mode == "infeasible" else
                            "PROCESS_ERROR" if mode == "detail_error" else
                            "PARAMETER_GENERATION_FAILED"
                            if mode == "undeclared_status" else "OK"
                        )
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
                "0", "0", "3", str(reps),
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
                    : >"$PICCARD_TEST_READY_MARKER"
                    while :; do sleep 1; done
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

    def tearDown(self):
        self.temp.cleanup()

    def run_runner(self, *args, mode="success", dry_run=False):
        env = self.env.copy()
        env["FAKE_MODE"] = mode
        if mode in (
            "preflight_hang", "preflight_startup_delay", "measurement_hang"
        ):
            env.update(self.test_timing_env)
        if dry_run:
            env["DRY_RUN"] = "1"
        return subprocess.run(
            [str(RUNNER), *args, f"--bench-noise={self.fake}"],
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
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
            candidates = json.loads((shard / "candidates.json").read_text())
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
        self.assertEqual(data["status_code"], "TIMEOUT")
        self.assertTrue(data["term_sent"])
        self.assertTrue(data["kill_sent"])
        self.assertLess(data["elapsed_ms"], 500)
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
        profile = json.loads(
            (result_root / "profiles" / "sensitivity64" /
             "profile_manifest.json").read_text())
        self.assertEqual(profile["profile_verdict"], "FAIL_INCOMPLETE")

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


if __name__ == "__main__":
    unittest.main()
