#!/usr/bin/env python3
"""Behavior tests for the pre-threshold-only benchmark runner."""

from __future__ import annotations

import csv
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_pre_threshold_profiles.sh"
TOY_EVIDENCE = ROOT / ".omo" / "evidence"

SCHEMA_BY_PRODUCER = {
    "bench_piccard": "benchmark",
    "bench_onehot_sqrt": "benchmark",
    "bench_dynamic": "dynamic",
    "bench_review_comparison": "review",
}


def make_executable(path: pathlib.Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class PreThresholdRunnerTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = pathlib.Path(self.temp.name)

    def run_command(self, command, *, cwd=None, env=None):
        merged = os.environ.copy()
        if env:
            merged.update(env)
        return subprocess.run(
            command,
            cwd=cwd or ROOT,
            env=merged,
            text=True,
            capture_output=True,
            check=False,
        )

    def dry_run(self, suite: str, *, seed: int, threads: int = 8,
                build_dir: pathlib.Path | None = None,
                results_root: pathlib.Path | None = None):
        build_dir = build_dir or self.tmp / "missing-build"
        command = [
            str(RUNNER), f"--suite={suite}", f"--seed={seed}",
            f"--threads={threads}", f"--build-dir={build_dir}",
            "--dry-run",
        ]
        if results_root is not None:
            command.append(f"--results-root={results_root}")
        return self.run_command(command)

    def test_primary_dry_run_pins_exact_matrix_and_has_no_side_effects(self):
        build_dir = self.tmp / "never-created-build"
        results_root = self.tmp / "never-created-results"
        result = self.dry_run(
            "primary", seed=20260729, threads=8,
            build_dir=build_dir, results_root=results_root,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(build_dir.exists())
        self.assertFalse(results_root.exists())
        lines = [line for line in result.stdout.splitlines()
                 if line.startswith("RUN ")]
        expected_commands = [
            "bench_piccard --profile=std128-t40-primary --security=STD128 --mode=combined --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --trials=30 --accuracy_trials=50 --seed=20260729",
            "bench_onehot_sqrt --profile=std128-t40-primary --security=STD128 --mode=timing --k=128 --m=64 --set_size=1000 --trials=30 --seed=20260729",
            "bench_onehot_sqrt --profile=std128-t40-primary --security=STD128 --mode=accuracy --k=128 --m=64 --set_size=1000 --accuracy_trials=50 --seed=20260729",
            "bench_dynamic --profile=std128-t40-primary --security=STD128 --mode=timing --k=128 --m=64 --set_size=1000 --depth=5 --trials=30 --seed=20260729",
            "bench_piccard --profile=std192-t40-primary --security=STD192 --mode=combined --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --trials=30 --accuracy_trials=50 --seed=20260729",
            "bench_onehot_sqrt --profile=std192-t40-primary --security=STD192 --mode=timing --k=128 --m=64 --set_size=1000 --trials=30 --seed=20260729",
            "bench_onehot_sqrt --profile=std192-t40-primary --security=STD192 --mode=accuracy --k=128 --m=64 --set_size=1000 --accuracy_trials=50 --seed=20260729",
            "bench_dynamic --profile=std192-t40-primary --security=STD192 --mode=timing --k=128 --m=64 --set_size=1000 --depth=5 --trials=30 --seed=20260729",
            "bench_review_comparison --suite=primary-review --profile=std128-t40-primary --security=STD128 --k=128 --m=64 --set-size=1000 --universe=16384 --target-jaccard=0.5 --trials=30 --accuracy-trials=50 --seed=20260729 --methods=piccard,piccard_sqrt,bcg12_mh_ff,bcg12_mh_ec,bcg12_exact_ff,bcg12_exact_ec,sj16 --sj16-key-bits=3072 --execution-trace-out=<results-root>/traces/<cell_id>.bin --strict-security --manifest-out=<results-root>/workloads/<cell_id>.bin",
            "bench_review_comparison --suite=primary-review --profile=std128-t40-primary --security=STD128 --k=128 --m=64 --set-size=1000 --universe=65536 --target-jaccard=0.5 --trials=30 --accuracy-trials=50 --seed=20260729 --methods=piccard,piccard_sqrt,bcg12_mh_ff,bcg12_mh_ec,bcg12_exact_ff,bcg12_exact_ec,sj16 --sj16-key-bits=3072 --execution-trace-out=<results-root>/traces/<cell_id>.bin --strict-security --manifest-out=<results-root>/workloads/<cell_id>.bin",
        ]
        self.assertEqual(
            lines,
            [f"RUN OMP_NUM_THREADS=8 OMP_DYNAMIC=FALSE {command}"
             for command in expected_commands],
        )
        self.assertNotIn("bench_threshold", result.stdout)
        self.assertIn("GATE source commit/cleanliness", result.stdout)
        self.assertIn("GATE embedded Release build provenance and binary SHA-256", result.stdout)
        self.assertIn("VERIFY verify_benchmark_provenance.py --schema=benchmark --run-manifest=<results-root>/manifest.json", result.stdout)
        self.assertIn("VERIFY verify_benchmark_provenance.py --schema=dynamic --run-manifest=<results-root>/manifest.json", result.stdout)
        self.assertIn("VERIFY verify_benchmark_provenance.py --schema=review --run-manifest=<results-root>/manifest.json", result.stdout)
        self.assertIn("VERIFY verify_review_comparison.py --run-manifest=<results-root>/manifest.json", result.stdout)

    def test_sensitivity_feasibility_and_smoke_matrix_is_frozen(self):
        sensitivity = self.dry_run("sensitivity", seed=20260729)
        self.assertEqual(sensitivity.returncode, 0, sensitivity.stderr)
        sensitivity_runs = [line for line in sensitivity.stdout.splitlines()
                            if line.startswith("RUN ")]
        sensitivity_commands = [
            "bench_piccard --profile=std128-t64-sensitivity --security=STD128 --mode=timing --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --trials=3 --seed=20260729",
            "bench_piccard --profile=std128-t64-sensitivity --security=STD128 --mode=accuracy --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --accuracy_trials=30 --seed=20260729",
            "bench_onehot_sqrt --profile=std128-t64-sensitivity --security=STD128 --mode=timing --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --trials=3 --seed=20260729",
            "bench_onehot_sqrt --profile=std128-t64-sensitivity --security=STD128 --mode=accuracy --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --accuracy_trials=30 --seed=20260729",
            "bench_dynamic --profile=std128-t64-sensitivity --security=STD128 --mode=timing --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --depth=5 --trials=3 --seed=20260729",
            "bench_piccard --profile=std192-t64-sensitivity --security=STD192 --mode=timing --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --trials=3 --seed=20260729",
            "bench_piccard --profile=std192-t64-sensitivity --security=STD192 --mode=accuracy --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --accuracy_trials=30 --seed=20260729",
            "bench_onehot_sqrt --profile=std192-t64-sensitivity --security=STD192 --mode=timing --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --trials=3 --seed=20260729",
            "bench_onehot_sqrt --profile=std192-t64-sensitivity --security=STD192 --mode=accuracy --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --accuracy_trials=30 --seed=20260729",
            "bench_dynamic --profile=std192-t64-sensitivity --security=STD192 --mode=timing --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --depth=5 --trials=3 --seed=20260729",
            "bench_review_comparison --suite=sj16-precompute-sensitivity --profile=std128-t64-sensitivity --security=STD128 --k=128 --m=64 --set-size=1000 --universe=16384 --target-jaccard=0.5 --trials=3 --accuracy-trials=0 --seed=20260729 --methods=sj16,sj16_precomputed --sj16-key-bits=3072 --execution-trace-out=<results-root>/traces/<cell_id>.bin --diagnostic-security --manifest-out=<results-root>/workloads/<cell_id>.bin",
            "bench_review_comparison --suite=sj16-precompute-sensitivity --profile=std128-t64-sensitivity --security=STD128 --k=128 --m=64 --set-size=1000 --universe=65536 --target-jaccard=0.5 --trials=3 --accuracy-trials=0 --seed=20260729 --methods=sj16,sj16_precomputed --sj16-key-bits=3072 --execution-trace-out=<results-root>/traces/<cell_id>.bin --diagnostic-security --manifest-out=<results-root>/workloads/<cell_id>.bin",
        ]
        self.assertEqual(
            sensitivity_runs,
            [f"RUN OMP_NUM_THREADS=8 OMP_DYNAMIC=FALSE {command}"
             for command in sensitivity_commands],
        )
        for line in sensitivity_runs:
            if "bench_review_comparison" not in line:
                self.assertIn(" --evidence_point ", line)
        self.assertEqual(sum("--suite=sj16-precompute-sensitivity" in line
                             for line in sensitivity_runs), 2)
        self.assertNotIn("bench_threshold", sensitivity.stdout)

        feasibility = self.dry_run("feasibility", seed=20260729)
        self.assertEqual(feasibility.returncode, 0, feasibility.stderr)
        feasibility_runs = [line for line in feasibility.stdout.splitlines()
                            if line.startswith("RUN ")]
        feasibility_commands = [
            "bench_piccard --profile=std128-t128-feasibility --security=STD128 --mode=timing --evidence_point --k=128 --m=64 --set_size=100 --target-jaccard=0.5 --trials=1 --seed=20260729",
            "bench_piccard --profile=std128-t128-feasibility --security=STD128 --mode=accuracy --evidence_point --k=128 --m=64 --set_size=100 --target-jaccard=0.5 --accuracy_trials=2 --seed=20260729",
            "bench_piccard --profile=std192-t128-feasibility --security=STD192 --mode=timing --evidence_point --k=128 --m=64 --set_size=100 --target-jaccard=0.5 --trials=1 --seed=20260729",
            "bench_piccard --profile=std192-t128-feasibility --security=STD192 --mode=accuracy --evidence_point --k=128 --m=64 --set_size=100 --target-jaccard=0.5 --accuracy_trials=2 --seed=20260729",
        ]
        self.assertEqual(
            feasibility_runs,
            [f"RUN OMP_NUM_THREADS=8 OMP_DYNAMIC=FALSE {command}"
             for command in feasibility_commands],
        )
        self.assertTrue(all(" --evidence_point " in line
                            for line in feasibility_runs))
        self.assertTrue(all("--set_size=100" in line
                            for line in feasibility_runs))
        self.assertIn("comparison-ineligible", feasibility.stdout)

        smoke = self.dry_run("smoke", seed=7, threads=2)
        self.assertEqual(smoke.returncode, 0, smoke.stderr)
        smoke_runs = [line for line in smoke.stdout.splitlines()
                      if line.startswith("RUN ")]
        self.assertEqual(smoke_runs, [
            "RUN OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE bench_review_comparison --suite=toy-smoke --profile=toy-smoke --k=16 --m=16 --set-size=10 --universe=64 --target-jaccard=0.5 --trials=1 --accuracy-trials=1 --seed=7 --methods=piccard,piccard_sqrt,bcg12_mh_ec,bcg12_exact_ec,sj16 --sj16-key-bits=1024 --allow-unmatched-security --manifest-out=<results-root>/workloads/<cell_id>.bin --execution-trace-out=<results-root>/traces/<cell_id>.bin",
            "RUN OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE bench_piccard --profile=toy-smoke --security=TOY --mode=timing --evidence_point --k=16 --m=16 --set_size=10 --target-jaccard=0.5 --trials=1 --seed=7",
            "RUN OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE bench_dynamic --scenario=refresh --refresh_updates=1 --profile=toy-smoke --security=TOY --mode=timing --evidence_point --k=16 --m=16 --set_size=100 --target-jaccard=0.5 --depth=5 --trials=1 --seed=7",
        ])

    def test_non_dry_run_rejects_relative_and_existing_roots(self):
        relative = self.run_command([
            str(RUNNER), "--suite=smoke", "--seed=7", "--threads=2",
            f"--build-dir={self.tmp / 'build'}", "--results-root=relative",
        ])
        self.assertEqual(relative.returncode, 2)
        self.assertIn("absolute --results-root", relative.stderr)

        relative_build = self.run_command([
            str(RUNNER), "--suite=smoke", "--seed=7", "--threads=2",
            "--build-dir=relative", f"--results-root={self.tmp / 'new'}",
        ])
        self.assertEqual(relative_build.returncode, 2)
        self.assertIn("absolute --build-dir", relative_build.stderr)

        existing = self.tmp / "existing"
        existing.mkdir()
        build = self.tmp / "build"
        build.mkdir()
        reused = self.run_command([
            str(RUNNER), "--suite=smoke", "--seed=7", "--threads=2",
            f"--build-dir={build}", f"--results-root={existing}",
        ])
        self.assertEqual(reused.returncode, 2)
        self.assertIn("already exists", reused.stderr)

    def make_harness(self):
        project = self.tmp / "project"
        scripts = project / "scripts"
        scripts.mkdir(parents=True)
        shutil.copy2(RUNNER, scripts / RUNNER.name)
        for name in (
            "verify_benchmark_provenance.py",
            "verify_review_comparison.py",
            "verify_sj16_extrapolation.py",
        ):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        evidence = project / ".omo" / "evidence"
        evidence.mkdir(parents=True)
        for name in (
            "work4-phase4-toy-results.csv",
            "work4-phase4-toy-workload.bin",
            "work4-phase4-toy-trace.bin",
        ):
            shutil.copy2(TOY_EVIDENCE / name, evidence / name)
        (project / ".gitignore").write_text("build/\nresults/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=project, check=True)
        subprocess.run(["git", "config", "user.email", "runner@test.invalid"], cwd=project, check=True)
        subprocess.run(["git", "config", "user.name", "Runner Test"], cwd=project, check=True)
        subprocess.run(["git", "add", "."], cwd=project, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=project, check=True)
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=project, text=True).strip()

        build = self.tmp / "build"
        build.mkdir()
        (build / "CMakeCache.txt").write_text(
            "CMAKE_BUILD_TYPE:STRING=Release\n", encoding="utf-8")
        fake = """
            #!/usr/bin/env python3
            import json, os, pathlib, shutil, sys

            args = sys.argv[1:]
            if args == ["--print-build-provenance"]:
                print(json.dumps({
                    "schema": "piccard-build-provenance-v1",
                    "commit": os.environ["FAKE_COMMIT"],
                    "dirty": os.environ.get("FAKE_DIRTY", "0") == "1",
                    "build_type": os.environ.get("FAKE_BUILD_TYPE", "Release"),
                    "source_dir": os.environ["FAKE_SOURCE_DIR"],
                }, sort_keys=True))
                raise SystemExit(0)
            with open(os.environ["FAKE_RUN_LOG"], "a", encoding="utf-8") as log:
                log.write(json.dumps([pathlib.Path(sys.argv[0]).name, *args]) + "\\n")
            if os.environ.get("FAIL_STD192") == "1" and "--security=STD192" in args:
                print("missing sanitizer calibration for STD192", file=sys.stderr)
                raise SystemExit(2)
            feasibility_failure = os.environ.get("FAIL_FEASIBILITY")
            if feasibility_failure and any("t128-feasibility" in arg for arg in args):
                required = "130" if feasibility_failure == "capacity" else "90"
                print(
                    "bench_piccard: infeasible sanitizer calibration for fixture: "
                    "transcript target 128, query cap 1048576, query adjustment 20, "
                    "coefficient adjustment 14, coefficient target 162, margin 8, "
                    "eval noise 56, required capacity " + required +
                    ", available log2(q/t) 95.75",
                    file=sys.stderr,
                )
                raise SystemExit(2)
            evidence = pathlib.Path(os.environ["FAKE_EVIDENCE"])
            fixtures = pathlib.Path(os.environ["FAKE_FIXTURES"])
            if pathlib.Path(sys.argv[0]).name == "bench_review_comparison":
                manifest = pathlib.Path(next(a.split("=", 1)[1] for a in args if a.startswith("--manifest-out=")))
                trace = pathlib.Path(next(a.split("=", 1)[1] for a in args if a.startswith("--execution-trace-out=")))
                shutil.copyfile(evidence / "work4-phase4-toy-workload.bin", manifest)
                shutil.copyfile(evidence / "work4-phase4-toy-trace.bin", trace)
                sys.stdout.write((evidence / "work4-phase4-toy-results.csv").read_text())
            else:
                name = pathlib.Path(sys.argv[0]).name
                fixture = "dynamic_toy_rows.csv" if name == "bench_dynamic" \\
                    else "benchmark_toy_rows.csv"
                lines = (fixtures / fixture).read_text().splitlines(True)
                timing_row, accuracy_row = ((lines[2] if "--scenario=refresh" in args else lines[1]), lines[1]) if name == "bench_dynamic" \\
                    else (lines[1], lines[2])
                mode = next(a.split("=", 1)[1] for a in args if a.startswith("--mode="))
                if "--evidence_point" in args:
                    rows = {"bench_onehot_sqrt": 2}.get(name, 1) * \\
                        [timing_row if mode == "timing" else accuracy_row]
                elif name == "bench_piccard":            # --mode=combined
                    rows = [timing_row] * 15 + [accuracy_row] * 15
                elif name == "bench_dynamic":
                    rows = [timing_row] * 15
                else:                                    # bench_onehot_sqrt native grids
                    rows = [timing_row] * 28 if mode == "timing" else [accuracy_row] * 22
                sys.stdout.write(lines[0] + "".join(rows))
        """
        for name in ("bench_piccard", "bench_onehot_sqrt", "bench_dynamic",
                     "bench_review_comparison"):
            make_executable(build / name, fake)
        log = self.tmp / "invocations.jsonl"
        env = {
            "FAKE_COMMIT": commit,
            "FAKE_SOURCE_DIR": str(project.resolve()),
            "FAKE_RUN_LOG": str(log),
            "FAKE_EVIDENCE": str(evidence),
            "FAKE_FIXTURES": str(ROOT / "tests" / "fixtures" / "runner"),
        }
        return project, build, log, env

    def run_smoke(self, project, build, results, env, *extra):
        return self.run_command([
            str(project / "scripts" / RUNNER.name),
            "--suite=smoke", "--seed=7", "--threads=2",
            f"--build-dir={build}", f"--results-root={results}", *extra,
        ], cwd=project, env=env)

    def run_feasibility(self, project, build, results, env, *extra):
        return self.run_command([
            str(project / "scripts" / RUNNER.name),
            "--suite=feasibility", "--seed=20260729", "--threads=2",
            f"--build-dir={build}", f"--results-root={results}", *extra,
        ], cwd=project, env=env)

    def test_fake_smoke_writes_exact_layout_manifest_and_terminal_cells(self):
        project, build, log, env = self.make_harness()
        results = self.tmp / "results"
        result = self.run_smoke(project, build, results, env)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(
            sorted(path.name for path in results.iterdir()),
            ["csv", "logs", "manifest.json", "terminal-cells.tsv", "traces", "workloads"],
        )
        manifest = json.loads((results / "manifest.json").read_text())
        self.assertEqual(manifest["schema"], "piccard-pre-threshold-run-v1")
        self.assertEqual(manifest["suite"], "smoke")
        self.assertEqual(manifest["seed"], 7)
        self.assertEqual(manifest["thread_policy"], {
            "OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "2"})
        self.assertEqual(manifest["source"]["commit"], env["FAKE_COMMIT"])
        self.assertFalse(manifest["source"]["dirty"])
        self.assertEqual(manifest["build"]["type"], "Release")
        self.assertEqual(len(manifest["cells"]), 3)
        self.assertTrue(all(cell["status"] == "MEASURED"
                            for cell in manifest["cells"]))
        self.assertTrue(all(cell["output"]["csv_sha256"]
                            for cell in manifest["cells"]))
        self.assertEqual(
            [cell["output"]["expected_csv_rows"] for cell in manifest["cells"]],
            [10, 1, 1],
        )
        self.assertEqual(
            [cell["output"]["csv_row_count"] for cell in manifest["cells"]],
            [10, 1, 1],
        )
        self.assertIn("cpu", manifest["machine"])
        self.assertIn("ram", manifest["machine"])
        self.assertIn("os", manifest["machine"])
        self.assertIn("compiler", manifest["machine"])
        self.assertIn("libraries", manifest["machine"])
        terminal = (results / "terminal-cells.tsv").read_text()
        self.assertTrue(terminal.startswith(
            "schema_version\tcell_id\tprofile_id\tproducer\tparameter_sha256\tstatus\treason_code\trequired_bits\tavailable_bits\tshortfall_bits\tlog_sha256\n"))
        self.assertEqual(len(terminal.splitlines()), 4)
        self.assertIn("verify_benchmark_provenance", result.stdout)
        self.assertIn("verify_review_comparison", result.stdout)
        invocations = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(len(invocations), 3)
        self.assertTrue(all("--evidence_point" not in row or row[0] in {"bench_piccard", "bench_dynamic"}
                            for row in invocations))
        refresh_cell = next(cell for cell in manifest["cells"]
                            if cell["producer"] == "bench_dynamic")
        with (results / refresh_cell["output"]["csv"]).open(newline="") as stream:
            refresh_rows = list(csv.DictReader(stream))
        self.assertEqual(len(refresh_rows), 1)
        self.assertEqual(refresh_rows[0]["label"], "refresh_owner_a_0_to_1")
        self.assertEqual(refresh_rows[0]["dynamic_scenario"], "refresh")
        self.assertEqual(refresh_rows[0]["set_size"], "100")
        for cell in manifest["cells"]:
            for field in ("csv", "log"):
                resolved = (results / cell["output"][field]).resolve()
                self.assertTrue(resolved.is_relative_to(results.resolve()))

    def test_resume_validates_identity_hashes_argv_and_path_containment(self):
        project, build, log, env = self.make_harness()
        results = self.tmp / "results"
        first = self.run_smoke(project, build, results, env)
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        before = log.read_text()
        resumed = self.run_smoke(project, build, results, env, "--resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr + resumed.stdout)
        self.assertEqual(log.read_text(), before)
        self.assertIn("RESUME skip", resumed.stdout)
        self.assertIn("VERIFY verify_benchmark_provenance", resumed.stdout)
        self.assertIn("VERIFY verify_review_comparison", resumed.stdout)

        mutations = (
            ("binary hash mismatch", lambda data: data["build"]["binaries"]["bench_piccard"].update(sha256="0" * 64)),
            ("argv mismatch", lambda data: data["cells"][0]["argv"].append("--tampered")),
            ("escapes results root", lambda data: data["cells"][0]["output"].update(csv="../escape.csv")),
            ("output hash mismatch", lambda data: data["cells"][0]["output"].update(csv_sha256="0" * 64)),
        )
        original = (results / "manifest.json").read_text()
        for cause, mutate in mutations:
            with self.subTest(cause=cause):
                data = json.loads(original)
                mutate(data)
                (results / "manifest.json").write_text(
                    json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
                rejected = self.run_smoke(project, build, results, env, "--resume")
                self.assertEqual(rejected.returncode, 2, rejected.stdout)
                self.assertIn(cause, rejected.stderr)
                (results / "manifest.json").write_text(original)

    def test_review_fixture_replay_in_piccard_producer_fails_closed(self):
        """A bench_piccard fake that masks as the review fixture must be caught.

        This pins that --schema=benchmark rejects review-shaped rows even
        when the row count happens to match: a wrong-schema fixture can no
        longer pass as bench_piccard evidence.
        """
        project, build, log, env = self.make_harness()
        masked = """
            #!/usr/bin/env python3
            import json, os, pathlib, sys

            args = sys.argv[1:]
            if args == ["--print-build-provenance"]:
                print(json.dumps({
                    "schema": "piccard-build-provenance-v1",
                    "commit": os.environ["FAKE_COMMIT"],
                    "dirty": os.environ.get("FAKE_DIRTY", "0") == "1",
                    "build_type": os.environ.get("FAKE_BUILD_TYPE", "Release"),
                    "source_dir": os.environ["FAKE_SOURCE_DIR"],
                }, sort_keys=True))
                raise SystemExit(0)
            with open(os.environ["FAKE_RUN_LOG"], "a", encoding="utf-8") as log:
                log.write(json.dumps([pathlib.Path(sys.argv[0]).name, *args]) + "\\n")
            evidence = pathlib.Path(os.environ["FAKE_EVIDENCE"])
            lines = (evidence / "work4-phase4-toy-results.csv").read_text().splitlines(True)
            sys.stdout.write(lines[0] + lines[1])
        """
        make_executable(build / "bench_piccard", masked)
        results = self.tmp / "results-masked-piccard"
        result = self.run_smoke(project, build, results, env)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("verify_benchmark_provenance", result.stderr + result.stdout)

    def test_build_provenance_and_primary_missing_calibration_fail_closed(self):
        project, build, _, env = self.make_harness()
        results = self.tmp / "results-commit"
        bad_commit = dict(env, FAKE_COMMIT="0" * 40)
        mismatch = self.run_smoke(project, build, results, bad_commit)
        self.assertEqual(mismatch.returncode, 2)
        self.assertIn("embedded commit", mismatch.stderr)

        results = self.tmp / "results-debug"
        debug = dict(env, FAKE_BUILD_TYPE="Debug")
        debug_result = self.run_command([
            str(project / "scripts" / RUNNER.name),
            "--suite=primary", "--seed=20260729", "--threads=8",
            f"--build-dir={build}", f"--results-root={results}",
        ], cwd=project, env=debug)
        self.assertEqual(debug_result.returncode, 2)
        self.assertIn("Release", debug_result.stderr)

        results = self.tmp / "results-missing-calibration"
        failed = self.run_command([
            str(project / "scripts" / RUNNER.name),
            "--suite=primary", "--seed=20260729", "--threads=8",
            f"--build-dir={build}", f"--results-root={results}",
        ], cwd=project, env=dict(env, FAIL_STD192="1"))
        self.assertEqual(failed.returncode, 2)
        self.assertIn("MISSING_CALIBRATION", failed.stderr + failed.stdout)
        manifest = json.loads((results / "manifest.json").read_text())
        self.assertTrue(any(
            cell["profile_id"] == "std192-t40-primary" and
            cell["status"] == "INFEASIBLE" and
            cell["reason_code"] == "MISSING_CALIBRATION"
            for cell in manifest["cells"]
        ))
        blocked_resume = self.run_command([
            str(project / "scripts" / RUNNER.name),
            "--suite=primary", "--seed=20260729", "--threads=8",
            f"--build-dir={build}", f"--results-root={results}", "--resume",
        ], cwd=project, env=dict(env, FAIL_STD192="1"))
        self.assertEqual(blocked_resume.returncode, 2)
        self.assertIn("blocking INFEASIBLE", blocked_resume.stderr)

    def test_capacity_shortfall_uses_real_diagnostic_fields_and_resumes(self):
        project, build, log, env = self.make_harness()
        env = dict(env, FAIL_FEASIBILITY="capacity")
        results = self.tmp / "results-capacity"
        first = self.run_feasibility(project, build, results, env)
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)

        with (results / "terminal-cells.tsv").open(newline="") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["status"], "INFEASIBLE")
            self.assertEqual(row["reason_code"], "CAPACITY_SHORTFALL")
            self.assertEqual(row["required_bits"], "130")
            self.assertEqual(row["available_bits"], "95.75")
            self.assertEqual(row["shortfall_bits"], "34.25")

        manifest = json.loads((results / "manifest.json").read_text())
        for cell in manifest["cells"]:
            self.assertEqual(cell["output"]["measurement_output"],
                             "absent-empty-csv")
            self.assertEqual(cell["output"]["csv_row_count"], 0)
            self.assertEqual(cell["output"]["csv_sha256"],
                             "e3b0c44298fc1c149afbf4c8996fb924"
                             "27ae41e4649b934ca495991b7852b855")

        before = log.read_text()
        resumed = self.run_feasibility(
            project, build, results, env, "--resume")
        self.assertEqual(resumed.returncode, 0,
                         resumed.stderr + resumed.stdout)
        self.assertEqual(log.read_text(), before)
        self.assertEqual(resumed.stdout.count("RESUME skip"), 4)

        original = (results / "manifest.json").read_text()
        mutations = (
            ("inconsistent bit fields",
             lambda data: data["cells"][0].update(shortfall_bits="34.24")),
            ("must have empty bit fields",
             lambda data: data["cells"][0].update(
                 reason_code="MISSING_CALIBRATION")),
            ("infeasible CSV representation mismatch",
             lambda data: data["cells"][0]["output"].update(
                 measurement_output="measured-csv")),
            ("output hash mismatch",
             lambda data: data["cells"][0]["output"].update(
                 log_sha256="0" * 64)),
        )
        for cause, mutate in mutations:
            with self.subTest(cause=cause):
                data = json.loads(original)
                mutate(data)
                (results / "manifest.json").write_text(
                    json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
                rejected = self.run_feasibility(
                    project, build, results, env, "--resume")
                self.assertEqual(rejected.returncode, 2, rejected.stdout)
                self.assertIn(cause, rejected.stderr)
                (results / "manifest.json").write_text(original)

    def test_non_shortfall_capacity_diagnostic_is_process_error(self):
        project, build, _, env = self.make_harness()
        env = dict(env, FAIL_FEASIBILITY="not-shortfall")
        results = self.tmp / "results-not-shortfall"
        result = self.run_feasibility(project, build, results, env)
        self.assertEqual(result.returncode, 2, result.stdout)
        with (results / "terminal-cells.tsv").open(newline="") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "ERROR")
        self.assertEqual(rows[0]["reason_code"], "PROCESS_ERROR")
        self.assertEqual(rows[0]["required_bits"], "")
        self.assertEqual(rows[0]["available_bits"], "")
        self.assertEqual(rows[0]["shortfall_bits"], "")

    def test_verifier_commands_carry_producer_schema(self):
        project, build, log, env = self.make_harness()
        results = self.tmp / "results-schema"
        result = self.run_smoke(project, build, results, env)
        manifest = json.loads((results / "manifest.json").read_text())
        self.assertEqual(len(manifest["cells"]), 3)
        verify_lines = {
            line.split()[-1]: line
            for line in result.stdout.splitlines()
            if line.startswith("VERIFY verify_benchmark_provenance ")
        }
        for cell in manifest["cells"]:
            schema = SCHEMA_BY_PRODUCER[cell["producer"]]
            line = verify_lines[f"--cell-id={cell['cell_id']}"]
            self.assertIn(f"--schema={schema} ", line)

    def test_seed_is_frozen_per_suite(self):
        wrong = self.dry_run("primary", seed=7)
        self.assertEqual(wrong.returncode, 2)
        self.assertIn("requires --seed=20260729", wrong.stderr)
        wrong_smoke = self.dry_run("smoke", seed=20260729)
        self.assertEqual(wrong_smoke.returncode, 2)
        self.assertIn("requires --seed=7", wrong_smoke.stderr)

    def test_evidence_executables_expose_machine_readable_build_provenance(self):
        build = ROOT / "build"
        binaries = [build / name for name in (
            "bench_piccard", "bench_onehot_sqrt", "bench_dynamic",
            "bench_review_comparison",
        )]
        if not all(binary.is_file() for binary in binaries):
            self.skipTest("benchmark executables have not been built")
        expected_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        for binary in binaries:
            with self.subTest(binary=binary.name):
                result = self.run_command([str(binary), "--print-build-provenance"])
                self.assertEqual(result.returncode, 0, result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual(value["schema"], "piccard-build-provenance-v1")
                self.assertEqual(value["commit"], expected_commit)
                self.assertIs(type(value["dirty"]), bool)
                self.assertEqual(value["build_type"], "Release")
                self.assertEqual(pathlib.Path(value["source_dir"]).resolve(), ROOT)


if __name__ == "__main__":
    unittest.main()
