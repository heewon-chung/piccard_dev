import csv
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class SanitizerRunnerForwardingTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.project = self.root / "project"
        self.scripts = self.project / "scripts"
        self.fake_bin = self.root / "fake-bin"
        self.side_effect_log = self.root / "side-effects.log"
        self.scripts.mkdir(parents=True)
        self.fake_bin.mkdir()

        for name in ("run_benchmarks.sh", "run_core_benchmarks.sh"):
            shutil.copy2(REPO_ROOT / "scripts" / name, self.scripts / name)

        for command in ("cmake", "mkdir", "ln", "tee"):
            fake = self.fake_bin / command
            fake.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' {command!r} >> "
                f"{str(self.side_effect_log)!r}\n"
                "exit 97\n",
                encoding="utf-8",
            )
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        self.tempdir.cleanup()

    def run_script(self, name, args=None):
        results_root = self.root / f"{name}-results"
        env = os.environ.copy()
        env.update(
            {
                "DRY_RUN": "1",
                "BENCH_RESULTS_ROOT": str(results_root),
                "PATH": f"{self.fake_bin}{os.pathsep}{env['PATH']}",
            }
        )
        if args is None:
            args = [
                "--quick",
                "--transcript_stat_bits=64",
                "--max_queries=17",
            ]
        completed = subprocess.run(
            [str(self.scripts / name), *args],
            cwd=self.project,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        return completed, results_root

    def assert_no_side_effects(self, results_root):
        self.assertFalse(
            self.side_effect_log.exists(),
            self.side_effect_log.read_text(encoding="utf-8")
            if self.side_effect_log.exists()
            else "",
        )
        self.assertFalse(results_root.exists())
        self.assertFalse((self.project / "build").exists())
        self.assertFalse((self.project / "scripts" / "results").exists())

    def test_full_runner_forwards_profile_to_complete_command_matrix(self):
        completed, results_root = self.run_script("run_benchmarks.sh")
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assert_no_side_effects(results_root)

        profile = "--transcript_stat_bits=64 --max_queries=17"
        expected = [
            "bench_piccard --mode=timing --security=TOY --trials=2 "
            f"--set_size=1000 {profile}",
            "bench_piccard --mode=accuracy --security=TOY --trials=5 "
            f"--set_size=1000 {profile}",
            "bench_piccard --mode=combined --security=TOY --trials=2 "
            "--accuracy_trials=5 --overlap=0.3 --set_size=1000 "
            f"{profile}",
            "bench_comparison --mode=timing --security=TOY --trials=2 "
            f"--set_size=1000 --accuracy_trials=5 {profile}",
            "bench_dynamic --mode=timing --security=TOY --trials=2 "
            "--set_size=1000 --depth=5 "
            f"{profile}",
            "bench_dynamic --mode=accuracy --security=TOY --trials=5 "
            "--set_size=1000 --depth=5 "
            f"{profile}",
            "bench_threshold --mode=timing --security=TOY --trials=2 "
            "--set_size=1000",
            "bench_threshold --mode=accuracy --security=TOY --trials=5 "
            "--set_size=1000",
            "bench_threshold --mode=spec --security=TOY",
        ]
        planned = [
            line.strip()
            for line in completed.stdout.splitlines()
            if line.startswith("  bench_")
        ]
        self.assertEqual(planned, expected)
        threshold_runner = [
            line.strip()
            for line in completed.stdout.splitlines()
            if "run_threshold_fpfn_grid.py" in line
        ]
        self.assertEqual(len(threshold_runner), 1)
        self.assertIn("--profile readiness-toy-v1", threshold_runner[0])
        self.assertIn("--security TOY", threshold_runner[0])
        self.assertIn("--seed 20260729", threshold_runner[0])
        self.assertIn("--trials 1", threshold_runner[0])
        for line in planned[:6]:
            self.assertIn(profile, line)
        for line in planned[6:]:
            self.assertNotIn("--transcript_stat_bits", line)
            self.assertNotIn("--max_queries", line)

    def test_full_runner_default_profile_has_no_empty_array_abort(self):
        completed, results_root = self.run_script(
            "run_benchmarks.sh", args=[]
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assert_no_side_effects(results_root)
        planned = [
            line.strip()
            for line in completed.stdout.splitlines()
            if line.startswith("  bench_")
        ]
        self.assertEqual(len(planned), 9)
        self.assertNotIn("--depth=5", "\n".join(planned))
        for line in planned[:6]:
            self.assertIn("--transcript_stat_bits=40", line)
            self.assertIn("--max_queries=1048576", line)

    def test_core_runner_forwards_profile_without_filesystem_effects(self):
        completed, results_root = self.run_script("run_core_benchmarks.sh")
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assert_no_side_effects(results_root)

    def test_non_dry_threshold_wrapper_keeps_grid_csv_separate_from_log(self):
        """Exercise the real shell wrapper with fake children, never a benchmark.

        The threshold orchestrator owns its CSV path.  The shell wrapper must
        capture only the orchestrator's receipt/log stream, otherwise shell
        redirection creates the CSV before the orchestrator can write it.
        """
        project = self.root / "non-dry-project"
        scripts = project / "scripts"
        build = project / "build"
        scripts.mkdir(parents=True)
        build.mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "scripts" / "run_benchmarks.sh", scripts / "run_benchmarks.sh")
        for name in ("run_threshold_fpfn_grid.py", "verify_threshold_outputs.py"):
            shutil.copy2(REPO_ROOT / "scripts" / name, scripts / name)

        # The first six producers are deliberately inert shell fakes.  The
        # threshold fake emits one structurally valid receipt only when the
        # orchestrator supplies a selected point; no benchmark code runs.
        inert = "#!/usr/bin/env bash\nexit 0\n"
        for name in ("bench_piccard", "bench_comparison"):
            path = build / name
            path.write_text(inert, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        threshold = build / "bench_threshold"
        threshold.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "args={}\n"
            "for item in sys.argv[1:]:\n"
            "  if item.startswith('--') and '=' in item:\n"
            "    key,value=item[2:].split('=',1); args[key]=value\n"
            "if 'point-k' not in args: raise SystemExit(0)\n"
            "print('schema_version,profile,security,estimator_model,hash_randomness,root_seed,k,m,set_size,tau_count,j_tau,grid_index,target_j,signed_delta,absolute_delta,alpha,realized_intersection,realized_union,realized_j,trial_index,row_seed,match_count,decision,exact_j_truth,outcome,predicted_decision_probability,predicted_error_probability,gaussian_error_approx')\n"
            "print('piccard-threshold-fpfn-v1,%s,%s,sha256-random-ranking-poc-v1,resampled,%s,%s,64,1000,1,0.5,%s,0.5,0,0,0.6,1000,1000,1,0,1,1,1,1,TP,0.5,0.5,0.5' % (args['profile'],args['security'],args['seed'],args['point-k'],args['grid-index']))\n",
            encoding="utf-8",
        )
        threshold.chmod(threshold.stat().st_mode | stat.S_IXUSR)

        results_root = self.root / "non-dry-results"
        env = os.environ.copy()
        env.update({"BENCH_RESULTS_ROOT": str(results_root), "DRY_RUN": "0"})
        completed = subprocess.run(
            [str(scripts / "run_benchmarks.sh"), "--quick"],
            cwd=project,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        # Exclude the runner's `latest` symlink; assert against the concrete
        # timestamped run directory so the artifact count is unambiguous.
        outputs = list(results_root.glob("*_quick/csv/threshold_fpfn_TOY.csv"))
        self.assertEqual(len(outputs), 1)
        with outputs[0].open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 84)
        logs = list(results_root.glob("*_quick/csv/threshold_fpfn_TOY.log"))
        self.assertEqual(len(logs), 1)
        self.assertNotEqual(outputs[0], logs[0])
