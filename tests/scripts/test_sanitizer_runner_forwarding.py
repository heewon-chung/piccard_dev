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
            "bench_threshold --mode=fpfn --security=TOY --trials=50 "
            "--set_size=1000",
            "bench_threshold --mode=spec --security=TOY",
        ]
        planned = [
            line.strip()
            for line in completed.stdout.splitlines()
            if line.startswith("  bench_")
        ]
        self.assertEqual(planned, expected)
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
        self.assertEqual(len(planned), 10)
        self.assertNotIn("--depth=5", "\n".join(planned))
        for line in planned[:6]:
            self.assertIn("--transcript_stat_bits=40", line)
            self.assertIn("--max_queries=1048576", line)

    def test_core_runner_forwards_profile_without_filesystem_effects(self):
        completed, results_root = self.run_script("run_core_benchmarks.sh")
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
            f"--set_size=1000 {profile}",
        ]
        planned = [
            line.strip()
            for line in completed.stdout.splitlines()
            if line.startswith("  bench_")
        ]
        self.assertEqual(planned, expected)
