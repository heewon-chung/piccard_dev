"""Pure and no-spawn contract tests for the flooding revision successor."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import revision_flooding_adapter as adapter  # noqa: E402


class FloodingRevisionAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.revision_matrix = adapter.load_revision_matrix(
            REPO / "benchmarks" / "revision_matrix.json")
        cls.noise_matrix = json.loads(
            (REPO / "scripts" / "noise_profiles.json").read_text())

    def cell(self, profile="primary40"):
        return adapter.select_cell(
            self.revision_matrix,
            f"paper-v1::flooding::profile={profile}",
        )

    def test_all_three_paper_profiles_have_one_planner_cell(self):
        for profile in adapter.PROFILE_IDS:
            with self.subTest(profile=profile):
                cell = self.cell(profile)
                plan = adapter.plan_cell(cell, adapter.PAPER_PROFILE)
                self.assertEqual(plan["profile_id"], profile)
                self.assertEqual(plan["repetitions_per_pattern"], 5)
                self.assertEqual(plan["patterns"], list(adapter.PATTERNS))
                self.assertEqual(plan["timing_contract"], "NOT_APPLICABLE")
                self.assertEqual(plan["status"], "DRY_RUN_ONLY")
                self.assertEqual(plan["command"][0], "scripts/run_noise_profiles.sh")
                self.assertIn(
                    f"--revision-cell=paper-v1::flooding::profile={profile}",
                    plan["command"],
                )
                self.assertIn("--repetitions=5", plan["command"])

    def test_toy_is_primary_only_and_one_repetition(self):
        plan = adapter.plan_cell(self.cell(), adapter.TOY_PROFILE)
        self.assertEqual(plan["repetitions_per_pattern"], 1)
        self.assertEqual(plan["status"], "READINESS_ONLY")
        self.assertEqual(plan["environment"]["DRY_RUN"], "0")
        self.assertIn("--repetitions=1", plan["command"])
        with self.assertRaises(adapter.FloodingRevisionError):
            adapter.plan_cell(self.cell("sensitivity64"), adapter.TOY_PROFILE)

    def test_malformed_or_adjacent_cell_fails_closed(self):
        bad = dict(self.cell())
        bad["cell_id"] = "paper-v1::flooding::profile=primary41"
        with self.assertRaises(adapter.FloodingRevisionError):
            adapter.validate_cell(bad)
        with self.assertRaises(adapter.FloodingRevisionError):
            adapter.select_cell(
                self.revision_matrix,
                "paper-v1::flooding::profile=primary41",
            )

    def test_noise_partition_is_exactly_one_canonical_std128_shard(self):
        for profile in adapter.PROFILE_IDS:
            partition = adapter.select_noise_partition(
                self.noise_matrix, profile)
            self.assertEqual(partition["profile_id"], profile)
            self.assertEqual(partition["circuit"], "onehot")
            self.assertEqual(partition["security"], "STD128")
            self.assertEqual(partition["requested_ring_dim"], 8192)
            self.assertIn({"k": 128, "m": 64}, partition["consumer_points"])

    def test_wrapper_paper_cell_is_no_spawn_and_single_shard(self):
        with tempfile.TemporaryDirectory() as temporary:
            result_root = Path(temporary) / "paper"
            result = subprocess.run(
                [
                    str(REPO / "scripts" / "run_noise_profiles.sh"),
                    "--revision-cell=paper-v1::flooding::profile=primary40",
                    "--run-profile=paper-v1",
                    "--profile=primary40",
                    f"--results-root={result_root}",
                    "--repetitions=5",
                ],
                cwd=REPO,
                env={**__import__("os").environ, "DRY_RUN": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.count("SHARD "), 1)
            self.assertIn("repetitions=5", result.stdout)
            self.assertIn("status=DRY_RUN_ONLY", result.stdout)
            self.assertFalse(result_root.exists())

    def test_wrapper_toy_dry_run_is_single_primary_cell_and_one_repetition(self):
        with tempfile.TemporaryDirectory() as temporary:
            result_root = Path(temporary) / "toy"
            result = subprocess.run(
                [
                    str(REPO / "scripts" / "run_noise_profiles.sh"),
                    "--revision-cell=paper-v1::flooding::profile=primary40",
                    "--run-profile=readiness-toy-v1",
                    "--profile=primary40",
                    f"--results-root={result_root}",
                    "--repetitions=1",
                ],
                cwd=REPO,
                env={**__import__("os").environ, "DRY_RUN": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.count("SHARD "), 1)
            self.assertIn("repetitions=1", result.stdout)
            self.assertIn("status=READINESS_ONLY", result.stdout)
            self.assertFalse(result_root.exists())

    def test_profile_only_successor_keeps_paper_profile_fanout_and_toy_primary_topology(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paper = subprocess.run(
                [
                    str(REPO / "scripts" / "run_noise_profiles.sh"),
                    "--run-profile=paper-v1",
                    "--profile=sensitivity64",
                    f"--results-root={root / 'paper'}",
                    "--repetitions=5",
                ],
                cwd=REPO,
                env={**__import__("os").environ, "DRY_RUN": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(paper.returncode, 0, paper.stderr)
            self.assertEqual(paper.stdout.count("SHARD "), 4)
            self.assertNotIn("profile=primary40", paper.stdout)
            self.assertNotIn("profile=feasibility128", paper.stdout)
            self.assertFalse((root / "paper").exists())

            toy = subprocess.run(
                [
                    str(REPO / "scripts" / "run_noise_profiles.sh"),
                    "--run-profile=readiness-toy-v1",
                    "--profile=primary40",
                    f"--results-root={root / 'toy'}",
                    "--repetitions=1",
                ],
                cwd=REPO,
                env={**__import__("os").environ, "DRY_RUN": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(toy.returncode, 0, toy.stderr)
            self.assertEqual(toy.stdout.count("SHARD "), 28)
            self.assertIn("repetitions=1", toy.stdout)
            self.assertNotIn("profile=sensitivity64", toy.stdout)
            self.assertNotIn("profile=feasibility128", toy.stdout)
            self.assertFalse((root / "toy").exists())


if __name__ == "__main__":
    unittest.main()
