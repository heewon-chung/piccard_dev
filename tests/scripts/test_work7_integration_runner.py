"""Hermetic behavior coverage for the Work 7 Phase 2 runner."""

import shutil
import tempfile
import unittest
from pathlib import Path


class Work7IntegrationRunnerTests(unittest.TestCase):
    fixtures = Path(__file__).parents[1] / "fixtures" / "work7" / "runner"

    def fake_root(self, fixture: str) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        shutil.copy(self.fixtures / fixture, Path(temporary.name) / fixture)
        return temporary

    def test_frozen_registry_contains_every_required_ctest_once(self):
        from scripts.run_work7_integration import FROZEN_CTESTS

        self.assertEqual(len(FROZEN_CTESTS), len(set(FROZEN_CTESTS)))
        self.assertIn("EstimatorDiagnostic", FROZEN_CTESTS)
        self.assertIn("Work7IntegrationRunner", FROZEN_CTESTS)

    def test_rejects_repeated_measured_count_in_fake_artifact(self):
        from scripts.run_work7_integration import Failure, validate_records

        with self.fake_root("repeated-count.csv") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(Failure, "measured count"):
                validate_records(root)

    def test_rejects_multiple_or_analytic_warmups_in_fake_artifact(self):
        from scripts.run_work7_integration import Failure, validate_records

        with self.fake_root("analytic-warmup.json") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(Failure, "warmup"):
                validate_records(root)

    def test_rejects_actual_data_path_in_fake_artifact(self):
        from scripts.run_work7_integration import Failure, validate_records

        with self.fake_root("actual-data.json") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(Failure, "actual-data"):
                validate_records(root)


if __name__ == "__main__":
    unittest.main()
