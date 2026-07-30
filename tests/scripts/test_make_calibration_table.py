import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "make_calibration_table.py"
FIXTURE = REPO / "tests" / "fixtures" / "calibration_finalized_v1.json"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "make_calibration_table", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalizedCalibrationGeneratorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.fixture_bytes = FIXTURE.read_bytes()
        cls.fixture = json.loads(cls.fixture_bytes)

    def fresh(self):
        return copy.deepcopy(self.fixture)

    def rejects(self, value):
        with self.assertRaises(ValueError):
            self.module.validate_finalized_manifest(value)

    def test_literal_fixture_validates_exhaustively(self):
        validated = self.module.validate_finalized_manifest(self.fresh())
        self.assertEqual(len(validated["keys"]), 34)
        self.assertEqual(
            sum(key["selected_row"] is not None for key in validated["keys"]),
            33,
        )

    def test_rejects_missing_pattern_or_too_few_repetitions(self):
        value = self.fresh()
        value["keys"][0]["selected_row"]["pattern_count"] = 2
        self.rejects(value)
        value = self.fresh()
        value["keys"][0]["selected_row"]["repetitions_per_pattern"] = 4
        self.rejects(value)

    def test_rejects_saturation_or_decrypt_failure_fields(self):
        value = self.fresh()
        value["keys"][0]["selected_row"]["saturated"] = 1
        self.rejects(value)
        value = self.fresh()
        value["keys"][0]["selected_row"]["decrypt_ok"] = 0
        self.rejects(value)

    def test_rejects_profile_security_or_full_key_mismatch(self):
        value = self.fresh()
        value["keys"][0]["security"] = "TOY"
        self.rejects(value)
        value = self.fresh()
        value["keys"][0]["profile_id"] = "not-" + value["keys"][0]["profile_id"]
        self.rejects(value)

    def test_rejects_calibrated_or_realized_dimension_mismatch(self):
        value = self.fresh()
        value["keys"][0]["selected_row"]["ring_dim_calibrated"] = 12288
        self.rejects(value)
        value = self.fresh()
        value["keys"][0]["selected_row"]["natural_ring_dim"] = 4096
        self.rejects(value)

    def test_rejects_stale_source_or_mixed_openfhe(self):
        value = self.fresh()
        value["run"]["source_commit"] = "0" * 40
        self.rejects(value)
        value = self.fresh()
        value["keys"][0]["openfhe_version"] = "stale"
        self.rejects(value)

    def test_rejects_insufficient_transcript_capacity(self):
        value = self.fresh()
        row = value["keys"][0]["selected_row"]
        row["flood_noise_bits"] = 400
        self.rejects(value)

    def test_rejects_missing_required_matrix_keys(self):
        for profile, security in (
            ("primary40", "STD128"),
            ("primary40", "STD192"),
            ("sensitivity64", "STD128"),
        ):
            value = self.fresh()
            index = next(
                i for i, key in enumerate(value["keys"])
                if key["profile_id"] == profile
                and key["security"] == security
            )
            value["keys"].pop(index)
            self.rejects(value)

    def test_rejects_incomplete_feasibility_but_accepts_infeasible(self):
        self.module.validate_finalized_manifest(self.fresh())
        value = self.fresh()
        key = next(
            key for key in value["keys"]
            if key["profile_id"] == "feasibility128"
            and key["infeasibility"] is not None
        )
        key["frontier_verdict"] = "INCOMPLETE"
        self.rejects(value)

    def test_frontier_rejects_equal_cost_conflicts_and_deduplicates_identical(self):
        row = copy.deepcopy(self.fixture["keys"][0]["selected_row"])
        self.assertEqual(
            self.module.select_frontier_candidate([row, copy.deepcopy(row)]),
            row,
        )
        conflict = copy.deepcopy(row)
        conflict["measured_eval_noise_bits"] += 0.25
        with self.assertRaises(ValueError):
            self.module.select_frontier_candidate([row, conflict])

    def test_unknown_extra_and_missing_fields_fail_closed(self):
        value = self.fresh()
        value["extra"] = 1
        self.rejects(value)
        value = self.fresh()
        del value["archive"]["members"]
        self.rejects(value)
        value = self.fresh()
        del value["keys"][0]["selected_row"]["ct_bytes"]
        self.rejects(value)

    def test_shuffled_keys_emit_identical_bytes_and_cost_is_order_independent(self):
        value = self.fresh()
        reversed_value = self.fresh()
        reversed_value["keys"].reverse()
        rows = self.module.render_rows(
            value, hashlib.sha256(self.fixture_bytes).hexdigest())
        reversed_rows = self.module.render_rows(
            reversed_value, hashlib.sha256(self.fixture_bytes).hexdigest())
        self.assertEqual(rows, reversed_rows)
        self.assertEqual(
            self.module.render_summary(value),
            self.module.render_summary(reversed_value),
        )

    def test_measurement_verdicts_and_archive_members_are_coherent(self):
        value = self.fresh()
        primary = next(
            profile for profile in value["profiles"]
            if profile["profile_id"] == "primary40")
        primary["measurement_profile_verdict"] = (
            "PASS_FEASIBILITY_WITH_INFEASIBLE")
        with self.assertRaisesRegex(ValueError, "measurement profile verdict"):
            self.module.validate_finalized_manifest(value)

        value = self.fresh()
        selected = next(
            key for key in value["keys"] if key["selected_row"] is not None)
        selected["measurement_key_verdict"] = "INFEASIBLE"
        with self.assertRaisesRegex(ValueError, "measurement key verdict"):
            self.module.validate_finalized_manifest(value)

        value = self.fresh()
        value["archive"]["members"].pop()
        with self.assertRaisesRegex(ValueError, "archive.*complete"):
            self.module.validate_finalized_manifest(value)

    def test_selected_candidate_is_bound_to_its_archive_detail_member(self):
        value = self.fresh()
        key = next(
            key for key in value["keys"] if key["selected_row"] is not None)
        base = f"profiles/{key['profile_id']}/{key['key_id']}/details/"
        expected = base + key["selected_row"]["candidate_id"] + ".csv"
        index = value["archive"]["members"].index(expected)
        value["archive"]["members"][index] = base + "unrelated-candidate.csv"
        value["archive"]["members"].sort()
        with self.assertRaisesRegex(ValueError, "selected.*detail"):
            self.module.validate_finalized_manifest(value)

    def test_cli_emits_deterministic_rows_and_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = root / "rows.inc"
            summary = root / "CALIBRATION_MATRIX.md"
            args = [
                "python3", str(SCRIPT),
                f"--manifest={FIXTURE}",
                f"--emit-rows={rows}",
                f"--out={summary}",
            ]
            first = subprocess.run(
                args, cwd=REPO, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            first_bytes = (rows.read_bytes(), summary.read_bytes())
            second = subprocess.run(
                args, cwd=REPO, text=True, capture_output=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(
                first_bytes, (rows.read_bytes(), summary.read_bytes()))
            self.assertNotIn(b"TOY", rows.read_bytes())
            self.assertNotIn(b"Threshold", rows.read_bytes())
            self.assertIn(b"INFEASIBLE", summary.read_bytes())

    def test_normative_staged_fragment_is_exact_generator_output(self):
        expected = self.module.render_rows(
            self.fresh(),
            hashlib.sha256(self.fixture_bytes).hexdigest(),
        )
        staged = (
            REPO / "tests" / "fixtures" /
            "noise_calibration_pre_threshold_rows.inc"
        )
        self.assertEqual(staged.read_bytes(), expected)

    def make_artifact_copy(self, root):
        archive_bytes = b"synthetic deterministic archive\n"
        value = self.fresh()
        value["archive"]["archive_sha256"] = hashlib.sha256(
            archive_bytes).hexdigest()
        manifest_bytes = (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        source = root / "source-manifest.json"
        source.write_bytes(manifest_bytes)
        artifact = root / "tracked"
        artifact.mkdir()
        (artifact / "manifest.json").write_bytes(manifest_bytes)
        (artifact / "CALIBRATION_MATRIX.md").write_bytes(
            self.module.render_summary(value))
        (artifact / "selected-shards.tar.zst").write_bytes(archive_bytes)
        names = (
            "manifest.json",
            "CALIBRATION_MATRIX.md",
            "selected-shards.tar.zst",
        )
        checksum = "".join(
            f"{hashlib.sha256((artifact / name).read_bytes()).hexdigest()}"
            f"  {name}\n"
            for name in names
        ).encode()
        (artifact / "tracked-copy.sha256").write_bytes(checksum)
        return source, artifact

    def test_phase5_artifact_copy_verification_accepts_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, artifact = self.make_artifact_copy(Path(temporary))
            self.module.verify_artifact_copy(source, artifact)
            result = subprocess.run(
                [
                    "python3", str(SCRIPT), "--verify-artifact-copy",
                    f"--manifest={source}", f"--artifact-dir={artifact}",
                ],
                cwd=REPO,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_phase5_artifact_copy_rejects_extra_symlink_and_tampering(self):
        mutators = (
            lambda artifact: (artifact / "extra").write_bytes(b"x"),
            lambda artifact: (
                (artifact / "tracked-copy.sha256").unlink(),
                (artifact / "tracked-copy.sha256").symlink_to("manifest.json"),
            ),
            lambda artifact: (artifact / "manifest.json").write_bytes(b"{}\n"),
            lambda artifact: (
                artifact / "CALIBRATION_MATRIX.md"
            ).write_bytes(b"stale\n"),
            lambda artifact: (
                artifact / "selected-shards.tar.zst"
            ).write_bytes(b"changed\n"),
            lambda artifact: (
                artifact / "tracked-copy.sha256"
            ).write_bytes(b"wrong order\n"),
        )
        for mutate in mutators:
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as temporary:
                    source, artifact = self.make_artifact_copy(Path(temporary))
                    mutate(artifact)
                    with self.assertRaises((OSError, ValueError)):
                        self.module.verify_artifact_copy(source, artifact)

    def test_removed_legacy_cli_is_rejected(self):
        result = subprocess.run(
            ["python3", str(SCRIPT), "--dir=legacy"],
            cwd=REPO,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
