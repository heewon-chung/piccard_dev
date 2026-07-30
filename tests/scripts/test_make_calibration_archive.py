import copy
import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "make_calibration_archive.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "make_calibration_archive", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeterministicCalibrationArchiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def make_tree(self, root):
        source = root / "source"
        (source / "profiles" / "primary40").mkdir(parents=True)
        (source / "profiles" / "primary40" / "profile_manifest.json").write_bytes(
            b'{"fixture":1}\n')
        (source / "profiles" / "primary40" / "completion_seal.json").write_bytes(
            b'{"fixture":2}\n')
        members = [
            "profiles/primary40/completion_seal.json",
            "profiles/primary40/profile_manifest.json",
        ]
        return source, members

    def test_repeated_builds_are_byte_identical_and_verify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, members = self.make_tree(root)
            first = root / "first.tar.zst"
            second = root / "second.tar.zst"
            first_info = self.module.build_archive(source, members, first)
            second_info = self.module.build_archive(
                source, list(reversed(members)), second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_info, second_info)
            self.assertEqual(first_info["members"], sorted(members))
            self.assertEqual(
                first_info["archive_sha256"],
                hashlib.sha256(first.read_bytes()).hexdigest(),
            )
            self.module.verify_archive(first, first_info)

    def test_rejects_unsafe_duplicate_or_nonregular_members(self):
        bad_members = (
            ["/absolute"],
            ["../escape"],
            ["profiles/../escape"],
            ["profiles//double"],
            ["profiles/primary40/profile_manifest.json"] * 2,
            ["manifest.json"],
        )
        for members in bad_members:
            with self.subTest(members=members):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    source, _ = self.make_tree(root)
                    with self.assertRaises(ValueError):
                        self.module.build_archive(
                            source, members, root / "bad.tar.zst")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = self.make_tree(root)
            target = source / "profiles" / "primary40" / "link"
            target.symlink_to("profile_manifest.json")
            with self.assertRaises(ValueError):
                self.module.build_archive(
                    source,
                    ["profiles/primary40/link"],
                    root / "bad.tar.zst",
                )

    def test_verify_rejects_omission_hash_and_zstd_version_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, members = self.make_tree(root)
            archive = root / "archive.tar.zst"
            info = self.module.build_archive(source, members, archive)
            for field, replacement in (
                ("members", info["members"][:-1]),
                ("tar_sha256", "0" * 64),
                ("archive_sha256", "0" * 64),
                ("zstd_version", info["zstd_version"] + "-changed"),
            ):
                changed = copy.deepcopy(info)
                changed[field] = replacement
                with self.subTest(field=field):
                    with self.assertRaises(ValueError):
                        self.module.verify_archive(archive, changed)

    def test_missing_zstd_fails_without_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, members = self.make_tree(root)
            destination = root / "archive.tar.zst"
            with self.assertRaises(ValueError):
                self.module.build_archive(
                    source,
                    members,
                    destination,
                    zstd_binary=root / "missing-zstd",
                )
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
