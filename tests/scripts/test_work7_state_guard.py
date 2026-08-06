#!/usr/bin/env python3
"""Behavior tests for the Work 7 Phase 0 byte-level state guard."""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import work7_evidence
from scripts.work7_evidence import (
    assert_output_roots_outside,
    canonical_json_bytes,
    create_tree_seal,
    snapshot_git_worktree,
    verify_tree_seal,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "scripts" / "work7_state_guard.py"


def run(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, check=check, capture_output=True, text=True)


def init_repo(path: Path) -> str:
    path.mkdir()
    run("git", "init", "-q", "-b", "tkde-major/pre-threshold-poc", cwd=path)
    run("git", "config", "user.email", "work7@example.test", cwd=path)
    run("git", "config", "user.name", "Work 7 test", cwd=path)
    (path / "tracked.txt").write_text("initial\n", encoding="utf-8")
    run("git", "add", "tracked.txt", cwd=path)
    run("git", "commit", "-qm", "initial", cwd=path)
    return run("git", "rev-parse", "HEAD", cwd=path).stdout.strip()


class Work7StateGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.source = self.root / "source"
        self.paper = self.root / "paper"
        self.threshold = self.root / "threshold"
        self.source_head = init_repo(self.source)
        init_repo(self.paper)
        init_repo(self.threshold)
        self.build = self.root / "build"
        self.session = self.root / "session"
        self.build.mkdir()
        self.session.mkdir()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def guard(self, output: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(GUARD),
             "--source-root", str(self.source), "--paper-root", str(self.paper),
             "--threshold-root", str(self.threshold), "--build-root", str(self.build),
             "--session-root", str(self.session),
             "--expected-source-branch", "tkde-major/pre-threshold-poc",
             "--expected-source-commit", self.source_head, "--output", str(output)],
            capture_output=True, text=True,
        )

    def test_canonical_json_is_sorted_ascii_compact_and_has_one_newline(self) -> None:
        self.assertEqual(canonical_json_bytes({"z": "\u00e9", "a": [1, 2]}),
                         b'{"a":[1,2],"z":"\\u00e9"}\n')

    def test_clean_source_passes_and_dirty_paper_is_recorded(self) -> None:
        (self.paper / "tracked.txt").write_text("paper is dirty\n", encoding="utf-8")
        output = self.session / "phase0" / "state.json"
        result = self.guard(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "work7_state_guard: PASS\n")
        state = __import__("json").loads(output.read_text(encoding="utf-8"))
        self.assertEqual(state["source"]["head"], self.source_head)
        self.assertNotEqual(state["paper"]["snapshot_sha256"], "")
        self.assertFalse((self.paper / ".git" / "index.lock").exists())

    def test_snapshot_does_not_change_git_index_metadata(self) -> None:
        index = self.paper / ".git" / "index"
        before = index.stat()
        snapshot_git_worktree(self.paper)
        after = index.stat()
        self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))

    def test_changed_dirty_bytes_change_snapshot_digest_without_status_shape_change(self) -> None:
        tracked = self.paper / "tracked.txt"
        tracked.write_text("one\n", encoding="utf-8")
        first = snapshot_git_worktree(self.paper)
        self.assertEqual(first, snapshot_git_worktree(self.paper))
        tracked.write_text("two\n", encoding="utf-8")
        second = snapshot_git_worktree(self.paper)
        self.assertEqual(first["porcelain_status"], second["porcelain_status"])
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_index_only_change_changes_snapshot_digest(self) -> None:
        first = snapshot_git_worktree(self.paper)
        (self.paper / "tracked.txt").write_text("staged only\n", encoding="utf-8")
        run("git", "add", "tracked.txt", cwd=self.paper)
        second = snapshot_git_worktree(self.paper)
        self.assertNotEqual(first["index_sha256"], second["index_sha256"])
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_untracked_bytes_and_executable_mode_change_snapshot_digest(self) -> None:
        first = snapshot_git_worktree(self.paper)
        extra = self.paper / "extra.txt"
        extra.write_bytes(b"first")
        second = snapshot_git_worktree(self.paper)
        extra.write_bytes(b"second")
        third = snapshot_git_worktree(self.paper)
        os.chmod(extra, extra.stat().st_mode | stat.S_IXUSR)
        fourth = snapshot_git_worktree(self.paper)
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertNotEqual(second["snapshot_sha256"], third["snapshot_sha256"])
        self.assertNotEqual(third["snapshot_sha256"], fourth["snapshot_sha256"])

    def test_symlink_target_changes_snapshot_digest_without_following_link(self) -> None:
        target = self.paper / "target-a"
        target.write_text("A", encoding="utf-8")
        os.symlink("target-a", self.paper / "link")
        first = snapshot_git_worktree(self.paper)
        (self.paper / "link").unlink()
        os.symlink("target-b", self.paper / "link")
        second = snapshot_git_worktree(self.paper)
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_submodule_status_is_recorded(self) -> None:
        child = self.root / "child"
        init_repo(child)
        run("git", "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(child), "deps/child", cwd=self.paper)
        run("git", "commit", "-am", "submodule", "-q", cwd=self.paper)
        snapshot = snapshot_git_worktree(self.paper)
        self.assertIn("deps/child", snapshot["submodule_status"])

    def test_dirty_source_is_rejected_without_creating_output(self) -> None:
        (self.source / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        output = self.session / "phase0" / "state.json"
        result = self.guard(output)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.startswith("work7_state_guard: FAIL: source worktree is dirty\n"))
        self.assertFalse(output.exists())

    def test_output_root_containment_and_symlink_alias_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            assert_output_roots_outside([self.source, self.paper, self.threshold], [self.paper / "evidence"])
        alias = self.root / "paper-alias"
        alias.symlink_to(self.paper, target_is_directory=True)
        with self.assertRaises(ValueError):
            assert_output_roots_outside([self.source, self.paper, self.threshold], [alias / "evidence"])

    def test_roots_must_be_distinct_and_output_roots_must_not_overlap(self) -> None:
        with self.assertRaises(ValueError):
            assert_output_roots_outside([self.source, self.source, self.threshold], [self.build, self.session])
        with self.assertRaises(ValueError):
            assert_output_roots_outside([self.source, self.paper, self.threshold], [self.build, self.build / "nested"])

    def test_symlink_artifact_root_seal_path_and_output_path_fail_closed(self) -> None:
        artifact = self.root / "artifact"
        artifact.mkdir()
        (artifact / "proof.txt").write_text("proof", encoding="utf-8")
        artifact_alias = self.root / "artifact-alias"
        artifact_alias.symlink_to(artifact, target_is_directory=True)
        with self.assertRaises(ValueError):
            create_tree_seal(artifact_alias, self.root / "seal.json", None, "phase0")
        seal_alias = self.root / "seal-alias.json"
        seal_alias.symlink_to(self.root / "missing-seal.json")
        with self.assertRaises(ValueError):
            create_tree_seal(artifact, seal_alias, None, "phase0")
        output_alias = self.session / "phase0" / "state.json"
        output_alias.parent.mkdir()
        output_alias.symlink_to(self.root / "missing-state.json")
        result = self.guard(output_alias)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.startswith("work7_state_guard: FAIL:"))

    def test_cli_rejects_relative_and_missing_arguments_with_one_failure_line(self) -> None:
        relative = subprocess.run([sys.executable, str(GUARD), "--source-root", "relative"],
                                  cwd=self.root, capture_output=True, text=True)
        missing = subprocess.run([sys.executable, str(GUARD)], cwd=self.root,
                                 capture_output=True, text=True)
        for result in (relative, missing):
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertRegex(result.stderr, r"^work7_state_guard: FAIL: .+\n$")

    def test_sha256_file_rejects_replacement_by_symlink_during_open(self) -> None:
        path = self.root / "race.txt"
        replacement = self.root / "replacement.txt"
        path.write_text("original", encoding="utf-8")
        replacement.write_text("replacement", encoding="utf-8")
        actual_open = os.open

        def replace_then_open(name: os.PathLike[str] | str, flags: int, *args: object) -> int:
            if Path(name) == path:
                path.unlink()
                path.symlink_to(replacement)
            return actual_open(name, flags, *args)

        with mock.patch.object(work7_evidence.os, "open", side_effect=replace_then_open):
            with self.assertRaises(ValueError):
                work7_evidence.sha256_file(path)

    def test_existing_output_collision_is_rejected_without_overwrite(self) -> None:
        output = self.session / "phase0" / "state.json"
        output.parent.mkdir()
        output.write_bytes(b"do not overwrite\n")
        result = self.guard(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output already exists", result.stderr)
        self.assertEqual(output.read_bytes(), b"do not overwrite\n")

    def test_tree_seal_is_reproducible_chained_and_rejects_overwrite_or_symlink(self) -> None:
        artifact = self.root / "artifact"
        artifact.mkdir()
        data = artifact / "proof.txt"
        data.write_bytes(b"proof\n")
        os.chmod(data, 0o755)
        seal = self.root / "seal.json"
        created = create_tree_seal(artifact, seal, "a" * 64, "phase0")
        verified = verify_tree_seal(seal, "a" * 64)
        self.assertEqual(created, verified)
        with self.assertRaises(FileExistsError):
            create_tree_seal(artifact, seal, "a" * 64, "phase0")
        (artifact / "link").symlink_to("proof.txt")
        with self.assertRaises(ValueError):
            create_tree_seal(artifact, self.root / "other-seal.json", None, "phase1")

    def test_verify_tree_seal_rejects_malformed_structure_and_digest(self) -> None:
        malformed = self.root / "malformed-seal.json"
        malformed.write_bytes(canonical_json_bytes({"schema": "piccard-work7-tree-seal-v1"}))
        with self.assertRaises(ValueError):
            verify_tree_seal(malformed)
        artifact = self.root / "artifact"
        artifact.mkdir()
        (artifact / "proof.txt").write_text("proof", encoding="utf-8")
        seal = self.root / "seal.json"
        create_tree_seal(artifact, seal, None, "phase0")
        with self.assertRaises(ValueError):
            verify_tree_seal(seal, "not-a-digest")


if __name__ == "__main__":
    unittest.main(verbosity=2)
