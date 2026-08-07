"""CLI behavior coverage for Work 7 review packets and terminal closure."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import threading
import unittest
from contextlib import redirect_stderr
from dataclasses import replace
from argparse import Namespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[2]
REVIEW_FIXTURES = ROOT / "tests/fixtures/work7/reviews"


class Work7CTestInventoryTests(unittest.TestCase):
    """Fail-closed parsing for the complete CTest registry."""

    @staticmethod
    def inventory(*names: str, total: int | None = None) -> bytes:
        """Render the relevant stable portion of ``ctest -N`` output."""
        rendered = [f"  Test #{index}: {name}" for index, name in enumerate(names, 1)]
        rendered.append(f"Total Tests: {len(names) if total is None else total}")
        return ("\n".join(rendered) + "\n").encode("utf-8")

    def test_inventory_allows_unrelated_registered_test(self):
        """The full registry may contain tests outside the frozen Work 7 scope."""
        from scripts.run_work7_integration import FROZEN_CTESTS
        from scripts.work7_review_packet import _ctest_inventory

        names = (*FROZEN_CTESTS, "UnrelatedProjectSmoke")
        self.assertEqual(_ctest_inventory(self.inventory(*names)), names)

    def test_inventory_rejects_missing_frozen_test(self):
        """Every frozen Work 7 test must still be registered."""
        from scripts.run_work7_integration import FROZEN_CTESTS
        from scripts.work7_review_packet import Failure, _ctest_inventory

        with self.assertRaises(Failure):
            _ctest_inventory(self.inventory(*FROZEN_CTESTS[1:]))

    def test_inventory_rejects_total_that_disagrees_with_complete_registry(self):
        """The declared total must truthfully count every parsed registry test."""
        from scripts.run_work7_integration import FROZEN_CTESTS
        from scripts.work7_review_packet import Failure, _ctest_inventory

        with self.assertRaises(Failure):
            _ctest_inventory(self.inventory(*FROZEN_CTESTS, "UnrelatedProjectSmoke", total=len(FROZEN_CTESTS)))


class Work7ReviewPacketTests(unittest.TestCase):
    """The packet is a real session-local snapshot, never a source-text check."""

    def test_package_imports_keep_captured_blob_identity_after_legacy_alias(self):
        """Package callers retain one evidence type even after a CLI-style import."""
        code = """\
import sys
from pathlib import Path
root = Path.cwd()
from scripts import work7_review_packet
package_blob = work7_review_packet.CapturedBlob
sys.path.insert(0, str(root / 'scripts'))
import work7_evidence
from scripts import verify_work7_claims
assert verify_work7_claims.CapturedBlob is package_blob
"""
        result = subprocess.run((sys.executable, "-c", code), cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def setUp(self):
        from tests.scripts.test_work7_integration_runner import Work7IntegrationRunnerTests

        helper = Work7IntegrationRunnerTests()
        produced, temporary, self.commit = helper.invoke_fake_runner(source_snapshot=ROOT, terminal_wrapper=True)
        self.temporary = temporary.resolve()
        self.addCleanup(shutil.rmtree, self.temporary, True)
        self.assertEqual(produced.returncode, 0, produced.stderr.decode())
        self.source, self.paper, self.threshold = (self.temporary / name for name in ("source", "paper", "threshold"))
        self.session = self.temporary / "sessions" / ("session-" + self.commit)
        generated = subprocess.run((sys.executable, str(ROOT / "scripts/generate_work7_response_candidate.py"),
                                   "--source-root", str(self.source), "--paper-root", str(self.paper),
                                   "--threshold-root", str(self.threshold), "--session-root", str(self.session),
                                   "--phase0-seal", str(self.session / "phase0/seal.json"),
                                   "--phase2-closure-seal", str(self.session / "phase2/closure-seal.json")),
                                  capture_output=True)
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())

    def command(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run((sys.executable, str(ROOT / "scripts/work7_review_packet.py"), *arguments), capture_output=True)

    def prepare_work(self) -> Path:
        output = self.session / "phase4/work-packet.json"
        result = self.command("prepare-work", "--source-root", str(self.source), "--session-root", str(self.session),
                              "--baseline-commit", "b907fae", "--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return output

    def work_review(self, packet: Path, *, checks: bool = True) -> Path:
        review = self.temporary / "work-review.txt"
        text = REVIEW_FIXTURES.joinpath("work-approved.template.txt").read_text(encoding="utf-8").format(
            SOURCE_COMMIT=self.commit, PACKET_SHA256=hashlib.sha256(packet.read_bytes()).hexdigest())
        if not checks:
            text = "\n".join(text.splitlines()[:7]) + "\n"
        review.write_text(text, encoding="utf-8")
        return review

    def final_review(self, packet: Path, provider: str) -> Path:
        filename = {"anthropic": "final-claude-approved.template.txt", "openai": "final-sol-approved.template.txt"}[provider]
        review = self.temporary / f"{provider}-final.txt"
        review.write_text(REVIEW_FIXTURES.joinpath(filename).read_text(encoding="utf-8").format(
            SOURCE_COMMIT=self.commit, PACKET_SHA256=hashlib.sha256(packet.read_bytes()).hexdigest()), encoding="utf-8")
        return review

    def prepare_final_packet(self) -> Path:
        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        final_packet = self.session / "phase5/final-packet.json"
        prepared = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                                "--work-review-seal", str(work_seal), "--output", str(final_packet))
        self.assertEqual(prepared.returncode, 0, prepared.stderr.decode())
        return final_packet

    def close_final(self, packet: Path, claude: Path, sol: Path, terminal: Path, seal: Path) -> subprocess.CompletedProcess[bytes]:
        return self.command("close-final", "--packet", str(packet), "--claude-review", str(claude), "--sol-review", str(sol),
                            "--terminal-report", str(terminal), "--session-root", str(self.session),
                            "--phase0-seal", str(self.session / "phase0/seal.json"), "--source-root", str(self.source), "--paper-root", str(self.paper),
                            "--threshold-root", str(self.threshold), "--output-seal", str(seal))

    def reseal_hostile_runtime(self, mutate) -> None:
        """Make a self-consistent hostile Phase 2 graph that Phase 3 can still consume."""
        from scripts.run_work7_integration import checked_command
        from scripts.work7_evidence import create_tree_seal, sha256_file

        runtime, phase2, phase3 = self.session / "phase2/runtime", self.session / "phase2", self.session / "phase3"
        mutate(runtime)
        # A hostile reseal can rewrite the evidence index as well as the changed
        # producer artifact; Phase 3's normal index checker must still accept it
        # so prepare-final is the gate under test.
        index_path = runtime / "evidence-index.json"; index = json.loads(index_path.read_bytes())
        for records in index["claims"].values():
            for record in records.values():
                record["sha256"] = hashlib.sha256((runtime / record["path"]).read_bytes()).hexdigest()
        index_path.write_bytes((json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n").encode())
        runtime_seal = phase2 / "runtime-seal.json"; runtime_seal.unlink()
        create_tree_seal(runtime, runtime_seal, sha256_file(self.session / "phase0/seal.json"), "phase2-runtime-artifacts")
        closure = phase2 / "closure-artifacts"; shutil.rmtree(closure); closure.mkdir()
        evidence = closure / "evidence-bound-report.json"
        command = (sys.executable, str(self.source / "scripts/verify_work7_claims.py"), "--mode", "evidence-bound",
                   "--contract", str(self.source / "scripts/work7_claims.json"), "--source-root", str(self.source),
                   "--source-commit", self.commit, "--ctest-inventory", str(runtime / "commands/ctest-inventory.stdout.txt"),
                   "--runtime-seal", str(runtime_seal), "--output", str(evidence))
        checked_command(command, self.source, closure / "commands", "evidence-bound")
        closure_seal = phase2 / "closure-seal.json"; closure_seal.unlink()
        create_tree_seal(closure, closure_seal, sha256_file(runtime_seal), "phase2-closure")
        shutil.rmtree(phase3)
        generated = subprocess.run((sys.executable, str(ROOT / "scripts/generate_work7_response_candidate.py"),
                                   "--source-root", str(self.source), "--paper-root", str(self.paper), "--threshold-root", str(self.threshold),
                                   "--session-root", str(self.session), "--phase0-seal", str(self.session / "phase0/seal.json"),
                                   "--phase2-closure-seal", str(closure_seal)), capture_output=True)
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())

    def assert_hostile_runtime_blocks_prepare_final(self, mutate) -> None:
        self.reseal_hostile_runtime(mutate)
        packet = self.prepare_work(); work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        output = self.session / "phase5/final-packet.json"
        result = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                              "--work-review-seal", str(work_seal), "--output", str(output))
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(output.exists())
        self.assertFalse((self.session / "phase5/members").exists())

    def _validate_while_path_is_atomically_replaced(self, target: Path, foreign: bytes) -> object:
        """Run byte-only validation while a live Phase 0--3 path is foreign."""
        from scripts.work7_review_packet import capture_phase04, validate_phase2_runtime_capture

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source)
        original = target.read_bytes()
        original_mode = target.stat().st_mode & 0o777
        replacement = target.with_name(target.name + ".foreign")
        restore = target.with_name(target.name + ".restore")
        replacement.write_bytes(foreign)
        os.chmod(replacement, original_mode)
        os.replace(replacement, target)
        barrier = threading.Barrier(2)
        result: list[object] = []
        errors: list[BaseException] = []

        def consume_captured_graph() -> None:
            try:
                barrier.wait(timeout=5)
                result.append(validate_phase2_runtime_capture(capture))
            except BaseException as error:  # Preserve worker errors for the test.
                errors.append(error)

        worker = threading.Thread(target=consume_captured_graph)
        worker.start()
        barrier.wait(timeout=5)
        worker.join(timeout=15)
        restore.write_bytes(original)
        os.chmod(restore, original_mode)
        os.replace(restore, target)
        if worker.is_alive():
            self.fail("captured runtime validation did not complete")
        if errors:
            raise errors[0]
        self.assertFalse((self.session / "phase5/members").exists())
        return result[0]

    def _phase5_snapshot(self) -> tuple[tuple[str, str, int | None, bytes], ...]:
        """Capture missing roots distinctly from empty roots and every entry's identity."""
        phase5 = self.session / "phase5"
        try:
            phase5.lstat()
        except FileNotFoundError:
            return ((".", "missing", None, b""),)

        def entry(path: Path, relative: str) -> tuple[str, str, int, bytes]:
            info = path.lstat()
            if path.is_file() and not path.is_symlink():
                return (relative, "file", info.st_mode & 0o777, path.read_bytes())
            elif path.is_dir() and not path.is_symlink():
                return (relative, "directory", info.st_mode & 0o777, b"")
            if path.is_symlink():
                return (relative, "symlink", info.st_mode & 0o777,
                        os.readlink(path).encode("utf-8", "surrogateescape"))
            return (relative, "other", info.st_mode & 0o777, b"")

        result = [entry(phase5, ".")]
        if not phase5.is_dir() or phase5.is_symlink():
            return tuple(result)
        for path in sorted(phase5.rglob("*")):
            result.append(entry(path, path.relative_to(phase5).as_posix()))
        return tuple(result)

    def _prepare_final_with_member_collision(self, relative: str) -> tuple[subprocess.CompletedProcess[bytes], Path]:
        """Create a real packet-member collision only after publication starts."""
        packet = self.prepare_work()
        seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        root = self.session / "phase5/members"
        target = root / relative
        injected = threading.Event()

        def collide() -> None:
            for _ in range(5000):
                if root.is_dir():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"collision sentinel\n")
                    os.chmod(target, 0o640)
                    injected.set()
                    return
                threading.Event().wait(0.001)

        worker = threading.Thread(target=collide)
        worker.start()
        result = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                              "--work-review-seal", str(seal), "--output", str(self.session / "phase5/final-packet.json"))
        worker.join(timeout=10)
        self.assertTrue(injected.is_set(), "collision worker did not synchronize with publication")
        return result, target

    def test_prepare_final_rolls_back_ordinary_member_collision_after_publication_starts(self):
        """A late ordinary collision preserves the foreign sentinel and removes owned outputs."""
        before = self._phase5_snapshot()
        result, sentinel = self._prepare_final_with_member_collision("session/phase2/static-report.json")
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertNotEqual(before, self._phase5_snapshot())
        self.assertEqual(sentinel.read_bytes(), b"collision sentinel\n")
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.session / "phase5/members/source").exists())
        self.assertFalse((self.session / "phase5/final-packet.json").exists())

    def test_prepare_final_rolls_back_generated_member_collision_after_ordinary_members(self):
        """A generated collision preserves its descendant while rolling back owned members."""
        before = self._phase5_snapshot()
        result, sentinel = self._prepare_final_with_member_collision("generated/final-verification-summary.json")
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertNotEqual(before, self._phase5_snapshot())
        self.assertEqual(sentinel.read_bytes(), b"collision sentinel\n")
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.session / "phase5/members/source").exists())
        self.assertFalse((self.session / "phase5/final-packet.json").exists())

    def test_capture_phase04_seal_swap_fails_second_capture_without_phase5_output(self):
        """A transient prerequisite-seal replacement cannot enter a later capture."""
        from scripts.work7_review_packet import Failure, capture_phase04, validate_phase2_runtime_capture

        packet = self.prepare_work()
        work = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work)).returncode, 0)
        first = capture_phase04(self.session, self.source)
        seal = self.session / "phase2/runtime-seal.json"
        original, mode = seal.read_bytes(), seal.stat().st_mode & 0o777
        foreign = seal.with_name("runtime-seal.foreign")
        foreign.write_bytes(b'{"foreign":true}\n')
        os.chmod(foreign, mode)
        os.replace(foreign, seal)
        with self.assertRaises(Failure):
            capture_phase04(self.session, self.source)
        # Runtime validation consumes only first's retained blobs while the
        # live predecessor path remains foreign.
        self.assertEqual(validate_phase2_runtime_capture(first).focused_pass_count, 28)
        restore = seal.with_name("runtime-seal.restore")
        restore.write_bytes(original)
        os.chmod(restore, mode)
        os.replace(restore, seal)
        self.assertFalse((self.session / "phase5/members").exists())

    def test_prepare_final_preserves_preexisting_output_collision_sentinel(self):
        """An existing packet target is never overwritten or removed by cleanup."""
        packet = self.prepare_work()
        seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        output = self.session / "phase5/final-packet.json"
        output.parent.mkdir(exist_ok=True)
        output.write_bytes(b"pre-existing packet sentinel\n")
        before = self._phase5_snapshot()
        result = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                              "--work-review-seal", str(seal), "--output", str(output))
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertEqual(self._phase5_snapshot(), before)

    def test_prepare_final_second_capture_boundary_rejects_real_seal_replacement_without_output(self):
        """A capture-two failure restores both a missing and an empty Phase 5 root exactly."""
        from scripts import work7_review_packet

        packet = self.prepare_work()
        seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        output = self.session / "phase5/final-packet.json"
        runtime_seal = self.session / "phase2/runtime-seal.json"
        original, mode = runtime_seal.read_bytes(), runtime_seal.stat().st_mode & 0o777
        phase5 = self.session / "phase5"
        self.assertFalse(phase5.exists())
        for initial in ("missing", "empty"):
            with self.subTest(initial=initial):
                if initial == "empty":
                    phase5.mkdir(mode=0o750)
                    os.chmod(phase5, 0o750)
                before = self._phase5_snapshot()
                reached = []

                def synchronize(point: str) -> None:
                    if point == "before_second_capture":
                        replacement = runtime_seal.with_name("runtime-seal.boundary")
                        replacement.write_bytes(b'{"foreign":true}\n')
                        os.chmod(replacement, mode)
                        os.replace(replacement, runtime_seal)
                        reached.append(point)

                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    status = work7_review_packet.main(["prepare-final", "--source-root", str(self.source),
                                                        "--session-root", str(self.session), "--work-review-seal", str(seal),
                                                        "--output", str(output)], synchronize=synchronize)
                restore = runtime_seal.with_name("runtime-seal.restore")
                restore.write_bytes(original)
                os.chmod(restore, mode)
                os.replace(restore, runtime_seal)
                self.assertEqual(reached, ["before_second_capture"])
                self.assertEqual(status, 2)
                self.assertIn("Phase 0--4 evidence changed during final packet preparation", stderr.getvalue())
                self.assertFalse(output.exists())
                self.assertEqual(self._phase5_snapshot(), before)

    def test_prepare_final_packet_creation_boundary_rolls_back_members_and_preserves_sentinel(self):
        """A late packet collision preserves its sentinel and removes every published member."""
        from scripts import work7_review_packet

        packet = self.prepare_work()
        seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        output = self.session / "phase5/final-packet.json"
        sentinel = b"late output collision sentinel\n"
        reached = []

        def synchronize(point: str) -> None:
            if point == "before_packet_create":
                output.write_bytes(sentinel)
                os.chmod(output, 0o640)
                reached.append(point)

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = work7_review_packet.main(["prepare-final", "--source-root", str(self.source),
                                                "--session-root", str(self.session), "--work-review-seal", str(seal),
                                                "--output", str(output)], synchronize=synchronize)
        self.assertEqual(reached, ["before_packet_create"])
        self.assertEqual(status, 2)
        self.assertIn("output already exists", stderr.getvalue())
        self.assertEqual(output.read_bytes(), sentinel)
        self.assertEqual(output.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.session / "phase5/members").exists())

    def test_runtime_semantics_use_captured_producer_bytes_while_live_member_is_foreign(self):
        """A live producer replacement must not affect byte-only semantic validation."""
        from scripts.work7_review_packet import RuntimeSummary

        target = self.session / "phase2/runtime/pre-threshold/manifest.json"
        summary = self._validate_while_path_is_atomically_replaced(target, b'{"foreign":true}\n')
        self.assertIsInstance(summary, RuntimeSummary)
        self.assertEqual(summary.focused_pass_count, 28)

    def test_runtime_semantics_use_captured_build_binary_while_live_binary_is_foreign(self):
        """R0-bound build executable bytes must not be reopened during semantic validation."""
        from scripts.work7_review_packet import RuntimeSummary

        target = self.temporary / "builds" / ("build-" + self.commit) / "bench_deletion_survival"
        summary = self._validate_while_path_is_atomically_replaced(target, b"#!/bin/sh\nexit 99\n")
        self.assertIsInstance(summary, RuntimeSummary)
        self.assertEqual(summary.deletion_survival, hashlib.sha256(
            (json.dumps([str(target), "--n=64", "--d=3", "--k=8", "--required_survival=0.99",
                        "--r_values=1,4,8", "--trials=1", "--seed=7"], sort_keys=True,
                       separators=(",", ":"), ensure_ascii=True) + "\n").encode()).hexdigest())

    def test_captured_prethreshold_validator_rejects_missing_terminal_and_output_bindings(self):
        """Dropping path-validator-required terminal/output bindings must fail byte validation."""
        from scripts.run_work7_integration import Failure, validate_prethreshold_capture
        from scripts.work7_evidence import CapturedBlob
        from scripts.work7_review_packet import capture_phase04

        packet = self.prepare_work(); seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source)
        blobs = dict(capture.packet_members)
        value = json.loads(blobs["phase2/runtime/pre-threshold/manifest.json"].raw)
        del value["terminal_cells"]
        del value["cells"][0]["output"]["csv_sha256"]
        raw = json.dumps(value).encode()
        blobs["phase2/runtime/pre-threshold/manifest.json"] = CapturedBlob(raw, hashlib.sha256(raw).hexdigest(), len(raw), "0644")
        blobs.update({"@build/" + name: blob for name, blob in capture.build_binaries})
        captured_members = dict(capture.packet_members)
        baseline_manifest = json.loads(captured_members["phase2/runtime/pre-threshold/manifest.json"].raw)
        pre_paths = {"phase2/runtime/pre-threshold/manifest.json", "phase2/runtime/pre-threshold/terminal-cells.tsv"}
        for cell in baseline_manifest["cells"]:
            for key, item in cell["output"].items():
                if not key.endswith("_sha256") and key not in {"expected_csv_rows", "csv_row_count", "measurement_output"}:
                    pre_paths.add("phase2/runtime/pre-threshold/" + item)
        baseline = tuple((path, captured_members[path]) for path in sorted(pre_paths)) + tuple(
            ("@build/" + name, dict(capture.build_binaries)[name]) for name in
            ("bench_review_comparison", "bench_piccard", "bench_dynamic"))
        argv = tuple(json.loads(captured_members["phase2/runtime/commands/pre-threshold.json"].raw)["argv"])
        validate_prethreshold_capture(baseline, capture.commit, argv, str(self.source), str(self.temporary / "builds" / ("build-" + self.commit)))
        blobs = {path: blob for path, blob in blobs.items() if path.startswith("phase2/runtime/pre-threshold/") or path.startswith("@build/")}
        with self.assertRaises(Failure):
            validate_prethreshold_capture(tuple(blobs.items()), capture.commit, argv,
                                          str(self.source), str(self.temporary / "builds" / ("build-" + self.commit)))

    def test_captured_real_validator_rejects_missing_root_artifact_cell_and_digest_bindings(self):
        """A metadata prefix cannot stand in for the complete real-run schema."""
        from scripts.run_work7_integration import Failure, validate_real_capture
        from scripts.work7_evidence import CapturedBlob
        from scripts.work7_review_packet import capture_phase04

        packet = self.prepare_work(); seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source); blobs = dict(capture.packet_members)
        metadata = blobs["phase2/runtime/real-datasets/run_metadata.tsv"].raw.decode().splitlines()
        raw = ("\n".join(row for row in metadata if not any(key in row for key in ("root_count", "artifact_count", "cell.000", "bench_real_datasets_sha256"))) + "\n").encode()
        digest = hashlib.sha256(raw).hexdigest()
        blobs["phase2/runtime/real-datasets/run_metadata.tsv"] = CapturedBlob(raw, digest, len(raw), "0644")
        status = b"key\tvalue\nschema_version\tpiccard-real-verification-v1\nrun_metadata_sha256\t" + digest.encode() + b"\nstatus\tVERIFIED\n"
        blobs["phase2/runtime/real-datasets/verification_status.tsv"] = CapturedBlob(status, hashlib.sha256(status).hexdigest(), len(status), "0644")
        blobs.update({"@build/" + name: blob for name, blob in capture.build_binaries})
        captured_members = dict(capture.packet_members)
        baseline_metadata = captured_members["phase2/runtime/real-datasets/run_metadata.tsv"].raw.decode().splitlines()
        real_paths = {"phase2/runtime/real-datasets/run_metadata.tsv", "phase2/runtime/real-datasets/verification_status.tsv",
                      "phase2/runtime/real-datasets/input_manifests/dblp_acm_u65536/dataset.manifest.tsv"}
        for row in baseline_metadata[1:]:
            key, item = row.split("\t", 1)
            if key.endswith(".path") and (key.startswith("artifact.") or ".output." in key):
                real_paths.add("phase2/runtime/real-datasets/" + item)
        baseline = tuple((path, captured_members[path]) for path in sorted(real_paths)) + (
            ("@build/bench_real_datasets", dict(capture.build_binaries)["bench_real_datasets"]),
            ("@source/scripts/summarize_real_datasets.py", captured_members["@source/scripts/summarize_real_datasets.py"]),
            ("@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv",
             captured_members["@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv"]),
        )
        validate_real_capture(baseline, capture.commit, str(self.source), str(self.temporary / "builds" / ("build-" + self.commit)))
        blobs = {path: blob for path, blob in blobs.items() if path.startswith("phase2/runtime/real-datasets/") or path.startswith("@build/")}
        with self.assertRaises(Failure):
            validate_real_capture(tuple(blobs.items()), capture.commit, str(self.source), str(self.temporary / "builds" / ("build-" + self.commit)))

    def test_captured_producer_validators_require_exact_byte_only_schemas(self):
        """Every path-validator field remains binding when only captured blobs exist."""
        from scripts.run_work7_integration import Failure, validate_prethreshold_capture, validate_real_capture
        from scripts.work7_evidence import CapturedBlob
        from scripts.work7_review_packet import capture_phase04

        packet = self.prepare_work(); seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source)
        members = dict(capture.packet_members)
        build = str(self.temporary / "builds" / ("build-" + self.commit))
        pre_manifest = json.loads(members["phase2/runtime/pre-threshold/manifest.json"].raw)
        pre_paths = {"phase2/runtime/pre-threshold/manifest.json", "phase2/runtime/pre-threshold/terminal-cells.tsv"}
        for cell in pre_manifest["cells"]:
            for key, value in cell["output"].items():
                if not key.endswith("_sha256") and key not in {"expected_csv_rows", "csv_row_count", "measurement_output"}:
                    pre_paths.add("phase2/runtime/pre-threshold/" + value)
        pre = tuple(sorted((path, members[path]) for path in pre_paths) +
                    [("@build/" + name, dict(capture.build_binaries)[name]) for name in
                     ("bench_review_comparison", "bench_piccard", "bench_dynamic")])
        pre_argv = tuple(json.loads(members["phase2/runtime/commands/pre-threshold.json"].raw)["argv"])
        validate_prethreshold_capture(pre, capture.commit, pre_argv, str(self.source), build)

        def altered_blob(raw: bytes) -> CapturedBlob:
            return CapturedBlob(raw, hashlib.sha256(raw).hexdigest(), len(raw), "0644")

        pre_mutations = (
            ("machine schema", lambda value: value["machine"].pop("libraries")),
            ("binary provenance", lambda value: value["build"]["binaries"]["bench_piccard"]["provenance"].__setitem__("dirty", True)),
            ("cell identity", lambda value: value["cells"][0].__setitem__("cell_id", "hostile")),
            ("sampling uniqueness", lambda value: value["cells"][0].__setitem__("argv", value["cells"][0]["argv"] + ["--trials=1"])),
            ("output row count", lambda value: value["cells"][1]["output"].__setitem__("csv_row_count", 2)),
            ("terminal cell binding", lambda value: value["terminal_cells"].__setitem__("row_count", 2)),
        )
        for label, mutate in pre_mutations:
            with self.subTest(prethreshold=label):
                value = json.loads(members["phase2/runtime/pre-threshold/manifest.json"].raw)
                mutate(value)
                hostile = dict(pre)
                raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                hostile["phase2/runtime/pre-threshold/manifest.json"] = altered_blob(raw)
                with self.assertRaises(Failure):
                    validate_prethreshold_capture(tuple(hostile.items()), capture.commit, pre_argv, str(self.source), build)

        self.assertIn("@source/scripts/summarize_real_datasets.py", members)
        real_metadata = members["phase2/runtime/real-datasets/run_metadata.tsv"].raw.decode("utf-8")
        real_paths = {"phase2/runtime/real-datasets/verification_status.tsv", "phase2/runtime/real-datasets/run_metadata.tsv"}
        for row in real_metadata.splitlines()[1:]:
            key, value = row.split("\t", 1)
            if key.endswith(".path") and (key.startswith("artifact.") or ".output." in key):
                real_paths.add("phase2/runtime/real-datasets/" + value)
        real_paths.add("phase2/runtime/real-datasets/input_manifests/dblp_acm_u65536/dataset.manifest.tsv")
        real = tuple(sorted((path, members[path]) for path in real_paths) + [
            ("@build/bench_real_datasets", dict(capture.build_binaries)["bench_real_datasets"]),
            ("@source/scripts/summarize_real_datasets.py", members["@source/scripts/summarize_real_datasets.py"]),
            ("@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv",
             members["@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv"]),
        ])
        validate_real_capture(real, capture.commit, str(self.source), build)
        real_mutations = (
            ("canonical root", "root.000.path", "/hostile/results"),
            ("artifact role", "artifact.000.role", "hostile"),
            ("cell argv", "cell.000.argv.000", "hostile-binary"),
            ("cell environment", "cell.002.env.001.value", "9"),
            ("input root binding", "cell.000.input.000.root_id", "results-root"),
            ("output digest", "cell.001.output.000.sha256", "0" * 64),
        )
        for label, key, replacement in real_mutations:
            with self.subTest(real=label):
                rows = [row.split("\t", 1) for row in real_metadata.splitlines()]
                raw = ("\n".join("\t".join((item[0], replacement if item[0] == key else item[1])) for item in rows) + "\n").encode()
                hostile = dict(real)
                hostile["phase2/runtime/real-datasets/run_metadata.tsv"] = altered_blob(raw)
                with self.assertRaises(Failure):
                    validate_real_capture(tuple(hostile.items()), capture.commit, str(self.source), build)

        hostile = dict(real)
        hostile["phase2/runtime/real-datasets/verification_status.tsv"] = altered_blob(
            b"key\tvalue\nschema_version\tpiccard-real-verification-v1\nrun_metadata_sha256\t" +
            members["phase2/runtime/real-datasets/run_metadata.tsv"].sha256.encode() + b"\nstatus\tHOSTILE\n")
        with self.assertRaises(Failure):
            validate_real_capture(tuple(hostile.items()), capture.commit, str(self.source), build)

    def test_captured_claim_reports_require_claims_and_runtime_seal_binding(self):
        """Top-level PASS fields alone cannot validate static/evidence claim reports."""
        from scripts.work7_evidence import CapturedBlob
        from scripts.work7_review_packet import Failure, capture_phase04, validate_phase2_runtime_capture

        packet = self.prepare_work(); seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source); members = dict(capture.packet_members)
        for relative in ("phase2/runtime/static-report.json", "phase2/static-report.json", "phase2/closure-artifacts/evidence-bound-report.json"):
            value = json.loads(members[relative].raw)
            value.pop("claims", None); value.pop("input_seals", None)
            raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            members[relative] = CapturedBlob(raw, hashlib.sha256(raw).hexdigest(), len(raw), "0644")
        with self.assertRaises(Failure):
            validate_phase2_runtime_capture(replace(capture, packet_members=tuple(sorted(members.items()))))

    def test_captured_claim_reports_preserve_full_contract_and_evidence_semantics(self):
        """Captured claim reports cannot weaken a per-claim state or sealed evidence role."""
        from scripts.work7_evidence import CapturedBlob
        from scripts.work7_review_packet import Failure, capture_phase04, validate_phase2_runtime_capture

        packet = self.prepare_work(); seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source)
        self.assertEqual(validate_phase2_runtime_capture(capture).focused_pass_count, 28)

        def blob(value: object) -> CapturedBlob:
            raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            return CapturedBlob(raw, hashlib.sha256(raw).hexdigest(), len(raw), "0644")

        mutations = []
        static = json.loads(dict(capture.packet_members)["phase2/runtime/static-report.json"].raw)
        static["claims"][0]["performance_state"] = "TOY_VERIFIED"
        mutations.append(("phase2/runtime/static-report.json", blob(static)))
        evidence = json.loads(dict(capture.packet_members)["phase2/closure-artifacts/evidence-bound-report.json"].raw)
        evidence["claims"][5]["toy_evidence_state"] = "PENDING"
        mutations.append(("phase2/closure-artifacts/evidence-bound-report.json", blob(evidence)))
        index = json.loads(dict(capture.packet_members)["phase2/runtime/evidence-index.json"].raw)
        index["claims"]["W7-G4-COMPARISON"]["comparison-toy"]["artifact_kind"] = "hostile"
        mutations.append(("phase2/runtime/evidence-index.json", blob(index)))
        for relative, hostile_blob in mutations:
            with self.subTest(claim_report=relative):
                members = dict(capture.packet_members); members[relative] = hostile_blob
                with self.assertRaises(Failure):
                    validate_phase2_runtime_capture(replace(capture, packet_members=tuple(sorted(members.items()))))

    def test_capture_phase04_rejects_phase2_static_copy_that_differs_from_runtime_sealed_twin(self):
        """A standalone static copy must be byte-identical to its sealed runtime twin."""
        from scripts.work7_review_packet import capture_phase04

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        static = self.session / "phase2/static-report.json"
        static.write_bytes(b'{"foreign":true}\n')
        output = self.session / "phase5/final-packet.json"
        result = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                              "--work-review-seal", str(work_seal),
                              "--output", str(output))
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertIn("sealed runtime copy", result.stderr.decode())
        self.assertFalse(output.exists())
        self.assertFalse((self.session / "phase5/members").exists())
        with self.assertRaisesRegex(Exception, "sealed runtime copy"):
            capture_phase04(self.session, self.source)

    def test_final_packet_seal_members_equal_the_predecessor_bound_captured_seal_blobs(self):
        """Every packet seal member must be the exact blob captured from its chain edge."""
        from scripts.work7_review_packet import capture_phase04

        packet = self.prepare_final_packet()
        capture = capture_phase04(self.session, self.source)
        value = json.loads(packet.read_bytes())
        members = {item["path"]: item for item in value["members"]}
        previous = None
        for relative, seal in capture.seals:
            self.assertEqual(seal.previous_seal_sha256, previous)
            packet_member = members[f"phase5/members/session/{relative}"]
            self.assertEqual((self.session / packet_member["path"]).read_bytes(), seal.blob.raw)
            self.assertEqual(packet_member["size"], seal.blob.size)
            self.assertEqual(packet_member["sha256"], seal.blob.sha256)
            previous = seal.blob.sha256

    def test_prepare_final_rejects_noncanonical_build_roots_before_output(self):
        """A resealed runtime must not redirect validation to any other build tree."""
        from scripts.work7_evidence import canonical_json_bytes

        def set_configure_build(runtime: Path, raw: str) -> None:
            record = runtime / "commands/configure.json"
            value = json.loads(record.read_bytes())
            value["argv"][4] = raw
            record.write_bytes(canonical_json_bytes(value))

        def relocate_complete_runtime(runtime: Path, raw: str) -> None:
            """Reseal a complete fake producer graph bound to a foreign build."""
            from scripts.run_work7_integration import FROZEN_CTESTS

            original = (self.temporary / "builds" / ("build-" + self.commit)).resolve()
            foreign = Path(raw)
            foreign.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(original, foreign)
            environment = {**os.environ, "FAKE_COMMIT": self.commit}
            pre, real = runtime / "pre-threshold", runtime / "real-datasets"
            shutil.rmtree(pre)
            shutil.rmtree(real)
            subprocess.run((str(self.source / "scripts/run_pre_threshold_profiles.sh"), "--suite=smoke", "--seed=7", "--threads=2",
                            "--build-dir=" + raw, "--results-root=" + str(pre)), cwd=self.source, env=environment, check=True)
            subprocess.run((str(self.source / "scripts/run_real_datasets.sh"), "--quick", "--seed=7", "--threads=2",
                            "--build-dir=" + raw, "--results-root=" + str(real)), cwd=self.source, env=environment, check=True)
            subprocess.run((sys.executable, str(self.source / "scripts/verify_real_dataset_outputs.py"), str(real)),
                           cwd=self.source, env=environment, check=True)
            commands = runtime / "commands"
            replacements = {
                "configure": ["cmake", "-S", str(self.source), "-B", raw, "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTS=ON", "-DBUILD_BENCHMARKS=ON"],
                "build": ["cmake", "--build", raw, "--parallel", "2"],
                "ctest-inventory": ["ctest", "--test-dir", raw, "-N"],
                "ctest-focused": ["ctest", "--test-dir", raw, "--output-on-failure", "-R",
                                  "^(" + "|".join(FROZEN_CTESTS) + ")$"],
                "pre-threshold": [str(self.source / "scripts/run_pre_threshold_profiles.sh"), "--suite=smoke", "--seed=7", "--threads=2",
                                  "--build-dir=" + raw, "--results-root=" + str(pre)],
                "real-datasets": [str(self.source / "scripts/run_real_datasets.sh"), "--quick", "--seed=7", "--threads=2",
                                  "--build-dir=" + raw, "--results-root=" + str(real)],
                "deletion-survival": [str(foreign / "bench_deletion_survival"), "--n=64", "--d=3", "--k=8",
                                       "--required_survival=0.99", "--r_values=1,4,8", "--trials=1", "--seed=7"],
            }
            for label, argv in replacements.items():
                record = commands / (label + ".json")
                value = json.loads(record.read_bytes())
                value["argv"] = argv
                record.write_bytes(canonical_json_bytes(value))

        baseline = self.temporary / "r0-phase-baseline"
        for phase in ("phase2", "phase3"):
            shutil.copytree(self.session / phase, baseline / phase)

        def reset_session_graph() -> None:
            for phase in ("phase2", "phase3", "phase4", "phase5"):
                shutil.rmtree(self.session / phase, ignore_errors=True)
            for phase in ("phase2", "phase3"):
                shutil.copytree(baseline / phase, self.session / phase)

        def run_case(name: str, mutate) -> None:
            with self.subTest(name=name):
                reset_session_graph()
                self.reseal_hostile_runtime(mutate)
                packet = self.prepare_work()
                work_seal = self.session / "phase4/work-review-seal.json"
                self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                              "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
                output = self.session / "phase5/final-packet.json"
                result = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                                      "--work-review-seal", str(work_seal), "--output", str(output))
                failures = [line for line in result.stderr.decode().splitlines() if "FAIL" in line]
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertEqual(len(failures), 1, result.stderr.decode())
                self.assertIn("noncanonical build root", failures[0])
                self.assertFalse(output.exists())
                self.assertFalse((self.session / "phase5/members").exists())

        # This complete relocation is intentionally first: before R0 it is a
        # valid, fully resealed graph and therefore produces the distinguishing RED.
        run_case("complete-foreign-build", lambda runtime: relocate_complete_runtime(
            runtime, str((self.temporary / "foreign-builds" / ("build-" + self.commit)).resolve())))
        run_case("relative", lambda runtime: set_configure_build(runtime, "build-" + self.commit))
        run_case("ordinary-symlink", lambda runtime: (
            (self.temporary / "build-link").symlink_to(self.temporary / "builds", target_is_directory=True),
            set_configure_build(runtime, str(self.temporary / "build-link" / ("build-" + self.commit))))[-1])
        run_case("wrong-commit", lambda runtime: (
            (self.temporary / "wrong" / ("build-" + "0" * 40)).mkdir(parents=True),
            set_configure_build(runtime, str((self.temporary / "wrong" / ("build-" + "0" * 40)).resolve())))[-1])
        run_case("missing", lambda runtime: set_configure_build(runtime, str(self.temporary / "missing" / ("build-" + self.commit))))
        for label, guarded in (("source", lambda: self.source), ("paper", lambda: self.paper),
                               ("threshold", lambda: self.threshold), ("session", lambda: self.session)):
            run_case(label + "-equal", lambda runtime, guarded=guarded: set_configure_build(runtime, str(guarded())))
            run_case(label + "-inside", lambda runtime, guarded=guarded: set_configure_build(runtime, str(guarded() / ("build-" + self.commit))))
            run_case(label + "-ancestor", lambda runtime, guarded=guarded: set_configure_build(runtime, str(guarded().parent)))
        if Path("/tmp").is_symlink() and Path("/private/tmp").is_dir():
            def tmp_alias(runtime: Path) -> None:
                alias = Path("/tmp") / ("work7-r0-" + self.temporary.name) / ("build-" + self.commit)
                alias.mkdir(parents=True)
                self.addCleanup(shutil.rmtree, alias.parent.resolve(), True)
                set_configure_build(runtime, str(alias))
            run_case("tmp-private-tmp-alias", tmp_alias)

    def test_validate_canonical_build_root_rejects_guarded_overlaps_after_name_checks(self):
        """A canonical expected build is still invalid if it overlaps any guarded root."""
        from scripts.work7_review_packet import Failure, validate_canonical_build_root

        parent = self.temporary / "canonical-overlap-checks"
        build = parent / ("build-" + self.commit)
        build.mkdir(parents=True)
        expected = str(build.resolve())
        for guarded in (build, parent, build / "guarded-descendant"):
            guarded.mkdir(exist_ok=True)
            with self.subTest(guarded=guarded):
                with self.assertRaisesRegex(Failure, "noncanonical build root"):
                    validate_canonical_build_root(expected, self.commit, (guarded.resolve(),), expected)

    def test_prepare_work_creates_deterministic_sealed_session_relative_packet(self):
        """Removing a required member or allowing absolute paths must break this behavior."""
        output = self.prepare_work()
        packet = json.loads(output.read_bytes())
        self.assertEqual(packet["schema"], "piccard-work7-review-packet-v1")
        self.assertEqual(packet["phase"], "work")
        self.assertEqual(packet["source_commit"], self.commit)
        self.assertRegex(hashlib.sha256(output.read_bytes()).hexdigest(), r"^[0-9a-f]{64}$")
        self.assertTrue(packet["members"])
        for member in packet["members"]:
            self.assertFalse(Path(member["path"]).is_absolute())
            self.assertTrue((self.session / member["path"]).is_file())
            self.assertEqual(member["sha256"], hashlib.sha256((self.session / member["path"]).read_bytes()).hexdigest())

    def test_close_work_rejects_header_only_approval_then_seals_raw_review(self):
        """Dropping a substantive check must not turn a header-only approval into a seal."""
        from scripts.work7_evidence import sha256_file, verify_tree_seal

        packet = self.prepare_work()
        missing = self.work_review(packet, checks=False)
        seal = self.session / "phase4/work-review-seal.json"
        rejected = self.command("close-work", "--packet", str(packet), "--raw-review", str(missing),
                                "--session-root", str(self.session), "--output-seal", str(seal))
        self.assertEqual(rejected.returncode, 2)
        self.assertFalse(seal.exists())
        approved = self.work_review(packet)
        closed = self.command("close-work", "--packet", str(packet), "--raw-review", str(approved),
                              "--session-root", str(self.session), "--output-seal", str(seal))
        self.assertEqual(closed.returncode, 0, closed.stderr.decode())
        value = verify_tree_seal(seal, sha256_file(self.session / "phase3/closure-seal.json"))
        self.assertEqual(value["kind"], "phase4-work-review")
        self.assertEqual((self.session / "phase4/work-review-artifacts/raw-review.txt").read_bytes(), approved.read_bytes())

    def test_close_work_rejects_missing_extra_or_recanonicalized_manifest_members(self):
        """A self-consistent but non-exact packet manifest is not reviewable evidence."""
        packet = self.prepare_work()
        original = json.loads(packet.read_bytes())
        for mutation in ("missing", "extra", "reordered", "label"):
            with self.subTest(mutation=mutation):
                value = json.loads(packet.read_bytes())
                if mutation == "missing":
                    value["members"].pop()
                elif mutation == "extra":
                    value["members"].append(dict(value["members"][0]))
                    value["members"][-1]["path"] = "phase4/members/extra.txt"
                    (self.session / "phase4/members/extra.txt").write_bytes(b"extra\n")
                    value["members"][-1]["size"] = 6
                    value["members"][-1]["sha256"] = hashlib.sha256(b"extra\n").hexdigest()
                else:
                    if mutation == "reordered":
                        value["members"].reverse()
                    else:
                        value["members"][0]["label"] = "different-provider-neutral-label"
                packet.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
                result = self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(self.session / "phase4/work-review-seal.json"))
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertFalse((self.session / "phase4/work-review-seal.json").exists())
                packet.write_bytes((json.dumps(original, sort_keys=True, separators=(",", ":")) + "\n").encode())

    def test_close_work_rejects_packet_seal_member_that_disagrees_with_prerequisite_digest(self):
        """A copied seal must be the exact seal named by the packet prerequisite chain."""
        packet = self.prepare_work()
        value = json.loads(packet.read_bytes())
        member = next(item for item in value["members"]
                      if item["path"] == "phase4/members/session/phase2/runtime-seal.json")
        hostile = b"hostile seal snapshot\n"
        copied = self.session / member["path"]
        copied.write_bytes(hostile)
        member["size"] = len(hostile)
        member["sha256"] = hashlib.sha256(hostile).hexdigest()
        packet.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())

        seal = self.session / "phase4/work-review-seal.json"
        result = self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                              "--session-root", str(self.session), "--output-seal", str(seal))
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(seal.exists())

    def test_final_close_binds_two_distinct_final_approvals_and_terminal_seal(self):
        """A duplicate provider or a final packet not bound to Phase 4 must fail closure."""
        from scripts.work7_evidence import sha256_file, verify_tree_seal

        final_packet = self.prepare_final_packet()
        summary = json.loads((self.session / "phase5/members/generated/final-verification-summary.json").read_bytes())
        from scripts.run_work7_integration import FROZEN_CTESTS

        source = self.source.resolve()
        build = (self.temporary / "builds" / ("build-" + self.commit)).resolve()
        runtime = (self.session / "phase2/runtime").resolve()
        regex = "^(" + "|".join(FROZEN_CTESTS) + ")$"
        argv = {
            "ctest_focused": ["ctest", "--test-dir", str(build), "--output-on-failure", "-R", regex],
            "pre_threshold": [str(source / "scripts/run_pre_threshold_profiles.sh"), "--suite=smoke", "--seed=7", "--threads=2",
                              "--build-dir=" + str(build), "--results-root=" + str(runtime / "pre-threshold")],
            "real_datasets": [str(source / "scripts/run_real_datasets.sh"), "--quick", "--seed=7", "--threads=2",
                              "--build-dir=" + str(build), "--results-root=" + str(runtime / "real-datasets")],
            "deletion_survival": [str(build / "bench_deletion_survival"), "--n=64", "--d=3", "--k=8",
                                   "--required_survival=0.99", "--r_values=1,4,8", "--trials=1", "--seed=7"],
        }
        expected_digests = {
            name: hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()).hexdigest()
            for name, value in argv.items()
        }
        self.assertEqual(summary["source_commit"], self.commit)
        self.assertEqual(summary["registry_test_count"], len(FROZEN_CTESTS))
        self.assertEqual(summary["registry_pass_count"], len(FROZEN_CTESTS))
        self.assertEqual(summary["registry_skip_count"], 0)
        self.assertEqual(summary["toy_argv_sha256"], expected_digests)
        self.assertEqual(summary["measured_count_policy"], "PASS")
        self.assertTrue(summary["external_snapshot_equality"])
        claude, sol = self.final_review(final_packet, "anthropic"), self.final_review(final_packet, "openai")
        terminal, seal = self.session / "phase5/terminal-report.json", self.session / "phase5/terminal-seal.json"
        closed = self.close_final(final_packet, claude, sol, terminal, seal)
        self.assertEqual(closed.returncode, 0, closed.stderr.decode())
        self.assertEqual(closed.stdout.decode(), f"WORK7_TERMINAL_SEAL_SHA256={sha256_file(seal)}\n")
        self.assertEqual((self.session / "phase5/terminal-seal.sha256").read_text(), sha256_file(seal) + "\n")
        self.assertEqual(verify_tree_seal(seal, sha256_file(self.session / "phase4/work-review-seal.json"))["kind"], "phase5-terminal")

    def test_close_final_rolls_back_every_caught_phase5_publication_failure(self):
        """Real Phase 5 collisions restore the complete pre-call byte graph."""
        from scripts import work7_review_packet

        packet = self.prepare_final_packet()
        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        capture = work7_review_packet.capture_phase04(self.session, self.source, self.paper, self.threshold)
        inputs = work7_review_packet._terminal_inputs_capture(self.session, packet, claude, sol, capture)
        try:
            from scripts.verify_work7_claims import terminal_report_bytes
        except ModuleNotFoundError:
            from verify_work7_claims import terminal_report_bytes
        report_raw = terminal_report_bytes(inputs)
        phase5_baseline = self.temporary / "phase5-publication-baseline"
        shutil.copytree(self.session / "phase5", phase5_baseline)
        predecessor = hashlib.sha256((self.session / "phase4/work-review-seal.json").read_bytes()).hexdigest()

        def restore_phase5() -> None:
            shutil.rmtree(self.session / "phase5")
            shutil.copytree(phase5_baseline, self.session / "phase5")

        for name, prepare in (
                ("report", lambda report, seal: report.write_bytes(b"report sentinel\n")),
                ("artifacts-after-report", lambda report, seal: (report.parent / "terminal-artifacts").mkdir()),
                ("pointer-after-seal", lambda report, seal: seal.with_name("terminal-seal.sha256").write_bytes(b"pointer sentinel\n")),
        ):
            with self.subTest(boundary=name):
                restore_phase5()
                report = self.session / "phase5/terminal-report.json"
                seal = self.session / "phase5/terminal-seal.json"
                prepare(report, seal)
                before = self._phase5_snapshot()
                with self.assertRaises((work7_review_packet.Failure, OSError, ValueError, FileExistsError)):
                    work7_review_packet.publish_phase5(
                        self.session, report, seal, inputs.final_packet.raw, inputs.claude_review.raw,
                        inputs.sol_review.raw, report_raw, predecessor)
                self.assertEqual(self._phase5_snapshot(), before)

    def test_terminal_core_matches_cli_report_from_identical_captured_bytes(self):
        """The standalone terminal CLI is only a capture/publish wrapper around the core."""
        from scripts.verify_work7_claims import TerminalInputs, terminal_report_bytes
        from scripts.work7_evidence import CapturedBlob
        from scripts.work7_review_packet import capture_phase04

        packet = self.prepare_final_packet()
        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        capture = capture_phase04(self.session, self.source, self.paper, self.threshold)
        packet_raw = packet.read_bytes()
        packet_value = json.loads(packet_raw)
        members = tuple((entry["path"], CapturedBlob(
            raw=(self.session / entry["path"]).read_bytes(), sha256=entry["sha256"],
            size=entry["size"], mode="0600")) for entry in packet_value["members"])
        core = terminal_report_bytes(TerminalInputs(
            phase04=capture, final_packet=CapturedBlob(packet_raw, hashlib.sha256(packet_raw).hexdigest(), len(packet_raw), "0600"),
            final_packet_members=members,
            claude_review=CapturedBlob(claude.read_bytes(), hashlib.sha256(claude.read_bytes()).hexdigest(), claude.stat().st_size, "0600"),
            sol_review=CapturedBlob(sol.read_bytes(), hashlib.sha256(sol.read_bytes()).hexdigest(), sol.stat().st_size, "0600"),
        ))
        terminal = self.session / "phase5/core-cli-report.json"
        result = subprocess.run((sys.executable, str(ROOT / "scripts/verify_work7_claims.py"), "--mode", "terminal",
                                 "--contract", str(self.source / "scripts/work7_claims.json"), "--source-root", str(self.source),
                                 "--source-commit", self.commit, "--ctest-inventory", str(self.session / "phase2/runtime/commands/ctest-inventory.stdout.txt"),
                                 "--output", str(terminal), "--phase3-closure-seal", str(self.session / "phase3/closure-seal.json"),
                                 "--work-review-seal", str(self.session / "phase4/work-review-seal.json"), "--review-packet", str(packet),
                                 "--claude-review", str(claude), "--sol-review", str(sol), "--phase0-seal", str(self.session / "phase0/seal.json"),
                                 "--paper-root", str(self.paper), "--threshold-root", str(self.threshold)), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(terminal.read_bytes(), core)

    def test_terminal_core_rejects_self_consistent_unsealed_minimal_work_packet(self):
        """A Work packet must equal the Phase 4 seal-owned packet bytes, not just parse."""
        from scripts.verify_work7_claims import Failure, TerminalInputs, terminal_report_bytes
        from scripts.work7_evidence import CapturedBlob, canonical_json_bytes
        from scripts.work7_review_packet import capture_phase04

        packet = self.prepare_final_packet()
        capture = capture_phase04(self.session, self.source, self.paper, self.threshold)
        seals = {name: seal.blob.sha256 for name, seal in capture.seals}
        forged_work = canonical_json_bytes({"schema": "piccard-work7-review-packet-v1", "phase": "work",
                                             "source_commit": self.commit,
                                             "prerequisite_seals": {name: seals[name] for name in tuple(seals)[:-1]},
                                             "members": []})
        forged_work_blob = CapturedBlob(forged_work, hashlib.sha256(forged_work).hexdigest(), len(forged_work), "0600")
        work_review = REVIEW_FIXTURES.joinpath("work-approved.template.txt").read_text(encoding="utf-8").format(
            SOURCE_COMMIT=self.commit, PACKET_SHA256=forged_work_blob.sha256).encode()
        forged_capture = replace(capture, phase4_packet=forged_work_blob,
                                 phase4_review=CapturedBlob(work_review, hashlib.sha256(work_review).hexdigest(), len(work_review), "0600"))
        packet_value = json.loads(packet.read_bytes())
        members = {entry["path"]: CapturedBlob((self.session / entry["path"]).read_bytes(), entry["sha256"], entry["size"], "0600")
                   for entry in packet_value["members"]}
        path = "phase5/members/session/phase4/work-review-artifacts/work-packet.json"
        members[path] = forged_work_blob
        entry = next(item for item in packet_value["members"] if item["path"] == path)
        entry.update(size=forged_work_blob.size, sha256=forged_work_blob.sha256)
        review_path = "phase5/members/session/phase4/work-review-artifacts/raw-review.txt"
        forged_review_blob = CapturedBlob(work_review, hashlib.sha256(work_review).hexdigest(), len(work_review), "0600")
        members[review_path] = forged_review_blob
        review_entry = next(item for item in packet_value["members"] if item["path"] == review_path)
        review_entry.update(size=forged_review_blob.size, sha256=forged_review_blob.sha256)
        packet_raw = canonical_json_bytes(packet_value)
        packet_blob = CapturedBlob(packet_raw, hashlib.sha256(packet_raw).hexdigest(), len(packet_raw), "0600")
        claude = self.final_review(packet, "anthropic").read_bytes().replace(hashlib.sha256(packet.read_bytes()).hexdigest().encode(), packet_blob.sha256.encode())
        sol = self.final_review(packet, "openai").read_bytes().replace(hashlib.sha256(packet.read_bytes()).hexdigest().encode(), packet_blob.sha256.encode())
        with self.assertRaises(Failure):
            terminal_report_bytes(TerminalInputs(forged_capture, packet_blob, tuple(members.items()),
                                                  CapturedBlob(claude, hashlib.sha256(claude).hexdigest(), len(claude), "0600"),
                                                  CapturedBlob(sol, hashlib.sha256(sol).hexdigest(), len(sol), "0600")))

    def test_close_final_revalidates_packet_members_before_publication(self):
        """A packet manifest that names a missing member cannot create terminal output."""
        packet = self.prepare_final_packet()
        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        victim = self.session / "phase5/members/generated/final-verification-summary.json"
        victim.unlink()
        terminal, seal = self.session / "phase5/missing-member-report.json", self.session / "phase5/missing-member-seal.json"
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(terminal.exists())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())

    def test_close_final_rejects_recanonicalized_generated_summary(self):
        """A self-consistent final packet cannot replace the verified generated summary."""
        packet = self.prepare_final_packet()
        summary = self.session / "phase5/members/generated/final-verification-summary.json"
        value = json.loads(summary.read_bytes())
        value["registry_pass_count"] = 0
        summary_raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        summary.write_bytes(summary_raw)
        packet_value = json.loads(packet.read_bytes())
        member = next(item for item in packet_value["members"]
                      if item["path"] == "phase5/members/generated/final-verification-summary.json")
        member["size"] = len(summary_raw)
        member["sha256"] = hashlib.sha256(summary_raw).hexdigest()
        packet.write_bytes((json.dumps(packet_value, sort_keys=True, separators=(",", ":")) + "\n").encode())

        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/forged-summary-report.json", self.session / "phase5/forged-summary-seal.json"
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(terminal.exists())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())

    def test_close_final_rejects_recanonicalized_generated_source_test_map(self):
        """A self-consistent final packet cannot replace the verified source/test map."""
        packet = self.prepare_final_packet()
        mapping = self.session / "phase5/members/generated/works1-6-source-test-map.json"
        value = json.loads(mapping.read_bytes())
        value["claims"][0]["required_ctest_names"] = []
        mapping_raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        mapping.write_bytes(mapping_raw)
        packet_value = json.loads(packet.read_bytes())
        member = next(item for item in packet_value["members"]
                      if item["path"] == "phase5/members/generated/works1-6-source-test-map.json")
        member["size"] = len(mapping_raw)
        member["sha256"] = hashlib.sha256(mapping_raw).hexdigest()
        packet.write_bytes((json.dumps(packet_value, sort_keys=True, separators=(",", ":")) + "\n").encode())

        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/forged-map-report.json", self.session / "phase5/forged-map-seal.json"
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(terminal.exists())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())

    def test_close_final_does_not_reopen_phase3_or_phase4_after_capture(self):
        """A Phase 4 replacement after capture cannot alter the byte-only terminal core."""
        from scripts import work7_review_packet
        from scripts.work7_evidence import create_tree_seal, sha256_file

        packet = self.prepare_final_packet()
        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        work_seal = self.session / "phase4/work-review-seal.json"
        terminal, seal = self.session / "phase5/raced-report.json", self.session / "phase5/raced-seal.json"
        original_validate_runtime = work7_review_packet.validate_phase2_runtime_capture

        def replace_phase4_after_runtime(*arguments):
            summary = original_validate_runtime(*arguments)
            artifacts = self.session / "phase4/work-review-artifacts"
            (artifacts / "foreign.txt").write_text("hostile\n", encoding="utf-8")
            work_seal.unlink()
            create_tree_seal(artifacts, work_seal, sha256_file(self.session / "phase3/closure-seal.json"),
                             "phase4-work-review")
            return summary

        args = Namespace(packet=packet, claude_review=claude, sol_review=sol, terminal_report=terminal,
                         session_root=self.session, phase0_seal=self.session / "phase0/seal.json", source_root=self.source,
                         paper_root=self.paper, threshold_root=self.threshold, output_seal=seal)
        with mock.patch.object(work7_review_packet, "validate_phase2_runtime_capture", side_effect=replace_phase4_after_runtime):
            work7_review_packet.close_final(args)
        self.assertTrue(terminal.exists())
        self.assertTrue((self.session / "phase5/terminal-artifacts").exists())
        self.assertTrue(seal.exists())

    def test_close_final_reaches_terminal_boundary_without_legacy_phase_paths(self):
        """A valid captured closure does not invoke any retired Phase 0--4 path reader."""
        from scripts import work7_review_packet

        packet = self.prepare_final_packet()
        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/captured-report.json", self.session / "phase5/captured-seal.json"
        args = Namespace(packet=packet, claude_review=claude, sol_review=sol, terminal_report=terminal,
                         session_root=self.session, phase0_seal=self.session / "phase0/seal.json", source_root=self.source,
                         paper_root=self.paper, threshold_root=self.threshold, output_seal=seal)

        def legacy_path(*_args, **_kwargs):
            raise AssertionError("legacy Phase 0--4 path reader was called")

        with mock.patch.multiple(work7_review_packet, phase0=legacy_path, chain=legacy_path,
                                 validate_phase4=legacy_path, validate_phase2_runtime=legacy_path,
                                 final_generated_member_bytes=legacy_path, create=True):
            work7_review_packet.close_final(args)
        self.assertTrue(terminal.exists())
        self.assertTrue(seal.exists())

    def test_close_final_generated_members_remain_captured_while_live_inputs_are_transiently_foreign(self):
        """Foreign live contract/inventory/external bytes after capture cannot enter final-member validation."""
        from scripts import work7_review_packet

        packet = self.prepare_final_packet()
        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/transient-report.json", self.session / "phase5/transient-seal.json"
        args = Namespace(packet=packet, claude_review=claude, sol_review=sol, terminal_report=terminal,
                         session_root=self.session, phase0_seal=self.session / "phase0/seal.json", source_root=self.source,
                         paper_root=self.paper, threshold_root=self.threshold, output_seal=seal)
        contract = self.source / "scripts/work7_claims.json"
        inventory = self.session / "phase2/runtime/commands/ctest-inventory.stdout.txt"
        paper_file = self.paper / "tracked"
        originals = {path: path.read_bytes() for path in (contract, inventory, paper_file)}
        modes = {path: path.stat().st_mode & 0o777 for path in originals}
        original_capture = work7_review_packet.capture_phase04
        seen_foreign = False

        def replace(path: Path, raw: bytes) -> None:
            replacement = path.with_name(path.name + ".foreign")
            replacement.write_bytes(raw)
            os.chmod(replacement, modes[path])
            os.replace(replacement, path)

        def restore() -> None:
            for path, raw in originals.items():
                replace(path, raw)

        def capture_then_replace(*capture_args):
            capture = original_capture(*capture_args)
            replace(contract, b'{"foreign":"contract"}\n')
            replace(inventory, b"Test #1: Foreign\nTotal Tests: 1\n")
            replace(paper_file, b"foreign external state\n")
            return capture

        def synchronize(point: str):
            nonlocal seen_foreign
            if point == "after_terminal_capture":
                self.assertEqual(contract.read_bytes(), b'{"foreign":"contract"}\n')
                self.assertEqual(inventory.read_bytes(), b"Test #1: Foreign\nTotal Tests: 1\n")
                self.assertEqual(paper_file.read_bytes(), b"foreign external state\n")
                seen_foreign = True
            elif point == "after_terminal_core":
                restore()

        with mock.patch.object(work7_review_packet, "capture_phase04", side_effect=capture_then_replace):
            work7_review_packet.close_final(args, synchronize=synchronize)
        self.assertTrue(seen_foreign)
        self.assertTrue(terminal.exists())
        self.assertTrue(seal.exists())

    def test_work_review_rejects_every_header_identity_and_check_mutation(self):
        """A parser that accepts one mutated Work approval would create a Phase 4 seal."""
        packet = self.prepare_work()
        original = self.work_review(packet).read_text(encoding="utf-8")
        mutations = {
            "verdict": lambda value: value.replace("VERDICT: APPROVED", "VERDICT: APPROVED_WITH_COMMENTS"),
            "provider": lambda value: value.replace("PROVIDER: openai", "PROVIDER: anthropic"),
            "model": lambda value: value.replace("MODEL: gpt-5.6-sol", "MODEL: gpt-5.5"),
            "effort": lambda value: value.replace("EFFORT: high", "EFFORT: medium"),
            "commit": lambda value: value.replace(self.commit, "0" * 40),
            "packet": lambda value: value.replace(hashlib.sha256(packet.read_bytes()).hexdigest(), "0" * 64),
            "status": lambda value: value.replace("STATUS: WORK7_APPROVED", "STATUS: PENDING"),
            "duplicate-header": lambda value: value + "PROVIDER: openai\n",
            "missing-check": lambda value: value.replace("CHECK NO_OVERCLAIM: CONFIRMED\n", ""),
            "duplicate-check": lambda value: value + "CHECK NO_OVERCLAIM: CONFIRMED\n",
        }
        for check in ("POC_SCOPE", "ONE_RUN_POLICY", "PROVENANCE", "FAIL_CLOSED", "EXTERNAL_IMMUTABILITY", "NO_OVERCLAIM"):
            mutations[f"missing-{check}"] = lambda value, check=check: value.replace(f"CHECK {check}: CONFIRMED\n", "")
            mutations[f"duplicate-{check}"] = lambda value, check=check: value + f"CHECK {check}: CONFIRMED\n"
        seal = self.session / "phase4/work-review-seal.json"
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                review = self.temporary / f"work-{name}.txt"
                review.write_text(mutate(original), encoding="utf-8")
                result = self.command("close-work", "--packet", str(packet), "--raw-review", str(review),
                                      "--session-root", str(self.session), "--output-seal", str(seal))
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertFalse(seal.exists())

    def test_final_review_matrix_rejects_header_identity_checks_and_duplicate_provider(self):
        """Any final approval mutation, including two Sol reviews, must prevent Phase 5."""
        packet = self.prepare_final_packet()
        claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        original = claude.read_text(encoding="utf-8")
        mutations = {
            "verdict": lambda value: value.replace("VERDICT: APPROVED", "VERDICT: APPROVED_WITH_COMMENTS"),
            "provider": lambda value: value.replace("PROVIDER: anthropic", "PROVIDER: foreign"),
            "model": lambda value: value.replace("MODEL: claude-fable", "MODEL: claude-other"),
            "effort": lambda value: value.replace("EFFORT: high", "EFFORT: low"),
            "commit": lambda value: value.replace(self.commit, "0" * 40),
            "packet": lambda value: value.replace(hashlib.sha256(packet.read_bytes()).hexdigest(), "0" * 64),
            "status": lambda value: value.replace("STATUS: POC_APPROVED_PERFORMANCE_PENDING", "STATUS: PENDING"),
            "duplicate-header": lambda value: value + "MODEL: claude-fable\n",
            "missing-check": lambda value: value.replace("CHECK G1_G7_INTENT: CONFIRMED\n", ""),
            "duplicate-check": lambda value: value + "CHECK G1_G7_INTENT: CONFIRMED\n",
        }
        for check in ("G1_G7_INTENT", "EVIDENCE_FRESHNESS", "PERFORMANCE_PENDING", "THRESHOLD_DEFERRED",
                      "EXTERNAL_IMMUTABILITY", "TERMINAL_STATUS_MAXIMAL"):
            mutations[f"missing-{check}"] = lambda value, check=check: value.replace(f"CHECK {check}: CONFIRMED\n", "")
            mutations[f"duplicate-{check}"] = lambda value, check=check: value + f"CHECK {check}: CONFIRMED\n"
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                bad = self.temporary / f"claude-{name}.txt"; bad.write_text(mutate(original), encoding="utf-8")
                terminal, seal = self.session / f"phase5/{name}-report.json", self.session / f"phase5/{name}-seal.json"
                result = self.close_final(packet, bad, sol, terminal, seal)
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())
        duplicate = self.temporary / "duplicate-sol.txt"; duplicate.write_bytes(sol.read_bytes())
        terminal, seal = self.session / "phase5/duplicate-report.json", self.session / "phase5/duplicate-seal.json"
        rejected = self.close_final(packet, duplicate, sol, terminal, seal)
        self.assertEqual(rejected.returncode, 2, rejected.stderr.decode())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())
        terminal, seal = self.session / "phase5/reversed-report.json", self.session / "phase5/reversed-seal.json"
        reversed_result = self.close_final(packet, sol, claude, terminal, seal)
        self.assertEqual(reversed_result.returncode, 0, reversed_result.stderr.decode())

    def test_prepare_final_rejects_resealed_phase4_member_mutation(self):
        """A self-consistent replacement Phase 4 seal cannot introduce an extra member."""
        from scripts.work7_evidence import create_tree_seal, sha256_file

        packet = self.prepare_work(); work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        root = self.session / "phase4/work-review-artifacts"; (root / "foreign.txt").write_text("hostile\n", encoding="utf-8")
        work_seal.unlink()
        create_tree_seal(root, work_seal, sha256_file(self.session / "phase3/closure-seal.json"), "phase4-work-review")
        output = self.session / "phase5/final-packet.json"
        result = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                              "--work-review-seal", str(work_seal), "--output", str(output))
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(output.exists())

    def test_capture_phase04_rejects_resealed_extra_and_missing_phase0_through3_members(self):
        """Every Phase 0--3 manifest has one fixed, complete member set."""
        from scripts.work7_evidence import create_tree_seal, sha256_file
        from scripts.work7_review_packet import Failure, capture_phase04

        packet = self.prepare_work(); work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        phases = (
            ("phase0", "phase0/artifacts", "state.json"),
            ("runtime", "phase2/runtime", "commands/build.json"),
            ("candidate", "phase3/candidate-artifacts", "ResponseStrategy.candidate.md"),
            ("closure", "phase3/closure-artifacts", "claim7-report.json"),
        )

        def reseal_chain(session: Path) -> None:
            chain = (
                ("phase0/seal.json", "phase0/artifacts", "phase0", None),
                ("phase2/runtime-seal.json", "phase2/runtime", "phase2-runtime-artifacts", "phase0/seal.json"),
                ("phase2/closure-seal.json", "phase2/closure-artifacts", "phase2-closure", "phase2/runtime-seal.json"),
                ("phase3/candidate-seal.json", "phase3/candidate-artifacts", "phase3-candidate-artifacts", "phase2/closure-seal.json"),
                ("phase3/closure-seal.json", "phase3/closure-artifacts", "phase3-closure", "phase3/candidate-seal.json"),
                ("phase4/work-review-seal.json", "phase4/work-review-artifacts", "phase4-work-review", "phase3/closure-seal.json"),
            )
            for seal_relative, root_relative, kind, previous_relative in chain:
                seal = session / seal_relative
                seal.unlink()
                previous = None if previous_relative is None else sha256_file(session / previous_relative)
                create_tree_seal(session / root_relative, seal, previous, kind)

        for phase, root_relative, missing_relative in phases:
            for mutation in ("extra", "missing"):
                with self.subTest(phase=phase, mutation=mutation):
                    trial = self.temporary / f"resealed-{phase}-{mutation}"
                    shutil.copytree(self.session, trial)
                    root = trial / root_relative
                    if mutation == "extra":
                        (root / "hostile-extra.txt").write_bytes(b"hostile member\n")
                    else:
                        (root / missing_relative).unlink()
                    reseal_chain(trial)
                    with self.assertRaises(Failure):
                        capture_phase04(trial, self.source)

    def test_capture_phase04_accepts_production_named_runtime_members_and_rejects_member_drift(self):
        """Runtime membership is derived from sealed producer records, not fixture toy names."""
        from scripts.work7_evidence import create_tree_seal, sha256_file
        from scripts.work7_review_packet import Failure, capture_phase04

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)

        def reseal_chain(session: Path) -> None:
            for seal_relative, root_relative, kind, previous_relative in (
                ("phase0/seal.json", "phase0/artifacts", "phase0", None),
                ("phase2/runtime-seal.json", "phase2/runtime", "phase2-runtime-artifacts", "phase0/seal.json"),
                ("phase2/closure-seal.json", "phase2/closure-artifacts", "phase2-closure", "phase2/runtime-seal.json"),
                ("phase3/candidate-seal.json", "phase3/candidate-artifacts", "phase3-candidate-artifacts", "phase2/closure-seal.json"),
                ("phase3/closure-seal.json", "phase3/closure-artifacts", "phase3-closure", "phase3/candidate-seal.json"),
                ("phase4/work-review-seal.json", "phase4/work-review-artifacts", "phase4-work-review", "phase3/closure-seal.json"),
            ):
                seal = session / seal_relative
                seal.unlink()
                previous = None if previous_relative is None else sha256_file(session / previous_relative)
                create_tree_seal(session / root_relative, seal, previous, kind)

        runtime = self.session / "phase2/runtime"
        manifest_path = runtime / "pre-threshold/manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        for cell in manifest["cells"]:
            producer, digest = cell["producer"], cell["parameter_sha256"]
            for field, directory, suffix in (("csv", "csv", ".csv"), ("log", "logs", ".log"),
                                             ("workload", "workloads", ".manifest.tsv"), ("trace", "traces", ".bin")):
                if field not in cell["output"]:
                    continue
                old = runtime / "pre-threshold" / cell["output"][field]
                relative = f"{directory}/toy-smoke/{producer}/{digest}{suffix}"
                new = runtime / "pre-threshold" / relative
                new.parent.mkdir(parents=True, exist_ok=True)
                old.rename(new)
                cell["output"][field] = relative
        manifest_path.write_bytes((json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
        # The old fixture's aggregate timing.csv is not a producer artifact.
        stale_timing = runtime / "pre-threshold/timing.csv"
        if stale_timing.exists():
            stale_timing.unlink()
        reseal_chain(self.session)

        # This was rejected by the obsolete PHASE2_RUNTIME_SEAL_MEMBERS fixture set.
        capture_phase04(self.session, self.source)
        production_member = next((runtime / "pre-threshold/csv").rglob("*.csv"))
        for mutation in ("extra", "missing"):
            with self.subTest(mutation=mutation):
                trial = self.temporary / f"production-runtime-{mutation}"
                shutil.copytree(self.session, trial)
                trial_runtime = trial / "phase2/runtime"
                if mutation == "extra":
                    (trial_runtime / "pre-threshold/csv/toy-smoke/bench_piccard/foreign.csv").write_bytes(b"foreign\n")
                else:
                    (trial_runtime / "pre-threshold" / production_member.relative_to(runtime / "pre-threshold")).unlink()
                reseal_chain(trial)
                with self.assertRaises(Failure):
                    capture_phase04(trial, self.source)

    def test_capture_phase04_rejects_resealed_production_output_alias(self):
        """Each pre-threshold producer role must bind a distinct sealed artifact."""
        from scripts.work7_evidence import create_tree_seal, sha256_file
        from scripts.work7_review_packet import Failure, capture_phase04

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)

        def reseal_chain() -> None:
            for seal_relative, root_relative, kind, previous_relative in (
                ("phase0/seal.json", "phase0/artifacts", "phase0", None),
                ("phase2/runtime-seal.json", "phase2/runtime", "phase2-runtime-artifacts", "phase0/seal.json"),
                ("phase2/closure-seal.json", "phase2/closure-artifacts", "phase2-closure", "phase2/runtime-seal.json"),
                ("phase3/candidate-seal.json", "phase3/candidate-artifacts", "phase3-candidate-artifacts", "phase2/closure-seal.json"),
                ("phase3/closure-seal.json", "phase3/closure-artifacts", "phase3-closure", "phase3/candidate-seal.json"),
                ("phase4/work-review-seal.json", "phase4/work-review-artifacts", "phase4-work-review", "phase3/closure-seal.json"),
            ):
                seal = self.session / seal_relative
                seal.unlink()
                previous = None if previous_relative is None else sha256_file(self.session / previous_relative)
                create_tree_seal(self.session / root_relative, seal, previous, kind)

        runtime = self.session / "phase2/runtime"
        manifest_path = runtime / "pre-threshold/manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        cell = next(item for item in manifest["cells"] if item["producer"] == "bench_piccard")
        old_log = runtime / "pre-threshold" / cell["output"]["log"]
        cell["output"]["log"] = cell["output"]["csv"]
        cell["output"]["log_sha256"] = cell["output"]["csv_sha256"]
        old_log.unlink()
        terminal_path = runtime / "pre-threshold/terminal-cells.tsv"
        terminal = terminal_path.read_text(encoding="utf-8").replace(
            hashlib.sha256(b"log").hexdigest(), cell["output"]["csv_sha256"])
        terminal_path.write_text(terminal, encoding="utf-8")
        manifest["terminal_cells"]["sha256"] = hashlib.sha256(terminal.encode()).hexdigest()
        manifest_path.write_bytes((json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
        reseal_chain()

        # A path-only set comparison accepted this alias before logical roles were counted.
        with self.assertRaises(Failure):
            capture_phase04(self.session, self.source)

    def test_capture_phase04_rejects_production_output_alias_to_fixed_member(self):
        """A producer role may not reuse a fixed runtime manifest/status member."""
        from scripts.work7_evidence import create_tree_seal, sha256_file
        from scripts.work7_review_packet import Failure, capture_phase04

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)

        def reseal_chain() -> None:
            for seal_relative, root_relative, kind, previous_relative in (
                ("phase0/seal.json", "phase0/artifacts", "phase0", None),
                ("phase2/runtime-seal.json", "phase2/runtime", "phase2-runtime-artifacts", "phase0/seal.json"),
                ("phase2/closure-seal.json", "phase2/closure-artifacts", "phase2-closure", "phase2/runtime-seal.json"),
                ("phase3/candidate-seal.json", "phase3/candidate-artifacts", "phase3-candidate-artifacts", "phase2/closure-seal.json"),
                ("phase3/closure-seal.json", "phase3/closure-artifacts", "phase3-closure", "phase3/candidate-seal.json"),
                ("phase4/work-review-seal.json", "phase4/work-review-artifacts", "phase4-work-review", "phase3/closure-seal.json"),
            ):
                seal = self.session / seal_relative
                seal.unlink()
                previous = None if previous_relative is None else sha256_file(self.session / previous_relative)
                create_tree_seal(self.session / root_relative, seal, previous, kind)

        runtime = self.session / "phase2/runtime"
        manifest_path = runtime / "pre-threshold/manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        cell = next(item for item in manifest["cells"] if item["producer"] == "bench_piccard")
        old_csv = runtime / "pre-threshold" / cell["output"]["csv"]
        fixed = runtime / "pre-threshold/terminal-cells.tsv"
        cell["output"]["csv"] = "terminal-cells.tsv"
        cell["output"]["csv_sha256"] = hashlib.sha256(fixed.read_bytes()).hexdigest()
        old_csv.unlink()
        manifest_path.write_bytes((json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
        reseal_chain()

        # A path-only dynamic-role uniqueness check previously accepted this fixed-member alias.
        with self.assertRaises(Failure):
            capture_phase04(self.session, self.source)

    def test_prepare_final_never_publishes_transient_source_packet_bytes(self):
        """A restored source file cannot replace the first captured source packet bytes."""
        from scripts import work7_review_packet
        from scripts.work7_review_packet import SOURCE_PACKET_MEMBERS, capture_phase04

        packet = self.prepare_work(); work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        expected_capture = capture_phase04(self.session, self.source)
        target = self.source / "docs/superpowers/specs/2026-08-06-work7-phase0-state-guard-design.md"
        original, mode = target.read_bytes(), target.stat().st_mode & 0o777
        foreign = b"transient foreign source packet bytes\n"
        reached: list[str] = []

        def synchronize(point: str) -> None:
            if point == "after_first_capture":
                replacement = target.with_name(target.name + ".foreign")
                replacement.write_bytes(foreign)
                os.chmod(replacement, mode)
                os.replace(replacement, target)
                reached.append(point)
            elif point == "before_second_capture":
                restore = target.with_name(target.name + ".restore")
                restore.write_bytes(original)
                os.chmod(restore, mode)
                os.replace(restore, target)
                reached.append(point)

        output = self.session / "phase5/final-packet.json"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = work7_review_packet.main(["prepare-final", "--source-root", str(self.source),
                                                "--session-root", str(self.session), "--work-review-seal", str(work_seal),
                                                "--output", str(output)], synchronize=synchronize)
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertEqual(reached, ["after_first_capture", "before_second_capture"])
        value = json.loads(output.read_bytes())
        member = next(item for item in value["members"]
                      if item["path"] == "phase5/members/source/docs/superpowers/specs/2026-08-06-work7-phase0-state-guard-design.md")
        published = self.session / member["path"]
        self.assertEqual(published.read_bytes(), original)
        self.assertNotEqual(published.read_bytes(), foreign)
        self.assertEqual(member["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(published.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        public = dict(expected_capture.packet_members)
        for relative in SOURCE_PACKET_MEMBERS:
            blob = public["@public/source/" + relative]
            path = self.session / "phase5/members/source" / relative
            self.assertEqual(path.read_bytes(), blob.raw)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        diff = self.session / "phase5/members/source/git-diff-b907fae-to-head.patch"
        self.assertEqual(diff.read_bytes(), public["@public/git-diff-b907fae-to-head.patch"].raw)
        self.assertEqual(diff.stat().st_mode & 0o777, 0o600)
        self.assertTrue(any(name.startswith("@source/") for name, _ in expected_capture.packet_members))
        self.assertFalse(any("@" in item["path"] for item in value["members"]))

    def test_phase04_capture_preserves_the_fixed_public_interface_and_never_publishes_private_members(self):
        """Private capture entries stay inside packet_members, not the Phase04 API or packet."""
        from dataclasses import fields, replace
        from scripts.work7_review_packet import SOURCE_PACKET_MEMBERS, capture_phase04

        packet = self.prepare_work(); work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source)
        self.assertEqual(tuple(field.name for field in fields(capture)), (
            "commit", "state_raw", "contract_raw", "ctest_inventory_raw", "seals", "packet_members",
            "build_binaries", "phase4_packet", "phase4_review", "source_snapshot_raw", "paper_snapshot_raw",
            "threshold_snapshot_raw"))
        self.assertEqual(replace(capture), capture)
        private = dict(capture.packet_members)
        self.assertTrue(all("@public/source/" + path in private for path in SOURCE_PACKET_MEMBERS))
        self.assertIn("@public/git-diff-b907fae-to-head.patch", private)
        self.assertTrue(any(name.startswith("@source/") for name in private))
        output = self.session / "phase5/final-packet.json"
        prepared = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                                "--work-review-seal", str(work_seal), "--output", str(output))
        self.assertEqual(prepared.returncode, 0, prepared.stderr.decode())
        self.assertFalse(any("@" in member["path"] for member in json.loads(output.read_bytes())["members"]))

    def test_prepare_final_rejects_self_consistent_foreign_producer_roots(self):
        """The runtime seal's artifact root, not a suffix, authorizes producer outputs."""
        from scripts.run_work7_integration import real_argv_sha256

        def replace_path(value: object, actual: str, foreign: str) -> object:
            if isinstance(value, str):
                return value.replace(actual, foreign)
            if isinstance(value, list):
                return [replace_path(item, actual, foreign) for item in value]
            if isinstance(value, dict):
                return {key: replace_path(item, actual, foreign) for key, item in value.items()}
            return value

        for producer in ("pre-threshold", "real-datasets"):
            with self.subTest(producer=producer):
                # Each hostile graph gets a fresh Phase 4/5 publication area;
                # the prior subtest intentionally left its rejected work gate.
                shutil.rmtree(self.session / "phase4", ignore_errors=True)
                shutil.rmtree(self.session / "phase5", ignore_errors=True)
                def mutate(runtime: Path, producer: str = producer) -> None:
                    actual = str(runtime / producer)
                    foreign = str(self.temporary / "foreign" / "phase2" / "runtime" / producer)
                    command = runtime / "commands" / (producer + ".json")
                    command_value = replace_path(json.loads(command.read_bytes()), actual, foreign)
                    command.write_bytes((json.dumps(command_value, sort_keys=True, separators=(",", ":")) + "\n").encode())
                    if producer == "pre-threshold":
                        manifest = runtime / "pre-threshold/manifest.json"
                        value = replace_path(json.loads(manifest.read_bytes()), actual, foreign)
                        manifest.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
                    else:
                        metadata = runtime / "real-datasets/run_metadata.tsv"
                        rows = [line.split("\t", 1) for line in metadata.read_text(encoding="utf-8").splitlines()]
                        values = {key: value.replace(actual, foreign) for key, value in rows[1:]}
                        for number in range(3):
                            prefix = f"cell.{number:03d}."
                            count = int(values[prefix + "argv_count"])
                            argv = [values[prefix + f"argv.{index:03d}"] for index in range(count)]
                            values[prefix + "argv_sha256"] = real_argv_sha256(argv)
                        metadata.write_text("key\tvalue\n" + "".join(key + "\t" + values[key] + "\n" for key, _ in rows[1:]), encoding="utf-8")
                        status = runtime / "real-datasets/verification_status.tsv"
                        status_values = dict(line.split("\t", 1) for line in status.read_text(encoding="utf-8").splitlines()[1:])
                        status_values["run_metadata_sha256"] = hashlib.sha256(metadata.read_bytes()).hexdigest()
                        status.write_text("key\tvalue\n" + "".join(key + "\t" + status_values[key] + "\n" for key in ("schema_version", "run_metadata_sha256", "status")), encoding="utf-8")
                        verify = runtime / "commands/verify-real-datasets.json"
                        verify_value = replace_path(json.loads(verify.read_bytes()), actual, foreign)
                        verify.write_bytes((json.dumps(verify_value, sort_keys=True, separators=(",", ":")) + "\n").encode())
                self.assert_hostile_runtime_blocks_prepare_final(mutate)

    def test_captured_contract_source_paths_reject_unsafe_or_uncaptured_references(self):
        """Final validation accepts only canonical captured regular-file source references."""
        from scripts.work7_evidence import CapturedBlob
        from scripts.work7_review_packet import Failure, _validate_captured_contract_sources, capture_phase04

        packet = self.prepare_work(); work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        capture = capture_phase04(self.session, self.source)
        for source_path in ("/absolute.py", "../escape.py", "src/core/../core/minhash.cpp", "missing.py", "src"):
            with self.subTest(source_path=source_path):
                contract = json.loads(capture.contract_raw.raw)
                contract["claims"][0]["source_paths"] = [source_path]
                raw = (json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n").encode()
                altered = replace(capture, contract_raw=CapturedBlob(raw, hashlib.sha256(raw).hexdigest(), len(raw), "0600"))
                with self.assertRaises(Failure):
                    _validate_captured_contract_sources(altered.contract_raw, dict(altered.packet_members))
        contract = json.loads(capture.contract_raw.raw)
        contract["claims"][0]["source_paths"] = ["src/core/minhash.cpp", "src/core/minhash.cpp"]
        raw = (json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n").encode()
        altered = replace(capture, contract_raw=CapturedBlob(raw, hashlib.sha256(raw).hexdigest(), len(raw), "0600"))
        with self.assertRaises(Failure):
            _validate_captured_contract_sources(altered.contract_raw, dict(altered.packet_members))

    def test_prepare_final_revalidates_phase4_after_runtime_validation(self):
        """A Phase 4 replacement after its first validation cannot enter the final packet."""
        from scripts import work7_review_packet
        from scripts.work7_evidence import create_tree_seal, sha256_file

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        output = self.session / "phase5/final-packet.json"
        original_validate_runtime = work7_review_packet.validate_phase2_runtime_capture

        def replace_phase4_after_runtime(*arguments):
            summary = original_validate_runtime(*arguments)
            artifacts = self.session / "phase4/work-review-artifacts"
            (artifacts / "foreign.txt").write_text("hostile\n", encoding="utf-8")
            work_seal.unlink()
            create_tree_seal(artifacts, work_seal, sha256_file(self.session / "phase3/closure-seal.json"),
                             "phase4-work-review")
            return summary

        args = Namespace(source_root=self.source, session_root=self.session, work_review_seal=work_seal,
                         output=output)
        with mock.patch.object(work7_review_packet, "validate_phase2_runtime_capture", side_effect=replace_phase4_after_runtime):
            with self.assertRaises(work7_review_packet.Failure):
                work7_review_packet.prepare_final(args)
        self.assertFalse(output.exists())
        self.assertFalse((self.session / "phase5/members").exists())

    def test_prepare_final_uses_captured_phase4_bytes_during_member_publication(self):
        """A Phase 4 swap after the second capture cannot replace packet member bytes."""
        from scripts import work7_review_packet
        from scripts.work7_evidence import create_tree_seal, sha256_file

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        output = self.session / "phase5/final-packet.json"
        original_copy_raw_member = work7_review_packet.copy_raw_member

        def replace_phase4_before_copy(raw, session, member_root, label, members):
            if label == "session/phase4/work-review-seal.json":
                artifacts = self.session / "phase4/work-review-artifacts"
                (artifacts / "foreign.txt").write_text("hostile\n", encoding="utf-8")
                work_seal.unlink()
                create_tree_seal(artifacts, work_seal, sha256_file(self.session / "phase3/closure-seal.json"),
                                 "phase4-work-review")
            return original_copy_raw_member(raw, session, member_root, label, members)

        args = Namespace(source_root=self.source, session_root=self.session, work_review_seal=work_seal,
                         output=output)
        with mock.patch.object(work7_review_packet, "copy_raw_member", side_effect=replace_phase4_before_copy):
            work7_review_packet.prepare_final(args)
        value = json.loads(output.read_bytes())
        member = next(item for item in value["members"]
                      if item["path"] == "phase5/members/session/phase4/work-review-seal.json")
        self.assertNotEqual((self.session / member["path"]).read_bytes(), work_seal.read_bytes())

    def test_prepare_final_seals_validated_phase4_bytes_despite_transient_replacement(self):
        """A replaced-and-restored Phase 4 path cannot substitute the copied validated seal bytes."""
        from scripts import work7_review_packet
        from scripts.work7_evidence import create_tree_seal, sha256_file

        packet = self.prepare_work()
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        original_seal = work_seal.read_bytes()
        output = self.session / "phase5/final-packet.json"
        original_copy_raw_member = work7_review_packet.copy_raw_member
        replaced = False

        def replace_before_phase4_seal_copy(raw, session, member_root, label, members):
            nonlocal replaced
            if label == "session/phase4/work-review-artifacts/work-packet.json":
                artifacts = self.session / "phase4/work-review-artifacts"
                (artifacts / "foreign.txt").write_text("hostile\n", encoding="utf-8")
                work_seal.unlink()
                create_tree_seal(artifacts, work_seal, sha256_file(self.session / "phase3/closure-seal.json"),
                                 "phase4-work-review")
                replaced = True
                artifacts = self.session / "phase4/work-review-artifacts"
                (artifacts / "foreign.txt").unlink()
                work_seal.unlink()
                create_tree_seal(artifacts, work_seal, sha256_file(self.session / "phase3/closure-seal.json"),
                                 "phase4-work-review")
                replaced = False
            return original_copy_raw_member(raw, session, member_root, label, members)

        args = Namespace(source_root=self.source, session_root=self.session, work_review_seal=work_seal,
                         output=output)
        with mock.patch.object(work7_review_packet, "copy_raw_member", side_effect=replace_before_phase4_seal_copy):
            work7_review_packet.prepare_final(args)
        self.assertFalse(replaced)
        value = json.loads(output.read_bytes())
        member = next(item for item in value["members"]
                      if item["path"] == "phase5/members/session/phase4/work-review-seal.json")
        self.assertEqual((self.session / member["path"]).read_bytes(), original_seal)
        self.assertEqual(member["sha256"], hashlib.sha256(original_seal).hexdigest())

    def test_prepare_final_rejects_resealed_hostile_command_record(self):
        """Changing a frozen producer argv and resealing cannot produce a final summary."""
        def mutate(runtime: Path) -> None:
            record = runtime / "commands/pre-threshold.json"; value = json.loads(record.read_bytes())
            value["argv"][1] = "--suite=hostile"
            record.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
        self.assert_hostile_runtime_blocks_prepare_final(mutate)

    def test_prepare_final_rejects_resealed_hostile_focused_ctest_output(self):
        """A resealed focused CTest Not Run result cannot be summarized as a pass."""
        def mutate(runtime: Path) -> None:
            (runtime / "commands/ctest-focused.stdout.txt").write_text(
                "1/28 Test #1: MinHash ... Not Run\n\n0% tests passed, 1 tests failed out of 28\n", encoding="utf-8")
        self.assert_hostile_runtime_blocks_prepare_final(mutate)

    def test_prepare_final_rejects_resealed_hostile_producer_count(self):
        """A resealed measured-count mutation cannot be converted into a PASS summary."""
        def mutate(runtime: Path) -> None:
            manifest = runtime / "pre-threshold/manifest.json"; value = json.loads(manifest.read_bytes())
            value["repetitions"] = 2
            manifest.write_text(json.dumps(value), encoding="utf-8")
        self.assert_hostile_runtime_blocks_prepare_final(mutate)

    def test_close_final_uses_stable_captured_review_and_packet_bytes(self):
        """A real replacement after capture cannot alter bytes passed to publication."""
        from scripts import work7_review_packet
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        original_sol = sol.read_bytes()
        original_packet = packet.read_bytes()
        terminal, seal = self.session / "phase5/stable-report.json", self.session / "phase5/stable-seal.json"
        args = Namespace(packet=packet, claude_review=claude, sol_review=sol, terminal_report=terminal,
                         session_root=self.session, phase0_seal=self.session / "phase0/seal.json", source_root=self.source,
                         paper_root=self.paper, threshold_root=self.threshold, output_seal=seal)
        def synchronize(point: str) -> None:
            if point == "after_terminal_capture":
                sol.write_bytes(b"foreign review\n")
                packet.write_bytes(b"foreign packet\n")
        work7_review_packet.close_final(args, synchronize=synchronize)
        self.assertEqual((self.session / "phase5/terminal-artifacts/sol-review.txt").read_bytes(), original_sol)
        self.assertEqual((self.session / "phase5/terminal-artifacts/final-packet.json").read_bytes(), original_packet)
        self.assertNotEqual(sol.read_bytes(), original_sol)
        self.assertNotEqual(packet.read_bytes(), original_packet)

    def test_close_final_core_rejection_leaves_no_phase5_seal_or_pointer(self):
        """A malformed captured final review fails before terminal publication."""
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        sol.write_text("malformed\n", encoding="utf-8")
        terminal, seal = self.session / "phase5/invalid-report.json", self.session / "phase5/invalid-seal.json"
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(terminal.exists())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())

    def test_close_final_external_drift_after_packet_preparation_leaves_no_phase5_seal_or_pointer(self):
        """External drift before terminal verification must fail before any terminal artifacts exist."""
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        (self.paper / "tracked").write_text("changed\n", encoding="utf-8")
        terminal, seal = self.session / "phase5/pre-drift-report.json", self.session / "phase5/pre-drift-seal.json"
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse(terminal.exists())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())

    def test_close_final_uses_captured_external_snapshot_after_terminal_capture(self):
        """External replacement after capture cannot be reopened by the terminal core."""
        from scripts import work7_review_packet
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/drift-report.json", self.session / "phase5/drift-seal.json"
        args = Namespace(packet=packet, claude_review=claude, sol_review=sol, terminal_report=terminal,
                         session_root=self.session, phase0_seal=self.session / "phase0/seal.json", source_root=self.source,
                         paper_root=self.paper, threshold_root=self.threshold, output_seal=seal)
        original = (self.paper / "tracked").read_bytes()
        def synchronize(point: str) -> None:
            if point == "after_terminal_capture":
                (self.paper / "tracked").write_bytes(b"foreign external state\n")
            elif point == "after_terminal_core":
                (self.paper / "tracked").write_bytes(original)
        work7_review_packet.close_final(args, synchronize=synchronize)
        self.assertTrue(terminal.exists())
        self.assertTrue(seal.exists())
