"""CLI behavior coverage for Work 7 review packets and terminal closure."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[2]
REVIEW_FIXTURES = ROOT / "tests/fixtures/work7/reviews"


class Work7ReviewPacketTests(unittest.TestCase):
    """The packet is a real session-local snapshot, never a source-text check."""

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
                            "--phase0-seal", str(self.session / "phase0/seal.json"), "--paper-root", str(self.paper),
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

    def _phase5_snapshot(self) -> tuple[tuple[str, str, int, bytes], ...]:
        phase5 = self.session / "phase5"
        if not phase5.exists():
            return ()
        result = []
        for path in sorted(phase5.rglob("*")):
            info = path.lstat()
            if path.is_file() and not path.is_symlink():
                result.append((path.relative_to(phase5).as_posix(), "file", info.st_mode & 0o777, path.read_bytes()))
            elif path.is_dir() and not path.is_symlink():
                result.append((path.relative_to(phase5).as_posix(), "directory", info.st_mode & 0o777, b""))
            else:
                result.append((path.relative_to(phase5).as_posix(), "other", info.st_mode & 0o777, b""))
        return tuple(result)

    def _prepare_final_with_member_collision(self, relative: str) -> subprocess.CompletedProcess[bytes]:
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
                    injected.set()
                    return
                threading.Event().wait(0.001)

        worker = threading.Thread(target=collide)
        worker.start()
        result = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                              "--work-review-seal", str(seal), "--output", str(self.session / "phase5/final-packet.json"))
        worker.join(timeout=10)
        self.assertTrue(injected.is_set(), "collision worker did not synchronize with publication")
        return result

    def test_prepare_final_rolls_back_ordinary_member_collision_after_publication_starts(self):
        """A late ordinary-member collision leaves Phase 5 exactly as it was."""
        before = self._phase5_snapshot()
        result = self._prepare_final_with_member_collision("session/phase2/static-report.json")
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertEqual(self._phase5_snapshot(), before)

    def test_prepare_final_rolls_back_generated_member_collision_after_ordinary_members(self):
        """A generated-member collision removes all previously published members."""
        before = self._phase5_snapshot()
        result = self._prepare_final_with_member_collision("generated/works1-6-source-test-map.json")
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertEqual(self._phase5_snapshot(), before)

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

    def test_close_final_revalidates_phase4_after_runtime_validation(self):
        """A Phase 4 reseal during final runtime validation cannot reach terminal closure."""
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
                         session_root=self.session, phase0_seal=self.session / "phase0/seal.json",
                         paper_root=self.paper, threshold_root=self.threshold, output_seal=seal)
        with mock.patch.object(work7_review_packet, "validate_phase2_runtime_capture", side_effect=replace_phase4_after_runtime):
            with self.assertRaises(work7_review_packet.Failure):
                work7_review_packet.close_final(args)
        self.assertFalse(terminal.exists())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())

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

    def test_close_final_uses_private_stable_review_copies_and_rejects_bad_terminal_report_or_drift(self):
        """Replacing a raw file after parsing cannot alter a seal; bad reports and drift cannot create one."""
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        original_sol = sol.read_bytes()
        original_packet = packet.read_bytes()
        os.environ.update({"WORK7_TEST_TERMINAL_ACTION": "replace-inputs", "WORK7_TEST_REVIEW_PATH": str(sol),
                           "WORK7_TEST_PACKET_PATH": str(packet)})
        self.addCleanup(os.environ.pop, "WORK7_TEST_TERMINAL_ACTION", None); self.addCleanup(os.environ.pop, "WORK7_TEST_REVIEW_PATH", None)
        self.addCleanup(os.environ.pop, "WORK7_TEST_PACKET_PATH", None)
        terminal, seal = self.session / "phase5/stable-report.json", self.session / "phase5/stable-seal.json"
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.session / "phase5/terminal-artifacts/sol-review.txt").read_bytes(), original_sol)
        self.assertEqual((self.session / "phase5/terminal-artifacts/final-packet.json").read_bytes(), original_packet)
        self.assertNotEqual(sol.read_bytes(), original_sol)
        self.assertNotEqual(packet.read_bytes(), original_packet)

    def test_close_final_invalid_terminal_report_leaves_no_phase5_seal_or_pointer(self):
        """A verifier success exit with a malformed report cannot create a terminal seal."""
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/invalid-report.json", self.session / "phase5/invalid-seal.json"
        os.environ["WORK7_TEST_TERMINAL_ACTION"] = "invalid-report"
        self.addCleanup(os.environ.pop, "WORK7_TEST_TERMINAL_ACTION", None)
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())

    def test_close_final_missing_terminal_report_leaves_no_phase5_seal_or_pointer(self):
        """A verifier success exit without a report cannot create a terminal seal."""
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/missing-report.json", self.session / "phase5/missing-seal.json"
        os.environ["WORK7_TEST_TERMINAL_ACTION"] = "missing-report"
        self.addCleanup(os.environ.pop, "WORK7_TEST_TERMINAL_ACTION", None)
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

    def test_close_final_external_drift_after_terminal_verification_leaves_no_phase5_seal_or_pointer(self):
        """A worktree change after the verifier writes its report still fails closure."""
        packet = self.prepare_final_packet(); claude, sol = self.final_review(packet, "anthropic"), self.final_review(packet, "openai")
        terminal, seal = self.session / "phase5/drift-report.json", self.session / "phase5/drift-seal.json"
        os.environ.update({"WORK7_TEST_TERMINAL_ACTION": "external-drift", "WORK7_TEST_PAPER_PATH": str(self.paper)})
        self.addCleanup(os.environ.pop, "WORK7_TEST_TERMINAL_ACTION", None); self.addCleanup(os.environ.pop, "WORK7_TEST_PAPER_PATH", None)
        result = self.close_final(packet, claude, sol, terminal, seal)
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertFalse((self.session / "phase5/terminal-artifacts").exists())
        self.assertFalse(seal.exists()); self.assertFalse(seal.with_name("terminal-seal.sha256").exists())
