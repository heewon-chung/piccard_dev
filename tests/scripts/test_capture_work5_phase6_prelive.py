#!/usr/bin/env python3
"""Hermetic Phase 6C journal and exact CTest-exception contracts."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_work5_benchmarks as verifier


FROZEN_REASON = "check_work6_scope: FAIL: include/fhe/bfv_context.h changes preexisting content"
SUBTESTS = (
    "condition", "body", "comment_prefix", "include_comment", "include_string",
    "helper_string", "helper_comment_decoy", "helper_char", "helper_nested",
    "helper_moved_body", "helper_moved_namespace", "attribute_prefix", "define_prefix",
    "duplicate", "brace_comment", "brace_string", "escaped_brace",
)
EXPECTED_REASONS = (
    *("check_work6_scope: FAIL: src/fhe/bfv_context.cpp changes preexisting content",) * 9,
    *("check_work6_scope: FAIL: codec definition has wrong scope",) * 2,
    *("check_work6_scope: FAIL: src/fhe/bfv_context.cpp changes preexisting content",) * 6,
)

# The accepted CTest exception is bound to the complete numbered test/name
# sequence, not merely to its exit code and one failed test.  Keep this local
# oracle independent from the production classifier.
CTEST_TEST_NAMES = (
    "NoiseCalibrationCutoverProbeCurrent", "NoiseCalibrationCutoverProbeV2",
    "DeletionSurvival", "DeletionMonteCarlo", "Params", "SecurityProfile",
    "MinHash", "RealDataset", "RealDatasetMetrics", "ComparisonWorkload",
    "EstimatorDiagnostic", "OneHotEncoder", "SqrtEncoder", "BottomStructure",
    "ThresholdPoly", "ThresholdTruth", "Paillier", "SJ16", "BFVContext",
    "BaselineEngine", "NoiseCalibrationProbe", "PublicCiphertextCodec",
    "DynamicCiphertextStore", "DynamicRefreshE2E", "PiccardEngine",
    "PiccardEngineLegacyCompile", "DynamicEngine", "ThresholdEngine", "SqrtPiccard",
    "RealDatasetTiming", "PiccardGrownRing", "BenchmarkUtils",
    "EstimatorProvenanceSerializers", "DynamicRefreshBenchmark", "BenchmarkProfile",
    "BaselineProfile", "NoiseCalibrationSchema", "ThresholdProfileCompat", "PiccardE2E",
    "Group", "Dgt12PsiCa", "Bcg12", "StdSecurityEvidenceSchema", "DeletionSurvivalCli",
    "VerifyWorkApproval", "Work7StateGuard", "Work7ClaimContract", "Work7IntegrationRunner",
    "Work7ResponseCandidate", "SanitizerRunnerForwarding", "NoiseProfileRunner",
    "CalibrationTableGenerator", "CalibrationCutover", "CalibrationArchive",
    "ReportingTaxonomy", "PreThresholdProfileRunner", "RunStdSecurityEvidence",
    "RunWork5Benchmarks", "VerifyWork5Benchmarks", "SummarizeStdSecurityEvidence",
    "VerifyReviewComparison", "VerifyBenchmarkProvenance", "CheckWork6Scope",
    "VerifySJ16Extrapolation",
    "RealDatasetPreprocess", "RunRealDatasets", "RealDatasetPipeline",
    "BenchmarkProfileExecutables", "ReviewComparisonCli", "BenchDynamicProbeIsolation",
    "BenchDynamicRefreshCli", "FheIndCli", "Work5ContextPreflight", "StdSecurityEvidenceE2E",
    "NoiseStrictMeasurementCleanup", "NoiseCandidatePlaintextCompatibility",
    "NoiseDetailIdentityMapping", "NoisePreThresholdCoverage",
    "NoisePreThresholdRejectsThreshold", "NoisePreThresholdSmoke",
    "NoisePreThresholdRejectsNonNaturalFirstRing", "NoisePreThresholdGrownSmoke",
    "NoisePreThresholdRejectsProfilePolicyMismatch",
)


def known_ctest_stdout() -> bytes:
    lines = ["Test project /fixture"]
    for number in range(1, 84):
        name = CTEST_TEST_NAMES[number - 1]
        lines.append(f"      Start {number:2d}: {name}")
        if number == 63:
            lines.append("63/83 Test #63: CheckWork6Scope ........................***Failed   25.00 sec")
            lines.append("test_bfv_production_shaped_mutations_fail_after_subtraction (...) ...")
            for subtest in SUBTESTS:
                lines.append(f"  test_bfv_production_shaped_mutations_fail_after_subtraction (...) (name='{subtest}') ... FAIL")
            # Match unittest's actual --output-on-failure shape: the checker
            # result occurs inside each AssertionError diff, never as a
            # standalone line-start diagnostic.
            for subtest, expected_reason in zip(SUBTESTS, EXPECTED_REASONS):
                lines.extend([
                    "======================================================================",
                    "FAIL: test_bfv_production_shaped_mutations_fail_after_subtraction "
                    "(tests.scripts.test_check_work6_scope.CheckWork6Scope."
                    "test_bfv_production_shaped_mutations_fail_after_subtraction) "
                    f"(name='{subtest}')",
                    "----------------------------------------------------------------------",
                    "AssertionError: checker result differs from the expected mutation reason",
                    "- " + FROZEN_REASON,
                    "+ " + expected_reason,
                ])
            lines.extend(["Ran 18 tests in 0.001s", "FAILED (failures=17)"])
        else:
            lines.append(f"{number}/83 Test #{number}: {name} ...........................   Passed    0.00 sec")
    lines.extend(["99% tests passed, 1 tests failed out of 83", "",
                  "The following tests FAILED:", "\t 63 - CheckWork6Scope (Failed)"])
    return ("\n".join(lines) + "\n").encode("utf-8")


class Work5CtestExceptionTest(unittest.TestCase):
    def test_only_the_hash_bound_known_signature_is_accepted(self) -> None:
        stdout = known_ctest_stdout()
        condition_header = (
            "FAIL: test_bfv_production_shaped_mutations_fail_after_subtraction "
            "(tests.scripts.test_check_work6_scope.CheckWork6Scope."
            "test_bfv_production_shaped_mutations_fail_after_subtraction) (name='condition')\n"
        ).encode()
        body_header = condition_header.replace(b"condition", b"body")
        receipt = verifier.classify_work6_scope_ctest(8, stdout, b"Errors while running CTest\n")
        self.assertEqual(receipt["classification"], "KNOWN_WORK6_SCOPE_DIAGNOSTIC_MISMATCH")
        self.assertEqual(receipt["test_count"], 83)
        self.assertEqual(receipt["failed_subtests"], list(SUBTESTS))
        cases = {
            "unexpected_green": (0, stdout.replace(b"1 tests failed", b"0 tests failed")),
            "wrong_exit": (1, stdout),
            "wrong_reason": (8, stdout.replace(FROZEN_REASON.encode(), b"accepted mutation")),
            "extra_failure": (8, stdout.replace(b"1 tests failed out of 83", b"2 tests failed out of 83")),
            "subtest_order": (8, stdout.replace(b"condition", b"zz_condition", 1)),
            "appended_pass_diagnostic": (8, stdout + b"check_work6_scope: PASS: accepted mutation\n"),
            "appended_extra_reason": (8, stdout + b"check_work6_scope: FAIL: accepted mutation\n"),
            "inserted_unrelated_failure_header": (8, stdout.replace(
                b"Ran 18 tests", b"FAIL: unexpected\nRan 18 tests", 1)),
            "missing_failure_header": (8, stdout.replace(condition_header, b"", 1)),
            "reordered_failure_headers": (8, stdout.replace(
                condition_header, b"FAIL-HEADER-SWAP\n", 1).replace(
                    body_header, condition_header, 1).replace(
                        b"FAIL-HEADER-SWAP\n", body_header, 1)),
            "changed_expected_reason": (8, stdout.replace(
                b"+ check_work6_scope: FAIL: codec definition has wrong scope",
                b"+ check_work6_scope: FAIL: accepted mutation", 1)),
        }
        for name, (exit_code, candidate) in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(verifier.VerificationError):
                    verifier.classify_work6_scope_ctest(exit_code, candidate,
                                                        b"Errors while running CTest\n")

    def test_test_name_sequence_and_raw_log_shape_are_frozen(self) -> None:
        stdout = known_ctest_stdout()
        mutations = {
            "changed_passed_name": stdout.replace(
                b"1/83 Test #1: NoiseCalibrationCutoverProbeCurrent",
                b"1/83 Test #1: RenamedTest", 1),
            "changed_start_name": stdout.replace(
                b"Start  2: NoiseCalibrationCutoverProbeV2",
                b"Start  2: RenamedTest", 1),
            "truncated_result": stdout.rsplit(b"99% tests passed", 1)[0],
            "duplicate_result": stdout.replace(
                b"99% tests passed, 1 tests failed out of 83\n",
                b"1/83 Test #1: NoiseCalibrationCutoverProbeCurrent ........ Passed 0.00 sec\n"
                b"99% tests passed, 1 tests failed out of 83\n", 1),
        }
        for name, candidate in mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(verifier.VerificationError):
                    verifier.classify_work6_scope_ctest(
                        8, candidate, b"Errors while running CTest\n")


class JournalContractTest(unittest.TestCase):
    def test_fresh_macos_configure_binds_openfhe_runtime_path(self) -> None:
        import capture_work5_phase6_prelive as capture

        configure = capture.configure_command(Path("/source"), Path("/build"))
        runtime_option = "-DCMAKE_BUILD_RPATH=/usr/local/lib"
        if capture.platform.system() == "Darwin" and Path("/usr/local/lib").is_dir():
            self.assertIn(runtime_option, configure)
        else:
            self.assertNotIn(runtime_option, configure)

    def test_workspace_build_command_is_source_bound(self) -> None:
        import capture_work5_phase6_prelive as capture

        self.assertEqual(capture.workspace_build_command(Path("/source")),
                         ["cmake", "--build", "/source/build", "-j2"])

    def test_macos_loader_path_is_explicitly_journaled(self) -> None:
        import capture_work5_phase6_prelive as capture

        environment = capture.capture_environment(2)
        if capture.platform.system() == "Darwin" and Path("/usr/local/lib").is_dir():
            self.assertEqual(environment["DYLD_LIBRARY_PATH"], "/usr/local/lib")
        else:
            self.assertNotIn("DYLD_LIBRARY_PATH", environment)

    def test_complete_pairs_are_monotone_and_incomplete_pairs_fail(self) -> None:
        import capture_work5_phase6_prelive as capture

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            stdout_payload = b"stdout\n"
            stderr_payload = b"stderr\n"
            (root / "logs/1.stdout").write_bytes(stdout_payload)
            (root / "logs/1.stderr").write_bytes(stderr_payload)
            events = [
                {"schema": "piccard-work5-command-event-v1", "event": "START", "sequence": 1,
                 "command_id": "first", "argv": ["true"], "cwd": "/fixture", "environment": {},
                 "git_sha": "a" * 40, "stdout_path": "logs/1.stdout", "stderr_path": "logs/1.stderr",
                 "started_at_utc": "2026-08-12T00:00:00Z"},
                {"schema": "piccard-work5-command-event-v1", "event": "END", "sequence": 1,
                 "command_id": "first", "argv": ["true"], "cwd": "/fixture", "environment": {},
                 "git_sha": "a" * 40, "stdout_path": "logs/1.stdout", "stderr_path": "logs/1.stderr",
                 "started_at_utc": "2026-08-12T00:00:00Z", "ended_at_utc": "2026-08-12T00:00:01Z",
                 "exit_code": 0, "stdout_sha256": hashlib.sha256(stdout_payload).hexdigest(),
                 "stderr_sha256": hashlib.sha256(stderr_payload).hexdigest(),
                 "classification": "PASS"},
            ]
            journal = root / "commands.jsonl"
            journal.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
                               encoding="utf-8")
            self.assertEqual(capture.journal_events(journal), events)
            journal.write_text(json.dumps(events[0], sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaises(capture.CaptureError):
                capture.journal_events(journal)

    def test_journal_end_timestamp_cannot_precede_start(self) -> None:
        import capture_work5_phase6_prelive as capture

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            payload = b"output\n"
            (root / "logs/1.stdout").write_bytes(payload)
            (root / "logs/1.stderr").write_bytes(b"")
            start = {
                "schema": "piccard-work5-command-event-v1", "event": "START", "sequence": 1,
                "command_id": "first", "argv": ["true"], "cwd": "/fixture", "environment": {},
                "git_sha": "a" * 40, "stdout_path": "logs/1.stdout", "stderr_path": "logs/1.stderr",
                "started_at_utc": "2026-08-12T00:00:01Z",
            }
            end = {
                **start, "event": "END", "ended_at_utc": "2026-08-12T00:00:00Z",
                "exit_code": 0, "stdout_sha256": hashlib.sha256(payload).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(), "classification": "PASS",
            }
            journal = root / "commands.jsonl"
            journal.write_text("".join(json.dumps(event, sort_keys=True) + "\n"
                                           for event in (start, end)), encoding="utf-8")
            with self.assertRaisesRegex(capture.CaptureError,
                                        "journal END precedes matching START"):
                capture.journal_events(journal)

    def test_journal_command_timestamps_are_monotone(self) -> None:
        import capture_work5_phase6_prelive as capture

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            events = []
            for sequence, command_id, started, ended in (
                    (1, "first", "2026-08-12T00:00:00Z", "2026-08-12T00:00:02Z"),
                    (2, "second", "2026-08-12T00:00:01Z", "2026-08-12T00:00:03Z")):
                payload = f"output-{sequence}\n".encode()
                stdout_path = f"logs/{sequence}.stdout"
                stderr_path = f"logs/{sequence}.stderr"
                (root / stdout_path).write_bytes(payload)
                (root / stderr_path).write_bytes(b"")
                start = {
                    "schema": "piccard-work5-command-event-v1", "event": "START",
                    "sequence": sequence, "command_id": command_id, "argv": ["true"],
                    "cwd": "/fixture", "environment": {}, "git_sha": "a" * 40,
                    "stdout_path": stdout_path, "stderr_path": stderr_path,
                    "started_at_utc": started,
                }
                events.extend((start, {
                    **start, "event": "END", "ended_at_utc": ended, "exit_code": 0,
                    "stdout_sha256": hashlib.sha256(payload).hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(), "classification": "PASS",
                }))
            journal = root / "commands.jsonl"
            journal.write_text("".join(json.dumps(event, sort_keys=True) + "\n"
                                           for event in events), encoding="utf-8")
            with self.assertRaisesRegex(capture.CaptureError,
                                        "journal START precedes previous END"):
                capture.journal_events(journal)

    def test_journal_end_requires_existing_unique_output_artifacts(self) -> None:
        import capture_work5_phase6_prelive as capture

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            payload = b"stdout\n"
            (root / "logs/1.stdout").write_bytes(payload)
            (root / "logs/1.stderr").write_bytes(b"")
            start = {
                "schema": "piccard-work5-command-event-v1", "event": "START", "sequence": 1,
                "command_id": "first", "argv": ["true"], "cwd": "/fixture", "environment": {},
                "git_sha": "a" * 40, "stdout_path": "logs/1.stdout", "stderr_path": "logs/1.stderr",
                "started_at_utc": "2026-08-12T00:00:00Z",
            }
            end = {
                **start, "event": "END", "ended_at_utc": "2026-08-12T00:00:01Z",
                "exit_code": 0, "stdout_sha256": hashlib.sha256(payload).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(), "classification": "PASS",
            }
            journal = root / "commands.jsonl"
            journal.write_text("".join(json.dumps(event, sort_keys=True) + "\n"
                                           for event in (start, end)), encoding="utf-8")
            (root / "logs/1.stdout").unlink()
            with self.assertRaises(capture.CaptureError):
                capture.journal_events(journal)

    def test_journal_pass_requires_zero_exit_and_known_ctest_is_exact(self) -> None:
        import capture_work5_phase6_prelive as capture

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "logs").mkdir()
            payload = b"stdout\n"
            (root / "logs/1.stdout").write_bytes(payload)
            (root / "logs/1.stderr").write_bytes(b"")
            start = {
                "schema": "piccard-work5-command-event-v1", "event": "START", "sequence": 1,
                "command_id": "first", "argv": ["true"], "cwd": "/fixture", "environment": {},
                "git_sha": "a" * 40, "stdout_path": "logs/1.stdout", "stderr_path": "logs/1.stderr",
                "started_at_utc": "2026-08-12T00:00:00Z",
            }
            end = {
                **start, "event": "END", "ended_at_utc": "2026-08-12T00:00:01Z",
                "exit_code": 9, "stdout_sha256": hashlib.sha256(payload).hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(), "classification": "PASS",
            }
            journal = root / "commands.jsonl"
            journal.write_text("".join(json.dumps(event, sort_keys=True) + "\n"
                                           for event in (start, end)), encoding="utf-8")
            with self.assertRaises(capture.CaptureError):
                capture.journal_events(journal)

            # A second command cannot reuse either output path, even if both
            # files and hashes are otherwise self-consistent.
            (root / "logs/1.stdout").write_bytes(payload)
            duplicate_start = {**start, "sequence": 2, "command_id": "second"}
            duplicate_end = {**end, "sequence": 2, "command_id": "second"}
            journal.write_text("".join(json.dumps(event, sort_keys=True) + "\n"
                                           for event in (start, end, duplicate_start, duplicate_end)),
                               encoding="utf-8")
            with self.assertRaises(capture.CaptureError):
                capture.journal_events(journal)


if __name__ == "__main__":
    unittest.main()
