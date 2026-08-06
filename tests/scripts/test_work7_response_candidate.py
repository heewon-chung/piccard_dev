"""Behavior tests for the unapplied Work 7 ResponseStrategy candidate."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).parents[2]


class Work7ResponseCandidateTests(unittest.TestCase):
    def make_git(self, root: Path, files: dict[str, bytes]) -> None:
        subprocess.run(("git", "init", "-q", "-b", "main", str(root)), check=True)
        subprocess.run(("git", "-C", str(root), "config", "user.email", "work7@example.test"), check=True)
        subprocess.run(("git", "-C", str(root), "config", "user.name", "Work 7"), check=True)
        for relative, data in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        subprocess.run(("git", "-C", str(root), "add", "."), check=True)
        subprocess.run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True)

    def make_phase_inputs(self, temporary: Path, *, invalid_utf8: bool = False) -> tuple[Path, Path, Path, Path, str, bytes]:
        """Build a sealed Phase 0/2 chain accepted by the tracked verifier."""
        from scripts.work7_evidence import canonical_json_bytes, create_tree_seal, sha256_file, snapshot_git_worktree

        ids = ("W7-G1-ESTIMATOR", "W7-G2-SANITIZER", "W7-G3-CALIBRATION", "W7-G4-COMPARISON",
               "W7-G5-REAL-DATA", "W7-G6-DYNAMIC", "W7-G7-INTEGRATION")

        paper, threshold = temporary / "paper", temporary / "threshold"
        baseline = b"# Revision response\n\nExisting dirty response text.\n"
        self.make_git(paper, {"Revision/ResponseStrategy.md": b"\xff" if invalid_utf8 else b"# Revision response\n"})
        # Phase 0 must preserve (rather than clean or normalize) externally dirty bytes.
        if not invalid_utf8:
            (paper / "Revision/ResponseStrategy.md").write_bytes(baseline)
        self.make_git(threshold, {"tracked": b"threshold\n"})
        # The source itself is deliberately the real checkout: the candidate must invoke
        # the tracked contract/verifier rather than a fixture replacement.
        source = ROOT.resolve()
        commit = subprocess.check_output(("git", "-C", str(source), "rev-parse", "HEAD"), text=True).strip()
        session = temporary / "session"
        phase0_artifacts = session / "phase0" / "artifacts"
        phase0_artifacts.mkdir(parents=True)
        state = {"schema": "piccard-work7-phase0-state-v1", "source": snapshot_git_worktree(source),
                 "paper": snapshot_git_worktree(paper), "threshold": snapshot_git_worktree(threshold),
                 "session_id": "work7-" + commit}
        (phase0_artifacts / "state.json").write_bytes(canonical_json_bytes(state))
        phase0 = session / "phase0" / "seal.json"
        create_tree_seal(phase0_artifacts, phase0, None, "phase0")

        contract = json.loads((source / "scripts" / "work7_claims.json").read_bytes())
        names = []
        for claim in contract["claims"]:
            names.extend(claim["required_ctest_names"])
        names = list(dict.fromkeys(names))
        runtime = session / "phase2" / "runtime"
        commands = runtime / "commands"
        commands.mkdir(parents=True)
        inventory = "Test project candidate\n" + "".join(
            f"  Test #{index}: {name}\n" for index, name in enumerate(names, 1)
        ) + f"\nTotal Tests: {len(names)}\n"
        (commands / "ctest-inventory.stdout.txt").write_text(inventory, encoding="utf-8")
        (runtime / "placeholder.txt").write_text("runtime\n", encoding="utf-8")
        runtime_seal = session / "phase2" / "runtime-seal.json"
        create_tree_seal(runtime, runtime_seal, sha256_file(phase0), "phase2-runtime-artifacts")
        closure = session / "phase2" / "closure-artifacts"
        closure.mkdir()
        rows = []
        for claim in contract["claims"]:
            rows.append({"id": claim["id"], "implementation_state": "IMPLEMENTED",
                         "toy_evidence_state": "TOY_VERIFIED" if claim["id"] != ids[-1] else "PENDING",
                         "performance_state": "PERFORMANCE_PENDING", "source_paths": claim["source_paths"],
                         "required_ctest_names": claim["required_ctest_names"], "evidence_keys": claim["evidence_keys"],
                         "deferred_rationale": claim["deferred_rationale"], "prohibited_overclaim": claim["prohibited_overclaim"]})
        report = {"schema": "piccard-work7-claim-report-v1", "source_commit": commit,
                  "mode": "evidence-bound", "threshold_gate_state": "DEFERRED_EXPECTED",
                  "work_gate_state": "PENDING", "claims": rows, "status": "PASS",
                  "validation_errors": [], "input_seals": {"runtime_seal_sha256": sha256_file(runtime_seal)}}
        (closure / "evidence-bound-report.json").write_bytes(canonical_json_bytes(report))
        phase2 = session / "phase2" / "closure-seal.json"
        create_tree_seal(closure, phase2, sha256_file(runtime_seal), "phase2-closure")
        return source, paper, threshold, session, commit, baseline

    def invoke(self, *, invalid_utf8: bool = False, tamper_phase2: bool = False,
               drift_external: bool = False, tamper_runtime: bool = False) -> tuple[subprocess.CompletedProcess[bytes], Path, Path, Path, Path, str, bytes]:
        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary, True)
        source, paper, threshold, session, commit, baseline = self.make_phase_inputs(temporary, invalid_utf8=invalid_utf8)
        if tamper_phase2:
            phase2 = session / "phase2" / "closure-seal.json"
            phase2.write_bytes(phase2.read_bytes() + b"x")
        if drift_external:
            (threshold / "tracked").write_bytes(b"changed after phase zero\n")
        if tamper_runtime:
            (session / "phase2" / "runtime" / "placeholder.txt").write_text("tampered\n", encoding="utf-8")
        result = subprocess.run((sys.executable, str(ROOT / "scripts" / "generate_work7_response_candidate.py"),
                                 "--source-root", str(source), "--paper-root", str(paper),
                                 "--threshold-root", str(threshold), "--session-root", str(session),
                                 "--phase0-seal", str(session / "phase0" / "seal.json"),
                                 "--phase2-closure-seal", str(session / "phase2" / "closure-seal.json")), capture_output=True)
        return result, temporary, paper, threshold, session, commit, baseline

    def test_candidate_is_unapplied_deterministic_and_sealed(self):
        from scripts.work7_evidence import sha256_file, snapshot_git_worktree, verify_tree_seal

        # These before/after checks prove the generator's only persistent output is session-local.
        result, _, paper, threshold, session, commit, baseline = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((paper / "Revision/ResponseStrategy.md").read_bytes(), baseline)
        candidate_root = session / "phase3" / "candidate-artifacts"
        candidate = (candidate_root / "ResponseStrategy.candidate.md").read_text(encoding="utf-8")
        diff = (candidate_root / "ResponseStrategy.candidate.diff").read_text(encoding="utf-8")
        self.assertTrue(candidate.startswith(baseline.decode("utf-8")))
        self.assertIn("WORK7_RESPONSE_CANDIDATE_BEGIN", candidate)
        self.assertNotRegex(candidate.split("WORK7_RESPONSE_CANDIDATE_BEGIN", 1)[1], r"(?i)\\b(?:ms|seconds|speedup|accuracy|%)\\b")
        for claim in ("W7-G1-ESTIMATOR", "W7-G2-SANITIZER", "W7-G3-CALIBRATION", "W7-G4-COMPARISON", "W7-G5-REAL-DATA", "W7-G6-DYNAMIC", "W7-G7-INTEGRATION"):
            self.assertIn(claim, candidate)
        self.assertIn("PERFORMANCE_PENDING", candidate)
        self.assertIn("DEFERRED_EXPECTED", candidate)
        self.assertIn("not authorized", candidate)
        self.assertTrue(diff.startswith("--- a/Revision/ResponseStrategy.md\n+++ b/Revision/ResponseStrategy.md\n"))
        metadata = json.loads((candidate_root / "candidate-metadata.json").read_bytes())
        self.assertEqual(metadata["source_commit"], commit)
        self.assertEqual(metadata["baseline_response_strategy_sha256"], hashlib.sha256(baseline).hexdigest())
        self.assertEqual(metadata["candidate_sha256"], sha256_file(candidate_root / "ResponseStrategy.candidate.md"))
        self.assertEqual([row["id"] for row in metadata["claim_mappings"]], ["W7-G1-ESTIMATOR", "W7-G2-SANITIZER", "W7-G3-CALIBRATION", "W7-G4-COMPARISON", "W7-G5-REAL-DATA", "W7-G6-DYNAMIC", "W7-G7-INTEGRATION"])
        candidate_seal = session / "phase3" / "candidate-seal.json"
        closure_seal = session / "phase3" / "closure-seal.json"
        verify_tree_seal(candidate_seal, sha256_file(session / "phase2" / "closure-seal.json"))
        verify_tree_seal(closure_seal, sha256_file(candidate_seal))
        report = json.loads((session / "phase3" / "closure-artifacts" / "claim7-report.json").read_bytes())
        self.assertEqual(report["mode"], "claim7")
        self.assertEqual([row["toy_evidence_state"] for row in report["claims"]], ["TOY_VERIFIED"] * 7)
        self.assertEqual(report["work_gate_state"], "PENDING")
        self.assertTrue((threshold / "tracked").is_file())
        self.assertEqual(snapshot_git_worktree(paper)["tracked_entries"][0]["sha256"], hashlib.sha256(baseline).hexdigest())

    def test_two_equivalent_sessions_render_identical_candidate_and_dry_apply(self):
        from scripts.generate_work7_response_candidate import apply_unified

        first, _, paper_one, _, session_one, _, baseline_one = self.invoke()
        second, _, paper_two, _, session_two, _, baseline_two = self.invoke()
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        self.assertEqual(second.returncode, 0, second.stderr.decode())
        first_root, second_root = (session_one / "phase3" / "candidate-artifacts",
                                   session_two / "phase3" / "candidate-artifacts")
        candidate_one = (first_root / "ResponseStrategy.candidate.md").read_bytes()
        diff_one = (first_root / "ResponseStrategy.candidate.diff").read_bytes()
        self.assertEqual(candidate_one, (second_root / "ResponseStrategy.candidate.md").read_bytes())
        self.assertEqual(diff_one, (second_root / "ResponseStrategy.candidate.diff").read_bytes())
        self.assertEqual(apply_unified(baseline_one.decode(), diff_one.decode()).encode(), candidate_one)
        self.assertEqual((paper_one / "Revision/ResponseStrategy.md").read_bytes(), baseline_one)
        self.assertEqual((paper_two / "Revision/ResponseStrategy.md").read_bytes(), baseline_two)

    def test_rejects_invalid_utf8_without_candidate_output(self):
        result, _, paper, _, session, _, _ = self.invoke(invalid_utf8=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"UTF-8", result.stderr)
        self.assertEqual((paper / "Revision/ResponseStrategy.md").read_bytes(), b"\xff")
        self.assertFalse((session / "phase3").exists())

    def test_rejects_response_strategy_symlink_before_reading_bytes(self):
        from scripts.generate_work7_response_candidate import Failure, read_baseline

        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary, True)
        _, paper, _, _, _, _ = self.make_phase_inputs(temporary)
        response = paper / "Revision" / "ResponseStrategy.md"
        outside = temporary / "outside.md"; outside.write_text("outside\n", encoding="utf-8")
        response.unlink(); response.symlink_to(outside)
        with self.assertRaisesRegex(Failure, "missing or not a regular file"):
            read_baseline(paper)

    def test_phase_seals_must_be_exact_canonical_session_paths(self):
        from scripts.work7_evidence import create_tree_seal

        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary, True)
        source, paper, threshold, session, _, _ = self.make_phase_inputs(temporary)
        copied = temporary / "foreign-phase0.json"
        copied.write_bytes((session / "phase0" / "seal.json").read_bytes())
        result = subprocess.run((sys.executable, str(ROOT / "scripts" / "generate_work7_response_candidate.py"),
                                 "--source-root", str(source), "--paper-root", str(paper), "--threshold-root", str(threshold),
                                 "--session-root", str(session), "--phase0-seal", str(copied),
                                 "--phase2-closure-seal", str(session / "phase2" / "closure-seal.json")), capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"escapes session root", result.stderr)
        self.assertFalse((session / "phase3").exists())

    def test_drift_injected_during_claim7_never_creates_phase3_closure(self):
        import scripts.generate_work7_response_candidate as generator

        for target in ("source", "paper", "threshold"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary_name:
                temporary = Path(temporary_name)
                source, paper, threshold, session, _, _ = self.make_phase_inputs(temporary)
                original_snapshot = generator.snapshot_git_worktree
                active = {"value": False}

                def snapshot(root: Path):
                    value = original_snapshot(root)
                    expected = {"source": source, "paper": paper, "threshold": threshold}[target].resolve()
                    if active["value"] and root.resolve() == expected:
                        value = dict(value); value["snapshot_sha256"] = "0" * 64
                    return value

                def fake_claim7(*args, **kwargs):
                    (session / "phase3" / "closure-artifacts").mkdir(parents=True)
                    active["value"] = True

                with mock.patch.object(generator, "snapshot_git_worktree", side_effect=snapshot), \
                     mock.patch.object(generator, "run_claim7", side_effect=fake_claim7):
                    result = generator.main(["--source-root", str(source), "--paper-root", str(paper),
                                             "--threshold-root", str(threshold), "--session-root", str(session),
                                             "--phase0-seal", str(session / "phase0" / "seal.json"),
                                             "--phase2-closure-seal", str(session / "phase2" / "closure-seal.json")])
                self.assertEqual(result, 2)
                self.assertFalse((session / "phase3" / "closure-seal.json").exists())

    def test_generator_rejects_malformed_or_wrong_claim7_report_before_closure(self):
        import scripts.generate_work7_response_candidate as generator
        from scripts.work7_evidence import create_tree_seal, sha256_file

        for kind in ("noncanonical", "wrong-input-seals"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary_name:
                temporary = Path(temporary_name)
                source, paper, threshold, session, commit, baseline = self.make_phase_inputs(temporary)
                candidate_root = session / "phase3" / "candidate-artifacts"
                candidate = generator.render_candidate(baseline)
                generator.write_artifacts(candidate_root, baseline, candidate, generator.make_diff(baseline, candidate),
                                          json.loads((session / "phase0" / "artifacts" / "state.json").read_bytes()), commit,
                                          session / "phase0" / "seal.json", session / "phase2" / "closure-seal.json")
                candidate_seal = session / "phase3" / "candidate-seal.json"
                create_tree_seal(candidate_root, candidate_seal, sha256_file(session / "phase2" / "closure-seal.json"), "phase3-candidate-artifacts")
                command = (sys.executable, str(source / "scripts" / "verify_work7_claims.py"), "--mode", "claim7",
                           "--contract", str(source / "scripts" / "work7_claims.json"), "--source-root", str(source),
                           "--source-commit", commit, "--ctest-inventory", str(session / "phase2" / "runtime" / "commands" / "ctest-inventory.stdout.txt"),
                           "--phase2-closure-seal", str(session / "phase2" / "closure-seal.json"), "--phase3-candidate-seal", str(candidate_seal),
                           "--phase0-seal", str(session / "phase0" / "seal.json"), "--paper-root", str(paper), "--threshold-root", str(threshold),
                           "--output", str(temporary / "valid-report.json"))
                subprocess.run(command, check=True, capture_output=True)
                report = (temporary / "valid-report.json").read_bytes()
                if kind == "noncanonical":
                    report = report[:-1]
                else:
                    value = json.loads(report); value["input_seals"] = {"phase2_closure_seal_sha256": "0" * 64,
                                                                         "phase3_candidate_seal_sha256": "0" * 64}
                    report = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"

                def fake_run(argv, **kwargs):
                    Path(argv[argv.index("--output") + 1]).write_bytes(report)
                    return subprocess.CompletedProcess(argv, 0, b"", b"")

                with mock.patch.object(generator.subprocess, "run", side_effect=fake_run):
                    with self.assertRaises(generator.Failure):
                        generator.run_claim7(source, paper, threshold, session, commit,
                                             session / "phase0" / "seal.json", session / "phase2" / "closure-seal.json", candidate_seal)
                self.assertFalse((session / "phase3" / "closure-seal.json").exists())

    def test_rejects_tampered_prior_seal_and_collision(self):
        tampered, _, _, _, tampered_session, _, _ = self.invoke(tamper_phase2=True)
        self.assertEqual(tampered.returncode, 2)
        self.assertIn(b"Phase 2 closure seal", tampered.stderr)
        self.assertFalse((tampered_session / "phase3").exists())
        runtime_tampered, _, _, _, runtime_session, _, _ = self.invoke(tamper_runtime=True)
        self.assertEqual(runtime_tampered.returncode, 2)
        self.assertIn(b"Phase 2 runtime seal", runtime_tampered.stderr)
        self.assertFalse((runtime_session / "phase3").exists())
        result, _, _, _, session, _, _ = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        # A second run cannot overwrite a candidate.  It must not create a new closure.
        again = subprocess.run((sys.executable, str(ROOT / "scripts" / "generate_work7_response_candidate.py"),
                                "--source-root", str(ROOT.resolve()), "--paper-root", str(session.parent / "paper"),
                                "--threshold-root", str(session.parent / "threshold"), "--session-root", str(session),
                                "--phase0-seal", str(session / "phase0" / "seal.json"),
                                "--phase2-closure-seal", str(session / "phase2" / "closure-seal.json")), capture_output=True)
        self.assertEqual(again.returncode, 2)
        self.assertIn(b"collision", again.stderr)

    def test_rejects_external_drift_before_any_candidate_write(self):
        result, _, _, _, session, _, _ = self.invoke(drift_external=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"Phase 0 snapshot changed: threshold", result.stderr)
        self.assertFalse((session / "phase3").exists())

    def test_claim7_rejects_every_candidate_artifact_binding_mutation(self):
        """A freshly resealed hostile candidate still cannot reach claim7 closure."""
        from scripts.work7_evidence import canonical_json_bytes, create_tree_seal, sha256_file

        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary, True)
        source, paper, threshold, session, commit, baseline = self.make_phase_inputs(temporary)
        from scripts.generate_work7_response_candidate import make_diff, render_candidate, write_artifacts
        phase2, phase0 = session / "phase2" / "closure-seal.json", session / "phase0" / "seal.json"

        def fresh_candidate(name: str) -> tuple[Path, Path]:
            root = session / "phase3" / "candidate-artifacts"
            if root.parent.exists():
                shutil.rmtree(root.parent)
            candidate = render_candidate(baseline)
            write_artifacts(root, baseline, candidate, make_diff(baseline, candidate),
                            json.loads((session / "phase0" / "artifacts" / "state.json").read_bytes()), commit, phase0, phase2)
            seal = session / "phase3" / "candidate-seal.json"
            create_tree_seal(root, seal, sha256_file(phase2), "phase3-candidate-artifacts")
            return root, seal

        def claim7(candidate_seal: Path, output: Path) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run((sys.executable, str(ROOT / "scripts" / "verify_work7_claims.py"), "--mode", "claim7",
                                   "--contract", str(source / "scripts" / "work7_claims.json"), "--source-root", str(source),
                                   "--source-commit", commit, "--ctest-inventory", str(session / "phase2" / "runtime" / "commands" / "ctest-inventory.stdout.txt"),
                                   "--phase2-closure-seal", str(phase2), "--phase3-candidate-seal", str(candidate_seal),
                                   "--phase0-seal", str(phase0), "--paper-root", str(paper), "--threshold-root", str(threshold),
                                   "--output", str(output)), capture_output=True)

        mutations = {
            "candidate": lambda root: (root / "ResponseStrategy.candidate.md").write_bytes((root / "ResponseStrategy.candidate.md").read_bytes() + b"tamper\n"),
            "diff": lambda root: (root / "ResponseStrategy.candidate.diff").write_bytes((root / "ResponseStrategy.candidate.diff").read_bytes() + b"tamper\n"),
            "metadata-noncanonical": lambda root: (root / "candidate-metadata.json").write_bytes((root / "candidate-metadata.json").read_bytes()[:-1]),
            "validation-mapping": lambda root: (lambda value: (value["claim_mappings"][0].__setitem__("toy_evidence_state", "PENDING"), (root / "candidate-validation.json").write_bytes(canonical_json_bytes(value))))(json.loads((root / "candidate-validation.json").read_bytes())),
            "foreign-artifact": lambda root: (root / "foreign.txt").write_text("foreign\n", encoding="utf-8"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                root, seal = fresh_candidate(name)
                mutate(root)
                seal.unlink()
                create_tree_seal(root, seal, sha256_file(phase2), "phase3-candidate-artifacts")
                checked = claim7(seal, temporary / f"{name}-claim7.json")
                self.assertEqual(checked.returncode, 2, checked.stderr.decode())
                self.assertFalse((temporary / f"{name}-claim7.json").exists())

        phase0_artifacts = temporary / "phase0-wrong-artifacts"
        shutil.copytree(session / "phase0" / "artifacts", phase0_artifacts)
        state = json.loads((phase0_artifacts / "state.json").read_bytes())
        state["session_id"] = "work7-" + ("0" * 40)
        (phase0_artifacts / "state.json").write_bytes(canonical_json_bytes(state))
        wrong_phase0 = temporary / "phase0-wrong.seal.json"
        create_tree_seal(phase0_artifacts, wrong_phase0, None, "phase0")
        root, seal = fresh_candidate("wrong-phase0")
        checked = subprocess.run((sys.executable, str(ROOT / "scripts" / "verify_work7_claims.py"), "--mode", "claim7",
                                  "--contract", str(source / "scripts" / "work7_claims.json"), "--source-root", str(source),
                                  "--source-commit", commit, "--ctest-inventory", str(session / "phase2" / "runtime" / "commands" / "ctest-inventory.stdout.txt"),
                                  "--phase2-closure-seal", str(phase2), "--phase3-candidate-seal", str(seal),
                                  "--phase0-seal", str(wrong_phase0), "--paper-root", str(paper), "--threshold-root", str(threshold),
                                  "--output", str(temporary / "wrong-phase0-claim7.json")), capture_output=True)
        self.assertEqual(checked.returncode, 2, checked.stderr.decode())

        (threshold / "tracked").write_bytes(b"drift\n")
        drift_root, drift_seal = fresh_candidate("drift")
        checked = claim7(drift_seal, temporary / "drift-claim7.json")
        self.assertEqual(checked.returncode, 2, checked.stderr.decode())
        self.assertIn(b"external worktree snapshot changed", checked.stderr)


if __name__ == "__main__":
    unittest.main()
