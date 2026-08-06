"""Behavior tests for the unapplied Work 7 ResponseStrategy candidate."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
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
               drift_external: bool = False) -> tuple[subprocess.CompletedProcess[bytes], Path, Path, Path, Path, str, bytes]:
        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary, True)
        source, paper, threshold, session, commit, baseline = self.make_phase_inputs(temporary, invalid_utf8=invalid_utf8)
        if tamper_phase2:
            phase2 = session / "phase2" / "closure-seal.json"
            phase2.write_bytes(phase2.read_bytes() + b"x")
        if drift_external:
            (threshold / "tracked").write_bytes(b"changed after phase zero\n")
        result = subprocess.run((sys.executable, str(ROOT / "scripts" / "generate_work7_response_candidate.py"),
                                 "--source-root", str(source), "--paper-root", str(paper),
                                 "--threshold-root", str(threshold), "--session-root", str(session),
                                 "--phase0-seal", str(session / "phase0" / "seal.json"),
                                 "--phase2-closure-seal", str(session / "phase2" / "closure-seal.json")), capture_output=True)
        return result, temporary, paper, threshold, session, commit, baseline

    def test_candidate_is_unapplied_deterministic_and_sealed(self):
        from scripts.work7_evidence import sha256_file, verify_tree_seal

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
        self.assertEqual(metadata["claim_ids"], ["W7-G1-ESTIMATOR", "W7-G2-SANITIZER", "W7-G3-CALIBRATION", "W7-G4-COMPARISON", "W7-G5-REAL-DATA", "W7-G6-DYNAMIC", "W7-G7-INTEGRATION"])
        candidate_seal = session / "phase3" / "candidate-seal.json"
        closure_seal = session / "phase3" / "closure-seal.json"
        verify_tree_seal(candidate_seal, sha256_file(session / "phase2" / "closure-seal.json"))
        verify_tree_seal(closure_seal, sha256_file(candidate_seal))
        report = json.loads((session / "phase3" / "closure-artifacts" / "claim7-report.json").read_bytes())
        self.assertEqual(report["mode"], "claim7")
        self.assertEqual([row["toy_evidence_state"] for row in report["claims"]], ["TOY_VERIFIED"] * 7)
        self.assertEqual(report["work_gate_state"], "PENDING")
        self.assertTrue((threshold / "tracked").is_file())

    def test_rejects_invalid_utf8_without_candidate_output(self):
        result, _, paper, _, session, _, _ = self.invoke(invalid_utf8=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"UTF-8", result.stderr)
        self.assertEqual((paper / "Revision/ResponseStrategy.md").read_bytes(), b"\xff")
        self.assertFalse((session / "phase3").exists())

    def test_rejects_tampered_prior_seal_and_collision(self):
        tampered, _, _, _, tampered_session, _, _ = self.invoke(tamper_phase2=True)
        self.assertEqual(tampered.returncode, 2)
        self.assertIn(b"Phase 2 closure seal", tampered.stderr)
        self.assertFalse((tampered_session / "phase3").exists())
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
        self.assertIn(b"external worktree snapshot changed", result.stderr)
        self.assertFalse((session / "phase3").exists())


if __name__ == "__main__":
    unittest.main()
