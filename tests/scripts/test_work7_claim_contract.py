"""Behavior tests for the immutable Work 7 lifecycle verifier."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "verify_work7_claims.py"
FIXTURE = ROOT / "tests" / "fixtures" / "work7" / "claims" / "valid-contract.json"
RAW_CTEST = ROOT / "tests" / "fixtures" / "work7" / "claims" / "raw-ctest-n.txt"
COMMIT = "a" * 40
PACKET = "b" * 64


class Work7ClaimContractTests(unittest.TestCase):
    """Each test pressures the CLI boundary with a sealed, local session."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.contract = self.source / "contract.json"
        self.calls = 0
        self.contract.write_bytes(FIXTURE.read_bytes())
        contract = json.loads(self.contract.read_text())
        self.inventory = self.root / "ctest.txt"
        records = "\n".join(
            f"  Test #{index}: {name}" for index, name in enumerate(
                sorted({test for claim in contract["claims"] for test in claim["required_ctest_names"]}), 1
            )
        )
        self.inventory.write_text(f"Test project {self.root / 'build'}\n{records}\n\nTotal Tests: {len(records.splitlines())}\n")
        for claim in contract["claims"]:
            for relative in claim["source_paths"]:
                path = self.source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def invoke(self, mode: str, **extra: Path) -> subprocess.CompletedProcess[str]:
        self.calls += 1
        output = self.root / f"{mode}-{self.calls}-report.json"
        command = [sys.executable, str(VERIFIER), "--mode", mode,
                   "--contract", str(self.contract), "--source-root", str(self.source),
                   "--source-commit", COMMIT, "--ctest-inventory", str(self.inventory),
                   "--output", str(output)]
        for key, value in extra.items():
            command.extend(["--" + key.replace("_", "-"), str(value)])
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        result.output_path = output  # type: ignore[attr-defined]
        return result

    def assert_pass(self, mode: str, **extra: Path) -> dict:
        result = self.invoke(mode, **extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"verify_work7_claims: PASS ({mode})\n")
        return json.loads(result.output_path.read_text())  # type: ignore[attr-defined]

    def assert_fail(self, mode: str, **extra: Path) -> None:
        result = self.invoke(mode, **extra)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertRegex(result.stderr, r"^verify_work7_claims: FAIL: .+\n$")
        self.assertFalse(result.output_path.exists())  # type: ignore[attr-defined]

    def mutate_contract(self, change) -> None:
        value = json.loads(self.contract.read_text())
        change(value)
        self.contract.write_text(json.dumps(value), encoding="utf-8")

    def test_static_emits_only_pending_and_deferrals(self) -> None:
        report = self.assert_pass("static")
        self.assertEqual(report["work_gate_state"], "PENDING")
        self.assertEqual(report["threshold_gate_state"], "DEFERRED_EXPECTED")
        self.assertEqual({claim["toy_evidence_state"] for claim in report["claims"]}, {"PENDING"})

    def test_static_rejects_contract_and_reference_mutations(self) -> None:
        mutations = {
            "missing-id": lambda v: v["claims"].pop(),
            "duplicate-id": lambda v: v["claims"].append(copy.deepcopy(v["claims"][0])),
            "wrong-field-state": lambda v: v["claims"][0].update(performance_state="TOY_VERIFIED"),
            "missing-source": lambda v: v["claims"][0]["source_paths"].__setitem__(0, "missing.py"),
            "escaping-source": lambda v: v["claims"][0]["source_paths"].__setitem__(0, "../escape.py"),
            "missing-ctest": lambda v: v["claims"][0]["required_ctest_names"].append("AbsentCTest"),
            "threshold-authorization": lambda v: v["allowed_gates"].__setitem__("threshold_gate_state", ["AUTHORIZED"]),
            "changed-contract-state": lambda v: v.__setitem__("current_state", "TOY_VERIFIED"),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                self.contract.write_bytes(FIXTURE.read_bytes())
                mutation(json.loads(self.contract.read_text())) if False else None
                self.mutate_contract(mutation)
                self.assert_fail("static")

    def make_seal(self, name: str, kind: str, previous: str | None = None) -> Path:
        sys.path.insert(0, str(ROOT / "scripts"))
        from work7_evidence import create_tree_seal, sha256_file
        artifact = self.root / name
        artifact.mkdir()
        seal = self.root / f"{name}.seal.json"
        create_tree_seal(artifact, seal, previous, kind)
        return seal

    def runtime(self, missing_claim: bool = False, foreign: bool = False) -> Path:
        sys.path.insert(0, str(ROOT / "scripts"))
        from work7_evidence import create_tree_seal
        artifact = self.root / f"runtime-{self.calls}"
        artifact.mkdir(exist_ok=True)
        contract = json.loads(self.contract.read_text())
        index = {"schema": "piccard-work7-evidence-index-v2", "source_commit": "c" * 40 if foreign else COMMIT,
                 "claims": {claim["id"]: {} for claim in contract["claims"][:6]}}
        for index_number, claim in enumerate(contract["claims"][:6], 1):
            for key in claim["evidence_keys"]:
                name = f"proof-{index_number}-{key}.bin"
                (artifact / name).write_bytes(f"proof {key}\n".encode())
                index["claims"][claim["id"]][key] = {
                    "artifact_kind": "ctest-log", "path": name,
                    "sha256": hashlib.sha256((artifact / name).read_bytes()).hexdigest(),
                }
        if missing_claim:
            index["claims"].pop("W7-G1-ESTIMATOR")
        (artifact / "evidence-index.json").write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n")
        seal = self.root / f"runtime-{self.calls}.seal.json"
        create_tree_seal(artifact, seal, None, "phase2-runtime-artifacts")
        return seal

    def test_ctest_inventory_accepts_raw_ctest_n_and_rejects_bad_trailer(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_work7_claims import inventory
        self.inventory.write_bytes(RAW_CTEST.read_bytes())
        self.assertEqual(inventory(self.inventory), {"MinHash", "EstimatorDiagnostic"})
        self.assert_fail("static")  # fixture deliberately lacks this contract's complete registry
        self.inventory.write_text("Test project x\n  Test #1: MinHash\n\nTotal Tests: 2\n")
        self.assert_fail("static")

    def test_static_rejects_unsafe_output_and_malformed_ctest_inventory(self) -> None:
        unsafe = self.source / "report.json"
        result = subprocess.run([sys.executable, str(VERIFIER), "--mode", "static", "--contract", str(self.contract),
                                 "--source-root", str(self.source), "--source-commit", COMMIT,
                                 "--ctest-inventory", str(self.inventory), "--output", str(unsafe)],
                                cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.inventory.write_text("Test project x\n  Test #1: MinHash\n  Test #1: Params\n\nTotal Tests: 2\n")
        self.assert_fail("static")

    def test_evidence_bound_binds_only_claims_one_to_six(self) -> None:
        report = self.assert_pass("evidence-bound", runtime_seal=self.runtime())
        self.assertEqual([claim["toy_evidence_state"] for claim in report["claims"][:6]], ["TOY_VERIFIED"] * 6)
        self.assertEqual(report["claims"][6]["toy_evidence_state"], "PENDING")

    def test_evidence_bound_rejects_preflight_foreign_tampered_and_missing_evidence(self) -> None:
        self.assert_fail("evidence-bound")
        self.assert_fail("evidence-bound", runtime_seal=self.runtime(missing_claim=True))
        self.assert_fail("evidence-bound", runtime_seal=self.runtime(foreign=True))
        seal = self.runtime()
        Path(json.loads(seal.read_text())["artifact_root"]).joinpath("proof-1-estimator.bin").write_text("tampered\n")
        self.assert_fail("evidence-bound", runtime_seal=seal)

    def test_evidence_bound_rejects_shared_index_or_arbitrary_evidence(self) -> None:
        seal = self.runtime()
        root = Path(json.loads(seal.read_text())["artifact_root"])
        index = json.loads((root / "evidence-index.json").read_text())
        index["claims"]["W7-G2-SANITIZER"]["sanitizer"] = index["claims"]["W7-G1-ESTIMATOR"]["estimator"]
        (root / "evidence-index.json").write_text(json.dumps(index))
        self.assert_fail("evidence-bound", runtime_seal=seal)

    def test_hostile_sealed_index_types_fail_without_traceback(self) -> None:
        for hostile in ([], {}, 7, ["ctest-log"]):
            with self.subTest(hostile=repr(hostile)):
                sys.path.insert(0, str(ROOT / "scripts"))
                from work7_evidence import create_tree_seal
                artifact = self.root / f"hostile-{len(repr(hostile))}-{self.calls}"
                artifact.mkdir()
                index = {"schema": "piccard-work7-evidence-index-v2", "source_commit": COMMIT,
                         "claims": {claim_id: {} for claim_id in ("W7-G1-ESTIMATOR", "W7-G2-SANITIZER", "W7-G3-CALIBRATION", "W7-G4-COMPARISON", "W7-G5-REAL-DATA", "W7-G6-DYNAMIC")}}
                index["claims"]["W7-G1-ESTIMATOR"] = {"estimator": {"path": "x", "sha256": "0" * 64, "artifact_kind": hostile}}
                (artifact / "x").write_text("x")
                (artifact / "evidence-index.json").write_text(json.dumps(index))
                seal = self.root / f"hostile-{len(repr(hostile))}-{self.calls}.seal.json"
                create_tree_seal(artifact, seal, None, "phase2-runtime-artifacts")
                self.assert_fail("evidence-bound", runtime_seal=seal)

    def test_claim7_requires_phase_two_and_candidate_seals(self) -> None:
        runtime = self.runtime()
        sys.path.insert(0, str(ROOT / "scripts"))
        from work7_evidence import create_tree_seal, sha256_file
        evidence = self.invoke("evidence-bound", runtime_seal=runtime)
        self.assertEqual(evidence.returncode, 0, evidence.stderr)
        closure_root = self.root / "phase2"
        closure_root.mkdir()
        (closure_root / "evidence-bound-report.json").write_bytes(evidence.output_path.read_bytes())  # type: ignore[attr-defined]
        phase2 = self.root / "phase2.seal.json"
        create_tree_seal(closure_root, phase2, sha256_file(runtime), "phase2-closure")
        candidate_root = self.root / "candidate"
        candidate_root.mkdir()
        (candidate_root / "candidate-validation.json").write_text(json.dumps({
            "schema": "piccard-work7-candidate-validation-v1", "source_commit": COMMIT,
            "claim_id": "W7-G7-INTEGRATION", "phase2_closure_seal_sha256": sha256_file(phase2),
        }) + "\n")
        candidate = self.root / "candidate.seal.json"
        create_tree_seal(candidate_root, candidate, sha256_file(phase2), "phase3-candidate-artifacts")
        report = self.assert_pass("claim7", phase2_closure_seal=phase2, phase3_candidate_seal=candidate)
        self.assertEqual(report["claims"][6]["toy_evidence_state"], "TOY_VERIFIED")
        self.assertEqual(report["work_gate_state"], "PENDING")
        self.assert_fail("claim7", phase2_closure_seal=phase2)

        base_report = json.loads(evidence.output_path.read_text())  # type: ignore[attr-defined]
        for name, mutate in {
            "extra-report-field": lambda value: value.__setitem__("overclaim", True),
            "performance-overclaim": lambda value: value["claims"][0].__setitem__("performance_state", "PERFORMANCE_VERIFIED"),
            "threshold-overclaim": lambda value: value.__setitem__("threshold_gate_state", "AUTHORIZED"),
            "non-object-claim": lambda value: value.__setitem__("claims", [None] * 7),
        }.items():
            with self.subTest(inherited_report=name):
                bad_root = self.root / f"phase2-{name}"; bad_root.mkdir()
                mutated = copy.deepcopy(base_report); mutate(mutated)
                (bad_root / "evidence-bound-report.json").write_text(json.dumps(mutated))
                bad_phase2 = self.root / f"phase2-{name}.seal.json"
                create_tree_seal(bad_root, bad_phase2, sha256_file(runtime), "phase2-closure")
                bad_candidate_root = self.root / f"candidate-{name}"; bad_candidate_root.mkdir()
                (bad_candidate_root / "candidate-validation.json").write_text(json.dumps({"schema": "piccard-work7-candidate-validation-v1", "source_commit": COMMIT, "claim_id": "W7-G7-INTEGRATION", "phase2_closure_seal_sha256": sha256_file(bad_phase2)}))
                bad_candidate = self.root / f"candidate-{name}.seal.json"
                create_tree_seal(bad_candidate_root, bad_candidate, sha256_file(bad_phase2), "phase3-candidate-artifacts")
                self.assert_fail("claim7", phase2_closure_seal=bad_phase2, phase3_candidate_seal=bad_candidate)

    def test_terminal_accepts_only_exact_dual_reviews_and_immutable_external_state(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from work7_evidence import create_tree_seal, sha256_file, snapshot_git_worktree
        paper, threshold = self.root / "paper", self.root / "threshold"
        for repo in (paper, threshold):
            repo.mkdir(); subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            (repo / "tracked.txt").write_text("stable\n"); subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "-c", "user.email=x@y.z", "-c", "user.name=x", "commit", "-qm", "init"], cwd=repo, check=True)
        phase0_root = self.root / "phase0"; phase0_root.mkdir()
        (phase0_root / "state.json").write_text(json.dumps({"schema": "piccard-work7-phase0-state-v1", "source": {"head": COMMIT}, "session_id": f"work7-{COMMIT}", "paper": snapshot_git_worktree(paper), "threshold": snapshot_git_worktree(threshold)}))
        phase0 = self.root / "phase0.seal.json"; create_tree_seal(phase0_root, phase0, None, "phase0")
        runtime = self.runtime()
        evidence = self.invoke("evidence-bound", runtime_seal=runtime)
        self.assertEqual(evidence.returncode, 0, evidence.stderr)
        phase2_root = self.root / "phase2-terminal"; phase2_root.mkdir()
        (phase2_root / "evidence-bound-report.json").write_bytes(evidence.output_path.read_bytes())  # type: ignore[attr-defined]
        phase2 = self.root / "phase2-terminal.seal.json"; create_tree_seal(phase2_root, phase2, sha256_file(runtime), "phase2-closure")
        candidate_root = self.root / "candidate-terminal"; candidate_root.mkdir()
        (candidate_root / "candidate-validation.json").write_text(json.dumps({"schema": "piccard-work7-candidate-validation-v1", "source_commit": COMMIT, "claim_id": "W7-G7-INTEGRATION", "phase2_closure_seal_sha256": sha256_file(phase2)}) + "\n")
        candidate = self.root / "candidate-terminal.seal.json"; create_tree_seal(candidate_root, candidate, sha256_file(phase2), "phase3-candidate-artifacts")
        claim7 = self.invoke("claim7", phase2_closure_seal=phase2, phase3_candidate_seal=candidate)
        self.assertEqual(claim7.returncode, 0, claim7.stderr)
        phase3_root = self.root / "phase3"; phase3_root.mkdir()
        (phase3_root / "claim7-report.json").write_bytes(claim7.output_path.read_bytes())  # type: ignore[attr-defined]
        phase3 = self.root / "phase3.seal.json"; create_tree_seal(phase3_root, phase3, sha256_file(candidate), "phase3-closure")
        packet = self.root / "packet.json"; packet.write_bytes(b"packet\n")
        digest = hashlib.sha256(packet.read_bytes()).hexdigest()
        def review(provider: str, model: str) -> Path:
            path = self.root / f"{provider}.txt"
            path.write_text("\n".join(["VERDICT: APPROVED", f"PROVIDER: {provider}", f"MODEL: {model}", "EFFORT: high", f"SOURCE_COMMIT: {COMMIT}", f"PACKET_SHA256: {digest}", "STATUS: POC_APPROVED_PERFORMANCE_PENDING", "CHECK G1_G7_INTENT: CONFIRMED", "CHECK EVIDENCE_FRESHNESS: CONFIRMED", "CHECK PERFORMANCE_PENDING: CONFIRMED", "CHECK THRESHOLD_DEFERRED: CONFIRMED", "CHECK EXTERNAL_IMMUTABILITY: CONFIRMED", "CHECK TERMINAL_STATUS_MAXIMAL: CONFIRMED", "prose"]) + "\n")
            return path
        claude_review, sol_review = review("anthropic", "claude-fable"), review("openai", "gpt-5.6-sol")
        work_root = self.root / "work"; work_root.mkdir()
        for path in (packet, claude_review, sol_review):
            (work_root / path.name).write_bytes(path.read_bytes())
        work = self.root / "work.seal.json"; create_tree_seal(work_root, work, sha256_file(phase3), "phase4-work-review")
        report = self.assert_pass("terminal", phase3_closure_seal=phase3, work_review_seal=work, review_packet=packet, claude_review=claude_review, sol_review=sol_review, phase0_seal=phase0, paper_root=paper, threshold_root=threshold)
        self.assertEqual(report["work_gate_state"], "POC_APPROVED_PERFORMANCE_PENDING")

        claude, sol = self.root / "anthropic.txt", self.root / "openai.txt"
        common = {"phase3_closure_seal": phase3, "work_review_seal": work, "review_packet": packet,
                  "claude_review": claude, "sol_review": sol, "phase0_seal": phase0,
                  "paper_root": paper, "threshold_root": threshold}
        original = claude.read_text()
        mutations = {
            "mismatched-packet": lambda: packet.write_bytes(b"changed packet\n"),
            "mismatched-commit": lambda: claude.write_text(original.replace(COMMIT, "c" * 40)),
            "conditional-verdict": lambda: claude.write_text(original.replace("VERDICT: APPROVED", "VERDICT: APPROVED_WITH_COMMENTS")),
            "wrong-provider": lambda: claude.write_text(original.replace("PROVIDER: anthropic", "PROVIDER: openai")),
            "wrong-model": lambda: claude.write_text(original.replace("MODEL: claude-fable", "MODEL: gpt-5.6-sol")),
            "header-only": lambda: claude.write_text("\n".join(original.splitlines()[:7]) + "\n"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                packet.write_bytes(b"packet\n")
                claude.write_text(original)
                mutate()
                self.assert_fail("terminal", **common)
        for confirmation in ("G1_G7_INTENT", "EVIDENCE_FRESHNESS", "PERFORMANCE_PENDING",
                             "THRESHOLD_DEFERRED", "EXTERNAL_IMMUTABILITY", "TERMINAL_STATUS_MAXIMAL"):
            with self.subTest(missing_confirmation=confirmation):
                claude.write_text(original.replace(f"CHECK {confirmation}: CONFIRMED\n", ""))
                self.assert_fail("terminal", **common)
        claude.write_text(original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
