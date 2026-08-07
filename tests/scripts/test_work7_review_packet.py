"""CLI behavior coverage for Work 7 review packets and terminal closure."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]


class Work7ReviewPacketTests(unittest.TestCase):
    """The packet is a real session-local snapshot, never a source-text check."""

    def setUp(self):
        from tests.scripts.test_work7_response_candidate import Work7ResponseCandidateTests

        self.temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temporary, True)
        helper = Work7ResponseCandidateTests()
        self.source, self.paper, self.threshold, self.session, self.commit, _ = helper.make_phase_inputs(self.temporary)
        static = subprocess.run((sys.executable, str(ROOT / "scripts/verify_work7_claims.py"), "--mode", "static",
                                 "--contract", str(self.source / "scripts/work7_claims.json"), "--source-root", str(self.source),
                                 "--source-commit", self.commit, "--ctest-inventory", str(self.session / "phase2/runtime/commands/ctest-inventory.stdout.txt"),
                                 "--output", str(self.session / "phase2/static-report.json")), capture_output=True)
        self.assertEqual(static.returncode, 0, static.stderr.decode())
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
        lines = ["VERDICT: APPROVED", "PROVIDER: openai", "MODEL: gpt-5.6-sol", "EFFORT: high",
                 f"SOURCE_COMMIT: {self.commit}", f"PACKET_SHA256: {hashlib.sha256(packet.read_bytes()).hexdigest()}",
                 "STATUS: WORK7_APPROVED"]
        if checks:
            lines.extend(f"CHECK {name}: CONFIRMED" for name in ("POC_SCOPE", "ONE_RUN_POLICY", "PROVENANCE", "FAIL_CLOSED", "EXTERNAL_IMMUTABILITY", "NO_OVERCLAIM"))
        review.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return review

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
        for mutation in ("missing", "extra", "reordered"):
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
                    value["members"].reverse()
                packet.write_bytes((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
                result = self.command("close-work", "--packet", str(packet), "--raw-review", str(self.work_review(packet)),
                                      "--session-root", str(self.session), "--output-seal", str(self.session / "phase4/work-review-seal.json"))
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertFalse((self.session / "phase4/work-review-seal.json").exists())
                packet.write_bytes((json.dumps(original, sort_keys=True, separators=(",", ":")) + "\n").encode())

    def test_final_close_binds_two_distinct_final_approvals_and_terminal_seal(self):
        """A duplicate provider or a final packet not bound to Phase 4 must fail closure."""
        from scripts.work7_evidence import sha256_file, verify_tree_seal

        packet = self.prepare_work()
        work = self.work_review(packet)
        work_seal = self.session / "phase4/work-review-seal.json"
        self.assertEqual(self.command("close-work", "--packet", str(packet), "--raw-review", str(work),
                                      "--session-root", str(self.session), "--output-seal", str(work_seal)).returncode, 0)
        final_packet = self.session / "phase5/final-packet.json"
        prepared = self.command("prepare-final", "--source-root", str(self.source), "--session-root", str(self.session),
                                "--work-review-seal", str(work_seal), "--output", str(final_packet))
        self.assertEqual(prepared.returncode, 0, prepared.stderr.decode())
        digest = hashlib.sha256(final_packet.read_bytes()).hexdigest()
        def final_review(provider: str, model: str) -> Path:
            path = self.temporary / f"{provider}-final.txt"
            path.write_text("\n".join(["VERDICT: APPROVED", f"PROVIDER: {provider}", f"MODEL: {model}", "EFFORT: high",
                f"SOURCE_COMMIT: {self.commit}", f"PACKET_SHA256: {digest}", "STATUS: POC_APPROVED_PERFORMANCE_PENDING",
                *[f"CHECK {check}: CONFIRMED" for check in ("G1_G7_INTENT", "EVIDENCE_FRESHNESS", "PERFORMANCE_PENDING", "THRESHOLD_DEFERRED", "EXTERNAL_IMMUTABILITY", "TERMINAL_STATUS_MAXIMAL")]]) + "\n", encoding="utf-8")
            return path
        claude, sol = final_review("anthropic", "claude-fable"), final_review("openai", "gpt-5.6-sol")
        terminal, seal = self.session / "phase5/terminal-report.json", self.session / "phase5/terminal-seal.json"
        closed = self.command("close-final", "--packet", str(final_packet), "--claude-review", str(claude), "--sol-review", str(sol),
                              "--terminal-report", str(terminal), "--session-root", str(self.session), "--phase0-seal", str(self.session / "phase0/seal.json"),
                              "--paper-root", str(self.paper), "--threshold-root", str(self.threshold), "--output-seal", str(seal))
        self.assertEqual(closed.returncode, 0, closed.stderr.decode())
        self.assertEqual(closed.stdout.decode(), f"WORK7_TERMINAL_SEAL_SHA256={sha256_file(seal)}\n")
        self.assertEqual((self.session / "phase5/terminal-seal.sha256").read_text(), sha256_file(seal) + "\n")
        self.assertEqual(verify_tree_seal(seal, sha256_file(work_seal))["kind"], "phase5-terminal")
