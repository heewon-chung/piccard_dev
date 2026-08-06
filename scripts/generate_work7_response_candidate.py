#!/usr/bin/env python3
"""Create an unapplied, sealed Work 7 ResponseStrategy candidate.

This tool deliberately writes only session-local evidence.  It never invokes a
Paper-side patch tool and treats the two external worktrees as byte snapshots.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from work7_evidence import (assert_output_roots_outside, _atomic_create,
                                _reject_symlink_components, _stable_regular_file, canonical_json_bytes,
                                create_tree_seal, sha256_file, snapshot_git_worktree,
                                verify_tree_seal)
except ModuleNotFoundError:
    from scripts.work7_evidence import (assert_output_roots_outside, _atomic_create,
                                        _reject_symlink_components, _stable_regular_file, canonical_json_bytes,
                                        create_tree_seal, sha256_file, snapshot_git_worktree,
                                        verify_tree_seal)


IDS = ("W7-G1-ESTIMATOR", "W7-G2-SANITIZER", "W7-G3-CALIBRATION",
       "W7-G4-COMPARISON", "W7-G5-REAL-DATA", "W7-G6-DYNAMIC", "W7-G7-INTEGRATION")


class Failure(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Failure(f"invalid arguments: {message}")


def parser() -> argparse.ArgumentParser:
    value = Parser(add_help=False)
    for name in ("source-root", "paper-root", "threshold-root", "session-root", "phase0-seal", "phase2-closure-seal"):
        value.add_argument("--" + name, required=True, type=Path)
    return value


def required_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise Failure(f"{label} must be an absolute path")
    _reject_symlink_components(path)
    try:
        value = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise Failure(f"{label} does not exist") from error
    if not value.is_dir():
        raise Failure(f"{label} is not a directory")
    return value


def required_file(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise Failure(f"{label} must be an absolute path")
    _reject_symlink_components(path)
    try:
        value = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise Failure(f"{label} does not exist") from error
    info = value.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise Failure(f"{label} is not a regular file")
    return value


def under(root: Path, candidate: Path, label: str) -> Path:
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise Failure(f"{label} escapes session root") from error
    return candidate


def exact_state(phase0: Path, source: Path, paper: Path, threshold: Path, session: Path) -> tuple[dict, str]:
    try:
        value = verify_tree_seal(phase0)
    except (OSError, ValueError) as error:
        raise Failure("invalid or tampered Phase 0 seal") from error
    if value["kind"] != "phase0" or value["previous_seal_sha256"] is not None:
        raise Failure("foreign Phase 0 seal")
    artifacts = Path(value["artifact_root"])
    expected = session / "phase0" / "artifacts"
    if artifacts != expected:
        raise Failure("Phase 0 artifact root is foreign")
    state_path = artifacts / "state.json"
    if "state.json" not in {entry["path"] for entry in value["entries"]}:
        raise Failure("Phase 0 state is not sealed")
    try:
        state = json.loads(state_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("invalid Phase 0 state") from error
    if (not isinstance(state, dict) or set(state) != {"schema", "source", "paper", "threshold", "session_id"} or
            state.get("schema") != "piccard-work7-phase0-state-v1" or not isinstance(state.get("source"), dict) or
            state.get("session_id") != "work7-" + state["source"].get("head", "")):
        raise Failure("invalid Phase 0 state")
    commit = state["source"].get("head")
    if not isinstance(commit, str) or len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise Failure("invalid Phase 0 source commit")
    assert_phase0_snapshots(state, source, paper, threshold)
    return state, commit


def assert_phase0_snapshots(state: dict, source: Path, paper: Path, threshold: Path) -> None:
    """Require all guarded worktrees to remain exactly as sealed in Phase 0."""
    expected = {"source": source, "paper": paper, "threshold": threshold}
    for name, root in expected.items():
        if snapshot_git_worktree(root) != state.get(name):
            raise Failure(f"Phase 0 snapshot changed: {name}")


def verify_phase2_chain(phase2: Path, phase0: Path, session: Path) -> None:
    try:
        closure = verify_tree_seal(phase2)
    except (OSError, ValueError) as error:
        raise Failure("invalid or tampered Phase 2 closure seal") from error
    if closure["kind"] != "phase2-closure" or Path(closure["artifact_root"]) != session / "phase2" / "closure-artifacts":
        raise Failure("foreign Phase 2 closure seal")
    runtime = session / "phase2" / "runtime-seal.json"
    if closure["previous_seal_sha256"] != sha256_file(runtime):
        raise Failure("Phase 2 closure does not bind runtime seal")
    try:
        runtime_value = verify_tree_seal(runtime, sha256_file(phase0))
    except (OSError, ValueError) as error:
        raise Failure("invalid or tampered Phase 2 runtime seal") from error
    if runtime_value["kind"] != "phase2-runtime-artifacts" or Path(runtime_value["artifact_root"]) != session / "phase2" / "runtime":
        raise Failure("foreign Phase 2 runtime seal")


def read_baseline(paper: Path) -> tuple[Path, bytes, str]:
    path = paper / "Revision" / "ResponseStrategy.md"
    try:
        _reject_symlink_components(path)
    except ValueError as error:
        raise Failure("ResponseStrategy input is missing or not a regular file") from error
    if not path.exists() or path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise Failure("ResponseStrategy input is missing or not a regular file")
    try:
        digest, _, raw = _stable_regular_file(path)
    except ValueError as error:
        raise Failure("ResponseStrategy input changed or is unsafe") from error
    try:
        raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise Failure("ResponseStrategy input is not UTF-8") from error
    return path, raw, digest


def render_candidate(baseline: bytes) -> bytes:
    text = baseline.decode("utf-8", "strict")
    suffix = "" if not text or text.endswith("\n") else "\n"
    rows = "\n".join(f"- `{claim}`: `IMPLEMENTED`; `TOY_VERIFIED`; `PERFORMANCE_PENDING`." for claim in IDS)
    section = (
        "\n<!-- WORK7_RESPONSE_CANDIDATE_BEGIN -->\n"
        "### Work 7 PoC integration candidate — unapplied\n\n"
        "This candidate records implementation and toy-evidence readiness only; it does not make a paper-grade completion or performance claim.\n\n"
        f"{rows}\n\n"
        "All performance evaluation remains `PERFORMANCE_PENDING`; actual-data and repeated-measurement campaigns are deferred.\n\n"
        "Threshold FP/FN work remains `DEFERRED_EXPECTED`. It is not authorized by this candidate and no threshold branch action is requested.\n"
        "<!-- WORK7_RESPONSE_CANDIDATE_END -->\n"
    )
    return (text + suffix + section).encode("utf-8")


def make_diff(before: bytes, after: bytes) -> bytes:
    left = before.decode("utf-8", "strict").splitlines(keepends=True)
    right = after.decode("utf-8", "strict").splitlines(keepends=True)
    return "".join(difflib.unified_diff(left, right, fromfile="a/Revision/ResponseStrategy.md",
                                          tofile="b/Revision/ResponseStrategy.md", lineterm="\n")).encode("utf-8")


def apply_unified(before: str, diff: str) -> str:
    """Strictly apply the generator's unified diff without touching Paper."""
    lines = before.splitlines(keepends=True)
    patch = diff.splitlines(keepends=True)
    if len(patch) < 2 or patch[0] != "--- a/Revision/ResponseStrategy.md\n" or patch[1] != "+++ b/Revision/ResponseStrategy.md\n":
        raise Failure("candidate diff has invalid headers")
    import re
    cursor = 0
    output: list[str] = []
    index = 2
    while index < len(patch):
        header = patch[index]
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n", header)
        if match is None:
            raise Failure("candidate diff has invalid hunk")
        old_start = int(match.group(1)) - 1
        if old_start < cursor or old_start > len(lines):
            raise Failure("candidate diff has invalid hunk location")
        output.extend(lines[cursor:old_start]); cursor = old_start; index += 1
        while index < len(patch) and not patch[index].startswith("@@ "):
            item = patch[index]
            if not item or item[0] not in " +-":
                raise Failure("candidate diff has invalid hunk entry")
            body = item[1:]
            if item[0] == " ":
                if cursor >= len(lines) or lines[cursor] != body:
                    raise Failure("candidate diff context does not apply")
                output.append(body); cursor += 1
            elif item[0] == "-":
                if cursor >= len(lines) or lines[cursor] != body:
                    raise Failure("candidate diff removal does not apply")
                cursor += 1
            else:
                output.append(body)
            index += 1
    output.extend(lines[cursor:])
    return "".join(output)


def dry_apply(before: bytes, diff: bytes, expected: bytes) -> None:
    try:
        applied = apply_unified(before.decode("utf-8", "strict"), diff.decode("utf-8", "strict")).encode("utf-8")
    except UnicodeDecodeError as error:
        raise Failure("candidate diff is not UTF-8") from error
    if applied != expected:
        raise Failure("candidate diff does not dry-apply to recorded bytes")
    with tempfile.TemporaryDirectory(prefix="work7-candidate-dry-apply-") as temporary:
        copy = Path(temporary) / "ResponseStrategy.md"
        copy.write_bytes(applied)
        if copy.read_bytes() != expected:
            raise Failure("candidate dry-apply copy mismatch")


def ensure_safe_prose(candidate: bytes) -> None:
    text = candidate.decode("utf-8", "strict")
    section = text.split("<!-- WORK7_RESPONSE_CANDIDATE_BEGIN -->", 1)[-1]
    if (text.count("<!-- WORK7_RESPONSE_CANDIDATE_BEGIN -->") != 1 or text.count("<!-- WORK7_RESPONSE_CANDIDATE_END -->") != 1 or
            any(section.count(claim) != 1 for claim in IDS) or "IMPLEMENTED" not in section or
            "TOY_VERIFIED" not in section or "PERFORMANCE_PENDING" not in section or
            "DEFERRED_EXPECTED" not in section or "not authorized" not in section.lower()):
        raise Failure("candidate prose does not map all lifecycle claims conservatively")
    prohibited = ("paper-grade completion", "performance claim", "authorized threshold", "threshold complete")
    # The two first phrases are allowed only as explicit negations in the fixed wording.
    if any(word in section.lower() for word in prohibited[2:]):
        raise Failure("candidate prose overclaims threshold scope")


def write_artifacts(root: Path, baseline: bytes, candidate: bytes, diff: bytes, state: dict, commit: str,
                    phase0: Path, phase2: Path) -> None:
    if root.exists() or root.is_symlink():
        raise Failure("candidate artifact collision")
    root.mkdir(parents=True, mode=0o700)
    mappings = [{"id": claim, "implementation_state": "IMPLEMENTED", "toy_evidence_state": "TOY_VERIFIED",
                 "performance_state": "PERFORMANCE_PENDING"} for claim in IDS]
    metadata = {
        "schema": "piccard-work7-candidate-metadata-v1", "source_commit": commit,
        "paper_head": state["paper"]["head"], "paper_snapshot_sha256": state["paper"]["snapshot_sha256"],
        "threshold_snapshot_sha256": state["threshold"]["snapshot_sha256"],
        "phase0_seal_sha256": sha256_file(phase0), "phase2_closure_seal_sha256": sha256_file(phase2),
        "baseline_response_strategy_sha256": hashlib.sha256(baseline).hexdigest(),
        "candidate_filename": "ResponseStrategy.candidate.md", "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
        "diff_filename": "ResponseStrategy.candidate.diff", "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "claim_mappings": mappings, "dry_apply_status": "PASS", "work_gate_state": "PENDING",
        "performance_state": "PERFORMANCE_PENDING", "threshold_gate_state": "DEFERRED_EXPECTED",
        "threshold_authorized": False,
    }
    metadata_bytes = canonical_json_bytes(metadata)
    validation = {
        "schema": "piccard-work7-candidate-validation-v1", "source_commit": commit,
        "paper_head": state["paper"]["head"], "paper_snapshot_sha256": state["paper"]["snapshot_sha256"],
        "threshold_snapshot_sha256": state["threshold"]["snapshot_sha256"],
        "phase0_seal_sha256": sha256_file(phase0), "phase2_closure_seal_sha256": sha256_file(phase2),
        "baseline_response_strategy_sha256": hashlib.sha256(baseline).hexdigest(),
        "candidate_filename": "ResponseStrategy.candidate.md", "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
        "diff_filename": "ResponseStrategy.candidate.diff", "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "metadata_filename": "candidate-metadata.json", "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        "claim_mappings": mappings, "dry_apply_status": "PASS", "work_gate_state": "PENDING",
        "performance_state": "PERFORMANCE_PENDING", "threshold_gate_state": "DEFERRED_EXPECTED",
        "threshold_authorized": False,
    }
    for name, content in (("ResponseStrategy.candidate.md", candidate), ("ResponseStrategy.candidate.diff", diff),
                          ("candidate-metadata.json", metadata_bytes),
                          ("candidate-validation.json", canonical_json_bytes(validation))):
        _atomic_create(root / name, content)


def run_claim7(source: Path, paper: Path, threshold: Path, session: Path, commit: str, phase0: Path,
               phase2: Path, candidate_seal: Path) -> None:
    closure = session / "phase3" / "closure-artifacts"
    if closure.exists() or closure.is_symlink():
        raise Failure("claim7 closure artifact collision")
    closure.mkdir(parents=True, mode=0o700)
    inventory = session / "phase2" / "runtime" / "commands" / "ctest-inventory.stdout.txt"
    argv = (sys.executable, str(source / "scripts" / "verify_work7_claims.py"), "--mode", "claim7",
            "--contract", str(source / "scripts" / "work7_claims.json"), "--source-root", str(source),
            "--source-commit", commit, "--ctest-inventory", str(inventory),
            "--phase2-closure-seal", str(phase2), "--phase3-candidate-seal", str(candidate_seal),
            "--phase0-seal", str(phase0), "--paper-root", str(paper), "--threshold-root", str(threshold),
            "--output", str(closure / "claim7-report.json"))
    result = subprocess.run(argv, cwd=source, check=False, capture_output=True)
    _atomic_create(closure / "claim7-command.json", canonical_json_bytes({"argv": list(argv), "returncode": result.returncode}))
    _atomic_create(closure / "claim7.stdout.txt", result.stdout)
    _atomic_create(closure / "claim7.stderr.txt", result.stderr)
    if result.returncode != 0:
        raise Failure("claim7 verifier failed")
    report_path = closure / "claim7-report.json"
    if not report_path.exists():
        raise Failure("claim7 verifier omitted its report")
    # Validate the report's full semantics, not merely a successful subprocess exit.
    try:
        from verify_work7_claims import inventory as ctest_inventory, load_contract, report_claims
    except ModuleNotFoundError:
        from scripts.verify_work7_claims import inventory as ctest_inventory, load_contract, report_claims
    try:
        raw = report_path.read_bytes()
        report = json.loads(raw)
        if canonical_json_bytes(report) != raw:
            raise Failure("claim7 verifier report is non-canonical")
        contract = load_contract(source / "scripts" / "work7_claims.json", source, ctest_inventory(inventory))
        report_claims(report, "claim7", commit, ["TOY_VERIFIED"] * 7, contract)
        if report["input_seals"] != {"phase2_closure_seal_sha256": sha256_file(phase2),
                                      "phase3_candidate_seal_sha256": sha256_file(candidate_seal)}:
            raise Failure("claim7 verifier report has wrong input seals")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise Failure("claim7 verifier produced a malformed or foreign report") from error


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        source = required_directory(args.source_root, "source root")
        paper = required_directory(args.paper_root, "paper root")
        threshold = required_directory(args.threshold_root, "threshold root")
        session = required_directory(args.session_root, "session root")
        phase0 = required_file(args.phase0_seal, "Phase 0 seal")
        phase2 = required_file(args.phase2_closure_seal, "Phase 2 closure seal")
        assert_output_roots_outside([source, paper, threshold], [session])
        for item, label in ((phase0, "Phase 0 seal"), (phase2, "Phase 2 closure seal")):
            under(session, item, label)
        if phase0 != session / "phase0" / "seal.json" or phase2 != session / "phase2" / "closure-seal.json":
            raise Failure("Phase seal path is outside the canonical session location")
        if (session / "phase3").exists() or (session / "phase3").is_symlink():
            raise Failure("candidate artifact collision")
        state, commit = exact_state(phase0, source, paper, threshold, session)
        verify_phase2_chain(phase2, phase0, session)
        _, baseline, _ = read_baseline(paper)
        assert_phase0_snapshots(state, source, paper, threshold)
        candidate = render_candidate(baseline)
        ensure_safe_prose(candidate)
        diff = make_diff(baseline, candidate)
        dry_apply(baseline, diff, candidate)
        assert_phase0_snapshots(state, source, paper, threshold)
        candidate_root = session / "phase3" / "candidate-artifacts"
        write_artifacts(candidate_root, baseline, candidate, diff, state, commit, phase0, phase2)
        assert_phase0_snapshots(state, source, paper, threshold)
        candidate_seal = session / "phase3" / "candidate-seal.json"
        create_tree_seal(candidate_root, candidate_seal, sha256_file(phase2), "phase3-candidate-artifacts")
        verify_tree_seal(candidate_seal, sha256_file(phase2))
        assert_phase0_snapshots(state, source, paper, threshold)
        run_claim7(source, paper, threshold, session, commit, phase0, phase2, candidate_seal)
        verify_tree_seal(candidate_seal, sha256_file(phase2))
        assert_phase0_snapshots(state, source, paper, threshold)
        closure_root = session / "phase3" / "closure-artifacts"
        closure_seal = session / "phase3" / "closure-seal.json"
        assert_phase0_snapshots(state, source, paper, threshold)
        create_tree_seal(closure_root, closure_seal, sha256_file(candidate_seal), "phase3-closure")
        verify_tree_seal(closure_seal, sha256_file(candidate_seal))
        assert_phase0_snapshots(state, source, paper, threshold)
    except (Failure, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"generate_work7_response_candidate: FAIL: {error}", file=sys.stderr)
        return 2
    print("generate_work7_response_candidate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
