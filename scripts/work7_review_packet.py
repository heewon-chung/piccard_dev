#!/usr/bin/env python3
"""Freeze Work 7 review inputs and close its two fail-closed review gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

try:
    from work7_evidence import (assert_output_roots_outside, _atomic_create,
                                _reject_symlink_components, _stable_regular_file,
                                canonical_json_bytes, create_tree_seal, sha256_file,
                                snapshot_git_worktree, verify_tree_seal)
except ModuleNotFoundError:
    from scripts.work7_evidence import (assert_output_roots_outside, _atomic_create,
                                         _reject_symlink_components, _stable_regular_file,
                                         canonical_json_bytes, create_tree_seal, sha256_file,
                                         snapshot_git_worktree, verify_tree_seal)


DESIGNS = (
    "docs/superpowers/specs/2026-08-06-work7-pre-threshold-poc-integration-design.md",
    "docs/superpowers/specs/2026-08-06-work7-phase0-state-guard-design.md",
    "docs/superpowers/specs/2026-08-06-work7-phase1-claim-contract-design.md",
    "docs/superpowers/specs/2026-08-06-work7-phase2-toy-runner-design.md",
    "docs/superpowers/specs/2026-08-06-work7-phase3-response-candidate-design.md",
    "docs/superpowers/specs/2026-08-06-work7-phase4-work-review-design.md",
    "docs/superpowers/specs/2026-08-06-work7-phase5-dual-review-design.md",
)
PLAN = "docs/superpowers/plans/2026-08-06-work7-terra-pre-threshold-integration.md"
CHECKS_WORK = ("POC_SCOPE", "ONE_RUN_POLICY", "PROVENANCE", "FAIL_CLOSED",
               "EXTERNAL_IMMUTABILITY", "NO_OVERCLAIM")
CHECKS_FINAL = ("G1_G7_INTENT", "EVIDENCE_FRESHNESS", "PERFORMANCE_PENDING",
                "THRESHOLD_DEFERRED", "EXTERNAL_IMMUTABILITY", "TERMINAL_STATUS_MAXIMAL")
WORK_SESSION_MEMBERS = (
    "phase2/static-report.json", "phase2/closure-artifacts/evidence-bound-report.json",
    "phase3/closure-artifacts/claim7-report.json", "phase0/seal.json", "phase2/runtime-seal.json",
    "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json",
    "phase3/candidate-artifacts/ResponseStrategy.candidate.md", "phase3/candidate-artifacts/ResponseStrategy.candidate.diff",
    "phase3/candidate-artifacts/candidate-metadata.json", "phase3/candidate-artifacts/candidate-validation.json",
    "phase0/artifacts/state.json",
)


class Failure(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Failure(f"invalid arguments: {message}")


def parser() -> argparse.ArgumentParser:
    value = Parser(add_help=False)
    commands = value.add_subparsers(dest="command", required=True)
    work = commands.add_parser("prepare-work", add_help=False)
    work.add_argument("--source-root", required=True, type=Path)
    work.add_argument("--session-root", required=True, type=Path)
    work.add_argument("--baseline-commit", required=True)
    work.add_argument("--output", required=True, type=Path)
    close_work = commands.add_parser("close-work", add_help=False)
    close_work.add_argument("--packet", required=True, type=Path)
    close_work.add_argument("--raw-review", required=True, type=Path)
    close_work.add_argument("--session-root", required=True, type=Path)
    close_work.add_argument("--output-seal", required=True, type=Path)
    final = commands.add_parser("prepare-final", add_help=False)
    final.add_argument("--source-root", required=True, type=Path)
    final.add_argument("--session-root", required=True, type=Path)
    final.add_argument("--work-review-seal", required=True, type=Path)
    final.add_argument("--output", required=True, type=Path)
    close_final = commands.add_parser("close-final", add_help=False)
    for name in ("packet", "claude-review", "sol-review", "terminal-report", "session-root", "phase0-seal",
                 "paper-root", "threshold-root", "output-seal"):
        close_final.add_argument("--" + name, required=True, type=Path)
    return value


def required(path: Path, label: str, *, directory: bool = False, exists: bool = True) -> Path:
    if not path.is_absolute():
        raise Failure(f"{label} must be an absolute path")
    _reject_symlink_components(path)
    try:
        result = path.resolve(strict=exists)
    except FileNotFoundError as error:
        raise Failure(f"{label} does not exist") from error
    if exists and ((directory and not result.is_dir()) or (not directory and not result.is_file())):
        raise Failure(f"{label} has wrong type")
    return result


def session_path(session: Path, path: Path, label: str, *, exists: bool = True) -> Path:
    result = required(path, label, exists=exists)
    try:
        result.relative_to(session)
    except ValueError as error:
        raise Failure(f"{label} escapes session root") from error
    return result


def canonical_object(path: Path, label: str) -> dict:
    try:
        raw = path.read_bytes(); value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise Failure(f"invalid {label}") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise Failure(f"non-canonical {label}")
    return value


def phase0(session: Path, path: Path) -> tuple[dict, str]:
    path = session_path(session, path, "Phase 0 seal")
    if path != session / "phase0/seal.json":
        raise Failure("foreign Phase 0 seal path")
    try:
        seal = verify_tree_seal(path)
    except (OSError, ValueError) as error:
        raise Failure("invalid or tampered Phase 0 seal") from error
    if seal["kind"] != "phase0" or seal["previous_seal_sha256"] is not None or Path(seal["artifact_root"]) != session / "phase0/artifacts":
        raise Failure("foreign Phase 0 seal")
    state = canonical_object(session / "phase0/artifacts/state.json", "Phase 0 state")
    commit = state.get("source", {}).get("head") if isinstance(state.get("source"), dict) else None
    if (set(state) != {"schema", "source", "paper", "threshold", "session_id"} or
            state.get("schema") != "piccard-work7-phase0-state-v1" or not isinstance(commit, str) or
            len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit) or
            state.get("session_id") != "work7-" + commit):
        raise Failure("invalid Phase 0 state")
    return state, commit


def chain(session: Path) -> tuple[dict, str]:
    state, commit = phase0(session, session / "phase0/seal.json")
    paths = (("phase2/runtime-seal.json", "phase2-runtime-artifacts", "phase2/runtime", sha256_file(session / "phase0/seal.json")),
             ("phase2/closure-seal.json", "phase2-closure", "phase2/closure-artifacts", None),
             ("phase3/candidate-seal.json", "phase3-candidate-artifacts", "phase3/candidate-artifacts", None),
             ("phase3/closure-seal.json", "phase3-closure", "phase3/closure-artifacts", None))
    previous = None
    for relative, kind, root, initial in paths:
        path = session / relative
        wanted = initial if initial is not None else previous
        try:
            seal = verify_tree_seal(path, wanted)
        except (OSError, ValueError) as error:
            raise Failure("invalid or tampered prerequisite seal") from error
        if seal["kind"] != kind or Path(seal["artifact_root"]) != session / root:
            raise Failure("foreign prerequisite seal")
        previous = sha256_file(path)
    return state, commit


def copy_member(source: Path, session: Path, member_root: Path, label: str, members: list[dict]) -> None:
    try:
        digest, info, raw = _stable_regular_file(source)
    except ValueError as error:
        raise Failure(f"unsafe packet member: {label}") from error
    target = member_root / label
    if target.exists() or target.is_symlink():
        raise Failure("packet member collision")
    _atomic_create(target, raw)
    members.append({"label": label.replace("/", ":"), "path": target.relative_to(session).as_posix(),
                    "size": info.st_size, "sha256": digest})


def packet_bytes(phase: str, commit: str, seals: dict[str, str], members: list[dict]) -> bytes:
    if len({member["path"] for member in members}) != len(members):
        raise Failure("duplicate packet member")
    return canonical_json_bytes({"schema": "piccard-work7-review-packet-v1", "phase": phase,
                                 "source_commit": commit, "prerequisite_seals": seals,
                                 "members": sorted(members, key=lambda item: item["path"])})


def expected_member_paths(phase: str) -> set[str]:
    work = {"phase4/members/source/" + item for item in DESIGNS + (PLAN, "scripts/work7_claims.json")}
    work |= {"phase4/members/source/git-diff-b907fae-to-head.patch"}
    work |= {"phase4/members/session/" + item for item in WORK_SESSION_MEMBERS}
    work |= {"phase4/members/external/current-paper-state.json", "phase4/members/external/current-threshold-state.json"}
    if phase == "work": return work
    final = {path.replace("phase4/members/", "phase5/members/") for path in work}
    final |= {"phase5/members/source/docs/superpowers/specs/2026-07-29-pre-threshold-poc-design.md",
              "phase5/members/session/phase4/work-review-artifacts/work-packet.json",
              "phase5/members/session/phase4/work-review-artifacts/raw-review.txt",
              "phase5/members/session/phase4/work-review-seal.json",
              "phase5/members/generated/works1-6-source-test-map.json",
              "phase5/members/generated/final-verification-summary.json"}
    return final


def validate_packet(path: Path, session: Path, phase: str, commit: str, seals: dict[str, str]) -> dict:
    value = canonical_object(path, f"{phase} packet")
    if (set(value) != {"schema", "phase", "source_commit", "prerequisite_seals", "members"} or
            value.get("schema") != "piccard-work7-review-packet-v1" or value.get("phase") != phase or
            value.get("source_commit") != commit or value.get("prerequisite_seals") != seals or
            not isinstance(value.get("members"), list) or not value["members"]):
        raise Failure("foreign or invalid review packet")
    paths: set[str] = set()
    for member in value["members"]:
        if (not isinstance(member, dict) or set(member) != {"label", "path", "size", "sha256"} or
                not isinstance(member["label"], str) or not member["label"] or not isinstance(member["path"], str) or
                not isinstance(member["size"], int) or member["size"] < 0 or not isinstance(member["sha256"], str) or
                len(member["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in member["sha256"])):
            raise Failure("invalid review packet member")
        relative = Path(member["path"])
        if relative.is_absolute() or ".." in relative.parts or member["path"] in paths:
            raise Failure("invalid review packet member")
        paths.add(member["path"])
        candidate = session / relative
        if not candidate.is_file() or candidate.is_symlink() or candidate.stat().st_size != member["size"] or sha256_file(candidate) != member["sha256"]:
            raise Failure("review packet member changed or missing")
    if paths != expected_member_paths(phase):
        raise Failure("review packet member manifest is not exact")
    if value["members"] != sorted(value["members"], key=lambda item: item["path"]):
        raise Failure("review packet member order is not canonical")
    return value


def git_diff(source: Path, baseline: str) -> bytes:
    if baseline != "b907fae":
        raise Failure("baseline commit must be exactly b907fae")
    result = subprocess.run(("git", "diff", f"{baseline}..HEAD"), cwd=source, capture_output=True,
                            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    if result.returncode:
        raise Failure("cannot generate baseline diff")
    return result.stdout


def prepare_work(args: argparse.Namespace) -> None:
    source, session = required(args.source_root, "source root", directory=True), required(args.session_root, "session root", directory=True)
    assert_output_roots_outside([source], [session])
    output = session_path(session, args.output, "output", exists=False)
    if output.exists() or output.is_symlink(): raise Failure("output already exists")
    state, commit = chain(session)
    if state["source"] != snapshot_git_worktree(source): raise Failure("Phase 0 snapshot changed: source")
    root = session / "phase4/members"
    if root.exists() or root.is_symlink(): raise Failure("review packet members already exist")
    root.mkdir(parents=True, mode=0o700)
    members: list[dict] = []
    for relative in DESIGNS + (PLAN, "scripts/work7_claims.json"):
        copy_member(source / relative, session, root, "source/" + relative, members)
    diff = root / "source/git-diff-b907fae-to-head.patch"
    _atomic_create(diff, git_diff(source, args.baseline_commit))
    members.append({"label": "git-diff-b907fae-to-head.patch", "path": diff.relative_to(session).as_posix(), "size": diff.stat().st_size, "sha256": sha256_file(diff)})
    for relative in WORK_SESSION_MEMBERS:
        copy_member(session / relative, session, root, "session/" + relative, members)
    for name in ("paper", "threshold"):
        current = snapshot_git_worktree(Path(state[name]["root"]))
        if current != state[name]: raise Failure(f"Phase 0 snapshot changed: {name}")
        target = root / f"external/current-{name}-state.json"
        _atomic_create(target, canonical_json_bytes(current))
        members.append({"label": f"current-{name}-state", "path": target.relative_to(session).as_posix(), "size": target.stat().st_size, "sha256": sha256_file(target)})
    seals = {relative: sha256_file(session / relative) for relative in ("phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json")}
    _atomic_create(output, packet_bytes("work", commit, seals, members))


def parse_review(path: Path, commit: str, digest: str, provider: str, model: str, status: str, checks: tuple[str, ...]) -> None:
    try: lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error: raise Failure("cannot read raw review") from error
    fields = ("VERDICT", "PROVIDER", "MODEL", "EFFORT", "SOURCE_COMMIT", "PACKET_SHA256", "STATUS")
    if len(lines) < 7: raise Failure("review header is incomplete")
    parsed: dict[str, str] = {}
    for line in lines[:7]:
        if ": " not in line: raise Failure("invalid review header")
        key, value = line.split(": ", 1)
        if key not in fields or key in parsed: raise Failure("invalid review header")
        parsed[key] = value
    if tuple(parsed) != fields or any(line.startswith(key + ":") for line in lines[7:] for key in fields):
        raise Failure("duplicate or misplaced review field")
    if parsed != {"VERDICT": "APPROVED", "PROVIDER": provider, "MODEL": model, "EFFORT": "high", "SOURCE_COMMIT": commit, "PACKET_SHA256": digest, "STATUS": status}:
        raise Failure("review identity, verdict, commit, packet, or status is invalid")
    for check in checks:
        if sum(line == f"CHECK {check}: CONFIRMED" for line in lines[7:]) != 1: raise Failure("review substantive confirmation is missing")


def validate_phase4(session: Path, commit: str) -> dict:
    work = session / "phase4/work-review-seal.json"
    try:
        value = verify_tree_seal(work, sha256_file(session / "phase3/closure-seal.json"))
    except (OSError, ValueError) as error:
        raise Failure("invalid work review seal") from error
    root = session / "phase4/work-review-artifacts"
    if (value["kind"] != "phase4-work-review" or Path(value["artifact_root"]) != root or
            {entry["path"] for entry in value["entries"]} != {"work-packet.json", "raw-review.txt"}):
        raise Failure("foreign work review seal")
    seals = {relative: sha256_file(session / relative) for relative in ("phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json")}
    validate_packet(root / "work-packet.json", session, "work", commit, seals)
    parse_review(root / "raw-review.txt", commit, sha256_file(root / "work-packet.json"), "openai", "gpt-5.6-sol", "WORK7_APPROVED", CHECKS_WORK)
    return value


def close_work(args: argparse.Namespace) -> None:
    session = required(args.session_root, "session root", directory=True)
    packet, raw, output = (session_path(session, args.packet, "packet"), required(args.raw_review, "raw review"),
                           session_path(session, args.output_seal, "output seal", exists=False))
    if output != session / "phase4/work-review-seal.json": raise Failure("foreign work review seal path")
    state, commit = chain(session)
    seals = {relative: sha256_file(session / relative) for relative in ("phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json")}
    validate_packet(packet, session, "work", commit, seals)
    parse_review(raw, commit, sha256_file(packet), "openai", "gpt-5.6-sol", "WORK7_APPROVED", CHECKS_WORK)
    root = session / "phase4/work-review-artifacts"
    if root.exists() or output.exists(): raise Failure("work review output collision")
    root.mkdir(parents=True, mode=0o700)
    for path, label in ((packet, "work-packet.json"), (raw, "raw-review.txt")):
        _, _, data = _stable_regular_file(path); _atomic_create(root / label, data)
    create_tree_seal(root, output, sha256_file(session / "phase3/closure-seal.json"), "phase4-work-review")


def prepare_final(args: argparse.Namespace) -> None:
    source, session = required(args.source_root, "source root", directory=True), required(args.session_root, "session root", directory=True)
    output, work = session_path(session, args.output, "output", exists=False), session_path(session, args.work_review_seal, "work review seal")
    state, commit = chain(session)
    if state["source"] != snapshot_git_worktree(source): raise Failure("Phase 0 snapshot changed: source")
    if work != session / "phase4/work-review-seal.json": raise Failure("foreign work review seal path")
    validate_phase4(session, commit)
    root = session / "phase5/members"
    if root.exists() or output.exists(): raise Failure("final packet output collision")
    root.mkdir(parents=True, mode=0o700); members: list[dict] = []
    for relative in DESIGNS + (PLAN, "scripts/work7_claims.json", "docs/superpowers/specs/2026-07-29-pre-threshold-poc-design.md"):
        copy_member(source / relative, session, root, "source/" + relative, members)
    diff = root / "source/git-diff-b907fae-to-head.patch"
    _atomic_create(diff, git_diff(source, "b907fae"))
    members.append({"label": "git-diff-b907fae-to-head.patch", "path": diff.relative_to(session).as_posix(), "size": diff.stat().st_size, "sha256": sha256_file(diff)})
    for relative in WORK_SESSION_MEMBERS + ("phase4/work-review-artifacts/work-packet.json",
                     "phase4/work-review-artifacts/raw-review.txt", "phase4/work-review-seal.json"):
        copy_member(session / relative, session, root, "session/" + relative, members)
    for name in ("paper", "threshold"):
        current = snapshot_git_worktree(Path(state[name]["root"]))
        if current != state[name]: raise Failure(f"Phase 0 snapshot changed: {name}")
        target = root / f"external/current-{name}-state.json"
        _atomic_create(target, canonical_json_bytes(current))
        members.append({"label": f"current-{name}-state", "path": target.relative_to(session).as_posix(), "size": target.stat().st_size, "sha256": sha256_file(target)})
    try:
        try:
            from verify_work7_claims import inventory, load_contract
        except ModuleNotFoundError:
            from scripts.verify_work7_claims import inventory, load_contract
        claims = load_contract(source / "scripts/work7_claims.json", source,
                               inventory(session / "phase2/runtime/commands/ctest-inventory.stdout.txt"))
    except Exception as error:
        raise Failure("invalid immutable lifecycle contract") from error
    if len(claims) != 7:
        raise Failure("invalid immutable lifecycle contract")
    mappings = [{"id": row["id"], "source_paths": row["source_paths"], "required_ctest_names": row["required_ctest_names"]} for row in claims]
    mapping = root / "generated/works1-6-source-test-map.json"
    _atomic_create(mapping, canonical_json_bytes({"schema": "piccard-work7-source-test-map-v1", "claims": mappings[:6]}))
    inventory = session / "phase2/runtime/commands/ctest-inventory.stdout.txt"
    names = [line.split(": ", 1)[1] for line in inventory.read_text().splitlines() if line.startswith("  Test #")]
    summary = root / "generated/final-verification-summary.json"
    external_equal = all(snapshot_git_worktree(Path(state[name]["root"])) == state[name] for name in ("paper", "threshold"))
    if not external_equal: raise Failure("external worktree snapshot changed")
    _atomic_create(summary, canonical_json_bytes({"schema": "piccard-work7-final-verification-v1", "source_commit": commit,
        "registry_test_count": len(names), "registry_pass_count": len(names), "registry_skip_count": 0,
        "toy_argv_sha256": {"runtime_seal": sha256_file(session / "phase2/runtime-seal.json")}, "measured_count_policy": "PASS",
        "external_snapshot_equality": True, "performance_state": "PERFORMANCE_PENDING"}))
    for target, label in ((mapping, "generated/works1-6-source-test-map.json"), (summary, "generated/final-verification-summary.json")):
        members.append({"label": label.replace("/", ":"), "path": target.relative_to(session).as_posix(), "size": target.stat().st_size, "sha256": sha256_file(target)})
    seals = {relative: sha256_file(session / relative) for relative in ("phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json", "phase4/work-review-seal.json")}
    _atomic_create(output, packet_bytes("final", commit, seals, members))


def close_final(args: argparse.Namespace) -> None:
    session = required(args.session_root, "session root", directory=True)
    packet, claude, sol = (session_path(session, args.packet, "packet"), required(args.claude_review, "claude review"), required(args.sol_review, "sol review"))
    terminal_report, output = session_path(session, args.terminal_report, "terminal report", exists=False), session_path(session, args.output_seal, "output seal", exists=False)
    state, commit = phase0(session, session_path(session, args.phase0_seal, "Phase 0 seal"))
    paper, threshold = required(args.paper_root, "paper root", directory=True), required(args.threshold_root, "threshold root", directory=True)
    if snapshot_git_worktree(paper) != state["paper"] or snapshot_git_worktree(threshold) != state["threshold"]: raise Failure("external worktree snapshot changed")
    chain(session)
    work_seal = session / "phase4/work-review-seal.json"
    validate_phase4(session, commit)
    seals = {relative: sha256_file(session / relative) for relative in ("phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json", "phase4/work-review-seal.json")}
    validate_packet(packet, session, "final", commit, seals)
    digest = sha256_file(packet)
    parse_review(claude, commit, digest, "anthropic", "claude-fable", "POC_APPROVED_PERFORMANCE_PENDING", CHECKS_FINAL)
    parse_review(sol, commit, digest, "openai", "gpt-5.6-sol", "POC_APPROVED_PERFORMANCE_PENDING", CHECKS_FINAL)
    source = required(Path(state["source"]["root"]), "sealed source root", directory=True)
    command = (sys.executable, str(source / "scripts/verify_work7_claims.py"), "--mode", "terminal", "--contract", str(source / "scripts/work7_claims.json"),
               "--source-root", str(source), "--source-commit", commit, "--ctest-inventory", str(session / "phase2/runtime/commands/ctest-inventory.stdout.txt"),
               "--output", str(terminal_report), "--phase3-closure-seal", str(session / "phase3/closure-seal.json"), "--work-review-seal", str(session / "phase4/work-review-seal.json"),
               "--review-packet", str(packet), "--claude-review", str(claude), "--sol-review", str(sol), "--phase0-seal", str(session / "phase0/seal.json"), "--paper-root", str(paper), "--threshold-root", str(threshold))
    result = subprocess.run(command, capture_output=True)
    if result.returncode != 0: raise Failure("terminal verifier rejected final review")
    if snapshot_git_worktree(paper) != state["paper"] or snapshot_git_worktree(threshold) != state["threshold"]: raise Failure("external worktree snapshot changed")
    root = session / "phase5/terminal-artifacts"
    if root.exists(): raise Failure("terminal artifacts collision")
    root.mkdir(parents=True, mode=0o700)
    for path, label in ((packet, "final-packet.json"), (claude, "claude-review.txt"), (sol, "sol-review.txt"), (terminal_report, "terminal-report.json")):
        _, _, data = _stable_regular_file(path); _atomic_create(root / label, data)
    create_tree_seal(root, output, sha256_file(session / "phase4/work-review-seal.json"), "phase5-terminal")
    try:
        final_seal = verify_tree_seal(output, sha256_file(session / "phase4/work-review-seal.json"))
    except (OSError, ValueError) as error:
        raise Failure("new terminal seal did not verify") from error
    if final_seal["kind"] != "phase5-terminal" or Path(final_seal["artifact_root"]) != root:
        raise Failure("new terminal seal is foreign")
    digest = sha256_file(output); pointer = output.with_name("terminal-seal.sha256")
    _atomic_create(pointer, (digest + "\n").encode("ascii"))
    if pointer.read_bytes() != (sha256_file(output) + "\n").encode("ascii"):
        raise Failure("terminal seal pointer mismatch")
    print(f"WORK7_TERMINAL_SEAL_SHA256={digest}")


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        {"prepare-work": prepare_work, "close-work": close_work, "prepare-final": prepare_final, "close-final": close_final}[args.command](args)
        return 0
    except (Failure, OSError, ValueError, FileExistsError) as error:
        print(f"work7_review_packet: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
