#!/usr/bin/env python3
"""Freeze Work 7 review inputs and close its two fail-closed review gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from work7_evidence import (CapturedBlob, CapturedTreeSeal, assert_output_roots_outside, _atomic_create,
                                _reject_symlink_components, _stable_regular_file,
                                canonical_json_bytes, capture_tree_seal, create_tree_seal, sha256_file,
                                snapshot_git_worktree, verify_tree_seal)
except ModuleNotFoundError:
    from scripts.work7_evidence import (CapturedBlob, CapturedTreeSeal, assert_output_roots_outside, _atomic_create,
                                         _reject_symlink_components, _stable_regular_file,
                                         canonical_json_bytes, capture_tree_seal, create_tree_seal, sha256_file,
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


@dataclass(frozen=True)
class Phase04Capture:
    commit: str
    state_raw: CapturedBlob
    contract_raw: CapturedBlob
    ctest_inventory_raw: CapturedBlob
    seals: tuple[tuple[str, CapturedTreeSeal], ...]
    packet_members: tuple[tuple[str, CapturedBlob], ...]
    build_binaries: tuple[tuple[str, CapturedBlob], ...]
    phase4_packet: CapturedBlob
    phase4_review: CapturedBlob
    source_snapshot_raw: bytes
    paper_snapshot_raw: bytes
    threshold_snapshot_raw: bytes


@dataclass(frozen=True)
class RuntimeSummary:
    ctest_focused: str
    pre_threshold: str
    real_datasets: str
    verify_real_datasets: str
    deletion_survival: str
    focused_pass_count: int


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_argv_sha256(argv: list[str]) -> str:
    """Bind an argv vector as canonical JSON, never as an ambiguous join."""
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv):
        raise Failure("invalid command argv")
    return _sha256_bytes(canonical_json_bytes(argv))


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


def validate_canonical_build_root(raw: object, commit: str, guarded: tuple[Path, ...], expected: object) -> Path:
    """Bind the recorded CMake ``-B`` value to the one fresh build root."""
    try:
        if not isinstance(raw, str):
            raise ValueError("build root is not a string")
        path = Path(raw)
        expected_path = Path(expected) if isinstance(expected, str) else None
        if not path.is_absolute() or expected_path is None or not expected_path.is_absolute():
            raise ValueError("build root is not absolute")
        current = Path(path.anchor)
        for component in path.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ValueError("build root has a symlink component")
        canonical = path.resolve(strict=True)
        expected_current = Path(expected_path.anchor)
        for component in expected_path.parts[1:]:
            expected_current /= component
            if stat.S_ISLNK(expected_current.lstat().st_mode):
                raise ValueError("expected build root has a symlink component")
        expected_canonical = expected_path.resolve(strict=True)
        if raw != str(canonical) or not canonical.is_dir() or canonical.name != "build-" + commit:
            raise ValueError("build root is not the canonical named directory")
        if expected != str(expected_canonical) or canonical != expected_canonical:
            raise ValueError("build root differs from sealed Phase 0 build root")
        assert_output_roots_outside(list(guarded), [canonical])
        for root in guarded:
            resolved = root.resolve(strict=True)
            try:
                canonical.relative_to(resolved)
            except ValueError:
                pass
            else:
                raise ValueError("build root is inside a guarded root")
            try:
                resolved.relative_to(canonical)
            except ValueError:
                pass
            else:
                raise ValueError("build root contains a guarded root")
        return canonical
    except (OSError, ValueError) as error:
        raise Failure("noncanonical build root") from error


def session_path(session: Path, path: Path, label: str, *, exists: bool = True) -> Path:
    result = required(path, label, exists=exists)
    try:
        result.relative_to(session)
    except ValueError as error:
        raise Failure(f"{label} escapes session root") from error
    return result


def stable_canonical_object(path: Path, label: str) -> tuple[dict, bytes, str]:
    try:
        digest, _, raw = _stable_regular_file(path)
        value = json.loads(raw)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise Failure(f"invalid {label}") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise Failure(f"non-canonical {label}")
    return value, raw, digest


def _captured_file(path: Path, label: str) -> CapturedBlob:
    try:
        digest, info, raw = _stable_regular_file(path)
    except (OSError, ValueError) as error:
        raise Failure(f"unsafe {label}") from error
    return CapturedBlob(raw=raw, sha256=digest, size=info.st_size,
                        mode=format(stat.S_IMODE(info.st_mode), "04o"))


def _canonical_blob(blob: CapturedBlob, label: str) -> dict:
    try:
        value = json.loads(blob.raw)
    except json.JSONDecodeError as error:
        raise Failure(f"invalid {label}") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != blob.raw:
        raise Failure(f"non-canonical {label}")
    return value


def _json_blob(blob: CapturedBlob, label: str) -> dict:
    try:
        value = json.loads(blob.raw)
    except json.JSONDecodeError as error:
        raise Failure(f"invalid {label}") from error
    if not isinstance(value, dict):
        raise Failure(f"invalid {label}")
    return value


def _captured_member_map(capture: Phase04Capture) -> dict[str, CapturedBlob]:
    return dict(capture.packet_members)


def _canonical_external_root(raw: object, label: str, guarded: tuple[Path, ...]) -> Path:
    try:
        if not isinstance(raw, str):
            raise ValueError("not a string")
        path = Path(raw)
        if not path.is_absolute():
            raise ValueError("not absolute")
        _reject_symlink_components(path)
        canonical = path.resolve(strict=True)
        if raw != str(canonical) or not canonical.is_dir():
            raise ValueError("not canonical directory")
        for other in guarded:
            try:
                canonical.relative_to(other)
            except ValueError:
                try:
                    other.relative_to(canonical)
                except ValueError:
                    continue
            raise ValueError("overlaps guarded root")
        return canonical
    except (OSError, ValueError) as error:
        raise Failure(f"noncanonical Phase 0 {label} root") from error


def capture_phase04(session: Path, source: Path, paper: Path | None = None,
                    threshold: Path | None = None) -> Phase04Capture:
    """Capture the immutable Phase 0--4 evidence graph before finalization.

    Every Phase-owned regular file is read only by ``capture_tree_seal`` or
    ``_captured_file`` in this one boundary; downstream consumers use blobs.
    """
    try:
        phase0 = capture_tree_seal(session / "phase0/seal.json", None, "phase0",
                                   session / "phase0/artifacts", {"state.json"})
    except (OSError, ValueError) as error:
        raise Failure("invalid or tampered Phase 0 seal") from error
    state_raw = dict(phase0.members)["state.json"]
    state = _canonical_blob(state_raw, "Phase 0 state")
    commit = state.get("source", {}).get("head") if isinstance(state.get("source"), dict) else None
    if (set(state) != {"schema", "source", "paper", "threshold", "build", "session_id"} or
            state.get("schema") != "piccard-work7-phase0-state-v2" or not isinstance(commit, str) or
            not re.fullmatch(r"[0-9a-f]{40}", commit) or state.get("session_id") != "work7-" + commit or
            not isinstance(state.get("build"), dict) or set(state["build"]) != {"root"}):
        raise Failure("invalid Phase 0 state")
    source_state = state.get("source")
    if not isinstance(source_state, dict) or not isinstance(source_state.get("root"), str):
        raise Failure("invalid Phase 0 source root")
    source_root = _canonical_external_root(source_state["root"], "source", (session,))
    if source_root != source:
        raise Failure("source root differs from sealed Phase 0 root")
    recorded_paper = _canonical_external_root(state.get("paper", {}).get("root") if isinstance(state.get("paper"), dict) else None,
                                              "paper", (source, session))
    recorded_threshold = _canonical_external_root(state.get("threshold", {}).get("root") if isinstance(state.get("threshold"), dict) else None,
                                                  "threshold", (source, paper or recorded_paper, session))
    if recorded_paper == recorded_threshold:
        raise Failure("Phase 0 external roots must be distinct")
    if paper is not None and paper != recorded_paper:
        raise Failure("paper root differs from sealed Phase 0 root")
    if threshold is not None and threshold != recorded_threshold:
        raise Failure("threshold root differs from sealed Phase 0 root")
    build = validate_canonical_build_root(state["build"].get("root"), commit,
                                          (source, recorded_paper, recorded_threshold, session), state["build"].get("root"))

    try:
        runtime_seal = capture_tree_seal(session / "phase2/runtime-seal.json", phase0.blob.sha256,
                                         "phase2-runtime-artifacts", session / "phase2/runtime")
    except (OSError, ValueError) as error:
        raise Failure("invalid or tampered prerequisite seal") from error
    order = (
        ("phase0/seal.json", phase0),
        ("phase2/runtime-seal.json", runtime_seal),
        ("phase2/closure-seal.json", None),
        ("phase3/candidate-seal.json", None),
        ("phase3/closure-seal.json", None),
        ("phase4/work-review-seal.json", None),
    )
    seals: list[tuple[str, CapturedTreeSeal]] = [order[0], order[1]]  # type: ignore[list-item]
    runtime_members = dict(seals[-1][1].members)
    try:
        configure = json.loads(runtime_members["commands/configure.json"].raw)
        configured_build = configure["argv"][4]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise Failure("configure command record is not exact") from error
    # R0 binds this value to the Phase 0 string, rather than merely accepting
    # a currently usable build directory from a resealed runtime graph.
    validate_canonical_build_root(configured_build, commit, (source, recorded_paper, recorded_threshold, session),
                                  state["build"]["root"])
    previous = seals[-1][1].blob.sha256
    for relative, kind, root, expected in (
        ("phase2/closure-seal.json", "phase2-closure", "phase2/closure-artifacts",
         {"evidence-bound-report.json", "commands/evidence-bound.json", "commands/evidence-bound.stderr.txt", "commands/evidence-bound.stdout.txt"}),
        ("phase3/candidate-seal.json", "phase3-candidate-artifacts", "phase3/candidate-artifacts", None),
        ("phase3/closure-seal.json", "phase3-closure", "phase3/closure-artifacts", None),
        ("phase4/work-review-seal.json", "phase4-work-review", "phase4/work-review-artifacts", {"work-packet.json", "raw-review.txt"}),
    ):
        try:
            seal = capture_tree_seal(session / relative, previous, kind, session / root, expected)
        except (OSError, ValueError) as error:
            raise Failure("invalid or tampered prerequisite seal") from error
        seals.append((relative, seal))
        previous = seal.blob.sha256
    all_members: dict[str, CapturedBlob] = {}
    for _, seal in seals:
        root = Path(seal.artifact_root)
        for relative, blob in seal.members:
            all_members[(root.relative_to(session) / relative).as_posix()] = blob
    for relative in WORK_SESSION_MEMBERS:
        if relative in {"phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json"}:
            continue
        if relative not in all_members:
            # The standalone Phase 2 static report has no owning manifest;
            # capture it once and compare it to its runtime-sealed twin below.
            all_members[relative] = _captured_file(session / relative, "packet member")
    runtime_static = all_members.get("phase2/runtime/static-report.json")
    static = all_members.get("phase2/static-report.json")
    if runtime_static is None or static is None or runtime_static.raw != static.raw:
        raise Failure("Phase 2 static report is not the sealed runtime copy")
    contract_raw = _captured_file(source / "scripts/work7_claims.json", "claim contract")
    inventory_raw = all_members.get("phase2/runtime/commands/ctest-inventory.stdout.txt")
    phase4_packet = all_members.get("phase4/work-review-artifacts/work-packet.json")
    phase4_review = all_members.get("phase4/work-review-artifacts/raw-review.txt")
    if inventory_raw is None or phase4_packet is None or phase4_review is None:
        raise Failure("captured Phase 0--4 graph is incomplete")
    binaries: list[tuple[str, CapturedBlob]] = []
    for name in ("bench_review_comparison", "bench_piccard", "bench_dynamic", "bench_real_datasets", "bench_deletion_survival"):
        blob = _captured_file(build / name, "build binary")
        if int(blob.mode, 8) & 0o111 == 0:
            raise Failure("build binary is not executable")
        binaries.append((name, blob))
    source_snapshot_raw = canonical_json_bytes(snapshot_git_worktree(source))
    paper_snapshot_raw = canonical_json_bytes(snapshot_git_worktree(recorded_paper))
    threshold_snapshot_raw = canonical_json_bytes(snapshot_git_worktree(recorded_threshold))
    if (source_snapshot_raw != canonical_json_bytes(state["source"]) or
            paper_snapshot_raw != canonical_json_bytes(state["paper"]) or
            threshold_snapshot_raw != canonical_json_bytes(state["threshold"])):
        raise Failure("Phase 0 snapshot changed")
    return Phase04Capture(commit=commit, state_raw=state_raw, contract_raw=contract_raw,
                          ctest_inventory_raw=inventory_raw, seals=tuple(seals),
                          packet_members=tuple(sorted(all_members.items())), build_binaries=tuple(binaries),
                          phase4_packet=phase4_packet, phase4_review=phase4_review,
                          source_snapshot_raw=source_snapshot_raw, paper_snapshot_raw=paper_snapshot_raw,
                          threshold_snapshot_raw=threshold_snapshot_raw)


def canonical_object(path: Path, label: str) -> dict:
    return stable_canonical_object(path, label)[0]


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
    build_state = state.get("build")
    if (set(state) != {"schema", "source", "paper", "threshold", "build", "session_id"} or
            state.get("schema") != "piccard-work7-phase0-state-v2" or not isinstance(build_state, dict) or
            set(build_state) != {"root"} or not isinstance(build_state.get("root"), str) or not isinstance(commit, str) or
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


def copy_raw_member(raw: bytes, session: Path, member_root: Path, label: str, members: list[dict]) -> None:
    """Snapshot already-stable bytes without reopening the reviewed input."""
    target = member_root / label
    if target.exists() or target.is_symlink():
        raise Failure("packet member collision")
    _atomic_create(target, raw)
    members.append({"label": label.replace("/", ":"), "path": target.relative_to(session).as_posix(),
                    "size": len(raw), "sha256": _sha256_bytes(raw)})


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


def expected_member_tuples(phase: str) -> list[tuple[str, str]]:
    prefix = f"phase{4 if phase == 'work' else 5}/members/"
    result: list[tuple[str, str]] = []
    for path in sorted(expected_member_paths(phase)):
        remainder = path.removeprefix(prefix)
        labels = {"external/current-paper-state.json": "current-paper-state",
                  "external/current-threshold-state.json": "current-threshold-state",
                  "source/git-diff-b907fae-to-head.patch": "git-diff-b907fae-to-head.patch"}
        result.append((labels.get(remainder, remainder.replace("/", ":")), path))
    return result


def _command_record(commands: Path, label: str, argv: tuple[str, ...] | None, cwd: Path) -> tuple[dict, bytes]:
    """Load a runner command once and bind its exact executable invocation."""
    record, _, _ = stable_canonical_object(commands / f"{label}.json", f"{label} command record")
    expected = {"argv", "cwd", "started_at", "ended_at", "returncode", "stdout", "stderr", "executable_sha256"}
    if (set(record) != expected or (argv is not None and record.get("argv") != list(argv)) or record.get("cwd") != str(cwd) or
            record.get("returncode") != 0 or record.get("stdout") != f"{label}.stdout.txt" or
            record.get("stderr") != f"{label}.stderr.txt" or not isinstance(record.get("started_at"), str) or
            not isinstance(record.get("ended_at"), str) or not isinstance(record.get("executable_sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}|unresolved|unreadable", record["executable_sha256"])):
        raise Failure(f"{label} command record is not exact")
    try:
        _, _, stdout = _stable_regular_file(commands / record["stdout"])
        _stable_regular_file(commands / record["stderr"])
    except ValueError as error:
        raise Failure(f"{label} command output is unsafe") from error
    return record, stdout


def _ctest_inventory(stdout: bytes) -> tuple[str, ...]:
    try:
        text = stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise Failure("CTest inventory is not UTF-8") from error
    names = tuple(re.findall(r"^\s*Test\s+#\d+:\s+([A-Za-z0-9_]+)\s*$", text, re.MULTILINE))
    total = re.findall(r"^Total Tests:\s*(\d+)\s*$", text, re.MULTILINE)
    if len(names) != len(set(names)) or set(names) != set(_frozen_ctests()) or total != [str(len(_frozen_ctests()))]:
        raise Failure("CTest registry is not the exact frozen registry")
    return names


def _validate_focused_ctest(stdout: bytes) -> int:
    try:
        text = stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise Failure("focused CTest output is not UTF-8") from error
    if any(token in text for token in ("Not Run", "Skipped", "Failed", "***")):
        raise Failure("focused CTest has failed, skipped, or not-run tests")
    passed = tuple(re.findall(r"^\s*\d+/\d+\s+Test\s+#\d+:\s+([A-Za-z0-9_]+)\s+.*\bPassed\b", text, re.MULTILINE))
    count = len(_frozen_ctests())
    summary = rf"100% tests passed, 0 tests failed out of {count}"
    if len(passed) != count or len(set(passed)) != count or set(passed) != set(_frozen_ctests()) or summary not in text:
        raise Failure("focused CTest result is not the exact frozen pass set")
    return count


def _frozen_ctests() -> tuple[str, ...]:
    try:
        from run_work7_integration import FROZEN_CTESTS
    except ModuleNotFoundError:
        from scripts.run_work7_integration import FROZEN_CTESTS
    return FROZEN_CTESTS


def _runtime_validators():
    try:
        from run_work7_integration import validate_deletion, validate_prethreshold, validate_real, validate_records
        from verify_work7_claims import inventory, load_contract, report_claims, runtime_evidence
    except ModuleNotFoundError:
        from scripts.run_work7_integration import validate_deletion, validate_prethreshold, validate_real, validate_records
        from scripts.verify_work7_claims import inventory, load_contract, report_claims, runtime_evidence
    return validate_deletion, validate_prethreshold, validate_real, validate_records, inventory, load_contract, report_claims, runtime_evidence


def validate_phase2_runtime(session: Path, source: Path, state: dict, commit: str) -> dict[str, str | int]:
    """Re-run every producer validator over the sealed Phase 2 execution graph."""
    if state.get("source") != snapshot_git_worktree(source):
        raise Failure("Phase 0 snapshot changed: source")
    try:
        head = subprocess.run(("git", "rev-parse", "HEAD"), cwd=source, capture_output=True, check=False,
                              env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except OSError as error:
        raise Failure("cannot determine current source commit") from error
    if head.returncode != 0 or head.stdout.decode("ascii", "replace").strip() != commit:
        raise Failure("current source commit differs from Phase 0")
    phase0_digest = sha256_file(session / "phase0/seal.json")
    runtime_seal, closure_seal = session / "phase2/runtime-seal.json", session / "phase2/closure-seal.json"
    try:
        runtime_value = verify_tree_seal(runtime_seal, phase0_digest)
        closure_value = verify_tree_seal(closure_seal, sha256_file(runtime_seal))
    except (OSError, ValueError) as error:
        raise Failure("invalid or tampered sealed Phase 2 runtime") from error
    runtime, closure = session / "phase2/runtime", session / "phase2/closure-artifacts"
    if (runtime_value["kind"] != "phase2-runtime-artifacts" or Path(runtime_value["artifact_root"]) != runtime or
            closure_value["kind"] != "phase2-closure" or Path(closure_value["artifact_root"]) != closure or
            {entry["path"] for entry in closure_value["entries"]} != {
                "evidence-bound-report.json", "commands/evidence-bound.json", "commands/evidence-bound.stderr.txt", "commands/evidence-bound.stdout.txt"}):
        raise Failure("sealed Phase 2 closure manifest is not exact")
    commands = runtime / "commands"
    configure = _command_record(commands, "configure", None, source)
    configure_argv = configure[0]["argv"]
    if not isinstance(configure_argv, list) or len(configure_argv) != 8 or not isinstance(configure_argv[4], str):
        raise Failure("configure command record is not exact")
    try:
        paper = Path(state["paper"]["root"])
        threshold = Path(state["threshold"]["root"])
    except (KeyError, TypeError) as error:
        raise Failure("invalid Phase 0 external roots") from error
    build = validate_canonical_build_root(configure_argv[4], commit, (source, paper, threshold, session), state["build"]["root"])
    expected_configure = ("cmake", "-S", str(source), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release",
                          "-DBUILD_TESTS=ON", "-DBUILD_BENCHMARKS=ON")
    _command_record(commands, "configure", expected_configure, source)
    _command_record(commands, "build", ("cmake", "--build", str(build), "--parallel", "2"), source)
    _, inventory_stdout = _command_record(commands, "ctest-inventory", ("ctest", "--test-dir", str(build), "-N"), source)
    _ctest_inventory(inventory_stdout)
    regex = "^(" + "|".join(_frozen_ctests()) + ")$"
    _, focused_stdout = _command_record(commands, "ctest-focused", ("ctest", "--test-dir", str(build), "--output-on-failure", "-R", regex), source)
    pass_count = _validate_focused_ctest(focused_stdout)
    pre = runtime / "pre-threshold"
    pre_argv = (str(source / "scripts/run_pre_threshold_profiles.sh"), "--suite=smoke", "--seed=7", "--threads=2",
                "--build-dir=" + str(build), "--results-root=" + str(pre))
    _command_record(commands, "pre-threshold", pre_argv, source)
    real = runtime / "real-datasets"
    real_argv = (str(source / "scripts/run_real_datasets.sh"), "--quick", "--seed=7", "--threads=2",
                 "--build-dir=" + str(build), "--results-root=" + str(real))
    _command_record(commands, "real-datasets", real_argv, source)
    verify_real_argv = (sys.executable, str(source / "scripts/verify_real_dataset_outputs.py"), str(real))
    _command_record(commands, "verify-real-datasets", verify_real_argv, source)
    deletion_argv = (str(build / "bench_deletion_survival"), "--n=64", "--d=3", "--k=8", "--required_survival=0.99",
                     "--r_values=1,4,8", "--trials=1", "--seed=7")
    _, deletion_stdout = _command_record(commands, "deletion-survival", deletion_argv, source)
    validate_deletion, validate_prethreshold, validate_real, validate_records, inventory, load_contract, report_claims, runtime_evidence = _runtime_validators()
    try:
        validate_prethreshold(pre, commit, pre_argv, source, build)
        validate_real(real, commit, build, source)
        deletion_output = commands / "deletion-survival.stdout.txt"
        if deletion_output.read_bytes() != deletion_stdout:
            raise Failure("deletion command output changed while validating")
        validate_deletion(deletion_output)
        # The runner applies this generic count/path screen before it writes its
        # own report/index JSON.  Reapply it only to producer-owned trees so
        # claim prose cannot be misclassified as a benchmark artifact.
        validate_records(pre)
        validate_records(real)
        claims = load_contract(source / "scripts/work7_claims.json", source, inventory(commands / "ctest-inventory.stdout.txt"))
        if len(claims) != 7:
            raise Failure("invalid immutable lifecycle contract")
        report_claims(canonical_object(runtime / "static-report.json", "sealed static report"), "static", commit,
                      ["PENDING"] * 7, claims)
        report_claims(canonical_object(session / "phase2/static-report.json", "Phase 2 static report"), "static", commit,
                      ["PENDING"] * 7, claims)
        if sha256_file(runtime / "static-report.json") != sha256_file(session / "phase2/static-report.json"):
            raise Failure("Phase 2 static report is not the sealed runtime copy")
        report_claims(canonical_object(closure / "evidence-bound-report.json", "sealed evidence-bound report"),
                      "evidence-bound", commit, ["TOY_VERIFIED"] * 6 + ["PENDING"], claims)
        evidence = canonical_object(closure / "evidence-bound-report.json", "sealed evidence-bound report")
        if evidence.get("input_seals") != {"runtime_seal_sha256": sha256_file(runtime_seal)}:
            raise Failure("evidence-bound report has wrong runtime seal")
        if runtime_evidence(runtime_seal, commit, claims) != {claim["id"] for claim in claims[:6]}:
            raise Failure("sealed runtime evidence is incomplete")
    except Failure:
        raise
    except (OSError, ValueError, TypeError) as error:
        raise Failure("sealed Phase 2 runtime evidence is invalid") from error
    return {"ctest_focused": canonical_argv_sha256(list(("ctest", "--test-dir", str(build), "--output-on-failure", "-R", regex))),
            "pre_threshold": canonical_argv_sha256(list(pre_argv)),
            "real_datasets": canonical_argv_sha256(list(real_argv)),
            "deletion_survival": canonical_argv_sha256(list(deletion_argv)),
            "registry_test_count": len(_frozen_ctests()), "registry_pass_count": pass_count}


def _captured_command(members: dict[str, CapturedBlob], label: str, argv: tuple[str, ...], cwd: str) -> bytes:
    record = _canonical_blob(members.get(f"phase2/runtime/commands/{label}.json", CapturedBlob(b"", "", 0, "")),
                             f"{label} command record")
    expected = {"argv", "cwd", "started_at", "ended_at", "returncode", "stdout", "stderr", "executable_sha256"}
    if (set(record) != expected or record.get("argv") != list(argv) or record.get("cwd") != cwd or
            record.get("returncode") != 0 or record.get("stdout") != f"{label}.stdout.txt" or
            record.get("stderr") != f"{label}.stderr.txt" or not isinstance(record.get("started_at"), str) or
            not isinstance(record.get("ended_at"), str) or not re.fullmatch(r"[0-9a-f]{64}|unresolved|unreadable", str(record.get("executable_sha256")))):
        raise Failure(f"{label} command record is not exact")
    stdout = members.get(f"phase2/runtime/commands/{label}.stdout.txt")
    stderr = members.get(f"phase2/runtime/commands/{label}.stderr.txt")
    if stdout is None or stderr is None:
        raise Failure(f"{label} command output is missing")
    return stdout.raw


def validate_phase2_runtime_capture(capture: Phase04Capture) -> RuntimeSummary:
    """Validate the captured runtime graph without reopening Phase 0--4 paths."""
    state = _canonical_blob(capture.state_raw, "Phase 0 state")
    source = str(state["source"]["root"])
    build = str(state["build"]["root"])
    members = _captured_member_map(capture)
    members.update({"@build/" + name: blob for name, blob in capture.build_binaries})
    regex = "^(" + "|".join(_frozen_ctests()) + ")$"
    configure = ("cmake", "-S", source, "-B", build, "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTS=ON", "-DBUILD_BENCHMARKS=ON")
    _captured_command(members, "configure", configure, source)
    _captured_command(members, "build", ("cmake", "--build", build, "--parallel", "2"), source)
    inventory = _captured_command(members, "ctest-inventory", ("ctest", "--test-dir", build, "-N"), source)
    _ctest_inventory(inventory)
    focused_argv = ("ctest", "--test-dir", build, "--output-on-failure", "-R", regex)
    focused = _captured_command(members, "ctest-focused", focused_argv, source)
    pass_count = _validate_focused_ctest(focused)
    pre_argv = (source + "/scripts/run_pre_threshold_profiles.sh", "--suite=smoke", "--seed=7", "--threads=2",
                "--build-dir=" + build, "--results-root=" + str(Path(build).parent.parent / "unused"))
    # Results roots are session-local, so preserve the exact captured value from
    # the command record while constraining all other immutable arguments.
    pre_record = _canonical_blob(members["phase2/runtime/commands/pre-threshold.json"], "pre-threshold command record")
    real_record = _canonical_blob(members["phase2/runtime/commands/real-datasets.json"], "real-datasets command record")
    for record, label, prefix in ((pre_record, "pre-threshold", [source + "/scripts/run_pre_threshold_profiles.sh", "--suite=smoke", "--seed=7", "--threads=2", "--build-dir=" + build]),
                                  (real_record, "real-datasets", [source + "/scripts/run_real_datasets.sh", "--quick", "--seed=7", "--threads=2", "--build-dir=" + build])):
        argv = record.get("argv")
        if not isinstance(argv, list) or argv[:5] != prefix or len(argv) != 6 or not isinstance(argv[-1], str) or not argv[-1].startswith("--results-root="):
            raise Failure(f"{label} command record is not exact")
        _captured_command(members, label, tuple(argv), source)
    pre_argv = tuple(pre_record["argv"])
    real_argv = tuple(real_record["argv"])
    verify_argv = (sys.executable, source + "/scripts/verify_real_dataset_outputs.py", real_argv[-1].split("=", 1)[1])
    _captured_command(members, "verify-real-datasets", verify_argv, source)
    deletion_argv = (build + "/bench_deletion_survival", "--n=64", "--d=3", "--k=8", "--required_survival=0.99",
                     "--r_values=1,4,8", "--trials=1", "--seed=7")
    deletion = _captured_command(members, "deletion-survival", deletion_argv, source)
    deletion_record = _canonical_blob(members["phase2/runtime/commands/deletion-survival.json"], "deletion command record")
    if deletion_record["executable_sha256"] != members["@build/bench_deletion_survival"].sha256:
        raise Failure("deletion command binary differs from captured build binary")
    try:
        from run_work7_integration import (validate_deletion_bytes, validate_prethreshold_capture,
                                           validate_real_capture, validate_record_counts_capture)
    except ModuleNotFoundError:
        from scripts.run_work7_integration import (validate_deletion_bytes, validate_prethreshold_capture,
                                                   validate_real_capture, validate_record_counts_capture)
    pre_blobs = tuple((path, blob) for path, blob in members.items()
                      if path.startswith("phase2/runtime/pre-threshold/") or path.startswith("@build/"))
    real_blobs = tuple((path, blob) for path, blob in members.items()
                       if path.startswith("phase2/runtime/real-datasets/") or path.startswith("@build/"))
    validate_prethreshold_capture(pre_blobs, capture.commit, pre_argv, source, build)
    validate_real_capture(real_blobs, capture.commit, source, build)
    validate_deletion_bytes(deletion)
    validate_record_counts_capture(pre_blobs)
    validate_record_counts_capture(real_blobs)
    for relative, mode in (("phase2/runtime/static-report.json", "static"),
                           ("phase2/static-report.json", "static"),
                           ("phase2/closure-artifacts/evidence-bound-report.json", "evidence-bound")):
        report = _canonical_blob(members[relative], "sealed claim report")
        if report.get("schema") != "piccard-work7-claim-report-v1" or report.get("source_commit") != capture.commit or report.get("mode") != mode or report.get("status") != "PASS":
            raise Failure("foreign source commit or invalid claim verifier report")
    return RuntimeSummary(ctest_focused=canonical_argv_sha256(list(focused_argv)),
                          pre_threshold=canonical_argv_sha256(list(pre_argv)),
                          real_datasets=canonical_argv_sha256(list(real_argv)),
                          verify_real_datasets=canonical_argv_sha256(list(verify_argv)),
                          deletion_survival=canonical_argv_sha256(list(deletion_argv)),
                          focused_pass_count=pass_count)


def final_generated_member_bytes(session: Path, source: Path, state: dict, commit: str,
                                 runtime_summary: dict[str, str | int]) -> tuple[bytes, bytes]:
    """Derive the two Phase 5 generated members from freshly verified inputs."""
    try:
        _, _, _, _, inventory, load_contract, _, _ = _runtime_validators()
        claims = load_contract(source / "scripts/work7_claims.json", source,
                               inventory(session / "phase2/runtime/commands/ctest-inventory.stdout.txt"))
    except Exception as error:
        raise Failure("invalid immutable lifecycle contract") from error
    if len(claims) != 7:
        raise Failure("invalid immutable lifecycle contract")
    mappings = [{"id": row["id"], "source_paths": row["source_paths"],
                 "required_ctest_names": row["required_ctest_names"]} for row in claims]
    if any(snapshot_git_worktree(Path(state[name]["root"])) != state[name]
           for name in ("paper", "threshold")):
        raise Failure("external worktree snapshot changed")
    mapping_raw = canonical_json_bytes({"schema": "piccard-work7-source-test-map-v1", "claims": mappings[:6]})
    summary_raw = canonical_json_bytes({"schema": "piccard-work7-final-verification-v1", "source_commit": commit,
        "registry_test_count": runtime_summary["registry_test_count"], "registry_pass_count": runtime_summary["registry_pass_count"],
        "registry_skip_count": 0, "toy_argv_sha256": {name: runtime_summary[name] for name in
        ("ctest_focused", "pre_threshold", "real_datasets", "deletion_survival")}, "measured_count_policy": "PASS",
        "external_snapshot_equality": True, "performance_state": "PERFORMANCE_PENDING"})
    return mapping_raw, summary_raw


def validate_final_generated_members(session: Path, packet: dict, mapping_raw: bytes, summary_raw: bytes) -> None:
    """Require both packet digests and current members to match the re-derived bytes."""
    members = {member["path"]: member for member in packet["members"]}
    generated = session / "phase5/members/generated"
    expected = (("works1-6-source-test-map.json", mapping_raw),
                ("final-verification-summary.json", summary_raw))
    for name, raw in expected:
        relative = f"phase5/members/generated/{name}"
        member = members[relative]
        if member["size"] != len(raw) or member["sha256"] != _sha256_bytes(raw):
            raise Failure("review packet generated member differs from verified Phase 2 execution")
        try:
            _, _, actual = _stable_regular_file(generated / name)
        except (OSError, ValueError) as error:
            raise Failure("review packet generated member is missing or unsafe") from error
        if actual != raw:
            raise Failure("review packet generated member differs from verified Phase 2 execution")


def validate_final_closure_prerequisites(session: Path, source: Path, paper: Path, threshold: Path,
                                         state: dict, commit: str, seals: dict[str, str]) -> None:
    """Bracket terminal closure with the exact chain used by the final packet."""
    if state["source"] != snapshot_git_worktree(source):
        raise Failure("Phase 0 snapshot changed: source")
    if snapshot_git_worktree(paper) != state["paper"] or snapshot_git_worktree(threshold) != state["threshold"]:
        raise Failure("external worktree snapshot changed")
    current = {relative: sha256_file(session / relative) for relative in seals}
    if current != seals:
        raise Failure("prerequisite seal changed during final closure")
    chain(session)
    validate_phase4(session, commit)


def validate_packet(path: Path, session: Path, phase: str, commit: str, seals: dict[str, str]) -> tuple[dict, bytes, str]:
    value, raw, digest = stable_canonical_object(path, f"{phase} packet")
    if (set(value) != {"schema", "phase", "source_commit", "prerequisite_seals", "members"} or
            value.get("schema") != "piccard-work7-review-packet-v1" or value.get("phase") != phase or
            value.get("source_commit") != commit or value.get("prerequisite_seals") != seals or
            not isinstance(value.get("members"), list) or not value["members"]):
        raise Failure("foreign or invalid review packet")
    paths: set[str] = set()
    members_by_path: dict[str, dict] = {}
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
        members_by_path[member["path"]] = member
        candidate = session / relative
        if not candidate.is_file() or candidate.is_symlink() or candidate.stat().st_size != member["size"] or sha256_file(candidate) != member["sha256"]:
            raise Failure("review packet member changed or missing")
    if paths != expected_member_paths(phase):
        raise Failure("review packet member manifest is not exact")
    if value["members"] != sorted(value["members"], key=lambda item: item["path"]):
        raise Failure("review packet member order is not canonical")
    if [(member["label"], member["path"]) for member in value["members"]] != expected_member_tuples(phase):
        raise Failure("review packet member labels are not exact")
    member_prefix = f"phase{4 if phase == 'work' else 5}/members/session/"
    if any(members_by_path[member_prefix + relative]["sha256"] != digest for relative, digest in seals.items()):
        raise Failure("review packet seal members differ from prerequisite seals")
    return value, raw, digest


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


def parse_review_bytes(raw: bytes, commit: str, digest: str, provider: str, model: str, status: str,
                       checks: tuple[str, ...]) -> None:
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise Failure("cannot read raw review") from error
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


def parse_review(path: Path, commit: str, digest: str, provider: str, model: str, status: str,
                 checks: tuple[str, ...]) -> tuple[bytes, str]:
    try:
        raw_digest, _, raw = _stable_regular_file(path)
    except ValueError as error:
        raise Failure("cannot read raw review") from error
    parse_review_bytes(raw, commit, digest, provider, model, status, checks)
    return raw, raw_digest


def parse_final_review(path: Path, commit: str, digest: str) -> tuple[str, bytes]:
    """Accept the two frozen final identities in either CLI argument order."""
    try:
        _, _, raw = _stable_regular_file(path)
    except ValueError as error:
        raise Failure("cannot read raw review") from error
    for name, provider, model in (("claude", "anthropic", "claude-fable"), ("sol", "openai", "gpt-5.6-sol")):
        try:
            parse_review_bytes(raw, commit, digest, provider, model, "POC_APPROVED_PERFORMANCE_PENDING", CHECKS_FINAL)
        except Failure:
            continue
        return name, raw
    raise Failure("final review identity, verdict, commit, packet, or status is invalid")


def validate_phase4(session: Path, commit: str) -> tuple[dict, bytes, str, bytes, bytes]:
    work = session / "phase4/work-review-seal.json"
    try:
        seal_digest, _, seal_raw = _stable_regular_file(work)
        value = verify_tree_seal(work, sha256_file(session / "phase3/closure-seal.json"))
    except (OSError, ValueError) as error:
        raise Failure("invalid work review seal") from error
    if canonical_json_bytes(value) != seal_raw:
        raise Failure("work review seal changed while validating")
    root = session / "phase4/work-review-artifacts"
    if (value["kind"] != "phase4-work-review" or Path(value["artifact_root"]) != root or
            {entry["path"] for entry in value["entries"]} != {"work-packet.json", "raw-review.txt"}):
        raise Failure("foreign work review seal")
    seals = {relative: sha256_file(session / relative) for relative in ("phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json")}
    _, packet_raw, packet_digest = validate_packet(root / "work-packet.json", session, "work", commit, seals)
    review_raw, review_digest = parse_review(root / "raw-review.txt", commit, packet_digest, "openai", "gpt-5.6-sol", "WORK7_APPROVED", CHECKS_WORK)
    sealed = {entry["path"]: entry["sha256"] for entry in value["entries"]}
    if sealed != {"work-packet.json": packet_digest, "raw-review.txt": review_digest}:
        raise Failure("work review inputs differ from the Phase 4 seal")
    return value, seal_raw, seal_digest, packet_raw, review_raw


def close_work(args: argparse.Namespace) -> None:
    session = required(args.session_root, "session root", directory=True)
    packet, raw, output = (session_path(session, args.packet, "packet"), required(args.raw_review, "raw review"),
                           session_path(session, args.output_seal, "output seal", exists=False))
    if output != session / "phase4/work-review-seal.json": raise Failure("foreign work review seal path")
    state, commit = chain(session)
    seals = {relative: sha256_file(session / relative) for relative in ("phase0/seal.json", "phase2/runtime-seal.json", "phase2/closure-seal.json", "phase3/candidate-seal.json", "phase3/closure-seal.json")}
    _, packet_raw, packet_digest = validate_packet(packet, session, "work", commit, seals)
    raw_review, _ = parse_review(raw, commit, packet_digest, "openai", "gpt-5.6-sol", "WORK7_APPROVED", CHECKS_WORK)
    root = session / "phase4/work-review-artifacts"
    if root.exists() or output.exists(): raise Failure("work review output collision")
    root.mkdir(parents=True, mode=0o700)
    for data, label in ((packet_raw, "work-packet.json"), (raw_review, "raw-review.txt")):
        _atomic_create(root / label, data)
    create_tree_seal(root, output, sha256_file(session / "phase3/closure-seal.json"), "phase4-work-review")


def prepare_final(args: argparse.Namespace, synchronize: Callable[[str], None] | None = None) -> None:
    source = required(args.source_root, "source root", directory=True)
    session = required(args.session_root, "session root", directory=True)
    output = session_path(session, args.output, "output", exists=False)
    work = session_path(session, args.work_review_seal, "work review seal")
    if work != session / "phase4/work-review-seal.json":
        raise Failure("foreign work review seal path")
    root = session / "phase5/members"
    if root.exists() or root.is_symlink() or output.exists() or output.is_symlink():
        raise Failure("final packet output collision")
    capture = capture_phase04(session, source)
    runtime = validate_phase2_runtime_capture(capture)
    state = _canonical_blob(capture.state_raw, "Phase 0 state")
    seals = {relative: seal.blob.sha256 for relative, seal in capture.seals}
    phase4_packet_value = _canonical_blob(capture.phase4_packet, "work packet")
    if phase4_packet_value.get("phase") != "work" or phase4_packet_value.get("source_commit") != capture.commit or phase4_packet_value.get("prerequisite_seals") != {key: value for key, value in seals.items() if key != "phase4/work-review-seal.json"}:
        raise Failure("foreign work review packet")
    parse_review_bytes(capture.phase4_review.raw, capture.commit, capture.phase4_packet.sha256,
                       "openai", "gpt-5.6-sol", "WORK7_APPROVED", CHECKS_WORK)
    claims = _json_blob(capture.contract_raw, "claim contract").get("claims")
    if not isinstance(claims, list) or len(claims) != 7 or any(not isinstance(row, dict) for row in claims):
        raise Failure("invalid immutable lifecycle contract")
    mappings = [{"id": row.get("id"), "source_paths": row.get("source_paths"),
                 "required_ctest_names": row.get("required_ctest_names")} for row in claims]
    mapping_raw = canonical_json_bytes({"schema": "piccard-work7-source-test-map-v1", "claims": mappings[:6]})
    summary_raw = canonical_json_bytes({"schema": "piccard-work7-final-verification-v1", "source_commit": capture.commit,
        "registry_test_count": len(_frozen_ctests()), "registry_pass_count": runtime.focused_pass_count,
        "registry_skip_count": 0, "toy_argv_sha256": {"ctest_focused": runtime.ctest_focused,
        "pre_threshold": runtime.pre_threshold, "real_datasets": runtime.real_datasets,
        "deletion_survival": runtime.deletion_survival}, "measured_count_policy": "PASS",
        "external_snapshot_equality": True, "performance_state": "PERFORMANCE_PENDING"})
    sources: list[tuple[str, bytes]] = []
    for relative in DESIGNS + (PLAN, "scripts/work7_claims.json", "docs/superpowers/specs/2026-07-29-pre-threshold-poc-design.md"):
        sources.append(("source/" + relative, _captured_file(source / relative, "source packet member").raw))
    sources.append(("source/git-diff-b907fae-to-head.patch", git_diff(source, "b907fae")))
    member_map = _captured_member_map(capture)
    seal_map = dict(capture.seals)
    for relative in WORK_SESSION_MEMBERS:
        raw = seal_map[relative].blob.raw if relative in seal_map else member_map[relative].raw
        sources.append(("session/" + relative, raw))
    sources.extend((("session/phase4/work-review-artifacts/work-packet.json", capture.phase4_packet.raw),
                    ("session/phase4/work-review-artifacts/raw-review.txt", capture.phase4_review.raw),
                    ("session/phase4/work-review-seal.json", seal_map["phase4/work-review-seal.json"].blob.raw),
                    ("external/current-paper-state.json", capture.paper_snapshot_raw),
                    ("external/current-threshold-state.json", capture.threshold_snapshot_raw),
                    ("generated/works1-6-source-test-map.json", mapping_raw),
                    ("generated/final-verification-summary.json", summary_raw)))
    # A complete second capture is the post-validation race detector.  Only
    # immutable in-memory bytes above survive to publication.
    if synchronize is not None:
        synchronize("before_second_capture")
    try:
        second_capture = capture_phase04(session, source)
    except Failure as error:
        raise Failure("Phase 0--4 evidence changed during final packet preparation") from error
    if second_capture != capture:
        raise Failure("Phase 0--4 evidence changed during final packet preparation")
    members: list[dict] = []
    created_root = False
    created_output = False
    try:
        root.mkdir(parents=True, mode=0o700)
        created_root = True
        for label, raw in sources:
            copy_raw_member(raw, session, root, label, members)
            if label == "source/git-diff-b907fae-to-head.patch":
                members[-1]["label"] = "git-diff-b907fae-to-head.patch"
            elif label == "external/current-paper-state.json":
                members[-1]["label"] = "current-paper-state"
            elif label == "external/current-threshold-state.json":
                members[-1]["label"] = "current-threshold-state"
        if synchronize is not None:
            synchronize("before_packet_create")
        _atomic_create(output, packet_bytes("final", capture.commit, seals, members))
        created_output = True
    except Exception:
        if created_output and output.exists() and output.is_file():
            output.unlink()
        if created_root:
            shutil.rmtree(root, ignore_errors=True)
        raise


def validate_terminal_report(path: Path, source: Path, ctest_inventory: Path, commit: str) -> tuple[dict, bytes, str]:
    """Reject a verifier that exits successfully but writes a foreign report."""
    value, raw, digest = stable_canonical_object(path, "terminal report")
    try:
        _, _, _, _, inventory, load_contract, report_claims, _ = _runtime_validators()
        claims = load_contract(source / "scripts/work7_claims.json", source, inventory(ctest_inventory))
        if len(claims) != 7:
            raise Failure("invalid immutable lifecycle contract")
        report_claims(value, "terminal", commit, ["TOY_VERIFIED"] * 7, claims)
    except Failure:
        raise
    except (OSError, ValueError, TypeError) as error:
        raise Failure("terminal report is invalid") from error
    if value.get("input_seals") != {}:
        raise Failure("terminal report has foreign input seals")
    return value, raw, digest


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
    final_packet, packet_raw, packet_digest = validate_packet(packet, session, "final", commit, seals)
    source = required(Path(state["source"]["root"]), "sealed source root", directory=True)
    if state["source"] != snapshot_git_worktree(source): raise Failure("Phase 0 snapshot changed: source")
    runtime_summary = validate_phase2_runtime(session, source, state, commit)
    mapping_raw, summary_raw = final_generated_member_bytes(session, source, state, commit, runtime_summary)
    validate_final_generated_members(session, final_packet, mapping_raw, summary_raw)
    validate_final_closure_prerequisites(session, source, paper, threshold, state, commit, seals)
    first_name, first_raw = parse_final_review(claude, commit, packet_digest)
    second_name, second_raw = parse_final_review(sol, commit, packet_digest)
    if first_name == second_name:
        raise Failure("final reviews duplicate one provider")
    reviews = {first_name: first_raw, second_name: second_raw}
    claude_raw, sol_raw = reviews["claude"], reviews["sol"]
    phase5 = session / "phase5"
    with tempfile.TemporaryDirectory(prefix=".close-final-inputs-", dir=phase5) as temporary:
        private = Path(temporary)
        private_packet, private_claude, private_sol = (private / "final-packet.json", private / "claude-review.txt", private / "sol-review.txt")
        _atomic_create(private_packet, packet_raw)
        _atomic_create(private_claude, claude_raw)
        _atomic_create(private_sol, sol_raw)
        command = (sys.executable, str(source / "scripts/verify_work7_claims.py"), "--mode", "terminal", "--contract", str(source / "scripts/work7_claims.json"),
                   "--source-root", str(source), "--source-commit", commit, "--ctest-inventory", str(session / "phase2/runtime/commands/ctest-inventory.stdout.txt"),
                   "--output", str(terminal_report), "--phase3-closure-seal", str(session / "phase3/closure-seal.json"), "--work-review-seal", str(session / "phase4/work-review-seal.json"),
                   "--review-packet", str(private_packet), "--claude-review", str(private_claude), "--sol-review", str(private_sol), "--phase0-seal", str(session / "phase0/seal.json"), "--paper-root", str(paper), "--threshold-root", str(threshold))
        result = subprocess.run(command, capture_output=True)
        if result.returncode != 0: raise Failure("terminal verifier rejected final review")
        _, terminal_raw, _ = validate_terminal_report(terminal_report, source,
                                                        session / "phase2/runtime/commands/ctest-inventory.stdout.txt", commit)
    validate_final_closure_prerequisites(session, source, paper, threshold, state, commit, seals)
    root = session / "phase5/terminal-artifacts"
    if root.exists(): raise Failure("terminal artifacts collision")
    root.mkdir(parents=True, mode=0o700)
    for data, label in ((packet_raw, "final-packet.json"), (claude_raw, "claude-review.txt"),
                        (sol_raw, "sol-review.txt"), (terminal_raw, "terminal-report.json")):
        _atomic_create(root / label, data)
    create_tree_seal(root, output, seals["phase4/work-review-seal.json"], "phase5-terminal")
    try:
        final_seal = verify_tree_seal(output, seals["phase4/work-review-seal.json"])
    except (OSError, ValueError) as error:
        raise Failure("new terminal seal did not verify") from error
    if final_seal["kind"] != "phase5-terminal" or Path(final_seal["artifact_root"]) != root:
        raise Failure("new terminal seal is foreign")
    digest = sha256_file(output); pointer = output.with_name("terminal-seal.sha256")
    _atomic_create(pointer, (digest + "\n").encode("ascii"))
    if pointer.read_bytes() != (sha256_file(output) + "\n").encode("ascii"):
        raise Failure("terminal seal pointer mismatch")
    print(f"WORK7_TERMINAL_SEAL_SHA256={digest}")


def main(argv: list[str] | None = None, synchronize: Callable[[str], None] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "prepare-final":
            prepare_final(args, synchronize)
        else:
            {"prepare-work": prepare_work, "close-work": close_work, "close-final": close_final}[args.command](args)
        return 0
    except (Failure, OSError, ValueError, FileExistsError) as error:
        print(f"work7_review_packet: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
