#!/usr/bin/env python3
"""Small fail-closed ownership lifecycle for invalid Work 7 generated runs."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from work7_evidence import canonical_json_bytes, sha256_file
except ModuleNotFoundError:
    from scripts.work7_evidence import canonical_json_bytes, sha256_file


_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_FAILURE_KINDS = frozenset(("execution", "technical-review", "review-delivery", "user-cancel"))


@dataclass
class ReservationLedger:
    """Only paths created by this invocation are eligible for partial cleanup."""

    created: list[Path]


def _commit_value(commit: str) -> str:
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise ValueError("commit must be a full lowercase SHA-1")
    return commit


def _parent(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or not path.is_dir():
        raise ValueError(f"{label} must be an existing absolute directory")
    return path.resolve(strict=True)


def _target(parent: Path, target: Path, expected_name: str, label: str) -> Path:
    if not isinstance(target, Path) or not target.is_absolute() or target.name != expected_name:
        raise ValueError(f"{label} is not an exact generated root")
    try:
        metadata = target.lstat()
        result = target.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} is not an exact generated root") from error
    if not stat.S_ISDIR(metadata.st_mode) or result.parent != parent:
        raise ValueError(f"{label} is not an exact generated root")
    return result


def _separate(left: Path, right: Path, label: str) -> None:
    if left == right:
        raise ValueError(f"{label} must be distinct")
    try:
        left.relative_to(right)
    except ValueError:
        pass
    else:
        raise ValueError(f"{label} must not overlap")
    try:
        right.relative_to(left)
    except ValueError:
        return
    raise ValueError(f"{label} must not overlap")


def _validate_generated_pair(build_parent: Path, session_parent: Path, build: Path,
                             session: Path, commit: str,
                             guarded: Iterable[Path]) -> tuple[Path, Path]:
    commit = _commit_value(commit)
    canonical_build_parent = _parent(build_parent, "build parent")
    canonical_session_parent = _parent(session_parent, "session parent")
    _separate(canonical_build_parent, canonical_session_parent, "generated parents")
    canonical_build = _target(canonical_build_parent, build, "build-" + commit, "build")
    canonical_session = _target(canonical_session_parent, session, "session-" + commit, "session")
    _separate(canonical_build, canonical_session, "generated roots")
    for raw_guard in guarded:
        guard = _parent(raw_guard, "guarded root")
        _separate(canonical_build, guard, "build and guarded root")
        _separate(canonical_session, guard, "session and guarded root")
    return canonical_build, canonical_session


def reserve_owned(parent: Path, name: str, ledger: ReservationLedger) -> Path:
    """Exclusively create a generated root, recording it only after success."""
    canonical_parent = _parent(parent, "reservation parent")
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("reservation name must be a single path component")
    target = canonical_parent / name
    target.mkdir(mode=0o700)
    canonical = target.resolve(strict=True)
    ledger.created.append(canonical)
    return canonical


def classify_failure(kind: str) -> str:
    """Every authoritative failure restarts from Phase 0 in this PoC."""
    if kind not in _FAILURE_KINDS:
        raise ValueError("unsupported failure kind")
    return "DISPOSE"


def dispose_generated_run(build_parent: Path, session_parent: Path, build: Path,
                          session: Path, commit: str, guarded: Iterable[Path]) -> None:
    """Validate both exact roots before deleting either one."""
    canonical_build, canonical_session = _validate_generated_pair(
        build_parent, session_parent, build, session, commit, guarded)
    shutil.rmtree(canonical_build)
    shutil.rmtree(canonical_session)


def _diagnostic_path(diagnostic_root: Path, commit: str) -> tuple[Path, str]:
    commit = _commit_value(commit)
    root = _parent(diagnostic_root, "diagnostic root")
    return root / ("failure-" + commit + ".json"), commit


def _external_diagnostic_root(diagnostic_root: Path, guarded: tuple[Path, ...],
                              build: Path, session: Path) -> Path:
    """Require a durable diagnostic root outside every protected generated root."""
    root = _parent(diagnostic_root, "diagnostic root")
    for raw_protected in (*guarded, build, session):
        protected = _parent(raw_protected, "guarded root")
        try:
            root.relative_to(protected)
        except ValueError:
            pass
        else:
            raise ValueError("diagnostic root must be external")
        try:
            protected.relative_to(root)
        except ValueError:
            continue
        raise ValueError("diagnostic root must be external")
    return root


def _packet_digest(packet: Path | None, packet_sha256: str | None) -> str | None:
    if packet_sha256 is not None and (not isinstance(packet_sha256, str) or not _SHA256.fullmatch(packet_sha256)):
        raise ValueError("packet SHA-256 must be lowercase hexadecimal or null")
    if packet is None:
        return packet_sha256
    if not isinstance(packet, Path) or not packet.is_absolute() or not packet.is_file():
        raise ValueError("packet must be an existing absolute regular file")
    captured = sha256_file(packet)
    if packet_sha256 is not None and packet_sha256 != captured:
        raise ValueError("packet SHA-256 does not match stable packet bytes")
    return captured


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _stable_diagnostic(path: Path, expected: dict[str, object], raw: bytes) -> None:
    try:
        observed = path.read_bytes()
        value = json.loads(observed)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("failure diagnostic did not stable-validate") from error
    if observed != raw or value != expected or set(value) != set(expected):
        raise ValueError("failure diagnostic did not stable-validate")


def _cleanup_ledger(ledger: ReservationLedger, build_parent: Path, session_parent: Path,
                    build: Path, session: Path, commit: str) -> None:
    """Best-effort rollback for a reservation that never became jointly owned."""
    expected = ((build, build_parent, "build-" + commit),
                (session, session_parent, "session-" + commit))
    for raw in reversed(ledger.created):
        for target, parent, name in expected:
            if raw != target or not raw.exists():
                continue
            canonical_parent = _parent(parent, "reservation parent")
            canonical_target = _target(canonical_parent, raw, name, "reserved root")
            shutil.rmtree(canonical_target)
            break


def _write_failure_diagnostic(kind: str, diagnostic_root: Path, build_parent: Path,
                              session_parent: Path, build: Path, session: Path,
                              commit: str, guarded: tuple[Path, ...], packet: Path | None,
                              packet_sha256: str | None) -> tuple[Path, Path, Path]:
    """Validate the full boundary and persist the exact diagnostic before cleanup."""
    action = classify_failure(kind)
    canonical_build, canonical_session = _validate_generated_pair(
        build_parent, session_parent, build, session, commit, guarded)
    canonical_diagnostic_root = _external_diagnostic_root(
        diagnostic_root, guarded, canonical_build, canonical_session)
    packet_sha256 = _packet_digest(packet, packet_sha256)
    commit = _commit_value(commit)
    diagnostic = canonical_diagnostic_root / ("failure-" + commit + ".json")
    record: dict[str, object] = {
        "schema": "piccard-work7-failure-v1",
        "source_commit": commit,
        "failure_kind": kind,
        "action": action,
        "build_root": str(canonical_build),
        "session_root": str(canonical_session),
        "packet_sha256": packet_sha256,
        "publishable": False,
    }
    raw = canonical_json_bytes(record)
    _write_exclusive(diagnostic, raw)
    _stable_diagnostic(diagnostic, record, raw)
    return diagnostic, canonical_build, canonical_session


def record_and_apply_failure(kind: str, diagnostic_root: Path, build_parent: Path,
                             session_parent: Path, build: Path, session: Path, commit: str,
                             guarded: tuple[Path, ...], packet: Path | None,
                             packet_sha256: str | None) -> str:
    """Write the diagnostic, dispose both validated roots, and return its path string."""
    diagnostic, canonical_build, canonical_session = _write_failure_diagnostic(
        kind, diagnostic_root, build_parent, session_parent, build, session, commit,
        guarded, packet, packet_sha256)
    shutil.rmtree(canonical_build)
    shutil.rmtree(canonical_session)
    return str(diagnostic)


def _record_and_apply_owned_failure(*, diagnostic_root: Path, build_parent: Path,
                                    session_parent: Path, build: Path, session: Path,
                                    commit: str, kind: str, guarded: tuple[Path, ...],
                                    packet: Path | None, packet_sha256: str | None,
                                    ledger: ReservationLedger) -> str:
    """Runner-only partial-reservation coordinator using its creation ledger."""
    diagnostic, canonical_build, canonical_session = _write_failure_diagnostic(
        kind, diagnostic_root, build_parent, session_parent, build, session, commit,
        guarded, packet, packet_sha256)
    if canonical_build in ledger.created and canonical_session in ledger.created:
        shutil.rmtree(canonical_build)
        shutil.rmtree(canonical_session)
    else:
        _cleanup_ledger(ledger, build_parent, session_parent, build, session, commit)
    return str(diagnostic)


def clear_diagnostic(diagnostic_root: Path, commit: str) -> None:
    """Delete only the exact diagnostic that blocks a fresh Phase 0 attempt."""
    path, _ = _diagnostic_path(diagnostic_root, commit)
    if not path.is_file():
        raise ValueError("failure diagnostic does not exist")
    path.unlink()


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("invalid arguments: " + message)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    failure = commands.add_parser("record-failure", add_help=False)
    for name in ("diagnostic-root", "build-parent", "session-parent", "build-root", "session-root"):
        failure.add_argument("--" + name, required=True, type=Path)
    failure.add_argument("--commit", required=True)
    failure.add_argument("--kind", required=True)
    failure.add_argument("--packet", type=Path)
    failure.add_argument("--packet-sha256")
    failure.add_argument("--guarded-root", action="append", default=[], type=Path)
    clear = commands.add_parser("clear-diagnostic", add_help=False)
    clear.add_argument("--diagnostic-root", required=True, type=Path)
    clear.add_argument("--commit", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "clear-diagnostic":
            clear_diagnostic(args.diagnostic_root, args.commit)
        else:
            record_and_apply_failure(
                args.kind, args.diagnostic_root, args.build_parent, args.session_parent,
                args.build_root, args.session_root, args.commit, tuple(args.guarded_root),
                args.packet, args.packet_sha256)
    except (OSError, ValueError, FileExistsError) as error:
        print("work7_run_lifecycle: FAIL: " + str(error), file=sys.stderr)
        return 2
    print("work7_run_lifecycle: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
