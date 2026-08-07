#!/usr/bin/env python3
"""Freeze Work 7 review inputs and close its two fail-closed review gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

if __package__:
    from scripts.work7_evidence import (CapturedBlob, CapturedTreeSeal, assert_output_roots_outside, _atomic_create,
                                         _reject_symlink_components, _stable_regular_file,
                                         canonical_json_bytes, capture_tree_seal, create_tree_seal, sha256_file,
                                         snapshot_git_worktree, verify_tree_seal)
else:
    from work7_evidence import (CapturedBlob, CapturedTreeSeal, assert_output_roots_outside, _atomic_create,
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
PHASE0_SEAL_MEMBERS = frozenset({"state.json"})
PHASE2_CLOSURE_SEAL_MEMBERS = frozenset({
    "evidence-bound-report.json", "commands/evidence-bound.json", "commands/evidence-bound.stderr.txt",
    "commands/evidence-bound.stdout.txt",
})
PHASE3_CANDIDATE_SEAL_MEMBERS = frozenset({
    "ResponseStrategy.candidate.md", "ResponseStrategy.candidate.diff", "candidate-metadata.json",
    "candidate-validation.json",
})
PHASE3_CLOSURE_SEAL_MEMBERS = frozenset({
    "claim7-command.json", "claim7-report.json", "claim7.stderr.txt", "claim7.stdout.txt",
})
PHASE4_SEAL_MEMBERS = frozenset({"work-packet.json", "raw-review.txt"})
SOURCE_PACKET_MEMBERS = DESIGNS + (
    PLAN, "scripts/work7_claims.json", "docs/superpowers/specs/2026-07-29-pre-threshold-poc-design.md",
)
_PUBLIC_SOURCE_PREFIX = "@public/source/"
_PUBLIC_DIFF_MEMBER = "@public/git-diff-b907fae-to-head.patch"
_PRIVATE_SOURCE_PREFIX = "@source/"


class Failure(ValueError):
    pass


_RUNTIME_COMMANDS = (
    "build", "configure", "ctest-focused", "ctest-inventory", "deletion-survival",
    "phase0-guard", "pre-threshold", "real-datasets", "static", "verify-real-datasets",
)
_PRETHRESHOLD_OUTPUT_FIELDS = {
    "bench_review_comparison": {"csv", "log", "workload", "trace"},
    "bench_piccard": {"csv", "log"},
    "bench_dynamic": {"csv", "log"},
}
_PRETHRESHOLD_OUTPUT_KEYS = {
    producer: fields | {field + "_sha256" for field in fields} |
    {"expected_csv_rows", "csv_row_count", "measurement_output"}
    for producer, fields in _PRETHRESHOLD_OUTPUT_FIELDS.items()
}


def _runtime_expected_members(members: tuple[tuple[str, CapturedBlob], ...]) -> frozenset[str]:
    """Derive the complete runtime member set from already captured producer bytes.

    This is deliberately byte-only: callers must use it immediately after a
    stable ``capture_tree_seal(..., None)`` and before exposing that capture.
    The pre-threshold and real-data producers are the authorities for their
    dynamic path names; command records and singleton reports are frozen.
    """
    values = dict(members)
    if len(values) != len(members):
        raise ValueError("runtime seal contains duplicate members")
    expected = {"evidence-index.json", "static-report.json", "pre-threshold/manifest.json",
                "pre-threshold/terminal-cells.tsv", "real-datasets/run_metadata.tsv",
                "real-datasets/verification_status.tsv"}
    for label in _RUNTIME_COMMANDS:
        expected.update({f"commands/{label}.json", f"commands/{label}.stdout.txt", f"commands/{label}.stderr.txt"})
    try:
        manifest_blob = values["pre-threshold/manifest.json"]
        manifest = json.loads(manifest_blob.raw)
        cells = manifest["cells"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("pre-threshold manifest cannot determine runtime members") from error
    if (not isinstance(cells, list) or len(cells) != len(_PRETHRESHOLD_OUTPUT_FIELDS) or
            any(not isinstance(row, dict) or not isinstance(row.get("producer"), str) for row in cells) or
            {row["producer"] for row in cells} != set(_PRETHRESHOLD_OUTPUT_FIELDS)):
        raise ValueError("pre-threshold manifest has no complete producer set")
    for row in cells:
        output = row.get("output")
        producer = row["producer"]
        if not isinstance(output, dict) or set(output) != _PRETHRESHOLD_OUTPUT_KEYS[producer]:
            raise ValueError("pre-threshold manifest has incomplete producer outputs")
        for field in _PRETHRESHOLD_OUTPUT_FIELDS[producer]:
            relative = output[field]
            path = Path(relative) if isinstance(relative, str) else Path()
            if not isinstance(relative, str) or not relative or path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
                raise ValueError("pre-threshold manifest has noncanonical producer output")
            expected.add("pre-threshold/" + relative)
    try:
        metadata_lines = values["real-datasets/run_metadata.tsv"].raw.decode("utf-8", "strict").splitlines()
    except (KeyError, UnicodeError) as error:
        raise ValueError("real-data metadata cannot determine runtime members") from error
    metadata: dict[str, str] = {}
    for line in metadata_lines:
        try:
            key, value = line.split("\t")
        except ValueError as error:
            raise ValueError("real-data metadata is not key-value TSV") from error
        if not key or key in metadata:
            raise ValueError("real-data metadata has duplicate keys")
        metadata[key] = value
    for key, relative in metadata.items():
        if not (key.endswith(".path") and (key.startswith("artifact.") or ".output." in key)):
            continue
        path = Path(relative)
        if not relative or path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
            raise ValueError("real-data metadata has noncanonical artifact path")
        expected.add("real-datasets/" + relative)
    return frozenset(expected)


@dataclass(frozen=True)
class _OwnedPublicationPath:
    """A path this invocation created, tied to its lstat identity."""

    path: Path
    device: int
    inode: int
    kind: int


@dataclass
class _PublicationLedger:
    """Exact Phase 5 creations, unwound without traversing shared trees."""

    created: list[_OwnedPublicationPath]

    def record(self, path: Path) -> None:
        info = path.lstat()
        self.created.append(_OwnedPublicationPath(path, info.st_dev, info.st_ino,
                                                  stat.S_IFMT(info.st_mode)))

    def rollback(self) -> None:
        for owned in reversed(self.created):
            try:
                info = owned.path.lstat()
            except FileNotFoundError:
                continue
            if (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) != (
                    owned.device, owned.inode, owned.kind):
                continue
            try:
                if stat.S_ISDIR(info.st_mode):
                    owned.path.rmdir()
                elif stat.S_ISREG(info.st_mode):
                    owned.path.unlink()
            except (FileNotFoundError, OSError):
                # A concurrent non-owned descendant or replacement is never
                # removed merely to make rollback appear complete.
                continue


def _ledger_directory(ledger: _PublicationLedger, path: Path, *, allow_existing: bool) -> None:
    """Create one directory exclusively, recording it only on this call's success."""
    _reject_symlink_components(path)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        try:
            info = path.lstat()
        except FileNotFoundError:
            # The name changed between mkdir and lstat; retry through the same
            # exclusive branch rather than treating a vanished object as ours.
            return _ledger_directory(ledger, path, allow_existing=allow_existing)
        if allow_existing and stat.S_ISDIR(info.st_mode):
            return
        raise Failure("final packet output collision") from None
    ledger.record(path)


def _ledger_directories(ledger: _PublicationLedger, base: Path, parent: Path) -> None:
    """Materialize missing parents one at a time, retaining no ownership of old ones."""
    try:
        relative = parent.relative_to(base)
    except ValueError as error:
        raise Failure("final packet output escapes session root") from error
    current = base
    for component in relative.parts:
        current /= component
        _ledger_directory(ledger, current, allow_existing=True)


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
    for name in ("packet", "claude-review", "sol-review", "terminal-report", "session-root", "phase0-seal", "source-root",
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


def _captured_bytes(raw: bytes, mode: str = "0600") -> CapturedBlob:
    return CapturedBlob(raw=raw, sha256=_sha256_bytes(raw), size=len(raw), mode=mode)


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
    members = dict(capture.packet_members)
    if len(members) != len(capture.packet_members):
        raise Failure("duplicate captured packet member")
    return members


def _canonical_contract_source_path(raw: object) -> str:
    """Return one contract source path only in its canonical captured form."""
    if not isinstance(raw, str) or not raw:
        raise Failure("invalid contract source path")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != raw or raw == ".":
        raise Failure("invalid contract source path")
    return raw


def _contract_source_paths(contract_raw: CapturedBlob) -> tuple[str, ...]:
    contract = _json_blob(contract_raw, "claim contract")
    claims = contract.get("claims")
    if not isinstance(claims, list):
        raise Failure("invalid immutable lifecycle contract")
    paths: list[str] = []
    for claim in claims:
        source_paths = claim.get("source_paths") if isinstance(claim, dict) else None
        if not isinstance(source_paths, list) or not source_paths:
            raise Failure("invalid contract source path")
        canonical = tuple(_canonical_contract_source_path(value) for value in source_paths)
        if len(set(canonical)) != len(canonical):
            raise Failure("duplicate contract source path")
        paths.extend(canonical)
    return tuple(dict.fromkeys(paths))


def _validate_captured_contract_sources(contract_raw: CapturedBlob,
                                        members: dict[str, CapturedBlob]) -> None:
    """Require every lifecycle source reference to be an already captured file.

    This intentionally has no source-root parameter: final validation must
    never reopen a live source path after the Phase 0--4 capture boundary.
    """
    for relative in _contract_source_paths(contract_raw):
        blob = members.get(_PRIVATE_SOURCE_PREFIX + relative)
        if (blob is None or blob.size != len(blob.raw) or blob.sha256 != _sha256_bytes(blob.raw) or
                not re.fullmatch(r"[0-7]{4}", blob.mode)):
            raise Failure("referenced source path is not a captured regular file")


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
                                   session / "phase0/artifacts", PHASE0_SEAL_MEMBERS)
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
                                         "phase2-runtime-artifacts", session / "phase2/runtime",
                                         None)
        if {relative for relative, _ in runtime_seal.members} != _runtime_expected_members(runtime_seal.members):
            raise ValueError("runtime tree seal member manifest is not exact")
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
         PHASE2_CLOSURE_SEAL_MEMBERS),
        ("phase3/candidate-seal.json", "phase3-candidate-artifacts", "phase3/candidate-artifacts",
         PHASE3_CANDIDATE_SEAL_MEMBERS),
        ("phase3/closure-seal.json", "phase3-closure", "phase3/closure-artifacts", PHASE3_CLOSURE_SEAL_MEMBERS),
        ("phase4/work-review-seal.json", "phase4-work-review", "phase4/work-review-artifacts", PHASE4_SEAL_MEMBERS),
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
    # Public source and diff bytes are still captured once, but live only in
    # the opaque packet-members namespace.  The fixed Phase04Capture interface
    # deliberately exposes no second mutable-looking source collection.
    for relative in SOURCE_PACKET_MEMBERS:
        all_members[_PUBLIC_SOURCE_PREFIX + relative] = _captured_file(
            source / relative, "source packet member")
    contract_raw = all_members[_PUBLIC_SOURCE_PREFIX + "scripts/work7_claims.json"]
    all_members[_PUBLIC_DIFF_MEMBER] = _captured_bytes(git_diff(source, "b907fae"))
    # Contract references are captured here as private regular-file blobs.
    # Later byte validators use these entries exclusively and never reopen the
    # referenced live source paths.
    for relative in _contract_source_paths(contract_raw):
        all_members[_PRIVATE_SOURCE_PREFIX + relative] = _captured_file(
            source / relative, "contract referenced source")
    # The real-data metadata binds the summarizer digest.  Retain its exact
    # source bytes in the capture graph; this private namespace is consumed
    # only by byte validators and is never a Phase 5 packet member.
    all_members["@source/scripts/summarize_real_datasets.py"] = _captured_file(
        source / "scripts/summarize_real_datasets.py", "real-data summarizer source")
    all_members["@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv"] = _captured_file(
        source / "tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv",
        "real-data fixture source")
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
    if __package__:
        from scripts.run_work7_integration import FROZEN_CTESTS
    else:
        from run_work7_integration import FROZEN_CTESTS
    return FROZEN_CTESTS


def _runtime_validators():
    if __package__:
        from scripts.run_work7_integration import validate_deletion, validate_prethreshold, validate_real, validate_records
        from scripts.verify_work7_claims import inventory, load_contract, report_claims, runtime_evidence
    else:
        from run_work7_integration import validate_deletion, validate_prethreshold, validate_real, validate_records
        from verify_work7_claims import inventory, load_contract, report_claims, runtime_evidence
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
    runtime_root = dict(capture.seals)["phase2/runtime-seal.json"].artifact_root
    pre_root = runtime_root + "/pre-threshold"
    real_root = runtime_root + "/real-datasets"
    pre_argv = (source + "/scripts/run_pre_threshold_profiles.sh", "--suite=smoke", "--seed=7", "--threads=2",
                "--build-dir=" + build, "--results-root=" + pre_root)
    real_argv = (source + "/scripts/run_real_datasets.sh", "--quick", "--seed=7", "--threads=2",
                 "--build-dir=" + build, "--results-root=" + real_root)
    _captured_command(members, "pre-threshold", pre_argv, source)
    _captured_command(members, "real-datasets", real_argv, source)
    verify_argv = (sys.executable, source + "/scripts/verify_real_dataset_outputs.py", real_root)
    _captured_command(members, "verify-real-datasets", verify_argv, source)
    deletion_argv = (build + "/bench_deletion_survival", "--n=64", "--d=3", "--k=8", "--required_survival=0.99",
                     "--r_values=1,4,8", "--trials=1", "--seed=7")
    deletion = _captured_command(members, "deletion-survival", deletion_argv, source)
    deletion_record = _canonical_blob(members["phase2/runtime/commands/deletion-survival.json"], "deletion command record")
    if deletion_record["executable_sha256"] != members["@build/bench_deletion_survival"].sha256:
        raise Failure("deletion command binary differs from captured build binary")
    if __package__:
        from scripts.run_work7_integration import (_capture_tsv, validate_deletion_bytes, validate_prethreshold_capture,
                                                   validate_real_capture, validate_record_counts_capture)
    else:
        from run_work7_integration import (_capture_tsv, validate_deletion_bytes, validate_prethreshold_capture,
                                           validate_real_capture, validate_record_counts_capture)
    pre_manifest = _json_blob(members["phase2/runtime/pre-threshold/manifest.json"], "pre-threshold manifest")
    pre_paths = {"phase2/runtime/pre-threshold/manifest.json", "phase2/runtime/pre-threshold/terminal-cells.tsv",
                 "@build/bench_review_comparison", "@build/bench_piccard", "@build/bench_dynamic"}
    for cell in pre_manifest.get("cells", []):
        if isinstance(cell, dict) and isinstance(cell.get("output"), dict):
            for key, value in cell["output"].items():
                if not key.endswith("_sha256") and key not in {"expected_csv_rows", "csv_row_count", "measurement_output"} and isinstance(value, str):
                    pre_paths.add("phase2/runtime/pre-threshold/" + value)
    pre_blobs = tuple((path, members[path]) for path in sorted(pre_paths) if path in members)
    real_metadata = _capture_tsv(members["phase2/runtime/real-datasets/run_metadata.tsv"].raw, "real-data metadata")
    real_paths = {"phase2/runtime/real-datasets/run_metadata.tsv", "phase2/runtime/real-datasets/verification_status.tsv",
                  "@build/bench_real_datasets", "@source/scripts/summarize_real_datasets.py",
                  "@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv"}
    for key, value in real_metadata.items():
        if (key.startswith("artifact.") or ".output." in key) and key.endswith(".path"):
            real_paths.add("phase2/runtime/real-datasets/" + value)
    real_blobs = tuple((path, members[path]) for path in sorted(real_paths) if path in members)
    if real_metadata.get("root.000.path") != real_root:
        raise Failure("real-data command results root is not exact")
    validate_prethreshold_capture(pre_blobs, capture.commit, pre_argv, source, build)
    validate_real_capture(real_blobs, capture.commit, source, build)
    validate_deletion_bytes(deletion)
    validate_record_counts_capture(pre_blobs)
    validate_record_counts_capture(real_blobs)
    if __package__:
        from scripts.verify_work7_claims import IDS, ROW_KEYS, STATES, TOP_KEYS, report_claims
    else:
        from verify_work7_claims import IDS, ROW_KEYS, STATES, TOP_KEYS, report_claims
    # The immutable tracked contract is sealed as exact bytes but is not a
    # canonical-JSON producer format; retain its established parser semantics.
    contract = _json_blob(capture.contract_raw, "claim contract")
    contract_claims = contract.get("claims")
    inventory_names = set(_ctest_inventory(capture.ctest_inventory_raw.raw))
    if (set(contract) != TOP_KEYS or contract.get("schema") != "piccard-work7-claim-lifecycle-v1" or
            contract.get("allowed_gates") != {"threshold_gate_state": ["DEFERRED_EXPECTED"],
                                              "work_gate_state": ["PENDING", "POC_APPROVED_PERFORMANCE_PENDING"]} or
            not isinstance(contract_claims, list) or len(contract_claims) != 7 or
            tuple(item.get("id") for item in contract_claims if isinstance(item, dict)) != IDS):
        raise Failure("invalid immutable lifecycle contract")
    for claim in contract_claims:
        if (not isinstance(claim, dict) or set(claim) != ROW_KEYS or claim.get("allowed_states") != STATES or
                claim.get("performance_state") != "PERFORMANCE_PENDING" or
                not isinstance(claim.get("original_intent"), str) or not claim["original_intent"] or
                any(not isinstance(claim.get(field), list) or not claim[field] or len(set(claim[field])) != len(claim[field]) or
                    any(not isinstance(value, str) or not value for value in claim[field])
                    for field in ("source_paths", "required_ctest_names", "evidence_keys")) or
                any(name not in inventory_names for name in claim["required_ctest_names"]) or
                any(not isinstance(claim.get(field), str) or not claim[field]
                    for field in ("deferred_rationale", "prohibited_overclaim"))):
            raise Failure("invalid immutable lifecycle contract")
    _validate_captured_contract_sources(capture.contract_raw, members)
    claim_ids = list(IDS)
    runtime_seal = dict(capture.seals)["phase2/runtime-seal.json"].blob.sha256
    for relative, mode in (("phase2/runtime/static-report.json", "static"),
                           ("phase2/static-report.json", "static"),
                           ("phase2/closure-artifacts/evidence-bound-report.json", "evidence-bound")):
        report = _canonical_blob(members[relative], "sealed claim report")
        expected_seals = {} if mode == "static" else {"runtime_seal_sha256": runtime_seal}
        states = ["PENDING"] * 7 if mode == "static" else ["TOY_VERIFIED"] * 6 + ["PENDING"]
        try:
            report_claims(report, mode, capture.commit, states, contract_claims)
        except ValueError as error:
            raise Failure("foreign source commit or invalid claim verifier report") from error
        if report.get("input_seals") != expected_seals:
            raise Failure("foreign source commit or invalid claim verifier report")
    evidence_index = _json_blob(members["phase2/runtime/evidence-index.json"], "runtime evidence index")
    runtime_members = dict(dict(capture.seals)["phase2/runtime-seal.json"].members)
    if (set(evidence_index) != {"schema", "source_commit", "claims"} or
            evidence_index.get("schema") != "piccard-work7-evidence-index-v2" or evidence_index.get("source_commit") != capture.commit or
            not isinstance(evidence_index.get("claims"), dict) or set(evidence_index["claims"]) != set(claim_ids[:6])):
        raise Failure("foreign or invalid runtime evidence")
    used: set[str] = set()
    for claim in contract_claims[:6]:
        records = evidence_index["claims"].get(claim["id"])
        if not isinstance(records, dict) or set(records) != set(claim["evidence_keys"]):
            raise Failure("missing sealed claim evidence")
        for record in records.values():
            if (not isinstance(record, dict) or set(record) != {"path", "sha256", "artifact_kind"} or
                    not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str) or
                    record.get("artifact_kind") not in {"ctest-log", "probe-output", "csv-artifact"} or
                    record["path"] == "evidence-index.json" or record["path"] in used or
                    record["path"] not in runtime_members or record["sha256"] != runtime_members[record["path"]].sha256):
                raise Failure("invalid sealed claim evidence")
            used.add(record["path"])
    return RuntimeSummary(ctest_focused=canonical_argv_sha256(list(focused_argv)),
                          pre_threshold=canonical_argv_sha256(list(pre_argv)),
                          real_datasets=canonical_argv_sha256(list(real_argv)),
                          verify_real_datasets=canonical_argv_sha256(list(verify_argv)),
                          deletion_survival=canonical_argv_sha256(list(deletion_argv)),
                          focused_pass_count=pass_count)


def captured_generated_member_bytes(capture: Phase04Capture, runtime_summary: RuntimeSummary) -> tuple[bytes, bytes]:
    """Derive final generated bytes only from the R1 capture and frozen summary."""
    contract = _json_blob(capture.contract_raw, "claim contract")
    claims = contract.get("claims")
    if (not isinstance(claims, list) or len(claims) != 7 or
            any(not isinstance(row, dict) for row in claims)):
        raise Failure("invalid immutable lifecycle contract")
    mappings = [{"id": row.get("id"), "source_paths": row.get("source_paths"),
                 "required_ctest_names": row.get("required_ctest_names")} for row in claims]
    mapping_raw = canonical_json_bytes({"schema": "piccard-work7-source-test-map-v1", "claims": mappings[:6]})
    summary_raw = canonical_json_bytes({"schema": "piccard-work7-final-verification-v1", "source_commit": capture.commit,
        "registry_test_count": len(_frozen_ctests()), "registry_pass_count": runtime_summary.focused_pass_count,
        "registry_skip_count": 0, "toy_argv_sha256": {name: getattr(runtime_summary, name) for name in
        ("ctest_focused", "pre_threshold", "real_datasets", "deletion_survival")}, "measured_count_policy": "PASS",
        "external_snapshot_equality": True, "performance_state": "PERFORMANCE_PENDING"})
    return mapping_raw, summary_raw


def _final_member_sources(capture: Phase04Capture, runtime: RuntimeSummary) -> list[tuple[str, bytes]]:
    """Return the exact public final-member bytes from one captured graph."""
    mapping_raw, summary_raw = captured_generated_member_bytes(capture, runtime)
    sources: list[tuple[str, bytes]] = []
    source_members = _captured_member_map(capture)
    for relative in SOURCE_PACKET_MEMBERS:
        try:
            sources.append(("source/" + relative, source_members[_PUBLIC_SOURCE_PREFIX + relative].raw))
        except KeyError as error:
            raise Failure("public source capture is incomplete") from error
    try:
        sources.append(("source/git-diff-b907fae-to-head.patch", source_members[_PUBLIC_DIFF_MEMBER].raw))
    except KeyError as error:
        raise Failure("public diff capture is incomplete") from error
    member_map = source_members
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
    return sources


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


def validate_final_packet_members_capture(session: Path, packet: dict, capture: Phase04Capture,
                                          runtime: RuntimeSummary) -> None:
    """Bind every public Phase 5 member to its captured or rederived byte source."""
    packet_members = {member["path"]: member for member in packet["members"]}
    for label, raw in _final_member_sources(capture, runtime):
        relative = "phase5/members/" + label
        member = packet_members.get(relative)
        if member is None or member["size"] != len(raw) or member["sha256"] != _sha256_bytes(raw):
            raise Failure("review packet member differs from captured Phase 0--4 evidence")
        try:
            _, _, actual = _stable_regular_file(session / relative)
        except (OSError, ValueError) as error:
            raise Failure("review packet member is missing or unsafe") from error
        if actual != raw:
            raise Failure("review packet member differs from captured Phase 0--4 evidence")


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


def normalize_final_review_blobs(first: CapturedBlob, second: CapturedBlob,
                                 commit: str, packet_sha256: str) -> tuple[CapturedBlob, CapturedBlob]:
    """Return canonical Claude/sol slots from two already-captured review bytes."""
    identities: dict[str, CapturedBlob] = {}
    for blob in (first, second):
        identity = None
        for name, provider, model in (("claude", "anthropic", "claude-fable"),
                                      ("sol", "openai", "gpt-5.6-sol")):
            try:
                parse_review_bytes(blob.raw, commit, packet_sha256, provider, model,
                                   "POC_APPROVED_PERFORMANCE_PENDING", CHECKS_FINAL)
            except Failure:
                continue
            identity = name
            break
        if identity is None or identity in identities:
            raise Failure("final review identity, verdict, commit, packet, or status is invalid")
        identities[identity] = blob
    if set(identities) != {"claude", "sol"}:
        raise Failure("final reviews duplicate one provider")
    return identities["claude"], identities["sol"]


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
    if synchronize is not None:
        synchronize("after_first_capture")
    state = _canonical_blob(capture.state_raw, "Phase 0 state")
    seals = {relative: seal.blob.sha256 for relative, seal in capture.seals}
    phase4_packet_value = _canonical_blob(capture.phase4_packet, "work packet")
    if phase4_packet_value.get("phase") != "work" or phase4_packet_value.get("source_commit") != capture.commit or phase4_packet_value.get("prerequisite_seals") != {key: value for key, value in seals.items() if key != "phase4/work-review-seal.json"}:
        raise Failure("foreign work review packet")
    parse_review_bytes(capture.phase4_review.raw, capture.commit, capture.phase4_packet.sha256,
                       "openai", "gpt-5.6-sol", "WORK7_APPROVED", CHECKS_WORK)
    sources = _final_member_sources(capture, runtime)
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
    ledger = _PublicationLedger([])
    try:
        # ``phase5`` is allowed to predate this call (and might be deliberately
        # empty), but the members root itself must be an exclusive creation.
        _ledger_directories(ledger, session, root.parent)
        _ledger_directory(ledger, root, allow_existing=False)
        for label, raw in sources:
            target = root / label
            _ledger_directories(ledger, root, target.parent)
            copy_raw_member(raw, session, root, label, members)
            ledger.record(target)
            if label == "source/git-diff-b907fae-to-head.patch":
                members[-1]["label"] = "git-diff-b907fae-to-head.patch"
            elif label == "external/current-paper-state.json":
                members[-1]["label"] = "current-paper-state"
            elif label == "external/current-threshold-state.json":
                members[-1]["label"] = "current-threshold-state"
        if synchronize is not None:
            synchronize("before_packet_create")
        _ledger_directories(ledger, session, output.parent)
        _atomic_create(output, packet_bytes("final", capture.commit, seals, members))
        ledger.record(output)
    except Exception:
        ledger.rollback()
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


def validate_terminal_report_capture(path: Path, capture: Phase04Capture) -> tuple[dict, bytes, str]:
    """Validate terminal output against the already-captured contract, never live inputs."""
    value, raw, digest = stable_canonical_object(path, "terminal report")
    contract = _json_blob(capture.contract_raw, "claim contract")
    claims = contract.get("claims")
    if not isinstance(claims, list) or len(claims) != 7 or any(not isinstance(claim, dict) for claim in claims):
        raise Failure("invalid immutable lifecycle contract")
    try:
        if __package__:
            from scripts.verify_work7_claims import report_claims
        else:
            from verify_work7_claims import report_claims
        report_claims(value, "terminal", capture.commit, ["TOY_VERIFIED"] * 7, claims)
    except ValueError as error:
        raise Failure("terminal report is invalid") from error
    if value.get("input_seals") != {}:
        raise Failure("terminal report has foreign input seals")
    return value, raw, digest


def _revalidate_external_snapshots(capture: Phase04Capture, source: Path, paper: Path, threshold: Path) -> None:
    """Transitional post-subprocess race check; it derives no closure values."""
    if (canonical_json_bytes(snapshot_git_worktree(source)) != capture.source_snapshot_raw or
            canonical_json_bytes(snapshot_git_worktree(paper)) != capture.paper_snapshot_raw or
            canonical_json_bytes(snapshot_git_worktree(threshold)) != capture.threshold_snapshot_raw):
        raise Failure("external worktree snapshot changed")


def _revalidate_captured_seals(session: Path, capture: Phase04Capture) -> None:
    """Transitional race detector only; no reopened byte is used as an input."""
    for relative, seal in capture.seals:
        try:
            current = _captured_file(session / relative, "prerequisite seal")
        except Failure as error:
            raise Failure("prerequisite seal changed during final closure") from error
        if current.raw != seal.blob.raw:
            raise Failure("prerequisite seal changed during final closure")


def _terminal_inputs_capture(session: Path, packet: Path, claude: Path, sol: Path,
                             capture: Phase04Capture):
    """Stable-capture all final inputs before entering the R2 terminal core."""
    if __package__:
        from scripts.verify_work7_claims import TerminalInputs
    else:
        from verify_work7_claims import TerminalInputs
    final_packet = _captured_file(packet, "final packet")
    value = _canonical_blob(final_packet, "final packet")
    records = value.get("members")
    if not isinstance(records, list):
        raise Failure("final packet members are invalid")
    members: list[tuple[str, CapturedBlob]] = []
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise Failure("final packet member is invalid")
        relative = Path(record["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise Failure("final packet member escapes session root")
        members.append((record["path"], _captured_file(session / relative, "final packet member")))
    normalized_claude, normalized_sol = normalize_final_review_blobs(
        _captured_file(claude, "final review"), _captured_file(sol, "final review"),
        capture.commit, final_packet.sha256)
    return TerminalInputs(capture, final_packet, tuple(members), normalized_claude, normalized_sol)


def publish_phase5(session: Path, terminal_report: Path, output_seal: Path,
                   packet_raw: bytes, claude_raw: bytes, sol_raw: bytes,
                   report_raw: bytes, previous_seal_sha256: str) -> str:
    """Publish the already-validated terminal byte graph or remove only this call's work.

    The terminal core deliberately runs before this function.  This boundary
    therefore has no authority to derive evidence: it exclusively creates,
    stable-reads, and validates the exact byte group supplied by its caller.
    """
    session = required(session, "session root", directory=True)
    terminal_report = session_path(session, terminal_report, "terminal report", exists=False)
    output_seal = session_path(session, output_seal, "output seal", exists=False)
    if (not isinstance(previous_seal_sha256, str) or
            re.fullmatch(r"[0-9a-f]{64}", previous_seal_sha256) is None):
        raise Failure("terminal predecessor seal digest is invalid")
    if any(not isinstance(raw, bytes) for raw in (packet_raw, claude_raw, sol_raw, report_raw)):
        raise Failure("terminal publication bytes are invalid")

    root = session / "phase5/terminal-artifacts"
    members = (("final-packet.json", packet_raw), ("claude-review.txt", claude_raw),
               ("sol-review.txt", sol_raw), ("terminal-report.json", report_raw))
    # The member files are exclusively created with 0600 by _atomic_create.
    # Build the exact canonical seal and pointer before changing Phase 5.
    seal_value = {
        "schema": "piccard-work7-tree-seal-v1",
        "kind": "phase5-terminal",
        "artifact_root": str(root),
        "previous_seal_sha256": previous_seal_sha256,
        "entries": [{"path": name, "size": len(raw), "mode": "0600",
                     "sha256": hashlib.sha256(raw).hexdigest()}
                    for name, raw in sorted(members)],
    }
    seal_raw = canonical_json_bytes(seal_value)
    seal_digest = hashlib.sha256(seal_raw).hexdigest()
    pointer = output_seal.with_name("terminal-seal.sha256")
    pointer_raw = (seal_digest + "\n").encode("ascii")
    ledger = _PublicationLedger([])
    try:
        _ledger_directories(ledger, session, terminal_report.parent)
        _atomic_create(terminal_report, report_raw)
        ledger.record(terminal_report)
        _ledger_directories(ledger, session, root.parent)
        _ledger_directory(ledger, root, allow_existing=False)
        for name, raw in members:
            target = root / name
            _atomic_create(target, raw)
            ledger.record(target)
        _ledger_directories(ledger, session, output_seal.parent)
        _atomic_create(output_seal, seal_raw)
        ledger.record(output_seal)
        _ledger_directories(ledger, session, pointer.parent)
        _atomic_create(pointer, pointer_raw)
        ledger.record(pointer)

        # Re-capture all output bytes and the seal graph after publication.
        if _captured_file(terminal_report, "published terminal report").raw != report_raw:
            raise Failure("published terminal report differs from captured bytes")
        published = capture_tree_seal(output_seal, previous_seal_sha256, "phase5-terminal", root,
                                      {name for name, _ in members})
        if published.blob.raw != seal_raw or published.blob.sha256 != seal_digest:
            raise Failure("published terminal seal differs from prospective seal")
        if {name: blob.raw for name, blob in published.members} != dict(members):
            raise Failure("published terminal artifacts differ from captured bytes")
        if _captured_file(pointer, "terminal seal pointer").raw != pointer_raw:
            raise Failure("terminal seal pointer mismatch")
    except (Failure, OSError, ValueError, FileExistsError):
        ledger.rollback()
        raise
    return seal_digest


def close_final(args: argparse.Namespace, synchronize: Callable[[str], None] | None = None) -> None:
    session = required(args.session_root, "session root", directory=True)
    packet, claude, sol = (session_path(session, args.packet, "packet"), required(args.claude_review, "claude review"), required(args.sol_review, "sol review"))
    terminal_report, output = session_path(session, args.terminal_report, "terminal report", exists=False), session_path(session, args.output_seal, "output seal", exists=False)
    phase0_seal = session_path(session, args.phase0_seal, "Phase 0 seal")
    if phase0_seal != session / "phase0/seal.json":
        raise Failure("foreign Phase 0 seal path")
    source = required(args.source_root, "source root", directory=True)
    paper, threshold = required(args.paper_root, "paper root", directory=True), required(args.threshold_root, "threshold root", directory=True)
    # This is the sole Phase 0--4 read boundary for closure.  It checks the
    # CLI roots against the sealed canonical roots before returning immutable
    # evidence bytes to every following R1 consumer.
    capture = capture_phase04(session, source, paper, threshold)
    inputs = _terminal_inputs_capture(session, packet, claude, sol, capture)
    if synchronize is not None:
        synchronize("after_terminal_capture")
    if __package__:
        from scripts.verify_work7_claims import terminal_report_bytes
    else:
        from verify_work7_claims import terminal_report_bytes
    # The terminal core is the complete semantic boundary.  In particular it
    # receives no Phase 3/4 path and cannot reopen the session after capture.
    terminal_raw = terminal_report_bytes(inputs)
    if synchronize is not None:
        synchronize("after_terminal_core")
    seals = {relative: seal.blob.sha256 for relative, seal in capture.seals}
    packet_raw, claude_raw, sol_raw = inputs.final_packet.raw, inputs.claude_review.raw, inputs.sol_review.raw
    digest = publish_phase5(session, terminal_report, output, packet_raw, claude_raw, sol_raw,
                            terminal_raw, seals["phase4/work-review-seal.json"])
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
