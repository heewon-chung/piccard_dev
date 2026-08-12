#!/usr/bin/env python3
"""Atomic non-circular seal creation for a complete Work #5 evidence root.

This module deliberately owns only the byte-level seal.  Semantic verification
and pre-seal receipt construction live in ``verify_work5_benchmarks.py`` so a
manifest never certifies a receipt that was created from the manifest itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


class SealError(RuntimeError):
    """A seal lifecycle violation that makes the root terminally unusable."""


PRE_SEAL_RECEIPT_SCHEMA = "piccard-work5-pre-seal-receipt-v1"
PRE_SEAL_RECEIPT_FIELDS = frozenset({
    "schema", "semantic_verdict", "created_at_utc", "results_root", "root_identity",
    "git_sha", "tracked_clean", "run_sha256", "build_dir", "executables", "scripts",
    "matrix_sha256", "command_template_sha256", "completed_phases",
    "phase_receipt_sha256", "full_ctest_receipt", "parameter_counts",
    "real_semantic_verdict", "dynamic_semantic_verdict", "inventory", "inventory_sha256",
    "directories", "directories_sha256",
})
PRE_SEAL_COMPLETED_PHASES = ["toy", "parameters", "real", "dynamic"]
PRE_SEAL_PARAMETER_COUNTS = {"terminal_cells": 61, "measured": 49, "skipped": 12, "errors": 0}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def root_identity(root: Path) -> dict[str, Any]:
    try:
        resolved = root.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise SealError(f"cannot stat evidence root: {exc}") from exc
    if root.is_symlink() or not resolved.is_dir():
        raise SealError("evidence root is not a non-symlink directory")
    return {"path": str(resolved), "st_dev": info.st_dev, "st_ino": info.st_ino}


def _canonical_argument(path: Path, label: str) -> Path:
    """Resolve ordinary path aliases while rejecting a symlink target itself."""
    path = Path(path).absolute()
    if path.is_symlink():
        raise SealError(f"{label} is a symlink")
    return path.resolve(strict=False)


def _valid_relative(relative: str) -> None:
    if (not relative or relative.startswith("/") or "\\" in relative or "\x00" in relative or
            "\n" in relative or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise SealError(f"unsafe evidence path: {relative!r}")


def _walk_regular_files(root: Path, *, directory_paths: list[str] | None = None) -> list[tuple[str, Path]]:
    expected_identity = root_identity(root)
    files: list[tuple[str, Path]] = []
    folded: set[str] = set()
    for directory, directories, names in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in directories:
            candidate = directory_path / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as exc:
                raise SealError(f"cannot stat evidence path: {candidate}") from exc
            if stat.S_ISLNK(mode):
                raise SealError(f"symlinked evidence path is forbidden: {candidate}")
            if not stat.S_ISDIR(mode):
                raise SealError(f"unsupported directory entry: {candidate}")
            relative = candidate.relative_to(root).as_posix()
            _valid_relative(relative)
            folded_relative = relative.casefold()
            if folded_relative in folded:
                raise SealError(f"case-colliding evidence path: {relative}")
            folded.add(folded_relative)
            if directory_paths is not None:
                directory_paths.append(relative)
        for name in names:
            candidate = directory_path / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as exc:
                raise SealError(f"cannot stat evidence path: {candidate}") from exc
            if stat.S_ISLNK(mode):
                raise SealError(f"symlinked evidence path is forbidden: {candidate}")
            if not stat.S_ISREG(mode):
                raise SealError(f"unsupported evidence file type: {candidate}")
            relative = candidate.relative_to(root).as_posix()
            _valid_relative(relative)
            folded_relative = relative.casefold()
            if folded_relative in folded:
                raise SealError(f"case-colliding evidence path: {relative}")
            folded.add(folded_relative)
            files.append((relative, candidate))
    if root_identity(root) != expected_identity:
        raise SealError("evidence root identity changed while enumerating files")
    return sorted(files, key=lambda item: item[0].encode("utf-8"))


def inventory(root: Path, *, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    for relative in excluded:
        _valid_relative(relative)
    return [{"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)}
            for relative, path in _walk_regular_files(root) if relative not in excluded]


def directory_inventory(root: Path) -> list[str]:
    """Return the complete canonical non-symlink directory topology."""
    directories: list[str] = []
    _walk_regular_files(root, directory_paths=directories)
    return sorted(directories, key=lambda item: item.encode("utf-8"))


def snapshot(root: Path) -> bytes:
    """A read-only complete byte snapshot for zero-write post-seal tests."""
    directories: list[str] = []
    entries = _walk_regular_files(root, directory_paths=directories)
    files = [{"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)}
             for relative, path in entries]
    files.sort(key=lambda item: item["path"].encode("utf-8"))
    directories.sort(key=lambda item: item.encode("utf-8"))
    return canonical_json({"identity": root_identity(root), "directories": directories,
                           "inventory": files})


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_no_replace(path: Path, payload: bytes, *, expected_root: dict[str, Any]) -> None:
    """Install one regular file with exclusive creation and durable link(2).

    ``os.replace`` is intentionally forbidden: a partial or prior seal is a
    terminal evidence state, never an invitation to repair the same root.
    """
    if root_identity(Path(expected_root["path"])) != expected_root:
        raise SealError("evidence root identity changed before atomic install")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise SealError(f"unsafe seal destination parent: {parent}")
    if path.exists() or path.is_symlink():
        raise SealError(f"refusing to overwrite existing seal artifact: {path}")
    if list(parent.glob(f".{path.name}.tmp.*")):
        raise SealError(f"stale seal temporary exists for target: {path}")
    temporary = parent / f".{path.name}.tmp.{os.getpid()}-{secrets.token_hex(16)}"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SealError(f"short write creating seal artifact: {path}")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if root_identity(Path(expected_root["path"])) != expected_root:
            raise SealError("evidence root identity changed before seal install")
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise SealError(f"refusing to overwrite existing seal artifact: {path}") from exc
        _fsync_directory(parent)
        temporary.unlink()
        _fsync_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_receipt(receipt_path: Path) -> dict[str, Any]:
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise SealError("pre-seal receipt is missing or unsafe")
    try:
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError(f"cannot read pre-seal receipt: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != PRE_SEAL_RECEIPT_SCHEMA:
        raise SealError("pre-seal receipt schema mismatch")
    if set(value) != PRE_SEAL_RECEIPT_FIELDS:
        raise SealError("pre-seal receipt fields are incomplete or contain extras")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise SealError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _require_git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_SHA_PATTERN.fullmatch(value) is None:
        raise SealError(f"{label} is not a lowercase Git SHA")
    return value


def _require_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise SealError(f"{label} is malformed")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SealError(f"{label} is malformed") from exc
    return value


def _regular_root_file(root: Path, relative: str, label: str) -> Path:
    _valid_relative(relative)
    candidate = root / relative
    if candidate.is_symlink() or not candidate.is_file():
        raise SealError(f"{label} is missing or unsafe")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise SealError(f"{label} escapes the evidence root") from exc
    try:
        if not stat.S_ISREG(candidate.lstat().st_mode):
            raise SealError(f"{label} is not a regular file")
    except OSError as exc:
        raise SealError(f"{label} cannot be stated") from exc
    return candidate


def _require_hash_map(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise SealError(f"{label} is missing or malformed")
    result: dict[str, str] = {}
    for key, digest in value.items():
        if not isinstance(key, str) or not key:
            raise SealError(f"{label} has a malformed key")
        result[key] = _require_sha256(digest, f"{label}[{key!r}]")
    return result


def _load_json_object(root: Path, relative: str, label: str) -> dict[str, Any]:
    path = _regular_root_file(root, relative, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise SealError(f"{label} is not a JSON object")
    return value


def _sorted_inventory(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        raise SealError("receipt inventory is malformed")
    parsed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise SealError("receipt inventory entry is malformed")
        relative, size, digest = entry.get("path"), entry.get("size"), entry.get("sha256")
        if not isinstance(relative, str) or not isinstance(size, int) or size < 0 or \
                not isinstance(digest, str) or len(digest) != 64 or \
                any(ch not in "0123456789abcdef" for ch in digest):
            raise SealError("receipt inventory entry is malformed")
        _valid_relative(relative)
        if relative in seen:
            raise SealError("receipt inventory has duplicate path")
        if relative.casefold() in {item["path"].casefold() for item in parsed}:
            raise SealError("receipt inventory has case-colliding path")
        seen.add(relative)
        parsed.append({"path": relative, "size": size, "sha256": digest})
    ordered = sorted(parsed, key=lambda item: item["path"].encode("utf-8"))
    if parsed != ordered:
        raise SealError("receipt inventory order is not deterministic")
    return ordered


def _sorted_directories(entries: list[str]) -> list[str]:
    if not isinstance(entries, list) or any(not isinstance(item, str) for item in entries):
        raise SealError("receipt directory inventory is malformed")
    seen: set[str] = set()
    for relative in entries:
        _valid_relative(relative)
        folded = relative.casefold()
        if folded in seen:
            raise SealError("receipt directory inventory has duplicate or case-colliding path")
        seen.add(folded)
    ordered = sorted(entries, key=lambda item: item.encode("utf-8"))
    if entries != ordered:
        raise SealError("receipt directory inventory order is not deterministic")
    return ordered


def _validate_complete_receipt(root: Path, receipt: dict[str, Any],
                               identity: dict[str, Any]) -> None:
    """Validate every semantic binding required before byte-level sealing."""
    if receipt.get("semantic_verdict") != "PASS" or \
            receipt.get("real_semantic_verdict") != "PASS" or \
            receipt.get("dynamic_semantic_verdict") != "PASS":
        raise SealError("pre-seal semantic verdict is not PASS")
    _require_timestamp(receipt.get("created_at_utc"), "pre-seal creation time")
    if receipt.get("results_root") != identity["path"] or receipt.get("root_identity") != identity:
        raise SealError("pre-seal receipt root identity mismatch")
    _require_git_sha(receipt.get("git_sha"), "pre-seal git identity")
    if type(receipt.get("tracked_clean")) is not bool or not receipt["tracked_clean"]:
        raise SealError("pre-seal tracked-clean proof is not true")
    build_dir = receipt.get("build_dir")
    if not isinstance(build_dir, str) or not build_dir or not os.path.isabs(build_dir):
        raise SealError("pre-seal build identity is malformed")
    executable_hashes = _require_hash_map(receipt.get("executables"), "pre-seal executable hashes")
    script_hashes = _require_hash_map(receipt.get("scripts"), "pre-seal script hashes")
    _require_sha256(receipt.get("run_sha256"), "pre-seal run hash")
    _require_sha256(receipt.get("matrix_sha256"), "pre-seal matrix hash")
    _require_sha256(receipt.get("command_template_sha256"), "pre-seal command-template hash")
    if receipt.get("completed_phases") != PRE_SEAL_COMPLETED_PHASES:
        raise SealError("pre-seal completed phases are not the exact final lifecycle")
    if receipt.get("parameter_counts") != PRE_SEAL_PARAMETER_COUNTS:
        raise SealError("pre-seal parameter counts are not 61/49/12/0")

    run_path = _regular_root_file(root, "run.json", "run identity")
    if sha256_file(run_path) != receipt["run_sha256"]:
        raise SealError("pre-seal run hash does not match run.json")
    try:
        run = json.loads(run_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError("run identity is not valid JSON") from exc
    if not isinstance(run, dict) or run.get("schema") != "piccard-work5-run-v1":
        raise SealError("run identity schema mismatch")
    source_root = run.get("source_root")
    if not isinstance(source_root, str) or not source_root or not os.path.isabs(source_root):
        raise SealError("run source identity is malformed")
    if run.get("git_sha") != receipt["git_sha"] or run.get("git_dirty") is not False or \
            run.get("build_dir") != build_dir or run.get("executables") != executable_hashes or \
            run.get("scripts") != script_hashes or run.get("matrix_sha256") != receipt["matrix_sha256"] or \
            run.get("command_template_sha256") != receipt["command_template_sha256"] or \
            run.get("completed_phases") != PRE_SEAL_COMPLETED_PHASES:
        raise SealError("pre-seal receipt does not bind run source identity")

    phase_hashes = receipt.get("phase_receipt_sha256")
    if not isinstance(phase_hashes, dict) or set(phase_hashes) != set(PRE_SEAL_COMPLETED_PHASES):
        raise SealError("pre-seal phase receipt hashes are incomplete")
    for phase in PRE_SEAL_COMPLETED_PHASES:
        relative = f"verification/{phase}.json"
        phase_path = _regular_root_file(root, relative, f"{phase} receipt")
        digest = _require_sha256(phase_hashes[phase], f"{phase} receipt hash")
        if sha256_file(phase_path) != digest:
            raise SealError(f"{phase} receipt hash does not match its artifact")
        try:
            phase_receipt = json.loads(phase_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SealError(f"{phase} receipt is not valid JSON") from exc
        if not isinstance(phase_receipt, dict) or \
                phase_receipt.get("schema") != "piccard-work5-verification-receipt-v1" or \
                phase_receipt.get("verdict") != "PASS" or phase_receipt.get("phase") != phase or \
                phase_receipt.get("results_root") != identity["path"] or \
                phase_receipt.get("run_sha256") != receipt["run_sha256"] or \
                phase_receipt.get("git_sha") != receipt["git_sha"] or \
                phase_receipt.get("completed_phases") != PRE_SEAL_COMPLETED_PHASES[:PRE_SEAL_COMPLETED_PHASES.index(phase) + 1]:
            raise SealError(f"{phase} receipt semantic binding mismatch")

    full_ctest = receipt.get("full_ctest_receipt")
    if not isinstance(full_ctest, dict) or set(full_ctest) != {"path", "sha256"} or \
            full_ctest.get("path") != "verification/full-ctest.json":
        raise SealError("full CTest receipt binding is malformed")
    full_ctest_path = _regular_root_file(root, full_ctest["path"], "full CTest receipt")
    if sha256_file(full_ctest_path) != _require_sha256(full_ctest.get("sha256"), "full CTest receipt hash"):
        raise SealError("full CTest receipt hash does not match its artifact")
    try:
        ctest_receipt = json.loads(full_ctest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError("full CTest receipt is not valid JSON") from exc
    if not isinstance(ctest_receipt, dict) or \
            ctest_receipt.get("schema") != "piccard-work5-ctest-gate-receipt-v1" or \
            ctest_receipt.get("verdict") != "PASS" or \
            ctest_receipt.get("classification") != "KNOWN_WORK6_SCOPE_DIAGNOSTIC_MISMATCH" or \
            ctest_receipt.get("results_root") != identity["path"] or \
            ctest_receipt.get("git_sha") != receipt["git_sha"] or \
            ctest_receipt.get("completed_phases") != ["toy"]:
        raise SealError("full CTest receipt semantic binding mismatch")


def _reject_stale_seal_temporary(root: Path) -> None:
    """Reject partial atomic-install remnants before any seal transition."""
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SealError(f"symlinked evidence path is forbidden: {path}")
        if path.name.startswith(".SHA256SUMS.tmp.") or \
                path.name.startswith(".SHA256SUMS.sha256.tmp."):
            raise SealError(f"stale seal temporary exists: {path}")


def verify_receipt_for_seal(root: Path, receipt_path: Path) -> dict[str, Any]:
    identity = root_identity(root)
    root = Path(identity["path"])
    receipt_path = _canonical_argument(Path(receipt_path), "pre-seal receipt")
    canonical_receipt = root / "verification" / "pre-seal-receipt.json"
    if receipt_path != canonical_receipt:
        raise SealError("pre-seal receipt path is not canonical")
    receipt = _load_receipt(receipt_path)
    _validate_complete_receipt(root, receipt, identity)
    expected = _sorted_inventory(receipt.get("inventory"))
    inventory_sha = receipt.get("inventory_sha256")
    if not isinstance(inventory_sha, str) or len(inventory_sha) != 64 or \
            any(ch not in "0123456789abcdef" for ch in inventory_sha) or \
            inventory_sha != sha256_bytes(canonical_json(expected)):
        raise SealError("pre-seal receipt inventory digest mismatch")
    expected_directories = _sorted_directories(receipt.get("directories"))
    directories_sha = receipt.get("directories_sha256")
    if not isinstance(directories_sha, str) or len(directories_sha) != 64 or \
            any(ch not in "0123456789abcdef" for ch in directories_sha) or \
            directories_sha != sha256_bytes(canonical_json(expected_directories)):
        raise SealError("pre-seal receipt directory inventory digest mismatch")
    if directory_inventory(root) != expected_directories:
        raise SealError("pre-seal receipt directory inventory does not match current root")
    receipt_relative = receipt_path.relative_to(root).as_posix()
    current = inventory(root, exclude={"SHA256SUMS", "SHA256SUMS.sha256"})
    receipt_entry = {"path": receipt_relative, "size": receipt_path.stat().st_size,
                     "sha256": sha256_file(receipt_path)}
    expected_with_receipt = sorted([*expected, receipt_entry],
                                   key=lambda item: item["path"].encode("utf-8"))
    if current != _sorted_inventory(expected_with_receipt):
        raise SealError("pre-seal receipt inventory does not match current root")
    return receipt


def create_seal(root: Path, receipt_path: Path, manifest_path: Path, digest_path: Path) -> None:
    identity = root_identity(root)
    root = Path(identity["path"])
    receipt_path = _canonical_argument(Path(receipt_path), "pre-seal receipt")
    manifest_path = _canonical_argument(Path(manifest_path), "manifest")
    digest_path = _canonical_argument(Path(digest_path), "manifest digest")
    if receipt_path != root / "verification" / "pre-seal-receipt.json":
        raise SealError("pre-seal receipt path is not canonical")
    if manifest_path != root / "SHA256SUMS" or digest_path != root / "SHA256SUMS.sha256":
        raise SealError("seal paths are not canonical")
    if manifest_path.exists() or manifest_path.is_symlink() or digest_path.exists() or digest_path.is_symlink():
        raise SealError("partial or existing seal state cannot be overwritten")
    _reject_stale_seal_temporary(root)
    verify_receipt_for_seal(root, receipt_path)
    entries = inventory(root, exclude={"SHA256SUMS", "SHA256SUMS.sha256"})
    lines = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries).encode("utf-8")
    atomic_no_replace(manifest_path, lines, expected_root=identity)
    digest_payload = f"{sha256_bytes(lines)}  SHA256SUMS\n".encode("ascii")
    atomic_no_replace(digest_path, digest_payload, expected_root=identity)


def verify_post_seal(root: Path, receipt_path: Path, manifest_path: Path, digest_path: Path) -> None:
    """Read-only post-seal validation.  It never creates or repairs a file."""
    identity = root_identity(root)
    root = Path(identity["path"])
    receipt_path = _canonical_argument(Path(receipt_path), "pre-seal receipt")
    manifest_path = _canonical_argument(Path(manifest_path), "manifest")
    digest_path = _canonical_argument(Path(digest_path), "manifest digest")
    before = snapshot(root)
    if (receipt_path != root / "verification" / "pre-seal-receipt.json" or
            manifest_path != root / "SHA256SUMS" or
            digest_path != root / "SHA256SUMS.sha256"):
        raise SealError("post-seal paths are not canonical")
    _reject_stale_seal_temporary(root)
    verify_receipt_for_seal(root, receipt_path)
    if any(path.is_symlink() or not path.is_file() for path in (manifest_path, digest_path)):
        raise SealError("seal files are missing or unsafe")
    manifest_bytes = manifest_path.read_bytes()
    expected_digest = f"{sha256_bytes(manifest_bytes)}  SHA256SUMS\n".encode("ascii")
    if digest_path.read_bytes() != expected_digest:
        raise SealError("SHA256SUMS digest mismatch")
    try:
        manifest_text = manifest_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SealError("SHA256SUMS is not strict UTF-8") from exc
    entries: list[dict[str, Any]] = []
    for line in manifest_text.splitlines(keepends=True):
        if not line.endswith("\n"):
            raise SealError("SHA256SUMS line lacks canonical newline")
        digest, separator, relative = line[:-1].partition("  ")
        if separator != "  " or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise SealError("SHA256SUMS line is malformed")
        _valid_relative(relative)
        entries.append({"path": relative, "sha256": digest})
    if not entries or len({entry["path"] for entry in entries}) != len(entries):
        raise SealError("SHA256SUMS path set is malformed")
    if entries != sorted(entries, key=lambda item: item["path"].encode("utf-8")):
        raise SealError("SHA256SUMS order is not deterministic")
    current = inventory(root, exclude={"SHA256SUMS", "SHA256SUMS.sha256"})
    if [entry["path"] for entry in entries] != [entry["path"] for entry in current]:
        raise SealError("SHA256SUMS path set does not equal evidence inventory")
    if any(entry["sha256"] != actual["sha256"]
           for entry, actual in zip(entries, current)):
        raise SealError("SHA256SUMS file hash mismatch")
    if root_identity(root) != identity or snapshot(root) != before:
        raise SealError("post-seal verification observed a root mutation")


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("create",), required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-digest", required=True)
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        create_seal(Path(args.root), Path(args.receipt), Path(args.manifest), Path(args.manifest_digest))
        print(json.dumps({"schema": "piccard-work5-seal-v1", "verdict": "PASS"}, sort_keys=True))
        return 0
    except SealError as exc:
        print(f"seal_work5_benchmarks: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
