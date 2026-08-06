#!/usr/bin/env python3
"""Canonical Work 7 evidence snapshots and immutable tree seals."""

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _framed_digest(parts: list[bytes]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(_frame(part))
    return digest.hexdigest()


def _mode(mode: int) -> str:
    return format(stat.S_IMODE(mode), "04o")


def _lstat_entry(path: Path, relative: str, missing_allowed: bool) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_allowed:
            return {"path": relative, "type": "missing"}
        raise ValueError(f"snapshot entry disappeared: {relative}") from None
    if stat.S_ISREG(info.st_mode):
        return {"path": relative, "type": "file", "mode": _mode(info.st_mode),
                "size": info.st_size, "sha256": sha256_file(path)}
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path).encode("utf-8", "surrogateescape")
        return {"path": relative, "type": "symlink", "mode": _mode(info.st_mode),
                "target": target.decode("utf-8", "surrogateescape"),
                "target_sha256": hashlib.sha256(target).hexdigest()}
    if stat.S_ISDIR(info.st_mode):
        return {"path": relative, "type": "directory", "mode": _mode(info.st_mode)}
    raise ValueError(f"unsupported snapshot entry type: {relative}")


def sha256_file(path: Path) -> str:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, check=False,
                            capture_output=True)
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {message}")
    return result.stdout


def _index_entries(raw: bytes) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, path = item.split(b"\t", 1)
        mode, object_id, stage = metadata.split(b" ")
        entries.append({"path": path.decode("utf-8", "surrogateescape"),
                        "mode": mode.decode("ascii"),
                        "object_id": object_id.decode("ascii"),
                        "stage": int(stage)})
    return entries


def _update_framed(digest: Any, value: bytes) -> None:
    digest.update(_frame(value))


def _update_entry_digest(digest: Any, root: Path, entry: dict[str, Any]) -> None:
    """Hash an entry by framing each variable field, never by concatenation."""
    for key in ("path", "type", "mode", "size", "sha256", "target", "target_sha256"):
        if key in entry:
            _update_framed(digest, key.encode("ascii"))
            _update_framed(digest, str(entry[key]).encode("utf-8", "surrogateescape"))
    if entry["type"] == "file":
        path = root / entry["path"]
        _update_framed(digest, b"bytes")
        _update_framed(digest, path.read_bytes())


def _snapshot_digest(root: Path, state: dict[str, Any], index_raw: bytes) -> str:
    digest = hashlib.sha256()
    for key in ("root", "branch", "head", "submodule_status"):
        _update_framed(digest, key.encode("ascii"))
        _update_framed(digest, str(state[key]).encode("utf-8", "surrogateescape"))
    _update_framed(digest, b"index_raw")
    _update_framed(digest, index_raw)
    for category in ("tracked_entries", "untracked_entries"):
        _update_framed(digest, category.encode("ascii"))
        for entry in state[category]:
            _update_entry_digest(digest, root, entry)
    return digest.hexdigest()


def snapshot_git_worktree(root: Path) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    _git(root, "rev-parse", "--is-inside-work-tree")
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    branch_result = subprocess.run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
                                   cwd=root, check=False, capture_output=True)
    if branch_result.returncode == 0:
        branch = branch_result.stdout.decode("utf-8", "strict").strip()
    elif branch_result.returncode == 1:
        branch = "DETACHED"
    else:
        raise ValueError("git symbolic-ref failed")
    index_raw = _git(root, "ls-files", "-s", "-z")
    index_entries = _index_entries(index_raw)
    tracked_paths = {entry["path"] for entry in index_entries}
    untracked_raw = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    untracked_paths = sorted(
        item.decode("utf-8", "surrogateescape") for item in untracked_raw.split(b"\0") if item
    )
    tracked = [_lstat_entry(root / path, path, True) for path in sorted(tracked_paths)]
    untracked = [_lstat_entry(root / path, path, False) for path in untracked_paths]
    submodule_status = _git(root, "submodule", "status", "--recursive").decode(
        "utf-8", "surrogateescape"
    )
    porcelain_status = _git(root, "status", "--porcelain=v1", "--untracked-files=all").decode(
        "utf-8", "surrogateescape"
    )
    state = {
        "root": str(root), "branch": branch, "head": head,
        "index_entries": index_entries, "index_sha256": _framed_digest([index_raw]),
        "tracked_entries": tracked, "untracked_entries": untracked,
        "submodule_status": submodule_status, "porcelain_status": porcelain_status,
    }
    # ``snapshot_sha256`` binds raw worktree bytes using individual frames;
    # porcelain output is retained for diagnostics only and never fingerprints
    # state.
    state["snapshot_sha256"] = _snapshot_digest(root, state, index_raw)
    return state


def assert_output_roots_outside(guarded_roots: list[Path], output_roots: list[Path]) -> None:
    resolved_guarded = [root.resolve(strict=True) for root in guarded_roots]
    for output in output_roots:
        resolved_output = output.resolve(strict=False)
        for guarded in resolved_guarded:
            try:
                resolved_output.relative_to(guarded)
            except ValueError:
                continue
            raise ValueError(f"output root is inside guarded worktree: {output}")


def _seal_entries(artifact_root: Path) -> list[dict[str, Any]]:
    root_info = artifact_root.lstat()
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError(f"artifact root is not a directory: {artifact_root}")
    entries: list[dict[str, Any]] = []
    for current, directories, files in os.walk(artifact_root, followlinks=False):
        current_path = Path(current)
        for name in directories[:]:
            child = current_path / name
            if stat.S_ISLNK(child.lstat().st_mode):
                raise ValueError(f"symlink in artifact root: {child}")
        for name in files:
            child = current_path / name
            info = child.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"non-regular artifact entry: {child}")
            entries.append({"path": child.relative_to(artifact_root).as_posix(),
                            "size": info.st_size, "mode": _mode(info.st_mode),
                            "sha256": sha256_file(child)})
    return sorted(entries, key=lambda entry: entry["path"])


def create_tree_seal(artifact_root: Path, seal_path: Path,
                     previous_seal_sha256: str | None, kind: str) -> dict:
    artifact_root = artifact_root.resolve(strict=True)
    seal_path = seal_path.resolve(strict=False)
    try:
        seal_path.relative_to(artifact_root)
    except ValueError:
        pass
    else:
        raise ValueError("seal path must be outside artifact root")
    if seal_path.exists() or seal_path.is_symlink():
        raise FileExistsError(f"seal already exists: {seal_path}")
    if previous_seal_sha256 is not None and not _is_sha256(previous_seal_sha256):
        raise ValueError("previous seal digest must be SHA-256")
    seal = {"schema": "piccard-work7-tree-seal-v1", "kind": kind,
            "artifact_root": str(artifact_root),
            "previous_seal_sha256": previous_seal_sha256,
            "entries": _seal_entries(artifact_root)}
    _atomic_create(seal_path, canonical_json_bytes(seal))
    return seal


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _atomic_create(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except FileExistsError:
        raise FileExistsError(f"output already exists: {path}") from None
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def verify_tree_seal(seal_path: Path, expected_previous_sha256: str | None = None) -> dict:
    if seal_path.is_symlink():
        raise ValueError(f"seal is a symlink: {seal_path}")
    raw = seal_path.read_bytes()
    try:
        seal = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("invalid seal JSON") from error
    if canonical_json_bytes(seal) != raw or seal.get("schema") != "piccard-work7-tree-seal-v1":
        raise ValueError("non-canonical or invalid seal")
    if expected_previous_sha256 is not None and seal.get("previous_seal_sha256") != expected_previous_sha256:
        raise ValueError("unexpected previous seal digest")
    artifact_root = Path(seal["artifact_root"])
    if seal_path.resolve(strict=False).is_relative_to(artifact_root.resolve(strict=True)):
        raise ValueError("seal path is inside artifact root")
    if seal.get("entries") != _seal_entries(artifact_root):
        raise ValueError("seal entries do not match artifact root")
    return seal
