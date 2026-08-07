#!/usr/bin/env python3
"""Canonical Work 7 evidence snapshots and immutable tree seals."""

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CapturedBlob:
    """A stable, immutable regular-file read used by a sealed evidence graph."""

    raw: bytes
    sha256: str
    size: int
    mode: str


@dataclass(frozen=True)
class CapturedTreeSeal:
    """The seal bytes plus the exact stable bytes named by its manifest."""

    blob: CapturedBlob
    kind: str
    artifact_root: str
    previous_seal_sha256: str | None
    members: tuple[tuple[str, CapturedBlob], ...]


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


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.normpath(os.path.abspath(os.fspath(path))))


def _is_trusted_system_alias(path: Path) -> bool:
    """Permit only macOS's fixed top-level aliases, not arbitrary links."""
    expected = {Path("/tmp"): Path("/private/tmp"), Path("/var"): Path("/private/var")}
    return path in expected and path.resolve(strict=True) == expected[path]


def _reject_symlink_components(path: Path) -> None:
    """Reject an existing symlink anywhere in a lexical path before resolve."""
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                if _is_trusted_system_alias(current):
                    continue
                raise ValueError(f"symlink path component is not allowed: {current}")
        except FileNotFoundError:
            break


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode), left.st_size,
            left.st_mtime_ns, left.st_ctime_ns) == (
                right.st_dev, right.st_ino, stat.S_IFMT(right.st_mode), right.st_size,
                right.st_mtime_ns, right.st_ctime_ns)


def _stable_regular_file(path: Path) -> tuple[str, os.stat_result, bytes]:
    """Read one regular path by descriptor and reject replacement or mutation."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise ValueError(f"not a regular file: {path}") from None
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot safely open regular file: {path}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(before, opened):
            raise ValueError(f"file changed while opening: {path}")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            chunks.append(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named_after = path.lstat()
    except FileNotFoundError:
        raise ValueError(f"file changed while reading: {path}") from None
    if not _same_identity(opened, after) or not _same_identity(before, named_after):
        raise ValueError(f"file changed while reading: {path}")
    return digest.hexdigest(), after, b"".join(chunks)


def _lstat_entry(path: Path, relative: str, missing_allowed: bool) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_allowed:
            return {"path": relative, "type": "missing"}
        raise ValueError(f"snapshot entry disappeared: {relative}") from None
    if stat.S_ISREG(info.st_mode):
        digest, stable_info, raw_bytes = _stable_regular_file(path)
        if not _same_identity(info, stable_info):
            raise ValueError(f"file changed while collecting snapshot: {relative}")
        return {"path": relative, "type": "file", "mode": _mode(stable_info.st_mode),
                "size": stable_info.st_size, "sha256": digest, "_raw_bytes": raw_bytes}
    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(path).encode("utf-8", "surrogateescape")
            after = path.lstat()
        except OSError as error:
            raise ValueError(f"symlink changed while collecting snapshot: {relative}") from error
        if not _same_identity(info, after):
            raise ValueError(f"symlink changed while collecting snapshot: {relative}")
        return {"path": relative, "type": "symlink", "mode": _mode(info.st_mode),
                "target": target.decode("utf-8", "surrogateescape"),
                "target_sha256": hashlib.sha256(target).hexdigest()}
    if stat.S_ISDIR(info.st_mode):
        return {"path": relative, "type": "directory", "mode": _mode(info.st_mode)}
    raise ValueError(f"unsupported snapshot entry type: {relative}")


def sha256_file(path: Path) -> str:
    return _stable_regular_file(path)[0]


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, check=False,
                            capture_output=True,
                            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
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
        _update_framed(digest, b"bytes")
        _update_framed(digest, entry["_raw_bytes"])


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
                                   cwd=root, check=False, capture_output=True,
                                   env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
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
    for entry in tracked + untracked:
        entry.pop("_raw_bytes", None)
    return state


def assert_output_roots_outside(guarded_roots: list[Path], output_roots: list[Path]) -> None:
    resolved_guarded = [root.resolve(strict=True) for root in guarded_roots]
    if len(set(resolved_guarded)) != len(resolved_guarded):
        raise ValueError("guarded worktree roots must be distinct")
    resolved_outputs: list[Path] = []
    for output in output_roots:
        _reject_symlink_components(output)
        resolved_output = output.resolve(strict=False)
        for guarded in resolved_guarded:
            try:
                resolved_output.relative_to(guarded)
            except ValueError:
                continue
            raise ValueError(f"output root is inside guarded worktree: {output}")

        for guarded in resolved_guarded:
            try:
                guarded.relative_to(resolved_output)
            except ValueError:
                continue
            raise ValueError(f"output root contains guarded worktree: {output}")
        for previous in resolved_outputs:
            try:
                resolved_output.relative_to(previous)
            except ValueError:
                try:
                    previous.relative_to(resolved_output)
                except ValueError:
                    continue
            raise ValueError("output roots must be distinct and non-overlapping")
        resolved_outputs.append(resolved_output)


def _seal_entries(artifact_root: Path) -> list[dict[str, Any]]:
    _reject_symlink_components(artifact_root)
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
            digest, stable_info, _ = _stable_regular_file(child)
            if not _same_identity(info, stable_info):
                raise ValueError(f"artifact entry changed while sealing: {child}")
            entries.append({"path": child.relative_to(artifact_root).as_posix(),
                            "size": stable_info.st_size, "mode": _mode(stable_info.st_mode),
                            "sha256": digest})
    return sorted(entries, key=lambda entry: entry["path"])


def create_tree_seal(artifact_root: Path, seal_path: Path,
                     previous_seal_sha256: str | None, kind: str) -> dict:
    _reject_symlink_components(artifact_root)
    _reject_symlink_components(seal_path)
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
    if not isinstance(kind, str) or not kind:
        raise ValueError("seal kind must be a non-empty string")
    seal = {"schema": "piccard-work7-tree-seal-v1", "kind": kind,
            "artifact_root": str(artifact_root),
            "previous_seal_sha256": previous_seal_sha256,
            "entries": _seal_entries(artifact_root)}
    _atomic_create(seal_path, canonical_json_bytes(seal))
    return seal


def _is_sha256(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _captured_blob(path: Path) -> CapturedBlob:
    digest, info, raw = _stable_regular_file(path)
    return CapturedBlob(raw=raw, sha256=digest, size=info.st_size, mode=_mode(info.st_mode))


def capture_tree_seal(path: Path, expected_previous: str | None, expected_kind: str,
                      expected_root: Path, expected_members: set[str] | None = None) -> CapturedTreeSeal:
    """Capture one canonical seal and every manifest member exactly once.

    Callers consume the returned bytes rather than reopening member paths.  This
    intentionally differs from ``verify_tree_seal``: it validates the same
    on-disk contract while retaining the stable reads that proved it.
    """
    _reject_symlink_components(path)
    _reject_symlink_components(expected_root)
    if path.is_symlink() or not isinstance(expected_kind, str) or not expected_kind:
        raise ValueError("invalid tree seal capture arguments")
    if expected_previous is not None and not _is_sha256(expected_previous):
        raise ValueError("expected previous seal digest must be SHA-256")
    try:
        seal_blob = _captured_blob(path)
        value = json.loads(seal_blob.raw)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("invalid seal JSON") from error
    required = {"schema", "kind", "artifact_root", "previous_seal_sha256", "entries"}
    if (not isinstance(value, dict) or set(value) != required or canonical_json_bytes(value) != seal_blob.raw or
            value.get("schema") != "piccard-work7-tree-seal-v1" or value.get("kind") != expected_kind or
            not isinstance(value.get("artifact_root"), str) or not Path(value["artifact_root"]).is_absolute() or
            value.get("previous_seal_sha256") != expected_previous or not isinstance(value.get("entries"), list)):
        raise ValueError("non-canonical or invalid seal")
    try:
        root = expected_root.resolve(strict=True)
    except OSError as error:
        raise ValueError("expected artifact root is invalid") from error
    if value["artifact_root"] != str(root):
        raise ValueError("foreign artifact root")
    try:
        path.resolve(strict=False).relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("seal path is inside artifact root")

    members: list[tuple[str, CapturedBlob]] = []
    names: set[str] = set()
    for entry in value["entries"]:
        if (not isinstance(entry, dict) or set(entry) != {"path", "size", "mode", "sha256"} or
                not isinstance(entry.get("path"), str) or not entry["path"] or
                not isinstance(entry.get("size"), int) or isinstance(entry["size"], bool) or entry["size"] < 0 or
                not isinstance(entry.get("mode"), str) or not re.fullmatch(r"[0-7]{4}", entry["mode"]) or
                not _is_sha256(entry.get("sha256"))):
            raise ValueError("invalid tree seal entry")
        relative = Path(entry["path"])
        if (relative.is_absolute() or ".." in relative.parts or relative.as_posix() != entry["path"] or
                entry["path"] in names):
            raise ValueError("duplicate, escaping, or noncanonical tree seal member")
        names.add(entry["path"])
        candidate = root / relative
        try:
            # ``O_NOFOLLOW`` protects only the terminal component.  A manifest
            # member must also reject an attacker-controlled symlink directory
            # between the captured artifact root and that terminal file.
            _reject_symlink_components(candidate)
            blob = _captured_blob(candidate)
        except ValueError as error:
            raise ValueError(f"invalid tree seal member: {entry['path']}") from error
        if (blob.size != entry["size"] or blob.mode != entry["mode"] or blob.sha256 != entry["sha256"]):
            raise ValueError(f"tree seal member differs from manifest: {entry['path']}")
        members.append((entry["path"], blob))
    if value["entries"] != sorted(value["entries"], key=lambda entry: entry["path"]):
        raise ValueError("tree seal entries are not canonical")
    if expected_members is not None and names != expected_members:
        raise ValueError("tree seal member manifest is not exact")
    return CapturedTreeSeal(blob=seal_blob, kind=value["kind"], artifact_root=value["artifact_root"],
                            previous_seal_sha256=value["previous_seal_sha256"], members=tuple(members))


def _atomic_create(path: Path, data: bytes) -> None:
    _reject_symlink_components(path)
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
    _reject_symlink_components(seal_path)
    if expected_previous_sha256 is not None and not _is_sha256(expected_previous_sha256):
        raise ValueError("expected previous seal digest must be SHA-256")
    if seal_path.is_symlink():
        raise ValueError(f"seal is a symlink: {seal_path}")
    raw = seal_path.read_bytes()
    try:
        seal = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("invalid seal JSON") from error
    required = {"schema", "kind", "artifact_root", "previous_seal_sha256", "entries"}
    if (not isinstance(seal, dict) or set(seal) != required or
            canonical_json_bytes(seal) != raw or
            seal.get("schema") != "piccard-work7-tree-seal-v1" or
            not isinstance(seal.get("kind"), str) or not seal["kind"] or
            not isinstance(seal.get("artifact_root"), str) or
            not Path(seal["artifact_root"]).is_absolute() or
            (seal.get("previous_seal_sha256") is not None and
             not _is_sha256(seal["previous_seal_sha256"])) or
            not isinstance(seal.get("entries"), list)):
        raise ValueError("non-canonical or invalid seal")
    if expected_previous_sha256 is not None and seal.get("previous_seal_sha256") != expected_previous_sha256:
        raise ValueError("unexpected previous seal digest")
    artifact_root = Path(seal["artifact_root"])
    _reject_symlink_components(artifact_root)
    if seal_path.resolve(strict=False).is_relative_to(artifact_root.resolve(strict=True)):
        raise ValueError("seal path is inside artifact root")
    if seal.get("entries") != _seal_entries(artifact_root):
        raise ValueError("seal entries do not match artifact root")
    return seal
