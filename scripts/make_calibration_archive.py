#!/usr/bin/env python3
"""Build and verify deterministic selected-shard evidence archives."""

import hashlib
import io
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


ARCHIVE_FIELDS = {
    "path", "members", "tar_sha256", "archive_sha256", "zstd_version",
}


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _resolve_zstd(zstd_binary):
    candidate = str(zstd_binary) if zstd_binary is not None else "zstd"
    resolved = shutil.which(candidate)
    if resolved is None:
        raise ValueError("zstd is unavailable")
    version = subprocess.run(
        [resolved, "--version"],
        text=True,
        capture_output=True,
    )
    if version.returncode != 0:
        raise ValueError("zstd --version failed")
    lines = version.stdout.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ValueError("zstd version output must be exactly one line")
    return resolved, lines[0]


def _validate_members(source_root, members):
    if (
        not isinstance(members, list)
        or not all(isinstance(member, str) for member in members)
        or len(members) != len(set(members))
    ):
        raise ValueError("archive members must be a unique string array")
    root_real = source_root.resolve(strict=True)
    validated = []
    for member in sorted(members):
        path = PurePosixPath(member)
        if (
            not member
            or member == "manifest.json"
            or path.is_absolute()
            or ".." in path.parts
            or member != path.as_posix()
        ):
            raise ValueError("unsafe archive member: " + member)
        source = source_root.joinpath(*path.parts)
        try:
            info = source.lstat()
        except FileNotFoundError as error:
            raise ValueError("missing archive member: " + member) from error
        if source.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ValueError("archive member is not a regular file: " + member)
        try:
            source.resolve(strict=True).relative_to(root_real)
        except ValueError as error:
            raise ValueError("archive member escapes source root") from error
        validated.append((member, source))
    return validated


def _tar_bytes(source_root, members):
    validated = _validate_members(source_root, members)
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        for member, source in validated:
            data = source.read_bytes()
            info = tarfile.TarInfo(member)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue(), [member for member, _ in validated]


def build_archive(
    source_root,
    members,
    destination,
    *,
    zstd_binary=None,
):
    """Build one normalized tar.zst and return its exhaustive archive object."""
    source_root = Path(source_root)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("archive destination must not exist")
    zstd, version = _resolve_zstd(zstd_binary)
    tar_bytes, ordered_members = _tar_bytes(source_root, members)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".piccard-archive-v1-", dir=destination.parent
    ) as temporary:
        temporary_root = Path(temporary)
        tar_path = temporary_root / "selected-shards.tar"
        archive_path = temporary_root / "selected-shards.tar.zst"
        with tar_path.open("wb") as output:
            output.write(tar_bytes)
            output.flush()
            os.fsync(output.fileno())
        compressed = subprocess.run(
            [
                zstd,
                "--threads=1",
                "-19",
                "--no-progress",
                str(tar_path),
                "-o",
                str(archive_path),
            ],
            text=True,
            capture_output=True,
        )
        if compressed.returncode != 0 or not archive_path.is_file():
            raise ValueError(
                "zstd compression failed: " + compressed.stderr.strip())
        archive_bytes = archive_path.read_bytes()
        with archive_path.open("rb") as source:
            os.fsync(source.fileno())
        os.replace(archive_path, destination)
    return {
        "path": "selected-shards.tar.zst",
        "members": ordered_members,
        "tar_sha256": _sha256(tar_bytes),
        "archive_sha256": _sha256(archive_bytes),
        "zstd_version": version,
    }


def verify_archive(archive_path, expected, *, zstd_binary=None):
    """Verify hashes, zstd identity, normalized metadata, and membership."""
    if not isinstance(expected, dict) or set(expected) != ARCHIVE_FIELDS:
        raise ValueError("archive verification object schema mismatch")
    if expected["path"] != "selected-shards.tar.zst":
        raise ValueError("archive verification path mismatch")
    zstd, version = _resolve_zstd(zstd_binary)
    if expected["zstd_version"] != version:
        raise ValueError("zstd version changed")
    archive_path = Path(archive_path)
    info = archive_path.lstat()
    if archive_path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError("archive output is not a regular file")
    archive_bytes = archive_path.read_bytes()
    if _sha256(archive_bytes) != expected["archive_sha256"]:
        raise ValueError("archive SHA mismatch")
    decompressed = subprocess.run(
        [zstd, "--decompress", "--stdout", str(archive_path)],
        capture_output=True,
    )
    if decompressed.returncode != 0:
        raise ValueError("zstd decompression failed")
    tar_bytes = decompressed.stdout
    if _sha256(tar_bytes) != expected["tar_sha256"]:
        raise ValueError("tar SHA mismatch")
    actual_members = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            if (
                not member.isfile()
                or member.uid != 0
                or member.gid != 0
                or member.uname != ""
                or member.gname != ""
                or member.mtime != 0
                or member.mode != 0o644
            ):
                raise ValueError("archive metadata is not normalized")
            actual_members.append(member.name)
    if (
        actual_members != sorted(actual_members)
        or actual_members != expected["members"]
        or len(actual_members) != len(set(actual_members))
    ):
        raise ValueError("archive membership mismatch")
    return expected
