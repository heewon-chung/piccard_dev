#!/usr/bin/env python3
"""Create and verify the non-replacing byte seal for a revision root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from revision_benchmark_common import (  # noqa: E402
    RevisionContractError,
    canonical_json,
    file_inventory,
    sha256_bytes,
    sha256_file,
    write_json,
)


SEAL_SCHEMA = "piccard-revision-seal-v1"
SEAL_NAME = "seal.json"
CHECKSUM_NAME = "seal.json.sha256"


class SealError(RevisionContractError):
    pass


def _root(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise SealError("seal root must be an absolute non-symlink directory")
    return path.resolve()


def _identity(root: Path) -> dict[str, Any]:
    info = root.stat()
    return {"path": str(root), "st_dev": info.st_dev, "st_ino": info.st_ino}


def inventory(root: Path) -> list[dict[str, Any]]:
    return file_inventory(root, exclude={SEAL_NAME, CHECKSUM_NAME})


def _inventory_digest(entries: list[dict[str, Any]]) -> str:
    return sha256_bytes(canonical_json(entries))


def _exclusive_bytes(path: Path, payload: bytes, root_identity: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise SealError(f"refusing to overwrite existing {path.name}")
    if path.parent != Path(root_identity["path"]):
        raise SealError("seal destination escaped result root")
    temporary = path.parent / f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SealError("short seal write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if _identity(path.parent) != root_identity:
            raise SealError("result root identity changed before seal install")
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise SealError(f"refusing to overwrite existing {path.name}") from exc
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        temporary.unlink()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def create_seal(root: Path) -> dict[str, Any]:
    root = _root(root)
    if (root / SEAL_NAME).exists() or (root / CHECKSUM_NAME).exists():
        raise SealError("seal already exists; result roots cannot be repaired or resealed")
    run_path = root / "run.json"
    verification_path = root / "verification" / "receipt.json"
    if not run_path.is_file() or not verification_path.is_file():
        raise SealError("run and verification receipts are required before sealing")
    try:
        run = json.loads(run_path.read_text(encoding="utf-8"))
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError(f"cannot read pre-seal receipts: {exc}") from exc
    if not isinstance(run, dict) or run.get("state") != "COMPLETED":
        raise SealError("run is not complete")
    if not isinstance(verification, dict) or verification.get("verdict") != "PASS":
        raise SealError("verification receipt is not PASS")
    if run.get("mode") == "toy":
        readiness_status = "READINESS_ONLY"
        performance_status = "PAPER_PERFORMANCE_PENDING"
    elif run.get("mode") == "paper":
        readiness_status = "PAPER_RUN_COMPLETE"
        performance_status = "PAPER_PERFORMANCE_RECORDED"
    else:
        readiness_status = "READINESS_ONLY"
        performance_status = "PAPER_PERFORMANCE_PENDING"
    identity = _identity(root)
    entries = inventory(root)
    seal_payload: dict[str, Any] = {
        "schema": SEAL_SCHEMA,
        "version": 1,
        "results_root": str(root),
        "root_identity": identity,
        "run_sha256": sha256_file(run_path),
        "verification_sha256": sha256_file(verification_path),
        "matrix_sha256": run.get("matrix_sha256"),
        "cell_count": run.get("cell_count"),
        "readiness_status": readiness_status,
        "performance_status": performance_status,
        "inventory": entries,
        "inventory_sha256": _inventory_digest(entries),
        "excluded_from_inventory": [SEAL_NAME, CHECKSUM_NAME],
    }
    # The seal checksum is the hash of the exact installed seal bytes.  It is
    # kept as a second exclusive file and is intentionally excluded from the
    # inventory to avoid a cyclic digest.
    payload = canonical_json(seal_payload)
    _exclusive_bytes(root / SEAL_NAME, payload, identity)
    digest_payload = f"{hashlib.sha256(payload).hexdigest()}  {SEAL_NAME}\n".encode("ascii")
    try:
        _exclusive_bytes(root / CHECKSUM_NAME, digest_payload, identity)
    except Exception:
        # A checksum failure leaves the first seal in place by design.  The
        # root is terminal and must be retained for diagnosis.
        raise
    return seal_payload


def verify_post_seal(root: Path) -> dict[str, Any]:
    root = _root(root)
    seal_path = root / SEAL_NAME
    checksum_path = root / CHECKSUM_NAME
    if not seal_path.is_file() or not checksum_path.is_file():
        raise SealError("seal and checksum are required")
    seal_bytes = seal_path.read_bytes()
    try:
        seal = json.loads(seal_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError("seal is not valid JSON") from exc
    if seal.get("schema") != SEAL_SCHEMA:
        raise SealError("seal schema mismatch")
    expected_checksum = f"{hashlib.sha256(seal_bytes).hexdigest()}  {SEAL_NAME}\n"
    if checksum_path.read_text(encoding="ascii") != expected_checksum:
        raise SealError("seal checksum mismatch")
    entries = inventory(root)
    if entries != seal.get("inventory") or _inventory_digest(entries) != seal.get("inventory_sha256"):
        raise SealError("sealed inventory changed")
    run_path = root / "run.json"
    verification_path = root / "verification" / "receipt.json"
    if sha256_file(run_path) != seal.get("run_sha256") or \
            sha256_file(verification_path) != seal.get("verification_sha256"):
        raise SealError("sealed receipt changed")
    return seal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--verify-post-seal", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        root = Path(args.root)
        if args.verify_post_seal:
            seal = verify_post_seal(root)
            print(f"revision seal: PASS ({seal['cell_count']} cells)")
        else:
            seal = create_seal(root)
            print(f"revision seal: CREATED ({seal['cell_count']} cells)")
        return 0
    except (SealError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"seal_revision_benchmarks: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
