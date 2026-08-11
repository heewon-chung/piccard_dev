#!/usr/bin/env python3
"""Strict manifest validation and atomic writer core for real-dataset
preprocessing (Work 5).

This module is stdlib-only, performs no network access, and never touches
`datasets/data/` on its own initiative -- it only reads/writes paths its
caller passes in. It implements:

  * the exact two-column `key<TAB>value` manifest grammar shared by source
    and processed manifests;
  * strict source-manifest validation (placeholder/path/checksum rejection);
  * the deterministic feature-hashing and bucketing primitives used by every
    dataset's trigram/shingle pipeline;
  * shared text normalization and 17-significant-digit float formatting;
  * per-record/per-pair set-size summary statistics (min/median/p95/max);
  * an atomic, checksum-verified writer for `processed/<variant>/` outputs.

Dataset-specific subcommands (`dblp-acm`, `enron`) are added in later phases;
this module's CLI only recognizes them and reports "not implemented" so that
those phases' own tests stay RED until implemented.
"""

import argparse
import csv
import hashlib
import heapq
import io
import math
import os
import re
import shutil
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path


class ManifestError(ValueError):
    """Raised for every strict-grammar or provenance validation failure."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceManifestInput:
    role: str
    relative_path: str
    resolved_path: Path
    sha256: str


@dataclass(frozen=True)
class SourceManifest:
    manifest_path: Path
    dataset: str
    schema_version: str
    dataset_version: str
    source_url: str
    citation: str
    license_or_terms_url: str
    acquisition_note: str
    parsing_schema: str
    preprocessing_profile: str
    inputs: tuple


@dataclass(frozen=True)
class RecordRow:
    record_id: str
    raw_features: tuple
    bucketed_features: tuple


@dataclass(frozen=True)
class PairRow:
    pair_id: str
    record_a: str
    record_b: str
    pair_kind: str
    label: int


@dataclass(frozen=True)
class SetSizeStats:
    min: int
    median: float
    p95: int
    max: int


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MANIFEST_HEADER = "key\tvalue"

_SOURCE_SCHEMA_VERSION = "piccard-real-source-v1"

_PLACEHOLDER_VALUES = frozenset({"todo", "tbd", "unknown", "replace-me"})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INDEXED_KEY_RE = re.compile(r"^input\.(0|[1-9][0-9]*)\.(role|path|sha256)$")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")

_FEATURE_HASH_DOMAIN = b"piccard-real-feature-v1"
_ENRON_TREE_DOMAIN = b"piccard-enron-tree-v1"

# dataset -> ((role_name, role_kind), ...); role_kind is "file" or "directory".
_DATASET_ROLE_TABLES = {
    "dblp_acm": (
        ("dblp_records", "file"),
        ("acm_records", "file"),
        ("dblp_acm_mapping", "file"),
    ),
    "enron": (
        ("maildir_root", "directory"),
    ),
}

# dataset -> (parsing_schema, preprocessing_profile)
_DATASET_SCHEMA_TOKENS = {
    "dblp_acm": ("dblp-acm-csv-v1", "dblp-acm-trigram-v1"),
    "enron": ("enron-maildir-rfc5322-v1", "enron-shingle5-v1"),
}

_REQUIRED_SCALAR_KEYS = (
    "schema_version", "dataset", "dataset_version", "source_url", "citation",
    "license_or_terms_url", "acquisition_note", "parsing_schema",
    "preprocessing_profile",
)

_PLACEHOLDER_CHECKED_KEYS = (
    "dataset_version", "source_url", "citation", "license_or_terms_url",
    "acquisition_note",
)

# The exact piccard-real-processed-v1 dataset.manifest.tsv key sequence
# (normative plan "Exact shared file grammar" / Phase 1 GREEN), shared
# prefix plus the dataset-specific drop-key tail.
_PROCESSED_MANIFEST_KEY_PREFIX = (
    "schema_version", "dataset", "variant", "preprocessing_version",
    "universe_size", "seed",
    "source_manifest_file", "source_manifest_sha256",
    "records_file", "records_sha256", "record_count",
    "pairs_file", "pairs_sha256", "pair_count",
    "raw_set_size_min", "raw_set_size_median", "raw_set_size_p95", "raw_set_size_max",
    "bucketed_set_size_min", "bucketed_set_size_median",
    "bucketed_set_size_p95", "bucketed_set_size_max",
    "original_positive_count", "retained_positive_count", "requested_pair_count",
    "max_documents", "min_related_pairs",
)

_PROCESSED_MANIFEST_DROP_KEYS = {
    "dblp_acm": ("dropped.empty_features_dblp", "dropped.empty_features_acm"),
    "enron": ("dropped.charset_or_mime", "dropped.empty_body", "dropped.short_body",
              "dropped.duplicate_message_id"),
}


def _processed_manifest_key_order(dataset) -> tuple:
    if dataset not in _PROCESSED_MANIFEST_DROP_KEYS:
        raise ManifestError(
            f"unknown dataset for processed manifest key order: {dataset!r}")
    return _PROCESSED_MANIFEST_KEY_PREFIX + _PROCESSED_MANIFEST_DROP_KEYS[dataset]


# ---------------------------------------------------------------------------
# sha256_file / parse_two_column_tsv
# ---------------------------------------------------------------------------

def sha256_file(path) -> str:
    """Return the lowercase hex SHA-256 of the bytes at `path`."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_two_column_tsv(path):
    """Parse a strict `key<TAB>value` TSV: UTF-8 without BOM, LF-terminated,
    exact `key\\tvalue` header, no blank lines, exactly one tab per row."""
    path = Path(path)
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ManifestError(f"BOM not allowed: {path}")
    if b"\r" in raw:
        raise ManifestError(f"CR not allowed (file must be LF-terminated): {path}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"invalid UTF-8 in {path}") from exc
    if text == "":
        raise ManifestError(f"empty file: {path}")
    if not text.endswith("\n"):
        raise ManifestError(f"file must be LF-terminated: {path}")
    lines = text[:-1].split("\n")
    if not lines or lines[0] != _MANIFEST_HEADER:
        raise ManifestError(f"missing or malformed header in {path}")
    pairs = []
    for line_number, line in enumerate(lines[1:], start=2):
        if line == "":
            raise ManifestError(f"blank line not allowed at line {line_number} in {path}")
        if line.count("\t") != 1:
            raise ManifestError(
                f"expected exactly one tab at line {line_number} in {path}")
        key, value = line.split("\t")
        pairs.append((key, value))
    return pairs


def _serialize_key_value_pairs(pairs) -> bytes:
    seen = set()
    lines = [_MANIFEST_HEADER]
    for key, value in pairs:
        if key in seen:
            raise ManifestError(f"duplicate manifest key: {key!r}")
        seen.add(key)
        _validate_tsv_field(key)
        _validate_tsv_field(value)
        lines.append(f"{key}\t{value}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _validate_tsv_field(value: str) -> None:
    if "\t" in value or "\n" in value or "\r" in value:
        raise ManifestError(f"field contains forbidden character: {value!r}")


# ---------------------------------------------------------------------------
# Path safety helpers
# ---------------------------------------------------------------------------

def _reject_placeholder(key: str, value: str) -> None:
    if value.strip() == "":
        raise ManifestError(f"empty value for {key!r}")
    if value.strip().casefold() in _PLACEHOLDER_VALUES:
        raise ManifestError(f"placeholder value not allowed for {key!r}: {value!r}")


def _resolve_manifest_relative_path(base_dir: Path, rel: str) -> Path:
    if not rel:
        raise ManifestError("empty input path")
    if rel.startswith("/"):
        raise ManifestError(f"absolute path not allowed: {rel!r}")
    if "\\" in rel:
        raise ManifestError(f"invalid path separator: {rel!r}")
    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ManifestError(f"invalid path component: {rel!r}")
    # Reject a symlink at ANY path component, not just the final leaf: an
    # intermediate symlinked directory can lead outside the manifest
    # directory just as easily as a symlinked leaf file can.
    current = base_dir
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ManifestError(f"symlink input path not allowed: {rel!r}")
    candidate = current
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ManifestError(f"input path not found: {rel!r}") from exc
    try:
        resolved.relative_to(base_dir)
    except ValueError as exc:
        raise ManifestError(f"input path escapes manifest directory: {rel!r}") from exc
    return resolved


def _raise_walk_error(error: OSError) -> None:
    # os.walk's default onerror=None silently skips a subtree it cannot
    # list (e.g. a permission-denied directory), which would let the tree
    # digest quietly omit files. Abort instead.
    raise ManifestError(f"cannot list maildir_root subtree: {error}") from error


def _directory_tree_digest(root: Path) -> str:
    """Canonical source-tree digest for a directory-role manifest input
    (e.g. Enron's `maildir_root`):

    SHA256("piccard-enron-tree-v1" || 0x00 ||
      for each regular file, sorted by ascending UTF-8 path bytes:
        BE32(len(path_utf8)) || path_utf8 || BE64(file_size) || raw_sha256)

    Symlinks and non-regular files abort rather than being skipped/dropped.
    Paths must already be Unicode NFC (normative: "Canonical paths must ...
    be Unicode NFC already"); a subtree os.walk cannot list, or a file that
    cannot be read, also aborts rather than being silently omitted.
    """
    entries = []
    for dirpath, dirnames, filenames in os.walk(
            root, onerror=_raise_walk_error, followlinks=False):
        current_dir = Path(dirpath)
        for name in dirnames:
            if (current_dir / name).is_symlink():
                raise ManifestError(
                    f"symlink not allowed under maildir_root: {current_dir / name}")
        for name in filenames:
            full_path = current_dir / name
            if full_path.is_symlink():
                raise ManifestError(
                    f"symlink not allowed under maildir_root: {full_path}")
            if not full_path.is_file():
                raise ManifestError(
                    f"non-regular file not allowed under maildir_root: {full_path}")
            rel = full_path.relative_to(root).as_posix()
            if unicodedata.normalize("NFC", rel) != rel:
                raise ManifestError(
                    f"maildir_root path is not Unicode NFC: {rel!r}")
            try:
                file_size = full_path.stat().st_size
                file_digest = bytes.fromhex(sha256_file(full_path))
            except OSError as exc:
                raise ManifestError(
                    f"cannot read file under maildir_root: {full_path}: {exc}") from exc
            entries.append((rel.encode("utf-8"), file_size, file_digest))
    entries.sort(key=lambda item: item[0])
    hasher = hashlib.sha256()
    hasher.update(_ENRON_TREE_DOMAIN)
    hasher.update(b"\x00")
    for path_bytes, size, digest in entries:
        hasher.update(len(path_bytes).to_bytes(4, "big"))
        hasher.update(path_bytes)
        hasher.update(size.to_bytes(8, "big"))
        hasher.update(digest)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# validate_source_manifest
# ---------------------------------------------------------------------------

def validate_source_manifest(path, dataset: str) -> SourceManifest:
    if dataset not in _DATASET_ROLE_TABLES:
        raise ManifestError(f"unknown dataset: {dataset!r}")
    manifest_path = Path(path)
    try:
        pairs = parse_two_column_tsv(manifest_path)
    except OSError as exc:
        raise ManifestError(f"cannot read source manifest: {manifest_path}") from exc

    values = {}
    for key, value in pairs:
        if key in values:
            raise ManifestError(f"duplicate manifest key: {key!r}")
        values[key] = value

    role_table = _DATASET_ROLE_TABLES[dataset]

    for key in values:
        if key in _REQUIRED_SCALAR_KEYS:
            continue
        if _INDEXED_KEY_RE.match(key) is None:
            raise ManifestError(f"unknown manifest key: {key!r}")

    for key in _REQUIRED_SCALAR_KEYS:
        if key not in values:
            raise ManifestError(f"missing required manifest key: {key!r}")

    schema_version = values["schema_version"]
    if schema_version != _SOURCE_SCHEMA_VERSION:
        raise ManifestError(f"unexpected schema_version: {schema_version!r}")

    manifest_dataset = values["dataset"]
    if manifest_dataset != dataset:
        raise ManifestError(
            f"manifest dataset {manifest_dataset!r} does not match requested "
            f"{dataset!r}")

    expected_parsing_schema, expected_profile = _DATASET_SCHEMA_TOKENS[dataset]
    if values["parsing_schema"] != expected_parsing_schema:
        raise ManifestError(f"unexpected parsing_schema: {values['parsing_schema']!r}")
    if values["preprocessing_profile"] != expected_profile:
        raise ManifestError(
            f"unexpected preprocessing_profile: {values['preprocessing_profile']!r}")

    for key in _PLACEHOLDER_CHECKED_KEYS:
        _reject_placeholder(key, values[key])

    max_seen_index = -1
    for key in values:
        match = _INDEXED_KEY_RE.match(key)
        if match is not None:
            max_seen_index = max(max_seen_index, int(match.group(1)))
    if max_seen_index >= len(role_table):
        raise ManifestError(
            f"unexpected extra input index {max_seen_index} for dataset {dataset!r}")

    manifest_dir = manifest_path.resolve(strict=True).parent
    inputs = []
    for index, (role_name, role_kind) in enumerate(role_table):
        role_key = f"input.{index}.role"
        path_key = f"input.{index}.path"
        sha_key = f"input.{index}.sha256"
        for key in (role_key, path_key, sha_key):
            if key not in values:
                raise ManifestError(f"missing required manifest key: {key!r}")
        declared_role = values[role_key]
        if declared_role != role_name:
            raise ManifestError(
                f"unexpected role at index {index}: {declared_role!r}")
        declared_path = values[path_key]
        declared_sha = values[sha_key]
        _reject_placeholder(sha_key, declared_sha)
        if not _SHA256_RE.match(declared_sha):
            raise ManifestError(f"malformed sha256 for {sha_key}: {declared_sha!r}")

        resolved = _resolve_manifest_relative_path(manifest_dir, declared_path)
        if role_kind == "file":
            if not resolved.is_file():
                raise ManifestError(
                    f"input path is not a regular file: {declared_path!r}")
            try:
                actual_sha = sha256_file(resolved)
            except OSError as exc:
                raise ManifestError(
                    f"unreadable input path: {declared_path!r}") from exc
        else:
            if not resolved.is_dir():
                raise ManifestError(
                    f"input path is not a directory: {declared_path!r}")
            actual_sha = _directory_tree_digest(resolved)

        if actual_sha != declared_sha:
            raise ManifestError(
                f"checksum mismatch for {sha_key}: declared {declared_sha!r}, "
                f"actual {actual_sha!r}")

        inputs.append(SourceManifestInput(
            role=role_name, relative_path=declared_path,
            resolved_path=resolved, sha256=declared_sha))

    return SourceManifest(
        manifest_path=manifest_path,
        dataset=manifest_dataset,
        schema_version=schema_version,
        dataset_version=values["dataset_version"],
        source_url=values["source_url"],
        citation=values["citation"],
        license_or_terms_url=values["license_or_terms_url"],
        acquisition_note=values["acquisition_note"],
        parsing_schema=values["parsing_schema"],
        preprocessing_profile=values["preprocessing_profile"],
        inputs=tuple(inputs),
    )


# ---------------------------------------------------------------------------
# Feature hashing / bucketing / text normalization / float formatting
# ---------------------------------------------------------------------------

def canonical_feature_hash(feature: str) -> int:
    """first-8-bytes-BE(SHA256("piccard-real-feature-v1" || 0x00 || feature))"""
    digest = hashlib.sha256(
        _FEATURE_HASH_DOMAIN + b"\x00" + feature.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def bucket_features(features, universe: int):
    """feature % universe_size, then sort + dedup."""
    if universe <= 0:
        raise ManifestError(f"universe must be positive: {universe!r}")
    return sorted({f % universe for f in features})


def normalize_text(s: str) -> str:
    """NFKC -> casefold -> non-[a-z0-9] => ' ' -> collapse runs -> strip."""
    s = unicodedata.normalize("NFKC", s)
    s = s.casefold()
    s = _NON_ALNUM_RE.sub(" ", s)
    return s.strip()


def format_float(x: float) -> str:
    """Finite, C-locale, 17 significant digits, -0 normalized to 0."""
    x = float(x)
    if not math.isfinite(x):
        raise ManifestError(f"non-finite float cannot be formatted: {x!r}")
    if x == 0.0:
        x = 0.0
    return "%.17g" % x


def summarize_set_sizes(sizes) -> SetSizeStats:
    """min/median/p95/max over integer set sizes.

    median: center value for odd n, arithmetic mean of the two center values
    for even n. p95: nearest-rank sorted[ceil(0.95*n)-1]. Empty input aborts.
    """
    ordered = sorted(sizes)
    n = len(ordered)
    if n == 0:
        raise ManifestError("summarize_set_sizes: empty input")
    minimum = ordered[0]
    maximum = ordered[-1]
    mid = n // 2
    if n % 2 == 1:
        median = float(ordered[mid])
    else:
        median = (ordered[mid - 1] + ordered[mid]) / 2.0
    p95_index = math.ceil(0.95 * n) - 1
    p95 = ordered[p95_index]
    return SetSizeStats(min=minimum, median=median, p95=p95, max=maximum)


# ---------------------------------------------------------------------------
# Canonical records.tsv / pairs.tsv serialization
# ---------------------------------------------------------------------------

def _validate_feature_list(features) -> None:
    previous = None
    for value in features:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ManifestError(f"invalid feature value: {value!r}")
        if previous is not None and value <= previous:
            raise ManifestError("feature list is not strictly increasing")
        previous = value


def _canonicalize_records(records) -> bytes:
    header = (b"record_id\traw_feature_count\traw_features_csv\t"
              b"bucketed_feature_count\tbucketed_features_csv\n")
    rows = []
    for record in records:
        _validate_tsv_field(record.record_id)
        _validate_feature_list(record.raw_features)
        _validate_feature_list(record.bucketed_features)
        row_str = "\t".join((
            record.record_id,
            str(len(record.raw_features)),
            ",".join(str(v) for v in record.raw_features),
            str(len(record.bucketed_features)),
            ",".join(str(v) for v in record.bucketed_features),
        ))
        row_bytes = row_str.encode("utf-8") + b"\n"
        rows.append((record.record_id.encode("utf-8"), row_bytes))
    rows.sort(key=lambda item: item)
    body = bytearray(header)
    previous_id = None
    for record_id_bytes, row_bytes in rows:
        if record_id_bytes == previous_id:
            raise ManifestError(f"duplicate record id: {record_id_bytes!r}")
        previous_id = record_id_bytes
        body.extend(row_bytes)
    return bytes(body)


def _canonicalize_pairs(pairs) -> bytes:
    header = b"pair_id\trecord_a\trecord_b\tpair_kind\tlabel\n"
    rows = []
    for pair in pairs:
        for field in (pair.pair_id, pair.record_a, pair.record_b, pair.pair_kind):
            _validate_tsv_field(field)
        row_str = "\t".join((
            pair.pair_id, pair.record_a, pair.record_b, pair.pair_kind,
            str(pair.label),
        ))
        sort_key = (
            pair.pair_id.encode("utf-8"),
            pair.record_a.encode("utf-8"),
            pair.record_b.encode("utf-8"),
            str(pair.label).encode("utf-8"),
        )
        rows.append((sort_key, row_str.encode("utf-8") + b"\n"))
    rows.sort(key=lambda item: item[0])
    body = bytearray(header)
    previous_id = None
    for sort_key, row_bytes in rows:
        pair_id_bytes = sort_key[0]
        if pair_id_bytes == previous_id:
            raise ManifestError(f"duplicate pair id: {pair_id_bytes!r}")
        previous_id = pair_id_bytes
        body.extend(row_bytes)
    return bytes(body)


# ---------------------------------------------------------------------------
# Atomic writer
# ---------------------------------------------------------------------------

def _write_file_with_fsync(path: Path, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    try:
        dir_fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


# Manifest keys write_processed_output computes itself and cross-checks
# against the caller-supplied manifest_pairs (checksum verify).
def _expected_auto_fields(records, pairs, records_bytes, pairs_bytes, source_bytes):
    return {
        "records_file": "records.tsv",
        "records_sha256": hashlib.sha256(records_bytes).hexdigest(),
        "record_count": str(len(records)),
        "pairs_file": "pairs.tsv",
        "pairs_sha256": hashlib.sha256(pairs_bytes).hexdigest(),
        "pair_count": str(len(pairs)),
        "source_manifest_file": "source.manifest.tsv",
        "source_manifest_sha256": hashlib.sha256(source_bytes).hexdigest(),
    }


def write_processed_output(output_dir, records, pairs, manifest_pairs,
                            source_manifest_path, *, overwrite: bool = False) -> None:
    """Canonically serialize records/pairs, copy the source manifest, verify
    that manifest_pairs' checksum/count fields match what was produced, then
    publish atomically via a sibling temp directory + rename.

    `manifest_pairs` must be the caller's fully ordered
    `dataset.manifest.tsv` key/value sequence, including correct values for
    `records_file`, `records_sha256`, `record_count`, `pairs_file`,
    `pairs_sha256`, `pair_count`, `source_manifest_file`, and
    `source_manifest_sha256` -- this function verifies those eight fields
    rather than computing/inserting them, so a caller bug in any of them is
    caught before anything is published.
    """
    output_dir = Path(output_dir)
    source_manifest_path = Path(source_manifest_path)
    if output_dir.exists() and not overwrite:
        raise ManifestError(f"output directory already exists: {output_dir}")

    records = list(records)
    pairs = list(pairs)
    manifest_pairs = list(manifest_pairs)

    records_bytes = _canonicalize_records(records)
    pairs_bytes = _canonicalize_pairs(pairs)
    try:
        source_bytes = source_manifest_path.read_bytes()
    except OSError as exc:
        raise ManifestError(
            f"cannot read source manifest to copy: {source_manifest_path}") from exc

    manifest_lookup = {}
    for key, value in manifest_pairs:
        if key in manifest_lookup:
            raise ManifestError(f"duplicate manifest key: {key!r}")
        manifest_lookup[key] = value

    if "dataset" not in manifest_lookup:
        raise ManifestError("missing manifest key: 'dataset'")
    expected_key_order = _processed_manifest_key_order(manifest_lookup["dataset"])
    actual_key_order = tuple(key for key, _ in manifest_pairs)
    if actual_key_order != expected_key_order:
        raise ManifestError(
            "dataset.manifest.tsv key sequence does not match the exact "
            f"piccard-real-processed-v1 order for dataset "
            f"{manifest_lookup['dataset']!r}: expected {expected_key_order!r}, "
            f"got {actual_key_order!r}")

    expected = _expected_auto_fields(records, pairs, records_bytes, pairs_bytes,
                                      source_bytes)
    for key, expected_value in expected.items():
        if key not in manifest_lookup:
            raise ManifestError(f"missing manifest key: {key!r}")
        if manifest_lookup[key] != expected_value:
            raise ManifestError(
                f"manifest key {key!r} mismatch: declared "
                f"{manifest_lookup[key]!r}, actual {expected_value!r}")

    manifest_bytes = _serialize_key_value_pairs(manifest_pairs)

    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=parent))
    try:
        _write_file_with_fsync(tmp_dir / "records.tsv", records_bytes)
        _write_file_with_fsync(tmp_dir / "pairs.tsv", pairs_bytes)
        _write_file_with_fsync(tmp_dir / "source.manifest.tsv", source_bytes)
        _write_file_with_fsync(tmp_dir / "dataset.manifest.tsv", manifest_bytes)
        for name, data in (
            ("records.tsv", records_bytes),
            ("pairs.tsv", pairs_bytes),
            ("source.manifest.tsv", source_bytes),
            ("dataset.manifest.tsv", manifest_bytes),
        ):
            actual_sha = sha256_file(tmp_dir / name)
            expected_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != expected_sha:
                raise ManifestError(
                    f"post-write checksum verification failed for {name}")
        _fsync_dir(tmp_dir)
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    if output_dir.exists():
        backup_dir = output_dir.with_name(f".{output_dir.name}.old-{os.getpid()}")
        os.rename(output_dir, backup_dir)
        try:
            os.rename(tmp_dir, output_dir)
        except BaseException:
            # Restore the previous contents so a failed publish leaves the
            # old output directory intact, not a bare backup name; either
            # way, the staging temp dir must never be left behind.
            try:
                os.rename(backup_dir, output_dir)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        shutil.rmtree(backup_dir, ignore_errors=True)
    else:
        try:
            os.rename(tmp_dir, output_dir)
        except BaseException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise


# ---------------------------------------------------------------------------
# DBLP-ACM: CSV parsing, normalization/trigram features, ground-truth pairs,
# deterministic negative sampling (Work 5 Phase 2)
# ---------------------------------------------------------------------------

_DBLP_ACM_RECORD_CSV_HEADER = ("id", "title", "authors", "venue", "year")
_DBLP_ACM_MAPPING_CSV_HEADER = ("idDBLP", "idACM")
_DBLP_ACM_FEATURE_FIELD_ORDER = ("title", "authors", "venue", "year")
_DBLP_NEGATIVE_HASH_DOMAIN = b"piccard-dblp-negative-v1"
# This checked-out directory is a deliberately quarantined prior run
# (pair_count=4448, seed=7).  It is not an input cache and must never become
# an implicit source for the Work #5 source-bound path.  Keep the guard here,
# at the lowest writer/parser layer, so callers cannot bypass it by invoking
# this module directly instead of its CLI.
_LEGACY_DBLP_ACM_PROCESSED_DIR = (
    Path(__file__).resolve().parents[1] / "datasets" / "data" / "processed"
    / "dblp_acm_u65536"
)


def _reject_legacy_dblp_acm_processed_path(path, label: str) -> None:
    """Reject the quarantined old DBLP-ACM processed tree as input or output."""
    candidate = Path(path).resolve(strict=False)
    legacy = _LEGACY_DBLP_ACM_PROCESSED_DIR.resolve(strict=False)
    try:
        candidate.relative_to(legacy)
    except ValueError:
        return
    raise ManifestError(
        f"{label} resolves within the forbidden prior-run DBLP-ACM directory: "
        f"{candidate}")


def _strip_utf8_bom(raw: bytes) -> bytes:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:]
    return raw


def _read_strict_csv_rows(path: Path, expected_header: tuple) -> list:
    """Strict RFC4180 CSV decode: UTF-8 (optional leading BOM stripped),
    exact header, and exactly len(expected_header) columns per data row."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read CSV: {path}") from exc
    raw = _strip_utf8_bom(raw)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"invalid UTF-8 in CSV: {path}") from exc
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter=",", quotechar='"',
                                strict=True))
    except csv.Error as exc:
        raise ManifestError(f"malformed CSV: {path}: {exc}") from exc
    if not rows:
        raise ManifestError(f"empty CSV (missing header): {path}")
    header = tuple(rows[0])
    if header != expected_header:
        raise ManifestError(
            f"unexpected CSV header in {path}: expected {expected_header!r}, "
            f"got {header!r}")
    data_rows = []
    for line_number, row in enumerate(rows[1:], start=2):
        if len(row) != len(expected_header):
            raise ManifestError(
                f"malformed CSV row at line {line_number} in {path}: {row!r}")
        data_rows.append(tuple(row))
    return data_rows


def _extract_trigrams(value: str) -> list:
    """Overlapping three-code-point substrings, no padding for len < 3."""
    if len(value) < 3:
        return []
    return [value[i:i + 3] for i in range(len(value) - 2)]


def _record_features(fields: dict) -> list:
    """Sorted/unique canonical_feature_hash ints over field_name=trigram for
    every (title, authors, venue, year) field, in that fixed order. Empty
    normalized values never create features."""
    hashes = set()
    for field in _DBLP_ACM_FEATURE_FIELD_ORDER:
        normalized = normalize_text(fields[field])
        if normalized == "":
            continue
        for trigram in _extract_trigrams(normalized):
            hashes.add(canonical_feature_hash(f"{field}={trigram}"))
    return sorted(hashes)


def _parse_dblp_acm_records_csv(path: Path, prefix: str) -> dict:
    """Parse a dblp_records/acm_records CSV into an ordered
    {generated_record_id: {title, authors, venue, year}} map, rejecting
    empty raw ids and duplicate generated ids."""
    rows = _read_strict_csv_rows(path, _DBLP_ACM_RECORD_CSV_HEADER)
    records = {}
    for raw_id, title, authors, venue, year in rows:
        if raw_id == "":
            raise ManifestError(f"empty id field in {path}")
        record_id = prefix + raw_id.encode("utf-8").hex()
        if record_id in records:
            raise ManifestError(f"duplicate record id in {path}: {record_id!r}")
        records[record_id] = {
            "title": title, "authors": authors, "venue": venue, "year": year}
    return records


def _parse_dblp_acm_mapping_csv(path: Path) -> list:
    """Parse the idDBLP,idACM mapping CSV into an ordered list of
    (generated_dblp_id, generated_acm_id) tuples, rejecting empty raw ids
    and exact duplicate rows."""
    rows = _read_strict_csv_rows(path, _DBLP_ACM_MAPPING_CSV_HEADER)
    pairs = []
    seen = set()
    for raw_dblp_id, raw_acm_id in rows:
        if raw_dblp_id == "" or raw_acm_id == "":
            raise ManifestError(f"empty mapping id in {path}")
        dblp_id = "dblp:" + raw_dblp_id.encode("utf-8").hex()
        acm_id = "acm:" + raw_acm_id.encode("utf-8").hex()
        key = (dblp_id, acm_id)
        if key in seen:
            raise ManifestError(f"duplicate mapping row: {key!r}")
        seen.add(key)
        pairs.append(key)
    return pairs


def _validate_one_to_one_mapping(pairs) -> None:
    dblp_seen = {}
    acm_seen = {}
    for dblp_id, acm_id in pairs:
        if dblp_id in dblp_seen and dblp_seen[dblp_id] != acm_id:
            raise ManifestError(
                f"non-one-to-one mapping: {dblp_id!r} maps to multiple ACM ids")
        dblp_seen[dblp_id] = acm_id
        if acm_id in acm_seen and acm_seen[acm_id] != dblp_id:
            raise ManifestError(
                f"non-one-to-one mapping: {acm_id!r} maps to multiple DBLP ids")
        acm_seen[acm_id] = dblp_id


def _dblp_acm_pair_id(pair_kind: str, record_a: str, record_b: str) -> str:
    payload = (pair_kind.encode("utf-8") + b"\x00" + record_a.encode("utf-8")
               + b"\x00" + record_b.encode("utf-8"))
    return "dblp_acm-pair:" + hashlib.sha256(payload).hexdigest()


def _dblp_negative_rank_key(seed: int, dblp_id: str, acm_id: str) -> bytes:
    dblp_bytes = dblp_id.encode("utf-8")
    acm_bytes = acm_id.encode("utf-8")
    payload = (_DBLP_NEGATIVE_HASH_DOMAIN
               + seed.to_bytes(8, "big")
               + len(dblp_bytes).to_bytes(4, "big") + dblp_bytes
               + len(acm_bytes).to_bytes(4, "big") + acm_bytes)
    return hashlib.sha256(payload).digest()


def _dblp_negative_candidates(dblp_ids, acm_ids, known_matches, seed: int):
    """Yield ((rank_key_bytes, dblp_id, acm_id), (dblp_id, acm_id)) for every
    cross-source pair that is not a known match. rank_key_bytes is the
    piccard-dblp-negative-v1 digest; the trailing (dblp_id, acm_id) in the
    sort key is the documented tie-break by generated endpoint IDs."""
    for dblp_id in dblp_ids:
        for acm_id in acm_ids:
            if (dblp_id, acm_id) in known_matches:
                continue
            digest = _dblp_negative_rank_key(seed, dblp_id, acm_id)
            yield (digest, dblp_id, acm_id), (dblp_id, acm_id)


class _MaxHeapOrder:
    """Wraps a sort key with reversed comparison so heapq (a min-heap) can
    be used as a bounded max-heap: the item with the largest key sits at
    heap[0] and is evicted first via heapreplace."""
    __slots__ = ("key", "payload")

    def __init__(self, key, payload):
        self.key = key
        self.payload = payload

    def __lt__(self, other):
        return self.key > other.key


def _bounded_top_k_ascending(candidates, k: int):
    """Streaming bounded top-k: return the k smallest-key (key, payload)
    pairs from `candidates`, ascending by key, using only O(k) memory (a
    fixed-size max-heap that evicts its current largest element whenever a
    smaller candidate arrives) rather than materializing every candidate.
    Must equal sorted(candidates)[:k] for any input order."""
    if k <= 0:
        return []
    heap = []
    for key, payload in candidates:
        item = _MaxHeapOrder(key, payload)
        if len(heap) < k:
            heapq.heappush(heap, item)
        elif item.key < heap[0].key:
            heapq.heapreplace(heap, item)
    ordered = sorted(heap, key=lambda it: it.key)
    return [(it.key, it.payload) for it in ordered]


def cmd_dblp_acm(*, source_manifest, output_dir, universe: int, pairs: int,
                  seed: int, strict: bool = True, overwrite: bool = False) -> None:
    """Validate a dblp_acm source manifest, parse its three CSV inputs,
    build normalized trigram features, assemble known-match and sampled
    negative pairs, and atomically publish processed/<variant>/ via
    write_processed_output.

    `strict` is accepted for CLI-shape compatibility with the normative
    evidence command; validate_source_manifest is unconditionally strict
    (there is no non-strict mode to select), so this flag currently has no
    additional effect.
    """
    del strict  # no non-strict mode exists; see docstring
    if universe != 65536:
        raise ManifestError(f"dblp-acm only accepts universe=65536, got {universe!r}")
    if pairs < 0:
        raise ManifestError(f"pairs must be non-negative: {pairs!r}")
    if seed < 0:
        raise ManifestError(f"seed must be non-negative: {seed!r}")

    _reject_legacy_dblp_acm_processed_path(source_manifest, "source manifest")
    _reject_legacy_dblp_acm_processed_path(output_dir, "output directory")

    manifest = validate_source_manifest(source_manifest, "dblp_acm")
    inputs_by_role = {i.role: i for i in manifest.inputs}
    dblp_records = _parse_dblp_acm_records_csv(
        inputs_by_role["dblp_records"].resolved_path, "dblp:")
    acm_records = _parse_dblp_acm_records_csv(
        inputs_by_role["acm_records"].resolved_path, "acm:")
    mapping_pairs = _parse_dblp_acm_mapping_csv(
        inputs_by_role["dblp_acm_mapping"].resolved_path)
    _validate_one_to_one_mapping(mapping_pairs)

    mapped_dblp_ids = {dblp_id for dblp_id, _ in mapping_pairs}
    mapped_acm_ids = {acm_id for _, acm_id in mapping_pairs}
    for dblp_id, acm_id in mapping_pairs:
        if dblp_id not in dblp_records:
            raise ManifestError(f"unknown mapping DBLP id: {dblp_id!r}")
        if acm_id not in acm_records:
            raise ManifestError(f"unknown mapping ACM id: {acm_id!r}")

    records = []
    retained_dblp_ids = []
    retained_acm_ids = []
    dropped_dblp = 0
    dropped_acm = 0

    for record_id, fields in dblp_records.items():
        raw_features = _record_features(fields)
        if not raw_features:
            if record_id in mapped_dblp_ids:
                raise ManifestError(
                    f"mapped DBLP record has zero features: {record_id!r}")
            dropped_dblp += 1
            continue
        bucketed = bucket_features(raw_features, universe)
        records.append(RecordRow(record_id=record_id, raw_features=tuple(raw_features),
                                  bucketed_features=tuple(bucketed)))
        retained_dblp_ids.append(record_id)

    for record_id, fields in acm_records.items():
        raw_features = _record_features(fields)
        if not raw_features:
            if record_id in mapped_acm_ids:
                raise ManifestError(
                    f"mapped ACM record has zero features: {record_id!r}")
            dropped_acm += 1
            continue
        bucketed = bucket_features(raw_features, universe)
        records.append(RecordRow(record_id=record_id, raw_features=tuple(raw_features),
                                  bucketed_features=tuple(bucketed)))
        retained_acm_ids.append(record_id)

    positive_count = len(mapping_pairs)
    if pairs < positive_count:
        raise ManifestError(
            f"insufficient pair request: --pairs={pairs} is below the "
            f"{positive_count} required known-match pairs")
    negatives_needed = pairs - positive_count

    pair_rows = []
    known_matches = set(mapping_pairs)
    for dblp_id, acm_id in mapping_pairs:
        record_a, record_b = sorted((dblp_id, acm_id))
        pair_rows.append(PairRow(
            pair_id=_dblp_acm_pair_id("known_match", record_a, record_b),
            record_a=record_a, record_b=record_b,
            pair_kind="known_match", label=1))

    if negatives_needed > 0:
        candidates = _dblp_negative_candidates(
            sorted(retained_dblp_ids), sorted(retained_acm_ids),
            known_matches, seed)
        selected = _bounded_top_k_ascending(candidates, negatives_needed)
        if len(selected) < negatives_needed:
            raise ManifestError(
                f"insufficient negative candidates: needed {negatives_needed}, "
                f"found {len(selected)}")
        for _, (dblp_id, acm_id) in selected:
            record_a, record_b = sorted((dblp_id, acm_id))
            pair_rows.append(PairRow(
                pair_id=_dblp_acm_pair_id("sampled_nonmatch", record_a, record_b),
                record_a=record_a, record_b=record_b,
                pair_kind="sampled_nonmatch", label=0))

    raw_stats = summarize_set_sizes([len(r.raw_features) for r in records])
    bucketed_stats = summarize_set_sizes([len(r.bucketed_features) for r in records])

    records_bytes = _canonicalize_records(records)
    pairs_bytes = _canonicalize_pairs(pair_rows)
    source_bytes = manifest.manifest_path.read_bytes()

    values = {
        "schema_version": "piccard-real-processed-v1",
        "dataset": "dblp_acm",
        "variant": f"dblp_acm_u{universe}",
        "preprocessing_version": "dblp-acm-trigram-v1",
        "universe_size": str(universe),
        "seed": str(seed),
        "source_manifest_file": "source.manifest.tsv",
        "source_manifest_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "records_file": "records.tsv",
        "records_sha256": hashlib.sha256(records_bytes).hexdigest(),
        "record_count": str(len(records)),
        "pairs_file": "pairs.tsv",
        "pairs_sha256": hashlib.sha256(pairs_bytes).hexdigest(),
        "pair_count": str(len(pair_rows)),
        "raw_set_size_min": str(raw_stats.min),
        "raw_set_size_median": format_float(raw_stats.median),
        "raw_set_size_p95": str(raw_stats.p95),
        "raw_set_size_max": str(raw_stats.max),
        "bucketed_set_size_min": str(bucketed_stats.min),
        "bucketed_set_size_median": format_float(bucketed_stats.median),
        "bucketed_set_size_p95": str(bucketed_stats.p95),
        "bucketed_set_size_max": str(bucketed_stats.max),
        "original_positive_count": str(positive_count),
        "retained_positive_count": str(positive_count),
        "requested_pair_count": str(pairs),
        "max_documents": "",
        "min_related_pairs": "",
        "dropped.empty_features_dblp": str(dropped_dblp),
        "dropped.empty_features_acm": str(dropped_acm),
    }
    manifest_pairs = [(key, values[key])
                       for key in _processed_manifest_key_order("dblp_acm")]

    write_processed_output(output_dir, records, pair_rows, manifest_pairs,
                            manifest.manifest_path, overwrite=overwrite)


# ---------------------------------------------------------------------------
# CLI (Phase 3's enron subcommand stays a dormant "not implemented" stub)
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prepare_real_datasets.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dblp_acm = subparsers.add_parser("dblp-acm")
    dblp_acm.add_argument("--source-manifest", required=True)
    dblp_acm.add_argument("--output-dir", required=True)
    dblp_acm.add_argument("--universe", required=True, type=int)
    dblp_acm.add_argument("--pairs", required=True, type=int)
    dblp_acm.add_argument("--seed", required=True, type=int)
    dblp_acm.add_argument("--strict", action="store_true")

    enron = subparsers.add_parser("enron", add_help=False)
    enron.add_argument("extra", nargs=argparse.REMAINDER)

    return parser


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.command == "dblp-acm":
        try:
            cmd_dblp_acm(
                source_manifest=args.source_manifest,
                output_dir=args.output_dir,
                universe=args.universe,
                pairs=args.pairs,
                seed=args.seed,
                strict=args.strict,
            )
        except ManifestError as exc:
            sys.stderr.write(f"dblp-acm: {exc}\n")
            return 1
        return 0
    sys.stderr.write(f"{args.command}: not implemented\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
