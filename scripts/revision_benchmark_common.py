#!/usr/bin/env python3
"""Shared, side-effect-free contracts for the revision readiness runner.

The checked-in revision matrix remains the only experiment topology source.
This module deliberately contains no benchmark or OpenFHE calls; it only
loads the matrix, derives the frozen toy selection, and serializes one
producer command for the outer lifecycle runner.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
MATRIX_DEFAULT = SCRIPT_ROOT / "benchmarks" / "revision_matrix.json"
FIXTURE_ROOT = SCRIPT_ROOT / "tests" / "fixtures" / "revision_matrix"
PHASES = (
    "preflight",
    "synthetic",
    "comparison",
    "real-fixtures",
    "dynamic-deletion",
    "threshold",
    "verification",
    "seal",
)
TOY_PROFILE = "readiness-toy-v1"
PAPER_PROFILE = "paper-v1"
PAPER_STD128_PROFILE = "paper-std128-t40-v1"
PAPER_STD192_PROFILE = "paper-std192-encoding-v1"
PAPER_VARIANTS = (
    "dblp_acm_u65536",
    "enron_u65536",
    "enron_u1048576",
)
CELL_SCHEMA = "piccard-revision-cell-receipt-v1"
EVENT_SCHEMA = "piccard-revision-event-v1"
FLOODING_EXECUTABLE = "scripts/run_noise_profiles.sh"
SUMMARY_EXECUTABLE = "summarize_real_datasets.py"
FLOODING_PAYLOAD_DIR = "payload"
DRY_RUN_METADATA_SCHEMA = "piccard-revision-dry-run-metadata-v1"
DRY_RUN_METADATA_AVAILABILITY = "UNAVAILABLE_NO_SPAWN"


class RevisionContractError(RuntimeError):
    """Raised for a fail-closed lifecycle or matrix contract violation."""


_PROCESSED_MANIFEST_PREFIX = (
    "schema_version", "dataset", "variant", "preprocessing_version",
    "universe_size", "seed", "source_manifest_file", "source_manifest_sha256",
    "records_file", "records_sha256", "record_count", "pairs_file",
    "pairs_sha256", "pair_count", "raw_set_size_min", "raw_set_size_median",
    "raw_set_size_p95", "raw_set_size_max", "bucketed_set_size_min",
    "bucketed_set_size_median", "bucketed_set_size_p95", "bucketed_set_size_max",
    "original_positive_count", "retained_positive_count", "requested_pair_count",
    "max_documents", "min_related_pairs",
)
_PROCESSED_DROP_KEYS = {
    "dblp_acm": ("dropped.empty_features_dblp", "dropped.empty_features_acm"),
    "enron": ("dropped.charset_or_mime", "dropped.empty_body",
              "dropped.short_body", "dropped.duplicate_copy",
              "dropped.duplicate_message_id"),
}
_PAPER_DATASET_BY_VARIANT = {
    "dblp_acm_u65536": {
        "dataset": "dblp_acm", "universe_size": "65536",
        "preprocessing_version": "dblp-acm-trigram-v1",
        "parsing_schema": "dblp-acm-csv-v1",
    },
    "enron_u65536": {
        "dataset": "enron", "universe_size": "65536",
        "preprocessing_version": "enron-shingle5-v2",
        "parsing_schema": "enron-maildir-rfc5322-v1",
    },
    "enron_u1048576": {
        "dataset": "enron", "universe_size": "1048576",
        "preprocessing_version": "enron-shingle5-v2",
        "parsing_schema": "enron-maildir-rfc5322-v1",
    },
}
_PAPER_DBLP_SOURCE_MANIFEST_SHA256 = (
    "ccd019830bf62931c6c86e5aaea71c6069d46d992755ad836573efaaa286e398")
_PAPER_DBLP_SOURCE_IDENTITY = (
    ("schema_version", "piccard-real-source-v1"),
    ("dataset", "dblp_acm"),
    ("dataset_version", "OpenICPSR E100843 V2 (2017-07-21)"),
    ("source_url", "https://doi.org/10.3886/E100843V2"),
    ("citation", "Rahm, Erhard, Köpcke, Hanna, and Thor, Andreas. DBLP ACM Dataset. "
                 "Ann Arbor, MI: Inter-university Consortium for Political and "
                 "Social Research [distributor], 2017-07-21. "
                 "https://doi.org/10.3886/E100843V2"),
    ("license_or_terms_url",
     "https://www.icpsr.umich.edu/sites/icpsr/about/policies/terms-of-use"),
    ("acquisition_note", "Downloaded from OpenICPSR project E100843 V2; "
                         "ACM.csv and DBLP-ACM_perfectMapping.csv are retained "
                         "as distributed; DBLP2.csv was transcoded from ISO-8859-1 "
                         "to UTF-8 without changing CSV fields."),
    ("parsing_schema", "dblp-acm-csv-v1"),
    ("preprocessing_profile", "dblp-acm-trigram-v1"),
    ("input.0.role", "dblp_records"),
    ("input.0.path", "DBLP2.csv"),
    ("input.0.sha256",
     "32863e8b4e7e18e5254c3e0e05cbc282af2e1e6e9d58e124605ebcbaa178ae7f"),
    ("input.1.role", "acm_records"),
    ("input.1.path", "ACM.csv"),
    ("input.1.sha256",
     "32055f1dfa619a4fdca33e7de729c66686a2fb3c71589921a6a3bd3af389120e"),
    ("input.2.role", "dblp_acm_mapping"),
    ("input.2.path", "DBLP-ACM_perfectMapping.csv"),
    ("input.2.sha256",
     "d9d7c9feaba3d19a2e73ba8bd6ae08407d8b16082881f6e55abc2d703682d53a"),
)
_PAPER_DBLP_PROCESSED_COUNTS = {
    "record_count": "4910",
    "pair_count": "10000",
    "requested_pair_count": "10000",
    "original_positive_count": "2224",
    "retained_positive_count": "2224",
    "max_documents": "",
    "min_related_pairs": "",
}


def _strict_key_value_file(path: Path, label: str) -> tuple[tuple[str, str], ...]:
    """Read a canonical two-column TSV without using a producer parser."""
    if not path.is_absolute():
        raise RevisionContractError(f"{label} must be an absolute path")
    if path.is_symlink() or not path.is_file():
        raise RevisionContractError(f"{label} must be a regular non-symlink file")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise RevisionContractError(f"{label} is not valid UTF-8") from exc
    if raw.startswith(b"\xef\xbb\xbf") or "\r" in text:
        raise RevisionContractError(f"{label} must be UTF-8 LF TSV without BOM/CR")
    if not text.endswith("\n") or not text:
        raise RevisionContractError(f"{label} must be nonempty and LF terminated")
    lines = text[:-1].split("\n")
    if not lines or lines[0] != "key\tvalue":
        raise RevisionContractError(f"{label} header mismatch")
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, line in enumerate(lines[1:], start=2):
        if not line or line.count("\t") != 1:
            raise RevisionContractError(f"{label} malformed row {index}")
        key, value = line.split("\t", 1)
        if not key or key in seen:
            raise RevisionContractError(f"{label} duplicate/empty key at row {index}")
        seen.add(key)
        result.append((key, value))
    return tuple(result)


def _processed_manifest_values(path: Path) -> dict[str, str]:
    pairs = _strict_key_value_file(path, "processed manifest")
    values = dict(pairs)
    dataset = values.get("dataset", "")
    expected = _PROCESSED_MANIFEST_PREFIX + (tuple(["pair_proxy"]) if dataset == "enron" else tuple()) + _PROCESSED_DROP_KEYS.get(dataset, tuple())
    if tuple(key for key, _ in pairs) != expected:
        raise RevisionContractError("processed manifest key order/schema mismatch")
    if values.get("schema_version") != "piccard-real-processed-v1":
        raise RevisionContractError("processed manifest schema_version mismatch")
    return values


def _positive_decimal(values: dict[str, str], key: str, label: str) -> int:
    value = values.get(key, "")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise RevisionContractError(f"{label} {key} must be a positive integer") from exc
    if parsed <= 0 or str(parsed) != value:
        raise RevisionContractError(f"{label} {key} must be a positive integer")
    return parsed


def _sha256_hex(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RevisionContractError(f"{label} must be a lowercase SHA-256 hex digest")


def _validate_bound_file(base: Path, declared: str, expected_name: str,
                         declared_sha: str, label: str) -> Path:
    if declared != expected_name:
        raise RevisionContractError(f"{label} path must be exactly {expected_name}")
    path = base / declared
    if path.is_symlink() or not path.is_file():
        raise RevisionContractError(f"{label} is missing or is a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(base.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise RevisionContractError(f"{label} escapes the manifest directory") from exc
    _sha256_hex(declared_sha, f"{label} SHA-256")
    if sha256_file(resolved) != declared_sha:
        raise RevisionContractError(f"{label} SHA-256 does not match manifest")
    return resolved


def _validate_paper_manifest(path: Path, variant: str, root_seed: int) -> dict[str, str]:
    if "toy-input" in path.resolve().parts:
        raise RevisionContractError(f"paper manifest {variant} may not be under toy-input")
    expected = _PAPER_DATASET_BY_VARIANT[variant]
    values = _processed_manifest_values(path)
    label = f"paper manifest {variant}"
    for key in ("dataset", "variant", "universe_size", "preprocessing_version"):
        expected_value = variant if key == "variant" else expected[key]
        if values.get(key) != expected_value:
            raise RevisionContractError(f"{label} {key} mismatch")
    try:
        seed = int(values.get("seed", ""), 10)
    except ValueError as exc:
        raise RevisionContractError(f"{label} seed is invalid") from exc
    if seed <= 0 or str(seed) != values.get("seed"):
        raise RevisionContractError(f"{label} seed must be a positive integer")
    if seed != root_seed:
        raise RevisionContractError(f"{label} seed does not match root seed")
    source = _validate_bound_file(
        path.parent, values.get("source_manifest_file", ""),
        "source.manifest.tsv", values.get("source_manifest_sha256", ""),
        f"{label} source manifest")
    source_pairs = _strict_key_value_file(source, f"{label} source manifest")
    source_values = dict(source_pairs)
    if (source_values.get("schema_version") != "piccard-real-source-v1" or
            source_values.get("dataset") != expected["dataset"] or
            source_values.get("parsing_schema") != expected["parsing_schema"] or
            source_values.get("preprocessing_profile") != expected["preprocessing_version"]):
        raise RevisionContractError(f"{label} source manifest identity mismatch")
    if expected["dataset"] == "dblp_acm":
        if values.get("source_manifest_sha256") != _PAPER_DBLP_SOURCE_MANIFEST_SHA256:
            raise RevisionContractError(f"{label} source manifest is not canonical DBLP-ACM")
        if source_pairs != _PAPER_DBLP_SOURCE_IDENTITY:
            raise RevisionContractError(f"{label} source manifest identity mismatch")
    records = _validate_bound_file(
        path.parent, values.get("records_file", ""), "records.tsv",
        values.get("records_sha256", ""), f"{label} records")
    pairs = _validate_bound_file(
        path.parent, values.get("pairs_file", ""), "pairs.tsv",
        values.get("pairs_sha256", ""), f"{label} pairs")
    record_count = _positive_decimal(values, "record_count", label)
    pair_count = _positive_decimal(values, "pair_count", label)
    requested_pair_count = _positive_decimal(values, "requested_pair_count", label)
    if pair_count != requested_pair_count:
        raise RevisionContractError(f"{label} pair count/request mismatch")
    original = values.get("original_positive_count")
    retained = values.get("retained_positive_count")
    if original != retained:
        raise RevisionContractError(f"{label} positive-count fields mismatch")
    if expected["dataset"] == "enron":
        required = {"record_count": 10000, "pair_count": 10000,
                    "requested_pair_count": 10000, "max_documents": 10000,
                    "min_related_pairs": 100}
        for key, expected_value in required.items():
            if values.get(key) != str(expected_value):
                raise RevisionContractError(f"{label} {key} does not match paper count")
        if original != "0" or retained != "0" or values.get("pair_proxy") != (
                "canonical-subject-proxy-not-thread-ground-truth-v1"):
            raise RevisionContractError(f"{label} Enron label/proxy taxonomy mismatch")
    else:
        for key, expected_value in _PAPER_DBLP_PROCESSED_COUNTS.items():
            if values.get(key) != expected_value:
                raise RevisionContractError(f"{label} DBLP count fields mismatch")
    # Check the bound pair labels independently of the manifest summary.
    try:
        pair_lines = pairs.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise RevisionContractError(f"{label} pairs are not valid UTF-8") from exc
    expected_header = "pair_id\trecord_a\trecord_b\tpair_kind\tlabel"
    if not pair_lines or pair_lines[0] != expected_header:
        raise RevisionContractError(f"{label} pairs header mismatch")
    if len(pair_lines) - 1 != pair_count:
        raise RevisionContractError(f"{label} pair_count does not match pairs.tsv")
    expected_labels = ({"thread_related": "-1", "cross_thread": "-1"}
                       if expected["dataset"] == "enron" else
                       {"known_match": "1", "sampled_nonmatch": "0"})
    for line in pair_lines[1:]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[3] not in expected_labels or fields[4] != expected_labels[fields[3]]:
            raise RevisionContractError(f"{label} pair kind/label taxonomy mismatch")
    # Keep the independent record binding observable even though the C++ loader
    # performs the full feature and endpoint validation during execution.
    try:
        record_lines = records.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise RevisionContractError(f"{label} records are not valid UTF-8") from exc
    expected_record_header = (
        "record_id\traw_feature_count\traw_features_csv\t"
        "bucketed_feature_count\tbucketed_features_csv")
    if not record_lines or record_lines[0] != expected_record_header:
        raise RevisionContractError(f"{label} records header mismatch")
    if len(record_lines) - 1 != record_count:
        raise RevisionContractError(f"{label} record_count does not match records.tsv")
    if not records.is_file():  # pragma: no cover - defensive after binding check
        raise RevisionContractError(f"{label} records binding disappeared")
    return values


def validate_paper_manifest_bindings(*, dblp_manifest: Path,
                                     variant_manifests: dict[str, Path],
                                     root_seed: int) -> dict[str, Path]:
    """Validate the exact three processed datasets required by paper mode."""
    expected_keys = set(PAPER_VARIANTS)
    if set(variant_manifests) != expected_keys:
        raise RevisionContractError("paper requires exactly three dataset variants")
    paths = {variant: Path(variant_manifests[variant])
             for variant in PAPER_VARIANTS}
    if paths["dblp_acm_u65536"].resolve() != Path(dblp_manifest).resolve():
        raise RevisionContractError("DBLP paper manifest bindings disagree")
    for variant, path in paths.items():
        _validate_paper_manifest(path, variant, root_seed)
    return {variant: path.resolve() for variant, path in paths.items()}


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def dry_run_source_metadata(root: Path) -> dict[str, Any]:
    """Return explicitly unavailable source metadata for strict dry planning.

    A dry-run is a static matrix projection, not an executable run.  Reading
    the Git commit/status would require invoking ``git`` (and used to violate
    the runner's zero-child contract), so the manifest records that those
    fields are intentionally unavailable rather than presenting a fabricated
    commit or cleanliness claim.  The verifier recognizes this versioned
    marker and applies the same no-spawn boundary.
    """
    del root  # The path is intentionally not inspected in strict dry-run.
    return {
        "schema": DRY_RUN_METADATA_SCHEMA,
        "availability": DRY_RUN_METADATA_AVAILABILITY,
        "reason": "strict-dry-run-no-child-processes",
        "commit": None,
        "dirty": None,
        "status": None,
    }


def dry_run_tool_metadata(build_dir: Path | None = None) -> dict[str, Any]:
    """Return no-spawn tool metadata for a static dry-run plan.

    ``platform.platform()``, compiler version, and CMake version probing can
    each launch a child on some hosts.  A dry plan therefore records only
    interpreter values already resident in this process and marks external
    tool probes unavailable.  ``build_dir`` is accepted to keep the call site
    parallel to :func:`tool_metadata`; it is deliberately not traversed.
    """
    del build_dir
    return {
        "schema": DRY_RUN_METADATA_SCHEMA,
        "availability": DRY_RUN_METADATA_AVAILABILITY,
        "reason": "strict-dry-run-no-child-processes",
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "compiler": None,
        "cmake": None,
        "openfhe": os.environ.get("PICCARD_OPENFHE_VERSION", "not-probed"),
    }


def write_json(path: Path, value: Any, *, fsync: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(value)
    with path.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        if fsync:
            os.fsync(stream.fileno())


def append_jsonl(path: Path, value: Any) -> None:
    existed = path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write(canonical_json(value))
        stream.flush()
        os.fsync(stream.fileno())
    if not existed:
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def load_matrix(path: Path) -> tuple[dict[str, Any], str]:
    """Load and independently validate the canonical matrix."""
    if not path.is_absolute():
        raise RevisionContractError("matrix path must be absolute")
    try:
        from validate_revision_matrix import load_document, validate_document
    except ImportError as exc:  # pragma: no cover - only broken installation
        raise RevisionContractError("matrix validator is unavailable") from exc
    try:
        document = load_document(path)
        fixtures = FIXTURE_ROOT if path.resolve() == MATRIX_DEFAULT.resolve() else None
        validate_document(document, fixtures)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RevisionContractError(f"canonical matrix rejected: {exc}") from exc
    return document, sha256_file(path)


def expected_toy_ids() -> set[str]:
    from validate_revision_matrix import expected_executable_toy_ids
    return set(expected_executable_toy_ids())


def representative_toy_ids() -> set[str]:
    from validate_revision_matrix import REPRESENTATIVE_TOY_IDS
    return set(REPRESENTATIVE_TOY_IDS)


def expected_paper_ids(document: dict[str, Any]) -> set[str]:
    return {str(cell["cell_id"]) for cell in document["cells"]}


def select_cells(document: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    if mode in {"paper", "dry-run"}:
        return sorted(document["cells"], key=lambda cell: cell["cell_id"])
    if mode == "toy":
        selected = expected_toy_ids()
        cells = [cell for cell in document["cells"] if cell["cell_id"] in selected]
        if len(cells) != 104:
            raise RevisionContractError(
                f"toy executable inventory must contain 104 cells, got {len(cells)}")
        return sorted(cells, key=lambda cell: cell["cell_id"])
    raise RevisionContractError(f"unsupported run mode: {mode}")


def phase_for_cell(cell: dict[str, Any]) -> str:
    family = cell["family"]
    if family in {
        "piccard_std128", "piccard_std192_encoding", "fhe_ind",
        "estimator_accuracy", "sqrt_comparison", "flooding",
    }:
        return "synthetic"
    if family in {"bcg12_minhash", "bcg12_exact", "sj16"}:
        return "comparison"
    if family in {"real_dataset"}:
        return "real-fixtures"
    if family in {
        "dynamic_timing", "dynamic_accuracy", "dynamic_refresh",
        "deletion_exact", "deletion_mc",
    }:
        return "dynamic-deletion"
    if family.startswith("threshold_"):
        return "threshold"
    raise RevisionContractError(f"unknown cell family: {family}")


def slug(cell_id: str) -> str:
    return "".join(character if character.isalnum() else "_"
                   for character in cell_id)


def cell_output(root: Path, cell_id: str) -> Path:
    return root / "cells" / slug(cell_id)


def _axis(cell: dict[str, Any], name: str, default: str | None = None) -> str:
    value = cell.get("axes", {}).get(name, default)
    if value is None:
        raise RevisionContractError(f"cell {cell['cell_id']} lacks axis {name}")
    return str(value)


def _toy(mode: str) -> bool:
    return mode == "toy"


def _profile(mode: str, family: str) -> str:
    if mode == "toy":
        return TOY_PROFILE
    if family in {"piccard_std128", "sqrt_comparison", "dynamic_timing",
                  "dynamic_accuracy", "dynamic_refresh"}:
        return PAPER_STD128_PROFILE
    if family == "piccard_std192_encoding":
        return PAPER_STD192_PROFILE
    return PAPER_PROFILE


def canonical_plan_argv(cell: dict[str, Any], mode: str) -> list[str]:
    """Return the exact planner-shaped argv, with lifecycle placeholders."""
    family = cell["family"]
    toy = _toy(mode)
    profile = _profile(mode, family)
    cid = cell["cell_id"]
    k, m, n, universe = (_axis(cell, key) for key in ("k", "m", "n", "u"))
    trials = lambda paper: "1" if toy else str(paper)

    if cell["invocation_status"] == "NO_SPAWN":
        return []
    if family == "piccard_std128":
        return [
            f"--revision-cell={cid}", f"--profile={profile}", "--mode=combined",
            "--evidence_point", f"--security={'TOY' if toy else 'STD128'}",
            f"--k={k}", f"--m={m}", f"--set_size={n}", f"--universe={universe}",
            f"--trials={trials(30)}", f"--accuracy_trials={trials(50)}",
            "--seed={seed}", "--raw_timing_dir={output}",
        ]
    if family == "fhe_ind":
        return [
            f"--revision-cell={cid}", "--mode=e2e", f"--cell-id={cid}",
            f"--security={'TOY' if toy else 'STD128'}", f"--n={n}",
            f"--universe={universe}", f"--trials={trials(30)}",
            "--raw-timing-out={output}/raw",
            f"--raw-timing-profile={profile}", "--seed={seed}",
        ]
    if family == "estimator_accuracy":
        j_cell = cell["axis"] == "j"
        paper = 50 if j_cell else 500
        return [
            f"--revision-cell={cid}", f"--profile={profile}",
            f"--cell={'estimator-j' if j_cell else 'estimator-k'}", f"--k={k}",
            "--m=64", "--set_size=1000", "--universe=65536",
            f"--trials={trials(paper)}",
            f"--jaccard-grid={cell['axis_value'] if j_cell else '0.5'}",
            "--seed={seed}",
        ]
    if family in {"deletion_exact", "deletion_mc"}:
        exact = family == "deletion_exact"
        return [
            f"--revision-cell={cid}", f"--profile={profile}",
            f"--cell={'exact' if exact else 'monte-carlo'}", "--k=128", "--m=64",
            "--set_size=1000", "--universe=65536",
            f"--trials={0 if exact else trials(1000)}", "--seed={seed}",
        ]
    if family == "sqrt_comparison":
        axis = cell["axis"]
        paper = 50 if axis == "accuracy_m" else (
            1 if axis in {"ciphertext_m", "ciphertext_km"} else 30)
        mode_arg = {"timing_m": "timing", "accuracy_m": "accuracy",
                    "ciphertext_m": "ciphertext", "crossover_m": "crossover",
                    "timing_k": "timing", "timing_n": "timing",
                    "timing_km": "timing", "ciphertext_km": "ciphertext"}[axis]
        args = [
            f"--revision-cell={cid}", f"--profile={profile}", f"--cell={axis}",
            f"--mode={mode_arg}", f"--security={'TOY' if toy else 'STD128'}",
            f"--k={k}", f"--m={m}", f"--set_size={n}",
            f"--universe={universe}", f"--trials={trials(paper)}", "--seed={seed}",
        ]
        if axis in {"timing_m", "crossover_m", "timing_k", "timing_n",
                    "timing_km"}:
            args.append("--raw_timing_dir={output}/raw")
        return args
    if family == "piccard_std192_encoding":
        return [
            f"--revision-cell={cid}", f"--profile={profile}", "--suite=encoding",
            "--methods=piccard_encode,piccard_sqrt_encode", "--security=STD192",
            f"--k={k}", f"--m={m}", f"--n={n}", f"--universe={universe}",
            f"--encoding-iters={trials(30)}", "--correctness-trials=1",
            "--seed={seed}", "--output={output}/encoding.csv",
        ]
    if family in {"bcg12_minhash", "bcg12_exact"}:
        minhash = family == "bcg12_minhash"
        return [
            f"--revision-cell={cid}", f"--profile={profile}",
            f"--suite={'bcg12-minhash' if minhash else 'bcg12-exact'}",
            f"--methods={'bcg12_mh_ec,bcg12_mh_ff' if minhash else 'bcg12_exact_ec,bcg12_exact_ff'}",
            f"--k={k}", "--m=64", f"--n={n}", f"--universe={universe}",
            f"--trials={trials(30)}", "--seed={seed}",
            "--raw_timing_dir={output}/raw",
            "--output={output}/comparison.csv",
        ]
    if family == "sj16":
        axis = cell["axis"]
        value = str(cell["axis_value"])
        if axis == "fit" and value == "per_element":
            return [
                f"--revision-cell={cid}", f"--profile={profile}",
                "--cell=fit-per-element", "--key-bits=3072",
                "--sizes=4096,8192,16384", "--held-out=32768", "--threads=2",
                "--precomputed=false", f"--query-trials={trials(30)}",
                f"--enc-iters={trials(30)}", "--warmup=1", "--seed={seed}",
                "--raw_timing_dir={output}/raw",
                f"--raw_timing_profile={profile}",
                "--output={output}/calibration.csv",
            ]
        if axis == "fit" and value == "precomputed":
            return [
                f"--revision-cell={cid}", f"--profile={profile}",
                "--cell=sj16-fit-precomputed", "--method=sj16_precomputed",
                "--k=128", "--m=64", "--n=1000", "--universe=65536",
                "--key-bits=3072", "--threads=2", f"--trials={trials(30)}",
                "--warmup=1", "--seed={seed}",
                "--raw_timing_dir={output}/raw",
                "--output={output}/comparison.csv",
            ]
        return [
            f"--revision-cell={cid}", f"--profile={profile}", "--suite=sj16",
            "--method=sj16", "--k=128", "--m=64", f"--n={n}",
            f"--universe={universe}", "--key-bits=3072", "--threads=2",
            f"--trials={trials(30)}", "--seed={seed}",
            "--raw_timing_dir={output}/raw",
            "--output={output}/comparison.csv",
        ]
    if family in {"dynamic_timing", "dynamic_accuracy", "dynamic_refresh"}:
        accuracy = family == "dynamic_accuracy"
        kind = "timing" if family == "dynamic_timing" else ("accuracy" if accuracy else "refresh")
        paper = 50 if accuracy else 30
        args = [
            f"--revision-cell={cid}", f"--profile={profile}", f"--cell={kind}",
            f"--mode={kind}", "--evidence_point",
            f"--security={'TOY' if toy else 'STD128'}", f"--k={k}", f"--m={m}",
            f"--set_size={n}", f"--universe={universe}", f"--trials={trials(paper)}",
            "--updates=1", "--seed={seed}",
        ]
        if not accuracy:
            args += ["--raw-timing-dir={output}/raw",
                     f"--raw-timing-profile={'readiness-toy-v1' if toy else 'paper-v1'}"]
        return args
    if family == "flooding":
        return [
            f"--revision-cell={cid}", f"--run-profile={'readiness-toy-v1' if toy else 'paper-v1'}",
            f"--profile={cell['axis_value']}",
            f"--repetitions={trials(5)}", "--results-root={output}",
            "--seed={seed}", "--threads=2",
        ]
    if family == "real_dataset":
        variant = _axis(cell, "variant")
        artifact = str(cell["axis_value"])
        if artifact == "summary":
            accuracy_id = f"paper-v1::real_dataset::{variant}_artifact=accuracy"
            return [
                f"--revision-cell={cid}",
                f"--accuracy-csv={{cell_output:{accuracy_id}}}/accuracy.csv",
                "--output={output}/summary.csv", f"--variant={variant}",
            ]
        if artifact == "accuracy":
            return [
                f"--revision-cell={cid}", "--mode=accuracy",
                f"--dataset-manifest={{variant_manifest:{variant}}}",
                "--max-pairs=1000", "--seed={seed}", "--csv={output}/accuracy.csv",
                "--workload-manifest-out={output}/accuracy.manifest.tsv",
                "--workload-rows-out={output}/accuracy.rows.tsv",
            ]
        if artifact == "std128_timing":
            return [
                f"--revision-cell={cid}", "--mode=timing",
                f"--dataset-manifest={{variant_manifest:{variant}}}",
                f"--profile={'readiness-toy-v1' if toy else 'paper-std128-t40-v1'}",
                f"--security={'TOY' if toy else 'STD128'}", "--k=128", "--m=64",
                f"--trials={trials(30)}", "--seed={seed}",
                "--raw-timing-dir={output}/raw",
                f"--raw-timing-profile={'readiness-toy-v1' if toy else 'paper-v1'}",
                "--csv={output}/timing.csv",
                "--workload-manifest-out={output}/timing.manifest.tsv",
            ]
        return [
            f"--revision-cell={cid}", "--mode=encoding",
            f"--dataset-manifest={{variant_manifest:{variant}}}",
            f"--profile={'readiness-toy-v1' if toy else 'paper-std192-encoding-v1'}",
            "--methods=onehot,sqrt", "--k=128", "--m=64",
            f"--encoding-iters={trials(30)}", "--correctness-trials=1",
            "--seed={seed}", "--csv={output}/encoding.csv",
            "--workload-manifest-out={output}/encoding.manifest.tsv",
        ]
    if family.startswith("threshold_"):
        if family == "threshold_dblp_fpfn":
            return [
                f"--revision-cell={cid}", "--mode=threshold",
                "--dataset-manifest={dblp_acm_u65536_manifest}", "--k=128", "--m=64",
                f"--threshold-trials={trials(50)}", "--seed={seed}",
                "--hash_randomness=resampled", "--csv={output}/threshold.csv",
                "--workload-manifest-out={output}/threshold.manifest.tsv",
                "--workload-rows-out={output}/threshold.rows.tsv",
            ]
        if family == "threshold_synthetic_fpfn":
            return [
                f"--revision-cell={cid}", f"--profile={profile}", "--mode=fpfn",
                f"--point-k={cell['point_k']}", f"--grid-index={cell['grid_index']}",
                "--m=64", "--set_size=1000", f"--trials={trials(1000)}",
                "--seed={seed}", "--hash_randomness=resampled",
            ]
        kind = {"threshold_timing": "timing", "threshold_spec": "spec",
                "threshold_agreement": "agreement"}[family]
        paper = 30 if kind == "timing" else (0 if kind == "spec" else 50)
        return [
            f"--revision-cell={cid}", f"--profile={profile}",
            f"--mode={'accuracy' if kind == 'agreement' else kind}", f"--cell={kind}",
            f"--security={'TOY' if toy else 'STD128'}", f"--k={_axis(cell, 'k')}",
            "--m=64", "--set_size=1000", f"--trials={trials(paper)}",
            "--seed={seed}",
            *( ["--raw_timing_dir={output}/raw"] if kind == "timing" else [] ),
        ]
    raise RevisionContractError(f"no planner for family {family}")


def materialize_argv(
    canonical: Iterable[str], *, root: Path, output: Path, seed: int,
    threads: int, variant_manifests: dict[str, Path] | None = None,
    dblp_manifest: Path | None = None,
) -> list[str]:
    variant_manifests = variant_manifests or {}
    result: list[str] = []
    for argument in canonical:
        value = argument.replace("{seed}", str(seed)).replace("{threads}", str(threads))
        value = value.replace("{output}", str(output))
        if "{dblp_acm_u65536_manifest}" in value:
            if dblp_manifest is None:
                raise RevisionContractError("DBLP manifest is not available")
            value = value.replace("{dblp_acm_u65536_manifest}", str(dblp_manifest))
        while "{variant_manifest:" in value:
            begin = value.index("{variant_manifest:")
            end = value.index("}", begin)
            variant = value[begin + len("{variant_manifest:"):end]
            manifest = variant_manifests.get(variant)
            if manifest is None:
                raise RevisionContractError(f"toy manifest is unavailable for {variant}")
            value = value[:begin] + str(manifest) + value[end + 1:]
        while "{cell_output:" in value:
            begin = value.index("{cell_output:")
            end = value.index("}", begin)
            cell_id = value[begin + len("{cell_output:"):end]
            value = value[:begin] + str(cell_output(root, cell_id)) + value[end + 1:]
        result.append(value)
    return result


def producer_output_dir(cell: dict[str, Any], output: Path) -> Path:
    """Return the producer-owned artifact root for one cell.

    Lifecycle evidence (stdout, stderr, and receipt) remains directly under
    ``output``.  The flooding wrapper has a stricter contract: its
    ``--results-root`` must be an absent child that the wrapper creates, so
    only flooding artifacts live under ``output/payload``.
    """
    if str(cell.get("family", "")) == "flooding":
        return output / FLOODING_PAYLOAD_DIR
    return output


def materialize_cell_argv(
    cell: dict[str, Any], mode: str, *, root: Path, output: Path, seed: int,
    threads: int, variant_manifests: dict[str, Path] | None = None,
    dblp_manifest: Path | None = None,
) -> list[str]:
    """Materialize planner argv with the cell-specific producer root."""
    return materialize_argv(
        canonical_plan_argv(cell, mode), root=root,
        output=producer_output_dir(cell, output), seed=seed, threads=threads,
        variant_manifests=variant_manifests, dblp_manifest=dblp_manifest,
    )


def executable_for_cell(cell: dict[str, Any]) -> str:
    """Return the concrete executable selected by the revision planner.

    ``producer`` is the logical producer recorded in the canonical matrix.
    Two planner branches deliberately dispatch through a source-tree wrapper:
    flooding uses ``run_noise_profiles.sh`` while real-dataset summaries use
    the Python summarizer.  Keeping this mapping here mirrors C++
    ``ExecutableForCell`` and prevents lifecycle code from silently treating
    a logical producer name as an executable path.
    """
    family = str(cell.get("family", ""))
    if family == "flooding":
        return FLOODING_EXECUTABLE
    if family == "real_dataset" and str(cell.get("axis_value", "")) == "summary":
        return SUMMARY_EXECUTABLE
    return _executable_for_logical_producer(str(cell["producer"]))


def _executable_for_logical_producer(producer: str) -> str:
    if producer == "bench_noise":
        return FLOODING_EXECUTABLE
    return producer


def command_for_producer(producer: str, *, root: Path, build_dir: Path) -> list[str]:
    """Resolve one logical producer to its concrete command.

    The two logical names that are not direct executables are handled here as
    well as in :func:`executable_for_cell`, so independent rematerialization
    that only has the matrix producer field still receives the planner's
    executable.  Flooding's wrapper must be explicitly bound to the selected
    build's ``bench_noise`` binary; it must never fall back to ``repo/build``.
    """
    logical_producer = producer
    executable = _executable_for_logical_producer(producer)
    if executable.endswith(".py"):
        command = [sys.executable, str(SCRIPT_ROOT / "scripts" / executable)]
    elif executable.startswith("scripts/"):
        command = [str(SCRIPT_ROOT / executable)]
    else:
        command = [str(build_dir / executable)]
    if logical_producer == "bench_noise":
        command.append(f"--bench-noise={build_dir / 'bench_noise'}")
    return command


def command_for_cell(cell: dict[str, Any], *, root: Path,
                     build_dir: Path) -> list[str]:
    """Resolve a canonical cell using the authoritative executable mapping."""
    executable = executable_for_cell(cell)
    command = command_for_producer(cell["producer"], root=root,
                                   build_dir=build_dir)
    # ``command_for_producer`` binds the flooding logical binary.  Assert that
    # its executable agrees with the family mapping before returning it; this
    # catches accidental future divergence between the two call paths.
    if cell["producer"] != "bench_noise" and command[0] != (
            sys.executable if executable.endswith(".py") else
            str(SCRIPT_ROOT / executable) if executable.startswith("scripts/") else
            str(build_dir / executable)):
        raise RevisionContractError("cell executable mapping is inconsistent")
    return command


def producer_extra_args(cell: dict[str, Any], output: Path) -> list[str]:
    """Return deterministic output bindings appended outside canonical argv."""
    producer = cell["producer"]
    if producer == "bench_fhe_ind":
        return [f"--output={output / 'fhe_ind.csv'}",
                f"--revision-identity-out={output / 'identity.csv'}"]
    if producer == "bench_piccard":
        return [f"--revision-identity-out={output / 'identity.csv'}"]
    if producer == "bench_dynamic":
        return [f"--revision-identity-out={output / 'identity.csv'}"]
    return []


def command_label(command: list[str]) -> str:
    return " ".join(command)


def tool_metadata(build_dir: Path | None = None) -> dict[str, str]:
    def output(command: list[str]) -> str:
        try:
            return subprocess.run(command, check=False, capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
    metadata = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "compiler": output(["c++", "--version"]).splitlines()[0]
        if output(["c++", "--version"]) != "unavailable" else "unavailable",
        "cmake": output(["cmake", "--version"]).splitlines()[0]
        if output(["cmake", "--version"]) != "unavailable" else "unavailable",
        "openfhe": os.environ.get("PICCARD_OPENFHE_VERSION", "not-probed"),
    }
    if build_dir is not None:
        cache = build_dir / "CMakeCache.txt"
        if cache.is_file():
            metadata["cmake_cache_sha256"] = sha256_file(cache)
            for line in cache.read_text(encoding="utf-8", errors="strict").splitlines():
                if line.startswith("OpenFHE_DIR:PATH="):
                    metadata["openfhe_dir"] = line.split("=", 1)[1]
                    version_file = Path(metadata["openfhe_dir"]) / "OpenFHEConfigVersion.cmake"
                    if version_file.is_file():
                        metadata["openfhe_config_version_sha256"] = sha256_file(version_file)
                    break
    return metadata


def source_metadata(root: Path) -> dict[str, Any]:
    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", "-C", str(root), *args], check=True,
                                  capture_output=True, text=True).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
    status = git("status", "--porcelain", "--untracked-files=no")
    return {
        "commit": git("rev-parse", "HEAD"),
        "dirty": bool(status),
        "status": status,
    }


def file_inventory(root: Path, *, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        entries.append({"path": relative, "size": path.stat().st_size,
                        "sha256": sha256_file(path)})
    return entries


def expected_row_count(cell: dict[str, Any], mode: str) -> int:
    count = 0
    for row in cell["expected_rows"]:
        count += int(row["toy_measured_count"] if mode == "toy"
                     else row["paper_measured_count"])
    return count


def script_hashes() -> dict[str, str]:
    names = (
        "revision_benchmark_common.py", "run_revision_benchmarks.py",
        "verify_revision_benchmarks.py", "seal_revision_benchmarks.py",
        "validate_revision_matrix.py",
    )
    result: dict[str, str] = {}
    for name in names:
        path = SCRIPT_ROOT / "scripts" / name
        if path.is_file():
            result[name] = sha256_file(path)
    return result


def binary_metadata(build_dir: Path, cells: list[dict[str, Any]]) -> dict[str, Any]:
    producers = sorted({cell["producer"] for cell in cells})
    result: dict[str, Any] = {}
    for producer in producers:
        if producer.endswith(".py"):
            path = SCRIPT_ROOT / "scripts" / producer
        elif producer.startswith("scripts/"):
            path = SCRIPT_ROOT / producer
        else:
            path = build_dir / producer
        if path.is_file() and not path.is_symlink():
            result[producer] = {"path": str(path.resolve()),
                                "sha256": sha256_file(path),
                                "size": path.stat().st_size}
        else:
            result[producer] = {"path": str(path), "sha256": "MISSING",
                                "size": 0}
    return result
