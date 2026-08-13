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
CELL_SCHEMA = "piccard-revision-cell-receipt-v1"
EVENT_SCHEMA = "piccard-revision-event-v1"


class RevisionContractError(RuntimeError):
    """Raised for a fail-closed lifecycle or matrix contract violation."""


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


def write_json(path: Path, value: Any, *, fsync: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(value)
    with path.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        if fsync:
            os.fsync(stream.fileno())


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write(canonical_json(value))
        stream.flush()
        os.fsync(stream.fileno())


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
    if family == "piccard_std128":
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
        paper = 50 if axis == "accuracy_m" else (1 if axis == "ciphertext_m" else 30)
        mode_arg = {"timing_m": "timing", "accuracy_m": "accuracy",
                    "ciphertext_m": "ciphertext", "crossover_m": "crossover"}[axis]
        return [
            f"--revision-cell={cid}", f"--profile={profile}", f"--cell={axis}",
            f"--mode={mode_arg}", f"--security={'TOY' if toy else 'STD128'}",
            "--k=128", f"--m={_axis(cell, 'm')}", "--set_size=1000",
            "--universe=65536", f"--trials={trials(paper)}", "--seed={seed}",
        ]
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
                "--output={output}/calibration.csv",
            ]
        if axis == "fit" and value == "precomputed":
            return [
                f"--revision-cell={cid}", f"--profile={profile}",
                "--cell=sj16-fit-precomputed", "--method=sj16_precomputed",
                "--k=128", "--m=64", "--n=1000", "--universe=65536",
                "--key-bits=3072", "--threads=2", f"--trials={trials(30)}",
                "--warmup=1", "--seed={seed}", "--output={output}/comparison.csv",
            ]
        return [
            f"--revision-cell={cid}", f"--profile={profile}", "--suite=sj16",
            "--method=sj16", "--k=128", "--m=64", f"--n={n}",
            f"--universe={universe}", "--key-bits=3072", "--threads=2",
            f"--trials={trials(30)}", "--seed={seed}",
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
            "--seed={seed}", "--threads={threads}",
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
            "--m=64", "--set_size=1000", f"--trials={trials(paper) if paper else 0}",
            "--seed={seed}",
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


def command_for_producer(producer: str, *, root: Path, build_dir: Path) -> list[str]:
    if producer.endswith(".py"):
        return [sys.executable, str(SCRIPT_ROOT / "scripts" / producer)]
    if producer.startswith("scripts/"):
        return [str(SCRIPT_ROOT / producer)]
    return [str(build_dir / producer)]


def command_label(command: list[str]) -> str:
    return " ".join(command)


def tool_metadata() -> dict[str, str]:
    def output(command: list[str]) -> str:
        try:
            return subprocess.run(command, check=False, capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "compiler": output(["c++", "--version"]).splitlines()[0]
        if output(["c++", "--version"]) != "unavailable" else "unavailable",
        "cmake": output(["cmake", "--version"]).splitlines()[0]
        if output(["cmake", "--version"]) != "unavailable" else "unavailable",
        "openfhe": os.environ.get("PICCARD_OPENFHE_VERSION", "not-probed"),
    }


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
