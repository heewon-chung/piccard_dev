#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
"""Runner for the real-dataset accuracy/timing benchmark matrix (Work 5,
master Task 9B). See docs/superpowers/plans/2026-07-29-05-real-dataset-pipeline.md
Phase 6 for the binding, byte-level contract this implements.

`evidence_mode` is derived, never CLI-settable: `--quick` fixes it to
`quick` and always runs exactly the one tracked DBLP-ACM fixture pair
(rev. 4 descope); its absence together with explicit `--source-manifest`/
`--dataset-manifest` pairs fixes it to `paper`.

Every non-dry invocation writes a canonical two-column `run_metadata.tsv`
under `--results-root` recording exact argv/environment/input/output
bindings for every cell, so `--resume` can recompute and match them bit for
bit before skipping a `status=complete` cell. Verification is a completely
separate, non-circular step (`scripts/verify_real_dataset_outputs.py`) --
this runner never writes verifier state.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import platform
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field


SCRIPT_DIR = pathlib.Path(sys.argv.pop(1)).resolve()
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
from prepare_real_datasets import (  # noqa: E402
    ManifestError,
    parse_two_column_tsv,
    sha256_file,
    validate_source_manifest,
)


SCHEMA = "piccard-real-run-v1"
QUICK_VARIANT = "dblp_acm_u65536"
QUICK_SOURCE_MANIFEST = (
    REPO_ROOT / "tests" / "fixtures" / "real_datasets" / "quick" / QUICK_VARIANT
    / "source.manifest.tsv"
)
QUICK_DATASET_MANIFEST = (
    REPO_ROOT / "tests" / "fixtures" / "real_datasets" / "quick" / QUICK_VARIANT
    / "dataset.manifest.tsv"
)
PAPER_PROFILES = ("std128-t40-primary", "std192-t40-primary")
SINGLE_TRIAL_PROFILES = (
    "work5-std128-t40-single-trial",
    "work5-std192-t40-single-trial",
)
SINGLE_TRIAL_SEED = 20260729
SINGLE_TRIAL_THREADS = 2
SINGLE_TRIAL_DATASET = "dblp_acm"
SINGLE_TRIAL_VARIANT = "dblp_acm_u65536"
SINGLE_TRIAL_PAIR_COUNT = 10000
SINGLE_TRIAL_SOURCE_MANIFEST = (
    REPO_ROOT / "datasets" / "manifests" / "dblp_acm.source.tsv"
).resolve()
_LEGACY_PROCESSED_DIR = (
    REPO_ROOT / "datasets" / "data" / "processed" / "dblp_acm_u65536"
).resolve()
_SINGLE_TRIAL_SOURCE_HASHES = {
    "dblp_records": "32863e8b4e7e18e5254c3e0e05cbc282af2e1e6e9d58e124605ebcbaa178ae7f",
    "acm_records": "32055f1dfa619a4fdca33e7de729c66686a2fb3c71589921a6a3bd3af389120e",
    "dblp_acm_mapping": "d9d7c9feaba3d19a2e73ba8bd6ae08407d8b16082881f6e55abc2d703682d53a",
}
ACCURACY_K = 128
ACCURACY_M = 64
HASH_RANDOMNESS = "resampled"
TIMING_PAIR = "median"
QUICK_TIMING_PROFILE = "toy-smoke"
QUICK_MAX_PAIRS = 2
QUICK_ACCURACY_TRIALS = 1
QUICK_TIMING_TRIALS = 1
PAPER_MAX_PAIRS = 10000
PAPER_ACCURACY_TRIALS = 1
PAPER_TIMING_TRIALS = 30
SINGLE_TRIAL_TIMING_TRIALS = 1


class RunnerError(ValueError):
    """A fail-closed runner validation error."""


def fail(message: str) -> None:
    raise RunnerError(message)


def argv_sha256(argv) -> str:
    hasher = hashlib.sha256()
    for argument in argv:
        encoded = argument.encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
    return hasher.hexdigest()


def read_kv(path: pathlib.Path) -> dict:
    pairs = parse_two_column_tsv(path)
    values: dict = {}
    for key, value in pairs:
        if key in values:
            fail(f"duplicate manifest key {key!r} in {path}")
        values[key] = value
    return values


def write_kv(path: pathlib.Path, pairs) -> None:
    lines = ["key\tvalue"]
    seen = set()
    for key, value in pairs:
        if key in seen:
            fail(f"duplicate manifest key while writing: {key!r}")
        seen.add(key)
        if "\t" in key or "\n" in value or "\t" in value or "\r" in value or "\r" in key:
            fail(f"forbidden character in manifest field: {key!r}={value!r}")
        lines.append(f"{key}\t{value}")
    data = ("\n".join(lines) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.remove(tmp_name)
        except OSError:
            pass
        raise


def ensure_contained(root: pathlib.Path, relative: str, label: str) -> pathlib.Path:
    if not relative or pathlib.Path(relative).is_absolute():
        fail(f"{label} must be a non-empty relative path")
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes its declared root: {relative!r}")
    return candidate


def run_short(command, cwd=None) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True,
                                check=False)
    except OSError as error:
        fail(f"cannot run {command[0]}: {error}")
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        fail(f"command failed ({' '.join(command)}): {detail}")
    return result.stdout.strip()


def source_identity(project: pathlib.Path, *, tracked_only: bool = False):
    """Return the source commit and cleanliness under the selected contract.

    Quick/paper retain their historical all-files cleanliness rule.  The
    single-trial validation path must instead match the outer Work 5 runner's
    frozen identity rule: tracked and staged changes are disqualifying, while
    the explicitly permitted untracked `.omo/evidence/` receipts are not.
    """
    commit = run_short(["git", "rev-parse", "HEAD"], project)
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        fail("git HEAD is not a full lowercase commit")
    untracked = "no" if tracked_only else "all"
    dirty = bool(run_short(
        ["git", "status", "--porcelain=v1", f"--untracked-files={untracked}"], project))
    return commit, dirty


def read_build_type(build_dir: pathlib.Path) -> str:
    cache = build_dir / "CMakeCache.txt"
    try:
        lines = cache.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"cannot read build CMakeCache.txt: {error}")
    values = [line.split("=", 1)[1] for line in lines
              if line.startswith("CMAKE_BUILD_TYPE:STRING=")]
    if len(values) != 1 or not values[0]:
        fail("CMakeCache.txt must contain exactly one CMAKE_BUILD_TYPE")
    return values[0]


# ---------------------------------------------------------------------------
# Manifest-pair bookkeeping
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ManifestPair:
    source_manifest: pathlib.Path
    dataset_manifest: pathlib.Path
    dataset: str
    variant: str


def _is_under(path: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
    except ValueError:
        return False
    return True


def _reject_legacy_processed_path(path: pathlib.Path, label: str) -> None:
    if _is_under(path, _LEGACY_PROCESSED_DIR):
        fail(f"{label} resolves within the quarantined prior processed DBLP-ACM directory")


def load_manifest_pair(source_manifest: pathlib.Path,
                        dataset_manifest: pathlib.Path) -> ManifestPair:
    if not source_manifest.is_absolute() or not dataset_manifest.is_absolute():
        fail("--source-manifest and --dataset-manifest must be absolute paths")
    source_manifest = source_manifest.resolve(strict=True)
    dataset_manifest = dataset_manifest.resolve(strict=True)
    # This is deliberately before parsing dataset.manifest.tsv: the old
    # 4448-pair run is not admissible even as a rejected configuration input.
    _reject_legacy_processed_path(source_manifest, "source manifest")
    _reject_legacy_processed_path(dataset_manifest, "dataset manifest")
    values = read_kv(dataset_manifest)
    dataset = values.get("dataset")
    variant = values.get("variant")
    if not dataset or not variant:
        fail(f"dataset manifest {dataset_manifest} is missing 'dataset'/'variant'")
    return ManifestPair(source_manifest=source_manifest,
                        dataset_manifest=dataset_manifest,
                        dataset=dataset, variant=variant)


def validate_single_trial_pair(pair: ManifestPair) -> None:
    """Bind validation mode to the immutable DBLP-ACM source and a fresh run.

    This runs source hashing before any real-data producer is launched.  The
    parser itself performs the required hash-before-UTF-8-decode check; this
    outer gate additionally freezes all three published source digests and
    rejects the old 4448-pair directory as either a source or a destination.
    """
    if pair.source_manifest != SINGLE_TRIAL_SOURCE_MANIFEST:
        fail("single-trial-validation requires exactly "
             f"{SINGLE_TRIAL_SOURCE_MANIFEST}")
    if pair.dataset != SINGLE_TRIAL_DATASET or pair.variant != SINGLE_TRIAL_VARIANT:
        fail("single-trial-validation requires dataset=dblp_acm and "
             "variant=dblp_acm_u65536")
    try:
        source = validate_source_manifest(pair.source_manifest, "dblp_acm")
    except ManifestError as error:
        fail(f"single-trial-validation source manifest validation failed: {error}")
    source_hashes = {entry.role: entry.sha256 for entry in source.inputs}
    if source_hashes != _SINGLE_TRIAL_SOURCE_HASHES:
        fail("single-trial-validation source input hashes are not the frozen DBLP-ACM hashes")
    values = read_kv(pair.dataset_manifest)
    expected = {
        "schema_version": "piccard-real-processed-v1",
        "dataset": SINGLE_TRIAL_DATASET,
        "variant": SINGLE_TRIAL_VARIANT,
        "universe_size": "65536",
        "seed": str(SINGLE_TRIAL_SEED),
        "record_count": "4910",
        "pair_count": str(SINGLE_TRIAL_PAIR_COUNT),
        "requested_pair_count": str(SINGLE_TRIAL_PAIR_COUNT),
        "original_positive_count": "2224",
        "retained_positive_count": "2224",
    }
    mismatches = [key for key, value in expected.items() if values.get(key) != value]
    if mismatches:
        fail("single-trial-validation processed manifest mismatch: " +
             ", ".join(mismatches))
    copied_source = pair.dataset_manifest.parent / "source.manifest.tsv"
    if (not copied_source.is_file() or sha256_file(copied_source) !=
            sha256_file(pair.source_manifest)):
        fail("single-trial-validation processed manifest is not bound to the supplied source manifest")


# ---------------------------------------------------------------------------
# Cell construction
# ---------------------------------------------------------------------------

@dataclass
class Cell:
    cell_id: str
    variant: str
    display_argv: list
    exec_argv: list
    env: dict
    input_specs: list   # [(role, root_id, root_path, rel_path_under_root)]
    output_paths: list  # [abs_path] (results-root relative derived later)


def accuracy_cell(pair: ManifestPair, results_root: pathlib.Path, source_root_id: str,
                  processed_root_id: str, processed_root: pathlib.Path,
                  seed: int, max_pairs: int, accuracy_trials: int) -> Cell:
    csv_path = results_root / "csv" / f"real_accuracy_{pair.variant}.csv"
    wm_path = results_root / "workloads" / f"accuracy_{pair.variant}.manifest.tsv"
    wr_path = results_root / "workloads" / f"accuracy_{pair.variant}.rows.tsv"
    display_argv = [
        "bench_real_datasets",
        f"--dataset-manifest={pair.dataset_manifest}",
        "--mode=accuracy",
        f"--k={ACCURACY_K}", f"--m={ACCURACY_M}",
        f"--max-pairs={max_pairs}",
        f"--accuracy_trials={accuracy_trials}",
        f"--seed={seed}",
        f"--hash_randomness={HASH_RANDOMNESS}",
        f"--csv={csv_path}",
        f"--workload-manifest-out={wm_path}",
        f"--workload-rows-out={wr_path}",
    ]
    dataset_manifest_rel = pair.dataset_manifest.relative_to(processed_root).as_posix()
    return Cell(
        cell_id=f"{pair.variant}:accuracy", variant=pair.variant,
        display_argv=display_argv, exec_argv=None,
        env={"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"},
        input_specs=[("processed-manifest", processed_root_id, processed_root,
                     dataset_manifest_rel)],
        output_paths=[csv_path, wm_path, wr_path],
    )


def summary_cell(pair: ManifestPair, results_root: pathlib.Path,
                 accuracy_csv: pathlib.Path) -> Cell:
    summary_path = results_root / "csv" / f"real_accuracy_summary_{pair.variant}.csv"
    display_argv = [
        "summarize_real_datasets.py",
        f"--input={accuracy_csv}",
        f"--output={summary_path}",
    ]
    return Cell(
        cell_id=f"{pair.variant}:accuracy-summary", variant=pair.variant,
        display_argv=display_argv, exec_argv=None,
        env={"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"},
        input_specs=[("accuracy-csv", "results-root", results_root,
                     accuracy_csv.relative_to(results_root).as_posix())],
        output_paths=[summary_path],
    )


def timing_cell(pair: ManifestPair, results_root: pathlib.Path, processed_root_id: str,
                processed_root: pathlib.Path, profile: str, seed: int, threads: int,
                trials: int) -> Cell:
    csv_path = results_root / "csv" / f"real_timing_{pair.variant}_{profile}.csv"
    wm_path = results_root / "workloads" / f"timing_{pair.variant}_{profile}.manifest.tsv"
    display_argv = [
        "bench_real_datasets",
        f"--dataset-manifest={pair.dataset_manifest}",
        "--mode=timing",
        f"--profile={profile}",
        f"--k={ACCURACY_K}", f"--m={ACCURACY_M}",
        f"--trials={trials}",
        f"--timing-pair={TIMING_PAIR}",
        f"--seed={seed}",
        f"--csv={csv_path}",
        f"--workload-manifest-out={wm_path}",
    ]
    dataset_manifest_rel = pair.dataset_manifest.relative_to(processed_root).as_posix()
    return Cell(
        cell_id=f"{pair.variant}:timing:{profile}", variant=pair.variant,
        display_argv=display_argv, exec_argv=None,
        env={"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(threads)},
        input_specs=[("processed-manifest", processed_root_id, processed_root,
                     dataset_manifest_rel)],
        output_paths=[csv_path, wm_path],
    )


def encoding_cell(pair: ManifestPair, results_root: pathlib.Path,
                  processed_root_id: str, processed_root: pathlib.Path,
                  profile: str, method: str, seed: int, threads: int) -> Cell:
    csv_path = results_root / "csv" / (
        f"real_encoding_{pair.variant}_{profile}_{method}.csv")
    wm_path = results_root / "workloads" / (
        f"encoding_{pair.variant}_{profile}_{method}.manifest.tsv")
    display_argv = [
        "bench_real_datasets",
        f"--dataset-manifest={pair.dataset_manifest}",
        "--mode=encoding",
        f"--profile={profile}",
        f"--method={method}",
        f"--k={ACCURACY_K}", f"--m={ACCURACY_M}",
        f"--trials={SINGLE_TRIAL_TIMING_TRIALS}",
        f"--timing-pair={TIMING_PAIR}",
        f"--seed={seed}",
        f"--csv={csv_path}",
        f"--workload-manifest-out={wm_path}",
    ]
    dataset_manifest_rel = pair.dataset_manifest.relative_to(processed_root).as_posix()
    return Cell(
        cell_id=f"{pair.variant}:encoding:{profile}:{method}", variant=pair.variant,
        display_argv=display_argv, exec_argv=None,
        env={"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(threads)},
        input_specs=[("processed-manifest", processed_root_id, processed_root,
                     dataset_manifest_rel)],
        output_paths=[csv_path, wm_path],
    )


def build_cells(pairs, results_root, roots_by_variant, evidence_mode, seed, threads,
                profiles):
    cells = []
    for pair in pairs:
        source_root_id = f"source-root-{pair.variant}"
        processed_root_id = f"processed-dataset-{pair.variant}"
        processed_root = roots_by_variant[pair.variant]["processed"]

        max_pairs = QUICK_MAX_PAIRS if evidence_mode == "quick" else PAPER_MAX_PAIRS
        accuracy_trials = (QUICK_ACCURACY_TRIALS if evidence_mode == "quick"
                          else PAPER_ACCURACY_TRIALS)
        acc = accuracy_cell(pair, results_root, source_root_id, processed_root_id,
                           processed_root, seed, max_pairs, accuracy_trials)
        cells.append(acc)
        cells.append(summary_cell(pair, results_root, acc.output_paths[0]))

        if evidence_mode == "quick":
            cells.append(timing_cell(
                pair, results_root, processed_root_id, processed_root,
                QUICK_TIMING_PROFILE, seed, threads, QUICK_TIMING_TRIALS))
        elif evidence_mode == "single-trial-validation":
            cells.append(timing_cell(
                pair, results_root, processed_root_id, processed_root,
                "work5-std128-t40-single-trial", seed, threads,
                SINGLE_TRIAL_TIMING_TRIALS))
            for method in ("piccard_encode", "piccard_sqrt_encode"):
                cells.append(encoding_cell(
                    pair, results_root, processed_root_id, processed_root,
                    "work5-std192-t40-single-trial", method, seed, threads))
        else:
            for profile in profiles:
                cells.append(timing_cell(
                    pair, results_root, processed_root_id, processed_root,
                    profile, seed, threads, PAPER_TIMING_TRIALS))
    return cells


# ---------------------------------------------------------------------------
# Metadata assembly
# ---------------------------------------------------------------------------

def build_roots_section(results_root, build_dir, pairs, roots_by_variant) -> list:
    pairs_out = [
        ("results-root", str(results_root)),
        ("build-dir", str(build_dir)),
        ("committed-source-root", str(REPO_ROOT)),
    ]
    for pair in pairs:
        pairs_out.append((f"source-root-{pair.variant}",
                          str(roots_by_variant[pair.variant]["source"])))
        pairs_out.append((f"processed-dataset-{pair.variant}",
                          str(roots_by_variant[pair.variant]["processed"])))
    root_ids = [item[0] for item in pairs_out]
    out = [("root_count", str(len(pairs_out)))]
    for index, (root_id, path) in enumerate(pairs_out):
        prefix = f"root.{index:03d}"
        out.append((f"{prefix}.id", root_id))
        out.append((f"{prefix}.path", path))
    return out, root_ids


def build_cell_section(cell: Cell, results_root: pathlib.Path) -> list:
    out = [("id", cell.cell_id)]
    argv = cell.display_argv
    out.append(("argv_count", str(len(argv))))
    for i, arg in enumerate(argv):
        out.append((f"argv.{i:03d}", arg))
    out.append(("argv_sha256", argv_sha256(argv)))

    env_items = sorted(cell.env.items())
    out.append(("env_count", str(len(env_items))))
    for i, (key, value) in enumerate(env_items):
        out.append((f"env.{i:03d}.key", key))
        out.append((f"env.{i:03d}.value", value))

    out.append(("input_count", str(len(cell.input_specs))))
    for i, (role, root_id, root_path, rel_path) in enumerate(cell.input_specs):
        abs_path = (root_path / rel_path).resolve(strict=True)
        out.append((f"input.{i:03d}.role", role))
        out.append((f"input.{i:03d}.root_id", root_id))
        out.append((f"input.{i:03d}.path", rel_path))
        out.append((f"input.{i:03d}.sha256", sha256_file(abs_path)))

    out.append(("output_count", str(len(cell.output_paths))))
    for i, out_path in enumerate(cell.output_paths):
        rel = out_path.resolve(strict=True).relative_to(results_root.resolve()).as_posix()
        out.append((f"output.{i:03d}.path", rel))
        out.append((f"output.{i:03d}.sha256", sha256_file(out_path)))

    out.append(("status", "complete"))
    return out


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

def dry_run(cells) -> int:
    print("GATE evidence_mode is derived, not CLI-overridable")
    print("GATE absolute --build-dir/--results-root; no overwrite; no resume+dry-run")
    print("GATE verifier is separate/non-circular; this runner never writes it")
    for cell in cells:
        env_str = " ".join(f"{k}={v}" for k, v in sorted(cell.env.items()))
        print(f"RUN {env_str} " + " ".join(cell.display_argv))
    return 0


# ---------------------------------------------------------------------------
# Resume validation
# ---------------------------------------------------------------------------

def validate_resume(existing: dict, results_root: pathlib.Path, evidence_mode: str,
                    source_commit: str, git_dirty: bool, build_type: str,
                    binary_sha: str, cells) -> dict:
    if existing.get("schema_version") != SCHEMA:
        fail("resume manifest schema_version mismatch")
    if existing.get("evidence_mode") != evidence_mode:
        fail("resume evidence_mode mismatch")
    if existing.get("source_commit") != source_commit:
        fail("resume source_commit mismatch")
    if existing.get("git_dirty") != ("true" if git_dirty else "false"):
        fail("resume git_dirty mismatch")
    if existing.get("build_type") != build_type:
        fail("resume build_type mismatch")
    if existing.get("bench_real_datasets_sha256") != binary_sha:
        fail("resume bench_real_datasets binary SHA-256 mismatch")

    cell_count = int(existing.get("cell_count", "-1"))
    if cell_count < 0:
        fail("resume manifest missing a valid cell_count")
    completed = {}
    wanted_by_id = {cell.cell_id: cell for cell in cells}
    for index in range(cell_count):
        prefix = f"cell.{index:03d}"
        cell_id = existing.get(f"{prefix}.id")
        if cell_id is None:
            fail(f"resume manifest is missing {prefix}.id")
        if cell_id not in wanted_by_id:
            fail(f"resume manifest contains an unexpected cell id: {cell_id!r}")
        wanted = wanted_by_id[cell_id]
        wanted_argv = wanted.display_argv
        wanted_sha = argv_sha256(wanted_argv)
        recorded_sha = existing.get(f"{prefix}.argv_sha256")
        if recorded_sha != wanted_sha:
            fail(f"resume argv_sha256 mismatch for cell {cell_id!r}")
        recorded_argv_count = int(existing.get(f"{prefix}.argv_count", "-1"))
        recorded_argv = [existing.get(f"{prefix}.argv.{i:03d}")
                        for i in range(recorded_argv_count)]
        if recorded_argv != wanted_argv:
            fail(f"resume argv mismatch for cell {cell_id!r}")
        status = existing.get(f"{prefix}.status")
        if status != "complete":
            fail(f"resume manifest has a non-complete cell {cell_id!r} "
                 f"(status={status!r}); a failed/inconsistent cell must abort, "
                 "not resume")
        output_count = int(existing.get(f"{prefix}.output_count", "-1"))
        for i in range(output_count):
            rel_path = existing.get(f"{prefix}.output.{i:03d}.path")
            declared_sha = existing.get(f"{prefix}.output.{i:03d}.sha256")
            path = ensure_contained(results_root, rel_path, f"cell {cell_id!r} output")
            if not path.is_file():
                fail(f"resume output is missing for cell {cell_id!r}: {rel_path}")
            if sha256_file(path) != declared_sha:
                fail(f"resume output checksum mismatch for cell {cell_id!r}: {rel_path}")
        input_count = int(existing.get(f"{prefix}.input_count", "-1"))
        if input_count != len(wanted.input_specs):
            fail(f"resume input_count mismatch for cell {cell_id!r}")
        for i in range(input_count):
            declared_role = existing.get(f"{prefix}.input.{i:03d}.role")
            declared_root_id = existing.get(f"{prefix}.input.{i:03d}.root_id")
            declared_path = existing.get(f"{prefix}.input.{i:03d}.path")
            declared_sha = existing.get(f"{prefix}.input.{i:03d}.sha256")
            wanted_role, wanted_root_id, wanted_root_path, wanted_rel_path = \
                wanted.input_specs[i]
            if (declared_role, declared_root_id, declared_path) != \
                    (wanted_role, wanted_root_id, wanted_rel_path):
                fail(f"resume input identity mismatch for cell {cell_id!r}")
            input_path = (wanted_root_path / wanted_rel_path).resolve(strict=True)
            if not input_path.is_file():
                fail(f"resume input is missing for cell {cell_id!r}: {wanted_rel_path}")
            if sha256_file(input_path) != declared_sha:
                fail(f"resume input checksum mismatch for cell {cell_id!r}: "
                     f"{wanted_rel_path}")
        completed[cell_id] = True
    return completed


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def next_partial_index(results_root: pathlib.Path) -> int:
    existing = sorted(results_root.glob("run.log.partial.*"))
    indices = []
    for path in existing:
        suffix = path.name.rsplit(".", 1)[-1]
        if suffix.isdigit():
            indices.append(int(suffix))
    return (max(indices) + 1) if indices else 1


def execute(args, project: pathlib.Path) -> int:
    build_dir = pathlib.Path(args.build_dir)
    results_root = pathlib.Path(args.results_root)
    if not build_dir.is_absolute():
        fail("--build-dir must be an absolute path")
    if not results_root.is_absolute():
        fail("--results-root must be an absolute path")
    build_dir = build_dir.resolve(strict=True)
    if not build_dir.is_dir():
        fail("--build-dir is not a directory")
    results_root_parent_resolved = results_root.parent.resolve(strict=True)
    results_root = results_root_parent_resolved / results_root.name

    if args.resume:
        if not results_root.is_dir():
            fail("--resume requires an existing --results-root")
    elif results_root.exists():
        fail("--results-root already exists; use a new path or --resume")

    binary_path = build_dir / "bench_real_datasets"
    if (binary_path.parent.resolve() != build_dir or not binary_path.is_file()
            or not os.access(binary_path, os.X_OK)):
        fail("bench_real_datasets executable is missing from --build-dir")
    summarizer_path = REPO_ROOT / "scripts" / "summarize_real_datasets.py"
    if not summarizer_path.is_file():
        fail("scripts/summarize_real_datasets.py is missing from the committed source root")

    commit, dirty = source_identity(
        project, tracked_only=(args.evidence_mode == "single-trial-validation"))
    if args.evidence_mode in ("paper", "single-trial-validation"):
        if dirty:
            fail(f"evidence_mode={args.evidence_mode} requires a clean source tree")
        build_type = read_build_type(build_dir)
        if build_type != "Release":
            fail(f"evidence_mode={args.evidence_mode} requires CMAKE_BUILD_TYPE=Release")
    else:
        build_type = read_build_type(build_dir)

    binary_sha = sha256_file(binary_path)
    summarizer_sha = sha256_file(summarizer_path)

    roots_by_variant = {}
    for pair in args.pairs:
        if args.evidence_mode == "single-trial-validation":
            validate_single_trial_pair(pair)
        roots_by_variant[pair.variant] = {
            "source": pair.source_manifest.parent,
            "processed": pair.dataset_manifest.parent,
        }

    cells = build_cells(args.pairs, results_root, roots_by_variant,
                        args.evidence_mode, args.seed, args.threads, args.profiles)

    root_pairs, root_ids = build_roots_section(results_root, build_dir, args.pairs,
                                               roots_by_variant)

    existing_completed = {}
    if args.resume:
        run_metadata_path = results_root / "run_metadata.tsv"
        if not run_metadata_path.is_file():
            fail("--resume requires an existing run_metadata.tsv")
        existing = read_kv(run_metadata_path)
        existing_completed = validate_resume(
            existing, results_root, args.evidence_mode, commit, dirty, build_type,
            binary_sha, cells)
        already_finalized = (results_root / "run.log").is_file()
        if already_finalized and len(existing_completed) == len(cells):
            print("RESUME already complete and finalized; nothing to do")
            return 0
    else:
        results_root.mkdir(mode=0o755, parents=False)
        for sub in ("csv", "workloads", "input_manifests"):
            (results_root / sub).mkdir()
        for pair in args.pairs:
            variant_dir = results_root / "input_manifests" / pair.variant
            variant_dir.mkdir()
            _copy_file(pair.source_manifest, variant_dir / "source.manifest.tsv")
            _copy_file(pair.dataset_manifest, variant_dir / "dataset.manifest.tsv")

    system_info_path = results_root / "system_info.txt"
    if not system_info_path.is_file():
        system_info_path.write_text(_system_info_text(), encoding="utf-8")

    partial_index = next_partial_index(results_root)
    partial_path = results_root / f"run.log.partial.{partial_index:03d}"
    log_lines = []

    for cell in cells:
        if existing_completed.get(cell.cell_id):
            print(f"RESUME skip {cell.cell_id}")
            continue

        for out_path in cell.output_paths:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if out_path.exists():
                fail(f"refusing to overwrite existing output: {out_path}")

        if cell.display_argv[0] == "bench_real_datasets":
            exec_argv = [str(binary_path)] + cell.display_argv[1:]
        else:
            exec_argv = [sys.executable, str(summarizer_path)] + cell.display_argv[1:]

        environment = os.environ.copy()
        environment.update(cell.env)
        env_str = " ".join(f"{k}={v}" for k, v in sorted(cell.env.items()))
        print(f"RUN {env_str} " + " ".join(cell.display_argv))
        log_lines.append(f"=== cell {cell.cell_id} ===")
        log_lines.append("$ " + " ".join(cell.display_argv))
        result = subprocess.run(exec_argv, env=environment, capture_output=True,
                                text=True, check=False)
        log_lines.append(result.stdout)
        log_lines.append(result.stderr)
        log_lines.append(f"=== end cell {cell.cell_id} (exit={result.returncode}) ===")

        if result.returncode != 0:
            _write_partial(partial_path, log_lines)
            _write_run_metadata(
                results_root, args, commit, dirty, build_type, binary_sha,
                summarizer_sha, root_pairs, cells, existing_completed, cell.cell_id,
                failed=True)
            detail = result.stderr.strip() or result.stdout.strip()
            print(f"CELL FAILED {cell.cell_id}: {detail}", file=sys.stderr)
            return 2

        for out_path in cell.output_paths:
            if not out_path.is_file():
                fail(f"cell {cell.cell_id} did not produce expected output: {out_path}")
        existing_completed[cell.cell_id] = True
        _write_run_metadata(
            results_root, args, commit, dirty, build_type, binary_sha,
            summarizer_sha, root_pairs, cells, existing_completed, None, failed=False)

    _write_partial(partial_path, log_lines)

    all_complete = all(existing_completed.get(cell.cell_id) for cell in cells)
    if all_complete:
        _finalize_run_log(results_root)
        _write_run_metadata(
            results_root, args, commit, dirty, build_type, binary_sha,
            summarizer_sha, root_pairs, cells, existing_completed, None, failed=False,
            finalize=True)
    return 0


def _copy_file(src: pathlib.Path, dst: pathlib.Path) -> None:
    data = src.read_bytes()
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dst.name}.tmp-", dir=str(dst.parent))
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_name, dst)


def _system_info_text() -> str:
    lines = [
        f"os: {platform.platform()}",
        f"machine: {platform.machine()}",
        f"processor: {platform.processor() or 'unknown'}",
        f"python_version: {platform.python_version()}",
    ]
    return "\n".join(lines) + "\n"


def _write_partial(partial_path: pathlib.Path, log_lines) -> None:
    data = ("\n".join(log_lines) + "\n").encode("utf-8")
    with open(partial_path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _finalize_run_log(results_root: pathlib.Path) -> None:
    partials = sorted(results_root.glob("run.log.partial.*"),
                      key=lambda p: int(p.name.rsplit(".", 1)[-1]))
    combined = bytearray()
    for partial in partials:
        combined.extend(partial.read_bytes())
    run_log_path = results_root / "run.log"
    fd, tmp_name = tempfile.mkstemp(prefix=".run.log.tmp-", dir=str(results_root))
    with os.fdopen(fd, "wb") as handle:
        handle.write(bytes(combined))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_name, run_log_path)
    for partial in partials:
        partial.unlink()


def _write_run_metadata(results_root, args, commit, dirty, build_type, binary_sha,
                        summarizer_sha, root_pairs, cells, completed, failed_cell_id,
                        *, failed: bool, finalize: bool = False) -> None:
    pairs = [
        ("schema_version", SCHEMA),
        ("evidence_mode", args.evidence_mode),
        ("source_commit", commit),
        ("git_dirty", "true" if dirty else "false"),
        ("build_type", build_type),
        ("bench_real_datasets_sha256", binary_sha),
        ("summarize_real_datasets_sha256", summarizer_sha),
    ]
    pairs.extend(root_pairs)

    artifacts = []
    system_info_path = results_root / "system_info.txt"
    artifacts.append(("system-info", "system_info.txt", sha256_file(system_info_path)))
    seen_variants = set()
    for pair in args.pairs:
        if pair.variant in seen_variants:
            continue
        seen_variants.add(pair.variant)
        variant_dir = results_root / "input_manifests" / pair.variant
        artifacts.append((
            f"copied-source-manifest-{pair.variant}",
            f"input_manifests/{pair.variant}/source.manifest.tsv",
            sha256_file(variant_dir / "source.manifest.tsv")))
        artifacts.append((
            f"copied-processed-manifest-{pair.variant}",
            f"input_manifests/{pair.variant}/dataset.manifest.tsv",
            sha256_file(variant_dir / "dataset.manifest.tsv")))
    run_log_path = results_root / "run.log"
    if finalize and run_log_path.is_file():
        artifacts.append(("run-log", "run.log", sha256_file(run_log_path)))

    pairs.append(("artifact_count", str(len(artifacts))))
    for index, (role, path, sha) in enumerate(artifacts):
        prefix = f"artifact.{index:03d}"
        pairs.append((f"{prefix}.role", role))
        pairs.append((f"{prefix}.path", path))
        pairs.append((f"{prefix}.sha256", sha))

    complete_cells = [cell for cell in cells if completed.get(cell.cell_id)]
    if failed:
        failed_cell = next(c for c in cells if c.cell_id == failed_cell_id)
        pairs.append(("cell_count", str(len(complete_cells) + 1)))
        for index, cell in enumerate(complete_cells):
            pairs.extend(_prefixed(f"cell.{index:03d}", build_cell_section(cell, results_root)))
        fail_index = len(complete_cells)
        prefix = f"cell.{fail_index:03d}"
        pairs.append((f"{prefix}.id", failed_cell.cell_id))
        argv = failed_cell.display_argv
        pairs.append((f"{prefix}.argv_count", str(len(argv))))
        for i, arg in enumerate(argv):
            pairs.append((f"{prefix}.argv.{i:03d}", arg))
        pairs.append((f"{prefix}.argv_sha256", argv_sha256(argv)))
        env_items = sorted(failed_cell.env.items())
        pairs.append((f"{prefix}.env_count", str(len(env_items))))
        for i, (k, v) in enumerate(env_items):
            pairs.append((f"{prefix}.env.{i:03d}.key", k))
            pairs.append((f"{prefix}.env.{i:03d}.value", v))
        pairs.append((f"{prefix}.input_count", "0"))
        pairs.append((f"{prefix}.output_count", "0"))
        pairs.append((f"{prefix}.status", "failed"))
    else:
        pairs.append(("cell_count", str(len(complete_cells))))
        for index, cell in enumerate(complete_cells):
            pairs.extend(_prefixed(f"cell.{index:03d}", build_cell_section(cell, results_root)))

    write_kv(results_root / "run_metadata.tsv", pairs)


def _prefixed(prefix, items):
    return [(f"{prefix}.{k}", v) for k, v in items]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-manifest", action="append", default=[])
    parser.add_argument("--dataset-manifest", action="append", default=[])
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--single-trial-validation", action="store_true")
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--threads", required=True, type=int)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if args.seed <= 0:
        parser.error("--seed must be a positive integer")
    if args.threads <= 0:
        parser.error("--threads must be a positive integer")
    if args.resume and args.dry_run:
        parser.error("--resume cannot be combined with --dry-run")
    if not pathlib.Path(args.build_dir).is_absolute():
        parser.error("--build-dir must be an absolute path")
    if not pathlib.Path(args.results_root).is_absolute():
        parser.error("--results-root must be an absolute path")

    has_manifests = bool(args.source_manifest) or bool(args.dataset_manifest)
    if args.quick and (has_manifests or args.profile or args.single_trial_validation):
        parser.error("--quick cannot be combined with --source-manifest/"
                     "--dataset-manifest/--profile/--single-trial-validation")
    if not args.quick and not has_manifests:
        parser.error("specify --quick or at least one --source-manifest/"
                     "--dataset-manifest pair")
    if len(args.source_manifest) != len(args.dataset_manifest):
        parser.error("--source-manifest and --dataset-manifest must be given "
                     "in equal-length, positionally paired counts")

    if args.quick:
        args.evidence_mode = "quick"
        args.pairs = [load_manifest_pair(QUICK_SOURCE_MANIFEST, QUICK_DATASET_MANIFEST)]
        args.profiles = ()
    elif args.single_trial_validation:
        if args.profile:
            parser.error("--single-trial-validation pins its two Work #5 profiles; "
                         "do not pass --profile")
        if len(args.source_manifest) != 1 or len(args.dataset_manifest) != 1:
            parser.error("--single-trial-validation requires exactly one "
                         "--source-manifest/--dataset-manifest pair")
        if args.seed != SINGLE_TRIAL_SEED:
            parser.error(f"--single-trial-validation freezes --seed={SINGLE_TRIAL_SEED}")
        if args.threads != SINGLE_TRIAL_THREADS:
            parser.error(f"--single-trial-validation freezes --threads={SINGLE_TRIAL_THREADS}")
        args.evidence_mode = "single-trial-validation"
        args.pairs = [load_manifest_pair(pathlib.Path(args.source_manifest[0]),
                                         pathlib.Path(args.dataset_manifest[0]))]
        args.profiles = SINGLE_TRIAL_PROFILES
    else:
        args.evidence_mode = "paper"
        seen = set()
        pairs = []
        for source_raw, dataset_raw in zip(args.source_manifest, args.dataset_manifest):
            pair = load_manifest_pair(pathlib.Path(source_raw), pathlib.Path(dataset_raw))
            if pair.variant in seen:
                parser.error(f"duplicate variant across manifest pairs: {pair.variant!r}")
            seen.add(pair.variant)
            pairs.append(pair)
        args.pairs = pairs
        if not args.profile:
            parser.error("evidence_mode=paper requires at least one --profile")
        if set(args.profile) != set(PAPER_PROFILES) or len(args.profile) != len(PAPER_PROFILES):
            parser.error(
                f"--profile must specify exactly {PAPER_PROFILES}, got {args.profile!r}")
        args.profiles = tuple(args.profile)

    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    project = REPO_ROOT
    if args.dry_run:
        results_root = pathlib.Path(args.results_root)
        build_dir = pathlib.Path(args.build_dir)
        if args.evidence_mode == "single-trial-validation":
            validate_single_trial_pair(args.pairs[0])
        roots_by_variant = {
            pair.variant: {"source": pair.source_manifest.parent,
                          "processed": pair.dataset_manifest.parent}
            for pair in args.pairs
        }
        cells = build_cells(args.pairs, results_root, roots_by_variant,
                           args.evidence_mode, args.seed, args.threads, args.profiles)
        _ = build_dir
        return dry_run(cells)
    try:
        return execute(args, project)
    except RunnerError as error:
        print(f"run_real_datasets: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
PY
