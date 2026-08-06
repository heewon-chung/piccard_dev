#!/usr/bin/env python3
"""Run the deliberately small, fail-closed Work 7 Phase 2 integration gate."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:  # Module execution and unittest package import use different sys.path roots.
    from work7_evidence import (canonical_json_bytes, create_tree_seal,
                                sha256_file, snapshot_git_worktree)
except ModuleNotFoundError:
    from scripts.work7_evidence import (canonical_json_bytes, create_tree_seal,
                                        sha256_file, snapshot_git_worktree)

# This is deliberately a literal registry, rather than an inventory-derived set.
FROZEN_CTESTS = (
    "MinHash", "EstimatorDiagnostic", "EstimatorProvenanceSerializers",
    "SecurityProfile", "Params", "NoiseCalibrationCutoverProbeV2", "NoisePreThresholdCoverage",
    "BenchmarkProfile", "BaselineProfile", "ComparisonWorkload", "ReviewComparisonCli",
    "VerifyReviewComparison", "VerifySJ16Extrapolation",
    "RealDataset", "RealDatasetMetrics", "RealDatasetTiming", "RealDatasetPreprocess", "RunRealDatasets",
    "DynamicCiphertextStore", "DynamicRefreshE2E", "DynamicRefreshBenchmark", "DeletionSurvival",
    "DeletionMonteCarlo", "DeletionSurvivalCli",
    "Work7StateGuard", "Work7ClaimContract", "Work7IntegrationRunner", "Work7ResponseCandidate",
)


class Failure(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Failure(f"invalid arguments: {message}")


def parser() -> argparse.ArgumentParser:
    value = Parser(add_help=False)
    for name in ("source-root", "paper-root", "threshold-root", "build-parent", "session-parent"):
        value.add_argument("--" + name, required=True, type=Path)
    value.add_argument("--expected-source-branch", required=True)
    return value


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def require_absolute(path: Path, name: str) -> Path:
    if not path.is_absolute():
        raise Failure(f"{name} must be an absolute path")
    if not path.is_dir():
        raise Failure(f"{name} must be an existing directory")
    return path.resolve()


def git_head(source: Path) -> str:
    item = subprocess.run(("git", "rev-parse", "HEAD"), cwd=source, check=False,
                          capture_output=True, text=True, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    if item.returncode or not __import__("re").fullmatch(r"[0-9a-f]{40}", item.stdout.strip()):
        raise Failure("cannot determine clean source commit")
    return item.stdout.strip()


def reserve(parent: Path, name: str) -> Path:
    target = parent / name
    try:
        target.mkdir(mode=0o700)
    except FileExistsError as error:
        raise Failure(f"output root already exists: {target}") from error
    return target


def executable_digest(argv: tuple[str, ...], cwd: Path) -> str:
    command = argv[0]
    candidate = Path(command) if "/" in command else Path(shutil.which(command) or "")
    if not candidate:
        return "unresolved"
    try:
        return sha256_file(candidate.resolve())
    except (OSError, ValueError):
        return "unreadable"


def checked_command(argv: tuple[str, ...], cwd: Path, records: Path, label: str) -> Path:
    """Run exactly once, retaining complete output and immutable provenance."""
    records.mkdir(parents=True, exist_ok=True)
    output = records / f"{label}.stdout.txt"
    error = records / f"{label}.stderr.txt"
    started = now()
    result = subprocess.run(argv, cwd=cwd, check=False, capture_output=True)
    ended = now()
    output.write_bytes(result.stdout)
    error.write_bytes(result.stderr)
    record = {"argv": list(argv), "cwd": str(cwd), "started_at": started, "ended_at": ended,
              "returncode": result.returncode, "stdout": output.name, "stderr": error.name,
              "executable_sha256": executable_digest(argv, cwd)}
    (records / f"{label}.json").write_bytes(canonical_json_bytes(record))
    if result.returncode:
        raise Failure(f"command failed: {label}")
    return output


def inventory_names(path: Path) -> set[str]:
    import re
    found = set(re.findall(r"^\s*Test\s+#\d+: ([A-Za-z0-9_]+)$", path.read_text(errors="replace"), re.M))
    if not found or "No tests were found" in path.read_text(errors="replace"):
        raise Failure("CTest inventory is empty")
    return found


def validate_records(root: Path) -> None:
    """Reject repeated measurement, non-toy data, invalid CSV, and bad warmups."""
    count_names = {"trials", "accuracy_trials", "accuracy-trials", "refresh_updates", "refresh-updates", "reps", "iterations"}
    def validate_value(value: object, location: str, timing: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = key.lower().replace("-", "_")
                if normalized in {item.replace("-", "_") for item in count_names} and item != 1:
                    raise Failure("measured count must equal 1")
                if "warmup" in normalized:
                    if normalized not in {"warmup", "discarded_warmup", "warmup_count"} or item not in (0, 1, "discarded", "discarded_warmup"):
                        raise Failure("unlabelled or multiple warmups")
                    if not timing:
                        raise Failure("warmup outside timing cell")
                validate_value(item, location, timing or "timing" in normalized)
        elif isinstance(value, list):
            for item in value:
                validate_value(item, location, timing)
        elif isinstance(value, str) and any(token in value.lower() for token in ("enron", "actual-data", "paper-manifest")):
            raise Failure("actual-data artifact path is forbidden")
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        lower = path.as_posix().lower()
        if any(token in lower for token in ("enron", "actual-data", "paper-manifest")):
            raise Failure("actual-data artifact path is forbidden")
        if path.suffix.lower() != ".csv":
            if path.suffix.lower() == ".json":
                try:
                    validate_value(json.loads(path.read_text(encoding="utf-8")), path.as_posix())
                except json.JSONDecodeError as error:
                    raise Failure("malformed JSON artifact") from error
            continue
        try:
            with path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
                headers = set(rows[0]) if rows else set()
        except (OSError, UnicodeError, csv.Error) as error:
            raise Failure("malformed CSV artifact") from error
        if not rows or not headers:
            raise Failure("malformed CSV artifact")
        for row in rows:
            for key, raw in row.items():
                normalized = key.lower().replace("-", "_")
                if normalized in {item.replace("-", "_") for item in count_names}:
                    if raw != "1":
                        raise Failure("measured count must equal 1")
                if "warmup" in normalized:
                    if raw not in ("", "0", "1", "discarded", "discarded_warmup"):
                        raise Failure("unlabelled warmup")
                    if raw in ("1", "discarded", "discarded_warmup") and "timing" not in lower:
                        raise Failure("warmup outside timing cell")


def artifact(path: Path, root: Path, kind: str) -> dict[str, str]:
    return {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path), "artifact_kind": kind}


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        source = require_absolute(args.source_root, "source-root")
        paper = require_absolute(args.paper_root, "paper-root")
        threshold = require_absolute(args.threshold_root, "threshold-root")
        build_parent = require_absolute(args.build_parent, "build-parent")
        session_parent = require_absolute(args.session_parent, "session-parent")
        commit = git_head(source)
        build = reserve(build_parent, "build-" + commit)
        session = reserve(session_parent, "session-" + commit)
        phase0_artifacts = session / "phase0" / "artifacts"
        phase0_artifacts.mkdir(parents=True)
        state = phase0_artifacts / "state.json"
        commands = session / "phase2" / "runtime" / "commands"
        guard = (sys.executable, str(source / "scripts" / "work7_state_guard.py"),
                 "--source-root", str(source), "--paper-root", str(paper), "--threshold-root", str(threshold),
                 "--build-root", str(build), "--session-root", str(session),
                 "--expected-source-branch", args.expected_source_branch, "--expected-source-commit", commit,
                 "--output", str(state))
        checked_command(guard, source, commands, "phase0-guard")
        phase0_seal = session / "phase0" / "seal.json"
        create_tree_seal(phase0_artifacts, phase0_seal, None, "phase0-artifacts")
        configure = ("cmake", "-S", str(source), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release",
                     "-DBUILD_TESTS=ON", "-DBUILD_BENCHMARKS=ON")
        configure_log = checked_command(configure, source, commands, "configure")
        text = configure_log.read_text(errors="replace").lower()
        if any(name not in text for name in ("openfhe", "gmp", "gtest", "python")):
            raise Failure("configure evidence missing required dependency")
        checked_command(("cmake", "--build", str(build), "--parallel", "2"), source, commands, "build")
        inventory = checked_command(("ctest", "--test-dir", str(build), "-N"), source, commands, "ctest-inventory")
        present = inventory_names(inventory)
        missing = set(FROZEN_CTESTS) - present
        if missing:
            raise Failure("frozen CTest is missing: " + sorted(missing)[0])
        phase2 = session / "phase2"
        static = phase2 / "static-report.json"
        checked_command((sys.executable, str(source / "scripts" / "verify_work7_claims.py"), "--mode", "static",
                         "--contract", str(source / "scripts" / "work7_claims.json"), "--source-root", str(source),
                         "--source-commit", commit, "--ctest-inventory", str(inventory), "--output", str(static)), source, commands, "static")
        regex = "^(" + "|".join(FROZEN_CTESTS) + ")$"
        ctest_log = checked_command(("ctest", "--test-dir", str(build), "--output-on-failure", "-R", regex), source, commands, "ctest-focused")
        ctest_text = ctest_log.read_text(errors="replace")
        if "Not Run" in ctest_text or "Skipped" in ctest_text or "No tests were found" in ctest_text:
            raise Failure("required CTest was skipped")
        runtime = phase2 / "runtime"
        pre = runtime / "pre-threshold"
        real = runtime / "real-datasets"
        checked_command((str(source / "scripts" / "run_pre_threshold_profiles.sh"), "--suite=smoke", "--seed=7", "--threads=2", "--build-dir=" + str(build), "--results-root=" + str(pre)), source, commands, "pre-threshold")
        checked_command((str(source / "scripts" / "run_real_datasets.sh"), "--quick", "--seed=7", "--threads=2", "--build-dir=" + str(build), "--results-root=" + str(real)), source, commands, "real-datasets")
        deletion = checked_command((str(build / "bench_deletion_survival"), "--n=64", "--d=3", "--k=8", "--required_survival=0.99", "--r_values=1,4,8", "--trials=1", "--seed=7"), source, commands, "deletion-survival")
        validate_records(runtime)
        index = runtime / "evidence-index.json"
        static_runtime = runtime / "static-report.json"
        shutil.copyfile(static, static_runtime)
        index.write_bytes(canonical_json_bytes({"schema": "piccard-work7-evidence-index-v2", "source_commit": commit, "claims": {
            "W7-G1-ESTIMATOR": {"estimator-functional": artifact(ctest_log, runtime, "ctest-log")},
            "W7-G2-SANITIZER": {"sanitizer-profile": artifact(inventory, runtime, "ctest-log")},
            "W7-G3-CALIBRATION": {"calibration-selection": artifact(static_runtime, runtime, "probe-output")},
            "W7-G4-COMPARISON": {"comparison-toy": artifact(pre / "run-manifest.json", runtime, "csv-artifact")},
            "W7-G5-REAL-DATA": {"synthetic-real-data": artifact(real / "run-metadata.tsv", runtime, "csv-artifact")},
            "W7-G6-DYNAMIC": {"dynamic-deletion-toy": artifact(deletion, runtime, "probe-output")},
        }}))
        runtime_seal = phase2 / "runtime-seal.json"
        create_tree_seal(runtime, runtime_seal, sha256_file(phase0_seal), "phase2-runtime-artifacts")
        closure = phase2 / "closure-artifacts"
        closure.mkdir()
        evidence = closure / "evidence-bound-report.json"
        checked_command((sys.executable, str(source / "scripts" / "verify_work7_claims.py"), "--mode", "evidence-bound",
                         "--contract", str(source / "scripts" / "work7_claims.json"), "--source-root", str(source),
                         "--source-commit", commit, "--ctest-inventory", str(inventory), "--runtime-seal", str(runtime_seal),
                         "--output", str(evidence)), source, closure / "commands", "evidence-bound")
        closure_seal = phase2 / "closure-seal.json"
        create_tree_seal(closure, closure_seal, sha256_file(runtime_seal), "phase2-closure-artifacts")
        initial = json.loads(state.read_text())
        for name, root in (("paper", paper), ("threshold", threshold)):
            if snapshot_git_worktree(root)["snapshot_sha256"] != initial[name]["snapshot_sha256"]:
                raise Failure("external snapshot changed: " + name)
    except (Failure, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"run_work7_integration: FAIL: {error}", file=sys.stderr)
        return 2
    print("run_work7_integration: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
