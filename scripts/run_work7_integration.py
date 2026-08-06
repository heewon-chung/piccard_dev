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
                                sha256_file, snapshot_git_worktree, verify_tree_seal)
except ModuleNotFoundError:
    from scripts.work7_evidence import (canonical_json_bytes, create_tree_seal,
                                        sha256_file, snapshot_git_worktree, verify_tree_seal)

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
                strict_rows = list(csv.reader(handle, strict=True))
            with path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
                headers = set(rows[0]) if rows else set()
        except (OSError, UnicodeError, csv.Error) as error:
            raise Failure("malformed CSV artifact") from error
        if len(strict_rows) < 2 or not rows or not headers:
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


def validate_claim_report(path: Path, commit: str, mode: str) -> None:
    """Do not trust a successful verifier executable with foreign output."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("malformed claim verifier report") from error
    if not isinstance(value, dict) or value.get("schema") != "piccard-work7-claim-report-v1" or value.get("source_commit") != commit or value.get("mode") != mode or value.get("status") != "PASS":
        raise Failure("foreign source commit or invalid claim verifier report")


def load_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Failure(f"malformed {label}") from error
    if not isinstance(value, dict): raise Failure(f"malformed {label}")
    return value


def sealed_file(root: Path, relative: object, digest: object, label: str) -> Path:
    if not isinstance(relative, str) or not isinstance(digest, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise Failure(f"invalid {label} path")
    try: candidate=(root/relative).resolve(strict=True); candidate.relative_to(root.resolve())
    except (OSError, ValueError): raise Failure(f"invalid {label} path") from None
    if not candidate.is_file() or sha256_file(candidate)!=digest: raise Failure(f"invalid {label} digest")
    return candidate


def validate_prethreshold(root: Path, commit: str, command: tuple[str, ...]) -> Path:
    path = root / "manifest.json"; value = load_json(path, "pre-threshold manifest")
    if value.get("schema") != "piccard-pre-threshold-run-v1" or value.get("suite") != "smoke" or value.get("seed") != 7 or value.get("repetitions") != 1:
        raise Failure("invalid pre-threshold manifest identity")
    if value.get("source", {}).get("commit") != commit or value.get("source", {}).get("dirty") is not False or value.get("thread_policy") != {"OMP_DYNAMIC":"FALSE", "OMP_NUM_THREADS":"2"}:
        raise Failure("invalid pre-threshold provenance")
    cells = value.get("cells")
    if not isinstance(cells, list) or len(cells) != 3 or {row.get("producer") for row in cells if isinstance(row, dict)} != {"bench_review_comparison", "bench_piccard", "bench_dynamic"}:
        raise Failure("invalid pre-threshold cells")
    expected={"bench_review_comparison": {"--trials=1","--accuracy-trials=1","--seed=7"}, "bench_piccard":{"--trials=1","--seed=7"}, "bench_dynamic":{"--scenario=refresh","--refresh_updates=1","--trials=1","--seed=7"}}
    for row in cells:
        argv=row.get("argv")
        sampling=[x for x in argv if isinstance(x,str) and (x.startswith("--trials=") or x.startswith("--accuracy-trials=") or x.startswith("--refresh_updates="))] if isinstance(argv,list) else []
        if row.get("status") != "MEASURED" or not isinstance(argv,list) or set(argv[1:]) != expected[row["producer"]] or len(sampling) != len(set(sampling)):
            raise Failure("pre-threshold row/argv mismatch")
    terminal=value.get("terminal_cells")
    if not isinstance(terminal,dict) or set(terminal)!={"path","row_count","sha256"} or terminal["path"]!="terminal-cells.tsv" or terminal["row_count"]!=3:
        raise Failure("missing pre-threshold terminal cells")
    terminal_path=root/terminal["path"]
    if not terminal_path.is_file() or sha256_file(terminal_path)!=terminal["sha256"] or len(terminal_path.read_text(encoding="utf-8").splitlines())!=4:
        raise Failure("invalid pre-threshold terminal cells")
    for row in cells:
        output=row.get("output", {})
        if not isinstance(output,dict): raise Failure("missing pre-threshold output")
        for key, relative in output.items():
            if key.endswith("_sha256") or key in {"expected_csv_rows","csv_row_count","measurement_output"}: continue
            digest_key=key+"_sha256"
            if digest_key not in output: raise Failure("missing pre-threshold artifact digest")
            sealed_file(root, relative, output[digest_key], "pre-threshold artifact")
    return path


def read_tsv(path: Path) -> dict[str, str]:
    try:
        rows = list(csv.reader(path.open(newline="", encoding="utf-8"), delimiter="\t", strict=True))
    except (OSError, UnicodeError, csv.Error) as error: raise Failure("malformed real-data TSV") from error
    if not rows or rows[0] != ["key", "value"] or any(len(row) != 2 for row in rows[1:]) or len(rows) < 2: raise Failure("malformed real-data TSV")
    value = dict(rows[1:])
    if len(value) != len(rows)-1: raise Failure("duplicate real-data TSV key")
    return value


def validate_real(root: Path, commit: str, build: Path) -> Path:
    metadata = root / "run_metadata.tsv"; value = read_tsv(metadata)
    if value.get("schema_version") != "piccard-real-run-v1" or value.get("evidence_mode") != "quick" or value.get("source_commit") != commit or value.get("git_dirty") != "false" or value.get("build_type") != "Release" or value.get("cell_count") != "3":
        raise Failure("invalid real-data metadata")
    artifact_count=value.get("artifact_count")
    if artifact_count is None or not artifact_count.isdigit(): raise Failure("invalid real-data artifact count")
    expected_keys=set()
    for number in range(int(artifact_count)):
        prefix=f"artifact.{number:03d}."; expected_keys |= {prefix+"role",prefix+"path",prefix+"sha256"}
        relative=value.get(prefix+"path"); digest=value.get(prefix+"sha256")
        sealed_file(root, relative, digest, "real-data artifact")
    if any(key.startswith("artifact.") and key not in expected_keys for key in value): raise Failure("extra real-data artifact entry")
    for number in range(3):
        prefix=f"cell.{number:03d}."
        if value.get(prefix+"status") != "complete" or value.get(prefix+"argv_count") in (None,"0") or value.get(prefix+"argv.000") is None or value.get(prefix+"output_count") in (None,"0"): raise Failure("invalid real-data cell")
        args=[value[prefix+f"argv.{i:03d}"] for i in range(int(value[prefix+"argv_count"]))]
        expected={"dblp_acm_u65536:accuracy":["bench_real_datasets","--accuracy_trials=1"],"dblp_acm_u65536:accuracy-summary":["summarize_real_datasets.py"],"dblp_acm_u65536:timing:toy-smoke":["bench_real_datasets","--trials=1"]}
        if value.get(prefix+"id") not in expected or args != expected[value[prefix+"id"]]: raise Failure("real-data argv/count mismatch")
        count=int(value[prefix+"output_count"])
        for index in range(count):
            out=f"{prefix}output.{index:03d}."; relative=value.get(out+"path"); digest=value.get(out+"sha256")
            sealed_file(root, relative, digest, "real-data output")
    status = read_tsv(root / "verification_status.tsv")
    if status != {"schema_version":"piccard-real-verification-v1", "run_metadata_sha256":sha256_file(metadata), "status":"VERIFIED"}: raise Failure("stale real-data verification status")
    return metadata


def validate_deletion(path: Path) -> None:
    header=("model,n,d,k,required_survival,r,exact_survival,union_bound_survival,mc_survival,mc_standard_error,maximum_safe_deletions,exact_expected_first_failure,exact_expected_safe_deletions,mc_mean_first_failure,mc_mean_safe_deletions,trials,seed".split(","))
    try: rows=list(csv.reader(path.open(newline="",encoding="utf-8"), strict=True))
    except (OSError, UnicodeError, csv.Error) as error: raise Failure("malformed deletion CSV") from error
    if len(rows)!=4 or rows[0]!=header or [row[5] for row in rows[1:]] != ["1","4","8"] or any(len(row)!=17 or row[0]!="ideal-independent-random-ranking-v1" or row[1:4]!=["64","3","8"] or row[4]!="0.99" or row[15:]!=["1","7"] for row in rows[1:]): raise Failure("invalid deletion CSV")


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
        create_tree_seal(phase0_artifacts, phase0_seal, None, "phase0")
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
        validate_claim_report(static, commit, "static")
        regex = "^(" + "|".join(FROZEN_CTESTS) + ")$"
        ctest_log = checked_command(("ctest", "--test-dir", str(build), "--output-on-failure", "-R", regex), source, commands, "ctest-focused")
        ctest_text = ctest_log.read_text(errors="replace")
        if "Not Run" in ctest_text or "Skipped" in ctest_text or "No tests were found" in ctest_text:
            raise Failure("required CTest was skipped")
        runtime = phase2 / "runtime"
        pre = runtime / "pre-threshold"
        real = runtime / "real-datasets"
        pre_command=(str(source / "scripts" / "run_pre_threshold_profiles.sh"), "--suite=smoke", "--seed=7", "--threads=2", "--build-dir=" + str(build), "--results-root=" + str(pre))
        checked_command(pre_command, source, commands, "pre-threshold")
        pre_manifest=validate_prethreshold(pre, commit, pre_command)
        checked_command((str(source / "scripts" / "run_real_datasets.sh"), "--quick", "--seed=7", "--threads=2", "--build-dir=" + str(build), "--results-root=" + str(real)), source, commands, "real-datasets")
        checked_command((sys.executable, str(source / "scripts" / "verify_real_dataset_outputs.py"), str(real)), source, commands, "verify-real-datasets")
        deletion = checked_command((str(build / "bench_deletion_survival"), "--n=64", "--d=3", "--k=8", "--required_survival=0.99", "--r_values=1,4,8", "--trials=1", "--seed=7"), source, commands, "deletion-survival")
        validate_real(real, commit, build)
        validate_deletion(deletion)
        validate_records(runtime)
        index = runtime / "evidence-index.json"
        static_runtime = runtime / "static-report.json"
        shutil.copyfile(static, static_runtime)
        index.write_bytes(canonical_json_bytes({"schema": "piccard-work7-evidence-index-v2", "source_commit": commit, "claims": {
            "W7-G1-ESTIMATOR": {"estimator-functional": artifact(ctest_log, runtime, "ctest-log")},
            "W7-G2-SANITIZER": {"sanitizer-profile": artifact(inventory, runtime, "ctest-log")},
            "W7-G3-CALIBRATION": {"calibration-selection": artifact(static_runtime, runtime, "probe-output")},
            "W7-G4-COMPARISON": {"comparison-toy": artifact(pre_manifest, runtime, "csv-artifact")},
            "W7-G5-REAL-DATA": {"synthetic-real-data": artifact(real / "run_metadata.tsv", runtime, "csv-artifact")},
            "W7-G6-DYNAMIC": {"dynamic-deletion-toy": artifact(deletion, runtime, "probe-output")},
        }}))
        runtime_seal = phase2 / "runtime-seal.json"
        create_tree_seal(runtime, runtime_seal, sha256_file(phase0_seal), "phase2-runtime-artifacts")
        verify_tree_seal(runtime_seal, sha256_file(phase0_seal))
        closure = phase2 / "closure-artifacts"
        closure.mkdir()
        evidence = closure / "evidence-bound-report.json"
        checked_command((sys.executable, str(source / "scripts" / "verify_work7_claims.py"), "--mode", "evidence-bound",
                         "--contract", str(source / "scripts" / "work7_claims.json"), "--source-root", str(source),
                         "--source-commit", commit, "--ctest-inventory", str(inventory), "--runtime-seal", str(runtime_seal),
                         "--output", str(evidence)), source, closure / "commands", "evidence-bound")
        verify_tree_seal(runtime_seal, sha256_file(phase0_seal))
        validate_claim_report(evidence, commit, "evidence-bound")
        closure_seal = phase2 / "closure-seal.json"
        create_tree_seal(closure, closure_seal, sha256_file(runtime_seal), "phase2-closure")
        verify_tree_seal(closure_seal, sha256_file(runtime_seal))
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
