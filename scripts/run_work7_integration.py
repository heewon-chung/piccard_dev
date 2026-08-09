#!/usr/bin/env python3
"""Run the deliberately small, fail-closed Work 7 Phase 2 integration gate."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from io import StringIO
from datetime import datetime, timezone
from pathlib import Path

try:  # Module execution and unittest package import use different sys.path roots.
    from work7_evidence import (CapturedBlob, canonical_json_bytes, create_tree_seal,
                                sha256_file, snapshot_git_worktree, verify_tree_seal)
    from work7_run_lifecycle import (ReservationLedger, _record_and_apply_owned_failure,
                                     reserve_owned)
except ModuleNotFoundError:
    from scripts.work7_evidence import (CapturedBlob, canonical_json_bytes, create_tree_seal,
                                        sha256_file, snapshot_git_worktree, verify_tree_seal)
    from scripts.work7_run_lifecycle import (ReservationLedger, _record_and_apply_owned_failure,
                                             reserve_owned)

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


COUNT_NAMES = {"trials", "accuracy_trials", "refresh_updates", "reps", "iterations"}


def validate_count_value(value: object) -> None:
    """Permit one active repetition or an explicitly unmeasured axis."""
    if value is None or value == "":
        return
    if type(value) in (int, float) and value in (0, 1):
        return
    if isinstance(value, str) and value in ("0", "1"):
        return
    raise Failure("measured count must equal 1")


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Failure(f"invalid arguments: {message}")


def parser() -> argparse.ArgumentParser:
    value = Parser(add_help=False)
    for name in ("source-root", "paper-root", "threshold-root", "build-parent", "session-parent",
                 "diagnostic-root"):
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


def require_external_diagnostic_root(diagnostic: Path, guarded: tuple[Path, ...]) -> Path:
    """Keep the durable failure record outside every mutable runner root."""
    for protected in guarded:
        try:
            diagnostic.relative_to(protected)
        except ValueError:
            pass
        else:
            raise Failure("diagnostic-root must be outside runner roots")
        try:
            protected.relative_to(diagnostic)
        except ValueError:
            continue
        raise Failure("diagnostic-root must be outside runner roots")
    return diagnostic


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
    def validate_value(value: object, location: str, timing: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = key.lower().replace("-", "_")
                if normalized in COUNT_NAMES:
                    validate_count_value(item)
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
                if normalized in COUNT_NAMES:
                    validate_count_value(raw)
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


def smoke_parameter_sha256(producer: str, argv: list[str]) -> str:
    values=[producer,"toy-smoke",*[x for x in argv[1:] if not x.startswith("--manifest-out=") and not x.startswith("--execution-trace-out=")],"OMP_DYNAMIC=FALSE","OMP_NUM_THREADS=2"]
    digest=hashlib.sha256(b"piccard-benchmark-cell-v1\0")
    for value in values:
        raw=value.encode(); digest.update(len(raw).to_bytes(4,"big")); digest.update(raw)
    return digest.hexdigest()


def validate_prethreshold(root: Path, commit: str, command: tuple[str, ...], source: Path, build: Path) -> Path:
    path = root / "manifest.json"; value = load_json(path, "pre-threshold manifest")
    top_keys = {"schema", "suite", "seed", "repetitions", "classification", "thread_policy", "profiles", "source", "build", "machine", "directories", "cells", "terminal_cells"}
    if set(value) != top_keys:
        raise Failure("invalid pre-threshold manifest schema")
    if value.get("schema") != "piccard-pre-threshold-run-v1" or value.get("suite") != "smoke" or value.get("seed") != 7 or value.get("repetitions") != 1 or value.get("classification") != "diagnostic" or value.get("profiles") != ["toy-smoke"] or value.get("directories") != {"csv":"csv", "workloads":"workloads", "traces":"traces", "logs":"logs"}:
        raise Failure("invalid pre-threshold manifest identity")
    source_record = value.get("source")
    if not isinstance(source_record, dict) or set(source_record) != {"commit", "dirty", "dir"} or source_record.get("commit") != commit or source_record.get("dirty") is not False or source_record.get("dir") != str(source) or value.get("thread_policy") != {"OMP_DYNAMIC":"FALSE", "OMP_NUM_THREADS":"2"}:
        raise Failure("invalid pre-threshold provenance")
    build_record = value.get("build")
    producers = ("bench_review_comparison", "bench_piccard", "bench_dynamic")
    if not isinstance(build_record, dict) or set(build_record) != {"dir", "type", "binaries"} or build_record.get("dir") != str(build.resolve()) or build_record.get("type") != "Release" or not isinstance(build_record.get("binaries"), dict) or set(build_record["binaries"]) != set(producers):
        raise Failure("invalid pre-threshold build provenance")
    versions = []
    for producer in producers:
        binary = build_record["binaries"][producer]
        expected_path = build.resolve() / producer
        if not isinstance(binary, dict) or set(binary) != {"path", "sha256", "provenance"} or binary.get("path") != str(expected_path) or not expected_path.is_file() or not os.access(expected_path, os.X_OK) or binary.get("sha256") != sha256_file(expected_path):
            raise Failure("invalid pre-threshold binary binding")
        provenance = binary["provenance"]
        if not isinstance(provenance, dict) or set(provenance) != {"schema", "commit", "dirty", "build_type", "openfhe_version", "source_dir"} or provenance.get("schema") != "piccard-build-provenance-v1" or provenance.get("commit") != commit or provenance.get("dirty") is not False or provenance.get("build_type") != "Release" or provenance.get("source_dir") != str(source) or not isinstance(provenance.get("openfhe_version"), str) or not provenance["openfhe_version"] or provenance["openfhe_version"].lower() == "unknown":
            raise Failure("invalid pre-threshold binary provenance")
        versions.append(provenance["openfhe_version"])
    machine = value.get("machine")
    if not isinstance(machine, dict) or set(machine) != {"cpu", "ram", "os", "compiler", "libraries"} or any(not isinstance(machine.get(key), str) or not machine[key] for key in ("cpu", "os", "compiler")) or not isinstance(machine.get("ram"), (str, int)) or (isinstance(machine.get("ram"), str) and not machine["ram"]) or not isinstance(machine.get("libraries"), dict) or machine["libraries"] != {"openfhe": sorted(set(versions))}:
        raise Failure("invalid pre-threshold machine provenance")
    cells = value.get("cells")
    if not isinstance(cells, list) or len(cells) != 3 or {row.get("producer") for row in cells if isinstance(row, dict)} != {"bench_review_comparison", "bench_piccard", "bench_dynamic"}:
        raise Failure("invalid pre-threshold cells")
    cell_keys = {"cell_id", "profile_id", "producer", "parameter_sha256", "argv", "environment", "output", "status", "reason_code", "required_bits", "available_bits", "shortfall_bits"}
    if any(not isinstance(row, dict) or set(row) != cell_keys for row in cells):
        raise Failure("invalid pre-threshold cell schema")
    expected={"bench_review_comparison":["--suite=toy-smoke","--profile=toy-smoke","--k=16","--m=16","--set-size=10","--universe=64","--target-jaccard=0.5","--trials=1","--accuracy-trials=1","--seed=7","--methods=piccard,piccard_sqrt,fhe_ind,bcg12_mh_ec,bcg12_exact_ec,sj16","--sj16-key-bits=1024","--allow-unmatched-security"], "bench_piccard":["--profile=toy-smoke","--security=TOY","--mode=timing","--evidence_point","--k=16","--m=16","--set_size=10","--target-jaccard=0.5","--trials=1","--seed=7"], "bench_dynamic":["--scenario=refresh","--refresh_updates=1","--profile=toy-smoke","--security=TOY","--mode=timing","--evidence_point","--k=16","--m=16","--set_size=100","--target-jaccard=0.5","--depth=5","--trials=1","--seed=7"]}
    expected_rows={"bench_review_comparison":12,"bench_piccard":1,"bench_dynamic":1}
    for row in cells:
        argv=row.get("argv")
        sampling=[x for x in argv if isinstance(x,str) and (x.startswith("--trials=") or x.startswith("--accuracy-trials=") or x.startswith("--refresh_updates="))] if isinstance(argv,list) else []
        output=row.get("output", {})
        dynamic=([f"--manifest-out={root/output.get('workload')}",f"--execution-trace-out={root/output.get('trace')}"] if row["producer"]=="bench_review_comparison" else [])
        digest=smoke_parameter_sha256(row.get("producer",""), argv if isinstance(argv,list) else [])
        if row.get("status") != "MEASURED" or row.get("profile_id")!="toy-smoke" or row.get("environment")!={"OMP_DYNAMIC":"FALSE","OMP_NUM_THREADS":"2"} or row.get("parameter_sha256")!=digest or row.get("cell_id")!=f"toy-smoke/{row.get('producer')}/{digest}" or row.get("reason_code")!="NONE" or any(row.get(k)!="" for k in ("required_bits","available_bits","shortfall_bits")) or not isinstance(argv,list) or argv != [row["producer"],*expected[row["producer"]],*dynamic] or len(sampling) != len(set(sampling)):
            raise Failure("pre-threshold row/argv mismatch")
    terminal=value.get("terminal_cells")
    if not isinstance(terminal,dict) or set(terminal)!={"path","row_count","sha256"} or terminal["path"]!="terminal-cells.tsv" or terminal["row_count"]!=3:
        raise Failure("missing pre-threshold terminal cells")
    terminal_path=root/terminal["path"]
    header="schema_version\tcell_id\tprofile_id\tproducer\tparameter_sha256\tstatus\treason_code\trequired_bits\tavailable_bits\tshortfall_bits\tlog_sha256"
    try:
        terminal_rows = list(csv.reader(terminal_path.open(newline="", encoding="utf-8"), delimiter="\t", strict=True))
    except (OSError, UnicodeError, csv.Error) as error:
        raise Failure("invalid pre-threshold terminal cells") from error
    if not terminal_path.is_file() or sha256_file(terminal_path)!=terminal["sha256"] or len(terminal_rows)!=4 or terminal_rows[0] != header.split("\t"):
        raise Failure("invalid pre-threshold terminal cells")
    expected_terminal_rows = [["piccard-benchmark-terminal-cell-v1", row["cell_id"], "toy-smoke", row["producer"], row["parameter_sha256"], "MEASURED", "NONE", "", "", "", row["output"]["log_sha256"]] for row in sorted(cells, key=lambda item: item["cell_id"])]
    if terminal_rows[1:] != expected_terminal_rows:
        raise Failure("pre-threshold terminal rows do not bind cells")
    for row in cells:
        output=row.get("output")
        if not isinstance(output,dict) or set(output) != ({"csv","csv_sha256","log","log_sha256","workload","workload_sha256","trace","trace_sha256","expected_csv_rows","csv_row_count","measurement_output"} if row["producer"]=="bench_review_comparison" else {"csv","csv_sha256","log","log_sha256","expected_csv_rows","csv_row_count","measurement_output"}) or output.get("measurement_output")!="measured-csv" or output.get("expected_csv_rows") != expected_rows[row["producer"]] or output.get("csv_row_count") != expected_rows[row["producer"]]: raise Failure("invalid pre-threshold output schema")
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


def real_argv_sha256(argv: list[str]) -> str:
    digest = hashlib.sha256()
    for argument in argv:
        raw = argument.encode("utf-8")
        digest.update(len(raw).to_bytes(4, "big"))
        digest.update(raw)
    return digest.hexdigest()


def validate_real(root: Path, commit: str, build: Path, source: Path) -> Path:
    """Accept only the finalized, one-run quick manifest produced by Work 5.

    The runner's TSV is a deliberately flat serialization.  Rebuild its complete
    quick-mode value map here instead of accepting a prefix-shaped subset: this
    makes counts, ordering, roots, argv framing, and every input/output digest
    part of the evidence binding.
    """
    metadata = root / "run_metadata.tsv"; value = read_tsv(metadata)
    if value.get("schema_version") != "piccard-real-run-v1" or value.get("evidence_mode") != "quick" or value.get("source_commit") != commit or value.get("git_dirty") != "false" or value.get("build_type") != "Release" or value.get("cell_count") != "3":
        raise Failure("invalid real-data metadata")
    source = source.resolve(); root = root.resolve(); build = build.resolve()
    variant = "dblp_acm_u65536"
    fixture = source / "tests" / "fixtures" / "real_datasets" / "quick" / variant
    roots = [
        ("results-root", root), ("build-dir", build), ("committed-source-root", source),
        (f"source-root-{variant}", fixture), (f"processed-dataset-{variant}", fixture),
    ]
    expected = {
        "schema_version": "piccard-real-run-v1", "evidence_mode": "quick",
        "source_commit": commit, "git_dirty": "false", "build_type": "Release",
        "bench_real_datasets_sha256": sha256_file(build / "bench_real_datasets"),
        "summarize_real_datasets_sha256": sha256_file(source / "scripts" / "summarize_real_datasets.py"),
        "root_count": str(len(roots)),
    }
    for number, (root_id, path) in enumerate(roots):
        if not path.is_dir() or path != path.resolve():
            raise Failure("invalid real-data authoritative root")
        expected[f"root.{number:03d}.id"] = root_id
        expected[f"root.{number:03d}.path"] = str(path)

    artifacts = [
        ("system-info", "system_info.txt"),
        (f"copied-source-manifest-{variant}", f"input_manifests/{variant}/source.manifest.tsv"),
        (f"copied-processed-manifest-{variant}", f"input_manifests/{variant}/dataset.manifest.tsv"),
        ("run-log", "run.log"),
    ]
    expected["artifact_count"] = str(len(artifacts))
    for number, (role, relative) in enumerate(artifacts):
        path = sealed_file(root, value.get(f"artifact.{number:03d}.path"), value.get(f"artifact.{number:03d}.sha256"), "real-data artifact")
        expected.update({f"artifact.{number:03d}.role": role, f"artifact.{number:03d}.path": relative,
                         f"artifact.{number:03d}.sha256": sha256_file(path)})

    dataset = fixture / "dataset.manifest.tsv"
    cells = [
        (f"{variant}:accuracy", ["bench_real_datasets", f"--dataset-manifest={dataset}", "--mode=accuracy", "--k=128", "--m=64", "--max-pairs=2", "--accuracy_trials=1", "--seed=7", "--hash_randomness=resampled", f"--csv={root / 'csv' / f'real_accuracy_{variant}.csv'}", f"--workload-manifest-out={root / 'workloads' / f'accuracy_{variant}.manifest.tsv'}", f"--workload-rows-out={root / 'workloads' / f'accuracy_{variant}.rows.tsv'}"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"}, [("processed-manifest", f"processed-dataset-{variant}", fixture, "dataset.manifest.tsv")], [f"csv/real_accuracy_{variant}.csv", f"workloads/accuracy_{variant}.manifest.tsv", f"workloads/accuracy_{variant}.rows.tsv"]),
        (f"{variant}:accuracy-summary", ["summarize_real_datasets.py", f"--input={root / 'csv' / f'real_accuracy_{variant}.csv'}", f"--output={root / 'csv' / f'real_accuracy_summary_{variant}.csv'}"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"}, [("accuracy-csv", "results-root", root, f"csv/real_accuracy_{variant}.csv")], [f"csv/real_accuracy_summary_{variant}.csv"]),
        (f"{variant}:timing:toy-smoke", ["bench_real_datasets", f"--dataset-manifest={dataset}", "--mode=timing", "--profile=toy-smoke", "--k=128", "--m=64", "--trials=1", "--timing-pair=median", "--seed=7", f"--csv={root / 'csv' / f'real_timing_{variant}_toy-smoke.csv'}", f"--workload-manifest-out={root / 'workloads' / f'timing_{variant}_toy-smoke.manifest.tsv'}"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "2"}, [("processed-manifest", f"processed-dataset-{variant}", fixture, "dataset.manifest.tsv")], [f"csv/real_timing_{variant}_toy-smoke.csv", f"workloads/timing_{variant}_toy-smoke.manifest.tsv"]),
    ]
    expected["cell_count"] = str(len(cells))
    for number, (cell_id, argv, env, inputs, outputs) in enumerate(cells):
        prefix = f"cell.{number:03d}."
        expected.update({prefix + "id": cell_id, prefix + "argv_count": str(len(argv)),
                         prefix + "argv_sha256": real_argv_sha256(argv), prefix + "env_count": str(len(env)),
                         prefix + "input_count": str(len(inputs)), prefix + "output_count": str(len(outputs)),
                         prefix + "status": "complete"})
        for index, item in enumerate(argv): expected[prefix + f"argv.{index:03d}"] = item
        for index, (key, item) in enumerate(sorted(env.items())):
            expected[prefix + f"env.{index:03d}.key"] = key; expected[prefix + f"env.{index:03d}.value"] = item
        for index, (role, root_id, input_root, relative) in enumerate(inputs):
            path = sealed_file(input_root, value.get(prefix + f"input.{index:03d}.path"), value.get(prefix + f"input.{index:03d}.sha256"), "real-data input")
            expected.update({prefix + f"input.{index:03d}.role": role, prefix + f"input.{index:03d}.root_id": root_id,
                             prefix + f"input.{index:03d}.path": relative, prefix + f"input.{index:03d}.sha256": sha256_file(path)})
        for index, relative in enumerate(outputs):
            path = sealed_file(root, value.get(prefix + f"output.{index:03d}.path"), value.get(prefix + f"output.{index:03d}.sha256"), "real-data output")
            expected[prefix + f"output.{index:03d}.path"] = relative
            expected[prefix + f"output.{index:03d}.sha256"] = sha256_file(path)
    if value != expected:
        raise Failure("real-data metadata does not exactly bind quick provenance")
    status = read_tsv(root / "verification_status.tsv")
    if status != {"schema_version":"piccard-real-verification-v1", "run_metadata_sha256":sha256_file(metadata), "status":"VERIFIED"}: raise Failure("stale real-data verification status")
    return metadata


def validate_deletion(path: Path) -> None:
    header=("model,n,d,k,required_survival,r,exact_survival,union_bound_survival,mc_survival,mc_standard_error,maximum_safe_deletions,exact_expected_first_failure,exact_expected_safe_deletions,mc_mean_first_failure,mc_mean_safe_deletions,trials,seed".split(","))
    try: rows=list(csv.reader(path.open(newline="",encoding="utf-8"), strict=True))
    except (OSError, UnicodeError, csv.Error) as error: raise Failure("malformed deletion CSV") from error
    if len(rows)!=4 or rows[0]!=header or [row[5] for row in rows[1:]] != ["1","4","8"] or any(len(row)!=17 or row[0]!="ideal-independent-random-ranking-v1" or row[1:4]!=["64","3","8"] or row[4]!="0.99" or row[15:]!=["1","7"] for row in rows[1:]): raise Failure("invalid deletion CSV")


def _capture_map(blobs: tuple[tuple[str, CapturedBlob], ...]) -> dict[str, CapturedBlob]:
    value = dict(blobs)
    if len(value) != len(blobs):
        raise Failure("duplicate captured evidence member")
    return value


def _capture_json(blobs: dict[str, CapturedBlob], relative: str, label: str) -> dict:
    try:
        raw = blobs[relative].raw
        value = json.loads(raw)
    except (KeyError, json.JSONDecodeError) as error:
        raise Failure(f"malformed {label}") from error
    # Producer JSON is sealed by its owning tree, but producer formatters do
    # not promise canonical serialization; retain and parse the exact bytes.
    if not isinstance(value, dict):
        raise Failure(f"malformed {label}")
    return value


def _capture_tsv(raw: bytes, label: str) -> dict[str, str]:
    try:
        rows = list(csv.reader(StringIO(raw.decode("utf-8", "strict")), delimiter="\t", strict=True))
    except (UnicodeError, csv.Error) as error:
        raise Failure(f"malformed {label}") from error
    if not rows or rows[0] != ["key", "value"] or any(len(row) != 2 for row in rows[1:]):
        raise Failure(f"malformed {label}")
    value = dict(rows[1:])
    if len(value) != len(rows) - 1:
        raise Failure(f"malformed {label}")
    return value


def validate_deletion_bytes(raw: bytes) -> None:
    header = "model,n,d,k,required_survival,r,exact_survival,union_bound_survival,mc_survival,mc_standard_error,maximum_safe_deletions,exact_expected_first_failure,exact_expected_safe_deletions,mc_mean_first_failure,mc_mean_safe_deletions,trials,seed".split(",")
    try:
        rows = list(csv.reader(StringIO(raw.decode("utf-8", "strict")), strict=True))
    except (UnicodeError, csv.Error) as error:
        raise Failure("malformed deletion CSV") from error
    if len(rows) != 4 or rows[0] != header or [row[5] for row in rows[1:]] != ["1", "4", "8"] or any(
            len(row) != 17 or row[0] != "ideal-independent-random-ranking-v1" or row[1:4] != ["64", "3", "8"] or
            row[4] != "0.99" or row[15:] != ["1", "7"] for row in rows[1:]):
        raise Failure("invalid deletion CSV")


def validate_record_counts_capture(blobs: tuple[tuple[str, CapturedBlob], ...]) -> None:
    """Apply the runner's one-run/no-actual-data screen without reopening files."""
    def check(value: object, timing: bool = False) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = key.lower().replace("-", "_")
                if normalized in COUNT_NAMES:
                    validate_count_value(item)
                if "warmup" in normalized and (not timing or item not in (0, 1, "discarded", "discarded_warmup")):
                    raise Failure("unlabelled or multiple warmups")
                check(item, timing or "timing" in normalized)
        elif isinstance(value, list):
            for item in value:
                check(item, timing)
        elif isinstance(value, str) and any(token in value.lower() for token in ("enron", "actual-data", "paper-manifest")):
            raise Failure("actual-data artifact path is forbidden")

    for relative, blob in blobs:
        if any(token in relative.lower() for token in ("enron", "actual-data", "paper-manifest")):
            raise Failure("actual-data artifact path is forbidden")
        if relative.endswith(".json"):
            try:
                check(json.loads(blob.raw))
            except json.JSONDecodeError as error:
                raise Failure("malformed JSON artifact") from error
        elif relative.endswith(".csv"):
            try:
                rows = list(csv.DictReader(StringIO(blob.raw.decode("utf-8", "strict"))))
            except (UnicodeError, csv.Error) as error:
                raise Failure("malformed CSV artifact") from error
            if not rows:
                raise Failure("malformed CSV artifact")
            for row in rows:
                for key, item in row.items():
                    if key.lower().replace("-", "_") in COUNT_NAMES:
                        validate_count_value(item)


def validate_prethreshold_capture(blobs: tuple[tuple[str, CapturedBlob], ...], commit: str,
                                  expected_argv: tuple[str, ...], source: str, build: str) -> str:
    values = _capture_map(blobs)
    manifest = _capture_json(values, "phase2/runtime/pre-threshold/manifest.json", "pre-threshold manifest")
    top_keys = {"schema", "suite", "seed", "repetitions", "classification", "thread_policy", "profiles",
                "source", "build", "machine", "directories", "cells", "terminal_cells"}
    if set(manifest) != top_keys:
        raise Failure("invalid pre-threshold manifest schema")
    if (manifest.get("schema") != "piccard-pre-threshold-run-v1" or manifest.get("suite") != "smoke" or
            manifest.get("seed") != 7 or manifest.get("repetitions") != 1 or manifest.get("classification") != "diagnostic" or
            manifest.get("profiles") != ["toy-smoke"] or manifest.get("directories") != {"csv": "csv", "workloads": "workloads", "traces": "traces", "logs": "logs"} or
            manifest.get("thread_policy") != {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "2"}):
        raise Failure("invalid pre-threshold manifest identity")
    source_record, build_record = manifest.get("source"), manifest.get("build")
    if (not isinstance(source_record, dict) or set(source_record) != {"commit", "dirty", "dir"} or
            source_record != {"commit": commit, "dirty": False, "dir": source} or
            not isinstance(build_record, dict) or set(build_record) != {"dir", "type", "binaries"} or
            build_record.get("dir") != build or build_record.get("type") != "Release" or not isinstance(build_record.get("binaries"), dict)):
        raise Failure("invalid pre-threshold provenance")
    expected_binary_names = ("bench_review_comparison", "bench_piccard", "bench_dynamic")
    if set(build_record["binaries"]) != set(expected_binary_names):
        raise Failure("invalid pre-threshold binary binding")
    versions: list[str] = []
    for name in expected_binary_names:
        record = build_record["binaries"][name]
        captured = values.get("@build/" + name)
        provenance = record.get("provenance") if isinstance(record, dict) else None
        if (not isinstance(record, dict) or set(record) != {"path", "sha256", "provenance"} or captured is None or
                record.get("path") != build + "/" + name or record.get("sha256") != captured.sha256 or
                not isinstance(provenance, dict) or set(provenance) != {"schema", "commit", "dirty", "build_type", "openfhe_version", "source_dir"} or
                provenance.get("schema") != "piccard-build-provenance-v1" or provenance.get("commit") != commit or
                provenance.get("dirty") is not False or provenance.get("build_type") != "Release" or provenance.get("source_dir") != source or
                not isinstance(provenance.get("openfhe_version"), str) or not provenance["openfhe_version"] or provenance["openfhe_version"].lower() == "unknown" or
                not re.fullmatch(r"[0-7]{4}", captured.mode) or not (int(captured.mode, 8) & 0o111)):
            raise Failure("invalid pre-threshold binary binding")
        versions.append(provenance["openfhe_version"])
    machine = manifest.get("machine")
    if (not isinstance(machine, dict) or set(machine) != {"cpu", "ram", "os", "compiler", "libraries"} or
            any(not isinstance(machine.get(key), str) or not machine[key] for key in ("cpu", "os", "compiler")) or
            not isinstance(machine.get("ram"), (str, int)) or (isinstance(machine.get("ram"), str) and not machine["ram"]) or
            machine.get("libraries") != {"openfhe": sorted(set(versions))}):
        raise Failure("invalid pre-threshold machine provenance")
    # The caller supplies the captured runner argv; its last value is the
    # session-specific producer root and is bound to every dynamic cell output.
    if (not isinstance(expected_argv, tuple) or len(expected_argv) != 6 or
            expected_argv[:5] != (source + "/scripts/run_pre_threshold_profiles.sh", "--suite=smoke", "--seed=7", "--threads=2", "--build-dir=" + build) or
            not isinstance(expected_argv[-1], str) or not expected_argv[-1].startswith("--results-root=")):
        raise Failure("pre-threshold command record is not exact")
    results_root = expected_argv[-1].split("=", 1)[1]
    if not Path(results_root).is_absolute():
        raise Failure("pre-threshold command results root is not exact")
    if not isinstance(manifest.get("cells"), list) or len(manifest["cells"]) != 3 or {row.get("producer") for row in manifest["cells"] if isinstance(row, dict)} != set(expected_binary_names):
        raise Failure("invalid pre-threshold cells")
    cell_keys = {"cell_id", "profile_id", "producer", "parameter_sha256", "argv", "environment", "output", "status", "reason_code", "required_bits", "available_bits", "shortfall_bits"}
    if any(not isinstance(row, dict) or set(row) != cell_keys for row in manifest["cells"]):
        raise Failure("invalid pre-threshold cell schema")
    terminal = manifest.get("terminal_cells")
    if not isinstance(terminal, dict) or set(terminal) != {"path", "row_count", "sha256"} or terminal.get("path") != "terminal-cells.tsv" or terminal.get("row_count") != 3:
        raise Failure("missing pre-threshold terminal cells")
    terminal_blob = values.get("phase2/runtime/pre-threshold/" + terminal["path"])
    if terminal_blob is None or terminal_blob.sha256 != terminal.get("sha256"):
        raise Failure("invalid pre-threshold terminal cells")
    try:
        terminal_rows = list(csv.reader(StringIO(terminal_blob.raw.decode("utf-8", "strict")), delimiter="\t", strict=True))
    except (UnicodeError, csv.Error) as error:
        raise Failure("invalid pre-threshold terminal cells") from error
    if len(terminal_rows) != 4 or terminal_rows[0] != "schema_version\tcell_id\tprofile_id\tproducer\tparameter_sha256\tstatus\treason_code\trequired_bits\tavailable_bits\tshortfall_bits\tlog_sha256".split("\t"):
        raise Failure("invalid pre-threshold terminal cells")
    expected_outputs = {"bench_review_comparison": {"csv", "csv_sha256", "log", "log_sha256", "workload", "workload_sha256", "trace", "trace_sha256", "expected_csv_rows", "csv_row_count", "measurement_output"},
                        "bench_piccard": {"csv", "csv_sha256", "log", "log_sha256", "expected_csv_rows", "csv_row_count", "measurement_output"},
                        "bench_dynamic": {"csv", "csv_sha256", "log", "log_sha256", "expected_csv_rows", "csv_row_count", "measurement_output"}}
    expected_args = {"bench_review_comparison": ["--suite=toy-smoke", "--profile=toy-smoke", "--k=16", "--m=16", "--set-size=10", "--universe=64", "--target-jaccard=0.5", "--trials=1", "--accuracy-trials=1", "--seed=7", "--methods=piccard,piccard_sqrt,fhe_ind,bcg12_mh_ec,bcg12_exact_ec,sj16", "--sj16-key-bits=1024", "--allow-unmatched-security"],
                     "bench_piccard": ["--profile=toy-smoke", "--security=TOY", "--mode=timing", "--evidence_point", "--k=16", "--m=16", "--set_size=10", "--target-jaccard=0.5", "--trials=1", "--seed=7"],
                     "bench_dynamic": ["--scenario=refresh", "--refresh_updates=1", "--profile=toy-smoke", "--security=TOY", "--mode=timing", "--evidence_point", "--k=16", "--m=16", "--set_size=100", "--target-jaccard=0.5", "--depth=5", "--trials=1", "--seed=7"]}
    expected_rows = {"bench_review_comparison": 12, "bench_piccard": 1, "bench_dynamic": 1}
    expected_paths = {"phase2/runtime/pre-threshold/manifest.json", "phase2/runtime/pre-threshold/terminal-cells.tsv", *("@build/" + name for name in expected_binary_names)}
    for row in manifest["cells"]:
        producer, output, argv = row["producer"], row.get("output"), row.get("argv")
        if not isinstance(output, dict) or set(output) != expected_outputs[producer] or output.get("measurement_output") != "measured-csv" or output.get("expected_csv_rows") != expected_rows[producer] or output.get("csv_row_count") != expected_rows[producer]:
            raise Failure("invalid pre-threshold output schema")
        dynamic = (["--manifest-out=" + results_root + "/" + output["workload"], "--execution-trace-out=" + results_root + "/" + output["trace"]] if producer == "bench_review_comparison" else [])
        sampling = [item for item in argv if isinstance(item, str) and (item.startswith("--trials=") or item.startswith("--accuracy-trials=") or item.startswith("--refresh_updates="))] if isinstance(argv, list) else []
        digest = smoke_parameter_sha256(producer, argv if isinstance(argv, list) else [])
        if (row.get("status") != "MEASURED" or row.get("profile_id") != "toy-smoke" or row.get("environment") != {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "2"} or
                row.get("parameter_sha256") != digest or row.get("cell_id") != "toy-smoke/" + producer + "/" + digest or row.get("reason_code") != "NONE" or
                any(row.get(key) != "" for key in ("required_bits", "available_bits", "shortfall_bits")) or not isinstance(argv, list) or argv != [producer, *expected_args[producer], *dynamic] or len(sampling) != len(set(sampling))):
            raise Failure("pre-threshold row/argv mismatch")
        for key, relative in row["output"].items():
            if key.endswith("_sha256") or key in {"expected_csv_rows", "csv_row_count", "measurement_output"}:
                continue
            if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise Failure("invalid pre-threshold artifact digest")
            target_path = "phase2/runtime/pre-threshold/" + relative
            target = values.get(target_path)
            if target is None or target.sha256 != row["output"].get(key + "_sha256"):
                raise Failure("invalid pre-threshold artifact digest")
            expected_paths.add(target_path)
    expected_terminal_rows = [["piccard-benchmark-terminal-cell-v1", row["cell_id"], "toy-smoke", row["producer"], row["parameter_sha256"], "MEASURED", "NONE", "", "", "", row["output"]["log_sha256"]] for row in sorted(manifest["cells"], key=lambda item: item["cell_id"])]
    if terminal_rows[1:] != expected_terminal_rows or set(values) != expected_paths:
        raise Failure("pre-threshold terminal rows do not bind cells")
    validate_record_counts_capture(blobs)
    return values["phase2/runtime/pre-threshold/manifest.json"].sha256


def validate_real_capture(blobs: tuple[tuple[str, CapturedBlob], ...], commit: str, source: str, build: str) -> str:
    values = _capture_map(blobs)
    try:
        metadata_blob = values["phase2/runtime/real-datasets/run_metadata.tsv"]
        source_blob = values["@source/scripts/summarize_real_datasets.py"]
        fixture_blob = values["@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv"]
        binary = values["@build/bench_real_datasets"]
    except KeyError as error:
        raise Failure("real-data capture is incomplete") from error
    metadata = _capture_tsv(metadata_blob.raw, "real-data metadata")
    variant = "dblp_acm_u65536"
    results_root = metadata.get("root.000.path")
    if (not isinstance(results_root, str) or not Path(results_root).is_absolute() or
            ".." in Path(results_root).parts):
        raise Failure("invalid real-data authoritative root")
    root = results_root
    fixture = source + "/tests/fixtures/real_datasets/quick/" + variant
    roots = [("results-root", root), ("build-dir", build), ("committed-source-root", source), ("source-root-" + variant, fixture), ("processed-dataset-" + variant, fixture)]
    expected: dict[str, str] = {"schema_version": "piccard-real-run-v1", "evidence_mode": "quick", "source_commit": commit,
                                "git_dirty": "false", "build_type": "Release", "bench_real_datasets_sha256": binary.sha256,
                                "summarize_real_datasets_sha256": source_blob.sha256, "root_count": str(len(roots))}
    for number, (root_id, path) in enumerate(roots):
        expected[f"root.{number:03d}.id"] = root_id; expected[f"root.{number:03d}.path"] = path
    artifacts = [("system-info", "system_info.txt"), ("copied-source-manifest-" + variant, "input_manifests/" + variant + "/source.manifest.tsv"),
                 ("copied-processed-manifest-" + variant, "input_manifests/" + variant + "/dataset.manifest.tsv"), ("run-log", "run.log")]
    expected["artifact_count"] = str(len(artifacts))
    expected_paths = {"phase2/runtime/real-datasets/run_metadata.tsv", "phase2/runtime/real-datasets/verification_status.tsv", "@build/bench_real_datasets", "@source/scripts/summarize_real_datasets.py", "@source/tests/fixtures/real_datasets/quick/dblp_acm_u65536/dataset.manifest.tsv"}
    for number, (role, relative) in enumerate(artifacts):
        path = "phase2/runtime/real-datasets/" + relative
        blob = values.get(path)
        if blob is None: raise Failure("real-data artifact is missing")
        expected.update({f"artifact.{number:03d}.role": role, f"artifact.{number:03d}.path": relative, f"artifact.{number:03d}.sha256": blob.sha256})
        expected_paths.add(path)
    dataset = fixture + "/dataset.manifest.tsv"
    cells = [(variant + ":accuracy", ["bench_real_datasets", "--dataset-manifest=" + dataset, "--mode=accuracy", "--k=128", "--m=64", "--max-pairs=2", "--accuracy_trials=1", "--seed=7", "--hash_randomness=resampled", "--csv=" + root + "/csv/real_accuracy_" + variant + ".csv", "--workload-manifest-out=" + root + "/workloads/accuracy_" + variant + ".manifest.tsv", "--workload-rows-out=" + root + "/workloads/accuracy_" + variant + ".rows.tsv"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"}, [("processed-manifest", "processed-dataset-" + variant, fixture, "dataset.manifest.tsv")], ["csv/real_accuracy_" + variant + ".csv", "workloads/accuracy_" + variant + ".manifest.tsv", "workloads/accuracy_" + variant + ".rows.tsv"]),
             (variant + ":accuracy-summary", ["summarize_real_datasets.py", "--input=" + root + "/csv/real_accuracy_" + variant + ".csv", "--output=" + root + "/csv/real_accuracy_summary_" + variant + ".csv"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "1"}, [("accuracy-csv", "results-root", root, "csv/real_accuracy_" + variant + ".csv")], ["csv/real_accuracy_summary_" + variant + ".csv"]),
             (variant + ":timing:toy-smoke", ["bench_real_datasets", "--dataset-manifest=" + dataset, "--mode=timing", "--profile=toy-smoke", "--k=128", "--m=64", "--trials=1", "--timing-pair=median", "--seed=7", "--csv=" + root + "/csv/real_timing_" + variant + "_toy-smoke.csv", "--workload-manifest-out=" + root + "/workloads/timing_" + variant + "_toy-smoke.manifest.tsv"], {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": "2"}, [("processed-manifest", "processed-dataset-" + variant, fixture, "dataset.manifest.tsv")], ["csv/real_timing_" + variant + "_toy-smoke.csv", "workloads/timing_" + variant + "_toy-smoke.manifest.tsv"])]
    expected["cell_count"] = str(len(cells))
    for number, (cell_id, argv, env, inputs, outputs) in enumerate(cells):
        prefix = f"cell.{number:03d}."
        expected.update({prefix + "id": cell_id, prefix + "argv_count": str(len(argv)), prefix + "argv_sha256": real_argv_sha256(argv), prefix + "env_count": str(len(env)), prefix + "input_count": str(len(inputs)), prefix + "output_count": str(len(outputs)), prefix + "status": "complete"})
        for index, item in enumerate(argv): expected[prefix + f"argv.{index:03d}"] = item
        for index, (key, item) in enumerate(sorted(env.items())): expected[prefix + f"env.{index:03d}.key"] = key; expected[prefix + f"env.{index:03d}.value"] = item
        for index, (role, root_id, input_root, relative) in enumerate(inputs):
            path = ("@source/tests/fixtures/real_datasets/quick/" + variant + "/dataset.manifest.tsv" if role == "processed-manifest"
                    else "phase2/runtime/real-datasets/" + relative)
            blob = fixture_blob if role == "processed-manifest" else values.get(path)
            if blob is None: raise Failure("real-data input is missing")
            expected.update({prefix + f"input.{index:03d}.role": role, prefix + f"input.{index:03d}.root_id": root_id, prefix + f"input.{index:03d}.path": relative, prefix + f"input.{index:03d}.sha256": blob.sha256})
            expected_paths.add(path)
        for index, relative in enumerate(outputs):
            path = "phase2/runtime/real-datasets/" + relative; blob = values.get(path)
            if blob is None: raise Failure("real-data output is missing")
            expected[prefix + f"output.{index:03d}.path"] = relative; expected[prefix + f"output.{index:03d}.sha256"] = blob.sha256; expected_paths.add(path)
    if metadata != expected or set(values) != expected_paths:
        raise Failure("real-data metadata does not exactly bind quick provenance")
    status = _capture_tsv(values["phase2/runtime/real-datasets/verification_status.tsv"].raw, "real-data verification status")
    if status != {"schema_version": "piccard-real-verification-v1", "run_metadata_sha256": metadata_blob.sha256, "status": "VERIFIED"}:
        raise Failure("stale real-data verification status")
    validate_record_counts_capture(blobs)
    return values["phase2/runtime/real-datasets/run_metadata.tsv"].sha256


def main(argv: list[str] | None = None) -> int:
    ledger: ReservationLedger | None = None
    build: Path | None = None
    session: Path | None = None
    commit: str | None = None
    diagnostic_root: Path | None = None
    try:
        args = parser().parse_args(argv)
        source = require_absolute(args.source_root, "source-root")
        paper = require_absolute(args.paper_root, "paper-root")
        threshold = require_absolute(args.threshold_root, "threshold-root")
        build_parent = require_absolute(args.build_parent, "build-parent")
        session_parent = require_absolute(args.session_parent, "session-parent")
        diagnostic_root = require_external_diagnostic_root(
            require_absolute(args.diagnostic_root, "diagnostic-root"),
            (source, paper, threshold, build_parent, session_parent))
        commit = git_head(source)
        diagnostic = diagnostic_root / ("failure-" + commit + ".json")
        if diagnostic.exists():
            raise Failure("failure diagnostic exists; use clear_diagnostic before a fresh Phase 0 run")
        ledger = ReservationLedger(created=[])
        build = build_parent / ("build-" + commit)
        session = session_parent / ("session-" + commit)
        build = reserve_owned(build_parent, "build-" + commit, ledger)
        session = reserve_owned(session_parent, "session-" + commit, ledger)
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
        if any(name not in text for name in ("openfhe", "gmp", "gtest")):
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
        pre_manifest=validate_prethreshold(pre, commit, pre_command, source, build)
        checked_command((str(source / "scripts" / "run_real_datasets.sh"), "--quick", "--seed=7", "--threads=2", "--build-dir=" + str(build), "--results-root=" + str(real)), source, commands, "real-datasets")
        checked_command((sys.executable, str(source / "scripts" / "verify_real_dataset_outputs.py"), str(real)), source, commands, "verify-real-datasets")
        deletion = checked_command((str(build / "bench_deletion_survival"), "--n=64", "--d=3", "--k=8", "--required_survival=0.99", "--r_values=1,4,8", "--trials=1", "--seed=7"), source, commands, "deletion-survival")
        validate_real(real, commit, build, source)
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
        if (ledger is not None and ledger.created and build is not None and session is not None
                and commit is not None and diagnostic_root is not None):
            try:
                _record_and_apply_owned_failure(
                    diagnostic_root=diagnostic_root, build_parent=build_parent,
                    session_parent=session_parent, build=build, session=session,
                    commit=commit, kind="execution", packet=None, packet_sha256=None,
                    guarded=(source, paper, threshold), ledger=ledger)
            except (ValueError, OSError, json.JSONDecodeError) as coordinator_error:
                print(f"run_work7_integration: FAIL: failure coordination failed: {coordinator_error}", file=sys.stderr)
        print(f"run_work7_integration: FAIL: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if (ledger is not None and ledger.created and build is not None and session is not None
                and commit is not None and diagnostic_root is not None):
            try:
                _record_and_apply_owned_failure(
                    diagnostic_root=diagnostic_root, build_parent=build_parent,
                    session_parent=session_parent, build=build, session=session,
                    commit=commit, kind="user-cancel", packet=None, packet_sha256=None,
                    guarded=(source, paper, threshold), ledger=ledger)
            except (ValueError, OSError, json.JSONDecodeError) as coordinator_error:
                print(f"run_work7_integration: FAIL: failure coordination failed: {coordinator_error}", file=sys.stderr)
        print("run_work7_integration: FAIL: user interrupted", file=sys.stderr)
        return 2
    print("run_work7_integration: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
