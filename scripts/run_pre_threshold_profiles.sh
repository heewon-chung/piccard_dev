#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
"""Run the frozen pre-threshold benchmark suites with fail-closed evidence state."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any


SCRIPT_DIR = pathlib.Path(sys.argv.pop(1)).resolve()
SCHEMA = "piccard-pre-threshold-run-v1"
TERMINAL_SCHEMA = "piccard-benchmark-terminal-cell-v1"
TERMINAL_HEADER = (
    "schema_version\tcell_id\tprofile_id\tproducer\tparameter_sha256\t"
    "status\treason_code\trequired_bits\tavailable_bits\tshortfall_bits\t"
    "log_sha256"
)
DOMAIN = b"piccard-benchmark-cell-v1\0"
PAPER_SEED = 20260729
SMOKE_SEED = 7
ENVIRONMENT_NAMES = ("OMP_DYNAMIC", "OMP_NUM_THREADS")
DECIMAL_PATTERN = r"(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?"
SCHEMA_BY_PRODUCER = {
    "bench_piccard": "benchmark",
    "bench_onehot_sqrt": "benchmark",
    "bench_dynamic": "dynamic",
    "bench_review_comparison": "review",
}


class RunnerError(ValueError):
    """A fail-closed runner validation error."""


@dataclass(frozen=True)
class Cell:
    profile: str
    producer: str
    args: tuple[str, ...]
    review: bool = False

    def semantic_args(self) -> tuple[str, ...]:
        return tuple(
            arg for arg in self.args
            if not arg.startswith("--manifest-out=")
            and not arg.startswith("--execution-trace-out=")
        )

    def parameter_sha256(self, threads: int) -> str:
        values = [self.producer, self.profile, *self.semantic_args()]
        environment = sorted(("OMP_DYNAMIC=FALSE", f"OMP_NUM_THREADS={threads}"))
        payload = bytearray(DOMAIN)
        for value in [*values, *environment]:
            encoded = value.encode("utf-8")
            payload.extend(struct.pack(">I", len(encoded)))
            payload.extend(encoded)
        return hashlib.sha256(payload).hexdigest()

    def cell_id(self, threads: int) -> str:
        return f"{self.profile}/{self.producer}/{self.parameter_sha256(threads)}"

    def expected_csv_rows(self) -> int:
        if self.review:
            suite = next(arg.split("=", 1)[1] for arg in self.args
                         if arg.startswith("--suite="))
            return {"primary-review": 14, "toy-smoke": 10,
                    "sj16-precompute-sensitivity": 2}[suite]
        if "--evidence_point" in self.args:
            return 2 if self.producer == "bench_onehot_sqrt" else 1
        if self.producer == "bench_piccard":
            return 30
        if self.producer == "bench_dynamic":
            return 15
        if self.producer == "bench_onehot_sqrt":
            return 28 if "--mode=timing" in self.args else 22
        fail(f"no frozen row count for producer {self.producer}")


def fail(message: str) -> None:
    raise RunnerError(message)


def security_profile(security: str, suffix: str) -> str:
    return f"{security.lower()}-{suffix}"


def matrix(suite: str, seed: int) -> list[Cell]:
    cells: list[Cell] = []
    if suite == "primary":
        for security in ("STD128", "STD192"):
            profile_id = security_profile(security, "t40-primary")
            common = (f"--profile={profile_id}", f"--security={security}")
            cells.extend((
                Cell(profile_id, "bench_piccard", common + (
                    "--mode=combined", "--k=128", "--m=64",
                    "--set_size=1000", "--target-jaccard=0.5", "--trials=30",
                    "--accuracy_trials=50", f"--seed={seed}")),
                Cell(profile_id, "bench_onehot_sqrt", common + (
                    "--mode=timing", "--k=128", "--m=64",
                    "--set_size=1000", "--trials=30", f"--seed={seed}")),
                Cell(profile_id, "bench_onehot_sqrt", common + (
                    "--mode=accuracy", "--k=128", "--m=64",
                    "--set_size=1000", "--accuracy_trials=50", f"--seed={seed}")),
                Cell(profile_id, "bench_dynamic", common + (
                    "--mode=timing", "--k=128", "--m=64",
                    "--set_size=1000", "--depth=5", "--trials=30",
                    f"--seed={seed}")),
            ))
        for universe in (16384, 65536):
            args = (
                "--suite=primary-review", "--profile=std128-t40-primary",
                "--security=STD128", "--k=128", "--m=64",
                "--set-size=1000", f"--universe={universe}",
                "--target-jaccard=0.5", "--trials=30", "--accuracy-trials=50",
                f"--seed={seed}",
                "--methods=piccard,piccard_sqrt,bcg12_mh_ff,bcg12_mh_ec,bcg12_exact_ff,bcg12_exact_ec,sj16",
                "--sj16-key-bits=3072",
                "--execution-trace-out=<trace>", "--strict-security",
                "--manifest-out=<workload>",
            )
            cells.append(Cell("std128-t40-primary", "bench_review_comparison",
                              args, True))
    elif suite == "sensitivity":
        for security in ("STD128", "STD192"):
            profile_id = security_profile(security, "t64-sensitivity")
            common = (f"--profile={profile_id}", f"--security={security}")
            point = ("--evidence_point", "--k=128", "--m=64",
                     "--set_size=1000", "--target-jaccard=0.5")
            cells.extend((
                Cell(profile_id, "bench_piccard", common + (
                    "--mode=timing",) + point + ("--trials=3", f"--seed={seed}")),
                Cell(profile_id, "bench_piccard", common + (
                    "--mode=accuracy",) + point +
                    ("--accuracy_trials=30", f"--seed={seed}")),
                Cell(profile_id, "bench_onehot_sqrt", common + (
                    "--mode=timing",) + point + ("--trials=3", f"--seed={seed}")),
                Cell(profile_id, "bench_onehot_sqrt", common + (
                    "--mode=accuracy",) + point +
                    ("--accuracy_trials=30", f"--seed={seed}")),
                Cell(profile_id, "bench_dynamic", common + (
                    "--mode=timing",) + point +
                    ("--depth=5", "--trials=3", f"--seed={seed}")),
            ))
        for universe in (16384, 65536):
            args = (
                "--suite=sj16-precompute-sensitivity",
                "--profile=std128-t64-sensitivity", "--security=STD128",
                "--k=128", "--m=64", "--set-size=1000",
                f"--universe={universe}", "--target-jaccard=0.5",
                "--trials=3", "--accuracy-trials=0", f"--seed={seed}",
                "--methods=sj16,sj16_precomputed", "--sj16-key-bits=3072",
                "--execution-trace-out=<trace>", "--diagnostic-security",
                "--manifest-out=<workload>",
            )
            cells.append(Cell("std128-t64-sensitivity",
                              "bench_review_comparison", args, True))
    elif suite == "feasibility":
        for security in ("STD128", "STD192"):
            profile_id = security_profile(security, "t128-feasibility")
            common = (f"--profile={profile_id}", f"--security={security}")
            point = ("--evidence_point", "--k=128", "--m=64",
                     "--set_size=100", "--target-jaccard=0.5")
            cells.extend((
                Cell(profile_id, "bench_piccard", common + (
                    "--mode=timing",) + point + ("--trials=1", f"--seed={seed}")),
                Cell(profile_id, "bench_piccard", common + (
                    "--mode=accuracy",) + point +
                    ("--accuracy_trials=2", f"--seed={seed}")),
            ))
    elif suite == "smoke":
        review_args = (
            "--suite=toy-smoke", "--profile=toy-smoke", "--k=16", "--m=16",
            "--set-size=10", "--universe=64", "--target-jaccard=0.5",
            "--trials=1", "--accuracy-trials=2", f"--seed={seed}",
            "--methods=piccard,piccard_sqrt,bcg12_mh_ec,bcg12_exact_ec,sj16",
            "--sj16-key-bits=1024", "--allow-unmatched-security",
            "--manifest-out=<workload>", "--execution-trace-out=<trace>",
        )
        cells.extend((
            Cell("toy-smoke", "bench_review_comparison", review_args, True),
            Cell("toy-smoke", "bench_piccard", (
                "--profile=toy-smoke", "--security=TOY", "--mode=timing",
                "--evidence_point", "--k=16", "--m=16", "--set_size=10",
                "--target-jaccard=0.5", "--trials=1", f"--seed={seed}")),
        ))
    else:
        fail(f"unknown suite: {suite}")
    return cells


def expected_seed(suite: str) -> int:
    return SMOKE_SEED if suite == "smoke" else PAPER_SEED


def profile_list(cells: list[Cell]) -> list[str]:
    return list(dict.fromkeys(cell.profile for cell in cells))


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def csv_row_count(path: pathlib.Path) -> int:
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream, strict=True))
    except (OSError, UnicodeError, csv.Error) as error:
        fail(f"cannot parse producer CSV: {error}")
    if not rows or not rows[0]:
        fail("producer CSV is empty")
    return len(rows) - 1


def canonical_decimal(text: str) -> tuple[Decimal, str]:
    try:
        value = Decimal(text)
    except InvalidOperation as error:
        fail(f"invalid capacity decimal: {text}")
    if not value.is_finite() or value < 0:
        fail(f"invalid capacity decimal: {text}")
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return value, rendered or "0"


def validate_terminal_record(cell: dict[str, Any]) -> None:
    status = cell.get("status")
    reason = cell.get("reason_code")
    required = cell.get("required_bits", "")
    available = cell.get("available_bits", "")
    shortfall = cell.get("shortfall_bits", "")
    if status == "MEASURED":
        if reason != "NONE" or any((required, available, shortfall)):
            fail("MEASURED terminal cell has invalid reason/bit fields")
        return
    if status == "INFEASIBLE" and reason == "MISSING_CALIBRATION":
        if any((required, available, shortfall)):
            fail("MISSING_CALIBRATION terminal cell must have empty bit fields")
        return
    if status == "INFEASIBLE" and reason == "CAPACITY_SHORTFALL":
        required_value, required_text = canonical_decimal(str(required))
        available_value, available_text = canonical_decimal(str(available))
        shortfall_value, shortfall_text = canonical_decimal(str(shortfall))
        if (str(required) != required_text or str(available) != available_text or
                str(shortfall) != shortfall_text or
                required_value <= available_value or
                shortfall_value != required_value - available_value):
            fail("CAPACITY_SHORTFALL terminal cell has inconsistent bit fields")
        return
    if status == "ERROR" and reason in {"PROCESS_ERROR", "TIMEOUT"}:
        if any((required, available, shortfall)):
            fail("ERROR terminal cell must have empty bit fields")
        return
    fail("terminal cell status/reason truth table violation")


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def run_short(command: list[str], cwd: pathlib.Path | None = None) -> str:
    try:
        result = subprocess.run(
            command, cwd=cwd, text=True, capture_output=True, check=False,
        )
    except OSError as error:
        fail(f"cannot run {command[0]}: {error}")
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        fail(f"command failed ({' '.join(command)}): {detail}")
    return result.stdout.strip()


def source_identity(project: pathlib.Path) -> tuple[str, bool]:
    commit = run_short(["git", "rev-parse", "HEAD"], project)
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        fail("git HEAD is not a full lowercase commit")
    dirty = bool(run_short(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], project))
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


def build_provenance(binary: pathlib.Path) -> dict[str, Any]:
    output = run_short([str(binary), "--print-build-provenance"])
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        fail(f"{binary.name} returned invalid build provenance JSON: {error}")
    if not isinstance(value, dict) or value.get("schema") != "piccard-build-provenance-v1":
        fail(f"{binary.name} returned invalid build provenance schema")
    required = {"commit", "dirty", "build_type", "source_dir"}
    if not required.issubset(value):
        fail(f"{binary.name} build provenance is incomplete")
    if not isinstance(value["dirty"], bool):
        fail(f"{binary.name} build provenance dirty flag is not boolean")
    return value


def machine_metadata(provenances: dict[str, dict[str, Any]]) -> dict[str, Any]:
    try:
        compiler = run_short(["c++", "--version"]).splitlines()[0]
    except RunnerError:
        compiler = "unknown"
    cpu = platform.processor() or platform.machine() or "unknown"
    try:
        ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        ram = "unknown"
    openfhe = sorted({str(value.get("openfhe_version", "unknown"))
                      for value in provenances.values()})
    return {
        "cpu": cpu,
        "ram": ram,
        "os": platform.platform(),
        "compiler": compiler,
        "libraries": {"openfhe": openfhe},
    }


def relative_output(cell: Cell, threads: int) -> dict[str, str]:
    cell_id = cell.cell_id(threads)
    output = {
        "csv": f"csv/{cell_id}.csv",
        "log": f"logs/{cell_id}.log",
    }
    if cell.review:
        output["workload"] = f"workloads/{cell_id}.bin"
        output["trace"] = f"traces/{cell_id}.bin"
    return output


def resolved_args(cell: Cell, root: pathlib.Path, threads: int) -> list[str]:
    paths = relative_output(cell, threads)
    resolved = []
    for argument in cell.args:
        if argument == "--manifest-out=<workload>":
            argument = f"--manifest-out={root / paths['workload']}"
        elif argument == "--execution-trace-out=<trace>":
            argument = f"--execution-trace-out={root / paths['trace']}"
        resolved.append(argument)
    return resolved


def display_args(cell: Cell) -> list[str]:
    displayed = []
    for argument in cell.args:
        if argument == "--manifest-out=<workload>":
            argument = "--manifest-out=<results-root>/workloads/<cell_id>.bin"
        elif argument == "--execution-trace-out=<trace>":
            argument = "--execution-trace-out=<results-root>/traces/<cell_id>.bin"
        displayed.append(argument)
    return displayed


def dry_run(cells: list[Cell], threads: int, suite: str) -> int:
    print("GATE source commit/cleanliness")
    print("GATE absolute caller-supplied build/results roots; no overwrite")
    print("GATE embedded Release build provenance and binary SHA-256")
    if suite == "feasibility":
        print("GATE feasibility cells are comparison-ineligible")
    for cell in cells:
        print("RUN " + " ".join((
            f"OMP_NUM_THREADS={threads}", "OMP_DYNAMIC=FALSE", cell.producer,
            *display_args(cell),
        )))
        print(
            "CAPTURE "
            f"stdout=<results-root>/csv/{cell.cell_id(threads)}.csv "
            f"stderr=<results-root>/logs/{cell.cell_id(threads)}.log")
    for cell in cells:
        schema = SCHEMA_BY_PRODUCER[cell.producer]
        suffix = ("--run-manifest=<results-root>/manifest.json "
                  f"--cell-id={cell.cell_id(threads)}")
        print(f"VERIFY verify_benchmark_provenance.py --schema={schema} {suffix}")
        if cell.review:
            print(f"VERIFY verify_review_comparison.py {suffix}")
    return 0


def ensure_contained(root: pathlib.Path, relative: Any, label: str) -> pathlib.Path:
    if not isinstance(relative, str) or not relative or pathlib.Path(relative).is_absolute():
        fail(f"{label} escapes results root")
    candidate = (root / relative).resolve(strict=False)
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} escapes results root")
    return candidate


def terminal_text(cells: list[dict[str, Any]]) -> str:
    rows = []
    for cell in sorted(cells, key=lambda value: value["cell_id"].encode("utf-8")):
        validate_terminal_record(cell)
        fields = (
            TERMINAL_SCHEMA, cell["cell_id"], cell["profile_id"],
            cell["producer"], cell["parameter_sha256"], cell["status"],
            cell["reason_code"], cell.get("required_bits", ""),
            cell.get("available_bits", ""), cell.get("shortfall_bits", ""),
            cell["output"]["log_sha256"],
        )
        if any(any(ch in str(field) for ch in "\t\r\n") for field in fields):
            fail("terminal cell field contains forbidden whitespace")
        rows.append("\t".join(str(field) for field in fields))
    return TERMINAL_HEADER + "\n" + "\n".join(rows) + ("\n" if rows else "")


def write_state(root: pathlib.Path, manifest: dict[str, Any]) -> None:
    terminal_path = root / "terminal-cells.tsv"
    data = terminal_text(manifest["cells"]).encode("utf-8")
    temporary = terminal_path.with_name(terminal_path.name + ".tmp")
    with temporary.open("wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, terminal_path)
    manifest["terminal_cells"] = {
        "path": "terminal-cells.tsv",
        "row_count": len(manifest["cells"]),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    atomic_json(root / "manifest.json", manifest)


def expected_cell_record(cell: Cell, threads: int, root: pathlib.Path) -> dict[str, Any]:
    parameter = cell.parameter_sha256(threads)
    return {
        "cell_id": cell.cell_id(threads),
        "profile_id": cell.profile,
        "producer": cell.producer,
        "parameter_sha256": parameter,
        "argv": [cell.producer, *resolved_args(cell, root, threads)],
        "environment": {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(threads)},
        "output": {
            **relative_output(cell, threads),
            "expected_csv_rows": cell.expected_csv_rows(),
        },
    }


def validate_resume(
    manifest: dict[str, Any], root: pathlib.Path, suite: str, seed: int,
    threads: int, source: dict[str, Any], build: dict[str, Any], cells: list[Cell],
) -> dict[str, dict[str, Any]]:
    if manifest.get("schema") != SCHEMA:
        fail("resume manifest schema mismatch")
    exact = {
        "suite": suite, "seed": seed,
        "thread_policy": {"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(threads)},
        "profiles": profile_list(cells), "source": source,
    }
    for key, value in exact.items():
        if manifest.get(key) != value:
            fail(f"resume {key} mismatch")
    old_build = manifest.get("build")
    if not isinstance(old_build, dict) or old_build.get("dir") != build["dir"]:
        fail("resume build directory mismatch")
    if old_build.get("type") != build["type"]:
        fail("resume build type mismatch")
    old_binaries = old_build.get("binaries", {})
    for name, identity in build["binaries"].items():
        if old_binaries.get(name, {}).get("sha256") != identity["sha256"]:
            fail(f"binary hash mismatch for {name}")
        if old_binaries.get(name) != identity:
            fail(f"binary identity mismatch for {name}")

    existing = manifest.get("cells")
    if not isinstance(existing, list):
        fail("resume cells are malformed")
    by_id: dict[str, dict[str, Any]] = {}
    expected = {cell.cell_id(threads): cell for cell in cells}
    for record in existing:
        if not isinstance(record, dict) or record.get("cell_id") in by_id:
            fail("resume cell identity is missing or duplicate")
        cell_id = record["cell_id"]
        if cell_id not in expected:
            fail("resume contains unexpected cell identity")
        cell = expected[cell_id]
        wanted = expected_cell_record(cell, threads, root)
        for key in ("profile_id", "producer", "parameter_sha256", "environment"):
            if record.get(key) != wanted[key]:
                fail(f"resume {key} mismatch")
        if record.get("argv") != wanted["argv"]:
            fail("argv mismatch under resume")
        output = record.get("output")
        if not isinstance(output, dict):
            fail("resume output is malformed")
        for path_key, expected_path in relative_output(cell, threads).items():
            if output.get(path_key) != expected_path:
                if path_key in output:
                    ensure_contained(root, output[path_key], f"output {path_key}")
                fail(f"resume output path mismatch for {path_key}")
            path = ensure_contained(root, output[path_key], f"output {path_key}")
            if not path.is_file():
                fail(f"resume output is missing: {path_key}")
        checksums = {
            "csv": "csv_sha256", "log": "log_sha256",
            "workload": "workload_sha256", "trace": "trace_sha256",
        }
        for path_key, hash_key in checksums.items():
            if path_key not in wanted["output"]:
                continue
            actual = sha256_file(root / output[path_key])
            if output.get(hash_key) != actual:
                fail(f"output hash mismatch for {path_key}")
        if output.get("expected_csv_rows") != cell.expected_csv_rows():
            fail("resume expected CSV row count mismatch")
        status = record.get("status")
        validate_terminal_record(record)
        if status == "MEASURED":
            if output.get("measurement_output") != "measured-csv":
                fail("resume measured CSV representation mismatch")
            actual_rows = csv_row_count(root / output["csv"])
            if output.get("csv_row_count") != actual_rows:
                fail("resume CSV row count mismatch")
            if actual_rows != cell.expected_csv_rows():
                fail("resume CSV does not have the frozen expected row count")
        elif status == "INFEASIBLE":
            if suite != "feasibility":
                fail("resume cannot skip blocking INFEASIBLE cell")
            if cell.review:
                fail("feasibility INFEASIBLE cell cannot be a review producer")
            if output.get("measurement_output") != "absent-empty-csv":
                fail("resume infeasible CSV representation mismatch")
            csv_path = root / output["csv"]
            if csv_path.stat().st_size != 0 or output.get("csv_row_count") != 0:
                fail("resume infeasible cell requires an empty zero-row CSV")
            if not isinstance(record.get("exit_code"), int) or record["exit_code"] == 0:
                fail("resume infeasible cell requires a nonzero producer exit")
        else:
            fail("resume cannot skip a nonterminal-success cell")
        by_id[cell_id] = record

    terminal = manifest.get("terminal_cells")
    terminal_path = ensure_contained(
        root, terminal.get("path") if isinstance(terminal, dict) else None,
        "terminal-cells path")
    if not terminal_path.is_file():
        fail("terminal-cells.tsv is missing")
    terminal_bytes = terminal_path.read_bytes()
    if terminal.get("sha256") != hashlib.sha256(terminal_bytes).hexdigest():
        fail("terminal-cells hash mismatch")
    if terminal.get("row_count") != len(existing):
        fail("terminal-cells row count mismatch")
    if terminal_bytes.decode("utf-8") != terminal_text(existing):
        fail("terminal-cells content mismatch")
    return by_id


def verifier_command(
    project: pathlib.Path, manifest_path: pathlib.Path,
    cell: dict[str, Any], review: bool,
) -> list[list[str]]:
    common = [f"--run-manifest={manifest_path}", f"--cell-id={cell['cell_id']}"]
    schema = SCHEMA_BY_PRODUCER[cell["producer"]]
    commands = [[sys.executable,
                 str(project / "scripts" / "verify_benchmark_provenance.py"),
                 f"--schema={schema}", *common]]
    if review:
        commands.append([sys.executable, str(project / "scripts" / "verify_review_comparison.py"), *common])
    return commands


def run_verifiers(project: pathlib.Path, manifest_path: pathlib.Path,
                  cell: dict[str, Any], review: bool) -> None:
    for command in verifier_command(project, manifest_path, cell, review):
        label = pathlib.Path(command[1]).stem
        print("VERIFY " + label + " " + " ".join(command[2:]))
        verifier_environment = os.environ.copy()
        verifier_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            command, env=verifier_environment, text=True,
            capture_output=True, check=False)
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            fail(f"{label} failed: {detail}")


def classify_failure(stderr: str) -> tuple[str, str, str, str, str]:
    lower = stderr.lower()
    if "missing sanitizer calibration" in lower or "no noise calibration" in lower:
        return "INFEASIBLE", "MISSING_CALIBRATION", "", "", ""
    capacity = re.search(
        rf"(?m)^[^\r\n]*\binfeasible sanitizer calibration\b[^\r\n]*"
        rf", required capacity (?P<required>{DECIMAL_PATTERN}),"
        rf" available log2\(q/t\) (?P<available>{DECIMAL_PATTERN})\s*$",
        stderr, re.IGNORECASE)
    if capacity:
        required, required_text = canonical_decimal(capacity.group("required"))
        available, available_text = canonical_decimal(capacity.group("available"))
        if required > available:
            _, shortfall_text = canonical_decimal(str(required - available))
            return ("INFEASIBLE", "CAPACITY_SHORTFALL", required_text,
                    available_text, shortfall_text)
    return "ERROR", "PROCESS_ERROR", "", "", ""


def execute(args: argparse.Namespace, cells: list[Cell], project: pathlib.Path) -> int:
    build_dir = pathlib.Path(args.build_dir)
    results_root = pathlib.Path(args.results_root)
    if not build_dir.is_absolute():
        fail("non-dry-run requires an absolute --build-dir")
    if not results_root.is_absolute():
        fail("non-dry-run requires an absolute --results-root")
    build_dir = build_dir.resolve()
    results_root = results_root.resolve(strict=False)
    if not build_dir.is_dir():
        fail("--build-dir is not a directory")
    if args.resume:
        if not results_root.is_dir():
            fail("--resume requires an existing results root")
    elif results_root.exists():
        fail("results root already exists; use a new path or --resume")

    commit, dirty = source_identity(project)
    diagnostic = args.suite == "smoke"
    if dirty and not diagnostic:
        fail("paper evidence requires a clean source tree")
    cache_build_type = read_build_type(build_dir)
    if cache_build_type != "Release" and not diagnostic:
        fail("paper evidence requires a Release CMake build")

    needed = list(dict.fromkeys(cell.producer for cell in cells))
    provenances: dict[str, dict[str, Any]] = {}
    binaries: dict[str, dict[str, Any]] = {}
    for name in needed:
        binary = build_dir / name
        if binary.parent.resolve() != build_dir or not binary.is_file() or not os.access(binary, os.X_OK):
            fail(f"required executable is missing from --build-dir: {name}")
        provenance = build_provenance(binary)
        if provenance["commit"] != commit:
            fail(f"{name} embedded commit does not match HEAD")
        if pathlib.Path(provenance["source_dir"]).resolve() != project.resolve():
            fail(f"{name} embedded source directory mismatch")
        if provenance["dirty"] != dirty:
            fail(f"{name} embedded dirty state does not match source tree")
        if provenance["build_type"] != cache_build_type:
            fail(f"{name} embedded build type disagrees with CMakeCache Release state")
        if provenance["build_type"] != "Release" and not diagnostic:
            fail(f"{name} is not an embedded Release build")
        provenances[name] = provenance
        binaries[name] = {
            "path": str(binary), "sha256": sha256_file(binary),
            "provenance": provenance,
        }

    source = {"commit": commit, "dirty": dirty, "dir": str(project.resolve())}
    build = {"dir": str(build_dir), "type": cache_build_type, "binaries": binaries}
    manifest_path = results_root / "manifest.json"
    if args.resume:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail(f"cannot read resume manifest: {error}")
        completed = validate_resume(
            manifest, results_root, args.suite, args.seed, args.threads,
            source, build, cells)
    else:
        results_root.mkdir(mode=0o755)
        for name in ("csv", "workloads", "traces", "logs"):
            (results_root / name).mkdir()
        manifest = {
            "schema": SCHEMA,
            "suite": args.suite,
            "seed": args.seed,
            "repetitions": 1,
            "classification": "diagnostic" if diagnostic else (
                "comparison-ineligible" if args.suite == "feasibility" else "evidence"),
            "thread_policy": {
                "OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": str(args.threads)},
            "profiles": profile_list(cells),
            "source": source,
            "build": build,
            "machine": machine_metadata(provenances),
            "directories": {
                "csv": "csv", "workloads": "workloads",
                "traces": "traces", "logs": "logs"},
            "cells": [],
        }
        completed = {}
        write_state(results_root, manifest)

    for cell in cells:
        cell_id = cell.cell_id(args.threads)
        if cell_id in completed:
            print(f"RESUME skip {cell_id}")
            continue
        record = expected_cell_record(cell, args.threads, results_root)
        paths = record["output"]
        for path_key, relative in paths.items():
            if path_key == "expected_csv_rows":
                continue
            path = ensure_contained(results_root, relative, "derived output")
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                fail(f"refusing to overwrite output: {path}")
        binary = pathlib.Path(binaries[cell.producer]["path"])
        command = [str(binary), *record["argv"][1:]]
        environment = os.environ.copy()
        environment.update(record["environment"])
        csv_path = results_root / paths["csv"]
        log_path = results_root / paths["log"]
        print("RUN " + " ".join((
            f"OMP_NUM_THREADS={args.threads}", "OMP_DYNAMIC=FALSE",
            cell.producer, *record["argv"][1:],
        )))
        with csv_path.open("xb") as stdout, log_path.open("xb") as stderr:
            result = subprocess.run(
                command, env=environment, stdout=stdout, stderr=stderr,
                check=False)
        stderr_text = log_path.read_text(encoding="utf-8", errors="replace")
        output = record["output"]
        output["log_sha256"] = sha256_file(log_path)
        if result.returncode == 0:
            if not csv_path.is_file():
                fail(f"producer did not create CSV: {cell_id}")
            output["csv_sha256"] = sha256_file(csv_path)
            output["csv_row_count"] = csv_row_count(csv_path)
            output["measurement_output"] = "measured-csv"
            if output["csv_row_count"] != output["expected_csv_rows"]:
                record.update({
                    "status": "ERROR", "reason_code": "PROCESS_ERROR",
                    "required_bits": "", "available_bits": "",
                    "shortfall_bits": "",
                })
            if cell.review:
                for path_key, hash_key in (("workload", "workload_sha256"),
                                           ("trace", "trace_sha256")):
                    artifact = results_root / output[path_key]
                    if not artifact.is_file():
                        fail(f"review producer did not create {path_key}: {cell_id}")
                    output[hash_key] = sha256_file(artifact)
            if "status" not in record:
                record.update({
                    "status": "MEASURED", "reason_code": "NONE",
                    "required_bits": "", "available_bits": "",
                    "shortfall_bits": "",
                })
        else:
            status, reason, required, available, shortfall = classify_failure(stderr_text)
            if status == "INFEASIBLE" and csv_path.stat().st_size != 0:
                status, reason, required, available, shortfall = (
                    "ERROR", "PROCESS_ERROR", "", "", "")
            record.update({
                "status": status, "reason_code": reason,
                "required_bits": required, "available_bits": available,
                "shortfall_bits": shortfall, "exit_code": result.returncode,
            })
            if csv_path.is_file():
                output["csv_sha256"] = sha256_file(csv_path)
            if status == "INFEASIBLE":
                output["csv_row_count"] = 0
                output["measurement_output"] = "absent-empty-csv"
        manifest["cells"].append(record)
        write_state(results_root, manifest)
        if record["status"] == "ERROR" and result.returncode == 0:
            print(
                f"CELL ERROR PROCESS_ERROR {cell_id}: CSV row count "
                f"{output['csv_row_count']} != {output['expected_csv_rows']}",
                file=sys.stderr)
            return 2
        if result.returncode != 0:
            print(f"CELL {record['status']} {record['reason_code']} {cell_id}", file=sys.stderr)
            if args.suite == "feasibility" and record["status"] == "INFEASIBLE":
                continue
            return 2
    reviews = {cell.cell_id(args.threads): cell.review for cell in cells}
    for record in manifest["cells"]:
        if record["status"] != "MEASURED":
            continue
        try:
            run_verifiers(
                project, manifest_path, record, reviews[record["cell_id"]])
        except RunnerError as error:
            record["status"] = "ERROR"
            record["reason_code"] = "PROCESS_ERROR"
            write_state(results_root, manifest)
            raise error
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True,
                        choices=("primary", "sensitivity", "feasibility", "smoke"))
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--threads", required=True, type=int)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--results-root")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.threads <= 0:
        parser.error("--threads must be positive")
    wanted_seed = expected_seed(args.suite)
    if args.seed != wanted_seed:
        parser.error(f"suite {args.suite} requires --seed={wanted_seed}")
    args.dry_run = args.dry_run or os.environ.get("DRY_RUN") == "1"
    if args.resume and args.dry_run:
        parser.error("--resume cannot be combined with --dry-run")
    if not args.dry_run and args.results_root is None:
        parser.error("non-dry-run requires --results-root")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cells = matrix(args.suite, args.seed)
    if args.dry_run:
        return dry_run(cells, args.threads, args.suite)
    project = SCRIPT_DIR.parent
    try:
        return execute(args, cells, project)
    except RunnerError as error:
        print(f"run_pre_threshold_profiles: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
PY
