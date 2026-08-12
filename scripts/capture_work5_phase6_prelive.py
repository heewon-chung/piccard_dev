#!/usr/bin/env python3
"""Create one source-bound, journaled, non-production Phase 6 pre-live gate.

The command is intentionally separate from ``run_work5_benchmarks.py``.  It
never creates a ``piccard-work5-run-v1`` root, never calls a Work #5 producer
phase, and never retries a command.  Its only measured commands are the two
direct TOY dynamic correctness diagnostics requested by the Phase 6 plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class CaptureError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError(message)


def journal_output_path(journal: Path, relative: Any) -> Path:
    validate_journal_relative_path(relative)
    candidate = journal.parent / relative
    # The journal itself can never be a command output: hashing it while it is
    # being appended would make the END record self-referential and would
    # invalidate the event stream.  Resolve only after rejecting links so a
    # path alias cannot smuggle the journal in through a symlink.
    require(candidate.resolve(strict=False) != journal.resolve(strict=False),
            "journal output artifact aliases the command journal")
    require(not candidate.is_symlink() and candidate.is_file(),
            "journal output artifact is missing or unsafe")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(journal.parent.resolve())
    except ValueError as exc:
        raise CaptureError("journal output artifact escapes evidence root") from exc
    return candidate


def validate_journal_relative_path(relative: Any) -> None:
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute() and
            "\\" not in relative and "\x00" not in relative and
            all(part not in ("", ".", "..") for part in relative.split("/")),
            "journal output path is malformed")


def validate_journal_timestamp(value: Any) -> None:
    require(isinstance(value, str) and value.endswith("Z") and len(value) >= 20,
            "journal timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CaptureError("journal timestamp is malformed") from exc
    require(parsed.tzinfo is not None, "journal timestamp lacks UTC offset")


def git(source_root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=source_root, text=True,
                            capture_output=True, check=False)
    require(result.returncode == 0, f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def output_path(root: Path, relative: str) -> Path:
    path = root / relative
    resolved_root = root.resolve()
    require(path.resolve(strict=False).is_relative_to(resolved_root), "journal output path escapes evidence root")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def write_exclusive(path: Path, payload: bytes) -> None:
    """Create one regular output artifact without assuming a single write."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CaptureError("short write creating command output artifact")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Journal:
    """Append-only fsynced command START/END records with monotone IDs."""

    def __init__(self, root: Path, *, source_root: Path, git_sha: str,
                 environment: dict[str, str]) -> None:
        self.root, self.source_root, self.git_sha, self.environment = root, source_root, git_sha, environment
        self.path = root / "commands.jsonl"
        self.sequence = 0

    def _append(self, value: dict[str, Any]) -> None:
        encoded = canonical_json(value)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(encoded)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise CaptureError("short write appending command journal")
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def run(self, command_id: str, argv: list[str], *, cwd: Path, classification: str = "PASS",
            allow_exit: set[int] | None = None) -> subprocess.CompletedProcess[bytes]:
        self.sequence += 1
        sequence = self.sequence
        stdout_relative = f"logs/{sequence:02d}-{command_id}.stdout"
        stderr_relative = f"logs/{sequence:02d}-{command_id}.stderr"
        started = utc_now()
        base = {
            "schema": "piccard-work5-command-event-v1", "sequence": sequence,
            "command_id": command_id, "argv": argv, "cwd": str(cwd.resolve()),
            "environment": self.environment, "git_sha": self.git_sha,
            "stdout_path": stdout_relative, "stderr_path": stderr_relative,
            "started_at_utc": started,
        }
        self._append({"event": "START", **base})
        completed = subprocess.run(argv, cwd=cwd, env={**os.environ, **self.environment},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        stdout_path = output_path(self.root, stdout_relative)
        stderr_path = output_path(self.root, stderr_relative)
        for path, data in ((stdout_path, completed.stdout), (stderr_path, completed.stderr)):
            write_exclusive(path, data)
        permitted = allow_exit if allow_exit is not None else {0}
        observed_classification = classification if completed.returncode in permitted else "FAIL"
        self._append({"event": "END", **base, "ended_at_utc": utc_now(),
                      "exit_code": completed.returncode,
                      "stdout_sha256": sha256_file(stdout_path),
                      "stderr_sha256": sha256_file(stderr_path),
                      "classification": observed_classification})
        if completed.returncode not in permitted:
            raise CaptureError(f"command {command_id} failed with exit {completed.returncode}")
        return completed


def journal_events(path: Path) -> list[dict[str, Any]]:
    try:
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError(f"cannot parse command journal: {exc}") from exc
    require(events, "command journal is empty")
    starts: dict[int, dict[str, Any]] = {}
    expected_sequence = 1
    seen_ids: set[str] = set()
    seen_output_paths: set[str] = set()
    active_sequence: int | None = None
    start_fields = {"schema", "event", "sequence", "command_id", "argv", "cwd",
                    "environment", "git_sha", "stdout_path", "stderr_path", "started_at_utc"}
    end_fields = {*start_fields, "ended_at_utc", "exit_code", "stdout_sha256",
                  "stderr_sha256", "classification"}
    for event in events:
        require(event.get("schema") == "piccard-work5-command-event-v1", "journal schema mismatch")
        sequence = event.get("sequence")
        require(type(sequence) is int and sequence >= 1, "journal sequence is malformed")
        event_type = event.get("event")
        require(set(event) == (start_fields if event_type == "START" else end_fields),
                "journal event fields do not match the frozen schema")
        require(isinstance(event.get("argv"), list) and event["argv"] and
                all(type(item) is str and item for item in event["argv"]),
                "journal argv is malformed")
        require(isinstance(event.get("cwd"), str) and Path(event["cwd"]).is_absolute(),
                "journal cwd is malformed")
        require(isinstance(event.get("environment"), dict) and
                all(type(key) is str and type(value) is str
                    for key, value in event["environment"].items()),
                "journal environment is malformed")
        require(isinstance(event.get("git_sha"), str) and len(event["git_sha"]) == 40 and
                all(ch in "0123456789abcdef" for ch in event["git_sha"]),
                "journal git SHA is malformed")
        validate_journal_relative_path(event.get("stdout_path"))
        validate_journal_relative_path(event.get("stderr_path"))
        validate_journal_timestamp(event.get("started_at_utc"))
        if event.get("event") == "START":
            require(active_sequence is None and sequence == expected_sequence and sequence not in starts,
                    "journal START sequence is not monotone")
            expected_sequence += 1
            command_id = event.get("command_id")
            require(isinstance(command_id, str) and command_id and command_id not in seen_ids,
                    "journal command id is missing or duplicated")
            seen_ids.add(command_id)
            starts[sequence] = event
            active_sequence = sequence
        elif event.get("event") == "END":
            require(active_sequence == sequence,
                    "journal END is not the matching next event for its START")
            start = starts.pop(sequence, None)
            require(start is not None and all(event.get(key) == start.get(key) for key in
                                              ("command_id", "argv", "cwd", "environment", "git_sha",
                                               "stdout_path", "stderr_path", "started_at_utc")),
                    "journal END does not bind its START")
            require(isinstance(event.get("exit_code"), int) and isinstance(event.get("ended_at_utc"), str) and
                    event.get("classification") in ("PASS", "KNOWN_WORK6_SCOPE_DIAGNOSTIC_MISMATCH"),
                    "journal END result is malformed")
            require(type(event.get("exit_code")) is int, "journal END exit code is malformed")
            validate_journal_timestamp(event.get("ended_at_utc"))
            for key in ("stdout_sha256", "stderr_sha256"):
                value = event.get(key)
                require(isinstance(value, str) and len(value) == 64 and
                        all(ch in "0123456789abcdef" for ch in value),
                        "journal END output hash is malformed")
                output_relative = event.get(f"{key[:-7]}_path")
                require(isinstance(output_relative, str) and output_relative not in seen_output_paths,
                        "journal output artifact is referenced more than once")
                output_path = journal_output_path(path, output_relative)
                seen_output_paths.add(output_relative)
                require(sha256_file(output_path) == value,
                        "journal output hash drifted")
            active_sequence = None
        else:
            raise CaptureError("journal event type is malformed")
    require(not starts, "command journal has an incomplete START event")
    return events


def configure_command(source_root: Path, build_dir: Path) -> list[str]:
    configure = ["cmake", "-S", str(source_root), "-B", str(build_dir),
                 "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTS=ON",
                 "-DBUILD_BENCHMARKS=ON"]
    # Homebrew's OpenFHE packages on this macOS host expose absolute dylib
    # paths without adding that directory to the build RPATH.  The pre-live
    # build is intentionally fresh, so bind the runtime search path in the
    # recorded configure argv rather than relying on the caller's shell
    # environment.  This keeps commands.jsonl truthful and makes every later
    # CTest/direct-benchmark child use the same source-bound binary contract.
    if platform.system() == "Darwin" and Path("/usr/local/lib").is_dir():
        configure.append("-DCMAKE_BUILD_RPATH=/usr/local/lib")

    return configure


def workspace_build_command(source_root: Path) -> list[str]:
    return ["cmake", "--build", str(source_root / "build"), "-j2"]


def build(source_root: Path, build_dir: Path, journal: Journal) -> None:
    journal.run("configure-release", configure_command(source_root, build_dir), cwd=source_root)
    journal.run("build-release", ["cmake", "--build", str(build_dir), "-j2"], cwd=source_root)
    # PreThresholdProfileRunner is an existing CTest test whose provenance
    # helper intentionally reads the repository's conventional build/ path.
    # Refresh that ignored helper build inside the journal before CTest so a
    # prior-commit local build cannot make a source-bound gate look green.
    workspace_build = source_root / "build"
    require(workspace_build.is_dir(), "source workspace build directory is missing")
    journal.run("workspace-build", workspace_build_command(source_root), cwd=source_root)


def write_manifest(root: Path) -> str:
    entries: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CaptureError("pre-live evidence contains a symlink")
        if path.is_file() and path.relative_to(root).as_posix() != "SHA256SUMS":
            entries.append((path.relative_to(root).as_posix(), path))
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    payload = "".join(f"{sha256_file(path)}  {relative}\n" for relative, path in entries).encode("utf-8")
    sums = root / "SHA256SUMS"
    descriptor = os.open(sums, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return sha256_file(sums)


def capture(args: argparse.Namespace) -> None:
    source_root = Path(args.source_root).resolve()
    build_dir = Path(args.build_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    require(source_root.is_dir() and (source_root / "scripts" / "run_work5_benchmarks.py").is_file(),
            "source root is not a Piccard checkout")
    require(git(source_root, "branch", "--show-current") == "main", "pre-live capture requires main branch")
    require(not git(source_root, "status", "--porcelain=v1", "--untracked-files=no"),
            "pre-live capture requires a clean tracked source tree")
    git_sha = git(source_root, "rev-parse", "HEAD")
    require(git_sha == args.expect_git_sha, "--expect-git-sha mismatch")
    require(not output_dir.exists() and not build_dir.exists(),
            "pre-live output/build path already exists")
    require(output_dir.parent != source_root and "piccard-work5-evidence" not in output_dir.as_posix(),
            "pre-live capture refuses a production evidence-root path")
    environment = {"OMP_NUM_THREADS": str(args.threads), "OMP_DYNAMIC": "FALSE"}
    output_dir.mkdir(parents=True, mode=0o700)
    journal = Journal(output_dir, source_root=source_root, git_sha=git_sha, environment=environment)
    build(source_root, build_dir, journal)
    focused = [sys.executable, "-m", "unittest", "tests.scripts.test_bench_dynamic_refresh_cli",
               "tests.scripts.test_run_work5_benchmarks", "tests.scripts.test_verify_work5_benchmarks",
               "tests.scripts.test_capture_work5_phase6_prelive",
               "tests.scripts.test_seal_work5_benchmarks", "-v"]
    journal.run("focused-python", focused, cwd=source_root)
    targeted = ["ctest", "--test-dir", str(build_dir), "--output-on-failure", "-R",
                "^(EstimatorProvenanceSerializers|DynamicCiphertextStore|DynamicRefreshE2E|"
                "DynamicRefreshBenchmark|BenchDynamicRefreshCli|RunWork5Benchmarks|"
                "VerifyWork5Benchmarks|PreThresholdProfileRunner)$"]
    journal.run("focused-ctest", targeted, cwd=source_root)
    full = journal.run("full-ctest", ["ctest", "--test-dir", str(build_dir), "--output-on-failure"],
                       cwd=source_root, classification="KNOWN_WORK6_SCOPE_DIAGNOSTIC_MISMATCH",
                       allow_exit={8})
    sys.path.insert(0, str(source_root / "scripts"))
    import run_work5_benchmarks as runner
    import verify_work5_benchmarks as verifier
    ctest_receipt = verifier.classify_work6_scope_ctest(8, full.stdout, full.stderr)
    direct_rows: list[dict[str, Any]] = []
    for updates, (label, argv) in zip((1, 2), runner.planned_dynamic_commands(build_dir, output_dir)):
        completed = journal.run(f"direct-{label}", argv, cwd=source_root)
        row_path = output_path(output_dir, f"dynamic/{label}.csv")
        descriptor = os.open(row_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, completed.stdout)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        row = runner.validate_dynamic_csv(completed.stdout, updates)
        verifier.verify_dynamic_csv(row_path, updates)
        direct_rows.append({"label": label, "csv": row_path.relative_to(output_dir).as_posix(),
                            "sha256": sha256_file(row_path), "correctness_status": row["correctness_status"]})
    require(direct_rows[0]["correctness_status"] == direct_rows[1]["correctness_status"] == "PASS",
            "direct dynamic correctness row failed")
    events = journal_events(output_dir / "commands.jsonl")
    frozen_hashes = verifier.frozen_work6_hashes()
    executables = {name: sha256_file(build_dir / name) for name in
                   ("bench_dynamic", "bench_piccard", "bench_onehot_sqrt", "bench_review_comparison")}
    metadata = {
        "schema": "piccard-work5-phase6-prelive-iterate-v1", "production": False,
        "purpose": "phase6-dynamic-schema-seal-and-ctest-code-gate", "source_root": str(source_root),
        "git_sha": git_sha, "tracked_clean": True, "branch": "main", "build_dir": str(build_dir),
        "build_type": "Release", "environment": environment, "started_at_utc": events[0]["started_at_utc"],
        "ended_at_utc": utc_now(), "command_event_count": len(events),
        "commands_journal": "commands.jsonl", "dynamic_rows": direct_rows,
        "ctest_gate": ctest_receipt, "scripts": {name: sha256_file(source_root / "scripts" / name)
            for name in ("run_work5_benchmarks.py", "verify_work5_benchmarks.py",
                         "capture_work5_phase6_prelive.py", "seal_work5_benchmarks.py")},
        "executables": executables, "frozen_work6_hashes": frozen_hashes,
        "no_production_runner_phase": True,
    }
    (output_dir / "manifest.json").write_bytes(canonical_json(metadata))
    write_manifest(output_dir)


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--expect-git-sha", required=True)
    parser.add_argument("--threads", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args(list(argv))
    if args.threads != 2 or args.seed != 7:
        parser.error("--threads=2 and --seed=7 are frozen")
    return args


def main(argv: Iterable[str] | None = None) -> int:
    try:
        capture(parse_args(sys.argv[1:] if argv is None else argv))
        print(json.dumps({"schema": "piccard-work5-phase6-prelive-iterate-v1", "verdict": "PASS"},
                         sort_keys=True))
        return 0
    except CaptureError as exc:
        print(f"capture_work5_phase6_prelive: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
