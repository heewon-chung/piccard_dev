#!/usr/bin/env python3
"""Fail-closed verifier for the immutable Work 7 claim lifecycle."""

import argparse
import difflib
import hashlib
import json
import stat
import sys
from pathlib import Path

try:
    from work7_evidence import (assert_output_roots_outside, _atomic_create, _reject_symlink_components, _stable_regular_file,
                                canonical_json_bytes, sha256_file, snapshot_git_worktree,
                                verify_tree_seal)
except ModuleNotFoundError:
    from scripts.work7_evidence import (assert_output_roots_outside, _atomic_create, _reject_symlink_components, _stable_regular_file,
                                        canonical_json_bytes, sha256_file, snapshot_git_worktree,
                                        verify_tree_seal)

IDS = ("W7-G1-ESTIMATOR", "W7-G2-SANITIZER", "W7-G3-CALIBRATION",
       "W7-G4-COMPARISON", "W7-G5-REAL-DATA", "W7-G6-DYNAMIC", "W7-G7-INTEGRATION")
ROW_KEYS = {"id", "original_intent", "source_paths", "required_ctest_names", "evidence_keys",
            "allowed_states", "performance_state", "deferred_rationale", "prohibited_overclaim"}
TOP_KEYS = {"schema", "allowed_gates", "claims"}
STATES = {"implementation_state": ["IMPLEMENTED"],
          "toy_evidence_state": ["PENDING", "TOY_VERIFIED"],
          "performance_state": ["PERFORMANCE_PENDING"]}


class Failure(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Failure(f"invalid arguments: {message}")


def parser() -> argparse.ArgumentParser:
    value = Parser(add_help=False)
    value.add_argument("--mode", required=True, choices=("static", "evidence-bound", "claim7", "terminal"))
    for name in ("contract", "source-root", "source-commit", "ctest-inventory", "output",
                 "runtime-seal", "phase2-closure-seal", "phase3-candidate-seal",
                 "phase3-closure-seal", "work-review-seal", "review-packet", "claude-review",
                 "sol-review", "phase0-seal", "paper-root", "threshold-root"):
        value.add_argument("--" + name, type=Path if name != "source-commit" else str)
    return value


def require_absolute(path: Path | None, name: str, exists: bool = True) -> Path:
    if path is None or not path.is_absolute():
        raise Failure(f"{name} must be an absolute path")
    _reject_symlink_components(path)
    try:
        return path.resolve(strict=exists)
    except FileNotFoundError as error:
        raise Failure(f"{name} does not exist") from error


def inside(root: Path, candidate: Path, label: str) -> Path:
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise Failure(f"{label} escapes source root") from error
    return candidate


def nonempty_strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise Failure(f"{label} must be a nonempty string list")
    return value


def load_contract(path: Path, source: Path, inventory: set[str]) -> list[dict]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("invalid contract JSON") from error
    if not isinstance(value, dict) or set(value) != TOP_KEYS or value.get("schema") != "piccard-work7-claim-lifecycle-v1":
        raise Failure("invalid contract schema")
    gates = value.get("allowed_gates")
    if gates != {"threshold_gate_state": ["DEFERRED_EXPECTED"],
                 "work_gate_state": ["PENDING", "POC_APPROVED_PERFORMANCE_PENDING"]}:
        raise Failure("invalid allowed gates")
    claims = value.get("claims")
    if not isinstance(claims, list) or tuple(row.get("id") for row in claims if isinstance(row, dict)) != IDS:
        raise Failure("contract must contain exactly the ordered claim IDs")
    for row in claims:
        if not isinstance(row, dict) or set(row) != ROW_KEYS:
            raise Failure("unknown or missing claim field")
        if not isinstance(row["original_intent"], str) or not row["original_intent"]:
            raise Failure("claim original intent is required")
        for field in ("source_paths", "required_ctest_names", "evidence_keys"):
            nonempty_strings(row[field], field)
        for field in ("deferred_rationale", "prohibited_overclaim"):
            if not isinstance(row[field], str) or not row[field]:
                raise Failure(f"{field} is required")
        if row["performance_state"] != "PERFORMANCE_PENDING" or row["allowed_states"] != STATES:
            raise Failure("invalid field-specific claim state")
        for relative in row["source_paths"]:
            candidate = Path(relative)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise Failure("invalid source path")
            resolved = inside(source, (source / candidate).resolve(strict=False), "source path")
            if not resolved.is_file():
                raise Failure("referenced source path is missing")
        if any(name not in inventory for name in row["required_ctest_names"]):
            raise Failure("required CTest name is missing")
    return claims


def inventory(path: Path) -> set[str]:
    try:
        import re
        found: dict[int, str] = {}
        lines = path.read_text(encoding="utf-8").splitlines()
        if len(lines) < 3 or re.fullmatch(r"Test project .+", lines[0]) is None:
            raise Failure("malformed CTest inventory header")
        cursor = 1
        while cursor < len(lines) and lines[cursor]:
            match = re.fullmatch(r"\s+Test\s+#(\d+): ([A-Za-z0-9_]+)", lines[cursor])
            if match is None:
                raise Failure("malformed CTest inventory line")
            number, name = int(match.group(1)), match.group(2)
            if number in found or name in found.values():
                raise Failure("duplicate CTest inventory entry")
            found[number] = name
            cursor += 1
        if cursor >= len(lines) or lines[cursor] != "":
            raise Failure("malformed CTest inventory trailer")
        cursor += 1
        if cursor != len(lines) - 1:
            raise Failure("malformed CTest inventory trailer")
        trailer = re.fullmatch(r"Total Tests: (\d+)", lines[cursor])
        if trailer is None or int(trailer.group(1)) != len(found):
            raise Failure("CTest inventory count does not match records")
        if not found:
            raise Failure("empty CTest inventory")
        return set(found.values())
    except OSError as error:
        raise Failure("cannot read CTest inventory") from error


def seal(path: Path, kind: str, previous: str | None = None) -> dict:
    try:
        value = verify_tree_seal(path, previous)
    except (ValueError, OSError) as error:
        raise Failure("invalid or tampered seal") from error
    if value["kind"] != kind:
        raise Failure("foreign seal kind")
    return value


def runtime_evidence(path: Path, commit: str, claims: list[dict]) -> set[str]:
    value = seal(path, "phase2-runtime-artifacts")
    root = Path(value["artifact_root"])
    index_path = root / "evidence-index.json"
    if "evidence-index.json" not in {entry["path"] for entry in value["entries"]}:
        raise Failure("runtime evidence index is not sealed")
    try:
        index = json.loads(index_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("invalid runtime evidence index") from error
    if (not isinstance(index, dict) or set(index) != {"schema", "source_commit", "claims"} or
            index["schema"] != "piccard-work7-evidence-index-v2" or index["source_commit"] != commit or
            not isinstance(index["claims"], dict)):
        raise Failure("foreign or invalid runtime evidence")
    sealed = {entry["path"]: entry for entry in value["entries"]}
    evidence: set[str] = set()
    used: set[str] = set()
    for claim in claims[:6]:
        claim_id = claim["id"]
        records = index["claims"].get(claim_id)
        if not isinstance(records, dict) or set(records) != set(claim["evidence_keys"]):
            raise Failure("missing sealed claim evidence")
        for key, record in records.items():
            if (not isinstance(record, dict) or set(record) != {"path", "sha256", "artifact_kind"} or
                    not isinstance(record["path"], str) or not isinstance(record["sha256"], str) or
                    not isinstance(record["artifact_kind"], str) or record["path"] in {"evidence-index.json"} or
                    record["path"] not in sealed or record["path"] in used or
                    record["sha256"] != sealed[record["path"]]["sha256"] or
                    record["artifact_kind"] not in {"ctest-log", "probe-output", "csv-artifact"}):
                raise Failure("invalid sealed claim evidence")
            used.add(record["path"])
        evidence.add(claim_id)
    if any(item not in IDS[:6] for item in index["claims"]):
        raise Failure("invalid runtime evidence claim")
    return evidence


def reference_list(value: object) -> bool:
    return (isinstance(value, list) and bool(value) and
            all(isinstance(item, str) and bool(item) for item in value) and len(set(value)) == len(value))


def report_claims(report: object, mode: str, commit: str, states: list[str], contract_claims: list[dict]) -> None:
    top = {"schema", "source_commit", "mode", "threshold_gate_state", "work_gate_state", "claims",
           "status", "validation_errors", "input_seals"}
    row_keys = {"id", "implementation_state", "toy_evidence_state", "performance_state", "source_paths",
                "required_ctest_names", "evidence_keys", "deferred_rationale", "prohibited_overclaim"}
    if (not isinstance(report, dict) or set(report) != top or report["schema"] != "piccard-work7-claim-report-v1" or
            report["mode"] != mode or report["source_commit"] != commit or report["threshold_gate_state"] != "DEFERRED_EXPECTED" or
            report["work_gate_state"] != ("POC_APPROVED_PERFORMANCE_PENDING" if mode == "terminal" else "PENDING") or
            report["status"] != "PASS" or report["validation_errors"] != [] or not isinstance(report["input_seals"], dict) or
            not isinstance(report["claims"], list) or len(report["claims"]) != 7 or
            any(not isinstance(row, dict) or set(row) != row_keys for row in report["claims"]) or
            [row["id"] for row in report["claims"]] != list(IDS) or
            any(row["implementation_state"] != "IMPLEMENTED" or row["performance_state"] != "PERFORMANCE_PENDING" for row in report["claims"]) or
            [row["toy_evidence_state"] for row in report["claims"]] != states or
            any(not reference_list(row[field]) for row in report["claims"] for field in ("source_paths", "required_ctest_names", "evidence_keys")) or
            any(any(not isinstance(row[field], str) or not row[field] for field in ("deferred_rationale", "prohibited_overclaim")) for row in report["claims"]) or
            any(any(report_row[field] != contract_row[field] for field in ("source_paths", "required_ctest_names", "evidence_keys", "deferred_rationale", "prohibited_overclaim"))
                for report_row, contract_row in zip(report["claims"], contract_claims))):
        raise Failure("invalid sealed claim report")


def _canonical_object(path: Path, label: str) -> dict:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise Failure(f"invalid {label}") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise Failure(f"non-canonical {label}")
    return value


def _safe_response_strategy(paper: Path) -> bytes:
    path = paper / "Revision" / "ResponseStrategy.md"
    _reject_symlink_components(path)
    if path.is_symlink() or not path.exists() or not stat.S_ISREG(path.lstat().st_mode):
        raise Failure("ResponseStrategy baseline is missing or unsafe")
    try:
        _, _, raw = _stable_regular_file(path)
        raw.decode("utf-8", "strict")
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise Failure("ResponseStrategy baseline is not UTF-8") from error
    return raw


def _render_candidate(baseline: bytes) -> bytes:
    text = baseline.decode("utf-8", "strict")
    suffix = "" if not text or text.endswith("\n") else "\n"
    rows = "\n".join(f"- `{claim}`: `IMPLEMENTED`; `TOY_VERIFIED`; `PERFORMANCE_PENDING`." for claim in IDS)
    return (text + suffix + "\n<!-- WORK7_RESPONSE_CANDIDATE_BEGIN -->\n"
            "### Work 7 PoC integration candidate — unapplied\n\n"
            "This candidate records implementation and toy-evidence readiness only; it does not make a paper-grade completion or performance claim.\n\n"
            + rows + "\n\n"
            "All performance evaluation remains `PERFORMANCE_PENDING`; actual-data and repeated-measurement campaigns are deferred.\n\n"
            "Threshold FP/FN work remains `DEFERRED_EXPECTED`. It is not authorized by this candidate and no threshold branch action is requested.\n"
            "<!-- WORK7_RESPONSE_CANDIDATE_END -->\n").encode("utf-8")


def _expected_diff(baseline: bytes, candidate: bytes) -> bytes:
    return "".join(difflib.unified_diff(baseline.decode("utf-8").splitlines(keepends=True),
                                          candidate.decode("utf-8").splitlines(keepends=True),
                                          fromfile="a/Revision/ResponseStrategy.md",
                                          tofile="b/Revision/ResponseStrategy.md", lineterm="\n")).encode("utf-8")


def _phase0_state(path: Path, source: Path, paper: Path, threshold: Path, commit: str) -> dict:
    value = seal(path, "phase0")
    if value["previous_seal_sha256"] is not None:
        raise Failure("Phase 0 seal is unexpectedly chained")
    state_path = Path(value["artifact_root"]) / "state.json"
    if "state.json" not in {entry["path"] for entry in value["entries"]}:
        raise Failure("Phase 0 state is not sealed")
    state = _canonical_object(state_path, "Phase 0 state")
    build = state.get("build")
    if (set(state) != {"schema", "source", "paper", "threshold", "build", "session_id"} or
            state.get("schema") != "piccard-work7-phase0-state-v2" or not isinstance(state.get("source"), dict) or
            not isinstance(build, dict) or set(build) != {"root"} or not isinstance(build.get("root"), str) or
            state["source"].get("head") != commit or state.get("session_id") != f"work7-{commit}"):
        raise Failure("invalid Phase 0 source/session state")
    if snapshot_git_worktree(source) != state["source"]:
        raise Failure("source worktree snapshot changed")
    if snapshot_git_worktree(paper) != state.get("paper") or snapshot_git_worktree(threshold) != state.get("threshold"):
        raise Failure("external worktree snapshot changed")
    return state


def _mappings(claims: list[dict]) -> list[dict]:
    return [{"id": row["id"], "implementation_state": "IMPLEMENTED", "toy_evidence_state": "TOY_VERIFIED",
             "performance_state": "PERFORMANCE_PENDING"} for row in claims]


def candidate_evidence(args: argparse.Namespace, phase2: Path, candidate: Path, commit: str, claims: list[dict]) -> None:
    phase2_value = seal(phase2, "phase2-closure")
    if phase2_value["previous_seal_sha256"] is None:
        raise Failure("phase2 closure is not chained")
    phase2_root = Path(phase2_value["artifact_root"])
    report_path = phase2_root / "evidence-bound-report.json"
    if "evidence-bound-report.json" not in {entry["path"] for entry in phase2_value["entries"]}:
        raise Failure("missing sealed evidence-bound report")
    evidence_report = _canonical_object(report_path, "sealed evidence-bound report")
    report_claims(evidence_report, "evidence-bound", commit, ["TOY_VERIFIED"] * 6 + ["PENDING"], claims)
    if evidence_report.get("input_seals") != {"runtime_seal_sha256": phase2_value["previous_seal_sha256"]}:
        raise Failure("evidence-bound report has wrong runtime seal")
    phase0 = require_absolute(args.phase0_seal, "phase0 seal")
    paper = require_absolute(args.paper_root, "paper root")
    threshold = require_absolute(args.threshold_root, "threshold root")
    phase0_value = seal(phase0, "phase0")
    phase0_root = Path(phase0_value["artifact_root"])
    session = phase0_root.parent.parent
    if phase0_root != session / "phase0" / "artifacts" or phase0 != session / "phase0" / "seal.json":
        raise Failure("Phase 0 seal is outside its declared session")
    if phase2 != session / "phase2" / "closure-seal.json" or phase2_root != session / "phase2" / "closure-artifacts":
        raise Failure("Phase 2 closure is outside the Phase 0 session")
    state = _phase0_state(phase0, require_absolute(args.source_root, "source root"), paper, threshold, commit)
    candidate_value = seal(candidate, "phase3-candidate-artifacts", sha256_file(phase2))
    root = Path(candidate_value["artifact_root"])
    if candidate != session / "phase3" / "candidate-seal.json" or root != session / "phase3" / "candidate-artifacts":
        raise Failure("candidate seal is outside the Phase 0 session")
    expected_files = {"ResponseStrategy.candidate.md", "ResponseStrategy.candidate.diff", "candidate-metadata.json", "candidate-validation.json"}
    if {entry["path"] for entry in candidate_value["entries"]} != expected_files:
        raise Failure("candidate seal contains missing or foreign artifacts")
    candidate_path, diff_path = root / "ResponseStrategy.candidate.md", root / "ResponseStrategy.candidate.diff"
    metadata_path, validation_path = root / "candidate-metadata.json", root / "candidate-validation.json"
    metadata = _canonical_object(metadata_path, "candidate metadata")
    validation = _canonical_object(validation_path, "candidate validation")
    mappings = _mappings(claims)
    metadata_keys = {"schema", "source_commit", "paper_head", "paper_snapshot_sha256", "threshold_snapshot_sha256",
                     "phase0_seal_sha256", "phase2_closure_seal_sha256", "baseline_response_strategy_sha256",
                     "candidate_filename", "candidate_sha256", "diff_filename", "diff_sha256", "claim_mappings",
                     "dry_apply_status", "work_gate_state", "performance_state", "threshold_gate_state", "threshold_authorized"}
    validation_keys = metadata_keys | {"metadata_filename", "metadata_sha256"}
    if set(metadata) != metadata_keys or set(validation) != validation_keys:
        raise Failure("candidate metadata or validation has unknown or missing fields")
    baseline = _safe_response_strategy(paper)
    expected = {"schema": "piccard-work7-candidate-metadata-v1", "source_commit": commit,
                "paper_head": state["paper"]["head"], "paper_snapshot_sha256": state["paper"]["snapshot_sha256"],
                "threshold_snapshot_sha256": state["threshold"]["snapshot_sha256"], "phase0_seal_sha256": sha256_file(phase0),
                "phase2_closure_seal_sha256": sha256_file(phase2),
                "baseline_response_strategy_sha256": hashlib.sha256(baseline).hexdigest(),
                "candidate_filename": "ResponseStrategy.candidate.md", "candidate_sha256": sha256_file(candidate_path),
                "diff_filename": "ResponseStrategy.candidate.diff", "diff_sha256": sha256_file(diff_path),
                "claim_mappings": mappings, "dry_apply_status": "PASS", "work_gate_state": "PENDING",
                "performance_state": "PERFORMANCE_PENDING", "threshold_gate_state": "DEFERRED_EXPECTED", "threshold_authorized": False}
    if metadata != expected:
        raise Failure("candidate metadata does not bind exact evidence")
    expected_validation = {**expected, "schema": "piccard-work7-candidate-validation-v1",
                           "metadata_filename": "candidate-metadata.json", "metadata_sha256": sha256_file(metadata_path)}
    if validation != expected_validation:
        raise Failure("candidate validation does not bind exact evidence")
    candidate_bytes, diff_bytes = candidate_path.read_bytes(), diff_path.read_bytes()
    if candidate_bytes != _render_candidate(baseline) or diff_bytes != _expected_diff(baseline, candidate_bytes):
        raise Failure("candidate prose or diff is not the exact conservative rendering")


def review(path: Path, commit: str, packet: str, provider: str, model: str) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise Failure("cannot read final review") from error
    required = ("VERDICT", "PROVIDER", "MODEL", "EFFORT", "SOURCE_COMMIT", "PACKET_SHA256", "STATUS")
    if len(lines) < 7:
        raise Failure("final review header is incomplete")
    parsed: dict[str, str] = {}
    for line in lines[:7]:
        if ": " not in line:
            raise Failure("invalid final review header")
        key, value = line.split(": ", 1)
        if key not in required or key in parsed:
            raise Failure("invalid final review header")
        parsed[key] = value
    if tuple(parsed) != required or any(line.startswith(key + ":") for line in lines[7:] for key in required):
        raise Failure("duplicate or misplaced final review field")
    expected = {"VERDICT": "APPROVED", "PROVIDER": provider, "MODEL": model, "EFFORT": "high",
                "SOURCE_COMMIT": commit, "PACKET_SHA256": packet,
                "STATUS": "POC_APPROVED_PERFORMANCE_PENDING"}
    if parsed != expected:
        raise Failure("final review identity, verdict, commit, packet, or status is invalid")
    checks = ("G1_G7_INTENT", "EVIDENCE_FRESHNESS", "PERFORMANCE_PENDING", "THRESHOLD_DEFERRED",
              "EXTERNAL_IMMUTABILITY", "TERMINAL_STATUS_MAXIMAL")
    for check in checks:
        if sum(line == f"CHECK {check}: CONFIRMED" for line in lines[7:]) != 1:
            raise Failure("final review substantive confirmation is missing")


def terminal(args: argparse.Namespace, commit: str, claims: list[dict]) -> dict:
    phase3 = require_absolute(args.phase3_closure_seal, "phase3 closure seal")
    work = require_absolute(args.work_review_seal, "work review seal")
    phase3_value = seal(phase3, "phase3-closure")
    if phase3_value["previous_seal_sha256"] is None:
        raise Failure("phase3 closure is not chained")
    phase3_root = Path(phase3_value["artifact_root"])
    claim7_path = phase3_root / "claim7-report.json"
    if "claim7-report.json" not in {entry["path"] for entry in phase3_value["entries"]}:
        raise Failure("missing sealed claim7 report")
    try:
        claim7_report = json.loads(claim7_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("invalid sealed claim7 report") from error
    report_claims(claim7_report, "claim7", commit, ["TOY_VERIFIED"] * 7, claims)
    inputs = claim7_report.get("input_seals")
    if (not isinstance(inputs, dict) or set(inputs) != {"phase2_closure_seal_sha256", "phase3_candidate_seal_sha256"} or
            inputs["phase3_candidate_seal_sha256"] != phase3_value["previous_seal_sha256"]):
        raise Failure("claim7 report has wrong candidate seal")
    work_value = seal(work, "phase4-work-review", sha256_file(phase3))
    packet_path = require_absolute(args.review_packet, "review packet")
    packet = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    review(require_absolute(args.claude_review, "claude review"), commit, packet, "anthropic", "claude-fable")
    review(require_absolute(args.sol_review, "sol review"), commit, packet, "openai", "gpt-5.6-sol")
    # Phase 4 is append-only and closes before the final packet and the two
    # independent final responses exist.  Their exact digests are instead
    # bound by the terminal report and Phase 5 seal after this parser has
    # validated each raw response against the same packet digest.
    phase0 = seal(require_absolute(args.phase0_seal, "phase0 seal"), "phase0")
    state_path = Path(phase0["artifact_root"]) / "state.json"
    try:
        state = json.loads(state_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("invalid phase0 state") from error
    build = state.get("build") if isinstance(state, dict) else None
    if (not isinstance(state, dict) or set(state) != {"schema", "source", "paper", "threshold", "build", "session_id"} or
            state.get("schema") != "piccard-work7-phase0-state-v2" or not isinstance(state.get("source"), dict) or
            not isinstance(build, dict) or set(build) != {"root"} or not isinstance(build.get("root"), str) or
            state["source"].get("head") != commit or state.get("session_id") != f"work7-{commit}"):
        raise Failure("invalid phase0 state")
    paper = require_absolute(args.paper_root, "paper root")
    threshold = require_absolute(args.threshold_root, "threshold root")
    if snapshot_git_worktree(paper) != state.get("paper") or snapshot_git_worktree(threshold) != state.get("threshold"):
        raise Failure("external worktree snapshot changed")
    return state


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if not isinstance(args.source_commit, str) or len(args.source_commit) != 40 or any(c not in "0123456789abcdef" for c in args.source_commit):
            raise Failure("source commit must be 40 lowercase hex")
        source = require_absolute(args.source_root, "source root")
        contract = require_absolute(args.contract, "contract")
        inside(source, contract, "contract")
        ctest = require_absolute(args.ctest_inventory, "ctest inventory")
        output = require_absolute(args.output, "output", exists=False)
        if output.exists() or output.is_symlink():
            raise Failure("output already exists")
        guarded = [source]
        if args.mode in ("claim7", "terminal"):
            guarded.extend([require_absolute(args.paper_root, "paper root"), require_absolute(args.threshold_root, "threshold root")])
        assert_output_roots_outside(guarded, [output])
        claims = load_contract(contract, source, inventory(ctest))
        toy = {claim["id"]: "PENDING" for claim in claims}
        if args.mode == "evidence-bound":
            runtime = require_absolute(args.runtime_seal, "runtime seal")
            for claim_id in runtime_evidence(runtime, args.source_commit, claims): toy[claim_id] = "TOY_VERIFIED"
        elif args.mode == "claim7":
            for name in ("phase0_seal", "paper_root", "threshold_root"):
                if getattr(args, name) is None:
                    raise Failure(f"{name.replace('_', ' ')} is required for claim7")
            candidate_evidence(args, require_absolute(args.phase2_closure_seal, "phase2 closure seal"),
                               require_absolute(args.phase3_candidate_seal, "phase3 candidate seal"), args.source_commit, claims)
            toy = {claim_id: "TOY_VERIFIED" for claim_id in IDS}
        elif args.mode == "terminal":
            state = terminal(args, args.source_commit, claims)
            toy = {claim_id: "TOY_VERIFIED" for claim_id in IDS}
        report = {"schema": "piccard-work7-claim-report-v1", "source_commit": args.source_commit,
                  "mode": args.mode, "threshold_gate_state": "DEFERRED_EXPECTED",
                  "work_gate_state": "POC_APPROVED_PERFORMANCE_PENDING" if args.mode == "terminal" else "PENDING",
                  "claims": [{"id": row["id"], "implementation_state": "IMPLEMENTED",
                              "toy_evidence_state": toy[row["id"]], "performance_state": "PERFORMANCE_PENDING",
                              "source_paths": row["source_paths"], "required_ctest_names": row["required_ctest_names"],
                              "evidence_keys": row["evidence_keys"], "deferred_rationale": row["deferred_rationale"],
                              "prohibited_overclaim": row["prohibited_overclaim"]} for row in claims],
                  "status": "PASS", "validation_errors": [], "input_seals": ({"runtime_seal_sha256": sha256_file(runtime)} if args.mode == "evidence-bound" else {"phase2_closure_seal_sha256": sha256_file(args.phase2_closure_seal), "phase3_candidate_seal_sha256": sha256_file(args.phase3_candidate_seal)} if args.mode == "claim7" else {})}
        _atomic_create(output, canonical_json_bytes(report))
        if args.mode == "terminal":
            if snapshot_git_worktree(require_absolute(args.paper_root, "paper root")) != state.get("paper") or snapshot_git_worktree(require_absolute(args.threshold_root, "threshold root")) != state.get("threshold"):
                output.unlink()
                raise Failure("external worktree snapshot changed after report creation")
    except (Failure, ValueError, OSError) as error:
        print(f"verify_work7_claims: FAIL: {error}", file=sys.stderr)
        return 2
    print(f"verify_work7_claims: PASS ({args.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
