#!/usr/bin/env python3
"""Fail-closed verifier for the immutable Work 7 claim lifecycle."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from work7_evidence import (_atomic_create, _reject_symlink_components,
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
        return {line.rsplit(":", 1)[1].strip() for line in path.read_text(encoding="utf-8").splitlines()
                if ":" in line and line.rsplit(":", 1)[1].strip()}
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


def runtime_evidence(path: Path, commit: str) -> set[str]:
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
            index["schema"] != "piccard-work7-evidence-index-v1" or index["source_commit"] != commit or
            not isinstance(index["claims"], dict)):
        raise Failure("foreign or invalid runtime evidence")
    sealed = {entry["path"] for entry in value["entries"]}
    evidence: set[str] = set()
    for claim_id in IDS[:6]:
        paths = index["claims"].get(claim_id)
        if not isinstance(paths, list) or not paths or any(not isinstance(item, str) or item not in sealed for item in paths):
            raise Failure("missing sealed claim evidence")
        evidence.add(claim_id)
    if any(item not in IDS[:6] for item in index["claims"]):
        raise Failure("invalid runtime evidence claim")
    return evidence


def candidate_evidence(phase2: Path, candidate: Path) -> None:
    phase2_value = seal(phase2, "phase2-closure")
    candidate_value = seal(candidate, "phase3-candidate-artifacts", sha256_file(phase2))
    root = Path(candidate_value["artifact_root"])
    path = root / "candidate-validation.json"
    if "candidate-validation.json" not in {entry["path"] for entry in candidate_value["entries"]}:
        raise Failure("missing sealed claim 7 evidence")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("invalid claim 7 evidence") from error
    if not isinstance(value, dict) or value.get("claim_id") != IDS[6]:
        raise Failure("premature claim 7 verification")
    # Ensures the closure's previous digest was parsed rather than merely accepting a kind label.
    if not phase2_value["entries"] and phase2_value["previous_seal_sha256"] is None:
        raise Failure("foreign phase2 closure")


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


def terminal(args: argparse.Namespace, commit: str) -> None:
    phase3 = require_absolute(args.phase3_closure_seal, "phase3 closure seal")
    work = require_absolute(args.work_review_seal, "work review seal")
    seal(phase3, "phase3-closure")
    seal(work, "phase4-work-review", sha256_file(phase3))
    packet_path = require_absolute(args.review_packet, "review packet")
    packet = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    review(require_absolute(args.claude_review, "claude review"), commit, packet, "anthropic", "claude-fable")
    review(require_absolute(args.sol_review, "sol review"), commit, packet, "openai", "gpt-5.6-sol")
    phase0 = seal(require_absolute(args.phase0_seal, "phase0 seal"), "phase0")
    state_path = Path(phase0["artifact_root"]) / "state.json"
    try:
        state = json.loads(state_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise Failure("invalid phase0 state") from error
    if not isinstance(state, dict) or state.get("schema") != "piccard-work7-phase0-state-v1":
        raise Failure("invalid phase0 state")
    paper = require_absolute(args.paper_root, "paper root")
    threshold = require_absolute(args.threshold_root, "threshold root")
    if snapshot_git_worktree(paper) != state.get("paper") or snapshot_git_worktree(threshold) != state.get("threshold"):
        raise Failure("external worktree snapshot changed")


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
        claims = load_contract(contract, source, inventory(ctest))
        toy = {claim["id"]: "PENDING" for claim in claims}
        if args.mode == "evidence-bound":
            runtime = require_absolute(args.runtime_seal, "runtime seal")
            for claim_id in runtime_evidence(runtime, args.source_commit): toy[claim_id] = "TOY_VERIFIED"
        elif args.mode == "claim7":
            candidate_evidence(require_absolute(args.phase2_closure_seal, "phase2 closure seal"),
                               require_absolute(args.phase3_candidate_seal, "phase3 candidate seal"))
            toy[IDS[6]] = "TOY_VERIFIED"
        elif args.mode == "terminal":
            terminal(args, args.source_commit)
            toy = {claim_id: "TOY_VERIFIED" for claim_id in IDS}
        report = {"schema": "piccard-work7-claim-report-v1", "source_commit": args.source_commit,
                  "mode": args.mode, "threshold_gate_state": "DEFERRED_EXPECTED",
                  "work_gate_state": "POC_APPROVED_PERFORMANCE_PENDING" if args.mode == "terminal" else "PENDING",
                  "claims": [{"id": row["id"], "implementation_state": "IMPLEMENTED",
                              "toy_evidence_state": toy[row["id"]], "performance_state": "PERFORMANCE_PENDING",
                              "source_paths": row["source_paths"], "required_ctest_names": row["required_ctest_names"],
                              "evidence_keys": row["evidence_keys"], "deferred_rationale": row["deferred_rationale"],
                              "prohibited_overclaim": row["prohibited_overclaim"]} for row in claims],
                  "status": "PASS", "validation_errors": []}
        _atomic_create(output, canonical_json_bytes(report))
    except (Failure, ValueError, OSError) as error:
        print(f"verify_work7_claims: FAIL: {error}", file=sys.stderr)
        return 2
    print(f"verify_work7_claims: PASS ({args.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
