# Work 7 Phase 1 — Claim Matrix and Fail-closed Verifier

## Purpose

Translate the seven approved pre-threshold goals into a machine-readable
contract that links original intent to current code, tests, toy evidence, and
deliberately deferred work.

## Input

A tracked claim matrix with exactly seven stable claim identifiers and only the
state vocabulary defined by the Work 7 integration design.

## Output contract

The verifier emits a canonical JSON report containing:

- matrix schema version;
- source commit;
- per-claim validation results;
- resolved source/test/evidence references;
- deferred-work justifications;
- validation errors; and
- overall pass/fail status.

The process exits nonzero when any claim fails.

## Success conditions

1. All seven original goals appear exactly once.
2. Every implementation reference exists under the source repository.
3. Every automated test reference is discoverable or resolves to a tracked test
   source that the fresh build registers.
4. Every toy evidence reference belongs to the current session manifest.
5. Real-data and repeated-performance claims remain
   `PERFORMANCE_PENDING`.
6. Threshold FP/FN work remains `DEFERRED_EXPECTED`.
7. Each row contains a clear prohibited-overclaim statement.

## Failure conditions

- A goal is missing, duplicated, or renamed without a schema change.
- An unknown state appears.
- A referenced path escapes the source/session roots or does not exist.
- A claim is marked verified without code, test, or current-session evidence.
- Toy output is represented as paper-grade performance evidence.
- Threshold work is represented as complete or authorized.
- A historical model approval is invented or reconstructed.

## Prohibited behavior

- No free-form status synonyms.
- No absolute machine-specific paths in the tracked matrix.
- No acceptance based solely on a prose review record.

## Verification

Tests mutate a valid fixture one field at a time: missing goal, duplicate goal,
unknown state, missing source, missing test, escaped path, foreign-session
artifact, toy overclaim, and invalid deferred-work state. Each mutation must
fail for the expected reason; the valid fixture must pass.
