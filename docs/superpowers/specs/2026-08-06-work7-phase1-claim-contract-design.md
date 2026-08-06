# Work 7 Phase 1 — Claim Matrix and Fail-closed Verifier

## Purpose

Translate the seven approved pre-threshold goals into a machine-readable
contract that links original intent to current code, tests, toy evidence, and
deliberately deferred work.

## Input

A tracked, immutable lifecycle matrix with exactly seven stable claim
identifiers, required references, allowed per-claim state transitions, and
allowed top-level gate transitions. It contains no session-local current state.

## Output contract

The same verifier has four mandatory modes and emits a new session-local state
snapshot/report each time:

- `static` runs before Phase 2 and validates schema/source/test references;
- `evidence-bound` runs after the Phase 2 runtime-artifact seal and binds claims
  1–6 to it;
- `claim7` runs after the Phase 3 response-candidate seal and marks structural
  readiness toy-verified without authorizing threshold work; and
- `terminal` runs after both Phase 5 raw approvals, validates their exact
  packet/commit/status fields, and alone emits the terminal Work 7 state.

Each report contains:

- matrix schema version;
- source commit;
- mode and per-claim validation results;
- resolved source/test/evidence references;
- deferred-work justifications;
- validation errors; and
- overall pass/fail status.

The process exits nonzero when any claim fails.

## Success conditions

1. All seven original goals appear exactly once with the allowed field-specific
   state combination for the selected verifier mode.
2. Every implementation reference exists under the source repository.
3. Every automated test reference is discoverable or resolves to a tracked test
   source that the fresh build registers.
4. In `static` mode no toy artifact is accepted; in `evidence-bound` mode every
   claim 1–6 artifact belongs to the Phase 2 runtime-artifact seal.
5. Real-data and repeated-performance claims remain
   `PERFORMANCE_PENDING`.
6. The top-level threshold gate remains `DEFERRED_EXPECTED`; the Work 7 gate is
   `PENDING` in the first three modes and reaches the approved value only in
   `terminal` mode.
7. `claim7` requires the Phase 2 closure and Phase 3 candidate seals and keeps
   the Work 7 gate pending.
8. `terminal` requires two accepted raw approvals for the same final packet and
   emits the only approved Work 7 state snapshot.
9. Each lifecycle row contains a clear prohibited-overclaim statement.

## Failure conditions

- A goal is missing, duplicated, or renamed without a schema change.
- An unknown state, wrong-field state, or disallowed combination appears.
- A referenced path escapes the source/session roots or does not exist.
- A claim is marked verified without code, test, or current-session evidence.
- Toy output is represented as paper-grade performance evidence.
- Threshold work is represented as complete or authorized.
- A tracked lifecycle contract is rewritten to represent session progress.
- A historical model approval is invented or reconstructed.

## Prohibited behavior

- No free-form status synonyms.
- No absolute machine-specific paths in the tracked matrix.
- No acceptance based solely on a prose review record.

## Verification

Tests mutate a valid fixture one field at a time: missing goal, duplicate goal,
unknown/wrong-field state, disallowed combination, missing source, missing
test, escaped path, preflight artifact, foreign-session artifact, toy
overclaim, premature claim-7 terminalization, mismatched review packet, invalid
review verdict, and invalid gate state. Each mutation must fail for the
expected reason; valid fixtures for all four modes must pass.
