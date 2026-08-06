# Work 7 Phase 1 — Claim Matrix and Fail-closed Verifier

## Purpose

Translate the seven approved pre-threshold goals into a machine-readable
contract that links original intent to current code, tests, toy evidence, and
deliberately deferred work.

## Input

A tracked claim matrix with exactly seven stable claim identifiers, the three
per-claim state axes, and the two top-level gate states defined by the Work 7
integration design.

## Output contract

The verifier has two mandatory modes. `static` runs before Phase 2 and validates
the matrix schema plus source/test references while requiring toy evidence to
be `PENDING`. `evidence-bound` runs after Phase 2 and binds claims 1–6 to the
runtime seal while leaving the Work 7 gate pending. Each mode emits a canonical
JSON report containing:

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
   claim 1–6 artifact belongs to the sealed Phase 2 manifest.
5. Real-data and repeated-performance claims remain
   `PERFORMANCE_PENDING`.
6. The top-level threshold gate remains `DEFERRED_EXPECTED` and the Work 7 gate
   remains `PENDING`.
7. Claim 7 records structural readiness and its non-authorization boundary;
   it cannot reach terminal state in either Phase 1 pass.
8. Each row contains a clear prohibited-overclaim statement.

## Failure conditions

- A goal is missing, duplicated, or renamed without a schema change.
- An unknown state, wrong-field state, or disallowed combination appears.
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
unknown/wrong-field state, disallowed combination, missing source, missing
test, escaped path, preflight artifact, foreign-session artifact, toy
overclaim, premature claim-7 terminalization, and invalid gate state. Each
mutation must fail for the expected reason; both valid mode fixtures must pass.
