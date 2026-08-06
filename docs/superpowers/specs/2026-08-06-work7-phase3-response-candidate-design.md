# Work 7 Phase 3 — Read-only ResponseStrategy Candidate

## Purpose

Produce an auditable manuscript-response handoff without modifying the user's
dirty Paper worktree or presenting toy evidence as final results.

## Inputs

- the current Paper `Revision/ResponseStrategy.md` bytes;
- Phase 0 Paper byte-level snapshot digest;
- validated claim report;
- Phase 2 closure seal; and
- explicit performance/threshold deferrals.

## Outputs

The Work 7 session contains:

1. a candidate full copy of `ResponseStrategy.md`;
2. a unified diff against the exact baseline bytes;
3. a metadata record with the Paper commit/snapshot digest and candidate digest;
   and
4. a validation report linking every inserted implementation claim to the claim
   matrix and Phase 2 seal; and
5. an immutable Phase 3 candidate-artifact seal chaining candidate artifacts
   to the Phase 2 closure seal; and
6. after `claim7` verification, a Phase 3 closure seal containing that report
   and chaining the candidate-artifact seal.

## Success conditions

1. Only session-root files are written.
2. The candidate accurately distinguishes implemented, toy-verified,
   performance-pending, and threshold-deferred items.
3. Every inserted measured value is either a non-performance diagnostic from
   the current toy session or omitted.
4. The unified diff applies to the recorded baseline bytes in a dry-run check.
5. After sealing the candidate artifacts, the `claim7` verifier emits a session-local
   structural-readiness snapshot while keeping the Work 7 and threshold gates
   `PENDING` and `DEFERRED_EXPECTED` respectively.
6. The claim-7 report is covered by the Phase 3 closure seal.
7. The Paper byte-level snapshot remains unchanged.

## Failure conditions

- Any Paper file is created, modified, staged, deleted, or normalized.
- A paper-grade number is inferred from a one-run toy probe.
- Actual-data or repeated-performance completion is claimed.
- Threshold FP/FN completion or branch authorization is claimed.
- Candidate text refers to an artifact not present in the Phase 2 closure seal.
- The diff baseline no longer matches the recorded Paper bytes.

## Prohibited behavior

- No automatic patch application.
- No cleanup of unrelated Paper edits.
- No prose that upgrades `POC_APPROVED_PERFORMANCE_PENDING` to paper readiness.

## Verification

The phase snapshots Paper before and after generation, validates candidate
claims against the lifecycle contract, dry-runs the diff against a temporary
copy, writes the candidate-artifact seal, runs `claim7`, writes the closure
seal, and fails if either external-worktree snapshot changes.
