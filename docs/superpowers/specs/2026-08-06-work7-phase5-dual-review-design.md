# Work 7 Phase 5 — Whole Pre-threshold Dual Review

## Purpose

Confirm that Works 1–7 collectively realize the approved pre-threshold PoC
intent before declaring implementation approval with performance still pending.

## Reviewers

- Claude Fable, high effort; and
- `gpt-5.6-sol`, high reasoning effort.

The reviews are independent and launched concurrently against the same frozen
packet. Neither reviewer receives or reacts to the other's verdict.

## Review packet

- exact final source commit;
- original 2026-07-29 pre-threshold design;
- approved Work 7 design and Phase 0–5 designs;
- seven-row claim matrix and verifier report;
- current code/test references for Works 1–6;
- one-run toy manifest and verification summary;
- candidate ResponseStrategy diff;
- external-worktree before/after fingerprints; and
- Work 7 work-level approval.

Every item, including the Work 7 raw approval and Phase 4 seal, is hashed into
one canonical final-review packet manifest. Both reviewers receive and must
echo its single digest.

## Required review questions

1. Does each of the seven original goals map to the implementation as intended?
2. Are any claims supported only by stale, foreign-session, or fabricated
   evidence?
3. Are actual-data and repeated-performance results still clearly pending?
4. Is threshold FP/FN work still clearly deferred and unauthorized?
5. Did Work 7 preserve the dirty Paper baseline and threshold worktree?
6. Is `POC_APPROVED_PERFORMANCE_PENDING` the strongest justified status?

## Success conditions

1. Both reviewers inspect and echo the same commit and final-review packet
   digest together with their provider/model identifiers.
2. Both independently return exactly `APPROVED` with no required changes.
3. Both explicitly approve the terminal status
   `POC_APPROVED_PERFORMANCE_PENDING`.
4. Both raw responses are preserved unedited and mechanically parsed; their
   hashes, the packet digest, and the Phase 4 seal chain into a terminal Phase
   5 seal.
5. Final external-worktree byte-level snapshots equal the Phase 0 baseline.

## Failure conditions

- Either verdict is conditional, requests a change, or is not `APPROVED`.
- Reviewers inspect different source commits or packet digests, omit required
  metadata, or return a non-exact verdict token.
- Either reviewer identifies an original-intent mismatch or overclaim.
- Paper or threshold state differs from baseline.
- The maximum of two remediation cycles is exhausted.

## Terminal record

The final record contains both unedited verdicts and their hashes,
provider/model identifiers, the exact source commit, the canonical review
packet and terminal-seal digests, the external-state digests, and the single
terminal status. Approval records must never be retroactively rewritten to
cover Works 1–6 individually.
