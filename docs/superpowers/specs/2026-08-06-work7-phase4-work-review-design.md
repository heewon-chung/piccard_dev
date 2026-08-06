# Work 7 Phase 4 — Work-level Review

## Purpose

Obtain an independent PoC-level implementation review of Work 7 itself before
the whole pre-threshold intent audit.

## Reviewer

`gpt-5.6-sol` with high reasoning effort.

## Review packet

- exact source commit and diff from the Work 7 design baseline;
- approved overall and Phase 0–5 designs;
- Terra implementation plan;
- claim matrix and verifier report;
- focused test and fresh-build summary;
- toy session manifest;
- ResponseStrategy candidate diff; and
- before/after Paper and threshold byte-level snapshot digests.

All packet files are listed by relative path, length, and SHA-256 in a
canonical packet manifest that also includes the exact source commit and every
prior phase-seal digest. Its digest is the review packet identity.

## Success conditions

1. The reviewer inspects the exact commit and all packet items.
2. The verdict is `APPROVED` with no required changes.
3. The review explicitly confirms PoC scope, one-run toy policy, provenance,
   fail-closed behavior, external-worktree immutability, and absence of
   paper-grade overclaims.
4. The raw response is preserved unedited and hashes into a Phase 4 seal.
5. A mechanical parser accepts exactly `APPROVED` and requires the response to
   echo provider/model metadata, source commit, and review packet digest.

## Failure conditions

- The verdict requests any change or cannot inspect required evidence.
- The reviewed commit/packet digest differs from the authoritative session or
  the response omits required provider/model metadata.
- A required claim lacks implementation, test, or evidence linkage.
- Any external-worktree mutation is observed.
- The reviewer finds a misleading performance or threshold claim.

## Remediation

A required change returns execution to the earliest affected phase. After the
fix, Work 7 creates a new commit-scoped session and reruns all focused
verification. At most two remediation cycles are allowed.
