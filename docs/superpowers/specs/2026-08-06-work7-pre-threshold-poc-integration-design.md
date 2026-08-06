# Work 7 Pre-threshold PoC Integration Design

**Date:** 2026-08-06

**Branch:** `tkde-major/pre-threshold-poc`

**Implementation baseline:** `b907fae`

**Design status:** approved

**Plan model:** `gpt-5.6-sol` xhigh

**Implementation model:** `gpt-5.6-terra`

**Work-level reviewer:** `gpt-5.6-sol` high

**Final reviewers:** Claude Fable high and `gpt-5.6-sol` high

## 1. Decision

Work 7 is a contract-based integration gate for the implementation produced by
Works 1–6. It verifies that the seven goals frozen in
`2026-07-29-pre-threshold-poc-design.md` are represented by code, tests, and
reproducible toy evidence without making paper-grade performance claims.

This document adapts the original Work 7 plan to the current PoC review scope.
It does not erase the original plan. The expensive actual-dataset and repeated
performance runs in that plan are deliberately deferred until all
implementation work is complete.

The only successful terminal status in this Work 7 run is:

```text
POC_APPROVED_PERFORMANCE_PENDING
```

That status means the implementation and one-run toy integration path are
approved. It does not mean that paper numbers are approved, that real-data
results have been produced, or that threshold FP/FN work is authorized.

## 2. Scope

Work 7 shall add:

1. a machine-readable claim matrix covering all seven pre-threshold goals;
2. a verifier that fails closed when a required claim lacks implementation,
   test, or evidence references;
3. a fresh-build toy integration runner whose benchmark-like invocations use
   exactly one trial/repetition;
4. immutable, commit-scoped evidence with command and artifact provenance;
5. a read-only generator for a candidate `ResponseStrategy.md` copy and diff;
6. a Work 7 `gpt-5.6-sol` high review gate; and
7. a whole-pre-threshold dual review gate requiring independent approval from
   Claude Fable high and `gpt-5.6-sol` high.

## 3. Non-goals

- Do not run or claim actual DBLP-ACM or Enron performance results.
- Do not run repeated timing, calibration, estimator-bias, or Monte Carlo
  campaigns. Every benchmark-like command used by this gate is one run with a
  toy-sized input.
- Do not edit any file in the Paper repository.
- Do not edit, merge, rebase, or authorize the threshold FP/FN worktree.
- Do not reconstruct missing historical review records or present user
  approvals as model-generated approvals.
- Do not convert a toy result into a manuscript number.
- Do not broaden Work 7 into production hardening or exhaustive edge-case
  coverage.

## 4. Frozen state vocabulary

Every claim row uses exactly one of these implementation states:

| State | Meaning |
|---|---|
| `IMPLEMENTED` | The required implementation exists and has an automated test reference. |
| `TOY_VERIFIED` | The implementation was exercised by this Work 7 toy session. |
| `PERFORMANCE_PENDING` | Actual data, repeated measurement, or paper-grade performance evidence is intentionally deferred. |
| `DEFERRED_EXPECTED` | The item belongs to later threshold FP/FN work and must not be implemented here. |

`TOY_VERIFIED` is not stronger than `IMPLEMENTED`; it records an integration
observation. A goal may therefore expose separate implementation and evidence
state fields. No other spelling or free-form state is accepted.

## 5. Claim contract

The matrix contains one row for each original design goal:

1. SHA-256 random-ranking estimator;
2. sanitizer profile and transcript accounting;
3. STD128/STD192 calibration and fail-closed selection;
4. matched-condition Piccard/BCG12/SJ16 comparison schema;
5. deterministic real-dataset pipeline with synthetic parser fixtures;
6. bounded-dynamic refresh and deletion-survival evidence; and
7. integration gate and manuscript-response handoff.

Each row contains:

- stable claim identifier;
- original-intent text;
- implementation state;
- evidence state;
- source paths;
- automated test names or paths;
- toy artifact paths when exercised;
- deferred-work rationale when applicable; and
- explicit prohibited overclaim text.

Paths are repository-relative and must resolve. Test references must be
discoverable in the fresh Release build. Toy artifacts must belong to the
current session and appear in its manifest.

## 6. Architecture

```text
state fingerprint
      |
      v
fresh Release build -----> claim contract verifier
      |                              |
      v                              v
Work 1–6 tests              contract validation
      |
      v
one-run toy probes -----> provenance validation
      |                              |
      +--------------+---------------+
                     v
             hashed session manifest
                     |
          +----------+-----------+
          v                      v
ResponseStrategy candidate   model review inputs
   (outside Paper)                 |
                                 v
             POC_APPROVED_PERFORMANCE_PENDING
```

The implementation consists of six ordered phases. A later phase may start
only after the preceding phase's success criteria pass.

| Phase | Unit | Detailed design |
|---|---|---|
| 0 | State guard and session identity | `2026-08-06-work7-phase0-state-guard-design.md` |
| 1 | Claim matrix and verifier | `2026-08-06-work7-phase1-claim-contract-design.md` |
| 2 | Fresh-build toy integration runner | `2026-08-06-work7-phase2-toy-runner-design.md` |
| 3 | Read-only ResponseStrategy candidate | `2026-08-06-work7-phase3-response-candidate-design.md` |
| 4 | Work-level review | `2026-08-06-work7-phase4-work-review-design.md` |
| 5 | Whole-pre-threshold dual review | `2026-08-06-work7-phase5-dual-review-design.md` |

## 7. Evidence session

Each run creates a new session keyed by the source commit. The runner refuses
to overwrite an existing session. The session records:

- source commit and clean/dirty status;
- Paper repository commit and complete status fingerprint;
- threshold worktree branch, commit, and complete status fingerprint;
- compiler, CMake, OpenFHE, and build configuration identifiers;
- exact argv and exit status for every command;
- start/end timestamps and durations;
- per-artifact SHA-256 digests; and
- a final manifest digest.

Generated runtime evidence remains outside tracked source paths by default.
Small schemas, claim contracts, verifier fixtures, and tests are tracked.
Final model-review records may be stored under the session root and referenced
by the handoff summary.

## 8. External repository guard

The Paper and threshold worktrees are read-only inputs. Before any generated
candidate or model review, Work 7 records their full fingerprints. After each
phase that reads them, it recomputes the fingerprint.

Success requires byte-for-byte identical status output and the same HEAD for
both external worktrees. The Paper worktree may already be dirty; its dirty
baseline is evidence to preserve, not a failure to clean up.

Any Work 7 process that changes either external worktree fails the phase. The
implementation must never discard, stage, format, or otherwise normalize the
user's existing Paper changes.

## 9. Test and benchmark policy

- Build from a newly created Release build directory.
- Run focused Work 1–6 tests plus Work 7 contract/provenance tests.
- Use synthetic fixtures for real-dataset parsers.
- Use toy parameter sizes for executable probes.
- Set every repeat/trial/iteration count controlling performance sampling to
  exactly `1`.
- Do not run the original plan's full actual-data or repeated-performance gate.
- Treat missing tools, stale binaries, skipped required tests, malformed rows,
  provenance mismatch, or a count greater than one as hard failures.

## 10. Review policy

The Work 7 diff and toy evidence receive a `gpt-5.6-sol` high work-level review.
After any required fix, the full focused verification is rerun against a new
commit-scoped session.

The final whole-pre-threshold review is performed independently and
concurrently by Claude Fable high and `gpt-5.6-sol` high. Both reviewers receive
the same source commit, approved design, claim matrix, session manifest,
candidate response diff, and verification summary.

Both reviewers must return an unqualified `APPROVED` verdict for the exact same
source commit. `APPROVED_WITH_COMMENTS`, a request for changes, an inability to
inspect evidence, or approval of different commits is not approval. At most two
remediation cycles are allowed before the Work 7 gate stops as failed.

## 11. Completion criteria

Work 7 is complete only when:

1. all Phase 0–5 success conditions pass;
2. all claim rows resolve to allowed states and valid references;
3. the fresh-build focused suite and every one-run toy probe pass;
4. the hashed session manifest and candidate response diff are reproducible;
5. Paper and threshold fingerprints are unchanged;
6. the Work 7 reviewer approves; and
7. both final reviewers approve the same commit and status.

Actual-data and multi-run performance work remains visible as
`PERFORMANCE_PENDING` in both the claim matrix and the response candidate.
