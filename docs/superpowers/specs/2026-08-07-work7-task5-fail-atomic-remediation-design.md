# Work 7 Task 5 Fail-Atomic Remediation Design

**Date:** 2026-08-07

**Branch:** `tkde-major/pre-threshold-poc`

**Remediation baseline:** `24e9c51`

**Decision status:** user-approved recommended approach

**Implementation model:** `gpt-5.6-terra`

**Task reviewer:** `gpt-5.6-sol` high

## 1. Purpose

Close the three load-bearing findings that prevented Task 5 approval without
changing the approved Work 7 PoC scope:

1. publish no terminal report, Phase 5 artifact, seal, or pointer after a
   caught validation or filesystem failure;
2. ensure packet generation and terminal verification consume the exact bytes
   that were validated, rather than reopening live Phase 0--4 paths; and
3. bind the fresh build root to one absolute, canonical,
   `build-<source-commit>` directory outside the source, Paper, threshold, and
   session trees.

Actual DBLP-ACM/Enron data and repeated performance measurement remain
`PERFORMANCE_PENDING`. Every measured trial remains exactly `1`.

## 2. Chosen architecture

### 2.1 Captured evidence graph

Introduce one read-only capture boundary for Phase 0--4 evidence. A capture
stable-reads each seal exactly once, parses the exact captured bytes, verifies
the predecessor and canonical tree manifest, and stable-reads each required
member exactly once. The member bytes must match the length, mode, and SHA-256
stored in the owning seal.

The capture returns an in-memory graph containing:

- canonical seal values and their original raw bytes;
- the SHA-256 of each original seal byte string;
- exact raw bytes for every required Phase 0--4 packet member; and
- exact Phase 0 source/Paper/threshold snapshots.

`prepare-final` copies only this captured member map. It never reopens a
Phase 0--4 report, candidate, packet, review, or seal to populate the final
packet. Immediately before writing the final packet, a second complete capture
must equal the first byte-for-byte and digest-for-digest.

### 2.2 Captured terminal verifier core

Refactor terminal verification in `verify_work7_claims.py` into a pure core
that accepts already captured values and byte strings. The core validates:

- the exact Phase 3 claim-7 closure and its predecessor binding;
- the exact Phase 4 Work packet and sol-high raw approval;
- the exact final packet digest and independent Fable-high/sol-high raw
  approvals;
- the immutable claim contract and frozen CTest inventory; and
- fresh Paper/threshold snapshots equal to Phase 0.

The CLI `--mode terminal` remains supported. Its wrapper captures its file
inputs once, invokes the same pure core, and atomically writes the returned
canonical report only after the core succeeds.

`close-final` imports and invokes this same verifier core with its in-memory
Phase 0--4 capture and stable final packet/review bytes. It does not pass a
live Phase 4 seal path to another process and does not create the requested
terminal-report path before all terminal validation succeeds.

### 2.3 Strict fail-atomic publication

`close-final` constructs these bytes before persistent Phase 5 publication:

- canonical terminal report;
- exact final packet, Claude review, sol review, and terminal report members;
- canonical Phase 5 seal bytes for the final artifact-root path; and
- `terminal-seal.sha256` bytes derived from the exact seal bytes.

It validates that prospective seal and pointer entirely from the in-memory
member map. It then publishes the explicit final paths with exclusive atomic
creation. Every path created by this invocation is recorded.

If a caught `Failure`, `OSError`, `ValueError`, or `FileExistsError` occurs
after publication begins, cleanup removes only those recorded paths in reverse
order. Pre-existing paths are never removed. After cleanup, none of the
following may exist if it did not exist before the call:

- the requested terminal report;
- `phase5/terminal-artifacts/` or any member below it;
- the Phase 5 seal; or
- `terminal-seal.sha256`.

An OS kill, process crash, or power loss between filesystem syscalls is outside
this PoC remediation. Caught program and injected filesystem failures are in
scope and must be fail-atomic.

### 2.4 Canonical build-root binding

Phase 0 state uses schema `piccard-work7-phase0-state-v2` and adds the exact
field `"build": {"root": "<canonical-absolute-build-root>"}`. The state guard
writes this value only after its guarded-root checks, and the Phase 0 seal makes
the value immutable for the remainder of the run.

The configure record's `-B` value must:

- be an absolute path containing no symlink component;
- resolve strictly to an existing directory;
- have basename exactly `build-<source-commit>`;
- be represented by its canonical resolved string in configure, build, CTest,
  producer, provenance, and deletion records;
- equal the exact canonical build-root string sealed in Phase 0 state; and
- be outside and neither an ancestor nor descendant of the source, Paper,
  threshold, and session roots.

A validly resealed runtime graph pointing to any other build root, including a
different otherwise-valid `build-<source-commit>` directory, fails before
`prepare-final` creates Phase 5 members or a packet.

### 2.5 Failure lifecycle and rerun policy

Function-level rollback and authoritative-run disposal are separate safety
boundaries:

- A publishing function removes only paths that the failing invocation created.
  It never removes a pre-existing path or an enclosing run directory.
- The Task 6 orchestrator owns the exact generated
  `build-<source-commit>` and `session-<source-commit>` directories.  For
  every supported authoritative failure, it first captures a minimal external
  diagnostic outside the guarded source, Paper, threshold, build, and session
  roots, then removes both directories completely.

Supported authoritative failures are execution, technical-review,
review-delivery, and user-cancel.  Execution covers build, test, verifier,
seal, schema, argv, count, provenance, external-drift, caught publication, and
terminal-verification failures. A technical review fails when a required
reviewer returns `REJECTED`, `NEEDS_FIXES`, or any Critical or Important
finding. Review delivery includes a transport timeout, provider error, or
syntactically unusable response, whether or not it makes a technical judgment.
All four kinds classify to `DISPOSE`; no failure preserves a packet, evidence,
or session for partial resumption or reviewer-only delivery.

After disposal, diagnose and remediate the implementation or design, clear the
exact external diagnostic record, and begin exactly one wholly fresh
authoritative toy run from Phase 0. The orchestrator never retries an
experiment, verifier, reviewer, packet, or evidence graph until a run happens
to pass. User cancellation follows the same fail-atomic disposal and fresh-run
boundary if work is resumed.

Disposal accepts only two already validated, fully resolved targets beneath
their configured temporary parents: the canonical `build-<source-commit>` and
`session-<source-commit>` directories.  It rejects symlinks, mismatched
basenames, unresolved paths, protected roots, ancestors of protected roots,
and broad targets.  Diagnostic output must not contain a publishable review,
seal, or terminal pointer and is cleared before the fresh run.

## 3. Alternatives rejected

### Preserve failed terminal reports in the authoritative session

Rejected because an unsealed report can be confused with successful terminal
evidence and makes retries ambiguous.

### Keep live paths and add only before/after digest checks

Rejected because a transient replacement followed by restoration can evade
endpoint checks while foreign bytes are consumed in the middle.

### Declare a single-writer assumption

Rejected because the final approval packet is the evidence boundary. Both
required reviewers must be able to rely on byte identity without trusting
unrecorded process discipline.

## 4. Implementation units

### Unit A: Canonical build root

Add a narrow validator used before any imported producer validator. It returns
the one canonical build `Path`; all expected argv construction consumes that
returned path.

### Unit B: Phase 0--4 capture graph

Add focused capture helpers and replace live reopening in `prepare-final`.
The capture API returns immutable bytes/digests, not paths for later reading.

### Unit C: Captured terminal verifier

Separate terminal semantics from terminal file I/O. Keep the existing CLI
contract through a wrapper using the same captured core.

### Unit D: Fail-atomic Phase 5 publisher

Generate report, members, seal, and pointer bytes first. Publish with an
explicit rollback ledger and reverify the published group before returning
success.

### Unit E: Hostile behavioral matrix

Use the hermetic synthetic Phase 0--3 producer fixture. Each case is one toy
run with measured counts `1`. Add deterministic tests for:

- relative, symlinked, foreign-name, contained, and ancestor build roots;
- transient Phase 0--4 seal/member replacement during packet preparation and
  terminal verification;
- malformed terminal report and external drift;
- injected failures while creating every Phase 5 member, the seal, and the
  pointer; and
- post-publication seal/pointer mismatch.

Every failure asserts complete restoration of the pre-call Phase 5 path set
and bytes. Success asserts the terminal report, sealed member copy, seal, and
pointer contain the exact prevalidated bytes.

## 5. Success conditions

- Task 5 focused tests and the claim-contract tests pass.
- Each new regression is demonstrated RED before its implementation fix and
  GREEN afterward.
- The complete five Work 7 Python suites pass once after the final source
  commit.
- `gpt-5.6-sol` high returns no Critical or Important finding and approves the
  remediation task.
- Every supported authoritative Task 6 failure, including reviewer delivery,
  timeout, provider, and unparseable-response failure, records an external
  diagnostic, disposes the exact generated build and session, is remediated,
  has that exact diagnostic cleared, and then begins a wholly fresh Phase 0
  run.
- No actual-data or repeated-performance campaign runs.
- Paper and threshold byte-level snapshots are unchanged.
- Task 6 starts only after this remediation approval.

## 6. Failure conditions

- Any final packet member is populated by reopening a live sealed path after
  capture.
- The terminal verifier consumes a live Phase 3 or Phase 4 path after capture.
- A caught failure leaves a new terminal report, Phase 5 member, seal, or
  pointer.
- A foreign or noncanonical build root reaches producer validation.
- Any supported authoritative failure leaves its generated build or session,
  permits partial resume, reuses a packet/evidence graph, or starts a new run
  before remediation and exact diagnostic clearing.
- A reviewer transport, timeout, provider, or unparseable-response failure is
  treated as retry-only rather than fail-atomic disposal and a fresh Phase 0
  run.
- Tests assert source text or mocks instead of observable CLI/filesystem
  behavior.
- The remediation changes performance status, measured counts, Paper, or the
  threshold worktree.
