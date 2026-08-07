# Work 7 Task 5 Fail-Atomic Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three remaining Task 5 review findings and provide a safe,
explicit disposal boundary for invalid authoritative Work 7 runs.

**Architecture:** Capture sealed Phase 0--4 inputs once into immutable byte
objects, verify and copy only those objects, and drive both the CLI and
`close-final` through one path-free terminal verifier core.  Build every Phase
5 output in memory before an exclusive fail-atomic publication.  Keep local
publication rollback separate from exact build/session disposal.

**Tech Stack:** Python 3 standard library, `unittest`, canonical JSON and tree
seal helpers in `scripts/work7_evidence.py`, Git, subprocess-based CLI tests.

## Global Constraints

- Implementation model is `gpt-5.6-terra`.
- Task review model is `gpt-5.6-sol` high; no Critical or Important finding may
  remain before Task 6.
- This is a TKDE revision PoC.  Do not add production hardening unrelated to
  the three Task 5 findings or the approved failure lifecycle.
- Every measured `trials`, `accuracy_trials`, and `refresh_updates` value is
  exactly `1`; retain only the already approved discarded timing warmup.
- Do not run DBLP-ACM, Enron, an actual-data campaign, or repeated performance
  measurements.  Keep `PERFORMANCE_PENDING` and `THRESHOLD_DEFERRED`.
- Paper and threshold worktrees are read-only and must equal their Phase 0
  byte-level snapshots at every finalization boundary.
- A caught publication failure rolls back only paths created by that call.
- An execution-invalidating failure disposes the exact validated
  `build-<commit>` and `session-<commit>` roots only after a minimal diagnostic
  is written outside guarded roots.  Diagnose/fix before one fresh Phase 0 run.
- A reviewer transport/provider/format failure without a technical verdict
  preserves the frozen session and retries only that reviewer.
- Never retry an experiment or verifier until it happens to pass.

## File Map and Fixed Interfaces

**Modify:**

- `scripts/work7_evidence.py`: captured blob/seal primitives that do not reopen
  a path after capture.
- `scripts/work7_review_packet.py`: canonical build validation, complete
  Phase 0--4 capture, final packet creation, and Phase 5 publication.
- `scripts/verify_work7_claims.py`: pure captured terminal verifier plus the
  existing CLI wrapper.
- `scripts/run_work7_integration.py`: safe exact-run disposal helpers and
  failure cleanup for roots reserved by the current invocation.
- `scripts/work7_run_lifecycle.py`: explicit failure classification,
  diagnostic, reviewer retry, and owned-root disposal coordinator.
- `tests/scripts/test_work7_review_packet.py`: R0--R3 hostile behavioral tests.
- `tests/scripts/test_work7_claim_contract.py`: terminal core/CLI equivalence.
- `tests/scripts/test_work7_integration_runner.py`: exact disposal lifecycle.
- `.superpowers/sdd/2026-08-06-work7-terra-pre-threshold-integration/task-5-report.md`:
  RED/GREEN commands, outputs, commit, and reviewer verdict.

**Do not modify:** Paper, threshold, benchmark parameters, Work 7 claim states,
or actual-data/performance scripts.

The implementation must keep these signatures stable across phases:

```python
@dataclass(frozen=True)
class CapturedBlob:
    raw: bytes
    sha256: str
    size: int
    mode: str

@dataclass(frozen=True)
class CapturedTreeSeal:
    blob: CapturedBlob
    kind: str
    artifact_root: str
    previous_seal_sha256: str | None
    members: tuple[tuple[str, CapturedBlob], ...]

def capture_tree_seal(path: Path, expected_previous: str | None,
                      expected_kind: str, expected_root: Path,
                      expected_members: set[str] | None = None) -> CapturedTreeSeal: ...

def validate_canonical_build_root(raw: object, commit: str,
                                  guarded: tuple[Path, ...]) -> Path: ...

@dataclass(frozen=True)
class Phase04Capture:
    commit: str
    state_raw: CapturedBlob
    contract_raw: CapturedBlob
    ctest_inventory_raw: CapturedBlob
    seals: tuple[tuple[str, CapturedTreeSeal], ...]
    packet_members: tuple[tuple[str, CapturedBlob], ...]
    build_binaries: tuple[tuple[str, CapturedBlob], ...]
    phase4_packet: CapturedBlob
    phase4_review: CapturedBlob
    source_snapshot_raw: bytes
    paper_snapshot_raw: bytes
    threshold_snapshot_raw: bytes

def capture_phase04(session: Path, source: Path,
                    paper: Path | None = None,
                    threshold: Path | None = None) -> Phase04Capture: ...

@dataclass(frozen=True)
class RuntimeSummary:
    ctest_focused: str
    pre_threshold: str
    real_datasets: str
    verify_real_datasets: str
    deletion_survival: str
    focused_pass_count: int

def validate_phase2_runtime_capture(capture: Phase04Capture) -> RuntimeSummary: ...

def validate_prethreshold_capture(blobs: tuple[tuple[str, CapturedBlob], ...],
                                  commit: str, expected_argv: tuple[str, ...],
                                  source: str, build: str) -> str: ...

def validate_real_capture(blobs: tuple[tuple[str, CapturedBlob], ...],
                          commit: str, source: str, build: str) -> str: ...

def validate_deletion_bytes(raw: bytes) -> None: ...

def validate_record_counts_capture(
        blobs: tuple[tuple[str, CapturedBlob], ...]) -> None: ...

@dataclass(frozen=True)
class TerminalInputs:
    phase04: Phase04Capture
    final_packet: CapturedBlob
    final_packet_members: tuple[tuple[str, CapturedBlob], ...]
    claude_review: CapturedBlob
    sol_review: CapturedBlob

def terminal_report_bytes(inputs: TerminalInputs) -> bytes: ...

def publish_phase5(session: Path, terminal_report: Path, output_seal: Path,
                   packet_raw: bytes, claude_raw: bytes, sol_raw: bytes,
                   report_raw: bytes, previous_seal_sha256: str) -> str: ...

def dispose_generated_run(build_parent: Path, session_parent: Path,
                          build: Path, session: Path, commit: str,
                          guarded: tuple[Path, ...]) -> None: ...

@dataclass
class ReservationLedger:
    created: list[Path]

def reserve_owned(parent: Path, name: str,
                  ledger: ReservationLedger) -> Path: ...

def classify_failure(kind: str) -> Literal["DISPOSE", "RETRY_REVIEWER"]: ...

@dataclass(frozen=True)
class CapturedReviewBundle:
    packet: CapturedBlob
    members: tuple[tuple[str, CapturedBlob], ...]

def capture_review_bundle(packet: Path, session: Path,
                          expected_packet_sha256: str) -> CapturedReviewBundle: ...

def deliver_reviewer_retry(bundle: CapturedReviewBundle,
                           delivery: Callable[[CapturedReviewBundle], bytes]) -> bytes: ...

def record_and_apply_failure(kind: str, diagnostic_root: Path,
                             build_parent: Path, session_parent: Path,
                             build: Path, session: Path, commit: str,
                             guarded: tuple[Path, ...], packet: Path | None,
                             packet_sha256: str | None) -> str: ...
```

Captured objects expose only immutable scalars, bytes, frozen dataclasses, and
tuples.  A parser may create a fresh local JSON object but never stores or
returns it as captured state.  Seal entry modes use the canonical four-digit
octal string from the seal schema; copied Phase 5 files are independently
created with the existing safe mode, so mode equality applies to validation of
the source member, not to the packet schema.  No captured object contains a
path that a later consumer is expected to reopen.

---

### Task 1: R0 — Bind the canonical build root

**Files:**

- Modify: `scripts/work7_review_packet.py`
- Test: `tests/scripts/test_work7_review_packet.py`

**Consumes:** Phase 0 source/Paper/threshold roots, session root, source commit,
and the captured configure command record.

**Produces:** `validate_canonical_build_root(...) -> Path`; every expected
configure/build/CTest/producer/deletion argv is derived from this returned path.

- [ ] **Step 1: Add hostile build-root tests.**

  Add `test_prepare_final_rejects_noncanonical_build_roots_before_output` with
  subtests for a relative path, a symlink component, `build-wrongcommit`, a
  non-existing path, and roots equal to/inside/ancestor of source, Paper,
  threshold, or session.  Reseal the synthetic Phase 2 graph after each
  mutation.  For one foreign `build-<commit>` case, make the hostile graph
  self-consistent by rewriting all configure/build/CTest/producer/deletion
  command records; the pre-threshold manifest build/binary paths and hashes;
  real-data `run_metadata.tsv`, its root bindings and verification-status
  digest; and the relocated fake binary files before resealing.  Assert exit
  `2`, exactly one `FAIL` line containing `noncanonical build root`, and absence
  of the final packet and every newly created Phase 5 member.

- [ ] **Step 2: Prove RED.**

  Run:

  ```bash
  python3 -W ignore::ResourceWarning -m unittest -v \
    tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_noncanonical_build_roots_before_output
  ```

  Expected: the fully self-consistent foreign build graph exits `0` or reaches
  a later validator instead of emitting `noncanonical build root`; this is the
  distinguishing RED, not merely a generic failure.

- [ ] **Step 3: Implement the narrow validator.**

  Require `raw` to be a string containing an absolute path.  Implement a strict
  component walk for this recorded `-B` value that has no macOS `/tmp`/`/var`
  trusted-alias exception; require `raw == str(path.resolve(strict=True))` and
  reject every symlink component; require an existing
  directory named exactly `build-<commit>`; use
  `assert_output_roots_outside` plus explicit bidirectional `relative_to`
  checks so the build is neither an ancestor nor descendant of any guarded
  root.  Return the canonical path and use its exact string for all expected
  argv and producer validators.

  Add ordinary symlink and `/tmp` versus `/private/tmp` alias subtests so reuse
  of the more permissive general `_reject_symlink_components` cannot pass R0.

- [ ] **Step 4: Prove GREEN and retain existing runtime hostility coverage.**

  Run the new test followed by:

  ```bash
  python3 -W ignore::ResourceWarning -m unittest -v \
    tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_resealed_hostile_command_record \
    tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_resealed_hostile_focused_ctest_output \
    tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_resealed_hostile_producer_count
  ```

- [ ] **Step 5: Record and commit.**

  Append exact RED/GREEN output to the Task 5 report and commit only R0 files:

  ```bash
  git commit -m "fix(work7): bind canonical task5 build root"
  ```

**R0 success:** every valid runtime command uses one canonical
`build-<commit>` outside guarded trees, and hostile roots fail before Phase 5
output.

**R0 failure:** a caller-controlled path reaches a producer validator, a valid
fresh root is rejected, or any Paper/threshold/source/session byte changes.

### Task 2: R1 — Capture the exact Phase 0--4 evidence graph

**Files:**

- Modify: `scripts/work7_evidence.py`
- Modify: `scripts/work7_review_packet.py`
- Modify: `scripts/run_work7_integration.py`
- Test: `tests/scripts/test_work7_review_packet.py`
- Test: `tests/scripts/test_work7_state_guard.py`

**Consumes:** canonical Phase 0--4 seal paths at one capture boundary.

**Produces:** `CapturedBlob`, `CapturedTreeSeal`, `capture_tree_seal`,
`Phase04Capture`, and `capture_phase04` as fixed above.

- [ ] **Step 1: Add observable capture tests.**

  Add `test_capture_tree_seal_returns_exact_member_bytes_without_reopen` and
  extend the existing transient-replacement fixture.  Replace a member after
  its stable read and restore it before the command returns; assert the final
  packet contains the originally verified bytes or fails without output, never
  the transient bytes.  Mutate Phase 0--3 seal/member bytes in turn and assert
  an entry size/mode/SHA mismatch fails.

  Add `test_captured_graph_is_recursively_immutable_and_preserves_seal_modes`:
  nested mutation is impossible because parsed dict/list values never escape,
  a source-member mode change is rejected, and Phase 5 copies use the safe
  output mode without claiming packet-schema mode equality.

- [ ] **Step 2: Prove RED.**

  Run the two new tests and existing
  `test_prepare_final_seals_validated_phase4_bytes_despite_transient_replacement`.
  Expected: the Phase 0--3 transient-member case copies foreign bytes because
  `prepare_final` reopens `WORK_SESSION_MEMBERS`.

- [ ] **Step 3: Implement captured primitives.**

  In `work7_evidence.py`, stable-read the seal once, require canonical JSON,
  validate schema/kind/root/predecessor from those bytes, stable-read every
  manifest member once, and compare regular-file type, mode, size, and SHA-256
  with the captured entry.  Reject duplicate/noncanonical/escaping member
  names.  Return immutable tuple-backed byte records; do not call
  `verify_tree_seal(path)` from the byte consumer.

- [ ] **Step 4: Build and use one Phase 0--4 graph.**

  `capture_phase04` captures Phase 0, runtime, closure, candidate, claim-7, and
  Work-review seals in predecessor order.  It validates exact manifest sets,
  parses state/packet/review from captured bytes, captures source packet files
  and current external snapshots, and applies R0.

  Capture Phase 0 state first and derive Paper/threshold roots from its exact
  `root` strings.  Require each to be absolute, strictly resolved without a
  symlink component, equal to its canonical string, distinct from and
  non-overlapping with source/session/build.  `prepare-final` passes `None` and
  uses these derived roots; `close-final` passes its CLI roots and requires
  exact canonical equality with the derived strings.  Update all callers and
  tests for this rule; no preliminary Phase 0 reopen is permitted.

  After R0 validates the build root, stable-capture the five executable build
  binaries `bench_review_comparison`, `bench_piccard`, `bench_dynamic`,
  `bench_real_datasets`, and `bench_deletion_survival`.  Require canonical
  paths, regular executable mode, size, and SHA-256; bind those blobs to every
  manifest/metadata/command reference and include them in the second-capture
  equality.  Add a synchronized transient build-binary replacement/restoration
  test that cannot pass with endpoint-only path checks.

  Refactor runtime semantic checks into byte consumers used by
  `validate_phase2_runtime_capture`: command-record JSON, stdout/stderr,
  pre-threshold manifests/results, real-data metadata/status/results, deletion
  CSV, evidence index, static/evidence claim reports, contract, and inventory
  all come from `Phase04Capture.packet_members` or captured owning-seal
  members.  Do not call the path-based `validate_phase2_runtime` or an imported
  producer validator that reopens a path after capture.  Preserve their exact
  current schemas and return a frozen `RuntimeSummary`.

  Put the four producer-schema byte functions declared in the fixed interface
  in `run_work7_integration.py`; the existing runner may wrap them with its own
  freshly captured blobs, while finalization passes only R1 blobs.  These pure
  functions accept expected path strings for comparison but never open them.

  Treat `phase2/static-report.json` as a stable-once blob that must byte-equal
  the `phase2/runtime/static-report.json` entry owned by the runtime seal.
  Treat the five seal JSON packet members as the exact captured seal blobs
  bound by the predecessor chain; they do not have an owning-seal entry.

  `prepare_final` constructs every prospective member and packet byte string in
  memory.  After a second complete `capture_phase04` agrees byte-for-byte with
  the first, publish members and packet with an exclusive creation ledger.  A
  member collision, generated-member error, second-capture mismatch, or packet
  creation error rolls back every path created by this call and restores the
  exact pre-call Phase 5 path/byte set.  It never reopens a Phase 0--4 member.

- [ ] **Step 5: Prove GREEN.**

  Add a synchronized subprocess/filesystem regression that swaps and restores
  a captured command report and one producer result during semantic
  validation.  Its barrier belongs to the test fixture; no source-text or mock
  call-count assertion satisfies the gate.  Run all `prepare_final` tests in
  `test_work7_review_packet.py` and the full `test_work7_state_guard.py` suite.
  Expected: all pass; failure at every member, generated member, second
  capture, or packet creation exits `2`, emits one targeted `FAIL` line, and
  restores the exact pre-call Phase 5 bytes.

- [ ] **Step 6: Record and commit.**

  ```bash
  git commit -m "fix(work7): capture sealed phase evidence once"
  ```

**R1 success:** every ordinary final packet session member equals the bytes,
size, mode, and digest validated against its owning seal; the standalone static
copy equals its runtime-sealed twin; seal-file members equal the captured
predecessor-bound blobs; runtime semantics derive from that captured graph; and
two complete captures agree.

**R1 failure:** any later copy reopens a sealed Phase 0--4 path, transient bytes
enter the packet, a parsed mutable object escapes the API, runtime semantics
use live paths, or failure leaves new output.

### Task 3: R2 — Share a path-free terminal verifier core

**Files:**

- Modify: `scripts/verify_work7_claims.py`
- Modify: `scripts/work7_review_packet.py`
- Test: `tests/scripts/test_work7_claim_contract.py`
- Test: `tests/scripts/test_work7_review_packet.py`

**Consumes:** `TerminalInputs` made exclusively from R1 capture plus stable
final packet/review bytes.

**Produces:** `terminal_report_bytes(inputs) -> bytes`; the CLI wrapper
and `close_final` use the identical core.

- [ ] **Step 1: Add core and equivalence tests.**

  Add `test_terminal_core_matches_cli_report_from_identical_captured_bytes`,
  `test_close_final_does_not_reopen_phase3_or_phase4_after_capture`, and
  `test_close_final_revalidates_packet_members_before_publication`.  Inject
  transient replacement/restoration during the former live subprocess window.
  Assert captured bytes are used or closure fails with no terminal output.
  Both callers must supply the complete `Phase04Capture` (including every
  owning-tree member, contract, CTest inventory, and build binary) and every
  final-packet member through `TerminalInputs`.

- [ ] **Step 2: Prove RED.**

  Run the three named tests.  Expected: the current `terminal(args, ...)`
  reopens the live Phase 3/4 roots and `close_final` has no final member check.

- [ ] **Step 3: Implement the pure core.**

  Parse only the `TerminalInputs` byte fields.  Parse the claim contract and
  frozen CTest inventory inside the core; do not accept a caller-provided
  `claims` object.  Validate the canonical Phase 0 state, exact
  Phase 2-closure -> Phase 3-candidate -> Phase 3-closure -> Phase 4 predecessor
  digests and manifests, exact claim-7 report, exact Work packet/raw approval,
  final packet manifest and every `final_packet_members` blob, final packet
  digest, distinct exact Fable/sol identities, seven claim states, frozen CTest
  binding, and captured current Paper/threshold snapshots.  Return canonical
  terminal report bytes without filesystem I/O, subprocesses, or output
  creation.

  Invoke `validate_phase2_runtime_capture(inputs.phase04)` inside the core,
  rederive `works1-6-source-test-map.json` and
  `final-verification-summary.json` from that result, and compare their exact
  canonical bytes with both final packet metadata and captured final member
  blobs.  This keeps the existing self-consistent generated-member forgery
  regressions inside the shared terminal boundary.

- [ ] **Step 4: Retain the terminal CLI.**

  The `--mode terminal` wrapper stable-captures every CLI path once, constructs
  `TerminalInputs`, calls the core, and atomically creates `--output` only after
  success.  `close_final` imports the same core and constructs inputs from R1;
  it must not pass Phase 3/4 paths to a subprocess.  Revalidate every final
  packet member against its recorded digest before returning report bytes.

  For standalone `--mode terminal`, derive the session root only from the
  canonical exact suffix `<session>/phase0/seal.json`; reject a symlinked or
  noncanonical session, and require the supplied Phase 3 closure and Work-review
  seal paths to equal their fixed relative paths under that same session.  Then
  call `capture_phase04(session, source, paper, threshold)` once.  Capture the
  externally supplied final packet/reviews once and resolve every packet member
  path under the same canonical session before constructing `TerminalInputs`.

  This deliberately changes the old provenance mechanism: `close_final` uses
  the current approved source module's imported core rather than executing the
  sealed session-source verifier as a subprocess.  Record that decision in the
  Task 5 report; byte-identical core/CLI tests replace trust in the old wrapper.

- [ ] **Step 5: Port terminal fixtures and fault injection.**

  Upgrade the claim-contract terminal fixture to contain canonical Phase 3 and
  Phase 4 seals, exact member names `work-packet.json` and `raw-review.txt`, a
  canonical Work packet bound to the fixture seals, and a parseable sol
  `WORK7_APPROVED` review with every `CHECKS_WORK` confirmation.

  Port the four existing close-final tests that use
  `WORK7_TEST_TERMINAL_ACTION`: replace the fake terminal subprocess hook with
  synchronized mutation at the capture/publish boundary.  Preserve malformed
  report, missing report, external drift, and input replacement behaviors when
  those can still occur; retire the old missing-subprocess-output scenario only
  after replacing it with the equivalent core-exception/no-publication case.
  Every case must execute real parsing and filesystem publication, not assert
  source text or mock call counts.

- [ ] **Step 6: Prove GREEN and CLI compatibility.**

  Run full `test_work7_claim_contract.py` and all close-final capture tests.
  Expected: byte-identical core/CLI reports, no traceback, no live Phase 3/4
  read after capture, and no output on rejection.

  Include the existing
  `test_close_final_rejects_recanonicalized_generated_summary` and
  `test_close_final_rejects_recanonicalized_generated_source_test_map` in this
  GREEN command explicitly.

- [ ] **Step 7: Record and commit.**

  ```bash
  git commit -m "fix(work7): verify terminal evidence from captured bytes"
  ```

**R2 success:** one pure core derives the terminal report from exact captured
bytes and both callers produce identical canonical output.

**R2 failure:** the core accepts paths, reads the filesystem, emits output
before success, or the CLI and close-final enforce different semantics.

### Task 4: R3 — Publish Phase 5 atomically and dispose invalid runs safely

**Files:**

- Modify: `scripts/work7_review_packet.py`
- Modify: `scripts/run_work7_integration.py`
- Create: `scripts/work7_run_lifecycle.py`
- Test: `tests/scripts/test_work7_review_packet.py`
- Test: `tests/scripts/test_work7_integration_runner.py`

**Consumes:** prevalidated packet/review/report bytes and exact, already
validated generated run roots.

**Produces:** `publish_phase5(...) -> terminal seal digest`, reservation-ledger
cleanup, `classify_failure`, `record_and_apply_failure`, and
`dispose_generated_run(...) -> None` as fixed above.

- [ ] **Step 1: Add publication fault matrix.**

  Add `test_close_final_rolls_back_every_caught_phase5_publication_failure`.
  Inject `OSError`, `Failure`, `ValueError`, or `FileExistsError` at creation of
  terminal report, artifact directory, each of four members, seal, seal
  verification, pointer, pointer readback, and post-publication member
  revalidation.  Snapshot the pre-call Phase 5 path/byte set.  Every subtest
  must restore it exactly; a pre-existing path must never be removed.

  Use real filesystem fault points.  Pre-create late-path collisions to force
  rollback of earlier writes; for replacement/readback faults, run the CLI in a
  child process and coordinate a watcher through test-owned FIFOs/barrier files
  outside the session.  The watcher performs an actual atomic replacement and
  restoration.  Assert child exit `2`, one targeted stderr line, and exact
  recursive pre/post path, type, mode, and byte equality.  Source inspection,
  mocks, and call-count assertions cannot satisfy this matrix.

- [ ] **Step 2: Add exact-disposal tests.**

  Add `test_invalid_run_disposal_removes_only_owned_exact_roots` and
  `test_run_disposal_rejects_broad_foreign_symlink_or_mismatched_targets`.
  Cover exact success, wrong basename/commit/parent, source/Paper/threshold
  containment or ancestry, parent itself, a sibling sentinel, and user
  cancellation.  Include a pre-existing session sentinel where build
  reservation would otherwise succeed, and a race where session appears after
  preflight.  Assert reviewer-only delivery failure retains an unchanged packet
  and member byte graph through reviewer consumption; replace and restore a
  live member between classification and the reviewer callback and require the
  callback to receive the captured bytes.  Technical rejection disposes both
  owned roots only after its diagnostic record exists outside them.

  Also replace and consistently reseal the complete packet/member graph before
  retry capture.  Supply the packet digest recorded by the original delivery
  attempt and require rejection before parsing or provider invocation.

- [ ] **Step 3: Prove RED.**

  Run the three new tests.  Expected: late Phase 5 failures leave partial
  artifacts and no reusable exact-run disposal boundary exists.

- [ ] **Step 4: Implement fail-atomic publication.**

  Construct canonical terminal report, four member bytes, prospective seal,
  and pointer bytes before persistent publication.  Record only paths created
  by this call.  Use exclusive atomic creation, then stable-read the published
  group and revalidate exact bytes, manifest, predecessor, seal digest, and
  pointer.  Catch the approved exception set, remove recorded paths in reverse
  order, remove only newly created empty directories, confirm restoration, and
  re-raise.  OS kill and power loss remain outside this PoC.

- [ ] **Step 5: Implement reservation ownership and exact run disposal.**

  Preflight both target absences and build/session mutual non-overlap before
  reservation.  `reserve_owned` appends a path to `ReservationLedger.created`
  only after exclusive directory creation succeeds.  If the second reservation
  loses a race, reverse-clean only ledger-owned paths; never touch the
  pre-existing target.  After both reservations, mark the two roots as jointly
  owned and allow two-root disposal.

  Resolve parents and targets without symlinks; require target parents and
  basenames exactly `build-<commit>`/`session-<commit>`; reject protected-root
  equality, ancestry, or containment; and validate both targets before either
  removal.  Use `shutil.rmtree` only on those two validated, jointly owned
  paths.  The runner uses its ledger for partial failures and the two-root
  function only after joint ownership is proven.

  Add required CLI argument `--diagnostic-root` to
  `run_work7_integration.py` and update every caller/fixture.  On a partial
  reservation failure, write the same minimal execution diagnostic and clean
  only `ReservationLedger.created`.  On every caught failure after joint
  ownership, call `record_and_apply_failure(kind="execution", ...)` before
  returning exit `2`; tests for every post-reservation failure require the
  diagnostic to predate removal and both roots to be absent.  The runner never
  leaves full owned roots for an unspecified external orchestrator.

- [ ] **Step 6: Implement the executable failure coordinator.**

  In `work7_run_lifecycle.py`, define exact `kind` values:
  `execution`, `technical-review`, and `user-cancel` map to `DISPOSE`;
  `review-delivery` maps to `RETRY_REVIEWER`.  For disposal, exclusively write
  canonical JSON
  `failure-<commit>.json` beneath an explicit absolute `--diagnostic-root`
  that is outside source, Paper, threshold, build, and session.  Its exact keys
  are `schema`, `source_commit`, `failure_kind`, `action`,
  `build_root`, `session_root`, `packet_sha256`, and `publishable=false`.
  Stable-read it, then dispose jointly owned roots.

  For reviewer retry, `capture_review_bundle` stable-captures and validates the
  canonical packet plus every packet member exactly once.  Before parsing any
  captured member, it requires the packet SHA-256 to equal
  `expected_packet_sha256` taken from the immutable original-delivery record,
  never recomputed from the current session path.  Classification and delivery
  occur in one coordinator call:
  `deliver_reviewer_retry(bundle, delivery)` passes only
  `CapturedReviewBundle`, never a live session path, to the provider adapter.
  The production Task 6 adapters materialize/read only those supplied bytes;
  the sol/Fable prompt is bound to `bundle.packet.sha256`.  A synchronized test
  replaces and restores the live packet and a member after classification but
  before callback consumption and requires the adapter to observe the captured
  originals.  No endpoint reread is used as proof.

  Before any fresh Phase 0 run, the coordinator requires removal of the prior
  diagnostic via an exact-path `clear-diagnostic` action; it refuses a new run
  while the record exists.  Tests invoke the CLI/API through a subprocess and
  compare actual filesystem bytes, not mock calls.

- [ ] **Step 7: Prove GREEN.**

  Run all close-final tests and full `test_work7_integration_runner.py`.
  Expected: success publishes all-or-nothing; caught failures leave the exact
  prior Phase 5 state; disposal never touches sentinels or guarded roots.

- [ ] **Step 8: Record and commit.**

  ```bash
  git commit -m "fix(work7): make final publication fail atomic"
  ```

**R3 success:** no caught failure leaves a new terminal report/member/seal/
pointer, and invalid-run disposal removes exactly the owned build and session.

**R3 failure:** partial publication survives, pre-existing data is removed,
only one disposal target is validated before deletion begins, or a reviewer
transport error regenerates evidence.

### Task 5: R4 — Hostile regression gate and independent approval

**Files:**

- Modify: Task 5 report only if verification/review evidence must be appended.
- Verify: all files changed in R0--R3.

**Consumes:** R0--R3 commits and the approved remediation spec.

**Produces:** one verified remediation commit range ready for Task 6, or a
bounded fix loop with no more than two review-driven correction rounds.

- [ ] **Step 1: Run static checks.**

  ```bash
  python3 -m py_compile scripts/work7_evidence.py scripts/work7_review_packet.py \
    scripts/verify_work7_claims.py scripts/run_work7_integration.py \
    scripts/work7_run_lifecycle.py \
    tests/scripts/test_work7_review_packet.py tests/scripts/test_work7_claim_contract.py \
    tests/scripts/test_work7_integration_runner.py
  git diff --check
  ```

- [ ] **Step 2: Run the focused Task 5 gate once.**

  ```bash
  python3 -W ignore::ResourceWarning -m unittest -q \
    tests.scripts.test_work7_review_packet \
    tests.scripts.test_work7_claim_contract
  ```

- [ ] **Step 3: Run all five Work 7 Python suites once.**

  ```bash
  python3 -W ignore::ResourceWarning -m unittest -q \
    tests.scripts.test_work7_state_guard \
    tests.scripts.test_work7_claim_contract \
    tests.scripts.test_work7_integration_runner \
    tests.scripts.test_work7_response_candidate \
    tests.scripts.test_work7_review_packet
  ```

  This is hermetic/toy verification, not an actual DBLP/Enron or repeated
  benchmark campaign.

- [ ] **Step 4: Verify immutable external scope.**

  Add
  `test_final_scope_audit_accepts_only_toy_count_one_and_deferred_status` to
  `test_work7_integration_runner.py`.  It generates one hermetic synthetic
  session, passes its captured command records/artifacts to the byte-only R1
  runtime validator, and asserts the exact allowlist: smoke pre-threshold,
  quick tracked synthetic fixture, deletion `--trials=1`, every
  `trials`/`accuracy_trials`/`refresh_updates` field `1`, no external
  DBLP/Enron dataset path, and maximal status
  `POC_APPROVED_PERFORMANCE_PENDING`.  Mutate each count, actual-data path, and
  status in subtests and require observable rejection.

  Define “actual data” by canonical root and evidence mode, not a filename
  token: explicitly allow only the tracked synthetic fixture
  `tests/fixtures/real_datasets/quick/dblp_acm_u65536` under the source snapshot
  with the approved `--quick` command; reject any DBLP/Enron path outside that
  root or any non-quick/actual-data mode.  Include one accepted tracked-fixture
  case and separate rejected external-DBLP and external-Enron cases.

  Run that audit at final HEAD:

  ```bash
  python3 -W ignore::ResourceWarning -m unittest -v \
    tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_final_scope_audit_accepts_only_toy_count_one_and_deferred_status
  ```

  Immediately before and after all R4 commands, compute
  `snapshot_git_worktree(...)["snapshot_sha256"]` for these exact read-only
  roots and require string equality:

  ```text
  Paper: /Users/heewonchung/Documents/00-Research/active/Private Jaccard with FHE/Paper
  threshold: /Users/heewonchung/Documents/orca/workspace/piccard/tkde-major-threshold-fpfn
  ```

  Use `python3 -c` to print each digest into shell variables; do not create a
  state file in either worktree.  Record the before/after values and audit test
  output in the Task 5 report.

- [ ] **Step 5: Request `gpt-5.6-sol` high review.**

  Give the reviewer the approved spec, this plan, the pre-remediation base
  `24e9c51`, HEAD, earlier findings, and fresh test output.  Approval requires
  explicit verification that all earlier Critical/Important findings are
  addressed and no new Critical/Important finding exists.

- [ ] **Step 6: Apply review findings one at a time.**

  Verify each finding against the code.  For a valid Critical/Important item,
  resume the Terra implementer, add a behavioral RED test, make the minimal
  fix, run the focused GREEN test, commit, rerun R4, and request a fresh review.
  Stop and ask the user if two correction rounds do not produce approval.

- [ ] **Step 7: Freeze the Task 6 handoff.**

  Record approved HEAD, commands, exact test counts, reviewer verdict, and the
  failure-classification runbook in the Task 5 report.  Do not start Task 6
  until the worktree is clean and sol-high returns `APPROVED`.

**R4 success:** static checks, focused tests, all five suites, immutability
checks, and sol-high review all pass with no Critical/Important finding.

**R4 failure:** any command fails, any required test is skipped, any measured
count exceeds `1`, actual data is run, external bytes change, the worktree is
dirty at handoff, or review is not an exact approval.

## Task 6 Failure Runbook After R4 Approval

1. Start once from fresh exact `build-<approved-commit>` and
   `session-<approved-commit>` roots.
2. On build/test/schema/argv/count/provenance/seal/drift/crash/terminal failure,
   write a minimal non-publishable diagnostic outside guarded roots, invoke
   `record_and_apply_failure`, diagnose and fix, invoke the exact
   `clear-diagnostic` action, then begin one new Phase 0 run.  A lingering
   `failure-<commit>.json` blocks the rerun.
3. On sol/Fable technical rejection, preserve the raw rejection only as
   external diagnostic evidence, dispose build/session, fix, and restart from
   Phase 0.
4. On reviewer timeout/provider failure/unparseable response with no technical
   judgment, classify it as `review-delivery`, create one
   `CapturedReviewBundle` using the packet digest stored before the original
   delivery, and call `deliver_reviewer_retry` so only captured packet/member
   bytes reach the failed provider adapter.  Do not modify or regenerate the
   packet/session and retry only that reviewer.
5. On user cancellation, dispose exact build/session.  Never delete via a glob,
   unresolved variable, workspace root, source root, Paper, or threshold.
6. Run only the approved toy profile with every measured repetition equal to
   `1`.  Actual data and repeated performance remain deferred.

## Plan Self-Review

- Spec coverage: R0 covers canonical build binding; R1 covers exact captured
  Phase 0--4 bytes; R2 covers the shared terminal core and no live paths; R3
  covers late publication rollback and exact run disposal; R4 covers hostile
  tests, one-pass suite verification, and independent approval.
- Placeholder scan: the plan contains no unresolved or fill-in instruction.  Every
  implementation phase names its tests, RED/GREEN command, boundary, success,
  failure, and commit.
- Type consistency: the fixed interface section defines every cross-phase type
  and signature before use.  R1 produces `Phase04Capture`; R2 consumes it to
  construct `TerminalInputs`; R3 consumes only validated bytes from R2.
- Scope: no actual-data or repeated-performance execution is introduced;
  Paper and threshold stay read-only; crash-consistent transactions outside
  caught Python/filesystem errors remain explicitly outside this PoC.
