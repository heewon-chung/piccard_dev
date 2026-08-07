# Task 2 / R1 report

## Scope

Implemented the fixed captured-byte interfaces in `scripts/work7_evidence.py`,
`scripts/work7_review_packet.py`, and `scripts/run_work7_integration.py`.
`prepare-final` now captures Phase 0--4 before validation, builds its proposed
packet bytes in memory, compares a complete second capture, and rolls back the
Phase 5 members/output it created if publication raises.

## TDD evidence

RED command (the requested new capture behaviors, before implementation):

```text
python3 -m unittest tests.scripts.test_work7_state_guard.Work7StateGuardTest.test_capture_tree_seal_returns_exact_member_bytes_without_reopen tests.scripts.test_work7_state_guard.Work7StateGuardTest.test_captured_graph_is_recursively_immutable_and_preserves_seal_modes -v
```

Observed output: `ImportError: cannot import name 'capture_tree_seal' from
'scripts.work7_evidence'`; `Ran 2 tests`; `FAILED (errors=2)`.

GREEN command after the minimal capture implementation:

```text
python3 -m unittest tests.scripts.test_work7_state_guard.Work7StateGuardTest.test_capture_tree_seal_returns_exact_member_bytes_without_reopen tests.scripts.test_work7_state_guard.Work7StateGuardTest.test_captured_graph_is_recursively_immutable_and_preserves_seal_modes -v
```

Observed output: both tests `ok`; `Ran 2 tests in 0.361s`; `OK`.

The pre-existing transient Phase 4 packet regression was run against the R1
path after adapting its restoration point to the capture/publication boundary:

```text
python3 -m unittest tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_seals_validated_phase4_bytes_despite_transient_replacement -v
```

Observed output: `ok`; `Ran 1 test in 8.094s`; `OK`.

The ordinary end-to-end final packet and close path was also re-run:

```text
python3 -m unittest tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_close_binds_two_distinct_final_approvals_and_terminal_seal -v
```

Observed output: `ok`; `Ran 1 test in 10.992s`; `OK`.

## Behavior guarded

* `test_capture_tree_seal_returns_exact_member_bytes_without_reopen` catches a
  production change that returns/reopens a path rather than retaining the
  verified member bytes.
* `test_captured_graph_is_recursively_immutable_and_preserves_seal_modes`
  catches mutable captured records or validation that ignores a manifest mode
  change.
* `test_prepare_final_seals_validated_phase4_bytes_despite_transient_replacement`
  catches Phase 5 copying a live Phase 4 seal/member instead of its captured
  predecessor-bound bytes.
* `test_final_close_binds_two_distinct_final_approvals_and_terminal_seal`
  catches a final packet that is no longer structurally consumable by Phase 5
  closure.

## Files

* `scripts/work7_evidence.py`
* `scripts/work7_review_packet.py`
* `scripts/run_work7_integration.py`
* `tests/scripts/test_work7_review_packet.py`
* `tests/scripts/test_work7_state_guard.py`

## Concerns / follow-up required

The full specified R1 fault matrix has **not** yet been observed GREEN: there
is no dedicated real-filesystem regression for a transient Phase 0--3 runtime
member or a transient required build binary during semantic validation, and no
separate observed rollback tests for member-generation, generated-member,
second-capture, and packet-creation failures.  The comprehensive
`test_prepare_final_rejects_noncanonical_build_roots_before_output` subcase
matrix was still executing when this report was written.  Do not treat this
task as fully verified until those tests are added/run serially and the full
`test_work7_state_guard.py` plus `prepare-final` suite are green.

## Unit A — byte-only semantic and seal-binding regressions

Added four real-filesystem regressions in
`tests/scripts/test_work7_review_packet.py`:

* `test_runtime_semantics_use_captured_producer_bytes_while_live_member_is_foreign`
  atomically replaces `pre-threshold/manifest.json` with foreign bytes while a
  synchronized worker runs `validate_phase2_runtime_capture`; the captured
  graph validates and Phase 5 remains absent.
* `test_runtime_semantics_use_captured_build_binary_while_live_binary_is_foreign`
  does the same to the R0-bound `bench_deletion_survival` executable.  The
  runtime summary retains the digest framed from the original captured argv.
* `test_capture_phase04_rejects_phase2_static_copy_that_differs_from_runtime_sealed_twin`
  changes only the standalone static report and verifies CLI exit 2, one
  failure reason containing `sealed runtime copy`, and no final packet/members.
* `test_final_packet_seal_members_equal_the_predecessor_bound_captured_seal_blobs`
  checks all six Phase 0--4 seal members in the final packet against their
  captured blobs, including size, SHA-256, and predecessor chain ordering.

Serial GREEN command:

```text
python3 -m unittest \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_runtime_semantics_use_captured_producer_bytes_while_live_member_is_foreign \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_runtime_semantics_use_captured_build_binary_while_live_binary_is_foreign \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_capture_phase04_rejects_phase2_static_copy_that_differs_from_runtime_sealed_twin \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_packet_seal_members_equal_the_predecessor_bound_captured_seal_blobs -v
```

Observed output: four `ok`; `Ran 4 tests in 28.989s`; `OK`.

Because the producer, build-binary, and seal assertions pass on the R1
implementation, discriminating REDs were run in disposable detached worktrees
at `09f90a3` and never committed:

* a temporary `validate_phase2_runtime_capture` mutant that read the live
  producer manifest failed with `Failure: mutant reopened live pre-threshold
  manifest` while the foreign bytes were installed;
* a corresponding build-binary reopen mutant failed with `Failure: mutant
  reopened live build binary`;
* removing both the static-twin equality check and the standalone static
  semantic check allowed a foreign static report through `prepare-final` with
  output `0`.

The seal-member regression checks the fixed captured predecessor blobs and
their final packet entries directly.  A dedicated concurrent live-seal swap
stress case remains for the later rollback/fault-matrix unit.

## Unit B — seal race and fail-atomic publication

Added filesystem-race regressions with exact recursive Phase 5 snapshots:

* An ordinary `session/phase2/static-report.json` collision is created by a
  polling worker only after `phase5/members` exists.  `prepare-final` exits 2
  and removes every member it created.
* A later generated-member collision at
  `generated/works1-6-source-test-map.json` likewise exits 2 and restores the
  exact pre-call path/type/mode/byte snapshot.
* A live `phase2/runtime-seal.json` replacement makes a subsequent complete
  capture fail while validation of the already captured graph still succeeds;
  the foreign seal never enters Phase 5.
* A pre-existing output collision sentinel survives an attempted prepare-final
  unchanged, including its bytes and file mode.

The seal-swap regression exposed a production gap: the initial runtime-seal
capture was evaluated outside the normal error translation and leaked
`ValueError`.  `capture_phase04` now converts it to the single fail-closed
`Failure` used by the CLI and callers.

Serial GREEN command:

```text
python3 -m unittest \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rolls_back_ordinary_member_collision_after_publication_starts \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rolls_back_generated_member_collision_after_ordinary_members \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_capture_phase04_seal_swap_fails_second_capture_without_phase5_output \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_preserves_preexisting_output_collision_sentinel -v
```

Observed output: four `ok`; `Ran 4 tests in 29.251s`; `OK`.

Remaining Unit B scope not yet demonstrated: a deterministic packet-creation
failure after member publication and a direct `prepare-final` second-capture
mismatch after all prospective bytes are assembled.  The production path has
the second-capture compare and exclusive creation ledger, but those two
specific real-filesystem fault injections need a non-mock synchronization
point to be fully observable.

## Unit C — deterministic late-capture and packet-create faults

`prepare_final` and `main` now accept an optional `synchronize(point)` callback
(default `None`).  It has no production effect and exposes only two named
filesystem boundaries: `before_second_capture`, after all prospective bytes
are assembled, and `before_packet_create`, after member publication.

RED before adding the optional boundary:

```text
python3 -m unittest \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_second_capture_boundary_rejects_real_seal_replacement_without_output \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_packet_creation_boundary_rolls_back_members_and_preserves_sentinel -v
```

Observed: both error with `TypeError: main() got an unexpected keyword argument
'synchronize'` (`Ran 2 tests`; `FAILED (errors=2)`).

GREEN after the minimal boundary implementation:

```text
python3 -m unittest \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_second_capture_boundary_rejects_real_seal_replacement_without_output \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_packet_creation_boundary_rolls_back_members_and_preserves_sentinel -v
```

Observed: two `ok`; `Ran 2 tests in 15.787s`; `OK`.

The first test atomically installs foreign `phase2/runtime-seal.json` bytes at
the second-capture boundary, calls real `main`, receives exit 2 and the
targeted `Phase 0--4 evidence changed during final packet preparation` line,
then restores the seal and requires the exact pre-call Phase 5 snapshot.  The
second creates a real output collision sentinel immediately before exclusive
packet creation; it requires exit 2, exact sentinel bytes/mode, and no
published `phase5/members` directory.

Both passing tests were mutation-proven in disposable detached worktrees at
`0f5edd6`, without committing the mutants:

* deleting the second-capture comparison made the first test fail because
  `main` returned `0` rather than `2`;
* restoring the old broad cleanup (`unlink` any existing output on failure)
  made the packet-collision test error because its sentinel was deleted.

## Remediation round 1 — terminal closure Phase 4 race

Controller reproduction:

```text
python3 -m unittest tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_revalidates_phase4_after_runtime_validation -v
```

RED observed: `AssertionError: Failure not raised` at
`test_work7_review_packet.py:698`; the terminal seal was printed, proving the
Phase 4 reseal reached terminal closure.

Cause: `close_final` continued to run the legacy path-based
`validate_phase2_runtime`, while the R1 race boundary and the regression patch
`validate_phase2_runtime_capture`.  The test's real Phase 4 reseal was never
triggered, so the later closure check still saw the original seal.

Fix: after the legacy summary needed by the terminal-packet schema, close-final
now captures Phase 0--4 and calls `validate_phase2_runtime_capture` before
deriving generated members and running `validate_final_closure_prerequisites`.
Thus a reseal in that window is observed by the existing final closure
revalidation and prevents all terminal outputs.

GREEN command:

```text
python3 -m unittest \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_revalidates_phase4_after_runtime_validation \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_external_drift_after_packet_preparation_leaves_no_phase5_seal_or_pointer -v
```

Observed: two `ok`; `Ran 2 tests in 17.752s`; `OK`.  Python emitted existing
`ResourceWarning` diagnostics from legacy runner path reads; no test failure.
