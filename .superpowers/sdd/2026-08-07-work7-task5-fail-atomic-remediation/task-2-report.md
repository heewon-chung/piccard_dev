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
