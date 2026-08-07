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
