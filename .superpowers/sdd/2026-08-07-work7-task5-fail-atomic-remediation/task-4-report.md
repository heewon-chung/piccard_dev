# Work 7 Task 4 report — Unit A publication

## RED

The new representative real-filesystem publication test was run before the
publisher existed:

```text
python3 -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_rolls_back_every_caught_phase5_publication_failure
Ran 1 test in 10.303s
FAILED (errors=3)
```

Each subtest failed with the expected missing fixed interface:
`AttributeError: module 'scripts.work7_review_packet' has no attribute
'publish_phase5'`.

## GREEN

`publish_phase5(session, terminal_report, output_seal, packet_raw,
claude_raw, sol_raw, report_raw, previous_seal_sha256) -> str` now constructs
the terminal report, four terminal-artifact members, canonical prospective
seal, and pointer bytes before persistent publication.  It exclusively
creates paths, records lstat identity only after each successful creation,
stable-recaptures the report/seal/members/pointer, and rolls back recorded
paths in reverse order on the supported caught failures.  Existing Phase 5
objects are not recorded and are therefore preserved.  `close_final` retains
the R2 captured-byte/core validation boundary and delegates only the already
validated bytes to this publisher.

Focused evidence:

```text
test_close_final_rolls_back_every_caught_phase5_publication_failure ... ok
Ran 1 test in 9.867s
OK

test_close_final_core_rejection_leaves_no_phase5_seal_or_pointer ... ok
Ran 1 test in 9.386s
OK

test_final_close_binds_two_distinct_final_approvals_and_terminal_seal ... ok
Ran 1 test in 9.512s
OK
```

The representative rollback test uses real Phase 5 sentinels and asserts
exact recursive pre/post path, type, mode, and byte equality for: report
creation collision; terminal-artifact directory collision after report
creation; and pointer collision after the prospective seal is created.
Existing generated-summary and generated-source/test-map forgery regressions
were also exercised and reported `ok` by the focused unittest invocation.

`python3 -m py_compile scripts/work7_review_packet.py
tests/scripts/test_work7_review_packet.py` completed successfully, and
`git diff --check` was run before the Unit A commit.

## PoC deferrals

Per the approved scope override, this Unit does not attempt OS-kill/power-loss
atomicity, concurrent symlink/path-spelling replacement defenses, or an
exhaustive Phase 5 fault matrix.  Disposal, lifecycle coordination, diagnostic
records, and runner wiring are serial Units B/C work and were not changed.

## Unit B — invalid generated-run disposal

`scripts/work7_run_lifecycle.py` now contains the focused ownership boundary.
`ReservationLedger.created` records only successful exclusive reservations.
All supported authoritative kinds (`execution`, `technical-review`,
`review-delivery`, and `user-cancel`) classify to `DISPOSE` under the approved
override.  `record_and_apply_failure` exclusively creates and stable-validates
the external canonical `failure-<commit>.json` record before deleting a jointly
ledger-owned `build-<commit>` and `session-<commit>` pair.  The record uses the
exact eight-key `piccard-work7-failure-v1` schema, `action: DISPOSE`, and
`publishable: false`.

For a second-reservation collision, only paths already recorded in the ledger
are removed; the pre-existing conflicting session is untouched.  Direct
two-root disposal validates both absolute parents, exact basenames, exact
directories, non-overlap, and protected roots before deleting either target.
The module also exposes a small `record-failure` / `clear-diagnostic` CLI for
the runner-wiring unit.

### TDD evidence

RED, before the lifecycle module existed:

```text
python3 -m unittest -v tests.scripts.test_work7_integration_runner.Work7RunLifecycleTests
Ran 3 tests in 0.001s
FAILED (errors=3)
```

Each error was the expected missing module import:
`ModuleNotFoundError: No module named 'scripts.work7_run_lifecycle'`.

GREEN after the minimal implementation:

```text
python3 -m unittest -v tests.scripts.test_work7_integration_runner.Work7RunLifecycleTests
Ran 3 tests in 0.018s
OK
```

The focused tests create real temporary build/session roots and files, verify
each supported representative failure's exact external JSON record, assert both
owned roots are gone, and preserve an outside sibling sentinel.  They also
verify a second reservation collision removes only the first ledger root and a
mismatched session basename is rejected before either root is deleted.

`python3 -m py_compile scripts/work7_run_lifecycle.py
tests/scripts/test_work7_integration_runner.py` and `git diff --check` also
completed successfully in the focused verification command.

### Unit B deferrals

Per the user-approved PoC override, this unit does not add exhaustive
symlink/path-spelling/race matrices, actual-data runs, repeated measurement,
or integration-runner wiring.  Unit C is responsible for passing the runner's
real reservation ledger and diagnostic root into this boundary on every caught
post-reservation failure.

## Unit C — integration-runner lifecycle wiring

`run_work7_integration.py` now requires an absolute, externally located
`--diagnostic-root`.  It derives the exact `failure-<commit>.json` path before
reservation and refuses a new invocation while that file exists, naming the
explicit `clear_diagnostic` action required before a fresh Phase 0 attempt.
The runner uses one `ReservationLedger` and `reserve_owned` for the exact
build root followed by the exact session root.  After a partial session
collision, it records the same canonical nonpublishable execution diagnostic
and rolls back only the ledger-created build root.  After joint ownership,
caught execution failures write and stable-validate the external diagnostic
before the Unit B helper deletes both exact roots.  A caught keyboard interrupt
is coordinated identically with `user-cancel`; successful runs retain both
evidence roots and create no diagnostic.

### TDD evidence

RED before runner wiring:

```text
python3 -m unittest -v \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_post_reservation_failure_is_disposed_then_requires_clear_for_fresh_phase0 \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_partial_session_collision_keeps_foreign_root_and_disposes_created_build
Ran 2 tests in 1.138s
FAILED (failures=1, errors=1)
```

The post-reservation configure failure produced no external diagnostic, and
the existing-session collision left no diagnostic/rollback proof—the expected
pre-wiring failures.

GREEN focused rerun:

```text
Ran 2 tests in 4.257s
OK
```

The real fake-tool configure failure proves the exact diagnostic bytes and
paths, that both generated roots are absent, and that an outside sibling
sentinel survives.  A second invocation is rejected before reservation until
the exact diagnostic is removed through `clear_diagnostic`; after clearing and
repairing the fake tool, a new run succeeds from Phase 0 and retains its build
and session evidence.  The collision test proves the pre-existing session
sentinel is retained while only the newly-created build root is rolled back.

### Unit C deferrals

Per the approved PoC override, Unit C does not add an exhaustive injected
failure matrix, symlink/path-spelling or concurrent-replacement cases,
actual-data execution, or repeated performance measurements.  The exercised
normal cases use toy inputs and all measured counts remain one.

## R3 review fix round 1 — external diagnostics and fixed public interface

`record_and_apply_failure` now has the restored fixed public signature:

```text
record_and_apply_failure(kind, diagnostic_root, build_parent, session_parent,
                         build, session, commit, guarded, packet,
                         packet_sha256) -> str
```

It has no ledger argument and accepts positional calls.  It validates the two
exact generated roots, then requires the canonical diagnostic root to be
strictly external to every guarded root and to both generated roots before any
diagnostic write or deletion.  Where `packet` is supplied, the wrapper
stable-captures its SHA-256 and requires any supplied digest to match.  On
success it returns the deterministic canonical diagnostic-path string.

Runner-specific partial-reservation behavior is deliberately private in
`_record_and_apply_owned_failure(...)`; it uses the same validation/write
boundary but consults `ReservationLedger` only to roll back paths the runner
actually created.  This retains the existing session-collision behavior while
keeping the fixed public disposal API independent of runner state.

### TDD evidence

The added guarded-contained diagnostic case and restored positional calls were
run before the implementation update:

```text
python3 -m unittest -v tests.scripts.test_work7_integration_runner.Work7RunLifecycleTests
Ran 4 tests in 0.015s
FAILED (errors=6)
```

The public API failed exactly because it still accepted zero positional
arguments (`TypeError: ... takes 0 positional arguments but 10 were given`),
and the private runner coordinator had not yet been introduced.

Focused GREEN verification:

```text
python3 -m unittest -v \
  tests.scripts.test_work7_integration_runner.Work7RunLifecycleTests \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_post_reservation_failure_is_disposed_then_requires_clear_for_fresh_phase0 \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_partial_session_collision_keeps_foreign_root_and_disposes_created_build
Ran 6 tests in 3.232s
OK
```

The new real-filesystem test places the proposed diagnostic directory beneath
a guarded source root and verifies rejection, no diagnostic creation, and both
generated roots retained.  The lifecycle test also asserts that the public
return is a `str` equal to the resolved `failure-<commit>.json` path.

`python3 -m py_compile scripts/work7_run_lifecycle.py
scripts/run_work7_integration.py tests/scripts/test_work7_integration_runner.py`
and `git diff --check` completed successfully with the focused run.
