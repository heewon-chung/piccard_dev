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
