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

## Remediation round 2 (partial)

Addressed reviewer Important 1: `capture_tree_seal` now calls
`_reject_symlink_components` for every manifest member before its stable
terminal-file read.  This closes the gap where `O_NOFOLLOW` protected only the
final component and an intermediate directory symlink could be followed.

Focused evidence:

```text
python3 -m unittest tests.scripts.test_work7_state_guard.Work7StateGuardTest.test_capture_tree_seal_rejects_nested_member_directory_symlink -v
```

Observed: `ok`; `Ran 1 test in 0.188s`; `OK`.

The remaining reviewer Critical producer-schema port plus Important exact
manifest/source-capture/creation-ledger/closure-input findings are not yet
implemented.  This report entry intentionally does not claim R1 completion.

## Unit D — captured claim-report schema parity

Enumerated legacy producer/report validation coverage: pre-threshold validates
the manifest key set, toy one-run cells, terminal binding and output digests;
real-data validates the flattened metadata roots/artifacts/cells/argv/input and
output digest bindings; deletion validates its fixed CSV; claim reports bind
the contract claims and, for evidence-bound mode, the runtime seal.

Focused hostile coverage was added for missing pre-threshold terminal/output
bindings, missing real metadata root/artifact/cell/digest bindings, and missing
claim-report claims/input-seals.  The first two were characterization checks:
the current captured validators already rejected them.  The claim report test
was a genuine RED: removal of `claims` and `input_seals` still passed the old
four-top-level-field screen.

The byte-only runtime validator now requires each report's exact top-level key
set, complete ordered contract claim IDs, and exact input seals (`{}` for
static reports; the captured runtime seal SHA-256 for evidence-bound report).

Focused command:

```text
python3 -m unittest \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_prethreshold_validator_rejects_missing_terminal_and_output_bindings \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_real_validator_rejects_missing_root_artifact_cell_and_digest_bindings \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_claim_reports_require_claims_and_runtime_seal_binding \
  tests.scripts.test_work7_state_guard -v
```

Observed focused tests: all three `ok`; state-guard output streamed all listed
tests as `ok` before runner completion.  The remaining full producer schema
port (notably exact argv/artifact-field parity for every path-validator branch)
remains outside this partial Unit D change.

### Unit D round 2b

Corrected the hostile producer tests to feed exactly the production filtered
`pre_blobs`/`real_blobs`, and to establish the unmodified captured baseline
before applying each mutation.  This exposed a real pre-threshold RED: deleting
`terminal_cells` and a referenced output digest passed the old captured-byte
validator.  The validator now enforces the complete top-level manifest key
set, directories/thread policy, terminal TSV identity/digest/header, exact
producer/output schemas, and every referenced output blob SHA-256.

Focused RED/GREEN command:

```text
python3 -m unittest \
 tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_prethreshold_validator_rejects_missing_terminal_and_output_bindings \
 tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_real_validator_rejects_missing_root_artifact_cell_and_digest_bindings -v
```

RED: prethreshold assertion `Failure not raised` (real baseline/mutation inputs
were filtered exactly as production).  GREEN: both tests `ok`; `Ran 2 tests in
16.983s`; `OK`.  Full per-cell argv/provenance and flattened real metadata
parity remains to be ported.

## Unit D completion — exact captured producer and claim parity

### RED

The new byte-only parity regression was first run before the producer port:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_producer_validators_require_exact_byte_only_schemas
```

Observed: six expected failures.  The old captured pre-threshold validator
accepted mutation of the machine schema, binary provenance, cell ID, duplicate
sampling flag, and output row count; it also had no captured
`@source/scripts/summarize_real_datasets.py` blob.  The focused claim-semantic
RED then showed three accepted mutations: a static per-claim performance state,
an evidence-bound per-claim toy state, and an evidence-index artifact kind.

### GREEN

The completion uses only production-filtered captured blobs.  The capture graph
now retains private namespaced source blobs for the real-data summarizer and
the external quick-fixture dataset bytes.  They participate in the complete
second-capture equality comparison but are never emitted as Phase 5 packet
members.  The runtime selector passes only each producer's manifest, declared
artifacts, required captured binary/source blobs, and verification TSV; it no
longer hands the validators unrelated producer files.

Fresh focused verification:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_producer_validators_require_exact_byte_only_schemas \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_claim_reports_preserve_full_contract_and_evidence_semantics
```

The final five-test command below re-ran both new cases plus all three existing
Unit D regressions and exited `0`.

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_prethreshold_validator_rejects_missing_terminal_and_output_bindings \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_real_validator_rejects_missing_root_artifact_cell_and_digest_bindings \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_claim_reports_require_claims_and_runtime_seal_binding
```

Observed: all three `ok`; `Ran 3 tests in 22.331s`; `OK`.

Final fresh command:

```text
python3 -W ignore::ResourceWarning -m unittest -q \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_producer_validators_require_exact_byte_only_schemas \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_claim_reports_preserve_full_contract_and_evidence_semantics \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_prethreshold_validator_rejects_missing_terminal_and_output_bindings \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_real_validator_rejects_missing_root_artifact_cell_and_digest_bindings \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_claim_reports_require_claims_and_runtime_seal_binding
```

Observed: exit `0`.

### Field-by-field parity statement

`validate_prethreshold_capture` now matches `validate_prethreshold` for the
exact top/source/build/binary-provenance/machine/directory schemas; producer
set; all three cell schemas, IDs, argv vectors, sampling uniqueness,
environment, status and one-run counts; output schema/row counts/digests; and
terminal TSV path/count/digest/header/sorted cell bindings.  The runner argv's
captured results root is tied to the dynamic manifest/trace cell arguments.

`validate_real_capture` now rebuilds and compares the entire flattened metadata
map: canonical quick roots, binary and captured summarizer digests, artifact
roles/paths/digests, three exact cell IDs/argv framing/hash/environment/input
and output counts/paths/digests/statuses, and the exact verification-status TSV.
The externally referenced fixture input is validated from its captured source
blob, so no live evidence path is reopened.

Captured static and evidence-bound reports now run the established pure
`report_claims` semantics against the captured contract and captured CTest
inventory, preserve the exact static `{}` versus evidence runtime-seal input
bindings, and independently validate the captured runtime evidence index
against the owning captured seal members.  The generic count screen remains in
both producer paths, preserving exactly-one trials/accuracy-trials/
refresh-updates and rejecting actual-data artifacts.

## Unit E — exact prerequisite manifests and source/diff capture equality

### Finding A — exact manifest sets

`capture_phase04` now supplies complete fixed member sets to every Phase 0--4
seal capture: Phase 0 state, the full Phase 2 runtime graph, Phase 2 closure,
Phase 3 candidate, Phase 3 closure, and Phase 4 review.  This closes the three
remaining acceptance paths for a self-consistently resealed runtime, candidate,
or claim-7 closure graph with an added member; the existing Phase 0, Phase 2
closure, and Phase 4 fixed sets are now expressed through the same constants.

The real-filesystem hostile regression makes an extra and a missing member for
each Phase 0--3 root, reseals the entire predecessor chain (including Phase 4),
and requires `capture_phase04` to reject it.  It does not assert source text or
mock invocation counts.

### Finding B — source/diff capture equality

`Phase04Capture` now retains every final packet source member and the baseline
Git diff as immutable captured blobs.  The contract blob is the same captured
source-member blob, and those new fields participate in the dataclass equality
used for the complete second capture.  `prepare_final` constructs all source
and diff members exclusively from these first-capture blobs; it does not reopen
a source packet path or regenerate the diff after capture.  The existing
private `@source/` summarizer and fixture blobs stay in `packet_members` for
validation/equality only and are never emitted as Phase 5 packet members.

The new `after_first_capture` synchronization point supports a deterministic
filesystem race regression.  It atomically replaces a source design after the
first complete capture, restores the original before the second capture, and
requires the final member to contain the verified original bytes, never the
transient bytes.  The same test checks every source member and diff against the
captured blobs, verifies safe `0600` packet/member output modes, and verifies
that no private namespace is emitted.

### TDD evidence and verification

RED before the Unit E implementation:

```text
python3 -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_capture_phase04_rejects_resealed_extra_and_missing_phase0_through3_members \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_never_publishes_transient_source_packet_bytes
```

Observed `Ran 2 tests in 18.114s`, `FAILED (failures=5)`: self-consistently
resealed runtime extra/missing and Phase 3 candidate/closure extra manifests
were accepted; the source test observed only `before_second_capture`, proving
the required first-capture race boundary did not exist.

Focused GREEN after the minimal implementation ran the same command and
observed `Ran 2 tests in 16.701s`, `OK`.

Fresh owned-suite verification:

```text
python3 -W ignore::ResourceWarning -m unittest -q tests.scripts.test_work7_review_packet
# Ran 41 tests in 494.477s — OK

python3 -W error::ResourceWarning -m unittest -v tests.scripts.test_work7_state_guard
# Ran 23 tests in 7.182s — OK
```

## Unit F — reviewer Important publication rollback ownership

### Finding mapping

The reviewer Important publication finding was that `prepare_final` created
`phase5/members` with recursive `mkdir(parents=True)` and, on a caught failure,
called `shutil.rmtree(root)`.  That broad cleanup could delete a collision
sentinel or any non-owned descendant created after publication began.  It also
did not distinguish an absent Phase 5 root from an already-present empty one.

`_PublicationLedger` now records, in creation order, every directory and
regular file successfully created by this `prepare-final` invocation.  This
includes an absent `phase5`, `phase5/members`, all member parents/files, and
the output packet (including any newly required packet-parent directories).
Each ledger entry stores its `lstat` device/inode/type identity.  On every
caught publication error, rollback visits entries in strict reverse order and
only `unlink`s an unchanged owned regular file or `rmdir`s an unchanged owned
empty directory.  It never recursively traverses a tree, and it leaves a
replaced path or non-owned descendant untouched.  Pre-existing directories are
never added to the ledger.

### TDD evidence

RED was run before the ledger implementation:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rolls_back_ordinary_member_collision_after_publication_starts \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rolls_back_generated_member_collision_after_ordinary_members
```

Observed: both tests errored with `FileNotFoundError` reading the injected
`collision sentinel`; the old `shutil.rmtree` had deleted it (`Ran 2 tests in
17.372s`, `FAILED (errors=2)`).

The snapshot helper now records an absent root separately from an empty root,
and every captured entry includes relative path, type, mode, and bytes (or the
symlink target bytes).  The focused real-filesystem rollback matrix was then
run against toy fixtures only:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rolls_back_ordinary_member_collision_after_publication_starts \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rolls_back_generated_member_collision_after_ordinary_members \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_second_capture_boundary_rejects_real_seal_replacement_without_output \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_packet_creation_boundary_rolls_back_members_and_preserves_sentinel
```

Observed: all four tests passed.  The ordinary collision occurs after ordinary
member publication; the generated-summary collision occurs after the first
generated member; the second-capture case asserts byte/mode-exact restoration
for both a missing and a pre-existing empty `phase5`; and the packet-creation
collision preserves its `0640` sentinel while removing owned members.  The
ordinary and generated pair independently reported `Ran 2 tests in 16.189s —
OK`; the packet-creation case independently reported `Ran 1 test in 8.511s —
OK`.

Mutation proof temporarily replaced `ledger.rollback()` with `pass` in the
disposable local edit, then ran the ordinary collision regression.  It failed
as intended because `phase5/members/source` remained after the failure
(`AssertionError: True is not false`; `Ran 1 test in 8.845s`, `FAILED
(failures=1)`).  The exact rollback call was restored immediately; no mutation
was committed.  This is behavioral evidence rather than a source-text or mock
call-count assertion.

Final owned-suite verification was run once after the focused matrix:

```text
python3 -W ignore::ResourceWarning -m unittest -q tests.scripts.test_work7_review_packet
```

Observed: exit 0 (toy fixture suite only).

## Unit G — reviewer Important legacy live-path closure inputs

`close_final` now establishes exactly one R1 Phase 0--4 capture with the
canonical CLI source, Paper, and threshold roots:

```text
capture_phase04(session, source, paper, threshold)
```

It validates that immutable graph through `validate_phase2_runtime_capture`
and derives both generated final-member byte strings through the shared pure
`captured_generated_member_bytes(capture, RuntimeSummary)` helper also used by
`prepare_final`.  The final-packet checker compares every public Phase 5 member
back to its captured (or pure rederived) bytes, including all session seal and
member copies.  It preserves the existing packet schema: frozen registry count
and argv hashes remain exact, and `verify_real_datasets` remains intentionally
absent from `toy_argv_sha256`.

The old path-based `phase0`, `chain`, `validate_phase4`,
`validate_phase2_runtime`, and `final_generated_member_bytes` paths no longer
provide closure inputs.  A late seal-byte comparison and external-snapshot
comparison remain explicitly transitional race detectors only: they never feed
any derived packet, generated-member, or seal value.  They preserve the
existing Phase 0/Phase 4 race fail-closed behavior before terminal publication.

### R1/R2 boundary

This is deliberately R1 only.  `close_final` still invokes the existing
terminal verifier subprocess, then validates its report against the captured
contract bytes.  It does not add `TerminalInputs`, `terminal_report_bytes`, or
the R2 shared terminal core, and it does not remove the terminal subprocess.

### TDD evidence

RED before the Unit G refactor:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_reaches_terminal_boundary_without_legacy_phase_paths \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_generated_members_remain_captured_while_live_inputs_are_transiently_foreign
```

Observed: the legacy-path bomb raised at `close_final -> phase0`; the
transient-capture case failed in `final_generated_member_bytes` after it
reopened the live CTest inventory (`malformed CTest inventory header`).

Focused GREEN outputs observed directly after the refactor:

* `test_close_final_reaches_terminal_boundary_without_legacy_phase_paths`:
  `ok` with all five legacy functions patched to raise.
* `test_close_final_generated_members_remain_captured_while_live_inputs_are_transiently_foreign`:
  `ok` while the live contract, CTest inventory, and Paper file were foreign
  throughout the captured final-member validation boundary.
* `test_close_final_revalidates_phase4_after_runtime_validation`: `ok`; the
  Phase 4 reseal reached the transitional seal race detector and produced no
  terminal artifact.

The later aggregate `-k close_final` run was duplicated by the controller and
interrupted; it is intentionally not claimed as verification evidence.  The
authoritative post-commit focused closure run remains pending.

## R1 fix round 3 — sol-high Important remediation

### Finding 1 — fixed `Phase04Capture` surface and private publication boundary

**RED.** The new fixed-interface regression failed while the capture still
required `source_packet_members` and `baseline_diff_raw`; the phase object had
two fields beyond the plan's exact interface.

**GREEN.** `Phase04Capture` now contains only the twelve fixed fields. Public
source blobs and the baseline diff are captured exactly once under reserved
`@public/...` entries in `packet_members`; contract, summarizer, fixture, and
contract-referenced source blobs remain reserved `@source/...` entries. Final
publication reads an explicit `SOURCE_PACKET_MEMBERS` allowlist plus the one
reserved public diff entry, so no `@...` entry can become a Phase 5 member.
The regression constructs/replaces the fixed dataclass without extra arguments
and verifies that the generated packet contains no `@` path.

### Finding 2 — producer roots bind exactly to the captured runtime seal

**RED.** A self-consistently resealed pre-threshold or real-data graph using a
foreign `.../phase2/runtime/<producer>` root passed the prior suffix checks and
could reach final-packet preparation.

**GREEN.** `validate_phase2_runtime_capture` derives exactly
`<runtime-seal.artifact_root>/pre-threshold` and
`<runtime-seal.artifact_root>/real-datasets`, then uses those strings in the
pre, real, and verify-real command records and in the real-data metadata
binding. The pre-threshold producer receives the same exact argv root for all
dynamic cell arguments; the real validator reconstructs every metadata argv
from the exact metadata root. The dummy `pre_argv` was removed. The hostile
tests rewrite every relevant producer command/metadata/argv/status digest
against a foreign root, reseal the full graph, and require `prepare-final` to
fail without Phase 5 output for each producer.

### Finding 3 — captured-only contract `source_paths`

**RED.** There was no captured-byte contract-source validator: finalization
could rely on legacy live-path semantics and did not prove that every contract
reference had been captured as a regular file.

**GREEN.** Capture now parses every lifecycle `source_paths` value before
finalization and stores each referenced regular source file under a reserved
`@source/<relative>` entry. The byte-only validator rejects absolute,
escaping, noncanonical, duplicate, missing, and directory/non-file references,
and never accepts a live source root. The regression mutates captured contract
bytes for each of those cases and verifies rejection.

Focused RED/GREEN command (toy fake-run fixtures only):

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_phase04_capture_preserves_the_fixed_public_interface_and_never_publishes_private_members \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_self_consistent_foreign_producer_roots \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_captured_contract_source_paths_reject_unsafe_or_uncaptured_references
```

Observed RED: the fixed-interface assertion failed and both self-consistent
foreign-root subtests failed before the exact binding implementation. Observed
GREEN: the fixed-interface test and both producer-root subtests reported `ok`;
the contract-source test reported `ok` independently (`Ran 1 test in 8.269s;
OK`). No actual-data, performance, or broad test suite was run.
