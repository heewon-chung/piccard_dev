# Work 7 Task 5 report

## RED

```text
python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_work_creates_deterministic_sealed_session_relative_packet
FAIL: can't open file 'scripts/work7_review_packet.py': [Errno 2] No such file or directory
```

The first real CLI test created temporary Git-backed Phase 0/2/3 evidence,
then invoked the missing `prepare-work` command.  It asserted a canonical,
session-relative packet and independently hashed each copied member.

Compatibility RED, after authorization for the only out-of-scope correction:

```text
python3 -m unittest -v tests.scripts.test_work7_claim_contract.Work7ClaimContractTests.test_terminal_accepts_only_exact_dual_reviews_and_immutable_external_state
FAIL: verify_work7_claims: FAIL: work review seal is missing packet or raw review
```

That regression seals only the already-available Work packet and Sol work-level
approval in Phase 4.  The old terminal verifier incorrectly required it to
also contain the later final packet and both independent final raw responses,
which cannot exist before an append-only Phase 4 seal is closed.

## GREEN / refactor

Implemented `scripts/work7_review_packet.py` with all four CLI commands.
Packets copy only regular files into phase-local `members/` directories,
record POSIX session-relative paths, lengths and SHA-256s in canonical JSON,
validate every Phase 0–3 prerequisite and member on closure, preserve raw
reviews, and create append-only Phase 4/5 tree seals.  Final closure invokes
the terminal verifier, independently checks Paper/threshold Phase 0 equality
before and after it, writes the Phase 5 seal, and prints/writes the exact
authoritative terminal seal digest.

The minimal authorized verifier compatibility correction removes only the
impossible Phase 4 membership test.  It retains the Phase 3→4 predecessor,
exact final packet digest, exact provider/model/high-effort/status headers,
all six final confirmations, and Phase 0 external snapshot checks.  The final
packet itself now independently binds the exact Phase 4 seal digest and every
snapshotted member is re-hashed before closing.

Focused GREEN:

```text
python3 -m unittest -q tests.scripts.test_work7_review_packet tests.scripts.test_work7_claim_contract
Ran 16 tests in 21.599s
OK

python3 -m py_compile scripts/work7_review_packet.py scripts/verify_work7_claims.py
git diff --check
```

Regression:

```text
python3 -m unittest -q tests.scripts.test_work7_state_guard tests.scripts.test_work7_claim_contract tests.scripts.test_work7_integration_runner tests.scripts.test_work7_response_candidate tests.scripts.test_work7_review_packet
OK
```

## Self-review and concerns

The tests exercise real subprocess CLIs, temporary Git Paper/threshold
worktrees, generated Phase 0–3 chains, raw review text, and independently
computed SHA-256 values.  No DBLP-ACM/Enron workload or repeated benchmark was
run; Paper and threshold were not written.  No CTest registry change was made.

Concern: the historical terminal verifier had an append-only ordering bug; the
authorized compatibility change is intentionally narrow and covered by its
terminal CLI regression.  Task 6 remains unstarted.

## Fix round 1/5 — exact manifests and Phase 4 gate

### RED

```text
python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_work_rejects_missing_extra_or_recanonicalized_manifest_members
FAIL (3 failures)
missing: close-work returned 0
extra: close-work returned 0
reordered: close-work returned 0
```

The mutation creates canonical JSON and valid member hashes, proving the old
validator only checked self-consistency rather than the specified manifest.

### GREEN

`validate_packet` now requires the exact ordered phase-specific member-path
set: Work includes every specified design/plan/claim/diff/report/seal/candidate
and external snapshot; final cumulatively includes those, the original design,
Phase 4 packet/raw/seal, and exactly the two generated members.  `prepare-final`
now snapshots the full inherited Work input set rather than a partial subset.

`prepare-final` and `close-final` independently validate the exact sealed
Phase 4 root, predecessor, two-entry artifact set, exact Work manifest, and
the sealed Sol-high work approval.  The baseline argument is now exactly
`b907fae`.  The dead external-member branch was removed.  Phase 5 is verified
after creation with its exact predecessor/kind/root and its pointer is compared
to a freshly recomputed seal digest before success output.

The source/test map now invokes the immutable lifecycle contract loader and
the frozen CTest inventory parser before deriving its first six rows.

```text
python3 -m unittest -q tests.scripts.test_work7_review_packet tests.scripts.test_work7_claim_contract
Ran 17 tests in 23.625s
OK

git diff --check
```

## Fix round 2/5 — manifest label identity

### RED

```text
python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_work_rejects_missing_extra_or_recanonicalized_manifest_members
FAIL (label mutation): close-work returned 0
```

The mutation altered only the canonical member label; its path, byte length,
and digest were unchanged.

### GREEN

Packets now require the exact sorted phase-specific `(label, path)` manifest,
including frozen provider-neutral labels.  The focused real CLI test now
rejects missing, extra, reordered, and label-only canonical manifests.

```text
python3 -m unittest -q tests.scripts.test_work7_review_packet
Ran 4 tests in 23.741s
OK
```

## Fix round 3/5 — transfer blocker

The label-only manifest RED was reproduced and corrected before this round.
The remaining requested change is not a local parser hardening: it requires
replacing the Task 5 minimal synthetic Phase 2 fixture with a complete,
seal-consistent execution-artifact graph accepted by the production Phase 2
validators.  Those validators bind fresh-build binaries, release provenance,
machine metadata, complete pre-threshold manifests/cells/logs, real-data
metadata, and deletion outputs.  Constructing it safely requires a dedicated
fixture builder or a preexisting sealed Phase 2 runtime artifact set; neither
is within the current Task 5 fixture and producing it ad hoc risks fabricating
execution evidence that this task is expressly required to reject.

No Task 6 run was started and no further source changes were made in this
round.  Transfer the remaining execution-derived summary, stable-private-copy
closure, and full hostile evidence matrix to the fresh implementer requested
by the review.

## Fix round 4/5 — verified runtime summaries and stable terminal bytes

### RED

```text
python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_close_binds_two_distinct_final_approvals_and_terminal_seal
FAIL: toy_argv_sha256 contained only runtime_seal
```

The initial final-packet regression expected four canonical exact-argv digests
(`ctest_focused`, `pre_threshold`, `real_datasets`, and `deletion_survival`).
The previous summary reported a runtime-seal digest instead, proving it could
state pass/skip/count conclusions without validating the sealed producer
runtime.

### GREEN / hardening

`prepare-final` now validates the current Phase 0 source snapshot and exact
commit, both Phase 2 seals and the exact closure manifest, CTest inventory and
focused result (the whole frozen registry, one pass each, zero failure/skip/Not
Run), exact runner command records and frozen argv, pre-threshold/real/deletion
outputs, measured-count policy, static/evidence-bound reports, and the sealed
evidence index.  It derives each argv digest from canonical JSON bytes.  These
checks run before Phase 5 members or the output packet are created.

The review parser now reads packet and raw-review bytes through
`_stable_regular_file` once, parses those bytes, and seals those same bytes.
Final review identities are provider-neutral at the CLI boundary (the two
accepted identities may be supplied in either order, but duplicates fail).
`close-final` calls the terminal verifier with private immutable input copies,
validates the canonical terminal report before creating Phase 5 artifacts, and
only seals the original stable bytes.  The external worktree check remains
both before and after terminal verification.

The focused review suite uses the existing executable fake-tool harness with a
temporary local clone of the tracked source history (preserving `b907fae`) and
fake external build/probe tools.  It produces a full production-validator
accepted Phase 2 graph before generating Phase 3.  Review templates under
`tests/fixtures/work7/reviews/` are synthetic input templates only; they are
not authoritative evidence.

Added behavioral tables cover Work and final header/identity/check mutations,
duplicate provider and reverse-order identities, exact packet/Phase 4 seal
membership, self-consistently resealed hostile argv/CTest/count evidence,
private-byte replacement injection, malformed terminal report, and external
drift after terminal verification.  Every failure case asserts no Phase 5 seal
or pointer (and hostile Phase 2 cases assert no final members/output).

Focused GREEN batches:

```text
python3 -m unittest -q \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_work_rejects_header_only_approval_then_seals_raw_review \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_work_rejects_missing_extra_or_recanonicalized_manifest_members \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_work_review_rejects_every_header_identity_and_check_mutation
Ran 3 tests in 27.240s
OK

python3 -m unittest -q \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_close_binds_two_distinct_final_approvals_and_terminal_seal \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_review_matrix_rejects_header_identity_checks_and_duplicate_provider
Ran 2 tests in 23.809s
OK

python3 -m unittest -q \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_resealed_hostile_focused_ctest_output \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_resealed_hostile_producer_count
Ran 2 tests in 25.537s
OK
```

## Fix round 5/5 — verified chain snapshots and complete failure matrix

### RED

The following direct regressions exercised the real `prepare-final` boundary
with a complete production-validator-accepted Phase 2 graph:

```text
python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_revalidates_phase4_after_runtime_validation
FAIL: AssertionError: Failure not raised

python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_phase4_replacement_during_member_snapshot
FAIL: AssertionError: Failure not raised

python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_work_rejects_packet_seal_member_that_disagrees_with_prerequisite_digest
FAIL: 0 != 2

python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_seals_validated_phase4_bytes_despite_transient_replacement
FAIL: copied Phase 4 seal bytes contained the injected foreign member
```

The first two failures showed separate replacement windows: a self-consistent
Phase 4 reseal after the initial gate, and a reseal while members were being
copied.  The third proved that a packet could self-consistently hash a copied
seal which differed from the prerequisite digest it claimed.  The fourth
proved a path could be replaced for the snapshot and restored before a late
digest check, leaving the final packet with bytes that had never been
validated.

### GREEN

`prepare-final` now runs the production Phase 2 validator before it validates
and captures the Phase 4 gate.  `validate_phase4` stable-reads the Phase 4
seal, confirms the verified tree corresponds to those exact bytes, then
stable-reads the approved Work packet and raw review.  Final preparation
copies all three captured byte strings rather than reopening them.  A final
digest bracket rechecks source and external snapshots, every prerequisite seal
digest, the Phase 0–3 tree chain, and the Phase 4 artifact tree before the
final packet is created.

Packet validation now cross-links every copied session seal member to its
named prerequisite digest; a packet cannot show a different Phase 0–4 seal
snapshot than the chain it asserts.  The final-summary test independently
canonicalizes each frozen CTest, pre-threshold, real-data, and deletion argv
and compares its SHA-256 to the generated summary rather than only checking
that a hexadecimal value exists.

The Work and final matrices now mutate every required substantive check in
both missing and duplicate forms, in addition to all header/identity fields,
duplicate provider, reversed final identities, manifest and Phase 4 seal
mutations, hostile resealed runtime argv/CTest/count evidence, malformed and
missing terminal reports, and external drift both before and after terminal
verification.  All terminal failure cases assert that neither a Phase 5 seal
nor its pointer exists.  Fixtures under `tests/fixtures/work7/reviews/` are
review-shaped templates containing the full required identities and
confirmations.

Focused GREEN evidence:

```text
python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_revalidates_phase4_after_runtime_validation
OK

python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_rejects_phase4_replacement_during_member_snapshot
OK

python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_work_rejects_packet_seal_member_that_disagrees_with_prerequisite_digest
OK

python3 -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_prepare_final_seals_validated_phase4_bytes_despite_transient_replacement
OK

python3 -W ignore::ResourceWarning -m unittest -v tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_close_binds_two_distinct_final_approvals_and_terminal_seal
Ran 1 test
OK
```

The focused Task 5 plus claim-contract run and one complete five-suite Work 7
run completed successfully after these changes:

```text
python3 -W ignore::ResourceWarning -m unittest -q \
  tests.scripts.test_work7_review_packet tests.scripts.test_work7_claim_contract

python3 -W ignore::ResourceWarning -m unittest -q \
  tests.scripts.test_work7_state_guard tests.scripts.test_work7_claim_contract \
  tests.scripts.test_work7_integration_runner tests.scripts.test_work7_response_candidate \
  tests.scripts.test_work7_review_packet
```

`ResourceWarning` suppression applies only to pre-existing unclosed handles
inside the fake integration-runner fixture; production integration-runner
behavior was not changed.  `py_compile` and `git diff --check` also completed
successfully.  Task 6 remains unstarted.

### Final generated-member closure supplement

#### RED

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_rejects_recanonicalized_generated_summary
FAIL: AssertionError: 0 != 2
```

The test rewrote only the canonical generated final summary, updated its
packet member length and digest, regenerated both raw approvals for that new
packet digest, and invoked `close-final`.  The prior implementation accepted
this self-consistent forgery because it verified packet/member consistency but
did not independently re-derive the generated bytes from the sealed Phase 2
execution before terminal closure.

#### GREEN

`final_generated_member_bytes` now derives the exact source/test map and
final-verification summary from a fresh `validate_phase2_runtime` result, the
immutable claims contract, frozen CTest inventory, and unchanged external
snapshots.  `prepare-final` writes those exact derived byte strings.
`close-final` repeats the Phase 2 validation and derivation, then requires
both the final packet member metadata and current generated member bytes to
equal the re-derived canonical values before it parses approvals or invokes
the terminal verifier.  Thus a self-consistent packet/review rewrite cannot
turn a generated assertion into a terminal artifact.

The revalidation makes the runtime check intentionally long, so final closure
now also brackets its terminal invocation with the exact captured Phase 0–4
seal map, Phase 0 source/Paper/threshold snapshots, full Phase 0–3 chain, and
exact Phase 4 tree validation.  It uses the captured Phase 4 digest as the
terminal seal predecessor after the post-verifier bracket rather than
reopening that path.

#### Chain-race RED/GREEN

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_revalidates_phase4_after_runtime_validation
FAIL: AssertionError: Failure not raised

python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_revalidates_phase4_after_runtime_validation
Ran 1 test in 10.078s
OK
```

The RED resealed a Phase 4 artifact root with a foreign member immediately
after fresh runtime validation.  The old close path accepted it and produced
a terminal seal.  The GREEN now fails before terminal-report creation and
asserts no terminal artifacts, seal, or pointer.

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_rejects_recanonicalized_generated_summary
Ran 1 test in 9.785s
OK

python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_rejects_recanonicalized_generated_source_test_map
Ran 1 test in 10.541s
OK

python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_close_binds_two_distinct_final_approvals_and_terminal_seal
Ran 1 test in 10.318s
OK

python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_close_binds_two_distinct_final_approvals_and_terminal_seal
Ran 1 test in 10.787s
OK

python3 -m py_compile scripts/work7_review_packet.py scripts/verify_work7_claims.py
git diff --check
```

The earlier focused Task 5/claim and complete five-suite Work 7 runs above
remain successful completed output.  They were not started again after this
supplement because duplicate broad verification was explicitly stopped; the
newly changed closure paths have their targeted GREEN evidence above.

### R4 gate import-identity remediation

#### RED

An authoritative ordered five-suite gate failed two captured-byte tests after
the claim-contract suite had inserted `scripts/` at the front of `sys.path`:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_claim_contract \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_final_scope_audit_accepts_only_toy_count_one_and_deferred_status
ERROR: scripts.verify_work7_claims.Failure: invalid captured final packet
```

The preceding suite had loaded `work7_evidence` as a top-level module.  A
later package import then let `scripts.verify_work7_claims` resolve that alias
first, while package-owned captures retained `scripts.work7_evidence`.
Python consequently created two distinct `CapturedBlob` classes, so the
fail-closed `isinstance` check rejected a valid frozen capture.  A new
process-isolated behavioral regression reproduces this import ordering; it
failed before the production change without inspecting source text.

#### GREEN

Both Work 7 terminal modules now select their collaborators from
`scripts.*` whenever package-imported and select top-level sibling modules
only when executed directly as CLI scripts.  The same deterministic rule
covers late/cyclic imports for `Phase04Capture`, terminal input construction,
the terminal core, and runtime validators.  Structural capture validation was
not weakened.

Focused ordered regression (the terminal-core case also executes the
standalone verifier CLI):

```text
python3 -W ignore::ResourceWarning -m unittest -q \
  tests.scripts.test_work7_claim_contract \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_final_scope_audit_accepts_only_toy_count_one_and_deferred_status \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_terminal_core_matches_cli_report_from_identical_captured_bytes \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_package_imports_keep_captured_blob_identity_after_legacy_alias
Ran 16 tests
OK
```

The complete five-suite gate was deliberately not restarted here; it is left
to the controller after this focused repair.
