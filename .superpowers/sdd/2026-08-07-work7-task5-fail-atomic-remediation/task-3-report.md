# Task 3 / R2 report

## Interface and provenance boundary

`verify_work7_claims.TerminalInputs` contains only the immutable R1
`Phase04Capture`, `CapturedBlob` values for the final packet and every packet
member, and the two review blobs.  `terminal_report_bytes(inputs) -> bytes`
accepts no path or parsed caller object and creates no output.  It validates
the Phase 0--4 chain/manifests, captured runtime evidence, claim 7, the Work
packet/review, final packet and every supplied member, both final review
identities, and the regenerated summary/map bytes before returning canonical
terminal-report bytes.

The standalone terminal CLI stable-captures its canonical session inputs once,
then atomically creates `--output` only after this core succeeds.  `close-final`
keeps its required `--source-root` CLI input, captures the R1 graph plus final
packet/reviews once, and imports the currently approved source module's core
directly.  It no longer runs the sealed-session verifier as a subprocess and
does not pass or reopen Phase 3/4 paths after capture.  Byte-identical core/CLI
coverage is the approved replacement for the old subprocess provenance.

## TDD evidence

RED command before the core existed:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_terminal_core_matches_cli_report_from_identical_captured_bytes \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_revalidates_packet_members_before_publication
```

Observed: `ImportError: cannot import name 'TerminalInputs' from
'scripts.verify_work7_claims'`; the member-revalidation test was already
green.  The result was `Ran 2 tests in 17.279s`, `FAILED (errors=1)`.

Focused GREEN observations after implementation:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_terminal_core_matches_cli_report_from_identical_captured_bytes
```

Observed: `ok`; `Ran 1 test in 10.422s`; `OK`.

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_claim_contract.Work7ClaimContractTests.test_terminal_accepts_only_exact_dual_reviews_and_immutable_external_state
```

Observed: `ok`; `Ran 1 test in 11.568s`; `OK`.

The focused close-final collection also observed `ok` for the no-reopen,
transient captured-input, stable packet/review capture, malformed-core-input,
pre-capture external drift, captured external snapshot, generated-summary, and
generated-source-map cases.  The controller intentionally stopped overlapping
aggregate processes before a final aggregate status was emitted; the
post-commit Task 3 gate is therefore the authoritative full-suite result.

Static checks before commit:

```text
python3 -m py_compile scripts/verify_work7_claims.py scripts/work7_review_packet.py \
  tests/scripts/test_work7_claim_contract.py tests/scripts/test_work7_review_packet.py
git diff --check
```

Observed: both exited successfully.

## Review fix round 1

The review's three Important findings are mapped as follows:

* The terminal core now requires `Phase04Capture.phase4_packet` and
  `phase4_review` to byte-equal the two Phase 4 seal members.  It validates the
  complete, ordered Work packet manifest against the captured Phase 0--4
  sources before accepting the Work approval.
* The standalone terminal wrapper requires `--contract` and
  `--ctest-inventory` to be the fixed captured source/session inputs and to
  byte-equal their R1 capture.  Foreign copies of otherwise identical files
  fail before output creation.
* Final reviews are captured first, parsed by identity, de-duplicated, and
  normalized to the `TerminalInputs` Claude/sol slots.  Thus either CLI
  argument order works while duplicate identities still fail.

The review RED command initially exposed the ignored contract/inventory inputs
(the terminal CLI test returned `0` for a foreign identical contract) and the
legacy argument-order handling.  The minimal Work-packet hostile fixture was
then completed to replace both the packet and review final-member bytes, so it
could reach the intended Phase 4 ownership check.

GREEN command:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_terminal_core_rejects_self_consistent_unsealed_minimal_work_packet \
  tests.scripts.test_work7_claim_contract.Work7ClaimContractTests.test_terminal_accepts_only_exact_dual_reviews_and_immutable_external_state \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_review_matrix_rejects_header_identity_checks_and_duplicate_provider \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_terminal_core_matches_cli_report_from_identical_captured_bytes \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_rejects_recanonicalized_generated_summary \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_close_final_rejects_recanonicalized_generated_source_test_map
```

Observed individual/serial results: minimal Work-packet hostile fixture `ok`;
contract/inventory binding fixture `ok`; final-review matrix `ok` (`Ran 1 test
in 21.173s`); standalone CLI/core equivalence plus both generated-forgery tests
all `ok` (`Ran 3 tests in 26.259s`).  No actual-data or performance command was
run.

## Review fix round 2

The standalone wrapper now uses the same byte-only
`normalize_final_review_blobs` helper as `close-final`.  It stable-captures
both raw reviews, validates exact identity/checks against the captured final
packet digest, rejects a duplicate provider identity, and only then assigns
canonical Claude and sol slots to `TerminalInputs`.

RED:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_claim_contract.Work7ClaimContractTests.test_terminal_accepts_only_exact_dual_reviews_and_immutable_external_state
```

Observed: reversed exact standalone reviews returned exit `2` with `review
identity, verdict, commit, packet, or status is invalid`; `Ran 1 test in
11.329s`; `FAILED (failures=1)`.

GREEN:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_claim_contract.Work7ClaimContractTests.test_terminal_accepts_only_exact_dual_reviews_and_immutable_external_state \
  tests.scripts.test_work7_review_packet.Work7ReviewPacketTests.test_final_review_matrix_rejects_header_identity_checks_and_duplicate_provider
```

Observed standalone reversed-order PASS and duplicate-identity FAIL behavior
green; the close-final final-review matrix was also green (`Ran 1 test in
23.837s`).
