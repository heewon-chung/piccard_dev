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
