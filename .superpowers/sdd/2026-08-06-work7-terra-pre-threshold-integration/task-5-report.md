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
