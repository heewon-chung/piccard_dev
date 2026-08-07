### Task 5/R4 focused scope-audit evidence

The focused audit is intentionally limited by the user-approved PoC override:
one hermetic fake-tool session and representative byte-level mutations, rather
than an adversarial path/symlink/race campaign.

RED evidence (before the test was added):

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_final_scope_audit_accepts_only_toy_count_one_and_deferred_status
AttributeError: type object 'Work7IntegrationRunnerTests' has no attribute
'test_final_scope_audit_accepts_only_toy_count_one_and_deferred_status'
```

GREEN evidence:

```text
python3 -W ignore::ResourceWarning -m unittest -v \
  tests.scripts.test_work7_integration_runner.Work7IntegrationRunnerTests.test_final_scope_audit_accepts_only_toy_count_one_and_deferred_status
Ran 1 test in 9.569s
OK
```

The accepted captured-byte graph asserts smoke pre-threshold, the tracked
`tests/fixtures/real_datasets/quick/dblp_acm_u65536` fixture under the cloned
source snapshot, quick evidence mode, deletion `--trials=1`, every relevant
`trials`/`accuracy_trials`/`refresh_updates` value equal to one, and terminal
`POC_APPROVED_PERFORMANCE_PENDING`. It is validated through the existing R1
captured runtime and terminal validators.

The same test rejects exactly these representative mutations: a measured CSV
count changed to two; an explicitly labelled external-actual-data authoritative
root outside the tracked fixture; and a final review status changed to the
premature `POC_APPROVED`. No DBLP/Enron actual-data execution, repeated
measurement/performance campaign, external-worktree mutation, or broad suite
run was performed by this focused audit.

Deferred by the override: exhaustive external-path, symlink, and race variants;
the controller retains the single authoritative all-five-suite R4 gate.

### Authoritative R4 result

The first complete ordered gate was invalidated after 110 tests/742.089s by a
Python module-alias identity failure.  Commit `3a336b1` made package and CLI
imports deterministic, and the ordered focused regression passed 16/16 in
46.881s.  The controller then restarted the complete gate from its first suite:

```text
Ran 111 tests in 749.006s
OK
```

Static checks were clean.  Paper and threshold snapshot digests were identical
before and after the retry.  No actual-data run, repeated performance run, or
unusual edge-case campaign was performed.  On any authoritative failure, the
runbook is to record the external diagnostic, delete the exact build/session
pair completely, remediate, clear the diagnostic, and restart at Phase 0.
