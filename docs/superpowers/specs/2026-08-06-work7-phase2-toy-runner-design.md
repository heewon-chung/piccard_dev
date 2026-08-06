# Work 7 Phase 2 — Fresh-build One-run Toy Integration Runner

## Purpose

Exercise the Work 1–6 implementation as one reproducible PoC path while
avoiding actual-data and multi-run performance cost.

## Inputs

- Phase 0 state record and empty session root;
- Phase 1 claim contract;
- source checkout at the frozen commit; and
- configured compiler/OpenFHE toolchain.

## Execution order

1. Create a new Release build directory outside tracked source paths.
2. Configure and compile the required binaries and tests.
3. Enumerate the frozen registry in the overall design, fail on any missing
   name, and run each focused Work 1–6 and Work 7 test once.
4. Retain the single `EstimatorDiagnostic` execution log as the functional
   estimator probe; do not invoke the multi-trial bias benchmark.
5. Run one matched-comparison probe.
6. Run the real-dataset path against tracked synthetic fixtures only.
7. Run one bounded-dynamic refresh probe.
8. Run one deletion-survival probe.
9. Validate every output row against its schema and exact argv.
10. Run the Phase 1 `evidence-bound` verifier for claims 1–6.
11. Hash artifacts and reports and write the immutable Phase 2 runtime seal,
    chaining it to the Phase 0 seal.

## Success conditions

1. Configuration and compilation succeed from the fresh directory.
2. CMake reports Release, tests/benchmarks enabled, and OpenFHE, GMP, GTest,
   and Python 3 available; every frozen-registry test is present and passes
   once without a skip.
3. Every benchmark-like invocation uses toy input and has all controlling
   trial/repeat/iteration counts equal to `1`.
4. The estimator, comparison, synthetic-data, refresh, and deletion artifacts
   are nonempty and schema-valid.
5. Artifact metadata agrees with the recorded command line and source commit.
6. Only whitelisted synthetic fixture roots are used; warmup and retry counts
   are zero.
7. All required artifacts and the evidence-bound claim report appear once in
   the Phase 2 seal with matching SHA-256.
8. A second seal verification pass succeeds without rewriting artifacts.

## Failure conditions

- A stale or pre-existing build directory is reused.
- A required dependency, binary, or frozen-registry test is absent, skipped,
  `Not Run`, or fails.
- Any performance-sampling count is absent when required, zero, or greater than
  one.
- The runner invokes actual DBLP-ACM or Enron input.
- A row/argv/profile/provenance mismatch occurs.
- An artifact is empty, malformed, duplicated, unhashed, outside the session,
  or changed after the Phase 2 seal.
- The runner executes the original heavyweight full-suite campaign.

## Prohibited behavior

- No actual-data download or acquisition.
- No timing aggregation advertised as performance evidence.
- No retry-until-pass loop.
- No in-place reuse of Work 1–6 evidence as the Work 7 session.

## Verification

Tests inspect the frozen registry and command construction before execution,
enforce count `1`, zero warmups/retries, reject actual-data paths, exercise
missing-test and manifest-tampering failures, and verify the Phase 0-to-Phase 2
digest link. The authoritative smoke run executes each probe exactly once.
Timing values may be recorded as diagnostics but are not compared to
performance thresholds.
