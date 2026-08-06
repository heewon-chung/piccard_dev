# Work 7 Pre-threshold PoC Integration Design

**Date:** 2026-08-06

**Branch:** `tkde-major/pre-threshold-poc`

**Implementation baseline:** `b907fae`

**Design status:** approved

**Plan model:** `gpt-5.6-sol` xhigh

**Implementation model:** `gpt-5.6-terra`

**Work-level reviewer:** `gpt-5.6-sol` high

**Final reviewers:** Claude Fable high and `gpt-5.6-sol` high

## 1. Decision

Work 7 is a contract-based integration gate for the implementation produced by
Works 1–6. It verifies that the seven goals frozen in
`2026-07-29-pre-threshold-poc-design.md` are represented by code, tests, and
reproducible toy evidence without making paper-grade performance claims.

This document adapts the original Work 7 plan to the current PoC review scope.
It does not erase the original plan. The expensive actual-dataset and repeated
performance runs in that plan are deliberately deferred until all
implementation work is complete.

The only successful terminal status in this Work 7 run is:

```text
POC_APPROVED_PERFORMANCE_PENDING
```

That status means the implementation and one-run toy integration path are
approved. It also records structural readiness for a later threshold branch:
the seven pre-threshold units compose and the remaining blocker is the
separately scheduled performance campaign. It does not mean that paper
numbers are approved, that real-data results have been produced, or that
creating, modifying, or merging threshold FP/FN work is authorized. This is
the user-approved PoC scope amendment to the original goal's stronger
operational branch-readiness wording.

## 2. Scope

Work 7 shall add:

1. a machine-readable claim matrix covering all seven pre-threshold goals;
2. a verifier that fails closed when a required claim lacks implementation,
   test, or evidence references;
3. a fresh-build toy integration runner whose benchmark-like invocations use
   exactly one trial/repetition;
4. immutable, commit-scoped evidence with command and artifact provenance;
5. a read-only generator for a candidate `ResponseStrategy.md` copy and diff;
6. a Work 7 `gpt-5.6-sol` high review gate; and
7. a whole-pre-threshold dual review gate requiring independent approval from
   Claude Fable high and `gpt-5.6-sol` high.

## 3. Non-goals

- Do not run or claim actual DBLP-ACM or Enron performance results.
- Do not run repeated timing, calibration, estimator-bias, or Monte Carlo
  campaigns. Every benchmark-like command used by this gate is one run with a
  toy-sized input.
- Do not edit any file in the Paper repository.
- Do not edit, merge, rebase, or authorize the threshold FP/FN worktree.
- Do not reconstruct missing historical review records or present user
  approvals as model-generated approvals.
- Do not convert a toy result into a manuscript number.
- Do not broaden Work 7 into production hardening or exhaustive edge-case
  coverage.

## 4. Frozen state axes

State values are field-specific. A value is invalid outside its declared
field; no free-form synonym is accepted.

| Field | Allowed value | Meaning |
|---|---|---|
| `implementation_state` | `IMPLEMENTED` | Required code exists and has a test reference. |
| `toy_evidence_state` | `PENDING`, `TOY_VERIFIED` | Current-session integration evidence is absent or verified. |
| `performance_state` | `PERFORMANCE_PENDING` | Actual data, repeated measurement, and paper-grade performance evidence are deferred. |
| top-level `threshold_gate_state` | `DEFERRED_EXPECTED` | Threshold FP/FN work is intentionally outside Work 7 and is not authorized. |
| top-level `work_gate_state` | `PENDING`, `POC_APPROVED_PERFORMANCE_PENDING` | Final dual-review gate has not or has passed. |

The allowed combinations are also frozen:

- static preflight, claims 1–6: `IMPLEMENTED/PENDING/PERFORMANCE_PENDING`;
- evidence-bound validation, claims 1–6:
  `IMPLEMENTED/TOY_VERIFIED/PERFORMANCE_PENDING`;
- claim 7 before final review:
  `IMPLEMENTED/TOY_VERIFIED/PERFORMANCE_PENDING` with
  `work_gate_state=PENDING`; and
- terminal validation, all claims:
  `IMPLEMENTED/TOY_VERIFIED/PERFORMANCE_PENDING` with
  `threshold_gate_state=DEFERRED_EXPECTED` and
  `work_gate_state=POC_APPROVED_PERFORMANCE_PENDING`.

The tracked matrix is an immutable lifecycle contract: it stores claim
definitions, required references, and allowed transitions, not mutable current
states. The verifier emits session-local derived state snapshots. `static`
checks code/test references and emits `PENDING` toy states; `evidence-bound`
checks claims 1–6 against the runtime-artifact seal; `claim7` runs after the
response-candidate seal; and `terminal` runs after both final raw review
responses exist. Only the terminal report may emit
`work_gate_state=POC_APPROVED_PERFORMANCE_PENDING`.

## 5. Claim contract

The matrix contains one row for each original design goal:

1. SHA-256 random-ranking estimator;
2. sanitizer profile and transcript accounting;
3. STD128/STD192 calibration and fail-closed selection;
4. matched-condition Piccard/BCG12/SJ16 comparison schema;
5. deterministic real-dataset pipeline with synthetic parser fixtures;
6. bounded-dynamic refresh and deletion-survival evidence; and
7. integration gate and manuscript-response handoff.

Each immutable lifecycle row contains:

- stable claim identifier;
- original-intent text;
- allowed `implementation_state` values;
- allowed `toy_evidence_state` transitions;
- allowed `performance_state` values;
- source paths;
- automated test names or paths;
- toy artifact paths when exercised;
- deferred-work rationale when applicable; and
- explicit prohibited overclaim text.

The contract also defines allowed transitions for the two top-level gate
states. Paths are repository-relative and must resolve. Test references must be
discoverable in the fresh Release build. Toy artifacts must belong to the
current session and appear in the seal named by the derived state snapshot.

## 6. Architecture

```text
byte-level state snapshot
      |
      v
fresh Release build -----> static claim verifier
      |                              |
      v                              v
Work 1–6 tests              contract validation
      |
      v
one-run toy probes -----> evidence-bound claim validation
      |                              |
      +--------------+---------------+
                     v
          immutable runtime-evidence seal
                     |
          +----------+-----------+
          v                      v
ResponseStrategy candidate   canonical review packet
   (outside Paper)                 |
                                 v
             POC_APPROVED_PERFORMANCE_PENDING
```

The implementation consists of six ordered phases. Phase 1 has a static pass
before Phase 2 and a mandatory evidence-bound pass after Phase 2. Claim 7 is
terminalized only in Phase 5. Except for those explicit closure checks, a later
phase may start only after the preceding phase's success criteria pass.

| Phase | Unit | Detailed design |
|---|---|---|
| 0 | State guard and session identity | `2026-08-06-work7-phase0-state-guard-design.md` |
| 1 | Claim matrix and verifier | `2026-08-06-work7-phase1-claim-contract-design.md` |
| 2 | Fresh-build toy integration runner | `2026-08-06-work7-phase2-toy-runner-design.md` |
| 3 | Read-only ResponseStrategy candidate | `2026-08-06-work7-phase3-response-candidate-design.md` |
| 4 | Work-level review | `2026-08-06-work7-phase4-work-review-design.md` |
| 5 | Whole-pre-threshold dual review | `2026-08-06-work7-phase5-dual-review-design.md` |

## 7. Evidence session

Each run creates a new session keyed by the source commit. The runner refuses
to overwrite an existing session. Within it, each phase writes a new immutable
subdirectory and a canonical phase seal. Every seal includes the preceding
seal's digest, forming this chain:

```text
phase0 state seal
  -> phase2 runtime-artifact seal
  -> phase2 closure (evidence-bound claims) seal
  -> phase3 response-candidate-artifact seal
  -> phase3 closure (claim 7) seal
  -> phase4 work-review seal
  -> phase5 dual-review terminal seal
```

No file covered by a seal may be changed. Phase 2 first seals raw runtime
artifacts, then validates claims against that immutable seal, then writes a
closure seal containing the claim report and chaining the runtime-artifact
seal. Later artifacts are appended under a new phase directory; no intermediate
manifest is final for the whole session. The terminal seal digest is the
authoritative session digest. Across its layered records, the session records:

- source commit and clean/dirty status;
- Paper repository commit and canonical byte-level snapshot digest;
- threshold worktree branch, commit, and canonical byte-level snapshot digest;
- compiler, CMake, OpenFHE, and build configuration identifiers;
- exact argv and exit status for every command;
- start/end timestamps and durations;
- per-artifact SHA-256 digests; and
- a digest for every immutable phase seal and one terminal digest.

Generated runtime evidence remains outside tracked source paths by default.
Small schemas, claim contracts, verifier fixtures, and tests are tracked.
Final model-review records may be stored under the session root and referenced
by the handoff summary.

## 8. External repository guard

The Paper and threshold worktrees are read-only inputs. Before any generated
candidate or model review, Work 7 records a canonical byte-level snapshot.
The snapshot covers HEAD, branch/detached state, index entries and blobs,
tracked worktree bytes, untracked file bytes, file modes, symlink targets, and
submodule commit/status records. Paths and lengths are framed before hashing,
so concatenation is unambiguous. After every phase that reads an external
worktree and before terminalization, Work 7 recomputes the snapshot.

Success requires identical canonical snapshot digests and the same HEAD for
both external worktrees. The Paper worktree may already be dirty; its dirty
baseline is evidence to preserve, not a failure to clean up. Evidence and
build roots must resolve outside all three guarded worktrees, and their real
paths may not alias a guarded path through a symlink.

Any Work 7 process that changes either external worktree fails the phase. The
implementation must never discard, stage, format, or otherwise normalize the
user's existing Paper changes.

## 9. Test and benchmark policy

- Build from a newly created Release build directory.
- Run the exact focused registry below plus Work 7 contract/provenance tests.
- Use synthetic fixtures for real-dataset parsers.
- Use toy parameter sizes for executable probes.
- Set every measured repeat/trial/iteration count controlling performance
  sampling to exactly `1`. One implementation-mandated discarded warmup per
  timing cell is permitted and must be recorded distinctly as `warmup`; it is
  not a measured repetition and is never summarized as evidence.
- Do not run the original plan's full actual-data or repeated-performance gate.
- Treat missing tools, stale binaries, skipped required tests, malformed rows,
  provenance mismatch, or a count greater than one as hard failures.

The fresh configure command fixes
`-DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=ON`.
Configuration must report OpenFHE, GMP, GTest, and Python 3 as available. The
required target/test registry is:

| Goal | Required CTest names |
|---|---|
| estimator | `MinHash`, `EstimatorDiagnostic`, `EstimatorProvenanceSerializers` |
| sanitizer/calibration | `SecurityProfile`, `Params`, `NoiseCalibrationCutoverProbeV2`, `NoisePreThresholdCoverage` |
| comparisons | `BenchmarkProfile`, `BaselineProfile`, `ComparisonWorkload`, `ReviewComparisonCli`, `VerifyReviewComparison`, `VerifySJ16Extrapolation` |
| real-data pipeline | `RealDataset`, `RealDatasetMetrics`, `RealDatasetTiming`, `RealDatasetPreprocess`, `RunRealDatasets` |
| dynamic/deletion | `DynamicCiphertextStore`, `DynamicRefreshE2E`, `DynamicRefreshBenchmark`, `DeletionSurvival`, `DeletionMonteCarlo`, `DeletionSurvivalCli` |
| Work 7 | `Work7StateGuard`, `Work7ClaimContract`, `Work7IntegrationRunner`, `Work7ResponseCandidate` |

The runner must fail if any registry name is missing from `ctest -N`; it runs
each selected test once with no repeat option and treats `Not Run` or `Skipped`
as failure. This curated registry is the PoC scope amendment to the original
all-unit/all-integration terminal campaign; that full campaign belongs to the
later performance pass.

The executable probe registry is also fixed:

| Probe | Command/policy | Output contract |
|---|---|---|
| estimator functional | execute `ctest --test-dir <fresh-build> --output-on-failure -R '^EstimatorDiagnostic$'` once and retain its log; never call `bench_estimator_bias` | passing test log bound to build/source provenance |
| comparison + refresh | `scripts/run_pre_threshold_profiles.sh --suite=smoke --seed=7 --threads=2 --build-dir=<fresh-build> --results-root=<session>/phase2/runtime/pre-threshold` | existing benchmark/review/dynamic schemas; every measured trials/accuracy-trials/refresh-updates field is `1`; existing discarded timing warmup allowed and recorded |
| synthetic real-data | `scripts/run_real_datasets.sh --quick --seed=7 --threads=2 --build-dir=<fresh-build> --results-root=<session>/phase2/runtime/real-datasets` | quick DBLP-ACM tracked fixture only; measured accuracy and timing trials are `1`; one recorded discarded timing warmup allowed |
| deletion survival | `<fresh-build>/bench_deletion_survival --n=64 --d=3 --k=8 --required_survival=0.99 --r_values=1,4,8 --trials=1 --seed=7` | existing 17-column CSV, three rows, `trials=1` |

All fixture inputs must resolve below `tests/fixtures/real_datasets/quick` or
`tests/fixtures/runner`. Retry count is zero. The verifier accepts only the
single discarded warmup already emitted by each timing-cell implementation;
it rejects warmups in accuracy/analytic cells or more than one warmup in any
timing cell.

## 10. Review policy

The Work 7 diff and toy evidence receive a `gpt-5.6-sol` high work-level review.
After any required fix, the full focused verification is rerun against a new
commit-scoped session.

The final whole-pre-threshold review is performed independently and
concurrently by Claude Fable high and `gpt-5.6-sol` high. A canonical review
packet manifest hashes the source commit, approved designs and plan, claim
matrix/report, every prior phase seal, candidate/diff, external snapshots,
and verification summary. Both reviewers receive the same packet digest.

Both reviewers must return a mechanically parsed record containing the
provider/model identifier, exact source commit, exact packet digest, terminal
status, and an unqualified `APPROVED` verdict. Their unedited raw outputs are
hashed into the Phase 5 seal. `APPROVED_WITH_COMMENTS`, a request for changes,
an inability to inspect evidence, a digest omission, or approval of different
commits/packets is not approval. At most two remediation cycles are allowed
before the Work 7 gate stops as failed.

## 11. Completion criteria

Work 7 is complete only when:

1. all Phase 0–5 success conditions pass;
2. all claim rows resolve to allowed states and valid references;
3. the fresh-build focused suite and every one-run toy probe pass;
4. the chained phase seals and candidate response diff are reproducible;
5. Paper and threshold byte-level snapshots are unchanged;
6. the Work 7 reviewer approves; and
7. both final reviewers approve the same commit, packet, and proposed status;
   and
8. the fail-closed terminal verifier validates both raw approvals and emits the
   terminal state before the Phase 5 terminal seal is written.

Actual-data and multi-run performance work remains visible as
`PERFORMANCE_PENDING` in both the claim matrix and the response candidate.
