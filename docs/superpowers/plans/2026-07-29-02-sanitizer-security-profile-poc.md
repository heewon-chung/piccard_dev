# Work 2 — Transcript-Aware Phase-Smudging Sanitizer PoC

> **Implementation owner:** Claude Opus 5  
> **Plan reviewer:** Claude Fable 5  
> **Work completion reviewers:** GPT-5.6-sol and Claude Fable 5  
> **Dependency:** Work 1 approved  
> **Next work:** STD128/STD192 calibration

## Objective

Turn the existing `lambda_stat` coefficient-level setting into an explicit
transcript profile. Size the empirical phase-smudging mask for the query count
and realized ring dimension, keep calibration margin separate, preserve
`Enc(0)` re-randomization, and label the resulting guarantee as a PoC rather
than full-ciphertext statistical freshness.

## Dependency gate

```bash
WORK1_HEAD="$(python3 scripts/verify_work_approval.py --work-id=1 \
  --expected-base="$PLANNING_COMMIT" \
  --plan-path=docs/superpowers/plans/2026-07-29-01-estimator-random-ranking-poc.md \
  --gpt="$REVIEW_STAGING_ROOT/work-1-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-1-fable.md" --print-head)"
test "$(git rev-parse HEAD)" = "$WORK1_HEAD"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

## Inputs and outputs

### Inputs

- `transcript_stat_bits: uint32_t`, supported experiment values `40`, `64`,
  and `128`, always positive.
- `max_queries: uint64_t`, `1..2^63`; revision profile uses `2^20`.
- `flood_margin_bits: uint32_t`, empirical safety margin; default `8`.
- calibration row containing realized `ring_dim`, `eval_noise_bits`, and
  `log2(q/t)`.

### Derived outputs

For selected row `N`:

```text
query_adjustment_bits = ceil(log2(max_queries))
coefficient_adjustment_bits = ceil(log2(N))
query_stat_bits = transcript_stat_bits + query_adjustment_bits
coefficient_stat_bits = query_stat_bits + coefficient_adjustment_bits
flood_noise_bits = eval_noise_bits + coefficient_stat_bits + flood_margin_bits
```

All additions are overflow-checked. Parameter/benchmark metadata:

```text
sanitizer_model=phase-smudging-enc0-poc-v1
sanitizer_assurance=empirical-phase-statistical+ciphertext-computational
transcript_stat_bits,max_queries,query_stat_bits,
coefficient_stat_bits,flood_margin_bits,eval_noise_bits,flood_noise_bits
```

## Phase 1 — Implement a pure, overflow-safe security-profile derivation

### Files

- Add: `include/util/security_profile.h`
- Add: `src/util/security_profile.cpp`
- Add: `tests/unit/test_security_profile.cpp`
- Modify: `CMakeLists.txt`

### RED tests

Test exact derivations:

| transcript | Q | N | query bits | coefficient bits |
|---:|---:|---:|---:|---:|
| 40 | 1 | 8192 | 40 | 53 |
| 40 | 2^20 | 8192 | 60 | 73 |
| 64 | 2^20 | 16384 | 84 | 98 |
| 128 | 2^20 | 32768 | 148 | 163 |

Also test `Q=3 -> ceil(log2 Q)=2`, non-power-of-two `N`, zero inputs,
and exact boundaries:

- pure `CeilLog2` accepts every positive integer (`3 -> 2`);
- production profile derivation accepts non-power-of-two `Q` but requires BFV
  `N` to be a positive power of two;
- `Q=2^63` is accepted with adjustment 63 and `Q=2^63+1` is rejected;
- transcript `41` is rejected rather than rounded/clamped;
- the checked-add helper throws independently on query-bit,
  coefficient-bit, and final flood-bit overflow near `UINT32_MAX`.

Run:

```bash
cmake --build build -j4 --target test_security_profile
./build/test_security_profile
```

Expected RED output: target/API absent.

### GREEN implementation

Implement a pure value type, for example `SanitizerProfile`, and one
`CeilLog2` helper with documented behavior. It must not depend on OpenFHE or a
calibration table.

### Pass conditions

- Every table value above matches exactly.
- Invalid/overflowing input throws `std::invalid_argument` or
  `std::overflow_error`.
- Core profile code has no floating-point logarithm.

## Phase 2 — Integrate the profile into fail-closed parameter selection

### Files

- Modify: `include/util/params.h`
- Modify: `src/util/params.cpp`
- Modify: `tests/unit/test_params.cpp`
- Modify: `include/util/params_calibration.h`, preserving
  `CalibrationAccess::Derive/DeriveSqrt`.
- Add: `src/util/params_calibration.cpp`
- Modify: `CMakeLists.txt`

### RED tests

Require:

1. default parameters explicitly resolve to transcript 40 and `Q=2^20`;
2. selected `query_stat_bits` and `coefficient_stat_bits` match the selected
   row's realized `N`;
3. `FloodNoiseBits()` uses
   `eval + coefficient + margin`, exactly once per term;
4. a row that fits the old coefficient-level formula but not the new
   transcript formula is rejected;
5. missing calibration remains a hard failure;
6. derive-only calibration access leaves flooding unsized;
7. 40, 64, and 128 remain distinct inputs and are never silently clamped;
8. after successful validation, independently mutating any public
   `eval_noise_bits`, `flood_margin_bits`, `transcript_stat_bits`,
   `max_queries`, or requested `ring_dim`
   makes `FloodNoiseBits()` throw `std::logic_error` instead of using stale
   derived values;
9. a test-only injected row with requested `N=8192` and realized
   `N=16384` yields coefficient bits 74 for `(t=40,Q=2^20)`, not the nominal-N
   value 73, and a mismatched runtime `N=8192` is rejected.

The concrete seam is the pure
`SelectSanitizerCandidate(profile, CalibrationCandidate)` function in
`params_calibration.h`. `CalibrationCandidate` carries requested, natural,
and calibrated/realized `N`, evaluation bound, and modulus capacity.
Production table rows are adapted through the same function; until Work 3
emits explicit grown rows, the legacy adapter sets calibrated `N` equal to
natural `N`. Tests inject the grown row directly—no test-only branch is added
to `PiccardParams`. Private derived/calibrated fields have compile-time
const-getter/no-mutator API checks; runtime mismatch is exercised through the
candidate selector plus BFV runtime-validation seam, not a mutation hook.

Run:

```bash
cmake --build build -j4 --target test_params
./build/test_params
```

Expected RED output: old `lambda_stat` behavior produces incorrect derived
values or accepts an under-sized row.

### GREEN implementation

- Replace ambiguous non-threshold `lambda_stat` with
  `transcript_stat_bits`. Threshold selection remains on a pinned private
  legacy coefficient target of 64 bits until the separate threshold branch;
  this compatibility path is not exposed as a transcript claim.
- Add `max_queries` and derived fields to `PiccardParams`.
- During calibration-row selection, derive the profile using that row's
  realized ring dimension.
- Store an immutable validation fingerprint of every source/derived field and
  verify it on every `FloodNoiseBits()` call; any later mutation invalidates
  the sized state.
- Make `query_stat_bits`, `coefficient_stat_bits`, `flood_noise_bits`, and
  selected calibrated `N` private with const getters. Before OpenFHE context
  creation, capture requested `N` in a separate immutable private field exposed
  by `RequestedRingDim()`; never overwrite that field with runtime `N`.
  Preserve the existing public `ring_dim` as the legacy/runtime value needed
  by encoders, rotations, benchmark rows, and threshold compatibility.
  `AdoptVerifiedRuntimeRingDim(runtime_n)` is the only trusted adoption API:
  it first verifies the pre-context source fingerprint, requires
  `runtime_n == SelectedCalibratedRingDim()`, updates only the runtime
  `ring_dim`, and atomically replaces the fingerprint with a post-context
  fingerprint containing both requested and runtime values. Calling it twice,
  calling it before selection, or passing a mismatch throws. Direct public
  mutation after adoption invalidates `FloodNoiseBits()`.
- Rewrite errors to name transcript target, query cap, coefficient adjustment,
  margin, capacity, and exact calibration key.
- Do not provide an automatic weaker fallback.

### Pass conditions

- Focused tests pass.
- A search limited to Phase-2 files
  (`include/util/params.h`, `src/util/params.cpp`, `tests/unit/test_params.cpp`)
  finds no ambiguous public `lambda_stat` field. The repository-wide stale
  semantics gate runs only after Phase 4.
- An infeasible 128-bit profile fails with a diagnostic that distinguishes
  infeasibility from missing calibration.

## Phase 3 — Align runtime flooding and realized-context checks

### Files

- Modify: `include/fhe/bfv_context.h`
- Modify: `src/fhe/bfv_context.cpp`
- Modify: `tests/unit/test_bfv_context.cpp`
- Modify: `src/protocol/piccard.cpp`
- Modify: `src/protocol/sqrt_piccard.cpp`
- Modify: `tests/unit/test_piccard_engine.cpp`
- Modify: `tests/unit/test_sqrt_piccard.cpp`
- Modify: `tests/unit/test_benchmark_utils.cpp`
- Modify: `benchmarks/baseline_engine.h` and its tests so its common
  unsized parameter copy uses `BaselineParams::AdoptRuntimeRingDim()`, never
  the sanitizer adoption API.
- Add: `tests/fixtures/noise_calibration_grown_rows.inc`
- Add: a dedicated CMake test target that compiles Piccard/sqrt engine tests
  with `PICCARD_NOISE_CALIBRATION_FILE` pointing at that fixture.
  Concretely, object-library target `piccard_params_grown_fixture` recompiles
  the production `src/util/params.cpp` translation unit with that definition;
  executable `test_piccard_grown_ring` links this object variant (and never the
  normal params object) with the production Piccard/sqrt engine sources.

### RED tests

Add/adjust tests for:

- plaintext preservation after flooding;
- repeated flooding of the same raw ciphertext yields different serialized
  ciphertexts;
- `Flood()` rejects unsized parameters;
- the sampled coefficient bound uses the derived `flood_noise_bits`;
- realized `N` mismatch invalidates the profile;
- runtime budget check is
  `eval + coefficient + margin + 2 <= log2(q/t)`;
- sanitizer model/assurance accessors return the exact fixed labels.
- all live Piccard/sqrt runtime-overwrite sites call
  `AdoptVerifiedRuntimeRingDim()` rather than assigning `ring_dim`;
- the FHE-IND/Baseline unsized copy calls only
  `BaselineParams::AdoptRuntimeRingDim()` and never
  `PiccardParams::AdoptVerifiedRuntimeRingDim()`;
- requested 8192 / selected+runtime 16384 keeps
  `RequestedRingDim()==8192`, reports legacy/actual `ring_dim==16384`, sizes
  encoding/rotation for 16384, and keeps `FloodNoiseBits()` valid;
- a direct post-adoption mutation to 8192 makes the engine parameter
  fingerprint fail closed;
- Piccard, sqrt, and `BaselineEngine` report the actual
  runtime N, while the threshold compatibility test keeps its current actual-N
  CSV semantics without changing threshold algorithms/schema.

Run:

```bash
cmake --build build -j4 --target \
  test_bfv_context test_piccard_engine test_sqrt_piccard \
  test_benchmark_utils test_piccard_grown_ring
./build/test_bfv_context \
  --gtest_filter='BFVContextTest.*Flood*:BFVContextBudget.*'
./build/test_piccard_engine
./build/test_sqrt_piccard
./build/test_benchmark_utils
./build/test_piccard_grown_ring
```

Expected RED output: accounting/metadata assertions fail under the old formula.

### GREEN implementation

Keep the cryptographic construction structurally unchanged:

1. add a fresh encryption of zero;
2. add independently sampled, centered wide noise to `c0`; and
3. return only at the protocol exit.

Rewrite public comments so they never claim full-ciphertext statistical
freshness. The exact two-part assurance is phase statistical under empirical
calibration plus computational ciphertext re-randomization.
Replace the live sanitized `params_.ring_dim = actual` assignments in Piccard
and sqrt with the verified adoption API. The currently unlinked/dead
`src/protocol/piccard_engine.cpp` is explicitly outside Work 2 and no test or
claim is attributed to it.
`BFVContext` performs the same adoption on its private parameter copy before
key generation and exposes the already-validated runtime N. Protocol copies
adopt that identical N before constructing encoders or rotation plans.

FHE-IND/Baseline is explicitly sanitizer-independent. `BFVContext` stores a
separate always-valid `runtime_ring_dim_` for context operations and exposes
it through `GetSlotCount()`; only a parameter set whose sanitizer is sized
calls the sanitizer adoption/fingerprint path. An unsized baseline context
may initialize and evaluate but `Flood()` remains fail-closed.
`BaselineParams::AdoptRuntimeRingDim(actual)` separately validates
`actual >= requested feature dimension`, power-of-two shape, and recomputes
chunk count; it does not call or inherit `PiccardParams` sanitizer metadata.
Tests prove the FHE-IND bridge bypass cannot make sanitizer fields applicable,
cannot call `Flood()`, and still reports actual N.

### Pass conditions

- Flood-focused and full BFV tests pass.
- The dedicated fixture supplies a real selectable requested-8192 /
  calibrated-16384 row through the production table adapter. Full Piccard and
  sqrt engine encoding/rotation tests use that compiled fixture (not private
  mutation or the pure selector alone), and requested/runtime N remain
  independently observable. Work 3 later replaces only this test evidence
  with measured production rows.
- Base, dynamic, and sqrt exits still flood exactly once.
- No post-flood homomorphic evaluation path is introduced.
- `threshold-fpfn` behavior/schema is untouched; common threshold compilation
  is allowed but no threshold-specific work is performed.

## Phase 4 — Propagate sanitizer metadata and CLI inputs

### Files

- Modify: `benchmarks/benchmark_utils.h`
- Modify: `benchmarks/benchmark_estimator_provenance.h`
- Modify: `benchmarks/benchmark_estimator_provenance.cpp`
- Modify: `benchmarks/bench_piccard.cpp`
- Modify: `benchmarks/bench_onehot_sqrt.cpp`
- Modify: `benchmarks/bench_dynamic.cpp`
- Modify: `benchmarks/bench_comparison.cpp`
- Modify: `benchmarks/bench_crossover.cpp`
- Modify: `benchmarks/bench_sqrt_comparison.cpp`
- Modify: `tests/unit/test_benchmark_utils.cpp`
- Modify: `tests/unit/test_estimator_provenance_serializers.cpp`
- Add: `tests/scripts/test_sanitizer_runner_forwarding.py`
- Add: `tests/unit/test_threshold_profile_compat.cpp`
- Add: `benchmarks/threshold_csv_schema.h`
- Modify: `benchmarks/bench_threshold.cpp` only to delegate its existing
  byte-identical header to that helper.
- Modify: `scripts/run_benchmarks.sh`
- Modify: `scripts/run_core_benchmarks.sh`
- Modify: `CMakeLists.txt`

### RED tests

Require strict parsing and schema behavior:

- canonical existing-style flags
  `--transcript_stat_bits=40|64|128` and
  `--max_queries=1048576`; optional hyphenated aliases must resolve
  identically;
- zero, overflow, malformed numbers, and unsupported transcript value 41 fail
  before key generation; Work 2 defines raw flags, not Work-4 named profiles;
- Piccard-family rows carry all sanitizer fields;
- BCG12/SJ16/non-FHE rows use string `not-applicable` and an empty cell for
  every numeric N/A, never alternate sentinels or fabricated zeros.
- `bench_crossover` emits arm-qualified sanitizer fields for both `onehot`
  and `sqrt`; before Work 4 introduces named profiles,
  `bench_sqrt_comparison` uses the explicit diagnostic tuple
  `security=TOY,transcript_stat_bits=40,max_queries=1048576,margin=8`.
- Every custom CSV writer delegates header/row serialization to a testable
  helper. Golden tests cover Piccard, onehot/sqrt, dynamic, crossover,
  sqrt-comparison, BCG12, SJ16, and the FHE-IND row, including exact
  not-applicable cells.
- the shared-config threshold regression keeps its exact legacy private
  coefficient target and CSV schema.

Run:

```bash
cmake --build build -j4 --target \
  test_benchmark_utils test_estimator_provenance_serializers \
  test_threshold_profile_compat
./build/test_benchmark_utils
./build/test_estimator_provenance_serializers
./build/test_threshold_profile_compat
python3 -m unittest tests.scripts.test_sanitizer_runner_forwarding -v
```

Expected RED output: parser/schema tests fail because the options and fields are
absent; the fake-runner test fails without executing a real build or
benchmark.

### GREEN implementation

Add profile fields to `BenchmarkConfig`. Rename the old
`flood_lambda_stat` column to `transcript_stat_bits`, append the other fields
without reordering unrelated columns, and forward values into every
non-threshold Piccard-family parameter construction in the listed benchmarks.
Update dry-run output so resolved transcript/query settings are visible.
Implement dry-run handling before any build, directory creation, or command
execution in both runners. The Python test injects fake commands, pins the
complete command matrix, asserts zero filesystem side effects, and verifies
that every Piccard-family command forwards the resolved profile. Only after
that test is GREEN may direct `DRY_RUN=1` commands be used as verification.

For crossover, use separate
`onehot_{coefficient_stat_bits,eval_noise_bits,flood_noise_bits}` and
`sqrt_{...}` columns plus each arm's actual `N`; never collapse different
contexts into one value. Move writer schemas out of benchmark-local classes so
unit tests exercise the exact production serializer.

The threshold compatibility golden uses
`k=64,m=8,security=TOY,tau=32`: private coefficient target 64,
requested/natural `N=1024`, natural depth 12, selected depth 14,
scaling-modulus size 40, eval-noise 331, and legacy flood bits 403. It also
pins the production `ThresholdCSVHeader()` used by `bench_threshold`, proves no transcript
assurance column is added, and verifies the known STD128 fail-closed behavior
at `k=256,m=64,security=STD128,tau=128`: requested `N=16384`, natural
depth 21, and exact `no noise calibration` failure. It must not silently
become a cheaper/different context.

### Pass conditions

- Header/row counts match for every writer.
- The dry run prints the exact resolved profile for each planned invocation.
- No benchmark hard-codes the old 64-bit default.
- Invalid profiles exit nonzero before emitting a data row.
- Threshold construction sites receive no new profile forwarding and continue
  to pass their existing regression tests under the pinned compatibility
  target.

## Work-level verification

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
ctest --test-dir build --output-on-failure
python3 -m unittest tests.scripts.test_sanitizer_runner_forwarding -v
DRY_RUN=1 ./scripts/run_benchmarks.sh
DRY_RUN=1 ./scripts/run_core_benchmarks.sh
rg -n 'lambda_stat|flood_lambda_stat' include src tests benchmarks scripts
```

The final search may contain only the named private threshold-compatibility
constant/comment; it must find no public parameter or CSV field with the old
meaning.

Review artifacts must include four derivation examples, fail-closed logs, the
runtime budget formula, CSV schema evidence, and a search for stale
`lambda_stat` semantics. Work 3 starts only after GPT-5.6-sol and Fable both
approve the nonempty `WORK1_HEAD..WORK2_HEAD` diff, the read-only
`$REVIEW_STAGING_ROOT/work-2-{gpt,fable}.md` files pass
`verify_work_approval.py --work-id=2 --expected-base="$WORK1_HEAD"
--plan-path=docs/superpowers/plans/2026-07-29-02-sanitizer-security-profile-poc.md`,
and clean `HEAD==WORK2_HEAD`.
