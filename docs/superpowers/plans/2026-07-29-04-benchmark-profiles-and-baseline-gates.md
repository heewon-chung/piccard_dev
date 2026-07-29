# Work 4 — Benchmark Profiles and BCG12/SJ16 Matched-Condition Gates

> **Implementation owner:** Claude Opus 5  
> **Plan reviewer:** Claude Fable 5  
> **Work completion reviewers:** GPT-5.6-sol and Claude Fable 5  
> **Dependency:** Work 3 approved  
> **Next work:** real datasets

## Objective

Create one strict pre-threshold benchmark profile/provenance layer and a
reviewer comparison executable that runs Piccard, BCG12, and SJ16 on the same
workload/trials/thread policy. Compare nominally matched 128-bit profiles.
Measure Piccard at STD192, but fail closed instead of mislabelling the existing
128-bit BCG12/SJ16 implementations as 192-bit matches.

## Dependency gate

```bash
WORK3_HEAD="$(python3 scripts/verify_work_approval.py --work-id=3 \
  --expected-base="$WORK2_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-03-std128-std192-calibration.md \
  --gpt="$REVIEW_STAGING_ROOT/work-3-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-3-fable.md" --print-head)"
test "$(git rev-parse HEAD)" = "$WORK3_HEAD"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

## Inputs and outputs

### Fixed profiles

```text
std128-t40-primary
std192-t40-primary
std128-t64-sensitivity
std192-t64-sensitivity
std128-t128-feasibility
std192-t128-feasibility
toy-smoke
```

Each profile fixes security, transcript bits, `max_queries=2^20`, run class,
allowed parameter grid, and whether failure is blocking.

### Comparison inputs

- `k,m,set_size,universe_size,target_jaccard`;
- timing and accuracy trials;
- root seed;
- OpenMP threads/dynamic policy;
- explicit method list; and
- strict or diagnostic security-parity policy.

### Row outputs

Every row records:

```text
profile_id,run_class,target_security_bits,cryptographic_profile,
nominal_security_bits,security_match,comparison_eligible,
comparison_scope,
primitive,protocol_model,output_semantics,assurance_scope,
security_basis,cost_scope,precomputation_mode,
secure_division_included,measurement_kind,
workload_id,workload_manifest_sha256,execution_trace_sha256,
root_seed,omp_threads,
estimator_model,sanitizer_model,sanitizer_assurance,
transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,
flood_margin_bits,eval_noise_bits,flood_noise_bits,
actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version,
target_semantics,target_jaccard,realized_intersection,realized_union,
realized_jaccard,timing_trials,accuracy_trials,omp_dynamic,measurement_status
```

`measurement_kind` is exactly
`fhe-timing|fhe-accuracy|plaintext-estimator|psi-timing|psi-accuracy|
ahe-timing|ahe-accuracy|diagnostic`; status is separately
`measured|extrapolated|infeasible|skipped|error`. String N/A is exactly
`not-applicable`, numeric N/A is an empty cell, and booleans are
`true|false`; numeric zero is never an N/A sentinel. Every writer uses this
same typed schema. Crossover rows carry arm-qualified complete provenance
tuples (`onehot_*`, `sqrt_*`) because the two contexts may differ.
The legacy SJ16 CSV used `measurement_kind=measured|extrapolated`; new rows
must instead use `measurement_kind=ahe-timing` and carry that distinction in
`measurement_status`. No verifier may interpret both meanings in one column.

Evidence mode accepts only `--target-jaccard=<decimal>` and sets
`target_semantics=jaccard`. It rejects legacy `--overlap` (whose old meaning
was intersection divided by set size) rather than silently reinterpreting it.
Every row stores the requested exact rational plus realized integer
intersection/union and reduced realized Jaccard; the verifier recomputes all
three.

The exact crossover suffix is:

```text
onehot_transcript_stat_bits,onehot_max_queries,onehot_query_stat_bits,
onehot_coefficient_stat_bits,onehot_flood_margin_bits,
onehot_eval_noise_bits,onehot_flood_noise_bits,onehot_actual_ring_dim,
onehot_log_q_bits,onehot_plaintext_modulus,onehot_num_limbs,
sqrt_transcript_stat_bits,sqrt_max_queries,sqrt_query_stat_bits,
sqrt_coefficient_stat_bits,sqrt_flood_margin_bits,
sqrt_eval_noise_bits,sqrt_flood_noise_bits,sqrt_actual_ring_dim,
sqrt_log_q_bits,sqrt_plaintext_modulus,sqrt_num_limbs
```

Every expected runner cell resolves according to this exhaustive policy:

| profile | expected-cell success | explicit infeasible/unsupported | skipped/error/missing |
|---|---|---|---|
| `std128-t40-primary` | measured, exit 0 | fail, exit 2 | fail, exit 2 |
| `std192-t40-primary` | measured, exit 0 | fail, exit 2 | fail, exit 2 |
| `std128-t64-sensitivity` | measured, exit 0 | fail, exit 2 | fail, exit 2 |
| `std192-t64-sensitivity` | measured, exit 0 | fail, exit 2 | fail, exit 2 |
| `std128-t128-feasibility` | measured, exit 0 | recorded `infeasible`, exit 0 | fail, exit 2 |
| `std192-t128-feasibility` | measured, exit 0 | recorded `infeasible`, exit 0 | fail, exit 2 |
| `toy-smoke` | diagnostic measured, exit 0 | fail, exit 2 | fail, exit 2 |

Producer-local catch/“Skipped” behavior never decides suite success. The
runner captures every expected grid key, requires exactly one terminal cell
record for it, and exits from this table. An infeasible feasibility cell has a
machine-readable reason/shortfall and no fabricated measurement row.

Terminal cells are UTF-8/LF `terminal-cells.tsv` with the exact tab-separated
header
`schema_version<TAB>cell_id<TAB>profile_id<TAB>producer<TAB>
parameter_sha256<TAB>status<TAB>reason_code<TAB>required_bits<TAB>
available_bits<TAB>shortfall_bits<TAB>log_sha256`. No field may contain tab,
CR, or LF. `schema_version` is `piccard-benchmark-terminal-cell-v1`.
`parameter_sha256` hashes
`ASCII("piccard-benchmark-cell-v1")||0x00`, followed by producer, profile,
every semantic workload specification/argv entry except runner-resolved output-path
flags, and sorted environment entries as `BE32(length)||bytes`.
`cell_id` is exactly
`<profile_id>/<producer>/<parameter_sha256>`. Rows are bytewise sorted by this
unique full ID.
CSV/log/workload/trace output paths are then derived from that ID and recorded
separately in the run manifest. The workload is generated afterward from the
already-hashed semantic specification, and its independent SHA is bound in
the run manifest/result rows; it is not an input to `parameter_sha256`, so no
pre-generation/hash/path cycle exists.

`status=MEASURED` requires `reason_code=NONE` and empty bit cells;
`INFEASIBLE` requires `CAPACITY_SHORTFALL|MISSING_CALIBRATION`.
`CAPACITY_SHORTFALL` requires numeric required/available bits and their exact
nonnegative shortfall; `MISSING_CALIBRATION` leaves all three bit cells empty.
`ERROR` requires
`PROCESS_ERROR|TIMEOUT` and empty bit cells. All require a 64-hex log hash.
The run manifest binds file SHA-256 and expected row count. Resume
accepts a terminal row only after revalidating source, binary, parameters, log
hash, and status; missing, duplicate, malformed, or unbound cells fail.

## Phase 1 — Implement the benchmark profile contract

### Files

- Add: `benchmarks/benchmark_profile.h`
- Add: `benchmarks/benchmark_profile.cpp`
- Add: `tests/unit/test_benchmark_profile.cpp`
- Modify: `benchmarks/benchmark_utils.h`
- Modify: `benchmarks/benchmark_estimator_provenance.h`
- Modify: `benchmarks/benchmark_estimator_provenance.cpp`
- Modify: `tests/unit/test_estimator_provenance_serializers.cpp`
- Modify: `benchmarks/bench_piccard.cpp`
- Modify: `benchmarks/bench_onehot_sqrt.cpp`
- Modify: `benchmarks/bench_piccard.cpp`
- Modify: `benchmarks/bench_onehot_sqrt.cpp`
- Modify: `benchmarks/bench_dynamic.cpp`
- Modify: `benchmarks/bench_comparison.cpp`
- Modify: `benchmarks/bench_crossover.cpp`
- Modify: `benchmarks/bench_sqrt_comparison.cpp`
- Modify: `CMakeLists.txt`

### RED tests

Require exact resolution of all seven profiles, including:

- t40 primary and t64 sensitivity classifications;
- t128 feasibility-only invariant;
- Q adjustment equals 20;
- a profile conflict with `--security`, transcript bits, or max queries fails;
- unknown profile fails;
- legacy CLI is labelled `legacy`, not silently primary.

Run:

```bash
cmake --build build -j4 --target \
  test_benchmark_profile test_estimator_provenance_serializers
./build/test_benchmark_profile
./build/test_estimator_provenance_serializers
```

Expected RED output: profile API/target absent.

### GREEN implementation

Use one resolver and one `ApplyBenchmarkProfile()` function at every listed
non-threshold Piccard-family evidence construction site. Profiles are
immutable after parse. Do not apply it to FHE-IND's bridge or threshold sites.

Exact suite grids:

```text
primary Piccard-family (per security={STD128,STD192}, t40):
  bench_piccard combined:
    k={16,32,64,128,256,512} at m=64,n=1000
    m={16,32,64,128,256} at k=128,n=1000
    n={100,1000,10000,100000} at k=128,m=64
    target_jaccard=0.5,timing_trials=30, accuracy_trials=50
  bench_onehot_sqrt timing:
    k={16,32,64,128,256,512} at m=64,n=1000
    m={4,16,64,256} at k=128,n=1000
    n={100,1000,10000,100000} at k=128,m=64
    timing_trials=30
  bench_onehot_sqrt accuracy:
    k=128,m=64,n=1000,target_jaccard={0.0,0.1,...,1.0},
    accuracy_trials=50 for each of 11 target Jaccards and both encodings
  bench_dynamic timing, depth=5:
    k={16,32,64,128,256,512} at m=64,n=1000
    m={16,32,64,128,256} at k=128,n=1000
    n={100,1000,10000,100000} at k=128,m=64
    timing_trials=30
primary reviewer comparison:
  STD128 only, k=128,m=64,n=1000,U={16384,65536},
  target_jaccard=0.5,timing_trials=30,accuracy_trials=50
sensitivity:
  security={STD128,STD192},t64,k=128,m=64,n=1000, target_jaccard=0.5
  bench_piccard mode={timing,accuracy}, trials={3,30}
  bench_onehot_sqrt mode={timing,accuracy}, trials={3,30}
  bench_dynamic mode=timing,depth=5,trials=3
feasibility:
  security={STD128,STD192},t128,k=128,m=64,n=100,
  target_jaccard=0.5,bench_piccard mode={timing,accuracy},trials={1,2}
```

Add `--evidence_point` to all three primary executables. It runs exactly the
single supplied `(k,m,set_size,target_jaccard)` rather than their native internal
sweeps; sensitivity and feasibility commands must use it. Primary commands
use the explicitly listed native grids. `bench_crossover` retains its exact
diagnostic grid `k={32,64,128,256,512}`,
`m={4,16,64,256,1024}`. `bench_sqrt_comparison` retains diagnostic points
`(128,64),(256,64),(512,64),(1024,64),(128,256),(128,1024)`. Both diagnostic
executables require a named profile and metadata but are not invoked by
primary/sensitivity/feasibility suites. Golden tests prove that a
sensitivity/feasibility command emits one point, not a hidden full sweep.
Dynamic evidence removes the current hidden `max(set_size,10000)` promotion;
emitted row-grid golden tests prove the requested `n=1000` is used. Separate
goldens pin every native timing row key and the exact 11-target-Jaccard accuracy rows.
Unknown options become fatal after each executable has consumed its declared
extension flags.
Piccard accuracy/evidence paths are changed to consume
`config.accuracy_trials`; goldens prove timing uses `trials`, accuracy uses
`accuracy_trials`, and exact row/trial counts match the grid.
`--mode=combined` is orchestration, not a row kind: it emits exactly two
aggregate rows for each parameter point, one `fhe-timing` with
`timing_trials` samples and one `fhe-accuracy` with `accuracy_trials` samples.
All accuracy producers, including Piccard and onehot/sqrt, emit one aggregate
row per point; optional per-trial detail goes to a separate manifest-bound raw
artifact and never appears in the common comparison CSV. Golden tests reject
the current mixed “one combined row versus per-trial accuracy rows” behavior.

### Pass conditions

- Tests pass.
- No t128 profile can be primary or comparison-eligible.
- A conflict exits before calibration lookup/key generation.
- Every listed production evidence runner uses a named profile.
- FHE-IND construction is proven unchanged. Run Work 2's
  `test_threshold_profile_compat` golden: shared-parser changes must leave the
  threshold CLI/header and pinned legacy parameters byte-identical, require no
  profile, and expose no transcript metadata.

## Phase 2 — Expose actual FHE and build provenance

### Files

- Add: `cmake/build_info.h.in`
- Add: `benchmarks/benchmark_provenance.h`
- Add: `benchmarks/benchmark_provenance.cpp`
- Modify: `CMakeLists.txt`
- Modify: `include/fhe/bfv_context.h`
- Modify: `src/fhe/bfv_context.cpp`
- Modify: `benchmarks/benchmark_utils.h`
- Modify: `benchmarks/bench_piccard.cpp`
- Modify: `benchmarks/bench_onehot_sqrt.cpp`
- Modify: `benchmarks/bench_comparison.cpp`
- Modify: `benchmarks/baseline_engine.h`
- Modify: `benchmarks/bench_dynamic.cpp`
- Modify: `benchmarks/bench_crossover.cpp`
- Modify: `benchmarks/bench_sqrt_comparison.cpp`
- Modify: `tests/unit/test_bfv_context.cpp`
- Modify: `tests/unit/test_benchmark_profile.cpp`

### RED tests

Require:

- actual `N`, tower-sum `log2(q)`, plaintext modulus, limb count, and
  OpenFHE version;
- runtime values agree with the live crypto context;
- Piccard rows require positive actual FHE values;
- AHE rows represent FHE values as not applicable;
- FHE-IND records its actual BFV N/logQ/plaintext/limbs while Piccard
  sanitizer fields remain not applicable;
- OpenFHE version cannot be `unknown`;
- query/coefficient bits agree with the selected sanitizer profile.

Run:

```bash
cmake --build build -j4 --target test_bfv_context test_benchmark_profile
./build/test_bfv_context --gtest_filter='*RuntimeMetadata*'
./build/test_benchmark_profile --gtest_filter='*Provenance*'
```

Expected RED output: runtime/build metadata APIs absent.

### GREEN implementation

Calculate `log_q_bits` by summing per-tower logarithms, not by converting the
full modulus to `double`. Generate the version header at configure time from
the discovered OpenFHE package. Each listed producer receives a live
`BenchmarkProvenance` object from its engine/context and passes it explicitly
to the shared row serializer; the serializer never attempts to infer live
context values from a result struct. Phase 4 integrates this same object into
the newly created reviewer executable.

### Pass conditions

- Focused tests pass.
- Actual and CSV parameters match for TOY and one calibrated STD128 context.
- Appended provenance does not reorder existing CSV columns.

## Phase 3 — Replace umbrella security labels with a strict capability map

### Files

- Add: `benchmarks/baseline_profile.h`
- Add: `benchmarks/baseline_profile.cpp`
- Add: `tests/unit/test_baseline_profile.cpp`
- Modify: `benchmarks/bench_comparison.cpp`
- Modify: `benchmarks/sj16_adapter.h`
- Modify: `benchmarks/baseline_engine.h`
- Modify as required: `include/baselines/pjs_baseline.h`
- Modify: `scripts/summarize_results.py`
- Modify: `scripts/verify_reporting_gaps.py`
- Add: `tests/scripts/test_reporting_taxonomy.py`
- Modify: `CMakeLists.txt`

### Fixed capability map

| Method | Implemented parameter | nominal bits | STD128 match | STD192 match |
|---|---|---:|---|---|
| BCG12-FF | FF-3072/256 | 128 | yes | no |
| BCG12-EC | P-256 | 128 | yes | no |
| SJ16 | Paillier-1024 | ~80 | no | no |
| SJ16 | Paillier-2048 | ~112 | no | no |
| SJ16 | Paillier-3072 | 128 proxy | yes | no |
| FHE-IND | local BFV indicator comparator | actual BFV target | boolean by live context | boolean by live context |

FHE-IND is not EPSet and is not assigned `KPA/leakage`. Its row says
`local-universe-sized-BFV-comparator` and avoids claiming a reviewed deployment
protocol. It remains `comparison_eligible=false`, `measurement_kind=diagnostic`
even when its live BFV primitive makes `security_match=true`. SJ16 always says
`intersection-shares-lower-bound` and
`secure_division_included=false`.

The verifier truth table uses these exact tokens. Every row additionally
records `security_basis`; Paillier-3072 uses
`rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security`.
Method-conditioned values are exact:

| method | `security_basis` |
|---|---|
| Piccard/Piccard-sqrt/FHE-IND | `openfhe-hesea-standard-live-context` |
| BCG12-FF | `finite-field-dh-3072-subgroup-256-parameter-map` |
| BCG12-EC | `nist-p256-parameter-map` |
| SJ16-1024 | `rsa-ifc-modulus-size-proxy-approximately-80-bits` |
| SJ16-2048 | `rsa-ifc-modulus-size-proxy-approximately-112-bits` |
| SJ16-3072 | `rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security` |

No implemented method may use `not-applicable` for this field; an unknown
method is rejected.
`cost_scope` is the timing boundary
`full-query-excluding-one-time-setup|online-query-with-precomputed-randomizers|
primitive-only`; it never encodes functionality scope.
`precomputation_mode` is
`crs-and-keys-only|randomizer-generation-included|
randomizers-precomputed|not-applicable`. Piccard and BCG12 main rows use
full-query-excluding-one-time-setup (all per-query work timed). SJ16 main uses
that same boundary with randomizer generation included; its sensitivity uses
online-query-with-precomputed-randomizers. FHE-IND is primitive-only.
`comparison_scope` independently records end-to-end/component/lower-bound
functionality. Summaries may not mix timing boundaries or precomputation modes.

| method family | primitive | protocol_model | output_semantics | assurance_scope | secure division | scope/eligibility |
|---|---|---|---|---|---|---|
| Piccard | `bfv-onehot-minhash` | `piccard-two-owner-outsourced` | `bias-corrected-jaccard-estimate` | `live-bfv+empirical-sanitizer-poc` | `false` | `end-to-end-estimator`, matched primary=true |
| Piccard-sqrt | `bfv-sqrt-minhash` | `piccard-sqrt-two-owner-outsourced` | `bias-corrected-jaccard-estimate` | `live-bfv+empirical-sanitizer-poc` | `false` | `end-to-end-estimator`, matched primary=true |
| BCG12-MinHash FF/EC | `bcg12-ff` or `bcg12-ec` | `bcg12-cardinality-on-minhash` | `minhash-collision-jaccard-estimate` | `implemented-baseline-parameter-map` | `false` | `matched-estimator-component`, true only at mapped STD128 |
| BCG12-exact FF/EC | `bcg12-ff` or `bcg12-ec` | `bcg12-exact-cardinality` | `harness-reconstructed-exact-jaccard` | `implemented-baseline-parameter-map` | `false` | `matched-cardinality-component`, true only at mapped STD128 |
| SJ16 | `paillier-1024|paillier-2048|paillier-3072` | `sj16-intersection-shares` | `harness-reconstructed-jaccard-with-plaintext-union` | `intersection-shares-lower-bound` | `false` | only 3072 is STD128 matched and eligible as `component-lower-bound`; 1024/2048 false |
| FHE-IND | `bfv-indicator-comparison` | `local-universe-sized-BFV-comparator` | `intersection-indicator-vector` | `live-bfv-primitive-only` | `false` | `diagnostic-only`, always false |

“Eligible” never erases scope: summaries must print
`comparison_scope`, and SJ16 timing/accuracy is not called full secure
Jaccard. For row parameters, Piccard/Piccard-sqrt require numeric `k,m`.
BCG12-MinHash requires numeric `k` and the workload hash seed but empty `m`,
because it consumes full-range minima. BCG12-exact and SJ16 use empty numeric
N/A cells for both `k,m`. Their group membership is bound by the shared
workload manifest, not fabricated parameters. FHE-IND uses empty `k,m` unless
its diagnostic primitive consumes them. Method-conditional verifier fixtures
enforce these exact rules.

### RED tests

Test:

- STD128 matches for BCG12 FF/EC and SJ16-3072;
- no supported BCG12/SJ16 STD192 match;
- strict STD192 parity rejects before setup;
- unmatched AHE diagnostic mode emits `security_match=false` and
  `comparison_eligible=false`;
- SJ16 lower-bound flag is invariant;
- exact and MinHash BCG12 modes remain distinct.
- BCG12 rows use `psi-timing|psi-accuracy`, never AHE labels.
- a separate SJ16 `precomputed-randomizer` sensitivity row is
  comparison-ineligible and cannot replace the main included-cost row.
- every timing row has verified cost/precomputation scope, and Paillier-3072
  retains the RSA/IFC modulus-size-proxy qualification.
- SJ16-1024 smoke is diagnostic/ineligible and cannot inherit the
  Paillier-3072 STD128 match.
- SJ16-2048 is ~112-bit diagnostic/ineligible and cannot inherit 3072's match.

Run:

```bash
cmake --build build -j4 --target test_baseline_profile
./build/test_baseline_profile
python3 -m unittest tests.scripts.test_reporting_taxonomy -v
```

Expected RED output: existing umbrella `AHE/no-leakage` lookup cannot express
these properties.

### GREEN implementation

Move taxonomy out of method-name string matching and into typed per-method
metadata. Do not add unreviewed P-384, FF-7680, or Paillier-7680 code in this
revision PoC. STD192 Piccard evidence remains valid, while matched AHE
comparison is explicitly unavailable.

### Pass conditions

- Strict map tests pass.
- No row with existing BCG12/SJ16 parameters can say `STD192 matched`.
- FHE-IND no longer says `KPA/leakage` or pretends to be EPSet.
- Summarizer and reporting verifier require the new FHE-IND label; neither
  hard-codes `KPA/leakage` for this method.
- Reporting fixtures execute both `summarize_results.py` and
  `verify_reporting_gaps.py`; they fail if either output contains
  `KPA/leakage` for FHE-IND or accepts the old taxonomy.
- No baseline inherits Piccard sanitizer fields.

## Phase 4 — Generate one canonical workload for every method

### Files

- Add: `benchmarks/comparison_workload.h`
- Add: `benchmarks/comparison_workload.cpp`
- Add: `tests/unit/test_comparison_workload.cpp`
- Add: `benchmarks/bench_review_comparison.cpp`
- Modify: `CMakeLists.txt`

### Workload contract

Generate all trial sets before method setup. Canonically encode spec, lengths,
trial seeds, set elements, exact Jaccard, and hash seed in big-endian form and
SHA-256 the manifest. Every adapter receives the same immutable trial.

The artifact is binary and uses extension `.bin`, never `.csv`. Its complete
top-level byte grammar, in order, is:

```text
ASCII("piccard-review-workload-v1") || 0x00
STR(suite) || STR(profile_id)
BE64(root_seed) || BE64(k) || BE64(m) || BE64(set_size) || BE64(universe)
BE64(target_jaccard_numerator) || BE64(target_jaccard_denominator)
BE32(method_count) || STR(method_0) ... STR(method_n)
BE32(timing_trials) || BE32(accuracy_trials)
BE32(record_count)
for each record in (kind_tag, trial_index) order:
  U8(kind_tag: warmup=0, timing=1, accuracy=2)
  BE32(trial_index) || BE64(trial_seed)
  BE64(hash_seed)
  VEC64(set_a) || VEC64(set_b)
  BE64(exact_intersection) || BE64(exact_union)
```

`STR` is `BE32(byte_length)||UTF-8`; `VEC64` is `BE64(count)` followed by
sorted unique BE64 elements. Target Jaccard is the reduced exact rational
parsed from the CLI decimal (`0.5 -> 1/2`), never floating bytes. For equal
set size `n`, the target intersection is nearest integer to
`2*n*p/(1+p)` with exact-half ties toward the lower integer; the artifact
stores the realized reduced rational `intersection/(2*n-intersection)` in
each record. Empty/empty is `1/1`.

Trial seed is
`first8BE(SHA256("piccard-review-trial-v1" || 0x00 || BE64(root_seed) ||
U8(kind_tag) || BE32(trial_index)))`. Rank every `x in [0,universe)` by
`SHA256("piccard-review-set-v1" || 0x00 || BE64(trial_seed) || BE64(x))`,
digest then x tie-break; take the first `intersection` for both sets, the next
`n-intersection` for A only, and the next same count for B only. Insufficient
universe fails before output.

The warmup record has index 0 and encodes
`first8BE(SHA256("piccard-review-hash-warmup-v1" || 0x00 ||
BE64(root_seed)))`. Timing records all encode the fixed CRS
`first8BE(SHA256("piccard-review-hash-timing-v1" || 0x00 ||
BE64(root_seed)))`. Accuracy record `i` encodes the resampled CRS
`first8BE(SHA256("piccard-review-hash-accuracy-v1" || 0x00 ||
BE64(root_seed) || BE32(i)))`. Piccard, Sqrt, and BCG12-MinHash receive that
exact encoded seed; exact BCG12/SJ16 ignore it but remain bound to the same
record.

`record_count=1+timing_trials+accuracy_trials`; the warmup precedes all timing
records, which precede all accuracy records, and measured indices are
contiguous from zero within each kind.
`workload_manifest_sha256` is SHA-256 of the entire binary artifact and
`workload_id` is exactly
`review-<universe>-<first16-lowercase-hex-of-that-sha>`. The verifier reparses
these bytes, regenerates every seed/set/rational, and recomputes both values
rather than trusting result rows.

Rules:

- setup/keygen and set generation excluded for every method;
- one warmup per method;
- identical measured trial counts;
- fixed timing CRS shared by Piccard/Sqrt/BCG12-MinHash;
- resampled accuracy CRS shared trial by trial;
- deterministic rotation of method execution order: let the manifest's
  ordered method list have length L and let
  `offset=trial_seed mod L`; record execution order is the cyclic list
  `method[(offset+j) mod L]` for `j=0..L-1`. Warmup, timing, and accuracy all
  use this formula, and the verifier regenerates it;
- no BCG12 trial cap, method skip, or SJ16 extrapolation in reviewer mode;
- one method failure invalidates the comparison group.

The harness requires
`--execution-trace-out=<runner-root>/traces/<cell_id>.bin`; it has no default,
rejects an existing path, and writes atomically before aggregate CSV
finalization. The runner supplies one unique manifest-bound path per cell and
records its SHA/path in `manifest.json`. Its grammar is
`ASCII("piccard-review-execution-trace-v1")||0x00 ||
workload_manifest_sha256_raw32 || BE32(expected_record_count) ||
BE32(observed_record_count)`, followed for each observed record by
`U8(kind)||BE32(trial_index)||BE32(expected_method_count)||
BE32(dispatched_count)||U8(record_status)` and the actual sequence as
`STR(method)` entries. `record_status` is
`0=complete,1=adapter_failure`; complete requires dispatched==expected, while
adapter failure permits `1 <= dispatched <= expected` (including failure in
the final dispatched adapter) and terminates the trace. A dispatch
is appended immediately before calling the adapter, so a failure is
representable and still invalidates the group. `execution_trace_sha256` is the SHA-256 of
these exact bytes, is manifest-bound, and appears identically in every group
row. The verifier reparses it and compares every sequence to the regenerated
cyclic schedule. Fixtures reject a wrong, missing, duplicated, or reordered
dispatch, reused output path, or malformed partial failure even when aggregate
rows otherwise look valid.

Membership is manifest-conditioned and the verifier accepts only these three
frozen suites:

- `suite=primary-review`: for each workload U, required methods are exactly
  `piccard,piccard_sqrt,bcg12_mh_ff,bcg12_mh_ec,bcg12_exact_ff,
  bcg12_exact_ec,sj16`. Each emits exactly one 30-trial timing aggregate and
  one 50-trial accuracy aggregate.
- `suite=toy-smoke`: required methods are exactly
  `piccard,piccard_sqrt,bcg12_mh_ec,bcg12_exact_ec,sj16`; each emits exactly
  one 1-trial timing aggregate and one 2-trial accuracy aggregate and is
  diagnostic/ineligible.
- `suite=sj16-precompute-sensitivity`: required methods are exactly
  `sj16,sj16_precomputed`, `timing_trials=3`, `accuracy_trials=0`, and each
  emits exactly one timing aggregate. Both use Paillier-3072 and the same
  canonical workload records; the first includes per-query randomizer
  generation, the second consumes precomputed randomizers. Both are
  diagnostic/comparison-ineligible, giving exactly two rows per universe.

Across these suites, Piccard rows use `fhe-timing|fhe-accuracy`, BCG12 rows use
`psi-timing|psi-accuracy`, and SJ16 rows use `ahe-timing|ahe-accuracy`.
Exact baselines report zero estimator error;
MinHash methods share the trial CRS. Duplicate/unexpected/missing method-kind
pairs fail. Therefore each primary U has exactly 14 rows and each smoke U
exactly 10; each SJ16 sensitivity U has exactly 2. The manifest freezes suite, ordered method list, timing and
accuracy trial counts; CLI values must match it, and the verifier selects no
implicit default.

### RED tests

Test deterministic generation/digest, exact cardinality/Jaccard, unique seeds,
seed sensitivity, canonical ordering, and that adapters observe the same trial
digest. Negative fixtures cover tampered workload bytes, duplicate/unexpected
methods, mismatched `k/m/set_size/universe`, and wrong timing/accuracy
membership or trial counts for exact versus estimator methods. Include valid
primary-14 and smoke-10 fixtures plus cross-suite method/trial substitution
failures.
Include a valid two-row SJ16 sensitivity fixture proving identical workload
binding, included-vs-precomputed timing boundaries, and exact membership;
reject any missing/extra row or swapped precomputation label.

Run:

```bash
cmake --build build -j4 --target test_comparison_workload
./build/test_comparison_workload
```

Expected RED output: workload API/target absent.

### GREEN implementation and smoke

```bash
OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE \
./build/bench_review_comparison \
  --suite=toy-smoke --profile=toy-smoke \
  --k=16 --m=16 --set-size=10 --universe=64 --target-jaccard=0.5 \
  --trials=1 --accuracy-trials=2 --seed=7 \
  --methods=piccard,piccard_sqrt,bcg12_mh_ec,bcg12_exact_ec,sj16 \
  --sj16-key-bits=1024 --allow-unmatched-security \
  --manifest-out=/tmp/piccard-review-workload.bin \
  --execution-trace-out=/tmp/piccard-review-smoke.trace.bin \
  > /tmp/piccard-review-results.csv
```

### Pass conditions

- Unit tests and smoke pass.
- Every result row has the same workload digest and conditions.
- Smoke rows are diagnostic/ineligible, never paper data.

## Phase 5 — Add machine-verifiable comparison and provenance gates

### Files

- Add: `scripts/verify_review_comparison.py`
- Add: `scripts/verify_benchmark_provenance.py`
- Add: `tests/scripts/test_verify_review_comparison.py`
- Add: `tests/scripts/test_verify_benchmark_provenance.py`
- Modify: `scripts/verify_sj16_extrapolation.py`
- Add: `tests/scripts/test_verify_sj16_extrapolation.py`
- Modify or supersede: `scripts/assert_methods.sh`

### RED tests

Fixture failures must cover:

- method exists elsewhere but is absent from the required workload;
- mismatched workload digest, trials, seed, threads, target Jaccard, or profile;
- strict unmatched security;
- extrapolated/skipped/error row;
- missing actual FHE metadata;
- invalid AHE profile;
- SJ16 missing lower-bound marker;
- missing estimator/sanitizer model;
- `NaN`, `Inf`, or CSV column-count mismatch.
- recomputed workload-byte hash mismatch or tampering;
- duplicate/unexpected method-kind pair;
- wrong `k`, `m`, `set_size`, or universe;
- missing/wrong timing-versus-accuracy membership or aggregate trial count.

Run:

```bash
python3 -m unittest \
  tests.scripts.test_verify_review_comparison \
  tests.scripts.test_verify_benchmark_provenance \
  tests.scripts.test_verify_sj16_extrapolation
```

Expected RED output: verifier/tests absent or old method-presence check falsely
accepts fixtures.

### GREEN implementation

Use Python's `csv` module and strict required-column checks. Verification must
produce a concise JSON/console verdict and nonzero exit on any group error.
Update `verify_sj16_extrapolation.py` to require
`measurement_kind=ahe-timing` and read only
`measurement_status=measured|extrapolated`. An explicit
`--legacy-sj16-schema` migration mode accepts the old column meaning, maps it
to the two new fields in memory, and prints a deprecation marker; without that
flag, old rows fail. Fixtures cover new measured/extrapolated rows, old rows
with/without the flag, and forbid mixed legacy/new semantics.

### Pass conditions

- All negative fixtures fail for the intended reason.
- A complete STD128 fixture passes.
- An STD192 AHE-matched fixture is rejected.

## Phase 6 — Add a pre-threshold-only runner matrix

### Files

- Add: `scripts/run_pre_threshold_profiles.sh`
- Add: `tests/scripts/test_run_pre_threshold_profiles.py`
- Modify: `scripts/run_benchmarks.sh`
- Modify: `scripts/run_core_benchmarks.sh`

### Suites

- `primary`: STD128/STD192 t40 Piccard-family runs; reviewer comparison at
  STD128 only.
- `sensitivity`: default/representative STD128/STD192 t64 points; baselines
  not rerun unless explicitly diagnostic.
- `feasibility`: one or two STD128/STD192 t128 points, 1–2 trials, always
  comparison-ineligible.
- `smoke`: TOY/short diagnostic paths including BCG12/SJ16.

Every command fixes seed and thread policy. No suite calls `bench_threshold`.
`--dry-run` creates no files and prints the complete commands and gates.
Non-dry-run requires caller-supplied absolute `--results-root`; the runner
creates exactly that directory (or validates it under `--resume`) and writes
`manifest.json`, `terminal-cells.tsv`, `csv/`, `workloads/`, `traces/`, and
`logs/` beneath it. There is no
implicit `latest` path or timestamp. Existing output is never overwritten.
It also requires absolute `--build-dir`, resolves every executable only from
that directory, and records each binary SHA-256/source commit. Evidence uses a
new empty Release build directory configured from a clean exact source commit.
CMake embeds `PICCARD_BUILD_COMMIT`, `PICCARD_BUILD_DIRTY=0`, and
`PICCARD_BUILD_TYPE=Release` in every evidence executable; each exposes
`--print-build-provenance`. The runner compares those embedded values with
HEAD and the manifest before any cell, then hashes the binary. Reusing a stale
binary or configuring from dirty/different source is fatal. Verifiers accept
`--run-manifest=<results-root>/manifest.json` and resolve exact
CSV/workload/trace paths beneath their declared subroots from the manifest
rather than guessing filenames.

The exact argv matrix, with `<S>` expanded in order `STD128,STD192` and `<P>`
to the matching lowercase profile ID, is:

```text
primary, for each <S>/<P>:
  bench_piccard --profile=<P>-t40-primary --security=<S> --mode=combined
    --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --trials=30
    --accuracy_trials=50 --seed=20260729
  bench_onehot_sqrt --profile=<P>-t40-primary --security=<S> --mode=timing
    --k=128 --m=64 --set_size=1000 --trials=30 --seed=20260729
  bench_onehot_sqrt --profile=<P>-t40-primary --security=<S> --mode=accuracy
    --k=128 --m=64 --set_size=1000 --accuracy_trials=50 --seed=20260729
  bench_dynamic --profile=<P>-t40-primary --security=<S> --mode=timing
    --k=128 --m=64 --set_size=1000 --depth=5 --trials=30 --seed=20260729
primary reviewer comparison, STD128 only, once per U={16384,65536}:
  bench_review_comparison --suite=primary-review
    --profile=std128-t40-primary --security=STD128
    --k=128 --m=64 --set-size=1000 --universe=<U> --target-jaccard=0.5
    --trials=30 --accuracy-trials=50 --seed=20260729
    --methods=piccard,piccard_sqrt,bcg12_mh_ff,bcg12_mh_ec,
      bcg12_exact_ff,bcg12_exact_ec,sj16 --sj16-key-bits=3072
    --execution-trace-out=<runner-root>/traces/<cell_id>.bin
    --strict-security
sensitivity, for each <S>/<P>, every command has --evidence_point:
  bench_piccard --profile=<P>-t64-sensitivity --security=<S> --mode=timing
    --evidence_point --k=128 --m=64 --set_size=1000
    --target-jaccard=0.5 --trials=3 --seed=20260729
  bench_piccard --profile=<P>-t64-sensitivity --security=<S> --mode=accuracy
    --evidence_point --k=128 --m=64 --set_size=1000
    --target-jaccard=0.5 --accuracy_trials=30 --seed=20260729
  bench_onehot_sqrt --profile=<P>-t64-sensitivity --security=<S>
    --mode=timing --evidence_point --k=128 --m=64 --set_size=1000
    --target-jaccard=0.5 --trials=3 --seed=20260729
  bench_onehot_sqrt --profile=<P>-t64-sensitivity --security=<S>
    --mode=accuracy --evidence_point --k=128 --m=64 --set_size=1000
    --target-jaccard=0.5 --accuracy_trials=30 --seed=20260729
  bench_dynamic --profile=<P>-t64-sensitivity --security=<S> --mode=timing
    --evidence_point --k=128 --m=64 --set_size=1000 --target-jaccard=0.5 --depth=5
    --trials=3 --seed=20260729
additional SJ16 sensitivity, STD128 only, once per U={16384,65536}:
  bench_review_comparison --suite=sj16-precompute-sensitivity
    --profile=std128-t64-sensitivity --security=STD128
    --k=128 --m=64 --set-size=1000 --universe=<U> --target-jaccard=0.5
    --trials=3 --accuracy-trials=0 --seed=20260729
    --methods=sj16,sj16_precomputed --sj16-key-bits=3072
    --execution-trace-out=<runner-root>/traces/<cell_id>.bin
    --diagnostic-security
feasibility, for each <S>/<P>, every command has --evidence_point:
  bench_piccard --profile=<P>-t128-feasibility --security=<S> --mode=timing
    --evidence_point --k=128 --m=64 --set_size=100 --target-jaccard=0.5
    --trials=1 --seed=20260729
  bench_piccard --profile=<P>-t128-feasibility --security=<S> --mode=accuracy
    --evidence_point --k=128 --m=64 --set_size=100 --target-jaccard=0.5
    --accuracy_trials=2 --seed=20260729
smoke:
  the exact Phase-4 bench_review_comparison command
  bench_piccard --profile=toy-smoke --security=TOY --mode=timing
    --evidence_point --k=16 --m=16 --set_size=10 --target-jaccard=0.5
    --trials=1 --seed=7
```

All single-point Piccard sensitivity commands above also include
`--evidence_point`; presentation does not imply it. All commands receive
runner-resolved output paths and
`OMP_NUM_THREADS=<threads>, OMP_DYNAMIC=FALSE`; those exact environment/argv
tokens are part of the golden fixture. Line wrapping above is presentation
only. A golden runner test pins the fully expanded commands byte-for-byte,
including `--evidence_point` on every single-point command.

### RED tests

With fake binaries, verify command matrix, no threshold command, explicit
profile/seed/thread arguments, no output in dry-run, primary failure on missing
STD192 calibration, and final verifier invocation. Also reject a relative
result root, pre-existing root without resume, hash/manifest mismatch under
resume, and any output path escaping the root.

Run:

```bash
python3 -m unittest tests.scripts.test_run_pre_threshold_profiles
```

Expected RED output: runner/test absent.

### GREEN smoke and dry-run

```bash
DRY_RUN=1 ./scripts/run_pre_threshold_profiles.sh \
  --suite=primary --seed=20260729 --threads=8 --build-dir="$(pwd)/build"
./scripts/run_pre_threshold_profiles.sh \
  --suite=smoke --seed=7 --threads=2 \
  --build-dir="$(pwd)/build" \
  --results-root=/tmp/piccard-pre-threshold-smoke
python3 -m unittest \
  tests.scripts.test_verify_review_comparison \
  tests.scripts.test_verify_benchmark_provenance \
  tests.scripts.test_verify_sj16_extrapolation \
  tests.scripts.test_run_pre_threshold_profiles
```

### Pass conditions

- Dry-run has no side effects.
- Smoke passes both verifiers.
- Result manifest includes command, commit/dirty state, Release/diagnostic
  classification, CPU/RAM/OS/compiler/library versions, seed, thread policy,
  profile list, and output checksums.
- Dirty/Debug paper runs fail unless explicitly diagnostic.
- Under `--resume`, every existing argv/output/checksum/commit/profile must
  validate before a completed cell is skipped; any mismatch fails. The runner
  substitutes the Phase-4 standalone `/tmp` output arguments with exact paths
  beneath `<results-root>/csv` and `<results-root>/workloads`, redirects each
  stdout/stderr beneath the root, and the golden test proves no path escapes.

## Work-level verification

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
ctest --test-dir build --output-on-failure
./build/test_threshold_profile_compat
DRY_RUN=1 ./scripts/run_pre_threshold_profiles.sh \
  --suite=primary --seed=20260729 --threads=8 --build-dir="$(pwd)/build"
SMOKE_ROOT="$(mktemp -d)"
rmdir "$SMOKE_ROOT"
./scripts/run_pre_threshold_profiles.sh \
  --suite=smoke --seed=7 --threads=2 \
  --build-dir="$(pwd)/build" \
  --results-root="$SMOKE_ROOT"
```

Review artifacts: capability map, actual metadata rows, workload manifest,
verifier logs, dry-run matrix, and smoke manifest. Work 5 starts only after
GPT-5.6-sol and Fable approve the nonempty `WORK3_HEAD..WORK4_HEAD` diff,
the read-only `$REVIEW_STAGING_ROOT/work-4-{gpt,fable}.md` files pass
`verify_work_approval.py --work-id=4 --expected-base="$WORK3_HEAD"
--plan-path=docs/superpowers/plans/2026-07-29-04-benchmark-profiles-and-baseline-gates.md`,
and clean `HEAD==WORK4_HEAD`.
