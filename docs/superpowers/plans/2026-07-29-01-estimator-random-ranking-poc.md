# Work 1 — SHA-256 Random-Ranking Estimator PoC

> **Implementation owner:** Claude Opus 5  
> **Plan reviewer:** Claude Fable 5  
> **Work completion reviewers:** GPT-5.6-sol and Claude Fable 5  
> **Dependency:** approved pre-threshold design  
> **Next work:** sanitizer security profile

## Objective

Replace the affine Mersenne-prime hash with one public, domain-separated,
cross-platform SHA-256 random-ranking implementation. Preserve the existing
`MinHasher` public construction API and route static, dynamic, and BCG12
MinHash paths through the same implementation. Add deterministic empirical
bias evidence and explicit estimator provenance.

## Inputs and outputs

### Inputs

- `k: uint32_t`, strictly positive.
- `hash_seed: uint64_t`, any value.
- `hash_range: uint64_t`, either `UINT64_MAX` for the supported full-rank mode
  or `> 0` for legacy modulo compatibility.
- Set elements as exact `uint64_t` values; unlike the old code, values
  separated by `2^61-1` remain distinct inputs.
- Diagnostic CLI:
  `--k`, `--m`, `--set-size`, `--trials`, `--seed`, and comma-separated
  `--jaccard-grid`.

### Outputs

- `k` deterministic 64-bit ranks per element.
- A deterministic MinHash signature containing the minimum rank per
  coordinate.
- Model string `sha256-random-ranking-poc-v1`.
- Diagnostic CSV:

```text
estimator_model,k,m,set_size,target_jaccard,realized_jaccard,
intersection_size,trials,seed,
mean_raw_rank_estimate,raw_rank_bias,raw_standard_error,
mean_bucket_match_probability,
mean_bias_corrected_estimate,corrected_bias,corrected_mae,
corrected_sample_sd,corrected_standard_error,corrected_bias_limit,
raw_passed,corrected_passed
```

`m` has one exact meaning: after full 64-bit minima are formed, the diagnostic
applies the deployed one-hot comparison `sig[i] % m`. It reports:

```text
raw_rank_estimate = count(sigA[i] == sigB[i]) / k
bucket_match_probability = count(sigA[i] % m == sigB[i] % m) / k
corrected_estimate =
  clamp((bucket_match_probability - 1/m) / (1 - 1/m), 0, 1)
```

Acceptance applies to the raw-rank and corrected estimates, never to the
uncorrected bucket-match probability. The latter intentionally contains about
`(1-J)/m` collision bias under the PoC model.

## Phase 0 — Add the cross-work approval-record verifier

### Files

- Add: `scripts/verify_work_approval.py`
- Add: `tests/scripts/test_verify_work_approval.py`
- Modify: `CMakeLists.txt`

### Contract and RED tests

The Python-standard-library-only tool accepts mandatory `--work-id`,
`--expected-base`, `--plan-path`, `--gpt`, `--fable`, optional `--repo`, and
`--print-head`. It requires each record to
contain exactly once:

```text
work_id,base_commit,head_commit,plan_blob_sha256,diff_sha256,
reviewer_model,reviewer_instance_id,fallback_reason,
fallback_evidence_path,fallback_evidence_sha256,verdict
```

Commits are full lowercase 40-hex, SHA values full lowercase 64-hex,
reviewers are the expected independent canonical models, and verdict is
exactly `APPROVE`. Both files bind the same work/base/head/plan/diff. The tool
requires `base_commit == --expected-base`, resolves both commits, requires a
nonempty direct ancestor diff, recomputes
`SHA256(git diff --binary --full-index base..head)`, and verifies the tracked
plan blob at `--plan-path` in the base commit. `plan_blob_sha256` is the SHA
of those exact base-commit bytes, and the blob at head must be byte-identical;
a Work cannot approve a plan it modified. It prints the head only after every
check succeeds and prints nothing on failure.

The primary record must be `reviewer_model=gpt-5.6-sol`. The secondary must be
`claude-fable-5` with empty `fallback_reason`; only when a recorded Fable call
failed with the authorized session-limit/unavailable condition may it be an
independent `gpt-5.6-sol` record with
`fallback_reason=FABLE_UNAVAILABLE`. In the normal Fable case both
`fallback_evidence_*` fields are empty. In the fallback case both records
name the same canonical regular file beneath `REVIEW_STAGING_ROOT` and its
SHA-256. The verifier derives `REVIEW_STAGING_ROOT` as the canonical common
parent of the two approval-record paths and requires both records plus the
failure artifact to be canonical regular files beneath it. Approval records
are direct children; the artifact path is exactly
`fallback/<fallback_evidence_sha256>.tsv`, with no symlink in either
component. Absolute paths, `.`, `..`, extra components, a non-regular final
file, or canonical escape are rejected. It never depends on an exported shell variable.

The failure artifact is UTF-8 two-column TSV with keys in this exact order:
`schema_version=piccard-fable-failure-v1`, `requested_model=claude-fable-5`,
`provider=anthropic`, `timestamp_utc=<RFC3339 Z>`,
`http_status=429|503`,
`error_code=session_limit|rate_limit|service_unavailable`,
`response_body_sha256=<64hex>`, and
`response_body_base64=<canonical RFC4648>`. Allowed pairs are
`429/(session_limit|rate_limit)` or `503/service_unavailable`; decoded body
bytes must hash exactly and contain the corresponding provider error class.
The read-only artifact is the captured provider call result. The verifier rejects a
symlink, writable or outside-root file, wrong digest, unrecognized error
class, or missing artifact; a self-declared fallback reason never suffices.
The two nonempty
`reviewer_instance_id` values must differ. Claude Opus is never accepted as a
reviewer.

Fake-repository tests reject missing/duplicate/extra machine fields, short
SHAs, mismatched reviewers/ranges/hashes, empty diff, non-ancestor head,
wrong Work, multiple verdicts, and writable/truncated record files. Run:
Also reject a correct-looking record whose base is any ancestor other than
the explicit expected base, wrong/missing plan path, changed plan blob, or
missing/mismatched fallback evidence.

```bash
python3 -m unittest tests.scripts.test_verify_work_approval -v
```

Expected RED: module absent. GREEN registers the suite with CTest. Pass only
when valid independent record fixtures print the exact head and every negative
fixture exits nonzero with empty stdout. This utility is workflow plumbing,
does not touch Paper, and is used to gate every later Work dependency.

## Phase 1 — Lock the byte-level hash contract

### Files

- Modify: `CMakeLists.txt`
- Modify: `include/core/minhash.h`
- Modify: `src/core/minhash.cpp`
- Modify: `include/util/params.h`
- Modify: `include/protocol/piccard_engine.h`
- Modify: `src/protocol/piccard_engine.cpp`
- Modify: `tests/unit/test_minhash.cpp`
- Add: `tests/unit/test_piccard_engine_legacy_compile.cpp`

- Modify: `CMakeLists.txt`
- Modify: `include/core/minhash.h`
- Modify: `src/core/minhash.cpp`
- Modify: `tests/unit/test_minhash.cpp`

### RED test

Add tests that require:

1. constructor rejection for `hash_range == 0`;
2. exact known-answer ranks for at least:
   `(seed=0,i=0,x=0)`, `(42,7,UINT64_MAX)`, and
   `(20260729,127,2^61-1)`;
3. different coordinates, seeds, and full-width elements produce different
   ranks;
4. `x` and `x+(2^61-1)` are no longer forced equal;
5. the existing empty-set and signature-size contracts remain intact.

Known-answer values must be generated once with an independent SHA-256 tool
over the exact bytes and written as hexadecimal constants. The test must not
call production serialization helpers to build its oracle.

Run:

```bash
cmake --build build -j4 --target test_minhash
./build/test_minhash --gtest_filter='MinHasher.Sha256*'
```

Expected RED output: new SHA-256 contract tests fail against the affine
implementation; the command exits nonzero.

### GREEN implementation

- Make OpenSSL Crypto a required dependency of `piccard_core`.
- Remove coefficient expansion and Mersenne arithmetic from `MinHasher`.
- Encode the fixed ASCII domain, seed, coordinate, and element in network byte
  order.
- Use the non-deprecated OpenSSL EVP digest interface.
- Interpret digest bytes `[0..7]` as a big-endian rank.
- Apply `% hash_range` only when the range is finite.
- Expose a constexpr/static model-name accessor without allocating per hash.
- Rewrite `PiccardParams::hash_range/hash_seed` comments to specify the public
  SHA-256 random-ranking CRS, with no affine/Mersenne semantics.
- Keep the exported legacy `PiccardEngine` source buildable by forwarding
  `hash_seed` to its MinHasher/BottomStructure construction sites. Its
  threshold method bodies remain byte-identical; a compile/link target makes
  this formerly unlinked source part of the gate.

### Pass conditions

- Focused tests pass.
- Two consecutive runs produce identical known-answer ranks.
- A Release build has no new deprecation or conversion warning.
- `MinHasher` contains no `std::mt19937`, affine coefficient, or Mersenne-prime
  path.
- A repository-wide construction/stale-semantics check covers tracked public
  headers and every tracked MinHasher/BottomStructure call site; the legacy
  engine compile/link target passes with the new arity.

## Phase 2 — Preserve static/dynamic/baseline parity

### Files

- Modify: `tests/unit/test_minhash.cpp`
- Modify: `tests/unit/test_bottom_structure.cpp`
- Modify: `tests/unit/test_dynamic_engine.cpp`
- Modify: `tests/unit/test_bcg12.cpp`
- Modify only if required: `src/core/bottom_structure.cpp`
- Modify only if required: `src/baselines/bcg12.cpp`

### RED tests

Add properties:

1. `ComputeSignature(set)[i]` equals the minimum of
   `ComputeElementHashes(x)[i]` over the set.
2. A `BottomStructure` initialized from a set has exactly the same signature
   as `MinHasher`.
3. `Initialize(prefix)+Insert(suffix)` equals initialization from the union.
4. A custom seed propagates through static, dynamic, and BCG12 MinHash modes.
5. Duplicate inputs do not change the signature.
6. Full-width values, including `UINT64_MAX`, are preserved across paths.

Run:

```bash
cmake --build build -j4 --target \
  test_minhash test_bottom_structure test_dynamic_engine test_bcg12
ctest --test-dir build --output-on-failure \
  -R 'MinHash|BottomStructure|DynamicEngine|Bcg12'
```

Expected RED output: the old Mersenne-invariance tests or new full-width parity
tests fail until their assumptions are updated.

### GREEN implementation

No duplicate SHA-256 implementation is allowed. If a dependent path needs an
adapter, it must call `MinHasher`. Delete or rewrite old tests that assert
Mersenne reduction; do not weaken unrelated correctness tests.

### Pass conditions

- All four focused test executables pass.
- `rg` over production `include/core` and `src/core` finds exactly one domain
  string and one rank-generation implementation; the independent test oracle
  may repeat the domain bytes.
- Static and dynamic signatures match bit-for-bit for the same set/seed.
- BCG12 MinHash mode records/uses the same seed and model.

## Phase 3 — Add estimator provenance to benchmark rows

### Files

- Modify: `benchmarks/benchmark_utils.h`
- Modify: `benchmarks/bench_piccard.cpp`
- Modify: `benchmarks/bench_onehot_sqrt.cpp`
- Modify: `benchmarks/bench_dynamic.cpp`
- Modify: `benchmarks/bench_comparison.cpp`
- Modify: `benchmarks/bench_crossover.cpp`
- Modify: `benchmarks/bench_sqrt_comparison.cpp`
- Add: `benchmarks/benchmark_estimator_provenance.h`
- Add: `benchmarks/benchmark_estimator_provenance.cpp`
- Modify: `tests/unit/test_benchmark_utils.cpp`
- Add: `tests/unit/test_estimator_provenance_serializers.cpp`
- Modify: `CMakeLists.txt`
- Modify as required: `scripts/summarize_results.py`

### RED tests

First factor provenance/defaulting and each non-threshold row serializer into
the shared helper rather than TU-local writers. Require every non-threshold
MinHash-using row to emit a nonempty
`estimator_model=sha256-random-ranking-poc-v1`; exact BCG12 and SJ16 rows must
emit `not-applicable`, never the Piccard estimator model.
Golden serializer fixtures cover Piccard, onehot/sqrt, dynamic, comparison,
crossover (both arms), and sqrt-comparison headers/rows directly through the
production helper. `bench_threshold.cpp` and its schema are explicitly
deferred/unchanged with threshold-fpfn; Work 2 keeps a byte-identical
compatibility golden rather than adding provenance there.

Run:

```bash
cmake --build build -j4 --target \
  test_benchmark_utils test_estimator_provenance_serializers
./build/test_benchmark_utils
./build/test_estimator_provenance_serializers
```

Expected RED output: CSV header/row schema tests fail because the field does
not exist.

### GREEN implementation

Append the estimator field to CSV schemas to avoid silently changing existing
column positions. Set it at row construction, not inside the CSV writer.
Update summaries only where they consume or verify provenance; do not invent a
paper claim.
The helper is the stable extension point. Work 2 and Work 4 explicitly own
later sanitizer/profile extensions to these same two files and their golden
serializer tests; downstream producers may not fork a second serializer.

### Pass conditions

- Header and row column counts are identical.
- MinHash rows contain the exact model string.
- Non-MinHash rows contain `not-applicable`.
- Existing dispersion/hash-seed/flooding columns retain their meaning.

## Phase 4 — Add deterministic empirical bias diagnostic

### Files

- Add: `benchmarks/bench_estimator_bias.cpp`
- Add: `benchmarks/estimator_diagnostic.h`
- Add: `benchmarks/estimator_diagnostic.cpp`
- Add: `tests/unit/test_estimator_diagnostic.cpp`
- Modify: `CMakeLists.txt`

### RED tests

Factor pure aggregation/grid logic so it can be tested without a long run.
Test:

- exact Jaccard generation for `0`, `0.5`, and `1`;
- deterministic repeated output for a fixed seed;
- correct CSV field count and finite statistics;
- `J=1` yields estimate `1`, zero bias, and zero MAE;
- invalid `m`, trials, set size, or grid points fail nonzero.
- pinned seed KATs for root 20260729:
  `(grid=0,trial=0)->0x4233064eb10c5c9b`,
  `(3,7)->0x5c7c90995424145b`, and
  `(6,9999)->0xf4f5bd3387a71db3`.

Run:

```bash
cmake --build build -j4 --target test_estimator_diagnostic
./build/test_estimator_diagnostic
```

Expected RED output: target or API is absent.

### GREEN implementation

The executable runs at least 10,000 fixed-seed trials per point for the
acceptance profile:

```bash
./build/bench_estimator_bias \
  --k=128 --m=64 --set-size=1000 --trials=10000 \
  --seed=20260729 --jaccard-grid=0,0.1,0.25,0.5,0.75,0.9,1
```

Use independent CRS seeds derived deterministically from the root seed. For
each trial compute the raw-rank, modulo-`m` bucket, and corrected estimates
defined above. Report observations, never “proof” or “unbiased theorem.”

`set_size=n` means each set has exactly n elements. Parse each grid decimal as
an exact reduced rational `p`; choose
`intersection=round_nearest_ties_down(2*n*p/(1+p))`. Construct A as
`{0,...,n-1}` and B as the first `intersection` common elements plus
`n-intersection` unique values starting at `n`. Record both requested
`target_jaccard` and
`realized_jaccard=intersection/(2*n-intersection)` plus
`intersection_size`; all bias/error gates use the realized value. Thus
nonrepresentable points such as n=1000,J=0.5 are deterministic and are never
silently called exact.
`raw_rank_bias=mean_raw_rank_estimate-realized_jaccard` and
`corrected_bias=mean_bias_corrected_estimate-realized_jaccard`.

For grid index g and trial r, the MinHasher seed is
`first8BE(SHA256("piccard-estimator-trial-v1" || 0x00 ||
BE64(root_seed) || BE32(g) || BE64(r)))`; the KATs above are generated by an
independent oracle. `estimator_diagnostic.{h,cpp}` owns set construction, seed
derivation, and aggregation and is linked by both executable and unit test.
For T trials, means and MAE divide by T; sample SD divides by T-1 (empty for
T=1); standard error is sample SD/sqrt(T). All CLI acceptance runs require
T>=2.

### Pass conditions

- The command exits zero and emits eight lines including the header.
- Every row records the fixed model, trial count, and root seed.
- Estimates lie in `[0,1]`; all statistics are finite.
- `J=1` is exact.
- For non-degenerate points, both deterministic checks satisfy
  `abs(raw_rank_bias) <= max(0.01, 4*raw_standard_error)` and
  `abs(corrected_bias) <= max(0.01, 4*corrected_standard_error)`.
  The fixed 0.01 floor accommodates finite-k clamping bias near J=0/1; the
  uncorrected bucket probability is not gated. A failure is a diagnostic
  blocker, not a tolerance-relaxation trigger.

## Work-level verification

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
ctest --test-dir build --output-on-failure
python3 -m unittest tests.scripts.test_verify_work_approval -v
./build/bench_estimator_bias \
  --k=128 --m=64 --set-size=1000 --trials=10000 \
  --seed=20260729 --jaccard-grid=0,0.1,0.25,0.5,0.75,0.9,1 \
  > /tmp/piccard-estimator-bias.csv
```

Review artifacts: full diff, test logs, diagnostic CSV, and a search showing
removal of the affine/Mersenne implementation. Work 2 may start only after
GPT-5.6-sol and either Fable or the verifier-authorized independent GPT
fallback both return `APPROVE`; their byte-fixed records are
written as `$REVIEW_STAGING_ROOT/work-1-{gpt,fable}.md`, made read-only, and
this command prints the exact Work-1 head:

```bash
python3 scripts/verify_work_approval.py --work-id=1 \
  --expected-base="$PLANNING_COMMIT" \
  --plan-path=docs/superpowers/plans/2026-07-29-01-estimator-random-ranking-poc.md \
  --gpt="$REVIEW_STAGING_ROOT/work-1-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-1-fable.md" --print-head
```
