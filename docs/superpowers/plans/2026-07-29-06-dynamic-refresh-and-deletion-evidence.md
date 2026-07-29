# Work 6 — Versioned Dynamic Refresh and Deletion-Survival Evidence

> **Implementation owner:** Claude Opus 5  
> **Plan reviewer:** Claude Fable 5  
> **Work completion reviewers:** GPT-5.6-sol and Claude Fable 5  
> **Dependency:** Work 5 approved  
> **Next work:** pre-threshold integration

## Objective

Complete the supported bounded-dynamic path as one owner's full re-encryption
and atomic versioned cloud replacement. Add reproducible ideal-random-ranking
analytic and Monte Carlo deletion evidence with correct safe-deletion versus
failure-time conventions. Ciphertext delta updates remain explicitly
unsupported.

## Inputs and outputs

At work start, read and validate the full `WORK5_HEAD` commit from Work 5's
two immutable external approval records:

```bash
set -euo pipefail
test -n "${REVIEW_STAGING_ROOT:?set by the approved planning commit}"
test -n "${PLANNING_COMMIT:?approved planning commit}"
WORK1_HEAD="$(python3 scripts/verify_work_approval.py --work-id=1 \
  --expected-base="$PLANNING_COMMIT" \
  --plan-path=docs/superpowers/plans/2026-07-29-01-estimator-random-ranking-poc.md \
  --gpt="$REVIEW_STAGING_ROOT/work-1-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-1-fable.md" --print-head)"
WORK2_HEAD="$(python3 scripts/verify_work_approval.py --work-id=2 \
  --expected-base="$WORK1_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-02-sanitizer-security-profile-poc.md \
  --gpt="$REVIEW_STAGING_ROOT/work-2-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-2-fable.md" --print-head)"
WORK3_HEAD="$(python3 scripts/verify_work_approval.py --work-id=3 \
  --expected-base="$WORK2_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-03-std128-std192-calibration.md \
  --gpt="$REVIEW_STAGING_ROOT/work-3-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-3-fable.md" --print-head)"
WORK4_HEAD="$(python3 scripts/verify_work_approval.py --work-id=4 \
  --expected-base="$WORK3_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-04-benchmark-profiles-and-baseline-gates.md \
  --gpt="$REVIEW_STAGING_ROOT/work-4-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-4-fable.md" --print-head)"
WORK5_GPT="$REVIEW_STAGING_ROOT/work-5-gpt.md"
WORK5_FABLE="$REVIEW_STAGING_ROOT/work-5-fable.md"
test -f "$WORK5_GPT" -a ! -w "$WORK5_GPT"
test -f "$WORK5_FABLE" -a ! -w "$WORK5_FABLE"
python3 scripts/verify_work_approval.py \
  --work-id=5 --expected-base="$WORK4_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-05-real-dataset-pipeline.md \
  --gpt="$WORK5_GPT" --fable="$WORK5_FABLE"
WORK5_HEAD="$(python3 scripts/verify_work_approval.py \
  --work-id=5 --expected-base="$WORK4_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-05-real-dataset-pipeline.md \
  --gpt="$WORK5_GPT" --fable="$WORK5_FABLE" \
  --print-head)"
test "$(git rev-parse "$WORK5_HEAD^{commit}")" = "$WORK5_HEAD"
test "$(git rev-parse HEAD)" = "$WORK5_HEAD"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Work 5 creates those records only after both reviewers approve. Each uses the
Plan-7 machine-readable schema, contains a full 40-hex head and one
`verdict: APPROVE`, and binds the same Work-5 base/head/plan/diff hashes.
`verify_work_approval.py` is implemented and tested in Work 1 Phase 0,
rejects missing/empty/short/mismatched/multiple fields, and exits nonzero
without printing a head on failure. Every exclusion diff below uses this
validated immutable SHA.

### Dynamic refresh input

- owner/set identifier;
- expected epoch `e`;
- destination epoch exactly `e+1`;
- hash seed and estimator model;
- cryptographic profile fingerprint;
- non-null freshly encrypted full feature ciphertext.

### Dynamic refresh output

- `Applied`, `StaleEpoch`, or `FutureEpoch`;
- observed current epoch;
- immutable pair snapshot;
- benchmark phase timings and serialized upload bytes.

### Deletion analysis input

```text
n=set_size, d=bottom_depth, k=hash_count,
required_survival, trials, seed
```

### Deletion analysis output

- exact survival `S(r)`;
- union-bound lower survival;
- maximum safe deletions;
- expected first failure time and expected safe deletions;
- seeded MC survival/mean/error; and
- model label `ideal-independent-random-ranking-v1`.

## Phase 1 — Expose bottom-structure exhaustion explicitly

### Files

- Modify: `include/core/bottom_structure.h`
- Modify: `src/core/bottom_structure.cpp`
- Modify: `tests/unit/test_bottom_structure.cpp`
- Modify: `tests/unit/test_dynamic_engine.cpp`

### RED tests

Require:

- `RequiresRebuild()` is true before initialization;
- false after valid nonempty initialization;
- true after one hash bucket is exhausted;
- `GetSignature()` and `DynamicPiccard::Encrypt()` give a rebuild-required
  error when exhausted;
- unaffected valid structures retain current signatures.
- migrate `ManyMutationsStillProducesValidResult`: exhausting all original
  candidates must now assert sticky failure; insertion does not clear it,
  empty/failed `Initialize()` does not clear it, and a successful full
  nonempty `Initialize()` restores operation.

Run:

```bash
cmake --build build -j4 --target test_bottom_structure test_dynamic_engine
./build/test_bottom_structure --gtest_filter='*Rebuild*'
./build/test_dynamic_engine --gtest_filter='*Exhausted*'
```

Expected RED output: method/explicit state absent.

### GREEN implementation

Use a private sticky `requires_rebuild_` flag. `Initialize()` resets it only
after rebuilding every bucket; any deletion that empties a bucket sets it.
While set, `Insert`, `Delete`, `GetSignature`, and encryption reject until a
new full `Initialize()` occurs. A later insertion must not clear exhaustion,
because previously discarded candidates are unavailable.

### Pass conditions

- Focused and full bottom/dynamic tests pass.
- Existing insert/delete/signature behavior remains unchanged.

## Phase 2 — Add a versioned atomic cloud ciphertext store

### Files

- Add: `include/protocol/dynamic_ciphertext_store.h`
- Add: `src/protocol/dynamic_ciphertext_store.cpp`
- Add: `tests/unit/test_dynamic_ciphertext_store.cpp`
- Modify: `include/fhe/bfv_context.h`
- Modify: `src/fhe/bfv_context.cpp`
- Add: `tests/unit/test_bfv_context_fingerprint.cpp`
- Modify: `CMakeLists.txt`

### Envelope

```cpp
struct VersionedCiphertext {
  std::string owner_id;
  uint64_t epoch;
  uint64_t hash_seed;
  std::string estimator_model;
  uint32_t k;
  uint32_t m;
  uint64_t hash_range;
  std::string encoding_model;
  std::string crypto_context_fingerprint;
  std::string public_key_fingerprint;
  std::string ciphertext_key_tag;
  std::vector<uint8_t> serialized_ciphertext;
};
```

`BFVContext` supplies a SHA-256 context fingerprint over canonical realized
parameters only, a separate public-key fingerprint, and strict
serialize/deserialize helpers. The store owns immutable serialized bytes rather than OpenFHE's
shared-pointer-backed mutable `Ciphertext`. Evaluation deserializes against the
live context and verifies the fingerprint first.

Fingerprint bytes are canonical:

```text
SHA256("piccard-bfv-context-v1" || 0x00 ||
  BE32(security_enum) || BE64(plaintext_modulus) || BE32(ring_dim) ||
  BE32(mult_depth) || BE32(scaling_mod_size) || BE32(num_limbs) ||
  for each active modulus in tower order:
    BE32(big_endian_modulus_length) || big_endian_modulus)
```

`public_key_fingerprint` is SHA-256 over domain
`piccard-bfv-public-key-v1`, NUL, and the exact binary public-key
serialization. The ciphertext's OpenFHE key tag must equal the live key tag.
`SerializeCiphertext()` rejects null; `DeserializeCiphertext()` rejects
empty/corrupt/trailing bytes, requires exact stream consumption, the active
context fingerprint, public-key fingerprint, and live key tag, then
round-trips byte-identically in tests.

The public codec has this complete callable interface:

```cpp
class PublicCiphertextCodec final {
 public:
  const std::string& ContextFingerprintHex() const noexcept;
  const std::string& PublicKeyFingerprintHex() const noexcept;
  const std::string& CiphertextKeyTag() const noexcept;
  std::vector<uint8_t> Serialize(const Ciphertext& ciphertext) const;
  Ciphertext Deserialize(const std::vector<uint8_t>& bytes) const;
  void ValidateEnvelope(const VersionedCiphertext& envelope) const;
};
```

All fingerprint getters return exactly 64 lowercase hex characters;
`CiphertextKeyTag()` returns the nonempty OpenFHE tag verbatim. `Serialize`
rejects null and `Deserialize` performs the strict parsing, exact-consumption,
live-context/key-tag checks, and byte-identical reserialization described
above. `ValidateEnvelope` checks all three public bindings and calls
`Deserialize`; it has no decrypt/evaluation/secret-key accessor.

`BFVContext::ExportPublicCiphertextCodec()` returns a
`shared_ptr<const PublicCiphertextCodec>` that owns only the OpenFHE public
crypto context/public key plus immutable context fingerprint, public-key
fingerprint, and key tag—never the secret key. The store takes and retains
this shared pointer, so validation lifetime is explicit and cannot dangle.
Export before successful context/key initialization throws `logic_error`;
the store constructor rejects a null codec before inspecting either envelope.
Constructor/replacement tests independently distinguish wrong envelope key
tag, wrong public-key fingerprint, and a serialized payload whose internal
key tag is wrong.

The store is initialized exactly once by its constructor and provides:

```cpp
enum class ReplaceStatus { Applied, StaleEpoch, FutureEpoch };
struct ReplaceOutcome {
  ReplaceStatus status;
  uint64_t observed_epoch;
};
struct CloudCiphertextPair {
  VersionedCiphertext first;
  VersionedCiphertext second;
};

DynamicCiphertextStore(
  std::shared_ptr<const PublicCiphertextCodec> codec,
  VersionedCiphertext first,
  VersionedCiphertext second);

ReplaceOutcome TryReplace(
  std::string_view owner_id,
  uint64_t expected_epoch,
  VersionedCiphertext replacement);

CloudCiphertextPair ReadPair() const;
```

Rules:

- constructor requires two distinct nonempty owners, both epoch zero, and
  equality of seed, estimator, `k`, `m`, hash range, encoding model, context,
  public key, and key tag; it fully validates/deserializes both envelopes.
- before locking, structurally validate nonempty fields/payload, live
  context/key/tag, exact serialization, `expected_epoch != UINT64_MAX`, and
  `replacement.epoch == expected_epoch+1`;
- under lock, resolve the owner (unknown throws), validate all immutable slot
  bindings, then compare epochs in this exact order:
  `expected < current -> StaleEpoch`,
  `expected > current -> FutureEpoch`,
  `expected == current -> atomically replace and Applied`;
- `observed_epoch` is the locked current epoch before apply for stale/future
  and the destination epoch after apply;
- constructor is the only initialization; no second-initialize API exists;
- failed replacement changes no field;
- read returns one consistent pair snapshot under a mutex.

### RED tests

Test constructor initialization, all initial-pair mismatch cases, single-owner
`0->1`, replay, skipped destination epoch
throw, wrong owner/CRS/model/context/public-key tag, empty/corrupt payload,
trailing bytes, null serialization, overflow at expected/destination,
unchanged peer, failed-state immutability, snapshot ownership after
caller-byte mutation, and a bounded reader/writer stress test. Also test null
codec rejection, export-before-initialization failure, exact lowercase
fingerprint encodings, public-codec lifetime after the creating `BFVContext`
object is destroyed, and compile-time absence of decrypt/secret-key methods.

Run:

```bash
cmake --build build -j4 --target test_dynamic_ciphertext_store
./build/test_dynamic_ciphertext_store
```

Expected RED output: store/target absent.

### Pass conditions

- Every transition matches the contract.
- Reader snapshots are internally consistent.
- No delta/additive ciphertext API exists.

## Phase 3 — Add single-owner full-refresh E2E

### Files

- Add: `tests/integration/test_dynamic_refresh_e2e.cpp`
- Modify: `CMakeLists.txt`
- Modify only if a minimal adapter is needed:
  `include/protocol/dynamic_piccard.h`,
  `src/protocol/dynamic_piccard.cpp`

### Test flow

1. Build A/B bottom structures and encrypt each once at epoch zero.
2. Install both ciphertexts in the store.
3. Evaluate/decrypt the stored pair.
4. Mutate A only using the deterministic independent-oracle fixture below.
5. Confirm the cloud still returns the old result before refresh.
6. Recompute A signature/encoding and freshly encrypt one full ciphertext.
7. Replace A `0->1`.
8. Evaluate stored A@1/B@0.
9. Compare exact match count with fresh plaintext local recomputation.
10. Reject replay and confirm result/state unchanged.

Run:

```bash
cmake --build build -j4 --target test_dynamic_refresh_e2e
./build/test_dynamic_refresh_e2e
```

Expected RED output: E2E target/path absent.

### Pass conditions

- Exactly one owner ciphertext is refreshed.
- The unchanged owner is not re-encrypted.
- The fixture scans candidates `max(A)+1..max(A)+1000000` with an independent
  SHA-ranking oracle and chooses the first insertion whose encoded A feature
  and plaintext A/B match count both change; absence is a test failure.
  Assert old match count differs from new, A serialized payload differs,
  updated cloud equals the new plaintext match count, and B's complete
  envelope is byte-identical.
- A second case deterministically deletes a current bucket minimum that has a
  successor, proves non-exhausting promotion changes the feature/result, and
  refreshes successfully.
- Stale replay cannot restore old state.
- Exhausted structures fail before encryption.

## Phase 4 — Measure one-owner refresh and upload payload

### Files

- Add: `benchmarks/dynamic_benchmark_utils.h`
- Add: `tests/unit/test_dynamic_benchmark_utils.cpp`
- Modify: `benchmarks/bench_dynamic.cpp`
- Modify: `scripts/run_pre_threshold_profiles.sh`
- Modify: `tests/scripts/test_run_pre_threshold_profiles.py`
- Modify: `scripts/verify_benchmark_provenance.py`
- Modify: `tests/scripts/test_verify_benchmark_provenance.py`
- Modify: `CMakeLists.txt`

### Appended CSV fields

```text
refresh_owner,refresh_batch_updates,refresh_epoch_before,
refresh_epoch_after,refresh_status,
phase_refresh_update_ms,phase_refresh_update_ms_sd,phase_refresh_update_ms_median,
phase_refresh_signature_ms,phase_refresh_signature_ms_sd,phase_refresh_signature_ms_median,
phase_refresh_encode_ms,phase_refresh_encode_ms_sd,phase_refresh_encode_ms_median,
phase_refresh_encrypt_ms,phase_refresh_encrypt_ms_sd,phase_refresh_encrypt_ms_median,
phase_refresh_serialize_ms,phase_refresh_serialize_ms_sd,phase_refresh_serialize_ms_median,
phase_cloud_replace_ms,phase_cloud_replace_ms_sd,phase_cloud_replace_ms_median,
refresh_total_ms,refresh_total_ms_sd,refresh_total_ms_median,
refresh_upload_bytes,
refresh_ciphertexts_uploaded
```

`refresh_upload_bytes` is binary serialization length. Network transfer latency
is not measured. Local throughput mutations and a real non-reverted refresh
batch are separate scenarios.

Each timing trial starts from the same cloned source sets and a fresh epoch-0
store, inserts exactly `refresh_updates` consecutive values beginning at
`max(initial_set)+1`, never reverts them, and performs one `0->1` replacement.
Aggregation uses the existing mean/SD/median convention. Non-refresh rows leave
numeric refresh fields empty and use `refresh_owner`/`refresh_status` text
`not-applicable`. Refresh rows preserve every Work-4 prefix field and use
`measurement_kind=fhe-timing,measurement_status=measured`. Upload bytes must
be identical across trials; otherwise fail rather than averaging byte counts.
For each trial, `refresh_total_ms` is the sum of update, signature, encode,
encrypt, serialize, and replace. Its mean/SD/median are computed from the
per-trial totals, not component aggregates. Existing dynamic
`total_ms,total_ms_sd,total_ms_median` equal this same triple on refresh rows.

### RED tests

Test header/row count, status/epoch fields, nonnegative phases, upload count
one, payload equality with serialized ciphertext size, and strict parsing of
`--scenario=refresh --refresh_updates=N`. Golden rows test every
mean/SD/median column, Work-4 provenance, and N/A behavior.
Python verifier fixtures include one valid refresh row and reject a missing
total, inconsistent total/component sum, bad epoch/status, missing profile,
or fabricated N/A value.

Run:

```bash
cmake --build build -j4 --target test_dynamic_benchmark_utils
./build/test_dynamic_benchmark_utils
python3 -m unittest \
  tests.scripts.test_verify_benchmark_provenance -v
```

### GREEN smoke

```bash
./build/bench_dynamic \
  --scenario=refresh --mode=timing --profile=toy-smoke --security=TOY \
  --k=16 --m=16 --set_size=100 --depth=5 \
  --refresh_updates=1 --trials=1 --seed=7 \
  > /tmp/piccard-dynamic-refresh.csv
```

Work 4's runner gains one primary refresh command per STD128/STD192 t40
profile at `(k,m,n,d)=(128,64,1000,5)`, `refresh_updates=1`, 30 trials, plus
the exact toy smoke above. It applies immutable `ApplyBenchmarkProfile()`
before context/key generation, sets the runner thread policy, writes beneath
the caller result root, and is pinned in the existing golden argv test.

### Pass conditions

- One row says applied, `0->1`, one ciphertext, positive upload bytes.
- Refreshed result equals fresh reference.
- Existing benchmark modes still pass their tests.
- The old insert-then-delete sequence is not labelled a refresh.

## Phase 5 — Implement exact ideal deletion-survival analysis

### Files

- Add: `include/analysis/deletion_survival.h`
- Add: `src/analysis/deletion_survival.cpp`
- Add: `tests/unit/test_deletion_survival.cpp`
- Modify: `CMakeLists.txt`

### Contract

For first failure time `T` (1-based) and `r` safe completed deletions:

```text
S(r) = Pr[T > r]
     = (1 - C(r,d)/C(n,d))^k
E[T] = sum_{r=0}^{n-1} S(r)
E[safe deletions] = E[T] - 1
```

Calculate the combination ratio as a long-double product and survival through
`log1p`/`exp`. Use monotone binary search for the maximum safe budget.

### RED tests

Require:

- `(n,d,k)=(5,2,1)`: `S(2)=0.9`, `S(3)=0.7`;
- `k=2` squares the one-hash result;
- one-hash order-statistic expectation matches `d(n+1)/(d+1)`;
- union-bound lower survival equals
  `max(0,1-k*C(r,d)/C(n,d))` on small exact fixtures and never exceeds exact
  survival;
- default `(1024,5,128)`:
  - 99% maximum safe deletions `156`;
  - `S(156)=0.9901069701` approximately;
  - `S(157)=0.9897831966` approximately;
  - expected failure time `357.7452319` approximately;
  - expected safe deletions `356.7452319` approximately;
- monotonic/boundary/invalid-input behavior.

Run:

```bash
cmake --build build -j4 --target test_deletion_survival
./build/test_deletion_survival
```

Expected RED output: analysis target absent.

### Pass conditions

- Small exact fixtures pass within `1e-12`.
- Default expectations pass within `1e-8`.
- Off-by-one semantics are separate named assertions.

## Phase 6 — Add reproducible ideal-model Monte Carlo

### Files

- Add: `include/analysis/deletion_monte_carlo.h`
- Add: `src/analysis/deletion_monte_carlo.cpp`
- Add: `tests/unit/test_deletion_monte_carlo.cpp`
- Add: `benchmarks/bench_deletion_survival.cpp`
- Modify: `CMakeLists.txt`

### Simulation

For each hash coordinate, sample a uniform `d`-subset of deletion positions
`1..n` with Floyd sampling. Its maximum is that coordinate's exhaustion time;
the minimum over `k` coordinates is `T`. Use raw `mt19937_64` words with
portable rejection-based `UniformBelow`, not `uniform_int_distribution`.

`UniformBelow(bound)` requires `bound>0`, computes uint64
`threshold = (-bound) % bound`, consumes raw words until `x>=threshold`, and
returns `x % bound`. Floyd iterates `j=n-d+1..n`, samples
`t=UniformBelow(j)+1`, and inserts `j` if `t` already exists, otherwise `t`.

Pinned independent goldens:

```text
seed=20260729, successive bounds/raw/result:
1    0x13abed35ef7208d7 -> 0
2    0xa821398ce4959c44 -> 0
3    0x3ec9d6707639929d -> 2
10   0xb2413cc1f3082f90 -> 8
1024 0x2376e8e55d856132 -> 306
1000 0xc3cb86fe4cb18180 -> 296

n=8,d=2,k=3,trials=16,seed=7:
T sequence = 3,6,2,7,5,5,3,3,3,7,6,5,6,6,6,3
histogram T=0..8 = 0,0,1,5,0,3,5,2,0
```

### CLI

```bash
./build/bench_deletion_survival \
  --n=1024 --d=5 --k=128 \
  --required_survival=0.99 --r_values=156,357,512 \
  --trials=100000 --seed=20260729
```

CSV records exact/union/MC survival and standard error at requested r values,
budget, exact/MC failure and safe-deletion means, config, seed, target
`required_survival`, and model. The union-bound lower survival is exactly
`max(0, 1-k*C(r,d)/C(n,d))`.

### RED tests

Require same-seed bit-identical histogram, histogram total, failure range,
monotone survival, and predeclared statistical checks at r=156,357,512 plus
mean failure time. Pin a golden `UniformBelow` raw-word vector and a small
fixed-seed histogram above to detect drift. MC survival counts exactly
`T > r`, never `T >= r`.

Run:

```bash
cmake --build build -j4 --target test_deletion_monte_carlo
./build/test_deletion_monte_carlo
```

### Pass conditions

- 100,000-trial command exits zero.
- Every selected point satisfies
  `abs(mc-exact) <= 5*sqrt(p(1-p)/trials)+1/trials`.
- Mean is within five sample standard errors.
- Output always says ideal model, never actual-hash proof.
- Core-only analysis and deletion-benchmark targets build and run without
  OpenFHE.

## Work-level verification

### Threshold-exclusion gate files

- Add: `scripts/check_threshold_exclusion.py`
- Add: `scripts/work6_allowed_paths.txt`
- Add: `tests/scripts/test_check_threshold_exclusion.py`
- Modify: `CMakeLists.txt` only to register this Python test and the new
  non-threshold Work-6 targets.

`work6_allowed_paths.txt` is a sorted exact whitelist of every file named by
Work 6 (including the gate files and permitted CMake/runner/provenance shared
files). The checker first rejects every changed path outside it. It then
freezes all base-tracked paths matching case-insensitive
`threshold|fpfn|false.?positive|false.?negative|decision.?boundary`—including
`benchmarks/threshold_csv_schema.h` and
`tests/unit/test_threshold_profile_compat.cpp`—and requires byte-identical
blobs at head, with exactly two path-name exemptions:
`scripts/run_pre_threshold_profiles.sh` and
`tests/scripts/test_run_pre_threshold_profiles.py`. Those two are allowed
only because "pre-threshold" denotes this runner scope; their complete textual
diffs still undergo the semantic scan and whitelist gate. Finally it scans both added and deleted lines in permitted
shared files, case-insensitively, for identifiers including
`ThresholdEngine`, `Compute*Threshold*`, `Decode*Threshold*`,
`Circuit::Threshold`, `ThresholdCSV`, `falsePositiveRate`,
`falseNegativeRate`, `decisionBoundarySweep`, FP/FN count/rate, and
threshold polynomial/tau/mode terms. It uses subprocess return codes directly:
Git/decoder/regex errors are fatal, while only a successful scan with zero
matches passes.

For unavoidable shared production files
`include/fhe/bfv_context.h` and `src/fhe/bfv_context.cpp`, the checker also
uses a brace/comment/string-aware C++ scanner. Every base declaration and
function body must remain byte-identical; the only permitted insertion is the
new `CryptoContextFingerprint()` and `ExportPublicCiphertextCodec()`
declarations, their standalone definitions, and the exact required
`PublicCiphertextCodec` forward-declaration/include lines at declared
class/namespace/include anchors. The new codec definition may read existing
initialized public-context/public-key members but may not alter their
initialization or any existing body. Additions inside any pre-existing
function body are rejected. Work-6 BFV tests live in the new dedicated
`test_bfv_context_fingerprint.cpp`, so the existing mixed
`test_bfv_context.cpp` is frozen byte-for-byte. CMake and the two runner files
likewise use exact allowed-line templates limited to named Work-6
targets/refresh argv; all other pre-existing lines remain byte-identical.

The test invokes the production checker against temporary Git repositories.
It covers uppercase/lowercase additions and deletions in CMake, a shared
header, and a shared source; forbidden new paths; every protected existing
artifact; a permitted refresh-only edit to each of the two exempt
pre-threshold runner paths; and one unrelated allowed change. Thus the mutation fixture tests
the exact deployed gate, not copied prose.
It also changes a protected body condition such as `x >= 2` to `x >= 3`
without adding a threshold token and proves rejection, while the standalone
fingerprint declaration/definition passes.
The positive fixture also compiles and accepts the exact public-codec
declaration/definition/forward-declaration additions while rejecting any
extra BFV method or body edit.

```bash
set -euo pipefail
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
ctest --test-dir build --output-on-failure
./build/bench_dynamic \
  --scenario=refresh --mode=timing --profile=toy-smoke --security=TOY \
  --k=16 --m=16 --set_size=100 --depth=5 \
  --refresh_updates=1 --trials=1 --seed=7
./build/bench_deletion_survival \
  --n=1024 --d=5 --k=128 --required_survival=0.99 \
  --r_values=156,357,512 --trials=100000 --seed=20260729

CORE_BUILD="$(mktemp -d)"
cmake -S . -B "$CORE_BUILD" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_DISABLE_FIND_PACKAGE_OpenFHE=TRUE
cmake --build "$CORE_BUILD" -j4 --target \
  test_deletion_survival test_deletion_monte_carlo \
  bench_deletion_survival
"$CORE_BUILD/test_deletion_survival"
"$CORE_BUILD/test_deletion_monte_carlo"
"$CORE_BUILD/bench_deletion_survival" \
  --n=64 --d=3 --k=8 --required_survival=0.99 \
  --r_values=1,4,8 --trials=1000 --seed=7

python3 -m unittest \
  tests.scripts.test_verify_benchmark_provenance \
  tests.scripts.test_run_pre_threshold_profiles \
  tests.scripts.test_check_threshold_exclusion -v

test -n "${WORK5_HEAD:?validated at Work-6 start}"
test "$WORK5_HEAD" = "$(git rev-parse "$WORK5_HEAD^{commit}")"
CANDIDATE_HEAD="$(git rev-parse HEAD)"
test "$CANDIDATE_HEAD" = "$(git rev-parse "$CANDIDATE_HEAD^{commit}")"
test -z "$(git status --porcelain=v1 --untracked-files=all)"

python3 scripts/check_threshold_exclusion.py \
  --base="$WORK5_HEAD" --head="$CANDIDATE_HEAD" \
  --allowed-paths=scripts/work6_allowed_paths.txt
```

The exact threshold-owned path diff must be empty. The supplemental scan
examines both additions and deletions and covers threshold executable/test
registration, circuit enum/schema/mode/tau identifiers, and FP/FN semantics
in every shared file including CMake. Its fixture mutates each listed token in
`CMakeLists.txt` and a shared header and proves rejection, while an unrelated
new target passes. The runner golden must prove no threshold command/schema.
Invalid/unset `WORK5_HEAD`, dirty/untracked candidate state, Git failure, or
`rg` error is fatal.

Review artifacts: state-machine tests, E2E refresh log, refresh CSV, analytic
fixtures, and MC CSV. Work 7 starts only after GPT-5.6-sol and Fable both
approve the nonempty `WORK5_HEAD..WORK6_HEAD` diff, the read-only
`$REVIEW_STAGING_ROOT/work-6-{gpt,fable}.md` files pass
`verify_work_approval.py --work-id=6 --expected-base="$WORK5_HEAD"
--plan-path=docs/superpowers/plans/2026-07-29-06-dynamic-refresh-and-deletion-evidence.md`,
and clean `HEAD==WORK6_HEAD`.
