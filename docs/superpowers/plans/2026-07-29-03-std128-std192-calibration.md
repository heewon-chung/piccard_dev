# Work 3 — STD128/STD192 Noise Calibration and Profile Matrix

> **Implementation owner:** Claude Opus 5  
> **Plan reviewer:** Claude Fable 5  
> **Work completion reviewers:** GPT-5.6-sol and Claude Fable 5  
> **Dependency:** Work 2 approved  
> **Next work:** benchmark and baseline gates

## Objective

Produce a reproducible calibration path for non-threshold OneHot and Sqrt
circuits at STD128 and STD192 under transcript profiles 40, 64, and 128. Adopt
only measured, non-saturated rows and record both requested and realized
cryptographic parameters. The full revision profile is transcript 40;
transcript 64 is representative sensitivity; transcript 128 is feasibility
only.

## Dependency gate

```bash
WORK2_HEAD="$(python3 scripts/verify_work_approval.py --work-id=2 \
  --expected-base="$WORK1_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-02-sanitizer-security-profile-poc.md \
  --gpt="$REVIEW_STAGING_ROOT/work-2-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-2-fable.md" --print-head)"
test "$(git rev-parse HEAD)" = "$WORK2_HEAD"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

## Inputs and outputs

### Calibration inputs

- Circuits: `onehot`, `sqrt`; `threshold` is rejected by this runner.
- Computational security: `STD128`, `STD192`.
- Transcript profile:
  - primary: `40`, `Q=1048576`, margin `8`;
  - sensitivity: `64`, same Q/margin;
  - feasibility: `128`, same Q/margin.
- Patterns: `all_match`, `no_match`, `random`.
- Fresh-encryption repetitions: minimum `5` per cell.
- Root seed: `20260729`.
- Search dimensions: natural depth plus bounded extra depth, scaling-modulus
  sizes, and explicitly enumerated permitted ring dimensions.

### Outputs

Aggregate candidate CSV includes:

```text
profile,circuit,shape_id,security,consumer_count,consumer_set_sha256,
worst_consumer_k,worst_consumer_m,pattern_count,repetitions_per_pattern,
detail_row_count,detail_sha256,seed,
requested_ring_dim,natural_ring_dim,realized_ring_dim,ring_growth_factor,
ring_dim_calibrated,
natural_depth,provisioned_depth,scaling_mod_size,num_limbs,
plaintext_mod,log_q,log_delta,eval_noise_bits,headroom_bits,
max_queries,query_stat_bits,coefficient_stat_bits,
flood_margin_bits,flood_noise_bits,
decrypt_ok,saturated,ct_bytes,openfhe_version,source_commit,
status_code,error_message,consumer_results_sha256
```

The separate detail CSV has the exact prefix
`profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,consumer_m,
pattern,rep_index,rep_seed,requested_ring_dim,natural_ring_dim,
ring_dim_calibrated` followed by the same measured context/noise/status fields
as the aggregate. Rows are sorted bytewise by
`(key_id,candidate_id,consumer_k,consumer_m,pattern,rep_index)`. There is one
separate detail CSV per candidate; its header plus exactly that candidate's
canonical rows are the bytes hashed by `detail_sha256` (never an ambiguous
slice of a key-level file). For a complete candidate, `pattern_count=3`,
`repetitions_per_pattern=5`,
`detail_row_count=consumer_count*3*5`. Context/provenance fields must be
identical across detail rows; `eval_noise_bits=max`,
`headroom_bits=min`, `decrypt_ok=logical-AND`, `saturated=logical-OR`, and
`ct_bytes=max`. Aggregate failure precedence is
`PROCESS_ERROR > TIMEOUT > CONTEXT_ERROR > DECRYPT_FAIL > SATURATED > OK`;
any non-OK detail makes the aggregate non-OK and ineligible. The
`consumer_results_sha256` hashes the canonical tuple of each consumer's
per-field reductions/status. Exact row counts and both hashes are revalidated
at resume/finalization.

`shape_id` identifies only the circuit layout (`onehot-v1` or
`sqrt-b<sqrt_base>-v1`); consumer-set identity belongs only to
`consumer_set_sha256`. `profile` is the exact `profile_id`; neither is inferred
from a filename.

Success rows use `status_code=OK`, `error_message=""`, and all numeric fields.
Failure rows use one of `CONTEXT_ERROR`, `DECRYPT_FAIL`, `SATURATED`,
`TIMEOUT`, or `PROCESS_ERROR`; unavailable numeric fields are empty (never zero sentinels), boolean
fields are `0|1`, and strings are RFC 4180 escaped.

`INFEASIBLE` is not a candidate-row status. After all candidates for a logical
key finish, the runner emits a key verdict
`SELECTED|INFEASIBLE|INCOMPLETE`; the combined manifest emits profile verdict
from the exhaustive enum
`PASS|FAIL_REQUIRED|PASS_FEASIBILITY_WITH_INFEASIBLE|FAIL_INCOMPLETE`.
Precedence is:
any missing/crashed/timed-out candidate set is `INCOMPLETE`; otherwise a
feasible selected row is `SELECTED`; otherwise it is `INFEASIBLE`.
Profile truth table:

| profile | all selected | at least one infeasible, none incomplete | any incomplete |
|---|---|---|---|
| primary40 | `PASS`, exit 0 | `FAIL_REQUIRED`, exit 2 | `FAIL_REQUIRED`, exit 2 |
| sensitivity64 | `PASS`, exit 0 | `FAIL_REQUIRED`, exit 2 | `FAIL_INCOMPLETE`, exit 2 |
| feasibility128 | `PASS`, exit 0 | `PASS_FEASIBILITY_WITH_INFEASIBLE`, exit 0 | `FAIL_INCOMPLETE`, exit 2 |

Thus any non-selected primary40 key, including STD192, is terminal; weaker
fallback is forbidden. Tests pin every cell and exit code.

Generated artifacts:

- `include/util/noise_calibration.inc`;
- a human-readable matrix summary;
- a manifest containing commands, environment, source SHA, raw-CSV SHA-256,
  OpenFHE version, selected/rejected counts, and profile verdicts.

## Phase 1 — Make the calibration schema profile- and provenance-aware

### Files

- Modify: `benchmarks/bench_noise.cpp`
- Modify: `src/util/params.cpp`
- Add: `benchmarks/noise_calibration_schema.h`
- Add: `benchmarks/noise_calibration_schema.cpp`
- Add: `tests/unit/test_noise_calibration_schema.cpp`
- Modify: `CMakeLists.txt`

### RED tests

Test pure CLI/schema helpers:

- accept only `onehot|sqrt` in `--pre_threshold` mode;
- accept STD128/STD192 and reject TOY/STD256 for the revision profile runner;
- parse transcript/Q/margin/repetition/seed strictly;
- emit actual OpenFHE version rather than a hard-coded string;
- emit requested, natural, and realized ring dimensions as distinct fields;
- emit the exact aggregate/detail schemas, deterministic row counts, and
  manifest-bound detail/consumer-result hashes defined above;
- include the derived security-profile fields from Work 2;
- implement `--coverage --pre_threshold` as OneHot/Sqrt-only STD128/STD192
  coverage over the exact matrix below while leaving plain `--coverage`
  unchanged for TOY/Threshold regressions;
- reject `reps < 5` for an evidence run while permitting an explicit
  `--smoke` override.

Run:

```bash
cmake --build build -j4 --target test_noise_calibration_schema
./build/test_noise_calibration_schema
```

Expected RED output: missing fields/options and old hard-coded provenance fail.

### GREEN implementation

Refactor parsing and row serialization out of the file-local `bench_noise`
helpers and `main` into the linkable
`benchmarks/noise_calibration_schema.{h,cpp}` library source. Both
`bench_noise` and `test_noise_calibration_schema` link that helper; the test
never links a second `main`. Preserve existing single-point developer mode,
but make evidence mode strict and self-describing.
Threshold behavior is unchanged and never selected by the new profile runner.
The real binary owns and tests canonical options `--pre_threshold`,
`--profile_manifest`, `--profile`, `--key_id`, `--scaling_mod_grid`,
`--max_depth_delta`, `--ring_candidates`, and `--timeout_seconds`.
Retire/guard the old `--emit-cpp` regeneration hint in `src/util/params.cpp`;
it names the new `--emit-rows` fragment path.

### Pass conditions

- Schema tests pass.
- Header/row field counts match for success and failure rows.
- Every row contains source commit and OpenFHE version.
- An evidence command with threshold exits nonzero before key generation.

## Phase 2 — Search and validate calibrated ring growth explicitly

### Files

- Modify: `include/util/params.h`
- Modify: `src/util/params.cpp`
- Modify: `include/fhe/bfv_context.h`
- Modify: `src/fhe/bfv_context.cpp`
- Modify: `benchmarks/bench_noise.cpp`
- Modify: `tests/unit/test_params.cpp`
- Modify: `tests/unit/test_bfv_context.cpp`

### RED tests

Require:

1. a calibration row records a separate `ring_dim_calibrated`;
2. production initialization accepts realized growth only when it exactly
   matches the selected measured row;
3. unmeasured growth still fails closed;
4. selector cost ordering compares actual `N`, `log q`, and ciphertext size,
   not only row order;
5. preserve the existing STD128/STD192 isolation invariant and prove a
   profile never borrows across security levels;
6. capacity is recomputed from transcript/query/coefficient/margin values;
7. the selected runtime context reproduces the table's `N`, depth, scaling
   size, and budget.
8. a synthetic grown-ring row changes `coefficient_stat_bits` by exactly the
   corresponding `ceil(log2 N)` delta.
9. the compiled pre-threshold row stores its exact OpenFHE version and
   initialization rejects a row whose version differs from the
   configure-time/runtime OpenFHE version before key generation.

Field meanings are fixed:

- `requested_ring_dim`: the circuit request before calibration growth;
- `natural_ring_dim`: realized `N` at natural depth/modulus;
- `ring_dim_calibrated`: realized `N` for the measured candidate;
- `realized_ring_dim`: live context `N`, equal to `ring_dim_calibrated`;
- `ring_growth_factor`: exact integer
  `ring_dim_calibrated/natural_ring_dim`, restricted to `1|2` for
  primary/sensitivity and `1|2|4` for feasibility. Requested-to-natural
  security growth is recorded separately and never folded into this factor.

The full compiled/logical key is
`(profile_id,circuit,shape_id,security,requested_ring_dim,natural_depth,
consumer_set_sha256,openfhe_version)`. Key IDs, shard paths, resume keys, and
compiled lookup keys encode or hash every component, so two profiles/layouts/
consumer sets cannot collide. Manifest-requested N and every measured N are
validated against it.
Every `PreThresholdNoiseCalibration` row stores all eight key fields plus
`ring_dim_natural,ring_dim_calibrated,provisioned_depth,scaling_mod_size,
num_limbs,plaintext_mod,log_q,log_delta,eval_noise_bits,ct_bytes` and the
derived transcript/query/coefficient/margin values. No key field exists only
in a comment or external filename.

The exact gate is:

```text
query_stat_bits =
  transcript_stat_bits + ceil(log2(max_queries))
coefficient_stat_bits =
  query_stat_bits + ceil(log2(N_realized))
eval_noise_bits + coefficient_stat_bits + flood_margin_bits + 2
  <= log2(q/plaintext_modulus)
```

Run:

```bash
cmake --build build -j4 --target test_params test_bfv_context
ctest --test-dir build --output-on-failure -R 'Params|BFVContext'
```

Expected RED output: the current natural-ring growth guard rejects any measured
growth and table rows lack the required key.

### GREEN implementation

Permit the harness to try an explicit ring list starting at natural `N` and
doubling within a CLI cap. A production parameter set uses only the selected
row's exact actual `N`; it never starts a search. Retain OpenFHE standard
security enforcement for STD128/STD192.

### Pass conditions

- Measured growth is accepted only for the matching table row.
- Mutating any selected field causes initialization to fail.
- Error messages report requested/natural/calibrated/realized `N`.
- No silent fallback to a lower transcript or security target exists.

## Phase 3 — Build profile-specific grids and an idempotent runner

### Files

- Add: `scripts/run_noise_profiles.sh`
- Add: `scripts/noise_profiles.json`
- Add: `include/util/noise_profile_matrix.h`
- Add: `tests/scripts/test_run_noise_profiles.py`
- Modify: `CMakeLists.txt` to register the script test when Python is present.

### Exact profile grid

Primary transcript-40 keys (natural depths OneHot=1, Sqrt=3):

```text
OneHot STD128 requested N =
  8192,16384,32768,65536,131072,262144,524288
OneHot STD192 requested N =
  16384,32768,65536,131072,262144,524288
Sqrt STD128 requested N = 8192,16384,32768
Sqrt STD192 requested N = 16384,32768
```

The compiled `include/util/noise_profile_matrix.h` is the single matrix
source. `bench_noise --print_profile_manifest` canonically emits it as JSON;
the tracked `scripts/noise_profiles.json` must compare byte-for-byte with that
output before coverage or the runner proceeds. C++ coverage consumes the
compiled constexpr matrix and Python consumes the verified JSON, so no C++
JSON parser/dependency is introduced. A stale/manual JSON edit fails the
golden test. The matrix lists these consumers exactly:

```text
onehot:
  k-sweep={(16,64),(32,64),(64,64),(128,64),(256,64),(512,64)}
  m-sweep={(128,16),(128,32),(128,64),(128,128),(128,256)}
  crossover={32,64,128,256,512} x {4,16,64,256,1024}
  sqrt-comparison={(128,64),(256,64),(512,64),(1024,64),
                   (128,256),(128,1024)}
sqrt:
  k-sweep={(16,64),(32,64),(64,64),(128,64),(256,64),(512,64)}
  m-sweep={(128,4),(128,16),(128,64),(128,256)}
  crossover and sqrt-comparison grids as above
```

OneHot uses `shape_id=onehot-v1`. Sqrt uses
`shape_id=sqrt-b<sqrt_base>-v1`; different `sqrt_base` values never collapse.
The matrix compiler first derives `(requested_ring_dim,natural_depth,shape_id)`
for every declared consumer and partitions by the seven-field base key
`(profile_id,circuit,shape_id,security,requested_ring_dim,natural_depth,
openfhe_version)`. Within each base partition it canonical-deduplicates/sorts
the consumers, computes `consumer_set_sha256`, and only then forms the
eight-field full logical key above. Thus
OneHot STD128 consumers `(16,64),(32,64),(64,64),(128,64)` may share the
requested-N=8192 partition, while `(256,64)` and `(512,64)` necessarily belong
to requested-N=16384 and 32768 partitions. Golden tests enumerate every
consumer exactly once across partitions and reject missing, duplicate, or
wrong-N membership.

For either circuit, each resulting logical key carries its exact canonical
sorted consumer list. The runner forwards it as one
`--consumer_points=k1:m1,k2:m2,...` argument. For every candidate and each
pattern/repetition, `bench_noise` executes every listed consumer, writes
per-consumer detail, and emits one aggregate candidate row whose
`eval_noise_bits` is the maximum. Missing/failed consumers make the candidate
fail. The consumer-list SHA and worst `(k,m)` are stored in raw/compiled
evidence. Sensitivity/feasibility use the singleton `(128,64)` list and never
borrow a primary consumer.

Sensitivity transcript-64 is exactly:

```text
(onehot,STD128,k=128,m=64,N=8192,depth=1)
(onehot,STD192,k=128,m=64,N=16384,depth=1)
(sqrt,STD128,k=128,m=64,N=8192,depth=3)
(sqrt,STD192,k=128,m=64,N=16384,depth=3)
```

Feasibility transcript-128 is exactly:

```text
(onehot,STD128,k=128,m=64,N=8192,depth=1)
(onehot,STD192,k=128,m=64,N=16384,depth=1)
```

### Exact bounded search

- scaling-modulus sizes: `40,45,50,52,54,58,60`;
- depth delta: `0..6`;
- primary40/sensitivity64 ring candidates:
  `N_natural,2*N_natural`, capped at `1048576`;
- feasibility128 candidates:
  `N_natural,2*N_natural,4*N_natural`, same cap;
- maximum candidates per primary/sensitivity key: `2*7*7=98`;
- maximum feasibility candidates per key: `3*7*7=147`.

The runner shards one logical key per process (runner `--key-id`, forwarded
to the binary as `--key_id`) and resumes only
after validating its manifest/CSV hash. Timeout tier is selected from the
largest candidate ring dimension the key can test after applying the
profile's 2x/4x growth cap—not requested or natural N: 45 minutes for
max-candidate N<=32768, 2 hours for 65536, 6 hours for 131072, 12 hours for
262144, and 24 hours for >=524288. Timeout emits a `TIMEOUT` failure row and makes a
required primary/sensitivity key fail; it is never skipped. The dry run reports
candidate count and timeout for every shard.

Before selecting a shard timeout, the runner invokes
`bench_noise --preflight_context --key_id=<id> --profile_manifest=<path>`.
This mode parses the full key and creates only OpenFHE context parameters—no
key generation, encryption, files, or measurements—and emits canonical JSON
containing source commit, OpenFHE version, full logical key, and
`natural_ring_dim`. The runner verifies those fields against the matrix, then
uses that discovered N and the profile growth cap for the timeout tier. A
preflight error/mismatch is a terminal `PROCESS_ERROR`; dry-run includes and
validates the same preflight output before printing commands. Preflight itself
is supervised with a fixed 120-second wall-clock bound and the same TERM then
30-second KILL policy. The guarded fake-binary seam tests preflight timeout,
signal, malformed JSON, and success without waiting production time; a
preflight hang can never occur outside a timeout.

The supervisor enforces wall time and sends TERM then KILL after 30 seconds.
Timeout, signal termination, OOM-like exit, crash, or missing/truncated CSV is
atomically represented by one synthetic `TIMEOUT` or `PROCESS_ERROR` row with
exit/signal details; it cannot disappear from the key verdict. Evidence mode
has no default root: it requires a new absolute `--results-root` outside the
Git worktree. At run start it records a clean source commit/status; subsequent
shards validate that same commit and ignore only their external `CAL_RUN`.
After successful finalization, the accepted manifest/selected raw shards are
copied once into `scripts/results/calibration/<SOURCE_COMMIT>/` for the later
artifact commit.

The fake supervisor test has an explicit safe injection seam:
`PICCARD_TEST_SUPERVISOR=1` is accepted only when the resolved benchmark
basename is `fake_bench_noise`; then
`PICCARD_TEST_TIMEOUT_MS` and `PICCARD_TEST_TERM_GRACE_MS` may be positive
integers as small as 10 ms. Production rejects either timing override unless
that guard is active. Goldens use 50 ms/20 ms and assert TERM then KILL without
waiting for production's 45-minute/30-second policy.

### RED tests

With a fake `bench_noise`, verify:

- exact command matrix;
- `--resume` skips only CSVs whose manifest SHA and row count validate;
- one failed cell does not disappear;
- primary/sensitivity/feasibility outputs cannot overwrite one another;
- threshold never appears;
- a partial run produces a nonzero final verdict.
- the exact key/candidate/timeout matrix above is stable.
- side-effect-free preflight output selects the timeout tier; wrong key,
  source, OpenFHE version, or natural N is fatal;
- timeout fake receives TERM then KILL and yields atomic `TIMEOUT`;
- crash, signal/OOM exit, missing CSV, and truncated CSV yield atomic
  `PROCESS_ERROR` with exit/signal detail;
- resume rejects every synthetic/incomplete/hash-mismatched shard.

Run:

```bash
python3 -m unittest tests/scripts/test_run_noise_profiles.py
```

Expected RED output: runner/test absent.

### GREEN implementation

Evidence mode always requires a caller-supplied new absolute results root
outside the Git worktree and has no default. A first invocation without
`--resume` creates it atomically and rejects an existing path. Later profile
invocations require `--resume`, require the root to exist, and validate the
frozen source/environment/run identity before writing only missing cells.
Developer `--smoke` mode alone may use a timestamped generated default. Use
atomic per-cell temp-file rename. Never delete prior measurements.

### Pass conditions

- Fake-run tests pass.
- `DRY_RUN=1` prints a complete deterministic command matrix.
- A smoke run (`reps=1`, default cells only) finishes and creates a valid
  manifest without being eligible for table generation.

## Phase 4 — Preserve legacy rows and reject incomplete/stale evidence

### Files

- Modify: `scripts/make_calibration_table.py`
- Add: `tests/scripts/test_make_calibration_table.py`
- Add: `scripts/apply_calibration_cutover.py`
- Add: `scripts/templates/noise_calibration_wrapper.inc`
- Add: `tests/scripts/test_apply_calibration_cutover.py`
- Add: `scripts/make_calibration_archive.py`
- Add: `tests/scripts/test_make_calibration_archive.py`
- Modify: `CMakeLists.txt`
- Add: `include/util/noise_calibration_legacy_rows.inc`
- Add: `tests/fixtures/noise_calibration_pre_threshold_rows.inc`
- Stage the future `include/util/noise_calibration.inc` wrapper in a test
  fixture, but do not cut over the active table in this phase.
- Generate only a fixture/temp pre-threshold fragment here. The tracked
  fragment and wrapper cutover occur atomically in Phase 5 after accepted
  evidence exists; the wrapper and legacy fragment are never generator
  outputs.

### RED tests

Fixtures must prove rejection of:

- missing patterns or fewer than five repetitions;
- saturated measurement;
- decryption failure;
- security/profile mismatch;
- actual-N mismatch;
- stale source commit or OpenFHE version mixture;
- insufficient transcript capacity;
- absent primary STD128/STD192 key;
- a feasibility-128 failure being incorrectly treated as a primary failure.
- any byte change to the pinned TOY and Threshold legacy row file.

Also test deterministic frontier selection and byte-for-byte stable C++ output
for identical input.

Run:

```bash
python3 -m unittest \
  tests/scripts/test_make_calibration_table.py \
  tests/scripts/test_apply_calibration_cutover.py \
  tests/scripts/test_make_calibration_archive.py
```

Expected RED output: current generator accepts incomplete provenance and uses
the old lambda formula.

### GREEN implementation

Before implementation, extract each current TOY and Threshold initializer
literal (from its opening `{Circuit::...` through its trailing comment)
byte-for-byte into the pinned legacy include and record its SHA-256 in a
fixture. The wrapper declares the old nine-field
`LegacyNoiseCalibration` array around that include. It declares a separate
expanded `PreThresholdNoiseCalibration` array, whose rows add
`ring_dim_calibrated`, measured `log_q`, and `ct_bytes`.

The staged wrapper has two deliberately separate paths:

- TOY/Threshold adapt a legacy row in memory with
  `ring_dim_calibrated=ring_dim_natural`, `log_q=not_applicable`, and
  `ct_bytes=not_applicable`, and retain the historical first-feasible-row
  ordering;
- OneHot/Sqrt STD128/STD192 consume only expanded pre-threshold rows and use
  the `(actual N, log q, ciphertext bytes)` cost ordering from Phase 2.

The sentinel is a typed optional/not-applicable value, never numeric zero.
The legacy fragment is not regenerated or reformatted. Thus an expanded
pre-threshold schema cannot silently reinterpret, reorder, or rewrite legacy
rows.

The compile transition is explicit. `params.cpp` includes
`PICCARD_NOISE_CALIBRATION_FILE` when defined, otherwise the current
`util/noise_calibration.inc`. The current single-array include has no
`PICCARD_PRE_THRESHOLD_CALIBRATION_V2` macro and compiles the preserved
`NoiseCalibration kNoiseCalibration[]` adapter path. The staged wrapper
defines that macro, declares
`LegacyNoiseCalibration kLegacyNoiseCalibration[]` and
`PreThresholdNoiseCalibration kPreThresholdNoiseCalibration[]`, and exposes
one typed `ForEachNoiseCalibrationCandidate` adapter consumed by selection;
`params.cpp` never assumes both raw arrays have the same fields.
`test_apply_calibration_cutover.py` compiles the exact frozen
`params.cpp`/schema helper twice—once against the current include and once
against the staged wrapper+fixture fragment—and runs plain and pre-threshold
coverage fixtures. The Phase-5 generated tracked fragment replaces only the
fixture input at cutover; no later source rewrite is permitted.

The sole finalization CLI is
`run_noise_profiles.sh --results-root=<root> --finalize-dir=<new-dir>`.
That one atomic transaction validates all shards, creates the combined
manifest and archive, and invokes `make_calibration_archive.py` internally;
there is no `--finalize-manifest` or standalone `--archive` mode, and the
helper cannot update a finalized run by itself. Runner integration tests pin
this exact invocation, reject a pre-existing/partial final directory, and
prove failure leaves no final directory.
It sorts canonical relative POSIX paths and creates
a deterministic uid/gid=0, uname/gname empty, mode-normalized, mtime=0 tar,
then invokes a preflighted `zstd --threads=1 -19 --no-progress`. The archive
contains every per-key manifest/verdict and raw shard needed to justify a
selected or accepted infeasible verdict; incomplete shards are forbidden. It
does not contain the combined manifest, avoiding self-reference. Finalization
records the exact `zstd --version`, archive member list, uncompressed tar SHA,
and final archive SHA-256 in the combined manifest. Fake tests pin byte
identity, ordering, selected and infeasible membership, missing-tool failure,
and rejection of incomplete/path-escaping members.

Generate a fixture frontier supporting all measured profiles. Expanded rows
also store the exact OpenFHE version string. The primary profile is mandatory.
Sensitivity cells are mandatory only for the declared representative grid.
Feasibility key verdicts may be `INFEASIBLE`, but candidate rows retain the
formal status enum and the best shortfall/reason is retained in the summary.

### Pass conditions

- Script tests pass.
- Re-running generation produces no diff.
- The staged generated table contains no threshold row.
- Before Phase 5 cutover, the active current table keeps plain coverage and
  focused TOY/STD128/Threshold tests green; no zero-missing STD192 claim is
  made yet.
- Register this Python suite with CTest.
- `CMakeLists.txt` registers all three Phase-4 Python suites with CTest.

## Phase 5 — Execute the approved calibration evidence run

### Generated/modified files

- Generate: `include/util/noise_calibration_pre_threshold_rows.inc`
- Atomically replace: `include/util/noise_calibration.inc`
- Generate external evidence only beneath caller `CAL_RUN`

Each shard is an explicit, reproducible invocation. For example:

```bash
./build/bench_noise --evidence --pre_threshold \
  --profile_manifest=scripts/noise_profiles.json \
  --profile=std128-t64-sensitivity \
  --key_id="$KEY_ID" \
  --security=STD128 --circuit=onehot \
  --consumer_points=128:64 \
  --transcript_stat_bits=64 --max_queries=1048576 --margin=8 \
  --reps=5 --seed=20260729 --scaling_mod_grid=40,45,50,52,54,58,60 \
  --max_depth_delta=6 --ring_candidates=natural,2x \
  --timeout_seconds=2700 \
  --csv="$CAL_RUN/shards/$KEY_ID.csv"
```

The runner expands this command once per exact matrix key, substitutes the
key-specific ring-candidate list and timeout tier, and records the fully
expanded command in the manifest. Unknown or missing options are fatal.
All `bench_noise` options use the underscore spellings frozen by Work 2;
unknown hyphen variants fail unless Work 2 explicitly implements and tests
them as aliases.

### Commands

```bash
SOURCE_COMMIT="$(git rev-parse HEAD)"
CAL_RUN="/tmp/piccard-calibration-$SOURCE_COMMIT"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4 --target bench_noise
test "$(./build/bench_noise --print_source_commit)" = "$SOURCE_COMMIT"
./build/bench_noise --print_profile_manifest \
  > "$CAL_RUN.profile-manifest.tmp"
cmp scripts/noise_profiles.json "$CAL_RUN.profile-manifest.tmp"
test ! -e "$CAL_RUN"
./scripts/run_noise_profiles.sh \
  --profile=primary40 --reps=5 --seed=20260729 \
  --max-queries=1048576 --margin=8 \
  --results-root="$CAL_RUN"
test -d "$CAL_RUN"
./scripts/run_noise_profiles.sh \
  --profile=sensitivity64 --reps=5 --seed=20260729 \
  --max-queries=1048576 --margin=8 --resume \
  --results-root="$CAL_RUN"
./scripts/run_noise_profiles.sh \
  --profile=feasibility128 --reps=5 --seed=20260729 \
  --max-queries=1048576 --margin=8 --resume \
  --results-root="$CAL_RUN"
./scripts/run_noise_profiles.sh \
  --results-root="$CAL_RUN" --finalize-dir="$CAL_RUN/finalized"
python3 scripts/make_calibration_table.py \
  --manifest="$CAL_RUN/finalized/manifest.json" \
  --emit-rows=include/util/noise_calibration_pre_threshold_rows.inc \
  --out="$CAL_RUN/CALIBRATION_MATRIX.md"
python3 scripts/apply_calibration_cutover.py \
  --staged-wrapper=scripts/templates/noise_calibration_wrapper.inc \
  --legacy-rows=include/util/noise_calibration_legacy_rows.inc \
  --pre-threshold-rows=include/util/noise_calibration_pre_threshold_rows.inc \
  --dest=include/util/noise_calibration.inc
cmake --build build -j4
ctest --test-dir build --output-on-failure
./build/bench_noise --coverage
./build/bench_noise --coverage --pre_threshold
DEST="scripts/results/calibration/$SOURCE_COMMIT"
STAGED_DEST="scripts/results/calibration/.$SOURCE_COMMIT.tmp"
test ! -e "$DEST"
test ! -e "$STAGED_DEST"
mkdir -p "$STAGED_DEST"
cp "$CAL_RUN/finalized/manifest.json" "$CAL_RUN/CALIBRATION_MATRIX.md" \
  "$CAL_RUN/finalized/selected-shards.tar.zst" "$STAGED_DEST/"
(
  cd "$STAGED_DEST"
  shasum -a 256 manifest.json CALIBRATION_MATRIX.md \
    selected-shards.tar.zst > tracked-copy.sha256
  shasum -a 256 -c tracked-copy.sha256
)
python3 scripts/make_calibration_table.py --verify-artifact-copy \
  --manifest="$CAL_RUN/finalized/manifest.json" \
  --artifact-dir="$STAGED_DEST"
mv "$STAGED_DEST" "$DEST"
```

For interruption recovery, do not repeat `test ! -e`. Re-enter only with:

```bash
test -d "$CAL_RUN"
test "$(./build/bench_noise --print_source_commit)" = \
     "$(git rev-parse HEAD)"
./scripts/run_noise_profiles.sh \
  --profile=<first-incomplete-profile> --reps=5 --seed=20260729 \
  --max-queries=1048576 --margin=8 --resume \
  --results-root="$CAL_RUN"
```

The Release binary embeds the configure-time full source commit; every shard
records binary SHA and embedded commit and requires both to match the clean
current HEAD and frozen run manifest before key generation. A rebuilt,
different, dirty, or unbound binary cannot resume.

Each profile invocation writes only its named fragment beneath the same
caller-supplied `CAL_RUN`; it does not create a new timestamped run. Finalize
is a recoverable directory transaction: it builds archive, member list,
checksums, and manifest beneath a unique sibling temp directory, fsyncs all
files and the directory, then atomically renames it to the previously absent
`$CAL_RUN/finalized`. Before rename, resume validates/removes only that owned
temp directory and rebuilds it; after rename, finalization is complete and
immutable. Thus no archive can become visible without its matching manifest.
It fails on a missing/duplicate profile or mixed source/OpenFHE/build
provenance. The generator accepts only the finalized combined manifest. The
cutover script validates
the staged wrapper, both fragments, both coverage modes, and a temporary
compile before an atomic destination rename; any validation failure leaves
the prior `noise_calibration.inc` byte-identical. The tracked evidence copy is
staged, checked against finalized hashes, and directory-renamed atomically;
partial copy never creates `DEST`, and a repeated source commit cannot
overwrite evidence.

After the combined manifest passes, generate the tracked pre-threshold
fragment, verify every compiled OpenFHE-version field, and atomically apply
the staged wrapper. The immutable legacy fragment already contains only
TOY/Threshold; no STD row is removed or rewritten there. Immediately run
plain coverage plus
`--coverage --pre_threshold`; pre-threshold coverage must report zero missing
primary STD128/STD192 keys, while plain coverage preserves TOY/Threshold.

### Pass conditions

- Primary40: all declared STD128 and STD192 keys have a feasible selected row,
  or the work stops with an explicit profile-design blocker.
- Sensitivity64: all declared representative cells resolve; an infeasible
  cell is a required-profile failure and no weaker fallback is permitted.
- Feasibility128: each point has either a verified feasible row or an explicit
  best-shortfall/infeasibility record.
- All selected rows decrypt for all patterns/repetitions, are unsaturated, and
  match runtime parameters.
- The manifest and raw CSV hashes verify.
- Evidence mode starts only from a clean committed source tree. Each shard
  records `source_commit`, `git_dirty=false`, OpenFHE version, exact argv, and
  profile-manifest SHA. Mixed commit/version data is rejected. Generation
  trusts the signed/hashed manifest fields rather than querying live Git state.

## Work-level verification

Review artifacts: code diff, script tests, focused C++ tests, raw evidence
manifest, generated matrix, table diff, coverage output, and full ctest log.
Work 4 starts only after GPT-5.6-sol and Fable approve the nonempty
`WORK2_HEAD..WORK3_HEAD` diff, the read-only
`$REVIEW_STAGING_ROOT/work-3-{gpt,fable}.md` files pass
`verify_work_approval.py --work-id=3 --expected-base="$WORK2_HEAD"
--plan-path=docs/superpowers/plans/2026-07-29-03-std128-std192-calibration.md`,
and clean `HEAD==WORK3_HEAD`.
