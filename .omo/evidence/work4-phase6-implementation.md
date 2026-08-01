# Work 4 Phase 6 implementation evidence

## Scope

Implemented the pre-threshold-only runner matrix and its fail-closed evidence
contract. No `Paper/**`, threshold producer, threshold FP/FN, response strategy,
calibration, or Work 5 file was edited.

Primary implementation:

- `scripts/run_pre_threshold_profiles.sh`
- `tests/scripts/test_run_pre_threshold_profiles.py`

Phase 6-required build/verification integration:

- `CMakeLists.txt`, `cmake/build_info.h.in`
- `benchmarks/benchmark_provenance.{h,cpp}`
- `benchmarks/bench_{piccard,onehot_sqrt,dynamic,review_comparison}.cpp`
- `scripts/verify_benchmark_provenance.py`
- `scripts/verify_review_comparison.py`

The legacy `scripts/run_benchmarks.sh` and `scripts/run_core_benchmarks.sh`
required no change: the new runner is independent, has no implicit `latest`
path, and contains no threshold command.

## RED evidence

Command:

```text
python3 -m unittest tests.scripts.test_run_pre_threshold_profiles
```

Initial result: `FAILED (errors=7)`. Every test failed because
`scripts/run_pre_threshold_profiles.sh` did not exist. A later focused RED
test ran all four built evidence executables with
`--print-build-provenance`; all four rejected the absent option. The CSV row
count binding test also failed with missing `expected_csv_rows`, before the
manifest row-count gate was implemented.

## GREEN evidence

Focused runner and Phase 5 verification:

```text
python3 -m unittest \
  tests.scripts.test_run_pre_threshold_profiles \
  tests.scripts.test_verify_review_comparison \
  tests.scripts.test_verify_benchmark_provenance \
  tests.scripts.test_verify_sj16_extrapolation
```

Result: `Ran 29 tests in 10.040s`, `OK`.

The eight runner tests use fake binaries and cover:

- byte-pinned primary, sensitivity, feasibility, and smoke argv matrices;
- explicit seed and `OMP_NUM_THREADS`/`OMP_DYNAMIC` policy;
- `--evidence_point` on every single-point Piccard-family cell;
- absence of `bench_threshold`;
- dry-run no-side-effects;
- absolute build/results roots and no overwrite;
- exact top-level result layout;
- build commit/dirty/type/source identity and binary SHA-256;
- primary failure on missing STD192 calibration;
- manifest-bound Phase 5 verifier invocation;
- terminal-cell schema, output hashes, and frozen CSV row counts; and
- resume validation of identity, binary/output hashes, argv, and path
  containment before skipping completed cells.

Targeted Release build (does not run benchmarks):

```text
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4 --target \
  bench_piccard bench_onehot_sqrt bench_dynamic bench_review_comparison
```

Result: all four Phase 6 evidence targets built. Their
`--print-build-provenance` output was valid JSON with schema
`piccard-build-provenance-v1`, Release build type, source directory, source
commit, dirty state, and OpenFHE 1.5.0.

Repository CTest:

```text
ctest --test-dir build --output-on-failure
```

Result: `100% tests passed out of 49` in `258.94 sec`.

Fresh focused CTest after the final row-count changes:

```text
ctest --test-dir build --output-on-failure \
  -R 'PreThresholdProfileRunner|ReviewComparisonCli|BenchmarkProfileExecutables|ThresholdProfileCompat'
```

Result: `100% tests passed out of 4` in `6.94 sec`.

Primary dry run:

```text
DRY_RUN=1 ./scripts/run_pre_threshold_profiles.sh \
  --suite=primary --seed=20260729 --threads=8 \
  --build-dir="$(pwd)/build"
```

Result: exit 0; printed all ten primary RUN cells, per-cell capture paths,
source/build gates, and manifest/cell-bound verifier commands. It created no
result files.

## Bounded execution policy

No calibration and no primary/sensitivity/feasibility benchmark was run. The
non-dry-run smoke evidence came from fake binaries inside the unit harness;
the harness executed both smoke cells, Phase 5 verifiers, manifest/terminal
generation, and resume without retaining temporary artifacts. A real
cryptographic toy smoke was deliberately deferred to keep this Phase 6 run
bounded; no real-smoke artifact exists.

## Unrelated aggregate-build failure

`cmake --build build -j4` built the Phase 6 targets but the aggregate `all`
target exited nonzero while linking the pre-existing `bench_threshold` target.
The undefined symbols were `BenchmarkRunClassName`,
`LegacyBenchmarkProfile`, and `ResolveBenchmarkProfile`. Phase 6 does not
modify that target or its linkage, `ThresholdProfileCompat` passes, and the
task explicitly forbids threshold edits, so this unrelated failure was not
changed or hidden.
