# Work 4 aggregate-build fix implementation evidence

## Scope and root cause

Starting branch/commit:

```text
tkde-major/pre-threshold-poc
a31a3c8d88681648b1dc74e666349347ef27f5a4
```

Claude Fable reported that `bench_threshold` includes Work 4's shared
`benchmark_utils.h`, which now calls serializer/profile functions implemented
by `piccard_benchmark_serializers`, while the executable linked only
`piccard_fhe`.

The report was reproduced before editing:

```text
cmake --build build --target bench_threshold -j8
```

Result: exit 2 while linking `bench_threshold`, with undefined symbols
`BenchmarkRunClassName`, `LegacyBenchmarkProfile`, and
`ResolveBenchmarkProfile`.

Adjacent benchmark targets using the same shared utilities already link
`piccard_benchmark_serializers`. The fix adds that library only to
`bench_threshold`'s `target_link_libraries`; no threshold source, CLI,
FP/FN behavior, `ResponseStrategy`, Work 5, or Paper file was changed.

The Phase 6 implementation note was also corrected to stop describing this
Work 4 build-wiring regression as pre-existing or unrelated.

## Targeted GREEN verification

Command:

```text
cmake -S . -B build -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=ON
cmake --build build --target bench_threshold test_threshold_profile_compat -j8
./build/test_threshold_profile_compat
```

Result: exit 0. CMake found OpenFHE 1.5.0, GMP, OpenSSL 3.6.3, and GTest;
both targets built. `ThresholdProfileCompat` ran 3 tests and all 3 passed:

```text
ToyGoldenRemainsPrivateCoefficientLevel
HeaderBytesRemainLegacyCompatible
Std128MissingCalibrationFailsClosed
```

## Aggregate build verification

Command:

```text
cmake --build build -j8
```

Result: exit 0; the aggregate build reached 100%, including
`bench_threshold`. The linker emitted only duplicate-library warnings for
existing OpenMP/static-library link entries.

## Full CTest verification

Command:

```text
ctest --test-dir build --output-on-failure -j8
```

Result: exit 0; `100% tests passed out of 49`; total real time 129.92 seconds.
This was the repository's existing CTest suite, including its bounded
calibration fixtures; no real benchmark matrix was launched.

## Final hygiene checks

Commands:

```text
git diff --check
git diff --name-only
```

Result: `git diff --check` exited 0. The intended pre-commit file set is:

```text
.omo/evidence/work4-aggregate-build-fix-implementation.md
.omo/evidence/work4-phase6-implementation.md
CMakeLists.txt
```

No remaining test or build failures were observed.
