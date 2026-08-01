# Work 4 Phase 3 implementation evidence

## Scope

- Added a typed baseline-capability map for BCG12, SJ16, FHE-IND, Piccard, and Piccard-sqrt.
- Made comparison-row serialization derive its reporting taxonomy from the capability map.
- Added strict Python validation so reporting rejects unknown, legacy, or capability-inconsistent rows.
- Kept SJ16 precomputation as a separately labelled, comparison-ineligible lower-bound row.
- Preserved live BFV provenance for the FHE-IND local-universe comparator.
- Did not change the paper, threshold false-positive/false-negative work, response strategies, or later phases.

## TDD evidence

RED checks observed before implementation:

1. The new C++ capability tests failed to compile because `baseline_profile.h` did not exist.
2. Comparison serialization tests failed to compile because `ComparisonResult` lacked a typed capability and nullable `k`/`m` fields.
3. All four Python reporting-taxonomy tests failed because the old summarizer accepted invalid fixtures and the old reporting-gap verifier expected the legacy schema.

GREEN checks after implementation:

```text
cmake --build build -j4 --target test_baseline_profile test_estimator_provenance_serializers test_benchmark_profile test_bcg12 test_sj16 bench_comparison
```

All requested targets built successfully.

```text
ctest --test-dir build --output-on-failure -R '^(BaselineProfile|EstimatorProvenanceSerializers|BenchmarkProfile|Bcg12|SJ16|ReportingTaxonomy)$'
```

Result: 6/6 tests passed (SJ16, EstimatorProvenanceSerializers, BenchmarkProfile, BaselineProfile, Bcg12, ReportingTaxonomy), 0 failed, 4.41 seconds.

```text
python3 -m unittest tests.scripts.test_reporting_taxonomy -v
```

Result: 4/4 tests passed, 0 failed, 0.475 seconds.

## Toy producer evidence

Exactly one bounded toy producer run was performed:

```text
OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE ./build/bench_comparison --profile=toy-smoke --security=TOY --mode=combined --evidence_point --k=16 --m=16 --set_size=16 --universe=64 --target-jaccard=0.5 --trials=1 --accuracy_trials=1 --seed=7
```

Result: exit 0 and six comparison rows emitted. The FHE-IND row used nullable `k`/`m`, a numeric ring dimension, and live BFV provenance fields. No long benchmark was run and the producer was not repeated.

## Taxonomy gates covered

- BCG12 fixed profiles distinguish FF-3072/256 and EC P-256 at nominal 128-bit security.
- SJ16 1024-bit and 2048-bit Paillier rows are diagnostic/ineligible; the 3072-bit row is an explicitly qualified RSA/IFC proxy.
- No STD192 AHE security match is claimed; strict resolution rejects one.
- FHE-IND is labelled as a local-universe-sized BFV comparator and diagnostic-only, not as EPSet.
- Piccard and Piccard-sqrt rows retain their FHE provenance and capability-derived reporting fields.
- Exact, estimator, measured, and diagnostic measurement kinds are separated from execution status.
- Cost scope, protocol model, primitive, output semantics, assurance scope, security basis, precomputation mode, and secure-division inclusion are serialized and validated.
- Numeric applicability is enforced: exact BCG12/SJ16 rows have no `k`, `m`, or ring dimension; BCG12 MinHash has `k` only; FHE-IND has a ring dimension only; Piccard variants have all three.
- The verifier rejects a lone precomputed SJ16 row so it cannot silently replace the main SJ16 baseline.

## Notes

- The build emitted only pre-existing GMP literal-operator deprecation and duplicate-library linker warnings.
- No STD192 AHE implementation or later-phase benchmark work was added.
