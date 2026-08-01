# Work 4 Phase 3 implementation evidence

## Scope

- Added a typed baseline-capability map for BCG12, SJ16, FHE-IND, Piccard, and Piccard-sqrt.
- Made comparison-row serialization derive its reporting taxonomy from the capability map.
- Added strict Python validation so reporting rejects unknown, legacy, or capability-inconsistent rows.
- Kept SJ16 precomputation as a separately labelled, comparison-ineligible lower-bound row.
- Preserved live BFV provenance for the FHE-IND local-universe comparator.
- Preserved the requested timing/accuracy evidence arm as typed capability
  metadata so combined diagnostic rows have an explicit, strict identity.
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

Review-correction RED/GREEN evidence:

- RED: a producer-shaped combined fixture failed in both reporting programs
  because the timing and accuracy FHE-IND rows collapsed to the duplicate key
  `('vary_universe_64', 'baseline', 'diagnostic')`.
- RED: serializer tests reported the missing `evidence_arm` column for both
  timing and accuracy diagnostic rows.
- GREEN: the combined fixture is accepted by both programs, the timing table
  selects the timing arm, and a same-arm duplicate remains rejected.

Final focused review-correction gate:

```text
cmake --build build -j4 --target test_baseline_profile test_estimator_provenance_serializers test_benchmark_profile test_bcg12 test_sj16 bench_comparison
ctest --test-dir build --output-on-failure -R '^(BaselineProfile|EstimatorProvenanceSerializers|BenchmarkProfile|Bcg12|SJ16|ReportingTaxonomy)$'
python3 -m unittest tests.scripts.test_reporting_taxonomy -v
```

Result: all build targets succeeded, focused CTest passed 6/6 in 5.22
seconds, and the Python reporting-taxonomy suite passed 6/6 in 0.759
seconds. A fresh reporter-only check of the persisted producer CSV also passed
both `summarize_results.py --latex` and `verify_reporting_gaps.py`. The
benchmark producer was not rerun during this final gate.

## Toy producer evidence

After the review correction, one bounded toy producer run was performed and
persisted; it was not repeated:

```text
OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE ./build/bench_comparison --profile=toy-smoke --security=TOY --mode=combined --evidence_point --k=16 --m=16 --set_size=16 --universe=64 --target-jaccard=0.5 --trials=1 --accuracy_trials=1 --seed=7
```

Result: exit 0 and six comparison rows emitted. FHE-IND retained
`measurement_kind=diagnostic` and `comparison_eligible=false`, with distinct
`evidence_arm=timing|accuracy` identities, nullable `k`/`m`, a numeric ring
dimension, and live BFV provenance fields. No long benchmark was run.

Auditable artifacts:

- Raw producer stdout CSV: `.omo/evidence/work4-phase3-toy-combined.csv`
- Producer command, return code, and stderr:
  `.omo/evidence/work4-phase3-toy-combined-command.log`
- Summarizer command, return code, stdout, and empty-stderr record:
  `.omo/evidence/work4-phase3-summarizer.out`
- Strict verifier command, return code, stdout, and empty-stderr record:
  `.omo/evidence/work4-phase3-verifier.out`

## Taxonomy gates covered

- BCG12 fixed profiles distinguish FF-3072/256 and EC P-256 at nominal 128-bit security.
- SJ16 1024-bit and 2048-bit Paillier rows are diagnostic/ineligible; the 3072-bit row is an explicitly qualified RSA/IFC proxy.
- No STD192 AHE security match is claimed; strict resolution rejects one.
- FHE-IND is labelled as a local-universe-sized BFV comparator and diagnostic-only, not as EPSet.
- Combined timing and accuracy rows carry a strict `evidence_arm`; duplicate
  checking includes the arm and still rejects any repeated same-arm identity.
- Piccard and Piccard-sqrt rows retain their FHE provenance and capability-derived reporting fields.
- Exact, estimator, measured, and diagnostic measurement kinds are separated from execution status.
- Cost scope, protocol model, primitive, output semantics, assurance scope, security basis, precomputation mode, and secure-division inclusion are serialized and validated.
- Numeric applicability is enforced: exact BCG12/SJ16 rows have no `k`, `m`, or ring dimension; BCG12 MinHash has `k` only; FHE-IND has a ring dimension only; Piccard variants have all three.
- The verifier rejects a lone precomputed SJ16 row so it cannot silently replace the main SJ16 baseline.

## Notes

- The build emitted only pre-existing GMP literal-operator deprecation and duplicate-library linker warnings.
- No STD192 AHE implementation or later-phase benchmark work was added.
