# Work 4 Phase 5 implementation evidence

## Scope

Implemented only Phase 5 of
`docs/superpowers/plans/2026-07-29-04-benchmark-profiles-and-baseline-gates.md`:

- added `scripts/verify_review_comparison.py`;
- added `scripts/verify_benchmark_provenance.py`;
- migrated `scripts/verify_sj16_extrapolation.py` to the typed SJ16 schema;
- added the three corresponding `tests/scripts/test_verify_*.py` modules.

No `Paper/**`, threshold-FP/FN, `ResponseStrategy`, runner-matrix (Phase 6),
or benchmark producer source was changed. `scripts/assert_methods.sh` is
superseded for reviewer artifacts by the manifest-conditioned Python gate and
was left unchanged. No benchmark was executed. Fixtures copy and mutate the
persisted Phase 4 TOY CSV/workload/trace artifacts under `.omo/evidence/`.

## RED evidence

Command:

```text
python3 -m unittest tests.scripts.test_verify_review_comparison tests.scripts.test_verify_benchmark_provenance tests.scripts.test_verify_sj16_extrapolation
```

Before implementation: exit 1, `Ran 17 tests`, `FAILED (failures=35)`.
The new comparison/provenance scripts were absent and the old SJ16 verifier
rejected `ahe-timing` while accepting legacy `measurement_kind` semantics
without an explicit migration flag.

## Verification evidence

Focused command (fresh final run before commit):

```text
python3 -m unittest -v tests.scripts.test_verify_review_comparison tests.scripts.test_verify_benchmark_provenance tests.scripts.test_verify_sj16_extrapolation
```

Recorded result: exit 0, `Ran 17 tests in 2.327s`, `OK`.

Static syntax and patch checks:

```text
python3 -m py_compile scripts/verify_review_comparison.py scripts/verify_benchmark_provenance.py scripts/verify_sj16_extrapolation.py tests/scripts/test_verify_review_comparison.py tests/scripts/test_verify_benchmark_provenance.py tests/scripts/test_verify_sj16_extrapolation.py
git diff --check
```

Recorded result: both exit 0 with no output.

Persisted producer artifact checks (no benchmark execution):

```text
python3 scripts/verify_benchmark_provenance.py --csv=.omo/evidence/work4-phase4-toy-results.csv
python3 scripts/verify_review_comparison.py --csv=.omo/evidence/work4-phase4-toy-results.csv --workload=.omo/evidence/work4-phase4-toy-workload.bin --execution-trace=.omo/evidence/work4-phase4-toy-trace.bin
```

Recorded results:

```json
{"rows": 10, "verdict": "PASS", "verifier": "benchmark-provenance"}
{"rows": 10, "suite": "toy-smoke", "verdict": "PASS", "verifier": "review-comparison", "workload_id": "review-64-e5a1f07c69125921"}
```

## Enforced contracts

- strict CSV parsing, required columns, row column counts, finite numeric
  values, exact typed booleans, and nonzero failure verdicts;
- fixed profile/capability truth tables, strict unmatched-security rejection,
  actual live-FHE metadata, Paillier profile qualification, SJ16 lower-bound
  markers, and estimator/sanitizer provenance including derived bit checks;
- byte-hashed and regenerated workload parsing, workload IDs, exact suite
  method/profile/trial policy, deterministic seeds/sets/cardinalities, and
  manifest-bound complete cyclic execution traces;
- exact row membership and group conditions, including duplicate/unexpected/
  missing method-kind pairs, parameters, target, seed, thread policy,
  timing/accuracy kinds, and aggregate trial counts;
- typed SJ16 `measurement_kind=ahe-timing` plus
  `measurement_status=measured|extrapolated`; legacy semantics are accepted
  only with `--legacy-sj16-schema`, emit `DEPRECATED`, and cannot be mixed with
  new semantics.
