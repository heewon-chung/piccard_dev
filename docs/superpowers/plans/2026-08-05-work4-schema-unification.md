# Work 4 Schema Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `verify_benchmark_provenance.py` validate Piccard-family producer CSVs against their real schemas so `run_pre_threshold_profiles.sh` suites pass end-to-end with real binaries, and bind the fake-binary test fixtures to the production schemas so the mismatch can never be masked again.

**Architecture:** The verifier gains an explicit `--schema=review|benchmark|dynamic` mode selected by the runner per producer. The `review` mode preserves today's validation semantics (its PASS JSON additionally reports the selected schema). The two new modes reuse the existing profile/sanitizer/FHE/estimator consistency checks (column names are shared) and map the measured-metric columns to each producer's real names (`time_ms*` for `SerializeBenchmarkHeader` producers, `total_ms*` for `SerializeDynamicHeader`). Producer CSV schemas and all C++ golden tests are unchanged. Fake-runner fixtures are replaced with real-schema fixtures pinned to the production serializers by a new C++ golden test.

**Tech Stack:** Python 3 stdlib (`csv`, `argparse`), GoogleTest, CMake/CTest, bash runner.

## Background facts (verified 2026-08-05, HEAD 21a99be)

- `scripts/verify_benchmark_provenance.py:21-35` `REQUIRED_COLUMNS` demands the review-comparison schema (`method`, `primitive`, `security_basis`, `measurement_status`, `total_ms*`, …) for **every** cell; `scripts/run_pre_threshold_profiles.sh:589` applies it to every MEASURED cell.
- Real producer schemas (all in `benchmarks/benchmark_estimator_provenance.cpp`):
  - `SerializeBenchmarkHeader()` (`:289`) — used by `bench_piccard` and `bench_onehot_sqrt`; 77 columns; timing stats are `time_ms,time_ms_sd,time_ms_median`; no taxonomy/`measurement_status` columns.
  - `SerializeDynamicHeader()` (`:395`) — used by `bench_dynamic`; timing stats are `total_ms,total_ms_sd,total_ms_median`; no taxonomy/`measurement_status` columns.
  - `SerializeComparisonHeader()`/review CSV — full typed schema; already passes.
- Result: real smoke run fails at the first `bench_piccard` cell with `missing required columns: …` (reproduced; terminal cell recorded `ERROR/PROCESS_ERROR`).
- Masking mechanism: `tests/scripts/test_run_pre_threshold_profiles.py:250-267` installs one fake script for all four producers that replays `.omo/evidence/work4-phase4-toy-results.csv` — a **review-schema** fixture — so the runner suite is green while the real contract is broken.
- Verified real TOY rows (seed 7) are available for fixtures; a `toy-smoke` `bench_piccard` timing row passes all sanitizer arithmetic checks (`40+20=60`, `60+log2(1024)=70`, `56+70+8=134`).
- `verify_review_comparison.py` is unaffected (runs only on review cells) and stays unchanged.
- Out of scope, tracked separately: `bench_dynamic` crashes at `set_size<=100` (`Bottom structure empty for hash function 0`) which breaks the primary n-sweep point `n=100`; row↔cell `profile_id` cross-binding in the verifier; `bench_review_comparison.cpp` TU-local serializer fork.

## Global Constraints

- Producer CSV schemas, column names, and column order are **unchanged** (plan Work-4: "Appended provenance does not reorder existing CSV columns"; existing columns retain their meaning).
- No `bench_threshold` / threshold schema changes of any kind.
- `--schema` defaults to `review` so every existing verifier invocation and fixture keeps today's validation behavior (the PASS JSON additionally carries a `"schema"` key — intended; review-CSV validation semantics unchanged).
- Fail-closed: a CSV that does not match the selected schema exits 2 with a `verify_benchmark_provenance: FAIL:` message; an unknown `--schema` value exits 2 via the file's existing CLI-misuse convention (argparse `parser.error()`, like `--run-manifest` misuse).
- TDD: write the failing test first, capture the failure, then implement.
- Do not commit until the user approves (commits happen after the GPT-5.6-sol review passes).

---

### Task 1: Verifier `--schema` support

**Files:**
- Modify: `scripts/verify_benchmark_provenance.py`
- Test: `tests/scripts/test_verify_benchmark_provenance.py`

**Interfaces:**
- Produces: CLI `verify_benchmark_provenance.py [--schema=review|benchmark|dynamic] (--csv PATH | CSV | --run-manifest M --cell-id C)`. `--schema` optional, default `review`. Exit 0 + JSON verdict on PASS (JSON gains a `"schema"` key), exit 2 on FAIL.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing tests**

Add to `tests/scripts/test_verify_benchmark_provenance.py` (follow the file's existing fixture-builder style; the helpers below are new):

```python
BENCHMARK_HEADER = (
    "label,k,m,set_size,ring_dim,time_ms,phase_minhash_ms,phase_encode_ms,"
    "phase_encrypt_ms,phase_multiply_ms,phase_rotate_sum_ms,phase_decrypt_ms,"
    "phase_bias_correction_ms,memory_bytes,ct_size_bytes,jaccard_computed,"
    "jaccard_expected,jaccard_error,jaccard_rel_error,accuracy_median,"
    "accuracy_p25,accuracy_p75,accuracy_p95,accuracy_max,encoding,mult_depth,"
    "num_cts,comm_bytes,phase_intra_digit_rotate_ms,phase_digit_and_ms,"
    "phase_cross_k_sum_ms,trials,time_ms_sd,time_ms_median,"
    "phase_minhash_ms_sd,phase_minhash_ms_median,phase_encode_ms_sd,"
    "phase_encode_ms_median,phase_encrypt_ms_sd,phase_encrypt_ms_median,"
    "phase_multiply_ms_sd,phase_multiply_ms_median,phase_rotate_sum_ms_sd,"
    "phase_rotate_sum_ms_median,phase_decrypt_ms_sd,phase_decrypt_ms_median,"
    "phase_bias_correction_ms_sd,phase_bias_correction_ms_median,"
    "rel_error_eligible_n,hash_randomness,hash_seed,hash_root_seed,"
    "accuracy_trials,phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,scaling_mod_size,"
    "sanitizer_model,sanitizer_assurance,estimator_model,profile_id,"
    "run_class,target_security_bits,comparison_eligible,measurement_kind,"
    "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version"
)

def benchmark_row(**overrides):
    row = {
        "label": "evidence_k16_m16_n10_timing", "k": "16", "m": "16",
        "set_size": "10", "ring_dim": "1024", "time_ms": "7.788",
        "jaccard_computed": "0.400000", "jaccard_expected": "0.428571",
        "jaccard_error": "0.028571", "encoding": "onehot", "trials": "1",
        "time_ms_sd": "-1.000", "time_ms_median": "7.788",
        "hash_randomness": "fixed", "hash_seed": "7", "hash_root_seed": "7",
        "accuracy_trials": "0",
        "transcript_stat_bits": "40", "max_queries": "1048576",
        "query_stat_bits": "60", "coefficient_stat_bits": "70",
        "flood_margin_bits": "8", "eval_noise_bits": "56",
        "flood_noise_bits": "134", "scaling_mod_size": "40",
        "sanitizer_model": "phase-smudging-enc0-poc-v1",
        "sanitizer_assurance":
            "empirical-phase-statistical+ciphertext-computational",
        "estimator_model": "sha256-random-ranking-poc-v1",
        "profile_id": "toy-smoke", "run_class": "smoke",
        "target_security_bits": "0", "comparison_eligible": "false",
        "measurement_kind": "fhe-timing", "actual_ring_dim": "1024",
        "log_q_bits": "159.999999723221", "plaintext_modulus": "12289",
        "num_limbs": "4", "openfhe_version": "1.5.0",
    }
    row.update(overrides)
    columns = BENCHMARK_HEADER.split(",")
    return ",".join(row.get(column, "") for column in columns)

def write_benchmark_csv(path, rows):
    path.write_text(BENCHMARK_HEADER + "\n" + "\n".join(rows) + "\n",
                    encoding="utf-8")
```

and the analogous `DYNAMIC_HEADER` / `dynamic_row(**overrides)` built from `SerializeDynamicHeader()`'s column list with defaults from the real TOY row (`total_ms=15.749`, `total_ms_sd=-1.000`, `total_ms_median=15.749`, `depth=5`, `jaccard_computed=0.600000`, `jaccard_expected=0.499250`, `jaccard_error=0.100750`, remaining sanitizer/FHE defaults identical to `benchmark_row`).

Test cases (each invoking `main([...])` the way the existing tests do):

```python
def test_benchmark_schema_accepts_real_piccard_family_row(self): ...
    # --schema=benchmark on a benchmark_row() CSV -> exit 0,
    # stdout JSON has "schema": "benchmark"

def test_benchmark_schema_accepts_accuracy_row(self): ...
    # measurement_kind="fhe-accuracy", time_ms="0.000" -> exit 0

def test_dynamic_schema_accepts_real_dynamic_row(self): ...
    # --schema=dynamic on a dynamic_row() CSV -> exit 0

def test_default_schema_still_rejects_piccard_family_csv(self): ...
    # no --schema flag on benchmark CSV -> exit 2,
    # stderr contains "missing required columns" (pins the original bug)

def test_benchmark_schema_rejects_review_csv(self): ...
    # --schema=benchmark on an existing valid review fixture -> exit 2

def test_review_schema_unchanged_on_valid_fixture(self): ...
    # --schema=review on an existing valid review fixture -> exit 0

def test_benchmark_schema_rejects_wrong_measurement_kind(self): ...
    # measurement_kind="psi-timing" -> exit 2

def test_benchmark_schema_rejects_missing_sanitizer_cell(self): ...
    # flood_noise_bits="" -> exit 2

def test_benchmark_schema_rejects_inconsistent_sanitizer_arithmetic(self): ...
    # query_stat_bits="61" -> exit 2

def test_benchmark_schema_rejects_nonfinite_metric(self): ...
    # time_ms="nan" -> exit 2

def test_benchmark_schema_rejects_estimator_model_mismatch(self): ...
    # estimator_model="not-applicable" -> exit 2

def test_benchmark_schema_rejects_wrong_profile_metadata(self): ...
    # run_class="primary" with profile_id="toy-smoke" -> exit 2

def test_benchmark_schema_rejects_comparison_eligibility_mismatch(self): ...
    # comparison_eligible="true" on toy-smoke -> exit 2

def test_unknown_schema_value_fails(self): ...
    # --schema=piccard -> argparse error (exit 2)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.scripts.test_verify_benchmark_provenance -v 2>&1 | tail -20`
Expected: new tests FAIL (`unrecognized arguments: --schema` / missing-columns FAIL where PASS expected). Pre-existing tests still pass.

- [ ] **Step 3: Implement `--schema` in the verifier**

In `scripts/verify_benchmark_provenance.py`:

```python
BENCHMARK_REQUIRED_COLUMNS = {
    "k", "m", "set_size", "trials", "accuracy_trials", "encoding",
    "hash_seed", "hash_root_seed",
    "estimator_model", "sanitizer_model", "sanitizer_assurance",
    "transcript_stat_bits", "max_queries", "query_stat_bits",
    "coefficient_stat_bits", "flood_margin_bits", "eval_noise_bits",
    "flood_noise_bits", "scaling_mod_size",
    "profile_id", "run_class", "target_security_bits",
    "comparison_eligible", "measurement_kind",
    "actual_ring_dim", "log_q_bits", "plaintext_modulus", "num_limbs",
    "openfhe_version",
    "time_ms", "time_ms_sd", "time_ms_median",
    "jaccard_computed", "jaccard_expected", "jaccard_error",
}
DYNAMIC_REQUIRED_COLUMNS = (
    (BENCHMARK_REQUIRED_COLUMNS - {"time_ms", "time_ms_sd",
                                   "time_ms_median", "encoding"})
    | {"total_ms", "total_ms_sd", "total_ms_median", "depth"}
)
FAMILY_SCHEMAS = {
    "benchmark": (BENCHMARK_REQUIRED_COLUMNS,
                  ("time_ms", "time_ms_median")),
    "dynamic": (DYNAMIC_REQUIRED_COLUMNS,
                ("total_ms", "total_ms_median")),
}
```

Extend `FLOAT_COLUMNS` with `{"time_ms", "time_ms_sd", "time_ms_median", "total_ms_sd"}` (`total_ms`/`total_ms_median` are already listed). `time_ms_sd`/`total_ms_sd` are `-1.000` for `trials=1`: finiteness only, no sign check.

```python
def validate_family_rows(rows, schema_name):
    metric_columns = FAMILY_SCHEMAS[schema_name][1]
    for row_number, row in enumerate(rows, 2):
        _validate_numeric_cells(row, row_number)
        target, transcript, profile_eligible = _validate_profile(row, row_number)
        kind = row["measurement_kind"]
        require(kind in {"fhe-timing", "fhe-accuracy"},
                f"row {row_number}: invalid Piccard-family measurement_kind {kind!r}")
        require(row["comparison_eligible"] ==
                ("true" if profile_eligible else "false"),
                f"row {row_number}: comparison_eligible mismatch for profile")
        _validate_models(row, row_number, "piccard")
        _validate_fhe(row, row_number, True)
        require(int(row["transcript_stat_bits"]) == transcript,
                f"row {row_number}: sanitizer profile transcript_stat_bits mismatch")
        for column in (*metric_columns,
                       "jaccard_computed", "jaccard_expected", "jaccard_error"):
            value = row.get(column, "")
            require(value != "",
                    f"row {row_number}: measured {column} is required")
            _finite(value, column, row_number)
```

In `main()`: `parser.add_argument("--schema", choices=("review", "benchmark", "dynamic"), default="review")`; then

```python
if args.schema == "review":
    _, rows = load_csv(path)
    validate_rows(rows)
else:
    _, rows = load_csv(path, required=FAMILY_SCHEMAS[args.schema][0])
    validate_family_rows(rows, args.schema)
```

and add `"schema": args.schema` to the PASS JSON.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.scripts.test_verify_benchmark_provenance -v 2>&1 | tail -5`
Expected: OK, zero failures (old + new tests).

### Task 2: Runner passes the schema per producer

**Files:**
- Modify: `scripts/run_pre_threshold_profiles.sh` (the embedded Python: `verifier_command`, `run_verifiers`, and the dry-run `VERIFY` printer near line 408)
- Test: `tests/scripts/test_run_pre_threshold_profiles.py`

**Interfaces:**
- Consumes: Task 1's `--schema` flag.
- Produces: every provenance `VERIFY` invocation (dry-run text and real command) carries `--schema=<benchmark|dynamic|review>` chosen from the cell's `producer`.

- [ ] **Step 1: Write the failing test**

```python
SCHEMA_BY_PRODUCER = {
    "bench_piccard": "benchmark",
    "bench_onehot_sqrt": "benchmark",
    "bench_dynamic": "dynamic",
    "bench_review_comparison": "review",
}

def test_verifier_commands_carry_producer_schema(self):
    # run the fake smoke suite, then read manifest cells; for every cell
    # assert the recorded/printed provenance VERIFY line contains
    # f"--schema={SCHEMA_BY_PRODUCER[cell['producer']]}"
```

Also update the existing pinned dry-run/`VERIFY` golden strings in this file to include the flag (they are byte-pinned and will otherwise fail).

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.scripts.test_run_pre_threshold_profiles -v 2>&1 | tail -15`
Expected: new test FAILS (no `--schema` in commands); pinned goldens updated in the same edit must fail until Step 3.

- [ ] **Step 3: Implement**

In `verifier_command` (`run_pre_threshold_profiles.sh:585-591`):

```python
SCHEMA_BY_PRODUCER = {
    "bench_piccard": "benchmark",
    "bench_onehot_sqrt": "benchmark",
    "bench_dynamic": "dynamic",
    "bench_review_comparison": "review",
}

def verifier_command(project, manifest_path, cell, review):
    common = [f"--run-manifest={manifest_path}", f"--cell-id={cell['cell_id']}"]
    schema = SCHEMA_BY_PRODUCER[cell["producer"]]
    commands = [[sys.executable,
                 str(project / "scripts" / "verify_benchmark_provenance.py"),
                 f"--schema={schema}", *common]]
    if review:
        commands.append([sys.executable,
                         str(project / "scripts" / "verify_review_comparison.py"),
                         *common])
    return commands
```

Mirror the same flag in the dry-run `VERIFY` printer (line ~408) so printed and executed commands match. An unknown producer must raise (`KeyError` is acceptable — fail closed).

- [ ] **Step 4: Run tests** — same command as Step 2, expected OK. (Full-suite green arrives in Task 3 when fixtures switch schemas.)

### Task 3: Real-schema fixtures + anti-masking pin

**Files:**
- Create: `tests/fixtures/runner/benchmark_toy_rows.csv` (header `SerializeBenchmarkHeader()`; row 2 = real TOY timing row; row 3 = real TOY accuracy row — both captured from `./build/bench_piccard --profile=toy-smoke … --seed=7`, verbatim)
- Create: `tests/fixtures/runner/dynamic_toy_rows.csv` (header `SerializeDynamicHeader()`; row 2 = real TOY `n=1000` timing row, verbatim)
- Modify: `tests/scripts/test_run_pre_threshold_profiles.py` (fake harness)
- Modify: `tests/unit/test_estimator_provenance_serializers.cpp`
- Modify: `CMakeLists.txt` (fixture-dir compile definition for that test target)

**Interfaces:**
- Consumes: `SerializeBenchmarkHeader()` / `SerializeDynamicHeader()` from `benchmarks/benchmark_estimator_provenance.h`.
- Produces: fixture files consumed by both the Python fake harness and the C++ pin test; compile definition `PICCARD_RUNNER_FIXTURE_DIR`.

- [ ] **Step 1: Write the failing C++ pin test**

In `tests/unit/test_estimator_provenance_serializers.cpp`:

```cpp
namespace {
std::string ReadFixtureLine(const char* name) {
    std::ifstream stream(std::string(PICCARD_RUNNER_FIXTURE_DIR "/") + name);
    EXPECT_TRUE(stream.is_open()) << name;
    std::string line;
    std::getline(stream, line);
    return line + "\n";
}
}  // namespace

TEST(RunnerFixtures, BenchmarkFixtureHeaderMatchesProduction) {
    EXPECT_EQ(ReadFixtureLine("benchmark_toy_rows.csv"),
              SerializeBenchmarkHeader());
}

TEST(RunnerFixtures, DynamicFixtureHeaderMatchesProduction) {
    EXPECT_EQ(ReadFixtureLine("dynamic_toy_rows.csv"),
              SerializeDynamicHeader());
}
```

CMake, on the `test_estimator_provenance_serializers` target:

```cmake
target_compile_definitions(test_estimator_provenance_serializers PRIVATE
    PICCARD_RUNNER_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures/runner")
```

- [ ] **Step 2: Run to verify it fails** — `cmake --build build -j4 --target test_estimator_provenance_serializers && ./build/test_estimator_provenance_serializers --gtest_filter='RunnerFixtures.*'`; expected FAIL (fixture files absent).

- [ ] **Step 3: Create the fixtures and rewire the fake harness**

Create the two fixture CSVs with real captured rows. In `test_run_pre_threshold_profiles.py`, point the Piccard-family fakes at them (review fake keeps `.omo/evidence/work4-phase4-toy-results.csv`):

```python
else:
    name = pathlib.Path(sys.argv[0]).name
    fixture = "dynamic_toy_rows.csv" if name == "bench_dynamic" \
        else "benchmark_toy_rows.csv"
    lines = (fixtures / fixture).read_text().splitlines(True)
    timing_row, accuracy_row = (lines[1], lines[1]) if name == "bench_dynamic" \
        else (lines[1], lines[2])
    mode = next(a.split("=", 1)[1] for a in args if a.startswith("--mode="))
    if "--evidence_point" in args:
        rows = {"bench_onehot_sqrt": 2}.get(name, 1) * \
            [timing_row if mode == "timing" else accuracy_row]
    elif name == "bench_piccard":            # --mode=combined
        rows = [timing_row] * 15 + [accuracy_row] * 15
    elif name == "bench_dynamic":
        rows = [timing_row] * 15
    else:                                    # bench_onehot_sqrt native grids
        rows = [timing_row] * 28 if mode == "timing" else [accuracy_row] * 22
    sys.stdout.write(lines[0] + "".join(rows))
```

(`fixtures` is passed via the existing `FAKE_EVIDENCE`-style env mechanism — add `FAKE_FIXTURES` pointing at `tests/fixtures/runner`. Replicated-row counts must keep matching the runner's frozen `expected_csv_rows`.)

Add one masking-regression test: a fake whose `bench_piccard` replays the **review** fixture must make the suite fail (exit != 0) — this pins that a wrong-schema fixture can no longer pass.

- [ ] **Step 4: Run to verify green**

Run: `cmake --build build -j4 --target test_estimator_provenance_serializers && ./build/test_estimator_provenance_serializers && python3 -m unittest tests.scripts.test_run_pre_threshold_profiles -v 2>&1 | tail -5`
Expected: all PASS.

### Task 4: Register the Phase-5 verifier suites with CTest

**Files:**
- Modify: `CMakeLists.txt` (next to the existing `ReportingTaxonomy`/`PreThresholdProfileRunner` registrations, ~lines 726-748; follow their exact `add_test(NAME … COMMAND Python3::Interpreter -m unittest …)` pattern)

- [ ] **Step 1:** Add `add_test` entries `VerifyReviewComparison`, `VerifyBenchmarkProvenance`, `VerifySJ16Extrapolation` for `tests.scripts.test_verify_review_comparison`, `tests.scripts.test_verify_benchmark_provenance`, `tests.scripts.test_verify_sj16_extrapolation` (same `WORKING_DIRECTORY`/environment as `ReportingTaxonomy`).
- [ ] **Step 2:** `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && ctest --test-dir build -N | grep -i verify` — expect the three new entries (total 52 tests).
- [ ] **Step 3:** `ctest --test-dir build -R 'VerifyReviewComparison|VerifyBenchmarkProvenance|VerifySJ16Extrapolation' --output-on-failure` — expect 3/3 pass.

### Task 5: End-to-end re-verification (the original reproduce case)

- [ ] **Step 1:** Clean rebuild + full suite: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j4 && ctest --test-dir build --output-on-failure` — expect 52/52.
- [ ] **Step 2:** Real smoke suite (the exact case that failed before the fix):

```bash
SMOKE_ROOT="$(mktemp -d)"; rmdir "$SMOKE_ROOT"
./scripts/run_pre_threshold_profiles.sh --suite=smoke --seed=7 --threads=2 \
  --build-dir="$(pwd)/build" --results-root="$SMOKE_ROOT"
echo "EXIT=$?"
```

Expected: exit 0; both cells `MEASURED/NONE` in `terminal-cells.tsv`; the `bench_piccard` cell's `VERIFY` line shows `--schema=benchmark` and `{"schema": "benchmark", …, "verdict": "PASS"}`.
- [ ] **Step 3:** `DRY_RUN=1 ./scripts/run_pre_threshold_profiles.sh --suite=primary --seed=20260729 --threads=8 --build-dir="$(pwd)/build"` — exit 0, `VERIFY` lines carry per-producer schemas, no files created.

### Task 6: Independent review — GPT-5.6-sol (high)

- [ ] **Step 1:** Send the full diff + this plan + test/smoke logs to the reviewer channel: `codex exec -m gpt-5.6-sol` (high reasoning). Ask for verdict APPROVE / blocking findings on: schema-mode correctness, fail-closed behavior, fixture pinning strength, no producer-schema drift, no threshold impact.
- [ ] **Step 2:** Fix blocking findings (returning to the relevant task's TDD loop) and re-review until APPROVE.
- [ ] **Step 3:** Present results to the user; commit only after user approval (suggested split: `fix(scripts): validate producer schemas in provenance verifier`, `test(benchmarks): pin runner fixtures to production schemas`, `build(tests): register verifier suites with ctest`).

## Self-review notes

- Spec coverage: BLOCKING-1 (schema mismatch) → Tasks 1-3; masking → Task 3; MINOR ctest registration → Task 4; reproduce-case re-verification → Task 5; user's review requirement → Task 6.
- The `review` default keeps every existing caller/fixture green; the original failure is pinned as a regression test (Task 1 `test_default_schema_still_rejects_piccard_family_csv`, Task 3 masking-regression test).
- Type/name consistency: `FAMILY_SCHEMAS` keys `benchmark|dynamic` match the runner's `SCHEMA_BY_PRODUCER` values and the argparse choices; fixture filenames `benchmark_toy_rows.csv`/`dynamic_toy_rows.csv` are identical across Tasks 3 steps and the C++ pin test.
