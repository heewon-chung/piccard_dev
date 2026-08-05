# Dynamic Probe Isolation + Work 3 Phase 5 CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (A) Fix the `bench_dynamic` crash at small set sizes by isolating the insert/delete throughput probes from the signature-bearing bottom structure; (B) make the Work 3 Phase 5 command block executable by having `run_noise_profiles.sh` accept-and-validate the four profile arguments and by correcting the stale regeneration hint in `params.cpp`.

**Architecture:** Part A is a benchmark-only change: the throughput probes run on a value copy of the initialized `BottomStructure`, so the structure that yields `sig_x` stays pristine (deterministically non-empty for every `n`; the only other closed path is the 2^-64 dedup-collision residue — see the failure-mode background fact). `BottomStructure` itself is untouched — its bounded-deletion behavior is the paper's model and is correct. Part B is runner/diagnostic-text only: `parse_cli` gains four recognized options that are validated for equality against the values the runner already resolves internally (root seed constant and compiled profile policy); a mismatch fails closed, so the CLI can confirm but never contradict the compiled matrix.

**Tech Stack:** C++17 (benchmark TU only), bash runner with embedded Python 3, Python unittest, GoogleTest, CMake/CTest.

## Background facts (verified 2026-08-05, HEAD 9a8c575)

- Crash: `bench_dynamic ... --set_size=100 --depth=5` aborts with `Bottom structure empty for hash function 0; re-initialization required` (`src/core/bottom_structure.cpp:56-60`). Reproduced at `k=16,m=16,n∈{10,100}` and at the primary grid shape `k=128,m=64,n=100`; `n=1000` passes.
- Mechanism (hypothesis tested): `RunTimedDynamic` (`benchmarks/bench_dynamic.cpp`, Phase 2/3 around the `const size_t num_ops = 100;` block) inserts 100 foreign elements (`3000000+i`) into `bottom_x` and then deletes them. `BottomStructure::InsertIntoSorted` (`src/core/bottom_structure.cpp:66-81`) keeps only the `d` smallest hashes and discards evicted originals permanently, so after the 100 deletions `bottom_[i]` is empty exactly when all `d` smallest of (originals ∪ probes) are probe hashes — per-function probability ≈ `(100/(n+100))^d`, i.e. ~0.62 at n=10, ~1/32 at n=100 (≈98% over k=128 functions), ~6e-6 at n=1000. Confirmed empirically: `--depth=105` at n=100 exits 0, `--depth=5` crashes (SIGABRT 134).
- Failure-mode precision (corrected after plan review): for this exact probe pattern (insert X, then delete exactly X), the surviving `bottom_[i][0]` is either the true set minimum or the array is empty — the true original minimum is evicted precisely when all `d` smallest union values are probes, which is the same event as post-deletion emptiness. So the realistic failure is the abort, not a silently wrong signature. The one silent path is the 2^-64 dedup collision (`InsertIntoSorted` stores a colliding probe/original hash once at `src/core/bottom_structure.cpp:69-71`, and the probe's `Delete` then erases the shared entry); probe isolation closes it too.
- This is not only a TOY artifact: the primary suites run `bench_dynamic --set_size=1000 --depth=5 --trials=30` per security level (`scripts/run_pre_threshold_profiles.sh:121-124`); with per-function empty probability ≈6.2e-6 and 31 `RunTimedDynamic` calls per cell, that is roughly a 2.4% abort chance per primary cell (~4.8% across STD128+STD192), an intermittent evidence-run failure source. Profile mode has no per-cell try/catch (`RunProfileGrid`, `benchmarks/bench_dynamic.cpp:655-691`), so an abort kills the whole cell.
- `--depth` in `bench_dynamic` sets `params.bottom_depth` (`benchmarks/bench_dynamic.cpp:293` etc.; default 5 at `include/util/params.h:52`). The runner's dynamic commands use `--depth=5`.
- Part B blocker (Work 3 audit): the Work 3 plan's Phase 5 block invokes `run_noise_profiles.sh --profile=primary40 --reps=5 --seed=20260729 --max-queries=1048576 --margin=8 --results-root=...`, but `parse_cli` (`scripts/run_noise_profiles.sh:132-181`) accepts only `--results-root/--profile/--resume/--bench-noise/--smoke/--finalize-dir` and fails `unknown runner argument: --reps=5`. The values are already resolved internally: `ROOT_SEED = 20260729` module constant (`scripts/run_noise_profiles.sh:47`) and reps/max_queries/margin from the compiled profile policy forwarded at `:483-486`.
- Part B minor (same audit): `src/util/params.cpp:598-602` prints a regeneration hint naming `bench_noise --pre_threshold ... --emit-rows=...`, but `bench_noise` has no `--emit-rows` (rejected at `benchmarks/noise_calibration_schema.cpp:509-512`); `--emit-rows` belongs to `scripts/make_calibration_table.py` (`:681`).
- Out of scope (user-confirmed): actually executing the Phase 5 measured calibration run; any `BottomStructure`/core change; deletion-survival analytics (Work 6).

## Global Constraints

- `src/core/bottom_structure.cpp` / `include/core/bottom_structure.h` are **not modified** — bounded deletion is the paper's model, not a bug.
- `SerializeDynamicHeader()`/row schema, all CSV schemas, and all golden serializer tests are unchanged.
- No threshold changes; no changes to the compiled noise-profile matrix, shard keys, timeout tiers, or manifest formats.
- Part B validation is equality-against-resolved-values only: the runner CLI may confirm, never override, the compiled profile policy or root seed. Mismatch = hard failure before any shard runs.
- The Work 3 plan document itself is not edited.
- TDD: failing test first for every behavior change; capture RED output.
- Commit locally per task (styles below). Do NOT push.

---

### Task A1: Isolate throughput probes from the signature structure

**Files:**
- Modify: `benchmarks/bench_dynamic.cpp` (only inside `RunTimedDynamic`)
- Create: `tests/scripts/test_bench_dynamic_probe_isolation.py`
- Modify: `CMakeLists.txt` (one new `add_test` registration)

**Interfaces:**
- Consumes: `BottomStructure` is copy-constructible (plain members: two `uint32_t`, `MinHasher` value member — itself three scalars — and `std::vector<std::vector<uint64_t>>`; no user-declared special members in either class, `include/core/bottom_structure.h:41-49`, `include/core/minhash.h:36-40`).
- Produces: no interface change; `DynamicResult` fields and CSV row unchanged. New CTest entry `BenchDynamicProbeIsolation`.

Note: `tests/scripts/test_benchmark_profile_executables.py` is NOT a general harness — it takes a single positional `$<TARGET_FILE:bench_comparison>` argv and cannot run `bench_dynamic`; hence the separate new test file, following that file's argv[1] convention.

- [ ] **Step 1: Write the failing executable-level test**

Create `tests/scripts/test_bench_dynamic_probe_isolation.py`, modeled on `test_benchmark_profile_executables.py`'s structure (`BENCH_DYNAMIC = sys.argv[1] if len(sys.argv) > 1 else "bench_dynamic"` consumed before `unittest.main(argv=[sys.argv[0]])`-style invocation — copy that file's exact argv-handling idiom):

```python
def run_dynamic(self, set_size, k, m, depth, trials="1"):
    return subprocess.run(
        [BENCH_DYNAMIC, "--profile=toy-smoke", "--security=TOY",
         "--mode=timing", "--evidence_point", f"--k={k}", f"--m={m}",
         f"--set_size={set_size}", "--target-jaccard=0.5",
         f"--depth={depth}", f"--trials={trials}", "--seed=7"],
        capture_output=True, text=True)

def test_small_sets_survive_probe_phases(self):
    # (k,m,n) in {(16,16,10), (16,16,100), (128,64,100)}, depth=5:
    # exit 0, exactly header + 1 data row, stderr free of
    # "Bottom structure empty"

def test_signature_matches_uncorrupted_reference(self):
    # k=128,m=64,n=100: jaccard_computed of the depth=5 row equals the
    # depth=105 row bit-for-bit (at most num_ops=100 probe values can beat
    # the true minimum, so d=105 >= 101 always retains it and
    # bottom_[i][0] is unchanged, making depth=105 the uncorrupted
    # reference), and both rows record their own depth column (5 and 105)
    # — this kills wrong fixes (try/catch row-dropping, silent depth
    # bump, post-probe re-init that forgets the probe phases).

def test_large_set_still_passes(self):
    # k=128,m=64,n=1000, depth=5, trials=5: exit 0, one data row.
```

Register in `CMakeLists.txt` immediately after `target_include_directories(bench_dynamic ...)` (`~:872`), following the `ReviewComparisonCli` precedent (`:856-863` — registration right after its own target, avoiding a forward `$<TARGET_FILE:>` reference):

```cmake
add_test(NAME BenchDynamicProbeIsolation
         COMMAND ${Python3_EXECUTABLE}
                 ${CMAKE_SOURCE_DIR}/tests/scripts/test_bench_dynamic_probe_isolation.py
                 $<TARGET_FILE:bench_dynamic>)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && python3 tests/scripts/test_bench_dynamic_probe_isolation.py ./build/bench_dynamic`
Expected: FAIL — the small-set cases exit 134 (SIGABRT) with `Bottom structure empty for hash function 0` on stderr (the reference-equality case cannot even produce a depth=5 row).

- [ ] **Step 3: Implement the minimal fix**

In `RunTimedDynamic` (`benchmarks/bench_dynamic.cpp`), Phase 2/3: run the probes on a scratch copy so `bottom_x` stays pristine for Phase 4's `GetSignature()`:

```cpp
    // Phase 2: Insert throughput — batch of 100 inserts (plaintext only).
    // Probes run on a scratch copy: the d-depth bottom structure discards
    // evicted originals permanently, so probing the signature-bearing
    // structure can empty it once the probes are deleted again (and, on a
    // hash collision, can drop a shared entry). The copy sits outside the
    // timed region; its rows start at capacity==size, so the first
    // displacing insert costs one reallocation per hash function.
    BottomStructure probe_structure = *bottom_x;
    const size_t num_ops = 100;
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        probe_structure.Insert(3000000 + i);
    }
    dr.phase_insert_ms = timer.ElapsedMs();
    ...
    // Phase 3: Delete throughput — undo the inserts (plaintext only)
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        probe_structure.Delete(3000000 + i);
    }
```

Phases 1 and 4-8 unchanged (`bottom_x->GetSignature()` now reads the untouched structure). Timing semantics preserved up to one caveat: the vector copy allocates capacity == size, so the first probe insert that displaces a per-function maximum triggers one reallocation per hash function before capacity stabilizes (`Initialize` reserved `d_+1`, `src/core/bottom_structure.cpp:21`; the members are private, so the copy cannot re-reserve externally). This is a one-time, out-of-steady-state cost, negligible against 100×k SHA-256 evaluations — state it in the code comment rather than pretending exact parity.

- [ ] **Step 4: Run to verify it passes**

Run: `cmake --build build -j4 --target bench_dynamic && python3 tests/scripts/test_bench_dynamic_probe_isolation.py ./build/bench_dynamic && ctest --test-dir build -R BenchDynamicProbeIsolation --output-on-failure`
Expected: all three tests PASS both directly and via CTest.

- [ ] **Step 5: Guard against regressions elsewhere**

Run: `ctest --test-dir build --output-on-failure -R 'DynamicEngine|BenchmarkProfile|EstimatorProvenance'` and the previously-passing shape `./build/bench_dynamic --profile=toy-smoke --security=TOY --mode=timing --evidence_point --k=16 --m=16 --set_size=1000 --target-jaccard=0.5 --depth=5 --trials=1 --seed=7` (exit 0, one data row).
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add benchmarks/bench_dynamic.cpp tests/scripts/test_bench_dynamic_probe_isolation.py CMakeLists.txt
git commit -m "fix(benchmarks): isolate dynamic throughput probes from signature structure"
```

### Task B1: Runner accepts and validates the Phase 5 profile arguments

**Files:**
- Modify: `scripts/run_noise_profiles.sh` (embedded Python: `parse_cli` at ~132-181; the resolved-policy access used at ~483-486)
- Test: `tests/scripts/test_run_noise_profiles.py`

**Interfaces:**
- Consumes: `ROOT_SEED` constant (`scripts/run_noise_profiles.sh:47`); the compiled profile policy fields the runner already forwards to `bench_noise` (`reps`, `max_queries`, `margin` — read how `:483-486` obtains them and reuse that exact source).
- Produces: `parse_cli` result gains four optional recorded values `reps/seed/max_queries/margin` (None when absent); validation happens after the profile policy is resolved, before any shard scheduling.

- [ ] **Step 1: Write the failing tests**

In `tests/scripts/test_run_noise_profiles.py`, following the file's existing fake-`bench_noise` harness and CLI-invocation conventions:

```python
def test_phase5_profile_arguments_accepted_when_matching(self):
    # DRY_RUN invocation with the Work-3 plan's exact argument vector:
    #   --profile=primary40 --reps=5 --seed=20260729
    #   --max-queries=1048576 --margin=8 --results-root=<newdir>
    # -> exit 0, same shard matrix as without the four arguments

def test_phase5_profile_arguments_rejected_on_mismatch(self):
    # one subtest per argument with a wrong value:
    #   --reps=4, --seed=1, --max-queries=65536, --margin=9
    # -> nonzero exit, stderr names the offending argument, the CLI value,
    #    and the resolved profile value; no shard command printed/executed

def test_smoke_reps_validated_against_effective_value(self):
    # --profile=sensitivity64 --smoke --reps=5 -> nonzero exit naming
    # CLI value 5 and effective value 1 (smoke runs shards with --reps=1:
    # search_topology :530-547 and the preflight branch :2456), while
    # --profile=sensitivity64 --smoke --reps=1 passes. Guards against
    # fail-open validation that compares the CLI against the policy's
    # repetitions=5 instead of the value the shards actually receive.

def test_unknown_runner_argument_still_rejected(self):
    # --frobnicate=1 -> nonzero exit, "unknown runner argument"
```

Additionally extend the existing
`test_finalization_cli_is_exclusive_and_removed_modes_are_unknown`
(`tests/scripts/test_run_noise_profiles.py:1862-1876`): add `--reps=5`,
`--seed=20260729`, `--max-queries=1048576`, `--margin=8` to its
forbidden-extras tuple (subTest loop — test count unchanged), pinning that
`--finalize-dir` invocations still reject the four confirmations.

- [ ] **Step 2: Run to verify RED**

Run: `python3 -m unittest tests.scripts.test_run_noise_profiles -k "phase5 or smoke_reps" -v`
Expected: accept-test and smoke-reps test FAIL today with `unknown runner argument: --reps=...`.

- [ ] **Step 3: Implement**

In `parse_cli`: recognize `--reps=`, `--seed=`, `--max-queries=`, `--margin=` (exact spellings from the Work 3 plan's Phase 5 block), parse as strict nonnegative integers, store on the parsed-arguments object; every other unknown argument still fails. After the profile policy is resolved (same place the runner currently reads reps/max_queries/margin for shard commands), add:

```python
def validate_cli_confirmations(options, policy):
    expected = {
        # effective values — what the shard commands actually receive,
        # not the raw policy: smoke shards run with --reps=1
        "reps": 1 if options["smoke"] else policy["repetitions"],
        "seed": ROOT_SEED,
        "max_queries": policy["max_queries"],
        "margin": policy["flood_margin_bits"],
    }
    for name, expected_value in expected.items():
        supplied = options[name]
        if supplied is not None and supplied != expected_value:
            fail(f"--{name.replace('_', '-')}={supplied} contradicts the "
                 f"effective run value {expected_value}; the CLI may "
                 "confirm but never override the profile matrix")
```

(Adapt key names to the runner's real dicts — `parse_cli` returns a plain dict (`scripts/run_noise_profiles.sh:133-140`), so the four new keys must be initialized to `None` for the existing `is not None -> duplicate` idiom; adding the four options to the existing `names` dict gives duplicate detection and both `--opt=value`/`--opt value` spellings for free. Read the exact policy field names where the shard builder consumes them (`:483-486`) rather than trusting the names above.) `--finalize-dir` invocations must still reject the four options (they are profile-run confirmations, not finalize options) — keep `parse_cli`'s exclusivity check consistent with how `--profile` interacts with `--finalize-dir` today.

- [ ] **Step 4: GREEN**

Run: `python3 -m unittest tests.scripts.test_run_noise_profiles -v`
Expected: all pass (35 existing + 4 new).

- [ ] **Step 5: Prove the Work 3 Phase 5 block parses end-to-end**

Run (dry-run, no side effects):

```bash
DRY_RUN=1 ./scripts/run_noise_profiles.sh \
  --profile=primary40 --reps=5 --seed=20260729 \
  --max-queries=1048576 --margin=8 \
  --results-root=/tmp/phase5-parse-check
```

Expected: exit 0, full shard matrix printed, no directory created.

- [ ] **Step 6: Commit**

```bash
git add scripts/run_noise_profiles.sh tests/scripts/test_run_noise_profiles.py
git commit -m "fix(calibration): accept and validate Phase 5 profile confirmations"
```

### Task B2: Correct the stale regeneration hint

**Files:**
- Modify: `src/util/params.cpp:594-602` (hint text only — the message begins at the `Measure the exact calibration key` sentence)
- Test: `tests/unit/test_params.cpp` (only if a test pins the hint string — grep `emit-rows|emit_rows|regenerate` in tests first)

- [ ] **Step 1:** Grep for tests pinning the current hint (`rg -n "emit-rows|emit_rows" tests/ src/`). If a pinned test exists, update its expectation first (RED), else proceed.
- [ ] **Step 2:** Rewrite the hint to name the real pipeline, keeping the message's surrounding structure:

```text
regenerate via scripts/run_noise_profiles.sh (evidence run + --finalize-dir),
then python3 scripts/make_calibration_table.py --manifest=<finalized-manifest>
  --emit-rows=include/util/noise_calibration_pre_threshold_rows.inc
then python3 scripts/apply_calibration_cutover.py ... --dest=include/util/noise_calibration.inc
```

(The cutover step must be named — the rows fragment alone is not consumed by the build; keep `include/util/noise_calibration.inc` mentioned as the final regeneration target, as the current message does.)

- [ ] **Step 3:** Run `cmake --build build -j4 --target test_params && ./build/test_params` plus `rg -n "bench_noise.*--emit-rows" src include` (expect zero hits).
- [ ] **Step 4:** Commit: `git commit -m "fix(calibration): point regeneration hint at make_calibration_table"` (with the touched files).

### Task C1: End-to-end verification

- [ ] **Step 1:** `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j4 && ctest --test-dir build --output-on-failure` — expect 53/53 (52 pre-change + the new `BenchDynamicProbeIsolation`).
- [ ] **Step 2:** Crash reproduce-case matrix, all expect exit 0 + one data row: `bench_dynamic` TOY timing at `(k=16,m=16,n=10)`, `(k=16,m=16,n=100)`, `(k=128,m=64,n=100)` with `--depth=5 --trials=1 --seed=7`, and `(k=128,m=64,n=1000)` with `--trials=5` (the primary-suite shape; A1's reference-equality test already gates value correctness).
- [ ] **Step 3:** The exact Work 3 Phase 5 profile invocations (all three: primary40, then sensitivity64/feasibility128 with `--resume`) under `DRY_RUN=1` against a nonexistent root — primary40 parses and prints its matrix; the two `--resume` invocations may fail only on the missing-root/resume-state precondition, never on argument parsing.
- [ ] **Step 4:** `DRY_RUN=1 ./scripts/run_pre_threshold_profiles.sh --suite=primary --seed=20260729 --threads=8 --build-dir="$(pwd)/build"` — unchanged, exit 0 (guards Part A didn't disturb the other runner).

### Task D1: Independent review — GPT-5.6-sol (high)

- [ ] **Step 1:** Send the full diff + this plan + test logs via `codex exec -m gpt-5.6-sol -c model_reasoning_effort=high --sandbox read-only`. Focus: probe-isolation correctness (timing semantics preserved, no residual path where probes touch the signature structure), CLI confirmation-vs-override semantics, fail-closed behavior, no core/threshold/schema impact.
- [ ] **Step 2:** Fix blocking findings via the TDD loop; re-review until APPROVE.
- [ ] **Step 3:** Report to the user; finalization (push/tracked-doc `git add -f`) only on user approval.

## Self-review notes

- Root cause is evidence-backed (mechanism + quantitative fit + depth-105 differential test); the fix removes the abort (crash-only realistic failure mode — see the corrected failure-mode background fact) plus the 2^-64 dedup-collision path, without touching the paper-model core.
- Part B keeps the "CLI cannot contradict the compiled matrix" property the Work 3 audit praised, while making the frozen plan command block executable verbatim.
- Type consistency: Task A1's copy relies on implicit copy-construction of `BottomStructure`; Step 3 of A1 names the exact members making that safe. Task B1's option spellings match the Work 3 plan block exactly (`--max-queries` hyphenated, runner-side).
