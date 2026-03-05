# Plan: Dynamic Update & Threshold Benchmarks

**Date:** 2026-02-27
**Status:** Draft (Revised per Architect/Critic consensus)
**Complexity:** MEDIUM

---

## Context

The Piccard FHE project has three protocol variants (basic/static, dynamic, threshold), but benchmarks only cover the basic protocol. The dynamic and threshold code is fully implemented and unit-tested. This plan adds benchmark coverage for both variants to generate paper-ready performance data.

### Key Technical Facts (from codebase investigation)

- **Dynamic variant**: `BottomStructure` with `Initialize/Insert/Delete/GetSignature`. After signature extraction, the FHE pipeline is identical to basic. The interesting measurements are: (a) BottomStructure operation throughput (pure CPU, no FHE), and (b) end-to-end dynamic protocol vs basic protocol overhead. **Note:** The dynamic CSV columns `phase_init_ms`, `phase_insert_ms`, `phase_delete_ms`, `ops_insert_per_sec`, `ops_delete_per_sec` are plaintext-only measurements (no FHE involved). The FHE phases (signature, encode, encrypt, compute, decrypt) are identical between dynamic and basic -- only the pre-processing (BottomStructure Initialize vs MinHash) differs.
- **Threshold variant**: Evaluates degree-k polynomial via Paterson-Stockmeyer in BFV. `mult_depth` is significantly higher than basic (formula: `1 + baby_depth + giant_mults`). Corrected computation for each k value:

| k | s = ceil(sqrt(k+1)) | baby_depth | num_chunks = (k+s)/s | giant_mults = num_chunks-1 | mult_depth = 1+baby+giant |
|---|---|---|---|---|---|
| 16 | 5 | 3 | 4 | 3 | **7** |
| 32 | 6 | 3 | 6 | 5 | **9** |
| 64 | 9 | 4 | 8 | 7 | **12** |
| 128 | 12 | 4 | 11 | 10 | **15** |

  For k=128, mult_depth=15 requires ring_dim ~65536 at STD128, which is slow but feasible.

- **Existing infrastructure**: `BenchmarkConfig` with CLI flags (`--mode`, `--k`, `--m`, `--set_size`, `--trials`, `--security`), `Timer`, `CSVWriter`, `MemoryTracker`, `CiphertextSizer`. The `run_benchmarks.sh` script iterates security levels and runs timing+accuracy modes. `summarize_results.py` generates 5 table types.
- **Existing script `run_benchmarks_macbook.sh`**: An older single-security-level variant of `run_benchmarks.sh`. This script is superseded by `run_benchmarks.sh --quick` and should be considered deprecated. No changes will be made to it.

### What the paper needs

1. A table showing BottomStructure Insert/Delete throughput and dynamic protocol overhead vs basic
2. A table showing threshold protocol timing (how the polynomial evaluation cost scales)
3. Threshold accuracy: does the threshold decision (bool) agree with the expected decision?

---

## Work Objectives

Add two new benchmark executables (`bench_dynamic`, `bench_threshold`) following existing patterns, wire them into `run_benchmarks.sh`, and add summary tables to `summarize_results.py`.

---

## Guardrails

### Must Have
- CSV output compatible with existing `summarize_results.py` infrastructure
- Explicit CSV column names defined in this plan (executor must use these exact names)
- Multi-trial median timing (consistent with `bench_piccard` pattern)
- CLI flags consistent with `BenchmarkConfig` (reuse or extend it)
- Runnable via `run_benchmarks.sh` alongside existing benchmarks
- Threshold benchmark must handle gracefully when OpenFHE cannot support the required `mult_depth` at a given security level -- write SKIPPED rows with timing fields = -1
- Quick-mode overrides for fast CI/smoke testing

### Must NOT Have
- Modifications to core library code (`src/`, `include/piccard/`)
- Changes to existing benchmark executables (`bench_piccard.cpp`, `bench_comparison.cpp`)
- New dependencies beyond what already exists
- Changes to `run_benchmarks_macbook.sh` (deprecated; superseded by `run_benchmarks.sh --quick`)

---

## Task Flow

```
Step 1: bench_dynamic.cpp          (new file)
Step 2: bench_threshold.cpp        (new file)
Step 3: CMakeLists.txt             (add 2 build targets)
Step 4: run_benchmarks.sh          (add dynamic + threshold runs, quick-mode overrides)
Step 5: summarize_results.py       (add Tables 6-8, SKIPPED row handling)
```

---

## Detailed TODOs

### Step 1: Create `benchmarks/bench_dynamic.cpp`

**Purpose:** Benchmark the dynamic variant's BottomStructure operations and end-to-end protocol.

**Modes:**
- `--mode=timing`: Per-phase timing of dynamic protocol + BottomStructure operation throughput
- `--mode=accuracy`: Dynamic variant accuracy vs exact Jaccard across similarity levels

**New CLI flag:** `--depth=D` (BottomStructure depth, default 5)

**Quick-mode overrides:** When `--quick` is passed (or detected via reduced trials): k=128, d=5, set_size=1000, trials=2.

**CSV schema** (new `DynamicResult` struct, written via a dedicated CSV writer).

Exact column names (executor must use these verbatim so `summarize_results.py` can parse via `r["column_name"]`):
```
label,k,m,ring_dim,depth,phase_init_ms,phase_insert_ms,phase_delete_ms,phase_signature_ms,phase_encode_ms,phase_encrypt_ms,phase_compute_ms,phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,jaccard_computed,jaccard_expected,jaccard_error,ops_insert_per_sec,ops_delete_per_sec
```

Column definitions:
| Column | Type | Description |
|--------|------|-------------|
| `label` | string | Scenario identifier, e.g. `vary_k_128`, `dynamic_vs_basic_k128` |
| `k` | int | Number of hash functions |
| `m` | int | Number of slots per hash function |
| `ring_dim` | int | BFV ring dimension (N) |
| `depth` | int | BottomStructure depth (d) |
| `phase_init_ms` | float | BottomStructure Initialize time (plaintext only) |
| `phase_insert_ms` | float | Batch insert time (plaintext only) |
| `phase_delete_ms` | float | Batch delete time (plaintext only) |
| `phase_signature_ms` | float | GetSignature time (plaintext only) |
| `phase_encode_ms` | float | Plaintext encoding time |
| `phase_encrypt_ms` | float | BFV encryption time |
| `phase_compute_ms` | float | FHE multiply + rotate-sum time |
| `phase_decrypt_ms` | float | Decryption + decode time |
| `total_ms` | float | End-to-end total |
| `memory_bytes` | int | Peak RSS |
| `ct_size_bytes` | int | Ciphertext size |
| `jaccard_computed` | float | Computed Jaccard value |
| `jaccard_expected` | float | Expected exact Jaccard value |
| `jaccard_error` | float | |computed - expected| |
| `ops_insert_per_sec` | float | Insert throughput |
| `ops_delete_per_sec` | float | Delete throughput |

**Note on plaintext measurements:** `phase_init_ms`, `phase_insert_ms`, `phase_delete_ms`, `ops_insert_per_sec`, `ops_delete_per_sec` are all plaintext-only BottomStructure operations. No FHE is involved. The FHE phases (encode, encrypt, compute, decrypt) are identical to the basic protocol. This is the key insight for the paper: dynamic updates add CPU-only pre-processing cost while the expensive FHE phases remain unchanged.

**Timing scenarios:**

1. **Vary k** (k in {64, 128, 256, 512}): BottomStructure has k sorted arrays, so Insert/Delete cost scales with k. Measure Initialize, Insert throughput (batch of 100 inserts), Delete throughput (batch of 100 deletes), then full dynamic protocol (signature->encode->encrypt->compute->decrypt).

2. **Vary depth d** (d in {3, 5, 10, 20}): Deeper structures track more hash values per function, affecting Insert/Delete cost. Fixed k=128, m=32.

3. **Vary set size** (sizes in {1000, 10000, 50000, 100000}): Initialize cost scales with set size. Insert/Delete are O(k*d) per element regardless of set size but the signature may differ.

4. **Dynamic vs Basic comparison**: For same (k, m, set_size) configurations, run both `ComputeJaccard` and `ComputeJaccardDynamic` and report the overhead ratio. This is the key table for the paper -- it shows the dynamic protocol adds minimal overhead to the FHE phases since only the pre-processing (Initialize vs MinHash) differs. Optionally include a "dynamic vs basic overhead" comparison row explicitly showing that FHE phases are identical and only pre-processing differs.

**Accuracy scenario:** Same as bench_piccard accuracy but using `ComputeJaccardDynamic`. Sweep overlaps {0.0, 0.1, ..., 1.0}. Verify dynamic matches basic protocol accuracy.

**Implementation pattern:** Follow `bench_piccard.cpp` structure -- `RunTimedProtocol` returns a result struct, `RunMultiTrial` takes median, scenario functions iterate parameter sweeps.

**Acceptance criteria:**
- [ ] Compiles and links against `piccard_fhe`
- [ ] Produces valid CSV on stdout with all columns populated using the exact column names above
- [ ] `--mode=timing` runs all 4 scenario types
- [ ] `--mode=accuracy` sweeps 11 overlap levels
- [ ] Insert/Delete throughput (ops/sec) columns are populated
- [ ] Dynamic vs basic overhead ratio is printed to stderr

---

### Step 2: Create `benchmarks/bench_threshold.cpp`

**Purpose:** Benchmark the threshold variant's polynomial evaluation and end-to-end protocol.

**Modes:**
- `--mode=timing`: Per-phase timing with polynomial evaluation as a separate phase
- `--mode=accuracy`: Threshold decision correctness across similarity levels and tau values

**New CLI flags:** `--tau=T` (threshold value, default k/2), `--max_k=K` (maximum k to attempt, default 128)

**Quick-mode overrides:** When `--quick` is passed: k=16 only, tau=k/2, trials=2.

**Threshold k range per security level:**
- **TOY**: k={16, 32, 64, 128} (all fast, use for smoke testing)
- **STD128**: k={16, 32, 64, 128} (k=128 is slow with ring_dim ~65536 but feasible and included by default)
- **STD192, STD256**: k={16, 32, 64} by default. Use `--max_k=128` flag to opt-in to k=128 (very slow, may hit OpenFHE limits)

**CSV schema** (new `ThresholdResult` struct).

Exact column names:
```
label,k,m,ring_dim,tau,mult_depth,phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,phase_multiply_ms,phase_rotate_sum_ms,phase_mask_ms,phase_poly_eval_ms,phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,threshold_result,threshold_expected,threshold_correct,note
```

Column definitions:
| Column | Type | Description |
|--------|------|-------------|
| `label` | string | Scenario identifier, e.g. `vary_k_128`, `SKIPPED_k128_STD256` |
| `k` | int | Number of hash functions (polynomial degree) |
| `m` | int | Number of slots per hash function |
| `ring_dim` | int | BFV ring dimension (N), or -1 if SKIPPED |
| `tau` | int | Threshold value |
| `mult_depth` | int | Required multiplicative depth |
| `phase_minhash_ms` | float | MinHash computation time, or -1 if SKIPPED |
| `phase_encode_ms` | float | Plaintext encoding time, or -1 if SKIPPED |
| `phase_encrypt_ms` | float | BFV encryption time, or -1 if SKIPPED |
| `phase_multiply_ms` | float | Ciphertext multiply time, or -1 if SKIPPED |
| `phase_rotate_sum_ms` | float | Rotate-and-sum time, or -1 if SKIPPED |
| `phase_mask_ms` | float | MultiplyPlain with e_1 time, or -1 if SKIPPED |
| `phase_poly_eval_ms` | float | Paterson-Stockmeyer polynomial evaluation time, or -1 if SKIPPED |
| `phase_decrypt_ms` | float | Decryption + decode time, or -1 if SKIPPED |
| `total_ms` | float | End-to-end total, or -1 if SKIPPED |
| `memory_bytes` | int | Peak RSS, or 0 if SKIPPED |
| `ct_size_bytes` | int | Ciphertext size, or 0 if SKIPPED |
| `threshold_result` | int | 0 or 1 computed threshold decision, or -1 if SKIPPED |
| `threshold_expected` | int | 0 or 1 expected threshold decision, or -1 if SKIPPED |
| `threshold_correct` | int | 1 if result==expected, 0 otherwise, or -1 if SKIPPED |
| `note` | string | Empty for normal rows; error message for SKIPPED rows |

**SKIPPED row handling:** When OpenFHE throws an exception for a threshold configuration (e.g., mult_depth too high for the security level):
1. Catch the exception in a try/catch around `engine.Initialize()`
2. Write a CSV row with `label` = `SKIPPED_<config>` (e.g., `SKIPPED_k128_STD256`)
3. Set all timing fields to `-1`
4. Set `memory_bytes` and `ct_size_bytes` to `0`
5. Set `threshold_result`, `threshold_expected`, `threshold_correct` to `-1`
6. Set `note` to the exception message (sanitized: no commas, no newlines)
7. Print a warning to stderr: `WARNING: Skipped k=128 at STD256: <reason>`
8. Continue to the next configuration (do not abort)

**Timing scenarios:**

1. **Vary k** (k per security level as defined above): Higher k increases polynomial degree, directly increasing `mult_depth` and computational cost. This is the most important parameter sweep -- it shows the Paterson-Stockmeyer scaling. tau=k/2 for each k. **Important:** If OpenFHE fails (throws), catch the exception and emit a SKIPPED row per the protocol above.

2. **Vary tau** (tau in {1, k/4, k/2, 3k/4, k}): Fixed k=32 or k=64. tau does not change mult_depth (polynomial degree is always k), so timing should be constant across tau. But accuracy changes -- this validates the polynomial is correct for different thresholds.

3. **Threshold vs basic timing comparison**: For each k, compare threshold protocol total time vs basic protocol total time. Report the overhead factor (expected to be large due to polynomial evaluation).

**Accuracy scenario:** For each (tau, overlap) combination, run the threshold protocol and check if the boolean result matches the expected decision. The expected decision is: `match_count >= tau` where `match_count` is computed by the basic protocol's `Decode`. Sweep tau in {k/4, k/2, 3k/4} and overlaps in {0.0, 0.1, ..., 1.0}. Report: number correct / total, false positive rate, false negative rate.

**Implementation pattern:** Similar to `bench_piccard.cpp`. The key difference is that `RunTimedProtocol` breaks the compute phase into sub-phases: multiply, rotate-sum, mask (MultiplyPlain with e_1), and poly_eval (EvalPolyBFV). This mirrors the implementation in `PiccardEngine::ComputeThresholdResult`.

**Acceptance criteria:**
- [ ] Compiles and links against `piccard_fhe`
- [ ] Produces valid CSV on stdout using the exact column names above
- [ ] `--mode=timing` reports poly_eval_ms as a separate phase
- [ ] `--mode=timing` gracefully skips configurations where OpenFHE throws, emitting SKIPPED rows with all timing fields = -1 and a `note` field with the error message
- [ ] `--mode=accuracy` reports threshold_correct (bool) and aggregate accuracy
- [ ] `mult_depth` is included in CSV output for each configuration
- [ ] `--max_k` flag controls the upper bound of k values attempted
- [ ] k range respects the per-security-level defaults (TOY/STD128: up to 128; STD192/STD256: up to 64 unless `--max_k=128`)

---

### Step 3: Update `CMakeLists.txt`

**Changes:** Add two new benchmark targets in the Benchmarks section (after existing `bench_comparison`).

```cmake
add_executable(bench_dynamic benchmarks/bench_dynamic.cpp)
target_link_libraries(bench_dynamic piccard_fhe)
target_include_directories(bench_dynamic PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

add_executable(bench_threshold benchmarks/bench_threshold.cpp)
target_link_libraries(bench_threshold piccard_fhe)
target_include_directories(bench_threshold PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
```

**Acceptance criteria:**
- [ ] Both targets compile when `BUILD_BENCHMARKS=ON` and OpenFHE is found
- [ ] Follows same pattern as existing `bench_piccard` and `bench_comparison` targets

---

### Step 4: Update `scripts/run_benchmarks.sh`

**Changes:** Add `bench_dynamic` and `bench_threshold` runs inside the per-security-level loop, after the existing 4 benchmark runs. Add quick-mode overrides for the new benchmarks. Update binary verification.

**Quick-mode overrides for new benchmarks:**
- `bench_dynamic`: `--depth=5 --set_size=1000` (plus the existing `--trials=2` from quick mode)
- `bench_threshold`: `--max_k=16` (plus the existing `--trials=2` from quick mode; only k=16, tau=k/2)

New runs per security level:
```bash
# 5. bench_dynamic: timing
run_bench "Dynamic timing ($SECURITY)" \
    "$BUILD_DIR/bench_dynamic" \
    "$OUT_DIR/dynamic_timing_${SECURITY}.csv" \
    --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" $DYNAMIC_EXTRA_FLAGS

# 6. bench_dynamic: accuracy
run_bench "Dynamic accuracy ($SECURITY)" \
    "$BUILD_DIR/bench_dynamic" \
    "$OUT_DIR/dynamic_accuracy_${SECURITY}.csv" \
    --mode=accuracy --security="$SECURITY" --trials="$ACCURACY_TRIALS" $DYNAMIC_EXTRA_FLAGS

# 7. bench_threshold: timing
run_bench "Threshold timing ($SECURITY)" \
    "$BUILD_DIR/bench_threshold" \
    "$OUT_DIR/threshold_timing_${SECURITY}.csv" \
    --mode=timing --security="$SECURITY" --trials="$TIMING_TRIALS" $THRESHOLD_EXTRA_FLAGS

# 8. bench_threshold: accuracy
run_bench "Threshold accuracy ($SECURITY)" \
    "$BUILD_DIR/bench_threshold" \
    "$OUT_DIR/threshold_accuracy_${SECURITY}.csv" \
    --mode=accuracy --security="$SECURITY" --trials="$ACCURACY_TRIALS" $THRESHOLD_EXTRA_FLAGS
```

Where the extra flags are set based on quick mode:
```bash
DYNAMIC_EXTRA_FLAGS=""
THRESHOLD_EXTRA_FLAGS=""
if [[ "$TAG" == "quick" ]]; then
    DYNAMIC_EXTRA_FLAGS="--depth=5 --set_size=1000"
    THRESHOLD_EXTRA_FLAGS="--max_k=16"
fi
```

Also update the binary verification section to check for `bench_dynamic` and `bench_threshold`.

**Note:** `run_benchmarks_macbook.sh` is not modified. It is a legacy single-security-level script that predates the multi-security-level `run_benchmarks.sh`. It is effectively deprecated in favor of `run_benchmarks.sh --quick`.

**Acceptance criteria:**
- [ ] `--quick` mode runs all 8 benchmarks (4 existing + 4 new) with TOY security and reduced parameters
- [ ] Output CSVs follow naming convention: `{type}_{mode}_{security}.csv`
- [ ] New benchmarks build automatically if binaries are missing
- [ ] Quick-mode overrides are applied to new benchmarks (bench_dynamic: small set_size; bench_threshold: k=16 only)

---

### Step 5: Update `scripts/summarize_results.py`

**Changes:** Add 3 new table functions, wire them into main, add SKIPPED row handling, update `read_csv()` stderr filter.

**read_csv() update:** Add `"SKIP"` to the stderr prefix filter on line 36 so that SKIPPED rows are NOT filtered out (they are valid CSV data, not stderr). The current filter skips lines starting with `("Benchmark", "===", "  ", "(No", "---")`. No change needed -- SKIPPED rows start with `SKIPPED_` which does not match any existing prefix. However, add a note/comment in the code clarifying this.

**SKIPPED row handling in table functions:** When iterating rows, check if timing fields are `-1` (indicating a SKIPPED configuration). Use `r.get(field, "0")` defaults for safety. Display "N/A" in table cells for SKIPPED rows. Include the `note` field content as a footnote or inline annotation.

**Table 6: Dynamic Protocol Timing** (`table_dynamic_timing`)
- Parse `dynamic_timing_{SEC}.csv`
- Headers: Label, k, m, d, Init(ms), Insert(ops/s), Delete(ops/s), Sig+Enc+Compute+Dec(ms), Total(ms), Overhead vs Basic
- Focus on the "dynamic vs basic comparison" scenario rows
- Access columns via: `r["label"]`, `r["k"]`, `r["m"]`, `r["depth"]`, `r["phase_init_ms"]`, `r["ops_insert_per_sec"]`, `r["ops_delete_per_sec"]`, `r["phase_signature_ms"]`, `r["phase_encode_ms"]`, `r["phase_encrypt_ms"]`, `r["phase_compute_ms"]`, `r["phase_decrypt_ms"]`, `r["total_ms"]`, `r["ct_size_bytes"]`
- LaTeX variant for paper

**Table 7: Threshold Protocol Timing** (`table_threshold_timing`)
- Parse `threshold_timing_{SEC}.csv`
- Headers: k, tau, mult_depth, N, Encrypt(ms), Mul(ms), RotSum(ms), Mask(ms), PolyEval(ms), Decrypt(ms), Total(ms), CT Size, vs Basic
- Access columns via: `r["k"]`, `r["tau"]`, `r["mult_depth"]`, `r["ring_dim"]`, `r["phase_encrypt_ms"]`, `r["phase_multiply_ms"]`, `r["phase_rotate_sum_ms"]`, `r["phase_mask_ms"]`, `r["phase_poly_eval_ms"]`, `r["phase_decrypt_ms"]`, `r["total_ms"]`, `r["ct_size_bytes"]`
- For SKIPPED rows (where `r.get("total_ms", "0")` == "-1" or label starts with "SKIPPED_"): display "N/A" for all timing cells, include `r.get("note", "")` as annotation
- Show how poly_eval dominates and how mult_depth drives ring_dim and total cost
- LaTeX variant for paper

**Table 8: Threshold Accuracy** (`table_threshold_accuracy`)
- Parse `threshold_accuracy_{SEC}.csv`
- Headers: tau, Overlap, Expected, Got, Correct, FP Rate, FN Rate
- Access columns via: `r["tau"]`, `r["label"]`, `r["threshold_expected"]`, `r["threshold_result"]`, `r["threshold_correct"]`
- Skip rows where `r.get("threshold_correct", "-1")` == "-1" (SKIPPED configurations)
- Aggregate correctness across trials
- LaTeX variant for paper

Wire into main loop (inside the `for sec in security_levels:` block):
```python
dynamic_timing = read_csv(d / f"dynamic_timing{suffix}.csv")
dynamic_accuracy = read_csv(d / f"dynamic_accuracy{suffix}.csv")
threshold_timing = read_csv(d / f"threshold_timing{suffix}.csv")
threshold_accuracy = read_csv(d / f"threshold_accuracy{suffix}.csv")

run_and_save(table_dynamic_timing,
             sd / f"table6_dynamic_timing{file_suffix}.txt" if sd else None,
             dynamic_timing, latex=args.latex)
run_and_save(table_threshold_timing,
             sd / f"table7_threshold_timing{file_suffix}.txt" if sd else None,
             threshold_timing, latex=args.latex)
run_and_save(table_threshold_accuracy,
             sd / f"table8_threshold_accuracy{file_suffix}.txt" if sd else None,
             threshold_accuracy, latex=args.latex)
```

**Acceptance criteria:**
- [ ] Tables 6-8 render correctly with `--quick` test data
- [ ] `--latex` flag generates LaTeX fragments for Tables 6-8
- [ ] Gracefully handles missing CSV files (prints "(no data)")
- [ ] Gracefully handles SKIPPED rows (displays "N/A" with note, does not crash)
- [ ] Column access uses `r.get(field, "0")` defaults for robustness against SKIPPED rows
- [ ] Saved as `table6_*.txt`, `table7_*.txt`, `table8_*.txt`

---

## Success Criteria

1. `run_benchmarks.sh --quick` completes successfully with all 8 benchmark types
2. CSV output files for dynamic and threshold benchmarks are well-formed, with exact column names matching the schemas above
3. `summarize_results.py` generates Tables 6-8 alongside existing Tables 1-5
4. Threshold benchmark gracefully handles OpenFHE parameter limits (no crashes; SKIPPED rows emitted)
5. Dynamic benchmark demonstrates minimal overhead vs basic protocol in the FHE phases
6. All new code follows existing patterns (Timer, CSVWriter, BenchmarkConfig, multi-trial median)
7. SKIPPED configurations produce parseable CSV rows with timing=-1 and a `note` field

---

## Risk Assessment

### R1: Threshold mult_depth exceeds OpenFHE limits (MEDIUM)

**Risk:** For k=128 with STD128, mult_depth=15 requires ring_dim ~65536 (64K), which is slow but feasible. At STD192/STD256, k=128 may push ring_dim to 131072 or exceed OpenFHE's maximum supported parameters.

**Mitigation:** Wrap `engine.Initialize()` in try/catch. Emit SKIPPED CSV rows (timing=-1, note=error message) for failed configurations. Default k range for STD192/STD256 stops at 64; k=128 is opt-in via `--max_k=128`. The benchmark script does not fail if some configurations are skipped.

**Impact if unmitigated:** Benchmark crashes at higher security levels, blocking paper-grade runs.

### R2: Threshold benchmark runtime (MEDIUM)

**Risk:** Polynomial evaluation with mult_depth=15 and ring_dim=65536 will be slow. A single threshold protocol run with k=128 at STD128 could take minutes, making multi-trial benchmarks impractical.

**Mitigation:** Use fewer trials for threshold timing (e.g., 3 instead of 10). The `--max_k` flag lets users control the upper bound. Quick mode restricts to k=16 only. Print estimated time warnings to stderr.

**Impact if unmitigated:** Paper-grade benchmark runs take hours instead of minutes.

### R3: Memory pressure from large ring dimensions (LOW)

**Risk:** Ring_dim >= 65536 with mult_depth=15 means large ciphertexts and key material. A single BFV context could consume several GB of RAM.

**Mitigation:** MemoryTracker already reports peak RSS. The benchmark creates one engine at a time and lets it go out of scope before the next configuration. Document memory requirements in system_info.txt.

---

## RALPLAN-DR Summary

### Principles

1. **Follow existing patterns**: New benchmarks must mirror the structure, CLI interface, and output format of `bench_piccard.cpp` and `bench_comparison.cpp` to maintain consistency.
2. **Graceful degradation**: The threshold benchmark must not crash when OpenFHE cannot support a configuration. Emit SKIPPED rows with timing=-1 and continue.
3. **Paper-ready output**: CSV and summary tables must be directly usable for paper figures and tables, with LaTeX export support.
4. **Minimal scope**: Only add benchmark code and script integration. No changes to the core library.
5. **Incremental builds**: Each step produces a compilable, testable artifact. Steps can be verified independently.

### Decision Drivers

1. **Paper deadline pressure**: Benchmarks are needed for paper tables/figures. Fastest path to usable data is the priority.
2. **OpenFHE parameter limits**: The threshold variant's high mult_depth (up to 15 for k=128) is the primary technical constraint. The design must accommodate potential failures via SKIPPED rows.
3. **Consistency with existing infrastructure**: Reusing `BenchmarkConfig`, `Timer`, `CSVWriter` patterns minimizes integration risk and keeps the codebase uniform.

### Viable Options

#### Option A: Two separate benchmark executables (RECOMMENDED)

**Description:** Create `bench_dynamic.cpp` and `bench_threshold.cpp` as independent executables, each with their own CSV schema and result structs. Follows the existing pattern where `bench_piccard` and `bench_comparison` are separate.

**Pros:**
- Consistent with existing project structure (2 executables -> 4 executables)
- Each benchmark can be run independently for debugging
- Threshold benchmark can fail without blocking dynamic benchmark
- Simpler error handling (try/catch scoped to one executable)
- Easier to add `--mode` flags specific to each variant

**Cons:**
- Some code duplication (ExactJaccard, MakeSetsWithOverlap, Median helper)
- Two new CMake targets to maintain
- run_benchmarks.sh grows from 4 to 8 benchmark runs

#### Option B: Extend bench_piccard.cpp with --variant flag

**Description:** Add `--variant=basic|dynamic|threshold` to `bench_piccard.cpp`. Reuse the existing timing/accuracy modes but swap the protocol variant internally.

**Pros:**
- No new files (smaller diff)
- Shared code (helpers, CSV writer) with no duplication
- Single executable covers all Piccard variants

**Cons:**
- `bench_piccard.cpp` becomes significantly more complex (435 lines -> ~800+ lines)
- Threshold's different CSV schema (extra columns: tau, mult_depth, poly_eval_ms, threshold_result, note) does not fit cleanly into existing `BenchmarkResult` struct
- Error handling for threshold failures (OpenFHE exceptions) pollutes the main flow
- Harder to run threshold in isolation for debugging
- Violates the existing pattern where different comparison dimensions get separate executables

### Recommendation

**Option A (two separate executables)** is recommended. The threshold variant has fundamentally different output schema (boolean result, mult_depth tracking, polynomial eval phase, SKIPPED row protocol) and different failure modes (OpenFHE parameter limits) that justify a separate executable. The small amount of helper duplication is acceptable and can be extracted to `benchmark_utils.h` if needed later. This approach is consistent with the existing project pattern where `bench_piccard` and `bench_comparison` are separate executables despite sharing some code.

### ADR: Architecture Decision Record

**Decision:** Implement two separate benchmark executables (`bench_dynamic`, `bench_threshold`) with dedicated CSV schemas, SKIPPED row protocol for threshold failures, per-security-level k range defaults, and quick-mode overrides.

**Drivers:** Paper deadline pressure requires fast path to usable data. OpenFHE parameter limits for high mult_depth configurations require graceful degradation. Existing codebase convention uses separate executables per benchmark dimension.

**Alternatives considered:** (A) Two separate executables [chosen], (B) Extend bench_piccard.cpp with --variant flag [rejected].

**Why chosen:** Option A maintains consistency with existing project patterns, provides clean error isolation (threshold failures cannot block dynamic benchmarks), and accommodates the fundamentally different CSV schemas between dynamic (plaintext operation throughput) and threshold (polynomial evaluation phases + boolean result + SKIPPED protocol).

**Consequences:** Two new source files to maintain. Some helper code duplication (ExactJaccard, MakeSetsWithOverlap, Median). run_benchmarks.sh grows from 4 to 8 runs. Quick mode will still complete in reasonable time due to parameter overrides.

**Follow-ups:** Consider extracting shared helpers to `benchmark_utils.h` if a third benchmark executable is ever needed. Monitor k=128 at STD128 runtime empirically to decide if it should remain in the default k range or become opt-in like STD192/STD256.
