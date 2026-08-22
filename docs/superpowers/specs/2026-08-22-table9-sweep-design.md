# Table 9 full-grid sweep — design

Date: 2026-08-22
Status: approved in conversation (Heewon Chung), pending gpt-5.6-sol plan review
Target: TKDE major revision R1, `tbl:comp` (prints as TABLE IX) in `Paper/Revision/Piccard_MR_R1.tex`

## 1. Problem

`tbl:comp` has 16 rows x 5 protocol columns = 80 cells. The 2026-08-20 AWS
`paper-v1` run measured only ~50 of them; the other ~30 are filled by reusing
the default-setting measurement and marking the cell `‡` ("independent of this
axis by construction"). Concretely:

| column | measured axes | reused (`‡`) axes |
|---|---|---|
| Piccard (`piccard_std128`) | u, n, k, m | none |
| Piccard+ (`sqrt_comparison::timing_*`) | n, k, m | u (4 rows) |
| BCG12 (`bcg12_minhash`) | n, k | u (4), m (4) |
| SJ16 (`sj16`) | u=2^14, 2^16 measured; 2^18, 2^20 extrapolated; n | k (5), m (4) |
| FHE-IND (`fhe_ind`) | u, n | k (5), m (4) |

The author wants every cell measured so that the claimed flatness is shown by
data rather than asserted by footnote.

## 2. Decisions (interview, 2026-08-22)

| decision | choice |
|---|---|
| implementation | standalone sweep script outside the revision matrix; no matrix / C++ adapter / verifier / seal changes |
| repetitions | **30 per cell** (matches the existing `paper-v1` raw-timing contract, so no C++ change is needed) |
| SJ16 |U|=2^18 and 2^20 | **measured**, not extrapolated |
| n=100,000 row | excluded (table keeps n = 100 / 1,000 / 10,000) |
| SJ16 threads | **16**, same as every other protocol (previous run used 2) |
| BCG12 variants | measure both EC (P-256) and FF-3072/256 in one process; table shows EC |
| existing 30-trial data | not reused; all 78 executable cells re-measured on one instance |
| instance | same AMI / `c8i.8xlarge` (CoreCount=16, SMT off) as the 2026-08-20 run, `--threads=16`, `--seed=20260729` |

Scope is a paper PoC: correctness of the numbers and timing comparability.
Edge cases, resumable crash recovery beyond "skip finished cells", and
matrix-grade sealing are out of scope.

## 3. Measurement grid

Rows (identical to the current table):

```
block U : (u, n, k, m) = (2^14,1000,128,64) (2^16,1000,128,64) (2^18,1000,128,64) (2^20,1000,128,64)
block n : (2^16,100,128,64) (2^16,1000,128,64) (2^16,10000,128,64)
block k : (2^16,1000,16,64) (2^16,1000,64,64) (2^16,1000,128,64) (2^16,1000,256,64) (2^16,1000,512,64)
block m : (2^16,1000,128,16) (2^16,1000,128,64) (2^16,1000,128,128) (2^16,1000,128,256)
```

The default point (2^16,1000,128,64) appears in all four blocks. It is
measured **once** and the same number is printed four times; the table footnote
says so. That gives 13 distinct parameter points.

Methods per point and the producer / raw phase that defines "end-to-end time
per query" — identical to what the `paper-v1` orchestrator used:

| method | producer | raw phase | notes |
|---|---|---|---|
| piccard | `bench_piccard --mode=combined` | `total` | accuracy trials not needed; pass the smallest value the producer accepts |
| piccard_plus | `bench_onehot_sqrt --mode=timing` | `total` of the `sqrt` sidecar | m must be a perfect square: m=32, 128 are `---`, not run |
| bcg12_ec, bcg12_ff | `bench_review_comparison` legacy CLI, `--suite=primary-review --methods=bcg12_mh_ec,bcg12_mh_ff` | `total` per method sidecar | one process yields both; the `--revision-cell` path cannot take non-matrix cells (golden ID set compiled into `revision_matrix.cpp`) |
| sj16 | `bench_review_comparison` legacy CLI, `--methods=sj16 --sj16-key-bits=3072`, `OMP_NUM_THREADS=16` | `total` | |
| fhe_ind | `bench_fhe_ind --mode=e2e --revision-cell=<existing matrix cell>` | `online_e2e` | takes only (u, n); k and m are not inputs |

Executable processes: 13 piccard + 11 piccard_plus (m=32, 128 skipped) +
13 bcg12 + 13 sj16 + 6 fhe_ind = **56 processes**, expanding to 78 table
cells (80 minus the two `---`). FHE-IND runs only its 6 distinct (|U|, n)
inputs, through the existing matrix cells `fhe_ind::u=16384,65536,262144,
1048576` and `fhe_ind::n=100,10000`, because its non-matrix CLI path is
frozen to one Work-5 workload and it takes no k or m; the k and m rows print
the u=65536 measurement.

Note on semantics: for fhe_ind (k, m), sj16 (k, m) and bcg12 (m) the varied
parameter is not an input to the protocol. Those cells are therefore
independent repeated runs of one configuration; what the table then shows is
run-to-run stability, not a parameter dependence. This is accepted and will be
stated in the footnote.

Statistics: each producer's raw-timing sidecar already emits per-trial samples
plus `aggregate` rows with `mean_ms`, `sample_sd_ms`, `median_ms` and a
Student-t 95% CI (`StudentT95(30) * sd / sqrt(30)`). The table prints
`mean ± CI half-width` in ms, exactly as today.

## 4. Components

### 4.1 `scripts/run_table9_sweep.py`

- Grid and method list are literal Python constants (no matrix lookup).
- Builds each process's argv by copying the conventions recorded in
  `results/piccard-results-20260820/planned_argv.jsonl`, **minus
  `--revision-cell=`** (and, for fhe_ind, minus `--revision-identity-out`),
  with `--trials=30`, `--seed=20260729`, `--security=STD128`, and a
  `paper-*` profile id so the sidecar writer selects the 30-trial contract.
- `--mode=dry-run` prints the planned argv as JSONL and exits 0 without
  spawning anything. `--mode=run` executes sequentially, one process at a
  time, in this order: piccard, piccard_plus, bcg12, fhe_ind for all points,
  then sj16 ascending by u (2^20 last).
- Output layout: `<results-root>/cells/<point_id>__<method>/` containing
  `stdout.log`, `stderr.log`, `argv.json`, `raw/` (sidecars), plus the
  producer's `--output` CSV where one exists. `<results-root>/run.json`
  records: git commit, `git status --porcelain` (the AWS run must be clean),
  sha256 + size of every binary used, platform string, `nproc`, `lscpu`
  summary, threads, seed, start/end timestamps, and per-cell exit codes and
  durations. `<results-root>/events.jsonl` appends one line per cell start /
  end.
- Resume: a cell directory containing `done.json` is skipped on a rerun.
- A `--security=TOY` and `--trials-override=1` pair exists **only** for the
  local smoke run; `run.json` marks such runs `smoke: true` and the
  summarizer refuses them unless `--allow-smoke` is passed.

### 4.2 `scripts/summarize_table9_sweep.py`

- Reads every `raw/*.tsv`, keeps `aggregate` rows for the phase listed in §3,
  and writes:
  - `table9.csv`: `point_id,u,n,k,m,method,measured_count,mean_ms,sd_ms,median_ms,ci95_half_ms`
  - `table9_rows.tex`: the 16 table body rows in the exact `tbl:comp` cell
    syntax (`$143.5\pm2.4$`, one decimal, `{,}` thousands separators, `---`
    for the two non-square Piccard+ cells, EC for the BCG12 column, FF kept
    in the CSV only).
  - `flatness.md`: per method and per axis, max/min of the means across the
    block, so the "flat" claim can be quoted with a number.
- Fails (exit 1) on any missing cell, any `measured_count != 30`, or any
  cell whose sidecar `expected_measured` disagrees with its sample count.

### 4.3 Tests (PoC level)

- `tests/scripts/test_run_table9_sweep.py`: dry-run emits exactly 56
  processes; every argv lacks `--revision-cell`; every argv has
  `--trials=30`; sj16 argv has `--threads=16`; piccard_plus is absent for
  m=32 and m=128.
- `tests/scripts/test_summarize_table9_sweep.py`: on a fixture built from
  two real 2026-08-20 sidecars, the CSV and LaTeX rows match golden strings;
  a fixture with 29 samples makes the script exit 1.
- Both are registered in CMake alongside the existing Python contract tests
  so `ctest` runs them.

## 5. Feasibility gate (must pass before AWS)

Each producer's legacy (non-`--revision-cell`) path has to accept the raw
sidecar flag and the cell/mode arguments we pass. This is **not yet verified**
for `bench_review_comparison`, `bench_onehot_sqrt --cell=timing_u`-style
axes, and `bench_fhe_ind --cell-id` validation. The plan therefore starts
with a local smoke run (`--security=TOY`, 1 trial) of one point per method on
the Mac build. If a producer rejects the legacy path, the permitted fix is
the smallest gate relaxation in that producer that leaves the
`--revision-cell` path untouched, re-verified by `ctest`. Anything larger is
reported back instead of implemented.

## 6. AWS execution

Same runbook as `aws-guide.md` Phase B, but the command is the sweep script
and the results root is `~/piccard-table9-<date>`. Expected wall time is
dominated by SJ16 at 16 threads; a conservative estimate from the 2-thread
numbers (2^20 ≈ 19 min/query, 2^18 ≈ 4.8 min, 2^16 ≈ 71 s) with only 4x
thread scaling is ≈ 2.5 h for SJ16 (2^20 alone ≈ 2.4 h at 30 trials if
scaling is 2x), under 1 h for everything else: **3–6 h, ≈ $5–10**. Results are
pulled back to `results/piccard-table9-<date>/` and committed.

## 7. Paper update

- Replace all 80 numbers in `tbl:comp`; drop every `‡`, `§`, `‡‡` marker in
  this table and the commented-out legacy footnotes; new footnote: "Time:
  mean ± 95% CI over 30 runs, ms; every cell measured on the same machine;
  the default setting (|U|=2^16, n=1000, k=128, m=64) is measured once and
  repeated in each block."
- Update body text that quotes these numbers: §IV-A repetition sentence,
  BCG12 103.5 ms / 211.7 ms, SJ16 17.6 s / 71.4 s, the 2^18 / 2^20 SJ16
  extrapolation remarks, and the SJ16 thread-footing remark.
- All edits tracked with `\heewon{}` / `\heewondel{}`; recompile and inspect
  the rendered page.

## 8. Pipeline and model assignment

1. Plan (Fable) → 2. plan review by gpt-5.6-sol (high) via `codex exec` →
3. implementation: sweep + summarizer + tests (sonnet), feasibility gate and
any producer gate relaxation (opus) → 4. implementation review (Fable +
gpt-5.6-sol high) → 5. AWS run (opus, push and run pre-authorized 2026-08-22) → 6. paper numbers (sonnet).

## 9. v2 amendment (2026-08-22, after gpt-5.6-sol plan review)

The review of plan v1 established, with source evidence, that §4–§5 above are
not implementable: `bench_review_comparison`'s non-matrix CLI is frozen to
seven-method suites with 50 accuracy trials (`comparison_workload.cpp:122,
302, 355`), `bench_piccard`/`bench_onehot_sqrt` without `--revision-cell` run
their built-in grids with different universe semantics
(`bench_piccard.cpp:1225-1260`, `bench_onehot_sqrt.cpp:713`), and the
`--revision-cell` path is bound to the golden cell-ID set compiled into
`revision_matrix.cpp:440-530`. The author therefore chose **matrix
extension** (decision 2026-08-22):

- `benchmarks/revision_matrix.json` gains 24 cells: `bcg12_minhash` u×4,
  m×5; `sj16` k×6, m×5; `sqrt_comparison` timing_u×4; and `sj16::u=262144`,
  `u=1048576` become measured RUN cells. All non-`fit` sj16 cells move to 16
  threads. 275 → 299 cells, 0 NO_SPAWN. Validators (`revision_matrix.cpp`,
  `revision_invocation_plan.cpp`, `validate_revision_matrix.py`,
  `verify_revision_benchmarks.py`, fixtures, tests) are extended to admit
  exactly these cells and nothing else.
- The sweep runner (`scripts/run_table9_sweep.py`) reuses the orchestrator's
  `canonical_plan_argv`/`materialize_cell_argv`/`command_for_cell` on a
  hard-coded list of 57 cell ids, so every argv is the one `--mode=paper`
  would produce. Resume re-runs only non-COMPLETED cells and refuses when
  provenance (source, tools, binaries, matrix, seed, threads, scripts)
  differs.
- Counts corrected: the m block is 16/64/128/256, so the only `---` is
  Piccard+ at m=128; processes are 13+12+13+13+6 = **57**, printed measured
  cells 79. FHE-IND has no k or m input and its non-matrix path is frozen,
  so its k/m rows print the `fhe_ind::u=65536` measurement (footnoted).
- The summarizer binds every number to a sidecar whose `cell_id` header
  equals the expected matrix cell id, and refuses runs that are not
  COMPLETED / clean / 16 threads / seed 20260729 unless overridden.
- §4.1–4.3 and §5 above are superseded by
  `docs/superpowers/plans/2026-08-22-table9-sweep.md` (v2).
