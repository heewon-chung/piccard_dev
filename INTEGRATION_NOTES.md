# Integration Notes — `tkde-major/hash-seed-crs`

Findings classified DEFER or OUT-OF-SCOPE under §0.3. **No code in this branch
was changed for any item here.**

## PHASE 4 RESULTS — fixed vs resampled CRS, STD128

Run 2026-07-25 on `a1e325c`. Both arms: `bench_piccard --mode=accuracy
--security=STD128 --k=128 --m=64 --set_size=1000 --trials=50 --seed=20260725`,
differing only in `--hash_randomness`. 8,250 paired rows per arm, 265 s per arm.

Pairing validated before any statistic was computed: `hash_root_seed` identical
across both arms; `jaccard_expected` identical on all 8,250 paired rows (same
sets); fixed arm used 1 distinct CRS, resampled arm 550.

**Per-cell: no detectable difference anywhere.** All 15 `(k, m, n)` groups have a
95% t-CI on the paired difference that contains 0 (n=550 each).

**Pooled: a small but detectable difference.** n=8,250, mean paired difference
in |error| (fixed − resampled) = **−0.001278**, sample SD 0.037575, 95% CI
**[−0.002089, −0.000467]** — excludes 0. Sign is negative, i.e. the fixed-CRS
arm reports *slightly smaller* error, so a fixed hash family mildly understates
the error the resampled probability space actually produces.

Report it as detectable-but-negligible, not as equivalence (§3 forbids claiming
equivalence from non-significance, and symmetrically we should not inflate a
0.0013 effect). For scale, mean |error| at k=128 is 0.0250, so the bias is ~5% of
the reported error and ~1.5% of the k=128 theoretical 1/√k = 0.0884. It is only
resolvable because n=8,250 confers high power; every individual cell is null.

Main-text mean |error|, resampled arm (the arm the paper should use):

| k | 16 | 32 | 64 | 128 | 256 | 512 |
|---|---|---|---|---|---|---|
| mean abs err | 0.0715 | 0.0512 | 0.0348 | 0.0250 | 0.0185 | 0.0126 |

Successive ratios are 0.72, 0.68, 0.72, 0.74, 0.68 against the 1/√2 ≈ 0.707
predicted by 1/√k — the expected convergence, which is an independent sanity
check that the new CRS expansion did not damage estimator quality.

This reproduces, with proper pairing inside the repository, the earlier
out-of-repo finding recorded in §3 of the branch plan.

Accuracy is independent of noise flooding, so these numbers are final for this
branch. **Timing and communication numbers are NOT**: re-measure after
`noise-flooding` merges (§"머지 순서").

## SATISFIED — the Phase 4 seed requirement (kept for the next branch)

**Phase 4 must pass an explicit, identical `--seed=N` to every binary and both
arms.** `run_benchmarks.sh` passes `--seed` to nothing and `ParseArgs` fills an
unspecified seed from `std::random_device` *per process*, so as shipped each
binary gets a different root and reruns differ again.

`HashTrialSeed(root, trial, overlap)` is pure, so pairing across sweeps, across
Piccard/Dynamic/one-hot/sqrt, and across `fixed`/`resampled` is structurally
guaranteed **only when the root is shared**. The capability is right; the default
invocation does not realise it.

If ignored: Phase 4 step 5's paired 95% t-CI would compare arms drawn from
*different set samples*, so the CI absorbs set variance instead of isolating the
hash effect — a wrong number in the response letter, with well-formed CSVs and
nothing in the output to reveal it. Confirm `hash_root_seed` is identical across
every CSV before computing anything paired.

Threading `--seed` into `run_benchmarks.sh` is OUT-OF-SCOPE here (§0.4-10).

## DEFER

**`rel_error_eligible_n` unset on `bench_piccard` accuracy rows** — the three
`BenchAccuracy*` functions leave it `0`; the `bench_dynamic` equivalents set
`(j_true > 0.0) ? 1 : 0`. Harmless: `summarize_results.py` derives its
relative-error column from `jaccard_rel_error >= 0` (:297-300), not this field,
so no reported number moves. Fix alongside the next change to those rows.

**`scripts/summarize_results.py` diff budget (Task 6)** — the plan's Task 6
gives the four edit steps verbatim; applying them exactly as written produces
a 42-line diff (28 insertions + 14 deletions) against the phase's own ≤40-line
cap for this file. The comment added ahead of the mode-detection code in Step
1 was shortened from three lines to one to bring the diff to exactly 40 lines
(26 insertions + 14 deletions); no logic changed, and Task 6 Step 4's
verification (`SINGLE-MODE OUTPUT IDENTICAL`, `MIXED-MODE SPLIT PRESENT`,
8-column `tabular` line) was re-run after the trim and still passes. Recorded
here because the plan's own worked example does not fit its own budget as
written, which a future phase editing this function should know before
reusing the snippet.

## OUT-OF-SCOPE

**`bench_threshold.cpp` per-trial reseeding** — owned by `threshold-fpfn`. The
API exists: `Piccard::SetHashSeed(uint64_t)`, forwarded through
`ThresholdPiccard`. Use `benchmark::HashTrialSeed(config.seed, trial, overlap)`
— the same `(root, trial, overlap)` signature as the other benchmarks, which is
what keeps threshold rows paired with Piccard/Dynamic rows for the same trial.
Append the same four provenance columns; note it defines its own CSV writer, so
they must be added there separately.

**`summarize_results.py` threshold tables** — owned by `threshold-fpfn`. If that
branch adds `hash_randomness` to threshold rows, mirror the mixed-mode split in
`table_accuracy_stats` rather than pooling modes.

**Accuracy `Std Dev` is population SD, timing SD is sample SD** —
`table_accuracy_stats` divides by `n` (:293); R3-5 timing columns use `n-1`.
Left alone per §0.4-9 / §4 because changing it moves already-reported numbers.
A definitions note for the paper and response letter, not a code defect: do not
conflate the two in either document.

**`MulModMersenne` overflow is unreachable at current universe sizes** —
fixed in commit `fc7d2b1`, recorded because the reachability matters later:
accuracy sets come from `[0, 10^7)` and `bench_comparison.cpp`'s
`universe_size` is `uint32_t` (default 65536), so nothing today reaches
`elem >= 2^61`. Raising the universe past `2^61` without that fix corrupts
~0.27% of hash values.

## BCG12 branch — cross-branch touches

`bench_comparison.cpp` `BenchVaryUniverse`: changed Piccard & SqrtPiccard
`jaccard_computed` from last-trial to mean-of-trials for consistency with
the BCG12 rows (finding from the BCG12 final review). Affects reported
estimate at trials>1 only; trials=1 unchanged.
