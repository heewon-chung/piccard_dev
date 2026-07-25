# Integration Notes — `tkde-major/hash-seed-crs`

Findings classified DEFER or OUT-OF-SCOPE under §0.3. **No code in this branch
was changed for any item here.**

## REQUIRED BEFORE PHASE 4 — read this first

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
