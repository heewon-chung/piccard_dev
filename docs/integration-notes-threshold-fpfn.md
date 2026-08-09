# Integration notes — tkde-major/threshold-fpfn (record only, do not fix here)

1. **D1 — k=256 threshold at STD128 (decision point, not a bug).** Facts
   (re-verified at c0888e5): the checked-in noise_calibration.inc still has NO
   STD128 threshold natural-depth-21 cell (only 7/9/12/15) —
   bench_noise.cpp's grid comment (:950-954) claims k=256 was "calibrated
   anyway" (registration at :955 via add_large, :877), but only the sweep grid
   was extended; the table was never regenerated, so `Validate()` fails closed
   with "missing threshold legacy calibration". Independently,
   bench_threshold.cpp's `mult_depth > 21` STD128 guard (:392-394) is flagged
   by that same comment as "written against pre-flooding semantics", to be
   re-tuned by this branch. Probe data (probe_threshold_k256.csv) holds six `all_match`
   measurements — depth 21 at sms 40/45/50/54, plus depths 22 and 23 at
   sms 45 — all decrypting at N=32768. The implementation requires headroom
   >= coefficient-stat bits + flood_margin_bits + 2 = 74 bits (pre-rework
   formula, then params.cpp:122-127; the lambda_stat member is gone — the
   value now flows through LegacyFloodCoefficientBits(), and the exact
   current requirement lives in SelectFloodingParams — RE-VERIFY the 74-bit
   figure there before acting on Option B),
   and TWO probe points already clear it: depth 22 / sms 45 (80.34 bits)
   and depth 23 / sms 45 (123.02 bits) — depth 23 is extra headroom, not
   the first sufficient configuration, and neither point is "the"
   provisioned depth: which cell the frontier actually selects is exactly
   what the Option B sweep determines. A six-point probe is not a
   calibration frontier. Options:
   - **A (this plan's default): keep fail-closed.** SKIPPED rows everywhere;
     the paper reports FHE up to k=128 and plaintext fpfn up to k=512. No
     calibration regeneration, guard untouched.
   - **B: restore the k=256 FHE column.** Requires (i) sweeping the large
     threshold cell with bench_noise (the k=256 entry is behind the
     large-registration path — re-grep `add_large` in the current
     bench_noise.cpp; a plain `--sweep` excludes it), and
     (ii) regenerating the calibration table. The old
     one-shot command is GONE: `scripts/make_calibration_table.py` now
     requires `--manifest` / `--emit-rows` / `--out` (~:680), has no
     `--emit-cpp`, and no longer accepts legacy threshold sweep CSVs — so
     Option B additionally needs either a port of the legacy threshold-row
     generator to the manifest workflow or a new approved calibration
     workflow. Do not attempt it with the old command. This deliberately
     lifts this plan's "do not regenerate the calibration table" constraint
     for the threshold keys — needs integrator + paper-author sign-off;
     fine as a follow-up branch.
   - **C (rejected): re-tune the guard only** — pointless while `Validate()`
     still throws for the missing cell.
   Decision belongs to the integrator + paper author; all tasks above assume A.
2. **flooding × threshold worst-case provisioned parameters** (selected from
   calibration, NOT measured by an executed STD128 threshold evaluation):
   k=128 natural depth 15, provisioned depth 16, limb 45, log2 q 630,
   N = 32768, flood bits 603. `--mode=spec` performs KeyGen and a single
   encryption per k; it does not run a threshold evaluation and does not
   perform or measure flooding. The eval-noise value shown comes from the
   calibration table, and the flood bits are derived/provisioned from that
   same table, not observed at runtime. k=512 (depth 30) remains impossible
   at STD128 (p=65537 caps N at 32768).
3. **Paper text anchors** (external Draft/V4 snapshot, not in the repo — see
   the anchor-pinning note): piccard.tex:2203 "100% threshold accuracy" must be
   replaced by the T24 (true-J acc + BFV agree) and T27 (boundary FP/FN vs
   an idealized binomial overlay — exact only under ideal minwise hashing;
   the live SHA-256 rank-hashing family only approximates that, so the
   overlay is empirically consistent, not exact SHA-256 minwise theory)
   results; piccard.tex:1285-1302 u_tau paragraph gets the T28 numbers
   (degree, PS shape, depth, modulus, flooding).
4. `MakeRandomSetsWithOverlap`'s alpha is NOT Jaccard (J = alpha/(2-alpha));
   now documented implicitly by the fpfn J-grid code. Other benches using the
   11-point alpha grid for "coverage" inherit the same skew — flag to whoever
   next touches bench_piccard accuracy.
5. **Threshold CSV schema extension (record for schema owners).** The
   byte-pinned golden `ThresholdProfileCompat.HeaderBytesRemainLegacyCompatible`
   was extended in lockstep with `ThresholdCSVHeader()`
   (benchmarks/threshold_csv_schema.h): append-only tail = 9 truth/provenance
   columns (Task 3) + 8 flood columns (Task 5b); the legacy 46-column prefix is
   byte-identical and the transcript_stat_bits / sanitizer_assurance npos
   assertions still hold. Also record verbatim the k=256 fail-closed wording
   this branch's SKIPPED notes rely on: "missing threshold legacy calibration"
   (pinned by ThresholdProfileCompat.Std128MissingCalibrationFailsClosed).
6. **STD128 production runbook (deferred by user decision 2026-08-08).** The
   fpfn/accuracy production commands, pilot gate (SHA-256 MinHasher ⇒ hours,
   not minutes), fallback ladder, and T27/T24 acceptance criteria from Task 12
   Steps 1–2 — reproduced verbatim so the user can run them without the plan.

```bash
# fpfn pilot FIRST (mandatory): the op-count cost is derived (Task 6 cost
# model: 8.47e10 SHA-256 rank evals) and the HEAD probe scales it
# to HOURS (~9 h order of magnitude at 96.3 ms per k=128 n=1000 signature
# pair) — this pilot is what establishes the machine-specific number.
# Cost is linear in --trials, so the full run is ~40x the pilot's wall time.
# Set the budget accordingly BEFORE launching (overnight is realistic).
mkdir -p results/csv
time ./build/bench_threshold --mode=fpfn --security=STD128 --trials=50 --set_size=1000 --seed=1 > /dev/null 2>&1

# Fallback if 40x pilot exceeds the 1 h budget (record what was used):
#   1. --trials=1000 for the whole run. Semantics verified: config.trials is
#      the inner per-point loop, so every one of the 21 points at every swept
#      k still gets 1000 trials. Halves cost; still satisfies the R3-4
#      commitment of >= 10^3 trials/point; worst-case Wilson half-width grows
#      from +/-0.0219 to +/-0.0309. Do NOT go below 1000/point — that breaks
#      the R3-4 commitment; escalate instead. (fpfn sweeps all k in one
#      invocation — no per-k filter flag exists, and adding one would violate
#      the single-edit benchmark_utils.h constraint.)
#   There is deliberately NO rung 2. Reducing --set_size to 300 (x0.30 cost)
#   was considered and DROPPED: it is a cost reduction, so the burden of
#   proof is on demonstrating equivalence (set-size independence of the
#   estimator is exact only for ideal minwise hashing with independent
#   uniform bucket collisions; the SHA-256 rank-hashing family approximates
#   that computationally), and a statistically sound gate costs
#   more than the rung would save. Arithmetic: the arms are PAIRED (the
#   per-trial set/CRS seeds deliberately exclude set size —
#   TrialSeed/HashTrialSeed, benchmark_utils.h:639-655 — so both arms share
#   each trial's hash draw), hence the right design is a paired-difference
#   equivalence test (TOST / CI-in-margin). Planning ASSUMPTION, not a
#   bound: Var(d) <= 0.5, valid when the pairing does not anti-correlate
#   the arms; the unconditional paired-Bernoulli bound is 1, which would
#   double every n below and only strengthen this conclusion. Margin:
#   delta = 0.02 is a defensible conservative choice (T27 reads FP/FN at
#   0.01-0.05 resolution and Step 2 gates at |diff| <= 0.03-0.04; output
#   resolution alone does not prove a unique "largest defensible" margin).
#   Under those choices: fitting the paired 95% CI (half-width
#   1.96*sqrt(0.5/n) = 1.386/sqrt(n)) inside ±delta needs
#   n > (1.386/0.02)^2 ≈ 4,802 trials/point even at zero observed
#   difference; a standard 5%-per-side TOST at 90% power needs ≈ 13,528
#   (≈ 16,244 if the full 95% CI must sit inside the margin). Run on BOTH
#   arms over all 21x6 points, the gate costs ≈ 3.1x (CI-only) to
#   8.8-10.6x (powered) the FULL production run, to authorize at most a
#   0.35x saving (70% of the post-rung-1 half cost). A small pilot cannot
#   substitute: at 200 trials/point, non-rejection is compatible with a
#   true difference of ~0.098 — non-rejection is NOT equivalence.
#   Auditable revival conditions (none currently met): delta = 0.03 / 0.04
#   still give CI-only gate costs of 1.39x / 0.78x — both above the 0.35x
#   saving; an adaptive paired design breaks even only if the realized
#   discordance variance is exceptionally small (roughly Var(d) < 0.02 for
#   a 90%-powered TOST); testing only boundary points would shrink the
#   gate but narrows T27's claimed coverage. So if rung 1 still exceeds
#   the budget, ESCALATE to the integrator: raise the budget, run
#   overnight in the background, or move to a faster machine. Do not
#   reduce set_size.

# Unsuffixed filenames: results/csv here is threshold-only, with no
# piccard_timing_STD128.csv to trigger suffix detection (Global Constraints
# rule) — suffixed names would make Step 2's summarizer render nothing.
./build/bench_threshold --mode=fpfn --security=STD128 --trials=2000 --set_size=1000 --seed=20260727 \
    > results/csv/threshold_fpfn.csv 2> results/csv/threshold_fpfn.log
./build/bench_threshold --mode=spec --security=STD128 \
    > results/csv/threshold_spec.csv 2> results/csv/threshold_spec.log
./build/bench_threshold --mode=accuracy --security=STD128 --trials=50 --set_size=1000 --seed=20260727 \
    > results/csv/threshold_accuracy.csv 2> results/csv/threshold_accuracy.log
```

Acceptance checks against theory (immediate spec-only check runs now; T27/T24
are deferred to the production run above):

```bash
# Immediate (spec-only — Table 27 does not exist until the user's production
# fpfn run, so start the range at Table 28):
python3 scripts/summarize_results.py results/csv 2>/dev/null | sed -n '/Table 28/,$p'
# Post-production (runbook — include verbatim in the integration notes):
#   python3 scripts/summarize_results.py results/csv 2>/dev/null | sed -n '/Table 27/,$p'
```

Acceptance criteria (from the Global-Constraints reference table):
- k=128 summary row: `J_tau ≈ 0.5873`, `sigma_J ≈ 0.0441`; FP and FN rates strictly between 0 and 0.5 with CIs excluding 0.
- Every decision-curve `|diff|` ≤ ~0.03 at n=2000 (≈ Wilson half-width 0.022 + slack; if the Step 1 fallback ladder reduced the run to 1000 trials/point, loosen to ~0.04 and say so in the report). On larger systematic deviations: check CRS resampling and the α↔J mapping first — the known implementation failure modes — but remember the overlay is **idealized** (the SHA-256 rank-hashing family approximates minwise independence computationally, so large offsets are more suspicious than they would be under a weaker family), so a consistent small offset that survives both checks can still be a real property of the hash family; report it as a finding rather than chasing a phantom bug.
- T24 at k=128: `True-J Acc` ≈ 0.983 (theory: 1 − (0.158 + 0.026)/11), `BFV Agree` = 1.000 exactly.
- T28: k=128 row shows degree 128, s=12, chunks=11, depth(nat)=15.
