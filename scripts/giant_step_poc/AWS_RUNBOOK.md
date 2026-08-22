# D-10 giant-step comparison — AWS runbook

Sequential run on one instance. Produces the tree-vs-Horner numbers for the
threshold variant (review item D-10) that go into the manuscript.

**Branch:** `d10-giant-step` (forked from `main` at `a1ee975`).
**Instance:** `c8i.8xlarge`, 16 physical cores, SMT off — same profile as the
Phase-B run in `aws-guide.md`, so the numbers are comparable with the existing
threshold table.
**Environment:** `OMP_NUM_THREADS=16 OMP_DYNAMIC=FALSE`, `--seed=20260729`,
`--m=64 --set_size=1000 --security=STD128`.

Nothing here writes to the revision matrix or the frozen calibration table, and
nothing here needs the seal workflow. It is a standalone measurement.

---

## Why timing must run alone

The probe steps measure *noise*, which is a property of the crypto parameters
and the RNG seed, not of the machine — they can share the box and even run in
parallel. The timing step measures wall clock and must have the instance to
itself: no builds, no other benchmarks, no second session. Everything below is
ordered so that the timing step is the only thing running when it runs.

---

## Step 0 — bring the box up

```sh
git clone <remote> piccard && cd piccard
git checkout d10-giant-step
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
      -DOpenFHE_DIR=/usr/local/lib/OpenFHE -DPICCARD_ENABLE_GMP=ON
cmake --build build -j
ctest --test-dir build --output-on-failure    # must be 100%
git rev-parse HEAD > results/giant-step-poc/commit.txt
```

If `ctest` is not 100%, stop. Do not measure against a red suite.

---

## Step 1 — probe the tree circuit (OPTIONAL on the timing box, ~30–60 min)

The tree cannot read the frozen calibration table by design: its natural depths
either have no row, or collide with a row that was measured on the Horner
circuit. So every tree configuration needs a measured `--ps_override`, and this
step is where those come from.

**Skip the full grid when the goal is timing.** The five overrides below were
already probed locally and are committed as
`results/giant-step-poc/overrides.txt`. Instead of the 52-cell grid, run the
targeted check, which re-measures only those five cells on this box
(~2 min at 16 threads) and fails if any measured noise exceeds the value the
override was selected with:

```sh
OMP_NUM_THREADS=16 sh scripts/giant_step_poc/verify_overrides.sh
```

This is the only real cross-machine noise check. Do **not** rely on the
Step 3 `spec` pass for it: under an override, `spec` reports the override's
own `eval_noise_bits` back (the selector copies it from the chosen candidate),
so `summarize.py`'s capacity inequality is satisfied by construction and
cannot detect a box whose noise differs. Run the full Steps 1–2 only for a k
that `verify_overrides.sh` reports as MISMATCH.

```
--ps_override=16:8:40:225:16384:304
--ps_override=32:9:40:255:16384:344
--ps_override=64:10:40:285:16384:384
--ps_override=128:10:54:341:16384:416
--ps_override=256:12:40:370:32768:464
```

```sh
export OMP_DYNAMIC=FALSE
# two jobs in parallel; noise is not timing-sensitive
KS="16 32 64 128" DELTAS="1 2 3" SMSS="40 45 50 54" OMP_NUM_THREADS=8 \
  sh scripts/giant_step_poc/probe_tree_noise.sh &
KS="256"          DELTAS="1 2 3" SMSS="40 45 50 54" OMP_NUM_THREADS=8 \
  sh scripts/giant_step_poc/probe_tree_noise.sh &
wait
```

Cells are written atomically: a cell that dies leaves no CSV and is re-run on
the next invocation, so the script is safe to repeat.

---

## Step 2 — select the overrides

```sh
KS="16 32 64 128 256" python3 scripts/giant_step_poc/select_override.py
```

Prints one `--ps_override=` line per k to stdout and to
`results/giant-step-poc/overrides.txt`, plus a per-cell feasibility table on
stderr — keep that table, it documents why each cell was chosen.

Feasibility is the same inequality the selector uses in production:
`ceil(max eval_noise_bits) + 64 + 8 + 2 <= floor(log_delta)`, and a cell counts
only if all three patterns (`all_match`, `no_match`, `random`) decrypted with
`saturated=0`.

**Exit 2 means some k has no feasible cell.** Widen the grid for that k alone
and repeat Steps 1–2, e.g.

```sh
KS="256" DELTAS="2 3 4" SMSS="40 45 50 54 58 60" OMP_NUM_THREADS=16 \
  sh scripts/giant_step_poc/probe_tree_noise.sh
```

Local reference points already measured on a Mac (OpenFHE 1.5.0, same seed) —
use them as a sanity check, not as a substitute:

| k | override found locally | check |
|---|---|---|
| 16 | `16:8:40:226:16384:304` | 226+64+8+2 = 300 ≤ 304 |
| 128 | `128:10:54:341:16384:416` | 341+64+8+2 = 415 ≤ 416 |

If AWS produces materially different noise for the same (k, depth, sms), stop
and report it — that would mean the measurement is not reproducible across
builds, which matters more than the timing.

---

## Step 3 — timing, exclusive (~1–2 h)

**Nothing else may run on the instance during this step.** Confirm with `top`
that the box is idle first.

```sh
sh scripts/giant_step_poc/run_compare.sh
```

It runs four passes in order — Horner spec, tree spec, Horner timing, tree
timing — with `--timing_scenario=vary_k` so only the varying-k sweep executes.
The m and set-size sweeps are deliberately excluded: the overrides are bound to
`m=64`, and `BenchVaryM` would otherwise apply an m=64 noise row to a geometry
it was never measured for. `bench_threshold` refuses that anyway, but the flag
keeps the run from wasting an hour producing SKIPPED rows.

Horner needs no override; it resolves from the frozen table exactly as the
existing manuscript numbers did.

---

## Step 4 — summarise and gate

```sh
python3 scripts/giant_step_poc/summarize.py
```

Writes `results/giant-step-poc/summary.md` and **exits non-zero if anything is
wrong**: a missing spec or timing row, a spec row whose status is not `ok`,
`fhe_agrees != 1`, a `residual_capacity_status` other than
`not-exposed-by-openfhe`, or `log2_q_over_t_bits < required_capacity_bits`.

Exit 0 is the acceptance gate. Also confirm by eye:

- tree natural depths are **6, 7, 8, 9, 10** for k = 16, 32, 64, 128, 256
- Horner natural depths are **7, 9, 12, 15, 21** — unchanged from the manuscript
- `threshold_correct` and `fhe_agrees` are `1` on every row (both are
  conjunctions over all 30 trials, not the last trial)

Read the natural depth from the `natural_mult_depth` column, never from the
override's provisioned `mult_depth` — an override may over-provision without
limit, and the two are separate columns for exactly this reason.

---

## Step 5 — recover

```sh
tar czf giant-step-poc.tgz results/giant-step-poc
# scp back to the Mac
```

Bring back `summary.md`, both timing CSVs, both spec CSVs, `overrides.txt`,
`commit.txt`, and the probe directory. The probe CSVs are the evidence for the
parameter choices and belong with the rest.

---

## What the local run already established

Measured on a Mac Studio M1 (OMP_NUM_THREADS=4, interleaved H/T rounds,
medians of 10 trials per round, 3 rounds):

| k | Horner N | Tree N | Tree / Horner speed-up (3 rounds) |
|---|---|---|---|
| 16 | 16384 | 16384 | 1.11 · 1.19 · 1.21 |
| 32 | 16384 | 16384 | **0.69 · 0.73 · 0.75** (tree slower) |
| 64 | 32768 | 16384 | 2.54 · 2.75 · 2.74 |
| 128 | 32768 | 16384 | 3.61 · 3.75 · 3.83 |
| 256 | 32768 | 32768 | 1.60 · 1.81 · 1.69 |

The advantage is not monotone in k. It is dominated by whether the tree's
shallower chain lets OpenFHE pick a smaller ring (k=64, 128). Where the ring
does not change and the chain is short (k=32), the tree's extra
`ceil(log2 l) - 1` squarings cost more than the levels it saves, and it is
genuinely slower. **A sub-1.0 ratio at k=32 on AWS is expected; do not
re-investigate it.**

Mean and median diverge on a loaded machine (Horner k=128: 2674 ms median vs
10007 ms mean in a block run), so both are kept in the CSV. The manuscript's
existing tables report mean ± 95% CI over 30 trials; on an idle box the two
should agree, and a large gap is a sign the box was not idle.

---

## Known non-issues, so they are not re-investigated on the box

- **`bench_noise` prints `*** NO FEASIBLE CELL ***`.** That is the harness
  reporting that the *default* λ_s target does not fit at that cell, and it
  still writes its rows. `select_override.py` does its own feasibility test on
  the CSV. Not an error.
- **`--depth_delta=0` fails to decrypt for tree k=128.** Expected: OpenFHE hands
  the same 6-limb 360-bit modulus to depths 8 and 9, so the budget does not grow
  where the noise does. This is a noise-budget miss, not a level shortage — the
  depth formula is correct at every k benchmarked here.
- **A `natural_mult_depth` of 15 at Horner k=128.** Correct. The circuit was
  measured decrypting at provisioned depth 15 with ~34 bits of headroom; the 16
  the context deploys comes from the flooding requirement, not from depth.
