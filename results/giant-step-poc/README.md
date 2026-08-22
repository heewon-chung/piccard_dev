# D-10 giant-step comparison — measured artefacts

Horner versus balanced-tree giant step in the Paterson--Stockmeyer evaluation
of the threshold polynomial (review item D-10). Feeds Table XI
(`tbl:threshold_timing`) and the threshold block of Table II
(`tbl:bfvparams`).

**Run:** AWS `c8i.8xlarge`, 16 physical cores (SMT off), Ubuntu 24.04,
GCC 13.3.0 `-O3`, OpenFHE 1.5.0, `OMP_NUM_THREADS=16`, `OMP_DYNAMIC=FALSE`,
seed 20260729, `m=64`, `n=1000`, STD128, 30 measured trials per timing cell.
Commit in `commit.txt`; `verify/provenance.txt` stamps the host that produced
the noise measurements.

| file | what it is |
|---|---|
| `summary.md` | joined spec+timing table, both arms; the acceptance gate's output |
| `{horner,tree}_spec.csv` | circuit shape, depths, ring, modulus chain, noise |
| `{horner,tree}_timing.csv` | per-phase timings, 30 trials, mean/sd/median |
| `overrides.txt` | the five measured `--ps_override` rows the tree arm needs |
| `verify/` | per-k re-measurement that gated those five rows on this box |
| `probe/` | the (depth_delta, scaling_mod_size) grid the rows were chosen from |

## Why the tree needs overrides at all

The frozen calibration table was measured on the Horner circuit. The tree's
natural depths either have no row or collide with a Horner-measured one, so
the selector refuses to serve it a row and every tree cell carries a measured
override instead. `verify_overrides.sh` re-measures exactly those cells and
gates them on the selector's own inequality,
`eval_noise + 64 + 8 + 2 <= log2(q/t)`, read from the run it just produced.

## Two facts worth keeping

Evaluation noise drifts by up to ±2 bits between runs of the same cell, so a
cell with 0--1 bits of slack is not a usable parameter. The original k=128
cell (depth 10, `sms` 54) sat at exactly 0 and failed here; depth 11 /
`sms` 48 holds N=16384 with 5--6 bits of slack, reproduced three times.

The tree's advantage is not monotone in k. It is dominated by whether the
shallower chain lets OpenFHE pick a smaller ring: 2.75x at k=64 and 3.17x at
k=128, where it does, but **0.79x at k=32**, where the ring is unchanged and
the extra `ceil(log2 l) - 1` squarings cost more than the levels saved.
