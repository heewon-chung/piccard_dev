# Giant-step tree vs. Horner comparison (D-10)

Purpose: produce the AWS-run evidence for review item D-10 -- a fair,
same-machine comparison of the tree-structured Paterson-Stockmeyer giant
step (`--giant_step=tree`) against the Horner baseline (`--giant_step=horner`)
for the threshold circuit, at `m=64`, `set_size=1000`, `STD128`, across the
varying-`k` sweep.

## Commands, in order

1. **Probe** the tree circuit's evaluation noise over a `(depth_delta, sms)`
   grid, one CSV per cell, written atomically:

   ```sh
   OMP_NUM_THREADS=16 sh scripts/giant_step_poc/probe_tree_noise.sh
   ```

2. **Select** the cheapest feasible `(depth, sms)` override per `k`, writing
   `results/giant-step-poc/overrides.txt`:

   ```sh
   python3 scripts/giant_step_poc/select_override.py
   ```

   Exits 2 and prints `NO FEASIBLE PROBE for k in [...]` if any `k` in
   `EXPECTED_KS` has no feasible cell; widen `DELTAS`/`SMSS` for those `k`
   and re-run step 1.

3. **Compare**: run Horner (no override) and Tree (with the selected
   overrides) back to back, spec then timing, on the same build/machine:

   ```sh
   OMP_NUM_THREADS=16 sh scripts/giant_step_poc/run_compare.sh
   ```

4. **Summarise**: join the four CSVs per `k` into a report, failing loudly
   on any gap or acceptance-criteria violation:

   ```sh
   python3 scripts/giant_step_poc/summarize.py
   ```

## Expected runtime (`c8i.8xlarge`, `OMP_NUM_THREADS=16`)

- Step 1 (probe): default grid is `k in {16,32,64,128,256}` x `depth_delta
  in {1,2,3}` x `sms in {40,45,50,54}` = 60 cells; each cell runs a
  delta-0 baseline plus the probed point (`--reps=5`, 3 patterns). Budget
  roughly 1-3 minutes per cell depending on `k`, so ~1-3 hours for the full
  grid. Interrupted/rerun cells are skipped (`if [ -s "$f" ]`), so the probe
  is safe to resume.
- Step 2 (select): seconds.
- Step 3 (compare): spec mode is < 1 minute per giant-step mode (2 runs).
  Timing mode is `--trials=30` over `k in {16..256}`, roughly 7-8 minutes
  per giant-step mode (2 runs), so ~15-16 minutes total.
- Step 4 (summarise): seconds.

## Environment

Run on `c8i.8xlarge`, `OMP_NUM_THREADS=16` (`OMP_DYNAMIC=FALSE`), same build
for both Horner and Tree runs within one `run_compare.sh` invocation. The
exact commit under test is recorded in `results/giant-step-poc/commit.txt`
by `run_compare.sh` (`git rev-parse HEAD`).

## Acceptance criteria

For every `tree` row in `summary.md` (and, for reference, every `horner`
row):

- `spec_status` (spec CSV `status`) is `ok`.
- `all_trials_fhe_agree` (timing CSV `fhe_agrees`) is `1`.
- `residual_capacity_status` is `not-exposed-by-openfhe`.
- `log2(q/t)` (`log2_q_over_t_bits`) is `>=` `required_cap`
  (`required_capacity_bits`).
- `nat_depth` (`natural_mult_depth`) matches the plan table's natural depth
  for that `k` -- this is the depth the tree circuit *needs*, independent
  of how much the `--ps_override` chose to provision.

`summarize.py` exits 1 (after still writing `summary.md`) if any of these
fail or if a `(mode, k)` cell is missing from either CSV pair.

## Notes

- `run_compare.sh` uses `--timing_scenario=vary_k` deliberately: the
  `--ps_override` values are calibrated for `m=64` at `STD128`, so running
  the `vary_m` or `vary_size` sweeps under the same override would apply an
  `m=64`-calibrated noise row to a different geometry.
- The depth reported for the tree circuit must always be read from the
  spec CSV's `natural_mult_depth` column, never from the override's
  provisioned `mult_depth` -- an override can over-provision depth without
  limit, which would understate the circuit's true requirement if used as
  the reported figure.
- `results/giant-step-poc/` is git-ignored (covered by the repository's
  top-level `results` ignore rule); nothing under it is committed.
