#!/bin/sh
# Same build, same machine, back to back: Horner (frozen calibration table,
# no override) then Tree (probe-derived overrides). Only the varying-k sweep
# runs; m and set-size sweeps are excluded because overrides are bound to m=64.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
BIN="$ROOT/build/bench_threshold"
OUT="$ROOT/results/giant-step-poc"
mkdir -p "$OUT"
: "${OMP_NUM_THREADS:=16}"; export OMP_NUM_THREADS
export OMP_DYNAMIC=FALSE
COMMON="--m=64 --set_size=1000 --security=STD128 --seed=20260729"
OVERRIDES=$(tr '\n' ' ' < "$OUT/overrides.txt")
run() { name=$1; shift; echo "== $name =="; "$BIN" "$@" > "$OUT/$name.csv" 2> "$OUT/$name.log"; }
run horner_spec   --mode=spec   $COMMON --giant_step=horner
run tree_spec     --mode=spec   $COMMON --giant_step=tree $OVERRIDES
run horner_timing --mode=timing $COMMON --trials=30 --timing_scenario=vary_k --giant_step=horner
run tree_timing   --mode=timing $COMMON --trials=30 --timing_scenario=vary_k --giant_step=tree $OVERRIDES
git -C "$ROOT" rev-parse HEAD > "$OUT/commit.txt"
echo "done: $OUT"
