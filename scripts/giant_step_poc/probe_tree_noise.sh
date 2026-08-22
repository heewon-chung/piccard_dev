#!/bin/sh
# Probe the tree-giant-step threshold circuit's evaluation noise per k over a
# small (depth_delta, scaling_mod_size) grid. Each cell is written to a temp
# file and renamed only after bench_noise exits 0, so an interrupted probe
# can never be mistaken for evidence.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
BIN="$ROOT/build/bench_noise"
OUT="$ROOT/results/giant-step-poc/probe"
mkdir -p "$OUT"
: "${OMP_NUM_THREADS:=16}"; export OMP_NUM_THREADS
export OMP_DYNAMIC=FALSE
KS="${KS:-16 32 64 128 256}"
DELTAS="${DELTAS:-1 2 3}"
SMSS="${SMSS:-40 45 50 54}"
for k in $KS; do
  for d in $DELTAS; do
    for s in $SMSS; do
      f="$OUT/k${k}_d${d}_s${s}.csv"
      if [ -s "$f" ]; then echo "skip $f"; continue; fi
      echo "probe k=$k delta=$d sms=$s"
      if "$BIN" --circuit=threshold --security=STD128 --k="$k" --m=64 \
             --giant_step=tree --depth_delta="$d" --sms="$s" \
             --reps=5 --patterns=all --seed=20260729 --csv="$f.tmp" \
             > "$OUT/k${k}_d${d}_s${s}.log" 2>&1; then
        mv "$f.tmp" "$f"
      else
        rm -f "$f.tmp"; echo "  FAILED (see log)"
      fi
    done
  done
done
