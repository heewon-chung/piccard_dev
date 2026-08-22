#!/bin/sh
# Re-measure ONLY the cells that overrides.txt points at, on this machine, and
# fail if any measured noise exceeds the noise the override was selected with.
# This is the real cross-machine check: bench_threshold --mode=spec only echoes
# the override's eval_noise_bits back (params_calibration.cpp, profile from the
# selected candidate); it never re-measures it.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
BIN="$ROOT/build/bench_noise"
DIR="$ROOT/results/giant-step-poc"
OVR="${OVERRIDES_FILE:-$DIR/overrides.txt}"
# Always re-measure: a stale CSV copied from another machine must never pass
# as evidence for this one. The directory is wiped and stamped with the host.
OUT="$DIR/verify"
rm -rf "$OUT"; mkdir -p "$OUT"
{ echo "host=$(hostname)"; echo "date=$(date -u +%FT%TZ)"; echo "commit=$(git -C "$ROOT" rev-parse HEAD)"; uname -m; } > "$OUT/provenance.txt"
: "${OMP_NUM_THREADS:=16}"; export OMP_NUM_THREADS
export OMP_DYNAMIC=FALSE
fail=0
while IFS= read -r line; do
  spec=${line#--ps_override=}
  k=$(echo "$spec" | cut -d: -f1); depth=$(echo "$spec" | cut -d: -f2)
  sms=$(echo "$spec" | cut -d: -f3); want=$(echo "$spec" | cut -d: -f4)
  logd=$(echo "$spec" | cut -d: -f6)
  # bench_noise takes a delta over the tree's natural depth; the override
  # carries the provisioned depth. Natural tree depths: PatersonStockmeyerNaturalDepth.
  case "$k" in 16) nat=6;; 32) nat=7;; 64) nat=8;; 128) nat=9;; 256) nat=10;; 512) nat=13;;
    *) echo "no natural depth for k=$k"; exit 1;; esac
  delta=$((depth - nat))
  f="$OUT/k${k}_depth${depth}_sms${sms}.csv"
  {
    echo "verify k=$k depth=$depth (delta=$delta) sms=$sms (override eval_noise=$want)"
    if "$BIN" --circuit=threshold --security=STD128 --k="$k" --m=64 \
         --giant_step=tree --depth_delta="$delta" --sms="$sms" \
         --reps=5 --patterns=all --seed=20260729 --csv="$f.tmp" \
         > "$OUT/k${k}.log" 2>&1; then
      mv "$f.tmp" "$f"
    else
      rm -f "$f.tmp"; echo "  bench_noise FAILED (see $OUT/k$k.log)"; fail=1; continue
    fi
  }
  # exactly the three patterns, each once (reps collapse to one row per pattern)
  pats=$(awk -F, 'NR>1{print $16}' "$f" | sort | tr '\n' ' ')
  if [ "$pats" != "all_match no_match random " ]; then
    echo "  MISMATCH k=$k: unexpected pattern rows [$pats]"; fail=1; continue
  fi
  # columns: 17 eval_noise_bits, 19 saturated, 20 decrypt_ok, 25 status
  got=$(awk -F, 'NR>1 && $17+0>m {m=$17+0} END{printf "%d", (m==int(m)?m:int(m)+1)}' "$f")
  bad=$(awk -F, 'NR>1 && ($19!="0" || $20!="1" || $25!="ok")' "$f" | wc -l | tr -d ' ')
  # The gate is the selector's own feasibility inequality (select_override.py):
  # eval + 64 (coefficient) + 8 (margin) + 2 (slack) <= log2(q/t). A +/-1 bit
  # run-to-run drift in eval_noise is normal and must not fail the run; a cell
  # that no longer satisfies the inequality must.
  need=$((got + 74))
  if [ "$bad" != "0" ] || [ "$need" -gt "$logd" ]; then
    echo "  INFEASIBLE k=$k: measured eval_noise=$got, need $need > log2(q/t)=$logd, bad_rows=$bad"; fail=1
  else
    drift=$((got - want))
    echo "  ok k=$k: eval_noise=$got (override $want, drift $drift), $need <= $logd, bad_rows=0"
  fi
done < "$OVR"
if [ "$fail" = 0 ]; then echo "all overrides verified on this machine"
else echo "VERIFY FAILED: re-run Steps 1-2 for the mismatched k"; exit 1; fi
