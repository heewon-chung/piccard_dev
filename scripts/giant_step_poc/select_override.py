#!/usr/bin/env python3
"""Pick, per k, the cheapest feasible (depth, sms) tree probe.

Feasibility mirrors PiccardParams::SelectFloodingParams (threshold branch):
    ceil(max eval_noise_bits) + 64 + 8 + 2 <= floor(log_delta)
(log_delta is floored because bench_noise prints it with one decimal and the
live context check uses the exact value). A cell counts only if every row has
decrypt_ok == 1, saturated == 0, status == ok, the expected pattern set is
complete, and all rows share one (ring_dim, mult_depth, sms, log_delta).
Cost order: realised ring_dim, then log_delta.
"""
import csv, glob, math, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROBE = os.path.join(ROOT, "results", "giant-step-poc", "probe")
COEFF_BITS, MARGIN, SLACK = 64, 8, 2
EXPECTED_KS = [int(x) for x in os.environ.get("KS", "16 32 64 128 256").split()]
EXPECTED_PATTERNS = set(os.environ.get("PATTERNS", "all_match no_match random").split())

best, seen_k = {}, set()
print("| k | nat | depth | sms | N | log_delta | eval | decrypt | feasible |", file=sys.stderr)
for path in sorted(glob.glob(os.path.join(PROBE, "k*_d*_s*.csv"))):
    m = re.search(r"k(\d+)_d(\d+)_s(\d+)\.csv$", path)
    k, delta, sms = (int(x) for x in m.groups())
    seen_k.add(k)
    rows = [r for r in csv.DictReader(open(path))
            if r["circuit"].lower().startswith("thr")
            and int(r["mult_depth"]) != int(r["natural_mult_depth"])]  # drop the delta-0 baseline
    if not rows:
        continue
    ctx = {(r["ring_dim"], r["mult_depth"], r["scaling_mod_size"], r["log_delta"]) for r in rows}
    patterns = {r["pattern"] for r in rows}
    ok = (len(ctx) == 1 and patterns == EXPECTED_PATTERNS
          and all(r["decrypt_ok"] == "1" and r["saturated"] == "0" and r["status"] == "ok" for r in rows))
    eval_bits = math.ceil(max(float(r["eval_noise_bits"]) for r in rows))
    log_delta = math.floor(float(rows[0]["log_delta"]))
    ring, depth, nat = int(rows[0]["ring_dim"]), int(rows[0]["mult_depth"]), int(rows[0]["natural_mult_depth"])
    feasible = ok and eval_bits + COEFF_BITS + MARGIN + SLACK <= log_delta
    cand = dict(k=k, nat=nat, depth=depth, sms=sms, eval=eval_bits, ring=ring, log_delta=log_delta)
    if feasible and (k not in best or (ring, log_delta) < (best[k]["ring"], best[k]["log_delta"])):
        best[k] = cand
    print(f"| {k} | {nat} | {depth} | {sms} | {ring} | {log_delta} | {eval_bits} | "
          f"{'ok' if ok else 'INCOMPLETE/FAIL'} | {'yes' if feasible else '-'} |", file=sys.stderr)

missing = [k for k in EXPECTED_KS if k not in best]
if missing:
    print(f"NO FEASIBLE PROBE for k in {missing}; widen DELTAS/SMSS for those k and re-run probe_tree_noise.sh", file=sys.stderr)
    sys.exit(2)
out_path = os.path.join(ROOT, "results", "giant-step-poc", "overrides.txt")
with open(out_path, "w") as f:
    for k in EXPECTED_KS:
        b = best[k]
        line = f"--ps_override={k}:{b['depth']}:{b['sms']}:{b['eval']}:{b['ring']}:{b['log_delta']}"
        print(line); f.write(line + "\n")
