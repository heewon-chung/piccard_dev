#!/usr/bin/env python3
"""Join horner/tree spec+timing CSVs per k into summary.md; exit 1 on gaps."""
import csv, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "results", "giant-step-poc")
KS = [int(x) for x in os.environ.get("KS", "16 32 64 128 256").split()]

def load(name):
    with open(os.path.join(OUT, name)) as f:
        return list(csv.DictReader(f))

spec = {m: {int(r["k"]): r for r in load(f"{m}_spec.csv") if r["k"].isdigit()} for m in ("horner", "tree")}
timing = {m: {int(r["k"]): r for r in load(f"{m}_timing.csv")
              if r["label"].startswith("vary_k_") and r["k"].isdigit()} for m in ("horner", "tree")}

cols = ["k", "mode", "spec_status", "nat_depth", "prov_depth", "N", "log2q", "log2(q/t)", "required_cap",
        "sms", "limbs", "giant_mults", "eval_noise", "flood_bits",
        "poly_eval_ms", "total_ms", "total_ms_sd", "total_ms_median", "ct_bytes", "trials",
        "all_trials_correct", "all_trials_fhe_agree"]
lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
problems = []
for k in KS:
    for m in ("horner", "tree"):
        s, t = spec[m].get(k), timing[m].get(k)
        if s is None or t is None:
            problems.append(f"{m} k={k}: missing {'spec' if s is None else ''} {'timing' if t is None else ''} row")
            continue
        if s["status"] != "ok": problems.append(f"{m} k={k}: spec status {s['status']} ({s.get('note','')})")
        if t["fhe_agrees"] != "1": problems.append(f"{m} k={k}: fhe_agrees={t['fhe_agrees']}")
        if s["residual_capacity_status"] != "not-exposed-by-openfhe":
            problems.append(f"{m} k={k}: residual_capacity_status={s['residual_capacity_status']}")
        if float(s["log2_q_over_t_bits"]) < float(s["required_capacity_bits"]):
            problems.append(f"{m} k={k}: log2(q/t) {s['log2_q_over_t_bits']} < required {s['required_capacity_bits']}")
        lines.append("| " + " | ".join(str(x) for x in [
            k, m, s["status"], s["natural_mult_depth"], s["mult_depth"], s["realized_ring_dim"],
            s["log_q_bits"], s["log2_q_over_t_bits"], s["required_capacity_bits"],
            s["scaling_mod_size"], s["num_limbs"], s["giant_mults"], s["eval_noise_bits"], s["flood_noise_bits"],
            t["phase_poly_eval_ms"], t["total_ms"], t["total_ms_sd"], t["total_ms_median"], t["ct_size_bytes"],
            t["trials"], t["threshold_correct"], t["fhe_agrees"]]) + " |")
md = "\n".join(lines) + "\n"
if problems:
    md += "\n**Problems**\n" + "".join(f"- {p}\n" for p in problems)
open(os.path.join(OUT, "summary.md"), "w").write(md)
print(md)
sys.exit(1 if problems else 0)
