"""Plan 13-2 V-5 (3) gate: SJ16 extrapolated CSV rows exist and follow the
field conventions bench_comparison.cpp's FinalizeSJ16Extrapolated (via
benchmarks/sj16_adapter.h) commits to.

Transcribed from Branch_Prompts/13_measurement-symmetry.md V-5 (3) with one
deviation from the literal pseudocode, verified empirically before writing
this file (build + run, not guessed):

    total_ms_sd sentinel check uses `float(...) == -1.0` instead of the
    plan's literal `r["total_ms_sd"] == "-1"`. bench_comparison.cpp's CSV
    writer renders EVERY *_sd column with `std::fixed <<
    std::setprecision(3)` (WriteRow, benchmarks/bench_comparison.cpp) — the
    -1.0 sentinel therefore always serializes as the string "-1.000", never
    bare "-1", for measured rows too. A literal "-1" string comparison would
    fail against a correct implementation on every real run; this is the
    same class of formatting-assumption bug the plan's own V-7 review
    history caught twice before (rounds 1-2 of this same document). All
    other assertions are transcribed as written.

Precondition (V-5 (1), enforced by the caller, not this script): a PASS
calibration artifact for the smoke run's --sj16_key_bits must already exist
at results/sj16_calibration_<host>.txt, and the smoke CSV (V-5 (2)) must be
generated AFTER that artifact exists. Without that ordering this script's
`assert extr` fires for the right reason (13-2 not exercised) but the wrong
cause (missing precondition, not missing implementation).
"""

import csv, pathlib, sys

smoke = pathlib.Path(sys.argv[1])
rows = list(csv.DictReader(open(smoke / "comparison_timing.csv")))

kinds = {r["measurement_kind"] for r in rows}
assert kinds <= {"measured", "extrapolated"}, kinds
assert all(r["measurement_kind"] for r in rows), "some row has an empty measurement_kind"

meas = [r for r in rows if r["method"] == "sj16" and r["measurement_kind"] == "measured"]
extr = [r for r in rows if r["method"] == "sj16" and r["measurement_kind"] == "extrapolated"]

# The (1) PASS fit is a precondition, so the extrapolated row is **required**.
# Without this assert, 13-2 could be unimplemented and this script would
# still pass.
assert extr, "PASS 적합이 있는데도 외삽 행이 0개 — 13-2 미구현이거나 방출 경로가 죽었다"
assert meas, "실측 sj16 행이 0개 — u<=max 지점이 측정되지 않았다"

for r in extr:
    assert r["trials"] == "0", ("extrapolated trials must be 0", r["trials"])
    assert float(r["total_ms"]) > 0, "extrapolated row has no predicted time"
    # See module docstring: -1.000 is the real serialized sentinel, not "-1".
    assert float(r["total_ms_sd"]) == -1.0, ("sd sentinel expected", r["total_ms_sd"])
    assert float(r["phase_encode_ms"]) == 0, "phase breakdown must not be invented"
    assert r["extrapolation_alpha"] and r["extrapolation_source"], "provenance missing"
for r in meas:
    assert not r["extrapolation_alpha"], "measured row carries extrapolation fields"

print(f"OK: sj16 measured={len(meas)} extrapolated={len(extr)}")
