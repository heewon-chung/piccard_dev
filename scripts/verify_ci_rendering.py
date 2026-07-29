import contextlib, csv, importlib.util, io, pathlib, sys

smoke = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("sr", "scripts/summarize_results.py")
sr = importlib.util.module_from_spec(spec); spec.loader.exec_module(sr)

FAMILY_BY_LABEL = {"tab:comparison-vary-k": "vary_k", "tab:comparison-vary-m": "vary_m",
                   "tab:comparison-vary-size": "vary_size",
                   "tab:comparison-vary-universe": "vary_universe"}
DISC = "FHE-IND"
CELL = 1                      # Method 열 신설 후 시나리오/파라미터 셀 위치

def render(ci):
    """비교 timing 표만 (layout, label, headers, rows) 로 포착한다."""
    tabs, _pt, _plt = [], sr.print_table, sr.print_latex_table
    def cap_pt(h, r, *a, **k):
        tabs.append(("ascii", None, list(h), [list(x) for x in r])); return _pt(h, r, *a, **k)
    def cap_plt(c, l, h, r, *a, **k):
        tabs.append(("latex", l, list(h), [list(x) for x in r])); return _plt(c, l, h, r, *a, **k)
    sr.print_table, sr.print_latex_table = cap_pt, cap_plt
    sys.argv = ["summarize_results.py", str(smoke), "--latex"] + (["--ci"] if ci else [])
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            sr.main()
    finally:
        sr.print_table, sr.print_latex_table = _pt, _plt
    # ASCII 는 "Speedup" 헤더로, LaTeX 는 라벨로 식별한다 (통신량 표 제외)
    return [t for t in tabs
            if (t[0] == "ascii" and "Speedup" in t[2]) or (t[0] == "latex" and t[1] in FAMILY_BY_LABEL)]

plain, withci = render(False), render(True)
assert plain and len(plain) == len(withci), (len(plain), len(withci))

rows = list(csv.DictReader(open(smoke / "comparison_timing.csv")))
csv_by = {(r["scenario"], r["method"]): r for r in rows}   # ⚠ 반드시 (시나리오, method)

def clean(v):
    return str(v).replace(",", "").replace("$", "").strip()

def scen_of(layout, label, row):
    # ⚠ ASCII 와 LaTeX 의 첫 값 셀 의미가 다르다: ASCII 는 전체 시나리오 문자열,
    #   LaTeX 는 파라미터 값만. 계열은 표 라벨에서 복원한다.
    return clean(row[CELL]) if layout == "ascii" \
        else f"{FAMILY_BY_LABEL[label]}_{clean(row[CELL])}"

# 검사할 열: (헤더명) -> (CSV 필드, side, primary 행의 출처)
COLS = {"Piccard (ms)":    ("total_ms",       "piccard",    "piccard"),
        "Comparator (ms)": ("total_ms",       "comparator", "baseline"),
        "Flood":           ("phase_flood_ms", "shared",     "piccard")}

lo_seen = hi_seen = changed = expect_changed = 0

def check(src, a, b, field, where):
    """한 셀을 두 모드 각각에서 summarizer 자신의 포매터와 대조한다."""
    global lo_seen, hi_seen, changed, expect_changed
    want_a = sr.fmt_disp(src, field, ci=False)
    want_b = sr.fmt_disp(src, field, ci=True)
    assert a == want_a, ("plain mismatch", where, a, want_a)
    assert b == want_b, ("ci mismatch", where, b, want_b)
    n = int(src.get("trials", "0") or 0)
    if n < 2:
        lo_seen += 1
        assert "±" not in a and "±" not in b, ("trials<2 인데 산포가 붙었다", where, n, a, b)
        assert a == b, ("trials<2 셀이 --ci 로 바뀌었다", where, a, b)
    else:
        hi_seen += 1
        # ⚠ "반드시 달라야 한다"고 못박지 않는다 — sd 가 표시 정밀도 아래면 두 서식이
        #   같을 수 있다. 기대 자체를 포매터에서 파생시켜 오탈락을 없앤다.
        if want_a != want_b:
            expect_changed += 1
            if a != b:
                changed += 1

for (l0, lab0, h0, r0), (l1, lab1, h1, r1) in zip(plain, withci):
    assert (l0, lab0, h0) == (l1, lab1, h1), ("table drift between --ci and plain", lab0)
    assert len(r0) == len(r1), ("row-count drift", lab0, len(r0), len(r1))
    idx = {h: i for i, h in enumerate(h0) if h in COLS}
    assert idx, ("no fmt_disp column found", h0)
    for row0, row1 in zip(r0, r1):
        label = str(row0[0]).replace("\\_", "_").strip()
        scen = scen_of(l0, lab0, row0)
        primary = DISC in label
        key_m = None if primary else label.split()[0]
        own = None if primary else ("piccard" if key_m.startswith("piccard") else "comparator")
        for hname, i in idx.items():
            field, side, primary_src = COLS[hname]
            a, b = str(row0[i]).strip(), str(row1[i]).strip()
            if primary:
                src = csv_by.get((scen, primary_src))
                if src is None:
                    assert a == "-" and b == "-", ("no CSV row but a value rendered", scen, hname, a)
                    continue
                check(src, a, b, field, (l0, lab0, scen, "primary", hname))
            else:
                if side not in ("shared", own):
                    assert a in ("", "-") and b in ("", "-"), \
                        ("value on the wrong side", scen, key_m, hname, a)
                    continue
                src = csv_by.get((scen, key_m))
                assert src is not None, ("no matching CSV row", scen, key_m)
                check(src, a, b, field, (l0, lab0, scen, key_m, hname))

assert lo_seen > 0, "trials<2 셀이 하나도 없다 — V-5 선행조건 없이 돌렸다 (검사가 공허해짐)"
assert hi_seen > 0, "trials>=2 셀이 하나도 없다 — --trials=5 로 생성했는지 확인"
assert expect_changed > 0, \
    "포매터 기준으로도 --ci 가 어떤 셀도 바꾸지 않는다 — sd 가 표시 정밀도 아래다. --trials 를 늘려 재시도"
assert changed == expect_changed, \
    ("--ci 가 바뀌어야 할 셀을 바꾸지 않았다 (플래그 미전파 의심)", changed, expect_changed)
print(f"OK: trials<2 {lo_seen}셀(맨 평균 유지), trials>=2 {hi_seen}셀, CI 전환 {changed}/{expect_changed}")
