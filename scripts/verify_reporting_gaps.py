import contextlib, csv, importlib.util, io, pathlib, re, subprocess, sys

smoke = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("sr", "scripts/summarize_results.py")
sr = importlib.util.module_from_spec(spec); spec.loader.exec_module(sr)   # import는 main()을 실행하지 않는다

ascii_tabs, tex_tabs = [], []
_pt, _plt = sr.print_table, sr.print_latex_table
def cap_pt(headers, rows, *a, **k):
    ascii_tabs.append((list(headers), [list(r) for r in rows])); return _pt(headers, rows, *a, **k)
def cap_plt(caption, label, headers, rows, *a, **k):
    tex_tabs.append((caption, label, list(headers), [list(r) for r in rows]))
    return _plt(caption, label, headers, rows, *a, **k)
sr.print_table, sr.print_latex_table = cap_pt, cap_plt      # 표 함수는 호출 시점에 모듈 전역을 참조
sys.argv = ["summarize_results.py", str(smoke), "--latex"]
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    sr.main()
stdout_text = buf.getvalue()        # ASCII 제목은 구조로 전달되지 않는 유일한 표면

DISCLOSURE = ("FHE-IND [KPA/leakage; universe-sized BFV indicator vector; "
              "not a faithful [11] reimplementation]")
unesc = lambda s: str(s).replace("\\_", "_")

# ── V-3a. 라벨/폭: 정확 집합 + 정확 개수 (skip 불가) ────────────────────
TIMING = {"tab:comparison-vary-k", "tab:comparison-vary-m",
          "tab:comparison-vary-size", "tab:comparison-vary-universe"}
COMM = "tab:communication-cost"
WIDTH = {**{l: 11 for l in TIMING}, COMM: 10}
seen = [lab for _, lab, _, _ in tex_tabs if lab in WIDTH]
assert sorted(seen) == sorted(WIDTH), f"expected {sorted(WIDTH)}, rendered {sorted(seen)}"
for caption, lab, headers, rows in tex_tabs:
    if lab not in WIDTH:
        continue
    assert len(headers) == WIDTH[lab], (lab, "header", len(headers), WIDTH[lab])
    for r in rows:
        assert len(r) == WIDTH[lab], (lab, "row", len(r), WIDTH[lab], r)

# ASCII: timing 정확히 4개(17열), 통신량 정확히 1개(10열, 마지막 헤더 토큰 == "Comm C")
ascii_timing = [t for t in ascii_tabs if "Speedup" in t[0]]
# 통신량 표 식별: 마지막 토큰은 Method 열 추가 후에도 `Ratio`로 남는다.
# `Comm C`를 마지막으로 만들려면 불필요한 재배치가 필요하고 `Comparator Comm` 표기와도
# 충돌하므로(Method 열 추가 후에도 마지막은 `Ratio`다), 고유 토큰 조합으로 식별한다 (구현된 헤더에 맞춰 확정할 것).
def is_comm(h):
    return ("Comparator CTs" in h) and ("Comparator Comm" in h) and h and h[-1] == "Ratio"
ascii_comm   = [t for t in ascii_tabs if is_comm(t[0])]
assert len(ascii_timing) == 4, f"expected 4 ASCII timing tables, got {len(ascii_timing)}"
assert len(ascii_comm) == 1, f"expected 1 ASCII communication table, got {len(ascii_comm)}"
for want, group in ((17, ascii_timing), (10, ascii_comm)):
    for headers, rows in group:
        assert len(headers) == want, ("ascii header", len(headers), want, headers)
        for r in rows:
            assert len(r) == want, ("ascii row", len(r), want, r)

# ── V-3b/c. primary 행을 앵커로 블록 분할 → 시나리오별 집합·순서를 전단사로 검증 ──
# primary 행 = Method 셀에 FHE-IND 고지를 담은 행. 이 정의 자체가
# "모든 primary 행이 고지를 갖는다"를 강제한다(블록 수 == 시나리오 수로 확인).
def blocks(rows):
    """primary 행(고지 라벨 보유)을 앵커로 분할. ⚠ 모든 행이 소비돼야 한다 —
    첫 primary 이전의 행을 조용히 버리면 전단사가 성립하지 않는다."""
    out, cur = [], None
    for r in rows:
        if DISCLOSURE in unesc(r[0]):
            cur = (r, []); out.append(cur)
        else:
            assert cur is not None, f"row before any primary row: {r}"
            cur[1].append(r)
    assert sum(1 + len(s) for _, s in out) == len(rows), \
        (sum(1 + len(s) for _, s in out), len(rows), "partition does not cover all rows")
    return out

rows_csv = list(csv.DictReader(open(smoke / "comparison_timing.csv")))
def base_of(m):
    for b in ("piccard_sqrt", "bcg12", "sj16"):
        if m == b or m.startswith(b + "_"):
            return b
    return None
rank = {"piccard_sqrt": 0, "bcg12": 1, "sj16": 2}
# ⚠ 모든 시나리오를 초기화한다. 보조 method가 없는 시나리오(예: vary_m_32는 piccard+baseline뿐)를
#   빠뜨리면 렌더는 빈 블록을 내는데 기대값에는 없어 대조가 어긋난다.
per_scen = {r["scenario"]: set() for r in rows_csv}
for r in rows_csv:
    if base_of(r["method"]):
        per_scen[r["scenario"]].add(r["method"])
expected = {s: tuple(sorted(v, key=lambda m: (rank[base_of(m)], m))) for s, v in per_scen.items()}

# 시나리오 식별 — ⚠ ASCII와 LaTeX의 첫 열 의미가 다르므로 경로를 분리한다.
#   ASCII timing 표는 `Scenario` 열로 시작해 **전체 시나리오 문자열**(예: vary_k_16)을 담는다.
#   LaTeX timing 표는 `$k$`/`$m$`/`$n$`/`$|U|$`로 시작해 **파라미터 값만**(예: 16) 담는다.
#   Method 열을 앞에 붙이면 두 경우 모두 실제 값은 인덱스 1로 밀린다.
FAMILY_BY_LABEL = {"tab:comparison-vary-k": "vary_k", "tab:comparison-vary-m": "vary_m",
                   "tab:comparison-vary-size": "vary_size",
                   "tab:comparison-vary-universe": "vary_universe"}
CELL = 1        # Method 열 신설 후 값 셀 위치 — 구현된 열 순서로 확정할 것
def clean(v):
    return str(v).replace(",", "").replace("$", "").strip()
def scen_ascii(prim):                 # 전체 시나리오가 이미 들어 있다
    return clean(prim[CELL])
def scen_latex(family, prim):         # 계열 + 파라미터 값
    return f"{family}_{clean(prim[CELL])}"

def observed_pairs(rows, scen_fn):
    return [(scen_fn(prim), tuple(unesc(s[0]).strip().split()[0] for s in supps))
            for prim, supps in blocks(rows)]

# ⚠ 헤더 부분문자열로 열을 찾지 말 것 — 축약 헤더(`Comm P/C`, `$N_P/N_C$`, `P/C CTs`)에서
#   오탐·누락이 나고 LaTeX 통신량 헤더에서는 확정적 오작동이 된다.
#   구현자는 **레이아웃별로 따로** 열 맵을 확정한다. ⚠ ASCII timing(17열)과 LaTeX timing(11열)은
#   레이아웃이 다르므로 하나의 "timing" 맵으로 묶으면 한쪽에서 확정적 오작동이 난다.
#     COLMAP[layout] = {열인덱스: (csv_필드, 종류, side, primary_src)}
#       layout ∈ {"ascii-timing", "latex-timing", "ascii-comm", "latex-comm"}
#       종류 ∈ {"time","bytes","trials","raw","derived"}
#       side  ∈ {"piccard","comparator","shared"}
#       primary_src ∈ {"piccard","baseline"} — **primary 행**의 그 셀이 어느 CSV 행에서
#         렌더되는지. ⚠ shared라고 일괄 baseline에서 읽으면 안 된다: primary 행의 `Flood`는
#         Piccard 행에서 렌더되므로(`summarize_results.py:487`) 정상 표가 오탈락한다.
#   또한 맵 누락을 assert로 강제한다. ⚠ 필수 집합을 **손으로 또 적으면** 두 선언이 함께
#   빠질 때 통과한다 → 포착된 **헤더에서 파생**한다: 면제 목록(파라미터/시나리오/Method 셀)을
#   제외한 나머지 열은 전부 매핑 대상이다.
#     EXEMPT_HEADERS[layout] = {"Method", "Scenario", "$k$", ...}  # 값이 method와 무관한 열
#   required = {i for i, h in enumerate(headers) if h not in EXEMPT_HEADERS[layout]}
#   ⚠ `Trials`·`Flood`는 Piccard 행과 comparator 행 **양쪽에 채워지므로** side="shared"다.
#     고정 side로 두면 정상 렌더를 오탈락시킨다.
#   ⚠ `Speedup`/`Ratio`(derived)와 `num_cts`(raw)도 method별로 달라지므로 맵에 포함한다.
#     derived는 CSV 두 행에서 계산해 대조하고, raw는 문자열 그대로 대조한다.
#   계약: method별로 값이 달라지는 열은 **모두** 맵에 있어야 하며, 알 수 없는 종류는
#     조용히 건너뛰지 말고 **즉시 실패**시킨다.
EXEMPT_HEADERS = {
    "ascii-timing": {"Method", "Scenario", "k", "m", "n", "|U|"},
    "latex-timing": {"Method", "$k$", "$m$", "$n$", "$|U|$"},
    "ascii-comm":   {"Method", "Scenario", "k", "|U|", "n"},
    "latex-comm":   {"Method", "Scenario", "$k$", "$|U|$", "$n$"},
}
COLMAP = {
    "ascii-timing": {
        2:  ("trials",         "trials",  "shared",     "piccard"),
        7:  ("ring_dim",       "raw",     "piccard",    "piccard"),
        8:  ("ring_dim",       "raw",     "comparator", "baseline"),
        9:  ("total_ms",       "time",    "piccard",    "piccard"),
        10: ("total_ms",       "time",    "comparator", "baseline"),
        11: ("speedup",        "derived", "shared",     "baseline"),
        12: ("ct_size_bytes",  "bytes",   "piccard",    "piccard"),
        13: ("ct_size_bytes",  "bytes",   "comparator", "baseline"),
        14: ("comm_bytes",     "bytes",   "piccard",    "piccard"),
        15: ("comm_bytes",     "bytes",   "comparator", "baseline"),
        16: ("phase_flood_ms", "time",    "shared",     "piccard"),
    },
    "latex-timing": {
        2:  ("trials",         "trials",  "shared",     "piccard"),
        3:  ("ring_dim",       "raw",     "piccard",    "piccard"),
        4:  ("ring_dim",       "raw",     "comparator", "baseline"),
        5:  ("total_ms",       "time",    "piccard",    "piccard"),
        6:  ("total_ms",       "time",    "comparator", "baseline"),
        7:  ("speedup",        "derived", "shared",     "baseline"),
        8:  ("comm_bytes",     "bytes",   "piccard",    "piccard"),
        9:  ("comm_bytes",     "bytes",   "comparator", "baseline"),
        10: ("phase_flood_ms", "time",    "shared",     "piccard"),
    },
    "ascii-comm": {
        5: ("num_cts",    "raw",     "piccard",    "piccard"),
        6: ("comm_bytes", "bytes",   "piccard",    "piccard"),
        7: ("num_cts",    "raw",     "comparator", "baseline"),
        8: ("comm_bytes", "bytes",   "comparator", "baseline"),
        9: ("ratio",      "derived", "shared",     "baseline"),
    },
    "latex-comm": {  # identical indices — same row objects as ascii-comm
        5: ("num_cts",    "raw",     "piccard",    "piccard"),
        6: ("comm_bytes", "bytes",   "piccard",    "piccard"),
        7: ("num_cts",    "raw",     "comparator", "baseline"),
        8: ("comm_bytes", "bytes",   "comparator", "baseline"),
        9: ("ratio",      "derived", "shared",     "baseline"),
    },
}                                       # ← 구현 후 4개 레이아웃 모두 확정
# 파생 셀(Speedup / Ratio)은 **직접 재구현하지 않는다** — 서식과 0값 정책이 갈린다:
#   · ASCII `1.2x` vs LaTeX `1.2$\times$`
#   · **행 역할에 따라 0값 처리가 다르다**: method_ms=0·piccard_ms>0일 때
#     primary 행은 `0.0x`를, supplementary 행은 `-`를 렌더한다
#     (`summarize_results.py:469` vs `:506`) → `latex=`만으로는 구분 불가.
#   · LaTeX 통신량 표는 현재 **ASCII 행을 재사용**하므로 ratio가 `x`로 렌더된다.
# 구현 계약: `summarize_results.py`에 헬퍼를 **추출**하되 시그니처에 **행 역할**을 포함하고,
#   현재 출력을 그대로 보존해야 한다:
#     fmt_speedup(method_ms, piccard_ms, *, latex: bool, row_role: "primary"|"supplementary")
#     fmt_ratio(method_bytes, piccard_bytes, *, latex: bool, row_role: ...)
#   ⚠ `fmt_ratio`는 LaTeX 통신량의 현재 `x` 서식을 유지해야 한다. 이를 `$\times$`로 바꾸려면
#     **계획서에서 명시적으로 승인하고** 그 변경을 검증에 반영할 것(조용한 출력 변경 금지).
def derived_value(field, row, piccard_row, latex, row_role):
    if field == "speedup":
        return sr.fmt_speedup(float(row.get("total_ms", "0")),
                              float(piccard_row.get("total_ms", "0")),
                              latex=latex, row_role=row_role)
    if field == "ratio":
        return sr.fmt_ratio(float(row.get("comm_bytes", "0")),
                            float(piccard_row.get("comm_bytes", "0")),
                            latex=latex, row_role=row_role)
    raise AssertionError(("unknown derived field", field))

def check_labels_and_values(name, layout, headers, rows, scen_fn, csv_by, ci=False):
    """라벨·값·side를 모두 검증한다. 비어있지 않음만 보면 조작된 값도 통과하므로
    summarizer 자신의 포매터로 CSV 원본과 대조한다.
    primary(FHE-IND) 행도 comparator 값으로 검증한다 — 보조행만 보면 본행 값이 무검증이다."""
    colmap = COLMAP.get(layout)
    assert colmap, (name, layout, "column map not defined — fill COLMAP after implementing")
    exempt = EXEMPT_HEADERS.get(layout)
    assert exempt is not None, (name, layout, "exempt-header set not declared")
    req = {i for i, h in enumerate(headers) if str(h) not in exempt}
    assert set(colmap) == req, \
        (name, layout, "COLMAP must cover every non-exempt column (derived from headers)",
         sorted(req - set(colmap)), sorted(set(colmap) - req))
    is_latex = layout.startswith("latex")
    def cell_matches(row, cells, c, field, kd, piccard_row=None, row_role="supplementary"):
        cell = str(cells[c]).strip()
        if kd == "time":      want = sr.fmt_disp(row, field, ci=ci)
        elif kd == "bytes":   want = sr.fmt_bytes(row.get(field, "0"))
        elif kd == "trials":  want = sr.get_trials(row)
        elif kd == "raw":     want = row.get(field, "")
        elif kd == "derived":                       # Speedup / Ratio: CSV 두 행에서 계산
            want = derived_value(field, row, piccard_row, is_latex, row_role)
        else:
            raise AssertionError((name, c, "unknown column kind — do not skip silently", kd))
        assert cell == str(want).strip(), (name, c, "value mismatch", cell, want)

    for prim, supps in blocks(rows):
        scen = scen_fn(prim)
        pic_row = csv_by.get((scen, "piccard"))
        assert pic_row is not None, (name, scen, "no piccard CSV row for this scenario")
        # primary(FHE-IND) 행도 검증한다 — 보조행만 보면 본행 값이 무검증으로 남는다
        base_row = csv_by.get((scen, "baseline"))
        assert base_row is not None, (name, scen, "no baseline CSV row")
        for c, (field, kd, side, primary_src) in colmap.items():
            src = pic_row if primary_src == "piccard" else base_row
            cell_matches(src, prim, c, field, kd, pic_row, row_role="primary")
        for s in supps:
            lab = unesc(s[0]).strip()
            key = lab.split()[0]
            row = csv_by.get((scen, key))
            assert row is not None, (name, scen, key, "no matching CSV row")
            # 보안군 표기는 CSV의 security_class와 **정확히** 일치해야 한다
            assert f"[{row['security_class']}" in lab, \
                (name, key, "security class mismatch", lab, row["security_class"])
            if key == "sj16":
                assert "secure division excluded" in lab or "lower bound" in lab, \
                    (name, "sj16 lower-bound caveat missing from label", lab)
            own = "piccard" if key.startswith("piccard") else "comparator"
            for c, (field, kd, side, _primary_src) in colmap.items():
                if side not in ("shared", own):
                    assert str(s[c]).strip() in ("", "-"), \
                        (name, key, "value on the wrong side", c, s[c])
                    continue
                cell_matches(row, s, c, field, kd, pic_row)


# timing: ASCII 4표 + LaTeX 4표 — 각 렌더링 경로가 전 시나리오를 정확히 한 번씩 재현해야 한다
tex_timing = [(FAMILY_BY_LABEL[lab], h, rw) for _, lab, h, rw in tex_tabs if lab in TIMING]
paths = [("latex", [(h, rw, (lambda p, f=fam: scen_latex(f, p))) for fam, h, rw in tex_timing]),
         ("ascii", [(h, rw, scen_ascii) for h, rw in ascii_timing])]
for name, tabs in paths:
    got = {}
    for headers, rows, scen_fn in tabs:
        for scen, seq in observed_pairs(rows, scen_fn):
            assert scen not in got, f"{name}: scenario {scen} rendered twice"
            got[scen] = seq
    assert got == expected, (f"{name}: per-scenario supplementary mismatch",
                             sorted(set(expected) - set(got)), sorted(set(got) - set(expected)),
                             {s: (expected[s], got[s]) for s in got if s in expected and got[s] != expected[s]})

# 라벨·값·side 검사 — timing 8표 + 통신량 2표 = **10표 전부**에 적용한다.
# (timing에만 호출하면 통신량 표에서 BCG12/SJ16이 전부 누락돼도 통과한다.)
csv_by = {(r["scenario"], r["method"]): r for r in rows_csv}
checked = 0
for h, rw in ascii_timing:
    check_labels_and_values("ascii-timing", "ascii-timing", h, rw, scen_ascii, csv_by); checked += 1
for fam, h, rw in tex_timing:
    check_labels_and_values("latex-timing", "latex-timing", h, rw,
                            (lambda p, f=fam: scen_latex(f, p)), csv_by); checked += 1
assert checked == 8, f"expected 8 timing tables checked, got {checked}"

# 통신량 표(ASCII 1 + LaTeX 1)도 동일하게 — 여기를 빼면 BCG12/SJ16을 전부 누락해도 통과한다
tex_comm = [(h, rw) for _, lab, h, rw in tex_tabs if lab == COMM]
assert len(tex_comm) == 1, f"expected 1 LaTeX communication table, got {len(tex_comm)}"
for name, (headers, rows) in (("ascii-comm", ascii_comm[0]), ("latex-comm", tex_comm[0])):
    got = {}
    for prim, supps in blocks(rows):
        # 통신량 표는 한 표에 전 시나리오가 들어가므로 계열을 행에서 읽어야 한다
        # (구현된 시나리오 셀 위치에 맞춰 SCEN_COL을 확정할 것)
        # 통신량 표는 계열 파라미터가 없고 첫 열(Method 추가 후 인덱스 1)에
        # 원본 시나리오 문자열을 그대로 담는다.
        scen = clean(prim[CELL])
        assert scen not in got, (name, f"scenario {scen} rendered twice")
        got[scen] = tuple(unesc(s[0]).strip().split()[0] for s in supps)
    assert set(got) == set(expected), (name, "scenario set mismatch",
                                       sorted(set(expected) - set(got)), sorted(set(got) - set(expected)))
    for s, seq in got.items():
        assert seq == expected[s], (name, s, expected[s], seq)
    # 통신량 표에도 라벨·값·side 검사를 적용한다 (timing에만 걸면 여기가 검사 밖이다)
    check_labels_and_values(name, name, headers, rows, lambda p: clean(p[CELL]), csv_by)  # name ∈ {ascii-comm, latex-comm}

# LaTeX 캡션: WIDTH에 속한 5개 표 전부
for caption, lab, _, _ in tex_tabs:
    if lab in WIDTH:
        assert "Comparator" in caption, (lab, "caption not neutralized")
        assert "FHE-IND" in caption, (lab, "caption lacks disclosure")
# ASCII 제목: 비교/통신량 제목 정확히 5개, 전부 고지 포함
titles = [l for l in stdout_text.splitlines() if re.match(r"\s*Table \d+:", l)]
comp_titles = [t for t in titles if "Comparator" in t]
assert len(comp_titles) == 5, f"expected 5 comparator ASCII titles, got {len(comp_titles)}"
for t in comp_titles:
    assert "FHE-IND" in t, f"ASCII title lacks disclosure: {t}"

# ── V-3d. 중립화: 표 구조 + CLI help(stderr 포함) + 소스 문서 ────────────
STALE = [r"\bBaseline\b", r"\bbaseline\b", r"\$N_B\$", r"\bN_b\b",
         r"Comm B", r"B CTs", r"B Comm"]
blob = "\n".join(str(x) for t in ascii_tabs for x in t) + \
       "\n".join(str(x) for t in tex_tabs for x in t) + "\n" + stdout_text
proc = subprocess.run(["./build/bench_comparison", "--help"], capture_output=True, text=True)
assert proc.returncode == 0, f"--help exited {proc.returncode}"
help_out = proc.stdout + proc.stderr          # PrintUsage()는 stderr로 쓴다
assert help_out.strip(), "--help produced no output on either stream"
for name, text in (("tables+titles", blob), ("cli-help", help_out)):
    for pat in STALE:
        assert not re.search(pat, text), f"{name}: stale {pat!r} remains"
# 소스 문서의 잘못된 귀속 (계획 10-2 항목 6).
# ⚠ 전면 금지는 과하다 — "not an EPSet/ZLG+24 reimplementation" 같은 **정정 문구**를 막는다.
#   남아 있는 언급은 부정 표현과 같은 줄에 있어야 하고, FHE-IND 고지가 존재해야 한다.
# 귀속 정정은 **문구를 고정**한다. 정규식으로 "부정문 여부"를 판정하려 하면
# "not a faithful reimplementation of EPSet" 같은 정당한 변형을 거부하거나
# "Not timing-only; this is an EPSet reimplementation" 같은 문장을 통과시킨다.
APPROVED_NOTE = ("not a faithful reimplementation of ZLG+24/EPSet; this is a "
                 "universe-sized BFV indicator-vector protocol")
def normalize(s):
    # 주석 구분자만 제거한다. ⚠ `/`를 무조건 지우면 `ZLG+24/EPSet`가 `ZLG+24 EPSet`가 되어
    #   정규화하지 않은 APPROVED_NOTE와 절대 일치하지 않는다(이전 판의 확정 오작동).
    s = re.sub(r"(^|\n)\s*(//+|/\*+|\*+/?|#+)", " ", s)
    return re.sub(r"\s+", " ", s).strip()
NOTE_N = normalize(APPROVED_NOTE)          # 승인 문구도 같은 규칙으로 정규화
for path in ("benchmarks/baseline_engine.h", "benchmarks/bench_comparison.cpp"):
    norm = normalize(pathlib.Path(path).read_text())
    assert NOTE_N in norm, f"{path}: approved corrective note missing verbatim"
    # 승인 문구 밖에서의 언급은 금지 — 문구를 지운 뒤 잔존 여부로 판정
    residual = norm.replace(NOTE_N, " ")
    assert not re.search(r"ZLG\+24|EPSet", residual), \
        f"{path}: EPSet/ZLG+24 mentioned outside the approved corrective note"
# CLI 표시: 토큰만 보면 무관한 help 줄로도 통과하므로 비교자 문구 전체를 요구한다
assert "FHE-IND" in help_out and re.search(r"indicator[- ]vector", help_out, re.I), \
    "CLI help does not present the FHE-IND comparator identity (label + indicator-vector)"
print("OK")
