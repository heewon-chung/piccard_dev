# 브랜치: `tkde-major/noise-flooding` — 실행 계획

워크트리: `~/Documents/orca/workspace/piccard/tkde-major-noise-flooding`
리뷰 항목: **R2-W6** / 로드맵 **P1-3**

**시작 전에 `00_shared_context.md`를 읽어라.** 이 문서는 2026-07-25 조사 세션의 결과로
초안 프롬프트를 대체한 것이다. 초안의 미확인 추정 몇 가지는 실측으로 뒤집혔으므로,
아래 "§2 검증된 코드 상태"를 초안보다 우선한다.

---

## §0. 이 브랜치가 해결하는 것

리뷰어 2의 지적:

> R2-W6: "Noise-flooding overhead not characterized. The receiver-view simulation relies on
> flooding with noise of magnitude 2^λ times the evaluation noise. The impact on modulus size,
> ciphertext expansion, and decryption correctness is not analyzed, yet it is essential to the
> security claim. The reported parameters (q ≈ 109 bits at depth 1) do not obviously leave
> room for 2^λ flooding with λ = 128."

**지적은 타당하다.** 논문 `appendix.tex:78-79`는 flooding을 한다고 쓰여 있는데 구현에 없고,
현재 파라미터로는 λ=128을 수용할 수 없다(§3에 정확한 수치).

### 확정된 설계 결정 (승인됨, 2026-07-25)

| 항목 | 결정 | 근거 |
|---|---|---|
| 통계적 보안 파라미터 | **λ_s = 64** 기본 | 계산 비용이 λ_s=40과 동일(둘 다 limb 1개 추가). λ_s만 40으로 바꾸면 파라미터가 자동으로 내려가는 구조로 만든다 |
| B_eval 근거 | **측정 + 명시적 마진** | 해석적 상한 유도는 범위 밖. 측정값을 캘리브레이션 표에 박고 회귀 테스트로 고정 |
| flooding on/off | **항상 on, 스위치 없음** | 증명 없는 코드 경로를 만들지 않는다 |

⚠️ **"항상 on" + "측정 기반 B_eval"의 귀결:** flooding은 **서버**가 수행하는데 서버에는
비밀키가 없다. 따라서 B_eval을 런타임에 측정할 수 없고, **오프라인 캘리브레이션 상수**여야
한다. 이것이 §5 설계 전체의 출발점이다.

---

## §1. 시작 상태

```
HEAD = 4bd7459  Merge pull request #2 (tkde-major/hash-seed-crs)
        ├─ c88ab0c  Merge PR #1 (tkde-major/benchmark-stats)
        └─ 4f21248..a1e325c  hash-seed-crs (CRS 시드)
```

**선행 브랜치 2개가 이미 머지돼 있다.** 초안이 경고한 `params.{h,cpp}` rebase 충돌은
**해소됐다** — 지금 `params.{h,cpp}`는 이 브랜치가 자유롭게 수정할 수 있다.

베이스라인 재확인 (작업 시작 전 직접 실행할 것):
```bash
cmake -S . -B build && cmake --build build -j8
cd build && ctest --output-on-failure
```
→ **빌드 클린, 13/13 통과** (benchmark-stats가 `BenchmarkUtils` 테스트를 추가해 12→13).

---

## §2. 검증된 코드 상태

초안의 주장을 전부 직접 확인했다. **두 개가 틀렸다.**

| 초안 주장 | 검증 결과 |
|---|---|
| 코드에 flooding이 없다 | ✅ **맞음.** `bfv_context.cpp`의 `Multiply`/`Add`/`Rotate` 모두 OpenFHE 암호문을 그대로 반환 |
| q를 키울 손잡이가 없다 | ❌ **틀림.** `SetScalingModSize`가 BFV에서 동작한다. 이게 핵심 손잡이다 (§4) |
| 논문의 q ≈ 109비트 | ❌ **틀림.** 실제는 **120비트**(60비트 limb × 2). depth-3은 "≈200"이 아니라 **180비트** |
| rebase 필요 | ❌ **해소됨** (§1) |

### 2.1 OpenFHE BFV에서 쓸 수 있는 손잡이 (실측)

```
SetStatisticalSecurity      → DISABLED_FOR_BFVRNS
SetNumAdversarialQueries    → DISABLED_FOR_BFVRNS
SetFirstModSize             → DISABLED_FOR_BFVRNS
SetExecutionMode            → DISABLED_FOR_BFVRNS
SetDecryptionNoiseMode      → DISABLED_FOR_BFVRNS
   (gen-cryptocontext-bfvrns-params.h:64-97)

NOISE_FLOODING_HRA / NOISE_FLOODING_MULTIPARTY / NOISE_FLOODING_DECRYPT
   → BGV/CKKS 전용. BFV 경로에 연결돼 있지 않음.

SetEvalAddCount / SetKeySwitchCount
   → multiplicativeDepth와 상호 배타. 셋 중 하나만 non-zero 허용.
     (bfvrns-parametergeneration.cpp:313에서 예외)
```

**결론: `SetMultiplicativeDepth` + `SetScalingModSize` 둘뿐이고, flooding 연산은 직접 구현해야 한다.**

### 2.2 ⚠️ 핵심 구조 제약 — flooding을 `Piccard::Evaluate`에 넣으면 안 된다

`src/protocol/threshold_piccard.cpp:30`:
```cpp
// Step 1-2: REUSE Piccard's multiply + rotate-and-sum
auto rotated_sum = piccard_.Evaluate(ct_x, ct_y);   // ← 중간 결과!
// ... 이후 마스킹 + degree-k 다항식(깊이 ~15) 평가가 이어짐
```

`Piccard::Evaluate`에 flooding을 넣으면 threshold 경로는 **2^72배로 부풀린 노이즈를
깊이-15 다항식에 통과**시키게 되고 복호는 확실히 깨진다.

수신자에게 나가는 암호문과 중간 결과를 **타입/이름 수준에서 구분**해야 한다 (§5.2).

호출 관계 (전수 확인):

| 호출자 | `Piccard::Evaluate` 용도 | flooding |
|---|---|---|
| `Piccard::Run` (piccard.cpp:96) | 수신자에게 반환 | **필요** |
| `DynamicPiccard` (`: public Piccard`, 상속) | 수신자에게 반환 | **필요** |
| `ThresholdPiccard::Evaluate:30` | **중간 결과** | **금지** |
| `SqrtPiccard::Evaluate` (독립 구현) | 수신자에게 반환 | **필요** |

### 2.3 ⚠️ 벤치마크가 프로토콜을 인라인 복제한다 — 7개 지점

`RunTimedProtocol` 계열은 `Piccard::Evaluate`를 **호출하지 않고** multiply + rotate-and-sum을
직접 재현한다. 라이브러리에만 flooding을 넣으면 **재측정된 모든 시간 수치가 flooding을
누락**한다 — 이 브랜치의 산출물이 통째로 무효가 되는 실패 모드다.

| 파일:행 | 무엇 |
|---|---|
| `benchmarks/bench_piccard.cpp:106` | one-hot rotate-and-sum |
| `benchmarks/bench_comparison.cpp:256` | one-hot |
| `benchmarks/bench_comparison.cpp:529,538` | sqrt (intra-digit, cross-k) |
| `benchmarks/bench_dynamic.cpp:244` | one-hot |
| `benchmarks/bench_threshold.cpp:260` | one-hot (threshold 전단) |
| `benchmarks/bench_onehot_sqrt.cpp:42` | one-hot |
| `benchmarks/bench_onehot_sqrt.cpp:79,94` | sqrt |
| `benchmarks/baseline_engine.h:202` | BCG12/SJ16 베이스라인 — **다른 브랜치 소유, §8에 기록만** |

### 2.4 `src/protocol/piccard_engine.cpp`는 죽은 코드다

CMakeLists의 `PICCARD_FHE_SOURCES`에 없고, hash-seed-crs가 `MinHasher`/`BottomStructure`의
기본 시드를 제거한 뒤로 **컴파일조차 되지 않는다**:
```
$ c++ -fsyntax-only src/protocol/piccard_engine.cpp
error: no matching constructor for initialization of 'piccard::MinHasher'
error: no matching constructor for initialization of 'piccard::BottomStructure'
```
이름과 달리 `tests/unit/test_piccard_engine.cpp`는 `protocol/piccard.h`를 포함해 `Piccard`를
테스트한다. **이 파일에는 flooding을 넣지 말 것.** §8에 기록만 한다.

---

## §3. 측정 결과 (2026-07-25, OpenFHE 1.5.0, macOS arm64)

측정 방법: 복호 노이즈 = `‖(c₀ + c₁·s) − Δ·m‖_∞`를 CRT 역보간으로 정확히 계산.
프로브 소스는 `{scratchpad}/probe_{modulus,noise,table,time,sqrt}.cpp`.

### 3.1 현재 파라미터의 flooding 여유

| 설정 | N | log q | limbs | t | **B_eval** | log(Δ/2) | **수용 λ_s** |
|---|---|---|---|---|---|---|---|
| Piccard (128,64) d1 | 8192 | 120 | 2 | 65537 | 77.6 | 103.0 | **25.4** |
| Piccard (256,256) d1 | 65536 | 120 | 2 | 786433 | 83.2 | 99.4 | **16.2** |
| Piccard⁺ (256,64) d3 | 8192 | 180 | 3 | 65537 | 135.5 | 163.0 | **27.5** |

경험적 확인 (128,64): 2¹⁰⁰ flooding까지 match count 정확 복원, 2¹⁰⁴에서 붕괴.

**모든 행이 production plaintext modulus로 측정됐다.** 검토 과정에서 sqrt 행의 t가 한때
12289로 잘못 적혀 있었다(다른 프로브의 컨텍스트 전용 행에서 전사된 오류). 실제 측정은
`FindPlaintextModulus(256, 2·8192) = 65537`을 썼고, 이는 프로브가 출력한
`logΔ = 164.0 = 180 − log₂(65537) = 180 − 16`으로 확인된다. t가 12289였다면 logΔ는 166.4로
나왔을 것이다. **따라서 §4의 "4.1비트 부족"은 유효하며, production 파라미터에서 더 나빠지지 않는다.**

**λ=128이 불가능한 이유 (응답서에 그대로 쓸 수치):**
(128,64)에서 λ=128 수용에 필요한 log q ≥ 77.6 + 128 + 2 + 16 = **223.6 > 218 = maxQ(8192)**.
→ N=16384 필요, 시간 2배. **리뷰어의 직관이 정확히 맞다.**
반면 km=2¹⁶(N=65536)은 maxQ=1747이라 λ=128도 들어간다. 문제는 **작은 km 설정**이다.

### 3.2 N은 2배가 되지 않는다 — 가장 중요한 미지수의 답

N은 log q가 아니라 **슬롯 요구량 km**이 결정하고, log q는 보안 상한보다 한참 아래다.

| N | 현재 log q | maxQ (128-classic, ternary) | 여유 |
|---|---|---|---|
| 8192 | 120 | **218** | 98 |
| 16384 | 120 | 438 | 318 |
| 32768 | 120 | 881 | 761 |
| 65536 | 120 | 1747 | 1627 |
| 131072 | 120 | 3523 | 3403 |

### 3.3 손잡이 스윕 — limb를 쪼개면 여유가 생긴다

지배적 노이즈 항은 HYBRID key-switching이고 **limb 크기에 비례**한다. 같은 q를 더 작은
limb로 쪼개면 B_eval이 내려간다.

**Piccard (one-hot), N=8192 고정:**

| depth | sms | log q | ct | B_eval | 수용 λ_s |
|---|---|---|---|---|---|
| 1 | 60 (현재) | 120 | 240 KB | 77.6 | 25.4 |
| 2 | 40 | 120 | **240 KB (동일)** | 59.2 | 43.8 |
| 2 | 50 | 150 | 300 KB | 69.1 | 63.9 |
| 2 | **60** | **180** | **360 KB** | **79.7** | **83.3** ✅ |
| 3 | 60 | 180 | 360 KB | 78.4 | 84.6 |

**Piccard (256,256), N=65536:** d2/sms60 → log q 180, B_eval 83.1, 수용 **76.3** ✅

**Piccard⁺ (base-√m), N=8192 고정:**

| depth | sms | log q | ct | B_eval | 수용 λ_s |
|---|---|---|---|---|---|
| 3 | 60 (현재) | 180 | 360 KB | 135.5 | 27.5 |
| 4 | 45 | 180 | **360 KB (동일)** | 105.2 | 57.8 |
| 4 | **50** | 200 | 400 KB | 115.1 | **67.9** ⚠️ |
| 4 | 60 | 240 | — | — | ✗ **OpenFHE 거부** (N=16384 요구) |

### 3.4 시간 영향 (k=128, m=64, 5회 평균, ms)

| 설정 | Encrypt | Compute | **Flood** | Decrypt | 합 |
|---|---|---|---|---|---|
| d1/sms60 (현재, flooding 없음) | 5.97 | 13.09 | — | 0.33 | 19.4 |
| d2/sms50 + flooding | 6.36 | 17.69 | **0.49** | 0.39 | 24.9 |
| d2/sms60 + flooding | 6.39 | 17.84 | **0.68** | 0.40 | 25.3 |

**flooding 연산 자체는 전체의 3% 미만.** 비용은 전부 limb 1개 추가에서 온다 (**+28%**).
**2배가 아니다.**

---

## §4. ~~열려 있는 위험~~ → **해소됨 (Phase 0, 2026-07-25)**

**결론: 3개 회로 × 18개 (회로, 링 차원) 조합 전부가 λ_s=64 + margin 8에서 실현 가능하다. N은 어디서도
커지지 않는다. (a)/(b)/(c) 결정은 필요 없다.**

원인은 프로브의 스윕 구멍이었다. §3.3의 sqrt 행은 `sms ∈ {45,50,55,60}`만 봤는데,
**`sms=40`이 결정적**이었다: log q 200에서 limb를 40비트로 쪼개면 5-limb가 되고
B_eval이 **115.19 → 96.02로 19.2비트** 떨어진다. 총 모듈러스는 그대로다.

Phase 0 캘리브레이션 결과 (`bench_noise --sweep --reps=5`, 1,740행, 30분 38초).
표는 `scripts/results/calibration/TABLE.md`, 생성기는 `scripts/make_calibration_table.py`:

| circuit | 요청 N | 자연 depth | 자연 N | mult_depth | sms | log q | limbs | B_eval | 여유 | ct (KB) |
|---|---|---|---|---|---|---|---|---|---|---|
| onehot | 1024 | 1 | 1024 | 3 | 52 | 156 | 3 | 67.54 | 0.86 | 49 |
| onehot | 2048 | 1 | 2048 | 4 | 40 | 160 | 4 | 56.43 | 15.97 | 129 |
| onehot | 4096 | 1 | 4096 | 3 | 40 | 160 | 4 | 58.12 | 12.58 | 257 |
| onehot | 8192 | 1 | 8192 | 3 | 40 | 160 | 4 | 60.00 | 10.00 | 513 |
| onehot | 16384 | 1 | 16384 | 3 | 40 | 160 | 4 | 61.17 | 8.83 | 1025 |
| onehot | 32768 | 1 | 32768 | 3 | 40 | 160 | 4 | 63.06 | 6.94 | 2049 |
| onehot | 65536 | 1 | 65536 | 3 | 40 | 160 | 4 | 64.40 | 2.00 | 4098 |
| onehot | 131072 | 1 | 131072 | 3 | 40 | 160 | 4 | 65.82 | 0.58 | 8194 |
| sqrt | 1024 | 3 | 1024 | 5 | 40 | 200 | 5 | 91.73 | 20.67 | 82 |
| sqrt | 2048 | 3 | 2048 | 5 | 40 | 200 | 5 | 92.92 | 19.48 | 162 |
| sqrt | 4096 | 3 | 4096 | 4 | 40 | 200 | 5 | 94.41 | 16.29 | 322 |
| sqrt | 8192 | 3 | 8192 | 4 | 40 | 200 | 5 | 96.02 | 13.98 | 642 |
| sqrt | 16384 | 3 | 16384 | 4 | 40 | 200 | 5 | 96.31 | 13.69 | 1282 |
| sqrt | 32768 | 3 | 32768 | 4 | 40 | 200 | 5 | 97.26 | 12.74 | 2562 |
| threshold | 1024* | 7 | 1024 | 9 | 45 | 315 | 7 | 211.65 | 15.75 | 114 |
| threshold | 2048 | 9 | 2048 | 11 | 40 | 360 | 9 | 269.24 | 3.16 | 290 |
| threshold | 8192 | 9 | 16384 | 11 | 54 | 432 | 8 | 335.24 | 6.76 | 2050 |
| threshold | 8192 | 15 | 32768 | 17 | 45 | 630 | 14 | 531.78 | 8.22 | 7171 |

(* TOY 행. `ct`는 **실제 직렬화 크기**이며 이론값 `2N⌈log q⌉`보다 ~1.6배 크다 — §8-5 참조.)

**표의 키는 `(circuit, 요청 N, 자연 depth)`이다.** `(circuit, N)`만으로는 threshold k=32와
k=128을 구분할 수 없다 — 둘 다 요청 N이 8192인데 자연 depth가 9/15로 갈리고 자연 N이
16384/32768로 달라진다. 세 항목 모두 컨텍스트 생성 전에 `Validate()`가 아는 값이다.

`B_eval`은 all_match / no_match / random 세 패턴 × `--reps`회 반복의 **최악값**이다.
"여유"는 margin 8을 이미 반영한 뒤 남은 비트다.

⚠️ **셀당 1회 측정은 부족하다.** 관측된 패턴 간 편차는 최대 **4.00비트**(468개 3패턴 셀 중
91개가 2비트 초과)로, 초판 계획이 적었던 "~1.8비트"는 과소 서술이었다. 실제로 onehot N=2048은
1회 측정에서 여유 0.04비트로 "실현 가능"이었으나 `--reps=5`에서 **1.34비트 부족**으로 뒤집혔다.
즉 단일 측정은 실현 가능 판정을 잘못 내린다. 하네스는 `--reps`로 신선한 암호화 난수 하에
반복 측정해 최악값을 취한다(KeyGen은 공유하므로 큰 N에서도 비용이 작다). **캘리브레이션 표는
`--reps=5` 이상으로 생성할 것.**

**threshold의 N 증가는 flooding 탓이 아니다.** k=32/STD128은 flooding 없이 자연 depth 9에서
이미 8192 → 16384로 커진다(깊은 모듈러스 체인 때문). 그래서 판정 기준을 "슬롯 요구 N"이
아니라 "회로의 자연 N"으로 잡아야 하며, 하네스가 매 설정마다 자연 구성을 먼저 측정해
기준선으로 삼는다.

**0-5 결과 및 step 10 판정 기준 확정:** OpenFHE가 `MinRingDimForSecurity`보다 **작은** N을
고른 경우는 **0건**이다. 그러나 **더 큰** N을 고른 경우는 1,740행 중 **315건**이고
(그중 회로의 자연 N까지 넘어선 것이 **180건** — 새 판정 기준이 실제로 거르는 수), 여기에는
flooding 여유를 전혀 요구하지 않은 자연 구성(threshold STD128 k=32: 8192→16384,
k=128: 8192→32768)이 포함된다.

따라서 §5.2 step 10을 "예측과 정확히 일치하지 않으면 throw"로 두면 **모든 STD128 threshold
설정에서 오탐**이 난다. 판정 기준은 다음으로 확정한다:

> 예측 `ring_dim`은 **하한**이다. 실제 `ring_dim`이 캘리브레이션 표의
> `ring_dim_natural`(그 회로가 flooding 없이도 필요로 하는 차원)을 **초과**할 때만 throw한다.

이를 위해 캘리브레이션 표는 `ring_dim_natural`을 데이터로 싣는다.

**캘리브레이션 표의 키는 §4에 적은 대로 `(circuit, ring_dim_requested, natural_mult_depth)`다.**

---

## §4-old. (기록용) 당시의 위험 서술 — Piccard⁺ @ λ_s=64

λ_s=64 + margin 8 = **72비트**가 필요한데 Piccard⁺의 최선 측정치가 **67.9** — **4.1비트 부족**.
`sms=60`은 log q 240 > 218이라 OpenFHE가 거부한다.

**Phase 0에서 반드시 해소할 것.** 탐색 순서:
1. `sms ∈ {51,52,...,58}` 세밀 스윕 (d4). log q = 4×sms ≤ 218 → **sms ≤ 54**.
2. `depth 5` + `sms ∈ {40,...,43}` (log q = 5×sms ≤ 218 → sms ≤ 43).
3. 현재 측정치는 **단일 입력**이다. 최악 입력(일치 0 / 일치 k / 랜덤)에서 B_eval이 몇 비트
   올라갈 수 있으므로 여유는 더 좁아질 수 있다.

**"4.1비트"의 신뢰도:** §3.1에 적었듯 sqrt 측정은 production t(=65537)로 이뤄졌고 logΔ=164.0이
이를 뒷받침한다. 부족분이 t 선택 때문에 더 크지는 않다. 남은 불확실성은 위 3번(최악 입력)뿐이다.
Phase 0-2의 "라이브러리 API로만 측정" 규칙이 production 모듈러스 선택을 구조적으로 보장하므로,
**Phase 0의 재측정값이 §3의 수치를 대체한다** — §3에 앵커링하지 말 것.

**그래도 72를 못 넘기면** 아래 중 선택 — 이 결정은 사용자에게 물을 것:
- (a) Piccard⁺만 λ_s=40 (margin 8 → 48비트 필요, d4/sms50의 67.9로 충분)
- (b) Piccard⁺만 N=16384 수용 (시간 2배 — 논문 결론에 영향)
- (c) margin을 4로 축소 (68 ≥ 67.9, 여유 0.1비트 — **권장하지 않음**)

one-hot 경로는 λ_s=64에 여유가 충분하다 (83.3 / 76.3).

**threshold 경로는 아직 미측정이다.** 초안은 "두 브랜치 머지 후 확인"이라고 했지만
`threshold_piccard.cpp`는 **이 브랜치에서 이미 컴파일된다** → **Phase 0에서 측정 가능하고,
측정해야 한다.** 예상: k=128 → depth 15 → N=32768, log q 600, maxQ 881(281비트 여유).
threshold는 깊이를 전부 소진하는 회로라 여유가 depth-1처럼 빠듯할 것으로 보이며,
그 경우 limb 1개 추가(depth 16 → log q 660 < 881)로 해결될 전망이다. **측정으로 확정할 것.**

---

## §5. 설계

### 5.1 캘리브레이션 표 — B_eval은 오프라인 상수

서버에 비밀키가 없으므로 B_eval은 런타임 측정 불가(§0). 따라서:

```cpp
// include/util/params.h
enum class Circuit { OneHot, Sqrt, Threshold };

// 캘리브레이션 1행. Phase 0 하네스가 생성한다.
struct NoiseCalibration {
    Circuit  circuit;
    uint32_t ring_dim;
    uint32_t mult_depth;
    uint32_t scaling_mod_size;
    uint32_t eval_noise_bits;   // 측정된 B_eval의 ceil
    uint32_t log_delta;         // 측정 시점의 log2(Δ) — 예측용
};
```

B_eval은 `k`,`m`에 직접 의존하지 않는다 — `N`(회전 횟수 log₂N)과 limb 구성이 지배한다.
`t = FindPlaintextModulus(k, 2N)`도 벤치마크 스윕 범위(k ≤ 512) 전체에서 N만의 함수로
붕괴한다(첫 소수 후보가 이미 512를 넘는다). 따라서 `(circuit, N, depth, sms)` 키로 충분하다.

⚠️ **표는 반드시 TOY 링 차원을 포함해야 한다.** 테스트 18개 중 **17개가
`SecurityLevel::TOY`**를 쓴다(`grep -rn "SecurityLevel::" tests/`). fail-closed throw와
"항상 on"이 결합하면, 표가 STD128만 덮을 경우 **`Validate()`가 던져 13/13이 전부 깨진다** —
§7-1 완료 기준과 정면 충돌이다. TOY는 `HEStd_NotSet`이라 maxQ 제약이 없어 q를 자유롭게
키울 수 있지만, **행이 없으면 못 쓴다.**

필수 커버리지:

| 보안 레벨 | 커버할 N | 정책 |
|---|---|---|
| TOY | 1024, 2048, 4096 (+ 테스트가 실제로 만드는 값) | **필수** — 없으면 테스트가 깨진다 |
| STD128 | 8192, 16384, 32768, 65536, 131072 | **필수** — 논문 수치 전부 |
| STD192 / STD256 | — | **fail-closed throw를 의도된 동작으로 명시**하고 §8에 한계로 기록. 논문은 STD128만 보고한다 |

**TOY는 depth ≥ 2로 올라갈 가능성이 높다** (N=1024, log q 120이면 가용 예산이 ~32비트에
불과해 λ_s=64를 못 담는다). 따라서 **Phase 3에서 `tests/unit/test_params.cpp`의 기존
`mult_depth` 관련 단언이 갱신 대상이다** — 이걸 회귀로 오해하지 말 것.

캘리브레이션 표 주석에는 **생성 커밋 해시와 OpenFHE 버전(현재 1.5.0)을 함께** 남긴다.
B_eval은 구현 의존적이라 OpenFHE 업그레이드가 표를 조용히 무효화한다.

### 5.2 예측 → 검증 2단계

`Validate()`는 컨텍스트가 생기기 전에 파라미터를 정해야 하는데 실제 log Δ는 컨텍스트가
있어야 안다. 따라서 **예측하고, 만든 뒤 검증한다.**

```
PiccardParams::Validate()                 [예측]
  1. feature_dim / ring_dim / plaintext_mod  — 현행 로직 유지
  2. 회로별 기본 mult_depth                   — 현행 로직 유지
  3. 표에서 (circuit, ring_dim) 후보를 뽑아,
     eval_noise_bits + lambda_stat + flood_margin_bits + 2 <= log_delta
     를 만족하는 것 중 **log q가 가장 작은** 것을 선택
  4. mult_depth / scaling_mod_size / eval_noise_bits 확정
  5. 선택된 조합이 ring_dim을 키우면 → throw (N 증가는 조용히 넘어가지 않는다)
  6. 후보가 없으면 → throw, 캘리브레이션 하네스 실행 방법을 메시지에 담을 것

BFVContext::Initialize()                  [검증]
  7. scaling_mod_size != 0 이면 SetScalingModSize(scaling_mod_size)
  8. 컨텍스트 생성 후 **실제** log2(q), log2(t)로 log Δ 재계산
  9. lambda_stat + flood_margin_bits + eval_noise_bits + 2 <= log_delta_actual
     아니면 throw
 10. cc_->GetRingDimension() 이 예측과 다르면 throw
```

`params.h` 신규 필드:
```cpp
uint32_t lambda_stat        = 64;  // 통계적 보안 파라미터 λ_s
uint32_t flood_margin_bits  = 8;   // B_eval 과소평가에 대한 안전 마진
uint32_t scaling_mod_size   = 0;   // 0 = OpenFHE 기본(60); Validate()가 채운다
uint32_t eval_noise_bits    = 0;   // 파생: 캘리브레이션된 B_eval
```

**마진의 의미:** smudging lemma는 `B_flood / B_eval_실제 ≥ 2^λs`를 요구한다. B_eval을
과소평가하면 **보안이 깎인다.** 따라서 마진은 B_eval 쪽을 부풀린다:
```
log2(B_flood) = eval_noise_bits + flood_margin_bits + lambda_stat
```

### 5.3 flooding 연산

```cpp
// bfv_context.h
// 수신자에게 나가는 암호문에만 적용한다. 중간 결과에 적용하면 이후 연산에서
// 복호가 깨진다 — §2.2 참조.
lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
Flood(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;
```

구현 (스파이크에서 동작 검증 완료, 0.35–0.68 ms):
1. `B_bits = eval_noise_bits + flood_margin_bits + lambda_stat`
2. 각 계수마다 `[-2^B_bits, 2^B_bits - 1]` **균등 정수**를 뽑는다 (구현이 쓰는 구간.
   폭이 정확히 2의 거듭제곱이라 비트 단위로 정확히 균등하다)
3. RNS 잔여류로 변환해 `DCRTPoly`(COEFFICIENT)를 만들고 `SetFormat(EVALUATION)`
4. `out->GetElements()[0] += noise` (사전에 `Clone()`)

**난수는 반드시 `lbcrypto::PseudoRandomNumberGenerator::GetPRNG()`** (CSPRNG).
`std::mt19937_64` 금지 — 프로브에서만 재현성 때문에 썼다. hash-seed-crs가 도입한 CRS
시드는 **공개 파라미터**이고 flooding 난수는 **서버의 비밀 난수**다. 절대 연결하지 말 것.

균등 분포를 쓰는 이유: smudging lemma가 균등 분포로 진술돼 있고, 통계적 거리
`≤ B_eval/B_flood = 2^-λs`가 곧바로 나온다. 이산 가우시안은 σ가 클 때 샘플러가 느리고
논증이 번거롭다.

### 5.4 Evaluate 분리 — 안전한 기본값, 명시적 우회

```cpp
// piccard.h
// 수신자에게 반환할 결과. flooding이 적용된다.
Ciphertext Evaluate(ct_x, ct_y) const;

// flooding이 적용되지 않은 중간 결과. 이 위에 추가 동형 연산을 쌓는
// 호출자만 사용한다(ThresholdPiccard). 이 암호문을 그대로 수신자에게
// 보내면 보안 증명이 성립하지 않는다.
Ciphertext EvaluateRaw(ct_x, ct_y) const;
```
`Evaluate() = Flood(EvaluateRaw())`.

기본이 안전하고, 우회하려면 이름을 명시해야 한다. `ThresholdPiccard::Evaluate`는
`EvaluateRaw`를 쓰고 **다항식 평가 후에** `Flood`를 호출한다.

`DynamicPiccard`는 `Evaluate`를 오버라이드하지 않으므로(비가상, `dynamic_piccard.h:12`)
flooding된 버전을 자동으로 상속한다 — 변경 불필요.

`EvaluateRaw`는 **public + 문서화**로 둔다. `ThresholdPiccard`는 `Piccard`를 상속이 아니라
멤버로 보유하므로(`threshold_piccard.h`) protected로 내리면 friend 선언이 필요해지고,
벤치마크가 중간 결과를 계측할 길도 막힌다. 현재 소비자는 2개뿐이고 §5.4 주석이 계약을
명시하므로 public이 타당하다.

---

## §6. 실행 순서

### Phase 0 — 캘리브레이션 하네스 (다른 모든 것의 선행)

**0-0. 손잡이 배관 선행 이식 (이것 없이는 Phase 0을 시작할 수 없다).**
Phase 0-2는 `sms` 격자를 **라이브러리 API로** 스윕해야 하는데, 지금
`params.h`에는 `scaling_mod_size` 필드가 없고 `BFVContext::Initialize()`
(`bfv_context.cpp:11-68`)는 `SetScalingModSize`를 호출하지 않는다. 따라서
**최소 배관만 Phase 1/2에서 앞당겨 가져온다:**
- `params.h`에 `uint32_t scaling_mod_size = 0;` 필드만 추가 (예측 로직은 Phase 1에 남긴다)
- `Initialize()`에 `if (scaling_mod_size) bfv_params.SetScalingModSize(scaling_mod_size);`
  한 줄만 추가 (§5.2의 step 7만; 검증 로직 8–10은 Phase 2에 남긴다)

**0-1.** `BFVContext`에 캘리브레이션 전용 비밀키 접근자 추가.
```cpp
// 캘리브레이션/테스트 전용. 프로토콜에서 수신자의 비밀키는 수신자를 떠나지 않는다.
// 복호 노이즈 측정은 비밀키 없이는 불가능하므로 이 접근자가 존재한다.
const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& GetSecretKeyForCalibration() const;
```

**0-2.** `benchmarks/bench_noise.cpp` 신설 + CMakeLists 등록.
- `MeasureNoiseBits(ct, sk, Q, t)` — `{scratchpad}/probe_noise.cpp:NoiseBits` 이식
- 회로 3종(one-hot / sqrt / threshold)을 **라이브러리 API로** 실행해 측정
  (인라인 복제 금지 — §2.3의 실패 모드를 하네스에서 반복하지 않는다)
- **최악 입력 스윕**: 일치 0 / 일치 k / 랜덤 one-hot / 랜덤 sqrt
- `(circuit, N, depth, sms)` 격자 스윕 → 캘리브레이션 표 CSV 출력.
  **§5.1의 커버리지 표대로 TOY 링 차원을 반드시 포함할 것**

**0-3.** ⚠️ **Piccard⁺ λ_s=64 세밀 스윕** (§4). 여기서 결론이 안 나면 진행 중단하고
사용자에게 (a)/(b)/(c) 선택을 물을 것.

**0-4.** ⚠️ **threshold 경로 B_eval 측정** (§4). k ∈ {32, 128}, N=32768.

**0-5.** `MinRingDimForSecurity()` 스팟 체크. 이 상수들은 주석(`params.cpp:20-22`)이
명시하듯 **depth 1 기준**이다. depth 2–4에서 OpenFHE가 8192보다 작은 ring_dim을 고를 수
있고, 그러면 §5.2 step 10의 "예측과 다르면 throw"가 오탐을 낸다. 실제 선택값을 확인하고
step 10의 판정 기준(정확히 일치 vs 예측 이상)을 확정할 것.

**Phase 0 완료 기준:** 3개 회로 전부에 대해 λ_s=64 + margin 8을 만족하는
(depth, sms) 조합이 **N을 키우지 않고** 존재함을 수치로 보였거나, 불가능한 회로에 대해
사용자 결정을 받았다. TOY 행이 표에 있다.

### Phase 1 — λ_s 파라미터화 (`include/util/params.h`, `src/util/params.cpp`)

- §5.2의 신규 필드 4개 추가
- `NoiseCalibration` 표를 Phase 0 결과로 채운다 (출처 커밋 해시를 주석에 남길 것)
- `Validate()` / `ValidateSqrt()`에 §5.2 예측 로직 1–6 추가
- **`threshold_mode`의 depth 계산(params.cpp:72-97)은 건드리지 말 것** — Paterson-Stockmeyer
  계산이 `EvalPolyBFV`의 step-size와 정확히 일치해야 한다. flooding 여유는 `scaling_mod_size`와
  `mult_depth` **가산**으로만 확보한다

### Phase 2 — flooding 연산 (`include/fhe/bfv_context.h`, `src/fhe/bfv_context.cpp`)

**완료 (2026-07-26, Task 1–5, 커밋 `fc82fcf..f3033f2`).** 아래 항목 전부 구현되고 `ctest`
13/13으로 검증됨: `BFVContext::Flood()`(§5.3, 재랜덤화 포함), `Initialize()` 검증 로직 7–10,
`Piccard`/`SqrtPiccard`/`ThresholdPiccard`의 `Evaluate`/`EvaluateRaw` 분리, `bench_noise.cpp`의
raw 경로 전환. 원 계획에 없던 확장(`SqrtPiccard`/`ThresholdPiccard`에도 `EvaluateRaw` 추가)은
Task 5에서 이뤄졌고 §8-12에 기록. 비용 측정과 재랜덤화 결정의 귀결은 §8-11, §8-13 참조.

- `Initialize()`에 §5.2의 검증 로직 7–10 추가
- `Flood()` 구현 (§5.3)
- 적용 지점:

| 파일 | 변경 |
|---|---|
| `src/protocol/piccard.cpp` | `Evaluate` → `EvaluateRaw` 로 개명, `Evaluate = Flood(EvaluateRaw)` 신설 |
| `include/protocol/piccard.h` | 두 메서드 선언 + §5.4 주석 |
| `src/protocol/threshold_piccard.cpp:30` | `piccard_.Evaluate` → `piccard_.EvaluateRaw` |
| `benchmarks/bench_noise.cpp` (RunThreshold) | 정확성 검사용 `base.Evaluate` → `base.EvaluateRaw`. 그대로 두면 검사가 flooding된 노이즈를 재게 된다 |
| `src/protocol/threshold_piccard.cpp:38` | `EvalPolyBFV(...)` 결과를 `Flood()`로 감쌈 |
| `src/protocol/sqrt_piccard.cpp:94` | `return result;` → `return bfv_->Flood(result);` |
| `dynamic_piccard` | **변경 없음** — `Piccard::Evaluate` 상속으로 자동 적용 |
| `src/protocol/piccard_engine.cpp` | **손대지 말 것** — 죽은 코드 (§2.4) |

### Phase 3 — 회귀 테스트

- `tests/unit/test_bfv_context.cpp`: `Flood`가 복호 결과를 바꾸지 않음 / 노이즈가
  실제로 `B_bits` 부근까지 올라감 / 예산 초과 파라미터에서 `Initialize()`가 throw
- `tests/unit/test_params.cpp`: λ_s=64와 λ_s=40이 서로 다른 (depth, sms)를 고르고,
  **둘 다 ring_dim을 키우지 않음**
- `tests/unit/test_piccard_engine.cpp`(=`Piccard`), `test_threshold_engine.cpp`,
  `test_sqrt_piccard.cpp`, `test_dynamic_engine.cpp`: flooding 하에서 결과 정확성
- **캘리브레이션 고정 테스트**: 측정 B_eval **≤** 표의 `eval_noise_bits`.
  부등호 방향이 중요하다 — 측정값이 표를 넘으면 flooding이 실제 노이즈를 덮지 못해
  λ_s가 조용히 깎인다. OpenFHE 업그레이드나 그리드 변경이 **실패로 드러나야** 한다.
  표가 낡으면 실패하도록 — 이게 §5.1 전체를 지탱하는 안전장치다
- `ThresholdPiccard`가 중간 결과에 flooding하지 않음을 보장하는 테스트
  (깊이-15 경로가 복호되는 것 자체가 증거)

### Phase 4 — 벤치마크 배관 (§2.3 — 빠뜨리면 이 브랜치 전체가 무효)

- `benchmark_utils.h`: `BenchmarkResult`에 **말미 추가** (기존 열 위치 불변 — 확립된 규약)
  ```
  phase_flood_ms, flood_lambda_stat, flood_eval_noise_bits,
  flood_margin_bits, flood_noise_bits, scaling_mod_size
  ```
  `WriteHeader()` / `WriteRow()`도 말미에 추가. **`benchmark_utils.h`는 공유 파일이므로
  최소 편집 원칙**(`00_shared_context.md`)
- §2.3의 인라인 지점에 flooding 단계 추가 + `phase_flood_ms` 계측, `br.time_ms` 합산에 포함.

⚠️ **flooding은 "나열된 행"이 아니라 "그 벤치마크의 프로토콜 출구"에 넣는다.**
`§2.3의 7개 지점에 추가`를 문자 그대로 rotate-and-sum 직후에 넣으면 threshold 경로에서
§2.2의 실패 모드를 그대로 재현한다. 지점별로 명시한다:

| 파일 | flooding 위치 |
|---|---|
| `bench_piccard.cpp:106` | rotate-and-sum 직후 (여기가 출구) |
| `bench_comparison.cpp:256` | rotate-and-sum 직후 |
| `bench_comparison.cpp:538` | cross-k sum 직후 (sqrt 출구) |
| `bench_dynamic.cpp:244` | rotate-and-sum 직후 |
| `bench_onehot_sqrt.cpp:42` | rotate-and-sum 직후 |
| `bench_onehot_sqrt.cpp:94` | cross-k sum 직후 (sqrt 출구) |
| `bench_threshold.cpp` | **rotate-and-sum(:261)이 아니라 Phase 7 `EvalPolyBFV`(:275) 직후** |

⚠️ **`bench_threshold.cpp`는 `tkde-major/threshold-fpfn` 소유다**
(`00_shared_context.md:48`, `INTEGRATION_NOTES.md`의 OUT-OF-SCOPE에서 재확인).
`남의 브랜치가 소유한 파일은 건드리지 마라` 규칙이 적용된다. **기본 방침: 이 브랜치에서
편집하지 말고 §8에 요구사항으로 기록한다** — flooding은 Phase 7 직후에 들어가야 하고
`phase_flood_ms` 열이 필요하다는 것. 편집이 불가피하다고 판단되면 **사용자에게 먼저
확인**하고, 승인 시 최소 편집 + §8에 조율 메모를 남긴다.

**편집이 불필요한 벤치마크** (라이브러리 API를 거치므로 flooding이 자동 적용되고,
기존 compute/evaluate 구간 시간에 포함된다 — 빠뜨린 게 아니다):
`bench_crossover.cpp:110,122` (`engine.Run`), `bench_sqrt_comparison.cpp:65` (`engine.Evaluate`).
- `ct_size_bytes`는 이미 `CiphertextSizer::GetSerializedSize`(실제 직렬화 크기)를 쓴다 —
  limb 증가가 자동 반영된다. **논문 표의 이론값 `2N⌈log q⌉`와는 다르다** (§8-5)
- `scripts/summarize_results.py`: flooding 열을 표에 노출. **공유 파일, 최소 편집.**
  INTEGRATION_NOTES에 이 파일 편집이 ≤40행 예산이라는 선례가 기록돼 있다

### Phase 5 — 논문 산출물

- **모듈러스 산정 표** (P1-3 요구 산출물): 회로별로
  `log q = log t + B_eval + λ_s + margin + 여유` 분해를 보이는 표
- `appendix.tex:78-79` 수정: λ → λ_s, smudging lemma 명시, 통계적 거리 2^-λ_s 진술
- **residual leakage 문단**: flooding 미적용 시 평가 노이즈에 남는 상대 입력 정보
- ⚠️ **`appendix.tex`의 수신자 뷰 시뮬레이션이 재랜덤화를 요구하는지 확인할 것.**
  §5.3은 c₀에 smudging 노이즈만 더한다. 증명이 결과 암호문의 **재랜덤화**
  (신선한 `Enc_pk(0)` 덧셈)까지 요구한다면 `Flood()`가 그것도 해야 한다.
  지금 추가하면 싸고, 응답서가 나간 뒤에 고치면 비싸다. 표준 semi-honest 논증
  (입력 암호문은 RLWE 하에서 의사난수, 회로는 공개)이면 c₀ smudging으로 충분하다
- `piccard.tex`의 log q = 109 → 실측값 정정 (§8-1)
- **`ref.bib` 신규 항목 필요**: 현재 `Gen09`만 있다. smudging lemma 인용
  (Asharov–Jain–López-Alt–Tromer–Vaikuntanathan–Wichs, EUROCRYPT 2012)과
  통계적 보안 파라미터 40–64비트 관행의 근거를 추가할 것

---

## §7. 완료 기준

1. `cmake --build build -j8` 클린, `ctest` 전부 통과 (13개 + 신규).
   **TOY 테스트가 깨지지 않았다** — 깨졌다면 캘리브레이션 표에 TOY 행이 없는 것이다 (§5.1)
2. 3개 회로 모두 λ_s=64에서 flooding이 적용되고 복호가 정확하다
3. **어떤 설정에서도 `ring_dim`이 flooding 때문에 커지지 않았다** (테스트로 고정)
4. `lambda_stat`을 40으로 바꾸면 파라미터가 자동으로 내려가고 전부 통과한다
5. **이 브랜치가 편집한** 벤치마크 CSV에 flooding 열이 있고 `phase_flood_ms`가 0이 아니다.
   `bench_threshold.cpp`는 threshold-fpfn이 §8-8을 처리할 때까지 이 열이 없는 것이 정상이다
6. **정확도(match count)가 flooding으로 바뀌지 않았다.** INTEGRATION_NOTES는 hash-seed-crs의
   Phase 4 정확도 수치를 **최종**으로 선언했다. TOY/STD128 스팟 체크에서 match count가
   flooding 전후로 동일함을 확인할 것 — 이 수치가 움직이면 그 브랜치의 결론이 무효가 된다
7. 모듈러스 산정 표가 생성된다
8. **전체 재측정은 하지 않는다** — 다른 브랜치가 아직 안 들어왔다 (`00_shared_context.md`)

---

## §8. 통합 시 기록 사항 (여기서 고치지 말 것)

1. **논문 log q 오기**: 109 → 실제 **120** (depth 1), 200 → 실제 **180** (depth 3).
   `piccard.tex:1347`의 "약 1.7MB" → 실제 1.875MB. `tbl:sqrt_comparison`의 437KB → 480KB 등
   **모든 암호문 크기가 ~10% 과소 기재**.
2. **`tbl:sqrt_comparison`의 N=4096 @ depth 3은 128비트 보안에서 불가능**:
   depth 3은 log q 180이 필요하고 maxQ(4096)=109. 실측 **N=8192**.
   46% / 23% 절감 주장 재계산 필요. — sqrt/benchmark 브랜치 소유.
3. **threshold × flooding**: k=128 → depth 15 → N=32768, log q 600, maxQ 881 → **281비트 여유**
   (limb 4개분). depth 16이어도 660으로 안전. **상한을 넘지 않는다.**
   B_eval은 Phase 0-4에서 측정 — 결과를 여기에 갱신할 것.
4. **`src/protocol/piccard_engine.cpp`는 죽은 코드**이고 컴파일되지 않는다 (§2.4).
   삭제하거나 CMakeLists에 복구하는 결정이 필요하다.
5. **통신량 표의 기준 불일치**: 논문은 이론값 `2N⌈log q⌉`를 쓰는데 실제 직렬화 크기는
   **limb 개수**에 비례한다. d2/sms40은 이론상 현재와 같지만 직렬화하면 1.5배다.
   논문 표를 실측 `ct_size_bytes` 기준으로 옮길지 결정 필요.
6. **`baseline_engine.h:202`의 rotate-and-sum**에는 flooding이 없다. BCG12/SJ16 베이스라인도
   같은 보안 모델로 비교하려면 동등한 처리가 필요하다 — `implement-bcg12`/`implement-sj16` 소유.
7. `MinRingDimForSecurity()`가 계산한 `ring_dim`을 `bfv_context.cpp:36-50`이 무시하고
   재계산 후 덮어쓴다 — 중복 로직. 상수는 depth 1 기준이라 depth ≥ 2에서 부정확할 수 있다.
8. **`bench_threshold.cpp`에 flooding 요구사항** (threshold-fpfn 소유): flooding은
   rotate-and-sum이 아니라 **Phase 7 `EvalPolyBFV` 직후**에 들어가야 하고, `phase_flood_ms`
   열이 필요하다. threshold 회로의 B_eval은 Phase 0-4 측정값을 여기에 기입할 것.
9. **`bench_threshold.cpp:409`의 `mult_depth > 21` 가드가 낡았다 (threshold-fpfn 소유).**
   그 가드는 flooding 이전 의미의 `mult_depth`(= 회로의 자연 깊이)를 기준으로 쓰였다. Phase 1
   이후 `mult_depth`는 flooding 여유분만큼 부풀려지므로 가드가 **약 2단계 일찍** 발동한다.

   구체적 손실: threshold STD128 **k=256**(자연 depth 21)은 Phase 1 이전에 `mult_depth=21`로
   가드를 통과해 데이터를 생성했다. 지금은 λ_s=64를 담으려면 확보 depth 22가 필요한데
   22 > 21이라 가드가 거부한다.

   근거 수치 (`scripts/results/calibration/probe_threshold_k256.csv`, `--reps=1 --patterns=match`
   단발 프로브. 캘리브레이션 표 생성에는 쓰이지 않으며 `make_calibration_table.py`가 읽지 않는
   별도 파일이다):

   | 확보 depth | sms | log q | B_eval | 여유(headroom) | λ_s=64+margin 8 = 72 필요 |
   |---|---|---|---|---|---|
   | 21 | 40 | 760 | 709.87 | 33.13 | 부족 |
   | 21 | 45 | 765 | 719.91 | 28.09 | 부족 |
   | 21 | 50 | 800 | 722.41 | 60.59 | 부족 |
   | 21 | 54 | 810 | 732.21 | 60.79 | 부족 |
   | 22 | 45 | 810 | 712.66 | 80.34 | **충분** |
   | 23 | 45 | 855 | 714.98 | 123.02 | **충분** |

   **이 키는 캘리브레이션 표에 없다** — 넣어도 위 가드가 거부해 데이터 포인트가 복구되지
   않으므로 측정하지 않았다. 가드를 `natural_mult_depth` 기준으로 바꾸거나 상한을 올린 뒤
   `bench_noise`의 그리드에 `(256,64)`를 추가하고 재생성하면 복구된다.

   k=512(자연 depth 30)는 Phase 1 이전에도 가드가 거부했으므로 회귀가 아니다.

   depth 30(k=512)은 그 위에 측정 비용도 매우 크다.

   **미보정으로 남은 키 4건** (2026-07-26 기준, `bench_noise --coverage`가 201개 설정을 확인):

   | 키 | 구성 주체 | 처리 |
   |---|---|---|
   | `one-hot / TOY @ N=262144` | `bench_crossover` (256,1024) | skip + WARNING |
   | `one-hot / TOY @ N=524288` | `bench_crossover` (512,1024) | skip + WARNING |
   | `threshold / STD128 @ (16384, 21)` | `bench_threshold` k=256 | skip (위 가드가 어차피 거부) |
   | `threshold / STD128 @ (32768, 30)` | `bench_threshold` k=512 | skip (Phase 1 이전에도 거부) |

   앞의 둘은 TOY 전용 대형 링이라 측정 시간에 비해 얻는 것이 없어 fail-closed로 둔다.
   `bench_crossover`는 이제 해당 셀을 건너뛰고 나머지 23개를 정상 처리한다(실행 확인).

   **미보정 키는 `bench_noise --coverage`로 확인한다.** 그 모드는 테스트와 모든
   벤치마크 스윕이 구성하는 `(k, m, security)`를 재현해 `Validate()`가 던지는 키를 나열한다.
   벤치마크의 스윕이 바뀌면 그 모드도 함께 고쳐야 한다 — 스윕을 잘못 재현하면 실제와 다른
   "이상 없음"을 보고한다. 특히 `bench_threshold`는 `QuickSweep`으로 TOY 스윕을 가장 작은 2개로
   줄이지만 `bench_crossover`는 `QuickSweep`을 쓰지 않아 모든 보안 레벨에서 5×5 전체를 돈다.

10. **STD192 / STD256는 캘리브레이션 표에 없다** — 해당 레벨로 벤치마크를 돌리면
   `Validate()`가 던진다. 의도된 fail-closed 동작이며, 논문은 STD128만 보고한다.
   해당 레벨이 필요해지면 캘리브레이션을 확장할 것.

11. **`Flood()` 자체 비용 측정 (Task 6, TOY, N=1024, `FloodNoiseBits()`=140비트).**
    `bench_noise`는 Task 5 이후 모든 경로가 `EvaluateRaw`를 쓰고 그 파라미터는
    `CalibrationAccess`에서 나와 `flooding_sized_ == false`이므로 `Flood()`를 측정할 수
    없다(`FloodNoiseBits()`가 throw). `tests/unit/test_bfv_context.cpp`의
    `FloodCostIsRecorded`(20회 반복, 중앙값)가 검증된 컨텍스트와 `Flood()`가 만나는
    유일한 지점이라 여기서 측정했다:

    - 총 비용: 중앙값 **1,119 μs**
    - 분리 — 재랜덤화(`ctx->Encrypt(zeros)` 776 μs + `cc->EvalAdd(ct, ...)` 29 μs =
      **805 μs, 총합의 약 72%**) vs 마스크 샘플링·합산 나머지(**≈314 μs, 약 28%**).
      두 조각 모두 `BFVContext`에 공개된 API로 테스트에서 직접 측정했으며 `Flood()`
      본체는 계측하지 않았다.
    - **재랜덤화가 지배적이다.** §3.4가 기록한 "flooding 연산 자체는 전체의 3% 미만"은
      재랜덤화가 없던 스파이크 측정치이고, 완전한 공개키 암호화(`Encrypt(zeros)`)가
      추가된 지금은 "flooding 비용"이라고 부르는 수치의 대부분이 사실 그 암호화다.
    - N=1024 TOY 스케일 숫자이며, threshold @ STD128(N=32768, 605비트 마스크, 14 limb)에
      그대로 적용할 수 없다. STD128 수치가 필요하면 별도 하네스로 Phase 4에서 재측정한다.

12. **Task 5 범위 확장: `SqrtPiccard`/`ThresholdPiccard`에 `EvaluateRaw` 추가.** Task 3이
    `Piccard::Evaluate`를 플러딩 버전으로 바꾸자 `bench_noise`의 네 호출 지점
    (`RunOneHot`/`RunSqrt`/`RunThreshold`의 두 호출)이 캘리브레이션 미확정 파라미터
    (`flooding_sized_ == false`)에서 `FloodNoiseBits()`를 요구해 전부 throw했다. 하네스에서
    `lambda_stat`/`flood_margin_bits`를 조정해 플러딩을 우회하는 대안은 **작동하지 않는다** —
    throw는 마스크 크기가 아니라 `flooding_sized_` 플래그 하나에 무조건 걸려 있기 때문이다
    (`params.cpp:105-111`). 따라서 `SqrtPiccard`/`ThresholdPiccard`에도 `Piccard`와 동일한
    `EvaluateRaw`/`Evaluate = Flood(EvaluateRaw)` 쌍을 추가해 세 회로가 같은 계약을
    노출하도록 했다. 원 계획의 File Structure 표를 벗어나는 확장이며 Task 5의 "Scope note"에
    명시적으로 기록됨.

13. **재랜덤화 결정: 채택.** `3_noise-flooding.md`(본 문서) 상단의 "Open decision" 섹션이
    2026-07-26에 확정한 대로, `Flood()`는 마스크를 더하기 전에
    `cc_->EvalAdd(ct, Encrypt(zeros))`로 먼저 재랜덤화한다(`src/fhe/bfv_context.cpp`,
    Task 1 Step 4). `appendix.tex`의 "fresh encryption" 서술이 구현과 일치하므로 논문 수정은
    불필요. 다만 비용은 무시할 수 있는 수준이 아니다 — §8-11에서 보듯 재랜덤화가 `Flood()`
    전체 비용의 약 72%를 차지한다.

14. **Union-bound 자격 부여.** 수신자는 암호문의 `N`개 좌표 전부를 본다. smudging lemma가
    좌표 하나당 주는 통계적 거리 `2^-(lambda_stat + flood_margin_bits)`를 그대로 전체
    보안 주장에 쓸 수 없고, union bound로 `N * 2^-(lambda_stat + flood_margin_bits)`가
    실제로 전달되는 통계적 거리다. `lambda_stat=64`, `flood_margin_bits=8`, `N=32768`
    (=2^15)일 때 `2^15 * 2^-72 = 2^-57`이며, 쓰기 쉬운 `2^-lambda_stat = 2^-64`보다 약하다.
    `flood_margin_bits`는 B_eval 과소평가를 덮기 위한 마진이지 이 union bound를 덮기 위한
    것이 아니므로, 새 주석이나 논문 문구에 `2^-lambda_stat`만 단독으로 쓰지 말 것.

15. **`bench_threshold`가 이제 라이브러리 API를 통해 플러딩된다 (threshold-fpfn에 알림).**
    이 브랜치는 `benchmarks/bench_threshold.cpp`를 편집하지 않았지만, 그 파일의 여러
    호출 지점(`engine->GetPiccard().Run(sa, sb)`, 예: `bench_threshold.cpp:462,518,570,
    621,688,754`)은 `Piccard::Run` → `Piccard::Evaluate`(Task 3)를 거치므로 이 브랜치가
    머지되면 자동으로 `Flood()`가 적용된다. 따라서 이 벤치마크의 wall-clock 수치는 조용히
    변하는데, §8-8에서 요청한 `phase_flood_ms` 열이 아직 그 파일에 없어 변화폭을 어느
    단계 탓으로 돌릴 방법이 없다. threshold-fpfn이 §8-8의 요구사항(Phase 7
    `EvalPolyBFV` 직후 flooding, `phase_flood_ms` 열)을 처리할 때 이 시프트도 함께
    흡수해야 한다.

16. ⚠️ **재랜덤화가 "fresh encryption과 통계적으로 구별 불가"를 성립시키지 않는다 —
    논문 문구 결정 필요 (gpt-5.6-sol 검토, 2026-07-26).**

    `Flood()`는 `c0`에 지수적으로 넓은 마스크를 더하고 `Enc_pk(0)`으로 재랜덤화한다.
    그런데 **일반 `Enc_pk(0)`은 일반 폭의 난수만 싣는다.** 그래서:

    | 성분 | 무엇이 성립하는가 |
    |---|---|
    | 복호 위상 `c0 + c1·s` | **통계적** smudging (union bound 반영 시 ≈ 2^-57 @ N=32768) |
    | `c1` | Ring-LWE 하의 **계산적** 구별 불가 |

    `appendix.tex`가 주장하는 "**fresh encryption**과 통계적으로 구별 불가"는 이보다 강하다.
    그 수준은 zero-encryption 자체에 넓은 난수를 싣는 sanitization 구성(예: Ducas–Stehlé 계열)이
    필요하고, 그 경우 `c1·s` 기여분까지 다시 캘리브레이션해야 한다.

    **두 갈래 중 하나를 골라야 한다:**
    - (a) sanitization을 구현하고 재캘리브레이션 + 전체 쌍 분포 테스트 추가;
    - (b) 증명을 실제 구성에 맞춰 수정 — 시뮬레이터가 평가된 `c1`을 받을 수 있게 하고,
      위상 노이즈 smudging만 주장(반semi-honest 모델에서 표준적이고 전체 증명이 어차피
      IND-CPA에 의존한다는 점에서 정합적).

    **현재 코드는 (b)에 해당한다.** `bfv_context.h`의 `Flood()` 주석을 그에 맞게 정정해 두었다.
    (a)를 택하면 Phase 2를 다시 열어야 한다. 응답서가 나가기 전에 결정할 것.

    참고: https://eprint.iacr.org/2022/1459.pdf , https://eprint.iacr.org/2024/1534.pdf


---

## §9. 프로브 소스

`{scratchpad}/probe_modulus.cpp` — maxQ 표, 손잡이 가용성
`{scratchpad}/probe_noise.cpp` — B_eval 측정 + flooding 스파이크
`{scratchpad}/probe_table.cpp` — (depth, sms) 격자 스윕
`{scratchpad}/probe_time.cpp` — 타이밍
`{scratchpad}/probe_sqrt.cpp` — Piccard⁺ 회로

빌드:
```bash
c++ -std=c++17 -O2 -o probe_X probe_X.cpp \
  -I/usr/local/include/openfhe -I/usr/local/include/openfhe/core \
  -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/binfhe \
  -I/usr/local/include/openfhe/third-party/include \
  -L/usr/local/lib -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe
DYLD_LIBRARY_PATH=/usr/local/lib ./probe_X
```
Phase 0에서 `benchmarks/bench_noise.cpp`로 통합한다.
