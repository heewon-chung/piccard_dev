# 공통 컨텍스트 (6개 브랜치 프롬프트에 모두 포함됨)

## 상황

IEEE TKDE에 제출한 논문 *"Piccard: MinHash-based similarity search with untrusted servers"* 가
**major revision** 판정을 받았다. 리뷰어 3명 전원이 major revision을 권고했고(R1 "Good" /
R2 "Good" / R3 "Fair"), AE는 "doable to fix" 기조다. 파싱된 코멘트 24건 중 Major 12건.

리비전 대응은 코드 작업 6개 브랜치로 쪼개서 병렬 진행한다. 이 워크트리는 그중 하나다.

## 파일 위치

| 대상 | 경로 |
|---|---|
| 논문 원고 | `~/Documents/03-TeX/01-Paper/01-In_Progress/Private_Jaccard_with_FHE/Draft/V4/piccard.tex` |
| 부록 | 같은 디렉토리 `appendix.tex` |
| **리뷰 원문** | 같은 디렉토리 `Review.txt` |
| **리비전 로드맵** | 같은 디렉토리 `Revision_Roadmap.md` (P1/P2/P3 우선순위 정리본) |
| 응답서 초안 | 같은 디렉토리 `Response_Letter_Skeleton.md` |

## 저장소 상태

6개 브랜치 모두 `01a75ac`에서 분기했다. 직전 3개 커밋의 의미:

- `c2d4b51` — 아티팩트 추적 해제 (`build/`, `.cache/`, `.omc/`, `results/`, `.DS_Store` 690개)
- `50a3e3c` — 그동안 커밋되지 않았던 소스 4,277줄: **Piccard⁺(base-√m) 구현 전체**,
  `include/piccard/*` → `include/*` 평탄화, 벤치 하네스·summarizer 재작업
- `01a75ac` — baseline 배관: `include/baselines/pjs_baseline.h`(공통 계약 + `SecurityClass` enum),
  CMake의 GMP 탐지 + `piccard_baselines` 타겟(`src/baselines/*.cpp` glob, 비어 있어도 무해),
  `bench_comparison`의 `security_class` 열

빌드·테스트:
```bash
cmake -S . -B build && cmake --build build -j8
cd build && ctest --output-on-failure
```
기준선에서 **빌드 클린, 12/12 테스트 통과**를 확인했다. 작업 시작 전 이 상태를 직접 재확인할 것.

의존성은 Homebrew: OpenFHE, GMP 6.3.0, libomp, GTest 모두 설치돼 있다.

## 6개 브랜치와 소유 범위

| 브랜치 | 다루는 리뷰 항목 | 주로 소유하는 파일 |
|---|---|---|
| `tkde-major/benchmark-stats` | R3-5 (분산/CI) | `benchmark_utils.h`, 모든 `bench_*.cpp`의 집계 경로, `summarize_results.py` |
| `tkde-major/hash-seed-crs` | R3-1, R3-2 (난수 명시) | `params.{h,cpp}`, `minhash.*`, `bottom_structure.*`, `piccard.cpp` |
| `tkde-major/noise-flooding` | R2-W6 | `bfv_context.{h,cpp}`, `params.{h,cpp}` |
| `tkde-major/threshold-fpfn` | R3-4 | `bench_threshold.cpp`, `summarize_results.py`의 threshold 표 |
| `tkde-major/implement-bcg12` | R2-W1 | `src/baselines/bcg12.*` (신규) |
| `tkde-major/implement-sj16` | R2-W1 | `src/baselines/sj16.*` (신규) |

**남의 브랜치가 소유한 파일은 건드리지 마라.** 손대야 할 이유를 발견하면 고치지 말고 기록해두고,
통합 시점에 처리한다. 특히 `benchmark_utils.h`와 `summarize_results.py`는 여러 브랜치가
공유하므로 최소 편집 원칙을 지킨다.

## 머지 순서 (합의됨)

```
benchmark-stats → hash-seed-crs → noise-flooding → threshold-fpfn → implement-bcg12 → implement-sj16
```

넓고 얕은 리팩터를 먼저, 좁고 깊은 것을 다음, 순수 추가를 마지막에 둔 순서다.
`noise-flooding`이 머지되면 **모든 시간·통신량 측정치가 무효**가 되므로, 최종 수치는
그 이후에 일괄 재측정한다.

## 이번 세션에서 할 일

**구현하지 마라.** 이 세션의 목적은 오리엔테이션이다:

1. 위 리뷰 원문과 로드맵에서 이 브랜치에 해당하는 부분을 읽는다
2. 아래 "현재 코드 상태"에 적힌 근거를 **직접 열어서 확인**한다 (내가 틀렸을 수 있다)
3. 무엇을 왜 고쳐야 하는지, 어떤 순서로 할지 계획을 세운다
4. 불확실한 지점·설계 판단이 필요한 지점을 질문으로 정리한다

코드 수정, 커밋, 빌드 변경은 하지 않는다. 계획에 대한 승인을 받은 뒤 시작한다.
