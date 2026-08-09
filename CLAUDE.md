# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Piccard: MinHash-based private Jaccard similarity search over BFV fully homomorphic encryption (OpenFHE). C++17 implementation for the IEEE TKDE paper *"Piccard: MinHash-based similarity search with untrusted servers"*, currently under **major revision**.

Paper sources live outside this repo: `~/Documents/03-TeX/01-Paper/01-In_Progress/Private_Jaccard_with_FHE/Draft/V4/` (`piccard.tex`, `appendix.tex`, `Review.txt`, `Revision_Roadmap.md`, `Response_Letter_Skeleton.md`).

## TKDE Revision Workflow (read before editing)

Revision work is split across 6 parallel branches forked from a common baseline; `Branch_Prompts/00_shared_context.md` is the authority on branch ownership, merge order, and file boundaries. Key rules:

- Each `tkde-major/*` branch owns specific files (see the table in `00_shared_context.md`). **Do not edit files owned by another branch** — record the need and defer to integration.
- Shared files (`benchmarks/benchmark_utils.h`, `scripts/summarize_results.py`) get minimal edits only.
- Merge order: `benchmark-stats → hash-seed-crs → noise-flooding → threshold-fpfn → implement-bcg12 → implement-sj16`. Once `noise-flooding` merges, all timing/communication measurements are invalid and must be re-run.
- Check `git status --short --branch` and the current branch before editing — local `main` may lag `origin/main`.

## Build &amp; Test

```bash
cmake -S . -B build && cmake --build build -j8
cd build && ctest --output-on-failure          # all tests (12 at baseline, all should pass)
./build/test_minhash                            # single test binary
./build/test_piccard_engine --gtest_filter=PiccardEngineTest.Name
```

Dependencies (all Homebrew): OpenFHE, GMP, libomp, GTest. CMake degrades gracefully — `piccard_core` builds with none of them; missing OpenFHE disables `piccard_fhe`, all FHE tests, and benchmarks; missing GMP disables `piccard_baselines`. CMakeLists already handles the macOS libomp path via `brew --prefix libomp`.

## Benchmarks

```bash
./scripts/run_benchmarks.sh --quick    # smoke test: TOY security, 2 trials
./scripts/run_benchmarks.sh            # paper-grade: STD128, 10 timing / 50 accuracy trials
./scripts/run_core_benchmarks.sh       # core only (no dynamic/threshold)
python3 scripts/summarize_results.py results/<dir>/csv --latex
```

Output lands in `results/YYYY-MM-DD_HHMMSS_TAG/` (csv/, tables/, system_info.txt, run.log); paper-ready snapshots are checked in under `scripts/results/`. Benchmark binaries (`bench_piccard`, `bench_comparison`, `bench_dynamic`, `bench_threshold`, `bench_sqrt_comparison`, `bench_onehot_sqrt`, `bench_crossover`) **start running immediately when invoked** — there is no `--help`; flags are `--key=value` (see `BenchmarkConfig::ParseArgs` in `benchmarks/benchmark_utils.h`). They emit CSV rows to stdout mixed with human-readable progress lines; `summarize_results.py` skips the non-CSV lines.

## Architecture

Three-layer CMake structure, bottom-up:

1. `**piccard_core**` (`src/core/`, `src/util/` — no OpenFHE): pure math. `PiccardParams::Validate()` in `util/params.cpp` derives everything (`feature_dim = k*m`, ring dimension, plaintext prime `p ≡ 1 mod 2N`) from user knobs `k` (MinHash count), `m` (one-hot bucket size), and `SecurityLevel` (TOY/STD128/STD192/STD256 — TOY is insecure, for fast tests). `MinHasher` uses universal hashing mod the Mersenne prime 2^61−1. Encoders: `OneHotEncoder` (k·m slots) and `SqrtEncoder` (base-√m, k·2√m slots — the Piccard⁺ variant). `BottomStructure` keeps the d smallest hashes per function for dynamic insert/delete (paper Algorithms 3–5). `threshold_poly` builds the polynomial for threshold matching.
2. `**piccard_fhe**` (`src/fhe/`, `src/protocol/` — requires OpenFHE): `BFVContext` wraps the OpenFHE crypto context (encrypt/decrypt, rotate, plaintext multiply, and `EvalPolyBFV` = Paterson–Stockmeyer polynomial evaluation). Protocol variants:
  - `Piccard` (base class): set → MinHash signature → one-hot encode → BFV encrypt → slot-wise multiply → rotate-and-sum → decrypt slot 0 = match count → bias-corrected Jaccard `(v/k − 1/m)/(1 − 1/m)`.
  - `DynamicPiccard` extends `Piccard` with `BottomStructure`-backed Insert/Delete.
  - `ThresholdPiccard` composes `Piccard` + threshold polynomial → boolean output (higher mult depth).
  - `SqrtPiccard` is the base-√m encoding variant (smaller feature dim, one extra mult).
3. `**piccard_baselines**` (`src/baselines/*.cpp` glob, requires GMP + OpenFHE): AHE/DH-based comparison baselines (BCG12, SJ16) implementing `include/baselines/pjs_baseline.h` — being added on the `implement-bcg12`/`implement-sj16` branches; the glob target is valid while the directory is empty.

**Legacy files**: `include/protocol/piccard_engine.h` and `src/protocol/piccard_engine.cpp` are dead code — not compiled anywhere (the `test_piccard_engine` target actually tests the `Piccard` class).

## Gotchas

- The seeds for `MinHasher`/`BottomStructure` default to 42; both sides of the protocol must share the same seed and `hash_range` or signatures won't align (being formalized as a CRS on the `hash-seed-crs` branch).
- `PiccardParams` must go through `Validate()` (or `ValidateSqrt()` for `SqrtPiccard`) before constructing any engine — derived fields are zero otherwise.
- Threshold mode changes `mult_depth`, which changes BFV parameters and therefore all timing numbers; don't mix threshold and non-threshold timings.

