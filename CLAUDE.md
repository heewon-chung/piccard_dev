# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Piccard: MinHash-based private Jaccard similarity search over BFV fully homomorphic encryption (OpenFHE). C++17 implementation for the IEEE TKDE paper *"Piccard: MinHash-based similarity search with untrusted servers"*, currently under **major revision**.

Paper sources live outside this repo: `~/Documents/03-TeX/01-Paper/01-In_Progress/Private_Jaccard_with_FHE/Draft/V4/` (`piccard.tex`, `appendix.tex`, `ref.bib`, `Review.txt`, `Response_Letter_Skeleton.md`, `Cover_Letter/`, `Branch_Prompts/`).

## TKDE Revision Workflow (read before editing)

**The parallel-branch phase is over.** All ten revision PRs are merged into `main` (`benchmark-stats`, `hash-seed-crs`, `noise-flooding`, `implement-bcg12`, `implement-sj16`, `bench-reporting-plumbing`, `comparison-reporting-gaps`, `measurement-symmetry`, `threshold-fpfn`, `std192-evidence`). The surviving `tkde-major/*` branches and `Branch_Prompts/*.md` are historical; their file-ownership rules no longer apply. Work directly on `main` unless told otherwise.

What replaced them as the authority is **`benchmarks/revision_matrix.json`** — a versioned, fail-closed experiment matrix. It is the single source of truth for what gets measured, at which counts, by which producer:

- `paper-v1` profile: **263 cells** across 20 families (`piccard_std128`, `piccard_std192_encoding`, `sqrt_comparison`, `dynamic_timing`/`dynamic_accuracy`, `threshold_synthetic_fpfn` (84), `sj16`, `bcg12_exact`/`bcg12_minhash`, `fhe_ind`, `flooding`, `real_dataset`, …). Golden cell-ID lists live in `tests/fixtures/revision_matrix/`.
- `readiness-toy-v1` profile: 104 executable cells, every measured count projected to 1.
- Each cell carries `invocation_status` (`RUN` / `NO_SPAWN`), `eligibility`, `expected_rows`, and a `raw_timing_contract`. Adding or retuning an experiment means editing the matrix, not just a runner script.

Since `noise-flooding` merged, **every pre-merge timing and communication number is invalid.** Do not cite figures from `scripts/results/` snapshots dated before the merge.

Always check `git status --short --branch` before editing — several worktrees (`.ouroboros/`, `/private/tmp/piccard-revision-*`) may hold stale checkouts.

## Build & Test

```bash
cmake -S . -B build && cmake --build build -j8
cd build && ctest --output-on-failure          # 110 registered tests, all should pass
./build/test_minhash                            # single test binary
./build/test_piccard_engine --gtest_filter=PiccardEngineTest.Name
```

Dependencies: **OpenFHE 1.5.0** (source-built into `/usr/local`, not Homebrew), GMP, OpenSSL, libomp, GTest, Python 3. CMake degrades gracefully — `piccard_core` builds with none of the optional ones; missing OpenFHE disables `piccard_fhe`, the FHE tests, and most benchmarks; missing GMP disables `piccard_baselines`. The macOS libomp path is handled via `brew --prefix libomp`, guarded by `if(APPLE)`, so Linux uses the stock `find_package(OpenMP)` path.

Two build-time constraints that fail hard rather than degrade:

- **OpenSSL is `REQUIRED`** (SHA-256 MinHash and the baselines need it).
- **Evidence builds require real Git provenance.** `CMakeLists.txt` calls `git rev-parse HEAD` and `git status --porcelain` and raises `FATAL_ERROR` without a full 40-char commit, then hashes every tracked source file into a `PICCARD_CONFIGURED_BUILD_ID` baked into `build_info.h`. Configure from a real clone; an exported tarball will not build.
- Paper benchmark verification records and checks the exact OpenFHE version
  through `scripts/verify_revision_benchmarks.py`.

The tree builds 16 `bench_*` executables and 59 test executables; `ctest` also drives Python contract tests under `tests/scripts/`.

## Benchmarks

The matrix orchestrator is the single supported benchmark entry point:

```bash
python3 scripts/run_revision_benchmarks.py --mode=dry-run --build-dir=build \
    --results-root=<dir> --seed=<n> --threads=<n>
python3 scripts/run_revision_benchmarks.py --mode=toy   ...   # 104-cell readiness inventory
python3 scripts/run_revision_benchmarks.py --mode=paper ... --authorize-paper-run \
    --paper-dblp-manifest=... --paper-enron-u65536-manifest=... --paper-enron-u1048576-manifest=...
```

It walks eight phases (`preflight → synthetic → comparison → real-fixtures → dynamic-deletion → threshold → verification → seal`), emits per-cell JSONL receipts, and never constructs an FHE context itself. `--mode=paper` refuses to run without `--authorize-paper-run` and without bound dataset manifests. `scripts/verify_revision_benchmarks.py` checks the resulting artifacts against the matrix before `scripts/seal_revision_benchmarks.py` seals the run.

**Do not invoke benchmark binaries directly for paper measurements.** The revision runner supplies their exact `--key=value` arguments, captures stdout/stderr, and binds raw timing sidecars to the matrix cell. The heaviest single item is the SJ16 sweep (~19.5 min/query at |U|=2^16, single-threaded), so a full `paper-v1` pass is on the order of a day.

## Architecture

Bottom-up CMake layering:

1. **`piccard_core`** (`src/core/`, `src/util/` — no OpenFHE): pure math. `PiccardParams::Validate()` in `util/params.cpp` derives everything (`feature_dim = k*m`, ring dimension, plaintext prime `p ≡ 1 mod 2N`) from user knobs `k` (MinHash count), `m` (one-hot bucket size), and `SecurityLevel` (TOY/STD128/STD192/STD256 — TOY is insecure, for fast tests). Validation also **sizes the noise-flooding term** against the frozen calibration table in `include/util/noise_calibration.inc`; see `FloodNoiseBits()`, `FloodingSized()`, and the deliberately unsafe `DeriveWithoutFlooding()`. `MinHasher` uses **SHA-256 byte-level random ranking** (`ModelName() == "sha256-random-ranking-poc-v1"`) keyed by a public CRS seed. Encoders: `OneHotEncoder` (k·m slots) and `SqrtEncoder` (base-√m, k·2√m slots — the Piccard⁺ variant). `BottomStructure` keeps the d smallest hashes per function for dynamic insert/delete (paper Algorithms 3–5). `threshold_poly` builds the polynomial for threshold matching; `threshold_truth` supplies the plaintext ground truth for the FP/FN grid.
2. **`piccard_fhe`** (`src/fhe/`, `src/protocol/` — requires OpenFHE): `BFVContext` wraps the OpenFHE crypto context (encrypt/decrypt, rotate, plaintext multiply, and `EvalPolyBFV` = Paterson–Stockmeyer polynomial evaluation). Protocol variants:
   - `Piccard` (base class): set → MinHash signature → one-hot encode → BFV encrypt → slot-wise multiply → rotate-and-sum → decrypt slot 0 = match count → bias-corrected Jaccard `(v/k − 1/m)/(1 − 1/m)`.
   - `DynamicPiccard` extends `Piccard` with `BottomStructure`-backed Insert/Delete, plus `DynamicCiphertextStore` and a refresh path.
   - `ThresholdPiccard` composes `Piccard` + threshold polynomial → boolean output (higher mult depth).
   - `SqrtPiccard` is the base-√m encoding variant (smaller feature dim, one extra mult).
3. **`piccard_baselines`** (`src/baselines/*.cpp` glob, requires GMP + OpenSSL + OpenFHE): the comparison baselines are **implemented**, not stubs — `bcg12.cpp` (over pluggable `group_ec`/`group_ff` backends), `sj16.cpp` (Paillier AHE, OpenMP-parallel encryption at `sj16.cpp:175`), `dgt12_psica.cpp`, all against `include/baselines/pjs_baseline.h`. `paillier.cpp` is compiled separately into `piccard_paillier` (GMP-only, no OpenFHE).

Supporting libraries worth knowing about:

- `piccard_data` (`src/data/`): strict loader/validator for processed real-dataset outputs (DBLP-ACM, Enron) under `datasets/`.
- `piccard_security_profile`, `piccard_dynamic_analysis` (deletion survival + Monte Carlo).
- A family of **OpenFHE-free revision adapters** (`piccard_revision_matrix`, `piccard_revision_invocation_plan`, and per-producer `*_revision_adapter` libraries). These parse the matrix, select an exact cell, and plan an invocation *without* constructing a crypto context, so matrix topology and counts stay testable before anything expensive runs.

**Legacy files**: `include/protocol/piccard_engine.h` and `src/protocol/piccard_engine.cpp` are not part of any production library — `piccard_fhe` does not include them, and the `test_piccard_engine` target actually exercises the `Piccard` class. They survive only because `test_piccard_engine_legacy_compile` compiles them as a guard against bit-rot.

## Gotchas

- **The CRS seed has no default.** `MinHasher` and `BottomStructure` deliberately require an explicit `seed` argument so static and dynamic paths cannot silently diverge; do not reintroduce a default. `PiccardParams::hash_seed` still defaults to 42, but it is now documented as the public CRS seed serialized into every SHA-256 rank input. Both sides of the protocol must share the same seed *and* `hash_range`.
- `PiccardParams` must go through `Validate()` (or `ValidateSqrt()` for `SqrtPiccard`) before constructing any engine — derived fields are zero otherwise, and flooding is unsized.
- Threshold mode changes `mult_depth`, which changes BFV parameters and therefore all timing numbers; don't mix threshold and non-threshold timings.
- Timing cells must run without core contention. Accuracy, FP/FN, and Monte-Carlo cells make no timing claim and may run concurrently; timing cells may not.
- `include/util/noise_calibration.inc` is a generated measured artifact (`scripts/make_calibration_table.py`, recorded as OpenFHE 1.5.0 / macOS arm64). Do not hand-edit it, and treat a platform or OpenFHE change as requiring re-verification of its provenance claim.
- Design docs and plans for the revision work live in `docs/superpowers/specs/` and `docs/superpowers/plans/` — check there before re-deriving a decision.
