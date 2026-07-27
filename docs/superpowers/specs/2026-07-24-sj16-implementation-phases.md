# SJ16 baseline — phased implementation plan (rev. 2)

Companion to `2026-07-24-sj16-baseline-design.md`. Splits the design's §8 Work
order into ordered phases. Each phase is self-contained, ends on a **green build
+ passing tests**, and states exactly what to build and how to prove it works.

**Rev. 2** incorporates an independent review (gpt-5.6-sol, high effort,
16 findings). Changes from rev. 1 are marked `[R#]` against the finding they
close.

- Branch: `tkde-major/implement-sj16`
- Correct source paper (confirmed): `~/Downloads/Secure_Multiset_Intersection_Cardinality_and_its_Application_to_Jaccard_Coefficient.pdf` (Samanthula & Jiang, TDSC 2016). `1111.5062v5.pdf` is EsPRESSo/BCG12 — a *different* protocol owned by `implement-bcg12`; not used here.
- **Base commit: `4bd7459`** — merge-order #1 (`benchmark-stats`) **and** #2
  (`hash-seed-crs`) are both already merged (branch rebased 2026-07-26). `[R8-r2]`
- **CRS orthogonality**: `hash-seed-crs` exposes the MinHash randomness as a
  public CRS seed and threads it through the Piccard paths. **SJ16 does not use
  MinHash** (it is a universe-indicator protocol), so the CRS changes do not
  touch SJ16 logic; the only interaction is that SJ16 reuses the same per-trial
  `(set_a,set_b)` the loop already generates (Phase 4). `[R8-r2]`
- **Current test count: 13** (`Params MinHash OneHotEncoder SqrtEncoder BottomStructure ThresholdPoly BFVContext PiccardEngine DynamicEngine ThresholdEngine SqrtPiccard BenchmarkUtils PiccardE2E`). After SJ16 → **15** (`Paillier`, `SJ16` added). `[R8]`
- `benchmark-stats` introduced `QuickSweep<T>(...)` around the sweeps
  (`bench_comparison.cpp:663,742,826,1040`) and per-trial dispersion; the
  universe per-trial loop at `:882-884` generates `(set_a,set_b)` via
  `MakeRandomSetsWithOverlap(...)`. SJ16 must plug into that loop and reuse those
  inputs. `[R8][R16-r2]`

## Conventions used by every phase

- **Scope** = exact files created/edited and the surface to add.
- **Steps** = ordered actions, concrete enough to follow without further design.
- **Verify** = commands + pass criteria (green = proceed).
- **Do-not-touch** = files owned by other branches or out of scope.
- TDD for library units (Phases 1–2): test first, watch it fail, implement.
- Shared files (`CMakeLists.txt`, `bench_comparison.cpp`) get the **smallest
  possible** diff; every edit is logged, because `implement-bcg12` shares them
  and merges before us.
- **`file(GLOB ...)` does not auto-refresh.** After adding any new
  `src/baselines/*.cpp`, re-run `cmake -S . -B build` before building, or the
  new source is not picked up. `[R7]`

---

## Phase 0 — Guard: reconfirm baseline and record the current CMake pattern

**Goal.** Prove the tree is green before any change and capture the *current*
(`4bd7459`) anchors. No production code.

**Steps.**
1. `git rev-parse --short HEAD` → expect `4bd7459` (or a later descendant). If
   the tree has advanced again, refresh anchors before proceeding. `[R8-r2]`
2. `cmake -S . -B build && cmake --build build -j8` — clean.
3. `cd build && ctest --output-on-failure` — **13/13**.
4. Confirm GMP (`HAVE_GMP`, `CMakeLists.txt:55-66`). Phase 1 introduces a
   **GMP-only** `piccard_paillier` static lib so the Paillier unit does not link
   OpenFHE (resolves the transitive-OpenFHE concern); `piccard_baselines` then
   links `piccard_paillier`. `[R7-r2]`
5. Record current line anchors used later: `SecurityClassOf` at
   `bench_comparison.cpp:135` (already maps `sj16`→`AHE/no-leakage`, `:138`);
   `target_link_libraries(bench_comparison piccard_fhe)` at `CMakeLists.txt:246`;
   universe sweep at `bench_comparison.cpp:826`; ct-size via
   `CiphertextSizer::GetSerializedSize` (`:247` etc.).

**Verify.** 13/13 pass; HEAD is `4bd7459` (or a later descendant); GMP present.
Otherwise stop.

**Do-not-touch.** Everything (read-only phase).

---

## Phase 1 — Paillier primitive (GMP), with a CSPRNG, with unit tests

**Goal.** A correct additive-homomorphic Paillier over GMP, with a real CSPRNG
and thread-safe randomness, that builds and tests green on its own.

**Scope.**
- New `include/baselines/csprng.h` — OS-backed randomness. `[R1]`
- New `include/baselines/paillier.h`, `src/baselines/paillier.cpp`
- New `tests/unit/test_paillier.cpp`
- `CMakeLists.txt`:
  - a **GMP-only** `piccard_paillier` static lib (`paillier.cpp`, links only
    `${GMP_LIBRARY}` + OpenMP, **no OpenFHE**); `piccard_baselines` **links**
    `piccard_paillier` (it does not recompile it).
    Gated by a new `option(PICCARD_ENABLE_GMP "..." ON)` that also gates the
    `find_path/find_library(GMP)` block, so `-DPICCARD_ENABLE_GMP=OFF` gives a
    deterministic no-GMP build (finding 15) rather than relying on
    `NOTFOUND` cache entries that `find_*` can re-discover. `[R7-r2][R15-r2]`
  - the `src/baselines/*.cpp` glob gains `CONFIGURE_DEPENDS` **and explicitly
    removes `paillier.cpp`** (`list(REMOVE_ITEM PICCARD_BASELINE_SOURCES
    .../paillier.cpp)`), so `paillier.cpp` is compiled **once** (in
    `piccard_paillier`) and never pulled into the OpenFHE-linked
    `piccard_baselines` via the glob. `[R7-r3]`
  - a `test_paillier` target, guarded `if(TARGET piccard_paillier)`.
  **Shared-file edits — logged.** `[R7]`

**CSPRNG surface `[R1]`.** A per-thread wrapper drawing entropy from the OS.
```cpp
namespace piccard { namespace baselines {
class CSPRNG {                         // one instance per thread; never shared
public:
    void FillBytes(void* buf, size_t n);          // getentropy in <=256 B chunks,
                                                  // checked return, retry on EINTR,
                                                  // abort on hard failure
    void RandomMpz(mpz_t out, const mpz_t upper);  // uniform [0,upper) via
                                                  // rejection sampling (no modulo bias)
    void RandomCoprime(mpz_t out, const mpz_t n);  // Paillier nonce ρ ∈ Z_n*:
                                                  // reject ρ=0, ρ>=n, gcd(ρ,n)!=1
    void RandomBits(mpz_t out, unsigned bits);
};
CSPRNG& ThreadLocalCSPRNG();           // thread_local accessor for parallelism
}}
```
Rationale: GMP's `gmp_randstate_t` is not cryptographic, and a single shared
mutable state cannot serve parallel encryptions (design D4) nor sit behind
`const` methods. `getentropy` caps at 256 bytes/call, so `FillBytes` loops with
a checked return; `RandomMpz` uses rejection sampling to avoid modulo bias; the
Paillier nonce is drawn from `Z_n*` via `RandomCoprime`. `[R1-r2][R10]`

**Paillier surface.**
```cpp
class Paillier {
public:
    explicit Paillier(unsigned key_bits);        // 1024/2048/3072 only
    Paillier(const Paillier&) = delete;           // mpz_t ownership; no copy/move
    Paillier& operator=(const Paillier&) = delete;
    ~Paillier();

    void KeyGen();                                 // invariants enforced (below)
    void Encrypt(mpz_t c, const mpz_t m) const;    // c=(1+mN)·ρ^N mod N^2, ρ fresh
    void Decrypt(mpz_t m, const mpz_t c) const;    // -> m in [0,N)
    void AddCipher(mpz_t out, const mpz_t a, const mpz_t b) const;  // a·b mod N^2
    void ScalarMul(mpz_t out, const mpz_t c, const mpz_t k) const;  // c^k mod N^2

    unsigned KeyBits() const;
    // WIRE encoding: fixed-width big-endian mpz_export into a ceil(2K/8)-byte
    // buffer (a Z_{N^2} element). This IS the transmitted form; its length is
    // the byte count. Fixed width => actual == theoretical == ceil(2K/8). `[R13-r2]`
    size_t   SerializeCiphertext(const mpz_t c, unsigned char* out) const;
    size_t   CiphertextBytes() const;                         // ceil(2K/8)
    const mpz_t& N() const;
};
```
`Encrypt`/`Decrypt` are logically `const` (keys don't change) but pull
randomness from `ThreadLocalCSPRNG()`, not from mutable member state. `[R1]`

**KeyGen invariants (regenerate until all hold) `[R2]`.**
- draw `p,q` as `K/2`-bit primes (top bit set before `mpz_nextprime`); **reject
  and redraw if `mpz_nextprime` crossed the `K/2`-bit boundary**;
- require `p != q`;
- require **`mpz_sizeinbase(N,2) == K`** exactly;
- `lambda = lcm(p-1,q-1)`; compute `mu` via `mpz_invert(mu, lambda, N)` and
  **check its return value** (`gcd(lambda,N)=1`); redraw on failure.
- Reject unsupported `key_bits` (`!= 1024,2048,3072`) with an exception.

**Decryption (correct for `g=1+N`, unchanged from rev. 1) `[R2]`.**
`u = c^lambda mod N^2`; `L = (u-1)/N`; `m = L·mu mod N`. (With `g=1+N`,
`L(g^lambda mod N^2)=lambda`, so `mu=lambda^{-1} mod N`.)

**Verify.** `ctest -R Paillier` green (K=1024 for speed):
- **Roundtrip** for `m ∈ {0,1,2,7,N-1, 20×random}`.
- **Additive homomorphism** `Dec(AddCipher(Enc a,Enc b)) == (a+b) mod N`.
- **Scalar** `Dec(ScalarMul(Enc a,k)) == (a·k) mod N`.
- **Semantic**: two `Encrypt(m)` differ (fresh `ρ`).
- **Modulus size**: `mpz_sizeinbase(N,2)==K` for K∈{1024,2048,3072}; `p!=q`;
  `CiphertextBytes()==ceil(2K/8)`. `[R2][R14]`
- **Wire encoding**: `SerializeCiphertext` produces exactly `ceil(2K/8)` bytes;
  the value round-trips via `mpz_import`. `[R13-r2]`
- **Nonce domain**: sampled `ρ` satisfies `gcd(ρ,N)==1`, `0<ρ<N`. `[R1-r2]`
- **Unsupported key size throws.**
- Suite now **14/14**.

**Do-not-touch.** `src/baselines/bcg12.*`, `baseline_engine.h`,
`summarize_results.py`.

**CMake log.** `option(PICCARD_ENABLE_GMP ON)`; `piccard_paillier` GMP-only lib;
baselines glob gets `CONFIGURE_DEPENDS` **and** `list(REMOVE_ITEM ... paillier.cpp)`
so it compiles once; `piccard_baselines` links `piccard_paillier`; one
`test_paillier` target (guarded `if(TARGET piccard_paillier)`). Reconfigure after
adding `paillier.cpp`. `[R7-r3][R15-r2]`

---

## Phase 2 — SJ16 protocol engine (parallel-safe), with unit tests

**Goal.** `PJSBaseline` implementation of Algorithm 1 (set setting, `n=1`) that
exposes its shares for testing and runs its `|U|` encryptions in parallel with
per-thread randomness.

**Scope.**
- New `include/baselines/sj16.h`, `src/baselines/sj16.cpp`
- New `tests/unit/test_sj16.cpp`
- `CMakeLists.txt`: add `test_sj16` target (guarded). **Shared-file edit — logged.**

**Surface — shares are observable `[R4]`.**
```cpp
struct SJ16Result {          // full protocol result; tests/harness read this
    mpz_class x1, x2;        // additive shares: (x1+x2) mod N == |X ∩ Y|
    uint64_t  intersection;  // reconstructed in the harness only (not by a party)
    QueryCost cost;          // timings + comm, for the benchmark
};

class SJ16 : public PJSBaseline {
public:
    SJ16(unsigned key_bits, bool precompute = false);

    const char* Name() const override { return "sj16"; }
    SecurityClass Security() const override { return SecurityClass::AHE_NoLeakage; }

    void Setup() override;                  // Paillier KeyGen; one-time
    void SetUniverse(uint32_t u);           // domain m=|U|; required before a query
    QueryCost RunQuery(const std::vector<uint64_t>& x,
                       const std::vector<uint64_t>& y) override;  // adapts RunProtocol().cost

    // richer entry point for tests + calibration:
    SJ16Result RunProtocol(const std::vector<uint64_t>& x,
                           const std::vector<uint64_t>& y);
    // test seam: force the mask instead of drawing it `[R5]`
    SJ16Result RunProtocolWithMask(const std::vector<uint64_t>& x,
                                   const std::vector<uint64_t>& y,
                                   const mpz_t r_mask);

    double MeasureEncryptMsMedian(size_t iters) const;   // for Phase 3
    void   PrepareRandomizerPool(size_t count);          // fill count=m+1 ρ^N `[R11-r2]`
};
```
`RunQuery` returns `RunProtocol(...).cost`; reconstruction of `intersection`
happens **in the harness**, matching design §7. `[R4]`

**Protocol steps (timed in the four `QueryCost` phases).**
1. **encode**: indicator `M1[i]=1 iff i∈dedup(X)`, `M2` likewise, over `[0,m)`.
   **Deduplicate inputs** and compute `|X|,|Y|` from the deduplicated sets so the
   indicator encoding and `|X|+|Y|−I` share one set semantics. Validate every
   element `< m`; else throw `out_of_range`. `[R6]`
2. **encrypt (P1, dominant, parallel)**: `Z[i]=Encrypt(M1[i])` for all `m`
   entries. Parallelized with `#pragma omp parallel for`; each thread uses
   `ThreadLocalCSPRNG()`. Thread count is pinned (design D4, resolved here). `[R1][R10]`
3. **compute (P2)**: `S = Π_{i∈dedup(Y)} Z[i]` via `AddCipher` (exponent 1, no
   `ScalarMul`). Then, with a single mask: draw `r_mask ← Z_N` from the CSPRNG;
   `x2 = (N − r_mask) mod N`; `S' = AddCipher(S, Encrypt(r_mask))`. `Encrypt`
   supplies its own fresh nonce `ρ`, so no separate `Enc(0)` rerandomization is
   used. `r_mask` (plaintext mask) and `ρ` (Paillier nonce) are distinct. `[R3]`
4. **decrypt (P1)**: `x1 = Decrypt(S')`; harness reconstructs
   `I = (x1 + x2) mod N`.
5. Fill `QueryCost`:
   - `jaccard_estimate = I / (|X|+|Y|−I)` (`1.0` if union 0).
   - **Communication = sum of actually-produced wire buffers `[R13-r3]`**:
     serialize every uploaded `Z[i]` and the response `S'` with
     `SerializeCiphertext`, and **sum the returned buffer lengths** —
     `ct_size_bytes = Σ_{i<m} len(Z[i])` (P1→P2 upload),
     `comm_bytes = ct_size_bytes + len(S')` (adds the P2→P1 response). Do not
     compute it as `m × CiphertextBytes()`; that product is emitted only as the
     **theoretical cross-check** `(m+1)·2K/8`, which coincides with the sum
     because the encoding is fixed-width — a coincidence disclosed against the
     variable-length OpenFHE serialization Piccard rows use. Record the two
     directions separately. Key/framing/setup traffic excluded and stated. Not
     the BFV `3×ct` formula. `[R13-r3]`

**Precompute mode `[R11-r2]`.** A query needs `m` indicator encryptions **plus
one** for the `r_mask` — so `PrepareRandomizerPool(m+1)` fills `m+1` fresh `ρ^N
mod N^2` values before the timed region. Consumption is via an atomic index so
parallel encrypt threads each take a distinct `ρ`; each value is used **exactly
once**; the pool is refilled to `m+1` before every measured query. An assertion
fires on exhaustion or reuse. This is the weaker "precompute `ρ^N` only" variant,
explicitly distinguished from the paper's stronger "precompute `Enc(0)`,
`Enc(1)`" suggestion. Offline pool build time + memory recorded separately
(Phase 4). `[R11-r2]`

**Verify.** `ctest -R SJ16` green (K=1024, small m=256):
- **Exactness** over ≥20 random (X,Y): `(x1+x2) mod N == |X∩Y|` (cleartext). `[R4]`
- **Forced-mask identity `[R5]`**: `RunProtocolWithMask` with
  `r_mask ∈ {0, 1, N−1}` gives `x1=(I+r_mask) mod N`, `x2=(N−r_mask) mod N`,
  `(x1+x2) mod N == I`, both shares in `[0,N)`. (The `r_mask=0` case shows
  `x1=I` is a *valid* execution — so "shares ≠ I" is NOT asserted.)
- **Freshness**: two default `RunProtocol` calls on the same input yield
  different `x1` (fresh mask). Secrecy/uniformity is treated as an RNG +
  code-review property, not a unit assertion. `[R5]`
- **Edge cases `[R6]`**: empty/empty, empty/nonempty, disjoint, identical,
  full-universe, singleton, duplicate elements in input (dedup), unset/zero
  universe throws, repeated `Setup`, repeated queries.
- **Jaccard exact**: `|jaccard_estimate − J_true| == 0`.
- **comm accounting**: `ct_size_bytes == m·ceil(2K/8)`;
  `comm_bytes == (m+1)·ceil(2K/8)`; serialized ciphertext round-trips. `[R13-r2]`
- **precompute**: `PrepareRandomizerPool(m+1)` then a query consumes exactly
  `m+1` values with no reuse; exhaustion asserts. `[R11-r2]`
- Suite now **15/15**.

**Do-not-touch.** Same as Phase 1.

**CMake log.** One added test target (guarded).

---

## Phase 3 — Thread policy, calibration & a fitted cost model

**Goal.** Pin the thread budget for both protocols, and validate the design's
extrapolation with a *fitted* linear model per key size — not a
per-encryption-times-`m` guess. This gates the right to extrapolate. `[R9][R10]`

**Scope.**
- New `benchmarks/bench_sj16_calibrate.cpp` (own CLI; not a ctest — minutes-long).
- `CMakeLists.txt`: one guarded `add_executable`. **Shared-file edit — logged.**

**Thread policy (resolve before any measurement) `[R10]`.**
1. Pick a fixed physical-thread budget `P` (e.g. `OMP_NUM_THREADS=8` on the
   M1 Max's performance cores) applied identically to Piccard and SJ16 runs.
2. Record actual thread count in the calibration output and the results table.
3. Report **both** single-thread and matched-`P`-thread SJ16 numbers if scaling
   is materially non-linear, so the comparison cannot be accused of a threading
   artifact.

**Cost-model fit `[R9]`.** For each `K ∈ {1024, 2048, 3072}`:
1. Measure full `RunProtocol` at **≥3 universe sizes** plus **one held-out
   size**. To keep `K=3072` tractable, use small sizes for the fit
   (e.g. `2^12, 2^13, 2^14`) with held-out `2^15`; `K=1024` can add larger
   points cheaply. Report per-size dispersion (median ± IQR over trials).
2. Fit `T(m) = α·m + β` by least squares (the additive-sum expectation is a
   fitted slope `α`, not `median_enc × m`). `[R9]`
3. **Residual gate (mathematical)**: prediction error on the held-out size
   `|T_measured − (α·held + β)| / T_measured < τ` with `τ = 0.10`. Emit `α, β,
   R², held-out residual`. If the gate fails at any `K`, extrapolation for that
   `K` is **not** authorized and design D3 must be revised. `[R9]`
4. **Paper cross-check (descriptive, not pass/fail) `[R9]`**: report measured
   `K=1024` ms/encryption next to SJ16's 2.57 ms and the machine ratio as
   context — it is not an acceptance criterion.
5. Write `results/sj16_calibration_<host>.txt` with all fits + thread count.

**Verify.**
- Builds clean; tool runs; existing ctest unaffected (15/15).
- A fit exists for every reported `K` **including `K=3072`**, each with its
  held-out residual < τ and dispersion reported. `[R9]`
- Thread count is pinned and recorded. `[R10]`

**Do-not-touch.** Same. `results/` is git-ignored (`c2d4b51`).

**CMake log.** One `add_executable` line.

---

## Phase 4 — Register in bench_comparison via an SJ16-owned adapter

**Goal.** SJ16 appears as a `method=sj16` row, **opt-in**, with the shared-file
diff held to an include + four config fields + four SJ16 integration points
(caller-owned construct/`Setup()` outside the loop, `SetUniverse(u)` per
universe, per-trial `RunSJ16OnTrial` collection, post-loop `FinalizeSJ16`). `[R16-r3]`

**Scope.**
- New `benchmarks/sj16_adapter.h` — owns `RunSJ16OnTrial` (per-trial timing),
  `FinalizeSJ16` (`SJ16Trial`s → aggregated `ComparisonResult`), and the
  extrapolation-boundary logic.
  It reuses the exact `(set_a,set_b)` the universe loop produces
  (`bench_comparison.cpp:882-884`). A measured trial returns an **adapter-owned
  record** — not a bare `QueryCost`, which has no `j_true` and so cannot yield a
  mean error (the round-3 regression): `[R16-r3]`
  ```cpp
  struct SJ16Trial { QueryCost cost; double j_true; };  // retains truth for error

  // one measured trial (called inside the existing per-trial loop):
  SJ16Trial RunSJ16OnTrial(SJ16& eng, const std::vector<uint64_t>& set_a,
                           const std::vector<uint64_t>& set_b, double j_true);
  // aggregate the trials into the published row: median timing + per-trial
  // dispersion + mean error = mean|cost.jaccard_estimate − j_true|, mirroring
  // RunMultiTrial* and benchmark-stats dispersion:
  ComparisonResult FinalizeSJ16(const std::vector<SJ16Trial>& trials, uint32_t u,
                                const std::string& scenario);
  ```
  **Engine ownership**: the `SJ16` engine is constructed + `Setup()` **once by
  the shared-file call site, outside the universe loop**, then passed by
  reference to `RunSJ16OnTrial`; the adapter never constructs it. **Heavy code
  (timing, aggregation, extrapolation boundary) lives in the adapter.** `[R16-r3]`
- `benchmarks/bench_comparison.cpp` — exact shared diff, honestly inventoried
  (**not "three fields"**) `[R16-r2]`:
  - `#include "sj16_adapter.h"` under `#ifdef HAVE_SJ16`;
  - **four** `ComparisonConfig` fields (`sj16`, `sj16_key_bits`,
    `sj16_max_universe`, `sj16_precompute`) + their **four parser cases** in
    `ParseArgs` + **four help lines**;
  - one `SJ16` construct + `Setup()` **outside** the universe loop (engine
    caller-owned);
  - one `SetUniverse(u)` per universe iteration (inside the universe loop,
    before the trial loop);
  - one `RunSJ16OnTrial(...)` call **inside** the existing per-trial loop
    (reusing that loop's `(set_a,set_b)`, accumulating `SJ16Trial`s);
  - one `FinalizeSJ16(...)` call after the loop to emit the aggregated row.
- `CMakeLists.txt`: link `piccard_baselines` into `bench_comparison` + define
  `HAVE_SJ16` (only when `PICCARD_ENABLE_GMP`). **Shared-file edit — logged.**

**Steps.**
1. CLI (extend `ComparisonConfig::ParseArgs`): `--sj16` (default off),
   `--sj16_key_bits=K` (default 3072), `--sj16_max_universe=N` (default 65536,
   the measure/extrapolate boundary), `--sj16_precompute` (default off, drives
   the D5 sensitivity row). `[R11]`
2. Guard **all** SJ16 code with `#ifdef HAVE_SJ16` so the binary still builds
   with GMP absent.
3. The **shared-file call site** constructs `SJ16(key_bits, precompute)` and
   calls `Setup()` **once, outside the universe loop** (keygen is per-K, not
   per-trial/universe), then per scenario calls `SetUniverse(u)`. The **adapter**
   does the per-trial work (`RunSJ16OnTrial`, incl. `PrepareRandomizerPool(m+1)`
   before each measured query in precompute mode) and the aggregation
   (`FinalizeSJ16`, mapping to `ComparisonResult{method="sj16"}`). `SecurityClassOf`
   already returns `AHE/no-leakage` (`:135,:138`) — **no edit there**. `[R11-r2][R16-r3]`
4. Respect `QuickSweep` on the universe sweep (`:826`): SJ16 runs on the same
   sampled `u` set, and reuses each trial's `(set_a,set_b)` — no independent
   data generation. `[R8][R16-r2]`
5. For `u > sj16_max_universe`: **do not silently skip** — log to stderr that
   the row is left for the Phase-3 fitted model and print the `(α,β)` needed to
   reproduce it. No new CSV column (keeps the shared schema stable). `[R9]`
6. **Labeling `[R12]`**: the row/table caption states "SJ16: shares of
   intersection cardinality; secure division excluded — optimistic lower bound",
   not "end-to-end Jaccard".

**Verify.**
- `cmake --build build -j8` clean; GMP present ⇒ `HAVE_SJ16` defined; **15/15**.
- **Opt-in smoke** (K=1024, small U):
  ```
  ./build/bench_comparison --mode=timing --security=TOY --trials=1 \
      --universe=16384 --sj16 --sj16_key_bits=1024 --sj16_max_universe=16384
  ```
  CSV has a `sj16` row: `security_class=AHE/no-leakage`, non-zero
  `phase_encrypt_ms`, `jaccard_error≈0`, `comm_bytes==Σserialized+serialized(S')`.
- **Regression (schema/row-set under a fixed seed, not byte-identity) `[R15]`**:
  run with `--seed=<fixed>` with and without `--sj16`; assert the non-`--sj16`
  run produces the **same set of `(scenario,method)` rows and identical CSV
  columns** as the pre-Phase-4 binary. Timings will differ run-to-run — do not
  assert byte identity.
- **Precompute path exists `[R11]`**: `--sj16 --sj16_precompute` runs and emits a
  row; offline pool time/memory recorded to stderr.
- **GMP-absent build `[R15-r2]`**: fresh build dir configured with
  `-DPICCARD_ENABLE_GMP=OFF` (a real option that skips the `find_*(GMP)` block —
  not `NOTFOUND` cache entries that `find_*` can re-discover), rebuild;
  `bench_comparison` still links (SJ16 compiled out; `HAVE_SJ16` undefined). An
  actual build, not "reason via the guard".

**Do-not-touch.** `SecurityClassOf` (already correct), `src/baselines/bcg12.*`,
`baseline_engine.h`, `summarize_results.py`.

**CMake log.** One `target_link_libraries` addition + one
`target_compile_definitions(... HAVE_SJ16)`, worded to match the BCG12 branch.

---

## Cross-phase notes

- **Merge order.** We merge last; the shared-file diff (test targets, one link
  line, one include, **four** config fields + their four parser cases + four
  help lines, one caller-owned construct/`Setup()` outside the loop, one
  `SetUniverse(u)` per universe, one per-trial `RunSJ16OnTrial` call, one
  post-loop `FinalizeSJ16` call)
  is deliberately small so the rebase onto BCG12 + benchmark-stats is a
  contained diff. `[R16-r3]`
- **Thread parity** (design D4) is resolved in Phase 3 **before** measurement,
  and appears in the Definition of Done — not deferred. `[R10]`
- **Handoff items (do not fix here):**
  - `piccard.tex:790` SJ16 leakage wording (shares hidden, not "receiver
    learns");
  - Table I `O(|U|)` footnote (holds for `n=1`);
  - **Lower-bound label consumer `[R12-r2]`.** The "intersection-sharing only;
    secure division excluded" caption is prose in this spec; it must land in an
    actual artifact. Assigned owners: (a) the paper comparison-table caption in
    `piccard.tex` (§IV, paper-writing task); (b) `summarize_results.py` (owned by
    `benchmark-stats`) must both stop dropping `sj16` **and** carry the label
    into the emitted table. **Acceptance test (run post-merge by the
    `benchmark-stats` owner):** feed a CSV containing an `sj16` row through
    `summarize_results.py` and assert the generated table T13 contains the
    `sj16` row *and* the lower-bound caption. Until that passes, the revision may
    not claim the row is integrated.
  - ZLG+24 baseline fidelity (R3-5).

## Definition of done (all phases)

1. `cmake --build build -j8` clean with GMP present; HEAD-based anchors current
   (`4bd7459`). `[R8]`
2. `ctest` green: 13 original + `Paillier` + `SJ16` = **15/15**. `[R8]`
3. Calibration: a fitted `T(m)=αm+β` per `K` **including `K=3072`**, each with
   held-out residual < 0.10 and dispersion reported; thread count pinned and
   recorded. `[R9][R10]`
4. `bench_comparison --sj16` emits a valid `sj16` row (comm = actual serialized
   bytes, both directions); `--sj16_precompute` path works; default run's
   row-set/schema unchanged under a fixed seed; GMP-absent build still links via
   a real fresh configure. `[R11][R13][R15]`
5. Row/table labeled "intersection-sharing only; secure division excluded". `[R12]`
6. No edits to other branches' files; shared-file edits ≤ the logged minimum,
   heavy code in `sj16_adapter.h` / `src/baselines/sj16.*`. `[R16]`
