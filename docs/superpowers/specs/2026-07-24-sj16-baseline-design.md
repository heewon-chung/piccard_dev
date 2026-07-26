# SJ16 comparison baseline — design

- Branch: `tkde-major/implement-sj16`
- Review item: **R2-W1** (roadmap **P1-6(a)**)
- Base commit: **`4bd7459`** — merge-order #1 (`benchmark-stats`) and #2
  (`hash-seed-crs`) are both merged in (rebased 2026-07-26); the tree has
  **13 tests**, `QuickSweep` sweeps, per-trial dispersion, and a public MinHash
  CRS seed (orthogonal to SJ16, which uses no MinHash). (Design first written at
  `01a75ac`; the phased plan carries the live anchors.)
- Status: **design + phased plan; phased plan reviewed once (gpt-5.6-sol, high)
  and revised — see rev. 2 of the phases doc.**

## 1. Goal

Implement Samanthula & Jiang's SJCM protocol (`SJ16`) as a second comparison
baseline for Piccard, so the evaluation contains a protocol in *the same
security class* as Piccard (no during-execution leakage) rather than only the
weaker KPA-secure ZLG+24 baseline. R2's objection is that a 128× headline
against a weaker baseline "conflates a security-level difference with a
performance win"; this branch supplies the same-class comparison point.

Reference: B. K. Samanthula and W. Jiang, "Secure multiset intersection
cardinality and its application to Jaccard coefficient," *IEEE Trans.
Dependable Secur. Comput.*, 13(5):591–604, 2016.

## 2. Verified starting state

Re-confirmed at `01a75ac` before planning:

- `cmake -S . -B build && cmake --build build -j8` — clean.
- `ctest` — **12/12 pass**.
- GMP 6.3.0 present at `/opt/homebrew/lib/libgmp.dylib`.
- `include/baselines/pjs_baseline.h` — interface and `SecurityClass` enum exist.
- `bench_comparison.cpp:124` — `SecurityClassOf()` already maps `"sj16"` to
  `AHE/no-leakage`.

### Correction to the branch brief

The brief states that adding a file under `src/baselines/` is enough ("파일만
추가하면 자동으로 잡힌다"). That is true for the `piccard_baselines` *library*
target (glob at `CMakeLists.txt:139`) but **not** for the benchmark binary:

- `CMakeLists.txt:240` is `target_link_libraries(bench_comparison piccard_fhe)`
  — `piccard_baselines` is not linked. Registering SJ16 requires a CMake edit,
  on a line shared with `tkde-major/implement-bcg12`.
- `scripts/summarize_results.py:350-351` hardcodes `methods.get("piccard")` and
  `methods.get("baseline")`. A new `sj16` CSV row is emitted but **silently
  dropped from tables T10–T14**. (`piccard_sqrt` is currently dropped for the
  same reason.) That file is owned by another branch — handoff item, see §9.

## 3. Protocol specification (from the source, not the abstract)

Algorithm 1, p.596; Observation 5.1 and §5.1, p.595.

Notation: `m` = element domain size (= our `universe_size`, `|U|`), `n` = max
element frequency, `K` = Paillier key size in bits.

**Frequency matrix.** `M_i` has size `m × n`. Row `i` is a *unary* encoding of
the multiplicity of element `i`:

```
M_1[i][j] = 1  for 0 <= j < f_{D1}(i)
          = 0  for f_{D1}(i) <= j < n
```

**Key identity** (Observation 5.1): `M_1[i] • M_2[i] = min(f_1(i), f_2(i))`,
hence `|D1 ∩ D2| = Σ_{i=0}^{m-1} M_1[i] • M_2[i]`  (Eq. 4).

**Execution** (Algorithm 1):

| Step | Party | Work |
|---|---|---|
| (a) | P1 | `Z[i][j] = E_pk(M_1[i][j])` for all `m·n` entries; send to P2 |
| (b) | P2 | `S_i = Π_{j : M_2[i][j] ≠ 0} Z[i][j]^{M_2[i][j]}` |
| (c) | P2 | `S = Π_i S_i`; pick random `r ∈ Z_N` |
| (d) | P2 | `x_2 = N − r`; `S' = S · E_pk(r)`; send `S'` to P1 |
| (e) | P1 | `x_1 = D_sk(S')` |

Output: additive shares with `x_1 + x_2 mod N = |D1 ∩ D2|`. **Neither party
learns the cardinality itself.**

Costs (§5.1): P1 does `O(m·n)` encryptions, P2 does `O(m·n)` modular
multiplications, communication is `O(K·m·n)` bits.

### Specialization to the set setting — `n = 1`

Piccard is compared in the set setting, so max frequency `n = 1`:

- The `m × n` frequency matrix collapses to a **length-`|U|` binary indicator
  vector**. This is exactly the `O(|U|)` computation/communication row that
  Table I of `piccard.tex` already attributes to SJ16.
- Entries of `M_2` are binary, so step (b) needs **no exponentiation** — it is a
  product of the ciphertexts at P2's own set positions, i.e. `|D2|` modular
  multiplications. Negligible.
- **`SJCM_apr` (§6) degenerates to `SJCM`.** Its column count is
  `t = ⌈w_1/w_0⌉`, which is `1` when `w_1 = n = 1`. The approximate variant is
  therefore not implemented, and this is stated with justification rather than
  silently skipped.
- Because SJ16's cost is `m·n`, `n = 1` is the **cheapest possible
  configuration for SJ16** — we benchmark it at its most favourable setting.

Essentially the entire protocol cost is P1's `|U|` Paillier encryptions plus the
`|U|`-ciphertext upload.

## 4. Decisions

### D1 — AHE scheme: Paillier

Settled by the source, not a judgement call. §3.2, p.593: *"Any HEnc⁺ system is
applicable, but this paper adopts Paillier's scheme for the actual
implementation due to its efficiency, particularly when the plaintext values are
small."* Exponential ElGamal would require discrete-log extraction (BSGS) at
decryption, a deviation from the original.

Implementation uses the standard `g = 1 + N` form: `c = (1 + mN) · r^N mod N²`.

### D2 — Security parameter: `K = 3072` headline, `2048` / `1024` alongside

Paillier rests on factoring, BFV on lattices, so the levels must be mapped
rather than compared directly. Per NIST SP 800-57 Part 1 Rev. 5:

| `K` | symmetric-equivalent | role |
|---|---|---|
| 1024 | ~80-bit | SJ16's own setting — **calibration anchor** |
| 2048 | ~112-bit | SJ16's larger setting |
| **3072** | **~128-bit** | **matches Piccard STD128 — headline row** |

Wording (per review finding 14): the 3072-bit mapping is stated as "nominal
128-bit classical strength using the RSA/IFC modulus-size proxy" — NIST's IFC
table is for RSA/IFC, not a formal Paillier/DCRA equivalence, and neither side's
assumptions nor post-quantum posture are claimed equal. Piccard's BFV uses
`HEStd_128_classic` (`src/fhe/bfv_context.cpp:25`). KeyGen must assert
`bitlen(N)==3072`.

The `K = 1024` row exists so our implementation can be checked against the
original paper's reported numbers (§6). This pre-empts, for SJ16, the fidelity
objection R3-5 raised about the ZLG+24 baseline.

### D3 — Measurement boundary: measure `2^14`, `2^16`; extrapolate `2^18`, `2^20`

SJ16's cost is `T(|U|) = |U|·t_enc(K) + |D2|·t_mul(K) + t_dec` — exactly linear
and data-independent, with none of the `ring_dim`-jump discontinuities that make
BFV extrapolation risky. Procedure (**strengthened per review finding 9** — a
fitted slope, not `median_enc × m`):

1. For each reported `K` (**including `K=3072`**), measure full-query time at
   **≥3 universe sizes plus one held-out size** (median ± IQR over trials).
2. Fit `T(m) = α·m + β` by least squares; report `α, β, R²`.
3. **Residual gate**: held-out prediction error < 10%; if it fails at any `K`,
   extrapolation for that `K` is not authorized.
4. Derive `2^18`, `2^20` from the fitted model; mark those cells `†` with a
   footnote naming the held-out residual.
5. The `median_enc × m` figures in §5 are a sanity anchor only; the paper ratio
   in §6 is descriptive, not a pass/fail criterion.

Communication needs no extrapolation at all — the upload is `|U|·2K/8` bytes and
the total (upload + one response ciphertext) is `(|U|+1)·2K/8`, exact. The
benchmark *measures* it by summing the produced wire buffers (plan finding 13),
with this closed form as the cross-check.

**Any reduced range must be visible in the table.** Silently truncating would
read as full-range measurement, which is the very failure mode R2/R3 flagged.

### D4 — Thread count: fixed and stated for both protocols

Piccard is currently measured with OpenMP at the default thread count (MinHash
in `src/core/minhash.cpp`, plus OpenFHE's internal parallelism). SJ16's `|U|`
encryptions are embarrassingly parallel and benefit more, so leaving this
implicit is not defensible. `OMP_NUM_THREADS` will be pinned explicitly, applied
to both protocols, and recorded in the results table. **Resolved in phased-plan
Phase 3, before any measurement, and in the Definition of Done — not deferred**
(review finding 10): pick a fixed physical-thread budget `P`, apply it to both
protocols, record the actual count, and report single-thread plus matched-`P`
SJ16 numbers if scaling is materially non-linear. SJ16's `|U|` encryptions are
parallelized with a per-thread CSPRNG (finding 1). The post-`noise-flooding`
re-measurement reuses this pinned value.

### D5 — Offline randomness precomputation: not in the main row, reported as a sensitivity row

SJ16 §8.4 ("Directions for performance improvement") suggests precomputing
encryptions of constants offline, citing Damgård et al., but the paper's own
measurements do not use it (their 70.15 min at `m=20K, n=80, K=1024` implies
online encryption).

- **Main row**: no precomputation — faithful to what SJ16 measured, and the
  precondition for the `K=1024` calibration check.
- **Sensitivity row**: online cost given a precomputed `r^N` pool. With
  precomputation an encryption becomes one modular multiplication:
  17.892 ms → 7.660 µs, a ~2300× online speedup. Omitting this invites the
  reviewer objection that the baseline was crippled.
- The paper text must note that precomputation shifts work offline **without
  changing throughput** — each query consumes `|U|+1` fresh randomisers (`|U|`
  indicator encryptions plus one for the `r_mask`), so the pool must be refilled
  at the query rate. Only single-query latency improves.
- Communication (48 MB at `|U|=2^16`, `K=3072`) is untouched by any of this.

## 5. Measured unit costs (M1 Max, GMP 6.3.0, single thread)

Scratchpad measurement, no repo changes:

```
K=1024: encrypt 0.925 ms | modmul 1.353 µs | ct 256 B
K=2048: encrypt 7.099 ms | modmul 4.312 µs | ct 512 B
K=3072: encrypt 17.892 ms | modmul 7.660 µs | ct 768 B
```

Projected per query at `K = 3072`, single-threaded:

| `\|U\|` | P1 encryption | upload |
|---|---|---|
| 2^14 | 4.9 min | 12 MB |
| 2^16 | 19.5 min | 48 MB |
| 2^18 | 78 min † | 192 MB |
| 2^20 | 5.2 h † | 768 MB |

† extrapolated per D3.

## 6. Cross-check against the original paper

Two independent data points from SJ16 §8:

- Table 3 (`m=20K`, `w_1=80`, `K=1024`): 70.15 min, 409.6 MB.
  `m·n = 1.6M` encryptions → **2.63 ms/encryption**; 409.6 MB / 1.6M = 256 B per
  ciphertext = `2K` bits. ✓
- §8.2 (`m=5K`, `n=20`, `K=1024`): 4.29 min over `100K` encryptions →
  **2.57 ms/encryption**. ✓

Our M1 Max figure of 0.925 ms at `K=1024` is 2.8× faster than their 2010-era
Xeon 3.07 GHz — plausible, and the cost model reproduces. The implementation
must reproduce the same relationship; this is an acceptance criterion (§8).

## 7. Interface mapping

```
Name()     -> "sj16"
Security() -> SecurityClass::AHE_NoLeakage
Setup()    -> Paillier keygen (K bits) + t_enc calibration; excluded from query cost
RunQuery() -> phase_encode  : build the length-|U| indicator vectors
              phase_encrypt : P1's |U| Paillier encryptions        <- dominant
              phase_compute : P2's product accumulation + rerandomisation
              phase_decrypt : P1's single decryption + share reconstruction
```

Two asymmetries that must be documented rather than papered over:

- **Communication.** `QueryCost::comm_bytes` is documented as "2× upload + 1×
  result download" because both parties encrypt in the BFV baselines. SJ16 is
  genuinely asymmetric: only P1 uploads `|U|` ciphertexts, P2 returns one.
  **Measured as actual serialized Paillier bytes** (review finding 13) for
  parity with how Piccard rows measure `CiphertextSizer::GetSerializedSize`, and
  reported per direction (P1→P2 upload, P2→P1 one-ciphertext response); the
  theoretical closed form `(|U|+1)·2K/8` is emitted alongside. Key/framing/setup
  traffic is excluded and stated as such. Not the BFV `3×ct` formula.
- **Party model.** SJ16 is a two-party protocol; Piccard is delegated
  (three-party). Both are reported as total protocol wall-clock and total bytes
  on the wire, with the model difference stated in §IV-A of the paper.

**Accuracy.** SJ16 computes the intersection exactly ("SJCM always yields 100
percent accuracy", §8.3). Its error column is 0. Piccard's advantage is speed
and communication, not accuracy, and the table must show that plainly.

`jaccard_estimate` is reconstructed as `x_1 + x_2 mod N`, then
`J = I / (|X| + |Y| − I)`. Reconstruction happens in the harness, outside the
protocol, for accuracy checking only — a deployed SJCM would run a secure
division protocol on the shares, whose cost we exclude. **The SJ16 row/table is
therefore labeled "shares of intersection cardinality; secure division excluded
— optimistic lower bound", not "end-to-end Jaccard"** (review finding 12). That
exclusion favours SJ16 and is stated as such.

## 8. Work order

1. `include/baselines/paillier.h`, `src/baselines/paillier.cpp` — GMP Paillier
   (keygen / encrypt / decrypt / homomorphic add / scalar mul, `g = 1+N`).
2. `tests/unit/test_paillier.cpp` — roundtrip, additive homomorphism, scalar
   multiplication, ciphertext size.
3. `include/baselines/sj16.h`, `src/baselines/sj16.cpp` — `PJSBaseline`
   implementation following Algorithm 1 step for step.
4. `tests/unit/test_sj16.cpp` — on small random sets: `x_1 + x_2 mod N` equals
   `|X ∩ Y|` exactly; Jaccard matches the cleartext value; forced-mask identity
   (`r_mask ∈ {0,1,N−1}`) and cross-run freshness. (**Not** "neither share
   equals the cardinality" — `x_1=I` is a valid execution when `r_mask=0`;
   secrecy is an RNG/code-review property, per review finding 5.)
5. **Calibration check** — run `K=1024` at the paper's `m=5K, n=20` conditions
   and record ms/encryption against their 2.57 ms. Acceptance: same order,
   consistent with the machine gap.
6. `bench_comparison.cpp` registration behind an opt-in `--sj16` flag (default
   off, so `run_benchmarks.sh` does not silently become an hours-long run), plus
   `--sj16_max_universe=N` for the D3 measure/extrapolate boundary and
   `--sj16_key_bits=K`.
7. CMake: link `piccard_baselines` into `bench_comparison` and add the
   `HAVE_PICCARD_BASELINES` compile definition. Written to match the BCG12
   branch's wording so the shared lines conflict as little as possible.

## 9. Out of scope — observations to hand off

- **`piccard.tex:790` is factually wrong about SJ16.** It says "The receiver
  still learns |x∩y|, |x∪y|, and |y|". SJCM outputs additive shares and the
  paper explicitly states the Jaccard value "should be hidden from both
  parties". A reviewer can catch this. Table I's leakage column (`✗`) is fine.
- Table I lists SJ16's computation as `O(|U|)`, which holds for sets (`n=1`);
  the multiset general form is `O(|U|·n)`. A one-line footnote would be exact.
- `scripts/summarize_results.py` comparison tables hardcode `piccard`/`baseline`
  and drop any other method — affects `sj16`, `bcg12`, and `piccard_sqrt`.
  Owned by `tkde-major/benchmark-stats`. **Not edited here.**
- R3-5 context: `benchmarks/baseline_engine.h` chunks a universe-sized binary
  vector by `ring_dim` and does a full rotate-and-sum per chunk; it does not
  reproduce ZLG+24's k-d tree optimisation. The reviewer's fidelity concern
  looks well founded. Not this branch's scope; not touched.

## 10. Risks

- **Merge order.** This branch merges last, so `bench_comparison.cpp` and the
  CMake link line will likely need a rebase onto BCG12's versions. Mitigation:
  keep everything possible inside `src/baselines/sj16.*`; hold shared-file edits
  to single lines.
- **Re-measurement invalidation.** `noise-flooding` invalidates all timing and
  communication numbers. SJ16's figures are therefore provisional until the
  post-merge measurement pass; the thread-count decision (D4) should be fixed
  before that pass, not after.
- **Runtime.** Even with the D3 boundary, the `K=3072` measured range costs
  roughly 25 min of single-threaded work per trial across `2^14`+`2^16`.
  Parallelism (D4) and trial count need to be settled before the final run.
