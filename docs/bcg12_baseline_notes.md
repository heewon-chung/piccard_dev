# BCG12 baseline — implementation notes

Working notes for the BCG12 (EsPRESSo, arXiv:1111.5062v5) comparison
baseline, built on top of `include/baselines/group.h`. This file now covers
the full implementation: the group-arithmetic foundation (the abstract
`Group` interface and its two backends, Phase 0), the DGT12 PSI-CA protocol
and the `BCG12`/`PJSBaseline` wrapper with benchmark integration (Phases
1–3), and paper-ready provenance/analysis for items 1–6 (Phase 4, below).

## Group parameter provenance (Task 0.5)

### Finite-field backend: DSA-style `Z_p^*`, `|p|=3072`, `|q|=256`

The FF backend (`src/baselines/group_ff.cpp`) ships fixed domain parameters
`p`, `q`, `g` generated once on the dev machine (2026-07-26, OpenSSL 3.6.3),
using the exact commands whose output was pasted into the source file as hex
constants:

```bash
openssl genpkey -genparam -algorithm DSA \
  -pkeyopt dsa_paramgen_bits:3072 -pkeyopt dsa_paramgen_q_bits:256 -out dsa3072.pem
openssl pkeyparam -in dsa3072.pem -text   # copy P, Q, G into hex constants
```

`dsa_paramgen_bits:3072` and `dsa_paramgen_q_bits:256` produce **DSA-style**
domain parameters: a 3072-bit prime `p` with a 256-bit prime subgroup order
`q` such that `q | (p-1)`, and a generator `g` of that order-`q` subgroup.
This is deliberately **not** a safe prime (`p = 2q'+1` with `q'` prime):
a safe prime's cofactor is only 2, so its "subgroup order" would be
`(p-1)/2 ≈ 3071` bits, not the 256-bit order this protocol's security
argument (and its exponent/point size accounting) assumes.

Verified 2026-07-26 that this exact `openssl genpkey -genparam -algorithm
DSA -pkeyopt dsa_paramgen_bits:3072 -pkeyopt dsa_paramgen_q_bits:256`
invocation runs cleanly on the dev machine (OpenSSL 3.6.3) and produces
valid params in ~1 second.

Before being pasted into `group_ff.cpp`, the generated `p`, `q`, `g` were
independently re-verified in Python (Miller-Rabin, 40 rounds, outside GMP)
to satisfy all of the required properties:

- `p` is prime, bit length exactly 3072.
- `q` is prime, bit length exactly 256.
- `q | (p-1)`.
- `1 < g < p`, `g != 1`.
- `g^q mod p == 1` (i.e. `g` generates a subgroup of order dividing `q`;
  combined with `q` prime and `g != 1`, `g`'s order is exactly `q`).

`FFGroup::ValidateParams()` (`src/baselines/group_ff.cpp`) re-checks, with
GMP, that `p` and `q` are prime (`mpz_probab_prime_p`, 40 rounds), that
`q | (p-1)`, that `1 < g < p`, and that `g^q mod p == 1` — four of the
five Python-verified properties. It does **not** re-check the 3072/256-bit
lengths of `p`/`q` at construction time (those are fixed by the length of
the hardcoded hex constants, not re-measured), so a corrupted or mistyped
constant that happens to preserve primality/subgroup structure would still
pass `ValidateParams()`.

### Elliptic-curve backend: NIST P-256

The EC backend (`src/baselines/group_ec.cpp`) uses OpenSSL's built-in
`NID_X9_62_prime256v1` (NIST P-256) curve parameters directly — no
generation step is needed since these are standard, widely-audited domain
parameters (FIPS 186-5 / NIST SP 800-186; FIPS 186-4 originally specified
P-256 but was withdrawn in 2024). P-256 has cofactor 1, so every on-curve,
non-infinity point is a valid group element of the full prime order.

### Security-level justification

| Backend | Parameters | Security level | Source |
|---|---|---|---|
| FF `Z_p^*` (this branch) | `\|p\|=3072, \|q\|=256` | 128-bit | NIST SP 800-57 Pt.1 Rev.5, Table 2: 128-bit security ⇒ `L=3072, N=256` for FFC (DSA/DH-style) parameters |
| EC P-256 (this branch) | NIST P-256 | 128-bit | FIPS 186-5 / NIST SP 800-186 (FIPS 186-4 was the original, now-withdrawn, source); standard 256-bit-order curve, ~128-bit security |
| BCG12 paper's original (EsPRESSo, §3.3) | `\|p\|=1024, \|q\|=160` | ~80-bit | Superseded parameter choice at time of the original construction (arXiv 2011, v5 2013; journal version J. Computer Security 22(3), 2014) |

Both backends target the modern 128-bit security level (NIST SP 800-57
Pt.1 Rev.5, Table 2), which is two nominal NIST security tiers above the
paper's original 1024/160 (~80-bit) choice (NIST's tiers run 80, 112,
128-bit) — chosen so the BCG12 comparison
in the paper is not artificially advantaged by outdated, weaker parameters.
`P-256` is the modern/fastest-reasonable secondary backend; the FF
`Z_p^*` backend at `3072/256` is the primary backend because it is
faithful to BCG12's own cost model (the paper is expressed in terms of
modular exponentiations over `Z_p^*`).

(This is item 1 of Phase 4 — DEC-3. No further group-size material is
added below; §"Security-level justification" above is the single source
of truth for the FF/EC choice and its NIST SP 800-57 basis.)

## Phase 4 — paper-ready provenance & analysis

### 2. Trust model: BCG12 (2-party) vs. Piccard (3-party outsourced) — corrected (DEC-2)

**The distinction is trust model + required per-query interaction + data
custody — not a false "BCG12 has no reusable precomputation" claim.**
EsPRESSo (BCG12) itself states (§2.2, §3.3) that DGT12 PSI-CA admits
reusable **offline** `O(|A|+|B|)` work: each item's `HashToGroup` call
(`H(a_i)` for Alice, `H(b_j)` for Bob — the `hash_to_group_ms` component
of `PsiCaCost`, measured once *before* the three masking rounds in
`RunDgt12`, `src/baselines/dgt12_psica.cpp`) depends only on the item
itself, not on which counterparty it is later compared against. Once an
owner has group-hashed their own elements, that work is reusable across
*any number* of subsequent PSI-CA sessions against *any* counterparty —
it is not re-derived per query.

What actually differs between the two protocols is:

- **Trust model.** BCG12/DGT12 is a genuine **2-party** protocol (per-variant
  `ModelOf()` in `benchmarks/bench_comparison.cpp` reports `"2-party"`
  for every `bcg12_*` row): Alice and Bob interact directly; plaintext sets
  never leave either owner's machine, and only masked group elements /
  32-byte tags cross the wire. There is no third party at all, trusted or
  untrusted.
- **Required per-query interaction.** Every single PSI-CA execution needs
  **both data owners online simultaneously**, exchanging the 3-message
  DGT12 flow (Alice → Bob masked elements; Bob → Alice re-masked elements
  + his own tags; Alice unmasks and matches) — even when each side's
  `HashToGroup` step has already been amortized away, the masking-exponentiation
  rounds (`alice_round1_ms`, `bob_ms`, `alice_round2_ms`) are inherently
  interactive and must be re-run live for every comparison. Piccard is
  **3-party outsourced**: the two data owners upload FHE ciphertexts once
  and then go offline; an untrusted server performs all subsequent
  per-query computation on stored ciphertexts without either owner present.
- **Data custody.** BCG12 never stores anyone's data with a third party —
  masked elements are ephemeral, single-session artifacts. Piccard's server
  persistently custodies encrypted representations of both parties' sets
  between queries.

**Cold vs. amortized/online cost, reported separately** (STD128, `k=128`,
`vary_universe` sweep, committed code `3edde48`,
`docs/bcg12_std128_measured.csv`,
`trials=3`, medians). "Cold total" = full `QueryCost.total_ms` (all four
phases). `phase_encode_ms` (a real CSV column) is the MinHash sketch + item
encoding + `HashToGroup` for every item; for the FF backend it is almost
entirely `HashToGroup` (one 3072-bit modexp per item — the sketch/encode part
is sub-millisecond). "Online rounds" = the three interactive masking rounds,
computed as `phase_encrypt_ms_median + phase_compute_ms_median +
phase_decrypt_ms_median` (verified against the CSV, e.g. `73.279 + 153.010 +
78.735 = 305.02 ≈ 305.0` for `\|U\|=16384` FF), i.e. what a returning pair
of data owners with already-hashed items still pays live per query. **This
"Online rounds" column, and the "Cold/online ratio" column derived from it,
are sum-of-medians proxies**, not the median of each trial's own
`(phase_encrypt+phase_compute+phase_decrypt)` total — a sum of per-phase
medians is not in general equal to the median of the paired per-trial
online sum, so treat both columns as an approximation rather than an exact
statistic. (We report `phase_encode_ms` rather than an isolated
`hash_to_group_ms`: the latter is instrumented inside `PsiCaCost` but is
not a column of the comparison CSV, so quoting it here would be a
misattribution — for FF, `phase_encode_ms` *is* hash-dominated to within a
sub-ms sketch/encode term.)

| Universe `\|U\|` | Backend | Cold total (ms) | `phase_encode_ms` (hash-dominated) | Online rounds (ms) | Cold/online ratio |
|---|---|---:|---:|---:|---:|
| 16384 | FF | 1998.0 | 1693.7 | 305.0 | 6.6× |
| 16384 | EC | 42.9 | 13.2 | 29.6 | 1.4× |
| 65536 | FF | 1990.5 | 1674.5 | 307.4 | 6.5× |
| 65536 | EC | 33.8 | 11.9 | 21.6 | 1.6× |
| 262144 | FF | 1982.9 | 1653.8 | 333.3 | 5.9× |
| 262144 | EC | 35.6 | 13.9 | 21.6 | 1.6× |
| 1048576 | FF | 1968.4 | 1649.5 | 311.9 | 6.3× |
| 1048576 | EC | 39.0 | 15.4 | 21.6 | 1.8× |

For the FF backend, `phase_encode_ms` (dominated by one 3072-bit modular
exponentiation per item in `HashToGroup`, `group_ff.cpp`) is ~83–85% of the
cold total, so amortizing it away matters a great deal: FF's *online* per-query
cost (~305–333 ms) is ~16× Piccard's standalone steady-state per-query cost
(~19–20 ms per the paper's isolated Piccard measurement; see the item-4 caveat
on the in-sweep Piccard numbers) — far better than the ~100× that FF's cold
total (~1980 ms ÷ ~19–20 ms) implies. For
the EC backend, `HashToGroup` (try-and-increment; compressed-coordinate
recovery does compute a P-256 field square root, which *is* a field
exponentiation, but it is cheap relative to the FF path) avoids the two
expensive operations FF pays for — no 3072-bit cofactor exponentiation and
no group scalar multiplication — so cold and online numbers are close and
both remain in the tens-of-ms range. This feeds reviewer point R2-W5/P1-7: the fair statement is
"BCG12 can amortize per-item hashing, but not the live 2-party interaction," not
"BCG12 has no precomputation reuse at all."

### 3. Accuracy parity: same pre-bucketing MinHash family; Piccard's bucketing adds collision variance, not a retained bias

Fig. 3 (BCG12's MinHash-approximate mode) and Piccard draw their bottom-`k`
MinHash signatures from the **same shared pre-bucketing MinHash family**
(the `k` min-hashes computed from the common CRS — see item 6), compared
by per-position equality: `\hat{J} = |\{i : sig_x[i] = sig_y[i]\}| / k`.
This identity is proven bit-for-bit by
`tests/unit/test_bcg12.cpp::Bcg12.MinHashMatchesPlaintextEstimator`, which
asserts `BCG12::RunQuery(...).jaccard_estimate == piccard::MinHasher::EstimateJaccard(...)`
on the plaintext reference implementation — not an approximate/statistical
match, an exact `EXPECT_DOUBLE_EQ`. The phrase "same estimator" is
reserved for this shared *pre-bucketing* MinHash family; the one-hot
bucketing described below is a **Piccard-only post-step** applied after
the shared signature is computed, and is not what the identity test
covers.

At **equal `k`**, BCG12's `Setup()` builds its `MinHasher` with
`hash_range = UINT64_MAX` (`src/baselines/bcg12.cpp:48`) — the unbucketed
full-range signature, matched by exact tag equality inside DGT12 PSI-CA.
Piccard's live protocol path (`Piccard::KeyGen`, `src/protocol/piccard.cpp:17-19`
— not `src/protocol/piccard_engine.cpp`, which is not among the FHE sources
`bench_comparison` builds against) also computes an
unbucketed MinHash signature (`params_.hash_range` defaults to
`UINT64_MAX` too), but then feeds it through `OneHotEncoder::Encode`
(`include/core/onehot_encoder.h:15`) before the FHE inner-product step:
`feature[i*m + sig[i] % m] = 1` — i.e. Piccard's homomorphically computed
*raw* matched-count reduces each of the `k` signature values mod `m`
(`m=64` in the STD128 benchmark configuration) into one of `m` one-hot
buckets, so two distinct signature values that happen to collide mod `m`
are counted as a match. **Under ideal minwise-independent hashing and
independent, uniform mod-`m` collisions** — the fixed affine-hash MinHash
CRS (`src/core/minhash.cpp`, item 6) *approximates* but does not guarantee
these idealizing assumptions — in expectation the raw matched-ratio is
`E[raw] = J + (1−J)/m`, i.e. an upward collision bias of `(1−J)/m` on the
*raw* matched-ratio (at most `1/m`, reached at `J=0`; `≈ 1/96 ≈ 0.0104` at
`J=1/3, m=64`, not `1/64`) — and it is precisely why `RunPiccardTimed`
(`benchmarks/bench_comparison.cpp:279`) applies the correction
`j_hat = (raw_ratio - 1/m) / (1 - 1/m)`, which is data-independent and,
under those same idealizing assumptions, maps `E[raw]` back to `J` exactly
(`(J + (1−J)/m − 1/m)/(1 − 1/m) = J`), before
reporting `jaccard_computed`. **Piccard's reported estimator therefore
applies this correction and is unbiased in expectation — it does not retain
a collision bias.** What the correction does *not* remove is the
**additional collision variance/noise** the bucketing introduces: a
bucket collision between two distinct MinHash values is still a random
event layered on top of the base MinHash sampling randomness, and
correcting the mean does not shrink that extra source of spread.
BCG12's exact tag-equality matching has no analogue of this term.
Consequently, **at equal `k`, and under the stated independence
assumptions, BCG12's Fig.-3 estimator variance is ≤ Piccard's** (stated as
an inequality under that assumption, not as a proven strict inequality) —
Piccard's variance is the same base MinHash sampling variance plus this
extra collision-variance term from one-hot bucketing.

This is stated honestly as a **theoretical/code-level** claim, backed by
the identity test and by reading the two encoding paths above — it is
*not* re-derived as a rigorous empirical variance comparison, because
item 4's `trials=3` table is still far too few trials to resolve a
variance difference this small. The measured mean `jaccard_error` is
nonetheless *consistent* with the theoretical claim: at
`vary_universe_16384/65536/262144/1048576` (`k=128`, `set_size=1000`,
`jaccard_expected=0.333333`), Piccard's mean `jaccard_error` over 3 trials
is `0.042328 / 0.047619 / 0.047619 / 0.044974` while BCG12 (both backends,
which report **identical** `jaccard_computed` at every universe size,
confirming group-backend choice doesn't affect the matched count) reports
`0.041667 / 0.038194 / 0.030382 / 0.042535` — BCG12's mean |error| is ≤
Piccard's at all four sizes, the direction the "same base MinHash sampling
variance plus an extra one-hot collision-variance term for Piccard"
argument predicts, though `n=3` is far too few to be conclusive. The
definitive evidence is a high-`n` paired dispersion comparison (via
`ComputeDispersion`, as `INTEGRATION_NOTES.md`'s accuracy-mode analysis
already does for Piccard alone at `n=550`/cell); running that same paired
analysis for BCG12 is future work, not claimed here.

### 4. Measured comparison table (STD128, `vary_universe`, `k=128`) — PROVISIONAL

Source: `docs/bcg12_std128_measured.csv`,
committed code `3edde48`, **`trials=3`** per row, medians with sample SD.
Fig. 3 (MinHash, `bcg12_mh_ff` / `bcg12_mh_ec`) is the primary equal-accuracy
comparison against Piccard, same `k`, same MinHash CRS (item 6). Fig. 2 exact
(`bcg12_exact_ff` / `bcg12_exact_ec`, `O(n)`, no MinHash — see `vary_size_*`
rows in the CSV) is scaling context only, never a like-for-like accuracy
comparison, per DEC-1. `baseline`/ZLG+24 (one HE multiplication plus
`O(log|U|)` rotations/additions per query, `O(|U|)`-scaling encoding and
communication — see item 6/R3-5 below, `benchmarks/baseline_engine.h`) is included
for context, not as a same-security-class comparison (it is `KPA/leakage`,
not `AHE/no-leakage` or `CPA/no-leakage`). Note on the `AHE/no-leakage`
label itself: `AHE_NoLeakage` (`SecurityClass`, `pjs_baseline.h`) and the
paper's Table I "AHE" crypto-primitive column are the paper's own
classification of BCG12/DGT12; the concrete construction implemented here
is DH-based and secure under DDH in the random-oracle model (blind
exponentiation), not additively-homomorphic encryption — see the DEC-4
Table I erratum (item 5) for the full note.

| `\|U\|` | Method | Model | total_ms median (±SD) | comm_bytes | jaccard (comp / expected) |
|---|---|---|---:|---:|---|
| 16384 | piccard | 3-party-outsourced | 60.2 (±3.4) | 789033 | 0.291005 / 0.333333 |
| 16384 | bcg12_mh_ff | 2-party | 1998.0 (±79.1) | 102400 | 0.291667 / 0.333333 |
| 16384 | bcg12_mh_ec | 2-party | 42.9 (±5.6) | 12544 | 0.291667 / 0.333333 |
| 16384 | baseline (ZLG+24) | 3-party-outsourced | 121.2 (±2.5) | 1575465 | 0.333333 / 0.333333 |
| 65536 | piccard | 3-party-outsourced | 58.5 (±3.6) | 789033 | 0.322751 / 0.333333 |
| 65536 | bcg12_mh_ff | 2-party | 1990.5 (±41.0) | 102400 | 0.328125 / 0.333333 |
| 65536 | bcg12_mh_ec | 2-party | 33.8 (±3.9) | 12544 | 0.328125 / 0.333333 |
| 65536 | baseline (ZLG+24) | 3-party-outsourced | 475.4 (±39.7) | 6294057 | 0.333333 / 0.333333 |
| 262144 | piccard | 3-party-outsourced | 103.2 (±11.8) | 789033 | 0.333333 / 0.333333 |
| 262144 | bcg12_mh_ff | 2-party | 1982.9 (±99.1) | 102400 | 0.330729 / 0.333333 |
| 262144 | bcg12_mh_ec | 2-party | 35.6 (±9.2) | 12544 | 0.330729 / 0.333333 |
| 262144 | baseline (ZLG+24) | 3-party-outsourced | 1579.3 (±352.4) | 25168425 | 0.333333 / 0.333333 |
| 1048576 | piccard | 3-party-outsourced | 220.5 (±49.6) | 789033 | 0.346561 / 0.333333 |
| 1048576 | bcg12_mh_ff | 2-party | 1968.4 (±15.2) | 102400 | 0.346354 / 0.333333 |
| 1048576 | bcg12_mh_ec | 2-party | 39.0 (±11.3) | 12544 | 0.346354 / 0.333333 |
| 1048576 | baseline (ZLG+24) | 3-party-outsourced | 4421.8 (±64.1) | 100665897 | 0.333333 / 0.333333 |

**Key story, read from the actual numbers above (not from the plan's
predictive "Estimated runtimes" model, which used a simplified
`ms/op × op-count` formula and is superseded by these measured rows):**

- **Communication (the robust, reproducible result).** `comm_bytes` for
  every non-baseline method is constant across `\|U\|` in this sweep (it
  depends on `k`/`set_size`, not universe size): Piccard 789033 B,
  `bcg12_mh_ff` 102400 B, `bcg12_mh_ec` 12544 B. `bcg12_mh_ec`'s comm is
  `789033 / 12544 ≈ 62.9×` **less** than Piccard's — matches the "~60×
  less communication" figure from DEC-1. `bcg12_mh_ff`'s comm is
  `789033 / 102400 ≈ 7.7×` less than Piccard's. The *BCG12* comm figures
  (12544 / 102400 B — serialized group elements + 32-byte tags) carry no FHE
  and no measurement noise, so they are stable and safe to cite as-is;
  Piccard's 789033 B, by contrast, is three serialized BFV ciphertexts and
  **will change when `noise-flooding` merges** (larger modulus ⇒ larger
  ciphertexts), so the ratios above are provisional on the Piccard side.
- **BCG12 timing is stable and universe-independent, as designed.**
  `bcg12_mh_ec` medians are 33.8–42.9 ms and `bcg12_mh_ff` 1968–1998 ms
  across all four universe sizes (no trend with `\|U\|`, small SD relative
  to the FF magnitude). These are the trustworthy BCG12 numbers.
- **The in-sweep Piccard column is contaminated — do NOT read a clean
  speedup from it.** Piccard's per-query cost is *designed* to be
  universe-size-independent (`ring_dim` is driven by `k·m`, not `\|U\|`),
  yet its measured median here climbs with `\|U\|`: ~59–60 ms at the two
  smaller universes (60.2, 58.5 — flat within noise), then 103.2 and 220.5 ms
  at `\|U\|=2^18` and `2^20` (SD also grows, to ±49.6 ms at `\|U\|=2^20`).
  The **most plausible** explanation is a benchmark-structure confounder,
  not an intrinsic Piccard cost: in `BenchVaryUniverse` the universe-sized
  `baseline` engine (up to 100.7 MB of ciphertext at `\|U\|=2^20`) is
  constructed and exercised in the *same* per-trial loop as Piccard, so
  memory/cache pressure from the giant co-scheduled baseline is a
  plausible source of the inflated Piccard timing at large `\|U\|`. This is
  not established causality, though — the CSV and code here only show the
  correlation between `\|U\|` and Piccard's measured median; an isolated,
  controlled rerun of Piccard alone (no co-scheduled `baseline`) is
  required to confirm memory/cache pressure is actually the cause before
  this is stated as fact. Piccard's true standalone steady state is
  ~19–20 ms (paper Table `tbl:comp`, measured in isolation). **Therefore
  this table's Piccard column overstates Piccard's cost, and the honest
  reading is: BCG12's numbers are clean; Piccard must be re-measured in
  isolation before any
  paper-facing "Piccard vs. BCG12" time ratio is quoted.** Even against
  the (inflated) in-sweep Piccard, `bcg12_mh_ec` is faster at every size;
  against Piccard's true ~19–20 ms standalone, `bcg12_mh_ec` (~34–43 ms)
  and Piccard are the same order of magnitude — consistent with DEC-1's
  "comparable time," with BCG12's decisive advantage being communication.
- `bcg12_mh_ff` (faithful-but-slower, dominated by 3072-bit modular
  exponentiation) is the slow variant on cold total (~100× Piccard's
  standalone steady state), but only ~16× on the amortizable/online number
  (item 2) — its disadvantage is concentrated almost entirely in the amortizable
  `HashToGroup` step, not the interactive protocol.
- `baseline`/ZLG+24 is included only for scale context: not the same
  security class, and both its `total_ms` and `comm_bytes` grow with `\|U\|`
  (as expected for an `O(\|U\|)`-communication, universe-sized-vector
  protocol) — 121 ms/1.58 MB at `\|U\|=16384` up to 4422 ms/100.7 MB at
  `\|U\|=1048576`.

**This table is marked PROVISIONAL.** Per `INTEGRATION_NOTES.md` (§"PHASE 4
RESULTS", which records that timing/communication numbers are re-measured
after `noise-flooding` merges, citing merge-order section `"머지 순서"`;
`00_shared_context.md`, if present in your checkout, has the fuller
merge-order table but is untracked and not guaranteed to exist in a clean
checkout), all timing/communication numbers across
every branch are re-measured after the `noise-flooding` branch merges.
BCG12 uses no FHE, so its *absolute* numbers (the `bcg12_*` rows above)
are noise-flooding-independent and stable. Piccard's numbers are not —
noise-flooding changes Piccard's FHE cost, and (per the previous bullet)
the in-sweep Piccard numbers are additionally inflated by co-scheduled
baseline memory pressure — so the **Piccard-vs-BCG12 speedup/ratio columns
must be regenerated post-merge, with Piccard measured in isolation**, even
though the BCG12-side numbers feeding those ratios will not change. The
`trials=3` medians here carry SD; re-run with `trials≥5` at merge time for a
tighter, more stable dispersion estimate (more trials sharpen the precision
of the SD estimate itself, not the underlying spread of the measurements).

### 5. Table I erratum (DEC-4) — for merge-time, not edited here

`piccard.tex:299`'s comparison table (`\label{tbl:comparison}`) has a
single row for `\cite{BCG12}`:

```
\cite{BCG12}  & $\bigO{n}$ exp. & $\bigO{n}$ & Minhash & AHE & $\bsym{\times}$\\
```

This conflates two different protocols from the BCG12/EsPRESSo paper into
one row: the `$O(n)$` computation/communication figures are Fig. 2's
**exact** Jaccard protocol (raw sets, no MinHash, cost linear in the
underlying set size `n` — not universe size), while the "Minhash" tool
column names Fig. 3's **approximate** protocol (MinHash signatures, cost
`O(k)` in the signature length, independent of `n`). No single row can
correctly describe both variants at once — the row as written is only
accurate for Fig. 2 in its computation/communication columns and only
accurate for Fig. 3 in its "Main tools/data structures" column. Separately,
the row's "AHE" crypto-primitive column is also the paper's own
classification (matching the `AHE_NoLeakage` enum label used in this
codebase, item 1 above), not a description of the concrete DGT12
construction, which is DH-based/DDH-in-the-ROM rather than
additively-homomorphic encryption. This is an **erratum** to fix at merge
time (the paper's `\ours` row already correctly separates Piccard's own
MinHash+one-hot mechanism from its complexity figures); `piccard.tex`
itself is intentionally **not edited** by this branch — this is a note
for the integrator, per the plan's scope discipline.

### 6. R3-5 observation on `baseline_engine.h` fidelity, and the cross-branch MinHash-CRS dependency

**`benchmarks/baseline_engine.h` (ZLG+24 baseline) fidelity risk.** The
ZLG+24 paper's headline complexity is `O(|U| log n)` SHE ops using a
**k-d tree** to prune the comparison (per `piccard.tex:299`'s own
`\cite{ZLG+24}` row: `$\bigO{\len{\calU}\log{n}}$ SHE ops`, `k-d tree`).
`baseline_engine.h`'s actual implementation
(`BaselineEngine::ComputeJaccard` → `ComputeInnerProduct` → `RotateAndSum`,
`benchmarks/baseline_engine.h:146-203`) is a **universe-sized indicator-vector
encoding plus a homomorphic inner product realized as rotate-and-sum**
(`log2(N)` rotations to accumulate all slots into slot 0) — there is
**no k-d-tree-based pruning/matching** anywhere in this implementation.
This is a legitimate, working SHE baseline (and its own doc comment at the
top of the file is honest about this: "encodes sets as binary vectors of
dimension `U_set`"), but it is **not** a faithful reimplementation of
ZLG+24's asymptotic `O(|U| log n)` computation — with `ring_dim ≥ |U|`, its
per-query HE-*operation* count is one homomorphic multiplication plus
`O(log|U|)` rotations/additions (`RotateAndSum`'s `log2(N)` loop), not
`O(|U|)` HE ops and not the paper's claimed `O(log n)` factor either. What
actually scales `O(|U|)` here is the **encoding, ciphertext size, and
communication** (the universe-sized indicator vector and the ciphertext(s)
that carry it) — not the HE-operation count. This is a fidelity risk the
integrator should be aware of before citing this baseline's measured
numbers as representative of ZLG+24 specifically (as opposed to "an
`O(|U|)`-encoding/communication SHE-based baseline in the same family").
Flagged per R3-5; not fixed here — `baseline_engine.h` is out of this
branch's scope (Global Constraints: "Do not modify... the *runtime
behavior* of `benchmarks/baseline_engine.h`").

**Cross-branch MinHash-CRS dependency (`hash-seed-crs`, already merged).**
BCG12's MinHash mode sources its `minhash_seed` from
`PiccardParams{}.hash_seed` (default `42`, `include/util/params.h:24`),
not a hardcoded literal — see `benchmarks/bench_comparison.cpp`:
`bp_ff.minhash_seed = PiccardParams{}.hash_seed;   // CRS parity`. This
means Piccard and BCG12 provably share the same public common reference
string for the hash family `H`, which is a precondition for item 3's
"same estimator" claim to be meaningful (two engines computing MinHash
signatures under *different* CRSs would not be comparable at all, same
estimator or not). Note that `include/util/params.h` only *holds* the
`hash_seed` field — the actual CRS derivation (expanding the seed into
the per-hash coefficients `H = ((a_i,b_i))_{i=1..k}`) lives in
`src/core/minhash.cpp` (`MinHasher`'s constructor / `ExpandHashSeed`), so
that file, not `params.{h,cpp}`, is what to consult (or watch for
changes) if the CRS-derivation *algorithm* itself is ever revised. There
are two independent things that must line up, and they have different
owners: (1) the **derivation algorithm** — both Piccard and BCG12 already
construct their signatures through the same shared `MinHasher` class, so
they track the *same* derivation automatically regardless of what
`hash_seed` value is used; and (2) the **default-seed value** — parity on
`42` specifically only holds because BCG12 reads
`PiccardParams{}.hash_seed` rather than hardcoding the literal `42`, so a
change to that default in `params.{h,cpp}` (`hash-seed-crs`'s owned
files) automatically keeps both sides' *default* in sync too. Worth one
line in `INTEGRATION_NOTES.md` at merge time so `hash-seed-crs`'s owners
know a second branch now depends on their default.

## Status

Phase 0 complete: `Group` interface, `TagHash`, item encoders
(`EncodeRawItem`/`EncodeTaggedItem`), the FF backend, and the EC backend
are implemented and unit-tested (`ctest -R Group`).

Phases 1–3 complete: DGT12 PSI-CA (Fig. 1, `src/baselines/dgt12_psica.cpp`),
the `BCG12 : PJSBaseline` wrapper (Exact/MinHash modes × FF/EC backends,
`src/baselines/bcg12.cpp`), and `bench_comparison` integration
(per-variant rows `bcg12_mh_ff`/`bcg12_mh_ec`/`bcg12_exact_ff`/`bcg12_exact_ec`)
are implemented and unit-tested (`ctest -R "Group|Dgt12PsiCa|Bcg12"`).

Phase 4 (this revision) complete: paper-ready provenance and analysis
above (group-size justification, 2-party-vs-3-party trust model with cold/
amortized costs, accuracy parity, measured comparison table marked
PROVISIONAL pending `noise-flooding`, Table I erratum note, R3-5
`baseline_engine.h` fidelity observation, and the cross-branch MinHash-CRS
dependency). Final self-check: clean build, 16/16 `ctest` passing, scope
check clean (`NO_FORBIDDEN`, `SHARED_EDITS_OK` against `START_SHA=4bd7459`).
This branch's implementation work is complete.
