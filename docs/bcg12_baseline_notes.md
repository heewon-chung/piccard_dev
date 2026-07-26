# BCG12 baseline — implementation notes

Working notes for the BCG12 (EsPRESSo, arXiv:1111.5062v5) comparison
baseline, built on top of `include/baselines/group.h`. Phase 0 (this file)
covers only the group-arithmetic foundation: the abstract `Group` interface
and its two backends. Protocol-level notes (DGT12 PSI-CA, the `BCG12`
`PJSBaseline` wrapper, benchmark integration) land here in later phases.

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

`FFGroup::ValidateParams()` (`src/baselines/group_ff.cpp`) re-checks the
same five properties with GMP (`mpz_probab_prime_p`, 40 rounds) at every
construction, so a corrupted or mistyped constant fails fast at startup
rather than silently degrading security.

### Elliptic-curve backend: NIST P-256

The EC backend (`src/baselines/group_ec.cpp`) uses OpenSSL's built-in
`NID_X9_62_prime256v1` (NIST P-256) curve parameters directly — no
generation step is needed since these are standard, widely-audited domain
parameters (FIPS 186-4). P-256 has cofactor 1, so every on-curve,
non-infinity point is a valid group element of the full prime order.

### Security-level justification

| Backend | Parameters | Security level | Source |
|---|---|---|---|
| FF `Z_p^*` (this branch) | `\|p\|=3072, \|q\|=256` | 128-bit | NIST SP 800-57 Pt.1 Rev.5, Table 2: 128-bit security ⇒ `L=3072, N=256` for FFC (DSA/DH-style) parameters |
| EC P-256 (this branch) | NIST P-256 | 128-bit | FIPS 186-4; standard 256-bit-order curve, ~128-bit security |
| BCG12 paper's original (EsPRESSo, §3.3) | `\|p\|=1024, \|q\|=160` | ~80-bit | Superseded parameter choice at time of publication (2011) |

Both backends target the modern 128-bit security level (NIST SP 800-57
Pt.1 Rev.5, Table 2), which is one full security-level step above the
paper's original 1024/160 (~80-bit) choice — chosen so the BCG12 comparison
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
`vary_universe` sweep, `.superpowers/sdd/2026-07-26-implement-bcg12-baseline/std128_measured.csv`,
`trials=1` — see item 4 for the trials caveat). "Cold total" = full
`QueryCost.total_ms` including `HashToGroup` for every item; "amortized/online"
= the same total *minus* `hash_to_group_ms`, i.e. what a returning pair of
data owners with already-hashed items still has to pay live per query:

| Universe `\|U\|` | Backend | Cold total (ms) | `hash_to_group_ms` | Amortized/online (ms) | Cold/online ratio |
|---|---|---:|---:|---:|---:|
| 16384 | FF | 1973.421 | 1664.518 | 308.903 | 6.4× |
| 16384 | EC | 27.034 | 5.460 | 21.575 | 1.3× |
| 65536 | FF | 1964.839 | 1650.150 | 314.688 | 6.2× |
| 65536 | EC | 40.668 | 15.009 | 25.658 | 1.6× |
| 262144 | FF | 2057.557 | 1713.611 | 343.946 | 6.0× |
| 262144 | EC | 36.854 | 7.946 | 28.908 | 1.3× |
| 1048576 | FF | 1977.368 | 1647.479 | 329.888 | 6.0× |
| 1048576 | EC | 43.429 | 21.838 | 21.592 | 2.0× |

For the FF backend, `HashToGroup` (one 3072-bit modular exponentiation per
item, `group_ff.cpp`) is ~84% of the cold total, so amortizing it away
matters a great deal: FF's *online* per-query cost (~309–344 ms) is only
~4× Piccard's steady-state per-query cost (see item 4), not the ~20–30×
the cold number suggests. For the EC backend, `HashToGroup` (try-and-increment,
no modular exponentiation) is already cheap, so cold and amortized numbers
are close and both backends' amortized costs remain in the tens-of-ms range.
This feeds reviewer point R2-W5/P1-7: the fair statement is "BCG12 can
amortize per-item hashing, but not the live 2-party interaction," not
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
Piccard's engine (`src/protocol/piccard_engine.cpp:12`) also computes an
unbucketed MinHash signature (`params_.hash_range` defaults to
`UINT64_MAX` too), but then feeds it through `OneHotEncoder::Encode`
(`include/core/onehot_encoder.h:15`) before the FHE inner-product step:
`feature[i*m + sig[i] % m] = 1` — i.e. Piccard's homomorphically computed
*raw* matched-count reduces each of the `k` signature values mod `m`
(`m=64` in the STD128 benchmark configuration) into one of `m` one-hot
buckets, so two distinct signature values that happen to collide mod `m`
are counted as a match. That collision is exactly the standard
birthday-style `1/m` upward bias on the *raw* matched-ratio — and it is
precisely why `RunPiccardTimed` (`benchmarks/bench_comparison.cpp:279`)
applies the standard bias correction, `j_hat = (raw_ratio - 1/m) / (1 -
1/m)`, before reporting `jaccard_computed`. **Piccard's reported estimator
therefore applies this correction and is unbiased in expectation — it does
not retain a `1/m` bias.** What the correction does *not* remove is the
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
*not* re-derived as an empirical variance comparison in item 4's table,
because that table is `trials=1` per row and carries no dispersion
statistics (`ComputeDispersion` needs `n>1`; the CSV's `*_sd` columns are
sentinel `-1.000` for single-trial rows). The single-trial CSV numbers are
nonetheless *consistent* with the theoretical claim: at
`vary_universe_16384/65536/262144/1048576` (`k=128`, `set_size=1000`,
`jaccard_expected=0.333333`), Piccard's single-trial `jaccard_error` is
`0.007937 / 0.055556 / 0.031746 / 0.015873` while BCG12 (both backends,
which report **identical** `jaccard_computed` at every universe size,
confirming group-backend choice doesn't affect the matched-count) reports
`0.018229 / 0.052083 / 0.020833 / 0.005208` — mixed sign of who is closer
on any single trial, exactly what "same base variance plus an extra
collision-variance term that only matters in expectation/over many
trials" predicts. A proper multi-trial dispersion comparison (via
`ComputeDispersion`, as `INTEGRATION_NOTES.md`'s accuracy-mode analysis
already does for Piccard alone) is future work, not claimed here.

### 4. Measured comparison table (STD128, `vary_universe`, `k=128`) — PROVISIONAL

Source: `.superpowers/sdd/2026-07-26-implement-bcg12-baseline/std128_measured.csv`,
**`trials=1`** per row (no dispersion available; see item 3). Fig. 3 (MinHash,
`bcg12_mh_ff` / `bcg12_mh_ec`) is the primary equal-accuracy comparison
against Piccard, same `k`, same MinHash CRS (item 6). Fig. 2 exact
(`bcg12_exact_ff` / `bcg12_exact_ec`, `O(n)`, no MinHash — see `vary_size_*`
rows in the CSV) is scaling context only, never a like-for-like accuracy
comparison, per DEC-1. `baseline`/ZLG+24 (`O(|U|log n)` SHE inner product,
`benchmarks/baseline_engine.h`) is included for context, not as a
same-security-class comparison (it is `KPA/leakage`, not `AHE/no-leakage`
or `CPA/no-leakage`).

| `\|U\|` | Method | Model | total_ms (cold) | comm_bytes | jaccard (comp / expected) |
|---|---|---|---:|---:|---|
| 16384 | piccard | 3-party-outsourced | 93.962 | 789033 | 0.341270 / 0.333333 |
| 16384 | bcg12_mh_ff | 2-party | 1973.421 | 102400 | 0.351562 / 0.333333 |
| 16384 | bcg12_mh_ec | 2-party | 27.034 | 12544 | 0.351562 / 0.333333 |
| 16384 | baseline (ZLG+24) | 3-party-outsourced | 134.096 | 1575465 | 0.333333 / 0.333333 |
| 65536 | piccard | 3-party-outsourced | 71.832 | 789033 | 0.277778 / 0.333333 |
| 65536 | bcg12_mh_ff | 2-party | 1964.839 | 102400 | 0.281250 / 0.333333 |
| 65536 | bcg12_mh_ec | 2-party | 40.668 | 12544 | 0.281250 / 0.333333 |
| 65536 | baseline (ZLG+24) | 3-party-outsourced | 517.108 | 6294057 | 0.333333 / 0.333333 |
| 262144 | piccard | 3-party-outsourced | 68.152 | 789033 | 0.301587 / 0.333333 |
| 262144 | bcg12_mh_ff | 2-party | 2057.557 | 102400 | 0.312500 / 0.333333 |
| 262144 | bcg12_mh_ec | 2-party | 36.854 | 12544 | 0.312500 / 0.333333 |
| 262144 | baseline (ZLG+24) | 3-party-outsourced | 1728.699 | 25168425 | 0.333333 / 0.333333 |
| 1048576 | piccard | 3-party-outsourced | **380.144 (outlier — see below)** | 789033 | 0.317460 / 0.333333 |
| 1048576 | bcg12_mh_ff | 2-party | 1977.368 | 102400 | 0.328125 / 0.333333 |
| 1048576 | bcg12_mh_ec | 2-party | 43.429 | 12544 | 0.328125 / 0.333333 |
| 1048576 | baseline (ZLG+24) | 3-party-outsourced | 4467.247 | 100665897 | 0.333333 / 0.333333 |

**Key story, read from the actual numbers above (not from the plan's
predictive "Estimated runtimes" model, which used a simplified
`ms/op × op-count` formula and is superseded by these measured rows):**

- `comm_bytes` for every method is constant across `\|U\|` in this sweep
  (it depends on `k`/`set_size`, not universe size): Piccard 789033 B,
  `bcg12_mh_ff` 102400 B, `bcg12_mh_ec` 12544 B. `bcg12_mh_ec`'s comm is
  `789033 / 12544 ≈ 62.9×` **less** than Piccard's — matches the "~60×
  less communication" figure from DEC-1. `bcg12_mh_ff`'s comm is
  `789033 / 102400 ≈ 7.7×` less than Piccard's.
- **Timing:** at the three non-outlier universe sizes (16384/65536/262144),
  `bcg12_mh_ec`'s cold `total_ms` (27.0 / 40.7 / 36.9 ms) is actually
  **faster** than Piccard's (94.0 / 71.8 / 68.2 ms) in this single-trial
  measurement — 1.8×–3.5× faster, not merely "comparable time" as the
  plan's predictive DEC-1 model estimated (~19 ms Piccard vs. ~24 ms EC).
  The measured Piccard steady-state total is ~68–95 ms, not ~19–20 ms;
  the DEC-1 figure was a theoretical per-op estimate from the plan's
  "Estimated runtimes" table, not a measured number, and should be treated
  as superseded by this table for any paper-facing claim. `bcg12_mh_ff`
  (faithful-but-slower, dominated by 3072-bit modular exponentiation) is
  ~20–30× slower than Piccard on the cold total, but only ~4× slower on
  the amortized/online number from item 2's table — the FF backend's
  disadvantage is concentrated almost entirely in the amortizable
  `HashToGroup` step, not the interactive protocol itself.
- The **`\|U\|=1048576` Piccard row (380.144 ms) is a clear outlier**
  against Piccard's own ~68–95 ms steady state at the other three
  universe sizes in this same sweep (driven by `phase_compute_ms=325.807`,
  vs. 47–83 ms at the other three rows) — almost certainly single-trial
  system noise (a scheduling stall, thermal/frequency-scaling event, or
  similar), not a real universe-size effect, since Piccard's per-query
  cost is designed to be universe-size-independent (`ring_dim` here is
  driven by `k·m`, not `\|U\|`). **Do not use this row's Piccard number
  in any paper-facing "Piccard vs. BCG12" comparison without re-measuring
  with `trials>1`.**
- `baseline`/ZLG+24 is included only for scale context: it is not the
  same security class, and both its `total_ms` and `comm_bytes` grow with
  `\|U\|` (as expected for an `O(\|U\|)`-communication, universe-sized-vector
  protocol) — 134 ms/1.58 MB at `\|U\|=16384` up to 4467 ms/100.7 MB at
  `\|U\|=1048576`.

**This table is marked PROVISIONAL.** Per `INTEGRATION_NOTES.md` and
`00_shared_context.md` §머지 순서, all timing/communication numbers across
every branch are re-measured after the `noise-flooding` branch merges.
BCG12 uses no FHE, so its *absolute* numbers (the `bcg12_*` rows above)
are noise-flooding-independent and stable. Piccard's numbers are not —
noise-flooding changes Piccard's FHE cost — so the **Piccard-vs-BCG12
speedup/ratio columns in this table must be regenerated post-merge**,
even though the BCG12-side numbers feeding those ratios will not change.
Re-run with `trials≥5` (per `benchmark_utils.h`'s `ComputeDispersion`) at
that point to also replace the single-trial numbers above with numbers
that carry real dispersion statistics, resolving the item-3 caveat that
this table currently has none.

### 5. Table I erratum (DEC-4) — for merge-time, not edited here

`piccard.tex:299`'s comparison table (`\label{tbl:comparison}`) has a
single row for `\cite{BCG12}`:

```
\cite{BCG12}  & $\bigO{n}$ exp. & $\bigO{n}$ & Minhash & AHE & $\bsym{\times}$\\
```

This conflates two different protocols from the BCG12/EsPRESSo paper into
one row: the `$O(n)$` computation/communication figures are Fig. 2's
**exact** Jaccard protocol (raw sets, no MinHash, cost linear in the
underlying set/universe size `n`), while the "Minhash" tool column names
Fig. 3's **approximate** protocol (MinHash signatures, cost `O(k)` in the
signature length, independent of `n`). No single row can correctly
describe both variants at once — the row as written is only accurate for
Fig. 2 in its computation/communication columns and only accurate for
Fig. 3 in its "Main tools/data structures" column. This is an **erratum**
to fix at merge time (the paper's `\ours` row already correctly separates
Piccard's own MinHash+one-hot mechanism from its complexity figures);
`piccard.tex` itself is intentionally **not edited** by this branch —
this is a note for the integrator, per the plan's scope discipline.

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
This is a legitimate, working `O(|U|)`-communication SHE baseline (and its
own doc comment at the top of the file is honest about this: "encodes sets
as binary vectors of dimension `U_set`"), but it is **not** a faithful
reimplementation of ZLG+24's asymptotic `O(|U| log n)` computation — it is
closer to `O(|U|)` per query with no tree-pruning speedup. This is a
fidelity risk the integrator should be aware of before citing this
baseline's measured numbers as representative of ZLG+24 specifically (as
opposed to "an `O(|U|)`-scaling SHE-based baseline in the same family").
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
estimator or not). This is a **cross-branch dependency**: if a future
change to `hash-seed-crs`'s owned files (`params.{h,cpp}`) changes the
default `hash_seed`, or changes how the CRS is derived, both Piccard's
and BCG12's benchmark rows track it automatically and stay in parity —
but only because BCG12 reads the field rather than hardcoding `42`. Worth
one line in `INTEGRATION_NOTES.md` at merge time so `hash-seed-crs`'s
owners know a second branch now depends on their default.

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
