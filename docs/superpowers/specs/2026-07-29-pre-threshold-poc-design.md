# Pre-threshold PoC Design

**Date:** 2026-07-29  
**Branch:** `tkde-major/pre-threshold-poc`  
**Base commit:** `aa3053a`  
**Scope owner:** implementation only; manuscript text remains owned by the coauthors

## 1. Goal

Resolve every implementation or reproducibility issue currently identified in
`Paper/Revision/ResponseStrategy.md` before the separate `threshold-fpfn` work
starts. The result must be a reproducible PoC evidence path, not a claim that
the implementation exactly realizes every theorem currently written in the
manuscript.

The implementation must provide:

1. a public, reproducible random-ranking estimator based on SHA-256;
2. a clearly labelled empirical phase-smudging sanitizer with transcript-level
   accounting;
3. usable STD128 and STD192 calibration/profile paths;
4. matched-condition benchmark execution for Piccard, BCG12, and SJ16;
5. deterministic DBLP-ACM and Enron preprocessing/benchmark inputs;
6. bounded-dynamic full refresh with epoch/version checking and reproducible
   deletion-survival evidence; and
7. one integration gate that proves the repository is ready to branch into
   `threshold-fpfn`.

## 2. Explicit non-goals

- Do not edit `Paper/Revision/Piccard_MR_R1.tex`, the submitted manuscript, or
  any other LaTeX source.
- Do not implement threshold FP/FN experiments, dense boundary sweeps,
  threshold-specific reseeding, or threshold-specific benchmark schema.
- Do not claim a formal full-ciphertext statistical sanitizer. The PoC combines
  fresh `Enc(0)` re-randomization with coefficient-wise decryption-phase
  smudging and reports that assurance model verbatim.
- Do not claim exact minwise independence or an exact finite-range collision
  formula for SHA-256. The estimator is an empirical random-oracle-style PoC.
- Do not implement ciphertext delta updates. The supported dynamic path is a
  single owner's full feature refresh followed by atomic cloud replacement.
- Do not vendor or redistribute externally licensed real datasets.
- Do not report long-running paper numbers merely because a smoke test passes.

## 3. Frozen decisions

### 3.1 Estimator

For hash coordinate `i`, public CRS seed `seed`, and element `x`, compute:

```text
SHA256(
  "piccard-minhash-poc-v1" ||
  uint64_be(seed) ||
  uint32_be(i) ||
  uint64_be(x)
)
```

Interpret the first eight digest bytes as a big-endian `uint64_t` rank. The
minimum rank per coordinate forms the MinHash signature. This gives deterministic
cross-platform behavior without relying on implementation-defined standard
library distributions. `hash_range == UINT64_MAX` uses the full rank. A finite
legacy `hash_range` remains an explicitly labelled compatibility mode and may
reduce the rank modulo that range; it is not used in paper profiles.

The same implementation must serve:

- static Piccard;
- `BottomStructure` for the dynamic variant; and
- BCG12's MinHash comparison mode.

Every result row that uses the estimator records
`estimator_model=sha256-random-ranking-poc-v1`.

### 3.2 Sanitizer accounting

The security-profile inputs are:

- `transcript_stat_bits`: target for a complete transcript;
- `max_queries`: maximum returned ciphertexts under the same profile/key epoch;
- `flood_margin_bits`: empirical calibration safety margin; and
- realized ring dimension `N`.

Derived values are:

```text
query_stat_bits =
    transcript_stat_bits + ceil(log2(max_queries))

coefficient_stat_bits =
    query_stat_bits + ceil(log2(N))

flood_noise_bits =
    eval_noise_bits + coefficient_stat_bits + flood_margin_bits
```

The `ceil(log2(N))` term is the coefficient union bound. The query and
coefficient adjustments are not hidden inside the calibration margin.

Supported experiment profiles:

- primary: transcript 40, `max_queries = 2^20`, full STD128/STD192 sweep;
- sensitivity: transcript 64, same query cap, representative STD128/STD192
  points;
- feasibility: transcript 128, same query cap, one or two representative
  points, allowed to fail closed when no calibrated parameter set fits.

CSV metadata uses:

```text
sanitizer_model=phase-smudging-enc0-poc-v1
sanitizer_assurance=empirical-phase-statistical+ciphertext-computational
```

### 3.3 Calibration

Calibration rows are keyed by circuit, security level, requested ring
dimension, natural multiplicative depth, realized ring dimension, modulus
layout, and OpenFHE version. A profile is usable only if:

1. all configured patterns decrypt correctly;
2. the noise measurement is not saturated;
3. the recorded realized `N` equals the runtime `N`;
4. `flood_noise_bits + 2 <= log2(q/t)`; and
5. the requested transcript/query/coefficient target is carried in provenance.

The selector fails closed on missing or infeasible cells. Ring growth may be
searched during calibration, but production selection only adopts a measured
row; it never silently grows an experiment.

### 3.4 Matched-condition comparisons

“Same parameters” means matched experimental conditions where schemes have
different native parameters:

- same machine and build;
- same set pair/workload or same generated trial seed;
- same timing trial count;
- same OpenMP thread policy;
- explicit nominal security profile;
- explicit functionality/output/model differences.

BCG12 and SJ16 must not inherit Piccard-only flooding fields. Their rows state
their primitive, deployment model, output, exact/approximate mode, nominal
strength, and whether a value is measured or extrapolated. SJ16 secure division
remains excluded and therefore its timing is labelled a lower bound.

### 3.5 Real datasets

Raw datasets live outside Git. A manifest supplies:

- dataset identifier and version;
- expected file names;
- SHA-256 checksums;
- source URL and acquisition note;
- parsing schema; and
- deterministic preprocessing profile.

Small synthetic fixtures exercise every parser in CI. The real-data runner
fails before benchmarking when a file/checksum/schema is wrong. Preprocessed
sets are deterministic and accompanied by a provenance manifest. DBLP-ACM is
the record-linkage primary dataset. Enron messages are converted to normalized
word shingles for the near-duplicate workload.

### 3.6 Bounded-dynamic refresh

The supported state transition is:

```text
owner local set/bottom structure at epoch e
  -> local insert/delete operations
  -> full encoded feature encryption for epoch e+1
  -> versioned refresh package
  -> atomic cloud compare-and-swap replacement
```

Cloud replacement rejects:

- a stale source epoch;
- a skipped destination epoch;
- a mismatched owner/set identifier;
- a mismatched public hash CRS; and
- an invalid ciphertext package.

The benchmark reports local update time, re-encoding time, encryption time,
serialized upload bytes, replacement time, and the epoch transition. It never
labels the sum of two owners' encryption as a single-owner refresh.

Deletion survival is evaluated independently under the ideal independent
random-ranking model. The tool emits analytic survival probability and
seeded Monte Carlo estimates, distinguishes first failure time from the number
of safe deletions, and tests off-by-one conventions.

## 4. Work order and dependency graph

```text
1 Estimator random ranking
          |
          v
2 Sanitizer profile/accounting
          |
          v
3 STD128/STD192 calibration
          |
          v
4 Benchmark profiles + BCG12/SJ16 gates
          |
          +----------+
          v          v
5 Real datasets   6 Dynamic refresh/deletion
          \          /
           v        v
        7 Integration + ResponseStrategy update
                    |
                    v
             threshold-fpfn branch
```

Estimator changes precede all evidence generation. Sanitizer accounting
precedes calibration because it defines the target. Calibration precedes
benchmark profiles because the runner must reject unsupported combinations.
Real-data and dynamic work can be reasoned about independently, but are
implemented sequentially so each work receives its required dual approval.

## 5. Review and implementation protocol

Before any production-code change:

1. all seven work plans exist;
2. Claude Fable reviews every plan independently;
3. every plan has an `APPROVE` verdict, or all blocking findings have been
   incorporated and the re-review returns `APPROVE`; and
4. the Release baseline remains 18/18 tests passing.

For every implementation phase:

1. Claude Opus 5 receives only the approved phase and relevant context;
2. Opus writes a failing test first;
3. the failure is captured;
4. Opus makes the smallest implementation change;
5. the focused test and required regression tests pass;
6. an independent reviewer audits the diff and evidence;
7. blocking findings return to Opus before the next phase.

After all phases of one work:

1. GPT-5.6-sol independently reviews the complete work;
2. Claude Fable independently reviews the same work;
3. both must approve before the next work begins.

## 6. Global pass criteria

The pre-threshold branch is complete only when:

- a clean Release configure/build succeeds;
- all unit/integration tests pass;
- sanitizer-negative tests prove fail-closed behavior;
- estimator and deletion diagnostics reproduce from fixed seeds;
- STD128 and STD192 transcript-40 primary profiles validate and initialize
  usable contexts; primary STD192 infeasibility is a terminal blocker.
  Transcript-128 feasibility points alone may end in an explicit,
  evidence-backed infeasibility result without fallback;
- benchmark dry-run and quick/smoke gates cover Piccard, BCG12, and SJ16;
- real-data fixture tests pass and absent/corrupt real inputs fail before timing;
- dynamic stale/atomic/version tests pass;
- no threshold FP/FN file or behavior was introduced;
- `Paper/Revision/ResponseStrategy.md` implementation status is updated from
  verified artifacts only; and
- any remaining non-threshold development issue is placed in a new audit
  document and processed at most two additional implementation-review cycles.
