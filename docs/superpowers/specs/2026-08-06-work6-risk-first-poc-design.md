# Work 6 Risk-First PoC Design

**Date:** 2026-08-06

**Baseline:** `b09d008`

**Status:** user-approved design

**Implementation model:** `gpt-5.6-terra`

**Plan approval gates:** Claude Fable high and `gpt-5.6-sol xhigh`

## 1. Goal

Implement Work 6 as a bounded-dynamic proof of concept that supports one
owner's full ciphertext refresh with atomic epoch replacement and produces
reproducible deletion-survival evidence. The implementation must support the
TKDE major-revision claims without expanding into ciphertext delta updates or
threshold FP/FN experiments.

Work 3, Work 4, and Work 5 are accepted dependencies by explicit user
approval. Their deferred paper-scale measurements and historical approval
record mechanics do not block Work 6. The current clean commit `b09d008` is
the Work 6 implementation baseline.

## 2. Scope

Work 6 contains seven implementation units:

1. expose sticky bottom-structure exhaustion and rebuild requirements;
2. bind ciphertexts to owner, epoch, CRS, encoding, context, public key, and
   key tag in a versioned atomic store;
3. prove single-owner full refresh in an end-to-end test;
4. implement exact ideal-model deletion-survival calculations;
5. implement deterministic Monte Carlo evidence and a CSV CLI;
6. record one-owner refresh phases, epoch transition, and upload bytes in the
   existing benchmark/provenance path; and
7. enforce threshold exclusion and run the Work 6 integration gate.

The following are out of scope:

- ciphertext delta or additive update APIs;
- multi-owner transactions;
- network transfer latency;
- distributed storage or persistence;
- paper-scale benchmark execution during implementation;
- threshold, FP/FN, or decision-boundary behavior; and
- exhaustive defensive edge cases that do not affect a paper claim.

## 3. Architecture and implementation order

The implementation follows a risk-first order:

```text
bottom exhaustion invariant
  -> public ciphertext identity + atomic store
  -> single-owner refresh E2E
  -> exact deletion analysis
  -> deterministic Monte Carlo + CLI
  -> refresh benchmark/provenance
  -> threshold-exclusion and integration gate
```

Correctness comes before measurement. Benchmark and reporting code may not be
added until the refresh state transition and deletion model pass focused
tests. Each unit is independently reviewable and is split into small TDD
phases in the implementation plan.

## 4. Component boundaries

### 4.1 Bottom-structure lifecycle

`BottomStructure` owns a sticky `requires_rebuild` state. Exhausting any hash
bucket makes signatures and encryption unavailable. Later insertion does not
clear the state because previously discarded candidates cannot be recovered.
Only a successful nonempty full initialization restores operation.

`DynamicPiccard` consumes this state through the existing signature path; it
does not maintain a second lifecycle flag.

### 4.2 Public ciphertext identity and atomic store

A public codec exported by `BFVContext` serializes ciphertexts and exposes
stable context, public-key, and key-tag identities without exposing decryption
or secret-key operations.

`DynamicCiphertextStore` owns serialized immutable envelopes for exactly two
distinct owners. A replacement provides an owner, expected epoch, and a full
fresh ciphertext for destination epoch `expected + 1`. Validation occurs
before mutation; the owner slot is replaced atomically under a mutex.

The public outcome is `Applied`, `StaleEpoch`, or `FutureEpoch`, together with
the observed epoch. Invalid envelopes throw and leave the stored pair
unchanged.

### 4.3 Single-owner refresh flow

The E2E path is:

```text
owner A/B sets at epoch 0
  -> encrypt and install A@0/B@0
  -> mutate A locally
  -> recompute A signature and encoding
  -> freshly encrypt and serialize A@1
  -> compare-and-swap A from 0 to 1
  -> evaluate A@1/B@0
  -> compare with fresh plaintext match count
```

Owner B's complete envelope must remain byte-identical. A stale replay must be
rejected without changing the refreshed result.

### 4.4 Deletion-survival evidence

For set size `n`, bottom depth `d`, hash count `k`, first failure time `T`, and
`r` completed safe deletions, the exact ideal independent-random-ranking model
is:

```text
S(r) = Pr[T > r] = (1 - C(r,d) / C(n,d))^k
E[T] = sum(r=0..n-1, S(r))
E[safe deletions] = E[T] - 1
```

The analytic module also returns the union-bound lower survival and the
largest deletion budget meeting a requested survival target. The Monte Carlo
module samples deterministic bottom-position subsets from raw `mt19937_64`
words and reports survival and mean estimates against the exact model. Every
output is labelled `ideal-independent-random-ranking-v1`; it is not evidence
about the deployed SHA-256 ranks themselves.

### 4.5 Benchmark and provenance

The refresh benchmark measures one owner's update, signature, encoding,
encryption, serialization, cloud replacement, total refresh time, serialized
upload bytes, and epoch transition. It uploads exactly one ciphertext and
does not label two-owner encryption as a single-owner refresh.

Implementation-time benchmark verification uses only profile `toy-smoke` and
exactly one timing or accuracy repetition. Paper-scale performance collection
is deferred.

## 5. Failure model

The PoC retains only failures that can invalidate its paper evidence:

- exhausted bottom structure used for a signature or encryption;
- stale or future epoch replacement;
- wrong owner or skipped destination epoch;
- CRS, estimator, encoding, context, public-key, or key-tag mismatch;
- empty, corrupt, or non-canonical serialized ciphertext;
- analytic invalid domains and safe-deletion/failure-time off-by-one errors;
- Monte Carlo drift from fixed-seed deterministic behavior;
- benchmark rows whose totals, epochs, upload count, or provenance disagree;
- any Work 6 change that introduces threshold or FP/FN behavior.

Every failed store operation preserves the complete prior pair. Every failed
phase blocks the next phase; no warning-only continuation is permitted for a
required success condition.

## 6. Test and phase gates

Every implementation unit is decomposed into multiple phases. Each phase must
state:

- prerequisites and exact files;
- consumed and produced interfaces;
- the failing test and expected RED reason;
- the minimal GREEN change;
- focused and regression commands;
- explicit PASS conditions;
- explicit FAIL/STOP conditions; and
- the next-phase entry condition.

Production behavior is implemented test-first. A phase passes only when its
focused tests and named regressions exit zero and its required observable
values match. A phase fails when RED does not fail for the stated reason,
GREEN does not pass, an invariant is unverified, the worktree contains an
unexpected change, or a command violates the TOY/one-repetition policy.

The final Work 6 gate requires a clean Release build, the focused Work 6 tests,
the relevant existing dynamic/provenance regressions, one TOY refresh row,
one TOY deletion CLI run, and the threshold-exclusion check. Full historical
benchmark suites and paper-scale measurements are not part of this gate.

## 7. Plan authoring and approval contract

The detailed implementation plan is written for a fresh `gpt-5.6-terra`
worker with no assumed repository context. It names exact paths, interfaces,
commands, expected failures, and expected outputs; it contains no unfinished
placeholder, implicit edge-case request, or cross-phase shortcut.

The plan is not final until two independent reviewers return `APPROVE`:

1. Claude Fable high; and
2. `gpt-5.6-sol xhigh`.

Any blocking finding is incorporated into the plan and both reviewers receive
the revised complete plan. Approval is re-collected after material revisions.
Implementation begins only from the jointly approved plan.

## 8. Work 6 completion criteria

Work 6 is complete at PoC level when:

- exhausted structures fail closed until successful rebuild;
- a full owner ciphertext refresh applies only at the expected next epoch;
- the unchanged owner remains byte-identical and stale replay cannot revert
  state;
- refreshed FHE output equals the fresh local plaintext match count;
- analytic fixtures and deterministic Monte Carlo checks agree within their
  declared tolerances;
- one TOY, one-repetition refresh benchmark row is internally consistent;
- deletion evidence is explicitly labelled as an ideal model;
- threshold exclusion passes; and
- all named focused and regression tests pass from a clean tree.
