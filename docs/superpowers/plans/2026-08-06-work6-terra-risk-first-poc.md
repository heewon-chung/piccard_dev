# Work 6 Terra Risk-First Dynamic Refresh PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build reproducible Work 6 PoC evidence for sticky bottom-structure exhaustion, one owner's full ciphertext re-encryption with atomic epoch replacement, exact and seeded ideal-model deletion survival, and a provenance-checked TOY refresh CSV without introducing ciphertext deltas or threshold FP/FN behavior.

**Architecture:** Work proceeds risk-first: make invalid bounded-dynamic local state explicit; add a public-only ciphertext codec and a mutex-protected two-slot versioned store; prove a one-owner `0->1` refresh end to end; then add OpenFHE-free exact and deterministic Monte Carlo deletion analysis. The evidence layer adds one `bench_dynamic --scenario=refresh` row whose timed scope contains only the changed owner's update, signature, encoding, encryption, serialization, and compare-and-swap replacement; the existing verifier and runner bind that row to TOY, one trial, the live estimator/sanitizer provenance, and the no-threshold/no-delta scope gate.

**Tech Stack:** C++17, CMake 3.20+, GoogleTest, OpenFHE BFVRNS, OpenSSL SHA-256, Python 3 standard library, shell runner with embedded Python, CTest.

## Global Constraints

- The approved Work 1–5 code baseline is `b09d008`. The tracked Work 6 design baseline is `a15fd4e`, whose parent chain contains `b09d008`; force-add and commit this ignored plan as the only next metadata change. Before Task 1, require `git ls-files --error-unmatch` for both design and plan, record `PLAN_COMMIT="$(git rev-parse HEAD)"`, and require a clean tree. Every code/scope comparison still uses `b09d008`, and no production change may precede Task 1's RED test.
- The human explicitly approved Works 3, 4, and 5. Do not invoke `verify_work_approval.py`, request their approval artifacts, reconstruct their head chain, or treat their evidence state as a Work 6 blocker.
- Execute Tasks 1–9 in the exact risk order shown. A task starts only after its focused tests pass and its task diff receives an independent spec-compliance and code-quality review.
- Every production behavior begins with the focused failing test shown in its task. Capture the stated RED reason, implement the minimum GREEN behavior, run the focused regression command, and make the task commit before moving on.
- Human-approved OpenFHE 1.5.0 amendment: ciphertext wire bytes are the one-pass canonical form `N(c)=S(D(S(c)))`, where `S`/`D` are direct OpenFHE binary serialization/deserialization. `Serialize` must verify `S(D(N(c)))=N(c)` and fail rather than iterate if one pass is not a fixed point. `Deserialize(b)` accepts only exactly consumed, correctly bound bytes satisfying `S(D(b))=b`; later store/evidence code binds these canonical wire bytes, not raw `S(c)`.
- Work 6 implements a single owner's full signature re-encoding and fresh full ciphertext encryption. The cloud replaces that complete serialized ciphertext atomically; no ciphertext delta, additive update, patch, or in-place mutation API may be added.
- A replacement binds the owner/set identifier, source and destination epochs, SHA-256 public CRS (`hash_seed`, estimator model, `k`, `m`, and `hash_range`), encoding model, realized BFV context, public key, OpenFHE key tag, and serialized ciphertext payload.
- Stale and future source epochs are distinct results. Only `expected_epoch == current_epoch` with `replacement.epoch == expected_epoch + 1` applies.
- The PoC retains only state-machine and evidence-integrity failures: unusable bottom state, empty/distinct owner identifiers, malformed epoch transition, wrong immutable CRS/crypto binding, and empty/corrupt ciphertext bytes. Do not add a general validation framework, retry policy, persistence layer, network layer, or concurrency stress harness.
- Deletion survival is explicitly `ideal-independent-random-ranking-v1`. It is independent of the deployed SHA-256 estimator and must never be described as proof about actual hash-coordinate independence.
- For first failure time `T` (1-based) and completed safe deletions `r`, use `S(r)=Pr[T>r]=(1-C(r,d)/C(n,d))^k`, `E[T]=sum_{r=0}^{n-1}S(r)`, and `E[safe deletions]=E[T]-1`. Tests name failure time and safe deletions separately.
- Every Work 6 benchmark execution uses `SecurityLevel::TOY` or `--security=TOY` and `--trials=1`. Any executed repetition or accuracy loop uses count `1`; a refresh timing row keeps `accuracy_trials=0` as the explicit statement that no accuracy loop executed. Do not execute the primary, sensitivity, or feasibility benchmark suites. Full STD128/STD192 performance measurement and multi-trial dispersion are deferred.
- Existing non-refresh dynamic rows retain their schema meaning. New refresh columns are appended, legacy rows emit `dynamic_scenario=legacy` with empty refresh-only cells, and refresh rows emit `measurement_kind=fhe-timing`, `profile_id=toy-smoke`, `trials=1`, and `accuracy_trials=0` because no accuracy trial is executed.
- Do not edit manuscript/LaTeX sources, threshold implementation/tests/schemas, threshold FP/FN behavior, dense boundary sweeps, or threshold reseeding. The final scope checker rejects these changes from `b09d008..HEAD`.
- Do not run `BenchDynamicProbeIsolation` during Work 6 verification because its inherited executable-level regression uses more than one timing trial. Use the focused Work 6 TOY commands below.
- Preserve unrelated user and other-agent changes. Each commit stages only the paths named in its task.

---

## File Map

| Path | Change | Responsibility |
|---|---|---|
| `include/core/bottom_structure.h` | Modify | Public sticky `RequiresRebuild()` state and private usability guard. |
| `src/core/bottom_structure.cpp` | Modify | Set/reset sticky exhaustion and reject incremental operations while unusable. |
| `tests/unit/test_bottom_structure.cpp` | Modify | Focused state lifecycle and deletion-exhaustion tests. |
| `tests/unit/test_dynamic_engine.cpp` | Modify | Dynamic encryption refuses exhausted state and full initialization recovers. |
| `include/fhe/public_ciphertext_codec.h` | Create | Public-only ciphertext serialization and live context/public-key/key-tag binding. |
| `src/fhe/public_ciphertext_codec.cpp` | Create | Strict binary codec and immutable binding getters. |
| `include/fhe/bfv_context.h` | Modify | Export `std::shared_ptr<const PublicCiphertextCodec>` after key generation. |
| `src/fhe/bfv_context.cpp` | Modify | Canonical BFV and public-key fingerprints and codec export. |
| `tests/unit/test_public_ciphertext_codec.cpp` | Create | Round-trip, malformed bytes, fingerprint, and wrong-key tests. |
| `include/protocol/dynamic_ciphertext_store.h` | Create | Versioned envelope, replace outcome, pair snapshot, envelope factory, and two-slot store API. |
| `src/protocol/dynamic_ciphertext_store.cpp` | Create | Immutable binding validation, mutex-protected read, and epoch compare-and-swap. |
| `tests/unit/test_dynamic_ciphertext_store.cpp` | Create | Constructor, applied/stale/future, owner/CRS/crypto, and failed-state immutability tests. |
| `tests/integration/test_dynamic_refresh_e2e.cpp` | Create | Old-cloud/new-cloud one-owner full-refresh proof and stale replay rejection. |
| `include/analysis/deletion_survival.h` | Create | Exact analytic deletion-survival interface. |
| `src/analysis/deletion_survival.cpp` | Create | Stable combination ratio, survival, budget search, and expectations. |
| `tests/unit/test_deletion_survival.cpp` | Create | Small exact fixtures, default goldens, and off-by-one semantics. |
| `include/analysis/deletion_monte_carlo.h` | Create | Portable ideal-model sampler and result interface. |
| `src/analysis/deletion_monte_carlo.cpp` | Create | Rejection sampling, Floyd subsets, first-failure simulation, and histogram. |
| `tests/unit/test_deletion_monte_carlo.cpp` | Create | Raw RNG goldens and deterministic one-trial histogram. |
| `benchmarks/bench_deletion_survival.cpp` | Create | Exact/union/MC CSV CLI. |
| `tests/scripts/test_bench_deletion_survival.py` | Create | Executable CSV/model/one-trial contract. |
| `benchmarks/benchmark_estimator_provenance.h` | Modify | Append optional refresh evidence fields to `DynamicResult`. |
| `benchmarks/benchmark_estimator_provenance.cpp` | Modify | Append dynamic refresh header/cells without reordering inherited columns. |
| `benchmarks/dynamic_refresh_benchmark.h` | Create | One-trial refresh measurement function declaration. |
| `benchmarks/dynamic_refresh_benchmark.cpp` | Create | One-owner timed pipeline and stored-vs-local correctness gate. |
| `benchmarks/bench_dynamic.cpp` | Modify | Strict `--scenario=legacy|refresh` and `--refresh_updates=N` routing. |
| `tests/unit/test_estimator_provenance_serializers.cpp` | Modify | Extend the exact legacy dynamic header/row golden for the appended schema. |
| `tests/unit/test_dynamic_refresh_benchmark.cpp` | Create | Serializer and TOY one-owner timing/upload test. |
| `tests/scripts/test_bench_dynamic_refresh_cli.py` | Create | Durable strict refresh CLI matrix with exactly one successful TOY one-trial execution. |
| `scripts/verify_benchmark_provenance.py` | Modify | Refresh-row provenance, arithmetic, epoch, upload, and one-trial gates. |
| `tests/scripts/test_verify_benchmark_provenance.py` | Modify | Valid refresh fixture and targeted false-evidence mutations. |
| `scripts/run_pre_threshold_profiles.sh` | Modify | Add one TOY refresh cell and pin smoke repetition/accuracy counts to one. |
| `tests/scripts/test_run_pre_threshold_profiles.py` | Modify | Freeze the new smoke argv, cell count, schemas, and fake refresh row. |
| `tests/fixtures/runner/dynamic_toy_rows.csv` | Modify | Production-shaped legacy and refresh dynamic rows with appended columns. |
| `scripts/check_work6_scope.py` | Create | Git-diff whitelist, threshold exclusion, and ciphertext-delta API scan. |
| `scripts/work6_allowed_paths.txt` | Create | Sorted exact Work 6 diff whitelist. |
| `tests/scripts/test_check_work6_scope.py` | Create | Hermetic allowed/forbidden path and semantic mutation tests. |
| `docs/superpowers/plans/2026-08-06-work6-terra-risk-first-poc.md` | Existing metadata | This approved Terra execution plan, tracked before implementation starts. |
| `docs/superpowers/specs/2026-08-06-work6-risk-first-poc-design.md` | Existing metadata | Approved Work 6 design already committed above the code baseline. |
| `CMakeLists.txt` | Modify | Register new sources, libraries, executables, and tests only. |

## Dependency and Review Order

```text
Task 1 exhaustion state
  -> Task 2 public codec
  -> Task 3 atomic store
  -> Task 4 one-owner E2E
  -> Task 5 exact survival
  -> Task 6 deterministic MC + CLI
  -> Task 7 refresh timing/upload row
  -> Task 8 runner + provenance gate
  -> Task 9 threshold/delta exclusion + final verification
```

## Execution Entry Gate

The coordinator force-adds and commits this ignored plan before dispatching
Task 1. A fresh Terra worker begins by running:

```bash
set -euo pipefail
test "$(git rev-parse --short=7 a15fd4e^{commit})" = "a15fd4e"
git ls-files --error-unmatch \
  docs/superpowers/specs/2026-08-06-work6-risk-first-poc-design.md \
  docs/superpowers/plans/2026-08-06-work6-terra-risk-first-poc.md
test -z "$(git status --porcelain=v1 --untracked-files=all)"
PLAN_COMMIT="$(git rev-parse HEAD)"
git diff --name-only b09d008.."$PLAN_COMMIT" > /tmp/work6-entry-paths.txt
diff -u - /tmp/work6-entry-paths.txt <<'EOF'
docs/superpowers/plans/2026-08-06-work6-terra-risk-first-poc.md
docs/superpowers/specs/2026-08-06-work6-risk-first-poc-design.md
EOF
```

If any command fails, stop before writing Task 1's RED tests. `PLAN_COMMIT` is
the task-review base for Task 1; `b09d008` remains the Work 6 scope-check base.

## Unit-to-Phase Gate Matrix

The seven design units below are the execution-level control structure. A
Terra worker completes phases in numeric order and checks the matching Task
steps for exact code and commands. A phase with any FAIL/STOP condition does
not advance, even when another test happens to pass.

### Unit 1 — Sticky bottom-structure exhaustion

#### Phase 1.1 — RED lifecycle contract

- **Prerequisites:** clean plan baseline; existing `BottomStructure` and
  `DynamicPiccard` tests build; Task 1 Steps 1–2 are the only owned changes.
- **PASS:** the new lifecycle and exhausted-encryption tests compile far
  enough to identify missing `RequiresRebuild()`/guard behavior and fail for
  that stated reason.
- **FAIL/STOP:** a new test passes before production changes, fails from a
  typo/fixture error, or any non-Task-1 file changes.
- **Next entry:** Phase 1.2 starts only after the RED output is recorded.

#### Phase 1.2 — GREEN sticky state and regression

- **Prerequisites:** Phase 1.1 PASS; follow Task 1 Steps 3–5.
- **PASS:** focused bottom/dynamic tests pass; exhaustion is sticky; only a
  successful nonempty `Initialize()` restores use; Task 1 review approves.
- **FAIL/STOP:** insertion clears exhaustion, empty/failed initialization
  clears it, signature/encryption proceeds while exhausted, or a regression
  fails.
- **Next entry:** Unit 2 starts after the Task 1 commit and review gate.

### Unit 2 — Public ciphertext identity and atomic store

#### Phase 2.1 — RED public-codec identity contract

- **Prerequisites:** Unit 1 PASS; Task 2 Steps 1–2 own only codec, BFV, test,
  and CMake paths.
- **PASS:** tests fail because the public codec/fingerprint/export interfaces
  do not yet exist, while existing BFV tests remain runnable.
- **FAIL/STOP:** failure is caused by unavailable OpenFHE, invalid test setup,
  or a test requires secret-key/decrypt capability in the codec.
- **Next entry:** Phase 2.2 begins after the intended RED is captured.

#### Phase 2.2 — GREEN codec and canonical bindings

- **Prerequisites:** Phase 2.1 PASS; follow Task 2 Steps 3–5.
- **PASS:** canonical context/public-key fingerprints, key tag, one-pass
  canonical fixed-point serialization/deserialization, wrong-key rejection,
  and public-only lifetime tests pass; Task 2 review approves.
- **FAIL/STOP:** trailing/corrupt/non-fixed-point bytes are accepted,
  canonical emission needs more than one normalization pass, fingerprints are
  not stable lowercase hex, the codec exposes decryption/secret-key access, or
  an existing BFV regression fails.
- **Next entry:** Phase 2.3 starts after the Task 2 commit and review gate.

#### Phase 2.3 — RED/GREEN atomic store state machine

- **Prerequisites:** Phase 2.2 PASS; Task 3 owns store header/source/test and
  CMake registration.
- **PASS:** Task 3 RED first fails on the absent store, then GREEN passes for
  constructor bindings, one-owner `0->1`, distinct stale/future outcomes,
  unchanged peer, and failed-state immutability; Task 3 review approves.
- **FAIL/STOP:** a malformed transition mutates state, immutable bindings can
  change, stale/future collapse to one result, more than one lock scope owns a
  pair transition, or a delta/update API is introduced.
- **Next entry:** Unit 3 starts after the Task 3 commit and review gate.

### Unit 3 — Single-owner full-refresh E2E

#### Phase 3.1 — Executable refresh fixture contract

- **Prerequisites:** Unit 2 PASS; Task 4 Steps 1–2 own only the E2E test and
  required CMake target.
- **PASS:** the deterministic fixture compiles and passes using the already
  reviewed Unit 2 state machine; it proves the local mutation changes A's
  encoded feature/plaintext match result.
- **FAIL/STOP:** the mutation does not change the observable result, owner B
  changes, the test is nondeterministic, or passing requires new production
  behavior in Unit 3.
- **Next entry:** Phase 3.2 begins after the executable fixture passes.

#### Phase 3.2 — GREEN refresh, equality, and replay gate

- **Prerequisites:** Phase 3.1 PASS; follow Task 4 Steps 3–4.
- **PASS:** A alone refreshes `0->1`; B's complete envelope is byte-identical;
  stored FHE output equals fresh plaintext recomputation; replay is stale and
  cannot restore A@0; Task 4 review approves.
- **FAIL/STOP:** both owners are re-encrypted, stale cloud output changes
  before refresh, refreshed output disagrees with plaintext, or replay changes
  the pair.
- **Next entry:** Unit 4 starts after the Task 4 commit and review gate.

### Unit 4 — Exact deletion-survival analysis

#### Phase 4.1 — RED formula and off-by-one fixtures

- **Prerequisites:** Unit 3 PASS; Task 5 Steps 1–2 own the OpenFHE-free
  analysis interface/test/CMake paths.
- **PASS:** small exact `S(2)`/`S(3)` fixtures, `k=2`, 156/157 budget goldens,
  and separately named `E[T]`/`E[T]-1` tests fail because the analysis module
  is absent.
- **FAIL/STOP:** a fixture confuses `T>r` with `T>=r`, uses the deployed
  SHA-256 implementation, or fails from numeric constants unrelated to the
  missing module.
- **Next entry:** Phase 4.2 begins after the intended RED is recorded.

#### Phase 4.2 — GREEN stable analytic core

- **Prerequisites:** Phase 4.1 PASS; follow Task 5 Steps 3–5.
- **PASS:** exact/union survival, monotone budget search, expected failure, and
  expected safe deletions pass declared tolerances in an OpenFHE-free target;
  Task 5 review approves.
- **FAIL/STOP:** survival is nonmonotone/out of range, budget is not 156 for
  the pinned case, expectations are off by one, or invalid domains are
  accepted.
- **Next entry:** Unit 5 starts after the Task 5 commit and review gate.

### Unit 5 — Deterministic Monte Carlo and CSV CLI

#### Phase 5.1 — RED portable sampler contract

- **Prerequisites:** Unit 4 PASS; Task 6 Steps 1–2 own MC interface/source/test
  and CLI test paths.
- **PASS:** raw-word `UniformBelow`, fixed-seed first-failure histogram, and
  `T>r` survival tests fail because the sampler is absent.
- **FAIL/STOP:** tests depend on `uniform_int_distribution`, more than one MC
  trial, platform-specific random output, or actual SHA-256 ranks.
- **Next entry:** Phase 5.2 begins after the intended RED is recorded.

#### Phase 5.2 — GREEN sampler and ideal-model CLI

- **Prerequisites:** Phase 5.1 PASS; follow Task 6 Steps 3–5.
- **PASS:** pinned raw outcomes and one-trial histogram are bit-identical; CLI
  accepts only `--trials=1`; rows carry the ideal-model label and exact values;
  targets build without OpenFHE; Task 6 review approves.
- **FAIL/STOP:** seed replay drifts, sampling is biased by modulo without
  rejection, CLI accepts a non-one trial count, or output suggests an
  actual-hash proof.
- **Next entry:** Unit 6 starts after the Task 6 commit and review gate.

### Unit 6 — Refresh benchmark and provenance

#### Phase 6.1 — RED/GREEN one-owner measurement core

- **Prerequisites:** Unit 5 PASS; Task 7 owns dynamic measurement helper,
  serializer, executable routing, test, and CMake paths.
- **PASS:** RED first identifies missing refresh measurement/schema behavior;
  GREEN measures A-only update, signature, encode, encrypt, serialize, and
  replace; total is their sum; upload bytes match A@1; only TOY and one trial
  are accepted; Task 7 review approves.
- **FAIL/STOP:** initialization or B encryption enters timed scope, totals do
  not reconcile, upload count is not one, correctness is unchecked, or a
  non-TOY/non-one-trial refresh runs.
- **Next entry:** Phase 6.2 starts after the Task 7 commit and review gate.

#### Phase 6.2 — RED/GREEN verifier and runner cell

- **Prerequisites:** Phase 6.1 PASS; Task 8 owns verifier/tests, runner/tests,
  and the dynamic TOY fixture.
- **PASS:** targeted false-evidence mutations are RED, then the verifier
  rejects each inconsistent total/epoch/status/profile/trial/upload/binding;
  the runner adds exactly one TOY refresh cell with all counts one; Task 8
  review approves.
- **FAIL/STOP:** a legacy row fabricates refresh fields, any primary/
  sensitivity/feasibility refresh cell is added or executed, `trials>1`
  appears in a Work 6 command, or an inherited schema meaning changes.
- **Next entry:** Unit 7 starts after the Task 8 commit and review gate.

### Unit 7 — Scope exclusion and integration verification

#### Phase 7.1 — RED/GREEN threshold and delta scope gate

- **Prerequisites:** Unit 6 PASS; Task 9 Steps 1–4 own scope checker,
  whitelist, tests, and CMake registration.
- **PASS:** hermetic RED cases initially lack the checker; GREEN accepts the
  exact Work 6 paths and rejects forbidden paths, threshold/FPFN semantics,
  ciphertext-delta APIs, Git/decode errors, and whitelist drift.
- **FAIL/STOP:** a protected threshold path changes, semantic scanning ignores
  deletions, a decoder/Git failure is treated as success, or the whitelist
  covers unrelated work.
- **Next entry:** Phase 7.2 begins after focused checker tests pass.

#### Phase 7.2 — Final clean-tree Work 6 gate

- **Prerequisites:** Phase 7.1 PASS; follow Task 9 Steps 5–7 from a clean tree.
- **PASS:** Release configure/build, named focused/regression tests, one TOY
  refresh artifact, one-trial deletion artifact, provenance verification, and
  scope check all pass; final independent implementation review approves.
- **FAIL/STOP:** any command exits nonzero, a benchmark count exceeds one,
  an artifact lacks its model/provenance binding, the tree contains unexpected
  changes, or review reports a blocking finding.
- **Next entry:** Work 6 may be declared PoC-complete only after Phase 7.2 PASS.

### Task 1: A — Make `BottomStructure` exhaustion sticky and explicit

**Files:**
- Modify: `include/core/bottom_structure.h`
- Modify: `src/core/bottom_structure.cpp`
- Modify: `tests/unit/test_bottom_structure.cpp`
- Modify: `tests/unit/test_dynamic_engine.cpp`

**Interfaces:**
- Consumes: existing `BottomStructure(uint32_t k, uint32_t d, uint64_t hash_range, uint64_t seed)`, `Initialize`, `Insert`, `Delete`, `GetSignature`; `DynamicPiccard::Encrypt(const BottomStructure&)` already calls `GetSignature()`.
- Produces: `bool BottomStructure::RequiresRebuild() const noexcept`; private `void RequireUsable() const`; sticky private `bool requires_rebuild_ = true`.
- Error contract: unusable `Insert`, `Delete`, or `GetSignature` throws `std::logic_error("BottomStructure requires full nonempty Initialize()")`.

- [ ] **Step 1: Write focused failing state tests**

Add these tests to `tests/unit/test_bottom_structure.cpp`:

```cpp
TEST_F(BottomStructureTest, RebuildStateIsStickyUntilFullInitialize) {
    BottomStructure bottom(1, 1, hash_range, seed);
    EXPECT_TRUE(bottom.RequiresRebuild());
    EXPECT_THROW(bottom.Insert(9), std::logic_error);
    EXPECT_THROW(bottom.Delete(9), std::logic_error);
    EXPECT_THROW(bottom.GetSignature(), std::logic_error);

    bottom.Initialize({9});
    EXPECT_FALSE(bottom.RequiresRebuild());
    bottom.Delete(9);
    EXPECT_TRUE(bottom.RequiresRebuild());
    EXPECT_THROW(bottom.Insert(10), std::logic_error);
    EXPECT_THROW(bottom.Delete(10), std::logic_error);
    EXPECT_THROW(bottom.GetSignature(), std::logic_error);

    EXPECT_THROW(bottom.Initialize({}), std::invalid_argument);
    EXPECT_TRUE(bottom.RequiresRebuild());
    bottom.Initialize({10, 11});
    EXPECT_FALSE(bottom.RequiresRebuild());
    EXPECT_NO_THROW(bottom.GetSignature());
}
```

Replace `ManyMutationsStillProducesValidResult` in `tests/unit/test_dynamic_engine.cpp` with the semantic regression:

```cpp
TEST_F(DynamicEngineTest, ExhaustedStructureRejectsEncryptionUntilReinitialized) {
    auto bottom = engine->InitSet({7});
    ASSERT_FALSE(bottom->RequiresRebuild());
    bottom->Delete(7);
    ASSERT_TRUE(bottom->RequiresRebuild());
    EXPECT_THROW(engine->Encrypt(*bottom), std::logic_error);
    EXPECT_THROW(bottom->Insert(8), std::logic_error);

    bottom->Initialize({8, 9});
    EXPECT_FALSE(bottom->RequiresRebuild());
    EXPECT_NO_THROW(engine->Encrypt(*bottom));
}
```

- [ ] **Step 2: Run RED and capture the expected reason**

Run:

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
set +e
cmake --build build-work6 -j4 \
  --target test_bottom_structure test_dynamic_engine \
  > /tmp/work6-task1-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'RequiresRebuild' /tmp/work6-task1-red.log
! rg -q 'No rule to make target|unknown target' /tmp/work6-task1-red.log
```

Expected RED: compilation fails because `BottomStructure` has no `RequiresRebuild()` member. Do not weaken the tests to accept the current delayed `GetSignature()` runtime error.

- [ ] **Step 3: Implement the minimal sticky state**

Add to the public/private sections of `include/core/bottom_structure.h`:

```cpp
    bool RequiresRebuild() const noexcept { return requires_rebuild_; }

private:
    bool requires_rebuild_ = true;
    void RequireUsable() const;
```

Implement the guard and state transitions in `src/core/bottom_structure.cpp`:

```cpp
void BottomStructure::RequireUsable() const {
    if (requires_rebuild_) {
        throw std::logic_error(
            "BottomStructure requires full nonempty Initialize()");
    }
}

void BottomStructure::Initialize(const std::vector<uint64_t>& set) {
    if (set.empty()) throw std::invalid_argument("Set must not be empty");
    for (uint32_t i = 0; i < k_; i++) {
        bottom_[i].clear();
        bottom_[i].reserve(d_ + 1);
    }
    for (uint64_t elem : set) {
        const auto hashes = hasher_.ComputeElementHashes(elem);
        for (uint32_t i = 0; i < k_; i++) InsertIntoSorted(i, hashes[i]);
    }
    requires_rebuild_ = false;
}

void BottomStructure::Insert(uint64_t elem) {
    RequireUsable();
    const auto hashes = hasher_.ComputeElementHashes(elem);
    for (uint32_t i = 0; i < k_; i++) InsertIntoSorted(i, hashes[i]);
}

void BottomStructure::Delete(uint64_t elem) {
    RequireUsable();
    const auto hashes = hasher_.ComputeElementHashes(elem);
    for (uint32_t i = 0; i < k_; i++) {
        auto it = std::lower_bound(bottom_[i].begin(), bottom_[i].end(),
                                   hashes[i]);
        if (it != bottom_[i].end() && *it == hashes[i]) bottom_[i].erase(it);
        if (bottom_[i].empty()) requires_rebuild_ = true;
    }
}

std::vector<uint64_t> BottomStructure::GetSignature() const {
    RequireUsable();
    std::vector<uint64_t> sig(k_);
    for (uint32_t i = 0; i < k_; i++) sig[i] = bottom_[i][0];
    return sig;
}
```

Do not let insertion clear `requires_rebuild_`; discarded candidates can be recovered only from a full nonempty set.

- [ ] **Step 4: Run GREEN and focused regression**

Run:

```bash
set -euo pipefail
cmake --build build-work6 -j4 --target test_bottom_structure test_dynamic_engine
./build-work6/test_bottom_structure
./build-work6/test_dynamic_engine
```

Expected: both executables report all tests passed. Existing valid initialize/insert/delete/signature behavior remains green.

- [ ] **Step 5: Commit and review gate**

```bash
set -euo pipefail
git add include/core/bottom_structure.h src/core/bottom_structure.cpp \
  tests/unit/test_bottom_structure.cpp tests/unit/test_dynamic_engine.cpp
git commit -m "feat(dynamic): expose sticky bottom exhaustion"
```

Completion gate: the independent reviewer confirms that the flag begins true, only successful nonempty `Initialize()` clears it, any emptied bucket sets it, all incremental operations reject while set, and no ciphertext/storage code appears in this task.

### Task 2: B1 — Add a public-only ciphertext codec and crypto fingerprints

**Files:**
- Create: `include/fhe/public_ciphertext_codec.h`
- Create: `src/fhe/public_ciphertext_codec.cpp`
- Modify: `include/fhe/bfv_context.h`
- Modify: `src/fhe/bfv_context.cpp`
- Create: `tests/unit/test_public_ciphertext_codec.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: initialized `BFVContext` public crypto context and generated public key; OpenFHE binary `lbcrypto::Serial`; OpenSSL `EVP_sha256`.
- Produces:

```cpp
class PublicCiphertextCodec final {
public:
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    const std::string& ContextFingerprintHex() const noexcept;
    const std::string& PublicKeyFingerprintHex() const noexcept;
    const std::string& CiphertextKeyTag() const noexcept;
    std::vector<uint8_t> Serialize(const Ciphertext& ciphertext) const;
    Ciphertext Deserialize(const std::vector<uint8_t>& bytes) const;

private:
    friend class BFVContext;
    friend class PublicCiphertextCodecTestPeer;
    static void RequireCanonicalSerialization(
        const std::vector<uint8_t>& supplied,
        const std::vector<uint8_t>& canonical);
    PublicCiphertextCodec(
        lbcrypto::CryptoContext<lbcrypto::DCRTPoly> context,
        lbcrypto::PublicKey<lbcrypto::DCRTPoly> public_key,
        std::string context_fingerprint_hex,
        std::string public_key_fingerprint_hex,
        std::string ciphertext_key_tag);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> context_;
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> public_key_;
    std::string context_fingerprint_hex_;
    std::string public_key_fingerprint_hex_;
    std::string ciphertext_key_tag_;
};

std::shared_ptr<const PublicCiphertextCodec>
BFVContext::ExportPublicCiphertextCodec() const;
```

- Context fingerprint canonical bytes are: ASCII `piccard-bfv-context-v1`, one NUL byte, BE32 security code (`TOY=0`, `STD128=1`, `STD192=2`, `STD256=3`), BE64 plaintext modulus, BE32 realized ring dimension, BE32 multiplicative depth, BE32 scaling-modulus size, BE32 active tower count, then for each tower in OpenFHE order BE32 decimal-modulus-string length followed by `tower->GetModulus().ToString()` as ASCII decimal digits.
- Public-key fingerprint is SHA-256 over ASCII `piccard-bfv-public-key-v1`, one NUL byte, and the exact OpenFHE binary public-key serialization. Both getters return 64 lowercase hex characters. Key tag is the generated public key's nonempty OpenFHE tag verbatim.
- Let `S`/`D` denote direct OpenFHE binary serialization/deserialization.
  `Serialize` rejects a null ciphertext and a context/key-tag mismatch, then
  emits the one-pass canonical wire form `N(c)=S(D(S(c)))`. Before returning,
  it requires `S(D(N(c)))=N(c)` and throws `std::logic_error` rather than
  iterating if one pass is not a fixed point. `Deserialize` rejects empty,
  corrupt, or trailing bytes, verifies the decoded ciphertext uses the
  retained live context and key tag, directly reserializes that decoded object
  with `S`, and rejects unless `S(D(b))` equals the supplied bytes exactly.

- [ ] **Step 1: Write the failing codec tests**

Create `tests/unit/test_public_ciphertext_codec.cpp` with a TOY fixture and these representative tests:

```cpp
TEST(PublicCiphertextCodecTest, RoundTripsAndBindsContextPublicKeyAndTag) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();
    BFVContext context(params);
    context.Initialize();

    const auto codec = context.ExportPublicCiphertextCodec();
    ASSERT_TRUE(codec);
    EXPECT_EQ(codec->ContextFingerprintHex().size(), 64u);
    EXPECT_EQ(codec->PublicKeyFingerprintHex().size(), 64u);
    EXPECT_TRUE(std::all_of(codec->ContextFingerprintHex().begin(),
                            codec->ContextFingerprintHex().end(),
                            [](char c) {
                                return std::isdigit(static_cast<unsigned char>(c)) ||
                                       (c >= 'a' && c <= 'f');
                            }));
    EXPECT_FALSE(codec->CiphertextKeyTag().empty());

    const auto ciphertext = context.Encrypt({1, 0, 1, 0});
    const auto bytes = codec->Serialize(ciphertext);
    ASSERT_FALSE(bytes.empty());
    const auto decoded = codec->Deserialize(bytes);
    EXPECT_EQ(decoded->GetKeyTag(), codec->CiphertextKeyTag());
    EXPECT_EQ(codec->Serialize(decoded), bytes);
}

TEST(PublicCiphertextCodecTest, RejectsUninitializedMalformedAndWrongKey) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.security = SecurityLevel::TOY;
    params.Validate();

    BFVContext uninitialized(params);
    EXPECT_THROW(uninitialized.ExportPublicCiphertextCodec(), std::logic_error);

    BFVContext first(params);
    BFVContext second(params);
    first.Initialize();
    second.Initialize();
    const auto first_codec = first.ExportPublicCiphertextCodec();
    const auto second_codec = second.ExportPublicCiphertextCodec();
    EXPECT_EQ(first_codec->ContextFingerprintHex(),
              second_codec->ContextFingerprintHex());
    EXPECT_NE(first_codec->PublicKeyFingerprintHex(),
              second_codec->PublicKeyFingerprintHex());

    const auto bytes = first_codec->Serialize(first.Encrypt({1, 2, 3}));
    EXPECT_THROW(second_codec->Deserialize(bytes), std::invalid_argument);
    EXPECT_THROW(first_codec->Deserialize({}), std::invalid_argument);
    auto trailing = bytes;
    trailing.push_back(0x00);
    EXPECT_THROW(first_codec->Deserialize(trailing), std::invalid_argument);
}
```

Keep empty, corrupt, trailing, context, key-tag, and canonical mismatch as
separate assertions; also keep null-ciphertext, context-mismatch, and
key-tag-mismatch behaviors in separate focused tests. Add a real OpenFHE
canonical-emission test that independently computes `S(D(S(c)))`, compares it
to `codec->Serialize(c)`, and verifies
`S(D(codec->Serialize(c))) == codec->Serialize(c)`. Do not assert that raw
`S(c)` must differ: only the one-pass/fixed-point relations are the contract.
Define a test peer in the `piccard` namespace and use it
to exercise the exact private mismatch branch without adding a public test
seam:

```cpp
class PublicCiphertextCodecTestPeer {
public:
    static void RequireCanonical(
        const std::vector<uint8_t>& supplied,
        const std::vector<uint8_t>& canonical) {
        PublicCiphertextCodec::RequireCanonicalSerialization(
            supplied, canonical);
    }
};

TEST(PublicCiphertextCodecTest, RejectsNonCanonicalByteRepresentation) {
    EXPECT_NO_THROW(PublicCiphertextCodecTestPeer::RequireCanonical(
        {0x01, 0x02}, {0x01, 0x02}));
    EXPECT_THROW(PublicCiphertextCodecTestPeer::RequireCanonical(
        {0x01, 0x02}, {0x01, 0x03}), std::invalid_argument);
}
```

In the same RED change, register only the test target under the existing
OpenFHE/GTest block; do not add `src/fhe/public_ciphertext_codec.cpp` to any
production target yet:

```cmake
add_executable(
    test_public_ciphertext_codec
    tests/unit/test_public_ciphertext_codec.cpp
)
target_link_libraries(test_public_ciphertext_codec piccard_fhe test_main)
add_test(NAME PublicCiphertextCodec COMMAND test_public_ciphertext_codec)
```

- [ ] **Step 2: Run RED and capture the expected reason**

Run:

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
set +e
cmake --build build-work6 -j4 --target test_public_ciphertext_codec \
  > /tmp/work6-task2-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'public_ciphertext_codec|PublicCiphertextCodec|ExportPublicCiphertextCodec' \
  /tmp/work6-task2-red.log
! rg -q 'No rule to make target|unknown target' /tmp/work6-task2-red.log
```

Expected RED: the registered test target compiles the authored test and fails
because `fhe/public_ciphertext_codec.h` and
`BFVContext::ExportPublicCiphertextCodec()` do not exist. A missing target is
not an acceptable RED result.

- [ ] **Step 3: Implement canonical hashing and codec export**

In `src/fhe/bfv_context.cpp`, add local `AppendBE32`, `AppendBE64`, and `Sha256Hex` helpers plus these two exact helpers:

```cpp
std::string ContextFingerprintHex(const BFVContext& context);
std::string PublicKeyFingerprintHex(
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& public_key);
```

Build the canonical context bytes exactly from `context.GetParams().security`, `context.GetCryptoContext()->GetCryptoParameters()`, `context.GetSlotCount()`, and active element towers. Serialize `public_key` using binary `lbcrypto::Serial::Serialize` and hash the declared domain plus those bytes. Add:

```cpp
std::shared_ptr<const PublicCiphertextCodec>
BFVContext::ExportPublicCiphertextCodec() const {
    if (!cc_ || !key_pair_.good() || !key_pair_.publicKey) {
        throw std::logic_error(
            "public ciphertext codec requires initialized context and keys");
    }
    const std::string key_tag = key_pair_.publicKey->GetKeyTag();
    if (key_tag.empty()) {
        throw std::logic_error("generated public key has an empty key tag");
    }
    return std::shared_ptr<const PublicCiphertextCodec>(
        new PublicCiphertextCodec(
            cc_, key_pair_.publicKey, ContextFingerprintHex(*this),
            PublicKeyFingerprintHex(key_pair_.publicKey), key_tag));
}
```

In `src/fhe/public_ciphertext_codec.cpp`, include `ciphertext-ser.h`, `cryptocontext-ser.h`, `key/key-ser.h`, and `scheme/bfvrns/bfvrns-ser.h`. Add private translation-unit helpers `SerializeBinary` and `DeserializeBinaryExact`; the latter rejects empty/corrupt/trailing input and does not perform canonical recursion. Implement one-pass canonical emission and fixed-point checking:

```cpp
std::vector<uint8_t> PublicCiphertextCodec::Serialize(
    const Ciphertext& ciphertext) const {
    if (!ciphertext) throw std::invalid_argument("ciphertext is null");
    if (ciphertext->GetCryptoContext() != context_ ||
        ciphertext->GetKeyTag() != ciphertext_key_tag_) {
        throw std::invalid_argument(
            "ciphertext does not match the live context and public key");
    }
    const auto direct = SerializeBinary(ciphertext);
    const auto normalized = DeserializeBinaryExact(direct);
    RequireLiveBinding(normalized);
    const auto canonical = SerializeBinary(normalized);
    const auto fixed_point = DeserializeBinaryExact(canonical);
    RequireLiveBinding(fixed_point);
    if (SerializeBinary(fixed_point) != canonical) {
        throw std::logic_error(
            "one-pass ciphertext normalization is not a fixed point");
    }
    return canonical;
}

PublicCiphertextCodec::Ciphertext PublicCiphertextCodec::Deserialize(
    const std::vector<uint8_t>& bytes) const {
    const auto ciphertext = DeserializeBinaryExact(bytes);
    RequireLiveBinding(ciphertext);
    RequireCanonicalSerialization(bytes, SerializeBinary(ciphertext));
    return ciphertext;
}
```

`RequireLiveBinding` is a private method or equivalent private helper that
applies the retained live-context and key-tag check. Public `Deserialize` must
compare with direct `SerializeBinary(ciphertext)`, not call public `Serialize`
and normalize a second time. Public `Serialize` performs exactly one
normalization pass and one fixed-point verification; it never loops.

`RequireCanonicalSerialization` throws
`std::invalid_argument("ciphertext bytes are not canonical")` whenever the two
vectors differ. This comparison is part of `Deserialize`, not a caller-side
test-only check.

The class stores only public context, public key, fingerprints, and key tag. It has no decrypt or secret-key member.

- [ ] **Step 4: Register sources and run GREEN**

Add `src/fhe/public_ciphertext_codec.cpp` to `PICCARD_FHE_SOURCES`. Keep the
test-only target registered in Step 1; do not register a second target or
CTest name.

Run:

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
cmake --build build-work6 -j4 --target test_public_ciphertext_codec test_bfv_context
./build-work6/test_public_ciphertext_codec
./build-work6/test_bfv_context
```

Expected: both test executables pass; the new fingerprints are stable within a context and a fresh key changes the public-key binding.

- [ ] **Step 5: Commit and review gate**

```bash
set -euo pipefail
git add include/fhe/public_ciphertext_codec.h src/fhe/public_ciphertext_codec.cpp \
  include/fhe/bfv_context.h src/fhe/bfv_context.cpp \
  tests/unit/test_public_ciphertext_codec.cpp CMakeLists.txt
git commit -m "feat(dynamic): add public ciphertext codec bindings"
```

Completion gate: reviewer verifies the canonical byte order, exact binary
stream consumption, one-pass fixed-point invariant, independent
null/context/key-tag failure tests, no secret-key capability, and no
store/epoch logic in this task.

### Task 3: B2 — Add the minimal versioned atomic two-owner store

**Files:**
- Create: `include/protocol/dynamic_ciphertext_store.h`
- Create: `src/protocol/dynamic_ciphertext_store.cpp`
- Create: `tests/unit/test_dynamic_ciphertext_store.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `PublicCiphertextCodec`; validated `PiccardParams` fields `k`, `m`, `hash_range`, `hash_seed`; serialized ciphertext bytes.
- Produces exactly:

```cpp
struct VersionedCiphertext {
    std::string owner_set_id;
    uint64_t epoch = 0;
    uint64_t hash_seed = 0;
    std::string estimator_model;
    uint32_t k = 0;
    uint32_t m = 0;
    uint64_t hash_range = 0;
    std::string encoding_model;
    std::string context_fingerprint;
    std::string public_key_fingerprint;
    std::string ciphertext_key_tag;
    std::vector<uint8_t> serialized_ciphertext;
};

bool operator==(const VersionedCiphertext& left,
                const VersionedCiphertext& right);

VersionedCiphertext MakeVersionedCiphertext(
    std::string owner_set_id,
    uint64_t epoch,
    const PiccardParams& params,
    const PublicCiphertextCodec& codec,
    std::vector<uint8_t> serialized_ciphertext);

enum class ReplaceStatus { Applied, StaleEpoch, FutureEpoch };

struct ReplaceOutcome {
    ReplaceStatus status;
    uint64_t observed_epoch;
};

struct CloudCiphertextPair {
    VersionedCiphertext first;
    VersionedCiphertext second;
};

class DynamicCiphertextStore final {
public:
    DynamicCiphertextStore(
        std::shared_ptr<const PublicCiphertextCodec> codec,
        VersionedCiphertext first,
        VersionedCiphertext second);

    ReplaceOutcome TryReplace(
        std::string_view owner_set_id,
        uint64_t expected_epoch,
        VersionedCiphertext replacement);

    CloudCiphertextPair ReadPair() const;

private:
    std::shared_ptr<const PublicCiphertextCodec> codec_;
    VersionedCiphertext first_;
    VersionedCiphertext second_;
    mutable std::mutex mutex_;
};
```

- `MakeVersionedCiphertext` uses fixed strings `sha256-random-ranking-poc-v1` and `onehot-mod-m-v1` and copies the codec's three crypto bindings.
- Constructor requires a non-null codec, distinct nonempty owner/set IDs, both epochs zero, identical CRS/encoding/crypto fields, and valid decoded payloads.
- `TryReplace` first requires `expected_epoch != UINT64_MAX`, `replacement.epoch == expected_epoch + 1`, matching nonempty owner ID, valid payload, and matching immutable slot fields. Under one mutex: unknown owner throws; `expected < current` returns stale; `expected > current` returns future; equality replaces the full envelope and returns applied. Failed calls change neither slot.

- [ ] **Step 1: Write failing transition tests**

Create this TOY fixture in `tests/unit/test_dynamic_ciphertext_store.cpp`; it initializes one `BFVContext`, exports one codec, encrypts fresh small feature vectors, and constructs `owner-a`/`owner-b` envelopes:

```cpp
class DynamicCiphertextStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        params.k = 16;
        params.m = 16;
        params.security = SecurityLevel::TOY;
        params.Validate();
        context = std::make_unique<BFVContext>(params);
        context->Initialize();
        codec = context->ExportPublicCiphertextCodec();
    }

    VersionedCiphertext Envelope(
        const std::string& owner_set_id,
        uint64_t epoch,
        int64_t marker) {
        const auto ciphertext = context->Encrypt({marker, 0, 1, 0});
        return MakeVersionedCiphertext(
            owner_set_id, epoch, params, *codec,
            codec->Serialize(ciphertext));
    }

    VersionedCiphertext A(uint64_t epoch) {
        return Envelope("owner-a", epoch, 1);
    }

    VersionedCiphertext B(uint64_t epoch) {
        return Envelope("owner-b", epoch, 2);
    }

    PiccardParams params;
    std::unique_ptr<BFVContext> context;
    std::shared_ptr<const PublicCiphertextCodec> codec;
};
```

Add:

```cpp
TEST_F(DynamicCiphertextStoreTest, AppliesOneOwnerAndDistinguishesReplayFromFuture) {
    DynamicCiphertextStore store(codec, A(0), B(0));
    const VersionedCiphertext peer_before = store.ReadPair().second;

    const auto applied = store.TryReplace("owner-a", 0, A(1));
    EXPECT_EQ(applied.status, ReplaceStatus::Applied);
    EXPECT_EQ(applied.observed_epoch, 1u);
    EXPECT_EQ(store.ReadPair().second, peer_before);

    const auto stale = store.TryReplace("owner-a", 0, A(1));
    EXPECT_EQ(stale.status, ReplaceStatus::StaleEpoch);
    EXPECT_EQ(stale.observed_epoch, 1u);

    const auto future = store.TryReplace("owner-a", 2, A(3));
    EXPECT_EQ(future.status, ReplaceStatus::FutureEpoch);
    EXPECT_EQ(future.observed_epoch, 1u);
    EXPECT_EQ(store.ReadPair().second, peer_before);
}

TEST_F(DynamicCiphertextStoreTest, RejectsOwnerCrsCryptoAndMalformedPackagesAtomically) {
    DynamicCiphertextStore store(codec, A(0), B(0));
    const CloudCiphertextPair before = store.ReadPair();

    auto wrong_owner = A(1);
    wrong_owner.owner_set_id = "owner-c";
    EXPECT_THROW(store.TryReplace("owner-a", 0, wrong_owner),
                 std::invalid_argument);

    auto wrong_crs = A(1);
    ++wrong_crs.hash_seed;
    EXPECT_THROW(store.TryReplace("owner-a", 0, wrong_crs),
                 std::invalid_argument);

    auto wrong_crypto = A(1);
    wrong_crypto.public_key_fingerprint.assign(64, '0');
    EXPECT_THROW(store.TryReplace("owner-a", 0, wrong_crypto),
                 std::invalid_argument);

    auto corrupt = A(1);
    corrupt.serialized_ciphertext = {0x01, 0x02, 0x03};
    EXPECT_THROW(store.TryReplace("owner-a", 0, corrupt),
                 std::invalid_argument);

    EXPECT_EQ(store.ReadPair().first, before.first);
    EXPECT_EQ(store.ReadPair().second, before.second);
}

TEST_F(DynamicCiphertextStoreTest, RejectsSkippedDestinationEpoch) {
    DynamicCiphertextStore store(codec, A(0), B(0));
    EXPECT_THROW(store.TryReplace("owner-a", 0, A(2)),
                 std::invalid_argument);
    EXPECT_EQ(store.ReadPair().first.epoch, 0u);
}
```

Also test constructor rejection for identical owners and mismatched `hash_seed`. These two cases prove slot identity and shared CRS without an exhaustive mismatch matrix.

In the same RED change, register only the test target; do not add the store
source to `PICCARD_FHE_SOURCES` yet:

```cmake
add_executable(
    test_dynamic_ciphertext_store
    tests/unit/test_dynamic_ciphertext_store.cpp
)
target_link_libraries(test_dynamic_ciphertext_store piccard_fhe test_main)
add_test(NAME DynamicCiphertextStore COMMAND test_dynamic_ciphertext_store)
```

- [ ] **Step 2: Run RED**

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
set +e
cmake --build build-work6 -j4 --target test_dynamic_ciphertext_store \
  > /tmp/work6-task3-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'dynamic_ciphertext_store|DynamicCiphertextStore|TryReplace' \
  /tmp/work6-task3-red.log
! rg -q 'No rule to make target|unknown target' /tmp/work6-task3-red.log
```

Expected RED: the registered target compiles the authored test and fails on
the missing `protocol/dynamic_ciphertext_store.h` or its declared symbols. A
missing target is not an acceptable RED result.

- [ ] **Step 3: Implement immutable validation and compare-and-swap**

Use private helpers in `src/protocol/dynamic_ciphertext_store.cpp`:

```cpp
void ValidatePayload(const PublicCiphertextCodec& codec,
                     const VersionedCiphertext& envelope) {
    if (envelope.owner_set_id.empty())
        throw std::invalid_argument("owner_set_id is empty");
    if (envelope.estimator_model != "sha256-random-ranking-poc-v1" ||
        envelope.encoding_model != "onehot-mod-m-v1")
        throw std::invalid_argument("dynamic estimator or encoding model mismatch");
    if (envelope.context_fingerprint != codec.ContextFingerprintHex() ||
        envelope.public_key_fingerprint != codec.PublicKeyFingerprintHex() ||
        envelope.ciphertext_key_tag != codec.CiphertextKeyTag())
        throw std::invalid_argument("dynamic ciphertext crypto binding mismatch");
    static_cast<void>(codec.Deserialize(envelope.serialized_ciphertext));
}

bool SameImmutableBinding(const VersionedCiphertext& left,
                          const VersionedCiphertext& right) {
    return left.owner_set_id == right.owner_set_id &&
           left.hash_seed == right.hash_seed &&
           left.estimator_model == right.estimator_model &&
           left.k == right.k && left.m == right.m &&
           left.hash_range == right.hash_range &&
           left.encoding_model == right.encoding_model &&
           left.context_fingerprint == right.context_fingerprint &&
           left.public_key_fingerprint == right.public_key_fingerprint &&
           left.ciphertext_key_tag == right.ciphertext_key_tag;
}
```

`TryReplace` performs structural/payload checks, locks `mutex_`, selects `first_` or `second_`, validates `SameImmutableBinding`, and then performs the exact stale/future/equal order. `ReadPair()` returns value copies while holding the same mutex. Do not expose a reference or mutable ciphertext object.

- [ ] **Step 4: Register and run GREEN**

Add `src/protocol/dynamic_ciphertext_store.cpp` to `PICCARD_FHE_SOURCES`.
Keep the RED test target and CTest registration from Step 1 unchanged.

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
cmake --build build-work6 -j4 --target test_dynamic_ciphertext_store
./build-work6/test_dynamic_ciphertext_store
```

Expected: all constructor, transition, binding, and immutability assertions pass.

- [ ] **Step 5: Commit and review gate**

```bash
set -euo pipefail
git add include/protocol/dynamic_ciphertext_store.h \
  src/protocol/dynamic_ciphertext_store.cpp \
  tests/unit/test_dynamic_ciphertext_store.cpp CMakeLists.txt
git commit -m "feat(dynamic): add atomic versioned ciphertext store"
```

Completion gate: reviewer confirms one lock protects the complete pair snapshot and replacement, `observed_epoch` semantics match the contract, wrong bindings fail before mutation, and the public header contains no ciphertext-update method other than full `TryReplace`.

### Task 4: B3 — Prove a one-owner full refresh end to end

**Files:**
- Create: `tests/integration/test_dynamic_refresh_e2e.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Tasks 1–3 APIs; existing `DynamicPiccard::InitSet`, `Encrypt`, `EncodeSignature`, `Evaluate`, `Decrypt`; `PublicCiphertextCodec::Deserialize`.
- Produces: integration target/CTest name `test_dynamic_refresh_e2e` / `DynamicRefreshE2E`; no new production API.

- [ ] **Step 1: Write the end-to-end test first**

Create a TOY engine with `k=16`, `m=16`, `bottom_depth=5`, `hash_seed=7`. Build `A={0..49}` and `B={25..74}`. Use this exact helper in the test:

```cpp
VersionedCiphertext EncryptEnvelope(
    const DynamicPiccard& engine,
    const std::shared_ptr<const PublicCiphertextCodec>& codec,
    const std::string& owner_set_id,
    uint64_t epoch,
    const BottomStructure& bottom) {
    const auto ciphertext = engine.Encrypt(bottom);
    return MakeVersionedCiphertext(
        owner_set_id, epoch, engine.GetParams(), *codec,
        codec->Serialize(ciphertext));
}

int64_t LocalMatchCount(const DynamicPiccard& engine,
                        const BottomStructure& left,
                        const BottomStructure& right) {
    const auto a = engine.EncodeSignature(left.GetSignature());
    const auto b = engine.EncodeSignature(right.GetSignature());
    return std::inner_product(a.begin(), a.end(), b.begin(), int64_t{0});
}

int64_t StoredMatchCount(
    const DynamicPiccard& engine,
    const std::shared_ptr<const PublicCiphertextCodec>& codec,
    const CloudCiphertextPair& pair) {
    const auto first = codec->Deserialize(pair.first.serialized_ciphertext);
    const auto second = codec->Deserialize(pair.second.serialized_ciphertext);
    return engine.Decrypt(engine.Evaluate(first, second)).match_count;
}
```

The test installs A@0/B@0, asserts stored equals old local, then scans candidate values `1000..100000` using a copy of A's bottom structure and selects the first whose encoded feature and local A/B match count both differ. Apply only that insertion to A, assert the cloud still reports old local before refresh, freshly encrypt/serialize only A@1, call `TryReplace("owner-a", 0, replacement)`, and assert:

```cpp
EXPECT_EQ(outcome.status, ReplaceStatus::Applied);
EXPECT_NE(old_a.serialized_ciphertext, replacement.serialized_ciphertext);
EXPECT_EQ(store.ReadPair().second, old_b);
EXPECT_EQ(StoredMatchCount(engine, codec, store.ReadPair()), new_local);
EXPECT_NE(old_local, new_local);

auto replay_package = old_a;
replay_package.epoch = 1;
const auto replay = store.TryReplace("owner-a", 0, replay_package);
EXPECT_EQ(replay.status, ReplaceStatus::StaleEpoch);
EXPECT_EQ(StoredMatchCount(engine, codec, store.ReadPair()), new_local);
```

Fail the test with `ASSERT_TRUE(chosen.has_value())` if the bounded deterministic scan finds no changing insertion.

Register the integration target in the same test-only change:

```cmake
add_executable(
    test_dynamic_refresh_e2e
    tests/integration/test_dynamic_refresh_e2e.cpp
)
target_link_libraries(test_dynamic_refresh_e2e piccard_fhe test_main)
add_test(NAME DynamicRefreshE2E COMMAND test_dynamic_refresh_e2e)
```

- [ ] **Step 2: Run the executable integration contract**

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
cmake --build build-work6 -j4 --target test_dynamic_refresh_e2e
./build-work6/test_dynamic_refresh_e2e
```

Expected: the test compiles and passes against the reviewed Tasks 1–3 code.
Task 4 introduces no production behavior, so an artificial RED is forbidden.
If it fails, stop and correct either the test fixture or the preceding task
whose contract is violated; do not add a new production adapter in Task 4.

- [ ] **Step 3: Run the focused dynamic regression set**

Run:

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
cmake --build build-work6 -j4 --target \
  test_bottom_structure test_dynamic_engine \
  test_public_ciphertext_codec test_dynamic_ciphertext_store \
  test_dynamic_refresh_e2e
./build-work6/test_bottom_structure
./build-work6/test_dynamic_engine
./build-work6/test_public_ciphertext_codec
./build-work6/test_dynamic_ciphertext_store
./build-work6/test_dynamic_refresh_e2e
```

Expected: every executable passes; B's complete envelope is unchanged,
cloud-before-refresh remains old, cloud-after-refresh equals the new local
match count, and replay is stale.

- [ ] **Step 4: Commit and review gate**

```bash
set -euo pipefail
git add tests/integration/test_dynamic_refresh_e2e.cpp CMakeLists.txt
git commit -m "test(dynamic): prove one-owner full refresh end to end"
```

Completion gate: reviewer confirms that only A is freshly encrypted, initial A/B ciphertext creation is not mislabeled as refresh cost, the oracle is local plaintext feature equality, and stale replay cannot restore A@0.

### Task 5: C1 — Implement exact ideal deletion-survival analysis

**Files:**
- Create: `include/analysis/deletion_survival.h`
- Create: `src/analysis/deletion_survival.cpp`
- Create: `tests/unit/test_deletion_survival.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces the OpenFHE-free library `piccard_dynamic_analysis` and:

```cpp
struct DeletionSurvivalConfig {
    uint64_t set_size;
    uint32_t bottom_depth;
    uint32_t hash_count;
};

struct DeletionSurvivalSummary {
    uint64_t maximum_safe_deletions;
    long double expected_first_failure_time;
    long double expected_safe_deletions;
};

long double BottomExhaustionProbability(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions);
long double ExactDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions);
long double UnionBoundDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t completed_deletions);
DeletionSurvivalSummary AnalyzeDeletionSurvival(
    const DeletionSurvivalConfig& config, long double required_survival);
```

- Valid config requires `set_size>0`, `bottom_depth>0`, `bottom_depth<=set_size`, `hash_count>0`. Completed deletions must be `<=set_size`; required survival must be finite in `(0,1]`.
- Compute `C(r,d)/C(n,d)` as `product_{i=0}^{d-1}(r-i)/(n-i)` in `long double`; use `exp(k*log1p(-q))` for exact survival and `max(0,1-k*q)` for the union lower bound. Use monotone binary search over `r in [0,n]` for the largest safe budget.

- [ ] **Step 1: Write exact RED tests**

Create `tests/unit/test_deletion_survival.cpp`:

```cpp
TEST(DeletionSurvivalTest, SmallFixtureAndOffByOneSemanticsAreExact) {
    const DeletionSurvivalConfig one{5, 2, 1};
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(one, 2)),
                0.9, 1e-12);
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(one, 3)),
                0.7, 1e-12);
    const DeletionSurvivalConfig two{5, 2, 2};
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(two, 3)),
                0.49, 1e-12);

    const auto summary = AnalyzeDeletionSurvival(one, 0.7L);
    EXPECT_EQ(summary.maximum_safe_deletions, 3u);
    EXPECT_NEAR(static_cast<double>(summary.expected_first_failure_time),
                4.0, 1e-12);
    EXPECT_NEAR(static_cast<double>(summary.expected_safe_deletions),
                3.0, 1e-12);
}

TEST(DeletionSurvivalTest, DefaultPoCGoldensMatchExactAnalysis) {
    const DeletionSurvivalConfig config{1024, 5, 128};
    const auto summary = AnalyzeDeletionSurvival(config, 0.99L);
    EXPECT_EQ(summary.maximum_safe_deletions, 156u);
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(config, 156)),
                0.990106970136603, 1e-12);
    EXPECT_NEAR(static_cast<double>(ExactDeletionSurvival(config, 157)),
                0.989783196554901, 1e-12);
    EXPECT_NEAR(static_cast<double>(summary.expected_first_failure_time),
                357.745231932978, 1e-9);
    EXPECT_NEAR(static_cast<double>(summary.expected_safe_deletions),
                356.745231932978, 1e-9);
}
```

Add one test asserting union survival is `0.4` for `(n,d,k,r)=(5,2,2,3)` while exact is `0.49`, and one invalid-input test for `d>n` and `r>n`.

In the same RED change, register a test-only target linked only to `test_main`
and the repository include directory. Do not create or link
`piccard_dynamic_analysis` yet:

```cmake
add_executable(
    test_deletion_survival
    tests/unit/test_deletion_survival.cpp
)
target_include_directories(test_deletion_survival PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_deletion_survival test_main)
add_test(NAME DeletionSurvival COMMAND test_deletion_survival)
```

- [ ] **Step 2: Run RED**

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
set +e
cmake --build build-work6 -j4 --target test_deletion_survival \
  > /tmp/work6-task5-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'deletion_survival|DeletionSurvival' /tmp/work6-task5-red.log
! rg -q 'No rule to make target|unknown target' /tmp/work6-task5-red.log
```

Expected RED: the registered test target compiles the authored tests and fails
because `analysis/deletion_survival.h` and its symbols are absent. A missing
target is not an acceptable RED result.

- [ ] **Step 3: Implement the exact formulas**

The core implementation is:

```cpp
long double BottomExhaustionProbability(
    const DeletionSurvivalConfig& config, uint64_t r) {
    Validate(config, r);
    if (r < config.bottom_depth) return 0.0L;
    long double ratio = 1.0L;
    for (uint32_t i = 0; i < config.bottom_depth; ++i) {
        ratio *= static_cast<long double>(r - i) /
                 static_cast<long double>(config.set_size - i);
    }
    return ratio;
}

long double ExactDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t r) {
    const long double q = BottomExhaustionProbability(config, r);
    if (q == 1.0L) return 0.0L;
    return std::exp(static_cast<long double>(config.hash_count) *
                    std::log1p(-q));
}
```

Calculate expected first failure as the sum for `r=0` through `n-1` inclusive, then subtract exactly `1.0L` for expected safe deletions. Name local variables `first_failure` and `safe_deletions`; do not collapse the semantics into an unnamed mean.

- [ ] **Step 4: Register and run GREEN in a core-only build**

In CMake create `piccard_dynamic_analysis` from
`src/analysis/deletion_survival.cpp`, expose `include/`, and replace the RED
target's link line with `piccard_dynamic_analysis test_main`. Keep its existing
CTest registration.

```bash
set -euo pipefail
cmake -S . -B build-work6-core -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_DISABLE_FIND_PACKAGE_OpenFHE=TRUE
cmake --build build-work6-core -j4 --target test_deletion_survival
./build-work6-core/test_deletion_survival
```

Expected: all exact tests pass and the target configures/builds without OpenFHE.

- [ ] **Step 5: Commit and review gate**

```bash
set -euo pipefail
git add include/analysis/deletion_survival.h \
  src/analysis/deletion_survival.cpp tests/unit/test_deletion_survival.cpp \
  CMakeLists.txt
git commit -m "feat(analysis): add exact deletion survival"
```

Completion gate: reviewer recomputes the two small fixtures, verifies binary search returns 156 at 99%, and checks `E[T]` versus `E[T]-1` names and assertions.

### Task 6: C2 — Add deterministic ideal-model Monte Carlo and CSV CLI

**Files:**
- Create: `include/analysis/deletion_monte_carlo.h`
- Create: `src/analysis/deletion_monte_carlo.cpp`
- Create: `tests/unit/test_deletion_monte_carlo.cpp`
- Create: `benchmarks/bench_deletion_survival.cpp`
- Create: `tests/scripts/test_bench_deletion_survival.py`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `DeletionSurvivalConfig` and analytic functions from Task 5.
- Produces:

```cpp
uint64_t UniformBelow(std::mt19937_64& generator, uint64_t bound);
uint64_t SampleFirstFailure(
    const DeletionSurvivalConfig& config, std::mt19937_64& generator);

struct DeletionMonteCarloResult {
    uint64_t trials;
    uint64_t seed;
    std::vector<uint64_t> failure_histogram;
    long double mean_first_failure_time;
    long double mean_safe_deletions;

    long double SurvivalAt(uint64_t completed_deletions) const;
    long double StandardErrorAt(uint64_t completed_deletions) const;
};

DeletionMonteCarloResult SimulateDeletionSurvival(
    const DeletionSurvivalConfig& config, uint64_t trials, uint64_t seed);
```

- `UniformBelow(bound)` requires `bound>0`, sets `threshold=(-bound)%bound`, consumes raw `mt19937_64` words until `word>=threshold`, and returns `word%bound`.
- For each coordinate, Floyd-sample a uniform `d`-subset of positions `1..n`: for `j=n-d+1..n`, sample `t=UniformBelow(j)+1`, insert `j` if `t` is already present, else insert `t`. The coordinate fails at its maximum selected position; global `T` is the minimum coordinate failure.
- CLI exact form:

```text
bench_deletion_survival --n=N --d=D --k=K --required_survival=P --r_values=R1,R2 --trials=1 --seed=S
```

- CSV columns are exactly:

```text
model,n,d,k,required_survival,r,exact_survival,union_bound_survival,mc_survival,mc_standard_error,maximum_safe_deletions,exact_expected_first_failure,exact_expected_safe_deletions,mc_mean_first_failure,mc_mean_safe_deletions,trials,seed
```

and model is `ideal-independent-random-ranking-v1`.

- [ ] **Step 1: Write deterministic RED tests**

In `tests/unit/test_deletion_monte_carlo.cpp`, pin the portable RNG and one-trial outcome:

```cpp
TEST(DeletionMonteCarloTest, UniformBelowUsesPortableRawWordRejection) {
    std::mt19937_64 raw(20260729);
    EXPECT_EQ(raw(), UINT64_C(0x13abed35ef7208d7));
    EXPECT_EQ(raw(), UINT64_C(0xa821398ce4959c44));
    EXPECT_EQ(raw(), UINT64_C(0x3ec9d6707639929d));
    EXPECT_EQ(raw(), UINT64_C(0xb2413cc1f3082f90));
    EXPECT_EQ(raw(), UINT64_C(0x2376e8e55d856132));
    EXPECT_EQ(raw(), UINT64_C(0xc3cb86fe4cb18180));

    std::mt19937_64 generator(20260729);
    EXPECT_EQ(UniformBelow(generator, 1), 0u);
    EXPECT_EQ(UniformBelow(generator, 2), 0u);
    EXPECT_EQ(UniformBelow(generator, 3), 2u);
    EXPECT_EQ(UniformBelow(generator, 10), 8u);
    EXPECT_EQ(UniformBelow(generator, 1024), 306u);
    EXPECT_EQ(UniformBelow(generator, 1000), 296u);
}

TEST(DeletionMonteCarloTest, OneTrialIsSeededAndUsesStrictTGreaterThanR) {
    const DeletionSurvivalConfig config{8, 2, 3};
    const auto first = SimulateDeletionSurvival(config, 1, 7);
    const auto second = SimulateDeletionSurvival(config, 1, 7);
    EXPECT_EQ(first.failure_histogram, second.failure_histogram);
    ASSERT_EQ(first.failure_histogram.size(), 9u);
    EXPECT_EQ(first.failure_histogram[3], 1u);
    EXPECT_EQ(std::accumulate(first.failure_histogram.begin(),
                              first.failure_histogram.end(), uint64_t{0}),
              1u);
    EXPECT_EQ(first.SurvivalAt(2), 1.0L);
    EXPECT_EQ(first.SurvivalAt(3), 0.0L);
    EXPECT_EQ(first.mean_first_failure_time, 3.0L);
    EXPECT_EQ(first.mean_safe_deletions, 2.0L);
}
```

Create `tests/scripts/test_bench_deletion_survival.py`; take the executable path from `sys.argv[1]`, run:

```python
[BENCH, "--n=64", "--d=3", "--k=8", "--required_survival=0.99",
 "--r_values=1,4,8", "--trials=1", "--seed=7"]
```

and assert exit zero, exact header, three data rows, every model cell exact, every `trials` cell `1`, every seed `7`, MC survival in `{0,1}`, and the same summary fields on all three rows. The C++ parser retains a direct `trials != 1` guard; no Work 6 test launches a benchmark with any other trial count.

In the same RED change, register test-only compile targets without adding MC
production sources to `piccard_dynamic_analysis`:

```cmake
add_executable(
    test_deletion_monte_carlo
    tests/unit/test_deletion_monte_carlo.cpp
)
target_include_directories(test_deletion_monte_carlo PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(test_deletion_monte_carlo test_main)
add_test(NAME DeletionMonteCarlo COMMAND test_deletion_monte_carlo)

add_executable(
    bench_deletion_survival
    benchmarks/bench_deletion_survival.cpp
)
target_include_directories(bench_deletion_survival PRIVATE ${CMAKE_SOURCE_DIR}/include)
```

- [ ] **Step 2: Run RED**

```bash
set -euo pipefail
cmake -S . -B build-work6-core -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_DISABLE_FIND_PACKAGE_OpenFHE=TRUE
set +e
cmake --build build-work6-core -j4 --target \
  test_deletion_monte_carlo bench_deletion_survival \
  > /tmp/work6-task6-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'deletion_monte_carlo|DeletionMonteCarlo' /tmp/work6-task6-red.log
! rg -q 'No rule to make target|unknown target' /tmp/work6-task6-red.log
```

Expected RED: both registered targets compile their authored sources and fail
on the missing `analysis/deletion_monte_carlo.h`/symbols. Missing targets are
not an acceptable RED result.

- [ ] **Step 3: Implement the sampler and one-trial guard**

Use `std::unordered_set<uint64_t>` for each Floyd subset. Build a histogram of length `n+1`; valid `T` lies in `1..n`. `SurvivalAt(r)` sums histogram entries for indexes strictly greater than `r`. Standard error is `sqrt(p*(1-p)/trials)`.

In the CLI parser, use `std::from_chars` for integer options, `std::stold` with exact consumption for the probability, reject duplicate/missing options, reject `trials != 1`, validate every requested `r<=n`, and print long-double values with `std::setprecision(17)`.

- [ ] **Step 4: Register and run GREEN core-only**

Add `src/analysis/deletion_monte_carlo.cpp` to
`piccard_dynamic_analysis`. Replace the RED targets' link lines so
`test_deletion_monte_carlo` links `piccard_dynamic_analysis test_main` and
`bench_deletion_survival` links only `piccard_dynamic_analysis`. Register
`DeletionSurvivalCli` only when `BUILD_TESTS`, passing
`$<TARGET_FILE:bench_deletion_survival>` to the Python test.

```bash
set -euo pipefail
cmake -S . -B build-work6-core -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_DISABLE_FIND_PACKAGE_OpenFHE=TRUE
cmake --build build-work6-core -j4 --target \
  test_deletion_survival test_deletion_monte_carlo bench_deletion_survival
./build-work6-core/test_deletion_survival
./build-work6-core/test_deletion_monte_carlo
python3 tests/scripts/test_bench_deletion_survival.py \
  ./build-work6-core/bench_deletion_survival
```

Expected: all tests pass with exactly one simulated trial; no statistical-accuracy claim is made from that single draw.

- [ ] **Step 5: Commit and review gate**

```bash
set -euo pipefail
git add include/analysis/deletion_monte_carlo.h \
  src/analysis/deletion_monte_carlo.cpp \
  tests/unit/test_deletion_monte_carlo.cpp \
  benchmarks/bench_deletion_survival.cpp \
  tests/scripts/test_bench_deletion_survival.py CMakeLists.txt
git commit -m "feat(analysis): add seeded deletion survival simulation"
```

Completion gate: reviewer checks the six pinned raw outcomes, Floyd interval and collision substitution, `T>r` convention, one-trial enforcement, ideal-model label, and OpenFHE-free linkage.

### Task 7: D1 — Measure one-owner refresh timing and upload bytes

**Files:**
- Modify: `benchmarks/benchmark_estimator_provenance.h`
- Modify: `benchmarks/benchmark_estimator_provenance.cpp`
- Create: `benchmarks/dynamic_refresh_benchmark.h`
- Create: `benchmarks/dynamic_refresh_benchmark.cpp`
- Modify: `benchmarks/bench_dynamic.cpp`
- Modify: `tests/unit/test_estimator_provenance_serializers.cpp`
- Create: `tests/unit/test_dynamic_refresh_benchmark.cpp`
- Create: `tests/scripts/test_bench_dynamic_refresh_cli.py`
- Modify: `tests/fixtures/runner/dynamic_toy_rows.csv`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Append these exact fields to `DynamicResult`:

```cpp
std::string dynamic_scenario = "legacy";
std::optional<std::string> refresh_owner_set_id;
std::optional<uint64_t> refresh_updates;
std::optional<uint64_t> refresh_epoch_before;
std::optional<uint64_t> refresh_epoch_after;
std::optional<std::string> refresh_status;
std::optional<double> phase_refresh_update_ms;
std::optional<double> phase_refresh_signature_ms;
std::optional<double> phase_refresh_encode_ms;
std::optional<double> phase_refresh_encrypt_ms;
std::optional<double> phase_refresh_serialize_ms;
std::optional<double> phase_cloud_replace_ms;
std::optional<double> refresh_total_ms;
std::optional<size_t> refresh_upload_bytes;
std::optional<uint32_t> refresh_ciphertexts_uploaded;
std::optional<std::string> refresh_context_fingerprint;
std::optional<std::string> refresh_public_key_fingerprint;
```

- Append the same CSV columns after inherited `openfhe_version`:

```text
dynamic_scenario,refresh_owner_set_id,refresh_updates,refresh_epoch_before,
refresh_epoch_after,refresh_status,phase_refresh_update_ms,
phase_refresh_signature_ms,phase_refresh_encode_ms,phase_refresh_encrypt_ms,
phase_refresh_serialize_ms,phase_cloud_replace_ms,refresh_total_ms,
refresh_upload_bytes,refresh_ciphertexts_uploaded,
refresh_context_fingerprint,refresh_public_key_fingerprint
```

- Produces:

```cpp
DynamicResult RunSingleOwnerRefresh(
    const DynamicPiccard& engine,
    const std::vector<uint64_t>& set_a,
    const std::vector<uint64_t>& set_b,
    uint32_t depth,
    uint64_t refresh_updates);
```

- `bench_dynamic` accepts `--scenario=legacy|refresh` (default legacy) and `--refresh_updates=N`. Refresh requires `scenario=refresh`, `mode=timing`, named `toy-smoke`, `security=TOY`, `evidence_point=true`, `trials=1`, and `refresh_updates>0`. Legacy rejects `--refresh_updates`.
- One refresh call has no warmup. Initial A@0/B@0 encryption and store construction occur before timers. Timed phases are A-only local insert batch, A signature, A encoding, fresh A full encryption, A binary serialization, and `TryReplace` A `0->1`. `refresh_total_ms` is their per-call sum and equals inherited `total_ms`; `refresh_upload_bytes` is the serialized A@1 ciphertext byte count; `refresh_ciphertexts_uploaded=1`.

- [ ] **Step 1: Write serializer and live TOY RED tests**

In `tests/unit/test_estimator_provenance_serializers.cpp`, extend
`DynamicGoldenSchema`'s exact expected header with all 17 appended columns.
Extend its legacy expected row with `dynamic_scenario=legacy` followed by
exactly 16 empty cells, and assert the inherited prefix remains byte-for-byte
unchanged. In `tests/fixtures/runner/dynamic_toy_rows.csv`, append the same 17
header columns and append `legacy` plus 16 empty cells to every existing
legacy row. Do not add the refresh evidence row yet; Task 8 owns that addition.
This fixture alignment deliberately makes the existing serializer golden and
`RunnerFixtures.DynamicFixtureHeaderMatchesProduction` fail against the old
production serializer during RED.

Create `tests/unit/test_dynamic_refresh_benchmark.cpp`. First construct a complete `DynamicResult` refresh fixture, serialize it, parse header/row with a small comma splitter, and assert every appended value by column name. Use timing components `1,2,3,4,5,6` and total `21`.

Add a live test:

```cpp
TEST(DynamicRefreshBenchmarkTest, MeasuresExactlyOneOwnerZeroToOne) {
    PiccardParams params;
    params.k = 16;
    params.m = 16;
    params.bottom_depth = 5;
    params.hash_seed = 7;
    params.security = SecurityLevel::TOY;
    params.Validate();
    DynamicPiccard engine(params);
    engine.KeyGen();

    std::vector<uint64_t> a;
    std::vector<uint64_t> b;
    for (uint64_t value = 0; value < 100; ++value) a.push_back(value);
    for (uint64_t value = 50; value < 150; ++value) b.push_back(value);

    const DynamicResult row = RunSingleOwnerRefresh(engine, a, b, 5, 1);
    EXPECT_EQ(row.dynamic_scenario, "refresh");
    EXPECT_EQ(row.refresh_owner_set_id, "owner-a");
    EXPECT_EQ(row.refresh_updates, 1u);
    EXPECT_EQ(row.refresh_epoch_before, 0u);
    EXPECT_EQ(row.refresh_epoch_after, 1u);
    EXPECT_EQ(row.refresh_status, "applied");
    EXPECT_EQ(row.refresh_ciphertexts_uploaded, 1u);
    ASSERT_TRUE(row.refresh_upload_bytes.has_value());
    EXPECT_GT(*row.refresh_upload_bytes, 0u);
    ASSERT_TRUE(row.refresh_total_ms.has_value());
    EXPECT_DOUBLE_EQ(row.total_ms, *row.refresh_total_ms);
    EXPECT_DOUBLE_EQ(row.total_ms_median, row.total_ms);
    EXPECT_DOUBLE_EQ(row.total_ms_sd, -1.0);
    EXPECT_DOUBLE_EQ(row.phase_insert_ms, *row.phase_refresh_update_ms);
    EXPECT_DOUBLE_EQ(row.phase_signature_ms, *row.phase_refresh_signature_ms);
    EXPECT_DOUBLE_EQ(row.phase_encode_ms, *row.phase_refresh_encode_ms);
    EXPECT_DOUBLE_EQ(row.phase_encrypt_ms, *row.phase_refresh_encrypt_ms);
    EXPECT_DOUBLE_EQ(row.phase_insert_ms_median, row.phase_insert_ms);
    EXPECT_DOUBLE_EQ(row.phase_signature_ms_median, row.phase_signature_ms);
    EXPECT_DOUBLE_EQ(row.phase_encode_ms_median, row.phase_encode_ms);
    EXPECT_DOUBLE_EQ(row.phase_encrypt_ms_median, row.phase_encrypt_ms);
    EXPECT_EQ(row.ct_size_bytes, *row.refresh_upload_bytes);
    EXPECT_DOUBLE_EQ(
        row.jaccard_error,
        std::abs(row.jaccard_computed - row.jaccard_expected));
    ASSERT_GT(row.jaccard_expected, 0.0);
    EXPECT_DOUBLE_EQ(
        row.jaccard_rel_error,
        row.jaccard_error / row.jaccard_expected);
    EXPECT_EQ(row.rel_error_eligible_n, 1u);
    EXPECT_EQ(row.trials, 1u);
}
```

In the same RED change, register only the authored test target. Do not add
`dynamic_refresh_benchmark.cpp` to `bench_dynamic` or any library yet:

```cmake
add_executable(
    test_dynamic_refresh_benchmark
    tests/unit/test_dynamic_refresh_benchmark.cpp
)
target_include_directories(test_dynamic_refresh_benchmark PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
target_link_libraries(
    test_dynamic_refresh_benchmark
    piccard_fhe piccard_benchmark_serializers test_main
)
add_test(NAME DynamicRefreshBenchmark COMMAND test_dynamic_refresh_benchmark)
```

- [ ] **Step 2: Run RED**

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
cmake --build build-work6 -j4 --target test_estimator_provenance_serializers
set +e
./build-work6/test_estimator_provenance_serializers \
  --gtest_filter='EstimatorProvenanceSerializers.DynamicGoldenSchema:RunnerFixtures.DynamicFixtureHeaderMatchesProduction' \
  > /tmp/work6-task7-golden-red.log 2>&1
GOLDEN_RED_STATUS=$?
cmake --build build-work6 -j4 --target test_dynamic_refresh_benchmark \
  > /tmp/work6-task7-refresh-red.log 2>&1
REFRESH_RED_STATUS=$?
set -e
test "$GOLDEN_RED_STATUS" -ne 0
test "$REFRESH_RED_STATUS" -ne 0
rg -q 'DynamicGoldenSchema|DynamicFixtureHeaderMatchesProduction' \
  /tmp/work6-task7-golden-red.log
rg -q 'dynamic_refresh_benchmark|RunSingleOwnerRefresh|DynamicResult' \
  /tmp/work6-task7-refresh-red.log
! rg -q 'No rule to make target|unknown target' \
  /tmp/work6-task7-refresh-red.log
```

Expected RED: the existing serializer executable builds, then the two focused
goldens fail because production still emits the old header/row. The newly
registered refresh test compiles far enough to fail because `DynamicResult`
has no refresh fields and `dynamic_refresh_benchmark.h`/
`RunSingleOwnerRefresh` do not exist. A missing target or a fixture parse error
is not an acceptable RED result.

- [ ] **Step 3: Append serializer fields without altering inherited columns**

Reuse the translation unit's existing `WriteOptional(std::ostringstream&, const std::optional<T>&)` template. In `SerializeDynamicHeader()`, replace the terminal literal `"openfhe_version\n"` with `"openfhe_version,dynamic_scenario,refresh_owner_set_id,refresh_updates,refresh_epoch_before,refresh_epoch_after,refresh_status,phase_refresh_update_ms,phase_refresh_signature_ms,phase_refresh_encode_ms,phase_refresh_encrypt_ms,phase_refresh_serialize_ms,phase_cloud_replace_ms,refresh_total_ms,refresh_upload_bytes,refresh_ciphertexts_uploaded,refresh_context_fingerprint,refresh_public_key_fingerprint\n"`.

In `SerializeDynamicRow()`, replace the terminal `out << "\n";` after `WriteBenchmarkProvenanceFields` with this exact suffix:

```cpp
    out << "," << r.dynamic_scenario << ",";
    WriteOptional(out, r.refresh_owner_set_id);
    out << ",";
    WriteOptional(out, r.refresh_updates);
    out << ",";
    WriteOptional(out, r.refresh_epoch_before);
    out << ",";
    WriteOptional(out, r.refresh_epoch_after);
    out << ",";
    WriteOptional(out, r.refresh_status);
    out << "," << std::fixed << std::setprecision(3);
    WriteOptional(out, r.phase_refresh_update_ms);
    out << ",";
    WriteOptional(out, r.phase_refresh_signature_ms);
    out << ",";
    WriteOptional(out, r.phase_refresh_encode_ms);
    out << ",";
    WriteOptional(out, r.phase_refresh_encrypt_ms);
    out << ",";
    WriteOptional(out, r.phase_refresh_serialize_ms);
    out << ",";
    WriteOptional(out, r.phase_cloud_replace_ms);
    out << ",";
    WriteOptional(out, r.refresh_total_ms);
    out << ",";
    WriteOptional(out, r.refresh_upload_bytes);
    out << ",";
    WriteOptional(out, r.refresh_ciphertexts_uploaded);
    out << ",";
    WriteOptional(out, r.refresh_context_fingerprint);
    out << ",";
    WriteOptional(out, r.refresh_public_key_fingerprint);
    out << "\n";
```

Legacy default is `dynamic_scenario=legacy` and all 16 refresh-only cells empty.

- [ ] **Step 4: Implement the one-owner measurement**

In `dynamic_refresh_benchmark.cpp`, initialize bottom structures and initial envelopes before timing. Copy B's full envelope. Before the timers, copy `set_a` to `refreshed_set_a`, reserve `set_a.size()+refresh_updates`, and compute `next_value=*std::max_element(set_a.begin(), set_a.end())+1`; reject empty input sets and zero updates. During the A-only refresh:

```cpp
Timer timer;
timer.Start();
for (uint64_t offset = 0; offset < refresh_updates; ++offset) {
    const uint64_t value = next_value + offset;
    refreshed_set_a.push_back(value);
    bottom_a->Insert(value);
}
row.phase_refresh_update_ms = timer.ElapsedMs();

timer.Start();
const auto signature_a = bottom_a->GetSignature();
row.phase_refresh_signature_ms = timer.ElapsedMs();

timer.Start();
const auto feature_a = engine.EncodeSignature(signature_a);
row.phase_refresh_encode_ms = timer.ElapsedMs();

timer.Start();
const auto ciphertext_a = engine.EncryptFeature(feature_a);
row.phase_refresh_encrypt_ms = timer.ElapsedMs();

timer.Start();
const auto upload = codec->Serialize(ciphertext_a);
row.phase_refresh_serialize_ms = timer.ElapsedMs();

const auto replacement = MakeVersionedCiphertext(
    "owner-a", 1, engine.GetParams(), *codec, upload);
timer.Start();
const auto outcome = store.TryReplace("owner-a", 0, replacement);
row.phase_cloud_replace_ms = timer.ElapsedMs();
```

Sum the six recorded doubles, then bind every inherited timing alias exactly:

```cpp
row.phase_insert_ms = *row.phase_refresh_update_ms;
row.phase_insert_ms_median = row.phase_insert_ms;
row.phase_insert_ms_sd = -1.0;
row.phase_signature_ms = *row.phase_refresh_signature_ms;
row.phase_signature_ms_median = row.phase_signature_ms;
row.phase_signature_ms_sd = -1.0;
row.phase_encode_ms = *row.phase_refresh_encode_ms;
row.phase_encode_ms_median = row.phase_encode_ms;
row.phase_encode_ms_sd = -1.0;
row.phase_encrypt_ms = *row.phase_refresh_encrypt_ms;
row.phase_encrypt_ms_median = row.phase_encrypt_ms;
row.phase_encrypt_ms_sd = -1.0;
row.phase_init_ms = row.phase_delete_ms = row.phase_compute_ms =
    row.phase_decrypt_ms = row.phase_flood_ms = 0.0;
row.phase_init_ms_median = row.phase_delete_ms_median =
    row.phase_compute_ms_median = row.phase_decrypt_ms_median =
    row.phase_flood_ms_median = 0.0;
row.phase_init_ms_sd = row.phase_delete_ms_sd =
    row.phase_compute_ms_sd = row.phase_decrypt_ms_sd =
    row.phase_flood_ms_sd = -1.0;
row.total_ms = *row.refresh_total_ms;
row.total_ms_median = row.total_ms;
row.total_ms_sd = -1.0;
row.ct_size_bytes = *row.refresh_upload_bytes;
```

After timing, deserialize the stored pair, evaluate/decrypt it, compute the
local encoded-vector inner product, throw `std::runtime_error` on mismatch,
and throw if stored B differs from the saved B envelope.

Populate `refresh_context_fingerprint` and `refresh_public_key_fingerprint`
from the codec; populate `hash_seed`/`hash_root_seed` from the engine,
`hash_randomness="fixed"`, `accuracy_trials=0`, and `trials=1`. Compute
`jaccard_expected` from `refreshed_set_a` and `set_b`, while
`jaccard_computed` is the decrypted refreshed estimator result. Bind all
inherited accuracy fields before returning:

```cpp
row.jaccard_error =
    std::abs(row.jaccard_computed - row.jaccard_expected);
if (row.jaccard_expected > 0.0) {
    row.jaccard_rel_error = row.jaccard_error / row.jaccard_expected;
    row.rel_error_eligible_n = 1;
} else {
    row.jaccard_rel_error = -1.0;
    row.rel_error_eligible_n = 0;
}
```

The live TOY test above exercises the positive-expected branch and asserts all
five inherited accuracy cells are mutually consistent; no default metric is
accepted as evidence.

- [ ] **Step 5: Route strict CLI refresh mode**

Parse `--scenario=` and `--refresh_updates=` before `RejectUnknownBenchmarkOptions`; include both prefixes in that call. For refresh, call `RunSingleOwnerRefresh` exactly once on the supplied evidence point, set estimator/sanitizer/live BFV provenance, call `ApplyBenchmarkProfile(config, row, BenchmarkMeasurementKind::FheTiming)`, then write one row and return. Do not call `RunMultiTrialDynamic`, its warmup, or a native profile grid.

- [ ] **Step 6: Register and run GREEN**

Add `dynamic_refresh_benchmark.cpp` to `bench_dynamic` sources and to the
already registered RED unit target. Keep its include directories, link
libraries, and CTest registration unchanged.

```bash
set -euo pipefail
cmake -S . -B build-work6 -DCMAKE_BUILD_TYPE=Release
cmake --build build-work6 -j4 --target \
  test_estimator_provenance_serializers \
  test_dynamic_refresh_benchmark bench_dynamic
./build-work6/test_estimator_provenance_serializers
./build-work6/test_dynamic_refresh_benchmark
./build-work6/bench_dynamic \
  --scenario=refresh --refresh_updates=1 \
  --profile=toy-smoke --security=TOY --mode=timing --evidence_point \
  --k=16 --m=16 --set_size=100 --target-jaccard=0.5 \
  --depth=5 --trials=1 --seed=7 \
  > /tmp/piccard-work6-refresh.csv
```

Expected: test passes; CSV contains one header and one applied A `0->1` row, one uploaded ciphertext, positive byte count, and no warmup row.

- [ ] **Step 7: Commit and review gate**

```bash
set -euo pipefail
git add benchmarks/benchmark_estimator_provenance.h \
  benchmarks/benchmark_estimator_provenance.cpp \
  benchmarks/dynamic_refresh_benchmark.h \
  benchmarks/dynamic_refresh_benchmark.cpp benchmarks/bench_dynamic.cpp \
  tests/unit/test_estimator_provenance_serializers.cpp \
  tests/unit/test_dynamic_refresh_benchmark.cpp \
  tests/scripts/test_bench_dynamic_refresh_cli.py \
  tests/fixtures/runner/dynamic_toy_rows.csv CMakeLists.txt
git commit -m "feat(benchmarks): measure one-owner dynamic refresh"
```

Completion gate: reviewer traces every timed field to one A-only phase, confirms A/B initialization is outside timing, total is the six-component sum, upload bytes equal serialized A@1 bytes, correctness is checked after timing, and the executable refuses non-TOY or `trials!=1` refresh runs.

### Task 8: D2 — Gate refresh provenance and add the one-trial runner cell

**Files:**
- Modify: `scripts/verify_benchmark_provenance.py`
- Modify: `tests/scripts/test_verify_benchmark_provenance.py`
- Modify: `scripts/run_pre_threshold_profiles.sh`
- Modify: `tests/scripts/test_run_pre_threshold_profiles.py`
- Modify: `tests/fixtures/runner/dynamic_toy_rows.csv`

**Interfaces:**
- Consumes: Task 7 appended CSV schema and `bench_dynamic` refresh CLI.
- Produces: dynamic verifier rules for `dynamic_scenario=refresh`; smoke runner matrix adds exactly one dynamic refresh cell; all executed smoke repetition/accuracy arguments are one.

- Refresh verifier required values: profile `toy-smoke`, run class `smoke`, target security `0`, comparison eligible `false`, measurement kind `fhe-timing`, trials `1`, accuracy trials `0`, fixed hash randomness and seed/root seed `7`, estimator and sanitizer/live BFV metadata already validated by `_validate_models` and `_validate_fhe`, owner `owner-a`, updates positive, epochs `0` and `1`, status `applied`, nonnegative six phases, positive total/upload, one ciphertext, lowercase 64-hex context/public-key fingerprints, and `abs(refresh_total_ms-sum(components))<=0.01` for three-decimal CSV rounding. It also requires `total_ms==total_ms_median==refresh_total_ms`, `total_ms_sd==-1`, `ct_size_bytes==refresh_upload_bytes`, the four inherited insert/signature/encode/encrypt aliases and medians to equal their refresh components with SD `-1`, and inherited init/delete/compute/decrypt/flood values and medians to be `0` with SD `-1`. The inherited accuracy cells must satisfy `0<=jaccard_computed<=1`, `0<jaccard_expected<=1`, `abs(jaccard_error-abs(jaccard_computed-jaccard_expected))<=0.000002`, `abs(jaccard_rel_error-jaccard_error/jaccard_expected)<=0.000005`, and `rel_error_eligible_n==1`; these tolerances cover independent six-decimal CSV rounding only.
- Legacy dynamic rows require `dynamic_scenario=legacy` and empty refresh-only cells.

- [ ] **Step 1: Add failing verifier fixtures**

Extend `DYNAMIC_HEADER` and `dynamic_row` in `tests/scripts/test_verify_benchmark_provenance.py`. Add:

```python
def refresh_row(**overrides):
    values = {
        "dynamic_scenario": "refresh",
        "refresh_owner_set_id": "owner-a",
        "refresh_updates": "1",
        "refresh_epoch_before": "0",
        "refresh_epoch_after": "1",
        "refresh_status": "applied",
        "phase_refresh_update_ms": "1.000",
        "phase_refresh_signature_ms": "2.000",
        "phase_refresh_encode_ms": "3.000",
        "phase_refresh_encrypt_ms": "4.000",
        "phase_refresh_serialize_ms": "5.000",
        "phase_cloud_replace_ms": "6.000",
        "refresh_total_ms": "21.000",
        "total_ms": "21.000",
        "total_ms_sd": "-1.000",
        "total_ms_median": "21.000",
        "ct_size_bytes": "4096",
        "phase_init_ms": "0.000",
        "phase_init_ms_sd": "-1.000",
        "phase_init_ms_median": "0.000",
        "phase_insert_ms": "1.000",
        "phase_insert_ms_sd": "-1.000",
        "phase_insert_ms_median": "1.000",
        "phase_delete_ms": "0.000",
        "phase_delete_ms_sd": "-1.000",
        "phase_delete_ms_median": "0.000",
        "phase_signature_ms": "2.000",
        "phase_signature_ms_sd": "-1.000",
        "phase_signature_ms_median": "2.000",
        "phase_encode_ms": "3.000",
        "phase_encode_ms_sd": "-1.000",
        "phase_encode_ms_median": "3.000",
        "phase_encrypt_ms": "4.000",
        "phase_encrypt_ms_sd": "-1.000",
        "phase_encrypt_ms_median": "4.000",
        "phase_compute_ms": "0.000",
        "phase_compute_ms_sd": "-1.000",
        "phase_compute_ms_median": "0.000",
        "phase_decrypt_ms": "0.000",
        "phase_decrypt_ms_sd": "-1.000",
        "phase_decrypt_ms_median": "0.000",
        "phase_flood_ms": "0.000",
        "phase_flood_ms_sd": "-1.000",
        "phase_flood_ms_median": "0.000",
        "jaccard_computed": "0.600000",
        "jaccard_expected": "0.499250",
        "jaccard_error": "0.100750",
        "jaccard_rel_error": "0.201803",
        "rel_error_eligible_n": "1",
        "refresh_upload_bytes": "4096",
        "refresh_ciphertexts_uploaded": "1",
        "refresh_context_fingerprint": "1" * 64,
        "refresh_public_key_fingerprint": "2" * 64,
    }
    values.update(overrides)
    return dynamic_row(**values)
```

Test the complete fixture above as PASS. Then use parameterized/subtest
mutations so every binding below is rejected independently (one field changed
per case):

- owner, positive update count, epochs before/after, and applied status;
- each of the six refresh phase values, their six-component sum, refresh
  total, inherited total, inherited median, and inherited SD sentinel;
- all four inherited insert/signature/encode/encrypt value aliases, all four
  medians, and all four SD sentinels;
- every value, median, and SD member of the five unused inherited
  init/delete/compute/decrypt/flood triplets;
- ciphertext size versus upload size, positive upload size, and exactly one
  uploaded ciphertext;
- context fingerprint and public-key fingerprint separately;
- `jaccard_computed`, `jaccard_expected`, `jaccard_error`,
  `jaccard_rel_error`, and `rel_error_eligible_n`, including one mutation just
  outside each declared six-decimal rounding tolerance;
- `profile_id`, `run_class`, `target_security_bits`, `comparison_eligible`,
  `measurement_kind`, `trials`, `accuracy_trials`, `hash_randomness`,
  `hash_seed`, `hash_root_seed`, every sanitizer numeric constant,
  `sanitizer_model`, `sanitizer_assurance`, `estimator_model`, and every live
  BFV metadata field already consumed by `_validate_models`/`_validate_fhe`.

Include empty and non-finite timing cases where the strict numeric helpers are
responsible for rejection. Test a legacy row with one fabricated refresh-only
cell is rejected. The PASS fixture must not rely on blank inherited phase or
size cells.

- [ ] **Step 2: Run verifier RED**

```bash
set -euo pipefail
set +e
python3 -m unittest \
  tests.scripts.test_verify_benchmark_provenance -v \
  > /tmp/work6-task8-verifier-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'FAILED|ERROR' /tmp/work6-task8-verifier-red.log
```

Expected RED: valid refresh row either fails for unknown columns/contract or passes without rejecting at least one false-evidence mutation.

- [ ] **Step 3: Implement refresh-specific validation**

Add the 17 appended columns to `DYNAMIC_REQUIRED_COLUMNS`. In `validate_family_rows`, after inherited dynamic validation, route to:

```python
def _validate_dynamic_refresh(row, row_number):
    scenario = row["dynamic_scenario"]
    if scenario == "legacy":
        for column in REFRESH_ONLY_COLUMNS:
            require(row[column] == "",
                    f"row {row_number}: legacy row fabricates {column}")
        return
    require(scenario == "refresh",
            f"row {row_number}: invalid dynamic_scenario")
    require(row["profile_id"] == "toy-smoke" and row["run_class"] == "smoke",
            f"row {row_number}: refresh evidence must use toy-smoke")
    require(row["target_security_bits"] == "0" and
            row["comparison_eligible"] == "false" and
            row["measurement_kind"] == "fhe-timing",
            f"row {row_number}: refresh evidence provenance mismatch")
    require(row["trials"] == "1" and row["accuracy_trials"] == "0",
            f"row {row_number}: Work 6 refresh requires one timing trial")
    require(row["refresh_owner_set_id"] == "owner-a" and
            row["refresh_status"] == "applied" and
            row["refresh_epoch_before"] == "0" and
            row["refresh_epoch_after"] == "1",
            f"row {row_number}: refresh transition is not owner-a 0->1 applied")
```

Parse integer/float fields with the existing strict helpers, compute the phase
sum, apply `0.01` tolerance, and validate fingerprints using `HEX64`. Add a
single helper `_require_close(row_number, left_name, right_name, tolerance)`
and call it for `refresh_total_ms`, `total_ms`, `total_ms_median`, the four
phase aliases, and their medians. Require all one-trial SD fields above to be
exactly `-1`; require unused phase values/medians exactly `0`; require
`ct_size_bytes` and `refresh_upload_bytes` to parse as the same positive
integer. Parse the five accuracy cells, require their ranges/eligibility, and
recompute absolute and relative error from the serialized computed/expected
values using the exact `0.000002` and `0.000005` tolerances above. No duplicated
timing or accuracy field is trusted without a binding check.

- [ ] **Step 4: Write the runner RED expectation**

In the smoke expected command list in `tests/scripts/test_run_pre_threshold_profiles.py`, change the inherited review accuracy count to `--accuracy-trials=1` and append exactly:

```text
RUN OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE bench_dynamic --scenario=refresh --refresh_updates=1 --profile=toy-smoke --security=TOY --mode=timing --evidence_point --k=16 --m=16 --set_size=100 --target-jaccard=0.5 --depth=5 --trials=1 --seed=7
```

Update smoke manifest assertions from 2 to 3 cells, expected row counts `[10,1,1]`, terminal lines from 3 to 4, and invocation count from 2 to 3. In the fake executable, select the refresh fixture row when `--scenario=refresh` is present.

Run:

```bash
set -euo pipefail
set +e
python3 -m unittest \
  tests.scripts.test_run_pre_threshold_profiles.PreThresholdRunnerTest.test_sensitivity_feasibility_and_smoke_matrix_is_frozen \
  tests.scripts.test_run_pre_threshold_profiles.PreThresholdRunnerTest.test_fake_smoke_writes_exact_layout_manifest_and_terminal_cells -v \
  > /tmp/work6-task8-runner-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'FAILED|ERROR' /tmp/work6-task8-runner-red.log
```

Expected RED: smoke currently has only two commands/cells and review accuracy count two.

- [ ] **Step 5: Add the exact smoke cell and production-shaped fixture**

In `matrix("smoke", seed)`, set review `--accuracy-trials=1` and append this cell. Do not add refresh cells to primary/sensitivity/feasibility:

```python
Cell("toy-smoke", "bench_dynamic", (
    "--scenario=refresh", "--refresh_updates=1",
    "--profile=toy-smoke", "--security=TOY", "--mode=timing",
    "--evidence_point", "--k=16", "--m=16", "--set_size=100",
    "--target-jaccard=0.5", "--depth=5", "--trials=1",
    f"--seed={seed}",
))
```

Start from the Task 7-aligned `tests/fixtures/runner/dynamic_toy_rows.csv`;
do not append or reorder its header columns again. Keep row 1 as
`dynamic_scenario=legacy` with the existing 16 empty refresh-only cells, add
row 2 using the valid `refresh_row` values from Step 1, and update the fake
harness to emit row 2 only for refresh.

- [ ] **Step 6: Run GREEN and verify the real CSV**

```bash
set -euo pipefail
python3 -m unittest \
  tests.scripts.test_verify_benchmark_provenance \
  tests.scripts.test_run_pre_threshold_profiles -v
./scripts/run_pre_threshold_profiles.sh \
  --suite=smoke --seed=7 --threads=2 \
  --build-dir="$(pwd)/build-work6" --dry-run
python3 scripts/verify_benchmark_provenance.py \
  --schema=dynamic --csv=/tmp/piccard-work6-refresh.csv
```

Expected: Python suites pass; dry run prints exactly three TOY cells and every printed timing/repetition/accuracy count is one; verifier prints JSON with `"verdict": "PASS"`, one row, and schema dynamic.

- [ ] **Step 7: Commit and review gate**

```bash
set -euo pipefail
git add scripts/verify_benchmark_provenance.py \
  tests/scripts/test_verify_benchmark_provenance.py \
  scripts/run_pre_threshold_profiles.sh \
  tests/scripts/test_run_pre_threshold_profiles.py \
  tests/fixtures/runner/dynamic_toy_rows.csv
git commit -m "feat(evidence): gate one-trial refresh provenance"
```

Completion gate: reviewer mutates each false-evidence field and observes rejection, checks legacy rows cannot populate refresh cells, confirms the smoke lane is TOY/one trial, and confirms approved full-profile matrices were not executed or re-approved.

### Task 9: D3 — Enforce threshold/delta exclusion and complete Work 6 verification

**Files:**
- Create: `scripts/check_work6_scope.py`
- Create: `scripts/work6_allowed_paths.txt`
- Create: `tests/scripts/test_check_work6_scope.py`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces CLI:

```text
python3 scripts/check_work6_scope.py --base=COMMIT --head=COMMIT --allowed-paths=FILE
```

- Exit 0 prints `check_work6_scope: PASS`; exit 2 prints `check_work6_scope: FAIL: <reason>`.
- Allowed-path file contains every File Map path, one repository-relative path per line, sorted bytewise. Blank lines, duplicates, absolute paths, `..`, and unsorted entries are fatal.
- Checker obtains `git diff --name-only -z --no-renames
  --diff-filter=ACMRTD base head`, decodes and splits the NUL-delimited paths,
  and rejects any added, changed, or deleted path outside the whitelist.
  Disabling rename detection intentionally exposes a rename as deletion of
  its source plus addition of its destination, so both paths are checked. It
  also
  rejects changed path names matching case-insensitive
  `threshold|fpfn|false.?positive|false.?negative|decision.?boundary` except
  exactly `scripts/run_pre_threshold_profiles.sh` and
  `tests/scripts/test_run_pre_threshold_profiles.py`. Those two exception
  strings are assembled from nonmatching fragments in checker source.
- It scans both `+` and `-` lines, excluding patch headers, across every
  changed `CMakeLists.txt` and every changed path beneath `include/`, `src/`,
  `benchmarks/`, `scripts/`, and `tests/`. Both threshold/FPFN expressions and
  `ciphertext.*delta|delta.*ciphertext|applydelta|incremental.*ciphertext` are
  fatal in code, test, fixture, or runner diffs. Git errors, missing deleted
  blobs, strict UTF-8 decode errors, and regex errors are fatal.
- `scripts/work6_allowed_paths.txt` is the only exact path excluded from that
  generic added/deleted source-line scan because its data necessarily names
  the two exceptions above. It is not exempt from checking: parse the
  candidate blob as strict whitelist data, apply the forbidden path and
  ciphertext-update marker detectors to every entry, and permit only the two
  exact legacy runner exceptions above. A similar but nonexact path is fatal.
- `include/fhe/bfv_context.h` and `src/fhe/bfv_context.cpp` receive an
  additional structural freeze. For the header, remove exactly one permitted
  `<memory>` include, one `PublicCiphertextCodec` forward declaration, and one
  exact `ExportPublicCiphertextCodec()` declaration from the candidate; the
  remaining bytes must equal the base blob. For the source, a brace/comment/
  string-aware scanner removes exactly the new codec include lines and the
  complete top-level definitions named `AppendBE32`, `AppendBE64`,
  `Sha256Hex`, `ContextFingerprintHex`, `PublicKeyFingerprintHex`, and
  `BFVContext::ExportPublicCiphertextCodec`; the remaining bytes must equal
  the base blob. Each allowed insertion occurs exactly once and only at
  include, namespace, class-public, or top-level definition scope. An
  insertion inside or change to any preexisting function body is fatal.

- [ ] **Step 1: Write the checker tests first**

Create `tests/scripts/test_check_work6_scope.py`. Each test creates a temporary
Git repository, commits a base, writes a sorted whitelist, commits a candidate,
and invokes the production checker. The checker scans its own newly added
source and test diffs, so neither file may spell a complete forbidden marker
in a source line—not in identifiers, comments, docstrings, diagnostics, regex
literals, or fixtures. Build detector expressions and malicious fixture text
at runtime from nonmatching fragments, for example:

```python
STATE_MARKER = "thresh" + "old"
RATE_MARKER = "fp" + "fn"
UPDATE_MARKER = "ApplyCipher" + "textDe" + "lta"
```

Use the same split-fragment rule in production regex construction (for
example, concatenate `"cipher" + "text"` and `"de" + "lta"` pieces before
calling `re.compile`). No complete marker may occur in the candidate patch as
plain text; it exists only in memory after Python evaluates the fragments.
Use neutral test names and comments:

```python
def test_allowed_change_passes(self):
    # base has CMakeLists.txt; candidate adds include/analysis/deletion_survival.h;
    # whitelist contains that path -> exit 0 and PASS

def test_path_outside_whitelist_fails(self):
    # candidate adds notes.txt; empty whitelist -> exit 2 naming notes.txt

def test_renames_check_both_paths(self):
    # outside-to-allowed and allowed-to-outside both fail; allowed-to-allowed
    # passes when both source and destination are exact whitelist entries

def test_forbidden_path_or_semantic_line_fails(self):
    # subtests assemble disallowed path and build-rule text from fragments;
    # exercise both added and deleted lines in each scanned path family

def test_forbidden_update_api_fails(self):
    # subtests assemble the disallowed API text from fragments; exercise both
    # added and deleted lines in allowed production and test paths

def test_nul_source_is_forced_through_text_scan(self):
    # an allowed source path contains a NUL plus an assembled disallowed
    # marker; both addition and deletion candidates must fail

def test_bfv_preexisting_body_is_frozen(self):
    # change a token-free existing condition, insert one statement inside an
    # existing body, and alter an existing declaration -> all exit 2

def test_exact_bfv_codec_insertions_pass(self):
    # exact include/forward/export declaration and the six declared standalone
    # top-level definitions pass after structural subtraction

def test_unsorted_or_traversing_whitelist_fails(self):
    # subtests for b before a and ../escape

def test_path_data_uses_narrow_entry_validation(self):
    # the real sorted path-data file and its two exact legacy exceptions pass;
    # an assembled lookalike path or assembled disallowed-update path fails

def test_checker_and_tests_pass_their_own_candidate_diff(self):
    # candidate adds byte-for-byte copies of the production checker, this test
    # module, and the real sorted path-data file; invoking the copied checker
    # on base..candidate must return PASS
```

The self-application test is mandatory and must run the normal semantic scan
over both copied source files and the strict entry parser over the copied real
path-data file. Do not exempt either source path, skip their added lines, or
add a generic checker-implementation bypass. The only generic-scan exclusion
is the exact path-data file, which must pass its dedicated entry validation;
the exact BFV structural subtraction and the two narrowly listed legacy runner
path exceptions are the only other special cases.

- [ ] **Step 2: Run RED**

```bash
set -euo pipefail
set +e
python3 -m unittest tests.scripts.test_check_work6_scope -v \
  > /tmp/work6-task9-red.log 2>&1
RED_STATUS=$?
set -e
test "$RED_STATUS" -ne 0
rg -q 'check_work6_scope|No such file|cannot open' /tmp/work6-task9-red.log
```

Expected RED: checker script is missing, so every expected-PASS case fails to launch.

- [ ] **Step 3: Implement fail-closed Git and regex handling**

Create `scripts/work6_allowed_paths.txt` with exactly:

```text
CMakeLists.txt
benchmarks/bench_deletion_survival.cpp
benchmarks/bench_dynamic.cpp
benchmarks/benchmark_estimator_provenance.cpp
benchmarks/benchmark_estimator_provenance.h
benchmarks/dynamic_refresh_benchmark.cpp
benchmarks/dynamic_refresh_benchmark.h
docs/superpowers/plans/2026-08-06-work6-terra-risk-first-poc.md
docs/superpowers/specs/2026-08-06-work6-risk-first-poc-design.md
include/analysis/deletion_monte_carlo.h
include/analysis/deletion_survival.h
include/core/bottom_structure.h
include/fhe/bfv_context.h
include/fhe/public_ciphertext_codec.h
include/protocol/dynamic_ciphertext_store.h
scripts/check_work6_scope.py
scripts/run_pre_threshold_profiles.sh
scripts/verify_benchmark_provenance.py
scripts/work6_allowed_paths.txt
src/analysis/deletion_monte_carlo.cpp
src/analysis/deletion_survival.cpp
src/core/bottom_structure.cpp
src/fhe/bfv_context.cpp
src/fhe/public_ciphertext_codec.cpp
src/protocol/dynamic_ciphertext_store.cpp
tests/fixtures/runner/dynamic_toy_rows.csv
tests/integration/test_dynamic_refresh_e2e.cpp
tests/scripts/test_bench_deletion_survival.py
tests/scripts/test_bench_dynamic_refresh_cli.py
tests/scripts/test_check_work6_scope.py
tests/scripts/test_run_pre_threshold_profiles.py
tests/scripts/test_verify_benchmark_provenance.py
tests/unit/test_bottom_structure.cpp
tests/unit/test_deletion_monte_carlo.cpp
tests/unit/test_deletion_survival.cpp
tests/unit/test_dynamic_ciphertext_store.cpp
tests/unit/test_dynamic_engine.cpp
tests/unit/test_dynamic_refresh_benchmark.cpp
tests/unit/test_estimator_provenance_serializers.cpp
tests/unit/test_public_ciphertext_codec.cpp
```

Use `subprocess.run(command, check=False, capture_output=True)` and require
return code zero for `git rev-parse`, NUL-delimited path diff, zero-context
patch diff, and every `git show <commit>:<path>` blob read. Resolve both
commits with `git rev-parse revision^{commit}` and require the output to be a
full lowercase 40-hex SHA. Run both the path diff and zero-context patch diff
with `--no-renames`, and force the patch command to text with `--text`
(`git diff --text --unified=0 --no-renames ...`). Split the path diff only on
NUL bytes and reject an empty or malformed path record. An entirely empty
path-diff output means no changed paths; otherwise require a terminal NUL,
remove only that delimiter, split the remaining bytes on NUL, and reject any
empty interior record. Parse patch lines only when they begin `+` or `-`,
excluding patch header lines. Decode every Git output as strict UTF-8; a
decoder or regex error is fatal. Implement the BFV structural subtraction as dedicated pure
functions and exercise them with the production checker tests above; do not
approximate it with a token allowlist. Construct every forbidden detector from
nonmatching string fragments before compiling it, and keep all identifiers,
comments, docstrings, diagnostics, and fixtures neutral so the checker and its
test file pass the mandatory self-application regression without a wholesale
exemption. Before generic semantic scanning, recognize only the exact
repository-relative `scripts/work6_allowed_paths.txt`; read its candidate blob
through the same strict UTF-8 Git path, re-run sorted/unique/relative-path
validation, and apply both forbidden marker families to every entry. Build the
two permitted legacy runner entries from fragments and compare by exact string
equality. Skip generic patch-line scanning for this one data file only after
that validation succeeds; do not use a basename, suffix, directory, or glob
exemption.

The NUL-bearing regression must write bytes, not a textual escape sequence,
and must prove `--text` exposes the assembled marker to the normal regex scan.
The generic scanner may not accept Git's `Binary files ... differ` summary as
evidence that content was checked.

The production entry point is:

```python
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--allowed-paths", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        check(args.base, args.head, args.allowed_paths)
    except ScopeError as error:
        print(f"check_work6_scope: FAIL: {error}", file=sys.stderr)
        return 2
    print("check_work6_scope: PASS")
    return 0
```

Register `CheckWork6Scope` in CTest beside the other pure-Python tests.

- [ ] **Step 4: Run the focused checker GREEN gate**

```bash
set -euo pipefail
python3 -m unittest tests.scripts.test_check_work6_scope -v
```

Expected: every hermetic path, semantic, deletion, delta, and BFV structural
fixture passes. Do not generate final binaries or artifacts from the dirty,
pre-commit tree.

- [ ] **Step 5: Commit Task 9 and establish the clean final HEAD**

```bash
set -euo pipefail
git add scripts/check_work6_scope.py scripts/work6_allowed_paths.txt \
  tests/scripts/test_check_work6_scope.py CMakeLists.txt
git commit -m "test(evidence): exclude threshold and delta work from Work 6"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
git ls-files --error-unmatch \
  docs/superpowers/specs/2026-08-06-work6-risk-first-poc-design.md \
  docs/superpowers/plans/2026-08-06-work6-terra-risk-first-poc.md
FINAL_HEAD="$(git rev-parse HEAD)"
test "$(git rev-parse "$FINAL_HEAD^{commit}")" = "$FINAL_HEAD"
printf '%s\n' "$FINAL_HEAD" > /tmp/piccard-work6-final-head.txt
test "$(wc -l < /tmp/piccard-work6-final-head.txt)" -eq 1
```

Expected: Task 9 is committed, the tree is clean, design and plan are tracked,
and `/tmp/piccard-work6-final-head.txt` contains exactly the full candidate
commit. This external record bridges later steps even when each code block is
run in a fresh shell.

- [ ] **Step 6: Build and verify fresh final artifacts from `FINAL_HEAD`**

```bash
set -euo pipefail
FINAL_HEAD="$(git rev-parse HEAD)"
RECORDED_HEAD="$(sed -n '1p' /tmp/piccard-work6-final-head.txt)"
test "$FINAL_HEAD" = "$RECORDED_HEAD"
test "$(git rev-parse "$FINAL_HEAD^{commit}")" = "$FINAL_HEAD"
FINAL_BUILD="$(mktemp -d)"
FINAL_ARTIFACTS="$(mktemp -d)"
printf '%s\n' "$FINAL_ARTIFACTS" \
  > /tmp/piccard-work6-final-artifacts.txt
test "$(wc -l < /tmp/piccard-work6-final-artifacts.txt)" -eq 1
printf 'FINAL_HEAD=%s\nFINAL_ARTIFACTS=%s\n' \
  "$FINAL_HEAD" "$FINAL_ARTIFACTS"
cmake -S . -B "$FINAL_BUILD" -DCMAKE_BUILD_TYPE=Release
cmake --build "$FINAL_BUILD" -j4 --target \
  test_bottom_structure test_dynamic_engine test_bfv_context \
  test_estimator_provenance_serializers \
  test_public_ciphertext_codec test_dynamic_ciphertext_store \
  test_dynamic_refresh_e2e test_deletion_survival \
  test_deletion_monte_carlo test_dynamic_refresh_benchmark \
  bench_dynamic bench_deletion_survival
ctest --test-dir "$FINAL_BUILD" --output-on-failure -R \
  'BottomStructure|DynamicEngine|BFVContext|PublicCiphertextCodec|DynamicCiphertextStore|DynamicRefreshE2E|DeletionSurvival|DeletionMonteCarlo|DeletionSurvivalCli|DynamicRefreshBenchmark|EstimatorProvenanceSerializers|VerifyBenchmarkProvenance|PreThresholdProfileRunner|CheckWork6Scope'

"$FINAL_BUILD/bench_dynamic" \
  --scenario=refresh --refresh_updates=1 \
  --profile=toy-smoke --security=TOY --mode=timing --evidence_point \
  --k=16 --m=16 --set_size=100 --target-jaccard=0.5 \
  --depth=5 --trials=1 --seed=7 \
  > "$FINAL_ARTIFACTS/refresh.csv"
python3 scripts/verify_benchmark_provenance.py \
  --schema=dynamic --csv="$FINAL_ARTIFACTS/refresh.csv"

"$FINAL_BUILD/bench_deletion_survival" \
  --n=1024 --d=5 --k=128 --required_survival=0.99 \
  --r_values=156,157,357 --trials=1 --seed=20260729 \
  > "$FINAL_ARTIFACTS/deletion.csv"
python3 - "$FINAL_ARTIFACTS/deletion.csv" <<'PY'
import csv
import sys
from pathlib import Path

def require(condition, message):
    if not condition:
        raise SystemExit(f"deletion artifact check failed: {message}")

with Path(sys.argv[1]).open(newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream, strict=True))
require(len(rows) == 3, "expected exactly three rows")
require(all(row["model"] == "ideal-independent-random-ranking-v1"
            for row in rows), "model label mismatch")
require(all(row["trials"] == "1" for row in rows), "trial count mismatch")
require(rows[0]["maximum_safe_deletions"] == "156", "safe budget mismatch")
require(rows[0]["exact_expected_first_failure"].startswith("357.7452319"),
        "first-failure golden mismatch")
require(rows[0]["exact_expected_safe_deletions"].startswith("356.7452319"),
        "safe-deletion golden mismatch")
PY
python3 scripts/check_work6_scope.py \
  --base=b09d008 --head="$FINAL_HEAD" \
  --allowed-paths=scripts/work6_allowed_paths.txt
test "$(git rev-parse HEAD)" = "$FINAL_HEAD"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Expected: the fresh Release build and selected tests pass; refresh verifier and
scope checker print PASS; deletion CSV has three exact/union/seeded-MC rows,
one trial each, the exact budget/expectation goldens, and the ideal-model
label; HEAD and tree remain clean and unchanged throughout final verification.
The command prints both literal handoff values, and the one-line artifact-path
record names the directory containing the two reviewed CSV files.

- [ ] **Step 7: Final independent review gate**

Rehydrate and validate the recorded literal values in the new shell before
constructing the handoff:

```bash
set -euo pipefail
FINAL_HEAD="$(sed -n '1p' /tmp/piccard-work6-final-head.txt)"
FINAL_ARTIFACTS="$(sed -n '1p' /tmp/piccard-work6-final-artifacts.txt)"
test "$(wc -l < /tmp/piccard-work6-final-head.txt)" -eq 1
test "$(wc -l < /tmp/piccard-work6-final-artifacts.txt)" -eq 1
test "$(git rev-parse HEAD)" = "$FINAL_HEAD"
test "$(git rev-parse "$FINAL_HEAD^{commit}")" = "$FINAL_HEAD"
test -d "$FINAL_ARTIFACTS"
test -f "$FINAL_ARTIFACTS/refresh.csv"
test -f "$FINAL_ARTIFACTS/deletion.csv"
printf 'FINAL_HEAD=%s\nFINAL_ARTIFACTS=%s\n' \
  "$FINAL_HEAD" "$FINAL_ARTIFACTS"
git diff --stat b09d008.."$FINAL_HEAD"
```

Copy the two printed literal values into the review record. Give the reviewer
the diff stat above, `git diff b09d008..<literal FINAL_HEAD>`, this plan,
focused RED/GREEN logs, `<literal FINAL_ARTIFACTS>/refresh.csv`,
`<literal FINAL_ARTIFACTS>/deletion.csv`, verifier output, and scope-checker
output. Approval requires: no missing traceability row below, no benchmark
count above one in Work 6 executions, no threshold/delta behavior, and no
false provenance field.

Completion gate: reviewer returns APPROVE with no blocking state-machine, formula, evidence-scope, or provenance finding.

## Work 6 Claim Traceability

| Work 6 claim | Task | Primary test/evidence |
|---|---:|---|
| Bottom exhaustion is explicit, sticky, and recoverable only by full nonempty initialization | 1 | `RebuildStateIsStickyUntilFullInitialize`; `ExhaustedStructureRejectsEncryptionUntilReinitialized` |
| Refresh is one owner's full signature re-encoding and fresh full encryption | 4, 7 | `DynamicRefreshE2E`; `MeasuresExactlyOneOwnerZeroToOne`; refresh CSV phase fields |
| Cloud replacement is atomic full-envelope `0->1` compare-and-swap | 3 | `AppliesOneOwnerAndDistinguishesReplayFromFuture`; unchanged peer and failed-state assertions |
| Stale and future source epochs are distinct | 3, 4 | `StaleEpoch` replay versus `FutureEpoch`; E2E replay remains new state |
| Owner/set, public CRS, encoding, realized BFV context, public key, key tag, and payload are bound | 2, 3 | codec wrong-key/malformed tests; store owner/CRS/crypto tests |
| Deletion survival uses the exact analytic formula and correct safe/failure convention | 5 | small `(5,2,1)` fixtures, 156/157 goldens, `E[T]` and `E[T]-1` assertions |
| Monte Carlo is seeded, portable, deterministic, and explicitly ideal-model | 6 | six `UniformBelow` goldens; one-trial `T=3` histogram; CLI model column |
| Refresh evidence reports local update, signature/re-encoding, encryption, serialization, replacement, and upload bytes | 7, 8 | `DynamicRefreshBenchmark`; valid refresh verifier fixture; real TOY refresh CSV |
| Refresh timing never sums two owners' encryption and uploads one ciphertext | 7 | initialization outside timers; `refresh_ciphertexts_uploaded=1`; reviewer phase trace |
| Work 6 evidence is TOY and exactly one trial; full performance is deferred | 6–9 | CLI guards, runner argv golden, verifier `trials=1`, final commands |
| No ciphertext delta API is introduced | 3, 9 | store's exact public interface; scope check `ciphertext.*delta` rejection |
| No threshold FP/FN behavior or threshold-owned artifact changes | 8, 9 | smoke dry-run lacks threshold producer; path/semantic scope checker on `b09d008..HEAD` |
| Works 3–5 approval/evidence state is inherited and not reopened | Global, 9 | no approval-verifier command in any task; final review starts from `b09d008` diff only |

## Plan Self-Review Checklist

- [x] Spec coverage: every bounded-dynamic refresh and deletion-survival claim in the design and every binding decision in this Work 6 request maps to a task/test in the traceability table.
- [x] Prohibited-marker scan: the plan contains no no-content marker named by the writing-plans skill.
- [x] Type consistency: `PublicCiphertextCodec`, `VersionedCiphertext`, `ReplaceOutcome`, `CloudCiphertextPair`, `DeletionSurvivalConfig`, `DeletionMonteCarloResult`, `DynamicResult` refresh fields, and all method names/signatures match across consuming tasks.
- [x] Toy/trial rule: every executable Work 6 benchmark command uses TOY and `trials=1`; the refresh timing row uses `accuracy_trials=0` because no accuracy loop executes; no full profile suite is executed.
- [x] Risk order: exhaustion precedes codec/store/E2E, which precede exact/MC deletion, which precede timing/provenance/scope gates.
- [x] Terra executability: each task has exact owned paths, interfaces, representative compilable code, RED reason, GREEN commands, expected result, commit command, dependency, and completion review gate.

Plan complete and saved to `docs/superpowers/plans/2026-08-06-work6-terra-risk-first-poc.md`. Execute with `superpowers:subagent-driven-development` task-by-task; do not batch Tasks 1–9 or bypass their review gates.
