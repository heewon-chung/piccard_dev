# Work 7 Terra Pre-threshold Integration Implementation Plan

> **For the implementing agent:** use `superpowers:test-driven-development`
> for every production change and `superpowers:subagent-driven-development`
> to execute the tasks in order. Do not start a later task until the current
> task has a clean task review.

**Goal:** Implement a fail-closed, reproducible Work 7 PoC integration gate
that maps Works 1–6 to the approved pre-threshold intent, executes only
one-measured-trial toy probes, preserves the Paper and threshold worktrees, and
can terminalize only after independent Claude Fable high and GPT-5.6-sol high
approval.

**Architecture:** Add a Python standard-library integration layer. A shared
module snapshots guarded Git worktrees and creates chained immutable seals. A
tracked lifecycle contract defines the seven claims. A four-mode verifier emits
session-local state reports without editing the contract. The integration
runner performs a fresh Release build, a frozen focused test registry, and the
existing toy/synthetic probes. A response generator creates an unapplied Paper
candidate. Review-packet and verdict tools bind both model reviews to one exact
commit and packet digest.

**Technology:** Python 3 standard library, Git CLI, CMake/CTest, existing C++
benchmarks and shell/Python runners, `unittest`, SHA-256 canonical JSON.

**Approved design:**
`docs/superpowers/specs/2026-08-06-work7-pre-threshold-poc-integration-design.md`
and its Phase 0–5 companion documents at design commit `3a79ba4`.

## Global constraints

These constraints bind every task verbatim:

- Implementation model: `gpt-5.6-terra`.
- Task and work-level review model: `gpt-5.6-sol` high.
- Final reviewers: Claude Fable high and `gpt-5.6-sol` high, launched
  independently and concurrently.
- Actual DBLP-ACM/Enron inputs and repeated paper-performance campaigns are not
  run. Their status is always `PERFORMANCE_PENDING`.
- Every measured trial/repetition/accuracy trial is exactly `1`.
- One existing, discarded, explicitly labelled warmup per timing cell is
  allowed. It is not a measured repetition. No retry loop is allowed.
- The Paper and threshold worktrees are read-only. Preserve existing dirty
  Paper bytes, index, modes, symlinks, untracked files, and submodule state.
- Build/session output roots resolve outside all three guarded worktrees and
  may not alias one through a symlink.
- Never apply the generated `ResponseStrategy.md` patch.
- Never reconstruct historical model approvals for Works 1–6.
- Never authorize, edit, merge, or rebase threshold FP/FN work.
- The strongest possible terminal status is
  `POC_APPROVED_PERFORMANCE_PENDING`.
- Generated session evidence is append-only. Each phase seal hashes the prior
  seal; a sealed artifact is never rewritten.

## Unit and phase map

| Task | Design phases | Owned responsibility |
|---|---|---|
| 1 | Phase 0 foundation | canonical Git snapshot, path guard, tree seals |
| 2 | Phase 1 | immutable claim lifecycle contract, four-mode verifier |
| 3 | Phase 2 | fresh Release build, exact test registry, one-run toy evidence |
| 4 | Phase 3 | read-only response candidate and claim-7 closure |
| 5 | Phases 4–5 | review packets, exact verdict validation, terminal closure |
| 6 | all | authoritative run, work review, simultaneous final review |

---

## Task 1: Phase 0 state guard and chained-seal foundation

**Files**

- Create: `scripts/work7_evidence.py`
- Create: `scripts/work7_state_guard.py`
- Create: `tests/scripts/test_work7_state_guard.py`
- Modify: `CMakeLists.txt`

### Interface to implement

`scripts/work7_evidence.py` exposes:

```python
canonical_json_bytes(value: object) -> bytes
sha256_file(path: pathlib.Path) -> str
snapshot_git_worktree(root: pathlib.Path) -> dict
assert_output_roots_outside(guarded_roots: list[pathlib.Path],
                            output_roots: list[pathlib.Path]) -> None
create_tree_seal(artifact_root: pathlib.Path, seal_path: pathlib.Path,
                 previous_seal_sha256: str | None, kind: str) -> dict
verify_tree_seal(seal_path: pathlib.Path,
                 expected_previous_sha256: str | None = None) -> dict
```

Canonical JSON is UTF-8, `sort_keys=True`, compact separators, `ensure_ascii`
enabled, and ends in exactly one newline. A tree seal lists every regular file
under `artifact_root` by POSIX relative path, byte length, mode, and SHA-256.
Symlinks or special files in evidence roots fail closed. The seal itself lives
outside `artifact_root`, so it cannot hash itself.

The Git snapshot contains resolved root, branch/detached marker, full HEAD,
the parsed index entry list from `git ls-files -s -z` (path, mode, object ID,
and stage for every entry), the digest of its framed raw bytes, recursively
framed tracked and untracked entries, modes, file bytes or symlink targets,
missing tracked entries, and `git submodule status --recursive`. Preserve both
the structured index entries and their digest in canonical state JSON. Frame
every variable field as an 8-byte big-endian length followed by bytes before
hashing. Do not rely on porcelain status text as the content fingerprint.

`work7_state_guard.py` CLI:

```text
--source-root ABS --paper-root ABS --threshold-root ABS
--build-root ABS --session-root ABS
--expected-source-branch tkde-major/pre-threshold-poc
--expected-source-commit FULL_SHA --output ABS/phase0/state.json
```

It requires a clean source, records dirty external states without rejecting
them, creates no output until all checks pass, writes canonical JSON atomically,
and exits `0` with `work7_state_guard: PASS`; a contract failure exits `2` with
one `work7_state_guard: FAIL: ...` line on stderr.

### TDD steps

1. RED — write tests using temporary real Git repositories for:
   clean source pass, dirty Paper pass, changed bytes with unchanged porcelain
   shape changing the digest, index-only change, untracked bytes, executable
   mode, symlink target, submodule status, dirty source rejection, path
   containment, symlink alias, and existing output collision.

   Run:

   ```bash
   python3 -m unittest -v tests.scripts.test_work7_state_guard
   ```

   Success for RED: tests import/call missing Work 7 code and fail for that
   reason. Failure for RED: tests pass, fail from fixture syntax, or inspect
   source text instead of behavior.

2. GREEN — implement the minimum functions and CLI. Use `subprocess.run` with
   argument lists, no shell, `check=False`, captured bytes, and explicit
   return-code validation. Use `lstat`, never follow a snapshot entry symlink.

3. GREEN verification — rerun the unit command. Register it in CMake as
   `Work7StateGuard`, then configure a temporary tests-only build and verify:

   ```bash
   cmake -S . -B /tmp/piccard-work7-task1-build \
     -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=OFF
   ctest --test-dir /tmp/piccard-work7-task1-build \
     --output-on-failure -R '^Work7StateGuard$'
   ```

4. REFACTOR — keep snapshot collection, canonicalization, and CLI validation
   separate. Re-run both commands.

### Phase 0 success conditions

- All behavior tests pass and CTest discovers `Work7StateGuard`.
- A byte change in an already-dirty file changes the snapshot digest.
- Recomputed unchanged snapshots and seals are byte-identical.
- Guarded-root containment/aliasing and seal overwrite attempts fail closed.

### Phase 0 failure conditions

- Status text is used as the only external-state fingerprint.
- Any guard operation writes into Paper or threshold.
- A symlink is followed while hashing or an existing seal is overwritten.
- Output paths within any guarded worktree are accepted.

### Commit

```bash
git add CMakeLists.txt scripts/work7_evidence.py scripts/work7_state_guard.py \
  tests/scripts/test_work7_state_guard.py
git commit -m "feat(work7): add byte-level state and seal guard"
```

---

## Task 2: Phase 1 immutable lifecycle contract and verifier

**Files**

- Create: `scripts/work7_claims.json`
- Create: `scripts/verify_work7_claims.py`
- Create: `tests/scripts/test_work7_claim_contract.py`
- Create fixtures under: `tests/fixtures/work7/claims/`
- Modify: `CMakeLists.txt`

### Contract shape

The tracked JSON contains no current session state. It has schema
`piccard-work7-claim-lifecycle-v1`, exactly seven IDs
`W7-G1-ESTIMATOR`, `W7-G2-SANITIZER`, `W7-G3-CALIBRATION`,
`W7-G4-COMPARISON`, `W7-G5-REAL-DATA`, `W7-G6-DYNAMIC`, and
`W7-G7-INTEGRATION`. Each row contains original intent, nonempty source paths,
required CTest names, evidence keys, allowed state transitions,
`performance_state=PERFORMANCE_PENDING`, deferred rationale, and prohibited
overclaim. Top-level allowed gates are
`threshold_gate_state=DEFERRED_EXPECTED` and
`work_gate_state=PENDING -> POC_APPROVED_PERFORMANCE_PENDING`.

Populate source/test references by inspecting current files. Use only test
names in the frozen registry from the approved design. Claim 7 source paths
point to Work 7 scripts and tests added by this plan.

### Verifier CLI

```text
verify_work7_claims.py --mode static|evidence-bound|claim7|terminal
  --contract ABS --source-root ABS --source-commit FULL_SHA
  --ctest-inventory ABS
  [--runtime-seal ABS]
  [--phase2-closure-seal ABS --phase3-candidate-seal ABS]
  [--phase3-closure-seal ABS --work-review-seal ABS
   --review-packet ABS --claude-review ABS --sol-review ABS
   --phase0-seal ABS --paper-root ABS --threshold-root ABS]
  --output ABS
```

Mode requirements:

- `static`: validate schema, exact IDs, paths, CTest inventory, and allowed
  transitions; emit claims 1–7 implemented, toy pending, performance pending,
  threshold deferred, work gate pending.
- `evidence-bound`: verify the runtime-artifact seal and its
  `evidence-index.json`; claims 1–6 must map to sealed artifacts. Claim 7 stays
  pending.
- `claim7`: verify Phase 2 closure and Phase 3 candidate-artifact seal; emit
  claim 7 toy-verified but keep both gates pending/deferred.
- `terminal`: verify Phase 3 closure, work-review seal, final packet digest,
  and two exact raw review records. Before writing its report, recompute Paper
  and threshold byte-level snapshots and require equality to Phase 0. Only this
  mode emits `POC_APPROVED_PERFORMANCE_PENDING`.

All outputs are canonical session-local reports. Never edit the contract.
Reject absolute/missing/escaping contract paths, unknown fields/states,
duplicate IDs, foreign or tampered seals, missing evidence, and toy-to-paper
overclaims. Exit `0` with `verify_work7_claims: PASS (<mode>)`; contract failure
exits `2` with one stable error line.

The terminal-review parser in this task accepts only the final-review schema
below. It requires exactly these seven unique fields, with no conditional
verdict token:

```text
VERDICT: APPROVED
PROVIDER: anthropic|openai
MODEL: claude-fable|gpt-5.6-sol
EFFORT: high
SOURCE_COMMIT: <40 lowercase hex>
PACKET_SHA256: <64 lowercase hex>
STATUS: POC_APPROVED_PERFORMANCE_PENDING
```

Additional prose is allowed after the seven header lines, but no second field
line may appear.

For `--mode terminal`, each raw final-review record must additionally contain
all six unique substantive confirmation lines below. Header-only approval must
fail before any terminal report/status is written:

```text
CHECK G1_G7_INTENT: CONFIRMED
CHECK EVIDENCE_FRESHNESS: CONFIRMED
CHECK PERFORMANCE_PENDING: CONFIRMED
CHECK THRESHOLD_DEFERRED: CONFIRMED
CHECK EXTERNAL_IMMUTABILITY: CONFIRMED
CHECK TERMINAL_STATUS_MAXIMAL: CONFIRMED
```

### TDD steps

1. RED — add table-driven fixtures covering one valid snapshot per mode and
   one mutation per required rejection: missing/duplicate ID, wrong-field
   state, missing/escaping source, missing CTest, preflight evidence,
   foreign/tampered seal, missing claim evidence, premature claim 7, changed
   tracked contract, mismatched commit/packet, conditional verdict, wrong
   provider/model, header-only terminal approval, each missing terminal
   confirmation, and threshold authorization.

   ```bash
   python3 -m unittest -v tests.scripts.test_work7_claim_contract
   ```

2. GREEN — implement strict parsing and mode-specific derived reports. Reuse
   seal verification from Task 1. Do not add a general JSON-schema dependency.

3. GREEN verification — register CTest `Work7ClaimContract`, reconfigure the
   reused build after the `CMakeLists.txt` change, prove membership with
   `ctest -N`, and only then run the entry:

   ```bash
   cmake -S . -B /tmp/piccard-work7-task1-build \
     -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=OFF
   ctest --test-dir /tmp/piccard-work7-task1-build -N | \
     rg 'Work7ClaimContract'
   ctest --test-dir /tmp/piccard-work7-task1-build \
     --output-on-failure -R '^Work7ClaimContract$'
   ```

   Do not run production `--mode static` against `scripts/work7_claims.json`
   in Task 2: its claim-7 references intentionally name Work 7 scripts and
   CTest entries created by Tasks 3–4. The fixture suite proves verifier/schema
   behavior now. The first production static validation is Task 3 execution
   step 5 after Task 4 and all four frozen Work 7 CTest names exist.

4. REFACTOR — deduplicate field parsing only after all tests pass.

### Phase 1 success conditions

- Fixture lifecycle-contract bytes remain unchanged across all four verifier
  modes; the production contract receives its first static validation only
  after Tasks 3–4 are complete.
- Every mode emits only its allowed state combination.
- Every referenced path/test/evidence item is validated fail-closed.
- Terminal mode cannot pass with one review, different packet/commit, or a
  non-exact `APPROVED` verdict.

### Phase 1 failure conditions

- Session progress is written into tracked JSON.
- Prose alone satisfies an evidence reference.
- A mode accepts another mode's required state transition.
- Historical Work 1–6 approval files are fabricated.

### Commit

```bash
git add CMakeLists.txt scripts/work7_claims.json \
  scripts/verify_work7_claims.py tests/scripts/test_work7_claim_contract.py \
  tests/fixtures/work7/claims
git commit -m "feat(work7): add immutable claim lifecycle gate"
```

---

## Task 3: Phase 2 fresh-build toy integration runner

**Files**

- Create: `scripts/run_work7_integration.py`
- Create: `tests/scripts/test_work7_integration_runner.py`
- Create fixtures under: `tests/fixtures/work7/runner/`
- Modify: `CMakeLists.txt`

### Runner CLI

```text
run_work7_integration.py
  --source-root ABS --paper-root ABS --threshold-root ABS
  --build-parent ABS --session-parent ABS
  --expected-source-branch tkde-major/pre-threshold-poc
```

Derive the clean source commit and reserve, without overwrite,
`<build-parent>/build-<sha>` and `<session-parent>/session-<sha>`.

Execution is fixed:

1. run Phase 0 guard; write and seal `phase0/artifacts/state.json`;
2. configure the empty build directory with
   `-DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=ON`;
3. require configure evidence for OpenFHE, GMP, GTest, and Python 3;
4. build once with `cmake --build <build> --parallel 2`;
5. save `ctest -N` inventory and run `static` claim verification;
6. require every frozen CTest name from the approved design, then run the
   exact anchored regex once, no `--repeat`, saving the full log;
7. run comparison/refresh:

   ```text
   scripts/run_pre_threshold_profiles.sh --suite=smoke --seed=7 --threads=2
     --build-dir=<build> --results-root=<session>/phase2/runtime/pre-threshold
   ```

8. run synthetic real-data:

   ```text
   scripts/run_real_datasets.sh --quick --seed=7 --threads=2
     --build-dir=<build> --results-root=<session>/phase2/runtime/real-datasets
   ```

9. run deletion evidence once:

   ```text
   <build>/bench_deletion_survival --n=64 --d=3 --k=8
     --required_survival=0.99 --r_values=1,4,8 --trials=1 --seed=7
   ```

10. create `evidence-index.json` mapping claims 1–6 to the CTest/probe
    artifacts, verify exact argv and schemas, and create the runtime-artifact
    seal chained to Phase 0;
11. run `evidence-bound` against that seal and create a Phase 2 closure seal
    containing its report and chaining the runtime seal; and
12. recompute Paper and threshold snapshots and require Phase 0 equality.

The CTest registry is exactly the approved design's 24 existing tests plus
`Work7StateGuard`, `Work7ClaimContract`, `Work7IntegrationRunner`, and
`Work7ResponseCandidate`. `EstimatorDiagnostic` runs only within that single
CTest invocation; its retained log is the one-shot estimator functional
artifact. Never invoke `bench_estimator_bias`.

Validate all measured `trials`, `accuracy_trials`, `refresh_updates`, or
equivalent sampling fields equal `1`. Permit at most one explicitly labelled
discarded warmup in a timing cell. Reject warmups in accuracy/analytic cells,
unlabelled/multiple warmups, retries, actual-data manifest paths, missing or
skipped CTests, stale build directories, and row/argv mismatch.

### TDD steps

1. RED — use fake `cmake`, `ctest`, benchmark, and runner executables that emit
   complete realistic records. Test the exact command sequence and success
   seals. Add one failure fixture for each gate: existing root, dirty source,
   missing dependency/test, skip/Not Run, measured count 2, multiple warmups,
   actual-data path, malformed CSV, foreign commit, tampered runtime artifact,
   and external snapshot change.

   ```bash
   python3 -m unittest -v tests.scripts.test_work7_integration_runner
   ```

2. GREEN — implement command construction as immutable argument tuples and a
   single checked command runner that records argv, cwd, start/end time,
   return code, stdout/stderr file, and executable SHA-256. Do not retry.

3. GREEN verification — register `Work7IntegrationRunner`, reconfigure the
   reused build, require `ctest -N` to contain that exact name, then run its
   Python and CTest entries. Treat `No tests were found` as failure. Do not run
   the authoritative real binaries yet.

4. REFACTOR — isolate schema/count validation from subprocess orchestration;
   rerun both tests.

### Phase 2 success conditions

- Hermetic fake-tool tests prove the exact commands and fail-closed branches.
- Fresh configuration/build and the frozen registry are mandatory.
- Raw artifacts are sealed before evidence-bound verification; its report is
  stored only in the closure seal.
- Measured counts are exactly one and external snapshots are unchanged.

### Phase 2 failure conditions

- A pre-existing build/session is reused or overwritten.
- The registry is selected dynamically or a missing test is ignored.
- Actual data, repeated trials, or retry-until-pass is invoked.
- Any sealed file is later changed.

### Commit

```bash
git add CMakeLists.txt scripts/run_work7_integration.py \
  tests/scripts/test_work7_integration_runner.py tests/fixtures/work7/runner
git commit -m "feat(work7): add one-run toy integration runner"
```

---

## Task 4: Phase 3 read-only ResponseStrategy candidate

**Files**

- Create: `scripts/generate_work7_response_candidate.py`
- Create: `tests/scripts/test_work7_response_candidate.py`
- Create fixtures under: `tests/fixtures/work7/response/`
- Modify: `CMakeLists.txt`

### CLI and output

```text
generate_work7_response_candidate.py
  --source-root ABS --paper-root ABS --threshold-root ABS
  --session-root ABS --phase0-seal ABS --phase2-closure-seal ABS
```

Require valid Phase 0 and Phase 2 chains. Recompute external snapshots before
reading Paper. Read exact bytes from `Revision/ResponseStrategy.md`; reject
non-UTF-8. Append one clearly delimited candidate section containing the seven
claim IDs, implemented/toy/performance states, structural threshold readiness,
the non-authorization sentence, and no timing/result number. Write only under
`phase3/candidate-artifacts/`:

- `ResponseStrategy.candidate.md`;
- `ResponseStrategy.candidate.diff` from `difflib.unified_diff`;
- `candidate-metadata.json` with Paper HEAD/snapshot, source commit, input seal
  digests, candidate/diff digests; and
- `candidate-validation.json` mapping prose claims to lifecycle IDs.

Dry-apply the diff to a temporary copy outside Paper. Recompute Paper and
threshold snapshots. Create the candidate-artifact seal, run claim verifier
mode `claim7`, store its report under `phase3/closure-artifacts/`, and create
the Phase 3 closure seal.

### TDD steps

1. RED — test a dirty Paper fixture is preserved byte-for-byte; candidate and
   diff are deterministic; patch dry-apply succeeds; each inserted claim maps
   to a lifecycle row; performance/threshold deferrals are explicit; no number
   is inserted. Fail on Paper mutation, invalid/tampered prior seal, foreign
   artifact, invalid UTF-8, candidate collision, or overclaim fixture.

   ```bash
   python3 -m unittest -v tests.scripts.test_work7_response_candidate
   ```

2. GREEN — implement the minimal generator. Register CTest
   `Work7ResponseCandidate`, reconfigure the reused build, require `ctest -N`
   to contain the exact name, then run both focused commands. Treat
   `No tests were found` as failure.

3. REFACTOR — separate rendering from filesystem/state guards and rerun tests.

### Phase 3 success conditions

- Paper/threshold snapshot digests exactly match Phase 0.
- The candidate/diff dry-apply to the recorded bytes but are never applied.
- Claim 7 reaches toy-verified structural readiness while Work 7 stays pending
  and threshold stays deferred.
- Candidate-artifact and closure seals verify in order.

### Phase 3 failure conditions

- Any external file/index/status changes.
- A one-run diagnostic becomes a paper number or performance claim.
- Threshold branch modification/authorization is stated.
- Claim 7 report is written before the candidate artifacts are sealed.

### Commit

```bash
git add CMakeLists.txt scripts/generate_work7_response_candidate.py \
  tests/scripts/test_work7_response_candidate.py tests/fixtures/work7/response
git commit -m "feat(work7): generate read-only response candidate"
```

---

## Task 5: Phases 4–5 review packet and terminal gate tooling

**Files**

- Create: `scripts/work7_review_packet.py`
- Create: `tests/scripts/test_work7_review_packet.py`
- Create fixtures under: `tests/fixtures/work7/reviews/`

### CLI

```text
work7_review_packet.py prepare-work
  --source-root ABS --session-root ABS --baseline-commit b907fae --output ABS

work7_review_packet.py close-work
  --packet ABS --raw-review ABS --session-root ABS --output-seal ABS

work7_review_packet.py prepare-final
  --source-root ABS --session-root ABS --work-review-seal ABS --output ABS

work7_review_packet.py close-final
  --packet ABS --claude-review ABS --sol-review ABS
  --terminal-report ABS --session-root ABS --phase0-seal ABS
  --paper-root ABS --threshold-root ABS --output-seal ABS
```

Every prepare command creates an immutable `members/` snapshot under that
review phase and copies every review input into it. The canonical packet lists
only POSIX paths relative to the session root, provider-neutral labels, byte
lengths, SHA-256 values, source commit, and every prerequisite seal digest; it
contains no absolute inspection path. Reviewers inspect the session-relative
copies. Packet digest is SHA-256 of canonical packet bytes. `prepare-work`
includes these exact members: the seven approved Work 7 design files, this
Terra plan, `scripts/work7_claims.json`, `git-diff-b907fae-to-head.patch`, all
three derived claim reports available through Phase 3 (`static`,
`evidence-bound`, and `claim7`), Phase 0/2/3 seals,
candidate Markdown/diff/metadata, and the Phase 0 plus current external-state
snapshots. `prepare-final` additionally includes the original 2026-07-29
pre-threshold design, Work 7 raw approval and Phase 4 seal, and two generated
canonical members:

- `works1-6-source-test-map.json`, schema
  `piccard-work7-source-test-map-v1`, derived from immutable lifecycle claims
  1–6 and containing their resolved source paths and frozen CTest names; and
- `final-verification-summary.json`, schema
  `piccard-work7-final-verification-v1`, derived from verified Phase 0–4 seals
  and recording source commit, registry test count/pass count/zero skips, exact
  toy argv digests, measured-count policy result, external snapshot equality,
  and `performance_state=PERFORMANCE_PENDING`.

`prepare-final` generates those two members itself and validates every field
against the sealed inputs before hashing the final packet. No caller-authored
free-form source/test map or verification summary is accepted.

`close-work` uses a separate work-level review schema, not the terminal parser:
provider `openai`, model `gpt-5.6-sol`, effort high, exact `APPROVED`, matching
commit/packet, and status `WORK7_APPROVED`. The seven field names are identical
but the status domain and accepted provider/model are scoped to work review.
After those headers it requires these unique substantive confirmations:

```text
CHECK POC_SCOPE: CONFIRMED
CHECK ONE_RUN_POLICY: CONFIRMED
CHECK PROVENANCE: CONFIRMED
CHECK FAIL_CLOSED: CONFIRMED
CHECK EXTERNAL_IMMUTABILITY: CONFIRMED
CHECK NO_OVERCLAIM: CONFIRMED
```

`close-final` does not itself decide terminal state: first run
`verify_work7_claims.py --mode terminal` with the two raw responses. Then
`close-final` includes both unedited raw hashes and terminal report in the
Phase 5 seal. It accepts provider/model pairs
`anthropic/claude-fable/high` and `openai/gpt-5.6-sol/high` in either input
order, never duplicates of one provider.

Each final raw response must also contain these six unique confirmations,
corresponding to the approved whole-intent review questions:

```text
CHECK G1_G7_INTENT: CONFIRMED
CHECK EVIDENCE_FRESHNESS: CONFIRMED
CHECK PERFORMANCE_PENDING: CONFIRMED
CHECK THRESHOLD_DEFERRED: CONFIRMED
CHECK EXTERNAL_IMMUTABILITY: CONFIRMED
CHECK TERMINAL_STATUS_MAXIMAL: CONFIRMED
```

Header-only approval is invalid. Immediately before writing any terminal report
or Phase 5 seal, terminal verifier and `close-final` independently recompute
Paper/threshold snapshots and require Phase 0 equality. Thus drift after packet
preparation fails before terminal artifacts are created.

After writing and verifying the Phase 5 seal, `close-final` computes the
SHA-256 of the canonical Phase 5 seal bytes. That SHA-256 is the authoritative
session digest. It prints the value as
`WORK7_TERMINAL_SEAL_SHA256=<64-lowercase-hex>` and exclusively creates
`terminal-seal.sha256` containing the same value plus one newline. This pointer
is not recursively part of the seal; verification recomputes the Phase 5 seal
digest and compares it to the pointer. The earlier terminal claim report never
contains or predicts the terminal-seal digest.

### TDD steps

1. RED — test deterministic packet digest, any item mutation, missing packet
   item, wrong seal chain, conditional/missing/duplicated verdict fields,
   commit/digest mismatch, wrong provider/model/effort, duplicate provider,
   header-only approval, missing substantive confirmation, missing terminal
   report, external snapshot drift after packet preparation, and drift between
   terminal verification and final closure.

   ```bash
   python3 -m unittest -v tests.scripts.test_work7_review_packet
   ```

2. GREEN — implement using Task 1 canonical/seal helpers and Task 2 verdict
   parser. This orchestration test remains a direct Python suite rather than
   expanding the frozen authoritative CTest registry.

3. GREEN/REFACTOR — run focused Python/CTest tests, then the complete four
   Work 7 Python suites once. Keep review tooling provider-neutral except for
   the frozen accepted identity pairs.

### Phases 4–5 success conditions

- Each reviewer can inspect one identical packet digest and exact source SHA.
- Raw model output is preserved and hashed; no normalized substitute is used.
- Work-level close accepts only sol-high.
- Terminal close requires valid Fable-high and sol-high approvals plus a
  terminal verifier report for the same packet/commit, and exposes the Phase 5
  seal SHA-256 as the authoritative session digest.
- No terminal report/seal is written unless a fresh external-state check equals
  Phase 0.

### Phases 4–5 failure conditions

- A reviewer approves a different packet or commit.
- `APPROVED_WITH_COMMENTS`, missing metadata, or one provider twice passes.
- Terminal status is written before both raw approvals validate.
- Review artifacts are used as retroactive Work 1–6 approvals.

### Commit

```bash
git add scripts/work7_review_packet.py \
  tests/scripts/test_work7_review_packet.py tests/fixtures/work7/reviews
git commit -m "feat(work7): bind review packets and terminal gate"
```

---

## Task 6: Authoritative run and required reviews

This task changes source only when a reviewer finds a real defect. Runtime
evidence is generated outside all guarded worktrees.

### Preflight

1. Verify the linked worktree is on `tkde-major/pre-threshold-poc`, clean, and
   all Task 1–5 commits exist.
2. Create fresh temporary parents with `mktemp -d` for build and session.
3. Record Paper and threshold paths exactly as approved:

   ```text
   Paper: /Users/heewonchung/Documents/00-Research/active/Private Jaccard with FHE/Paper
   threshold: /Users/heewonchung/Documents/orca/workspace/piccard/tkde-major-threshold-fpfn
   ```

### Authoritative Phase 0–3 run

Run the integration runner once. It performs one fresh build, the frozen CTest
registry once, and all toy probes with measured counts one. Then run the
response-candidate generator. Verify all Phase 0–3 seals twice without writing.

Success: all commands exit 0, no CTest skip/Not Run, all exact schemas/counts
pass, and external snapshot digests are unchanged.

Failure: do not retry. Diagnose, add a failing regression test, fix with Terra,
commit, obtain sol-high task re-review, and create a new commit-keyed session.

### Work-level sol-high review

1. Prepare the work packet.
2. Dispatch `gpt-5.6-sol` high read-only against the exact packet. Require raw
   output header:

   ```text
   VERDICT: APPROVED
   PROVIDER: openai
   MODEL: gpt-5.6-sol
   EFFORT: high
   SOURCE_COMMIT: <exact>
   PACKET_SHA256: <exact>
   STATUS: WORK7_APPROVED
   ```

   The prompt reproduces the six Work-level `CHECK ...: CONFIRMED` questions
   from Task 5 and instructs the reviewer to emit each only after inspecting
   its packet evidence. `close-work` rejects a missing confirmation.

3. If required changes exist, use `superpowers:receiving-code-review`, verify
   each finding, resume the Terra implementer for one fix wave, rerun the full
   authoritative Phase 0–3 path in a new session, and re-review. Maximum two
   remediation cycles.
4. Close and seal Phase 4 only after exact approval.

### Simultaneous final dual review

1. Prepare the final packet and freeze its digest.
2. Start Claude CLI with model `fable`, effort `high`, read-only permissions,
   and start a `gpt-5.6-sol` high reviewer subagent before waiting for either.
   Both prompts name the same packet path/digest and prohibit seeing the other
   verdict.
3. Require both raw records to use the seven terminal header fields from Task 2
   and exact status `POC_APPROVED_PERFORMANCE_PENDING`. Their prompts reproduce
   the six final `CHECK ...: CONFIRMED` questions from Task 5; closure requires
   every confirmation in each independent raw response.
4. If either requests a change, one Terra fix wave handles the complete verified
   findings list. Rerun the full authoritative path, work review, and both final
   reviews against the new commit/session. Maximum two cycles.
5. When both approve, first recompute and verify Paper/threshold snapshots,
   then run claim verifier `terminal`. `close-final` recomputes them again
   before writing anything. Close Phase 5, record the
   emitted Phase 5 seal SHA-256 as the authoritative session digest, and verify
   the seal/pointer plus final Paper/threshold snapshots.

### Final success conditions

- Work-level sol-high raw verdict is exact `APPROVED`.
- Claude Fable high and sol-high independently approve the same final commit
  and packet digest.
- Terminal verifier, Phase 5 seal, and authoritative terminal-seal digest
  pointer pass.
- Source is clean; Paper and threshold byte-level snapshots match Phase 0.
- Final status is exactly `POC_APPROVED_PERFORMANCE_PENDING`.

### Final failure conditions

- Any review is conditional, mismatched, or cannot inspect the packet.
- Any external worktree changes.
- Actual-data/multi-run work is represented as complete.
- A threshold branch action is authorized or performed.
- Two remediation cycles do not produce both approvals.

## Final verification commands

Run fresh after the final source commit:

```bash
python3 -m unittest -v \
  tests.scripts.test_work7_state_guard \
  tests.scripts.test_work7_claim_contract \
  tests.scripts.test_work7_integration_runner \
  tests.scripts.test_work7_response_candidate \
  tests.scripts.test_work7_review_packet

git diff --check b907fae..HEAD
git status --short
```

The authoritative runner's saved build/test/probe logs are the evidence for the
fresh Release build and frozen focused CTest registry. Do not run actual data or
repeat any performance benchmark for this Work 7 completion.
