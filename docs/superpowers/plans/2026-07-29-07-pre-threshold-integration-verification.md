# Work 7 — Pre-threshold Integration, Residual Audit, and Strategy Update

> **Implementation owner:** Claude Opus 5 for Work-7 utilities/remediation  
> **Plan reviewer:** Claude Fable 5, or GPT-5.6-sol when Fable is unavailable  
> **Final reviewers:** GPT-5.6-sol and Claude Fable 5  
> **Dependency:** Works 1–6 individually approved  
> **Next work:** separate `threshold-fpfn` branch only after approval

## Objective

Bind every non-threshold implementation claim to committed source, exact
review records, reproducible test/benchmark artifacts, and an unchanged Paper
tree except for the final `ResponseStrategy.md` status patch. Audit remaining
development issues and allow at most two remediation cycles. Never implement,
run, or report threshold FP/FN work here.

## Fixed paths and identities

```bash
PROJECT_ROOT="/Users/heewonchung/Documents/00-Research/active/Private Jaccard with FHE"
PAPER_REPO="$(cd "$PROJECT_ROOT/Paper" && pwd -P)"
WT="/Users/heewonchung/Documents/orca/workspace/piccard/pre-threshold-poc"
THRESHOLD_WT="/Users/heewonchung/Documents/orca/workspace/piccard/tkde-major-threshold-fpfn"
BASE_COMMIT="$(git -C "$WT" rev-parse aa3053a^{commit})"
PLANNING_COMMIT="$(git -C "$WT" rev-parse HEAD)"
REVIEW_STAGING_ROOT="/Users/heewonchung/Documents/orca/workspace/piccard/review-staging-$PLANNING_COMMIT"
SESSION_ROOT="$WT/scripts/results/integration/session-$PLANNING_COMMIT"
GLOBAL_BASELINE="$SESSION_ROOT/global-baseline"
SESSION_LEDGER="$SESSION_ROOT/session-ledger.tsv"
```

Only the approved design/spec and seven plans are force-added by Phase 0
despite `.gitignore`; before Work 1 each must pass
`git ls-files --error-unmatch`. Work-review/audit Markdown remains in external
staging until Phase 7 and is not subject to that precondition.
`SESSION_ROOT` is created once, before the first Phase 2.  Its
`GLOBAL_BASELINE` is immutable across both permitted remediation reruns; a
rerun must compare against it and must never replace it.

## Approval-record and ownership contract

Each Work 1–6 has two committed records:

```text
audits/reviews/work-<N>-gpt.md
audits/reviews/work-<N>-fable.md
```

Each begins with one exact machine-readable block:

```text
work_id: <N>
base_commit: <40 lowercase hex>
head_commit: <40 lowercase hex>
plan_blob_sha256: <64 lowercase hex>
diff_sha256: <64 lowercase hex>
reviewer_model: <canonical model>
reviewer_instance_id: <nonempty unique agent/session id>
fallback_reason: <empty or FABLE_UNAVAILABLE>
fallback_evidence_path: <empty or fallback/<fallback_evidence_sha256>.tsv>
fallback_evidence_sha256: <empty or 64 lowercase hex>
verdict: APPROVE
```

There is exactly one `verdict:` line. Both records must bind the same work,
base/head, plan blob, and SHA-256 of
`git diff --binary --full-index base_commit..head_commit`. The work diff is
nonempty; Work 1 starts at the approved planning commit, every later work base
equals the previous work head.
The primary model is GPT-5.6-sol. The secondary is Fable, or—only when a
captured Fable-unavailable/session-limit record exists—another independent
GPT-5.6-sol instance with `fallback_reason=FABLE_UNAVAILABLE`. Instance IDs
must differ; Opus is implementation-only and is rejected as a reviewer.
Fallback requires the same immutable failed-call artifact contract and
verification implemented by Work 1; a reason without a readable, read-only,
digest-matching captured Fable failure is rejected.

During product implementation, signed record bytes are written outside the
product worktree at
`$REVIEW_STAGING_ROOT/<record-name>` and their SHA-256s are fixed
before the next Work begins. They are copied unchanged and first committed
only by the Phase-7 evidence commit. Thus review records are committed and
auditable without contaminating the product-source parent chain or making the
next Work's base ambiguous. The verifier compares pending and committed bytes.
Every record stores `fallback_evidence_path=fallback/<sha256>.tsv`. The same
relative path exists beneath staging and is copied byte-identically to
`audits/reviews/fallback/<sha256>.tsv` in the evidence commit; the approval
record itself remains byte-identical. The committed verifier resolves that
relative path beside `audits/reviews/`, recomputes the artifact/body hashes,
and rejects an absent artifact. Final evidence is self-contained if staging
disappears.
`REVIEW_STAGING_ROOT` is created once immediately after `PLANNING_COMMIT`,
must not pre-exist, and is read-only after each individual record is written.

Phase 1 is a separately reviewed product-source work
`work-7-harness-{gpt,fable}.md`: its base is Work 6 head and its head includes
all validators, integration runner, tests, and CMake registration. Each
remediation uses records
`remediation-<cycle>-{gpt,fable}.md`, whose base is its approved
`REMEDIATION_PLAN_COMMIT`. `SOURCE_COMMIT` is the final head of this chained product-source
sequence—not necessarily Work 6 head.
`audits/work-ownership.tsv` assigns every changed path and every
`--unified=0` hunk to exactly one Work/harness/remediation; duplicate/unowned
entries fail.

Every remediation has an explicit two-commit transition. Starting at the
preceding source head, add only
`docs/superpowers/plans/remediation-<cycle>.md`, verify that one-path diff, get
it committed as `REMEDIATION_PLAN_COMMIT`, then obtain independent plan
approval bound to that commit before any implementation. The
plan approval is staged as
`remediation-<cycle>-plan-approval.tsv` with exact fields
`schema_version=piccard-remediation-plan-approval-v1,cycle,prior_source,
plan_commit,plan_path,plan_blob_sha256,primary_model,primary_instance,
primary_verdict,secondary_model,secondary_instance,secondary_verdict,
fallback_reason,fallback_evidence_path,fallback_evidence_sha256`.
The verifier checks the one-path diff, tracked blob, independent instances,
authorized fallback, and both APPROVE verdicts; the source-evidence manifest
binds its committed byte-identical copy and any fallback artifact. The
implementation record's `base_commit` is that plan commit and its
`plan_blob_sha256` is the tracked blob there; Opus then creates a nonempty
implementation diff ending at `REMEDIATION_HEAD`. Ownership records the
plan-only hunk as `remediation-<cycle>-plan` and code hunks as
`remediation-<cycle>`. No unaccounted commit may appear between the preceding
source, plan commit, and implementation head.

## Outputs

Tracked:

```text
audits/pre-threshold-manifest.json
audits/pre-threshold-final-evidence-manifest.json
audits/pre-threshold-evidence-matrix.md
audits/pre-threshold-remaining-cycle-1.md
audits/pre-threshold-remaining-cycle-2.md
audits/pre-threshold-final-audit.md
audits/work-ownership.tsv
audits/reviews/planning-approval.md
audits/reviews/final-source-{gpt,fable}.md
audits/reviews/final-strategy-{gpt,fable}.md
scripts/inventory_tree.py
scripts/normalize_warnings.py
scripts/session_ledger.py
scripts/verify_integration_evidence.py
scripts/run_integration_verification.sh
tests/scripts/test_inventory_tree.py
tests/scripts/test_normalize_warnings.py
tests/scripts/test_session_ledger.py
tests/scripts/test_verify_integration_evidence.py
tests/scripts/test_run_integration_verification.py
CMakeLists.txt
```

Generated evidence lives in a new commit-keyed absolute root:

```text
scripts/results/integration/session-<planning-commit>/
  global-baseline/
  pre-threshold-<40-char-source-commit>/
```

Each commit-keyed run root contains the full binary patch, logs, builds,
benchmark results, per-run snapshots, and artifact hashes. It must not exist
before its run; no overwrite or implicit `latest` is allowed.  Evidence
commits and reviewer records are made in a separate worktree and never become
an ancestor of a later `SOURCE_COMMIT`.

## Phase 0 — Commit only the approved planning inputs

Run once after every plan has the required plan-review approval and before any
implementation:

```bash
set -euo pipefail
test "$(git -C "$WT" rev-parse HEAD)" = "$BASE_COMMIT"
git -C "$WT" diff --quiet
git -C "$WT" diff --cached --quiet
test -z "$(git -C "$WT" status --porcelain=v1 --untracked-files=all)"

git -C "$WT" add -f \
  docs/superpowers/specs/2026-07-29-pre-threshold-poc-design.md \
  docs/superpowers/plans/2026-07-29-01-estimator-random-ranking-poc.md \
  docs/superpowers/plans/2026-07-29-02-sanitizer-security-profile-poc.md \
  docs/superpowers/plans/2026-07-29-03-std128-std192-calibration.md \
  docs/superpowers/plans/2026-07-29-04-benchmark-profiles-and-baseline-gates.md \
  docs/superpowers/plans/2026-07-29-05-real-dataset-pipeline.md \
  docs/superpowers/plans/2026-07-29-06-dynamic-refresh-and-deletion-evidence.md \
  docs/superpowers/plans/2026-07-29-07-pre-threshold-integration-verification.md
STAGED_PATHS="$(git -C "$WT" diff --cached --name-only | LC_ALL=C sort)"
EXPECTED_PATHS="$(printf '%s\n' \
  docs/superpowers/plans/2026-07-29-01-estimator-random-ranking-poc.md \
  docs/superpowers/plans/2026-07-29-02-sanitizer-security-profile-poc.md \
  docs/superpowers/plans/2026-07-29-03-std128-std192-calibration.md \
  docs/superpowers/plans/2026-07-29-04-benchmark-profiles-and-baseline-gates.md \
  docs/superpowers/plans/2026-07-29-05-real-dataset-pipeline.md \
  docs/superpowers/plans/2026-07-29-06-dynamic-refresh-and-deletion-evidence.md \
  docs/superpowers/plans/2026-07-29-07-pre-threshold-integration-verification.md \
  docs/superpowers/specs/2026-07-29-pre-threshold-poc-design.md |
  LC_ALL=C sort)"
test "$STAGED_PATHS" = "$EXPECTED_PATHS"
git -C "$WT" commit -m "docs: approve pre-threshold implementation plans"
PLANNING_COMMIT="$(git -C "$WT" rev-parse HEAD)"
test "$PLANNING_COMMIT" != "$BASE_COMMIT"
test -z "$(git -C "$WT" status --porcelain=v1 --untracked-files=all)"
REVIEW_STAGING_ROOT="/Users/heewonchung/Documents/orca/workspace/piccard/review-staging-$PLANNING_COMMIT"
SESSION_ROOT="$WT/scripts/results/integration/session-$PLANNING_COMMIT"
GLOBAL_BASELINE="$SESSION_ROOT/global-baseline"
SESSION_LEDGER="$SESSION_ROOT/session-ledger.tsv"
test ! -e "$REVIEW_STAGING_ROOT"
mkdir "$REVIEW_STAGING_ROOT"
```

The plan-review bundle at
`$REVIEW_STAGING_ROOT/planning-approval.md` records the independent plan
reviewers and SHA-256 of every staged file and is made read-only. Its exact
two-column TSV schema is
`schema_version=piccard-planning-approval-v1`, `base_commit`,
`planning_commit`, `file_count`, contiguous
`file.000.path|sha256`, and for each Plan 1–7 contiguous
`plan.01.primary_model|primary_instance|primary_verdict|
secondary_model|secondary_instance|secondary_verdict|fallback_reason|
fallback_evidence_path|fallback_evidence_sha256`.
Every verdict is `APPROVE`; instances differ; secondary fallback follows the
same authorized Fable-unavailable rule and binds the failed-call evidence
SHA. The file list must equal the Phase-0 staged list and the verifier
recomputes all blobs from `PLANNING_COMMIT`.
The
integration verifier treats `BASE_COMMIT..PLANNING_COMMIT` as a separately
approved exact path-whitelisted planning range. Work ownership and the Work-1
diff begin strictly at `PLANNING_COMMIT`; planning hunks are never assigned to
an implementation Work.

## Phase 1 — Implement and test evidence validators

### RED tests

`test_inventory_tree.py` pins a NUL-safe inventory containing, for every entry
except `.git`, relative UTF-8 path bytes, lstat type, permission mode, and:

- regular file: size plus SHA-256;
- symlink: literal link-target bytes;
- directory/other: type/mode only.

It detects regular/symlink/mode/target changes and includes `.agent`,
`.claude`, and `.codex` links.

`test_verify_integration_evidence.py` rejects:

- ignored/untracked plan or review records;
- short/mismatched commits or multiple verdict lines;
- empty/per-work-discontinuous diffs;
- review/diff/plan hash mismatch;
- unowned, multiply owned, or mixed-category hunks;
- artifact paths outside the run root;
- a manifest referring to a different source commit/binary hash.

```bash
python3 -m unittest \
  tests.scripts.test_inventory_tree \
  tests.scripts.test_normalize_warnings \
  tests.scripts.test_session_ledger \
  tests.scripts.test_verify_integration_evidence \
  tests.scripts.test_run_integration_verification -v
```

Expected RED: modules absent.

### GREEN and pass conditions

Implement using Python standard library, binary I/O, and `os.lstat`; never
follow inventory symlinks. Register both suites with CTest. The verifier writes
no state and returns nonzero on the first contract violation.
`normalize_warnings.py` extracts compiler `warning:` records, replaces source
roots and line/column coordinates with stable tokens, sorts unique records,
and has GCC/Clang golden fixtures.
`session_ledger.py` implements an append-only TSV hash chain with monotone
sequence number, event, remediation count, source commit, prior-row SHA, and
row SHA. Tests reject truncation, edit/reorder, duplicate sequence, count
decrease/jump, more than two remediation increments, or source-run events
whose declared expected count differs from the ledger.
Implement `run_integration_verification.sh` and its fake-tool contract test in
this phase as well; Phase 4 only executes the already-reviewed runner.

After GREEN, commit these files as the nonempty Work-7 harness diff, obtain
independent GPT/Fable approvals using the common record schema, and require a
clean tree. Only that approved harness head may become the first
`SOURCE_COMMIT` for Phase 2. Generate the exhaustive hunk ownership table
against `PLANNING_COMMIT..SOURCE_COMMIT`, have both harness reviewers bind its
SHA, and freeze it read-only at
`$REVIEW_STAGING_ROOT/work-ownership-$SOURCE_COMMIT.tsv`; do not place it in
the product worktree. Each remediation head gets a new complete,
commit-suffixed table rather than modifying an earlier one.

## Phase 2 — Freeze committed source, Paper, and threshold state

```bash
SOURCE_COMMIT="$(git -C "$WT" rev-parse HEAD)"
test "$SOURCE_COMMIT" != "$BASE_COMMIT"
test -z "$(git -C "$WT" status --porcelain=v1 --untracked-files=all)"
test -n "${EXPECTED_REMEDIATION_COUNT:?0, 1, or 2}"
case "$EXPECTED_REMEDIATION_COUNT" in 0|1|2) ;; *) exit 1 ;; esac
if test "$EXPECTED_REMEDIATION_COUNT" -eq 0; then
  test ! -e "$SESSION_ROOT"
  SESSION_TMP="$SESSION_ROOT.init.$$"
  test ! -e "$SESSION_TMP"
  mkdir -p "$SESSION_TMP/global-baseline"
  TMP_BASELINE="$SESSION_TMP/global-baseline"
  git -C "$PAPER_REPO" status --porcelain=v1 -z \
    > "$TMP_BASELINE/paper-status.z"
  python3 "$WT/scripts/inventory_tree.py" "$PAPER_REPO" \
    > "$TMP_BASELINE/paper.inventory.z"
  cp "$PAPER_REPO/Revision/ResponseStrategy.md" \
    "$TMP_BASELINE/ResponseStrategy.md"
  git -C "$THRESHOLD_WT" symbolic-ref -q HEAD \
    > "$TMP_BASELINE/threshold-branch.txt"
  git -C "$THRESHOLD_WT" rev-parse HEAD \
    > "$TMP_BASELINE/threshold-head.txt"
  git -C "$THRESHOLD_WT" status --porcelain=v1 -z \
    > "$TMP_BASELINE/threshold-status.z"
  python3 "$WT/scripts/inventory_tree.py" "$THRESHOLD_WT" \
    > "$TMP_BASELINE/threshold.inventory.z"
  chmod -R a-w "$TMP_BASELINE"
  python3 "$WT/scripts/session_ledger.py" init \
    --ledger="$SESSION_TMP/session-ledger.tsv" \
    --planning="$PLANNING_COMMIT" --source="$SOURCE_COMMIT"
  mv "$SESSION_TMP" "$SESSION_ROOT"
else
  test -d "$SESSION_ROOT"
  python3 "$WT/scripts/session_ledger.py" verify \
    --ledger="$SESSION_LEDGER" \
    --planning="$PLANNING_COMMIT" \
    --expected-remediation-count="$EXPECTED_REMEDIATION_COUNT"
fi
ATTEMPT_INDEX="$(python3 "$WT/scripts/session_ledger.py" append \
  --ledger="$SESSION_LEDGER" --event=SOURCE_RUN_START \
  --expected-remediation-count="$EXPECTED_REMEDIATION_COUNT" \
  --source="$SOURCE_COMMIT" --print-sequence)"
RUN_ROOT="$SESSION_ROOT/attempt-$ATTEMPT_INDEX-pre-threshold-$SOURCE_COMMIT"
test ! -e "$RUN_ROOT"
mkdir -p "$RUN_ROOT/logs" "$RUN_ROOT/audits"
test -f "$REVIEW_STAGING_ROOT/work-ownership-$SOURCE_COMMIT.tsv"
cp "$REVIEW_STAGING_ROOT/work-ownership-$SOURCE_COMMIT.tsv" \
  "$RUN_ROOT/audits/work-ownership.tsv"
shasum -a 256 "$RUN_ROOT/audits/work-ownership.tsv" \
  > "$RUN_ROOT/audits/work-ownership.tsv.sha256"

git -C "$WT" diff --binary --full-index \
  "$BASE_COMMIT".."$SOURCE_COMMIT" > "$RUN_ROOT/source.patch"
test -s "$RUN_ROOT/source.patch"
shasum -a 256 "$RUN_ROOT/source.patch" > "$RUN_ROOT/source.patch.sha256"
git -C "$WT" diff --binary --full-index \
  "$BASE_COMMIT".."$PLANNING_COMMIT" > "$RUN_ROOT/planning.patch"
git -C "$WT" diff --binary --full-index \
  "$PLANNING_COMMIT".."$SOURCE_COMMIT" > "$RUN_ROOT/product.patch"
test -s "$RUN_ROOT/planning.patch"
test -s "$RUN_ROOT/product.patch"
python3 "$WT/scripts/verify_integration_evidence.py" \
  --worktree="$WT" --base="$BASE_COMMIT" \
  --planning="$PLANNING_COMMIT" --source="$SOURCE_COMMIT" \
  --planning-approval="$REVIEW_STAGING_ROOT/planning-approval.md" \
  --ownership="$RUN_ROOT/audits/work-ownership.tsv" \
  --staged-reviews="$REVIEW_STAGING_ROOT"

test -d "$GLOBAL_BASELINE"
test ! -w "$GLOBAL_BASELINE/paper.inventory.z"

# Every rerun proves that no prior cycle changed Paper or the threshold
# worktree.  These files are per-run copies only; the comparison authority is
# always GLOBAL_BASELINE.
git -C "$PAPER_REPO" status --porcelain=v1 -z \
  > "$RUN_ROOT/paper-status-initial.z"
python3 "$WT/scripts/inventory_tree.py" "$PAPER_REPO" \
  > "$RUN_ROOT/paper-initial.inventory.z"
cp "$PAPER_REPO/Revision/ResponseStrategy.md" \
  "$RUN_ROOT/ResponseStrategy.initial.md"
cmp "$GLOBAL_BASELINE/paper-status.z" "$RUN_ROOT/paper-status-initial.z"
cmp "$GLOBAL_BASELINE/paper.inventory.z" "$RUN_ROOT/paper-initial.inventory.z"
cmp "$GLOBAL_BASELINE/ResponseStrategy.md" \
    "$RUN_ROOT/ResponseStrategy.initial.md"

git -C "$THRESHOLD_WT" symbolic-ref -q HEAD \
  > "$RUN_ROOT/threshold-branch-initial.txt"
git -C "$THRESHOLD_WT" rev-parse HEAD \
  > "$RUN_ROOT/threshold-head-initial.txt"
git -C "$THRESHOLD_WT" status --porcelain=v1 -z \
  > "$RUN_ROOT/threshold-status-initial.z"
python3 "$WT/scripts/inventory_tree.py" "$THRESHOLD_WT" \
  > "$RUN_ROOT/threshold-initial.inventory.z"
cmp "$GLOBAL_BASELINE/threshold-branch.txt" \
    "$RUN_ROOT/threshold-branch-initial.txt"
cmp "$GLOBAL_BASELINE/threshold-head.txt" \
    "$RUN_ROOT/threshold-head-initial.txt"
cmp "$GLOBAL_BASELINE/threshold-status.z" \
    "$RUN_ROOT/threshold-status-initial.z"
cmp "$GLOBAL_BASELINE/threshold.inventory.z" \
    "$RUN_ROOT/threshold-initial.inventory.z"
```

Pass: all six per-work diffs/reviews are nonvacuous and chained; every
changed path/hunk is owned; all snapshots exist before implementation evidence
is run. The first invocation is the only one allowed to create
`GLOBAL_BASELINE`; all later cycles compare to those immutable bytes before
doing any work.

## Phase 3 — Classify every changed hunk and enforce threshold exclusion

`verify_integration_evidence.py` first verifies the separately approved
path-whitelisted `planning.patch`, then parses every implementation hunk in
`product.patch`.
`$RUN_ROOT/audits/work-ownership.tsv` gives location, Work, category,
rationale, and
approval-record paths. Categories are:

```text
APPROVED_NON_THRESHOLD
COMMON_COMPATIBILITY
EXISTING_THRESHOLD_REGRESSION
THRESHOLD_FPFN
```

An unclassified/multiply classified hunk or any `THRESHOLD_FPFN` hunk fails.
Mixed files are classified per hunk, never hidden by file-level labels.
Supplementary keyword scanning is correctly fail-on-match:

```bash
SEMANTIC_PATCH="$RUN_ROOT/pre-threshold-semantic.patch"
git -C "$WT" diff -U0 "$PLANNING_COMMIT".."$SOURCE_COMMIT" -- \
  benchmarks include src scripts tests > "$SEMANTIC_PATCH" || exit 1
set +e
rg -i '^[+-][^+-].*(false.?positive|false.?negative|fp.?count|fn.?count|fp.?rate|fn.?rate|decision.?boundary.?sweep|binomial.?overlay)' \
  "$SEMANTIC_PATCH"
semantic_status=$?
set -e
case "$semantic_status" in
  0) exit 1 ;;
  1) ;;
  *) echo "semantic scan failed" >&2; exit 1 ;;
esac
```

The pre-threshold runner manifest must contain no threshold binary/schema/path.
Existing threshold correctness regression is allowed but produces no FP/FN
evidence.

## Phase 4 — Execute the reviewed commit-bound verification function

Execute the Phase-1-reviewed `scripts/run_integration_verification.sh`. Its
only entry point is:

```bash
scripts/run_integration_verification.sh \
  --source-commit="$SOURCE_COMMIT" \
  --results-root="$RUN_ROOT" \
  --paper-root="$PAPER_REPO" \
  --threshold-worktree="$THRESHOLD_WT" \
  --actual-data-config="${ACTUAL_DATA_CONFIG:-NONE}"
```

`--actual-data-config` is mandatory. `NONE` deterministically creates
`$RUN_ROOT/actual-data.status` containing the single line
`BLOCKED_DATA_PENDING`. Any other value must be a canonical absolute regular
file with this exact alternating TSV schema and exactly three ordered pairs:

```text
schema_version	piccard-actual-data-config-v1
source_manifest	/absolute/path/dblp_acm.source.tsv
dataset_manifest	/absolute/path/dblp_acm_u65536/dataset.manifest.tsv
source_manifest	/absolute/path/enron.source.tsv
dataset_manifest	/absolute/path/enron_u65536/dataset.manifest.tsv
source_manifest	/absolute/path/enron.source.tsv
dataset_manifest	/absolute/path/enron_u1048576/dataset.manifest.tsv
```

The runner validates each referenced file before any real-data command,
records the config and input SHA-256s, passes the six paths to
`run_real_datasets.sh` in that exact order with both primary profiles, and
writes `VERIFIED_ACTUAL_DATA` only after the Work-5 verifier succeeds. A
missing/malformed/noncanonical configured path is `BLOCKED`, never silently
downgraded to `NONE`. The fake-tool test covers `NONE`, a valid config, all
schema/path failures, and proves no paper-ready/data-ready status can be
emitted without an actual verified path.

It requires clean `HEAD == source-commit`, a newly created root from Phase 2,
and creates fresh build trees inside that root:

```text
$RUN_ROOT/build-debug
$RUN_ROOT/build-release
```

It never reuses repository `build/`. Every configure/build/test command logs
stdout/stderr and preserves the real exit code:

```bash
cmake -S "$WT" -B "$RUN_ROOT/build-debug" -DCMAKE_BUILD_TYPE=Debug \
  > "$RUN_ROOT/logs/configure-debug.log" 2>&1
cmake --build "$RUN_ROOT/build-debug" -j4 \
  > "$RUN_ROOT/logs/build-debug.log" 2>&1
ctest --test-dir "$RUN_ROOT/build-debug" --output-on-failure \
  > "$RUN_ROOT/logs/ctest-debug.log" 2>&1

cmake -S "$WT" -B "$RUN_ROOT/build-release" -DCMAKE_BUILD_TYPE=Release \
  > "$RUN_ROOT/logs/configure-release.log" 2>&1
cmake --build "$RUN_ROOT/build-release" -j4 \
  > "$RUN_ROOT/logs/build-release.log" 2>&1
ctest --test-dir "$RUN_ROOT/build-release" --output-on-failure \
  > "$RUN_ROOT/logs/ctest-release.log" 2>&1
ctest --test-dir "$RUN_ROOT/build-release" \
  --repeat until-fail:3 --output-on-failure \
  > "$RUN_ROOT/logs/ctest-release-repeat.log" 2>&1
```

Then, exactly once in fresh phase-specific roots:

```bash
"$RUN_ROOT/build-release/bench_estimator_bias" \
  --k=128 --m=64 --set-size=1000 --trials=10000 \
  --seed=20260729 --jaccard-grid=0,0.1,0.25,0.5,0.75,0.9,1 \
  > "$RUN_ROOT/estimator-bias.csv"
"$RUN_ROOT/build-release/bench_noise" --coverage --pre_threshold \
  > "$RUN_ROOT/logs/noise-coverage.log" 2>&1

DRY_RUN=1 "$WT/scripts/run_pre_threshold_profiles.sh" \
  --suite=primary --seed=20260729 --threads=8 \
  --build-dir="$RUN_ROOT/build-release" \
  > "$RUN_ROOT/logs/pre-threshold-dry-run.log" 2>&1
"$WT/scripts/run_pre_threshold_profiles.sh" \
  --suite=smoke --seed=7 --threads=2 \
  --build-dir="$RUN_ROOT/build-release" \
  --results-root="$RUN_ROOT/bench-smoke"

"$WT/scripts/run_real_datasets.sh" --quick --seed=7 --threads=2 \
  --build-dir="$RUN_ROOT/build-release" \
  --results-root="$RUN_ROOT/real-quick"

# When ACTUAL_DATA_CONFIG is an absolute file, the runner expands its exact
# three source/dataset pairs here; no guessed path or default dataset is used.
"$WT/scripts/run_real_datasets.sh" \
  --source-manifest=<DBLP_SOURCE_FROM_CONFIG> \
  --dataset-manifest=<DBLP_U65536_FROM_CONFIG> \
  --source-manifest=<ENRON_SOURCE_FROM_CONFIG> \
  --dataset-manifest=<ENRON_U65536_FROM_CONFIG> \
  --source-manifest=<ENRON_SOURCE_FROM_CONFIG> \
  --dataset-manifest=<ENRON_U1048576_FROM_CONFIG> \
  --profile=std128-t40-primary --profile=std192-t40-primary \
  --seed=20260729 --threads=8 \
  --build-dir="$RUN_ROOT/build-release" \
  --results-root="$RUN_ROOT/real-actual"

"$RUN_ROOT/build-release/bench_deletion_survival" \
  --n=1024 --d=5 --k=128 --required_survival=0.99 \
  --r_values=156,357,512 --trials=100000 --seed=20260729 \
  > "$RUN_ROOT/deletion-survival.csv"
```

Verifiers consume runner manifests, not guessed filenames:

```bash
python3 "$WT/scripts/verify_benchmark_provenance.py" \
  --run-manifest="$RUN_ROOT/bench-smoke/manifest.json"
python3 "$WT/scripts/verify_review_comparison.py" \
  --run-manifest="$RUN_ROOT/bench-smoke/manifest.json"
python3 "$WT/scripts/verify_real_dataset_outputs.py" \
  "$RUN_ROOT/real-quick"
# Required in configured actual-data mode:
python3 "$WT/scripts/verify_real_dataset_outputs.py" \
  "$RUN_ROOT/real-actual"
```

The function records executable SHA-256s, expanded commands, dependency
versions, CPU/RAM/OS/compiler, OpenMP policy, source commit, outputs, and logs.
It rejects skipped required tests, unknown-option acceptance, `--help` data
rows, dependency absence, warning-fingerprint change, output escape, or stale
binary commit. `ctest -N` count must equal executed non-skipped required tests.

The warning baseline is produced on the same host/compiler from an exported
base tree:

```bash
mkdir "$RUN_ROOT/base-source"
git -C "$WT" archive "$BASE_COMMIT" | tar -x -C "$RUN_ROOT/base-source"
cmake -S "$RUN_ROOT/base-source" -B "$RUN_ROOT/build-base-debug" \
  -DCMAKE_BUILD_TYPE=Debug > "$RUN_ROOT/logs/configure-base.log" 2>&1
cmake --build "$RUN_ROOT/build-base-debug" -j4 \
  > "$RUN_ROOT/logs/build-base.log" 2>&1
python3 "$WT/scripts/normalize_warnings.py" \
  --source-root="$RUN_ROOT/base-source" "$RUN_ROOT/logs/build-base.log" \
  > "$RUN_ROOT/warnings-base.txt"
python3 "$WT/scripts/normalize_warnings.py" \
  --source-root="$WT" "$RUN_ROOT/logs/build-debug.log" \
  > "$RUN_ROOT/warnings-source.txt"
diff -u "$RUN_ROOT/warnings-base.txt" "$RUN_ROOT/warnings-source.txt"
```

Any normalized new warning fails; removal is recorded separately and requires
an explicit verifier allowance. Missing configure/build/test logs fail.

## Phase 5 — Build the reviewer evidence matrix

`audits/pre-threshold-evidence-matrix.md` contains:

| Issue | Required evidence |
|---|---|
| R3-1 | SHA-256 ranking contract, tests, bias CSV |
| R1-3/R3-2/W6 | transcript/Q/N profile, sanitizer PoC, fail-closed tests |
| R3-5 | STD128/STD192 actual N/logQ calibration and coverage |
| W1 | strict STD128 common workload; honest STD192 AHE gap |
| W2 | fixtures, deterministic DBLP/Enron pipeline, actual-data status |
| R1-1/W3/R3-3 | versioned atomic single-owner full refresh |
| R1-2/R3-3 | analytic/MC deletion evidence and off-by-one |
| R3-4 | `DEFERRED_EXPECTED` |

Every row names behavior, test, artifact SHA, source commit, Work approvals,
threshold dependency, and status from:
`implemented|smoke-verified|calibrated|paper-grade-measured|
implemented-data-pending|paper-wording-pending|deferred`.
PoC is never described as proof-equivalent.

Primary40 Piccard STD192 missing calibration, timeout, or infeasibility is
terminal `BLOCKED`. Unsupported matched AHE-192 remains the expected honest
capability rejection and is not itself a Piccard failure.

If the actual DBLP/Enron source manifests/checksums are unavailable, set
terminal candidate `BLOCKED_DATA_PENDING`. The implementation and fixture
evidence may pass, and ResponseStrategy is still updated honestly, but the
workflow may not authorize threshold branching.

## Phase 6 — Global residual audit and at most two remediation cycles

The append-only `SESSION_LEDGER` is the sole authority for the global
`remediation_count`; process memory or Markdown is not authoritative. It
starts at zero, may increase only by one, and may never exceed two. Triggers
include:

- initial residual audit finding;
- any rerun/build/schema/provenance failure;
- final-source reviewer rejection;
- post-ResponseStrategy factuality reviewer rejection.

Always write `audits/pre-threshold-final-audit.md`, even with zero remediation.
For a product/source trigger while count < 2:

1. append `PRODUCT_REMEDIATION_START` with the prior source and trigger hash;
   `session_ledger.py` atomically increments and prints the new count;
   write
   `audits/pre-threshold-remaining-cycle-<count>.md`;
2. create the dedicated detailed plan as the one-path plan-only commit
   specified above, obtain Fable (or authorized GPT fallback) plan approval,
   then have Opus implement from that exact commit phase-by-phase with new
   independent phase reviewers;
3. obtain GPT/Fable work approval whose base is
   `REMEDIATION_PLAN_COMMIT` and whose plan blob is present at that base;
4. apply and commit both explicit transitions only on the product branch,
   starting from the preceding product `SOURCE_COMMIT`—never from an evidence
   or reviewer commit; set the implementation head as the new `SOURCE_COMMIT`, create a
   brand-new commit-keyed `RUN_ROOT`, and rerun Phases 2–5 in full with fresh
   build trees while comparing Paper/threshold state to the original immutable
   `GLOBAL_BASELINE`;
5. re-audit.

A post-ResponseStrategy rejection is classified before consuming the cycle:

- if a source/evidence claim is false, first verify the attempted strategy
  file still has the recorded attempt SHA, copy the immutable baseline
  `ResponseStrategy.md` back, prove the full Paper inventory/status again
  equals `GLOBAL_BASELINE`, append `PRODUCT_REMEDIATION_START`, and follow the
  full source path above;
- if source evidence is sound and only wording/status/scope is rejected,
  append `STRATEGY_RETRY_START` (also incrementing the same global count),
  preserve the rejected attempt beneath
  `$RUN_ROOT/strategy-attempt-<ledger-sequence>/`, restore the baseline bytes
  under the same SHA/inventory guards, and repeat Phase 8 only. It does not
  create a fake new source commit or rerun Phases 2–5.

Every strategy attempt has a distinct subroot with a two-stage seal. Its
`payload/` (initial/final file, patch, hashes, ledger snapshot) is made
read-only before review. After review, immutable records and terminal verdict
are copied into a new `review-outcome/`, then the attempt root is made
read-only and never changed. Rollback is allowed only for the exact file bytes this workflow
wrote; a concurrent or unrecognized Paper change is terminal `BLOCKED`, not
overwritten.

After count 2, any trigger is terminal `BLOCKED/REJECTED`; no third cycle and
no threshold work. The terminal audit records count, all triggers, final
source/evidence hashes, and unresolved items. Evidence/review commits for a
failed source are retained on their own named evidence branch but are never
merged or rebased into the product-source chain.

## Phase 7 — Bind and review final source evidence

Never commit audit evidence on the product-source branch. Create one detached
evidence branch/worktree from the final product `SOURCE_COMMIT`:

```bash
EVIDENCE_WT="/Users/heewonchung/Documents/orca/workspace/piccard/evidence-$SOURCE_COMMIT"
EVIDENCE_BRANCH="tkde-major/pre-threshold-evidence-$SOURCE_COMMIT"
test ! -e "$EVIDENCE_WT"
git -C "$WT" worktree add -b "$EVIDENCE_BRANCH" \
  "$EVIDENCE_WT" "$SOURCE_COMMIT"
test "$(git -C "$EVIDENCE_WT" rev-parse HEAD)" = "$SOURCE_COMMIT"
```

Copy the generated audit Markdown/JSON/TSV from the run root, the
byte-identical `planning-approval.md` to
`audits/reviews/planning-approval.md`, and the
Work/harness/remediation records from `REVIEW_STAGING_ROOT`
into their tracked destinations in `EVIDENCE_WT`, including every
`remediation-*-plan-approval.tsv`. For each referenced
`fallback/<sha>.tsv`, create `audits/reviews/fallback/` and copy the artifact
there byte-identically. Verify every staged-record/artifact SHA and relative
reference before copying and do not modify `WT`. Then:

```bash
test "$(git -C "$EVIDENCE_WT" rev-parse HEAD)" = "$SOURCE_COMMIT"
git -C "$EVIDENCE_WT" add -f \
  docs/superpowers/specs docs/superpowers/plans audits \
  scripts/inventory_tree.py scripts/normalize_warnings.py \
  scripts/session_ledger.py \
  scripts/verify_integration_evidence.py \
  scripts/run_integration_verification.sh tests/scripts CMakeLists.txt
git -C "$EVIDENCE_WT" ls-files --error-unmatch \
  docs/superpowers/plans/2026-07-29-07-pre-threshold-integration-verification.md
git -C "$EVIDENCE_WT" ls-files --error-unmatch \
  audits/pre-threshold-manifest.json
git -C "$EVIDENCE_WT" ls-files --error-unmatch audits/work-ownership.tsv
git -C "$EVIDENCE_WT" ls-files --error-unmatch \
  audits/reviews/planning-approval.md
python3 "$EVIDENCE_WT/scripts/verify_integration_evidence.py" \
  --verify-committed-review-copy \
  --staged-reviews="$REVIEW_STAGING_ROOT" \
  --committed-reviews="$EVIDENCE_WT/audits/reviews" \
  --staged-ownership="$REVIEW_STAGING_ROOT/work-ownership-$SOURCE_COMMIT.tsv" \
  --committed-ownership="$EVIDENCE_WT/audits/work-ownership.tsv"
cmp "$REVIEW_STAGING_ROOT/planning-approval.md" \
    "$EVIDENCE_WT/audits/reviews/planning-approval.md"
git -C "$EVIDENCE_WT" diff --cached --quiet && exit 1
git -C "$EVIDENCE_WT" commit -m \
  "test: record pre-threshold source evidence"
ARTIFACT_COMMIT="$(git -C "$EVIDENCE_WT" rev-parse HEAD)"
test "$(git -C "$EVIDENCE_WT" rev-parse "$ARTIFACT_COMMIT^")" = \
     "$SOURCE_COMMIT"
git -C "$EVIDENCE_WT" show \
  "$ARTIFACT_COMMIT:audits/pre-threshold-manifest.json" \
  > "$RUN_ROOT/tracked-manifest.json"
shasum -a 256 "$RUN_ROOT/tracked-manifest.json" \
  > "$RUN_ROOT/tracked-manifest.sha256"
{
  printf '%s\n' "$SOURCE_COMMIT" "$ARTIFACT_COMMIT"
  cat "$RUN_ROOT/tracked-manifest.sha256" "$RUN_ROOT/source.patch.sha256"
} > "$RUN_ROOT/evidence-bundle.binding"
shasum -a 256 "$RUN_ROOT/evidence-bundle.binding" \
  > "$RUN_ROOT/evidence-bundle.sha256"
```

`ARTIFACT_COMMIT` is stored in the external evidence bundle and both review
records; the tracked manifest itself binds `SOURCE_COMMIT`, its parent/source
diff, and every artifact SHA, avoiding a self-referential commit hash.
The evidence manifest also records `GLOBAL_BASELINE` hashes and the explicit
actual-data config/status. `SOURCE_COMMIT` remains the product head and cannot
equal `ARTIFACT_COMMIT`.

Independently give the same bundle to GPT-5.6-sol and Fable. Records
`final-source-{gpt,fable}.md` bind canonical reviewer, source/artifact commits,
manifest blob SHA, source patch SHA, and one terminal verdict. Both must
also bind `evidence-bundle.sha256` and `APPROVE`; otherwise Phase 6 consumes a
remaining cycle or terminates. Reviewers do not see one another's record
before submitting.

After both records arrive, write
`audits/reviews/final-source-outcome.tsv` as exact UTF-8/LF two-column TSV
with keys in this order:
`schema_version=piccard-final-source-outcome-v1`, `remediation_count`,
`source_commit`, `artifact_commit`, `evidence_bundle_sha256`,
`gpt_record_path`, `gpt_record_sha256`, `gpt_verdict`,
`secondary_record_path`, `secondary_record_sha256`, `secondary_verdict`,
`combined_verdict=APPROVE|REJECT`,
`next_state=PHASE8|PRODUCT_REMEDIATION|TERMINAL_REJECTED`,
`trigger_sha256` (empty only for APPROVE), and `final_audit_blob_sha256`.
Unknown, missing, duplicate, reordered, tab/newline-bearing, or inconsistent
fields fail. The audit blob SHA is computed after updating
`audits/pre-threshold-final-audit.md` with both actual verdicts and the
resulting next-trigger or terminal unresolved state; the outcome is then
written and revalidated against that staged blob. Force-add exactly
those two records, the outcome TSV, and updated audit in `EVIDENCE_WT`.
Validate and commit them as `SOURCE_REVIEW_COMMIT`. That commit must have
`ARTIFACT_COMMIT` as parent and change no implementation or original source
manifest. It is created for APPROVE and REJECT alike, so a final-source
rejection at count two is causally and terminally recorded without Phase 8.
The product worktree must still have `HEAD == SOURCE_COMMIT` and a clean tree.

If review triggers remediation, discard neither branch nor evidence. Return to
the product `WT` at `SOURCE_COMMIT`, create the explicit remediation plan
commit followed by its implementation commit, and repeat Phases 2–7 in a new
commit-keyed run root and new evidence worktree.
The remediation plan/implementation/review records belong to that new source
chain; prior artifact/reviewer commits are never its parents.

## Phase 8 — Update only ResponseStrategy, then post-edit review

Only now patch:

```text
Paper/Revision/ResponseStrategy.md
```

Allowed sections are status/date/base/head/benchmark state; F2/F3/F5/F7/F8;
§1.5/1.6; R1-1/R1-2/R1-3; W1/W2/W3/W4/W6;
R3-1/R3-2/R3-3/R3-5; and implementation/open/deferred summaries.
Do not edit any TeX, appendix, response letter, or other Paper file.
Distinguish implementation, smoke, calibration, paper-grade measurement,
actual-data pending, and paper-wording pending. R3-4 remains deferred.

Before editing, start a distinct attempt:

```bash
PRE_EDIT_CHECK="$(mktemp -d)"
git -C "$PAPER_REPO" status --porcelain=v1 -z \
  > "$PRE_EDIT_CHECK/paper-status.z"
python3 "$WT/scripts/inventory_tree.py" "$PAPER_REPO" \
  > "$PRE_EDIT_CHECK/paper.inventory.z"
cmp "$GLOBAL_BASELINE/paper-status.z" "$PRE_EDIT_CHECK/paper-status.z"
cmp "$GLOBAL_BASELINE/paper.inventory.z" "$PRE_EDIT_CHECK/paper.inventory.z"
cmp "$GLOBAL_BASELINE/ResponseStrategy.md" \
  "$PAPER_REPO/Revision/ResponseStrategy.md"
STRATEGY_SEQUENCE="$(python3 "$WT/scripts/session_ledger.py" append \
  --ledger="$SESSION_LEDGER" --event=STRATEGY_ATTEMPT_START \
  --expected-remediation-count="$EXPECTED_REMEDIATION_COUNT" \
  --source="$SOURCE_COMMIT" --print-sequence)"
STRATEGY_ROOT="$RUN_ROOT/strategy-attempt-$STRATEGY_SEQUENCE"
test ! -e "$STRATEGY_ROOT"
mkdir "$STRATEGY_ROOT"
cp "$GLOBAL_BASELINE/ResponseStrategy.md" \
  "$STRATEGY_ROOT/ResponseStrategy.initial.md"
```

Capture the patch without treating `diff` exit 1 as failure:

```bash
if cmp -s "$GLOBAL_BASELINE/ResponseStrategy.md" \
             "$PAPER_REPO/Revision/ResponseStrategy.md"; then
  exit 1
fi
diff_status=0
diff -u "$GLOBAL_BASELINE/ResponseStrategy.md" \
  "$PAPER_REPO/Revision/ResponseStrategy.md" \
  > "$STRATEGY_ROOT/ResponseStrategy.patch.diff" || diff_status=$?
test "$diff_status" -eq 1
test -s "$STRATEGY_ROOT/ResponseStrategy.patch.diff"
cp "$PAPER_REPO/Revision/ResponseStrategy.md" \
  "$STRATEGY_ROOT/ResponseStrategy.final.md"
shasum -a 256 "$GLOBAL_BASELINE/ResponseStrategy.md" \
  "$STRATEGY_ROOT/ResponseStrategy.final.md" \
  "$STRATEGY_ROOT/ResponseStrategy.patch.diff" \
  > "$STRATEGY_ROOT/ResponseStrategy.hashes"
```

Create the final inventory/status:

```bash
python3 "$WT/scripts/inventory_tree.py" "$PAPER_REPO" \
  > "$STRATEGY_ROOT/paper-final.inventory.z"
git -C "$PAPER_REPO" status --porcelain=v1 -z \
  > "$STRATEGY_ROOT/paper-status-final.z"
```

The verifier compares `paper-final.inventory.z` and `paper-status-final.z`
against the immutable `GLOBAL_BASELINE` inventory/status while allowing only
the regular-file content/size digest of `Revision/ResponseStrategy.md` to
differ; every path/type/mode/symlink target and every other digest must match.
Parsed NUL status maps must preserve every pre-existing path/status. Only
`Revision/ResponseStrategy.md` may appear as newly modified or retain its
global-baseline modified status; no other entry may appear, disappear, or
change.

Freeze and compare threshold state:

```bash
git -C "$THRESHOLD_WT" symbolic-ref -q HEAD \
  > "$STRATEGY_ROOT/threshold-branch-final.txt"
git -C "$THRESHOLD_WT" rev-parse HEAD \
  > "$STRATEGY_ROOT/threshold-head-final.txt"
git -C "$THRESHOLD_WT" status --porcelain=v1 -z \
  > "$STRATEGY_ROOT/threshold-status-final.z"
python3 "$WT/scripts/inventory_tree.py" "$THRESHOLD_WT" \
  > "$STRATEGY_ROOT/threshold-final.inventory.z"
cmp "$GLOBAL_BASELINE/threshold-branch.txt" "$STRATEGY_ROOT/threshold-branch-final.txt"
cmp "$GLOBAL_BASELINE/threshold-head.txt" "$STRATEGY_ROOT/threshold-head-final.txt"
cmp "$GLOBAL_BASELINE/threshold-status.z" "$STRATEGY_ROOT/threshold-status-final.z"
cmp "$GLOBAL_BASELINE/threshold.inventory.z" "$STRATEGY_ROOT/threshold-final.inventory.z"
```

Now build the final, post-Paper/post-threshold evidence manifest in
`EVIDENCE_WT`. `audits/pre-threshold-final-evidence-manifest.json` must
enumerate and SHA-256-bind:

- `SOURCE_COMMIT`, `ARTIFACT_COMMIT`, and `SOURCE_REVIEW_COMMIT`;
- source patch, tracked source manifest, all Work/harness/remediation reviews,
  the byte-identical planning approval,
  test/build/benchmark/data outputs, actual-data status/config, and the
  immutable per-attempt ledger snapshot (never the live append-only ledger);
- immutable global Paper/threshold inventories, statuses, branch/head, and the
  per-run initial copies;
- final Paper/threshold inventories/statuses, ResponseStrategy initial/final
  files and patch;
- terminal audit, ownership table, evidence matrix, and source-review records.

First copy every otherwise-external Paper/threshold authority into a sealed
regular-file subroot:

```bash
python3 "$WT/scripts/session_ledger.py" verify \
  --ledger="$SESSION_LEDGER" --planning="$PLANNING_COMMIT" \
  --expected-remediation-count="$EXPECTED_REMEDIATION_COUNT"
PAYLOAD_ROOT="$STRATEGY_ROOT/payload"
test ! -e "$PAYLOAD_ROOT"
mkdir "$PAYLOAD_ROOT"
LEDGER_SNAPSHOT="$PAYLOAD_ROOT/session-ledger.final.tsv"
cp "$SESSION_LEDGER" "$LEDGER_SNAPSHOT"
chmod a-w "$LEDGER_SNAPSHOT"
shasum -a 256 "$LEDGER_SNAPSHOT" > "$LEDGER_SNAPSHOT.sha256"

SEALED_ROOT="$PAYLOAD_ROOT/sealed"
test ! -e "$SEALED_ROOT"
mkdir "$SEALED_ROOT"
cp "$GLOBAL_BASELINE"/paper-status.z \
   "$GLOBAL_BASELINE"/paper.inventory.z \
   "$GLOBAL_BASELINE"/ResponseStrategy.md \
   "$GLOBAL_BASELINE"/threshold-branch.txt \
   "$GLOBAL_BASELINE"/threshold-head.txt \
   "$GLOBAL_BASELINE"/threshold-status.z \
   "$GLOBAL_BASELINE"/threshold.inventory.z \
   "$SEALED_ROOT/"
cp "$STRATEGY_ROOT"/ResponseStrategy.initial.md \
   "$STRATEGY_ROOT"/ResponseStrategy.final.md \
   "$STRATEGY_ROOT"/ResponseStrategy.patch.diff \
   "$STRATEGY_ROOT"/ResponseStrategy.hashes \
   "$STRATEGY_ROOT"/paper-final.inventory.z \
   "$STRATEGY_ROOT"/paper-status-final.z \
   "$STRATEGY_ROOT"/threshold-branch-final.txt \
   "$STRATEGY_ROOT"/threshold-head-final.txt \
   "$STRATEGY_ROOT"/threshold-status-final.z \
   "$STRATEGY_ROOT"/threshold-final.inventory.z \
   "$SEALED_ROOT/"
cp "$LEDGER_SNAPSHOT" "$LEDGER_SNAPSHOT.sha256" "$SEALED_ROOT/"
chmod -R a-w "$SEALED_ROOT"
cp "$STRATEGY_ROOT"/ResponseStrategy.initial.md \
   "$STRATEGY_ROOT"/ResponseStrategy.final.md \
   "$STRATEGY_ROOT"/ResponseStrategy.patch.diff \
   "$STRATEGY_ROOT"/ResponseStrategy.hashes \
   "$PAYLOAD_ROOT/"
chmod -R a-w "$PAYLOAD_ROOT"
```

The manifest binds only this immutable per-attempt ledger snapshot, never the
live append-only `SESSION_LEDGER`. A later retry may append to the live ledger
without changing historical attempt evidence.

External artifact members are permitted only as canonical regular files
beneath `RUN_ROOT`; tracked records are addressed only as
`<commit>:<tracked-path>` plus Git blob SHA. Reject a missing, duplicate,
outside-root, mutable-symlink, or unhashed member.
Copy the final current audit/matrix files into `EVIDENCE_WT`, force-add the
final manifest, and commit only those evidence updates:

```bash
EVIDENCE_PARENT_COMMIT="${PREVIOUS_STRATEGY_REVIEW_COMMIT:-$SOURCE_REVIEW_COMMIT}"
test "$(git -C "$EVIDENCE_WT" rev-parse HEAD)" = "$EVIDENCE_PARENT_COMMIT"
git -C "$EVIDENCE_WT" add -f \
  audits/pre-threshold-final-audit.md \
  audits/pre-threshold-evidence-matrix.md \
  audits/pre-threshold-final-evidence-manifest.json
git -C "$EVIDENCE_WT" diff --cached --quiet && exit 1
git -C "$EVIDENCE_WT" commit -m \
  "test: seal final pre-threshold evidence bundle"
FINAL_EVIDENCE_COMMIT="$(git -C "$EVIDENCE_WT" rev-parse HEAD)"
test "$(git -C "$EVIDENCE_WT" rev-parse "$FINAL_EVIDENCE_COMMIT^")" = \
     "$EVIDENCE_PARENT_COMMIT"
REVIEW_PAYLOAD_ROOT="$STRATEGY_ROOT/review-payload"
test ! -e "$REVIEW_PAYLOAD_ROOT"
mkdir "$REVIEW_PAYLOAD_ROOT"
git -C "$EVIDENCE_WT" show \
  "$FINAL_EVIDENCE_COMMIT:audits/pre-threshold-final-evidence-manifest.json" \
  > "$REVIEW_PAYLOAD_ROOT/final-evidence-manifest.json"
shasum -a 256 "$REVIEW_PAYLOAD_ROOT/final-evidence-manifest.json" \
  > "$REVIEW_PAYLOAD_ROOT/final-evidence-manifest.sha256"
{
  printf '%s\n' "$SOURCE_COMMIT" "$ARTIFACT_COMMIT" \
    "$SOURCE_REVIEW_COMMIT" "$FINAL_EVIDENCE_COMMIT"
  cat "$REVIEW_PAYLOAD_ROOT/final-evidence-manifest.sha256" \
    "$RUN_ROOT/source.patch.sha256" \
    "$PAYLOAD_ROOT/ResponseStrategy.hashes"
} > "$REVIEW_PAYLOAD_ROOT/final-evidence-bundle.binding"
shasum -a 256 "$REVIEW_PAYLOAD_ROOT/final-evidence-bundle.binding" \
  > "$REVIEW_PAYLOAD_ROOT/final-evidence-bundle.sha256"
chmod -R a-w "$REVIEW_PAYLOAD_ROOT"
```

Finally, independent GPT/Fable records
`final-strategy-{gpt,fable}.md` bind final source/artifact commits, evidence
manifest SHA, initial/final ResponseStrategy SHA, and patch SHA. Both also
bind `SOURCE_REVIEW_COMMIT`, `FINAL_EVIDENCE_COMMIT`,
the attempt-specific
`$REVIEW_PAYLOAD_ROOT/final-evidence-bundle.sha256`, canonical model, and one terminal verdict;
both review factuality and scope independently. A rejection uses the same
global cycle counter.

After both verdicts exist, copy the read-only records into the attempt's new
`review-outcome/`. Its `verdict.tsv` has exact two-column keys
`schema_version=piccard-strategy-verdict-v1`, `strategy_sequence`,
`remediation_count`, `gpt_record_sha256`, `secondary_record_sha256`,
`gpt_verdict`, `secondary_verdict`, and
`combined_verdict=APPROVE|REJECT`. Update
`audits/pre-threshold-final-audit.md` with both actual verdicts and either the
next trigger or terminal unresolved state, and generate an outcome manifest
at tracked path
`audits/reviews/final-strategy-outcome.json`. It is canonical sorted-key JSON
with schema, strategy sequence/remediation count, `FINAL_EVIDENCE_COMMIT`,
review-payload bundle SHA, both record paths/hashes/verdicts, verdict-TSV hash,
final-audit blob SHA, and combined verdict; unknown/missing keys fail. Then
force-add exactly those records, that outcome manifest, and the
updated audit in `EVIDENCE_WT` and commit them as
`STRATEGY_REVIEW_COMMIT`, whose parent is `FINAL_EVIDENCE_COMMIT`. This commit
exists for APPROVE and REJECT alike, so a rejection at remediation count two
is causally recorded without needing a nonexistent third cycle. Only after
that commit is the full attempt root made read-only.

If both approve, `STRATEGY_REVIEW_COMMIT` is `FINAL_AUDIT_COMMIT`. If either
rejects and count is below two, retain the rejection commit and pass it as
`PREVIOUS_STRATEGY_REVIEW_COMMIT`; the next retry seal is its child. The final
validator checks that each outcome's referenced audit/manifest blobs at
`FINAL_EVIDENCE_COMMIT` are exactly the reviewed bytes and that the child
audit records the resulting verdict. No rejected record can be renamed or
reused as approval.
The product branch remains at the reviewed `SOURCE_COMMIT`.

## Terminal pass condition

Ready for a separate threshold branch only when:

- all Works and final source/strategy records are valid `APPROVE`;
- final verification was run against the final source with fresh builds;
- no non-threshold blocker remains and remediation count is at most two;
- Paper and threshold inventories satisfy the exact invariants;
- actual required datasets are verified (otherwise
  `BLOCKED_DATA_PENDING`);
- ResponseStrategy claims trace to committed source and hashed artifacts.
