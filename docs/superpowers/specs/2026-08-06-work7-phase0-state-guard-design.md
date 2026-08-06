# Work 7 Phase 0 — State Guard and Session Identity

## Purpose

Freeze all in-scope and read-only repository state before Work 7 generates
evidence. This phase prevents a dirty Paper baseline or a moving threshold
worktree from being confused with Work 7 output.

## Inputs

- pre-threshold source worktree path;
- Paper worktree path;
- threshold FP/FN worktree path; and
- destination evidence root.

## Output contract

The phase emits a canonical JSON state record containing, for each worktree:

- absolute resolved path;
- current branch or detached-HEAD marker;
- full commit SHA;
- porcelain-v1 status including untracked files; and
- SHA-256 digest of the canonical state fields.

It also emits a session identifier derived from the pre-threshold source
commit. An existing destination with the same identifier is never overwritten.

## Success conditions

1. The source branch is `tkde-major/pre-threshold-poc` at the expected commit
   and is clean before runtime evidence generation.
2. All three worktrees are readable Git worktrees.
3. Paper and threshold status, including existing dirt, is recorded without
   modification.
4. Recomputing the state record produces the same canonical digest.
5. The selected session destination does not already exist.

## Failure conditions

- A path is missing, unreadable, or not a Git worktree.
- The source tree is dirty at the start of an authoritative run.
- A branch or commit differs from the configured expectation.
- A session path collision occurs.
- Canonicalization is nondeterministic.
- Paper or threshold state changes between the initial and final guard check.

## Prohibited behavior

- No checkout, reset, clean, stash, add, commit, format, or file write may be
  performed in Paper or threshold.
- The implementation may not exclude untracked Paper files from the fingerprint.
- The implementation may not delete an old session to make a rerun pass.

## Verification

Unit fixtures cover clean, dirty, malformed, and collision states. An
integration test records the real three-worktree baseline, reruns the guard,
and proves that the two external fingerprints did not change.
