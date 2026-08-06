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
- index entry modes/object IDs/stages;
- framed path, mode, type, byte digest, and symlink target for every tracked
  and untracked worktree entry;
- submodule commit and recursively reported status; and
- SHA-256 digest of the canonical byte-level snapshot.

It also emits a session identifier derived from the pre-threshold source
commit and seals the Phase 0 record. An existing destination with the same
identifier is never overwritten. Evidence and build roots must resolve outside
all guarded worktrees and must not alias one through a symlink.

## Success conditions

1. The source branch is `tkde-major/pre-threshold-poc` at the expected commit
   and is clean before runtime evidence generation.
2. All three worktrees are readable Git worktrees.
3. Paper and threshold status, including existing dirt, is recorded without
   modification.
4. Recomputing every byte-level snapshot produces the same canonical digest.
5. Changing bytes in an already-dirty tracked or untracked file changes the
   digest even when porcelain status text does not change.
6. The selected session destination does not already exist and neither output
   root is contained in or aliases a guarded worktree.

## Failure conditions

- A path is missing, unreadable, or not a Git worktree.
- The source tree is dirty at the start of an authoritative run.
- A branch or commit differs from the configured expectation.
- A session path collision occurs.
- An evidence/build path is within or aliases a guarded worktree.
- Canonicalization is nondeterministic.
- Paper or threshold state changes between the initial and final guard check.

## Prohibited behavior

- No checkout, reset, clean, stash, add, commit, format, or file write may be
  performed in Paper or threshold.
- The implementation may not exclude untracked Paper files, modes, symlinks,
  index state, or submodules from the snapshot.
- The implementation may not delete an old session to make a rerun pass.

## Verification

Unit fixtures cover clean, dirty, byte mutation with unchanged status shape,
untracked files, executable modes, symlinks, submodules, containment/aliasing,
malformed input, and collision states. An integration test records the real
three-worktree baseline, reruns the guard after every external read, and proves
that the two external snapshots did not change.
