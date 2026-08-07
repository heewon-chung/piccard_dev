#!/usr/bin/env python3
"""Fail-closed Phase 0 CLI for freezing Work 7 worktree state."""

import argparse
import os
import sys
from pathlib import Path

from work7_evidence import (assert_output_roots_outside, canonical_json_bytes,
                            snapshot_git_worktree, _atomic_create,
                            _reject_symlink_components)


class _FailureParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(f"invalid arguments: {message}")


def _parser() -> argparse.ArgumentParser:
    parser = _FailureParser(add_help=False)
    for name in ("source-root", "paper-root", "threshold-root", "build-root", "session-root", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--expected-source-branch", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    return parser


def _source_is_clean(source: Path) -> bool:
    import subprocess
    result = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                            cwd=source, check=False, capture_output=True,
                            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    if result.returncode != 0:
        raise ValueError("cannot determine source worktree status")
    return not result.stdout


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        path_arguments = (args.source_root, args.paper_root, args.threshold_root,
                          args.build_root, args.session_root, args.output)
        if any(not path.is_absolute() for path in path_arguments):
            raise ValueError("all path arguments must be absolute")
        for path in path_arguments:
            _reject_symlink_components(path)
        source, paper, threshold, build = (args.source_root.resolve(strict=True),
                                            args.paper_root.resolve(strict=True),
                                            args.threshold_root.resolve(strict=True),
                                            args.build_root.resolve(strict=True))
        assert_output_roots_outside([source, paper, threshold], [build, args.session_root])
        assert_output_roots_outside([source, paper, threshold], [args.output])
        output = args.output.resolve(strict=False)
        try:
            output.relative_to(args.session_root.resolve(strict=False))
        except ValueError:
            raise ValueError("output must be inside session root") from None
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"output already exists: {output}")
        source_snapshot = snapshot_git_worktree(source)
        if source_snapshot["branch"] != args.expected_source_branch:
            raise ValueError("source branch does not match expected branch")
        if source_snapshot["head"] != args.expected_source_commit:
            raise ValueError("source commit does not match expected commit")
        if not _source_is_clean(source):
            raise ValueError("source worktree is dirty")
        state = {"schema": "piccard-work7-phase0-state-v2", "source": source_snapshot,
                 "paper": snapshot_git_worktree(paper),
                 "threshold": snapshot_git_worktree(threshold),
                 "build": {"root": str(build)},
                 "session_id": f"work7-{source_snapshot['head']}"}
        _atomic_create(output, canonical_json_bytes(state))
    except (ValueError, FileExistsError, OSError) as error:
        print(f"work7_state_guard: FAIL: {error}", file=sys.stderr)
        return 2
    print("work7_state_guard: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
