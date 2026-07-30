#!/usr/bin/env python3
"""Real-subprocess tests for scripts/verify_work_approval.py.

Every case drives the actual script with the real ``python3`` interpreter
against a real temporary Git repository built by real ``git`` commands. Nothing
is mocked and no assertion inspects the verifier's source text, because the
point of this gate is that the approval records genuinely bind to commits,
diffs, and plan blobs that Git itself confirms.

Two properties every negative case must prove, not merely imply:

* the pristine control pair is accepted under the same invocation, so a
  rejection cannot come from a broken or absent verifier; and
* the rejection is *the intended one* -- the diagnostic carries the verifier's
  own prefix and names the expected cause. ``assert_rejects`` therefore takes a
  mandatory cause substring, and argparse-level rejections use a separate
  helper with its own exit code and shape.

The shared fixture repository has this history (``P`` is the expected base):

    A0 --- P --- H            H changes src/a.txt, plan blob untouched
            \\--- E            empty commit: real child, empty diff
            \\--- C            changes the plan blob itself
      \\---------- S           side branch: not a descendant of P

Two further fixture repositories exist because the byte contract needs ranges
that a *wrong* diff invocation would visibly mangle:

``semantics``
    one base with three heads -- a pure rename, a change whose hunk layout is
    decided by the default indent heuristic, and a mixed head carrying a mode
    change, a retargeted symlink, a deletion, a binary rewrite, and a gitlink.
``attrs``
    a base-committed ``.gitattributes`` that selects a *named* diff driver and
    marks another path binary, so hostile ``diff.<driver>.*`` configuration has
    something to attach to.
``bulk``
    built on first use, not in ``setUpClass``, because it costs real disk: a
    24 MiB plan blob and a wholesale rewrite of a 16 MiB incompressible file, so
    the diff and the plan blob are each far larger than any memory the verifier
    may use to hash them.

For those repositories the expected bytes are never taken from the verifier.
They are produced by ``_reference_diff_bytes``, which runs the brief's own
``git diff --binary --full-index base..head`` in a pristine copy under empty
global and system configuration *and* with the system and global gitattributes
stacks switched off -- the definition ``diff_sha256`` must satisfy.

Almost every case drives the script itself in a subprocess. Two do not:
``test_verifier_script_is_executable_python`` asserts a file mode and so has
nothing to invoke, and ``test_cmake_requires_python3_when_tests_are_enabled``
configures the real project with CMake to check that the gate is registered
rather than skipped.

Three cases act on the verifier *while* it runs, and each does so through a real
rendezvous with a PATH shim rather than a sleep-and-hope:

``sleeping_git_shim``
    hangs inside a git call, with a background child of its own, so a signal can
    be delivered while a git process group and an isolated view really exist.
``rendezvous_git_shim``
    pauses one git call until the test has finished rewriting a record through a
    descriptor it retained from before the ``chmod``, then delegates to the real
    git so the verification runs to completion.
``mutating_git_shim``
    performs one filesystem mutation mid-run for the cases the shim can do alone.

Run:
    python3 -m unittest tests.scripts.test_verify_work_approval -v
"""

import glob
import hashlib
import os
import random
import shlex
import shutil
import signal
import subprocess
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "scripts" / "verify_work_approval.py"

PLAN_PATH = "docs/superpowers/plans/work-1.md"
PLAN_SYMLINK_PATH = "docs/superpowers/plans/work-1-link.md"
PLAN_TEXT = "# Work 1 plan\n\nApproval-record verifier fixture plan.\n"

DIAG_PREFIX = "verify_work_approval: "

FIELD_ORDER = (
    "work_id",
    "base_commit",
    "head_commit",
    "plan_blob_sha256",
    "diff_sha256",
    "reviewer_model",
    "reviewer_instance_id",
    "fallback_reason",
    "fallback_evidence_path",
    "fallback_evidence_sha256",
    "verdict",
)

# The Work-final pair is fixed and ordered: GPT is primary, Claude Opus is the
# independent cross-check. Per-phase GPT review is a separate checkpoint.
PRIMARY_MODEL = "gpt-5.6-sol"
SECONDARY_MODEL = "claude-opus-5"
PRIMARY_INSTANCE = "gpt-5.6-sol-review-a1"
SECONDARY_INSTANCE = "claude-opus-5-review-b2"

# Exact per-slot matching rejects the other slot's model, the retired Fable
# contract, and near-misses that would expose prefix or case-insensitive checks.
REJECTED_PRIMARY_MODELS = (
    "claude-opus-5",
    "claude-fable-5",
    "gpt-5.6-sol-mini",
    "GPT-5.6-SOL",
)
REJECTED_SECONDARY_MODELS = (
    "gpt-5.6-sol",
    "claude-fable-5",
    "claude-opus-5-mini",
    "CLAUDE-OPUS-5",
)

_OMIT = object()

_HEX40 = "0123456789abcdef" * 2 + "01234567"
assert len(_HEX40) == 40

# Every knob that could make `git diff` emit different bytes for the same two
# commits. The verifier must produce byte-identical output with all of these
# hostile, whether they arrive from global or from repository configuration.
HOSTILE_DIFF_CONFIG = """\
[diff]
\tnoprefix = true
\tmnemonicPrefix = true
\texternal = "sh -c 'echo HOSTILE-EXTERNAL-DIFF'"
\tsrcPrefix = HOSTILE_SRC/
\tdstPrefix = HOSTILE_DST/
\talgorithm = histogram
\tindentHeuristic = true
\trenames = copies
\tcontext = 9
\tinterHunkContext = 5
\tsuppressBlankEmpty = true
\twsErrorHighlight = all
\tcolorMoved = zebra
\trelative = true
\tsubmodule = log
\torderFile = {order_file}
[color]
\tui = always
\tdiff = always
[core]
\tabbrev = 8
\tquotePath = false
\tbigFileThreshold = 1
"""

FORCED_COLOR_CONFIG = "[color]\n\tui = always\n\tdiff = always\n"

# Attributes that turn a text file into a binary patch and route another
# through a textconv filter. Left *uncommitted* in the worktree on purpose: the
# fingerprint is defined over the base commit's attributes, so a worktree file
# must not move the bytes.
HOSTILE_GITATTRIBUTES = "*.txt -diff\n*.md diff=hostile\n"

# Base-committed attributes for the `attrs` fixture: one path routed through a
# *named* driver, one marked binary. Identical at base and head, so the brief's
# literal command (worktree at head) and an attributes source pinned to the base
# tree are the same thing for this fixture.
ATTRS_GITATTRIBUTES = "*.txt diff=weird\n*.dat -diff\n"

# Everything a named diff driver can do to the emitted bytes: force a binary
# patch, rewrite hunk headers, or replace the diff entirely.
NAMED_DRIVER_CONFIG = (
    '[diff "weird"]\n'
    "\tbinary = true\n"
    '\txfuncname = "^HOSTILE"\n'
    "\ttextconv = \"sh -c 'echo HOSTILE-TEXTCONV'\"\n"
    "\tcommand = \"sh -c 'echo HOSTILE-DRIVER-COMMAND'\"\n"
    "\tcachetextconv = true\n"
)

# Rename fixture: seven of eight lines survive, so default rename detection
# reports one `similarity index` rename instead of an add/delete pair.
RENAME_BASE = "".join(f"l{index}\n" for index in range(1, 9))
RENAME_HEAD = RENAME_BASE.replace("l4\n", "CHANGED\n")

# Hunk-layout fixture: inserting a whole brace block is exactly the case the
# default indent heuristic shifts, so `--no-indent-heuristic` emits a different
# hunk header for the same content.
LAYOUT_BASE = "{\n  a();\n}\n\n{\n  b();\n}\n\npad1\npad2\npad3\npad4\npad5\n"
LAYOUT_HEAD = LAYOUT_BASE.replace("{\n  b();\n}\n", "{\n  x();\n}\n\n{\n  b();\n}\n")

# The verifier's own floor, restated here so the guard is pinned by the test
# suite and not only by the implementation. GIT_ATTR_SOURCE -- the mechanism the
# isolated view uses to pin the gitattributes stack to the base commit -- is
# documented from git 2.41 onwards and does not exist in 2.40, where it is
# silently ignored like any other unknown environment variable.
MIN_GIT_VERSION_TEXT = "2.41.0"

# Every 2.40.x response must be refused for that reason, not merely refused.
# `2.40` is included because a two-component response is a real shape (some
# vendors ship one) and must not sneak under the floor.
REFUSED_GIT_VERSIONS = ("2.40.0", "2.40.4", "2.40")

# Vendor and build suffixes that real `git --version` output carries. Apple ships
# the parenthesised form, Git for Windows the `.windows.N` tail, and a git built
# from a tagged checkout the `describe` tail. Strict parsing must not lock any of
# them out.
ACCEPTED_GIT_VERSION_SHAPES = (
    "git version 2.41.0.windows.1",
    "git version 2.41.1.83.gc57b6d9c1e",
)

# Trailing text that is *not* a documented shape. Each of these carries a
# perfectly good version followed by something the verifier has no business
# accepting, so a prefix match would wave them through.
REFUSED_GIT_VERSION_TAILS = (
    "git version 2.41.0 HACKED",
    "git version 2.41.0-not-a-real-git",
    "git version 2.41.0 (Apple Git-999) and then some",
)

# Malformed *vendor* shapes: the tail is where the documented forms live, so it
# is where a loose grammar hides. No real git prints a doubled or dangling dot
# separator, and no real git prints a note with nothing in it. A tail grammar
# that accepts these is one that accepts arbitrary punctuation after the version
# it claims to have parsed -- exactly the prefix-parsing weakness the anchors
# were added to close, moved one character to the right.
#
REFUSED_GIT_VERSION_SHAPES = (
    "git version 2.41.0..windows.1",
    "git version 2.41.0.windows..1",
    "git version 2.41.0.windows.",
    "git version 2.41.0.",
    "git version 2.41.0 ()",
    "git version 2.41.0 (   )",
)

# Far past CPython's 4300-digit int/str conversion limit, so a verifier that
# calls int() on unbounded input raises ValueError instead of diagnosing.
HUGE_DIGITS = "9" * 5000
HUGE_ZEROS = "0" * 5000

# A diagnostic is only "concise" if it is bounded, not merely single-line: a
# one-line 5 kB echo of hostile input is not a diagnostic.
MAX_DIAGNOSTIC_BYTES = 400

# The verifier's documented practical ceilings, restated here so the suite pins
# them independently of the implementation. A canonical record is under 700
# bytes, so 8 KiB is more than ten times the largest legitimate one; the longest
# example instance id in the module docstring is 40 characters.
MAX_RECORD_BYTES = 8192
MAX_INSTANCE_ID_CHARS = 128

# The ceiling on what a *short* git command may say. `rev-parse`, `ls-tree` on
# one literal path, `merge-base` and `--version` all answer in well under a
# line, so 64 KiB is generous; the point is that the answer's size is decided
# here and not by whatever binary is first on PATH.
MAX_GIT_STDOUT_BYTES = 65536

# How much of a git child's stderr is retained for a diagnostic. Everything past
# it is drained and dropped, so a talkative git costs a bounded prefix and never
# a temporary file.
MAX_GIT_STDERR_BYTES = 4096

# A flood, in mebibytes, for a git shim to emit on stdout *and* stderr at once:
# far more than either ceiling, and far more than any diagnostic or buffer the
# verifier may pay for. Sized to dwarf the memory allowance below while staying
# quick to generate through a pipe.
GIT_FLOOD_MIB = 64

# How much peak memory a flooded run may cost above an ordinary one. Measured as
# a difference between two runs of the same launcher, exactly like the bulk
# fixture, so interpreter startup cancels out. A verifier that buffers either
# flooded channel pays 64 MiB and misses this by a factor of four.
MAX_FLOOD_PEAK_GROWTH_BYTES = 16 << 20

# The largest file a verification is allowed to write, enforced with
# ``RLIMIT_FSIZE``. The isolated view's four files are a few hundred bytes
# between them, so this is enormous for legitimate use and far too small for a
# spooled copy of a flooded stderr.
MAX_SPOOL_FILE_BYTES = 1 << 20

# Hostile CLI values: six figures of attacker-chosen text in a single option.
# Every one of these reaches a diagnostic through string interpolation, so an
# unclipped one turns a "concise diagnostic" into a 100 kB stderr.
HUGE_CLI_CHARS = 100_000

# argparse prints its own usage block before the error line, so a CLI-level
# diagnostic is legitimately longer than a verification one -- but still
# kilobytes short of echoing a 100 000-character value.
MAX_CLI_DIAGNOSTIC_BYTES = 1024

# Signals a build system or an impatient operator actually sends. Both must
# leave nothing behind: no git child, no process group, no isolated view.
TERMINATION_SIGNALS = ("SIGTERM", "SIGINT")

# How long a real rendezvous may take before the test gives up on it. Generous,
# because a cold CI machine builds the isolated view slowly, but finite: a
# rendezvous that never happens must fail the suite rather than hang it.
RENDEZVOUS_TIMEOUT = 60

# Hostile record sizes: megabytes, so a verifier that reads before it validates
# has already allocated them by the time it could object.
OVERSIZE_RECORD_BYTES = 4 << 20

# The bounded-memory fixture. Both figures are random bytes, so nothing about
# them compresses away: the binary patch for `data.bin` is tens of megabytes and
# the plan blob is megabytes on its own, which makes the *blob* stream as much a
# subject of the test as the diff stream.
BULK_PLAN_BYTES = 24 << 20
BULK_DATA_BYTES = 16 << 20

# How much *more* peak memory the large range may cost than the ordinary
# fixture. Measured as a difference between two runs of the same launcher, so
# interpreter startup, imports and the git child processes -- which dominate the
# absolute figure and vary by machine -- cancel out, and what remains is the cost
# of hashing 40-odd megabytes instead of a few hundred bytes. Streaming costs a
# chunk buffer or two; buffering costs the length of what was buffered.
MAX_BULK_PEAK_GROWTH_BYTES = 8 << 20

# A launcher that runs the real verifier and reports its own peak RSS around the
# run. `resource` measures this process only -- git is a child -- so a git that
# buffers a binary patch internally cannot mask a verifier that does. Nothing is
# mocked: `runpy` executes the real file as `__main__` against the real git.
MEMORY_LAUNCHER_SOURCE = '''\
import pathlib
import resource
import runpy
import sys

VERIFIER = {verifier}


def peak():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Darwin reports bytes; Linux reports kilobytes.
    return value if sys.platform == "darwin" else value * 1024


report = pathlib.Path(sys.argv[1])
sys.argv = [VERIFIER, *sys.argv[2:]]
before = peak()
status = 0
try:
    runpy.run_path(VERIFIER, run_name="__main__")
except SystemExit as exc:
    status = 0 if exc.code is None else exc.code
report.write_text("{{}} {{}}".format(before, peak()))
sys.exit(status)
'''

REAL_GIT = shutil.which("git")
assert REAL_GIT, "git must be on PATH to run these tests"

# Unlike git, CMake is not required to exercise the verifier itself -- only the
# one case that checks how the gate is registered, which skips without it.
CMAKE = shutil.which("cmake")
CTEST = shutil.which("ctest")

# Generous for a cold CI machine, but finite: no verifier invocation in this
# suite has any business running longer, so a hang is a failure.
INVOKE_TIMEOUT = 90


def _git_env():
    """Isolate the fixture repository from the developer's Git configuration."""
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_AUTHOR_NAME": "Phase Zero",
            "GIT_AUTHOR_EMAIL": "phase0@example.invalid",
            "GIT_COMMITTER_NAME": "Phase Zero",
            "GIT_COMMITTER_EMAIL": "phase0@example.invalid",
            "GIT_AUTHOR_DATE": "2026-07-29T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-07-29T00:00:00Z",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    return env


def _git(repo, *args, capture_bytes=False, stdin=None):
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        env=_git_env(),
        check=True,
    )
    return proc.stdout if capture_bytes else proc.stdout.decode().strip()


def _reference_diff_bytes(repo, base, head, *extra):
    """The required bytes, from the brief's command under clean configuration.

    This is the definition ``diff_sha256`` has to satisfy, and the verifier is
    never consulted to produce it: plain ``git diff --binary --full-index
    base..head`` in a *pristine* repository (no local configuration, no
    ``$GIT_DIR/info/attributes``, no replace refs) with global and system
    configuration emptied. No option that changes default behaviour is passed,
    so rename detection, the indent heuristic, the myers algorithm, three lines
    of context and the ``a/``/``b/`` prefixes are all Git's own defaults.

    Configuration is not the only ambient input. The system attributes file and
    ``core.attributesFile`` (which falls back to
    ``$XDG_CONFIG_HOME/git/attributes`` when unset) can both change these bytes
    on their own, so they are switched off explicitly. Otherwise a developer or
    CI image carrying a global attributes file would move the yardstick rather
    than the verifier, and the comparison would prove nothing.

    ``extra`` exists only for the negative direction: passing
    ``--no-renames`` or ``--no-indent-heuristic`` produces the bytes a verifier
    forcing non-default semantics would have hashed, which must be *rejected*.
    """
    proc = subprocess.run(
        _reference_diff_argv(repo, base, head, extra),
        capture_output=True,
        env=_reference_diff_env(),
        check=True,
    )
    return proc.stdout


def _reference_diff_env():
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def _reference_diff_argv(repo, base, head, extra=()):
    return [
        "git",
        "-C",
        str(repo),
        "--no-pager",
        "-c",
        f"core.attributesFile={os.devnull}",
        "diff",
        *extra,
        "--binary",
        "--full-index",
        f"{base}..{head}",
    ]


def _stream_sha256(argv, env):
    """SHA-256 and length of a command's stdout, without buffering it.

    Used for the bounded-memory fixture: a test that held tens of megabytes in
    order to check that the verifier does not would be measuring the wrong
    process, and would make its own launcher the memory hog.
    """
    digest = hashlib.sha256()
    size = 0
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, env=env)
    with proc:
        while True:
            chunk = proc.stdout.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    assert proc.returncode == 0, f"{argv[:4]} exited {proc.returncode}"
    return digest.hexdigest(), size


def _reference_diff_digest(repo, base, head):
    """The required diff bytes, hashed by streaming rather than buffering."""
    return _stream_sha256(_reference_diff_argv(repo, base, head), _reference_diff_env())


def _blob_digest(repo, revision_path):
    """A tracked blob's exact bytes, hashed by streaming rather than buffering."""
    blob = _git(repo, "rev-parse", revision_path)
    return _stream_sha256(
        ["git", "-C", str(repo), "cat-file", "blob", blob], _git_env()
    )


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _write_readonly(path, data, mode=0o444):
    path = Path(path)
    if path.exists():
        os.chmod(path, 0o644)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    os.chmod(path, mode)


def _render(fields, order=FIELD_ORDER):
    """Render a record. An empty value emits a bare ``key:`` line."""
    lines = []
    for key in order:
        value = fields[key]
        lines.append(f"{key}: {value}" if value != "" else f"{key}:")
    return "".join(line + "\n" for line in lines)


def _wait_for(predicate, timeout, description):
    """Poll a real condition rather than sleeping and hoping.

    Returns the deadline outcome so the caller can turn it into an assertion:
    every rendezvous in this suite is between real processes, so it can be
    waited for, and a rendezvous that never arrives must fail rather than hang.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _process_is_gone(pid):
    """True once `pid` no longer names a live process.

    A killed grandchild is briefly a zombie -- its parent died with it, so the
    reaping is up to init -- and a zombie still answers ``kill(pid, 0)``. The
    process state is therefore consulted directly, which is also what makes this
    honest: "gone" means gone, not merely "not responding".
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    state = subprocess.run(
        ["ps", "-o", "state=", "-p", str(pid)], capture_output=True
    ).stdout.decode(errors="replace").strip()
    return state == "" or state.startswith("Z")


class VerifyWorkApprovalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = Path(tempfile.mkdtemp(prefix="verify-work-approval-"))
        cls.repo = cls.workspace / "repo"
        cls.repo.mkdir()
        repo = cls.repo

        _git(repo, "init", "-q", "-b", "main")

        (repo / "src").mkdir()
        (repo / "src" / "a.txt").write_text("a0\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "root")
        cls.commit_root = _git(repo, "rev-parse", "HEAD")

        plan_file = repo / PLAN_PATH
        plan_file.parent.mkdir(parents=True)
        plan_file.write_text(PLAN_TEXT)
        os.symlink("work-1.md", repo / PLAN_SYMLINK_PATH)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "plan")
        cls.commit_base = _git(repo, "rev-parse", "HEAD")

        # Several changed lines with shared context, so a different diff
        # algorithm or context width really does change the emitted bytes.
        (repo / "src" / "a.txt").write_text("head\nb\nc\nd\ne\nf\ng\nh\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "work")
        cls.commit_head = _git(repo, "rev-parse", "HEAD")

        _git(repo, "checkout", "-q", cls.commit_base)
        _git(repo, "commit", "-q", "--allow-empty", "-m", "empty")
        cls.commit_empty = _git(repo, "rev-parse", "HEAD")

        _git(repo, "checkout", "-q", cls.commit_base)
        plan_file.write_text(PLAN_TEXT + "\nEdited by the Work itself.\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "plan-changed")
        cls.commit_plan_changed = _git(repo, "rev-parse", "HEAD")

        _git(repo, "checkout", "-q", cls.commit_root)
        (repo / "side.txt").write_text("side\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "side")
        cls.commit_side = _git(repo, "rev-parse", "HEAD")

        _git(repo, "checkout", "-q", cls.commit_head)

        cls.plan_blob_git_sha = _git(repo, "rev-parse", f"{cls.commit_base}:{PLAN_PATH}")
        cls.plan_blob_sha = _sha256_hex(
            _git(repo, "cat-file", "blob", cls.plan_blob_git_sha, capture_bytes=True)
        )
        cls.diff_sha = cls._diff_sha(cls.commit_base, cls.commit_head)
        cls.diff_sha_empty = cls._diff_sha(cls.commit_base, cls.commit_empty)
        cls.diff_sha_plan_changed = cls._diff_sha(
            cls.commit_base, cls.commit_plan_changed
        )
        cls.diff_sha_side = cls._diff_sha(cls.commit_base, cls.commit_side)
        cls.diff_sha_root_head = cls._diff_sha(cls.commit_root, cls.commit_head)

        cls._build_semantics_repo()
        cls._build_attrs_repo()

    # ------------------------------------------------------- extra fixtures

    @classmethod
    def _build_semantics_repo(cls):
        """One base, three heads, each mangled by a wrong diff invocation.

        ``head_rename`` is a pure rename, so it disappears into an add/delete
        pair under ``--no-renames``. ``head_layout`` inserts a brace block, so
        its hunk header moves under ``--no-indent-heuristic``. ``head_mixed``
        carries a mode change, a retargeted symlink, a deletion, a binary
        rewrite and a new gitlink, so `--binary --full-index` and the default
        submodule format are exercised on real Git data.
        """
        repo = cls.workspace / "semantics"
        repo.mkdir()
        cls.sem_repo = repo
        _git(repo, "init", "-q", "-b", "main")

        plan = repo / PLAN_PATH
        plan.parent.mkdir(parents=True)
        plan.write_text(PLAN_TEXT)
        (repo / "src").mkdir()
        (repo / "src" / "rename_me.txt").write_text(RENAME_BASE)
        (repo / "src" / "mode.sh").write_text("#!/bin/sh\necho hello\n")
        (repo / "src" / "deleted.txt").write_text("gone\n")
        os.symlink("rename_me.txt", repo / "src" / "link")
        (repo / "src" / "bin.bin").write_bytes(b"a\x00b\x00c\n")
        (repo / "layout.txt").write_text(LAYOUT_BASE)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "semantics base")
        cls.sem_base = _git(repo, "rev-parse", "HEAD")

        _git(repo, "mv", "src/rename_me.txt", "src/renamed.txt")
        (repo / "src" / "renamed.txt").write_text(RENAME_HEAD)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "rename")
        cls.sem_head_rename = _git(repo, "rev-parse", "HEAD")

        _git(repo, "checkout", "-q", cls.sem_base)
        (repo / "layout.txt").write_text(LAYOUT_HEAD)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "layout")
        cls.sem_head_layout = _git(repo, "rev-parse", "HEAD")

        _git(repo, "checkout", "-q", cls.sem_base)
        os.chmod(repo / "src" / "mode.sh", 0o755)
        (repo / "src" / "deleted.txt").unlink()
        (repo / "src" / "link").unlink()
        os.symlink("bin.bin", repo / "src" / "link")
        (repo / "src" / "bin.bin").write_bytes(b"a\x00b\x00Z\n")
        _git(repo, "add", "-A")
        # A gitlink cannot be produced from a worktree directory, so it is
        # written straight into the index. Added only at this head, so the two
        # other ranges stay free of submodule entries.
        _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},sub")
        _git(repo, "commit", "-qm", "mixed")
        cls.sem_head_mixed = _git(repo, "rev-parse", "HEAD")

        cls.sem_plan_sha = _sha256_hex(
            _git(
                repo,
                "cat-file",
                "blob",
                _git(repo, "rev-parse", f"{cls.sem_base}:{PLAN_PATH}"),
                capture_bytes=True,
            )
        )

    @classmethod
    def _build_attrs_repo(cls):
        """A base-committed ``.gitattributes`` that selects a named driver.

        The attributes are byte-identical at base and head, so the brief's
        literal command run against the head worktree and an attributes source
        pinned to the base tree agree by construction -- which is what makes
        ``_reference_diff_bytes`` the right yardstick for this fixture.
        """
        repo = cls.workspace / "attrs"
        repo.mkdir()
        cls.attrs_repo = repo
        _git(repo, "init", "-q", "-b", "main")

        plan = repo / PLAN_PATH
        plan.parent.mkdir(parents=True)
        plan.write_text(PLAN_TEXT)
        (repo / ".gitattributes").write_text(ATTRS_GITATTRIBUTES)
        (repo / "src").mkdir()
        (repo / "src" / "a.txt").write_text(
            "int f(void)\n{\n\treturn 1;\n}\n\nl6\nl7\nl8\n"
        )
        (repo / "src" / "b.dat").write_bytes(b"binary-ish\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "attrs base")
        cls.attrs_base = _git(repo, "rev-parse", "HEAD")

        (repo / "src" / "a.txt").write_text(
            "int f(void)\n{\n\treturn 2;\n}\n\nl6\nl7\nl8\n"
        )
        (repo / "src" / "b.dat").write_bytes(b"binary-ish CHANGED\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "attrs head")
        cls.attrs_head = _git(repo, "rev-parse", "HEAD")

        assert _git(repo, "rev-parse", f"{cls.attrs_base}:.gitattributes") == _git(
            repo, "rev-parse", f"{cls.attrs_head}:.gitattributes"
        ), "the fixture's attributes must not change across the range"

        # A third commit whose attributes mark every text path binary. It is not
        # part of any verified range; it exists so a hostile GIT_ATTR_SOURCE has
        # a real tree to point at.
        (repo / ".gitattributes").write_text("*.txt -diff\n*.dat -diff\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "attrs hostile source")
        cls.attrs_hostile_source = _git(repo, "rev-parse", "HEAD")
        _git(repo, "checkout", "-q", cls.attrs_head)

        cls.attrs_plan_sha = _sha256_hex(
            _git(
                repo,
                "cat-file",
                "blob",
                _git(repo, "rev-parse", f"{cls.attrs_base}:{PLAN_PATH}"),
                capture_bytes=True,
            )
        )

    @classmethod
    def bulk_fixture(cls):
        """A range whose diff is tens of megabytes of incompressible binary patch.

        Built on first use rather than in ``setUpClass``: it costs real disk and
        real seconds, and only the bounded-memory case needs it.

        ``data.bin`` is rewritten wholesale with unrelated random bytes, so git
        emits a ``GIT binary patch`` whose base85 payload is larger than the file
        itself and cannot be delta-compressed. The plan blob is large *and*
        unchanged across the range, so the plan-blob stream is exercised too --
        by a blob the verifier must hash in full.
        """
        if getattr(cls, "_bulk", None) is None:
            repo = cls.workspace / "bulk"
            repo.mkdir()
            _git(repo, "init", "-q", "-b", "main")

            plan = repo / PLAN_PATH
            plan.parent.mkdir(parents=True)
            plan.write_bytes(random.Random(11).randbytes(BULK_PLAN_BYTES))
            (repo / "data.bin").write_bytes(random.Random(22).randbytes(BULK_DATA_BYTES))
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "bulk base")
            base = _git(repo, "rev-parse", "HEAD")

            (repo / "data.bin").write_bytes(random.Random(33).randbytes(BULK_DATA_BYTES))
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "bulk head")
            head = _git(repo, "rev-parse", "HEAD")

            diff_sha, diff_size = _reference_diff_digest(repo, base, head)
            plan_sha, plan_size = _blob_digest(repo, f"{base}:{PLAN_PATH}")
            cls._bulk = {
                "repo": repo,
                "base": base,
                "head": head,
                "diff_sha": diff_sha,
                "diff_size": diff_size,
                "plan_sha": plan_sha,
                "plan_size": plan_size,
            }
        return cls._bulk

    @classmethod
    def _diff_sha(cls, base, head):
        return _sha256_hex(
            _git(
                cls.repo,
                "diff",
                "--binary",
                "--full-index",
                f"{base}..{head}",
                capture_bytes=True,
            )
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workspace, ignore_errors=True)

    def setUp(self):
        self.staging = Path(tempfile.mkdtemp(prefix="approval-staging-"))
        self.addCleanup(shutil.rmtree, self.staging, ignore_errors=True)
        self.gpt_path = self.staging / "work-1-gpt.md"
        self.secondary_path = self.staging / "work-1-secondary.md"
        self.write_pair()
        # A pristine pair that no test mutates. Every rejection assertion also
        # checks that this control is accepted, so a negative case can never
        # pass merely because the verifier is broken or absent.
        self.control_gpt = self.staging / "control-gpt.md"
        self.control_secondary = self.staging / "control-secondary.md"
        _write_readonly(
            self.control_gpt,
            _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {})),
        )
        _write_readonly(
            self.control_secondary,
            _render(self.fields(SECONDARY_MODEL, SECONDARY_INSTANCE, {})),
        )

    # ---------------------------------------------------------------- fixtures

    def fields(self, model, instance, overrides):
        values = {
            "work_id": "1",
            "base_commit": self.commit_base,
            "head_commit": self.commit_head,
            "plan_blob_sha256": self.plan_blob_sha,
            "diff_sha256": self.diff_sha,
            "reviewer_model": model,
            "reviewer_instance_id": instance,
            "fallback_reason": "",
            "fallback_evidence_path": "",
            "fallback_evidence_sha256": "",
            "verdict": "APPROVE",
        }
        values.update(overrides)
        return values

    def write_gpt(self, mode=0o444, order=FIELD_ORDER, **overrides):
        _write_readonly(
            self.gpt_path,
            _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, overrides), order),
            mode,
        )

    def write_secondary(self, mode=0o444, order=FIELD_ORDER, **overrides):
        _write_readonly(
            self.secondary_path,
            _render(
                self.fields(SECONDARY_MODEL, SECONDARY_INSTANCE, overrides), order
            ),
            mode,
        )

    def write_pair(self, gpt=None, secondary=None, **common):
        self.write_gpt(**{**common, **(gpt or {})})
        self.write_secondary(**{**common, **(secondary or {})})

    def repo_copy(self, name, source=None):
        """An independent copy of a fixture repository, same objects.

        Used by the hostile-configuration, hostile-attributes and
        replace-object tests so that the shared class fixtures are never
        mutated.
        """
        dest = self.staging / name
        shutil.copytree(self.repo if source is None else source, dest, symlinks=True)
        return dest

    def alt_pair(self, name, base, head, plan_blob_sha256, diff_sha256):
        """A record pair bound to another repository's range."""
        overrides = {
            "base_commit": base,
            "head_commit": head,
            "plan_blob_sha256": plan_blob_sha256,
            "diff_sha256": diff_sha256,
        }
        gpt = self.staging / f"{name}-gpt.md"
        secondary = self.staging / f"{name}-secondary.md"
        _write_readonly(
            gpt, _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, overrides))
        )
        _write_readonly(
            secondary,
            _render(self.fields(SECONDARY_MODEL, SECONDARY_INSTANCE, overrides)),
        )
        return {"gpt": gpt, "secondary": secondary, "expected_base": base}

    def git_shim(self, name, version_branch):
        """A PATH shim that answers ``git --version`` and delegates the rest.

        Delegation is the point: the at-the-floor cases run the *entire*
        verification against the real ``git``, so a version guard test cannot
        pass merely because everything downstream broke.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        shim.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "--version" ]; then\n'
            f"{version_branch}\n"
            "fi\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def failing_git_shim(self, name, subcommand, stderr_text, status=128):
        """A PATH shim that fails one git subcommand loudly and delegates the rest.

        The failure carries a deliberately enormous stderr, because "concise
        diagnostic" has to survive a git that is not concise at all.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        shim.write_text(
            "#!/bin/sh\n"
            'for arg in "$@"; do\n'
            f'  if [ "$arg" = {shlex.quote(subcommand)} ]; then\n'
            f"    printf '%s' {shlex.quote(stderr_text)} >&2\n"
            f"    exit {status}\n"
            "  fi\n"
            "done\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def flooding_git_shim(self, name, subcommand, mebibytes, status=0):
        """A PATH shim that floods *both* channels of one git call at once.

        Concurrency is the point. A verifier that drains stdout while stderr
        fills its pipe -- or the reverse -- deadlocks rather than failing, so the
        two floods are started together and the shim waits for both. The volume
        is far past any ceiling the verifier documents, so a verifier that keeps
        either channel pays for all of it.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        count = mebibytes << 20
        shim.write_text(
            "#!/bin/sh\n"
            'for arg in "$@"; do\n'
            f'  if [ "$arg" = {shlex.quote(subcommand)} ]; then\n'
            f"    (yes {'x' * 63} | head -c {count}) &\n"
            f"    (yes {'y' * 63} | head -c {count} >&2) &\n"
            "    wait\n"
            f"    exit {status}\n"
            "  fi\n"
            "done\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def noisy_git_shim(self, name, subcommand, mebibytes):
        """A PATH shim that delegates to the real git but shouts while doing it.

        The distinguishing feature is that the call *succeeds*: stdout is the
        real git's real output, so the verification must still reach the correct
        head. Only stderr is flooded, concurrently with the real work, which is
        precisely the situation in which a verifier that spools stderr somewhere
        pays for tens of mebibytes it will never read.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        shim.write_text(
            "#!/bin/sh\n"
            'for arg in "$@"; do\n'
            f'  if [ "$arg" = {shlex.quote(subcommand)} ]; then\n'
            f"    (yes {'y' * 63} | head -c {mebibytes << 20} >&2) &\n"
            f'    {shlex.quote(REAL_GIT)} "$@"\n'
            "    status=$?\n"
            "    wait\n"
            "    exit $status\n"
            "  fi\n"
            "done\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def sleeping_git_shim(self, name, marker, child_pid, grandchild_pid, seconds=300):
        """A PATH shim that hangs -- with a child of its own -- inside one git call.

        It strikes on the first invocation naming the isolated view, which is
        necessarily after the view has been built, so a signal arriving now finds
        both a live git process group and a view directory that must not survive.

        The background ``sleep`` is what makes this a *process group* test:
        a verifier that kills only its direct child leaves the grandchild
        running. Both pids are published before the marker, so the test never
        reads a half-written pid.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        shim.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            "  *verify-work-approval-view-*)\n"
            f"    sleep {seconds} &\n"
            f"    echo $! > {shlex.quote(str(grandchild_pid))}\n"
            f"    echo $$ > {shlex.quote(str(child_pid))}\n"
            f"    : > {shlex.quote(str(marker))}\n"
            "    wait\n"
            "    exit 0 ;;\n"
            "esac\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def rendezvous_git_shim(self, name, request, ack):
        """A PATH shim that pauses one git call until the test says go.

        A real rendezvous, not a race: the shim announces that the verifier has
        reached a git call inside the isolated view -- which is after both
        records have been validated and read -- and blocks there until the test
        has finished mutating the record. Then it delegates to the real git and
        the verification runs to completion, so what the case proves is what the
        verifier does about the mutation, not that it was interrupted.

        Later view calls find the acknowledgement already present and do not
        pause, which is what lets a control run share the shim.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        shim.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            "  *verify-work-approval-view-*)\n"
            f"    : > {shlex.quote(str(request))}\n"
            "    i=0\n"
            f"    while [ ! -f {shlex.quote(str(ack))} ] && "
            f"[ $i -lt {RENDEZVOUS_TIMEOUT * 20} ]; do\n"
            "      sleep 0.05\n"
            "      i=$((i + 1))\n"
            "    done ;;\n"
            "esac\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def mutating_git_shim(self, name, command):
        """A PATH shim that performs one filesystem mutation inside a git call.

        Same striking point as ``rendezvous_git_shim`` -- the first call naming
        the isolated view -- for mutations the shim can make on its own, so no
        rendezvous is needed. Every invocation still delegates to the real git.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        shim.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            f"  *verify-work-approval-view-*) {command} ;;\n"
            "esac\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def cleanup_breaking_git_shim(self, name, parent):
        """A PATH shim that makes removing the isolated view fail.

        The view directory is created inside ``parent`` and its own name is
        random, so the only reliable way to break its removal from outside is
        to take the write bit off ``parent``: the entries inside the view still
        delete, the final ``rmdir`` cannot. The shim strikes on the first
        invocation naming the view directory itself -- which is necessarily
        after it has been built and before it is removed -- and delegates every
        invocation to the real git, so the verification itself runs normally and
        *succeeds*. Matching on the view's own name rather than on ``--git-dir``
        matters: the repository probe runs ``rev-parse --git-dir`` long before
        the view exists.
        """
        directory = self.staging / name
        directory.mkdir()
        shim = directory / "git"
        shim.write_text(
            "#!/bin/sh\n"
            "case \"$*\" in\n"
            f"  *verify-work-approval-view-*)"
            f" chmod 500 {shlex.quote(str(parent))} ;;\n"
            "esac\n"
            f'exec {shlex.quote(REAL_GIT)} "$@"\n'
        )
        os.chmod(shim, 0o755)
        return {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}

    def private_tempdir(self, name, mode=None):
        """A temp directory the test owns, so leaks are attributable to it."""
        parent = self.staging / name
        parent.mkdir()
        # Restored before the staging tree is removed (cleanups run LIFO), so a
        # test that takes the write bit away cannot leak into /tmp.
        self.addCleanup(os.chmod, parent, 0o700)
        if mode is not None:
            os.chmod(parent, mode)
        return parent

    def assert_no_view_left(self, parent):
        leftovers = sorted(str(path) for path in parent.glob("*"))
        self.assertEqual(
            leftovers, [], f"no isolated view may be left behind; found {leftovers}"
        )

    def hostile_config_text(self):
        order_file = self.staging / "hostile-order"
        order_file.write_text("*.h\n*.c\n*.md\n")
        return HOSTILE_DIFF_CONFIG.format(order_file=order_file)

    # ----------------------------------------------------------------- running

    def argv(
        self,
        work_id="1",
        expected_base=None,
        plan_path=PLAN_PATH,
        gpt=None,
        secondary=None,
        repo=None,
        print_head=False,
    ):
        expected_base = self.commit_base if expected_base is None else expected_base
        gpt = self.gpt_path if gpt is None else gpt
        secondary = self.secondary_path if secondary is None else secondary
        repo = self.repo if repo is None else repo
        args = []
        for name, value in (
            ("work-id", work_id),
            ("expected-base", expected_base),
            ("plan-path", plan_path),
            ("gpt", gpt),
            ("secondary", secondary),
            ("repo", repo),
        ):
            if value is not _OMIT:
                args.append(f"--{name}={value}")
        if print_head:
            args.append("--print-head")
        return args

    def umask_launcher(self, mask):
        """Launch the real script under a hostile umask.

        ``umask`` is a property of the process, not something a flag can carry,
        so the shell sets it and then execs the very same interpreter and
        script every other test uses.
        """
        return [
            "/bin/sh",
            "-c",
            f'umask {mask}; exec "$0" "$@"',
            sys.executable,
            str(VERIFIER),
        ]

    def tempdir_launcher(self, tempdir):
        """Launch the real script with the stdlib temp directory pinned.

        ``TMPDIR`` alone cannot do this: ``tempfile`` silently falls back to
        ``/tmp`` when the candidate is unusable, so an unwritable ``TMPDIR``
        would never reach the verifier. ``tempfile.tempdir`` is the documented
        knob that takes effect without a fallback. Nothing about the verifier is
        mocked -- ``runpy`` runs the real file as ``__main__``, against the real
        ``git`` -- and the pinning is proved real by
        ``test_isolated_view_cleanup_failure_is_reported``, which finds the
        view directory in exactly this location.
        """
        return [
            sys.executable,
            "-c",
            "import runpy, tempfile;"
            f"tempfile.tempdir={str(tempdir)!r};"
            f"runpy.run_path({str(VERIFIER)!r}, run_name='__main__')",
        ]

    def fsize_launcher(self, limit):
        """Launch the real script under a hard limit on how large a file it may write.

        ``RLIMIT_FSIZE`` is the one bound that distinguishes "drained and
        dropped" from "spooled to disk" without having to find a spool file that
        was unlinked the moment it was created. Everything the verifier
        legitimately writes -- the four small files of the isolated view -- is
        three orders of magnitude below the limit, so a run that stays inside it
        is a run that wrote no spool. Like the other launchers this configures
        the *launcher*: ``runpy`` then executes the real file as ``__main__``
        against the real git.
        """
        return [
            sys.executable,
            "-c",
            "import resource, runpy;"
            f"resource.setrlimit(resource.RLIMIT_FSIZE, ({limit}, {limit}));"
            f"runpy.run_path({str(VERIFIER)!r}, run_name='__main__')",
        ]

    def memory_launcher(self, report):
        """Launch the real script and have it report its own peak RSS.

        Two numbers land in ``report``: the launcher's peak before the verifier
        runs and its peak afterwards. The difference is what the verification
        itself cost, which keeps the assertion independent of how much memory a
        bare interpreter uses on this machine.

        Like ``tempdir_launcher``, this configures the *launcher*, not the
        verifier: ``runpy`` runs the real file as ``__main__`` against the real
        git. Git's own memory is deliberately out of scope -- it is a child
        process, so a git that buffers a binary patch internally cannot hide a
        verifier that does the same.
        """
        script = self.staging / "memory-launcher.py"
        script.write_text(MEMORY_LAUNCHER_SOURCE.format(verifier=repr(str(VERIFIER))))
        return [sys.executable, str(script), str(report)]

    def peak_growth(self, name, head, **kwargs):
        """Peak-RSS growth of one successful verification of ``head``.

        The run must succeed with the exact head: a measurement taken from a run
        that failed early would look wonderfully frugal and prove nothing.
        """
        report = self.staging / name
        proc = self.invoke(
            launcher=self.memory_launcher(report), print_head=True, **kwargs
        )
        stderr = proc.stderr.decode(errors="replace")
        self.assertNotIn("Traceback", stderr, f"no traceback may escape; {stderr!r}")
        self.assertEqual(
            (proc.returncode, proc.stdout),
            (0, (head + "\n").encode()),
            f"the streamed digests must still match the required bytes; "
            f"stderr={stderr!r}",
        )
        baseline, peak = (int(value) for value in report.read_text().split())
        return peak - baseline

    def invoke(
        self, env_extra=None, cwd=None, timeout=INVOKE_TIMEOUT, launcher=None, **kwargs
    ):
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        # cwd defaults to the staging directory, not the repository, so --repo
        # must be honoured; the default-repo test overrides it deliberately.
        # Every invocation is time-bounded: a verifier that can be made to spin
        # on hostile input must fail the suite, not stall it.
        launcher = [sys.executable, str(VERIFIER)] if launcher is None else launcher
        try:
            return subprocess.run(
                [*launcher, *self.argv(**kwargs)],
                capture_output=True,
                cwd=str(self.staging if cwd is None else cwd),
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            self.fail(
                f"the verifier did not terminate within {timeout}s; hostile input "
                "must never make it spin"
            )

    def spawn(self, env_extra=None, launcher=None, **kwargs):
        """Start a real verification without waiting for it.

        The signal and rendezvous cases have to act on the verifier *while* it
        runs, which ``invoke`` cannot express. Everything else is identical: the
        same launcher, the same argv, the same working directory.
        """
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        launcher = [sys.executable, str(VERIFIER)] if launcher is None else launcher
        proc = subprocess.Popen(
            [*launcher, *self.argv(**kwargs)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self.staging),
            env=env,
        )
        self.addCleanup(self.reap_spawned, proc)
        return proc

    def reap_spawned(self, proc):
        """Never leave a spawned verifier behind, however the test ended."""
        if proc.poll() is None:
            proc.kill()
        proc.communicate()

    def finish(self, proc, timeout=INVOKE_TIMEOUT):
        """Collect a spawned run into the shape the assertion helpers take."""
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.fail(
                f"the verifier did not terminate within {timeout}s; neither "
                "hostile input nor a signal may make it hang"
            )
        return subprocess.CompletedProcess(
            proc.args, proc.returncode, stdout=stdout, stderr=stderr
        )

    def assert_process_gone(self, pid, description, timeout=15):
        self.assertTrue(
            _wait_for(lambda: _process_is_gone(pid), timeout, description),
            f"{description} (pid {pid}) is still alive; a terminated run must "
            "leave no git process behind",
        )

    def peak_growth_of_rejection(self, name, cause, **kwargs):
        """Peak-RSS growth of one *rejected* verification.

        The success-path measurement cannot serve here: these runs are supposed
        to fail. The rejection shape is asserted first, so a run that failed for
        some unrelated reason -- and was therefore cheap -- cannot pass as a
        frugal one.
        """
        report = self.staging / name
        proc = self.invoke(launcher=self.memory_launcher(report), **kwargs)
        self.assert_rejection(proc, cause)
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)
        baseline, peak = (int(value) for value in report.read_text().split())
        return peak - baseline

    def assert_accepts(self, **kwargs):
        proc = self.invoke(**kwargs)
        self.assertEqual(
            proc.returncode,
            0,
            f"expected acceptance, stderr={proc.stderr.decode(errors='replace')}",
        )
        return proc

    def assert_accepts_head(self, head=None, **kwargs):
        """Acceptance plus the exact verified head, the strongest positive."""
        proc = self.assert_accepts(print_head=True, **kwargs)
        expected = self.commit_head if head is None else head
        self.assertEqual(proc.stdout, (expected + "\n").encode())
        return proc

    def assert_control_accepted(self, env_extra=None):
        """Guard against vacuous negatives: the pristine pair must be accepted."""
        proc = self.invoke(
            gpt=self.control_gpt,
            secondary=self.control_secondary,
            print_head=True,
            env_extra=env_extra,
        )
        self.assertEqual(
            (proc.returncode, proc.stdout),
            (0, (self.commit_head + "\n").encode()),
            "control fixture must be accepted, otherwise this negative case "
            f"proves nothing; stderr={proc.stderr.decode(errors='replace')}",
        )

    def assert_rejects(self, cause, env_extra=None, control_env_extra=_OMIT, **kwargs):
        """Assert a verification-level rejection whose diagnostic names `cause`.

        `cause` is mandatory: a bare nonzero exit would not distinguish "the
        mutation was caught" from "something else went wrong first".

        The control run inherits `env_extra` so hostile-environment negatives
        are non-vacuous. `control_env_extra` overrides that for the cases whose
        whole point is a broken environment -- the version-guard shims, where
        the control has to run under the real `git` to prove anything.
        """
        self.assert_control_accepted(
            env_extra=env_extra if control_env_extra is _OMIT else control_env_extra
        )
        return self.assert_rejection(self.invoke(env_extra=env_extra, **kwargs), cause)

    def assert_rejection(self, proc, cause):
        """The shape every verification-level rejection must have."""
        stderr = proc.stderr.decode(errors="replace")
        self.assertEqual(
            proc.returncode, 1, f"expected verification exit 1; stderr={stderr!r}"
        )
        self.assertEqual(proc.stdout, b"", "failures must print nothing to stdout")
        self.assertNotIn(
            "Traceback", stderr, f"no traceback may escape; stderr={stderr!r}"
        )
        lines = stderr.splitlines()
        self.assertEqual(
            len(lines), 1, f"expected exactly one concise line; stderr={stderr!r}"
        )
        self.assertTrue(
            lines[0].startswith(DIAG_PREFIX),
            f"diagnostic must carry the {DIAG_PREFIX!r} prefix; got {lines[0]!r}",
        )
        detail = lines[0][len(DIAG_PREFIX) :]
        self.assertIn(
            cause,
            detail,
            f"rejection must be caused by {cause!r}, but the verifier said {detail!r}",
        )
        return proc

    def assert_argparse_rejects(self, **kwargs):
        """Assert a CLI-level rejection: argparse's own exit 2 and usage text.

        Kept separate from `assert_rejects` because argparse never emits the
        verifier's diagnostic prefix, and conflating the two would let a
        verification test pass on an accidental CLI error.
        """
        self.assert_control_accepted()
        proc = self.invoke(**kwargs)
        stderr = proc.stderr.decode(errors="replace")
        self.assertEqual(
            proc.returncode, 2, f"expected argparse exit 2; stderr={stderr!r}"
        )
        self.assertEqual(proc.stdout, b"", "failures must print nothing to stdout")
        self.assertIn("usage:", stderr)
        self.assertNotIn(
            DIAG_PREFIX,
            stderr,
            "a CLI-level rejection must not masquerade as a verification failure",
        )
        self.assertNotIn("Traceback", stderr)
        return proc

    # ---------------------------------------------------------------- positive

    def test_valid_pair_is_accepted_silently(self):
        proc = self.assert_accepts()
        self.assertEqual(proc.stdout, b"")

    def test_valid_pair_prints_exact_head(self):
        self.assert_accepts_head()

    def test_relative_plan_path_is_resolved_inside_the_repo(self):
        # The verifier runs from the staging directory, so a bare relative plan
        # path can only resolve through --repo.
        self.assertFalse((self.staging / PLAN_PATH).exists())
        self.assert_accepts_head()

    # ------------------------------------------------- diff byte determinism

    def test_hostile_global_diff_config_does_not_change_diff_bytes(self):
        hostile = self.staging / "hostile-global.gitconfig"
        hostile.write_text(self.hostile_config_text())
        self.assert_accepts_head(env_extra={"GIT_CONFIG_GLOBAL": str(hostile)})

    def test_hostile_repository_diff_config_does_not_change_diff_bytes(self):
        repo = self.repo_copy("repo-hostile-config")
        with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write("\n" + self.hostile_config_text())
        self.assert_accepts_head(repo=repo)

    def test_forced_color_config_does_not_change_diff_bytes(self):
        repo = self.repo_copy("repo-forced-color")
        with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write("\n" + FORCED_COLOR_CONFIG)
        forced = self.staging / "forced-color.gitconfig"
        forced.write_text(FORCED_COLOR_CONFIG)
        self.assert_accepts_head(
            repo=repo, env_extra={"GIT_CONFIG_GLOBAL": str(forced)}
        )

    def test_external_diff_config_does_not_change_diff_bytes(self):
        repo = self.repo_copy("repo-external-diff")
        with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write(
                "\n[diff]\n\texternal = \"sh -c 'echo REPO-EXTERNAL-DIFF'\"\n"
            )
        self.assert_accepts_head(repo=repo)

    def test_noprefix_config_does_not_change_diff_bytes(self):
        repo = self.repo_copy("repo-noprefix")
        with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write("\n[diff]\n\tnoprefix = true\n\tmnemonicPrefix = true\n")
        self.assert_accepts_head(repo=repo)

    def test_external_diff_environment_does_not_change_diff_bytes(self):
        self.assert_accepts_head(
            env_extra={"GIT_EXTERNAL_DIFF": "sh -c 'echo ENV-EXTERNAL-DIFF'"}
        )

    def test_git_config_parameters_environment_does_not_change_diff_bytes(self):
        self.assert_accepts_head(
            env_extra={
                "GIT_CONFIG_PARAMETERS": "'diff.noprefix=true' 'color.ui=always'",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "diff.algorithm",
                "GIT_CONFIG_VALUE_0": "histogram",
            }
        )

    def test_hostile_worktree_gitattributes_do_not_change_diff_bytes(self):
        repo = self.repo_copy("repo-hostile-attrs")
        (repo / ".gitattributes").write_text(HOSTILE_GITATTRIBUTES)
        with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write(
                "\n[diff \"hostile\"]\n"
                "\ttextconv = \"sh -c 'echo HOSTILE-TEXTCONV'\"\n"
                "\tcommand = \"sh -c 'echo HOSTILE-ATTR-COMMAND'\"\n"
            )
        self.assert_accepts_head(repo=repo)

    # ------------------------------------- exact clean-config diff semantics

    def assert_matches_reference(self, name, repo, base, head, plan_sha, *, must_contain=()):
        """The verifier must accept the *required* clean-config bytes.

        The expected hash comes from `_reference_diff_bytes`, i.e. from the
        brief's own command, never from the verifier. `must_contain` asserts the
        reference really exercises the feature under test, so the comparison
        cannot pass on a diff that never contained a rename or a binary patch.
        """
        reference = _reference_diff_bytes(repo, base, head)
        for needle in must_contain:
            self.assertIn(
                needle, reference, f"the reference diff must exercise {needle!r}"
            )
        pair = self.alt_pair(name, base, head, plan_sha, _sha256_hex(reference))
        self.assert_accepts_head(head=head, repo=repo, **pair)
        return reference

    def assert_variant_rejected(self, name, repo, base, head, plan_sha, *variant_flags):
        """Bytes from a non-default diff invocation must NOT verify.

        This is what pins the semantics from the other side: forcing
        `--no-renames` or `--no-indent-heuristic` produces a hash the verifier
        has to refuse, so the required behaviour cannot silently drift back.
        """
        reference = _reference_diff_bytes(repo, base, head)
        variant = _reference_diff_bytes(repo, base, head, *variant_flags)
        self.assertNotEqual(
            reference,
            variant,
            f"{variant_flags} must change the bytes, or this test proves nothing",
        )
        # Both directions in one test: the required bytes verify, the
        # non-default bytes do not. Either half alone could pass vacuously.
        accepted = self.alt_pair(
            f"{name}-required", base, head, plan_sha, _sha256_hex(reference)
        )
        self.assert_accepts_head(head=head, repo=repo, **accepted)
        rejected = self.alt_pair(name, base, head, plan_sha, _sha256_hex(variant))
        self.assert_rejection(
            self.invoke(repo=repo, **rejected), "recomputed diff_sha256"
        )

    def test_rename_range_matches_the_required_clean_config_bytes(self):
        self.assert_matches_reference(
            "rename",
            self.sem_repo,
            self.sem_base,
            self.sem_head_rename,
            self.sem_plan_sha,
            must_contain=(b"similarity index ", b"rename from ", b"rename to "),
        )

    def test_no_renames_bytes_are_rejected(self):
        self.assert_variant_rejected(
            "rename-variant",
            self.sem_repo,
            self.sem_base,
            self.sem_head_rename,
            self.sem_plan_sha,
            "--no-renames",
        )

    def test_hunk_layout_matches_the_required_clean_config_bytes(self):
        reference = self.assert_matches_reference(
            "layout",
            self.sem_repo,
            self.sem_base,
            self.sem_head_layout,
            self.sem_plan_sha,
        )
        # The default indent heuristic puts the hunk at line 2; without it Git
        # emits @@ -3,6 +3,10 @@ for exactly the same content.
        self.assertIn(b"@@ -2,6 +2,10 @@", reference)

    def test_no_indent_heuristic_bytes_are_rejected(self):
        self.assert_variant_rejected(
            "layout-variant",
            self.sem_repo,
            self.sem_base,
            self.sem_head_layout,
            self.sem_plan_sha,
            "--no-indent-heuristic",
        )

    def test_mixed_change_range_matches_the_required_clean_config_bytes(self):
        self.assert_matches_reference(
            "mixed",
            self.sem_repo,
            self.sem_base,
            self.sem_head_mixed,
            self.sem_plan_sha,
            must_contain=(
                b"old mode 100644",
                b"new mode 100755",
                b"deleted file mode ",
                b"GIT binary patch",
                b"new file mode 160000",
                b"Subproject commit ",
            ),
        )

    # ------------------------------------------- named diff-driver isolation

    def assert_named_driver_is_neutralised(self, name, repo):
        """The audited repository must be visibly hostile, and still verify.

        The first assertion is the non-vacuity guard: `git diff` *in that
        repository* has to emit different bytes than the reference, otherwise
        the driver was never in effect and the test is theatre.
        """
        reference = _reference_diff_bytes(self.attrs_repo, self.attrs_base, self.attrs_head)
        hostile = _git(
            repo,
            "diff",
            "--binary",
            "--full-index",
            f"{self.attrs_base}..{self.attrs_head}",
            capture_bytes=True,
        )
        self.assertNotEqual(
            reference, hostile, "the named driver must actually change the bytes"
        )
        pair = self.alt_pair(
            name,
            self.attrs_base,
            self.attrs_head,
            self.attrs_plan_sha,
            _sha256_hex(reference),
        )
        return pair, repo

    def test_named_driver_in_repository_config_does_not_change_diff_bytes(self):
        repo = self.repo_copy("attrs-local-driver", source=self.attrs_repo)
        with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
            handle.write("\n" + NAMED_DRIVER_CONFIG)
        pair, repo = self.assert_named_driver_is_neutralised("attrs-local", repo)
        self.assert_accepts_head(head=self.attrs_head, repo=repo, **pair)

    def test_named_driver_in_global_config_does_not_change_diff_bytes(self):
        hostile = self.staging / "named-driver.gitconfig"
        hostile.write_text(NAMED_DRIVER_CONFIG)
        env_extra = {"GIT_CONFIG_GLOBAL": str(hostile)}
        # Non-vacuity for the global case has to be measured with that global
        # config in effect, so it is checked directly rather than through the
        # local-config helper.
        reference = _reference_diff_bytes(
            self.attrs_repo, self.attrs_base, self.attrs_head
        )
        env = _git_env()
        env["GIT_CONFIG_GLOBAL"] = str(hostile)
        hostile_bytes = subprocess.run(
            [
                "git",
                "-C",
                str(self.attrs_repo),
                "diff",
                "--binary",
                "--full-index",
                f"{self.attrs_base}..{self.attrs_head}",
            ],
            capture_output=True,
            env=env,
            check=True,
        ).stdout
        self.assertNotEqual(
            reference,
            hostile_bytes,
            "the global named driver must actually change the bytes",
        )
        pair = self.alt_pair(
            "attrs-global",
            self.attrs_base,
            self.attrs_head,
            self.attrs_plan_sha,
            _sha256_hex(reference),
        )
        self.assert_accepts_head(
            head=self.attrs_head,
            repo=self.attrs_repo,
            env_extra=env_extra,
            **pair,
        )

    def test_repository_info_attributes_do_not_change_diff_bytes(self):
        # $GIT_DIR/info/attributes outranks every in-tree attributes source, so
        # round 1 could only refuse a repository that had one. The isolated view
        # never reads it, so it is now neutralised instead of refused.
        repo = self.repo_copy("attrs-info-attributes", source=self.attrs_repo)
        info = repo / ".git" / "info"
        info.mkdir(exist_ok=True)
        (info / "attributes").write_text("*.txt -diff\n")
        pair, repo = self.assert_named_driver_is_neutralised("attrs-info", repo)
        self.assert_accepts_head(head=self.attrs_head, repo=repo, **pair)

    # ------------------------------------------------------- replace objects

    def test_replaced_base_commit_cannot_change_the_verified_diff(self):
        repo = self.repo_copy("repo-replace-base")
        decoy = _git(
            repo, "commit-tree", f"{self.commit_root}^{{tree}}", "-m", "decoy"
        )
        _git(repo, "replace", "-f", self.commit_base, decoy)
        self.assertNotEqual(
            self.diff_sha,
            _sha256_hex(
                _git(
                    repo,
                    "diff",
                    "--binary",
                    "--full-index",
                    f"{self.commit_base}..{self.commit_head}",
                    capture_bytes=True,
                )
            ),
            "the replacement must actually change what the repository reports",
        )
        self.assert_accepts_head(repo=repo)

    def test_replaced_head_commit_cannot_change_the_verified_diff(self):
        repo = self.repo_copy("repo-replace-head")
        decoy = _git(
            repo, "commit-tree", f"{self.commit_root}^{{tree}}", "-m", "decoy",
            "-p", self.commit_base,
        )
        _git(repo, "replace", "-f", self.commit_head, decoy)
        self.assertNotEqual(
            self.diff_sha,
            _sha256_hex(
                _git(
                    repo,
                    "diff",
                    "--binary",
                    "--full-index",
                    f"{self.commit_base}..{self.commit_head}",
                    capture_bytes=True,
                )
            ),
            "the replacement must actually change what the repository reports",
        )
        self.assert_accepts_head(repo=repo)

    def test_replaced_plan_blob_cannot_change_the_verified_plan_bytes(self):
        repo = self.repo_copy("repo-replace-plan-blob")
        evil = _git(repo, "hash-object", "-w", "--stdin", stdin=b"EVIL PLAN\n")
        _git(repo, "replace", "-f", self.plan_blob_git_sha, evil)
        self.assertEqual(
            _git(repo, "cat-file", "blob", self.plan_blob_git_sha, capture_bytes=True),
            b"EVIL PLAN\n",
            "the replacement must actually change what the repository reports",
        )
        self.assert_accepts_head(repo=repo)

    # ------------------------------- streamed hashing and bounded git output

    def test_large_incompressible_binary_range_is_hashed_without_buffering_it(self):
        """Hashing must cost bounded memory whatever the range costs on disk.

        A Work range can legitimately contain large binary files, and
        ``--binary`` turns each one into a base85 payload larger than the file
        itself. A verifier that collects that output into one ``bytes`` object
        needs as much memory as the diff is long -- twice that while the chunks
        are joined -- so a big-but-honest Work range would kill the audit gate
        on a small runner.

        The fixture is deliberately incompressible, both figures are larger than
        the memory head-room this test allows, and the run is required to
        *succeed* with the exact head: bounded memory is worthless if the
        streamed digest no longer matches the required bytes.

        The bound is a comparison between two runs of the same launcher -- the
        ordinary fixture and this one -- so interpreter startup, imports and the
        git child processes cancel out and what is measured is the cost of the
        range itself.
        """
        bulk = self.bulk_fixture()
        pair = self.alt_pair(
            "bulk", bulk["base"], bulk["head"], bulk["plan_sha"], bulk["diff_sha"]
        )
        small_growth = self.peak_growth("small-peak-rss", self.commit_head)
        bulk_growth = self.peak_growth(
            "bulk-peak-rss",
            bulk["head"],
            repo=bulk["repo"],
            gpt=pair["gpt"],
            secondary=pair["secondary"],
            expected_base=pair["expected_base"],
            timeout=600,
        )
        # Non-vacuity: buffering *either* stream would exceed the allowance on
        # its own, so this cannot pass on a fixture that is too small to matter.
        self.assertGreater(bulk["diff_size"], MAX_BULK_PEAK_GROWTH_BYTES)
        self.assertGreater(bulk["plan_size"], MAX_BULK_PEAK_GROWTH_BYTES)
        self.assertLess(
            bulk_growth - small_growth,
            MAX_BULK_PEAK_GROWTH_BYTES,
            f"peak memory grew by {bulk_growth - small_growth} bytes more than on "
            f"the ordinary fixture ({bulk_growth} vs {small_growth}) while hashing "
            f"a {bulk['diff_size']}-byte diff and a {bulk['plan_size']}-byte plan "
            "blob; neither may be held in memory",
        )

    def test_failing_git_diff_is_a_concise_bounded_diagnostic(self):
        """Git's own stderr must not become the diagnostic.

        A failing git may print as much as it likes, and the streaming hash has
        to read that stderr somewhere. The verifier must turn it into one
        bounded line and a nonzero exit -- not a 5 kB "concise" diagnostic, not
        a traceback, and not a deadlock on a full stderr pipe while stdout is
        being drained.
        """
        shim = self.failing_git_shim("shim-diff-fail", "diff", "x" * 5000)
        proc = self.assert_rejects(
            "git diff failed", env_extra=shim, control_env_extra={}
        )
        self.assertLess(
            len(proc.stderr),
            MAX_DIAGNOSTIC_BYTES,
            "git's stderr must be bounded before it is reported",
        )

    def test_short_git_command_flooding_both_channels_is_refused_concisely(self):
        """A short git command's output size must be the verifier's decision.

        ``merge-base --is-ancestor`` answers with nothing at all, so a binary on
        PATH that answers with tens of mebibytes on stdout *and* stderr at once
        is not a git whose answer means anything. Collecting that output because
        the command is "known to be short" makes the size of the reply decide how
        much memory the audit gate asks for -- and draining one channel while the
        other fills its pipe hangs instead.

        The refusal is required to name the stdout ceiling, so passing on some
        later mismatch does not count, and the run is required to cost bounded
        memory: a flooded run may not be more expensive than an ordinary one by
        more than a small multiple of the chunk size.
        """
        shim = self.flooding_git_shim("shim-flood-short", "merge-base", GIT_FLOOD_MIB)
        self.assert_control_accepted()
        small = self.peak_growth("flood-small-peak-rss", self.commit_head)
        flooded = self.peak_growth_of_rejection(
            "flood-short-peak-rss",
            f"at most {MAX_GIT_STDOUT_BYTES} bytes",
            env_extra=shim,
            timeout=300,
        )
        self.assertLess(
            flooded - small,
            MAX_FLOOD_PEAK_GROWTH_BYTES,
            f"peak memory grew by {flooded - small} bytes more than on an "
            f"ordinary run ({flooded} vs {small}) while a git shim emitted "
            f"{GIT_FLOOD_MIB} MiB on each channel; neither may be retained",
        )

    def test_streamed_git_flooding_both_channels_is_hashed_within_bounded_memory(self):
        """The streamed channel is unbounded by design; the other one is not.

        A real ``diff`` may legitimately be tens of mebibytes, so stdout is
        hashed rather than capped -- but its stderr must be drained concurrently
        and kept only as a bounded prefix. Feeding both channels tens of
        mebibytes at once therefore has exactly one acceptable outcome: the
        flooded stdout is hashed, disagrees with the recorded digest, and the run
        fails in one bounded line without a deadlock, a temporary file, or a
        memory footprint that tracks the flood.
        """
        shim = self.flooding_git_shim("shim-flood-diff", "diff", GIT_FLOOD_MIB)
        self.assert_control_accepted()
        small = self.peak_growth("flood-diff-small-peak-rss", self.commit_head)
        flooded = self.peak_growth_of_rejection(
            "flood-diff-peak-rss",
            "recomputed diff_sha256",
            env_extra=shim,
            timeout=300,
        )
        self.assertLess(
            flooded - small,
            MAX_FLOOD_PEAK_GROWTH_BYTES,
            f"peak memory grew by {flooded - small} bytes more than on an "
            f"ordinary run ({flooded} vs {small}) while hashing a "
            f"{GIT_FLOOD_MIB} MiB flood against a {GIT_FLOOD_MIB} MiB stderr",
        )

    def test_streamed_git_failing_with_megabytes_of_stderr_is_concise(self):
        """A failing git's essay must cost a bounded prefix, not a spool file.

        Spooling stderr to a temporary file avoids the deadlock but pays for it
        in disk: tens of mebibytes per failing git call, written somewhere the
        caller did not choose. Only a bounded prefix is ever needed, because only
        the first line -- clipped -- reaches the diagnostic.
        """
        shim = self.flooding_git_shim(
            "shim-flood-diff-fail", "diff", GIT_FLOOD_MIB, status=128
        )
        small = self.peak_growth("flood-fail-small-peak-rss", self.commit_head)
        flooded = self.peak_growth_of_rejection(
            "flood-fail-peak-rss", "git diff failed", env_extra=shim, timeout=300
        )
        self.assertLess(
            flooded - small,
            MAX_FLOOD_PEAK_GROWTH_BYTES,
            f"peak memory grew by {flooded - small} bytes more than on an "
            f"ordinary run ({flooded} vs {small}) while draining a "
            f"{GIT_FLOOD_MIB} MiB stderr from a failing git",
        )

    def test_noisy_but_successful_git_stderr_is_not_spooled_to_disk(self):
        """Draining stderr must cost a bounded prefix of memory and no disk at all.

        Spooling a git child's stderr to a temporary file is the easy way to
        avoid a deadlock, and it silently makes every talkative git call cost
        disk: tens of mebibytes, written wherever the process happens to put
        temporary files, for output nobody will ever read past its first line.

        The bound here is a real one rather than an inspection. Under
        ``RLIMIT_FSIZE`` the four small files of the isolated view fit with three
        orders of magnitude to spare, and a multi-mebibyte spool does not fit at
        all -- so a run that completes at the correct head under this limit is a
        run that wrote no spool. The git call succeeds and its stdout is the real
        git's, so the digests still have to match: this is a positive case, which
        is the strongest kind.
        """
        shim = self.noisy_git_shim("shim-noisy-diff", "diff", GIT_FLOOD_MIB)
        proc = self.invoke(
            launcher=self.fsize_launcher(MAX_SPOOL_FILE_BYTES),
            env_extra=shim,
            print_head=True,
            timeout=300,
        )
        stderr = proc.stderr.decode(errors="replace")
        self.assertNotIn("Traceback", stderr, f"no traceback may escape; {stderr!r}")
        self.assertEqual(
            (proc.returncode, proc.stdout),
            (0, (self.commit_head + "\n").encode()),
            f"a git that floods stderr with {GIT_FLOOD_MIB} MiB must still verify "
            f"to the exact head, without writing a file larger than "
            f"{MAX_SPOOL_FILE_BYTES} bytes; stderr={stderr!r}",
        )

    def test_git_version_flooding_stdout_is_refused_concisely(self):
        """The very first git call is a short one, and is bounded like the rest.

        ``--version`` is answered by whatever binary is first on PATH, before
        anything else has been checked, so it is the earliest place an unbounded
        collection can be provoked.
        """
        shim = self.flooding_git_shim("shim-flood-version", "--version", GIT_FLOOD_MIB)
        proc = self.assert_rejects(
            f"at most {MAX_GIT_STDOUT_BYTES} bytes",
            env_extra=shim,
            control_env_extra={},
            timeout=300,
        )
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    # ---------------------------------------------------------- git version

    def test_git_below_the_required_version_is_refused(self):
        shim = self.git_shim(
            "shim-old", '  echo "git version 2.39.9"\n  exit 0'
        )
        self.assert_rejects(
            "is too old", env_extra=shim, control_env_extra={}
        )

    def test_git_2_40_is_refused_for_the_missing_attr_source_capability(self):
        """2.40 is the dangerous case, not merely an old one.

        ``GIT_ATTR_SOURCE`` arrived in git 2.41. A 2.40 binary does not fail on
        it -- it ignores it, like any unknown environment variable, and happily
        emits a diff whose gitattributes came from somewhere else. That is
        exactly the silent wrong answer this gate exists to prevent, so the
        refusal must name the capability rather than just complain about age.
        """
        for version in REFUSED_GIT_VERSIONS:
            with self.subTest(version=version):
                shim = self.git_shim(
                    f"shim-{version.replace('.', '-')}",
                    f'  echo "git version {version}"\n  exit 0',
                )
                proc = self.assert_rejects(
                    "is too old", env_extra=shim, control_env_extra={}
                )
                detail = proc.stderr.decode()
                self.assertIn("GIT_ATTR_SOURCE", detail)
                self.assertIn(MIN_GIT_VERSION_TEXT, detail)

    def test_unparsable_git_version_is_refused(self):
        shim = self.git_shim(
            "shim-garbage", '  echo "git version banana"\n  exit 0'
        )
        self.assert_rejects(
            "cannot parse", env_extra=shim, control_env_extra={}
        )

    def test_git_version_with_thousands_of_digits_is_refused_concisely(self):
        """An unbounded version component must not escape as a ValueError.

        CPython refuses to build an int from more than 4300 digits, so a
        verifier that calls ``int()`` on whatever ``git --version`` printed
        dies with a traceback instead of diagnosing. Both positions are
        exercised because they are parsed by different capture groups.
        """
        for label, version in (
            ("major", f"{HUGE_DIGITS}.41.0"),
            ("minor", f"2.{HUGE_DIGITS}.0"),
        ):
            with self.subTest(component=label):
                shim = self.git_shim(
                    f"shim-huge-{label}",
                    f'  echo "git version {version}"\n  exit 0',
                )
                proc = self.assert_rejects(
                    f"{len(HUGE_DIGITS)} digits",
                    env_extra=shim,
                    control_env_extra={},
                )
                self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_unparsable_git_version_diagnostic_is_bounded(self):
        # The diagnostic quotes what git said. A 5 kB response must therefore
        # be clipped: one line is necessary for conciseness, not sufficient.
        shim = self.git_shim(
            "shim-huge-garbage", f'  echo "git version {"x" * 5000}"\n  exit 0'
        )
        proc = self.assert_rejects(
            "cannot parse", env_extra=shim, control_env_extra={}
        )
        self.assertLess(
            len(proc.stderr),
            MAX_DIAGNOSTIC_BYTES,
            "the diagnostic must not echo an unbounded git response",
        )

    def test_failing_git_version_probe_is_refused(self):
        shim = self.git_shim(
            "shim-broken", '  echo "no version for you" >&2\n  exit 3'
        )
        self.assert_rejects(
            "git version", env_extra=shim, control_env_extra={}
        )

    def test_git_at_the_required_version_is_accepted(self):
        # The shim only spoofs `--version`; everything else is the real git, so
        # this proves the guard is a floor rather than a wall.
        shim = self.git_shim(
            "shim-floor", f'  echo "git version {MIN_GIT_VERSION_TEXT}"\n  exit 0'
        )
        self.assert_accepts_head(env_extra=shim)

    def test_vendor_suffixed_git_version_is_accepted(self):
        shim = self.git_shim(
            "shim-vendor", '  echo "git version 2.41.0 (Apple Git-999)"\n  exit 0'
        )
        self.assert_accepts_head(env_extra=shim)

    def test_two_component_git_version_is_accepted(self):
        shim = self.git_shim("shim-two", '  echo "git version 2.41"\n  exit 0')
        self.assert_accepts_head(env_extra=shim)

    def test_dotted_vendor_git_version_shapes_are_accepted(self):
        """Strictness must not lock out shapes real gits actually print.

        Git for Windows appends ``.windows.N`` and a git built from a tagged
        checkout appends a ``describe`` tail. Both are documented vendor
        suffixes on a version that satisfies the floor, so both must verify --
        against the real git, since the shim only spoofs ``--version``.
        """
        for index, text in enumerate(ACCEPTED_GIT_VERSION_SHAPES):
            with self.subTest(version=text):
                shim = self.git_shim(
                    f"shim-shape-{index}", f'  echo "{text}"\n  exit 0'
                )
                self.assert_accepts_head(env_extra=shim)

    def test_git_version_with_trailing_garbage_is_refused(self):
        """A version is what the whole line says, not what its prefix says.

        An unanchored parse reads ``git version 2.41.0`` out of anything that
        starts that way and ignores the rest, so a wrapper announcing something
        else entirely -- or a supply-chain shim padding its identity -- passes
        the floor. Whatever printed this is not the git whose behaviour the byte
        contract depends on, so it must be refused rather than half-read.
        """
        for index, text in enumerate(REFUSED_GIT_VERSION_TAILS):
            with self.subTest(version=text):
                shim = self.git_shim(
                    f"shim-tail-{index}", f'  echo "{text}"\n  exit 0'
                )
                self.assert_rejects(
                    "cannot parse", env_extra=shim, control_env_extra={}
                )

    def test_malformed_vendor_git_version_shapes_are_refused(self):
        """The vendor tail is a grammar too, and it must be a strict one.

        Anchoring the pattern was only half the job: a tail that accepts any run
        of dots and alphanumerics accepts a doubled separator, a dangling
        separator, and -- for the parenthesised form -- a note with nothing in
        it. None of those is a shape a real ``git --version`` prints, so each one
        means the binary answering is not the git the byte contract depends on.

        Every case runs end to end against the real repository, so the rejection
        is the version guard's and not some later step's, and each is required to
        be a bounded one-line diagnostic.
        """
        for index, text in enumerate(REFUSED_GIT_VERSION_SHAPES):
            with self.subTest(version=text):
                shim = self.git_shim(
                    f"shim-malformed-{index}", f'  echo "{text}"\n  exit 0'
                )
                proc = self.assert_rejects(
                    "cannot parse", env_extra=shim, control_env_extra={}
                )
                self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_multiline_git_version_is_refused(self):
        """One line, or nothing. And the refusal itself must stay one line.

        A first line that parses says nothing about what follows it, and a
        diagnostic that echoed the whole response would break the one-line
        contract every other rejection keeps.
        """
        shim = self.git_shim(
            "shim-multiline",
            '  printf "git version 2.41.0\\nHACKED\\n"\n  exit 0',
        )
        proc = self.assert_rejects(
            "exactly one is required", env_extra=shim, control_env_extra={}
        )
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    # ------------------------------------------------- hostile git environment

    def test_hostile_git_config_count_is_not_iterated(self):
        # A verifier that trusted GIT_CONFIG_COUNT and looped up to it would
        # hang here for the rest of the decade. The injected key must also be
        # dropped, not merely survived.
        started = time.monotonic()
        self.assert_accepts_head(
            timeout=45,
            env_extra={
                "GIT_CONFIG_COUNT": "99999999999999999999",
                "GIT_CONFIG_KEY_0": "diff.external",
                "GIT_CONFIG_VALUE_0": "sh -c 'echo HOSTILE-COUNT'",
                "GIT_CONFIG_KEY_7": "diff.noprefix",
                "GIT_CONFIG_VALUE_7": "true",
            }
        )
        self.assertLess(
            time.monotonic() - started,
            60,
            "the attacker-supplied count must not drive a loop",
        )

    def test_non_numeric_git_config_count_is_ignored(self):
        self.assert_accepts_head(
            env_extra={
                "GIT_CONFIG_COUNT": "not-a-number",
                "GIT_CONFIG_KEY_0": "diff.noprefix",
                "GIT_CONFIG_VALUE_0": "true",
            }
        )

    def test_hostile_attr_source_environment_is_ignored(self):
        # The verifier chooses the attributes source itself. An inherited
        # GIT_ATTR_SOURCE pointing at a tree whose attributes mark everything
        # binary must not reach the diff.
        reference = _reference_diff_bytes(
            self.attrs_repo, self.attrs_base, self.attrs_head
        )
        env = _git_env()
        env["GIT_ATTR_SOURCE"] = self.attrs_hostile_source
        hijacked = subprocess.run(
            [
                "git",
                "-C",
                str(self.attrs_repo),
                "diff",
                "--binary",
                "--full-index",
                f"{self.attrs_base}..{self.attrs_head}",
            ],
            capture_output=True,
            env=env,
            check=True,
        ).stdout
        self.assertNotEqual(
            reference, hijacked, "the hostile attributes source must really bite"
        )
        pair = self.alt_pair(
            "attr-source",
            self.attrs_base,
            self.attrs_head,
            self.attrs_plan_sha,
            _sha256_hex(reference),
        )
        self.assert_accepts_head(
            head=self.attrs_head,
            repo=self.attrs_repo,
            env_extra={"GIT_ATTR_SOURCE": self.attrs_hostile_source},
            **pair,
        )

    def test_hostile_git_dir_environment_is_ignored(self):
        # GIT_DIR would otherwise redirect every object read to a repository
        # that knows nothing about this Work's commits.
        self.assertNotEqual(
            _git(self.sem_repo, "rev-parse", "HEAD"),
            self.commit_head,
            "the decoy repository must have a different HEAD",
        )
        self.assert_accepts_head(
            env_extra={"GIT_DIR": str(self.sem_repo / ".git")}
        )

    def test_replace_ref_base_environment_is_ignored(self):
        repo = self.repo_copy("repo-replace-ref-base")
        decoy = _git(
            repo, "commit-tree", f"{self.commit_root}^{{tree}}", "-m", "decoy"
        )
        _git(
            repo,
            "update-ref",
            f"refs/evil-replace/{self.commit_base}",
            decoy,
        )
        self.assert_accepts_head(
            repo=repo, env_extra={"GIT_REPLACE_REF_BASE": "refs/evil-replace/"}
        )

    # ------------------------------------------------- isolated view lifecycle

    def test_isolated_view_leaves_no_temporary_directory(self):
        pattern = os.path.join(tempfile.gettempdir(), "verify-work-approval-view-*")
        before = set(glob.glob(pattern))
        self.assert_accepts_head()
        self.assertEqual(
            set(glob.glob(pattern)) - before,
            set(),
            "the isolated view must be removed when the verifier exits",
        )

    def test_isolated_view_is_usable_under_a_restrictive_umask(self):
        """The view must not depend on the caller's umask.

        ``mkdtemp`` and ``mkdir`` both mask the mode they are given, so under
        ``umask 0777`` an unguarded view is created mode 000: git cannot read
        it, and the verifier cannot even finish writing it. A gate that works
        only for developers with a friendly umask is not a gate.
        """
        probe = self.staging / "umask-probe"
        subprocess.run(
            ["/bin/sh", "-c", f"umask 0777; : > {shlex.quote(str(probe))}"],
            check=True,
        )
        self.assertEqual(
            stat.S_IMODE(probe.stat().st_mode),
            0o000,
            "the launcher's umask must really be hostile, or this proves nothing",
        )
        proc = self.invoke(launcher=self.umask_launcher("0777"), print_head=True)
        stderr = proc.stderr.decode(errors="replace")
        self.assertNotIn("Traceback", stderr, f"no traceback may escape; {stderr!r}")
        self.assertEqual(
            (proc.returncode, proc.stdout),
            (0, (self.commit_head + "\n").encode()),
            f"stderr={stderr!r}",
        )

    @unittest.skipIf(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "root bypasses directory permission bits",
    )
    def test_unusable_temporary_directory_is_a_concise_diagnostic(self):
        # A filesystem error while building the view is a real operational
        # case (read-only or full /tmp in a container). It must be diagnosed,
        # not traced, and it must leave nothing behind.
        parent = self.private_tempdir("readonly-tmp", mode=0o500)
        self.assert_control_accepted()
        proc = self.invoke(launcher=self.tempdir_launcher(parent), print_head=True)
        self.assert_rejection(proc, "isolated git view")
        self.assert_no_view_left(parent)

    def test_successful_run_removes_the_isolated_view(self):
        parent = self.private_tempdir("view-tmp-success")
        proc = self.invoke(launcher=self.tempdir_launcher(parent), print_head=True)
        self.assertEqual(
            (proc.returncode, proc.stdout),
            (0, (self.commit_head + "\n").encode()),
            f"stderr={proc.stderr.decode(errors='replace')}",
        )
        self.assert_no_view_left(parent)

    def test_failed_verification_removes_the_isolated_view(self):
        # The failure is chosen to happen *after* the view exists -- resolving
        # commits is the first thing done through it -- so this really tests
        # unwinding rather than never having created anything.
        parent = self.private_tempdir("view-tmp-failure")
        self.write_pair(head_commit=_HEX40)
        proc = self.invoke(launcher=self.tempdir_launcher(parent))
        self.assert_rejection(proc, f"head_commit {_HEX40} does not resolve to a commit")
        self.assert_no_view_left(parent)

    @unittest.skipIf(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "root bypasses directory permission bits",
    )
    def test_isolated_view_cleanup_failure_is_reported(self):
        """A leaked view must fail loudly, not be swallowed.

        Everything here verifies successfully; only the removal fails. A
        verifier that ignores cleanup errors would print the head commit and
        exit 0 while leaving a directory behind, which is precisely the silent
        leak the reviewers asked to close.
        """
        parent = self.private_tempdir("view-tmp-cleanup")
        self.assert_control_accepted()
        shim = self.cleanup_breaking_git_shim("shim-cleanup", parent)
        proc = self.invoke(
            launcher=self.tempdir_launcher(parent), env_extra=shim, print_head=True
        )
        self.assert_rejection(proc, "could not be removed")
        # Non-vacuity, and proof that the launcher really pinned the temp
        # directory: the leak this diagnostic reports is right here.
        leaked = sorted(parent.glob("verify-work-approval-view-*"))
        self.assertEqual(
            len(leaked),
            1,
            f"the shim must produce a real, reported leak; found {leaked}",
        )

    # ------------------------------------------------------------- termination

    def assert_signal_leaves_nothing_behind(self, signal_name):
        """One signal, delivered while a git child is really running.

        A build system cancelling a job, or an operator pressing Ctrl-C, arrives
        at an arbitrary moment -- most of the run is spent inside a git child, so
        that is the moment worth testing. What must not survive it: the git
        child, anything that child started, and the isolated view. The shim's
        background ``sleep`` is the part a direct-child kill would miss.

        The exit status is required to be the conventional ``128 + signum``
        rather than a death by the default disposition, because that is the
        difference between a run that cleaned up and a run that was simply
        killed.
        """
        signum = int(getattr(signal, signal_name))
        tag = signal_name.lower()
        parent = self.private_tempdir(f"view-tmp-{tag}")
        marker = self.staging / f"{tag}-ready"
        child_pid_file = self.staging / f"{tag}-child.pid"
        grandchild_pid_file = self.staging / f"{tag}-grandchild.pid"
        shim = self.sleeping_git_shim(
            f"shim-{tag}", marker, child_pid_file, grandchild_pid_file
        )
        proc = self.spawn(
            launcher=self.tempdir_launcher(parent), env_extra=shim, print_head=True
        )
        self.assertTrue(
            _wait_for(marker.exists, RENDEZVOUS_TIMEOUT, "git shim reached the view"),
            "the shim must reach a git call inside the isolated view, otherwise "
            "there is nothing to terminate",
        )
        view = sorted(parent.glob("verify-work-approval-view-*"))
        self.assertEqual(
            len(view),
            1,
            f"the view must exist when the signal arrives; found {view}",
        )
        child = int(child_pid_file.read_text())
        grandchild = int(grandchild_pid_file.read_text())
        self.assertFalse(
            _process_is_gone(child), "the git child must be alive when signalled"
        )
        self.assertFalse(
            _process_is_gone(grandchild),
            "the git child's own child must be alive when signalled",
        )

        proc.send_signal(signum)
        finished = self.finish(proc, timeout=INVOKE_TIMEOUT)
        stderr = finished.stderr.decode(errors="replace")
        self.assertEqual(
            finished.stdout, b"", "a terminated run must print nothing to stdout"
        )
        self.assertNotIn("Traceback", stderr, f"no traceback may escape; {stderr!r}")
        self.assertEqual(
            finished.returncode,
            128 + signum,
            f"a handled {signal_name} must exit {128 + signum}, not die of the "
            f"default disposition; stderr={stderr!r}",
        )
        lines = stderr.splitlines()
        self.assertEqual(
            len(lines), 1, f"expected exactly one concise line; stderr={stderr!r}"
        )
        self.assertTrue(lines[0].startswith(DIAG_PREFIX), f"got {lines[0]!r}")
        self.assertIn(signal_name, lines[0], f"the signal must be named; {lines[0]!r}")
        self.assert_process_gone(child, "the git child")
        self.assert_process_gone(grandchild, "the git child's own child")
        self.assert_no_view_left(parent)

    def test_sigterm_during_a_git_child_leaves_nothing_behind(self):
        self.assert_signal_leaves_nothing_behind("SIGTERM")

    def test_sigint_during_a_git_child_leaves_nothing_behind(self):
        self.assert_signal_leaves_nothing_behind("SIGINT")

    # ------------------------------------------------------- record structure

    def test_missing_field_is_rejected(self):
        order = tuple(f for f in FIELD_ORDER if f != "plan_blob_sha256")
        self.write_gpt(order=order)
        self.assert_rejects("is missing field(s): plan_blob_sha256")

    def test_duplicate_field_is_rejected(self):
        self.write_gpt(order=FIELD_ORDER + ("head_commit",))
        self.assert_rejects("repeats field 'head_commit'")

    def test_multiple_verdicts_are_rejected(self):
        self.write_secondary(order=FIELD_ORDER + ("verdict",))
        self.assert_rejects("repeats field 'verdict'")

    def test_unknown_field_is_rejected(self):
        text = _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {}))
        _write_readonly(self.gpt_path, text + "reviewer_notes: looks fine\n")
        self.assert_rejects("unknown field 'reviewer_notes'")

    def test_line_without_colon_is_rejected(self):
        text = _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {}))
        _write_readonly(self.gpt_path, text + "APPROVE\n")
        self.assert_rejects("is not a 'key: value' line")

    def test_missing_space_after_colon_is_rejected(self):
        text = _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {}))
        _write_readonly(self.gpt_path, text.replace("verdict: APPROVE", "verdict:APPROVE"))
        self.assert_rejects("needs exactly one space after ':'")

    def test_blank_line_is_rejected(self):
        text = _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {}))
        _write_readonly(self.gpt_path, text.replace("base_commit:", "\nbase_commit:"))
        self.assert_rejects("is blank")

    def test_trailing_whitespace_in_value_is_rejected(self):
        text = _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {}))
        _write_readonly(self.gpt_path, text.replace("verdict: APPROVE", "verdict: APPROVE "))
        self.assert_rejects("malformed surrounding space")

    def test_empty_record_is_rejected(self):
        _write_readonly(self.secondary_path, b"")
        self.assert_rejects("is empty or lacks a final newline")

    def test_non_utf8_record_is_rejected(self):
        text = _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {}))
        _write_readonly(self.gpt_path, text.encode().replace(PRIMARY_INSTANCE.encode(), b"gpt-\xff-a1"))
        self.assert_rejects("is not valid UTF-8")

    # ------------------------------------------------------ record size bounds

    def test_multi_megabyte_canonical_record_is_rejected(self):
        """A record too big to be a record must be refused before it is read.

        These bytes are *canonical*: eleven fields, correct grammar, a huge but
        well-formed ``reviewer_instance_id``. Nothing but a size bound can refuse
        them, and a verifier that reads the descriptor first and validates later
        has already allocated the megabytes by the time it could object. The
        refusal is required to name the byte ceiling, so passing this test on the
        instance-id cap -- which is checked much later, after parsing -- does not
        count.
        """
        self.write_gpt(reviewer_instance_id="x" * OVERSIZE_RECORD_BYTES)
        self.assertGreater(self.gpt_path.stat().st_size, OVERSIZE_RECORD_BYTES)
        proc = self.assert_rejects(f"at most {MAX_RECORD_BYTES} bytes")
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_oversize_secondary_record_is_rejected(self):
        # Both slots are read, so both must be bounded.
        self.write_secondary(reviewer_instance_id="x" * OVERSIZE_RECORD_BYTES)
        self.assert_rejects(f"at most {MAX_RECORD_BYTES} bytes")

    def test_record_grown_through_a_retained_writable_descriptor_is_rejected(self):
        """A read-only mode is not a promise about size.

        The record is made read-only exactly as a real one would be, but a writer
        that opened it *before* the ``chmod`` still holds a writable descriptor
        and keeps appending through it -- the one write path the mode check
        cannot close. What the verifier then opens is a genuine regular
        read-only file that is nonetheless megabytes long, so only a size bound
        stands between it and the allocation.

        The append happens before the run, because the window between the
        verifier's ``fstat`` and its ``read`` cannot be hit deliberately from
        another process. Both orderings are refused by the same ceiling.
        """
        self.write_gpt(mode=0o644)
        fd = os.open(self.gpt_path, os.O_WRONLY | os.O_APPEND)
        self.addCleanup(os.close, fd)
        os.chmod(self.gpt_path, 0o444)
        for _ in range(4):
            os.write(fd, b"z" * (1 << 20))
        # Non-vacuity: the object the verifier opens really is read-only, really
        # is a regular file, and really has grown past the ceiling.
        self.assertEqual(stat.S_IMODE(self.gpt_path.stat().st_mode), 0o444)
        self.assertGreater(self.gpt_path.stat().st_size, 4 << 20)
        proc = self.assert_rejects(f"at most {MAX_RECORD_BYTES} bytes")
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_over_long_reviewer_instance_id_is_rejected(self):
        """The only free-form field needs a ceiling of its own.

        Every other field is pinned to hex, to an exact string, or to empty.
        ``reviewer_instance_id`` is arbitrary text, so without a cap it is the
        one place a record can carry kilobytes of anything -- under the record
        ceiling, and straight into a diagnostic.
        """
        self.write_gpt(reviewer_instance_id="i" * (MAX_INSTANCE_ID_CHARS + 1))
        self.assertLess(self.gpt_path.stat().st_size, MAX_RECORD_BYTES)
        proc = self.assert_rejects(f"at most {MAX_INSTANCE_ID_CHARS} characters")
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_reviewer_instance_id_at_the_cap_is_accepted(self):
        # A cap, not a wall: the longest legitimate instance id still verifies.
        self.write_gpt(reviewer_instance_id="i" * MAX_INSTANCE_ID_CHARS)
        self.assert_accepts_head()

    # -------------------------------------------------- record stability
    #
    # The length comparison in the read is not enough on its own: it only sees a
    # record that got longer or shorter. A writer holding a descriptor from
    # before the ``chmod`` can rewrite the record *in place*, to the same length,
    # while the verification is under way -- and then the file the audit trail
    # points at is not the file the verdict was issued about.

    def test_same_length_record_rewrite_during_verification_is_rejected(self):
        """A same-length in-place rewrite must not slip past the size check.

        The record is made read-only exactly as a real one would be, but a
        descriptor opened *before* the ``chmod`` survives it, and this test keeps
        one. Halfway through the verification -- at a real rendezvous inside a git
        call, with the isolated view already built and both records already read
        -- that descriptor rewrites the record to *different bytes of the same
        length*. Nothing about the size changes, and the replacement is itself a
        perfectly canonical record, so the only thing that can catch it is a
        comparison against the state of the object that was actually validated.

        Then the shim delegates to the real git and the verification finishes, so
        this measures what the verifier concludes rather than what interrupting it
        does.
        """
        self.write_gpt(mode=0o644)
        writer = os.open(self.gpt_path, os.O_WRONLY)
        self.addCleanup(os.close, writer)
        os.chmod(self.gpt_path, 0o444)
        original = self.gpt_path.read_bytes()
        replacement = _render(
            self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE[:-2] + "z9", {})
        ).encode()
        # Non-vacuity, before anything runs: the mutation really is same-length
        # and really is a different record.
        self.assertEqual(len(replacement), len(original))
        self.assertNotEqual(replacement, original)

        request = self.staging / "rendezvous-request"
        ack = self.staging / "rendezvous-ack"
        shim = self.rendezvous_git_shim("shim-rendezvous", request, ack)
        proc = self.spawn(env_extra=shim, print_head=True)
        self.assertTrue(
            _wait_for(request.exists, RENDEZVOUS_TIMEOUT, "git reached the view"),
            "the verifier must reach a git call inside the isolated view, "
            "otherwise the mutation is not mid-verification at all",
        )
        self.assertEqual(os.pwrite(writer, replacement, 0), len(replacement))
        ack.touch()
        finished = self.finish(proc)

        self.assertEqual(
            self.gpt_path.read_bytes(),
            replacement,
            "the retained descriptor must really have rewritten the record",
        )
        self.assertEqual(self.gpt_path.stat().st_size, len(original))
        self.assert_rejection(finished, "changed while it was being verified")
        # The shim is not what caused the rejection: with the acknowledgement
        # already in place it no longer pauses, and an unmutated pair verifies
        # through the very same shim.
        self.assert_control_accepted(env_extra=shim)

    def test_record_made_writable_during_verification_is_rejected(self):
        """The mode that was approved must still be the mode at the verdict.

        A record that becomes writable mid-run is no longer the immutable
        evidence the mode check accepted, and a ``chmod`` leaves the contents --
        and the size -- untouched, so only the mode and the inode change time
        record it.
        """
        chmod = f"chmod 644 {shlex.quote(str(self.gpt_path))} 2>/dev/null || true"
        shim = self.mutating_git_shim("shim-chmod", chmod)
        self.assert_control_accepted()
        proc = self.invoke(env_extra=shim, print_head=True)
        self.assertEqual(
            stat.S_IMODE(self.gpt_path.stat().st_mode),
            0o644,
            "the shim must really have made the record writable",
        )
        self.assert_rejection(proc, "changed while it was being verified")

    # ------------------------------------------------------------ field values

    def test_short_base_commit_in_record_is_rejected(self):
        # The flag stays a valid 40-hex sha so the record field is what fails.
        short = self.commit_base[:39]
        self.write_pair(base_commit=short)
        self.assert_rejects(f"base_commit {short!r} is not full lowercase 40-hex")

    def test_uppercase_head_commit_is_rejected(self):
        self.write_pair(head_commit=self.commit_head.upper())
        self.assert_rejects(
            f"head_commit {self.commit_head.upper()!r} is not full lowercase 40-hex"
        )

    def test_short_diff_sha_is_rejected(self):
        self.write_pair(diff_sha256=self.diff_sha[:63])
        self.assert_rejects(
            f"diff_sha256 {self.diff_sha[:63]!r} is not full lowercase 64-hex"
        )

    def test_non_hex_plan_blob_sha_is_rejected(self):
        bad = "g" + self.plan_blob_sha[1:]
        self.write_pair(plan_blob_sha256=bad)
        self.assert_rejects(f"plan_blob_sha256 {bad!r} is not full lowercase 64-hex")

    def test_verdict_must_be_exactly_approve(self):
        self.write_secondary(verdict="APPROVED")
        self.assert_rejects("verdict 'APPROVED' is not exactly 'APPROVE'")

    def test_lowercase_verdict_is_rejected(self):
        self.write_gpt(verdict="approve")
        self.assert_rejects("verdict 'approve' is not exactly 'APPROVE'")

    def test_record_work_id_must_match_the_flag(self):
        self.write_pair(work_id="2")
        self.assert_rejects("work_id 2 does not match --work-id=1")

    def test_record_work_id_rejects_leading_zero(self):
        # The flag stays valid so the record field is what fails.
        self.write_pair(work_id="01")
        self.assert_rejects("work_id '01' is not a positive integer")

    def test_record_work_id_rejects_zero(self):
        self.write_pair(work_id="0")
        self.assert_rejects("work_id '0' is not a positive integer")

    def test_record_work_id_with_thousands_of_digits_is_rejected(self):
        """A canonical-looking but unbounded work_id must not raise ValueError.

        ``9`` repeated 5000 times satisfies the ``[1-9][0-9]*`` grammar, so it
        reaches the comparison against ``--work-id``. CPython refuses to build
        an int from more than 4300 digits, so converting it unguarded ends the
        run with a traceback on stderr instead of the one-line diagnostic every
        other rejection produces.
        """
        self.write_pair(work_id=HUGE_DIGITS)
        proc = self.assert_rejects(f"work_id has {len(HUGE_DIGITS)} digits")
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_record_work_id_of_thousands_of_zeros_is_rejected_concisely(self):
        # Fails the grammar rather than the bound, so it takes the other
        # branch -- which must not echo 5000 characters back at the operator.
        self.write_pair(work_id=HUGE_ZEROS)
        proc = self.assert_rejects("is not a positive integer")
        self.assertLess(
            len(proc.stderr),
            MAX_DIAGNOSTIC_BYTES,
            "the diagnostic must not echo an unbounded field value",
        )

    # ---------------------------------------------------------------- reviewers

    def test_work_final_gpt_and_opus_pair_is_accepted(self):
        """The reviewer contract stated positively.

        The primary carries `gpt-5.6-sol`, the secondary carries
        `claude-opus-5`, and the instance ids differ. Per-phase review is not a
        substitute for either Work-final record.
        """
        self.write_pair()
        proc = self.assert_accepts_head()
        self.assertEqual(proc.stderr, b"")
        gpt_text = self.gpt_path.read_text()
        secondary_text = self.secondary_path.read_text()
        self.assertIn(f"reviewer_model: {PRIMARY_MODEL}\n", gpt_text)
        self.assertIn(f"reviewer_model: {SECONDARY_MODEL}\n", secondary_text)
        self.assertIn(f"reviewer_instance_id: {PRIMARY_INSTANCE}\n", gpt_text)
        self.assertIn(f"reviewer_instance_id: {SECONDARY_INSTANCE}\n", secondary_text)
        self.assertNotEqual(PRIMARY_INSTANCE, SECONDARY_INSTANCE)

    def test_primary_must_be_gpt_5_6_sol(self):
        for model in REJECTED_PRIMARY_MODELS:
            with self.subTest(model=model):
                self.write_gpt(reviewer_model=model)
                self.assert_rejects(
                    f"reviewer_model {model!r} is not the required "
                    f"{PRIMARY_MODEL!r}"
                )

    def test_secondary_must_be_claude_opus_5(self):
        for model in REJECTED_SECONDARY_MODELS:
            with self.subTest(model=model):
                self.write_secondary(reviewer_model=model)
                self.assert_rejects(
                    f"reviewer_model {model!r} is not the required "
                    f"{SECONDARY_MODEL!r}"
                )

    def test_two_gpt_work_final_records_are_rejected(self):
        self.write_secondary(reviewer_model=PRIMARY_MODEL)
        self.assert_rejects(
            f"reviewer_model {PRIMARY_MODEL!r} is not the required "
            f"{SECONDARY_MODEL!r}"
        )

    def test_identical_reviewer_instance_ids_are_rejected(self):
        # Distinct models do not excuse reusing the same execution identity.
        self.write_pair(reviewer_instance_id="shared-instance")
        self.assert_rejects("share reviewer_instance_id 'shared-instance'")

    def test_empty_reviewer_instance_id_is_rejected(self):
        self.write_secondary(reviewer_instance_id="")
        self.assert_rejects("reviewer_instance_id is empty")

    def test_empty_primary_reviewer_instance_id_is_rejected(self):
        self.write_gpt(reviewer_instance_id="")
        self.assert_rejects("reviewer_instance_id is empty")

    def test_nonempty_fallback_reason_is_rejected(self):
        self.write_secondary(fallback_reason="FABLE_UNAVAILABLE")
        self.assert_rejects("fallback_reason must be empty")

    def test_nonempty_fallback_evidence_path_is_rejected(self):
        self.write_pair(fallback_evidence_path="fallback/x.tsv")
        self.assert_rejects("fallback_evidence_path must be empty")

    def test_nonempty_fallback_evidence_sha256_is_rejected(self):
        self.write_pair(fallback_evidence_sha256=_sha256_hex(b"x"))
        self.assert_rejects("fallback_evidence_sha256 must be empty")

    # -------------------------------------------------------------- file modes

    def test_user_writable_record_is_rejected(self):
        self.write_gpt(mode=0o644)
        self.assert_rejects("is writable (mode 0644)")

    def test_group_writable_record_is_rejected(self):
        self.write_secondary(mode=0o464)
        self.assert_rejects("is writable (mode 0464)")

    def test_other_writable_record_is_rejected(self):
        self.write_secondary(mode=0o446)
        self.assert_rejects("is writable (mode 0446)")

    def test_symlink_record_is_rejected(self):
        target = self.staging / "real-gpt.md"
        _write_readonly(target, _render(self.fields(PRIMARY_MODEL, PRIMARY_INSTANCE, {})))
        link = self.staging / "linked-gpt.md"
        os.symlink(target, link)
        self.assertTrue(os.path.islink(link))
        self.assert_rejects("is a symlink", gpt=link)

    def test_directory_record_is_rejected(self):
        self.assert_rejects("is not a regular file", gpt=self.staging)

    def test_fifo_record_is_rejected(self):
        fifo = self.staging / "fifo-gpt.md"
        os.mkfifo(fifo, 0o444)
        self.assert_rejects("is not a regular file", gpt=fifo)

    def test_absent_record_is_rejected(self):
        self.assert_rejects(
            "No such file or directory", secondary=self.staging / "absent.md"
        )

    @unittest.skipIf(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "root bypasses file permission bits",
    )
    def test_unreadable_record_is_rejected_without_a_traceback(self):
        # Mode 0o000 has no write bit, so it passes the read-only check and the
        # failure can only surface at open time. It must still be a concise
        # diagnostic, never an escaping OSError.
        self.write_gpt(mode=0o000)
        self.assert_rejects("Permission denied")

    def test_same_path_for_both_records_is_rejected(self):
        self.assert_rejects("same file", secondary=self.gpt_path)

    def test_hardlinked_record_pair_is_rejected(self):
        # Two different pathnames, one inode: the two "independent" records are
        # the same object, which the opened-object identity check must catch.
        link = self.staging / "hardlink-secondary.md"
        os.link(self.gpt_path, link)
        self.assertNotEqual(str(link), str(self.gpt_path))
        self.assert_rejects("same file", secondary=link)

    # ----------------------------------------------------------- cross-binding

    def test_records_must_agree_on_base_commit(self):
        self.write_secondary(base_commit=self.commit_root)
        self.assert_rejects("records disagree on base_commit")

    def test_records_must_agree_on_head(self):
        self.write_secondary(head_commit=self.commit_empty)
        self.assert_rejects("records disagree on head_commit")

    def test_records_must_agree_on_plan_blob_sha(self):
        self.write_secondary(plan_blob_sha256=_sha256_hex(b"other plan"))
        self.assert_rejects("records disagree on plan_blob_sha256")

    def test_records_must_agree_on_diff_sha(self):
        self.write_secondary(diff_sha256=self.diff_sha_empty)
        self.assert_rejects("records disagree on diff_sha256")

    def test_records_disagreeing_on_work_id_are_caught_by_field_validation(self):
        # The remaining bound field. A disagreement here cannot reach the
        # cross-record check because each record's work_id is first required to
        # equal --work-id, so at most one of the two can pass.
        self.write_secondary(work_id="2")
        self.assert_rejects("work_id 2 does not match --work-id=1")

    # -------------------------------------------------------------- git ranges

    def test_ancestor_other_than_expected_base_is_rejected(self):
        # Fully self-consistent record over root..head, but root is not the
        # expected base commit for this Work.
        self.write_pair(
            base_commit=self.commit_root, diff_sha256=self.diff_sha_root_head
        )
        self.assert_rejects(
            f"record base_commit {self.commit_root} is not the expected base"
        )

    def test_expected_base_not_matching_record_is_rejected(self):
        self.assert_rejects(
            f"is not the expected base {self.commit_root}",
            expected_base=self.commit_root,
        )

    def test_unknown_head_commit_is_rejected(self):
        self.write_pair(head_commit=_HEX40)
        self.assert_rejects(f"head_commit {_HEX40} does not resolve to a commit")

    def test_non_commit_head_object_is_rejected(self):
        self.write_pair(head_commit=self.plan_blob_git_sha)
        self.assert_rejects(
            f"head_commit {self.plan_blob_git_sha} does not resolve to a commit"
        )

    def test_wrong_diff_sha_is_rejected(self):
        self.write_pair(diff_sha256=_sha256_hex(b"not the diff"))
        self.assert_rejects("recomputed diff_sha256")

    def test_empty_diff_is_rejected(self):
        self.write_pair(
            head_commit=self.commit_empty, diff_sha256=self.diff_sha_empty
        )
        self.assert_rejects(
            f"diff {self.commit_base}..{self.commit_empty} is empty"
        )

    def test_base_equal_to_head_is_rejected(self):
        self.write_pair(
            head_commit=self.commit_base,
            diff_sha256=_sha256_hex(b""),
        )
        self.assert_rejects("identical; the Work range is empty")

    def test_non_ancestor_head_is_rejected(self):
        self.write_pair(
            head_commit=self.commit_side, diff_sha256=self.diff_sha_side
        )
        self.assert_rejects(f"is not an ancestor of head_commit {self.commit_side}")

    def test_non_git_repo_is_rejected(self):
        outside = self.staging / "not-a-repo"
        outside.mkdir()
        self.assert_rejects("is not a git repository", repo=outside)

    # ------------------------------------------------------------- plan blobs

    def test_absent_plan_path_is_rejected(self):
        self.assert_rejects(
            "is not tracked at the base commit",
            plan_path="docs/superpowers/plans/missing.md",
        )

    def test_plan_blob_sha_mismatch_is_rejected(self):
        self.write_pair(plan_blob_sha256=_sha256_hex(b"wrong plan bytes"))
        self.assert_rejects("recomputed plan_blob_sha256")

    def test_plan_blob_changed_at_head_is_rejected(self):
        self.write_pair(
            head_commit=self.commit_plan_changed,
            diff_sha256=self.diff_sha_plan_changed,
        )
        self.assert_rejects("changed between base and head")

    def test_absolute_plan_path_is_rejected(self):
        self.assert_rejects(
            "must be repository-relative, not absolute", plan_path="/" + PLAN_PATH
        )

    def test_parent_traversal_plan_path_is_rejected(self):
        self.assert_rejects("has a '..' component", plan_path="../" + PLAN_PATH)

    def test_interior_parent_traversal_plan_path_is_rejected(self):
        self.assert_rejects("has a '..' component", plan_path="docs/../" + PLAN_PATH)

    def test_dot_component_plan_path_is_rejected(self):
        self.assert_rejects("has a '.' component", plan_path="./" + PLAN_PATH)

    def test_empty_component_plan_path_is_rejected(self):
        self.assert_rejects(
            "has an empty component", plan_path="docs//superpowers/plans/work-1.md"
        )

    def test_empty_plan_path_is_rejected(self):
        self.assert_rejects("--plan-path must not be empty", plan_path="")

    def test_symlink_plan_blob_is_rejected(self):
        entry = _git(self.repo, "ls-tree", self.commit_base, "--", PLAN_SYMLINK_PATH)
        self.assertTrue(entry.startswith("120000 blob"), entry)
        blob = _git(self.repo, "rev-parse", f"{self.commit_base}:{PLAN_SYMLINK_PATH}")
        target_sha = _sha256_hex(
            _git(self.repo, "cat-file", "blob", blob, capture_bytes=True)
        )
        self.write_pair(plan_blob_sha256=target_sha)
        self.assert_rejects(
            "has non-regular mode 120000", plan_path=PLAN_SYMLINK_PATH
        )

    def test_directory_plan_path_is_rejected(self):
        self.assert_rejects(
            "is a tree, not a blob", plan_path="docs/superpowers/plans"
        )

    def test_symlinked_worktree_directory_does_not_reject_a_safe_plan_path(self):
        """The current worktree must not decide whether a Git path is safe.

        Everything this tool verifies is read out of a commit's tree, never off
        disk, and the lexical component rules -- no absolute path, no empty, no
        ``.``, no ``..`` -- already make repository escape impossible for a
        relative Git path. Resolving the path on disk *as well* made the verdict
        depend on mutable state: a checkout whose ``docs`` is a symlink into a
        shared directory is an ordinary layout, and here it resolves outside the
        root, so the record was rejected as an escape although its tracked plan
        blob was exactly right.

        The tree is untouched; only the worktree is rearranged. The plan blob is
        still the same object at base and head, so the verification must succeed.
        """
        copy = self.repo_copy("symlinked-worktree")
        outside = self.staging / "outside-docs"
        shutil.move(str(copy / "docs"), str(outside))
        os.symlink(outside, copy / "docs")
        # Non-vacuity: on-disk resolution really does leave the repository here.
        root = os.path.realpath(copy)
        self.assertFalse(
            os.path.realpath(copy / PLAN_PATH).startswith(root + os.sep),
            "the symlink must really resolve outside the repository",
        )
        self.assertTrue((copy / PLAN_PATH).is_file())
        self.assert_accepts_head(repo=copy)

    # --------------------------------------------------------------------- CLI

    def test_missing_required_option_is_rejected(self):
        for omitted in ("work_id", "expected_base", "plan_path", "gpt", "secondary"):
            with self.subTest(omitted=omitted):
                self.assert_argparse_rejects(**{omitted: _OMIT})

    def test_zero_work_id_flag_is_rejected(self):
        self.assert_argparse_rejects(work_id="0")

    def test_negative_work_id_flag_is_rejected(self):
        self.assert_argparse_rejects(work_id="-1")

    def test_non_numeric_work_id_flag_is_rejected(self):
        self.assert_argparse_rejects(work_id="one")

    def test_work_id_flag_with_thousands_of_digits_is_rejected(self):
        # The flag side of the same unbounded-decimal hazard. argparse owns
        # this rejection, so it is exit 2 with usage text rather than the
        # verifier's prefix -- but a traceback would be a defect either way.
        self.assert_argparse_rejects(work_id=HUGE_DIGITS)

    # Six-figure CLI values. Every one of these reaches a diagnostic through
    # string interpolation, so each is a place where "concise" quietly meant
    # "one line of 100 kB". The bound is asserted on stderr, not merely on the
    # exit code, because the exit code was always right.

    def test_huge_expected_base_flag_is_rejected_concisely(self):
        proc = self.assert_argparse_rejects(expected_base="0" * HUGE_CLI_CHARS)
        self.assertLess(
            len(proc.stderr),
            MAX_CLI_DIAGNOSTIC_BYTES,
            "argparse must not echo a 100 000-character value",
        )

    def test_huge_absolute_plan_path_is_rejected_concisely(self):
        proc = self.assert_rejects(
            "must be repository-relative", plan_path="/" + "p" * HUGE_CLI_CHARS
        )
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_huge_tracked_plan_path_is_rejected_concisely(self):
        # Lexically safe, so it survives the path rules and is interpolated into
        # a *git* diagnostic instead -- a second, separate echo of the same value.
        proc = self.assert_rejects(
            "is not tracked at the base commit", plan_path="p" * HUGE_CLI_CHARS
        )
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_huge_record_path_is_rejected_concisely(self):
        proc = self.assert_rejects(
            "cannot be opened", gpt=self.staging / ("r" * HUGE_CLI_CHARS)
        )
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_huge_repo_path_is_rejected_concisely(self):
        proc = self.assert_rejects("--repo", repo="d" * HUGE_CLI_CHARS)
        self.assertLess(len(proc.stderr), MAX_DIAGNOSTIC_BYTES)

    def test_short_expected_base_flag_is_rejected(self):
        self.assert_argparse_rejects(expected_base=self.commit_base[:12])

    def test_uppercase_expected_base_flag_is_rejected(self):
        self.assert_argparse_rejects(expected_base=self.commit_base.upper())

    def test_default_repo_is_the_current_directory(self):
        # --repo is optional and defaults to '.', which is only meaningful if
        # the verifier really resolves it against its own working directory.
        proc = self.invoke(repo=_OMIT, print_head=True, cwd=self.repo)
        self.assertEqual(
            (proc.returncode, proc.stdout),
            (0, (self.commit_head + "\n").encode()),
            f"stderr={proc.stderr.decode(errors='replace')}",
        )

    def test_default_repo_outside_a_repository_is_rejected(self):
        outside = self.staging / "default-repo-outside"
        outside.mkdir()
        proc = self.invoke(repo=_OMIT, cwd=outside)
        self.assert_rejection(proc, "is not a git repository")

    def test_verifier_script_is_executable_python(self):
        self.assertTrue(VERIFIER.is_file(), f"{VERIFIER} must exist")
        self.assertTrue(stat.S_IMODE(VERIFIER.stat().st_mode) & 0o111)

    # ------------------------------------------------------- build registration

    def cmake_configure(self, name, *extra):
        """Configure the real project out of tree, with tests on.

        Benchmarks are switched off because they are irrelevant here and cost
        configure time; everything the approval gate depends on is inside
        ``if(BUILD_TESTS)``.
        """
        build = self.staging / name
        proc = subprocess.run(
            [
                CMAKE,
                "-S",
                str(REPO_ROOT),
                "-B",
                str(build),
                "-DBUILD_TESTS=ON",
                "-DBUILD_BENCHMARKS=OFF",
                *extra,
            ],
            capture_output=True,
            timeout=600,
        )
        output = (proc.stdout + proc.stderr).decode(errors="replace")
        return build, proc.returncode, output

    @unittest.skipUnless(
        CMAKE and CTEST, "cmake and ctest are required to check the registration"
    )
    def test_cmake_requires_python3_when_tests_are_enabled(self):
        """With tests on, a missing Python 3 must fail configuration.

        The approval gate *is* this Python suite, so a build tree that quietly
        drops it still reports ``100% tests passed`` -- the one outcome a gate
        must never produce. ``CMAKE_DISABLE_FIND_PACKAGE_Python3`` reproduces the
        interpreter's absence exactly as CMake models it, without needing a
        machine that lacks one.

        Both directions are asserted: without an interpreter, configuration
        fails and says why; with one, configuration succeeds *and* the test is
        really registered.
        """
        _, status, output = self.cmake_configure(
            "cmake-no-python", "-DCMAKE_DISABLE_FIND_PACKAGE_Python3=TRUE"
        )
        self.assertNotEqual(
            status,
            0,
            f"configuration must fail rather than skip the gate; output={output!r}",
        )
        self.assertIn("VerifyWorkApproval", output)
        self.assertNotIn("skipping VerifyWorkApproval", output)

        build, status, output = self.cmake_configure("cmake-with-python")
        self.assertEqual(status, 0, f"control configuration must succeed; {output!r}")
        listed = subprocess.run(
            [CTEST, "--test-dir", str(build), "-N", "-R", "VerifyWorkApproval"],
            capture_output=True,
            timeout=300,
        )
        self.assertEqual(listed.returncode, 0)
        self.assertIn(
            "Total Tests: 1",
            listed.stdout.decode(errors="replace"),
            "the gate must be registered exactly once when Python3 is available",
        )


if __name__ == "__main__":
    unittest.main()
