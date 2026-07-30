#!/usr/bin/env python3
"""Verify the two independent approval records that gate one Work.

A Work may only unblock its successor when two independent reviewers approved
the exact same commit range over the exact same plan text. This tool refuses to
take any of that on trust: it re-resolves both commits, recomputes the SHA-256
of the real ``git diff --binary --full-index base..head`` bytes, and re-hashes
the tracked plan blob out of the base commit. A Work also cannot approve a plan
it edited, so the plan blob at head must be the same object as at base.

The Work-final reviewer pair is fixed and ordered for this project:

    --gpt        must be recorded by exactly ``gpt-5.6-sol``
    --secondary  must be recorded by exactly ``claude-opus-5``

The per-phase single-GPT review is a separate implementation checkpoint; these
two records are the Work-final cross-check artifacts. Both
``reviewer_instance_id`` values must be nonempty and different. No fallback
reviewer is accepted: all three ``fallback_*`` fields must be empty.

Standard library only, so it runs anywhere the repository is checked out.
Requires git 2.41 or newer; an older git is refused before any verification.

Usage:
    scripts/verify_work_approval.py --work-id=1 \\
        --expected-base=<40hex> \\
        --plan-path=docs/superpowers/plans/<plan>.md \\
        --gpt=<record> --secondary=<record> [--repo=.] [--print-head]

Prints nothing on success unless --print-head, which prints the verified
40-hex head commit and a newline. Every failure exits nonzero, writes a
diagnostic to stderr, and prints nothing to stdout.

Required diff semantics for record producers
--------------------------------------------
``diff_sha256`` is the SHA-256 of the exact bytes of

    git diff --binary --full-index <base>..<head>

as that command behaves with **no** Git configuration in effect beyond Git's
own defaults, and with the gitattributes stack taken from the base commit's own
tree. Nothing that changes default behaviour is added: default rename
detection, the default indent heuristic, the myers algorithm, three lines of
context and the ``a/``/``b/`` prefixes all stand.

The verifier does not run that command inside the audited repository, because
the repository's ``.git/config``, ``.git/info/attributes`` and
``refs/replace/*`` could all change its output. It builds a throwaway bare Git
directory that borrows only the audited object database and carries no
configuration of its own, and runs the command there (see ``IsolatedGit``). To
reproduce a fingerprint by hand, do the equivalent -- for example in a fresh
clone with no local configuration:

    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \\
    GIT_CONFIG_SYSTEM=/dev/null GIT_ATTR_NOSYSTEM=1 \\
    GIT_ATTR_SOURCE=<base> git -c core.attributesFile=/dev/null \\
        --no-replace-objects diff --binary --full-index <base>..<head>

Canonical record grammar
------------------------
A record is UTF-8 text, LF-terminated, with no carriage return, no blank line,
and no trailing content. It contains each of the eleven fields below exactly
once, in any order, one field per line, in one of exactly two shapes::

    <key>: <value>      nonempty value: exactly one space after the colon
    <key>:              empty value: nothing at all after the colon

A value carries no leading or trailing whitespace. Every other shape is a
rejection: a line with no colon, ``key:value``, ``key:  value``,
``key: value``-with-trailing-space, an unknown key, a repeated key (which is
what a second ``verdict`` line reduces to), or a missing key.

A record is also bounded, before any of it is read. The whole file may be at
most ``MAX_RECORD_BYTES`` (8192) bytes -- over ten times the largest legitimate
record -- and ``reviewer_instance_id``, the only free-form field, at most
``MAX_INSTANCE_ID_CHARS`` (128) characters. The file size is checked on the
descriptor that was opened, the read is bounded by that ceiling rather than by
what the file offers, and a file that changes length between the two is refused:
read-only permissions do not stop a writer that opened the file earlier from
appending through the descriptor it still holds.

That same writer can also rewrite a record *in place*, to the same length, with
equally canonical content, so a record is required to hold still for the whole
run and not merely to be the right length. Each descriptor stays open until the
verdict, the state it was validated in is kept (identity, file type, permission
bits, size, ctime, mtime), and it is compared against a fresh ``fstat`` after the
bytes are read and again before success is reported. See ``RecordHandle``.

Bounded, reaped git children
----------------------------
Every git command goes through one place, ``_git_child``: no inherited stdin, a
session of its own so the whole process group can be signalled, and both output
channels drained *concurrently* -- reading one to completion while the other
fills its pipe is a deadlock. A short command's stdout is kept only up to
``MAX_GIT_STDOUT_BYTES``; the hashed diff and blob streams are unbounded but
never held. stderr is kept only as a ``MAX_GIT_STDERR_BYTES`` prefix, in memory
rather than spooled to a temporary file, and the remainder is read and dropped.

``SIGTERM`` and ``SIGINT`` are handled rather than left to their default
disposition, which would kill this process and leave behind whatever it was in
the middle of. The handler raises, so termination unwinds the same way any
failure does: the running git child is killed by process group and reaped, the
isolated view is removed, nothing is printed to stdout, and the exit status is
the conventional ``128 + signum``.

Complete example of an accepting primary record::

    work_id: 1
    base_commit: 9ac27390e0d1b4c5aa8f3e2d1c0b9a8f7e6d5c4b
    head_commit: 3f5a1c8e7d6b4a29018f7e6d5c4b3a2918f7e6d5
    plan_blob_sha256: 5f2c9a1e8b7d6c4a3928f1e0d9c8b7a695847362514f3e2d1c0b9a8f7e6d5c4b3
    diff_sha256: a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
    reviewer_model: gpt-5.6-sol
    reviewer_instance_id: gpt-5.6-sol-review-2026-07-29T09:11:04Z-7c1
    fallback_reason:
    fallback_evidence_path:
    fallback_evidence_sha256:
    verdict: APPROVE

The secondary record carries ``reviewer_model: claude-opus-5`` and is
byte-identical except for its own distinct ``reviewer_instance_id``, for
example ``claude-opus-5-review-2026-07-29T10:02:47Z-b93``.
"""

import argparse
import errno
import hashlib
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack

# Fixed, ordered Work-final reviewer pair.
PRIMARY_MODEL = "gpt-5.6-sol"
SECONDARY_MODEL = "claude-opus-5"

RECORD_FIELDS = (
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

# Fields both records must agree on: they must approve one identical Work range
# over one identical plan.
BOUND_FIELDS = (
    "work_id",
    "base_commit",
    "head_commit",
    "plan_blob_sha256",
    "diff_sha256",
)

FALLBACK_FIELDS = (
    "fallback_reason",
    "fallback_evidence_path",
    "fallback_evidence_sha256",
)

HEX40_RE = re.compile(r"\A[0-9a-f]{40}\Z")
HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
KEY_RE = re.compile(r"\A[a-z][a-z0-9_]*\Z")
POSITIVE_INT_RE = re.compile(r"\A[1-9][0-9]*\Z")

# Regular file blobs only: 120000 is a symlink and 160000 a submodule gitlink.
REGULAR_BLOB_MODES = frozenset({"100644", "100755"})

VERDICT = "APPROVE"

# The floor is set by GIT_ATTR_SOURCE, the mechanism that pins the gitattributes
# stack to the base commit's own tree. It is a git 2.41 feature: 2.40 added only
# `git check-attr --source`, and neither the `--attr-source` global option nor
# this environment variable exists there. Every other capability the isolated
# view needs is older: GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM (2.32),
# `rev-parse --path-format` (2.31), `rev-parse --show-object-format` (2.29) and
# `--end-of-options` (2.24). The version is checked rather than hoped for
# because an older git *ignores* GIT_ATTR_SOURCE silently -- it fails no
# louder than a typo -- and would hash a different, unreproducible diff.
MIN_GIT_VERSION = (2, 41, 0)

# Anchored at both ends, because a version is what the whole line says and not
# what its prefix says: an unanchored parse reads "2.41.0" out of
# `git version 2.41.0 HACKED` and then trusts that binary to behave like git
# 2.41.0. Two documented vendor tails are accepted, and nothing else is:
#
#   .windows.1, .rc1.29.gc57b6d9c1e   dotted vendor/build tail (Git for Windows,
#                                     and a git built from a tagged checkout)
#   (Apple Git-154)                   one parenthesised vendor note
#
# Both tails are themselves strict grammars, because a loose tail reopens the
# hole the anchors closed one character further right. Each dotted segment is a
# nonempty run of alphanumerics, so a doubled separator (`2.41.0..windows.1`) and
# a dangling one (`2.41.0.`) are refused. Neither tail can start the version over
# either, so `2.41.0 (note) and then some`, `2.41.0-not-really` and a trailing
# bare word are all refused. No real `git --version` prints any of these shapes,
# and a binary that does is not the git whose behaviour the byte contract depends
# on.
#
# The parenthesised note is captured rather than constrained in the pattern, and
# `require_git_version` refuses an empty or whitespace-only one. A pattern that
# demanded a non-space character inside `[^()]*` on both sides of it would have to
# try every way of splitting the note, which is quadratic in its length on
# exactly the inputs that fail -- a hostile version string is the last place to
# put a super-linear parse.
GIT_VERSION_RE = re.compile(
    r"\Agit version (\d+)\.(\d+)(?:\.(\d+))?"
    r"(?:\.[0-9A-Za-z]+)*"
    r"(?: \((?P<note>[^()]*)\))?"
    r"\Z"
)
VERSION_COMPONENT_GROUPS = (1, 2, 3)

# Decimal input is bounded before it is converted. CPython refuses to build an
# int from more than 4300 digits, so an unbounded conversion turns hostile or
# merely broken input into an escaping ValueError instead of a diagnostic. The
# accepted grammar is unchanged -- a work id still matches `[1-9][0-9]*` and a
# version component is still decimal -- these limits only put a practical
# ceiling on how long such a value may be. 18 digits covers any signed 64-bit
# work id; 9 covers any version component git will plausibly ever ship.
MAX_WORK_ID_DIGITS = 18
MAX_VERSION_COMPONENT_DIGITS = 9

# Untrusted text is clipped before it reaches a diagnostic: "concise" has to
# mean bounded, not merely single-line. The limit is above the longest value a
# real diagnostic quotes in full (a 64-hex digest).
MAX_QUOTED_CHARS = 80

# A record is bounded before a single byte of it is allocated. The canonical
# record is eleven short lines -- two 40-hex commits, two 64-hex digests, a fixed
# model name, a capped instance id, three empty fallback fields and a verdict --
# so under 700 bytes; 8 KiB is over ten times that. The point of the ceiling is
# not to be tight but to be *finite*: without it, whatever a descriptor happens
# to deliver decides how much memory this process asks for, and a read-only mode
# is no promise about size (a writer holding a descriptor from before the chmod
# can still append).
MAX_RECORD_BYTES = 8192
RECORD_READ_CHUNK = 4096

# reviewer_instance_id is the one free-form field: every other value is pinned to
# hex, to an exact string, or to empty. Real ids are model name plus timestamp
# plus a short nonce, around 40 characters, so 128 is generous.
MAX_INSTANCE_ID_CHARS = 128

# Git output that is hashed is never held: a --binary diff over a large
# incompressible file is longer than the file, so buffering it would make peak
# memory a function of the Work range. Only the digest and the length are kept.
GIT_READ_CHUNK = 1 << 20

# A git child may print as much as it likes on either channel, so both are
# bounded and neither is ever allowed to fill.
#
# stderr is drained *concurrently* with stdout -- a pipe left unread while the
# other channel is drained deadlocks -- and only this prefix is retained; the
# rest is read and dropped. Only the first line of the prefix, clipped, reaches
# the diagnostic. It is deliberately kept in memory: spooling it to a temporary
# file avoids the deadlock but pays for it in unbounded disk, written wherever
# the process happens to put temporary files.
MAX_GIT_STDERR_BYTES = 4096

# The ceiling on what a *short* git command may say. `rev-parse`, `ls-tree` on
# one literal path, `merge-base` and `--version` all answer in well under a line,
# so this is generous -- the point is that the size of the answer is decided here
# and not by whichever binary is first on PATH. A command that exceeds it is not
# answering the question that was asked, so its child is killed and the run
# fails: it is never partially read and never trusted.
MAX_GIT_STDOUT_BYTES = 65536


class VerificationError(Exception):
    """A checked precondition failed; the caller reports it and exits nonzero."""


class Terminated(Exception):
    """A termination signal arrived; unwind, clean up, and exit nonzero.

    Raised from the signal handler so an interruption travels the same path as
    any other failure: the ``ExitStack`` in ``verify`` unwinds, the isolated view
    is removed, and every git child is killed and reaped on the way out.
    """

    def __init__(self, signum):
        self.signum = signum
        self.name = signal.Signals(signum).name
        super().__init__(self.name)


def fail(message):
    raise VerificationError(message)


def _version_text(version):
    return ".".join(str(part) for part in version)


def _clip(text):
    """A bounded rendering of untrusted text, for one-line diagnostics."""
    if len(text) <= MAX_QUOTED_CHARS:
        return text
    return f"{text[:MAX_QUOTED_CHARS]}... ({len(text)} characters)"


def _quoted(text):
    """``repr`` of a *clipped* value: quoting must not undo the bound.

    Every diagnostic that echoes something the caller chose -- an option value, a
    path, a record field, a git version string -- goes through here. A 100 000
    character ``--plan-path`` is a plausible thing to be handed, and interpolating
    it whole turns a concise diagnostic into a 100 kB one.
    """
    return repr(_clip(str(text)))


def _oserror_text(exc):
    return exc.strerror or str(exc)


# ---------------------------------------------------------------- git plumbing


def _base_env():
    """A child environment carrying no inherited Git input at all.

    Deny-by-default rather than a deny list: every ``GIT_*`` variable is
    dropped, so ``GIT_DIR``, ``GIT_OBJECT_DIRECTORY``,
    ``GIT_ALTERNATE_OBJECT_DIRECTORIES``, ``GIT_EXTERNAL_DIFF``,
    ``GIT_ATTR_SOURCE``, ``GIT_REPLACE_REF_BASE``, ``GIT_CONFIG_PARAMETERS``
    and the ``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY_n``/``GIT_CONFIG_VALUE_n``
    family all go without being enumerated. That leaves no list to keep in sync
    with future Git releases, and in particular no attacker-supplied count is
    ever iterated: the real, finite environment is what gets scanned.
    """
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("GIT_")
    }
    # Pathspecs are literal repository paths, never globs, and nothing here may
    # block on a credential prompt or take a lock.
    env["GIT_LITERAL_PATHSPECS"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def _isolated_env(attr_source=None):
    """``_base_env`` with every remaining ambient configuration source emptied.

    Global and system configuration are redirected to the null device and the
    system attributes file is switched off, so nothing outside the isolated
    view can reach the diff. ``attr_source`` pins the gitattributes stack to a
    tree-ish -- the base commit -- instead of a working tree that does not
    exist in a bare view.
    """
    env = _base_env()
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_ATTR_NOSYSTEM"] = "1"
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    if attr_source is not None:
        env["GIT_ATTR_SOURCE"] = attr_source
    return env


def _git_failure(label, stderr, returncode):
    """One bounded line about a git failure, whatever git chose to print."""
    lines = stderr.decode("utf-8", "replace").strip().splitlines()
    detail = _clip(lines[0]) if lines else f"exit {returncode}"
    return f"git {label} failed: {detail}"


class _TooMuchOutput(Exception):
    """A short git command said more than a short git command may say."""

    def __init__(self, limit):
        self.limit = limit
        super().__init__(limit)


class _CollectingSink:
    """Keeps a short command's whole stdout, provided it stays under a bound.

    The bound is the point. Without one, the size of the reply decides how much
    memory this process asks for, which is a decision that belongs to the
    verifier and not to whatever binary answered.
    """

    def __init__(self, limit=MAX_GIT_STDOUT_BYTES):
        self.limit = limit
        self._chunks = []
        self.size = 0

    def feed(self, chunk):
        if self.size + len(chunk) > self.limit:
            raise _TooMuchOutput(self.limit)
        self._chunks.append(chunk)
        self.size += len(chunk)

    def value(self):
        return b"".join(self._chunks)


class _DigestSink:
    """Hashes stdout and counts it, retaining none of it.

    A ``--binary`` patch over a large incompressible file is longer than the file
    itself, so this channel cannot be bounded -- but it can be *unheld*. The
    caller gets the digest and the length, which is everything it needs: "the
    diff is nonempty" is a checked precondition and there is no buffer left to
    measure.
    """

    def __init__(self):
        self._digest = hashlib.sha256()
        self.size = 0

    def feed(self, chunk):
        self._digest.update(chunk)
        self.size += len(chunk)

    def hexdigest(self):
        return self._digest.hexdigest()


class _GitResult:
    """What a git child said, in bounded form."""

    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# Every git child this process has started and not yet reaped. `_git_child`'s
# `finally` normally empties this as each command ends, including when a
# termination signal unwinds through it. The registry covers the one case that
# ordering cannot: a first signal arriving *inside* `_reap_child`, which
# interrupts the `waitpid` it was in the middle of. `_reap_all_children` then
# finishes the job on the way out of `main`.
_LIVE_CHILDREN = set()


def _reap_child(proc):
    """Kill a git child's whole process group if it is still running, then reap it.

    The *group* matters. A git command can start children of its own -- a pager, a
    textconv filter, a shim wrapping the real git -- and killing only the direct
    child orphans them. Every child is started with ``start_new_session=True``, so
    its pid is also its process group id and this signal reaches everything it
    spawned. Reaping then follows unconditionally: an unreaped child is a zombie
    for as long as this process lives.
    """
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
    try:
        proc.wait()
    except OSError:
        pass
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    _LIVE_CHILDREN.discard(proc)


def _reap_all_children():
    for proc in list(_LIVE_CHILDREN):
        _reap_child(proc)


def _drain(proc, sink):
    """Read both of a child's channels until they close, favouring neither.

    A child writing to two pipes fills whichever one is not being read, and then
    blocks forever: draining stdout to completion before looking at stderr (or
    the reverse) is the classic way to hang. Both are therefore polled together
    and read one syscall at a time, so a full pipe is always someone's next read.

    stdout goes to ``sink``, which either bounds it or hashes it. stderr is kept
    only as a prefix: the remainder is read and dropped, which is what keeps the
    child unblocked without keeping its output.
    """
    stderr_prefix = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ, sink)
        selector.register(proc.stderr, selectors.EVENT_READ, None)
        while selector.get_map():
            for key, _ in selector.select():
                # read1 returns as soon as one raw read does, so a channel with
                # less than a chunk available never blocks the other one.
                chunk = key.fileobj.read1(GIT_READ_CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data is None:
                    room = MAX_GIT_STDERR_BYTES - len(stderr_prefix)
                    if room > 0:
                        stderr_prefix += chunk[:room]
                else:
                    key.data.feed(chunk)
    return bytes(stderr_prefix)


def _git_child(args, env, label, sink):
    """Run one git command with both channels bounded, and always reap it.

    Returns ``(returncode, stderr_prefix)``; stdout has already gone wherever
    ``sink`` puts it, which is the caller's business and never this function's.

    The single place a git process is created, so the guarantees hold for every
    git call this tool makes: no inherited stdin, a session of its own so the
    whole process group can be signalled, both channels drained concurrently,
    stderr retained only as a prefix, and the child killed and reaped on every
    exit path -- ordinary completion, a diagnosed failure, or a termination
    signal arriving mid-read.
    """
    try:
        proc = subprocess.Popen(
            ["git", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        fail(f"cannot run git {label}: {_oserror_text(exc)}")
    _LIVE_CHILDREN.add(proc)
    try:
        try:
            stderr = _drain(proc, sink)
        except _TooMuchOutput as exc:
            fail(
                f"git {label} produced more than {exc.limit} bytes on stdout; at "
                f"most {exc.limit} bytes are accepted from this command"
            )
        except OSError as exc:
            fail(f"cannot read git {label} output: {_oserror_text(exc)}")
        return proc.wait(), stderr
    finally:
        _reap_child(proc)


def run_git(args, env, label, allow_failure=False):
    """Run a git command whose output is known to be short, and keep it.

    Only for commands that answer a question in well under a line --
    ``rev-parse``, ``ls-tree`` on a single path, ``merge-base``, ``--version``.
    Anything whose size is a function of the audited history goes through
    ``stream_git_sha256`` instead.

    ``allow_failure`` covers commands whose nonzero exit *is* an answer
    (``merge-base --is-ancestor``). It does not cover a flood: output past the
    ceiling means the command is not answering the question asked, so that is a
    hard failure whatever the caller expected of the exit code.
    """
    sink = _CollectingSink()
    returncode, stderr = _git_child(args, env, label, sink)
    if returncode != 0 and not allow_failure:
        fail(_git_failure(label, stderr, returncode))
    return _GitResult(returncode, sink.value(), stderr)


def stream_git_sha256(args, env, label):
    """Hash a git command's stdout without ever holding it in memory.

    Returns ``(sha256_hex, byte_count)``. Every failure -- a git that cannot be
    started, a git that exits nonzero, a broken stream mid-read -- ends as a
    ``VerificationError``, never as a traceback.
    """
    sink = _DigestSink()
    returncode, stderr = _git_child(args, env, label, sink)
    if returncode != 0:
        fail(_git_failure(label, stderr, returncode))
    return sink.hexdigest(), sink.size


def repo_git(repo, *args, label=None, allow_failure=False):
    """Ask the audited repository about itself.

    Only used to locate the repository and its object database. Ambient global
    configuration is deliberately *kept* for these calls, because dropping it
    would also drop ``safe.directory`` and the tool would start refusing
    repositories in CI containers. Nothing these calls return can change the
    verified bytes: they yield paths and the object format, and every object is
    then read through the isolated view.
    """
    return run_git(
        ["-C", repo, "--no-pager", *args],
        _base_env(),
        label or args[0],
        allow_failure=allow_failure,
    )


def _stdout_line(proc):
    return proc.stdout.decode("utf-8", "replace").strip()


def require_git_version():
    """Refuse a git that cannot provide the isolation this tool relies on.

    The whole response is required to be one line that is *entirely* a version:
    a first line that parses says nothing about the lines after it, and neither
    does a prefix about the text after it.
    """
    proc = run_git(["--version"], _base_env(), "version")
    lines = proc.stdout.decode("utf-8", "replace").splitlines()
    if len(lines) != 1:
        fail(
            f"git --version produced {len(lines)} lines; exactly one is required"
        )
    text = lines[0].strip()
    match = GIT_VERSION_RE.match(text)
    # An empty or whitespace-only vendor note is not a shape any git prints; it
    # is checked here rather than in the pattern to keep the parse linear.
    if not match or (
        match.group("note") is not None and not match.group("note").strip()
    ):
        fail(f"cannot parse a git version from {_quoted(text)}")
    components = tuple(match.group(group) for group in VERSION_COMPONENT_GROUPS)
    for part in components:
        # Bounded before conversion: whatever printed this is not trusted to
        # have printed a number an int can hold.
        if part is not None and len(part) > MAX_VERSION_COMPONENT_DIGITS:
            fail(
                "git reported a version component with {} digits; at most {} "
                "are accepted".format(len(part), MAX_VERSION_COMPONENT_DIGITS)
            )
    found = tuple(int(part) if part else 0 for part in components)
    if found < MIN_GIT_VERSION:
        fail(
            "git {} is too old: pinning the gitattributes stack to the base "
            "commit needs GIT_ATTR_SOURCE, which arrived in git 2.41 and is "
            "silently ignored by every earlier git, so git >= {} is required "
            "or diff_sha256 is not reproducible".format(
                _version_text(found), _version_text(MIN_GIT_VERSION)
            )
        )
    return found


def require_git_repository(repo):
    if not os.path.isdir(repo):
        fail(f"--repo {_quoted(repo)} is not a directory")
    proc = repo_git(repo, "rev-parse", "--git-dir", allow_failure=True)
    if proc.returncode != 0:
        fail(f"--repo {_quoted(repo)} is not a git repository")


class IsolatedGit:
    """A throwaway bare Git directory that borrows only the audited objects.

    Everything that can steer the verified bytes -- configuration, attributes,
    replacement refs -- lives in this directory, which the verifier writes
    itself and which contains no diff settings whatsoever. The audited
    repository contributes exactly one thing: its object database, reached
    through ``objects/info/alternates``. So the repository's own
    ``.git/config``, ``.git/info/attributes`` and ``refs/replace/*``, the user's
    global and system configuration, and the process environment are all out of
    the picture, and what remains is Git's default behaviour -- which is
    precisely the byte contract: a clean-configuration
    ``git diff --binary --full-index base..head``.

    This replaces the earlier approach of pinning individual ``diff.*`` knobs.
    Enumerating knobs could never cover an *arbitrary* named diff driver chosen
    by a committed ``.gitattributes`` file, and forcing options such as
    ``--no-renames`` bought determinism by changing the very semantics the
    fingerprint is supposed to describe.
    """

    def __init__(self, git_dir):
        self.git_dir = git_dir

    def _argv(self, args):
        return [
            "--git-dir",
            self.git_dir,
            "--no-pager",
            "--no-replace-objects",
            *args,
        ]

    def run(self, *args, allow_failure=False, attr_source=None, label=None):
        return run_git(
            self._argv(args),
            _isolated_env(attr_source),
            label or args[0],
            allow_failure=allow_failure,
        )

    def stream_sha256(self, *args, attr_source=None, label=None):
        """Same isolation, for output that must never be buffered."""
        return stream_git_sha256(
            self._argv(args), _isolated_env(attr_source), label or args[0]
        )


# The view is created with explicit modes because both mkdtemp and mkdir mask
# the mode they are given. Under a restrictive umask -- 0777 is legal -- an
# unguarded view lands as mode 000: the verifier cannot finish writing it and
# git cannot read it. The modes are the tightest that work, since only this
# process ever opens the view.
_VIEW_DIR_MODE = 0o700
_VIEW_FILE_MODE = 0o600


def _make_view_dir(path):
    os.mkdir(path)
    os.chmod(path, _VIEW_DIR_MODE)


def _write_view_file(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, _VIEW_FILE_MODE)


def _remove_view(git_dir):
    """Remove the isolated view, and never hide a failure to do so.

    Suppressing the error would leave a directory behind while the run reported
    success, so the leak would be invisible in exactly the case where it
    happened. It is reported as an ordinary one-line diagnostic instead, which
    also makes the run fail -- the right direction for an audit gate that could
    not clean up after itself.
    """
    try:
        shutil.rmtree(git_dir)
    except OSError as exc:
        fail(
            f"the isolated git view {git_dir} could not be removed: "
            f"{_oserror_text(exc)}"
        )
    if os.path.lexists(git_dir):
        fail(f"the isolated git view {git_dir} could not be removed")


def isolated_view(stack, repo):
    """Build the isolated view over the audited repository's object database."""
    objects = _stdout_line(
        repo_git(
            repo,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
            label="rev-parse",
        )
    )
    if not objects:
        fail("cannot locate the object database of --repo")
    if not os.path.isdir(objects):
        fail(f"object database {_quoted(objects)} is not a directory")
    # objects/info/alternates is line-based; '#' starts a comment and '"' a
    # quoted path, so a path Git would read back as something else must be
    # refused instead of silently pointing at a different object database.
    if objects[0] in "#\"" or "\n" in objects:
        fail(
            f"object database path {_quoted(objects)} cannot be expressed as an "
            "alternate"
        )
    object_format = _stdout_line(
        repo_git(repo, "rev-parse", "--show-object-format", label="rev-parse")
    )
    if object_format not in ("sha1", "sha256"):
        fail(f"--repo uses unsupported object format {_quoted(object_format)}")

    # No diff, color or algorithm settings: Git's defaults are the contract.
    # core.attributesFile is pinned only because leaving it unset falls back to
    # $XDG_CONFIG_HOME/git/attributes, which is ambient state rather than a
    # default. There are no refs, hence no refs/replace/*.
    config = [
        "[core]\n",
        "\trepositoryformatversion = {}\n".format(0 if object_format == "sha1" else 1),
        "\tbare = true\n",
        "\tattributesFile = {}\n".format(os.devnull),
    ]
    if object_format != "sha1":
        config.append("[extensions]\n\tobjectformat = {}\n".format(object_format))

    # A read-only or full temporary directory is an ordinary operational
    # failure, so it is diagnosed rather than traced. Removal is registered
    # before anything is written into the view, so a failure part-way through
    # building it cannot leave one behind either.
    try:
        git_dir = tempfile.mkdtemp(prefix="verify-work-approval-view-")
    except OSError as exc:
        fail(f"cannot create the isolated git view: {_oserror_text(exc)}")
    stack.callback(_remove_view, git_dir)
    try:
        os.chmod(git_dir, _VIEW_DIR_MODE)
        _make_view_dir(os.path.join(git_dir, "refs"))
        _make_view_dir(os.path.join(git_dir, "objects"))
        _make_view_dir(os.path.join(git_dir, "objects", "info"))
        _write_view_file(os.path.join(git_dir, "HEAD"), "ref: refs/heads/isolated\n")
        _write_view_file(os.path.join(git_dir, "config"), "".join(config))
        _write_view_file(
            os.path.join(git_dir, "objects", "info", "alternates"), objects + "\n"
        )
    except OSError as exc:
        fail(f"cannot populate the isolated git view: {_oserror_text(exc)}")
    return IsolatedGit(git_dir)


def resolve_commit(view, label, sha):
    """Require sha to name an existing commit object that resolves to itself."""
    proc = view.run(
        "rev-parse", "--verify", "--end-of-options", f"{sha}^{{commit}}",
        allow_failure=True,
    )
    if proc.returncode != 0:
        fail(f"{label} {sha} does not resolve to a commit in this repository")
    resolved = _stdout_line(proc)
    if resolved != sha:
        fail(f"{label} {sha} resolved to {resolved}, not to itself")
    return resolved


def range_diff_digest(view, base, head):
    """The digest and length of the exact bytes ``diff_sha256`` covers.

    No option that changes default behaviour is passed, so these are the bytes
    of a clean-configuration ``git diff --binary --full-index base..head``. The
    gitattributes stack is pinned to the base commit's tree, which is both
    deterministic and what a clean checkout of base would have used.

    The bytes are streamed, so a Work range containing large binary files costs
    the same memory as an empty one. The length comes back because "the diff is
    nonempty" is a checked precondition and there is no buffer left to measure.
    """
    return view.stream_sha256(
        "diff", "--binary", "--full-index", f"{base}..{head}",
        attr_source=base, label="diff",
    )


def blob_digest(view, blob):
    """The digest and length of a blob's exact bytes, streamed like the diff."""
    return view.stream_sha256("cat-file", "blob", blob, label="cat-file")


def tree_blob(view, commit, path, label):
    """Return the git blob id of a tracked regular file at commit."""
    proc = view.run(
        "ls-tree", "-z", "--full-tree", commit, "--", path, label="ls-tree"
    )
    entries = [chunk for chunk in proc.stdout.split(b"\0") if chunk]
    if not entries:
        fail(f"plan path {_quoted(path)} is not tracked at the {label}")
    if len(entries) != 1:
        fail(f"plan path {_quoted(path)} matched {len(entries)} entries at the {label}")
    meta, tab, name = entries[0].partition(b"\t")
    if not tab:
        fail(f"unparsable git ls-tree entry at the {label}")
    parts = meta.split(b" ")
    if len(parts) != 3:
        fail(f"unparsable git ls-tree entry at the {label}")
    mode, obj_type, blob = (part.decode("utf-8", "replace") for part in parts)
    if name.decode("utf-8", "replace") != path:
        fail(f"git ls-tree returned {_quoted(name)} for plan path {_quoted(path)}")
    if obj_type != "blob":
        fail(f"plan path {_quoted(path)} is a {obj_type}, not a blob, at the {label}")
    if mode not in REGULAR_BLOB_MODES:
        fail(f"plan path {_quoted(path)} has non-regular mode {mode} at the {label}")
    return blob


# ------------------------------------------------------------- record access

# O_NOFOLLOW refuses a symlink at the final component instead of following it.
# O_NONBLOCK keeps the open from blocking on a FIFO or a device that fstat is
# about to reject anyway.
_OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_OPEN_FLAGS = (
    os.O_RDONLY
    | _OPEN_NOFOLLOW
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
# Linux and macOS report ELOOP for O_NOFOLLOW on a symlink; FreeBSD uses EMLINK.
_SYMLINK_ERRNOS = frozenset(
    code for code in (getattr(errno, "ELOOP", None), getattr(errno, "EMLINK", None))
    if code is not None
)


# The state of the opened object that is snapshotted at validation and required
# to still hold later. Identity answers "is this the same file"; the file type and
# the permission bits are the two properties that were *validated*, so they are
# also the two that must not drift; the size and the two timestamps are what an
# in-place rewrite moves. A same-length rewrite through a descriptor retained
# from before the ``chmod`` changes neither the size nor the identity, and is
# caught by nothing except the times.
_RECORD_STAT_FIELDS = (
    ("device", lambda st: st.st_dev),
    ("inode", lambda st: st.st_ino),
    ("file type", lambda st: stat.S_IFMT(st.st_mode)),
    ("permissions", lambda st: stat.S_IMODE(st.st_mode)),
    ("size", lambda st: st.st_size),
    ("inode change time", lambda st: st.st_ctime_ns),
    ("modification time", lambda st: st.st_mtime_ns),
)


def _record_snapshot(st):
    return tuple(read(st) for _, read in _RECORD_STAT_FIELDS)


class RecordHandle:
    """One approval record, opened once, with the state it was validated in.

    Validating a pathname, closing that check, and later reopening the same
    pathname is a time-of-check/time-of-use gap: whatever the second open lands
    on is what actually gets read. So the file is opened once, the *opened
    object* is validated through ``fstat`` on that descriptor, every read comes
    from that same descriptor, and the identity that proves the two records are
    different files comes from the same ``fstat``.

    The descriptor alone is still not enough, because a read-only mode is not a
    promise that the object behind it holds still: a writer that opened the file
    before the ``chmod`` keeps a writable descriptor across it. That is why the
    validated state is *kept* -- see ``check_unchanged``.
    """

    def __init__(self, label, raw, fd, st):
        self.label = label
        self.raw = raw
        self.fd = fd
        self.identity = (st.st_dev, st.st_ino)
        self.size = st.st_size
        self.snapshot = _record_snapshot(st)

    def _name(self):
        return f"--{self.label} {_quoted(self.raw)}"

    def check_unchanged(self):
        """Require the opened object to still be exactly what was validated.

        Called after the bytes are read and again before the verdict is issued.
        The size comparison in ``read`` only sees a record that grew or shrank; a
        writer holding a descriptor from before the ``chmod`` can rewrite the
        record *in place*, to the same length, with equally canonical content, at
        any point during the run. Then the file the audit trail points at is not
        the file the verdict was issued about -- which is the whole thing this
        gate exists to prevent -- and the only evidence is the state of the
        object itself.

        Because the snapshot covers the file type and the permission bits, and
        those were validated as "regular" and "read-only" when it was taken,
        equality with it also re-establishes both of those.
        """
        try:
            st = os.fstat(self.fd)
        except OSError as exc:
            fail(f"{self._name()} cannot be re-inspected: {_oserror_text(exc)}")
        current = _record_snapshot(st)
        if current == self.snapshot:
            return
        changed = ", ".join(
            name
            for (name, _), before, after in zip(
                _RECORD_STAT_FIELDS, self.snapshot, current
            )
            if before != after
        )
        fail(
            f"{self._name()} changed while it was being verified ({changed}); an "
            "approval record must not change between validation and the verdict"
        )

    def read(self):
        """Read the validated descriptor, bounded by what was validated.

        At most ``MAX_RECORD_BYTES + 1`` bytes are read, so the ceiling holds even
        if the object grew after ``fstat`` measured it, and the total is required
        to equal the size that was validated. A record that changed length
        between the check and the read is refused rather than parsed: whatever it
        is now, it is not the object whose size and mode were approved. The
        stability check then covers the mutations a length comparison cannot see.
        """
        chunks = []
        remaining = MAX_RECORD_BYTES + 1
        read = 0
        try:
            while remaining > 0:
                chunk = os.read(self.fd, min(RECORD_READ_CHUNK, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                read += len(chunk)
                remaining -= len(chunk)
        except OSError as exc:
            fail(f"{self._name()} cannot be read: {_oserror_text(exc)}")
        if read > MAX_RECORD_BYTES:
            fail(
                f"{self._name()} delivered more than {MAX_RECORD_BYTES} bytes; at "
                f"most {MAX_RECORD_BYTES} bytes are accepted for an approval record"
            )
        if read != self.size:
            fail(
                f"{self._name()} changed length while it was being read "
                f"({self.size} bytes when checked, {read} bytes read)"
            )
        self.check_unchanged()
        return b"".join(chunks)


def open_record(stack, label, raw):
    """Open a record exactly once and validate the object that was opened.

    The size of the opened object is checked here, before anything is read,
    because a read-only mode is not a promise about size: a writer that opened
    the file before the ``chmod`` still holds a writable descriptor and can keep
    appending through it. Without this the file decides how much memory the
    process asks for.

    Returns a ``RecordHandle``; the descriptor is closed by ``stack``.
    """
    if raw == "":
        fail(f"--{label} must not be empty")
    name = f"--{label} {_quoted(raw)}"
    try:
        fd = os.open(raw, _OPEN_FLAGS)
    except OSError as exc:
        if exc.errno in _SYMLINK_ERRNOS:
            fail(f"{name} is a symlink; approval records must be canonical")
        fail(f"{name} cannot be opened: {_oserror_text(exc)}")
    stack.callback(os.close, fd)
    try:
        st = os.fstat(fd)
    except OSError as exc:
        fail(f"{name} cannot be inspected: {_oserror_text(exc)}")
    if not _OPEN_NOFOLLOW:
        # Only reachable where the platform lacks O_NOFOLLOW. lstat can fail on
        # its own -- a vanished path, a permission change -- and that must stay
        # a one-line diagnostic rather than an escaping OSError.
        try:
            link_mode = os.lstat(raw).st_mode
        except OSError as exc:
            fail(f"{name} cannot be inspected: {_oserror_text(exc)}")
        if stat.S_ISLNK(link_mode):
            fail(f"{name} is a symlink; approval records must be canonical")
    if not stat.S_ISREG(st.st_mode):
        fail(f"{name} is not a regular file")
    if st.st_mode & 0o222:
        fail(
            f"{name} is writable (mode {stat.S_IMODE(st.st_mode):04o}); "
            "approval records must be read-only"
        )
    if st.st_size > MAX_RECORD_BYTES:
        fail(
            f"{name} is {st.st_size} bytes; at most {MAX_RECORD_BYTES} bytes are "
            "accepted for an approval record"
        )
    return RecordHandle(label, raw, fd, st)


def parse_record(label, data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} record is not valid UTF-8: {exc}")
    if "\r" in text:
        fail(f"{label} record contains a carriage return")
    if not text.endswith("\n"):
        fail(f"{label} record is empty or lacks a final newline")

    fields = {}
    for number, line in enumerate(text[:-1].split("\n"), start=1):
        if line == "":
            fail(f"{label} record line {number} is blank")
        key, colon, rest = line.partition(":")
        if not colon:
            fail(f"{label} record line {number} is not a 'key: value' line")
        if not KEY_RE.match(key):
            fail(f"{label} record line {number} has malformed key {_quoted(key)}")
        if key not in RECORD_FIELDS:
            fail(f"{label} record has unknown field {_quoted(key)}")
        if key in fields:
            fail(f"{label} record repeats field {key!r}")
        if rest == "":
            value = ""
        elif rest.startswith(" "):
            value = rest[1:]
            if value == "" or value != value.strip():
                fail(f"{label} record field {key!r} has malformed surrounding space")
        else:
            fail(f"{label} record field {key!r} needs exactly one space after ':'")
        fields[key] = value

    missing = [key for key in RECORD_FIELDS if key not in fields]
    if missing:
        fail(f"{label} record is missing field(s): {', '.join(missing)}")
    return fields


def validate_record(label, fields, expected_model, work_id):
    raw_work_id = fields["work_id"]
    if not POSITIVE_INT_RE.match(raw_work_id):
        fail(f"{label} record work_id {_quoted(raw_work_id)} is not a positive integer")
    # The grammar above accepts any number of digits, so the length is checked
    # before the conversion rather than after it fails.
    if len(raw_work_id) > MAX_WORK_ID_DIGITS:
        fail(
            f"{label} record work_id has {len(raw_work_id)} digits; at most "
            f"{MAX_WORK_ID_DIGITS} are accepted"
        )
    if int(raw_work_id) != work_id:
        fail(
            f"{label} record work_id {raw_work_id} does not match "
            f"--work-id={work_id}"
        )
    for key in ("base_commit", "head_commit"):
        if not HEX40_RE.match(fields[key]):
            fail(
                f"{label} record {key} {_quoted(fields[key])} is not full "
                "lowercase 40-hex"
            )
    for key in ("plan_blob_sha256", "diff_sha256"):
        if not HEX64_RE.match(fields[key]):
            fail(
                f"{label} record {key} {_quoted(fields[key])} is not full "
                "lowercase 64-hex"
            )
    # Exact per-slot match: no prefix, no case folding, no fallback model.
    if fields["reviewer_model"] != expected_model:
        fail(
            f"{label} record reviewer_model {_quoted(fields['reviewer_model'])} is "
            f"not the required {expected_model!r}"
        )
    instance_id = fields["reviewer_instance_id"]
    if instance_id == "":
        fail(f"{label} record reviewer_instance_id is empty")
    # The only free-form field, so the only one that needs a length of its own.
    if len(instance_id) > MAX_INSTANCE_ID_CHARS:
        fail(
            f"{label} record reviewer_instance_id has {len(instance_id)} "
            f"characters; at most {MAX_INSTANCE_ID_CHARS} characters are accepted"
        )
    for key in FALLBACK_FIELDS:
        if fields[key] != "":
            fail(
                f"{label} record {key} must be empty: the fixed "
                f"{PRIMARY_MODEL}/{SECONDARY_MODEL} reviewer pair has no fallback"
            )
    if fields["verdict"] != VERDICT:
        fail(
            f"{label} record verdict {_quoted(fields['verdict'])} is not exactly "
            f"{VERDICT!r}"
        )


# ---------------------------------------------------------------- plan paths


def check_plan_path(raw):
    """Require a safe repository-relative Git path, judged as a Git path.

    The plan is read out of a commit's tree -- ``ls-tree`` at base and at head --
    and never off disk, so the only question is whether ``raw`` is a path a tree
    can safely be asked about: nonempty, not absolute, ``/``-separated, and free
    of empty, ``.`` and ``..`` components. Those component rules leave a relative
    path no way to name anything outside the tree, which is what "no repository
    escape" means for a Git path.

    Deliberately *not* resolved on disk. ``realpath`` answers a question about the
    current worktree, which is mutable and need not even exist: a checkout whose
    ``docs`` is a symlink into a shared directory is an ordinary layout, and
    resolving through it reported an escape and rejected records whose tracked
    plan blob was exactly right. Nothing verified here comes from the worktree, so
    nothing verified here may depend on its shape.
    """
    if raw == "":
        fail("--plan-path must not be empty")
    if raw.startswith("/") or os.path.isabs(raw):
        fail(f"--plan-path {_quoted(raw)} must be repository-relative, not absolute")
    if "\\" in raw:
        fail(f"--plan-path {_quoted(raw)} must use '/' separators only")
    for component in raw.split("/"):
        if component == "":
            fail(f"--plan-path {_quoted(raw)} has an empty component")
        if component in (".", ".."):
            fail(f"--plan-path {_quoted(raw)} has a {_quoted(component)} component")
    return raw


# --------------------------------------------------------------------- checks


def verify(args):
    require_git_version()
    repo = args.repo
    require_git_repository(repo)
    plan_path = check_plan_path(args.plan_path)

    # One stack for the whole verification: the record descriptors stay open
    # until the verdict, so the objects that were validated can be re-checked at
    # the end, and the isolated view is removed on every exit path -- including a
    # termination signal, which unwinds this stack like any other failure.
    with ExitStack() as stack:
        # Both records are held open at once, so the identity comparison and
        # the reads all refer to the objects that were validated.
        gpt_record = open_record(stack, "gpt", args.gpt)
        secondary_record = open_record(stack, "secondary", args.secondary)
        records = (gpt_record, secondary_record)
        if gpt_record.identity == secondary_record.identity:
            fail(
                "--gpt and --secondary are the same file (device/inode); two "
                "independent records are required"
            )
        gpt = parse_record("primary", gpt_record.read())
        secondary = parse_record("secondary", secondary_record.read())

        validate_record("primary", gpt, PRIMARY_MODEL, args.work_id)
        validate_record("secondary", secondary, SECONDARY_MODEL, args.work_id)

        # Models and instance identities are independently pinned.
        if gpt["reviewer_instance_id"] == secondary["reviewer_instance_id"]:
            fail(
                "both records share reviewer_instance_id "
                f"{_quoted(gpt['reviewer_instance_id'])}; the reviews are not "
                "independent"
            )

        for key in BOUND_FIELDS:
            if gpt[key] != secondary[key]:
                fail(
                    f"records disagree on {key}: {gpt[key]!r} (primary) vs "
                    f"{secondary[key]!r} (secondary)"
                )

        base = gpt["base_commit"]
        head = gpt["head_commit"]
        if base != args.expected_base:
            fail(
                f"record base_commit {base} is not the expected base "
                f"{args.expected_base}"
            )

        # Every commit, tree, blob and diff below is read through the isolated
        # view, so no repository-local configuration, attributes file or
        # replacement ref can influence what is verified.
        view = isolated_view(stack, repo)

        resolve_commit(view, "base_commit", base)
        resolve_commit(view, "head_commit", head)
        if base == head:
            fail("base_commit and head_commit are identical; the Work range is empty")
        if view.run(
            "merge-base", "--is-ancestor", base, head, allow_failure=True
        ).returncode != 0:
            fail(f"base_commit {base} is not an ancestor of head_commit {head}")

        diff_sha, diff_size = range_diff_digest(view, base, head)
        if diff_size == 0:
            fail(f"the diff {base}..{head} is empty")
        if diff_sha != gpt["diff_sha256"]:
            fail(
                f"recomputed diff_sha256 {diff_sha} does not match the recorded "
                f"{gpt['diff_sha256']}"
            )

        base_blob = tree_blob(view, base, plan_path, "base commit")
        plan_sha, _ = blob_digest(view, base_blob)
        if plan_sha != gpt["plan_blob_sha256"]:
            fail(
                f"recomputed plan_blob_sha256 {plan_sha} does not match the recorded "
                f"{gpt['plan_blob_sha256']}"
            )
        head_blob = tree_blob(view, head, plan_path, "head commit")
        if head_blob != base_blob:
            fail(
                f"plan path {_quoted(plan_path)} changed between base and head; a "
                "Work cannot approve a plan it modified"
            )

        # Last: the records this verdict is about must still be the objects that
        # were validated. Everything above took real time -- several git children,
        # a diff over the whole Work range -- and a writer holding a descriptor
        # from before the `chmod` could have rewritten either record in place
        # during it, to the same length, with equally canonical content.
        for record in records:
            record.check_unchanged()

    return head


# ------------------------------------------------------------------------ CLI


def positive_int(raw):
    if not POSITIVE_INT_RE.match(raw):
        raise argparse.ArgumentTypeError(f"{_quoted(raw)} is not a positive integer")
    if len(raw) > MAX_WORK_ID_DIGITS:
        raise argparse.ArgumentTypeError(
            f"a work id may not have more than {MAX_WORK_ID_DIGITS} digits; "
            f"this one has {len(raw)}"
        )
    return int(raw)


def hex40(raw):
    if not HEX40_RE.match(raw):
        raise argparse.ArgumentTypeError(
            f"{_quoted(raw)} is not a full lowercase 40-hex sha"
        )
    return raw


def build_parser():
    parser = argparse.ArgumentParser(
        description="Verify the two independent Work approval records.",
    )
    parser.add_argument("--work-id", type=positive_int, required=True)
    parser.add_argument("--expected-base", type=hex40, required=True)
    parser.add_argument("--plan-path", required=True)
    parser.add_argument(
        "--gpt", required=True, help=f"primary {PRIMARY_MODEL} record path"
    )
    parser.add_argument(
        "--secondary",
        required=True,
        help=f"secondary {SECONDARY_MODEL} record path",
    )
    parser.add_argument("--repo", default=os.curdir)
    parser.add_argument("--print-head", action="store_true")
    return parser


# Signals a build system or an impatient operator actually sends. Both are
# handled rather than left to the default disposition, which would kill this
# process outright and leave behind whatever it was in the middle of: a git child
# blocked on a pipe, that child's own children, and an isolated view directory.
TERMINATION_SIGNALS = (signal.SIGTERM, signal.SIGINT)


def _ignore_termination_signals():
    for signum in TERMINATION_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def _install_termination_handlers():
    """Turn termination signals into an ordinary unwind.

    The handler raises, so the exception travels the normal failure path: the
    ``ExitStack`` in ``verify`` unwinds, every live git child is killed by process
    group and reaped, and the isolated view is removed.

    Both signals are ignored from the first one onwards. The cleanup that follows
    is short and bounded -- a ``SIGKILL`` to one process group, a ``waitpid``, and
    the removal of a four-file directory -- and interrupting it half-way is
    precisely the outcome being prevented, so a repeat signal is not allowed to
    do that.
    """

    def handler(signum, frame):
        _ignore_termination_signals()
        raise Terminated(signum)

    for signum in TERMINATION_SIGNALS:
        signal.signal(signum, handler)


def main(argv=None):
    args = build_parser().parse_args(argv)
    _install_termination_handlers()
    try:
        head = verify(args)
    except VerificationError as exc:
        print(f"verify_work_approval: {exc}", file=sys.stderr)
        return 1
    except Terminated as exc:
        # Nothing is left running or lying around by now: the unwind above did
        # the killing, reaping and removing. This only reports it, with the
        # conventional 128 + signum so a caller can tell a terminated run from a
        # verification that failed on its merits.
        print(
            f"verify_work_approval: terminated by {exc.name} before the "
            "verification finished",
            file=sys.stderr,
        )
        return 128 + exc.signum
    finally:
        # Disarm before the last cleanup, and stay disarmed. Past this point
        # there is nothing for a signal to interrupt -- the stack has unwound --
        # so raising out of here would only turn the report into a traceback,
        # and a handler whose unwind target no longer exists is worse than none.
        _ignore_termination_signals()
        # No git child may outlive this process, whatever path was taken out of
        # `verify`.
        _reap_all_children()
    if args.print_head:
        sys.stdout.write(head + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
