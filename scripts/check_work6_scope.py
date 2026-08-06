#!/usr/bin/env python3
"""Fail closed scope guard for the bounded dynamic Work 6 change set."""

import argparse
import re
import subprocess
import sys
from pathlib import Path


class ScopeError(Exception):
    pass


DATA_PATH = "scripts/" + "work6_" + "allowed_paths" + ".txt"
OLD_RUNNER = "scripts/run_pre_" + "thresh" + "old_profiles.sh"
OLD_TEST = "tests/scripts/test_run_pre_" + "thresh" + "old_profiles.py"
BFV_HEADER = "include/fhe/bfv_context.h"
BFV_SOURCE = "src/fhe/bfv_context.cpp"


def _rx():
    try:
        state = "thresh" + "old"
        rate = "fp" + "fn"
        false_pos = "false" + ".?" + "positive"
        false_neg = "false" + ".?" + "negative"
        updates = "(?:" + "cipher" + "text.*" + "delta" + "|" + "delta" + ".*" + "cipher" + "text|apply" + "delta|incremental.*" + "cipher" + "text)"
        return re.compile("(?:" + state + "|" + rate + "|" + false_pos + "|" + false_neg + "|decision" + ".?" + "boundary)", re.I), re.compile(updates, re.I)
    except re.error as error:
        raise ScopeError("regex construction failed: " + str(error)) from error


def _git(*command):
    result = subprocess.run(["git", *command], check=False, capture_output=True)
    if result.returncode != 0:
        raise ScopeError("git command failed")
    return result.stdout


def _text(value, label):
    try:
        return value.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ScopeError(label + " is not valid UTF-8") from error


def _commit(revision):
    value = _text(_git("rev-parse", revision + "^{commit}"), "revision").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ScopeError("revision did not resolve to a full commit")
    return value


def _paths(data):
    if not data:
        return []
    if not data.endswith(b"\0"):
        raise ScopeError("path diff has no terminal NUL")
    pieces = data[:-1].split(b"\0")
    if not pieces or any(not piece for piece in pieces):
        raise ScopeError("path diff has malformed record")
    return [_text(piece, "path diff") for piece in pieces]


def _allowed_text(text):
    if not text or not text.endswith("\n"):
        raise ScopeError("allowed paths must end with one newline")
    entries = text.splitlines()
    if not entries or any(not item for item in entries):
        raise ScopeError("allowed paths contains a blank entry")
    if entries != sorted(entries) or len(entries) != len(set(entries)):
        raise ScopeError("allowed paths must be sorted and unique")
    for item in entries:
        if item.startswith("/") or ".." in item.split("/") or "\\" in item:
            raise ScopeError("allowed paths contains a non-relative entry")
    return entries


def _read_allowed(path):
    try:
        return _allowed_text(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError) as error:
        raise ScopeError("cannot read allowed paths") from error


def _show(commit, path):
    return _text(_git("show", commit + ":" + path), "blob " + path)


def _lex(source):
    masked = list(source)
    depth = [0] * len(source)
    level = 0; index = 0; state = None; escape = False
    while index < len(source):
        depth[index] = level
        char = source[index]; next_char = source[index + 1:index + 2]
        if state == "line":
            if char != "\n": masked[index] = " "
            else: state = None
        elif state == "block":
            masked[index] = " "
            if char == "*" and next_char == "/":
                masked[index + 1] = " "; index += 1; state = None
        elif state:
            masked[index] = " "
            if escape: escape = False
            elif char == "\\": escape = True
            elif char == state: state = None
        elif char == "#" and (index == 0 or source[index - 1] == "\n"):
            newline = source.find("\n", index)
            stop = len(source) if newline < 0 else newline
            for item in range(index, stop): depth[item] = level
            index = stop - 1
        elif char == "/" and next_char == "/":
            masked[index] = masked[index + 1] = " "; index += 1; state = "line"
        elif char == "/" and next_char == "*":
            masked[index] = masked[index + 1] = " "; index += 1; state = "block"
        elif char in "\"'":
            masked[index] = " "; state = char
        elif char == "{": level += 1
        elif char == "}":
            level -= 1
            if level < 0: raise ScopeError("unbalanced braces")
        index += 1
    if state or level:
        raise ScopeError("unterminated lexical construct")
    return "".join(masked), depth


def _one(masked, text, label):
    starts = [match.start() for match in re.finditer(re.escape(text), masked)]
    if len(starts) != 1: raise ScopeError(label + " must occur exactly once")
    return starts[0]


def _line_span(source, start):
    left = source.rfind("\n", 0, start) + 1
    right = source.find("\n", start)
    return left, len(source) if right < 0 else right + 1


def _public_member(masked, depth, start):
    class_match = re.search(r"\bclass\s+BFVContext\b[^\{]*\{", masked)
    if not class_match: raise ScopeError("missing context class")
    opening = masked.find("{", class_match.start())
    member_depth = depth[opening] + 1
    if not (opening < start and depth[start] == member_depth):
        raise ScopeError("codec export is not a class member")
    prefix = masked[opening + 1:start]
    public = list(re.finditer(r"\bpublic\s*:", prefix))
    private = list(re.finditer(r"\b(?:private|protected)\s*:", prefix))
    if not public or (private and private[-1].start() > public[-1].start()):
        raise ScopeError("codec export is not public")


def subtract_header(candidate):
    masked, depth = _lex(candidate); spans = []
    include = "#include <memory>"
    start = _one(masked, include, "codec memory include")
    left, right = _line_span(candidate, start)
    if candidate[left:right] != include + "\n" or depth[start] != 0:
        raise ScopeError("codec memory include has wrong scope")
    spans.append((left, right))
    forward = "class PublicCiphertextCodec;"
    start = _one(masked, forward, "codec forward declaration")
    left, right = _line_span(candidate, start)
    if candidate[left:right] != forward + "\n" or depth[start] != 1:
        raise ScopeError("codec forward declaration has wrong scope")
    if candidate[right:right + 1] != "\n":
        raise ScopeError("codec forward declaration lacks namespace spacing")
    right += 1
    spans.append((left, right))
    declaration = "    std::shared_ptr<const PublicCiphertextCodec>\n    ExportPublicCiphertextCodec() const;\n"
    start = _one(masked, declaration, "codec export declaration")
    _public_member(masked, depth, start)
    right = start + len(declaration)
    if candidate[right:right + 1] != "\n": raise ScopeError("codec export lacks public spacing")
    spans.append((start, right + 1))
    for left, right in sorted(spans, reverse=True): candidate = candidate[:left] + candidate[right:]
    return candidate


def _brace_end(masked, opening):
    level = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{": level += 1
        elif masked[index] == "}":
            level -= 1
            if level == 0: return index + 1
    raise ScopeError("unbalanced codec definition")


def _definition_span(source, masked, depth, name, expected_depth):
    found = []
    for match in re.finditer(r"(?<![A-Za-z0-9_:])" + re.escape(name) + r"\s*\(", masked):
        if depth[match.start()] != expected_depth: continue
        opening = masked.find("{", match.end())
        if opening >= 0 and depth[opening] == expected_depth and not any(char in ";{}" for char in masked[match.end():opening]):
            found.append(match)
    if len(found) != 1: raise ScopeError("codec definition has wrong scope")
    match = found[0]; opening = masked.find("{", match.end())
    if opening < 0 or depth[opening] != expected_depth:
        raise ScopeError("codec definition has no top-level body")
    if any(char in ";{}" for char in masked[match.end():opening]):
        raise ScopeError("codec definition has malformed signature")
    separator = masked.rfind("\n\n", 0, match.start())
    if separator < 0: raise ScopeError("codec definition has no declaration boundary")
    start = separator + 2
    if any(char in ";{}" for char in masked[start:match.start()]):
        raise ScopeError("codec definition has prefixed bytes")
    end = _brace_end(masked, opening)
    if source[end:end + 2] == "\n\n": end += 2
    elif source[end:end + 1] == "\n": end += 1
    return start, end


def subtract_source(candidate):
    masked, depth = _lex(candidate); spans = []
    for include in ['#include "fhe/public_ciphertext_codec.h"', '#include "key/key-ser.h"', '#include <openssl/evp.h>']:
        start = _one(masked, include, "codec include")
        left, right = _line_span(candidate, start)
        if candidate[left:right] != include + "\n" or depth[start] != 0:
            raise ScopeError("codec include has wrong scope")
        if include != '#include "key/key-ser.h"':
            if candidate[right:right + 1] != "\n": raise ScopeError("codec include lacks spacing")
            right += 1
        spans.append((left, right))
    helpers = ["AppendBE32", "AppendBE64", "Sha256Hex", "ContextFingerprintHex", "PublicKeyFingerprintHex"]
    for name in helpers: spans.append(_definition_span(candidate, masked, depth, name, 2))
    spans.append(_definition_span(candidate, masked, depth, "BFVContext::ExportPublicCiphertextCodec", 1))
    for left, right in sorted(spans, reverse=True): candidate = candidate[:left] + candidate[right:]
    return candidate


def _freeze(base, head, path):
    before = _show(base, path)
    after = _show(head, path)
    try:
        remainder = subtract_header(after) if path == BFV_HEADER else subtract_source(after)
    except ScopeError:
        raise
    if remainder != before:
        raise ScopeError(path + " changes preexisting content")


def _scan_patch(base, head, path, state_rx, update_rx):
    patch = _text(_git("diff", "--text", "--unified=0", "--no-renames", base, head, "--", path), "patch")
    if any(line.startswith("Binary files ") for line in patch.splitlines()):
        raise ScopeError(path + " did not expose source lines")
    header_records = 0
    for line in patch.splitlines():
        if header_records < 2 and (line.startswith("--- a/") or line.startswith("+++ b/")):
            header_records += 1
            continue
        if line.startswith(("+", "-")) and (state_rx.search(line[1:]) or update_rx.search(line[1:])):
            raise ScopeError(path + " contains excluded content")


def check(base_revision, head_revision, allowed_path):
    base = _commit(base_revision)
    head = _commit(head_revision)
    allowed = _read_allowed(allowed_path)
    state_rx, update_rx = _rx()
    changed = _paths(_git("diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRTD", base, head))
    for path in changed:
        if path not in allowed:
            raise ScopeError("path outside whitelist: " + path)
        if state_rx.search(path) and path not in (OLD_RUNNER, OLD_TEST):
            raise ScopeError("path has excluded name: " + path)
    if DATA_PATH in changed:
        candidate_entries = _allowed_text(_show(head, DATA_PATH))
        for entry in candidate_entries:
            if (state_rx.search(entry) and entry not in (OLD_RUNNER, OLD_TEST)) or update_rx.search(entry):
                raise ScopeError("path data has excluded entry")
    for path in changed:
        if path == DATA_PATH:
            continue
        if path == BFV_HEADER or path == BFV_SOURCE:
            _freeze(base, head, path)
        if path == "CMakeLists.txt" or path.startswith(("include/", "src/", "benchmarks/", "scripts/", "tests/")):
            _scan_patch(base, head, path, state_rx, update_rx)


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


if __name__ == "__main__":
    raise SystemExit(main())
