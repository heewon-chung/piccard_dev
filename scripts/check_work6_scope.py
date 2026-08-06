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


def _remove_once(value, addition, label):
    count = value.count(addition)
    if count != 1:
        raise ScopeError(label + " must occur exactly once")
    return value.replace(addition, "", 1)


def subtract_header(candidate):
    candidate = _remove_once(candidate, "#include <memory>\n", "codec memory include")
    candidate = _remove_once(candidate, "class PublicCiphertextCodec;\n\n", "codec forward declaration")
    declaration = "    std::shared_ptr<const PublicCiphertextCodec>\n    ExportPublicCiphertextCodec() const;\n"
    return _remove_once(candidate, declaration + "\n", "codec export declaration")


def _brace_end(source, opening):
    depth = 0
    quote = None
    escape = False
    line = False
    block = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1:index + 2]
        if line:
            if char == "\n": line = False
        elif block:
            if char == "*" and following == "/": block = False; index += 1
        elif quote:
            if escape: escape = False
            elif char == "\\": escape = True
            elif char == quote: quote = None
        elif char == "/" and following == "/": line = True; index += 1
        elif char == "/" and following == "*": block = True; index += 1
        elif char in "\"'": quote = char
        elif char == "{": depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0: return index + 1
        index += 1
    raise ScopeError("unbalanced codec definition")


def _definition_span(source, name):
    match = re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*\(", source)
    if not match:
        raise ScopeError("missing codec definition")
    open_brace = source.find("{", match.end())
    if open_brace < 0:
        raise ScopeError("codec definition has no body")
    start = source.rfind("\n\n", 0, match.start())
    start = 0 if start < 0 else start + 2
    end = _brace_end(source, open_brace)
    if source[end:end + 2] == "\n\n": end += 2
    elif source[end:end + 1] == "\n": end += 1
    return start, end


def subtract_source(candidate):
    includes = [
        '#include "fhe/public_ciphertext_codec.h"\n\n',
        '#include "key/key-ser.h"\n',
        '#include <openssl/evp.h>\n\n',
    ]
    for include in includes:
        candidate = _remove_once(candidate, include, "codec include")
    names = ["AppendBE32", "AppendBE64", "Sha256Hex", "SecurityCode", "ContextFingerprintHex", "PublicKeyFingerprintHex", "BFVContext::ExportPublicCiphertextCodec"]
    for name in names:
        start, end = _definition_span(candidate, name)
        candidate = candidate[:start] + candidate[end:]
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
    for line in patch.splitlines():
        if line.startswith(("+++", "---")):
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
