#!/usr/bin/env bash
#
# assert_methods.sh — Postcondition check for a comparison_timing CSV
# (bench_comparison --mode=timing output): fail loudly if any required
# method row is missing (R2-W1 — a silently-dropped row is the exact bug
# class this closes).
#
# Deliberately a standalone executable, not a runner-internal function:
# a shell function is undefined in the caller's parent shell, so calling
# it there would fail with "command not found" (a non-zero exit) and make
# every negative test in the acceptance suite falsely "pass". A real
# executable has no such gap.
#
# Usage:
#   scripts/assert_methods.sh <csv>
#
# Exit codes:
#   0  every required method is present
#   1  usage error (missing arg / unreadable csv)
#   2  one or more required methods are missing (named on stderr)

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <csv>" >&2
    exit 1
fi

csv="$1"

if [[ ! -r "$csv" ]]; then
    echo "assert_methods.sh: cannot read CSV: $csv" >&2
    exit 1
fi

# method is column 2 -- bench_comparison.cpp:192 header is
# "scenario,method,security_class,...".
REQUIRED=(piccard piccard_sqrt baseline bcg12_mh_ff bcg12_mh_ec bcg12_exact_ec bcg12_exact_ff sj16)

present="$(awk -F',' 'NR>1 {print $2}' "$csv" | sort -u)"

missing=()
for m in "${REQUIRED[@]}"; do
    # Exact whole-field match only: `grep -qx` against one method-value-per-line
    # input. A prefix/substring check would let e.g. "piccard_sqrt" satisfy the
    # "piccard" requirement, which is the wrong kind of pass.
    if ! grep -qx -- "$m" <<< "$present"; then
        missing+=("$m")
    fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "assert_methods.sh: missing required method(s): ${missing[*]}" >&2
    exit 2
fi

exit 0
