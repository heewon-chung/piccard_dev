#!/usr/bin/env python3
"""Hermetic command sentinel for Work #5 runner state-machine tests.

This fixture is deliberately not a cryptographic or CSV producer.  It records
only whether a runner attempted to enter a benchmark command.  A test can
forbid an argument before key generation (for example ``--set-size=100000``),
or force a real sleeping child process so the runner must handle
``subprocess.TimeoutExpired``.  Production evidence must never accept this
fixture as a measurement.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def append_event(arguments: list[str]) -> None:
    path_text = os.environ.get("PICCARD_WORK5_FAKE_EVENT_LOG")
    if not path_text:
        return
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"argv": arguments}, sort_keys=True) + "\n")


def main() -> int:
    arguments = sys.argv[1:]
    append_event(arguments)
    forbidden = os.environ.get("PICCARD_WORK5_FAKE_FORBID_ARGUMENT")
    combination = os.environ.get("PICCARD_WORK5_FAKE_FORBID_COMBINATION")
    forbidden_combination = (combination is not None and
                             all(item in arguments
                                 for item in combination.split("|") if item))
    if (forbidden and forbidden in arguments) or forbidden_combination:
        sentinel = os.environ.get("PICCARD_WORK5_FAKE_KEYGEN_SENTINEL")
        if sentinel:
            Path(sentinel).write_text("forbidden benchmark command reached\n",
                                      encoding="utf-8")
        return 91
    mode = os.environ.get("PICCARD_WORK5_FAKE_MODE", "measured")
    if mode == "sleep":
        # This is intentionally a real child-process sleep.  The lifecycle
        # contract must obtain subprocess.TimeoutExpired rather than merely
        # translating a fixture-selected exit code.
        time.sleep(float(os.environ.get("PICCARD_WORK5_FAKE_SLEEP_SECONDS",
                                        "1.0")))
    if mode == "timeout":
        # The runner must translate a command timeout / conventional 124 into
        # terminal ERROR/TIMEOUT and never reclassify it as a preflight skip.
        return 124
    if mode == "error":
        return 17
    print(json.dumps({
        "schema": "piccard-work5-test-command-v1",
        "status": "MEASURED",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
