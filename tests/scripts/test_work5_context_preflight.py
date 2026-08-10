#!/usr/bin/env python3
"""Live compatibility checks for the separate Work #5 context-only APIs."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_BINARY_ARGS = sys.argv[1:]
sys.argv[1:] = []


class Work5ContextPreflightTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if len(_BINARY_ARGS) != 2:
            raise SystemExit("usage: test_work5_context_preflight.py PICCARD FHE_IND")
        cls.piccard = Path(_BINARY_ARGS[0]).resolve()
        cls.fhe_ind = Path(_BINARY_ARGS[1]).resolve()

    def execute(self, argv: list[str]) -> dict:
        completed = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=90)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(Path(next(arg.split("=", 1)[1] for arg in argv
                                  if arg.startswith("--output="))).read_text())

    def test_work5_modes_bind_identity_without_keys_and_old_mode_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Vary k/m/U/security for the Piccard family.  n/U are identity-bound
            # even though the context derivation only consumes k/m/security.
            cases = (("STD128", 16, 64, 1000, 16384),
                     ("STD192", 128, 16, 10000, 65536))
            for index, (security, k, m, n, universe) in enumerate(cases):
                path = root / f"piccard-{index}.json"
                value = self.execute([str(self.piccard), "--mode=work5-preflight",
                                  "--circuit=onehot", f"--security={security}",
                                  "--shape-id=onehot-v1", f"--cell-id=piccard-{index}",
                                  f"--k={k}", f"--m={m}", f"--n={n}",
                                  f"--universe={universe}", f"--output={path}", "--format=json"])
                self.assertEqual(value["schema"], "piccard-work5-piccard-context-preflight-v1")
                self.assertEqual((value["security"], value["k"], value["m"], value["n"], value["universe"]),
                                 (security, k, m, n, universe))
                self.assertFalse(value["keygen_started"])
                self.assertIn("context_tuple_sha256", value)
            fhe_path = root / "fhe.json"
            fhe = self.execute([str(self.fhe_ind), "--mode=work5-preflight", "--method=fhe_ind",
                            "--circuit=fhe_ind", "--security=STD192",
                            "--shape-id=fhe-indicator-v1", "--cell-id=fhe-192",
                            "--n=10000", "--universe=65536", f"--output={fhe_path}", "--format=json"])
            self.assertEqual(fhe["schema"], "piccard-work5-fhe-ind-context-preflight-v1")
            self.assertEqual((fhe["security"], fhe["n"], fhe["universe"]), ("STD192", 10000, 65536))
            self.assertFalse(fhe["keygen_started"])

            # Existing Work #4 mode remains its original schema and deterministic
            # bytes for identical old inputs.
            old_a, old_b = root / "old-a.json", root / "old-b.json"
            base = [str(self.piccard), "--mode=preflight", "--circuit=onehot",
                    "--security=STD128", "--shape-id=onehot-v1", "--format=json"]
            self.execute([*base, f"--output={old_a}"])
            self.execute([*base, f"--output={old_b}"])
            self.assertEqual(old_a.read_bytes(), old_b.read_bytes())
            self.assertEqual(json.loads(old_a.read_text())["schema"],
                             "piccard-std-security-preflight-v1")


if __name__ == "__main__":
    unittest.main()
