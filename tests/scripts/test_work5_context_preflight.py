#!/usr/bin/env python3
"""Live compatibility checks for the separate Work #5 context-only APIs."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import run_work5_benchmarks as work5_runner

_BINARY_ARGS = sys.argv[1:]
sys.argv[1:] = []
WORK4_GOLDEN = (Path(__file__).resolve().parents[2] / ".omc" / "evidence" /
                "work4-fhe-ind" / "phase4" / "run-20260809T232756+0900" /
                "std-results" / "preflight" / "onehot-std128-depth3-sms40.json")
WORK4_PROJECTION_SHA256 = "69a688d9aa20ef79c1c4335223a81bb29d774aed9416c9f869bcc79c480c1099"
WORK4_KEYS = ("circuit", "k", "keygen_started", "log_q_bits", "m", "mode",
              "natural_depth", "natural_ring_dim", "num_limbs", "openfhe_version",
              "ordered_rns_moduli", "plaintext_modulus", "provisioned_depth",
              "realized_ring_dim", "reason", "requested_ring_dim", "scaling_mod_size",
              "schema", "security", "shape_id", "skipped", "table_eligible")


def work4_projection(value: dict) -> dict:
    return {key: value[key] for key in WORK4_KEYS}


def projection_digest(value: dict) -> str:
    return hashlib.sha256((json.dumps(work4_projection(value), sort_keys=True,
                                      separators=(",", ":")) + "\n").encode()).hexdigest()


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
                self.assertRegex(value["piccard_binary_sha256"], r"^[0-9a-f]{64}$")
            fhe_path = root / "fhe.json"
            fhe = self.execute([str(self.fhe_ind), "--mode=work5-preflight", "--method=fhe_ind",
                            "--circuit=fhe_ind", "--security=STD192",
                            "--shape-id=fhe-indicator-v1", "--cell-id=fhe-192",
                            "--n=10000", "--universe=65536", f"--output={fhe_path}", "--format=json"])
            self.assertEqual(fhe["schema"], "piccard-work5-fhe-ind-context-preflight-v1")
            self.assertEqual((fhe["security"], fhe["n"], fhe["universe"]), ("STD192", 10000, 65536))
            self.assertFalse(fhe["keygen_started"])
            self.assertRegex(fhe["fhe_ind_binary_sha256"], r"^[0-9a-f]{64}$")

            # This is an immutable pre-9b5a08a Work4 artifact, not a second
            # output from the corrected binary.  Build/source identity fields
            # are intentionally excluded from the fixed semantic projection.
            self.assertTrue(WORK4_GOLDEN.is_file())
            golden = json.loads(WORK4_GOLDEN.read_text())
            self.assertEqual(projection_digest(golden), WORK4_PROJECTION_SHA256)
            old_a = root / "old-a.json"
            base = [str(self.piccard), "--mode=preflight", "--circuit=onehot",
                    "--security=STD128", "--shape-id=onehot-v1", "--format=json"]
            self.execute([*base, f"--output={old_a}"])
            actual = json.loads(old_a.read_text())
            self.assertEqual(projection_digest(actual), WORK4_PROJECTION_SHA256)
            self.assertEqual(list(actual), sorted(actual))
            self.assertEqual(actual["schema"], "piccard-std-security-preflight-v1")
            self.assertEqual((actual["mode"], actual["circuit"], actual["shape_id"],
                              actual["security"], actual["k"], actual["m"],
                              actual["keygen_started"], actual["table_eligible"]),
                             ("preflight", "onehot", "onehot-v1", "STD128", 16, 16, False, False))

    def test_runner_records_two_distinct_piccard_contexts_before_workload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".tmp").mkdir()
            cell = next(item for item in work5_runner.frozen_cells()
                        if item["cell_id"] == "work5-std128-piccard::control")
            work5_runner.ensure_staging_directory(root, cell["cell_id"])
            reason, observed = work5_runner.context_preflight(
                self.piccard.parent, root, cell, test_fixture=False, timeout=90,
                deadline=time.monotonic() + 90)
            self.assertIsNone(reason)
            self.assertEqual(set(observed), {"context_onehot", "context_sqrt"})
            paths = work5_runner.artifact_paths(root, cell["cell_id"])
            onehot = json.loads(paths["context_onehot"].read_text())
            sqrt = json.loads(paths["context_sqrt"].read_text())
            self.assertEqual((onehot["circuit"], sqrt["circuit"]), ("onehot", "sqrt"))
            self.assertNotEqual(onehot["context_tuple_sha256"], sqrt["context_tuple_sha256"])

    def test_context_output_install_is_no_replace_and_leaves_no_partial_final(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            piccard_path = root / "piccard.json"
            piccard_args = [str(self.piccard), "--mode=work5-preflight", "--circuit=onehot",
                            "--security=STD128", "--shape-id=onehot-v1", "--cell-id=atomic-p",
                            "--k=16", "--m=16", "--n=1000", "--universe=16384",
                            f"--output={piccard_path}", "--format=json"]
            self.execute(piccard_args)
            piccard_bytes = piccard_path.read_bytes()
            duplicate = subprocess.run(piccard_args, text=True, capture_output=True,
                                       check=False, timeout=90)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertEqual(piccard_path.read_bytes(), piccard_bytes)
            self.assertFalse(list(root.glob("piccard.json.tmp-*")))

            fhe_path = root / "fhe.json"
            fhe_args = [str(self.fhe_ind), "--mode=work5-preflight", "--method=fhe_ind",
                        "--circuit=fhe_ind", "--security=STD128", "--shape-id=fhe-indicator-v1",
                        "--cell-id=atomic-f", "--n=1000", "--universe=16384",
                        f"--output={fhe_path}", "--format=json"]
            self.execute(fhe_args)
            fhe_bytes = fhe_path.read_bytes()
            duplicate = subprocess.run(fhe_args, text=True, capture_output=True,
                                       check=False, timeout=90)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertEqual(fhe_path.read_bytes(), fhe_bytes)
            self.assertFalse(list(root.glob(".fhe.json.tmp-*")))


if __name__ == "__main__":
    unittest.main()
