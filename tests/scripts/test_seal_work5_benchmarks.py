#!/usr/bin/env python3
"""No-replace deterministic seal primitives used by Phase 6B."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import seal_work5_benchmarks as sealer


class Work5SealContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "root"
        (self.root / "verification").mkdir(parents=True)
        hashes = {
            "bench_fixture": "0" * 64,
        }
        script_hashes = {
            "run_work5_benchmarks.py": "1" * 64,
        }
        run = {
            "schema": "piccard-work5-run-v1", "source_root": "/fixture/source",
            "git_sha": "a" * 40, "git_dirty": False,
            "build_dir": "/fixture/build", "executables": hashes, "scripts": script_hashes,
            "matrix_sha256": "2" * 64, "command_template_sha256": "3" * 64,
            "completed_phases": ["toy", "parameters", "real", "dynamic"],
        }
        (self.root / "run.json").write_bytes(sealer.canonical_json(run))
        (self.root / "payload.txt").write_text("payload\n", encoding="utf-8")
        phase_receipt_hashes = {}
        completed = ["toy", "parameters", "real", "dynamic"]
        for index, phase in enumerate(completed, start=1):
            phase_receipt = {
                "schema": "piccard-work5-verification-receipt-v1", "verdict": "PASS",
                "phase": phase, "results_root": str(self.root.resolve()),
                "run_sha256": sealer.sha256_file(self.root / "run.json"), "git_sha": "a" * 40,
                "completed_phases": completed[:index], "phase_inventory_sha256": "4" * 64,
                "terminal_cells": 61,
            }
            phase_path = self.root / "verification" / f"{phase}.json"
            phase_path.write_bytes(sealer.canonical_json(phase_receipt))
            phase_receipt_hashes[phase] = sealer.sha256_file(phase_path)
        full_ctest = {
            "schema": "piccard-work5-ctest-gate-receipt-v1", "verdict": "PASS",
            "classification": "KNOWN_WORK6_SCOPE_DIAGNOSTIC_MISMATCH",
            "results_root": str(self.root.resolve()), "git_sha": "a" * 40,
            "completed_phases": ["toy"], "frozen_work6_hashes": {},
        }
        full_ctest_path = self.root / "verification" / "full-ctest.json"
        full_ctest_path.write_bytes(sealer.canonical_json(full_ctest))
        receipt = {
            "schema": "piccard-work5-pre-seal-receipt-v1",
            "semantic_verdict": "PASS", "created_at_utc": "2026-08-12T00:00:00Z",
            "results_root": str(self.root.resolve()),
            "root_identity": sealer.root_identity(self.root),
            "git_sha": "a" * 40, "tracked_clean": True,
            "run_sha256": sealer.sha256_file(self.root / "run.json"),
            "build_dir": "/fixture/build", "executables": hashes, "scripts": script_hashes,
            "matrix_sha256": "2" * 64, "command_template_sha256": "3" * 64,
            "completed_phases": completed, "phase_receipt_sha256": phase_receipt_hashes,
            "full_ctest_receipt": {"path": "verification/full-ctest.json",
                                    "sha256": sealer.sha256_file(full_ctest_path)},
            "parameter_counts": dict(sealer.PRE_SEAL_PARAMETER_COUNTS),
            "real_semantic_verdict": "PASS", "dynamic_semantic_verdict": "PASS",
            "inventory": sealer.inventory(self.root, exclude={"verification/pre-seal-receipt.json"}),
        }
        receipt["inventory_sha256"] = sealer.sha256_bytes(
            sealer.canonical_json(receipt["inventory"]))
        receipt["directories"] = sealer.directory_inventory(self.root)
        receipt["directories_sha256"] = sealer.sha256_bytes(
            sealer.canonical_json(receipt["directories"]))
        (self.root / "verification" / "pre-seal-receipt.json").write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def test_create_and_read_only_verify_reject_overwrite_links_and_drift(self) -> None:
        receipt = self.root / "verification" / "pre-seal-receipt.json"
        manifest = self.root / "SHA256SUMS"
        digest = self.root / "SHA256SUMS.sha256"
        sealer.create_seal(self.root, receipt, manifest, digest)
        before = sealer.snapshot(self.root)
        sealer.verify_post_seal(self.root, receipt, manifest, digest)
        self.assertEqual(before, sealer.snapshot(self.root))
        with self.assertRaises(sealer.SealError):
            sealer.create_seal(self.root, receipt, manifest, digest)
        (self.root / "payload.txt").write_text("changed\n", encoding="utf-8")
        before_failure = sealer.snapshot(self.root)
        with self.assertRaises(sealer.SealError):
            sealer.verify_post_seal(self.root, receipt, manifest, digest)
        self.assertEqual(before_failure, sealer.snapshot(self.root))

    def test_receipt_order_and_digest_are_mandatory(self) -> None:
        receipt_path = self.root / "verification" / "pre-seal-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt.pop("inventory_sha256")
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(sealer.SealError):
            sealer.create_seal(self.root, receipt_path, self.root / "SHA256SUMS",
                               self.root / "SHA256SUMS.sha256")

    def test_receipt_schema_and_semantic_bindings_are_exact(self) -> None:
        receipt_path = self.root / "verification" / "pre-seal-receipt.json"
        original = json.loads(receipt_path.read_text(encoding="utf-8"))
        mutations = {
            "missing_git_sha": lambda value: value.pop("git_sha"),
            "extra_forged_field": lambda value: value.__setitem__("forged", "accepted"),
            "semantic_fail": lambda value: value.__setitem__("semantic_verdict", "FAIL"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = json.loads(json.dumps(original))
                mutate(candidate)
                receipt_path.write_text(json.dumps(candidate, sort_keys=True) + "\n", encoding="utf-8")
                with self.assertRaises(sealer.SealError):
                    sealer.create_seal(self.root, receipt_path, self.root / "SHA256SUMS",
                                       self.root / "SHA256SUMS.sha256")
                receipt_path.write_bytes(sealer.canonical_json(original))

    def test_receipt_is_inserted_at_its_canonical_inventory_position(self) -> None:
        """A production receipt sorts between parameter and real receipts."""
        receipt_path = self.root / "verification" / "pre-seal-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["inventory"] = sealer.inventory(
            self.root, exclude={"verification/pre-seal-receipt.json"})
        receipt["inventory_sha256"] = sealer.sha256_bytes(
            sealer.canonical_json(receipt["inventory"]))
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        sealer.create_seal(self.root, receipt_path, self.root / "SHA256SUMS",
                           self.root / "SHA256SUMS.sha256")

        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        inventory = list(reversed(receipt["inventory"]))
        receipt["inventory"] = inventory
        receipt["inventory_sha256"] = sealer.sha256_bytes(sealer.canonical_json(inventory))
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(sealer.SealError):
            sealer.create_seal(self.root, receipt_path, self.root / "SHA256SUMS",
                               self.root / "SHA256SUMS.sha256")

    def test_stale_temp_and_case_colliding_directories_are_rejected(self) -> None:
        stale = self.root / ".SHA256SUMS.tmp.stale"
        stale.write_text("stale\n", encoding="utf-8")
        receipt_path = self.root / "verification" / "pre-seal-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["inventory"] = sealer.inventory(self.root, exclude={"verification/pre-seal-receipt.json"})
        receipt["inventory_sha256"] = sealer.sha256_bytes(sealer.canonical_json(receipt["inventory"]))
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(sealer.SealError):
            sealer.create_seal(self.root, receipt_path, self.root / "SHA256SUMS",
                               self.root / "SHA256SUMS.sha256")

        stale.unlink()
        collision = [
            {"path": "Alpha", "size": 0, "sha256": "0" * 64},
            {"path": "alpha", "size": 0, "sha256": "1" * 64},
        ]
        with self.assertRaises(sealer.SealError):
            sealer._sorted_inventory(collision)

    def test_post_seal_detects_empty_directory_drift_without_writing(self) -> None:
        receipt = self.root / "verification" / "pre-seal-receipt.json"
        manifest = self.root / "SHA256SUMS"
        digest = self.root / "SHA256SUMS.sha256"
        sealer.create_seal(self.root, receipt, manifest, digest)
        before = sealer.snapshot(self.root)
        (self.root / "new-empty-directory").mkdir()
        with self.assertRaises(sealer.SealError):
            sealer.verify_post_seal(self.root, receipt, manifest, digest)
        self.assertNotEqual(before, sealer.snapshot(self.root))


if __name__ == "__main__":
    unittest.main()
