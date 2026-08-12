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
        (self.root / "run.json").write_text('{"schema":"fixture"}\n', encoding="utf-8")
        (self.root / "payload.txt").write_text("payload\n", encoding="utf-8")
        receipt = {
            "schema": "piccard-work5-pre-seal-receipt-v1",
            "results_root": str(self.root.resolve()),
            "root_identity": sealer.root_identity(self.root),
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

    def test_receipt_is_inserted_at_its_canonical_inventory_position(self) -> None:
        """A production receipt sorts between parameter and real receipts."""
        for name in ("full-ctest.json", "parameters.json", "real.json", "toy.json"):
            (self.root / "verification" / name).write_text(
                json.dumps({"phase": name.removesuffix(".json")}) + "\n", encoding="utf-8")
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
