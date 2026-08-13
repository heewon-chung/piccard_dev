from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_revision_benchmarks.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"


class RevisionRunnerContractTest(unittest.TestCase):
    def run_runner(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(RUNNER), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_dry_run_requires_absolute_results_root_and_never_spawns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=dry-run",
                "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "dry"),
                "--seed", "20260729",
                "--threads", "2",
                "--matrix", str(MATRIX),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            root = Path(temporary) / "dry"
            manifest = json.loads((root / "run.json").read_text())
            self.assertEqual(manifest["mode"], "dry-run")
            self.assertEqual(manifest["spawned_processes"], 0)
            self.assertEqual(manifest["cell_count"], 263)

    def test_paper_requires_explicit_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=paper",
                "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "paper"),
                "--seed", "20260729",
                "--threads", "2",
                "--matrix", str(MATRIX),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("authorize-paper-run", result.stderr)

    def test_authorized_paper_rejects_missing_producer_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=paper", "--authorize-paper-run",
                "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "paper"),
                "--seed", "1", "--threads", "1", "--matrix", str(MATRIX))
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue("missing producers" in result.stderr.lower() or
                            "tracked-clean" in result.stderr.lower())

    def test_results_root_must_be_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            results = Path(temporary) / "already-there"
            results.mkdir()
            result = self.run_runner(
                "--mode=dry-run",
                "--build-dir", str(build),
                "--results-root", str(results),
                "--seed", "1",
                "--threads", "1",
                "--matrix", str(MATRIX),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fresh", result.stderr.lower())

    def test_toy_selection_is_104_cells_and_has_no_public_no_exec_bypass(self) -> None:
        help_result = self.run_runner("--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertNotIn("no-exec", help_result.stdout)
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import load_matrix, select_cells
        document, _ = load_matrix(MATRIX)
        cells = select_cells(document, "toy")
        self.assertEqual(len(cells), 104)
        self.assertTrue(all(cell["invocation_status"] == "RUN" for cell in cells))

    def test_toy_enron_inputs_use_real_enron_processed_grammar(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from run_revision_benchmarks import _copy_toy_manifests
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifests, _ = _copy_toy_manifests(root)
            for variant in ("enron_u65536", "enron_u1048576"):
                values = {}
                for line in manifests[variant].read_text().splitlines()[1:]:
                    key, value = line.split("\t", 1)
                    values[key] = value
                self.assertEqual(values["dataset"], "enron")
                self.assertEqual(values["variant"], variant)
                self.assertEqual(values["preprocessing_version"],
                                 "enron-shingle5-v2")
                self.assertIn("dropped.duplicate_copy", values)
                self.assertEqual(values["original_positive_count"], "0")
                pairs = manifests[variant].parent / values["pairs_file"]
                pair_text = pairs.read_text()
                self.assertTrue(any(line.endswith("\t-1")
                                    for line in pair_text.splitlines()[1:]))
                self.assertTrue("thread_related" in pair_text or
                                "cross_thread" in pair_text)

    def test_toy_flooding_uses_wrapper_executable_and_binds_logical_binary(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import load_matrix, select_cells
        from run_revision_benchmarks import _binary_metadata, _materialized_command

        document, _ = load_matrix(MATRIX)
        cell = next(item for item in select_cells(document, "toy")
                    if item["family"] == "flooding")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "results"
            root.mkdir()
            build = Path(temporary) / "build"
            build.mkdir()
            wrapper = ROOT / "scripts" / "run_noise_profiles.sh"
            binary = build / "bench_noise"
            binary.write_text("fake producer\n", encoding="utf-8")
            manifests = {"dblp_acm_u65536": root / "dblp.manifest.tsv"}
            manifests["dblp_acm_u65536"].write_text("fixture\n", encoding="utf-8")
            canonical, command = _materialized_command(
                cell, "toy", root=root, build_dir=build, seed=7, threads=2,
                variant_manifests=manifests,
                dblp_manifest=manifests["dblp_acm_u65536"],
            )
            self.assertEqual(cell["producer"], "bench_noise")
            self.assertEqual(command[0], str(wrapper))
            self.assertIn("--bench-noise=" + str(binary), command)
            self.assertIn("--revision-cell=" + cell["cell_id"], command)
            payload = root / "cells" / "".join(
                character if character.isalnum() else "_"
                for character in cell["cell_id"]
            ) / "payload"
            self.assertIn("--results-root=" + str(payload), command)
            self.assertFalse(payload.exists(),
                             "the flooding wrapper must own-create its payload root")
            metadata = _binary_metadata(build, [cell])
            self.assertEqual(metadata["bench_noise"]["path"], str(binary.resolve()))
            self.assertNotEqual(command[0], str(binary))

    def test_real_summary_uses_python_summary_executable_mapping(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import executable_for_cell, load_matrix

        document, _ = load_matrix(MATRIX)
        cell = next(item for item in document["cells"]
                    if item["family"] == "real_dataset" and
                    item["axis_value"] == "summary")
        self.assertEqual(cell["producer"], "summarize_real_datasets.py")
        self.assertEqual(executable_for_cell(cell), "summarize_real_datasets.py")


if __name__ == "__main__":
    unittest.main()
