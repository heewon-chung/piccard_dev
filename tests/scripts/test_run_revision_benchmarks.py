from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_dry_run_process_boundary_is_zero_child_including_metadata(self) -> None:
        """The complete in-process dry planner must not create any child.

        Checking only the runner's producer counter is insufficient: metadata
        probes and toy fixture preparation used to create children before the
        first planned cell.  Keep this as a subprocess/Popen spy around the
        complete run, not just a helper-level unit test.
        """
        sys.path.insert(0, str(ROOT / "scripts"))
        import run_revision_benchmarks as runner

        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            results = Path(temporary) / "dry"

            def forbidden_child(*_args: object, **_kwargs: object) -> None:
                raise AssertionError("dry-run must not create a child process")

            parsed = runner.build_parser().parse_args([
                "--mode=dry-run", "--build-dir", str(build),
                "--results-root", str(results), "--seed", "20260729",
                "--threads", "2", "--matrix", str(MATRIX),
            ])
            with patch.object(subprocess, "run", side_effect=forbidden_child), \
                    patch.object(subprocess, "Popen", side_effect=forbidden_child):
                self.assertEqual(runner.run(parsed), 0)

            manifest = json.loads((results / "run.json").read_text())
            self.assertEqual(manifest["cell_count"], 263)
            self.assertEqual(manifest["planned_processes"], 260)
            self.assertEqual(manifest["spawned_processes"], 0)
            self.assertEqual(manifest["source"]["schema"],
                             "piccard-revision-dry-run-metadata-v1")
            self.assertEqual(manifest["source"]["availability"],
                             "UNAVAILABLE_NO_SPAWN")
            self.assertEqual(manifest["tools"]["schema"],
                             "piccard-revision-dry-run-metadata-v1")
            self.assertEqual(manifest["tools"]["availability"],
                             "UNAVAILABLE_NO_SPAWN")
            self.assertFalse((results / "toy-input").exists())
            self.assertFalse(any(path.name == "source.manifest.tsv"
                                 for path in results.rglob("*")))

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
                            "tracked-clean" in result.stderr.lower() or
                            "paper mode requires" in result.stderr.lower())

    def test_authorized_paper_requires_all_three_processed_manifests(self) -> None:
        """Executable paper mode cannot fall back to hermetic toy inputs."""
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            build.mkdir()
            result = self.run_runner(
                "--mode=paper", "--authorize-paper-run",
                "--build-dir", str(build),
                "--results-root", str(Path(temporary) / "paper"),
                "--seed", "20260729", "--threads", "2",
                "--matrix", str(MATRIX))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("paper-dblp-manifest", result.stderr)

    def test_paper_rejects_hermetic_toy_processed_manifests(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import (RevisionContractError,
                                               validate_paper_manifest_bindings)
        from run_revision_benchmarks import _copy_toy_manifests

        with tempfile.TemporaryDirectory() as temporary:
            manifests, dblp = _copy_toy_manifests(Path(temporary))
            with self.assertRaisesRegex(RevisionContractError, "paper|toy|count|variant"):
                validate_paper_manifest_bindings(
                    dblp_manifest=dblp,
                    variant_manifests=manifests,
                    root_seed=20260729,
                )

    def test_paper_manifest_identity_and_provenance_mutations_fail_closed(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import (RevisionContractError,
                                               _validate_paper_manifest)

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "processed" / "dblp_acm_u65536"
            shutil.copytree(
                ROOT / "tests" / "fixtures" / "real_datasets" / "quick" /
                "dblp_acm_u65536", destination)
            manifest = destination / "dataset.manifest.tsv"
            text = manifest.read_text()
            text = text.replace("\t7\nsource_manifest_file", "\t20260729\nsource_manifest_file")
            manifest.write_text(text)
            _validate_paper_manifest(manifest, "dblp_acm_u65536", 20260729)
            mutations = {
                "wrong seed": ("seed\t20260729", "seed\t7"),
                "wrong dataset": ("dataset\tdblp_acm", "dataset\tenron"),
                "wrong variant": ("variant\tdblp_acm_u65536", "variant\tenron_u65536"),
                "wrong profile": ("preprocessing_version\tdblp-acm-trigram-v1",
                                   "preprocessing_version\twrong-profile"),
                "wrong universe": ("universe_size\t65536", "universe_size\t1048576"),
                "wrong count": ("pair_count\t6", "pair_count\t5"),
                "wrong labels": ("original_positive_count\t3",
                                  "original_positive_count\t2"),
                "wrong source binding": ("source_manifest_sha256\t0b40cef7bfe0eb259a66d094b26685a0bb72f5f5a35371a404a8cb1691de81b4",
                                          "source_manifest_sha256\t" + "0" * 64),
            }
            for label, (old, new) in mutations.items():
                with self.subTest(label=label):
                    mutated = destination / f"{label.replace(' ', '_')}.tsv"
                    mutated_lines = []
                    replaced = False
                    for line in text.splitlines(keepends=True):
                        if line.startswith(old):
                            mutated_lines.append(new + "\n")
                            replaced = True
                        else:
                            mutated_lines.append(line)
                    self.assertTrue(replaced, label)
                    mutated.write_text("".join(mutated_lines))
                    with self.assertRaises(RevisionContractError):
                        _validate_paper_manifest(mutated, "dblp_acm_u65536", 20260729)

    def test_paper_materialization_uses_explicit_manifests_not_toy_input(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import load_matrix
        from run_revision_benchmarks import _materialized_command

        document, _ = load_matrix(MATRIX)
        cells = [cell for cell in document["cells"]
                 if cell["family"] == "real_dataset" and
                 cell["axis_value"] in {"accuracy", "std128_timing",
                                         "std192_encoding"}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "paper"
            root.mkdir()
            build = Path(temporary) / "build"
            build.mkdir()
            explicit = {
                "dblp_acm_u65536": Path(temporary) / "processed" /
                "dblp_acm_u65536" / "dataset.manifest.tsv",
                "enron_u65536": Path(temporary) / "processed" /
                "enron_u65536" / "dataset.manifest.tsv",
                "enron_u1048576": Path(temporary) / "processed" /
                "enron_u1048576" / "dataset.manifest.tsv",
            }
            for cell in cells:
                _, command = _materialized_command(
                    cell, "paper", root=root, build_dir=build,
                    seed=20260729, threads=2,
                    variant_manifests=explicit,
                    dblp_manifest=explicit["dblp_acm_u65536"],
                )
                joined = " ".join(command)
                self.assertNotIn("toy-input", joined)
                self.assertIn(str(explicit[cell["variant"]]), joined)

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
