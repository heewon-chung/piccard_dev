from __future__ import annotations

import json
import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_revision_benchmarks.py"
VERIFIER = ROOT / "scripts" / "verify_revision_benchmarks.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"


class RevisionVerifierContractTest(unittest.TestCase):
    def make_dry_root(self, temporary: str) -> Path:
        root = Path(temporary) / "dry"
        build = Path(temporary) / "build"
        build.mkdir()
        run = subprocess.run(
            [sys.executable, str(RUNNER), "--mode=dry-run",
             "--build-dir", str(build), "--results-root", str(root),
             "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
            cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return root

    def test_verifier_rejects_changed_manifest_and_cell_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dry"
            build = Path(temporary) / "build"
            build.mkdir()
            run = subprocess.run(
                [sys.executable, str(RUNNER), "--mode=dry-run",
                 "--build-dir", str(build), "--results-root", str(root),
                 "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            manifest = root / "run.json"
            value = json.loads(manifest.read_text())
            value["cell_count"] = 262
            manifest.write_text(json.dumps(value, sort_keys=True) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_verifier_rejects_swapped_security_method(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dry"
            build = Path(temporary) / "build"
            build.mkdir()
            run = subprocess.run(
                [sys.executable, str(RUNNER), "--mode=dry-run",
                 "--build-dir", str(build), "--results-root", str(root),
                 "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            argv_file = root / "planned_argv.jsonl"
            lines = argv_file.read_text().splitlines()
            mutated = json.loads(lines[0])
            mutated["argv"].append("--security=STD192")
            lines[0] = json.dumps(mutated, sort_keys=True)
            argv_file.write_text("\n".join(lines) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_verifier_rejects_coordinated_materialized_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_dry_root(temporary)
            path = root / "planned_argv.jsonl"
            records = [json.loads(line) for line in path.read_text().splitlines()]
            target = next(record for record in records
                          if any(arg == "--trials=30" for arg in record["command"]))
            target["command"] = ["--trials=31" if arg == "--trials=30" else arg
                                 for arg in target["command"]]
            target["argv"] = ["--trials=31" if arg == "--trials=30" else arg
                              for arg in target["argv"]]
            path.write_text("\n".join(json.dumps(row, sort_keys=True)
                                      for row in records) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_family_verifier_recomputes_and_rejects_forged_real_summary(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import summarize_real_datasets as summarizer
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["cell_id"] ==
                    "paper-v1::real_dataset::dblp_acm_u65536_artifact=summary")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            accuracy_id = ("paper-v1::real_dataset::dblp_acm_u65536_"
                           "artifact=accuracy")
            accuracy = cell_output(root, accuracy_id) / "accuracy.csv"
            accuracy.parent.mkdir(parents=True)
            row = ["0"] * len(summarizer.ACCURACY_HEADER_FIELDS)
            indices = {name: index for index, name in
                       enumerate(summarizer.ACCURACY_HEADER_FIELDS)}
            row[indices["dataset"]] = "dblp_acm"
            row[indices["variant"]] = "dblp_acm_u65536"
            row[indices["exact_jaccard_bucketed"]] = "0.25"
            row[indices["abs_error"]] = "0.125"
            row[indices["record_a"]] = "a"
            row[indices["record_b"]] = "b"
            for key in ("set_size_a_raw", "set_size_b_raw",
                        "set_size_a_bucketed", "set_size_b_bucketed"):
                row[indices[key]] = "2"
            with accuracy.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle, lineterminator="\n")
                writer.writerow(summarizer.ACCURACY_HEADER_FIELDS)
                writer.writerow(row)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            summary = output / "summary.csv"
            command = [sys.executable, str(ROOT / "scripts" / "summarize_real_datasets.py"),
                       f"--revision-cell={cell['cell_id']}",
                       f"--accuracy-csv={accuracy}", f"--output={summary}",
                       "--variant=dblp_acm_u65536"]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                       text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            (output / "stdout.log").write_text("")
            (output / "stderr.log").write_text("")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n")
            plans = {cell["cell_id"]: {"command": command}}
            _check_family_artifacts(root, "toy", [cell], plans)
            summary.write_text(summary.read_text() + "forged,row\n")
            receipt["artifact_inventory"] = file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], plans)

    def test_family_verifier_rejects_token_only_stdout_without_csv(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["expected_artifact_schema"] ==
                    "review-comparison-csv-v1")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            tokens = ",".join(row["method"] for row in cell["expected_rows"])
            (output / "stdout.log").write_text(tokens + "\n")
            (output / "stderr.log").write_text("")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(
                    root, "toy", [cell],
                    {cell["cell_id"]: {"command": ["unused"]}})

    def test_verifier_rejects_missing_binary_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_dry_root(temporary)
            manifest = root / "run.json"
            value = json.loads(manifest.read_text())
            value["binaries"] = {}
            manifest.write_text(json.dumps(value, sort_keys=True) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_family_verifier_rejects_wrong_fhe_ind_cell_identity(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["expected_artifact_schema"] == "fhe-ind-csv-v1")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            (output / "stdout.log").write_text(
                "cell_id,method,status,trials\nWRONG-CELL,fhe_ind,DIAGNOSTIC,1\n")
            (output / "stderr.log").write_text("")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_family_verifier_rejects_duplicate_piccard_rows_and_wrong_trials(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["expected_artifact_schema"] ==
                    "piccard-benchmark-csv-v1")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            row = f"{cell['cell_id']},999,0\n"
            (output / "stdout.log").write_text(
                "label,trials,accuracy_trials\n" + row + row)
            (output / "stderr.log").write_text("")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})


if __name__ == "__main__":
    unittest.main()
