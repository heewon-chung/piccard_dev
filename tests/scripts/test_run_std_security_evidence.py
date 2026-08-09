#!/usr/bin/env python3
"""Fail-closed contract tests for the STD diagnostic runner."""

from __future__ import annotations

import importlib.util
import csv
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_std_security_evidence.py"
FAKE = ROOT / "tests" / "fixtures" / "std_security_evidence" / "fake_bench.py"
FAKE_FHE = ROOT / "tests" / "fixtures" / "std_security_evidence" / "fake_fhe_ind.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("std_security_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to import runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StdSecurityEvidenceRunnerTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tmp = pathlib.Path(self.temp.name)
        self.build = self.tmp / "build"
        self.build.mkdir()
        self.binary = self.build / "bench_std_security_evidence"
        shutil.copy2(FAKE, self.binary)
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)

    def run_runner(self, *arguments: str, env: dict[str, str] | None = None):
        merged = os.environ.copy()
        merged["PYTHONDONTWRITEBYTECODE"] = "1"
        merged["FAKE_SOURCE_ROOT"] = str(ROOT)
        if env:
            merged.update(env)
        return subprocess.run(
            ["python3", str(RUNNER), "--build-dir", str(self.build), *arguments],
            cwd=ROOT, env=merged, text=True, capture_output=True, check=False,
        )

    def test_dry_run_freezes_four_core_cells_and_has_no_side_effect(self):
        result = self.run_runner("--dry-run", "--include-fhe-ind=off")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(
            [cell["cell_id"] for cell in payload["cells"]],
            ["onehot-std128", "onehot-std192", "sqrt-std128", "sqrt-std192"],
        )
        self.assertNotIn("threshold", result.stdout.lower())
        self.assertFalse((self.tmp / "results").exists())

    def test_auto_defers_both_fhe_ind_cells_without_explicit_binary(self):
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto")
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = json.loads((results / "manifest.json").read_text())
        self.assertEqual(
            set(manifest["cells"]),
            {"onehot-std128", "onehot-std192", "sqrt-std128", "sqrt-std192",
             "fhe-ind-std128", "fhe-ind-std192"},
        )
        for cell_id in ("fhe-ind-std128", "fhe-ind-std192"):
            record = manifest["cells"][cell_id]
            self.assertEqual(record["status"], "DEFERRED_FHE_IND_NOT_READY")
            self.assertTrue(record["reason"].startswith("readiness"))
            self.assertFalse(record["keygen_started"])
            self.assertFalse(record["calibration_started"])
            self.assertFalse(record["e2e_started"])
        self.assertTrue(manifest["complete"])
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)

    def test_auto_defers_when_capability_schema_omits_required_field(self):
        wrapper = self.tmp / "fhe-ind-missing-context-fields"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import json, subprocess, sys\n"
            f"fake = {str(FAKE_FHE)!r}\n"
            "if '--capabilities' in sys.argv:\n"
            "    completed = subprocess.run([sys.executable, fake, *sys.argv[1:]],\n"
            "                               capture_output=True, text=True)\n"
            "    payload = json.loads(completed.stdout)\n"
            "    payload.pop('context_tuple_fields', None)\n"
            "    print(json.dumps(payload, separators=(',', ':')))\n"
            "    sys.stderr.write(completed.stderr)\n"
            "    raise SystemExit(completed.returncode)\n"
            "completed = subprocess.run([sys.executable, fake, *sys.argv[1:]])\n"
            "raise SystemExit(completed.returncode)\n",
            encoding="utf-8")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(wrapper))
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = json.loads((results / "manifest.json").read_text())
        readiness = manifest["identity"]["fhe_ind"]
        self.assertFalse(readiness["ready"])
        self.assertIn("full context-tuple fields", readiness["reason"])
        for cell_id in ("fhe-ind-std128", "fhe-ind-std192"):
            self.assertEqual(manifest["cells"][cell_id]["status"],
                             "DEFERRED_FHE_IND_NOT_READY")
            self.assertFalse((results / "preflight" / f"{cell_id}.json").exists())
            self.assertFalse((results / "measurements" / f"{cell_id}.csv").exists())

    def test_require_invalid_capability_fails_before_results_root_creation(self):
        missing = self.tmp / "missing-fhe-ind"
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "require",
            "--fhe-ind-binary", str(missing))
        self.assertEqual(run.returncode, 2)
        self.assertIn("readiness executable_missing", run.stderr)
        self.assertFalse(results.exists())

    def test_ready_fhe_ind_adds_exactly_two_measured_cells(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary))
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = json.loads((results / "manifest.json").read_text())
        self.assertEqual(
            [manifest["cells"][cell]["status"] for cell in (
                "fhe-ind-std128", "fhe-ind-std192")],
            ["MEASURED", "MEASURED"],
        )
        self.assertFalse(manifest["cells"]["fhe-ind-std128"]["calibration_started"])
        self.assertEqual(manifest["cells"]["fhe-ind-std128"]["calibration_applicable"],
                         False)
        self.assertTrue((results / "preflight" / "fhe-ind-std128.json").is_file())
        self.assertTrue((results / "measurements" / "fhe-ind-std128.csv").is_file())

    def test_oversize_fhe_preflight_skips_before_e2e(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary),
            env={"FAKE_FHE_OVERSIZE": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = json.loads((results / "manifest.json").read_text())
        for cell_id in ("fhe-ind-std128", "fhe-ind-std192"):
            record = manifest["cells"][cell_id]
            self.assertEqual(record["status"], "SKIPPED_PRECHECK")
            self.assertFalse(record["keygen_started"])
            self.assertFalse(record["e2e_started"])
            self.assertIn("realized_ring_dim bound=32768 observed=65536",
                          record["reason"])
            self.assertIn("provisioned_depth bound=4 observed=10",
                          record["reason"])
            self.assertFalse((results / "measurements" / f"{cell_id}.csv").exists())

    def test_resume_rejects_tampered_fhe_preflight_record_hash(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary))
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["cells"]["fhe-ind-std128"]["preflight_sha256"] = "0" * 64
        manifest_path.write_bytes(runner.canonical_json(manifest))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary), "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("resume FHE-IND preflight binding mismatch", resumed.stderr)

    def test_resume_rejects_zero_fhe_timing_after_hash_rebinding(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary))
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        measurement = results / "measurements" / "fhe-ind-std128.csv"
        rows = list(csv.DictReader(measurement.read_text().splitlines()))
        rows[0]["setup_context_ms"] = "0"
        with measurement.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=list(rows[0]),
                                    lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        digest = runner.sha256_file(measurement)
        manifest["cells"]["fhe-ind-std128"]["measurement_sha256"] = digest
        manifest["artifacts"]["fhe-ind-std128"]["measurement"]["sha256"] = digest
        terminal = results / "terminal-cells.tsv"
        terminal.write_bytes(runner.terminal_tsv_bytes(
            manifest["cells"], runner.CORE_CELLS + runner.FHE_IND_CELLS))
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal)
        manifest_path.write_bytes(runner.canonical_json(manifest))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary), "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("FHE-IND timing field must be positive: setup_context_ms",
                      resumed.stderr)

    def test_resume_rejects_fhe_rns_tuple_mismatch_after_hash_rebinding(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary))
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        measurement = results / "measurements" / "fhe-ind-std128.csv"
        with measurement.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
            header = rows[0].keys()
        rows[0]["ordered_rns_moduli"] = '["1000000007","1000000033"]'
        rows[0]["ordered_rns_moduli_sha256"] = runner.ordered_rns_sha256(
            ["1000000007", "1000000033"])
        with measurement.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=list(header),
                                    lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        digest = runner.sha256_file(measurement)
        manifest["cells"]["fhe-ind-std128"]["measurement_sha256"] = digest
        manifest["artifacts"]["fhe-ind-std128"]["measurement"]["sha256"] = digest
        terminal = results / "terminal-cells.tsv"
        terminal.write_bytes(runner.terminal_tsv_bytes(
            manifest["cells"], runner.CORE_CELLS + runner.FHE_IND_CELLS))
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal)
        manifest_path.write_bytes(runner.canonical_json(manifest))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind", "auto",
            "--fhe-ind-binary", str(fhe_binary), "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("FHE-IND measurement/preflight RNS tuple mismatch",
                      resumed.stderr)

    def test_preflight_caps_are_fail_closed_at_exact_boundaries(self):
        runner = load_runner()
        base = {"realized_ring_dim": 32768, "provisioned_depth": 4,
                "log_q_bits": 240.0}
        self.assertEqual(runner.preflight_reason(base), "")
        ring = dict(base, realized_ring_dim=32769)
        self.assertEqual(
            runner.preflight_reason(ring),
            "realized_ring_dim bound=32768 observed=32769",
        )
        depth = dict(base, provisioned_depth=5)
        self.assertEqual(
            runner.preflight_reason(depth),
            "provisioned_depth bound=4 observed=5",
        )
        log_q = dict(base, log_q_bits=240.0001)
        self.assertEqual(
            runner.preflight_reason(log_q),
            "log2(q) bound=240 observed=240.0001",
        )
        all_caps = dict(realized_ring_dim=32769, provisioned_depth=5,
                        log_q_bits=240.0001)
        self.assertEqual(
            runner.preflight_reason(all_caps),
            "realized_ring_dim bound=32768 observed=32769; "
            "provisioned_depth bound=4 observed=5; "
            "log2(q) bound=240 observed=240.0001",
        )

    def test_fake_binary_runs_all_cells_once_and_resume_reuses_hashes(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--threads", "1",
            "--include-fhe-ind=off",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        self.assertTrue(manifest["complete"])
        self.assertEqual(
            [manifest["cells"][cell]["status"] for cell in (
                "onehot-std128", "onehot-std192", "sqrt-std128", "sqrt-std192")],
            ["MEASURED"] * 4,
        )
        self.assertEqual(manifest["identity"]["embedded"]["build_type"], "Release")
        second = self.run_runner(
            "--results-root", str(results), "--threads", "1",
            "--include-fhe-ind=off", "--resume",
        )
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_resume_rejects_one_byte_measurement_mutation(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        path = results / "measurements" / "onehot-std128.csv"
        path.write_bytes(path.read_bytes() + b" ")
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("measurement hash mismatch", resumed.stderr)

    def test_oversized_preflight_is_skip_before_calibration(self):
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off",
            env={"FAKE_RING_DIM": "32769"},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = json.loads((results / "manifest.json").read_text())
        for cell in manifest["cells"].values():
            self.assertEqual(cell["status"], "SKIPPED_PRECHECK")
            self.assertFalse(cell["keygen_started"])
            self.assertFalse(cell["calibration_started"])
            self.assertFalse(cell["e2e_started"])
            self.assertIn("realized_ring_dim bound=32768 observed=32769", cell["reason"])
        self.assertFalse(any((results / "calibration").iterdir()))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume",
            env={"FAKE_RING_DIM": "32769"},
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)

    def test_execution_failure_is_error_not_skip(self):
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off",
            env={"FAKE_FAIL_MODE": "e2e"},
        )
        self.assertEqual(run.returncode, 2)
        manifest = json.loads((results / "manifest.json").read_text())
        for cell in manifest["cells"].values():
            self.assertEqual(cell["status"], "ERROR")
            self.assertNotEqual(cell["status"], "SKIPPED_PRECHECK")
        for cell_id in ("onehot-std128", "onehot-std192", "sqrt-std128", "sqrt-std192"):
            artifacts = manifest["artifacts"][cell_id]
            self.assertEqual(len(artifacts["preflights"]), 4 if cell_id.startswith("onehot") else 2)
            self.assertIn("calibration", artifacts)
            self.assertIn("log", artifacts)

    def test_exact_capacity_failure_is_the_only_retryable_calibration_outcome(self):
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off",
            env={"FAKE_FAIL_MODE": "calibration-capacity"},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = json.loads((results / "manifest.json").read_text())
        for cell_id, record in manifest["cells"].items():
            self.assertEqual(record["status"], "MEASURED")
            self.assertEqual(record["candidate"][1], 45)

    def test_near_match_capacity_error_is_not_retryable(self):
        results = self.tmp / "results"
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off",
            env={"FAKE_FAIL_MODE": "calibration-capacity-extra"},
        )
        self.assertEqual(run.returncode, 2)
        manifest = json.loads((results / "manifest.json").read_text())
        for cell_id, record in manifest["cells"].items():
            self.assertEqual(record["status"], "ERROR")
            self.assertIn("calibration failed", record["reason"])
            self.assertNotIn("calibration", manifest["artifacts"][cell_id])

    def test_existing_results_root_is_never_overwritten_without_resume(self):
        results = self.tmp / "results"
        results.mkdir()
        marker = results / "marker"
        marker.write_text("keep")
        run = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(run.returncode, 2)
        self.assertIn("use --resume", run.stderr)
        self.assertEqual(marker.read_text(), "keep")

    def test_relative_results_root_is_rejected_before_filesystem_output(self):
        run = self.run_runner(
            "--results-root", "relative-results", "--include-fhe-ind=off")
        self.assertEqual(run.returncode, 2)
        self.assertIn("must be absolute", run.stderr)
        self.assertFalse((ROOT / "relative-results").exists())

    def test_resume_rejects_semantically_mutated_workload_even_with_new_hashes(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        workload_path = results / "workload" / "workload.json"
        workload = json.loads(workload_path.read_text())
        workload["bytes_hex"] = "01"
        workload["manifest_sha256"] = runner.sha256_bytes(b"\x01")
        workload["workload_id"] = "fake-workload-mutated"
        workload_path.write_bytes(runner.canonical_json(workload))
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["artifacts"]["workload"]["sha256"] = runner.sha256_file(workload_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("workload does not match this executable", resumed.stderr)

    def test_resume_rejects_measurement_tuple_mutation_after_hash_rebinding(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        measurement_path = results / "measurements" / "onehot-std128.csv"
        with measurement_path.open(newline="", encoding="utf-8") as source:
            rows = list(csv.reader(source))
        rows[1][rows[0].index("requested_ring_dim")] = "999999"
        measurement_path.write_text("\n".join(",".join(row) for row in rows) + "\n")
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        cell = manifest["cells"]["onehot-std128"]
        cell["measurement_sha256"] = runner.sha256_file(measurement_path)
        manifest["artifacts"]["onehot-std128"]["measurement"]["sha256"] = cell["measurement_sha256"]
        terminal_path = results / "terminal-cells.tsv"
        terminal_lines = terminal_path.read_text().splitlines()
        terminal_lines[1] = terminal_lines[1].rsplit("\t", 1)[0] + "\t" + cell["measurement_sha256"]
        terminal_path.write_text("\n".join(terminal_lines) + "\n")
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = runner.sha256_file(terminal_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("measurement/calibration field mismatch: requested_ring_dim", resumed.stderr)

    def test_resume_rejects_self_consistent_wrong_context_digest(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        preflight_path = results / "preflight" / "onehot-std128-depth3-sms40.json"
        preflight = json.loads(preflight_path.read_text())
        preflight["context_tuple_sha256"] = "0" * 64
        preflight_path.write_bytes(runner.canonical_json(preflight))
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for item in manifest["artifacts"]["onehot-std128"]["preflights"]:
            if item["path"].endswith(preflight_path.name):
                item["sha256"] = runner.sha256_file(preflight_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("resume preflight does not match this executable", resumed.stderr)

    def test_resume_rejects_self_consistent_random_calibration_tamper(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        calibration_path = results / "calibration" / "onehot-std128.json"
        calibration = json.loads(calibration_path.read_text())
        random_row = next(row for row in calibration["patterns"]
                          if row["pattern"] == "random")
        self.assertEqual(random_row["expected_matches"], 0)
        random_row["expected_matches"] = 1
        random_row["observed_matches"] = 1
        calibration_path.write_bytes(runner.canonical_json(calibration))
        calibration_hash = runner.sha256_file(calibration_path)

        measurement_path = results / "measurements" / "onehot-std128.csv"
        with measurement_path.open(newline="", encoding="utf-8") as source:
            rows = list(csv.reader(source))
        rows[1][rows[0].index("calibration_artifact_sha256")] = calibration_hash
        measurement_path.write_text(",".join(rows[0]) + "\n" +
                                    ",".join(rows[1]) + "\n")
        measurement_hash = runner.sha256_file(measurement_path)

        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        cell = manifest["cells"]["onehot-std128"]
        cell["calibration_sha256"] = calibration_hash
        cell["measurement_sha256"] = measurement_hash
        artifacts = manifest["artifacts"]["onehot-std128"]
        artifacts["calibration"]["sha256"] = calibration_hash
        artifacts["measurement"]["sha256"] = measurement_hash
        terminal_path = results / "terminal-cells.tsv"
        terminal_lines = terminal_path.read_text().splitlines()
        terminal_lines[1] = terminal_lines[1].rsplit("\t", 1)[0] + \
                            "\t" + measurement_hash
        terminal_path.write_text("\n".join(terminal_lines) + "\n")
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))

        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("random calibration match count is invalid", resumed.stderr)

    def test_resume_rejects_boolean_calibration_match_field(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        calibration_path = results / "calibration" / "onehot-std128.json"
        calibration = json.loads(calibration_path.read_text())
        no_match = next(row for row in calibration["patterns"]
                        if row["pattern"] == "no_match")
        no_match["observed_matches"] = False
        calibration_path.write_bytes(runner.canonical_json(calibration))
        calibration_hash = runner.sha256_file(calibration_path)
        measurement_path = results / "measurements" / "onehot-std128.csv"
        with measurement_path.open(newline="", encoding="utf-8") as source:
            rows = list(csv.reader(source))
        rows[1][rows[0].index("calibration_artifact_sha256")] = calibration_hash
        measurement_path.write_text(",".join(rows[0]) + "\n" +
                                    ",".join(rows[1]) + "\n")
        measurement_hash = runner.sha256_file(measurement_path)
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        cell = manifest["cells"]["onehot-std128"]
        cell["calibration_sha256"] = calibration_hash
        cell["measurement_sha256"] = measurement_hash
        artifacts = manifest["artifacts"]["onehot-std128"]
        artifacts["calibration"]["sha256"] = calibration_hash
        artifacts["measurement"]["sha256"] = measurement_hash
        terminal_path = results / "terminal-cells.tsv"
        lines = terminal_path.read_text().splitlines()
        lines[1] = lines[1].rsplit("\t", 1)[0] + "\t" + measurement_hash
        terminal_path.write_text("\n".join(lines) + "\n")
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))

        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("observed_matches", resumed.stderr)

    def test_resume_rejects_self_consistent_timing_hash_seed_tamper(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for cell_id in ("onehot-std128", "onehot-std192",
                        "sqrt-std128", "sqrt-std192"):
            measurement_path = results / "measurements" / f"{cell_id}.csv"
            with measurement_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.reader(source))
            rows[1][rows[0].index("timing_hash_seed")] = "999"
            measurement_path.write_text(",".join(rows[0]) + "\n" +
                                        ",".join(rows[1]) + "\n")
            measurement_hash = runner.sha256_file(measurement_path)
            manifest["cells"][cell_id]["measurement_sha256"] = measurement_hash
            manifest["artifacts"][cell_id]["measurement"]["sha256"] = measurement_hash
        manifest["workload_binding"]["timing_hash_seed"] = "999"
        terminal_path = results / "terminal-cells.tsv"
        terminal_lines = terminal_path.read_text().splitlines()
        for index, cell_id in enumerate(("onehot-std128", "onehot-std192",
                                         "sqrt-std128", "sqrt-std192"), 1):
            terminal_lines[index] = terminal_lines[index].rsplit("\t", 1)[0] + \
                                    "\t" + manifest["cells"][cell_id]["measurement_sha256"]
        terminal_path.write_text("\n".join(terminal_lines) + "\n")
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))

        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("Timing[0] hash seed mismatch", resumed.stderr)

    def test_resume_rejects_semantically_forged_terminal_tsv(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        terminal_path = results / "terminal-cells.tsv"
        lines = terminal_path.read_text().splitlines()
        lines[1] = lines[1].replace("MEASURED", "ERROR", 1)
        terminal_path.write_text("\n".join(lines) + "\n")
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))
        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("terminal-cells semantic binding mismatch", resumed.stderr)

    def test_resume_continues_from_a_valid_partial_terminal_checkpoint(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for cell_id in ("onehot-std192", "sqrt-std128", "sqrt-std192"):
            for candidate in runner.CANDIDATES[
                    "onehot" if cell_id.startswith("onehot") else "sqrt"]:
                (results / "preflight" /
                 runner.candidate_name(cell_id, *candidate)).unlink()
            for path in (
                    results / "calibration" / f"{cell_id}.json",
                    results / "measurements" / f"{cell_id}.csv",
                    results / "logs" / f"{cell_id}.log"):
                path.unlink()
            manifest["cells"].pop(cell_id)
            manifest["artifacts"].pop(cell_id)
        terminal_path = results / "terminal-cells.tsv"
        terminal_path.write_bytes(runner.terminal_tsv_bytes(manifest["cells"]))
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))

        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        final = json.loads(manifest_path.read_text())
        self.assertEqual(
            [final["cells"][cell_id]["status"] for cell_id, *_ in runner.CORE_CELLS],
            ["MEASURED"] * 4,
        )

    def test_partial_resume_rederives_unbound_preflight_before_reuse(self):
        results = self.tmp / "results"
        first = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off")
        self.assertEqual(first.returncode, 0, first.stderr)
        runner = load_runner()
        missing = "onehot-std192"
        manifest_path = results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for path in (
                results / "calibration" / f"{missing}.json",
                results / "measurements" / f"{missing}.csv",
                results / "logs" / f"{missing}.log"):
            path.unlink()
        manifest["cells"].pop(missing)
        manifest["artifacts"].pop(missing)
        preflight_path = results / "preflight" / \
            runner.candidate_name(missing, 3, 40)
        preflight = json.loads(preflight_path.read_text())
        preflight["realized_ring_dim"] = 32769
        preflight["reason"] = "realized_ring_dim bound=32768 observed=32769"
        preflight["skipped"] = True
        preflight_path.write_bytes(runner.canonical_json(preflight))
        terminal_path = results / "terminal-cells.tsv"
        terminal_path.write_bytes(runner.terminal_tsv_bytes(manifest["cells"]))
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal_path)
        manifest_path.write_bytes(runner.canonical_json(manifest))

        resumed = self.run_runner(
            "--results-root", str(results), "--include-fhe-ind=off", "--resume")
        self.assertEqual(resumed.returncode, 2)
        final = json.loads(manifest_path.read_text())
        self.assertEqual(final["cells"][missing]["status"], "ERROR")
        self.assertIn("resume preflight does not match this executable",
                      final["cells"][missing]["reason"])


if __name__ == "__main__":
    unittest.main()
