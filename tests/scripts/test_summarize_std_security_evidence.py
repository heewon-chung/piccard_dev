#!/usr/bin/env python3
"""Contract tests for the paired STD tuple report generator."""

from __future__ import annotations

import csv
import importlib.util
import json
import math
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_std_security_evidence.py"
SUMMARIZER = ROOT / "scripts" / "summarize_std_security_evidence.py"
FAKE = ROOT / "tests" / "fixtures" / "std_security_evidence" / "fake_bench.py"
FAKE_FHE = ROOT / "tests" / "fixtures" / "std_security_evidence" / "fake_fhe_ind.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("std_security_runner_for_summary", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to import runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_summarizer():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(
        "std_security_summarizer_for_consumer_test", SUMMARIZER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to import summarizer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SummarizeStdSecurityEvidenceTest(unittest.TestCase):
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

    def run_runner(self, results: pathlib.Path):
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["FAKE_SOURCE_ROOT"] = str(ROOT)
        return subprocess.run(
            ["python3", str(RUNNER), "--build-dir", str(self.build),
             "--results-root", str(results), "--threads", "1",
             "--include-fhe-ind", "off"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False,
        )

    def run_runner_auto(self, results: pathlib.Path):
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["FAKE_SOURCE_ROOT"] = str(ROOT)
        return subprocess.run(
            ["python3", str(RUNNER), "--build-dir", str(self.build),
             "--results-root", str(results), "--threads", "1",
             "--include-fhe-ind", "auto"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False,
        )

    def run_runner_auto_ready(self, results: pathlib.Path,
                              fhe_binary: pathlib.Path,
                              env_extra: dict[str, str] | None = None):
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["FAKE_SOURCE_ROOT"] = str(ROOT)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["python3", str(RUNNER), "--build-dir", str(self.build),
             "--results-root", str(results), "--threads", "1",
             "--include-fhe-ind", "auto", "--fhe-ind-binary", str(fhe_binary)],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False,
        )

    def summarize(self, results: pathlib.Path):
        output = results / "summary"
        return subprocess.run(
            ["python3", str(SUMMARIZER), "--manifest",
             str(results / "manifest.json"), "--output-dir", str(output)],
            cwd=ROOT, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True, capture_output=True, check=False,
        )

    def make_results(self) -> pathlib.Path:
        results = self.tmp / "results"
        run = self.run_runner(results)
        self.assertEqual(run.returncode, 0, run.stderr)
        return results

    def test_v2_reports_project_exact_provenance_fields_from_complete_record(self):
        summarizer = load_summarizer()
        runner = summarizer.runner
        runner.ACTIVE_SCHEMA_VERSION = "v2"
        complete = {
            "schema": "piccard-std-security-parameter-provenance-v2",
            "kind": "piccard",
            "circuit": "onehot",
            "shape_id": "onehot-v1",
            "security": "STD128",
            "bfv_context_fingerprint": "v2-context-fingerprint",
            "requested_ring_dim": 111,
            "natural_ring_dim": 222,
            "provisioned_ring_dim": 333,
            "realized_ring_dim": 444,
            "natural_depth": 2,
            "provisioned_depth": 5,
            "log_q_bits": 60.0,
            "log_q_over_t_bits": 60.0 - math.log2(65537),
            "plaintext_modulus": 65537,
            "num_limbs": 2,
            "scaling_mod_size": 41,
            "ordered_rns_moduli": ["1000000007", "1000000009"],
            "ordered_rns_limb_bits": [30, 30],
            "openfhe_version": "v2-openfhe",
            "transcript_stat_bits": 91,
            "max_queries": 12345,
            "query_stat_bits": 92,
            "coefficient_stat_bits": 93,
            "flood_margin_bits": 94,
            "eval_noise_bits": 95,
            "flood_noise_bits": 96,
            "required_capacity_bits": 98,
            "flooding_assurance":
                "empirical-phase-statistical+ciphertext-computational",
            "residual_capacity": {
                "status": "not-exposed-by-openfhe",
                "definition": "log2(q/t)-required_flood_budget_bits",
                "bits": None,
            },
            "context_tuple_sha256": "a" * 64,
            "status": "MEASURED",
            "reason": "",
            "legacy_encoding_note": "",
        }
        runner.validate_complete_provenance(complete)
        provenance_json = runner.canonical_json(complete).decode("utf-8")
        provenance_sha256 = runner.sha256_bytes(
            runner.complete_provenance_canonical(complete))
        v2_values = {
            "requested_ring_dim": "111",
            "natural_ring_dim": "222",
            "provisioned_ring_dim": "333",
            "realized_ring_dim": "444",
            "natural_depth": "2",
            "provisioned_depth": "5",
            "scaling_mod_size": "41",
            "num_limbs": "2",
            "plaintext_modulus": "65537",
            "ordered_rns_moduli": '["1000000007","1000000009"]',
            "ordered_rns_limb_bits": "[30,30]",
            "openfhe_version": "v2-openfhe",
            "transcript_stat_bits": "91",
            "max_queries": "12345",
            "query_stat_bits": "92",
            "coefficient_stat_bits": "93",
            "flood_margin_bits": "94",
            "eval_noise_bits": "95",
            "flood_noise_bits": "96",
            "required_capacity_bits": "98",
            "flooding_assurance": complete["flooding_assurance"],
            "residual_capacity_status": "not-exposed-by-openfhe",
            "residual_capacity_definition":
                "log2(q/t)-required_flood_budget_bits",
            "residual_capacity_bits": "",
            "provenance_schema": complete["schema"],
            "provenance_kind": "piccard",
            "log_q_bits": "60",
            "context_tuple_sha256": "a" * 64,
        }

        data = {
            "cell_id": "onehot-std128", "circuit": "onehot",
            "shape_id": "onehot-v1", "security": "STD128",
            "calibration_origin": "diagnostic-artifact",
            "calibration_artifact_sha256": "calibration-hash",
            "complete_provenance_json": provenance_json,
            "complete_provenance_sha256": provenance_sha256,
            "context_tuple_sha256": "a" * 64,
            "status": "MEASURED", "reason": "",
            "requested_ring_dim": "legacy-requested",
            "natural_ring_dim": "legacy-natural",
            "realized_ring_dim": "legacy-realized",
            "natural_depth": "legacy-depth",
            "provisioned_depth": "legacy-provisioned-depth",
            "scaling_mod_size": "legacy-scaling",
            "num_limbs": "legacy-limbs",
            "plaintext_modulus": "legacy-plaintext",
            "log_q_bits": "legacy-log-q",
            "ordered_rns_moduli_sha256": "legacy-rns-digest",
            "openfhe_version": "legacy-openfhe",
            "sanitizer_profile": "legacy-sanitizer",
            "transcript_stat_bits": "legacy-transcript",
            "max_queries": "legacy-queries",
            "query_stat_bits": "legacy-query-stat",
            "coefficient_stat_bits": "legacy-coefficient-stat",
            "flood_margin_bits": "legacy-margin",
            "eval_noise_bits": "legacy-eval-noise",
            "flood_noise_bits": "legacy-flood-noise",
            "setup_context_ms": "1", "setup_keygen_ms": "1",
            "phase_minhash_ms": "1", "phase_encode_ms": "1",
            "phase_encrypt_ms": "1", "phase_evaluate_ms": "1",
            "phase_flood_ms": "1", "phase_decrypt_ms": "1",
            "online_e2e_ms": "6", "full_e2e_ms": "8",
            "match_count": "10", "jaccard_estimate": "0.6",
        }
        calibration = {
            "calibration_quality": "diagnostic-one-repetition",
            "ordered_rns_moduli": ["legacy-modulus"],
        }
        entry = {
            "cell": {"cell_id": "onehot-std128", "circuit": "onehot"},
            "status": "MEASURED", "record": {"reason": ""},
            "row": data, "calibration": calibration,
        }
        binding = {
            "workload_manifest_sha256": "b" * 64, "circuit": "onehot",
            "shape_id": "onehot-v1", "k": "16", "m": "16",
            "set_size": "10", "universe": "64", "seed": "7",
            "target_jaccard": "0.5", "realized_intersection": "7",
            "realized_union": "13", "realized_jaccard": "0.53846153846153844",
            "trials": "1",
        }
        ratios = {"online": "", "full": "", "label": ""}
        csv_row = summarizer._row_for_csv(
            "onehot", "STD128", entry, binding, ratios)
        for field, expected in v2_values.items():
            with self.subTest(csv_field=field):
                self.assertEqual(csv_row[field], expected)
        self.assertEqual(
            csv_row["ordered_rns_moduli_sha256"],
            runner.ordered_rns_sha256(complete["ordered_rns_moduli"]),
        )
        self.assertEqual(csv_row["bfv_context_fingerprint"],
                         complete["bfv_context_fingerprint"])
        self.assertEqual(csv_row["complete_provenance_json"], provenance_json)

        pairs = {}
        for circuit in ("onehot", "sqrt"):
            entries = {}
            for security in ("STD128", "STD192"):
                cell_id = f"{circuit}-{security.lower()}"
                entries[security] = {
                    "cell": {"cell_id": cell_id, "circuit": circuit},
                    "status": "MEASURED", "record": {"reason": ""},
                    "row": data, "calibration": calibration,
                }
            pairs[circuit] = {"entries": entries, "binding": binding}
        markdown = summarizer.render_markdown(
            pathlib.Path("/tmp/manifest.json"),
            {"manifest_sha256": "b" * 64}, pairs)
        markdown_text = markdown.decode("utf-8")
        for field, expected in v2_values.items():
            markdown_expected = expected or "not measured"
            with self.subTest(markdown_field=field):
                self.assertIn(
                    f"| `{field}` | {markdown_expected} | "
                    f"{markdown_expected} | same |",
                              markdown_text)

    def read_manifest(self, results: pathlib.Path):
        return json.loads((results / "manifest.json").read_text())

    def write_manifest(self, results: pathlib.Path, manifest: dict):
        runner = load_runner()
        (results / "manifest.json").write_bytes(runner.canonical_json(manifest))

    def rebind_measurement(self, results: pathlib.Path, manifest: dict,
                           cell_id: str):
        runner = load_runner()
        measurement = results / "measurements" / f"{cell_id}.csv"
        measurement_hash = runner.sha256_file(measurement)
        manifest["cells"][cell_id]["measurement_sha256"] = measurement_hash
        manifest["artifacts"][cell_id]["measurement"]["sha256"] = measurement_hash
        terminal = results / "terminal-cells.tsv"
        terminal.write_bytes(runner.terminal_tsv_bytes(manifest["cells"]))
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal)

    def test_four_rows_and_two_circuit_sections_are_paired(self):
        results = self.make_results()
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        with (results / "summary" / "parameter-tuples.csv").open(
                newline="", encoding="utf-8") as source:
            reader = csv.reader(source)
            header = next(reader)
            self.assertEqual(len(header), len(set(header)))
            rows = [dict(zip(header, row)) for row in reader]
        self.assertEqual(len(rows), 4)
        self.assertEqual({row["pair_id"] for row in rows}, {"onehot", "sqrt"})
        self.assertTrue(all(row["context_tuple_sha256"] for row in rows))
        self.assertTrue(all(row["ordered_rns_moduli"].startswith("[") for row in rows))
        self.assertTrue(all(row["sanitizer_profile"] == "primary40" for row in rows))
        markdown = (results / "summary" / "parameter-tuples.md").read_text()
        self.assertIn("## Onehot (`onehot`)", markdown)
        self.assertIn("## Sqrt (`sqrt`)", markdown)
        self.assertIn("1000000007", markdown)
        self.assertNotIn("`ordered_rns_moduli` | not measured | not measured", markdown)
        self.assertIn("Timing ratios (STD192 / STD128; single-run diagnostic)", markdown)
        self.assertIn("Diagnostic smoke evidence only", markdown)
        self.assertNotIn("calibration reuse", markdown.lower())
        for forbidden in ("SD", "CI", "p-value", "statistically significant"):
            self.assertNotIn(forbidden, markdown)

    def test_auto_deferred_fhe_cells_are_visible_in_verified_report(self):
        results = self.tmp / "results"
        run = self.run_runner_auto(results)
        self.assertEqual(run.returncode, 0, run.stderr)
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        markdown = (results / "summary" / "parameter-tuples.md").read_text()
        self.assertIn("## FHE-IND readiness gate", markdown)
        self.assertIn("fhe-ind-std128", markdown)
        self.assertIn("DEFERRED_FHE_IND_NOT_READY", markdown)
        with (results / "summary" / "parameter-tuples.csv").open(
                newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(len(rows), 6)
        fhe_row = next(row for row in rows if row["pair_id"] == "fhe_ind")
        self.assertEqual(fhe_row["universe"], "64")
        self.assertEqual(fhe_row["k"], "N/A")
        self.assertEqual(fhe_row["m"], "N/A")

    def test_ready_fhe_cells_have_separate_tuple_comparison(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        run = self.run_runner_auto_ready(results, fhe_binary)
        self.assertEqual(run.returncode, 0, run.stderr)
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        markdown = (results / "summary" / "parameter-tuples.md").read_text()
        self.assertIn("FHE-IND paired diagnostic values", markdown)
        self.assertIn("not-applicable", markdown)
        self.assertIn("[\"1000000007\",\"1000000009\"]", markdown)
        with (results / "summary" / "parameter-tuples.csv").open(
                newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        fhe_rows = [row for row in rows if row["pair_id"] == "fhe_ind"]
        self.assertEqual(len(fhe_rows), 2)
        self.assertTrue(all(row["universe"] == "64" for row in fhe_rows))
        self.assertTrue(all(row["bfv_context_fingerprint"] for row in fhe_rows))
        self.assertTrue(all(row["k"] == "N/A" and row["m"] == "N/A"
                            for row in fhe_rows))
        self.assertTrue(all(row["sanitizer_profile"] == "not-applicable"
                            for row in fhe_rows))
        self.assertIn("not table-eligible", markdown)

    def test_oversize_fhe_cells_are_reported_as_preflight_skips(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        run = self.run_runner_auto_ready(
            results, fhe_binary, {"FAKE_FHE_OVERSIZE": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        with (results / "summary" / "parameter-tuples.csv").open(
                newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        fhe_rows = [row for row in rows if row["pair_id"] == "fhe_ind"]
        self.assertEqual([row["status"] for row in fhe_rows],
                         ["SKIPPED_PRECHECK", "SKIPPED_PRECHECK"])
        self.assertTrue(all("realized_ring_dim bound=32768" in row["reason"]
                            for row in fhe_rows))
        markdown = (results / "summary" / "parameter-tuples.md").read_text()
        self.assertIn("SKIPPED_PRECHECK", markdown)
        self.assertNotIn("FHE-IND paired diagnostic values", markdown)

    def test_summary_rejects_tampered_fhe_binary_identity(self):
        fhe_binary = self.tmp / "fhe-ind"
        shutil.copy2(FAKE_FHE, fhe_binary)
        fhe_binary.chmod(fhe_binary.stat().st_mode | stat.S_IXUSR)
        results = self.tmp / "results"
        run = self.run_runner_auto_ready(results, fhe_binary)
        self.assertEqual(run.returncode, 0, run.stderr)
        manifest = self.read_manifest(results)
        manifest["identity"]["fhe_ind"]["binary_sha256"] = "0" * 64
        self.write_manifest(results, manifest)
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 2)
        self.assertIn("FHE-IND binary provenance hash mismatch", summary.stderr)

    def test_changed_workload_digest_refuses_report(self):
        results = self.make_results()
        runner = load_runner()
        measurement = results / "measurements" / "onehot-std192.csv"
        with measurement.open(newline="", encoding="utf-8") as source:
            rows = list(csv.reader(source))
        rows[1][rows[0].index("workload_manifest_sha256")] = "f" * 64
        measurement.write_text(",".join(rows[0]) + "\n" +
                               ",".join(rows[1]) + "\n")
        manifest = self.read_manifest(results)
        self.rebind_measurement(results, manifest, "onehot-std192")
        self.write_manifest(results, manifest)
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 2)
        self.assertIn("measurement workload digest mismatch", summary.stderr)

    def test_differing_trials_refuse_pairing(self):
        results = self.make_results()
        measurement = results / "measurements" / "sqrt-std192.csv"
        with measurement.open(newline="", encoding="utf-8") as source:
            rows = list(csv.reader(source))
        rows[1][rows[0].index("trials")] = "2"
        measurement.write_text(",".join(rows[0]) + "\n" +
                               ",".join(rows[1]) + "\n")
        manifest = self.read_manifest(results)
        self.rebind_measurement(results, manifest, "sqrt-std192")
        self.write_manifest(results, manifest)
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 2)
        self.assertIn("measurement frozen field mismatch: trials", summary.stderr)

    def test_skipped_side_preserves_reason_and_omits_timing_ratio(self):
        results = self.make_results()
        runner = load_runner()
        manifest = self.read_manifest(results)
        cell_id = "onehot-std192"
        record = manifest["cells"][cell_id]
        artifact = manifest["artifacts"][cell_id]
        reasons = []
        for candidate, binding, entry in zip(
                runner.CANDIDATES["onehot"], artifact["preflights"],
                record["preflight_caps"]):
            path = results / "preflight" / runner.candidate_name(cell_id, *candidate)
            data = json.loads(path.read_text())
            data["realized_ring_dim"] = 32769
            data["reason"] = "realized_ring_dim bound=32768 observed=32769"
            data["skipped"] = True
            path.write_bytes(runner.canonical_json(data))
            binding["sha256"] = runner.sha256_file(path)
            entry.update({
                "realized_ring_dim": data["realized_ring_dim"],
                "provisioned_depth": data["provisioned_depth"],
                "log_q_bits": data["log_q_bits"],
                "skipped": True,
                "reason": data["reason"],
            })
            reasons.append(data["reason"])
        for path in (
                results / "calibration" / f"{cell_id}.json",
                results / "measurements" / f"{cell_id}.csv"):
            path.unlink()
        artifact.pop("calibration", None)
        artifact.pop("measurement", None)
        record.update({
            "status": "SKIPPED_PRECHECK",
            "reason": "; ".join(reasons),
            "keygen_started": False,
            "calibration_started": False,
            "e2e_started": False,
        })
        for key in ("candidate", "calibration_path", "calibration_sha256",
                    "measurement_path", "measurement_sha256"):
            record.pop(key, None)
        terminal = results / "terminal-cells.tsv"
        terminal.write_bytes(runner.terminal_tsv_bytes(manifest["cells"]))
        manifest["artifacts"]["terminal-cells.tsv"]["sha256"] = \
            runner.sha256_file(terminal)
        self.write_manifest(results, manifest)

        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        markdown = (results / "summary" / "parameter-tuples.md").read_text()
        self.assertIn("`SKIPPED_PRECHECK`", markdown)
        self.assertIn("realized_ring_dim bound=32768 observed=32769", markdown)
        self.assertIn("Timing ratios: not reported because one security cell was skipped.",
                      markdown)
        self.assertIn("not measured", markdown)
        self.assertIn("not compared", markdown)
        with (results / "summary" / "parameter-tuples.csv").open(
                newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        skipped = next(row for row in rows if row["cell_id"] == cell_id)
        self.assertEqual(skipped["status"], "SKIPPED_PRECHECK")
        self.assertEqual(skipped["full_e2e_ms"], "")
        self.assertEqual(skipped["timing_ratio_std192_over_std128_full"], "")

    def test_existing_markdown_does_not_allow_partial_report_write(self):
        results = self.make_results()
        markdown = results / "summary" / "parameter-tuples.md"
        markdown.write_text("sentinel\n")
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 2)
        self.assertIn("summary artifacts are unbound", summary.stderr)
        self.assertEqual(markdown.read_text(), "sentinel\n")
        self.assertFalse((results / "summary" / "parameter-tuples.csv").exists())

    def test_resume_rejects_tampered_bound_report(self):
        results = self.make_results()
        summary = self.summarize(results)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        markdown = results / "summary" / "parameter-tuples.md"
        markdown.write_bytes(markdown.read_bytes() + b"tamper\n")
        run = self.run_runner(results)
        # The root exists, so the command is a resume attempt below; this
        # first invocation intentionally verifies the no-overwrite guard.
        self.assertEqual(run.returncode, 2)
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        resume = subprocess.run(
            ["python3", str(RUNNER), "--build-dir", str(self.build),
             "--results-root", str(results), "--threads", "1",
             "--include-fhe-ind", "off", "--resume"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False,
        )
        self.assertEqual(resume.returncode, 2)
        self.assertIn("resume summary artifact hash mismatch", resume.stderr)


if __name__ == "__main__":
    unittest.main()
