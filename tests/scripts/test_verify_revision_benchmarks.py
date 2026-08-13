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
    THRESHOLD_SPEC_HEADER = (
        "k,tau,degree,ps_baby_s,ps_num_chunks,baby_depth,giant_mults,"
        "natural_mult_depth,mult_depth,scaling_mod_size,ring_dim,"
        "plaintext_mod,log2_q,eval_noise_bits,flood_noise_bits,ct_bytes,"
        "poly_build_ms,status,note,schema_version,requested_ring_dim,"
        "natural_ring_dim,provisioned_ring_dim,realized_ring_dim,"
        "natural_depth,provisioned_depth,log_q_bits,log2_q_over_t_bits,"
        "plaintext_modulus,num_limbs,realized_scaling_mod_size,"
        "ordered_rns_moduli,ordered_rns_limb_bits,ordered_rns_limb_bits_sum,"
        "openfhe_version,flooding_assurance,transcript_stat_bits,max_queries,"
        "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
        "required_capacity_bits,residual_capacity_definition,"
        "residual_capacity_bits,residual_capacity_status"
    )
    SQRT_HEADER = (
        "encoding,k,m,N,Depth,Encode,Encrypt,Evaluate,Decrypt,Total(ms),"
        "|err|,rel_err,security,transcript_stat_bits,max_queries,"
        "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
        "eval_noise_bits,flood_noise_bits,sanitizer_model,"
        "sanitizer_assurance,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind,"
        "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
        "openfhe_version"
    )

    def write_family_stdout(self, root: Path, cell: dict, payload: str) -> None:
        from revision_benchmark_common import cell_output
        output = cell_output(root, cell["cell_id"])
        output.mkdir(parents=True)
        (output / "stdout.log").write_text(payload, encoding="utf-8")
        (output / "stderr.log").write_text("", encoding="utf-8")
        (output / "receipt.json").write_text(
            json.dumps({"artifact_inventory": []}) + "\n", encoding="utf-8")

    def write_artifact(self, root: Path, cell: dict, name: str,
                       payload: str, command_prefix: str = "--output=") -> list[str]:
        from revision_benchmark_common import cell_output, file_inventory, sha256_file
        output = cell_output(root, cell["cell_id"])
        output.mkdir(parents=True, exist_ok=True)
        (output / "stdout.log").write_text("", encoding="utf-8")
        (output / "stderr.log").write_text("", encoding="utf-8")
        path = output / name
        path.write_text(payload, encoding="utf-8")
        receipt = {"artifact_inventory": file_inventory(
            output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
        (output / "receipt.json").write_text(
            json.dumps(receipt) + "\n", encoding="utf-8")
        return [f"{command_prefix}{path}"]

    @staticmethod
    def csv_row(header: str, **overrides: str) -> str:
        fields = header.rstrip("\n").split(",")
        values = [""] * len(fields)
        for name, value in overrides.items():
            if name not in fields:
                raise AssertionError(f"unknown CSV field: {name}")
            values[fields.index(name)] = str(value)
        return ",".join(values)

    def write_stdout_rows(self, root: Path, cell: dict, header: str,
                          rows: list[str]) -> None:
        self.write_family_stdout(root, cell, header + "\n".join(rows) + "\n")

    @staticmethod
    def full_sj16_fixture(trials: int = 1) -> str:
        lines = [
            "# SJ16 calibration summary",
            "overall_status=PASS",
            "# ---- provenance ----",
            "precompute_mode=off",
            "# --------------------",
            "key_bits=3072",
            "threads_requested=2",
            "threads_observed=2",
            f"trials_per_size={trials}",
            f"enc_iters={trials}",
            "held_out=32768",
            "residual_tau=0.1",
            "fit_sizes=4096,8192,16384",
            "# columns: key_bits,t_enc_median_ms,t_enc_iqr_ms,alpha_ms_per_m,beta_ms,r2,held_measured_ms,held_pred_ms,held_residual,gate",
            "3072,1,0,0.001,1,1,33,33,0,PASS",
            "# ---- per-size dispersion (median/q1/q3/iqr + raw samples) ----",
            f"k3072_t_enc median=1 samples={','.join(['1'] * trials)}",
        ]
        for size in (4096, 8192, 16384):
            lines.append(
                f"k3072_fit_m={size} median=1 q1=1 q3=1 iqr=0 "
                f"samples={','.join(['1'] * trials)}")
        lines.append(
            f"k3072_heldout_m=32768 median=33 q1=33 q3=33 iqr=0 "
            f"samples={','.join(['33'] * trials)}")
        return "\n".join(lines) + "\n"

    def matrix_cell(self, schema: str, *, family: str | None = None,
                    axis: str | None = None, axis_value: str | None = None) -> dict:
        document = json.loads(MATRIX.read_text())
        for cell in document["cells"]:
            if cell["expected_artifact_schema"] != schema:
                continue
            if family is not None and cell["family"] != family:
                continue
            if axis is not None and cell.get("axis") != axis:
                continue
            if axis_value is not None and str(cell.get("axis_value")) != axis_value:
                continue
            return cell
        raise AssertionError(f"no cell for {schema}/{family}/{axis}={axis_value}")

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
        from revision_benchmark_common import cell_output, file_inventory, sha256_file
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

    def test_family_verifier_accepts_threshold_spec_success_row(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("threshold-csv-v1", family="threshold_spec",
                                axis="k", axis_value="64")
        fields = self.THRESHOLD_SPEC_HEADER.split(",")
        values = ["N/A"] * len(fields)
        values[fields.index("k")] = "64"
        values[fields.index("status")] = "ok"
        values[fields.index("schema_version")] = "piccard-threshold-spec-v2"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     self.THRESHOLD_SPEC_HEADER + "\n" +
                                     ",".join(values) + "\n")
            _check_family_artifacts(
                root, "toy", [cell], {cell["cell_id"]: {"command": []}})

    def test_family_verifier_accepts_sqrt_accuracy_onehot_shape(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="accuracy_m", axis_value="128")
        fields = self.SQRT_HEADER.split(",")
        values = [""] * len(fields)
        values[fields.index("encoding")] = "OneHot"
        values[fields.index("k")] = "128"
        values[fields.index("m")] = "128"
        values[fields.index("comparison_eligible")] = "true"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     self.SQRT_HEADER + "\n" +
                                     ",".join(values) + "\n")
            (cell_output(root, cell["cell_id"]) / "stderr.log").write_text(
                "revision_terminal,schema=sqrt-revision-terminal-v1,"
                f"cell_id={cell['cell_id']},row_id=sqrt,status=NOT_APPLICABLE,"
                "terminal_status=NOT_APPLICABLE,reason=sqrt-m-not-perfect-square,"
                "reason_code=sqrt-m-not-perfect-square,measured_count=0\n",
                encoding="utf-8")
            _check_family_artifacts(
                root, "toy", [cell], {cell["cell_id"]: {"command": []}})

    def test_family_verifier_rejects_threshold_spec_header_drift(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        cell = self.matrix_cell("threshold-csv-v1", family="threshold_spec",
                                axis="k", axis_value="64")
        fields = self.THRESHOLD_SPEC_HEADER.replace("status", "status_drift").split(",")
        values = ["N/A"] * len(fields)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     ",".join(fields) + "\n" +
                                     ",".join(values) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(
                    root, "toy", [cell], {cell["cell_id"]: {"command": []}})

    def test_family_verifier_accepts_sqrt_timing_legacy_shape(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import (
            _SQRT_TIMING_HEADER, _check_family_artifacts)
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="timing_m", axis_value="128")
        fields = _SQRT_TIMING_HEADER.rstrip("\n").split(",")
        values = [""] * len(fields)
        values[fields.index("label")] = "revision_" + cell["cell_id"]
        values[fields.index("k")] = "128"
        values[fields.index("m")] = "128"
        values[fields.index("set_size")] = "1000"
        values[fields.index("comparison_eligible")] = "true"
        values[fields.index("encoding")] = "onehot"
        values[fields.index("trials")] = "1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     _SQRT_TIMING_HEADER + ",".join(values) + "\n")
            cell_output(root, cell["cell_id"]).joinpath("stderr.log").write_text(
                "revision_terminal,schema=sqrt-revision-terminal-v1,"
                f"cell_id={cell['cell_id']},row_id=sqrt,status=NOT_APPLICABLE,"
                "terminal_status=NOT_APPLICABLE,reason=sqrt-m-not-perfect-square,"
                "reason_code=sqrt-m-not-perfect-square,measured_count=0\n",
                encoding="utf-8")
            _check_family_artifacts(root, "toy", [cell],
                                    {cell["cell_id"]: {"command": []}})

    def test_family_verifier_accepts_real_versioned_encoding_pair(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REAL_ENCODING_HEADER, _check_family_artifacts)
        from revision_benchmark_common import cell_output
        cell = self.matrix_cell("real-dataset-csv-v1", family="real_dataset",
                                axis_value="std192_encoding",
                                axis="dblp_acm_u65536_artifact")
        fields = _REAL_ENCODING_HEADER.rstrip("\n").split(",")
        rows = []
        for method in ("piccard_encode", "piccard_sqrt_encode"):
            values = [""] * len(fields)
            values[fields.index("dataset")] = "dblp_acm"
            values[fields.index("variant")] = "dblp_acm_u65536"
            values[fields.index("k")] = "128"
            values[fields.index("m")] = "64"
            values[fields.index("target_security_bits")] = "192"
            values[fields.index("comparison_eligible")] = "false"
            values[fields.index("comparison_scope")] = "encoding-only-diagnostic"
            values[fields.index("cost_scope")] = "encoding-only"
            values[fields.index("secure_division_included")] = "false"
            values[fields.index("method")] = method
            values[fields.index("timed_encoder_pairs")] = "1"
            values[fields.index("correctness_pair_calls")] = "1"
            values[fields.index("signature_derivation_timed")] = "false"
            values[fields.index("correctness_status")] = "PASS"
            rows.append(",".join(values))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            command = self.write_artifact(
                root, cell, "encoding.csv",
                _REAL_ENCODING_HEADER + "\n".join(rows) + "\n",
                "--csv=")
            _check_family_artifacts(root, "toy", [cell],
                                    {cell["cell_id"]: {"command": command}})

    def test_family_verifier_accepts_sj16_calibration_contract(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("sj16-calibration-v1", family="sj16",
                                axis="fit", axis_value="per_element")
        text = self.full_sj16_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(root, cell, "calibration.csv", text)
            _check_family_artifacts(root, "toy", [cell],
                                    {cell["cell_id"]: {"command": command}})

    def test_family_verifier_accepts_nested_noise_shard_contract(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory, sha256_file
        from revision_flooding_adapter import select_noise_partition
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("noise-profile-v1", family="flooding",
                                axis="profile", axis_value="primary40")
        matrix = json.loads((ROOT / "scripts" / "noise_profiles.json").read_text())
        partition = select_noise_partition(matrix, "primary40")
        key_id = partition["key_id"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            shard = output / "payload" / "profiles" / "primary40" / key_id
            details = shard / "details"
            details.mkdir(parents=True)
            payload = output / "payload"
            (payload / "run_manifest.json").write_text(json.dumps({
                "schema": "piccard-noise-revision-run-v1", "profile_id": "primary40",
                "run_profile": "readiness-toy-v1", "status": "READINESS_ONLY",
                "table_eligible": False, "repetitions_per_pattern": 1,
                "patterns": ["zero", "random", "adversarial"], "invocation_count": 1}),
                encoding="utf-8")
            (payload / "resolved_noise_profiles.json").write_text(
                json.dumps({"source_commit": "a" * 40, "profiles": []}), encoding="utf-8")
            (payload / "profiles" / "primary40" / "profile_manifest.json").write_text(
                json.dumps({"schema": "piccard-noise-revision-profile-v1",
                            "profile_id": "primary40", "key_count": 1,
                            "key_verdicts": {key_id: "SELECTED"},
                            "source_commit": "a" * 40,
                            "profile_verdict": "READINESS_ONLY",
                            "table_eligible": False}), encoding="utf-8")
            (shard / "revision_identity.json").write_text(json.dumps({
                "schema": "piccard-noise-revision-shard-v1",
                "cell_id": cell["cell_id"], "run_profile": "readiness-toy-v1",
                "profile_id": "primary40", "key_id": key_id,
                "source_commit": "a" * 40,
                "consumer_points": partition["consumer_points"],
                "consumer_set_sha256": partition["consumer_set_sha256"],
                "repetitions_per_pattern": 1,
                "patterns": ["zero", "random", "adversarial"],
                "status": "READINESS_ONLY", "table_eligible": False}), encoding="utf-8")
            aggregate_header = (
                "profile,circuit,shape_id,security,consumer_count,consumer_set_sha256,"
                "worst_consumer_k,worst_consumer_m,pattern_count,repetitions_per_pattern,"
                "detail_row_count,detail_sha256,seed,requested_ring_dim,natural_ring_dim,"
                "realized_ring_dim,ring_growth_factor,ring_dim_calibrated,natural_depth,"
                "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,log_delta,"
                "eval_noise_bits,headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
                "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,openfhe_version,"
                "source_commit,status_code,error_message,consumer_results_sha256\n")
            aggregate = [""] * len(aggregate_header.rstrip("\n").split(","))
            af = aggregate_header.rstrip("\n").split(",")
            for name, value in (("profile", "primary40"),
                                ("source_commit", "a" * 40),
                                ("consumer_count", str(len(partition["consumer_points"]))),
                                ("consumer_set_sha256", partition["consumer_set_sha256"]),
                                ("pattern_count", "3"),
                                ("repetitions_per_pattern", "1"),
                                ("detail_row_count", str(len(partition["consumer_points"]) * 3))):
                aggregate[af.index(name)] = value
            (shard / "aggregate.csv").write_text(
                aggregate_header + ",".join(aggregate) + "\n", encoding="utf-8")
            detail_header = (
                "profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,consumer_m,"
                "pattern,rep_index,rep_seed,requested_ring_dim,natural_ring_dim,"
                "ring_dim_calibrated,realized_ring_dim,ring_growth_factor,natural_depth,"
                "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,log_delta,"
                "eval_noise_bits,headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
                "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,openfhe_version,"
                "source_commit,status_code,error_message\n")
            df = detail_header.rstrip("\n").split(",")
            detail_rows = []
            for k, m in ((str(p["k"]), str(p["m"]))
                         for p in partition["consumer_points"]):
                for pattern in ("zero", "random", "adversarial"):
                    values = [""] * len(df)
                    for name, value in (("profile", "primary40"), ("key_id", key_id),
                                        ("source_commit", "a" * 40),
                                        ("candidate_id", "N8192-d1-s40"),
                                        ("consumer_k", k), ("consumer_m", m),
                                        ("pattern", pattern), ("rep_index", "0")):
                        values[df.index(name)] = value
                    detail_rows.append(",".join(values))
            (details / "N8192-d1-s40.csv").write_text(
                detail_header + "\n".join(detail_rows) + "\n", encoding="utf-8")
            aggregate[af.index("ring_dim_calibrated")] = "8192"
            aggregate[af.index("provisioned_depth")] = "1"
            aggregate[af.index("scaling_mod_size")] = "40"
            aggregate[af.index("detail_sha256")] = sha256_file(
                details / "N8192-d1-s40.csv")
            aggregate[af.index("status_code")] = "OK"
            (shard / "aggregate.csv").write_text(
                aggregate_header + ",".join(aggregate) + "\n", encoding="utf-8")
            (shard / "candidates.json").write_text(json.dumps({
                "schema": "piccard-candidate-manifest", "version": 1,
                "key_id": key_id, "source_commit": "a" * 40,
                "openfhe_version": partition["openfhe_version"],
                "profile_id": "primary40", "circuit": partition["circuit"],
                "shape_id": partition["shape_id"], "security": partition["security"],
                "requested_ring_dim": partition["requested_ring_dim"],
                "natural_depth": partition["natural_depth"],
                "consumer_points": partition["consumer_points"],
                "consumer_set_sha256": partition["consumer_set_sha256"],
                "command": [], "candidate_count": 1,
                "candidates": [{"candidate_id": "N8192-d1-s40",
                                "status_code": "OK",
                                "detail_sha256": sha256_file(details / "N8192-d1-s40.csv"),
                                "detail_row_count": len(detail_rows)}]},
                sort_keys=True), encoding="utf-8")
            (output / "stdout.log").write_text("", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            _check_family_artifacts(root, "toy", [cell], {cell["cell_id"]: {
                "command": ["scripts/run_noise_profiles.sh",
                            f"--results-root={payload}"]}})
            identity_path = shard / "revision_identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["consumer_points"] = [{"k": 128, "m": 999}]
            identity_path.write_text(json.dumps(identity), encoding="utf-8")
            from verify_revision_benchmarks import RevisionContractError
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], {cell["cell_id"]: {
                    "command": ["scripts/run_noise_profiles.sh",
                                f"--results-root={payload}"]}})

    def test_c1_review_wrong_axes_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REVIEW_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("review-comparison-csv-v1", family="bcg12_minhash",
                                axis="control", axis_value="default")
        rows = [self.csv_row(_REVIEW_HEADER, method=method, k=128, m=64,
                             set_size=1000, universe_size=65536, trials=1)
                for method in ("bcg12_mh_ec", "bcg12_mh_ff")]
        rows[0] = self.csv_row(_REVIEW_HEADER, method="bcg12_mh_ec", k=999,
                               m=64, set_size=1000, universe_size=65536,
                               trials=1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _REVIEW_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_std192_review_wrong_axes_taxonomy_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REVIEW_ENCODING_HEADER, _check_family_artifacts,
            RevisionContractError)
        cell = self.matrix_cell("review-encoding-csv-v1",
                                family="piccard_std192_encoding",
                                axis="control", axis_value="default")
        rows = [self.csv_row(_REVIEW_ENCODING_HEADER, method=method,
                             target_security_bits=128, comparison_eligible="false",
                             comparison_scope="encoding-only-diagnostic", k=128,
                             m=64, timed_encoder_pairs=1,
                             correctness_pair_calls=1, correctness_status="PASS")
                for method in ("piccard_encode", "piccard_sqrt_encode")]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _REVIEW_ENCODING_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_estimator_wrong_shape_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _ESTIMATOR_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("estimator-diagnostic-csv-v1",
                                family="estimator_accuracy", axis="j",
                                axis_value="0.0")
        row = self.csv_row(_ESTIMATOR_HEADER, estimator_model="sha256-random-ranking-poc-v1",
                           k=128, m=64, set_size=1000, target_jaccard="0.9",
                           trials=1, seed=7)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _ESTIMATOR_HEADER, [row])
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_sqrt_accuracy_wrong_shape_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _SQRT_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="accuracy_m", axis_value="16")
        rows = [self.csv_row(_SQRT_HEADER, encoding="OneHot", k=128, m=32),
                self.csv_row(_SQRT_HEADER, encoding="Sqrt", k=128, m=16)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _SQRT_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_sqrt_crossover_wrong_shape_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _CROSSOVER_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="crossover_m", axis_value="16")
        row = self.csv_row(_CROSSOVER_HEADER, k=128, m=64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _CROSSOVER_HEADER, [row])
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_threshold_fpfn_forged_science_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify_threshold_outputs as fpfn
        from verify_revision_benchmarks import (
            _THRESHOLD_FPFN_HEADER, _check_family_artifacts,
            RevisionContractError)
        cell = self.matrix_cell("threshold-fpfn-csv-v1",
                                family="threshold_synthetic_fpfn",
                                axis="point", axis_value="k128_j0")
        point = fpfn._point(128, 0)
        seed = fpfn.row_seed(7, 128, 0, 0)
        match = fpfn._canonical_match_count(point, seed)
        decision = int(match >= point["tau_count"])
        truth = int(point["realized_j"] >= point["j_tau"])
        probability = fpfn._binomial_survival(
            128, point["tau_count"], point["realized_j"] +
            (1.0 - point["realized_j"]) / 64.0)
        row = self.csv_row(
            _THRESHOLD_FPFN_HEADER, schema_version=fpfn.SCHEMA_VERSION,
            profile="readiness-toy-v1", security="TOY",
            estimator_model=fpfn.ESTIMATOR_MODEL, hash_randomness="resampled",
            root_seed=7, k=128, m=64, set_size=1000,
            tau_count=point["tau_count"], j_tau=point["j_tau"], grid_index=0,
            target_j=point["target_j"], signed_delta=point["signed_delta"],
            absolute_delta=point["absolute_delta"], alpha=point["alpha"],
            realized_intersection=point["realized_intersection"],
            realized_union=point["realized_union"], realized_j=point["realized_j"],
            trial_index=0, row_seed=seed, match_count=match, decision=decision,
            exact_j_truth=truth,
            outcome=("TP" if truth and decision else
                     "TN" if not truth and not decision else
                     "FP" if decision else "FN"),
            predicted_decision_probability=probability,
            predicted_error_probability=(1.0 - probability if truth else probability),
            gaussian_error_approx=fpfn.gaussian_error_approx(point["realized_j"], 128))
        row = row.split(",")
        fields = _THRESHOLD_FPFN_HEADER.rstrip("\n").split(",")
        row[fields.index("predicted_decision_probability")] = "0.5"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _THRESHOLD_FPFN_HEADER,
                                   [",".join(row)])
            plan = {cell["cell_id"]: {"command": [
                "--profile=readiness-toy-v1", "--security=TOY", "--mode=fpfn",
                "--point-k=128", "--grid-index=0", "--m=64",
                "--set_size=1000", "--trials=1", "--seed=7"]}}
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], plan)

    def test_c1_piccard_double_count_per_row_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _SQRT_TIMING_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("piccard-benchmark-csv-v1", family="piccard_std128",
                                axis="control", axis_value="default")
        rows = [self.csv_row(_SQRT_TIMING_HEADER, label=cell["cell_id"],
                             encoding="onehot", k=128, m=64, set_size=1000,
                             trials=1, accuracy_trials=1),
                self.csv_row(_SQRT_TIMING_HEADER, label=cell["cell_id"],
                             encoding="onehot", k=128, m=64, set_size=1000,
                             trials=1, accuracy_trials=1)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _SQRT_TIMING_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_sj16_missing_fit_topology_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        cell = self.matrix_cell("sj16-calibration-v1", family="sj16",
                                axis="fit", axis_value="per_element")
        text = self.full_sj16_fixture().replace(
            "k3072_fit_m=8192 median=1 q1=1 q3=1 iqr=0 samples=1\n", "")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(root, cell, "calibration.csv", text)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": command}})

    def test_c1_real_std192_forged_taxonomy_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REAL_ENCODING_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("real-dataset-csv-v1", family="real_dataset",
                                axis_value="std192_encoding",
                                axis="dblp_acm_u65536_artifact")
        rows = [self.csv_row(_REAL_ENCODING_HEADER, profile_id="paper-std192-encoding-v1",
                             run_class="primary", target_security_bits=192,
                             comparison_eligible="false",
                             comparison_scope="full-protocol", dataset="dblp_acm",
                             variant="dblp_acm_u65536", k=128, m=64, method=method,
                             timed_encoder_pairs=1, correctness_pair_calls=1,
                             correctness_status="PASS")
                for method in ("piccard_encode", "piccard_sqrt_encode")]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(
                root, cell, "encoding.csv", _REAL_ENCODING_HEADER +
                "\n".join(rows) + "\n", "--csv=")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": command}})

    def test_c1_real_threshold_truth_forgery_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REAL_THRESHOLD_HEADER, _check_family_artifacts,
            _threshold_seed, _threshold_tau, _threshold_boundary,
            RevisionContractError)
        cell = self.matrix_cell("real-threshold-csv-v1",
                                family="threshold_dblp_fpfn")
        requested = 0.25
        tau = _threshold_tau(requested, 128, 64)
        realized = _threshold_boundary(tau, 128, 64)
        row = self.csv_row(
            _REAL_THRESHOLD_HEADER, schema_version="piccard-real-threshold-v1",
            dataset="dblp_acm", variant="dblp_acm_u65536", pair_id="p0",
            pair_kind="sampled_nonmatch", label=0, record_a="a", record_b="b",
            k=128, m=64, hash_randomness="resampled", root_seed=7,
            split="evaluation", rank_position=1, threshold_trial_index=0,
            hash_seed=_threshold_seed(7, "p0", 0), match_count=0, decision=0,
            label_truth=1, label_outcome="TN", exact_j_truth=1,
            exact_j_outcome="FN", exact_jaccard_bucketed=0.5,
            requested_j_threshold=requested, tau_count=tau,
            realized_j_tau=realized, calibration_fpr=0.0,
            calibration_fnr=0.0, calibration_balanced_error=0.0,
            threshold_workload_sha256="a" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(
                root, cell, "threshold.csv", _REAL_THRESHOLD_HEADER + row + "\n",
                "--csv=")
            command += ["--seed=7", "--threshold-trials=1"]
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": command}})

    def test_r5_blank_canonical_axes_are_rejected_across_schema_families(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape, RevisionContractError
        cases = (
            ("review-comparison-csv-v1", "bcg12_minhash"),
            ("deletion-survival-csv-v1", "deletion_mc"),
            ("dynamic-benchmark-csv-v1", "dynamic_timing"),
            ("estimator-diagnostic-csv-v1", "estimator_accuracy"),
            ("fhe-ind-csv-v1", "fhe_ind"),
            ("piccard-benchmark-csv-v1", "piccard_std128"),
            ("sqrt-comparison-csv-v1", "sqrt_comparison"),
            ("threshold-csv-v1", "threshold_timing"),
        )
        for schema, family in cases:
            with self.subTest(schema=schema, family=family):
                cell = self.matrix_cell(schema, family=family)
                with self.assertRaises(RevisionContractError):
                    _bind_cell_shape([{"k": ""}], cell,
                                     {"command": []}, cell["cell_id"])

    def test_r5_review_security_taxonomy_forgery_is_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape, RevisionContractError
        cell = self.matrix_cell("review-comparison-csv-v1",
                                family="bcg12_minhash",
                                axis="control", axis_value="default")
        row = {
            "k": "128", "m": "64", "set_size": "1000",
            "universe_size": "65536", "comparison_eligible": "true",
            "suite": "bcg12_minhash", "scenario": "review-65536",
            "method": "bcg12_mh_ec", "cryptographic_profile": "FORGED-FHE",
            "nominal_security_bits": "128", "security_match": "true",
            "comparison_scope": "matched-estimator-component",
            "primitive": "bcg12-ec",
            "protocol_model": "bcg12-cardinality-on-minhash",
            "output_semantics": "minhash-collision-jaccard-estimate",
            "assurance_scope": "implemented-baseline-parameter-map",
            "security_basis": "nist-p256-parameter-map",
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
            "secure_division_included": "false", "workload_id": "w",
            "workload_manifest_sha256": "a" * 64,
            "execution_trace_sha256": "b" * 64,
        }
        with self.assertRaises(RevisionContractError):
            _bind_cell_shape([row], cell, {"command": []}, cell["cell_id"])

    def test_r5_review_security_taxonomy_actual_shape_is_accepted(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape
        cell = self.matrix_cell("review-comparison-csv-v1",
                                family="bcg12_minhash",
                                axis="control", axis_value="default")
        base = {
            "k": "128", "m": "64", "set_size": "1000",
            "universe_size": "65536",
            "suite": "bcg12_minhash", "scenario": "review-65536",
            "method": "bcg12_mh_ec", "cryptographic_profile": "P-256",
            "nominal_security_bits": "128",
            "comparison_scope": "matched-estimator-component",
            "primitive": "bcg12-ec",
            "protocol_model": "bcg12-cardinality-on-minhash",
            "output_semantics": "minhash-collision-jaccard-estimate",
            "assurance_scope": "implemented-baseline-parameter-map",
            "security_basis": "nist-p256-parameter-map",
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
            "secure_division_included": "false", "workload_id": "w",
            "workload_manifest_sha256": "a" * 64,
            "execution_trace_sha256": "b" * 64,
        }
        for abstract_profile, row_profile, run_class, target, match, eligible in (
                ("readiness-toy-v1", "readiness-toy-v1", "smoke", "0",
                 "false", "false"),
                ("paper-v1", "std128-t40-primary", "primary", "128",
                 "true", "true")):
            with self.subTest(profile=abstract_profile):
                row = dict(base, profile_id=row_profile, run_class=run_class,
                           target_security_bits=target, security_match=match,
                           comparison_eligible=eligible)
                command = [f"--profile={abstract_profile}",
                           "--suite=bcg12-minhash", "--security=STD128",
                           "--k=128", "--m=64", "--n=1000",
                           "--universe=65536"]
                _bind_cell_shape([row], cell, {"command": command},
                                 cell["cell_id"])

    def test_r6_review_rows_bind_exact_workload_trace_and_timing_arm(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import hashlib
        from tests.scripts import review_verifier_fixtures as fixture
        from verify_revision_benchmarks import (
            _bind_review_sidecars, RevisionContractError)
        methods = ("bcg12_mh_ec", "bcg12_mh_ff")
        seed, k, m, n, universe = 7, 16, 16, 10, 64
        intersection = fixture._realized_intersection(n, 1, 2)
        identities = ((0, 0), (1, 0))
        encoded = []
        workload = bytearray(fixture.WORKLOAD_DOMAIN)
        workload.extend(fixture._string("revision-test"))
        workload.extend(fixture._string("readiness-toy-v1"))
        workload.extend(fixture._be64(seed))
        for value in (k, m, n, universe, 1, 2):
            workload.extend(fixture._be64(value))
        workload.extend(fixture._be32(len(methods)))
        for method in methods:
            workload.extend(fixture._string(method))
        workload.extend(fixture._be32(1) + fixture._be32(0) +
                        fixture._be32(len(identities)))
        for kind, index in identities:
            trial_seed = fixture._trial_seed(seed, kind, index)
            hash_value = fixture._hash_seed(seed, kind, index)
            encoded.append((kind, index, trial_seed))
            set_a, set_b = fixture._regenerate_sets(
                universe, n, intersection, trial_seed)
            workload.extend(bytes([kind]) + fixture._be32(index) +
                            fixture._be64(trial_seed) + fixture._be64(hash_value))
            for values in (set_a, set_b):
                workload.extend(fixture._be64(len(values)))
                for value in values:
                    workload.extend(fixture._be64(value))
            workload.extend(fixture._be64(intersection) +
                            fixture._be64(2 * n - intersection))
        workload_bytes = bytes(workload)
        workload_digest = hashlib.sha256(workload_bytes).digest()
        trace = bytearray(fixture.TRACE_DOMAIN + workload_digest)
        trace.extend(fixture._be32(2) + fixture._be32(2))
        for kind, index, trial_seed in encoded:
            order = methods[trial_seed % 2:] + methods[:trial_seed % 2]
            trace.extend(bytes([kind]) + fixture._be32(index) +
                         fixture._be32(2) + fixture._be32(2) + b"\0")
            for method in order:
                trace.extend(fixture._string(method))
        trace_bytes = bytes(trace)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "workload.bin").write_bytes(workload_bytes)
            (output / "execution-trace.bin").write_bytes(trace_bytes)
            timing = {
                "method": "bcg12_mh_ec", "evidence_arm": "timing",
                "measurement_kind": "psi-timing",
                "workload_id": f"review-{universe}-{workload_digest.hex()[:16]}",
                "workload_manifest_sha256": workload_digest.hex(),
                "execution_trace_sha256": hashlib.sha256(trace_bytes).hexdigest(),
            }
            cell = {
                "family": "revision-test", "axes": {"k": k, "m": m,
                    "n": n, "u": universe},
                "expected_artifact_schema": "review-comparison-csv-v1",
                "expected_rows": [
                    {"method": method, "terminal_status": "MEASURED",
                     "toy_measured_count": 1, "paper_measured_count": 1}
                    for method in methods],
            }
            plan = {"command": ["--profile=readiness-toy-v1", "--seed=7"]}
            _bind_review_sidecars(output, [timing], cell, plan, "toy", "cell")
            for field, forged in (
                    ("workload_id", "FORGED-WORKLOAD"),
                    ("workload_manifest_sha256", "not-a-digest"),
                    ("execution_trace_sha256", "also-forged"),
                    ("measurement_kind", "FORGED-TIMING-KIND"),
                    ("evidence_arm", "FORGED-ARM")):
                with self.subTest(field=field):
                    mutation = dict(timing)
                    mutation[field] = forged
                    with self.assertRaises(RevisionContractError):
                        _bind_review_sidecars(
                            output, [mutation], cell, plan, "toy", "cell")

    def test_r5_encoding_signature_timing_forgery_is_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape, RevisionContractError
        cell = self.matrix_cell("real-dataset-csv-v1", family="real_dataset",
                                axis_value="std192_encoding")
        row = {
            "k": "128", "m": "64", "dataset": "dblp_acm",
            "variant": "dblp_acm_u65536", "target_security_bits": "192",
            "comparison_eligible": "false",
            "comparison_scope": "encoding-only-diagnostic",
            "cost_scope": "encoding-only", "secure_division_included": "false",
            "signature_derivation_timed": "true",
        }
        with self.assertRaises(RevisionContractError):
            _bind_cell_shape([row], cell, {"command": []}, cell["cell_id"])


if __name__ == "__main__":
    unittest.main()
