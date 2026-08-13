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
        values = ["0"] * len(fields)
        values[fields.index("encoding")] = "OneHot"
        values[fields.index("k")] = "128"
        values[fields.index("m")] = "128"
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
        values = ["0"] * len(fields)
        values[fields.index("label")] = "revision_" + cell["cell_id"]
        values[fields.index("k")] = "128"
        values[fields.index("m")] = "128"
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
            values = ["0"] * len(fields)
            values[fields.index("dataset")] = "dblp_acm"
            values[fields.index("variant")] = "dblp_acm_u65536"
            values[fields.index("k")] = "128"
            values[fields.index("m")] = "64"
            values[fields.index("method")] = method
            values[fields.index("timed_encoder_pairs")] = "1"
            values[fields.index("correctness_pair_calls")] = "1"
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
        text = ("overall_status=PASS\nkey_bits=3072\ntrials_per_size=1\n"
                "held_out=32768\nheld_measured_ms=0\n"
                "# columns: key_bits,t_enc_median_ms,t_enc_iqr_ms,alpha_ms_per_m,"
                "beta_ms,r2,held_measured_ms,held_pred_ms,held_residual,gate\n"
                "3072,0,0,0,0,0,0,0,0,PASS\n")
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


if __name__ == "__main__":
    unittest.main()
