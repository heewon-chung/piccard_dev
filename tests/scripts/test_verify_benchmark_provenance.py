#!/usr/bin/env python3
"""Behavior tests for strict benchmark row provenance validation."""

import csv
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "verify_benchmark_provenance.py"
SOURCE = ROOT / ".omo" / "evidence" / "work4-phase4-toy-results.csv"


BENCHMARK_HEADER = (
    "label,k,m,set_size,ring_dim,time_ms,phase_minhash_ms,phase_encode_ms,"
    "phase_encrypt_ms,phase_multiply_ms,phase_rotate_sum_ms,phase_decrypt_ms,"
    "phase_bias_correction_ms,memory_bytes,ct_size_bytes,jaccard_computed,"
    "jaccard_expected,jaccard_error,jaccard_rel_error,accuracy_median,"
    "accuracy_p25,accuracy_p75,accuracy_p95,accuracy_max,encoding,mult_depth,"
    "num_cts,comm_bytes,phase_intra_digit_rotate_ms,phase_digit_and_ms,"
    "phase_cross_k_sum_ms,trials,time_ms_sd,time_ms_median,"
    "phase_minhash_ms_sd,phase_minhash_ms_median,phase_encode_ms_sd,"
    "phase_encode_ms_median,phase_encrypt_ms_sd,phase_encrypt_ms_median,"
    "phase_multiply_ms_sd,phase_multiply_ms_median,phase_rotate_sum_ms_sd,"
    "phase_rotate_sum_ms_median,phase_decrypt_ms_sd,phase_decrypt_ms_median,"
    "phase_bias_correction_ms_sd,phase_bias_correction_ms_median,"
    "rel_error_eligible_n,hash_randomness,hash_seed,hash_root_seed,"
    "accuracy_trials,phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,scaling_mod_size,"
    "sanitizer_model,sanitizer_assurance,estimator_model,profile_id,"
    "run_class,target_security_bits,comparison_eligible,measurement_kind,"
    "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version"
)


def benchmark_row(**overrides):
    row = {
        "label": "evidence_k16_m16_n10_timing", "k": "16", "m": "16",
        "set_size": "10", "ring_dim": "1024", "time_ms": "7.788",
        "jaccard_computed": "0.400000", "jaccard_expected": "0.428571",
        "jaccard_error": "0.028571", "encoding": "onehot", "trials": "1",
        "time_ms_sd": "-1.000", "time_ms_median": "7.788",
        "hash_randomness": "fixed", "hash_seed": "7", "hash_root_seed": "7",
        "accuracy_trials": "0",
        "transcript_stat_bits": "40", "max_queries": "1048576",
        "query_stat_bits": "60", "coefficient_stat_bits": "70",
        "flood_margin_bits": "8", "eval_noise_bits": "56",
        "flood_noise_bits": "134", "scaling_mod_size": "40",
        "sanitizer_model": "phase-smudging-enc0-poc-v1",
        "sanitizer_assurance":
            "empirical-phase-statistical+ciphertext-computational",
        "estimator_model": "sha256-random-ranking-poc-v1",
        "profile_id": "toy-smoke", "run_class": "smoke",
        "target_security_bits": "0", "comparison_eligible": "false",
        "measurement_kind": "fhe-timing", "actual_ring_dim": "1024",
        "log_q_bits": "159.999999723221", "plaintext_modulus": "12289",
        "num_limbs": "4", "openfhe_version": "1.5.0",
    }
    row.update(overrides)
    columns = BENCHMARK_HEADER.split(",")
    return ",".join(row.get(column, "") for column in columns)


def write_benchmark_csv(path, rows):
    path.write_text(BENCHMARK_HEADER + "\n" + "\n".join(rows) + "\n",
                    encoding="utf-8")


DYNAMIC_HEADER = (
    "label,k,m,set_size,ring_dim,depth,phase_init_ms,phase_insert_ms,"
    "phase_delete_ms,phase_signature_ms,phase_encode_ms,phase_encrypt_ms,"
    "phase_compute_ms,phase_decrypt_ms,total_ms,memory_bytes,ct_size_bytes,"
    "jaccard_computed,jaccard_expected,jaccard_error,jaccard_rel_error,"
    "ops_insert_per_sec,ops_delete_per_sec,trials,total_ms_sd,"
    "total_ms_median,phase_init_ms_sd,phase_init_ms_median,"
    "phase_insert_ms_sd,phase_insert_ms_median,phase_delete_ms_sd,"
    "phase_delete_ms_median,phase_signature_ms_sd,phase_signature_ms_median,"
    "phase_encode_ms_sd,phase_encode_ms_median,phase_encrypt_ms_sd,"
    "phase_encrypt_ms_median,phase_compute_ms_sd,phase_compute_ms_median,"
    "phase_decrypt_ms_sd,phase_decrypt_ms_median,rel_error_eligible_n,"
    "hash_randomness,hash_seed,hash_root_seed,accuracy_trials,"
    "phase_flood_ms,phase_flood_ms_sd,phase_flood_ms_median,"
    "transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
    "flood_margin_bits,eval_noise_bits,flood_noise_bits,scaling_mod_size,"
    "sanitizer_model,sanitizer_assurance,estimator_model,profile_id,"
    "run_class,target_security_bits,comparison_eligible,measurement_kind,"
    "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version,"
    "dynamic_scenario,refresh_owner_set_id,refresh_updates,"
    "refresh_epoch_before,refresh_epoch_after,refresh_status,"
    "phase_refresh_update_ms,phase_refresh_signature_ms,"
    "phase_refresh_encode_ms,phase_refresh_encrypt_ms,"
    "phase_refresh_serialize_ms,phase_cloud_replace_ms,refresh_total_ms,"
    "refresh_upload_bytes,refresh_ciphertexts_uploaded,"
    "refresh_context_fingerprint,refresh_public_key_fingerprint"
)


def dynamic_row(**overrides):
    row = {
        "label": "evidence_k16_m16_n10_dynamic", "k": "16", "m": "16",
        "set_size": "10", "ring_dim": "1024", "depth": "5",
        "total_ms": "15.749", "total_ms_sd": "-1.000",
        "total_ms_median": "15.749",
        "jaccard_computed": "0.600000", "jaccard_expected": "0.499250",
        "jaccard_error": "0.100750", "trials": "1",
        "hash_randomness": "fixed", "hash_seed": "7", "hash_root_seed": "7",
        "accuracy_trials": "0",
        "transcript_stat_bits": "40", "max_queries": "1048576",
        "query_stat_bits": "60", "coefficient_stat_bits": "70",
        "flood_margin_bits": "8", "eval_noise_bits": "56",
        "flood_noise_bits": "134", "scaling_mod_size": "40",
        "sanitizer_model": "phase-smudging-enc0-poc-v1",
        "sanitizer_assurance":
            "empirical-phase-statistical+ciphertext-computational",
        "estimator_model": "sha256-random-ranking-poc-v1",
        "profile_id": "toy-smoke", "run_class": "smoke",
        "target_security_bits": "0", "comparison_eligible": "false",
        "measurement_kind": "fhe-timing", "actual_ring_dim": "1024",
        "log_q_bits": "159.999999723221", "plaintext_modulus": "12289",
        "num_limbs": "4", "openfhe_version": "1.5.0",
        "dynamic_scenario": "legacy",
    }
    row.update(overrides)
    columns = DYNAMIC_HEADER.split(",")
    return ",".join(row.get(column, "") for column in columns)


def write_dynamic_csv(path, rows):
    path.write_text(DYNAMIC_HEADER + "\n" + "\n".join(rows) + "\n",
                    encoding="utf-8")


def refresh_row(**overrides):
    values = {
        "label": "refresh_owner_a_0_to_1",
        "set_size": "100",
        "dynamic_scenario": "refresh",
        "refresh_owner_set_id": "owner-a",
        "refresh_updates": "1",
        "refresh_epoch_before": "0",
        "refresh_epoch_after": "1",
        "refresh_status": "applied",
        "phase_refresh_update_ms": "1.000",
        "phase_refresh_signature_ms": "2.000",
        "phase_refresh_encode_ms": "3.000",
        "phase_refresh_encrypt_ms": "4.000",
        "phase_refresh_serialize_ms": "5.000",
        "phase_cloud_replace_ms": "6.000",
        "refresh_total_ms": "21.000",
        "total_ms": "21.000",
        "total_ms_sd": "-1.000",
        "total_ms_median": "21.000",
        "ct_size_bytes": "4096",
        "phase_init_ms": "0.000",
        "phase_init_ms_sd": "-1.000",
        "phase_init_ms_median": "0.000",
        "phase_insert_ms": "1.000",
        "phase_insert_ms_sd": "-1.000",
        "phase_insert_ms_median": "1.000",
        "phase_delete_ms": "0.000",
        "phase_delete_ms_sd": "-1.000",
        "phase_delete_ms_median": "0.000",
        "phase_signature_ms": "2.000",
        "phase_signature_ms_sd": "-1.000",
        "phase_signature_ms_median": "2.000",
        "phase_encode_ms": "3.000",
        "phase_encode_ms_sd": "-1.000",
        "phase_encode_ms_median": "3.000",
        "phase_encrypt_ms": "4.000",
        "phase_encrypt_ms_sd": "-1.000",
        "phase_encrypt_ms_median": "4.000",
        "phase_compute_ms": "0.000",
        "phase_compute_ms_sd": "-1.000",
        "phase_compute_ms_median": "0.000",
        "phase_decrypt_ms": "0.000",
        "phase_decrypt_ms_sd": "-1.000",
        "phase_decrypt_ms_median": "0.000",
        "phase_flood_ms": "0.000",
        "phase_flood_ms_sd": "-1.000",
        "phase_flood_ms_median": "0.000",
        "jaccard_computed": "0.600000",
        "jaccard_expected": "0.499250",
        "jaccard_error": "0.100750",
        "jaccard_rel_error": "0.201803",
        "rel_error_eligible_n": "1",
        "refresh_upload_bytes": "4096",
        "refresh_ciphertexts_uploaded": "1",
        "refresh_context_fingerprint": "1" * 64,
        "refresh_public_key_fingerprint": "2" * 64,
    }
    values.update(overrides)
    return dynamic_row(**values)


class BenchmarkProvenanceVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.csv_path = Path(self.temp.name) / "results.csv"
        with SOURCE.open(newline="") as stream:
            reader = csv.DictReader(stream)
            self.fields = list(reader.fieldnames or ())
            self.rows = list(reader)
        self.write_rows(self.rows)

    def write_rows(self, rows):
        with self.csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self.fields)
            writer.writeheader()
            writer.writerows(rows)

    def run_verifier(self):
        return subprocess.run(
            ["python3", str(VERIFIER), f"--csv={self.csv_path}"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_legacy_baseline_label_is_rejected(self):
        rows = [dict(row) for row in self.rows]
        rows[4]["method"] = "baseline"
        self.write_rows(rows)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("unknown method", result.stderr)

    def assert_rejects(self, rows, cause):
        self.write_rows(rows)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(cause, result.stderr)

    def test_valid_persisted_toy_rows_pass(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"verdict": "PASS"', result.stdout)

    def test_measured_rows_require_each_core_metric_to_be_finite(self):
        required_metrics = (
            "total_ms", "total_ms_median", "jaccard_computed",
            "jaccard_expected", "jaccard_error",
        )
        for column in required_metrics:
            for value in ("", "NaN"):
                with self.subTest(column=column, value=value):
                    rows = [dict(row) for row in self.rows]
                    rows[0][column] = value
                    self.assert_rejects(rows, column)

    def test_complete_std128_capability_fixture_passes(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            row.update(profile_id="std128-t40-primary", run_class="primary",
                       target_security_bits="128", security_match="true",
                       comparison_eligible="true")
            if row["method"] in {"piccard", "piccard_sqrt"}:
                row.update(cryptographic_profile="live-BFV-STD128",
                           nominal_security_bits="128")
            elif row["method"] == "fhe_ind":
                row.update(cryptographic_profile="live-BFV-STD128",
                           nominal_security_bits="128",
                           comparison_eligible="false")
            elif row["method"] == "sj16":
                row.update(cryptographic_profile="Paillier-3072",
                           nominal_security_bits="128", primitive="paillier-3072",
                           security_basis="rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security")
        self.write_rows(rows)
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_work5_single_trial_profiles_are_smoke_t40_and_not_comparison_eligible(self):
        for profile, target in (("work5-std128-t40-single-trial", "128"),
                                ("work5-std192-t40-single-trial", "192")):
            with self.subTest(profile=profile):
                rows = [dict(row) for row in self.rows]
                for row in rows:
                    row.update(profile_id=profile, run_class="smoke",
                               target_security_bits=target, comparison_eligible="false")
                    if row["method"] in {"piccard", "piccard_sqrt", "fhe_ind"}:
                        row.update(cryptographic_profile=f"live-BFV-STD{target}",
                                   nominal_security_bits=target, security_match="true")
                    elif row["method"] == "sj16":
                        row.update(cryptographic_profile="Paillier-3072", nominal_security_bits="128",
                                   primitive="paillier-3072",
                                   security_basis="rsa-ifc-modulus-size-proxy-not-a-proof-of-equivalent-security",
                                   security_match="true" if target == "128" else "false")
                    elif row["method"].startswith("bcg12_"):
                        row.update(nominal_security_bits="128",
                                   security_match="true" if target == "128" else "false")
                self.write_rows(rows)
                result = self.run_verifier()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_actual_fhe_metadata_fails(self):
        rows = [dict(row) for row in self.rows]
        rows[0]["actual_ring_dim"] = ""
        self.assert_rejects(rows, "actual FHE metadata")

    def test_invalid_ahe_profile_and_unmatched_std192_claim_fail(self):
        rows = [dict(row) for row in self.rows]
        rows[10]["cryptographic_profile"] = "Paillier-4096"
        self.assert_rejects(rows, "AHE profile")

        rows = [dict(row) for row in self.rows]
        rows[10].update(profile_id="std192-t40-primary", run_class="primary",
                       target_security_bits="192", cryptographic_profile="Paillier-3072",
                       nominal_security_bits="128", primitive="paillier-3072",
                       security_match="true", comparison_eligible="true")
        self.assert_rejects(rows, "STD192")

    def test_sj16_lower_bound_and_model_markers_are_required(self):
        rows = [dict(row) for row in self.rows]
        rows[10]["assurance_scope"] = "not-applicable"
        self.assert_rejects(rows, "lower-bound")

        rows = [dict(row) for row in self.rows]
        rows[0]["estimator_model"] = ""
        self.assert_rejects(rows, "estimator_model")

        rows = [dict(row) for row in self.rows]
        rows[0]["sanitizer_model"] = ""
        self.assert_rejects(rows, "sanitizer_model")

        rows = [dict(row) for row in self.rows]
        rows[0]["query_stat_bits"] = "61"
        self.assert_rejects(rows, "query_stat_bits")

    def test_nonfinite_numeric_and_csv_shape_fail_closed(self):
        for value in ("NaN", "Inf", "-Inf"):
            with self.subTest(value=value):
                rows = [dict(row) for row in self.rows]
                rows[0]["total_ms"] = value
                self.assert_rejects(rows, "finite numeric")

        text = self.csv_path.read_text().splitlines()
        text[1] += ",extra-cell"
        self.csv_path.write_text("\n".join(text) + "\n")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("column count", result.stderr)

    def test_required_column_is_not_optional(self):
        missing = "measurement_status"
        fields = [field for field in self.fields if field != missing]
        with self.csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.rows)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("required columns", result.stderr)


class PiccardFamilySchemaVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.csv_path = Path(self.temp.name) / "family.csv"
        with SOURCE.open(newline="") as stream:
            reader = csv.DictReader(stream)
            self.review_fields = list(reader.fieldnames or ())
            self.review_rows = list(reader)

    def write_review_csv(self):
        with self.csv_path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self.review_fields)
            writer.writeheader()
            writer.writerows(self.review_rows)

    def run_verifier(self, *extra_args):
        return subprocess.run(
            ["python3", str(VERIFIER), f"--csv={self.csv_path}", *extra_args],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_benchmark_schema_accepts_real_piccard_family_row(self):
        write_benchmark_csv(self.csv_path, [benchmark_row()])
        result = self.run_verifier("--schema=benchmark")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"schema": "benchmark"', result.stdout)

    def test_benchmark_schema_accepts_accuracy_row(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(
            measurement_kind="fhe-accuracy", time_ms="0.000")])
        result = self.run_verifier("--schema=benchmark")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dynamic_schema_accepts_real_dynamic_row(self):
        write_dynamic_csv(self.csv_path, [dynamic_row()])
        result = self.run_verifier("--schema=dynamic")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"schema": "dynamic"', result.stdout)

    def test_dynamic_schema_accepts_complete_refresh_row(self):
        write_dynamic_csv(self.csv_path, [refresh_row()])
        result = self.run_verifier("--schema=dynamic")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dynamic_refresh_accepts_inclusive_serialized_decimal_boundaries(self):
        cases = (
            ("phase-total", refresh_row(
                refresh_total_ms="21.010", total_ms="21.010",
                total_ms_median="21.010")),
            ("absolute-error", refresh_row(
                jaccard_error="0.100752",
                jaccard_rel_error="0.2018067100650976464697045568")),
            ("relative-error", refresh_row(
                jaccard_computed="0.5", jaccard_expected="0.5",
                jaccard_error="0", jaccard_rel_error="0.000005")),
        )
        for label, row in cases:
            with self.subTest(label=label):
                write_dynamic_csv(self.csv_path, [row])
                result = self.run_verifier("--schema=dynamic")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_dynamic_refresh_rejects_each_false_evidence_binding(self):
        mutations = {
            "refresh_owner_set_id": "owner-b", "refresh_updates": "0",
            "refresh_epoch_before": "1", "refresh_epoch_after": "2",
            "refresh_status": "skipped", "phase_refresh_update_ms": "1.100",
            "phase_refresh_signature_ms": "2.100", "phase_refresh_encode_ms": "3.100",
            "phase_refresh_encrypt_ms": "4.100", "phase_refresh_serialize_ms": "5.100",
            "phase_cloud_replace_ms": "6.100", "refresh_total_ms": "21.100",
            "total_ms": "21.100", "total_ms_median": "21.100", "total_ms_sd": "0.000",
            "phase_insert_ms": "1.100", "phase_signature_ms": "2.100",
            "phase_encode_ms": "3.100", "phase_encrypt_ms": "4.100",
            "phase_insert_ms_median": "1.100", "phase_signature_ms_median": "2.100",
            "phase_encode_ms_median": "3.100", "phase_encrypt_ms_median": "4.100",
            "phase_insert_ms_sd": "0.000", "phase_signature_ms_sd": "0.000",
            "phase_encode_ms_sd": "0.000", "phase_encrypt_ms_sd": "0.000",
            "ct_size_bytes": "4097", "refresh_upload_bytes": "0",
            "refresh_ciphertexts_uploaded": "2",
            "refresh_context_fingerprint": "A" * 64,
            "refresh_public_key_fingerprint": "2" * 63,
            "jaccard_computed": "1.100000", "jaccard_expected": "0.000000",
            "jaccard_error": "0.100753", "jaccard_rel_error": "0.201809",
            "rel_error_eligible_n": "0", "profile_id": "std128-t40-primary",
            "run_class": "primary", "target_security_bits": "128",
            "comparison_eligible": "true", "measurement_kind": "fhe-accuracy",
            "trials": "2", "accuracy_trials": "1", "hash_randomness": "random",
            "hash_seed": "8", "hash_root_seed": "8",
            "transcript_stat_bits": "41", "max_queries": "2097152",
            "query_stat_bits": "61", "coefficient_stat_bits": "71",
            "flood_margin_bits": "9", "eval_noise_bits": "57",
            "flood_noise_bits": "135", "scaling_mod_size": "41",
            "sanitizer_model": "wrong", "sanitizer_assurance": "wrong",
            "estimator_model": "wrong", "actual_ring_dim": "2048",
            "log_q_bits": "160.0", "plaintext_modulus": "12290",
            "num_limbs": "5", "openfhe_version": "1.5.1",
        }
        for unused in ("phase_init_ms", "phase_delete_ms", "phase_compute_ms",
                       "phase_decrypt_ms", "phase_flood_ms"):
            mutations[unused] = "0.100"
            mutations[f"{unused}_median"] = "0.100"
            mutations[f"{unused}_sd"] = "0.000"
        for column, value in mutations.items():
            with self.subTest(column=column):
                write_dynamic_csv(self.csv_path, [refresh_row(**{column: value})])
                result = self.run_verifier("--schema=dynamic")
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_dynamic_refresh_rejects_phase_sum_legacy_cells_and_strict_numbers(self):
        cases = (
            ("phase sum", refresh_row(phase_cloud_replace_ms="6.020")),
            ("legacy", dynamic_row(refresh_total_ms="21.000")),
            ("empty", refresh_row(phase_refresh_update_ms="")),
            ("nonfinite", refresh_row(phase_refresh_update_ms="NaN")),
        )
        for label, row in cases:
            with self.subTest(label=label):
                write_dynamic_csv(self.csv_path, [row])
                result = self.run_verifier("--schema=dynamic")
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_dynamic_refresh_rejects_relative_error_just_outside_boundary(self):
        write_dynamic_csv(self.csv_path, [refresh_row(
            jaccard_computed="0.5", jaccard_expected="0.5",
            jaccard_error="0", jaccard_rel_error="0.000006")])
        result = self.run_verifier("--schema=dynamic")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_default_schema_still_rejects_piccard_family_csv(self):
        write_benchmark_csv(self.csv_path, [benchmark_row()])
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("missing required columns", result.stderr)

    def test_benchmark_schema_rejects_review_csv(self):
        self.write_review_csv()
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_review_schema_unchanged_on_valid_fixture(self):
        self.write_review_csv()
        result = self.run_verifier("--schema=review")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"verdict": "PASS"', result.stdout)

    def test_benchmark_schema_rejects_wrong_measurement_kind(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(
            measurement_kind="psi-timing")])
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_benchmark_schema_rejects_missing_sanitizer_cell(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(
            flood_noise_bits="")])
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("flood_noise_bits", result.stderr)

    def test_benchmark_schema_rejects_inconsistent_sanitizer_arithmetic(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(
            query_stat_bits="61")])
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("query_stat_bits", result.stderr)

    def test_benchmark_schema_rejects_nonfinite_metric(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(time_ms="nan")])
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("finite", result.stderr)

    def test_benchmark_schema_rejects_estimator_model_mismatch(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(
            estimator_model="not-applicable")])
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("estimator_model", result.stderr)

    def test_benchmark_schema_rejects_wrong_profile_metadata(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(
            run_class="primary")])
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_benchmark_schema_rejects_comparison_eligibility_mismatch(self):
        write_benchmark_csv(self.csv_path, [benchmark_row(
            comparison_eligible="true")])
        result = self.run_verifier("--schema=benchmark")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("comparison_eligible", result.stderr)

    def test_unknown_schema_value_fails(self):
        write_benchmark_csv(self.csv_path, [benchmark_row()])
        result = self.run_verifier("--schema=piccard")
        self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
