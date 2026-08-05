"""Behavior tests for the Work-5 real-dataset manifest/writer core.

Covers scripts/prepare_real_datasets.py: strict source-manifest validation,
the canonical TSV grammar, the deterministic feature-hashing primitives, the
atomic processed-output writer, and the .gitignore scoping for datasets/.

Hermetic: every test builds its inputs under tempfile.TemporaryDirectory();
none of them touch the real datasets/ tree or the network.
"""

import csv
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "prepare_real_datasets.py"
COMMON_FIXTURES = REPO / "tests" / "fixtures" / "real_datasets" / "common"

# The exact piccard-real-processed-v1 ordered key list (normative plan
# "Exact shared file grammar" / Phase 1 GREEN, lines ~214-235), hardcoded
# here independently of the module under test so the order check itself is
# pinned rather than tautologically re-derived from the implementation.
_DBLP_PROCESSED_KEY_ORDER = (
    "schema_version", "dataset", "variant", "preprocessing_version",
    "universe_size", "seed",
    "source_manifest_file", "source_manifest_sha256",
    "records_file", "records_sha256", "record_count",
    "pairs_file", "pairs_sha256", "pair_count",
    "raw_set_size_min", "raw_set_size_median", "raw_set_size_p95", "raw_set_size_max",
    "bucketed_set_size_min", "bucketed_set_size_median",
    "bucketed_set_size_p95", "bucketed_set_size_max",
    "original_positive_count", "retained_positive_count", "requested_pair_count",
    "max_documents", "min_related_pairs",
    "dropped.empty_features_dblp", "dropped.empty_features_acm",
)

_ENRON_PROCESSED_KEY_ORDER = (
    "schema_version", "dataset", "variant", "preprocessing_version",
    "universe_size", "seed",
    "source_manifest_file", "source_manifest_sha256",
    "records_file", "records_sha256", "record_count",
    "pairs_file", "pairs_sha256", "pair_count",
    "raw_set_size_min", "raw_set_size_median", "raw_set_size_p95", "raw_set_size_max",
    "bucketed_set_size_min", "bucketed_set_size_median",
    "bucketed_set_size_p95", "bucketed_set_size_max",
    "original_positive_count", "retained_positive_count", "requested_pair_count",
    "max_documents", "min_related_pairs",
    "dropped.charset_or_mime", "dropped.empty_body", "dropped.short_body",
    "dropped.duplicate_message_id",
)


def load_module():
    spec = importlib.util.spec_from_file_location(
        "prepare_real_datasets", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_lf(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def write_csv_lf(path: Path, header, rows) -> None:
    """Write a strict RFC4180 CSV with LF line endings (Python's csv module
    quotes fields containing commas/quotes/newlines automatically)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)
    path.write_bytes(buf.getvalue().encode("utf-8"))


QUICK_DBLP_ACM_DIR = (REPO / "tests" / "fixtures" / "real_datasets" / "quick"
                      / "dblp_acm_u65536")


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _copy_common_fixture(self, tmp_dir: Path, name: str, dest_name: str) -> Path:
        data = (COMMON_FIXTURES / name).read_bytes()
        dest = tmp_dir / dest_name
        dest.write_bytes(data)
        return dest

    def _build_dblp_acm_manifest(self, tmp_dir: Path, *, bad_index0_sha=None,
                                  bad_index0_path=None, dataset_version="2026-release",
                                  source_url="https://example.invalid/dblp-acm",
                                  citation="Example Citation 2020",
                                  license_url="https://example.invalid/terms",
                                  acquisition_note="acquired locally on 2026-01-01"):
        dblp_path = self._copy_common_fixture(tmp_dir, "sample_a.txt", "dblp_records.csv")
        acm_path = self._copy_common_fixture(tmp_dir, "sample_b.txt", "acm_records.csv")
        mapping_path = self._copy_common_fixture(tmp_dir, "sample_c.txt", "mapping.csv")

        sha0 = bad_index0_sha if bad_index0_sha is not None else sha256_hex(
            dblp_path.read_bytes())
        path0 = bad_index0_path if bad_index0_path is not None else "dblp_records.csv"
        sha1 = sha256_hex(acm_path.read_bytes())
        sha2 = sha256_hex(mapping_path.read_bytes())

        lines = [
            "key\tvalue",
            "schema_version\tpiccard-real-source-v1",
            "dataset\tdblp_acm",
            f"dataset_version\t{dataset_version}",
            f"source_url\t{source_url}",
            f"citation\t{citation}",
            f"license_or_terms_url\t{license_url}",
            f"acquisition_note\t{acquisition_note}",
            "parsing_schema\tdblp-acm-csv-v1",
            "preprocessing_profile\tdblp-acm-trigram-v1",
            "input.0.role\tdblp_records",
            f"input.0.path\t{path0}",
            f"input.0.sha256\t{sha0}",
            "input.1.role\tacm_records",
            "input.1.path\tacm_records.csv",
            f"input.1.sha256\t{sha1}",
            "input.2.role\tdblp_acm_mapping",
            "input.2.path\tmapping.csv",
            f"input.2.sha256\t{sha2}",
        ]
        manifest_path = tmp_dir / "source.manifest.tsv"
        write_lf(manifest_path, "\n".join(lines) + "\n")
        return manifest_path

    def _minimal_record(self, record_id, raw_features=(1, 2), bucketed_features=(1, 2)):
        return self.module.RecordRow(
            record_id=record_id,
            raw_features=tuple(raw_features),
            bucketed_features=tuple(bucketed_features))

    def _minimal_pair(self, pair_id, record_a, record_b, pair_kind="known_match",
                       label=1):
        return self.module.PairRow(
            pair_id=pair_id, record_a=record_a, record_b=record_b,
            pair_kind=pair_kind, label=label)

    def _manifest_pairs_for(self, records, pairs, records_sha, pairs_sha,
                             source_sha, dataset="dblp_acm", overrides=None):
        is_dblp = dataset == "dblp_acm"
        values = {
            "schema_version": "piccard-real-processed-v1",
            "dataset": dataset,
            "variant": "dblp_acm_u65536" if is_dblp else "enron_u65536",
            "preprocessing_version":
                "dblp-acm-trigram-v1" if is_dblp else "enron-shingle5-v1",
            "universe_size": "65536",
            "seed": "7",
            "source_manifest_file": "source.manifest.tsv",
            "source_manifest_sha256": source_sha,
            "records_file": "records.tsv",
            "records_sha256": records_sha,
            "record_count": str(len(records)),
            "pairs_file": "pairs.tsv",
            "pairs_sha256": pairs_sha,
            "pair_count": str(len(pairs)),
            "raw_set_size_min": "1",
            "raw_set_size_median": "1",
            "raw_set_size_p95": "1",
            "raw_set_size_max": "1",
            "bucketed_set_size_min": "1",
            "bucketed_set_size_median": "1",
            "bucketed_set_size_p95": "1",
            "bucketed_set_size_max": "1",
            "original_positive_count": "1" if is_dblp else "",
            "retained_positive_count": "1" if is_dblp else "",
            "requested_pair_count": str(len(pairs)),
            "max_documents": "" if is_dblp else "10",
            "min_related_pairs": "" if is_dblp else "2",
            "dropped.empty_features_dblp": "0",
            "dropped.empty_features_acm": "0",
            "dropped.charset_or_mime": "0",
            "dropped.empty_body": "0",
            "dropped.short_body": "0",
            "dropped.duplicate_message_id": "0",
        }
        if overrides:
            values.update(overrides)
        order = _DBLP_PROCESSED_KEY_ORDER if is_dblp else _ENRON_PROCESSED_KEY_ORDER
        return [(key, values[key]) for key in order]

    def _write_valid_output(self, module, tmp_dir, output_dir, *, overwrite=False):
        manifest_path = self._build_dblp_acm_manifest(tmp_dir)
        records = [self._minimal_record("dblp:01"), self._minimal_record("acm:02")]
        pairs = [self._minimal_pair("dblp_acm-pair:aa", "acm:02", "dblp:01")]
        records_sha = sha256_hex(module._canonicalize_records(records))
        pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
        source_sha = sha256_hex(manifest_path.read_bytes())
        manifest_pairs = self._manifest_pairs_for(
            records, pairs, records_sha, pairs_sha, source_sha)
        module.write_processed_output(
            output_dir, records, pairs, manifest_pairs, manifest_path,
            overwrite=overwrite)
        return records, pairs, manifest_pairs, manifest_path

    # ------------------------------------------------------------------
    # sha256_file / parse_two_column_tsv
    # ------------------------------------------------------------------

    def test_sha256_file_matches_hashlib(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.bin"
            path.write_bytes(b"hello world")
            self.assertEqual(module.sha256_file(path), hashlib.sha256(b"hello world").hexdigest())

    def test_parse_two_column_tsv_strict_grammar(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kv.tsv"
            write_lf(path, "key\tvalue\na\t1\nb\t2\n")
            self.assertEqual(module.parse_two_column_tsv(path), [("a", "1"), ("b", "2")])

    def test_parse_two_column_tsv_rejects_bad_header(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kv.tsv"
            write_lf(path, "wrong\theader\na\t1\n")
            with self.assertRaises(module.ManifestError):
                module.parse_two_column_tsv(path)

    def test_parse_two_column_tsv_rejects_missing_trailing_newline(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kv.tsv"
            path.write_bytes(b"key\tvalue\na\t1")
            with self.assertRaises(module.ManifestError):
                module.parse_two_column_tsv(path)

    def test_parse_two_column_tsv_rejects_bom(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kv.tsv"
            path.write_bytes(b"\xef\xbb\xbfkey\tvalue\na\t1\n")
            with self.assertRaises(module.ManifestError):
                module.parse_two_column_tsv(path)

    def test_parse_two_column_tsv_rejects_multi_tab_line(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kv.tsv"
            write_lf(path, "key\tvalue\na\t1\t2\n")
            with self.assertRaises(module.ManifestError):
                module.parse_two_column_tsv(path)

    # ------------------------------------------------------------------
    # validate_source_manifest
    # ------------------------------------------------------------------

    def test_validate_source_manifest_accepts_well_formed_manifest(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._build_dblp_acm_manifest(Path(tmp))
            result = module.validate_source_manifest(manifest_path, "dblp_acm")
            self.assertEqual(result.dataset, "dblp_acm")
            self.assertEqual(len(result.inputs), 3)
            self.assertEqual(result.inputs[0].role, "dblp_records")

    def test_validate_source_manifest_rejects_missing_checksum(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            lines = manifest_path.read_text("utf-8").splitlines()
            lines = [l for l in lines if not l.startswith("input.0.sha256\t")]
            write_lf(manifest_path, "\n".join(lines) + "\n")
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    def test_validate_source_manifest_rejects_placeholder_checksum(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._build_dblp_acm_manifest(
                Path(tmp), bad_index0_sha="TODO")
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    def test_validate_source_manifest_rejects_placeholder_scalar_field(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._build_dblp_acm_manifest(
                Path(tmp), acquisition_note="unknown")
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    def test_validate_source_manifest_rejects_unreadable_input(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._build_dblp_acm_manifest(
                Path(tmp), bad_index0_path="does-not-exist.csv",
                bad_index0_sha="a" * 64)
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    def test_validate_source_manifest_rejects_absolute_input_path(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._build_dblp_acm_manifest(
                Path(tmp), bad_index0_path="/etc/passwd", bad_index0_sha="a" * 64)
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    def test_validate_source_manifest_rejects_path_escape(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = self._build_dblp_acm_manifest(
                Path(tmp), bad_index0_path="../outside.csv", bad_index0_sha="a" * 64)
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    def test_validate_source_manifest_rejects_symlink_input(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            real_target = tmp_dir / "real_target.csv"
            real_target.write_bytes(b"payload")
            link_path = tmp_dir / "linked.csv"
            link_path.symlink_to(real_target)
            manifest_path = self._build_dblp_acm_manifest(
                tmp_dir, bad_index0_path="linked.csv",
                bad_index0_sha=sha256_hex(real_target.read_bytes()))
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    def test_validate_source_manifest_checksum_mismatch_creates_no_output(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(
                tmp_dir, bad_index0_sha="b" * 64)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")
            self.assertFalse(output_dir.exists())

    def test_validate_source_manifest_enron_maildir_role(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            maildir = tmp_dir / "maildir"
            (maildir / "inbox").mkdir(parents=True)
            (maildir / "inbox" / "1.").write_bytes(b"From: a\n\nhi\n")
            digest = module._directory_tree_digest(maildir)
            lines = [
                "key\tvalue",
                "schema_version\tpiccard-real-source-v1",
                "dataset\tenron",
                "dataset_version\t2026-release",
                "source_url\thttps://example.invalid/enron",
                "citation\tExample Citation 2020",
                "license_or_terms_url\thttps://example.invalid/terms",
                "acquisition_note\tacquired locally on 2026-01-01",
                "parsing_schema\tenron-maildir-rfc5322-v1",
                "preprocessing_profile\tenron-shingle5-v1",
                "input.0.role\tmaildir_root",
                "input.0.path\tmaildir",
                f"input.0.sha256\t{digest}",
            ]
            manifest_path = tmp_dir / "source.manifest.tsv"
            write_lf(manifest_path, "\n".join(lines) + "\n")
            result = module.validate_source_manifest(manifest_path, "enron")
            self.assertEqual(result.inputs[0].role, "maildir_root")

    def test_directory_tree_digest_rejects_symlink(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            maildir = tmp_dir / "maildir"
            maildir.mkdir()
            real_file = tmp_dir / "outside.txt"
            real_file.write_bytes(b"x")
            (maildir / "link").symlink_to(real_file)
            with self.assertRaises(module.ManifestError):
                module._directory_tree_digest(maildir)

    # ------------------------------------------------------------------
    # canonical_feature_hash / bucket_features / normalize_text
    # ------------------------------------------------------------------

    def test_canonical_feature_hash_known_answer(self):
        module = self.module
        # Independent 5-line reference computation (not calling the module
        # under test), pinning the exact known-answer vector.
        digest = hashlib.sha256(
            b"piccard-real-feature-v1\x00" + "title=abc".encode("utf-8")).digest()
        expected = int.from_bytes(digest[:8], "big")
        self.assertEqual(module.canonical_feature_hash("title=abc"), expected)

    def test_canonical_feature_hash_is_deterministic_and_distinguishes_input(self):
        module = self.module
        a = module.canonical_feature_hash("title=abc")
        b = module.canonical_feature_hash("title=abd")
        self.assertEqual(a, module.canonical_feature_hash("title=abc"))
        self.assertNotEqual(a, b)

    def test_bucket_features_mods_sorts_and_dedups(self):
        module = self.module
        # 5 % 65536 == 5 and 65541 % 65536 == 5: two inputs collapse to one
        # bucketed value; 70000 % 65536 == 4464 stays distinct.
        self.assertEqual(
            module.bucket_features([70000, 5, 65541, 5], 65536), [5, 4464])

    def test_normalize_text_pipeline(self):
        module = self.module
        self.assertEqual(module.normalize_text("  Hello,   WORLD!! "), "hello world")
        # Only ASCII [a-z0-9] survives; a diacritic maps to a space and is
        # then stripped, per the exact "non-[a-z0-9] => ' '" contract.
        self.assertEqual(module.normalize_text("Café"), "caf")

    # ------------------------------------------------------------------
    # format_float
    # ------------------------------------------------------------------

    def test_format_float_normalizes_negative_zero(self):
        module = self.module
        self.assertEqual(module.format_float(-0.0), "0")
        self.assertEqual(module.format_float(0.0), "0")

    def test_format_float_basic_values(self):
        module = self.module
        self.assertEqual(module.format_float(1.0), "1")
        self.assertEqual(module.format_float(0.1), "%.17g" % 0.1)

    def test_format_float_rejects_non_finite(self):
        module = self.module
        with self.assertRaises(module.ManifestError):
            module.format_float(float("nan"))
        with self.assertRaises(module.ManifestError):
            module.format_float(float("inf"))

    # ------------------------------------------------------------------
    # summarize_set_sizes
    # ------------------------------------------------------------------

    def test_summarize_set_sizes_n1(self):
        module = self.module
        stats = module.summarize_set_sizes([5])
        self.assertEqual((stats.min, stats.median, stats.p95, stats.max), (5, 5.0, 5, 5))

    def test_summarize_set_sizes_n2_even_median_and_nearest_rank_p95(self):
        module = self.module
        stats = module.summarize_set_sizes([20, 10])
        self.assertEqual(stats.min, 10)
        self.assertEqual(stats.max, 20)
        self.assertEqual(stats.median, 15.0)
        self.assertEqual(stats.p95, 20)

    def test_summarize_set_sizes_n3(self):
        module = self.module
        stats = module.summarize_set_sizes([3, 1, 2])
        self.assertEqual((stats.min, stats.median, stats.p95, stats.max), (1, 2.0, 3, 3))

    def test_summarize_set_sizes_n20(self):
        module = self.module
        stats = module.summarize_set_sizes(list(range(1, 21)))
        self.assertEqual(stats.min, 1)
        self.assertEqual(stats.max, 20)
        self.assertEqual(stats.median, 10.5)
        self.assertEqual(stats.p95, 19)

    def test_summarize_set_sizes_rejects_empty(self):
        module = self.module
        with self.assertRaises(module.ManifestError):
            module.summarize_set_sizes([])

    # ------------------------------------------------------------------
    # write_processed_output
    # ------------------------------------------------------------------

    def test_write_processed_output_row_order_independent_byte_identical(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records_fwd = [self._minimal_record("dblp:01"), self._minimal_record("acm:02")]
            records_rev = list(reversed(records_fwd))
            pairs_fwd = [self._minimal_pair("dblp_acm-pair:aa", "acm:02", "dblp:01"),
                         self._minimal_pair("dblp_acm-pair:bb", "dblp:01", "acm:02",
                                             pair_kind="sampled_nonmatch", label=0)]
            pairs_rev = list(reversed(pairs_fwd))

            records_sha = sha256_hex(module._canonicalize_records(records_fwd))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs_fwd))
            source_sha = sha256_hex(manifest_path.read_bytes())
            manifest_pairs = self._manifest_pairs_for(
                records_fwd, pairs_fwd, records_sha, pairs_sha, source_sha)

            out_a = tmp_dir / "out_a"
            out_b = tmp_dir / "out_b"
            module.write_processed_output(
                out_a, records_fwd, pairs_fwd, manifest_pairs, manifest_path,
                overwrite=False)
            module.write_processed_output(
                out_b, records_rev, pairs_rev, manifest_pairs, manifest_path,
                overwrite=False)

            self.assertEqual((out_a / "records.tsv").read_bytes(),
                              (out_b / "records.tsv").read_bytes())
            self.assertEqual((out_a / "pairs.tsv").read_bytes(),
                              (out_b / "pairs.tsv").read_bytes())

    def test_write_processed_output_rejects_duplicate_record_id(self):
        module = self.module
        records = [self._minimal_record("dblp:01"), self._minimal_record("dblp:01")]
        with self.assertRaises(module.ManifestError):
            module._canonicalize_records(records)

    def test_write_processed_output_provenance_differs_with_raw_bytes(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_a = self._build_dblp_acm_manifest(
                tmp_dir, dataset_version="release-A")
            manifest_b_dir = tmp_dir / "b"
            manifest_b_dir.mkdir()
            manifest_b = self._build_dblp_acm_manifest(
                manifest_b_dir, dataset_version="release-B")
            self.assertNotEqual(sha256_hex(manifest_a.read_bytes()),
                                 sha256_hex(manifest_b.read_bytes()))

            records = [self._minimal_record("dblp:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))

            out_a = tmp_dir / "out_a"
            out_b = tmp_dir / "out_b"
            manifest_pairs_a = self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha,
                sha256_hex(manifest_a.read_bytes()))
            manifest_pairs_b = self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha,
                sha256_hex(manifest_b.read_bytes()))
            module.write_processed_output(
                out_a, records, pairs, manifest_pairs_a, manifest_a, overwrite=False)
            module.write_processed_output(
                out_b, records, pairs, manifest_pairs_b, manifest_b, overwrite=False)

            self.assertNotEqual(
                (out_a / "source.manifest.tsv").read_bytes(),
                (out_b / "source.manifest.tsv").read_bytes())
            self.assertNotEqual(
                sha256_hex((out_a / "dataset.manifest.tsv").read_bytes()),
                sha256_hex((out_b / "dataset.manifest.tsv").read_bytes()))

    def test_write_processed_output_rejects_overwrite_without_flag(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "out"
            self._write_valid_output(module, tmp_dir, output_dir)
            before = (output_dir / "records.tsv").read_bytes()
            with self.assertRaises(module.ManifestError):
                self._write_valid_output(module, tmp_dir, output_dir)
            self.assertEqual((output_dir / "records.tsv").read_bytes(), before)

    def test_write_processed_output_overwrite_replaces_contents(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "out"
            self._write_valid_output(module, tmp_dir, output_dir)
            # Second call with overwrite=True must succeed cleanly.
            self._write_valid_output(module, tmp_dir, output_dir, overwrite=True)
            self.assertTrue((output_dir / "records.tsv").exists())

    def test_write_processed_output_rejects_checksum_mismatch_in_manifest_pairs(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("dblp:01")]
            pairs = []
            manifest_pairs = self._manifest_pairs_for(
                records, pairs, "0" * 64, sha256_hex(module._canonicalize_pairs(pairs)),
                sha256_hex(manifest_path.read_bytes()))
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.write_processed_output(
                    output_dir, records, pairs, manifest_pairs, manifest_path,
                    overwrite=False)
            self.assertFalse(output_dir.exists())

    def test_write_processed_output_injected_write_failure_leaves_no_partial_dir(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("dblp:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
            source_sha = sha256_hex(manifest_path.read_bytes())
            manifest_pairs = self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha, source_sha)
            output_dir = tmp_dir / "out"

            call_count = {"n": 0}
            real_writer = module._write_file_with_fsync

            def flaky_writer(path, data):
                call_count["n"] += 1
                if call_count["n"] == 2:
                    raise OSError("injected failure")
                return real_writer(path, data)

            with mock.patch.object(module, "_write_file_with_fsync", flaky_writer):
                with self.assertRaises(OSError):
                    module.write_processed_output(
                        output_dir, records, pairs, manifest_pairs, manifest_path,
                        overwrite=False)

            self.assertFalse(output_dir.exists())
            leftovers = list(tmp_dir.glob(".out.tmp-*"))
            self.assertEqual(leftovers, [])

    # ------------------------------------------------------------------
    # templates strict-rejected
    # ------------------------------------------------------------------

    def test_dblp_acm_template_is_rejected_by_strict_validation(self):
        module = self.module
        template = REPO / "datasets" / "manifests" / "dblp_acm.source.template.tsv"
        with self.assertRaises(module.ManifestError):
            module.validate_source_manifest(template, "dblp_acm")

    def test_enron_template_is_rejected_by_strict_validation(self):
        module = self.module
        template = REPO / "datasets" / "manifests" / "enron.source.template.tsv"
        with self.assertRaises(module.ManifestError):
            module.validate_source_manifest(template, "enron")

    # ------------------------------------------------------------------
    # CLI skeleton
    # ------------------------------------------------------------------

    def test_cli_dblp_acm_missing_required_args_exit_code(self):
        # Phase 2 replaces the Phase-1 "not implemented" stub with a real
        # subcommand that requires --output-dir/--universe/--pairs/--seed;
        # argparse itself now produces exit code 2 for the incomplete
        # invocation below (not the old "not implemented" stub message).
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "dblp-acm", "--source-manifest=x"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

    def test_cli_enron_not_implemented_exit_code(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "enron", "--source-manifest=x"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

    # ------------------------------------------------------------------
    # .gitignore scoping [FA1]
    # ------------------------------------------------------------------

    def test_gitignore_ignores_datasets_data_tree(self):
        result = subprocess.run(
            ["git", "check-ignore", "-q", "datasets/data/some/nested/file.txt"],
            cwd=REPO)
        self.assertEqual(result.returncode, 0)

    def test_gitignore_tracks_readme_and_templates(self):
        for rel in ("datasets/README.md",
                    "datasets/manifests/dblp_acm.source.template.tsv",
                    "datasets/manifests/enron.source.template.tsv"):
            result = subprocess.run(["git", "check-ignore", "-q", rel], cwd=REPO)
            self.assertEqual(result.returncode, 1, f"{rel} unexpectedly ignored")

    # ------------------------------------------------------------------
    # Codex review finding 1: exact processed-manifest key sequence
    # ------------------------------------------------------------------

    def test_write_processed_output_accepts_full_dblp_acm_key_order(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("dblp:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
            source_sha = sha256_hex(manifest_path.read_bytes())
            manifest_pairs = self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha, source_sha)
            output_dir = tmp_dir / "out"
            module.write_processed_output(
                output_dir, records, pairs, manifest_pairs, manifest_path,
                overwrite=False)
            self.assertTrue((output_dir / "dataset.manifest.tsv").exists())

    def test_write_processed_output_accepts_full_enron_key_order(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("enron:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
            source_sha = sha256_hex(manifest_path.read_bytes())
            manifest_pairs = self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha, source_sha, dataset="enron")
            output_dir = tmp_dir / "out"
            module.write_processed_output(
                output_dir, records, pairs, manifest_pairs, manifest_path,
                overwrite=False)
            self.assertTrue((output_dir / "dataset.manifest.tsv").exists())

    def test_write_processed_output_rejects_missing_manifest_key(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("dblp:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
            source_sha = sha256_hex(manifest_path.read_bytes())
            full_pairs = self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha, source_sha)
            truncated = [(k, v) for k, v in full_pairs if k != "raw_set_size_median"]
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.write_processed_output(
                    output_dir, records, pairs, truncated, manifest_path,
                    overwrite=False)
            self.assertFalse(output_dir.exists())

    def test_write_processed_output_rejects_reordered_manifest_keys(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("dblp:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
            source_sha = sha256_hex(manifest_path.read_bytes())
            full_pairs = list(self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha, source_sha))
            idx_seed = next(i for i, (k, _) in enumerate(full_pairs) if k == "seed")
            idx_universe = next(
                i for i, (k, _) in enumerate(full_pairs) if k == "universe_size")
            full_pairs[idx_seed], full_pairs[idx_universe] = (
                full_pairs[idx_universe], full_pairs[idx_seed])
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.write_processed_output(
                    output_dir, records, pairs, full_pairs, manifest_path,
                    overwrite=False)
            self.assertFalse(output_dir.exists())

    def test_write_processed_output_rejects_extra_unexpected_manifest_key(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("dblp:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
            source_sha = sha256_hex(manifest_path.read_bytes())
            full_pairs = list(self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha, source_sha))
            full_pairs.insert(6, ("unexpected_extra_key", "x"))
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.write_processed_output(
                    output_dir, records, pairs, full_pairs, manifest_path,
                    overwrite=False)
            self.assertFalse(output_dir.exists())

    # ------------------------------------------------------------------
    # Codex review finding 2: symlink rejection in every path component
    # ------------------------------------------------------------------

    def test_validate_source_manifest_rejects_symlinked_intermediate_directory(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            real_subdir = tmp_dir / "real_subdir"
            real_subdir.mkdir()
            real_file = real_subdir / "dblp_records.csv"
            real_file.write_bytes(b"payload-through-symlinked-dir")
            linked_subdir = tmp_dir / "linked_subdir"
            linked_subdir.symlink_to(real_subdir)
            manifest_path = self._build_dblp_acm_manifest(
                tmp_dir, bad_index0_path="linked_subdir/dblp_records.csv",
                bad_index0_sha=sha256_hex(real_file.read_bytes()))
            with self.assertRaises(module.ManifestError):
                module.validate_source_manifest(manifest_path, "dblp_acm")

    # ------------------------------------------------------------------
    # Codex review finding 3: NFC-only paths in the Enron tree digest
    # ------------------------------------------------------------------

    def test_directory_tree_digest_rejects_non_nfc_path(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            maildir = tmp_dir / "maildir"
            maildir.mkdir()
            nfd_name = unicodedata.normalize("NFD", "café.txt")
            self.assertNotEqual(nfd_name, unicodedata.normalize("NFC", nfd_name))
            (maildir / nfd_name).write_bytes(b"body")
            with self.assertRaises(module.ManifestError):
                module._directory_tree_digest(maildir)

    # ------------------------------------------------------------------
    # Codex review finding 4: os.walk errors must abort, not skip
    # ------------------------------------------------------------------

    def test_directory_tree_digest_unreadable_subdirectory_aborts(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("permission checks are bypassed when running as root")
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            maildir = tmp_dir / "maildir"
            blocked = maildir / "blocked"
            blocked.mkdir(parents=True)
            (blocked / "hidden.txt").write_bytes(b"x")
            os.chmod(blocked, 0o000)
            try:
                with self.assertRaises(module.ManifestError):
                    module._directory_tree_digest(maildir)
            finally:
                os.chmod(blocked, 0o755)

    def test_directory_tree_digest_unreadable_file_aborts(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("permission checks are bypassed when running as root")
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            maildir = tmp_dir / "maildir"
            maildir.mkdir()
            blocked_file = maildir / "blocked.txt"
            blocked_file.write_bytes(b"x")
            os.chmod(blocked_file, 0o000)
            try:
                with self.assertRaises(module.ManifestError):
                    module._directory_tree_digest(maildir)
            finally:
                os.chmod(blocked_file, 0o644)

    # ------------------------------------------------------------------
    # Codex review finding 5: failed final rename leaves no partial dir
    # ------------------------------------------------------------------

    def test_write_processed_output_rename_failure_leaves_no_partial_dir_fresh(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_dblp_acm_manifest(tmp_dir)
            records = [self._minimal_record("dblp:01")]
            pairs = []
            records_sha = sha256_hex(module._canonicalize_records(records))
            pairs_sha = sha256_hex(module._canonicalize_pairs(pairs))
            source_sha = sha256_hex(manifest_path.read_bytes())
            manifest_pairs = self._manifest_pairs_for(
                records, pairs, records_sha, pairs_sha, source_sha)
            output_dir = tmp_dir / "out"

            real_rename = os.rename

            def flaky_rename(src, dst):
                if Path(dst) == output_dir:
                    raise OSError("injected rename failure")
                return real_rename(src, dst)

            with mock.patch("os.rename", side_effect=flaky_rename):
                with self.assertRaises(OSError):
                    module.write_processed_output(
                        output_dir, records, pairs, manifest_pairs, manifest_path,
                        overwrite=False)

            self.assertFalse(output_dir.exists())
            leftovers = list(tmp_dir.glob(".out.tmp-*")) + list(tmp_dir.glob(".out.old-*"))
            self.assertEqual(leftovers, [])

    def test_write_processed_output_rename_failure_restores_old_dir_on_overwrite(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "out"
            self._write_valid_output(module, tmp_dir, output_dir)
            original_records_bytes = (output_dir / "records.tsv").read_bytes()

            real_rename = os.rename
            state = {"failed_once": False}

            def flaky_rename(src, dst):
                # Fail only the first rename into output_dir (the forward
                # tmp_dir -> output_dir publish); let the subsequent
                # backup_dir -> output_dir restore succeed for real.
                if Path(dst) == output_dir and not state["failed_once"]:
                    state["failed_once"] = True
                    raise OSError("injected rename failure")
                return real_rename(src, dst)

            with mock.patch("os.rename", side_effect=flaky_rename):
                with self.assertRaises(OSError):
                    self._write_valid_output(module, tmp_dir, output_dir, overwrite=True)

            self.assertTrue(output_dir.exists())
            self.assertEqual((output_dir / "records.tsv").read_bytes(),
                              original_records_bytes)
            leftovers = list(tmp_dir.glob(".out.tmp-*")) + list(tmp_dir.glob(".out.old-*"))
            self.assertEqual(leftovers, [])


class DblpAcmTests(unittest.TestCase):
    """Behavior tests for cmd_dblp_acm (Work 5 Phase 2): CSV parsing,
    normalization/trigram features, ground-truth pairs, and deterministic
    negative sampling.

    Hermetic: every test builds its CSV/manifest inputs under
    tempfile.TemporaryDirectory(), except the frozen golden-fixture test
    which reads only the tracked tests/fixtures/real_datasets/quick/
    dblp_acm_u65536/ directory (never datasets/, never the network).
    """

    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    # ------------------------------------------------------------------
    # fixture builders
    # ------------------------------------------------------------------

    def _default_dblp_rows(self):
        return [
            ["d1", "Distributed Hash Tables", "Alice Smith", "VLDB", "2019"],
            ["d2", "Bucketized Feature Encoding", "Bob Jones", "SIGMOD", "2020"],
            ["d3", "Trigram Based Record Linkage", "Carol Lee", "ICDE", "2018"],
            ["d4", "Approximate Nearest Neighbor Search", "Dave Kim", "KDD", "2021"],
        ]

    def _default_acm_rows(self):
        return [
            ["a1", "Distributed Hash Tables", "Alice Smith", "VLDB", "2019"],
            ["a2", "Bucketized Feature Encoding", "Bob Jones", "SIGMOD", "2020"],
            ["a3", "Trigram Based Record Linkage", "Carol Lee", "ICDE", "2018"],
            ["a4", "Private Set Intersection Protocols", "Erin Zhao", "CCS", "2022"],
        ]

    def _default_mapping_rows(self):
        return [["d1", "a1"], ["d2", "a2"], ["d3", "a3"]]

    def _write_source_manifest(self, tmp_dir: Path, dblp_path: Path, acm_path: Path,
                                mapping_path: Path) -> Path:
        lines = [
            "key\tvalue",
            "schema_version\tpiccard-real-source-v1",
            "dataset\tdblp_acm",
            "dataset_version\t2026-release",
            "source_url\thttps://example.invalid/dblp-acm",
            "citation\tExample Citation 2020",
            "license_or_terms_url\thttps://example.invalid/terms",
            "acquisition_note\tacquired locally on 2026-01-01",
            "parsing_schema\tdblp-acm-csv-v1",
            "preprocessing_profile\tdblp-acm-trigram-v1",
            "input.0.role\tdblp_records",
            f"input.0.path\t{dblp_path.name}",
            f"input.0.sha256\t{sha256_hex(dblp_path.read_bytes())}",
            "input.1.role\tacm_records",
            f"input.1.path\t{acm_path.name}",
            f"input.1.sha256\t{sha256_hex(acm_path.read_bytes())}",
            "input.2.role\tdblp_acm_mapping",
            f"input.2.path\t{mapping_path.name}",
            f"input.2.sha256\t{sha256_hex(mapping_path.read_bytes())}",
        ]
        manifest_path = tmp_dir / "source.manifest.tsv"
        write_lf(manifest_path, "\n".join(lines) + "\n")
        return manifest_path

    def _build_manifest(self, tmp_dir: Path, *, dblp_rows=None, acm_rows=None,
                         mapping_rows=None, dblp_bom=False):
        dblp_rows = self._default_dblp_rows() if dblp_rows is None else dblp_rows
        acm_rows = self._default_acm_rows() if acm_rows is None else acm_rows
        mapping_rows = (self._default_mapping_rows() if mapping_rows is None
                         else mapping_rows)
        dblp_path = tmp_dir / "dblp_records.csv"
        acm_path = tmp_dir / "acm_records.csv"
        mapping_path = tmp_dir / "mapping.csv"
        write_csv_lf(dblp_path, ("id", "title", "authors", "venue", "year"), dblp_rows)
        write_csv_lf(acm_path, ("id", "title", "authors", "venue", "year"), acm_rows)
        write_csv_lf(mapping_path, ("idDBLP", "idACM"), mapping_rows)
        if dblp_bom:
            dblp_path.write_bytes(b"\xef\xbb\xbf" + dblp_path.read_bytes())
        return self._write_source_manifest(tmp_dir, dblp_path, acm_path, mapping_path)

    def _generated_id(self, prefix: str, raw_id: str) -> str:
        return prefix + raw_id.encode("utf-8").hex()

    # ------------------------------------------------------------------
    # CSV decoding: quoted commas, BOM
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_handles_bom_and_quoted_commas(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            dblp_rows = self._default_dblp_rows()
            dblp_rows[0] = ["d1", "Hashing, Trigrams and Sets", "Alice Smith",
                             "VLDB", "2019"]
            acm_rows = self._default_acm_rows()
            acm_rows[0] = ["a1", "Hashing, Trigrams and Sets", "Alice Smith",
                            "VLDB", "2019"]
            manifest_path = self._build_manifest(
                tmp_dir, dblp_rows=dblp_rows, acm_rows=acm_rows, dblp_bom=True)
            output_dir = tmp_dir / "out"
            module.cmd_dblp_acm(source_manifest=manifest_path, output_dir=output_dir,
                                 universe=65536, pairs=6, seed=7)
            records_text = (output_dir / "records.tsv").read_text("utf-8")
            self.assertIn(self._generated_id("dblp:", "d1"), records_text)
            self.assertIn(self._generated_id("acm:", "a1"), records_text)

    # ------------------------------------------------------------------
    # duplicate record ids
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_duplicate_record_id_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            dblp_rows = self._default_dblp_rows() + [
                ["d1", "Duplicate Title", "Someone Else", "OSDI", "2021"]]
            manifest_path = self._build_manifest(tmp_dir, dblp_rows=dblp_rows)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=6, seed=7)
            self.assertFalse(output_dir.exists())

    # ------------------------------------------------------------------
    # unknown mapping ids
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_unknown_dblp_mapping_id_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            mapping_rows = self._default_mapping_rows() + [["d-missing", "a4"]]
            manifest_path = self._build_manifest(tmp_dir, mapping_rows=mapping_rows)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=6, seed=7)
            self.assertFalse(output_dir.exists())

    def test_cmd_dblp_acm_unknown_acm_mapping_id_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            mapping_rows = self._default_mapping_rows() + [["d4", "a-missing"]]
            manifest_path = self._build_manifest(tmp_dir, mapping_rows=mapping_rows)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=6, seed=7)
            self.assertFalse(output_dir.exists())

    # ------------------------------------------------------------------
    # duplicate / non-one-to-one mapping rows
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_duplicate_mapping_row_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            mapping_rows = self._default_mapping_rows() + [["d1", "a1"]]
            manifest_path = self._build_manifest(tmp_dir, mapping_rows=mapping_rows)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=6, seed=7)
            self.assertFalse(output_dir.exists())

    def test_cmd_dblp_acm_non_one_to_one_mapping_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            mapping_rows = self._default_mapping_rows() + [["d1", "a4"]]
            manifest_path = self._build_manifest(tmp_dir, mapping_rows=mapping_rows)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=6, seed=7)
            self.assertFalse(output_dir.exists())

    # ------------------------------------------------------------------
    # pair-count sufficiency
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_insufficient_pair_request_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_manifest(tmp_dir)  # 3 known matches
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=2, seed=7)
            self.assertFalse(output_dir.exists())

    def test_cmd_dblp_acm_insufficient_negative_candidates_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            # Exactly 3 dblp + 3 acm records, all mapped 1:1: only
            # 3*3 - 3 == 6 negative candidates exist.
            dblp_rows = [
                ["d1", "Distributed Hash Tables", "Alice Smith", "VLDB", "2019"],
                ["d2", "Bucketized Feature Encoding", "Bob Jones", "SIGMOD", "2020"],
                ["d3", "Trigram Based Record Linkage", "Carol Lee", "ICDE", "2018"],
            ]
            acm_rows = [
                ["a1", "Distributed Hash Tables", "Alice Smith", "VLDB", "2019"],
                ["a2", "Bucketized Feature Encoding", "Bob Jones", "SIGMOD", "2020"],
                ["a3", "Trigram Based Record Linkage", "Carol Lee", "ICDE", "2018"],
            ]
            mapping_rows = [["d1", "a1"], ["d2", "a2"], ["d3", "a3"]]
            manifest_path = self._build_manifest(
                tmp_dir, dblp_rows=dblp_rows, acm_rows=acm_rows,
                mapping_rows=mapping_rows)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                # 3 positives + 7 negatives requested, only 6 negatives exist.
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=10, seed=7)
            self.assertFalse(output_dir.exists())

    # ------------------------------------------------------------------
    # known-match leakage into negatives
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_no_negative_is_a_known_match(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_manifest(tmp_dir)
            output_dir = tmp_dir / "out"
            module.cmd_dblp_acm(source_manifest=manifest_path, output_dir=output_dir,
                                 universe=65536, pairs=6, seed=7)
            known_match_endpoints = {
                frozenset((self._generated_id("dblp:", d), self._generated_id("acm:", a)))
                for d, a in self._default_mapping_rows()
            }
            pairs_text = (output_dir / "pairs.tsv").read_text("utf-8")
            lines = pairs_text.splitlines()[1:]
            sampled_nonmatch_count = 0
            for line in lines:
                pair_id, record_a, record_b, pair_kind, label = line.split("\t")
                if pair_kind == "sampled_nonmatch":
                    sampled_nonmatch_count += 1
                    self.assertNotIn(frozenset((record_a, record_b)),
                                      known_match_endpoints)
                    self.assertEqual(label, "0")
                else:
                    self.assertEqual(pair_kind, "known_match")
                    self.assertEqual(label, "1")
                    self.assertIn(frozenset((record_a, record_b)),
                                  known_match_endpoints)
            self.assertEqual(sampled_nonmatch_count, 3)

    # ------------------------------------------------------------------
    # input-row permutation invariance
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_row_permutation_invariance(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            fwd_dir = tmp_dir / "fwd"
            rev_dir = tmp_dir / "rev"
            fwd_dir.mkdir()
            rev_dir.mkdir()
            manifest_fwd = self._build_manifest(
                fwd_dir, dblp_rows=self._default_dblp_rows(),
                acm_rows=self._default_acm_rows(),
                mapping_rows=self._default_mapping_rows())
            manifest_rev = self._build_manifest(
                rev_dir, dblp_rows=list(reversed(self._default_dblp_rows())),
                acm_rows=list(reversed(self._default_acm_rows())),
                mapping_rows=list(reversed(self._default_mapping_rows())))
            out_fwd = tmp_dir / "out_fwd"
            out_rev = tmp_dir / "out_rev"
            module.cmd_dblp_acm(source_manifest=manifest_fwd, output_dir=out_fwd,
                                 universe=65536, pairs=6, seed=7)
            module.cmd_dblp_acm(source_manifest=manifest_rev, output_dir=out_rev,
                                 universe=65536, pairs=6, seed=7)
            self.assertEqual((out_fwd / "records.tsv").read_bytes(),
                              (out_rev / "records.tsv").read_bytes())
            self.assertEqual((out_fwd / "pairs.tsv").read_bytes(),
                              (out_rev / "pairs.tsv").read_bytes())

    # ------------------------------------------------------------------
    # streaming bounded top-k == full sort (>=3 seeds)
    # ------------------------------------------------------------------

    def test_bounded_top_k_matches_full_sort_multiple_seeds(self):
        module = self.module
        dblp_ids = sorted(self._generated_id("dblp:", f"{i:04x}") for i in range(30))
        acm_ids = sorted(self._generated_id("acm:", f"{i:04x}") for i in range(30))
        known_matches = {(dblp_ids[0], acm_ids[0]), (dblp_ids[1], acm_ids[1])}
        for seed in (7, 42, 20260729):
            k = 25
            full_list = sorted(
                module._dblp_negative_candidates(dblp_ids, acm_ids, known_matches, seed),
                key=lambda item: item[0])
            expected = [payload for _, payload in full_list[:k]]
            bounded = module._bounded_top_k_ascending(
                module._dblp_negative_candidates(dblp_ids, acm_ids, known_matches, seed),
                k)
            actual = [payload for _, payload in bounded]
            self.assertEqual(actual, expected)
            # Sanity: the property is non-trivial (results are not just the
            # naive enumeration order) and no known match leaks through.
            self.assertEqual(len(actual), k)
            for dblp_id, acm_id in actual:
                self.assertNotIn((dblp_id, acm_id), known_matches)

    # ------------------------------------------------------------------
    # empty-feature drop / abort semantics
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_mapped_record_with_empty_features_aborts(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            dblp_rows = self._default_dblp_rows() + [["d5", "", "", "", ""]]
            mapping_rows = self._default_mapping_rows() + [["d5", "a4"]]
            manifest_path = self._build_manifest(
                tmp_dir, dblp_rows=dblp_rows, mapping_rows=mapping_rows)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=65536,
                                     pairs=7, seed=7)
            self.assertFalse(output_dir.exists())

    def test_cmd_dblp_acm_unmapped_record_with_empty_features_dropped_and_counted(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            dblp_rows = self._default_dblp_rows() + [["d6", "", "", "", ""]]
            manifest_path = self._build_manifest(tmp_dir, dblp_rows=dblp_rows)
            output_dir = tmp_dir / "out"
            module.cmd_dblp_acm(source_manifest=manifest_path, output_dir=output_dir,
                                 universe=65536, pairs=6, seed=7)
            records_text = (output_dir / "records.tsv").read_text("utf-8")
            self.assertNotIn(self._generated_id("dblp:", "d6"), records_text)
            manifest_values = dict(module.parse_two_column_tsv(
                output_dir / "dataset.manifest.tsv"))
            self.assertEqual(manifest_values["dropped.empty_features_dblp"], "1")
            self.assertEqual(manifest_values["dropped.empty_features_acm"], "0")
            self.assertEqual(manifest_values["record_count"], "8")

    # ------------------------------------------------------------------
    # pass conditions: exact pair count, sorted/unique features, manifest
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_pass_conditions_on_default_fixture(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_manifest(tmp_dir)
            output_dir = tmp_dir / "out"
            module.cmd_dblp_acm(source_manifest=manifest_path, output_dir=output_dir,
                                 universe=65536, pairs=6, seed=7)

            pairs_lines = (output_dir / "pairs.tsv").read_text("utf-8").splitlines()
            self.assertEqual(len(pairs_lines) - 1, 6)

            records_lines = (output_dir / "records.tsv").read_text("utf-8").splitlines()
            self.assertEqual(len(records_lines) - 1, 8)
            for line in records_lines[1:]:
                (record_id, raw_count, raw_csv, bucketed_count,
                 bucketed_csv) = line.split("\t")
                for count_str, csv_str in ((raw_count, raw_csv),
                                            (bucketed_count, bucketed_csv)):
                    values = [] if csv_str == "" else [int(x) for x in csv_str.split(",")]
                    self.assertEqual(int(count_str), len(values))
                    self.assertEqual(values, sorted(set(values)))
                    self.assertEqual(len(values), len(set(values)))

            manifest_values = dict(module.parse_two_column_tsv(
                output_dir / "dataset.manifest.tsv"))
            self.assertEqual(manifest_values["schema_version"],
                              "piccard-real-processed-v1")
            self.assertEqual(manifest_values["dataset"], "dblp_acm")
            self.assertEqual(manifest_values["variant"], "dblp_acm_u65536")
            self.assertEqual(manifest_values["preprocessing_version"],
                              "dblp-acm-trigram-v1")
            self.assertEqual(manifest_values["universe_size"], "65536")
            self.assertEqual(manifest_values["seed"], "7")
            self.assertEqual(manifest_values["record_count"], "8")
            self.assertEqual(manifest_values["pair_count"], "6")
            self.assertEqual(manifest_values["original_positive_count"], "3")
            self.assertEqual(manifest_values["retained_positive_count"], "3")
            self.assertEqual(manifest_values["requested_pair_count"], "6")
            self.assertEqual(manifest_values["max_documents"], "")
            self.assertEqual(manifest_values["min_related_pairs"], "")
            self.assertEqual(manifest_values["dropped.empty_features_dblp"], "0")
            self.assertEqual(manifest_values["dropped.empty_features_acm"], "0")
            self.assertEqual(
                manifest_values["records_sha256"],
                sha256_hex((output_dir / "records.tsv").read_bytes()))
            self.assertEqual(
                manifest_values["pairs_sha256"],
                sha256_hex((output_dir / "pairs.tsv").read_bytes()))
            self.assertEqual(
                manifest_values["source_manifest_sha256"],
                sha256_hex((output_dir / "source.manifest.tsv").read_bytes()))

    # ------------------------------------------------------------------
    # universe validation
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_rejects_non_65536_universe(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            manifest_path = self._build_manifest(tmp_dir)
            output_dir = tmp_dir / "out"
            with self.assertRaises(module.ManifestError):
                module.cmd_dblp_acm(source_manifest=manifest_path,
                                     output_dir=output_dir, universe=1024,
                                     pairs=6, seed=7)
            self.assertFalse(output_dir.exists())

    # ------------------------------------------------------------------
    # CLI end-to-end
    # ------------------------------------------------------------------

    def test_cli_dblp_acm_full_invocation_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            dblp_path = tmp_dir / "dblp_records.csv"
            acm_path = tmp_dir / "acm_records.csv"
            mapping_path = tmp_dir / "mapping.csv"
            write_csv_lf(dblp_path, ("id", "title", "authors", "venue", "year"),
                         self._default_dblp_rows())
            write_csv_lf(acm_path, ("id", "title", "authors", "venue", "year"),
                         self._default_acm_rows())
            write_csv_lf(mapping_path, ("idDBLP", "idACM"),
                         self._default_mapping_rows())
            manifest_path = self._write_source_manifest(
                tmp_dir, dblp_path, acm_path, mapping_path)
            output_dir = tmp_dir / "out"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "dblp-acm",
                 f"--source-manifest={manifest_path}",
                 f"--output-dir={output_dir}",
                 "--universe=65536", "--pairs=6", "--seed=7", "--strict"],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output_dir / "dataset.manifest.tsv").exists())

    # ------------------------------------------------------------------
    # frozen quick fixture (golden)
    # ------------------------------------------------------------------

    def test_cmd_dblp_acm_quick_fixture_byte_identical_to_golden(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "out"
            module.cmd_dblp_acm(
                source_manifest=QUICK_DBLP_ACM_DIR / "source.manifest.tsv",
                output_dir=output_dir, universe=65536, pairs=6, seed=7)
            for name in ("records.tsv", "pairs.tsv", "source.manifest.tsv",
                         "dataset.manifest.tsv"):
                self.assertEqual(
                    (output_dir / name).read_bytes(),
                    (QUICK_DBLP_ACM_DIR / name).read_bytes(),
                    f"golden mismatch for {name}")


if __name__ == "__main__":
    unittest.main()
