"""Behavior tests for the Work-5 real-dataset manifest/writer core.

Covers scripts/prepare_real_datasets.py: strict source-manifest validation,
the canonical TSV grammar, the deterministic feature-hashing primitives, the
atomic processed-output writer, and the .gitignore scoping for datasets/.

Hermetic: every test builds its inputs under tempfile.TemporaryDirectory();
none of them touch the real datasets/ tree or the network.
"""

import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "prepare_real_datasets.py"
COMMON_FIXTURES = REPO / "tests" / "fixtures" / "real_datasets" / "common"


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
                             source_sha, extra=()):
        base = [
            ("schema_version", "piccard-real-processed-v1"),
            ("dataset", "dblp_acm"),
            ("variant", "dblp_acm_u65536"),
            ("preprocessing_version", "dblp-acm-trigram-v1"),
            ("universe_size", "65536"),
            ("seed", "7"),
            ("source_manifest_file", "source.manifest.tsv"),
            ("source_manifest_sha256", source_sha),
            ("records_file", "records.tsv"),
            ("records_sha256", records_sha),
            ("record_count", str(len(records))),
            ("pairs_file", "pairs.tsv"),
            ("pairs_sha256", pairs_sha),
            ("pair_count", str(len(pairs))),
        ]
        return base + list(extra)

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

    def test_cli_dblp_acm_not_implemented_exit_code(self):
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


if __name__ == "__main__":
    unittest.main()
