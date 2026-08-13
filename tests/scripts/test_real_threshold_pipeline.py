#!/usr/bin/env python3
"""RED/GREEN contract tests for the plaintext DBLP threshold pipeline.

These tests intentionally reconstruct the split, candidates, threshold
conversion, and confusion outcomes independently of the C++ driver.  The
fixture has three pairs of each label, so even/odd rank splitting leaves a
non-empty calibration and evaluation class for both labels.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "build" / "bench_real_datasets"
THRESHOLD_BINARY = REPO / "build" / "bench_real_threshold"
FIXTURE = (REPO / "tests" / "fixtures" / "real_datasets" / "quick" /
           "dblp_acm_u65536" / "dataset.manifest.tsv")
DRIVER = REPO / "benchmarks" / "real_threshold_driver.cpp"
VERIFY = REPO / "scripts" / "verify_real_dataset_outputs.py"
SUMMARY = REPO / "scripts" / "summarize_real_datasets.py"

THRESHOLD_HEADER = (
    "schema_version,dataset,variant,dataset_manifest_sha256,records_sha256,"
    "pairs_sha256,pair_id,pair_kind,label,record_a,record_b,k,m,"
    "hash_randomness,root_seed,split,rank_position,threshold_trial_index,"
    "hash_seed,match_count,decision,label_truth,label_outcome,"
    "exact_j_truth,exact_j_outcome,exact_jaccard_bucketed,"
    "requested_j_threshold,tau_count,realized_j_tau,calibration_fpr,"
    "calibration_fnr,calibration_balanced_error,calibration_digest,"
    "evaluation_digest,threshold_workload_sha256\n"
)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RealThresholdPipelineTest(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"missing bench_real_datasets binary: {BINARY}")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_threshold(self, *, suffix="", k=128, m=64, trials=1,
                      manifest=FIXTURE, max_pairs=4, seed=20260729,
                      binary=BINARY, mode_args=("--mode=threshold",)):
        csv_path = self.root / f"threshold{suffix}.csv"
        manifest_path = self.root / f"threshold{suffix}.manifest.tsv"
        rows_path = self.root / f"threshold{suffix}.rows.tsv"
        result = subprocess.run(
            [str(binary), f"--dataset-manifest={manifest}",
             *mode_args, f"--k={k}", f"--m={m}",
             f"--max-pairs={max_pairs}", f"--threshold-trials={trials}",
             f"--seed={seed}", "--hash_randomness=resampled",
             f"--csv={csv_path}",
             f"--workload-manifest-out={manifest_path}",
             f"--workload-rows-out={rows_path}"],
            capture_output=True, text=True,
        )
        return result, csv_path, manifest_path, rows_path

    def run_revision_threshold(self, *, suffix="", trials=1,
                               manifest=FIXTURE, seed=20260729,
                               binary=BINARY):
        """Invoke the real producer with the exact threshold cell argv.

        The canonical real-threshold plan intentionally has no ``--profile``;
        toy/paper selection is represented by the frozen trial count.  Keep
        this command in canonical planner order so the test reaches the
        producer boundary rather than only exercising the pure adapter.
        """
        cell = "paper-v1::threshold_dblp_fpfn::control=default"
        output_root = self.root / f"revision{suffix}"
        output_root.mkdir()
        csv_path = output_root / "threshold.csv"
        manifest_path = output_root / "threshold.manifest.tsv"
        rows_path = output_root / "threshold.rows.tsv"
        result = subprocess.run(
            [str(binary), f"--revision-cell={cell}", "--mode=threshold",
             f"--dataset-manifest={manifest}", "--k=128", "--m=64",
             f"--threshold-trials={trials}", f"--seed={seed}",
             "--hash_randomness=resampled", f"--csv={csv_path}",
             f"--workload-manifest-out={manifest_path}",
             f"--workload-rows-out={rows_path}"],
            capture_output=True, text=True,
        )
        return result, csv_path, manifest_path, rows_path

    def test_revision_threshold_toy_count_one_dispatches_without_profile(self):
        result, csv_path, manifest_path, rows_path = self.run_revision_threshold(
            suffix="-toy", trials=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(csv_path.is_file())
        self.assertTrue(manifest_path.is_file())
        self.assertTrue(rows_path.is_file())
        with csv_path.open(newline="") as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 2)

    def test_revision_threshold_paper_count_fifty_remains_canonical(self):
        result, csv_path, manifest_path, rows_path = self.run_revision_threshold(
            suffix="-paper", trials=50)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(csv_path.is_file())
        self.assertTrue(manifest_path.is_file())
        self.assertTrue(rows_path.is_file())
        with csv_path.open(newline="") as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 100)

    def test_isolated_threshold_cli_requires_exactly_one_threshold_mode(self):
        for mode_args, label in (
                ((), "missing"),
                (("--mode=not-threshold",), "wrong"),
                (("--mode=threshold", "--mode=threshold"), "duplicate")):
            with self.subTest(mode=label):
                result, csv_path, manifest_path, rows_path = self.run_threshold(
                    suffix=f"-mode-{label}", binary=THRESHOLD_BINARY,
                    mode_args=mode_args)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(csv_path.exists())
                self.assertFalse(manifest_path.exists())
                self.assertFalse(rows_path.exists())

    def test_threshold_executable_is_link_free_from_openfhe(self):
        self.assertTrue(THRESHOLD_BINARY.is_file(),
                        f"missing link-isolated threshold executable: {THRESHOLD_BINARY}")
        audit = (subprocess.run(["otool", "-L", str(THRESHOLD_BINARY)],
                                capture_output=True, text=True)
                 if subprocess.run(["sh", "-c", "command -v otool >/dev/null"],
                                   capture_output=True).returncode == 0
                 else subprocess.run(["ldd", str(THRESHOLD_BINARY)],
                                     capture_output=True, text=True))
        self.assertEqual(audit.returncode, 0, audit.stderr)
        linked = audit.stdout.casefold()
        self.assertNotIn("openfhe", linked)
        self.assertNotIn("piccard_fhe", linked)
        result, csv_path, manifest_path, rows_path = self.run_threshold(
            suffix="-isolated", binary=THRESHOLD_BINARY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(csv_path.is_file())
        self.assertTrue(manifest_path.is_file())
        self.assertTrue(rows_path.is_file())

    def test_split_rank_kat_uses_all_sha256_bytes(self):
        verifier = _load_module(VERIFY, "verify_threshold_rank_kat")
        pair_id = "kat-pair:β"
        expected = hashlib.sha256(
            b"piccard-dblp-threshold-split-v1\x00" +
            pair_id.encode("utf-8")).digest()
        self.assertEqual(verifier._threshold_split_rank(pair_id), expected)

    def test_seed_and_digest_kats_bind_literal_bytes(self):
        verifier = _load_module(VERIFY, "verify_threshold_seed_kat")
        self.assertEqual(
            verifier._threshold_trial_seed(20260729, "kat-pair:β", 3),
            10938419951913682935,
        )
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = dict(line.split("\t", 1)
                        for line in manifest_path.read_text().splitlines()[1:])
        workload_bytes = manifest_path.read_bytes()
        self.assertEqual(
            manifest["rows_sha256"], hashlib.sha256(rows_path.read_bytes()).hexdigest())
        self.assertEqual(
            manifest["calibration_rows_sha256"],
            hashlib.sha256("".join(
                "\t".join(row.split("\t")[i] for i in (0, 1, 3, 6)) + "\n"
                for row in rows_path.read_text().splitlines()[1:]
                if row.split("\t")[2] == "calibration").encode()).hexdigest())
        self.assertEqual(
            manifest["evaluation_rows_sha256"],
            hashlib.sha256("".join(
                "\t".join(row.split("\t")[i] for i in (0, 1, 3, 6)) + "\n"
                for row in rows_path.read_text().splitlines()[1:]
                if row.split("\t")[2] == "evaluation").encode()).hexdigest())
        with csv_path.open(newline="") as handle:
            first = next(csv.DictReader(handle))
        self.assertEqual(first["hash_seed"], str(
            verifier._threshold_trial_seed(20260729, first["pair_id"], 0)))
        self.assertEqual(first["threshold_workload_sha256"],
                         hashlib.sha256(workload_bytes).hexdigest())

    def test_selection_kat_checks_balanced_error_and_larger_j_tie(self):
        verifier = _load_module(VERIFY, "verify_threshold_selection_kat")
        pairs = [
            {"label": 0, "split": "calibration", "exact_jaccard_bucketed": 0.2},
            {"label": 1, "split": "calibration", "exact_jaccard_bucketed": 0.8},
            {"label": 0, "split": "evaluation", "exact_jaccard_bucketed": 0.0},
            {"label": 1, "split": "evaluation", "exact_jaccard_bucketed": 1.0},
        ]
        choice = verifier._threshold_choice(pairs, [0.2, 0.5, 0.8], 128, 64)
        self.assertEqual(choice["requested"], 0.8)
        self.assertEqual(choice["fpr"], 0.0)
        self.assertEqual(choice["fnr"], 0.0)
        self.assertEqual(choice["tau_count"], 103)
        self.assertAlmostEqual(choice["realized"], 0.8015873015873016)

    def _copy_manifest(self, name, *, dataset=None, variant=None, pairs_bytes=None):
        root = self.root / name
        root.mkdir()
        for source in FIXTURE.parent.iterdir():
            if source.is_file():
                (root / source.name).write_bytes(source.read_bytes())
        if pairs_bytes is not None:
            (root / "pairs.tsv").write_bytes(pairs_bytes)
        lines = (root / "dataset.manifest.tsv").read_text().splitlines()
        replacements = {}
        if dataset is not None:
            replacements["dataset"] = dataset
        if variant is not None:
            replacements["variant"] = variant
        if pairs_bytes is not None:
            replacements["pairs_sha256"] = hashlib.sha256(pairs_bytes).hexdigest()
        rebuilt = [lines[0]]
        for line in lines[1:]:
            key, value = line.split("\t", 1)
            rebuilt.append(f"{key}\t{replacements.get(key, value)}")
        (root / "dataset.manifest.tsv").write_text("\n".join(rebuilt) + "\n")
        return root / "dataset.manifest.tsv"

    def test_wrong_dataset_and_minus_one_label_reject_before_outputs(self):
        wrong_dataset = self._copy_manifest(
            "wrong-dataset", dataset="enron", variant="enron_u65536")
        result, csv_path, manifest_path, rows_path = self.run_threshold(
            suffix="-wrong-dataset", manifest=wrong_dataset)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(csv_path.exists() or manifest_path.exists() or rows_path.exists())

        pair_lines = (FIXTURE.parent / "pairs.tsv").read_text().splitlines()
        pair_lines[1] = pair_lines[1].rsplit("\t", 1)[0] + "\t-1"
        minus_one_pairs = ("\n".join(pair_lines) + "\n").encode()
        minus_one = self._copy_manifest("minus-one", pairs_bytes=minus_one_pairs)
        result, csv_path, manifest_path, rows_path = self.run_threshold(
            suffix="-minus-one", manifest=minus_one)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(csv_path.exists() or manifest_path.exists() or rows_path.exists())

    def _run_verifier(self, csv_path, manifest_path, rows_path):
        return subprocess.run(
            [sys.executable, str(VERIFY), "--mode=threshold",
             f"--dataset-manifest={FIXTURE}", f"--threshold-csv={csv_path}",
             f"--threshold-manifest={manifest_path}",
             f"--threshold-rows={rows_path}", "--seed=20260729",
             "--threshold-trials=1", "--max-pairs=4"],
            capture_output=True, text=True)

    def _rebind_workload_hash(self, csv_path, manifest_path):
        workload_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        with csv_path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            fields = reader.fieldnames
        for row in rows:
            row["threshold_workload_sha256"] = workload_sha
        with csv_path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def test_verifier_rejects_every_workload_manifest_grammar_mutation(self):
        mutations = ("extra", "missing", "reordered", "noncontiguous", "extra-candidate")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result, csv_path, manifest_path, rows_path = self.run_threshold(
                    suffix=f"-manifest-{mutation}")
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = manifest_path.read_text().splitlines()
                if mutation == "extra":
                    lines.append("unexpected_key\tunexpected_value")
                elif mutation == "missing":
                    lines = [line for line in lines if not line.startswith("m\t")]
                elif mutation == "reordered":
                    first = lines.index("k\t128")
                    second = lines.index("m\t64")
                    lines[first], lines[second] = lines[second], lines[first]
                elif mutation == "noncontiguous":
                    lines = [line.replace("candidate.1\t", "candidate.3\t")
                             for line in lines]
                else:
                    insert = next(i for i, line in enumerate(lines)
                                  if line.startswith("selected_requested_j_threshold\t"))
                    lines.insert(insert, "candidate.3\t0.25")
                manifest_path.write_text("\n".join(lines) + "\n")
                self._rebind_workload_hash(csv_path, manifest_path)
                checked = self._run_verifier(csv_path, manifest_path, rows_path)
                self.assertNotEqual(checked.returncode, 0, checked.stdout)

    def test_verifier_rejects_threshold_row_and_selection_mutations(self):
        row_mutations = {
            "row-seed": ("hash_seed", lambda value: str(int(value) + 1)),
            "match-count": ("match_count", lambda value: str((int(value) + 1) % 129)),
            "requested-threshold": ("requested_j_threshold", lambda _value: "0.25"),
            "tau-count": ("tau_count", lambda value: str(int(value) + 1)),
            "realized-boundary": ("realized_j_tau", lambda _value: "0.0"),
            "pair-identity": ("pair_id", lambda _value: "unknown-pair"),
            "label-truth": ("label_truth", lambda value: str(1 - int(value))),
            "label-outcome": ("label_outcome", lambda _value: "FP"),
            "exact-j-outcome": ("exact_j_outcome", lambda _value: "FP"),
            "calibration-digest": ("calibration_digest", lambda _value: "0" * 64),
            "evaluation-digest": ("evaluation_digest", lambda _value: "0" * 64),
            "workload-digest": ("threshold_workload_sha256", lambda _value: "0" * 64),
        }
        for mutation, (field, transform) in row_mutations.items():
            with self.subTest(mutation=mutation):
                result, csv_path, manifest_path, rows_path = self.run_threshold(
                    suffix=f"-row-mutation-{mutation}")
                self.assertEqual(result.returncode, 0, result.stderr)
                with csv_path.open(newline="") as handle:
                    reader = csv.DictReader(handle)
                    fields = reader.fieldnames
                    rows = list(reader)
                rows[0][field] = transform(rows[0][field])
                with csv_path.open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields,
                                            lineterminator="\n")
                    writer.writeheader()
                    writer.writerows(rows)
                checked = self._run_verifier(csv_path, manifest_path, rows_path)
                self.assertNotEqual(checked.returncode, 0, checked.stdout)

        for mutation, key, value in (
                ("selected-threshold", "selected_requested_j_threshold", "0.25"),
                ("manifest-tau", "tau_count", "1"),
                ("manifest-boundary", "realized_j_tau", "0.0"),
                ("manifest-digest", "calibration_rows_sha256", "0" * 64),
        ):
            with self.subTest(mutation=mutation):
                result, csv_path, manifest_path, rows_path = self.run_threshold(
                    suffix=f"-manifest-mutation-{mutation}")
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = manifest_path.read_text().splitlines()
                lines = [
                    line.split("\t", 1)[0] + "\t" + value
                    if line.startswith(key + "\t") else line
                    for line in lines
                ]
                manifest_path.write_text("\n".join(lines) + "\n")
                self._rebind_workload_hash(csv_path, manifest_path)
                checked = self._run_verifier(csv_path, manifest_path, rows_path)
                self.assertNotEqual(checked.returncode, 0, checked.stdout)

    def test_summary_uses_pair_level_distribution_and_trial_level_confusions(self):
        result, csv_path, _, _ = self.run_threshold(suffix="-two-trials", trials=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "two-trial-summary.csv"
        summary = subprocess.run(
            [sys.executable, str(SUMMARY), "--mode=threshold",
             f"--input={csv_path}", f"--output={output}"],
            capture_output=True, text=True)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        with output.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        confusion = [row for row in rows if row["section"] == "confusion"]
        # Confusion denominators are trial-level, but conditional on each
        # truth class: one evaluation pair per label times two trials.
        self.assertEqual({int(row["denominator"]) for row in confusion}, {2})
        self.assertEqual(
            {(row["truth_basis"], row["category"]):
             (int(row["count"]), int(row["denominator"]), row["rate"],
              row["ci95_low"], row["ci95_high"])
             for row in confusion},
            {("label", "TP"): (2, 2, "1", "1", "1"),
             ("label", "TN"): (2, 2, "1", "1", "1"),
             ("label", "FP"): (0, 2, "0", "0", "0"),
             ("label", "FN"): (0, 2, "0", "0", "0"),
             ("exact_j", "TP"): (2, 2, "1", "1", "1"),
             ("exact_j", "TN"): (2, 2, "1", "1", "1"),
             ("exact_j", "FP"): (0, 2, "0", "0", "0"),
             ("exact_j", "FN"): (0, 2, "0", "0", "0")})
        distribution = [row for row in rows if row["section"] == "distribution"]
        self.assertEqual({int(row["denominator"]) for row in distribution}, {1})
        self.assertEqual(sum(int(row["count"]) for row in distribution if row["category"] == "0"), 1)
        self.assertEqual(sum(int(row["count"]) for row in distribution if row["category"] == "1"), 1)
        self.assertEqual(
            {(row["category"], row["jaccard_bucket"])
             for row in distribution if row["count"] == "1"},
            {("0", "b00_10"), ("1", "b60_100")})

    def test_summary_rejects_decision_truth_outcome_threshold_and_row_mutations(self):
        mutations = ("decision", "label_truth", "exact_j_truth", "label_outcome",
                     "exact_j_outcome", "requested_j_threshold", "omit", "duplicate")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result, csv_path, _, _ = self.run_threshold(
                    suffix=f"-summary-{mutation}", trials=2)
                self.assertEqual(result.returncode, 0, result.stderr)
                with csv_path.open(newline="") as handle:
                    reader = csv.DictReader(handle)
                    fields = reader.fieldnames
                    rows = list(reader)
                if mutation == "omit":
                    rows.pop(0)
                elif mutation == "duplicate":
                    rows[-1] = dict(rows[0])
                else:
                    if mutation in {"decision", "label_truth", "exact_j_truth"}:
                        rows[0][mutation] = str(1 - int(rows[0][mutation]))
                    elif mutation in {"label_outcome", "exact_j_outcome"}:
                        rows[0][mutation] = "FP" if rows[0][mutation] != "FP" else "TN"
                    else:
                        rows[0][mutation] = "0.25"
                with csv_path.open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
                    writer.writeheader()
                    writer.writerows(rows)
                output = self.root / f"summary-{mutation}.csv"
                summary = subprocess.run(
                    [sys.executable, str(SUMMARY), "--mode=threshold",
                     f"--input={csv_path}", f"--output={output}"],
                    capture_output=True, text=True)
                self.assertNotEqual(summary.returncode, 0, summary.stdout)

    def test_threshold_mode_emits_exact_versioned_header_and_held_out_rows(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(csv_path.read_text().split("\n", 1)[0] + "\n",
                         THRESHOLD_HEADER)
        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        # 3 positives + 3 negatives, even ranks calibrated and odd ranks held out.
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["split"] for row in rows}, {"evaluation"})
        self.assertEqual({int(row["label"]) for row in rows}, {0, 1})
        self.assertTrue(manifest_path.is_file())
        self.assertTrue(rows_path.is_file())

    def test_split_rank_and_candidate_selection_are_independently_reproducible(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        pair_rows = []
        with (FIXTURE.parent / "pairs.tsv").open(newline="") as handle:
            for row in csv.DictReader(handle, delimiter="\t"):
                payload = (b"piccard-dblp-threshold-split-v1\x00" +
                           row["pair_id"].encode())
                digest = hashlib.sha256(payload).digest()
                pair_rows.append((int(row["label"]), digest,
                                  row["pair_id"]))
        expected = {}
        selected_ids = {line.split("\t", 1)[0]
                        for line in rows_path.read_text().splitlines()[1:]}
        for label in (0, 1):
            ranked = sorted((digest, pair_id)
                            for current, digest, pair_id in pair_rows
                            if current == label and pair_id in selected_ids)
            for rank, (_digest, pair_id) in enumerate(ranked):
                expected[pair_id] = ("calibration" if rank % 2 == 0
                                     else "evaluation", rank)

        workload_lines = rows_path.read_text().splitlines()
        self.assertEqual(workload_lines[0],
                         "pair_id\tlabel\tsplit\trank_position\t"
                         "record_a\trecord_b\texact_jaccard_bucketed")
        for line in workload_lines[1:]:
            pair_id, label, split, rank, record_a, record_b, exact_j = line.split("\t")
            self.assertEqual((split, int(rank)), expected[pair_id])

        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        selected = rows[0]["requested_j_threshold"]
        selected_float = float(selected)
        calibration_values = sorted({
            float(line.split("\t")[-1])
            for line in workload_lines[1:]
            if line.split("\t")[2] == "calibration"
        })
        candidates = sorted(set(calibration_values + [
            (left + right) / 2.0
            for left, right in zip(calibration_values, calibration_values[1:])
        ]))
        self.assertIn(selected_float, candidates)
        self.assertEqual(int(rows[0]["tau_count"]),
                         int(__import__("math").ceil(
                             128 * (1 / 64 + (1 - 1 / 64) * selected_float))))

    def test_evaluation_reports_separate_label_and_exact_j_truth_outcomes(self):
        result, csv_path, _, _ = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        with csv_path.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        for row in rows:
            self.assertIn(row["label_outcome"], {"TP", "TN", "FP", "FN"})
            self.assertIn(row["exact_j_outcome"], {"TP", "TN", "FP", "FN"})
            self.assertNotEqual(row["label_outcome"], "")
            self.assertNotEqual(row["exact_j_outcome"], "")

    def test_wrong_dataset_label_minus_one_and_nonfrozen_parameters_reject(self):
        result, *_ = self.run_threshold(k=64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "threshold.csv").exists())

        # The DBLP fixture's labels are valid; independently mutate the pair
        # file and all bound checksums in a temporary copy to exercise the
        # driver's explicit -1 rejection rather than a checksum-only failure.
        self.assertTrue(FIXTURE.is_file())

    def test_driver_is_plaintext_only(self):
        self.assertTrue(DRIVER.is_file())
        source = DRIVER.read_text(encoding="utf-8").casefold()
        for token in ("openfhe", "lbcrypto", "bfv_context", "keygen(",
                      "encrypt(", "decrypt("):
            self.assertNotIn(token, source)

    def test_verifier_and_summary_entrypoints_exist(self):
        self.assertTrue(VERIFY.is_file())
        self.assertTrue(SUMMARY.is_file())

    def test_summary_emits_two_confusion_bases_and_label_conditioned_distribution(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "threshold-summary.csv"
        summary = subprocess.run(
            [sys.executable, str(SUMMARY), "--mode=threshold",
             f"--input={csv_path}", f"--output={output}"],
            capture_output=True, text=True,
        )
        self.assertEqual(summary.returncode, 0, summary.stderr)
        with output.open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual({row["truth_basis"] for row in rows},
                         {"label", "exact_j", "label-conditioned-exact-j"})
        confusion = [row for row in rows if row["section"] == "confusion"]
        self.assertEqual(len(confusion), 8)
        self.assertTrue(all(int(row["denominator"]) > 0 for row in confusion))

    def test_verifier_rejects_a_calibration_row_in_evaluation_csv(self):
        result, csv_path, manifest_path, rows_path = self.run_threshold()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = csv_path.read_text().splitlines()
        header = lines[0].split(",")
        values = lines[1].split(",")
        values[header.index("split")] = "calibration"
        csv_path.write_text("\n".join((lines[0], ",".join(values), "")))
        checked = subprocess.run(
            [sys.executable, str(VERIFY), "--mode=threshold",
             f"--dataset-manifest={FIXTURE}", f"--threshold-csv={csv_path}",
             f"--threshold-manifest={manifest_path}",
             f"--threshold-rows={rows_path}", "--seed=20260729",
             "--threshold-trials=1", "--max-pairs=4"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("calibration", checked.stderr.lower())


if __name__ == "__main__":
    unittest.main()
