#!/usr/bin/env python3
"""Pure-Python contract tests for the canonical Phase 9 matrix."""

from __future__ import annotations

import copy
import pathlib
import tempfile
import unittest

from scripts import validate_revision_matrix


ROOT = pathlib.Path(__file__).resolve().parents[2]
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"
FIXTURES = ROOT / "tests" / "fixtures" / "revision_matrix"


class RevisionMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = validate_revision_matrix.load_document(MATRIX)
        validate_revision_matrix.validate_document(cls.document, FIXTURES)

    def test_exact_263_20_104_cardinalities_and_sorted_goldens(self):
        cells = self.document["cells"]
        self.assertEqual(len(cells), 275)
        ids = [cell["cell_id"] for cell in cells]
        self.assertEqual(ids, sorted(ids))
        paper = (FIXTURES / "paper_cell_ids.txt").read_text().splitlines()
        toy = (FIXTURES / "toy_cell_ids.txt").read_text().splitlines()
        executable = (FIXTURES / "executable_toy_cell_ids.txt").read_text().splitlines()
        self.assertEqual(ids, paper)
        self.assertEqual(len(toy), 20)
        self.assertEqual(len(executable), 104)
        self.assertEqual(executable, sorted(executable))

    def test_family_counts_and_required_contract_literals(self):
        counts = {}
        for cell in self.document["cells"]:
            counts[cell["family"]] = counts.get(cell["family"], 0) + 1
        self.assertEqual(counts, self.document["families"])
        self.assertEqual(counts["threshold_synthetic_fpfn"], 84)
        self.assertEqual(counts["real_dataset"], 12)

        sqrt = next(c for c in self.document["cells"]
                    if c["cell_id"] == "paper-v1::sqrt_comparison::timing_m=32")
        sqrt_row = next(r for r in sqrt["expected_rows"] if r["row_id"] == "sqrt")
        self.assertEqual(sqrt_row["status"], "NOT_APPLICABLE")
        self.assertEqual(sqrt_row["reason"], "sqrt-m-not-perfect-square")

        sj = next(c for c in self.document["cells"]
                  if c["cell_id"] == "paper-v1::sj16::u=262144")
        self.assertEqual(sj["invocation_status"], "NO_SPAWN")
        self.assertEqual(sj["expected_rows"][0]["status"], "EXTRAPOLATED")
        self.assertEqual(
            sj["expected_rows"][0]["reason"],
            "sj16-paillier3072-calibration-bound-v1")

        sj_fit = next(c for c in self.document["cells"]
                      if c["cell_id"] == "paper-v1::sj16::fit=per_element")
        self.assertEqual(sj_fit["invocation_status"], "RUN")
        self.assertEqual(sj_fit["timeout_class"], "long")
        for sj_cell in self.document["cells"]:
            if sj_cell["family"] == "sj16" and sj_cell is not sj_fit:
                expected = ("standard"
                            if sj_cell["invocation_status"] == "NO_SPAWN"
                            else "long")
                self.assertEqual(sj_cell["timeout_class"], expected)

        bcg12_long = next(c for c in self.document["cells"]
                          if c["cell_id"] == "paper-v1::bcg12_exact::n=100000")
        self.assertEqual(bcg12_long["timeout_class"], "long")
        # k=256 tops the threshold sweep: agreement runs 2886 s there and
        # timing 157 s, so only the 6.1 s spec cell keeps the standard stop.
        for family, timeout_class in (("threshold_timing", "extended"),
                                      ("threshold_agreement", "long"),
                                      ("threshold_spec", "standard")):
            k256 = next(c for c in self.document["cells"]
                        if c["cell_id"] == f"paper-v1::{family}::k=256")
            self.assertEqual(k256["invocation_status"], "RUN")
            self.assertEqual(k256["timeout_class"], timeout_class)
            self.assertNotEqual(k256["expected_rows"][0]["status"],
                                "NOT_APPLICABLE")

    def test_largest_set_size_cells_outrank_the_standard_timeout(self):
        """No cell at the top of a set-size sweep may keep the 600 s stop.

        paper-v1 is one non-resumable run, so a cell that overruns its stop
        aborts the whole matrix.  Measured on the campaign host,
        piccard_std128::n=100000 needs 759 s and
        piccard_std192_encoding::n=100000 needs 693 s against the 600 s
        standard stop, so every 100000-element point
        is provisioned above standard: the SJ16/BCG12-exact baselines keep
        ``long`` and the remaining FHE producers take ``extended``.
        """
        top_of_sweep = [cell for cell in self.document["cells"]
                        if cell["axis"] in {"n", "timing_n"}
                        and str(cell["axis_value"]) == "100000"]
        self.assertEqual(len(top_of_sweep), 9)
        expected = {
            "paper-v1::sj16::n=100000": "long",
            "paper-v1::bcg12_exact::n=100000": "long",
            "paper-v1::bcg12_minhash::n=100000": "extended",
            "paper-v1::dynamic_accuracy::n=100000": "extended",
            "paper-v1::dynamic_timing::n=100000": "extended",
            "paper-v1::fhe_ind::n=100000": "extended",
            "paper-v1::piccard_std128::n=100000": "extended",
            "paper-v1::piccard_std192_encoding::n=100000": "extended",
            "paper-v1::sqrt_comparison::timing_n=100000": "extended",
        }
        self.assertEqual({cell["cell_id"] for cell in top_of_sweep},
                         set(expected))
        for cell in top_of_sweep:
            self.assertEqual(cell["timeout_class"], expected[cell["cell_id"]],
                             cell["cell_id"])
            self.assertNotEqual(cell["timeout_class"], "standard",
                                cell["cell_id"])

    def test_threshold_phase_cells_outrank_the_standard_timeout(self):
        """Every measurement-bearing threshold family is above the 600 s stop.

        The fourth paper-v1 attempt was the first to reach this phase and was
        killed at ``threshold_agreement::k=128`` after 600.1 s, 21 h 51 m into
        a non-resumable run.  Re-measured to natural completion on hardware
        that tracks the campaign host to within 5%, the phase is far slower
        than the standard stop allows::

            threshold_agreement   k=16/32/64/128/256  138/160/881/1455/2886 s
            threshold_timing      worst point (k=128)                 202.8 s
            threshold_synthetic_fpfn worst point (k512_j-10)          391.8 s
            threshold_dblp_fpfn   control=default                     237.9 s
            threshold_spec        worst point (k=256)                   6.1 s

        Only threshold_spec still clears a 3x margin under ``standard``, so it
        is the one threshold family left there; the other four move as whole
        families, and the two agreement points whose measurements pass
        3600/3 s take ``long``.
        """
        expected = {}
        for k in (16, 32, 64):
            expected[f"paper-v1::threshold_agreement::k={k}"] = "extended"
        for k in (128, 256):
            expected[f"paper-v1::threshold_agreement::k={k}"] = "long"
        for k in (16, 32, 64, 128, 256):
            expected[f"paper-v1::threshold_timing::k={k}"] = "extended"
            expected[f"paper-v1::threshold_spec::k={k}"] = "standard"
        for k in (64, 128, 256, 512):
            for grid in range(-10, 11):
                expected[
                    f"paper-v1::threshold_synthetic_fpfn::point=k{k}_j{grid}"
                ] = "extended"
        expected["paper-v1::threshold_dblp_fpfn::control=default"] = "extended"
        self.assertEqual(len(expected), 100)

        threshold = [cell for cell in self.document["cells"]
                     if cell["family"].startswith("threshold_")]
        self.assertEqual({cell["cell_id"] for cell in threshold}, set(expected))
        for cell in threshold:
            self.assertEqual(cell["timeout_class"], expected[cell["cell_id"]],
                             cell["cell_id"])
            if cell["family"] != "threshold_spec":
                self.assertNotEqual(cell["timeout_class"], "standard",
                                    cell["cell_id"])

    def test_every_timeout_class_keeps_a_threefold_measured_margin(self):
        """No cell with a measured runtime may sit within 3x of its stop.

        Measurements are the slowest natural completion observed for the cell:
        the threshold phase from the post-mortem re-runs, the top of the
        set-size sweep from the campaign host.  A stop is a safety net for a
        hang, not a budget, so the matrix must leave the measurement at most a
        third of its stop.
        """
        seconds = {"standard": 600, "extended": 3600, "long": 64800}
        measured = {
            "paper-v1::threshold_agreement::k=16": 138.0,
            "paper-v1::threshold_agreement::k=32": 160.0,
            "paper-v1::threshold_agreement::k=64": 881.0,
            "paper-v1::threshold_agreement::k=128": 1455.0,
            "paper-v1::threshold_agreement::k=256": 2886.0,
            "paper-v1::threshold_timing::k=128": 202.8,
            "paper-v1::threshold_timing::k=256": 157.0,
            "paper-v1::threshold_spec::k=256": 6.1,
            "paper-v1::threshold_synthetic_fpfn::point=k512_j-10": 391.8,
            "paper-v1::threshold_synthetic_fpfn::point=k256_j-10": 199.6,
            "paper-v1::threshold_dblp_fpfn::control=default": 237.9,
            "paper-v1::bcg12_exact::n=10000": 273.5,
            "paper-v1::bcg12_exact::n=100000": 2739.5,
            "paper-v1::piccard_std128::n=100000": 759.0,
            "paper-v1::piccard_std192_encoding::n=100000": 693.0,
            "paper-v1::dynamic_accuracy::n=100000": 384.4,
            "paper-v1::dynamic_timing::n=100000": 241.7,
        }
        cells = {cell["cell_id"]: cell for cell in self.document["cells"]}
        self.assertEqual(set(measured) - set(cells), set())
        for cell_id, duration in measured.items():
            stop = seconds[cells[cell_id]["timeout_class"]]
            self.assertGreaterEqual(stop, 3.0 * duration, cell_id)

    def test_lowered_threshold_timeout_classes_fail_closed(self):
        for cell_id in ("paper-v1::threshold_agreement::k=256",
                        "paper-v1::threshold_agreement::k=64",
                        "paper-v1::threshold_timing::k=128",
                        "paper-v1::threshold_synthetic_fpfn::point=k512_j0",
                        "paper-v1::threshold_dblp_fpfn::control=default"):
            lowered = copy.deepcopy(self.document)
            for cell in lowered["cells"]:
                if cell["cell_id"] == cell_id:
                    cell["timeout_class"] = "standard"
            with self.assertRaises(ValueError, msg=cell_id):
                validate_revision_matrix.validate_document(lowered, FIXTURES)

        demoted = copy.deepcopy(self.document)
        for cell in demoted["cells"]:
            if cell["cell_id"] == "paper-v1::threshold_agreement::k=128":
                cell["timeout_class"] = "extended"
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(demoted, FIXTURES)

    def test_exact_bcg12_sweep_is_classified_point_by_point(self):
        """bcg12_exact is costly one point below the top of its sweep.

        Every other family's n sweep is cheap until n=100000.  The exact BCG12
        baseline is not: measured on the campaign host it runs 4.3 s at n=100,
        28.6 s at n=1000, 273.5 s at n=10000 and 2739.5 s at n=100000, so
        n=10000 sits at 2.19x under the 600 s standard stop and needs
        ``extended``.  Its MinHash sibling takes 75.9 s at the same point and
        stays standard.
        """
        expected = {
            "paper-v1::bcg12_exact::control=default": "standard",
            "paper-v1::bcg12_exact::n=100": "standard",
            "paper-v1::bcg12_exact::n=1000": "standard",
            "paper-v1::bcg12_exact::n=10000": "extended",
            "paper-v1::bcg12_exact::n=100000": "long",
        }
        exact = [cell for cell in self.document["cells"]
                 if cell["family"] == "bcg12_exact"]
        self.assertEqual({cell["cell_id"] for cell in exact}, set(expected))
        for cell in exact:
            self.assertEqual(cell["timeout_class"], expected[cell["cell_id"]],
                             cell["cell_id"])
        minhash = next(c for c in self.document["cells"]
                       if c["cell_id"] == "paper-v1::bcg12_minhash::n=10000")
        self.assertEqual(minhash["timeout_class"], "standard")

    def test_aws_campaign_durations_keep_a_threefold_margin(self):
        """Sweep every real campaign duration against its stop.

        The fourth paper-v1 attempt completed 173 cells before it was killed;
        their wall-clock times on the c8i host are the authoritative input to
        timeout classification.  Every one of them must leave a 3x margin,
        with a single documented exception.
        """
        seconds = {"standard": 600, "extended": 3600, "long": 64800}
        # sj16::fit=precomputed is a serial Paillier-3072 fit that needs
        # 33610 s against the 64800 s `long` stop -- 1.93x.  There is no
        # larger class to promote it to, and it is not a hazard: it has
        # completed in production twice, on attempts 3 and 4, within 0.2% of
        # the same duration, so the run-to-run variance that would have to
        # appear for it to overrun is far outside anything observed.
        known_exceptions = {"paper-v1::sj16::fit=precomputed"}
        # The kill itself, not a completion: this cell was cut off at its
        # 600 s standard stop and actually needs 1455 s.
        truncated = {"paper-v1::threshold_agreement::k=128"}

        path = (ROOT / "tests" / "fixtures" / "revision_timeouts" /
                "aws_attempt4_durations.txt")
        durations = {}
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cell_id, value = line.rsplit(None, 1)
            durations[cell_id] = float(value)
        self.assertEqual(len(durations), 174)

        cells = {cell["cell_id"]: cell for cell in self.document["cells"]}
        self.assertEqual(set(durations) - set(cells), set())
        violations = []
        for cell_id, duration in durations.items():
            if cell_id in truncated:
                continue
            stop = seconds[cells[cell_id]["timeout_class"]]
            if stop < 3.0 * duration:
                violations.append((cell_id, duration, stop, stop / duration))
        self.assertEqual({v[0] for v in violations}, known_exceptions,
                         f"unexpected sub-3x cells: {violations}")

    def test_raw_phase_contract_covers_timing_rows_only(self):
        """The matrix is the allow-list for independent raw timing evidence."""
        expected = set()
        for cell in self.document["cells"]:
            family = cell["family"]
            axis = cell["axis"]
            value = str(cell["axis_value"])
            raw = False
            if family in {"piccard_std128", "bcg12_minhash", "bcg12_exact",
                          "dynamic_timing", "dynamic_refresh",
                          "threshold_timing"}:
                raw = True
            elif family == "fhe_ind":
                raw = True
            elif family == "real_dataset" and cell["axes"].get("artifact") == "std128_timing":
                raw = True
            elif family == "sj16":
                raw = not (axis == "u" and value in {"262144", "1048576"})
            elif family == "sqrt_comparison" and axis in {"timing_m", "crossover_m",
                                                          "timing_k", "timing_n",
                                                          "timing_km"}:
                # A non-square m has no sqrt producer row, hence no sqrt raw
                # artifact; the onehot timing row remains contract-bound.
                raw = True
            if cell["invocation_status"] != "RUN":
                raw = False

            rows = cell["expected_rows"]
            for row in rows:
                row_key = (cell["cell_id"], row["row_id"])
                has_contract = row.get("raw_timing_contract") == "raw-phase-v1"
                if family == "sqrt_comparison" and axis in {"timing_m", "crossover_m",
                                                            "timing_k", "timing_n",
                                                            "timing_km"}:
                    expected_row = row["row_id"] == "onehot" or (
                        row["row_id"] == "sqrt" and
                        str(cell["axes"].get("m")) in {"16", "64", "256"})
                    self.assertEqual(has_contract, expected_row, row_key)
                elif family == "piccard_std128":
                    self.assertEqual(has_contract,
                                     row["row_id"] == "onehot_timing",
                                     row_key)
                else:
                    self.assertEqual(has_contract, raw, row_key)
                if has_contract:
                    expected.add(row_key)

        # These sentinels make accidental broadening (accuracy/ciphertext/
        # status-only rows) fail loudly even if the family loop above changes.
        self.assertNotIn(("paper-v1::sqrt_comparison::accuracy_m=64", "onehot"), expected)
        self.assertNotIn(("paper-v1::sqrt_comparison::ciphertext_m=64", "onehot"), expected)
        self.assertNotIn(("paper-v1::threshold_spec::k=64", "spec"), expected)
        self.assertIn(("paper-v1::threshold_timing::k=256", "timing"), expected)
        self.assertNotIn(("paper-v1::real_dataset::enron_u65536_artifact=std192_encoding",
                          "std192_encoding"), expected)

    def test_family_axes_datasets_and_paper_count_contract(self):
        cells = {cell["cell_id"]: cell for cell in self.document["cells"]}

        # The comparison control is the frozen U=65536 geometry.  The n sweep
        # grows only its terminal n=100000 cell to the smallest containing U.
        for family in ("piccard_std128", "piccard_std192_encoding",
                       "fhe_ind", "bcg12_minhash", "bcg12_exact", "sj16",
                       "dynamic_timing", "dynamic_accuracy"):
            control = cells[f"paper-v1::{family}::control=default"]
            self.assertEqual(control["axes"]["u"], 65536)
            n_1000 = cells[f"paper-v1::{family}::n=1000"]
            self.assertEqual(n_1000["axes"]["u"], 65536)
            n_100000 = cells[f"paper-v1::{family}::n=100000"]
            self.assertEqual(n_100000["axes"]["u"], 262144)

        # The explicit U axis remains the complete frozen universe sweep.
        for family in ("piccard_std128", "piccard_std192_encoding", "fhe_ind",
                       "sj16"):
            values = [cells[f"paper-v1::{family}::u={u}"]["axes"]["u"]
                      for u in (16384, 65536, 262144, 1048576)]
            self.assertEqual(values, [16384, 65536, 262144, 1048576])

        real_expectations = {
            "dblp_acm_u65536": ("dblp_acm", 65536),
            "enron_u65536": ("enron", 65536),
            "enron_u1048576": ("enron", 1048576),
        }
        for variant, (dataset, universe) in real_expectations.items():
            for artifact in ("accuracy", "summary", "std128_timing",
                             "std192_encoding"):
                cell = cells[f"paper-v1::real_dataset::{variant}_artifact={artifact}"]
                self.assertEqual(cell["dataset"], dataset)
                self.assertEqual(cell["variant"], variant)
                self.assertEqual(cell["axes"]["variant"], variant)
                self.assertEqual(cell["axes"]["u"], universe)

        dblp = cells["paper-v1::threshold_dblp_fpfn::control=default"]
        self.assertEqual(dblp["dataset"], "dblp_acm")
        self.assertEqual(dblp["variant"], "dblp_acm_u65536")
        self.assertEqual(dblp["axes"]["variant"], "dblp_acm_u65536")
        self.assertEqual(dblp["axes"]["u"], 65536)
        self.assertEqual(dblp["paper_count"], 50)
        self.assertEqual(dblp["paper_trials"], 50)
        self.assertEqual(dblp["paper_counts"]["held_out"], 50)
        self.assertEqual(dblp["expected_rows"][0]["paper_measured_count"], 50)

        for cell in self.document["cells"]:
            if cell["family"] == "piccard_std192_encoding":
                self.assertEqual(cell["paper_count"], 30)
                self.assertEqual(cell["paper_trials"], 30)
                self.assertEqual(cell["paper_counts"]["encoding"], 30)
                self.assertEqual(cell["expected_rows"][0]["paper_measured_count"], 30)
                self.assertEqual(cell["expected_rows"][0]["measured_count"], 30)
            if (cell["family"] == "real_dataset" and
                    cell["axes"]["artifact"] in {"std128_timing", "std192_encoding"}):
                self.assertEqual(cell["paper_count"], 30)
                self.assertEqual(cell["paper_trials"], 30)
                self.assertEqual(cell["expected_rows"][0]["paper_measured_count"], 30)
                self.assertEqual(cell["expected_rows"][0]["measured_count"], 30)

    def test_duplicate_omitted_and_silent_rows_fail_closed(self):
        omitted = copy.deepcopy(self.document)
        omitted["cells"].pop()
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(omitted, FIXTURES)

        duplicate = copy.deepcopy(self.document)
        duplicate["cells"].append(copy.deepcopy(duplicate["cells"][0]))
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(duplicate, FIXTURES)

        silent = copy.deepcopy(self.document)
        silent["cells"][0]["expected_rows"] = []
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(silent, FIXTURES)

        omitted_row = copy.deepcopy(self.document)
        omitted_row["cells"][0]["expected_rows"].pop()
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(omitted_row, FIXTURES)

        duplicate_row = copy.deepcopy(self.document)
        duplicate_row["cells"][0]["expected_rows"].append(
            copy.deepcopy(duplicate_row["cells"][0]["expected_rows"][0]))
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(duplicate_row, FIXTURES)

    def test_enron_has_no_threshold_cell_and_every_row_has_terminal_fields(self):
        for cell in self.document["cells"]:
            if cell["family"] == "real_dataset" and cell["axes"].get("variant", "").startswith("enron"):
                self.assertNotIn("threshold", cell["cell_id"])
            for row in cell["expected_rows"]:
                self.assertIn("row_id", row)
                self.assertIn("status", row)
                self.assertIn("reason", row)
                self.assertIn("measured_count", row)

    def test_runner_contract_mutations_fail_closed(self):
        def mutate(cell_id, mutation):
            document = copy.deepcopy(self.document)
            cell = next(c for c in document["cells"] if c["cell_id"] == cell_id)
            mutation(cell)
            with self.assertRaises(ValueError):
                validate_revision_matrix.validate_document(document, FIXTURES)

        mutate("paper-v1::piccard_std128::control=default",
               lambda c: c.__setitem__("producer", "bench_review_comparison"))
        mutate("paper-v1::piccard_std128::control=default",
               lambda c: c["axes"].__setitem__("u", 16384))
        mutate("paper-v1::piccard_std128::n=100000",
               lambda c: c["axes"].__setitem__("u", 65536))
        mutate("paper-v1::real_dataset::enron_u1048576_artifact=accuracy",
               lambda c: c.__setitem__("dataset", "synthetic"))
        mutate("paper-v1::real_dataset::enron_u1048576_artifact=accuracy",
               lambda c: c["axes"].__setitem__("u", 65536))

        count_cell = "paper-v1::piccard_std128::control=default"
        for field, value in (("paper_count", 31), ("toy_count", 2),
                             ("paper_trials", 31), ("toy_trials", 2)):
            mutate(count_cell, lambda c, f=field, v=value: c.__setitem__(f, v))
        mutate(count_cell,
               lambda c: c["paper_counts"].__setitem__("timing", 31))
        mutate(count_cell,
               lambda c: c["toy_counts"].__setitem__("timing", 2))
        mutate(count_cell,
               lambda c: c["expected_rows"][0].__setitem__(
                   "paper_measured_count", 31))
        mutate(count_cell,
               lambda c: c["expected_rows"][0].__setitem__(
                   "toy_measured_count", 2))

        mutate("paper-v1::dynamic_refresh::control=default",
               lambda c: c.__setitem__("updates", 2))
        mutate("paper-v1::dynamic_refresh::control=default",
               lambda c: c["expected_rows"][0].__setitem__("updates", 2))

        fit = "paper-v1::sj16::fit=per_element"
        for field, value in (("sizes", [4096, 8192]),
                             ("held_out", 16384), ("key_bits", 2048),
                             ("threads", 1), ("precomputed", True),
                             ("fit_authority", False)):
            mutate(fit, lambda c, f=field, v=value: c.__setitem__(f, v))
        mutate(fit,
               lambda c: c["paper_counts"].__setitem__("enc_iters", 29))
        mutate(fit,
               lambda c: c["expected_rows"][0].__setitem__("warmup_calls", 0))
        mutate(fit, lambda c: c.__setitem__("timeout_class", "standard"))
        mutate("paper-v1::sj16::control=default",
               lambda c: c.__setitem__("timeout_class", "extended"))

        mutate("paper-v1::sj16::u=262144",
               lambda c: c["expected_rows"][0].__setitem__(
                   "reason", ""))
        mutate("paper-v1::sqrt_comparison::timing_m=32",
               lambda c: c["expected_rows"][1].__setitem__(
                   "status", "MEASURED"))
        mutate("paper-v1::piccard_std192_encoding::control=default",
               lambda c: c["expected_rows"][0].__setitem__(
                   "method", "piccard_sqrt_encode"))
        mutate("paper-v1::fhe_ind::control=default",
               lambda c: c["expected_rows"][0].__setitem__(
                   "raw_timing_contract", "aggregate-only"))
        mutate("paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy",
               lambda c: c["expected_rows"][0].__setitem__(
                   "variant", "enron_u65536"))

    def test_reciprocal_family_payload_swap_fails_closed(self):
        document = copy.deepcopy(self.document)
        first = next(c for c in document["cells"]
                     if c["cell_id"] == "paper-v1::piccard_std128::control=default")
        second = next(c for c in document["cells"]
                      if c["cell_id"] == "paper-v1::piccard_std192_encoding::control=default")
        first_id, second_id = first["cell_id"], second["cell_id"]
        first_payload = copy.deepcopy(first)
        second_payload = copy.deepcopy(second)
        first.clear()
        first.update(second_payload)
        second.clear()
        second.update(first_payload)
        first["cell_id"], second["cell_id"] = first_id, second_id
        with self.assertRaises(ValueError):
            validate_revision_matrix.validate_document(document, FIXTURES)

    def test_toy_inventory_is_exact_and_drift_is_rejected(self):
        expected = {
            "paper-v1::bcg12_exact::control=default",
            "paper-v1::bcg12_minhash::control=default",
            "paper-v1::deletion_exact::control=default",
            "paper-v1::deletion_mc::control=default",
            "paper-v1::dynamic_accuracy::control=default",
            "paper-v1::dynamic_refresh::control=default",
            "paper-v1::dynamic_timing::control=default",
            "paper-v1::estimator_accuracy::j=0.5",
            "paper-v1::fhe_ind::control=default",
            "paper-v1::flooding::profile=primary40",
            "paper-v1::piccard_std128::control=default",
            "paper-v1::piccard_std192_encoding::control=default",
            "paper-v1::real_dataset::dblp_acm_u65536_artifact=accuracy",
            "paper-v1::real_dataset::enron_u65536_artifact=accuracy",
            "paper-v1::sj16::fit=per_element",
            "paper-v1::sqrt_comparison::timing_m=64",
            "paper-v1::threshold_agreement::k=64",
            "paper-v1::threshold_dblp_fpfn::control=default",
            "paper-v1::threshold_spec::k=64",
            "paper-v1::threshold_timing::k=64",
        }
        toy = (FIXTURES / "toy_cell_ids.txt").read_text().splitlines()
        self.assertEqual(set(toy), expected)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for path in FIXTURES.iterdir():
                (root / path.name).write_text(path.read_text())
            drifted = ["paper-v1::piccard_std128::k=16"] + toy[1:]
            (root / "toy_cell_ids.txt").write_text("\n".join(drifted) + "\n")
            with self.assertRaises(ValueError):
                validate_revision_matrix.validate_document(self.document, root)

    def test_coordinated_toy_inventory_drift_fails_closed(self):
        toy = (FIXTURES / "toy_cell_ids.txt").read_text().splitlines()
        executable = (FIXTURES / "executable_toy_cell_ids.txt").read_text().splitlines()
        old_id = "paper-v1::piccard_std128::control=default"
        replacement = "paper-v1::piccard_std128::k=16"
        self.assertIn(old_id, toy)
        self.assertNotIn(replacement, toy)
        self.assertIn(old_id, executable)
        self.assertNotIn(replacement, executable)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for path in FIXTURES.iterdir():
                (root / path.name).write_text(path.read_text())
            drifted_toy = sorted(replacement if value == old_id else value
                                 for value in toy)
            drifted_executable = sorted(replacement if value == old_id else value
                                        for value in executable)
            (root / "toy_cell_ids.txt").write_text("\n".join(drifted_toy) + "\n")
            (root / "executable_toy_cell_ids.txt").write_text(
                "\n".join(drifted_executable) + "\n")
            with self.assertRaises(ValueError):
                validate_revision_matrix.validate_document(self.document, root)


if __name__ == "__main__":
    unittest.main()
