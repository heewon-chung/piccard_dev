from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts import summarize_table9_sweep as summ  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "table9_sweep"
SCRIPT = ROOT / "scripts" / "summarize_table9_sweep.py"


class MappingTest(unittest.TestCase):
    def test_cell_for_default_point_and_fhe_ind(self) -> None:
        d = ("k", 65536, 1000, 128, 64)
        self.assertEqual(summ.cell_for(*d, "piccard"), "paper-v1::piccard_std128::u=65536")
        self.assertEqual(summ.cell_for(*d, "piccard_plus"), "paper-v1::sqrt_comparison::timing_u=65536")
        self.assertEqual(summ.cell_for(*d, "sj16"), "paper-v1::sj16::u=65536")
        # k and m are not SJ16/BCG12 inputs, so those rows repeat the default point.
        self.assertEqual(summ.cell_for("k", 65536, 1000, 16, 64, "sj16"), "paper-v1::sj16::u=65536")
        self.assertEqual(summ.cell_for("m", 65536, 1000, 128, 256, "bcg12_ec"), "paper-v1::bcg12_minhash::u=65536")
        self.assertEqual(summ.cell_for("u", 16384, 1000, 128, 64, "bcg12_ec"), "paper-v1::bcg12_minhash::u=65536")
        # n and k ARE BCG12 inputs; u and n ARE SJ16 inputs.
        self.assertEqual(summ.cell_for("k", 65536, 1000, 16, 64, "bcg12_ec"), "paper-v1::bcg12_minhash::k=16")
        self.assertEqual(summ.cell_for("n", 65536, 100, 128, 64, "sj16"), "paper-v1::sj16::n=100")
        self.assertEqual(summ.cell_for("u", 16384, 1000, 128, 64, "sj16"), "paper-v1::sj16::u=16384")
        # SJ16 at 2^18 / 2^20 has no cell at all: the paper's extrapolation fills it.
        self.assertIsNone(summ.cell_for("u", 262144, 1000, 128, 64, "sj16"))
        self.assertIsNone(summ.cell_for("u", 1048576, 1000, 128, 64, "sj16"))
        self.assertIsNone(summ.cell_for("m", 65536, 1000, 128, 128, "piccard_plus"))
        self.assertEqual(summ.cell_for("u", 16384, 1000, 128, 64, "fhe_ind"), "paper-v1::fhe_ind::u=16384")
        self.assertEqual(summ.cell_for("n", 65536, 100, 128, 64, "fhe_ind"), "paper-v1::fhe_ind::n=100")
        self.assertEqual(summ.cell_for("n", 65536, 1000, 128, 64, "fhe_ind"), "paper-v1::fhe_ind::u=65536")
        self.assertEqual(summ.cell_for("m", 65536, 1000, 128, 256, "fhe_ind"), "paper-v1::fhe_ind::u=65536")


class AggregateTest(unittest.TestCase):
    def test_loads_every_column_from_real_sidecars(self) -> None:
        aggs = summ.load_aggregates(FIX / "good")
        self.assertEqual(set(aggs), {
            ("paper-v1::piccard_std128::u=16384", "piccard"),
            ("paper-v1::sqrt_comparison::timing_k=16", "piccard_plus"),
            ("paper-v1::fhe_ind::u=16384", "fhe_ind"),
            ("paper-v1::bcg12_minhash::k=16", "bcg12_ec"),
            ("paper-v1::bcg12_minhash::k=16", "bcg12_ff"),
            ("paper-v1::sj16::u=16384", "sj16"),
        })
        self.assertEqual(aggs[("paper-v1::piccard_std128::u=16384", "piccard")].measured_count, 30)
        self.assertEqual(summ.format_cell(aggs[("paper-v1::piccard_std128::u=16384", "piccard")]), r"$143.5\pm2.4$")
        self.assertEqual(summ.format_cell(aggs[("paper-v1::sj16::u=16384", "sj16")]), r"$17{,}635\pm152$")
        self.assertEqual(summ.format_cell(aggs[("paper-v1::fhe_ind::u=16384", "fhe_ind")]), r"$47.0\pm2.1$")

    def test_format_cell_rules(self) -> None:
        agg = summ.Aggregate(mean_ms=17634.6377, sd_ms=1.0, median_ms=1.0, ci95_half_ms=151.76,
                             measured_count=30, ci95_low_ms=0.0, ci95_high_ms=0.0)
        self.assertEqual(summ.format_cell(agg), r"$17{,}635\pm152$")
        self.assertEqual(summ.format_cell(agg._replace(mean_ms=143.54, ci95_half_ms=2.44)), r"$143.5\pm2.4$")
        self.assertEqual(summ.format_cell(agg._replace(mean_ms=1170.5, ci95_half_ms=4.5)), r"$1{,}170.5\pm4.5$")
        self.assertEqual(summ.format_cell(None), "---")

    def test_extrapolated_sj16_rows_render_without_an_interval(self) -> None:
        rows = summ.render_rows({}).splitlines()
        # |U| block rows 3 and 4 are the two extrapolated SJ16 cells; they
        # must carry the paper's existing double-dagger marker (K-3) so the
        # LaTeX is never indistinguishable from a measurement.
        self.assertIn(r"$285{,}389^{\ddagger\ddagger}$", rows[2])
        self.assertIn(r"$1{,}141{,}500^{\ddagger\ddagger}$", rows[3])
        self.assertNotIn(r"285{,}389\pm", rows[2])

    def test_no_measured_cell_carries_the_extrapolation_marker(self) -> None:
        aggs = summ.load_aggregates(FIX / "good")
        row0 = summ.render_rows(aggs).splitlines()[0]  # |U|=2^14, all real sidecars
        self.assertNotIn(r"\ddagger", row0)

    def test_short_sidecar_is_rejected(self) -> None:
        with self.assertRaises(summ.SweepError):
            summ.load_aggregates(FIX / "short")

    def test_wrong_cell_id_header_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = FIX / "good" / "cells" / "paper_v1__piccard_std128__u_16384"
            dst = root / "cells" / "paper_v1__piccard_std128__u_65536"   # directory claims u=65536
            dst.mkdir(parents=True)
            for f in src.iterdir():
                (dst / f.name).write_bytes(f.read_bytes())
            (root / "run.json").write_text((FIX / "good" / "run.json").read_text())
            with self.assertRaises(summ.SweepError):
                summ.load_aggregates(root)


class FlatnessTest(unittest.TestCase):
    def test_empty_aggregates_do_not_synthesize_a_ratio_from_extrapolation_alone(self) -> None:
        # With zero real data, the sj16 |U| block has fewer than two measured
        # rows (the other two are the paper's extrapolation literals), so it
        # must not print a numeric ratio -- not "4.000" from the two literals,
        # and not any other invented number.
        report = summ.flatness({})
        row = next(line for line in report.splitlines() if line.startswith("| u |"))
        cells = [c.strip() for c in row.strip("|").split("|")]
        sj16_cell = cells[1 + summ.PRINTED.index("sj16")]
        self.assertEqual(sj16_cell, "n/a (insufficient measured rows)")

    def test_axis_the_column_does_not_consume_prints_not_an_input(self) -> None:
        # bcg12_ec does not consume m (CONSUMED_AXES["bcg12_ec"] == {"n", "k"}), so
        # every m-block row resolves to the same cell id: the ratio would be a
        # tautological 1.000.  This must read "not an input", not "1.000".
        report = summ.flatness({})
        row = next(line for line in report.splitlines() if line.startswith("| m |"))
        cells = [c.strip() for c in row.strip("|").split("|")]
        bcg12_cell = cells[1 + summ.PRINTED.index("bcg12_ec")]
        self.assertEqual(bcg12_cell, "n/a (not an input)")

    def test_measured_block_prints_the_hand_computed_ratio(self) -> None:
        # Two distinct piccard k-block cells with known means: the printed
        # ratio must equal max/min of exactly those two values.
        aggs = {
            ("paper-v1::piccard_std128::k=16", "piccard"):
                summ.Aggregate(100.0, 1.0, 100.0, 1.0, 30, 99.0, 101.0),
            ("paper-v1::piccard_std128::u=65536", "piccard"):
                summ.Aggregate(150.0, 1.0, 150.0, 1.0, 30, 149.0, 151.0),
        }
        report = summ.flatness(aggs)
        row = next(line for line in report.splitlines() if line.startswith("| k |"))
        cells = [c.strip() for c in row.strip("|").split("|")]
        piccard_cell = cells[1 + summ.PRINTED.index("piccard")]
        self.assertEqual(piccard_cell, f"{150.0 / 100.0:.3f}")


def _copy_cell_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True)
    for f in src.iterdir():
        if f.is_file():
            (dst / f.name).write_bytes(f.read_bytes())


def _rewrite_aggregate_field(tsv: Path, phase: str, field: str, value: str) -> None:
    lines = tsv.read_text().splitlines(True)
    header_idx = next(i for i, l in enumerate(lines) if l.startswith("aggregate\tproducer_id\t"))
    columns = lines[header_idx].rstrip("\n").split("\t")
    data_idx = next(i for i, l in enumerate(lines)
                     if l.startswith("aggregate\t") and i != header_idx
                     and l.split("\t")[columns.index("phase")] == phase)
    fields = lines[data_idx].rstrip("\n").split("\t")
    fields[columns.index(field)] = value
    lines[data_idx] = "\t".join(fields) + "\n"
    tsv.write_text("".join(lines))


class IntegrityTest(unittest.TestCase):
    """K-1 (evidence binding via receipt.json / exact sidecar selection) and
    K-2 (recomputing the aggregate from its own samples) regression tests."""

    def test_attempt_sibling_directory_is_never_consulted(self) -> None:
        # A "failed attempt" directory (Task 2's resume/retry archiving)
        # sits next to, but is never, the canonical cell directory.  With no
        # canonical cells/<slug>/ present, the cell must simply be absent
        # from the result -- never discovered via the sibling.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sibling = root / "cells" / "paper_v1__piccard_std128__u_16384.attempt-1"
            _copy_cell_dir(FIX / "good" / "cells" / "paper_v1__piccard_std128__u_16384", sibling)
            aggs = summ.load_aggregates(root)
            self.assertNotIn(("paper-v1::piccard_std128::u=16384", "piccard"), aggs)

    def test_two_candidate_sidecars_fail_naming_both(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dst = root / "cells" / "paper_v1__piccard_std128__u_16384"
            _copy_cell_dir(FIX / "good" / "cells" / "paper_v1__piccard_std128__u_16384", dst)
            tsv = next(dst.glob("bench_piccard__*.tsv"))
            duplicate = dst / ("dup_" + tsv.name)
            duplicate.write_bytes(tsv.read_bytes())  # a second real sidecar in the same directory
            with self.assertRaises(summ.SweepError) as ctx:
                summ.load_aggregates(root)
            self.assertIn(tsv.name, str(ctx.exception))
            self.assertIn(duplicate.name, str(ctx.exception))

    def test_real_runner_receipt_schema_is_readable(self) -> None:
        # scripts/run_table9_sweep.py's receipt has no artifact_inventory key
        # (that belongs to the full orchestrator's receipt schema); this
        # fixture is a real receipt.json copied verbatim from a finished AWS
        # run so a future schema drift between the two scripts fails here,
        # in CI, rather than silently on a finished run.
        aggs = summ.load_aggregates(FIX / "real_receipt_schema")
        self.assertIn(("paper-v1::piccard_std128::u=16384", "piccard"), aggs)
        self.assertEqual(summ.format_cell(aggs[("paper-v1::piccard_std128::u=16384", "piccard")]),
                          r"$139.5\pm0.5$")

    def test_receipt_not_completed_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dst = root / "cells" / "paper_v1__piccard_std128__u_16384"
            _copy_cell_dir(FIX / "good" / "cells" / "paper_v1__piccard_std128__u_16384", dst)
            receipt = json.loads((dst / "receipt.json").read_text())
            receipt["execution_status"] = "FAILED"
            (dst / "receipt.json").write_text(json.dumps(receipt))
            with self.assertRaises(summ.SweepError):
                summ.load_aggregates(root)

    def test_altered_aggregate_mean_with_intact_samples_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dst = root / "cells" / "paper_v1__piccard_std128__u_16384"
            _copy_cell_dir(FIX / "good" / "cells" / "paper_v1__piccard_std128__u_16384", dst)
            tsv = next(dst.glob("bench_piccard__*.tsv"))
            _rewrite_aggregate_field(tsv, "total", "mean_ms", "999999.0")
            with self.assertRaises(summ.SweepError):
                summ.load_aggregates(root)

    def test_duplicate_aggregate_row_for_phase_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dst = root / "cells" / "paper_v1__piccard_std128__u_16384"
            _copy_cell_dir(FIX / "good" / "cells" / "paper_v1__piccard_std128__u_16384", dst)
            tsv = next(dst.glob("bench_piccard__*.tsv"))
            lines = tsv.read_text().splitlines(True)
            header_idx = next(i for i, l in enumerate(lines) if l.startswith("aggregate\tproducer_id\t"))
            columns = lines[header_idx].rstrip("\n").split("\t")
            data_idx = next(i for i, l in enumerate(lines)
                             if l.startswith("aggregate\t") and i != header_idx
                             and l.split("\t")[columns.index("phase")] == "total")
            lines.insert(data_idx + 1, lines[data_idx])  # duplicate the 'total' aggregate row
            tsv.write_text("".join(lines))
            with self.assertRaises(summ.SweepError):
                summ.load_aggregates(root)

    def test_repeated_trial_index_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dst = root / "cells" / "paper_v1__piccard_std128__u_16384"
            _copy_cell_dir(FIX / "good" / "cells" / "paper_v1__piccard_std128__u_16384", dst)
            tsv = next(dst.glob("bench_piccard__*.tsv"))
            lines = tsv.read_text().splitlines(True)
            header_idx = next(i for i, l in enumerate(lines) if l.startswith("sample\tproducer_id\t"))
            columns = lines[header_idx].rstrip("\n").split("\t")
            measured_idx = [i for i, l in enumerate(lines) if l.startswith("sample\t") and i != header_idx
                             and l.split("\t")[columns.index("phase")] == "total"
                             and l.split("\t")[columns.index("sample_kind")] == "measured"]
            other_trial_index = lines[measured_idx[6]].rstrip("\n").split("\t")[columns.index("trial_index")]
            fields = lines[measured_idx[5]].rstrip("\n").split("\t")
            fields[columns.index("trial_index")] = other_trial_index  # now a duplicate of measured_idx[6]'s
            lines[measured_idx[5]] = "\t".join(fields) + "\n"
            tsv.write_text("".join(lines))
            with self.assertRaises(summ.SweepError):
                summ.load_aggregates(root)


class ManifestGapTest(unittest.TestCase):
    def test_symmetric_difference_against_table9_cell_ids(self) -> None:
        cell_ids = list(summ.TABLE9_CELL_IDS)
        missing_id = cell_ids.pop()
        manifest = {"cells": [{"cell_id": c, "execution_status": "COMPLETED"} for c in cell_ids]
                     + [{"cell_id": "not-a-real-cell", "execution_status": "COMPLETED"},
                        {"cell_id": "paper-v1::piccard_std128::u=999", "execution_status": "FAILED"}]}
        missing, unexpected = summ._manifest_cell_gap(manifest)
        self.assertEqual(missing, {missing_id})
        self.assertEqual(unexpected, {"not-a-real-cell"})  # the FAILED entry doesn't count either way

    def test_exact_match_has_no_gap(self) -> None:
        manifest = {"cells": [{"cell_id": c, "execution_status": "COMPLETED"} for c in summ.TABLE9_CELL_IDS]}
        self.assertEqual(summ._manifest_cell_gap(manifest), (set(), set()))


def _write_matrix(root: Path, cell_id: str, producer: str) -> None:
    (root).mkdir(parents=True, exist_ok=True)
    (root / "matrix.json").write_text(json.dumps({"cells": [{"cell_id": cell_id, "producer": producer}]}))


class ThreadProvenanceTest(unittest.TestCase):
    """Q-1: --threads is inert for bench_review_comparison, so a run's
    declared provenance.threads must be cross-checked against what a
    producer actually recorded (omp_threads/omp_dynamic), wherever that
    column shows up -- a real .csv, or (as on the AWS-synced results) a
    CSV-formatted stdout.log.  Which cells MUST record it is derived from
    the archived matrix.json's own `producer` field, not from whichever
    cells happen to volunteer the column -- a cell that should record it
    and doesn't is a failure, not a silent pass."""

    SJ16_CELL = "paper-v1::sj16::u=16384"       # producer bench_review_comparison: MUST record
    PICCARD_CELL = "paper-v1::piccard_std128::u=16384"  # producer bench_piccard: never records

    def test_thread_mismatch_in_csv_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_matrix(root, self.SJ16_CELL, "bench_review_comparison")
            cell_dir = root / "cells" / summ.slug(self.SJ16_CELL)
            cell_dir.mkdir(parents=True)
            (cell_dir / "stdout.log").write_text(
                "suite,scenario,omp_threads,omp_dynamic\nrevision-x,y,8,false\n")
            with self.assertRaises(summ.SweepError):
                summ.check_thread_provenance(root, 16)

    def test_omp_dynamic_true_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_matrix(root, self.SJ16_CELL, "bench_review_comparison")
            cell_dir = root / "cells" / summ.slug(self.SJ16_CELL)
            cell_dir.mkdir(parents=True)
            (cell_dir / "stdout.log").write_text(
                "suite,scenario,omp_threads,omp_dynamic\nrevision-x,y,16,true\n")
            with self.assertRaises(summ.SweepError):
                summ.check_thread_provenance(root, 16)

    def test_matching_threads_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_matrix(root, self.SJ16_CELL, "bench_review_comparison")
            cell_dir = root / "cells" / summ.slug(self.SJ16_CELL)
            cell_dir.mkdir(parents=True)
            (cell_dir / "stdout.log").write_text(
                "suite,scenario,omp_threads,omp_dynamic\nrevision-x,y,16,false\n")
            summ.check_thread_provenance(root, 16)  # must not raise

    def test_non_recording_producer_with_no_column_is_not_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_matrix(root, self.PICCARD_CELL, "bench_piccard")
            cell_dir = root / "cells" / summ.slug(self.PICCARD_CELL)
            cell_dir.mkdir(parents=True)
            (cell_dir / "identity.csv").write_text("schema,cell_id,universe_size\npiccard-table9-sweep-run-v1,x,16384\n")
            summ.check_thread_provenance(root, 16)  # must not raise

    def test_recording_producer_with_no_column_anywhere_is_rejected(self) -> None:
        # A bench_review_comparison cell whose directory carries no
        # omp_threads column at all -- e.g. a truncated/renamed/absent
        # producer output -- must fail naming the cell, not pass silently
        # because nothing volunteered the evidence.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_matrix(root, self.SJ16_CELL, "bench_review_comparison")
            cell_dir = root / "cells" / summ.slug(self.SJ16_CELL)
            cell_dir.mkdir(parents=True)
            (cell_dir / "stderr.log").write_text("")  # no CSV content, no omp_threads column
            with self.assertRaises(summ.SweepError) as ctx:
                summ.check_thread_provenance(root, 16)
            self.assertIn(self.SJ16_CELL, str(ctx.exception))

    def test_header_only_column_with_no_data_rows_is_rejected(self) -> None:
        # A file that carries the omp_threads *heading* but zero data rows
        # (truncated stdout.log, a producer killed after printing its
        # header, a trimmed fixture) must fail distinctly from "no file at
        # all" -- the column existing is not the same as a value being
        # verified.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_matrix(root, self.SJ16_CELL, "bench_review_comparison")
            cell_dir = root / "cells" / summ.slug(self.SJ16_CELL)
            cell_dir.mkdir(parents=True)
            (cell_dir / "stdout.log").write_text("suite,scenario,omp_threads,omp_dynamic\n")  # header only
            with self.assertRaises(summ.SweepError) as ctx:
                summ.check_thread_provenance(root, 16)
            message = str(ctx.exception)
            self.assertIn(self.SJ16_CELL, message)
            self.assertIn("no data rows", message)

    def test_missing_declared_threads_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_matrix(root, self.SJ16_CELL, "bench_review_comparison")
            with self.assertRaises(summ.SweepError):
                summ.check_thread_provenance(root, None)


class ExtrapolationIntegrityTest(unittest.TestCase):
    """Q-2: EXTRAPOLATED_SJ16 may only be used when there is genuinely
    nothing else -- if a real cell directory exists for either id it
    stands in for, that is a drift that must fail loudly, not be
    shadowed.  TABLE9_CELL_IDS excludes both ids by construction, so
    `load_aggregates`'s `aggs` can never contain them -- the guard has to
    look at the results tree instead.  This test proves the guard is
    reachable (fails with the directory present, passes once it's gone),
    not merely that it type-checks."""

    def test_extrapolated_cell_directory_is_rejected_then_its_absence_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cell_dir = root / "cells" / "paper_v1__sj16__u_262144"
            (cell_dir / "raw").mkdir(parents=True)
            (cell_dir / "receipt.json").write_text(json.dumps({
                "schema": "piccard-table9-sweep-cell-receipt-v1",
                "cell_id": "paper-v1::sj16::u=262144", "execution_status": "COMPLETED", "exit_code": 0,
            }))
            (cell_dir / "raw" / "bench_review_comparison__paper-v1__sj16__u_262144__sj16__paper-v1.tsv").write_text(
                "schema_version\tpiccard-paper-raw-timing-v1\n")
            with self.assertRaises(summ.SweepError) as ctx:
                summ.load_aggregates(root)
            self.assertIn("paper-v1::sj16::u=262144", str(ctx.exception))

            shutil.rmtree(cell_dir)
            summ.load_aggregates(root)  # now must not raise -- proves the guard is reachable, not dead

    def test_extrapolated_row_without_a_real_cell_directory_still_returns_the_constant(self) -> None:
        agg = summ._lookup({}, ("u", 262144, 1000, 128, 64), "sj16")
        self.assertEqual(agg.mean_ms, 285389.0)


class MatrixProvenanceTest(unittest.TestCase):
    """Q-3: a results root must carry the exact matrix it was planned
    against (<root>/matrix.json), archived alongside the run -- never the
    repository's present matrix, which keeps evolving after a run is
    archived and would otherwise make an old, valid run unreproducible."""

    def test_matrix_sha_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            (root / "cells").mkdir(parents=True)
            shutil.copyfile(FIX / "good" / "matrix.json", root / "matrix.json")
            manifest = {
                "schema": "piccard-table9-sweep-run-v1", "state": "COMPLETED", "dirty_allowed": False,
                "provenance": {"threads": 16, "seed": 20260729, "matrix_sha256": "0" * 64},  # deliberately wrong
                "cells": [{"cell_id": c, "execution_status": "COMPLETED", "exit_code": 0}
                          for c in summ.TABLE9_CELL_IDS],
            }
            (root / "run.json").write_text(json.dumps(manifest))
            r = subprocess.run([sys.executable, str(SCRIPT), f"--results-root={root}",
                                f"--out-dir={tmp}", "--partial"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("0" * 64, r.stderr)
            self.assertIn(summ.sha256_file(root / "matrix.json"), r.stderr)

    def test_missing_matrix_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            (root / "cells").mkdir(parents=True)
            manifest = {
                "schema": "piccard-table9-sweep-run-v1", "state": "COMPLETED", "dirty_allowed": False,
                "provenance": {"threads": 16, "seed": 20260729, "matrix_sha256": "da2bdfa"},
                "cells": [{"cell_id": c, "execution_status": "COMPLETED", "exit_code": 0}
                          for c in summ.TABLE9_CELL_IDS],
            }
            (root / "run.json").write_text(json.dumps(manifest))  # no matrix.json written
            r = subprocess.run([sys.executable, str(SCRIPT), f"--results-root={root}",
                                f"--out-dir={tmp}", "--partial"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("matrix.json", r.stderr)

    def test_archived_matrix_sha256_reads_the_results_root_copy(self) -> None:
        self.assertEqual(summ._archived_matrix_sha256(FIX / "good"),
                          summ.sha256_file(FIX / "good" / "matrix.json"))


class CliTest(unittest.TestCase):
    def test_partial_renders_sixteen_rows_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run([sys.executable, str(SCRIPT), f"--results-root={FIX / 'good'}",
                                f"--out-dir={tmp}", "--partial"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = (Path(tmp) / "table9_rows.tex").read_text().splitlines()
            self.assertEqual(len(rows), 16)
            self.assertEqual(rows[0], "\t$2^{14}$ & 1,000 & 128 & 64 & $143.5\\pm2.4$ & --- & --- & $17{,}635\\pm152$ & $47.0\\pm2.1$ \\\\")
            self.assertTrue(rows[7].startswith("\t$2^{16}$ & 1,000 & 16 & 64 & --- & "))
            self.assertNotIn("--- & --- & --- & --- & ---", rows[7])  # piccard_plus k=16 is present
            csv_lines = (Path(tmp) / "table9.csv").read_text().splitlines()
            self.assertEqual(csv_lines[0], "cell_id,column,measured_count,mean_ms,sd_ms,median_ms,ci95_half_ms")
            self.assertEqual(len(csv_lines), 7)
            self.assertIn("| u |", (Path(tmp) / "flatness.md").read_text())

    def test_refuses_missing_cells_without_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run([sys.executable, str(SCRIPT), f"--results-root={FIX / 'good'}",
                                f"--out-dir={tmp}"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("missing", r.stderr)

    def test_manifest_missing_one_expected_cell_is_refused_without_partial(self) -> None:
        # A COMPLETED manifest whose cell set is not exactly TABLE9_CELL_IDS
        # (e.g. one id silently dropped) must be refused -- and the missing
        # id must be named -- unless --partial is passed.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            (root / "cells").mkdir(parents=True)
            shutil.copyfile(FIX / "good" / "matrix.json", root / "matrix.json")
            good_matrix_sha = json.loads((FIX / "good" / "run.json").read_text())["provenance"]["matrix_sha256"]
            cell_ids = list(summ.TABLE9_CELL_IDS)
            missing_id = cell_ids.pop()
            manifest = {
                "schema": "piccard-table9-sweep-run-v1", "state": "COMPLETED", "dirty_allowed": False,
                "provenance": {"threads": 16, "seed": 20260729, "matrix_sha256": good_matrix_sha},
                "cells": [{"cell_id": c, "execution_status": "COMPLETED", "exit_code": 0} for c in cell_ids],
            }
            (root / "run.json").write_text(json.dumps(manifest))
            r = subprocess.run([sys.executable, str(SCRIPT), f"--results-root={root}", f"--out-dir={tmp}"],
                                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn(missing_id, r.stderr)
            self.assertIn("missing", r.stderr.lower())

    def test_refuses_failed_or_dirty_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            (root / "cells").mkdir(parents=True)
            shutil.copyfile(FIX / "good" / "matrix.json", root / "matrix.json")
            (root / "run.json").write_text((FIX / "nonstandard_run.json").read_text())
            r = subprocess.run([sys.executable, str(SCRIPT), f"--results-root={root}",
                                f"--out-dir={tmp}", "--partial"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("nonstandard", r.stderr)


if __name__ == "__main__":
    unittest.main()
