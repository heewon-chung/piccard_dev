from __future__ import annotations

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
        # |U| block rows 3 and 4 are the two extrapolated SJ16 cells.
        self.assertIn(r"$285{,}389$", rows[2])
        self.assertIn(r"$1{,}141{,}500$", rows[3])
        self.assertNotIn(r"285{,}389\pm", rows[2])

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

    def test_refuses_failed_or_dirty_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            (root / "cells").mkdir(parents=True)
            (root / "run.json").write_text((FIX / "nonstandard_run.json").read_text())
            r = subprocess.run([sys.executable, str(SCRIPT), f"--results-root={root}",
                                f"--out-dir={tmp}", "--partial"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("nonstandard", r.stderr)


if __name__ == "__main__":
    unittest.main()
