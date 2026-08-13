#!/usr/bin/env python3
"""Static producer contract for the versioned threshold specification output.

The threshold spec sweep constructs OpenFHE contexts and is intentionally not
run by this gate.  These checks pin the producer seam, schema field order, and
the separation from the historical timing/accuracy writer.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "benchmarks" / "bench_threshold.cpp"
SCHEMA = ROOT / "benchmarks" / "threshold_csv_schema.h"


def function_body(source: str, signature: str, end_marker: str) -> str:
    start = source.index(signature)
    end = source.index(end_marker, start)
    return source[start:end]


class ThresholdProvenanceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = BENCHMARK.read_text(encoding="utf-8")
        cls.schema = SCHEMA.read_text(encoding="utf-8")
        cls.spec = function_body(
            cls.benchmark,
            "static void BenchSpecDump(const BenchmarkConfig& config,\n"
            "                          std::optional<uint32_t> selected_k = std::nullopt)",
            "// Main",
        )

    def test_spec_uses_successor_writer_only(self) -> None:
        self.assertIn("std::cout << ThresholdSpecCSVHeader();", self.spec)
        self.assertIn("WriteThresholdSpecRow(std::cout, row);", self.spec)
        self.assertNotIn("ThresholdCSVHeader()", self.spec)
        self.assertIn('if (config.mode != "spec") {', self.benchmark)
        self.assertIn("csv.WriteHeader();", self.benchmark)

    def test_spec_calls_common_provenance_constructor(self) -> None:
        self.assertRegex(
            self.spec,
            r"MakePiccardBenchmarkProvenance\s*\(\s*bfv\s*\)",
        )
        self.assertIn("provenance.ordered_rns_moduli", self.spec)
        self.assertIn("provenance.ordered_rns_limb_bits", self.spec)
        self.assertIn("provenance.residual_capacity_status", self.spec)
        self.assertIn("provenance.flooding_assurance", self.spec)
        self.assertRegex(self.spec, r"provenance\.query_stat_bits")

    def test_successful_threshold_rows_pin_legacy_assurance_and_query_zero(self) -> None:
        self.assertIn('"legacy-coefficient-level"', self.schema)
        self.assertIn("row.flooding_assurance = provenance.flooding_assurance;", self.spec)
        self.assertRegex(
            self.spec,
            r"row\.query_stat_bits\s*=\s*\*provenance\.query_stat_bits",
        )
        self.assertRegex(
            self.spec,
            r"row\.query_stat_bits\s*!=\s*0",
        )
        self.assertRegex(
            self.schema,
            r"row\.query_stat_bits\s*!=\s*0",
        )

    def test_successor_header_contains_complete_canonical_fields(self) -> None:
        required_fields = (
            "schema_version",
            "requested_ring_dim",
            "natural_ring_dim",
            "provisioned_ring_dim",
            "realized_ring_dim",
            "natural_depth",
            "provisioned_depth",
            "log_q_bits",
            "log2_q_over_t_bits",
            "plaintext_modulus",
            "num_limbs",
            "ordered_rns_moduli",
            "ordered_rns_limb_bits",
            "ordered_rns_limb_bits_sum",
            "scaling_mod_size",
            "openfhe_version",
            "flooding_assurance",
            "transcript_stat_bits",
            "max_queries",
            "query_stat_bits",
            "coefficient_stat_bits",
            "flood_margin_bits",
            "eval_noise_bits",
            "flood_noise_bits",
            "required_capacity_bits",
            "residual_capacity_definition",
            "residual_capacity_bits",
            "residual_capacity_status",
        )
        header = self.schema[self.schema.index("ThresholdSpecCSVHeader") :]
        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(field, header)

    def test_skipped_rows_are_not_populated_from_live_metadata(self) -> None:
        self.assertIn('row.status = "SKIPPED";', self.spec)
        self.assertIn("WriteThresholdSpecRow(std::cout, row);", self.spec)
        self.assertIn("const auto u32 = [skipped]", self.schema)
        self.assertIn('kThresholdSpecNotApplicable = "N/A"', self.schema)
        self.assertIn("IsThresholdSpecSkipped(const ThresholdSpecRow& row)", self.schema)


if __name__ == "__main__":
    unittest.main()
