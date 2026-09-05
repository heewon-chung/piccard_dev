#!/usr/bin/env python3
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts import dblp_trigram_stats as stats  # noqa: E402

RECORDS = (
    "record_id\traw_feature_count\traw_features_csv\tbucketed_feature_count\tbucketed_features_csv\n"
    "a\t3\t1,2,65537\t2\t1,2\n"          # 65537 % 65536 == 1 -> one collision, one feature lost
    "b\t2\t2,3\t2\t2,3\n"
    "c\t1\t70000\t1\t4464\n"
)


class ComputeTest(unittest.TestCase):
    def test_counts_distinct_features_and_collisions(self) -> None:
        result = stats.compute(RECORDS, 65536)
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["distinct_raw_features"], 5)        # {1,2,65537,3,70000}
        self.assertEqual(result["distinct_bucketed_features"], 4)   # {1,2,3,4464}
        self.assertAlmostEqual(result["log2_distinct_raw_features"], math.log2(5))
        self.assertEqual(result["raw_set_size"], {"min": 1, "median": 2.0, "p95": 3, "max": 3})
        self.assertEqual(result["bucketed_set_size"], {"min": 1, "median": 2.0, "p95": 2, "max": 2})
        self.assertEqual(result["records_with_bucket_collision"], 1)
        self.assertEqual(result["features_lost_to_bucket_collision"], 1)
        self.assertEqual(result["design_bound"]["trigrams"], 46656)

    def test_bucketed_column_must_equal_modulo_of_raw(self) -> None:
        bad = RECORDS.replace("c\t1\t70000\t1\t4464", "c\t1\t70000\t1\t4465")
        with self.assertRaises(stats.StatsError):
            stats.compute(bad, 65536)


if __name__ == "__main__":
    unittest.main()
