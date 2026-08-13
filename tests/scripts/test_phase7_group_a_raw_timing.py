#!/usr/bin/env python3
"""Static contract checks for the Phase 7 Group A producer adapters.

The benchmark binaries are deliberately not executed by the Phase 7 gate.
These checks therefore pin the source-level integration seam shared by the
four producer families; the schema's independent literal tests cover the
runtime TSV validation and aggregate recomputation.
"""

from pathlib import Path
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[2]


class GroupARawTimingIntegrationTests(unittest.TestCase):
    PRODUCERS = {
        "bench_piccard.cpp": "bench_piccard",
        "bench_onehot_sqrt.cpp": "bench_onehot_sqrt",
        "bench_sqrt_comparison.cpp": "bench_sqrt_comparison",
        "bench_crossover.cpp": "bench_crossover",
    }

    def _source(self, filename: str) -> str:
        return (SOURCE_ROOT / "benchmarks" / filename).read_text(encoding="utf-8")

    def test_every_group_a_producer_has_the_versioned_sidecar_seam(self) -> None:
        for filename, producer_id in self.PRODUCERS.items():
            with self.subTest(filename=filename):
                source = self._source(filename)
                self.assertIn('#include "raw_timing_schema.h"', source)
                self.assertIn("WriteRawTimingArtifactsV1", source)
                self.assertIn("ExpectedTimingTrials", source)
                self.assertIn("SampleKind::Measured", source)
                self.assertIn("RawTimingSample", source)
                self.assertIn("--raw_timing_dir=", source)
                self.assertIn(producer_id, source)
                if producer_id == "bench_sqrt_comparison":
                    self.assertIn("WarmupPolicy::None", source)
                else:
                    self.assertIn("SampleKind::DiscardedWarmup", source)

    def test_sidecar_option_is_consistent_and_profile_gated(self) -> None:
        sources = [self._source(filename) for filename in self.PRODUCERS]
        for source in sources:
            self.assertIn('"--raw_timing_dir="', source)
            self.assertIn("readiness-toy-v1", source)
            self.assertTrue(
                "paper-v1" in source or "kPaperTimingProfileVersion" in source
            )
            self.assertIn("TimingContractFor", source)

        # Every adapter must derive/store a per-trial seed instead of leaving
        # the schema's seed field at its default value.
        self.assertTrue(any("TrialSeed(" in source for source in sources))
        self.assertTrue(any("config.seed" in source for source in sources))


if __name__ == "__main__":
    unittest.main()
