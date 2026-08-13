#!/usr/bin/env python3
"""Static/literal contract checks for the Phase 7 Group C producers.

This test deliberately does not execute a benchmark.  The producer binaries
are crypto/timing programs, so this gate checks the source contract and leaves
runtime evidence to the Phase 7 runner.
"""

from pathlib import Path
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[2]


class Phase7GroupCProducerContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.review = (SOURCE_ROOT / "benchmarks/bench_review_comparison.cpp").read_text()
        cls.fhe_ind = (SOURCE_ROOT / "benchmarks/bench_fhe_ind.cpp").read_text()
        cls.sj16 = (SOURCE_ROOT / "benchmarks/bench_sj16_calibrate.cpp").read_text()

    def test_all_owned_producers_use_versioned_raw_schema(self):
        for source in (self.review, self.fhe_ind, self.sj16):
            self.assertIn('"raw_timing_schema.h"', source)
            self.assertIn("RawTimingArtifact", source)
            self.assertIn("RawTimingSample", source)
            self.assertIn("WriteRawTiming", source)
            self.assertIn("readiness-toy-v1", source)
            self.assertIn("paper-v1", source)

    def test_raw_output_is_opt_in_and_trace_stays_separate(self):
        self.assertIn("raw-timing-out", self.review)
        self.assertIn("raw_timing_dir", self.review)
        self.assertIn("raw-timing-out", self.fhe_ind)
        self.assertIn("raw_timing_dir", self.fhe_ind)
        self.assertIn("raw-timing-out", self.sj16)
        self.assertIn("raw_timing_dir", self.sj16)
        self.assertIn("execution_trace_out", self.review)
        self.assertIn("execution_trace_out", self.review)
        self.assertIn("WriteRawTimingArtifactsV1", self.review)
        self.assertIn("WriteRawTimingArtifactV1", self.fhe_ind)
        self.assertIn("WriteRawTimingArtifactsV1", self.sj16)

    def test_fhe_ind_raw_artifact_has_setup_online_and_e2e_phases(self):
        for phase in (
            '"setup_context"',
            '"setup_keygen"',
            '"encode"',
            '"encrypt"',
            '"evaluate"',
            '"decrypt"',
            '"online_e2e"',
            '"full_e2e"',
        ):
            self.assertIn(phase, self.fhe_ind)

    def test_sj16_raw_artifact_has_query_and_encryption_phases(self):
        self.assertIn('"query"', self.sj16)
        self.assertIn('"encrypt"', self.sj16)
        self.assertIn("expected_measured", self.sj16)
        self.assertIn("sample_kind", self.sj16)
        self.assertIn("DiscardedWarmup", self.sj16)

    def test_warmup_policy_literals_are_bound_to_producer_contracts(self):
        self.assertIn("WarmupPolicy::DiscardOne", self.review)
        self.assertIn("WarmupPolicy::None", self.fhe_ind)
        self.assertIn("WarmupPolicy::DiscardOne", self.sj16)
        for source in (self.review, self.fhe_ind, self.sj16):
            self.assertIn("ExpectedTimingTrials", source)
            self.assertIn("ComputeTimingAggregateV1", source)

    def test_work5_cli_and_default_artifacts_remain_present(self):
        # These strings are the immutable Work 5 paths/CLI contract.  The new
        # sidecar option must not replace the legacy output or trace path.
        self.assertIn("manifest-out", self.review)
        self.assertIn("execution-trace-out", self.review)
        self.assertIn("E2eCsv", self.fhe_ind)
        self.assertIn("results/sj16_calibration_", self.sj16)


if __name__ == "__main__":
    unittest.main()
