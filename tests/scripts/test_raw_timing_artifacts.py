"""Static and literal checks for Phase 7 raw timing producer contracts.

This test deliberately does not import the C++ serializer or execute a
benchmark.  It reads the checked-in producer sources, checks that every named
timing family is wired to the versioned raw API, and recomputes the frozen
aggregate formula from literal values independently of the production helper.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[2]
BENCHMARKS = SOURCE / "benchmarks"

PRODUCER_SOURCES = {
    "bench_piccard": "bench_piccard.cpp",
    "bench_onehot_sqrt": "bench_onehot_sqrt.cpp",
    "bench_sqrt_comparison": "bench_sqrt_comparison.cpp",
    "bench_crossover": "bench_crossover.cpp",
    "bench_dynamic": "bench_dynamic.cpp",
    "bench_threshold": "bench_threshold.cpp",
    "bench_review_comparison": "bench_review_comparison.cpp",
    "bench_fhe_ind": "bench_fhe_ind.cpp",
    "bench_sj16_calibrate": "bench_sj16_calibrate.cpp",
    "real_timing": "real_timing_driver.cpp",
    "dynamic_refresh": "dynamic_refresh_benchmark.cpp",
}

# The refresh helper is intentionally separated from the executable's CLI;
# include its owning writer when checking the complete source-level seam.
PRODUCER_INTEGRATION_SOURCES = {
    "dynamic_refresh": ("bench_dynamic.cpp",),
}

PHASES = (
    "phase_minhash_ms",
    "phase_encode_ms",
    "phase_encrypt_ms",
    "phase_cloud_multiply_ms",
    "phase_cloud_rotate_ms",
    "phase_sanitize_ms",
    "phase_decrypt_ms",
    "phase_bias_correction_ms",
)


def independent_aggregate(values: list[float]) -> dict[str, float | None]:
    """Recompute the schema's mean/SD/median/95% interval without C++ code."""

    ordered = sorted(values)
    count = len(ordered)
    mean = sum(ordered) / count
    median = (
        ordered[count // 2]
        if count % 2
        else (ordered[count // 2 - 1] + ordered[count // 2]) / 2.0
    )
    if count == 1:
        return {
            "mean": mean,
            "sample_sd": None,
            "median": median,
            "ci95_low": None,
            "ci95_high": None,
        }
    sample_sd = math.sqrt(sum((value - mean) ** 2 for value in values) / (count - 1))
    # Frozen two-sided 95% Student-t value for N=30 (df=29).
    t95 = 2.045229642132703
    margin = t95 * sample_sd / math.sqrt(count)
    return {
        "mean": mean,
        "sample_sd": sample_sd,
        "median": median,
        "ci95_low": mean - margin,
        "ci95_high": mean + margin,
    }


class RawTimingArtifactsTest(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (SOURCE / relative).read_text(encoding="utf-8")

    def test_literal_aggregate_formula_and_n_one_sentinel(self):
        paper = independent_aggregate([float(value) for value in range(1, 31)])
        self.assertEqual(paper["mean"], 15.5)
        self.assertEqual(paper["median"], 15.5)
        self.assertAlmostEqual(paper["sample_sd"], math.sqrt(77.5), places=14)
        self.assertLess(paper["ci95_low"], paper["mean"])
        self.assertGreater(paper["ci95_high"], paper["mean"])

        toy = independent_aggregate([3.25])
        self.assertEqual(toy["mean"], 3.25)
        self.assertEqual(toy["median"], 3.25)
        self.assertIsNone(toy["sample_sd"])
        self.assertIsNone(toy["ci95_low"])
        self.assertIsNone(toy["ci95_high"])

    def test_common_contract_freezes_all_producers_and_noise_exemption(self):
        schema = self.read("benchmarks/raw_timing_schema.cpp")
        header = self.read("benchmarks/raw_timing_schema.h")
        for producer in PRODUCER_SOURCES:
            self.assertIn(f'{{"{producer}"', schema, producer)
        for producer in PRODUCER_SOURCES:
            contract = re.search(
                rf'\{{"{re.escape(producer)}",\s*(\d+),\s*(\d+),\s*'
                r'WarmupPolicy::(None|DiscardOne)',
                schema,
            )
            self.assertIsNotNone(contract, producer)
            self.assertEqual(contract.group(1), "30", producer)
            self.assertEqual(contract.group(2), "1", producer)
        self.assertIn('"NOT_APPLICABLE"', header)
        self.assertIn("contract == nullptr ? kTimingNotApplicable", schema)
        # There must be no accidental paper-timing contract for the noise
        # calibration executable; its generic lookup therefore resolves to
        # NOT_APPLICABLE without requiring any bench_noise source change.
        self.assertNotIn('"bench_noise"', schema)
        noise = self.read("benchmarks/bench_noise.cpp")
        # Noise is calibration evidence, not a raw timing producer.  The
        # exemption is verified by the common contract lookup; bench_noise is
        # intentionally left untouched and does not include the raw API.
        self.assertNotIn("raw_timing_schema.h", noise)

    def test_each_named_producer_is_wired_to_raw_api(self):
        for producer, filename in PRODUCER_SOURCES.items():
            source = (BENCHMARKS / filename).read_text(encoding="utf-8")
            sibling_header = BENCHMARKS / filename.replace(".cpp", ".h")
            if sibling_header.exists():
                source += "\n" + sibling_header.read_text(encoding="utf-8")
            for extra_filename in PRODUCER_INTEGRATION_SOURCES.get(producer, ()):
                source += "\n" + (BENCHMARKS / extra_filename).read_text(
                    encoding="utf-8"
                )
            self.assertIn("raw_timing_schema.h", source, producer)
            self.assertIn("RawTimingArtifact", source, producer)
            # The no-overwrite writer owns canonical serialization; a producer
            # may call it directly or stage an explicit serializer call first.
            self.assertTrue(
                "SerializeRawTimingArtifactV1" in source
                or "WriteRawTimingArtifactV1" in source
                or "WriteRawTimingArtifactsV1" in source,
                producer,
            )

    def test_real_timing_has_aligned_phases_warmup_profiles_and_seed(self):
        source = self.read("benchmarks/real_timing_driver.cpp")
        header = self.read("benchmarks/real_timing_driver.h")
        for phase in PHASES:
            self.assertIn(phase, source, phase)
        self.assertIn("DiscardedWarmup", source)
        self.assertIn("SampleKind::Measured", source)
        self.assertIn("hash_seed", source)
        self.assertIn("readiness-toy-v1", source)
        self.assertIn("paper-std128-t40-v1", source)
        self.assertIn("expected_measured", source)
        self.assertIn("raw_timing", header)
        # Work 5 remains the legacy CSV/workload path; the raw artifact is an
        # additional sidecar rather than a replacement serializer.
        self.assertIn("RealTimingHeader()", source)
        self.assertIn("AtomicWriteFile(fs::path(args.csv_path)", source)


if __name__ == "__main__":
    unittest.main()
