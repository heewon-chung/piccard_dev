#!/usr/bin/env python3
"""Executable regression test: dynamic throughput probes must not corrupt
the signature-bearing BottomStructure.

`RunTimedDynamic` used to run its insert/delete throughput probes directly
on the same BottomStructure whose signature Phase 4 reads. The d-depth
bottom structure discards evicted originals permanently, so probing and
then undoing the probes can leave a hash function's row empty, aborting
the process. This test pins the fix: probes must run on a scratch copy so
the signature-bearing structure stays untouched.

Coverage limit: every invocation here is `--security=TOY`, and TOY forces
`RunTimedDynamic`'s probe batch down to `num_ops == 1` (bench_dynamic.cpp).
A single insert/delete round trip can never empty a depth-d row, so this
file structurally cannot exercise the 100-op paper batch or the rebuild
path it needs. That path is covered by the plaintext unit test
`tests/unit/test_dynamic_probe_workload.cpp` (ctest: DynamicProbeWorkload).
"""

import csv
import io
import subprocess
import sys
import unittest


BENCH_DYNAMIC = sys.argv[1] if len(sys.argv) > 1 else "bench_dynamic"


class BenchDynamicProbeIsolationTest(unittest.TestCase):
    def run_dynamic(self, set_size, k, m, depth, trials="1"):
        return subprocess.run(
            [BENCH_DYNAMIC, "--profile=toy-smoke", "--security=TOY",
             "--mode=timing", "--evidence_point", f"--k={k}", f"--m={m}",
             f"--set_size={set_size}", "--target-jaccard=0.5",
             f"--depth={depth}", f"--trials={trials}", "--seed=7"],
            capture_output=True, text=True)

    def test_small_sets_survive_probe_phases(self):
        for k, m, n in [(16, 16, 10), (16, 16, 100), (128, 64, 100)]:
            with self.subTest(k=k, m=m, n=n):
                completed = self.run_dynamic(n, k, m, depth=5)
                self.assertEqual(
                    completed.returncode, 0,
                    f"k={k} m={m} n={n}: exit {completed.returncode}, "
                    f"stderr={completed.stderr}")
                self.assertNotIn("Bottom structure empty", completed.stderr)
                rows = list(csv.DictReader(io.StringIO(completed.stdout)))
                self.assertEqual(len(rows), 1)

    def test_signature_matches_uncorrupted_reference(self):
        # The scratch probes must never alter the signature-bearing structure,
        # so changing its retained depth must not change jaccard_computed.
        pristine = self.run_dynamic(100, 128, 64, depth=105)
        self.assertEqual(pristine.returncode, 0, pristine.stderr)
        pristine_rows = list(csv.DictReader(io.StringIO(pristine.stdout)))
        self.assertEqual(len(pristine_rows), 1)
        self.assertEqual(pristine_rows[0]["depth"], "105")

        probed = self.run_dynamic(100, 128, 64, depth=5)
        self.assertEqual(probed.returncode, 0, probed.stderr)
        probed_rows = list(csv.DictReader(io.StringIO(probed.stdout)))
        self.assertEqual(len(probed_rows), 1)
        self.assertEqual(probed_rows[0]["depth"], "5")

        self.assertEqual(
            probed_rows[0]["jaccard_computed"],
            pristine_rows[0]["jaccard_computed"])

    def test_large_set_still_passes(self):
        completed = self.run_dynamic(1000, 128, 64, depth=5, trials="5")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rows = list(csv.DictReader(io.StringIO(completed.stdout)))
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
