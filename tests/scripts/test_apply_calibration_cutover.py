import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ACTIVE = REPO / "include" / "util" / "noise_calibration.inc"
LEGACY = REPO / "include" / "util" / "noise_calibration_legacy_rows.inc"
WRAPPER = REPO / "scripts" / "templates" / "noise_calibration_wrapper.inc"
FIXTURE_ROWS = (
    REPO / "tests" / "fixtures" /
    "noise_calibration_pre_threshold_rows.inc"
)
PARAMS = REPO / "src" / "util" / "params.cpp"
CUTOVER = REPO / "scripts" / "apply_calibration_cutover.py"

ACTIVE_SHA256 = (
    "d3c8e052ee29ca04150030beb994b6b97d738643a943e05de53a2943cfb13462"
)
LEGACY_SHA256 = (
    "8f54b7c23afe8fb1b0ecb5dca125318636d65c3ae0c78af005408d98accc42e3"
)


class CalibrationStagingArtifactTest(unittest.TestCase):
    def test_active_table_remains_frozen(self):
        self.assertEqual(
            hashlib.sha256(ACTIVE.read_bytes()).hexdigest(), ACTIVE_SHA256)

    def test_legacy_rows_are_exact_byte_preserving_extraction(self):
        expected = b"".join(
            line
            for line in ACTIVE.read_bytes().splitlines(keepends=True)
            if line.lstrip().startswith(b"{Circuit::")
            and (
                b"SecurityLevel::TOY" in line
                or b"Circuit::Threshold" in line
            )
        )
        self.assertEqual(expected.count(b"\n"), 303)
        self.assertEqual(LEGACY.read_bytes(), expected)
        self.assertEqual(
            hashlib.sha256(LEGACY.read_bytes()).hexdigest(), LEGACY_SHA256)

    def test_wrapper_has_typed_v2_split_without_zero_sentinels(self):
        text = WRAPPER.read_text()
        self.assertIn("#define PICCARD_PRE_THRESHOLD_CALIBRATION_V2 1", text)
        self.assertIn("std::optional<double>", text)
        self.assertIn("std::optional<uint64_t>", text)
        self.assertIn("ForEachNoiseCalibrationCandidate", text)
        self.assertNotRegex(text, r"nullopt\\s*\\?\\s*0")

    def test_fixture_expanded_rows_have_only_std_pre_threshold_roles(self):
        text = FIXTURE_ROWS.read_text()
        rows = [
            line for line in text.splitlines()
            if line.lstrip().startswith("{{")
        ]
        self.assertEqual(len(rows), 33)
        for row in rows:
            self.assertRegex(row, r"Circuit::(OneHot|Sqrt)")
            self.assertRegex(row, r"SecurityLevel::STD(128|192)")
            self.assertNotIn("Circuit::Threshold", row)
            self.assertNotIn("SecurityLevel::TOY", row)

    def test_params_keeps_current_include_and_has_conditional_adapter(self):
        text = PARAMS.read_text()
        self.assertIn(
            '#define PICCARD_NOISE_CALIBRATION_FILE '
            '"util/noise_calibration.inc"',
            text,
        )
        self.assertRegex(
            text,
            re.compile(
                r"#ifdef PICCARD_PRE_THRESHOLD_CALIBRATION_V2.*"
                r"ForEachNoiseCalibrationCandidate",
                re.DOTALL,
            ),
        )

    def test_current_and_v2_probe_targets_compile_and_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            configured = subprocess.run(
                [
                    "cmake", "-S", str(REPO), "-B", str(build),
                    "-DCMAKE_BUILD_TYPE=Release",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(configured.returncode, 0, configured.stderr)
            compiled = subprocess.run(
                [
                    "cmake", "--build", str(build), "-j4", "--target",
                    "noise_calibration_cutover_probe_current",
                    "noise_calibration_cutover_probe_v2",
                    "bench_noise",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            for target in (
                "noise_calibration_cutover_probe_current",
                "noise_calibration_cutover_probe_v2",
            ):
                result = subprocess.run(
                    [str(build / target)],
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            coverage = subprocess.run(
                [str(build / "bench_noise"), "--coverage", "--pre_threshold"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(coverage.returncode, 0, coverage.stderr)
            self.assertIn("V2 table coverage inactive", coverage.stdout)

    def test_current_probe_rejects_same_count_wrong_legacy_key_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mutated = root / "mutated-active.inc"
            before = (
                b"Circuit::Sqrt, SecurityLevel::TOY, 32768, 3")
            after = (
                b"Circuit::Sqrt, SecurityLevel::TOY, 262144, 3")
            original = ACTIVE.read_bytes()
            self.assertEqual(original.count(before), 8)
            mutated.write_bytes(original.replace(before, after))
            executable = root / "probe"
            result = subprocess.run(
                [
                    os.environ.get("CXX", "c++"),
                    "-std=c++17", "-O0",
                    "-I" + str(REPO / "include"),
                    "-I" + str(REPO),
                    "-DPICCARD_NOISE_CALIBRATION_FILE="
                    f'"{mutated}"',
                    str(REPO / "src" / "util" / "params.cpp"),
                    str(REPO / "src" / "util" / "params_calibration.cpp"),
                    str(REPO / "src" / "util" / "security_profile.cpp"),
                    str(REPO / "tests" / "fixtures" /
                        "noise_calibration_cutover_probe.cpp"),
                    "-o", str(executable),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            probe = subprocess.run(
                [str(executable)], text=True, capture_output=True)
            self.assertNotEqual(probe.returncode, 0)
            self.assertIn("legacy selection-key", probe.stderr)


class AtomicCalibrationCutoverTest(unittest.TestCase):
    def make_inputs(self, root):
        wrapper = root / "wrapper.inc"
        legacy = root / "legacy.inc"
        expanded = root / "expanded.inc"
        wrapper.write_bytes(WRAPPER.read_bytes())
        legacy.write_bytes(LEGACY.read_bytes())
        expanded.write_bytes(FIXTURE_ROWS.read_bytes())
        destination = root / "destination.inc"
        destination.write_bytes(b"prior destination bytes\n")
        return wrapper, legacy, expanded, destination

    def run_cutover(
        self, wrapper, legacy, expanded, destination, env=None
    ):
        return subprocess.run(
            [
                "python3", str(CUTOVER),
                f"--staged-wrapper={wrapper}",
                f"--legacy-rows={legacy}",
                f"--pre-threshold-rows={expanded}",
                f"--dest={destination}",
            ],
            cwd=REPO,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def feasibility_std128_row(self, expanded):
        return next(
            line for line in expanded.read_text().splitlines()
            if line.startswith('    {{"feasibility128"')
            and "SecurityLevel::STD128" in line
        )

    def feasibility_std192_row(self, std128_row):
        row = std128_row.replace(
            "SecurityLevel::STD128, 8192, 1",
            "SecurityLevel::STD192, 16384, 1",
        ).replace(
            "}, 8192, 8192,",
            "}, 16384, 16384,",
        )
        return row.replace(", 161, 8, 209},", ", 162, 8, 210},")

    def test_valid_cutover_atomically_copies_only_the_wrapper(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self.make_inputs(Path(temporary))
            result = self.run_cutover(*inputs)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(inputs[-1].read_bytes(), WRAPPER.read_bytes())
            self.assertEqual(
                hashlib.sha256(ACTIVE.read_bytes()).hexdigest(),
                ACTIVE_SHA256,
            )

    def test_cutover_accepts_real_outcomes_and_approved_ring_growth(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self.make_inputs(Path(temporary))
            expanded = inputs[2]
            text = expanded.read_text()
            std128 = self.feasibility_std128_row(expanded)
            grown128 = std128.replace(
                "}, 8192, 8192,", "}, 8192, 16384,"
            ).replace(", 161, 8, 209},", ", 162, 8, 210},")
            grown192 = self.feasibility_std192_row(std128).replace(
                "}, 16384, 16384,", "}, 16384, 65536,"
            ).replace(
                ", 65537, 300.0, 283.9999779863886,",
                ", 786433, 300.0, 280.4150356647984,",
            ).replace(", 162, 8, 210},", ", 164, 8, 212},")
            expanded.write_text(
                text.replace(std128, grown128) + grown192 + "\n")
            result = self.run_cutover(*inputs)
            self.assertEqual(result.returncode, 0, result.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            inputs = self.make_inputs(Path(temporary))
            expanded = inputs[2]
            std128 = self.feasibility_std128_row(expanded)
            expanded.write_text(
                expanded.read_text().replace(std128 + "\n", ""))
            result = self.run_cutover(*inputs)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_duplicate_expanded_row_is_rejected(self):
        for distinct_bytes in (False, True):
            with self.subTest(distinct_bytes=distinct_bytes):
                with tempfile.TemporaryDirectory() as temporary:
                    inputs = self.make_inputs(Path(temporary))
                    row = self.feasibility_std128_row(inputs[2])
                    if distinct_bytes:
                        row = row.replace(", 12288, 128,", ", 12289, 128,")
                    inputs[2].write_text(inputs[2].read_text() + row + "\n")
                    prior = inputs[-1].read_bytes()
                    result = self.run_cutover(*inputs)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("duplicate", result.stderr.lower())
                    self.assertEqual(inputs[-1].read_bytes(), prior)

    def test_altered_wrapper_or_legacy_preserves_prior_destination(self):
        mutators = (
            (
                lambda wrapper, legacy, expanded: wrapper.write_bytes(
                    wrapper.read_bytes() + b" "),
                "wrapper hash",
            ),
            (
                lambda wrapper, legacy, expanded: legacy.write_bytes(
                    legacy.read_bytes().replace(b"1024", b"2048", 1)),
                "legacy hash",
            ),
        )
        for mutate, reason in mutators:
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as temporary:
                    inputs = self.make_inputs(Path(temporary))
                    prior = hashlib.sha256(inputs[-1].read_bytes()).hexdigest()
                    mutate(*inputs[:3])
                    result = self.run_cutover(*inputs)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(reason, result.stderr)
                    self.assertEqual(
                        hashlib.sha256(inputs[-1].read_bytes()).hexdigest(),
                        prior,
                    )

    def test_malformed_role_or_stale_openfhe_preserves_destination(self):
        mutators = (
            (
                lambda wrapper, legacy, expanded: expanded.write_bytes(
                    expanded.read_bytes()
                    + b"{Circuit::Threshold, SecurityLevel::TOY, 1},\n"),
                "expanded fragment role",
            ),
            (
                lambda wrapper, legacy, expanded: expanded.write_bytes(
                    expanded.read_bytes().replace(b'"1.5.0"', b'"1.4.2"', 1)),
                "OpenFHE",
            ),
            (
                lambda wrapper, legacy, expanded: expanded.write_bytes(
                    expanded.read_bytes() + b'#include "evil.inc"\n'),
                "expanded fragment role",
            ),
        )
        for mutate, reason in mutators:
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as temporary:
                    inputs = self.make_inputs(Path(temporary))
                    prior = inputs[-1].read_bytes()
                    mutate(*inputs[:3])
                    result = self.run_cutover(*inputs)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(reason, result.stderr)
                    self.assertEqual(inputs[-1].read_bytes(), prior)

    def test_compile_failure_preserves_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self.make_inputs(Path(temporary))
            prior = inputs[-1].read_bytes()
            env = os.environ.copy()
            env["CXX"] = "/usr/bin/false"
            result = self.run_cutover(*inputs, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("compile", result.stderr)
            self.assertEqual(inputs[-1].read_bytes(), prior)

    def test_probe_runtime_regression_preserves_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self.make_inputs(root)
            prior = inputs[-1].read_bytes()
            fake_cxx = root / "fake-cxx"
            fake_cxx.write_text(
                "#!/bin/sh\n"
                "out=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = -o ]; then shift; out=$1; fi\n"
                "  shift\n"
                "done\n"
                "printf '#!/bin/sh\\nexit 1\\n' >\"$out\"\n"
                "chmod +x \"$out\"\n"
            )
            fake_cxx.chmod(0o755)
            env = os.environ.copy()
            env["CXX"] = str(fake_cxx)
            result = self.run_cutover(*inputs, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("probe", result.stderr)
            self.assertEqual(inputs[-1].read_bytes(), prior)

    def test_preexisting_cutover_temp_collision_is_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self.make_inputs(Path(temporary))
            prior = inputs[-1].read_bytes()
            collision = inputs[-1].with_name(
                "." + inputs[-1].name + ".piccard-cutover-v1.tmp")
            collision.write_bytes(b"unowned collision\n")
            result = self.run_cutover(*inputs)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("collision", result.stderr)
            self.assertEqual(inputs[-1].read_bytes(), prior)
            self.assertEqual(collision.read_bytes(), b"unowned collision\n")


if __name__ == "__main__":
    unittest.main()
