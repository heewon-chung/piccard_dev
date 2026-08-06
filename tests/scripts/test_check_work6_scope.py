import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / ("check_" + "work6_scope" + ".py")
DATA = ROOT / "scripts" / ("work6_" + "allowed_paths" + ".txt")
STATE = "thresh" + "old"
RATE = "fp" + "fn"
UPDATE = "ApplyCipher" + "textDe" + "lta"


class ScopeFixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run("git", "init", "-q")
        self.run("git", "config", "user.email", "scope@example.invalid")
        self.run("git", "config", "user.name", "Scope")

    def close(self):
        self.temp.cleanup()

    def run(self, *args, check=True):
        return subprocess.run(args, cwd=self.root, check=check,
                              capture_output=True, text=True)

    def write(self, name, data, binary=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")

    def commit(self, message):
        if not any(path.is_file() for path in self.root.rglob("*")
                   if ".git" not in path.parts):
            self.write(".keep", "base\n")
        self.run("git", "add", "-A")
        self.run("git", "commit", "-qm", message)
        return self.run("git", "rev-parse", "HEAD").stdout.strip()

    def check(self, base, allowed="", source=CHECKER):
        allowed_file = self.root / "paths.txt"
        allowed_file.write_text(allowed, encoding="utf-8")
        return self.run(sys.executable, str(source), f"--base={base}",
                        "--head=HEAD", f"--allowed-paths={allowed_file}",
                        check=False)


class CheckWork6Scope(unittest.TestCase):
    def setUp(self):
        self.repo = ScopeFixture()

    def tearDown(self):
        self.repo.close()

    def assert_pass(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def assert_fail(self, result, fragment=None):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("FAIL", result.stderr)
        if fragment:
            self.assertIn(fragment, result.stderr)

    def test_allowed_change_passes(self):
        self.repo.write("CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\n")
        base = self.repo.commit("base")
        self.repo.write("include/analysis/deletion_survival.h", "// added\n")
        self.repo.commit("candidate")
        self.assert_pass(self.repo.check(base, "include/analysis/deletion_survival.h\n"))

    def test_path_outside_whitelist_fails(self):
        base = self.repo.commit("base")
        self.repo.write("notes.txt", "x\n")
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, "a\n"), "notes.txt")

    def test_renames_check_both_paths(self):
        for old, new, allowed, good in [
            ("outside.txt", "include/x.h", "include/x.h\n", False),
            ("include/x.h", "outside.txt", "include/x.h\n", False),
            ("include/x.h", "include/y.h", "include/x.h\ninclude/y.h\n", True),
        ]:
            with self.subTest(old=old, new=new):
                self.repo.write(old, "x\n")
                base = self.repo.commit("base")
                (self.repo.root / new).parent.mkdir(parents=True, exist_ok=True)
                self.repo.run("git", "mv", old, new)
                self.repo.commit("move")
                result = self.repo.check(base, allowed)
                (self.assert_pass if good else self.assert_fail)(result)
                self.repo.close()
                self.repo = ScopeFixture()

    def test_forbidden_path_or_semantic_line_fails(self):
        bad_path = "tests/" + STATE + "_case.py"
        for family in ("include/x.h", "src/x.cpp", "benchmarks/x.cpp", "scripts/x.py", "tests/x.py"):
            with self.subTest(family=family):
                self.repo.write(family, "neutral\n")
                base = self.repo.commit("base")
                self.repo.write(family, "neutral " + STATE + " " + RATE + "\n")
                self.repo.commit("candidate")
                self.assert_fail(self.repo.check(base, family + "\n"))
                self.repo.close(); self.repo = ScopeFixture()
        self.repo.write(bad_path, "neutral\n")
        base = self.repo.commit("base")
        self.repo.write(bad_path, "changed\n")
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, bad_path + "\n"))

    def test_forbidden_update_api_fails(self):
        for path in ("src/x.cpp", "tests/x.py"):
            with self.subTest(path=path):
                self.repo.write(path, "plain\n")
                base = self.repo.commit("base")
                self.repo.write(path, UPDATE + "()\n")
                self.repo.commit("candidate")
                self.assert_fail(self.repo.check(base, path + "\n"))
                self.repo.close(); self.repo = ScopeFixture()

    def test_nul_source_is_forced_through_text_scan(self):
        path = "src/x.cpp"
        self.repo.write(path, b"plain\x00line\n", binary=True)
        base = self.repo.commit("base")
        self.repo.write(path, ("plain\x00" + UPDATE + "\n").encode(), binary=True)
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, path + "\n"))

    def test_bfv_preexisting_body_is_frozen(self):
        header = "include/fhe/bfv_context.h"
        source = "src/fhe/bfv_context.cpp"
        self.repo.write(header, "#pragma once\nclass BFVContext { public: void Old(); };\n")
        self.repo.write(source, '#include "fhe/bfv_context.h"\nnamespace piccard { void BFVContext::Old() { int x = 1; } }\n')
        base = self.repo.commit("base")
        self.repo.write(source, '#include "fhe/bfv_context.h"\nnamespace piccard { void BFVContext::Old() { int x = 2; } }\n')
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, header + "\n" + source + "\n"))

    def test_exact_bfv_codec_insertions_pass(self):
        header = "include/fhe/bfv_context.h"
        source = "src/fhe/bfv_context.cpp"
        self.repo.write(header, "#pragma once\n#include <vector>\nnamespace piccard {\nclass BFVContext { public: void Old();\n};\n}\n")
        self.repo.write(source, '#include "fhe/bfv_context.h"\n\n#include "build_info.h"\n#include "math/distributiongenerator.h"\n\nnamespace piccard {\n\nvoid BFVContext::Old() {}\n}\n')
        base = self.repo.commit("base")
        self.repo.write(header, "#pragma once\n#include <memory>\n#include <vector>\nnamespace piccard {\nclass PublicCiphertextCodec;\n\nclass BFVContext { public: void Old();\n    std::shared_ptr<const PublicCiphertextCodec>\n    ExportPublicCiphertextCodec() const;\n\n};\n}\n")
        names = ["AppendBE32", "AppendBE64", "Sha256Hex", "SecurityCode", "ContextFingerprintHex", "PublicKeyFingerprintHex"]
        defs = "\n\n".join("void " + name + "() {}" for name in names)
        self.repo.write(source, '#include "fhe/bfv_context.h"\n\n#include "fhe/public_ciphertext_codec.h"\n\n#include "build_info.h"\n#include "key/key-ser.h"\n#include "math/distributiongenerator.h"\n\n#include <openssl/evp.h>\n\nnamespace piccard {\n\n' + defs + '\n\nvoid BFVContext::ExportPublicCiphertextCodec() {}\n\nvoid BFVContext::Old() {}\n}\n')
        self.repo.commit("candidate")
        self.assert_pass(self.repo.check(base, header + "\n" + source + "\n"))

    def test_unsorted_or_traversing_whitelist_fails(self):
        base = self.repo.commit("base")
        self.repo.write("a", "x\n")
        self.repo.commit("candidate")
        for paths in ("b\na\n", "../escape\n"):
            with self.subTest(paths=paths):
                self.assert_fail(self.repo.check(base, paths))

    def test_path_data_uses_narrow_entry_validation(self):
        base = self.repo.commit("base")
        data_path = "scripts/" + "work6_" + "allowed_paths" + ".txt"
        self.repo.write(data_path, DATA.read_text(encoding="utf-8"))
        self.repo.commit("candidate")
        self.assert_pass(self.repo.check(base, data_path + "\n"))
        base = self.repo.run("git", "rev-parse", "HEAD").stdout.strip()
        lookalike = "scripts/run_pre_" + STATE + "_profiles.py"
        self.repo.write(data_path, lookalike + "\n")
        self.repo.commit("bad")
        self.assert_fail(self.repo.check(base, data_path + "\n"))

    def test_checker_and_tests_pass_their_own_candidate_diff(self):
        base = self.repo.commit("base")
        for original, target in ((CHECKER, "scripts/" + CHECKER.name),
                                 (Path(__file__), "tests/scripts/" + Path(__file__).name),
                                 (DATA, "scripts/" + DATA.name)):
            self.repo.write(target, original.read_text(encoding="utf-8"))
        self.repo.commit("candidate")
        allowed = "\n".join(sorted(["scripts/" + CHECKER.name,
                                      "scripts/" + DATA.name,
                                      "tests/scripts/" + Path(__file__).name])) + "\n"
        copied = self.repo.root / "scripts" / CHECKER.name
        self.assert_pass(self.repo.check(base, allowed, copied))


if __name__ == "__main__":
    unittest.main()
