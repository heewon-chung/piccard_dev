import os
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
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
        allowed_file = self.root.parent / "paths.txt"
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
        self.assertEqual(result.stdout, "check_work6_scope: PASS\n")
        self.assertEqual(result.stderr, "")

    def assert_fail(self, result, reason):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "check_work6_scope: FAIL: " + reason + "\n")

    def production_bfv_case(self, mutate):
        header = "include/fhe/bfv_context.h"
        source = "src/fhe/bfv_context.cpp"
        base_header = subprocess.check_output(["git", "show", "b09d008:" + header], cwd=ROOT, text=True)
        base_source = subprocess.check_output(["git", "show", "b09d008:" + source], cwd=ROOT, text=True)
        candidate_header = subprocess.check_output(["git", "show", "HEAD:" + header], cwd=ROOT, text=True)
        candidate_source = subprocess.check_output(["git", "show", "HEAD:" + source], cwd=ROOT, text=True)
        self.repo.write(header, base_header); self.repo.write(source, base_source)
        base = self.repo.commit("base")
        candidate_header, candidate_source = mutate(candidate_header, candidate_source)
        self.repo.write(header, candidate_header); self.repo.write(source, candidate_source)
        self.repo.commit("candidate")
        return self.repo.check(base, header + "\n" + source + "\n"), header, source

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
        self.assert_fail(self.repo.check(base, "a\n"), "path outside whitelist: notes.txt")

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
                if good: self.assert_pass(result)
                else: self.assert_fail(result, "path outside whitelist: " + (old if old.startswith("outside") else new))
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
                self.assert_fail(self.repo.check(base, family + "\n"), family + " contains excluded content")
                self.repo.close(); self.repo = ScopeFixture()
        self.repo.write(bad_path, "neutral\n")
        base = self.repo.commit("base")
        self.repo.write(bad_path, "changed\n")
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, bad_path + "\n"), "path has excluded name: " + bad_path)

    def test_forbidden_update_api_fails(self):
        for path in ("src/x.cpp", "tests/x.py"):
            with self.subTest(path=path):
                self.repo.write(path, "plain\n")
                base = self.repo.commit("base")
                self.repo.write(path, UPDATE + "()\n")
                self.repo.commit("candidate")
                self.assert_fail(self.repo.check(base, path + "\n"), path + " contains excluded content")
                self.repo.close(); self.repo = ScopeFixture()

    def test_semantic_alternatives_cover_families_and_directions(self):
        state_parts = [STATE, RATE, "false" + "Positive", "false" + "Negative",
                       "decision" + "Boundary"]
        update_parts = ["cipher" + "text" + "Delta", "delta" + "Cipher" + "text",
                        "Apply" + "Delta", "incremental" + "Cipher" + "text"]
        families = ["CMakeLists.txt", "include/x.h", "src/x.cpp", "benchmarks/x.cpp",
                    "scripts/x.py", "tests/x.py"]
        for family in families:
            for marker in state_parts + update_parts:
                for old, new in (("plain\n", marker + "\n"), (marker + "\n", "plain\n")):
                    with self.subTest(family=family, direction=(old == "plain\n")):
                        self.repo.write(family, old)
                        base = self.repo.commit("base")
                        self.repo.write(family, new)
                        self.repo.commit("candidate")
                        self.assert_fail(self.repo.check(base, family + "\n"), family + " contains excluded content")
                        self.repo.close(); self.repo = ScopeFixture()

    def test_nul_source_is_forced_through_text_scan(self):
        path = "src/x.cpp"
        for old, new in ((b"plain\x00line\n", ("plain\x00" + UPDATE + "\n").encode()),
                         (("plain\x00" + UPDATE + "\n").encode(), b"plain\x00line\n")):
            with self.subTest(direction=old == b"plain\x00line\n"):
                self.repo.write(path, old, binary=True)
                base = self.repo.commit("base")
                self.repo.write(path, new, binary=True)
                self.repo.commit("candidate")
                self.assert_fail(self.repo.check(base, path + "\n"), path + " contains excluded content")
                self.repo.close(); self.repo = ScopeFixture()

    def test_patch_content_prefixes_are_not_headers(self):
        path = "src/x.cpp"
        for sign, first, second in (("plus", "plain\n", "++" + STATE + "\n"),
                                    ("minus", "--" + STATE + "\n", "plain\n")):
            with self.subTest(sign=sign):
                self.repo.write(path, first)
                base = self.repo.commit("base")
                self.repo.write(path, second)
                self.repo.commit("candidate")
                result = self.repo.check(base, path + "\n")
                self.assert_fail(result, path + " contains excluded content")
                self.repo.close(); self.repo = ScopeFixture()

    def test_patch_prefixes_in_added_and_deleted_files(self):
        path = "scripts/x.py"
        base = self.repo.commit("base")
        self.repo.write(path, "++" + STATE + "\n")
        self.repo.commit("added")
        self.assert_fail(self.repo.check(base, path + "\n"), path + " contains excluded content")
        self.repo.close(); self.repo = ScopeFixture()
        self.repo.write("stable.txt", "stable\n")
        self.repo.write(path, "--" + STATE + "\n")
        base = self.repo.commit("base")
        (self.repo.root / path).unlink()
        self.repo.commit("deleted")
        self.assert_fail(self.repo.check(base, path + "\n"), path + " contains excluded content")

    def test_bfv_preexisting_body_is_frozen(self):
        header = "include/fhe/bfv_context.h"
        source = "src/fhe/bfv_context.cpp"
        self.repo.write(header, "#pragma once\nclass BFVContext { public: void Old(); };\n")
        self.repo.write(source, '#include "fhe/bfv_context.h"\nnamespace piccard { void BFVContext::Old() { int x = 1; } }\n')
        base = self.repo.commit("base")
        self.repo.write(source, '#include "fhe/bfv_context.h"\nnamespace piccard { void BFVContext::Old() { int x = 2; } }\n')
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, header + "\n" + source + "\n"), "missing unique anonymous namespace")

    def test_bfv_production_shaped_mutations_fail_after_subtraction(self):
        export_decl = "    std::shared_ptr<const PublicCiphertextCodec>\n    ExportPublicCiphertextCodec() const;\n"
        # The current candidate header contains later approved BFV additions.
        # Header-first subtraction therefore rejects every production-shaped
        # mutation before the source-specific mutation can be inspected.
        header_reason = "include/fhe/bfv_context.h changes preexisting content"
        def move_helper(source, destination):
            start = source.index("void AppendBE32")
            end = source.index("\n}\n\n", start) + 3
            helper = source[start:end]
            source = source[:start] + source[end:]
            return destination(source, helper)

        def move_export_after_close(header):
            header = header.replace(export_decl, "", 1)
            return header.replace("};\n\n} // namespace piccard", "};\n" + export_decl + "\n} // namespace piccard", 1)

        def move_export_nested(header):
            header = header.replace(export_decl, "", 1)
            return header.replace("void Initialize();", "void Initialize() {\n" + export_decl + "}", 1)

        cases = [
            ("condition", lambda h, s: (h, s.replace("top_bits < 32", "top_bits <= 32", 1)), header_reason),
            ("body", lambda h, s: (h, s.replace("BFVContext::CalibrationRingDiagnostics() const {", "BFVContext::CalibrationRingDiagnostics() const { int injected = 0;", 1)), header_reason),
            ("header", lambda h, s: (h.replace("Decrypt(", "DecryptChanged(", 1), s), header_reason),
            ("private", lambda h, s: (h.replace("public:\n    explicit BFVContext", "private:\n    explicit BFVContext", 1), s), "codec export is not public"),
            ("comment_prefix", lambda h, s: (h, s.replace("void AppendBE32", "// prefix\nvoid AppendBE32", 1)), header_reason),
            ("forward_wrong_namespace", lambda h, s: (h.replace("class PublicCiphertextCodec;", "namespace wrong { class PublicCiphertextCodec; }", 1), s), "codec forward declaration has wrong scope"),
            ("protected", lambda h, s: (h.replace("public:\n    explicit BFVContext", "protected:\n    explicit BFVContext", 1), s), "codec export is not public"),
            ("export_after_close", lambda h, s: (move_export_after_close(h), s), "codec export is not a class member"),
            ("export_nested", lambda h, s: (move_export_nested(h), s), "codec export is not a class member"),
            ("include_comment", lambda h, s: (h, s.replace('#include "fhe/public_ciphertext_codec.h"', '// #include "fhe/public_ciphertext_codec.h"\n#include "fhe/public_ciphertext_codec.h"', 1)), header_reason),
            ("include_string", lambda h, s: (h, s + '\nconst char* text = "#include \\"fhe/public_ciphertext_codec.h\\"";\n'), header_reason),
            ("helper_string", lambda h, s: (h, s + '\nconst char* text = "void AppendBE32";\n'), header_reason),
            ("helper_comment_decoy", lambda h, s: (h, s + "\n// void AppendBE32(std::vector<uint8_t>& bytes, uint32_t value) { }\n"), header_reason),
            ("helper_char", lambda h, s: (h, s + "\nchar escaped = '\\\\'; char brace = '}';\n"), header_reason),
            ("helper_nested", lambda h, s: (h, s + "\nnamespace nested { void AppendBE32(std::vector<uint8_t>& bytes, uint32_t value) {} }\n"), header_reason),
            ("helper_moved_body", lambda h, s: (h, move_helper(s, lambda text, helper: text.replace("BFVContext::CalibrationRingDiagnostics() const {", "BFVContext::CalibrationRingDiagnostics() const {\n" + helper, 1))), header_reason),
            ("helper_moved_namespace", lambda h, s: (h, move_helper(s, lambda text, helper: text + "\nnamespace nested {\n" + helper + "\n}\n")), header_reason),
            ("attribute_prefix", lambda h, s: (h, s.replace("void AppendBE32", "[[maybe_unused]]\nvoid AppendBE32", 1)), header_reason),
            ("define_prefix", lambda h, s: (h, s.replace("void AppendBE32", "#define LOCAL 1\nvoid AppendBE32", 1)), header_reason),
            ("duplicate", lambda h, s: (h, s + "\nvoid AppendBE32(std::vector<uint8_t>& bytes, uint32_t value) {}\n"), header_reason),
            ("brace_comment", lambda h, s: (h, s + "\n// { }\n"), header_reason),
            ("brace_string", lambda h, s: (h, s + '\nconst char* braces = "{ }";\n'), header_reason),
            ("escaped_brace", lambda h, s: (h, s + "\nchar brace = '\\}';\n"), header_reason),
        ]
        for name, mutate, reason in cases:
            with self.subTest(name=name):
                result, _, _ = self.production_bfv_case(mutate)
                self.assert_fail(result, reason)
                self.repo.close(); self.repo = ScopeFixture()

    def test_exact_bfv_codec_insertions_pass(self):
        header = "include/fhe/bfv_context.h"
        source = "src/fhe/bfv_context.cpp"
        self.repo.write(header, "#pragma once\n#include <vector>\nnamespace piccard {\nclass BFVContext { public: void Old();\n};\n}\n")
        self.repo.write(source, '#include "fhe/bfv_context.h"\n\n#include "build_info.h"\n#include "math/distributiongenerator.h"\n\nnamespace piccard {\n\nnamespace {\n\nvoid Keep() {}\n\n} // namespace\n\nvoid BFVContext::Old() {}\n}\n')
        base = self.repo.commit("base")
        self.repo.write(header, "#pragma once\n#include <memory>\n#include <vector>\nnamespace piccard {\nclass PublicCiphertextCodec;\n\nclass BFVContext { public: void Old();\n    std::shared_ptr<const PublicCiphertextCodec>\n    ExportPublicCiphertextCodec() const;\n\n};\n}\n")
        defs = "\n\n".join([
            "void AppendBE32(std::vector<uint8_t>& bytes, uint32_t value) {}",
            "void AppendBE64(std::vector<uint8_t>& bytes, uint64_t value) {}",
            "std::string Sha256Hex(const std::vector<uint8_t>& bytes) {}",
            "std::string ContextFingerprintHex(const BFVContext& context) {}",
            "std::string PublicKeyFingerprintHex(\n    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& public_key) {}",
        ])
        self.repo.write(source, '#include "fhe/bfv_context.h"\n\n#include "fhe/public_ciphertext_codec.h"\n\n#include "build_info.h"\n#include "key/key-ser.h"\n#include "math/distributiongenerator.h"\n\n#include <openssl/evp.h>\n\nnamespace piccard {\n\nnamespace {\n\n' + defs + '\n\nvoid Keep() {}\n\n} // namespace\n\nstd::shared_ptr<const PublicCiphertextCodec>\nBFVContext::ExportPublicCiphertextCodec() const {}\n\nvoid BFVContext::Old() {}\n}\n')
        self.repo.commit("candidate")
        self.assert_pass(self.repo.check(base, header + "\n" + source + "\n"))

    def test_fail_closed_pure_inputs(self):
        spec = importlib.util.spec_from_file_location("scope_checker", CHECKER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for data in (b"a", b"a\x00\x00"):
            with self.subTest(data=data):
                with self.assertRaises(module.ScopeError): module._paths(data)
        with self.assertRaises(module.ScopeError): module._text(b"\xff", "x")
        for data in ("a\n\n", "a\na\n", "/a\n", "b\na\n", "../a\n"):
            with self.subTest(paths=data):
                with self.assertRaises(module.ScopeError): module._allowed_text(data)
        with mock.patch.object(module, "_git", return_value=b"not-a-commit\n"):
            with self.assertRaises(module.ScopeError): module._commit("bad")
        with mock.patch.object(module.subprocess, "run", return_value=mock.Mock(returncode=1, stdout=b"")):
            with self.assertRaises(module.ScopeError): module._git("rev-parse", "bad")
        with mock.patch.object(module.re, "compile", side_effect=module.re.error("x")):
            with self.assertRaises(module.ScopeError): module._rx()

    def test_similar_path_data_filename_is_scanned_normally(self):
        path = "scripts/work6_allowed_paths_copy.txt"
        base = self.repo.commit("base")
        self.repo.write(path, "Apply" + "Delta\n")
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, path + "\n"), path + " contains excluded content")

    def test_unsorted_or_traversing_whitelist_fails(self):
        base = self.repo.commit("base")
        self.repo.write("a", "x\n")
        self.repo.commit("candidate")
        for paths in ("b\na\n", "../escape\n"):
            with self.subTest(paths=paths):
                self.assert_fail(self.repo.check(base, paths), "allowed paths " + ("must be sorted and unique" if paths.startswith("b") else "contains a non-relative entry"))

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
        self.assert_fail(self.repo.check(base, data_path + "\n"), "path data has excluded entry")

    def test_path_data_candidate_update_entry_fails_exactly(self):
        data_path = "scripts/" + "work6_" + "allowed_paths" + ".txt"
        base = self.repo.commit("base")
        self.repo.write(data_path, "src/" + "Apply" + "Delta" + ".cpp\n")
        self.repo.commit("candidate")
        self.assert_fail(self.repo.check(base, data_path + "\n"), "path data has excluded entry")

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
