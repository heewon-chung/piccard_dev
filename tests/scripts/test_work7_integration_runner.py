"""Hermetic behavior coverage for the Work 7 Phase 2 runner."""

import shutil
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


class Work7IntegrationRunnerTests(unittest.TestCase):
    fixtures = Path(__file__).parents[1] / "fixtures" / "work7" / "runner"

    def fake_root(self, fixture: str) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        shutil.copy(self.fixtures / fixture, Path(temporary.name) / fixture)
        return temporary

    def test_frozen_registry_contains_every_required_ctest_once(self):
        from scripts.run_work7_integration import FROZEN_CTESTS

        self.assertEqual(len(FROZEN_CTESTS), len(set(FROZEN_CTESTS)))
        self.assertIn("EstimatorDiagnostic", FROZEN_CTESTS)
        self.assertIn("Work7IntegrationRunner", FROZEN_CTESTS)

    def test_rejects_repeated_measured_count_in_fake_artifact(self):
        from scripts.run_work7_integration import Failure, validate_records

        with self.fake_root("repeated-count.csv") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(Failure, "measured count"):
                validate_records(root)

    def test_rejects_multiple_or_analytic_warmups_in_fake_artifact(self):
        from scripts.run_work7_integration import Failure, validate_records

        with self.fake_root("analytic-warmup.json") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(Failure, "warmup"):
                validate_records(root)

    def test_rejects_actual_data_path_in_fake_artifact(self):
        from scripts.run_work7_integration import Failure, validate_records

        with self.fake_root("actual-data.json") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(Failure, "actual-data"):
                validate_records(root)

    def make_git(self, root: Path, branch: str = "main") -> None:
        subprocess.run(("git", "init", "-q", "-b", branch, str(root)), check=True)
        subprocess.run(("git", "-C", str(root), "config", "user.email", "runner@example.test"), check=True)
        subprocess.run(("git", "-C", str(root), "config", "user.name", "Runner"), check=True)
        (root / "tracked").write_text("clean\n", encoding="utf-8")
        subprocess.run(("git", "-C", str(root), "add", "."), check=True)
        subprocess.run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True)

    def write(self, path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def invoke_fake_runner(self, fault: str | None = None) -> tuple[subprocess.CompletedProcess[bytes], Path, str]:
        """Drive the actual runner process with executable fake dependencies."""
        from scripts.run_work7_integration import FROZEN_CTESTS
        from scripts.work7_evidence import snapshot_git_worktree

        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary, True)
        source, paper, threshold = (temporary / name for name in ("source", "paper", "threshold"))
        for root in (source, paper, threshold):
            root.mkdir()
        self.make_git(source, "tkde-major/pre-threshold-poc")
        self.make_git(paper)
        self.make_git(threshold)
        commit = subprocess.check_output(("git", "-C", str(source), "rev-parse", "HEAD"), text=True).strip()
        state = {"schema": "piccard-work7-phase0-state-v1", "source": {"head": commit},
                 "paper": snapshot_git_worktree(paper), "threshold": snapshot_git_worktree(threshold),
                 "session_id": "work7-" + commit}
        scripts = source / "scripts"
        self.write(scripts / "work7_state_guard.py", """
            import json, os, pathlib, sys
            p=pathlib.Path(sys.argv[sys.argv.index('--output')+1]); p.parent.mkdir(parents=True,exist_ok=True)
            if os.environ.get('FAKE_FAULT') == 'dirty': raise SystemExit(2)
            p.write_text(os.environ['FAKE_STATE']); print('work7_state_guard: PASS')
        """)
        self.write(scripts / "verify_work7_claims.py", """
            import json, os, pathlib, sys
            a=sys.argv; mode=a[a.index('--mode')+1]; output=pathlib.Path(a[a.index('--output')+1]); commit=a[a.index('--source-commit')+1]
            if os.environ.get('FAKE_FAULT') == 'tamper' and mode == 'evidence-bound':
                p=pathlib.Path(a[a.index('--runtime-seal')+1]); p.write_text(p.read_text()+'x')
            if os.environ.get('FAKE_FAULT') == 'foreign' and mode == 'static': commit='0'*40
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_text(json.dumps({'schema':'piccard-work7-claim-report-v1','source_commit':commit,'mode':mode,'status':'PASS'}))
        """)
        self.write(scripts / "run_pre_threshold_profiles.sh", """
            #!/usr/bin/env python3
            import json, os, pathlib, sys
            root=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--results-root='))); root.mkdir(parents=True)
            if os.environ.get('FAKE_FAULT') == 'malformed': (root/'bad.csv').write_text('a,b\\n\"bad')
            elif os.environ.get('FAKE_FAULT') == 'count2': (root/'timing.csv').write_text('trials,status\\n2,MEASURED\\n')
            elif os.environ.get('FAKE_FAULT') == 'warmup': (root/'timing.csv').write_text('warmup,trials\\n2,1\\n')
            elif os.environ.get('FAKE_FAULT') == 'unlabelled': (root/'timing.csv').write_text('warmup,trials\\nmaybe,1\\n')
            elif os.environ.get('FAKE_FAULT') == 'actual': (root/'actual-data.csv').write_text('trials\\n1\\n')
            else: (root/'timing.csv').write_text('trials,warmup\\n1,discarded\\n')
            (root/'run-manifest.json').write_text(json.dumps({'trials':1,'refresh_updates':1}))
        """)
        self.write(scripts / "run_real_datasets.sh", """
            #!/usr/bin/env python3
            import os, pathlib, sys
            root=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--results-root='))); root.mkdir(parents=True)
            root.joinpath('run-metadata.tsv').write_text('key\\tvalue\\n')
            if os.environ.get('FAKE_FAULT') == 'drift': pathlib.Path(os.environ['FAKE_PAPER']).joinpath('tracked').write_text('changed\\n')
            if os.environ.get('FAKE_FAULT') == 'threshold-drift': pathlib.Path(os.environ['FAKE_THRESHOLD']).joinpath('tracked').write_text('changed\\n')
        """)
        (scripts / "work7_claims.json").write_text("{}", encoding="utf-8")
        fakebin = temporary / "bin"; fakebin.mkdir()
        self.write(fakebin / "cmake", """
            #!/usr/bin/env python3
            import pathlib, sys
            a=sys.argv
            if '-B' in a:
                b=pathlib.Path(a[a.index('-B')+1]); b.mkdir(parents=True,exist_ok=True)
                p=b/'bench_deletion_survival'; p.write_text('#!/bin/sh\\necho trials,status\\necho 1,MEASURED\\n'); p.chmod(0o755)
                print('OpenFHE GMP GTest' if __import__('os').environ.get('FAKE_FAULT') == 'dependency' else 'OpenFHE GMP GTest Python3')
        """)
        self.write(fakebin / "ctest", """
            #!/usr/bin/env python3
            import os, sys
            if '-N' in sys.argv:
                for i,n in enumerate(os.environ['FAKE_TESTS'].split(','),1): print(f'  Test #{i}: {n}')
                print(); print('Total Tests: '+str(len(os.environ['FAKE_TESTS'].split(','))))
            elif os.environ.get('FAKE_FAULT') == 'skip': print('1/1 Test #1: MinHash ... Not Run')
            else: print('100% tests passed')
        """)
        env = {**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ["PATH"], "FAKE_STATE": json.dumps(state),
               "FAKE_TESTS": ",".join(name for name in FROZEN_CTESTS if not (fault == "missing" and name == "MinHash")),
               "FAKE_FAULT": fault or "", "FAKE_PAPER": str(paper), "FAKE_THRESHOLD": str(threshold)}
        if fault == "existing-build": (temporary / "builds" / ("build-" + commit)).mkdir(parents=True)
        if fault == "existing-session": (temporary / "sessions" / ("session-" + commit)).mkdir(parents=True)
        (temporary / "builds").mkdir(exist_ok=True); (temporary / "sessions").mkdir(exist_ok=True)
        result = subprocess.run((sys.executable, str(Path(__file__).parents[2] / "scripts" / "run_work7_integration.py"),
                                 "--source-root", str(source), "--paper-root", str(paper), "--threshold-root", str(threshold),
                                 "--build-parent", str(temporary / "builds"), "--session-parent", str(temporary / "sessions"),
                                 "--expected-source-branch", "tkde-major/pre-threshold-poc"), env=env, capture_output=True)
        return result, temporary, commit

    def test_fake_tools_prove_exact_sequence_and_seal_lifecycle(self):
        result, root, commit = self.invoke_fake_runner()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        session = root / "sessions" / ("session-" + commit)
        commands = session / "phase2" / "runtime" / "commands"
        labels = ["phase0-guard", "configure", "build", "ctest-inventory", "static", "ctest-focused", "pre-threshold", "real-datasets", "deletion-survival"]
        root = root.resolve()
        self.assertEqual([json.loads((commands / (label + ".json")).read_text())["argv"][0] for label in labels], [sys.executable, "cmake", "cmake", "ctest", sys.executable, "ctest", str(root / "source" / "scripts" / "run_pre_threshold_profiles.sh"), str(root / "source" / "scripts" / "run_real_datasets.sh"), str(root / "builds" / ("build-" + commit) / "bench_deletion_survival")])
        self.assertEqual(json.loads((commands / "configure.json").read_text())["argv"], ["cmake", "-S", str(root / "source"), "-B", str(root / "builds" / ("build-" + commit)), "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTS=ON", "-DBUILD_BENCHMARKS=ON"])
        self.assertEqual(json.loads((commands / "pre-threshold.json").read_text())["argv"][1:4], ["--suite=smoke", "--seed=7", "--threads=2"])
        self.assertEqual(json.loads((commands / "real-datasets.json").read_text())["argv"][1:4], ["--quick", "--seed=7", "--threads=2"])
        self.assertEqual(json.loads((commands / "deletion-survival.json").read_text())["argv"][1:], ["--n=64", "--d=3", "--k=8", "--required_survival=0.99", "--r_values=1,4,8", "--trials=1", "--seed=7"])
        self.assertTrue((session / "phase2" / "runtime-seal.json").is_file())
        closure = json.loads((session / "phase2" / "closure-seal.json").read_text())
        self.assertEqual(closure["previous_seal_sha256"], __import__("hashlib").sha256((session / "phase2" / "runtime-seal.json").read_bytes()).hexdigest())
        self.assertTrue((session / "phase2" / "closure-artifacts" / "evidence-bound-report.json").is_file())

    def test_fake_tool_hard_failures(self):
        cases = ("existing-build", "existing-session", "dirty", "dependency", "missing", "skip", "count2", "warmup", "unlabelled", "actual", "malformed", "foreign", "tamper", "drift", "threshold-drift")
        for fault in cases:
            with self.subTest(fault=fault):
                result, _, _ = self.invoke_fake_runner(fault)
                self.assertEqual(result.returncode, 2, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
