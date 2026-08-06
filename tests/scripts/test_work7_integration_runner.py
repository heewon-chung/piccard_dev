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
            import hashlib
            cells=[]
            specs=[('bench_review_comparison',['--suite=toy-smoke','--profile=toy-smoke','--k=16','--m=16','--set-size=10','--universe=64','--target-jaccard=0.5','--trials=1','--accuracy-trials=1','--seed=7','--methods=piccard,piccard_sqrt,bcg12_mh_ec,bcg12_exact_ec,sj16','--sj16-key-bits=1024','--allow-unmatched-security']),('bench_piccard',['--profile=toy-smoke','--security=TOY','--mode=timing','--evidence_point','--k=16','--m=16','--set_size=10','--target-jaccard=0.5','--trials=1','--seed=7']),('bench_dynamic',['--scenario=refresh','--refresh_updates=1','--profile=toy-smoke','--security=TOY','--mode=timing','--evidence_point','--k=16','--m=16','--set_size=100','--target-jaccard=0.5','--depth=5','--trials=1','--seed=7'])]
            for i,(name,args) in enumerate(specs):
                cid='toy-'+str(i); (root/'csv').mkdir(exist_ok=True); (root/'logs').mkdir(exist_ok=True); p=root/'csv'/(cid+'.csv'); q=root/'logs'/(cid+'.log'); p.write_text('trials\\n' + ('1\\n'*10 if i==0 else '1\\n')); q.write_text('log')
                out={'csv':str(p.relative_to(root)),'csv_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'log':str(q.relative_to(root)),'log_sha256':hashlib.sha256(q.read_bytes()).hexdigest(),'expected_csv_rows':10 if i==0 else 1,'csv_row_count':10 if i==0 else 1,'measurement_output':'measured-csv'}
                if i==0:
                    (root/'workloads').mkdir(exist_ok=True); (root/'traces').mkdir(exist_ok=True); w=root/'workloads'/(cid+'.bin'); t=root/'traces'/(cid+'.bin'); w.write_text('w'); t.write_text('t'); out.update({'workload':str(w.relative_to(root)),'workload_sha256':hashlib.sha256(w.read_bytes()).hexdigest(),'trace':str(t.relative_to(root)),'trace_sha256':hashlib.sha256(t.read_bytes()).hexdigest()}); args += [f'--manifest-out={w}',f'--execution-trace-out={t}']
                if os.environ.get('FAKE_FAULT') == 'pre-argv' and i==0: args[0]='--suite=bad'
                if os.environ.get('FAKE_FAULT') == 'pre-output' and i==0: out['measurement_output']='bad'
                if os.environ.get('FAKE_FAULT') == 'pre-digest' and i==0: out['csv_sha256']='0'*64
                if os.environ.get('FAKE_FAULT') == 'pre-escape' and i==0: out['csv']='../escape.csv'
                argv=[name,*args]; d=hashlib.sha256(b'piccard-benchmark-cell-v1\\0')
                for v in [name,'toy-smoke',*[x for x in argv[1:] if not x.startswith('--manifest-out=') and not x.startswith('--execution-trace-out=')],'OMP_DYNAMIC=FALSE','OMP_NUM_THREADS=2']:
                    b=v.encode(); d.update(len(b).to_bytes(4,'big')); d.update(b)
                digest=d.hexdigest(); cid='toy-smoke/'+name+'/'+digest
                cells.append({'cell_id':cid,'profile_id':'toy-smoke','parameter_sha256':digest,'producer':name,'environment':{'OMP_DYNAMIC':'FALSE','OMP_NUM_THREADS':'2'},'status':'MEASURED','reason_code':'NONE','required_bits':'','available_bits':'','shortfall_bits':'','argv':argv,'output':out})
            terminal='schema_version\\tcell_id\\tprofile_id\\tproducer\\tparameter_sha256\\tstatus\\treason_code\\trequired_bits\\tavailable_bits\\tshortfall_bits\\tlog_sha256\\n' + ''.join('piccard-benchmark-terminal-cell-v1\\t'+c['cell_id']+'\\ttoy-smoke\\t'+c['producer']+'\\t'+c['parameter_sha256']+'\\tMEASURED\\tNONE\\t\\t\\t\\t'+c['output']['log_sha256']+'\\n' for c in sorted(cells,key=lambda c:c['cell_id'])) ; (root/'terminal-cells.tsv').write_text(terminal)
            (root/'manifest.json').write_text(json.dumps({'schema':'piccard-pre-threshold-run-v1','suite':'smoke','seed':7,'repetitions':1,'source':{'commit':os.environ['FAKE_COMMIT'],'dirty':False,'dir':os.getcwd()},'thread_policy':{'OMP_DYNAMIC':'FALSE','OMP_NUM_THREADS':'2'},'cells':cells,'terminal_cells':{'path':'terminal-cells.tsv','row_count':3,'sha256':hashlib.sha256(terminal.encode()).hexdigest()}}))
        """)
        self.write(scripts / "run_real_datasets.sh", """
            #!/usr/bin/env python3
            import hashlib, os, pathlib, sys
            root=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--results-root='))); root.mkdir(parents=True)
            source=pathlib.Path.cwd(); build=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--build-dir='))); variant='dblp_acm_u65536'; fixture=source/'tests'/'fixtures'/'real_datasets'/'quick'/variant
            h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            for relative, body in [('system_info.txt','system'),(f'input_manifests/{variant}/source.manifest.tsv','source'),(f'input_manifests/{variant}/dataset.manifest.tsv','dataset'),('run.log','log'),(f'csv/real_accuracy_{variant}.csv','trials\\n1\\n'),(f'workloads/accuracy_{variant}.manifest.tsv','a'),(f'workloads/accuracy_{variant}.rows.tsv','b'),(f'csv/real_accuracy_summary_{variant}.csv','summary'),(f'csv/real_timing_{variant}_toy-smoke.csv','trials\\n1\\n'),(f'workloads/timing_{variant}_toy-smoke.manifest.tsv','t')]:
                p=root/relative; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(body)
            roots=[('results-root',root),('build-dir',build),('committed-source-root',source),(f'source-root-{variant}',fixture),(f'processed-dataset-{variant}',fixture)]
            rows=[('schema_version','piccard-real-run-v1'),('evidence_mode','quick'),('source_commit',os.environ['FAKE_COMMIT']),('git_dirty','false'),('build_type','Release'),('bench_real_datasets_sha256',h(build/'bench_real_datasets')),('summarize_real_datasets_sha256',h(source/'scripts'/'summarize_real_datasets.py')),('root_count',str(len(roots)))]
            for i,(key,path) in enumerate(roots): rows += [(f'root.{i:03d}.id',key),(f'root.{i:03d}.path',str(path.resolve()))]
            artifacts=[('system-info','system_info.txt'),(f'copied-source-manifest-{variant}',f'input_manifests/{variant}/source.manifest.tsv'),(f'copied-processed-manifest-{variant}',f'input_manifests/{variant}/dataset.manifest.tsv'),('run-log','run.log')]
            rows += [('artifact_count',str(len(artifacts)))]
            for i,(role,relative) in enumerate(artifacts): rows += [(f'artifact.{i:03d}.role',role),(f'artifact.{i:03d}.path',relative),(f'artifact.{i:03d}.sha256',h(root/relative))]
            dataset=fixture/'dataset.manifest.tsv'; accuracy=root/'csv'/f'real_accuracy_{variant}.csv'; summary=root/'csv'/f'real_accuracy_summary_{variant}.csv'; timing=root/'csv'/f'real_timing_{variant}_toy-smoke.csv'
            cells=[(f'{variant}:accuracy',['bench_real_datasets',f'--dataset-manifest={dataset}','--mode=accuracy','--k=128','--m=64','--max-pairs=2','--accuracy_trials=1','--seed=7','--hash_randomness=resampled',f'--csv={accuracy}',f'--workload-manifest-out={root / "workloads" / f"accuracy_{variant}.manifest.tsv"}',f'--workload-rows-out={root / "workloads" / f"accuracy_{variant}.rows.tsv"}'],{'OMP_DYNAMIC':'FALSE','OMP_NUM_THREADS':'1'},[('processed-manifest',f'processed-dataset-{variant}',fixture,'dataset.manifest.tsv')],[accuracy,root/'workloads'/f'accuracy_{variant}.manifest.tsv',root/'workloads'/f'accuracy_{variant}.rows.tsv']),(f'{variant}:accuracy-summary',['summarize_real_datasets.py',f'--input={accuracy}',f'--output={summary}'],{'OMP_DYNAMIC':'FALSE','OMP_NUM_THREADS':'1'},[('accuracy-csv','results-root',root,f'csv/real_accuracy_{variant}.csv')],[summary]),(f'{variant}:timing:toy-smoke',['bench_real_datasets',f'--dataset-manifest={dataset}','--mode=timing','--profile=toy-smoke','--k=128','--m=64','--trials=1','--timing-pair=median','--seed=7',f'--csv={timing}',f'--workload-manifest-out={root / "workloads" / f"timing_{variant}_toy-smoke.manifest.tsv"}'],{'OMP_DYNAMIC':'FALSE','OMP_NUM_THREADS':'2'},[('processed-manifest',f'processed-dataset-{variant}',fixture,'dataset.manifest.tsv')],[timing,root/'workloads'/f'timing_{variant}_toy-smoke.manifest.tsv'])]
            rows += [('cell_count','3')]
            frame=lambda a: hashlib.sha256(b''.join(len(x.encode()).to_bytes(4,'big')+x.encode() for x in a)).hexdigest()
            for i,(cid,args,env,inputs,outputs) in enumerate(cells):
                p=f'cell.{i:03d}'; rows += [(p+'.id',cid),(p+'.argv_count',str(len(args))),*[(p+f'.argv.{j:03d}',x) for j,x in enumerate(args)],(p+'.argv_sha256',frame(args)),(p+'.env_count',str(len(env))),*sum(([(p+f'.env.{j:03d}.key',k),(p+f'.env.{j:03d}.value',v)] for j,(k,v) in enumerate(sorted(env.items()))),[]),(p+'.input_count',str(len(inputs)))]
                for j,(role,rid,base,relative) in enumerate(inputs): rows += [(p+f'.input.{j:03d}.role',role),(p+f'.input.{j:03d}.root_id',rid),(p+f'.input.{j:03d}.path',relative),(p+f'.input.{j:03d}.sha256',h(base/relative))]
                rows += [(p+'.output_count',str(len(outputs)))]
                for j,out in enumerate(outputs): rows += [(p+f'.output.{j:03d}.path',out.relative_to(root).as_posix()),(p+f'.output.{j:03d}.sha256',h(out))]
                rows += [(p+'.status','complete')]
            if os.environ.get('FAKE_FAULT') == 'real-argv': rows[rows.index(('cell.000.argv.001',f'--dataset-manifest={dataset}'))]=('cell.000.argv.001','--dataset-manifest=bad')
            if os.environ.get('FAKE_FAULT') == 'real-root': rows=[x for x in rows if x[0] != 'root.004.path']
            root.joinpath('run_metadata.tsv').write_text('key\\tvalue\\n' + ''.join(k+'\\t'+v+'\\n' for k,v in rows))
            if os.environ.get('FAKE_FAULT') == 'drift': pathlib.Path(os.environ['FAKE_PAPER']).joinpath('tracked').write_text('changed\\n')
            if os.environ.get('FAKE_FAULT') == 'threshold-drift': pathlib.Path(os.environ['FAKE_THRESHOLD']).joinpath('tracked').write_text('changed\\n')
        """)
        fixture = source / "tests" / "fixtures" / "real_datasets" / "quick" / "dblp_acm_u65536"
        fixture.mkdir(parents=True)
        (fixture / "source.manifest.tsv").write_text("source\n", encoding="utf-8")
        (fixture / "dataset.manifest.tsv").write_text("dataset\n", encoding="utf-8")
        (scripts / "summarize_real_datasets.py").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.write(scripts / "verify_real_dataset_outputs.py", """
            #!/usr/bin/env python3
            import hashlib, pathlib, sys
            root=pathlib.Path(sys.argv[1]); raw=(root/'run_metadata.tsv').read_bytes()
            if __import__('os').environ.get('FAKE_FAULT') == 'stale-verification': raw=b'bad'
            (root/'verification_status.tsv').write_text('key\\tvalue\\nschema_version\\tpiccard-real-verification-v1\\nrun_metadata_sha256\\t'+hashlib.sha256(raw).hexdigest()+'\\nstatus\\tVERIFIED\\n')
        """)
        (scripts / "work7_claims.json").write_text("{}", encoding="utf-8")
        fakebin = temporary / "bin"; fakebin.mkdir()
        self.write(fakebin / "cmake", """
            #!/usr/bin/env python3
            import pathlib, sys
            a=sys.argv
            if '-B' in a:
                b=pathlib.Path(a[a.index('-B')+1]); b.mkdir(parents=True,exist_ok=True)
                p=b/'bench_deletion_survival'; p.write_text('#!/bin/sh\\necho model,n,d,k,required_survival,r,exact_survival,union_bound_survival,mc_survival,mc_standard_error,maximum_safe_deletions,exact_expected_first_failure,exact_expected_safe_deletions,mc_mean_first_failure,mc_mean_safe_deletions,trials,seed\\nfor r in 1 4 8; do echo ideal-independent-random-ranking-v1,64,3,8,0.99,$r,1,1,1,0,1,1,1,1,1,1,7; done\\n'); p.chmod(0o755)
                q=b/'bench_real_datasets'; q.write_text('#!/bin/sh\\nexit 0\\n'); q.chmod(0o755)
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
               "FAKE_FAULT": fault or "", "FAKE_PAPER": str(paper), "FAKE_THRESHOLD": str(threshold), "FAKE_COMMIT": commit}
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
        labels = ["phase0-guard", "configure", "build", "ctest-inventory", "static", "ctest-focused", "pre-threshold", "real-datasets", "verify-real-datasets", "deletion-survival"]
        root = root.resolve()
        self.assertEqual([json.loads((commands / (label + ".json")).read_text())["argv"][0] for label in labels], [sys.executable, "cmake", "cmake", "ctest", sys.executable, "ctest", str(root / "source" / "scripts" / "run_pre_threshold_profiles.sh"), str(root / "source" / "scripts" / "run_real_datasets.sh"), sys.executable, str(root / "builds" / ("build-" + commit) / "bench_deletion_survival")])
        self.assertEqual(json.loads((commands / "configure.json").read_text())["argv"], ["cmake", "-S", str(root / "source"), "-B", str(root / "builds" / ("build-" + commit)), "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTS=ON", "-DBUILD_BENCHMARKS=ON"])
        self.assertEqual(json.loads((commands / "pre-threshold.json").read_text())["argv"][1:4], ["--suite=smoke", "--seed=7", "--threads=2"])
        self.assertEqual(json.loads((commands / "real-datasets.json").read_text())["argv"][1:4], ["--quick", "--seed=7", "--threads=2"])
        self.assertEqual(json.loads((commands / "deletion-survival.json").read_text())["argv"][1:], ["--n=64", "--d=3", "--k=8", "--required_survival=0.99", "--r_values=1,4,8", "--trials=1", "--seed=7"])
        self.assertTrue((session / "phase2" / "runtime-seal.json").is_file())
        self.assertEqual(json.loads((session / "phase0" / "seal.json").read_text())["kind"], "phase0")
        closure = json.loads((session / "phase2" / "closure-seal.json").read_text())
        self.assertEqual(closure["kind"], "phase2-closure")
        self.assertEqual(closure["previous_seal_sha256"], __import__("hashlib").sha256((session / "phase2" / "runtime-seal.json").read_bytes()).hexdigest())
        self.assertTrue((session / "phase2" / "closure-artifacts" / "evidence-bound-report.json").is_file())

    def test_fake_tool_hard_failures(self):
        cases = ("existing-build", "existing-session", "dirty", "dependency", "missing", "skip", "count2", "warmup", "unlabelled", "actual", "malformed", "foreign", "tamper", "drift", "threshold-drift", "stale-verification", "pre-argv", "pre-output", "pre-digest", "pre-escape", "real-argv", "real-root")
        for fault in cases:
            with self.subTest(fault=fault):
                result, _, _ = self.invoke_fake_runner(fault)
                self.assertEqual(result.returncode, 2, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
