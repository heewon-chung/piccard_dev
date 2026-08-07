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

    def invoke_fake_runner(self, fault: str | None = None, *, source_snapshot: Path | None = None,
                           terminal_wrapper: bool = False) -> tuple[subprocess.CompletedProcess[bytes], Path, str]:
        """Drive the actual runner process with executable fake dependencies."""
        from scripts.run_work7_integration import FROZEN_CTESTS
        from scripts.work7_evidence import snapshot_git_worktree

        temporary = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temporary, True)
        source, paper, threshold = (temporary / name for name in ("source", "paper", "threshold"))
        if source_snapshot is None:
            source.mkdir()
        else:
            subprocess.run(("git", "clone", "--quiet", "--local", str(source_snapshot), str(source)), check=True)
            subprocess.run(("git", "-C", str(source), "config", "user.email", "runner@example.test"), check=True)
            subprocess.run(("git", "-C", str(source), "config", "user.name", "Runner"), check=True)
        for root in (paper, threshold):
            root.mkdir()
        if source_snapshot is None:
            self.make_git(source, "tkde-major/pre-threshold-poc")
        self.make_git(paper)
        self.make_git(threshold)
        if source_snapshot is not None:
            response = paper / "Revision" / "ResponseStrategy.md"
            response.parent.mkdir(parents=True, exist_ok=True)
            response.write_text("# Baseline response\n", encoding="utf-8")
            subprocess.run(("git", "-C", str(paper), "add", "."), check=True)
            subprocess.run(("git", "-C", str(paper), "commit", "-qm", "response baseline"), check=True)
        commit = subprocess.check_output(("git", "-C", str(source), "rev-parse", "HEAD"), text=True).strip()
        state = {"schema": "piccard-work7-phase0-state-v2", "source": {"head": commit},
                 "paper": snapshot_git_worktree(paper), "threshold": snapshot_git_worktree(threshold),
                 "build": {"root": str((temporary / "builds" / ("build-" + commit)).resolve())},
                 "session_id": "work7-" + commit}
        scripts = source / "scripts"
        self.write(scripts / "work7_state_guard.py", """
                import json, os, pathlib, sys
                p=pathlib.Path(sys.argv[sys.argv.index('--output')+1]); p.parent.mkdir(parents=True,exist_ok=True)
                if os.environ.get('FAKE_FAULT') == 'dirty': raise SystemExit(2)
                state=json.loads(os.environ['FAKE_STATE']); state['build']={'root':str(pathlib.Path(sys.argv[sys.argv.index('--build-root')+1]).resolve())}
                p.write_text(json.dumps(state, sort_keys=True, separators=(',', ':'))+'\\n'); print('work7_state_guard: PASS')
            """)
        if source_snapshot is None:
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
            root=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--results-root='))); build=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--build-dir='))); root.mkdir(parents=True)
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
                if os.environ.get('FAKE_FAULT') == 'pre-symlink' and i==0:
                    outside=root.parent/'outside.csv'; outside.write_text('trials\\n1\\n'); link=root/'escape-link.csv'; link.symlink_to(outside); out['csv']='escape-link.csv'; out['csv_sha256']=hashlib.sha256(outside.read_bytes()).hexdigest()
                argv=[name,*args]; d=hashlib.sha256(b'piccard-benchmark-cell-v1\\0')
                for v in [name,'toy-smoke',*[x for x in argv[1:] if not x.startswith('--manifest-out=') and not x.startswith('--execution-trace-out=')],'OMP_DYNAMIC=FALSE','OMP_NUM_THREADS=2']:
                    b=v.encode(); d.update(len(b).to_bytes(4,'big')); d.update(b)
                digest=d.hexdigest(); cid='toy-smoke/'+name+'/'+digest
                cells.append({'cell_id':cid,'profile_id':'toy-smoke','parameter_sha256':digest,'producer':name,'environment':{'OMP_DYNAMIC':'FALSE','OMP_NUM_THREADS':'2'},'status':'MEASURED','reason_code':'NONE','required_bits':'','available_bits':'','shortfall_bits':'','argv':argv,'output':out})
            if os.environ.get('FAKE_FAULT') == 'pre-extra-key': cells[0]['unexpected']='tamper'
            terminal='schema_version\\tcell_id\\tprofile_id\\tproducer\\tparameter_sha256\\tstatus\\treason_code\\trequired_bits\\tavailable_bits\\tshortfall_bits\\tlog_sha256\\n' + ''.join('piccard-benchmark-terminal-cell-v1\\t'+c['cell_id']+'\\ttoy-smoke\\t'+c['producer']+'\\t'+c['parameter_sha256']+'\\tMEASURED\\tNONE\\t\\t\\t\\t'+c['output']['log_sha256']+'\\n' for c in sorted(cells,key=lambda c:c['cell_id']))
            if os.environ.get('FAKE_FAULT') == 'terminal-row': terminal=terminal.replace('\\tMEASURED\\tNONE', '\\tREJECTED\\tNONE', 1)
            (root/'terminal-cells.tsv').write_text(terminal)
            producers=['bench_review_comparison','bench_piccard','bench_dynamic']; provenance={'schema':'piccard-build-provenance-v1','commit':os.environ['FAKE_COMMIT'],'dirty':False,'build_type':'Release','openfhe_version':'1.9.0','source_dir':os.getcwd()}
            binaries={name:{'path':str((build/name).resolve()),'sha256':hashlib.sha256((build/name).read_bytes()).hexdigest(),'provenance':provenance.copy()} for name in producers}
            manifest={'schema':'piccard-pre-threshold-run-v1','suite':'smoke','seed':7,'repetitions':1,'classification':'diagnostic','thread_policy':{'OMP_DYNAMIC':'FALSE','OMP_NUM_THREADS':'2'},'profiles':['toy-smoke'],'source':{'commit':os.environ['FAKE_COMMIT'],'dirty':False,'dir':os.getcwd()},'build':{'dir':str(build.resolve()),'type':'Release','binaries':binaries},'machine':{'cpu':'fake-cpu','ram':1,'os':'fake-os','compiler':'fake-c++','libraries':{'openfhe':['1.9.0']}},'directories':{'csv':'csv','workloads':'workloads','traces':'traces','logs':'logs'},'cells':cells,'terminal_cells':{'path':'terminal-cells.tsv','row_count':3,'sha256':hashlib.sha256(terminal.encode()).hexdigest()}}
            fault=os.environ.get('FAKE_FAULT')
            if fault == 'pre-top-missing': del manifest['machine']
            if fault == 'pre-classification': manifest['classification']='evidence'
            if fault == 'pre-binary-hash': manifest['build']['binaries']['bench_piccard']['sha256']='0'*64
            if fault == 'pre-provenance-commit': manifest['build']['binaries']['bench_piccard']['provenance']['commit']='0'*40
            if fault == 'pre-provenance-source': manifest['build']['binaries']['bench_piccard']['provenance']['source_dir']='/foreign'
            if fault == 'pre-provenance-type': manifest['build']['binaries']['bench_piccard']['provenance']['build_type']='Debug'
            if fault == 'pre-machine-openfhe': manifest['machine']['libraries']={'openfhe':['different']}
            if fault == 'pre-directories': manifest['directories']['logs']='other'
            (root/'manifest.json').write_text(json.dumps(manifest))
        """)
        self.write(scripts / "run_real_datasets.sh", """
            #!/usr/bin/env python3
            import hashlib, os, pathlib, sys
            root=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--results-root='))); root.mkdir(parents=True)
            source=pathlib.Path.cwd(); build=pathlib.Path(next(x.split('=',1)[1] for x in sys.argv if x.startswith('--build-dir='))); variant='dblp_acm_u65536'; fixture=source/'tests'/'fixtures'/'real_datasets'/'quick'/variant
            h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            for relative, body in [('system_info.txt','system'),(f'input_manifests/{variant}/source.manifest.tsv','source'),(f'input_manifests/{variant}/dataset.manifest.tsv','dataset'),('run.log','log'),(f'csv/real_accuracy_{variant}.csv','trials\\n1\\n'),(f'workloads/accuracy_{variant}.manifest.tsv','a'),(f'workloads/accuracy_{variant}.rows.tsv','b'),(f'csv/real_accuracy_summary_{variant}.csv','trials\\n1\\n'),(f'csv/real_timing_{variant}_toy-smoke.csv','trials\\n1\\n'),(f'workloads/timing_{variant}_toy-smoke.manifest.tsv','t')]:
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
            fault=os.environ.get('FAKE_FAULT')
            def change(key, value):
                rows[rows.index(next(item for item in rows if item[0] == key))]=(key,value)
            if fault == 'real-artifact-digest': change('artifact.000.sha256','0'*64)
            if fault == 'real-output-digest': change('cell.000.output.000.sha256','0'*64)
            if fault == 'real-input-digest': change('cell.000.input.000.sha256','0'*64)
            if fault == 'real-artifact-escape': change('artifact.000.path','nested/../escape.txt')
            if fault == 'real-output-escape': change('cell.000.output.000.path','nested/../escape.csv')
            if fault == 'real-symlink':
                outside=root.parent/'outside.csv'; outside.write_text('trials\\n1\\n'); (root/'escape-link.csv').symlink_to(outside); change('cell.000.output.000.path','escape-link.csv'); change('cell.000.output.000.sha256',h(outside))
            if fault == 'real-accuracy-token': change('cell.000.argv.006','--accuracy_trials=2')
            if fault == 'real-accuracy-duplicate': change('cell.000.argv.007','--accuracy_trials=1')
            if fault == 'real-timing-token': change('cell.002.argv.006','--trials=2')
            if fault == 'real-timing-duplicate': change('cell.002.argv.007','--trials=1')
            if fault == 'real-argv-gap': rows=[x for x in rows if x[0] != 'cell.000.argv.001']
            if fault == 'real-input-gap': rows=[x for x in rows if x[0] != 'cell.000.input.000.path']
            if fault == 'real-output-gap': rows=[x for x in rows if x[0] != 'cell.000.output.001.path']
            root.joinpath('run_metadata.tsv').write_text('key\\tvalue\\n' + ''.join(k+'\\t'+v+'\\n' for k,v in rows))
            if os.environ.get('FAKE_FAULT') == 'drift': pathlib.Path(os.environ['FAKE_PAPER']).joinpath('tracked').write_text('changed\\n')
            if os.environ.get('FAKE_FAULT') == 'threshold-drift': pathlib.Path(os.environ['FAKE_THRESHOLD']).joinpath('tracked').write_text('changed\\n')
        """)
        fixture = source / "tests" / "fixtures" / "real_datasets" / "quick" / "dblp_acm_u65536"
        fixture.mkdir(parents=True, exist_ok=True)
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
        if source_snapshot is not None and terminal_wrapper:
            verifier = scripts / "verify_work7_claims.py"
            verifier.rename(scripts / "verify_work7_claims_real.py")
            verifier_real = scripts / "verify_work7_claims_real.py"
            verifier_real.write_text(
                verifier_real.read_text(encoding="utf-8")
                .replace("piccard-work7-phase0-state-v1", "piccard-work7-phase0-state-v2")
                .replace('{"schema", "source", "paper", "threshold", "session_id"}',
                         '{"schema", "source", "paper", "threshold", "build", "session_id"}'),
                encoding="utf-8",
            )
            self.write(verifier, """
                #!/usr/bin/env python3
                import os, pathlib, runpy, sys
                action=os.environ.get('WORK7_TEST_TERMINAL_ACTION', '')
                mode=sys.argv[sys.argv.index('--mode')+1]
                if mode == 'terminal' and action == 'invalid-report':
                    pathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_text('{}\\n')
                    raise SystemExit(0)
                if mode == 'terminal' and action == 'missing-report':
                    raise SystemExit(0)
                try:
                    runpy.run_path(str(pathlib.Path(__file__).with_name('verify_work7_claims_real.py')), run_name='__main__')
                except SystemExit as error:
                    code=error.code if isinstance(error.code, int) else 1
                else:
                    code=0
                if mode == 'terminal' and action == 'replace-inputs':
                    pathlib.Path(os.environ['WORK7_TEST_REVIEW_PATH']).write_text('tampered after private copy\\n')
                    pathlib.Path(os.environ['WORK7_TEST_PACKET_PATH']).write_text('{}\\n')
                if mode == 'terminal' and action == 'external-drift':
                    pathlib.Path(os.environ['WORK7_TEST_PAPER_PATH']).joinpath('tracked').write_text('changed\\n')
                raise SystemExit(code)
            """)
        if source_snapshot is None:
            (scripts / "work7_claims.json").write_text("{}", encoding="utf-8")
        fakebin = temporary / "bin"; fakebin.mkdir()
        self.write(fakebin / "cmake", """
            #!/usr/bin/env python3
            import pathlib, sys
            a=sys.argv
            if '-B' in a:
                b=pathlib.Path(a[a.index('-B')+1]); b.mkdir(parents=True,exist_ok=True)
                p=b/'bench_deletion_survival'; p.write_text('#!/bin/sh\\necho model,n,d,k,required_survival,r,exact_survival,union_bound_survival,mc_survival,mc_standard_error,maximum_safe_deletions,exact_expected_first_failure,exact_expected_safe_deletions,mc_mean_first_failure,mc_mean_safe_deletions,trials,seed\\nfor r in 1 4 8; do echo ideal-independent-random-ranking-v1,64,3,8,'+('0.98' if __import__('os').environ.get('FAKE_FAULT') == 'deletion-survival' else '0.99')+',$r,1,1,1,0,1,1,1,1,1,1,7; done\\n'); p.chmod(0o755)
                q=b/'bench_real_datasets'; q.write_text('#!/bin/sh\\nexit 0\\n'); q.chmod(0o755)
                for name in ('bench_review_comparison','bench_piccard','bench_dynamic'):
                    q=b/name; q.write_text('#!/bin/sh\\nexit 0\\n'); q.chmod(0o755)
                print('OpenFHE GMP GTest' if __import__('os').environ.get('FAKE_FAULT') == 'dependency' else 'OpenFHE GMP GTest Python3')
        """)
        self.write(fakebin / "ctest", """
            #!/usr/bin/env python3
            import os, sys
            if '-N' in sys.argv:
                print('Test project fake')
                for i,n in enumerate(os.environ['FAKE_TESTS'].split(','),1): print(f'  Test #{i}: {n}')
                print(); print('Total Tests: '+str(len(os.environ['FAKE_TESTS'].split(','))))
            elif os.environ.get('FAKE_FAULT') == 'skip': print('1/1 Test #1: MinHash ... Not Run')
            else:
                names=os.environ['FAKE_TESTS'].split(',')
                for i,n in enumerate(names,1): print(f'{i}/{len(names)} Test #{i}: {n} ... Passed 0.00 sec')
                print(); print(f'100% tests passed, 0 tests failed out of {len(names)}')
        """)
        if source_snapshot is not None:
            subprocess.run(("git", "-C", str(source), "add", "."), check=True)
            subprocess.run(("git", "-C", str(source), "commit", "-qm", "fake producer dependencies"), check=True)
            commit = subprocess.check_output(("git", "-C", str(source), "rev-parse", "HEAD"), text=True).strip()
            state = {"schema": "piccard-work7-phase0-state-v2", "source": snapshot_git_worktree(source),
                     "paper": snapshot_git_worktree(paper), "threshold": snapshot_git_worktree(threshold),
                     "build": {"root": str((temporary / "builds" / ("build-" + commit)).resolve())},
                     "session_id": "work7-" + commit}
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

    def test_producer_evidence_tampering_has_targeted_failure(self):
        cases = {
            "pre-top-missing": "invalid pre-threshold manifest schema",
            "pre-classification": "invalid pre-threshold manifest identity",
            "pre-binary-hash": "invalid pre-threshold binary binding",
            "pre-provenance-commit": "invalid pre-threshold binary provenance",
            "pre-provenance-source": "invalid pre-threshold binary provenance",
            "pre-provenance-type": "invalid pre-threshold binary provenance",
            "pre-machine-openfhe": "invalid pre-threshold machine provenance",
            "pre-directories": "invalid pre-threshold manifest identity",
            "terminal-row": "pre-threshold terminal rows do not bind cells",
            "pre-extra-key": "invalid pre-threshold cell schema",
            "pre-symlink": "invalid pre-threshold artifact path",
            "real-artifact-digest": "invalid real-data artifact digest",
            "real-output-digest": "invalid real-data output digest",
            "real-input-digest": "invalid real-data input digest",
            "real-artifact-escape": "invalid real-data artifact path",
            "real-output-escape": "invalid real-data output path",
            "real-symlink": "invalid real-data output path",
            "real-accuracy-token": "real-data metadata does not exactly bind quick provenance",
            "real-accuracy-duplicate": "real-data metadata does not exactly bind quick provenance",
            "real-timing-token": "real-data metadata does not exactly bind quick provenance",
            "real-timing-duplicate": "real-data metadata does not exactly bind quick provenance",
            "real-argv-gap": "real-data metadata does not exactly bind quick provenance",
            "real-input-gap": "invalid real-data input path",
            "real-output-gap": "invalid real-data output path",
            "deletion-survival": "invalid deletion CSV",
        }
        for fault, expected in cases.items():
            with self.subTest(fault=fault):
                result, _, _ = self.invoke_fake_runner(fault)
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertIn(expected, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
