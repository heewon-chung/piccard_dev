from __future__ import annotations

import json
import csv
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "run_revision_benchmarks.py"
VERIFIER = ROOT / "scripts" / "verify_revision_benchmarks.py"
MATRIX = ROOT / "benchmarks" / "revision_matrix.json"


class RevisionVerifierContractTest(unittest.TestCase):
    THRESHOLD_SPEC_HEADER = (
        "k,tau,degree,ps_baby_s,ps_num_chunks,baby_depth,giant_mults,"
        "natural_mult_depth,mult_depth,scaling_mod_size,ring_dim,"
        "plaintext_mod,log2_q,eval_noise_bits,flood_noise_bits,ct_bytes,"
        "poly_build_ms,status,note,schema_version,requested_ring_dim,"
        "natural_ring_dim,provisioned_ring_dim,realized_ring_dim,"
        "natural_depth,provisioned_depth,log_q_bits,log2_q_over_t_bits,"
        "plaintext_modulus,num_limbs,realized_scaling_mod_size,"
        "ordered_rns_moduli,ordered_rns_limb_bits,ordered_rns_limb_bits_sum,"
        "openfhe_version,flooding_assurance,transcript_stat_bits,max_queries,"
        "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
        "required_capacity_bits,residual_capacity_definition,"
        "residual_capacity_bits,residual_capacity_status"
    )
    SQRT_HEADER = (
        "encoding,k,m,N,Depth,Encode,Encrypt,Evaluate,Decrypt,Total(ms),"
        "|err|,rel_err,security,transcript_stat_bits,max_queries,"
        "query_stat_bits,coefficient_stat_bits,flood_margin_bits,"
        "eval_noise_bits,flood_noise_bits,sanitizer_model,"
        "sanitizer_assurance,estimator_model,profile_id,run_class,"
        "target_security_bits,comparison_eligible,measurement_kind,"
        "actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,"
        "openfhe_version"
    )

    def write_family_stdout(self, root: Path, cell: dict, payload: str) -> None:
        from revision_benchmark_common import cell_output
        output = cell_output(root, cell["cell_id"])
        output.mkdir(parents=True)
        (output / "stdout.log").write_text(payload, encoding="utf-8")
        (output / "stderr.log").write_text("", encoding="utf-8")
        (output / "receipt.json").write_text(
            json.dumps({"artifact_inventory": []}) + "\n", encoding="utf-8")

    def write_artifact(self, root: Path, cell: dict, name: str,
                       payload: str, command_prefix: str = "--output=") -> list[str]:
        from revision_benchmark_common import cell_output, file_inventory, sha256_file
        output = cell_output(root, cell["cell_id"])
        output.mkdir(parents=True, exist_ok=True)
        (output / "stdout.log").write_text("", encoding="utf-8")
        (output / "stderr.log").write_text("", encoding="utf-8")
        path = output / name
        path.write_text(payload, encoding="utf-8")
        receipt = {"artifact_inventory": file_inventory(
            output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
        (output / "receipt.json").write_text(
            json.dumps(receipt) + "\n", encoding="utf-8")
        return [f"{command_prefix}{path}"]

    @staticmethod
    def csv_row(header: str, **overrides: str) -> str:
        fields = header.rstrip("\n").split(",")
        values = [""] * len(fields)
        for name, value in overrides.items():
            if name not in fields:
                raise AssertionError(f"unknown CSV field: {name}")
            values[fields.index(name)] = str(value)
        return ",".join(values)

    def write_stdout_rows(self, root: Path, cell: dict, header: str,
                          rows: list[str]) -> None:
        self.write_family_stdout(root, cell, header + "\n".join(rows) + "\n")

    @staticmethod
    def full_sj16_fixture(trials: int = 1) -> str:
        lines = [
            "# SJ16 calibration summary",
            "overall_status=PASS",
            "validation_scope=READINESS_ONLY",
            "# ---- provenance ----",
            "precompute_mode=off",
            "# --------------------",
            "key_bits=3072",
            "threads_requested=2",
            "threads_observed=2",
            f"trials_per_size={trials}",
            f"enc_iters={trials}",
            "held_out=32768",
            "residual_tau=0.100000",
            "fit_sizes=4096,8192,16384",
            "# columns: key_bits,t_enc_median_ms,t_enc_iqr_ms,alpha_ms_per_m,beta_ms,r2,held_measured_ms,held_pred_ms,held_residual,gate",
            "3072,1,0,0.001,1,1,33,33,0,READINESS_ONLY",
            "# ---- per-size dispersion (median/q1/q3/iqr + raw samples) ----",
            f"k3072_t_enc median=1 iqr=0 samples={','.join(['1'] * trials)}",
        ]
        for size in (4096, 8192, 16384):
            lines.append(
                f"k3072_fit_m={size} median=1 q1=1 q3=1 iqr=0 "
                f"samples={','.join(['1'] * trials)}")
        lines.append(
            f"k3072_heldout_m=32768 median=33 q1=33 q3=33 iqr=0 "
            f"samples={','.join(['33'] * trials)}")
        return "\n".join(lines) + "\n"

    def matrix_cell(self, schema: str, *, family: str | None = None,
                    axis: str | None = None, axis_value: str | None = None) -> dict:
        document = json.loads(MATRIX.read_text())
        for cell in document["cells"]:
            if cell["expected_artifact_schema"] != schema:
                continue
            if family is not None and cell["family"] != family:
                continue
            if axis is not None and cell.get("axis") != axis:
                continue
            if axis_value is not None and str(cell.get("axis_value")) != axis_value:
                continue
            return cell
        raise AssertionError(f"no cell for {schema}/{family}/{axis}={axis_value}")

    def make_dry_root(self, temporary: str) -> Path:
        root = Path(temporary) / "dry"
        build = Path(temporary) / "build"
        build.mkdir()
        run = subprocess.run(
            [sys.executable, str(RUNNER), "--mode=dry-run",
             "--build-dir", str(build), "--results-root", str(root),
             "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
            cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return root

    @staticmethod
    def _root_snapshot(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(
                path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def test_toy_and_post_seal_modes_accept_canonical_sealed_lifecycle_read_only(self) -> None:
        """A sealed toy root accepts both required read-only verifier modes.

        The complete artifact/science checks are already covered by the
        independent dry/toy KATs.  This KAT isolates the lifecycle boundary:
        it creates the same terminal phase stream and seal that the runner
        creates, then invokes both public CLI modes without allowing the
        semantic checks to be bypassed in production.
        """
        sys.path.insert(0, str(ROOT / "scripts"))
        import seal_revision_benchmarks as sealer
        import verify_revision_benchmarks as verifier
        from revision_benchmark_common import PHASES

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "toy"
            (root / "verification").mkdir(parents=True)
            phase_status = {}
            phase_records = []
            for phase in PHASES:
                phase_status[phase] = "STARTED"
                phase_records.append({
                    "schema": "piccard-revision-phase-v1",
                    "phase": phase, "state": "STARTED",
                    "reason": "", "index": PHASES.index(phase),
                    "time_ns": PHASES.index(phase) + 1,
                })
                if phase != "seal":
                    phase_status[phase] = "COMPLETED"
                    phase_records.append({
                        "schema": "piccard-revision-phase-v1",
                        "phase": phase, "state": "COMPLETED",
                        "reason": "", "index": PHASES.index(phase),
                        "time_ns": len(phase_records) + 1,
                    })
            run = {
                "schema": "piccard-revision-readiness-run-v1",
                "version": 1, "mode": "toy", "state": "COMPLETED",
                "phase_status": phase_status,
                "readiness_status": "READINESS_ONLY",
                "performance_status": "PAPER_PERFORMANCE_PENDING",
                "cell_count": 0, "toy_measured_count": 0,
                "matrix_sha256": "a" * 64,
            }
            (root / "run.json").write_text(
                json.dumps(run, sort_keys=True) + "\n", encoding="utf-8")
            (root / "verification" / "receipt.json").write_text(
                json.dumps({"verdict": "PASS"}, sort_keys=True) + "\n",
                encoding="utf-8")
            (root / "phases.jsonl").write_text(
                "".join(json.dumps(record, sort_keys=True) + "\n"
                        for record in phase_records), encoding="utf-8")

            # Keep the real phase/seal checks active.  The remaining checks
            # need a 104-cell producer campaign and are not the subject of
            # this lifecycle KAT.
            check_patches = [
                patch.object(verifier, "_check_run_manifest", return_value=run),
                patch.object(verifier, "_check_matrix",
                             return_value=({}, "a" * 64, [])),
                patch.object(verifier, "_check_source_and_tools"),
                patch.object(verifier, "_check_plans", return_value={}),
                patch.object(verifier, "_check_events"),
                patch.object(verifier, "_check_receipts"),
                patch.object(verifier, "_check_family_taxonomy"),
                patch.object(verifier, "_check_family_artifacts"),
            ]
            for item in check_patches:
                item.start()
            try:
                # The runner's internal pre-seal call still selects the
                # explicit verification stage rather than the sealed stage.
                preseal_records = phase_records[:phase_records.index(
                    next(record for record in phase_records
                         if record["phase"] == "verification" and
                         record["state"] == "STARTED")) + 1]
                (root / "phases.jsonl").write_text(
                    "".join(json.dumps(record, sort_keys=True) + "\n"
                            for record in preseal_records), encoding="utf-8")
                run["state"] = "VERIFYING"
                run["phase_status"]["verification"] = "STARTED"
                (root / "run.json").write_text(
                    json.dumps(run, sort_keys=True) + "\n", encoding="utf-8")
                self.assertEqual(
                    verifier.verify_root(root, mode="toy",
                                        lifecycle_stage="verification")["mode"],
                    "toy")

                # Complete the immutable stream and install the canonical
                # non-replacing seal, exactly as the runner does.
                (root / "phases.jsonl").write_text(
                    "".join(json.dumps(record, sort_keys=True) + "\n"
                            for record in phase_records), encoding="utf-8")
                run["state"] = "COMPLETED"
                run["phase_status"] = phase_status
                (root / "run.json").write_text(
                    json.dumps(run, sort_keys=True) + "\n", encoding="utf-8")
                sealer.create_seal(root)

                for mode in ("toy", "post-seal"):
                    with self.subTest(mode=mode):
                        before = self._root_snapshot(root)
                        self.assertEqual(
                            verifier.main([str(root), f"--mode={mode}"]), 0)
                        self.assertEqual(before, self._root_snapshot(root))

                # A seal or lifecycle mutation must fail closed, and the
                # failure must not repair or rewrite any root member.
                seal_before = (root / "seal.json").read_bytes()
                (root / "seal.json").write_bytes(seal_before + b"\n")
                tampered_before = self._root_snapshot(root)
                self.assertEqual(
                    verifier.main([str(root), "--mode=toy"]), 2)
                self.assertEqual(tampered_before, self._root_snapshot(root))
                (root / "seal.json").write_bytes(seal_before)
                phases_before = (root / "phases.jsonl").read_bytes()
                (root / "phases.jsonl").write_text(
                    phases_before.decode().replace('"state": "STARTED"',
                                                     '"state": "COMPLETED"', 1),
                    encoding="utf-8")
                lifecycle_before = self._root_snapshot(root)
                self.assertEqual(
                    verifier.main([str(root), "--mode=post-seal"]), 2)
                self.assertEqual(lifecycle_before, self._root_snapshot(root))
            finally:
                for item in reversed(check_patches):
                    item.stop()

    def test_event_timestamps_follow_event_stream_order_and_bind_cells(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import EVENT_SCHEMA, RevisionContractError
        from verify_revision_benchmarks import _check_events

        first_cell = "paper-v1::estimator_accuracy::j=0.5"
        second_cell = "paper-v1::fhe_ind::control=default"
        plans = {
            # The matrix/planned inventory order differs from phase execution:
            # synthetic starts with estimator_accuracy, then fhe_ind.
            second_cell: {"command": ["producer", second_cell],
                          "invocation_status": "RUN"},
            first_cell: {"command": ["producer", first_cell],
                         "invocation_status": "RUN"},
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_files: dict[str, tuple[str, str]] = {}
            for cell_id in (first_cell, second_cell):
                output = root / "cells" / cell_id.replace("::", "_")
                output.mkdir(parents=True)
                stdout = output / "stdout.log"
                stderr = output / "stderr.log"
                stdout.write_text(f"stdout:{cell_id}\n", encoding="utf-8")
                stderr.write_text(f"stderr:{cell_id}\n", encoding="utf-8")
                event_files[cell_id] = (
                    str(stdout.relative_to(root)), str(stderr.relative_to(root)))

            def digest(relative_path: str) -> str:
                return hashlib.sha256((root / relative_path).read_bytes()).hexdigest()

            def event_stream() -> list[dict]:
                events = []
                sequence = 1
                for cell_id, start_ns, end_ns in (
                        (first_cell, 10, 20), (second_cell, 30, 40)):
                    stdout_path, stderr_path = event_files[cell_id]
                    events.append({
                        "schema": EVENT_SCHEMA, "version": 1,
                        "sequence": sequence, "event": "START",
                        "cell_id": cell_id, "argv": plans[cell_id]["command"],
                    })
                    sequence += 1
                    events.append({
                        "schema": EVENT_SCHEMA, "version": 1,
                        "sequence": sequence, "event": "END",
                        "cell_id": cell_id, "exit_code": 0,
                        "start_ns": start_ns, "end_ns": end_ns,
                        "stdout_path": stdout_path, "stderr_path": stderr_path,
                        "stdout_sha256": digest(stdout_path),
                        "stderr_sha256": digest(stderr_path),
                    })
                    sequence += 1
                return events

            def write_events(events: list[dict]) -> None:
                (root / "events.jsonl").write_text(
                    "".join(json.dumps(event, sort_keys=True) + "\n"
                            for event in events), encoding="utf-8")

            write_events(event_stream())
            # This is the real phase/event order and must be accepted despite
            # plans being supplied in matrix insertion order.
            _check_events(root, "toy", plans)

            mutations = {
                "overlapping global chronology": lambda events: (
                    events[3].update(start_ns=19, end_ns=29)),
                "cross-cell START/END binding": lambda events: (
                    events[1].update(cell_id=second_cell)),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    events = event_stream()
                    mutate(events)
                    write_events(events)
                    with self.assertRaises(RevisionContractError):
                        _check_events(root, "toy", plans)

    def test_verifier_rejects_changed_manifest_and_cell_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dry"
            build = Path(temporary) / "build"
            build.mkdir()
            run = subprocess.run(
                [sys.executable, str(RUNNER), "--mode=dry-run",
                 "--build-dir", str(build), "--results-root", str(root),
                 "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            manifest = root / "run.json"
            value = json.loads(manifest.read_text())
            value["cell_count"] = 262
            manifest.write_text(json.dumps(value, sort_keys=True) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_verifier_rejects_swapped_security_method(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "dry"
            build = Path(temporary) / "build"
            build.mkdir()
            run = subprocess.run(
                [sys.executable, str(RUNNER), "--mode=dry-run",
                 "--build-dir", str(build), "--results-root", str(root),
                 "--seed", "7", "--threads", "1", "--matrix", str(MATRIX)],
                cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            argv_file = root / "planned_argv.jsonl"
            lines = argv_file.read_text().splitlines()
            mutated = json.loads(lines[0])
            mutated["argv"].append("--security=STD192")
            lines[0] = json.dumps(mutated, sort_keys=True)
            argv_file.write_text("\n".join(lines) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_verifier_rejects_coordinated_sj16_timeout_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_dry_root(temporary)
            argv_file = root / "planned_argv.jsonl"
            records = [json.loads(line) for line in argv_file.read_text().splitlines()]
            target = next(record for record in records
                          if record["cell_id"] ==
                          "paper-v1::sj16::fit=per_element")
            target["timeout_class"] = "standard"
            target["timeout_seconds"] = 600
            argv_file.write_text("".join(json.dumps(record, sort_keys=True) + "\n"
                                             for record in records))
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_raw_profile_binding_accepts_std128_cli_for_sqrt_producers(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (RevisionContractError,
                                                _raw_bind_command_profile)

        for producer in ("bench_onehot_sqrt", "bench_crossover"):
            _raw_bind_command_profile(
                {"command": ["--profile=paper-std128-t40-v1"]},
                producer, "paper", "kat")
            _raw_bind_command_profile(
                {"command": ["--profile=readiness-toy-v1"]},
                producer, "toy", "kat")
            with self.assertRaises(RevisionContractError):
                _raw_bind_command_profile(
                    {"command": ["--profile=paper-v1"]},
                    producer, "paper", "kat")
            with self.assertRaises(RevisionContractError):
                _raw_bind_command_profile(
                    {"command": ["--profile=paper-std128-t40-v1",
                                 "--raw-timing-profile=paper-v1"]},
                    producer, "paper", "kat")
        # The generic branch still binds CLI profile == raw profile.
        _raw_bind_command_profile(
            {"command": ["--profile=paper-v1"]},
            "bench_review_comparison", "paper", "kat")
        with self.assertRaises(RevisionContractError):
            _raw_bind_command_profile(
                {"command": ["--profile=paper-std128-t40-v1"]},
                "bench_review_comparison", "paper", "kat")

    def test_raw_require_stat_accepts_ulp_noise_and_rejects_corruption(self) -> None:
        import math
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (RevisionContractError,
                                                _raw_require_stat)

        for expected in (0.0, 1e-8, 1.0, 1e5):
            near = math.nextafter(expected, math.inf)
            near_text = format(near, ".17g")
            _raw_require_stat(near_text, near, expected, "sample_sd_ms", "kat")

            corrupt = 1e-6 if expected == 0.0 else expected * (1 + 1e-3)
            corrupt_text = format(corrupt, ".17g")
            with self.assertRaises(RevisionContractError):
                _raw_require_stat(corrupt_text, corrupt, expected,
                                  "sample_sd_ms", "kat")

    def test_verifier_rejects_coordinated_materialized_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_dry_root(temporary)
            path = root / "planned_argv.jsonl"
            records = [json.loads(line) for line in path.read_text().splitlines()]
            target = next(record for record in records
                          if any(arg == "--trials=30" for arg in record["command"]))
            target["command"] = ["--trials=31" if arg == "--trials=30" else arg
                                 for arg in target["command"]]
            target["argv"] = ["--trials=31" if arg == "--trials=30" else arg
                              for arg in target["argv"]]
            path.write_text("\n".join(json.dumps(row, sort_keys=True)
                                      for row in records) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_verifier_piccard_plan_requires_canonical_identity_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_dry_root(temporary)
            path = root / "planned_argv.jsonl"
            original = path.read_text()
            records = [json.loads(line) for line in original.splitlines()]
            target = next(record for record in records
                          if record["producer"] == "bench_piccard")
            cid = target["cell_id"]
            from revision_benchmark_common import cell_output
            identity = f"--revision-identity-out={cell_output(root.resolve(), cid) / 'identity.csv'}"
            self.assertNotIn(identity, target["canonical_argv"])
            self.assertEqual(target["command"].count(identity), 1)
            self.assertEqual(target["argv"].count(identity), 1)

            for label in ("missing", "duplicate", "rebound"):
                with self.subTest(label=label):
                    mutated_records = [json.loads(line)
                                       for line in original.splitlines()]
                    mutated = next(record for record in mutated_records
                                   if record["cell_id"] == cid)
                    if label == "missing":
                        mutated["command"].remove(identity)
                        mutated["argv"].remove(identity)
                    elif label == "duplicate":
                        mutated["command"].append(identity)
                        mutated["argv"].append(identity)
                    else:
                        foreign = f"--revision-identity-out={root / 'foreign' / 'identity.csv'}"
                        mutated["command"] = [foreign if item == identity else item
                                              for item in mutated["command"]]
                        mutated["argv"] = [foreign if item == identity else item
                                            for item in mutated["argv"]]
                    path.write_text("\n".join(
                        json.dumps(record, sort_keys=True)
                        for record in mutated_records) + "\n")
                    check = subprocess.run(
                        [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                        cwd=ROOT, text=True, capture_output=True)
                    self.assertNotEqual(check.returncode, 0, check.stderr)

    def test_piccard_identity_sidecar_actual_shape_kat_and_mutations(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _SQRT_TIMING_HEADER, _check_family_artifacts,
            RevisionContractError)

        cell = self.matrix_cell("piccard-benchmark-csv-v1",
                                family="piccard_std128",
                                axis="control", axis_value="default")
        cell = json.loads(json.dumps(cell))
        for expected_row in cell["expected_rows"]:
            expected_row.pop("raw_timing_contract", None)
        cid = cell["cell_id"]
        expected_identity = (
            "schema,cell_id,universe_size\n"
            f"piccard-revision-cell-v1,{cid},{cell['axes']['u']}\n"
        ).encode("utf-8")
        rows = [
            self.csv_row(_SQRT_TIMING_HEADER, label=cid, k=128, m=64,
                         set_size=1000, trials=1, accuracy_trials=0,
                         profile_id="readiness-toy-v1", run_class="smoke",
                         target_security_bits=0, comparison_eligible="false"),
            self.csv_row(_SQRT_TIMING_HEADER, label=cid, k=128, m=64,
                         set_size=1000, trials=1, accuracy_trials=1,
                         profile_id="readiness-toy-v1", run_class="smoke",
                         target_security_bits=0, comparison_eligible="false"),
        ]

        cases = (
            ("positive", expected_identity, True),
            ("missing", None, False),
            ("wrong universe", expected_identity.replace(b",65536\n", b",16384\n"), False),
            ("wrong cell", expected_identity.replace(cid.encode(), b"wrong-cell"), False),
        )
        for label, identity_payload, accepted in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                output = cell_output(root, cid)
                output.mkdir(parents=True)
                (output / "stdout.log").write_text(
                    _SQRT_TIMING_HEADER + "\n".join(rows) + "\n",
                    encoding="utf-8")
                (output / "stderr.log").write_text("", encoding="utf-8")
                if identity_payload is not None:
                    (output / "identity.csv").write_bytes(identity_payload)
                receipt = {"artifact_inventory": file_inventory(
                    output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
                (output / "receipt.json").write_text(
                    json.dumps(receipt) + "\n", encoding="utf-8")
                plan = {cid: {"command": [
                    f"--revision-cell={cid}",
                    "--profile=readiness-toy-v1",
                    f"--revision-identity-out={output / 'identity.csv'}",
                ]}}
                if accepted:
                    _check_family_artifacts(root, "toy", [cell], plan)
                else:
                    with self.assertRaises(RevisionContractError):
                        _check_family_artifacts(root, "toy", [cell], plan)

    def test_family_verifier_recomputes_and_rejects_forged_real_summary(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import summarize_real_datasets as summarizer
        from revision_benchmark_common import cell_output, file_inventory, sha256_file
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["cell_id"] ==
                    "paper-v1::real_dataset::dblp_acm_u65536_artifact=summary")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            accuracy_id = ("paper-v1::real_dataset::dblp_acm_u65536_"
                           "artifact=accuracy")
            accuracy = cell_output(root, accuracy_id) / "accuracy.csv"
            accuracy.parent.mkdir(parents=True)
            row = ["0"] * len(summarizer.ACCURACY_HEADER_FIELDS)
            indices = {name: index for index, name in
                       enumerate(summarizer.ACCURACY_HEADER_FIELDS)}
            row[indices["dataset"]] = "dblp_acm"
            row[indices["variant"]] = "dblp_acm_u65536"
            row[indices["exact_jaccard_bucketed"]] = "0.25"
            row[indices["abs_error"]] = "0.125"
            row[indices["record_a"]] = "a"
            row[indices["record_b"]] = "b"
            for key in ("set_size_a_raw", "set_size_b_raw",
                        "set_size_a_bucketed", "set_size_b_bucketed"):
                row[indices[key]] = "2"
            with accuracy.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle, lineterminator="\n")
                writer.writerow(summarizer.ACCURACY_HEADER_FIELDS)
                writer.writerow(row)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            summary = output / "summary.csv"
            command = [sys.executable, str(ROOT / "scripts" / "summarize_real_datasets.py"),
                       f"--revision-cell={cell['cell_id']}",
                       f"--accuracy-csv={accuracy}", f"--output={summary}",
                       "--variant=dblp_acm_u65536"]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True,
                                       text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            (output / "stdout.log").write_text("")
            (output / "stderr.log").write_text("")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n")
            plans = {cell["cell_id"]: {"command": command}}
            _check_family_artifacts(root, "toy", [cell], plans)
            summary.write_text(summary.read_text() + "forged,row\n")
            receipt["artifact_inventory"] = file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], plans)

    def test_family_verifier_rejects_token_only_stdout_without_csv(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["expected_artifact_schema"] ==
                    "review-comparison-csv-v1")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            tokens = ",".join(row["method"] for row in cell["expected_rows"])
            (output / "stdout.log").write_text(tokens + "\n")
            (output / "stderr.log").write_text("")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(
                    root, "toy", [cell],
                    {cell["cell_id"]: {"command": ["unused"]}})

    def test_verifier_rejects_missing_binary_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.make_dry_root(temporary)
            manifest = root / "run.json"
            value = json.loads(manifest.read_text())
            value["binaries"] = {}
            manifest.write_text(json.dumps(value, sort_keys=True) + "\n")
            check = subprocess.run(
                [sys.executable, str(VERIFIER), str(root), "--mode=dry-run"],
                cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(check.returncode, 0)

    def test_family_verifier_rejects_wrong_fhe_ind_cell_identity(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["expected_artifact_schema"] == "fhe-ind-csv-v1")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            (output / "stdout.log").write_text(
                "cell_id,method,status,trials\nWRONG-CELL,fhe_ind,DIAGNOSTIC,1\n")
            (output / "stderr.log").write_text("")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_fhe_ind_allows_only_canonical_output_and_rejects_extra_csv(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _FHE_IND_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("fhe-ind-csv-v1", family="fhe_ind",
                                axis="control", axis_value="default")
        cell = json.loads(json.dumps(cell))
        for expected_row in cell["expected_rows"]:
            expected_row.pop("raw_timing_contract", None)
        fields = _FHE_IND_HEADER.rstrip("\n").split(",")
        values = [""] * len(fields)
        for name, value in {
                "cell_id": cell["cell_id"], "method": "fhe_ind",
                "k": "N/A", "m": "N/A", "universe": "65536",
                "set_size": "1000", "seed": "0", "trials": "1"}.items():
            values[fields.index(name)] = value
        payload = _FHE_IND_HEADER + ",".join(values) + "\n"

        def write_fixture(root: Path, output_name: str,
                          *, unrelated: bool = False) -> list[str]:
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            (output / output_name).write_text(payload, encoding="utf-8")
            if unrelated:
                (output / "unrelated.csv").write_text("not evidence\n",
                                                        encoding="utf-8")
            (output / "stdout.log").write_text("", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(
                json.dumps(receipt) + "\n", encoding="utf-8")
            return [f"--output={output / output_name}",
                    "--universe=65536", "--set_size=1000", "--seed=7"]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "canonical"
            command = write_fixture(root, "fhe_ind.csv")
            _check_family_artifacts(
                root, "toy", [cell], {cell["cell_id"]: {"command": command}})

            for label, output_name, unrelated in (
                    ("substitute output", "substitute.csv", False),
                    ("unrelated CSV", "fhe_ind.csv", True)):
                with self.subTest(label=label):
                    case_root = Path(temporary) / label.replace(" ", "_")
                    case_command = write_fixture(
                        case_root, output_name, unrelated=unrelated)
                    with self.assertRaises(RevisionContractError):
                        _check_family_artifacts(
                            case_root, "toy", [cell],
                            {cell["cell_id"]: {"command": case_command}})

    def test_fhe_ind_binds_universe_set_size_seed_and_allows_na_k_m(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _FHE_IND_HEADER, _bind_cell_shape, RevisionContractError)
        cell = self.matrix_cell("fhe-ind-csv-v1", family="fhe_ind",
                                axis="control", axis_value="default")
        fields = _FHE_IND_HEADER.rstrip("\n").split(",")
        row = {field: "" for field in fields}
        row.update({"cell_id": cell["cell_id"], "k": "N/A", "m": "N/A",
                    "universe": "65536", "set_size": "1000", "seed": "0"})
        command = ["--output=/tmp/fhe_ind.csv", "--universe=65536",
                   "--set_size=1000", "--seed=7"]
        _bind_cell_shape([row], cell, {"command": command}, cell["cell_id"])

        for label, field, value in (("seed", "seed", "1"),
                                    ("universe", "universe", "32768"),
                                    ("set size", "set_size", "999")):
            with self.subTest(label=label):
                mutated = dict(row)
                mutated[field] = value
                with self.assertRaises(RevisionContractError):
                    _bind_cell_shape([mutated], cell,
                                     {"command": command}, cell["cell_id"])

    def test_toy_real_accuracy_binds_ineligible_without_profile_and_paper_stays_eligible(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _REAL_ACCURACY_HEADER, _check_family_artifacts,
            RevisionContractError)
        cell = self.matrix_cell("real-dataset-csv-v1", family="real_dataset",
                                axis_value="accuracy",
                                axis="dblp_acm_u65536_artifact")
        fields = _REAL_ACCURACY_HEADER.rstrip("\n").split(",")
        values = [""] * len(fields)
        for name, value in {
                "dataset": "dblp_acm", "variant": "dblp_acm_u65536",
                "k": "128", "m": "64", "root_seed": "7",
                "comparison_eligible": "false", "pair_id": "pair-0",
                "pair_kind": "sampled_nonmatch", "accuracy_trial_index": "0"}.items():
            values[fields.index(name)] = value

        def write_fixture(root: Path, eligible: str) -> list[str]:
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            row_values = list(values)
            row_values[fields.index("comparison_eligible")] = eligible
            (output / "accuracy.csv").write_text(
                _REAL_ACCURACY_HEADER + ",".join(row_values) + "\n",
                encoding="utf-8")
            (output / "stdout.log").write_text("", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(
                json.dumps(receipt) + "\n", encoding="utf-8")
            command = [f"--revision-cell={cell['cell_id']}",
                       "--mode=accuracy", "--seed=7",
                       f"--csv={output / 'accuracy.csv'}"]
            self.assertFalse(any(arg.startswith("--profile=") for arg in command))
            return command

        with tempfile.TemporaryDirectory() as temporary:
            toy_root = Path(temporary) / "toy"
            toy_command = write_fixture(toy_root, "false")
            _check_family_artifacts(
                toy_root, "toy", [cell],
                {cell["cell_id"]: {"command": toy_command}})

            forged_root = Path(temporary) / "forged"
            forged_command = write_fixture(forged_root, "true")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(
                    forged_root, "toy", [cell],
                    {cell["cell_id"]: {"command": forged_command}})

            paper_root = Path(temporary) / "paper"
            paper_command = write_fixture(paper_root, "true")
            _check_family_artifacts(
                paper_root, "paper", [cell],
                {cell["cell_id"]: {"command": paper_command}})

    def test_family_verifier_rejects_duplicate_piccard_rows_and_wrong_trials(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        document = json.loads(MATRIX.read_text())
        cell = next(item for item in document["cells"]
                    if item["expected_artifact_schema"] ==
                    "piccard-benchmark-csv-v1")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            row = f"{cell['cell_id']},999,0\n"
            (output / "stdout.log").write_text(
                "label,trials,accuracy_trials\n" + row + row)
            (output / "stderr.log").write_text("")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_family_verifier_accepts_threshold_spec_success_row(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("threshold-csv-v1", family="threshold_spec",
                                axis="k", axis_value="64")
        fields = self.THRESHOLD_SPEC_HEADER.split(",")
        values = ["N/A"] * len(fields)
        values[fields.index("k")] = "64"
        values[fields.index("status")] = "ok"
        values[fields.index("schema_version")] = "piccard-threshold-spec-v2"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     self.THRESHOLD_SPEC_HEADER + "\n" +
                                     ",".join(values) + "\n")
            _check_family_artifacts(
                root, "toy", [cell], {cell["cell_id"]: {"command": []}})

    def test_family_verifier_accepts_sqrt_accuracy_onehot_shape(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="accuracy_m", axis_value="128")
        fields = self.SQRT_HEADER.split(",")
        values = [""] * len(fields)
        values[fields.index("encoding")] = "OneHot"
        values[fields.index("k")] = "128"
        values[fields.index("m")] = "128"
        values[fields.index("comparison_eligible")] = "true"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     self.SQRT_HEADER + "\n" +
                                     ",".join(values) + "\n")
            (cell_output(root, cell["cell_id"]) / "stderr.log").write_text(
                "revision_terminal,schema=sqrt-revision-terminal-v1,"
                f"cell_id={cell['cell_id']},row_id=sqrt,status=NOT_APPLICABLE,"
                "terminal_status=NOT_APPLICABLE,reason=sqrt-m-not-perfect-square,"
                "reason_code=sqrt-m-not-perfect-square,measured_count=0\n",
                encoding="utf-8")
            _check_family_artifacts(
                root, "toy", [cell], {cell["cell_id"]: {"command": []}})

    def test_family_verifier_rejects_threshold_spec_header_drift(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        cell = self.matrix_cell("threshold-csv-v1", family="threshold_spec",
                                axis="k", axis_value="64")
        fields = self.THRESHOLD_SPEC_HEADER.replace("status", "status_drift").split(",")
        values = ["N/A"] * len(fields)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     ",".join(fields) + "\n" +
                                     ",".join(values) + "\n")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(
                    root, "toy", [cell], {cell["cell_id"]: {"command": []}})

    def test_family_verifier_accepts_sqrt_timing_legacy_shape(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import (
            _SQRT_TIMING_HEADER, _check_family_artifacts)
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="timing_m", axis_value="128")
        # This is intentionally a legacy sparse-shape fixture.  The canonical
        # matrix now carries raw-phase-v1 authority for this RUN row, so make
        # the legacy test explicit about opting out of that newer contract.
        cell = json.loads(json.dumps(cell))
        for expected_row in cell["expected_rows"]:
            expected_row.pop("raw_timing_contract", None)
        fields = _SQRT_TIMING_HEADER.rstrip("\n").split(",")
        values = [""] * len(fields)
        values[fields.index("label")] = "revision_" + cell["cell_id"]
        values[fields.index("k")] = "128"
        values[fields.index("m")] = "128"
        values[fields.index("set_size")] = "1000"
        values[fields.index("comparison_eligible")] = "true"
        values[fields.index("encoding")] = "onehot"
        values[fields.index("trials")] = "1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_family_stdout(root, cell,
                                     _SQRT_TIMING_HEADER + ",".join(values) + "\n")
            cell_output(root, cell["cell_id"]).joinpath("stderr.log").write_text(
                "revision_terminal,schema=sqrt-revision-terminal-v1,"
                f"cell_id={cell['cell_id']},row_id=sqrt,status=NOT_APPLICABLE,"
                "terminal_status=NOT_APPLICABLE,reason=sqrt-m-not-perfect-square,"
                "reason_code=sqrt-m-not-perfect-square,measured_count=0\n",
                encoding="utf-8")
            _check_family_artifacts(root, "toy", [cell],
                                    {cell["cell_id"]: {"command": []}})

    def test_family_verifier_rejects_missing_canonical_raw_sidecar(self) -> None:
        """A RUN timing row with raw-phase-v1 authority cannot omit its sidecar."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output
        from verify_revision_benchmarks import (
            _SQRT_TIMING_HEADER, _check_family_artifacts,
            RevisionContractError)
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="timing_m", axis_value="128")
        fields = _SQRT_TIMING_HEADER.rstrip("\n").split(",")
        values = [""] * len(fields)
        values[fields.index("label")] = "revision_" + cell["cell_id"]
        values[fields.index("k")] = "128"
        values[fields.index("m")] = "128"
        values[fields.index("set_size")] = "1000"
        values[fields.index("comparison_eligible")] = "true"
        values[fields.index("encoding")] = "onehot"
        values[fields.index("trials")] = "1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            (output / "stdout.log").write_text(
                _SQRT_TIMING_HEADER + ",".join(values) + "\n",
                encoding="utf-8")
            (output / "stderr.log").write_text(
                "revision_terminal,schema=sqrt-revision-terminal-v1,"
                f"cell_id={cell['cell_id']},row_id=sqrt,status=NOT_APPLICABLE,"
                "terminal_status=NOT_APPLICABLE,reason=sqrt-m-not-perfect-square,"
                "reason_code=sqrt-m-not-perfect-square,measured_count=0\n",
                encoding="utf-8")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": []}) + "\n",
                encoding="utf-8")
            raw_dir = output / "raw"
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(
                    root, "toy", [cell],
                    {cell["cell_id"]: {"command": [
                        f"--raw_timing_dir={raw_dir}"]}})

    def test_raw_phase_v1_new_sqrt_positive_and_mutation_matrix(self) -> None:
        """The new raw contract accepts one toy artifact and rejects mutations."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _SQRT_TIMING_HEADER, _check_family_artifacts,
            RevisionContractError)

        source_cell = self.matrix_cell(
            "sqrt-comparison-csv-v1", family="sqrt_comparison",
            axis="timing_m", axis_value="128")
        cid = source_cell["cell_id"]
        phases = ("decrypt", "encode", "encrypt", "flood", "minhash",
                  "multiply", "rotate_sum", "total")
        producer = "bench_onehot_sqrt"
        profile = "readiness-toy-v1"
        raw_cell = cid + "::onehot"
        root_seed = 7

        def build(mutation: str | None = None) -> tuple[Path, dict, dict]:
            root = Path(tempfile.mkdtemp())
            output = cell_output(root, cid)
            output.mkdir(parents=True)
            fields = _SQRT_TIMING_HEADER.rstrip("\n").split(",")
            values = [""] * len(fields)
            primary = {
                "label": "revision_" + cid, "k": "128", "m": "128",
                "set_size": "1000", "encoding": "onehot", "trials": "1",
                "profile_id": profile, "run_class": "smoke",
                "target_security_bits": "0", "comparison_eligible": "false",
                "measurement_kind": "fhe-timing", "time_ms": "7.000",
                "time_ms_sd": "-1.000", "time_ms_median": "7.000",
            }
            for name, value in primary.items():
                values[fields.index(name)] = value
            for phase in phases:
                if phase == "total":
                    continue
                for suffix, value in (("", "1.000"), ("_sd", "-1.000"),
                                      ("_median", "1.000")):
                    values[fields.index("phase_" + phase + "_ms" + suffix)] = value
            for suffix, value in (("", "7.000"), ("_sd", "-1.000"),
                                  ("_median", "7.000")):
                values[fields.index("time_ms" + suffix)] = value
            (output / "stdout.log").write_text(
                _SQRT_TIMING_HEADER + ",".join(values) + "\n", encoding="utf-8")
            (output / "stderr.log").write_text(
                "revision_terminal,schema=sqrt-revision-terminal-v1,"
                f"cell_id={cid},row_id=sqrt,status=NOT_APPLICABLE,"
                "terminal_status=NOT_APPLICABLE,reason=sqrt-m-not-perfect-square,"
                "reason_code=sqrt-m-not-perfect-square,measured_count=0\n",
                encoding="utf-8")
            raw_dir = output / "raw"
            raw_dir.mkdir()
            samples: list[tuple[str, str, int, int, str]] = []
            for phase in sorted(phases):
                sample_phase = ("bogus" if mutation == "phase" and
                                phase == "encrypt" else phase)
                measured_index = 1 if mutation == "index" and phase == "encrypt" else 0
                measured_seed = (root_seed + 501 if mutation == "seed" and
                                 phase == "encrypt" else root_seed + 500)
                measured_value = "7" if phase == "total" else "1"
                samples.append((sample_phase, "discarded_warmup", 0,
                                root_seed, "1"))
                samples.append((sample_phase, "measured", measured_index,
                                measured_seed, measured_value))
            lines = [
                "schema_version\tpiccard-paper-raw-timing-v1",
                "artifact_type\traw_timing_v1", f"producer_id\t{producer}",
                f"profile_id\t{profile}", f"cell_id\t{raw_cell}",
                "warmup_policy\tdiscard_one", "expected_measured\t1", "samples",
                "sample\tproducer_id\tprofile_id\tcell_id\tphase\tsample_kind\t"
                "trial_index\tseed\traw_ms",
            ]
            for phase, kind, index, seed, value in samples:
                lines.append("\t".join(("sample", producer, profile, raw_cell,
                                        phase, kind, str(index), str(seed), value)))
            lines += [
                "aggregates",
                "aggregate\tproducer_id\tprofile_id\tcell_id\tphase\t"
                "measured_count\tmean_ms\tsample_sd_ms\tmedian_ms\t"
                "ci95_low_ms\tci95_high_ms\tformat_version",
            ]
            for phase in sorted(phases):
                mean = "2" if mutation == "aggregate" and phase == "encrypt" else (
                    "7" if phase == "total" else "1")
                count = "2" if mutation == "count" and phase == "encrypt" else "1"
                lines.append("\t".join(("aggregate", producer, profile, raw_cell,
                                        phase, count, mean, "N/A", mean, "N/A",
                                        "N/A", "17-digit")))
            safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_"
                            for ch in raw_cell) or "artifact"
            raw_path = raw_dir / f"{producer}__{safe}__{profile}.tsv"
            raw_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            if mutation == "extra":
                (raw_dir / "unrelated.tsv").write_text("not raw evidence\n",
                                                         encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n",
                                                  encoding="utf-8")
            cell = json.loads(json.dumps(source_cell))
            plan = {cid: {"command": [f"--profile={profile}", "--seed=7",
                                        f"--raw_timing_dir={raw_dir}"]}}
            return root, cell, plan

        root, cell, plan = build()
        try:
            _check_family_artifacts(root, "toy", [cell], plan)
        finally:
            import shutil
            shutil.rmtree(root)
        for mutation in ("seed", "phase", "index", "count", "aggregate", "extra"):
            with self.subTest(mutation=mutation):
                root, cell, plan = build(mutation)
                try:
                    with self.assertRaises(RevisionContractError):
                        _check_family_artifacts(root, "toy", [cell], plan)
                finally:
                    import shutil
                    shutil.rmtree(root)

    def test_raw_phase_v1_review_bcg_positive_and_workload_seed_mutation(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _REVIEW_HEADER, _check_family_artifacts, _review_taxonomy,
            RevisionContractError)
        from verify_review_comparison import expected_kind
        from tests.scripts import review_verifier_fixtures as fixture

        source_cell = self.matrix_cell(
            "review-comparison-csv-v1", family="bcg12_minhash",
            axis="control", axis_value="default")
        cid = source_cell["cell_id"]
        methods = ("bcg12_mh_ec", "bcg12_mh_ff")
        profile = "readiness-toy-v1"

        def build(mutate_workload: bool = False) -> tuple[Path, dict, dict]:
            root = Path(tempfile.mkdtemp())
            output = cell_output(root, cid)
            output.mkdir(parents=True)
            digest, trace_digest = self._write_versioned_review_sidecars(
                output, suite="revision-bcg12-minhash-v1", profile=profile,
                methods=methods, timing_trials=1, k=128, m=64,
                set_size=1000, universe=65536)
            fields = _REVIEW_HEADER.rstrip("\n").split(",")
            rows = []
            for method in methods:
                values = {
                    "suite": "revision-bcg12-minhash-v1",
                    "scenario": "review-65536", "method": method,
                    "profile_id": profile, "run_class": "smoke",
                    "target_security_bits": "0", "measurement_kind": expected_kind(method, "timing"),
                    "evidence_arm": "timing", "workload_id": f"review-65536-{digest[:16]}",
                    "workload_manifest_sha256": digest,
                    "execution_trace_sha256": trace_digest, "root_seed": "7",
                    "k": "128", "m": "64", "set_size": "1000",
                    "universe_size": "65536", "timing_trials": "1",
                    "accuracy_trials": "0", "trials": "1",
                    "hash_randomness": "fixed", "hash_seed": str(fixture._hash_seed(7, 1, 0)),
                    "total_ms": "3.000000", "total_ms_sd": "",
                    "total_ms_median": "3.000000",
                    "comparison_eligible": "false",
                }
                values.update(_review_taxonomy(method, 0, True))
                rows.append(",".join(values.get(field, "") for field in fields))
            (output / "stdout.log").write_text(
                _REVIEW_HEADER + "\n".join(rows) + "\n", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            raw_dir = output / "raw"
            raw_dir.mkdir()
            warmup_seed = fixture._trial_seed(7, 0, 0)
            measured_seed = fixture._trial_seed(7, 1, 0)
            for method in methods:
                raw_cell = cid + "::" + method
                safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_"
                                for ch in raw_cell)
                lines = [
                    "schema_version\tpiccard-paper-raw-timing-v1",
                    "artifact_type\traw_timing_v1",
                    "producer_id\tbench_review_comparison",
                    f"profile_id\t{profile}", f"cell_id\t{raw_cell}",
                    "warmup_policy\tdiscard_one", "expected_measured\t1", "samples",
                    "sample\tproducer_id\tprofile_id\tcell_id\tphase\tsample_kind\t"
                    "trial_index\tseed\traw_ms",
                    f"sample\tbench_review_comparison\t{profile}\t{raw_cell}\t"
                    f"total\tdiscarded_warmup\t0\t{warmup_seed}\t3",
                    f"sample\tbench_review_comparison\t{profile}\t{raw_cell}\t"
                    f"total\tmeasured\t0\t{measured_seed}\t3",
                    "aggregates",
                    "aggregate\tproducer_id\tprofile_id\tcell_id\tphase\t"
                    "measured_count\tmean_ms\tsample_sd_ms\tmedian_ms\t"
                    "ci95_low_ms\tci95_high_ms\tformat_version",
                    f"aggregate\tbench_review_comparison\t{profile}\t{raw_cell}\t"
                    "total\t1\t3\tN/A\t3\tN/A\tN/A\t17-digit",
                ]
                (raw_dir / f"bench_review_comparison__{safe}__{profile}.tsv").write_text(
                    "\n".join(lines) + "\n", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n",
                                                  encoding="utf-8")
            plan = {cid: {"command": [
                f"--revision-cell={cid}", f"--profile={profile}",
                "--suite=bcg12-minhash", "--methods=" + ",".join(methods),
                "--k=128", "--m=64", "--n=1000", "--universe=65536",
                "--trials=1", "--seed=7", f"--raw_timing_dir={raw_dir}",
                f"--output={output / 'comparison.csv'}"]}}
            if mutate_workload:
                payload = bytearray((output / "workload.bin").read_bytes())
                payload[-1] ^= 1
                (output / "workload.bin").write_bytes(payload)
            return root, source_cell, plan

        root, cell, plan = build()
        try:
            _check_family_artifacts(root, "toy", [cell], plan)
        finally:
            import shutil
            shutil.rmtree(root)
        root, cell, plan = build(True)
        try:
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], plan)
        finally:
            import shutil
            shutil.rmtree(root)

    def test_raw_phase_v1_sj16_calibration_positive_and_dispersion_mutations(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _check_family_artifacts, RevisionContractError)

        source_cell = self.matrix_cell(
            "sj16-calibration-v1", family="sj16",
            axis="fit", axis_value="per_element")
        cid = source_cell["cell_id"]
        profile = "readiness-toy-v1"
        base = 0xC0FFEE ^ (3072 << 8) ^ 7
        enc_seed = 0xE11C0DE5EED ^ 3072 ^ 7
        specs = [(cid + "::encrypt", "encrypt", enc_seed, enc_seed, "1.000000")]
        for size, value in ((4096, "1.000000"), (8192, "1.000000"),
                            (16384, "1.000000"), (32768, "33.000000")):
            query_base = (base ^ size) & ((1 << 64) - 1)
            specs.append((cid + f"::query_m={size}", "query",
                          query_base ^ 0x9E3779B97F4A7C15, query_base, value))

        def build(mutation: str | None = None) -> tuple[Path, dict, dict]:
            root = Path(tempfile.mkdtemp())
            output = cell_output(root, cid)
            output.mkdir(parents=True)
            text = self.full_sj16_fixture().replace(
                "k3072_t_enc median=1 iqr=0 samples=1",
                "k3072_t_enc median=1.000000 iqr=0.000000 samples=1.000000")
            for size in (4096, 8192, 16384):
                text = text.replace(
                    f"k3072_fit_m={size} median=1 q1=1 q3=1 iqr=0 samples=1",
                    f"k3072_fit_m={size} median=1.000000 q1=1.000000 "
                    "q3=1.000000 iqr=0.000000 samples=1.000000")
            text = text.replace(
                "k3072_heldout_m=32768 median=33 q1=33 q3=33 iqr=0 samples=33",
                "k3072_heldout_m=32768 median=33.000000 q1=33.000000 "
                "q3=33.000000 iqr=0.000000 samples=33.000000")
            (output / "calibration.csv").write_text(text, encoding="utf-8")
            (output / "stdout.log").write_text("", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            raw_dir = output / "raw"
            raw_dir.mkdir()
            for cell_id, phase, warmup_seed, measured_seed, measured in specs:
                value = ("2" if mutation == "sample" and cell_id.endswith("encrypt")
                         else measured)
                median = ("2" if mutation == "median" and cell_id.endswith("encrypt")
                          else value)
                aggregate_value = value.split(".", 1)[0]
                aggregate_median = median.split(".", 1)[0]
                safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_"
                                for ch in cell_id)
                lines = [
                    "schema_version\tpiccard-paper-raw-timing-v1",
                    "artifact_type\traw_timing_v1",
                    "producer_id\tbench_sj16_calibrate", f"profile_id\t{profile}",
                    f"cell_id\t{cell_id}", "warmup_policy\tdiscard_one",
                    "expected_measured\t1", "samples",
                    "sample\tproducer_id\tprofile_id\tcell_id\tphase\tsample_kind\t"
                    "trial_index\tseed\traw_ms",
                    f"sample\tbench_sj16_calibrate\t{profile}\t{cell_id}\t{phase}\t"
                    f"discarded_warmup\t0\t{warmup_seed}\t{measured}",
                    f"sample\tbench_sj16_calibrate\t{profile}\t{cell_id}\t{phase}\t"
                    f"measured\t0\t{measured_seed}\t{value}", "aggregates",
                    "aggregate\tproducer_id\tprofile_id\tcell_id\tphase\t"
                    "measured_count\tmean_ms\tsample_sd_ms\tmedian_ms\t"
                    "ci95_low_ms\tci95_high_ms\tformat_version",
                    f"aggregate\tbench_sj16_calibrate\t{profile}\t{cell_id}\t{phase}\t"
                    f"1\t{aggregate_value}\tN/A\t{aggregate_median}\tN/A\tN/A\t17-digit",
                ]
                (raw_dir / f"bench_sj16_calibrate__{safe}__{profile}.tsv").write_text(
                    "\n".join(lines) + "\n", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n",
                                                  encoding="utf-8")
            command = [f"--profile={profile}", "--key-bits=3072",
                       "--sizes=4096,8192,16384", "--held-out=32768",
                       "--threads=2", "--query-trials=1", "--enc-iters=1",
                       "--warmup=1", "--seed=7", f"--raw_timing_dir={raw_dir}",
                       f"--raw_timing_profile={profile}",
                       f"--output={output / 'calibration.csv'}"]
            return root, source_cell, {cid: {"command": command}}

        root, cell, plan = build()
        try:
            _check_family_artifacts(root, "toy", [cell], plan)
        finally:
            import shutil
            shutil.rmtree(root)
        for mutation in ("sample", "median"):
            with self.subTest(mutation=mutation):
                root, cell, plan = build(mutation)
                try:
                    with self.assertRaises(RevisionContractError):
                        _check_family_artifacts(root, "toy", [cell], plan)
                finally:
                    import shutil
                    shutil.rmtree(root)

    def test_raw_phase_v1_threshold_positive_and_aggregate_mutation(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _RAW_PHASES_THRESHOLD, _THRESHOLD_HEADER,
            _check_family_artifacts, RevisionContractError)

        cell = self.matrix_cell("threshold-csv-v1", family="threshold_timing",
                                axis="k", axis_value="128")
        cid = cell["cell_id"]
        profile = "readiness-toy-v1"
        root_seed = 7
        phases = {phase: 1.0 for phase in _RAW_PHASES_THRESHOLD}
        phases["total"] = 9.0

        def build(mutation: str | None = None) -> tuple[Path, dict, dict]:
            root = Path(tempfile.mkdtemp())
            output = cell_output(root, cid)
            output.mkdir(parents=True)
            row_values: dict[str, str] = {
                "label": cid, "k": "128", "m": "64", "set_size": "1000",
                "trials": "1", "hash_randomness": "fixed",
                "hash_seed": str(root_seed), "hash_root_seed": str(root_seed),
                "accuracy_trials": "0", "threshold_result": "1",
                "threshold_expected": "1", "threshold_correct": "1",
                "jaccard_computed": "0.5", "jaccard_expected": "0.5",
                "jaccard_error": "0", "jaccard_rel_error": "0",
            }
            field_for_phase = {
                "total": "total_ms", "minhash": "phase_minhash_ms",
                "encode": "phase_encode_ms", "encrypt": "phase_encrypt_ms",
                "multiply": "phase_multiply_ms",
                "rotate_sum": "phase_rotate_sum_ms", "mask": "phase_mask_ms",
                "poly_eval": "phase_poly_eval_ms", "flood": "phase_flood_ms",
                "decrypt": "phase_decrypt_ms",
            }
            for phase, field in field_for_phase.items():
                value = phases[phase]
                row_values[field] = format(value, ".3f")
                row_values[field + "_sd"] = "-1.000"
                row_values[field + "_median"] = format(value, ".3f")
            (output / "stdout.log").write_text(
                _THRESHOLD_HEADER + self.csv_row(_THRESHOLD_HEADER, **row_values) + "\n",
                encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            raw_dir = output / "raw"
            raw_dir.mkdir()
            safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_"
                            for ch in cid)
            lines = [
                "schema_version\tpiccard-paper-raw-timing-v1",
                "artifact_type\traw_timing_v1",
                "producer_id\tbench_threshold", f"profile_id\t{profile}",
                f"cell_id\t{cid}", "warmup_policy\tdiscard_one",
                "expected_measured\t1", "samples",
                "sample\tproducer_id\tprofile_id\tcell_id\tphase\tsample_kind\t"
                "trial_index\tseed\traw_ms",
            ]
            for phase in sorted(_RAW_PHASES_THRESHOLD):
                sample_phase = phase
                lines.append(
                    f"sample\tbench_threshold\t{profile}\t{cid}\t{sample_phase}\t"
                    f"discarded_warmup\t0\t{root_seed}\t{format(phases[phase], '.17g')}")
                measured_seed = root_seed + 500
                if mutation == "seed" and phase == "minhash":
                    measured_seed += 1
                lines.append(
                    f"sample\tbench_threshold\t{profile}\t{cid}\t{phase}\t"
                    f"measured\t0\t{measured_seed}\t{format(phases[phase], '.17g')}")
            lines.extend([
                "aggregates",
                "aggregate\tproducer_id\tprofile_id\tcell_id\tphase\t"
                "measured_count\tmean_ms\tsample_sd_ms\tmedian_ms\t"
                "ci95_low_ms\tci95_high_ms\tformat_version",
            ])
            for phase in sorted(_RAW_PHASES_THRESHOLD):
                mean = phases[phase]
                if mutation == "aggregate" and phase == "decrypt":
                    mean += 1.0
                lines.append(
                    f"aggregate\tbench_threshold\t{profile}\t{cid}\t{phase}\t"
                    f"1\t{format(mean, '.17g')}\tN/A\t{format(phases[phase], '.17g')}\t"
                    "N/A\tN/A\t17-digit")
            raw_name = f"bench_threshold__{safe}__{profile}.tsv"
            (raw_dir / raw_name).write_text("\n".join(lines) + "\n",
                                            encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n",
                                                  encoding="utf-8")
            command = [
                f"--revision-cell={cid}", f"--profile={profile}",
                "--security=TOY", "--mode=timing", "--k=128", "--m=64",
                "--set_size=1000", "--universe=65536", "--trials=1",
                "--seed=7", f"--raw_timing_dir={raw_dir}",
            ]
            return root, cell, {cid: {"command": command}}

        root, cell, plan = build()
        try:
            _check_family_artifacts(root, "toy", [cell], plan)
        finally:
            import shutil
            shutil.rmtree(root)
        for mutation in ("aggregate",):
            with self.subTest(mutation=mutation):
                root, cell, plan = build(mutation)
                try:
                    with self.assertRaises(RevisionContractError):
                        _check_family_artifacts(root, "toy", [cell], plan)
                finally:
                    import shutil
                    shutil.rmtree(root)

    def test_threshold_agreement_requires_eleven_points_and_fhe_agreement(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _THRESHOLD_HEADER, _check_family_artifacts, RevisionContractError)

        cell = self.matrix_cell("threshold-csv-v1",
                                family="threshold_agreement",
                                axis="k", axis_value="64")
        cid = cell["cell_id"]

        def build(disagreement: bool = False) -> tuple[Path, dict]:
            root = Path(tempfile.mkdtemp())
            output = cell_output(root, cid)
            output.mkdir(parents=True)
            rows = []
            for overlap_index in range(11):
                values = {
                    "label": f"{cid}::overlap_index={overlap_index}::trial=0",
                    "k": "64", "m": "64", "set_size": "1000",
                    "trials": "0", "accuracy_trials": "1",
                    "fhe_agrees": "0" if disagreement and overlap_index == 5 else "1",
                }
                rows.append(self.csv_row(_THRESHOLD_HEADER, **values))
            (output / "stdout.log").write_text(
                _THRESHOLD_HEADER + "\n".join(rows) + "\n", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            (output / "receipt.json").write_text(
                json.dumps({"artifact_inventory": file_inventory(
                    output, exclude={"stdout.log", "stderr.log", "receipt.json"})}) + "\n",
                encoding="utf-8")
            command = [
                f"--revision-cell={cid}", "--profile=readiness-toy-v1",
                "--mode=accuracy", "--cell=agreement", "--security=TOY",
                "--k=64", "--m=64", "--set_size=1000", "--trials=1",
                "--seed=7",
            ]
            return root, {cid: {"command": command}}

        root, plan = build()
        try:
            _check_family_artifacts(root, "toy", [cell], plan)
        finally:
            import shutil
            shutil.rmtree(root)

        root, plan = build(disagreement=True)
        try:
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], plan)
        finally:
            import shutil
            shutil.rmtree(root)

    def test_raw_phase_v1_real_manifest_bound_pair_identity_all_variants(self) -> None:
        """Real timing must bind the raw cell to the canonical processed data.

        The mutations update the primary CSV and, where applicable, the raw
        sidecar together.  A verifier that derives pair identity or hash
        seed from that CSV therefore accepts the forged evidence; only an
        independently loaded manifest contract rejects it.
        """
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _REAL_TIMING_HEADER, _RAW_PHASES_REAL, _raw_real_hash_seed,
            _check_family_artifacts, RevisionContractError)

        variants = (
            ("dblp_acm_u65536", "dblp_acm", 65536),
            ("enron_u65536", "enron", 65536),
            ("enron_u1048576", "enron", 1048576),
        )
        root_seed, k, m = 7, 128, 64
        profile = "readiness-toy-v1"

        def build(variant: str, dataset: str, universe: int,
                  mutation: str | None = None) -> tuple[Path, dict, dict]:
            root = Path(tempfile.mkdtemp())
            cell = self.matrix_cell(
                "real-dataset-csv-v1", family="real_dataset",
                axis=f"{variant}_artifact", axis_value="std128_timing")
            cid = cell["cell_id"]
            output = cell_output(root, cid)
            output.mkdir(parents=True)

            source_bytes = b"key\tvalue\nsource\thermetic-real-timing\n"
            (output / "source.manifest.tsv").write_bytes(source_bytes)
            records_bytes = (
                b"record_id\traw_feature_count\traw_features_csv\t"
                b"bucketed_feature_count\tbucketed_features_csv\n"
                b"a\t1\t1\t1\t1\n"
                b"b\t3\t1,2,3\t3\t2,3,4\n"
                b"c\t2\t5,6\t2\t5,6\n"
                b"d\t4\t7,8,9,10\t4\t7,8,9,10\n")
            pairs_bytes = (
                b"pair_id\trecord_a\trecord_b\tpair_kind\tlabel\n" +
                (b"pair_b\ta\tb\tknown_match\t1\n"
                 b"pair_a\tc\td\tsampled_nonmatch\t0\n"
                 if dataset == "dblp_acm" else
                 b"pair_b\ta\tb\tcross_thread\t-1\n"
                 b"pair_a\tc\td\tthread_related\t-1\n"))
            (output / "records.tsv").write_bytes(records_bytes)
            (output / "pairs.tsv").write_bytes(pairs_bytes)
            digest = lambda payload: hashlib.sha256(payload).hexdigest()
            manifest_pairs = [
                ("schema_version", "piccard-real-processed-v1"),
                ("dataset", dataset), ("variant", variant),
                ("preprocessing_version", "dblp-acm-trigram-v1" if
                 dataset == "dblp_acm" else "enron-shingle5-v2"),
                ("universe_size", str(universe)), ("seed", "7"),
                ("source_manifest_file", "source.manifest.tsv"),
                ("source_manifest_sha256", digest(source_bytes)),
                ("records_file", "records.tsv"),
                ("records_sha256", digest(records_bytes)),
                ("record_count", "4"), ("pairs_file", "pairs.tsv"),
                ("pairs_sha256", digest(pairs_bytes)), ("pair_count", "2"),
                ("raw_set_size_min", "1"), ("raw_set_size_median", "2"),
                ("raw_set_size_p95", "4"), ("raw_set_size_max", "4"),
                ("bucketed_set_size_min", "1"),
                ("bucketed_set_size_median", "2"),
                ("bucketed_set_size_p95", "4"),
                ("bucketed_set_size_max", "4"),
                ("original_positive_count", "1" if dataset == "dblp_acm" else "0"),
                ("retained_positive_count", "1" if dataset == "dblp_acm" else "0"),
                ("requested_pair_count", "2"),
                ("max_documents", "" if dataset == "dblp_acm" else "4"),
                ("min_related_pairs", "" if dataset == "dblp_acm" else "1"),
            ]
            if dataset == "enron":
                manifest_pairs.append(
                    ("pair_proxy", "canonical-subject-proxy-not-thread-ground-truth-v1"))
            manifest_pairs.extend(
                (key, "0") for key in (
                    ("dropped.empty_features_dblp", "dropped.empty_features_acm")
                    if dataset == "dblp_acm" else
                    ("dropped.charset_or_mime", "dropped.empty_body",
                     "dropped.short_body", "dropped.duplicate_copy",
                     "dropped.duplicate_message_id")))
            manifest_bytes = ("key\tvalue\n" + "".join(
                f"{key}\t{value}\n" for key, value in manifest_pairs)).encode()
            (output / "dataset.manifest.tsv").write_bytes(manifest_bytes)
            manifest_digest = digest(manifest_bytes)

            # real_timing_driver.cpp selects pair_a: combined sizes are 4 and
            # 6, so both are equally distant from median 5 and pair_a wins the
            # lexical tie-break even though pairs.tsv lists pair_b first.
            selected_pair = "pair_a"
            selected_a, selected_b = "c", "d"
            selected_kind, selected_label = (
                ("sampled_nonmatch", "0") if dataset == "dblp_acm" else
                ("thread_related", "-1"))
            row_pair, row_a, row_b = selected_pair, selected_a, selected_b
            row_digest = manifest_digest
            if mutation == "pair":
                row_pair, row_a, row_b = "pair_b", "a", "b"
                selected_kind, selected_label = (
                    ("known_match", "1") if dataset == "dblp_acm" else
                    ("cross_thread", "-1"))
            elif mutation == "endpoints":
                row_a, row_b = "a", "b"
            elif mutation == "manifest_digest":
                row_digest = "0" * 64

            real_seed = _raw_real_hash_seed(
                root_seed, row_digest, k, m, profile, cid)
            raw_cell = f"real_timing:{variant}:{row_pair}:k={k}:m={m}"
            phases = {phase: 1.0 for phase in _RAW_PHASES_REAL}
            phases["total"] = 8.0
            row_values: dict[str, str] = {
                "profile_id": profile, "run_class": "smoke",
                "target_security_bits": "0", "comparison_eligible": "false",
                "comparison_scope": "full-protocol", "primitive": "piccard",
                "protocol_model": "piccard-ckks", "output_semantics": "jaccard",
                "assurance_scope": "readiness", "security_basis": "toy",
                "cost_scope": "full-query", "precomputation_mode": "off",
                "secure_division_included": "true", "measurement_kind": "timing",
                "workload_id": "w0", "workload_manifest_sha256": "b" * 64,
                "execution_trace_sha256": "b" * 64, "root_seed": str(root_seed),
                "omp_threads": "1", "estimator_model": "none",
                "sanitizer_model": "none", "sanitizer_assurance": "none",
                "transcript_stat_bits": "0", "max_queries": "1",
                "query_stat_bits": "0", "coefficient_stat_bits": "0",
                "flood_margin_bits": "0", "eval_noise_bits": "0",
                "flood_noise_bits": "0", "actual_ring_dim": "4096",
                "log_q_bits": "0", "plaintext_modulus": "0", "num_limbs": "1",
                "openfhe_version": "toy", "target_semantics": "jaccard",
                "target_jaccard": "0.5", "realized_intersection": "1",
                "realized_union": "2", "realized_jaccard": "0.5",
                "timing_trials": "1", "accuracy_trials": "0",
                "omp_dynamic": "false", "measurement_status": "measured",
                "dataset": dataset, "variant": variant,
                "dataset_manifest_sha256": row_digest,
                "records_sha256": digest(records_bytes),
                "pairs_sha256": digest(pairs_bytes), "pair_id": row_pair,
                "pair_kind": selected_kind, "label": selected_label,
                "record_a": row_a, "record_b": row_b, "k": str(k), "m": str(m),
                "hash_seed": str(real_seed), "trial_index": "0",
                "phase_minhash_ms": "1", "phase_encode_ms": "1",
                "phase_encrypt_ms": "1", "phase_cloud_multiply_ms": "1",
                "phase_cloud_rotate_ms": "1", "phase_sanitize_ms": "1",
                "phase_decrypt_ms": "1", "phase_bias_correction_ms": "1",
                "total_query_ms": "8", "result_value": "0.5",
                "ciphertext_bytes": "1", "upload_bytes": "1", "download_bytes": "1",
            }
            (output / "timing.csv").write_text(
                _REAL_TIMING_HEADER + self.csv_row(_REAL_TIMING_HEADER,
                                                    **row_values) + "\n",
                encoding="utf-8")
            (output / "stdout.log").write_text("", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            raw_dir = output / "raw"
            raw_dir.mkdir()
            safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_"
                            for ch in raw_cell)
            lines = [
                "schema_version\tpiccard-paper-raw-timing-v1",
                "artifact_type\traw_timing_v1", "producer_id\treal_timing",
                f"profile_id\t{profile}", f"cell_id\t{raw_cell}",
                "warmup_policy\tdiscard_one", "expected_measured\t1", "samples",
                "sample\tproducer_id\tprofile_id\tcell_id\tphase\tsample_kind\t"
                "trial_index\tseed\traw_ms",
            ]
            for phase in sorted(_RAW_PHASES_REAL):
                sample_phase = ("wrong_phase" if mutation == "phase" and
                                phase == "phase_minhash_ms" else phase)
                lines.append(
                    f"sample\treal_timing\t{profile}\t{raw_cell}\t{sample_phase}\t"
                    f"discarded_warmup\t0\t{real_seed}\t{format(phases[phase], '.17g')}")
                measured_seed = real_seed + (1 if mutation == "seed" and
                                              phase == "phase_minhash_ms" else 0)
                lines.append(
                    f"sample\treal_timing\t{profile}\t{raw_cell}\t{phase}\t"
                    f"measured\t0\t{measured_seed}\t{format(phases[phase], '.17g')}")
            lines.extend([
                "aggregates",
                "aggregate\tproducer_id\tprofile_id\tcell_id\tphase\t"
                "measured_count\tmean_ms\tsample_sd_ms\tmedian_ms\t"
                "ci95_low_ms\tci95_high_ms\tformat_version",
            ])
            for phase in sorted(_RAW_PHASES_REAL):
                value = phases[phase]
                lines.append(
                    f"aggregate\treal_timing\t{profile}\t{raw_cell}\t{phase}\t"
                    f"1\t{format(value, '.17g')}\tN/A\t{format(value, '.17g')}\t"
                    "N/A\tN/A\t17-digit")
            (raw_dir / f"real_timing__{safe}__{profile}.tsv").write_text(
                "\n".join(lines) + "\n", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt) + "\n",
                                                  encoding="utf-8")
            command = [
                f"--revision-cell={cid}", f"--profile={profile}",
                "--raw-timing-profile=readiness-toy-v1", "--security=TOY",
                "--mode=timing", f"--dataset={dataset}", f"--variant={variant}",
                f"--dataset-manifest={output / 'dataset.manifest.tsv'}",
                "--k=128", "--m=64", "--set_size=1000",
                f"--universe={universe}", "--trials=1", "--seed=7",
                f"--csv={output / 'timing.csv'}", f"--raw-timing-dir={raw_dir}",
            ]
            return root, cell, {cid: {"command": command}}

        for variant, dataset, universe in variants:
            with self.subTest(variant=variant, mutation="positive"):
                root, cell, plan = build(variant, dataset, universe)
                try:
                    _check_family_artifacts(root, "toy", [cell], plan)
                finally:
                    import shutil
                    shutil.rmtree(root)
            for mutation in ("pair", "endpoints", "manifest_digest", "seed", "phase"):
                with self.subTest(variant=variant, mutation=mutation):
                    root, cell, plan = build(variant, dataset, universe, mutation)
                    try:
                        with self.assertRaises(RevisionContractError):
                            _check_family_artifacts(root, "toy", [cell], plan)
                    finally:
                        import shutil
                        shutil.rmtree(root)

    def test_family_verifier_accepts_real_versioned_encoding_pair(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REAL_ENCODING_HEADER, _check_family_artifacts)
        from revision_benchmark_common import cell_output
        cell = self.matrix_cell("real-dataset-csv-v1", family="real_dataset",
                                axis_value="std192_encoding",
                                axis="dblp_acm_u65536_artifact")
        fields = _REAL_ENCODING_HEADER.rstrip("\n").split(",")
        rows = []
        for method in ("piccard_encode", "piccard_sqrt_encode"):
            values = [""] * len(fields)
            values[fields.index("dataset")] = "dblp_acm"
            values[fields.index("variant")] = "dblp_acm_u65536"
            values[fields.index("k")] = "128"
            values[fields.index("m")] = "64"
            values[fields.index("target_security_bits")] = "192"
            values[fields.index("comparison_eligible")] = "false"
            values[fields.index("comparison_scope")] = "encoding-only-diagnostic"
            values[fields.index("cost_scope")] = "encoding-only"
            values[fields.index("secure_division_included")] = "false"
            values[fields.index("method")] = method
            values[fields.index("timed_encoder_pairs")] = "1"
            values[fields.index("correctness_pair_calls")] = "1"
            values[fields.index("signature_derivation_timed")] = "false"
            values[fields.index("correctness_status")] = "PASS"
            rows.append(",".join(values))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            command = self.write_artifact(
                root, cell, "encoding.csv",
                _REAL_ENCODING_HEADER + "\n".join(rows) + "\n",
                "--csv=")
            _check_family_artifacts(root, "toy", [cell],
                                    {cell["cell_id"]: {"command": command}})

    def test_family_verifier_accepts_sj16_calibration_contract(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("sj16-calibration-v1", family="sj16",
                                axis="fit", axis_value="per_element")
        cell = json.loads(json.dumps(cell))
        for expected_row in cell["expected_rows"]:
            expected_row.pop("raw_timing_contract", None)
        text = self.full_sj16_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(root, cell, "calibration.csv", text)
            _check_family_artifacts(root, "toy", [cell],
                                    {cell["cell_id"]: {"command": command}})

    def test_family_verifier_accepts_nested_noise_shard_contract(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory, sha256_file
        from revision_flooding_adapter import select_noise_partition
        from verify_revision_benchmarks import _check_family_artifacts
        cell = self.matrix_cell("noise-profile-v1", family="flooding",
                                axis="profile", axis_value="primary40")
        matrix = json.loads((ROOT / "scripts" / "noise_profiles.json").read_text())
        partition = select_noise_partition(matrix, "primary40")
        key_id = partition["key_id"]
        source_commit = "a" * 40
        tracked_manifest = (ROOT / "scripts" / "noise_profiles.json").read_bytes()
        self.assertEqual(tracked_manifest.count(b"runtime-source-commit"), 1)
        resolved_manifest = tracked_manifest.replace(
            b"runtime-source-commit", source_commit.encode("ascii"), 1)

        def seed_for(consumer_k: int, consumer_m: int, pattern: str,
                     rep_index: int = 0) -> str:
            payload = (f"{matrix['root_seed']}\n{key_id}\nN8192-d1-s40\n"
                       f"{consumer_k}:{consumer_m}\n{pattern}\n{rep_index}\n")
            return str(int.from_bytes(
                hashlib.sha256(payload.encode("ascii")).digest()[:8], "big"))

        self.assertEqual(seed_for(128, 64, "zero"), "9883777269193876463")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = cell_output(root, cell["cell_id"])
            shard = output / "payload" / "profiles" / "primary40" / key_id
            details = shard / "details"
            details.mkdir(parents=True)
            payload = output / "payload"
            (payload / "run_manifest.json").write_text(json.dumps({
                "schema": "piccard-noise-revision-run-v1", "profile_id": "primary40",
                "run_profile": "readiness-toy-v1", "status": "READINESS_ONLY",
                "table_eligible": False, "repetitions_per_pattern": 1,
                "patterns": ["zero", "random", "adversarial"], "invocation_count": 1}),
                encoding="utf-8")
            (payload / "resolved_noise_profiles.json").write_bytes(resolved_manifest)
            (payload / "profiles" / "primary40" / "profile_manifest.json").write_text(
                json.dumps({"schema": "piccard-noise-revision-profile-v1",
                            "profile_id": "primary40", "key_count": 1,
                            "key_verdicts": {key_id: "SELECTED"},
                            "source_commit": source_commit,
                            "profile_verdict": "READINESS_ONLY",
                            "table_eligible": False}), encoding="utf-8")
            (shard / "revision_identity.json").write_text(json.dumps({
                "schema": "piccard-noise-revision-shard-v1",
                "cell_id": cell["cell_id"], "run_profile": "readiness-toy-v1",
                "profile_id": "primary40", "key_id": key_id,
                "source_commit": source_commit,
                "consumer_points": partition["consumer_points"],
                "consumer_set_sha256": partition["consumer_set_sha256"],
                "repetitions_per_pattern": 1,
                "patterns": ["zero", "random", "adversarial"],
                "status": "READINESS_ONLY", "table_eligible": False}), encoding="utf-8")
            aggregate_header = (
                "profile,circuit,shape_id,security,consumer_count,consumer_set_sha256,"
                "worst_consumer_k,worst_consumer_m,pattern_count,repetitions_per_pattern,"
                "detail_row_count,detail_sha256,seed,requested_ring_dim,natural_ring_dim,"
                "realized_ring_dim,ring_growth_factor,ring_dim_calibrated,natural_depth,"
                "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,log_delta,"
                "eval_noise_bits,headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
                "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,openfhe_version,"
                "source_commit,status_code,error_message,consumer_results_sha256\n")
            aggregate = [""] * len(aggregate_header.rstrip("\n").split(","))
            af = aggregate_header.rstrip("\n").split(",")
            for name, value in (("profile", "primary40"),
                                ("source_commit", source_commit),
                                ("seed", str(matrix["root_seed"])),
                                ("consumer_count", str(len(partition["consumer_points"]))),
                                ("consumer_set_sha256", partition["consumer_set_sha256"]),
                                ("pattern_count", "3"),
                                ("repetitions_per_pattern", "1"),
                                ("detail_row_count", str(len(partition["consumer_points"]) * 3))):
                aggregate[af.index(name)] = value
            (shard / "aggregate.csv").write_text(
                aggregate_header + ",".join(aggregate) + "\n", encoding="utf-8")
            detail_header = (
                "profile,key_id,candidate_id,circuit,shape_id,security,consumer_k,consumer_m,"
                "pattern,rep_index,rep_seed,requested_ring_dim,natural_ring_dim,"
                "ring_dim_calibrated,realized_ring_dim,ring_growth_factor,natural_depth,"
                "provisioned_depth,scaling_mod_size,num_limbs,plaintext_mod,log_q,log_delta,"
                "eval_noise_bits,headroom_bits,max_queries,query_stat_bits,coefficient_stat_bits,"
                "flood_margin_bits,flood_noise_bits,decrypt_ok,saturated,ct_bytes,openfhe_version,"
                "source_commit,status_code,error_message\n")
            df = detail_header.rstrip("\n").split(",")
            detail_rows = []
            for k, m in ((str(p["k"]), str(p["m"]))
                         for p in partition["consumer_points"]):
                for pattern in ("zero", "random", "adversarial"):
                    values = [""] * len(df)
                    for name, value in (("profile", "primary40"), ("key_id", key_id),
                                        ("source_commit", source_commit),
                                        ("candidate_id", "N8192-d1-s40"),
                                        ("consumer_k", k), ("consumer_m", m),
                                        ("pattern", pattern), ("rep_index", "0"),
                                        ("rep_seed", seed_for(int(k), int(m), pattern))):
                        values[df.index(name)] = value
                    detail_rows.append(",".join(values))
            (details / "N8192-d1-s40.csv").write_text(
                detail_header + "\n".join(detail_rows) + "\n", encoding="utf-8")
            aggregate[af.index("ring_dim_calibrated")] = "8192"
            aggregate[af.index("provisioned_depth")] = "1"
            aggregate[af.index("scaling_mod_size")] = "40"
            aggregate[af.index("detail_sha256")] = sha256_file(
                details / "N8192-d1-s40.csv")
            aggregate[af.index("status_code")] = "OK"
            (shard / "aggregate.csv").write_text(
                aggregate_header + ",".join(aggregate) + "\n", encoding="utf-8")
            (shard / "candidates.json").write_text(json.dumps({
                "schema": "piccard-candidate-manifest", "version": 1,
                "key_id": key_id, "source_commit": source_commit,
                "openfhe_version": partition["openfhe_version"],
                "profile_id": "primary40", "circuit": partition["circuit"],
                "shape_id": partition["shape_id"], "security": partition["security"],
                "requested_ring_dim": partition["requested_ring_dim"],
                "natural_depth": partition["natural_depth"],
                "consumer_points": partition["consumer_points"],
                "consumer_set_sha256": partition["consumer_set_sha256"],
                "command": [], "candidate_count": 1,
                "candidates": [{"candidate_id": "N8192-d1-s40",
                                "status_code": "OK",
                                "detail_sha256": sha256_file(details / "N8192-d1-s40.csv"),
                                "detail_row_count": len(detail_rows)}]},
                sort_keys=True), encoding="utf-8")
            (output / "stdout.log").write_text("", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            _check_family_artifacts(root, "toy", [cell], {cell["cell_id"]: {
                "command": ["scripts/run_noise_profiles.sh",
                            f"--results-root={payload}"]}})
            from verify_revision_benchmarks import RevisionContractError
            resolved_path = payload / "resolved_noise_profiles.json"
            self.assertEqual(resolved_path.read_bytes(), resolved_manifest)
            detail_path = details / "N8192-d1-s40.csv"
            original_detail = detail_path.read_bytes()
            check_plan = {cell["cell_id"]: {
                "command": ["scripts/run_noise_profiles.sh",
                            f"--results-root={payload}"]}}

            resolved_path.write_bytes(json.dumps({
                "source_commit": source_commit, "profiles": []}).encode("utf-8"))
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], check_plan)
            resolved_path.write_bytes(resolved_manifest)

            expected_seed = seed_for(16, 64, "zero").encode("ascii")
            detail_path.write_bytes(original_detail.replace(expected_seed, b"1", 1))
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], check_plan)
            detail_path.write_bytes(original_detail)
            detail_path.write_bytes(original_detail.replace(expected_seed, b"", 1))
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], check_plan)
            detail_path.write_bytes(original_detail)

            detail_lines = original_detail.splitlines(keepends=True)
            detail_lines[1], detail_lines[2] = detail_lines[2], detail_lines[1]
            detail_path.write_bytes(b"".join(detail_lines))
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], check_plan)
            detail_path.write_bytes(original_detail)

            identity_path = shard / "revision_identity.json"
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
            identity["consumer_points"] = [{"k": 128, "m": 999}]
            identity_path.write_text(json.dumps(identity), encoding="utf-8")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], {cell["cell_id"]: {
                    "command": ["scripts/run_noise_profiles.sh",
                                f"--results-root={payload}"]}})

    def test_c1_review_wrong_axes_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REVIEW_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("review-comparison-csv-v1", family="bcg12_minhash",
                                axis="control", axis_value="default")
        rows = [self.csv_row(_REVIEW_HEADER, method=method, k=128, m=64,
                             set_size=1000, universe_size=65536, trials=1)
                for method in ("bcg12_mh_ec", "bcg12_mh_ff")]
        rows[0] = self.csv_row(_REVIEW_HEADER, method="bcg12_mh_ec", k=999,
                               m=64, set_size=1000, universe_size=65536,
                               trials=1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _REVIEW_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_std192_review_wrong_axes_taxonomy_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REVIEW_ENCODING_HEADER, _check_family_artifacts,
            RevisionContractError)
        cell = self.matrix_cell("review-encoding-csv-v1",
                                family="piccard_std192_encoding",
                                axis="control", axis_value="default")
        rows = [self.csv_row(_REVIEW_ENCODING_HEADER, method=method,
                             target_security_bits=128, comparison_eligible="false",
                             comparison_scope="encoding-only-diagnostic", k=128,
                             m=64, timed_encoder_pairs=1,
                             correctness_pair_calls=1, correctness_status="PASS")
                for method in ("piccard_encode", "piccard_sqrt_encode")]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _REVIEW_ENCODING_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_estimator_wrong_shape_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _ESTIMATOR_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("estimator-diagnostic-csv-v1",
                                family="estimator_accuracy", axis="j",
                                axis_value="0.0")
        row = self.csv_row(_ESTIMATOR_HEADER, estimator_model="sha256-random-ranking-poc-v1",
                           k=128, m=64, set_size=1000, target_jaccard="0.9",
                           trials=1, seed=7)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _ESTIMATOR_HEADER, [row])
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_sqrt_accuracy_wrong_shape_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _SQRT_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="accuracy_m", axis_value="16")
        rows = [self.csv_row(_SQRT_HEADER, encoding="OneHot", k=128, m=32),
                self.csv_row(_SQRT_HEADER, encoding="Sqrt", k=128, m=16)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _SQRT_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_sqrt_crossover_wrong_shape_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _CROSSOVER_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("sqrt-comparison-csv-v1", family="sqrt_comparison",
                                axis="crossover_m", axis_value="16")
        row = self.csv_row(_CROSSOVER_HEADER, k=128, m=64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _CROSSOVER_HEADER, [row])
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_threshold_fpfn_forged_science_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify_threshold_outputs as fpfn
        from verify_revision_benchmarks import (
            _THRESHOLD_FPFN_HEADER, _check_family_artifacts,
            RevisionContractError)
        cell = self.matrix_cell("threshold-fpfn-csv-v1",
                                family="threshold_synthetic_fpfn",
                                axis="point", axis_value="k128_j0")
        point = fpfn._point(128, 0)
        seed = fpfn.row_seed(7, 128, 0, 0)
        match = fpfn._canonical_match_count(point, seed)
        decision = int(match >= point["tau_count"])
        truth = int(point["realized_j"] >= point["j_tau"])
        probability = fpfn._binomial_survival(
            128, point["tau_count"], point["realized_j"] +
            (1.0 - point["realized_j"]) / 64.0)
        row = self.csv_row(
            _THRESHOLD_FPFN_HEADER, schema_version=fpfn.SCHEMA_VERSION,
            profile="readiness-toy-v1", security="TOY",
            estimator_model=fpfn.ESTIMATOR_MODEL, hash_randomness="resampled",
            root_seed=7, k=128, m=64, set_size=1000,
            tau_count=point["tau_count"], j_tau=point["j_tau"], grid_index=0,
            target_j=point["target_j"], signed_delta=point["signed_delta"],
            absolute_delta=point["absolute_delta"], alpha=point["alpha"],
            realized_intersection=point["realized_intersection"],
            realized_union=point["realized_union"], realized_j=point["realized_j"],
            trial_index=0, row_seed=seed, match_count=match, decision=decision,
            exact_j_truth=truth,
            outcome=("TP" if truth and decision else
                     "TN" if not truth and not decision else
                     "FP" if decision else "FN"),
            predicted_decision_probability=probability,
            predicted_error_probability=(1.0 - probability if truth else probability),
            gaussian_error_approx=fpfn.gaussian_error_approx(point["realized_j"], 128))
        row = row.split(",")
        fields = _THRESHOLD_FPFN_HEADER.rstrip("\n").split(",")
        row[fields.index("predicted_decision_probability")] = "0.5"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _THRESHOLD_FPFN_HEADER,
                                   [",".join(row)])
            plan = {cell["cell_id"]: {"command": [
                "--profile=readiness-toy-v1", "--security=TOY", "--mode=fpfn",
                "--point-k=128", "--grid-index=0", "--m=64",
                "--set_size=1000", "--trials=1", "--seed=7"]}}
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell], plan)

    def test_c1_piccard_double_count_per_row_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _SQRT_TIMING_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("piccard-benchmark-csv-v1", family="piccard_std128",
                                axis="control", axis_value="default")
        rows = [self.csv_row(_SQRT_TIMING_HEADER, label=cell["cell_id"],
                             encoding="onehot", k=128, m=64, set_size=1000,
                             trials=1, accuracy_trials=1),
                self.csv_row(_SQRT_TIMING_HEADER, label=cell["cell_id"],
                             encoding="onehot", k=128, m=64, set_size=1000,
                             trials=1, accuracy_trials=1)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_stdout_rows(root, cell, _SQRT_TIMING_HEADER, rows)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": []}})

    def test_c1_sj16_missing_fit_topology_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts, RevisionContractError
        cell = self.matrix_cell("sj16-calibration-v1", family="sj16",
                                axis="fit", axis_value="per_element")
        text = self.full_sj16_fixture().replace(
            "k3072_fit_m=8192 median=1 q1=1 q3=1 iqr=0 samples=1\n", "")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(root, cell, "calibration.csv", text)
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": command}})

    def test_c1_real_std192_forged_taxonomy_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REAL_ENCODING_HEADER, _check_family_artifacts, RevisionContractError)
        cell = self.matrix_cell("real-dataset-csv-v1", family="real_dataset",
                                axis_value="std192_encoding",
                                axis="dblp_acm_u65536_artifact")
        rows = [self.csv_row(_REAL_ENCODING_HEADER, profile_id="paper-std192-encoding-v1",
                             run_class="primary", target_security_bits=192,
                             comparison_eligible="false",
                             comparison_scope="full-protocol", dataset="dblp_acm",
                             variant="dblp_acm_u65536", k=128, m=64, method=method,
                             timed_encoder_pairs=1, correctness_pair_calls=1,
                             correctness_status="PASS")
                for method in ("piccard_encode", "piccard_sqrt_encode")]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(
                root, cell, "encoding.csv", _REAL_ENCODING_HEADER +
                "\n".join(rows) + "\n", "--csv=")
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": command}})

    def test_c1_real_threshold_truth_forgery_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _REAL_THRESHOLD_HEADER, _check_family_artifacts,
            _threshold_seed, _threshold_tau, _threshold_boundary,
            RevisionContractError)
        cell = self.matrix_cell("real-threshold-csv-v1",
                                family="threshold_dblp_fpfn")
        requested = 0.25
        tau = _threshold_tau(requested, 128, 64)
        realized = _threshold_boundary(tau, 128, 64)
        row = self.csv_row(
            _REAL_THRESHOLD_HEADER, schema_version="piccard-real-threshold-v1",
            dataset="dblp_acm", variant="dblp_acm_u65536", pair_id="p0",
            pair_kind="sampled_nonmatch", label=0, record_a="a", record_b="b",
            k=128, m=64, hash_randomness="resampled", root_seed=7,
            split="evaluation", rank_position=1, threshold_trial_index=0,
            hash_seed=_threshold_seed(7, "p0", 0), match_count=0, decision=0,
            label_truth=1, label_outcome="TN", exact_j_truth=1,
            exact_j_outcome="FN", exact_jaccard_bucketed=0.5,
            requested_j_threshold=requested, tau_count=tau,
            realized_j_tau=realized, calibration_fpr=0.0,
            calibration_fnr=0.0, calibration_balanced_error=0.0,
            threshold_workload_sha256="a" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = self.write_artifact(
                root, cell, "threshold.csv", _REAL_THRESHOLD_HEADER + row + "\n",
                "--csv=")
            command += ["--seed=7", "--threshold-trials=1"]
            with self.assertRaises(RevisionContractError):
                _check_family_artifacts(root, "toy", [cell],
                                        {cell["cell_id"]: {"command": command}})

    def test_real_threshold_science_uses_evaluation_workload_rows_only(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _REAL_THRESHOLD_HEADER, _check_family_artifacts,
            _threshold_boundary, _threshold_seed, _threshold_tau,
            RevisionContractError)
        cell = self.matrix_cell("real-threshold-csv-v1",
                                family="threshold_dblp_fpfn")
        requested = 0.25
        tau = _threshold_tau(requested, 128, 64)
        realized = _threshold_boundary(tau, 128, 64)
        evaluation_pair = "evaluation-pair"
        calibration_pair = "calibration-pair"
        output_row = {
            "schema_version": "piccard-real-threshold-v1",
            "dataset": "dblp_acm", "variant": "dblp_acm_u65536",
            "dataset_manifest_sha256": "a" * 64,
            "records_sha256": "b" * 64, "pairs_sha256": "c" * 64,
            "pair_id": evaluation_pair, "pair_kind": "sampled_nonmatch",
            "label": "0", "record_a": "evaluation-a", "record_b": "evaluation-b",
            "k": "128", "m": "64", "hash_randomness": "resampled",
            "root_seed": "7", "split": "evaluation", "rank_position": "1",
            "threshold_trial_index": "0",
            "hash_seed": str(_threshold_seed(7, evaluation_pair, 0)),
            "match_count": "0", "decision": "0", "label_truth": "0",
            "label_outcome": "TN", "exact_j_truth": "0",
            "exact_j_outcome": "TN", "exact_jaccard_bucketed": "0",
            "requested_j_threshold": str(requested), "tau_count": str(tau),
            "realized_j_tau": str(realized), "calibration_fpr": "0",
            "calibration_fnr": "0", "calibration_balanced_error": "0",
            "calibration_digest": "d" * 64, "evaluation_digest": "e" * 64,
            "threshold_workload_sha256": "f" * 64,
        }
        workload_header = (
            "pair_id\tlabel\tsplit\trank_position\trecord_a\trecord_b\t"
            "exact_jaccard_bucketed\n")
        base_workload = [
            (calibration_pair, "0", "calibration", "0", "calibration-a",
             "calibration-b", "0"),
            (evaluation_pair, "0", "evaluation", "1", "evaluation-a",
             "evaluation-b", "0"),
        ]
        def write_fixture(root: Path, *, row: dict[str, str] = output_row,
                          workload: list[tuple[str, ...]] = base_workload) -> list[str]:
            output = cell_output(root, cell["cell_id"])
            output.mkdir(parents=True)
            (output / "threshold.csv").write_text(
                _REAL_THRESHOLD_HEADER + self.csv_row(_REAL_THRESHOLD_HEADER,
                                                       **row) + "\n",
                encoding="utf-8")
            workload_text = workload_header + "".join(
                "\t".join(values) + "\n" for values in workload)
            (output / "threshold.rows.tsv").write_text(
                workload_text, encoding="utf-8")
            (output / "stdout.log").write_text("", encoding="utf-8")
            (output / "stderr.log").write_text("", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(
                json.dumps(receipt) + "\n", encoding="utf-8")
            return [f"--csv={output / 'threshold.csv'}", "--seed=7",
                    "--threshold-trials=1",
                    f"--workload-rows-out={output / 'threshold.rows.tsv'}"]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "valid"
            command = write_fixture(root)
            _check_family_artifacts(
                root, "toy", [cell], {cell["cell_id"]: {"command": command}})

            mutations: dict[str, tuple[dict[str, str], list[tuple[str, ...]]]] = {}
            leaked = dict(output_row)
            leaked["pair_id"] = calibration_pair
            mutations["calibration pair leaked to output"] = (leaked, base_workload)
            mutations["missing evaluation pair"] = (
                output_row, [base_workload[0]])
            mutations["extra evaluation pair"] = (
                output_row, base_workload + [
                    ("extra-evaluation-pair", "0", "evaluation", "2",
                     "extra-a", "extra-b", "0")])
            mutations["duplicate workload pair"] = (
                output_row, base_workload + [base_workload[0]])
            malformed_split = list(base_workload)
            malformed_split[0] = (calibration_pair, "0", "unknown", "0",
                                  "calibration-a", "calibration-b", "0")
            mutations["malformed split"] = (output_row, malformed_split)
            malformed_rank = list(base_workload)
            malformed_rank[0] = (calibration_pair, "0", "calibration", "bad",
                                  "calibration-a", "calibration-b", "0")
            mutations["malformed rank"] = (output_row, malformed_rank)
            for label, (row, workload) in mutations.items():
                with self.subTest(label=label):
                    case_root = Path(temporary) / label.replace(" ", "_")
                    case_command = write_fixture(
                        case_root, row=dict(row), workload=list(workload))
                    with self.assertRaises(RevisionContractError):
                        _check_family_artifacts(
                            case_root, "toy", [cell],
                            {cell["cell_id"]: {"command": case_command}})

    def test_r5_blank_canonical_axes_are_rejected_across_schema_families(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape, RevisionContractError
        cases = (
            ("review-comparison-csv-v1", "bcg12_minhash"),
            ("deletion-survival-csv-v1", "deletion_mc"),
            ("dynamic-benchmark-csv-v1", "dynamic_timing"),
            ("estimator-diagnostic-csv-v1", "estimator_accuracy"),
            ("fhe-ind-csv-v1", "fhe_ind"),
            ("piccard-benchmark-csv-v1", "piccard_std128"),
            ("sqrt-comparison-csv-v1", "sqrt_comparison"),
            ("threshold-csv-v1", "threshold_timing"),
        )
        for schema, family in cases:
            with self.subTest(schema=schema, family=family):
                cell = self.matrix_cell(schema, family=family)
                with self.assertRaises(RevisionContractError):
                    _bind_cell_shape([{"k": ""}], cell,
                                     {"command": []}, cell["cell_id"])

    def test_r5_review_security_taxonomy_forgery_is_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape, RevisionContractError
        cell = self.matrix_cell("review-comparison-csv-v1",
                                family="bcg12_minhash",
                                axis="control", axis_value="default")
        row = {
            "k": "128", "m": "64", "set_size": "1000",
            "universe_size": "65536", "comparison_eligible": "true",
            "suite": "revision-bcg12-minhash-v1", "scenario": "review-65536",
            "method": "bcg12_mh_ec", "cryptographic_profile": "FORGED-FHE",
            "nominal_security_bits": "128", "security_match": "true",
            "comparison_scope": "matched-estimator-component",
            "primitive": "bcg12-ec",
            "protocol_model": "bcg12-cardinality-on-minhash",
            "output_semantics": "minhash-collision-jaccard-estimate",
            "assurance_scope": "implemented-baseline-parameter-map",
            "security_basis": "nist-p256-parameter-map",
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
            "secure_division_included": "false", "workload_id": "w",
            "workload_manifest_sha256": "a" * 64,
            "execution_trace_sha256": "b" * 64,
        }
        with self.assertRaises(RevisionContractError):
            _bind_cell_shape([row], cell, {"command": []}, cell["cell_id"])

    def test_r5_review_security_taxonomy_actual_shape_is_accepted(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape
        cell = self.matrix_cell("review-comparison-csv-v1",
                                family="bcg12_minhash",
                                axis="control", axis_value="default")
        base = {
            "k": "128", "m": "64", "set_size": "1000",
            "universe_size": "65536",
            "suite": "revision-bcg12-minhash-v1", "scenario": "review-65536",
            "method": "bcg12_mh_ec", "cryptographic_profile": "P-256",
            "nominal_security_bits": "128",
            "comparison_scope": "matched-estimator-component",
            "primitive": "bcg12-ec",
            "protocol_model": "bcg12-cardinality-on-minhash",
            "output_semantics": "minhash-collision-jaccard-estimate",
            "assurance_scope": "implemented-baseline-parameter-map",
            "security_basis": "nist-p256-parameter-map",
            "cost_scope": "full-query-excluding-one-time-setup",
            "precomputation_mode": "crs-and-keys-only",
            "secure_division_included": "false", "workload_id": "w",
            "workload_manifest_sha256": "a" * 64,
            "execution_trace_sha256": "b" * 64,
        }
        for abstract_profile, row_profile, run_class, target, match, eligible in (
                ("readiness-toy-v1", "readiness-toy-v1", "smoke", "0",
                 "false", "false"),
                ("paper-v1", "std128-t40-primary", "primary", "128",
                 "true", "true")):
            with self.subTest(profile=abstract_profile):
                row = dict(base, profile_id=row_profile, run_class=run_class,
                           target_security_bits=target, security_match=match,
                           comparison_eligible=eligible)
                command = [f"--profile={abstract_profile}",
                           "--suite=bcg12-minhash", "--security=STD128",
                           "--k=128", "--m=64", "--n=1000",
                           "--universe=65536"]
                _bind_cell_shape([row], cell, {"command": command},
                                 cell["cell_id"])

    @staticmethod
    def _write_versioned_review_sidecars(output: Path, *, suite: str,
                                         profile: str, methods: tuple[str, ...],
                                         timing_trials: int, k: int = 16,
                                         m: int = 16, set_size: int = 10,
                                         universe: int = 64, seed: int = 7):
        """Emit the C++ BE wire format without invoking a producer.

        This deliberately duplicates the small serialization contract rather
        than importing a producer helper.  In particular, the versioned
        encoding wire contains a correctness-count field and kind-3 record
        with its own hash domain.  The resulting bytes are consumed by the
        independent verifier and execution-trace parser exactly as producer
        artifacts are.
        """
        import hashlib
        from tests.scripts import review_verifier_fixtures as fixture
        from verify_revision_benchmarks import _correctness_hash_seed

        encoding = set(methods) <= {"piccard_encode", "piccard_sqrt_encode"}
        correctness_trials = 1 if encoding else 0
        accuracy_trials = 0
        records = [(0, 0)]
        records.extend((1, index) for index in range(timing_trials))
        records.extend((3, index) for index in range(correctness_trials))
        intersection = fixture._realized_intersection(set_size, 1, 2)
        workload = bytearray(fixture.WORKLOAD_DOMAIN)
        workload.extend(fixture._string(suite))
        workload.extend(fixture._string(profile))
        workload.extend(fixture._be64(seed))
        for value in (k, m, set_size, universe, 1, 2):
            workload.extend(fixture._be64(value))
        workload.extend(fixture._be32(len(methods)))
        for method in methods:
            workload.extend(fixture._string(method))
        workload.extend(fixture._be32(timing_trials))
        workload.extend(fixture._be32(accuracy_trials))
        if encoding:
            workload.extend(fixture._be32(correctness_trials))
        workload.extend(fixture._be32(len(records)))
        encoded = []
        for kind, index in records:
            trial_seed = fixture._trial_seed(seed, kind, index)
            if kind == 3:
                hash_value = _correctness_hash_seed(seed, index)
            else:
                hash_value = fixture._hash_seed(seed, kind, index)
            set_a, set_b = fixture._regenerate_sets(
                universe, set_size, intersection, trial_seed)
            encoded.append((kind, index, trial_seed))
            workload.extend(bytes([kind]) + fixture._be32(index) +
                            fixture._be64(trial_seed) + fixture._be64(hash_value))
            for values in (set_a, set_b):
                workload.extend(fixture._be64(len(values)))
                for value in values:
                    workload.extend(fixture._be64(value))
            workload.extend(fixture._be64(intersection) +
                            fixture._be64(2 * set_size - intersection))
        workload_bytes = bytes(workload)
        workload_digest = hashlib.sha256(workload_bytes).digest()
        trace = bytearray(fixture.TRACE_DOMAIN + workload_digest)
        trace.extend(fixture._be32(len(records)) + fixture._be32(len(records)))
        for kind, index, trial_seed in encoded:
            offset = trial_seed % len(methods)
            order = methods[offset:] + methods[:offset]
            trace.extend(bytes([kind]) + fixture._be32(index) +
                         fixture._be32(len(methods)) + fixture._be32(len(methods)) + b"\0")
            for method in order:
                trace.extend(fixture._string(method))
        trace_bytes = bytes(trace)
        (output / "workload.bin").write_bytes(workload_bytes)
        (output / "execution-trace.bin").write_bytes(trace_bytes)
        return workload_digest.hex(), hashlib.sha256(trace_bytes).hexdigest()

    def _bind_versioned_fixture(self, *, cell: dict, mode: str, profile: str,
                                suite: str, methods: tuple[str, ...],
                                timing_trials: int, m: int = 16):
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_review_sidecars
        from verify_review_comparison import expected_kind
        # Keep KATs tiny while retaining the exact family/suite/profile and
        # row applicability topology.  The production verifier binds these
        # same fields to the canonical matrix dimensions in its outer call.
        cell = dict(cell)
        cell["axes"] = {"k": 16, "m": m, "n": 10, "u": 64}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            workload_digest, trace_digest = self._write_versioned_review_sidecars(
                output, suite=suite, profile=profile, methods=methods,
                timing_trials=timing_trials, m=m)
            rows = [{
                "method": method, "evidence_arm": "timing",
                "measurement_kind": expected_kind(method, "timing"),
                "workload_id": f"review-64-{workload_digest[:16]}",
                "workload_manifest_sha256": workload_digest,
                "execution_trace_sha256": trace_digest,
            } for method in methods]
            plan = {"command": [f"--profile={profile}", "--seed=7"]}
            _bind_review_sidecars(output, rows, cell, plan, mode, cell["cell_id"])
            return output

    def _write_full_versioned_encoding_fixture(
            self, root: Path, *, cell: dict, mode: str,
            command_profile: str, row_profile: str,
            methods: tuple[str, ...], timing_trials: int) -> dict:
        """Write a producer-shaped review-encoding cell for the full verifier.

        The planner command deliberately carries the abstract paper profile
        in paper mode, while the wire row/workload carries the concrete
        profile emitted by the revision adapter.  This is the boundary where
        the family verifier must apply the same mapping as its sidecar path.
        """
        from revision_benchmark_common import cell_output, file_inventory
        from tests.scripts import review_verifier_fixtures as fixture
        from verify_review_comparison import expected_kind
        from verify_revision_benchmarks import _REVIEW_ENCODING_HEADER

        cid = cell["cell_id"]
        output = cell_output(root, cid)
        output.mkdir(parents=True, exist_ok=True)
        axes = cell["axes"]
        k, m, set_size, universe = (
            int(axes[name]) for name in ("k", "m", "n", "u"))
        workload_digest, trace_digest = self._write_versioned_review_sidecars(
            output, suite="revision-std192-encoding-v1", profile=row_profile,
            methods=methods, timing_trials=timing_trials, k=k, m=m,
            set_size=set_size, universe=universe, seed=7)
        realized_intersection = fixture._realized_intersection(set_size, 1, 2)
        realized_union = 2 * set_size - realized_intersection
        hash_seed = fixture._hash_seed(7, 1, 0)
        run_class = "smoke" if mode == "toy" else "primary"
        target_bits = "0" if mode == "toy" else "192"
        rows = []
        for method in methods:
            sqrt = method == "piccard_sqrt_encode"
            feature_dimension = (k * 2 * int(m ** 0.5)
                                 if sqrt else k * m)
            encoded_slots = 1 << (feature_dimension - 1).bit_length()
            values = {
                "suite": "revision-std192-encoding-v1",
                "scenario": f"review-{universe}",
                "method": method,
                "profile_id": row_profile,
                "run_class": run_class,
                "target_security_bits": target_bits,
                "cryptographic_profile": "local-encoding-only",
                "nominal_security_bits": "",
                "security_match": "false",
                "comparison_eligible": "false",
                "comparison_scope": "encoding-only-diagnostic",
                "primitive": "sqrt-encoding" if sqrt else "onehot-encoding",
                "protocol_model": ("piccard-sqrt-local-encoding"
                                    if sqrt else "piccard-local-encoding"),
                "output_semantics": "encoded-feature-vector",
                "assurance_scope": "deterministic-encoder-correctness",
                "security_basis": "local-encoding-no-cryptographic-security-claim",
                "cost_scope": "encoding-only",
                "precomputation_mode": "not-applicable",
                "secure_division_included": "false",
                "measurement_kind": expected_kind(method, "timing"),
                "evidence_arm": "timing",
                "workload_id": f"review-{universe}-{workload_digest[:16]}",
                "workload_manifest_sha256": workload_digest,
                "execution_trace_sha256": trace_digest,
                "root_seed": "7",
                "omp_threads": "1",
                "omp_dynamic": "false",
                "k": str(k),
                "m": str(m),
                "set_size": str(set_size),
                "universe_size": str(universe),
                "target_semantics": "jaccard",
                "target_jaccard_numerator": "1",
                "target_jaccard_denominator": "2",
                "target_jaccard": "0.5",
                "realized_intersection": str(realized_intersection),
                "realized_union": str(realized_union),
                "realized_jaccard": str(realized_intersection / realized_union),
                "timing_trials": str(timing_trials),
                "accuracy_trials": "0",
                "correctness_trials": "1",
                "trials": str(timing_trials),
                "hash_randomness": "fixed",
                "hash_seed": str(hash_seed),
                "encoder_input_construction": "canonical-minhash-signatures-untimed",
                "encoder_warmup_pairs": "1",
                "timed_encoder_pairs": str(timing_trials),
                "correctness_pair_calls": "1",
                "signature_derivation_timed": "false",
                "encode_a_ms": "0.1",
                "encode_b_ms": "0.2",
                "encode_pair_ms": "0.3",
                "encoded_slots_a": str(encoded_slots),
                "encoded_slots_b": str(encoded_slots),
                "correctness_feature_sha256_a": "a" * 64,
                "correctness_feature_sha256_b": "b" * 64,
                "correctness_status": "PASS",
                "measurement_status": "measured",
            }
            fields = _REVIEW_ENCODING_HEADER.rstrip("\n").split(",")
            rows.append(",".join(values.get(field, "") for field in fields))
        (output / "stdout.log").write_text(
            _REVIEW_ENCODING_HEADER + "\n".join(rows) + "\n", encoding="utf-8")
        (output / "stderr.log").write_text("", encoding="utf-8")
        (output / "receipt.json").write_text(
            json.dumps({"artifact_inventory": []}) + "\n", encoding="utf-8")
        terminal = "".join(
            "revision_terminal,schema=review-encoding-terminal-v1,"
            f"cell_id={cid},row_id={item['row_id']},status={item['status']},"
            f"terminal_status={item['terminal_status']},reason={item['reason']},"
            f"reason_code={item['reason_code']},measured_count="
            f"{item['toy_measured_count'] if mode == 'toy' else item['paper_measured_count']}\n"
            for item in cell["expected_rows"])
        (output / "stderr.log").write_text(terminal, encoding="utf-8")
        receipt = json.loads((output / "receipt.json").read_text())
        receipt["artifact_inventory"] = file_inventory(
            output, exclude={"stdout.log", "stderr.log", "receipt.json"})
        (output / "receipt.json").write_text(
            json.dumps(receipt) + "\n", encoding="utf-8")
        plan = {
            "command": [
                f"--revision-cell={cid}", f"--profile={command_profile}",
                "--suite=encoding", "--methods=piccard_encode,piccard_sqrt_encode",
                "--security=STD192", f"--k={k}", f"--m={m}",
                f"--n={set_size}", f"--universe={universe}",
                f"--encoding-iters={timing_trials}",
                "--correctness-trials=1", "--seed=7",
                f"--output={output / 'encoding.csv'}",
            ]
        }
        return plan

    def test_r8_encoding_full_path_kat_accepts_toy_and_paper_square_and_nonsquare(self) -> None:
        """Versioned encoding rows pass the same full family path as producers."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _check_family_artifacts

        cases = (
            ("toy", "readiness-toy-v1", "readiness-toy-v1", 1),
            ("paper", "paper-v1", "paper-std192-encoding-v1", 30),
        )
        for mode, command_profile, row_profile, timing_trials in cases:
            for axis_value, methods in (
                    ("64", ("piccard_encode", "piccard_sqrt_encode")),
                    ("32", ("piccard_encode",))):
                with self.subTest(mode=mode, m=axis_value):
                    cell = self.matrix_cell(
                        "review-encoding-csv-v1", family="piccard_std192_encoding",
                        axis="m", axis_value=axis_value)
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        plan = self._write_full_versioned_encoding_fixture(
                            root, cell=cell, mode=mode,
                            command_profile=command_profile,
                            row_profile=row_profile, methods=methods,
                            timing_trials=timing_trials)
                        _check_family_artifacts(root, mode, [cell],
                                                {cell["cell_id"]: plan})

    def test_r7_encoding_wire_kat_accepts_toy_and_paper_square_and_nonsquare(self) -> None:
        """The exact C++ versioned wire is accepted in all encoding branches."""
        for mode, profile, timing in (("toy", "readiness-toy-v1", 1),
                                      ("paper", "paper-std192-encoding-v1", 30)):
            for axis_value, methods in (
                    ("16", ("piccard_encode", "piccard_sqrt_encode")),
                    ("32", ("piccard_encode",))):
                with self.subTest(mode=mode, m=axis_value):
                    cell = self.matrix_cell(
                        "review-encoding-csv-v1", family="piccard_std192_encoding",
                        axis="m", axis_value=axis_value)
                    self._bind_versioned_fixture(
                        cell=cell, mode=mode, profile=profile,
                        suite="revision-std192-encoding-v1", methods=methods,
                        timing_trials=timing, m=int(axis_value))

    def test_r7_review_wire_kat_accepts_producer_suites_and_profiles(self) -> None:
        """BCG12 MinHash/exact and SJ16 use the concrete revision suite IDs."""
        cases = (
            ("bcg12_minhash", "revision-bcg12-minhash-v1",
             ("bcg12_mh_ec", "bcg12_mh_ff")),
            ("bcg12_exact", "revision-bcg12-exact-v1",
             ("bcg12_exact_ec", "bcg12_exact_ff")),
            ("sj16", "revision-sj16-v1", ("sj16",)),
        )
        for family, suite, methods in cases:
            with self.subTest(family=family):
                cell = self.matrix_cell("review-comparison-csv-v1",
                                        family=family, axis="control",
                                        axis_value="default")
                self._bind_versioned_fixture(
                    cell=cell, mode="paper", profile="std128-t40-primary",
                    suite=suite, methods=methods, timing_trials=30)

    def test_r7_versioned_correctness_hash_domain_mutation_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import (
            _bind_review_sidecars, RevisionContractError)
        from verify_review_comparison import expected_kind
        cell = self.matrix_cell("review-encoding-csv-v1",
                                family="piccard_std192_encoding",
                                axis="m", axis_value="16")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            digest, trace_digest = self._write_versioned_review_sidecars(
                output, suite="revision-std192-encoding-v1",
                profile="readiness-toy-v1",
                methods=("piccard_encode", "piccard_sqrt_encode"),
                timing_trials=1)
            data = bytearray((output / "workload.bin").read_bytes())
            # The last record is kind=3; flip its hash-seed byte while leaving
            # the record topology and all set payload bytes intact.  For this
            # fixture n=10, so the fixed BE wire length of one trial is 213.
            record_start = len(data) - 213
            hash_start = record_start + 1 + 4 + 8
            data[hash_start] ^= 1
            (output / "workload.bin").write_bytes(data)
            rows = [{"method": method, "evidence_arm": "timing",
                     "measurement_kind": expected_kind(method, "timing"),
                     "workload_id": f"review-64-{digest[:16]}",
                     "workload_manifest_sha256": digest,
                     "execution_trace_sha256": trace_digest}
                    for method in ("piccard_encode", "piccard_sqrt_encode")]
            with self.assertRaises(RevisionContractError):
                _bind_review_sidecars(
                    output, rows, cell,
                    {"command": ["--profile=readiness-toy-v1", "--seed=7"]},
                    "toy", cell["cell_id"])

    def test_r5_encoding_signature_timing_forgery_is_rejected(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _bind_cell_shape, RevisionContractError
        cell = self.matrix_cell("real-dataset-csv-v1", family="real_dataset",
                                axis_value="std192_encoding")
        row = {
            "k": "128", "m": "64", "dataset": "dblp_acm",
            "variant": "dblp_acm_u65536", "target_security_bits": "192",
            "comparison_eligible": "false",
            "comparison_scope": "encoding-only-diagnostic",
            "cost_scope": "encoding-only", "secure_division_included": "false",
            "signature_derivation_timed": "true",
        }
        with self.assertRaises(RevisionContractError):
            _bind_cell_shape([row], cell, {"command": []}, cell["cell_id"])

    def test_raw_phase_v1_actual_shape_kat_and_mutation_matrix(self) -> None:
        """Piccard/FHE-IND raw-phase-v1 is independent, canonical evidence."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from revision_benchmark_common import cell_output, file_inventory
        from verify_revision_benchmarks import (
            _FHE_IND_HEADER, _SQRT_TIMING_HEADER, _check_family_artifacts,
            RevisionContractError)

        def safe(value: str) -> str:
            return "".join(ch if ch.isalnum() or ch in "_.-" else "_"
                           for ch in value) or "artifact"

        def raw_payload(producer: str, cid: str, profile: str, count: int,
                        root_seed: int, *, mutate: str | None = None) -> str:
            phases = (("bias_correction", 8.0), ("decrypt", 7.0),
                      ("encode", 2.0), ("encrypt", 3.0),
                      ("evaluate", 5.0), ("flood", 6.0),
                      ("full_e2e", 38.0), ("minhash", 1.0),
                      ("multiply", 4.0), ("online_e2e", 17.0),
                      ("rotate_sum", 5.0), ("setup_context", 10.0),
                      ("setup_keygen", 11.0), ("total", 36.0))
            wanted = {"bench_piccard": {
                "bias_correction", "decrypt", "encode", "encrypt",
                "flood", "minhash", "multiply", "rotate_sum", "total"},
                "bench_fhe_ind": {
                "decrypt", "encode", "encrypt", "evaluate", "full_e2e",
                "online_e2e", "setup_context", "setup_keygen"}}[producer]
            phases = tuple((phase, base) for phase, base in phases
                           if phase in wanted)
            rows: list[tuple[str, str, int, int, float]] = []
            for phase, base in phases:
                if producer == "bench_piccard":
                    rows.append((phase, "discarded_warmup", 0, root_seed,
                                 base + 0.25))
                for trial in range(count):
                    seed = (root_seed + trial * 10007 + 500
                            if producer == "bench_piccard" else root_seed + trial)
                    increment = 0.25
                    if producer == "bench_piccard" and phase == "total":
                        increment = 2.0
                    elif producer == "bench_fhe_ind" and phase == "online_e2e":
                        increment = 1.0
                    elif producer == "bench_fhe_ind" and phase == "full_e2e":
                        increment = 1.5
                    rows.append((phase, "measured", trial, seed,
                                 base + trial * increment))
            if mutate == "swapped_index":
                if count < 2:
                    raise AssertionError("swap mutation needs paper count")
                first = next(i for i, row in enumerate(rows)
                             if row[1] == "measured" and row[2] == 0)
                second = next(i for i, row in enumerate(rows)
                              if row[1] == "measured" and row[2] == 1)
                left, right = rows[first], rows[second]
                rows[first] = (left[0], left[1], 1, left[3], left[4])
                rows[second] = (right[0], right[1], 0, right[3], right[4])
            if mutate in {"duplicate_index", "missing_index"}:
                index = next(i for i, row in enumerate(rows)
                             if row[1] == "measured" and row[2] == count - 1)
                row = rows[index]
                rows[index] = (row[0], row[1], count - 2, row[3], row[4])
            if mutate == "seed":
                index = next(i for i, row in enumerate(rows)
                             if row[1] == "measured")
                row = rows[index]
                rows[index] = (row[0], row[1], row[2], row[3] + 1, row[4])
            if mutate == "warmup_kind":
                index = next(i for i, row in enumerate(rows)
                             if row[1] == ("discarded_warmup" if
                                           producer == "bench_piccard" else
                                           "measured"))
                row = rows[index]
                rows[index] = (row[0],
                               "measured" if producer == "bench_piccard"
                               else "discarded_warmup",
                               row[2], row[3], row[4])
            if mutate == "warmup_value":
                index = next(i for i, row in enumerate(rows)
                             if row[1] == ("discarded_warmup" if
                                           producer == "bench_piccard" else
                                           "measured"))
                row = rows[index]
                rows[index] = (row[0], row[1], row[2], row[3], row[4] + 9.0)
            if mutate == "warmup_nonfinite":
                index = next(i for i, row in enumerate(rows)
                             if row[1] == "discarded_warmup")
                row = rows[index]
                rows[index] = (row[0], row[1], row[2], row[3], float("nan"))
            if mutate == "warmup_negative":
                index = next(i for i, row in enumerate(rows)
                             if row[1] == "discarded_warmup")
                row = rows[index]
                rows[index] = (row[0], row[1], row[2], row[3], -1.0)

            values_by_phase: dict[str, list[float]] = {phase: [] for phase, _ in phases}
            for phase, kind, _trial, _seed, value in rows:
                if kind == "measured":
                    values_by_phase[phase].append(value)
            lines = ["schema_version\tpiccard-paper-raw-timing-v1",
                     "artifact_type\traw_timing_v1",
                     f"producer_id\t{producer}", f"profile_id\t{profile}",
                     f"cell_id\t{cid}",
                     f"warmup_policy\t{'discard_one' if producer == 'bench_piccard' else 'none'}",
                     f"expected_measured\t{count}", "samples",
                     "sample\tproducer_id\tprofile_id\tcell_id\tphase\tsample_kind\ttrial_index\tseed\traw_ms"]
            # Canonical serializer order is phase, warmup-before-measured, trial.
            for phase, _base in phases:
                phase_rows = [row for row in rows if row[0] == phase]
                phase_rows.sort(key=lambda row: (row[1] != "discarded_warmup", row[2]))
                for _phase, kind, trial, seed, value in phase_rows:
                    lines.append("\t".join(("sample", producer, profile, cid,
                                              phase, kind, str(trial), str(seed),
                                              format(value, ".17g"))))
            lines += ["aggregates",
                      "aggregate\tproducer_id\tprofile_id\tcell_id\tphase\tmeasured_count\tmean_ms\tsample_sd_ms\tmedian_ms\tci95_low_ms\tci95_high_ms\tformat_version"]
            for phase, _base in sorted(phases):
                values = values_by_phase[phase]
                mean = sum(values) / len(values)
                median = values[len(values) // 2] if len(values) % 2 else (
                    values[len(values) // 2 - 1] + values[len(values) // 2]) / 2.0
                if len(values) == 1:
                    sd = low = high = "N/A"
                else:
                    sd_value = (sum((value - mean) ** 2 for value in values) /
                                (len(values) - 1)) ** 0.5
                    # The frozen producer uses Student-t 95% values; mutation
                    # tests only need a structurally valid aggregate, so use a
                    # deterministic zero-width CI for the toy positive case.
                    margin = 0.0 if count == 1 else 2.045229642132703 * sd_value / count ** 0.5
                    sd, low, high = (format(item, ".17g") for item in
                                     (sd_value, mean - margin, mean + margin))
                if mutate == "aggregate" and phase == sorted(phases)[0][0]:
                    mean = mean + 1.0
                lines.append("\t".join(("aggregate", producer, profile, cid,
                                        phase, str(count), format(mean, ".17g"),
                                        sd, format(median, ".17g"), low, high,
                                        "17-digit")))
            return "\n".join(lines) + "\n"

        def write_case(root: Path, producer: str, mode: str,
                       mutation: str | None = None) -> tuple[dict, dict, Path]:
            family = "piccard_std128" if producer == "bench_piccard" else "fhe_ind"
            schema = ("piccard-benchmark-csv-v1" if producer == "bench_piccard"
                      else "fhe-ind-csv-v1")
            cell = self.matrix_cell(schema, family=family,
                                    axis="control", axis_value="default")
            cid = cell["cell_id"]
            output = cell_output(root, cid)
            output.mkdir(parents=True)
            count = 1 if mode == "toy" else 30
            profile = "readiness-toy-v1" if mode == "toy" else "paper-v1"
            row_profile = (profile if mode == "toy" else
                           "paper-std128-t40-v1")
            seed = 7
            if producer == "bench_piccard":
                phase_values = {"bias_correction": 8.0, "decrypt": 7.0,
                                "encode": 2.0, "encrypt": 3.0, "flood": 6.0,
                                "minhash": 1.0, "multiply": 4.0,
                                "rotate_sum": 5.0, "total": 36.0}
                fields = {"label": cid, "k": 128, "m": 64,
                          "set_size": 1000, "trials": count,
                          "accuracy_trials": 0, "profile_id": row_profile,
                          "run_class": "smoke" if mode == "toy" else "primary",
                          "target_security_bits": 0 if mode == "toy" else 128,
                          "comparison_eligible": "false" if mode == "toy" else "true",
                          "hash_seed": seed, "hash_root_seed": seed,
                          "measurement_kind": "fhe-timing"}
                for phase, value in phase_values.items():
                    name = "time_ms" if phase == "total" else f"phase_{phase}_ms"
                    increment = 2.0 if phase == "total" else 0.25
                    mean = value + increment * (count - 1) / 2.0
                    sd = -1.0 if count == 1 else (
                        (sum((value + increment * trial - mean) ** 2
                             for trial in range(count)) / (count - 1)) ** 0.5)
                    fields[name] = format(mean, ".3f")
                    fields[f"{name}_sd"] = format(sd, ".3f")
                    fields[f"{name}_median"] = format(mean, ".3f")
                timing = self.csv_row(_SQRT_TIMING_HEADER, **fields)
                accuracy = self.csv_row(
                    _SQRT_TIMING_HEADER, label=cid, k=128, m=64,
                    set_size=1000, trials=50 if mode == "paper" else 1,
                    accuracy_trials=50 if mode == "paper" else 1,
                    profile_id=row_profile,
                    run_class="smoke" if mode == "toy" else "primary",
                    target_security_bits=0 if mode == "toy" else 128,
                    comparison_eligible="false" if mode == "toy" else "true",
                    measurement_kind="fhe-accuracy")
                (output / "stdout.log").write_text(
                    _SQRT_TIMING_HEADER + timing + "\n" + accuracy + "\n",
                    encoding="utf-8")
                raw_dir = output
                command = [f"--revision-cell={cid}",
                           f"--profile={'readiness-toy-v1' if mode == 'toy' else 'paper-std128-t40-v1'}",
                           "--mode=combined", "--security=TOY" if mode == "toy" else "--security=STD128",
                           "--k=128", "--m=64", "--set_size=1000", "--universe=65536",
                           f"--trials={count}", f"--accuracy_trials={1 if mode == 'toy' else 50}",
                           f"--seed={seed}", f"--raw_timing_dir={raw_dir}",
                           f"--revision-identity-out={output / 'identity.csv'}"]
                raw_name = f"bench_piccard__{safe(cid)}__{profile}.tsv"
            else:
                fields = {"cell_id": cid, "circuit": "fhe_ind", "shape_id": "fhe-ind",
                          "security": "TOY" if mode == "toy" else "STD128",
                          "k": "N/A", "m": "N/A", "universe": 65536,
                          "set_size": 1000, "seed": 0, "trials": count,
                          "timing_hash_seed": 0,
                          "status": "DIAGNOSTIC", "method": "fhe_ind"}
                phase_values = {"setup_context": 10.0, "setup_keygen": 11.0,
                                "encode": 2.0, "encrypt": 3.0, "evaluate": 5.0,
                                "decrypt": 7.0, "online_e2e": 17.0,
                                "full_e2e": 38.0}
                for phase, value in phase_values.items():
                    fields[{"encode": "phase_encode_ms", "encrypt": "phase_encrypt_ms",
                            "evaluate": "phase_evaluate_ms", "decrypt": "phase_decrypt_ms",
                            "online_e2e": "online_e2e_ms", "full_e2e": "full_e2e_ms"}.get(phase, phase + "_ms")] = format(value, ".17g")
                (output / "fhe_ind.csv").write_text(
                    _FHE_IND_HEADER + self.csv_row(_FHE_IND_HEADER, **fields) + "\n",
                    encoding="utf-8")
                raw_dir = output / "raw"
                raw_dir.mkdir()
                command = [f"--revision-cell={cid}", "--mode=e2e",
                           f"--cell-id={cid}",
                           f"--security={'TOY' if mode == 'toy' else 'STD128'}",
                           "--n=1000", "--universe=65536", f"--trials={count}",
                           f"--raw-timing-out={raw_dir}",
                           f"--raw-timing-profile={profile}", f"--seed={seed}",
                           f"--output={output / 'fhe_ind.csv'}",
                           f"--revision-identity-out={output / 'identity.csv'}"]
                raw_name = f"bench_fhe_ind__{safe(cid)}__{profile}.tsv"
            identity = ("schema,cell_id,universe_size\n"
                        f"piccard-revision-cell-v1,{cid},{cell['axes']['u']}\n"
                        if producer == "bench_piccard" else "identity\n")
            (output / "identity.csv").write_text(identity, encoding="utf-8")
            if producer == "bench_fhe_ind":
                (output / "stdout.log").write_text("", encoding="utf-8")
            raw_path = raw_dir / raw_name
            raw_text = raw_payload(
                producer, cid, profile, count,
                seed if producer == "bench_piccard" else 0,
                mutate=mutation)
            if mutation == "header":
                raw_text = raw_text.replace(
                    "schema_version\tpiccard-paper-raw-timing-v1",
                    "schema_version\twrong-raw-timing-v1", 1)
            raw_path.write_text(raw_text, encoding="utf-8")
            if mutation == "wrong_path":
                wrong_prefix = ("--raw_timing_dir=" if
                                producer == "bench_piccard" else
                                "--raw-timing-out=")
                wrong = output / "wrong-raw"
                command = [wrong_prefix + str(wrong) if item.startswith(wrong_prefix)
                           else item for item in command]
            (output / "stderr.log").write_text("", encoding="utf-8")
            receipt = {"artifact_inventory": file_inventory(
                output, exclude={"stdout.log", "stderr.log", "receipt.json"})}
            (output / "receipt.json").write_text(
                json.dumps(receipt) + "\n", encoding="utf-8")
            return cell, {cid: {"command": command}}, raw_path

        for producer in ("bench_piccard", "bench_fhe_ind"):
            for mode in ("toy", "paper"):
                with self.subTest(producer=producer, mode=mode):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        cell, plan, _ = write_case(root, producer, mode)
                        _check_family_artifacts(root, mode, [cell], plan)
            for mutation in ("swapped_index", "duplicate_index", "missing_index",
                             "seed", "warmup_kind", "aggregate",
                             "wrong_path", "header"):
                with self.subTest(producer=producer, mutation=mutation):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        cell, plan, _ = write_case(root, producer, "paper",
                                                   mutation=mutation)
                        with self.assertRaises(RevisionContractError):
                            _check_family_artifacts(root, "paper", [cell], plan)

            if producer == "bench_piccard":
                with self.subTest(producer=producer, mutation="warmup_value"):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        cell, plan, _ = write_case(
                            root, producer, "paper", mutation="warmup_value")
                        # Warmup timing is diagnostic and non-authoritative:
                        # changing only its finite value must remain valid.
                        _check_family_artifacts(root, "paper", [cell], plan)
                for mutation in ("warmup_nonfinite", "warmup_negative"):
                    with self.subTest(producer=producer, mutation=mutation):
                        with tempfile.TemporaryDirectory() as temporary:
                            root = Path(temporary)
                            cell, plan, _ = write_case(
                                root, producer, "paper", mutation=mutation)
                            with self.assertRaises(RevisionContractError):
                                _check_family_artifacts(root, "paper", [cell], plan)

    def test_raw_phase_release_fma_statistic_is_byte_exact(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from verify_revision_benchmarks import _raw_sample_sd

        values = [586855846.00507104, 3804800778.6489544]
        # AppleClang Release contracts delta * delta + sum_sq as FMA in the
        # producer.  The expected 17-digit spelling differs from a separate
        # multiply followed by addition by one final bit.
        self.assertEqual(_raw_sample_sd(values), 2275430683.357378)


if __name__ == "__main__":
    unittest.main()
