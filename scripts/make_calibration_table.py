#!/usr/bin/env python3
"""Validate finalized calibration evidence and emit deterministic artifacts."""

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath


SCRIPT_DIR = Path(__file__).resolve().parent
MATRIX_PATH = SCRIPT_DIR / "noise_profiles.json"
PROFILE_ORDER = ("primary40", "sensitivity64", "feasibility128")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_RE = re.compile(r"^[0-9a-f]{40}$")

TOP_FIELDS = {
    "schema", "version", "table_eligible", "run", "profiles", "keys",
    "archive",
}
RUN_FIELDS = {
    "schema", "version", "run_nonce", "source_commit", "git_head",
    "source_tree_dirty", "smoke_only", "table_eligible",
    "benchmark_sha256", "openfhe_version", "matrix_sha256",
    "resolved_matrix_sha256", "command_policy", "platform",
    "python_version", "run_manifest_sha256",
}
PROFILE_FIELDS = {
    "profile_id", "measurement_profile_verdict",
    "finalization_profile_verdict", "profile_manifest_sha256",
    "completion_seal_sha256", "shards",
}
SHARD_FIELDS = {"key_id", "shard_manifest_sha256"}
KEY_FIELDS = {
    "profile_id", "circuit", "shape_id", "security",
    "requested_ring_dim", "natural_depth", "consumer_set_sha256",
    "openfhe_version", "key_id", "measurement_key_verdict",
    "frontier_verdict", "shard_manifest_sha256", "selected_row",
    "infeasibility",
}
SELECTED_FIELDS = {
    "candidate_id", "natural_ring_dim", "ring_dim_calibrated",
    "provisioned_depth", "scaling_mod_size", "num_limbs",
    "plaintext_mod", "log_q", "log_delta",
    "measured_eval_noise_bits", "eval_noise_bits", "ct_bytes",
    "transcript_stat_bits", "max_queries", "query_stat_bits",
    "coefficient_stat_bits", "flood_margin_bits", "flood_noise_bits",
    "pattern_count", "repetitions_per_pattern", "detail_row_count",
    "detail_sha256", "consumer_results_sha256", "aggregate_csv_sha256",
    "candidate_manifest_sha256", "shard_manifest_sha256",
}
INFEASIBILITY_FIELDS = {
    "shortfall_bits", "reason", "best_candidate_id",
    "best_measured_eval_noise_bits", "required_capacity_bits",
    "log_delta",
}
ARCHIVE_FIELDS = {
    "path", "members", "tar_sha256", "archive_sha256", "zstd_version",
}
KEY_IDENTITY_FIELDS = (
    "profile_id", "circuit", "shape_id", "security",
    "requested_ring_dim", "natural_depth", "consumer_set_sha256",
    "openfhe_version",
)
INTEGRAL_SELECTED_FIELDS = {
    "natural_ring_dim", "ring_dim_calibrated", "provisioned_depth",
    "scaling_mod_size", "num_limbs", "plaintext_mod", "eval_noise_bits",
    "ct_bytes", "transcript_stat_bits", "max_queries", "query_stat_bits",
    "coefficient_stat_bits", "flood_margin_bits", "flood_noise_bits",
    "pattern_count", "repetitions_per_pattern", "detail_row_count",
}
SELECTED_HASH_FIELDS = {
    "detail_sha256", "consumer_results_sha256", "aggregate_csv_sha256",
    "candidate_manifest_sha256", "shard_manifest_sha256",
}


def _exact(value, fields, where):
    if not isinstance(value, dict) or set(value) != fields:
        missing = sorted(fields - set(value)) if isinstance(value, dict) else []
        extra = sorted(set(value) - fields) if isinstance(value, dict) else []
        raise ValueError(
            f"{where} schema mismatch (missing={missing}, extra={extra})")


def _integer(value, where, positive=False):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{where} must be a JSON integer")
    if positive and value <= 0:
        raise ValueError(f"{where} must be positive")
    return value


def _number(value, where, positive=False):
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
    ):
        raise ValueError(f"{where} must be a finite JSON number")
    if positive and value <= 0:
        raise ValueError(f"{where} must be positive")
    return float(value)


def _hash(value, where):
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{where} must be lowercase SHA-256")


def _power_of_two(value):
    return value > 0 and value & (value - 1) == 0


def _canonical_matrix():
    value = json.loads(MATRIX_PATH.read_text())
    return value, {entry["key_id"]: entry for entry in value["partitions"]}


def _validate_run(run, matrix):
    _exact(run, RUN_FIELDS, "run")
    if run["schema"] != "piccard-noise-run" or run["version"] != 1:
        raise ValueError("run schema/version mismatch")
    if (
        run["source_tree_dirty"] is not False
        or run["smoke_only"] is not False
        or run["table_eligible"] is not True
    ):
        raise ValueError("run is dirty, smoke-only, or table-ineligible")
    if (
        not isinstance(run["run_nonce"], str)
        or re.fullmatch(r"[0-9a-f]{32}", run["run_nonce"]) is None
    ):
        raise ValueError("run nonce is invalid")
    for field in ("source_commit", "git_head"):
        if (
            not isinstance(run[field], str)
            or SOURCE_RE.fullmatch(run[field]) is None
        ):
            raise ValueError(f"run {field} is invalid")
    if run["source_commit"] != run["git_head"]:
        raise ValueError("stale or mixed source commit")
    for field in (
        "benchmark_sha256", "matrix_sha256", "resolved_matrix_sha256",
        "run_manifest_sha256",
    ):
        _hash(run[field], "run " + field)
    matrix_bytes = MATRIX_PATH.read_bytes()
    if run["matrix_sha256"] != hashlib.sha256(matrix_bytes).hexdigest():
        raise ValueError("tracked matrix SHA mismatch")
    if run["openfhe_version"] != matrix["openfhe_version"]:
        raise ValueError("run OpenFHE version mismatch")
    for field in (
        "openfhe_version", "command_policy", "platform", "python_version",
    ):
        if not isinstance(run[field], str) or not run[field]:
            raise ValueError(f"run {field} must be a non-empty string")


def _validate_selected(row, key, partition):
    _exact(row, SELECTED_FIELDS, "selected_row")
    expected_candidate_id = (
        f"N{row['ring_dim_calibrated']}-"
        f"d{row['provisioned_depth']}-"
        f"s{row['scaling_mod_size']}"
    )
    if row["candidate_id"] != expected_candidate_id:
        raise ValueError("selected candidate_id is inconsistent")
    for field in INTEGRAL_SELECTED_FIELDS:
        _integer(row[field], "selected " + field, positive=True)
    for field in (
        "log_q", "log_delta", "measured_eval_noise_bits",
    ):
        _number(row[field], "selected " + field, positive=True)
    for field in SELECTED_HASH_FIELDS:
        _hash(row[field], "selected " + field)
    if row["shard_manifest_sha256"] != key["shard_manifest_sha256"]:
        raise ValueError("selected row shard binding mismatch")
    if row["pattern_count"] != 3 or row["repetitions_per_pattern"] < 5:
        raise ValueError("selected row lacks three patterns/five repetitions")
    if (
        row["detail_row_count"]
        != len(partition["consumer_points"])
        * row["pattern_count"]
        * row["repetitions_per_pattern"]
    ):
        raise ValueError("selected detail row count mismatch")
    requested = key["requested_ring_dim"]
    natural = row["natural_ring_dim"]
    calibrated = row["ring_dim_calibrated"]
    if (
        not _power_of_two(natural)
        or not _power_of_two(calibrated)
        or natural < requested
        or calibrated < natural
        or calibrated % natural != 0
    ):
        raise ValueError("selected calibrated/realized N mismatch")
    growth = calibrated // natural
    maximum_growth = {
        "primary40": 2,
        "sensitivity64": 2,
        "feasibility128": 4,
    }[key["profile_id"]]
    if not _power_of_two(growth) or growth > maximum_growth:
        raise ValueError("selected ring growth violates profile policy")
    if row["provisioned_depth"] < key["natural_depth"]:
        raise ValueError("selected depth is below natural depth")
    expected_delta = row["log_q"] - math.log2(row["plaintext_mod"])
    if (
        row["log_delta"] >= row["log_q"]
        or abs(row["log_delta"] - expected_delta) > 1e-6
    ):
        raise ValueError("selected log_delta does not match q/plaintext")
    if row["plaintext_mod"] % (2 * calibrated) != 1:
        raise ValueError("selected plaintext modulus is incompatible with N")
    compiled = math.ceil(row["measured_eval_noise_bits"])
    if compiled > 0xFFFFFFFF or row["eval_noise_bits"] != compiled:
        raise ValueError("selected compiled eval-noise conversion mismatch")
    stat = {
        "primary40": 40,
        "sensitivity64": 64,
        "feasibility128": 128,
    }[key["profile_id"]]
    query = stat + math.ceil(math.log2(row["max_queries"]))
    coefficient = query + math.ceil(math.log2(calibrated))
    flood = compiled + coefficient + row["flood_margin_bits"]
    if (
        row["transcript_stat_bits"] != stat
        or row["max_queries"] != 1048576
        or row["query_stat_bits"] != query
        or row["coefficient_stat_bits"] != coefficient
        or row["flood_margin_bits"] != 8
        or row["flood_noise_bits"] != flood
        or flood + 2 > row["log_delta"]
    ):
        raise ValueError("selected transcript capacity contract mismatch")


def _validate_infeasibility(value):
    _exact(value, INFEASIBILITY_FIELDS, "infeasibility")
    reason = value["reason"]
    if reason == "NO_COMPLETE_NUMERIC_OK_CANDIDATE":
        if any(
            value[field] is not None
            for field in INFEASIBILITY_FIELDS - {"reason"}
        ):
            raise ValueError("no-candidate infeasibility tuple must be null")
        return
    if reason != "INSUFFICIENT_CAPACITY":
        raise ValueError("unknown infeasibility reason")
    if (
        not isinstance(value["best_candidate_id"], str)
        or not value["best_candidate_id"]
    ):
        raise ValueError("best infeasible candidate id is invalid")
    measured = _number(
        value["best_measured_eval_noise_bits"],
        "best measured eval noise",
        positive=True,
    )
    required = _integer(
        value["required_capacity_bits"],
        "required capacity",
        positive=True,
    )
    log_delta = _number(value["log_delta"], "infeasible log_delta", True)
    shortfall = _number(value["shortfall_bits"], "shortfall bits", True)
    if required <= log_delta or abs(shortfall - (required - log_delta)) > 1e-9:
        raise ValueError("infeasibility shortfall mismatch")
    if measured <= 0:
        raise ValueError("infeasible measured noise is invalid")


def _validate_archive(archive):
    _exact(archive, ARCHIVE_FIELDS, "archive")
    if archive["path"] != "selected-shards.tar.zst":
        raise ValueError("archive path mismatch")
    for field in ("tar_sha256", "archive_sha256"):
        _hash(archive[field], "archive " + field)
    if (
        not isinstance(archive["zstd_version"], str)
        or not archive["zstd_version"]
        or "\n" in archive["zstd_version"]
    ):
        raise ValueError("zstd version must be one non-empty line")
    members = archive["members"]
    if (
        not isinstance(members, list)
        or not all(isinstance(member, str) for member in members)
        or members != sorted(members)
        or len(members) != len(set(members))
    ):
        raise ValueError("archive members must be unique and bytewise sorted")
    for member in members:
        path = PurePosixPath(member)
        if (
            not member
            or path.is_absolute()
            or ".." in path.parts
            or member != path.as_posix()
        ):
            raise ValueError("unsafe archive member")


def validate_finalized_manifest(value):
    """Exhaustively validate and return one finalized manifest."""
    _exact(value, TOP_FIELDS, "manifest")
    if (
        value["schema"] != "piccard-calibration-finalized"
        or value["version"] != 1
        or value["table_eligible"] is not True
    ):
        raise ValueError("finalized schema/version/eligibility mismatch")
    matrix, canonical = _canonical_matrix()
    _validate_run(value["run"], matrix)

    profiles = value["profiles"]
    if (
        not isinstance(profiles, list)
        or [profile.get("profile_id") for profile in profiles]
        != list(PROFILE_ORDER)
    ):
        raise ValueError("finalized profile topology/order mismatch")
    profile_map = {}
    for profile in profiles:
        _exact(profile, PROFILE_FIELDS, "profile")
        profile_id = profile["profile_id"]
        if profile_id in profile_map:
            raise ValueError("duplicate profile")
        allowed_measurement_verdicts = (
            {"PASS"}
            if profile_id != "feasibility128"
            else {"PASS", "PASS_FEASIBILITY_WITH_INFEASIBLE"}
        )
        if profile["measurement_profile_verdict"] not in allowed_measurement_verdicts:
            raise ValueError("invalid measurement profile verdict")
        if profile["finalization_profile_verdict"] not in {
            "PASS", "PASS_FEASIBILITY_WITH_INFEASIBLE",
        }:
            raise ValueError("invalid finalization profile verdict")
        for field in (
            "profile_manifest_sha256", "completion_seal_sha256",
        ):
            _hash(profile[field], "profile " + field)
        shards = profile["shards"]
        if not isinstance(shards, list):
            raise ValueError("profile shards must be an array")
        for shard in shards:
            _exact(shard, SHARD_FIELDS, "profile shard")
            _hash(shard["shard_manifest_sha256"], "profile shard hash")
        if [shard["key_id"] for shard in shards] != sorted(
            shard["key_id"] for shard in shards
        ):
            raise ValueError("profile shards are not bytewise sorted")
        if len({shard["key_id"] for shard in shards}) != len(shards):
            raise ValueError("duplicate profile shard")
        profile_map[profile_id] = profile
    if set(profile_map) != set(PROFILE_ORDER):
        raise ValueError("missing profile")

    keys = value["keys"]
    if not isinstance(keys, list) or len(keys) != len(canonical):
        raise ValueError("finalized key count mismatch")
    key_ids = [key.get("key_id") for key in keys if isinstance(key, dict)]
    if len(key_ids) != len(keys) or len(set(key_ids)) != len(key_ids):
        raise ValueError("duplicate or malformed logical key")
    if set(key_ids) != set(canonical):
        raise ValueError("missing/unknown canonical logical key")
    by_profile = {profile: [] for profile in PROFILE_ORDER}
    for key in keys:
        _exact(key, KEY_FIELDS, "key")
        partition = canonical[key["key_id"]]
        for field in KEY_IDENTITY_FIELDS:
            if key[field] != partition[field]:
                raise ValueError("finalized full logical key mismatch")
        if key["openfhe_version"] != value["run"]["openfhe_version"]:
            raise ValueError("mixed OpenFHE version")
        _hash(key["consumer_set_sha256"], "consumer set hash")
        _hash(key["shard_manifest_sha256"], "key shard hash")
        if key["measurement_key_verdict"] not in {
            "SELECTED", "INFEASIBLE",
        }:
            raise ValueError("invalid measurement key verdict")
        selected = key["selected_row"]
        infeasible = key["infeasibility"]
        if (selected is None) == (infeasible is None):
            raise ValueError("exactly one finalized key result is required")
        if selected is not None:
            if key["frontier_verdict"] != "SELECTED":
                raise ValueError("selected row has wrong frontier verdict")
            if key["measurement_key_verdict"] != "SELECTED":
                raise ValueError(
                    "selected row has incoherent measurement key verdict")
            _validate_selected(selected, key, partition)
        else:
            if key["frontier_verdict"] != "INFEASIBLE":
                raise ValueError("incomplete/invalid frontier verdict")
            _validate_infeasibility(infeasible)
            if key["profile_id"] != "feasibility128":
                raise ValueError("required profile key is infeasible")
        by_profile[key["profile_id"]].append(key)

    for profile_id, profile_keys in by_profile.items():
        profile = profile_map[profile_id]
        expected_shards = {
            key["key_id"]: key["shard_manifest_sha256"]
            for key in profile_keys
        }
        actual_shards = {
            shard["key_id"]: shard["shard_manifest_sha256"]
            for shard in profile["shards"]
        }
        if actual_shards != expected_shards:
            raise ValueError("profile/key shard topology mismatch")
        has_infeasible = any(
            key["frontier_verdict"] == "INFEASIBLE"
            for key in profile_keys
        )
        expected_verdict = (
            "PASS_FEASIBILITY_WITH_INFEASIBLE"
            if profile_id == "feasibility128" and has_infeasible
            else "PASS"
        )
        if profile["finalization_profile_verdict"] != expected_verdict:
            raise ValueError("finalization profile verdict mismatch")
        has_measurement_infeasible = any(
            key["measurement_key_verdict"] == "INFEASIBLE"
            for key in profile_keys
        )
        expected_measurement_verdict = (
            "PASS_FEASIBILITY_WITH_INFEASIBLE"
            if profile_id == "feasibility128" and has_measurement_infeasible
            else "PASS"
        )
        if (
            profile["measurement_profile_verdict"]
            != expected_measurement_verdict
        ):
            raise ValueError("measurement profile verdict mismatch")
    _validate_archive(value["archive"])
    members = set(value["archive"]["members"])
    fixed_members = set()
    detail_prefixes = {}
    for profile_id in PROFILE_ORDER:
        fixed_members.update({
            f"profiles/{profile_id}/profile_manifest.json",
            f"profiles/{profile_id}/completion_seal.json",
        })
    for key in keys:
        base = f"profiles/{key['profile_id']}/{key['key_id']}"
        fixed_members.update({
            f"{base}/aggregate.csv",
            f"{base}/candidates.json",
            f"{base}/shard_manifest.json",
        })
        detail_prefixes[key["key_id"]] = f"{base}/details/"
    if not fixed_members.issubset(members):
        raise ValueError("archive evidence is incomplete")
    for key_id, prefix in detail_prefixes.items():
        details = [
            member for member in members
            if member.startswith(prefix) and member.endswith(".csv")
        ]
        if not details:
            raise ValueError(
                "archive evidence is incomplete for " + key_id)
        key = next(item for item in keys if item["key_id"] == key_id)
        if key["selected_row"] is not None:
            expected_detail = (
                prefix + key["selected_row"]["candidate_id"] + ".csv")
            if expected_detail not in details:
                raise ValueError(
                    "selected candidate detail archive binding mismatch")
    if any(
        member not in fixed_members
        and not any(
            member.startswith(prefix) and member.endswith(".csv")
            for prefix in detail_prefixes.values()
        )
        for member in members
    ):
        raise ValueError("archive evidence topology is incoherent")
    return value


def select_frontier_candidate(candidates):
    """Select the deterministic cheapest row, deduplicating exact equals."""
    if not candidates:
        raise ValueError("frontier candidate list is empty")
    ordered = sorted(
        candidates,
        key=lambda row: (
            row["ring_dim_calibrated"],
            row["log_q"],
            row["ct_bytes"],
            row["provisioned_depth"],
            row["scaling_mod_size"],
        ),
    )
    cheapest_cost = (
        ordered[0]["ring_dim_calibrated"],
        ordered[0]["log_q"],
        ordered[0]["ct_bytes"],
        ordered[0]["provisioned_depth"],
        ordered[0]["scaling_mod_size"],
    )
    cheapest = [
        row for row in ordered
        if (
            row["ring_dim_calibrated"],
            row["log_q"],
            row["ct_bytes"],
            row["provisioned_depth"],
            row["scaling_mod_size"],
        ) == cheapest_cost
    ]
    canonical = json.dumps(
        cheapest[0], sort_keys=True, separators=(",", ":"))
    if any(
        json.dumps(row, sort_keys=True, separators=(",", ":")) != canonical
        for row in cheapest[1:]
    ):
        raise ValueError("conflicting equal-cost frontier candidates")
    return cheapest[0]


def _cpp_number(value):
    if isinstance(value, int):
        return str(value)
    return repr(float(value))


def render_rows(value, manifest_sha256):
    validate_finalized_manifest(value)
    _hash(manifest_sha256, "finalized manifest binding")
    lines = [
        "// Generated by scripts/make_calibration_table.py; do not edit.",
        f"// finalized manifest sha256: {manifest_sha256}",
    ]
    for key in sorted(value["keys"], key=lambda item: item["key_id"]):
        row = key["selected_row"]
        if row is None:
            continue
        circuit = {
            "onehot": "Circuit::OneHot",
            "sqrt": "Circuit::Sqrt",
        }[key["circuit"]]
        security = {
            "STD128": "SecurityLevel::STD128",
            "STD192": "SecurityLevel::STD192",
        }[key["security"]]
        request = (
            f'{{"{key["profile_id"]}", {circuit}, "{key["shape_id"]}", '
            f'{security}, {key["requested_ring_dim"]}, '
            f'{key["natural_depth"]}, "{key["consumer_set_sha256"]}", '
            f'"{key["openfhe_version"]}"}}'
        )
        fields = [
            request,
            row["natural_ring_dim"],
            row["ring_dim_calibrated"],
            row["provisioned_depth"],
            row["scaling_mod_size"],
            row["num_limbs"],
            row["plaintext_mod"],
            row["log_q"],
            row["log_delta"],
            row["eval_noise_bits"],
            row["ct_bytes"],
            row["transcript_stat_bits"],
            row["max_queries"],
            row["query_stat_bits"],
            row["coefficient_stat_bits"],
            row["flood_margin_bits"],
            row["flood_noise_bits"],
        ]
        rendered = ", ".join(
            field if isinstance(field, str) else _cpp_number(field)
            for field in fields
        )
        lines.append(f"    {{{rendered}}},")
    return ("\n".join(lines) + "\n").encode()


def render_summary(value):
    validate_finalized_manifest(value)
    lines = [
        "# Finalized pre-threshold calibration matrix",
        "",
        "| profile | key | circuit | security | verdict | selected N | log q | detail |",
        "|---|---|---|---|---|---:|---:|---|",
    ]
    for key in sorted(value["keys"], key=lambda item: item["key_id"]):
        row = key["selected_row"]
        if row is not None:
            selected_n = str(row["ring_dim_calibrated"])
            log_q = _cpp_number(row["log_q"])
            detail = (
                f"candidate `{row['candidate_id']}`, "
                f"measured eval {row['measured_eval_noise_bits']}, "
                f"compiled eval {row['eval_noise_bits']}"
            )
        else:
            selected_n = "—"
            log_q = "—"
            detail = (
                f"{key['infeasibility']['reason']}; shortfall "
                f"{key['infeasibility']['shortfall_bits']}"
            )
        lines.append(
            f"| {key['profile_id']} | `{key['key_id']}` | "
            f"{key['circuit']} | {key['security']} | "
            f"{key['frontier_verdict']} | {selected_n} | {log_q} | "
            f"{detail} |"
        )
    return ("\n".join(lines) + "\n").encode()


def _regular_single_link(path):
    info = path.lstat()
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def verify_artifact_copy(manifest_path, artifact_dir):
    expected_names = {
        "manifest.json", "CALIBRATION_MATRIX.md",
        "selected-shards.tar.zst", "tracked-copy.sha256",
    }
    if not artifact_dir.is_dir() or artifact_dir.is_symlink():
        raise ValueError("artifact-dir must be a direct real directory")
    entries = {entry.name: entry for entry in artifact_dir.iterdir()}
    if set(entries) != expected_names:
        raise ValueError("artifact-dir file topology mismatch")
    if not all(_regular_single_link(path) for path in entries.values()):
        raise ValueError("artifact-dir entries must be regular non-symlink files")
    manifest_bytes = manifest_path.read_bytes()
    if entries["manifest.json"].read_bytes() != manifest_bytes:
        raise ValueError("copied manifest is not byte-identical")
    value = validate_finalized_manifest(json.loads(manifest_bytes))
    archive_bytes = entries["selected-shards.tar.zst"].read_bytes()
    if (
        hashlib.sha256(archive_bytes).hexdigest()
        != value["archive"]["archive_sha256"]
    ):
        raise ValueError("copied archive hash mismatch")
    if (
        entries["CALIBRATION_MATRIX.md"].read_bytes()
        != render_summary(value)
    ):
        raise ValueError("copied Markdown is not reproducible")
    ordered = (
        "manifest.json", "CALIBRATION_MATRIX.md",
        "selected-shards.tar.zst",
    )
    checksum = "".join(
        f"{hashlib.sha256(entries[name].read_bytes()).hexdigest()}  {name}\n"
        for name in ordered
    ).encode()
    if entries["tracked-copy.sha256"].read_bytes() != checksum:
        raise ValueError("tracked-copy.sha256 bytes/order mismatch")


def _write_new_or_replace(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    with temporary.open("wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def parse_args(arguments):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--emit-rows")
    parser.add_argument("--out")
    parser.add_argument("--verify-artifact-copy", action="store_true")
    parser.add_argument("--artifact-dir")
    args = parser.parse_args(arguments)
    if args.verify_artifact_copy:
        if args.artifact_dir is None or args.emit_rows is not None or args.out is not None:
            parser.error(
                "--verify-artifact-copy requires only --manifest and "
                "--artifact-dir")
    elif (
        args.emit_rows is None
        or args.out is None
        or args.artifact_dir is not None
    ):
        parser.error(
            "generation requires --manifest, --emit-rows, and --out")
    return args


def main(arguments=None):
    args = parse_args(sys.argv[1:] if arguments is None else arguments)
    manifest_path = Path(args.manifest)
    if args.verify_artifact_copy:
        verify_artifact_copy(manifest_path, Path(args.artifact_dir))
        return 0
    manifest_bytes = manifest_path.read_bytes()
    value = validate_finalized_manifest(json.loads(manifest_bytes))
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    _write_new_or_replace(Path(args.emit_rows), render_rows(value, digest))
    _write_new_or_replace(Path(args.out), render_summary(value))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"calibration table generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
