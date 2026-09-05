#!/usr/bin/env python3
"""Re-computable DBLP-ACM trigram statistics, kept OUTSIDE the frozen dataset
manifest (docs/response/HANDOFF.md W2).

dataset.manifest.tsv's key list is pinned behind schema_version
piccard-real-processed-v1 in both scripts/prepare_real_datasets.py and
src/data/real_dataset.cpp, and its hash is the input binding the 2026-08-20
run recorded, so it is never regenerated.  This script reads the processed
records.tsv, counts the distinct raw feature hashes (one per distinct
trigram) and the distinct 2^16 buckets they land in, and re-derives the
set-size quantiles the manifest already carries, so the manuscript's
"natural universe" sentence can cite a measurement instead of the 36^3
design bound.

  python3 scripts/dblp_trigram_stats.py \
      --records=datasets/data/processed/dblp_acm_u65536_paper/records.tsv \
      --manifest=datasets/data/processed/dblp_acm_u65536_paper/dataset.manifest.tsv \
      --output=results/dblp-trigram-stats-<date>/stats.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts.prepare_real_datasets import summarize_set_sizes  # noqa: E402

HEADER = ["record_id", "raw_feature_count", "raw_features_csv",
          "bucketed_feature_count", "bucketed_features_csv"]


class StatsError(RuntimeError):
    pass


def _features(field: str) -> list[int]:
    return [int(token) for token in field.split(",")] if field else []


def compute(records_text: str, universe: int) -> dict[str, Any]:
    lines = records_text.splitlines()
    if not lines or lines[0].split("\t") != HEADER:
        raise StatsError("records.tsv header mismatch")
    raw_union: set[int] = set()
    bucket_union: set[int] = set()
    raw_sizes: list[int] = []
    bucket_sizes: list[int] = []
    collided_records = 0
    lost = 0
    for number, line in enumerate(lines[1:], start=2):
        fields = line.split("\t")
        if len(fields) != 5:
            raise StatsError(f"records.tsv line {number}: expected 5 fields")
        raw = _features(fields[2])
        bucketed = _features(fields[4])
        if len(raw) != int(fields[1]) or len(bucketed) != int(fields[3]):
            raise StatsError(f"records.tsv line {number}: feature counts disagree with lists")
        if sorted({f % universe for f in raw}) != bucketed:
            raise StatsError(f"records.tsv line {number}: bucketed list is not raw mod universe")
        raw_union.update(raw)
        bucket_union.update(bucketed)
        raw_sizes.append(len(raw))
        bucket_sizes.append(len(bucketed))
        if len(bucketed) < len(raw):
            collided_records += 1
            lost += len(raw) - len(bucketed)
    raw_stats = summarize_set_sizes(raw_sizes)
    bucket_stats = summarize_set_sizes(bucket_sizes)
    return {
        "record_count": len(raw_sizes),
        "distinct_raw_features": len(raw_union),
        "distinct_bucketed_features": len(bucket_union),
        "log2_distinct_raw_features": math.log2(len(raw_union)),
        "log2_distinct_bucketed_features": math.log2(len(bucket_union)),
        "raw_set_size": {"min": raw_stats.min, "median": raw_stats.median,
                         "p95": raw_stats.p95, "max": raw_stats.max},
        "bucketed_set_size": {"min": bucket_stats.min, "median": bucket_stats.median,
                              "p95": bucket_stats.p95, "max": bucket_stats.max},
        "records_with_bucket_collision": collided_records,
        "features_lost_to_bucket_collision": lost,
        "design_bound": {"alphabet": "[a-z0-9]", "trigrams": 36 ** 3, "log2": math.log2(36 ** 3)},
    }


def _manifest(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines()[1:]:
        key, _, value = line.partition("\t")
        values[key] = value
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    records = Path(args.records)
    manifest = _manifest(Path(args.manifest))
    universe = int(manifest["universe_size"])
    raw_bytes = records.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    result = compute(raw_bytes.decode("utf-8"), universe)
    if result["record_count"] != int(manifest["record_count"]):
        raise StatsError("record_count disagrees with the manifest")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                            text=True, check=False).stdout.strip() or "unavailable"
    payload = {
        "schema": "piccard-dblp-trigram-stats-v1",
        "records_file": str(records.resolve().relative_to(ROOT)) if records.resolve().is_relative_to(ROOT) else str(records),
        "records_sha256": digest,
        "manifest_records_sha256": manifest["records_sha256"],
        "sha256_matches_manifest": digest == manifest["records_sha256"],
        "universe_size": universe,
        **result,
        "git_commit": commit,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: payload[k] for k in ("record_count", "distinct_raw_features",
                                              "distinct_bucketed_features", "sha256_matches_manifest")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
