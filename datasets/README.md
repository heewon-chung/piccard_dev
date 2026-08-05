# Real-Dataset Acquisition (DBLP-ACM, Enron)

This repository does not redistribute the DBLP-ACM entity-resolution corpus
or the Enron email corpus, and `prepare_real_datasets.py` never downloads
anything over the network. You must acquire a local copy of each dataset
yourself, from its original/official distribution, under whatever license
or terms of use that distributor publishes, before running the strict
preprocessing pipeline.

No mirror URLs and no credentials are recorded in this repository. Do not
add any to this file, to the source-manifest templates, or to any tracked
fixture.

## 1. Acquire the raw data locally

- **DBLP-ACM**: obtain the DBLP bibliography records, the ACM bibliography
  records, and the ground-truth ID mapping between them, from their
  original publishers/maintainers. Keep the three files (or an equivalent
  layout) somewhere outside this repository, e.g.
  `~/real-datasets/dblp-acm/`.
- **Enron**: obtain the Enron email corpus maildir tree from its official
  academic distribution. Keep the extracted `maildir/` root outside this
  repository, e.g. `~/real-datasets/enron/maildir/`.

`datasets/data/` in this repository is reserved for local, `.gitignore`d
working copies of raw and processed artifacts; nothing under it is ever
committed.

## 2. Record a source manifest

Copy the matching template from `datasets/manifests/` (`dblp_acm.source.
template.tsv` or `enron.source.template.tsv`) to a local, untracked path
(for example under `datasets/data/`), and replace every `TODO` placeholder
with real values:

- `dataset_version`, `source_url`, `citation`, `license_or_terms_url`: the
  release/version identifier, the dataset's own homepage or DOI, its
  citation, and the license/terms page you obtained it under.
- `acquisition_note`: a short, credential-free note on how and when you
  obtained your local copy (e.g. "downloaded from the official DBLP/ACM
  benchmark release, 2026-01-01").
- `input.<i>.path`: a path relative to the manifest file itself (no
  absolute paths, no `.`/`..` components, no symlinks) pointing at your
  local copy of that input.
- `input.<i>.sha256`: the SHA-256 of the input's bytes (a directory input,
  such as Enron's `maildir_root`, uses the canonical source-tree digest
  the pipeline computes over that directory, not a single file hash).

Strict mode rejects the templates as shipped: every `TODO` is a
placeholder, and placeholders, empty values, absolute paths, symlinks, and
checksum mismatches all fail validation by design.

## 3. Run the pipeline

Once Phases 2–3 add the dataset subcommands, invoke
`scripts/prepare_real_datasets.py dblp-acm ...` or `... enron ...` with
`--source-manifest=<your manifest path>` and `--strict`. The tool validates
your manifest, then writes a deterministic, atomically-published
`processed/<variant>/` directory (`records.tsv`, `pairs.tsv`,
`source.manifest.tsv`, `dataset.manifest.tsv`).
