# Work 5 — Deterministic DBLP-ACM and Enron Dataset Pipeline

> **Implementation owner:** Claude Opus 5  
> **Plan reviewer:** Claude Fable 5  
> **Work completion reviewers:** GPT-5.6-sol and Claude Fable 5  
> **Dependency:** Work 4 approved  
> **Next work:** bounded-dynamic refresh and deletion evidence

## Objective

Implement reproducible, strict real-data preprocessing, loading, accuracy, and
timing paths for DBLP-ACM and Enron. Do not redistribute or auto-download raw
data. Preserve DBLP labels for the later threshold branch, but perform no
threshold, FP/FN, or decision-boundary experiment here.

## Dependency gate

```bash
WORK4_HEAD="$(python3 scripts/verify_work_approval.py --work-id=4 \
  --expected-base="$WORK3_HEAD" \
  --plan-path=docs/superpowers/plans/2026-07-29-04-benchmark-profiles-and-baseline-gates.md \
  --gpt="$REVIEW_STAGING_ROOT/work-4-gpt.md" \
  --fable="$REVIEW_STAGING_ROOT/work-4-fable.md" --print-head)"
test "$(git rev-parse HEAD)" = "$WORK4_HEAD"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

## Inputs and outputs

### Raw input manifest

Required fields:

```text
schema_version,dataset,dataset_version,source_url,citation,
license_or_terms_url,acquisition_note,parsing_schema,
preprocessing_profile,input_role,input_path,input_sha256
```

Strict mode rejects placeholders, missing files, checksum mismatch, path
escape, and unknown schema.

### Processed output

```text
processed/<variant>/
  records.tsv
  pairs.tsv
  source.manifest.tsv
  dataset.manifest.tsv
```

`records.tsv`:

```text
record_id<TAB>raw_feature_count<TAB>raw_features_csv<TAB>
bucketed_feature_count<TAB>bucketed_features_csv
```

`pairs.tsv`:

```text
pair_id<TAB>record_a<TAB>record_b<TAB>pair_kind<TAB>label
```

DBLP labels are `1` known match and `0` sampled known non-match. Enron labels
are `-1` unlabeled. Manifest records source/output checksums, preprocessing
version/config, record/pair counts, dropped counts, and set-size statistics.

### Exact shared file grammar

All TSV files are UTF-8 without BOM, LF-terminated, have the exact required
header, forbid embedded tabs/newlines, and use an empty field for N/A.
`*_features_csv` is empty or comma-separated unsigned base-10 uint64 values in
strict increasing order; the count equals the list length.

Source and processed manifests are two-column TSVs:

```text
key<TAB>value
```

Source manifests require unique `schema_version`, `dataset`, `source_url`,
`dataset_version`, `citation`, `license_or_terms_url`, `acquisition_note`,
`parsing_schema`, `preprocessing_profile`, and zero-based contiguous
`input.<i>.role`, `input.<i>.path`, `input.<i>.sha256` keys. SHA-256 is 64
lowercase hex characters. Exact values/contracts are:

| dataset | schema/version | parsing/profile | exact indexed roles |
|---|---|---|---|
| DBLP-ACM | `piccard-real-source-v1`, caller-recorded non-placeholder release/version | `dblp-acm-csv-v1`, `dblp-acm-trigram-v1` | `0=dblp_records`, `1=acm_records`, `2=dblp_acm_mapping` |
| Enron | `piccard-real-source-v1`, caller-recorded non-placeholder corpus version | `enron-maildir-rfc5322-v1`, `enron-shingle5-v1` | `0=maildir_root` |

No other role or role cardinality is accepted. `acquisition_note` records how
and when the user obtained the local copy without credentials. URLs, citation,
version, terms, and acquisition note reject empty values and the
case-insensitive placeholders `todo|tbd|unknown|replace-me`.
Every `input.<i>.path` is a relative POSIX path resolved against the canonical
source-manifest directory; absolute paths, symlinks, `.`/`..`, and canonical
escape fail. File roles hash file bytes. `maildir_root` uses the canonical
tree digest defined in Phase 3 as its `input.0.sha256`.

Processed manifests require:

```text
schema_version,dataset,variant,preprocessing_version,universe_size,seed,
source_manifest_file,source_manifest_sha256,
records_file,records_sha256,record_count,
pairs_file,pairs_sha256,pair_count,
raw_set_size_min,raw_set_size_median,raw_set_size_p95,raw_set_size_max,
bucketed_set_size_min,bucketed_set_size_median,
bucketed_set_size_p95,bucketed_set_size_max,
original_positive_count,retained_positive_count
```

The literal schema is `piccard-real-processed-v1`. Variants are derived, never
caller-supplied: `dblp_acm_u65536`, `enron_u65536`, or `enron_u1048576`;
this safe `[a-z0-9_]+` token is the only value used in filenames. DBLP accepts
only universe 65536; Enron accepts 65536 or 1048576.

`source.manifest.tsv` is a byte-identical canonical copy of the validated
source manifest; its relative filename and digest are mandatory. Paper mode
requires a paired `--source-manifest=<original path>` immediately before each
`--dataset-manifest=<processed path>`, verifies the original digest equals the
copy, then resolves/revalidates roles relative to the original directory.
Quick mode uses paired tracked fixture manifests. Runner
`input_manifests/` copies both source and processed manifests. DBLP records the
mapping-row count as `original_positive_count`; every positive must survive,
so `retained_positive_count` must equal it. Enron writes both as empty N/A.

`preprocessing_version` is exactly `dblp-acm-trigram-v1` or
`enron-shingle5-v1`. Every allowed drop key below is mandatory even when zero.
Processed manifests also require `requested_pair_count`; Enron requires
`max_documents` and `min_related_pairs`, while those two fields are empty N/A
for DBLP.

The only drop keys are
`dropped.empty_features_dblp|dropped.empty_features_acm` for DBLP and
`dropped.charset_or_mime|dropped.empty_body|dropped.short_body|
dropped.duplicate_message_id` for Enron. Unknown drop keys fail. Duplicate/unknown required
keys, input-index gaps, absolute output subpaths, and `..` components fail.
`pair_kind` is exactly `known_match|sampled_nonmatch` for DBLP-ACM and
`thread_related|cross_thread` for Enron.

Identifiers are generated, never copied ambiguously from raw text:

- DBLP record ID is `dblp:` plus lowercase hex of the raw UTF-8 DBLP ID;
- ACM record ID is `acm:` plus lowercase hex of the raw UTF-8 ACM ID;
- Enron record ID is `enron:` plus the full lowercase SHA-256 of the
  normalized POSIX relative source path;
- pair ID is `<dataset>-pair:` plus the full lowercase SHA-256 of
  `pair_kind || 0x00 || record_a || 0x00 || record_b`, where endpoints are
  lexicographically ordered UTF-8 IDs.

Raw IDs must be nonempty after strict CSV decoding. A generated-ID collision,
duplicate record ID, duplicate mapping row, non-one-to-one mapping, unknown
mapping endpoint, or malformed row aborts the whole run before output rename.

Features use:

```text
first-8-bytes-BE(
  SHA256("piccard-real-feature-v1" || 0x00 || canonical_feature_utf8)
)
```

Bucketed protocol inputs use `feature % universe_size` followed by
sort/dedup. Accuracy always reports exact Jaccard before and after bucketing;
the protocol ground truth is the bucketed-set exact Jaccard.

## Phase 1 — Build strict manifest and deterministic preprocessing primitives

### Files

- Add: `scripts/prepare_real_datasets.py`
- Add: `datasets/README.md`
- Add: `datasets/manifests/dblp_acm.source.template.tsv`
- Add: `datasets/manifests/enron.source.template.tsv`
- Add: `tests/scripts/test_real_dataset_preprocess.py`
- Add: `tests/fixtures/real_datasets/common/`
- Add: the three exact
  `tests/fixtures/real_datasets/quick/<variant>/` manifest pairs named in
  Phase 6 and their raw/processed fixture payloads.
- Modify: `.gitignore`
- Modify: `CMakeLists.txt`

### RED tests

Test:

- missing/placeholder checksum and unreadable input rejection;
- checksum mismatch creates no output;
- UTF-8 canonical hashing known-answer vector;
- row-order-independent, byte-identical normalized `records.tsv` and
  `pairs.tsv`; provenance manifests/checksums are expected to differ when raw
  source bytes differ;
- existing output is not overwritten without an explicit safe flag;
- temporary failure leaves no partial final directory.

Run:

```bash
python3 -m unittest tests.scripts.test_real_dataset_preprocess -v
```

Expected RED output: script/module absent.

### GREEN implementation

Use Python standard library only. Canonical `records.tsv` order is ascending
bytewise UTF-8 encoded normalized record ID, then the complete serialized row
as tie-break. Canonical `pairs.tsv` order is ascending bytewise UTF-8
`pair_id`, then `(record_a,record_b,label)` bytes. Duplicate canonical keys are
rejected. A `piccard-real-processed-v1` manifest emits keys in exactly this
order:

```text
schema_version,dataset,variant,preprocessing_version,universe_size,seed,
source_manifest_file,source_manifest_sha256,
records_file,records_sha256,record_count,
pairs_file,pairs_sha256,pair_count,
raw_set_size_min,raw_set_size_median,raw_set_size_p95,raw_set_size_max,
bucketed_set_size_min,bucketed_set_size_median,
bucketed_set_size_p95,bucketed_set_size_max,
original_positive_count,retained_positive_count,requested_pair_count,
max_documents,min_related_pairs,
<dataset-specific drop keys in the exact order declared below>
```

DBLP ends with
`dropped.empty_features_dblp,dropped.empty_features_acm`; Enron ends with
`dropped.charset_or_mime,dropped.empty_body,dropped.short_body,
dropped.duplicate_message_id`. DBLP writes empty N/A for
`max_documents,min_related_pairs`; Enron writes empty N/A for the two positive
counts. Processed manifests have no indexed role entries or extra keys, so no
map iteration order is observable. Write into a sibling temporary directory,
fsync/close, verify output checksums, then atomically rename. Raw/processed
actual data is ignored; templates and synthetic fixtures remain tracked.
Register the Python suite with CTest when Python is available.

### Pass conditions

- Tests pass on two consecutive runs.
- Reordered fixture input yields identical normalized records/pairs hashes;
  raw/source and processed provenance manifest hashes change honestly.
- No network access occurs.
- No raw or processed real-data file is staged by Git.
- `.gitignore` explicitly re-includes `datasets/README.md` while actual data
  remains ignored; a test checks both properties.

## Phase 2 — Implement DBLP-ACM parsing, normalization, and pairs

### Inputs

Roles:

- `dblp_records`: CSV header exactly `id,title,authors,venue,year`;
- `acm_records`: the same exact header;
- `dblp_acm_mapping`: header exactly `idDBLP,idACM`.

Evidence command:

```bash
python3 scripts/prepare_real_datasets.py dblp-acm \
  --source-manifest=/path/dblp_acm.source.tsv \
  --output-dir=/path/processed/dblp_acm_u65536 \
  --universe=65536 --pairs=10000 --seed=20260729 --strict
```

### Normalization

Strict UTF-8/BOM handling uses Unicode NFKC followed by `casefold()`, maps
every code point outside ASCII `[a-z0-9]` to one space, and collapses spaces.
In fixed title/authors/venue/year order, extract overlapping three-code-point
substrings from each normalized **value** without padding, then hash the
canonical feature `field_name=trigram`. Field names themselves never create
features for empty values. A record with no resulting trigram is dropped as
`dropped.empty_features_dblp` or `dropped.empty_features_acm`; a ground-truth
mapping that points to such a record aborts rather than silently deleting a
positive.

All known mapping pairs are included. Rank absent cross-source pairs by
`SHA256("piccard-dblp-negative-v1" || BE64(seed) ||
BE32(len(generated_dblp_id)) || generated_dblp_id ||
BE32(len(generated_acm_id)) || generated_acm_id)`, tie-broken by the generated
endpoint IDs, until `--pairs` is reached. A
streaming bounded top-k must match full sorting. Random-library-dependent
sampling is forbidden.

### RED tests

Cover quoted commas, BOM/Unicode, duplicate record IDs, unknown mapping IDs,
duplicate/non-one-to-one mappings, insufficient pair request, known-match
leakage into negatives, and input-row permutation.

Run:

```bash
python3 -m unittest \
  tests.scripts.test_real_dataset_preprocess.DblpAcmTests -v
```

Expected RED output: dataset-specific path absent.

### Pass conditions

- Every ground-truth mapping appears exactly once.
- No sampled negative is a known match.
- Requested pair count is exact.
- Features are sorted/unique.
- Manifest counts/checksums equal actual files.
- Fixture output is byte-identical to its golden files.

## Phase 3 — Implement Enron MIME/shingle preprocessing and pairs

### Input role

The source manifest has exactly one `maildir_root` directory. Files are
addressed by normalized POSIX relative paths; non-regular files and symlinks
are rejected.

### Evidence commands

```bash
python3 scripts/prepare_real_datasets.py enron \
  --source-manifest=/path/enron.source.tsv \
  --output-dir=/path/processed/enron_u65536 \
  --universe=65536 --max-documents=10000 --pairs=10000 \
  --min-related-pairs=100 --seed=20260729 --strict

python3 scripts/prepare_real_datasets.py enron \
  --source-manifest=/path/enron.source.tsv \
  --output-dir=/path/processed/enron_u1048576 \
  --universe=1048576 --max-documents=10000 --pairs=10000 \
  --min-related-pairs=100 --seed=20260729 --strict
```

### Processing

- Sort relative source paths; reject symlinks/path escape.
- Hash the tree from path, size, and file SHA-256 using the exact encoding
  below.
- Select capped documents by canonical hash rank.
- Parse MIME with Python `email`; use `text/plain`; exclude attachments.
- Record malformed charset/empty/short/duplicate-ID drops.
- Strip quoted reply lines and normalize tokens.
- Form consecutive five-word shingles.
- Identify related pairs from `In-Reply-To`/`References` and canonical subject
  groups; fill remaining pairs deterministically from different groups.

Message normalization is NFKC+casefold followed by ASCII `[a-z0-9]+`
tokenization. A five-word shingle joins five consecutive tokens with U+001F,
without padding. Document selection ranks
`SHA256("piccard-enron-document-v1" || BE64(seed) || relative_path)` with path
tie-break. Related and cross-thread candidates use separate domains,
BE64(seed), ordered IDs, digest order, then ID tie-break.

MIME and thread behavior is fully deterministic:

1. Parse bytes with `email.parser.BytesParser(policy=email.policy.default)`.
   Any parser/header defect, invalid transfer encoding, or RFC-2047 decoding
   defect drops the message as `dropped.charset_or_mime`. Walk MIME leaves
   depth-first in message order. A leaf is an attachment if
   Content-Disposition is `attachment` or it has a nonempty filename.
   For every other `text/plain` leaf, call `get_payload(decode=True)`, use the
   declared charset or `us-ascii` when absent, decode with `errors="strict"`,
   and join decoded leaves with one LF. No selected leaf is
   `dropped.empty_body`.
2. Remove a line when `lstrip()` begins with `>`. Remove an English quoted
   tail starting at the first line matching case-insensitively either
   `^-{2,}\s*original message\s*-{2,}$` or `^on .+ wrote:$`.
3. Decode/unfold Subject, apply NFKC+casefold, remove the full anchored prefix
   `(?i)^\s*(?:(?:re(?:\[[0-9]+\])?|fw|fwd)\s*:\s*)+`, tokenize the remainder
   as `[a-z0-9]+`, and join
   tokens with one space. Empty canonical subjects create no subject edge.
4. Normalize Message-ID/References/In-Reply-To by unfolding the decoded
   header, stripping leading/trailing ASCII whitespace, and extracting
   nonempty ASCII tokens matching
   `<[\x21-\x3B\x3D\x3F-\x7E]+>` (printable ASCII except interior `<`/`>`),
   then ASCII-lowercasing. Adjacent `<a><b>` is exactly two tokens; malformed
   nesting such as `<a<b>` leaves non-whitespace residue and is rejected.
   After
   removing tokens, the residue must contain only ASCII whitespace; otherwise
   it is malformed. Message-ID must contain zero or one token; multiple or
   malformed nonempty values are `dropped.charset_or_mime`. References and
   In-Reply-To retain tokens in header order and deduplicate first occurrence.
   Missing Message-ID is allowed:
   the path-derived record ID still exists but cannot be a header target.
   After MIME/header/body validation and short-body removal, sort by canonical
   path; for a duplicate normalized Message-ID, retain the first path and drop
   later paths as `dropped.duplicate_message_id`.
5. Build an undirected graph over retained records: add an edge for each
   resolvable In-Reply-To/References token and between records with the same
   nonempty canonical subject. `thread_related` means the endpoints share a
   transitive connected component; `cross_thread` means different components.
6. Rank all related candidates first, select up to `--pairs`, require at least
   `--min-related-pairs`, then fill the remainder with ranked cross-thread
   candidates. Insufficient candidates fail.

Candidate rank bytes are exactly:

```text
SHA256(domain_ascii || 0x00 || BE64(seed) ||
       BE32(len(record_a_utf8)) || record_a_utf8 ||
       BE32(len(record_b_utf8)) || record_b_utf8)
```

with lexicographically ordered endpoints and domains
`piccard-enron-related-v1` and `piccard-enron-cross-v1`. Digest bytes then
`(record_a,record_b)` break ties. Golden fixtures pin MIME part order,
quote-tail removal, canonical subject, missing/duplicate Message-ID behavior,
connected components, ranks, and selected pair IDs.

Canonical paths must decode as UTF-8, use `/`, be Unicode NFC already, contain
no empty/`.`/`..` component, and remain under the canonical `maildir_root`.
Sort UTF-8 path bytes. The source-tree digest is:

```text
SHA256("piccard-enron-tree-v1" || 0x00 ||
  for each regular file:
    BE32(len(path_utf8)) || path_utf8 || BE64(file_size) ||
    raw_32_byte_file_sha256)
```

Symlinks/non-regular files abort rather than incrementing a drop counter.
After quote removal/tokenization, zero tokens is `dropped.empty_body`; one to
four tokens is `dropped.short_body`; five or more produces shingles.

### RED tests

Cover multipart mail, attachment exclusion, quoted replies, malformed charset,
subject-prefix normalization, duplicate Message-ID, short body, symlink,
source traversal order, and duplicate pair rejection.

Run:

```bash
python3 -m unittest \
  tests.scripts.test_real_dataset_preprocess.EnronTests -v
```

Expected RED output: Enron mode or at least one pinned golden semantic is
absent/mismatched.

### Pass conditions

- Exact pair count and minimum related-pair count hold.
- Same-pair and unwanted same-thread duplicates are absent.
- Drop statistics and set-size min/median/p95/max are in the manifest.
- 2^16 and 2^20 variants select the same documents/pairs.
- Repeated outputs are byte-identical.

## Phase 4 — Add a strict C++ processed-data loader

### Files

- Add: `include/data/real_dataset.h`
- Add: `src/data/real_dataset.cpp`
- Add: `tests/unit/test_real_dataset.cpp`
- Modify: `CMakeLists.txt`

### API

```cpp
RealDataset LoadRealDataset(
    const std::filesystem::path& manifest_path);
```

The returned object contains metadata, sorted raw/bucketed feature sets, and
pair endpoints/kind/label.

### RED tests

Reject unsupported schema, manifest path escape, checksum mismatch, wrong
column count, duplicate IDs, unknown endpoint, unsorted/duplicate features,
out-of-universe bucket, invalid label/kind, and count mismatch. Verify Python
and C++ feature-hash/bucketing golden vectors.

Run:

```bash
cmake --build build -j4 --target test_real_dataset
./build/test_real_dataset
```

Expected RED output: loader/target absent.

### Pass conditions

- All valid/malformed fixtures behave exactly as specified.
- Full validation completes before benchmark key generation.
- Loader writes nothing and does not pollute CSV/stdout.

## Phase 5 — Add real-data accuracy and timing benchmark

### Files

- Add: `benchmarks/bench_real_datasets.cpp`
- Add: `include/data/real_dataset_metrics.h`
- Add: `src/data/real_dataset_metrics.cpp`
- Add: `tests/unit/test_real_dataset_metrics.cpp`
- Add: `scripts/summarize_real_datasets.py`
- Add: `tests/scripts/test_real_dataset_pipeline.py`
- Modify: `CMakeLists.txt`

### RED tests

Add the metrics and script tests before the implementation. They must fail
because the benchmark, canonical CSV writer, and summarizer do not yet exist.
Pin a golden two-pair CSV whose median is the arithmetic mean of the two
middle sorted values and whose P95 uses the documented nearest-rank rule.

Expected RED output: missing target/module or a golden-output mismatch.

### Accuracy mode

```bash
./build/bench_real_datasets \
  --dataset-manifest=/path/dataset.manifest.tsv \
  --mode=accuracy --k=128 --m=64 --max-pairs=10000 \
  --accuracy_trials=1 --seed=20260729 --hash_randomness=resampled \
  --csv=/tmp/real_accuracy_<variant>.csv \
  --workload-manifest-out=/tmp/accuracy_workload.manifest.tsv \
  --workload-rows-out=/tmp/accuracy_workload.rows.tsv
```

All three output flags are mandatory and have no default.

Accuracy is a plaintext execution of the exact deployed estimator pipeline,
not 10,000 FHE queries. Each pair row records dataset/output hashes, pair
metadata, raw/bucketed set sizes and exact Jaccards, estimated Jaccard,
absolute/relative error, estimator model, CRS provenance, and
`measurement_kind=plaintext-estimator`.

Accuracy rows have this exact header: first the Work-4 columns in their
published order, then these columns in this order:

```text
dataset,variant,dataset_manifest_sha256,records_sha256,pairs_sha256,
pair_id,pair_kind,label,record_a,record_b,
k,m,hash_randomness,accuracy_trial_index,hash_seed,
set_size_a_raw,set_size_b_raw,set_size_a_bucketed,set_size_b_bucketed,
exact_jaccard_raw,exact_jaccard_bucketed,estimated_jaccard,
bucket_match_fraction,abs_error,rel_error,jaccard_bucket,
accuracy_workload_sha256
```

The complete Work-4 prefix is:

```text
profile_id,run_class,target_security_bits,cryptographic_profile,
nominal_security_bits,security_match,comparison_eligible,
comparison_scope,primitive,protocol_model,output_semantics,assurance_scope,
security_basis,cost_scope,precomputation_mode,
secure_division_included,measurement_kind,
workload_id,workload_manifest_sha256,execution_trace_sha256,
root_seed,omp_threads,
estimator_model,sanitizer_model,sanitizer_assurance,
transcript_stat_bits,max_queries,query_stat_bits,coefficient_stat_bits,
flood_margin_bits,eval_noise_bits,flood_noise_bits,
actual_ring_dim,log_q_bits,plaintext_modulus,num_limbs,openfhe_version,
target_semantics,target_jaccard,realized_intersection,realized_union,
realized_jaccard,timing_trials,accuracy_trials,omp_dynamic,measurement_status
```

Timing rows use the same prefix and dataset identity/endpoint columns through
`record_b`, followed exactly by:

```text
k,m,hash_seed,trial_index,phase_minhash_ms,phase_encode_ms,phase_encrypt_ms,
phase_cloud_multiply_ms,phase_cloud_rotate_ms,phase_sanitize_ms,
phase_decrypt_ms,phase_bias_correction_ms,total_query_ms,result_value,
ciphertext_bytes,upload_bytes,download_bytes
```

Their `measurement_kind` is `fhe-timing`; accuracy uses
`plaintext-estimator`. Non-applicable numeric cells are empty, booleans are
`true|false`, integer units are bytes/counts, and timing units are
milliseconds. Header/row counts are tested exactly.

Accuracy trial indices are zero-based. For each `(pair_id,trial_index)`:

```text
hash_seed = first-8-bytes-BE(
  SHA256("piccard-real-crs-v1" || 0x00 || BE64(root_seed) ||
         BE32(len(pair_id_utf8)) || pair_id_utf8 ||
         BE64(trial_index)))
```

The benchmark writes tab-separated `accuracy_workload.rows.tsv` with exact
header `pair_id,trial_index,hash_seed,record_a,record_b`, sorted by pair/trial,
and two-column `accuracy_workload.manifest.tsv` with:

```text
schema_version=piccard-real-accuracy-workload-v1
dataset_manifest_sha256,rows_sha256,k,m,root_seed,max_pairs,
accuracy_trials,hash_randomness,pair_selection=manifest-order-prefix
```

`workload_manifest_sha256` and appended `accuracy_workload_sha256` both equal
the exact manifest-file SHA-256. `bucket_match_fraction` is uncorrected
modulo-m equality; `estimated_jaccard` is the Plan-1 bias-corrected/clamped
deployed estimate.
`abs_error=abs(estimated_jaccard-exact_jaccard_bucketed)` and relative error
uses `exact_jaccard_bucketed` only when nonzero. Raw Jaccard is diagnostic.
The prefix `accuracy_trials` equals the CLI value.

Prefix values are fixed:

| field class | plaintext accuracy | FHE timing |
|---|---|---|
| profile/run/security | `plaintext-estimator`, `diagnostic`, numeric security empty | selected Work-4 profile |
| comparison flags | `security_match=false`, `comparison_eligible=false` | profile-resolved |
| primitive/protocol/output | `sha256-minhash`, `plaintext-estimator-pipeline`, `bias-corrected-jaccard-estimate` | `bfv-onehot-minhash`, `piccard-two-owner-outsourced`, `bias-corrected-jaccard-estimate` |
| workload | variant + workload SHA | timing pair + dataset-manifest SHA |
| sanitizer/FHE | string `not-applicable`, numeric empty | live Work-2/4 values |

Field-complete values:

```text
plaintext accuracy:
 profile_id=plaintext-estimator, run_class=diagnostic,
 target_security_bits=<empty>, cryptographic_profile=not-applicable,
 nominal_security_bits=<empty>, comparison_scope=diagnostic-only,
 assurance_scope=empirical-poc, security_basis=not-applicable,
 cost_scope=not-applicable, precomputation_mode=not-applicable,
 secure_division_included=false, measurement_status=measured,
 workload_id=real:<variant>:accuracy, omp_threads=1,
 execution_trace_sha256=not-applicable,
 target_semantics=observed-dataset-pair, target_jaccard=<empty>,
 timing_trials=<empty>, accuracy_trials=<CLI>, omp_dynamic=false
FHE timing:
 profile/security/nominal/match/eligibility=<Work-4 resolver>,
 comparison_scope=end-to-end-estimator,
 assurance_scope=live-bfv+empirical-sanitizer-poc,
 security_basis=<Work-4 resolver>,
 cost_scope=full-query-excluding-one-time-setup,
 precomputation_mode=crs-and-keys-only, secure_division_included=false,
 measurement_status=measured,
 workload_id=real:<variant>:timing:<profile>,
 execution_trace_sha256=not-applicable,
 target_semantics=observed-dataset-pair, target_jaccard=<empty>,
 timing_trials=<CLI>, accuracy_trials=<empty>, omp_dynamic=false
```

For each real pair the prefix `realized_intersection`, `realized_union`, and
`realized_jaccard` are the bucketed-set values and must equal the corresponding
per-pair exact fields. Timing and accuracy serializers call the same Work-4
typed row builder; no Plan-5-local token aliases are allowed.

Summaries group bucketed exact Jaccard into `[0,.1)`, `[.1,.3)`, `[.3,.6)`,
and `[.6,1]`, encoded respectively as
`b00_10|b10_30|b30_60|b60_100`. The upper endpoint 1 belongs to `b60_100`.
The exact summary header is:

```text
dataset,variant,jaccard_bucket,n,mae,sample_sd,median,p95,max,
ci95_low,ci95_high
```

Sort finite absolute errors. Median is the center value for odd `n` and the
arithmetic mean of the two center values for even `n`; P95 is nearest-rank
`sorted[ceil(0.95*n)-1]`. Sample SD uses denominator `n-1`. CI is the PoC
normal interval `mean ± 1.96*sample_sd/sqrt(n)` without clipping. For `n=0`,
all statistic cells are empty; for `n=1`, sample SD and both CI cells are
empty while mean/median/P95/max equal the sole value. If exact bucketed
Jaccard is zero, `rel_error` is the empty N/A sentinel, never zero or infinity.

All floating output is finite C-locale decimal with 17 significant digits
(`-0` normalized to `0`); Python and C++ golden tests require byte-identical
formatting. Manifest set-size median/P95 use these same median and nearest-rank
definitions over integer sizes; an empty processed dataset is invalid.

### Timing mode

```bash
./build/bench_real_datasets \
  --dataset-manifest=/path/dataset.manifest.tsv \
  --mode=timing --profile=std128-t40-primary \
  --k=128 --m=64 --trials=30 --timing-pair=median \
  --seed=20260729 \
  --csv=/tmp/real_timing_<variant>_std128-t40-primary.csv \
  --workload-manifest-out=/tmp/timing_workload.manifest.tsv
```

Both timing output flags are mandatory and have no default; timing input
serialization hashes live in the manifest, so timing has no separate workload
rows file.

Choose the pair minimizing distance from the median combined bucketed set
size, where combined size is
`set_size_a_bucketed + set_size_b_bucketed`, tie-broken by lexical `pair_id`.
Discard one warmup. Trial indices are zero-based after the warmup. Report separate
MinHash, encode, encrypt, cloud multiply/rotate/
sanitize, decrypt, and plaintext bias-correction timing, plus actual
profile/N/logQ and communication. `total_query_ms` is the sum of every listed
phase from MinHash through bias correction; dataset loading, context setup, and
key generation are excluded. `result_value` is the corrected estimate.
`ciphertext_bytes` is the serialized evaluated-result ciphertext;
`upload_bytes` is the sum of both serialized input ciphertexts; and
`download_bytes` equals the serialized evaluated result. Serialize to binary
memory with the production OpenFHE serializer and count exact bytes.
MinHash, encode, and encrypt phases are the sum over both owners. The fixed
timing seed is:

```text
first8BE(SHA256("piccard-real-timing-crs-v1" || 0x00 ||
  BE64(root_seed) || dataset_manifest_sha256_raw32 || BE32(k) || BE32(m) ||
  BE32(len(profile_id)) || profile_id))
```

Write a two-column `timing_workload.manifest.tsv` with literal schema
`piccard-real-timing-workload-v1`, dataset hash, selected pair, k/m/profile,
root seed, derived hash seed, and trials. It then binds every fresh encrypted
input pair with contiguous indexed keys:

```text
input_pair_count	31
input.000.role	warmup
input.000.trial_index	
input.000.a_sha256	<64hex>
input.000.b_sha256	<64hex>
input.001.role	measured
input.001.trial_index	0
input.001.a_sha256	<64hex>
input.001.b_sha256	<64hex>
...
input.030.role	measured
input.030.trial_index	29
```

The count is exactly `trials+1`; indices are zero-padded to three digits,
there is one warmup at index 000, measured trial indices are contiguous, and
each hash is over the production binary serialization of that trial's newly
encrypted owner input. Duplicate/missing/extra indices or hashes fail. Timing
rows' prefix workload SHA is this complete manifest SHA.

### RED tests

Test hand-calculated exact/bias-corrected values, zero-J relative sentinel,
empty summary bucket, seed provenance, accuracy path never invoking KeyGen,
timing source/pair hashes, exact headers/units/N/A encoding/numeric formatting,
`n=0|1|2` summaries, adjacent/malformed Message-ID tokens, timing-root-seed
sensitivity, the exact warmup+trial input-hash cardinality, and TOY
plaintext-vs-FHE equality.

Run:

```bash
cmake --build build -j4 --target test_real_dataset_metrics
./build/test_real_dataset_metrics
python3 -m unittest tests.scripts.test_real_dataset_pipeline -v
```

### Pass conditions

- Fixture exact Jaccards and summaries match hand calculations.
- TOY full-FHE result agrees with the plaintext estimator path.
- Accuracy rows cannot be confused with FHE timings.
- Timing rows carry complete profile/provenance and trial dispersion.
- STD192 never falls back to STD128.

## Phase 6 — Add real-data runner and fail-fast verifier

### Files

- Add: `scripts/run_real_datasets.sh`
- Add: `scripts/verify_real_dataset_outputs.py`
- Add: `tests/scripts/test_run_real_datasets.py`

### Runner

```bash
scripts/run_real_datasets.sh \
  --source-manifest=/path/dblp_acm.source.tsv \
  --dataset-manifest=/path/dblp_acm_u65536/dataset.manifest.tsv \
  --source-manifest=/path/enron.source.tsv \
  --dataset-manifest=/path/enron_u65536/dataset.manifest.tsv \
  --source-manifest=/path/enron.source.tsv \
  --dataset-manifest=/path/enron_u1048576/dataset.manifest.tsv \
  --profile=std128-t40-primary \
  --profile=std192-t40-primary \
  --build-dir=/absolute/path/to/release-build \
  --threads=8 --seed=20260729 \
  --results-root=/absolute/path/to/real-run
```

Quick mode uses only tracked synthetic fixtures and is always marked
diagnostic. Paper mode records exact argv, commit/dirty status, libraries,
machine/thread policy, dataset and output checksums, profiles, and model labels.
`--quick` fixes run-level `evidence_mode=quick`; its absence with explicit
source/dataset pairs fixes `evidence_mode=paper`. No CLI may override this
derived origin field.
Every non-dry invocation requires an absolute `--results-root`, creates exactly
that directory (or validates it under explicit `--resume`), and never creates
an implicit timestamp or `latest` symlink. Existing output is not overwritten.

For each manifest in CLI order, the runner emits exactly:

```text
bench_real_datasets --dataset-manifest=<M> --mode=accuracy
  --k=128 --m=64 --max-pairs=10000 --accuracy_trials=1
  --seed=20260729 --hash_randomness=resampled
  --csv=<root>/csv/real_accuracy_<variant>.csv
  --workload-manifest-out=<root>/workloads/accuracy_<variant>.manifest.tsv
  --workload-rows-out=<root>/workloads/accuracy_<variant>.rows.tsv
summarize_real_datasets.py --input=<accuracy.csv>
  --output=<root>/csv/real_accuracy_summary_<variant>.csv
bench_real_datasets --dataset-manifest=<M> --mode=timing
  --profile=std128-t40-primary --k=128 --m=64 --trials=30
  --timing-pair=median --seed=20260729
  --csv=<root>/csv/real_timing_<variant>_std128-t40-primary.csv
  --workload-manifest-out=<root>/workloads/timing_<variant>_std128-t40-primary.manifest.tsv
bench_real_datasets --dataset-manifest=<M> --mode=timing
  --profile=std192-t40-primary --k=128 --m=64 --trials=30
  --timing-pair=median --seed=20260729
  --csv=<root>/csv/real_timing_<variant>_std192-t40-primary.csv
  --workload-manifest-out=<root>/workloads/timing_<variant>_std192-t40-primary.manifest.tsv
```

It resolves the executable only from absolute `--build-dir`, records its
SHA-256. Accuracy/summarizer cells run with
`OMP_NUM_THREADS=1,OMP_DYNAMIC=FALSE`; FHE timing cells use caller
`OMP_NUM_THREADS=<threads>,OMP_DYNAMIC=FALSE`. Each cell records its exact
effective environment, so the accuracy row's `omp_threads=1` is truthful.
`--dry-run`
executes before directory creation and prints this matrix. Under `--resume`,
every command, source/processed manifest, binary, output checksum, commit, and
profile must match; otherwise fail. Canonicalize every path and require it to
remain beneath its role-specific root: original data beneath its declared
source base; each external processed manifest, its records/pairs, and copied
source manifest beneath the canonical processed-dataset directory containing
that manifest; copied inputs and all outputs beneath `--results-root`,
executables beneath canonical `--build-dir`, and runner/summarizer scripts
beneath the clean committed source root. No role may borrow another role's
allowlist.

`run_metadata.tsv` is the canonical two-column run manifest with literal
`schema_version=piccard-real-run-v1`, run-level
`evidence_mode=paper|quick`, source commit/dirty/build type,
build-dir/binary SHA, exact ordered argv/environment, thread policy, every
input/output relative path and SHA, and cell status. Indexed cell keys are
exactly:

```text
schema_version	piccard-real-run-v1
evidence_mode	paper
source_commit	<40hex>
git_dirty	false
build_type	Release
root_count	<N>
root.000.id	source-root
root.000.path	<canonical absolute path>
artifact_count	<N>
artifact.000.role	system-info
artifact.000.path	system_info.txt
artifact.000.sha256	<64hex>
cell_count	<N>
cell.000.id	<variant>:accuracy
cell.000.argv_sha256	<64hex>
cell.000.argv_count	<N>
cell.000.argv.000	<exact UTF-8 argument>
cell.000.env_count	2
cell.000.env.000.key	OMP_DYNAMIC
cell.000.env.000.value	FALSE
cell.000.env.001.key	OMP_NUM_THREADS
cell.000.env.001.value	1
cell.000.input_count	<N>
cell.000.input.000.role	processed-manifest
cell.000.input.000.root_id	processed-dataset-<variant>
cell.000.input.000.path	dataset.manifest.tsv
cell.000.input.000.sha256	<64hex>
cell.000.output_count	<N>
cell.000.output.000.path	<results-root-relative path>
cell.000.output.000.sha256	<64hex>
cell.000.status	complete
```

Root/artifact/cell/argv/env/input/output indices are contiguous and
zero-padded; argv SHA is over `BE32(length)||argument-bytes` in order and
environment keys are sorted ASCII. Global artifacts include every copied
source/processed manifest, `system_info.txt`, and the finalized `run.log`;
the runner closes/fsyncs the log before hashing artifacts and writing metadata.
Interrupted work uses invocation-numbered `.partial` logs; resume validates
and incorporates them, then creates the immutable final `run.log` only when
all cells are complete.
`run_metadata.tsv` itself and later `verification_status.tsv` are explicitly
excluded to avoid self-reference. There is no unindexed free-form cell data.
Paper mode
requires clean Git and `CMAKE_BUILD_TYPE=Release`. Resume skips exactly a
`status=complete` cell only after recomputing and matching every binding;
missing cells run, failed/inconsistent cells abort.

Verifier state is non-circular and separate. The runner never writes verifier
status. `verify_real_dataset_outputs.py <results-root>` parses the exact
metadata schema, resolves every role against its allowlist, recomputes every
input/output/argv/manifest hash and semantic row invariant, then atomically
writes `verification_status.tsv` containing exactly
`schema_version=piccard-real-verification-v1`,
`run_metadata_sha256=<64hex>`, and `status=VERIFIED`. A rerun must reproduce
the same bytes; a stale/mismatched status fails.

Quick expands the same pipeline for exactly the tracked DBLP and Enron fixture
manifest pairs, with `max_pairs=2`, `accuracy_trials=1`, and one
`profile=toy-smoke,trials=1` timing cell per fixture. It still requires
absolute `--build-dir` and explicit positive `--seed` and `--threads` (there
are no hidden defaults), writes the same workload/summary/manifest layout, and
sets every row/run class to diagnostic. The golden runner test pins the
effective seed/thread environment and complete argv list.

Non-quick actual-data verification rejects fixture masquerading
deterministically using run-level `evidence_mode=paper`; row-level
`run_class`/`measurement_kind` retain their Work-4/plaintext meanings and are
not repurposed as a data-origin flag. The exact quick manifest pairs are:

```text
tests/fixtures/real_datasets/quick/dblp_acm_u65536/{source.manifest.tsv,dataset.manifest.tsv}
tests/fixtures/real_datasets/quick/enron_u65536/{source.manifest.tsv,dataset.manifest.tsv}
tests/fixtures/real_datasets/quick/enron_u1048576/{source.manifest.tsv,dataset.manifest.tsv}
```

At configure/test time, the verifier builds a checked-in fixture fingerprint
table from every raw role `input_sha256` (or canonical Enron tree digest) and
each processed `records_sha256` and `pairs_sha256` at those paths. Paper mode
rejects any input whose underlying raw/tree digest or either processed-content
digest matches that table, regardless of changed citation/acquisition
metadata, manifest bytes, filename, or variant token. `evidence_mode=quick`
can never produce `VERIFIED_ACTUAL_DATA`; paper mode plus all content-origin
and semantic checks can.

Result layout:

```text
/absolute/path/to/real-run/
  csv/real_accuracy_<variant>.csv
  csv/real_accuracy_summary_<variant>.csv
  csv/real_timing_<variant>_<profile>.csv
  workloads/accuracy_<variant>.manifest.tsv
  workloads/accuracy_<variant>.rows.tsv
  workloads/timing_<variant>_<profile>.manifest.tsv
  input_manifests/<variant>/source.manifest.tsv
  input_manifests/<variant>/dataset.manifest.tsv
  run_metadata.tsv
  verification_status.tsv  # verifier output; absent until verification passes
  system_info.txt
  run.log
```

### RED tests

With fake binaries/data, require fail-fast on missing source role/checksum,
placeholder license/citation, missing variant/row, dropped DBLP positive,
insufficient Enron related pairs, absent STD128/STD192 timing, model/path
omission, NaN/Inf, or fixture masquerading as real evidence.
Pin the complete argv/environment matrix and prove dry-run has zero side
effects. Also reject relative roots, path escape, pre-existing root without
resume, invalid resume checksum/argv, source-manifest-copy mismatch, and
`original_positive_count != retained_positive_count`. Fixtures enumerate
every cell ID exactly:

```text
<variant>:accuracy
<variant>:accuracy-summary
<variant>:timing:<profile_id>
```

Paper mode has three variants, one accuracy and summary cell each, and two
timing profiles each; quick has its declared fixture variants and one
`toy-smoke` timing profile. Duplicate/missing/unknown IDs fail.

Run:

```bash
python3 -m unittest tests.scripts.test_run_real_datasets -v
```

Expected RED output: runner/verifier modules are absent, or a negative fixture
is incorrectly accepted.

### Pass conditions

```bash
scripts/run_real_datasets.sh --quick --seed=7 --threads=2 \
  --build-dir="$(pwd)/build" \
  --results-root=/tmp/piccard-real-quick
python3 scripts/verify_real_dataset_outputs.py /tmp/piccard-real-quick
```

- Quick fixture run and verifier pass.
- If real data is available, all three declared variants and both primary
  profiles pass with verified manifests.
- If raw data/license/checksum is unavailable, the implementation status is
  `IMPLEMENTED_DATA_PENDING`; W2 is not marked resolved and Work 7 must carry
  this blocker explicitly.

## Work-level verification

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
ctest --test-dir build --output-on-failure
scripts/run_real_datasets.sh --quick --resume --seed=7 --threads=2 \
  --build-dir="$(pwd)/build" \
  --results-root=/tmp/piccard-real-quick
python3 scripts/verify_real_dataset_outputs.py /tmp/piccard-real-quick
```

Review artifacts: preprocessing golden outputs, C++ validation tests, quick
accuracy/timing CSVs, runner/verifier logs, and—when available—actual dataset
manifests/results. Work 6 starts only after GPT-5.6-sol and Fable both approve
the implementation, write read-only
`$REVIEW_STAGING_ROOT/work-5-{gpt,fable}.md`, and
`verify_work_approval.py --work-id=5 --expected-base="$WORK4_HEAD"
--plan-path=docs/superpowers/plans/2026-07-29-05-real-dataset-pipeline.md
... --print-head` returns the exact clean
Work-5 product head. Actual data absence remains a declared integration
blocker rather than a hidden implementation failure.
