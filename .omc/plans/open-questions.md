# Open Questions

## dynamic-threshold-benchmarks - 2026-02-27

- [x] What is the maximum k value that should be attempted for threshold benchmarks at STD128? k=128 requires mult_depth=19, which may be at the edge of OpenFHE's capabilities. Need to determine empirically during first run. -- **RESOLVED:** mult_depth is actually 15 (not 19). At STD128, ring_dim ~65536 is slow but feasible. k=128 is included by default for TOY and STD128. For STD192/STD256, k stops at 64 by default with `--max_k=128` opt-in.
- [ ] Should the dynamic benchmark measure incremental update cost (single Insert/Delete) or batch update cost (N inserts followed by protocol rerun)? Current plan measures batch throughput. -- Affects what the paper can claim about amortized vs per-operation cost.
- [ ] For threshold accuracy, should false positive/negative rates be computed per-tau or aggregated across all tau values? Current plan computes per-tau. -- Affects table layout in the paper.
- [x] Should helper functions (ExactJaccard, MakeSetsWithOverlap, Median) be extracted from bench_piccard.cpp into benchmark_utils.h to avoid duplication? Current plan accepts duplication for simplicity. -- **RESOLVED:** Accept duplication for now per ADR. Extract to benchmark_utils.h only if a third benchmark executable is needed.
- [ ] What tau values are most meaningful for the paper? Current plan uses {1, k/4, k/2, 3k/4, k}. The paper may want specific tau values that correspond to meaningful Jaccard thresholds (e.g., tau such that J >= 0.5). -- Affects what data the paper presents.
- [ ] Monitor k=128 at STD128 runtime empirically. If single-run takes >5 minutes, consider making it opt-in (like STD192/STD256) rather than default. -- Determines whether paper-grade runs are practical with current defaults.
