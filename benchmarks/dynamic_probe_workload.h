#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace piccard {
class BottomStructure;

namespace benchmark {

// First synthetic probe element. Probes occupy [kDynamicProbeBase,
// kDynamicProbeBase + num_ops), disjoint from the MakeSetsWithOverlap ranges
// (shared < 1000000, owner-A tail in 1000000+, owner-B tail in 2000000+).
inline constexpr uint64_t kDynamicProbeBase = 3000000;

// Timings and rebuild accounting for one insert/delete throughput probe batch.
struct ProbeWorkloadTiming {
    double insert_ms = 0.0;
    // Algorithm 5 (Delete) cost only. Owner-side rebuilds are excluded; see
    // RunProbeWorkload for the methodology rationale.
    double delete_ms = 0.0;
    // Algorithm 3 (Initialize) cost incurred inside the delete loop, reported
    // separately so an excluded rebuild is never a silently dropped cost.
    double rebuild_ms = 0.0;
    size_t rebuild_count = 0;
};

/**
 * @brief Run the dynamic insert/delete throughput probe batch on a structure.
 *
 * Inserts `num_ops` synthetic probes into `probe_structure`, then deletes them
 * back, timing each phase. `probe_structure` must be a scratch copy: the
 * depth-d bottom structure discards evicted originals permanently, so the
 * probes are destructive and must never touch the signature-bearing structure.
 *
 * Deleting probes can empty a bottom row (all d retained hashes for some hash
 * function were probe hashes), which arms BottomStructure's rebuild flag and
 * makes every later Insert/Delete/GetSignature throw. That is the engine's
 * correct Algorithm 3/4/5 contract, so the harness handles it the way the
 * protocol's owner would: re-run Initialize over the current logical member
 * set and continue.
 *
 * @param probe_structure Scratch copy of the owner's bottom structure.
 * @param owner_set       The owner's set, used as the rebuild base.
 * @param probe_base      First probe element (see kDynamicProbeBase).
 * @param num_ops         Number of probes to insert and then delete.
 */
ProbeWorkloadTiming RunProbeWorkload(BottomStructure& probe_structure,
                                     const std::vector<uint64_t>& owner_set,
                                     uint64_t probe_base,
                                     size_t num_ops);

}  // namespace benchmark
}  // namespace piccard
