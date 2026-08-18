#include "dynamic_probe_workload.h"

#include "benchmark_utils.h"
#include "core/bottom_structure.h"

namespace piccard::benchmark {

ProbeWorkloadTiming RunProbeWorkload(BottomStructure& probe_structure,
                                     const std::vector<uint64_t>& owner_set,
                                     uint64_t probe_base,
                                     size_t num_ops) {
    ProbeWorkloadTiming timing;
    Timer timer;

    // Insert phase. Insert never arms the rebuild flag (bottom_structure.cpp
    // only sets it from Delete), and the scratch copy starts clear because it
    // was copied from a freshly Initialize()d structure, so no guard is needed.
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        probe_structure.Insert(probe_base + i);
    }
    timing.insert_ms = timer.ElapsedMs();

    // Delete phase. Undo the inserts, rebuilding whenever a delete has emptied
    // a bottom row.
    //
    // Rebuild set: the owner's set plus the probes not yet deleted. At the
    // rebuild point the structure's logical members are exactly
    // owner_set U {probe_base + i, ..., probe_base + num_ops - 1}, so
    // Initialize over that set restores precisely the d-deep sketch the
    // protocol's owner would hold. Rebuilding from owner_set alone would be
    // wrong in a way that hides itself: the remaining probe hashes would be
    // absent, so their Delete calls would silently no-op (Delete is a
    // lower_bound miss for a non-member) and the measured per-op cost would
    // drift below the real one.
    //
    // Timer accounting: rebuild time is excluded from delete_ms, and therefore
    // from ops_delete_per_sec. delete_ms is the paper's Algorithm 5 throughput
    // figure; a rebuild is Algorithm 3, an O(n*k) operation of a different
    // kind, whose cost the dynamic_refresh family reports on its own terms.
    // Folding an Initialize into a 100-op delete batch would yield a number
    // that is neither delete throughput nor rebuild cost, and whose magnitude
    // would be dominated by a harness artifact (100 synthetic probes forced
    // through a depth-5 sketch) rather than by the protocol. The excluded cost
    // is not discarded: rebuild_count and rebuild_ms carry it back to the
    // caller.
    std::vector<uint64_t> rebuild_set;
    rebuild_set.reserve(owner_set.size() + num_ops);
    timer.Start();
    for (size_t i = 0; i < num_ops; i++) {
        if (probe_structure.RequiresRebuild()) {
            timing.delete_ms += timer.ElapsedMs();

            Timer rebuild_timer;
            rebuild_timer.Start();
            rebuild_set.assign(owner_set.begin(), owner_set.end());
            for (size_t j = i; j < num_ops; j++) {
                rebuild_set.push_back(probe_base + j);
            }
            probe_structure.Initialize(rebuild_set);
            timing.rebuild_ms += rebuild_timer.ElapsedMs();
            timing.rebuild_count++;

            timer.Start();
        }
        probe_structure.Delete(probe_base + i);
    }
    timing.delete_ms += timer.ElapsedMs();

    return timing;
}

}  // namespace piccard::benchmark
