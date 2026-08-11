#pragma once

#include <cstdint>
#include <string>

namespace piccard::bench {

// Plain local-encoder CLI contract for the STD192 Work #5 diagnostic.  This
// interface intentionally contains no cryptosystem types: its implementation
// derives the canonical MinHash input outside the timed region and invokes
// only the core OneHotEncoder or SqrtEncoder.
struct RealEncodingCliArgs {
    std::string dataset_manifest_path;
    std::string profile_id;
    std::string method;
    uint32_t k = 0;
    uint32_t m = 0;
    uint32_t trials = 0;
    std::string timing_pair;
    uint64_t root_seed = 0;
    std::string csv_path;
    std::string workload_manifest_out_path;
};

// Produces exactly one discarded warmup, one timed core encoder call, and one
// independent encoder correctness call for either explicit Work #5 encoding
// method.  The output schema deliberately has no end-to-end query or
// cryptosystem-phase fields.
int RunRealEncodingMode(const RealEncodingCliArgs& args);

}  // namespace piccard::bench
