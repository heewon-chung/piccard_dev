#pragma once

/**
 * @file pjs_baseline.h
 * @brief Common contract for private Jaccard similarity (PJS) baselines
 *
 * Piccard is compared against protocols built on very different primitives
 * (BFV, AHE, DH-based PSI-CA), so bench_comparison drives them through one
 * interface and records the security class alongside the cost. Reporting the
 * security class is what keeps "comparison within the same security class"
 * (BCG12, SJ16) separate from "comparison against a weaker baseline"
 * (ZLG+24, which is KPA-secure and leaks during execution).
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace piccard {
namespace baselines {

// What a protocol guarantees, used to group rows in the comparison table.
enum class SecurityClass {
    CPA_NoLeakage,  // IND-CPA, no during-execution leakage (Piccard)
    AHE_NoLeakage,  // AHE/DH-based, no during-execution leakage (BCG12, SJ16)
    KPA_Leakage,    // KPA-secure, leaks during execution (ZLG+24)
    Unknown,
};

inline const char* ToString(SecurityClass sc) {
    switch (sc) {
        case SecurityClass::CPA_NoLeakage: return "CPA/no-leakage";
        case SecurityClass::AHE_NoLeakage: return "AHE/no-leakage";
        case SecurityClass::KPA_Leakage:   return "KPA/leakage";
        case SecurityClass::Unknown:       return "unknown";
    }
    return "unknown";
}

// Cost of a single PJS query, uniform across protocols. Phases that a given
// protocol does not have (e.g. no encrypt step) stay at 0.
struct QueryCost {
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_compute_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double total_ms = 0.0;

    size_t comm_bytes = 0;      // 2x upload + 1x result download
    size_t ct_size_bytes = 0;   // per-party upload

    double jaccard_estimate = 0.0;
};

// Implemented by each baseline protocol. Setup() covers one-time key/parameter
// generation and is excluded from per-query cost.
class PJSBaseline {
public:
    virtual ~PJSBaseline() = default;

    virtual const char* Name() const = 0;
    virtual SecurityClass Security() const = 0;

    virtual void Setup() = 0;

    virtual QueryCost RunQuery(const std::vector<uint64_t>& set_x,
                               const std::vector<uint64_t>& set_y) = 0;
};

} // namespace baselines
} // namespace piccard
