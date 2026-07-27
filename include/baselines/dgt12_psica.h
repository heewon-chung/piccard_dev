#pragma once
#include "baselines/group.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace piccard { namespace baselines {

struct PsiCaCost {
    // HashToGroup for ALL items (Alice's H(a_i) + Bob's H(b_j)) is measured here,
    // BEFORE the masking rounds, so its wall-time is attributed exactly once (to
    // phase_encode) with no double counting inside the rounds below.
    double hash_to_group_ms = 0.0; // H(a_i) ∀i + H(b_j) ∀j  (excl. from the 3 rounds)
    double alice_round1_ms = 0.0;  // alpha_i = ha_i^{R_a}                     (|A| exps)
    double bob_ms          = 0.0;  // alpha'_i=alpha_i^{R_b}(|A|) + beta_j=hb_j^{R_b}(|B|) + shuffles + H'
    double alice_round2_ms = 0.0;  // beta'_i=alpha'^{1/R_a}(|A|) + ta_i=H'(...) + match
    double total_ms        = 0.0;  // hash_to_group_ms + the 3 rounds

    // Masking exponentiations only: Alice 2|A| (round1 |A| + round2 |A|) + Bob (|A|+|B|)
    // = 3|A| + |B|  (== 4k when |A|=|B|=k). Matches EsPRESSo §3.3 "4k".
    size_t protocol_exps = 0;
    size_t hash_exps     = 0;      // cofactor exps inside HashToGroup (FF only); 0 for EC try-and-increment
    size_t alice_upload_bytes = 0; // {alpha}                       (== |A|·EB)
    size_t bob_upload_bytes   = 0; // {alpha'} + {tb}               (== |A|·EB + |B|·32)
    size_t payload_bytes      = 0; // alice_upload + bob_upload (total cryptographic payload; Alice
                                   // computes the count locally, so there is NO "result download")
    uint64_t cardinality = 0;      // |A ∩ B| (Alice-only output)
};

// Optional test-only deterministic exponent source. Production passes nullptr → CSPRNG.
using ExponentSource = std::function<std::vector<uint8_t>()>;

PsiCaCost RunDgt12(const Group& group,
                   const std::vector<std::vector<uint8_t>>& a_items,
                   const std::vector<std::vector<uint8_t>>& b_items,
                   ExponentSource test_only_exp = nullptr);

}} // namespace
