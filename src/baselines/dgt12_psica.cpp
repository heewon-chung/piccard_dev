/**
 * @file dgt12_psica.cpp
 * @brief DGT12 Private Set Intersection Cardinality (EsPRESSo Fig. 1), an
 *        in-process, instrumented simulation on top of the `Group`
 *        abstraction. See dgt12_psica.h for the wire-level cost model.
 *
 * Protocol (Fig. 1): Alice A={a_1..a_v}, Bob B={b_1..b_w}.
 *   1. Alice: R_a<-Z_q; forall i: ha_i=H(a_i), alpha_i=ha_i^{R_a} -> send {alpha_i}.
 *   2. Bob: shuffle B (Pi); R_b<-Z_q; forall i: alpha'_i=alpha_i^{R_b}, shuffle
 *      {alpha'} (Pi'); forall j: beta_j=hb_j^{R_b}, tb_j=H'(beta_j)
 *      -> send {alpha'}, {tb_j}.
 *   3. Alice: forall i: beta'_i=(alpha'_i)^{1/R_a mod q}, ta_i=H'(beta'_i);
 *      output |{tb} ∩ {ta}|.
 */

#include "baselines/dgt12_psica.h"

#include <openssl/rand.h>

#include <chrono>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

namespace piccard {
namespace baselines {

namespace {

using Clock = std::chrono::steady_clock;

double ElapsedMs(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

// Uniform index in [0, range) via CSPRNG (RAND_bytes) with rejection sampling
// to avoid modulo bias. Security-relevant: backs the Fisher-Yates shuffles
// below (must-not: no std::mt19937_64 on this path).
size_t CsprngIndexBelow(size_t range) {
    if (range <= 1) return 0;
    const uint64_t max = std::numeric_limits<uint64_t>::max();
    const uint64_t limit = max - (max % static_cast<uint64_t>(range));
    uint64_t x = 0;
    do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&x), sizeof(x)) != 1) {
            throw std::runtime_error("RunDgt12: RAND_bytes failed (CSPRNG shuffle)");
        }
    } while (x >= limit);
    return static_cast<size_t>(x % static_cast<uint64_t>(range));
}

// Fisher-Yates shuffle drawing each swap index from the CSPRNG above.
std::vector<size_t> FisherYatesCsprng(size_t n) {
    std::vector<size_t> idx(n);
    for (size_t i = 0; i < n; ++i) idx[i] = i;
    for (size_t i = n; i-- > 1;) {
        size_t j = CsprngIndexBelow(i + 1);
        std::swap(idx[i], idx[j]);
    }
    return idx;
}

std::string ToKey(const std::vector<uint8_t>& tag) {
    return std::string(tag.begin(), tag.end());
}

}  // namespace

PsiCaCost RunDgt12(const Group& group,
                    const std::vector<std::vector<uint8_t>>& a_items,
                    const std::vector<std::vector<uint8_t>>& b_items,
                    ExponentSource test_only_exp) {
    PsiCaCost cost;
    const size_t v = a_items.size();
    const size_t w = b_items.size();

    auto DrawExponent = [&]() -> std::vector<uint8_t> {
        return test_only_exp ? test_only_exp() : group.RandomExponent();
    };

    // Pre-hash: H(a_i) forall i, H(b_j) forall j. Timed once, BEFORE the
    // masking rounds, so this cost is attributable exactly once (to
    // phase_encode upstream) with no double counting inside the rounds below.
    std::vector<ElementPtr> ha(v);
    std::vector<ElementPtr> hb(w);
    {
        auto t0 = Clock::now();
        for (size_t i = 0; i < v; ++i) {
            ha[i] = group.HashToGroup(a_items[i], &cost.hash_exps);
        }
        for (size_t j = 0; j < w; ++j) {
            hb[j] = group.HashToGroup(b_items[j], &cost.hash_exps);
        }
        auto t1 = Clock::now();
        cost.hash_to_group_ms = ElapsedMs(t0, t1);
    }

    // Round 1 (Alice): R_a <- CSPRNG; alpha_i = ha_i^{R_a}. Exponentiation only.
    const std::vector<uint8_t> R_a = DrawExponent();
    std::vector<ElementPtr> alpha(v);
    {
        auto t0 = Clock::now();
        for (size_t i = 0; i < v; ++i) {
            alpha[i] = group.Exp(ha[i], R_a);
        }
        auto t1 = Clock::now();
        cost.alice_round1_ms = ElapsedMs(t0, t1);
    }
    cost.protocol_exps += v;
    cost.alice_upload_bytes = v * group.ElementBytes();  // {alpha}

    // Round 2 (Bob): shuffle B (Pi); alpha'_i = alpha_i^{R_b} forall i,
    // shuffle {alpha'} (Pi'); beta_j = hb_j^{R_b}, tb_j = H'(beta_j) forall j.
    const std::vector<uint8_t> R_b = DrawExponent();
    std::vector<ElementPtr> alpha_prime(v);
    std::vector<std::vector<uint8_t>> tb(w);
    {
        auto t0 = Clock::now();

        // Pi: shuffle Bob's own set order (drawn from CSPRNG) before re-hashing.
        const std::vector<size_t> pi = FisherYatesCsprng(w);

        for (size_t i = 0; i < v; ++i) {
            alpha_prime[i] = group.Exp(alpha[i], R_b);
        }

        // Pi': shuffle {alpha'} before it is (conceptually) sent back to Alice.
        const std::vector<size_t> pi_prime = FisherYatesCsprng(v);
        std::vector<ElementPtr> alpha_prime_shuffled(v);
        for (size_t i = 0; i < v; ++i) {
            alpha_prime_shuffled[i] = alpha_prime[pi_prime[i]];
        }
        alpha_prime = std::move(alpha_prime_shuffled);

        for (size_t j = 0; j < w; ++j) {
            const size_t src = pi[j];
            ElementPtr beta = group.Exp(hb[src], R_b);
            tb[j] = TagHash(group.Serialize(beta));
        }

        auto t1 = Clock::now();
        cost.bob_ms = ElapsedMs(t0, t1);
    }
    cost.protocol_exps += v + w;
    cost.bob_upload_bytes = v * group.ElementBytes() + w * 32;  // {alpha'} + {tb}

    // Round 3 (Alice): beta'_i = (alpha'_i)^{1/R_a}, ta_i = H'(beta'_i);
    // output |{tb} ∩ {ta}|. Unmask with ExpInverse and the SAME R_a.
    uint64_t cardinality = 0;
    {
        auto t0 = Clock::now();

        std::unordered_set<std::string> tb_set;
        tb_set.reserve(w);
        for (size_t j = 0; j < w; ++j) tb_set.insert(ToKey(tb[j]));

        for (size_t i = 0; i < v; ++i) {
            ElementPtr beta_prime = group.ExpInverse(alpha_prime[i], R_a);
            std::vector<uint8_t> ta = TagHash(group.Serialize(beta_prime));
            if (tb_set.count(ToKey(ta)) != 0) ++cardinality;
        }

        auto t1 = Clock::now();
        cost.alice_round2_ms = ElapsedMs(t0, t1);
    }
    cost.protocol_exps += v;
    cost.cardinality = cardinality;

    cost.payload_bytes = cost.alice_upload_bytes + cost.bob_upload_bytes;
    cost.total_ms = cost.hash_to_group_ms + cost.alice_round1_ms + cost.bob_ms + cost.alice_round2_ms;

    return cost;
}

}  // namespace baselines
}  // namespace piccard
