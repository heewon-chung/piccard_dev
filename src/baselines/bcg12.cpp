/**
 * @file bcg12.cpp
 * @brief BCG12 (EsPRESSo) as a `PJSBaseline`: DGT12 PSI-CA (Fig. 1) fed
 *        either raw sets (exact Jaccard, Fig. 2) or MinHash signatures
 *        (approximate Jaccard, Fig. 3). See bcg12.h for the params/QueryCost
 *        contract and the plan's QueryCost mapping table for phase wiring.
 */

#include "baselines/bcg12.h"

#include "baselines/dgt12_psica.h"
#include "baselines/group_ec.h"
#include "baselines/group_ff.h"
#include "core/minhash.h"

#include <chrono>
#include <cstdint>
#include <set>
#include <stdexcept>

namespace piccard {
namespace baselines {

namespace {
using Clock = std::chrono::steady_clock;

double ElapsedMs(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}
}  // namespace

BCG12::BCG12(const Bcg12Params& p) : params_(p) {}

BCG12::~BCG12() = default;

const char* BCG12::Name() const {
    if (params_.mode == Bcg12Mode::MinHash) {
        return params_.backend == Bcg12Backend::FF ? "bcg12_mh_ff" : "bcg12_mh_ec";
    }
    return params_.backend == Bcg12Backend::FF ? "bcg12_exact_ff" : "bcg12_exact_ec";
}

SecurityClass BCG12::Security() const { return SecurityClass::AHE_NoLeakage; }

void BCG12::Setup() {
    group_ = (params_.backend == Bcg12Backend::FF) ? MakeFiniteFieldGroup() : MakeEcGroup();
    if (params_.mode == Bcg12Mode::MinHash) {
        hasher_ = std::make_unique<piccard::MinHasher>(params_.k, UINT64_MAX, params_.minhash_seed);
    }
}

QueryCost BCG12::RunQuery(const std::vector<uint64_t>& set_x, const std::vector<uint64_t>& set_y) {
    if (!group_) {
        throw std::runtime_error("BCG12::RunQuery: Setup() was not called");
    }

    double preprocessing_ms = 0.0;
    double jaccard_estimate = 0.0;
    std::vector<std::vector<uint8_t>> a_items;
    std::vector<std::vector<uint8_t>> b_items;

    if (params_.mode == Bcg12Mode::MinHash) {
        if (!hasher_) {
            throw std::runtime_error("BCG12::RunQuery: MinHash mode requires Setup() to build hasher_");
        }
        const uint32_t k = params_.k;

        auto t0 = Clock::now();
        std::vector<uint64_t> sig_x = hasher_->ComputeSignature(set_x);
        std::vector<uint64_t> sig_y = hasher_->ComputeSignature(set_y);
        a_items.reserve(k);
        b_items.reserve(k);
        for (uint32_t i = 0; i < k; ++i) {
            a_items.push_back(EncodeTaggedItem(sig_x[i], i));
            b_items.push_back(EncodeTaggedItem(sig_y[i], i));
        }
        auto t1 = Clock::now();
        preprocessing_ms = ElapsedMs(t0, t1);

        PsiCaCost psi = RunDgt12(*group_, a_items, b_items);
        jaccard_estimate = k > 0 ? static_cast<double>(psi.cardinality) / static_cast<double>(k) : 0.0;

        QueryCost qc;
        qc.phase_encode_ms = preprocessing_ms + psi.hash_to_group_ms;
        qc.phase_encrypt_ms = psi.alice_round1_ms;
        qc.phase_compute_ms = psi.bob_ms;
        qc.phase_decrypt_ms = psi.alice_round2_ms;
        qc.total_ms = qc.phase_encode_ms + qc.phase_encrypt_ms + qc.phase_compute_ms + qc.phase_decrypt_ms;
        qc.comm_bytes = psi.payload_bytes;
        qc.ct_size_bytes = psi.alice_upload_bytes;
        qc.jaccard_estimate = jaccard_estimate;
        return qc;
    }

    // Exact mode (Fig. 2) lands in Task 2.2.
    throw std::runtime_error("BCG12::RunQuery: Exact mode not yet implemented");
}

}  // namespace baselines
}  // namespace piccard
