#pragma once

/**
 * @file baseline_engine.h
 * @brief FHE-IND comparator: binary vector encoding + BFV inner product
 *
 * Implements pairwise Jaccard computation using full-dimension binary vectors
 * encrypted with BFV, in the style of LeP20's one-hot BFV construction. This
 * is not a faithful reimplementation of ZLG+24/EPSet; this is a
 * universe-sized BFV indicator-vector protocol, implemented in C++ using the
 * same OpenFHE library as Piccard for a fair same-machine comparison.
 *
 * Key difference from Piccard: encodes sets as binary vectors of dimension
 * U_set (universe size), whereas Piccard compresses to dimension k*m via
 * MinHash + one-hot encoding. When U_set >> k*m, the comparator requires
 * larger ring_dim, making all BFV operations more expensive.
 */

#include "util/params.h"
#include "fhe/bfv_context.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace piccard {
namespace baseline {

// ============================================================================
// BaselineParams - Configuration for binary vector baseline
// ============================================================================

struct BaselineParams {
    uint32_t universe_size;  // U_set: dimension of binary vectors
    SecurityLevel security = SecurityLevel::STD128;

    // Derived by Validate()
    uint32_t ring_dim = 0;
    uint64_t plaintext_mod = 0;
    uint32_t num_ciphertexts = 0;  // ceil(U_set / ring_dim)
    uint32_t mult_depth = 1;

    uint32_t RequestedFeatureDim() const {
        return requested_feature_dim_;
    }

    void Validate() {
        if (universe_size == 0) {
            throw std::invalid_argument("universe_size must be > 0");
        }
        requested_feature_dim_ = universe_size;

        uint32_t min_ring = MinRingDimForSecurity(security);
        ring_dim = NextPowerOf2(universe_size);
        if (ring_dim < min_ring) {
            ring_dim = min_ring;
        }

        // BFV plaintext modulus: prime p > 1, p == 1 mod 2N
        // Binary vectors only need values 0/1, but inner product can be up to
        // universe_size, so we need p > universe_size to avoid wrap-around.
        uint32_t two_n = 2 * ring_dim;
        plaintext_mod = FindPlaintextModulus(universe_size, two_n);
        assert(IsPrime(plaintext_mod));

        num_ciphertexts = (universe_size + ring_dim - 1) / ring_dim;
        mult_depth = 1;
    }

    void AdoptRuntimeRingDim(uint32_t actual) {
        if (requested_feature_dim_ == 0) {
            throw std::logic_error(
                "baseline runtime adoption requires validated parameters");
        }
        if (actual == 0 || (actual & (actual - 1)) != 0) {
            throw std::invalid_argument(
                "baseline runtime ring dimension must be a power of two");
        }
        if (actual < requested_feature_dim_) {
            throw std::invalid_argument(
                "baseline runtime ring dimension does not cover the requested "
                "feature dimension");
        }
        ring_dim = actual;
        num_ciphertexts =
            (requested_feature_dim_ + ring_dim - 1) / ring_dim;
    }

private:
    uint32_t requested_feature_dim_ = 0;
};

// ============================================================================
// MakeBFVParams - Bridge BaselineParams -> PiccardParams for BFVContext reuse
// ============================================================================

static inline PiccardParams MakeBFVParams(const BaselineParams& bp) {
    PiccardParams pp;
    // Set user-configurable fields to dummy values that won't be used
    pp.k = 1;
    pp.m = bp.universe_size;
    pp.security = bp.security;
    // Set derived fields directly (bypass Validate)
    pp.feature_dim = bp.RequestedFeatureDim();
    pp.ring_dim = bp.ring_dim;
    pp.plaintext_mod = bp.plaintext_mod;
    pp.mult_depth = bp.mult_depth;
    pp.hash_range = UINT64_MAX;
    return pp;
}

// ============================================================================
// BaselineEngine - Binary vector + BFV inner product
// ============================================================================

class BaselineEngine {
public:
    explicit BaselineEngine(const BaselineParams& params)
        : params_(params) {}

    void Initialize() {
        auto pp = MakeBFVParams(params_);
        bfv_ctx_ = std::make_unique<BFVContext>(pp);
        bfv_ctx_->Initialize();

        // Baseline runtime adoption is intentionally independent of the
        // sanitizer profile/fingerprint path.
        uint32_t actual = bfv_ctx_->GetSlotCount();
        params_.AdoptRuntimeRingDim(actual);
    }

    /// Encode a set as binary vector chunks (one vector per ciphertext).
    /// For each element e in set, sets chunks[e / ring_dim][e % ring_dim] = 1.
    std::vector<std::vector<int64_t>>
    EncodeBinaryVectors(const std::vector<uint64_t>& set) const {
        std::vector<std::vector<int64_t>> chunks(
            params_.num_ciphertexts,
            std::vector<int64_t>(params_.ring_dim, 0));

        for (uint64_t e : set) {
            if (e >= params_.universe_size) {
                throw std::out_of_range(
                    "Element " + std::to_string(e) +
                    " >= universe_size " + std::to_string(params_.universe_size));
            }
            uint32_t chunk_idx = static_cast<uint32_t>(e / params_.ring_dim);
            uint32_t slot_idx = static_cast<uint32_t>(e % params_.ring_dim);
            chunks[chunk_idx][slot_idx] = 1;
        }

        return chunks;
    }

    /// Encrypt each chunk into a ciphertext.
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>
    EncryptChunks(const std::vector<std::vector<int64_t>>& chunks) const {
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> cts;
        cts.reserve(chunks.size());
        for (const auto& chunk : chunks) {
            cts.push_back(bfv_ctx_->Encrypt(chunk));
        }
        return cts;
    }

    /// Pairwise multiply + rotate-and-sum + aggregate across chunks.
    /// Result slot[0] = |X intersect Y| (exact integer).
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    ComputeInnerProduct(
        const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ct_x,
        const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& ct_y) const
    {
        assert(ct_x.size() == ct_y.size());
        assert(!ct_x.empty());

        // Process first chunk
        auto product = bfv_ctx_->Multiply(ct_x[0], ct_y[0]);
        auto total = RotateAndSum(product);

        // Process remaining chunks (if any)
        for (size_t i = 1; i < ct_x.size(); i++) {
            auto prod_i = bfv_ctx_->Multiply(ct_x[i], ct_y[i]);
            auto partial_i = RotateAndSum(prod_i);
            total = bfv_ctx_->Add(total, partial_i);
        }

        return total;
    }

    /// Decrypt slot[0] -> |X intersect Y|, compute J = intersection / union.
    double ComputeJaccardFromInnerProduct(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
        size_t size_x,
        size_t size_y) const
    {
        auto values = bfv_ctx_->Decrypt(ct);
        int64_t intersection = values[0];
        int64_t union_size =
            static_cast<int64_t>(size_x) +
            static_cast<int64_t>(size_y) -
            intersection;
        if (union_size == 0) return 1.0;
        return static_cast<double>(intersection) / static_cast<double>(union_size);
    }

    /// Convenience: full protocol (encode -> encrypt -> compute -> decrypt).
    double ComputeJaccard(const std::vector<uint64_t>& set_x,
                          const std::vector<uint64_t>& set_y) const {
        auto chunks_x = EncodeBinaryVectors(set_x);
        auto chunks_y = EncodeBinaryVectors(set_y);
        auto ct_x = EncryptChunks(chunks_x);
        auto ct_y = EncryptChunks(chunks_y);
        auto ct_result = ComputeInnerProduct(ct_x, ct_y);
        return ComputeJaccardFromInnerProduct(ct_result, set_x.size(), set_y.size());
    }

    const BaselineParams& GetParams() const { return params_; }
    const BFVContext& GetBFVContext() const { return *bfv_ctx_; }

private:
    /// Rotate-and-sum: accumulate all slots into slot 0 using log2(N) steps.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    RotateAndSum(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
        auto result = ct;
        for (uint32_t step = 1; step < params_.ring_dim; step *= 2) {
            auto rotated = bfv_ctx_->Rotate(result, static_cast<int>(step));
            result = bfv_ctx_->Add(result, rotated);
        }
        return result;
    }

    BaselineParams params_;
    std::unique_ptr<BFVContext> bfv_ctx_;
};

} // namespace baseline
} // namespace piccard
