#pragma once

/**
 * @file baseline_engine.h
 * @brief FHE-IND comparator: binary vector encoding + BFV inner product
 *
 * Implements pairwise Jaccard computation using full-dimension binary vectors
 * encrypted with BFV. This is a local, universe-sized BFV indicator comparator
 * implemented in C++ using the same OpenFHE library as Piccard. It is reported
 * only as a diagnostic primitive, not as a reviewed deployment protocol.
 *
 * Key difference from Piccard: encodes sets as binary vectors of dimension
 * U_set (universe size), whereas Piccard compresses to dimension k*m via
 * MinHash + one-hot encoding. When U_set >> k*m, the comparator requires
 * larger ring_dim, making all BFV operations more expensive.
 */

#include "util/params.h"
#include "fhe/bfv_context.h"
#include "benchmark_provenance.h"

#include <cassert>
#include <cstddef>
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
// Phased FHE-IND query contract
// ============================================================================

/**
 * @brief Setup timing kept separate from the online query timing.
 *
 * Context construction and key generation are one-time setup.  They are
 * intentionally not part of FheIndQueryResult::online_ms or any of its four
 * query phases.
 */
struct BaselineSetupTimings {
    double context_ms = 0.0;
    double keygen_ms = 0.0;
    double total_ms = 0.0;
};

/** @brief The four online phases of one FHE-IND query. */
struct FheIndPhaseTimings {
    double encode_ms = 0.0;
    double encrypt_ms = 0.0;
    double evaluate_ms = 0.0;
    double decrypt_ms = 0.0;
    double online_ms = 0.0;

    double TotalOnlineMs() const {
        return encode_ms + encrypt_ms + evaluate_ms + decrypt_ms;
    }
};

/**
 * @brief Serialized ciphertext and query communication accounting.
 *
 * The communication convention is two party uploads plus one result
 * ciphertext download.  Setup material and keys are not represented here.
 */
struct FheIndCommunicationMetadata {
    size_t per_ciphertext_bytes = 0;
    size_t party_x_ciphertext_bytes = 0;
    size_t party_y_ciphertext_bytes = 0;
    size_t result_ciphertext_bytes = 0;
    size_t upload_bytes = 0;
    size_t download_bytes = 0;
    size_t total_bytes = 0;
};

/**
 * @brief Reusable, one-query FHE-IND measurement result.
 *
 * This is deliberately a primitive-level contract.  It reports the exact
 * decrypted intersection and plaintext Jaccard derived from public set sizes;
 * it does not flood the result, perform secure division, or make a protocol
 * security-equivalence claim.  The direct fields mirror the benchmark row
 * vocabulary used by existing adapters.  `phases` and `communication` expose
 * the same values as grouped views for new callers.
 */
struct FheIndQueryResult {
    uint32_t universe_size = 0;
    uint32_t ring_dim = 0;
    uint32_t num_ciphertexts = 0;

    int64_t intersection = 0;
    int64_t union_size = 0;
    double jaccard = 0.0;

    FheIndPhaseTimings phases;
    FheIndCommunicationMetadata communication;

    // Online phase fields, in milliseconds.  setup_* are copied from the
    // engine's one-time setup record and are never added to online_ms.
    double phase_encode_ms = 0.0;
    double phase_encrypt_ms = 0.0;
    double phase_evaluate_ms = 0.0;
    double phase_decrypt_ms = 0.0;
    double online_ms = 0.0;
    double setup_context_ms = 0.0;
    double setup_keygen_ms = 0.0;
    double setup_ms = 0.0;

    // Compatibility spellings for existing benchmark row consumers.
    double phase_compute_ms = 0.0;
    double total_ms = 0.0;

    // Ciphertext/communication fields.  ciphertext_bytes and ct_size_bytes
    // are the bytes uploaded by party X; party-specific fields retain the
    // exact totals when serialized ciphertext lengths differ.
    size_t per_ciphertext_bytes = 0;
    size_t party_x_ciphertext_bytes = 0;
    size_t party_y_ciphertext_bytes = 0;
    size_t result_ciphertext_bytes = 0;
    size_t ciphertext_bytes = 0;
    size_t communication_bytes = 0;
    size_t ct_size_bytes = 0;
    size_t comm_bytes = 0;

    // Existing provenance validation is reused verbatim.  In particular,
    // MakeFheIndBenchmarkProvenance leaves Piccard sanitizer fields N/A.
    benchmark::BenchmarkProvenance provenance;
    BFVRuntimeMetadata runtime_metadata;

    // Names commonly used by measurement serializers/adapters.
    int64_t intersection_count = 0;
    double jaccard_estimate = 0.0;
};

// ============================================================================
// BaselineEngine - Binary vector + BFV inner product
// ============================================================================

class BaselineEngine {
public:
    explicit BaselineEngine(const BaselineParams& params)
        : params_(params) {}

    /**
     * @brief Construct the BFV context without generating keys.
     *
     * This is useful to callers that need a context-only preflight.  Runtime
     * ring adoption happens before key generation so rotation keys are sized
     * from the realized context.
     */
    void InitializeContextOnly();

    /** @brief Generate the encryption/evaluation/rotation keys for the context. */
    void InitializeKeys();

    /** @brief One-time setup: InitializeContextOnly followed by InitializeKeys. */
    void Initialize();

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
        const int64_t intersection = DecryptIntersection(ct);
        int64_t union_size =
            static_cast<int64_t>(size_x) +
            static_cast<int64_t>(size_y) -
            intersection;
        if (union_size == 0) return 1.0;
        return static_cast<double>(intersection) / static_cast<double>(union_size);
    }

    /** @brief Decrypt only slot 0 of an evaluated inner-product ciphertext. */
    int64_t DecryptIntersection(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
        auto values = bfv_ctx_->Decrypt(ct);
        if (values.empty()) {
            throw std::runtime_error(
                "FHE-IND decryption returned no packed slots");
        }
        return values[0];
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

    /**
     * @brief Execute one FHE-IND query with explicit online phase timing.
     *
     * The engine must have completed Initialize() first.  Context/key setup
     * is never performed here and is never included in the returned online
     * timing.  The evaluate phase consists of ciphertext multiplication,
     * rotate-and-sum, and cross-chunk aggregation via ComputeInnerProduct.
     */
    FheIndQueryResult RunQueryPhased(
        const std::vector<uint64_t>& set_x,
        const std::vector<uint64_t>& set_y) const;

    /** @brief Alias retained for callers that prefer verb-first naming. */
    FheIndQueryResult RunPhasedQuery(
        const std::vector<uint64_t>& set_x,
        const std::vector<uint64_t>& set_y) const {
        return RunQueryPhased(set_x, set_y);
    }

    const BaselineParams& GetParams() const { return params_; }
    const BFVContext& GetBFVContext() const { return *bfv_ctx_; }
    const BaselineSetupTimings& GetSetupTimings() const {
        return setup_timings_;
    }

    /** @brief Alias for setup-time consumers using the singular spelling. */
    const BaselineSetupTimings& GetSetupTiming() const {
        return GetSetupTimings();
    }

    bool IsContextInitialized() const { return bfv_ctx_ != nullptr; }
    bool HasGeneratedKeys() const {
        return bfv_ctx_ != nullptr && bfv_ctx_->HasGeneratedKeysForTesting();
    }

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
    BaselineSetupTimings setup_timings_;
};

} // namespace baseline
} // namespace piccard
