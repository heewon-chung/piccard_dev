#include "baseline_engine.h"

#include "benchmark_provenance.h"
#include "benchmark_utils.h"

// OpenFHE serialization registration is required by CiphertextSizer.  Keep
// this in the reusable measurement implementation so adapters share one size
// accounting path rather than each reimplementing serialization.
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

#include <chrono>
#include <stdexcept>

namespace piccard {
namespace baseline {
namespace {

using Clock = std::chrono::steady_clock;

double ElapsedMilliseconds(const Clock::time_point& start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start)
        .count();
}

template <typename CiphertextVector>
size_t SerializedBytes(const CiphertextVector& ciphertexts) {
    size_t total = 0;
    for (const auto& ciphertext : ciphertexts) {
        total += benchmark::CiphertextSizer::GetSerializedSize(ciphertext);
    }
    return total;
}

}  // namespace

void BaselineEngine::InitializeContextOnly() {
    if (params_.RequestedFeatureDim() == 0) {
        throw std::logic_error(
            "FHE-IND setup requires BaselineParams::Validate() first");
    }
    if (bfv_ctx_ != nullptr) {
        throw std::logic_error("FHE-IND context was already initialized");
    }

    const auto start = Clock::now();
    auto context = std::make_unique<BFVContext>(MakeBFVParams(params_));
    context->InitializeContextOnly();

    // Runtime adoption is intentionally independent of the Piccard sanitizer
    // and fingerprint path.  Perform it before key generation so the BFV
    // context creates exactly the rotation-key set required by the realized N.
    params_.AdoptRuntimeRingDim(context->GetSlotCount());
    bfv_ctx_ = std::move(context);
    setup_timings_.context_ms = ElapsedMilliseconds(start);
    setup_timings_.total_ms = setup_timings_.context_ms;
}

void BaselineEngine::InitializeKeys() {
    if (bfv_ctx_ == nullptr) {
        throw std::logic_error(
            "FHE-IND key generation requires an initialized context");
    }
    if (bfv_ctx_->HasGeneratedKeysForTesting()) {
        throw std::logic_error("FHE-IND keys were already generated");
    }

    const auto start = Clock::now();
    bfv_ctx_->InitializeKeys();
    setup_timings_.keygen_ms = ElapsedMilliseconds(start);
    setup_timings_.total_ms =
        setup_timings_.context_ms + setup_timings_.keygen_ms;
}

void BaselineEngine::Initialize() {
    InitializeContextOnly();
    InitializeKeys();
}

FheIndQueryResult BaselineEngine::RunQueryPhased(
    const std::vector<uint64_t>& set_x,
    const std::vector<uint64_t>& set_y) const {
    if (bfv_ctx_ == nullptr) {
        throw std::logic_error(
            "FHE-IND query requires an initialized context and keys");
    }
    if (!bfv_ctx_->HasGeneratedKeysForTesting()) {
        throw std::logic_error(
            "FHE-IND query requires generated encryption and evaluation keys");
    }

    FheIndQueryResult result;
    result.universe_size = params_.universe_size;
    result.ring_dim = params_.ring_dim;
    result.num_ciphertexts = params_.num_ciphertexts;
    result.setup_context_ms = setup_timings_.context_ms;
    result.setup_keygen_ms = setup_timings_.keygen_ms;
    result.setup_ms = setup_timings_.total_ms;

    // Online phase 1: build both full-universe indicator-vector chunk lists.
    auto start = Clock::now();
    auto chunks_x = EncodeBinaryVectors(set_x);
    auto chunks_y = EncodeBinaryVectors(set_y);
    result.phase_encode_ms = ElapsedMilliseconds(start);

    // Online phase 2: encrypt every chunk for both parties.
    start = Clock::now();
    auto ct_x = EncryptChunks(chunks_x);
    auto ct_y = EncryptChunks(chunks_y);
    result.phase_encrypt_ms = ElapsedMilliseconds(start);

    // Online phase 3: multiply matching chunks, rotate-and-sum each chunk,
    // then aggregate across chunks.
    start = Clock::now();
    auto ct_result = ComputeInnerProduct(ct_x, ct_y);
    result.phase_evaluate_ms = ElapsedMilliseconds(start);

    // Online phase 4: decrypt slot 0 and derive plaintext Jaccard from the
    // public set sizes.  No flooding or secure-division operation is applied.
    start = Clock::now();
    result.intersection = DecryptIntersection(ct_result);
    result.union_size = static_cast<int64_t>(set_x.size()) +
                        static_cast<int64_t>(set_y.size()) -
                        result.intersection;
    result.jaccard = result.union_size == 0
        ? 1.0
        : static_cast<double>(result.intersection) /
              static_cast<double>(result.union_size);
    result.phase_decrypt_ms = ElapsedMilliseconds(start);

    result.phases.encode_ms = result.phase_encode_ms;
    result.phases.encrypt_ms = result.phase_encrypt_ms;
    result.phases.evaluate_ms = result.phase_evaluate_ms;
    result.phases.decrypt_ms = result.phase_decrypt_ms;
    result.phases.online_ms = result.phase_encode_ms +
                              result.phase_encrypt_ms +
                              result.phase_evaluate_ms +
                              result.phase_decrypt_ms;
    result.online_ms = result.phases.online_ms;
    result.total_ms = result.online_ms;
    result.phase_compute_ms = result.phase_evaluate_ms;

    // Ciphertext and communication accounting is deliberately outside the
    // online timers.  It reuses the repository's canonical serialized-size
    // helper and counts both uploads plus the returned result ciphertext.
    if (ct_x.empty() || ct_y.empty()) {
        throw std::logic_error(
            "FHE-IND query produced no ciphertext chunks");
    }
    result.per_ciphertext_bytes =
        benchmark::CiphertextSizer::GetSerializedSize(ct_x.front());
    result.party_x_ciphertext_bytes = SerializedBytes(ct_x);
    result.party_y_ciphertext_bytes = SerializedBytes(ct_y);
    result.result_ciphertext_bytes =
        benchmark::CiphertextSizer::GetSerializedSize(ct_result);
    result.communication.upload_bytes =
        result.party_x_ciphertext_bytes + result.party_y_ciphertext_bytes;
    result.communication.download_bytes = result.result_ciphertext_bytes;
    result.communication.total_bytes = result.communication.upload_bytes +
                                      result.communication.download_bytes;
    result.communication.per_ciphertext_bytes = result.per_ciphertext_bytes;
    result.communication.party_x_ciphertext_bytes =
        result.party_x_ciphertext_bytes;
    result.communication.party_y_ciphertext_bytes =
        result.party_y_ciphertext_bytes;
    result.communication.result_ciphertext_bytes =
        result.result_ciphertext_bytes;

    result.ciphertext_bytes = result.party_x_ciphertext_bytes;
    result.ct_size_bytes = result.ciphertext_bytes;
    result.communication_bytes = result.communication.total_bytes;
    result.comm_bytes = result.communication_bytes;

    // Provenance is generated by the existing FHE-IND helper.  It carries the
    // live BFV tuple while leaving Piccard sanitizer fields inapplicable.
    result.runtime_metadata = bfv_ctx_->GetRuntimeMetadata();
    result.provenance =
        benchmark::MakeFheIndBenchmarkProvenance(*bfv_ctx_);

    result.intersection_count = result.intersection;
    result.jaccard_estimate = result.jaccard;
    return result;
}

}  // namespace baseline
}  // namespace piccard
