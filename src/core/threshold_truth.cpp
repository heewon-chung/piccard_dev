#include "core/threshold_truth.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace piccard {
namespace {

constexpr char kSeedDomain[] = "piccard-threshold-fpfn-seed-v1";

void StoreUint64Be(uint64_t value, unsigned char* output) {
    for (int byte = 7; byte >= 0; --byte) {
        output[7 - byte] = static_cast<unsigned char>(
            value >> (static_cast<unsigned>(byte) * 8));
    }
}

void StoreUint32Be(uint32_t value, unsigned char* output) {
    for (int byte = 3; byte >= 0; --byte) {
        output[3 - byte] = static_cast<unsigned char>(
            value >> (static_cast<unsigned>(byte) * 8));
    }
}

uint64_t LoadUint64Be(const unsigned char* input) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | input[i];
    }
    return value;
}

}  // namespace

bool IsSyntheticThresholdK(uint32_t k) noexcept {
    return std::find(kSyntheticThresholdK.begin(), kSyntheticThresholdK.end(), k) !=
           kSyntheticThresholdK.end();
}

uint32_t SyntheticThresholdTauCount(uint32_t k) {
    switch (k) {
        case 64u: return 38u;
        case 128u: return 76u;
        case 256u: return 153u;
        case 512u: return 307u;
        default:
            throw std::invalid_argument(
                "synthetic threshold k must be one of 64, 128, 256, 512");
    }
}

bool IsSyntheticThresholdGridIndex(int32_t grid_index) noexcept {
    return grid_index >= kSyntheticThresholdGridMin &&
           grid_index <= kSyntheticThresholdGridMax;
}

std::vector<int32_t> SyntheticThresholdGridIndices() {
    std::vector<int32_t> result;
    result.reserve(static_cast<size_t>(kSyntheticThresholdGridMax -
                                       kSyntheticThresholdGridMin + 1));
    for (int32_t index = kSyntheticThresholdGridMin;
         index <= kSyntheticThresholdGridMax; ++index) {
        result.push_back(index);
    }
    return result;
}

SyntheticThresholdPoint MakeSyntheticThresholdPoint(uint32_t k,
                                                    int32_t grid_index) {
    if (!IsSyntheticThresholdK(k)) {
        throw std::invalid_argument(
            "synthetic threshold k must be one of 64, 128, 256, 512");
    }
    if (!IsSyntheticThresholdGridIndex(grid_index)) {
        throw std::invalid_argument(
            "synthetic threshold grid index must be in [-10,10]");
    }

    SyntheticThresholdPoint point;
    point.k = k;
    point.tau_count = SyntheticThresholdTauCount(k);
    point.grid_index = grid_index;
    point.j_tau = JaccardThreshold(point.tau_count, k,
                                   kSyntheticThresholdM);
    point.target_j = std::clamp(
        point.j_tau + 0.01 * static_cast<double>(grid_index), 0.0, 1.0);
    point.signed_delta = point.target_j - point.j_tau;
    point.absolute_delta = std::abs(point.signed_delta);
    point.alpha = 2.0 * point.target_j / (1.0 + point.target_j);

    const auto intersection = static_cast<uint32_t>(
        std::floor(static_cast<double>(kSyntheticThresholdSetSize) *
                   point.alpha));
    point.realized_intersection = intersection;
    point.realized_union = 2u * kSyntheticThresholdSetSize - intersection;
    point.realized_j = static_cast<double>(point.realized_intersection) /
                       static_cast<double>(point.realized_union);
    return point;
}

uint64_t SyntheticThresholdRowSeed(uint64_t root_seed,
                                   uint32_t k,
                                   int32_t grid_index,
                                   uint64_t trial_index) {
    if (!IsSyntheticThresholdK(k)) {
        throw std::invalid_argument(
            "synthetic threshold k must be one of 64, 128, 256, 512");
    }
    if (!IsSyntheticThresholdGridIndex(grid_index)) {
        throw std::invalid_argument(
            "synthetic threshold grid index must be in [-10,10]");
    }

    constexpr size_t kDomainSize = sizeof(kSeedDomain) - 1;
    std::array<unsigned char, kDomainSize + 1 + 8 + 4 + 4 + 8> input{};
    std::memcpy(input.data(), kSeedDomain, kDomainSize);
    input[kDomainSize] = 0;
    StoreUint64Be(root_seed, input.data() + kDomainSize + 1);
    StoreUint32Be(k, input.data() + kDomainSize + 1 + 8);
    StoreUint32Be(static_cast<uint32_t>(grid_index + 10),
                  input.data() + kDomainSize + 1 + 8 + 4);
    StoreUint64Be(trial_index,
                  input.data() + kDomainSize + 1 + 8 + 4 + 4);

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("failed to allocate SHA-256 context");
    }
    const bool success =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
        EVP_DigestFinal_ex(context, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!success || digest_size != 32u) {
        throw std::runtime_error("SHA-256 row-seed computation failed");
    }
    return LoadUint64Be(digest.data());
}

double SyntheticThresholdBinomialDecisionProbability(uint32_t k,
                                                     uint32_t tau_count,
                                                     double p) {
    if (k == 0 || tau_count > k || !std::isfinite(p) || p < 0.0 || p > 1.0) {
        throw std::invalid_argument("invalid binomial threshold arguments");
    }
    if (p == 0.0) return tau_count == 0u ? 1.0 : 0.0;
    if (p == 1.0) return 1.0;

    // Start at x=0, then walk upward so the sum has the exact order frozen by
    // the readiness contract.  All synthetic p values are comfortably away
    // from the singular endpoints, but the endpoint branches above keep this
    // helper total and deterministic for KATs.
    const double one_minus_p = 1.0 - p;
    double pmf = std::pow(one_minus_p, static_cast<double>(k));
    double survival = 0.0;
    for (uint32_t x = 0; x <= k; ++x) {
        if (x >= tau_count) survival += pmf;
        if (x == k) break;
        pmf *= (static_cast<double>(k - x) /
                static_cast<double>(x + 1u)) * (p / one_minus_p);
    }
    return std::clamp(survival, 0.0, 1.0);
}

double SyntheticThresholdGaussianErrorApprox(double realized_j,
                                             uint32_t k,
                                             uint32_t m) {
    if (k == 0 || m <= 1 || !std::isfinite(realized_j) || realized_j < 0.0 ||
        realized_j > 1.0) {
        throw std::invalid_argument("invalid Gaussian threshold arguments");
    }
    const double p_j = realized_j + (1.0 - realized_j) /
                                    static_cast<double>(m);
    const double p_tau = static_cast<double>(SyntheticThresholdTauCount(k)) /
                         static_cast<double>(k);
    const double denominator = std::sqrt(p_tau * (1.0 - p_tau));
    const double z = std::sqrt(static_cast<double>(k)) *
                     std::abs(p_j - p_tau) / denominator;
    return 0.5 * std::erfc(z / std::sqrt(2.0));
}

int SyntheticThresholdDecision(int64_t match_count,
                               uint32_t tau_count) noexcept {
    return match_count >= static_cast<int64_t>(tau_count) ? 1 : 0;
}

const char* SyntheticThresholdOutcome(int exact_j_truth,
                                      int decision) noexcept {
    if (exact_j_truth == 1) return decision == 1 ? "TP" : "FN";
    return decision == 1 ? "FP" : "TN";
}

}  // namespace piccard
