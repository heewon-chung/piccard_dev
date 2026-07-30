#include "core/minhash.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

#ifdef _OPENMP
#include <omp.h>
#endif

namespace piccard {

namespace {

constexpr std::array<unsigned char, 22> kDomain = {
    'p', 'i', 'c', 'c', 'a', 'r', 'd', '-', 'm', 'i', 'n',
    'h', 'a', 's', 'h', '-', 'p', 'o', 'c', '-', 'v', '1',
};

void StoreUint64Be(uint64_t value, unsigned char* output) {
    for (int byte = 7; byte >= 0; --byte) {
        output[7 - byte] =
            static_cast<unsigned char>(value >> (static_cast<unsigned>(byte) * 8));
    }
}

void StoreUint32Be(uint32_t value, unsigned char* output) {
    for (int byte = 3; byte >= 0; --byte) {
        output[3 - byte] =
            static_cast<unsigned char>(value >> (static_cast<unsigned>(byte) * 8));
    }
}

} // namespace

MinHasher::MinHasher(uint32_t k, uint64_t hash_range, uint64_t seed)
    : k_(k), hash_range_(hash_range), seed_(seed) {
    if (k == 0) throw std::invalid_argument("k must be > 0");
    if (hash_range == 0) {
        throw std::invalid_argument("hash_range must be > 0");
    }
}

uint64_t MinHasher::HashRank(uint32_t coordinate, uint64_t elem) const {
    std::array<unsigned char, kDomain.size() + 8 + 4 + 8> input{};
    std::copy(kDomain.begin(), kDomain.end(), input.begin());
    StoreUint64Be(seed_, input.data() + kDomain.size());
    StoreUint32Be(coordinate, input.data() + kDomain.size() + 8);
    StoreUint64Be(elem, input.data() + kDomain.size() + 8 + 4);

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_size = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to allocate SHA-256 context");
    }

    const bool success =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
        EVP_DigestFinal_ex(context, digest.data(), &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!success || digest_size != 32) {
        throw std::runtime_error("SHA-256 rank computation failed");
    }

    uint64_t rank = 0;
    for (size_t i = 0; i < 8; ++i) {
        rank = (rank << 8) | digest[i];
    }
    if (hash_range_ != std::numeric_limits<uint64_t>::max()) {
        rank %= hash_range_;
    }
    return rank;
}

std::vector<uint64_t> MinHasher::ComputeSignature(const std::vector<uint64_t>& set) const {
    if (set.empty()) throw std::invalid_argument("Set must not be empty");

    std::vector<uint64_t> signature(k_, std::numeric_limits<uint64_t>::max());

#ifdef _OPENMP
    #pragma omp parallel
    {
        std::vector<uint64_t> local_sig(k_, std::numeric_limits<uint64_t>::max());

        #pragma omp for nowait
        for (size_t e = 0; e < set.size(); e++) {
            for (uint32_t i = 0; i < k_; i++) {
                const uint64_t h = HashRank(i, set[e]);
                local_sig[i] = std::min(local_sig[i], h);
            }
        }

        #pragma omp critical
        {
            for (uint32_t i = 0; i < k_; i++) {
                signature[i] = std::min(signature[i], local_sig[i]);
            }
        }
    }
#else
    for (uint64_t elem : set) {
        for (uint32_t i = 0; i < k_; i++) {
            const uint64_t h = HashRank(i, elem);
            signature[i] = std::min(signature[i], h);
        }
    }
#endif

    return signature;
}

std::vector<uint64_t> MinHasher::ComputeElementHashes(uint64_t elem) const {
    std::vector<uint64_t> hashes(k_);
    for (uint32_t i = 0; i < k_; i++) {
        hashes[i] = HashRank(i, elem);
    }
    return hashes;
}

double MinHasher::EstimateJaccard(const std::vector<uint64_t>& sig_x,
                                  const std::vector<uint64_t>& sig_y) {
    if (sig_x.size() != sig_y.size()) {
        throw std::invalid_argument("Signatures must have the same length");
    }
    if (sig_x.empty()) throw std::invalid_argument("Signatures must not be empty");

    uint32_t matches = 0;
    for (size_t i = 0; i < sig_x.size(); i++) {
        if (sig_x[i] == sig_y[i]) matches++;
    }
    return static_cast<double>(matches) / static_cast<double>(sig_x.size());
}

} // namespace piccard
