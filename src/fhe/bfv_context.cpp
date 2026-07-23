#include "fhe/bfv_context.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace piccard {

BFVContext::BFVContext(const PiccardParams& params) : params_(params) {}

void BFVContext::Initialize() {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> bfv_params;

    bfv_params.SetPlaintextModulus(params_.plaintext_mod);
    bfv_params.SetMultiplicativeDepth(params_.mult_depth);

    // The minimum ring_dim our protocol needs (feature_dim slots).
    uint32_t needed_ring_dim = NextPowerOf2(params_.feature_dim);

    switch (params_.security) {
        case SecurityLevel::TOY:
            bfv_params.SetSecurityLevel(lbcrypto::HEStd_NotSet);
            bfv_params.SetRingDim(params_.ring_dim);
            break;
        case SecurityLevel::STD128:
            bfv_params.SetSecurityLevel(lbcrypto::HEStd_128_classic);
            break;
        case SecurityLevel::STD192:
            bfv_params.SetSecurityLevel(lbcrypto::HEStd_192_classic);
            break;
        case SecurityLevel::STD256:
            bfv_params.SetSecurityLevel(lbcrypto::HEStd_256_classic);
            break;
    }

    if (params_.security != SecurityLevel::TOY) {
        // Let OpenFHE choose the minimum ring_dim for the security level
        // and modulus chain, then force a larger value only if the protocol
        // needs more plaintext slots than OpenFHE selected.
        cc_ = lbcrypto::GenCryptoContext(bfv_params);
        uint32_t auto_ring_dim = cc_->GetRingDimension();

        if (auto_ring_dim < needed_ring_dim) {
            // Protocol needs more slots; re-create with explicit ring_dim.
            bfv_params.SetRingDim(needed_ring_dim);
            cc_ = lbcrypto::GenCryptoContext(bfv_params);
        }
    } else {
        cc_ = lbcrypto::GenCryptoContext(bfv_params);
    }

    // Record the ring_dim OpenFHE actually selected.
    params_.ring_dim = cc_->GetRingDimension();

    cc_->Enable(lbcrypto::PKE);
    cc_->Enable(lbcrypto::KEYSWITCH);
    cc_->Enable(lbcrypto::LEVELEDSHE);

    key_pair_ = cc_->KeyGen();
    cc_->EvalMultKeyGen(key_pair_.secretKey);

    // Generate rotation keys for powers of 2 (for rotate-and-sum)
    std::vector<int> rotation_indices;
    for (uint32_t i = 1; i < params_.ring_dim; i *= 2) {
        rotation_indices.push_back(static_cast<int>(i));
    }
    cc_->EvalRotateKeyGen(key_pair_.secretKey, rotation_indices);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::Encrypt(const std::vector<int64_t>& values) const {
    auto pt = cc_->MakePackedPlaintext(values);
    return cc_->Encrypt(key_pair_.publicKey, pt);
}

std::vector<int64_t>
BFVContext::Decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    lbcrypto::Plaintext pt;
    cc_->Decrypt(key_pair_.secretKey, ct, &pt);
    pt->SetLength(params_.ring_dim);
    return pt->GetPackedValue();
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::Multiply(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_a,
                     const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_b) const {
    // OpenFHE EvalMult includes automatic relinearization when
    // EvalMultKeyGen was called (see Initialize())
    return cc_->EvalMult(ct_a, ct_b);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::Add(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_a,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_b) const {
    return cc_->EvalAdd(ct_a, ct_b);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::Rotate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct, int steps) const {
    return cc_->EvalRotate(ct, steps);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::MultiplyPlain(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                          const std::vector<int64_t>& plain) const {
    auto pt = cc_->MakePackedPlaintext(plain);
    return cc_->EvalMult(ct, pt);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::MultiplyScalar(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                           int64_t scalar) const {
    std::vector<int64_t> plain(params_.ring_dim, scalar);
    auto pt = cc_->MakePackedPlaintext(plain);
    return cc_->EvalMult(ct, pt);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::AddPlain(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                     const std::vector<int64_t>& plain) const {
    auto pt = cc_->MakePackedPlaintext(plain);
    return cc_->EvalAdd(ct, pt);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::EvalPolyBFV(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                        const std::vector<int64_t>& coeffs) const {
    // Baby-step/giant-step (Paterson-Stockmeyer) polynomial evaluation.
    // For polynomial c_0 + c_1*x + ... + c_d*x^d:
    //   1. Baby step: compute x, x^2, ..., x^s (s = ceil(sqrt(d+1)))
    //   2. Giant step: group into chunks of s, evaluate via Horner on x^s

    if (coeffs.empty()) {
        throw std::invalid_argument("Polynomial must have at least one coefficient");
    }

    uint32_t degree = static_cast<uint32_t>(coeffs.size()) - 1;

    // Degree 0: just a constant
    if (degree == 0) {
        std::vector<int64_t> c(params_.ring_dim, coeffs[0]);
        return Encrypt(c);
    }

    // Baby step size
    uint32_t s = 1;
    while (s * s < degree + 1) s++;

    // Baby step: compute powers x^1, x^2, ..., x^s
    // powers[j] for j=0 is "identity" (handled separately as plaintext)
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> powers(s + 1);
    powers[1] = ct;
    for (uint32_t j = 2; j <= s; j++) {
        if (j % 2 == 0) {
            powers[j] = Multiply(powers[j / 2], powers[j / 2]);
        } else {
            powers[j] = Multiply(powers[j - 1], powers[1]);
        }
    }

    // Giant step: split polynomial into chunks of size s
    // P(x) = q_0(x) + x^s * q_1(x) + x^(2s) * q_2(x) + ...
    // where q_i(x) = c[i*s] + c[i*s+1]*x + ... + c[i*s+s-1]*x^(s-1)
    uint32_t num_chunks = (degree + s) / s;  // ceil((degree+1) / s)

    // Evaluate each chunk using baby-step powers (plaintext-ct operations only)
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> chunks;
    chunks.reserve(num_chunks);

    for (uint32_t i = 0; i < num_chunks; i++) {
        // Evaluate q_i(x) = sum_{j=0}^{s-1} c[i*s+j] * x^j
        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> chunk;
        bool chunk_initialized = false;

        // Process non-constant terms (j > 0) first
        for (uint32_t j = 1; j < s; j++) {
            uint32_t idx = i * s + j;
            if (idx >= coeffs.size()) break;
            if (coeffs[idx] == 0) continue;

            auto term = MultiplyScalar(powers[j], coeffs[idx]);
            if (!chunk_initialized) {
                chunk = term;
                chunk_initialized = true;
            } else {
                chunk = Add(chunk, term);
            }
        }

        // Add constant term (j=0) as plaintext to preserve ciphertext level
        uint32_t const_idx = i * s;
        if (const_idx < coeffs.size() && coeffs[const_idx] != 0) {
            std::vector<int64_t> c(params_.ring_dim, coeffs[const_idx]);
            if (!chunk_initialized) {
                // Only constant in this chunk: create zero ct at baby-step level
                chunk = MultiplyScalar(powers[1], 0);
                chunk = AddPlain(chunk, c);
                chunk_initialized = true;
            } else {
                chunk = AddPlain(chunk, c);
            }
        }

        if (!chunk_initialized) {
            // All-zero chunk: zero ct at baby-step level
            chunk = MultiplyScalar(powers[1], 0);
        }

        chunks.push_back(chunk);
    }

    // Combine chunks using Horner's method on x^s:
    // result = chunks[n-1]
    // for i = n-2 downto 0: result = result * x^s + chunks[i]
    auto result = chunks[num_chunks - 1];
    for (int i = static_cast<int>(num_chunks) - 2; i >= 0; i--) {
        result = Multiply(result, powers[s]);
        result = Add(result, chunks[i]);
    }

    return result;
}

} // namespace piccard
