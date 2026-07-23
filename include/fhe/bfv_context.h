#pragma once

#include "util/params.h"
#include "openfhe.h"

#include <cstdint>
#include <vector>

namespace piccard {

class BFVContext {
public:
    explicit BFVContext(const PiccardParams& params);

    void Initialize();

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Encrypt(const std::vector<int64_t>& values) const;

    std::vector<int64_t>
    Decrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Multiply(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_a,
             const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_b) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Add(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_a,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct_b) const;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Rotate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct, int steps) const;

    // Multiply ciphertext by a plaintext vector (does not consume mult depth)
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    MultiplyPlain(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                  const std::vector<int64_t>& plain) const;

    // Multiply ciphertext by a scalar plaintext
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    MultiplyScalar(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                   int64_t scalar) const;

    // Add a plaintext vector to a ciphertext
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    AddPlain(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
             const std::vector<int64_t>& plain) const;

    // Evaluate polynomial on ciphertext using baby-step/giant-step
    // (Paterson-Stockmeyer). coeffs[i] is the coefficient of x^i in Z_p.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    EvalPolyBFV(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct,
                const std::vector<int64_t>& coeffs) const;

    uint32_t GetSlotCount() const { return params_.ring_dim; }

    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& GetCryptoContext() const {
        return cc_;
    }

private:
    PiccardParams params_;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc_;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key_pair_;
};

} // namespace piccard
