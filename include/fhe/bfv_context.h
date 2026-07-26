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

    // Add the masking noise the security proof requires, and return the result.
    //
    // The receiver can otherwise inspect the decryption noise of an evaluated
    // ciphertext and learn more than the output, which is what stops the
    // receiver's view from being simulatable. A uniform mask of magnitude
    // 2^FloodNoiseBits() -- calibrated to exceed any evaluation noise this
    // circuit can produce by 2^lambda_stat -- smudges the decryption phase.
    //
    // What that delivers, stated precisely, because the two halves differ:
    //   * the decryption noise is statistically smudged. Over the N
    //     coefficients the receiver sees, a union bound gives
    //     N * 2^-(lambda_stat + flood_margin_bits) -- roughly 2^-57 at
    //     N = 32768, not 2^-lambda_stat.
    //   * the c1 component is re-randomized by the fresh Enc_pk(0) below,
    //     which hides the circuit *computationally* under Ring-LWE. An
    //     ordinary encryption of zero carries ordinary-width randomness, so
    //     this is not statistical indistinguishability from a fresh
    //     ciphertext; that would need a sanitization construction with wide
    //     randomness in the zero-encryption too. See 3_noise-flooding.md
    //     section 8.
    //
    // Apply this ONLY to a ciphertext being handed back to the receiver. The
    // mask is enormous by construction, so any further homomorphic operation
    // on a flooded ciphertext will exhaust the modulus and destroy the result.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Flood(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    uint32_t GetSlotCount() const { return params_.ring_dim; }

    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& GetCryptoContext() const {
        return cc_;
    }

    // Calibration and tests only — never call this from protocol code.
    //
    // In the protocol the receiver's secret key never leaves the receiver, and
    // the server performs noise flooding without it. But the flooding bound is
    // 2^(lambda_s) times the evaluation noise, and measuring that noise means
    // computing ||(c0 + c1*s) - Delta*m||_inf, which is impossible without s.
    // The calibration harness therefore needs the key; the resulting bound is
    // baked in as an offline constant so the server never needs it at runtime.
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& GetSecretKeyForCalibration() const {
        return key_pair_.secretKey;
    }

private:
    PiccardParams params_;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc_;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key_pair_;
};

} // namespace piccard
