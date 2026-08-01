#pragma once

#include "util/params.h"
#include "openfhe.h"

#include <cstdint>
#include <string>
#include <vector>

namespace piccard {

/** @brief Parameters read from the realized OpenFHE BFV context. */
struct BFVRuntimeMetadata {
    uint32_t actual_ring_dim = 0;
    double log_q_bits = 0.0;
    uint64_t plaintext_modulus = 0;
    uint32_t num_limbs = 0;
    std::string openfhe_version;
};

class BFVContext {
public:
    explicit BFVContext(const PiccardParams& params);

    /**
     * @brief Constructs and validates the OpenFHE context without keygen.
     *
     * This calibration-only seam performs no encryption or file I/O.
     */
    void InitializeContextOnly();

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

    // Apply the transcript sanitizer and return the receiver-facing result.
    //
    // sanitizer_model=phase-smudging-enc0-poc-v1
    // sanitizer_assurance=empirical-phase-statistical+ciphertext-computational
    //
    // The independently sampled wide c0 mask empirically smudges the
    // decryption phase under the calibrated transcript profile. Fresh Enc(0)
    // re-randomizes the ciphertext computationally under the encryption
    // assumption. This PoC does not claim full-ciphertext statistical
    // freshness.
    //
    // Apply this ONLY to a ciphertext being handed back to the receiver. The
    // mask is enormous by construction, so any further homomorphic operation
    // on a flooded ciphertext will exhaust the modulus and destroy the result.
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
    Flood(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const;

    /** @brief Returns the actual ring dimension of the realized context. */
    uint32_t GetSlotCount() const { return runtime_ring_dim_; }

    /** @brief Returns live modulus-chain, plaintext, ring, and build metadata. */
    BFVRuntimeMetadata GetRuntimeMetadata() const;

    /** @brief Returns the context's verified private parameter copy. */
    const PiccardParams& GetParams() const { return params_; }

    /**
     * @brief Returns eval + coefficient-stat + margin + two guard bits.
     */
    uint32_t RequiredFloodBudgetBits() const;

    /**
     * @brief Names requested, natural, calibrated, and realized dimensions.
     */
    std::string CalibrationRingDiagnostics() const;

    /**
     * @brief Narrow test seam proving contract failures precede key generation.
     */
    bool HasGeneratedKeysForTesting() const { return key_pair_.good(); }

    /** @brief Returns the fixed sanitizer construction label. */
    static constexpr const char* SanitizerModel() {
        return "phase-smudging-enc0-poc-v1";
    }

    /** @brief Returns the fixed two-part PoC assurance label. */
    static constexpr const char* SanitizerAssurance() {
        return "empirical-phase-statistical+ciphertext-computational";
    }

    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& GetCryptoContext() const {
        return cc_;
    }

    // Calibration and tests only — never call this from protocol code.
    //
    // In the protocol the receiver's secret key never leaves the receiver, and
    // the server performs noise flooding without it. But the flooding bound is
    // derived from the evaluation noise plus the coefficient-adjusted
    // transcript target and empirical margin. Measuring that evaluation noise
    // means computing ||(c0 + c1*s) - Delta*m||_inf, which is impossible
    // without s. The calibration harness therefore needs the key; the
    // resulting bound is baked in as an offline constant so the server never
    // needs it at runtime.
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& GetSecretKeyForCalibration() const {
        return key_pair_.secretKey;
    }

private:
    PiccardParams params_;
    uint32_t runtime_ring_dim_;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc_;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key_pair_;
};

} // namespace piccard
