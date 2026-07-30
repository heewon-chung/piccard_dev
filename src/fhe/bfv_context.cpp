#include "fhe/bfv_context.h"

#include "math/distributiongenerator.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <vector>

namespace piccard {

namespace {

/// A polynomial whose every coefficient is an independent uniform integer on
/// [-2^bits, 2^bits - 1], returned in EVALUATION format so it can be added to
/// a ciphertext component directly.
///
/// `bits` exceeds 128 for every configuration and reaches 605 for the
/// threshold variant at STD128, so the value is never materialised. Each coefficient is
/// drawn as 32-bit words w_0, w_1, ... representing u = sum_j w_j * 2^(32j),
/// and reduced per RNS limb using u mod q = sum_j w_j * (2^(32j) mod q).
/// Subtracting 2^bits mod q centres the result.
lbcrypto::DCRTPoly SampleFloodingNoise(
    const std::shared_ptr<lbcrypto::DCRTPoly::Params>& params, uint32_t bits) {
    auto& prng = lbcrypto::PseudoRandomNumberGenerator::GetPRNG();

    const uint32_t n = params->GetRingDimension();
    const auto& towers = params->GetParams();
    const uint32_t total_bits = bits + 1;              // u is drawn on [0, 2^(bits+1))
    const uint32_t num_words = (total_bits + 31) / 32;
    const uint32_t top_bits = total_bits - 32 * (num_words - 1);

    // Draw every coefficient's words once; the same integer has to be reduced
    // consistently against each limb, so it cannot be re-drawn per limb.
    std::vector<uint32_t> words(static_cast<size_t>(n) * num_words);
    for (size_t i = 0; i < words.size(); i++) {
        words[i] = prng();
    }
    // Trim the most significant word so u stays below 2^(bits+1).
    if (top_bits < 32) {
        const uint32_t mask = (1u << top_bits) - 1u;
        for (uint32_t c = 0; c < n; c++) {
            words[static_cast<size_t>(c) * num_words + (num_words - 1)] &= mask;
        }
    }

    lbcrypto::DCRTPoly noise(params, Format::COEFFICIENT, true);

    for (size_t i = 0; i < towers.size(); i++) {
        const lbcrypto::NativeInteger q = towers[i]->GetModulus();

        // pow[j] = 2^(32j) mod q
        std::vector<lbcrypto::NativeInteger> pow(num_words);
        pow[0] = lbcrypto::NativeInteger(1).Mod(q);
        lbcrypto::NativeInteger step = lbcrypto::NativeInteger(1).Mod(q);
        for (uint32_t s = 0; s < 32; s++) step = step.ModAdd(step, q);   // 2^32 mod q
        for (uint32_t j = 1; j < num_words; j++) pow[j] = pow[j - 1].ModMul(step, q);

        // centre = 2^bits mod q
        lbcrypto::NativeInteger centre = lbcrypto::NativeInteger(1).Mod(q);
        for (uint32_t s = 0; s < bits; s++) centre = centre.ModAdd(centre, q);

        lbcrypto::NativePoly limb(towers[i], Format::COEFFICIENT, true);
        for (uint32_t c = 0; c < n; c++) {
            lbcrypto::NativeInteger acc(0);
            const uint32_t* w = &words[static_cast<size_t>(c) * num_words];
            for (uint32_t j = 0; j < num_words; j++) {
                acc = acc.ModAdd(lbcrypto::NativeInteger(w[j]).ModMul(pow[j], q), q);
            }
            limb[c] = acc.ModSub(centre, q);
        }
        noise.SetElementAtIndex(i, limb);
    }

    noise.SetFormat(Format::EVALUATION);
    return noise;
}

} // namespace

BFVContext::BFVContext(const PiccardParams& params)
    : params_(params), runtime_ring_dim_(params.ring_dim) {}

uint32_t BFVContext::RequiredFloodBudgetBits() const {
    // FloodNoiseBits() first revalidates the complete Phase 2 fingerprint.
    const uint32_t selected_flood_bits = params_.FloodNoiseBits();
    const uint64_t required =
        static_cast<uint64_t>(params_.eval_noise_bits) +
        static_cast<uint64_t>(params_.CoefficientStatBits()) +
        static_cast<uint64_t>(params_.flood_margin_bits) + UINT64_C(2);
    if (required > std::numeric_limits<uint32_t>::max() ||
        required != static_cast<uint64_t>(selected_flood_bits) + 2) {
        throw std::logic_error(
            "runtime flooding budget disagrees with the selected sanitizer "
            "profile");
    }
    return static_cast<uint32_t>(required);
}

void BFVContext::Initialize() {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> bfv_params;

    bfv_params.SetPlaintextModulus(params_.plaintext_mod);
    bfv_params.SetMultiplicativeDepth(params_.mult_depth);

    // Ciphertext modulus shaping (R2-W6). Left at OpenFHE's default when 0.
    // Set before every GenCryptoContext call below so the retry path that
    // forces a larger ring dimension keeps the same limb layout.
    if (params_.scaling_mod_size != 0) {
        bfv_params.SetScalingModSize(params_.scaling_mod_size);
    }

    // A sized sanitizer may have selected a measured context larger than the
    // immutable requested N. Unsized baseline copies keep their independent
    // runtime request and never enter the sanitizer-adoption path.
    const uint32_t configured_ring_dim =
        params_.FloodingSized()
            ? params_.SelectedCalibratedRingDim()
            : params_.ring_dim;
    uint32_t needed_ring_dim = NextPowerOf2(params_.feature_dim);
    needed_ring_dim = std::max(needed_ring_dim, configured_ring_dim);

    switch (params_.security) {
        case SecurityLevel::TOY:
            bfv_params.SetSecurityLevel(lbcrypto::HEStd_NotSet);
            bfv_params.SetRingDim(needed_ring_dim);
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

    runtime_ring_dim_ = cc_->GetRingDimension();

    // This is the first point where the measured context actually exists.
    // Adoption verifies requested, selected, and actual N before any keys or
    // size-dependent rotation plans are created.
    if (params_.FloodingSized()) {
        params_.AdoptVerifiedRuntimeRingDim(runtime_ring_dim_);
    }

    if (params_.FloodingSized()) {
        auto elem_params = cc_->GetCryptoParameters()->GetElementParams();
        const double log_q =
            std::log2(elem_params->GetModulus().ConvertToDouble());
        const double log_delta =
            log_q - std::log2(static_cast<double>(params_.plaintext_mod));
        const double required =
            static_cast<double>(RequiredFloodBudgetBits());
        if (required > log_delta) {
            throw std::runtime_error(
                "noise flooding does not fit: needs " +
                std::to_string(static_cast<int>(required)) +
                " bits but log2(q/t) is only " +
                std::to_string(static_cast<int>(log_delta)) +
                ". The calibration table and this crypto context disagree; "
                "re-run `bench_noise --sweep` and regenerate "
                "include/util/noise_calibration.inc.");
        }
    }

    cc_->Enable(lbcrypto::PKE);
    cc_->Enable(lbcrypto::KEYSWITCH);
    cc_->Enable(lbcrypto::LEVELEDSHE);

    key_pair_ = cc_->KeyGen();
    cc_->EvalMultKeyGen(key_pair_.secretKey);

    // Generate rotation keys for powers of 2 (for rotate-and-sum)
    std::vector<int> rotation_indices;
    for (uint32_t i = 1; i < runtime_ring_dim_; i *= 2) {
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
    pt->SetLength(runtime_ring_dim_);
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
    std::vector<int64_t> plain(runtime_ring_dim_, scalar);
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
        std::vector<int64_t> c(runtime_ring_dim_, coeffs[0]);
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
            std::vector<int64_t> c(runtime_ring_dim_, coeffs[const_idx]);
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

lbcrypto::Ciphertext<lbcrypto::DCRTPoly>
BFVContext::Flood(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ct) const {
    // Throws unless Validate() sized the flooding term against the calibration
    // table, which is what keeps an unsized parameter set from producing a mask
    // smaller than the evaluation noise it is supposed to hide.
    const uint32_t bits = params_.FloodNoiseBits();

    // Re-randomize computationally with a fresh Enc(0). Its ordinary-width
    // noise is negligible beside the independently sampled phase mask below.
    std::vector<int64_t> zeros(runtime_ring_dim_, 0);
    auto out = cc_->EvalAdd(ct, Encrypt(zeros));

    auto elem_params = cc_->GetCryptoParameters()->GetElementParams();

    // Decryption evaluates c0 + c1*s, so a term added to c0 lands in the
    // decryption noise additively; adding to c1 would be scaled by the key.
    out->GetElements()[0] += SampleFloodingNoise(elem_params, bits);
    return out;
}

} // namespace piccard
