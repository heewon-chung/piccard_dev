#include "noise_calibration_probe.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace piccard {
namespace std_evidence {
namespace calibration {
namespace {

uint32_t CeilLog2(uint64_t value) {
    if (value == 0) {
        throw std::invalid_argument("log2 input must be positive");
    }
    uint32_t bits = 0;
    uint64_t threshold = 1;
    while (threshold < value) {
        if (threshold > (std::numeric_limits<uint64_t>::max() >> 1)) {
            return 64;
        }
        threshold <<= 1;
        ++bits;
    }
    return bits;
}

uint32_t CheckedAdd(uint32_t lhs, uint32_t rhs, const char* label) {
    if (rhs > std::numeric_limits<uint32_t>::max() - lhs) {
        throw std::overflow_error(std::string(label) + " overflows uint32");
    }
    return lhs + rhs;
}

}  // namespace

const char* PatternName(Pattern pattern) {
    switch (pattern) {
        case Pattern::AllMatch:
            return "all_match";
        case Pattern::NoMatch:
            return "no_match";
        case Pattern::Random:
            return "random";
    }
    throw std::invalid_argument("unknown calibration pattern");
}

uint64_t DerivePatternSeed(uint64_t root_seed,
                           const std::string& circuit,
                           uint32_t realized_ring_dim,
                           uint32_t provisioned_depth,
                           uint32_t scaling_mod_size,
                           Pattern pattern) {
    uint64_t value = root_seed;
    for (const char ch : circuit) {
        value = value * UINT64_C(0x100000001B3) +
                static_cast<unsigned char>(ch);
    }
    value ^= UINT64_C(0x9E3779B97F4A7C15) * realized_ring_dim;
    value ^= UINT64_C(0xD1B54A32D192ED03) * provisioned_depth;
    value ^= UINT64_C(0xA5A5A5A5A5A5A5A5) * scaling_mod_size;
    value ^= UINT64_C(0xBF58476D1CE4E5B9) *
             (static_cast<uint64_t>(pattern) + 1);
    value ^= value >> 30;
    value *= UINT64_C(0xBF58476D1CE4E5B9);
    value ^= value >> 27;
    value *= UINT64_C(0x94D049BB133111EB);
    value ^= value >> 31;
    return value;
}

std::pair<std::vector<uint64_t>, std::vector<uint64_t>> MakeSignatures(
    Pattern pattern,
    uint32_t k,
    uint32_t m,
    std::mt19937_64& rng) {
    if (k == 0 || m < 2) {
        throw std::invalid_argument("calibration signatures require k>0,m>=2");
    }
    std::vector<uint64_t> lhs(k);
    std::vector<uint64_t> rhs(k);
    std::uniform_int_distribution<uint64_t> distribution(0, m - 1);
    for (uint32_t i = 0; i < k; ++i) {
        switch (pattern) {
            case Pattern::AllMatch:
                lhs[i] = distribution(rng);
                rhs[i] = lhs[i];
                break;
            case Pattern::NoMatch:
                lhs[i] = distribution(rng);
                rhs[i] = (lhs[i] + 1) % m;
                break;
            case Pattern::Random:
                lhs[i] = distribution(rng);
                rhs[i] = distribution(rng);
                break;
        }
    }
    return {std::move(lhs), std::move(rhs)};
}

int64_t ExpectedMatches(const std::vector<uint64_t>& lhs,
                        const std::vector<uint64_t>& rhs,
                        uint32_t m) {
    if (m == 0 || lhs.size() != rhs.size()) {
        throw std::invalid_argument("signature dimensions do not match");
    }
    int64_t matches = 0;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (lhs[i] % m == rhs[i] % m) {
            ++matches;
        }
    }
    return matches;
}

double MeasureDecryptionPhaseNoise(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& secret_key,
    const lbcrypto::BigInteger& modulus_q,
    uint64_t plaintext_modulus) {
    if (!secret_key || plaintext_modulus == 0 || modulus_q == 0) {
        throw std::invalid_argument("noise measurement inputs are incomplete");
    }
    lbcrypto::DCRTPoly secret = secret_key->GetPrivateElement();
    const auto& elements = ciphertext->GetElements();
    if (elements.empty()) {
        throw std::invalid_argument("noise measurement ciphertext is empty");
    }

    lbcrypto::DCRTPoly decryption = elements.front();
    lbcrypto::DCRTPoly secret_power = secret;
    for (size_t index = 1; index < elements.size(); ++index) {
        decryption += elements[index] * secret_power;
        secret_power *= secret;
    }
    decryption.SetFormat(Format::COEFFICIENT);
    const auto interpolated = decryption.CRTInterpolate();
    const lbcrypto::BigInteger delta =
        modulus_q / lbcrypto::BigInteger(plaintext_modulus);
    const lbcrypto::BigInteger q_half = modulus_q >> 1;
    const lbcrypto::BigInteger delta_half = delta >> 1;

    double worst = 0.0;
    for (uint32_t index = 0; index < interpolated.GetLength(); ++index) {
        const lbcrypto::BigInteger value = interpolated[index];
        const lbcrypto::BigInteger absolute =
            value > q_half ? modulus_q - value : value;
        const lbcrypto::BigInteger remainder = absolute % delta;
        const lbcrypto::BigInteger distance =
            remainder > delta_half ? delta - remainder : remainder;
        worst = std::max(worst, distance.ConvertToDouble());
    }
    return worst > 0.0 ? std::log2(worst) : 0.0;
}

ContextDescription DescribeContext(const BFVContext& context) {
    const auto& crypto_context = context.GetCryptoContext();
    if (!crypto_context) {
        throw std::logic_error("context description requires initialized BFV");
    }
    ContextDescription description;
    description.metadata = context.GetRuntimeMetadata();
    description.modulus_q =
        crypto_context->GetCryptoParameters()->GetElementParams()->GetModulus();
    description.log_delta_bits =
        description.metadata.log_q_bits -
        std::log2(static_cast<double>(description.metadata.plaintext_modulus));
    return description;
}

CalibrationBudget ComputeBudget(double worst_eval_noise_bits,
                                uint32_t realized_ring_dim,
                                double log_q_bits,
                                uint64_t plaintext_modulus,
                                uint32_t transcript_stat_bits,
                                uint64_t max_queries,
                                uint32_t flood_margin_bits,
                                double log_delta_bits) {
    if (!std::isfinite(worst_eval_noise_bits) || worst_eval_noise_bits < 0.0 ||
        realized_ring_dim == 0 || !std::isfinite(log_q_bits) ||
        log_q_bits < 0.0 || plaintext_modulus == 0 || transcript_stat_bits == 0 ||
        max_queries == 0) {
        throw std::invalid_argument("invalid diagnostic capacity inputs");
    }
    CalibrationBudget budget;
    budget.eval_noise_bits = static_cast<uint32_t>(std::ceil(worst_eval_noise_bits));
    budget.query_stat_bits =
        CheckedAdd(transcript_stat_bits, CeilLog2(max_queries), "query bits");
    budget.coefficient_stat_bits = CheckedAdd(
        budget.query_stat_bits, CeilLog2(realized_ring_dim), "coefficient bits");
    budget.flood_margin_bits = flood_margin_bits;
    budget.flood_noise_bits =
        CheckedAdd(CheckedAdd(budget.eval_noise_bits,
                              budget.coefficient_stat_bits,
                              "flood noise bits"),
                   flood_margin_bits,
                   "flood noise bits");
    budget.required_capacity_bits =
        CheckedAdd(budget.flood_noise_bits, 2, "required capacity bits");
    budget.log_q_over_t_bits =
        log_q_bits - std::log2(static_cast<double>(plaintext_modulus));
    const double effective_log_delta =
        log_delta_bits == 0.0 ? budget.log_q_over_t_bits : log_delta_bits;
    budget.saturated = effective_log_delta - 1.0 - worst_eval_noise_bits < 0.5;
    budget.fits = !budget.saturated &&
                  static_cast<double>(budget.required_capacity_bits) <=
                      effective_log_delta;
    return budget;
}

}  // namespace calibration
}  // namespace std_evidence
}  // namespace piccard
