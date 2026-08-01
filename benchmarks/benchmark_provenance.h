#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace piccard {

class BFVContext;

namespace benchmark {

/** @brief Live cryptographic and build provenance for one benchmark row. */
struct BenchmarkProvenance {
    std::optional<uint32_t> actual_ring_dim;
    std::optional<double> log_q_bits;
    std::optional<uint64_t> plaintext_modulus;
    std::optional<uint32_t> num_limbs;
    std::string openfhe_version;

    bool sanitizer_applicable = false;
    std::optional<uint32_t> transcript_stat_bits;
    std::optional<uint64_t> max_queries;
    std::optional<uint32_t> query_stat_bits;
    std::optional<uint32_t> coefficient_stat_bits;
    std::optional<uint32_t> flood_margin_bits;
    std::optional<uint32_t> eval_noise_bits;
    std::optional<uint32_t> flood_noise_bits;
    std::optional<uint32_t> scaling_mod_size;
};

/** @brief Build complete Piccard provenance from its realized BFV context. */
BenchmarkProvenance MakePiccardBenchmarkProvenance(
    const BFVContext& context);

/** @brief Build FHE-IND provenance: live BFV fields, no Piccard sanitizer. */
BenchmarkProvenance MakeFheIndBenchmarkProvenance(
    const BFVContext& context);

/** @brief Build AHE provenance with exact not-applicable representation. */
BenchmarkProvenance MakeAheBenchmarkProvenance();

/** @brief Validate that provenance is exactly live-FHE or not-applicable. */
bool ValidateBenchmarkProvenance(const BenchmarkProvenance& provenance);

}  // namespace benchmark
}  // namespace piccard
