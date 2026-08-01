#include "benchmark_provenance.h"

#include "build_info.h"
#include "fhe/bfv_context.h"

#include <cmath>
#include <stdexcept>

namespace piccard {
namespace benchmark {
namespace {

BenchmarkProvenance MakeLiveFheProvenance(const BFVContext& context) {
    const BFVRuntimeMetadata runtime = context.GetRuntimeMetadata();
    BenchmarkProvenance provenance;
    provenance.actual_ring_dim = runtime.actual_ring_dim;
    provenance.log_q_bits = runtime.log_q_bits;
    provenance.plaintext_modulus = runtime.plaintext_modulus;
    provenance.num_limbs = runtime.num_limbs;
    provenance.openfhe_version = runtime.openfhe_version;
    return provenance;
}

}  // namespace

BenchmarkProvenance MakePiccardBenchmarkProvenance(
    const BFVContext& context) {
    BenchmarkProvenance provenance = MakeLiveFheProvenance(context);
    const PiccardParams& params = context.GetParams();
    if (!params.FloodingSized()) {
        throw std::logic_error(
            "Piccard provenance requires selected sanitizer parameters");
    }
    provenance.sanitizer_applicable = true;
    provenance.transcript_stat_bits = params.transcript_stat_bits;
    provenance.max_queries = params.max_queries;
    provenance.query_stat_bits = params.QueryStatBits();
    provenance.coefficient_stat_bits = params.CoefficientStatBits();
    provenance.flood_margin_bits = params.flood_margin_bits;
    provenance.eval_noise_bits = params.eval_noise_bits;
    provenance.flood_noise_bits = params.FloodNoiseBits();
    provenance.scaling_mod_size = params.scaling_mod_size;
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

BenchmarkProvenance MakeFheIndBenchmarkProvenance(
    const BFVContext& context) {
    BenchmarkProvenance provenance = MakeLiveFheProvenance(context);
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

BenchmarkProvenance MakeAheBenchmarkProvenance() {
    BenchmarkProvenance provenance;
    provenance.openfhe_version = "not-applicable";
    ValidateBenchmarkProvenance(provenance);
    return provenance;
}

bool ValidateBenchmarkProvenance(const BenchmarkProvenance& provenance) {
    const bool all_fhe = provenance.actual_ring_dim.has_value() &&
                         provenance.log_q_bits.has_value() &&
                         provenance.plaintext_modulus.has_value() &&
                         provenance.num_limbs.has_value();
    const bool any_fhe = provenance.actual_ring_dim.has_value() ||
                         provenance.log_q_bits.has_value() ||
                         provenance.plaintext_modulus.has_value() ||
                         provenance.num_limbs.has_value();
    if (any_fhe != all_fhe) {
        throw std::logic_error("partial FHE benchmark provenance");
    }
    if (all_fhe) {
        if (*provenance.actual_ring_dim == 0 ||
            !std::isfinite(*provenance.log_q_bits) ||
            *provenance.log_q_bits <= 0.0 ||
            *provenance.plaintext_modulus == 0 ||
            *provenance.num_limbs == 0) {
            throw std::logic_error(
                "live FHE benchmark provenance must be positive");
        }
        if (provenance.openfhe_version.empty() ||
            provenance.openfhe_version == "unknown" ||
            provenance.openfhe_version == "not-applicable") {
            throw std::logic_error(
                "live FHE benchmark provenance has invalid OpenFHE version");
        }
        if (provenance.openfhe_version != PICCARD_BUILD_OPENFHE_VERSION) {
            throw std::logic_error(
                "runtime OpenFHE version disagrees with configured build");
        }
    } else if (provenance.openfhe_version != "not-applicable") {
        throw std::logic_error(
            "non-FHE benchmark provenance must use not-applicable version");
    }

    const bool all_sanitizer =
        provenance.transcript_stat_bits.has_value() &&
        provenance.max_queries.has_value() &&
        provenance.query_stat_bits.has_value() &&
        provenance.coefficient_stat_bits.has_value() &&
        provenance.flood_margin_bits.has_value() &&
        provenance.eval_noise_bits.has_value() &&
        provenance.flood_noise_bits.has_value() &&
        provenance.scaling_mod_size.has_value();
    const bool any_sanitizer =
        provenance.transcript_stat_bits.has_value() ||
        provenance.max_queries.has_value() ||
        provenance.query_stat_bits.has_value() ||
        provenance.coefficient_stat_bits.has_value() ||
        provenance.flood_margin_bits.has_value() ||
        provenance.eval_noise_bits.has_value() ||
        provenance.flood_noise_bits.has_value() ||
        provenance.scaling_mod_size.has_value();
    if (provenance.sanitizer_applicable != all_sanitizer ||
        (!provenance.sanitizer_applicable && any_sanitizer)) {
        throw std::logic_error("inconsistent sanitizer provenance");
    }
    if (provenance.sanitizer_applicable && !all_fhe) {
        throw std::logic_error("Piccard sanitizer requires live FHE provenance");
    }
    return all_fhe;
}

}  // namespace benchmark
}  // namespace piccard
