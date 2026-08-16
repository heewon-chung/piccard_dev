// Piccard calibration schema-v2 wrapper. This file is copied byte-for-byte
// during the Phase-5 cutover; keep the legacy and expanded tables disjoint.
#define PICCARD_PRE_THRESHOLD_CALIBRATION_V2 1

// NOTE: no #include here. This file is pulled in from inside
// namespace piccard { namespace { ... } } (src/util/params.cpp), so a standard
// header included at this point would be nested in that namespace — which
// libstdc++ rejects outright. std::optional is required below and is included
// at file scope by params.cpp instead.

struct LegacyNoiseCalibration {
    Circuit circuit;
    SecurityLevel security;
    uint32_t ring_dim_requested;
    uint32_t natural_mult_depth;
    uint32_t ring_dim_natural;
    uint32_t mult_depth;
    uint32_t scaling_mod_size;
    uint32_t eval_noise_bits;
    double log_delta;
};

constexpr LegacyNoiseCalibration kLegacyNoiseCalibration[] = {
#include "util/noise_calibration_legacy_rows.inc"
};

#ifndef PICCARD_PRE_THRESHOLD_CALIBRATION_ROWS_FILE
#define PICCARD_PRE_THRESHOLD_CALIBRATION_ROWS_FILE \
    "util/noise_calibration_pre_threshold_rows.inc"
#endif

const PreThresholdCalibrationRow kPreThresholdNoiseCalibration[] = {
#include PICCARD_PRE_THRESHOLD_CALIBRATION_ROWS_FILE
};

// The existing selection path consumes this alias for TOY and Threshold rows.
// Expanded STD128/STD192 rows are selected before that compatibility path.
constexpr const auto& kNoiseCalibration = kLegacyNoiseCalibration;

struct NoiseCalibrationCandidateView {
    Circuit circuit;
    SecurityLevel security;
    uint32_t ring_dim_requested;
    uint32_t natural_mult_depth;
    uint32_t ring_dim_natural;
    uint32_t mult_depth;
    uint32_t scaling_mod_size;
    uint32_t eval_noise_bits;
    double log_delta;
    std::optional<double> log_q;
    std::optional<uint64_t> ct_bytes;
    const PreThresholdCalibrationRow* expanded;
};

template <typename Visitor>
void ForEachNoiseCalibrationCandidate(Visitor&& visitor) {
    for (const auto& row : kLegacyNoiseCalibration) {
        visitor(NoiseCalibrationCandidateView{
            row.circuit,
            row.security,
            row.ring_dim_requested,
            row.natural_mult_depth,
            row.ring_dim_natural,
            row.mult_depth,
            row.scaling_mod_size,
            row.eval_noise_bits,
            row.log_delta,
            std::nullopt,
            std::nullopt,
            nullptr,
        });
    }
    for (const auto& row : kPreThresholdNoiseCalibration) {
        visitor(NoiseCalibrationCandidateView{
            row.key.circuit,
            row.key.security,
            row.key.requested_ring_dim,
            row.key.natural_depth,
            row.natural_ring_dim,
            row.provisioned_depth,
            row.scaling_mod_size,
            row.eval_noise_bits,
            row.log_delta,
            row.log_q,
            row.ct_bytes,
            &row,
        });
    }
}
