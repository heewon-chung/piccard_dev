#pragma once

#include "util/params.h"

namespace piccard {

/// Back door to the flooding-free parameter derivation, for the noise
/// calibration harness only.
///
/// `benchmarks/bench_noise.cpp` measures the evaluation noise that
/// `PiccardParams::Validate()` later looks up, so it must be able to build a
/// parameter set before that table exists -- and for a configuration not yet in
/// the table, Validate() throws by design.
///
/// Nothing else may include this header. A parameter set produced here has no
/// flooding sized: `FloodNoiseBits()` throws on it, which is what stops such a
/// set from reaching a protocol path that would return an under-flooded
/// ciphertext to the receiver.
struct CalibrationAccess {
    static void Derive(PiccardParams& params) { params.DeriveWithoutFlooding(); }
    static void DeriveSqrt(PiccardParams& params) { params.DeriveSqrtWithoutFlooding(); }
};

} // namespace piccard
