// Toy correctness-only fixture for Work 2 Phase 3.
//
// The requested-8192 rows deliberately model a calibration whose realized
// OpenFHE context grew to N=16384. These are not production measurements and
// must never be included by the normal piccard_core target.
constexpr NoiseCalibration kNoiseCalibration[] = {
    // Existing toy rows needed by the shared engine tests in the fixture target.
    {Circuit::OneHot, SecurityLevel::TOY,
     1024, 1, 1024, 3, 40, 56, 146.4},
    {Circuit::Sqrt, SecurityLevel::TOY,
     1024, 3, 1024, 5, 40, 92, 186.4},

    // Requested N, natural depth, and realized/calibrated N stay distinct.
    {Circuit::OneHot, SecurityLevel::TOY,
     8192, 1, 16384, 4, 40, 62, 184.0},
    {Circuit::Sqrt, SecurityLevel::TOY,
     8192, 3, 16384, 4, 40, 97, 184.0},
};
